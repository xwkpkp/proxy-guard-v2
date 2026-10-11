//! 控制口 HTTP 服务（Rust 数据面侧，JSON over 127.0.0.1）。
//!
//! 路由（见 docs/contract.md）：
//!   POST /snapshot   Go → Rust 全量快照（version 单调，旧版本拒绝）
//!   POST /policy     Go → Rust 增量策略
//!   GET  /events     Rust → Go SSE 事件流
//!   GET  /metrics    指标快照
//!   GET  /health     存活
//!
//! token 认证：`Authorization: Bearer <token>`；PG_CTRL_TOKEN 为空则不校验
//! （仅限本地开发场景）。

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::config::{
    Ack, ConfigSnapshot, PolicyDelta, SharedState, SnapshotAck, ThreatEvent, CONTRACT_VERSION,
};
use crate::metrics::Metrics;

/// 控制口依赖。
pub struct ControlDeps {
    pub state: Arc<SharedState>,
    pub metrics: Arc<Metrics>,
    pub events: broadcast::Sender<ThreatEvent>,
    pub token: String,
}

/// 启动控制口（阻塞至出错）。
pub async fn serve(listen: SocketAddr, deps: Arc<ControlDeps>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("控制口监听 {listen}");
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let deps = deps.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let deps = deps.clone();
                async move { handle(req, deps).await }
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                log::debug!("控制连接关闭: {err}");
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    deps: Arc<ControlDeps>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    // 认证（token 为空跳过）
    if !deps.token.is_empty() {
        let ok = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == format!("Bearer {}", deps.token))
            .unwrap_or(false);
        if !ok {
            return Ok(json_resp(
                StatusCode::UNAUTHORIZED,
                &Ack {
                    accepted: false,
                    reason: "unauthorized".into(),
                },
            ));
        }
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method, path.as_str()) {
        (Method::GET, "/health") => Ok(json_resp(
            StatusCode::OK,
            &serde_json::json!({
                "ok": true,
                "service": "proxy-guard-core",
                "contract": CONTRACT_VERSION,
                "version": env!("CARGO_PKG_VERSION"),
            }),
        )),

        (Method::POST, "/snapshot") => {
            let body = match read_body(req.into_body(), 8 * 1024 * 1024).await {
                Ok(b) => b,
                Err(err) => {
                    return Ok(json_resp(
                        StatusCode::BAD_REQUEST,
                        &Ack { accepted: false, reason: err },
                    ))
                }
            };
            let snap: ConfigSnapshot = match serde_json::from_slice(&body) {
                Ok(s) => s,
                Err(err) => {
                    return Ok(json_resp(
                        StatusCode::BAD_REQUEST,
                        &Ack { accepted: false, reason: format!("bad snapshot json: {err}") },
                    ))
                }
            };
            let version = snap.version;
            match deps.state.apply_snapshot(snap).await {
                Ok(()) => {
                    log::info!("快照 v{version} 已生效");
                    Ok(json_resp(
                        StatusCode::OK,
                        &SnapshotAck {
                            accepted: true,
                            current_version: version,
                            reason: String::new(),
                        },
                    ))
                }
                Err(reason) => {
                    let current = deps.state.inner.read().await.version;
                    log::warn!("快照 v{version} 被拒: {reason}");
                    Ok(json_resp(
                        StatusCode::OK,
                        &SnapshotAck {
                            accepted: false,
                            current_version: current,
                            reason,
                        },
                    ))
                }
            }
        }

        (Method::POST, "/policy") => {
            let body = match read_body(req.into_body(), 1024 * 1024).await {
                Ok(b) => b,
                Err(err) => {
                    return Ok(json_resp(
                        StatusCode::BAD_REQUEST,
                        &Ack { accepted: false, reason: err },
                    ))
                }
            };
            let delta: PolicyDelta = match serde_json::from_slice(&body) {
                Ok(d) => d,
                Err(err) => {
                    return Ok(json_resp(
                        StatusCode::BAD_REQUEST,
                        &Ack { accepted: false, reason: format!("bad policy json: {err}") },
                    ))
                }
            };
            match deps.state.apply_delta(delta).await {
                Ok(()) => {
                    log::info!("策略增量已生效");
                    Ok(json_resp(
                        StatusCode::OK,
                        &Ack { accepted: true, reason: String::new() },
                    ))
                }
                Err(reason) => {
                    log::warn!("策略增量被拒: {reason}");
                    Ok(json_resp(
                        StatusCode::OK,
                        &Ack { accepted: false, reason },
                    ))
                }
            }
        }

        (Method::GET, "/metrics") => {
            let inner = deps.state.inner.read().await;
            let total = inner.pool.len() as i32;
            let active = inner
                .pool
                .iter()
                .filter(|a| !inner.blacklist.contains(*a))
                .count() as i32;
            drop(inner);
            Ok(json_resp(
                StatusCode::OK,
                &deps.metrics.snapshot(active, total),
            ))
        }

        (Method::GET, "/events") => Ok(sse_stream(deps)),

        _ => Ok(json_resp(
            StatusCode::NOT_FOUND,
            &Ack { accepted: false, reason: "not found".into() },
        )),
    }
}

/// SSE 事件流：把 broadcast 通道包成 `text/event-stream`。
fn sse_stream(deps: Arc<ControlDeps>) -> Response<BoxBody<Bytes, Infallible>> {
    let rx = deps.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(ev) => {
            let json = serde_json::to_string(&ev).unwrap_or_default();
            Some(Ok::<_, Infallible>(Frame::data(Bytes::from(format!(
                "data: {json}\n\n"
            )))))
        }
        // lagged（消费慢了）直接跳过：事件允许丢弃，不阻塞数据面
        Err(_) => None,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(StreamBody::new(stream).boxed())
        .unwrap()
}

fn json_resp<T: serde::Serialize>(
    status: StatusCode,
    v: &T,
) -> Response<BoxBody<Bytes, Infallible>> {
    let body = serde_json::to_vec(v).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed())
        .unwrap()
}

async fn read_body(body: Incoming, limit: usize) -> Result<Bytes, String> {
    match Limited::new(body, limit).collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(_) => Err(format!("body 超过 {limit} 字节上限")),
    }
}
