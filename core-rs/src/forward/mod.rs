//! 代理主体：HTTP 转发 + CONNECT 隧道（数据面核心）。
//!
//! 请求路径：
//!   解析目标 → SSRF 检查 → 检测（请求侧）→ 路由 → 出口选择（失败即时切换）
//!   → 转发 → 检测（响应侧）→ 组装返回。
//! 检测命中 → 事件经 broadcast 外发（Go 消费），**永不阻塞转发路径**。
//!
//! v2.0 范围：HTTP 转发 + CONNECT 隧道。
//! TODO(下一里程碑)：MITM（rcgen + rustls）；大响应流式直通。

pub mod router;
pub mod upstream;

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::config::{SharedState, ThreatEvent, ACTION_BLOCKED, ACTION_LOGGED, ACTION_PASSED, ACTION_SWITCHED, KIND_DETECT, KIND_SWITCH};
use crate::detect::{Detector, Hit};
use crate::metrics::Metrics;
use crate::safeguard::{self, CircuitBreaker};
use crate::trace;

use self::router::{DomainRouter, Route};
use self::upstream::{Pick, UpstreamPicker};

/// 请求体缓冲上限。
const MAX_REQ_BODY: usize = 8 * 1024 * 1024;
/// 响应体缓冲硬上限（超过直接 502；流式直通见 TODO）。
const MAX_RESP_BODY: usize = 32 * 1024 * 1024;
/// 上游连接（TCP / 代理 CONNECT 握手）超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// 不向上游透传的 hop-by-hop 头。
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

/// 代理运行时依赖。
pub struct ProxyDeps {
    pub state: Arc<SharedState>,
    pub detector: Arc<Detector>,
    pub picker: Arc<UpstreamPicker>,
    pub breaker: Arc<CircuitBreaker>,
    pub events: broadcast::Sender<ThreatEvent>,
    pub metrics: Arc<Metrics>,
}

/// 启动代理监听（阻塞至出错）。
pub async fn serve(listen: SocketAddr, deps: Arc<ProxyDeps>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("数据面监听 {listen}（HTTP 代理入口）");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let deps = deps.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let deps = deps.clone();
                async move { handle_request(req, deps).await }
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                log::debug!("连接关闭: {err}");
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    deps: Arc<ProxyDeps>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    deps.metrics
        .requests_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let trace_id = trace::new_trace_id();
    let resp = if req.method() == Method::CONNECT {
        handle_connect(req, deps, trace_id).await
    } else {
        handle_http(req, deps, trace_id).await
    };
    Ok(resp)
}

// ---------------------------------------------------------------------------
// CONNECT 隧道
// ---------------------------------------------------------------------------

async fn handle_connect(
    req: Request<Incoming>,
    deps: Arc<ProxyDeps>,
    trace_id: String,
) -> Response<BoxBody<Bytes, Infallible>> {
    let authority = match req.uri().authority() {
        Some(a) => a.clone(),
        None => return simple(StatusCode::BAD_REQUEST, "CONNECT 缺少目标"),
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    // SSRF / 熔断检查（快照一次性读出）
    let (ssrf_protect, circuit_threshold, circuit_cooldown_s) = {
        let inner = deps.state.inner.read().await;
        (
            inner.policy.ssrf_protect,
            inner.policy.circuit_threshold.max(1) as u32,
            inner.policy.circuit_cooldown_s.max(1) as u64,
        )
    };
    if ssrf_protect && safeguard::is_ssrf_target(&host) {
        deps.metrics.ssrf_blocked.fetch_add(1, Ordering::Relaxed);
        log::warn!("[trace={trace_id}] SSRF 拦截: {host}:{port}");
        return simple(StatusCode::FORBIDDEN, "proxy-guard: SSRF target blocked");
    }
    if deps.breaker.is_open(circuit_cooldown_s) {
        log::warn!("[trace={trace_id}] 熔断中，拒绝转发: {host}");
        return simple(StatusCode::SERVICE_UNAVAILABLE, "proxy-guard: circuit breaker open");
    }

    // 路由决策
    let route = {
        let inner = deps.state.inner.read().await;
        DomainRouter::from_table(&inner.routing).decide(&host)
    };

    // 建立上游连接（经池时含失败即时切换；失败重试 1 次）
    let (upstream, via) = match connect_target(&deps, &host, port, route).await {
        Ok(x) => x,
        Err(err) => {
            deps.metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            deps.breaker.record_failure(circuit_threshold);
            log::warn!("[trace={trace_id}] 上游连接失败 {host}:{port}: {err:#}");
            return simple(StatusCode::BAD_GATEWAY, "upstream unreachable");
        }
    };
    deps.breaker.record_success();

    let via_label = via.clone().unwrap_or_else(|| "DIRECT".to_string());
    log::debug!("[trace={trace_id}] CONNECT {host}:{port} via {via_label}");

    let deps2 = deps.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                let mut server_io = upstream;
                let started = Instant::now();
                match tokio::io::copy_bidirectional(&mut client_io, &mut server_io).await {
                    Ok((up, down)) => {
                        deps2
                            .metrics
                            .add_upstream_ms(started.elapsed().as_millis() as u64);
                        log::debug!(
                            "[trace={trace_id}] 隧道关闭 {host}:{port} ↑{up}B ↓{down}B"
                        );
                    }
                    Err(err) => {
                        log::debug!("[trace={trace_id}] 隧道异常 {host}:{port}: {err}");
                    }
                }
                if let Some(addr) = via {
                    deps2.picker.report_success(&addr);
                }
            }
            Err(err) => log::warn!("[trace={trace_id}] upgrade 失败: {err}"),
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// HTTP 转发
// ---------------------------------------------------------------------------

async fn handle_http(
    req: Request<Incoming>,
    deps: Arc<ProxyDeps>,
    trace_id: String,
) -> Response<BoxBody<Bytes, Infallible>> {
    let uri = req.uri().clone();
    let host = match uri.host() {
        Some(h) => h.to_string(),
        None => return simple(StatusCode::BAD_REQUEST, "缺少目标主机（需要绝对 URI）"),
    };
    let port = uri.port_u16().unwrap_or(80);
    let path_q = uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "/".to_string());

    // 快照视图（一次性读出，避免请求中途快照切换导致不一致）
    let (
        ssrf_protect,
        circuit_threshold,
        circuit_cooldown_s,
        route,
        rotation,
        scan_request,
        scan_response,
        block_on_detect,
        switch_on_detect,
        max_body_scan,
        weights,
        redline_enabled,
        csp_inject,
    ) = {
        let inner = deps.state.inner.read().await;
        let router = DomainRouter::from_table(&inner.routing);
        (
            inner.policy.ssrf_protect,
            inner.policy.circuit_threshold.max(1) as u32,
            inner.policy.circuit_cooldown_s.max(1) as u64,
            router.decide(&host),
            inner.policy.rotation.clone(),
            inner.policy.scan_request,
            inner.policy.scan_response,
            inner.policy.block_on_detect,
            inner.policy.switch_on_detect,
            inner.policy.max_body_scan as usize,
            inner.rule_weight.clone(),
            inner.policy.redline_enabled,
            inner.policy.csp_inject,
        )
    };

    // ---- 防护 3: SSRF 拦截（对照 shield.handle_http）----
    if ssrf_protect && safeguard::is_ssrf_target(&host) {
        deps.metrics.ssrf_blocked.fetch_add(1, Ordering::Relaxed);
        log::warn!("[trace={trace_id}] SSRF 拦截: {host}:{port}");
        return simple(StatusCode::FORBIDDEN, "proxy-guard: SSRF target blocked");
    }

    // 读请求体
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match read_limited(req.into_body(), MAX_REQ_BODY).await {
        Ok(b) => b,
        Err(err) => return simple(StatusCode::PAYLOAD_TOO_LARGE, &err),
    };
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    let headers_map = lower_headers(&headers);

    // ---- 防护 1: 数据红线（命中 → 阻断，对照 check_data_redline）----
    if redline_enabled {
        let reasons = safeguard::check_redline(&headers_map, &uri.to_string(), &body_text);
        if !reasons.is_empty() {
            deps.metrics.redline_blocked.fetch_add(1, Ordering::Relaxed);
            log::warn!(
                "[trace={trace_id}] 数据红线拦截: {host} | {}",
                reasons.join(", ")
            );
            emit_event(
                &deps, &trace_id, KIND_DETECT, "request", &format!("{host}{path_q}"),
                &[], &truncate(&body_text, 512), "", ACTION_BLOCKED,
            );
            return simple(
                StatusCode::FORBIDDEN,
                "proxy-guard: sensitive data redline blocked",
            );
        }
    }

    // ---- 防护 5: 熔断检查 ----
    if deps.breaker.is_open(circuit_cooldown_s) {
        log::warn!("[trace={trace_id}] 熔断中，拒绝转发: {host}");
        return simple(
            StatusCode::SERVICE_UNAVAILABLE,
            "proxy-guard: circuit breaker open",
        );
    }

    // ---- 请求侧扫描（规则 + SQLi 语义 path/body + rule_id 去重）----
    let mut hits: Vec<Hit> = Vec::new();
    if scan_request {
        // 解码视图对齐 Python 侧（%XX 解码 + query 中 + → 空格）
        let path_for_scan = decode_for_scan(&path_q);
        hits = deps
            .detector
            .scan_request(&path_for_scan, &headers_map, &body_text, &weights);
        // SQLi 语义加强：对 path 和 body 都做（对照 Python _scan_request_full）
        let mut sqli_hits = deps.detector.scan_sqli(&path_for_scan);
        sqli_hits.extend(deps.detector.scan_sqli(&body_text));
        let mut seen: HashSet<String> = hits.iter().map(|h| h.rule_id.clone()).collect();
        for h in sqli_hits {
            if seen.insert(h.rule_id.clone()) {
                hits.push(h);
            }
        }
    }

    if !hits.is_empty() {
        let blocked = block_on_detect;
        let action = if blocked { ACTION_BLOCKED } else { ACTION_LOGGED };
        let sample = format!("{path_q} | {}", truncate(&body_text, 2048));
        emit_event(
            &deps, &trace_id, KIND_DETECT, "request", &format!("{host}{path_q}"),
            &hits, &truncate(&sample, 4096), "", action,
        );
        if blocked {
            deps.metrics.blocked_total.fetch_add(1, Ordering::Relaxed);
            return simple(
                StatusCode::FORBIDDEN,
                "proxy-guard: request blocked (malicious traffic)",
            );
        }
    }

    // 上游连接（含失败切换重试）
    let (upstream, via) = match connect_target(&deps, &host, port, route).await {
        Ok(x) => x,
        Err(err) => {
            deps.metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            deps.breaker.record_failure(circuit_threshold);
            return simple(
                StatusCode::BAD_GATEWAY,
                &format!("upstream unreachable: {err}"),
            );
        }
    };

    // 组装上游请求
    let started = Instant::now();
    let up_uri: hyper::Uri = if via.is_some() {
        // 经代理：absolute-form
        uri.clone()
    } else {
        // 直连：origin-form
        path_q.parse().unwrap_or_else(|_| "/".parse().unwrap())
    };
    let mut builder = Request::builder().method(method.clone()).uri(up_uri);
    for (name, value) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lname.as_str()) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    if via.is_none() {
        // 直连时补 Host（origin-form 需要）
        if let Ok(hv) = HeaderValue::from_str(&host_port_header(&host, port)) {
            builder = builder.header(HeaderName::from_static("host"), hv);
        }
    }
    let up_req = match builder.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(err) => return simple(StatusCode::BAD_REQUEST, &format!("组装请求失败: {err}")),
    };

    // 发送到上游（client conn）
    let io = TokioIo::new(upstream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(x) => x,
        Err(err) => {
            deps.breaker.record_failure(circuit_threshold);
            return simple(StatusCode::BAD_GATEWAY, &format!("上游握手失败: {err}"));
        }
    };
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            log::debug!("client conn 结束: {err}");
        }
    });

    let up_resp = match sender.send_request(up_req).await {
        Ok(r) => r,
        Err(err) => {
            if let Some(addr) = &via {
                deps.picker.report_failure(addr, &rotation);
                deps.metrics.switched_total.fetch_add(1, Ordering::Relaxed);
                emit_event(
                    &deps, &trace_id, KIND_SWITCH, "request", &format!("{host}{path_q}"),
                    &[], "", addr, ACTION_SWITCHED,
                );
            }
            deps.breaker.record_failure(circuit_threshold);
            return simple(StatusCode::BAD_GATEWAY, &format!("上游请求失败: {err}"));
        }
    };
    if let Some(addr) = &via {
        deps.picker.report_success(addr);
    }
    deps.breaker.record_success();
    deps.metrics
        .add_upstream_ms(started.elapsed().as_millis() as u64);

    // 读响应体（缓冲上限）
    let status = up_resp.status();
    let resp_headers = up_resp.headers().clone();
    let resp_body = match read_limited(up_resp.into_body(), MAX_RESP_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return simple(
                StatusCode::BAD_GATEWAY,
                "响应体超过 32MB 缓冲上限（流式直通留给下一里程碑）",
            )
        }
    };
    let ctype = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let location = resp_headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // ---- 防护 6: 响应注入检测（对照 shield.handle_http）----
    let body_preview: String = String::from_utf8_lossy(&resp_body)
        .chars()
        .take(65536)
        .collect();
    let inj = safeguard::detect_response_injection(
        status.as_u16(),
        &ctype,
        location.as_deref(),
        &body_preview,
    );
    if !inj.is_empty() {
        log::warn!(
            "[trace={trace_id}] 响应被篡改注入: {host}{path_q} | {}",
            inj.join(", ")
        );
        emit_event(
            &deps, &trace_id, KIND_DETECT, "response", &format!("{host}{path_q}"),
            &[], &truncate(&inj.join("; "), 512), via.as_deref().unwrap_or(""),
            ACTION_LOGGED,
        );
        if switch_on_detect {
            if let Some(addr) = &via {
                deps.picker
                    .force_cooldown(addr, rotation.cooldown_s.max(1) as u64);
                deps.metrics.switched_total.fetch_add(1, Ordering::Relaxed);
                emit_event(
                    &deps, &trace_id, KIND_SWITCH, "response", &format!("{host}{path_q}"),
                    &[], "", addr, ACTION_SWITCHED,
                );
            }
        }
        if block_on_detect {
            deps.metrics.blocked_total.fetch_add(1, Ordering::Relaxed);
            return simple(
                StatusCode::BAD_GATEWAY,
                "proxy-guard: response tampering detected",
            );
        }
    }

    // ---- 响应侧扫描（gate: 仅可扫描 content-type；命中按 block 动作）----
    if scan_response && !resp_body.is_empty() && is_scannable(&ctype) {
        let scan_len = max_body_scan.min(resp_body.len());
        let sample: String = String::from_utf8_lossy(&resp_body[..scan_len]).to_string();
        let rhits = deps.detector.scan_response(&sample, &weights);
        if !rhits.is_empty() {
            let action = if block_on_detect { ACTION_BLOCKED } else { ACTION_LOGGED };
            emit_event(
                &deps, &trace_id, KIND_DETECT, "response", &format!("{host}{path_q}"),
                &rhits, &truncate(&sample, 4096), via.as_deref().unwrap_or(""), action,
            );
            if block_on_detect {
                deps.metrics.blocked_total.fetch_add(1, Ordering::Relaxed);
                return simple(
                    StatusCode::FORBIDDEN,
                    "proxy-guard: response blocked (malicious script)",
                );
            }
        }
    }

    // ---- 防护 8: CSP 注入（HTML 且无现有 CSP）----
    let inject_csp = csp_inject
        && safeguard::should_inject_csp(
            &ctype,
            resp_headers.contains_key("content-security-policy"),
        );

    // 组装返回
    rebuild_response(status, &resp_headers, resp_body, inject_csp)
}

// ---------------------------------------------------------------------------
// 上游连接
// ---------------------------------------------------------------------------

/// 建立到目标的连接。Route::Proxy 时经出口池（失败自动换一个，最多 2 次尝试）。
async fn connect_target(
    deps: &ProxyDeps,
    host: &str,
    port: u16,
    route: Route,
) -> anyhow::Result<(TcpStream, Option<String>)> {
    match route {
        Route::Direct => {
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
                .await??;
            Ok((stream, None))
        }
        Route::Proxy => {
            let mut last_err: Option<anyhow::Error> = None;
            for _ in 0..2 {
                let (pick, rotation) = {
                    let inner = deps.state.inner.read().await;
                    (
                        deps.picker
                            .pick(&inner.pool, &inner.blacklist, &inner.policy.rotation),
                        inner.policy.rotation.clone(),
                    )
                };
                let addr = match pick {
                    Pick::Via(a) => a,
                    Pick::Direct => {
                        let stream =
                            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
                                .await??;
                        return Ok((stream, None));
                    }
                    Pick::NoUpstream => anyhow::bail!("出口池不可用（空池或全部冷却/拉黑）"),
                };
                match connect_via_proxy(&addr, host, port).await {
                    Ok(stream) => {
                        deps.picker.report_success(&addr);
                        return Ok((stream, Some(addr)));
                    }
                    Err(err) => {
                        log::warn!("出口 {addr} 连接失败: {err:#}");
                        deps.picker.report_failure(&addr, &rotation);
                        deps.metrics
                            .switched_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        last_err = Some(err);
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| anyhow::anyhow!("所有出口失败")))
        }
    }
}

/// 经公共代理建立到 target 的隧道（手写 CONNECT 握手）。
async fn connect_via_proxy(proxy_addr: &str, host: &str, port: u16) -> anyhow::Result<TcpStream> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(proxy_addr))
        .await??;
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;

    // 读响应头（至 \r\n\r\n，上限 4KB）
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(CONNECT_TIMEOUT, stream.read(&mut byte)).await??;
        if n == 0 {
            anyhow::bail!("代理提前关闭连接");
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 4096 {
            anyhow::bail!("代理响应头过大");
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200") {
        anyhow::bail!("代理拒绝 CONNECT: {status_line}");
    }
    Ok(stream)
}

// ---------------------------------------------------------------------------
// 助手
// ---------------------------------------------------------------------------

fn empty() -> BoxBody<Bytes, Infallible> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full(data: Bytes) -> BoxBody<Bytes, Infallible> {
    Full::new(data).map_err(|never| match never {}).boxed()
}

fn simple(status: StatusCode, msg: &str) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(full(Bytes::from(msg.to_string())))
        .unwrap()
}

async fn read_limited(body: Incoming, limit: usize) -> Result<Bytes, String> {
    let limited = Limited::new(body, limit);
    match limited.collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(_) => Err(format!("body 超过 {limit} 字节上限")),
    }
}

fn lower_headers(headers: &hyper::HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        map.entry(name.as_str().to_ascii_lowercase())
            .or_insert_with(|| value.to_str().unwrap_or("").to_string());
    }
    map
}

fn host_port_header(host: &str, port: u16) -> String {
    if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

fn is_scannable(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    [
        "text/html",
        "text/plain",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "application/json",
        "application/xml",
        "text/xml",
        "text/css",
    ]
    .iter()
    .any(|t| ct.contains(t))
}

/// 扫描用的 URL 解码（对齐 Python 侧 aiohttp 解码视图）。
///
/// Python 版扫描的是 `request.url.path + "?" + request.url.query`
/// （yarl 已解码：%XX → 字节，query 中 + → 空格）。Rust 侧拿到的是
/// 原始编码形式，扫描前必须做同样的解码，否则漏检编码后的注入。
fn decode_for_scan(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    let mut in_query = false;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'?' => {
                in_query = true;
                out.push(b);
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b);
                        i += 1;
                    }
                }
            }
            b'+' if in_query => {
                out.push(b' ');
                i += 1;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

#[allow(clippy::too_many_arguments)]
fn emit_event(
    deps: &ProxyDeps,
    trace_id: &str,
    kind: &str,
    ctx: &str,
    target: &str,
    hits: &[Hit],
    sample: &str,
    proxy_used: &str,
    action: &str,
) {
    let ev = ThreatEvent {
        trace_id: trace_id.to_string(),
        ts: trace::now_unix(),
        kind: kind.to_string(),
        ctx: ctx.to_string(),
        target: target.to_string(),
        hits: hits.iter().map(|h| h.to_contract()).collect(),
        sample: sample.to_string(),
        proxy_used: proxy_used.to_string(),
        action_taken: action.to_string(),
    };
    // broadcast 无订阅者 / 满时都不阻塞：数据面事件允许丢弃
    if deps.events.send(ev).is_err() {
        log::debug!("事件无订阅者，丢弃");
    }
}

fn rebuild_response(
    status: StatusCode,
    headers: &hyper::HeaderMap,
    body: Bytes,
    inject_csp: bool,
) -> Response<BoxBody<Bytes, Infallible>> {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lname.as_str()) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }
    if inject_csp {
        builder = builder.header("content-security-policy", safeguard::DEFAULT_CSP);
    }
    builder.body(full(body)).unwrap()
}

#[allow(dead_code)]
fn unused_action_marker() -> &'static str {
    // 保持 ACTION_PASSED 常量被引用（事件语义表完整性）
    ACTION_PASSED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_is_char_safe() {
        let s = "你好世界abcd";
        assert_eq!(truncate(s, 4), "你好世界");
        assert_eq!(truncate(s, 100), s);
    }

    #[test]
    fn host_header_format() {
        assert_eq!(host_port_header("example.com", 80), "example.com");
        assert_eq!(host_port_header("example.com", 8080), "example.com:8080");
    }

    #[test]
    fn url_decode_for_scan() {
        // query 中的 + 与 %20 都还原为空格（对齐 Python aiohttp 解码视图）
        assert_eq!(
            decode_for_scan("/search?q=1+UNION+SELECT"),
            "/search?q=1 UNION SELECT"
        );
        assert_eq!(
            decode_for_scan("/search?q=1%20OR%201=1"),
            "/search?q=1 OR 1=1"
        );
        assert_eq!(decode_for_scan("/search?q='%20OR%201=1"), "/search?q=' OR 1=1");
        // path 段中的 + 保持字面
        assert_eq!(decode_for_scan("/a+b/c?x=1"), "/a+b/c?x=1");
        // 百分号解码
        assert_eq!(decode_for_scan("/x%2e%2e/y"), "/x../y");
        // 非法编码保持原样
        assert_eq!(decode_for_scan("/x%zz"), "/x%zz");
    }
}
