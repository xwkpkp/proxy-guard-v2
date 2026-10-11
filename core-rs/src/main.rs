//! proxy-guard-core — Rust 数据面（v2 三语言架构）。
//!
//! 数据流：客户端 → 本进程（转发 / 检测 / 路由 / 轮换执行）→ 出口；
//! 控制口接收 Go 的快照与增量策略，外发事件流（SSE）。
//!
//! 契约见 proto/control.proto；行为对照锚点见 docs/contract.md。
//!
//! 启动参数（CLI 或环境变量）：
//!   --listen 127.0.0.1:8888    用户流量入口（PG_LISTEN）
//!   --ctrl 127.0.0.1:8890      控制口（PG_CTRL_PORT / PG_CTRL_HOST）
//!   --rules rules              规则目录（PG_RULES_DIR）
//!   --token <hex>              控制口 token（PG_CTRL_TOKEN，空=不校验）

mod config;
mod control;
mod detect;
mod forward;
mod metrics;
mod safeguard;
mod trace;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::broadcast;

use config::{SharedState, ThreatEvent};
use control::ControlDeps;
use detect::Detector;
use forward::upstream::UpstreamPicker;
use forward::ProxyDeps;
use metrics::Metrics;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // ---- 参数（CLI 优先，环境变量兜底） ----
    let listen: SocketAddr = arg_or_env("--listen", "PG_LISTEN", "127.0.0.1:8888").parse()?;
    let ctrl_host = arg_or_env("--ctrl-host", "PG_CTRL_HOST", "127.0.0.1");
    let ctrl_port = arg_or_env("--ctrl-port", "PG_CTRL_PORT", "8890");
    let ctrl: SocketAddr = format!("{ctrl_host}:{ctrl_port}").parse()?;
    let rules_dir = arg_or_env("--rules", "PG_RULES_DIR", "rules");
    let token = arg_or_env("--token", "PG_CTRL_TOKEN", "");

    log::info!(
        "proxy-guard-core {} (contract {}) listen={listen} ctrl={ctrl} rules={rules_dir} auth={}",
        env!("CARGO_PKG_VERSION"),
        config::CONTRACT_VERSION,
        if token.is_empty() { "off" } else { "on" },
    );

    // ---- 组件 ----
    let state = SharedState::new(rules_dir.clone());
    let detector = Arc::new(Detector::load(Path::new(&rules_dir)));
    let picker = Arc::new(UpstreamPicker::new());
    let metrics = Arc::new(Metrics::default());
    let breaker = Arc::new(safeguard::CircuitBreaker::new());
    // 事件广播：容量 256，满则丢弃（数据面永不等待事件消费）
    let (events_tx, _) = broadcast::channel::<ThreatEvent>(256);

    let ctrl_deps = Arc::new(ControlDeps {
        state: state.clone(),
        metrics: metrics.clone(),
        events: events_tx.clone(),
        token,
    });
    let proxy_deps = Arc::new(ProxyDeps {
        state: state.clone(),
        detector,
        picker,
        breaker,
        events: events_tx.clone(),
        metrics: metrics.clone(),
    });

    // ---- 双服务并行（任一退出即整体结束） ----
    let ctrl_task = tokio::spawn(control::serve(ctrl, ctrl_deps));
    let proxy_task = tokio::spawn(forward::serve(listen, proxy_deps));

    tokio::select! {
        r = ctrl_task => {
            log::error!("控制口退出: {:?}", r);
        }
        r = proxy_task => {
            log::error!("数据面退出: {:?}", r);
        }
    }
    Ok(())
}

/// 取参数：`--flag value` / `--flag=value` / 环境变量 / 默认值。
fn arg_or_env(flag: &str, env: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    let prefix = format!("{flag}=");
    let mut i = 1;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        if let Some(v) = args[i].strip_prefix(&prefix) {
            return v.to_string();
        }
        i += 1;
    }
    std::env::var(env).unwrap_or_else(|_| default.to_string())
}
