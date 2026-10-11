//! 契约消息类型与共享状态。
//!
//! 与 proto/control.proto 逐字段对应（JSON 字段名 = proto 字段名，snake_case）。
//! 修改契约的顺序：proto/control.proto → docs/contract.md → Go/Python/Rust 三端。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// 契约版本（写入 /health 与日志）。
pub const CONTRACT_VERSION: &str = "v2.0";

/// Go 侧 nil slice/map 会序列化为 JSON null；数据面按空集合宽容处理。
pub fn null_as_empty_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// 同 null_as_empty_vec，用于 map 字段。
pub fn null_as_empty_map<'de, D, K, V>(d: D) -> Result<HashMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: std::hash::Hash + Eq + serde::Deserialize<'de>,
    V: serde::Deserialize<'de>,
{
    Ok(Option::<HashMap<K, V>>::deserialize(d)?.unwrap_or_default())
}

// ---------------------------------------------------------------------------
// 快照
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigSnapshot {
    pub version: u64,
    #[serde(default)]
    pub issued_at: i64,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub pool: Vec<String>,
    #[serde(default)]
    pub routing: RoutingTable,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub blacklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingTable {
    #[serde(default)]
    pub mode: String,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub direct_domains: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub direct_suffixes: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub proxy_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub rotation: RotationPolicy,
    #[serde(default)]
    pub scan_request: bool,
    #[serde(default)]
    pub scan_response: bool,
    #[serde(default)]
    pub block_on_detect: bool,
    #[serde(default)]
    pub switch_on_detect: bool,
    #[serde(default)]
    pub mitm_enabled: bool,
    #[serde(default = "def_max_body_scan")]
    pub max_body_scan: i64,
    #[serde(default)]
    pub circuit_threshold: i32,
    #[serde(default)]
    pub circuit_cooldown_s: i32,
    #[serde(default)]
    pub max_concurrent: i32,
    #[serde(default)]
    pub redline_enabled: bool,
    #[serde(default)]
    pub ssrf_protect: bool,
    #[serde(default)]
    pub csp_inject: bool,
    #[serde(default)]
    pub detect_injection: bool,
    #[serde(default)]
    pub llm_malicious_action: String,
    #[serde(default)]
    pub llm_suspicious_action: String,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            rotation: RotationPolicy::default(),
            scan_request: false,
            scan_response: false,
            block_on_detect: false,
            switch_on_detect: false,
            mitm_enabled: false,
            max_body_scan: def_max_body_scan(),
            circuit_threshold: 5,
            circuit_cooldown_s: 60,
            max_concurrent: 20,
            redline_enabled: false,
            ssrf_protect: true,
            csp_inject: false,
            detect_injection: false,
            llm_malicious_action: String::new(),
            llm_suspicious_action: String::new(),
        }
    }
}

fn def_max_body_scan() -> i64 {
    2 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    #[serde(default = "def_strategy")]
    pub strategy: String,
    #[serde(default = "def_switch_interval")]
    pub switch_interval_s: i32,
    #[serde(default = "def_max_failures")]
    pub max_failures: i32,
    #[serde(default = "def_cooldown")]
    pub cooldown_s: i32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        RotationPolicy {
            strategy: def_strategy(),
            switch_interval_s: def_switch_interval(),
            max_failures: def_max_failures(),
            cooldown_s: def_cooldown(),
        }
    }
}

fn def_strategy() -> String {
    "round_robin".to_string()
}
fn def_switch_interval() -> i32 {
    60
}
fn def_max_failures() -> i32 {
    3
}
fn def_cooldown() -> i32 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnapshotAck {
    #[serde(default)]
    pub accepted: bool,
    #[serde(default)]
    pub current_version: u64,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ack {
    #[serde(default)]
    pub accepted: bool,
    #[serde(default)]
    pub reason: String,
}

// ---------------------------------------------------------------------------
// 增量策略
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyDelta {
    #[serde(default)]
    pub base_version: u64,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub add_blacklist: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub remove_blacklist: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty_map")]
    pub rule_weight: HashMap<String, f64>,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub block_targets: Vec<String>,
}

// ---------------------------------------------------------------------------
// 事件与指标
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatEvent {
    #[serde(default)]
    pub trace_id: String,
    #[serde(default)]
    pub ts: i64,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub ctx: String,
    #[serde(default)]
    pub target: String,
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub hits: Vec<RuleHit>,
    #[serde(default)]
    pub sample: String,
    #[serde(default)]
    pub proxy_used: String,
    #[serde(default)]
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleHit {
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub rule_name: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricBatch {
    #[serde(default)]
    pub ts: i64,
    #[serde(default)]
    pub requests_total: u64,
    #[serde(default)]
    pub blocked_total: u64,
    #[serde(default)]
    pub switched_total: u64,
    #[serde(default)]
    pub pool_active: i32,
    #[serde(default)]
    pub pool_total: i32,
    #[serde(default)]
    pub avg_upstream_ms: f64,
    #[serde(default)]
    pub extras: HashMap<String, i64>,
}

/// 事件类型 / 动作常量（与 Go contract 对齐）。
pub const KIND_DETECT: &str = "detect";
pub const KIND_SWITCH: &str = "switch";
/// 契约语义表预留：熔断事件由后续熔断模块使用。
#[allow(dead_code)]
pub const KIND_CIRCUIT: &str = "circuit";

pub const ACTION_BLOCKED: &str = "blocked";
/// 契约语义表预留（warn 动作尚无产生点）。
#[allow(dead_code)]
pub const ACTION_WARNED: &str = "warned";
pub const ACTION_SWITCHED: &str = "switched";
pub const ACTION_LOGGED: &str = "logged";
pub const ACTION_PASSED: &str = "passed";

// ---------------------------------------------------------------------------
// 共享状态
// ---------------------------------------------------------------------------

/// 数据面运行时状态：快照 + 增量策略的合并视图。
///
/// 数据面自持原则：所有读取都从本结构出发；Go 断开时继续用最后快照运行。
pub struct SharedState {
    pub inner: RwLock<Inner>,
    /// 进程启动时刻（uptime 指标预留）。
    #[allow(dead_code)]
    pub started: Instant,
    /// 规则目录（规则热载预留）。
    #[allow(dead_code)]
    pub rules_dir: String,
}

#[derive(Debug, Default)]
pub struct Inner {
    pub version: u64,
    pub pool: Vec<String>,
    pub routing: RoutingTable,
    pub policy: Policy,
    pub blacklist: HashSet<String>,
    pub block_targets: HashSet<String>,
    pub rule_weight: HashMap<String, f64>,
}

impl Default for SharedState {
    fn default() -> Self {
        SharedState {
            inner: RwLock::new(Inner {
                policy: Policy::default(),
                ..Default::default()
            }),
            started: Instant::now(),
            rules_dir: "rules".to_string(),
        }
    }
}

impl SharedState {
    pub fn new(rules_dir: impl Into<String>) -> Arc<Self> {
        Arc::new(SharedState {
            rules_dir: rules_dir.into(),
            ..Default::default()
        })
    }

    /// 应用全量快照（原子替换）。version 必须严格递增。
    pub async fn apply_snapshot(&self, snap: ConfigSnapshot) -> Result<(), String> {
        let mut w = self.inner.write().await;
        if snap.version <= w.version {
            return Err(format!(
                "version {} <= current {}",
                snap.version, w.version
            ));
        }
        w.version = snap.version;
        w.pool = snap.pool;
        w.routing = snap.routing;
        w.policy = snap.policy;
        w.blacklist = snap.blacklist.into_iter().collect();
        Ok(())
    }

    /// 应用增量策略。base_version 不匹配时拒绝（调用方应回退全量快照）。
    pub async fn apply_delta(&self, d: PolicyDelta) -> Result<(), String> {
        let mut w = self.inner.write().await;
        if d.base_version != 0 && d.base_version != w.version {
            return Err(format!(
                "base_version {} != current {}",
                d.base_version, w.version
            ));
        }
        for addr in d.add_blacklist {
            w.blacklist.insert(addr);
        }
        for addr in d.remove_blacklist {
            w.blacklist.remove(&addr);
        }
        for (rule, weight) in d.rule_weight {
            w.rule_weight.insert(rule, weight);
        }
        // block_targets 为幂等全量集合（Go 每次都发当前全集）
        w.block_targets = d.block_targets.into_iter().collect();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_version_monotonic() {
        let st = SharedState::new("rules");
        let mut snap = ConfigSnapshot {
            version: 2,
            pool: vec!["1.1.1.1:80".into()],
            ..Default::default()
        };
        assert!(st.apply_snapshot(snap.clone()).await.is_ok());

        // 旧版本被拒
        snap.version = 1;
        assert!(st.apply_snapshot(snap.clone()).await.is_err());

        // 同版本被拒
        snap.version = 2;
        assert!(st.apply_snapshot(snap).await.is_err());

        // 新版本生效
        let snap3 = ConfigSnapshot {
            version: 3,
            pool: vec!["2.2.2.2:80".into()],
            ..Default::default()
        };
        assert!(st.apply_snapshot(snap3).await.is_ok());
        let r = st.inner.read().await;
        assert_eq!(r.version, 3);
        assert_eq!(r.pool, vec!["2.2.2.2:80"]);
    }

    #[tokio::test]
    async fn delta_base_version_check() {
        let st = SharedState::new("rules");
        let snap = ConfigSnapshot {
            version: 5,
            ..Default::default()
        };
        st.apply_snapshot(snap).await.unwrap();

        // base_version 不匹配被拒
        let bad = PolicyDelta {
            base_version: 4,
            ..Default::default()
        };
        assert!(st.apply_delta(bad).await.is_err());

        // 匹配时生效
        let good = PolicyDelta {
            base_version: 5,
            add_blacklist: vec!["9.9.9.9:8080".into()],
            block_targets: vec!["evil.example".into()],
            rule_weight: HashMap::from([("js_packer_eval".to_string(), 0.5)]),
            ..Default::default()
        };
        assert!(st.apply_delta(good).await.is_ok());
        let r = st.inner.read().await;
        assert!(r.blacklist.contains("9.9.9.9:8080"));
        assert!(r.block_targets.contains("evil.example"));
        assert_eq!(r.rule_weight.get("js_packer_eval"), Some(&0.5));
    }
}
