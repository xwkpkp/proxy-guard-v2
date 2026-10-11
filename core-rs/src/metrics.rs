//! 数据面指标（原子计数，供 /metrics 汇总）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::MetricBatch;
use crate::trace::now_unix;

/// 全局指标计数器。
#[derive(Default)]
pub struct Metrics {
    pub requests_total: AtomicU64,
    pub blocked_total: AtomicU64,
    pub switched_total: AtomicU64,
    pub ssrf_blocked: AtomicU64,
    pub redline_blocked: AtomicU64,
    pub events_dropped: AtomicU64,
    pub connect_failures: AtomicU64,
    /// 上游耗时累计（毫秒）与计数，用于平均值。
    pub upstream_ms_sum: AtomicU64,
    pub upstream_count: AtomicU64,
}

impl Metrics {
    pub fn add_upstream_ms(&self, ms: u64) {
        self.upstream_ms_sum.fetch_add(ms, Ordering::Relaxed);
        self.upstream_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 生成指标批次。
    pub fn snapshot(&self, pool_active: i32, pool_total: i32) -> MetricBatch {
        let cnt = self.upstream_count.load(Ordering::Relaxed);
        let sum = self.upstream_ms_sum.load(Ordering::Relaxed);
        let avg = if cnt > 0 { sum as f64 / cnt as f64 } else { 0.0 };

        let mut extras = HashMap::new();
        extras.insert(
            "events_dropped".to_string(),
            self.events_dropped.load(Ordering::Relaxed) as i64,
        );
        extras.insert(
            "connect_failures".to_string(),
            self.connect_failures.load(Ordering::Relaxed) as i64,
        );
        extras.insert(
            "ssrf_blocked".to_string(),
            self.ssrf_blocked.load(Ordering::Relaxed) as i64,
        );
        extras.insert(
            "redline_blocked".to_string(),
            self.redline_blocked.load(Ordering::Relaxed) as i64,
        );

        MetricBatch {
            ts: now_unix(),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            switched_total: self.switched_total.load(Ordering::Relaxed),
            pool_active,
            pool_total,
            avg_upstream_ms: avg,
            extras,
        }
    }
}
