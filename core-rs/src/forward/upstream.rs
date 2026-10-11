//! 上游出口选择与轮换执行（快路径）。
//!
//! 决定权/执行权分离：
//!   - 决定权（慢循环）在 Go：候选池、策略参数由快照下发；
//!   - 执行权（快路径）在本模块：每请求选择 + **失败即时切换**（本地冷却，
//!     不等 Go 往返，否则延迟爆炸）。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::RotationPolicy;

/// 出口选择器。
pub struct UpstreamPicker {
    counter: AtomicU64,
    inner: Mutex<PickerInner>,
}

#[derive(Default)]
struct PickerInner {
    cooldown: HashMap<String, Instant>,
    fail_streak: HashMap<String, u32>,
    current: String,
}

/// 一次选择的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// 直连（路由层已决定直连时由调用方处理；该变体保留语义完整）。
    #[allow(dead_code)]
    Direct,
    /// 经指定出口。
    Via(String),
    /// 需要走代理但池不可用。
    NoUpstream,
}

impl UpstreamPicker {
    pub fn new() -> Self {
        UpstreamPicker {
            counter: AtomicU64::new(0),
            inner: Mutex::new(PickerInner::default()),
        }
    }

    /// 从池中挑一个可用出口（跳过黑名单与冷却中的）。
    ///
    /// 策略：round_robin 为主（random 用计数+扰动实现）；fastest / least_used
    /// 在 v2.0 退化为 round_robin（延迟数据由 Go 侧评分，快路径不做二次判定）。
    pub fn pick(
        &self,
        pool: &[String],
        blacklist: &HashSet<String>,
        policy: &RotationPolicy,
    ) -> Pick {
        let candidates: Vec<&String> = {
            let now = Instant::now();
            let inner = self.inner.lock().unwrap();
            pool.iter()
                .filter(|addr| !blacklist.contains(*addr))
                .filter(|addr| {
                    inner
                        .cooldown
                        .get(*addr)
                        .map(|until| *until <= now)
                        .unwrap_or(true)
                })
                .collect()
        };

        if candidates.is_empty() {
            return Pick::NoUpstream;
        }

        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let idx = match policy.strategy.as_str() {
            "random" => (n.wrapping_mul(2654435761)) as usize % candidates.len(),
            _ => (n as usize) % candidates.len(),
        };
        let chosen = candidates[idx].clone();

        let mut inner = self.inner.lock().unwrap();
        inner.current = chosen.clone();
        Pick::Via(chosen)
    }

    /// 汇报成功（清失败计数）。
    pub fn report_success(&self, addr: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.fail_streak.remove(addr);
    }

    /// 汇报失败：连续失败达阈值则进入冷却（本地即时，无需 Go 参与）。
    pub fn report_failure(&self, addr: &str, policy: &RotationPolicy) {
        let mut inner = self.inner.lock().unwrap();
        let streak = inner.fail_streak.entry(addr.to_string()).or_insert(0);
        *streak += 1;
        let threshold = if policy.max_failures > 0 {
            policy.max_failures as u32
        } else {
            3
        };
        if *streak >= threshold {
            let cooldown = if policy.cooldown_s > 0 {
                policy.cooldown_s as u64
            } else {
                30
            };
            inner
                .cooldown
                .insert(addr.to_string(), Instant::now() + Duration::from_secs(cooldown));
            inner.fail_streak.remove(addr);
            log::warn!(
                "出口 {addr} 连续失败达 {threshold} 次，冷却 {cooldown}s（本地即时切换）"
            );
        }
    }

    /// 强制冷却（响应注入等场景，对照 Python force_rotate）。
    pub fn force_cooldown(&self, addr: &str, cooldown_s: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.cooldown.insert(
            addr.to_string(),
            Instant::now() + Duration::from_secs(cooldown_s.max(1)),
        );
        inner.fail_streak.remove(addr);
        log::warn!("出口 {addr} 被强制冷却 {cooldown_s}s");
    }

    /// 当前生效出口（指标 / 调试用）。
    #[allow(dead_code)]
    pub fn current(&self) -> String {
        self.inner.lock().unwrap().current.clone()
    }

    /// 冷却中的出口数量（指标 / 调试用）。
    #[allow(dead_code)]
    pub fn cooling_count(&self) -> usize {
        let now = Instant::now();
        self.inner
            .lock()
            .unwrap()
            .cooldown
            .values()
            .filter(|until| **until > now)
            .count()
    }
}

impl Default for UpstreamPicker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> Vec<String> {
        vec!["1.1.1.1:80".into(), "2.2.2.2:80".into(), "3.3.3.3:80".into()]
    }

    #[test]
    fn round_robin_cycles() {
        let p = UpstreamPicker::new();
        let pol = RotationPolicy::default();
        let seen: Vec<String> = (0..6)
            .map(|_| match p.pick(&pool(), &HashSet::new(), &pol) {
                Pick::Via(a) => a,
                other => panic!("应选中出口: {other:?}"),
            })
            .collect();
        assert_eq!(seen[0], seen[3]);
        assert_eq!(seen[1], seen[4]);
        assert_eq!(seen[2], seen[5]);
        assert_ne!(seen[0], seen[1]);
    }

    #[test]
    fn blacklist_skipped() {
        let p = UpstreamPicker::new();
        let pol = RotationPolicy::default();
        let bl: HashSet<String> = ["1.1.1.1:80".to_string()].into();
        for _ in 0..6 {
            match p.pick(&pool(), &bl, &pol) {
                Pick::Via(a) => assert_ne!(a, "1.1.1.1:80"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn failure_triggers_cooldown_and_switch() {
        let p = UpstreamPicker::new();
        let pol = RotationPolicy {
            max_failures: 2,
            cooldown_s: 60,
            ..Default::default()
        };
        // 打到 1.1.1.1 然后报两次失败 → 冷却
        p.report_failure("1.1.1.1:80", &pol);
        p.report_failure("1.1.1.1:80", &pol);
        assert_eq!(p.cooling_count(), 1);

        // 之后连续 4 次选择都不应再出现 1.1.1.1
        for _ in 0..4 {
            match p.pick(&pool(), &HashSet::new(), &pol) {
                Pick::Via(a) => assert_ne!(a, "1.1.1.1:80"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn empty_pool_no_upstream() {
        let p = UpstreamPicker::new();
        let pol = RotationPolicy::default();
        assert_eq!(p.pick(&[], &HashSet::new(), &pol), Pick::NoUpstream);
    }

    #[test]
    fn all_cooling_no_upstream() {
        let p = UpstreamPicker::new();
        let pol = RotationPolicy {
            max_failures: 1,
            cooldown_s: 60,
            ..Default::default()
        };
        for a in pool() {
            p.report_failure(&a, &pol);
        }
        assert_eq!(p.pick(&pool(), &HashSet::new(), &pol), Pick::NoUpstream);
    }
}
