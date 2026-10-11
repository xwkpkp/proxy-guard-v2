//! trace_id 生成与日志辅助。
//!
//! 格式：`pg-<unix_ms_base36>-<8位随机hex>`（见 docs/contract.md）。
//! 只注入本地日志与事件，不传给上游服务器（避免行为指纹）。

use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;

/// 生成新的 trace_id。
pub fn new_trace_id() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let r: u32 = rand::thread_rng().gen();
    format!("pg-{}-{:08x}", base36(ms), r)
}

fn base36(mut n: u64) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".to_string();
    }
    let mut buf = Vec::with_capacity(13);
    while n > 0 {
        buf.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    buf.reverse();
    String::from_utf8(buf).unwrap_or_default()
}

/// 当前 unix 秒。
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_id_shape() {
        let id = new_trace_id();
        assert!(id.starts_with("pg-"), "前缀: {id}");
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 3, "格式: {id}");
        assert_eq!(parts[2].len(), 8, "随机段: {id}");
    }

    #[test]
    fn trace_id_unique() {
        let a = new_trace_id();
        let b = new_trace_id();
        assert_ne!(a, b);
    }
}
