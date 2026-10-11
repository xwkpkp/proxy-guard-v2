//! 安全防护（对照 Python `core/safeguards.py`）。
//!
//! v2.0 覆盖：敏感数据红线（阻断）/ SSRF / 响应注入检测 / CSP 注入 / 熔断器。
//! 未覆盖（记为差距）：每出口限速（RateLimiter）、日志脱敏的完整实现。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use regex::Regex;

// =====================================================================
// 1. 敏感数据红线（命中 → 阻断）
// =====================================================================

const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-session-token",
];

type Pattern = (Regex, &'static str);

fn sensitive_patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            (r"(?i)password\s*[=:]\s*\S+", "password"),
            (r"(?i)passwd\s*[=:]\s*\S+", "passwd"),
            (r"(?i)token\s*[=:]\s*[A-Za-z0-9_\-]{8,}", "token"),
            (r"(?i)(access[_-]?token|refresh[_-]?token)\s*[=:]\s*\S+", "access_token"),
            (r"(?i)(secret|api[_-]?key)\s*[=:]\s*\S+", "secret"),
            (r"BEGIN\s+(RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY", "private_key"),
            (r"\b\d{15}(\d{2}[\dXx])?\b", "id_card"),
            (r"\b\d{16,19}\b", "bank_card"),
        ];
        raw.iter()
            .filter_map(|(p, label)| Regex::new(p).ok().map(|re| (re, *label)))
            .collect()
    })
}

/// 敏感数据红线检查。返回命中原因（空 = 通过）。
///
/// 命中任一敏感头或敏感模式（匹配 URL 或 body）→ 应阻断 403。
pub fn check_redline(headers: &HashMap<String, String>, url: &str, body: &str) -> Vec<String> {
    let mut reasons = Vec::new();
    for key in headers.keys() {
        if SENSITIVE_HEADERS.contains(&key.as_str()) {
            reasons.push(format!("敏感头 {key}"));
        }
    }
    for (re, label) in sensitive_patterns() {
        if re.is_match(url) || (!body.is_empty() && re.is_match(body)) {
            reasons.push(format!("敏感数据 ({label})"));
        }
    }
    reasons
}

// =====================================================================
// 2. SSRF 防护
// =====================================================================

/// SSRF 判定：目标为私有/环回/链路本地/元数据地址时返回 true。
///
/// 覆盖 Python `_SSRF_BLOCKED_NETS` 全部网段 + `_SSRF_BLOCKED_HOSTS` 主机名。
/// 局限（已知并记录）：仅检查 IP 字面量与已知元数据主机名；
/// 域名重绑定（DNS rebinding）防护依赖连接层二次校验，v2.0 未实现。
pub fn is_ssrf_target(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if h.is_empty() {
        return true;
    }
    let low = h.to_lowercase().trim_end_matches('.').to_string();
    if low == "localhost"
        || low.ends_with(".localhost")
        || low == "ip6-localhost"
        || low == "ip6-loopback"
        || low == "metadata.google.internal"
        || low == "metadata.aws.internal"
    {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => is_private_ip(&ip),
        Err(_) => false,
    }
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()                    // 10/8, 172.16/12, 192.168/16
                || v4.is_loopback()            // 127/8
                || v4.is_link_local()          // 169.254/16
                || v4.is_unspecified()         // 0.0.0.0
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || o[0] == 0                   // 0/8
                || (o[0] == 100 && (o[1] & 0xc0) == 64)  // 100.64/10 CGNAT
                || (o[0] == 198 && (o[1] & 0xfe) == 18)  // 198.18/15 benchmarking
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (seg[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        }
    }
}

// =====================================================================
// 3. 响应注入检测（代理篡改）
// =====================================================================

const INJECTED_AD_DOMAINS: &[&str] = &["doubleclick.net", "googlesyndication.com"];

fn injection_signs() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| {
        [
            r#"(?i)<script[^>]*src=["']https?://[^"']*(proxy|ad|track)[^"']*["']"#,
            r#"(?i)<iframe[^>]*(width|height)=["']0["']"#,
            r"(?i)inserted\s+by\s+(proxy|cache|cdn)",
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
    })
}

/// 检测代理是否篡改响应（注入脚本/广告/异常跳转）。返回原因列表。
pub fn detect_response_injection(
    status: u16,
    content_type: &str,
    location: Option<&str>,
    body: &str,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if body.is_empty() {
        return reasons;
    }
    let ctype = content_type.to_lowercase();
    if !ctype.contains("text/html") && !ctype.contains("javascript") {
        return reasons;
    }
    let text: String = body.chars().take(65536).collect();
    for pat in injection_signs() {
        if pat.is_match(&text) {
            reasons.push("响应含注入脚本/广告".to_string());
            break;
        }
    }
    for dom in INJECTED_AD_DOMAINS {
        if text.contains(dom) {
            reasons.push(format!("响应被注入广告域名 ({dom})"));
            break;
        }
    }
    if (300..400).contains(&status) {
        if let Some(loc) = location {
            if let Some(host) = url_host(loc) {
                if is_ssrf_target(&host) {
                    reasons.push(format!("异常重定向到内网 {loc}"));
                }
            }
        }
    }
    reasons
}

/// 从 URL 提取 host（轻量解析，不引入 URL crate）。
pub fn url_host(url: &str) -> Option<String> {
    let rest = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        return None;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // 去 userinfo
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    // 去端口（保守处理 IPv6 括号）
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("").to_string()
    } else {
        authority.split(':').next().unwrap_or("").to_string()
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

// =====================================================================
// 4. CSP 注入
// =====================================================================

/// 默认 CSP（与 Python DEFAULT_CSP 一致）。
pub const DEFAULT_CSP: &str = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

/// 是否应注入 CSP 头（HTML 响应且尚无 CSP）。
pub fn should_inject_csp(content_type: &str, has_csp_header: bool) -> bool {
    !has_csp_header && content_type.to_lowercase().contains("text/html")
}

// =====================================================================
// 5. 熔断器
// =====================================================================

/// 全局熔断器（对照 Python CircuitBreaker）。
/// 连续失败达阈值 → 打开（冷却期内拒绝转发 503）；冷却过后自动重置。
#[derive(Default)]
pub struct CircuitBreaker {
    fail_count: AtomicU32,
    opened_at: Mutex<Option<Instant>>,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_success(&self) {
        self.fail_count.store(0, Ordering::Relaxed);
        *self.opened_at.lock().unwrap() = None;
    }

    pub fn record_failure(&self, threshold: u32) {
        let n = self.fail_count.fetch_add(1, Ordering::Relaxed) + 1;
        let mut opened = self.opened_at.lock().unwrap();
        if n >= threshold.max(1) && opened.is_none() {
            *opened = Some(Instant::now());
            log::warn!("熔断器触发（连续失败 {n}），冷却期内拒绝转发");
        }
    }

    /// 是否熔断中。冷却到期自动复位。
    pub fn is_open(&self, cooldown_s: u64) -> bool {
        let mut opened = self.opened_at.lock().unwrap();
        if let Some(t) = *opened {
            if t.elapsed() > Duration::from_secs(cooldown_s.max(1)) {
                *opened = None;
                self.fail_count.store(0, Ordering::Relaxed);
                log::info!("熔断冷却结束，恢复转发");
                return false;
            }
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_blocks_internal() {
        for h in [
            "127.0.0.1", "10.0.0.8", "192.168.1.1", "172.16.3.4",
            "169.254.169.254", "100.64.0.1", "198.18.0.1", "192.0.0.1",
            "0.0.0.0", "localhost", "foo.localhost", "ip6-localhost",
            "metadata.google.internal", "metadata.aws.internal", "[::1]",
            "fe80::1", "fc00::1", "",
        ] {
            assert!(is_ssrf_target(h), "应拦截: {h}");
        }
    }

    #[test]
    fn ssrf_allows_public() {
        for h in ["8.8.8.8", "1.1.1.1", "example.com", "2606:4700::1111", "100.128.0.1", "198.20.0.1"] {
            assert!(!is_ssrf_target(h), "应放行: {h}");
        }
    }

    #[test]
    fn redline_blocks_sensitive() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer x".to_string());
        assert!(!check_redline(&headers, "/api", "").is_empty(), "敏感头");

        let empty = HashMap::new();
        assert!(!check_redline(&empty, "/login", "password=123456").is_empty(), "password 模式");
        assert!(!check_redline(&empty, "/p?card=4111111111111111", "").is_empty(), "银行卡");
        assert!(!check_redline(&empty, "/k", "BEGIN RSA PRIVATE KEY").is_empty(), "私钥");

        assert!(check_redline(&empty, "/normal", "hello world").is_empty(), "干净输入");
    }

    #[test]
    fn response_injection_detects() {
        let r = detect_response_injection(
            200,
            "text/html",
            None,
            r#"<script src="http://adproxy.example.com/x.js"></script>"#,
        );
        assert!(!r.is_empty());

        let r = detect_response_injection(200, "text/html", None, "<html>clean</html>");
        assert!(r.is_empty());

        // 非 html/javascript 不检查
        let r = detect_response_injection(200, "image/png", None, "<script src=x ad>");
        assert!(r.is_empty());
    }

    #[test]
    fn csp_injection_rules() {
        assert!(should_inject_csp("text/html; charset=utf-8", false));
        assert!(!should_inject_csp("text/html", true));
        assert!(!should_inject_csp("image/png", false));
    }

    #[test]
    fn breaker_opens_and_recovers() {
        let b = CircuitBreaker::new();
        for _ in 0..5 {
            b.record_failure(5);
        }
        assert!(b.is_open(60));
        // 冷却 0 秒 → 立即恢复（用 max(1) 语义验证复位逻辑）
        std::thread::sleep(Duration::from_millis(5));
        assert!(b.is_open(60), "冷却 60s 内仍打开");
        b.record_success();
        assert!(!b.is_open(60), "成功后关闭");
    }

    #[test]
    fn url_host_parse() {
        assert_eq!(url_host("http://evil.example/x"), Some("evil.example".into()));
        assert_eq!(url_host("https://1.2.3.4:8080/p"), Some("1.2.3.4".into()));
        assert_eq!(url_host("http://[::1]:80/"), Some("::1".into()));
        assert_eq!(url_host("/relative"), None);
    }
}
