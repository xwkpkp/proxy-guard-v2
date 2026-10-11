//! 启发式检测（对照 Python `_heuristic_response`）。
//!
//! 三条启发式：
//!   1. 超长高熵 Base64 块（≥2000 字符且熵 > 4.5）
//!   2. 超长 Hex 块（≥400 字符且熵 > 3.5）
//!   3. String.fromCharCode 密集拼接（计数 > 8）
//!
//! 阈值与 Python 版严格一致（见 tests 与 docs/contract.md 行为对照）。

use std::sync::OnceLock;

use regex::Regex;

use super::Hit;

fn b64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/=]{2000,}").expect("b64 regex"))
}

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[0-9a-fA-F]{400,}").expect("hex regex"))
}

fn charcode_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"String\.fromCharCode").expect("charcode regex"))
}

/// 香农熵（按字符/码点统计，与 Python 版一致）。
pub fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let mut n = 0usize;
    for ch in data.chars() {
        *freq.entry(ch).or_insert(0) += 1;
        n += 1;
    }
    let mut ent = 0.0;
    for cnt in freq.values() {
        let p = *cnt as f64 / n as f64;
        ent -= p * p.log2();
    }
    ent
}

/// 对响应体做启发式检测。
pub fn scan_response_heuristics(body: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    if body.is_empty() {
        return hits;
    }

    // 1. 超长高熵 Base64（只报首个块）
    for m in b64_re().find_iter(body) {
        if shannon_entropy(m.as_str()) > 4.5 {
            hits.push(Hit {
                rule_id: "heuristic_long_b64".into(),
                rule_name: "超长高熵 Base64 块".into(),
                severity: "medium".into(),
                desc: "响应中出现超长高熵字符串，疑似混淆载荷".into(),
                snippet: format!("{}...", truncate_chars(m.as_str(), 60)),
            });
            break;
        }
    }

    // 2. 超长 Hex（只报首个块）
    for m in hex_re().find_iter(body) {
        if shannon_entropy(m.as_str()) > 3.5 {
            hits.push(Hit {
                rule_id: "heuristic_long_hex".into(),
                rule_name: "超长 Hex 块".into(),
                severity: "medium".into(),
                desc: "响应中出现超长十六进制串，疑似 shellcode/编码载荷".into(),
                snippet: format!("{}...", truncate_chars(m.as_str(), 60)),
            });
            break;
        }
    }

    // 3. String.fromCharCode 密集拼接
    if charcode_re().find_iter(body).count() > 8 {
        hits.push(Hit {
            rule_id: "heuristic_charcode_spam".into(),
            rule_name: "String.fromCharCode 密集拼接".into(),
            severity: "medium".into(),
            desc: "响应中密集出现 String.fromCharCode，疑似混淆".into(),
            snippet: String::new(),
        });
    }

    hits
}

/// 按字符（非字节）截断，避免切坏 UTF-8。
pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_basics() {
        assert!((shannon_entropy("") - 0.0).abs() < f64::EPSILON);
        assert!(shannon_entropy("aaaa") < 0.5);
        assert!(shannon_entropy("abcdefghijklmnop") > 3.5);
    }

    #[test]
    fn long_b64_detected() {
        // 2001 个高熵 base64 字符
        let payload: String = (0..2001)
            .map(|i| {
                let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                alphabet[(i * 7 + 3) % 64] as char
            })
            .collect();
        let hits = scan_response_heuristics(&format!("<script>{payload}</script>"));
        assert!(hits.iter().any(|h| h.rule_id == "heuristic_long_b64"), "{hits:?}");
    }

    #[test]
    fn short_b64_not_detected() {
        let hits = scan_response_heuristics("aGVsbG8gd29ybGQ=");
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn charcode_spam_detected() {
        let body = "String.fromCharCode(1);".repeat(9);
        let hits = scan_response_heuristics(&body);
        assert!(hits.iter().any(|h| h.rule_id == "heuristic_charcode_spam"), "{hits:?}");
    }

    #[test]
    fn clean_body_no_hits() {
        let hits = scan_response_heuristics("<!doctype html><html><body>hello</body></html>");
        assert!(hits.is_empty(), "{hits:?}");
    }
}
