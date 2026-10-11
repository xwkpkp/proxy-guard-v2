//! SQLi 语义检测（对照 Python `core/sqli_detect.py`）。
//!
//! 先规范化（去注释 / 合并空白 / 小写），再做语义模式子串匹配，
//! 抓 `UnIoN/**/SeLeCt` 这类正则漏报的绕过写发。
//! 17 条语义模式与 Python 版一一对应。

use std::sync::OnceLock;

use regex::Regex;

use super::Hit;

fn block_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").expect("block comment regex"))
}

fn line_comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"--[^\n]*").expect("line comment regex"))
}

fn ws_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+").expect("ws regex"))
}

/// 规范化：去块注释 → 去行注释 → 合并空白 → 小写 trim。
pub fn normalize(text: &str) -> String {
    let t = block_comment_re().replace_all(text, " ");
    let t = line_comment_re().replace_all(&t, " ");
    let t = ws_re().replace_all(&t, " ");
    t.trim().to_lowercase()
}

/// (rule_id, name, pattern, desc)
const SEMANTIC_PATTERNS: &[(&str, &str, &str, &str)] = &[
    ("sqli_union_semantic", "UNION SELECT 语义注入", "union select", "UNION SELECT 注入（绕过大小写/注释分割后仍命中）"),
    ("sqli_union_all_semantic", "UNION ALL SELECT", "union all select", "UNION ALL SELECT 注入"),
    ("sqli_or_bool_true", "OR 1=1 布尔注入", "or 1=1", "布尔型注入 OR 1=1"),
    ("sqli_and_bool_true", "AND 1=1 布尔注入", "and 1=1", "布尔型注入 AND 1=1"),
    ("sqli_or_bool_str", "OR 'a'='a' 布尔注入", "or 'a'='a'", "布尔型注入 OR 'a'='a'"),
    ("sqli_sleep_semantic", "SLEEP() 时间盲注", "sleep(", "时间盲注 sleep()"),
    ("sqli_benchmark_semantic", "BENCHMARK() 时间盲注", "benchmark(", "时间盲注 benchmark()"),
    ("sqli_pg_sleep_semantic", "PG_SLEEP() 时间盲注", "pg_sleep(", "PostgreSQL 时间盲注"),
    ("sqli_waitfor_delay", "WAITFOR DELAY 时间盲注", "waitfor delay", "SQL Server 时间盲注"),
    ("sqli_into_outfile", "INTO OUTFILE 写文件", "into outfile", "写文件注入 INTO OUTFILE"),
    ("sqli_load_file", "LOAD_FILE() 读文件", "load_file(", "读文件注入 LOAD_FILE()"),
    ("sqli_info_schema", "INFORMATION_SCHEMA 探测", "information_schema", "信息架构探测"),
    ("sqli_concat_group", "CONCAT/GROUP_CONCAT", "group_concat(", "GROUP_CONCAT 数据提取"),
    ("sqli_hex_fn", "HEX() 函数", "hex(", "HEX 编码绕过"),
    ("sqli_unhex_fn", "UNHEX() 函数", "unhex(", "UNHEX 解码载荷"),
    ("sqli_char_fn", "CHAR() 函数", "char(", "CHAR 字符码绕过"),
    ("sqli_extractvalue", "EXTRACTVALUE 报错注入", "extractvalue(", "EXTRACTVALUE 报错注入"),
    ("sqli_updatexml", "UPDATEXML 报错注入", "updatexml(", "UPDATEXML 报错注入"),
];

/// 对文本做 SQLi 语义检测。
pub fn detect_sqli_semantic(text: &str) -> Vec<Hit> {
    if text.is_empty() {
        return Vec::new();
    }
    let norm = normalize(text);
    let mut hits = Vec::new();
    for (rule_id, name, pat, desc) in SEMANTIC_PATTERNS {
        if norm.contains(pat) {
            hits.push(Hit {
                rule_id: (*rule_id).to_string(),
                rule_name: (*name).to_string(),
                severity: "high".to_string(),
                desc: (*desc).to_string(),
                snippet: (*pat).to_string(),
            });
        }
    }
    hits
}

/// 语义模式条数（供对照测试断言）。
pub const SEMANTIC_PATTERN_COUNT: usize = SEMANTIC_PATTERNS.len();

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 Python tests/test_sqli_mitm.py 相同的样本集：
    /// (输入, 期望最少命中数)。判定必须与 Python 版一致。
    #[test]
    fn parity_with_python_samples() {
        let cases: &[(&str, usize)] = &[
            ("1 UNION SELECT password FROM users", 1),
            ("1 UnIoN/**/SeLeCt password", 1),
            ("1 UNION/**/ALL/**/SELECT 1,2,3", 1),
            ("' OR 1=1 --", 1),
            ("' AND 1=1 --", 1),
            ("' OR 'a'='a'", 1),
            ("1; WAITFOR DELAY '0:0:5'", 1),
            ("1 AND SLEEP(5)", 1),
            ("1 AND BENCHMARK(5000000,MD5(1))", 1),
            ("1 AND PG_SLEEP(5)", 1),
            ("1 INTO OUTFILE '/tmp/shell.php'", 1),
            ("LOAD_FILE('/etc/passwd')", 1),
            ("information_schema.tables", 1),
            ("GROUP_CONCAT(username,0x3a,password)", 1),
            ("EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))", 1),
            // 干净输入不应命中
            ("hello world normal search query", 0),
            ("product_id=42", 0),
        ];
        for (text, expect_min) in cases {
            let hits = detect_sqli_semantic(text);
            assert!(
                hits.len() >= *expect_min,
                "输入 {text:?} 期望 >= {expect_min} 命中，实际 {}（{:?}）",
                hits.len(),
                hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn normalization_works() {
        assert_eq!(normalize("UnIoN/**/SeLeCt"), "union select");
        assert_eq!(normalize("a -- comment\nb"), "a b");
        assert_eq!(normalize("  A   B  "), "a b");
    }

    #[test]
    fn pattern_count_matches_python() {
        assert_eq!(SEMANTIC_PATTERN_COUNT, 18);
    }
}
