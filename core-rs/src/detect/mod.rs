//! 检测引擎聚合入口：签名规则 + 启发式 + SQLi 语义。
//!
//! 行为对齐 Python 参照实现（core/detectors.py + core/sqli_detect.py）：
//!   - 同一份 rules/*.yaml；
//!   - 同一套启发式阈值；
//!   - 同一组 SQLi 语义模式。
//! 对照测试见各子模块 tests 与 docs/contract.md「行为对照锚点」。

pub mod heuristics;
pub mod rules;
pub mod sqli;

use std::collections::HashMap;
use std::path::Path;

use crate::config::RuleHit;

/// 一条命中。
#[derive(Debug, Clone)]
pub struct Hit {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    /// 语义详情（v2.1 事件扩展将携带到契约）。
    #[allow(dead_code)]
    pub desc: String,
    pub snippet: String,
}

impl Hit {
    /// 转换为契约结构（进事件流）。
    pub fn to_contract(&self) -> RuleHit {
        RuleHit {
            rule_id: self.rule_id.clone(),
            rule_name: self.rule_name.clone(),
            severity: self.severity.clone(),
            snippet: heuristics::truncate_chars(&self.snippet, 120),
        }
    }
}

/// 检测引擎。
pub struct Detector {
    pub script_rules: Vec<rules::Rule>,
    pub traffic_rules: Vec<rules::Rule>,
}

/// 权重 <= 该值的规则命中被静默（误报纠正，Go 侧研判回写）。
const WEIGHT_MUTE_THRESHOLD: f64 = 0.5;

impl Detector {
    /// 从规则目录加载。文件缺失时返回空引擎（降级为纯启发式+SQLi）。
    pub fn load(rules_dir: &Path) -> Self {
        let script = rules::load_rule_file(
            &rules_dir.join("malicious_signatures.yaml"),
            "response_body",
        )
        .unwrap_or_else(|err| {
            log::warn!("签名规则加载失败: {err:#}");
            Vec::new()
        });
        let traffic =
            rules::load_rule_file(&rules_dir.join("traffic_rules.yaml"), "request_path")
                .unwrap_or_else(|err| {
                    log::warn!("流量规则加载失败: {err:#}");
                    Vec::new()
                });
        log::info!(
            "检测引擎就绪: 签名规则 {} 条, 流量规则 {} 条, SQLi 语义 {} 条",
            script.len(),
            traffic.len(),
            sqli::SEMANTIC_PATTERN_COUNT
        );
        Detector {
            script_rules: script,
            traffic_rules: traffic,
        }
    }

    /// 扫描响应体：签名规则 + 启发式。
    pub fn scan_response(&self, body: &str, rule_weight: &HashMap<String, f64>) -> Vec<Hit> {
        let mut hits = Vec::new();
        for rule in &self.script_rules {
            if is_muted(&rule.id, rule_weight) {
                continue;
            }
            if let Some(h) = match_rule(rule, body) {
                hits.push(h);
            }
        }
        hits.extend(heuristics::scan_response_heuristics(body));
        hits
    }

    /// 扫描请求：流量规则（header / path / body）。
    pub fn scan_request(
        &self,
        path: &str,
        headers: &HashMap<String, String>,
        body: &str,
        rule_weight: &HashMap<String, f64>,
    ) -> Vec<Hit> {
        let mut hits = Vec::new();
        for rule in &self.traffic_rules {
            if is_muted(&rule.id, rule_weight) {
                continue;
            }
            let target: &str = match rule.scope.as_str() {
                "request_header" => headers
                    .get(&rule.field.to_lowercase())
                    .map(String::as_str)
                    .unwrap_or(""),
                "request_path" => path,
                "request_body" => body,
                _ => "",
            };
            if let Some(h) = match_rule(rule, target) {
                hits.push(h);
            }
        }
        hits
    }

    /// SQLi 语义检测（规范化 + 语义模式）。
    pub fn scan_sqli(&self, text: &str) -> Vec<Hit> {
        sqli::detect_sqli_semantic(text)
    }
}

fn is_muted(rule_id: &str, weights: &HashMap<String, f64>) -> bool {
    weights
        .get(rule_id)
        .is_some_and(|w| *w <= WEIGHT_MUTE_THRESHOLD)
}

/// 单条规则匹配（regex / substring / contains_any）。
fn match_rule(rule: &rules::Rule, text: &str) -> Option<Hit> {
    if text.is_empty() {
        return None;
    }
    match rule.rtype.as_str() {
        "regex" => {
            let re = rule.regex.as_ref()?;
            re.find(text).map(|m| Hit {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity.clone(),
                desc: rule.desc.clone(),
                snippet: heuristics::truncate_chars(m.as_str(), 120),
            })
        }
        "substring" => text.contains(&rule.pattern).then(|| Hit {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity.clone(),
            desc: rule.desc.clone(),
            snippet: heuristics::truncate_chars(&rule.pattern, 120),
        }),
        "contains_any" => rule
            .pattern
            .split('|')
            .find(|p| !p.is_empty() && text.contains(*p))
            .map(|p| Hit {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity.clone(),
                desc: rule.desc.clone(),
                snippet: heuristics::truncate_chars(p, 120),
            }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn detector() -> Detector {
        Detector::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rules"))
    }

    #[test]
    fn response_signature_hit() {
        let d = detector();
        let body = r#"<script>eval(function(p,a,c,k,e,d){...})</script>"#;
        let hits = d.scan_response(body, &HashMap::new());
        assert!(
            hits.iter().any(|h| h.rule_id == "js_packer_eval"),
            "{hits:?}"
        );
    }

    #[test]
    fn request_path_hit() {
        let d = detector();
        let hits = d.scan_request("/.env", &HashMap::new(), "", &HashMap::new());
        assert!(hits.iter().any(|h| h.rule_id == "path_env_file"), "{hits:?}");
    }

    #[test]
    fn request_header_hit() {
        let d = detector();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "sqlmap/1.7#stable".to_string());
        let hits = d.scan_request("/api", &headers, "", &HashMap::new());
        assert!(
            hits.iter().any(|h| h.rule_id == "scanner_ua_sqlmap"),
            "{hits:?}"
        );
    }

    #[test]
    fn muted_rule_skipped() {
        let d = detector();
        let weights = HashMap::from([("js_packer_eval".to_string(), 0.5)]);
        let body = r#"<script>eval(function(p,a,c,k,e,d){...})</script>"#;
        let hits = d.scan_response(body, &weights);
        assert!(
            !hits.iter().any(|h| h.rule_id == "js_packer_eval"),
            "被降权规则不应命中: {hits:?}"
        );
    }

    #[test]
    fn clean_request_no_hits() {
        let d = detector();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
        let hits = d.scan_request("/index.html", &headers, "q=hello", &HashMap::new());
        assert!(hits.is_empty(), "{hits:?}");
    }
}
