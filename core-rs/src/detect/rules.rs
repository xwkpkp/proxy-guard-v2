//! YAML 规则加载与编译。
//!
//! 与 Python 参照实现（core/detectors.py）消费**同一份** rules/*.yaml 文件，
//! 规则格式不变。regex crate 与 Python re 在本项目使用的语法子集上行为一致
//! （含 (?i) 内联 flag、字符类、[\s\S]）。

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct RawRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default = "def_severity")]
    severity: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    field: String,
    #[serde(rename = "type", default = "def_rtype")]
    rtype: String,
    #[serde(default)]
    pattern: String,
    #[serde(default)]
    desc: String,
}

fn def_severity() -> String {
    "low".to_string()
}

fn def_rtype() -> String {
    "substring".to_string()
}

#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<RawRule>,
}

/// 编译后的规则。
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub scope: String,
    pub field: String,
    /// regex / substring / contains_any
    pub rtype: String,
    pub pattern: String,
    pub regex: Option<Regex>,
    pub desc: String,
}

/// 加载一个规则文件。default_scope 用于缺省 scope 的规则
/// （脚本规则 → response_body，流量规则 → request_path）。
pub fn load_rule_file(path: &Path, default_scope: &str) -> Result<Vec<Rule>> {
    let text = fs::read_to_string(path).with_context(|| format!("读取规则 {}", path.display()))?;
    let file: RulesFile =
        serde_yaml::from_str(&text).with_context(|| format!("解析规则 {}", path.display()))?;

    let mut out = Vec::with_capacity(file.rules.len());
    for raw in file.rules {
        let regex = if raw.rtype == "regex" {
            match Regex::new(&raw.pattern) {
                Ok(re) => Some(re),
                Err(err) => {
                    log::warn!("规则 {} 正则编译失败: {err}", raw.id);
                    None
                }
            }
        } else {
            None
        };
        let scope = if raw.scope.is_empty() {
            default_scope.to_string()
        } else {
            raw.scope.clone()
        };
        out.push(Rule {
            id: raw.id,
            name: raw.name,
            severity: raw.severity,
            scope,
            field: raw.field,
            rtype: raw.rtype,
            pattern: raw.pattern,
            regex,
            desc: raw.desc,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn rules_dir() -> PathBuf {
        // 仓库根目录的 rules/（测试从 core-rs/ 运行）
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rules")
    }

    #[test]
    fn loads_all_rules() {
        let script = load_rule_file(&rules_dir().join("malicious_signatures.yaml"), "response_body")
            .expect("脚本规则应可加载");
        let traffic = load_rule_file(&rules_dir().join("traffic_rules.yaml"), "request_path")
            .expect("流量规则应可加载");

        // 与 Python 版数量对齐：13 条签名 + 15 条流量规则
        assert_eq!(script.len(), 13, "签名规则数量");
        assert_eq!(traffic.len(), 15, "流量规则数量");

        // 所有 regex 规则都应编译成功
        for r in script.iter().chain(traffic.iter()) {
            if r.rtype == "regex" {
                assert!(r.regex.is_some(), "规则 {} 正则应编译成功", r.id);
            }
        }
    }

    #[test]
    fn default_scope_applied() {
        let traffic = load_rule_file(&rules_dir().join("traffic_rules.yaml"), "request_path")
            .expect("加载失败");
        // 未显式写 scope 的规则（如 path_env_file 有 scope，但确保默认逻辑）
        assert!(traffic.iter().all(|r| !r.scope.is_empty()));
    }
}
