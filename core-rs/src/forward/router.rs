//! 域名路由（对照 Python `core/router.py`）。
//!
//! 决策顺序（mode=auto）：强制代理名单 → 直连后缀 → 直连白名单 → 默认走代理。
//! 路由表由 Go 快照下发（Go 生成、Rust 每请求查表执行）。

use crate::config::RoutingTable;

/// 路由决策结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Direct,
    Proxy,
}

/// 内置国内域名后缀（与 Python 版一致）。
const DOMESTIC_SUFFIXES: &[&str] = &[
    ".cn", ".com.cn", ".gov.cn", ".edu.cn", ".org.cn", ".net.cn",
    ".ac.cn", ".bj.cn", ".sh.cn", ".gd.cn", ".zj.cn", ".js.cn",
    ".tj.cn", ".cq.cn", ".sc.cn", ".sd.cn", ".ha.cn", ".hb.cn",
    ".中国", ".公司", ".网络", ".政务", ".公益", ".网址",
];

/// 内置国内常见域名白名单（按母域匹配，子域也命中）。
const DOMESTIC_NAMES: &[&str] = &[
    // 搜索 / 门户
    "baidu.com", "sogou.com", "so.com", "sina.com", "sina.com.cn",
    "sohu.com", "163.com", "126.com", "ifeng.com", "qq.com",
    "people.com.cn", "xinhuanet.com", "china.com", "huanqiu.com",
    // 电商
    "taobao.com", "tmall.com", "jd.com", "pinduoduo.com", "suning.com",
    "1688.com", "alibaba.com", "mi.com", "vivo.com.cn", "oppo.com",
    // 支付 / 金融
    "alipay.com", "tenpay.com", "weixin.qq.com", "icbc.com.cn",
    "ccb.com", "boc.cn", "abchina.com", "bank-comm.com", "cmbchina.com",
    // 社交 / 内容
    "weibo.com", "zhihu.com", "douban.com", "bilibili.com",
    "douyin.com", "kuaishou.com", "xiaohongshu.com", "tieba.baidu.com",
    // 视频 / 音乐
    "iqiyi.com", "youku.com", "mgtv.com", "music.163.com",
    "kugou.com", "kuwo.cn", "y.qq.com",
    // 游戏 / 直播
    "douyu.com", "huya.com", "yy.com",
    // 云服务 / 工具
    "cloud.tencent.com", "aliyun.com", "huaweicloud.com",
    "amap.com", "map.baidu.com", "gtimg.com",
    // CDN / 静态资源
    "bdstatic.com", "bdimg.com", "qqcdn.cn", "tencent-cloud.net",
    "alicdn.com", "mmstat.com", "tanx.com", "myqcloud.com",
    // 开发者社区 / 代码托管
    "csdn.net", "cnblogs.com", "jianshu.com", "oschina.net",
    "gitee.com", "coding.net", "segmentfault.com",
    // 快递 / 生活
    "sf-express.com", "yto.net.cn", "sto.cn", "meituan.com",
    "dianping.com", "ele.me", "58.com", "12306.cn",
];

/// 域名路由决策器。
#[derive(Debug, Default)]
pub struct DomainRouter {
    mode: String,
    direct_suffixes: Vec<String>,
    direct_names: Vec<String>,
    forced_proxy: Vec<String>,
}

impl DomainRouter {
    /// 从快照路由表构建（每版快照重建一次）。
    pub fn from_table(table: &RoutingTable) -> Self {
        let mut direct_suffixes: Vec<String> =
            DOMESTIC_SUFFIXES.iter().map(|s| s.to_string()).collect();
        direct_suffixes.extend(table.direct_suffixes.iter().cloned());

        let mut direct_names: Vec<String> =
            DOMESTIC_NAMES.iter().map(|s| s.to_string()).collect();
        for d in &table.direct_domains {
            let d = d.trim().to_lowercase();
            if !d.is_empty() {
                direct_names.push(d);
            }
        }

        let forced_proxy: Vec<String> = table
            .proxy_domains
            .iter()
            .map(|d| d.trim().to_lowercase())
            .filter(|d| !d.is_empty())
            .collect();

        DomainRouter {
            mode: if table.mode.is_empty() {
                "auto".to_string()
            } else {
                table.mode.clone()
            },
            direct_suffixes,
            direct_names,
            forced_proxy,
        }
    }

    /// host 规整：小写、去端口、去 IPv6 括号、去尾点。
    pub fn normalize(host: &str) -> String {
        let h = host.trim().to_lowercase();
        let h = if let Some(rest) = h.strip_prefix('[') {
            // IPv6: [::1]:443
            match rest.find(']') {
                Some(idx) => &rest[..idx],
                None => rest,
            }
        } else {
            match h.find(':') {
                Some(idx) => &h[..idx],
                None => &h[..],
            }
        };
        h.trim_matches('.').to_string()
    }

    fn match_names(host: &str, names: &[String]) -> bool {
        names
            .iter()
            .any(|n| host == n || host.ends_with(&format!(".{n}")))
    }

    /// 决策。
    pub fn decide(&self, host: &str) -> Route {
        let h = Self::normalize(host);
        if h.is_empty() {
            return Route::Proxy; // 拿不到域名，保守走代理
        }
        if self.mode == "direct_all" || self.mode == "all_direct" {
            return Route::Direct;
        }
        if self.mode == "proxy_all" || self.mode == "all_proxy" {
            return Route::Proxy;
        }
        // 1. 强制代理
        if Self::match_names(&h, &self.forced_proxy) {
            return Route::Proxy;
        }
        // 2. 直连后缀
        if self.direct_suffixes.iter().any(|suf| h.ends_with(suf)) {
            return Route::Direct;
        }
        // 3. 直连白名单
        if Self::match_names(&h, &self.direct_names) {
            return Route::Direct;
        }
        // 4. 默认走代理（海外）
        Route::Proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> DomainRouter {
        DomainRouter::from_table(&RoutingTable::default())
    }

    #[test]
    fn domestic_direct() {
        let r = router();
        assert_eq!(r.decide("www.baidu.com"), Route::Direct);
        assert_eq!(r.decide("API.taobao.com"), Route::Direct);
        assert_eq!(r.decide("example.com.cn"), Route::Direct);
        assert_eq!(r.decide("test.中国"), Route::Direct);
    }

    #[test]
    fn foreign_proxy() {
        let r = router();
        assert_eq!(r.decide("github.com"), Route::Proxy);
        assert_eq!(r.decide("www.google.com"), Route::Proxy);
        assert_eq!(r.decide(""), Route::Proxy);
    }

    #[test]
    fn forced_proxy_wins() {
        let table = RoutingTable {
            proxy_domains: vec!["baidu.com".to_string()],
            ..Default::default()
        };
        let r = DomainRouter::from_table(&table);
        assert_eq!(r.decide("www.baidu.com"), Route::Proxy);
    }

    #[test]
    fn host_normalization() {
        assert_eq!(DomainRouter::normalize("[::1]:443"), "::1");
        assert_eq!(DomainRouter::normalize("Example.COM:8080"), "example.com");
        assert_eq!(DomainRouter::normalize("example.com."), "example.com");
    }

    #[test]
    fn custom_suffix_extends() {
        let table = RoutingTable {
            direct_suffixes: vec![".internal".to_string()],
            ..Default::default()
        };
        let r = DomainRouter::from_table(&table);
        assert_eq!(r.decide("svc.internal"), Route::Direct);
    }
}
