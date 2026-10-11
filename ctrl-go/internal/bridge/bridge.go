// Package bridge 把 pgconfig（proxy-guard 配置）桥接为池引擎所需的 config.Config。
//
// 映射关系（pgconfig → 池引擎）：
//
//	pool.refresh_interval     → fetcher.interval
//	pool.sources              → fetcher.remote_sources（网络模式）
//	pool.validate_concurrency → validator.concurrency
//	pool.validate_timeout     → validator.timeout（列表下载超时 = 4 倍）
//	pool.judge_urls           → validator.probe_urls / ip_probe_urls
//	pool.max_pool_size        → pool.max_entries + fetcher.batch_size
package bridge

import (
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/config"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/pgconfig"
)

// ToEngineConfig 生成池引擎配置（网络模式；离线模式由 CLI 显式覆盖）。
func ToEngineConfig(p *pgconfig.Config) config.Config {
	cfg := config.Default()
	cfg.Mode = config.ModeSmart
	cfg.Runtime.Offline = false

	cfg.Fetcher.Interval = config.Duration{Duration: time.Duration(p.Pool.RefreshInterval) * time.Second}
	cfg.Fetcher.BatchSize = p.Pool.MaxPoolSize
	cfg.Fetcher.RemoteSources = make([]config.RemoteSource, 0, len(p.Pool.Sources))
	for _, s := range p.Pool.Sources {
		cfg.Fetcher.RemoteSources = append(cfg.Fetcher.RemoteSources, config.RemoteSource{
			URL:      s.URL,
			Protocol: "http",
		})
	}

	cfg.Validator.Concurrency = p.Pool.ValidateConcurrency
	cfg.Validator.Timeout = config.Duration{Duration: time.Duration(p.Pool.ValidateTimeout) * time.Second}
	if len(p.Pool.JudgeURLs) > 0 {
		cfg.Validator.ProbeURLs = append([]string(nil), p.Pool.JudgeURLs...)
		cfg.Validator.IPProbeURLs = append([]string(nil), p.Pool.JudgeURLs...)
	}
	// SelfIPProbeURL 保持关闭（与 proxy-tui 的安全默认一致）：泄漏检测是
	// opt-in，会让本机公网 IP 暴露给第三方，此处不开。

	cfg.Pool.MaxEntries = p.Pool.MaxPoolSize
	return cfg
}
