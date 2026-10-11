// Package pgconfig 解析 proxy-guard 的 config.yaml。
//
// 这是 Go 控制面作为"唯一配置源"的读入口：
//   - 兼容原 Python 版配置格式（agent/pool/rotator/routing/shield/llm）
//   - 新增 ctrl 段（Rust 数据面连接、API 监听、AI 层地址）
//
// Rust 数据面与 Python AI 层不读本文件；其策略全部来自 Go 的快照下发。
package pgconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config 是根配置对象。
type Config struct {
	Agent   Agent   `yaml:"agent"`
	Pool    Pool    `yaml:"pool"`
	Rotator Rotator `yaml:"rotator"`
	Routing Routing `yaml:"routing"`
	Shield  Shield  `yaml:"shield"`
	LLM     LLM     `yaml:"llm"`
	Ctrl    Ctrl    `yaml:"ctrl"`
}

// Agent 进程级配置。
type Agent struct {
	Name          string `yaml:"name"`
	ListenHost    string `yaml:"listen_host"`
	ListenPort    int    `yaml:"listen_port"`
	LogLevel      string `yaml:"log_level"`
	StatsInterval int    `yaml:"stats_interval"`
}

// Pool 代理池配置（抓取 + 验证）。
type Pool struct {
	RefreshInterval     int      `yaml:"refresh_interval"` // 秒
	ValidateTimeout     int      `yaml:"validate_timeout"` // 秒
	ValidateConcurrency int      `yaml:"validate_concurrency"`
	MinPoolSize         int      `yaml:"min_pool_size"`
	MaxPoolSize         int      `yaml:"max_pool_size"`
	Sources             []Source `yaml:"sources"`
	JudgeURLs           []string `yaml:"judge_urls"`
}

// Source 一个代理列表源。
type Source struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Format string `yaml:"format"` // plain | geonode
}

// Rotator 轮换策略（Go 侧维护参数，实际执行在 Rust）。
type Rotator struct {
	Strategy       string `yaml:"strategy"`
	SwitchInterval int    `yaml:"switch_interval"` // 秒
	MaxFailures    int    `yaml:"max_failures"`
	Cooldown       int    `yaml:"cooldown"` // 秒
}

// Routing 域名路由。
type Routing struct {
	Mode           string   `yaml:"mode"` // auto | direct_all | proxy_all
	DirectSuffixes []string `yaml:"direct_suffixes"`
	DirectDomains  []string `yaml:"direct_domains"`
	ProxyDomains   []string `yaml:"proxy_domains"`
}

// Shield 数据面防护策略。
type Shield struct {
	Enabled          bool   `yaml:"enabled"`
	ScanRequest      bool   `yaml:"scan_request"`
	ScanResponse     bool   `yaml:"scan_response"`
	BlockOnDetect    bool   `yaml:"block_on_detect"`
	MaxBodyScan      int64  `yaml:"max_body_scan"`
	SwitchOnDetect   bool   `yaml:"switch_on_detect"`
	RulesDir         string `yaml:"rules_dir"`
	MITMEnabled      bool   `yaml:"mitm_enabled"`
	CertStoreDir     string `yaml:"cert_store_dir"`
	SQLISemantic     bool   `yaml:"sqli_semantic"`
	RedlineEnabled   bool   `yaml:"redline_enabled"`
	SSRFProtect      bool   `yaml:"ssrf_protect"`
	CircuitThreshold int    `yaml:"circuit_threshold"`
	CircuitCooldown  int    `yaml:"circuit_cooldown"`
	MaxConcurrent    int    `yaml:"max_concurrent"`
	CSPInject        bool   `yaml:"csp_inject"`
	DetectInjection  bool   `yaml:"detect_injection"`
}

// LLM 研判层配置（Go 只透传给 Python；密钥不出本机）。
type LLM struct {
	Enabled       bool    `yaml:"enabled"`
	BaseURL       string  `yaml:"base_url"`
	APIKey        string  `yaml:"api_key"`
	Model         string  `yaml:"model"`
	Proxy         string  `yaml:"proxy"`
	Timeout       float64 `yaml:"timeout"`
	MaxConcurrent int     `yaml:"max_concurrent"`
	OutputPath    string  `yaml:"output_path"`
	JudgeURL      string  `yaml:"judge_url"` // Python /judge 端点（Python 侧启动后自注册）
}

// Ctrl v2 新增：三层拓扑参数。
type Ctrl struct {
	RustURL           string `yaml:"rust_url"`            // Rust 控制口
	CtrlToken         string `yaml:"ctrl_token"`          // 空 = 不校验（仅限本地开发）
	APIListen         string `yaml:"api_listen"`          // Go 管理 API 监听
	SnapshotIntervalS int    `yaml:"snapshot_interval_s"` // 快照重推周期
	AIURL             string `yaml:"ai_url"`              // Python 研判服务
}

// Load 读取并校验配置。缺失字段填充默认值。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Agent.Name == "" {
		c.Agent.Name = "proxy-guard"
	}
	if c.Agent.ListenHost == "" {
		c.Agent.ListenHost = "127.0.0.1"
	}
	if c.Agent.ListenPort == 0 {
		c.Agent.ListenPort = 8888
	}
	if c.Agent.StatsInterval <= 0 {
		c.Agent.StatsInterval = 30
	}
	if c.Pool.RefreshInterval <= 0 {
		c.Pool.RefreshInterval = 300
	}
	if c.Pool.ValidateTimeout <= 0 {
		c.Pool.ValidateTimeout = 8
	}
	if c.Pool.ValidateConcurrency <= 0 {
		c.Pool.ValidateConcurrency = 60
	}
	if c.Pool.MaxPoolSize <= 0 {
		c.Pool.MaxPoolSize = 200
	}
	if c.Pool.MinPoolSize <= 0 {
		c.Pool.MinPoolSize = 8
	}
	if c.Rotator.Strategy == "" {
		c.Rotator.Strategy = "round_robin"
	}
	if c.Rotator.SwitchInterval <= 0 {
		c.Rotator.SwitchInterval = 60
	}
	if c.Rotator.MaxFailures <= 0 {
		c.Rotator.MaxFailures = 3
	}
	if c.Rotator.Cooldown <= 0 {
		c.Rotator.Cooldown = 30
	}
	if c.Routing.Mode == "" {
		c.Routing.Mode = "auto"
	}
	if len(c.Routing.DirectSuffixes) == 0 {
		c.Routing.DirectSuffixes = []string{".cn"}
	}
	if c.Shield.RulesDir == "" {
		c.Shield.RulesDir = "rules"
	}
	if c.Shield.MaxBodyScan <= 0 {
		c.Shield.MaxBodyScan = 2 * 1024 * 1024
	}
	if c.Shield.CircuitThreshold <= 0 {
		c.Shield.CircuitThreshold = 5
	}
	if c.Shield.CircuitCooldown <= 0 {
		c.Shield.CircuitCooldown = 60
	}
	if c.Shield.MaxConcurrent <= 0 {
		c.Shield.MaxConcurrent = 20
	}
	if c.Ctrl.RustURL == "" {
		c.Ctrl.RustURL = "http://127.0.0.1:8890"
	}
	if c.Ctrl.APIListen == "" {
		c.Ctrl.APIListen = "127.0.0.1:8891"
	}
	if c.Ctrl.SnapshotIntervalS <= 0 {
		c.Ctrl.SnapshotIntervalS = 30
	}
	if c.Ctrl.AIURL == "" {
		c.Ctrl.AIURL = "http://127.0.0.1:8892"
	}
	if c.LLM.OutputPath == "" {
		c.LLM.OutputPath = "llm_judgments.jsonl"
	}
	if c.LLM.Timeout <= 0 {
		c.LLM.Timeout = 30
	}
	if c.LLM.MaxConcurrent <= 0 {
		c.LLM.MaxConcurrent = 2
	}
	if c.LLM.JudgeURL == "" {
		c.LLM.JudgeURL = c.Ctrl.AIURL + "/judge"
	}
}

// Validate 基本校验。
func (c *Config) Validate() error {
	if len(c.Pool.Sources) == 0 {
		return fmt.Errorf("pool.sources 为空：至少配置一个代理源")
	}
	for _, s := range c.Pool.Sources {
		if s.URL == "" {
			return fmt.Errorf("pool.sources 存在空 URL")
		}
	}
	if c.Pool.MinPoolSize > c.Pool.MaxPoolSize {
		return fmt.Errorf("min_pool_size(%d) > max_pool_size(%d)", c.Pool.MinPoolSize, c.Pool.MaxPoolSize)
	}
	switch c.Rotator.Strategy {
	case "round_robin", "fastest", "least_used", "random":
	default:
		return fmt.Errorf("未知 rotator.strategy: %q（可选 round_robin/fastest/least_used/random）", c.Rotator.Strategy)
	}
	switch c.Routing.Mode {
	case "auto", "direct_all", "proxy_all":
	default:
		return fmt.Errorf("未知 routing.mode: %q（可选 auto/direct_all/proxy_all）", c.Routing.Mode)
	}
	return nil
}

// PlainSources 返回可被行解析器消费的 plain 文本源（geonode 在 fetcher 内走 JSON 分支）。
func (c *Config) PlainSources() []Source { return c.Pool.Sources }

// APIKeyPresent 报告 LLM 密钥是否已配置（不泄露值）。
func (c *Config) APIKeyPresent() bool { return c.LLM.APIKey != "" }
