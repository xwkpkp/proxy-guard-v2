// Package contract 定义跨层契约消息。
//
// 与 proto/control.proto 逐字段对应（JSON 字段名 = proto 字段名，snake_case）。
// 修改契约的顺序：proto/control.proto → docs/contract.md → 本文件 → 三层实现。
package contract

// Version 契约版本标识（写入日志与 /health 响应）。
const Version = "v2.0"

// Rust 数据面控制口的 HTTP 路由。
const (
	PathSnapshot = "/snapshot"
	PathPolicy   = "/policy"
	PathEvents   = "/events"
	PathMetrics  = "/metrics"
	PathHealth   = "/health"
)

// ConfigSnapshot 全量配置快照（Go → Rust，POST /snapshot）。
type ConfigSnapshot struct {
	Version   uint64       `json:"version"`
	IssuedAt  int64        `json:"issued_at"`
	Pool      []string     `json:"pool"`
	Routing   RoutingTable `json:"routing"`
	Policy    Policy       `json:"policy"`
	Blacklist []string     `json:"blacklist"`
}

// SnapshotAck 快照接收应答。
type SnapshotAck struct {
	Accepted       bool   `json:"accepted"`
	CurrentVersion uint64 `json:"current_version"`
	Reason         string `json:"reason"`
}

// RoutingTable 域名路由表（Go 生成，Rust 每请求查表执行）。
type RoutingTable struct {
	Mode           string   `json:"mode"`
	DirectDomains  []string `json:"direct_domains"`
	DirectSuffixes []string `json:"direct_suffixes"`
	ProxyDomains   []string `json:"proxy_domains"`
}

// Policy 数据面策略参数。
//
// 轮换的"决定权/执行权"分离：Go 决定候选集与策略参数（慢循环），
// Rust 本地执行每请求选择与失败即时切换（快路径）。
type Policy struct {
	Rotation            RotationPolicy `json:"rotation"`
	ScanRequest         bool           `json:"scan_request"`
	ScanResponse        bool           `json:"scan_response"`
	BlockOnDetect       bool           `json:"block_on_detect"`
	SwitchOnDetect      bool           `json:"switch_on_detect"`
	MITMEnabled         bool           `json:"mitm_enabled"`
	MaxBodyScan         int64          `json:"max_body_scan"`
	CircuitThreshold    int            `json:"circuit_threshold"`
	CircuitCooldownS    int            `json:"circuit_cooldown_s"`
	MaxConcurrent       int            `json:"max_concurrent"`
	RedlineEnabled      bool           `json:"redline_enabled"`
	SSRFProtect         bool           `json:"ssrf_protect"`
	CSPInject           bool           `json:"csp_inject"`
	DetectInjection     bool           `json:"detect_injection"`
	LLMMaliciousAction  string         `json:"llm_malicious_action"`
	LLMSuspiciousAction string         `json:"llm_suspicious_action"`
}

// RotationPolicy 轮换策略参数。
type RotationPolicy struct {
	Strategy        string `json:"strategy"`          // round_robin | fastest | least_used | random
	SwitchIntervalS int    `json:"switch_interval_s"` // 定时切换
	MaxFailures     int    `json:"max_failures"`      // 连续失败 N 次本地切换
	CooldownS       int    `json:"cooldown_s"`        // 失效出口冷却
}

// PolicyDelta 增量策略（研判回写）。
type PolicyDelta struct {
	BaseVersion     uint64             `json:"base_version"`
	AddBlacklist    []string           `json:"add_blacklist,omitempty"`
	RemoveBlacklist []string           `json:"remove_blacklist,omitempty"`
	RuleWeight      map[string]float64 `json:"rule_weight,omitempty"`
	BlockTargets    []string           `json:"block_targets,omitempty"`
}

// Ack 通用应答。
type Ack struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason"`
}

// ThreatEvent 数据面事件（Rust → Go → Python）。
type ThreatEvent struct {
	TraceID     string    `json:"trace_id"`
	TS          int64     `json:"ts"`
	Kind        string    `json:"kind"`
	Ctx         string    `json:"ctx"`
	Target      string    `json:"target"`
	Hits        []RuleHit `json:"hits"`
	Sample      string    `json:"sample"`
	ProxyUsed   string    `json:"proxy_used"`
	ActionTaken string    `json:"action_taken"`
}

// RuleHit 单条规则命中。
type RuleHit struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Snippet  string `json:"snippet"`
}

// MetricBatch 指标批次（Rust → Go）。
type MetricBatch struct {
	TS            int64            `json:"ts"`
	RequestsTotal uint64           `json:"requests_total"`
	BlockedTotal  uint64           `json:"blocked_total"`
	SwitchedTotal uint64           `json:"switched_total"`
	PoolActive    int              `json:"pool_active"`
	PoolTotal     int              `json:"pool_total"`
	AvgUpstreamMS float64          `json:"avg_upstream_ms"`
	Extras        map[string]int64 `json:"extras"`
}

// VerdictUpdate 研判回写（Python → Go）。
type VerdictUpdate struct {
	TraceID    string  `json:"trace_id"`
	Verdict    string  `json:"verdict"`
	AttackType string  `json:"attack_type"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
	TS         int64   `json:"ts"`
	Model      string  `json:"model"`
	Target     string  `json:"target"` // host 或 host+path；malicious 时 Go 据此封锁
}

// WatchRequest 事件订阅参数。
type WatchRequest struct {
	MaxInflight int `json:"max_inflight"`
}

// 事件类型常量。
const (
	KindDetect  = "detect"
	KindSwitch  = "switch"
	KindCircuit = "circuit"
	KindVerdict = "verdict"
)

// 动作常量。
const (
	ActionBlocked  = "blocked"
	ActionWarned   = "warned"
	ActionSwitched = "switched"
	ActionLogged   = "logged"
	ActionPassed   = "passed"
)

// 研判结论常量。
const (
	VerdictMalicious  = "malicious"
	VerdictSuspicious = "suspicious"
	VerdictBenign     = "benign"
)
