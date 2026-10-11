// Package config defines the runtime configuration for proxy-tui and
// provides loading from YAML files with environment variable overrides.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode is the identifier of a proxy selection strategy.
type Mode string

// Supported startup modes.
const (
	ModeSmart      Mode = "smart"
	ModeLowLatency Mode = "low-latency"
	ModeHighAnon   Mode = "high-anon"
	ModeStable     Mode = "stable"
	ModeQuick      Mode = "quick"
	ModeCustom     Mode = "custom"
)

// Modes lists all modes in startup-menu order.
var Modes = []Mode{
	ModeSmart,
	ModeLowLatency,
	ModeHighAnon,
	ModeStable,
	ModeQuick,
	ModeCustom,
}

// ModeMeta carries presentation metadata for a mode.
type ModeMeta struct {
	Title  string // short title shown in the menu
	Filter string // one-line description of the filtering strategy
	When   string // recommended use case
}

var modeCatalog = map[Mode]ModeMeta{
	ModeSmart: {
		Title:  "Smart (recommended)",
		Filter: "balanced score + automatic rotation",
		When:   "general crawling and daily use",
	},
	ModeLowLatency: {
		Title:  "Low latency",
		Filter: "keep only proxies with latency < 1s",
		When:   "real-time requests and interactive tasks",
	},
	ModeHighAnon: {
		Title:  "High anonymity",
		Filter: "keep only Elite / Anonymous proxies",
		When:   "sensitive scenarios, avoid leaking the real IP",
	},
	ModeStable: {
		Title:  "Stable",
		Filter: "success rate > 90% and zero consecutive failures",
		When:   "long-running jobs",
	},
	ModeQuick: {
		Title:  "Quick start",
		Filter: "validate only the first 100 proxies",
		When:   "get into the TUI fast",
	},
	ModeCustom: {
		Title:  "Custom",
		Filter: "load filters from config.yaml",
		When:   "advanced users",
	},
}

// Meta returns the presentation metadata for the mode.
func (m Mode) Meta() ModeMeta { return modeCatalog[m] }

// String implements fmt.Stringer.
func (m Mode) String() string { return string(m) }

// ParseMode converts a CLI string into a Mode.
func ParseMode(s string) (Mode, error) {
	m := Mode(strings.ToLower(strings.TrimSpace(s)))
	for _, known := range Modes {
		if known == m {
			return m, nil
		}
	}
	return "", fmt.Errorf("unknown mode %q (valid: smart, low-latency, high-anon, stable, quick, custom)", s)
}

// Duration wraps time.Duration so YAML files can use "5s" style values.
type Duration struct{ time.Duration }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		v, perr := time.ParseDuration(s)
		if perr != nil {
			return fmt.Errorf("invalid duration %q: %w", s, perr)
		}
		d.Duration = v
		return nil
	}
	var n int64
	if err := value.Decode(&n); err != nil {
		return err
	}
	d.Duration = time.Duration(n)
	return nil
}

// Config is the root configuration object.
type Config struct {
	Mode      Mode      `yaml:"mode"`
	Runtime   Runtime   `yaml:"runtime"`
	Fetcher   Fetcher   `yaml:"fetcher"`
	Validator Validator `yaml:"validator"`
	Pool      Pool      `yaml:"pool"`
	TUI       TUI       `yaml:"tui"`
	Filter    Filter    `yaml:"filter"`

	// offlineFromFile records whether runtime.offline was explicitly
	// present in the YAML file. It lets the CLI decide whether the
	// --offline flag (whose Go default is unavoidably true) should win or
	// defer. Not serialised: it is provenance, not configuration.
	offlineFromFile bool
}

// OfflineExplicit reports whether runtime.offline was explicitly set in the
// config file. Callers use it to resolve the --offline flag precedence
// without clobbering a deliberate "offline: false" setting.
func (c Config) OfflineExplicit() bool { return c.offlineFromFile }

// SetOffline sets the runtime mode and records that the caller made an
// explicit choice (used by the CLI when --offline is passed).
func (c *Config) SetOffline(v bool) {
	c.Runtime.Offline = v
	c.offlineFromFile = true
}

// Runtime controls engine-wide behaviour.
type Runtime struct {
	// Offline runs the whole pipeline on simulated fetchers and
	// validators without touching the network (default true).
	Offline bool `yaml:"offline"`
}

// Fetcher configures proxy source collection.
type Fetcher struct {
	Interval      Duration       `yaml:"interval"`
	BatchSize     int            `yaml:"batch_size"`
	Seed          int64          `yaml:"seed"`
	Sources       int            `yaml:"sources"`
	QuickCap      int            `yaml:"quick_cap"`
	RemoteSources []RemoteSource `yaml:"remote_sources"`
}

// RemoteSource is one public proxy-list endpoint used in network mode.
// Every source is expected to serve one "host:port" per line.
type RemoteSource struct {
	URL      string `yaml:"url"`      // endpoint returning "host:port" lines
	Protocol string `yaml:"protocol"` // http, https or socks5 (defaults to http)
}

// Validator configures the validation worker pool and the probe endpoints
// used in network mode.
type Validator struct {
	Concurrency    int      `yaml:"concurrency"`
	Timeout        Duration `yaml:"timeout"`
	ProbeURLs      []string `yaml:"probe_urls"`        // JSON echo endpoints (origin + headers)
	IPProbeURLs    []string `yaml:"ip_probe_urls"`     // plain-text IP echo fallback
	SelfIPProbeURL string   `yaml:"self_ip_probe_url"` // direct probe that learns our own IP
}

// Pool configures scoring, eviction and rotation.
type Pool struct {
	InitialScore                   int      `yaml:"initial_score"`
	SuccessDelta                   int      `yaml:"success_delta"`
	FailDelta                      int      `yaml:"fail_delta"`
	MaxScore                       int      `yaml:"max_score"`
	MinScore                       int      `yaml:"min_score"`
	RemoveAfterConsecutiveFailures int      `yaml:"remove_after_consecutive_failures"`
	RotationEveryRequests          int      `yaml:"rotation_every_requests"`
	RecheckInterval                Duration `yaml:"recheck_interval"`
	RecheckBatch                   int      `yaml:"recheck_batch"`
	SimulatedRequestInterval       Duration `yaml:"simulated_request_interval"`
	// MaxEntries caps the number of proxies kept in the inventory. Older
	// removed entries are pruned past this bound so a session that runs for
	// days does not grow without limit. 0 disables the cap.
	MaxEntries int `yaml:"max_entries"`
}

// TUI configures interface behaviour.
type TUI struct {
	FPS       int `yaml:"fps"`
	LogBuffer int `yaml:"log_buffer"`
}

// Filter is the custom-mode filter set.
type Filter struct {
	MaxLatencyMs   int      `yaml:"max_latency_ms"`
	Anonymity      []string `yaml:"anonymity"`
	MinSuccessRate float64  `yaml:"min_success_rate"`
	MinChecks      int      `yaml:"min_checks"`
}

// Default returns the built-in configuration used when no file overrides it.
func Default() Config {
	return Config{
		Mode:    ModeSmart,
		Runtime: Runtime{Offline: true},
		Fetcher: Fetcher{
			Interval:  Duration{90 * time.Second},
			BatchSize: 300,
			Seed:      42,
			Sources:   4,
			QuickCap:  100,
			RemoteSources: []RemoteSource{
				{
					URL:      "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/http.txt",
					Protocol: "http",
				},
				{
					URL:      "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
					Protocol: "socks5",
				},
				{
					URL:      "https://cdn.jsdelivr.net/gh/clarketm/proxy-list@master/proxy-list-raw.txt",
					Protocol: "http",
				},
			},
		},
		Validator: Validator{
			// Leak detection is opt-in and MUST stay off unless the operator
			// asks for it: enabling it makes the tool issue a direct request
			// that hands our own public IP to a third party. Leaving this
			// empty was the documented behaviour; an earlier default of
			// "https://icanhazip.com" contradicted config.yaml and the README.
			SelfIPProbeURL: "",
			Concurrency:    10,
			Timeout:        Duration{5 * time.Second},
			ProbeURLs:      []string{"https://httpbin.org/get"},
			IPProbeURLs:    []string{"https://icanhazip.com"},
		},
		Pool: Pool{
			InitialScore:                   50,
			SuccessDelta:                   5,
			FailDelta:                      -10,
			MaxScore:                       100,
			MinScore:                       0,
			RemoveAfterConsecutiveFailures: 3,
			RotationEveryRequests:          5,
			RecheckInterval:                Duration{30 * time.Second},
			RecheckBatch:                   50,
			SimulatedRequestInterval:       Duration{2 * time.Second},
			MaxEntries:                     5000,
		},
		TUI: TUI{FPS: 10, LogBuffer: 1000},
	}
}

// Load reads the YAML file at path (falling back to defaults when it does
// not exist) and applies environment variable overrides.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			applyEnvOverrides(&cfg)
			return cfg, nil
		}
		return cfg, err
	}
	// Decode into a throwaway struct first so we can tell an explicit
	// "offline: false" apart from the field simply being absent. Plain
	// Unmarshal cannot make that distinction: both yield the zero value.
	var presence struct {
		Runtime *struct {
			Offline *bool `yaml:"offline"`
		} `yaml:"runtime"`
	}
	if err := yaml.Unmarshal(data, &presence); err == nil && presence.Runtime != nil && presence.Runtime.Offline != nil {
		cfg.offlineFromFile = true
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	applyEnvOverrides(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// applyEnvOverrides lets PROXY_TUI_MODE and PROXY_TUI_OFFLINE win over files.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PROXY_TUI_MODE"); v != "" {
		if m, err := ParseMode(v); err == nil {
			cfg.Mode = m
		}
	}
	switch strings.ToLower(os.Getenv("PROXY_TUI_OFFLINE")) {
	case "1", "true", "yes":
		cfg.Runtime.Offline = true
		cfg.offlineFromFile = true
	case "0", "false", "no":
		cfg.Runtime.Offline = false
		cfg.offlineFromFile = true
	}
}

// MaxValidatorConcurrency bounds the validation worker pool. The default
// probe targets (httpbin.org, icanhazip.com) are free third-party services,
// so the pool must not be configurable into hammering them.
const MaxValidatorConcurrency = 50

// Validate sanity-checks the configuration values.
func (c Config) Validate() error {
	if c.Fetcher.BatchSize < 1 {
		return errors.New("fetcher.batch_size must be >= 1")
	}
	if c.Fetcher.Sources < 1 {
		return errors.New("fetcher.sources must be >= 1")
	}
	if c.Validator.Concurrency < 1 {
		return errors.New("validator.concurrency must be >= 1")
	}
	if c.Validator.Concurrency > MaxValidatorConcurrency {
		return fmt.Errorf("validator.concurrency must be <= %d (the default probe endpoints are third-party services; raise this only for infrastructure you own)",
			MaxValidatorConcurrency)
	}
	if c.Pool.MaxEntries < 0 {
		return errors.New("pool.max_entries must be >= 0 (0 disables the cap)")
	}
	if c.Validator.Timeout.Duration <= 0 {
		return errors.New("validator.timeout must be positive")
	}
	if c.TUI.FPS < 1 || c.TUI.FPS > 30 {
		return errors.New("tui.fps must be between 1 and 30")
	}
	if c.TUI.LogBuffer < 10 {
		return errors.New("tui.log_buffer must be >= 10")
	}
	if c.Pool.RemoveAfterConsecutiveFailures < 1 {
		return errors.New("pool.remove_after_consecutive_failures must be >= 1")
	}
	if c.Pool.RotationEveryRequests < 1 {
		return errors.New("pool.rotation_every_requests must be >= 1")
	}
	if !c.Runtime.Offline {
		if len(c.Fetcher.RemoteSources) == 0 {
			return errors.New("network mode requires at least one fetcher.remote_sources entry")
		}
		if len(c.Validator.ProbeURLs) == 0 && len(c.Validator.IPProbeURLs) == 0 {
			return errors.New("network mode requires at least one probe endpoint")
		}
	}
	return nil
}

// QuickCapOrDefault returns the quick-mode validation cap (>= 1).
func (c Config) QuickCapOrDefault() int {
	if c.Fetcher.QuickCap < 1 {
		return 100
	}
	return c.Fetcher.QuickCap
}

// itoa is a tiny strconv wrapper used by other packages through helpers.
func itoa(n int) string { return strconv.Itoa(n) }

var _ = itoa // kept for symmetry; referenced by tests
