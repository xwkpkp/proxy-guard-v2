package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOfflinePrecedence locks in the runtime-mode precedence rules:
//
//	explicit --offline flag > config file / PROXY_TUI_OFFLINE > default
//
// The regression this guards against: flag.Bool("offline", true, ...)
// followed by an unconditional `cfg.Runtime.Offline = *flagOffline` made
// "offline: false" in config.yaml impossible to honour.
func TestOfflinePrecedence(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	// 1. config file explicitly says offline: false -> must stay false.
	p1 := write("net.yaml", "runtime:\n  offline: false\n")
	c1, err := Load(p1)
	if err != nil {
		t.Fatalf("load net.yaml: %v", err)
	}
	if c1.Runtime.Offline {
		t.Error("config offline:false was overridden back to true")
	}
	if !c1.OfflineExplicit() {
		t.Error("OfflineExplicit() = false, want true for an explicit key")
	}

	// 2. config file explicitly says offline: true -> stays true.
	p2 := write("off.yaml", "runtime:\n  offline: true\n")
	c2, err := Load(p2)
	if err != nil {
		t.Fatalf("load off.yaml: %v", err)
	}
	if !c2.Runtime.Offline {
		t.Error("config offline:true was not honoured")
	}

	// 3. config file omits the key entirely -> built-in default, and the
	//    value must NOT be reported as explicit (so the CLI may still
	//    override it).
	p3 := write("bare.yaml", "mode: smart\n")
	c3, err := Load(p3)
	if err != nil {
		t.Fatalf("load bare.yaml: %v", err)
	}
	if c3.OfflineExplicit() {
		t.Error("OfflineExplicit() = true for an omitted key, want false")
	}
	if !c3.Runtime.Offline {
		t.Error("omitted key should fall back to the offline-safe default")
	}

	// 4. missing file -> defaults, not explicit.
	c4, err := Load(filepath.Join(dir, "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if c4.OfflineExplicit() {
		t.Error("OfflineExplicit() = true for a missing file, want false")
	}
}

// TestEnvOverrideMarksExplicit verifies PROXY_TUI_OFFLINE is honoured and is
// treated as an explicit choice.
func TestEnvOverrideMarksExplicit(t *testing.T) {
	t.Setenv("PROXY_TUI_OFFLINE", "0")
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("runtime:\n  offline: true\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Runtime.Offline {
		t.Error("PROXY_TUI_OFFLINE=0 did not override offline:true")
	}
	if !c.OfflineExplicit() {
		t.Error("env override should count as explicit")
	}
}

// TestSetOffline covers the setter used by the CLI path.
func TestSetOffline(t *testing.T) {
	c := Default()
	if c.OfflineExplicit() {
		t.Error("Default() must not report an explicit offline setting")
	}
	c.SetOffline(false)
	if c.Runtime.Offline {
		t.Error("SetOffline(false) did not take effect")
	}
	if !c.OfflineExplicit() {
		t.Error("SetOffline must mark the value explicit")
	}
}

// TestSelfIPProbeURLDefaultsToEmpty is a privacy regression test.
//
// Default() used to ship SelfIPProbeURL: "https://icanhazip.com", which made
// the tool issue a direct request revealing the operator's own public IP
// whenever the config file was absent or lacked a validator section --
// contradicting both config.yaml and the README ("leak detection is opt-in").
func TestSelfIPProbeURLDefaultsToEmpty(t *testing.T) {
	if got := Default().Validator.SelfIPProbeURL; got != "" {
		t.Errorf("Default().Validator.SelfIPProbeURL = %q, want empty (leak detection must be opt-in)", got)
	}

	dir := t.TempDir()
	c, err := Load(filepath.Join(dir, "missing.yaml"))
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if got := c.Validator.SelfIPProbeURL; got != "" {
		t.Errorf("Load(missing).SelfIPProbeURL = %q, want empty", got)
	}

	// A YAML file without a validator section must not resurrect it either.
	p := filepath.Join(dir, "bare.yaml")
	if err := os.WriteFile(p, []byte("mode: smart\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	c2, err := Load(p)
	if err != nil {
		t.Fatalf("load bare: %v", err)
	}
	if got := c2.Validator.SelfIPProbeURL; got != "" {
		t.Errorf("Load(bare).SelfIPProbeURL = %q, want empty", got)
	}
}

// TestConcurrencyBounds verifies the worker pool cannot be configured into
// hammering public endpoints: the default is lowered and a hard ceiling is
// enforced by Validate.
func TestConcurrencyBounds(t *testing.T) {
	if got := Default().Validator.Concurrency; got > 20 {
		t.Errorf("Default().Validator.Concurrency = %d, want <= 20 (public endpoints are the default target)", got)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "hot.yaml")
	// Network mode so Validate's endpoint checks pass, plus a huge worker pool.
	body := "runtime:\n  offline: false\n" +
		"fetcher:\n  remote_sources:\n    - url: https://example.invalid/list.txt\n      protocol: http\n" +
		"validator:\n  concurrency: 5000\n  probe_urls:\n    - https://example.invalid/get\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(p); err == nil {
		t.Error("concurrency: 5000 was accepted, want rejection above the ceiling")
	}
}

// TestPoolCapacityDefaults pins the proxy-inventory ceiling that keeps a
// long-running session from growing without bound.
func TestPoolCapacityDefaults(t *testing.T) {
	if got := Default().Pool.MaxEntries; got <= 0 {
		t.Errorf("Default().Pool.MaxEntries = %d, want a positive ceiling", got)
	}
	if got := Default().Pool.MaxEntries; got > 20000 {
		t.Errorf("Default().Pool.MaxEntries = %d, want a sane bound (<= 20000)", got)
	}
}
