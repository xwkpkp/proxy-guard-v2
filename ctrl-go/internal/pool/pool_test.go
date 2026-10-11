package pool

import (
	"testing"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/validator"
)

func testScoreConfig() ScoreConfig {
	return ScoreConfig{
		InitialScore:                   50,
		SuccessDelta:                   5,
		FailDelta:                      -10,
		MaxScore:                       100,
		MinScore:                       0,
		RemoveAfterConsecutiveFailures: 3,
	}
}

func TestApplyResultScoringAndEviction(t *testing.T) {
	p := NewPool(testScoreConfig())
	tgt := fetcher.Target{Host: "1.2.3.4", Port: 8080, Protocol: "http", Source: "test"}
	if !p.Ensure(tgt) {
		t.Fatal("expected target to be added")
	}
	if p.Ensure(tgt) {
		t.Fatal("duplicate target should not be added twice")
	}

	// success: +5
	out := p.ApplyResult(validator.Result{Target: tgt, Alive: true, Latency: 300 * time.Millisecond, Anonymity: "elite", Country: "US"})
	if !out.Found || out.Kind != EventPass {
		t.Fatalf("expected pass event, got %+v", out)
	}
	got, _ := p.Get(tgt.Key())
	if got.Score != 55 || got.Status != StatusAlive || got.SuccessCount != 1 {
		t.Fatalf("unexpected proxy state: %+v", got)
	}

	// three consecutive failures: -10 each, then eviction
	for i := 0; i < 3; i++ {
		out = p.ApplyResult(validator.Result{Target: tgt, Alive: false, Error: "timeout"})
	}
	got, _ = p.Get(tgt.Key())
	if out.Kind != EventRemoved {
		t.Fatalf("expected removed event, got %s", out.Kind)
	}
	if got.Status != StatusRemoved || got.ConsecutiveFails != 3 || got.Score != 25 {
		t.Fatalf("unexpected proxy state: %+v", got)
	}
}

func TestScoreClamping(t *testing.T) {
	p := NewPool(testScoreConfig())
	tgt := fetcher.Target{Host: "9.9.9.9", Port: 80, Protocol: "http"}
	p.Ensure(tgt)
	// keep succeeding: score must clamp at 100
	for i := 0; i < 20; i++ {
		p.ApplyResult(validator.Result{Target: tgt, Alive: true, Latency: 10 * time.Millisecond})
	}
	got, _ := p.Get(tgt.Key())
	if got.Score != 100 {
		t.Fatalf("expected score clamped at 100, got %d", got.Score)
	}
}

func TestRotateRespectsFilter(t *testing.T) {
	p := NewPool(testScoreConfig())
	elite := fetcher.Target{Host: "1.1.1.1", Port: 80, Protocol: "http"}
	transparent := fetcher.Target{Host: "2.2.2.2", Port: 80, Protocol: "http"}
	p.Ensure(elite)
	p.Ensure(transparent)
	p.ApplyResult(validator.Result{Target: elite, Alive: true, Latency: 100 * time.Millisecond, Anonymity: "elite"})
	p.ApplyResult(validator.Result{Target: transparent, Alive: true, Latency: 100 * time.Millisecond, Anonymity: "transparent"})

	filter := Filter{Anonymity: []string{"elite"}}
	next, changed := p.Rotate(filter)
	if !changed || next != elite.Key() {
		t.Fatalf("expected rotation to the elite proxy, got %q", next)
	}
	// rotating again must stay inside the filter
	next, _ = p.Rotate(filter)
	if next != elite.Key() {
		t.Fatalf("rotation leaked outside the filter: %q", next)
	}
}

func TestRotateLatencyCeiling(t *testing.T) {
	p := NewPool(testScoreConfig())
	fast := fetcher.Target{Host: "3.3.3.3", Port: 80, Protocol: "http"}
	slow := fetcher.Target{Host: "4.4.4.4", Port: 80, Protocol: "http"}
	p.Ensure(fast)
	p.Ensure(slow)
	p.ApplyResult(validator.Result{Target: fast, Alive: true, Latency: 200 * time.Millisecond})
	p.ApplyResult(validator.Result{Target: slow, Alive: true, Latency: 2 * time.Second})

	filter := Filter{MaxLatency: time.Second}
	next, changed := p.Rotate(filter)
	if !changed || next != fast.Key() {
		t.Fatalf("expected the fast proxy, got %q", next)
	}
}

func TestStableFilterMinChecks(t *testing.T) {
	p := NewPool(testScoreConfig())
	tgt := fetcher.Target{Host: "5.5.5.5", Port: 80, Protocol: "http"}
	p.Ensure(tgt)
	p.ApplyResult(validator.Result{Target: tgt, Alive: true, Latency: 100 * time.Millisecond})

	filter := Filter{MinSuccessRate: 0.9, MinChecks: 5}
	st := p.Stats(filter)
	if st.Eligible != 0 {
		t.Fatalf("min checks not respected: %d eligible", st.Eligible)
	}
}

func TestEventLogRing(t *testing.T) {
	l := NewEventLog(5)
	for i := 0; i < 10; i++ {
		l.Append(EventInfo, "", "x", "y")
	}
	if got := len(l.Tail(100)); got != 5 {
		t.Fatalf("expected ring to keep 5 events, got %d", got)
	}
	since := l.Since(8)
	if len(since) != 2 {
		t.Fatalf("expected 2 events after id 8, got %d", len(since))
	}
	if l.LastID() != 10 {
		t.Fatalf("expected last id 10, got %d", l.LastID())
	}
}

func TestDisabledProxyExcludedFromRotation(t *testing.T) {
	p := NewPool(testScoreConfig())
	tgt := fetcher.Target{Host: "6.6.6.6", Port: 80, Protocol: "http"}
	p.Ensure(tgt)
	p.ApplyResult(validator.Result{Target: tgt, Alive: true, Latency: 100 * time.Millisecond})
	p.SetCurrent(tgt.Key())
	if _, ok := p.SetDisabled(tgt.Key(), true); !ok {
		t.Fatal("disable failed")
	}
	if cur := p.Current(); cur != "" {
		t.Fatalf("expected current cleared after disable, got %q", cur)
	}
	if _, _, changed := rotateOrNone(p, Filter{}); changed {
		t.Fatal("no eligible proxy should be selected when the only one is disabled")
	}
}

func rotateOrNone(p *Pool, f Filter) (string, bool, bool) {
	next, changed := p.Rotate(f)
	return next, changed, next != ""
}
