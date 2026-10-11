package pool

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/config"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/validator"
)

// Engine wires fetchers, the validation worker pool, the proxy inventory
// and the event log into one pipeline, and drives rotation and rechecks.
//
// Concurrency model (skeleton contract):
//
//	fetcher goroutine -> validate queue -> validator worker pool
//	                                          |
//	                                          v
//	                    proxy pool + event log <- collector goroutine
//	                                          |
//	                                          v
//	                              TUI event loop (via Snapshot)
//
// The TUI goroutine only renders and reacts; every network-facing task
// (simulated in offline mode) runs here in the background.
type Engine struct {
	cfg  config.Config
	pool *Pool
	log  *EventLog

	targets chan fetcher.Target
	results chan validator.Result
	ve      *validator.Engine

	mu      sync.Mutex
	filter  Filter
	started time.Time
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool

	fetched   atomic.Int64
	validated atomic.Int64
	passed    atomic.Int64
	failed    atomic.Int64
}

// NewEngine builds an engine from the configuration. In offline mode the
// pipeline runs on simulated fetchers and validators only.
func NewEngine(cfg config.Config) *Engine {
	var vf validator.Validator
	if cfg.Runtime.Offline {
		vf = validator.NewLocal(cfg.Validator.Timeout.Duration, cfg.Fetcher.Seed)
	} else {
		vf = validator.NewHTTP(
			cfg.Validator.Timeout.Duration,
			cfg.Validator.ProbeURLs,
			cfg.Validator.IPProbeURLs,
			cfg.Validator.SelfIPProbeURL,
		)
	}
	return &Engine{
		cfg: cfg,
		pool: NewPoolWithCap(ScoreConfig{
			InitialScore:                   cfg.Pool.InitialScore,
			SuccessDelta:                   cfg.Pool.SuccessDelta,
			FailDelta:                      cfg.Pool.FailDelta,
			MaxScore:                       cfg.Pool.MaxScore,
			MinScore:                       cfg.Pool.MinScore,
			RemoveAfterConsecutiveFailures: cfg.Pool.RemoveAfterConsecutiveFailures,
		}, cfg.Pool.MaxEntries),
		log:     NewEventLog(cfg.TUI.LogBuffer),
		ve:      validator.NewEngine(vf, cfg.Validator.Concurrency),
		filter:  FilterFromMode(cfg),
		started: time.Now(),
	}
}

// FilterFromMode translates the startup mode into pool filter rules.
func FilterFromMode(cfg config.Config) Filter {
	switch cfg.Mode {
	case config.ModeLowLatency:
		return Filter{MaxLatency: time.Second}
	case config.ModeHighAnon:
		return Filter{Anonymity: []string{validator.AnonElite, validator.AnonAnonymous}}
	case config.ModeStable:
		return Filter{MinSuccessRate: 0.9, MinChecks: 5}
	case config.ModeCustom:
		return Filter{
			MaxLatency:     time.Duration(cfg.Filter.MaxLatencyMs) * time.Millisecond,
			Anonymity:      cfg.Filter.Anonymity,
			MinSuccessRate: cfg.Filter.MinSuccessRate,
			MinChecks:      cfg.Filter.MinChecks,
		}
	default: // smart, quick
		return Filter{}
	}
}

// Start launches the background pipeline. Call Stop to shut it down.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	e.ctx = ctx
	e.cancel = cancel
	e.started = time.Now()
	e.running = true
	e.targets = make(chan fetcher.Target, 1024)
	e.results = make(chan validator.Result, 1024)

	e.ve.Run(ctx, e.targets, e.results)

	e.wg.Add(1)
	go e.fetchLoop(ctx)
	e.wg.Add(1)
	go e.collectLoop(ctx)
	e.wg.Add(1)
	go e.recheckLoop(ctx)
	// Rotation is request-paced. Until real outbound requests are integrated
	// into this tool, the simulated driver below keeps the rotation policy
	// observable; wire it to a real request counter afterwards.
	e.wg.Add(1)
	go e.usageLoop(ctx)

	e.log.Append(EventInfo, "", "engine started",
		fmt.Sprintf("mode=%s offline=%t workers=%d", e.cfg.Mode, e.cfg.Runtime.Offline, e.cfg.Validator.Concurrency))
	return nil
}

// Stop cancels the pipeline and waits for the goroutines to finish.
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	cancel := e.cancel
	e.mu.Unlock()

	cancel()
	// Wait for the pipeline to drain but never block the caller forever.
	finished := make(chan struct{})
	go func() {
		e.wg.Wait()
		e.ve.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
	}

	e.mu.Lock()
	e.running = false
	e.mu.Unlock()
}

// fetchLoop fetches an immediate first batch and then on every interval.
func (e *Engine) fetchLoop(ctx context.Context) {
	defer e.wg.Done()
	e.fetchOnce(ctx)
	ticker := time.NewTicker(e.cfg.Fetcher.Interval.Duration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.fetchOnce(ctx)
		}
	}
}

// fetchOnce runs one fetch round, registering new targets and forwarding
// them to the validation queue. Quick mode caps how many targets are
// actually queued.
func (e *Engine) fetchOnce(ctx context.Context) {
	f := e.buildFetcher()
	out := make(chan fetcher.Target, 256)
	done := make(chan struct{})
	go func() {
		defer close(done) // signalled after the batch is fully delivered
		defer close(out)  // required by the "for range out" consumer below
		if err := f.Fetch(ctx, out); err != nil && ctx.Err() == nil {
			e.log.Append(EventInfo, "", "fetch failed", f.Name()+": "+err.Error())
		}
	}()

	cap := e.fetchCap()
	total, added := 0, 0
	for t := range out {
		total++
		if cap > 0 && total > cap {
			continue // consume the rest of the batch without queuing
		}
		if e.pool.Ensure(t) {
			added++
			e.fetched.Add(1)
			e.log.Append(EventAdded, t.Key(), t.Key(), "queued from "+t.Source)
		}
		select {
		case e.targets <- t:
		case <-ctx.Done():
			<-done
			return
		}
	}
	<-done
	e.log.Append(EventSource, "", f.Name()+" batch",
		fmt.Sprintf("%d targets, %d new, queued for validation (cap=%d)", total, added, cap))
}

// buildFetcher returns the fetcher matching the runtime mode: simulated
// lists offline, public endpoints in network mode.
func (e *Engine) buildFetcher() fetcher.Fetcher {
	if e.cfg.Runtime.Offline {
		return fetcher.NewLocal(e.cfg.Fetcher.BatchSize, e.cfg.Fetcher.Sources, e.cfg.Fetcher.Seed)
	}
	endpoints := make([]fetcher.Endpoint, 0, len(e.cfg.Fetcher.RemoteSources))
	for _, src := range e.cfg.Fetcher.RemoteSources {
		if strings.TrimSpace(src.URL) == "" {
			continue
		}
		endpoints = append(endpoints, fetcher.Endpoint{URL: src.URL, Protocol: src.Protocol})
	}
	return fetcher.NewRemote(endpoints, e.cfg.Validator.Timeout.Duration*4)
}

// fetchCap returns the per-batch validation cap (quick mode) or 0.
func (e *Engine) fetchCap() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg.Mode == config.ModeQuick {
		return e.cfg.QuickCapOrDefault()
	}
	return 0
}

// collectLoop folds validation results into the pool and logs transitions.
func (e *Engine) collectLoop(ctx context.Context) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case r, ok := <-e.results:
			if !ok {
				return
			}
			e.handleResult(r)
		}
	}
}

func (e *Engine) handleResult(r validator.Result) {
	e.validated.Add(1)
	out := e.pool.ApplyResult(r)
	if !out.Found {
		return
	}
	switch out.Kind {
	case EventPass:
		e.passed.Add(1)
		e.log.Append(EventPass, out.Proxy.ID(), out.Proxy.ID(), summarizeResult(r))
	case EventSlow:
		e.passed.Add(1)
		e.log.Append(EventSlow, out.Proxy.ID(), out.Proxy.ID(),
			"alive but slow: "+summarizeResult(r))
	case EventFail:
		e.failed.Add(1)
		e.log.Append(EventFail, out.Proxy.ID(), out.Proxy.ID(), "dead: "+failureReason(r))
	case EventRemoved:
		e.failed.Add(1)
		e.log.Append(EventRemoved, out.Proxy.ID(), out.Proxy.ID(),
			fmt.Sprintf("evicted after %d consecutive failures", out.Proxy.ConsecutiveFails))
	}
}

// recheckLoop periodically re-validates proxies with stale results.
func (e *Engine) recheckLoop(ctx context.Context) {
	defer e.wg.Done()
	ticker := time.NewTicker(e.cfg.Pool.RecheckInterval.Duration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.recheck(ctx)
		}
	}
}

func (e *Engine) recheck(ctx context.Context) {
	interval := e.cfg.Pool.RecheckInterval.Duration
	candidates := e.pool.RecheckCandidates(e.cfg.Pool.RecheckBatch, interval*8/10)
	for _, p := range candidates {
		e.pool.MarkPending(p.ID())
		t := fetcher.Target{Host: p.Host, Port: p.Port, Protocol: p.Protocol, Source: "recheck"}
		select {
		case e.targets <- t:
			e.log.Append(EventRetry, p.ID(), p.ID(), "scheduled for re-validation")
		case <-ctx.Done():
			return
		}
	}
}

// usageLoop simulates outbound requests in offline mode so the rotation
// policy (every N requests) is exercised without real traffic.
func (e *Engine) usageLoop(ctx context.Context) {
	defer e.wg.Done()
	if e.cfg.Pool.SimulatedRequestInterval.Duration <= 0 {
		return
	}
	ticker := time.NewTicker(e.cfg.Pool.SimulatedRequestInterval.Duration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.simulateRequest()
		}
	}
}

func (e *Engine) simulateRequest() {
	filter := e.currentFilter()
	cur := e.pool.Current()
	if cur == "" {
		if next, changed := e.pool.Rotate(filter); changed {
			e.log.Append(EventRotated, next, next, "auto rotation picked a new proxy")
		} else if next != "" {
			e.log.Append(EventRotated, next, next, "using first eligible proxy")
		}
		return
	}
	e.pool.TouchUsed(cur)
	n := e.pool.CountRequest()
	if n >= e.cfg.Pool.RotationEveryRequests {
		if next, changed := e.pool.Rotate(filter); changed {
			e.log.Append(EventRotated, next, next,
				fmt.Sprintf("rotated after %d requests", n))
		}
	}
}

func (e *Engine) currentFilter() Filter {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.filter
}

// SetMode switches the active mode filter (called from the startup menu).
func (e *Engine) SetMode(m config.Mode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.Mode = m
	e.filter = FilterFromMode(e.cfg)
}

// RequestRetest re-validates a single proxy from the TUI.
func (e *Engine) RequestRetest(id string) error {
	e.mu.Lock()
	running := e.running
	ctx := e.ctx
	e.mu.Unlock()
	if !running {
		return fmt.Errorf("engine is not running")
	}

	p, ok := e.pool.Get(id)
	if !ok {
		return fmt.Errorf("unknown proxy %s", id)
	}
	if p.Status == StatusRemoved {
		return fmt.Errorf("%s was evicted and cannot be re-tested", id)
	}
	e.pool.MarkPending(id)
	t := fetcher.Target{Host: p.Host, Port: p.Port, Protocol: p.Protocol, Source: "manual"}
	select {
	case e.targets <- t:
	case <-ctx.Done():
		return fmt.Errorf("engine is shutting down")
	}
	e.log.Append(EventRetest, id, id, "manual re-test requested")
	return nil
}

// ToggleDisabled flips the operator disable flag for a proxy.
func (e *Engine) ToggleDisabled(id string) (string, error) {
	p, ok := e.pool.Get(id)
	if !ok {
		return "", fmt.Errorf("unknown proxy %s", id)
	}
	if p.Status == StatusRemoved {
		return "", fmt.Errorf("%s was evicted and cannot be disabled", id)
	}
	nowDisabled := p.Status == StatusDisabled
	if _, ok := e.pool.SetDisabled(id, !nowDisabled); !ok {
		return "", fmt.Errorf("unknown proxy %s", id)
	}
	if !nowDisabled {
		e.log.Append(EventDisabled, id, id, "disabled by operator")
		return "disabled", nil
	}
	e.log.Append(EventEnabled, id, id, "re-enabled by operator, queued for re-validation")
	return "enabled", nil
}

// UseProxy makes the given proxy the current one.
func (e *Engine) UseProxy(id string) error {
	p, ok := e.pool.Get(id)
	if !ok {
		return fmt.Errorf("unknown proxy %s", id)
	}
	if p.Status != StatusAlive {
		return fmt.Errorf("%s is not alive (status: %s)", id, p.Status)
	}
	if _, ok := e.pool.SetCurrent(id); !ok {
		return fmt.Errorf("unknown proxy %s", id)
	}
	e.log.Append(EventInfo, id, id, "set as current proxy")
	return nil
}

// RotateNow triggers a manual rotation and returns the new current id.
func (e *Engine) RotateNow() string {
	next, _ := e.pool.Rotate(e.currentFilter())
	if next != "" {
		e.log.Append(EventRotated, next, next, "manual rotation")
	}
	return next
}

// Pool exposes the inventory (used by tests and smoke runs).
func (e *Engine) Pool() *Pool { return e.pool }

// Log exposes the event log (used by tests and smoke runs).
func (e *Engine) Log() *EventLog { return e.log }

// Counters exposes engine throughput numbers.
type Counters struct {
	Fetched   int64
	Validated int64
	Passed    int64
	Failed    int64
}

// Snapshot is a consistent view of everything the TUI needs to render.
type Snapshot struct {
	Mode        config.Mode
	Uptime      time.Duration
	Started     bool
	Proxies     []Proxy
	Stats       Stats
	Current     string
	Events      []Event // events after the caller's watermark
	LastEventID int64
	Counters    Counters
}

// Snapshot assembles the render state. sinceEvent selects incremental
// events; pass 0 to receive the whole buffer.
func (e *Engine) Snapshot(sinceEvent int64) Snapshot {
	e.mu.Lock()
	started := e.running
	filter := e.filter
	mode := e.cfg.Mode
	uptime := time.Since(e.started)
	e.mu.Unlock()

	return Snapshot{
		Mode:        mode,
		Uptime:      uptime,
		Started:     started,
		Proxies:     e.pool.List(),
		Stats:       e.pool.Stats(filter),
		Current:     e.pool.Current(),
		Events:      e.log.Since(sinceEvent),
		LastEventID: e.log.LastID(),
		Counters: Counters{
			Fetched:   e.fetched.Load(),
			Validated: e.validated.Load(),
			Passed:    e.passed.Load(),
			Failed:    e.failed.Load(),
		},
	}
}

// formatLatency renders a duration in a compact human form.
func formatLatency(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func summarizeResult(r validator.Result) string {
	parts := []string{formatLatency(r.Latency), anonLabel(r.Anonymity)}
	switch {
	case r.Country != "":
		parts = append(parts, r.Country)
	case r.ExitIP != "":
		parts = append(parts, "exit="+r.ExitIP)
	}
	return strings.Join(parts, " ")
}

func anonLabel(a string) string {
	if a == "" {
		return "unknown"
	}
	return a
}

func failureReason(r validator.Result) string {
	if r.Error != "" {
		return r.Error
	}
	return "unknown error"
}
