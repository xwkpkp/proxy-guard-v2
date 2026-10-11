package pool

import (
	"sort"
	"sync"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/validator"
)

// ScoreConfig holds the scoring knobs.
type ScoreConfig struct {
	InitialScore                   int
	SuccessDelta                   int
	FailDelta                      int
	MaxScore                       int
	MinScore                       int
	RemoveAfterConsecutiveFailures int
}

// Filter selects which proxies may serve traffic in the current mode.
type Filter struct {
	MaxLatency     time.Duration // 0 = unlimited
	Anonymity      []string      // nil/empty = any
	MinSuccessRate float64       // 0 = off
	MinChecks      int           // success rate applies after this many checks
}

// Matches reports whether the proxy satisfies the filter.
func (f Filter) Matches(p Proxy) bool {
	if p.Status != StatusAlive {
		return false
	}
	if f.MaxLatency > 0 && p.Latency > f.MaxLatency {
		return false
	}
	if len(f.Anonymity) > 0 && !containsString(f.Anonymity, p.Anonymity) {
		return false
	}
	if f.MinSuccessRate > 0 {
		if p.SuccessCount+p.FailCount < f.MinChecks {
			return false
		}
		if p.SuccessRate() < f.MinSuccessRate {
			return false
		}
	}
	return true
}

// LessPreferred ranks two eligible proxies: higher score first, then lower
// latency as the tie-breaker.
func (f Filter) LessPreferred(a, b Proxy) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.Latency < b.Latency
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Stats is an aggregated view over the pool.
type Stats struct {
	Total      int
	Pending    int
	Alive      int
	Dead       int
	Removed    int
	Disabled   int
	Eligible   int           // alive proxies matching the mode filter
	AvgLatency time.Duration // mean latency of alive proxies
}

// ApplyOutcome reports what happened when a result was folded in.
type ApplyOutcome struct {
	Proxy Proxy
	Kind  EventKind
	Found bool
}

// Pool is the concurrency-safe proxy inventory.
type Pool struct {
	mu         sync.RWMutex
	sc         ScoreConfig
	maxEntries int
	items      map[string]*Proxy
	order      []string // insertion order for stable listings
	current    string
	requests   int // simulated requests since the last rotation
}

// NewPool creates an empty pool with no inventory cap.
func NewPool(sc ScoreConfig) *Pool { return NewPoolWithCap(sc, 0) }

// NewPoolWithCap creates an empty pool. maxEntries caps the inventory;
// evicted entries are pruned once the pool exceeds it, so a session that runs
// for days does not grow without bound. Values <= 0 disable the cap.
func NewPoolWithCap(sc ScoreConfig, maxEntries int) *Pool {
	if maxEntries < 0 {
		maxEntries = 0
	}
	return &Pool{items: make(map[string]*Proxy), sc: sc, maxEntries: maxEntries}
}

// Ensure adds the target as a pending proxy if it is not known yet.
// It reports whether a new entry was created.
func (p *Pool) Ensure(t fetcher.Target) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := t.Key()
	if _, ok := p.items[id]; ok {
		return false
	}
	np := fromTarget(t, p.sc.InitialScore, time.Now())
	p.items[id] = &np
	p.order = append(p.order, id)
	p.pruneLocked()
	return true
}

// pruneLocked drops evicted entries once the inventory exceeds maxEntries.
// Only StatusRemoved proxies are eligible, so nothing still in rotation or
// under operator control disappears. The active proxy is never pruned.
// Callers must hold the write lock.
func (p *Pool) pruneLocked() {
	if p.maxEntries <= 0 || len(p.order) <= p.maxEntries {
		return
	}
	// Evict oldest-first so the pool sheds its stalest entries.
	overflow := len(p.order) - p.maxEntries
	removed := make([]string, 0, overflow)
	kept := make([]string, 0, len(p.order))
	for _, id := range p.order {
		px, ok := p.items[id]
		if !ok {
			continue
		}
		if len(removed) < overflow && px.Status == StatusRemoved && id != p.current {
			delete(p.items, id)
			removed = append(removed, id)
			continue
		}
		kept = append(kept, id)
	}
	p.order = kept
}

// ApplyResult folds a validation result into the matching proxy.
func (p *Pool) ApplyResult(r validator.Result) ApplyOutcome {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := r.Target.Key()
	px, ok := p.items[id]
	if !ok {
		return ApplyOutcome{}
	}
	kind := px.apply(r, p.sc)
	return ApplyOutcome{Proxy: px.clone(), Kind: kind, Found: true}
}

// Get returns a copy of the proxy with the given id.
func (p *Pool) Get(id string) (Proxy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	px, ok := p.items[id]
	if !ok {
		return Proxy{}, false
	}
	return px.clone(), true
}

// MarkPending forces the proxy back into the pending state (retest).
func (p *Pool) MarkPending(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	px, ok := p.items[id]
	if !ok {
		return false
	}
	px.Status = StatusPending
	return true
}

// SetDisabled toggles the operator disable flag; re-enabling queues the
// proxy for re-validation by returning it to pending.
func (p *Pool) SetDisabled(id string, disabled bool) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	px, ok := p.items[id]
	if !ok {
		return Proxy{}, false
	}
	if disabled {
		px.Status = StatusDisabled
		if p.current == id {
			p.clearCurrentLocked()
		}
	} else {
		px.Status = StatusPending
	}
	return px.clone(), true
}

// SetCurrent makes the given proxy the active one.
func (p *Pool) SetCurrent(id string) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	px, ok := p.items[id]
	if !ok {
		return Proxy{}, false
	}
	p.clearCurrentLocked()
	p.current = id
	px.Current = true
	return px.clone(), true
}

// Current returns the id of the active proxy ("" when none).
func (p *Pool) Current() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

func (p *Pool) clearCurrentLocked() {
	if p.current == "" {
		return
	}
	if px, ok := p.items[p.current]; ok {
		px.Current = false
	}
	p.current = ""
}

// CountRequest registers a simulated request and returns the number of
// requests accumulated since the last rotation.
func (p *Pool) CountRequest() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests++
	return p.requests
}

// TouchUsed marks usage metadata on the given proxy.
func (p *Pool) TouchUsed(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if px, ok := p.items[id]; ok {
		px.RequestCount++
		px.LastUsed = time.Now()
	}
}

// Rotate picks the next eligible proxy according to the filter, makes it
// current and resets the request counter. It returns the new current id
// and whether it changed.
func (p *Pool) Rotate(f Filter) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	eligible := p.eligibleLocked(f)
	if len(eligible) == 0 {
		return p.current, false
	}
	idx := 0
	for i, e := range eligible {
		if e.ID() == p.current {
			idx = i
			break
		}
	}
	next := eligible[(idx+1)%len(eligible)]
	changed := next.ID() != p.current
	p.clearCurrentLocked()
	p.current = next.ID()
	p.items[next.ID()].Current = true
	p.requests = 0
	return p.current, changed
}

func (p *Pool) eligibleLocked(f Filter) []Proxy {
	var out []Proxy
	for _, id := range p.order {
		if px, ok := p.items[id]; ok && f.Matches(px.clone()) {
			out = append(out, px.clone())
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return f.LessPreferred(out[i], out[j]) })
	return out
}

// Stats aggregates the current pool state under the given filter.
func (p *Pool) Stats(f Filter) Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var st Stats
	var sum time.Duration
	var alive int
	for _, id := range p.order {
		px, ok := p.items[id]
		if !ok {
			continue
		}
		st.Total++
		switch px.Status {
		case StatusPending:
			st.Pending++
		case StatusAlive:
			st.Alive++
			alive++
			sum += px.Latency
			if f.Matches(px.clone()) {
				st.Eligible++
			}
		case StatusDead:
			st.Dead++
		case StatusRemoved:
			st.Removed++
		case StatusDisabled:
			st.Disabled++
		}
	}
	if alive > 0 {
		st.AvgLatency = sum / time.Duration(alive)
	}
	return st
}

// List returns copies of all proxies ordered by latest activity first,
// mirroring the log-style view of the left pane.
func (p *Pool) List() []Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Proxy, 0, len(p.order))
	for _, id := range p.order {
		if px, ok := p.items[id]; ok {
			out = append(out, px.clone())
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LastActivity().After(out[j].LastActivity())
	})
	return out
}

// RecheckCandidates returns up to batch proxies that are due for a
// re-validation (alive or dead, last checked older than the given age).
func (p *Pool) RecheckCandidates(batch int, older time.Duration) []Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := time.Now()
	var out []Proxy
	for _, id := range p.order {
		px, ok := p.items[id]
		if !ok {
			continue
		}
		if px.Status != StatusAlive && px.Status != StatusDead {
			continue
		}
		if now.Sub(px.LastCheck) < older {
			continue
		}
		out = append(out, px.clone())
		if len(out) >= batch {
			break
		}
	}
	return out
}

func (p *Proxy) clone() Proxy {
	cp := *p
	return cp
}
