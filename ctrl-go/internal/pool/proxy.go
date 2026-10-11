// Package pool maintains the live proxy inventory: scoring, status
// transitions, rotation and the event log surfaced by the TUI.
package pool

import (
	"strconv"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/validator"
)

// SlowThreshold is the latency above which an alive proxy is flagged slow.
const SlowThreshold = 1500 * time.Millisecond

// Status of a proxy inside the pool.
type Status string

// Possible proxy statuses.
const (
	StatusPending  Status = "pending"  // queued or being validated
	StatusAlive    Status = "alive"    // passed the latest check
	StatusDead     Status = "dead"     // failed the latest check, may recover
	StatusRemoved  Status = "removed"  // evicted after repeated failures
	StatusDisabled Status = "disabled" // turned off by the operator
)

// Proxy is a single entry of the pool.
type Proxy struct {
	Host             string
	Port             int
	Protocol         string
	Source           string
	Status           Status
	Score            int
	SuccessCount     int
	FailCount        int
	ConsecutiveFails int
	RequestCount     int
	Latency          time.Duration
	Anonymity        string
	ExitIP           string
	Country          string
	ASN              string
	Current          bool
	AddedAt          time.Time
	LastCheck        time.Time
	LastUsed         time.Time
}

// ID returns the unique proxy identity "host:port".
func (p Proxy) ID() string { return p.Host + ":" + strconv.Itoa(p.Port) }

// SuccessRate returns the share of successful checks in [0,1].
func (p Proxy) SuccessRate() float64 {
	total := p.SuccessCount + p.FailCount
	if total == 0 {
		return 0
	}
	return float64(p.SuccessCount) / float64(total)
}

// LastActivity is the timestamp used to order the log-style list.
func (p Proxy) LastActivity() time.Time {
	if !p.LastCheck.IsZero() {
		return p.LastCheck
	}
	return p.AddedAt
}

// fromTarget seeds a new pending proxy.
func fromTarget(t fetcher.Target, initialScore int, now time.Time) Proxy {
	return Proxy{
		Host:     t.Host,
		Port:     t.Port,
		Protocol: t.Protocol,
		Source:   t.Source,
		Status:   StatusPending,
		Score:    initialScore,
		AddedAt:  now,
	}
}

// apply folds a validation result into the proxy, returning the event kind
// that best describes the transition.
func (p *Proxy) apply(r validator.Result, sc ScoreConfig) EventKind {
	p.Latency = r.Latency
	p.Anonymity = r.Anonymity
	p.ExitIP = r.ExitIP
	p.Country = r.Country
	p.ASN = r.ASN
	p.LastCheck = time.Now()

	if r.Alive {
		p.SuccessCount++
		p.ConsecutiveFails = 0
		p.Status = StatusAlive
		p.addScore(sc.SuccessDelta, sc)
		if p.Latency > SlowThreshold {
			return EventSlow
		}
		return EventPass
	}

	p.FailCount++
	p.ConsecutiveFails++
	p.addScore(sc.FailDelta, sc)
	if p.ConsecutiveFails >= sc.RemoveAfterConsecutiveFailures {
		p.Status = StatusRemoved
		return EventRemoved
	}
	p.Status = StatusDead
	return EventFail
}

// addScore clamps the score into [MinScore, MaxScore].
func (p *Proxy) addScore(delta int, sc ScoreConfig) {
	p.Score += delta
	if p.Score > sc.MaxScore {
		p.Score = sc.MaxScore
	}
	if p.Score < sc.MinScore {
		p.Score = sc.MinScore
	}
}
