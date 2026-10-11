// Package validator checks whether proxy targets are alive and measures
// their latency, anonymity level and exit identity.
package validator

import (
	"context"
	"sync"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
)

// Anonymity levels reported by validators.
const (
	AnonElite       = "elite"
	AnonAnonymous   = "anonymous"
	AnonTransparent = "transparent"
	AnonUnknown     = ""
)

// Result is the outcome of validating a single target.
type Result struct {
	Target    fetcher.Target
	Alive     bool          // connectivity + usefulness check passed
	Latency   time.Duration // round trip of the probe request
	Anonymity string        // elite / anonymous / transparent / "" unknown
	ExitIP    string        // the IP the target presents to the world
	Country   string        // two-letter country code of the exit IP
	ASN       string        // autonomous system of the exit IP, e.g. "AS12345"
	Error     string        // human-readable failure reason when !Alive
}

// Validator probes a single target.
type Validator interface {
	// Name identifies the validator in logs.
	Name() string
	// Validate probes the target and returns the result.
	Validate(ctx context.Context, t fetcher.Target) Result
}

// Engine runs a fixed worker pool that validates targets concurrently.
type Engine struct {
	validator Validator
	workers   int
	wg        sync.WaitGroup
}

// NewEngine creates a validation engine with the given worker count.
func NewEngine(v Validator, workers int) *Engine {
	if workers < 1 {
		workers = 1
	}
	return &Engine{validator: v, workers: workers}
}

// Run consumes targets and emits results until ctx is canceled or the
// targets channel is closed and drained.
func (e *Engine) Run(ctx context.Context, targets <-chan fetcher.Target, results chan<- Result) {
	for i := 0; i < e.workers; i++ {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-targets:
					if !ok {
						return
					}
					res := e.validator.Validate(ctx, t)
					select {
					case results <- res:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
}

// Wait blocks until every worker has stopped.
func (e *Engine) Wait() { e.wg.Wait() }
