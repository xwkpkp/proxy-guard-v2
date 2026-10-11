package validator

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
)

// LocalValidator simulates validation results without any network access.
// Distributions are tuned to resemble a real free-proxy pool: most targets
// die, latencies follow a long tail and anonymity is uneven.
type LocalValidator struct {
	Timeout time.Duration
	Seed    int64

	seq atomic.Int64 // deterministic per-probe seed source
}

// NewLocal returns a LocalValidator bound to the given timeout.
func NewLocal(timeout time.Duration, seed int64) *LocalValidator {
	return &LocalValidator{Timeout: timeout, Seed: seed}
}

// Name implements Validator.
func (v *LocalValidator) Name() string { return "local-sim" }

var localCountries = []string{
	"US", "DE", "GB", "NL", "FR", "JP", "SG", "BR",
	"IN", "RU", "CN", "KR", "CA", "AU", "PL", "VN",
}

var localFailures = []string{
	"connection reset by peer",
	"tls handshake failure",
	"authentication required",
	"malformed response",
	"connection refused",
	"socks handshake failed",
}

// Validate implements Validator.
func (v *LocalValidator) Validate(ctx context.Context, t fetcher.Target) Result {
	rnd := rand.New(rand.NewSource(v.Seed + v.seq.Add(1)*7))
	res := Result{Target: t}

	// Long-tail latency: most probes answer in 60ms..~1s, a few take seconds.
	latency := time.Duration(60+int(rnd.ExpFloat64()*900)) * time.Millisecond
	if latency > 3*time.Second {
		latency = 3 * time.Second
	}
	// ~8% of probes never answer at all: simulate a hard timeout.
	if rnd.Float64() < 0.08 {
		latency = v.Timeout + 250*time.Millisecond
	}
	if latency > v.Timeout {
		res.Error = "probe timed out"
		return res
	}
	select {
	case <-ctx.Done():
		res.Error = "canceled"
		return res
	case <-time.After(latency):
	}
	res.Latency = latency

	// ~28% of reachable targets misbehave (reset, auth wall, garbage).
	if rnd.Float64() < 0.28 {
		res.Error = localFailures[rnd.Intn(len(localFailures))]
		return res
	}

	res.Alive = true
	res.Anonymity = pickAnonymity(rnd)
	res.Country = localCountries[rnd.Intn(len(localCountries))]
	res.ASN = fmt.Sprintf("AS%d", 1000+rnd.Intn(64000))
	res.ExitIP = t.Host // exit IP is the proxy itself in the simulation
	return res
}

// pickAnonymity draws an anonymity level from a realistic distribution.
func pickAnonymity(rnd *rand.Rand) string {
	switch r := rnd.Float64(); {
	case r < 0.25:
		return AnonElite
	case r < 0.60:
		return AnonAnonymous
	case r < 0.75:
		return AnonTransparent
	default:
		return AnonUnknown
	}
}
