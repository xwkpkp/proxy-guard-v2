package pool

import (
	"testing"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/validator"
)

// TestPoolPrunesRemovedEntries verifies the inventory stays bounded.
//
// The pool used to only ever add: evicted proxies were flagged StatusRemoved
// but never deleted, so a long session grew without limit while Snapshot()
// kept cloning and sorting the whole set several times a second.
func TestPoolPrunesRemovedEntries(t *testing.T) {
	const cap = 10
	p := NewPoolWithCap(testScoreConfig(), cap)

	// Fill well past the cap with entries that all fail, so each one reaches
	// StatusRemoved after RemoveAfterConsecutiveFailures consecutive failures.
	for i := 0; i < cap*3; i++ {
		tgt := fetcher.Target{Host: hostForIndex(i), Port: 8000 + i, Protocol: "http"}
		p.Ensure(tgt)

		// Drive it to Removed.
		for f := 0; f < 10; f++ {
			p.ApplyResult(validator.Result{
				Target: tgt,
				Alive:  false,
				Error:  "forced failure",
			})
		}
	}

	if got := len(p.order); got > cap {
		t.Errorf("inventory grew to %d entries, want <= %d", got, cap)
	}

	// The pruned entries must be gone from both the map and the order slice.
	for _, id := range p.order {
		if _, ok := p.items[id]; !ok {
			t.Errorf("order references %s but items has no entry", id)
		}
	}
}

// TestPoolNeverPrunesActiveEntries ensures the cap never drops a proxy that
// is still in rotation, disabled by the operator, or the current one.
func TestPoolNeverPrunesActiveEntries(t *testing.T) {
	const cap = 5
	p := NewPoolWithCap(testScoreConfig(), cap)

	// One healthy (alive) entry.
	alive := fetcher.Target{Host: "203.0.113.9", Port: 9000, Protocol: "http"}
	p.Ensure(alive)
	p.ApplyResult(validator.Result{Target: alive, Alive: true, Latency: 100})

	// Pad with removed entries well past the cap.
	for i := 0; i < cap*4; i++ {
		tgt := fetcher.Target{Host: hostForIndex(1000 + i), Port: 7000 + i, Protocol: "http"}
		p.Ensure(tgt)
		for f := 0; f < 10; f++ {
			p.ApplyResult(validator.Result{Target: tgt, Alive: false, Error: "forced"})
		}
	}

	if _, ok := p.Get(alive.Key()); !ok {
		t.Error("an alive proxy was pruned; the cap must only shed removed entries")
	}
}

// TestPoolCapDisabled keeps NewPool's unlimited behaviour intact for callers
// that do not opt in.
func TestPoolCapDisabled(t *testing.T) {
	p := NewPool(testScoreConfig())
	for i := 0; i < 500; i++ {
		p.Ensure(fetcher.Target{Host: hostForIndex(i), Port: 3000 + i, Protocol: "http"})
	}
	if got := len(p.order); got != 500 {
		t.Errorf("unlimited pool holds %d entries, want 500", got)
	}
}

// hostForIndex builds a deterministic, routable-looking IPv4 literal.
func hostForIndex(i int) string {
	return "198.51." + itoa(i/256%256) + "." + itoa(i%256)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
