package fetcher

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync/atomic"
)

// LocalFetcher generates synthetic proxy targets so the whole pipeline can
// run without touching the network. It is the default source while the
// project is in offline development mode.
type LocalFetcher struct {
	BatchSize int   // targets produced per Fetch call
	Sources   int   // number of simulated upstream lists
	Seed      int64 // base seed; runs are reproducible for a fixed seed

	round atomic.Int64 // bumped on every Fetch to vary the output
}

// NewLocal returns a LocalFetcher with the given parameters.
func NewLocal(batchSize, sources int, seed int64) *LocalFetcher {
	if batchSize < 1 {
		batchSize = 1
	}
	if sources < 1 {
		sources = 1
	}
	return &LocalFetcher{
		BatchSize: batchSize,
		Sources:   sources,
		Seed:      seed,
	}
}

// Name implements Fetcher.
func (f *LocalFetcher) Name() string { return "local-sim" }

// common ports and protocols seen in real free-proxy lists.
var localPorts = []int{80, 443, 1080, 3128, 8000, 8080, 8118, 8888, 9050, 53281}

var localProtocols = []string{
	"http", "http", "http",
	"https", "https",
	"socks5", "socks5",
	"socks4",
}

// Fetch implements Fetcher. Each call produces a fresh deterministic batch
// (the seed advances per round) so periodic re-fetches yield new targets,
// mimicking the short lifetime of free proxies.
func (f *LocalFetcher) Fetch(ctx context.Context, out chan<- Target) error {
	round := f.round.Add(1)
	rnd := rand.New(rand.NewSource(f.Seed + round*1_000_003))
	perSource := f.BatchSize / f.Sources
	seen := make(map[string]bool, f.BatchSize)

	for s := 0; s < f.Sources; s++ {
		name := fmt.Sprintf("%s-%d", f.Name(), s+1)
		for count := 0; count < perSource; {
			t := Target{
				Host:     randomPublicIPv4(rnd),
				Port:     localPorts[rnd.Intn(len(localPorts))],
				Protocol: localProtocols[rnd.Intn(len(localProtocols))],
				Source:   name,
			}
			key := t.Key()
			if seen[key] {
				continue
			}
			seen[key] = true
			select {
			case out <- t:
				count++
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

// randomPublicIPv4 returns a random address outside private and reserved
// ranges, formatted as dotted quad.
func randomPublicIPv4(rnd *rand.Rand) string {
	for attempt := 0; attempt < 64; attempt++ {
		a := 1 + rnd.Intn(223)
		b := rnd.Intn(256)
		c := rnd.Intn(256)
		d := 1 + rnd.Intn(254)
		switch {
		case a == 10, a == 127, a == 169, a == 0, a >= 224:
			continue
		case a == 172 && b >= 16 && b <= 31:
			continue
		case a == 192 && b == 168:
			continue
		}
		return strconv.Itoa(a) + "." + strconv.Itoa(b) + "." + strconv.Itoa(c) + "." + strconv.Itoa(d)
	}
	// TEST-NET-3 fallback; practically unreachable.
	return "203.0.113.1"
}

func itoa(n int) string { return strconv.Itoa(n) }
