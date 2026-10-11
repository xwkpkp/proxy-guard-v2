// Package fetcher collects candidate proxy targets from various sources.
package fetcher

import "context"

// Target is a candidate proxy discovered by a fetcher.
type Target struct {
	Host     string // IPv4 address
	Port     int
	Protocol string // "http", "https", "socks4", "socks5"
	Source   string // identifier of the origin, e.g. "local-sim-2"
}

// Key returns the unique identity of the target, "host:port".
func (t Target) Key() string {
	return t.Host + ":" + itoa(t.Port)
}

// Fetcher is a source of proxy targets.
//
// Implementations push every discovered target into out and return once
// the batch is exhausted. Fetch may be called again later to obtain a
// fresh batch.
type Fetcher interface {
	// Name identifies the fetcher in logs.
	Name() string
	// Fetch pushes targets into out until the batch is done or ctx expires.
	Fetch(ctx context.Context, out chan<- Target) error
}
