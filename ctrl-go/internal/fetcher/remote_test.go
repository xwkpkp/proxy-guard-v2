package fetcher

import (
	"context"
	"errors"
	"testing"
)

func TestParseProxyLine(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		proto    string
		wantHost string
		wantPort int
		wantProt string
		wantOK   bool
	}{
		{"plain", "1.2.3.4:8080", "http", "1.2.3.4", 8080, "http", true},
		{"trailing columns", "5.6.7.8:3128 US anonymous", "http", "5.6.7.8", 3128, "http", true},
		{"scheme wins", "socks5://9.9.9.9:1080", "http", "9.9.9.9", 1080, "socks5", true},
		{"default protocol", "11.22.33.44:8888", "", "11.22.33.44", 8888, "http", true},
		{"inline comment", "12.34.56.78:80 # comment", "http", "12.34.56.78", 80, "http", true},
		{"comment line", "# header row", "http", "", 0, "", false},
		{"private rejected", "127.0.0.1:8080", "http", "", 0, "", false},
		{"lan rejected", "192.168.1.5:8080", "http", "", 0, "", false},
		{"loopback rejected", "10.0.0.1:3128", "http", "", 0, "", false},
		{"bad port", "1.2.3.4:99999", "http", "", 0, "", false},
		{"no port", "1.2.3.4", "http", "", 0, "", false},
		{"empty", "   ", "http", "", 0, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseProxyLine(c.line, c.proto, "src")
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (%+v)", ok, c.wantOK, got)
			}
			if !ok {
				return
			}
			if got.Host != c.wantHost || got.Port != c.wantPort || got.Protocol != c.wantProt {
				t.Fatalf("got %+v, want host=%s port=%d proto=%s", got, c.wantHost, c.wantPort, c.wantProt)
			}
			if got.Source != "src" {
				t.Fatalf("source not propagated: %q", got.Source)
			}
		})
	}
}

func TestSourceNameFromURL(t *testing.T) {
	got := SourceNameFromURL("https://cdn.jsdelivr.net/gh/user/repo@master/http.txt")
	if got != "cdn.jsdelivr.net/http.txt" {
		t.Fatalf("unexpected source label: %q", got)
	}
}

// TestRemoteFetcherWithoutEndpoints covers the degraded path without
// touching the network. Real endpoint probing happens through the
// --smoke run with --offline=false, not from the unit suite.
func TestRemoteFetcherWithoutEndpoints(t *testing.T) {
	f := NewRemote(nil, 0)
	err := f.Fetch(context.Background(), make(chan Target, 1))
	if !errors.Is(err, ErrAllSourcesFailed) {
		t.Fatalf("expected ErrAllSourcesFailed, got %v", err)
	}
}
