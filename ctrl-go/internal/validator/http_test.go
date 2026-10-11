package validator

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
)

// The unit suite stays offline on purpose: endpoint connectivity is
// verified separately through the --smoke run with --offline=false.

const httpbinSample = `{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.13.0"
  },
  "origin": "112.46.214.47",
  "url": "https://httpbin.org/get"
}`

func TestParseEchoResponse(t *testing.T) {
	echo, ok := ParseEchoResponse([]byte(httpbinSample))
	if !ok {
		t.Fatal("expected the httpbin payload to parse")
	}
	if echo.Origin != "112.46.214.47" {
		t.Fatalf("origin = %q", echo.Origin)
	}
	if len(echo.Headers) != 3 { // Accept, Host, User-Agent
		t.Fatalf("expected 3 headers, got %d", len(echo.Headers))
	}
	if echo.Headers["Host"] != "httpbin.org" {
		t.Fatalf("headers not flattened: %+v", echo.Headers)
	}
	if _, ok := ParseEchoResponse([]byte("not-json")); ok {
		t.Fatal("expected malformed payload to be rejected")
	}
}

func TestParseEchoResponseIPField(t *testing.T) {
	echo, ok := ParseEchoResponse([]byte(`{"ip":"8.8.8.8"}`))
	if !ok || echo.Origin != "8.8.8.8" {
		t.Fatalf("unexpected parse result: %+v ok=%v", echo, ok)
	}
}

func TestClassifyAnonymity(t *testing.T) {
	const realIP = "203.0.113.9"

	cases := []struct {
		name    string
		headers map[string]string
		realIP  string
		want    string
	}{
		{"no proxy headers -> elite", map[string]string{"Host": "x"}, realIP, AnonElite},
		{"via without leak -> anonymous", map[string]string{"Via": "1.1 proxy"}, realIP, AnonAnonymous},
		{"x-forwarded-for leaking -> transparent",
			map[string]string{"X-Forwarded-For": "203.0.113.9"}, realIP, AnonTransparent},
		{"x-forwarded-for without leak -> anonymous",
			map[string]string{"X-Forwarded-For": "10.0.0.1"}, realIP, AnonAnonymous},
		{"leak detection off stays conservative",
			map[string]string{"Via": "1.1 proxy"}, "", AnonAnonymous},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyAnonymity(c.headers, c.realIP); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractIP(t *testing.T) {
	if got := ExtractIP([]byte("  185.226.204.22  \n")); got != "185.226.204.22" {
		t.Fatalf("plain text extraction failed: %q", got)
	}
	if got := ExtractIP([]byte(`{"origin":"1.2.3.4"}`)); got != "1.2.3.4" {
		t.Fatalf("json extraction failed: %q", got)
	}
	if got := ExtractIP([]byte(`{"origin":"1.2.3.4, 5.6.7.8"}`)); got != "1.2.3.4" {
		t.Fatalf("comma list should collapse to the first address: %q", got)
	}
	if got := ExtractIP([]byte("nothing here")); got != "" {
		t.Fatalf("expected empty result, got %q", got)
	}
}

func TestNewProbeClientProtocols(t *testing.T) {
	cases := []struct {
		protocol string
		wantErr  bool
	}{
		{"http", false},
		{"https", false},
		{"socks5", false},
		{"socks4", true},
		{"quic", true},
	}
	for _, c := range cases {
		t.Run(c.protocol, func(t *testing.T) {
			client, err := newProbeClient(fetcher.Target{Host: "1.2.3.4", Port: 8080, Protocol: c.protocol}, 2*time.Second)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil || client == nil {
				t.Fatalf("unexpected result: client=%v err=%v", client, err)
			}
			transport, ok := client.Transport.(interface{ CloseIdleConnections() })
			if !ok || transport == nil {
				t.Fatal("expected a custom transport")
			}
		})
	}
}

func TestNewProbeClientDisablesKeepAlive(t *testing.T) {
	client, err := newProbeClient(fetcher.Target{Host: "1.2.3.4", Port: 3128, Protocol: "http"}, time.Second)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", client.Transport)
	}
	if !transport.DisableKeepAlives {
		t.Fatal("keep-alive must stay disabled to avoid reusing proxy sockets")
	}
	if transport.Proxy == nil {
		t.Fatal("http targets must tunnel through Transport.Proxy")
	}
}

func TestProbeFailureReasonTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	client, err := newProbeClient(fetcher.Target{Host: "1.2.3.4", Port: 8080, Protocol: "http"}, time.Second)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	reason := ProbeFailureReason(ctx, client, []string{"https://example.invalid/get"})
	if !strings.Contains(reason, "timed out") && !strings.Contains(reason, "canceled") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}
