package validator

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
)

// TestNewProbeClientRefusesInternalLiterals is the dial-time SSRF guard.
//
// Parse-time screening in the fetcher is a first line of defence; the validator
// must be safe on its own because a Target can also be constructed by hand
// (RequestRetest and the recheck loop both rebuild Targets from pool fields).
func TestNewProbeClientRefusesInternalLiterals(t *testing.T) {
	bad := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "fc00::1",
	}
	for _, host := range bad {
		t.Run(host, func(t *testing.T) {
			target := fetcher.Target{Host: host, Port: 8080, Protocol: "http"}
			client, err := newProbeClient(target, 200*time.Millisecond)
			if err == nil {
				t.Fatalf("newProbeClient(%s) succeeded, want refusal", host)
			}
			if client != nil {
				t.Fatal("client must be nil on refusal")
			}
		})
	}
}

// TestNewProbeClientAcceptsPublicLiteral guards against over-blocking.
func TestNewProbeClientAcceptsPublicLiteral(t *testing.T) {
	target := fetcher.Target{Host: "93.184.216.34", Port: 8080, Protocol: "http"}
	if _, err := newProbeClient(target, 200*time.Millisecond); err != nil {
		t.Fatalf("newProbeClient(public literal) = %v, want success", err)
	}
}

// TestIsPublicIPValidatorCopy checks the validator's standalone classifier,
// especially 4-in-6 normalisation.
func TestIsPublicIPValidatorCopy(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", false},
		{"::ffff:127.0.0.1", false},
		{"169.254.169.254", false},
		{"100.100.100.100", false}, // inside 100.64.0.0/10
		{"1.2.3.4", true},
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("test bug: bad IP %q", c.ip)
		}
		if got := isPublicIP(ip); got != c.want {
			t.Errorf("isPublicIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// TestPinnedDialerRejectsLoopbackName covers the DNS-rebinding path: a
// syntactically public name that resolves to loopback must be refused at
// dial time. localhost is used because it needs no external DNS.
//
// Only localhost is resolved: this suite must never touch the network.
func TestPinnedDialerRejectsLoopbackName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	d, err := newPinnedDialer(ctx, &net.Dialer{Timeout: time.Second}, "localhost")
	if err == nil {
		t.Fatalf("newPinnedDialer(localhost) succeeded and pinned %q, want refusal", d.pinnedHost)
	}
}

// TestNewPinnedDialerPinsLiteralAddresses verifies the pinning logic using
// literal addresses only, so the suite performs no DNS at all.
func TestNewPinnedDialerPinsLiteralAddresses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	d, err := newPinnedDialer(ctx, &net.Dialer{Timeout: time.Second}, "93.184.216.34")
	if err != nil {
		t.Fatalf("newPinnedDialer(public literal) = %v, want success", err)
	}
	if d.pinnedHost != "93.184.216.34" {
		t.Errorf("pinnedHost = %q, want the literal unchanged", d.pinnedHost)
	}

	// A 4-in-6 mapped loopback must be rejected, not silently pinned.
	if _, err := newPinnedDialer(ctx, &net.Dialer{Timeout: time.Second}, "::ffff:127.0.0.1"); err == nil {
		t.Error("newPinnedDialer(::ffff:127.0.0.1) succeeded, want refusal")
	}
}
