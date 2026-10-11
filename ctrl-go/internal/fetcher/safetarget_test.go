package fetcher

import (
	"net"
	"testing"
)

// TestParseProxyLineRejectsInternalTargets is the SSRF regression suite.
//
// Proxy lists are untrusted third-party input. In network mode every accepted
// line becomes a TCP connection target, so an entry pointing at loopback, the
// LAN or a cloud metadata endpoint turns the tool into a confused deputy.
//
// The original check was `if ip := net.ParseIP(host); ip != nil && !isPublicIP(ip)`
// which short-circuited on hostnames: ParseIP returns nil, the guard never
// fired, and every domain sailed through.
func TestParseProxyLineRejectsInternalTargets(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		wantOK bool
	}{
		// --- hostnames that must never be accepted ---
		{"loopback name", "localhost:8080", false},
		{"gcp metadata", "metadata.google.internal:80", false},
		{"aws metadata name", "instance-data.internal:80", false},
		{"nip.io loopback", "127.0.0.1.nip.io:8080", true}, // public name; see TestNipIOClassNote
		{"mdns", "printer.local:9100", false},
		{"rfc6761 localhost tld", "box.localhost:8080", false},
		{"home arpa", "gw.home.arpa:80", false},
		{"lan tld", "router.lan:80", false},
		{"intranet tld", "wiki.intranet:80", false},
		{"localhost.localdomain", "localhost.localdomain:8080", false},

		// --- alternative IP notations (inet_aton tricks) ---
		{"octal loopback", "0177.0.0.1:8080", false},
		{"decimal loopback", "2130706433:8080", false},
		{"hex loopback", "0x7f000001:8080", false},
		{"short form", "127.1:8080", false},
		{"octal metadata", "0251.0376.0251.0376:80", false},
		{"leading zero v4", "010.0.0.1:8080", false},

		// --- private / special-use literals ---
		{"rfc1918 10", "10.0.0.1:3128", false},
		{"rfc1918 172", "172.16.0.1:3128", false},
		{"rfc1918 192", "192.168.1.5:8080", false},
		{"loopback literal", "127.0.0.1:8080", false},
		{"unspecified", "0.0.0.0:8080", false},
		{"link-local metadata", "169.254.169.254:80", false},
		{"link-local", "169.254.1.1:80", false},
		{"cgnat", "100.64.0.1:8080", false},
		{"cgnat upper", "100.127.255.254:8080", false},
		{"reserved 240", "240.0.0.1:8080", false},
		{"broadcast", "255.255.255.255:80", false},
		{"multicast", "224.0.0.1:80", false},
		{"benchmark", "198.18.0.1:8080", false},
		{"testnet1", "192.0.2.1:80", false},
		{"testnet3", "203.0.113.1:80", false},
		{"ipv6 loopback", "[::1]:8080", false},
		{"ipv6 ula", "[fc00::1]:8080", false},
		{"ipv6 link-local", "[fe80::1]:8080", false},
		{"ipv4-mapped loopback", "[::ffff:127.0.0.1]:8080", false},

		// --- malformed / injection-ish ---
		{"empty", "   ", false},
		{"no port", "1.2.3.4", false},
		{"bad port", "1.2.3.4:99999", false},
		{"comment line", "# header row", false},
		{"ok after comment strip", "1.2.3.4:80 # note", true},
		{"bad chars", "$(whoami).example.com:80", false},
		{"quote", "\"'evil\"`:80", false},

		// --- legitimate entries must still be accepted ---
		{"public v4", "1.2.3.4:8080", true},
		{"public v4 port 1", "8.8.8.8:53", true},
		{"trailing columns", "5.6.7.8:3128 US anonymous", true},
		{"scheme wins", "socks5://9.9.9.9:1080", true},
		{"default protocol", "11.22.33.44:8888", true},
		{"inline comment", "12.34.56.78:80 # comment", true},
		{"public hostname", "proxy.example.com:8080", true},
		{"public hostname sub", "a.b.c.example.org:3128", true},
		{"public ipv6", "[2001:4860:4860::8888]:8080", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseProxyLine(c.line, "http", "src")
			if ok != c.wantOK {
				t.Fatalf("ParseProxyLine(%q) accepted=%v, want %v (got host=%q port=%d)",
					c.line, ok, c.wantOK, got.Host, got.Port)
			}
			if !ok {
				return
			}
			if got.Source != "src" {
				t.Fatalf("source not propagated: %q", got.Source)
			}
		})
	}
}

// TestIsSafeTargetHostDirect exercises the host classifier on its own.
func TestIsSafeTargetHostDirect(t *testing.T) {
	bad := []string{
		"", " ", "localhost", "LOCALHOST", "metadata.google.internal",
		"0177.0.0.1", "2130706433", "0x7f.1", "169.254.169.254",
		"100.64.0.1", "host..example.com", ".leading.example.com",
		"-bad.example.com", "bad-.example.com", "under_score.example.com",
		"has space.example.com", "semi;colon.example.com",
	}
	for _, h := range bad {
		if isSafeTargetHost(h) {
			t.Errorf("isSafeTargetHost(%q) = true, want false", h)
		}
	}

	good := []string{
		"1.2.3.4", "8.8.8.8", "proxy.example.com", "a.b.example.org",
		"xn--bcher-kva.example", "2001:4860:4860::8888",
	}
	for _, h := range good {
		if !isSafeTargetHost(h) {
			t.Errorf("isSafeTargetHost(%q) = false, want true", h)
		}
	}
}

// TestIsPublicIPNormalisation ensures 4-in-6 mapped addresses are judged by
// their IPv4 form, so ::ffff:127.0.0.1 cannot masquerade as a public address.
func TestIsPublicIPNormalisation(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", false},
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:169.254.169.254", false},
		{"::ffff:100.64.0.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"1.2.3.4", true},
		{"8.8.8.8", true},
		{"::ffff:8.8.8.8", true},
		{"2001:4860:4860::8888", true},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("test bug: cannot parse %q", c.ip)
		}
		got := isPublicIP(ip)
		if got != c.want {
			t.Errorf("isPublicIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
