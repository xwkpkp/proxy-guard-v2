package fetcher

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"
)

// ErrAllSourcesFailed is returned when every configured endpoint failed.
var ErrAllSourcesFailed = errors.New("all remote proxy sources failed")

// Endpoint couples a public list URL with the protocol that list serves.
type Endpoint struct {
	URL      string
	Protocol string // http, https, socks5 (empty falls back to http)
}

// RemoteFetcher pulls proxy lists from public endpoints over the network.
//
// Enabled after the operator authorizes network testing. A failing source
// is never fatal: the fetcher degrades gracefully and continues with the
// remaining ones, only reporting an error when none delivered anything.
//
// Requests are plain unauthenticated GETs -- no credentials, cookies or
// personal data are sent to the list endpoints.
type RemoteFetcher struct {
	// Endpoints are the proxy-list sources polled in order.
	Endpoints []Endpoint
	// Timeout bounds a single HTTP request (default 20s).
	Timeout time.Duration
	// Client is optional; a conservative client is created on demand.
	Client *http.Client
}

// NewRemote returns a RemoteFetcher for the given endpoints.
func NewRemote(endpoints []Endpoint, timeout time.Duration) *RemoteFetcher {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &RemoteFetcher{Endpoints: endpoints, Timeout: timeout}
}

// Name implements Fetcher.
func (f *RemoteFetcher) Name() string { return "remote" }

// Fetch implements Fetcher: it walks every endpoint and pushes the
// deduplicated targets into out.
func (f *RemoteFetcher) Fetch(ctx context.Context, out chan<- Target) error {
	if len(f.Endpoints) == 0 {
		return fmt.Errorf("%w: no endpoints configured", ErrAllSourcesFailed)
	}
	seen := make(map[string]bool)
	var failures []string
	delivered := 0
	for _, ep := range f.Endpoints {
		n, err := f.fetchEndpoint(ctx, ep, seen, out)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures = append(failures, fmt.Sprintf("%s: %v", ep.URL, err))
			continue
		}
		delivered += n
	}
	if delivered == 0 && len(failures) > 0 {
		return fmt.Errorf("%w (%s)", ErrAllSourcesFailed, strings.Join(failures, "; "))
	}
	return nil
}

func (f *RemoteFetcher) fetchEndpoint(ctx context.Context, ep Endpoint, seen map[string]bool, out chan<- Target) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}

	source := SourceNameFromURL(ep.URL)

	// JSON 源（geonode /api/proxy-list 风格）：响应形如
	// {"data":[{"ip":"...","port":"8080","protocols":["http"]}, ...]}
	if isJSONSource(ep.URL, resp.Header.Get("Content-Type")) {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return 0, err
		}
		return parseGeonodeJSON(ctx, body, ep.Protocol, source, seen, out)
	}

	count := 0
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 512*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		t, ok := ParseProxyLine(scanner.Text(), ep.Protocol, source)
		if !ok || seen[t.Key()] {
			continue
		}
		seen[t.Key()] = true
		select {
		case out <- t:
			count++
		case <-ctx.Done():
			return count, ctx.Err()
		}
	}
	if err := scanner.Err(); err != nil {
		return count, err
	}
	return count, nil
}

// isJSONSource reports whether an endpoint should be parsed as a geonode
// style JSON list rather than "host:port" lines.
func isJSONSource(url, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "json") {
		return true
	}
	low := strings.ToLower(url)
	return strings.Contains(low, "geonode") || strings.Contains(low, "/api/proxy-list")
}

// geonodeList mirrors the subset of the geonode.com /api/proxy-list
// response we consume.
type geonodeList struct {
	Data []struct {
		IP        string   `json:"ip"`
		Port      any      `json:"port"`
		Protocols []string `json:"protocols"`
	} `json:"data"`
}

// parseGeonodeJSON converts a geonode JSON list body into Targets.
func parseGeonodeJSON(ctx context.Context, body []byte, defaultProtocol, source string, seen map[string]bool, out chan<- Target) (int, error) {
	var lst geonodeList
	if err := json.Unmarshal(body, &lst); err != nil {
		return 0, fmt.Errorf("geonode json: %w", err)
	}
	count := 0
	for _, e := range lst.Data {
		ip := strings.TrimSpace(e.IP)
		port := strings.TrimSpace(fmt.Sprint(e.Port))
		if ip == "" || port == "" {
			continue
		}
		proto := defaultProtocol
		if len(e.Protocols) > 0 && e.Protocols[0] != "" {
			proto = e.Protocols[0]
		}
		t, ok := ParseProxyLine(ip+":"+port, proto, source)
		if !ok || seen[t.Key()] {
			continue
		}
		seen[t.Key()] = true
		select {
		case out <- t:
			count++
		case <-ctx.Done():
			return count, ctx.Err()
		}
	}
	return count, nil
}

// client returns the HTTP client used for list downloads.
func (f *RemoteFetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{
		Timeout:   f.Timeout,
		Transport: &http.Transport{DisableKeepAlives: true, IdleConnTimeout: 5 * time.Second},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// ParseProxyLine converts one list line into a Target.
//
// Supported shapes: "host:port", "proto://host:port", and
// "IP:port protocol country ..." lists (extra columns after the first are
// ignored). Commented (#) lines and malformed entries are rejected.
//
// Because list lines are untrusted input that becomes a connection target in
// network mode, ParseProxyLine also refuses anything that could point at the
// local machine or a private network: non-public IP literals, alternative IP
// notations such as "0177.0.0.1", and special-use hostnames such as
// "localhost" or "metadata.google.internal". See isSafeTargetHost.
func ParseProxyLine(line, defaultProtocol, source string) (Target, bool) {
	raw := strings.TrimSpace(line)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return Target{}, false
	}
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	// "IP:port rest..." -> keep the first column only
	if i := strings.IndexAny(raw, " \t"); i > 0 {
		raw = raw[:i]
	}
	protocol := strings.ToLower(strings.TrimSpace(defaultProtocol))
	if protocol == "" {
		protocol = "http"
	}
	hostPort := raw
	if i := strings.Index(raw, "://"); i > 0 {
		switch scheme := strings.ToLower(raw[:i]); scheme {
		case "http", "https", "socks4", "socks5":
			protocol = scheme
		}
		hostPort = raw[i+3:]
	}
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return Target{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return Target{}, false
	}
	if host = strings.TrimSpace(host); host == "" {
		return Target{}, false
	}
	if !isSafeTargetHost(host) {
		return Target{}, false
	}
	return Target{Host: host, Port: port, Protocol: protocol, Source: source}, true
}

// SourceNameFromURL derives a short label for a list URL.
func SourceNameFromURL(rawURL string) string {
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "remote"
	}
	base := u.Host
	path := strings.Trim(u.Path, "/")
	if path != "" {
		if idx := strings.LastIndex(path, "/"); idx >= 0 {
			path = path[idx+1:]
		}
		if path != "" {
			base = base + "/" + path
		}
	}
	return base
}

// isSafeTargetHost decides whether a candidate proxy host may enter the pool.
//
// Proxy lists are untrusted third-party input, and in network mode every
// accepted entry becomes a TCP connection target. The previous check only
// validated literal IP addresses (net.ParseIP returned nil for a hostname and
// the test was skipped), so "localhost:8080" or
// "metadata.google.internal:80" sailed straight through -- letting anyone who
// can influence a list line point the tool at loopback, the LAN or a cloud
// metadata endpoint.
//
// Three classes of input are therefore rejected:
//
//  1. non-canonical IP notation ("0177.0.0.1", "2130706433"): inet_aton-style
//     parsers read these as loopback while net.ParseIP rejects them, so they
//     would slip past an IP-only check;
//  2. hostnames whose literal form is a special-use name (localhost, or any
//     name under a private/special-use TLD such as .internal/.local/.home.arpa);
//  3. IPv4/IPv6 literals that are not globally routable.
func isSafeTargetHost(host string) bool {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if h == "" {
		return false
	}

	// A hex- or octal-looking literal ("0x7f000001", "0177.0.0.1") is an
	// inet_aton address that some resolvers read as loopback while
	// net.ParseIP rejects it. Refuse every numeric form that is not a
	// canonical dotted quad, in any base, before doing anything else.
	if looksNumericAddress(h) && !isDottedQuad(h) {
		return false
	}

	// Canonical IP literals (v4 dotted quad or v6) are judged directly.
	if ip := net.ParseIP(h); ip != nil {
		return isPublicIP(ip)
	}

	// Anything left must be a DNS name. Hold it to a strict shape so shell
	// and URL metacharacters cannot travel into logs or the UI.
	if !isPlausibleHostname(h) {
		return false
	}
	return !isSpecialUseName(h)
}

// looksNumericAddress reports whether s is written as an address in some
// numeric base: digits, dots, or a 0x-prefixed hex blob.
func looksNumericAddress(s string) bool {
	if strings.HasPrefix(s, "0x") {
		return true
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// isDottedQuad reports whether s is exactly four canonical decimal octets.
func isDottedQuad(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		// Reject leading zeros: "0177" and "001" are the octal-notation
		// trick, not canonical addresses.
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// isPlausibleHostname validates the shape of a DNS name we are willing to
// resolve. Kept deliberately strict: labels of letters/digits/hyphens,
// separated by dots, no empty labels, no trailing dot ambiguity.
func isPlausibleHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
			case c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// specialUseNames are hostnames that always denote the local machine or a
// local network namespace.
var specialUseNames = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"ip6-localhost":         true,
	"ip6-loopback":          true,
}

// specialUseSuffixes are TLDs reserved for local or internal naming. A name
// under any of them can only resolve inside a local/private zone, never on
// the public internet, so it is never a legitimate public proxy.
var specialUseSuffixes = []string{
	".internal",  // GCP/AWS/Azure metadata: metadata.google.internal, ...
	".local",     // mDNS
	".localhost", // RFC 6761
	".home.arpa", // RFC 8375
	".lan",
	".intranet",
	".private",
	".corp",
	".home",
}

// isSpecialUseName reports whether a hostname is reserved for local or
// internal use.
func isSpecialUseName(host string) bool {
	if specialUseNames[host] {
		return true
	}
	for _, suffix := range specialUseSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// isPublicIP rejects loopback, private, link-local, CGNAT, multicast,
// documentation and other non-globally-routable ranges.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Normalise 4-in-6 forms (::ffff:127.0.0.1) so the v4 checks below apply.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// Cloud metadata lives at 169.254.169.254; covered by IsLinkLocalUnicast,
	// but be explicit because the impact of getting this wrong is high.
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return false
	}
	// Carrier-grade NAT (RFC 6598) 100.64.0.0/10 -- not globally routable.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return false
		}
		// Shared address space 100.64/10 handled above; documentation and
		// reserved blocks are not valid public proxy exits either.
		switch {
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24 IETF protocol assignments
			return false
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19): // 198.18.0.0/15 benchmarking
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2: // TEST-NET-1
			return false
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100: // TEST-NET-2
			return false
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // TEST-NET-3
			return false
		case v4[0] >= 240: // 240.0.0.0/4 reserved
			return false
		}
	} else if ip.To16() != nil {
		// Unique local addresses fc00::/7.
		if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
			return false
		}
	}
	return true
}
