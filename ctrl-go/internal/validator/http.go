package validator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/fetcher"
)

// ErrSOCKS4Unsupported is returned for targets tagged socks4; the SOCKS5
// dialer cannot speak that protocol.
var ErrSOCKS4Unsupported = errors.New("socks4 is not supported by the validator yet")

// maxEchoBody caps how much of an echo response is read.
const maxEchoBody = 256 * 1024

// HTTPValidator performs real probes over the network.
//
// Probe strategy:
//   - a JSON echo endpoint that returns both the origin IP and the request
//     headers is used first (exit IP + anonymity classification + latency),
//   - when every echo endpoint fails, a plain-text IP endpoint is used as a
//     fallback (exit IP + latency, anonymity left unknown),
//   - every target gets a fresh transport with keep-alive disabled, so no
//     TCP connection is ever reused for a different proxy,
//   - SOCKS5 targets use socks5h semantics: the hostname of the probe URL is
//     resolved by the proxy itself, never by our resolver.
//
// No credentials, cookies or personal data are attached to the probes.
type HTTPValidator struct {
	Timeout     time.Duration
	ProbeURLs   []string // JSON echo endpoints returning {"origin":..., "headers":{...}}
	IPProbeURLs []string // plain-text IP echo endpoints (fallback)

	// SelfIPProbeURL optionally enables leak detection: the validator issues
	// one DIRECT request (not through a proxy) to learn our own public IP,
	// then flags any proxy echoing that IP as transparent. It stays disabled
	// by default (empty value) to avoid extra outbound traffic.
	SelfIPProbeURL string

	// selfIPOnce guarantees the direct leak-detection request is issued at
	// most once for the lifetime of the validator, no matter how many
	// concurrent workers ask for it.
	selfIPOnce sync.Once
	selfIP     string
}

// NewHTTP returns a real-network validator bound to the given timeout and
// probe endpoint lists.
func NewHTTP(timeout time.Duration, probeURLs, ipProbeURLs []string, selfIPProbeURL string) *HTTPValidator {
	return &HTTPValidator{
		Timeout:        timeout,
		ProbeURLs:      probeURLs,
		IPProbeURLs:    ipProbeURLs,
		SelfIPProbeURL: selfIPProbeURL,
	}
}

// Name implements Validator.
func (v *HTTPValidator) Name() string { return "http" }

// Validate implements Validator.
func (v *HTTPValidator) Validate(ctx context.Context, t fetcher.Target) Result {
	res := Result{Target: t}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := newProbeClient(t, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	start := time.Now()
	realIP := v.selfIPAddress(ctx)

	// Phase 1: JSON echo endpoints give us the full picture.
	for _, endpoint := range v.ProbeURLs {
		body, err := doGET(ctx, client, endpoint)
		if err != nil {
			continue
		}
		echo, ok := ParseEchoResponse(body)
		if !ok || echo.Origin == "" {
			continue
		}
		res.Alive = true
		res.Latency = time.Since(start)
		res.ExitIP = echo.Origin
		res.Anonymity = classifyAnonymity(echo.Headers, realIP)
		return res
	}

	// Phase 2: plain-text IP endpoints still prove the proxy works.
	for _, endpoint := range v.IPProbeURLs {
		body, err := doGET(ctx, client, endpoint)
		if err != nil {
			continue
		}
		if ip := ExtractIP(body); ip != "" {
			res.Alive = true
			res.Latency = time.Since(start)
			res.ExitIP = ip
			res.Anonymity = AnonUnknown
			return res
		}
	}

	res.Latency = time.Since(start)
	res.Error = ProbeFailureReason(ctx, client, v.ProbeURLs)
	return res
}

// echoResponse models the JSON payload returned by echo endpoints.
type echoResponse struct {
	Origin  string
	Headers map[string]string
}

// ParseEchoResponse extracts origin and headers from an echo payload.
// It tolerates unknown field names and non-string header values.
func ParseEchoResponse(body []byte) (echoResponse, bool) {
	var raw struct {
		Origin  string         `json:"origin"`
		IP      string         `json:"ip"`
		Headers map[string]any `json:"headers"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return echoResponse{}, false
	}
	origin := firstNonEmpty(cleanIPPart(raw.Origin), cleanIPPart(raw.IP))
	if origin == "" {
		return echoResponse{}, false
	}
	headers := make(map[string]string, len(raw.Headers))
	for k, val := range raw.Headers {
		headers[k] = stringifyHeader(val)
	}
	return echoResponse{Origin: origin, Headers: headers}, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// cleanIPPart keeps a single address when a service reports a comma
// separated list (X-Forwarded-For style).
func cleanIPPart(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func stringifyHeader(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, fmt.Sprint(item))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprint(val)
	}
}

// proxyHeaders is the set of headers that reveal an intermediate proxy.
var proxyHeaders = map[string]bool{
	"via":                  true,
	"forwarded":            true,
	"proxy-connection":     true,
	"proxy-authorization":  true,
	"x-forwarded":          true,
	"x-forwarded-for":      true,
	"x-forwarded-host":     true,
	"x-forwarded-proto":    true,
	"x-forwarded-server":   true,
	"x-forwarded-ip":       true,
	"x-real-ip":            true,
	"x-proxy-id":           true,
	"x-proxy-protocol":     true,
	"client-ip":            true,
	"http_via":             true,
	"http_forwarded":       true,
	"http_x_forwarded_for": true,
}

// classifyAnonymity grades a proxy from the headers seen downstream:
//
//   - elite: no proxy headers were added,
//   - transparent: proxy headers leak our own address,
//   - anonymous: proxy headers exist but do not leak our address. When leak
//     detection is disabled (realIP empty) we stay conservative and never
//     announce elite.
func classifyAnonymity(headers map[string]string, realIP string) string {
	seenProxyHeader := false
	leaks := false
	for name, value := range headers {
		if !proxyHeaders[strings.ToLower(strings.TrimSpace(name))] {
			continue
		}
		seenProxyHeader = true
		if realIP != "" && strings.Contains(value, realIP) {
			leaks = true
		}
	}
	switch {
	case seenProxyHeader && leaks:
		return AnonTransparent
	case seenProxyHeader:
		return AnonAnonymous
	default:
		return AnonElite
	}
}

// ipPattern matches an IPv4 address inside free-form text bodies.
var ipPattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

// ExtractIP pulls an IPv4 address out of a plain-text echo response.
func ExtractIP(body []byte) string {
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err == nil {
		for _, key := range []string{"ip", "origin", "query"} {
			if val, ok := envelope[key].(string); ok {
				candidate := cleanIPPart(val)
				if net.ParseIP(candidate) != nil {
					return candidate
				}
			}
		}
	}
	if ip := ipPattern.FindString(string(body)); ip != "" {
		if parsed := net.ParseIP(ip); parsed != nil {
			return ip
		}
	}
	return ""
}

// newProbeClient builds a dedicated, keep-alive-free client tunnelled
// through a single proxy target.
//
// The target host is re-validated here, at the moment we are about to connect,
// rather than relying only on the fetcher's parse-time screening. That closes
// the DNS-rebinding gap: a public name such as 127.0.0.1.nip.io is syntactically
// fine but resolves to loopback, and only a resolution performed here can tell.
//
// When the host is a name we resolve it once, drop the result if every address
// is non-public, and pin the connection to the vetted IP so a second, hostile
// DNS answer cannot swap the target underneath us.
func newProbeClient(t fetcher.Target, timeout time.Duration) (*http.Client, error) {
	base := &net.Dialer{Timeout: timeout, KeepAlive: -1}

	// SOCKS5 hands the *proxy* address to our own dialer, so it must be
	// vetted too. HTTP proxies likewise. Resolution is bounded by timeout so
	// a slow hostile resolver cannot stall a worker.
	resolveCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dialer, err := newPinnedDialer(resolveCtx, base, t.Host)
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(dialer.pinnedHost, strconv.Itoa(t.Port))
	transport := &http.Transport{
		DisableKeepAlives:     true,
		IdleConnTimeout:       1 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 0,
		MaxIdleConns:          0,
		ForceAttemptHTTP2:     false,
	}

	switch strings.ToLower(strings.TrimSpace(t.Protocol)) {
	case "http", "https", "":
		transport.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: addr})
		transport.DialContext = dialer.dial
	case "socks5":
		socksDialer, err := proxy.SOCKS5("tcp", addr, nil, base)
		if err != nil {
			return nil, err
		}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			// hostname is handed to the proxy verbatim (socks5h behaviour)
			if contextDialer, ok := socksDialer.(proxy.ContextDialer); ok {
				return contextDialer.DialContext(ctx, network, address)
			}
			return socksDialer.Dial(network, address)
		}
	case "socks4":
		return nil, ErrSOCKS4Unsupported
	default:
		return nil, fmt.Errorf("unsupported protocol %q", t.Protocol)
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// pinnedDialer resolves a target host once and returns a dialer pinned to a
// publicly routable address.
type pinnedDialer struct {
	dialer     *net.Dialer
	pinnedHost string // IP literal, or the original name when resolution failed
}

func newPinnedDialer(ctx context.Context, base *net.Dialer, host string) (*pinnedDialer, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		// Literal address: already screened by the fetcher, but re-check the
		// ranges here so the validator is safe on its own.
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("target %s is not a public address", host)
		}
		return &pinnedDialer{dialer: base, pinnedHost: host}, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		// Resolution failure is not a security decision; let the dialer
		// produce the real error (timeout, NXDOMAIN, ...).
		return &pinnedDialer{dialer: base, pinnedHost: host}, nil
	}
	if len(ips) == 0 {
		return &pinnedDialer{dialer: base, pinnedHost: host}, nil
	}
	public := make([]net.IP, 0, len(ips))
	for _, cand := range ips {
		if isPublicIP(cand) {
			public = append(public, cand)
		}
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("target %s resolves only to non-public addresses (DNS rebinding / split-horizon name)", host)
	}
	// Pin the first vetted address: the connection must go to an address we
	// inspected, not to whatever a second DNS answer would return.
	return &pinnedDialer{dialer: base, pinnedHost: public[0].String()}, nil
}

// dial connects to the pinned address, preserving port and network.
func (v *pinnedDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return v.dialer.DialContext(ctx, network, net.JoinHostPort(v.pinnedHost, port))
}

// isPublicIP mirrors the fetcher's screening so the validator is safe when
// used on its own.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return false
		}
		switch {
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0:
			return false
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19):
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2:
			return false
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100:
			return false
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
			return false
		case v4[0] >= 240:
			return false
		}
	} else if ip.To16() != nil {
		if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
			return false
		}
	}
	return true
}

// doGET performs one probe request and returns a bounded response body.
func doGET(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEchoBody))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// ProbeFailureReason produces a compact failure description for the log.
func ProbeFailureReason(ctx context.Context, client *http.Client, endpoints []string) string {
	if len(endpoints) == 0 {
		return "no probe endpoints configured"
	}
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "probe timed out"
		}
		return "probe canceled"
	}
	if _, err := doGET(ctx, client, endpoints[0]); err != nil {
		return trimError(err.Error())
	}
	return "unexpected empty probe response"
}

func trimError(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	return s[:max] + "~"
}

// selfIPAddress learns our own public IP with one direct request. It is only
// performed when leak detection is enabled, and the result is cached.
//
// sync.Once replaces the previous unlock-then-fetch pattern, which had a
// window between the cache check and the assignment: with the default pool of
// 200 workers every validator passed that check before any of them had stored
// a value, so a single startup produced one direct request per worker.
func (v *HTTPValidator) selfIPAddress(ctx context.Context) string {
	if v.SelfIPProbeURL == "" {
		return "" // leak detection disabled by default
	}
	v.selfIPOnce.Do(func() {
		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true},
		}
		if ctx.Err() == nil {
			if body, err := doGET(ctx, client, v.SelfIPProbeURL); err == nil {
				v.selfIP = ExtractIP(body)
			}
		}
	})
	return v.selfIP
}
