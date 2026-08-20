// Package proxy is the data plane that replaces nginx. It reproduces the proxy
// behaviours the 2.x nginx.conf relied on: runtime DNS re-resolution of the
// backend, websocket upgrades, unbuffered streaming for SSE and long-poll, and
// rewriting upstream Location headers that would otherwise leak the internal
// upstream address to the browser.
package proxy

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yundera/appshield/internal/config"
)

// Proxy forwards to a single upstream.
type Proxy struct {
	rp         *httputil.ReverseProxy
	upstream   string // host:port, as configured — never a resolved IP
	listenPort string
	debug      bool
}

// New builds the reverse proxy from config.
func New(cfg *config.Config) *Proxy {
	upstream := net.JoinHostPort(cfg.BackendHost, strconv.Itoa(cfg.BackendPort))
	target := &url.URL{Scheme: "http", Host: upstream}

	p := &Proxy{
		upstream:   upstream,
		listenPort: strconv.Itoa(cfg.ListenPort),
		debug:      cfg.Debug,
	}

	dialer := &net.Dialer{
		Timeout:   cfg.ConnectTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		// Resolve on every dial. 2.x got this from nginx's
		// `resolver 127.0.0.11 valid=10s` combined with a variable in
		// proxy_pass, which forced runtime re-resolution instead of
		// resolving once at startup. A backend container that restarts on a
		// new IP has to be picked up without restarting the gate, so the
		// resolved address must never be cached beyond a connection.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// nginx used ipv6=off; prefer IPv4 and fall back rather than
			// paying Happy Eyeballs delays on a v4-only Docker network.
			if network == "tcp" {
				if c, err := dialer.DialContext(ctx, "tcp4", addr); err == nil {
					return c, nil
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		// Bound how long a pooled connection can outlive a DNS change.
		IdleConnTimeout:       10 * time.Second,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		ResponseHeaderTimeout: cfg.ReadTimeout,
		ExpectContinueTimeout: time.Second,
		// Compression is the backend's business; decompressing and
		// recompressing here would only burn CPU and break byte ranges.
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}

	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = target.Scheme
			r.Out.URL.Host = target.Host
			// Preserve the client's Host: the backend generates links and
			// cookies from it. nginx passed $host, which is lowercased and
			// port-stripped.
			r.Out.Host = hostOnly(r.In.Host)

			fwd := forwardedFor(r.In)
			r.Out.Header.Set("X-Forwarded-For", fwd)
			r.Out.Header.Set("X-Real-IP", clientIP(r.In))
			r.Out.Header.Set("X-Forwarded-Proto", scheme(r.In))
			r.Out.Header.Set("X-Forwarded-Host", hostOnly(r.In.Host))
			r.Out.Header.Set("X-Forwarded-Port", p.listenPort)
		},
		ModifyResponse: p.rewriteLocation,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Matches nginx's 502 when the upstream is unreachable. The error
			// text is logged, never shown: 2.x leaked upstream error strings
			// to the browser in several places.
			log.Printf("[proxy] %s %s -> %s: %v", r.Method, r.URL.Path, p.upstream, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// proxy_buffering off was the 2.x default, chosen for SSE, long-poll and
	// websocket compatibility. FlushInterval -1 flushes each write straight
	// through, which is the same trade.
	if cfg.Buffering {
		rp.FlushInterval = 100 * time.Millisecond
	} else {
		rp.FlushInterval = -1
	}

	p.rp = rp
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.rp.ServeHTTP(w, r)
}

// rewriteLocation turns an upstream redirect that points at the internal
// upstream into a root-relative one, reproducing:
//
//	proxy_redirect http://$backend_upstream/ /;
//	proxy_redirect https://$backend_upstream/ /;
//
// Unlike 2.x this applies on every route, not just `location /`. The bypass
// routes had no proxy_redirect, so they could leak `http://backend:8080/...`
// to the browser; that was an oversight rather than a decision.
func (p *Proxy) rewriteLocation(resp *http.Response) error {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" {
		return nil
	}
	if !strings.EqualFold(u.Host, p.upstream) {
		return nil
	}
	u.Scheme, u.Host = "", ""
	rel := u.String()
	if rel == "" || rel[0] != '/' {
		rel = "/" + rel
	}
	resp.Header.Set("Location", rel)
	if p.debug {
		log.Printf("[proxy] rewrote Location %q -> %q", loc, rel)
	}
	return nil
}

// hostOnly lowercases and strips any port, matching nginx's $host.
func hostOnly(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	// Bracketed IPv6 literal, with or without a port.
	if strings.HasPrefix(h, "[") {
		if i := strings.LastIndex(h, "]"); i > 0 {
			return h[:i+1]
		}
		return h
	}
	// A bare IPv6 address has several colons and no port.
	if strings.Count(h, ":") > 1 {
		return h
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// forwardedFor reproduces nginx's $proxy_add_x_forwarded_for: append this hop's
// client address to whatever the client already sent.
func forwardedFor(r *http.Request) string {
	ip := clientIP(r)
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		return prior + ", " + ip
	}
	return ip
}

// scheme reports the externally visible scheme. The gate always runs behind
// Caddy in a PCS deployment, so an inbound X-Forwarded-Proto is authoritative;
// falling back to the connection is only right for a direct plain-HTTP gate.
func scheme(r *http.Request) string {
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		// Take the first value: a chain of proxies may have appended.
		if i := strings.IndexByte(p, ','); i >= 0 {
			p = p[:i]
		}
		return strings.ToLower(strings.TrimSpace(p))
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// Scheme is exported for handlers that need the same derivation (cookie Secure
// flag, public origin construction).
func Scheme(r *http.Request) string { return scheme(r) }

// HostOnly is exported for the same reason.
func HostOnly(h string) string { return hostOnly(h) }
