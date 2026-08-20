package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yundera/appshield/internal/config"
)

func TestHostOnly(t *testing.T) {
	tests := map[string]string{
		"Example.COM":          "example.com",
		"example.com:8080":     "example.com",
		"example.com":          "example.com",
		"":                     "",
		"[::1]:8080":           "[::1]",
		"[2001:db8::1]":        "[2001:db8::1]",
		"2001:db8::1":          "2001:db8::1",
		"127.0.0.1:80":         "127.0.0.1",
		"beacon-example.com:9": "beacon-example.com",
	}
	for in, want := range tests {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestForwardedForAppends(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	if got := forwardedFor(r); got != "10.0.0.5" {
		t.Errorf("forwardedFor = %q, want %q", got, "10.0.0.5")
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got, want := forwardedFor(r), "203.0.113.9, 10.0.0.5"; got != want {
		t.Errorf("forwardedFor = %q, want %q", got, want)
	}
}

func TestSchemeDerivation(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if got := scheme(r); got != "http" {
		t.Errorf("scheme = %q, want http", got)
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := scheme(r); got != "https" {
		t.Errorf("scheme = %q, want https", got)
	}
	// A chain of proxies may append; the first value is the client-facing one.
	r.Header.Set("X-Forwarded-Proto", "https, http")
	if got := scheme(r); got != "https" {
		t.Errorf("scheme = %q, want https", got)
	}
}

// newTestProxy points a Proxy at an httptest backend.
func newTestProxy(t *testing.T, backend *httptest.Server, extra map[string]string) *Proxy {
	t.Helper()
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	kv := map[string]string{
		"BACKEND_HOST": u.Hostname(),
		"BACKEND_PORT": u.Port(),
		"LISTEN_PORT":  "80",
	}
	for k, v := range extra {
		kv[k] = v
	}
	cfg, _, err := config.Load(func(k string) string { return kv[k] }, "myapp")
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg)
}

func TestProxyForwardsStandardHeaders(t *testing.T) {
	var got http.Header
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		gotHost = r.Host
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	gate := httptest.NewServer(newTestProxy(t, backend, nil))
	defer gate.Close()

	req, _ := http.NewRequest("GET", gate.URL+"/some/path", nil)
	req.Host = "Beacon-Example.com:443"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if gotHost != "beacon-example.com" {
		t.Errorf("backend saw Host %q, want the client's host lowercased and port-stripped", gotHost)
	}
	for k, want := range map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "beacon-example.com",
		"X-Forwarded-Port":  "80",
	} {
		if v := got.Get(k); v != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}
	if got.Get("X-Real-IP") == "" || got.Get("X-Forwarded-For") == "" {
		t.Errorf("X-Real-IP / X-Forwarded-For not set: %v", got)
	}
}

func TestLocationRewrittenWhenPointingAtUpstream(t *testing.T) {
	var backendAddr string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal":
			// Backend leaks its own internal address.
			w.Header().Set("Location", "http://"+backendAddr+"/after?x=1")
		case "/external":
			w.Header().Set("Location", "https://elsewhere.example.com/keep")
		case "/relative":
			w.Header().Set("Location", "/already-relative")
		}
		w.WriteHeader(http.StatusFound)
	}))
	defer backend.Close()
	backendAddr = strings.TrimPrefix(backend.URL, "http://")

	gate := httptest.NewServer(newTestProxy(t, backend, nil))
	defer gate.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for path, want := range map[string]string{
		"/internal": "/after?x=1",
		"/external": "https://elsewhere.example.com/keep",
		"/relative": "/already-relative",
	} {
		resp, err := client.Get(gate.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("%s: Location = %q, want %q", path, got, want)
		}
	}
}

// With buffering off (the default) each backend write must reach the client
// immediately, or SSE and long-poll break.
func TestStreamingIsUnbuffered(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release // hold the response open
		fmt.Fprint(w, "data: second\n\n")
	}))
	defer backend.Close()

	gate := httptest.NewServer(newTestProxy(t, backend, nil))
	defer gate.Close()

	resp, err := http.Get(gate.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	type read struct {
		line string
		err  error
	}
	ch := make(chan read, 1)
	go func() {
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		ch <- read{line, err}
	}()

	select {
	case got := <-ch:
		close(release)
		if got.err != nil {
			t.Fatalf("read: %v", got.err)
		}
		if !strings.Contains(got.line, "first") {
			t.Errorf("got %q, want the first event", got.line)
		}
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("first event never arrived — the response is being buffered")
	}
}

// The gate sits in front of terminals, media players and MCP servers; a broken
// upgrade path breaks all of them.
func TestWebSocketUpgradeIsProxied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			t.Errorf("backend did not see the Upgrade header: %v", r.Header)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		line, _ := buf.ReadString('\n')
		buf.WriteString("echo:" + line)
		buf.Flush()
	}))
	defer backend.Close()

	gate := httptest.NewServer(newTestProxy(t, backend, nil))
	defer gate.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(gate.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: example.com\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading status: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status = %q, want 101 Switching Protocols", status)
	}
	for { // drain headers
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	fmt.Fprint(conn, "ping\n")
	echo, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if strings.TrimSpace(echo) != "echo:ping" {
		t.Errorf("echo = %q, want %q", strings.TrimSpace(echo), "echo:ping")
	}
}

func TestUnreachableBackendReturns502WithoutLeakingDetail(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := backend.URL
	backend.Close() // nothing is listening now

	u, _ := url.Parse(addr)
	kv := map[string]string{
		"BACKEND_HOST": u.Hostname(), "BACKEND_PORT": u.Port(), "LISTEN_PORT": "80",
		"PROXY_CONNECT_TIMEOUT": "1s",
	}
	cfg, _, err := config.Load(func(k string) string { return kv[k] }, "myapp")
	if err != nil {
		t.Fatal(err)
	}
	gate := httptest.NewServer(New(cfg))
	defer gate.Close()

	resp, err := http.Get(gate.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	if body := string(buf[:n]); strings.Contains(body, "connect") || strings.Contains(body, "dial") {
		t.Errorf("body leaks upstream error detail: %q", body)
	}
}
