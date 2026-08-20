package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/identity"
)

func cfg(t *testing.T, extra map[string]string) *config.Config {
	t.Helper()
	kv := map[string]string{"BACKEND_HOST": "whoami", "BACKEND_PORT": "80", "LISTEN_PORT": "80"}
	for k, v := range extra {
		kv[k] = v
	}
	c, _, err := config.Load(func(k string) string { return kv[k] }, "myapp")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func named(name string, seen *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = name
		w.WriteHeader(http.StatusOK)
	})
}

type allowAll struct{ id identity.Identity }

func (a allowAll) Authenticate(http.ResponseWriter, *http.Request, bool) (identity.Identity, bool) {
	return a.id, true
}

type denyAll struct{ called *bool }

func (d denyAll) Authenticate(w http.ResponseWriter, _ *http.Request, _ bool) (identity.Identity, bool) {
	*d.called = true
	w.WriteHeader(http.StatusFound)
	return identity.Identity{}, false
}

func newRouter(t *testing.T, c *config.Config, d Deps) *Router {
	t.Helper()
	d.Cfg = c
	if d.Propagator == nil {
		d.Propagator = &identity.Propagator{Enabled: true}
	}
	return New(d)
}

func TestGateRoutesOutrankBypassRules(t *testing.T) {
	// ALLOWED_PATHS=login is rejected outright by config, so the only way to
	// reach these routes is the gate's own handlers.
	c := cfg(t, map[string]string{"ALLOWED_PATHS": "api,static"})
	rt := newRouter(t, c, Deps{})

	for path, want := range map[string]Kind{
		"/health":              KindHealth,
		"/login":               KindLogin,
		"/login/":              KindLogin,
		"/nhl-auth/check":      KindNhlAuth,
		"/nhl-auth/oidc/login": KindNhlAuth,
		"/api":                 KindBypass,
		"/api/thing":           KindBypass,
		"/static/app.js":       KindBypass,
		"/":                    KindGated,
		"/anything":            KindGated,
		"/apixyz":              KindGated, // not a prefix extension of /api
		"/healthz":             KindGated, // /health is exact
		"/nhl-authorised":      KindGated,
	} {
		if got := rt.Match(path); got != want {
			t.Errorf("Match(%q) = %s, want %s", path, got, want)
		}
	}
}

func TestBypassPathMatchingSemantics(t *testing.T) {
	c := cfg(t, map[string]string{"ALLOWED_PATHS": "mcp,web/index.html"})
	rt := newRouter(t, c, Deps{})

	bypass := []string{"/mcp", "/mcp/", "/mcp/tools", "/web/index.html", "/web/index.html/x"}
	gated := []string{"/mcpx", "/mcp2", "/web", "/web/index.htm", "/other"}

	for _, p := range bypass {
		if got := rt.Match(p); got != KindBypass {
			t.Errorf("Match(%q) = %s, want bypass", p, got)
		}
	}
	for _, p := range gated {
		if got := rt.Match(p); got != KindGated {
			t.Errorf("Match(%q) = %s, want gated", p, got)
		}
	}
}

func TestExtensionBypassIsCaseInsensitive(t *testing.T) {
	c := cfg(t, map[string]string{"ALLOWED_EXTENSIONS": "js,css,PNG"})
	rt := newRouter(t, c, Deps{})

	for _, p := range []string{"/app.js", "/deep/style.CSS", "/img/logo.png", "/x.PNG"} {
		if got := rt.Match(p); got != KindBypass {
			t.Errorf("Match(%q) = %s, want bypass", p, got)
		}
	}
	for _, p := range []string{"/app.json", "/jsfile", "/a.js.map"} {
		if got := rt.Match(p); got != KindGated {
			t.Errorf("Match(%q) = %s, want gated", p, got)
		}
	}
}

func TestHashContentPaths(t *testing.T) {
	const hash40 = "/0123456789abcdef0123456789abcdef01234567"

	rt := newRouter(t, cfg(t, nil), Deps{})
	if got := rt.Match(hash40); got != KindGated {
		t.Errorf("without ALLOW_HASH_CONTENT_PATHS, Match = %s, want gated", got)
	}

	rt = newRouter(t, cfg(t, map[string]string{"ALLOW_HASH_CONTENT_PATHS": "true"}), Deps{})
	for _, p := range []string{hash40, hash40 + "/stream.mp4"} {
		if got := rt.Match(p); got != KindBypass {
			t.Errorf("Match(%q) = %s, want bypass", p, got)
		}
	}
	for _, p := range []string{
		"/0123456789abcdef0123456789abcdef0123456",  // 39 chars
		"/0123456789ABCDEF0123456789abcdef01234567", // uppercase is not [a-f0-9]
		"/g123456789abcdef0123456789abcdef01234567", // 'g' is not hex
	} {
		if got := rt.Match(p); got != KindGated {
			t.Errorf("Match(%q) = %s, want gated", p, got)
		}
	}
}

// nginx expressed the protected resource as `^~`, which suppresses regex
// evaluation. A resource protected by OAuth must never be reachable through a
// bypass rule.
func TestOAuthProtectedPathOutranksBypass(t *testing.T) {
	c := cfg(t, map[string]string{
		"OAUTH_RESOURCE":         "https://beacon-x.example.com/mcp",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "x.example.com",
		"ALLOWED_PATHS":          "mcp",
	})
	var seen string
	rt := newRouter(t, c, Deps{Broker: named("broker", &seen)})

	for _, p := range []string{"/mcp", "/mcp/tools"} {
		if got := rt.Match(p); got != KindGated {
			t.Errorf("Match(%q) = %s, want gated (OAuth-protected beats the bypass)", p, got)
		}
	}
	// A sibling path that merely shares a prefix is still just a bypass.
	if got := rt.Match("/mcpx"); got != KindGated {
		t.Errorf("Match(/mcpx) = %s, want gated", got)
	}
}

func TestBrokerRoutes(t *testing.T) {
	c := cfg(t, map[string]string{
		"OAUTH_RESOURCE":         "https://beacon-x.example.com/mcp",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "x.example.com",
	})
	var seen string
	rt := newRouter(t, c, Deps{Broker: named("broker", &seen)})

	for _, p := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource",
		"/AppShield/oidc/auth",
		"/AppShield/oauth/clients",
	} {
		if got := rt.Match(p); got != KindBroker {
			t.Errorf("Match(%q) = %s, want broker", p, got)
		}
	}

	// With the broker disabled those paths are ordinary gated traffic and go
	// to the backend, matching 2.x with the placeholder blanked.
	rt = newRouter(t, cfg(t, nil), Deps{})
	for _, p := range []string{"/.well-known/openid-configuration", "/AppShield/oidc/auth"} {
		if got := rt.Match(p); got != KindGated {
			t.Errorf("broker disabled: Match(%q) = %s, want gated", p, got)
		}
	}
}

func TestHealthIsUnauthenticated(t *testing.T) {
	called := false
	rt := newRouter(t, cfg(t, nil), Deps{Auth: denyAll{called: &called}})

	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "OK" {
		t.Errorf("health = %d %q, want 200 OK", rec.Code, rec.Body.String())
	}
	if called {
		t.Error("health must not invoke the authenticator")
	}
}

// The bypass routes are exactly where a spoofing hole would be invisible.
func TestBypassClearsIdentityHeaders(t *testing.T) {
	c := cfg(t, map[string]string{"ALLOWED_PATHS": "api"})
	var got http.Header
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() })
	rt := newRouter(t, c, Deps{Proxy: proxy})

	req := httptest.NewRequest("GET", "/api/thing", nil)
	for _, h := range identity.Managed() {
		req.Header.Set(h, "attacker")
	}
	rt.ServeHTTP(httptest.NewRecorder(), req)

	for _, h := range identity.Managed() {
		if v := got.Get(h); v != "" {
			t.Errorf("bypass route forwarded %s = %q", h, v)
		}
	}
}

// AUTH_MODE=none proxies everything, but must still not let a client forge an
// identity — 2.x got this right and it would be easy to lose.
func TestNoAuthModeStillClearsIdentityHeaders(t *testing.T) {
	var got http.Header
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() })
	rt := newRouter(t, cfg(t, nil), Deps{Proxy: proxy, Auth: nil})

	req := httptest.NewRequest("GET", "/anything", nil)
	req.Header.Set("Remote-User", "admin")
	req.Header.Set("X-AppShield-User", "admin")
	rt.ServeHTTP(httptest.NewRecorder(), req)

	if got.Get("Remote-User") != "" || got.Get("X-AppShield-User") != "" {
		t.Errorf("AUTH_MODE=none forwarded a client-supplied identity: %v", got)
	}
}

func TestGatedRouteAppliesIdentity(t *testing.T) {
	var got http.Header
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() })
	rt := newRouter(t, cfg(t, nil), Deps{
		Proxy: proxy,
		Auth:  allowAll{id: identity.Identity{Method: identity.MethodOIDC, Sub: "s1", User: "alice"}},
	})

	req := httptest.NewRequest("GET", "/private", nil)
	req.Header.Set("Remote-User", "admin") // spoof attempt
	rt.ServeHTTP(httptest.NewRecorder(), req)

	if got.Get("Remote-User") != "alice" {
		t.Errorf("Remote-User = %q, want the gate's answer", got.Get("Remote-User"))
	}
	if got.Get("X-AppShield-Method") != "oidc" {
		t.Errorf("X-AppShield-Method = %q", got.Get("X-AppShield-Method"))
	}
}

func TestDeniedRequestNeverReachesProxy(t *testing.T) {
	proxied := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied = true })
	called := false
	rt := newRouter(t, cfg(t, nil), Deps{Proxy: proxy, Auth: denyAll{called: &called}})

	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/private", nil))

	if !called {
		t.Error("authenticator was not consulted")
	}
	if proxied {
		t.Error("a denied request reached the backend")
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want the authenticator's 302", rec.Code)
	}
}

func TestRoutesDispatchToTheirHandlers(t *testing.T) {
	c := cfg(t, map[string]string{
		"OAUTH_RESOURCE":         "https://beacon-x.example.com/mcp",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "x.example.com",
	})
	var seen string
	rt := newRouter(t, c, Deps{
		Login:   named("login", &seen),
		NhlAuth: named("nhl-auth", &seen),
		Broker:  named("broker", &seen),
		Proxy:   named("proxy", &seen),
		Auth:    allowAll{id: identity.Identity{Method: identity.MethodOIDC, Sub: "s"}},
	})

	for path, want := range map[string]string{
		"/login":                                "login",
		"/nhl-auth/check":                       "nhl-auth",
		"/AppShield/oidc/auth":                  "broker",
		"/.well-known/oauth-protected-resource": "broker",
		"/whatever":                             "proxy",
		"/mcp":                                  "proxy",
	} {
		seen = ""
		rt.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
		if seen != want {
			t.Errorf("%s dispatched to %q, want %q", path, seen, want)
		}
	}
}
