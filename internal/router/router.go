// Package router decides which handler serves a request.
//
// 2.x inherited nginx's location-matching rules, which produced at least one
// surprise nobody intended: an ALLOWED_PATHS entry compiled to a regex, and
// regexes outrank plain prefix locations, so ALLOWED_PATHS=login silently sent
// the gate's own login page to the backend. Here precedence is an explicit,
// ordered list that can be unit-tested, and a bypass rule that would shadow a
// gate route is rejected at boot by the config package instead.
package router

import (
	"net/http"
	"strings"

	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/identity"
)

// Authenticator decides whether a request may reach the backend. When it
// returns ok=false it has already written the response — a redirect to the
// login page, an RFC 9728 Bearer challenge, or a 403.
type Authenticator interface {
	Authenticate(w http.ResponseWriter, r *http.Request, oauthProtected bool) (identity.Identity, bool)
}

// Kind is which class of route matched. Exported so precedence can be tested
// directly rather than inferred from end-to-end behaviour.
type Kind int

const (
	KindHealth Kind = iota
	KindLogin
	KindNhlAuth
	KindBroker
	KindBypass
	KindGated
)

func (k Kind) String() string {
	switch k {
	case KindHealth:
		return "health"
	case KindLogin:
		return "login"
	case KindNhlAuth:
		return "nhl-auth"
	case KindBroker:
		return "broker"
	case KindBypass:
		return "bypass"
	default:
		return "gated"
	}
}

// Deps are the handlers the router dispatches to. Auth may be nil when no
// authentication is configured; Broker may be nil when OAUTH_RESOURCE is unset.
type Deps struct {
	Cfg        *config.Config
	Auth       Authenticator
	Login      http.Handler
	NhlAuth    http.Handler
	Broker     http.Handler
	Proxy      http.Handler
	Propagator *identity.Propagator
}

type Router struct {
	Deps
	brokerWellKnown map[string]bool
}

func New(d Deps) *Router {
	return &Router{
		Deps: d,
		brokerWellKnown: map[string]bool{
			"/.well-known/openid-configuration":       true,
			"/.well-known/oauth-authorization-server": true,
			"/.well-known/oauth-protected-resource":   true,
		},
	}
}

// Match reports which route serves path, in strict precedence order.
func (rt *Router) Match(path string) Kind {
	// 1. The gate's own routes always win. In 2.x a bypass regex could
	//    outrank these; config rejects such a rule now, and this ordering
	//    makes the guarantee structural rather than incidental.
	switch {
	case path == "/health":
		return KindHealth
	case path == "/login" || strings.HasPrefix(path, "/login/"):
		return KindLogin
	case strings.HasPrefix(path, "/nhl-auth/"):
		return KindNhlAuth
	}

	// 2. Broker-owned routes, when enabled.
	if rt.Broker != nil {
		if rt.brokerWellKnown[path] || strings.HasPrefix(path, "/AppShield/") {
			return KindBroker
		}
	}

	// 3. The OAuth-protected resource. nginx expressed this as `^~`, a prefix
	//    match that suppresses regex evaluation, so it deliberately outranks
	//    the bypass rules below — a resource protected by OAuth must not be
	//    reachable through ALLOWED_PATHS.
	if rt.Cfg.OAuthEnabled && rt.Cfg.OAuthProtectedPath != "/" && underPrefix(path, rt.Cfg.OAuthProtectedPath) {
		return KindGated
	}

	// 4. Unauthenticated bypasses.
	if rt.matchesBypass(path) {
		return KindBypass
	}

	return KindGated
}

func (rt *Router) matchesBypass(path string) bool {
	for _, p := range rt.Cfg.AllowedPaths {
		// nginx: ^/(p)(/|$) — the bare path or anything beneath it, but not a
		// prefix extension like /logins.
		if path == "/"+p || strings.HasPrefix(path, "/"+p+"/") {
			return true
		}
	}
	if len(rt.Cfg.AllowedExtensions) > 0 {
		lower := strings.ToLower(path)
		for _, ext := range rt.Cfg.AllowedExtensions {
			if strings.HasSuffix(lower, "."+ext) {
				return true
			}
		}
	}
	if rt.Cfg.AllowHashContentPaths && isHashContentPath(path) {
		return true
	}
	return false
}

// isHashContentPath matches nginx's ^/[a-f0-9]{40} — deliberately unanchored
// at the end, so anything under a 40-hex prefix matches. Used by Stremio-style
// apps where the hash in the path is itself the capability token.
func isHashContentPath(path string) bool {
	if len(path) < 41 || path[0] != '/' {
		return false
	}
	for i := 1; i <= 40; i++ {
		c := path[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func underPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	// A prefix match on "/mcp" should not also match "/mcpx".
	if len(path) == len(prefix) {
		return true
	}
	return strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rt.Cfg.MaxBodyBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, rt.Cfg.MaxBodyBytes)
	}

	switch rt.Match(r.URL.Path) {
	case KindHealth:
		// Literal 200, unauthenticated — matches nginx.conf:80-82. Kept so
		// compose files can finally define a healthcheck against it.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))

	case KindLogin:
		rt.Login.ServeHTTP(w, r)

	case KindNhlAuth:
		rt.NhlAuth.ServeHTTP(w, r)

	case KindBroker:
		rt.Broker.ServeHTTP(w, r)

	case KindBypass:
		// No identity on this route — but still strip every managed header, so
		// an app that trusts them cannot be fed a forged one through the gate.
		identity.Clear(r)
		rt.Proxy.ServeHTTP(w, r)

	default: // KindGated
		if rt.Auth == nil { // AUTH_MODE=none
			identity.Clear(r)
			rt.Proxy.ServeHTTP(w, r)
			return
		}
		oauthProtected := rt.Cfg.OAuthEnabled &&
			strings.HasPrefix(r.URL.Path, rt.Cfg.OAuthProtectedPath)
		id, ok := rt.Auth.Authenticate(w, r, oauthProtected)
		if !ok {
			return // the authenticator has written the response
		}
		rt.Propagator.Apply(r, id)
		rt.Proxy.ServeHTTP(w, r)
	}
}
