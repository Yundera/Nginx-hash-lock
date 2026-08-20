// Package authn is the gate decision and the human-facing auth surface.
//
// In 2.x this was an HTTP subrequest: nginx asked 127.0.0.1:9999/nhl-auth/check
// on every request and translated the answer back through auth_request_set.
// Here it is a function call, which removes the round trip, the one-Set-Cookie
// limitation nginx imposed, and the unsupervised second process.
package authn

import (
	"crypto/subtle"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/identity"
	"github.com/yundera/appshield/internal/proxy"
	"github.com/yundera/appshield/internal/session"
	"github.com/yundera/appshield/web"
)

// failedLoginDelay is the only brute-force control the gate has ever had. It
// throttles a serial attacker and nothing else; it is not rate limiting.
const failedLoginDelay = 2 * time.Second

// BearerVerifier verifies an OAuth access token issued by the local broker.
// Nil when OAUTH_RESOURCE is unset.
type BearerVerifier interface {
	VerifyBearer(token string) (sub string, ok bool)
}

// Logouter lets the OIDC relying party end the upstream session as well as the
// local one. Nil unless OIDC is enabled.
type Logouter interface {
	// EndSessionURL returns where to send the browser to end the IdP session,
	// or "" to just render the local signed-out page.
	EndSessionURL(r *http.Request, sess *session.Session) string
}

type Deps struct {
	Cfg      *config.Config
	Sessions *session.Store
	Prop     *identity.Propagator
	Bearer   BearerVerifier
	Logout   Logouter
}

type Gate struct {
	Deps
}

func New(d Deps) *Gate { return &Gate{Deps: d} }

// Authenticate is the hot path: one call per proxied request.
func (g *Gate) Authenticate(w http.ResponseWriter, r *http.Request, oauthProtected bool) (identity.Identity, bool) {
	// 1. Machine access: an OAuth 2.1 access token from the local broker.
	if id, ok := g.bearerIdentity(r); ok {
		return id, true
	}

	// 2. A browser session.
	if id, outcome := g.sessionIdentity(r); outcome != outcomeAnonymous {
		if outcome == outcomeForbidden {
			g.forbidden(w)
			return identity.Identity{}, false
		}
		return id, true
	}

	g.challenge(w, r, oauthProtected)
	return identity.Identity{}, false
}

func (g *Gate) bearerIdentity(r *http.Request) (identity.Identity, bool) {
	if g.Bearer == nil {
		return identity.Identity{}, false
	}
	tok := bearerToken(r)
	// Only JWS-shaped tokens are worth verifying. 2.x used this same test so
	// an opaque bearer and a broker JWT could share the header.
	if tok == "" || strings.Count(tok, ".") != 2 {
		return identity.Identity{}, false
	}
	sub, ok := g.Bearer.VerifyBearer(tok)
	if !ok {
		return identity.Identity{}, false
	}
	return identity.Identity{Method: identity.MethodOAuth, Sub: sub}, true
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

type outcome int

const (
	outcomeAnonymous outcome = iota
	outcomeAllowed
	outcomeForbidden
)

func (g *Gate) sessionIdentity(r *http.Request) (identity.Identity, outcome) {
	c, err := r.Cookie(session.CookieName)
	if err != nil {
		return identity.Identity{}, outcomeAnonymous
	}
	sess, ok := g.Sessions.Get(c.Value)
	if !ok {
		return identity.Identity{}, outcomeAnonymous
	}

	switch {
	case sess.OIDCSub != "" || sess.Claims != nil:
		// A session minted before the gate recorded claims cannot be checked
		// against a group requirement. Delete it so the user re-authenticates,
		// rather than dead-ending them on a 403 they can do nothing about.
		if len(g.Cfg.RequiredGroups) > 0 && sess.Claims == nil {
			g.Sessions.Delete(c.Value)
			return identity.Identity{}, outcomeAnonymous
		}
		id := identity.Identity{Method: identity.MethodOIDC, Sub: sess.OIDCSub}
		if sess.Claims != nil {
			id.Sub = firstNonEmpty(sess.Claims.Sub, sess.OIDCSub)
			id.User, id.Email, id.Name = sess.Claims.User, sess.Claims.Email, sess.Claims.Name
			id.Groups = sess.Claims.Groups
		}
		if !g.groupsAllowed(id) {
			return identity.Identity{}, outcomeForbidden
		}
		return id, outcomeAllowed

	case sess.PasswordHash != "":
		// The password may have changed since the session was minted (the
		// container restarts with a new PASSWORD); such sessions must die.
		if subtle.ConstantTimeCompare([]byte(sess.PasswordHash), []byte(g.Cfg.PasswordHash)) != 1 {
			g.Sessions.Delete(c.Value)
			return identity.Identity{}, outcomeAnonymous
		}
		return identity.Identity{Method: identity.MethodPassword, User: g.Cfg.Username}, outcomeAllowed
	}

	return identity.Identity{}, outcomeAnonymous
}

// groupsAllowed enforces OIDC_REQUIRED_GROUPS. Machine identities are exempt by
// design; an OIDC identity asserting no groups fails closed.
func (g *Gate) groupsAllowed(id identity.Identity) bool {
	if len(g.Cfg.RequiredGroups) == 0 || id.Method != identity.MethodOIDC {
		return true
	}
	for _, want := range g.Cfg.RequiredGroups {
		for _, have := range id.Groups {
			if have == want {
				return true
			}
		}
	}
	return false
}

// challenge tells an unauthenticated caller how to authenticate.
func (g *Gate) challenge(w http.ResponseWriter, r *http.Request, oauthProtected bool) {
	// An OAuth-protected resource gets RFC 9728 discovery rather than a
	// browser redirect: its callers are machines that cannot follow one.
	if oauthProtected && g.Cfg.OAuthEnabled && g.Cfg.CanonicalOrigin != "" {
		w.Header().Set("WWW-Authenticate",
			`Bearer resource_metadata="`+g.Cfg.CanonicalOrigin+`/.well-known/oauth-protected-resource"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch g.Cfg.Mode {
	case config.AuthOIDC:
		redirectTo(w, r, "/nhl-auth/oidc/login")
	case config.AuthCredentials:
		redirectTo(w, r, "/login")
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// redirectTo sends the browser to the login entry point, preserving where it
// was trying to go. RequestURI is used raw, exactly as nginx's $request_uri
// was, but percent-encoded into the query so it survives the round trip.
func redirectTo(w http.ResponseWriter, r *http.Request, base string) {
	target := base + "?redirect=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, target, http.StatusFound)
}

func (g *Gate) forbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(web.ForbiddenHTML)
}

// --- routes --------------------------------------------------------------

// LoginPage serves GET /login.
func (g *Gate) LoginPage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// With OIDC configured there is no local login form; bounce straight
		// into the SSO flow so a stale bookmark still works.
		if g.Cfg.Mode == config.AuthOIDC {
			redirectTo(w, r, "/nhl-auth/oidc/login")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(web.LoginHTML)
	})
}

// RegisterRoutes adds the gate's own /nhl-auth endpoints. The OIDC relying
// party registers its routes on the same mux.
func (g *Gate) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /nhl-auth/login", g.handleLogin)
	mux.HandleFunc("/nhl-auth/logout", g.handleLogout)
	mux.HandleFunc("/nhl-auth/logged-out", g.handleLoggedOut)
	mux.HandleFunc("POST /nhl-auth/sessions/revoke", g.handleRevoke)
}

func (g *Gate) handleLogin(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	user := r.PostFormValue("username")
	pass := r.PostFormValue("password")

	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(g.Cfg.Username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(g.Cfg.Password)) == 1
	if !userOK || !passOK || g.Cfg.Mode != config.AuthCredentials {
		// Constant floor on the response time, so a wrong username and a wrong
		// password are indistinguishable and serial guessing is slow.
		if d := failedLoginDelay - time.Since(started); d > 0 {
			time.Sleep(d)
		}
		log.Printf("[auth] failed login for %q", user)
		http.Redirect(w, r, "/login?error=1&redirect="+
			url.QueryEscape(safeRedirect(r, r.PostFormValue("redirect"))), http.StatusFound)
		return
	}

	sess := &session.Session{
		Expires:      g.Sessions.NewExpiry(g.Cfg.SessionDuration),
		PasswordHash: g.Cfg.PasswordHash,
	}
	id, err := g.Sessions.Create(sess)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, g.cookie(r, id, g.Cfg.SessionDuration))
	log.Printf("[auth] login ok for %q", user)

	// 2.x passed this straight to res.redirect with no validation, which made
	// the login form an open redirect.
	http.Redirect(w, r, safeRedirect(r, r.PostFormValue("redirect")), http.StatusFound)
}

func (g *Gate) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Fetch-metadata CSRF guard. GET is deliberately supported because
	// 403.html links here, so a token cannot be required; this rejects the
	// cross-site sub-resource shapes a browser can be tricked into.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" && dest != "document" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	var sess *session.Session
	if c, err := r.Cookie(session.CookieName); err == nil {
		sess, _ = g.Sessions.Get(c.Value)
		g.Sessions.Delete(c.Value)
	}
	http.SetCookie(w, g.expireCookie(r))

	// When the session came from the IdP, end that session too — otherwise
	// every other app stays open for the rest of its TTL.
	if sess != nil && g.Logout != nil {
		if u := g.Logout.EndSessionURL(r, sess); u != "" {
			http.Redirect(w, r, u, http.StatusFound)
			return
		}
	}
	wasOIDC := sess != nil && sess.OIDCSub != ""
	g.signedOutPage(w, wasOIDC)
}

func (g *Gate) handleLoggedOut(w http.ResponseWriter, r *http.Request) {
	// The OP sends the browser here after RP-initiated logout. Landing on "/"
	// instead would start a fresh login and make logout look like a no-op.
	if c, err := r.Cookie(session.CookieName); err == nil {
		g.Sessions.Delete(c.Value)
	}
	http.SetCookie(w, g.expireCookie(r))
	g.signedOutPage(w, true)
}

func (g *Gate) signedOutPage(w http.ResponseWriter, wasOIDC bool) {
	note := ""
	if wasOIDC {
		note = `<p class="note">You may still be signed in with your identity provider.</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signed out</title><style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1e293b;padding:2.5rem 3rem;border-radius:12px;text-align:center;max-width:26rem}
h1{margin:0 0 .75rem;font-size:1.5rem}
p{margin:.5rem 0;color:#94a3b8;line-height:1.5}
a{color:#60a5fa}
</style></head><body><div class="card"><h1>Signed out</h1>
<p>Your session on this app has ended.</p>` + note + `
<p><a href="/">Sign in again</a></p></div></body></html>`))
}

// --- cookies -------------------------------------------------------------

// cookie builds the session cookie. Secure is derived from the forwarded
// scheme and never hardcoded: hardcoding false leaks the cookie on the
// HTTPS-only hosts every PCS app uses, and hardcoding true makes a plain-HTTP
// gate an unbreakable login loop because the browser will not send it back.
func (g *Gate) cookie(r *http.Request, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     session.CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   proxy.Scheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl / time.Second),
		// No Domain: the cookie stays host-only, scoped to this app's subdomain.
	}
}

func (g *Gate) expireCookie(r *http.Request) *http.Cookie {
	c := g.cookie(r, "", 0)
	c.MaxAge = -1
	c.Expires = time.Unix(0, 0)
	return c
}

// --- redirect safety -----------------------------------------------------

// PublicOrigin is the externally visible origin of this request.
func PublicOrigin(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return proxy.Scheme(r) + "://" + proxy.HostOnly(host)
}

// safeRedirect resolves a caller-supplied redirect against this request's own
// origin and rejects anything that leaves it, returning "/" instead. The OIDC
// flow in 2.x did exactly this; the password flow did not, which is what made
// it an open redirect.
func safeRedirect(r *http.Request, raw string) string {
	if raw == "" {
		return "/"
	}
	origin := PublicOrigin(r)
	base, err := url.Parse(origin)
	if err != nil {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	resolved := base.ResolveReference(u)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host {
		return "/"
	}
	out := resolved.EscapedPath()
	if out == "" {
		out = "/"
	}
	if resolved.RawQuery != "" {
		out += "?" + resolved.RawQuery
	}
	if resolved.Fragment != "" {
		out += "#" + resolved.EscapedFragment()
	}
	return out
}

// SafeRedirect is exported for the OIDC relying party, which needs the same rule.
func SafeRedirect(r *http.Request, raw string) string { return safeRedirect(r, raw) }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
