package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/identity"
	"github.com/yundera/appshield/internal/session"
)

const testNow = int64(1_700_000_000_000)

func now() time.Time { return time.UnixMilli(testNow) }

func newGate(t *testing.T, extra map[string]string) *Gate {
	t.Helper()
	kv := map[string]string{"BACKEND_HOST": "whoami", "BACKEND_PORT": "80", "LISTEN_PORT": "80"}
	for k, v := range extra {
		kv[k] = v
	}
	cfg, _, err := config.Load(func(k string) string { return kv[k] }, "myapp")
	if err != nil {
		t.Fatal(err)
	}
	store := session.Open("", now)
	t.Cleanup(func() { store.Close() })
	return New(Deps{
		Cfg:      cfg,
		Sessions: store,
		Prop: &identity.Propagator{
			Enabled:  cfg.IdentityHeaders,
			Secret:   []byte(cfg.AssertionSecret),
			TTL:      cfg.AssertionTTL,
			Audience: cfg.AppName,
			Now:      now,
		},
	})
}

func credGate(t *testing.T) *Gate {
	return newGate(t, map[string]string{"USER": "admin", "PASSWORD": "pw"})
}

func withSession(t *testing.T, g *Gate, sess *session.Session) *http.Cookie {
	t.Helper()
	id, err := g.Sessions.Create(sess)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: session.CookieName, Value: id}
}

// --- gate decision -------------------------------------------------------

func TestAnonymousIsRedirectedToLogin(t *testing.T) {
	g := credGate(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/private/page?a=1", nil)

	if _, ok := g.Authenticate(rec, r, false); ok {
		t.Fatal("anonymous request was allowed")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?redirect=") {
		t.Fatalf("Location = %q", loc)
	}
	// Where the user was going must survive the round trip.
	u, _ := url.Parse(loc)
	if got := u.Query().Get("redirect"); got != "/private/page?a=1" {
		t.Errorf("redirect = %q, want the original request URI", got)
	}
}

func TestOIDCModeRedirectsToSSO(t *testing.T) {
	g := newGate(t, map[string]string{"OIDC_REGISTRAR_URL": "http://reg:9092"})
	rec := httptest.NewRecorder()
	g.Authenticate(rec, httptest.NewRequest("GET", "/x", nil), false)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/nhl-auth/oidc/login?redirect=") {
		t.Errorf("Location = %q", loc)
	}
}

func TestNoAuthConfiguredReturns401(t *testing.T) {
	g := newGate(t, nil)
	rec := httptest.NewRecorder()
	g.Authenticate(rec, httptest.NewRequest("GET", "/x", nil), false)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestValidPasswordSessionIsAllowed(t *testing.T) {
	g := credGate(t)
	c := withSession(t, g, &session.Session{
		Expires:      testNow + 10_000,
		PasswordHash: g.Cfg.PasswordHash,
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	id, ok := g.Authenticate(httptest.NewRecorder(), r, false)
	if !ok {
		t.Fatal("valid session rejected")
	}
	if id.Method != identity.MethodPassword || id.User != "admin" {
		t.Errorf("identity = %+v", id)
	}
}

// When PASSWORD changes the container restarts with a new hash, and every
// session minted under the old one must stop working.
func TestPasswordSessionDiesWhenPasswordChanges(t *testing.T) {
	g := credGate(t)
	c := withSession(t, g, &session.Session{
		Expires:      testNow + 10_000,
		PasswordHash: "hash-from-an-older-password",
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	if _, ok := g.Authenticate(httptest.NewRecorder(), r, false); ok {
		t.Fatal("a session from a previous password was accepted")
	}
	if g.Sessions.Count() != 0 {
		t.Error("the stale session should have been deleted")
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	g := credGate(t)
	c := withSession(t, g, &session.Session{Expires: testNow - 1, PasswordHash: g.Cfg.PasswordHash})
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	if _, ok := g.Authenticate(httptest.NewRecorder(), r, false); ok {
		t.Error("expired session accepted")
	}
}

func TestUnknownCookieIsAnonymous(t *testing.T) {
	g := credGate(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: session.CookieName, Value: "nope"})
	rec := httptest.NewRecorder()
	if _, ok := g.Authenticate(rec, r, false); ok {
		t.Error("unknown session accepted")
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want a redirect to login", rec.Code)
	}
}

func TestOIDCSessionIdentity(t *testing.T) {
	g := newGate(t, map[string]string{"OIDC_REGISTRAR_URL": "http://reg:9092"})
	c := withSession(t, g, &session.Session{
		Expires: testNow + 10_000,
		OIDCSub: "sub-1",
		Claims: &session.Claims{
			Sub: "sub-1", User: "alice", Email: "a@e.com", Name: "Alice", Groups: []string{"admins"},
		},
	})
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)

	id, ok := g.Authenticate(httptest.NewRecorder(), r, false)
	if !ok {
		t.Fatal("valid OIDC session rejected")
	}
	if id.Method != identity.MethodOIDC || id.User != "alice" || id.Email != "a@e.com" || id.Groups[0] != "admins" {
		t.Errorf("identity = %+v", id)
	}
}

// --- group enforcement ---------------------------------------------------

func TestRequiredGroupsAllowsMember(t *testing.T) {
	g := newGate(t, map[string]string{
		"OIDC_REGISTRAR_URL":   "http://reg:9092",
		"OIDC_REQUIRED_GROUPS": "admins,staff",
	})
	c := withSession(t, g, &session.Session{
		Expires: testNow + 10_000, OIDCSub: "s",
		Claims: &session.Claims{Sub: "s", Groups: []string{"staff"}},
	})
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	if _, ok := g.Authenticate(httptest.NewRecorder(), r, false); !ok {
		t.Error("a member of a required group was denied")
	}
}

func TestRequiredGroupsDeniesNonMemberWith403(t *testing.T) {
	g := newGate(t, map[string]string{
		"OIDC_REGISTRAR_URL":   "http://reg:9092",
		"OIDC_REQUIRED_GROUPS": "admins",
	})
	c := withSession(t, g, &session.Session{
		Expires: testNow + 10_000, OIDCSub: "s",
		Claims: &session.Claims{Sub: "s", Groups: []string{"guests"}},
	})
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	rec := httptest.NewRecorder()

	if _, ok := g.Authenticate(rec, r, false); ok {
		t.Fatal("a non-member was allowed")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (not a redirect loop)", rec.Code)
	}
}

// An identity that asserts no groups can never satisfy a requirement.
func TestRequiredGroupsFailsClosedWithNoGroups(t *testing.T) {
	g := newGate(t, map[string]string{
		"OIDC_REGISTRAR_URL":   "http://reg:9092",
		"OIDC_REQUIRED_GROUPS": "admins",
	})
	c := withSession(t, g, &session.Session{
		Expires: testNow + 10_000, OIDCSub: "s", Claims: &session.Claims{Sub: "s"},
	})
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	rec := httptest.NewRecorder()
	if _, ok := g.Authenticate(rec, r, false); ok {
		t.Error("an identity with no groups satisfied a group requirement")
	}
}

// A session minted before the gate recorded claims cannot be group-checked.
// Deleting it forces re-auth instead of a 403 the user cannot act on.
func TestUngradedLegacySessionIsDeletedNotForbidden(t *testing.T) {
	g := newGate(t, map[string]string{
		"OIDC_REGISTRAR_URL":   "http://reg:9092",
		"OIDC_REQUIRED_GROUPS": "admins",
	})
	c := withSession(t, g, &session.Session{Expires: testNow + 10_000, OIDCSub: "s"}) // no Claims
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	rec := httptest.NewRecorder()

	if _, ok := g.Authenticate(rec, r, false); ok {
		t.Fatal("an ungraded session was allowed")
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want a redirect to re-authenticate", rec.Code)
	}
	if g.Sessions.Count() != 0 {
		t.Error("the ungraded session should have been deleted")
	}
}

// --- bearer / OAuth ------------------------------------------------------

type fakeBearer struct{ sub string }

func (f fakeBearer) VerifyBearer(tok string) (string, bool) {
	if tok == "good.jwt.sig" {
		return f.sub, true
	}
	return "", false
}

func TestBearerTokenGrantsOAuthIdentity(t *testing.T) {
	g := newGate(t, map[string]string{
		"OAUTH_RESOURCE":         "https://beacon-x.example.com/mcp",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "x.example.com",
	})
	g.Bearer = fakeBearer{sub: "client-9"}

	r := httptest.NewRequest("GET", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer good.jwt.sig")
	id, ok := g.Authenticate(httptest.NewRecorder(), r, true)
	if !ok {
		t.Fatal("a valid bearer token was rejected")
	}
	if id.Method != identity.MethodOAuth || id.Sub != "client-9" {
		t.Errorf("identity = %+v", id)
	}
}

// Only JWS-shaped tokens are worth verifying, so an opaque bearer and a broker
// JWT can share the header without one shadowing the other.
func TestNonJWSBearerIsIgnored(t *testing.T) {
	g := newGate(t, map[string]string{
		"OAUTH_RESOURCE":         "https://beacon-x.example.com/mcp",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "x.example.com",
	})
	g.Bearer = fakeBearer{sub: "client-9"}
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer opaque-not-a-jwt")
	if _, ok := g.Authenticate(httptest.NewRecorder(), r, true); ok {
		t.Error("an opaque bearer was accepted as a JWT")
	}
}

// A machine client cannot follow a browser redirect; it needs RFC 9728
// discovery instead.
func TestOAuthProtectedPathChallengesWithResourceMetadata(t *testing.T) {
	g := newGate(t, map[string]string{
		"OAUTH_RESOURCE":         "https://beacon-x.example.com/mcp",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "x.example.com",
		"OIDC_REGISTRAR_URL":     "http://reg:9092",
	})
	rec := httptest.NewRecorder()
	g.Authenticate(rec, httptest.NewRequest("GET", "/mcp", nil), true)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	want := `Bearer resource_metadata="https://beacon-x.example.com/.well-known/oauth-protected-resource"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// A browser hitting a non-protected path still gets the SSO redirect.
func TestNonProtectedPathStillRedirects(t *testing.T) {
	g := newGate(t, map[string]string{
		"OAUTH_RESOURCE":         "https://beacon-x.example.com/mcp",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "x.example.com",
		"OIDC_REGISTRAR_URL":     "http://reg:9092",
	})
	rec := httptest.NewRecorder()
	g.Authenticate(rec, httptest.NewRequest("GET", "/ui", nil), false)
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
}

// --- login ---------------------------------------------------------------

func postLogin(t *testing.T, g *Gate, form url.Values, https bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/nhl-auth/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if https {
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	g.RegisterRoutes(mux)
	mux.ServeHTTP(rec, r)
	return rec
}

func TestSuccessfulLoginSetsSecureCookie(t *testing.T) {
	g := credGate(t)
	rec := postLogin(t, g, url.Values{
		"username": {"admin"}, "password": {"pw"}, "redirect": {"/dash"},
	}, true)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dash" {
		t.Errorf("Location = %q, want /dash", loc)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != session.CookieName || c.Value == "" {
		t.Errorf("cookie = %+v", c)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie attributes wrong: %+v", c)
	}
	// Host-only: a Domain would share the session across sibling apps.
	if c.Domain != "" {
		t.Errorf("cookie has Domain=%q, want host-only", c.Domain)
	}
}

// Hardcoding Secure=true would make a plain-HTTP gate an unbreakable login loop.
func TestCookieSecureFollowsForwardedScheme(t *testing.T) {
	g := credGate(t)
	rec := postLogin(t, g, url.Values{"username": {"admin"}, "password": {"pw"}}, false)
	c := rec.Result().Cookies()[0]
	if c.Secure {
		t.Error("cookie is Secure on a plain-HTTP request; the browser would never send it back")
	}
}

func TestFailedLoginIsRejectedAndSlow(t *testing.T) {
	g := credGate(t)
	start := time.Now()
	rec := postLogin(t, g, url.Values{"username": {"admin"}, "password": {"wrong"}}, true)
	elapsed := time.Since(start)

	if len(rec.Result().Cookies()) != 0 {
		t.Error("a failed login set a cookie")
	}
	if g.Sessions.Count() != 0 {
		t.Error("a failed login created a session")
	}
	if elapsed < failedLoginDelay {
		t.Errorf("failed login took %v, want at least %v", elapsed, failedLoginDelay)
	}
}

func TestWrongUsernameAlsoRejected(t *testing.T) {
	g := credGate(t)
	postLogin(t, g, url.Values{"username": {"root"}, "password": {"pw"}}, true)
	if g.Sessions.Count() != 0 {
		t.Error("a wrong username was accepted")
	}
}

// 2.x passed the form's redirect field straight to res.redirect.
func TestLoginRedirectCannotLeaveTheOrigin(t *testing.T) {
	g := credGate(t)
	for _, evil := range []string{
		"https://evil.example.com/steal",
		"//evil.example.com/steal",
		"http://evil.example.com",
		"https://evil.example.com\\@x",
	} {
		rec := postLogin(t, g, url.Values{
			"username": {"admin"}, "password": {"pw"}, "redirect": {evil},
		}, true)
		loc := rec.Header().Get("Location")
		if strings.Contains(loc, "evil.example.com") {
			t.Errorf("redirect=%q produced an off-origin Location %q", evil, loc)
		}
	}
}

func TestSafeRedirectKeepsSameOriginTargets(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "app.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")

	for in, want := range map[string]string{
		"":                              "/",
		"/dash":                         "/dash",
		"/dash?tab=1":                   "/dash?tab=1",
		"https://app.example.com/dash":  "/dash",
		"https://evil.example.com/dash": "/",
		"//evil.example.com/dash":       "/",
	} {
		if got := SafeRedirect(r, in); got != want {
			t.Errorf("SafeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- logout --------------------------------------------------------------

func TestLogoutClearsSessionAndCookie(t *testing.T) {
	g := credGate(t)
	c := withSession(t, g, &session.Session{Expires: testNow + 10_000, PasswordHash: g.Cfg.PasswordHash})

	r := httptest.NewRequest("GET", "/nhl-auth/logout", nil)
	r.AddCookie(c)
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	g.RegisterRoutes(mux)
	mux.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want a terminal page", rec.Code)
	}
	if g.Sessions.Count() != 0 {
		t.Error("the session survived logout")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Errorf("logout did not expire the cookie: %+v", cookies)
	}
}

// GET must keep working (403.html links to it), but the cross-site
// sub-resource shapes a browser can be tricked into must not.
func TestLogoutRejectsCrossSiteSubresource(t *testing.T) {
	g := credGate(t)
	c := withSession(t, g, &session.Session{Expires: testNow + 10_000, PasswordHash: g.Cfg.PasswordHash})

	r := httptest.NewRequest("GET", "/nhl-auth/logout", nil)
	r.AddCookie(c)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Sec-Fetch-Dest", "image")
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	g.RegisterRoutes(mux)
	mux.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if g.Sessions.Count() != 1 {
		t.Error("a cross-site image request logged the user out")
	}
}

func TestLogoutAllowsTopLevelCrossSiteNavigation(t *testing.T) {
	g := credGate(t)
	c := withSession(t, g, &session.Session{Expires: testNow + 10_000, PasswordHash: g.Cfg.PasswordHash})

	r := httptest.NewRequest("GET", "/nhl-auth/logout", nil)
	r.AddCookie(c)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Sec-Fetch-Dest", "document")
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	g.RegisterRoutes(mux)
	mux.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK || g.Sessions.Count() != 0 {
		t.Errorf("a top-level navigation to logout should work: status=%d count=%d", rec.Code, g.Sessions.Count())
	}
}

// --- control API ---------------------------------------------------------

func controlToken(t *testing.T, g *Gate, lifetime int64) string {
	t.Helper()
	tok, err := g.Prop.SignControlToken(identity.ControlClaims{
		Iat: testNow / 1000,
		Exp: testNow/1000 + lifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func postRevoke(t *testing.T, g *Gate, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/nhl-auth/sessions/revoke", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	g.RegisterRoutes(mux)
	mux.ServeHTTP(rec, r)
	return rec
}

func assertionGate(t *testing.T) *Gate {
	return newGate(t, map[string]string{
		"OIDC_REGISTRAR_URL":        "http://reg:9092",
		"IDENTITY_ASSERTION_SECRET": "control-secret",
		"APP_NAME":                  "beacon",
	})
}

func TestRevokeRequiresSecret(t *testing.T) {
	g := newGate(t, map[string]string{"OIDC_REGISTRAR_URL": "http://reg:9092"})
	rec := postRevoke(t, g, "", `{"all":true}`)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501 without IDENTITY_ASSERTION_SECRET", rec.Code)
	}
}

func TestRevokeRejectsBadToken(t *testing.T) {
	g := assertionGate(t)
	if rec := postRevoke(t, g, "", `{"all":true}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	if rec := postRevoke(t, g, "not.a.token", `{"all":true}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: status = %d, want 401", rec.Code)
	}
}

// The audience split is the whole security argument for the control API.
func TestIdentityAssertionCannotRevokeSessions(t *testing.T) {
	g := assertionGate(t)
	assertion, err := g.Prop.MintAssertion(identity.Identity{Method: identity.MethodOIDC, Sub: "s", User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := postRevoke(t, g, assertion, `{"all":true}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("an identity assertion was accepted as a control token (status %d)", rec.Code)
	}
}

func TestRevokeBySub(t *testing.T) {
	g := assertionGate(t)
	g.Sessions.Create(&session.Session{Expires: testNow + 10_000, OIDCSub: "alice"})
	g.Sessions.Create(&session.Session{Expires: testNow + 10_000, OIDCSub: "alice"})
	g.Sessions.Create(&session.Session{Expires: testNow + 10_000, OIDCSub: "bob"})

	rec := postRevoke(t, g, controlToken(t, g, 60), `{"sub":"alice"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]int
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["revoked"] != 2 {
		t.Errorf("revoked = %d, want 2", got["revoked"])
	}
	if g.Sessions.Count() != 1 {
		t.Errorf("remaining = %d, want bob's session", g.Sessions.Count())
	}
}

func TestRevokeExceptSparesNamedSession(t *testing.T) {
	g := assertionGate(t)
	keep, _ := g.Sessions.Create(&session.Session{Expires: testNow + 10_000, OIDCSub: "alice"})
	g.Sessions.Create(&session.Session{Expires: testNow + 10_000, OIDCSub: "alice"})

	rec := postRevoke(t, g, controlToken(t, g, 60), `{"sub":"alice","except":"`+keep+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, ok := g.Sessions.Get(keep); !ok {
		t.Error("the spared session was revoked — an operator resetting their own password would be logged out")
	}
	if g.Sessions.Count() != 1 {
		t.Errorf("count = %d, want 1", g.Sessions.Count())
	}
}

func TestRevokeExceptAcceptsArray(t *testing.T) {
	g := assertionGate(t)
	a, _ := g.Sessions.Create(&session.Session{Expires: testNow + 10_000, OIDCSub: "alice"})
	b, _ := g.Sessions.Create(&session.Session{Expires: testNow + 10_000, OIDCSub: "alice"})
	g.Sessions.Create(&session.Session{Expires: testNow + 10_000, OIDCSub: "alice"})

	postRevoke(t, g, controlToken(t, g, 60), `{"sub":"alice","except":["`+a+`","`+b+`"]}`)
	if g.Sessions.Count() != 2 {
		t.Errorf("count = %d, want the two spared sessions", g.Sessions.Count())
	}
}

func TestRevokeRequiresASelector(t *testing.T) {
	g := assertionGate(t)
	if rec := postRevoke(t, g, controlToken(t, g, 60), `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// Zero matches is success — reporting otherwise would leak whether a user has
// a session on this app.
func TestRevokeZeroMatchesIsSuccess(t *testing.T) {
	g := assertionGate(t)
	rec := postRevoke(t, g, controlToken(t, g, 60), `{"sub":"nobody"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var got map[string]int
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["revoked"] != 0 {
		t.Errorf("revoked = %d, want 0", got["revoked"])
	}
}
