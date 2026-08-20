package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/jose"
	"github.com/yundera/appshield/internal/session"
)

const (
	issuer   = "https://beacon-example.com"
	resource = "https://beacon-example.com/mcp"
	verifier = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFG" // 46 chars, valid charset
)

func challengeFor(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type harness struct {
	*Server
	handler  http.Handler
	sessions *session.Store
	dir      string
	cookie   *http.Cookie
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	kv := map[string]string{
		"BACKEND_HOST":           "whoami",
		"BACKEND_PORT":           "80",
		"LISTEN_PORT":            "80",
		"OIDC_REGISTRAR_URL":     "http://reg:9092",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "example.com",
		"OAUTH_RESOURCE":         resource,
		"OAUTH_SCOPE":            "mcp",
		"OAUTH_DATA_DIR":         dir,
	}
	cfg, _, err := config.Load(func(k string) string { return kv[k] }, "beacon")
	if err != nil {
		t.Fatal(err)
	}
	store := session.Open("", time.Now)
	t.Cleanup(func() { store.Close() })

	s, err := New(cfg, store, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	// A logged-in human, which is what authorizes an OAuth client.
	id, err := store.Create(&session.Session{
		Expires: time.Now().Add(time.Hour).UnixMilli(),
		OIDCSub: "user-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{
		Server:   s,
		handler:  s.Handler(),
		sessions: store,
		dir:      dir,
		cookie:   &http.Cookie{Name: session.CookieName, Value: id},
	}
}

func (h *harness) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

func (h *harness) getJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	rec := h.do(httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// register performs Dynamic Client Registration and returns the response.
func (h *harness) register(t *testing.T, body string) map[string]any {
	t.Helper()
	r := httptest.NewRequest("POST", routeRegister, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := h.do(r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (h *harness) publicClient(t *testing.T) map[string]any {
	return h.register(t, `{"redirect_uris":["https://client.example.com/cb"],
	                       "token_endpoint_auth_method":"none","client_name":"MCP Inspector",
	                       "grant_types":["authorization_code","refresh_token"]}`)
}

func (h *harness) confidentialClient(t *testing.T) map[string]any {
	return h.register(t, `{"redirect_uris":["https://client.example.com/cb"],
	                       "grant_types":["authorization_code","refresh_token"]}`)
}

// authorize drives /auth and the interaction bridge, returning the code.
func (h *harness) authorize(t *testing.T, clientID, scope string) string {
	t.Helper()
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"https://client.example.com/cb"},
		"response_type":         {"code"},
		"scope":                 {scope},
		"state":                 {"st-1"},
		"code_challenge":        {challengeFor(verifier)},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
	}
	rec := h.do(httptest.NewRequest("GET", routeAuth+"?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/auth = %d: %s", rec.Code, rec.Body.String())
	}
	interaction := rec.Header().Get("Location")

	r := httptest.NewRequest("GET", interaction, nil)
	r.AddCookie(h.cookie)
	rec = h.do(r)
	if rec.Code != http.StatusFound {
		t.Fatalf("interaction = %d: %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("state"); got != "st-1" {
		t.Errorf("state = %q, want st-1", got)
	}
	// RFC 9207: advertised in discovery, so it must actually be present.
	if got := u.Query().Get("iss"); got != issuer {
		t.Errorf("iss = %q, want %q", got, issuer)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", u)
	}
	return code
}

func (h *harness) token(t *testing.T, form url.Values, c map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", routeToken, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret, ok := c["client_secret"].(string); ok && secret != "" {
		r.SetBasicAuth(c["client_id"].(string), secret)
	} else {
		// Public clients identify themselves in the body.
		form.Set("client_id", c["client_id"].(string))
		r = httptest.NewRequest("POST", routeToken, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return h.do(r)
}

func (h *harness) exchange(t *testing.T, c map[string]any, code string) map[string]any {
	t.Helper()
	rec := h.token(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example.com/cb"},
		"code_verifier": {verifier},
	}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("token = %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func decodePayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeHeader(t *testing.T, tok string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// --- discovery -----------------------------------------------------------

func TestDiscoveryDocument(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{wellKnownOIDC, wellKnownAS} {
		doc := h.getJSON(t, path)
		if doc["issuer"] != issuer {
			t.Errorf("%s: issuer = %v", path, doc["issuer"])
		}
		for k, want := range map[string]string{
			"authorization_endpoint": issuer + routeAuth,
			"token_endpoint":         issuer + routeToken,
			"jwks_uri":               issuer + routeJWKS,
			"registration_endpoint":  issuer + routeRegister,
		} {
			if doc[k] != want {
				t.Errorf("%s: %s = %v, want %v", path, k, doc[k], want)
			}
		}
		// PKCE is mandatory and S256-only.
		if methods := doc["code_challenge_methods_supported"].([]any); len(methods) != 1 || methods[0] != "S256" {
			t.Errorf("code_challenge_methods_supported = %v", methods)
		}
		// OAuth 2.1 has no implicit flow; 2.x advertised it by accident.
		for _, g := range doc["grant_types_supported"].([]any) {
			if g == "implicit" {
				t.Error("implicit is still advertised")
			}
		}
		if doc["authorization_response_iss_parameter_supported"] != true {
			t.Error("iss parameter support should be advertised")
		}
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	h := newHarness(t)
	doc := h.getJSON(t, wellKnownResource)
	if doc["resource"] != resource {
		t.Errorf("resource = %v", doc["resource"])
	}
	servers := doc["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != issuer {
		t.Errorf("authorization_servers = %v", servers)
	}
	scopes := doc["scopes_supported"].([]any)
	if len(scopes) != 1 || scopes[0] != "mcp" {
		t.Errorf("scopes_supported = %v", scopes)
	}
}

func TestJWKSIsPublicOnly(t *testing.T) {
	h := newHarness(t)
	doc := h.getJSON(t, routeJWKS)
	keys := doc["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("got %d keys", len(keys))
	}
	k := keys[0].(map[string]any)
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, leaked := k[private]; leaked {
			t.Errorf("JWKS leaks %q", private)
		}
	}
}

// --- keys ----------------------------------------------------------------

// 2.x wrote this private key with the default mode.
func TestSigningKeyIsNotWorldReadable(t *testing.T) {
	h := newHarness(t)
	fi, err := os.Stat(filepath.Join(h.dir, "jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("jwks.json mode is %o, want no group/other access", perm)
	}
}

// A parse bug that silently regenerated the key would 401 every live token.
func TestCorruptKeyRefusesToStart(t *testing.T) {
	h := newHarness(t)
	keyPath := filepath.Join(h.dir, "jwks.json")
	if err := os.WriteFile(keyPath, []byte("{not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	kv := map[string]string{
		"BACKEND_HOST": "whoami", "BACKEND_PORT": "80", "LISTEN_PORT": "80",
		"OAUTH_RESOURCE": resource, "APP_NAME": "beacon",
		"REDIRECT_HOST_SUFFIXES": "example.com", "OAUTH_DATA_DIR": h.dir,
	}
	cfg, _, _ := config.Load(func(k string) string { return kv[k] }, "beacon")
	if _, err := New(cfg, h.sessions, time.Now); err == nil {
		t.Fatal("expected a refusal rather than a regenerated key")
	}
}

// An existing key must be reused, not replaced, across restarts.
func TestExistingKeyIsReused(t *testing.T) {
	h := newHarness(t)
	before, err := os.ReadFile(filepath.Join(h.dir, "jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	kv := map[string]string{
		"BACKEND_HOST": "whoami", "BACKEND_PORT": "80", "LISTEN_PORT": "80",
		"OAUTH_RESOURCE": resource, "APP_NAME": "beacon",
		"REDIRECT_HOST_SUFFIXES": "example.com", "OAUTH_DATA_DIR": h.dir,
	}
	cfg, _, _ := config.Load(func(k string) string { return kv[k] }, "beacon")
	s2, err := New(cfg, h.sessions, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(h.dir, "jwks.json"))
	if string(before) != string(after) {
		t.Error("the key file was rewritten on restart")
	}
	if s2.key.Kid != h.key.Kid {
		t.Errorf("kid changed from %q to %q", h.key.Kid, s2.key.Kid)
	}
}

// The issuer is baked into every issued token; moving it must be loud.
func TestIssuerChangeRefusesToStart(t *testing.T) {
	h := newHarness(t)
	kv := map[string]string{
		"BACKEND_HOST": "whoami", "BACKEND_PORT": "80", "LISTEN_PORT": "80",
		"OAUTH_RESOURCE": resource, "APP_NAME": "renamed",
		"REDIRECT_HOST_SUFFIXES": "example.com", "OAUTH_DATA_DIR": h.dir,
	}
	cfg, _, _ := config.Load(func(k string) string { return kv[k] }, "renamed")
	_, err := New(cfg, h.sessions, time.Now)
	if err == nil {
		t.Fatal("expected a refusal when the issuer changes")
	}
	if !strings.Contains(err.Error(), "issuer changed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- registration --------------------------------------------------------

func TestDynamicRegistration(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)

	if c["client_id"] == "" {
		t.Error("no client_id issued")
	}
	if c["client_secret"] == "" {
		t.Error("a confidential client got no secret")
	}
	// 2.x returned 201 with RFC 7592 credentials; clients store and use them.
	if c["registration_access_token"] == "" || c["registration_client_uri"] == "" {
		t.Errorf("no RFC 7592 credentials: %v", c)
	}
	if c["client_secret_expires_at"] != float64(0) {
		t.Errorf("client_secret_expires_at = %v, want 0", c["client_secret_expires_at"])
	}
}

func TestPublicClientGetsNoSecret(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)
	if s, ok := c["client_secret"]; ok && s != "" {
		t.Errorf("a public client was issued a secret: %v", s)
	}
}

// MCP Inspector and similar local tooling register loopback redirect URIs.
func TestRegistrationAllowsLoopbackHTTP(t *testing.T) {
	h := newHarness(t)
	for _, uri := range []string{
		"http://localhost:6274/cb", "http://127.0.0.1:8080/cb", "https://remote.example.com/cb",
	} {
		body := `{"redirect_uris":["` + uri + `"]}`
		r := httptest.NewRequest("POST", routeRegister, strings.NewReader(body))
		if rec := h.do(r); rec.Code != http.StatusCreated {
			t.Errorf("redirect_uri %q rejected: %s", uri, rec.Body.String())
		}
	}
}

func TestRegistrationRejectsBadMetadata(t *testing.T) {
	h := newHarness(t)
	for name, body := range map[string]string{
		"no redirect_uris":  `{"client_name":"x"}`,
		"plain http remote": `{"redirect_uris":["http://remote.example.com/cb"]}`,
		"fragment":          `{"redirect_uris":["https://x.example.com/cb#frag"]}`,
		"relative":          `{"redirect_uris":["/cb"]}`,
		"bad grant":         `{"redirect_uris":["https://x.example.com/cb"],"grant_types":["password"]}`,
		"bad response type": `{"redirect_uris":["https://x.example.com/cb"],"response_types":["token"]}`,
		"bad auth method":   `{"redirect_uris":["https://x.example.com/cb"],"token_endpoint_auth_method":"private_key_jwt"}`,
		"not json":          `{`,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", routeRegister, strings.NewReader(body))
			if rec := h.do(r); rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestRegistrationReadBackWithAccessToken(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	id := c["client_id"].(string)

	r := httptest.NewRequest("GET", routeRegister+"/"+id, nil)
	r.Header.Set("Authorization", "Bearer "+c["registration_access_token"].(string))
	rec := h.do(r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	// Without the token it must not be readable.
	rec = h.do(httptest.NewRequest("GET", routeRegister+"/"+id, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated read = %d, want 401", rec.Code)
	}
}

// --- authorization -------------------------------------------------------

// An unauthenticated browser is sent through SSO and comes back.
func TestInteractionRedirectsToSSOWhenAnonymous(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)

	q := url.Values{
		"client_id": {c["client_id"].(string)}, "redirect_uri": {"https://client.example.com/cb"},
		"response_type": {"code"}, "code_challenge": {challengeFor(verifier)},
		"code_challenge_method": {"S256"},
	}
	rec := h.do(httptest.NewRequest("GET", routeAuth+"?"+q.Encode(), nil))
	interaction := rec.Header().Get("Location")

	rec = h.do(httptest.NewRequest("GET", interaction, nil)) // no cookie
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/nhl-auth/oidc/login?redirect=") {
		t.Errorf("Location = %q", loc)
	}
	if !strings.Contains(loc, url.QueryEscape(interaction)) {
		t.Errorf("the interaction is not preserved across login: %q", loc)
	}
}

// A password session has no OIDC subject and cannot authorize a client.
func TestPasswordSessionCannotAuthorize(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)
	pwID, _ := h.sessions.Create(&session.Session{
		Expires: time.Now().Add(time.Hour).UnixMilli(), PasswordHash: "ph",
	})

	q := url.Values{
		"client_id": {c["client_id"].(string)}, "redirect_uri": {"https://client.example.com/cb"},
		"response_type": {"code"}, "code_challenge": {challengeFor(verifier)},
		"code_challenge_method": {"S256"},
	}
	rec := h.do(httptest.NewRequest("GET", routeAuth+"?"+q.Encode(), nil))
	r := httptest.NewRequest("GET", rec.Header().Get("Location"), nil)
	r.AddCookie(&http.Cookie{Name: session.CookieName, Value: pwID})

	rec = h.do(r)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/nhl-auth/oidc/login") {
		t.Errorf("Location = %q, want the SSO login", loc)
	}
}

// Until the redirect_uri is validated, errors must be shown, not redirected.
func TestUnregisteredRedirectURIIsNotRedirectedTo(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)
	q := url.Values{
		"client_id": {c["client_id"].(string)}, "redirect_uri": {"https://evil.example.com/steal"},
		"response_type": {"code"}, "code_challenge": {challengeFor(verifier)},
		"code_challenge_method": {"S256"},
	}
	rec := h.do(httptest.NewRequest("GET", routeAuth+"?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "evil.example.com") {
		t.Errorf("redirected to an unregistered URI: %q", loc)
	}
}

func TestPKCEIsMandatory(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)

	for name, extra := range map[string]url.Values{
		"no challenge":   {},
		"plain method":   {"code_challenge": {"abc"}, "code_challenge_method": {"plain"}},
		"missing method": {"code_challenge": {challengeFor(verifier)}},
	} {
		t.Run(name, func(t *testing.T) {
			q := url.Values{
				"client_id": {c["client_id"].(string)}, "redirect_uri": {"https://client.example.com/cb"},
				"response_type": {"code"}, "state": {"st"},
			}
			for k, v := range extra {
				q[k] = v
			}
			rec := h.do(httptest.NewRequest("GET", routeAuth+"?"+q.Encode(), nil))
			u, _ := url.Parse(rec.Header().Get("Location"))
			if got := u.Query().Get("error"); got != "invalid_request" {
				t.Errorf("error = %q, want invalid_request (status %d)", got, rec.Code)
			}
			if u.Query().Get("iss") != issuer {
				t.Error("error redirect is missing iss")
			}
		})
	}
}

// 2.x parsed `resource` and then ignored it. Clients disagree about the
// canonical form, so validating it would break ones that work today.
func TestResourceIndicatorIsAcceptedAndIgnored(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)

	for _, res := range []string{resource, "https://beacon-example.com/", "https://something.else/mcp"} {
		q := url.Values{
			"client_id": {c["client_id"].(string)}, "redirect_uri": {"https://client.example.com/cb"},
			"response_type": {"code"}, "code_challenge": {challengeFor(verifier)},
			"code_challenge_method": {"S256"}, "resource": {res},
		}
		rec := h.do(httptest.NewRequest("GET", routeAuth+"?"+q.Encode(), nil))
		if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, routeInteraction) {
			t.Errorf("resource=%q was rejected: %q", res, loc)
		}
	}
	// ...and the audience minted is always the one resource we protect.
	code := h.authorize(t, c["client_id"].(string), "mcp")
	tokens := h.exchange(t, c, code)
	claims := decodePayload(t, tokens["access_token"].(string))
	if claims["aud"] != resource {
		t.Errorf("aud = %v, want %q", claims["aud"], resource)
	}
}

// --- token issuance ------------------------------------------------------

// oidc-provider emitted exactly these eight claims, with aud as a string.
func TestAccessTokenClaimShape(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp"))

	at := tokens["access_token"].(string)
	hdr := decodeHeader(t, at)
	if hdr["alg"] != "RS256" || hdr["typ"] != "at+jwt" || hdr["kid"] != h.key.Kid {
		t.Errorf("header = %v", hdr)
	}

	claims := decodePayload(t, at)
	want := []string{"jti", "sub", "iat", "exp", "scope", "client_id", "iss", "aud"}
	if len(claims) != len(want) {
		t.Errorf("access token has %d claims (%v), want exactly %v", len(claims), keysOf(claims), want)
	}
	for _, k := range want {
		if _, ok := claims[k]; !ok {
			t.Errorf("missing claim %q", k)
		}
	}
	// aud must be a JSON string, not an array: oidc-provider rejected
	// multi-valued audiences, so every existing token has the scalar form.
	if _, isString := claims["aud"].(string); !isString {
		t.Errorf("aud = %#v, want a JSON string", claims["aud"])
	}
	if claims["sub"] != "user-1" || claims["iss"] != issuer || claims["client_id"] != c["client_id"] {
		t.Errorf("claims = %v", claims)
	}
}

func TestIDTokenOnlyWithOpenIDScope(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)

	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp"))
	if _, ok := tokens["id_token"]; ok {
		t.Error("an id_token was issued without the openid scope")
	}

	tokens = h.exchange(t, c, h.authorize(t, c["client_id"].(string), "openid mcp"))
	idt, ok := tokens["id_token"].(string)
	if !ok {
		t.Fatal("no id_token with the openid scope")
	}
	claims := decodePayload(t, idt)
	if claims["aud"] != c["client_id"] {
		t.Errorf("id_token aud = %v, want the client id", claims["aud"])
	}
	if claims["at_hash"] == nil {
		t.Error("id_token has no at_hash")
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	code := h.authorize(t, c["client_id"].(string), "mcp")

	h.exchange(t, c, code) // first use succeeds
	rec := h.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier},
	}, c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("replayed code = %d, want 400", rec.Code)
	}
}

func TestTokenRequestValidation(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)

	tests := map[string]url.Values{
		"wrong verifier":     {"code_verifier": {"wrong-verifier-that-is-long-enough-to-pass-length"}},
		"no verifier":        {"code_verifier": {""}},
		"wrong redirect_uri": {"redirect_uri": {"https://client.example.com/other"}},
	}
	for name, override := range tests {
		t.Run(name, func(t *testing.T) {
			code := h.authorize(t, c["client_id"].(string), "mcp")
			form := url.Values{
				"grant_type": {"authorization_code"}, "code": {code},
				"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier},
			}
			for k, v := range override {
				form[k] = v
			}
			if rec := h.token(t, form, c); rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestCodeCannotBeRedeemedByAnotherClient(t *testing.T) {
	h := newHarness(t)
	victim := h.confidentialClient(t)
	attacker := h.confidentialClient(t)

	code := h.authorize(t, victim["client_id"].(string), "mcp")
	rec := h.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier},
	}, attacker)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestBadClientCredentialsRejected(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	code := h.authorize(t, c["client_id"].(string), "mcp")

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier},
	}
	r := httptest.NewRequest("POST", routeToken, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(c["client_id"].(string), "not-the-secret")
	if rec := h.do(r); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// --- refresh tokens ------------------------------------------------------

// The highest-risk behaviour in the whole port: oidc-provider issued refresh
// tokens to public web clients even without offline_access, and DCR defaults
// application_type to "web". Keying only off the scope would break MCP
// connectors an hour after cutover.
func TestPublicWebClientGetsRefreshTokenWithoutOfflineAccess(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp"))

	if tokens["refresh_token"] == nil || tokens["refresh_token"] == "" {
		t.Fatal("a public web client got no refresh token without offline_access")
	}
}

// The first gate in oidc-provider's issueRefreshToken: a client that did not
// register the refresh_token grant never gets one, whatever it asks for.
func TestClientWithoutRefreshGrantNeverGetsRefreshToken(t *testing.T) {
	h := newHarness(t)
	c := h.register(t, `{"redirect_uris":["https://client.example.com/cb"],
	                     "token_endpoint_auth_method":"none",
	                     "grant_types":["authorization_code"]}`)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp offline_access"))
	if tokens["refresh_token"] != nil {
		t.Error("a client without the refresh_token grant received a refresh token")
	}
}

func TestOfflineAccessAlwaysYieldsRefreshToken(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp offline_access"))
	if tokens["refresh_token"] == nil {
		t.Error("offline_access did not produce a refresh token")
	}
}

func TestRefreshTokenGrant(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp offline_access"))
	rt := tokens["refresh_token"].(string)

	rec := h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh = %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)

	at := out["access_token"].(string)
	if sub, ok := h.VerifyBearer(at); !ok || sub != "user-1" {
		t.Errorf("refreshed access token does not verify (sub=%q ok=%v)", sub, ok)
	}
}

// Public clients cannot keep a secret, so their refresh tokens rotate on
// every use.
func TestPublicClientRefreshTokenRotates(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp"))
	first := tokens["refresh_token"].(string)

	rec := h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, c)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	second, _ := out["refresh_token"].(string)

	if second == "" || second == first {
		t.Errorf("refresh token did not rotate: %q -> %q", first, second)
	}
	// The predecessor stays usable briefly so a retried request still works.
	rec = h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, c)
	if rec.Code != http.StatusOK {
		t.Errorf("a retry inside the grace window failed: %d", rec.Code)
	}
}

// Beyond the grace window a replayed refresh token means it leaked, so the
// whole grant is revoked.
func TestRefreshTokenReuseRevokesTheGrant(t *testing.T) {
	h := newHarness(t)
	c := h.publicClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp"))
	first := tokens["refresh_token"].(string)

	rec := h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, c)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	second := out["refresh_token"].(string)

	// Move past the grace window.
	h.Server.now = func() time.Time { return time.Now().Add(consumedGrace + time.Minute) }
	h.store.now = h.Server.now

	rec = h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("replay = %d, want 400", rec.Code)
	}
	// The successor must have been revoked along with the grant.
	rec = h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {second}}, c)
	if rec.Code == http.StatusOK {
		t.Error("the successor token still works after reuse was detected")
	}
}

// --- bearer verification -------------------------------------------------

func TestVerifyBearer(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp"))
	at := tokens["access_token"].(string)

	if sub, ok := h.VerifyBearer(at); !ok || sub != "user-1" {
		t.Errorf("VerifyBearer = %q, %v", sub, ok)
	}
	for name, tok := range map[string]string{
		"empty":       "",
		"opaque":      "not-a-jwt",
		"tampered":    at[:len(at)-3] + "AAA",
		"wrong shape": "a.b",
	} {
		if _, ok := h.VerifyBearer(tok); ok {
			t.Errorf("%s token verified", name)
		}
	}
}

// A token minted by another AppShield instance must not be accepted here.
func TestVerifyBearerRejectsForeignIssuerAndAudience(t *testing.T) {
	h := newHarness(t)
	other, err := jose.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Right claims, wrong key.
	tok, _ := other.Sign("at+jwt", accessTokenClaims{
		Sub: "user-1", Iss: issuer, Aud: resource, Exp: time.Now().Add(time.Hour).Unix(),
	})
	if _, ok := h.VerifyBearer(tok); ok {
		t.Error("a token signed by a foreign key verified")
	}

	// Our key, wrong issuer and audience.
	for _, claims := range []accessTokenClaims{
		{Sub: "u", Iss: "https://elsewhere.example.com", Aud: resource, Exp: time.Now().Add(time.Hour).Unix()},
		{Sub: "u", Iss: issuer, Aud: "https://elsewhere.example.com/mcp", Exp: time.Now().Add(time.Hour).Unix()},
		{Sub: "u", Iss: issuer, Aud: resource, Exp: time.Now().Add(-time.Hour).Unix()},
	} {
		tok, _ := h.key.Sign("at+jwt", claims)
		if _, ok := h.VerifyBearer(tok); ok {
			t.Errorf("token with claims %+v verified", claims)
		}
	}
}

func TestUserinfo(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "openid mcp"))

	r := httptest.NewRequest("GET", routeUserinfo, nil)
	r.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	rec := h.do(r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["sub"] != "user-1" {
		t.Errorf("sub = %v", out["sub"])
	}

	// Without a token it must challenge.
	if rec := h.do(httptest.NewRequest("GET", routeUserinfo, nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated userinfo = %d, want 401", rec.Code)
	}
}

// --- revocation & introspection ------------------------------------------

func TestRevocation(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp offline_access"))
	rt := tokens["refresh_token"].(string)

	form := url.Values{"token": {rt}}
	r := httptest.NewRequest("POST", routeRevocation, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(c["client_id"].(string), c["client_secret"].(string))
	if rec := h.do(r); rec.Code != http.StatusOK {
		t.Fatalf("revocation = %d", rec.Code)
	}

	if rec := h.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, c); rec.Code == http.StatusOK {
		t.Error("a revoked refresh token still works")
	}
}

// RFC 7009: revoking an unknown token is still a success, so a caller cannot
// probe for valid tokens.
func TestRevokingUnknownTokenSucceeds(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	form := url.Values{"token": {"never-existed"}}
	r := httptest.NewRequest("POST", routeRevocation, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(c["client_id"].(string), c["client_secret"].(string))
	if rec := h.do(r); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestIntrospection(t *testing.T) {
	h := newHarness(t)
	c := h.confidentialClient(t)
	tokens := h.exchange(t, c, h.authorize(t, c["client_id"].(string), "mcp"))

	introspect := func(tok string) map[string]any {
		form := url.Values{"token": {tok}}
		r := httptest.NewRequest("POST", routeIntrospect, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(c["client_id"].(string), c["client_secret"].(string))
		rec := h.do(r)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	active := introspect(tokens["access_token"].(string))
	if active["active"] != true || active["sub"] != "user-1" {
		t.Errorf("introspection = %v", active)
	}
	if inactive := introspect("garbage.token.here"); inactive["active"] != false {
		t.Errorf("a garbage token introspected as active: %v", inactive)
	}
}

// --- CORS ----------------------------------------------------------------

// Browser-resident MCP clients fail at the token endpoint with an opaque
// error if CORS is missing, and nothing appears in the server log.
func TestCORSOnTokenEndpointButNotAuthorize(t *testing.T) {
	h := newHarness(t)

	r := httptest.NewRequest("OPTIONS", routeToken, nil)
	r.Header.Set("Origin", "https://client.example.com")
	rec := h.do(r)
	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://client.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}

	// The authorization endpoint is a browser navigation, not a fetch.
	r = httptest.NewRequest("GET", routeAuth+"?client_id=x", nil)
	r.Header.Set("Origin", "https://client.example.com")
	rec = h.do(r)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("the authorization endpoint should not send CORS headers")
	}
}

func TestWellKnownIsCORSEnabled(t *testing.T) {
	h := newHarness(t)
	r := httptest.NewRequest("GET", wellKnownResource, nil)
	r.Header.Set("Origin", "https://client.example.com")
	rec := h.do(r)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://client.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
