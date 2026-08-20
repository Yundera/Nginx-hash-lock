// Package broker is the OAuth 2.1 authorization server AppShield runs for
// machine clients — the MCP servers that need remote, non-interactive access.
//
// It is hand-written against the standard library rather than built on a
// general-purpose OP library. The surface is one issuer, one resource, one
// scope, one signing algorithm, one response type and two grant types, with no
// consent object and no provider-side session: the human session is already
// AppShield's. A library would still leave open Dynamic Client Registration,
// resource indicators, protected-resource metadata, CORS and PKCE-always to be
// written by hand, while making the exact wire output harder to match.
package broker

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/jose"
	"github.com/yundera/appshield/internal/session"
)

// Routes, kept byte-identical to 2.x so cached client metadata stays valid.
const (
	routeAuth        = "/AppShield/oidc/auth"
	routeToken       = "/AppShield/oidc/token"
	routeJWKS        = "/AppShield/oidc/jwks"
	routeRegister    = "/AppShield/oidc/reg"
	routeRevocation  = "/AppShield/oidc/token/revocation"
	routeIntrospect  = "/AppShield/oidc/token/introspection"
	routeUserinfo    = "/AppShield/oidc/me"
	routeEndSession  = "/AppShield/oidc/session/end"
	routeInteraction = "/AppShield/interaction/"
	routeAdmin       = "/AppShield/oauth"

	wellKnownOIDC     = "/.well-known/openid-configuration"
	wellKnownAS       = "/.well-known/oauth-authorization-server"
	wellKnownResource = "/.well-known/oauth-protected-resource"
)

// Token lifetimes, matching the 2.x provider configuration.
const (
	accessTokenTTL  = time.Hour
	authCodeTTL     = 10 * time.Minute
	authRequestTTL  = time.Hour
	refreshTokenTTL = 90 * 24 * time.Hour
	// refreshAbsoluteMax stops rotation extending a grant for ever.
	refreshAbsoluteMax = time.Duration(365.25 * 24 * float64(time.Hour))
	// consumedGrace lets a client that retried a request still succeed with
	// the refresh token it just rotated away.
	consumedGrace = 30 * time.Second
)

type Server struct {
	cfg      *config.Config
	store    *store
	key      *jose.Key
	pub      *rsa.PublicKey
	sessions *session.Store
	now      func() time.Time

	issuer   string
	resource string
	scope    string
	// scopes is everything the AS will grant.
	scopes []string
}

// New loads or creates the signing key and returns a ready server.
//
// If jwks.json exists but cannot be parsed this fails rather than generating a
// replacement: silently rotating the signing key would 401 every access token
// in flight and break every client holding a cached JWKS.
func New(cfg *config.Config, sessions *session.Store, now func() time.Time) (*Server, error) {
	if now == nil {
		now = time.Now
	}
	st, err := newStore(cfg.OAuthDataDir, now)
	if err != nil {
		return nil, err
	}

	keyPath := filepath.Join(cfg.OAuthDataDir, "jwks.json")
	var key *jose.Key
	switch raw, err := os.ReadFile(keyPath); {
	case err == nil:
		if key, err = jose.ParseKey(raw); err != nil {
			return nil, fmt.Errorf("%s exists but cannot be read (%w); refusing to start rather than "+
				"rotate the signing key and invalidate every live token", keyPath, err)
		}
	case os.IsNotExist(err):
		if key, err = jose.GenerateKey(); err != nil {
			return nil, err
		}
		blob, err := json.Marshal(key.MarshalJWK())
		if err != nil {
			return nil, err
		}
		// 0600: 2.x wrote this private key world-readable.
		if err := st.writeFile(keyPath, blob); err != nil {
			return nil, fmt.Errorf("persisting the signing key: %w", err)
		}
		log.Printf("[oauth] generated a new signing key (kid %s)", key.Kid)
	default:
		return nil, fmt.Errorf("reading %s: %w", keyPath, err)
	}

	s := &Server{
		cfg:      cfg,
		store:    st,
		key:      key,
		pub:      &key.Private.PublicKey,
		sessions: sessions,
		now:      now,
		issuer:   cfg.CanonicalOrigin,
		resource: cfg.OAuthResource,
		scope:    cfg.OAuthScope,
	}
	s.scopes = []string{"openid", "offline_access", "profile", "email", cfg.OAuthScope}

	if err := s.checkIssuerStable(); err != nil {
		return nil, err
	}
	return s, nil
}

// checkIssuerStable refuses to start if the issuer has moved.
//
// The issuer is baked into every token already signed and into the discovery
// documents remote clients cache. It is derived from APP_NAME and the first
// REDIRECT_HOST_SUFFIXES entry, which is exactly the kind of thing a config
// edit changes by accident.
func (s *Server) checkIssuerStable() error {
	marker := filepath.Join(s.cfg.OAuthDataDir, "issuer")
	prev, err := os.ReadFile(marker)
	switch {
	case err == nil:
		if got := strings.TrimSpace(string(prev)); got != s.issuer {
			return fmt.Errorf("the OAuth issuer changed from %q to %q; every token already issued "+
				"names the old one. Restore APP_NAME/REDIRECT_HOST_SUFFIXES, or delete %s to accept "+
				"invalidating all existing tokens and client registrations", got, s.issuer, marker)
		}
		return nil
	case os.IsNotExist(err):
		return s.store.writeFile(marker, []byte(s.issuer+"\n"))
	default:
		return err
	}
}

// Store exposes the sweeper to main.
func (s *Server) SweepEvery(d time.Duration, stop <-chan struct{}) {
	s.store.sweepEvery(d, s.cfg.OAuthLegacySweep, stop)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+wellKnownOIDC, s.handleDiscovery)
	mux.HandleFunc("GET "+wellKnownAS, s.handleDiscovery)
	mux.HandleFunc("GET "+wellKnownResource, s.handleProtectedResource)

	mux.HandleFunc("GET "+routeAuth, s.handleAuthorize)
	mux.HandleFunc("POST "+routeToken, s.handleToken)
	mux.HandleFunc("GET "+routeJWKS, s.handleJWKS)
	mux.HandleFunc("POST "+routeRegister, s.handleRegister)
	mux.HandleFunc("GET "+routeRegister+"/{id}", s.handleReadClient)
	mux.HandleFunc("POST "+routeRevocation, s.handleRevocation)
	mux.HandleFunc("POST "+routeIntrospect, s.handleIntrospection)
	mux.HandleFunc("GET "+routeUserinfo, s.handleUserinfo)
	mux.HandleFunc("GET "+routeInteraction+"{uid}", s.handleInteraction)

	s.registerAdminRoutes(mux)

	return s.withCORS(mux)
}

// withCORS echoes the caller's origin on everything except the authorization
// endpoint, which is a browser navigation rather than a fetch.
//
// 2.x set clientBasedCORS to true for every client. Without it a
// browser-resident MCP client fails at the token endpoint with an opaque CORS
// error that appears in no server log.
func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && r.URL.Path != routeAuth {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "authorization, content-type")
			h.Set("Access-Control-Max-Age", "3600")
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- authorization -------------------------------------------------------

// authRequest is a validated authorization request awaiting a human.
type authRequest struct {
	ClientID    string `json:"clientId"`
	RedirectURI string `json:"redirectUri"`
	State       string `json:"state"`
	Scope       string `json:"scope"`
	Challenge   string `json:"codeChallenge"`
	Nonce       string `json:"nonce"`
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Until the client and redirect_uri are known-good, errors must be shown
	// rather than redirected: redirecting to an unvalidated URI is how an
	// open redirector gets built.
	c, err := s.loadClient(q.Get("client_id"))
	if err != nil {
		http.Error(w, "Unknown client", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(c.RedirectURIs) == 1 {
		redirectURI = c.RedirectURIs[0]
	}
	if !c.allowsRedirect(redirectURI) {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}

	state := q.Get("state")
	fail := func(code, desc string) {
		s.redirectError(w, r, redirectURI, code, desc, state)
	}

	if rt := q.Get("response_type"); rt != "code" {
		fail("unsupported_response_type", "only the authorization code flow is supported")
		return
	}
	if !c.allowsGrant("authorization_code") {
		fail("unauthorized_client", "this client may not use the authorization code grant")
		return
	}

	// PKCE is mandatory for every client, public or confidential.
	challenge := q.Get("code_challenge")
	if challenge == "" {
		fail("invalid_request", "code_challenge is required")
		return
	}
	if method := q.Get("code_challenge_method"); method != "S256" {
		fail("invalid_request", "code_challenge_method must be S256")
		return
	}

	// RFC 8707: parse for validity, then ignore. Any syntactically valid
	// resource yields the one audience this gate protects, which is what 2.x
	// did — MCP clients disagree about the canonical form, and rejecting the
	// variants would break clients that work today.
	if res := q.Get("resource"); res != "" {
		if u, err := url.Parse(res); err != nil || !u.IsAbs() || u.Fragment != "" {
			fail("invalid_target", "resource must be an absolute URI without a fragment")
			return
		}
	}

	req := authRequest{
		ClientID:    c.ID,
		RedirectURI: redirectURI,
		State:       state,
		Scope:       strings.Join(s.grantableScopes(q.Get("scope")), " "),
		Challenge:   challenge,
		Nonce:       q.Get("nonce"),
	}
	id, err := randomID(16)
	if err != nil {
		fail("server_error", "could not start the authorization request")
		return
	}
	if err := s.store.put(modelAuthRequest, id, req, authRequestTTL); err != nil {
		fail("server_error", "could not persist the authorization request")
		return
	}
	http.Redirect(w, r, routeInteraction+id, http.StatusFound)
}

// grantableScopes intersects the request with what this AS grants. Unknown
// scopes are dropped rather than rejected, so a client asking for something
// extra still gets a usable token.
func (s *Server) grantableScopes(requested string) []string {
	var out []string
	for _, want := range strings.Fields(requested) {
		if slices.Contains(s.scopes, want) && !slices.Contains(out, want) {
			out = append(out, want)
		}
	}
	if len(out) == 0 {
		out = []string{s.scope}
	}
	return out
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, code, desc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// authCode is a single-use authorization code, bound to everything the token
// request must prove it knows.
type authCode struct {
	ClientID    string `json:"clientId"`
	RedirectURI string `json:"redirectUri"`
	Challenge   string `json:"codeChallenge"`
	Scope       string `json:"scope"`
	AccountID   string `json:"accountId"`
	Nonce       string `json:"nonce"`
	GrantID     string `json:"grantId"`
}

// handleInteraction is where the machine flow meets the human session. It
// replaces oidc-provider's interaction and consent machinery: with no consent
// object, a first-party grant is simply the presence of a live OIDC session.
func (s *Server) handleInteraction(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	var req authRequest
	if err := s.store.get(modelAuthRequest, uid, &req); err != nil {
		http.Error(w, "This authorization request has expired. Please start again.", http.StatusBadRequest)
		return
	}

	sub := s.humanSubject(r)
	if sub == "" {
		// Only an OIDC session identifies an account. Send the browser through
		// SSO and come back here.
		http.Redirect(w, r, "/nhl-auth/oidc/login?redirect="+
			url.QueryEscape(routeInteraction+uid), http.StatusFound)
		return
	}

	grantID, err := randomID(16)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	code, err := randomID(32)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := s.store.put(modelAuthCode, code, authCode{
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Challenge:   req.Challenge,
		Scope:       req.Scope,
		AccountID:   sub,
		Nonce:       req.Nonce,
		GrantID:     grantID,
	}, authCodeTTL); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_ = s.store.destroy(modelAuthRequest, uid)

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	// RFC 9207: advertised in discovery, so strict clients validate it.
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// humanSubject returns the OIDC subject of the browser's AppShield session, or
// "" when there is none. A password session has no subject and therefore
// cannot authorize an OAuth client.
func (s *Server) humanSubject(r *http.Request) string {
	c, err := r.Cookie(session.CookieName)
	if err != nil {
		return ""
	}
	sess, ok := s.sessions.Get(c.Value)
	if !ok {
		return ""
	}
	return sess.OIDCSub
}

// --- jwks / userinfo -----------------------------------------------------

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.key.PublicJWKS())
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.VerifyBearer(bearer(r))
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "the access token is not valid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sub": sub})
}

// VerifyBearer checks an access token minted by this broker.
//
// The scope is deliberately not enforced: the gate protects one resource and
// the token's audience already names it. This matches 2.x, where OAUTH_SCOPE
// was advertised and granted but never checked at the gate.
func (s *Server) VerifyBearer(token string) (string, bool) {
	if strings.Count(token, ".") != 2 {
		return "", false
	}
	_, payload, err := jose.Verify(token, s.pub)
	if err != nil {
		return "", false
	}
	var claims accessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if claims.Iss != s.issuer || claims.Aud != s.resource {
		return "", false
	}
	if claims.Exp <= s.now().Unix() {
		return "", false
	}
	return claims.Sub, true
}

// --- helpers -------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// verifyPKCE compares the verifier against the stored challenge.
func verifyPKCE(verifier, challenge string) error {
	if n := len(verifier); n < 43 || n > 128 {
		return errors.New("code_verifier must be 43-128 characters")
	}
	for _, r := range verifier {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
			r == '-' || r == '.' || r == '_' || r == '~') {
			return errors.New("code_verifier contains an invalid character")
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(b64u(sum[:])), []byte(challenge)) != 1 {
		return errors.New("code_verifier does not match the challenge")
	}
	return nil
}
