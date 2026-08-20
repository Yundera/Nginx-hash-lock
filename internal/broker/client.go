package broker

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// client is the subset of an OAuth client this broker needs.
//
// It is read leniently and never rewritten: a document created by the 2.x
// oidc-provider carries members this implementation does not model, and
// preserving them keeps a rollback to the Node image clean.
type client struct {
	ID                      string   `json:"client_id"`
	Secret                  string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	IssuedAt                int64    `json:"client_id_issued_at,omitempty"`
}

func (c *client) isPublic() bool { return c.TokenEndpointAuthMethod == "none" }

func (c *client) allowsGrant(g string) bool {
	if len(c.GrantTypes) == 0 {
		return g == "authorization_code"
	}
	return slices.Contains(c.GrantTypes, g)
}

// allowsRedirect requires an exact string match. No prefix or wildcard
// matching: a loose comparison here is how authorization codes get stolen.
func (c *client) allowsRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if subtle.ConstantTimeCompare([]byte(u), []byte(uri)) == 1 {
			return true
		}
	}
	return false
}

// wantsRefreshToken decides whether this grant gets a refresh token.
//
// This reproduces oidc-provider's default issueRefreshToken exactly
// (node_modules/oidc-provider/lib/helpers/defaults.js:2919-2925): the client
// must allow the refresh_token grant, and then either offline_access was
// granted or the client is a public web client.
//
// The second half is the one that matters. DCR defaults application_type to
// "web", so a public MCP client that never asked for offline_access has still
// been receiving refresh tokens. Keying only off the scope would break those
// connectors an hour after cutover — the failure that looks like "it keeps
// asking me to log in".
func (c *client) wantsRefreshToken(scopes []string) bool {
	if !c.allowsGrant("refresh_token") {
		return false
	}
	if slices.Contains(scopes, "offline_access") {
		return true
	}
	return c.applicationType() == "web" && c.isPublic()
}

func (c *client) applicationType() string {
	if c.ApplicationType == "" {
		return "web"
	}
	return c.ApplicationType
}

func (s *Server) loadClient(id string) (*client, error) {
	var c client
	if err := s.store.get(modelClient, id, &c); err != nil {
		return nil, err
	}
	if c.ID == "" {
		c.ID = id
	}
	return &c, nil
}

// authenticateClient resolves and authenticates the client on a token request.
// It accepts HTTP Basic, client_secret_post, and public clients ("none").
func (s *Server) authenticateClient(r *http.Request) (*client, error) {
	id, secret, hasBasic := basicAuth(r)
	if !hasBasic {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id == "" {
		return nil, errors.New("no client_id")
	}
	c, err := s.loadClient(id)
	if err != nil {
		return nil, errors.New("unknown client")
	}
	if c.isPublic() {
		return c, nil
	}
	if c.Secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		return nil, errors.New("bad client credentials")
	}
	return c, nil
}

// basicAuth decodes HTTP Basic, form-urldecoding both halves as RFC 6749
// §2.3.1 requires. Skipping the decode breaks any client whose secret contains
// a character that had to be escaped.
func basicAuth(r *http.Request) (id, secret string, ok bool) {
	rawID, rawSecret, ok := r.BasicAuth()
	if !ok {
		return "", "", false
	}
	decID, err := url.QueryUnescape(rawID)
	if err != nil {
		decID = rawID
	}
	decSecret, err := url.QueryUnescape(rawSecret)
	if err != nil {
		decSecret = rawSecret
	}
	return decID, decSecret, true
}

// --- dynamic client registration (RFC 7591) ------------------------------

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type"`
	Scope                   string   `json:"scope"`
}

type registrationResponse struct {
	client
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// handleRegister implements open, unauthenticated Dynamic Client Registration.
// It is deliberately open: MCP clients discover the endpoint through RFC 9728
// and register themselves with no operator involvement, which is the whole
// point of the broker.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
		return
	}
	s.handleRegisterWith(w, req)
}

// handleRegisterWith is the shared body of self-service DCR and the admin
// create endpoint, so a hand-made client can never be looser than one that
// registered itself.
func (s *Server) handleRegisterWith(w http.ResponseWriter, req registrationRequest) {
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}

	appType := req.ApplicationType
	if appType == "" {
		appType = "web"
	}
	for _, raw := range req.RedirectURIs {
		if err := validateRedirectURI(raw, appType); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	authMethod := "client_secret_basic"
	if req.TokenEndpointAuthMethod != nil {
		authMethod = *req.TokenEndpointAuthMethod
	}
	switch authMethod {
	case "client_secret_basic", "client_secret_post", "none":
	default:
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
			fmt.Sprintf("unsupported token_endpoint_auth_method %q", authMethod))
		return
	}

	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	for _, g := range grants {
		if g != "authorization_code" && g != "refresh_token" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
				fmt.Sprintf("unsupported grant_type %q", g))
			return
		}
	}
	responses := req.ResponseTypes
	if len(responses) == 0 {
		responses = []string{"code"}
	}
	for _, rt := range responses {
		if rt != "code" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
				fmt.Sprintf("unsupported response_type %q", rt))
			return
		}
	}

	id, err := randomID(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not allocate a client id")
		return
	}
	c := client{
		ID:                      id,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grants,
		ResponseTypes:           responses,
		TokenEndpointAuthMethod: authMethod,
		ApplicationType:         appType,
		ClientName:              req.ClientName,
		Scope:                   req.Scope,
		IssuedAt:                s.now().Unix(),
	}
	if authMethod != "none" {
		secret, err := randomID(32)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not allocate a client secret")
			return
		}
		c.Secret = secret
	}

	// Clients never expire, so no TTL.
	if err := s.store.put(modelClient, c.ID, c, 0); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not persist the client")
		return
	}

	resp := registrationResponse{client: c, ClientSecretExpiresAt: 0}
	// RFC 7592 credentials. 2.x issued these by default, and a client that
	// stores them will try to use them.
	if rat, err := randomID(32); err == nil {
		if err := s.store.put(modelRegistrationT, rat, map[string]string{"clientId": c.ID}, 0); err == nil {
			resp.RegistrationAccessToken = rat
			resp.RegistrationClientURI = s.issuer + routeRegister + "/" + c.ID
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated) // 201, as 2.x returned
	_ = json.NewEncoder(w).Encode(resp)
}

// handleReadClient is the RFC 7592 read endpoint. 2.x mounted read but not
// update or delete, so this matches.
func (s *Server) handleReadClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tok := bearer(r)
	if tok == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "a registration access token is required")
		return
	}
	var rec struct {
		ClientID string `json:"clientId"`
	}
	if err := s.store.get(modelRegistrationT, tok, &rec); err != nil || rec.ClientID != id {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "unknown registration access token")
		return
	}
	c, err := s.loadClient(id)
	if err != nil {
		writeOAuthError(w, http.StatusNotFound, "invalid_client", "unknown client")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(registrationResponse{client: *c, ClientSecretExpiresAt: 0})
}

// validateRedirectURI mirrors oidc-provider's rules for web clients: https
// anywhere, http only on loopback. MCP Inspector and other local tooling
// depend on the loopback exception.
func validateRedirectURI(raw, appType string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a URI", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("redirect_uri %q must not contain a fragment", raw)
	}
	if !u.IsAbs() {
		return fmt.Errorf("redirect_uri %q must be absolute", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("redirect_uri %q may only use http on a loopback address", raw)
	default:
		// Native clients register custom schemes; web clients do not.
		if appType == "native" {
			return nil
		}
		return fmt.Errorf("redirect_uri %q must use https", raw)
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}
