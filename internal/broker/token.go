package broker

import (
	"crypto/sha256"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yundera/appshield/internal/jose"
)

// accessTokenClaims is exactly the claim set oidc-provider's JWT format
// emitted: eight members, no more. `aud` is a JSON string rather than an array
// — oidc-provider rejected multi-valued audiences, so every token already in
// circulation has the scalar form and strict clients may depend on it.
type accessTokenClaims struct {
	Jti      string `json:"jti"`
	Sub      string `json:"sub"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
	Iss      string `json:"iss"`
	Aud      string `json:"aud"`
}

type idTokenClaims struct {
	Iss    string `json:"iss"`
	Sub    string `json:"sub"`
	Aud    string `json:"aud"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
	Nonce  string `json:"nonce,omitempty"`
	AtHash string `json:"at_hash,omitempty"`
}

// refreshToken is stored under the token's own value, which is how 2.x's
// opaque format worked. Field names match oidc-provider's payload so a token
// issued by the Node image can be refreshed by this one.
type refreshToken struct {
	ClientID  string `json:"clientId"`
	AccountID string `json:"accountId"`
	Scope     string `json:"scope"`
	GrantID   string `json:"grantId,omitempty"`
	GTY       string `json:"gty,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	// Iiat is the initial issue time, preserved across rotations so a grant
	// cannot be extended indefinitely.
	Iiat      int64  `json:"iiat,omitempty"`
	Rotations int    `json:"rotations,omitempty"`
	Consumed  int64  `json:"consumed,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	// Resource was a string in some 2.x records and an array in others; keep
	// it raw so neither shape fails to parse.
	Resource json.RawMessage `json:"resource,omitempty"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	c, err := s.authenticateClient(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="AppShield"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r, c)
	case "refresh_token":
		s.grantRefreshToken(w, r, c)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code and refresh_token are supported")
	}
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request, c *client) {
	// Claiming by rename makes the code single-use even under concurrent
	// redemption, which the Node implementation got free from its event loop.
	var code authCode
	if err := s.store.claim(modelAuthCode, r.PostFormValue("code"), &code); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is invalid or expired")
		return
	}
	if code.ClientID != c.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the code was issued to a different client")
		return
	}
	// The redirect_uri must match the one the code was bound to.
	if got := r.PostFormValue("redirect_uri"); got != code.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	if err := verifyPKCE(r.PostFormValue("code_verifier"), code.Challenge); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	scopes := strings.Fields(code.Scope)
	resp, err := s.issue(c, code.AccountID, scopes, code.Nonce, code.GrantID, true)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) grantRefreshToken(w http.ResponseWriter, r *http.Request, c *client) {
	presented := r.PostFormValue("refresh_token")

	var rt refreshToken
	if err := s.store.claim(modelRefreshToken, presented, &rt); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is invalid or expired")
		return
	}
	if rt.ClientID != c.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was issued to a different client")
		return
	}
	now := s.now()
	if rt.Exp != 0 && rt.Exp <= now.Unix() {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token has expired")
		return
	}

	if rt.Consumed != 0 {
		// A token presented after it was rotated away. Inside the grace window
		// this is a client retrying; beyond it, the token leaked and is being
		// replayed, so the whole grant goes.
		if now.Sub(time.Unix(rt.Consumed, 0)) > consumedGrace {
			if rt.GrantID != "" {
				n := s.store.revokeGrant(rt.GrantID)
				log.Printf("[oauth] refresh token reuse detected for client %s; revoked grant (%d token(s))", c.ID, n)
			}
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token has already been used")
			return
		}
	}

	scopes := strings.Fields(rt.Scope)
	rotate := s.shouldRotate(c, &rt, now)

	resp, err := s.issue(c, rt.AccountID, scopes, rt.Nonce, rt.GrantID, false)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}

	if rotate {
		next := rt
		next.Rotations++
		next.Iat = now.Unix()
		next.Exp = now.Add(refreshTokenTTL).Unix()
		next.Consumed = 0
		id, err := randomID(32)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not rotate the refresh token")
			return
		}
		if err := s.store.put(modelRefreshToken, id, next, refreshTokenTTL); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not rotate the refresh token")
			return
		}
		_ = s.store.addToGrant(next.GrantID, modelRefreshToken, id)
		resp.RefreshToken = id

		// Keep the predecessor, marked consumed, for the rest of its original
		// lifetime — not merely for the grace window. Inside the window a
		// replay is a client retry; outside it, the token leaked, and the
		// record has to still be here for reuse detection to fire. Letting it
		// expire at the end of the grace window would make a stolen token look
		// merely "expired" and leave the grant alive.
		rt.Consumed = now.Unix()
		_ = s.store.put(modelRefreshToken, presented, rt, remaining(rt.Exp, now))
	} else {
		// Not rotating: put the token back exactly as it was.
		_ = s.store.put(modelRefreshToken, presented, rt, remaining(rt.Exp, now))
		resp.RefreshToken = presented
	}

	writeJSON(w, http.StatusOK, resp)
}

// shouldRotate reproduces oidc-provider's default policy rather than a
// stricter one. The live client population has been exercising exactly this
// behaviour, and "improve it on day one" is how a cutover breaks clients that
// worked yesterday.
func (s *Server) shouldRotate(c *client, rt *refreshToken, now time.Time) bool {
	// Past the absolute ceiling a grant stops being extended at all.
	if rt.Iiat != 0 && now.Sub(time.Unix(rt.Iiat, 0)) > refreshAbsoluteMax {
		return false
	}
	// Public clients rotate on every use: they cannot keep a secret, so a
	// stolen token must stop working as soon as the real client refreshes.
	if c.isPublic() {
		return true
	}
	if rt.Iat == 0 || rt.Exp == 0 || rt.Exp <= rt.Iat {
		return false
	}
	life := rt.Exp - rt.Iat
	elapsed := now.Unix() - rt.Iat
	return float64(elapsed) > 0.7*float64(life)
}

// issue mints the access token, and optionally an id token and a refresh token.
func (s *Server) issue(c *client, accountID string, scopes []string, nonce, grantID string, withRefresh bool) (*tokenResponse, error) {
	now := s.now()
	jti, err := randomID(16)
	if err != nil {
		return nil, err
	}

	at, err := s.key.Sign("at+jwt", accessTokenClaims{
		Jti:      jti,
		Sub:      accountID,
		Iat:      now.Unix(),
		Exp:      now.Add(accessTokenTTL).Unix(),
		Scope:    strings.Join(scopes, " "),
		ClientID: c.ID,
		Iss:      s.issuer,
		Aud:      s.resource,
	})
	if err != nil {
		return nil, err
	}

	resp := &tokenResponse{
		AccessToken: at,
		TokenType:   "Bearer",
		ExpiresIn:   int64(accessTokenTTL / time.Second),
		Scope:       strings.Join(scopes, " "),
	}

	if contains(scopes, "openid") {
		sum := sha256.Sum256([]byte(at))
		idt, err := s.key.Sign("JWT", idTokenClaims{
			Iss:    s.issuer,
			Sub:    accountID,
			Aud:    c.ID,
			Iat:    now.Unix(),
			Exp:    now.Add(accessTokenTTL).Unix(),
			Nonce:  nonce,
			AtHash: b64u(sum[:len(sum)/2]),
		})
		if err != nil {
			return nil, err
		}
		resp.IDToken = idt
	}

	if withRefresh && c.wantsRefreshToken(scopes) {
		id, err := randomID(32)
		if err != nil {
			return nil, err
		}
		rt := refreshToken{
			ClientID:  c.ID,
			AccountID: accountID,
			Scope:     strings.Join(scopes, " "),
			GrantID:   grantID,
			GTY:       "authorization_code",
			Iat:       now.Unix(),
			Exp:       now.Add(refreshTokenTTL).Unix(),
			Iiat:      now.Unix(),
			Nonce:     nonce,
		}
		if err := s.store.put(modelRefreshToken, id, rt, refreshTokenTTL); err != nil {
			return nil, err
		}
		_ = s.store.addToGrant(grantID, modelRefreshToken, id)
		resp.RefreshToken = id
	}

	return resp, nil
}

// remaining is how long is left until exp, measured against the server's
// clock rather than the wall clock so tests can move time.
func remaining(exp int64, now time.Time) time.Duration {
	if exp == 0 {
		return refreshTokenTTL
	}
	if d := time.Unix(exp, 0).Sub(now); d > 0 {
		return d
	}
	return time.Second
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// --- revocation & introspection ------------------------------------------

// handleRevocation implements RFC 7009. Revoking a refresh token takes the
// whole grant with it, so the access tokens issued alongside stop being
// re-issuable.
func (s *Server) handleRevocation(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	c, err := s.authenticateClient(r)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	token := r.PostFormValue("token")
	var rt refreshToken
	if err := s.store.get(modelRefreshToken, token, &rt); err == nil && rt.ClientID == c.ID {
		if rt.GrantID != "" {
			s.store.revokeGrant(rt.GrantID)
		}
		_ = s.store.destroy(modelRefreshToken, token)
	}
	// RFC 7009: an unknown token is still a success, so a caller cannot probe
	// for valid tokens.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// handleIntrospection implements RFC 7662 for access tokens.
func (s *Server) handleIntrospection(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	if _, err := s.authenticateClient(r); err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	token := r.PostFormValue("token")
	inactive := map[string]any{"active": false}

	if strings.Count(token, ".") == 2 {
		if _, payload, err := jose.Verify(token, s.pub); err == nil {
			var claims accessTokenClaims
			if json.Unmarshal(payload, &claims) == nil &&
				claims.Iss == s.issuer && claims.Exp > s.now().Unix() {
				writeJSON(w, http.StatusOK, map[string]any{
					"active":     true,
					"sub":        claims.Sub,
					"scope":      claims.Scope,
					"client_id":  claims.ClientID,
					"exp":        claims.Exp,
					"iat":        claims.Iat,
					"aud":        claims.Aud,
					"iss":        claims.Iss,
					"jti":        claims.Jti,
					"token_type": "Bearer",
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, inactive)
		return
	}

	var rt refreshToken
	if err := s.store.get(modelRefreshToken, token, &rt); err == nil && rt.Consumed == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"active":     true,
			"sub":        rt.AccountID,
			"scope":      rt.Scope,
			"client_id":  rt.ClientID,
			"exp":        rt.Exp,
			"iat":        rt.Iat,
			"token_type": "refresh_token",
		})
		return
	}
	writeJSON(w, http.StatusOK, inactive)
}
