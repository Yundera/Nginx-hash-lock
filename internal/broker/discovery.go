package broker

import "net/http"

// handleDiscovery serves both the OpenID Connect discovery document and its
// RFC 8414 alias. They were identical in 2.x and remain so.
//
// One deliberate narrowing: 2.x left response_types unconfigured, so the
// provider's defaults applied and a substring test on "id_token" caused
// `implicit` to be advertised in grant_types_supported. Nothing used it, and
// OAuth 2.1 removes the implicit flow, so it is gone here.
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 s.issuer,
		"authorization_endpoint": s.issuer + routeAuth,
		"token_endpoint":         s.issuer + routeToken,
		"jwks_uri":               s.issuer + routeJWKS,
		"registration_endpoint":  s.issuer + routeRegister,
		"revocation_endpoint":    s.issuer + routeRevocation,
		"introspection_endpoint": s.issuer + routeIntrospect,
		"userinfo_endpoint":      s.issuer + routeUserinfo,
		"end_session_endpoint":   s.issuer + routeEndSession,

		"scopes_supported":                      s.scopes,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		// PKCE is mandatory, and S256 is the only method accepted.
		"code_challenge_methods_supported": []string{"S256"},
		"claims_supported":                 []string{"sub"},
		// RFC 9207. Advertised because handleInteraction always sets `iss` on
		// the authorization response; strict clients validate it when it is.
		"authorization_response_iss_parameter_supported": true,
		"resource_indicators_supported":                  true,
	})
}

// handleProtectedResource is the RFC 9728 document an MCP client fetches after
// a 401, to learn which authorization server guards this resource. It is the
// entry point of the whole discovery → registration → authorization sequence.
func (s *Server) handleProtectedResource(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"scopes_supported":         []string{s.scope},
		"bearer_methods_supported": []string{"header"},
	})
}
