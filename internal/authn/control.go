package authn

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/yundera/appshield/internal/identity"
	"github.com/yundera/appshield/internal/session"
)

// revokeRequest is the control-API body. `except` accepts a bare string or an
// array, because the backend that calls this usually has exactly one session id
// to spare — its own caller's.
type revokeRequest struct {
	Sub    string          `json:"sub"`
	User   string          `json:"user"`
	All    bool            `json:"all"`
	Except json.RawMessage `json:"except"`
}

func (rr *revokeRequest) except() map[string]bool {
	out := map[string]bool{}
	if len(rr.Except) == 0 {
		return out
	}
	var one string
	if err := json.Unmarshal(rr.Except, &one); err == nil {
		if one != "" {
			out[one] = true
		}
		return out
	}
	var many []string
	if err := json.Unmarshal(rr.Except, &many); err == nil {
		for _, v := range many {
			if v != "" {
				out[v] = true
			}
		}
	}
	return out
}

// handleRevoke lets a backend end sessions it has decided are no longer valid —
// a deleted account, a password reset. Without it a 30-day session could not be
// withdrawn.
//
// Authentication is a short-lived HS256 token with aud=appshield-control. That
// audience is deliberately different from the identity assertion's: the gate
// hands a backend an assertion on every request and the backend may log it, so
// sharing an audience would turn a log line into a revocation credential.
func (g *Gate) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if g.Prop == nil || len(g.Prop.Secret) == 0 {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "IDENTITY_ASSERTION_SECRET is not configured",
		})
		return
	}

	tok := bearerToken(r)
	if tok == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return
	}
	if err := g.Prop.VerifyControlToken(tok); err != nil {
		log.Printf("[control] rejected revoke request: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	var req revokeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Sub == "" && req.User == "" && !req.All {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "one of sub, user or all is required",
		})
		return
	}

	spare := req.except()
	n := g.Sessions.Revoke(func(id string, sess *session.Session) bool {
		if spare[id] {
			return false
		}
		switch {
		case req.All:
			return true
		case req.Sub != "":
			if sess.OIDCSub == req.Sub {
				return true
			}
			return sess.Claims != nil && sess.Claims.Sub == req.Sub
		case req.User != "":
			return sess.Claims != nil && sess.Claims.User == req.User
		}
		return false
	})

	log.Printf("[control] revoked %d session(s)", n)
	// Zero is success: the API is idempotent, and reporting "not found" would
	// leak whether a given user has a session on this app.
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ControlAudience is re-exported so backends and tests share one constant.
const ControlAudience = identity.ControlAudience
