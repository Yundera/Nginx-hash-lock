package broker

import (
	"encoding/json"
	"net/http"

	"github.com/yundera/appshield/internal/session"
)

// registerAdminRoutes mounts the small operator UI for inspecting and revoking
// the clients that registered themselves. Every route requires a live human
// session on this app — the same session that gets you into the app itself.
func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+routeAdmin, s.requireHuman(s.handleAdminPage))
	mux.HandleFunc("GET "+routeAdmin+"/info", s.requireHuman(s.handleAdminInfo))
	mux.HandleFunc("GET "+routeAdmin+"/clients", s.requireHuman(s.handleListClients))
	mux.HandleFunc("POST "+routeAdmin+"/clients", s.requireHuman(s.handleCreateClient))
	mux.HandleFunc("DELETE "+routeAdmin+"/clients/{id}", s.requireHuman(s.handleDeleteClient))
}

// requireHuman gates on any live AppShield session, OIDC or password. Note
// this is weaker than what the interaction bridge requires: authorizing an
// OAuth client needs an OIDC subject, but merely looking at the client list
// only needs to be someone who can already use the app.
func (s *Server) requireHuman(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(session.CookieName)
		if err != nil {
			http.Redirect(w, r, "/login?redirect="+r.URL.EscapedPath(), http.StatusFound)
			return
		}
		sess, ok := s.sessions.Get(c.Value)
		if !ok || (sess.OIDCSub == "" && sess.PasswordHash == "") {
			http.Redirect(w, r, "/login?redirect="+r.URL.EscapedPath(), http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAdminInfo(w http.ResponseWriter, r *http.Request) {
	ids, _ := s.store.list(modelClient)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":   s.issuer,
		"resource": s.resource,
		"scope":    s.scope,
		"clients":  len(ids),
	})
}

type adminClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	AuthMethod   string   `json:"token_endpoint_auth_method"`
	IssuedAt     int64    `json:"client_id_issued_at,omitempty"`
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	ids, err := s.store.list(modelClient)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not list clients")
		return
	}
	out := make([]adminClient, 0, len(ids))
	for _, id := range ids {
		c, err := s.loadClient(id)
		if err != nil {
			continue
		}
		// Deliberately no client_secret: this list is rendered in a browser.
		out = append(out, adminClient{
			ClientID:     c.ID,
			ClientName:   c.ClientName,
			RedirectURIs: c.RedirectURIs,
			AuthMethod:   c.TokenEndpointAuthMethod,
			IssuedAt:     c.IssuedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

// handleCreateClient registers a client by hand, for tooling that cannot do
// Dynamic Client Registration itself.
func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
		return
	}
	// Same validation and defaults as DCR, so a hand-made client cannot be
	// looser than a self-registered one.
	s.handleRegisterWith(w, req)
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.loadClient(id); err != nil {
		writeOAuthError(w, http.StatusNotFound, "invalid_client", "unknown client")
		return
	}
	if err := s.store.destroy(modelClient, id); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not delete the client")
		return
	}
	// Tokens outlive the client record otherwise: an access token is
	// self-contained and would keep working until it expired.
	s.revokeClientTokens(id)
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// revokeClientTokens drops every refresh token belonging to a client.
func (s *Server) revokeClientTokens(clientID string) {
	ids, err := s.store.list(modelRefreshToken)
	if err != nil {
		return
	}
	for _, id := range ids {
		var rt refreshToken
		if err := s.store.get(modelRefreshToken, id, &rt); err != nil {
			continue
		}
		if rt.ClientID != clientID {
			continue
		}
		if rt.GrantID != "" {
			s.store.revokeGrant(rt.GrantID)
		}
		_ = s.store.destroy(modelRefreshToken, id)
	}
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(adminPage))
}

const adminPage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AppShield · OAuth clients</title><style>
:root{color-scheme:dark}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;
margin:0;padding:2rem;line-height:1.5}
main{max-width:60rem;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .25rem}
.sub{color:#94a3b8;margin:0 0 2rem;font-size:.9rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:.6rem .75rem;border-bottom:1px solid #1e293b;vertical-align:top}
th{color:#94a3b8;font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;color:#7dd3fc;
overflow-wrap:anywhere}
button{background:#7f1d1d;color:#fecaca;border:0;border-radius:6px;padding:.35rem .7rem;
cursor:pointer;font-size:.8rem}
button:hover{background:#991b1b}
.empty{color:#64748b;padding:2rem 0}
</style></head><body><main>
<h1>OAuth clients</h1>
<p class="sub" id="meta"></p>
<table><thead><tr><th>Name</th><th>Client ID</th><th>Redirect URIs</th><th>Auth</th><th></th></tr></thead>
<tbody id="rows"></tbody></table>
<p class="empty" id="empty" hidden>No clients have registered yet.</p>
<script>
const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function load() {
  const info = await (await fetch('/AppShield/oauth/info')).json();
  document.getElementById('meta').textContent =
    info.issuer + ' · protecting ' + info.resource + ' · scope "' + info.scope + '"';
  const { clients } = await (await fetch('/AppShield/oauth/clients')).json();
  document.getElementById('empty').hidden = clients.length > 0;
  document.getElementById('rows').innerHTML = clients.map(c =>
    '<tr><td>' + esc(c.client_name || '—') + '</td>' +
    '<td><code>' + esc(c.client_id) + '</code></td>' +
    '<td>' + c.redirect_uris.map(u => '<code>' + esc(u) + '</code>').join('<br>') + '</td>' +
    '<td>' + esc(c.token_endpoint_auth_method) + '</td>' +
    '<td><button data-id="' + esc(c.client_id) + '">Revoke</button></td></tr>').join('');
}
document.addEventListener('click', async e => {
  const id = e.target.dataset && e.target.dataset.id;
  if (!id) return;
  if (!confirm('Revoke ' + id + '? Its tokens stop working immediately.')) return;
  await fetch('/AppShield/oauth/clients/' + encodeURIComponent(id), { method: 'DELETE' });
  load();
});
load();
</script></main></body></html>`
