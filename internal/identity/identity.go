// Package identity tells the backend who the gate let in.
//
// The security rule, inherited from 2.x and tightened here: every header in
// this package's managed set is overwritten on EVERY route, including the
// unauthenticated bypasses. A client-supplied `Remote-User: admin` must never
// reach a backend that trusts proxy-set identity. Turning forwarding on must
// not create a spoofing hole, and turning it off must not leave one.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Authentication methods. 2.x also had "hash"; AUTH_HASH was removed in 3.0.
const (
	MethodOIDC     = "oidc"
	MethodPassword = "password"
	MethodOAuth    = "oauth"
)

// Identity is the gate's answer for one request.
type Identity struct {
	Method string
	Sub    string
	User   string
	Email  string
	Name   string
	Groups []string
}

// emitted maps each forwarded header to the field it carries. This is the
// single source of truth: the clear list below is derived from it, so the two
// can never drift apart. In 2.x they were three hand-maintained lists in
// entrypoint.sh, and X-AppShield-User/-Email/-Name/-Groups fell through the
// gap — emitted by the auth service, neither forwarded nor blanked by nginx,
// so a client could set them and have them reach the backend untouched.
var emitted = []struct {
	header string
	value  func(Identity) string
}{
	// Authelia / Traefik forward-auth convention
	{"Remote-User", func(i Identity) string { return i.User }},
	{"Remote-Name", func(i Identity) string { return i.Name }},
	{"Remote-Email", func(i Identity) string { return i.Email }},
	{"Remote-Groups", func(i Identity) string { return i.groups() }},
	// oauth2-proxy / generic nginx auth_request convention
	{"X-Forwarded-User", func(i Identity) string { return i.User }},
	{"X-Forwarded-Email", func(i Identity) string { return i.Email }},
	{"X-Forwarded-Groups", func(i Identity) string { return i.groups() }},
	{"X-Forwarded-Preferred-Username", func(i Identity) string { return i.User }},
	{"X-Auth-Request-User", func(i Identity) string { return i.User }},
	{"X-Auth-Request-Email", func(i Identity) string { return i.Email }},
	{"X-Auth-Request-Groups", func(i Identity) string { return i.groups() }},
	{"X-Auth-Request-Preferred-Username", func(i Identity) string { return i.User }},
	// No convention exists for these
	{"X-AppShield-Method", func(i Identity) string { return i.Method }},
	{"X-AppShield-Sub", func(i Identity) string { return i.Sub }},
}

// alsoCleared are headers the gate does not emit but must still strip, because
// a backend might read them and a client might send them. 2.x left exactly
// these four spoofable.
var alsoCleared = []string{
	"X-AppShield-User",
	"X-AppShield-Email",
	"X-AppShield-Name",
	"X-AppShield-Groups",
	"X-AppShield-Assertion",
}

func (i Identity) groups() string { return strings.Join(i.Groups, ",") }

// Managed lists every header this package controls. Exported for tests that
// assert clear/emit symmetry.
func Managed() []string {
	out := make([]string, 0, len(emitted)+len(alsoCleared))
	for _, e := range emitted {
		out = append(out, e.header)
	}
	return append(out, alsoCleared...)
}

// Propagator applies identity to outbound requests.
type Propagator struct {
	Enabled  bool
	Secret   []byte
	TTL      time.Duration
	Audience string // APP_NAME, or "appshield" when unset
	Now      func() time.Time
}

// Clear strips every managed header. Called on every route, authenticated or
// not, before anything is added back.
func Clear(r *http.Request) {
	for _, h := range Managed() {
		r.Header.Del(h)
	}
}

// Apply clears the managed headers and, when forwarding is enabled, sets the
// ones this identity has values for. An empty value means the header is absent
// rather than present-and-empty, matching nginx's behaviour of dropping a
// header whose proxy_set_header value is "".
func (p *Propagator) Apply(r *http.Request, id Identity) {
	Clear(r)
	if !p.Enabled || id.Method == "" {
		return
	}
	for _, e := range emitted {
		if v := headerSafe(e.value(id)); v != "" {
			r.Header.Set(e.header, v)
		}
	}
	if len(p.Secret) == 0 {
		return
	}
	tok, err := p.MintAssertion(id)
	if err != nil {
		// An assertion we cannot mint must not become an outage; the request
		// still goes through with unsigned headers.
		return
	}
	r.Header.Set("X-AppShield-Assertion", tok)
}

// headerSafe strips CR, LF, NUL and other C0/C1 control characters, which
// would otherwise allow header injection through a display name coming from
// the IdP. Go writes UTF-8 header bytes directly, so unlike Node no latin1
// round-trip is needed.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// --- assertion JWT -------------------------------------------------------
//
// HS256 by hand. One algorithm, one key, ~40 lines — a JOSE library would be
// the largest dependency in the binary for no benefit.

const (
	assertionIssuer = "appshield"
	controlIssuer   = "appshield-backend"
	// ControlAudience is deliberately different from the assertion audience.
	// The gate hands a backend an assertion on every request and the backend
	// may well log it; if the two shared an audience, a logged assertion would
	// double as a session-revocation credential.
	ControlAudience = "appshield-control"
	// controlMaxLifetime caps how long a control token may be valid for.
	controlMaxLifetime = 300 * time.Second
)

type assertionClaims struct {
	Method string   `json:"method"`
	User   string   `json:"user,omitempty"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Iss    string   `json:"iss"`
	Aud    string   `json:"aud"`
	Sub    string   `json:"sub"`
	Iat    int64    `json:"iat"`
	Exp    int64    `json:"exp"`
}

func (p *Propagator) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// MintAssertion produces the X-AppShield-Assertion JWT. It is minted fresh per
// request and never stored: it is a transport of the gate's current answer,
// not a session token.
func (p *Propagator) MintAssertion(id Identity) (string, error) {
	if len(p.Secret) == 0 {
		return "", errors.New("no assertion secret configured")
	}
	iat := p.now().Unix()
	aud := p.Audience
	if aud == "" {
		aud = assertionIssuer
	}
	sub := id.Sub
	if sub == "" {
		sub = id.User
	}
	if sub == "" {
		sub = id.Method
	}
	return sign(p.Secret, assertionClaims{
		Method: headerSafe(id.Method),
		User:   headerSafe(id.User),
		Email:  headerSafe(id.Email),
		Name:   headerSafe(id.Name),
		Groups: id.Groups,
		Iss:    assertionIssuer,
		Aud:    aud,
		Sub:    headerSafe(sub),
		Iat:    iat,
		Exp:    iat + int64(p.TTL/time.Second),
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(secret []byte, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	// Header is fixed, so it can be a constant rather than another marshal.
	const header = `{"alg":"HS256","typ":"JWT"}`
	signingInput := b64([]byte(header)) + "." + b64(payload)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(signingInput))
	return signingInput + "." + b64(m.Sum(nil)), nil
}

// ControlClaims is the token a backend presents to the session-revocation API.
type ControlClaims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// VerifyControlToken checks a control-API bearer token. Every check here is
// load-bearing: the alg pin stops an "alg":"none" downgrade, and the lifetime
// cap bounds the damage from a leaked token.
func (p *Propagator) VerifyControlToken(tok string) error {
	if len(p.Secret) == 0 {
		return errors.New("no assertion secret configured")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return errors.New("malformed token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("malformed header")
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return errors.New("malformed header")
	}
	// Pin the algorithm explicitly rather than trusting the token to name it.
	if hdr.Alg != "HS256" {
		return fmt.Errorf("unsupported alg %q", hdr.Alg)
	}

	m := hmac.New(sha256.New, p.Secret)
	m.Write([]byte(parts[0] + "." + parts[1]))
	want := m.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("malformed signature")
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errors.New("bad signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("malformed payload")
	}
	var c ControlClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return errors.New("malformed payload")
	}
	if c.Iss != controlIssuer {
		return fmt.Errorf("unexpected issuer %q", c.Iss)
	}
	if c.Aud != ControlAudience {
		return fmt.Errorf("unexpected audience %q", c.Aud)
	}
	if c.Iat == 0 || c.Exp == 0 {
		return errors.New("iat and exp are required")
	}
	if c.Exp-c.Iat > int64(controlMaxLifetime/time.Second) {
		return fmt.Errorf("token lifetime exceeds the %s cap", controlMaxLifetime)
	}
	now := p.now().Unix()
	if now >= c.Exp {
		return errors.New("token expired")
	}
	// Small tolerance for clock skew between gate and backend containers.
	if now < c.Iat-30 {
		return errors.New("token not yet valid")
	}
	return nil
}

// SignControlToken mints a control-API token. The gate itself never needs
// this — backends mint their own — but it keeps the claim shape in one place
// and lets tests and any future SDK build a valid token without duplicating it.
func (p *Propagator) SignControlToken(c ControlClaims) (string, error) {
	if len(p.Secret) == 0 {
		return "", errors.New("no assertion secret configured")
	}
	if c.Iss == "" {
		c.Iss = controlIssuer
	}
	if c.Aud == "" {
		c.Aud = ControlAudience
	}
	return sign(p.Secret, c)
}
