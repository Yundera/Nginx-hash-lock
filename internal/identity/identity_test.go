package identity

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testProp(secret string) *Propagator {
	return &Propagator{
		Enabled:  true,
		Secret:   []byte(secret),
		TTL:      60 * time.Second,
		Audience: "beacon",
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
}

func realIdentity() Identity {
	return Identity{
		Method: MethodOIDC,
		Sub:    "user-123",
		User:   "alice",
		Email:  "alice@example.com",
		Name:   "Alice Example",
		Groups: []string{"admins", "staff"},
	}
}

// Every managed header must be strippable, or it is spoofable.
func TestClearRemovesEveryManagedHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	for _, h := range Managed() {
		r.Header.Set(h, "attacker-supplied")
	}
	Clear(r)
	for _, h := range Managed() {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("%s survived Clear with value %q", h, v)
		}
	}
}

// This is the 2.x hole: X-AppShield-User and friends were emitted by the auth
// service but neither forwarded nor blanked by nginx, so a client could set
// them and have them reach the backend.
func TestSpoofedHeadersNeverReachTheBackend(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	spoofed := map[string]string{
		"Remote-User":           "admin",
		"Remote-Groups":         "root",
		"X-Forwarded-User":      "admin",
		"X-Auth-Request-User":   "admin",
		"X-AppShield-User":      "admin",
		"X-AppShield-Email":     "admin@evil.example",
		"X-AppShield-Name":      "Administrator",
		"X-AppShield-Groups":    "root",
		"X-AppShield-Sub":       "0",
		"X-AppShield-Method":    "oauth",
		"X-AppShield-Assertion": "forged.token.here",
	}
	for k, v := range spoofed {
		r.Header.Set(k, v)
	}

	testProp("s3cret").Apply(r, realIdentity())

	if got := r.Header.Get("Remote-User"); got != "alice" {
		t.Errorf("Remote-User = %q, want the gate's answer %q", got, "alice")
	}
	// Not emitted by the gate, so after Apply they must simply be gone.
	for _, h := range []string{"X-AppShield-User", "X-AppShield-Email", "X-AppShield-Name", "X-AppShield-Groups"} {
		if got := r.Header.Get(h); got != "" {
			t.Errorf("%s = %q, want it stripped (the gate never emits it)", h, got)
		}
	}
	if got := r.Header.Get("X-AppShield-Assertion"); got == spoofed["X-AppShield-Assertion"] {
		t.Error("forged assertion survived")
	}
}

// With forwarding off, nothing identity-shaped may reach the backend at all —
// including what the client sent.
func TestForwardingDisabledStillStrips(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Remote-User", "admin")
	r.Header.Set("X-AppShield-Method", "oidc")

	p := testProp("s3cret")
	p.Enabled = false
	p.Apply(r, realIdentity())

	for _, h := range Managed() {
		if v := r.Header.Get(h); v != "" {
			t.Errorf("%s = %q, want absent when IDENTITY_HEADERS is off", h, v)
		}
	}
}

func TestEmptyValuesAreOmittedNotBlank(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	// An OAuth machine identity carries only a method and a sub.
	testProp("").Apply(r, Identity{Method: MethodOAuth, Sub: "client-9"})

	if got := r.Header.Get("X-AppShield-Method"); got != "oauth" {
		t.Errorf("X-AppShield-Method = %q", got)
	}
	if got := r.Header.Get("X-AppShield-Sub"); got != "client-9" {
		t.Errorf("X-AppShield-Sub = %q", got)
	}
	for _, h := range []string{"Remote-User", "Remote-Email", "Remote-Name", "Remote-Groups"} {
		if _, present := r.Header[h]; present {
			t.Errorf("%s is present but should be absent for an identity with no such value", h)
		}
	}
}

func TestGroupsJoinedWithCommas(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	testProp("").Apply(r, realIdentity())
	for _, h := range []string{"Remote-Groups", "X-Forwarded-Groups", "X-Auth-Request-Groups"} {
		if got := r.Header.Get(h); got != "admins,staff" {
			t.Errorf("%s = %q, want %q", h, got, "admins,staff")
		}
	}
}

// A display name from an IdP is attacker-influenced in the general case.
func TestHeaderSafeStripsControlCharacters(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	testProp("").Apply(r, Identity{
		Method: MethodOIDC,
		User:   "ali\r\nX-Injected: yes",
		Name:   "Al\x00ice\x1b",
	})
	if got := r.Header.Get("Remote-User"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("Remote-User = %q still contains CR/LF", got)
	}
	if r.Header.Get("X-Injected") != "" {
		t.Error("header injection succeeded")
	}
	if got := r.Header.Get("Remote-Name"); got != "Alice" {
		t.Errorf("Remote-Name = %q, want control characters removed", got)
	}
}

func decodeClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAssertionClaims(t *testing.T) {
	p := testProp("s3cret")
	tok, err := p.MintAssertion(realIdentity())
	if err != nil {
		t.Fatal(err)
	}
	c := decodeClaims(t, tok)

	for k, want := range map[string]any{
		"iss":    "appshield",
		"aud":    "beacon",
		"sub":    "user-123",
		"method": "oidc",
		"user":   "alice",
		"email":  "alice@example.com",
		"name":   "Alice Example",
	} {
		if c[k] != want {
			t.Errorf("claim %s = %v, want %v", k, c[k], want)
		}
	}
	if c["iat"].(float64) != 1_700_000_000 {
		t.Errorf("iat = %v", c["iat"])
	}
	if c["exp"].(float64) != 1_700_000_060 {
		t.Errorf("exp = %v, want iat+TTL", c["exp"])
	}
}

// sub falls back through sub -> user -> method, so every identity has one.
func TestAssertionSubjectFallback(t *testing.T) {
	p := testProp("s3cret")
	for _, tc := range []struct {
		id   Identity
		want string
	}{
		{Identity{Method: MethodOIDC, Sub: "s", User: "u"}, "s"},
		{Identity{Method: MethodPassword, User: "u"}, "u"},
		{Identity{Method: MethodOAuth}, "oauth"},
	} {
		tok, err := p.MintAssertion(tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if got := decodeClaims(t, tok)["sub"]; got != tc.want {
			t.Errorf("sub = %v, want %v", got, tc.want)
		}
	}
}

func TestAssertionOmitsEmptyClaims(t *testing.T) {
	p := testProp("s3cret")
	tok, err := p.MintAssertion(Identity{Method: MethodOAuth, Sub: "client-9"})
	if err != nil {
		t.Fatal(err)
	}
	c := decodeClaims(t, tok)
	for _, k := range []string{"user", "email", "name", "groups"} {
		if _, present := c[k]; present {
			t.Errorf("claim %q should be omitted when empty", k)
		}
	}
}

func TestNoAssertionWithoutSecret(t *testing.T) {
	p := testProp("")
	if _, err := p.MintAssertion(realIdentity()); err == nil {
		t.Error("expected an error when no secret is configured")
	}
	r := httptest.NewRequest("GET", "/", nil)
	p.Apply(r, realIdentity())
	if r.Header.Get("X-AppShield-Assertion") != "" {
		t.Error("assertion emitted without a secret")
	}
	// The rest of the identity still goes through — no secret is not an outage.
	if r.Header.Get("Remote-User") != "alice" {
		t.Error("identity forwarding should still work without an assertion secret")
	}
}

// --- control token -------------------------------------------------------

func mintControl(t *testing.T, secret string, c ControlClaims) string {
	t.Helper()
	tok, err := sign([]byte(secret), c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func validControl() ControlClaims {
	return ControlClaims{
		Iss: controlIssuer,
		Aud: ControlAudience,
		Iat: 1_700_000_000,
		Exp: 1_700_000_060,
	}
}

func TestControlTokenAccepted(t *testing.T) {
	p := testProp("s3cret")
	if err := p.VerifyControlToken(mintControl(t, "s3cret", validControl())); err != nil {
		t.Errorf("valid control token rejected: %v", err)
	}
}

func TestControlTokenRejections(t *testing.T) {
	p := testProp("s3cret")

	tests := map[string]struct {
		secret string
		claims ControlClaims
	}{
		"wrong secret": {"other", validControl()},
		"wrong issuer": {"s3cret", ControlClaims{Iss: "someone-else", Aud: ControlAudience, Iat: 1_700_000_000, Exp: 1_700_000_060}},
		// The whole point of the audience split: an identity assertion, which
		// the backend receives on every request and may log, must not work here.
		"assertion audience": {"s3cret", ControlClaims{Iss: controlIssuer, Aud: "beacon", Iat: 1_700_000_000, Exp: 1_700_000_060}},
		"missing iat":        {"s3cret", ControlClaims{Iss: controlIssuer, Aud: ControlAudience, Exp: 1_700_000_060}},
		"missing exp":        {"s3cret", ControlClaims{Iss: controlIssuer, Aud: ControlAudience, Iat: 1_700_000_000}},
		"lifetime too long":  {"s3cret", ControlClaims{Iss: controlIssuer, Aud: ControlAudience, Iat: 1_700_000_000, Exp: 1_700_000_000 + 301}},
		"expired":            {"s3cret", ControlClaims{Iss: controlIssuer, Aud: ControlAudience, Iat: 1_699_999_000, Exp: 1_699_999_100}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := p.VerifyControlToken(mintControl(t, tc.secret, tc.claims)); err == nil {
				t.Error("expected rejection")
			}
		})
	}
}

// An "alg":"none" token with no signature must never be accepted.
func TestControlTokenRejectsAlgNone(t *testing.T) {
	payload, _ := json.Marshal(validControl())
	tok := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) +
		"." + base64.RawURLEncoding.EncodeToString(payload) + "."
	if err := testProp("s3cret").VerifyControlToken(tok); err == nil {
		t.Error("alg=none accepted")
	}
}

func TestControlTokenMalformed(t *testing.T) {
	p := testProp("s3cret")
	for _, tok := range []string{"", "a.b", "a.b.c.d", "!!!.???.###"} {
		if err := p.VerifyControlToken(tok); err == nil {
			t.Errorf("malformed token %q accepted", tok)
		}
	}
}

func TestControlTokenNeedsSecret(t *testing.T) {
	p := testProp("")
	if err := p.VerifyControlToken(mintControl(t, "s3cret", validControl())); err == nil {
		t.Error("expected an error when no secret is configured")
	}
}
