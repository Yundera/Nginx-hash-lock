package config

import (
	"strings"
	"testing"
	"time"
)

// env builds a getenv func from a map, so tests never touch the real
// environment and can run in parallel.
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

// base is the minimum that boots: upstream only, no auth.
func base(extra map[string]string) map[string]string {
	kv := map[string]string{
		"BACKEND_HOST": "whoami",
		"BACKEND_PORT": "80",
		"LISTEN_PORT":  "80",
	}
	for k, v := range extra {
		kv[k] = v
	}
	return kv
}

func load(t *testing.T, kv map[string]string) (*Config, []string) {
	t.Helper()
	c, w, err := Load(env(kv), "myapp")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c, w
}

func TestRequiredUpstreamValidation(t *testing.T) {
	for name, kv := range map[string]map[string]string{
		"missing host": {"BACKEND_PORT": "80", "LISTEN_PORT": "80"},
		"bad host":     {"BACKEND_HOST": "who ami", "BACKEND_PORT": "80", "LISTEN_PORT": "80"},
		"host slash":   {"BACKEND_HOST": "who/ami", "BACKEND_PORT": "80", "LISTEN_PORT": "80"},
		"port zero":    {"BACKEND_HOST": "whoami", "BACKEND_PORT": "0", "LISTEN_PORT": "80"},
		"port high":    {"BACKEND_HOST": "whoami", "BACKEND_PORT": "70000", "LISTEN_PORT": "80"},
		"port text":    {"BACKEND_HOST": "whoami", "BACKEND_PORT": "http", "LISTEN_PORT": "80"},
		"listen empty": {"BACKEND_HOST": "whoami", "BACKEND_PORT": "80"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Load(env(kv), "myapp"); err == nil {
				t.Fatal("expected boot to be refused")
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	c, _ := load(t, base(nil))

	if c.Buffering || c.RequestBuffering {
		t.Error("buffering must default off in both directions")
	}
	for _, d := range []time.Duration{c.ConnectTimeout, c.SendTimeout, c.ReadTimeout} {
		if d != 300*time.Second {
			t.Errorf("timeout = %v, want 300s", d)
		}
	}
	if c.MaxBodyBytes != 0 {
		t.Errorf("MaxBodyBytes = %d, want 0 (unlimited)", c.MaxBodyBytes)
	}
	if c.SessionDuration != 720*time.Hour {
		t.Errorf("SessionDuration = %v, want 720h", c.SessionDuration)
	}
	if c.SessionsFile != "/data/sessions.json" {
		t.Errorf("SessionsFile = %q", c.SessionsFile)
	}
	if !c.IdentityHeaders {
		t.Error("IDENTITY_HEADERS must default on")
	}
	if c.AssertionTTL != 60*time.Second {
		t.Errorf("AssertionTTL = %v, want 60s", c.AssertionTTL)
	}
	if c.OAuthScope != "access" || c.OAuthDataDir != "/data/oauth" {
		t.Errorf("OAuth defaults wrong: %q %q", c.OAuthScope, c.OAuthDataDir)
	}
	if c.Mode != AuthNone {
		t.Errorf("Mode = %q, want none", c.Mode)
	}
}

func TestModeDerivation(t *testing.T) {
	tests := []struct {
		name string
		kv   map[string]string
		want AuthMode
	}{
		{"nothing", nil, AuthNone},
		{"user only", map[string]string{"USER": "admin"}, AuthNone},
		{"password only", map[string]string{"PASSWORD": "pw"}, AuthNone},
		{"credentials", map[string]string{"USER": "admin", "PASSWORD": "pw"}, AuthCredentials},
		{"oidc", map[string]string{"OIDC_REGISTRAR_URL": "http://reg:9092"}, AuthOIDC},
		// OIDC wins outright — it does not compose with USER/PASSWORD.
		{"oidc beats credentials", map[string]string{
			"OIDC_REGISTRAR_URL": "http://reg:9092", "USER": "admin", "PASSWORD": "pw",
		}, AuthOIDC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := load(t, base(tc.kv))
			if c.Mode != tc.want {
				t.Errorf("Mode = %q, want %q", c.Mode, tc.want)
			}
		})
	}
}

func TestOIDCCredentialsCollisionWarns(t *testing.T) {
	_, warns := load(t, base(map[string]string{
		"OIDC_REGISTRAR_URL": "http://reg:9092", "USER": "admin", "PASSWORD": "pw",
	}))
	if !hasWarn(warns, "USER/PASSWORD are ignored") {
		t.Errorf("expected a warning about ignored credentials, got %v", warns)
	}
}

// The password hash must stay byte-identical to app.js:150 —
// sha256(PASSWORD + USERNAME) — or every persisted password session is
// invalidated on upgrade.
func TestPasswordHashMatchesNode(t *testing.T) {
	c, _ := load(t, base(map[string]string{"USER": "admin", "PASSWORD": "pw"}))
	const want = "5c496f9ce398c2b796a95184d6cb67c286b1747cacc64da3bc32a7adffa00cfd"
	if c.PasswordHash != want {
		t.Errorf("PasswordHash = %q, want %q (sha256 of PASSWORD+USERNAME)", c.PasswordHash, want)
	}
}

func TestRegistrarURLTrailingSlashesStripped(t *testing.T) {
	c, _ := load(t, base(map[string]string{"OIDC_REGISTRAR_URL": "http://reg:9092///"}))
	if c.RegistrarURL != "http://reg:9092" {
		t.Errorf("RegistrarURL = %q", c.RegistrarURL)
	}
}

func TestAppHostsAndCanonicalOrigin(t *testing.T) {
	c, _ := load(t, base(map[string]string{
		"APP_NAME":               "Beacon",
		"REDIRECT_HOST_SUFFIXES": "example.com, 1-2-3-4.nip.io",
	}))
	if c.AppName != "beacon" {
		t.Errorf("AppName = %q, want lowercased", c.AppName)
	}
	want := []string{"beacon-example.com", "beacon-1-2-3-4.nip.io"}
	if len(c.AppHosts) != 2 || c.AppHosts[0] != want[0] || c.AppHosts[1] != want[1] {
		t.Errorf("AppHosts = %v, want %v", c.AppHosts, want)
	}
	// Pinned to the FIRST host; this becomes the OAuth issuer.
	if c.CanonicalOrigin != "https://beacon-example.com" {
		t.Errorf("CanonicalOrigin = %q", c.CanonicalOrigin)
	}
}

func TestAppNameFallsBackToHostname(t *testing.T) {
	c, _, err := Load(env(base(map[string]string{"REDIRECT_HOST_SUFFIXES": "example.com"})), "MyApp")
	if err != nil {
		t.Fatal(err)
	}
	if c.AppName != "myapp" || c.CanonicalOrigin != "https://myapp-example.com" {
		t.Errorf("AppName=%q CanonicalOrigin=%q", c.AppName, c.CanonicalOrigin)
	}
}

func TestOAuthProtectedPath(t *testing.T) {
	tests := map[string]string{
		"https://beacon-x.example.com/mcp": "/mcp",
		"https://beacon-x.example.com/":    "/",
		"https://beacon-x.example.com":     "/",
		"https://a.example.com/deep/path":  "/deep/path",
	}
	for resource, want := range tests {
		t.Run(resource, func(t *testing.T) {
			c, _ := load(t, base(map[string]string{
				"OAUTH_RESOURCE":         resource,
				"APP_NAME":               "beacon",
				"REDIRECT_HOST_SUFFIXES": "x.example.com",
			}))
			if !c.OAuthEnabled {
				t.Fatal("OAuthEnabled = false")
			}
			if c.OAuthProtectedPath != want {
				t.Errorf("OAuthProtectedPath = %q, want %q", c.OAuthProtectedPath, want)
			}
		})
	}
}

func TestOAuthResourceAliasAndValidation(t *testing.T) {
	c, _ := load(t, base(map[string]string{"MCP_OAUTH_RESOURCE": "https://a.example.com/mcp"}))
	if !c.OAuthEnabled || c.OAuthResource != "https://a.example.com/mcp" {
		t.Errorf("MCP_OAUTH_RESOURCE alias not honoured: %+v", c.OAuthResource)
	}
	// OAUTH_RESOURCE wins over the alias.
	c, _ = load(t, base(map[string]string{
		"OAUTH_RESOURCE":     "https://real.example.com/mcp",
		"MCP_OAUTH_RESOURCE": "https://alias.example.com/mcp",
	}))
	if c.OAuthResource != "https://real.example.com/mcp" {
		t.Errorf("OAUTH_RESOURCE should win, got %q", c.OAuthResource)
	}
	if _, _, err := Load(env(base(map[string]string{"OAUTH_RESOURCE": "not-a-url"})), "myapp"); err == nil {
		t.Error("expected a relative OAUTH_RESOURCE to be refused")
	}
}

// A gate whose only protection was AUTH_HASH must refuse to boot rather than
// silently serving the backend to the internet.
func TestRemovedAuthRefusesToStartUnprotected(t *testing.T) {
	_, _, err := Load(env(base(map[string]string{"AUTH_HASH": "deadbeef"})), "myapp")
	if err == nil {
		t.Fatal("expected refusal to start when AUTH_HASH was the only auth")
	}
	if !strings.Contains(err.Error(), "refusing to start unprotected") {
		t.Errorf("unexpected error: %v", err)
	}

	_, _, err = Load(env(base(map[string]string{"CREDENTIAL_VALIDATE_URL": "http://bridge:8090/validate"})), "myapp")
	if err == nil {
		t.Fatal("expected refusal for CREDENTIAL_VALIDATE_URL as the only auth")
	}
}

// ...but a gate that also has OIDC just gets a warning. This is the real fleet
// case: 15 deployments set AUTH_HASH alongside OIDC_REGISTRAR_URL.
func TestRemovedAuthAlongsideOIDCOnlyWarns(t *testing.T) {
	c, warns := load(t, base(map[string]string{
		"AUTH_HASH":          "deadbeef",
		"AUTH_HASH_MODE":     "env",
		"OIDC_REGISTRAR_URL": "http://reg:9092",
	}))
	if c.Mode != AuthOIDC {
		t.Errorf("Mode = %q", c.Mode)
	}
	if !hasWarn(warns, "AUTH_HASH is set but ignored") {
		t.Errorf("expected AUTH_HASH warning, got %v", warns)
	}
	if !hasWarn(warns, "AUTH_HASH_MODE is set but ignored") {
		t.Errorf("expected AUTH_HASH_MODE warning, got %v", warns)
	}
}

func TestRemovedAuthWithOAuthBrokerBoots(t *testing.T) {
	if _, _, err := Load(env(base(map[string]string{
		"AUTH_HASH":              "deadbeef",
		"OAUTH_RESOURCE":         "https://beacon-x.example.com/mcp",
		"APP_NAME":               "beacon",
		"REDIRECT_HOST_SUFFIXES": "x.example.com",
	})), "myapp"); err != nil {
		t.Fatalf("broker counts as authentication, should boot: %v", err)
	}
}

func TestBypassPathsNormalised(t *testing.T) {
	c, _ := load(t, base(map[string]string{"ALLOWED_PATHS": " /api/ ,mcp, sse ,web/index.html"}))
	want := []string{"api", "mcp", "sse", "web/index.html"}
	if len(c.AllowedPaths) != len(want) {
		t.Fatalf("AllowedPaths = %v, want %v", c.AllowedPaths, want)
	}
	for i := range want {
		if c.AllowedPaths[i] != want[i] {
			t.Errorf("AllowedPaths[%d] = %q, want %q", i, c.AllowedPaths[i], want[i])
		}
	}
}

// Every ALLOWED_PATHS value in real production use must still parse.
func TestRealWorldBypassPaths(t *testing.T) {
	for _, v := range []string{
		"mcp", "mcp,sse,messages", "webhook", "web/index.html", "callback",
		"/api/", "api/app,build-info", "api/health,api/perf,api/bench,api/brand", "mcp,webhook",
	} {
		if _, err := bypassPaths(v); err != nil {
			t.Errorf("ALLOWED_PATHS=%q should be accepted: %v", v, err)
		}
	}
}

// In 2.x these compiled to a regex that outranked the gate's own routes.
func TestBypassPathsCannotShadowReservedRoutes(t *testing.T) {
	for _, v := range []string{"login", "health", "nhl-auth", "AppShield", "LOGIN", "nhl-auth/check", "/login/"} {
		if _, err := bypassPaths(v); err == nil {
			t.Errorf("ALLOWED_PATHS=%q must be rejected as shadowing a gate route", v)
		}
	}
}

func TestExtensionsNormalised(t *testing.T) {
	c, _ := load(t, base(map[string]string{"ALLOWED_EXTENSIONS": "JS, .css ,png"}))
	want := []string{"js", "css", "png"}
	for i := range want {
		if c.AllowedExtensions[i] != want[i] {
			t.Errorf("AllowedExtensions[%d] = %q, want %q", i, c.AllowedExtensions[i], want[i])
		}
	}
}

func TestAssertionTTLFloor(t *testing.T) {
	c, _ := load(t, base(map[string]string{"IDENTITY_ASSERTION_TTL_SECONDS": "1"}))
	if c.AssertionTTL != 5*time.Second {
		t.Errorf("AssertionTTL = %v, want the 5s floor", c.AssertionTTL)
	}
}

func TestIdentityHeadersOffValues(t *testing.T) {
	for _, v := range []string{"off", "OFF", "false", "0", "no"} {
		c, _ := load(t, base(map[string]string{"IDENTITY_HEADERS": v}))
		if c.IdentityHeaders {
			t.Errorf("IDENTITY_HEADERS=%q should disable forwarding", v)
		}
	}
	for _, v := range []string{"", "on", "true", "yes"} {
		c, _ := load(t, base(map[string]string{"IDENTITY_HEADERS": v}))
		if !c.IdentityHeaders {
			t.Errorf("IDENTITY_HEADERS=%q should keep forwarding on", v)
		}
	}
}

func TestDurationParsing(t *testing.T) {
	tests := map[string]time.Duration{
		"":      300 * time.Second,
		"300s":  300 * time.Second,
		"60":    60 * time.Second,
		"5m":    5 * time.Minute,
		"1h":    time.Hour,
		"500ms": 500 * time.Millisecond,
		"1d":    24 * time.Hour,
	}
	for in, want := range tests {
		got, err := duration(in, 300*time.Second)
		if err != nil || got != want {
			t.Errorf("duration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"soon", "-5s", "5y"} {
		if _, err := duration(bad, 0); err == nil {
			t.Errorf("duration(%q) should fail", bad)
		}
	}
}

func TestSizeParsing(t *testing.T) {
	tests := map[string]int64{
		"":     0,
		"0":    0,
		"1024": 1024,
		"10k":  10 << 10,
		"10M":  10 << 20,
		"1g":   1 << 30,
	}
	for in, want := range tests {
		got, err := size(in, 0)
		if err != nil || got != want {
			t.Errorf("size(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"big", "-1", "1t"} {
		if _, err := size(bad, 0); err == nil {
			t.Errorf("size(%q) should fail", bad)
		}
	}
}

func hasWarn(warns []string, substr string) bool {
	for _, w := range warns {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
