// Package config turns the process environment into a validated, immutable
// Config. It replaces the ~570 lines of sed in the 2.x entrypoint.sh: same
// variable names, same defaults, same refuse-to-start checks, but resolved once
// in one place instead of being smeared across shell and nginx templating.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AuthMode is how the gate decides who gets in. AUTH_HASH was removed in 3.0,
// which takes the 2.x "hash_only" and "both" modes with it.
type AuthMode string

const (
	AuthNone        AuthMode = "none"
	AuthCredentials AuthMode = "credentials_only"
	AuthOIDC        AuthMode = "oidc_only"
)

// Paths the gate serves itself. A bypass rule may never shadow one of these:
// in 2.x an ALLOWED_PATHS entry compiled to a regex that outranked the plain
// prefix locations, so ALLOWED_PATHS=login silently sent the login page to the
// backend. 3.0 rejects that at boot instead of misrouting at request time.
var reservedPaths = []string{"health", "login", "nhl-auth", "AppShield"}

// Matches nginx's own hostname validation from entrypoint.sh:19-22.
var backendHostRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// Config is fully derived at boot and never mutated afterwards, with the single
// documented exception of the OIDC relying party's allowed-origin set, which the
// registrar may replace on first registration (see internal/oidcrp).
type Config struct {
	// Upstream
	BackendHost string
	BackendPort int
	ListenPort  int

	// Proxy tuning. Buffering defaults off in both directions: 2.x chose
	// compatibility (SSE, long-poll, websockets) over throughput.
	Buffering        bool
	RequestBuffering bool
	ConnectTimeout   time.Duration
	SendTimeout      time.Duration
	ReadTimeout      time.Duration
	MaxBodyBytes     int64 // 0 = unlimited

	// Authentication
	Mode            AuthMode
	Username        string
	Password        string
	PasswordHash    string // sha256(PASSWORD + USERNAME), matches app.js:150
	SessionDuration time.Duration
	SessionsFile    string

	// OIDC relying party
	RegistrarURL         string
	RequiredGroups       []string
	AppName              string
	RedirectHostSuffixes []string
	AppHosts             []string
	AllowedOrigins       []string
	// CanonicalOrigin is PINNED to the first app host and never re-derived from
	// registrar output. When the broker is enabled this becomes the OAuth
	// issuer, baked into every token already signed and every discovery
	// document a remote client has cached. Moving it invalidates all of them.
	CanonicalOrigin string

	// Identity propagation
	IdentityHeaders bool
	AssertionSecret string
	AssertionTTL    time.Duration

	// OAuth 2.1 broker
	OAuthEnabled       bool
	OAuthResource      string
	OAuthScope         string
	OAuthDataDir       string
	OAuthProtectedPath string
	OAuthLegacySweep   bool

	// Unauthenticated bypasses
	AllowedPaths          []string
	AllowedExtensions     []string
	AllowHashContentPaths bool

	Debug bool
}

// Load reads and validates configuration. getenv and hostname are injected so
// the whole thing is testable without touching the real environment.
//
// It returns warnings (printed at boot, non-fatal) separately from the error
// that refuses the boot outright.
func Load(getenv func(string) string, hostname string) (*Config, []string, error) {
	var warns []string
	c := &Config{}

	// --- upstream, validated before anything else uses these values ---
	c.BackendHost = strings.TrimSpace(getenv("BACKEND_HOST"))
	if !backendHostRe.MatchString(c.BackendHost) {
		return nil, nil, fmt.Errorf("BACKEND_HOST %q is not a valid hostname (allowed: A-Z a-z 0-9 . _ -)", c.BackendHost)
	}
	var err error
	if c.BackendPort, err = port(getenv, "BACKEND_PORT"); err != nil {
		return nil, nil, err
	}
	if c.ListenPort, err = port(getenv, "LISTEN_PORT"); err != nil {
		return nil, nil, err
	}

	// --- proxy tuning ---
	c.Buffering = onOff(getenv("PROXY_BUFFERING"), false)
	c.RequestBuffering = onOff(getenv("PROXY_REQUEST_BUFFERING"), false)
	for _, t := range []struct {
		key string
		dst *time.Duration
	}{
		{"PROXY_CONNECT_TIMEOUT", &c.ConnectTimeout},
		{"PROXY_SEND_TIMEOUT", &c.SendTimeout},
		{"PROXY_READ_TIMEOUT", &c.ReadTimeout},
	} {
		d, err := duration(getenv(t.key), 300*time.Second)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", t.key, err)
		}
		*t.dst = d
	}
	if c.MaxBodyBytes, err = size(getenv("CLIENT_MAX_BODY_SIZE"), 0); err != nil {
		return nil, nil, fmt.Errorf("CLIENT_MAX_BODY_SIZE: %w", err)
	}

	// --- credentials ---
	c.Username = getenv("USER")
	c.Password = getenv("PASSWORD")
	sum := sha256.Sum256([]byte(c.Password + c.Username))
	c.PasswordHash = hex.EncodeToString(sum[:])

	hours, err := positiveFloat(getenv("SESSION_DURATION_HOURS"), 720)
	if err != nil {
		return nil, nil, fmt.Errorf("SESSION_DURATION_HOURS: %w", err)
	}
	c.SessionDuration = time.Duration(hours * float64(time.Hour))
	c.SessionsFile = def(getenv("SESSIONS_FILE"), "/data/sessions.json")

	// --- OIDC relying party ---
	c.RegistrarURL = strings.TrimRight(strings.TrimSpace(getenv("OIDC_REGISTRAR_URL")), "/")
	c.RequiredGroups = csv(getenv("OIDC_REQUIRED_GROUPS"), false)
	c.AppName = strings.ToLower(def(getenv("APP_NAME"), hostname))
	c.RedirectHostSuffixes = csv(getenv("REDIRECT_HOST_SUFFIXES"), true)
	if c.AppName != "" {
		for _, s := range c.RedirectHostSuffixes {
			c.AppHosts = append(c.AppHosts, strings.ToLower(c.AppName+"-"+s))
		}
	}
	for _, h := range c.AppHosts {
		c.AllowedOrigins = append(c.AllowedOrigins, "https://"+h)
	}
	if len(c.AppHosts) > 0 {
		c.CanonicalOrigin = "https://" + c.AppHosts[0]
	}

	// --- identity propagation ---
	c.IdentityHeaders = onOff(getenv("IDENTITY_HEADERS"), true)
	c.AssertionSecret = strings.TrimSpace(getenv("IDENTITY_ASSERTION_SECRET"))
	ttl, err := positiveFloat(getenv("IDENTITY_ASSERTION_TTL_SECONDS"), 60)
	if err != nil {
		return nil, nil, fmt.Errorf("IDENTITY_ASSERTION_TTL_SECONDS: %w", err)
	}
	if ttl < 5 { // floor, matching app.js:53-56
		ttl = 5
	}
	c.AssertionTTL = time.Duration(ttl * float64(time.Second))

	// --- OAuth broker. MCP_OAUTH_RESOURCE is a back-compat alias only. ---
	c.OAuthResource = strings.TrimSpace(def(getenv("OAUTH_RESOURCE"), getenv("MCP_OAUTH_RESOURCE")))
	c.OAuthEnabled = c.OAuthResource != ""
	c.OAuthScope = def(getenv("OAUTH_SCOPE"), "access")
	c.OAuthDataDir = def(getenv("OAUTH_DATA_DIR"), "/data/oauth")
	c.OAuthLegacySweep = truthy(getenv("OAUTH_LEGACY_SWEEP"))
	c.OAuthProtectedPath = "/"
	if c.OAuthEnabled {
		u, err := url.Parse(c.OAuthResource)
		if err != nil || !u.IsAbs() {
			return nil, nil, fmt.Errorf("OAUTH_RESOURCE %q must be an absolute URL", c.OAuthResource)
		}
		if u.Path != "" {
			c.OAuthProtectedPath = u.Path
		}
		// 2.x derived this path twice — once in shell by stripping scheme://host
		// with sed, once in JS via new URL().pathname — and the two could
		// disagree. One derivation now, so they cannot.
		if c.CanonicalOrigin == "" {
			warns = append(warns, "OAUTH_RESOURCE is set but no APP_NAME/REDIRECT_HOST_SUFFIXES could be resolved; "+
				"falling back to the resource origin as the OAuth issuer")
			c.CanonicalOrigin = u.Scheme + "://" + u.Host
		}
	}

	// --- unauthenticated bypasses ---
	if c.AllowedPaths, err = bypassPaths(getenv("ALLOWED_PATHS")); err != nil {
		return nil, nil, err
	}
	c.AllowedExtensions = extensions(getenv("ALLOWED_EXTENSIONS"))
	c.AllowHashContentPaths = truthy(getenv("ALLOW_HASH_CONTENT_PATHS"))

	c.Debug = truthy(getenv("DEBUG"))

	// --- mode derivation. OIDC wins outright; it does not compose with
	// USER/PASSWORD, matching entrypoint.sh:129-138. ---
	switch {
	case c.RegistrarURL != "":
		c.Mode = AuthOIDC
		if c.Username != "" && c.Password != "" {
			warns = append(warns, "USER/PASSWORD are ignored: OIDC_REGISTRAR_URL selects OIDC mode")
		}
	case c.Username != "" && c.Password != "":
		c.Mode = AuthCredentials
	default:
		c.Mode = AuthNone
	}

	// --- removed settings. Each warns; each refuses the boot if it was the
	// only thing standing between the backend and the internet. ---
	removed := []struct {
		key, note string
	}{
		{"AUTH_HASH", "removed in 3.0; machine access is now the OAuth 2.1 broker (OAUTH_RESOURCE)"},
		{"AUTH_HASH_MODE", "removed in 3.0 along with AUTH_HASH"},
		{"AUTH_HASH_FILE", "removed in 3.0 along with AUTH_HASH"},
		{"CREDENTIAL_VALIDATE_URL", "removed in 2.0.8; the CasaOS bridge it delegated to is retired"},
		{"CREDENTIAL_CACHE_TTL_SECONDS", "removed in 2.0.8"},
	}
	sawRemovedAuth := false
	for _, r := range removed {
		if strings.TrimSpace(getenv(r.key)) == "" {
			continue
		}
		warns = append(warns, fmt.Sprintf("%s is set but ignored — %s", r.key, r.note))
		if r.key == "AUTH_HASH" || r.key == "CREDENTIAL_VALIDATE_URL" {
			sawRemovedAuth = true
		}
	}
	if sawRemovedAuth && c.Mode == AuthNone && !c.OAuthEnabled {
		return nil, warns, fmt.Errorf(
			"refusing to start unprotected: the only authentication configured (AUTH_HASH and/or " +
				"CREDENTIAL_VALIDATE_URL) has been removed. Configure OIDC_REGISTRAR_URL, USER+PASSWORD, " +
				"or OAUTH_RESOURCE")
	}

	if c.AssertionSecret != "" && !c.IdentityHeaders {
		warns = append(warns, "IDENTITY_ASSERTION_SECRET is set but IDENTITY_HEADERS is off — no assertion will be emitted")
	}
	if len(c.RequiredGroups) > 0 && c.Mode != AuthOIDC {
		warns = append(warns, "OIDC_REQUIRED_GROUPS is set but OIDC is not enabled — it will not be enforced")
	}
	if c.Mode == AuthNone && !c.OAuthEnabled {
		warns = append(warns, "no authentication configured — every request will be proxied straight through")
	}

	return c, warns, nil
}

// --- parsing helpers ---

func def(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func port(getenv func(string) string, key string) (int, error) {
	raw := strings.TrimSpace(getenv(key))
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%s %q must be an integer between 1 and 65535", key, raw)
	}
	return n, nil
}

// onOff follows the 2.x convention: off/false/0/no disable, anything else
// (including empty) takes the default.
func onOff(v string, dflt bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return dflt
	case "off", "false", "0", "no":
		return false
	default:
		return true
	}
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// duration parses nginx-style times: a bare number is seconds, or a suffix of
// ms/s/m/h/d.
func duration(v string, dflt time.Duration) (time.Duration, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return dflt, nil
	}
	units := []struct {
		suffix string
		mul    time.Duration
	}{
		{"ms", time.Millisecond},
		{"s", time.Second},
		{"m", time.Minute},
		{"h", time.Hour},
		{"d", 24 * time.Hour},
	}
	for _, u := range units {
		if !strings.HasSuffix(v, u.suffix) {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSuffix(v, u.suffix), 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%q is not a valid duration", v)
		}
		return time.Duration(n * float64(u.mul)), nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a valid duration", v)
	}
	return time.Duration(n * float64(time.Second)), nil
}

// size parses nginx-style byte sizes: bare bytes, or k/m/g suffixes. 0 means
// unlimited, matching client_max_body_size.
func size(v string, dflt int64) (int64, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return dflt, nil
	}
	mul := int64(1)
	switch {
	case strings.HasSuffix(v, "k"):
		mul, v = 1<<10, strings.TrimSuffix(v, "k")
	case strings.HasSuffix(v, "m"):
		mul, v = 1<<20, strings.TrimSuffix(v, "m")
	case strings.HasSuffix(v, "g"):
		mul, v = 1<<30, strings.TrimSuffix(v, "g")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a valid size", v)
	}
	return n * mul, nil
}

func positiveFloat(v string, dflt float64) (float64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return dflt, nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q must be a positive number", v)
	}
	return n, nil
}

func csv(v string, lower bool) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lower {
			part = strings.ToLower(part)
		}
		out = append(out, part)
	}
	return out
}

// bypassPaths normalises ALLOWED_PATHS the way 2.x did (strip surrounding
// slashes and spaces) but treats the result as a literal path prefix rather
// than splicing it into a regex, closing the config-injection hole at
// entrypoint.sh:422 where an unescaped `.*` became an unbounded bypass.
func bypassPaths(v string) ([]string, error) {
	var out []string
	for _, p := range csv(v, false) {
		p = strings.Trim(p, "/")
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		first := p
		if i := strings.IndexByte(p, '/'); i >= 0 {
			first = p[:i]
		}
		for _, r := range reservedPaths {
			if strings.EqualFold(first, r) {
				return nil, fmt.Errorf("ALLOWED_PATHS entry %q would shadow the gate's own /%s route; "+
					"choose a different path", p, r)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

func extensions(v string) []string {
	var out []string
	for _, e := range csv(v, true) {
		out = append(out, strings.TrimPrefix(e, "."))
	}
	return out
}

// FromEnv is the production entry point.
func FromEnv() (*Config, []string, error) {
	host, _ := os.Hostname()
	return Load(os.Getenv, host)
}
