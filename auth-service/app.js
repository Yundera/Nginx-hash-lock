const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Issuer, generators } = require('openid-client');

const app = express();
const PORT = 9999;

// Configuration from environment
const USERNAME = process.env.USER || '';
const PASSWORD = process.env.PASSWORD || '';
const AUTH_HASH = process.env.AUTH_HASH || '';
const SESSION_DURATION_HOURS = parseInt(process.env.SESSION_DURATION_HOURS || '720', 10);
const SESSION_DURATION_MS = SESSION_DURATION_HOURS * 60 * 60 * 1000;
// OIDC mode is enabled whenever OIDC_REGISTRAR_URL is set — no separate toggle.
// The registrar must be reachable on the `pcs` docker network (e.g. http://auth-registrar:9092).
const OIDC_REGISTRAR_URL = (process.env.OIDC_REGISTRAR_URL || '').replace(/\/+$/, '');
const OIDC_ENABLED = OIDC_REGISTRAR_URL.length > 0;

// --- Identity propagation (opt-in) -----------------------------------------
// AppShield authenticates; historically it told the backend NOTHING about who
// got in — a 200 from /nhl-auth/check and nothing more. That makes the gate
// unusable for an app whose own authorization depends on the identity (roles,
// per-user state, an audit trail).
//
// The gate forwards the authenticated identity to the backend under the names
// the forward-auth ecosystem already uses — Remote-User/-Name/-Email/-Groups
// (Authelia, Traefik) plus the X-Forwarded-* and X-Auth-Request-* aliases
// (oauth2-proxy) — so an app that already supports proxy auth needs no patch.
// ON BY DEFAULT; IDENTITY_HEADERS=off opts an app out. nginx OVERWRITES the
// whole set on every proxied request and blanks it where no identity exists, so
// a client cannot inject one (see identity_clear.conf / identity_forward.conf in
// entrypoint.sh) — which is load-bearing precisely because these names are ones
// real apps act on.
//
// TRUST MODEL — read before enabling. Plain headers are only as trustworthy as
// the network path: on a shared docker network any other container can reach the
// backend directly and forge them. That is acceptable for an app whose backend
// is only reachable through the gate; it is NOT acceptable for a privileged app.
// For those, also set IDENTITY_ASSERTION_SECRET: the gate then adds
// X-AppShield-Assertion, a short-lived HS256 JWT of the same claims that the backend
// verifies with the shared secret, making forgery detectable regardless of who
// can open a socket to it.
// Default ON: an app behind the gate should be able to know who it is serving
// without every compose file having to ask. `IDENTITY_HEADERS: "off"` is the
// escape hatch for an app that must not receive the user's email/name/groups,
// or one that mis-handles the conventional headers below.
const IDENTITY_HEADERS = !/^(off|false|0|no)$/i.test((process.env.IDENTITY_HEADERS || 'on').trim());
const IDENTITY_ASSERTION_SECRET = (process.env.IDENTITY_ASSERTION_SECRET || '').trim();
const IDENTITY_ASSERTION_TTL_SECONDS = Math.max(
    5,
    parseInt(process.env.IDENTITY_ASSERTION_TTL_SECONDS || '60', 10) || 60,
);

// Groups that an interactive OIDC identity must have at least one of. Empty =
// authenticate-only, the historical behaviour (any identity the IdP accepts
// gets in). Machine auth (hash, OAuth Bearer) is NOT subject to this: it
// carries no groups claim, and gating it here would silently break API access
// the moment an app adopts group enforcement.
const REQUIRED_GROUPS = (process.env.OIDC_REQUIRED_GROUPS || '')
    .split(',')
    .map((g) => g.trim())
    .filter(Boolean);

// --- OAuth 2.1 broker (opt-in) ------------------------------------------
// When OAUTH_RESOURCE is set, AppShield additionally runs an OAuth 2.1 /
// OIDC Authorization Server (panva oidc-provider) that fronts Dex, so remote
// OAuth clients (claude.ai via DCR, or a manually-created client) can obtain
// Bearer tokens for the protected resource. When unset, NONE of this code
// activates and AppShield behaves exactly as before.
//
// OAUTH_RESOURCE is the resource URL this proxy fronts (RFC 8707 resource
// indicator / RFC 9728 protected resource); MCP_OAUTH_RESOURCE is accepted as a
// back-compat alias. AppShield knows nothing about what the resource IS — the
// protected PATH is derived from the resource URL (never hardcoded), and
// OAUTH_SCOPE is a free-form label the resource advertises and grants (not
// enforced at the gate today). All resource-specific values live in the app's
// compose, not here.
const OAUTH_RESOURCE = (process.env.OAUTH_RESOURCE || process.env.MCP_OAUTH_RESOURCE || '').trim();
const OAUTH_ENABLED = OAUTH_RESOURCE.length > 0;
const OAUTH_SCOPE = (process.env.OAUTH_SCOPE || 'access').trim();
// The single path we protect + emit the RFC 9728 challenge for, taken straight
// from the resource URL's path (e.g. https://host/mcp -> "/mcp"). "/" when off.
const OAUTH_PROTECTED_PATH = OAUTH_ENABLED ? new URL(OAUTH_RESOURCE).pathname : '/';
const OAUTH_DATA_DIR = process.env.OAUTH_DATA_DIR || '/data/oauth';

// --- Public host set (multi-domain SSO) -------------------------------------
// AppShield is reachable under several hostnames (a custom domain, IP-based
// fallbacks, etc.). We register an OIDC callback for ALL of them, then pick the
// redirect_uri matching the host the user actually arrived on — login on
// <app>-<suffixA> returns there, login on <app>-<suffixB> returns there.
//
// THE REGISTRAR OWNS THIS SET. Which hostnames an app answers on is a property
// of the deployment — which suffixes exist, and which app the PCS root domain
// reverse-proxies to — not something an app can derive from its own name. The
// root domain is the case that proves it: whoever it points at is *also* served
// at the bare suffix (`example.com`, not just `<app>-example.com`), and no
// amount of local computation can discover that. So /register returns the
// authoritative redirect_uris and we adopt them (see adoptRegisteredCallbacks).
//
// What follows is only a SEED: our best guess at our own hosts, used to talk to
// registrars too old to answer with a list, and as the fallback if /register
// never succeeds. The `<app>-<suffix>` join is the mesh-router subdomain
// convention; the suffix list is pure config, supplied by the app's compose the
// same way the caddy_* labels are. When the list is unset we fall back to the
// legacy single request-Host behaviour.
const APP_NAME = (process.env.APP_NAME || os.hostname() || '').toLowerCase();
const REDIRECT_HOST_SUFFIXES = (process.env.REDIRECT_HOST_SUFFIXES || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
const CALLBACK_PATH = '/nhl-auth/oidc/callback';

function computeAppHosts(appName) {
    return REDIRECT_HOST_SUFFIXES.map((suffix) => `${appName}-${suffix}`.toLowerCase());
}

const APP_HOSTS = APP_NAME ? computeAppHosts(APP_NAME) : [];
// Mutable: replaced wholesale by the registrar's list on first registration.
let allowedOrigins = new Set(APP_HOSTS.map((h) => `https://${h}`));
// PINNED to our own first host, and deliberately NOT re-derived from whatever
// the registrar returns. When OAUTH_RESOURCE is set this value becomes
// OAUTH_ISSUER (see bootstrapOauthProvider) — the issuer baked into every token
// we have already signed and into the discovery documents remote clients cache.
// Moving it would invalidate all of them. It is also read at boot, before any
// /register call has happened, so it cannot depend on one.
const CANONICAL_ORIGIN = APP_HOSTS.length ? `https://${APP_HOSTS[0]}` : null;
// Where to send a request that arrives on a host we don't recognise. Starts as
// the canonical origin and is only ever FILLED IN from the registrar's list when
// we had no host config at all — it never overrides CANONICAL_ORIGIN, so the
// OAuth issuer above stays put.
let fallbackOrigin = CANONICAL_ORIGIN;
if (OIDC_ENABLED) {
    console.log(`[Auth Service] app=${APP_NAME} public hosts (guess, pending registration): ${APP_HOSTS.join(', ') || '(none — falling back to request Host)'}`);
}

// Generate password hash for session validation
// When password changes (container restart), password-based sessions become invalid
const PASSWORD_HASH = crypto.createHash('sha256').update(PASSWORD + USERNAME).digest('hex');

// Session store — a plain object behind a write-through file persistence layer,
// so gate restarts/recreates no longer log every user out mid-TTL.
// Format: { sessionId: { expires: timestamp, passwordHash?: string, authHash?: string,
//            oidcSub?: string, claims?: { sub, user, email, name, groups[] } } }
//
// `claims` is additive: sessions restored from a file written by an older build
// simply have none, and degrade to an identity of just the sub (which is what
// oidcSub already held). Nothing re-reads it for authentication decisions other
// than group enforcement — it exists to be forwarded.
//
// Persisted at SESSIONS_FILE on the same /data volume as OAUTH_DATA_DIR and the
// managed AUTH_HASH. Without a /data mount the file lands in the container layer
// (survives `docker restart`, lost on recreate) — i.e. no worse than the old
// in-memory behaviour, and no error. passwordHash/authHash invalidation still
// applies to restored sessions: if the credential changed while the gate was
// down, the session dies on its first check exactly as it would have live.
const SESSIONS_FILE = process.env.SESSIONS_FILE || '/data/sessions.json';

function loadSessions() {
    try {
        const raw = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
        const now = Date.now();
        const live = {};
        let dropped = 0;
        for (const [id, sess] of Object.entries(raw)) {
            if (sess && typeof sess.expires === 'number' && sess.expires > now) live[id] = sess;
            else dropped++;
        }
        console.log(`[Auth Service] Restored ${Object.keys(live).length} session(s) from ${SESSIONS_FILE}` + (dropped ? ` (${dropped} expired dropped)` : ''));
        return live;
    } catch (e) {
        if (e.code !== 'ENOENT') console.log(`[Auth Service] Could not restore sessions from ${SESSIONS_FILE}: ${e.message}`);
        return {};
    }
}

// Atomic write (temp + rename, same pattern as oauthFileAdapter), coalesced so
// a burst of mutations (e.g. the hourly cleanup) produces one write.
let sessionsSaveTimer = null;
function saveSessionsSoon() {
    if (sessionsSaveTimer) return;
    sessionsSaveTimer = setTimeout(() => {
        sessionsSaveTimer = null;
        try {
            fs.mkdirSync(path.dirname(SESSIONS_FILE), { recursive: true });
            const tmp = `${SESSIONS_FILE}.${process.pid}.tmp`;
            // 0600: session IDs are bearer secrets.
            fs.writeFileSync(tmp, JSON.stringify(sessions), { mode: 0o600 });
            fs.renameSync(tmp, SESSIONS_FILE);
        } catch (e) {
            console.log(`[Auth Service] Could not persist sessions to ${SESSIONS_FILE}: ${e.message}`);
        }
    }, 100);
}

// Write-through: every assignment/delete on `sessions` schedules a persist, so
// all login/logout call sites stay plain object mutations.
const sessions = new Proxy(loadSessions(), {
    set(target, prop, value) { target[prop] = value; saveSessionsSoon(); return true; },
    deleteProperty(target, prop) { delete target[prop]; saveSessionsSoon(); return true; },
});

// OIDC state: the client is lazy-initialized on the first /oidc/login request, because we
// need the public Host header to compute the redirect URI before calling the registrar.
let oidcClient = null;
let oidcIssuerUrl = null;

// OAuth provider state — populated asynchronously by bootstrapOauthProvider()
// after app.listen (oidc-provider v9 is ESM-only, loaded via dynamic import).
let oauthProvider = null;          // the oidc-provider Provider instance
let oauthProviderCallback = null;  // provider.callback() — Node request handler
let oauthLocalJWKS = null;         // jose local JWKS for verifying /mcp bearer tokens
let oauthJose = null;              // the imported jose module
let OAUTH_ISSUER = null;           // single fixed issuer origin

// Pending authorization-code flows keyed by OAuth `state`: { codeVerifier, originalUri, createdAt }
const pendingOidcFlows = new Map();
const OIDC_FLOW_TTL_MS = 10 * 60 * 1000;

/**
 * Cookie attributes for the gate session.
 *
 * `Secure` is derived from how the request actually arrived rather than hardcoded
 * either way. It used to be `secure: false` unconditionally, which on an
 * HTTPS-only host (every PCS app is behind Caddy TLS) let the session cookie be
 * sent over plaintext if anything ever downgraded the connection — and matters
 * more now that a gate can front a privileged app. Hardcoding it to `true` is
 * not an option either: a gate reached over plain HTTP would set a cookie the
 * browser refuses to send back, i.e. an unbreakable login loop.
 *
 * Express derives req.protocol from X-Forwarded-Proto because `trust proxy` is
 * on (see app.set above). Caddy sets that header; when nothing does, the value
 * is `http` and the cookie stays non-Secure, which is the old behaviour.
 */
function sessionCookieOptions(req) {
    return {
        httpOnly: true,
        secure: req.protocol === 'https',
        maxAge: SESSION_DURATION_MS,
        sameSite: 'lax',
    };
}

// Generate secure random session ID
function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

// Cleanup expired sessions every hour
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [sessionId, session] of Object.entries(sessions)) {
        if (session.expires < now) {
            delete sessions[sessionId];
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[Auth Service] Cleaned up ${cleaned} expired sessions`);
    }
}, 60 * 60 * 1000);

// Cleanup stale pending OIDC flows every 5 minutes
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [state, flow] of pendingOidcFlows) {
        if (now - flow.createdAt > OIDC_FLOW_TTL_MS) {
            pendingOidcFlows.delete(state);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[Auth Service] Cleaned up ${cleaned} stale OIDC flows`);
    }
}, 5 * 60 * 1000);

function getPublicOrigin(req) {
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const host = req.headers['x-forwarded-host'] || req.headers['host'];
    if (!host) {
        throw new Error('Cannot determine public origin: no Host header');
    }
    return `${proto}://${host}`;
}

// Pick the callback URL for the host the request arrived on. Falls back to the
// canonical host for an unrecognised host, and to the raw request origin when no
// host set is known at all (legacy single-host behaviour).
function chosenRedirect(req) {
    const origin = getPublicOrigin(req);
    const base = allowedOrigins.has(origin) ? origin : (fallbackOrigin || origin);
    return `${base}${CALLBACK_PATH}`;
}

// Replace our guessed host set with the registrar's authoritative one. This is
// what lets a login that started on the bare root domain finish there instead of
// being bounced to <app>-<suffix>: that host is in the registrar's list and can
// never be in ours.
function adoptRegisteredCallbacks(callbacks) {
    const origins = new Set();
    for (const uri of callbacks) {
        try {
            origins.add(new URL(uri).origin);
        } catch {
            console.warn(`[Auth Service] Ignoring unparseable registered redirect_uri: ${uri}`);
        }
    }
    if (origins.size === 0) return;

    const added = [...origins].filter((o) => !allowedOrigins.has(o));
    const dropped = [...allowedOrigins].filter((o) => !origins.has(o));
    allowedOrigins = origins;
    // Only fills a hole; never moves a canonical origin we already published.
    if (!fallbackOrigin) fallbackOrigin = [...origins][0];

    if (added.length) console.log(`[Auth Service] Registrar added host(s): ${added.join(', ')}`);
    // Not an error — it means the deployment no longer routes those hosts to us
    // (e.g. this app stopped being the root app). Worth seeing, because sessions
    // held on a dropped origin will stop being accepted.
    if (dropped.length) console.log(`[Auth Service] Registrar dropped host(s): ${dropped.join(', ')}`);
}

// Memoised so that two parallel first-logins (or a /login and its /callback)
// don't each POST /register. A failure clears the memo so the next request
// retries rather than inheriting a dead promise.
let oidcClientPromise = null;
function getOrInitOidcClient(publicOrigin) {
    if (oidcClient) return Promise.resolve(oidcClient);
    if (!oidcClientPromise) {
        oidcClientPromise = initOidcClient(publicOrigin).catch((err) => {
            oidcClientPromise = null;
            throw err;
        });
    }
    return oidcClientPromise;
}

async function initOidcClient(publicOrigin) {
    // Our own guess at the host set. Sent alongside callback_path so that a
    // registrar predating the callback_path contract — which requires a non-empty
    // redirect_uris and ignores anything else — still answers. A registrar that
    // understands callback_path ignores this in turn and derives the real list.
    // Drop this field once every PCS is on mesh-auth >= 1.2.0.
    const guessedCallbacks = allowedOrigins.size > 0
        ? [...allowedOrigins].map((o) => `${o}${CALLBACK_PATH}`)
        : [`${publicOrigin}${CALLBACK_PATH}`];
    console.log(`[Auth Service] Registering OIDC client with ${OIDC_REGISTRAR_URL} (callback_path=${CALLBACK_PATH}, guess=${guessedCallbacks.join(', ')})`);

    const response = await fetch(`${OIDC_REGISTRAR_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ callback_path: CALLBACK_PATH, redirect_uris: guessedCallbacks }),
    });
    if (!response.ok) {
        const body = await response.text();
        throw new Error(`Registrar returned ${response.status}: ${body}`);
    }
    const { client_id, client_secret, issuer_url, redirect_uris } = await response.json();

    // Use what came back, not what we guessed. An older registrar omits the
    // field entirely, in which case our guess is exactly what it registered.
    const callbacks = Array.isArray(redirect_uris) && redirect_uris.length > 0
        ? redirect_uris
        : guessedCallbacks;
    if (!Array.isArray(redirect_uris)) {
        console.log('[Auth Service] Registrar returned no redirect_uris (pre-1.2.0); keeping locally computed host set');
    }
    adoptRegisteredCallbacks(callbacks);
    console.log(`[Auth Service] Registered OIDC client_id=${client_id} issuer=${issuer_url} callbacks=${callbacks.join(', ')}`);

    const issuer = await Issuer.discover(issuer_url);
    oidcClient = new issuer.Client({
        client_id,
        client_secret,
        redirect_uris: callbacks,
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
    });
    oidcIssuerUrl = issuer_url;
    return oidcClient;
}

// Trust the X-Forwarded-* headers set by Caddy/nginx in front of us.
app.set('trust proxy', true);

// Middleware
// The oidc-provider protocol endpoints parse their own request bodies; if our
// generic body parsers consume the stream first, the token endpoint 400s. Skip
// them for provider protocol paths (the admin /AppShield/oauth* JSON endpoints
// are NOT skipped — they want parsed JSON).
const isOauthProtocolPath = (p) =>
    p.startsWith('/AppShield/oidc') ||
    p === '/.well-known/openid-configuration' ||
    p === '/.well-known/oauth-authorization-server';
const skipForProtocol = (mw) => (req, res, next) =>
    isOauthProtocolPath(req.path) ? next() : mw(req, res, next);
app.use(skipForProtocol(express.json()));
app.use(skipForProtocol(express.urlencoded({ extended: true })));
app.use(cookieParser());

// ===========================================================================
// Identity propagation
// ===========================================================================

// jose is ESM-only; both the OAuth broker and the identity assertion need it, so
// the dynamic import is memoized here rather than duplicated.
let josePromise = null;
function loadJose() {
    if (!josePromise) josePromise = import('jose');
    return josePromise;
}

/**
 * Make a claim value safe to carry in an HTTP header, the way every other
 * forward-auth proxy does it: raw UTF-8 bytes, control characters removed.
 *
 * We emit the conventional header names (Remote-User & co), so the VALUES have
 * to follow the same convention too — an app that already understands
 * `Remote-Name` expects a name, not a percent-encoded one. Anything that could
 * forge a header boundary (CR, LF, NUL, other C0/C1 controls) is dropped rather
 * than escaped: no legitimate claim contains one.
 *
 * The latin1 round-trip is not a mangling, it is how you put UTF-8 on the wire
 * from Node: Node serialises header values byte-per-code-unit, so encoding to
 * UTF-8 first and reinterpreting as latin1 makes the bytes leave the socket as
 * real UTF-8. A receiver that reads headers as latin1 (Node itself does) must
 * re-decode; X-AppShield-Assertion carries the exact values for anything that
 * needs fidelity guarantees rather than convention compatibility.
 */
function headerSafe(value) {
    if (value === undefined || value === null) return '';
    const clean = String(value).replace(/[\r\n\u0000-\u001f\u007f-\u009f]/g, '');
    return Buffer.from(clean, 'utf8').toString('latin1');
}

/**
 * The identity a session represents, in the shape the backend receives.
 *
 * `method` is the part an app must not ignore: `hash` and `oauth` are machine
 * callers with no human behind them, and an app that treats them as a user
 * (auditing them, or granting them a user's permissions) is wrong. Human
 * methods are `oidc` and `password`.
 */
function sessionIdentity(session) {
    if (!session) return null;
    if (session.oidcSub || session.claims) {
        const c = session.claims || {};
        return {
            method: 'oidc',
            sub: c.sub || session.oidcSub || '',
            user: c.user || '',
            email: c.email || '',
            name: c.name || '',
            groups: Array.isArray(c.groups) ? c.groups : [],
        };
    }
    if (session.passwordHash) {
        // The static-credential mode has exactly one account and no directory
        // behind it, so USER is the whole identity. No sub: there is no issuer.
        return { method: 'password', sub: '', user: USERNAME, email: '', name: '', groups: [] };
    }
    if (session.authHash) return { method: 'hash', sub: '', user: '', email: '', name: '', groups: [] };
    return null;
}

/** Pull the identity claims we forward out of an OIDC id_token claim set. */
function claimsFromIdToken(claims) {
    const groups = Array.isArray(claims.groups) ? claims.groups.map(String) : [];
    return {
        sub: String(claims.sub || ''),
        user: String(claims.preferred_username || claims.email || claims.sub || ''),
        email: String(claims.email || ''),
        name: String(claims.name || ''),
        groups,
    };
}

/**
 * Does this identity satisfy OIDC_REQUIRED_GROUPS?
 *
 * Fail-closed for interactive OIDC identities only (see REQUIRED_GROUPS above).
 * An OIDC identity whose IdP asserts no groups at all cannot satisfy a
 * non-empty requirement — that is the intended outcome, not an oversight: an
 * app that requires `admins` must not open up because the connector forgot to
 * send the claim.
 */
function groupsAllowed(identity) {
    if (!REQUIRED_GROUPS.length) return true;
    if (!identity || identity.method !== 'oidc') return true;
    return (identity.groups || []).some((g) => REQUIRED_GROUPS.includes(g));
}

/**
 * A session minted before this build has `oidcSub` but no `claims`, so its
 * groups are unknown — indistinguishable from "member of nothing". Denying it
 * with 403 would strand the user on an error page with no way back; treating it
 * as unauthenticated sends them through the IdP, which re-mints the session WITH
 * claims and answers the question for real. Only matters for the one upgrade
 * where an app turns group enforcement on with sessions already in flight.
 */
function isUngradedLegacySession(session, identity) {
    return Boolean(
        REQUIRED_GROUPS.length &&
        identity && identity.method === 'oidc' &&
        session && session.oidcSub && !session.claims
    );
}

function sendForbiddenGroups(res, identity) {
    const who = identity && identity.user ? identity.user : '(unknown)';
    console.log(`[Auth Service] Auth check denied: ${who} lacks required group(s) ${REQUIRED_GROUPS.join(',')}`);
    return res.status(403).send('Forbidden: account is not a member of a permitted group');
}

/**
 * A short-lived signed statement of the same identity carried in the headers.
 *
 * Purpose is integrity, not confidentiality — it is a JWS, anyone holding it
 * can read it. The point is that a backend can verify the gate produced it,
 * which plain headers cannot establish when something other than the gate can
 * open a connection to the backend.
 *
 * Deliberately short-lived (default 60s) and minted per request: it is a
 * transport of the gate's current answer, never a session token, and must not
 * be storable and replayable as one.
 */
async function mintAssertion(identity) {
    if (!IDENTITY_ASSERTION_SECRET || !identity) return null;
    try {
        const jose = await loadJose();
        const key = new TextEncoder().encode(IDENTITY_ASSERTION_SECRET);
        return await new jose.SignJWT({
            method: identity.method,
            user: identity.user || undefined,
            email: identity.email || undefined,
            name: identity.name || undefined,
            groups: identity.groups && identity.groups.length ? identity.groups : undefined,
        })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuer('appshield')
            .setAudience(APP_NAME || 'appshield')
            .setSubject(identity.sub || identity.user || identity.method)
            .setIssuedAt()
            .setExpirationTime(`${IDENTITY_ASSERTION_TTL_SECONDS}s`)
            .sign(key);
    } catch (err) {
        // An assertion we cannot mint must not become an outage: the request is
        // authenticated either way, and the backend that requires an assertion
        // will reject it on its own terms.
        console.error(`[Auth Service] Could not mint identity assertion: ${err.message}`);
        return null;
    }
}

/**
 * The single 200 path out of /nhl-auth/check.
 *
 * Every "authentication succeeded" answer goes through here so that no future
 * branch can accidentally return a bare OK and leave nginx forwarding whatever
 * X-Auth-* headers the *client* sent. (nginx blanks them too — this is the
 * second of the two locks.)
 */
async function authOk(req, res, identity) {
    if (IDENTITY_HEADERS && identity) {
        // These are the values; nginx fans each one out onto every conventional
        // header name it answers to (see identity_forward.conf in entrypoint.sh).
        // Kept under our own prefix on THIS hop so the auth subrequest has one
        // unambiguous source per value.
        res.set('X-AppShield-Method', headerSafe(identity.method));
        res.set('X-AppShield-Sub', headerSafe(identity.sub));
        res.set('X-AppShield-User', headerSafe(identity.user));
        res.set('X-AppShield-Email', headerSafe(identity.email));
        res.set('X-AppShield-Name', headerSafe(identity.name));
        res.set('X-AppShield-Groups', headerSafe((identity.groups || []).join(',')));
        const assertion = await mintAssertion(identity);
        if (assertion) res.set('X-AppShield-Assertion', assertion);
    }
    return res.status(200).send('OK');
}

// Send a 401, attaching the RFC 9728 discovery challenge when the original
// request targeted the protected path so OAuth clients (claude.ai) can find the
// auth server.
function sendUnauthorized(req, res, message = 'Unauthorized') {
    if (OAUTH_ENABLED && OAUTH_ISSUER) {
        const orig = req.headers['x-original-uri'] || '';
        if (orig.startsWith(OAUTH_PROTECTED_PATH)) {
            res.set(
                'WWW-Authenticate',
                `Bearer resource_metadata="${OAUTH_ISSUER}/.well-known/oauth-protected-resource"`
            );
        }
    }
    return res.status(401).send(message);
}

// A human (interactive) session: an OIDC login or a username/password login,
// never a machine AUTH_HASH session. Returns the session or null.
function humanSession(req) {
    const s = sessions[req.cookies.appshield_session];
    if (s && s.expires > Date.now() && (s.oidcSub || (s.passwordHash && s.passwordHash === PASSWORD_HASH))) {
        return s;
    }
    return null;
}

// JSON API gate: bare 401 (callers are XHR/programmatic).
function requireHumanSession(req, res, next) {
    if (!humanSession(req)) return res.status(401).send('Human login required');
    return next();
}

// Browser page gate: redirect to the human login flow instead of a bare 401, so
// an expired/cleared session (e.g. after a redeploy wipes the in-memory session
// store) lands on login and bounces back, rather than showing a blank
// "Human login required" page.
function pageRequireHumanSession(req, res, next) {
    if (humanSession(req)) return next();
    const back = encodeURIComponent(req.originalUrl || '/AppShield/oauth');
    if (OIDC_ENABLED) return res.redirect(`/nhl-auth/oidc/login?redirect=${back}`);
    return res.redirect(`/login?redirect=${back}`);
}

// Serve login page
app.get('/login', (req, res) => {
    const loginHtmlPath = path.join(__dirname, '../login.html');

    if (fs.existsSync(loginHtmlPath)) {
        res.sendFile(loginHtmlPath);
    } else {
        // Fallback inline login page if file doesn't exist
        res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Login Required</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            padding: 3rem;
            max-width: 400px;
            width: 90%;
        }
        h1 { color: #2c3e50; margin-bottom: 2rem; text-align: center; }
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; margin-bottom: 0.5rem; color: #2c3e50; font-weight: 500; }
        input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 1rem;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover { opacity: 0.9; }
        .error { color: #e74c3c; margin-top: 1rem; text-align: center; }
        .footer {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid #ecf0f1;
            color: #95a5a6;
            font-size: 0.85rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.75rem;
        }
        .footer-logo {
            width: 120px;
            height: auto;
            opacity: 0.7;
            transition: opacity 0.3s;
        }
        .footer-logo:hover {
            opacity: 1;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Login Required</h1>
        <form method="POST" action="/nhl-auth/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <input type="hidden" name="redirect" value="/">
            <button type="submit">Login</button>
            <div class="error" id="error"></div>
        </form>
        <div class="footer">
            <svg class="footer-logo" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 330.68923 161.53949"><defs><linearGradient id="d" x1="28.41308" y1="24.34637" x2="119.03571" y2="114.96899" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#27b4e1"/><stop offset=".0935" stop-color="#3da4d5"/><stop offset=".41983" stop-color="#8870ae"/><stop offset=".69027" stop-color="#bf4a92"/><stop offset=".89107" stop-color="#e13281"/><stop offset="1" stop-color="#ee2a7b"/></linearGradient></defs><g><path d="M107.81025,100.86073l6.40941.05962c16.66759,0,30.17937-13.51171,30.17937-30.1793s-13.51178-30.1793-30.17937-30.1793c-1.51561,0-3.0042.11478-4.45984.33045.06712-.86962.11199-1.74544.11199-2.63229,0-18.64504-15.1148-33.75991-33.75991-33.75991-17.83852,0-32.43546,13.83828-33.6659,31.36378-1.6969-.27143-3.43574-.41718-5.20917-.41718-18.08006,0-32.73684,14.65678-32.73684,32.73691,0,16.69318,12.57326,32.47318,28.64476,32.47318l7.71007.07145" style="fill:#dcebf9; stroke:url(#d); stroke-linecap:round; stroke-linejoin:round; stroke-width:9px;"/><path d="M102.9618,76.11709l-26.48454,32.23774c-1.14171,1.38972-1.7722,3.12901-1.78623,4.92752l-.24151,22.92321" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:10px;"/><line x1="65.9599" y1="99.84852" x2="45.93722" y2="75.47637" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:10px;"/><circle cx="74.44951" cy="147.53169" r="8.48961" style="fill:none; stroke:#294056; stroke-linecap:round; stroke-linejoin:round; stroke-width:9px;"/><rect x="90.48678" y="91.18463" width="240.20245" height="53.06293" style="fill:none;"/><path d="M109.6869,144.49847c-2.76025,0-5.23047-.58984-7.41016-1.76953-2.18066-1.17969-3.8999-2.91016-5.16016-5.19043-1.25977-2.27979-1.88965-5.0791-1.88965-8.3999v-14.75977c0-.87939.28955-1.60986.86963-2.18994.57959-.57959,1.31006-.87012,2.18994-.87012.87939,0,1.60986.29053,2.19043.87012.5791.58008.86963,1.31055.86963,2.18994v14.75977c0,2.24072.41992,4.09033,1.26025,5.55029.83984,1.46045,1.97998,2.54053,3.41992,3.23975,1.43994.7002,3.06006,1.0498,4.85986,1.0498,1.71924,0,3.24951-.33936,4.59033-1.02002,1.33936-.67969,2.40918-1.59912,3.20996-2.75977.79932-1.15967,1.19971-2.45996,1.19971-3.8999h3.78027c0,2.48047-.61035,4.72021-1.83008,6.71973-1.2207,2.00098-2.87988,3.58057-4.97998,4.73975-2.1001,1.16113-4.49072,1.74023-7.16992,1.74023ZM122.94667,144.19867c-.88037,0-1.61035-.29004-2.18994-.87012-.58057-.5791-.87012-1.30957-.87012-2.18945v-26.76025c0-.91992.28955-1.65967.87012-2.22021.57959-.55957,1.30957-.83984,2.18994-.83984.91992,0,1.65918.28027,2.22021.83984.55957.56055.83984,1.30029.83984,2.22021v26.76025c0,.87988-.28027,1.61035-.83984,2.18945-.56104.58008-1.30029.87012-2.22021.87012Z" style="fill:#294056;"/><path d="M139.8661,144.25824c-.88037,0-1.61035-.28906-2.18994-.86914-.58057-.58008-.87012-1.31055-.87012-2.19043v-26.75977c0-.91992.28955-1.65967.87012-2.22021.57959-.55957,1.30957-.83984,2.18994-.83984.91992,0,1.65918.28027,2.22021.83984.55957.56055.83984,1.30029.83984,2.22021v26.75977c0,.87988-.28027,1.61035-.83984,2.19043-.56104.58008-1.30029.86914-2.22021.86914ZM164.52626,144.25824c-.88037,0-1.61084-.28906-2.18994-.86914-.58057-.58008-.87012-1.31055-.87012-2.19043v-14.75977c0-2.28027-.41992-4.14014-1.26025-5.58008-.83984-1.43994-1.97021-2.50977-3.38965-3.20996-1.42041-.69971-3.05078-1.05029-4.89014-1.05029-1.68018,0-3.20068.34033-4.56006,1.02002-1.36035.68066-2.44043,1.58984-3.23975,2.72998-.80078,1.14014-1.2002,2.45068-1.2002,3.93018h-3.77979c0-2.52002.60938-4.77002,1.82959-6.75,1.21973-1.97998,2.88965-3.54932,5.01025-4.70996,2.11963-1.15967,4.5-1.74023,7.14014-1.74023,2.75977,0,5.229.59082,7.40967,1.77002,2.17969,1.18018,3.8999,2.91016,5.16016,5.18994,1.25977,2.28027,1.89014,5.08057,1.89014,8.40039v14.75977c0,.87988-.29102,1.61035-.87012,2.19043-.58057.58008-1.31055.86914-2.18994.86914Z" style="fill:#294056;"/><path d="M192.60633,144.4389c-3.12012,0-5.93066-.72949-8.43066-2.19043-2.5-1.45947-4.47949-3.44971-5.93945-5.96973-1.46094-2.52002-2.19043-5.35986-2.19043-8.52002,0-3.15967.66992-5.98975,2.01074-8.49023,1.33887-2.49902,3.16895-4.479,5.48926-5.93994,2.31934-1.45947,4.94043-2.18994,7.86035-2.18994,2.35938,0,4.53906.49023,6.54004,1.47021,2,.98047,3.67969,2.31006,5.04004,3.98975v-16.19971c0-.91992.28906-1.65967.87012-2.22021.5791-.55957,1.30957-.83984,2.18945-.83984.91992,0,1.65918.28027,2.2207.83984.55957.56055.83984,1.30029.83984,2.22021v27.35986c0,3.16016-.73047,6-2.19043,8.52002-1.46094,2.52002-3.42969,4.51025-5.91016,5.96973-2.48047,1.46094-5.2793,2.19043-8.39941,2.19043ZM192.60633,139.03851c2.04004,0,3.85938-.48926,5.45996-1.46973,1.59961-.97998,2.85938-2.32959,3.7793-4.05029.91992-1.71924,1.38086-3.63916,1.38086-5.75977,0-2.16016-.46094-4.08008-1.38086-5.76025-.91992-1.67969-2.17969-3.00928-3.7793-3.98975-1.60059-.97998-3.41992-1.47021-5.45996-1.47021-2.00098,0-3.81055.49023-5.43066,1.47021-1.61914.98047-2.90039,2.31006-3.83984,3.98975-.94043,1.68018-1.41016,3.6001-1.41016,5.76025,0,2.12061.46973,4.04053,1.41016,5.75977.93945,1.7207,2.2207,3.07031,3.83984,4.05029,1.62012.98047,3.42969,1.46973,5.43066,1.46973Z" style="fill:#294056;"/><path d="M235.32606,144.4389c-3.32129,0-6.27051-.70996-8.85059-2.12988s-4.59961-3.37988-6.05957-5.88037c-1.46094-2.49951-2.19043-5.37012-2.19043-8.60986,0-3.2793.69043-6.16992,2.07031-8.66992,1.37988-2.49951,3.29004-4.45996,5.72949-5.88037,2.43945-1.41943,5.24023-2.12988,8.40039-2.12988,3.12012,0,5.7998.68994,8.04004,2.06982,2.23926,1.38037,3.9502,3.28076,5.12988,5.7002,1.17969,2.4209,1.77051,5.21045,1.77051,8.37012,0,.76025-.26074,1.39014-.78027,1.89014-.52051.50049-1.18066.75-1.98047.75h-24.17969v-4.80029h24l-2.45996,1.68018c-.04004-2-.44043-3.78955-1.2002-5.37012-.75977-1.57959-1.83984-2.82959-3.24023-3.75-1.40039-.91943-3.09961-1.37988-5.09961-1.37988-2.28027,0-4.22949.50049-5.84961,1.5-1.62012,1-2.85059,2.37012-3.69043,4.10986-.83984,1.74023-1.25977,3.71045-1.25977,5.91016,0,2.2002.5,4.16064,1.5,5.87988.99902,1.72021,2.37891,3.08057,4.13965,4.08008,1.75977,1,3.78027,1.5,6.06055,1.5,1.23926,0,2.50977-.22998,3.80957-.68994,1.2998-.45947,2.34961-.99023,3.15039-1.59033.59961-.43945,1.24902-.66895,1.9502-.68994.69922-.01953,1.30957.19043,1.8291.63037.67969.59961,1.04004,1.25977,1.08008,1.97998.04004.71973-.28027,1.34033-.95996,1.85986-1.36035,1.08008-3.05078,1.95996-5.06934,2.63965-2.02051.68066-3.95117,1.02051-5.79004,1.02051Z" style="fill:#294056;"/><path d="M260.16493,144.19867c-.95996,0-1.70117-.24902-2.2207-.75-.51953-.5-.7793-1.25-.7793-2.25v-26.81982c0-.95996.25977-1.69971.7793-2.22021.51953-.51953,1.26074-.77979,2.2207-.77979.99902,0,1.74902.25,2.25.75.49902.50049.75,1.25049.75,2.25v26.81982c0,.95996-.25098,1.7002-.75,2.21973-.50098.52051-1.25098.78027-2.25.78027ZM260.10438,123.67865c0-2.3999.58984-4.5498,1.77051-6.4502,1.17871-1.89893,2.76855-3.40967,4.76953-4.52979,2-1.11914,4.2002-1.68018,6.60059-1.68018,2.39941,0,4.18945.39014,5.36914,1.17041,1.17969.77979,1.62988,1.70996,1.35059,2.78955-.12012.56104-.35059.99023-.69043,1.29004-.33984.30029-.73047.49072-1.16992.57031-.44043.08057-.9209.06006-1.43945-.06006-2.56055-.51953-4.86035-.55957-6.90039-.12012-2.04004.44043-3.65039,1.26025-4.83008,2.45996-1.18066,1.2002-1.76953,2.7207-1.76953,4.56006h-3.06055Z" style="fill:#294056;"/><path d="M297.60438,144.4389c-2.91992,0-5.54102-.72949-7.86035-2.19043-2.32031-1.45947-4.15039-3.43945-5.48926-5.93994-1.34082-2.49902-2.01074-5.32959-2.01074-8.48975,0-3.15967.72949-6,2.19043-8.52002,1.45996-2.52002,3.43945-4.50928,5.93945-5.97021,2.5-1.45947,5.31055-2.18994,8.43066-2.18994s5.91895.73047,8.39941,2.18994c2.48047,1.46094,4.44922,3.4502,5.91016,5.97021,1.45996,2.52002,2.19043,5.36035,2.19043,8.52002h-2.33984c0,3.16016-.6709,5.99072-2.01074,8.48975-1.33984,2.50049-3.16992,4.48047-5.48926,5.93994-2.32031,1.46094-4.94141,2.19043-7.86035,2.19043ZM298.80458,139.03851c2.04004,0,3.85938-.48926,5.45996-1.46973,1.59961-.97998,2.85938-2.31934,3.7793-4.02002.91992-1.69971,1.38086-3.60938,1.38086-5.72998,0-2.16016-.46094-4.08936-1.38086-5.79004-.91992-1.69971-2.17969-3.03955-3.7793-4.02002-1.60059-.97998-3.41992-1.47021-5.45996-1.47021-2.00098,0-3.81055.49023-5.43066,1.47021-1.61914.98047-2.90039,2.32031-3.83984,4.02002-.94043,1.70068-1.41016,3.62988-1.41016,5.79004,0,2.12061.46973,4.03027,1.41016,5.72998.93945,1.70068,2.2207,3.04004,3.83984,4.02002,1.62012.98047,3.42969,1.46973,5.43066,1.46973ZM312.24403,144.25824c-.87988,0-1.61035-.28906-2.18945-.86914-.58105-.58008-.87012-1.31055-.87012-2.19043v-9.18018l1.13965-6.35986,4.98047,2.16016v13.37988c0,.87988-.29102,1.61035-.87012,2.19043-.58008.58008-1.31055.86914-2.19043.86914Z" style="fill:#294056;"/></g></svg>
            <div>Protected by Nginx Hash Lock - Credential-Based Authentication</div>
        </div>
    </div>
    <script>
        const params = new URLSearchParams(window.location.search);
        if (params.get('error') === 'invalid') {
            document.getElementById('error').textContent = 'Invalid username or password';
        }
        if (params.get('redirect')) {
            document.querySelector('input[name="redirect"]').value = params.get('redirect');
        }
    </script>
</body>
</html>
        `);
    }
});

// Handle login submission
app.post('/nhl-auth/login', async (req, res) => {
    const { username, password, redirect } = req.body;
    const startTime = Date.now();

    // Validate credentials
    const isValid = username === USERNAME && password === PASSWORD;

    if (isValid) {
        // Create session
        const sessionId = generateSessionId();
        sessions[sessionId] = {
            expires: Date.now() + SESSION_DURATION_MS,
            passwordHash: PASSWORD_HASH
        };

        console.log(`[Auth Service] Login successful for user: ${username}`);
        console.log(`[Auth Service] Session created: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

        // Set cookie and redirect
        res.cookie('appshield_session', sessionId, sessionCookieOptions(req));

        res.redirect(redirect || '/');
    } else {
        // Apply 2-second delay for failed attempts (anti-brute force)
        const elapsed = Date.now() - startTime;
        const delay = Math.max(0, 2000 - elapsed);

        console.log(`[Auth Service] Login failed for user: ${username || '(empty)'}`);

        setTimeout(() => {
            res.redirect('/login?error=invalid' + (redirect ? `&redirect=${encodeURIComponent(redirect)}` : ''));
        }, delay);
    }
});

// Auth check endpoint (called by nginx auth_request)
app.get('/nhl-auth/check', async (req, res) => {
    // Check for existing session first
    let sessionId = req.cookies.appshield_session;

    if (sessionId && sessions[sessionId]) {
        const session = sessions[sessionId];

        // Check if session is expired
        if (session.expires < Date.now()) {
            console.log(`[Auth Service] Auth check failed: Session expired (${sessionId.substring(0, 8)}...)`);
            delete sessions[sessionId];
            // Continue to check other auth methods
        }
        // Check if credentials are still valid
        else {
            // Session is valid if ANY of: password hash, auth hash, or OIDC sub is set.
            // OIDC sessions are trusted until expiry — there's no local credential to re-verify.
            const passwordValid = session.passwordHash && session.passwordHash === PASSWORD_HASH;
            const authHashValid = session.authHash && session.authHash === AUTH_HASH;
            const oidcValid = !!session.oidcSub;

            if (passwordValid || authHashValid || oidcValid) {
                const identity = sessionIdentity(session);
                if (isUngradedLegacySession(session, identity)) {
                    console.log(`[Auth Service] Re-authenticating pre-groups session (${sessionId.substring(0, 8)}...)`);
                    delete sessions[sessionId];
                    return sendUnauthorized(req, res);
                }
                if (!groupsAllowed(identity)) return sendForbiddenGroups(res, identity);
                console.log(`[Auth Service] Auth check passed via session (${sessionId.substring(0, 8)}...)`);
                return await authOk(req, res, identity);
            } else {
                console.log(`[Auth Service] Auth check failed: Credentials changed, invalidating session (${sessionId.substring(0, 8)}...)`);
                delete sessions[sessionId];
                // Continue to check other auth methods
            }
        }
    }

    // No valid session - check if hash parameter is valid
    if (process.env.AUTH_HASH) {
        const originalUri = req.headers['x-original-uri'] || '';
        const hashMatch = originalUri.match(/[?&]hash=([^&]+)/);

        if (hashMatch && hashMatch[1] === process.env.AUTH_HASH) {
            console.log('[Auth Service] Auth check passed via hash parameter');

            // Create a new session only if one doesn't exist
            if (!sessionId || !sessions[sessionId]) {
                sessionId = generateSessionId();
                sessions[sessionId] = {
                    expires: Date.now() + SESSION_DURATION_MS,
                    authHash: AUTH_HASH
                };

                console.log(`[Auth Service] Session created for hash auth: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

                // Set session cookie
                res.cookie('appshield_session', sessionId, sessionCookieOptions(req));
            }

            return await authOk(req, res, { method: 'hash', sub: '', user: '', email: '', name: '', groups: [] });
        }
    }

    // No valid session — check the AUTH_HASH carried in the Authorization header.
    // Machine / API clients (non-interactive) present the hash as either an HTTP
    // Basic credential (true basic auth, e.g. `curl -u any:<hash>`) or a Bearer
    // token. Validated against AUTH_HASH only — never USER/PASSWORD, which are the
    // interactive (human) modes. Stateless: no session cookie is minted, the client
    // simply re-sends the header on each request.
    if (process.env.AUTH_HASH) {
        const authHeader = req.headers['authorization'] || '';
        let headerHashOk = false;
        if (/^Bearer /i.test(authHeader)) {
            headerHashOk = authHeader.slice(7).trim() === process.env.AUTH_HASH;
        } else if (/^Basic /i.test(authHeader)) {
            try {
                const decoded = Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8');
                const sep = decoded.indexOf(':');
                const user = sep >= 0 ? decoded.slice(0, sep) : decoded;
                const pass = sep >= 0 ? decoded.slice(sep + 1) : '';
                // Accept the hash as either field so `-u <hash>:` and `-u any:<hash>` both work.
                headerHashOk = pass === process.env.AUTH_HASH || user === process.env.AUTH_HASH;
            } catch (e) { /* malformed base64 — treat as no match */ }
        }
        if (headerHashOk) {
            console.log('[Auth Service] Auth check passed via Authorization header (hash)');
            return await authOk(req, res, { method: 'hash', sub: '', user: '', email: '', name: '', groups: [] });
        }
    }

    // OAuth: accept a Bearer JWT access token issued by our own provider.
    // Only attempted for 3-segment tokens, so the opaque AUTH_HASH bearer above
    // and these JWTs coexist on the same gate.
    if (OAUTH_ENABLED && oauthLocalJWKS && oauthJose) {
        const authHeader = req.headers['authorization'] || '';
        const m = /^Bearer\s+(.+)$/i.exec(authHeader);
        if (m && m[1].split('.').length === 3) {
            try {
                const verified = await oauthJose.jwtVerify(m[1], oauthLocalJWKS, {
                    issuer: OAUTH_ISSUER,
                    audience: OAUTH_RESOURCE,
                });
                console.log('[Auth Service] Auth check passed via Bearer JWT');
                // A machine caller: `sub` is the OAuth client/grant subject, not
                // a person. Reported as method=oauth so the backend can tell.
                return await authOk(req, res, {
                    method: 'oauth',
                    sub: String(verified.payload.sub || ''),
                    user: '', email: '', name: '', groups: [],
                });
            } catch (e) {
                console.log(`[Auth Service] Bearer JWT rejected: ${e.message}`);
                // fall through to the remaining checks / 401
            }
        }
    }

    // Check session cookie again (for cases where hash auth wasn't valid)
    sessionId = req.cookies.appshield_session;

    if (!sessionId) {
        console.log('[Auth Service] Auth check failed: No session cookie and no valid hash');
        return sendUnauthorized(req, res);
    }

    const session = sessions[sessionId];

    if (!session) {
        console.log(`[Auth Service] Auth check failed: Session not found (${sessionId.substring(0, 8)}...)`);
        return sendUnauthorized(req, res);
    }

    if (session.expires < Date.now()) {
        console.log(`[Auth Service] Auth check failed: Session expired (${sessionId.substring(0, 8)}...)`);
        delete sessions[sessionId];
        return sendUnauthorized(req, res);
    }

    // Check if password has changed
    if (session.passwordHash && session.passwordHash !== PASSWORD_HASH) {
        console.log(`[Auth Service] Auth check failed: Password changed, invalidating session (${sessionId.substring(0, 8)}...)`);
        delete sessions[sessionId];
        return sendUnauthorized(req, res);
    }

    // Session is valid
    const identity = sessionIdentity(session);
    if (isUngradedLegacySession(session, identity)) {
        console.log(`[Auth Service] Re-authenticating pre-groups session (${sessionId.substring(0, 8)}...)`);
        delete sessions[sessionId];
        return sendUnauthorized(req, res);
    }
    if (!groupsAllowed(identity)) return sendForbiddenGroups(res, identity);
    console.log(`[Auth Service] Auth check passed via session (${sessionId.substring(0, 8)}...)`);
    return await authOk(req, res, identity);
});

// Establish session endpoint (for hash authentication to set cookies properly)
app.get('/nhl-auth/establish-session', (req, res) => {
    // Check if hash parameter is valid
    if (process.env.AUTH_HASH) {
        const hash = req.query.hash;
        let returnTo = req.query.return_to || '/';

        // Strip hash parameter from return URL to prevent redirect loop
        returnTo = returnTo.replace(/[?&]hash=[^&]+(&|$)/, (match, p1) => p1 === '&' ? '&' : '?').replace(/[?&]$/, '').replace(/\?$/, '') || '/';

        if (hash && hash === process.env.AUTH_HASH) {
            // Check if session already exists
            let sessionId = req.cookies.appshield_session;

            if (sessionId && sessions[sessionId]) {
                const session = sessions[sessionId];
                // Check if session is valid (not expired and credentials are still valid)
                const passwordValid = session.passwordHash && session.passwordHash === PASSWORD_HASH;
                const authHashValid = session.authHash && session.authHash === AUTH_HASH;

                if (session.expires > Date.now() && (passwordValid || authHashValid)) {
                    // Valid session already exists
                    console.log(`[Auth Service] Session already valid: ${sessionId.substring(0, 8)}...`);
                    // Redirect back if requested
                    if (req.query.return_to) {
                        return res.redirect(returnTo);
                    }
                    return res.status(200).json({ status: 'ok', message: 'Session already valid' });
                } else {
                    // Session expired or password changed, delete it
                    delete sessions[sessionId];
                }
            }

            // Create new session
            sessionId = generateSessionId();
            sessions[sessionId] = {
                expires: Date.now() + SESSION_DURATION_MS,
                authHash: AUTH_HASH
            };

            console.log(`[Auth Service] Session established via hash: ${sessionId.substring(0, 8)}... (expires in ${SESSION_DURATION_HOURS}h)`);

            // Set session cookie
            res.cookie('appshield_session', sessionId, sessionCookieOptions(req));

            // Redirect back if requested
            if (req.query.return_to) {
                return res.redirect(returnTo);
            }

            return res.status(200).json({ status: 'ok', message: 'Session established' });
        }
    }

    return res.status(401).json({ status: 'error', message: 'Invalid or missing hash' });
});

// Start OIDC authorization_code + PKCE flow
app.get('/nhl-auth/oidc/login', async (req, res) => {
    if (!OIDC_ENABLED) {
        return res.status(404).send('OIDC authentication not enabled');
    }
    try {
        const publicOrigin = getPublicOrigin(req);
        const client = await getOrInitOidcClient(publicOrigin);

        const codeVerifier = generators.codeVerifier();
        const codeChallenge = generators.codeChallenge(codeVerifier);
        const state = generators.state();

        // Constrain the post-login redirect to our own origin. An attacker-controlled
        // redirect= param would otherwise turn this endpoint into an open redirector
        // after a successful login.
        let originalUri = '/';
        const redirectParam = typeof req.query.redirect === 'string' ? req.query.redirect : '';
        if (redirectParam) {
            try {
                const parsed = new URL(redirectParam, publicOrigin);
                if (parsed.origin === publicOrigin) {
                    originalUri = parsed.pathname + parsed.search + parsed.hash;
                }
            } catch {
                originalUri = '/';
            }
        }

        pendingOidcFlows.set(state, { codeVerifier, originalUri, createdAt: Date.now() });

        const authUrl = client.authorizationUrl({
            redirect_uri: chosenRedirect(req),
            scope: 'openid profile email groups',
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
        });
        console.log(`[Auth Service] OIDC login: state=${state.substring(0, 8)}... target=${originalUri}`);
        res.redirect(authUrl);
    } catch (err) {
        console.error('[Auth Service] OIDC login failed:', err);
        res.status(500).send('OIDC login failed: ' + err.message);
    }
});

// Exchange authorization code for tokens and mint a session cookie
app.get('/nhl-auth/oidc/callback', async (req, res) => {
    if (!OIDC_ENABLED) {
        return res.status(404).send('OIDC authentication not enabled');
    }
    try {
        const publicOrigin = getPublicOrigin(req);
        const client = await getOrInitOidcClient(publicOrigin);

        const params = client.callbackParams(req);
        if (!params.state || !pendingOidcFlows.has(params.state)) {
            console.warn(`[Auth Service] OIDC callback rejected: unknown state=${params.state}`);
            return res.status(400).send('Invalid or expired OIDC state');
        }
        const flow = pendingOidcFlows.get(params.state);
        pendingOidcFlows.delete(params.state);

        // The IdP redirected back to the same host the login used, so recomputing
        // from the callback request yields the matching redirect_uri (required to
        // equal the one sent at /authorize for the token exchange).
        const tokenSet = await client.callback(
            chosenRedirect(req),
            params,
            { state: params.state, code_verifier: flow.codeVerifier },
        );
        const claims = tokenSet.claims();
        const identityClaims = claimsFromIdToken(claims);

        // Enforce group membership BEFORE minting a session. Checking only at
        // /nhl-auth/check would also work, but the user would arrive back with a
        // cookie they cannot use and a bare 403 on every page; refusing here
        // says why, once, and leaves no session behind.
        if (!groupsAllowed({ method: 'oidc', ...identityClaims })) {
            console.log(`[Auth Service] OIDC login denied for sub=${claims.sub}: not in ${REQUIRED_GROUPS.join(',')}`);
            return res.status(403).send(
                'Forbidden: your account is not a member of a group permitted to use this application.'
            );
        }

        const sessionId = generateSessionId();
        sessions[sessionId] = {
            expires: Date.now() + SESSION_DURATION_MS,
            oidcSub: claims.sub,
            claims: identityClaims,
        };
        console.log(`[Auth Service] OIDC session created for sub=${claims.sub} user=${identityClaims.user || '(none)'} groups=[${identityClaims.groups.join(',')}] (${sessionId.substring(0, 8)}...)`);

        res.cookie('appshield_session', sessionId, sessionCookieOptions(req));
        res.redirect(flow.originalUri || '/');
    } catch (err) {
        console.error('[Auth Service] OIDC callback failed:', err);
        res.status(500).send('OIDC callback failed: ' + err.message);
    }
});

// Sign out: destroy the gate session and clear the cookie.
//
// Deliberately renders a terminal page instead of redirecting to `/`. The IdP
// session outlives ours (Dex holds a 30-day SSO session), so bouncing the
// browser back through the gate would silently re-authenticate and look like
// logout did nothing. Landing here makes the state unambiguous; the link then
// starts a fresh, deliberate login.
app.all('/nhl-auth/logout', (req, res) => {
    const sessionId = req.cookies.appshield_session;
    if (sessionId && sessions[sessionId]) {
        delete sessions[sessionId];
        console.log(`[Auth Service] Session destroyed on logout (${sessionId.substring(0, 8)}...)`);
    }
    res.clearCookie('appshield_session', {httpOnly: true, secure: req.protocol === 'https', sameSite: 'lax'});
    res.status(200).type('html').send(
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signed out</title>' +
        '<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;' +
        'justify-content:center;height:100vh;margin:0;background:#f5f7fa;color:#294056}' +
        'div{text-align:center}a{color:#27b4e1}</style></head><body><div>' +
        '<h1>Signed out</h1><p>Your session on this application has ended.</p>' +
        '<p><a href="/">Sign in again</a></p>' +
        '<p style="font-size:.85em;opacity:.7">You may still be signed in with your ' +
        'identity provider; signing in again may not ask for your password.</p>' +
        '</div></body></html>'
    );
});

// ===========================================================================
// Control API: session revocation
//
// WHY THIS EXISTS. A gate session is a bearer credential valid for its full TTL
// (30 days by default) and nothing outside the gate could end one. That is fine
// for a media app and wrong for a privileged one: an app that can delete an
// account, reset its password or strip its admin rights needs those actions to
// take effect on sessions already in flight, not just on the next login.
// settings-center-app solves it today with a per-account session epoch stamped
// into its own JWT; a gate-issued session has no such handle, so the gate has to
// offer one.
//
// AUTHENTICATION. The endpoint is reachable from the internet (everything under
// /nhl-auth/ is), so it is gated on a signed control token rather than on where
// the request came from — nginx proxies it from 127.0.0.1, which makes network
// origin unusable as a check. The token is an HS256 JWT signed with
// IDENTITY_ASSERTION_SECRET: the same secret the backend already needs in order
// to verify identity assertions, used in the other direction. No second secret
// to provision, and a gate without that secret has no control API at all.
//
// AUDIENCE SEPARATION IS THE POINT. Identity assertions carry aud=APP_NAME;
// control tokens carry aud="appshield-control". Without that split, an identity
// assertion — which the gate hands to the backend on every request, and which a
// backend may well log — would double as a session-revocation credential.
// ===========================================================================
const CONTROL_AUDIENCE = 'appshield-control';
const CONTROL_ISSUER = 'appshield-backend';
const CONTROL_MAX_TOKEN_LIFETIME_SECONDS = 300;

/** Verify a control token. Returns its payload, or null (having logged why). */
async function verifyControlToken(req) {
    const header = req.headers['authorization'] || '';
    const m = /^Bearer\s+(.+)$/i.exec(header);
    if (!m) {
        console.log('[Auth Service] Control call rejected: no Bearer token');
        return null;
    }
    try {
        const jose = await loadJose();
        const key = new TextEncoder().encode(IDENTITY_ASSERTION_SECRET);
        const { payload, protectedHeader } = await jose.jwtVerify(m[1], key, {
            issuer: CONTROL_ISSUER,
            audience: CONTROL_AUDIENCE,
        });
        // The key is symmetric, so jose can only have accepted an HMAC alg — this
        // is belt-and-braces against a future change to how the key is built.
        if (protectedHeader.alg !== 'HS256') {
            console.log(`[Auth Service] Control call rejected: unexpected alg ${protectedHeader.alg}`);
            return null;
        }
        // Bound the replay window. jose already enforces exp; this additionally
        // refuses a token minted with a year-long lifetime, which would be a
        // standing credential rather than a one-shot authorisation.
        if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') {
            console.log('[Auth Service] Control call rejected: token missing iat/exp');
            return null;
        }
        if (payload.exp - payload.iat > CONTROL_MAX_TOKEN_LIFETIME_SECONDS) {
            console.log('[Auth Service] Control call rejected: token lifetime exceeds ' +
                `${CONTROL_MAX_TOKEN_LIFETIME_SECONDS}s`);
            return null;
        }
        return payload;
    } catch (err) {
        console.log(`[Auth Service] Control call rejected: ${err.message}`);
        return null;
    }
}

/**
 * POST /nhl-auth/sessions/revoke
 *
 * Body selects what to end — at least one of:
 *   { "sub": "<idp subject>" }   every session for that subject
 *   { "user": "<username>" }     every session for that preferred_username
 *   { "all": true }              every session on this gate
 *
 * `sub` and `user` may be combined; a session matching either is revoked, which
 * is what you want when an account is renamed and old sessions still carry the
 * previous username.
 *
 * Idempotent by construction: revoking something already gone returns
 * {revoked: 0}, not an error. Deleting through the `sessions` Proxy persists to
 * SESSIONS_FILE, so a revocation survives a gate restart rather than coming back
 * with the restored session set.
 */
app.post('/nhl-auth/sessions/revoke', async (req, res) => {
    if (!IDENTITY_ASSERTION_SECRET) {
        // Not an error the caller can fix by retrying — say so plainly rather
        // than 401, which would look like a bad token.
        return res.status(501).json({
            error: 'control API disabled: IDENTITY_ASSERTION_SECRET is not configured on this gate',
        });
    }

    const token = await verifyControlToken(req);
    if (!token) return res.status(401).json({ error: 'invalid or missing control token' });

    const { sub, user, all } = req.body || {};
    if (!sub && !user && all !== true) {
        return res.status(400).json({ error: 'specify at least one of: sub, user, all' });
    }

    const matches = (session) => {
        if (all === true) return true;
        if (sub && (session.claims?.sub === sub || session.oidcSub === sub)) return true;
        if (user && session.claims?.user === user) return true;
        return false;
    };

    let revoked = 0;
    for (const [sessionId, session] of Object.entries(sessions)) {
        if (matches(session)) {
            delete sessions[sessionId];
            revoked++;
        }
    }

    const what = all === true ? 'all sessions' : `sub=${sub || '-'} user=${user || '-'}`;
    console.log(`[Auth Service] Revoked ${revoked} session(s) (${what}) on behalf of ${token.sub || CONTROL_ISSUER}`);
    return res.status(200).json({ revoked });
});

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        activeSessions: Object.keys(sessions).length,
        sessionDurationHours: SESSION_DURATION_HOURS
    });
});

// ===========================================================================
// OAuth 2.1 Authorization Server (opt-in, fronts Dex)
// ===========================================================================

const OAUTH_ADMIN_PAGE = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Remote Access</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f4f5f7;color:#2c3e50;margin:0;padding:2rem;}
  .wrap{max-width:760px;margin:0 auto;}
  h1{font-size:1.4rem;} h2{font-size:1.05rem;margin-top:2rem;}
  .card{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem 1.25rem;margin:1rem 0;}
  code{background:#f0f0f0;padding:.1rem .3rem;border-radius:4px;font-size:.85rem;word-break:break-all;}
  pre{background:#1e1e1e;color:#d4d4d4;padding:1rem;border-radius:6px;overflow:auto;font-size:.8rem;}
  label{display:block;margin:.5rem 0 .25rem;font-weight:600;font-size:.9rem;}
  input{width:100%;padding:.5rem;border:1px solid #ccc;border-radius:6px;box-sizing:border-box;}
  button{background:#5b6ee1;color:#fff;border:none;border-radius:6px;padding:.55rem 1rem;font-weight:600;cursor:pointer;margin-top:.75rem;}
  button.danger{background:#e15b5b;padding:.3rem .6rem;margin:0;font-size:.8rem;}
  table{width:100%;border-collapse:collapse;font-size:.85rem;} td,th{text-align:left;padding:.4rem;border-bottom:1px solid #eee;}
  .tag{font-size:.7rem;padding:.1rem .4rem;border-radius:4px;background:#eef;}
  .muted{color:#888;font-size:.85rem;}
</style></head>
<body><div class="wrap">
  <h1>Remote Access (OAuth 2.1)</h1>
  <p class="muted">Connect remote OAuth clients (claude.ai, n8n, …) to this server securely. claude.ai registers itself automatically; clients that cannot self-register (e.g. n8n) need a manual client below.</p>

  <div class="card" id="info"><h2>Connection</h2><div id="info-body" class="muted">Loading…</div></div>

  <div class="card">
    <h2>Add a manual client</h2>
    <p class="muted">For clients that don't support Dynamic Client Registration. Paste the client's OAuth callback/redirect URL.</p>
    <label>Name</label><input id="c-name" placeholder="e.g. n8n">
    <label>Redirect URI(s) — one per line</label>
    <input id="c-redirects" placeholder="https://…/rest/oauth2-credential/callback">
    <button onclick="createClient()">Create client</button>
    <pre id="create-out" style="display:none"></pre>
  </div>

  <div class="card"><h2>Registered clients</h2><div id="clients">Loading…</div></div>
</div>
<script>
const J = (r) => r.json();
async function loadInfo(){
  const i = await fetch('oauth/info').then(J);
  document.getElementById('info-body').innerHTML =
    '<p>Give this URL to a remote OAuth client:</p><p><code>'+i.resource+'</code></p>'+
    '<p class="muted">Issuer: <code>'+i.issuer+'</code></p>';
}
async function loadClients(){
  const list = await fetch('oauth/clients').then(J);
  if(!list.length){ document.getElementById('clients').innerHTML='<p class="muted">None yet.</p>'; return; }
  let h='<table><tr><th>Name</th><th>Client ID</th><th>Type</th><th></th></tr>';
  for(const c of list){
    h+='<tr><td>'+(c.client_name||'—')+'</td><td><code>'+c.client_id+'</code></td>'+
       '<td><span class="tag">'+c.origin+'</span></td>'+
       '<td><button class="danger" onclick="delClient(\\''+c.client_id+'\\')">Revoke</button></td></tr>';
  }
  document.getElementById('clients').innerHTML = h+'</table>';
}
async function createClient(){
  const name=document.getElementById('c-name').value.trim();
  const redirect_uris=document.getElementById('c-redirects').value.split(/\\s+/).filter(Boolean);
  const res=await fetch('oauth/clients',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({name,redirect_uris})});
  const out=document.getElementById('create-out');
  const data=await res.json();
  if(!res.ok){ out.style.display='block'; out.textContent='Error: '+(data.error||res.status); return; }
  out.style.display='block';
  out.textContent=
    'Client ID:     '+data.client_id+'\\n'+
    'Client Secret: '+data.client_secret+'\\n'+
    'Auth URL:      '+data.authorization_endpoint+'\\n'+
    'Token URL:     '+data.token_endpoint+'\\n'+
    'Scope:         '+data.scope+'\\n\\n'+
    '(Copy the secret now — it is not shown again.)';
  loadClients();
}
async function delClient(id){
  if(!confirm('Revoke client '+id+'?')) return;
  await fetch('oauth/clients/'+encodeURIComponent(id),{method:'DELETE'});
  loadClients();
}
loadInfo(); loadClients();
</script></body></html>`;

async function bootstrapOauthProvider() {
    const fsp = fs.promises;
    fs.mkdirSync(OAUTH_DATA_DIR, { recursive: true });

    const { default: Provider } = await import('oidc-provider');
    oauthJose = await import('jose');

    // Issuer = the canonical public origin (single fixed value; oidc-provider
    // does not support per-host issuers). Fall back to the resource's origin.
    OAUTH_ISSUER = CANONICAL_ORIGIN || new URL(OAUTH_RESOURCE).origin;

    // --- Persisted signing keys (JWKS) & cookie keys ------------------------
    const jwksFile = path.join(OAUTH_DATA_DIR, 'jwks.json');
    let jwks;
    if (fs.existsSync(jwksFile)) {
        jwks = JSON.parse(fs.readFileSync(jwksFile, 'utf8'));
    } else {
        const { privateKey } = await oauthJose.generateKeyPair('RS256', { extractable: true });
        const jwk = await oauthJose.exportJWK(privateKey);
        jwk.use = 'sig';
        jwk.alg = 'RS256';
        jwk.kid = crypto.randomBytes(8).toString('hex');
        jwks = { keys: [jwk] };
        await fsp.writeFile(jwksFile, JSON.stringify(jwks));
    }
    // Public-only set for local verification of /mcp bearer tokens.
    const publicJwks = {
        keys: jwks.keys.map((k) => {
            const { d, p, q, dp, dq, qi, ...pub } = k;
            return pub;
        }),
    };
    oauthLocalJWKS = oauthJose.createLocalJWKSet(publicJwks);

    const cookieKeysFile = path.join(OAUTH_DATA_DIR, 'cookie-keys.json');
    let cookieKeys;
    if (fs.existsSync(cookieKeysFile)) {
        cookieKeys = JSON.parse(fs.readFileSync(cookieKeysFile, 'utf8'));
    } else {
        cookieKeys = [crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')];
        await fsp.writeFile(cookieKeysFile, JSON.stringify(cookieKeys));
    }

    const OAuthFileAdapter = require('./oauthFileAdapter');

    const configuration = {
        adapter: OAuthFileAdapter,
        clients: [],
        jwks,
        cookies: { keys: cookieKeys },
        pkce: { required: () => true, methods: ['S256'] },
        routes: {
            authorization: '/AppShield/oidc/auth',
            token: '/AppShield/oidc/token',
            jwks: '/AppShield/oidc/jwks',
            registration: '/AppShield/oidc/reg',
            revocation: '/AppShield/oidc/token/revocation',
            introspection: '/AppShield/oidc/token/introspection',
            userinfo: '/AppShield/oidc/me',
            end_session: '/AppShield/oidc/session/end',
            pushed_authorization_request: '/AppShield/oidc/request',
        },
        // Supported scopes. Must be a superset of whatever remote clients request
        // at Dynamic Client Registration, or oidc-provider rejects the registration
        // with invalid_client_metadata. claude.ai requests standard OIDC scopes plus
        // the advertised resource scope (OAUTH_SCOPE), so all are registered here.
        scopes: ['openid', 'offline_access', 'profile', 'email', OAUTH_SCOPE],
        claims: { openid: ['sub'] },
        interactions: {
            url: (ctx, interaction) => `/AppShield/interaction/${interaction.uid}`,
        },
        findAccount: async (ctx, id) => ({
            accountId: id,
            claims: async () => ({ sub: id }),
        }),
        clientBasedCORS: () => true,
        features: {
            devInteractions: { enabled: false },
            registration: { enabled: true, initialAccessToken: false },
            resourceIndicators: {
                enabled: true,
                defaultResource: () => OAUTH_RESOURCE,
                useGrantedResource: () => true,
                getResourceServerInfo: () => ({
                    scope: OAUTH_SCOPE,
                    audience: OAUTH_RESOURCE,
                    accessTokenTTL: 3600,
                    accessTokenFormat: 'jwt',
                }),
            },
        },
        ttl: {
            AccessToken: 3600,
            AuthorizationCode: 600,
            IdToken: 3600,
            // 90 days: long-lived clients (an aggregator holding this endpoint)
            // only need a human again once the refresh token or the grant
            // expires. At 14 days that meant a re-login every fortnight even for
            // something in constant use.
            RefreshToken: 90 * 24 * 3600,
            Interaction: 3600,
            Grant: 90 * 24 * 3600,
            Session: SESSION_DURATION_HOURS * 3600,
        },
    };

    oauthProvider = new Provider(OAUTH_ISSUER, configuration);
    oauthProvider.proxy = true;
    oauthProviderCallback = oauthProvider.callback();

    // Diagnostics: log DCR / authorization / server errors so failed remote-client
    // registrations (e.g. claude.ai) are visible in the auth-service log.
    oauthProvider.on('registration_create.error', (ctx, err) => {
        console.log(`[Auth Service] DCR error: ${err.message} | body=${JSON.stringify(ctx.oidc && ctx.oidc.body)}`);
    });
    oauthProvider.on('authorization.error', (ctx, err) => {
        console.log(`[Auth Service] authorization error: ${err.message} | desc=${err.error_description} | detail=${err.error_detail || ''}`);
    });
    oauthProvider.on('server_error', (ctx, err) => {
        console.error('[Auth Service] oidc server_error:', err && err.stack || err);
    });

    // Honour offline_access even when the client omits prompt=consent.
    //
    // OIDC Core 11.1 says an authorization server MUST ignore the offline_access
    // scope unless the request also carries prompt=consent, and oidc-provider
    // implements that literally: it silently drops the scope. The default
    // issueRefreshToken policy then sees no offline_access in the granted scopes
    // and issues no refresh token, so the client is left with a 1-hour access
    // token and no way to renew it — it has to send the user back through a full
    // login every hour.
    //
    // Clients that derive their scopes from the protected resource metadata
    // (RFC 9728, advertised below) hit this constantly: they request
    // offline_access because the resource advertises it, but send no prompt
    // parameter. Verified against this server — the same authorization request
    // with prompt=consent added returns a refresh token, without it does not.
    //
    // Adding the prompt here rather than relaxing issueRefreshToken keeps the
    // change narrow: only requests that explicitly asked for offline access are
    // touched, the grant genuinely contains the scope, and clients that never
    // asked still get no refresh token. No user decision is bypassed either —
    // consent is auto-granted first-party in the interaction handler below, so
    // prompt=consent costs one extra redirect and shows nothing.
    // Mounted at the root on purpose: Express restores req.url when a middleware
    // mounted on a sub-path returns, which would silently undo the rewrite below.
    const AUTHORIZATION_PATH = '/AppShield/oidc/auth';
    app.use((req, res, next) => {
        if (req.path !== AUTHORIZATION_PATH) return next();
        // Only the browser-facing GET carries the parameters in the query string.
        // A POST authorization request (rare) and pushed authorization requests
        // (/AppShield/oidc/request) carry them in a body that is deliberately not
        // parsed for provider paths, so they are left alone; a client using those
        // must send prompt=consent itself.
        if (req.method !== 'GET') return next();
        const scopes = String(req.query.scope || '').split(' ');
        if (!scopes.includes('offline_access') || req.query.prompt) return next();
        try {
            const url = new URL(req.originalUrl, OAUTH_ISSUER);
            url.searchParams.set('prompt', 'consent');
            req.url = url.pathname + url.search;
            console.log('[Auth Service] added prompt=consent for offline_access request');
        } catch (err) {
            console.log(`[Auth Service] could not add prompt=consent: ${err.message}`);
        }
        return next();
    });

    // Route provider-owned paths to oidc-provider; everything else falls through.
    app.use((req, res, next) => {
        if (!oauthProviderCallback) return next();
        if (req.path === '/.well-known/openid-configuration' || req.path.startsWith('/AppShield/oidc')) {
            return oauthProviderCallback(req, res);
        }
        return next();
    });

    // RFC 8414 alias — OAuth clients fetch oauth-authorization-server; re-dispatch
    // to the provider's own discovery doc so the two never drift.
    app.get('/.well-known/oauth-authorization-server', (req, res) => {
        req.url = '/.well-known/openid-configuration';
        oauthProviderCallback(req, res);
    });

    // RFC 9728 Protected Resource Metadata (this server is the RS for /mcp).
    app.get('/.well-known/oauth-protected-resource', (req, res) => {
        res.json({
            resource: OAUTH_RESOURCE,
            authorization_servers: [OAUTH_ISSUER],
            bearer_methods_supported: ['header'],
            // offline_access is advertised on purpose. A client that derives its
            // scopes from this document (or from the WWW-Authenticate challenge)
            // asks for nothing else — so without it listed here, nothing ever
            // requests offline access, oidc-provider issues no refresh token, and
            // every consumer has to be re-authorized by a human once the 1h
            // access token expires. Merely annoying for an interactive browser
            // client; it makes unattended clients unusable.
            scopes_supported: [OAUTH_SCOPE, 'offline_access'],
        });
    });

    // Interaction endpoint — the single bridge into the existing Dex login flow.
    app.get('/AppShield/interaction/:uid', async (req, res) => {
        try {
            const details = await oauthProvider.interactionDetails(req, res);
            const { prompt, params } = details;

            // Resolve the authenticated human from our existing session store.
            const sid = req.cookies.appshield_session;
            const sess = sessions[sid];
            const accountId = sess && sess.expires > Date.now() ? sess.oidcSub : null;
            console.log(`[Auth Service] interaction uid=${details.uid} prompt=${prompt.name} account=${accountId ? 'yes' : 'no'}`);

            if (!accountId) {
                // Not logged in via Dex yet — kick off the EXISTING flow and come back.
                const back = `/AppShield/interaction/${details.uid}`;
                return res.redirect('/nhl-auth/oidc/login?redirect=' + encodeURIComponent(back));
            }

            if (prompt.name === 'login') {
                return oauthProvider.interactionFinished(
                    req, res, { login: { accountId } }, { mergeWithLastSubmission: false }
                );
            }

            if (prompt.name === 'consent') {
                // Canonical auto-grant (first-party): grant exactly what oidc-provider
                // reports as missing — OIDC scopes/claims AND per-resource scopes — so
                // the consent prompt is fully satisfied and the provider doesn't loop
                // back asking for more.
                const grant = details.grantId
                    ? await oauthProvider.Grant.find(details.grantId)
                    : new oauthProvider.Grant({ accountId, clientId: params.client_id });
                const d = prompt.details;
                if (d.missingOIDCScope) grant.addOIDCScope(d.missingOIDCScope.join(' '));
                if (d.missingOIDCClaims) grant.addOIDCClaims(d.missingOIDCClaims);
                if (d.missingResourceScopes) {
                    for (const [indicator, scopes] of Object.entries(d.missingResourceScopes)) {
                        grant.addResourceScope(indicator, scopes.join(' '));
                    }
                }
                const grantId = await grant.save();
                return oauthProvider.interactionFinished(
                    req, res, { consent: { grantId } }, { mergeWithLastSubmission: true }
                );
            }

            // Unknown prompt — finish with what we have.
            return oauthProvider.interactionFinished(req, res, { login: { accountId } });
        } catch (err) {
            console.error('[Auth Service] interaction error:', err);
            res.status(500).send('Interaction error: ' + err.message);
        }
    });

    // --- Admin API + page (human-session gated) -----------------------------
    app.get('/AppShield/oauth', pageRequireHumanSession, (req, res) => {
        res.type('html').send(OAUTH_ADMIN_PAGE);
    });

    app.get('/AppShield/oauth/info', requireHumanSession, (req, res) => {
        res.json({
            issuer: OAUTH_ISSUER,
            resource: OAUTH_RESOURCE,
            authorization_endpoint: `${OAUTH_ISSUER}/AppShield/oidc/auth`,
            token_endpoint: `${OAUTH_ISSUER}/AppShield/oidc/token`,
            registration_endpoint: `${OAUTH_ISSUER}/AppShield/oidc/reg`,
            scopes_supported: [OAUTH_SCOPE],
        });
    });

    app.get('/AppShield/oauth/clients', requireHumanSession, async (req, res) => {
        const dir = path.join(OAUTH_DATA_DIR, 'Client');
        let out = [];
        try {
            for (const f of fs.readdirSync(dir)) {
                if (!f.endsWith('.json')) continue;
                const doc = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
                const c = doc.payload || {};
                out.push({
                    client_id: c.client_id,
                    client_name: c.client_name || null,
                    redirect_uris: c.redirect_uris || [],
                    origin: c.appshield_origin || 'dcr',
                });
            }
        } catch (e) { /* no clients dir yet */ }
        res.json(out);
    });

    app.post('/AppShield/oauth/clients', requireHumanSession, async (req, res) => {
        const { name, redirect_uris } = req.body || {};
        const uris = Array.isArray(redirect_uris)
            ? redirect_uris.map((u) => String(u).trim()).filter(Boolean)
            : [];
        if (!uris.length) {
            return res.status(400).json({ error: 'At least one redirect_uri is required' });
        }
        const client_id = crypto.randomBytes(16).toString('hex');
        const client_secret = crypto.randomBytes(32).toString('hex');
        const metadata = {
            client_id,
            client_secret,
            client_name: (name && String(name).trim()) || client_id,
            redirect_uris: uris,
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_basic',
            scope: `openid ${OAUTH_SCOPE} offline_access`,
            appshield_origin: 'manual',
        };
        await new OAuthFileAdapter('Client').upsert(client_id, metadata);
        res.json({
            client_id,
            client_secret,
            authorization_endpoint: `${OAUTH_ISSUER}/AppShield/oidc/auth`,
            token_endpoint: `${OAUTH_ISSUER}/AppShield/oidc/token`,
            scope: `openid ${OAUTH_SCOPE} offline_access`,
        });
    });

    app.delete('/AppShield/oauth/clients/:id', requireHumanSession, async (req, res) => {
        await new OAuthFileAdapter('Client').destroy(req.params.id);
        res.json({ revoked: req.params.id });
    });

    console.log(`[Auth Service] OAuth provider ready (issuer=${OAUTH_ISSUER}, resource=${OAUTH_RESOURCE})`);
}

// Start server
app.listen(PORT, () => {
    console.log('=====================================');
    console.log('[Auth Service] Started successfully');
    console.log(`[Auth Service] Listening on port ${PORT}`);
    console.log(`[Auth Service] Username configured: ${USERNAME ? 'Yes' : 'No'}`);
    console.log(`[Auth Service] Password configured: ${PASSWORD ? 'Yes' : 'No'}`);
    console.log(`[Auth Service] OIDC enabled: ${OIDC_ENABLED ? `Yes (registrar=${OIDC_REGISTRAR_URL})` : 'No'}`);
    console.log(`[Auth Service] Session duration: ${SESSION_DURATION_HOURS} hours`);
    console.log(`[Auth Service] OAuth enabled: ${OAUTH_ENABLED ? `Yes (resource=${OAUTH_RESOURCE})` : 'No'}`);
    console.log(`[Auth Service] Identity headers: ${IDENTITY_HEADERS ? 'on' : 'off'}` +
        (IDENTITY_HEADERS ? ` (assertion: ${IDENTITY_ASSERTION_SECRET ? `signed, ${IDENTITY_ASSERTION_TTL_SECONDS}s` : 'unsigned headers only'})` : ''));
    console.log(`[Auth Service] Required groups: ${REQUIRED_GROUPS.length ? REQUIRED_GROUPS.join(',') : '(none — any authenticated identity)'}`);
    console.log(`[Auth Service] Control API (session revocation): ${IDENTITY_ASSERTION_SECRET ? 'enabled' : 'disabled (no IDENTITY_ASSERTION_SECRET)'}`);
    if (IDENTITY_ASSERTION_SECRET && !IDENTITY_HEADERS) {
        console.warn('[Auth Service] WARNING: IDENTITY_ASSERTION_SECRET is set but IDENTITY_HEADERS is off — no identity is forwarded.');
    }
    if (REQUIRED_GROUPS.length && !OIDC_ENABLED) {
        console.warn('[Auth Service] WARNING: OIDC_REQUIRED_GROUPS is set but OIDC is off — no identity carries groups, so it has no effect.');
    }
    console.log('=====================================');

    if (OAUTH_ENABLED) {
        bootstrapOauthProvider().catch((err) => {
            console.error('[Auth Service] OAuth bootstrap failed (human auth unaffected):', err);
        });
    }
});
