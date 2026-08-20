// Command appshield is the authentication gate: a single static binary that
// replaces the nginx + Node sidecar pair used through 2.x.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/yundera/appshield/internal/authn"
	"github.com/yundera/appshield/internal/broker"
	"github.com/yundera/appshield/internal/config"
	"github.com/yundera/appshield/internal/identity"
	"github.com/yundera/appshield/internal/oidcrp"
	"github.com/yundera/appshield/internal/proxy"
	"github.com/yundera/appshield/internal/router"
	"github.com/yundera/appshield/internal/session"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "3.0.0-dev"

// sessionSweep reclaims memory held by sessions nobody returns for. Lookups
// also expire lazily, so this is housekeeping rather than enforcement.
const sessionSweep = time.Hour

func main() {
	log.SetFlags(0)
	log.SetPrefix("[appshield] ")

	if err := run(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}

func run() error {
	tuneRuntime()

	cfg, warns, err := config.FromEnv()
	for _, w := range warns {
		log.Printf("WARNING: %s", w)
	}
	if err != nil {
		return err
	}

	banner(cfg)

	sessions := session.Open(cfg.SessionsFile, time.Now)
	defer func() {
		if err := sessions.Close(); err != nil {
			log.Printf("WARNING: final session flush failed: %v", err)
		}
	}()

	prop := &identity.Propagator{
		Enabled:  cfg.IdentityHeaders,
		Secret:   []byte(cfg.AssertionSecret),
		TTL:      cfg.AssertionTTL,
		Audience: cfg.AppName,
	}

	gate := authn.New(authn.Deps{Cfg: cfg, Sessions: sessions, Prop: prop})

	nhlAuth := http.NewServeMux()
	gate.RegisterRoutes(nhlAuth)

	if cfg.Mode == config.AuthOIDC {
		rp := oidcrp.New(cfg, sessions, time.Now)
		rp.RegisterRoutes(nhlAuth)
		// Lets logout end the IdP session too, not just the local one.
		gate.Logout = rp
	}

	var brokerHandler http.Handler
	if cfg.OAuthEnabled {
		b, err := broker.New(cfg, sessions, time.Now)
		if err != nil {
			return fmt.Errorf("oauth broker: %w", err)
		}
		brokerHandler = b.Handler()
		// Lets the gate accept the broker's own access tokens on the
		// protected path.
		gate.Bearer = b

		stopOAuthSweep := make(chan struct{})
		go b.SweepEvery(30*time.Minute, stopOAuthSweep)
		defer close(stopOAuthSweep)
	}

	// The gate must consult the authenticator whenever anything can grant
	// access — including a broker token on an otherwise unauthenticated app.
	var auth router.Authenticator
	if cfg.Mode != config.AuthNone || cfg.OAuthEnabled {
		auth = gate
	}

	rt := router.New(router.Deps{
		Cfg:        cfg,
		Auth:       auth,
		Login:      gate.LoginPage(),
		NhlAuth:    nhlAuth,
		Broker:     brokerHandler,
		Proxy:      proxy.New(cfg),
		Propagator: prop,
	})

	srv := &http.Server{
		Addr:    ":" + strconv.Itoa(cfg.ListenPort),
		Handler: rt,
		// No ReadTimeout or WriteTimeout: they would cap websocket and SSE
		// connections, which the gate must carry for as long as the backend
		// keeps them open. ReadHeaderTimeout still bounds slowloris.
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       65 * time.Second, // matches nginx keepalive_timeout 65
	}

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", srv.Addr, err)
	}

	stopSweeper := make(chan struct{})
	go sessions.SweepEvery(sessionSweep, stopSweeper)
	defer close(stopSweeper)

	// Everything below is steady state; hand back whatever the boot allocated.
	debug.FreeOSMemory()

	errc := make(chan error, 1)
	go func() {
		log.Printf("listening on :%d, proxying to %s:%d", cfg.ListenPort, cfg.BackendHost, cfg.BackendPort)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	log.Print("shutting down")
	// 2.x had no shutdown handler, so a pending debounced session write was
	// simply lost on stop. The deferred sessions.Close above makes it durable.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// tuneRuntime trades a little throughput for a much smaller resident set. The
// gate is an I/O-bound sidecar that idles most of the time; the whole point of
// 3.0 is that ~45 copies of it fit comfortably on a 4 GB box.
func tuneRuntime() {
	// A sidecar has no business spinning up one P per core on a 16-core host:
	// each costs stacks and per-P caches for work that is almost entirely I/O.
	if runtime.GOMAXPROCS(0) > 2 {
		runtime.GOMAXPROCS(2)
	}
	// Collect more eagerly than the default 100%. Garbage here is small and
	// short-lived, so the CPU cost is negligible against the RSS saved.
	debug.SetGCPercent(20)
	// A backstop, not a target: keeps a traffic spike from ratcheting the heap
	// permanently, since freed heap is only slowly returned to the OS.
	debug.SetMemoryLimit(64 << 20)
}

func banner(c *config.Config) {
	log.Printf("AppShield %s", version)
	log.Printf("  mode            %s", c.Mode)
	log.Printf("  backend         %s:%d", c.BackendHost, c.BackendPort)
	log.Printf("  listen          :%d", c.ListenPort)
	if c.AppName != "" {
		log.Printf("  app             %s", c.AppName)
	}
	if len(c.AppHosts) > 0 {
		log.Printf("  public hosts    %v", c.AppHosts)
		log.Printf("  canonical       %s", c.CanonicalOrigin)
	}
	if c.Mode == config.AuthOIDC {
		log.Printf("  registrar       %s", c.RegistrarURL)
		if len(c.RequiredGroups) > 0 {
			log.Printf("  required groups %v", c.RequiredGroups)
		}
	}
	if c.OAuthEnabled {
		log.Printf("  oauth resource  %s (scope %q, protecting %s)", c.OAuthResource, c.OAuthScope, c.OAuthProtectedPath)
	}
	log.Printf("  identity        %s", onOff(c.IdentityHeaders))
	if c.AssertionSecret != "" {
		log.Printf("  assertion       on (ttl %s)", c.AssertionTTL)
	}
	log.Printf("  sessions        %s (%s)", c.SessionsFile, c.SessionDuration)
	if len(c.AllowedPaths) > 0 {
		log.Printf("  bypass paths    %v", c.AllowedPaths)
	}
	if len(c.AllowedExtensions) > 0 {
		log.Printf("  bypass exts     %v", c.AllowedExtensions)
	}
	if c.AllowHashContentPaths {
		log.Print("  bypass          40-hex content paths")
	}
	if c.Debug {
		log.Print("  debug           on (per-request logging)")
	}
	_ = os.Stdout.Sync()
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
