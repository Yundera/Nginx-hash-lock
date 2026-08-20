// Package session stores who is logged in.
//
// The on-disk format is deliberately unchanged from 2.x so an upgrade does not
// log everybody out: same JSON shape, same field names, same millisecond
// timestamps. Sessions whose only credential was AUTH_HASH are dropped on load,
// since 3.0 removed that mechanism.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CookieName is the session cookie. Host-only by design (no Domain attribute),
// so each app's gate holds its own session — which is precisely why OIDC
// back-channel logout is needed to end them all at once.
const CookieName = "appshield_session"

// saveDebounce coalesces bursts of mutations into one write, matching the
// 100 ms trailing-edge debounce in app.js:190-205.
const saveDebounce = 100 * time.Millisecond

// Claims is the identity an OIDC login produced. Additive: sessions restored
// from an older file simply have none and degrade to just the subject.
type Claims struct {
	Sub    string   `json:"sub,omitempty"`
	User   string   `json:"user,omitempty"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Session is one logged-in browser. Exactly one credential field is set.
type Session struct {
	// Expires is milliseconds since the Unix epoch, as written by Date.now()
	// in 2.x. Keeping the unit is what makes the file interchangeable.
	Expires int64 `json:"expires"`

	PasswordHash string `json:"passwordHash,omitempty"`

	OIDCSub string  `json:"oidcSub,omitempty"`
	Claims  *Claims `json:"claims,omitempty"`
	// IDToken is kept for RP-initiated logout's id_token_hint.
	IDToken string `json:"idToken,omitempty"`
	// OIDCSid is the OP's session id, used to match back-channel logout tokens.
	OIDCSid string `json:"oidcSid,omitempty"`
}

func (s *Session) expired(nowMS int64) bool { return s.Expires < nowMS }

// Store is an in-memory map with write-through persistence.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session

	path string
	now  func() time.Time

	saveMu    sync.Mutex
	saveTimer *time.Timer
	closed    bool
}

// Open loads the store from path. A missing file is normal (most deployments
// do not mount /data); a corrupt one is logged and treated as empty rather
// than being allowed to stop the gate from booting.
func Open(path string, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	s := &Store{
		sessions: map[string]*Session{},
		path:     path,
		now:      now,
	}
	// Most deployments do not mount a volume at /data. Find that out once, at
	// boot, rather than failing on every debounced write for the life of the
	// process.
	if s.path != "" {
		if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
			log.Printf("[session] %s is not writable (%v) — sessions will be kept in memory only "+
				"and will not survive a restart; mount a volume at /data to persist them",
				filepath.Dir(s.path), err)
			s.path = ""
		}
	}
	s.load()
	return s
}

func (s *Store) nowMS() int64 { return s.now().UnixMilli() }

func (s *Store) load() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[session] cannot read %s (%v) — starting empty", s.path, err)
		}
		return
	}
	var onDisk map[string]*Session
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		log.Printf("[session] %s is corrupt (%v) — starting empty", s.path, err)
		return
	}

	nowMS := s.nowMS()
	var expired, orphaned int
	for id, sess := range onDisk {
		if sess == nil || sess.expired(nowMS) {
			expired++
			continue
		}
		// A session whose only credential was AUTH_HASH cannot be
		// re-validated now that the mechanism is gone.
		if sess.PasswordHash == "" && sess.OIDCSub == "" {
			orphaned++
			continue
		}
		s.sessions[id] = sess
	}
	log.Printf("[session] loaded %d session(s) from %s (%d expired, %d without a usable credential)",
		len(s.sessions), s.path, expired, orphaned)
}

// Get returns a live session. An expired one is removed and reported missing,
// so callers never have to check the deadline themselves.
func (s *Store) Get(id string) (*Session, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if sess.expired(s.nowMS()) {
		s.Delete(id)
		return nil, false
	}
	return sess, true
}

// Create stores a session under a fresh 32-byte identifier.
func (s *Store) Create(sess *Session) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()

	s.saveSoon()
	return id, nil
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	_, existed := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()
	if existed {
		s.saveSoon()
	}
}

// Count reports live sessions, for the health endpoint.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// Revoke deletes every session matching pred and returns how many went. Used
// by the control API and by back-channel logout.
func (s *Store) Revoke(pred func(id string, sess *Session) bool) int {
	s.mu.Lock()
	var gone int
	for id, sess := range s.sessions {
		if pred(id, sess) {
			delete(s.sessions, id)
			gone++
		}
	}
	s.mu.Unlock()
	if gone > 0 {
		s.saveSoon()
	}
	return gone
}

// Sweep drops expired sessions. Called hourly; Get also expires lazily, so this
// only reclaims memory for sessions nobody comes back for.
func (s *Store) Sweep() int {
	nowMS := s.nowMS()
	return s.Revoke(func(_ string, sess *Session) bool { return sess.expired(nowMS) })
}

// SweepEvery runs Sweep until ctx-like stop channel closes.
func (s *Store) SweepEvery(d time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if n := s.Sweep(); n > 0 {
				log.Printf("[session] swept %d expired session(s)", n)
			}
		}
	}
}

// saveSoon arms the debounce. The timer is cleared before the write runs, so a
// mutation that lands during the write schedules another pass rather than
// being swallowed.
func (s *Store) saveSoon() {
	if s.path == "" {
		return
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.closed || s.saveTimer != nil {
		return
	}
	s.saveTimer = time.AfterFunc(saveDebounce, func() {
		s.saveMu.Lock()
		s.saveTimer = nil
		s.saveMu.Unlock()
		if err := s.Flush(); err != nil {
			log.Printf("[session] save failed: %v", err)
		}
	})
}

// Flush writes the store to disk now. Safe to call concurrently.
func (s *Store) Flush() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	blob, err := json.Marshal(s.sessions)
	s.mu.RUnlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sessions-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	// Session ids are bearer secrets: never leave them group- or world-readable.
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return err
	}
	// 2.x renamed without syncing, so a power cut could leave the rename
	// durable but the contents not.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// Close stops the debounce timer and performs a final synchronous write. 2.x
// had no shutdown handler, so a pending 100 ms save was simply lost on stop.
func (s *Store) Close() error {
	s.saveMu.Lock()
	s.closed = true
	if s.saveTimer != nil {
		s.saveTimer.Stop()
		s.saveTimer = nil
	}
	s.saveMu.Unlock()
	return s.Flush()
}

// NewExpiry returns the Expires value for a session created now.
func (s *Store) NewExpiry(d time.Duration) int64 {
	return s.now().Add(d).UnixMilli()
}
