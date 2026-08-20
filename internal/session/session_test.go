package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixedNow(ms int64) func() time.Time {
	return func() time.Time { return time.UnixMilli(ms) }
}

const nowMS = int64(1_700_000_000_000)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data", "sessions.json")
	s := Open(path, fixedNow(nowMS))
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestCreateGetDelete(t *testing.T) {
	s, _ := newStore(t)

	id, err := s.Create(&Session{Expires: nowMS + 1000, PasswordHash: "ph"})
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 64 {
		t.Errorf("session id is %d chars, want 64 (32 random bytes hex)", len(id))
	}
	if _, ok := s.Get(id); !ok {
		t.Fatal("session not found after Create")
	}
	if s.Count() != 1 {
		t.Errorf("Count = %d, want 1", s.Count())
	}
	s.Delete(id)
	if _, ok := s.Get(id); ok {
		t.Error("session survived Delete")
	}
}

func TestSessionIDsAreUnique(t *testing.T) {
	s, _ := newStore(t)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := s.Create(&Session{Expires: nowMS + 1000, PasswordHash: "ph"})
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatal("duplicate session id")
		}
		seen[id] = true
	}
}

func TestGetExpiresLazily(t *testing.T) {
	s, _ := newStore(t)
	id, _ := s.Create(&Session{Expires: nowMS - 1, PasswordHash: "ph"})
	if _, ok := s.Get(id); ok {
		t.Error("an expired session was returned")
	}
	if s.Count() != 0 {
		t.Error("an expired session should be removed when looked up")
	}
}

func TestSweep(t *testing.T) {
	s, _ := newStore(t)
	live, _ := s.Create(&Session{Expires: nowMS + 10_000, PasswordHash: "ph"})
	s.Create(&Session{Expires: nowMS - 1, PasswordHash: "ph"})
	s.Create(&Session{Expires: nowMS - 5000, OIDCSub: "u"})

	if n := s.Sweep(); n != 2 {
		t.Errorf("Sweep removed %d, want 2", n)
	}
	if _, ok := s.Get(live); !ok {
		t.Error("Sweep removed a live session")
	}
}

func TestRevokeByPredicate(t *testing.T) {
	s, _ := newStore(t)
	alice, _ := s.Create(&Session{Expires: nowMS + 10_000, OIDCSub: "alice", Claims: &Claims{User: "alice"}})
	bob, _ := s.Create(&Session{Expires: nowMS + 10_000, OIDCSub: "bob", Claims: &Claims{User: "bob"}})

	n := s.Revoke(func(_ string, sess *Session) bool { return sess.OIDCSub == "alice" })
	if n != 1 {
		t.Errorf("Revoke returned %d, want 1", n)
	}
	if _, ok := s.Get(alice); ok {
		t.Error("alice's session survived")
	}
	if _, ok := s.Get(bob); !ok {
		t.Error("bob's session should be untouched")
	}
}

// The `except` case: an operator resetting their own password must not be
// logged out of the page they are on.
func TestRevokeCanSpareSpecificSessions(t *testing.T) {
	s, _ := newStore(t)
	keep, _ := s.Create(&Session{Expires: nowMS + 10_000, OIDCSub: "alice"})
	drop, _ := s.Create(&Session{Expires: nowMS + 10_000, OIDCSub: "alice"})

	s.Revoke(func(id string, sess *Session) bool {
		return sess.OIDCSub == "alice" && id != keep
	})
	if _, ok := s.Get(keep); !ok {
		t.Error("the spared session was revoked")
	}
	if _, ok := s.Get(drop); ok {
		t.Error("the other session survived")
	}
}

// --- persistence ---------------------------------------------------------

func TestSaveIsDebouncedTrailingEdge(t *testing.T) {
	s, path := newStore(t)
	s.Create(&Session{Expires: nowMS + 10_000, PasswordHash: "ph"})

	// Nothing should have hit the disk yet: the write is on a trailing edge.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the store wrote immediately instead of debouncing")
	}
	// A burst inside the window is absorbed into the same write.
	for i := 0; i < 20; i++ {
		s.Create(&Session{Expires: nowMS + 10_000, PasswordHash: "ph"})
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the debounced write never happened: %v", err)
	}
	var onDisk map[string]*Session
	if err := json.Unmarshal(blob, &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != 21 {
		t.Errorf("persisted %d sessions, want 21", len(onDisk))
	}
}

// Session ids are bearer secrets. 2.x got this right for sessions.json and
// wrong for the OAuth token store; it must be right in both places here.
func TestSessionFileIsNotWorldReadable(t *testing.T) {
	s, path := newStore(t)
	s.Create(&Session{Expires: nowMS + 10_000, PasswordHash: "ph"})
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("sessions file mode is %o, want no group/other access", perm)
	}
}

// 2.x had no SIGTERM handler, so a pending debounced write was lost on stop.
func TestCloseFlushesPendingWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	s := Open(path, fixedNow(nowMS))
	id, _ := s.Create(&Session{Expires: nowMS + 10_000, PasswordHash: "ph"})

	if err := s.Close(); err != nil { // immediately, before the debounce fires
		t.Fatal(err)
	}

	reopened := Open(path, fixedNow(nowMS))
	if _, ok := reopened.Get(id); !ok {
		t.Error("the session was lost on shutdown")
	}
}

func TestRoundTripPreservesAllFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	s := Open(path, fixedNow(nowMS))
	want := &Session{
		Expires: nowMS + 10_000,
		OIDCSub: "sub-1",
		Claims:  &Claims{Sub: "sub-1", User: "alice", Email: "a@e.com", Name: "Alice", Groups: []string{"g1", "g2"}},
		IDToken: "eyJhbGc.payload.sig",
		OIDCSid: "sid-9",
	}
	id, _ := s.Create(want)
	s.Close()

	got, ok := Open(path, fixedNow(nowMS)).Get(id)
	if !ok {
		t.Fatal("session missing after reload")
	}
	if got.OIDCSub != want.OIDCSub || got.IDToken != want.IDToken || got.OIDCSid != want.OIDCSid {
		t.Errorf("scalar fields differ: %+v", got)
	}
	if got.Claims == nil || got.Claims.User != "alice" || len(got.Claims.Groups) != 2 {
		t.Errorf("claims not preserved: %+v", got.Claims)
	}
}

// The upgrade path: a file written by 2.x must load, minus what 3.0 no longer
// honours. Note `authHash` and the unknown field, both of which 2.x could write.
func TestLoadsRealV2SessionsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	v2 := `{
      "aaaa": {"expires": 1800000000000, "passwordHash": "abc123"},
      "bbbb": {"expires": 1800000000000, "oidcSub": "user-1",
               "claims": {"sub":"user-1","user":"alice","email":"a@e.com","groups":["admins"]},
               "idToken": "eyJ.x.y"},
      "cccc": {"expires": 1800000000000, "oidcSub": "user-2", "oidcSid": "sid-2"},
      "dddd": {"expires": 1500000000000, "passwordHash": "expired"},
      "eeee": {"expires": 1800000000000, "authHash": "deadbeef"},
      "ffff": {"expires": 1800000000000, "oidcSub": "user-3", "someFutureField": 42}
    }`
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	s := Open(path, fixedNow(nowMS))
	defer s.Close()

	for _, id := range []string{"aaaa", "bbbb", "cccc", "ffff"} {
		if _, ok := s.Get(id); !ok {
			t.Errorf("session %s should have survived the upgrade", id)
		}
	}
	// Expired.
	if _, ok := s.Get("dddd"); ok {
		t.Error("an expired session was loaded")
	}
	// AUTH_HASH is gone in 3.0, so its sessions have no usable credential.
	if _, ok := s.Get("eeee"); ok {
		t.Error("an authHash-only session should be dropped")
	}
	if s.Count() != 4 {
		t.Errorf("Count = %d, want 4", s.Count())
	}
	// Claims survive the round trip through the Go structs.
	sess, _ := s.Get("bbbb")
	if sess.Claims == nil || sess.Claims.User != "alice" || sess.Claims.Groups[0] != "admins" {
		t.Errorf("claims lost: %+v", sess.Claims)
	}
}

// Expires is milliseconds since the epoch, as Date.now() wrote it. Getting the
// unit wrong would silently expire or immortalise every session.
func TestExpiresIsMilliseconds(t *testing.T) {
	s, _ := newStore(t)
	got := s.NewExpiry(720 * time.Hour)
	want := time.UnixMilli(nowMS).Add(720 * time.Hour).UnixMilli()
	if got != want {
		t.Errorf("NewExpiry = %d, want %d", got, want)
	}
	if got < 1_000_000_000_000 {
		t.Errorf("NewExpiry = %d looks like seconds, not milliseconds", got)
	}
}

func TestCorruptFileStartsEmptyRatherThanFailing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	os.WriteFile(path, []byte("{not json"), 0o600)

	s := Open(path, fixedNow(nowMS))
	defer s.Close()
	if s.Count() != 0 {
		t.Errorf("Count = %d, want 0", s.Count())
	}
	// The store must still be usable.
	if _, err := s.Create(&Session{Expires: nowMS + 1000, PasswordHash: "ph"}); err != nil {
		t.Errorf("store unusable after a corrupt load: %v", err)
	}
}

func TestMissingFileIsNormal(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "nope", "sessions.json"), fixedNow(nowMS))
	defer s.Close()
	if s.Count() != 0 {
		t.Error("expected an empty store")
	}
}

// Most deployments do not mount /data; an empty path must simply disable
// persistence rather than error on every mutation.
func TestEmptyPathDisablesPersistence(t *testing.T) {
	s := Open("", fixedNow(nowMS))
	id, err := s.Create(&Session{Expires: nowMS + 1000, PasswordHash: "ph"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(id); !ok {
		t.Error("in-memory sessions should still work")
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close with no path: %v", err)
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	s, _ := newStore(t)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				id, err := s.Create(&Session{Expires: nowMS + 10_000, PasswordHash: "ph"})
				if err != nil {
					return
				}
				s.Get(id)
				s.Count()
				s.Delete(id)
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
