package broker

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Model names. The on-disk layout is deliberately the one oidc-provider's file
// adapter used in 2.x, so an existing /data/oauth directory keeps working and
// live refresh tokens survive the cutover.
//
// In oidc-provider's opaque token format the value handed to the client IS the
// storage document id, so a refresh token a client holds today is literally a
// filename under RefreshToken/.
const (
	modelClient        = "Client"
	modelRefreshToken  = "RefreshToken"
	modelAuthCode      = "AuthorizationCode"
	modelAuthRequest   = "AuthRequest"
	modelRegistrationT = "RegistrationAccessToken"
	grantIndexDir      = "_grant"
)

// expiringModels are swept on a timer. Client has no expiry, and grant index
// files are cleaned up when the grant is revoked.
var expiringModels = []string{modelRefreshToken, modelAuthCode, modelAuthRequest, modelRegistrationT}

// legacyModels are 2.x directories 3.0 no longer writes. They are left alone
// unless OAUTH_LEGACY_SWEEP is set, so a rollback to the Node image still finds
// its state intact.
var legacyModels = []string{"AccessToken", "Session", "Grant", "Interaction", "DeviceCode"}

// document is the on-disk envelope, matching oauthFileAdapter.js.
type document struct {
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt int64           `json:"expiresAt"` // ms since epoch, 0 = no expiry
}

// store is a small file-backed key-value store.
//
// Files are written 0600 into 0700 directories. 2.x used the default mode,
// which left every live refresh token as a world-readable filename in a
// world-readable directory.
type store struct {
	dir string
	now func() time.Time

	// grantMu serialises read-modify-write on the grant index files, which
	// Node got for free from the single-threaded event loop.
	grantMu sync.Mutex
}

func newStore(dir string, now func() time.Time) (*store, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("OAUTH_DATA_DIR %s is not writable (%w). The broker stores its signing "+
			"key and registered clients there, so it needs a persistent volume mounted at that path", dir, err)
	}
	return &store{dir: dir, now: now}, nil
}

// path is <dir>/<model>/<escaped id>.json. Escaping keeps an id containing a
// slash from escaping its directory.
func (s *store) path(model, id string) string {
	return filepath.Join(s.dir, model, url.QueryEscape(id)+".json")
}

func (s *store) nowMS() int64 { return s.now().UnixMilli() }

// put writes a document, replacing any existing one atomically.
func (s *store) put(model, id string, payload any, ttl time.Duration) error {
	blob, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	doc := document{Payload: blob}
	if ttl > 0 {
		doc.ExpiresAt = s.now().Add(ttl).UnixMilli()
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return s.writeFile(s.path(model, id), out)
}

func (s *store) writeFile(dst string, blob []byte) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, dst)
}

// errNotFound is returned for a missing, expired or unreadable document.
var errNotFound = errors.New("not found")

// get decodes a document into v. An expired document is destroyed and reported
// missing. A corrupt file reads as "not found" rather than failing the request,
// matching 2.x — a token nobody can parse is a token nobody can use.
func (s *store) get(model, id string, v any) error {
	if id == "" {
		return errNotFound
	}
	raw, err := os.ReadFile(s.path(model, id))
	if err != nil {
		return errNotFound
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return errNotFound
	}
	if doc.ExpiresAt != 0 && doc.ExpiresAt < s.nowMS() {
		_ = s.destroy(model, id)
		return errNotFound
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(doc.Payload, v); err != nil {
		return errNotFound
	}
	return nil
}

func (s *store) destroy(model, id string) error {
	err := os.Remove(s.path(model, id))
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// claim atomically takes ownership of a single-use document, decoding it into
// v. Exactly one caller can succeed.
//
// Node inherited this atomicity from the event loop; Go has real concurrency,
// so two simultaneous redemptions of one authorization code could otherwise
// both succeed. Renaming is the atomic primitive the filesystem gives us: the
// loser sees ENOENT.
func (s *store) claim(model, id string, v any) error {
	if id == "" {
		return errNotFound
	}
	src := s.path(model, id)

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	dst := src + ".claimed." + hex.EncodeToString(nonce)

	if err := os.Rename(src, dst); err != nil {
		return errNotFound // already claimed, or never existed
	}
	defer os.Remove(dst)

	raw, err := os.ReadFile(dst)
	if err != nil {
		return errNotFound
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return errNotFound
	}
	if doc.ExpiresAt != 0 && doc.ExpiresAt < s.nowMS() {
		return errNotFound
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(doc.Payload, v); err != nil {
		return errNotFound
	}
	return nil
}

// list returns every live id in a model.
func (s *store) list(model string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, model))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		id, err := url.QueryUnescape(strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue
		}
		if err := s.get(model, id, nil); err != nil {
			continue // expired or corrupt
		}
		out = append(out, id)
	}
	return out, nil
}

// --- grant index ---------------------------------------------------------
//
// _grant/<grantId>.json holds ["Model/id", ...] so every token issued under one
// grant can be revoked together. The format is 2.x's, so grants created by the
// Node image remain revocable.

func (s *store) addToGrant(grantID, model, id string) error {
	if grantID == "" {
		return nil
	}
	s.grantMu.Lock()
	defer s.grantMu.Unlock()

	refs, _ := s.grantRefs(grantID)
	ref := model + "/" + id
	for _, existing := range refs {
		if existing == ref {
			return nil
		}
	}
	refs = append(refs, ref)
	blob, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	return s.writeFile(filepath.Join(s.dir, grantIndexDir, url.QueryEscape(grantID)+".json"), blob)
}

func (s *store) grantRefs(grantID string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, grantIndexDir, url.QueryEscape(grantID)+".json"))
	if err != nil {
		return nil, err
	}
	var refs []string
	if err := json.Unmarshal(raw, &refs); err != nil {
		return nil, err
	}
	return refs, nil
}

// revokeGrant destroys everything issued under a grant.
func (s *store) revokeGrant(grantID string) int {
	s.grantMu.Lock()
	defer s.grantMu.Unlock()

	refs, err := s.grantRefs(grantID)
	if err != nil {
		return 0
	}
	var n int
	for _, ref := range refs {
		model, id, ok := strings.Cut(ref, "/")
		if !ok {
			continue
		}
		if s.destroy(model, id) == nil {
			n++
		}
	}
	_ = os.Remove(filepath.Join(s.dir, grantIndexDir, url.QueryEscape(grantID)+".json"))
	return n
}

// --- sweeper -------------------------------------------------------------

// sweep removes expired documents. 2.x expired lazily on read only, so a
// document nobody looked up again stayed on disk for ever and the directory
// grew without bound.
func (s *store) sweep(includeLegacy bool) int {
	models := append([]string{}, expiringModels...)
	if includeLegacy {
		models = append(models, legacyModels...)
	}
	var n int
	for _, model := range models {
		entries, err := os.ReadDir(filepath.Join(s.dir, model))
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() {
				continue
			}
			// Clean up any claim file abandoned by a crash mid-redemption.
			if strings.Contains(name, ".claimed.") || strings.HasPrefix(name, ".tmp-") {
				full := filepath.Join(s.dir, model, name)
				if fi, err := e.Info(); err == nil && s.now().Sub(fi.ModTime()) > time.Hour {
					if os.Remove(full) == nil {
						n++
					}
				}
				continue
			}
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			id, err := url.QueryUnescape(strings.TrimSuffix(name, ".json"))
			if err != nil {
				continue
			}
			// get() destroys anything expired as a side effect.
			if err := s.get(model, id, nil); err == errNotFound {
				n++
			}
		}
	}
	return n
}

func (s *store) sweepEvery(d time.Duration, includeLegacy bool, stop <-chan struct{}) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if n := s.sweep(includeLegacy); n > 0 {
				log.Printf("[oauth] swept %d expired document(s)", n)
			}
		}
	}
}

// randomID produces an opaque token value. It doubles as the storage document
// id, which is what makes 2.x's tokens readable by this implementation.
func randomID(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
