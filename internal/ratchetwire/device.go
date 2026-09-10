package ratchetwire

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Multi-device state sync.
//
// THE PROBLEM. A double ratchet is a linear chain with a send counter (§Session.ns).
// Two devices holding the same session state and BOTH sending will use the same
// counter value for different messages. That is not a privacy leak — it is a
// keystream reuse, which breaks confidentiality of both messages outright. So
// "sync the state" is not a convenience feature; getting it wrong is the most
// severe failure mode in the whole protocol.
//
// WHAT THIS DOES. Every device gets a stable id that is INDEPENDENT of the
// messaging identity (two devices of one identity must be distinguishable, or
// concurrent use is invisible). State can be exported as an encrypted bundle
// and imported on another device. Every import and every send is recorded in a
// local ledger, and the ledger makes the dangerous case VISIBLE: if this device
// has sent since it last synced and another device also holds the session, the
// two send chains may already have collided.
//
// WHAT THIS DOES NOT DO. It cannot prevent two devices from colliding in the
// window before they sync — no purely local mechanism can, because neither
// device can see the other's sends. What it does is refuse to send once a
// conflict is known, and say plainly that the session must be replaced rather
// than silently carrying on with a possibly-reused chain. Making concurrent
// send actually SAFE requires per-device send chains (a wire-format change),
// which is deliberately not attempted here.

const (
	deviceFile  = "device.json"
	ledgerFile  = "sync-ledger.json"
	bundleLabel = "spore/e2/device-bundle/v1"
)

// DeviceState is this installation's stable device identity. It is generated
// once per state directory and never derived from the messaging identity: if it
// were, two devices of one identity would share an id and the ledger below
// could not tell them apart.
type DeviceState struct {
	ID      string `json:"id"`      // hex, 16 bytes
	Created int64  `json:"created"` // unix seconds
}

// LoadOrCreateDevice reads this device's id, creating one on first use.
func LoadOrCreateDevice(dir string) (*DeviceState, error) {
	if dir == "" {
		return nil, errors.New("ratchetwire: empty device directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, deviceFile)
	if b, err := os.ReadFile(p); err == nil {
		var d DeviceState
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, fmt.Errorf("ratchetwire: corrupt %s: %w", deviceFile, err)
		}
		if len(d.ID) != 32 {
			return nil, fmt.Errorf("ratchetwire: %s has a malformed device id", deviceFile)
		}
		return &d, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, err
	}
	d := &DeviceState{ID: hex.EncodeToString(raw), Created: time.Now().Unix()}
	b, _ := json.MarshalIndent(d, "", "  ")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, err
	}
	return d, nil
}

// SessionLedgerEntry records what THIS device knows about one session.
type SessionLedgerEntry struct {
	// LastWriter is the device id that last wrote this session's state here —
	// either this device after a send, or the exporting device after an import.
	LastWriter string `json:"last_writer"`
	// MySends is how many messages this device has sent in this session since
	// it last adopted state from elsewhere. Non-zero plus a foreign LastWriter
	// is the collision signature.
	MySends uint64 `json:"my_sends,omitempty"`
	// Conflict is set once a collision has been detected. It is sticky: it
	// clears only when the session is deleted or state is imported cleanly
	// under a NEW session id.
	Conflict bool `json:"conflict,omitempty"`
	// ConflictWith names the other device, for the error message.
	ConflictWith string `json:"conflict_with,omitempty"`
}

type syncLedger struct {
	Sessions map[string]SessionLedgerEntry `json:"sessions"`
}

func loadLedger(dir string) (*syncLedger, error) {
	p := filepath.Join(dir, ledgerFile)
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &syncLedger{Sessions: map[string]SessionLedgerEntry{}}, nil
		}
		return nil, err
	}
	var l syncLedger
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("ratchetwire: corrupt %s: %w", ledgerFile, err)
	}
	if l.Sessions == nil {
		l.Sessions = map[string]SessionLedgerEntry{}
	}
	return &l, nil
}

func (l *syncLedger) save(dir string) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "ledger-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, filepath.Join(dir, ledgerFile))
}

// SessionRecord is one session inside a bundle. State is the plaintext session
// bytes; the whole bundle is encrypted, so it is never exposed on its own.
type SessionRecord struct {
	ID    string `json:"id"`
	State []byte `json:"state"`
}

// DeviceBundle is a portable, encrypted snapshot of a state directory.
type DeviceBundle struct {
	Version  int    `json:"version"`
	Device   string `json:"device"`   // exporting device id
	Created  int64  `json:"created"`  //
	Sessions []byte `json:"sessions"` // encrypted payload
}

// deriveBundleKey binds bundle encryption to the state key, so only a device
// already provisioned with the same state key can read one. A bundle is NOT a
// way to bootstrap a device that lacks the account's key material.
func deriveBundleKey(stateKey []byte) ([]byte, error) {
	if len(stateKey) != 32 {
		return nil, errors.New("ratchetwire: state key must be 32 bytes")
	}
	r := hkdf.New(sha256.New, stateKey, []byte("spore/e2/device-bundle"), []byte(bundleLabel))
	k := make([]byte, 32)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}

// ExportBundle packages every session in dir into one encrypted bundle.
func ExportBundle(dir string, stateKey []byte, dev *DeviceState) (*DeviceBundle, error) {
	if dev == nil {
		return nil, errors.New("ratchetwire: nil device state")
	}
	store, err := NewFileStateStore(dir, stateKey)
	if err != nil {
		return nil, err
	}
	ids, err := store.IDs()
	if err != nil {
		return nil, err
	}
	sort.Slice(ids, func(i, j int) bool { return hexID(ids[i]) < hexID(ids[j]) })
	recs := make([]SessionRecord, 0, len(ids))
	for _, id := range ids {
		// Load returns decrypted session bytes, so the bundle carries state and
		// not the local at-rest envelope. The bundle is then re-encrypted as a
		// whole; the receiving store protects it again on import.
		st, err := store.Load(id)
		if err != nil {
			return nil, fmt.Errorf("ratchetwire: export session %s: %w", hexID(id), err)
		}
		recs = append(recs, SessionRecord{ID: hexID(id), State: st})
	}
	plain, err := json.Marshal(recs)
	if err != nil {
		return nil, err
	}
	key, err := deriveBundleKey(stateKey)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, []byte(bundleLabel))
	out := append(nonce, ct...)
	return &DeviceBundle{
		Version: 1, Device: dev.ID, Created: time.Now().Unix(), Sessions: out,
	}, nil
}

// ImportReport is the per-session outcome of an import.
type ImportReport struct {
	Imported int
	Conflict []string // session ids where both devices had sent — chain may have collided
}

// ImportBundle applies a bundle to the local store.
//
// It records the exporting device as each session's last writer and clears this
// device's send count for it (this device has now adopted that state). If this
// device had ALSO sent in that session since its last sync, the two send chains
// may already have collided: that session is flagged as a conflict, reported,
// and will refuse to send until it is replaced.
func ImportBundle(dir string, stateKey []byte, b *DeviceBundle, dev *DeviceState) (*ImportReport, error) {
	if dev == nil {
		return nil, errors.New("ratchetwire: nil device state")
	}
	if b == nil || b.Version != 1 {
		return nil, errors.New("ratchetwire: unsupported bundle version")
	}
	key, err := deriveBundleKey(stateKey)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(b.Sessions) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("ratchetwire: bundle payload truncated")
	}
	nonce := b.Sessions[:aead.NonceSize()]
	ct := b.Sessions[aead.NonceSize():]
	// A bundle from a different state key fails authentication here. That is the
	// check that stops one account's history being merged into another's.
	plain, err := aead.Open(nil, nonce, ct, []byte(bundleLabel))
	if err != nil {
		return nil, errors.New("ratchetwire: bundle will not open with this state key (wrong account, or the bundle is damaged)")
	}
	var recs []SessionRecord
	if err := json.Unmarshal(plain, &recs); err != nil {
		return nil, fmt.Errorf("ratchetwire: malformed bundle payload: %w", err)
	}
	store, err := NewFileStateStore(dir, stateKey)
	if err != nil {
		return nil, err
	}
	led, err := loadLedger(dir)
	if err != nil {
		return nil, err
	}
	rep := &ImportReport{}
	for _, r := range recs {
		raw, err := hex.DecodeString(r.ID)
		if err != nil || len(raw) != 8 {
			return nil, fmt.Errorf("ratchetwire: bundle session id %q is not 8 bytes of hex", r.ID)
		}
		if len(r.State) == 0 {
			return nil, fmt.Errorf("ratchetwire: bundle session %s has empty state", r.ID)
		}
		var id [8]byte
		copy(id[:], raw)
		prev := led.Sessions[r.ID]
		// The collision test. MySends counts sends THIS device made since it
		// last adopted state from elsewhere. If it is non-zero, this device has
		// a chain of its own; if the exporter is a different device, that device
		// has one too, and both started from the same counter.
		if prev.MySends > 0 && b.Device != dev.ID {
			prev.Conflict = true
			prev.ConflictWith = b.Device
		}
		if err := store.Save(id, r.State); err != nil {
			return nil, fmt.Errorf("ratchetwire: import session %s: %w", r.ID, err)
		}
		prev.LastWriter = b.Device
		prev.MySends = 0
		led.Sessions[r.ID] = prev
		rep.Imported++
		if prev.Conflict {
			rep.Conflict = append(rep.Conflict, r.ID)
		}
	}
	if err := led.save(dir); err != nil {
		return nil, err
	}
	return rep, nil
}

// ErrSendConflict is returned when a send is refused because this device and
// another have both advanced the same session without syncing.
var ErrSendConflict = errors.New("ratchetwire: refusing to send — this session may already have a colliding send chain")

// CheckSendAllowed is the guard the send path calls before emitting a message.
// It refuses when the ledger knows another device has written this session
// while this device was also sending.
func CheckSendAllowed(dir string, id [8]byte, dev *DeviceState) error {
	if dev == nil {
		return errors.New("ratchetwire: nil device state")
	}
	led, err := loadLedger(dir)
	if err != nil {
		return err
	}
	e, ok := led.Sessions[hexID(id)]
	if !ok {
		return nil // unknown session: nothing recorded, nothing to refuse
	}
	if e.Conflict {
		return fmt.Errorf("%w (session %s collided with device %s — start a NEW session with this contact; continuing this one risks reusing message keys)", ErrSendConflict, hexID(id), shortDev(e.ConflictWith))
	}
	if e.MySends > 0 && e.LastWriter != dev.ID && e.LastWriter != "" {
		return fmt.Errorf("%w (session %s was last written by device %s and you have already sent from your copy — sync state before sending again)", ErrSendConflict, hexID(id), shortDev(e.LastWriter))
	}
	return nil
}

// RecordSend notes that this device emitted a message in session id.
func RecordSend(dir string, id [8]byte, dev *DeviceState) error {
	led, err := loadLedger(dir)
	if err != nil {
		return err
	}
	e := led.Sessions[hexID(id)]
	e.LastWriter = dev.ID
	e.MySends++
	led.Sessions[hexID(id)] = e
	return led.save(dir)
}

// LedgerEntry exposes one session's ledger row for reporting.
func LedgerEntry(dir string, id [8]byte) (SessionLedgerEntry, bool) {
	led, err := loadLedger(dir)
	if err != nil {
		return SessionLedgerEntry{}, false
	}
	e, ok := led.Sessions[hexID(id)]
	return e, ok
}

// LedgerIDs lists every session the ledger knows about.
func LedgerIDs(dir string) ([]string, error) {
	led, err := loadLedger(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(led.Sessions))
	for k := range led.Sessions {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func shortDev(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// EncodeBundle renders a bundle as text for transfer. Bundles are explicitly
// transferable material, so a self-describing JSON envelope is used rather than
// a bare binary blob: it keeps the payload auditable in transit.
func EncodeBundle(b *DeviceBundle) ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// DecodeBundle parses a bundle produced by EncodeBundle.
func DecodeBundle(raw []byte) (*DeviceBundle, error) {
	var b DeviceBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	if b.Version != 1 {
		return nil, fmt.Errorf("ratchetwire: unsupported bundle version %d", b.Version)
	}
	return &b, nil
}
