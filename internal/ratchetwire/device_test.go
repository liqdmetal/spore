package ratchetwire

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func devDir(t *testing.T) string { return t.TempDir() }

func key(fill byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = fill
	}
	return k
}

func sid(b byte) [8]byte {
	var id [8]byte
	for i := range id {
		id[i] = b
	}
	return id
}

// seedSession writes state for id directly into a state directory.
func seedSession(t *testing.T, dir string, id [8]byte, st []byte, k []byte) {
	t.Helper()
	s, err := NewFileStateStore(dir, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(id, st); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceIDIsStableAndDistinct(t *testing.T) {
	d1 := devDir(t)
	a, err := LoadOrCreateDevice(d1)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.ID) != 32 {
		t.Fatalf("device id = %q, want 32 hex chars", a.ID)
	}
	// Reloading must return the same id, or every restart looks like a new
	// device and the conflict ledger can never fire.
	b, err := LoadOrCreateDevice(d1)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Fatalf("device id changed across loads: %s -> %s", a.ID, b.ID)
	}
	// A second directory is a second device.
	c, err := LoadOrCreateDevice(devDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == a.ID {
		t.Fatal("two state directories produced the SAME device id — devices would be indistinguishable")
	}
}

func TestExportImportRoundTripsState(t *testing.T) {
	src, dst := devDir(t), devDir(t)
	k := key(1)
	id := sid(0xab)
	state := []byte("pretend this is serialized ratchet state")
	seedSession(t, src, id, state, k)

	devA, _ := LoadOrCreateDevice(src)
	devB, _ := LoadOrCreateDevice(dst)
	b, err := ExportBundle(src, k, devA)
	if err != nil {
		t.Fatal(err)
	}
	if b.Device != devA.ID {
		t.Fatalf("bundle device = %s, want %s", b.Device, devA.ID)
	}
	rep, err := ImportBundle(dst, k, b, devB)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 1 {
		t.Fatalf("imported = %d, want 1", rep.Imported)
	}
	if len(rep.Conflict) != 0 {
		t.Fatalf("unexpected conflict on a clean import: %v", rep.Conflict)
	}
	// The state must be readable at the destination.
	s, err := NewFileStateStore(dst, k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, state) {
		t.Fatalf("imported state = %q, want %q", got, state)
	}
}

// A bundle must not open under another account's state key. This is the check
// that stops one identity's conversation state being merged into another's.
func TestImportRejectsWrongStateKey(t *testing.T) {
	src, dst := devDir(t), devDir(t)
	seedSession(t, src, sid(1), []byte("state"), key(1))
	devA, _ := LoadOrCreateDevice(src)
	devB, _ := LoadOrCreateDevice(dst)
	b, err := ExportBundle(src, key(1), devA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportBundle(dst, key(2), b, devB); err == nil {
		t.Fatal("a bundle opened under the WRONG state key — cross-account state merge is possible")
	}
	// And nothing was written.
	s, _ := NewFileStateStore(dst, key(2))
	ids, err := s.IDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("failed import left %d session(s) behind", len(ids))
	}
}

func TestImportRejectsTamperedBundle(t *testing.T) {
	src, dst := devDir(t), devDir(t)
	seedSession(t, src, sid(1), []byte("state"), key(1))
	devA, _ := LoadOrCreateDevice(src)
	devB, _ := LoadOrCreateDevice(dst)
	b, err := ExportBundle(src, key(1), devA)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext.
	b.Sessions[len(b.Sessions)-1] ^= 0x01
	if _, err := ImportBundle(dst, key(1), b, devB); err == nil {
		t.Fatal("a tampered bundle was accepted — the payload is not authenticated")
	}
}

// The collision case. Device A sends; B imports and sends; A imports B's state.
// Both chains advanced from the same counter, so A must be told, and must be
// refused rather than allowed to send into a possibly-reused chain.
func TestConflictDetectedWhenBothDevicesSend(t *testing.T) {
	dirA, dirB := devDir(t), devDir(t)
	k := key(3)
	id := sid(0x5a)
	seedSession(t, dirA, id, []byte("v0"), k)

	devA, _ := LoadOrCreateDevice(dirA)
	devB, _ := LoadOrCreateDevice(dirB)

	// A sends, so A's ledger has a chain of its own.
	if err := RecordSend(dirA, id, devA); err != nil {
		t.Fatal(err)
	}
	// A shares state; B adopts it cleanly (B has not sent, so no conflict yet).
	b1, err := ExportBundle(dirA, k, devA)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := ImportBundle(dirB, k, b1, devB)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Conflict) != 0 {
		t.Fatalf("B was flagged on a clean first import: %v", rep.Conflict)
	}
	// B may send now — it adopted A's state and has no chain of its own.
	if err := CheckSendAllowed(dirB, id, devB); err != nil {
		t.Fatalf("B refused a send it should have been allowed: %v", err)
	}
	if err := RecordSend(dirB, id, devB); err != nil {
		t.Fatal(err)
	}

	// B sends back; A adopts B's state. A had already sent, so this is the
	// collision signature.
	b2, err := ExportBundle(dirB, k, devB)
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := ImportBundle(dirA, k, b2, devA)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Conflict) != 1 {
		t.Fatalf("conflict was NOT detected after both devices sent: report = %+v", rep2)
	}
	if rep2.Conflict[0] != hexID(id) {
		t.Fatalf("conflict names %s, want %s", rep2.Conflict[0], hexID(id))
	}
	// And the guard now refuses to send on that session.
	err = CheckSendAllowed(dirA, id, devA)
	if err == nil {
		t.Fatal("send was ALLOWED on a session known to have colliding chains")
	}
	if !errors.Is(err, ErrSendConflict) {
		t.Fatalf("error = %v, want ErrSendConflict", err)
	}
}

// A single device must never flag itself: no import, no foreign writer.
func TestSingleDeviceNeverConflicts(t *testing.T) {
	dir := devDir(t)
	k := key(4)
	id := sid(7)
	seedSession(t, dir, id, []byte("state"), k)
	dev, _ := LoadOrCreateDevice(dir)
	for i := 0; i < 5; i++ {
		if err := CheckSendAllowed(dir, id, dev); err != nil {
			t.Fatalf("send %d refused on a single-device install: %v", i, err)
		}
		if err := RecordSend(dir, id, dev); err != nil {
			t.Fatal(err)
		}
	}
	e, ok := LedgerEntry(dir, id)
	if !ok {
		t.Fatal("ledger entry missing after sends")
	}
	if e.MySends != 5 {
		t.Fatalf("MySends = %d, want 5", e.MySends)
	}
	if e.Conflict {
		t.Fatal("single device flagged itself as conflicting")
	}
	if e.LastWriter != dev.ID {
		t.Fatalf("LastWriter = %s, want own device %s", e.LastWriter, dev.ID)
	}
}

// Importing state must clear this device's send count, because it has adopted
// the exporter's chain. Otherwise every import would look like a conflict.
func TestImportClearsOwnSendCount(t *testing.T) {
	dirA, dirB := devDir(t), devDir(t)
	k := key(5)
	id := sid(9)
	seedSession(t, dirA, id, []byte("a"), k)
	devA, _ := LoadOrCreateDevice(dirA)
	devB, _ := LoadOrCreateDevice(dirB)

	// B sends on its own first, then imports A's state: that IS a conflict.
	if err := RecordSend(dirB, id, devB); err != nil {
		t.Fatal(err)
	}
	b, err := ExportBundle(dirA, k, devA)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := ImportBundle(dirB, k, b, devB)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Conflict) != 1 {
		t.Fatalf("expected a conflict for B (it had sent), got %+v", rep)
	}
	e, _ := LedgerEntry(dirB, id)
	if e.MySends != 0 {
		t.Fatalf("MySends = %d after import, want 0 (B adopted A's chain)", e.MySends)
	}
	if e.LastWriter != devA.ID {
		t.Fatalf("LastWriter = %s, want exporter %s", e.LastWriter, devA.ID)
	}
}

// The guard must refuse when another device wrote the session and this device
// has already sent from its own copy — even before a full conflict is recorded.
func TestGuardRefusesStaleWriter(t *testing.T) {
	dir := devDir(t)
	k := key(6)
	id := sid(0x11)
	seedSession(t, dir, id, []byte("state"), k)
	dev, _ := LoadOrCreateDevice(dir)

	if err := CheckSendAllowed(dir, id, dev); err != nil {
		t.Fatalf("first send refused: %v", err)
	}
	if err := RecordSend(dir, id, dev); err != nil {
		t.Fatal(err)
	}
	// Simulate another device having written this session locally.
	led, err := loadLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := led.Sessions[hexID(id)]
	e.LastWriter = "deadbeefdeadbeefdeadbeefdeadbeef"
	led.Sessions[hexID(id)] = e
	if err := led.save(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckSendAllowed(dir, id, dev); err == nil {
		t.Fatal("send allowed although another device last wrote this session")
	}
}

// An unknown session is not a refusal: a session the ledger has never seen has
// nothing recorded against it.
func TestGuardAllowsUnknownSession(t *testing.T) {
	dir := devDir(t)
	dev, _ := LoadOrCreateDevice(dir)
	if err := CheckSendAllowed(dir, sid(0x77), dev); err != nil {
		t.Fatalf("unknown session refused: %v", err)
	}
}

func TestBundleEnvelopeRoundTrip(t *testing.T) {
	src := devDir(t)
	seedSession(t, src, sid(1), []byte("state"), key(7))
	dev, _ := LoadOrCreateDevice(src)
	b, err := ExportBundle(src, key(7), dev)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	// The encoded form must not carry plaintext session state.
	if bytes.Contains(raw, []byte("state")) {
		t.Fatal("encoded bundle leaks plaintext session bytes")
	}
	got, err := DecodeBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != b.Device || got.Version != 1 {
		t.Fatalf("decoded bundle mismatch: %+v", got)
	}
	if _, err := DecodeBundle([]byte(`{"version":99}`)); err == nil {
		t.Fatal("an unknown bundle version was accepted")
	}
	if _, err := DecodeBundle([]byte(`not json`)); err == nil {
		t.Fatal("malformed bundle JSON was accepted")
	}
}

func TestImportRejectsMalformedRecords(t *testing.T) {
	dir, dst := devDir(t), devDir(t)
	k := key(8)
	dev, _ := LoadOrCreateDevice(dst)
	devA, _ := LoadOrCreateDevice(dir)

	// A bundle whose payload decodes to a bad session id.
	recs, _ := json.Marshal([]SessionRecord{{ID: "zz", State: []byte("x")}})
	b := sealForTest(t, k, devA.ID, recs)
	if _, err := ImportBundle(dst, k, b, dev); err == nil {
		t.Fatal("bundle with a non-hex session id was accepted")
	}

	// A bundle whose session state is empty.
	recs2, _ := json.Marshal([]SessionRecord{{ID: hexID(sid(1)), State: nil}})
	b2 := sealForTest(t, k, devA.ID, recs2)
	if _, err := ImportBundle(dst, k, b2, dev); err == nil {
		t.Fatal("bundle with empty session state was accepted")
	}
}

// TestLoadOrCreateDeviceRejectsMalformedID: a truncated device id must be an
// error, not silently accepted. The id is what distinguishes two devices on one
// identity, so a malformed one would make the collision guard compare garbage —
// and a corrupt file is exactly what a partial write leaves behind.
func TestLoadOrCreateDeviceRejectsMalformedID(t *testing.T) {
	dir := devDir(t)
	// Short id: the shape a truncated write produces.
	if err := writeFile(filepath.Join(dir, "device.json"), []byte(`{"id":"abcd","created":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateDevice(dir); err == nil {
		t.Fatal("a malformed device id was accepted")
	}

	// Not JSON at all.
	if err := writeFile(filepath.Join(dir, "device.json"), []byte(`{oops`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateDevice(dir); err == nil {
		t.Fatal("corrupt device.json was accepted")
	}

	// And a valid one still loads.
	ok := devDir(t)
	d, err := LoadOrCreateDevice(ok)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateDevice(ok)
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != again.ID {
		t.Fatalf("device id changed across loads: %s -> %s", d.ID, again.ID)
	}
}

// TestBundlePayloadIsBoundToItsContext proves the AAD label is really part of
// the seal. Tampering with the CIPHERTEXT would be caught by the tag alone; the
// label is what stops a payload sealed for one purpose being accepted here, so
// it needs its own check or it silently becomes decoration.
func TestBundlePayloadIsBoundToItsContext(t *testing.T) {
	dir := devDir(t)
	dev, _ := LoadOrCreateDevice(dir)
	stateKey := key(7)

	// Seal the same payload the production exporter would, but WITHOUT the
	// context label — as a different protocol/version would.
	k, err := deriveBundleKey(stateKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	recs, _ := json.Marshal([]SessionRecord{{ID: "0102030405060708", State: []byte("st")}})
	ct := aead.Seal(nil, nonce, recs, nil) // NO AAD
	b := &DeviceBundle{Version: 1, Device: dev.ID, Sessions: append(nonce, ct...)}

	if _, err := ImportBundle(dir, stateKey, b, dev); err == nil {
		t.Fatal("a payload sealed WITHOUT the context label was accepted — the AAD is not bound")
	}
}

// sealForTest builds a bundle around an arbitrary payload, so tests can probe
// what ImportBundle does with malformed contents rather than only well-formed
// ones produced by ExportBundle.
func sealForTest(t *testing.T, stateKey []byte, deviceID string, payload []byte) *DeviceBundle {
	t.Helper()
	k, err := deriveBundleKey(stateKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	ct := aead.Seal(nil, nonce, payload, []byte(bundleLabel))
	return &DeviceBundle{Version: 1, Device: deviceID, Sessions: append(nonce, ct...)}
}

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

func TestExportEmptyStoreIsValid(t *testing.T) {
	dir := devDir(t)
	dev, _ := LoadOrCreateDevice(dir)
	b, err := ExportBundle(dir, key(9), dev)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != 1 || len(b.Sessions) == 0 {
		t.Fatalf("empty-store bundle is malformed: %+v", b)
	}
	// And it must import cleanly into another device as a no-op.
	dst := devDir(t)
	devB, _ := LoadOrCreateDevice(dst)
	rep, err := ImportBundle(dst, key(9), b, devB)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 0 {
		t.Fatalf("imported %d sessions from an empty store", rep.Imported)
	}
}

func TestExportRejectsBadStateKey(t *testing.T) {
	dir := devDir(t)
	dev, _ := LoadOrCreateDevice(dir)
	if _, err := ExportBundle(dir, []byte("short"), dev); err == nil {
		t.Fatal("export accepted a short state key")
	}
	if _, err := ExportBundle(dir, key(1), nil); err == nil {
		t.Fatal("export accepted a nil device")
	}
	if err := CheckSendAllowed(dir, sid(1), nil); err == nil {
		t.Fatal("guard accepted a nil device")
	}
}

func TestLedgerIDsListsSessions(t *testing.T) {
	dir := devDir(t)
	dev, _ := LoadOrCreateDevice(dir)
	a, b := sid(1), sid(2)
	if err := RecordSend(dir, a, dev); err != nil {
		t.Fatal(err)
	}
	if err := RecordSend(dir, b, dev); err != nil {
		t.Fatal(err)
	}
	ids, err := LedgerIDs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("ledger lists %d sessions, want 2", len(ids))
	}
}

// TestCorruptLedgerFailsClosed: a damaged ledger must surface an error rather
// than silently pretending no conflict was ever recorded.
func TestCorruptLedgerFailsClosed(t *testing.T) {
	dir := devDir(t)
	dev, _ := LoadOrCreateDevice(dir)
	if err := writeFile(filepath.Join(dir, ledgerFile), []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if err := CheckSendAllowed(dir, sid(1), dev); err == nil {
		t.Fatal("a corrupt ledger was treated as 'no conflicts known'")
	}
}
