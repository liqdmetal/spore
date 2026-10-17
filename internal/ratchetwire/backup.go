package ratchetwire

// Encrypted device backup and restore.
//
// A backup carries what a device needs to resume: its device id, its identity
// key, the sync ledger, and every session's protected head record. The whole
// payload is sealed under a passphrase (scrypt → XChaCha20-Poly1305). The header
// fields are bound as associated data, so editing the generation, device id, or
// KDF parameters makes the backup fail to open.
//
// Rollback protection has two layers, and restore runs both before it writes
// anything:
//
//  1. Generation. Each backup takes the next generation number, and the highest
//     generation this device has written or restored is recorded in
//     backup-generation.json. A backup older than that is refused.
//  2. Session sequence. Each session record carries its ratchet sequence. A
//     session is refused if this device's durable append-only log already holds
//     a higher sequence for it: restoring an older ratchet state would reuse
//     message keys the peer has already seen.
//
// Limit: restoring onto empty storage has no local marks, so neither check can
// catch a rollback there. The marks are only as trustworthy as the state
// directory: whoever can rewrite the logs can also rewrite the marks.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/liqdmetal/spore/internal/bounds"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const (
	backupFormat     = "spore/device-backup/v1"
	backupMarkFile   = "backup-generation.json"
	backupScryptN    = 1 << 15
	backupScryptR    = 8
	backupScryptP    = 1
	backupSaltLen    = 16
	backupMinPass    = 12
	backupMaxSession = 64 << 10 // same cap as a session head file
	backupMaxLedger  = 1 << 16  // same cap as the sync ledger
)

type backupKDF struct {
	Alg  string `json:"alg"`
	N    int    `json:"n"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Salt []byte `json:"salt"`
}

// backupEnvelope is the on-disk backup file. Everything except Ciphertext is
// authenticated as associated data.
type backupEnvelope struct {
	Format     string    `json:"format"`
	Device     string    `json:"device"`
	Generation uint64    `json:"generation"`
	Created    int64     `json:"created"`
	KDF        backupKDF `json:"kdf"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
}

type backupSession struct {
	ID       string `json:"id"`
	Sequence uint64 `json:"sequence"`
	Record   []byte `json:"record"` // protected head record, sealed under the state key
}

// backupPayload is the plaintext inside the envelope. It is never written to
// disk unencrypted.
type backupPayload struct {
	Device        string          `json:"device"`
	DeviceCreated int64           `json:"device_created"`
	Generation    uint64          `json:"generation"`
	Identity      []byte          `json:"identity"`
	Ledger        []byte          `json:"ledger,omitempty"`
	Sessions      []backupSession `json:"sessions"`
}

type generationMark struct {
	Device     string `json:"device"`
	Generation uint64 `json:"generation"`
}

// OpenedBackup is a decrypted backup, ready to be restored. Opening it writes
// nothing, so a caller can check the identity target before restoring.
type OpenedBackup struct {
	Device     string
	Generation uint64
	Identity   []byte
	payload    backupPayload
}

// RestoreResult reports what a restore applied.
type RestoreResult struct {
	Device     string
	Generation uint64
	Sessions   int
}

// CreateBackup seals this device's identity key, sync ledger, and session
// records under passphrase. It returns the encoded backup file and its
// generation. The generation is recorded before the bytes are returned, so if
// the caller's write later fails, that number is burned rather than reused.
func CreateBackup(stateDir string, stateKey, passphrase, identity []byte, dev *DeviceState) ([]byte, uint64, error) {
	if dev == nil {
		return nil, 0, errors.New("ratchetwire: nil device state")
	}
	if err := checkBackupPassphrase(passphrase); err != nil {
		return nil, 0, err
	}
	if len(identity) == 0 {
		return nil, 0, errors.New("ratchetwire: backup needs the identity key")
	}
	store, err := NewFileStateStore(stateDir, stateKey)
	if err != nil {
		return nil, 0, err
	}
	mark, err := loadGenerationMark(stateDir)
	if err != nil {
		return nil, 0, err
	}
	if mark.Device != "" && mark.Device != dev.ID {
		return nil, 0, fmt.Errorf("ratchetwire: state dir high-water belongs to device %s, not %s", shortDev(mark.Device), shortDev(dev.ID))
	}
	ids, err := store.IDs()
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(ids, func(i, j int) bool { return hexID(ids[i]) < hexID(ids[j]) })
	sessions := make([]backupSession, 0, len(ids))
	for _, id := range ids {
		record, err := bounds.ReadBound(store.path(id), backupMaxSession)
		if err != nil {
			return nil, 0, err
		}
		// Verify under the state key before sealing. A damaged session should
		// fail now, not on the day the backup is needed.
		seq, _, err := UnprotectSession(store.protector, id, record)
		if err != nil {
			return nil, 0, fmt.Errorf("ratchetwire: session %s does not verify; refusing to back it up: %w", hexID(id), err)
		}
		sessions = append(sessions, backupSession{ID: hexID(id), Sequence: seq, Record: record})
	}
	ledger, err := readOptionalFile(filepath.Join(stateDir, ledgerFile), backupMaxLedger)
	if err != nil {
		return nil, 0, err
	}

	gen := mark.Generation + 1
	plain, err := json.Marshal(backupPayload{
		Device:        dev.ID,
		DeviceCreated: dev.Created,
		Generation:    gen,
		Identity:      identity,
		Ledger:        ledger,
		Sessions:      sessions,
	})
	if err != nil {
		return nil, 0, err
	}
	salt, err := randomBytes(backupSaltLen)
	if err != nil {
		return nil, 0, err
	}
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, 0, err
	}
	env := backupEnvelope{
		Format:     backupFormat,
		Device:     dev.ID,
		Generation: gen,
		Created:    time.Now().Unix(),
		KDF:        backupKDF{Alg: "scrypt", N: backupScryptN, R: backupScryptR, P: backupScryptP, Salt: salt},
		Nonce:      nonce,
	}
	if err := sealBackup(passphrase, &env, plain); err != nil {
		return nil, 0, err
	}
	if err := saveGenerationMark(stateDir, generationMark{Device: dev.ID, Generation: gen}); err != nil {
		return nil, 0, err
	}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	return raw, gen, nil
}

// OpenBackup decrypts and validates a backup file. It writes nothing.
func OpenBackup(passphrase, raw []byte) (*OpenedBackup, error) {
	var env backupEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("ratchetwire: not a Spore device backup: %w", err)
	}
	if env.Format != backupFormat {
		return nil, fmt.Errorf("ratchetwire: unsupported backup format %q", env.Format)
	}
	if err := checkDeviceID(env.Device); err != nil {
		return nil, err
	}
	if len(env.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("ratchetwire: backup nonce has the wrong length")
	}
	key, err := deriveBackupKey(passphrase, env.KDF)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, env.Nonce, env.Ciphertext, backupAAD(&env))
	if err != nil {
		return nil, errors.New("ratchetwire: backup will not open with this passphrase, or it is damaged or was altered")
	}
	var p backupPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("ratchetwire: malformed backup payload: %w", err)
	}
	if p.Device != env.Device || p.Generation != env.Generation {
		return nil, errors.New("ratchetwire: backup payload disagrees with its header")
	}
	if len(p.Identity) == 0 {
		return nil, errors.New("ratchetwire: backup carries no identity key")
	}
	return &OpenedBackup{Device: p.Device, Generation: p.Generation, Identity: p.Identity, payload: p}, nil
}

// Restore applies an opened backup to stateDir. Every check runs before the
// first write, so a refused restore leaves the state directory unchanged.
func (b *OpenedBackup) Restore(stateDir string, stateKey []byte, anchor AnchorCheck) (*RestoreResult, error) {
	if b == nil {
		return nil, errors.New("ratchetwire: nil backup")
	}
	store, err := NewFileStateStore(stateDir, stateKey)
	if err != nil {
		return nil, err
	}
	existing, err := readDeviceFile(stateDir)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.ID != b.Device {
		return nil, fmt.Errorf("ratchetwire: state dir belongs to device %s; this backup is for device %s", shortDev(existing.ID), shortDev(b.Device))
	}
	mark, err := loadGenerationMark(stateDir)
	if err != nil {
		return nil, err
	}
	if mark.Generation > b.Generation {
		return nil, fmt.Errorf("ratchetwire: backup generation %d is older than this device's last backup or restore (generation %d); refusing rollback", b.Generation, mark.Generation)
	}

	// The external anchor catches a rollback that the local mark cannot see,
	// such as a restore onto empty storage.
	if anchor.Path != "" {
		a, err := ReadBackupAnchor(anchor.Path, stateKey)
		switch {
		case os.IsNotExist(err) && anchor.Init:
			// First restore for this device: nothing to compare against yet.
		case os.IsNotExist(err):
			return nil, fmt.Errorf("ratchetwire: no backup anchor at %s; pass -anchor-init only on a device's first restore", anchor.Path)
		case err != nil:
			return nil, err
		default:
			if a.Device != b.Device {
				return nil, fmt.Errorf("ratchetwire: backup anchor %s is for device %s, not %s", anchor.Path, shortDev(a.Device), shortDev(b.Device))
			}
			if b.Generation < a.Generation {
				return nil, fmt.Errorf("ratchetwire: backup generation %d is older than the external anchor (generation %d); refusing rollback", b.Generation, a.Generation)
			}
		}
	}

	type pendingSession struct {
		id     [8]byte
		seq    uint64
		record []byte
	}
	pending := make([]pendingSession, 0, len(b.payload.Sessions))
	for _, s := range b.payload.Sessions {
		id, err := parseSessionID(s.ID)
		if err != nil {
			return nil, err
		}
		seq, _, err := UnprotectSession(store.protector, id, s.Record)
		if err != nil {
			return nil, fmt.Errorf("ratchetwire: session %s does not open under this state key: %w", s.ID, err)
		}
		if seq != s.Sequence {
			return nil, fmt.Errorf("ratchetwire: session %s: backup metadata disagrees with its record", s.ID)
		}
		logged, err := store.maxLoggedSequence(id)
		if err != nil {
			return nil, err
		}
		if logged > seq {
			return nil, fmt.Errorf("ratchetwire: session %s: backup is at sequence %d but this device has reached %d; restoring it would roll the ratchet back and reuse message keys", s.ID, seq, logged)
		}
		pending = append(pending, pendingSession{id: id, seq: seq, record: s.Record})
	}

	// The external anchor is raised before any write, so a failure here
	// leaves the device unchanged.
	if anchor.Path != "" {
		if err := WriteBackupAnchor(anchor.Path, stateKey, b.Device, b.Generation); err != nil {
			return nil, err
		}
	}

	// Every check has passed. Writes start here.
	if existing == nil {
		raw, err := json.MarshalIndent(DeviceState{ID: b.Device, Created: b.payload.DeviceCreated}, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(stateDir, deviceFile, raw); err != nil {
			return nil, err
		}
	}
	for _, p := range pending {
		if err := store.installRecord(p.id, p.seq, p.record); err != nil {
			return nil, err
		}
	}
	if len(b.payload.Ledger) > 0 {
		if err := writeFileAtomic(stateDir, ledgerFile, b.payload.Ledger); err != nil {
			return nil, err
		}
	}
	high := mark.Generation
	if b.Generation > high {
		high = b.Generation
	}
	if err := saveGenerationMark(stateDir, generationMark{Device: b.Device, Generation: high}); err != nil {
		return nil, err
	}
	return &RestoreResult{Device: b.Device, Generation: b.Generation, Sessions: len(pending)}, nil
}

// installRecord writes a verified protected head record with the sequence it
// carries. It appends the log first, matching Save: a crash between the two
// steps leaves a higher logged sequence, which is safe.
func (s *FileStateStore) installRecord(id [8]byte, seq uint64, record []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.appendLog(id, seq, StateDigest(record)); err != nil {
		return err
	}
	if err := writeFileAtomic(s.dir, filepath.Base(s.path(id)), record); err != nil {
		return err
	}
	delete(s.sequence, id) // Load repopulates the in-memory high-water mark
	return nil
}

func sealBackup(passphrase []byte, env *backupEnvelope, plain []byte) error {
	key, err := deriveBackupKey(passphrase, env.KDF)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	env.Ciphertext = aead.Seal(nil, env.Nonce, plain, backupAAD(env))
	return nil
}

// backupAAD binds every header field except the ciphertext. Editing any of them
// makes the backup fail to open.
func backupAAD(env *backupEnvelope) []byte {
	return []byte(fmt.Sprintf("%s|%s|%d|%d|%s|%d|%d|%d|%x|%x",
		backupFormat, env.Device, env.Generation, env.Created,
		env.KDF.Alg, env.KDF.N, env.KDF.R, env.KDF.P, env.KDF.Salt, env.Nonce))
}

// deriveBackupKey runs scrypt with bounds on the parameters, so a hostile file
// cannot force an allocation or runtime far beyond what this code writes.
func deriveBackupKey(passphrase []byte, kdf backupKDF) ([]byte, error) {
	if kdf.Alg != "scrypt" {
		return nil, fmt.Errorf("ratchetwire: unsupported backup KDF %q", kdf.Alg)
	}
	if kdf.N < 1<<14 || kdf.N > 1<<17 || kdf.R < 1 || kdf.R > 8 || kdf.P < 1 || kdf.P > 4 {
		return nil, errors.New("ratchetwire: backup KDF parameters are out of range")
	}
	if len(kdf.Salt) != backupSaltLen {
		return nil, errors.New("ratchetwire: backup salt has the wrong length")
	}
	return scrypt.Key(passphrase, kdf.Salt, kdf.N, kdf.R, kdf.P, 32)
}

func checkBackupPassphrase(p []byte) error {
	if len(p) < backupMinPass {
		return fmt.Errorf("ratchetwire: backup passphrase must be at least %d characters", backupMinPass)
	}
	return nil
}

func checkDeviceID(s string) error {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 16 {
		return errors.New("ratchetwire: backup device id is malformed")
	}
	return nil
}

func parseSessionID(s string) ([8]byte, error) {
	var id [8]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 8 {
		return id, fmt.Errorf("ratchetwire: backup session id %q is not 8 bytes of hex", s)
	}
	copy(id[:], raw)
	return id, nil
}

func loadGenerationMark(dir string) (generationMark, error) {
	var m generationMark
	raw, err := bounds.ReadBound(filepath.Join(dir, backupMarkFile), 1<<10)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("ratchetwire: corrupt %s: %w", backupMarkFile, err)
	}
	return m, nil
}

func saveGenerationMark(dir string, m generationMark) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, backupMarkFile, raw)
}

// readDeviceFile returns the device identity in dir, or nil when there is none.
// Unlike LoadOrCreateDevice it never creates one.
func readDeviceFile(dir string) (*DeviceState, error) {
	raw, err := bounds.ReadBound(filepath.Join(dir, deviceFile), 1<<10)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d DeviceState
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("ratchetwire: corrupt %s: %w", deviceFile, err)
	}
	if err := checkDeviceID(d.ID); err != nil {
		return nil, err
	}
	return &d, nil
}

func readOptionalFile(path string, max int) ([]byte, error) {
	raw, err := bounds.ReadBound(path, max)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return raw, err
}

// writeFileAtomic replaces dir/name through a synced temp file and a rename.
func writeFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, name+"-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(e error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return e
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
