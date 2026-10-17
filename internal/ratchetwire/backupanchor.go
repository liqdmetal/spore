package ratchetwire

// External monotonic anchor for device backups.
//
// The state directory's generation mark cannot help a restore onto empty
// storage: nothing local is left to compare with. An anchor is a small
// authenticated record that the operator keeps outside the state directory: a
// separate volume, removable media, or a folder synced elsewhere. It records
// the highest backup generation this device has written or restored, and a
// restore refuses any backup older than it, even on empty storage.
//
// The record carries an HMAC keyed by a key derived from the state key. An
// attacker who can write the anchor location, but who lacks the state key,
// cannot lower the anchor or forge a new one. What the MAC cannot stop is a
// replay of an older, validly MACed anchor copy. An anchor is only as current
// as its last write. Closing that gap needs a hardware counter or a remote
// witness, which this package does not have. Keep the anchor on storage the
// state directory's attacker cannot restore for you.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/liqdmetal/spore/internal/bounds"

	"golang.org/x/crypto/hkdf"
)

const (
	anchorFormat   = "spore/device-backup-anchor/v1"
	anchorInfo     = "spore/e2/backup-anchor/v1"
	anchorMaxBytes = 4 << 10
)

type backupAnchorRecord struct {
	Format     string `json:"format"`
	Device     string `json:"device"`
	Generation uint64 `json:"generation"`
	MAC        string `json:"mac"` // hex HMAC-SHA256 over format, device, generation
}

// BackupAnchor is an anchor record whose MAC has been verified.
type BackupAnchor struct {
	Device     string
	Generation uint64
}

// AnchorCheck selects an external anchor for a restore. An empty Path disables
// the check.
type AnchorCheck struct {
	Path string
	// Init allows a missing anchor on a device's first restore. Without it a
	// missing anchor is refused, so deleting the anchor cannot silently switch
	// the check off.
	Init bool
}

func anchorMAC(stateKey []byte, device string, gen uint64) ([]byte, error) {
	if len(stateKey) != 32 {
		return nil, errors.New("ratchetwire: state key must be 32 bytes")
	}
	kr := hkdf.New(sha256.New, stateKey, nil, []byte(anchorInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kr, key); err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "%s|%s|%d", anchorFormat, device, gen)
	return m.Sum(nil), nil
}

// ReadBackupAnchor loads and authenticates an anchor. A missing file returns an
// error for which os.IsNotExist holds.
func ReadBackupAnchor(path string, stateKey []byte) (*BackupAnchor, error) {
	raw, err := bounds.ReadBound(path, anchorMaxBytes)
	if err != nil {
		return nil, err
	}
	var r backupAnchorRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("ratchetwire: corrupt backup anchor %s: %w", path, err)
	}
	if r.Format != anchorFormat {
		return nil, fmt.Errorf("ratchetwire: backup anchor %s has unsupported format %q", path, r.Format)
	}
	if err := checkDeviceID(r.Device); err != nil {
		return nil, err
	}
	got, err := hex.DecodeString(r.MAC)
	if err != nil {
		return nil, fmt.Errorf("ratchetwire: backup anchor %s has a malformed MAC", path)
	}
	want, err := anchorMAC(stateKey, r.Device, r.Generation)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(got, want) {
		return nil, fmt.Errorf("ratchetwire: backup anchor %s does not authenticate under this state key", path)
	}
	return &BackupAnchor{Device: r.Device, Generation: r.Generation}, nil
}

// WriteBackupAnchor records device at generation gen in the anchor at path. It
// never lowers an existing anchor and never overwrites one it cannot verify,
// since that could hide a real rollback.
func WriteBackupAnchor(path string, stateKey []byte, device string, gen uint64) error {
	if path == "" {
		return errors.New("ratchetwire: empty anchor path")
	}
	if err := checkDeviceID(device); err != nil {
		return err
	}
	prev, err := ReadBackupAnchor(path, stateKey)
	switch {
	case err == nil:
		if prev.Device != device {
			return fmt.Errorf("ratchetwire: backup anchor %s belongs to device %s, not %s", path, shortDev(prev.Device), shortDev(device))
		}
		if gen < prev.Generation {
			return fmt.Errorf("ratchetwire: backup anchor %s is at generation %d; refusing to lower it to %d", path, prev.Generation, gen)
		}
		if gen == prev.Generation {
			return nil
		}
	case os.IsNotExist(err):
		// First write for this anchor.
	default:
		return err
	}
	mac, err := anchorMAC(stateKey, device, gen)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(backupAnchorRecord{
		Format:     anchorFormat,
		Device:     device,
		Generation: gen,
		MAC:        hex.EncodeToString(mac),
	}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(dir, filepath.Base(path), raw)
}
