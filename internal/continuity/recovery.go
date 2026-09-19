package continuity

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
)

const (
	recoveryBundleType    = "spore-continuity-recovery-bundle"
	recoveryBundleVersion = 1
	maxRecoveryArtifacts  = 32
	maxRecoveryBytes      = 64 << 20
	maxRecoveryJSONBytes  = 128 << 20
)

// RecoveryJSONLimit is the maximum encoded JSON size accepted by recovery
// bundle verification. It includes base64 expansion and JSON overhead.
func RecoveryJSONLimit() int64 { return maxRecoveryJSONBytes }

var (
	ErrInvalidRecoveryBundle     = errors.New("continuity: invalid recovery bundle")
	ErrRecoveryDestinationExists = errors.New("continuity: recovery destination already contains an artifact")
)

// RecoveryArtifact is a verified, non-secret continuity artifact encoded for
// transport. Private keys and plaintext payload files are intentionally not
// representable through the supported artifact-name set.
type RecoveryArtifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Data   string `json:"data"`
}

// RecoveryBundle contains encrypted vault material and signed/opaque metadata
// needed to recover continuity operations on another machine. It contains no
// owner, observer, or recipient private key and no released plaintext.
type RecoveryBundle struct {
	Type      string             `json:"type"`
	Version   uint8              `json:"version"`
	BundleID  string             `json:"bundle_id"`
	CreatedAt int64              `json:"created_at"`
	Artifacts []RecoveryArtifact `json:"artifacts"`
}

var recoveryArtifactNames = map[string]struct{}{
	"continuity-vault.json":                 {},
	"continuity-successor-vault.json":       {},
	"quorum-policy.json":                    {},
	"quorum-release.json":                   {},
	"continuity-anchor.json":                {},
	"continuity-anchor-receipt.json":        {},
	"continuity-watch.json":                 {},
	"continuity-release-notice.json":        {},
	"continuity-revocations.json":           {},
	"continuity-revocation-checkpoint.json": {},
	"continuity-rotation.json":              {},
}

// NewRecoveryBundle validates and packages the supplied fixed-name artifacts.
// The input map is copied and sorted; caller buffers are not retained.
func NewRecoveryBundle(files map[string][]byte) (*RecoveryBundle, error) {
	if len(files) == 0 || len(files) > maxRecoveryArtifacts {
		return nil, ErrInvalidRecoveryBundle
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if _, ok := recoveryArtifactNames[name]; !ok {
			return nil, fmt.Errorf("%w: unsupported artifact %q", ErrInvalidRecoveryBundle, name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	artifacts := make([]RecoveryArtifact, 0, len(names))
	var total int64
	for _, name := range names {
		raw := files[name]
		if len(raw) == 0 || int64(len(raw)) > MaxArtifactBytes {
			return nil, fmt.Errorf("%w: artifact %q size", ErrInvalidRecoveryBundle, name)
		}
		if err := verifyRecoveryArtifact(name, raw); err != nil {
			return nil, err
		}
		total += int64(len(raw))
		if total > maxRecoveryBytes {
			return nil, ErrArtifactTooLarge
		}
		h := sha256.Sum256(raw)
		artifacts = append(artifacts, RecoveryArtifact{
			Name: name, Size: int64(len(raw)), SHA256: hex.EncodeToString(h[:]),
			Data: base64.StdEncoding.EncodeToString(raw),
		})
	}
	b := &RecoveryBundle{
		Type: recoveryBundleType, Version: recoveryBundleVersion,
		CreatedAt: time.Now().Unix(), Artifacts: artifacts,
	}
	b.BundleID = recoveryBundleID(*b)
	if err := b.Verify(); err != nil {
		return nil, err
	}
	return b, nil
}

// Verify validates all bytes, hashes, names, strict artifact formats, and
// cross-artifact epoch bindings. It performs no network or wallet operation.
func (b *RecoveryBundle) Verify() error {
	if b == nil || b.Type != recoveryBundleType || b.Version != recoveryBundleVersion ||
		b.CreatedAt <= 0 || len(b.Artifacts) == 0 || len(b.Artifacts) > maxRecoveryArtifacts {
		return ErrInvalidRecoveryBundle
	}
	if _, err := decodeFixed(b.BundleID, 32); err != nil {
		return ErrInvalidRecoveryBundle
	}
	var total int64
	seen := make(map[string]struct{}, len(b.Artifacts))
	for i, artifact := range b.Artifacts {
		if artifact.Name == "" || i > 0 && b.Artifacts[i-1].Name >= artifact.Name {
			return ErrInvalidRecoveryBundle
		}
		if _, ok := recoveryArtifactNames[artifact.Name]; !ok {
			return ErrInvalidRecoveryBundle
		}
		if _, ok := seen[artifact.Name]; ok {
			return ErrInvalidRecoveryBundle
		}
		seen[artifact.Name] = struct{}{}
		raw, err := decodeRecoveryData(artifact)
		if err != nil {
			return err
		}
		total += int64(len(raw))
		if total > maxRecoveryBytes {
			return ErrArtifactTooLarge
		}
		if err := verifyRecoveryArtifact(artifact.Name, raw); err != nil {
			return err
		}
	}
	if recoveryBundleID(*b) != b.BundleID {
		return ErrInvalidRecoveryBundle
	}
	if err := verifyRecoveryCrossBindings(b); err != nil {
		return err
	}
	return nil
}

// Restore writes verified artifacts into a local recovery directory. The
// directory may be new or empty, but an existing artifact is never overwritten.
func (b *RecoveryBundle) Restore(dir string) error {
	if err := b.Verify(); err != nil {
		return err
	}
	if dir == "" {
		return ErrInvalidRecoveryBundle
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("continuity recovery: create destination: %w", err)
	}
	if err := validateRecoveryDirectory(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("continuity recovery: inspect destination: %w", err)
	}
	if len(entries) != 0 {
		return ErrRecoveryDestinationExists
	}
	for _, artifact := range b.Artifacts {
		path := filepath.Join(dir, artifact.Name)
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return ErrInvalidRecoveryDestination
			}
			return ErrRecoveryDestinationExists
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("continuity recovery: inspect destination: %w", err)
		}
	}
	created := make([]string, 0, len(b.Artifacts))
	cleanup := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for _, artifact := range b.Artifacts {
		raw, err := decodeRecoveryData(artifact)
		if err != nil {
			cleanup()
			return err
		}
		path := filepath.Join(dir, artifact.Name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			cleanup()
			return fmt.Errorf("continuity recovery: create %s: %w", artifact.Name, err)
		}
		created = append(created, path)
		if _, err := f.Write(raw); err != nil {
			_ = f.Close()
			cleanup()
			return fmt.Errorf("continuity recovery: write %s: %w", artifact.Name, err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			cleanup()
			return fmt.Errorf("continuity recovery: sync %s: %w", artifact.Name, err)
		}
		if err := f.Close(); err != nil {
			cleanup()
			return fmt.Errorf("continuity recovery: close %s: %w", artifact.Name, err)
		}
	}
	return nil
}

var ErrInvalidRecoveryDestination = errors.New("continuity: invalid recovery destination")

func validateRecoveryDirectory(dir string) error {
	clean := filepath.Clean(dir)
	current := clean
	for {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidRecoveryDestination
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}

// ParseRecoveryBundle strictly decodes and verifies a recovery bundle.
func ParseRecoveryBundle(raw []byte) (*RecoveryBundle, error) {
	var b RecoveryBundle
	if err := decodeStrictLimit(raw, &b, maxRecoveryJSONBytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRecoveryBundle, err)
	}
	if err := b.Verify(); err != nil {
		return nil, err
	}
	return &b, nil
}

func decodeRecoveryData(a RecoveryArtifact) ([]byte, error) {
	if a.Size <= 0 || a.Size > MaxArtifactBytes || len(a.Data) > maxRecoveryBytes*2 {
		return nil, ErrInvalidRecoveryBundle
	}
	raw, err := base64.StdEncoding.DecodeString(a.Data)
	if err != nil || int64(len(raw)) != a.Size {
		return nil, ErrInvalidRecoveryBundle
	}
	h := sha256.Sum256(raw)
	if a.SHA256 != hex.EncodeToString(h[:]) {
		return nil, ErrInvalidRecoveryBundle
	}
	return raw, nil
}

func verifyRecoveryArtifact(name string, raw []byte) error {
	var err error
	switch {
	case name == "continuity-vault.json":
		_, err = Parse(raw)
	case name == "quorum-policy.json":
		_, err = ParseQuorumPolicy(raw)
	case name == "quorum-release.json":
		_, err = ParseQuorumRelease(raw)
	case name == "continuity-anchor.json":
		_, err = ParseChainAnchor(raw)
	case name == "continuity-anchor-receipt.json":
		_, err = ParseAnchorReceipt(raw)
	case name == "continuity-watch.json":
		_, err = ParseWatchState(raw)
	case name == "continuity-release-notice.json":
		_, err = ParseNotice(raw)
	case name == "continuity-revocations.json":
		_, err = ParseRevocationState(raw)
	case name == "continuity-revocation-checkpoint.json":
		_, err = ParseRevocationCheckpoint(raw)
	case name == "continuity-rotation.json":
		_, err = ParseVaultRotation(raw)
	default:
		return ErrInvalidRecoveryBundle
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidRecoveryBundle, name, err)
	}
	return nil
}

func verifyRecoveryCrossBindings(b *RecoveryBundle) error {
	files := make(map[string][]byte, len(b.Artifacts))
	for _, artifact := range b.Artifacts {
		raw, err := decodeRecoveryData(artifact)
		if err != nil {
			return err
		}
		files[artifact.Name] = raw
	}
	var vault *Vault
	var policy *QuorumPolicy
	if raw := files["continuity-vault.json"]; raw != nil {
		var err error
		vault, err = Parse(raw)
		if err != nil {
			return err
		}
	}
	var successor *Vault
	if raw := files["continuity-successor-vault.json"]; raw != nil {
		var err error
		successor, err = Parse(raw)
		if err != nil {
			return err
		}
	}
	hasRotation := files["continuity-rotation.json"] != nil
	if hasRotation && (vault == nil || successor == nil) {
		return fmt.Errorf("%w: rotation requires retired and successor vaults", ErrInvalidRecoveryBundle)
	}
	if (successor != nil) != hasRotation {
		return fmt.Errorf("%w: successor vault requires rotation certificate", ErrInvalidRecoveryBundle)
	}
	if vault != nil && successor != nil {
		certRaw := files["continuity-rotation.json"]
		cert, err := ParseVaultRotation(certRaw)
		if err != nil {
			return err
		}
		if err := VerifyRotation(vault, successor, cert); err != nil {
			return fmt.Errorf("%w: rotation binding: %v", ErrInvalidRecoveryBundle, err)
		}
	}
	if raw := files["quorum-policy.json"]; raw != nil {
		var err error
		policy, err = ParseQuorumPolicy(raw)
		if err != nil {
			return err
		}
	}
	if vault != nil && policy != nil {
		if err := VerifyPolicyForVault(policy, vault); err != nil {
			return fmt.Errorf("%w: policy/vault binding: %v", ErrInvalidRecoveryBundle, err)
		}
	}
	var revocations *RevocationState
	if raw := files["continuity-revocations.json"]; raw != nil {
		var err error
		revocations, err = ParseRevocationState(raw)
		if err != nil {
			return err
		}
	}
	var checkpoint *RevocationCheckpoint
	if raw := files["continuity-revocation-checkpoint.json"]; raw != nil {
		var err error
		checkpoint, err = ParseRevocationCheckpoint(raw)
		if err != nil {
			return err
		}
	}
	if (revocations == nil) != (checkpoint == nil) {
		return fmt.Errorf("%w: revocation state and checkpoint must travel together", ErrInvalidRecoveryBundle)
	}
	if vault != nil && revocations != nil {
		if err := VerifyRevocationCheckpoint(vault, revocations, checkpoint); err != nil {
			return fmt.Errorf("%w: revocation binding: %v", ErrInvalidRecoveryBundle, err)
		}
	}
	var rotation *VaultRotation
	if raw := files["continuity-rotation.json"]; raw != nil {
		var err error
		rotation, err = ParseVaultRotation(raw)
		if err != nil {
			return err
		}
	}
	if rotation != nil && vault != nil && rotation.NewVaultID != vault.VaultID && rotation.OldVaultID != vault.VaultID {
		return fmt.Errorf("%w: rotation vault binding", ErrInvalidRecoveryBundle)
	}
	var chainAnchor *ChainAnchor
	if raw := files["continuity-anchor.json"]; raw != nil {
		var err error
		chainAnchor, err = ParseChainAnchor(raw)
		if err != nil {
			return err
		}
	}
	var receipt *AnchorReceipt
	if raw := files["continuity-anchor-receipt.json"]; raw != nil {
		var err error
		receipt, err = ParseAnchorReceipt(raw)
		if err != nil {
			return err
		}
	}
	if chainAnchor != nil && policy != nil {
		if chainAnchor.PolicyID != policy.PolicyID || chainAnchor.VaultID != policy.VaultID || chainAnchor.CheckInSeq != policy.CheckInSeq || chainAnchor.Deadline != policy.Deadline {
			return fmt.Errorf("%w: anchor/policy binding", ErrInvalidRecoveryBundle)
		}
	}
	if chainAnchor != nil && vault != nil && policy == nil {
		if chainAnchor.VaultID != vault.VaultID {
			return fmt.Errorf("%w: anchor/vault binding", ErrInvalidRecoveryBundle)
		}
	}
	if chainAnchor != nil && vault != nil && policy != nil {
		if err := chainAnchor.VerifyAgainst(vault, policy); err != nil {
			return fmt.Errorf("%w: anchor binding: %v", ErrInvalidRecoveryBundle, err)
		}
	}
	if chainAnchor != nil && receipt != nil {
		if receipt.VaultID != chainAnchor.VaultID || receipt.PolicyID != chainAnchor.PolicyID || receipt.CheckInSeq != chainAnchor.CheckInSeq || receipt.Deadline != chainAnchor.Deadline {
			return fmt.Errorf("%w: receipt/anchor binding", ErrInvalidRecoveryBundle)
		}
		wire, err := chainAnchor.ToDEROAnchor()
		if err != nil {
			return err
		}
		packed, err := dero.PackArguments(wire.ToArguments())
		if err != nil || DigestAnchorWire(packed) != receipt.WireDigest {
			return fmt.Errorf("%w: receipt wire digest binding", ErrInvalidRecoveryBundle)
		}
	}
	var watchState *WatchState
	if raw := files["continuity-watch.json"]; raw != nil {
		var err error
		watchState, err = ParseWatchState(raw)
		if err != nil {
			return err
		}
		if vault != nil {
			if err := watchState.VerifyForVault(vault); err != nil {
				return fmt.Errorf("%w: watch binding: %v", ErrInvalidRecoveryBundle, err)
			}
		}
	}
	var notice *ReleaseNotice
	if raw := files["continuity-release-notice.json"]; raw != nil {
		var err error
		notice, err = ParseNotice(raw)
		if err != nil {
			return err
		}
		if vault != nil {
			if err := VerifyNoticeForVault(vault, notice); err != nil {
				return fmt.Errorf("%w: notice binding: %v", ErrInvalidRecoveryBundle, err)
			}
		}
	}
	if notice != nil && watchState != nil {
		if notice.VaultID != watchState.VaultID || notice.PolicyID != watchState.PolicyID || notice.OwnerSigPub != watchState.OwnerSigPub || notice.CheckInSeq != watchState.CheckInSeq || notice.LastCheckIn != watchState.LastCheckIn || notice.Deadline != watchState.Deadline || notice.ObserverPub != watchState.ObserverPub {
			return fmt.Errorf("%w: watch/notice binding", ErrInvalidRecoveryBundle)
		}
	}
	if raw := files["quorum-release.json"]; raw != nil {
		q, err := ParseQuorumRelease(raw)
		if err != nil {
			return err
		}
		if vault != nil {
			if err := VerifyNoticeQuorumForVault(vault, q); err != nil {
				return fmt.Errorf("%w: quorum binding: %v", ErrInvalidRecoveryBundle, err)
			}
		}
		if policy != nil && q.Policy.PolicyID != policy.PolicyID {
			return fmt.Errorf("%w: quorum/policy binding", ErrInvalidRecoveryBundle)
		}
		if notice != nil {
			seenNotice := false
			for _, attestation := range q.Attestations {
				if attestation.Notice == *notice {
					seenNotice = true
					break
				}
			}
			if !seenNotice {
				return fmt.Errorf("%w: quorum/notice binding", ErrInvalidRecoveryBundle)
			}
		}
	}
	return nil
}

func recoveryBundleID(b RecoveryBundle) string {
	copy := b
	copy.BundleID = ""
	copy.CreatedAt = 0
	data, _ := json.Marshal(struct {
		Type      string             `json:"type"`
		Version   uint8              `json:"version"`
		Artifacts []RecoveryArtifact `json:"artifacts"`
	}{copy.Type, copy.Version, copy.Artifacts})
	h := sha256.Sum256(append([]byte(domain+"/recovery-bundle/v1"), data...))
	return hex.EncodeToString(h[:])
}
