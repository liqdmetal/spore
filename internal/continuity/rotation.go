package continuity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

const (
	revocationVersion    uint8 = 1
	revocationType             = "spore-continuity-revocations"
	rotationVersion      uint8 = 1
	rotationType               = "spore-continuity-vault-rotation"
	checkpointType             = "spore-continuity-revocation-checkpoint"
	maxRevocationRecords       = MaxCheckIns
)

var (
	ErrInvalidRevocation = errors.New("continuity: invalid revocation state")
	ErrKeyRevoked        = errors.New("continuity: key is revoked")
	ErrInvalidRotation   = errors.New("continuity: invalid vault rotation")
	ErrVaultRetired      = errors.New("continuity: vault is retired")
)

type RevocationKind string

const (
	RevokedRecipient RevocationKind = "recipient"
	RevokedObserver  RevocationKind = "observer"
)

type RevocationState struct {
	Version     uint8              `json:"version"`
	Type        string             `json:"type"`
	VaultID     string             `json:"vault_id"`
	PolicyID    string             `json:"policy_id"`
	OwnerSigPub string             `json:"owner_sig_pub"`
	Records     []RevocationRecord `json:"records"`
}

type RevocationRecord struct {
	Seq       uint64         `json:"seq"`
	Kind      RevocationKind `json:"kind"`
	Subject   string         `json:"subject"`
	At        int64          `json:"at"`
	Prev      string         `json:"prev"`
	Signature string         `json:"signature"`
}

func NewRevocationState(v *Vault) (*RevocationState, error) {
	if v == nil || v.Verify() != nil {
		return nil, ErrInvalidRevocation
	}
	return &RevocationState{Version: revocationVersion, Type: revocationType, VaultID: v.VaultID, PolicyID: v.PolicyID, OwnerSigPub: v.OwnerSigPub}, nil
}

func (s *RevocationState) Revoke(v *Vault, ownerPriv []byte, kind RevocationKind, subject []byte, at int64) error {
	if s == nil || v == nil || s.VerifyForVault(v) != nil || at < v.CreatedAt || at <= 0 || len(s.Records) >= maxRevocationRecords || (kind != RevokedRecipient && kind != RevokedObserver) || len(subject) != ed25519.PublicKeySize {
		return ErrInvalidRevocation
	}
	owner, err := ownerSigningPrivate(v, ownerPriv)
	if err != nil {
		return err
	}
	defer sporecrypto.Zero(owner)
	hexSubject := hex.EncodeToString(subject)
	for _, record := range s.Records {
		if record.Kind == kind && record.Subject == hexSubject {
			return ErrInvalidRevocation
		}
	}
	record := RevocationRecord{Seq: uint64(len(s.Records)), Kind: kind, Subject: hexSubject, At: at}
	if len(s.Records) > 0 {
		record.Prev = revocationDigest(s.Records[len(s.Records)-1])
	}
	record.Signature = hex.EncodeToString(ed25519.Sign(owner, revocationTranscript(s.VaultID, record)))
	s.Records = append(s.Records, record)
	return s.VerifyForVault(v)
}

func (s *RevocationState) VerifyForVault(v *Vault) error {
	if s == nil || v == nil || v.Verify() != nil || s.VaultID != v.VaultID || s.PolicyID != v.PolicyID || s.OwnerSigPub != v.OwnerSigPub {
		return ErrInvalidRevocation
	}
	for _, record := range s.Records {
		if record.At < v.CreatedAt {
			return ErrInvalidRevocation
		}
	}
	return s.Verify()
}

// Verify authenticates the self-contained revocation chain. Vault binding is
// deliberately separate because the vault carries the authoritative creation
// and owner-policy identity.
func (s *RevocationState) Verify() error {
	if s == nil || s.Version != revocationVersion || s.Type != revocationType || len(s.Records) > maxRevocationRecords {
		return ErrInvalidRevocation
	}
	vaultID, err := decodeFixed(s.VaultID, 32)
	if err != nil || isZero(vaultID) {
		return ErrInvalidRevocation
	}
	policyID, err := decodeFixed(s.PolicyID, 32)
	if err != nil || isZero(policyID) {
		return ErrInvalidRevocation
	}
	pub, err := decodeFixed(s.OwnerSigPub, ed25519.PublicKeySize)
	if err != nil || isZero(pub) {
		return ErrInvalidRevocation
	}
	seen := make(map[string]struct{}, len(s.Records))
	for i, record := range s.Records {
		if record.Seq != uint64(i) || record.At <= 0 || (record.Kind != RevokedRecipient && record.Kind != RevokedObserver) {
			return ErrInvalidRevocation
		}
		if _, err := decodeFixed(record.Subject, ed25519.PublicKeySize); err != nil {
			return ErrInvalidRevocation
		}
		key := string([]byte{byte(record.Kind[0])}) + ":" + record.Subject
		if _, exists := seen[key]; exists {
			return ErrInvalidRevocation
		}
		seen[key] = struct{}{}
		if i == 0 {
			if record.Prev != "" {
				return ErrInvalidRevocation
			}
		} else if record.Prev != revocationDigest(s.Records[i-1]) {
			return ErrInvalidRevocation
		}
		sig, err := hex.DecodeString(record.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), revocationTranscript(s.VaultID, record), sig) {
			return ErrInvalidRevocation
		}
	}
	return nil
}

func (s *RevocationState) IsRevoked(kind RevocationKind, subject []byte) bool {
	if s == nil {
		return false
	}
	want := hex.EncodeToString(subject)
	for _, record := range s.Records {
		if record.Kind == kind && record.Subject == want {
			return true
		}
	}
	return false
}

type RevocationCheckpoint struct {
	Version     uint8  `json:"version"`
	Type        string `json:"type"`
	VaultID     string `json:"vault_id"`
	PolicyID    string `json:"policy_id"`
	RecordCount uint64 `json:"record_count"`
	Head        string `json:"head"`
	OwnerSigPub string `json:"owner_sig_pub"`
	Signature   string `json:"signature"`
}

func NewRevocationCheckpoint(v *Vault, state *RevocationState, ownerPriv []byte) (*RevocationCheckpoint, error) {
	if v == nil || state == nil || state.VerifyForVault(v) != nil {
		return nil, ErrInvalidRevocation
	}
	owner, err := ownerSigningPrivate(v, ownerPriv)
	if err != nil {
		return nil, err
	}
	defer sporecrypto.Zero(owner)
	c := &RevocationCheckpoint{Version: revocationVersion, Type: checkpointType, VaultID: v.VaultID, PolicyID: v.PolicyID, RecordCount: uint64(len(state.Records)), OwnerSigPub: v.OwnerSigPub}
	if len(state.Records) > 0 {
		c.Head = revocationDigest(state.Records[len(state.Records)-1])
	}
	c.Signature = hex.EncodeToString(ed25519.Sign(owner, checkpointTranscript(c)))
	if err := VerifyRevocationCheckpoint(v, state, c); err != nil {
		return nil, err
	}
	return c, nil
}

func VerifyRevocationCheckpoint(v *Vault, state *RevocationState, c *RevocationCheckpoint) error {
	if v == nil || state == nil || c == nil || state.VerifyForVault(v) != nil || c.VaultID != v.VaultID || c.PolicyID != v.PolicyID || c.OwnerSigPub != v.OwnerSigPub || c.RecordCount != uint64(len(state.Records)) {
		return ErrInvalidRevocation
	}
	if err := VerifyRevocationCheckpointSelfContained(c); err != nil {
		return err
	}
	if c.RecordCount == 0 {
		if c.Head != "" {
			return ErrInvalidRevocation
		}
	} else if c.Head != revocationDigest(state.Records[c.RecordCount-1]) {
		return ErrInvalidRevocation
	}
	return nil
}

func VerifyRevocationCheckpointSelfContained(c *RevocationCheckpoint) error {
	if c == nil || c.Version != revocationVersion || c.Type != checkpointType || c.RecordCount > maxRevocationRecords {
		return ErrInvalidRevocation
	}
	vaultID, err := decodeFixed(c.VaultID, 32)
	if err != nil || isZero(vaultID) {
		return ErrInvalidRevocation
	}
	policyID, err := decodeFixed(c.PolicyID, 32)
	if err != nil || isZero(policyID) {
		return ErrInvalidRevocation
	}
	pub, err := decodeFixed(c.OwnerSigPub, ed25519.PublicKeySize)
	if err != nil || isZero(pub) {
		return ErrInvalidRevocation
	}
	if c.RecordCount == 0 {
		if c.Head != "" {
			return ErrInvalidRevocation
		}
	} else if len(c.Head) != 64 {
		return ErrInvalidRevocation
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), checkpointTranscript(c), sig) {
		return ErrInvalidRevocation
	}
	return nil
}

func VerifyRevocationForKey(v *Vault, state *RevocationState, checkpoint *RevocationCheckpoint, kind RevocationKind, pub []byte) error {
	if v == nil || state == nil || checkpoint == nil || len(pub) != ed25519.PublicKeySize {
		return ErrInvalidRevocation
	}
	if err := VerifyRevocationCheckpoint(v, state, checkpoint); err != nil {
		return err
	}
	if kind != RevokedRecipient && kind != RevokedObserver {
		return ErrInvalidRevocation
	}
	if state.IsRevoked(kind, pub) {
		return ErrKeyRevoked
	}
	return nil
}

func ReleaseWithRevocations(v *Vault, state *RevocationState, checkpoint *RevocationCheckpoint, recipientPriv []byte, now int64) ([]byte, error) {
	if v == nil || state == nil || checkpoint == nil {
		return nil, ErrInvalidRevocation
	}
	recipient, err := sporecrypto.KeyPairFromPriv(recipientPriv)
	if err != nil {
		return nil, ErrRecipientNotFound
	}
	if err := VerifyRevocationForKey(v, state, checkpoint, RevokedRecipient, recipient.Pub); err != nil {
		return nil, err
	}
	return Release(v, recipientPriv, now)
}

func ObserveWithRevocations(v *Vault, state *RevocationState, checkpoint *RevocationCheckpoint, observerPriv []byte, now int64) (*ReleaseNotice, error) {
	if len(observerPriv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidNotice
	}
	key := append(ed25519.PrivateKey(nil), observerPriv...)
	defer sporecrypto.Zero(key)
	if err := VerifyRevocationForKey(v, state, checkpoint, RevokedObserver, key.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	return Observe(v, observerPriv, now)
}

func AttestWithRevocations(policy *QuorumPolicy, v *Vault, state *RevocationState, checkpoint *RevocationCheckpoint, observerPriv []byte, now int64) (*QuorumAttestation, error) {
	if err := VerifyPolicyForVault(policy, v); err != nil {
		return nil, err
	}
	key := append(ed25519.PrivateKey(nil), observerPriv...)
	defer sporecrypto.Zero(key)
	if err := VerifyRevocationForKey(v, state, checkpoint, RevokedObserver, key.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	return Attest(policy, v, observerPriv, now)
}

func VerifyNoticeQuorumForVaultWithRevocations(v *Vault, q *QuorumRelease, state *RevocationState, checkpoint *RevocationCheckpoint) error {
	if err := VerifyNoticeQuorumForVault(v, q); err != nil {
		return err
	}
	for _, attestation := range q.Attestations {
		pub, err := hex.DecodeString(attestation.Attester)
		if err != nil {
			return ErrInvalidRevocation
		}
		if err := VerifyRevocationForKey(v, state, checkpoint, RevokedObserver, pub); err != nil {
			return err
		}
	}
	return nil
}

func ReleaseWithQuorumRevocations(v *Vault, q *QuorumRelease, state *RevocationState, checkpoint *RevocationCheckpoint, recipientPriv []byte, now int64) ([]byte, error) {
	if err := VerifyNoticeQuorumForVaultWithRevocations(v, q, state, checkpoint); err != nil {
		return nil, err
	}
	recipient, err := sporecrypto.KeyPairFromPriv(recipientPriv)
	if err != nil {
		return nil, ErrRecipientNotFound
	}
	if err := VerifyRevocationForKey(v, state, checkpoint, RevokedRecipient, recipient.Pub); err != nil {
		return nil, err
	}
	return Release(v, recipientPriv, now)
}

func NewQuorumReleaseWithRevocations(policy *QuorumPolicy, v *Vault, state *RevocationState, checkpoint *RevocationCheckpoint, attestations []QuorumAttestation) (*QuorumRelease, error) {
	q, err := NewQuorumRelease(policy, attestations)
	if err != nil {
		return nil, err
	}
	if err := VerifyNoticeQuorumForVaultWithRevocations(v, q, state, checkpoint); err != nil {
		return nil, err
	}
	return q, nil
}

type VaultRotation struct {
	Version     uint8  `json:"version"`
	Type        string `json:"type"`
	OldVaultID  string `json:"old_vault_id"`
	OldPolicyID string `json:"old_policy_id"`
	NewVaultID  string `json:"new_vault_id"`
	NewPolicyID string `json:"new_policy_id"`
	At          int64  `json:"at"`
	OwnerSigPub string `json:"owner_sig_pub"`
	Signature   string `json:"signature"`
}

func RotateVault(old *Vault, oldOwnerPriv []byte, opts CreateOptions) (*Vault, *VaultRotation, error) {
	if old == nil || old.Verify() != nil {
		return nil, nil, ErrInvalidRotation
	}
	newVault, err := Create(opts)
	if err != nil {
		return nil, nil, err
	}
	if opts.CreatedAt <= old.CreatedAt {
		return nil, nil, ErrInvalidRotation
	}
	owner, err := ownerSigningPrivate(old, oldOwnerPriv)
	if err != nil {
		return nil, nil, err
	}
	defer sporecrypto.Zero(owner)
	pub := owner.Public().(ed25519.PublicKey)
	cert := &VaultRotation{Version: rotationVersion, Type: rotationType, OldVaultID: old.VaultID, OldPolicyID: old.PolicyID, NewVaultID: newVault.VaultID, NewPolicyID: newVault.PolicyID, At: opts.CreatedAt, OwnerSigPub: hex.EncodeToString(pub)}
	cert.Signature = hex.EncodeToString(ed25519.Sign(owner, rotationTranscript(cert)))
	if err := VerifyRotation(old, newVault, cert); err != nil {
		return nil, nil, err
	}
	return newVault, cert, nil
}

func VerifyRotation(old, successor *Vault, cert *VaultRotation) error {
	if old == nil || successor == nil || cert == nil || old.Verify() != nil || successor.Verify() != nil || cert.OldVaultID != old.VaultID || cert.OldPolicyID != old.PolicyID || cert.NewVaultID != successor.VaultID || cert.NewPolicyID != successor.PolicyID || cert.At != successor.CreatedAt || cert.At <= old.CreatedAt || cert.OwnerSigPub != old.OwnerSigPub {
		return ErrInvalidRotation
	}
	return VerifyRotationSelfContained(cert)
}

func ReleaseWithRotation(old *Vault, cert *VaultRotation, successor *Vault, recipientPriv []byte, now int64) ([]byte, error) {
	if err := VerifyRotation(old, successor, cert); err != nil {
		return nil, err
	}
	return nil, ErrVaultRetired
}

func ownerSigningPrivate(v *Vault, ownerPriv []byte) (ed25519.PrivateKey, error) {
	if v == nil || len(ownerPriv) != 32 {
		return nil, ErrInvalidRevocation
	}
	key := append([]byte(nil), ownerPriv...)
	owner, err := sporecrypto.KeyPairFromPriv(key)
	sporecrypto.Zero(key)
	if err != nil || hex.EncodeToString(owner.Pub) != v.OwnerPub {
		return nil, ErrInvalidRevocation
	}
	return signingKey(ownerPriv), nil
}

func revocationTranscript(vaultID string, r RevocationRecord) []byte {
	b, _ := json.Marshal(struct {
		Domain  string         `json:"domain"`
		Vault   string         `json:"vault_id"`
		Seq     uint64         `json:"seq"`
		Kind    RevocationKind `json:"kind"`
		Subject string         `json:"subject"`
		At      int64          `json:"at"`
		Prev    string         `json:"prev"`
	}{domain + "/revocation/v1", vaultID, r.Seq, r.Kind, r.Subject, r.At, r.Prev})
	return b
}

func revocationDigest(r RevocationRecord) string {
	b, _ := json.Marshal(r)
	return hashBytes(b)
}

func checkpointTranscript(c *RevocationCheckpoint) []byte {
	b, _ := json.Marshal(struct {
		Domain      string `json:"domain"`
		Version     uint8  `json:"version"`
		Type        string `json:"type"`
		VaultID     string `json:"vault_id"`
		PolicyID    string `json:"policy_id"`
		RecordCount uint64 `json:"record_count"`
		Head        string `json:"head"`
		OwnerSigPub string `json:"owner_sig_pub"`
	}{domain + "/revocation-checkpoint/v1", c.Version, c.Type, c.VaultID, c.PolicyID, c.RecordCount, c.Head, c.OwnerSigPub})
	return b
}

func rotationTranscript(r *VaultRotation) []byte {
	b, _ := json.Marshal(struct {
		Domain      string `json:"domain"`
		Version     uint8  `json:"version"`
		OldVaultID  string `json:"old_vault_id"`
		OldPolicyID string `json:"old_policy_id"`
		NewVaultID  string `json:"new_vault_id"`
		NewPolicyID string `json:"new_policy_id"`
		At          int64  `json:"at"`
		OwnerSigPub string `json:"owner_sig_pub"`
	}{domain + "/rotation/v1", r.Version, r.OldVaultID, r.OldPolicyID, r.NewVaultID, r.NewPolicyID, r.At, r.OwnerSigPub})
	return b
}

func ParseRevocationState(raw []byte) (*RevocationState, error) {
	var s RevocationState
	if err := decodeStrict(raw, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRevocation, err)
	}
	if err := s.Verify(); err != nil {
		return nil, err
	}
	return &s, nil
}

func ParseRevocationCheckpoint(raw []byte) (*RevocationCheckpoint, error) {
	var c RevocationCheckpoint
	if err := decodeStrict(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRevocation, err)
	}
	if err := VerifyRevocationCheckpointSelfContained(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func ParseVaultRotation(raw []byte) (*VaultRotation, error) {
	var r VaultRotation
	if err := decodeStrict(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRotation, err)
	}
	if err := VerifyRotationSelfContained(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

func VerifyRotationSelfContained(r *VaultRotation) error {
	if r == nil || r.Version != rotationVersion || r.Type != rotationType || r.At <= 0 {
		return ErrInvalidRotation
	}
	if _, err := decodeFixed(r.OwnerSigPub, ed25519.PublicKeySize); err != nil {
		return ErrInvalidRotation
	}
	if _, err := decodeFixed(r.OldVaultID, 32); err != nil {
		return ErrInvalidRotation
	}
	if _, err := decodeFixed(r.OldPolicyID, 32); err != nil {
		return ErrInvalidRotation
	}
	if _, err := decodeFixed(r.NewVaultID, 32); err != nil {
		return ErrInvalidRotation
	}
	if _, err := decodeFixed(r.NewPolicyID, 32); err != nil {
		return ErrInvalidRotation
	}
	pub, err := decodeFixed(r.OwnerSigPub, ed25519.PublicKeySize)
	if err != nil {
		return ErrInvalidRotation
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), rotationTranscript(r), sig) {
		return ErrInvalidRotation
	}
	return nil
}

func MarshalRevocationState(s *RevocationState) ([]byte, error) { return json.Marshal(s) }
func MarshalVaultRotation(r *VaultRotation) ([]byte, error)     { return json.Marshal(r) }

func revokedKeys(s *RevocationState) []string {
	keys := make([]string, 0, len(s.Records))
	for _, r := range s.Records {
		keys = append(keys, r.Subject)
	}
	sort.Strings(keys)
	return keys
}
