package continuity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

const quorumVersion uint8 = 1

var (
	ErrInvalidQuorum       = errors.New("continuity: invalid quorum")
	ErrQuorumNotMet        = errors.New("continuity: quorum threshold not met")
	ErrDuplicateAttester   = errors.New("continuity: duplicate attester")
	ErrAttesterNotApproved = errors.New("continuity: attester is not approved")
)

// QuorumPolicy approves independent observer keys for one exact vault epoch.
// It contains non-secret metadata only. A later owner check-in makes this policy
// stale and requires a new policy, preventing old notices from being replayed.
type QuorumPolicy struct {
	Version     uint8    `json:"version"`
	PolicyID    string   `json:"policy_id"`
	VaultID     string   `json:"vault_id"`
	VaultPolicy string   `json:"vault_policy_id"`
	OwnerSigPub string   `json:"owner_sig_pub"`
	CheckInSeq  uint64   `json:"checkin_seq"`
	LastCheckIn int64    `json:"last_check_in"`
	Deadline    int64    `json:"deadline"`
	Threshold   uint     `json:"threshold"`
	Attesters   []string `json:"attesters"`
}

// QuorumAttestation is one attester's signed release-ready notice. The notice
// is copied into the quorum bundle so the bundle is independently verifiable.
type QuorumAttestation struct {
	Attester string        `json:"attester"`
	Notice   ReleaseNotice `json:"notice"`
}

// QuorumRelease is an explicit, non-decrypting quorum result. It authorizes no
// automatic action; a designated recipient still calls ReleaseWithQuorum.
type QuorumRelease struct {
	Version      uint8               `json:"version"`
	QuorumID     string              `json:"quorum_id"`
	Policy       QuorumPolicy        `json:"policy"`
	Attestations []QuorumAttestation `json:"attestations"`
}

// NewQuorumPolicy binds the threshold and approved observer keys to the
// vault's currently signed check-in epoch.
func NewQuorumPolicy(v *Vault, threshold uint, attesters [][]byte) (*QuorumPolicy, error) {
	if v == nil || v.Verify() != nil || threshold == 0 || threshold > uint(len(attesters)) {
		return nil, ErrInvalidQuorum
	}
	last := v.Checkins[len(v.Checkins)-1]
	keys := make([]string, 0, len(attesters))
	seen := make(map[string]struct{}, len(attesters))
	for _, raw := range attesters {
		if len(raw) != ed25519.PublicKeySize {
			return nil, ErrInvalidQuorum
		}
		key := hex.EncodeToString(raw)
		if _, ok := seen[key]; ok {
			return nil, ErrDuplicateAttester
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	p := &QuorumPolicy{
		Version: quorumVersion, VaultID: v.VaultID, VaultPolicy: v.PolicyID,
		OwnerSigPub: v.OwnerSigPub, CheckInSeq: last.Seq, LastCheckIn: last.At,
		Deadline: last.Deadline, Threshold: threshold, Attesters: keys,
	}
	p.PolicyID = quorumPolicyID(*p)
	return p, nil
}

// Attest signs a release-ready notice under an approved independent attester
// key. The vault contains only non-secret metadata and ciphertext; no payload
// plaintext or recipient private key is accessed.
func Attest(policy *QuorumPolicy, v *Vault, observerPriv []byte, now int64) (*QuorumAttestation, error) {
	if policy == nil || v == nil || len(observerPriv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidQuorum
	}
	if err := VerifyPolicyForVault(policy, v); err != nil {
		return nil, err
	}
	n, err := Observe(v, observerPriv, now)
	if err != nil {
		return nil, err
	}
	key := append(ed25519.PrivateKey(nil), observerPriv...)
	defer sporecrypto.Zero(key)
	attester := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if !policyAllows(policy, attester) {
		return nil, ErrAttesterNotApproved
	}
	return &QuorumAttestation{Attester: attester, Notice: *n}, nil
}

// NewQuorumRelease verifies distinct approved attestations and returns a
// threshold result. All attestations must match the policy's exact epoch.
func NewQuorumRelease(policy *QuorumPolicy, attestations []QuorumAttestation) (*QuorumRelease, error) {
	if policy == nil || verifyPolicy(*policy) != nil || len(attestations) < int(policy.Threshold) {
		return nil, ErrQuorumNotMet
	}
	seen := make(map[string]struct{}, len(attestations))
	valid := make([]QuorumAttestation, 0, len(attestations))
	for _, att := range attestations {
		if _, ok := seen[att.Attester]; ok {
			return nil, ErrDuplicateAttester
		}
		seen[att.Attester] = struct{}{}
		if !policyAllows(policy, att.Attester) || att.Attester != att.Notice.ObserverPub {
			return nil, ErrAttesterNotApproved
		}
		if err := att.Notice.Verify(); err != nil {
			return nil, err
		}
		if !noticeMatchesPolicy(policy, att.Notice) {
			return nil, fmt.Errorf("%w: attestation does not match policy epoch", ErrInvalidQuorum)
		}
		valid = append(valid, att)
	}
	if len(valid) < int(policy.Threshold) {
		return nil, ErrQuorumNotMet
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Attester < valid[j].Attester })
	q := &QuorumRelease{Version: quorumVersion, Policy: *policy, Attestations: valid}
	q.QuorumID = quorumReleaseID(*q)
	return q, nil
}

// ReleaseWithQuorum decrypts only after the quorum bundle and the current vault
// both verify. It remains explicit and local; it never moves funds or contacts
// an observer.
func ReleaseWithQuorum(v *Vault, q *QuorumRelease, recipientPriv []byte, now int64) ([]byte, error) {
	if v == nil || q == nil {
		return nil, ErrInvalidQuorum
	}
	if err := VerifyNoticeQuorumForVault(v, q); err != nil {
		return nil, err
	}
	return Release(v, recipientPriv, now)
}

// Verify authenticates a quorum result without private keys or the payload.
func (q *QuorumRelease) Verify() error {
	if q == nil || q.Version != quorumVersion {
		return ErrInvalidQuorum
	}
	if err := verifyPolicy(q.Policy); err != nil {
		return err
	}
	built, err := NewQuorumRelease(&q.Policy, q.Attestations)
	if err != nil {
		return err
	}
	if q.QuorumID != built.QuorumID {
		return ErrInvalidQuorum
	}
	return nil
}

// VerifyNoticeQuorumForVault verifies the quorum and binds it to the current
// vault epoch, rejecting a quorum made obsolete by a later owner check-in.
func VerifyNoticeQuorumForVault(v *Vault, q *QuorumRelease) error {
	if v == nil || q == nil {
		return ErrInvalidQuorum
	}
	if err := v.Verify(); err != nil {
		return err
	}
	if err := q.Verify(); err != nil {
		return err
	}
	if err := VerifyPolicyForVault(&q.Policy, v); err != nil {
		return err
	}
	return nil
}

// ParseQuorumPolicy decodes and validates a policy from its JSON form.
func ParseQuorumPolicy(raw []byte) (*QuorumPolicy, error) {
	var p QuorumPolicy
	if err := decodeStrict(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidQuorum, err)
	}
	if err := verifyPolicy(p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseQuorumAttestation decodes one attestation and verifies its embedded
// observer signature. Policy binding is intentionally deferred to the caller.
func ParseQuorumAttestation(raw []byte) (*QuorumAttestation, error) {
	var a QuorumAttestation
	if err := decodeStrict(raw, &a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidQuorum, err)
	}
	if err := a.Notice.Verify(); err != nil {
		return nil, err
	}
	if a.Attester != a.Notice.ObserverPub {
		return nil, ErrInvalidQuorum
	}
	if _, err := decodeFixed(a.Attester, ed25519.PublicKeySize); err != nil {
		return nil, ErrInvalidQuorum
	}
	return &a, nil
}

// ParseQuorumRelease decodes and validates a complete quorum bundle.
func ParseQuorumRelease(raw []byte) (*QuorumRelease, error) {
	var q QuorumRelease
	if err := decodeStrict(raw, &q); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidQuorum, err)
	}
	if err := q.Verify(); err != nil {
		return nil, err
	}
	return &q, nil
}

func VerifyPolicyForVault(policy *QuorumPolicy, v *Vault) error {
	if policy == nil || v == nil {
		return ErrInvalidQuorum
	}
	if err := v.Verify(); err != nil {
		return err
	}
	if err := verifyPolicy(*policy); err != nil {
		return err
	}
	last := v.Checkins[len(v.Checkins)-1]
	if policy.VaultID != v.VaultID || policy.VaultPolicy != v.PolicyID || policy.OwnerSigPub != v.OwnerSigPub || policy.CheckInSeq != last.Seq || policy.LastCheckIn != last.At || policy.Deadline != last.Deadline {
		return fmt.Errorf("%w: quorum policy does not match vault", ErrInvalidQuorum)
	}
	return nil
}

func verifyPolicy(p QuorumPolicy) error {
	if p.Version != quorumVersion || p.PolicyID == "" || p.Threshold == 0 || p.Threshold > uint(len(p.Attesters)) || p.VaultPolicy == "" {
		return ErrInvalidQuorum
	}
	vaultID, err := decodeFixed(p.VaultID, 32)
	if err != nil || isZero(vaultID) {
		return ErrInvalidQuorum
	}
	vaultPolicyID, err := decodeFixed(p.VaultPolicy, 32)
	if err != nil || isZero(vaultPolicyID) {
		return ErrInvalidQuorum
	}
	ownerSigPub, err := decodeFixed(p.OwnerSigPub, ed25519.PublicKeySize)
	if err != nil || isZero(ownerSigPub) {
		return ErrInvalidQuorum
	}
	if p.LastCheckIn <= 0 || p.Deadline <= p.LastCheckIn {
		return ErrInvalidQuorum
	}
	prev := ""
	for _, key := range p.Attesters {
		if _, err := decodeFixed(key, ed25519.PublicKeySize); err != nil || key <= prev {
			return ErrInvalidQuorum
		}
		prev = key
	}
	if quorumPolicyID(p) != p.PolicyID {
		return ErrInvalidQuorum
	}
	return nil
}

func noticeMatchesPolicy(p *QuorumPolicy, n ReleaseNotice) bool {
	return n.VaultID == p.VaultID && n.PolicyID == p.VaultPolicy && n.OwnerSigPub == p.OwnerSigPub && n.CheckInSeq == p.CheckInSeq && n.LastCheckIn == p.LastCheckIn && n.Deadline == p.Deadline
}

func policyAllows(p *QuorumPolicy, key string) bool {
	i := sort.SearchStrings(p.Attesters, key)
	return i < len(p.Attesters) && p.Attesters[i] == key
}

func quorumPolicyID(p QuorumPolicy) string {
	b, _ := json.Marshal(struct {
		Domain      string   `json:"domain"`
		Version     uint8    `json:"version"`
		VaultID     string   `json:"vault_id"`
		VaultPolicy string   `json:"vault_policy_id"`
		OwnerSigPub string   `json:"owner_sig_pub"`
		CheckInSeq  uint64   `json:"checkin_seq"`
		LastCheckIn int64    `json:"last_check_in"`
		Deadline    int64    `json:"deadline"`
		Threshold   uint     `json:"threshold"`
		Attesters   []string `json:"attesters"`
	}{domain + "/quorum-policy/v1", p.Version, p.VaultID, p.VaultPolicy, p.OwnerSigPub, p.CheckInSeq, p.LastCheckIn, p.Deadline, p.Threshold, p.Attesters})
	return hashBytes(b)
}

func quorumReleaseID(q QuorumRelease) string {
	b, _ := json.Marshal(struct {
		Domain       string              `json:"domain"`
		Version      uint8               `json:"version"`
		PolicyID     string              `json:"policy_id"`
		Attestations []QuorumAttestation `json:"attestations"`
	}{domain + "/quorum-release/v1", q.Version, q.Policy.PolicyID, q.Attestations})
	return hashBytes(b)
}

func hashBytes(b []byte) string {
	h := sha256.Sum256(append([]byte(domain+"/quorum/"), b...))
	return hex.EncodeToString(h[:])
}
