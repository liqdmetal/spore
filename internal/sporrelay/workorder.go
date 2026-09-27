package sporrelay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

const RegisterObjectiveAction = "objectives.register"

// WorkOrder is RelayOS's objective registration payload. It exposes only
// privacy-preserving commitments; the detailed task and acceptance policy stay
// with the buyer and provider until a later execution protocol exists.
type WorkOrder struct {
	ObjectiveID           string `json:"objective_id"`
	OwnerPseudonym        string `json:"owner_pseudonym"`
	DescriptionCommitment string `json:"description_commitment"`
	PolicyHash            string `json:"policy_hash"`
}

// NewWorkOrder creates a registration payload with an opaque UUIDv7 objective
// identifier. Owner and commitments remain caller-supplied; this function does
// not create a Relay identity or assert a wallet binding.
func NewWorkOrder(ownerPseudonym, descriptionCommitment, policyHash string) WorkOrder {
	return WorkOrder{
		ObjectiveID:           generateObjID(),
		OwnerPseudonym:        ownerPseudonym,
		DescriptionCommitment: descriptionCommitment,
		PolicyHash:            policyHash,
	}
}

func (w WorkOrder) Validate() error {
	if strings.TrimSpace(w.ObjectiveID) == "" {
		return errors.New("sporrelay: work order objective_id is required")
	}
	if strings.TrimSpace(w.OwnerPseudonym) == "" {
		return errors.New("sporrelay: work order owner_pseudonym is required")
	}
	if strings.TrimSpace(w.DescriptionCommitment) == "" {
		return errors.New("sporrelay: work order description_commitment is required")
	}
	if strings.TrimSpace(w.PolicyHash) == "" {
		return errors.New("sporrelay: work order policy_hash is required")
	}
	return nil
}

// RelayActorIdentity is RelayOS's identity, distinct from Spore's pinned
// messaging identity and any chain wallet address.
type RelayActorIdentity struct {
	ActorID   string `json:"actor_id"`
	PublicKey string `json:"public_key"`
}

// RelayAuthorityGrant mirrors the resource- and scope-bounded grant validated
// by RelayOS AuthorityCode. Spore checks its binding fields but deliberately
// leaves cryptographic verification, revocation, expiry, and replay protection
// to the authoritative RelayOS service.
type RelayAuthorityGrant struct {
	IssuerID   string   `json:"issuer_id"`
	SubjectID  string   `json:"subject_id"`
	ResourceID string   `json:"resource_id"`
	Scopes     []string `json:"scopes"`
	NotBefore  string   `json:"not_before"`
	ExpiresAt  string   `json:"expires_at"`
	Nonce      string   `json:"nonce"`
	Signature  string   `json:"signature"`
}

// ObjectiveRegistrationCommand is the concrete objectives.register action
// supported by the inspected RelayOS /v1/commands service.
type ObjectiveRegistrationCommand struct {
	Action     string    `json:"action"`
	ResourceID string    `json:"resource_id"`
	Payload    WorkOrder `json:"payload"`
}

// AuthorizedWorkOrderCommand is an already-authorized RelayOS envelope. The
// caller obtains/signs it using RelayOS's trusted issuer and actor identities;
// Spore forwards it unchanged and never substitutes its own key material.
type AuthorizedWorkOrderCommand struct {
	Actor     RelayActorIdentity           `json:"actor"`
	Scope     string                       `json:"scope"`
	Command   ObjectiveRegistrationCommand `json:"command"`
	Grant     RelayAuthorityGrant          `json:"grant"`
	Signature string                       `json:"signature"`
}

// Validate enforces the local least-authority envelope shape. It is not a
// cryptographic verification; RelayOS still verifies issuer/actor signatures,
// grant lifetime/revocation, nonce replay, resource, and scope.
func (c AuthorizedWorkOrderCommand) Validate() error {
	if strings.TrimSpace(c.Actor.ActorID) == "" || strings.TrimSpace(c.Actor.PublicKey) == "" {
		return errors.New("sporrelay: Relay actor identity is incomplete")
	}
	if !validRelayBase64(c.Actor.PublicKey, ed25519.PublicKeySize) {
		return errors.New("sporrelay: Relay actor public_key must be base64url-encoded Ed25519 key material")
	}
	if c.Command.Action != RegisterObjectiveAction || c.Scope != RegisterObjectiveAction || c.Scope != c.Command.Action {
		return fmt.Errorf("sporrelay: only a signed %q command is supported", RegisterObjectiveAction)
	}
	if err := c.Command.Payload.Validate(); err != nil {
		return err
	}
	if c.Command.ResourceID != c.Command.Payload.ObjectiveID {
		return errors.New("sporrelay: command resource_id must equal work order objective_id")
	}
	if strings.TrimSpace(c.Grant.IssuerID) == "" || strings.TrimSpace(c.Grant.Signature) == "" || strings.TrimSpace(c.Signature) == "" || strings.TrimSpace(c.Grant.Nonce) == "" || strings.TrimSpace(c.Grant.NotBefore) == "" || strings.TrimSpace(c.Grant.ExpiresAt) == "" {
		return errors.New("sporrelay: signed authority grant and command signature are required")
	}
	if !validRelayBase64(c.Grant.Signature, ed25519.SignatureSize) || !validRelayBase64(c.Signature, ed25519.SignatureSize) {
		return errors.New("sporrelay: RelayOS command and grant signatures must be base64url-encoded Ed25519 signatures")
	}
	if c.Grant.SubjectID != c.Actor.ActorID {
		return errors.New("sporrelay: authority grant subject does not match Relay actor")
	}
	if c.Grant.ResourceID != c.Command.ResourceID {
		return errors.New("sporrelay: authority grant must be scoped to this work order resource")
	}
	if _, err := time.Parse(time.RFC3339Nano, c.Grant.NotBefore); err != nil {
		return fmt.Errorf("sporrelay: authority grant not_before is not RFC3339: %w", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, c.Grant.ExpiresAt); err != nil {
		return fmt.Errorf("sporrelay: authority grant expires_at is not RFC3339: %w", err)
	}
	if len(c.Grant.Scopes) != 1 || c.Grant.Scopes[0] != RegisterObjectiveAction {
		return fmt.Errorf("sporrelay: authority grant must contain only scope %q", RegisterObjectiveAction)
	}
	return nil
}

func validRelayBase64(value string, wantBytes int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(value)
	}
	return err == nil && len(decoded) == wantBytes
}

// ObjectiveRegistrationResult is only the RelayOS record returned after
// registration. It is not a work completion, acceptance, or payment receipt.
type ObjectiveRegistrationResult struct {
	ObjectiveID           string `json:"objective_id"`
	OwnerPseudonym        string `json:"owner_pseudonym"`
	DescriptionCommitment string `json:"description_commitment"`
	PolicyHash            string `json:"policy_hash"`
}

func (r ObjectiveRegistrationResult) matches(w WorkOrder) bool {
	return r.ObjectiveID == w.ObjectiveID &&
		r.OwnerPseudonym == w.OwnerPseudonym &&
		r.DescriptionCommitment == w.DescriptionCommitment &&
		r.PolicyHash == w.PolicyHash
}

// UUIDv7 objective IDs are monotonically increasing within this process. IDs
// from separate processes have no total ordering; the random tail supplies
// collision resistance across installations.
var (
	objIDMu      sync.Mutex
	objIDLastMS  int64 = math.MinInt64
	objIDCounter uint16
)

func generateObjID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("sporrelay: generateObjID: crypto/rand unavailable: %v", err))
	}
	objIDMu.Lock()
	defer objIDMu.Unlock()
	now := time.Now().UnixMilli()
	if now > objIDLastMS {
		objIDLastMS = now
		objIDCounter = objIDRandA(b)
	} else {
		objIDCounter++
		if objIDCounter == 1<<12 {
			objIDLastMS++
			objIDCounter = objIDRandA(b)
		}
	}
	ms := uint64(objIDLastMS)
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	b[6] = 0x70 | byte(objIDCounter>>8)
	b[7] = byte(objIDCounter)
	b[8] = (b[8] & 0x3f) | 0x80
	return formatUUID(b)
}

func objIDRandA(b [16]byte) uint16 { return uint16(b[6]&0x0f)<<8 | uint16(b[7]) }

func formatUUID(b [16]byte) string {
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst)
}
