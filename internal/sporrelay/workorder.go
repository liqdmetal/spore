package sporrelay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
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
	actorPublicKey, err := decodeRelayBase64(c.Actor.PublicKey)
	if err != nil || len(actorPublicKey) != ed25519.PublicKeySize {
		return errors.New("sporrelay: Relay actor public_key must be base64url-encoded Ed25519 key material")
	}
	if c.Actor.ActorID != relayActorIDForPublicKey(actorPublicKey) {
		return errors.New("sporrelay: Relay actor_id must be derived from its public_key")
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
	decoded, err := decodeRelayBase64(value)
	return err == nil && len(decoded) == wantBytes
}

func decodeRelayBase64(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return base64.URLEncoding.DecodeString(value)
	}
	return decoded, nil
}

func relayActorIDForPublicKey(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return "did:relay:" + hex.EncodeToString(digest[:])[:40]
}

// RelayActorID derives the Relay actor ID from raw Ed25519 public-key bytes.
func RelayActorID(publicKey ed25519.PublicKey) string {
	return relayActorIDForPublicKey(publicKey)
}

// PrepareAuthorizedWorkOrder assembles and actor-signs an objectives.register
// command using a caller-held Relay actor key, a RelayOS-issued grant, and a
// caller-supplied trusted issuer identity. It never creates or signs grants,
// chooses an issuer, checks revocation/replay state, or replaces RelayOS's
// authoritative authorization check.
func PrepareAuthorizedWorkOrder(actorPrivateKey ed25519.PrivateKey, trustedIssuer RelayActorIdentity, grant RelayAuthorityGrant, work WorkOrder) (AuthorizedWorkOrderCommand, error) {
	if len(actorPrivateKey) != ed25519.PrivateKeySize {
		return AuthorizedWorkOrderCommand{}, fmt.Errorf("sporrelay: Relay actor private key must be %d bytes", ed25519.PrivateKeySize)
	}
	derivedActorKey := ed25519.NewKeyFromSeed(actorPrivateKey[:ed25519.SeedSize])
	if !bytes.Equal(derivedActorKey, actorPrivateKey) {
		crypto.Zero(derivedActorKey)
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: Relay actor private key has inconsistent public-key bytes")
	}
	crypto.Zero(derivedActorKey)
	actorPublicKey := actorPrivateKey[ed25519.SeedSize:]
	actorID := relayActorIDForPublicKey(actorPublicKey)

	if err := work.Validate(); err != nil {
		return AuthorizedWorkOrderCommand{}, err
	}
	if trustedIssuer.ActorID == "" {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: trusted Relay issuer actor_id is required")
	}
	issuerPublicKey, err := decodeRelayBase64(trustedIssuer.PublicKey)
	if err != nil || len(issuerPublicKey) != ed25519.PublicKeySize {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: trusted Relay issuer public_key must be base64url-encoded Ed25519 key material")
	}
	if trustedIssuer.ActorID != relayActorIDForPublicKey(issuerPublicKey) {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: trusted Relay issuer actor_id does not match its public_key")
	}
	if grant.IssuerID != trustedIssuer.ActorID {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: authority grant issuer does not match the supplied trusted Relay issuer")
	}
	if grant.SubjectID != actorID {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: authority grant subject does not match the local Relay actor key")
	}
	if grant.ResourceID != work.ObjectiveID {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: authority grant resource must exactly match objective_id")
	}
	if len(grant.Scopes) != 1 || grant.Scopes[0] != RegisterObjectiveAction {
		return AuthorizedWorkOrderCommand{}, fmt.Errorf("sporrelay: authority grant must contain only scope %q", RegisterObjectiveAction)
	}
	if strings.TrimSpace(grant.Nonce) == "" {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: authority grant nonce is required")
	}
	grantSignature, err := decodeRelayBase64(grant.Signature)
	if err != nil || len(grantSignature) != ed25519.SignatureSize {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: RelayOS-issued grant must contain a base64url Ed25519 signature")
	}
	notBefore, err := time.Parse(time.RFC3339Nano, grant.NotBefore)
	if err != nil {
		return AuthorizedWorkOrderCommand{}, fmt.Errorf("sporrelay: authority grant not_before is not RFC3339: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil {
		return AuthorizedWorkOrderCommand{}, fmt.Errorf("sporrelay: authority grant expires_at is not RFC3339: %w", err)
	}
	now := time.Now()
	if expiresAt.Before(notBefore) || now.Before(notBefore) || now.After(expiresAt) {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: authority grant is not currently valid")
	}
	unsignedGrant, err := relayUnsignedGrant(grant)
	if err != nil {
		return AuthorizedWorkOrderCommand{}, fmt.Errorf("sporrelay: canonicalize RelayOS authority grant: %w", err)
	}
	grantBytes, err := relayCanonicalJSON(unsignedGrant)
	if err != nil {
		return AuthorizedWorkOrderCommand{}, fmt.Errorf("sporrelay: canonicalize RelayOS authority grant: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(issuerPublicKey), grantBytes, grantSignature) {
		return AuthorizedWorkOrderCommand{}, errors.New("sporrelay: authority grant signature is invalid for the supplied trusted issuer")
	}

	command := AuthorizedWorkOrderCommand{
		Actor: RelayActorIdentity{
			ActorID:   actorID,
			PublicKey: base64.RawURLEncoding.EncodeToString(actorPublicKey),
		},
		Scope: RegisterObjectiveAction,
		Command: ObjectiveRegistrationCommand{
			Action: RegisterObjectiveAction, ResourceID: work.ObjectiveID, Payload: work,
		},
		Grant: grant,
	}
	grantBytes, err = relayCanonicalJSON(grant)
	if err != nil {
		return AuthorizedWorkOrderCommand{}, fmt.Errorf("sporrelay: canonicalize RelayOS authority grant: %w", err)
	}
	grantHash := sha256.Sum256(grantBytes)
	actorPayload := map[string]any{
		"actor_id":     actorID,
		"scope":        command.Scope,
		"command_type": "IngressCommand",
		"command":      command.Command,
		"grant_hash":   hex.EncodeToString(grantHash[:]),
	}
	actorBytes, err := relayCanonicalJSON(actorPayload)
	if err != nil {
		return AuthorizedWorkOrderCommand{}, fmt.Errorf("sporrelay: canonicalize RelayOS command signature: %w", err)
	}
	command.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(actorPrivateKey, actorBytes))
	if err := command.Validate(); err != nil {
		return AuthorizedWorkOrderCommand{}, err
	}
	return command, nil
}

func relayUnsignedGrant(grant RelayAuthorityGrant) (map[string]any, error) {
	data, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	delete(fields, "signature")
	return fields, nil
}

// relayCanonicalJSON mirrors RelayOS's canonical_bytes for these protocol
// values: lexically sorted object keys, compact JSON, and Python's default
// ensure_ascii string escaping. This keeps actor/grant signatures compatible
// without relying on Go's different U+2028/U+2029 and Unicode escaping rules.
func relayCanonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var canonical bytes.Buffer
	if err := writeRelayCanonicalJSON(&canonical, normalized); err != nil {
		return nil, err
	}
	return canonical.Bytes(), nil
}

func writeRelayCanonicalJSON(out *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		writeRelayJSONString(out, value)
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeRelayCanonicalJSON(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeRelayJSONString(out, key)
			out.WriteByte(':')
			if err := writeRelayCanonicalJSON(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case json.Number:
		return errors.New("RelayOS signed command values cannot contain JSON numbers")
	default:
		return fmt.Errorf("unsupported RelayOS canonical JSON value %T", value)
	}
	return nil
}

func writeRelayJSONString(out *bytes.Buffer, value string) {
	const digits = "0123456789abcdef"
	writeEscape := func(codepoint uint16) {
		out.WriteString("\\u")
		out.WriteByte(digits[(codepoint>>12)&0xf])
		out.WriteByte(digits[(codepoint>>8)&0xf])
		out.WriteByte(digits[(codepoint>>4)&0xf])
		out.WriteByte(digits[codepoint&0xf])
	}
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteByte(byte(r))
		case '\b':
			out.WriteString("\\b")
		case '\f':
			out.WriteString("\\f")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		case '\t':
			out.WriteString("\\t")
		default:
			switch {
			case r < 0x20:
				writeEscape(uint16(r))
			case r <= 0x7f:
				out.WriteByte(byte(r))
			case r <= 0xffff:
				writeEscape(uint16(r))
			default:
				r -= 0x10000
				writeEscape(uint16(0xd800 + (r >> 10)))
				writeEscape(uint16(0xdc00 + (r & 0x3ff)))
			}
		}
	}
	out.WriteByte('"')
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
