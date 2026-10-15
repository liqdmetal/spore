// Package handoff implements private, human-reviewed work coordination. It is
// not a RelayOS execution protocol, independent verifier, or settlement rail.
package handoff

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/sporrelay"
)

const (
	Domain     = "spore/private-handoff/v1"
	MaxContent = 16 << 10
	MaxPolicy  = 8 << 10
	MaxMessage = 96 << 10
	MaxStore   = 8 << 20
)

type Peer struct {
	Address string `json:"address"`
	Pinned  string `json:"pinned_sig"`
}

// Registration is a local observation exported by work-order register, not a
// server-signed receipt or an independently verifiable RelayOS state proof.
type Registration struct {
	// Source is empty for a RelayOS observation. local-dao-review explicitly
	// denotes local commitments and MUST NOT imply any remote registration.
	Source     string              `json:"source,omitempty"`
	Version    int                 `json:"version"`
	RelayURL   string              `json:"relay_url"`
	ActorID    string              `json:"actor_id"`
	Objective  sporrelay.WorkOrder `json:"objective"`
	ObservedAt int64               `json:"observed_at"`
}

func (r Registration) Validate() error {
	if r.Source == "local-dao-review" {
		if r.Version != 1 || r.ObservedAt <= 0 || r.RelayURL != "" || r.ActorID != "" {
			return errors.New("handoff: local review cannot claim RelayOS registration")
		}
		if err := r.Objective.Validate(); err != nil {
			return err
		}
		if len(r.Objective.ObjectiveID) > 256 || len(r.Objective.OwnerPseudonym) > 256 || !validHash(r.Objective.DescriptionCommitment) || !validHash(r.Objective.PolicyHash) {
			return errors.New("handoff: invalid local review commitments")
		}
		return nil
	}
	if r.Source != "" {
		return errors.New("handoff: unsupported registration source")
	}
	u, err := url.Parse(r.RelayURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(r.RelayURL) > 2048 {
		return errors.New("handoff: invalid RelayOS registration URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()))) {
		return errors.New("handoff: registration URL requires HTTPS or loopback HTTP")
	}
	if r.Version != 1 || r.ObservedAt <= 0 || !strings.HasPrefix(r.ActorID, "did:relay:") || !validHex(strings.TrimPrefix(r.ActorID, "did:relay:"), 20) {
		return errors.New("handoff: invalid registration observation")
	}
	if err := r.Objective.Validate(); err != nil {
		return err
	}
	if len(r.Objective.ObjectiveID) > 256 || len(r.Objective.OwnerPseudonym) > 256 || !validHash(r.Objective.DescriptionCommitment) || !validHash(r.Objective.PolicyHash) {
		return errors.New("handoff: objective requires bounded IDs and sha256 commitments")
	}
	return nil
}

type Terms struct {
	ID           string       `json:"id"`
	Registration Registration `json:"registration"`
	Buyer        Peer         `json:"buyer"`
	Provider     Peer         `json:"provider"`
	ExpiresAt    int64        `json:"expires_at"`
}

// Message sequences are brief(1), deliver(2), accept|reject(3). A decision
// commits to the exact deliverable hash; it cannot accept an unseen revision.
type Message struct {
	Version    int    `json:"version"`
	Terms      Terms  `json:"terms"`
	EventID    string `json:"event_id"`
	Sequence   int    `json:"sequence"`
	Previous   string `json:"previous"`
	Kind       string `json:"kind"`
	Content    []byte `json:"content,omitempty"`
	Policy     []byte `json:"policy,omitempty"`
	ResultHash string `json:"result_hash,omitempty"`
}

type Envelope struct {
	Domain    string  `json:"domain"`
	Message   Message `json:"message"`
	Signature string  `json:"signature"`
}

func Commitment(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

func NewID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func validHex(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && hex.EncodeToString(b) == s
}

func validHash(s string) bool {
	return strings.HasPrefix(s, "sha256:") && validHex(strings.TrimPrefix(s, "sha256:"), 32)
}

func (p Peer) Validate() error {
	if strings.TrimSpace(p.Address) != p.Address || p.Address == "" || len(p.Address) > 512 || strings.ContainsAny(p.Address, "\r\n\x00") || !validHex(p.Pinned, 32) {
		return errors.New("handoff: invalid participant address or signing pin")
	}
	return nil
}

func (m Message) Sender() Peer {
	if m.Kind == "deliver" {
		return m.Terms.Provider
	}
	return m.Terms.Buyer
}

func (m Message) Recipient() Peer {
	if m.Kind == "deliver" {
		return m.Terms.Buyer
	}
	return m.Terms.Provider
}

func (m Message) Validate() error {
	t := m.Terms
	if m.Version != 1 || !validHex(t.ID, 16) || !validHex(m.EventID, 16) || t.ExpiresAt <= 0 {
		return errors.New("handoff: unsupported version or invalid identifiers/expiry")
	}
	if err := t.Registration.Validate(); err != nil {
		return err
	}
	if t.ExpiresAt <= t.Registration.ObservedAt {
		return errors.New("handoff: expiry must follow registration observation")
	}
	if err := t.Buyer.Validate(); err != nil {
		return err
	}
	if err := t.Provider.Validate(); err != nil {
		return err
	}
	if t.Buyer.Address == t.Provider.Address || t.Buyer.Pinned == t.Provider.Pinned {
		return errors.New("handoff: buyer and provider must be distinct")
	}
	if len(m.Content) > MaxContent || len(m.Policy) > MaxPolicy {
		return errors.New("handoff: content or policy exceeds limit")
	}
	switch m.Kind {
	case "brief":
		if m.Sequence != 1 || m.Previous != "" || len(m.Content) == 0 || len(m.Policy) == 0 || m.ResultHash != "" || Commitment(m.Content) != t.Registration.Objective.DescriptionCommitment || Commitment(m.Policy) != t.Registration.Objective.PolicyHash {
			return errors.New("handoff: brief/policy do not match objective commitments")
		}
	case "deliver":
		if m.Sequence != 2 || !validHash(m.Previous) || len(m.Content) == 0 || len(m.Policy) != 0 || Commitment(m.Content) != m.ResultHash {
			return errors.New("handoff: invalid deliverable or result commitment")
		}
	case "accept", "reject":
		if m.Sequence != 3 || !validHash(m.Previous) || len(m.Content) != 0 || len(m.Policy) != 0 || !validHash(m.ResultHash) {
			return errors.New("handoff: invalid decision")
		}
	default:
		return errors.New("handoff: unsupported event kind")
	}
	return nil
}

func Sign(m Message, identity []byte) (Envelope, error) {
	if err := m.Validate(); err != nil {
		return Envelope{}, err
	}
	pub, err := secure.SigPubOf(identity)
	if err != nil {
		return Envelope{}, err
	}
	if hex.EncodeToString(pub) != m.Sender().Pinned {
		return Envelope{}, errors.New("handoff: wrong signing identity for this transition")
	}
	key, err := secure.SigKeypairOf(identity)
	if err != nil {
		return Envelope{}, err
	}
	defer clear(key)
	raw, err := json.Marshal(m)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(key, append([]byte(Domain+"\x00"), raw...))
	return Envelope{Domain: Domain, Message: m, Signature: hex.EncodeToString(sig)}, nil
}

func (e Envelope) Verify() error {
	if e.Domain != Domain {
		return errors.New("handoff: unsupported signing domain")
	}
	if err := e.Message.Validate(); err != nil {
		return err
	}
	sig, err := hex.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !validHex(e.Signature, ed25519.SignatureSize) {
		return errors.New("handoff: invalid signature encoding")
	}
	pin, _ := hex.DecodeString(e.Message.Sender().Pinned)
	raw, err := json.Marshal(e.Message)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pin, append([]byte(Domain+"\x00"), raw...), sig) {
		return errors.New("handoff: signature mismatch")
	}
	return nil
}

func (e Envelope) Hash() string {
	raw, _ := json.Marshal(e)
	return Commitment(raw)
}

func Encode(e Envelope) ([]byte, error) {
	if err := e.Verify(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if len(raw) > MaxMessage {
		return nil, errors.New("handoff: envelope exceeds limit")
	}
	return raw, err
}

func Decode(raw []byte) (Envelope, error) {
	var e Envelope
	if err := DecodeJSON(raw, &e, MaxMessage); err != nil {
		return e, err
	}
	return e, e.Verify()
}

// IsEnvelope routes even oversized or malformed signed-domain payloads away
// from ordinary mail indexing. Decode is always required before use.
func IsEnvelope(raw []byte) bool { return isDomain(raw, Domain) }

func isDomain(raw []byte, domain string) bool {
	var head struct {
		Domain string `json:"domain"`
	}
	if json.Unmarshal(raw, &head) == nil && head.Domain == domain {
		return true
	}
	trimmed := bytes.TrimSpace(raw)
	return bytes.HasPrefix(trimmed, []byte("{")) && bytes.Contains(raw, []byte(`"domain"`)) && bytes.Contains(raw, []byte(domain))
}

// DecodeJSON rejects duplicate (including case-aliased) keys, nulls, excessive
// nesting, unknown fields, and trailing values before interpreting signed data.
func DecodeJSON(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("handoff: JSON exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := walkJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("handoff: trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func walkJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("handoff: JSON nesting exceeds limit")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("handoff: null is not permitted")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	end := json.Delim(']')
	seen := map[string]bool{}
	if delim == '{' {
		end = '}'
	} else if delim != '[' {
		return errors.New("handoff: invalid JSON delimiter")
	}
	for d.More() {
		if delim == '{' {
			k, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := k.(string)
			if !ok {
				return errors.New("handoff: invalid object key")
			}
			name = strings.ToLower(name)
			if seen[name] {
				return fmt.Errorf("handoff: duplicate JSON key %q", name)
			}
			seen[name] = true
		}
		if err := walkJSON(d, depth+1); err != nil {
			return err
		}
	}
	t, err = d.Token()
	if err != nil {
		return err
	}
	if t != end {
		return errors.New("handoff: unclosed JSON value")
	}
	return nil
}
