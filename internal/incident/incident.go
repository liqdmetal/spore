// Package incident owns local incident state and policy. E2 transport carries
// these strictly validated, identity-signed messages inside existing sessions.
package incident

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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/liqdmetal/spore/internal/secure"
)

const (
	Version         = 1
	MaxFileBytes    = 4 << 20
	MaxDetails      = 16 << 10
	MaxMessageBytes = MaxDetails*6 + 8192
	MaxResponders   = 64
	fileMagic       = "SPI1"
	messageDomain   = "spore/incident/v1"
)

var (
	ErrNotFound = errors.New("incident: not found")
	ErrClosed   = errors.New("incident: incident is closed")
)

type Status string

const (
	Active   Status = "open"
	Resolved Status = "resolved"
	Expired  Status = "expired"
	Declined Status = "declined"
	Acked    Status = "acknowledged"
	Invited  Status = "invited"
)

type Responder struct {
	Address string `json:"address"`
	Pinned  string `json:"pinned_sig"`
	Session string `json:"session,omitempty"`
	Status  Status `json:"status"`
	At      int64  `json:"at,omitempty"`
}

type Peer struct {
	Address string `json:"address"`
	Pinned  string `json:"pinned_sig"`
}

type Outbox struct {
	EventID   string `json:"event_id"`
	Recipient string `json:"recipient"`
	Pinned    string `json:"recipient_pinned"`
	Session   string `json:"session"`
	Payload   []byte `json:"payload"`
	Pointer   []byte `json:"pointer,omitempty"`
	CreatedAt int64  `json:"created_at"`
	Sent      bool   `json:"sent"`
	Accounted bool   `json:"accounted,omitempty"`
	Preparing bool   `json:"preparing,omitempty"`
}

type Event struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	At      int64  `json:"at"`
	Actor   string `json:"actor"`
	Address string `json:"address,omitempty"`
}

type Record struct {
	Version            int         `json:"version"`
	ID                 string      `json:"id"`
	Creator            string      `json:"creator"`
	CreatorPinned      string      `json:"creator_pinned"`
	Summary            string      `json:"summary"`
	Details            string      `json:"details,omitempty"`
	CreatedAt          int64       `json:"created_at"`
	Deadline           int64       `json:"deadline"`
	ExpiresAt          int64       `json:"expires_at"`
	Required           int         `json:"required"`
	SelectionFinalized bool        `json:"selection_finalized,omitempty"`
	Status             Status      `json:"status"`
	Responders         []Responder `json:"responders"`
	Events             []Event     `json:"events"`
	Outbox             []Outbox    `json:"outbox,omitempty"`
}

type Store struct {
	mu        sync.Mutex
	path      string
	key       [32]byte
	rows      map[string]Record
	preparing map[string]bool
}

// Message is an application payload carried only inside an existing E2 session.
type Message struct {
	Version         int    `json:"version"`
	Type            string `json:"type"`
	IncidentID      string `json:"incident_id"`
	EventID         string `json:"event_id"`
	Creator         string `json:"creator"`
	CreatorPinned   string `json:"creator_pinned"`
	Sender          string `json:"sender"`
	SenderPinned    string `json:"sender_pinned"`
	Recipient       string `json:"recipient"`
	RecipientPinned string `json:"recipient_pinned"`
	Summary         string `json:"summary,omitempty"`
	Details         string `json:"details,omitempty"`
	Deadline        int64  `json:"deadline,omitempty"`
	ExpiresAt       int64  `json:"expires_at,omitempty"`
	Required        int    `json:"required,omitempty"`
}

type signedEnvelope struct {
	Domain    string          `json:"domain"`
	Message   json.RawMessage `json:"message"`
	Signature string          `json:"signature"`
}

func EncodeMessage(m Message) ([]byte, error) {
	if err := ValidateMessage(m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func DecodeMessage(raw []byte) (Message, error) {
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return Message{}, errors.New("incident: application payload exceeds size limit")
	}
	var m Message
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Message{}, fmt.Errorf("incident: malformed application payload: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return Message{}, err
	}
	if err := ValidateMessage(m); err != nil {
		return Message{}, err
	}
	return m, nil
}

func SignMessage(m Message, identityPriv []byte) ([]byte, error) {
	if err := ValidateMessage(m); err != nil {
		return nil, err
	}
	pub, err := secure.SigPubOf(identityPriv)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(m.SenderPinned, hex.EncodeToString(pub)) {
		return nil, errors.New("incident: signer does not match the message sender pin")
	}
	if err := ValidateMessage(m); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	key, err := secure.SigKeypairOf(identityPriv)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, append([]byte(messageDomain+"\x00"), canonical...))
	raw, err := json.Marshal(signedEnvelope{Domain: messageDomain, Message: canonical, Signature: hex.EncodeToString(sig)})
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxMessageBytes {
		return nil, errors.New("incident: signed message exceeds size limit")
	}
	return raw, nil
}

func PeekSignedMessage(raw []byte) (Message, error) {
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return Message{}, errors.New("incident: signed message exceeds size limit")
	}
	var env signedEnvelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Message{}, fmt.Errorf("incident: invalid signed envelope: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return Message{}, err
	}
	if env.Domain != messageDomain {
		return Message{}, errors.New("incident: unsupported signed-message domain")
	}
	return DecodeMessage(env.Message)
}

func DecodeSignedMessage(raw, pinned []byte) (Message, error) {
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return Message{}, errors.New("incident: signed message exceeds size limit")
	}
	var env signedEnvelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Message{}, fmt.Errorf("incident: invalid signed envelope: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return Message{}, err
	}
	m, err := PeekSignedMessage(raw)
	if err != nil {
		return Message{}, err
	}
	sig, err := hex.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Message{}, errors.New("incident: malformed signature")
	}
	canonical, err := json.Marshal(m)
	if err != nil {
		return Message{}, err
	}
	if len(pinned) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pinned), append([]byte(messageDomain+"\x00"), canonical...), sig) {
		return Message{}, errors.New("incident: signature does not match pinned contact")
	}
	return m, nil
}

// IsIncidentEnvelope detects only the incident signing domain. Other JSON
// application payloads stay in the normal E2 display/receipt path.
func IsIncidentEnvelope(raw []byte) bool {
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return false
	}
	var env signedEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return false
	}
	return env.Domain == messageDomain && len(env.Message) != 0
}

func ValidateMessage(m Message) error {
	if m.Version != Version || m.IncidentID == "" || len(m.IncidentID) > 128 || m.EventID == "" || len(m.EventID) > 128 || m.Creator == "" || !validPin(m.CreatorPinned) || m.Sender == "" || !validPin(m.SenderPinned) || m.Recipient == "" || !validPin(m.RecipientPinned) {
		return errors.New("incident: incomplete or unsupported application message")
	}
	switch m.Type {
	case "invite":
		if m.Sender != m.Creator || !strings.EqualFold(m.SenderPinned, m.CreatorPinned) || strings.TrimSpace(m.Summary) == "" || len(m.Summary) > 256 || len(m.Details) > MaxDetails || m.Deadline <= 0 || m.ExpiresAt <= m.Deadline || m.Required < 1 || m.Required > MaxResponders {
			return errors.New("incident: invalid invitation")
		}
	case "ack", "decline":
		if m.Recipient != m.Creator || !strings.EqualFold(m.RecipientPinned, m.CreatorPinned) || m.Summary != "" || m.Details != "" || m.Deadline != 0 || m.ExpiresAt != 0 || m.Required != 0 {
			return errors.New("incident: response contains unexpected fields")
		}
	default:
		return errors.New("incident: unsupported application message type")
	}
	return nil
}

// ImportInvitation creates the recipient's local copy without leaking the
// invitee roster; each E2 invitation carries only one recipient.
func (s *Store) ImportInvitation(m Message, localAddress, localPinned, session string, now time.Time) (Record, error) {
	if err := ValidateMessage(m); err != nil {
		return Record{}, err
	}
	if m.Type != "invite" || localAddress == "" || !strings.EqualFold(m.Recipient, localAddress) || !strings.EqualFold(m.RecipientPinned, localPinned) {
		return Record{}, errors.New("incident: invitation is not addressed to this pinned identity")
	}
	if !validSessionID(session) {
		return Record{}, errors.New("incident: invitation requires a valid authenticated E2 session ID")
	}
	if !now.Before(time.Unix(m.Deadline, 0)) || !now.Before(time.Unix(m.ExpiresAt, 0)) {
		return Record{}, ErrClosed
	}
	r := Record{Version: Version, ID: m.IncidentID, Creator: m.Creator, CreatorPinned: m.CreatorPinned, Summary: m.Summary, Details: m.Details, CreatedAt: now.Unix(), Deadline: m.Deadline, ExpiresAt: m.ExpiresAt, Required: m.Required, SelectionFinalized: true, Status: Active, Responders: []Responder{{Address: localAddress, Pinned: localPinned, Session: session, Status: Invited}}, Events: []Event{{ID: m.EventID, Kind: "invited", At: now.Unix(), Actor: m.Creator, Address: localAddress}}}
	if err := Validate(r); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.rows[r.ID]; ok {
		if old.Creator != r.Creator || !strings.EqualFold(old.CreatorPinned, r.CreatorPinned) || old.Summary != r.Summary || old.Details != r.Details || old.Deadline != r.Deadline || old.ExpiresAt != r.ExpiresAt || old.Required != r.Required || len(old.Events) == 0 || old.Events[0].ID != m.EventID {
			return Record{}, errors.New("incident: conflicting invitation for existing ID")
		}
		return clone(old), nil
	}
	if err := s.commitLocked(r.ID, r); err != nil {
		return Record{}, err
	}
	return clone(r), nil
}

func NewEventID() (string, error) { return newID() }

func Open(path string, key []byte) (*Store, error) {
	if len(key) != chacha20poly1305.KeySize || path == "" {
		return nil, errors.New("incident: state key must be 32 bytes and store path is required")
	}
	s := &Store{path: path, rows: map[string]Record{}, preparing: map[string]bool{}}
	copy(s.key[:], key)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxFileBytes || len(raw) < 4+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead || string(raw[:4]) != fileMagic {
		return nil, errors.New("incident: malformed or oversized encrypted store")
	}
	aead, err := chacha20poly1305.NewX(s.key[:])
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, raw[4:4+aead.NonceSize()], raw[4+aead.NonceSize():], []byte("spore/incident/store/v1"))
	if err != nil {
		return nil, errors.New("incident: cannot authenticate store (wrong key or damaged file)")
	}
	var doc struct {
		Version   int      `json:"version"`
		Incidents []Record `json:"incidents"`
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("incident: decode store: %w", err)
	}
	if doc.Version != Version {
		return nil, fmt.Errorf("incident: unsupported store version %d", doc.Version)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	for _, r := range doc.Incidents {
		if err := Validate(r); err != nil {
			return nil, err
		}
		if _, exists := s.rows[r.ID]; exists {
			return nil, errors.New("incident: duplicate incident ID in store")
		}
		s.rows[r.ID] = r
	}
	return s, nil
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("incident: trailing data")
	}
	return nil
}

func (s *Store) Create(creator, creatorPinned, summary, details string, deadline, expires time.Time, required int, responders []Responder, now time.Time) (Record, error) {
	now = now.UTC()
	if creator == "" || !validPin(creatorPinned) || strings.TrimSpace(summary) == "" || len(summary) > 256 || len(details) > MaxDetails {
		return Record{}, errors.New("incident: creator and summary are required; summary/details exceed limits")
	}
	if !deadline.After(now) || !expires.After(deadline) {
		return Record{}, errors.New("incident: expiry must be after a future response deadline")
	}
	if len(responders) > MaxResponders || required < 1 || (len(responders) > 0 && required > len(responders)) {
		return Record{}, errors.New("incident: invalid responder/quorum count")
	}
	seen := map[string]bool{}
	for i := range responders {
		addressKey := strings.ToLower(responders[i].Address)
		if responders[i].Address == "" || !validPin(responders[i].Pinned) || (responders[i].Session != "" && !validSessionID(responders[i].Session)) || seen[addressKey] {
			return Record{}, errors.New("incident: every responder must be unique and pinned")
		}
		seen[addressKey] = true
		responders[i].Status = Invited
		responders[i].At = 0
	}
	id, err := newID()
	if err != nil {
		return Record{}, err
	}
	r := Record{Version: Version, ID: id, Creator: creator, CreatorPinned: creatorPinned, Summary: summary, Details: details, CreatedAt: now.Unix(), Deadline: deadline.Unix(), ExpiresAt: expires.Unix(), Required: required, SelectionFinalized: false, Status: Active, Responders: responders, Events: []Event{{ID: id + "-created", Kind: "created", At: now.Unix(), Actor: creator}}}
	return r, s.put(r)
}

func (s *Store) Get(id string, now time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if r.Status == Active && !now.Before(time.Unix(r.ExpiresAt, 0)) {
		r.Status = Expired
		r.Events = append(r.Events, Event{ID: id + "-expired", Kind: "expired", At: now.Unix(), Actor: "system"})
		if err := s.commitLocked(id, r); err != nil {
			return Record{}, err
		}
	}
	return clone(s.rows[id]), nil
}

func (s *Store) List(now time.Time) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.rows))
	for id := range s.rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Record, 0, len(ids))
	for _, id := range ids {
		r := s.rows[id]
		if r.Status == Active && !now.Before(time.Unix(r.ExpiresAt, 0)) {
			r.Status = Expired
			r.Events = append(r.Events, Event{ID: id + "-expired", Kind: "expired", At: now.Unix(), Actor: "system"})
			if err := s.commitLocked(id, r); err != nil {
				return nil, err
			}
		}
		out = append(out, clone(s.rows[id]))
	}
	return out, nil
}

func (s *Store) Respond(id, address, pinned string, status Status, eventID, session string, now time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if r.Status != Active {
		return Record{}, ErrClosed
	}
	if !r.SelectionFinalized {
		return Record{}, errors.New("incident: responder selection is not finalized")
	}
	if !now.Before(time.Unix(r.ExpiresAt, 0)) {
		r.Status = Expired
		r.Events = append(r.Events, Event{ID: id + "-expired", Kind: "expired", At: now.Unix(), Actor: "system"})
		if err := s.commitLocked(id, r); err != nil {
			return Record{}, err
		}
		return clone(r), ErrClosed
	}
	if !now.Before(time.Unix(r.Deadline, 0)) {
		return Record{}, ErrClosed
	}
	if status != Acked && status != Declined {
		return Record{}, errors.New("incident: response must be acknowledge or decline")
	}
	if eventID == "" || len(eventID) > 128 {
		return Record{}, errors.New("incident: valid event ID required")
	}
	responderIndex := -1
	for i := range r.Responders {
		if r.Responders[i].Address == address && strings.EqualFold(r.Responders[i].Pinned, pinned) {
			responderIndex = i
			break
		}
	}
	if responderIndex < 0 || !validSessionID(session) || !strings.EqualFold(r.Responders[responderIndex].Session, session) {
		return Record{}, errors.New("incident: response is not from the invited pinned responder session")
	}
	if r.Responders[responderIndex].Status != Invited {
		for _, e := range r.Events {
			if e.ID == eventID && e.Kind == string(status) && e.Actor == address {
				return clone(r), nil
			}
		}
		return Record{}, errors.New("incident: responder already answered")
	}
	for _, e := range r.Events {
		if e.ID == eventID {
			if e.Kind == string(status) && e.Actor == address {
				return clone(r), nil
			}
			return Record{}, errors.New("incident: event ID replay conflicts with prior response")
		}
	}
	if r.Responders[responderIndex].Status != Invited {
		return Record{}, errors.New("incident: responder already answered")
	}
	r.Responders[responderIndex].Status = status
	r.Responders[responderIndex].At = now.Unix()
	r.Events = append(r.Events, Event{ID: eventID, Kind: string(status), At: now.Unix(), Actor: address, Address: address})
	acked := 0
	for _, p := range r.Responders {
		if p.Status == Acked {
			acked++
		}
	}
	quorumRecorded := false
	for _, e := range r.Events {
		if e.Kind == "quorum" {
			quorumRecorded = true
			break
		}
	}
	if acked >= r.Required && !quorumRecorded {
		r.Events = append(r.Events, Event{ID: id + "-quorum", Kind: "quorum", At: now.Unix(), Actor: "system"})
	}
	if err := s.commitLocked(id, r); err != nil {
		return Record{}, err
	}
	return clone(r), nil
}

func (s *Store) Resolve(id, actor string, now time.Time) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if r.Status != Active {
		return Record{}, ErrClosed
	}
	if actor != r.Creator {
		return Record{}, errors.New("incident: only creator can resolve")
	}
	if !r.SelectionFinalized {
		return Record{}, errors.New("incident: responder selection is not finalized")
	}
	if !now.Before(time.Unix(r.ExpiresAt, 0)) {
		r.Status = Expired
		r.Events = append(r.Events, Event{ID: id + "-expired", Kind: "expired", At: now.Unix(), Actor: "system"})
		if err := s.commitLocked(id, r); err != nil {
			return Record{}, err
		}
		return clone(r), ErrClosed
	}
	r.Status = Resolved
	r.Events = append(r.Events, Event{ID: id + "-resolved-" + fmt.Sprint(now.UnixNano()), Kind: "resolved", At: now.Unix(), Actor: actor})
	if err := s.commitLocked(id, r); err != nil {
		return Record{}, err
	}
	return clone(r), nil
}

// AddInviteOutbox atomically records selection and signed intent before
// the ratchet send; delivery is later durably prepared against its session.
func (s *Store) AddInviteOutbox(id, eventID string, peer Peer, session string, payload []byte, now time.Time) (Event, error) {
	if peer.Address == "" || !validPin(peer.Pinned) || eventID == "" || !validSessionID(session) || len(payload) == 0 || len(payload) > MaxMessageBytes {
		return Event{}, errors.New("incident: invite requires a pinned contact, E2 session, and valid payload")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return Event{}, ErrNotFound
	}
	if r.Status != Active || !now.Before(time.Unix(r.Deadline, 0)) || !now.Before(time.Unix(r.ExpiresAt, 0)) {
		return Event{}, ErrClosed
	}
	creatorPin, _ := hex.DecodeString(r.CreatorPinned)
	message, err := DecodeSignedMessage(payload, creatorPin)
	if err != nil || message.Type != "invite" || message.EventID != eventID || message.IncidentID != id || message.Recipient != peer.Address || !strings.EqualFold(message.RecipientPinned, peer.Pinned) || message.Creator != r.Creator || !strings.EqualFold(message.CreatorPinned, r.CreatorPinned) || message.Summary != r.Summary || message.Details != r.Details || message.Deadline != r.Deadline || message.ExpiresAt != r.ExpiresAt || message.Required != r.Required {
		return Event{}, errors.New("incident: invitation payload does not match the authenticated outbox intent")
	}
	index := -1
	for i := range r.Responders {
		if strings.EqualFold(r.Responders[i].Address, peer.Address) {
			if !strings.EqualFold(r.Responders[i].Pinned, peer.Pinned) {
				return Event{}, errors.New("incident: contact pin changed since selection")
			}
			index = i
			break
		}
	}
	if index < 0 {
		return Event{}, errors.New("incident: recipient was not explicitly selected for this incident")
	}
	if !r.SelectionFinalized {
		return Event{}, errors.New("incident: responder selection is not finalized")
	}
	if r.Responders[index].Session != "" && !strings.EqualFold(r.Responders[index].Session, session) {
		return Event{}, errors.New("incident: invitation session does not match the selected responder session")
	}
	for _, entry := range r.Outbox {
		if entry.EventID == eventID {
			if entry.Recipient != peer.Address || !strings.EqualFold(entry.Pinned, peer.Pinned) || entry.Session != session || !bytes.Equal(entry.Payload, payload) {
				return Event{}, errors.New("incident: conflicting invitation retry")
			}
			for _, event := range r.Events {
				if event.ID == eventID {
					return event, nil
				}
			}
		}
	}
	for _, event := range r.Events {
		if event.ID == eventID {
			return Event{}, errors.New("incident: invitation event ID already used")
		}
		if event.Kind == "invited" && event.Address == peer.Address {
			return Event{}, errors.New("incident: responder already invited")
		}
	}
	if r.Required > len(r.Responders) {
		return Event{}, errors.New("incident: quorum exceeds selected responder count")
	}
	r.Responders[index].Session = session
	ev := Event{ID: eventID, Kind: "invited", At: now.Unix(), Actor: r.Creator, Address: peer.Address}
	r.Events = append(r.Events, ev)
	r.Outbox = append(r.Outbox, Outbox{EventID: eventID, Recipient: peer.Address, Pinned: peer.Pinned, Session: session, Payload: append([]byte(nil), payload...), CreatedAt: now.Unix()})
	if err := s.commitLocked(id, r); err != nil {
		return Event{}, err
	}
	return ev, nil
}

func (s *Store) QueueResponse(id, address, pinned string, status Status, eventID, recipient, recipientPinned, session string, payload []byte, now time.Time) error {
	if status != Acked && status != Declined || eventID == "" || recipient == "" || !validPin(recipientPinned) || !validPin(pinned) || !validSessionID(session) || len(payload) == 0 || len(payload) > MaxMessageBytes {
		return errors.New("incident: invalid response outbox entry")
	}
	senderPin, _ := hex.DecodeString(pinned)
	message, err := DecodeSignedMessage(payload, senderPin)
	wantType := "ack"
	if status == Declined {
		wantType = "decline"
	}
	if err != nil || message.Type != wantType || message.EventID != eventID || message.IncidentID != id || message.Sender != address || !strings.EqualFold(message.SenderPinned, pinned) || message.Creator == "" || message.Creator != recipient || !strings.EqualFold(message.CreatorPinned, recipientPinned) || message.Recipient != recipient || !strings.EqualFold(message.RecipientPinned, recipientPinned) {
		return errors.New("incident: response payload does not match the authenticated outbox intent")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	if r.Status != Active || r.Creator != recipient || !strings.EqualFold(r.CreatorPinned, recipientPinned) {
		return errors.New("incident: response destination does not match active invitation")
	}
	if !now.Before(time.Unix(r.Deadline, 0)) {
		return ErrClosed
	}
	index := -1
	for i := range r.Responders {
		if r.Responders[i].Address == address && strings.EqualFold(r.Responders[i].Pinned, pinned) {
			index = i
			break
		}
	}
	if index < 0 || !strings.EqualFold(r.Responders[index].Session, session) {
		return errors.New("incident: response is not from this invited pinned responder/session")
	}
	for _, entry := range r.Outbox {
		if entry.EventID == eventID {
			if entry.Recipient == recipient && strings.EqualFold(entry.Pinned, recipientPinned) && strings.EqualFold(entry.Session, session) && bytes.Equal(entry.Payload, payload) {
				return nil
			}
			return errors.New("incident: response event ID replay conflicts with outbox")
		}
	}
	for _, event := range r.Events {
		if event.ID == eventID {
			return errors.New("incident: response event ID already used")
		}
	}
	if r.Responders[index].Status != Invited {
		return errors.New("incident: responder already answered")
	}
	r.Responders[index].Status = status
	r.Responders[index].At = now.Unix()
	r.Events = append(r.Events, Event{ID: eventID, Kind: string(status), At: now.Unix(), Actor: address, Address: address})
	r.Outbox = append(r.Outbox, Outbox{EventID: eventID, Recipient: recipient, Pinned: recipientPinned, Session: session, Payload: append([]byte(nil), payload...), CreatedAt: now.Unix()})
	return s.commitLocked(id, r)
}

func (s *Store) Queue(id, eventID, recipient, pinned, session string, payload, pointer []byte, now time.Time) error {
	if !validPin(pinned) || !validSessionID(session) || recipient == "" || eventID == "" || len(payload) == 0 || len(payload) > MaxMessageBytes || len(pointer) == 0 || len(pointer) > 4096 {
		return errors.New("incident: invalid prepared outbox entry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	if eventID == "" || recipient == "" || !validSessionID(session) || len(payload) == 0 || len(payload) > MaxMessageBytes || len(pointer) == 0 || len(pointer) > 4096 {
		return errors.New("incident: invalid prepared outbox entry")
	}
	for _, e := range r.Outbox {
		if e.EventID == eventID {
			if e.Recipient != recipient || e.Session != session || !bytes.Equal(e.Payload, payload) || !bytes.Equal(e.Pointer, pointer) {
				return errors.New("incident: conflicting outbox event ID")
			}
			return nil
		}
	}
	r.Outbox = append(r.Outbox, Outbox{EventID: eventID, Recipient: recipient, Pinned: pinned, Session: session, Payload: append([]byte(nil), payload...), Pointer: append([]byte(nil), pointer...), CreatedAt: now.Unix()})
	return s.commitLocked(id, r)
}

func (s *Store) AddResponder(id string, peer Peer, session string, now time.Time) error {
	if peer.Address == "" || !validPin(peer.Pinned) || !validSessionID(session) {
		return errors.New("incident: responder must be pinned to a valid E2 session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	if r.Status != Active || r.SelectionFinalized || len(r.Outbox) != 0 || len(r.Events) != 1 {
		return errors.New("incident: responders can only be selected before selection is finalized or invitations are sent")
	}
	for _, responder := range r.Responders {
		if strings.EqualFold(responder.Address, peer.Address) {
			if strings.EqualFold(responder.Pinned, peer.Pinned) && responder.Session == session {
				return nil
			}
			return errors.New("incident: responder already selected with different identity/session")
		}
	}
	if len(r.Responders) >= MaxResponders {
		return errors.New("incident: selected responders exceed the limit")
	}
	r.Responders = append(r.Responders, Responder{Address: peer.Address, Pinned: peer.Pinned, Session: session, Status: Invited})
	return s.commitLocked(id, r)
}

func (s *Store) FinalizeSelection(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	if !r.SelectionFinalized && r.Status == Active && len(r.Outbox) == 0 && len(r.Events) == 1 && len(r.Responders) > 0 && r.Required <= len(r.Responders) {
		for i := range r.Responders {
			if !validSessionID(r.Responders[i].Session) {
				return errors.New("incident: every selected responder needs an authenticated session")
			}
		}
		r.SelectionFinalized = true
		return s.commitLocked(id, r)
	}
	if r.SelectionFinalized {
		return errors.New("incident: responder selection already finalized")
	}
	return errors.New("incident: responder selection is incomplete or already finalized")
}

func (s *Store) StoreResponderSession(id, address, session string) error {
	if !validSessionID(session) {
		return errors.New("incident: invalid session ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	for i := range r.Responders {
		if r.Responders[i].Address == address {
			if r.Responders[i].Session == session {
				return nil
			}
			if r.SelectionFinalized || len(r.Events) > 1 || len(r.Outbox) > 0 {
				return errors.New("incident: responder session is immutable after selection is finalized or an invitation is sent")
			}
			if r.Responders[i].Session != "" && r.Responders[i].Session != session {
				return errors.New("incident: responder session is already pinned")
			}
			r.Responders[i].Session = session
			return s.commitLocked(id, r)
		}
	}
	return errors.New("incident: responder not found")
}

// BeginDeliveryPreparation durably marks the point before a ratchet send is
// attempted. If the process stops before its pointer is saved, the outbox
// remains blocked rather than encrypting the same logical event with an
// advanced ratchet state and losing the first pointer.
func (s *Store) BeginDeliveryPreparation(id, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	for i := range r.Outbox {
		entry := &r.Outbox[i]
		if entry.EventID != eventID {
			continue
		}
		if len(entry.Pointer) != 0 {
			return errors.New("incident: delivery already has a prepared pointer")
		}
		if entry.Preparing {
			return errors.New("incident: prior pointer preparation was interrupted; refusing to advance this ratchet again")
		}
		entry.Preparing = true
		if err := s.commitLocked(id, r); err != nil {
			return err
		}
		s.preparing[id+"\x00"+eventID] = true
		return nil
	}
	return errors.New("incident: outbox event not found")
}

func (s *Store) PrepareDelivery(id, eventID, session string, pointer []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	for i := range r.Outbox {
		if r.Outbox[i].EventID != eventID {
			continue
		}
		entry := &r.Outbox[i]
		if !validSessionID(session) || len(pointer) == 0 || len(pointer) > 4096 || entry.Session != session {
			return errors.New("incident: invalid prepared delivery or changed session")
		}
		if len(entry.Pointer) != 0 {
			if !bytes.Equal(entry.Pointer, pointer) {
				return errors.New("incident: prepared delivery is immutable")
			}
			return nil
		}
		if !entry.Preparing || !s.preparing[id+"\x00"+eventID] {
			return errors.New("incident: delivery preparation was interrupted; pointer cannot be restored safely")
		}
		entry.Pointer = append([]byte(nil), pointer...)
		entry.Preparing = false
		for j := range r.Responders {
			if r.Responders[j].Address == entry.Recipient {
				r.Responders[j].Session = session
			}
		}
		if err := s.commitLocked(id, r); err != nil {
			return err
		}
		delete(s.preparing, id+"\x00"+eventID)
		return nil
	}
	return errors.New("incident: outbox event not found")
}

func (s *Store) Pending(id string) ([]Outbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return nil, ErrNotFound
	}
	var out []Outbox
	for _, e := range r.Outbox {
		if !e.Sent {
			e.Payload = append([]byte(nil), e.Payload...)
			e.Pointer = append([]byte(nil), e.Pointer...)
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.rows, id)
	if err := s.saveLocked(); err != nil {
		s.rows[id] = old
		return err
	}
	return nil
}

func (s *Store) MarkAccounted(id, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	for i := range r.Outbox {
		if r.Outbox[i].EventID == eventID {
			r.Outbox[i].Accounted = true
			return s.commitLocked(id, r)
		}
	}
	return errors.New("incident: outbox event not found")
}

func (s *Store) MarkSent(id, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok {
		return ErrNotFound
	}
	for i := range r.Outbox {
		if r.Outbox[i].EventID == eventID {
			if len(r.Outbox[i].Pointer) == 0 {
				return errors.New("incident: cannot mark unprepared delivery sent")
			}
			r.Outbox[i].Sent = true
			return s.commitLocked(id, r)
		}
	}
	return errors.New("incident: outbox event not found")
}

func (s *Store) put(r Record) error {
	if err := Validate(r); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.rows[r.ID]; exists {
		return errors.New("incident: incident ID already exists")
	}
	s.rows[r.ID] = clone(r)
	if err := s.saveLocked(); err != nil {
		delete(s.rows, r.ID)
		return err
	}
	return nil
}

func (s *Store) commitLocked(id string, r Record) error {
	if err := Validate(r); err != nil {
		return err
	}
	old, existed := s.rows[id]
	s.rows[id] = clone(r)
	if err := s.saveLocked(); err != nil {
		if existed {
			s.rows[id] = old
		} else {
			delete(s.rows, id)
		}
		return err
	}
	return nil
}

func (s *Store) saveLocked() error {
	incidents := make([]Record, 0, len(s.rows))
	for _, r := range s.rows {
		incidents = append(incidents, clone(r))
	}
	sort.Slice(incidents, func(i, j int) bool { return incidents[i].ID < incidents[j].ID })
	plain, err := json.Marshal(struct {
		Version   int      `json:"version"`
		Incidents []Record `json:"incidents"`
	}{Version: Version, Incidents: incidents})
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(s.key[:])
	if err != nil {
		return err
	}
	if len(plain)+4+aead.NonceSize()+aead.Overhead() > MaxFileBytes {
		return errors.New("incident: encrypted store exceeds size limit")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, plain, []byte("spore/incident/store/v1"))
	raw := append([]byte(fileMagic), nonce...)
	raw = append(raw, sealed...)
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".incident-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	complete = true
	return nil
}

func Validate(r Record) error {
	if r.Version != Version || r.ID == "" || len(r.ID) > 128 || r.Creator == "" || !validPin(r.CreatorPinned) || strings.TrimSpace(r.Summary) == "" || len(r.Summary) > 256 || len(r.Details) > MaxDetails || r.CreatedAt <= 0 || r.Deadline <= r.CreatedAt || r.ExpiresAt <= r.Deadline || r.Required < 1 || r.Required > MaxResponders {
		return errors.New("incident: invalid record")
	}
	if r.Status != Active && r.Status != Resolved && r.Status != Expired {
		return errors.New("incident: invalid incident status")
	}
	if len(r.Responders) > MaxResponders || len(r.Events) == 0 || len(r.Events) > 4096 || len(r.Outbox) > 4096 || (len(r.Responders) > 0 && r.Required > len(r.Responders) && r.Events[0].Kind != "created" && r.Events[0].Kind != "invited") {
		return errors.New("incident: invalid record collection sizes")
	}
	if !r.SelectionFinalized && (len(r.Outbox) != 0 || len(r.Events) != 1 || r.Status != Active) {
		return errors.New("incident: unfinished responder selection has invalid state")
	}
	participants := map[string]bool{}
	for _, responder := range r.Responders {
		key := strings.ToLower(responder.Address)
		if responder.Address == "" || !validPin(responder.Pinned) || (responder.Session != "" && !validSessionID(responder.Session)) || (responder.Status != Invited && responder.Status != Acked && responder.Status != Declined) || (responder.Status != Invited && responder.Session == "") || participants[key] || responder.At < 0 {
			return errors.New("incident: invalid or duplicate responder")
		}
		participants[key] = true
	}
	events := map[string]bool{}
	for _, event := range r.Events {
		if event.ID == "" || len(event.ID) > 128 || events[event.ID] || event.At <= 0 || event.Actor == "" {
			return errors.New("incident: invalid or duplicate event")
		}
		switch event.Kind {
		case "created", "invited", string(Acked), string(Declined), "quorum", "resolved", "expired":
		default:
			return errors.New("incident: unsupported event kind")
		}
		events[event.ID] = true
	}
	outboxEvents := map[string]bool{}
	for _, entry := range r.Outbox {
		if entry.EventID == "" || !events[entry.EventID] || outboxEvents[entry.EventID] || entry.Recipient == "" || !validPin(entry.Pinned) || !validSessionID(entry.Session) || len(entry.Payload) == 0 || len(entry.Payload) > MaxMessageBytes || len(entry.Pointer) > 4096 || (entry.Preparing && len(entry.Pointer) != 0) || ((entry.Accounted || entry.Sent) && len(entry.Pointer) == 0) {
			return errors.New("incident: invalid outbox entry")
		}
		outboxEvents[entry.EventID] = true
	}
	return nil
}

func validPin(pin string) bool {
	b, err := hex.DecodeString(pin)
	return err == nil && len(b) == ed25519.PublicKeySize
}

func validSessionID(session string) bool {
	b, err := hex.DecodeString(session)
	return err == nil && len(b) == 8
}

func clone(r Record) Record {
	r.Responders = append([]Responder(nil), r.Responders...)
	r.Events = append([]Event(nil), r.Events...)
	r.Outbox = append([]Outbox(nil), r.Outbox...)
	for i := range r.Outbox {
		r.Outbox[i].Payload = append([]byte(nil), r.Outbox[i].Payload...)
		r.Outbox[i].Pointer = append([]byte(nil), r.Outbox[i].Pointer...)
	}
	return r
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func inviteEventID(id, address string) string {
	h := sha256.Sum256([]byte(id + "\x00" + strings.ToLower(address)))
	return "invite-" + hex.EncodeToString(h[:16])
}
