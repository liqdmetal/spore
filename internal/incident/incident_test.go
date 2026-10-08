package incident

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/secure"
)

func validTestPin(seed byte) string {
	pub, _ := secure.SigPubOf(bytes.Repeat([]byte{seed}, 32))
	return hex.EncodeToString(pub)
}

func TestLifecycleAuthorizationQuorumDedupRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.enc")
	key := bytes.Repeat([]byte{7}, 32)
	now := time.Unix(1_800_000_000, 0)
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	ownerPriv, alicePriv, bobPriv, evePriv := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	ownerPin, _ := secure.SigPubOf(ownerPriv)
	alicePin, _ := secure.SigPubOf(alicePriv)
	bobPin, _ := secure.SigPubOf(bobPriv)
	evePin, _ := secure.SigPubOf(evePriv)
	r, err := s.Create("owner", hex.EncodeToString(ownerPin), "node outage", "private detail", now.Add(time.Minute), now.Add(time.Hour), 2, []Responder{{Address: "alice", Pinned: hex.EncodeToString(alicePin), Session: "000000000000000a"}, {Address: "bob", Pinned: hex.EncodeToString(bobPin), Session: "000000000000000b"}, {Address: "eve", Pinned: hex.EncodeToString(evePin), Session: "000000000000000e"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeSelection(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Respond(r.ID, "eve", strings.Repeat("0", 64), Acked, "event-0", "0000000000000000", now); err == nil {
		t.Fatal("uninvited pin accepted")
	}
	if _, err = s.Respond(r.ID, "bob", hex.EncodeToString(bobPin), Acked, "event-b", "000000000000000b", now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Respond(r.ID, "bob", hex.EncodeToString(bobPin), Acked, "event-b", "000000000000000b", now); err != nil {
		t.Fatalf("duplicate event should be idempotent: %v", err)
	}
	got, err := s.Respond(r.ID, "alice", hex.EncodeToString(alicePin), Acked, "event-a", "000000000000000a", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != Active {
		t.Fatalf("quorum must not resolve the incident automatically: status=%s", got.Status)
	}
	quorum := false
	for _, event := range got.Events {
		if event.Kind == "quorum" {
			quorum = true
		}
	}
	if !quorum {
		t.Fatal("quorum event missing")
	}
	got, err = s.Resolve(r.ID, "owner", now)
	if err != nil || got.Status != Resolved {
		t.Fatalf("explicit resolve = %s, %v", got.Status, err)
	}
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err = reopened.Get(r.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != Resolved || len(got.Events) != 5 {
		t.Fatalf("reopened state=%+v", got)
	}
	mode, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode.Mode().Perm() != 0600 && mode.Mode().Perm() != 0666 {
		t.Fatalf("mode=%v", mode.Mode().Perm())
	}
	cipher, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, []byte("private detail")) {
		t.Fatal("incident plaintext persisted")
	}
}

func TestSignedMessagesBindSignerAndInvitationTarget(t *testing.T) {
	identity := bytes.Repeat([]byte{9}, 32)
	otherIdentity := bytes.Repeat([]byte{8}, 32)
	pin, err := secure.SigPubOf(identity)
	if err != nil {
		t.Fatal(err)
	}
	otherPin, err := secure.SigPubOf(otherIdentity)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	message := Message{Version: Version, Type: "invite", IncidentID: "incident-1", EventID: "event-1", Creator: "owner", CreatorPinned: hex.EncodeToString(pin), Sender: "owner", SenderPinned: hex.EncodeToString(pin), Recipient: "alice", RecipientPinned: hex.EncodeToString(otherPin), Summary: "incident", Details: "private", Deadline: now.Add(time.Hour).Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix(), Required: 1}
	raw, err := SignMessage(message, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSignedMessage(raw, pin); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSignedMessage(raw, otherPin); err == nil {
		t.Fatal("wrong pinned key accepted")
	}
	if _, err := SignMessage(message, otherIdentity); err == nil {
		t.Fatal("non-creator signed invitation")
	}
	store, err := Open(filepath.Join(t.TempDir(), "incidents.enc"), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportInvitation(message, "mallory", hex.EncodeToString(otherPin), "0000000000000001", now); err == nil {
		t.Fatal("invitation for another address was imported")
	}
	record, err := store.ImportInvitation(message, "alice", hex.EncodeToString(otherPin), "0123456789abcdef", now)
	if err != nil {
		t.Fatal(err)
	}
	if record.Responders[0].Address != "alice" {
		t.Fatalf("imported responder=%+v", record.Responders)
	}
	if _, err := store.ImportInvitation(message, "alice", hex.EncodeToString(otherPin), "0123456789abcdef", now); err != nil {
		t.Fatalf("same signed invite should be idempotent: %v", err)
	}
	mutated := strings.Replace(string(raw), "incident-1", "incident-2", 1)
	if _, err := DecodeSignedMessage([]byte(mutated), pin); err == nil {
		t.Fatal("tampered signed message accepted")
	}
}

func TestResolveOnlyCreatorAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "i")
	s, err := Open(path, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	ownerPin, _ := secure.SigPubOf(bytes.Repeat([]byte{5}, 32))
	responderPin, _ := secure.SigPubOf(bytes.Repeat([]byte{6}, 32))
	r, err := s.Create("owner", hex.EncodeToString(ownerPin), "summary", "", now.Add(time.Minute), now.Add(2*time.Minute), 1, []Responder{{Address: "a", Pinned: hex.EncodeToString(responderPin), Session: "000000000000000a"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeSelection(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Respond(r.ID, "a", hex.EncodeToString(responderPin), Acked, "late", "000000000000000a", now.Add(90*time.Second)); !errors.Is(err, ErrClosed) {
		t.Fatalf("deadline should close responses without expiring incident: %v", err)
	}
	if _, err = s.Resolve(r.ID, "a", now); err == nil {
		t.Fatal("non-creator resolved incident")
	}
	got, err := s.Get(r.ID, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != Expired {
		t.Fatalf("status=%s", got.Status)
	}
	if _, err = s.Respond(r.ID, "a", hex.EncodeToString(responderPin), Acked, "late", "000000000000000a", now.Add(3*time.Minute)); !errors.Is(err, ErrClosed) {
		t.Fatalf("late reply err=%v", err)
	}
}

func TestOutboxKeepsPreparedPointerForRestartRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.enc")
	key := bytes.Repeat([]byte{2}, 32)
	store, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	record, err := store.Create("owner", validTestPin(10), "summary", "private", now.Add(time.Hour), now.Add(2*time.Hour), 1, []Responder{{Address: "alice", Pinned: validTestPin(11), Session: "0123456789abcdef"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	eventID := inviteEventID(record.ID, "alice")
	payload, err := SignMessage(Message{Version: Version, Type: "invite", IncidentID: record.ID, EventID: eventID, Creator: record.Creator, CreatorPinned: record.CreatorPinned, Sender: record.Creator, SenderPinned: record.CreatorPinned, Recipient: "alice", RecipientPinned: validTestPin(11), Summary: record.Summary, Details: record.Details, Deadline: record.Deadline, ExpiresAt: record.ExpiresAt, Required: record.Required}, bytes.Repeat([]byte{10}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeSelection(record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddInviteOutbox(record.ID, eventID, Peer{Address: "alice", Pinned: validTestPin(11)}, "0123456789abcdef", payload, now); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginDeliveryPreparation(record.ID, eventID); err != nil {
		t.Fatal(err)
	}
	if err := store.PrepareDelivery(record.ID, eventID, "0123456789abcdef", []byte("opaque-pointer")); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reopened.Pending(record.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	if !bytes.Equal(pending[0].Pointer, []byte("opaque-pointer")) || pending[0].Preparing {
		t.Fatalf("prepared delivery changed across restart: %+v", pending[0])
	}
	if err := reopened.MarkSent(record.ID, pending[0].EventID); err != nil {
		t.Fatal(err)
	}
	pending, err = reopened.Pending(record.ID)
	if err != nil || len(pending) != 0 {
		t.Fatalf("sent message remains pending: %v, %v", pending, err)
	}
}

func TestInterruptedPointerPreparationCannotAdvanceRatchetAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.enc")
	key := bytes.Repeat([]byte{14}, 32)
	store, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	record, err := store.Create("owner", validTestPin(1), "summary", "", now.Add(time.Hour), now.Add(2*time.Hour), 1, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddResponder(record.ID, Peer{Address: "alice", Pinned: validTestPin(2)}, "0123456789abcdef", now); err != nil {
		t.Fatal(err)
	}
	if err := store.FinalizeSelection(record.ID); err != nil {
		t.Fatal(err)
	}
	eventID, err := NewEventID()
	if err != nil {
		t.Fatal(err)
	}
	private := bytes.Repeat([]byte{1}, 32)
	pin := validTestPin(1)
	payload, err := SignMessage(Message{Version: Version, Type: "invite", IncidentID: record.ID, EventID: eventID, Creator: record.Creator, CreatorPinned: pin, Sender: record.Creator, SenderPinned: pin, Recipient: "alice", RecipientPinned: validTestPin(2), Summary: record.Summary, Deadline: record.Deadline, ExpiresAt: record.ExpiresAt, Required: record.Required}, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddInviteOutbox(record.ID, eventID, Peer{Address: "alice", Pinned: validTestPin(2)}, "0123456789abcdef", payload, now); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginDeliveryPreparation(record.ID, eventID); err != nil {
		t.Fatal(err)
	}

	restarted, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.Pending(record.ID)
	if err != nil || len(pending) != 1 || !pending[0].Preparing || len(pending[0].Pointer) != 0 {
		t.Fatalf("interrupted preparation state=%+v err=%v", pending, err)
	}
	if err := restarted.BeginDeliveryPreparation(record.ID, eventID); err == nil {
		t.Fatal("restarted outbox advanced the ratchet a second time")
	}
	if err := restarted.PrepareDelivery(record.ID, eventID, "0123456789abcdef", []byte("unverified pointer")); err == nil {
		t.Fatal("restarted process accepted a pointer it could not have retained")
	}
}

func TestCreateSelectsRespondersBeforeInvitations(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "incident.enc"), bytes.Repeat([]byte{12}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	r, err := store.Create("owner", validTestPin(1), "summary", "", now.Add(time.Hour), now.Add(2*time.Hour), 2, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []Peer{{Address: "alice", Pinned: validTestPin(2)}, {Address: "bob", Pinned: validTestPin(3)}} {
		if err := store.AddResponder(r.ID, peer, "0123456789abcdef", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.AddResponder(r.ID, Peer{Address: "eve", Pinned: validTestPin(4)}, "1123456789abcdef", now); err != nil {
		t.Fatalf("additional responder before invitations: %v", err)
	}
	got, err := store.Get(r.ID, now)
	if err != nil || len(got.Responders) != 3 {
		t.Fatalf("record=%+v err=%v", got, err)
	}
	if err := store.FinalizeSelection(r.ID); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		address string
		seed    byte
		session string
	}{{"alice", 2, "0123456789abcdef"}, {"bob", 3, "0123456789abcdef"}, {"eve", 4, "1123456789abcdef"}} {
		eventID, err := NewEventID()
		if err != nil {
			t.Fatal(err)
		}
		private := bytes.Repeat([]byte{1}, 32)
		pin := validTestPin(1)
		msg := Message{Version: Version, Type: "invite", IncidentID: r.ID, EventID: eventID, Creator: r.Creator, CreatorPinned: pin, Sender: r.Creator, SenderPinned: pin, Recipient: target.address, RecipientPinned: validTestPin(target.seed), Summary: r.Summary, Deadline: r.Deadline, ExpiresAt: r.ExpiresAt, Required: r.Required}
		payload, err := SignMessage(msg, private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AddInviteOutbox(r.ID, eventID, Peer{Address: target.address, Pinned: validTestPin(target.seed)}, target.session, payload, now); err != nil {
			t.Fatalf("invite selected responder %s: %v", target.address, err)
		}
	}
	if err := store.FinalizeSelection(r.ID); err == nil {
		t.Fatal("finalized responder selection a second time")
	}
	if err := store.AddResponder(r.ID, Peer{Address: "mallory", Pinned: validTestPin(5)}, "2123456789abcdef", now); err == nil {
		t.Fatal("added responder after selection finalized")
	}
	if err := store.StoreResponderSession(r.ID, "alice", "1123456789abcdef"); err == nil {
		t.Fatal("changed session binding after selection finalized")
	}
	if _, err := store.Get(r.ID, now); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsWrongKeyAndMalformedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "i")
	s, err := Open(path, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	ownerPin, _ := secure.SigPubOf(bytes.Repeat([]byte{9}, 32))
	responderPin, _ := secure.SigPubOf(bytes.Repeat([]byte{8}, 32))
	_, err = s.Create("o", hex.EncodeToString(ownerPin), "s", "", now.Add(time.Minute), now.Add(time.Hour), 1, []Responder{{Address: "a", Pinned: hex.EncodeToString(responderPin), Session: "000000000000000a"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("wrong key opened store")
	}
	if err = os.WriteFile(path, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("malformed file opened")
	}
}
