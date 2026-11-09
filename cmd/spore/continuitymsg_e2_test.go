package main

// End-to-end proof for continuity check-in messages: a REAL ratchet session,
// the REAL ingestor (the single function both the chain watcher and the
// relay-fabric drain call), and a REAL vault file on the holder side. The
// unit tests in continuitymsg_test.go pin the codec and adoption rules; these
// tests pin that the rules actually run on the inbox path and that nothing
// else about the ingestor (maildb, chat printing, replay) shifts.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/continuity"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// continuityE2Kit stands up a sender/receiver ratchet pair over ONE shared
// body store (as production does) with the handshake already ingested, so the
// receiver endpoint holds exactly the live session a real recipient has.
type continuityE2Kit struct {
	body     ratchetwire.BodyStore
	sender   *ratchetwire.DurableEndpoint
	receiver *ratchetwire.DurableEndpoint
	session  [8]byte
	db       *maildb.MailDB
}

func newContinuityE2Kit(t *testing.T) *continuityE2Kit {
	t.Helper()
	id := make([]byte, 32)
	spk := make([]byte, 32)
	for i := 0; i < 32; i++ {
		id[i], spk[i] = byte(1), byte(2)
	}
	var opk [32]byte
	for i := range opk {
		opk[i] = 3
	}
	sig, err := secure.SigPubOf(id)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ratchet.BuildBundle(id, spk, 1, &opk, 1)
	if err != nil {
		t.Fatal(err)
	}
	body := store.NewMemStore()
	newEP := func() *ratchetwire.DurableEndpoint {
		t.Helper()
		states, err := ratchetwire.NewFileStateStore(t.TempDir(), make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		ep, err := ratchetwire.NewDurableEndpointWithExpiry(body, states, time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return ep
	}
	k := &continuityE2Kit{body: body, sender: newEP(), receiver: newEP()}
	db, err := maildb.Open(filepath.Join(t.TempDir(), "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	k.db = db

	// The chain carrier's role: deliver the handshake once so both sides hold
	// the session. Everything after this is a FrameMessage continuation.
	ptr, _, sess, err := k.sender.SendFirstSession(id, bundle, sig, []byte("handshake"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	k.session = sess
	frame, err := ratchetwire.FetchFrame(body, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rawBody, err := ratchetwire.GetBody(body, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.receiver.ReceiveFirst(id, spk, &opk, frame, rawBody); err != nil {
		t.Fatal(err)
	}
	return k
}

// send advances the sender ratchet and returns the frame plus its pointer
// payload, i.e. exactly what the carrier would make available.
func (k *continuityE2Kit) send(t *testing.T, plain []byte) (ratchetwire.Pointer, []byte) {
	t.Helper()
	ptr, raw, err := k.sender.SendNext(k.session, plain, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := ratchetwire.FetchFrame(k.body, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if frame.Kind != ratchetwire.FrameMessage {
		t.Fatalf("expected a continuation frame, got kind %v", frame.Kind)
	}
	return ptr, raw
}

// ingestChain runs the chain-watcher path: the same ingest() the watcher
// calls, with a chain Incoming carrying the sender address.
func (k *continuityE2Kit) ingestChain(t *testing.T, ing *e2Ingestor, txid string, plain []byte) {
	t.Helper()
	ptr, _ := k.send(t, plain)
	frame, err := ratchetwire.FetchFrame(k.body, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ing.ingest(chain.Incoming{TxID: txid, Sender: "owner"}, frame, ptr, false)
}

func vaultSeq(t *testing.T, path string) (*continuity.Vault, uint64, int64) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := continuity.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	last := v.Checkins[len(v.Checkins)-1]
	return v, last.Seq, last.Deadline
}

func TestContinuityCheckInAdvancesHolderVaultOverSession(t *testing.T) {
	v, owner := continuityMsgVault(t)
	vaultPath := filepath.Join(t.TempDir(), "holder-vault.json")
	if err := writeContinuityVault(vaultPath, v); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	msg, err := marshalContinuityCheckInMessage(mustEnvelope(t, v))
	if err != nil {
		t.Fatal(err)
	}

	k := newContinuityE2Kit(t)
	ing := &e2Ingestor{st: k.body, ep: k.receiver, mdb: k.db, continuity: vaultPath}
	k.ingestChain(t, ing, "e2-checkin-1", msg)

	// The far side advanced: seq 0 -> 1 with the deadline the owner signed.
	merged, seq, deadline := vaultSeq(t, vaultPath)
	if seq != 1 || deadline != 1095 {
		after, _ := os.ReadFile(vaultPath)
		t.Fatalf("holder vault not advanced: seq=%d deadline=%d changed=%v", seq, deadline, string(after) != string(before))
	}
	if merged.VaultID != v.VaultID {
		t.Fatalf("adopted a different vault: %s vs %s", merged.VaultID, v.VaultID)
	}

	// A check-in is protocol, not chat: nothing was indexed as a message body.
	if hits := k.db.SearchSimple("continuity"); len(hits) != 0 {
		t.Fatalf("check-in envelope recorded as chat: %d hit(s)", len(hits))
	}
	if hits := k.db.SearchSimple("sealed"); len(hits) != 0 {
		t.Fatalf("payload material reached the mail store: %d hit(s)", len(hits))
	}

	// The session still carries ordinary messages afterwards.
	k.ingestChain(t, ing, "e2-chat-1", []byte("still here"))
	if hits := k.db.SearchSimple("still here"); len(hits) != 1 {
		t.Fatalf("ordinary message after a check-in: got %d hit(s), want 1", len(hits))
	}
	if _, seq2, _ := vaultSeq(t, vaultPath); seq2 != 1 {
		t.Fatalf("a chat message moved the vault to seq %d", seq2)
	}
}

func TestContinuityCheckInRefusalsLeaveHolderVaultUntouched(t *testing.T) {
	holder, owner := continuityMsgVault(t)
	vaultPath := filepath.Join(t.TempDir(), "holder-vault.json")
	if err := writeContinuityVault(vaultPath, holder); err != nil {
		t.Fatal(err)
	}
	if err := continuity.CheckIn(holder, owner, 1005); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	foreign, foreignOwner := continuityMsgVault(t)
	if err := continuity.CheckIn(foreign, foreignOwner, 1005); err != nil {
		t.Fatal(err)
	}
	foreignMsg, err := marshalContinuityCheckInMessage(mustEnvelope(t, foreign))
	if err != nil {
		t.Fatal(err)
	}

	k := newContinuityE2Kit(t)
	ing := &e2Ingestor{st: k.body, ep: k.receiver, mdb: k.db, continuity: vaultPath}
	k.ingestChain(t, ing, "e2-foreign", foreignMsg)
	k.ingestChain(t, ing, "e2-claimonly", []byte(`{"type":"`+continuityCheckInType+`"}`))

	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused check-in modified the holder vault")
	}
	if hits := k.db.SearchSimple("continuity-checkins"); len(hits) != 0 {
		t.Fatalf("refused protocol JSON indexed as chat: %d hit(s)", len(hits))
	}

	// A genuine check-in on the SAME session still lands: refusals consume
	// nothing but the ratchet step.
	good, err := marshalContinuityCheckInMessage(mustEnvelope(t, holder))
	if err != nil {
		t.Fatal(err)
	}
	k.ingestChain(t, ing, "e2-good", good)
	if _, seq, _ := vaultSeq(t, vaultPath); seq != 1 {
		t.Fatalf("genuine check-in after refusals: seq=%d, want 1", seq)
	}
}

// TestContinuityCheckInSurvivesFabricTransport drives the same message through
// ingestPointer — the relay-fabric drain's entry point — so both transports
// provably share one adoption rule and the fabric path is not a side door that
// skips verification or a hole that drops the artifact as chat.
func TestContinuityCheckInFabricTransportAdopts(t *testing.T) {
	v, owner := continuityMsgVault(t)
	vaultPath := filepath.Join(t.TempDir(), "holder-vault.json")
	if err := writeContinuityVault(vaultPath, v); err != nil {
		t.Fatal(err)
	}
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	msg, err := marshalContinuityCheckInMessage(mustEnvelope(t, v))
	if err != nil {
		t.Fatal(err)
	}

	k := newContinuityE2Kit(t)
	ing := &e2Ingestor{st: k.body, ep: k.receiver, mdb: k.db, continuity: vaultPath}
	_, raw := k.send(t, msg)
	if _, ok := ing.ingestPointer(raw, time.Now()); !ok {
		t.Fatal("fabric pointer for a check-in was not ingested")
	}
	if _, seq, deadline := vaultSeq(t, vaultPath); seq != 1 || deadline != 1095 {
		t.Fatalf("fabric-delivered check-in not adopted: seq=%d deadline=%d", seq, deadline)
	}
}

// TestContinuityCheckInWithoutVaultFlagStaysOutOfChat pins the default holder
// path: a receiver that has not set up a copy still recognizes the type (so it
// can say what arrived) but must not index the protocol JSON as a message.
func TestContinuityCheckInWithoutVaultFlagStaysOutOfChat(t *testing.T) {
	v, owner := continuityMsgVault(t)
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	msg, err := marshalContinuityCheckInMessage(mustEnvelope(t, v))
	if err != nil {
		t.Fatal(err)
	}

	k := newContinuityE2Kit(t)
	k.ingestChain(t, &e2Ingestor{st: k.body, ep: k.receiver, mdb: k.db}, "e2-noflag", msg)
	if hits := k.db.SearchSimple("continuity-checkins"); len(hits) != 0 {
		t.Fatalf("unadopted envelope recorded as chat: %d hit(s)", len(hits))
	}
	if hits := k.db.SearchSimple("sealed"); len(hits) != 0 {
		t.Fatalf("payload material reached the mail store: %d hit(s)", len(hits))
	}
	// A message that is NOT typed still lands as chat on the same session.
	k.ingestChain(t, &e2Ingestor{st: k.body, ep: k.receiver, mdb: k.db}, "e2-chat", []byte("plain hello"))
	if hits := k.db.SearchSimple("plain hello"); len(hits) != 1 {
		t.Fatalf("ordinary message after an unadopted check-in: %d hit(s), want 1", len(hits))
	}
}

func mustEnvelope(t *testing.T, v *continuity.Vault) *continuity.CheckInEnvelope {
	t.Helper()
	env, err := v.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	return env
}
