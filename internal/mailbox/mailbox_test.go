package mailbox

import (
	"context"
	"testing"
	"time"

	"github.com/liqdmetal/mycelium/internal/chain"
	"github.com/liqdmetal/mycelium/internal/longmsg"
	"github.com/liqdmetal/mycelium/internal/rendezvous"
	"github.com/liqdmetal/mycelium/internal/store"
	"github.com/liqdmetal/mycelium/internal/whisper"
)

func openMailbox(t *testing.T) *Mailbox {
	t.Helper()
	m, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// senderToMailbox builds a fresh sender endpoint that encrypts a long body to
// the mailbox's public key, holds the ciphertext on an in-memory peer
// transport (standing in for a sender node), and returns everything needed to
// deliver the pointer.
func senderToMailbox(t *testing.T, m *Mailbox, text string) (*longmsg.Pointer, *rendezvous.MemTransport) {
	t.Helper()
	sender, err := longmsg.NewEndpoint(store.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := sender.SendBody(m.PublicKey(), []byte(text), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sender.Store().Get(ptr.CID)
	if err != nil {
		t.Fatal(err)
	}
	transport := rendezvous.NewMemTransport()
	transport.Put(ptr.CID, ct)
	return ptr, transport
}

// pointerIncoming renders a canonical pointer-whisper payload for the given
// pointer as an on-chain Incoming (as any non-DERO chain.Watch would surface).
func pointerIncoming(t *testing.T, ptr *longmsg.Pointer, txid string) chain.Incoming {
	t.Helper()
	payload, err := whisper.CanonicalCodec{}.EncodePointer(ptr.EphemeralPub, ptr.CID)
	if err != nil {
		t.Fatal(err)
	}
	return chain.Incoming{TxID: txid, Sender: "alice", TopoHeight: 42, Payload: payload}
}

// TestDeliverDecryptsLongBodyOnPointerScan is the core decrypt-on-pointer-scan
// logic: a mailbox watching a chain sees a pointer-whisper, fetches the body
// over an (in-memory) peer transport, verifies + decrypts it, and stores the
// plaintext durably. No chain or live node required.
func TestDeliverDecryptsLongBodyOnPointerScan(t *testing.T) {
	m := openMailbox(t)
	const secret = "this long body never rides a block and never sits on a third party"
	ptr, transport := senderToMailbox(t, m, secret)

	msgs, err := m.Deliver(context.Background(), pointerIncoming(t, ptr, "tx-1"),
		whisper.CanonicalCodec{}, transport.Fetch)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("deliver stored %d messages, want 1", len(msgs))
	}
	if msgs[0].Text != secret {
		t.Fatalf("decrypted text = %q, want %q", msgs[0].Text, secret)
	}
	if msgs[0].Kind != "long" {
		t.Fatalf("kind = %q, want long", msgs[0].Kind)
	}
	if n, err := m.Count(); err != nil || n != 1 {
		t.Fatalf("log count = %d (%v), want 1", n, err)
	}
}

// TestDeliverIsIdempotent: re-delivering the same pointer (restart re-scan)
// must not store a duplicate.
func TestDeliverIsIdempotent(t *testing.T) {
	m := openMailbox(t)
	ptr, transport := senderToMailbox(t, m, "dupe me")
	inc := pointerIncoming(t, ptr, "tx-dup")
	if _, err := m.Deliver(context.Background(), inc, whisper.CanonicalCodec{}, transport.Fetch); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Deliver(context.Background(), inc, whisper.CanonicalCodec{}, transport.Fetch); err != nil {
		t.Fatal(err)
	}
	if n, _ := m.Count(); n != 1 {
		t.Fatalf("count = %d, want 1 (pointer re-scan must not duplicate)", n)
	}
}

// TestWrongRecipientNotStored: a body encrypted to someone ELSE's key must fail
// decrypt (ECDH) and must not be stored.
func TestWrongRecipientNotStored(t *testing.T) {
	m := openMailbox(t)
	other, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := longmsg.NewEndpoint(store.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := sender.SendBody(other.PublicKey(), []byte("not for me"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := sender.Store().Get(ptr.CID)
	transport := rendezvous.NewMemTransport()
	transport.Put(ptr.CID, ct)

	if _, err := m.Deliver(context.Background(), pointerIncoming(t, ptr, "tx-x"),
		whisper.CanonicalCodec{}, transport.Fetch); err == nil {
		t.Fatal("expected decrypt failure for a body meant for another recipient")
	}
	if n, _ := m.Count(); n != 0 {
		t.Fatalf("count = %d, want 0 (foreign body must not be stored)", n)
	}
}

// TestBurnDeadlineRefused: a pointer whose BurnDeadline has passed is refused
// BEFORE the body is fetched — a burned message can never be read or stored.
func TestBurnDeadlineRefused(t *testing.T) {
	m := openMailbox(t)
	ptr, _ := senderToMailbox(t, m, "burning secret")
	ptr.BurnDeadline = uint64(time.Now().Add(-time.Minute).Unix())

	fetched := false
	_, err := m.ReceivePointer(context.Background(), ptr, "tx-burn", "alice", 7,
		func(ctx context.Context, cid [32]byte) ([]byte, error) { fetched = true; return []byte("never"), nil })
	if err == nil {
		t.Fatal("expected burned-pointer rejection")
	}
	if fetched {
		t.Fatal("body must not be fetched for a burned pointer")
	}
	if n, _ := m.Count(); n != 0 {
		t.Fatalf("count = %d, want 0 (burned message must not be stored)", n)
	}
}

// TestExpiredBodyNotDelivered enforces the mailbox-side burn path used by real
// HTTP-pushed bodies: a body whose store deadline passed (X-Burn-Deadline)
// yields ErrExpired from the local fetch, so the pointer is not delivered and
// nothing is stored.
func TestExpiredBodyNotDelivered(t *testing.T) {
	m := openMailbox(t)
	sender, err := longmsg.NewEndpoint(store.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := sender.SendBody(m.PublicKey(), []byte("will burn"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := sender.Store().Get(ptr.CID)
	// Push the real body into the mailbox store with a PAST deadline, exactly
	// like an HTTP /put whose X-Burn-Deadline has since elapsed.
	if err := m.PutBody(ptr.CID, ct, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Deliver(context.Background(), pointerIncoming(t, ptr, "tx-exp"),
		whisper.CanonicalCodec{}, m.LocalFetch); err == nil {
		t.Fatal("expected delivery failure for an expired local body")
	}
	if n, _ := m.Count(); n != 0 {
		t.Fatalf("count = %d, want 0 (expired body must not be stored)", n)
	}
}

// --- in-memory chain.Chain so the scanner loop is testable with no node ---

type fakeChain struct {
	incoming []chain.Incoming
}

func (f *fakeChain) Name() string                                { return "fake" }
func (f *fakeChain) Address(ctx context.Context) (string, error) { return "me", nil }
func (f *fakeChain) Height(ctx context.Context) (uint64, error)  { return 99, nil }
func (f *fakeChain) PostPayload(context.Context, string, chain.Payload, uint64) (chain.PostResult, error) {
	return chain.PostResult{}, nil
}
func (f *fakeChain) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	return f.incoming, nil
}

// TestRunScannerDeliversFromChain drives the full always-on scan path against an
// in-memory chain.Chain and asserts the message arrives through the scanner.
func TestRunScannerDeliversFromChain(t *testing.T) {
	m := openMailbox(t)
	ptr, transport := senderToMailbox(t, m, "delivered via scanner")

	c := &fakeChain{incoming: []chain.Incoming{pointerIncoming(t, ptr, "tx-scan")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan Message, 1)
	go func() {
		m.RunScanner(ctx, c, whisper.CanonicalCodec{},
			chain.WatchOpts{MinHeight: 0, Interval: time.Millisecond}, transport.Fetch,
			func(msg Message) { got <- msg }, nil)
	}()

	select {
	case msg := <-got:
		if msg.Text != "delivered via scanner" {
			t.Fatalf("scanner text = %q", msg.Text)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scanner never delivered the message")
	}
	if n, _ := m.Count(); n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}
