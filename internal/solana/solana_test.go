package solana

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/liqdmetal/spore/internal/chain"
)

// TestEncodeDecodeInboxRoundTrip verifies a borsh Inbox with one StoredMessage
// round-trips through EncodeInbox/DecodeInbox.
func TestEncodeDecodeInboxRoundTrip(t *testing.T) {
	msg := StoredMessage{
		Data: []byte("hello mycelium"),
		Seq:  7,
	}
	// from = 32 bytes, fixed pattern
	for i := range msg.From {
		msg.From[i] = byte(i)
	}
	in := &Inbox{Messages: []StoredMessage{msg}}

	enc, err := EncodeInbox(in)
	if err != nil {
		t.Fatalf("EncodeInbox: %v", err)
	}

	dec, err := DecodeInbox(enc)
	if err != nil {
		t.Fatalf("DecodeInbox: %v", err)
	}
	if len(dec.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(dec.Messages))
	}
	got := dec.Messages[0]
	if !bytes.Equal(got.From[:], msg.From[:]) {
		t.Errorf("From mismatch:\n got %x\nwant %x", got.From, msg.From)
	}
	if !bytes.Equal(got.Data, msg.Data) {
		t.Errorf("Data mismatch: got %q want %q", got.Data, msg.Data)
	}
	if got.Seq != msg.Seq {
		t.Errorf("Seq mismatch: got %d want %d", got.Seq, msg.Seq)
	}
}

// TestEncodeInboxEmpty verifies an empty inbox encodes to just a zero u32
// length prefix (4 zero bytes) and decodes back to zero messages.
func TestEncodeInboxEmpty(t *testing.T) {
	enc, err := EncodeInbox(&Inbox{})
	if err != nil {
		t.Fatalf("EncodeInbox: %v", err)
	}
	want := []byte{0, 0, 0, 0}
	if !bytes.Equal(enc, want) {
		t.Fatalf("empty inbox encoded as %x, want %x", enc, want)
	}
	dec, err := DecodeInbox(enc)
	if err != nil {
		t.Fatalf("DecodeInbox: %v", err)
	}
	if len(dec.Messages) != 0 {
		t.Fatalf("expected 0 messages, got %d", len(dec.Messages))
	}
}

// TestEncodeDecodeInboxMultiple verifies multiple messages round-trip in order.
func TestEncodeDecodeInboxMultiple(t *testing.T) {
	in := &Inbox{Messages: []StoredMessage{
		{Data: []byte("one"), Seq: 0},
		{Data: []byte("two"), Seq: 1},
		{Data: []byte("three"), Seq: 2},
	}}
	enc, err := EncodeInbox(in)
	if err != nil {
		t.Fatalf("EncodeInbox: %v", err)
	}
	dec, err := DecodeInbox(enc)
	if err != nil {
		t.Fatalf("DecodeInbox: %v", err)
	}
	if len(dec.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(dec.Messages))
	}
	for i, want := range []string{"one", "two", "three"} {
		if string(dec.Messages[i].Data) != want {
			t.Errorf("message %d data = %q, want %q", i, dec.Messages[i].Data, want)
		}
		if dec.Messages[i].Seq != uint64(i) {
			t.Errorf("message %d seq = %d, want %d", i, dec.Messages[i].Seq, i)
		}
	}
}

// TestDecodeInboxTruncated verifies decoding truncated data returns an error
// rather than panicking.
func TestDecodeInboxTruncated(t *testing.T) {
	enc, err := EncodeInbox(&Inbox{Messages: []StoredMessage{{Data: []byte("x"), Seq: 1}}})
	if err != nil {
		t.Fatalf("EncodeInbox: %v", err)
	}
	for _, cut := range []int{0, 1, 4, 8, len(enc) - 1} {
		if _, err := DecodeInbox(enc[:cut]); err == nil {
			t.Errorf("expected error decoding %d-byte truncated input, got nil", cut)
		}
	}
}

// TestInboxPDADerivation verifies the recipient inbox PDA derivation matches
// the known program's convention seeds=[b"mycelium", recipient_pubkey].
func TestInboxPDADerivation(t *testing.T) {
	recipient := solana.MustPublicKeyFromBase58("DpfWQNnxUdJ7Lz9mr6Xvjs9WbiRAJD7N1Q5cVQtckjKX")
	pda, bump, err := solana.FindProgramAddress(
		[][]byte{[]byte("mycelium"), recipient.Bytes()},
		DefaultProgramID,
	)
	if err != nil {
		t.Fatalf("FindProgramAddress: %v", err)
	}
	_ = bump
	// The derived address must be deterministic and off the ed25519 curve.
	if pda == recipient {
		t.Fatal("PDA must differ from the recipient pubkey")
	}
	// Re-deriving with the same seeds must give the identical address.
	pda2, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("mycelium"), recipient.Bytes()},
		DefaultProgramID,
	)
	if err != nil {
		t.Fatalf("FindProgramAddress (2nd): %v", err)
	}
	if pda != pda2 {
		t.Fatalf("PDA derivation is not deterministic: %s vs %s", pda, pda2)
	}
	if len(pda) != solana.PublicKeyLength {
		t.Fatalf("PDA length = %d, want %d", len(pda), solana.PublicKeyLength)
	}
}

// TestBackendSelfConsistency builds a Backend and checks Name/Address and that
// its inboxPDA matches the raw solana.FindProgramAddress result.
func TestBackendSelfConsistency(t *testing.T) {
	key, err := solana.NewRandomPrivateKey()
	if err != nil {
		t.Fatalf("NewRandomPrivateKey: %v", err)
	}
	b := NewBackend("", DefaultProgramID, key)
	if b.Name() != "solana" {
		t.Errorf("Name = %q, want solana", b.Name())
	}
	addr := b.signer.PublicKey().String()
	gotAddr, _ := b.Address(nil)
	if gotAddr != addr {
		t.Errorf("Address = %q, want %q", gotAddr, addr)
	}
	pda, err := b.inboxPDA(b.signer.PublicKey())
	if err != nil {
		t.Fatalf("inboxPDA: %v", err)
	}
	ref, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("mycelium"), b.signer.PublicKey().Bytes()},
		b.programID,
	)
	if err != nil {
		t.Fatalf("FindProgramAddress: %v", err)
	}
	if pda != ref {
		t.Errorf("inboxPDA = %s, want %s", pda, ref)
	}
}

// TestInboxToIncomingSeqKeys verifies every inbox message gets a distinct,
// stable, non-empty TxID — the old code returned TxID "" for ALL messages,
// which made chain.Watch's dedup drop everything after the first message
// (audit H2).
func TestInboxToIncomingSeqKeys(t *testing.T) {
	in := &Inbox{Messages: []StoredMessage{
		{From: [32]byte{1}, Data: []byte("one"), Seq: 0},
		{From: [32]byte{2}, Data: []byte("two"), Seq: 1},
		{From: [32]byte{3}, Data: []byte("three"), Seq: 2},
	}}
	got := inboxToIncoming(in)
	if len(got) != 3 {
		t.Fatalf("got %d incoming, want 3", len(got))
	}
	seen := map[string]bool{}
	for i, inc := range got {
		if inc.TxID == "" {
			t.Errorf("message %d has empty TxID — dedup would swallow it", i)
		}
		if seen[inc.TxID] {
			t.Errorf("duplicate TxID %q across messages", inc.TxID)
		}
		seen[inc.TxID] = true
		if inc.Sender == "" {
			t.Errorf("message %d has empty Sender", i)
		}
		if string(inc.Payload) != []string{"one", "two", "three"}[i] {
			t.Errorf("message %d payload = %q", i, inc.Payload)
		}
	}
	// Stability: a second decode of the same inbox yields identical keys (so
	// mailbox log dedup and chain.Watch dedup survive restarts).
	again := inboxToIncoming(in)
	for i := range got {
		if got[i].TxID != again[i].TxID {
			t.Errorf("TxID not stable across calls: %q vs %q", got[i].TxID, again[i].TxID)
		}
	}
}

// fakeChain returns the same incoming list on every poll — mimicking the
// Solana backend, which re-reads the FULL inbox every poll.
type fakeChain struct{ list []chain.Incoming }

func (f *fakeChain) Name() string { return "fake" }
func (f *fakeChain) Address(ctx context.Context) (string, error) {
	return "fake", nil
}
func (f *fakeChain) Height(ctx context.Context) (uint64, error) { return 0, nil }
func (f *fakeChain) PostPayload(ctx context.Context, recipientAddr string, p chain.Payload, amountHint uint64) (chain.PostResult, error) {
	return chain.PostResult{TxID: "fake"}, nil
}
func (f *fakeChain) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	return f.list, nil
}

// TestWatchDeliversEverySolanaMessage is the regression test for audit H2:
// the Solana backend re-lists the whole inbox each poll, and every entry used
// to carry TxID "" — chain.Watch's dedup then delivered exactly ONE message
// per process lifetime. With seq-keyed TxIDs, all messages must be delivered
// exactly once.
func TestWatchDeliversEverySolanaMessage(t *testing.T) {
	fc := &fakeChain{list: inboxToIncoming(&Inbox{Messages: []StoredMessage{
		{From: [32]byte{1}, Data: []byte("m0"), Seq: 0},
		{From: [32]byte{2}, Data: []byte("m1"), Seq: 1},
		{From: [32]byte{3}, Data: []byte("m2"), Seq: 2},
	}})}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	in, errc := chain.Watch(ctx, fc, chain.WatchOpts{Interval: time.Millisecond})

	got := map[string]int{}
	for {
		select {
		case inc, ok := <-in:
			if !ok {
				in = nil
				continue
			}
			got[inc.TxID]++
		case err := <-errc:
			t.Fatalf("watch error: %v", err)
			return
		case <-ctx.Done():
			// Several polls have run (1ms interval vs 150ms budget); each poll
			// re-listed all 3 messages. Each must have been delivered exactly once.
			for _, want := range []string{"sol-inbox-0", "sol-inbox-1", "sol-inbox-2"} {
				if got[want] != 1 {
					t.Errorf("message %s delivered %d times, want exactly 1 (old bug: only the first ever arrived)", want, got[want])
				}
			}
			if len(got) != 3 {
				t.Errorf("delivered %d distinct messages, want 3", len(got))
			}
			return
		}
	}
}
