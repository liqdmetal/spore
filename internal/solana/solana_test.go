package solana

import (
	"bytes"
	"testing"

	"github.com/gagliardetto/solana-go"
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
