package ratchet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/crypto"
)

// ---- fixtures ----

// fixedScalar returns a deterministic 32-byte scalar for tests.
func fixedScalar(b byte) []byte {
	return bytes.Repeat([]byte{b}, 32)
}

// pair is an established session pair (Alice initiates, Bob responds).
type pair struct {
	alice, bob *Session
	bundle     *SPKBundle
}

// establishPair runs X3DH with fixed identity/SPK/OPK scalars.
func establishPair(t *testing.T, withOPK bool) pair {
	t.Helper()
	ikA, ikB, spkB, opkB := fixedScalar(0xA1), fixedScalar(0xB1), fixedScalar(0xB2), fixedScalar(0xB3)
	var opkPtr *[32]byte
	opkID := uint32(7)
	if withOPK {
		opkPtr = &[32]byte{}
		copy(opkPtr[:], opkB)
	}
	bundle, err := BuildBundle(ikB, spkB, 42, opkPtr, opkID)
	if err != nil {
		t.Fatal(err)
	}
	// Alice pins Bob's sig key (derived from his identity, same as envelopes).
	pinned, err := sigPubOf(ikB)
	if err != nil {
		t.Fatal(err)
	}
	alice, hs, err := EstablishInitiator(ikA, bundle, pinned)
	if err != nil {
		t.Fatal(err)
	}
	var bob *Session
	if withOPK {
		bob, err = EstablishResponder(ikB, spkB, opkPtr, hs)
	} else {
		bob, err = EstablishResponder(ikB, spkB, nil, hs)
	}
	if err != nil {
		t.Fatal(err)
	}
	if alice.ID() != bob.ID() {
		t.Fatalf("session id mismatch: %x != %x", alice.ID(), bob.ID())
	}
	return pair{alice: alice, bob: bob, bundle: bundle}
}

// sigPubOf re-derives the identity's Ed25519 public key for pinning (same
// derivation as secure.sigKeypair: sha256("spore/sig/v1/seed" || priv)).
func sigPubOf(identityPriv []byte) ([]byte, error) {
	seed := sha256.Sum256(append([]byte("spore/sig/v1/seed"), identityPriv...))
	k := ed25519.NewKeyFromSeed(seed[:])
	pub := k.Public().(ed25519.PublicKey)
	return append([]byte(nil), pub...), nil
}

func TestX3DHWithOPKRoundTrip(t *testing.T) {
	p := establishPair(t, true)
	m, err := p.alice.Encrypt([]byte("hello bob"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := p.bob.Decrypt(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello bob" {
		t.Fatalf("got %q", pt)
	}
	// Bob replies (fresh DH ratchet key on his first send).
	r, err := p.bob.Encrypt([]byte("hi alice"))
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := p.alice.Decrypt(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt2) != "hi alice" {
		t.Fatalf("got %q", pt2)
	}
}

func TestX3DHDegradedWithoutOPK(t *testing.T) {
	p := establishPair(t, false)
	if !p.bundleWasDegraded() {
		t.Fatal("expected degraded bundle")
	}
	m, err := p.alice.Encrypt([]byte("no opk"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.bob.Decrypt(m); err != nil {
		t.Fatal(err)
	}
}

func (p pair) bundleWasDegraded() bool { return p.bundle.OPKPub == nil }

func TestSPKSigRejection(t *testing.T) {
	_, _, ikB, _ := fixedScalar(0xA1), fixedScalar(0xB1), fixedScalar(0xB2), fixedScalar(0xB3)
	bundle, err := BuildBundle(ikB, fixedScalar(0xB2), 1, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Pinned to the WRONG identity: the bundle must be rejected.
	wrongPin, err := sigPubOf(fixedScalar(0xEE))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := EstablishInitiator(fixedScalar(0xA1), bundle, wrongPin); err == nil {
		t.Fatal("bundle accepted against a foreign pinned sig key")
	}
	// Tamper the SPK pub: signature no longer verifies.
	bundle.SPKPub[0] ^= 0xFF
	good, _ := sigPubOf(ikB)
	if _, _, err := EstablishInitiator(fixedScalar(0xA1), bundle, good); err == nil {
		t.Fatal("tampered SPK accepted")
	}
}

func TestOPKSwapDetected(t *testing.T) {
	_, ikB, spkB, _ := fixedScalar(0xA1), fixedScalar(0xB1), fixedScalar(0xB2), fixedScalar(0xB3)
	bundle, err := BuildBundle(ikB, spkB, 1, opkBytes(0xB3), 1)
	if err != nil {
		t.Fatal(err)
	}
	// A malicious mailbox swaps in its own OPK.
	fake := fixedScalar(0xF0)
	fk, _ := crypto.KeyPairFromPriv(fake)
	copy(bundle.OPKPub[:], fk.Pub)
	pinned, _ := sigPubOf(ikB)
	if _, _, err := EstablishInitiator(fixedScalar(0xA1), bundle, pinned); err == nil {
		t.Fatal("swapped OPK accepted — hash not bound into the signed transcript")
	}
}

func opkBytes(b byte) *[32]byte {
	p := [32]byte{}
	for i := range p {
		p[i] = b
	}
	return &p
}

// ---- double ratchet ----

func TestLongConversationAlternating(t *testing.T) {
	p := establishPair(t, true)
	msgs := []string{"m1", "m2", "m3"}
	for i, s := range msgs {
		m, err := p.alice.Encrypt([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.bob.Decrypt(m)
		if err != nil {
			t.Fatalf("bob msg %d: %v", i, err)
		}
		if string(got) != s {
			t.Fatalf("bob msg %d: got %q", i, got)
		}
	}
	// Direction change with fresh DH keys, twice.
	for _, s := range []string{"r1", "r2"} {
		m, err := p.bob.Encrypt([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.alice.Decrypt(m)
		if err != nil {
			t.Fatalf("alice %s: %v", s, err)
		}
		if string(got) != s {
			t.Fatalf("alice: got %q", got)
		}
	}
	// And back again — full alternation exercises both ratchets.
	m, err := p.alice.Encrypt([]byte("m4"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.bob.Decrypt(m); err != nil || string(got) != "m4" {
		t.Fatalf("bob m4: %q %v", got, err)
	}
}

// Golden requirement (§11.4): receive 2,3 then 1 — all deliver, and the
// skipped store drains to zero after delivery + TTL sweep.
func TestOutOfOrderDelivers231AndStoreDrains(t *testing.T) {
	p := establishPair(t, true)
	var wire [][]byte
	for i := 0; i < 3; i++ {
		m, err := p.alice.Encrypt([]byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, m.MarshalBinary())
	}
	deadline := time.Now().Add(time.Hour)
	for _, i := range []int{1, 2, 0} {
		m, err := UnmarshalMessage(wire[i])
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.bob.DecryptWithDeadline(m, deadline)
		if err != nil {
			t.Fatalf("deliver #%d: %v", i+1, err)
		}
		if got[0] != byte('a'+i) {
			t.Fatalf("deliver #%d: got %q", i+1, got)
		}
	}
	if len(p.bob.skipped) != 0 {
		t.Fatalf("skipped store not drained after delivery: %d keys", len(p.bob.skipped))
	}
	// Late-duplicated message 2 is a replay now.
	m2, _ := UnmarshalMessage(wire[1])
	if _, err := p.bob.Decrypt(m2); err == nil {
		t.Fatal("replayed message accepted after the chain advanced past it")
	}
}

func TestSkippedKeyDeadlineSweep(t *testing.T) {
	p := establishPair(t, true)
	m1, _ := p.alice.Encrypt([]byte("m1"))
	m2, _ := p.alice.Encrypt([]byte("m2"))
	// Deliver m2 first: m1's key lands in the skipped store with a deadline
	// that has ALREADY passed.
	past := time.Now().Add(-time.Minute)
	if _, err := p.bob.DecryptWithDeadline(m2, past); err != nil {
		t.Fatal(err)
	}
	if len(p.bob.skipped) != 1 {
		t.Fatalf("expected 1 skipped key, got %d", len(p.bob.skipped))
	}
	if n := p.bob.SweepSkipped(time.Now()); n != 1 {
		t.Fatalf("sweep dropped %d keys, want 1", n)
	}
	// The skipped key is dead: delivering m1 now must fail CLOSED (the
	// message rots with its key — this is the per-message rot property G5).
	if _, err := p.bob.Decrypt(m1); err == nil {
		t.Fatal("message with a swept (rotted) key decrypted — rot is broken")
	}
}

func TestSkipBoundsFailClosed(t *testing.T) {
	p := establishPair(t, true)
	p.bob.MaxSkipPerChain = 4
	p.bob.MaxSkipPerSession = 8
	// Deliver message #6 first: buffering 5 skipped keys exceeds the
	// per-chain cap → the receive must fail closed, not over-keep.
	for i := 0; i < 6; i++ {
		if _, err := p.alice.Encrypt([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	m6, _ := p.alice.Encrypt([]byte("six")) // n=6; requires skipping 0..5
	wire := m6.MarshalBinary()
	mm, _ := UnmarshalMessage(wire)
	if _, err := p.bob.Decrypt(mm); err == nil {
		t.Fatal("over-cap skipped-key buffering accepted — bounds must fail closed")
	}
}

func TestHeaderTamperFailsClosed(t *testing.T) {
	p := establishPair(t, true)
	m, _ := p.alice.Encrypt([]byte("secret"))
	wire := m.MarshalBinary()
	// Flip a bit in the header (AAD — the tag must catch it).
	wire[5] ^= 0x01
	mm, err := UnmarshalMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.bob.Decrypt(mm); err == nil {
		t.Fatal("tampered header accepted — header is not AAD")
	}
	// And the ciphertext itself.
	wire2 := m.MarshalBinary()
	wire2[len(wire2)-1] ^= 0x01
	mm2, _ := UnmarshalMessage(wire2)
	if _, err := p.bob.Decrypt(mm2); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestForeignSessionRejected(t *testing.T) {
	p1 := establishPair(t, true)
	p2 := establishPair(t, true)
	// A message from session 1 fed to session 2 (different sid → AAD/KDF
	// labels differ) must not decrypt.
	m, _ := p1.alice.Encrypt([]byte("wrong session"))
	if _, err := p2.bob.Decrypt(m); err == nil {
		t.Fatal("cross-session message decrypted")
	}
}

// ---- compromise ----

// TestCompromiseSimulation is the roadmap's headline test (§11.2): steal a
// serialized state snapshot at step N; assert messages the victim already
// consumed are DEAD (their keys were erased — forward secrecy) while
// in-flight traffic is exposed (the honest boundary), and that after the
// snapshot is stale the attacker is locked out entirely.
func TestCompromiseSimulation(t *testing.T) {
	p := establishPair(t, true)

	// Step 1: Alice sends m1; Bob consumes it (message key erased on use).
	m1, err := p.alice.Encrypt([]byte("burn after reading"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.bob.Decrypt(m1); err != nil {
		t.Fatal(err)
	}

	// Step 2: the attacker steals BOB's exported state right now.
	stolen, err := p.bob.Export()
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := ImportState(stolen)
	if err != nil {
		t.Fatal(err)
	}

	// Step 3: history is gone. The stolen state's receiving cursor is past
	// m1; its chain keys can never re-derive m1's message key.
	if _, err := attacker.Decrypt(m1); err == nil {
		t.Fatal("FORWARD SECRECY BROKEN: stolen state decrypted an already-consumed message")
	}

	// Step 4: in-flight exposure — the honest boundary. m2, sent on the
	// still-current chain, IS decryptable from the stolen state.
	m2, _ := p.alice.Encrypt([]byte("in flight"))
	got, err := attacker.Decrypt(m2)
	if err != nil {
		t.Fatalf("expected in-flight exposure (state is current): %v", err)
	}
	if string(got) != "in flight" {
		t.Fatalf("got %q", got)
	}

	// Step 5: the conversation heals. Bob replies (fresh DH ratchet key),
	// Alice receives it (ratchets; retires her old DH key; generates a
	// fresh one for her next send), Alice sends m3. The attacker's stolen
	// state lacks BOTH fresh scalars → locked out.
	r1, err := p.bob.Encrypt([]byte("heal"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.alice.Decrypt(r1); err != nil {
		t.Fatal(err)
	}
	m3, err := p.alice.Encrypt([]byte("post healing"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attacker.Decrypt(m3); err == nil {
		t.Fatal("POST-COMPROMISE SECURITY BROKEN: stale stolen state decrypted a post-healing message")
	}
	// The honest parties still read everything.
	if got, err := p.bob.Decrypt(m3); err != nil || string(got) != "post healing" {
		t.Fatalf("honest bob lost the session after healing: %q %v", got, err)
	}
	// Attacker cannot decrypt r2 either (Bob's fresh key lives only on devices).
	r2, _ := p.bob.Encrypt([]byte("still healing"))
	if _, err := attacker.Decrypt(r2); err == nil {
		t.Fatal("stale state decrypted Bob's post-healing traffic")
	}
}

func TestEraseKillsEverything(t *testing.T) {
	p := establishPair(t, true)
	m1, _ := p.alice.Encrypt([]byte("one"))
	wire := m1.MarshalBinary()
	p.bob.Erase()
	mm, _ := UnmarshalMessage(wire)
	if _, err := p.bob.Decrypt(mm); err == nil {
		t.Fatal("erased session still decrypts")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	p := establishPair(t, true)
	// Advance the ratchet a bit, including a skipped key.
	m1, _ := p.alice.Encrypt([]byte("m1"))
	m2, _ := p.alice.Encrypt([]byte("m2"))
	if _, err := p.bob.Decrypt(m2); err != nil { // m1 skipped
		t.Fatal(err)
	}
	blob, err := p.bob.Export()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ImportState(blob)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID() != p.bob.ID() {
		t.Fatal("session id lost in export/import")
	}
	// The restored session behaves identically: decrypt the skipped m1.
	got, err := restored.Decrypt(m1)
	if err != nil {
		t.Fatalf("restored session cannot decrypt skipped message: %v", err)
	}
	if string(got) != "m1" {
		t.Fatalf("got %q", got)
	}
	// And continues ratcheting.
	m3, _ := p.alice.Encrypt([]byte("m3"))
	if _, err := restored.Decrypt(m3); err != nil {
		t.Fatal(err)
	}
}

// Deterministic scalar helpers shared with the vector test.
func hexScalar(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
