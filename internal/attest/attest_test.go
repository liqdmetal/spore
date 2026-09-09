package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func hashOf(t *testing.T, b []byte) ([]byte, int64) {
	t.Helper()
	sum, n, err := HashDocument(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return sum, n
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := mustKey(t)
	doc := []byte("This agreement is between A and B for 100 DERO.")
	sum, n := hashOf(t, doc)

	env, err := Sign(priv, sum, n, "I agree to these terms", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Verify(sum); err != nil {
		t.Fatalf("valid attestation rejected: %v", err)
	}
	// Verifiable by a THIRD PARTY who has only the envelope + document.
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var got Envelope
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(sum); err != nil {
		t.Fatalf("attestation did not survive JSON round trip: %v", err)
	}
	// And it must bind to the pinned key.
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if err := got.VerifyPinned(sum, pub); err != nil {
		t.Fatalf("VerifyPinned with correct key failed: %v", err)
	}
}

// TestAlteredDocumentFailsVerification is the whole point of the primitive:
// changing one byte of the contract must break the signature.
func TestAlteredDocumentFailsVerification(t *testing.T) {
	priv := mustKey(t)
	doc := []byte("Pay 100 DERO on delivery.")
	sum, n := hashOf(t, doc)
	env, err := Sign(priv, sum, n, "agreed", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	for _, tampered := range [][]byte{
		[]byte("Pay 900 DERO on delivery."), // amount changed
		[]byte("Pay 100 DERO on delivery"),  // trailing byte removed
		[]byte("pay 100 DERO on delivery."), // case changed
		append([]byte("Pay 100 DERO on delivery."), 0x00),
		{},
	} {
		badSum, _ := hashOf(t, tampered)
		if err := env.Verify(badSum); err == nil {
			t.Fatalf("altered document %q verified — forgery accepted", tampered)
		}
	}
}

// TestWrongSignerRejected: a valid signature by the WRONG person must not pass
// a pinned check. This is the "someone else signed your contract" attack.
func TestWrongSignerRejected(t *testing.T) {
	alice, bob := mustKey(t), mustKey(t)
	doc := []byte("Employment offer, 2026.")
	sum, n := hashOf(t, doc)

	// Bob signs a document that was supposed to be signed by Alice.
	env, err := Sign(bob, sum, n, "I agree", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The signature is internally VALID...
	if err := env.Verify(sum); err != nil {
		t.Fatalf("bob's own signature should be self-consistent: %v", err)
	}
	// ...but must fail when we require Alice's pinned key.
	alicePub := hex.EncodeToString(alice.Public().(ed25519.PublicKey))
	err = env.VerifyPinned(sum, alicePub)
	if err == nil {
		t.Fatal("attestation signed by the wrong key passed a pinned check")
	}
	if !strings.Contains(err.Error(), "WRONG KEY") {
		t.Fatalf("error should name the wrong-key problem, got: %v", err)
	}
}

// TestTamperedEnvelopeFieldsRejected: every signed field must be covered by the
// transcript. If any is editable after the fact, the artifact is worthless.
func TestTamperedEnvelopeFieldsRejected(t *testing.T) {
	priv := mustKey(t)
	doc := []byte("Statement of work.")
	sum, n := hashOf(t, doc)
	base, err := Sign(priv, sum, n, "I accept the SOW", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*Envelope){
		"statement rewritten": func(e *Envelope) { e.Statement = "I reject the SOW" },
		"signed_at backdated": func(e *Envelope) { e.SignedAt = "2001-01-01T00:00:00Z" },
		"doc_size inflated":   func(e *Envelope) { e.DocSize = 999999 },
		"domain downgraded":   func(e *Envelope) { e.Domain = "spore/attest/v0" },
		"signer swapped":      func(e *Envelope) { e.SignerPub = hex.EncodeToString(mustKey(t).Public().(ed25519.PublicKey)) },
		"statement emptied":   func(e *Envelope) { e.Statement = "" },
		"sig zeroed":          func(e *Envelope) { e.Sig = strings.Repeat("00", ed25519.SignatureSize) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			cp := *base
			mutate(&cp)
			if err := cp.Verify(sum); err == nil {
				t.Fatalf("tampered envelope (%s) verified — field is not covered by the signature", name)
			}
		})
	}
}

// TestTranscriptBeginsWithDomainTag is the REAL domain-separation guard.
//
// An earlier version of this file only asserted that an attestation signature
// differs from a naive signature over the bare document hash. That assertion is
// worthless: the transcript also contains the statement, signer and timestamp,
// so it differs from a bare hash even with NO domain tag at all — verified by
// mutation testing (deleting the tag left every test passing).
//
// This test asserts the STRUCTURE directly: the transcript must begin with the
// length-prefixed domain tag. Deleting `put([]byte(domainTag))` from
// transcript() fails here immediately.
func TestTranscriptBeginsWithDomainTag(t *testing.T) {
	docHash := make([]byte, 32)
	for i := range docHash {
		docHash[i] = byte(i)
	}
	got := transcript(docHash, 123, "stmt", "pub", "when")

	// Expected prefix: 8-byte big-endian length, then the tag bytes.
	var want []byte
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(domainTag)))
	want = append(want, n[:]...)
	want = append(want, []byte(domainTag)...)

	if !bytes.HasPrefix(got, want) {
		t.Fatalf("transcript does not begin with the length-prefixed domain tag %q.\n"+
			"Domain separation is missing: a signature from another protocol that signs\n"+
			"with this same Ed25519 key could be replayed as an attestation.\n"+
			"got prefix % x", domainTag, got[:min(len(got), 40)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSignatureIsNotValidUnderADifferentDomain proves the tag actually binds
// the signature: re-signing the same facts under a different domain string must
// not verify against this scheme.
func TestSignatureIsNotValidUnderADifferentDomain(t *testing.T) {
	priv := mustKey(t)
	doc := []byte("cross-scheme replay target")
	sum, n := hashOf(t, doc)

	env, err := Sign(priv, sum, n, "agreed", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Build the identical transcript but with a foreign domain tag, exactly as
	// a sibling protocol reusing this key would.
	var foreign []byte
	put := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		foreign = append(foreign, l[:]...)
		foreign = append(foreign, b...)
	}
	put([]byte("spore/otherproto/v1"))
	put(sum)
	var sz [8]byte
	binary.BigEndian.PutUint64(sz[:], uint64(n))
	put(sz[:])
	put([]byte(env.Statement))
	put([]byte(env.SignerPub))
	put([]byte(env.SignedAt))

	forged := *env
	forged.Sig = hex.EncodeToString(ed25519.Sign(priv, foreign))
	if err := forged.Verify(sum); err == nil {
		t.Fatal("a signature made under a DIFFERENT domain tag verified as an attestation")
	}
}

// TestDomainSeparation proves an attestation signature is NOT a bare signature
// over the document hash. Otherwise a signature captured from another protocol
// that signs raw hashes with the same key could be replayed as an attestation.
func TestDomainSeparation(t *testing.T) {
	priv := mustKey(t)
	doc := []byte("cross-protocol replay target")
	sum, n := hashOf(t, doc)

	// A naive signature over the raw hash, as another protocol might produce.
	naive := ed25519.Sign(priv, sum)

	env, err := Sign(priv, sum, n, "agreed", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	realSig, err := hex.DecodeString(env.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(naive, realSig) {
		t.Fatal("attestation signs the bare hash — no domain separation")
	}

	// And a raw-hash signature must not be accepted as an attestation.
	forged := *env
	forged.Sig = hex.EncodeToString(naive)
	if err := forged.Verify(sum); err == nil {
		t.Fatal("a raw-hash signature was accepted as an attestation (replayable)")
	}
}

func TestSignRejectsEmptyStatement(t *testing.T) {
	priv := mustKey(t)
	sum, n := hashOf(t, []byte("doc"))
	if _, err := Sign(priv, sum, n, "", time.Now()); err == nil {
		t.Fatal("Sign accepted an empty statement: the signature's meaning would be undefined")
	}
}

func TestAnchorDigestCommitsToEverything(t *testing.T) {
	priv := mustKey(t)
	sum, n := hashOf(t, []byte("anchor me"))
	env, err := Sign(priv, sum, n, "agreed", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d1, err := env.AnchorDigest()
	if err != nil {
		t.Fatal(err)
	}
	// Same envelope -> same digest (deterministic, so a verifier can recompute).
	d2, err := env.AnchorDigest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("AnchorDigest is not deterministic")
	}
	// Any change -> different digest.
	alt := *env
	alt.Statement = "agreed (revised)"
	d3, err := alt.AnchorDigest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("AnchorDigest does not commit to the statement")
	}
}

// TestSheetMultiSigner covers the contract case: several parties, no ordering,
// no coordinator, and an explicit "who still has to sign" answer.
func TestSheetMultiSigner(t *testing.T) {
	alice, bob, carol := mustKey(t), mustKey(t), mustKey(t)
	pub := func(k ed25519.PrivateKey) string {
		return hex.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	doc := []byte("Three-party settlement agreement.")
	sum, n := hashOf(t, doc)

	sheet := &Sheet{}
	for _, k := range []ed25519.PrivateKey{bob, alice} { // deliberately out of order
		env, err := Sign(k, sum, n, "I agree", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := sheet.Add(env); err != nil {
			t.Fatal(err)
		}
	}

	required := []string{pub(alice), pub(bob), pub(carol)}
	missing, err := sheet.VerifyAll(sum, required)
	if err != nil {
		t.Fatalf("valid sheet rejected: %v", err)
	}
	if len(missing) != 1 || missing[0] != pub(carol) {
		t.Fatalf("missing = %v, want just carol", missing)
	}

	// Carol signs; now it is fully executed.
	cenv, err := Sign(carol, sum, n, "I agree", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := sheet.Add(cenv); err != nil {
		t.Fatal(err)
	}
	missing, err = sheet.VerifyAll(sum, required)
	if err != nil || len(missing) != 0 {
		t.Fatalf("fully signed sheet: missing=%v err=%v", missing, err)
	}

	// Double-signing must be refused.
	dup, err := Sign(alice, sum, n, "I agree again", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := sheet.Add(dup); err == nil {
		t.Fatal("sheet accepted a second signature from the same key")
	}

	// A signature over a DIFFERENT document must not join the sheet.
	otherSum, otherN := hashOf(t, []byte("a different agreement"))
	wrong, err := Sign(mustKey(t), otherSum, otherN, "I agree", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := sheet.Add(wrong); err == nil {
		t.Fatal("sheet accepted a signature covering a different document")
	}
}

// TestSheetFailsClosedOnOneBadSignature: a sheet with any invalid signature
// must fail entirely, not silently report the rest as fine.
func TestSheetFailsClosedOnOneBadSignature(t *testing.T) {
	alice, bob := mustKey(t), mustKey(t)
	doc := []byte("joint agreement")
	sum, n := hashOf(t, doc)

	good, err := Sign(alice, sum, n, "I agree", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bad, err := Sign(bob, sum, n, "I agree", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bad.Statement = "I DISAGREE" // invalidates bob's signature

	sheet := &Sheet{}
	if err := sheet.Add(good); err != nil {
		t.Fatal(err)
	}
	sheet.Sigs = append(sheet.Sigs, bad) // bypass Add to simulate a hostile sheet

	if _, err := sheet.VerifyAll(sum, nil); err == nil {
		t.Fatal("sheet with one invalid signature verified as a whole")
	}
}

func TestHashDocumentStreamsLargeInput(t *testing.T) {
	big := make([]byte, 5<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	sum, n, err := HashDocument(bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(big)) {
		t.Fatalf("size = %d, want %d", n, len(big))
	}
	priv := mustKey(t)
	env, err := Sign(priv, sum, n, "I have reviewed this 5 MiB file", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Verify(sum); err != nil {
		t.Fatal(err)
	}
}
