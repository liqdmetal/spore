package broadcast

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func cid(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func pubKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func TestSealOpenRoundTrip(t *testing.T) {
	priv, pubHex := pubKey(t)
	body := []byte("ISSUE #1\n\nOff-grid dispatch: the well is in.\n")

	ct, notice, err := SealIssue(priv, "offgrid", 1, "Dispatch 1", body, cid)
	if err != nil {
		t.Fatal(err)
	}
	// The shared ciphertext must not contain the plaintext.
	if bytes.Contains(ct, []byte("the well is in")) {
		t.Fatal("plaintext leaked into the shared ciphertext")
	}
	got, err := OpenIssue(notice, ct, pubHex, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch: %q", got)
	}

	// The notice must survive the wire (it rides a pairwise E2 message).
	wire, err := notice.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := ParseNotice(wire)
	if !ok {
		t.Fatal("ParseNotice rejected our own notice")
	}
	if _, err := OpenIssue(parsed, ct, pubHex, 0); err != nil {
		t.Fatalf("round-tripped notice failed to open: %v", err)
	}
}

// TestSubscriberCannotForgeAnIssue is THE test for this design.
//
// Every subscriber holds the issue key, so a subscriber can encrypt any body
// they like under it. Confidentiality cannot provide authenticity here. Only
// the publisher's signature can, and it must be checked against a PINNED key.
func TestSubscriberCannotForgeAnIssue(t *testing.T) {
	publisher, publisherPub := pubKey(t)
	real := []byte("Meeting is at the north gate.")

	ct, notice, err := SealIssue(publisher, "cell", 1, "", real, cid)
	if err != nil {
		t.Fatal(err)
	}

	// A subscriber legitimately learns the issue key from their notice.
	key, err := hex.DecodeString(notice.Key)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(notice.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}

	// They re-encrypt a FORGED body under that same key, with the same AAD.
	forgedBody := []byte("Meeting is at the SOUTH gate.")
	aad := transcript(notice.Channel, notice.Seq, "", "", 0, "", "")
	forgedCT := aead.Seal(nil, nonce, forgedBody, aad)

	// Attack 1: swap the ciphertext, keep the publisher's signature.
	if _, err := OpenIssue(notice, forgedCT, publisherPub, 0); err == nil {
		t.Fatal("FORGERY ACCEPTED: substituted ciphertext opened with the publisher's signature")
	}

	// Attack 2: also update the notice's hash/size/CID to match the forgery,
	// leaving the signature (which the subscriber cannot recompute) in place.
	sum := sha256.Sum256(forgedBody)
	forgedNotice := *notice
	forgedNotice.PlainSHA256 = hex.EncodeToString(sum[:])
	forgedNotice.PlainSize = int64(len(forgedBody))
	forgedNotice.BodyCID = cid(forgedCT)
	if _, err := OpenIssue(&forgedNotice, forgedCT, publisherPub, 0); err == nil {
		t.Fatal("FORGERY ACCEPTED: subscriber rewrote the notice and it verified")
	}

	// Attack 3: the subscriber signs the forgery with their OWN key. It is a
	// perfectly valid signature — just not the pinned publisher's.
	subscriber, _ := pubKey(t)
	selfSigned := forgedNotice
	selfSigned.PublisherPub = hex.EncodeToString(subscriber.Public().(ed25519.PublicKey))
	tr := transcript(selfSigned.Channel, selfSigned.Seq, selfSigned.BodyCID,
		selfSigned.PlainSHA256, selfSigned.PlainSize, selfSigned.Title, selfSigned.PublisherPub)
	selfSigned.Sig = hex.EncodeToString(ed25519.Sign(subscriber, tr))
	_, err = OpenIssue(&selfSigned, forgedCT, publisherPub, 0)
	if err == nil {
		t.Fatal("FORGERY ACCEPTED: a subscriber-signed issue passed as the publisher's")
	}
	if !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("error should name the pinning failure, got: %v", err)
	}

	// And the real issue must still open, so the checks are not just refusing
	// everything.
	if _, err := OpenIssue(notice, ct, publisherPub, 0); err != nil {
		t.Fatalf("genuine issue rejected: %v", err)
	}
}

func TestPinnedPublisherRequired(t *testing.T) {
	priv, _ := pubKey(t)
	ct, notice, err := SealIssue(priv, "ch", 1, "", []byte("hello"), cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenIssue(notice, ct, "", 0); err == nil {
		t.Fatal("OpenIssue accepted an issue with no pinned publisher key")
	}
	// A different publisher's key must be refused.
	_, otherPub := pubKey(t)
	if _, err := OpenIssue(notice, ct, otherPub, 0); err == nil {
		t.Fatal("OpenIssue accepted an issue signed by a different key")
	}
}

// TestReplayedIssueRejected: a relay that re-delivers issue 3 after issue 7
// must not be able to pass it off as current.
func TestReplayedIssueRejected(t *testing.T) {
	priv, pubHex := pubKey(t)
	ct3, n3, err := SealIssue(priv, "ch", 3, "", []byte("old news"), cid)
	if err != nil {
		t.Fatal(err)
	}
	// Subscriber has already accepted issue 7.
	if _, err := OpenIssue(n3, ct3, pubHex, 7); err == nil {
		t.Fatal("replayed older issue accepted")
	}
	// Same seq is also not an advance.
	if _, err := OpenIssue(n3, ct3, pubHex, 3); err == nil {
		t.Fatal("re-delivery of the current issue accepted as new")
	}
	// But a genuinely newer issue is fine.
	ct8, n8, err := SealIssue(priv, "ch", 8, "", []byte("new news"), cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenIssue(n8, ct8, pubHex, 7); err != nil {
		t.Fatalf("advancing issue rejected: %v", err)
	}
}

// TestCiphertextCannotBeLiftedBetweenIssues: the AAD binds channel+seq, so an
// issue body cannot be replayed into a different slot even with its key.
func TestCiphertextCannotBeLiftedBetweenIssues(t *testing.T) {
	priv, pubHex := pubKey(t)
	ct, n1, err := SealIssue(priv, "chA", 1, "", []byte("channel A secret"), cid)
	if err != nil {
		t.Fatal(err)
	}
	// Re-label the notice as a different channel/seq, re-signing correctly as
	// the publisher (worst case: the publisher's own key is doing this).
	moved := *n1
	moved.Channel = "chB"
	moved.Seq = 1
	tr := transcript(moved.Channel, moved.Seq, moved.BodyCID, moved.PlainSHA256, moved.PlainSize, moved.Title, moved.PublisherPub)
	moved.Sig = hex.EncodeToString(ed25519.Sign(priv, tr))
	if _, err := OpenIssue(&moved, ct, pubHex, 0); err == nil {
		t.Fatal("ciphertext opened under a different channel — AAD is not binding")
	}
}

func TestTamperedNoticeFieldsRejected(t *testing.T) {
	priv, pubHex := pubKey(t)
	ct, base, err := SealIssue(priv, "ch", 5, "Title", []byte("payload"), cid)
	if err != nil {
		t.Fatal(err)
	}
	muts := map[string]func(*Notice){
		"title rewritten":   func(n *Notice) { n.Title = "Different Title" },
		"seq bumped":        func(n *Notice) { n.Seq = 6 },
		"cid swapped":       func(n *Notice) { n.BodyCID = cid([]byte("other")) },
		"size inflated":     func(n *Notice) { n.PlainSize = 9999 },
		"hash swapped":      func(n *Notice) { n.PlainSHA256 = cid([]byte("other")) },
		"channel rewritten": func(n *Notice) { n.Channel = "elsewhere" },
		"domain downgraded": func(n *Notice) { n.Domain = "spore/broadcast/v0" },
	}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			cp := *base
			mut(&cp)
			if _, err := OpenIssue(&cp, ct, pubHex, 0); err == nil {
				t.Fatalf("tampered notice (%s) accepted — field is not covered by the signature", name)
			}
		})
	}
}

func TestSealIssueRejectsBadInput(t *testing.T) {
	priv, _ := pubKey(t)
	if _, _, err := SealIssue(priv, "", 1, "", []byte("x"), cid); err == nil {
		t.Fatal("empty channel accepted")
	}
	if _, _, err := SealIssue(priv, "ch", 0, "", []byte("x"), cid); err == nil {
		t.Fatal("seq 0 accepted (0 means 'no issue seen' for subscribers)")
	}
	if _, _, err := SealIssue(priv, "ch", 1, "", []byte("x"), nil); err == nil {
		t.Fatal("nil bodyCIDFn accepted")
	}
}

// TestEveryIssueUsesAFreshKey: keys must never be chained or reused, so
// compromising one issue key reveals exactly one issue.
func TestEveryIssueUsesAFreshKey(t *testing.T) {
	priv, _ := pubKey(t)
	seen := map[string]bool{}
	for seq := uint64(1); seq <= 25; seq++ {
		_, n, err := SealIssue(priv, "ch", seq, "", []byte("same body every time"), cid)
		if err != nil {
			t.Fatal(err)
		}
		if seen[n.Key] {
			t.Fatalf("issue key reused at seq %d", seq)
		}
		seen[n.Key] = true
		if seen[n.Nonce] {
			t.Fatalf("nonce reused at seq %d", seq)
		}
		seen[n.Nonce] = true
	}
}

// TestIdenticalBodiesProduceDifferentCiphertext: publishing the same text twice
// must not be detectable by comparing stored objects.
func TestIdenticalBodiesProduceDifferentCiphertext(t *testing.T) {
	priv, _ := pubKey(t)
	body := []byte("identical content")
	ct1, _, err := SealIssue(priv, "ch", 1, "", body, cid)
	if err != nil {
		t.Fatal(err)
	}
	ct2, _, err := SealIssue(priv, "ch", 2, "", body, cid)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("identical plaintexts produced identical ciphertext — issues are linkable by content")
	}
}

func TestParseNoticeRejectsNonNotices(t *testing.T) {
	for _, b := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"domain":"spore/broadcast/v1"}`), // no channel/sig
		[]byte(`not json`),
		[]byte(`{"domain":"other","channel":"c","sig":"00"}`),
		[]byte(`{"inReplyTo":"x","status":"read"}`), // a receipt, not a notice
	} {
		if _, ok := ParseNotice(b); ok {
			t.Fatalf("ParseNotice accepted %q", b)
		}
	}
}

// TestFanoutCostIsRealArithmetic pins the claimed saving to actual numbers.
func TestFanoutCostIsRealArithmetic(t *testing.T) {
	const body = 200 * 1000 // 200 KB issue
	const notice = 400      // generous notice size
	sk, pw := FanoutCost(body, notice, 10_000)
	if pw <= sk {
		t.Fatalf("pairwise (%d) should dwarf sender-key (%d)", pw, sk)
	}
	ratio := pw / sk
	if ratio < 100 {
		t.Fatalf("sender-key saving at 10k subscribers is only %dx; expected >100x", ratio)
	}
	t.Logf("10k subscribers, 200 KB issue: sender-key %d bytes vs pairwise %d bytes (%dx cheaper)", sk, pw, ratio)
}
