package paylock

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"golang.org/x/crypto/sha3"
)

func newKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubHex(k *btcec.PrivateKey) string {
	return hex.EncodeToString(k.PubKey().SerializeCompressed())
}

func issueKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// TestPayerWalletUnwrapsWithoutAnyHandshake is the product claim: the payer
// never registered, never sent a prekey, never had a spore identity. Their
// wallet key alone opens the issue key.
func TestPayerWalletUnwrapsWithoutAnyHandshake(t *testing.T) {
	publisher := newKey(t)
	wallet := newKey(t) // the subscriber's ETH/BTC wallet

	key := issueKey(t)
	w, err := WrapForPayer(publisher, pubHex(wallet), "offgrid", 7, key, "0xtxhash", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	got, err := w.UnwrapWithWallet(wallet, pubHex(publisher))
	if err != nil {
		t.Fatalf("payer could not unwrap with their own wallet: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("unwrapped key does not match the issue key")
	}
}

// TestRecoveredPubkeyFromSignatureMatches proves the core mechanism: a
// signature yields the signer's public key, which is what lets a publisher
// wrap to a payer they have never talked to.
func TestRecoveredPubkeyFromSignatureMatches(t *testing.T) {
	wallet := newKey(t)
	msg := sha3.Sum256([]byte("pay 0.01 ETH for offgrid issue 7"))

	// Produce a recoverable signature the way a wallet does.
	compact := btcecdsa.SignCompact(wallet, msg[:], true)
	// btcec emits [V||R||S]; convert to Ethereum's [R||S||V] to prove the
	// normalisation path in RecoverPayerPubkey works on real wallet output.
	eth := make([]byte, 65)
	copy(eth, compact[1:])
	eth[64] = (compact[0] - 27) & 3

	recovered, err := RecoverPayerPubkey(msg[:], eth)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != pubHex(wallet) {
		t.Fatalf("recovered %s, want %s", recovered, pubHex(wallet))
	}
}

// TestRecoverAcceptsBothVEncodings: wallets differ on whether V is 0/1 or
// 27/28. Both must work, or half of real signatures fail.
func TestRecoverAcceptsBothVEncodings(t *testing.T) {
	wallet := newKey(t)
	msg := sha3.Sum256([]byte("v encoding"))
	compact := btcecdsa.SignCompact(wallet, msg[:], true)
	rs := compact[1:]
	vRaw := (compact[0] - 27) & 3 // the recovery bit: 0 or 1

	for _, v := range []byte{vRaw, vRaw + 27} {
		sig := make([]byte, 65)
		copy(sig, rs)
		sig[64] = v
		got, err := RecoverPayerPubkey(msg[:], sig)
		if err != nil {
			t.Fatalf("V=%d rejected: %v", v, err)
		}
		if got != pubHex(wallet) {
			t.Fatalf("V=%d recovered the wrong key", v)
		}
	}
}

// TestRecoverHandlesBtcecCompressedV feeds the RAW btcec compact V (31/32,
// where +4 means "compressed pubkey") straight through, WITHOUT the test
// pre-masking it.
//
// This exists because an earlier version of TestRecoverAcceptsBothVEncodings
// masked the V itself before calling, so deleting the masking logic inside
// RecoverPayerPubkey left every test passing — verified by mutation. A wrong
// recovery id is not a benign error: it recovers a DIFFERENT valid public key,
// so the publisher would wrap the issue key to a wallet nobody controls.
func TestRecoverHandlesBtcecCompressedV(t *testing.T) {
	wallet := newKey(t)
	msg := sha3.Sum256([]byte("raw btcec compact V"))
	compact := btcecdsa.SignCompact(wallet, msg[:], true)

	rawV := compact[0]
	if rawV < 31 {
		t.Skipf("expected a compressed-flag V (31/32), got %d", rawV)
	}
	sig := make([]byte, 65)
	copy(sig, compact[1:])
	sig[64] = rawV // unmasked, exactly as btcec produced it

	got, err := RecoverPayerPubkey(msg[:], sig)
	if err != nil {
		t.Fatalf("raw btcec V=%d rejected: %v", rawV, err)
	}
	if got != pubHex(wallet) {
		t.Fatalf("raw btcec V=%d recovered %s, want %s", rawV, got, pubHex(wallet))
	}
}

// TestPayerTargetingGivesAClearErrorNotAnAEADFailure documents what the
// explicit PayerPub check does and does NOT do.
//
// It is NOT a cryptographic control: PayerPub is inside the KEK's KDF info, so
// a wrong wallet already fails the AEAD. Mutation testing proved this —
// deleting the check leaves every security property intact and the whole suite
// green, because confidentiality never depended on it.
//
// Its real value is DIAGNOSTIC: "this key is wrapped for payer X, not for your
// wallet Y" tells a subscriber they used the wrong wallet, where a bare AEAD
// failure would send them hunting a corruption bug. So the property under test
// is the ERROR MESSAGE, and it is labelled as such rather than dressed up as
// an access control.
func TestPayerTargetingGivesAClearErrorNotAnAEADFailure(t *testing.T) {
	publisher := newKey(t)
	payer := newKey(t)
	wrongWallet := newKey(t)
	key := issueKey(t)

	w, err := WrapForPayer(publisher, pubHex(payer), "ch", 1, key, "", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.UnwrapWithWallet(wrongWallet, pubHex(publisher))
	if err == nil {
		t.Fatal("the wrong wallet unwrapped the issue key")
	}
	// The diagnostic must name the wallet mismatch, not just "unwrap failed".
	if !strings.Contains(err.Error(), "wrapped for payer") {
		t.Fatalf("expected a wallet-mismatch diagnostic, got: %v", err)
	}
}

// TestRecoverRejectsMalformedInput
func TestRecoverRejectsMalformedInput(t *testing.T) {
	msg := sha3.Sum256([]byte("x"))
	if _, err := RecoverPayerPubkey(msg[:31], make([]byte, 65)); err == nil {
		t.Fatal("accepted a short message hash")
	}
	if _, err := RecoverPayerPubkey(msg[:], make([]byte, 64)); err == nil {
		t.Fatal("accepted a 64-byte signature")
	}
	bad := make([]byte, 65)
	bad[64] = 99
	if _, err := RecoverPayerPubkey(msg[:], bad); err == nil {
		t.Fatal("accepted an out-of-range recovery id")
	}
}

// TestOtherWalletsCannotUnwrap is the paywall: paying does not let you share
// access, and not paying gets you nothing.
func TestOtherWalletsCannotUnwrap(t *testing.T) {
	publisher := newKey(t)
	payer := newKey(t)
	freeloader := newKey(t)

	key := issueKey(t)
	w, err := WrapForPayer(publisher, pubHex(payer), "ch", 1, key, "", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.UnwrapWithWallet(freeloader, pubHex(publisher)); err == nil {
		t.Fatal("a wallet that did not pay unwrapped the issue key")
	}
	// Even the publisher's own key must not unwrap it via this path: the wrap
	// is addressed to the payer, and silently accepting anything else would
	// hide a targeting bug.
	if _, err := w.UnwrapWithWallet(publisher, pubHex(publisher)); err == nil {
		t.Fatal("wrap opened by a key it was not addressed to")
	}
}

// TestWrapIsBoundToTheIssue: a wrap for issue 5 must not open issue 6, or one
// payment would buy the whole archive.
func TestWrapIsBoundToTheIssue(t *testing.T) {
	publisher := newKey(t)
	payer := newKey(t)
	key5 := issueKey(t)

	w5, err := WrapForPayer(publisher, pubHex(payer), "ch", 5, key5, "", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Relabel the wrap as issue 6 and channel "other".
	for _, mutate := range []func(*WrappedKey){
		func(w *WrappedKey) { w.Seq = 6 },
		func(w *WrappedKey) { w.Channel = "other" },
	} {
		cp := *w5
		mutate(&cp)
		if _, err := cp.UnwrapWithWallet(payer, pubHex(publisher)); err == nil {
			t.Fatal("a relabelled wrap unwrapped: channel/seq are not bound into the KDF")
		}
	}
}

// TestUnwrapRequiresPinnedPublisher: without pinning, a stranger can wrap a
// key to your wallet and you would trust content you never paid for.
func TestUnwrapRequiresPinnedPublisher(t *testing.T) {
	real := newKey(t)
	impostor := newKey(t)
	payer := newKey(t)
	key := issueKey(t)

	// The impostor wraps to the payer's wallet — perfectly valid crypto.
	w, err := WrapForPayer(impostor, pubHex(payer), "ch", 1, key, "", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// It opens if you pin the impostor (their crypto is fine)...
	if _, err := w.UnwrapWithWallet(payer, pubHex(impostor)); err != nil {
		t.Fatalf("impostor's own wrap should be self-consistent: %v", err)
	}
	// ...but must fail when you require the publisher you actually paid.
	if _, err := w.UnwrapWithWallet(payer, pubHex(real)); err == nil {
		t.Fatal("a wrap from an impostor passed a pinned-publisher check")
	}
	// And an empty expectation must be refused outright.
	if _, err := w.UnwrapWithWallet(payer, ""); err == nil {
		t.Fatal("unwrap proceeded with no expected publisher key")
	}
}

func TestTamperedWrapRejected(t *testing.T) {
	publisher := newKey(t)
	payer := newKey(t)
	key := issueKey(t)
	base, err := WrapForPayer(publisher, pubHex(payer), "ch", 3, key, "ref", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	muts := map[string]func(*WrappedKey){
		"ciphertext flipped": func(w *WrappedKey) {
			b, _ := hex.DecodeString(w.Ct)
			b[0] ^= 0xff
			w.Ct = hex.EncodeToString(b)
		},
		"nonce flipped": func(w *WrappedKey) {
			b, _ := hex.DecodeString(w.Nonce)
			b[0] ^= 0xff
			w.Nonce = hex.EncodeToString(b)
		},
		"domain downgraded": func(w *WrappedKey) { w.Domain = "spore/paylock/v0" },
	}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			cp := *base
			mut(&cp)
			if _, err := cp.UnwrapWithWallet(payer, pubHex(publisher)); err == nil {
				t.Fatalf("tampered wrap (%s) unwrapped", name)
			}
		})
	}
}

// TestPaymentRefIsNotTrusted: the recorded tx hash is convenience metadata.
// Editing it must not affect whether the key unwraps, so nobody mistakes it
// for an access-control check.
func TestPaymentRefIsNotTrusted(t *testing.T) {
	publisher := newKey(t)
	payer := newKey(t)
	key := issueKey(t)
	w, err := WrapForPayer(publisher, pubHex(payer), "ch", 1, key, "0xreal", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w.PaymentRef = "0xtotally-made-up"
	got, err := w.UnwrapWithWallet(payer, pubHex(publisher))
	if err != nil {
		t.Fatalf("payment_ref must not gate decryption: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("key mismatch")
	}
}

func TestWrapValidatesInput(t *testing.T) {
	publisher := newKey(t)
	payer := newKey(t)
	good := issueKey(t)

	if _, err := WrapForPayer(nil, pubHex(payer), "ch", 1, good, "", rand.Reader); err == nil {
		t.Fatal("nil publisher key accepted")
	}
	if _, err := WrapForPayer(publisher, pubHex(payer), "", 1, good, "", rand.Reader); err == nil {
		t.Fatal("empty channel accepted")
	}
	if _, err := WrapForPayer(publisher, pubHex(payer), "ch", 0, good, "", rand.Reader); err == nil {
		t.Fatal("seq 0 accepted")
	}
	if _, err := WrapForPayer(publisher, pubHex(payer), "ch", 1, good[:16], "", rand.Reader); err == nil {
		t.Fatal("short issue key accepted")
	}
	if _, err := WrapForPayer(publisher, "not-hex", "ch", 1, good, "", rand.Reader); err == nil {
		t.Fatal("malformed payer pubkey accepted")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	publisher := newKey(t)
	payer := newKey(t)
	key := issueKey(t)
	w, err := WrapForPayer(publisher, pubHex(payer), "ch", 2, key, "0xabc", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := w.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// A wrapped key is safe to publish, so it must not contain the plaintext.
	if bytes.Contains(blob, key) {
		t.Fatal("wrapped key JSON contains the raw issue key")
	}
	parsed, err := ParseWrappedKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsed.UnwrapWithWallet(payer, pubHex(publisher))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("round-tripped wrap did not unwrap")
	}
	if _, err := ParseWrappedKey([]byte(`{"domain":"other"}`)); err == nil {
		t.Fatal("ParseWrappedKey accepted a foreign domain")
	}
}

// TestEthAddressOfKnownVector checks address derivation against a published
// Ethereum test vector, so "matches MetaMask" is verified, not assumed.
//
// Vector: private key 0x4646...1e46 (the classic EIP-155 example key) has
// address 0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f.
func TestEthAddressOfKnownVector(t *testing.T) {
	kb, err := hex.DecodeString("4646464646464646464646464646464646464646464646464646464646464646")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := btcec.PrivKeyFromBytes(kb)

	keccak := func(b []byte) []byte {
		h := sha3.NewLegacyKeccak256()
		h.Write(b)
		return h.Sum(nil)
	}
	addr, err := EthAddressOf(pubHex(priv), keccak)
	if err != nil {
		t.Fatal(err)
	}
	const want = "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
	if addr != want {
		t.Fatalf("EthAddressOf = %s, want %s (address derivation does NOT match Ethereum)", addr, want)
	}
}

func TestEthAddressOfRequiresKeccak(t *testing.T) {
	k := newKey(t)
	if _, err := EthAddressOf(pubHex(k), nil); err == nil {
		t.Fatal("EthAddressOf accepted a nil hash function (SHA3 != Keccak; silently using the wrong one yields wrong addresses)")
	}
}

// TestSharedSecretIsSymmetric: publisher-side and wallet-side derivation must
// agree, which is the whole reason no round trip is needed.
func TestSharedSecretIsSymmetric(t *testing.T) {
	a, b := newKey(t), newKey(t)
	s1 := sharedSecret(a, b.PubKey())
	s2 := sharedSecret(b, a.PubKey())
	if !bytes.Equal(s1, s2) {
		t.Fatal("ECDH is not symmetric — the payer could never derive the publisher's key")
	}
	// And it must not be the raw X coordinate (which is not a uniform key).
	var pt btcec.JacobianPoint
	b.PubKey().AsJacobian(&pt)
	var out btcec.JacobianPoint
	btcec.ScalarMultNonConst(&a.Key, &pt, &out)
	out.ToAffine()
	rawX := out.X.Bytes()
	if bytes.Equal(s1, rawX[:]) {
		t.Fatal("shared secret is the raw X coordinate, not a hashed KDF output")
	}
}

// TestEveryIssueGetsADistinctKEK: without this, one leaked issue key would
// expose every issue wrapped to the same wallet.
func TestEveryIssueGetsADistinctKEK(t *testing.T) {
	publisher := newKey(t)
	payer := newKey(t)
	secret := sharedSecret(publisher, payer.PubKey())

	seen := map[string]bool{}
	for seq := uint64(1); seq <= 20; seq++ {
		k, err := kek(secret, "ch", seq, pubHex(payer), pubHex(publisher))
		if err != nil {
			t.Fatal(err)
		}
		h := hex.EncodeToString(k)
		if seen[h] {
			t.Fatalf("KEK reused at seq %d", seq)
		}
		seen[h] = true
	}
	// Different channels must also differ at the same seq.
	k1, _ := kek(secret, "chA", 1, pubHex(payer), pubHex(publisher))
	k2, _ := kek(secret, "chB", 1, pubHex(payer), pubHex(publisher))
	if bytes.Equal(k1, k2) {
		t.Fatal("channel is not bound into the KEK")
	}
}
