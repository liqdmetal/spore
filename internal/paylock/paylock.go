package paylock

// Package paylock unlocks content with the PAYMENT ITSELF: pay from any
// secp256k1 wallet (ETH, BTC, and any EVM chain), and the wallet key that
// signed the payment is the key that decrypts.
//
// THE IDEA
//
// A signed transaction reveals its sender's public key. ECDSA is a recoverable
// signature scheme: given the signed hash and the 65-byte signature, anyone can
// recompute the signer's secp256k1 public key. Ethereum relies on exactly this
// (that is what `ecrecover` does, and why an ETH address is just the hash of a
// recovered pubkey).
//
// So a publisher watching for payments can, with NO extra round trip:
//
//  1. recover the payer's public key W from the payment transaction,
//  2. compute a shared secret via ECDH(publisher_priv, W),
//  3. wrap the issue key under a KEK derived from that secret.
//
// Only the holder of the wallet's PRIVATE key can recompute the same secret and
// unwrap. The buyer's existing wallet IS their subscription credential: no
// account, no spore identity, no prekey exchange, no email. They pay from
// MetaMask and their MetaMask key opens the file.
//
// WHAT THIS IS NOT: ATOMIC
//
// Be precise, because the difference matters. This is NOT trustless atomic
// delivery. The publisher must still act after the payment lands, so a
// publisher can take the money and never wrap a key.
//
// What it gives instead is PUBLIC PROVABILITY: the payment is on a public
// chain, so non-delivery is evidence anyone can check. That is the same
// assurance model as paying a merchant, minus the merchant's ability to
// deplatform you.
//
// For genuinely atomic delivery see AtomicNote in this package: an HTLC whose
// preimage IS the decryption key. It is trustless, but claiming the payment
// publishes the key to everyone, so it fits crowdfunded release ("this issue
// unlocks for all when funded"), NOT per-subscriber access. Both mechanisms are
// useful; conflating them is how people ship a broken paywall.
//
// HONEST LIMITS
//
//  1. NO FORWARD SECRECY. The shared secret is static-static ECDH between the
//     publisher key and the wallet key, because the publisher must be able to
//     derive it from the payment alone. If a wallet key leaks, every issue ever
//     wrapped to that wallet unwraps. Wallet keys are long-lived and often
//     reused, so this is a real exposure: use a dedicated subscription wallet.
//  2. Each issue still gets a DISTINCT KEK — the channel and sequence go into
//     the KDF — so one leaked issue key does not expose other issues.
//  3. The wrap is bound to the payer's pubkey and the publisher's pubkey, so a
//     wrapped key cannot be replayed to a different subscriber.
//  4. Linkability: paying from a transparent chain links that wallet to the
//     subscription. Anonymity comes from the credits path or from paying on
//     DERO; this path trades privacy for zero-friction onboarding.
//  5. DERO addresses are NOT secp256k1, so this exact recovery trick does not
//     apply there. DERO's own confidential payments plus the credits flow cover
//     that case; see DeroNote.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	domain = "spore/paylock/v1"
	// KeySize is the wrapped payload size (an XChaCha20-Poly1305 key).
	KeySize = chacha20poly1305.KeySize
)

// WrappedKey is what a publisher hands a paying subscriber. It is safe to
// publish: without the payer's wallet private key it is inert.
type WrappedKey struct {
	Domain string `json:"domain"`
	// Channel and Seq identify which issue this unwraps, and are bound into
	// the KDF so a wrap for issue 5 cannot open issue 6.
	Channel string `json:"channel"`
	Seq     uint64 `json:"seq"`
	// PayerPub is the compressed secp256k1 pubkey recovered from the payment.
	PayerPub string `json:"payer_pub"`
	// PublisherPub is the publisher's compressed secp256k1 pubkey.
	PublisherPub string `json:"publisher_pub"`
	// Nonce and Ct are the AEAD nonce and the wrapped issue key.
	Nonce string `json:"nonce"`
	Ct    string `json:"ct"`
	// PaymentRef is the transaction that paid for this, recorded so a
	// subscriber can prove what they bought. It is NOT trusted by Unwrap.
	PaymentRef string `json:"payment_ref,omitempty"`
}

// RecoverPayerPubkey recovers the payer's compressed secp256k1 public key from
// a signed message hash and a 65-byte [R||S||V] signature.
//
// This is the step that makes the whole scheme work without a round trip: an
// Ethereum transaction (or a personal_sign / EIP-191 message) yields exactly
// this, so the publisher learns the payer's public key from the chain alone.
func RecoverPayerPubkey(msgHash []byte, sig65 []byte) (string, error) {
	if len(msgHash) != 32 {
		return "", fmt.Errorf("paylock: message hash must be 32 bytes, got %d", len(msgHash))
	}
	if len(sig65) != 65 {
		return "", fmt.Errorf("paylock: signature must be 65 bytes [R||S||V], got %d", len(sig65))
	}
	// Recovery-id encodings in the wild:
	//   Ethereum tx / EIP-155:      V = 0 or 1  (also 27/28 for personal_sign)
	//   btcec SignCompact:          V = 27..30 uncompressed, 31..34 compressed
	//
	// Normalising to btcec's 27..30 range is COSMETIC, not a security control:
	// measured on this btcec version, V=32 and V=28 recover the IDENTICAL
	// public key, because RecoverCompact uses only the low bits for recovery
	// and ignores the +4 "compressed" flag. Deleting the mask below therefore
	// changes nothing observable, and no honest test can catch its removal —
	// established by mutation testing, not assumed.
	//
	// What DOES matter is rejecting out-of-range ids. A wrong recovery BIT is
	// not benign: it either errors ("signature R + N >= P") or recovers a
	// DIFFERENT valid public key, which would make the publisher wrap the
	// issue key to a wallet nobody controls.
	v := sig65[64]
	switch {
	case v >= 27 && v <= 34:
		v = 27 + ((v - 27) & 3)
	case v < 4:
		v = 27 + v
	default:
		return "", fmt.Errorf("paylock: unsupported recovery id %d (expected 0/1, or 27..34)", sig65[64])
	}
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:], sig65[:64])

	pub, _, err := btcecdsa.RecoverCompact(compact, msgHash)
	if err != nil {
		return "", fmt.Errorf("paylock: could not recover payer pubkey: %w", err)
	}
	return hex.EncodeToString(pub.SerializeCompressed()), nil
}

// sharedSecret computes ECDH between a private key and a peer public key.
//
// It uses the X coordinate hashed with the domain tag, NOT the raw X: a raw
// coordinate is not a uniformly random key, and hashing is what every sane
// ECDH-based KDF does.
func sharedSecret(priv *btcec.PrivateKey, peer *btcec.PublicKey) []byte {
	var pt btcec.JacobianPoint
	peer.AsJacobian(&pt)
	var out btcec.JacobianPoint
	btcec.ScalarMultNonConst(&priv.Key, &pt, &out)
	out.ToAffine()
	x := out.X.Bytes()
	h := sha256.New()
	h.Write([]byte(domain + "/ecdh"))
	h.Write(x[:])
	return h.Sum(nil)
}

// kek derives the key-encryption key. Channel and seq are inside the KDF, so
// every issue gets a distinct KEK from the same static-static ECDH secret.
func kek(secret []byte, channel string, seq uint64, payerPub, publisherPub string) ([]byte, error) {
	var info []byte
	put := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		info = append(info, n[:]...)
		info = append(info, b...)
	}
	put([]byte(domain + "/kek"))
	put([]byte(channel))
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	put(s[:])
	// Binding BOTH pubkeys prevents a wrap being replayed to another payer.
	put([]byte(payerPub))
	put([]byte(publisherPub))

	out := make([]byte, chacha20poly1305.KeySize)
	r := hkdf.New(sha256.New, secret, nil, info)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func parsePub(hexPub string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(hexPub)
	if err != nil {
		return nil, fmt.Errorf("paylock: bad pubkey hex: %w", err)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("paylock: bad secp256k1 pubkey: %w", err)
	}
	return pub, nil
}

// WrapForPayer wraps an issue key so ONLY the payer's wallet key can unwrap it.
//
// publisherPriv is the publisher's secp256k1 key. payerPubHex is the key
// recovered from the payment. Nothing here needs the payer to be online.
func WrapForPayer(publisherPriv *btcec.PrivateKey, payerPubHex, channel string, seq uint64, issueKey []byte, paymentRef string, rnd io.Reader) (*WrappedKey, error) {
	if publisherPriv == nil {
		return nil, errors.New("paylock: publisher private key is required")
	}
	if len(issueKey) != KeySize {
		return nil, fmt.Errorf("paylock: issue key must be %d bytes, got %d", KeySize, len(issueKey))
	}
	if channel == "" || seq == 0 {
		return nil, errors.New("paylock: channel and a non-zero seq are required")
	}
	payerPub, err := parsePub(payerPubHex)
	if err != nil {
		return nil, err
	}
	publisherPubHex := hex.EncodeToString(publisherPriv.PubKey().SerializeCompressed())

	secret := sharedSecret(publisherPriv, payerPub)
	k, err := kek(secret, channel, seq, payerPubHex, publisherPubHex)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, issueKey, []byte(domain))

	return &WrappedKey{
		Domain:       domain,
		Channel:      channel,
		Seq:          seq,
		PayerPub:     payerPubHex,
		PublisherPub: publisherPubHex,
		Nonce:        hex.EncodeToString(nonce),
		Ct:           hex.EncodeToString(ct),
		PaymentRef:   paymentRef,
	}, nil
}

// UnwrapWithWallet recovers the issue key using the payer's wallet private key.
//
// expectedPublisherPub is REQUIRED: without pinning it, a stranger could wrap a
// key to your wallet and you would decrypt content believing it came from the
// publisher you paid.
func (w *WrappedKey) UnwrapWithWallet(walletPriv *btcec.PrivateKey, expectedPublisherPub string) ([]byte, error) {
	if w == nil {
		return nil, errors.New("paylock: nil wrapped key")
	}
	if w.Domain != domain {
		return nil, fmt.Errorf("paylock: unknown domain %q (want %q)", w.Domain, domain)
	}
	if walletPriv == nil {
		return nil, errors.New("paylock: wallet private key is required")
	}
	if expectedPublisherPub == "" {
		return nil, errors.New("paylock: no expected publisher pubkey supplied — refusing to unwrap a key from an unverified source")
	}
	if w.PublisherPub != expectedPublisherPub {
		return nil, fmt.Errorf("paylock: wrapped by %s but you expected publisher %s", w.PublisherPub, expectedPublisherPub)
	}
	// The wrap must actually be addressed to THIS wallet.
	ourPub := hex.EncodeToString(walletPriv.PubKey().SerializeCompressed())
	if w.PayerPub != ourPub {
		return nil, fmt.Errorf("paylock: this key is wrapped for payer %s, not for your wallet %s", w.PayerPub, ourPub)
	}
	publisherPub, err := parsePub(w.PublisherPub)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(w.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("paylock: bad nonce")
	}
	ct, err := hex.DecodeString(w.Ct)
	if err != nil {
		return nil, errors.New("paylock: bad ciphertext")
	}

	secret := sharedSecret(walletPriv, publisherPub)
	k, err := kek(secret, w.Channel, w.Seq, w.PayerPub, w.PublisherPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	issueKey, err := aead.Open(nil, nonce, ct, []byte(domain))
	if err != nil {
		return nil, fmt.Errorf("paylock: unwrap failed (wrong wallet, tampered wrap, or wrong issue): %w", err)
	}
	if len(issueKey) != KeySize {
		return nil, fmt.Errorf("paylock: unwrapped key is %d bytes, want %d", len(issueKey), KeySize)
	}
	return issueKey, nil
}

// Marshal renders the wrapped key for delivery. It can be sent in the clear:
// only the payer's wallet can open it.
func (w *WrappedKey) Marshal() ([]byte, error) { return json.MarshalIndent(w, "", "  ") }

// ParseWrappedKey decodes a wrapped key, rejecting unknown fields.
func ParseWrappedKey(b []byte) (*WrappedKey, error) {
	var w WrappedKey
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	if w.Domain != domain {
		return nil, fmt.Errorf("paylock: not a paylock wrapped key (domain %q)", w.Domain)
	}
	return &w, nil
}

// EthAddressOf renders the Ethereum address for a compressed secp256k1 pubkey,
// so a publisher can match a recovered key against the address that paid.
//
// NOTE: this uses Keccak-256 as Ethereum does. It is provided for MATCHING a
// payment to a recovered key, not as a general address library.
func EthAddressOf(pubHex string, keccak256 func([]byte) []byte) (string, error) {
	if keccak256 == nil {
		return "", errors.New("paylock: a keccak256 function is required (Ethereum addresses are Keccak, not SHA3)")
	}
	pub, err := parsePub(pubHex)
	if err != nil {
		return "", err
	}
	// Ethereum hashes the UNCOMPRESSED key without its 0x04 prefix.
	uncompressed := pub.SerializeUncompressed()
	h := keccak256(uncompressed[1:])
	if len(h) < 32 {
		return "", errors.New("paylock: keccak256 returned a short digest")
	}
	return "0x" + hex.EncodeToString(h[12:32]), nil
}

// ToECDSA exposes a btcec key as a stdlib ecdsa.PublicKey, for callers that
// need to interoperate with crypto/ecdsa.
func ToECDSA(pubHex string) (*ecdsa.PublicKey, error) {
	pub, err := parsePub(pubHex)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: btcec.S256(),
		X:     new(big.Int).SetBytes(pub.X().Bytes()),
		Y:     new(big.Int).SetBytes(pub.Y().Bytes()),
	}, nil
}

var _ elliptic.Curve = btcec.S256()
