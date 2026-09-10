package secure

// Wire-spec vector generation. Run with:
//
//	go test ./internal/secure/ -run TestGenerateWireSpecVectors -v
//
// and commit the printed JSON as docs/interop-vectors.json. The vectors are
// fully deterministic: fixed X25519 scalars, fixed ephemeral scalar, fixed
// nonce, deterministic Ed25519 seed derivation. See docs/WIRE_SPEC.md.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/whisper"
)

func h(b []byte) string     { return hex.EncodeToString(b) }
func h32(b [32]byte) string { return hex.EncodeToString(b[:]) }

// sporePeerFrameVectors builds authoritative frame vectors: frame = LE32(len)
// + payload; payload_ok = 0x00 + body; payload_err = 0x01 + ascii error. The
// body deliberately starts with ASCII '4' — the byte that broke the old
// client (audit H4).
func sporePeerFrameVectors() map[string]string {
	body := []byte{0x34, 0x34, 0x34, 0x34, 0xAB, 0xCD}
	errText := []byte("404 not found")
	okPayload := append([]byte{0x00}, body...)
	errPayload := append([]byte{0x01}, errText...)
	frame := func(p []byte) string {
		out := make([]byte, 4, 4+len(p))
		l := uint32(len(p))
		out[0], out[1], out[2], out[3] = byte(l), byte(l>>8), byte(l>>16), byte(l>>24)
		out = append(out, p...)
		return h(out)
	}
	return map[string]string{
		"body_hex":           h(body),
		"expected_ok_frame":  frame(okPayload),
		"expected_err_text":  string(errText),
		"expected_err_frame": frame(errPayload),
	}
}

func TestGenerateWireSpecVectors(t *testing.T) {
	// --- fixed identities (from RFC-representative test scalars) ---
	alicePriv := sha256.Sum256([]byte("spore-vector-alice-x25519"))
	bobPriv := sha256.Sum256([]byte("spore-vector-bob-x25519"))
	ephPriv := sha256.Sum256([]byte("spore-vector-eph-x25519"))
	nonceSum := sha256.Sum256([]byte("spore-vector-nonce"))
	nonce := nonceSum[:NonceLen]

	alicePub, _ := PubKeyOf(alicePriv[:])
	bobPub, _ := PubKeyOf(bobPriv[:])
	ephPub, _ := PubKeyOf(ephPriv[:])
	aliceSig, _ := SigPubOf(alicePriv[:])

	secret, err := crypto.SharedSecret(ephPriv[:], bobPub)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.DeriveKeyBound(secret, ephPub, bobPub)
	if err != nil {
		t.Fatal(err)
	}

	// --- canonical vectors ---
	text := "meet me at the garden gate"
	textPayload := whisper.EncodeTextCanonical(text)
	var vEph, vCID [32]byte
	copy(vEph[:], ephPub)
	bodySum := sha256.Sum256([]byte("spore-vector-body"))
	copy(vCID[:], bodySum[:])
	pointerPayload := whisper.EncodePointerCanonical(vEph, vCID)

	// --- envelope vector: text ---
	textEnv, err := EncryptDeterministic(ephPriv[:], nonce, alicePriv[:], bobPub, textPayload)
	if err != nil {
		t.Fatal(err)
	}
	// --- envelope vector: pointer ---
	ptrEnv, err := EncryptDeterministic(ephPriv[:], nonce, alicePriv[:], bobPub, pointerPayload)
	if err != nil {
		t.Fatal(err)
	}

	// Independent reference computation of the text-envelope ciphertext, for
	// implementers who want to verify each stage:
	ctRef, err := crypto.Seal(textPayload, key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	doc := map[string]interface{}{
		"_comment": "Golden interop vectors for the Spore wire formats. Source of truth: docs/WIRE_SPEC.md. Regenerate: go test ./internal/secure/ -run TestGenerateWireSpecVectors.",
		"fixed_scalars": map[string]string{
			"alice_x25519_priv": h32(alicePriv),
			"bob_x25519_priv":   h32(bobPriv),
			"eph_x25519_priv":   h32(ephPriv),
			"nonce_24":          h(nonce),
		},
		"derived_keys": map[string]string{
			"alice_x25519_pub": h(alicePub),
			"bob_x25519_pub":   h(bobPub),
			"eph_x25519_pub":   h(ephPub),
			"alice_sig_pub":    h(aliceSig),
			"aead_key":         h(key),
		},
		"canonical": map[string]string{
			"encode_text_input":       text,
			"encode_text_hex":         h(textPayload),
			"encode_pointer_eph_pub":  h32(vEph),
			"encode_pointer_body_cid": h32(vCID),
			"encode_pointer_hex":      h(pointerPayload),
		},
		"envelope_v2_text": map[string]string{
			"recipient_x25519_pub": h(bobPub),
			"sender_x25519_priv":   h32(alicePriv),
			"eph_x25519_priv":      h32(ephPriv),
			"nonce":                h(nonce),
			"inner_canonical_hex":  h(textPayload),
			"ciphertext_hex":       h(ctRef),
			"expected_payload_hex": h(textEnv),
		},
		"envelope_v2_pointer": map[string]string{
			"expected_payload_hex": h(ptrEnv),
		}, // spore-peer transport frame (4-byte LE length + status-prefixed
		// payload) — cross-implementation Go<->Rust. Frames computed, not
		// hardcoded, so the length prefixes are authoritative.
		"spore_peer_frame": sporePeerFrameVectors(),
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	t.Logf("vectors:\n%s", out)
	_ = os.WriteFile("../../docs/interop-vectors.json", out, 0o644)
}
