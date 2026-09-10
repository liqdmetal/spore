package invite

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
)

// encodeRaw renders raw JSON as an invite body, so a test can forge one.
func encodeRaw(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

var (
	// A real, on-chain mainnet address (the same one the payload corpus pins).
	mainnetAddr = "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq"
	otherAddr   = "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fZ"
)

func filled(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// fixture builds a signed invite for a synthetic identity.
func fixture(t *testing.T, seed byte, o Options) ([]byte, *Invite) {
	t.Helper()
	identity := filled(seed)
	spk := filled(seed + 1)
	bundle, err := ratchet.BuildBundle(identity, spk, 1, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	o.Bundle = *bundle
	if o.Address == "" {
		o.Address = mainnetAddr
	}
	inv, err := New(identity, o)
	if err != nil {
		t.Fatal(err)
	}
	return identity, inv
}

// TestInviteRoundTrip is the happy path: a signed invite decodes and verifies.
func TestInviteRoundTrip(t *testing.T) {
	_, inv := fixture(t, 0x10, Options{Name: "alice", Note: "beta"})

	encoded, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, Prefix) {
		t.Fatalf("encoded invite lacks the %q prefix: %q", Prefix, encoded)
	}
	if strings.ContainsAny(encoded, "\n\r\t ") {
		t.Fatal("encoded invite is not a single pasteable token")
	}

	got, err := DecodeAndVerify(encoded, time.Now())
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if got.Name != "alice" || got.Address != mainnetAddr || got.Note != "beta" {
		t.Fatalf("fields changed: %#v", got)
	}
	if got.Chain != "dero" {
		t.Fatalf("chain = %q, want dero", got.Chain)
	}
}

// TestTamperedAddressIsRejected is the reason the invite is signed at all.
//
// The bundle's own signature authenticates the BUNDLE, not the address. Without
// a signature over the whole payload, an attacker who noticed an invite could
// swap in their own address and receive every pointer while the bundle still
// verified perfectly. This asserts that edit is caught.
func TestTamperedAddressIsRejected(t *testing.T) {
	_, inv := fixture(t, 0x20, Options{Name: "alice"})

	encoded, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// Swap the address for the attacker's, leaving everything else intact.
	// A valid checksum is used so the failure cannot be blamed on address
	// validation — it must be the SIGNATURE that rejects it.
	tampered := *inv
	tampered.Address = otherAddr
	tamperedBytes, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	forged := Prefix + encodeRaw(tamperedBytes)

	if _, err := DecodeAndVerify(forged, time.Now()); err == nil {
		t.Fatal("a tampered destination address was accepted")
	}
	// And the original must still be fine, proving the test is not just
	// rejecting everything.
	if _, err := DecodeAndVerify(encoded, time.Now()); err != nil {
		t.Fatalf("the untampered invite stopped verifying: %v", err)
	}
}

// TestTamperedFieldsAreRejected walks every field an attacker might edit.
func TestTamperedFieldsAreRejected(t *testing.T) {
	_, inv := fixture(t, 0x30, Options{Name: "alice", Note: "note", PrekeyURL: "https://example.test/prekey"})

	edits := map[string]func(*Invite){
		"name":       func(i *Invite) { i.Name = "mallory" },
		"address":    func(i *Invite) { i.Address = otherAddr },
		"chain":      func(i *Invite) { i.Chain = "evm" },
		"note":       func(i *Invite) { i.Note = "trust me" },
		"prekey_url": func(i *Invite) { i.PrekeyURL = "https://evil.test/prekey" },
		"store_url":  func(i *Invite) { i.StoreURL = "https://evil.test" },
		"issued_at":  func(i *Invite) { i.IssuedAt = "2020-01-01T00:00:00Z" },
		"expires_at": func(i *Invite) { i.ExpiresAt = "2099-01-01T00:00:00Z" },
		"spk_id":     func(i *Invite) { i.Bundle.SPKID = 999 },
		"spk_pub":    func(i *Invite) { i.Bundle.SPKPub = [32]byte{0xee} },
		"opk_id":     func(i *Invite) { i.Bundle.OPKID = 42 },
		"opk_hash":   func(i *Invite) { i.Bundle.OPKHash = [32]byte{0xdd} },
		"version":    func(i *Invite) { i.V = 2 },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			tampered := *inv
			edit(&tampered)
			// Sign field is left as-is: the attacker cannot re-sign.
			raw, err := json.Marshal(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeAndVerify(Prefix+encodeRaw(raw), time.Now()); err == nil {
				t.Fatalf("editing %s was accepted", name)
			}
		})
	}
}

// TestBundleFromAnotherIdentityIsRejected covers the case a naive
// implementation misses: a VALID invite (correctly signed) that carries someone
// else's bundle. The signature must not authenticate a bundle it does not own.
func TestBundleFromAnotherIdentityIsRejected(t *testing.T) {
	_, alice := fixture(t, 0x40, Options{Name: "alice"})
	malloryIdentity := filled(0x99)
	mallorySPK := filled(0x9a)
	malloryBundle, err := ratchet.BuildBundle(malloryIdentity, mallorySPK, 1, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Alice's invite, but carrying Mallory's bundle, and properly re-signed by
	// Alice (i.e. the attacker holds Alice's signing key — the strongest
	// attacker this check can still stop).
	mixed := *alice
	mixed.Bundle = *malloryBundle
	mixed.Sig = ""
	if err := mixed.Sign(filled(0x40)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerify(Prefix+encodeRaw(raw), time.Now()); err == nil {
		t.Fatal("accepted a signed invite carrying a foreign bundle")
	}
}

// TestSignatureFromWrongKeyIsRejected: a forged invite signed by someone who is
// not the advertised pin.
func TestSignatureFromWrongKeyIsRejected(t *testing.T) {
	_, inv := fixture(t, 0x50, Options{Name: "alice"})
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign the same payload with a different identity, leaving the pin.
	forged := *inv
	forged.Sig = ""
	if err := forged.Sign(filled(0x51)); err != nil {
		// Signing refuses because the pin would not match — also acceptable.
		return
	}
	raw, err = json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerify(Prefix+encodeRaw(raw), time.Now()); err == nil {
		t.Fatal("accepted an invite whose signature came from an unpinned key")
	}
}

// TestExpiryIsEnforced.
func TestExpiryIsEnforced(t *testing.T) {
	base := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_, inv := fixture(t, 0x60, Options{Name: "alice", TTL: time.Hour, Now: func() time.Time { return base }})

	encoded, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerify(encoded, base.Add(30*time.Minute)); err != nil {
		t.Fatalf("invite rejected inside its validity window: %v", err)
	}
	if _, err := DecodeAndVerify(encoded, base.Add(2*time.Hour)); err == nil {
		t.Fatal("an expired invite was accepted")
	}
	// An invite with no TTL never expires by time.
	_, forever := fixture(t, 0x61, Options{Name: "bob"})
	enc2, err := forever.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerify(enc2, base.Add(100*365*24*time.Hour)); err != nil {
		t.Fatalf("a TTL-less invite expired: %v", err)
	}
}

// TestMalformedInputsAreRejected: the parser is fed hostile shapes.
func TestMalformedInputsAreRejected(t *testing.T) {
	_, inv := fixture(t, 0x70, Options{Name: "alice"})
	good, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"empty":         "",
		"no prefix":     strings.TrimPrefix(good, Prefix),
		"wrong prefix":  "spore-invite-v2:" + strings.TrimPrefix(good, Prefix),
		"not base64":    Prefix + "!!!!not base64!!!!",
		"truncated b64": good[:len(good)-6],
		"json array":    Prefix + encodeRaw([]byte(`[1,2,3]`)),
		"json null":     Prefix + encodeRaw([]byte(`null`)),
		"unknown field": Prefix + encodeRaw([]byte(`{"v":1,"extra":"x"}`)),
		"oversized":     Prefix + strings.Repeat("A", MaxEncoded+100),
		"plain text":    "just some words",
		"prefix only":   Prefix,
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("accepted malformed input %q", name)
		}
	}
}

// TestOPKBearingBundleRequiresAcknowledgement: an invite carrying a one-time
// prekey must not be issued casually, because the same OPK reaching two people
// reuses a one-time key.
func TestOPKBearingBundleRequiresAcknowledgement(t *testing.T) {
	identity := filled(0x80)
	spk := filled(0x81)
	var opk [32]byte
	copy(opk[:], filled(0x82))
	bundle, err := ratchet.BuildBundle(identity, spk, 1, &opk, 5)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.OPKPub == nil {
		t.Fatal("fixture did not produce an OPK-bearing bundle")
	}

	if _, err := New(identity, Options{Address: mainnetAddr, Bundle: *bundle}); err == nil {
		t.Fatal("issued an OPK-bearing invite without acknowledgement")
	}
	inv, err := New(identity, Options{Address: mainnetAddr, Bundle: *bundle, AllowOPK: true})
	if err != nil {
		t.Fatalf("acknowledged OPK invite refused: %v", err)
	}
	encoded, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerify(encoded, time.Now()); err != nil {
		t.Fatalf("OPK-bearing invite did not verify: %v", err)
	}
}

// TestIssuanceRejectsBadInputs.
func TestIssuanceRejectsBadInputs(t *testing.T) {
	identity := filled(0x90)
	spk := filled(0x91)
	bundle, err := ratchet.BuildBundle(identity, spk, 1, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := New(identity, Options{Bundle: *bundle}); err == nil {
		t.Error("accepted an invite with no address")
	}
	if _, err := New(identity, Options{Address: "dero1notarealaddress", Bundle: *bundle}); err == nil {
		t.Error("accepted an invite with an invalid mainnet address")
	}
	if _, err := New(identity, Options{Address: mainnetAddr}); err == nil {
		t.Error("accepted an invite with a zero bundle")
	}
}

// TestFingerprintIsStableAndDistinct: the fingerprint is what humans compare
// out of band, so it must be deterministic per identity and tell identities
// apart.
func TestFingerprintIsStableAndDistinct(t *testing.T) {
	_, a1 := fixture(t, 0xa0, Options{Name: "alice"})
	_, a2 := fixture(t, 0xa0, Options{Name: "alice"})
	_, b := fixture(t, 0xb0, Options{Name: "bob"})

	fa := a1.Fingerprint()
	if fa == "" {
		t.Fatal("fingerprint is empty")
	}
	if fa != a2.Fingerprint() {
		t.Fatal("fingerprint is not deterministic for the same identity")
	}
	if fa == b.Fingerprint() {
		t.Fatal("two identities share a fingerprint")
	}
	if !strings.Contains(fa, "-") {
		t.Fatalf("fingerprint is not grouped for reading aloud: %q", fa)
	}
	// It must be short enough to read to someone.
	if len(fa) > 24 {
		t.Fatalf("fingerprint %q is too long to compare aloud", fa)
	}
}

// TestEncodedInviteCarriesNoPrivateMaterial: an invite is meant to be pasted
// into channels the sender does not control.
func TestEncodedInviteCarriesNoPrivateMaterial(t *testing.T) {
	identity := filled(0xc0)
	spk := filled(0xc1)
	var opk [32]byte
	copy(opk[:], filled(0xc2))
	bundle, err := ratchet.BuildBundle(identity, spk, 1, &opk, 3)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := New(identity, Options{Address: mainnetAddr, Bundle: *bundle, AllowOPK: true, Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(encoded)

	// The private scalars must not appear, raw or hex-encoded.
	for _, secret := range [][]byte{identity, spk, opk[:]} {
		if strings.Contains(lower, hex.EncodeToString(secret)) {
			t.Fatal("an inviter private key appears in the encoded invite")
		}
		if strings.Contains(encoded, string(secret)) {
			t.Fatal("raw private key bytes appear in the encoded invite")
		}
	}
	// Nor should any token-shaped field exist in the JSON at all.
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token", "password", "secret", "priv"} {
		if bytes.Contains(bytes.ToLower(raw), []byte(forbidden)) {
			t.Errorf("invite JSON contains a %q field", forbidden)
		}
	}
}

// TestTranscriptIsUnambiguous is the structured-signature guard: without length
// prefixes, moving a character between two adjacent fields would leave the
// signed bytes unchanged, so a signature over one invite would validate a
// different one.
func TestTranscriptIsUnambiguous(t *testing.T) {
	a := &Invite{V: 1, Name: "ab", Chain: "dero", Address: "c"}
	b := &Invite{V: 1, Name: "a", Chain: "dero", Address: "bc"}
	if string(transcript(a)) == string(transcript(b)) {
		t.Fatal("field boundaries are ambiguous in the transcript: a shift between fields is invisible to the signature")
	}

	// The same check across every adjacent string boundary.
	base := Invite{V: 1, Name: "n", Chain: "ch", Address: "a", PinnedSig: "p", PrekeyURL: "pu", StoreURL: "su", Note: "no", IssuedAt: "i", ExpiresAt: "e"}
	for i := 0; i < 10; i++ {
		shifted := base
		switch i {
		case 0:
			shifted.Name, shifted.Chain = base.Name+"c", base.Chain[1:]
		case 1:
			shifted.Chain, shifted.Address = base.Chain+"a", base.Address[1:]
		case 2:
			shifted.Address, shifted.PinnedSig = base.Address+"p", base.PinnedSig[1:]
		case 3:
			shifted.PinnedSig, shifted.PrekeyURL = base.PinnedSig+"p", base.PrekeyURL[1:]
		case 4:
			shifted.PrekeyURL, shifted.StoreURL = base.PrekeyURL+"s", base.StoreURL[1:]
		case 5:
			shifted.StoreURL, shifted.Note = base.StoreURL+"n", base.Note[1:]
		case 6:
			shifted.Note, shifted.IssuedAt = base.Note+"i", base.IssuedAt[1:]
		case 7:
			shifted.IssuedAt, shifted.ExpiresAt = base.IssuedAt+"e", base.ExpiresAt[1:]
		default:
			continue
		}
		if string(transcript(&base)) == string(transcript(&shifted)) {
			t.Fatalf("boundary %d is ambiguous", i)
		}
	}
}

// TestAbsentOPKIsDistinctFromEmptyOPK: the transcript must mark a missing OPK
// explicitly, so a degraded bundle cannot be confused with a zero-valued one.
func TestAbsentOPKIsDistinctFromEmptyOPK(t *testing.T) {
	absent := &Invite{V: 1, Name: "x"}
	zero := &Invite{V: 1, Name: "x"}
	var z [32]byte
	zero.Bundle.OPKPub = &z
	if string(transcript(absent)) == string(transcript(zero)) {
		t.Fatal("an absent OPK is indistinguishable from a zero OPK in the transcript")
	}
}

// TestVerifyRejectsUnsignedInvite: a structurally valid invite with no
// signature must not pass.
func TestVerifyRejectsUnsignedInvite(t *testing.T) {
	_, inv := fixture(t, 0xd0, Options{Name: "alice"})
	unsigned := *inv
	unsigned.Sig = ""
	if err := unsigned.Verify(time.Now()); err == nil {
		t.Fatal("an unsigned invite verified")
	}
}

// TestEncodedInviteStaysCompact guards the wire form against regression.
//
// ratchet.SPKBundle marshals its [32]byte fields as arrays of 32 decimal
// numbers, which made the token 1428 characters. The compact wire form (hex
// fields) cut that to ~1074. An invite is meant to be pasted into a chat by a
// human, so if this creeps back toward the array form, the onboarding step gets
// materially worse. The ceiling below is deliberately loose — it catches the
// doubling, not ordinary field additions.
func TestEncodedInviteStaysCompact(t *testing.T) {
	_, inv := fixture(t, 0xf0, Options{
		Name:      "alice",
		Note:      "spore beta",
		PrekeyURL: "https://spore.example.test/u/alice/prekey",
		StoreURL:  "https://spore.example.test/u/alice",
	})
	encoded, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	const ceiling = 1200
	if len(encoded) > ceiling {
		t.Fatalf("encoded invite is %d characters (ceiling %d) — is the bundle being "+
			"marshalled as decimal arrays again?", len(encoded), ceiling)
	}
	// And it must still round-trip after compaction.
	if _, err := DecodeAndVerify(encoded, time.Now()); err != nil {
		t.Fatalf("compacted invite does not verify: %v", err)
	}
}

// TestCompactWireFormSurvivesReEncode: marshalling an invite twice must be
// stable, so a re-encoded invite is byte-identical and still verifies.
func TestCompactWireFormSurvivesReEncode(t *testing.T) {
	_, inv := fixture(t, 0xf1, Options{Name: "alice"})
	first, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := decoded.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("re-encoding an invite changed it")
	}
	if _, err := DecodeAndVerify(second, time.Now()); err != nil {
		t.Fatalf("re-encoded invite does not verify: %v", err)
	}
}

// TestCompactWireRejectsWrongSizedFields: the hex form must enforce field
// widths at parse time, so a truncated key cannot reach verification and be
// misreported as a signature problem.
func TestCompactWireRejectsWrongSizedFields(t *testing.T) {
	_, inv := fixture(t, 0xf2, Options{Name: "alice"})
	encoded, err := inv.Encode()
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(encoded, Prefix)
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	bundle, ok := m["bundle"].(map[string]any)
	if !ok {
		t.Fatal("wire form has no bundle object")
	}

	for name, value := range map[string]any{
		"ik_pub":   strings.Repeat("ab", 16), // 16 bytes, want 32
		"spk_pub":  "zz",                     // not hex
		"spk_sig":  strings.Repeat("cd", 32), // 32 bytes, want 64
		"opk_hash": "",                       // empty
	} {
		broken := map[string]any{}
		for k, v := range m {
			broken[k] = v
		}
		nb := map[string]any{}
		for k, v := range bundle {
			nb[k] = v
		}
		nb[name] = value
		broken["bundle"] = nb
		out, err := json.Marshal(broken)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(Prefix + encodeRaw(out)); err == nil {
			t.Errorf("accepted a %s field of the wrong size", name)
		}
	}
}

// TestSigPubMatchesPin sanity-checks the fixture machinery, so a failure above
// is never misread as a pin mismatch in the test harness itself.
func TestSigPubMatchesPin(t *testing.T) {
	identity, inv := fixture(t, 0xe0, Options{Name: "alice"})
	pub, err := secure.SigPubOf(identity)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(pub) != inv.PinnedSig {
		t.Fatal("fixture pinned_sig does not match the signing identity")
	}
}
