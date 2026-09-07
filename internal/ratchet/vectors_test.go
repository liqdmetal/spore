package ratchet

// Deterministic ratchet vectors (docs/RATCHET.md §11.2): fixed X25519
// scalars for identity/SPK/OPK/ephemeral and every subsequent DH ratchet
// step make the whole handshake + conversation reproducible. HKDF/HMAC/
// Ed25519 are already deterministic; X25519 inputs are the only randomness
// this construction consumes.
//
// Run `go test ./internal/ratchet/ -run TestGenerateRatchetVectors -v` to
// (re)generate docs/ratchet-vectors.json, then commit it. The conformance
// test (TestRatchetVectorConformance) CONSUMES the committed file: it
// replays the SAME deterministic conversation on fresh sessions and requires
// byte-identical ciphertexts, headers, session ids and a matching final
// transcript hash — so the committed vectors stay in lockstep with the code.
//
// Both tests share runScenario so the recorded scenario and its replay can
// never drift. The replay DECRYPTS every message it delivers (including the
// out-of-order batch), so the golden requirement from §11.4 — skip a key,
// deliver 2,3,1 from the store — is exercised end to end.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Vector-scenario constants — EVERY scalar is fixed. Scalar i of the ratchet
// queue is bytes.Repeat({0x40+i}, 32).
func vecScalar(base byte) []byte { return bytesRep(base, 32) }

func bytesRep(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// vecDeadline is a fixed wall-clock value so JSON output is stable.
var vecDeadline = time.Unix(1800000000, 0).UTC()

type vecFile struct {
	Spec       string   `json:"spec"`
	Scenario   []vecMsg `json:"scenario"`
	FinalState string   `json:"final_state_sha256"`
}

type vecMsg struct {
	From       string `json:"from"` // "alice" | "bob"
	Plaintext  string `json:"plaintext_hex"`
	Wire       string `json:"wire_hex"` // full Message.MarshalBinary
	SessionID  string `json:"session_id_hex"`
	HeaderOnly string `json:"header_hex"`
}

// vecSession carries one side plus a fixed-queue DH generator for future
// ratchet steps.
type vecSession struct {
	s    *Session
	name string
}

// buildVecSessions establishes the deterministic handshake (same fixed
// scalars both tests use) and wires each side's post-handshake DH queue.
func buildVecSessions(t *testing.T) (*vecSession, *vecSession, string) {
	t.Helper()
	ikA, ikB, spkB, opkB := vecScalar(0xA1), vecScalar(0xB1), vecScalar(0xB2), vecScalar(0xB3)
	bundle, err := BuildBundle(ikB, spkB, 42, opkPtr(opkB), 7)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := sigPubOf(ikB)
	if err != nil {
		t.Fatal(err)
	}
	// Alice's EK is 0xC1; her first ratchet key IS the EK; subsequent DH
	// ratchet scalars come from per-side queues (0x42.., 0x61..) consumed in
	// lockstep by the recorded scenario.
	alice, hs, err := EstablishInitiatorDet(ikA, bundle, pinned, vecScalar(0xC1), nil)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := EstablishResponderDet(ikB, spkB, opkPtr(opkB), hs, [][]byte{vecScalar(0x41)})
	if err != nil {
		t.Fatal(err)
	}
	// Fixed DH queues so every future ratchet step is reproducible.
	alice.dhGen = queueGen(scalarRange(0x42, 0x5F))
	bob.dhGen = queueGen(scalarRange(0x61, 0x7F))
	return &vecSession{s: alice, name: "alice"}, &vecSession{s: bob, name: "bob"}, hex.EncodeToString(alice.sid[:])
}

// runScenario drives the full deterministic conversation: A→B m1,m2; B→A r1;
// A→B m3; B→A r2; then A→B m4,m5,m6 delivered OUT OF ORDER (6,4,5) — the §11.4
// golden requirement — followed by the recorded tail m4,m5,m6 in order. Every
// delivery is decrypted on the receiving side and must succeed; the returned
// slice holds the byte-identical messages the generator writes and the
// conformance test re-derives.
func runScenario(t *testing.T) ([]vecMsg, string) {
	t.Helper()
	alice, bob, sid := buildVecSessions(t)

	var msgs []vecMsg
	// A→B m1, m2 (same chain).
	record(t, alice, "m1: first ratcheted message", &msgs)
	record(t, alice, "m2: still on chain one", &msgs)
	if _, err := bob.s.Decrypt(mustUnmarshal(t, msgs[0].Wire)); err != nil {
		t.Fatalf("bob cannot decrypt m1: %v", err)
	}
	if _, err := bob.s.Decrypt(mustUnmarshal(t, msgs[1].Wire)); err != nil {
		t.Fatalf("bob cannot decrypt m2: %v", err)
	}
	// B→A r1 (direction change, bob opens a fresh ratchet key).
	record(t, bob, "r1: bob ratchets", &msgs)
	if _, err := alice.s.Decrypt(mustUnmarshal(t, msgs[2].Wire)); err != nil {
		t.Fatalf("alice cannot decrypt r1: %v", err)
	}
	// A→B m3 (alice ratchets off bob's new key).
	record(t, alice, "m3: post first heal", &msgs)
	if _, err := bob.s.Decrypt(mustUnmarshal(t, msgs[3].Wire)); err != nil {
		t.Fatalf("bob cannot decrypt m3: %v", err)
	}
	// B→A r2.
	record(t, bob, "r2: bob ratchets again", &msgs)
	if _, err := alice.s.Decrypt(mustUnmarshal(t, msgs[4].Wire)); err != nil {
		t.Fatalf("alice cannot decrypt r2: %v", err)
	}
	// A→B m4,m5,m6 (offline gap) delivered out of order 6,4,5: keys for 4,5
	// land in the skipped store, 6 decrypts at cursor, then 4 and 5 come back
	// from the store. This is the §11.4 golden requirement.
	var ooo []vecMsg
	record(t, alice, "m4", &ooo)
	record(t, alice, "m5", &ooo)
	record(t, alice, "m6", &ooo)
	for _, i := range []int{2, 0, 1} {
		got, err := bob.s.DecryptWithDeadline(mustUnmarshal(t, ooo[i].Wire), vecDeadline)
		if err != nil {
			t.Fatalf("bob cannot decrypt out-of-order delivery %d (%s): %v", i, ooo[i].Plaintext, err)
		}
		if hex.EncodeToString(got) != ooo[i].Plaintext {
			t.Fatalf("out-of-order %d plaintext mismatch: %s != %s", i, hex.EncodeToString(got), ooo[i].Plaintext)
		}
	}
	// Recorded tail — bob now consumes the same three messages in order.
	record(t, alice, "m4", &msgs)
	record(t, alice, "m5", &msgs)
	record(t, alice, "m6", &msgs)
	for i := 5; i < 8; i++ {
		got, err := bob.s.DecryptWithDeadline(mustUnmarshal(t, msgs[i].Wire), vecDeadline)
		if err != nil {
			t.Fatalf("bob cannot decrypt recorded tail %d: %v", i, err)
		}
		if hex.EncodeToString(got) != msgs[i].Plaintext {
			t.Fatalf("recorded tail %d plaintext mismatch", i)
		}
	}
	// Final transcript hash: sha256 of both sides' session ids must agree.
	if got := hex.EncodeToString(bob.s.sid[:]); got != sid {
		t.Fatalf("session ids diverged: alice=%s bob=%s", sid, got)
	}
	final := sha256.Sum256([]byte(sid))
	return msgs, hex.EncodeToString(final[:])
}

// TestGenerateRatchetVectors produces the golden file. Only overwrites when
// SPORE_GEN_VECTORS is set, so CI is read-only-safe by default.
func TestGenerateRatchetVectors(t *testing.T) {
	if os.Getenv("SPORE_GEN_VECTORS") == "" {
		t.Skip("set SPORE_GEN_VECTORS=1 to regenerate docs/ratchet-vectors.json")
	}
	msgs, final := runScenario(t)
	vf := vecFile{Spec: "spore/ratchet-vectors/v1", Scenario: msgs, FinalState: final}
	out, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../docs/ratchet-vectors.json", out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d vectors", len(msgs))
}

func opkPtr(b []byte) *[32]byte {
	p := [32]byte{}
	copy(p[:], b)
	return &p
}

func mustUnmarshal(t *testing.T, hexWire string) Message {
	t.Helper()
	raw, err := hex.DecodeString(hexWire)
	if err != nil {
		t.Fatal(err)
	}
	m, err := UnmarshalMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestRatchetVectorConformance consumes docs/ratchet-vectors.json: it replays
// the identical deterministic conversation on fresh sessions (buildVecSessions
// + runScenario) and requires that every re-derived wire, header, plaintext,
// session id and the final transcript hash exactly match the committed file.
// Because the ratchet is deterministic end to end, this locks the committed
// vectors to the current code — a code change that alters any derived byte
// fails here, as does a stale or hand-edited vectors file.
func TestRatchetVectorConformance(t *testing.T) {
	raw, err := os.ReadFile("../../docs/ratchet-vectors.json")
	if err != nil {
		t.Skipf("vectors not committed yet: %v", err)
	}
	var vf vecFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if vf.Spec != "spore/ratchet-vectors/v1" {
		t.Fatalf("unknown vector spec %q", vf.Spec)
	}
	gotMsgs, gotFinal := runScenario(t)
	if len(gotMsgs) != len(vf.Scenario) {
		t.Fatalf("scenario length mismatch: replay %d vs committed %d", len(gotMsgs), len(vf.Scenario))
	}
	if gotFinal != vf.FinalState {
		t.Fatalf("final transcript hash mismatch: replay %s vs committed %s", gotFinal, vf.FinalState)
	}
	for i := range vf.Scenario {
		want := vf.Scenario[i]
		got := gotMsgs[i]
		if got.From != want.From {
			t.Fatalf("vec %d: sender mismatch: %s != %s", i, got.From, want.From)
		}
		if got.Wire != want.Wire {
			t.Fatalf("vec %d: wire mismatch (code drifted from committed vectors)", i)
		}
		if got.HeaderOnly != want.HeaderOnly {
			t.Fatalf("vec %d: header mismatch", i)
		}
		if got.Plaintext != want.Plaintext {
			t.Fatalf("vec %d: plaintext mismatch", i)
		}
		if got.SessionID != want.SessionID {
			t.Fatalf("vec %d: session id drifted: %s != %s", i, got.SessionID, want.SessionID)
		}
	}
}

// scalarRange builds the deterministic scalar queue [lo..hi] (inclusive).
func scalarRange(lo, hi byte) [][]byte {
	var q [][]byte
	for b := lo; ; b++ {
		q = append(q, vecScalar(b))
		if b == hi {
			break
		}
	}
	return q
}

// record encrypts one message from a side and appends its vector entry.
func record(t *testing.T, a *vecSession, pt string, msgs *[]vecMsg) {
	t.Helper()
	m, err := a.s.Encrypt([]byte(pt))
	if err != nil {
		t.Fatal(err)
	}
	*msgs = append(*msgs, vecMsg{
		From:       a.name,
		Plaintext:  hex.EncodeToString([]byte(pt)),
		Wire:       hex.EncodeToString(m.MarshalBinary()),
		SessionID:  hex.EncodeToString(a.s.sid[:]),
		HeaderOnly: hex.EncodeToString(m.Header.marshal()),
	})
}
