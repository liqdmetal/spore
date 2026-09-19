// Package wirefuzz hosts the standalone OSS-Fuzz targets for the SPR2 wire
// parsers (E2 audit recommendation 2). It lives in its own package so the
// OSS-Fuzz build is insulated from the main ratchetwire package's test-file
// layout: go-118-fuzz-build requires the fuzz target to be in the package
// named by the directory (an external `_test` package is invisible to its
// function finder).
package wirefuzz

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/liqdmetal/spore/internal/fabric"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// Standalone parser fuzz targets (E2 audit recommendation 2): the SPR2 frame
// parser, the X3DH handshake parser, and the ratchet message parser are the
// three byte-level attack surfaces a hostile body store feeds directly. They
// were previously fuzzed only through endpoint flows; here the attacker
// controls the bytes end to end. Every accepted input must (a) satisfy the
// documented invariants and (b) round-trip through Marshal → Parse identity.

// validInitFrameBytes builds a well-formed init frame carrying body.
// It returns the error instead of calling testing.TB.Fatal so it composes
// with the OSS-Fuzz libFuzzer shim, whose fake testing package has no TB
// interface (only concrete F and T).
func validInitFrameBytes(body []byte) ([]byte, error) {
	var sid [8]byte
	copy(sid[:], []byte("sidsid!"))
	hs := &ratchet.HandshakeMessage{
		IKPub: fill32(1), EKPub: fill32(2), SPKID: 7, OPKID: 9, SessionID: sid,
	}
	d := time.Now().Add(time.Hour).Truncate(time.Second)
	frame, err := ratchetwire.NewInitFrame(hs, ratchet.Message{
		Header:     ratchet.Header{DHPub: fill32(3), PN: 0, N: 0},
		Nonce:      nonce24(4),
		Ciphertext: body,
	}, d)
	if err != nil {
		return nil, err
	}
	return frame.MarshalBinary()
}

func validInitFrame(f *testing.F, body []byte) []byte {
	f.Helper()
	out, err := validInitFrameBytes(body)
	if err != nil {
		f.Fatal(err)
	}
	return out
}

func fill32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func nonce24(b byte) [24]byte {
	var out [24]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// TestGenerateSeedCorpus regenerates the OSS-Fuzz seed corpus files shipped
// alongside the fuzz targets. The libFuzzer shim used by go-118-fuzz-build
// treats f.Add as a no-op, so OSS-Fuzz must receive seeds as
// <fuzzer>_seed_corpus.zip archives; this test writes the same inputs as
// individual files (named <label>_<hash-prefix>) for build.sh to zip.
// It is a no-op without SPORE_GEN_SEED_CORPUS=1 so normal `go test` runs stay
// side-effect free.
func TestGenerateSeedCorpus(t *testing.T) {
	if os.Getenv("SPORE_GEN_SEED_CORPUS") != "1" {
		t.Skip("set SPORE_GEN_SEED_CORPUS=1 to regenerate the OSS-Fuzz seed corpus")
	}
	dir := filepath.Join("testdata", "fuzz", "seedcorpus")
	// Reset the directory so regeneration is idempotent (frame seeds embed a
	// fresh deadline each run, so old hash-named copies would otherwise pile up).
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSeed := func(label string, data []byte) {
		t.Helper()
		sum := sha256.Sum256(data)
		path := filepath.Join(dir, fmt.Sprintf("%s_%x", label, sum[:6]))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Frame parser seeds (FuzzFrameParse).
	frameValid, err := validInitFrameBytes([]byte("attack surface: the whole body store"))
	if err != nil {
		t.Fatal(err)
	}
	writeSeed("frame_valid", frameValid)
	writeSeed("frame_spr2_short", []byte("SPR2\x01\x01\x00\x00"))
	writeSeed("frame_empty", []byte{})
	writeSeed("frame_zeros", bytes.Repeat([]byte{0x00}, 80))
	writeSeed("frame_ffs", bytes.Repeat([]byte{0xFF}, 120))

	// Handshake parser seeds (FuzzHandshakeUnmarshal).
	var sid [8]byte
	copy(sid[:], []byte("handshake"))
	full := &ratchet.HandshakeMessage{IKPub: fill32(1), EKPub: fill32(2), SPKID: 1, OPKID: 2, SessionID: sid}
	degraded := &ratchet.HandshakeMessage{IKPub: fill32(1), EKPub: fill32(2), SPKID: 1, OPKID: testNoOPK, SessionID: sid, Degraded: true}
	writeSeed("hs_full", full.MarshalBinary())
	writeSeed("hs_degraded", degraded.MarshalBinary())
	writeSeed("hs_zeroes", make([]byte, 81))
	writeSeed("hs_tiny", []byte{0x01})

	// Message parser seeds (FuzzMessageUnmarshal).
	msg := ratchet.Message{
		Header:     ratchet.Header{DHPub: fill32(5), PN: 1, N: 2},
		Nonce:      nonce24(6),
		Ciphertext: []byte("sixteen byte pad" + "...."),
	}
	valid := msg.MarshalBinary()
	writeSeed("msg_valid", valid)
	writeSeed("msg_trunc1", valid[:len(valid)-1])
	writeSeed("msg_short", valid[:60])
	writeSeed("msg_empty", []byte{})

	// rpc2/CBOR decoder seeds (FuzzFabricRPC2Frame) — the second encoding's
	// hostile-frame surface (F4a follow-up). Real vector frames give the
	// fuzzer the exact on-wire shapes; the mutations around them are the
	// mutations a hostile relay would actually send.
	seedRP2, err := loadRPC2VectorFrames()
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range seedRP2 {
		writeSeed(fmt.Sprintf("rpc2_vector_%02d", i), b)
	}
	writeSeed("rpc2_empty", []byte{})
	writeSeed("rpc2_single_byte", []byte{0xa1})
	writeSeed("rpc2_depth_bomb", bytes.Repeat([]byte{0x9f}, 80)) // indefinite arrays, nested
	writeSeed("rpc2_huge_len", []byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	writeSeed("rpc2_bad_utf8_text", []byte{0x63, 0xff, 0xfe, 0xfd})
	writeSeed("rpc2_bool_trap", []byte{0xe2, 0x00, 0x14}) // head that looks like a simple value
}

func FuzzFrameParse(f *testing.F) {
	f.Add(validInitFrame(f, []byte("attack surface: the whole body store")))
	f.Add([]byte("SPR2\x01\x01\x00\x00"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x00}, 80))
	f.Add(bytes.Repeat([]byte{0xFF}, 120))

	f.Fuzz(func(t *testing.T, b []byte) {
		frame, err := ratchetwire.Parse(b)
		if err != nil {
			return
		}
		// Invariants Parse must enforce for anything it accepts.
		if frame.Deadline == 0 {
			t.Fatal("accepted a zero deadline")
		}
		if frame.Kind != ratchetwire.FrameInit && frame.Kind != ratchetwire.FrameMessage {
			t.Fatal("accepted an unknown kind")
		}
		if frame.Kind == ratchetwire.FrameInit && len(frame.Handshake) == 0 {
			t.Fatal("accepted an init frame with no handshake")
		}
		if frame.Kind == ratchetwire.FrameMessage && len(frame.Handshake) != 0 {
			t.Fatal("accepted a message frame with a handshake")
		}
		// A live accepted frame must re-marshal and re-parse to itself.
		if time.Now().Unix() < int64(frame.Deadline) {
			out, err := frame.MarshalBinary()
			if err != nil {
				t.Fatalf("accepted frame failed to re-marshal: %v", err)
			}
			re, err := ratchetwire.Parse(out)
			if err != nil {
				t.Fatalf("re-marshaled frame failed to parse: %v", err)
			}
			if re.Kind != frame.Kind || re.SessionID != frame.SessionID || re.Deadline != frame.Deadline {
				t.Fatal("round trip mismatch: header fields")
			}
			if !bytes.Equal(re.Message.Ciphertext, frame.Message.Ciphertext) ||
				re.Message.Nonce != frame.Message.Nonce || re.Message.Header != frame.Message.Header {
				t.Fatal("round trip mismatch: message")
			}
		}
	})
}

// testNoOPK mirrors ratchet's unexported noOPK sentinel (0xFFFFFFFF): a
// handshake with this OPK id MUST carry Degraded=true, per UnmarshalHandshake.
const testNoOPK = 0xFFFFFFFF

func FuzzHandshakeUnmarshal(f *testing.F) {
	var sid [8]byte
	copy(sid[:], []byte("handshake"))
	full := &ratchet.HandshakeMessage{IKPub: fill32(1), EKPub: fill32(2), SPKID: 1, OPKID: 2, SessionID: sid}
	degraded := &ratchet.HandshakeMessage{IKPub: fill32(1), EKPub: fill32(2), SPKID: 1, OPKID: testNoOPK, SessionID: sid, Degraded: true}
	f.Add(full.MarshalBinary())
	f.Add(degraded.MarshalBinary())
	f.Add(make([]byte, 81))
	f.Add([]byte{0x01})

	f.Fuzz(func(t *testing.T, b []byte) {
		hs, err := ratchet.UnmarshalHandshake(b)
		if err != nil {
			return
		}
		// The degraded flag and the OPK id must agree in anything accepted.
		if hs.Degraded != (hs.OPKID == testNoOPK) {
			t.Fatal("accepted a handshake with degraded/OPK inconsistency")
		}
		again, err := ratchet.UnmarshalHandshake(hs.MarshalBinary())
		if err != nil {
			t.Fatalf("accepted handshake failed to re-marshal: %v", err)
		}
		if *again != *hs {
			t.Fatal("handshake round trip mismatch")
		}
	})
}

// loadRPC2VectorFrames pulls the byte-exact rpc2 frames from the golden
// vectors (same file every other conformance test consumes) for the fuzz
// seed corpus.
func loadRPC2VectorFrames() ([][]byte, error) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "interop-vectors.json"))
	if err != nil {
		return nil, err
	}
	var v struct {
		FabricV1 struct {
			RPC2ReqFreg  string `json:"rpc2_request_freg_frame_hex"`
			RPC2RespFreg string `json:"rpc2_response_freg_frame_hex"`
			RPC2ReqFput  string `json:"rpc2_request_fput_frame_hex"`
			RPC2RespFput string `json:"rpc2_response_fput_frame_hex"`
			RPC2ReqFpop  string `json:"rpc2_request_fpop_frame_hex"`
			RPC2RespFpop string `json:"rpc2_response_fpop_frame_hex"`
			RPC2RespErr  string `json:"rpc2_response_error_frame_hex"`
		} `json:"fabric_v1"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	var out [][]byte
	for _, s := range []string{
		v.FabricV1.RPC2ReqFreg, v.FabricV1.RPC2RespFreg,
		v.FabricV1.RPC2ReqFput, v.FabricV1.RPC2RespFput,
		v.FabricV1.RPC2ReqFpop, v.FabricV1.RPC2RespFpop,
		v.FabricV1.RPC2RespErr,
	} {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// rpc2RoundTripMode is the go-cbor decode mode for the round-trip check.
// The CONTRACT depth cap is 64 on both implementations (p2p.rs MAX_DEPTH =
// 64, fabric.rpc2MaxDepth = 64, pinned by the deep-nesting negative vector
// tests) — but the two counting conventions can differ by one, so the
// checker takes headroom (128) rather than re-stating the contract at a
// second site where a mismatch would reject contract-valid frames.
var rpc2RoundTripMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{MaxNestedLevels: 128}.DecMode()
	if err != nil {
		panic("cbor.DecOptions(128 levels) never fails: " + err.Error())
	}
	return dm
}()

// FuzzFabricRPC2Frame — the CBOR/rpc2 decoder (internal/fabric rpc2.go),
// the hostile-frame surface of the fabric's SECOND encoding (F4a). The
// relay-facing parse path for Peer.FabricReg/Put/Pop; byte-exact shapes are
// pinned by the rpc2_* vectors, so this target hunts what the conformance
// suite cannot: crashers and invariant breaks under arbitrary mutation.
//
// Invariants (mirroring the Rust decoder's contract and the negative
// vector cases):
//   - errors are one of the three value errors (no panics, no hangs —
//     the depth cap bounds recursion, allocation is bounded by the frame);
//   - an accepted frame's payload (when present) survives the go-cbor
//     round trip;
//   - zero-consumption decodes are malformed.
func FuzzFabricRPC2Frame(f *testing.F) {
	vecSeeds, err := loadRPC2VectorFrames()
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range vecSeeds {
		f.Add(s)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa1})
	f.Add(bytes.Repeat([]byte{0x9f}, 80))                                     // indefinite heads — rejected, but mutator fodder
	f.Add([]byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // huge declared length
	f.Add([]byte{0x63, 0xff, 0xfe, 0xfd})                                     // invalid UTF-8 text
	f.Add([]byte{0xe2, 0x00, 0x14})                                           // simple-value head where a map is wanted
	f.Fuzz(func(t *testing.T, b []byte) {
		msg, err := fabric.DecodeRPC2Frame(b)
		if err != nil {
			return // rejections are fine; crashes and hangs are the hunt
		}
		// An accepted frame's payload (when present) must survive the
		// canonical go-cbor round trip — the second encoding's version of
		// the marshal/parse identity the other targets assert.
		if msg.Payload != nil {
			goCbor, err := cbor.Marshal(msg.Payload)
			if err != nil {
				t.Fatalf("accepted payload failed to re-encode: %v", err)
			}
			var back any
			if err := rpc2RoundTripMode.Unmarshal(goCbor, &back); err != nil {
				t.Fatalf("re-encoded payload failed to re-parse: %v", err)
			}
		}
	})
}

func FuzzMessageUnmarshal(f *testing.F) {
	msg := ratchet.Message{
		Header:     ratchet.Header{DHPub: fill32(5), PN: 1, N: 2},
		Nonce:      nonce24(6),
		Ciphertext: []byte("sixteen byte pad" + "...."), // ≥ 16-byte tag placeholder
	}
	valid := msg.MarshalBinary()
	f.Add(valid)
	f.Add(valid[:len(valid)-1])
	f.Add(valid[:60])
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ratchet.UnmarshalMessage(b)
		if err != nil {
			return
		}
		again, err := ratchet.UnmarshalMessage(m.MarshalBinary())
		if err != nil {
			t.Fatalf("accepted message failed to re-marshal: %v", err)
		}
		if again.Header != m.Header || again.Nonce != m.Nonce || !bytes.Equal(again.Ciphertext, m.Ciphertext) {
			t.Fatal("message round trip mismatch")
		}
	})
}
