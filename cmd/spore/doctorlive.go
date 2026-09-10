// doctor --live — known-answer self-tests for the wire paths.
//
// Plain `spore doctor` proves the ENVIRONMENT is sane (identity parses, data
// dir is writable, bind is safe, chain answers). It cannot prove the build
// still DECODES what the network actually SENDS, and that gap is where silent
// failure lives.
//
// Three real defects shipped through a green build and a green unit suite:
//
//   - a Bech32 generator constant had lost a hex digit, so EVERY destination
//     address failed with "invalid checksum";
//   - address validation did BN256 field arithmetic with the group ORDER
//     instead of the base-field prime P — measured at 49.5% of valid
//     destinations rejected and 50.2% of invalid ones accepted, i.e. a coin
//     flip in both directions;
//   - a `data[0] > 127` guard on DERO's ring-position byte silently dropped
//     about half of large-ring traffic.
//
// None of them fail loudly on their own. `--live` closes that gap by driving
// the real receive paths with known-answer inputs, so each one is a loud,
// immediate failure instead of a mystery on the wire.
//
// Checks:
//
//	addr-mainnet  a real mainnet destination validates; known-bad ones do not
//	payload-0     a byte-exact padded payload-0 (ring byte + CBOR map + random
//	              pad) decodes back to the arguments that produced it
//	ring-byte     every 0x00-0xff ring position is accepted
//	e2-pointer    the DERO typed-argument codec round-trips an E2 pointer
//	ratchet-echo  X3DH handshake + ratchet encrypt/decrypt round-trips
//	mailbox-put   real HTTP store PUT/GET/DELETE (needs -store; else skipped)
//
// All are deterministic except mailbox-put. Nothing here touches a wallet, a
// key on disk, or funds.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// doctorLiveOpts configures the self-tests. Store and RPC are the networked parts.
type doctorLiveOpts struct {
	Store    string // mailbox base URL, e.g. https://host/u/alice ("" = skip)
	StoreTok string
	RPC      string // wallet RPC endpoint, e.g. http://127.0.0.1:20211/json_rpc ("" = skip)
	RPCLogin string // wallet RPC basic auth user:pass
	Timeout  time.Duration
}

// mainnetSample is a SYNTHETIC but fully valid mainnet-format DERO address:
// genuine bech32, version 1, on-curve x = 2, correct checksum. It is the
// primary guard for the address checks — a wrong field modulus or a corrupted
// Bech32 generator constant does not fail loudly on its own, but it cannot
// validate this string. It is deliberately not anybody's real address.
const mainnetSample = "dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4"

// offCurveKey is a compressed key whose x coordinate is 4. x³ + 3 = 67 is not
// a quadratic residue mod the BN256 field prime, so no point has this x and the
// key must be refused. (x = 4 is the smallest such value.)
func offCurveKey() []byte {
	b := make([]byte, 33)
	b[31] = 0x04 // big-endian x = 4, y selector 0
	return b
}

// paddedPayload0 reconstructs DERO's exact on-chain payload-0 layout so the
// decoder is exercised against the real shape instead of a hand-trimmed
// fixture:
//
//	[ring position: 1 byte] [CBOR map: n bytes] [random pad to PAYLOAD0_LIMIT]
//
// walletapi/transaction_build.go builds it as
//
//	payload := append([]byte{byte(uint(witness_index[1]))}, data...)
//
// where `data` is rpc.CheckPack(PAYLOAD0_LIMIT) — the bare CBOR map padded with
// random bytes to exactly PAYLOAD0_LIMIT. The receiver decrypts, then decodes
// the CBOR map at offset 1 and ignores the pad.
func paddedPayload0(ringPos byte, args anchor.Arguments) ([]byte, error) {
	packed, err := dero.PackArguments(args)
	if err != nil {
		return nil, err
	}
	if len(packed) > dero.Payload0Limit {
		return nil, fmt.Errorf("packed %d bytes exceeds payload-0 limit %d", len(packed), dero.Payload0Limit)
	}
	data := make([]byte, dero.Payload0Limit)
	copy(data, packed)
	if _, err := rand.Read(data[len(packed):]); err != nil {
		return nil, err
	}
	return append([]byte{ringPos}, data...), nil
}

// runLiveDoctorChecks executes the self-tests in order.
func runLiveDoctorChecks(o doctorLiveOpts) []doctorCheck {
	var out []doctorCheck

	// 1. A real mainnet destination must validate. This is the single highest
	// value assertion in the file: it fails on a corrupted Bech32 table, on a
	// wrong BN256 modulus, and on any change to the address layout.
	{
		got, err := dero.ValidateAddress(mainnetSample)
		switch {
		case err != nil:
			out = append(out, doctorCheck{Name: "addr-mainnet", OK: false,
				Note: fmt.Sprintf("valid mainnet-format address REJECTED: %v — a constant or the field modulus is wrong", err)})
		case got != mainnetSample:
			out = append(out, doctorCheck{Name: "addr-mainnet", OK: false,
				Note: fmt.Sprintf("canonical form changed: %q", got)})
		default:
			out = append(out, doctorCheck{Name: "addr-mainnet", OK: true,
				Note: "valid mainnet-format address accepted"})
		}
	}

	// 2. Known-bad destinations must be refused, including one that is
	// well-formed except for being off-curve.
	{
		var bad []string
		if _, err := dero.ValidateAddress(mainnetSample[:len(mainnetSample)-1] + "a"); err == nil {
			bad = append(bad, "bad checksum")
		}
		if _, err := dero.ValidateAddress("deto1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq"); err == nil {
			bad = append(bad, "wrong hrp")
		}
		if _, err := dero.ValidateAddress(""); err == nil {
			bad = append(bad, "empty")
		}
		// Off-curve key via the argument packer: x = 4 is not on y² = x³ + 3.
		if _, err := dero.PackArguments(anchor.Arguments{{Name: "X", DataType: anchor.DataAddress, Value: offCurveKey()}}); err == nil {
			bad = append(bad, "off-curve compressed key")
		}
		if len(bad) > 0 {
			out = append(out, doctorCheck{Name: "addr-reject", OK: false,
				Note: fmt.Sprintf("accepted invalid destination(s): %v", bad)})
		} else {
			out = append(out, doctorCheck{Name: "addr-reject", OK: true,
				Note: "checksum, hrp, empty, and off-curve keys all refused"})
		}
	}

	// 3. Padded payload-0 round-trip. This is the shape wallets that cannot
	// parse padded CBOR hand back in Entry.Data, and the only form some
	// messages ever take on the receive path.
	//
	// Note the decoder returns arguments SORTED by name+type (the CBOR map is
	// re-emitted deterministically), not in the order they were written, so
	// every assertion here looks arguments up by name.
	{
		want := anchor.Arguments{
			{Name: "K", DataType: anchor.DataHash, Value: randHex32()},
			{Name: "D", DataType: anchor.DataUint64, Value: uint64(1790000000)},
		}
		wire, err := paddedPayload0(0x00, want)
		if err != nil {
			out = append(out, doctorCheck{Name: "payload-0", OK: false, Note: fmt.Sprintf("build: %v", err)})
		} else if got, err := dero.RawPayloadToArgs(wire); err != nil {
			out = append(out, doctorCheck{Name: "payload-0", OK: false, Note: fmt.Sprintf("decode: %v", err)})
		} else if len(got) != len(want) {
			out = append(out, doctorCheck{Name: "payload-0", OK: false,
				Note: fmt.Sprintf("decoded %d args, want %d", len(got), len(want))})
		} else if d, ok := argNamed(got, "D"); !ok {
			out = append(out, doctorCheck{Name: "payload-0", OK: false,
				Note: fmt.Sprintf("uint argument D missing from %#v", got)})
		} else if d.Value != uint64(1790000000) {
			out = append(out, doctorCheck{Name: "payload-0", OK: false,
				Note: fmt.Sprintf("uint argument round-tripped as %#v", d.Value)})
		} else if k, ok := argNamed(got, "K"); !ok || k.Value != want[0].Value {
			out = append(out, doctorCheck{Name: "payload-0", OK: false,
				Note: "hash argument did not survive the round-trip"})
		} else {
			out = append(out, doctorCheck{Name: "payload-0", OK: true,
				Note: fmt.Sprintf("%d-byte padded payload decodes (ring byte + CBOR + %d-byte pad ignored)",
					len(wire), dero.Payload0Limit-len(mustPack(want)))})
		}
	}

	// 4. Every ring position is legitimate. transaction.go reserves one byte
	// for it ("uptp 256 ring") and transaction_build.go writes a shuffled
	// witness index, so any bound here drops real traffic.
	{
		valid := true
		var failedAt int = -1
		for pos := 0; pos <= 0xff; pos++ {
			wire, err := paddedPayload0(byte(pos), anchor.Arguments{{Name: "T", DataType: anchor.DataString, Value: "x"}})
			if err != nil {
				valid, failedAt = false, pos
				break
			}
			if _, err := dero.RawPayloadToArgs(wire); err != nil {
				valid, failedAt = false, pos
				break
			}
		}
		if !valid {
			out = append(out, doctorCheck{Name: "ring-byte", OK: false,
				Note: fmt.Sprintf("ring position 0x%02x rejected — a range guard is dropping real traffic", failedAt)})
		} else {
			out = append(out, doctorCheck{Name: "ring-byte", OK: true,
				Note: "all 256 ring positions accepted"})
		}
	}

	// 5. The DERO typed-argument codec must round-trip an E2 pointer. This is
	// the path a padded payload takes into delivery, so a regression here
	// silently strands every message.
	{
		deadline := time.Now().Add(time.Hour).Unix()
		p := ratchetwire.PointerPayload{
			Version:      ratchetwire.PointerV1,
			Route:        rand32(),
			CID:          rand32(),
			BurnDeadline: uint64(deadline),
		}
		codec := ratchetwire.DeroChainCodec{}
		wire, err := codec.EncodePointer(p)
		if err != nil {
			out = append(out, doctorCheck{Name: "e2-pointer", OK: false, Note: fmt.Sprintf("encode: %v", err)})
		} else if got, ok := codec.DecodePointer(wire); !ok {
			out = append(out, doctorCheck{Name: "e2-pointer", OK: false, Note: "decode rejected a pointer this build just encoded"})
		} else if got.Route != p.Route || got.CID != p.CID || got.BurnDeadline != p.BurnDeadline {
			out = append(out, doctorCheck{Name: "e2-pointer", OK: false,
				Note: fmt.Sprintf("pointer changed in transit: %#v", got)})
		} else {
			out = append(out, doctorCheck{Name: "e2-pointer", OK: true,
				Note: fmt.Sprintf("DERO codec round-trips a %d-argument pointer", 4)})
		}
	}

	// 6. X3DH + ratchet round-trip. A crypto regression would otherwise only
	// surface as a peer that cannot decrypt.
	{
		aliceID, bobID := randBytes(32), randBytes(32)
		bobSPK := randBytes(32)
		var opk [32]byte
		copy(opk[:], randBytes(32))

		bundle, err := ratchet.BuildBundle(bobID, bobSPK, 1, &opk, 1)
		if err != nil {
			out = append(out, doctorCheck{Name: "ratchet-echo", OK: false, Note: fmt.Sprintf("bundle: %v", err)})
		} else if pinned, err := secure.SigPubOf(bobID); err != nil {
			out = append(out, doctorCheck{Name: "ratchet-echo", OK: false, Note: fmt.Sprintf("sig key: %v", err)})
		} else if a, hs, err := ratchet.EstablishInitiator(aliceID, bundle, pinned); err != nil {
			out = append(out, doctorCheck{Name: "ratchet-echo", OK: false, Note: fmt.Sprintf("X3DH initiator: %v", err)})
		} else if msg, err := a.Encrypt([]byte("spore doctor live probe")); err != nil {
			out = append(out, doctorCheck{Name: "ratchet-echo", OK: false, Note: fmt.Sprintf("encrypt: %v", err)})
		} else if b, err := ratchet.EstablishResponder(bobID, bobSPK, &opk, hs); err != nil {
			out = append(out, doctorCheck{Name: "ratchet-echo", OK: false, Note: fmt.Sprintf("X3DH responder: %v", err)})
		} else if plain, err := b.Decrypt(msg); err != nil {
			out = append(out, doctorCheck{Name: "ratchet-echo", OK: false, Note: fmt.Sprintf("decrypt: %v", err)})
		} else if string(plain) != "spore doctor live probe" {
			out = append(out, doctorCheck{Name: "ratchet-echo", OK: false,
				Note: fmt.Sprintf("plaintext changed: %q", plain)})
		} else {
			out = append(out, doctorCheck{Name: "ratchet-echo", OK: true,
				Note: "X3DH handshake + ratchet round-trip clean"})
		}
	}

	// 7. Wallet receive-readiness. A wallet whose transfer history is empty
	// while its balance is NOT accepts pointers on chain and then reports
	// nothing, so every inbound message is silently missed. That failure is
	// invisible to a balance check and invisible to a send test — both look
	// healthy — which is exactly why it earns an explicit check.
	//
	// Measured live (2026-09-10) on a freshly generated R153 wallet: held
	// 10002 atomic, sent fine, and returned an empty set from get_transfers
	// for every flag combination, before and after a full rescan. An
	// established wallet recorded the same inbound transfer immediately, so
	// the receiving role is what such a wallet cannot do.
	if o.RPC == "" {
		out = append(out, doctorCheck{Name: "wallet-recv", OK: true,
			Note: "skipped (pass -rpc http://127.0.0.1:20211/json_rpc to test a wallet)"})
	} else {
		u, p := parseLogin(o.RPCLogin)
		// Normalization lives in the client now, so this is only for the
		// message we print. One implementation, every caller covered.
		ep := dero.NormalizeWalletRPCURL(o.RPC)
		ctx, cancel := context.WithTimeout(context.Background(), o.Timeout)
		defer cancel()
		cl := dero.NewClient(ep, u, p)
		ready, hasHistory, bal, err := cl.WalletReceiveReady(ctx)
		switch {
		case err != nil:
			out = append(out, doctorCheck{Name: "wallet-recv", OK: false,
				Note: fmt.Sprintf("%s: %v — the endpoint must be the /json_rpc PATH and -rpc-login must match the wallet", ep, err)})
		case !ready:
			out = append(out, doctorCheck{Name: "wallet-recv", OK: false,
				Note: fmt.Sprintf("UNUSABLE AS A RECEIVER: balance %d but get_transfers returned NO history — inbound pointers would be silently missed. Receive with an established wallet, or rebuild this one's transfer index", bal)})
		case !hasHistory:
			out = append(out, doctorCheck{Name: "wallet-recv", OK: true,
				Note: "empty wallet (zero balance, no history): fine as a sender, but receiving is UNVERIFIED here — fund it and re-run to confirm it can report inbound transfers"})
		default:
			out = append(out, doctorCheck{Name: "wallet-recv", OK: true,
				Note: fmt.Sprintf("history present (balance %d) — reports inbound transfers", bal)})
		}
	}

	// 8. Live store round-trip. The only check that proves the hosed mailbox
	// actually accepts and returns a body.
	if o.Store == "" {
		out = append(out, doctorCheck{Name: "mailbox-put", OK: true,
			Note: "skipped (pass -store https://host/u/<name> to test a real mailbox)"})
		return out
	}
	{
		st, err := store.NewHTTPStoreWithToken(o.Store, o.StoreTok)
		if err != nil {
			out = append(out, doctorCheck{Name: "mailbox-put", OK: false, Note: fmt.Sprintf("client: %v", err)})
			return out
		}
		body := []byte("spore doctor live probe " + hex.EncodeToString(randBytes(8)))
		cid := crypto.CID(body)
		deadline := time.Now().Add(time.Minute)
		if err := st.Put(cid, body, deadline); err != nil {
			out = append(out, doctorCheck{Name: "mailbox-put", OK: false,
				Note: fmt.Sprintf("PUT %s: %v (check the store URL and -store-token)", o.Store, err)})
			return out
		}
		got, err := st.Get(cid)
		if err != nil {
			out = append(out, doctorCheck{Name: "mailbox-put", OK: false, Note: fmt.Sprintf("GET after PUT: %v", err)})
			return out
		}
		if string(got) != string(body) {
			out = append(out, doctorCheck{Name: "mailbox-put", OK: false,
				Note: fmt.Sprintf("body changed: got %d bytes, want %d", len(got), len(body))})
			return out
		}
		// Clean up so the probe does not linger in the operator's store.
		if err := st.Delete(cid); err != nil {
			out = append(out, doctorCheck{Name: "mailbox-put", OK: false,
				Note: fmt.Sprintf("DELETE after GET: %v (probe left behind)", err)})
			return out
		}
		out = append(out, doctorCheck{Name: "mailbox-put", OK: true,
			Note: fmt.Sprintf("PUT/GET/DELETE round-trip clean against %s", o.Store)})
	}

	return out
}

// argNamed finds an argument by name. The payload decoder returns arguments
// sorted by name+type rather than in written order, so callers must look them
// up rather than index them.
func argNamed(args anchor.Arguments, name string) (anchor.Argument, bool) {
	for _, a := range args {
		if a.Name == name {
			return a, true
		}
	}
	return anchor.Argument{}, false
}

// randBytes returns n random bytes.
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// randHex32 returns a 64-char hex string, the JSON form of a DERO hash argument.
func randHex32() string { return hex.EncodeToString(randBytes(32)) }

// rand32 returns 32 random bytes as an array (for key material).
func rand32() [32]byte {
	var b [32]byte
	copy(b[:], randBytes(32))
	return b
}

// mustPack is a convenience for the payload-0 note; it only ever reports the
// padding width, so an error collapses to zero.
func mustPack(args anchor.Arguments) []byte {
	b, err := dero.PackArguments(args)
	if err != nil {
		return nil
	}
	return b
}
