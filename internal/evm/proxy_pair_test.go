package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	becdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// This file pins the path the Base Sepolia rehearsal will exercise, minus the
// network: a CONTRACT-EXECUTING stub EVM node — it decodes signed legacy txs,
// recovers the sender like a real chain would (including nonce enforcement),
// and executes the real MyceliumMailbox ABI shapes (deliver/read/burn +
// Inbox logs) — in front of TWO real evm.Proxy instances. If the proxy, the
// local signer, or the mailbox wire format drifts, this fails before any
// funded rehearsal does. The stub charges no gas: funding is the one thing
// it cannot model.

var (
	// recipientKey is a second fixed never-for-funds key (B in the pair).
	recipientKey = strings.Repeat("0203040506070809", 4)
)

var (
	rehearsalKeyAddr = mustTestAddr(rehearsalKey)
	recipientKeyAddr = mustTestAddr(recipientKey)
)

func mustTestAddr(k string) string {
	a, err := AddressForKey(k)
	if err != nil {
		panic(err)
	}
	return a
}

const stubChainID = "0x14a34" // Base Sepolia's id, matching the rehearsal target

// stubMailbox executes MyceliumMailbox semantics over
// eth_sendRawTransaction (signed txs) and eth_call (views).
type stubMailbox struct {
	t         *testing.T
	srv       *httptest.Server
	srvURL    string
	mailbox   string                       // contract address (derived like a real deployment)
	msgs      map[string]map[uint64][]byte // recipient -> seq -> payload (deleted = burned)
	inboxSeqs map[string]uint64            // recipient -> next MESSAGE seq (the contract's _seq[to])
	seqs      map[string]uint64            // address -> next TX nonce (eth_getTransactionCount)
	logs      []ethLog                     // Inbox logs (all recipients; getLogs filters)
	height    uint64
	burnTxs   []string // recovered senders of burn txs
}

func newStubMailbox(t *testing.T) *stubMailbox {
	s := &stubMailbox{
		t:         t,
		msgs:      map[string]map[uint64][]byte{},
		inboxSeqs: map[string]uint64{},
		seqs:      map[string]uint64{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handler))
	s.srvURL = s.srv.URL
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubMailbox) handler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || json.Unmarshal(body, &req) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	switch req.Method {
	case "eth_chainId":
		writeRPCResult(w, req.ID, stubChainID)
	case "eth_blockNumber":
		writeRPCResult(w, req.ID, "0x"+strconv.FormatUint(s.height, 16))
	case "eth_getTransactionCount":
		var p [2]string
		_ = json.Unmarshal(req.Params, &p)
		writeRPCResult(w, req.ID, "0x"+strconv.FormatUint(s.seqs[p[0]], 16))
	case "eth_gasPrice":
		writeRPCResult(w, req.ID, "0x3b9aca00")
	case "eth_estimateGas":
		writeRPCResult(w, req.ID, "0x186a0")
	case "eth_getCode":
		var p [2]string
		_ = json.Unmarshal(req.Params, &p)
		if strings.EqualFold(p[0], s.mailbox) {
			writeRPCResult(w, req.ID, "0x6080") // non-empty = deployed
		} else {
			writeRPCResult(w, req.ID, "0x")
		}
	case "eth_sendRawTransaction":
		var p []string
		if json.Unmarshal(req.Params, &p) != nil || len(p) != 1 {
			writeRPCError(w, req.ID, "want one raw tx")
			return
		}
		s.execRaw(w, req.ID, p[0])
	case "eth_getLogs":
		// params is [filterObj] — unmarshal the ARRAY, then the filter.
		var pf []struct {
			FromBlock string   `json:"fromBlock"`
			Topics    []string `json:"topics"`
		}
		if json.Unmarshal(req.Params, &pf) != nil || len(pf) != 1 {
			writeRPCError(w, req.ID, "stub: bad getLogs params")
			return
		}
		f := pf[0]
		var out []ethLog
		for _, l := range s.logs {
			if len(l.Topics) >= 2 &&
				strings.EqualFold(l.Topics[0], bytes32ToHex(inboxTopic)) &&
				strings.EqualFold(l.Topics[1], f.Topics[1]) {
				out = append(out, l)
			}
		}
		raw, _ := json.Marshal(out)
		writeRPCResultJSON(w, req.ID, raw)
	case "eth_call":
		// params is [callObj, "latest"] — mixed types, so parse positionally.
		var pc []json.RawMessage
		if json.Unmarshal(req.Params, &pc) != nil || len(pc) != 2 {
			writeRPCError(w, req.ID, "want [callObj, tag]")
			return
		}
		var callObj map[string]interface{}
		if json.Unmarshal(pc[0], &callObj) != nil {
			writeRPCError(w, req.ID, "stub: bad call object")
			return
		}
		data, _ := callObj["data"].(string)
		from, _ := callObj["from"].(string)
		s.execCall(w, req.ID, from, data)
	default:
		writeRPCError(w, req.ID, "stub: no such method "+req.Method)
	}
}

// decodeSignedTx recovers the SENDER from a signed legacy EIP-155 tx — the
// piece a real chain does that accept-everything stubs skip.
func (s *stubMailbox) decodeSignedTx(rawHex string) (from, to string, items [][]byte, ok bool) {
	raw, err := hex.DecodeString(strings.TrimPrefix(rawHex, "0x"))
	if err != nil || len(raw) == 0 || raw[0] < 0xc0 {
		return "", "", nil, false
	}
	payload := raw[1:]
	if raw[0] > 0xf7 { // long list — length-of-length prefix
		ll := int(raw[0] - 0xf7)
		if len(payload) < ll {
			return "", "", nil, false
		}
		payload = payload[ll:]
	}
	for len(payload) > 0 {
		b := payload[0]
		var size int
		var val []byte
		switch {
		case b < 0x80:
			val, payload = payload[:1], payload[1:]
		case b < 0xb8:
			size = int(b - 0x80)
			if len(payload) < 1+size {
				return "", "", nil, false
			}
			val, payload = payload[1:1+size], payload[1+size:]
		case b < 0xc0:
			ll := int(b - 0xb7)
			if len(payload) < 1+ll {
				return "", "", nil, false
			}
			for _, c := range payload[1 : 1+ll] {
				size = size<<8 | int(c)
			}
			if len(payload) < 1+ll+size {
				return "", "", nil, false
			}
			val, payload = payload[1+ll:1+ll+size], payload[1+ll+size:]
		default:
			return "", "", nil, false // nested list: not a legacy tx
		}
		items = append(items, val)
	}
	// [nonce, gasPrice, gas, to, value, data, v, r, s]
	if len(items) != 9 {
		return "", "", nil, false
	}
	chainID, _ := new(big.Int).SetString(strings.TrimPrefix(stubChainID, "0x"), 16)
	v := itemBig(items[6])
	recIDBig := new(big.Int).Sub(v, new(big.Int).Mul(chainID, big.NewInt(2)))
	if recIDBig.Cmp(big.NewInt(35)) < 0 {
		return "", "", nil, false // not an EIP-155 signature for this chain
	}
	recID := recIDBig.Uint64() - 35
	if recID > 1 {
		return "", "", nil, false
	}
	// Rebuild the unsigned EIP-155 pre-image and recover the pubkey from it.
	// `to` must be NIL for a creation tx (an empty-but-non-nil slice would
	// encode as 0x94-prefixed, hashing a different pre-image than the signer
	// used — sender recovery would fail on exactly the deploy tx).
	var toRef []byte
	if len(items[3]) > 0 {
		toRef = items[3]
	}
	unsigned := legacyRLP(itemBig(items[0]).Uint64(), itemBig(items[1]), itemBig(items[2]),
		toRef, itemBig(items[4]), items[5], chainID, big.NewInt(0), big.NewInt(0))
	compact := make([]byte, 65)
	compact[0] = byte(27 + recID)
	// r and s must be RIGHT-aligned 32-byte fields. RLP strips leading zero
	// bytes (minimal big-endian), so a short component copied naively would
	// be left-aligned and silently corrupt the signature — recover a wrong
	// pubkey, i.e. a sender that exists nowhere. FillBytes zero-pads on the
	// left, which is exactly the EVM encoding.
	var r32, s32 [32]byte
	itemBig(items[7]).FillBytes(r32[:])
	itemBig(items[8]).FillBytes(s32[:])
	copy(compact[1:33], r32[:])
	copy(compact[33:65], s32[:])
	pub, _, err := becdsa.RecoverCompact(compact, keccak256(unsigned))
	if err != nil {
		return "", "", nil, false
	}
	// SerializeUncompressed ALREADY carries the 0x04 prefix — hash X||Y only
	// (an extra 0x04 here silently shifts the address and every derived
	// contract address with it).
	from = "0x" + hex.EncodeToString(keccak256(pub.SerializeUncompressed()[1:])[12:])
	if len(items[3]) > 0 {
		to = "0x" + hex.EncodeToString(items[3])
	}
	return from, to, items, true
}

func itemBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

func writeRPCResultRaw(w http.ResponseWriter, id json.RawMessage, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "result": "0x" + hex.EncodeToString(raw),
	})
}

// writeRPCResultJSON emits raw bytes AS the result value (not a hex string
// wrapping it) — for eth_getLogs, whose result is a JSON array of log
// objects, exactly as a real node returns it.
func writeRPCResultJSON(w http.ResponseWriter, id json.RawMessage, resultJSON []byte) {
	w.Header().Set("Content-Type", "application/json")
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", id, resultJSON)
}

func (s *stubMailbox) execRaw(w http.ResponseWriter, id json.RawMessage, rawHex string) {
	from, to, items, ok := s.decodeSignedTx(rawHex)
	if !ok {
		writeRPCError(w, id, "stub: undecodable or wrongly-signed tx")
		return
	}
	// Enforce nonce exactly like a chain: too low is a replay, a gap queues
	// (the stub refuses it — the proxy always fetches the pending count).
	declared := itemBig(items[0]).Uint64()
	if declared != s.seqs[from] {
		writeRPCError(w, id, "stub: nonce mismatch (replay or gap): tx signed with nonce "+strconv.FormatUint(declared, 10)+", chain expects "+strconv.FormatUint(s.seqs[from], 10)+" for "+shortAddr(from))
		return
	}
	s.seqs[from] = declared + 1
	s.height++
	txHash := "0x" + hex.EncodeToString(keccak256([]byte(rawHex)))
	s.t.Logf("stub: tx %s from %s to %s", shortHash(txHash), shortAddr(from), shortAddr(to))

	if to == "" { // contract creation — the deploy step
		s.mailbox = createAddress(from, declared)
		writeRPCResult(w, id, txHash)
		return
	}
	if !strings.EqualFold(to, s.mailbox) {
		writeRPCResult(w, id, txHash) // plain transfer; accepted, no-op
		return
	}

	sel, words, dyn, ok2 := abiDecomposeSigned(items)
	if !ok2 || len(words) < 2 {
		writeRPCError(w, id, "stub: malformed calldata")
		return
	}
	recip := "0x" + hex.EncodeToString(words[0][12:])
	switch {
	case sel == deliverSelector:
		plen := new(big.Int).SetBytes(words[2][:]).Uint64()
		if int(plen) > len(dyn) {
			writeRPCError(w, id, "stub: deliver length overruns calldata")
			return
		}
		payload := dyn[:plen]
		seq := s.inboxSeqs[recip]
		if s.msgs[recip] == nil {
			s.msgs[recip] = map[uint64][]byte{}
		}
		s.msgs[recip][seq] = payload
		s.inboxSeqs[recip] = seq + 1
		s.emitInbox(recip, from, seq, payload, txHash)
		writeRPCResult(w, id, txHash)
	case sel == burnSelector:
		seq := new(big.Int).SetBytes(words[1][:]).Uint64()
		if !strings.EqualFold(recip, from) {
			writeRPCError(w, id, "mailbox: only recipient")
			return
		}
		if len(s.msgs[recip][seq]) == 0 {
			writeRPCError(w, id, "stub: burn of an empty slot")
			return
		}
		delete(s.msgs[recip], seq) // compost: the slot is provably gone
		s.burnTxs = append(s.burnTxs, from)
		writeRPCResult(w, id, txHash)
	default:
		writeRPCError(w, id, "stub: unknown selector on a state tx")
	}
}

// abiDecomposeSigned splits a signed tx's calldata field into selector +
// 32-byte words + the dynamic bytes tail for deliver(address,bytes):
// selector || word(to) || word(off) || word(len) || data(padded).
func abiDecomposeSigned(items [][]byte) ([4]byte, [][32]byte, []byte, bool) {
	var sel [4]byte
	data := items[5]
	if len(data) < 4 {
		return sel, nil, nil, false
	}
	copy(sel[:], data[:4])
	rest := data[4:]
	var words [][32]byte
	var dyn []byte
	if sel == deliverSelector {
		if len(rest) < 96 {
			return sel, nil, nil, false
		}
		for i := 0; i < 3; i++ {
			var w [32]byte
			copy(w[:], rest[:32])
			words = append(words, w)
			rest = rest[32:]
		}
		dyn = rest
		// NOTE: encodeDeliver pads the TOTAL buffer to a 32-byte multiple, so
		// the data tail here is len(dyn) = 32-aligned-data minus nothing — it
		// need not be 32-aligned itself. The real contract tolerates any
		// trailing padding (it copies exactly `len` bytes), so the stub does
		// too; the plen <= len(dyn) check at the call site is the real bound.
		return sel, words, dyn, true
	}
	for len(rest) >= 32 {
		var w [32]byte
		copy(w[:], rest[:32])
		words = append(words, w)
		rest = rest[32:]
	}
	if len(rest) != 0 {
		return sel, nil, nil, false
	}
	return sel, words, nil, true
}

func (s *stubMailbox) emitInbox(to, from string, seq uint64, payload []byte, txHash string) {
	toWord, err := padAddr20(to)
	if err != nil {
		s.t.Fatal(err)
	}
	fromWord, err := padAddr20(from)
	if err != nil {
		s.t.Fatal(err)
	}
	seqWord := uintWord(seq)
	var cid [32]byte
	copy(cid[:], keccak256(payload))
	s.logs = append(s.logs, ethLog{
		Address:         s.mailbox,
		Topics:          []string{bytes32ToHex(inboxTopic), addrTopicToHex(toWord), addrTopicToHex(fromWord), bytes32ToHex(seqWord)},
		Data:            "0x" + hex.EncodeToString(cid[:]),
		BlockNumber:     "0x" + strconv.FormatUint(s.height, 16),
		TransactionHash: txHash,
	})
}

func (s *stubMailbox) execCall(w http.ResponseWriter, id json.RawMessage, from, dataHex string) {
	raw, err := hex.DecodeString(strings.TrimPrefix(dataHex, "0x"))
	if err != nil {
		writeRPCError(w, id, "stub: bad eth_call data")
		return
	}
	if len(raw) < 4 {
		writeRPCError(w, id, "stub: short view calldata")
		return
	}
	var sel [4]byte
	copy(sel[:], raw[:4])
	rest := raw[4:]
	if sel == lengthSelector() {
		if len(rest) < 32 {
			writeRPCError(w, id, "stub: length wants an address arg")
			return
		}
		recip := "0x" + hex.EncodeToString(rest[12:32])
		lw := uintWord(uint64(len(s.msgs[recip])))
		writeRPCResultRaw(w, id, lw[:])
		return
	}
	if len(rest) < 64 {
		writeRPCError(w, id, "stub: view wants (address,uint256)")
		return
	}
	recip := "0x" + hex.EncodeToString(rest[12:32])
	seq := new(big.Int).SetBytes(rest[32:64]).Uint64()
	switch {
	case sel == readSelector:
		// The contract's rule: only the recipient may read (msg.sender == to).
		if !strings.EqualFold(recip, from) {
			writeRPCError(w, id, "mailbox: only recipient")
			return
		}
		writeRPCResultRaw(w, id, abiEncodeReadResult(s.msgs[recip][seq], s.height))
	default:
		writeRPCError(w, id, "stub: unknown view selector")
	}
}

// lengthSelector is keccak("length(address)")[:4].
func lengthSelector() [4]byte { return sel4("length(address)") }

// abiEncodeReadResult returns the ABI encoding of read()'s
// (address from, uint256 blockNumber, bytes data) — exactly what
// decodeReadResult parses on the client side.
func abiEncodeReadResult(payload []byte, block uint64) []byte {
	out := make([]byte, 0, 128+len(payload))
	var zero [32]byte
	bw := uintWord(block)
	ow := uintWord(96) // dynamic offset is from the block start: past ALL THREE head words
	lw := uintWord(uint64(len(payload)))
	out = append(out, zero[:]...) // from (unused)
	out = append(out, bw[:]...)   // blockNumber (unused)
	out = append(out, ow[:]...)   // offset of bytes
	out = append(out, lw[:]...)   // length
	out = append(out, payload...)
	for len(out)%32 != 0 {
		out = append(out, 0)
	}
	return out
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}

func shortAddr(a string) string {
	if len(a) > 14 {
		return a[:8] + "…" + a[len(a)-4:]
	}
	return a
}

// TestProxyPairFullRoundTrip is the rehearsal, minus the network. A deploys
// and delivers; B discovers via eth_getLogs + read() through THEIR proxy,
// auto-burns; the empty-slot proof is the read()-returns-nothing assertion
// the runbook backs with a cast call.
func TestProxyPairFullRoundTrip(t *testing.T) {
	stub := newStubMailbox(t)

	proxyA, err := NewProxy(stub.srvURL, rehearsalKey)
	if err != nil {
		t.Fatal(err)
	}
	proxyB, err := NewProxy(stub.srvURL, recipientKey)
	if err != nil {
		t.Fatal(err)
	}
	srvA := httptest.NewServer(proxyA.Handler())
	defer srvA.Close()
	srvB := httptest.NewServer(proxyB.Handler())
	defer srvB.Close()

	// The signer refuses a creation tx (no `to`): the deploy rides the
	// deploy path's own raw broadcast, not SignAndSendTransaction.
	bA := NewBackend(srvA.URL, "evm", rehearsalKeyAddr)
	if _, err := bA.SignAndSendTransaction(context.Background(), rehearsalKey, map[string]interface{}{
		"to":   "",
		"data": "0x6080",
	}); err == nil {
		t.Fatal("empty `to` must be refused by the signer")
	}

	// --- A deploys THROUGH PROXY A: views forward verbatim, the raw
	// creation tx forwards verbatim, the stub executes it.
	if _, err := bA.DeployContractEIP155(context.Background(), rehearsalKey, "6080", nil); err != nil {
		t.Fatalf("deploy through proxy A: %v", err)
	}
	code, err := bA.GetCode(context.Background(), stub.mailbox)
	if err != nil || len(code) == 0 {
		t.Fatalf("no code at the derived address after deploy (err=%v)", err)
	}

	// --- A delivers two payloads to B via proxy A (PostPayload's contract
	// path: eth_sendTransaction deliver(to,data) → signed by proxy A).
	sender := NewBackend(srvA.URL, "evm", rehearsalKeyAddr)
	sender.SetMailbox(stub.mailbox)
	for _, msg := range [][]byte{[]byte("pointer one"), []byte("pointer two — A to B")} {
		if _, err := sender.PostPayload(context.Background(), recipientKeyAddr, msg, 0); err != nil {
			t.Fatalf("deliver through proxy A: %v", err)
		}
	}

	// --- B discovers via eth_getLogs + read() through PROXY B.
	receiver := NewBackend(srvB.URL, "evm", recipientKeyAddr)
	receiver.SetMailbox(stub.mailbox)
	incoming, err := receiver.ListIncoming(context.Background(), 1)
	if err != nil {
		t.Fatalf("B list-incoming through proxy B: %v", err)
	}
	if len(incoming) != 2 {
		t.Fatalf("B should see 2 messages, saw %d", len(incoming))
	}
	if string(incoming[0].Payload) != "pointer one" || string(incoming[1].Payload) != "pointer two — A to B" {
		t.Fatalf("payloads garbled: %q, %q", incoming[0].Payload, incoming[1].Payload)
	}
	if incoming[0].Sender != rehearsalKeyAddr || incoming[0].BurnKey != "0" || incoming[1].BurnKey != "1" {
		t.Fatalf("sender/burnkeys wrong: %+v", incoming)
	}
	if len(stub.burnTxs) != 0 {
		t.Fatal("no burns may have happened before B acts")
	}

	// --- B auto-burns (chain.Watch's exact call), through proxy B. The stub
	// recovered the burn SENDER from the signature: it must be B.
	if err := receiver.Burn(context.Background(), incoming[0].BurnKey); err != nil {
		t.Fatalf("burn through proxy B: %v", err)
	}
	if err := receiver.Burn(context.Background(), incoming[1].BurnKey); err != nil {
		t.Fatalf("burn 2 through proxy B: %v", err)
	}
	if len(stub.burnTxs) != 2 || stub.burnTxs[0] != recipientKeyAddr || stub.burnTxs[1] != recipientKeyAddr {
		t.Fatalf("burn txs must be recovered as B, got %v", stub.burnTxs)
	}

	// --- Empty-slot proof: ListIncoming sees nothing, the on-chain slots
	// are gone, and a direct read() (B's own encoder/decoder, through the
	// proxy) returns empty data for both seqs — the runbook's cast-call
	// assertion. `length` still counts 2: burned seqs stay spent, exactly
	// like the real contract.
	after, err := receiver.ListIncoming(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Fatalf("B still sees %d deliverable messages after burning", len(after))
	}
	if len(stub.msgs[recipientKeyAddr]) != 0 {
		t.Fatalf("on-chain slots not empty: %+v", stub.msgs[recipientKeyAddr])
	}
	for _, seq := range []uint64{0, 1} {
		readCalldata, err := encodeRead(recipientKeyAddr, seq)
		if err != nil {
			t.Fatal(err)
		}
		callObj := map[string]interface{}{
			"from": recipientKeyAddr,
			"to":   stub.mailbox,
			"data": readCalldata,
		}
		var resHex string
		if err := receiver.call(context.Background(), "eth_call", []interface{}{callObj, "latest"}, &resHex); err != nil {
			t.Fatalf("read(%d) through proxy B: %v", seq, err)
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(resHex, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		data, err := decodeReadResult(raw)
		if err != nil {
			t.Fatalf("read(%d) decode: %v", seq, err)
		}
		if len(data) != 0 {
			t.Fatalf("slot %d not empty after burn: %q", seq, data)
		}
	}

	// Chain-shaped rejections: a never-existing seq cannot be burned, and a
	// nonce replay is refused by the stub (the proxy re-fetches nonces, so
	// this only fires if someone bypasses it).
	if err := receiver.Burn(context.Background(), "999"); err == nil {
		t.Fatal("burning a never-existing seq must fail")
	}
	if _, err := sender.PostPayload(context.Background(), recipientKeyAddr, []byte("post-burn hello"), 0); err != nil {
		t.Fatalf("post-burn delivery must work: %v", err)
	}
	if _, _, _, ok := stub.decodeSignedTx("0xdeadbeef"); ok {
		t.Fatal("garbage must not decode as a signed tx")
	}
}
