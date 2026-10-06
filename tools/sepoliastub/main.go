// sepoliastub — a stateful local EVM JSON-RPC server for CI, standing in for
// Base Sepolia so the full sepolia rehearsal script (scripts/sepolia_rehearsal.sh)
// and `spore contract deploy-mycelium` run hermetically, with no faucet.
//
// Scope is deliberately narrow: exactly the RPC surface the rehearsal's
// Phase A path needs, with the stateful half of MyceliumMailbox semantics
// (contracts/MyceliumMailbox.sol):
//
//	eth_chainId, eth_gasPrice, eth_blockNumber
//	eth_getBalance, eth_getTransactionCount, eth_getCode
//	eth_estimateGas            (a simulation — never mutates state)
//	eth_sendRawTransaction     (the deploy + evm-proxy signing path)
//	eth_sendTransaction        (the recipient-signed burn path)
//	eth_getLogs                (Inbox(to=us) discovery)
//	eth_call                   (read() and length() simulation)
//	eth_getTransactionByHash   (reading a mined tx back off the chain)
//	eth_getBlockByNumber       (the scan window; always full transactions)
//
// Signing interop: spore signs legacy EIP-155 transactions with btcec's
// SignCompact — <recid+27><r><s> — and this stub recovers the signer with
// RecoverCompact. To do that it rebuilds the unsigned RLP pre-image
// (the exact legacyRLP layout internal/evm/contract.go signs), re-encoding
// each decoded field, so the stub only ever depends on the wire-visible side
// of the signer, never on spore internals.
//
// Semantics that must match the real contract (drift here = a CI lie):
//   - deliver() stores (from, block, data) per (to, seq) and emits
//     Inbox(address indexed to, address indexed from, uint256 indexed seq,
//     bytes32 cid) — four 32-byte topics, addresses left-padded.
//   - read(to, seq) requires msg.sender == to and returns
//     (from, blockNumber, bytes) with the bytes head at offset 96.
//   - burn(to, seq) requires msg.sender == to and clears ONLY the data;
//     the log stays (events are immutable) and length(to) never decreases.
//   - a burn estimate against a missing message reverts, exactly the node
//     behavior `spore contract estimate` documents as its burn fallback.
//   - every accepted tx mines into a fresh block, so a deliver's Inbox log
//     always sits ABOVE the head the script captures before sending — the
//     -min-height/eth_getLogs fromBlock contract the rehearsal relies on.
//   - every accepted tx is retrievable by hash and by block, because the E2
//     receive path's burn is deliberately unlogged: scripts/evm-burn-txid.sh
//     reads it back off the chain, and the rehearsal now runs that step, so
//     the surface it needs has to exist here or the offline rehearsal stops
//     mirroring the real one.
//
// Not simulated, on purpose: gas accounting, signatures other than legacy
// EIP-155, nonzero-value txs, and any contract other than the mailbox.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	becdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"golang.org/x/crypto/sha3"
)

// ---------- fixed chain constants (Base Sepolia-shaped, stub-owned) ----------

const (
	// 84532 = Base Sepolia, so the script's chain-id note fires and spore
	// signs EIP-155 txs with the id the stub advertises.
	chainID      = 84532
	gasPriceHex  = "0x3b9aca00"          // 1 gwei
	startHeight  = uint64(100)           // eth_blockNumber before the first tx
	startBalance = "0x56bc75e2d63100000" // 100 ETH in wei — everyone is funded
	codeHex      = "6080604052"          // non-empty code for eth_getCode
)

// Selectors are keccak256(sig)[:4] — the same values internal/evm computes
// via sel4(). Recomputed here rather than hardcoded so a signature change in
// mailbox.go and a drift in this stub fail CI together, not silently apart.
var (
	selDeliver = selector4("deliver(address,bytes)")
	selBurn    = selector4("burn(address,uint256)")
	selRead    = selector4("read(address,uint256)")
	selLength  = selector4("length(address)")
	inboxTopic = keccak256([]byte("Inbox(address,address,uint256,bytes32)"))
)

func selector4(sig string) []byte { return keccak256([]byte(sig))[:4] }

func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(b)
	return h.Sum(nil)
}

// ---------- tx model ----------

type stubTx struct {
	From    string // lowercase 0x-hex
	To      string // "" = contract creation
	Data    []byte
	Hash    string
	Block   uint64
	Created string // contract address, creation txs only
}

type msgEntry struct {
	from   string
	block  uint64
	data   []byte // nil once burned (the slot's storage is cleared)
	burned bool
}

type stubChain struct {
	mu       sync.Mutex
	txByHash map[string]*stubTx
	order    []*stubTx         // mined txs, oldest first (block queries)
	nonce    map[string]uint64 // per-signer accepted-tx count
	codeAt   map[string]bool   // addresses holding contract code
	contract string            // the created MyceliumMailbox address
	msgs     map[string][]*msgEntry
	nextSeq  map[string]uint64 // recipient -> next seq (length(to); never decreases)
	logs     []stubLog
	height   uint64
}

type stubLog struct {
	Address         string   `json:"address"`
	Topics          []string `json:"topics"`
	Data            string   `json:"data"`
	BlockNumber     string   `json:"blockNumber"`
	TransactionHash string   `json:"transactionHash"`
}

func newStubChain() *stubChain {
	return &stubChain{
		txByHash: map[string]*stubTx{},
		nonce:    map[string]uint64{},
		codeAt:   map[string]bool{},
		msgs:     map[string][]*msgEntry{},
		nextSeq:  map[string]uint64{},
		height:   startHeight,
	}
}

// ---------- RLP (the tx-side mirror of internal/evm's legacyRLP) ----------

func rlpString(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpLen(len(b), 0x80), b...)
}

func rlpLen(n int, offset byte) []byte {
	if n < 56 {
		return []byte{offset + byte(n)}
	}
	lb := bigEndian(uint64(n))
	return append([]byte{offset + 55 + byte(len(lb))}, lb...)
}

func bigEndian(v uint64) []byte {
	if v == 0 {
		return nil
	}
	var buf [8]byte
	n := 0
	for v > 0 {
		buf[7-n] = byte(v)
		v >>= 8
		n++
	}
	return buf[8-n:]
}

// decodeLegacyTx parses a signed legacy RLP transaction, rebuilds the
// unsigned EIP-155 pre-image, recovers the signer, and validates the chain
// id. Returns the lowercase from/to ("to" empty for creation) and calldata.
func decodeLegacyTx(rlp []byte) (from, to string, data []byte, err error) {
	if len(rlp) == 0 || rlp[0] < 0xc0 {
		return "", "", nil, fmt.Errorf("rlp: tx is not a list")
	}
	if rlp[0] < 0xf8 {
		rlp = rlp[1 : 1+int(rlp[0]-0xc0)]
	} else {
		lenBytes := int(rlp[0] - 0xf7)
		n64 := new(big.Int).SetBytes(rlp[1 : 1+lenBytes])
		if !n64.IsUint64() || int(n64.Uint64()) > len(rlp) {
			return "", "", nil, fmt.Errorf("rlp: absurd list length")
		}
		rlp = rlp[1+lenBytes : 1+lenBytes+int(n64.Uint64())]
	}
	var fields [][]byte
	for len(rlp) > 0 {
		item, rest, e := rlpItem(rlp)
		if e != nil {
			return "", "", nil, e
		}
		fields = append(fields, item)
		rlp = rest
	}
	// EIP-155 signed: [nonce, gasPrice, gas, to, value, data, v, r, s].
	// Pre-155 (6 fields) is rejected: spore never signs without a chain id.
	if len(fields) != 9 {
		return "", "", nil, fmt.Errorf("rlp: want 9 EIP-155 fields, got %d", len(fields))
	}
	if len(fields[4]) != 0 {
		return "", "", nil, fmt.Errorf("stub: nonzero-value txs are not simulated")
	}
	if len(fields[3]) == 20 {
		to = "0x" + hex.EncodeToString(fields[3])
	}
	data = fields[5]
	v := new(big.Int).SetBytes(fields[6])
	r := new(big.Int).SetBytes(fields[7])
	s := new(big.Int).SetBytes(fields[8])
	// v = chainID*2 + 35 + recid (recid 0 or 1). v parity IS the recid
	// because chainID*2 + 35 is always odd.
	if v.Cmp(big.NewInt(35)) < 0 {
		return "", "", nil, fmt.Errorf("stub: bad EIP-155 v %s", v)
	}
	vm35 := new(big.Int).Sub(v, big.NewInt(35))
	recID := vm35.Bit(0)
	chainIDBig := new(big.Int).Rsh(vm35, 1)
	if !chainIDBig.IsInt64() || chainIDBig.Int64() != chainID {
		return "", "", nil, fmt.Errorf("stub: tx is for chain id %s, stub serves %d", chainIDBig, chainID)
	}
	// Unsigned pre-image: fields 0..5 plus chainID, 0, 0. Each element below
	// is a field's CONTENT; recoverSigner re-encodes it as an RLP string —
	// the exact shape legacyRLP signed.
	unsigned := append([][]byte{}, fields[:6]...)
	unsigned = append(unsigned, chainIDBig.Bytes(), nil, nil)
	from, err = recoverSigner(unsigned, r, s, recID)
	return from, to, data, err
}

// rlpItem decodes one RLP binary-string item, returning its content and the
// remaining bytes. List items inside a tx field list are an encoding error.
func rlpItem(b []byte) (item, rest []byte, err error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("rlp: truncated")
	}
	c := b[0]
	switch {
	case c < 0x80:
		return b[:1], b[1:], nil
	case c < 0xb8:
		n := int(c - 0x80)
		if len(b) < 1+n {
			return nil, nil, fmt.Errorf("rlp: short string")
		}
		return b[1 : 1+n], b[1+n:], nil
	case c < 0xc0:
		lenBytes := int(c - 0xb7)
		if len(b) < 1+lenBytes {
			return nil, nil, fmt.Errorf("rlp: short long-string length")
		}
		n64 := new(big.Int).SetBytes(b[1 : 1+lenBytes])
		if !n64.IsUint64() || int(n64.Uint64()) > len(b) {
			return nil, nil, fmt.Errorf("rlp: absurd string length")
		}
		n := int(n64.Uint64())
		if len(b) < 1+lenBytes+n {
			return nil, nil, fmt.Errorf("rlp: long string overruns input")
		}
		return b[1+lenBytes : 1+lenBytes+n], b[1+lenBytes+n:], nil
	default:
		return nil, nil, fmt.Errorf("rlp: unexpected list in tx fields")
	}
}

// recoverSigner concatenates the re-encoded pre-image, hashes it, and
// recovers the signer with the same btcec primitive spore's signer uses.
func recoverSigner(unsigned [][]byte, r, s *big.Int, recID uint) (string, error) {
	var payload []byte
	for _, f := range unsigned {
		payload = append(payload, rlpString(f)...)
	}
	payload = append(rlpLen(len(payload), 0xc0), payload...)
	sig := make([]byte, 65)
	sig[0] = byte(27 + recID)
	r.FillBytes(sig[1:33])
	s.FillBytes(sig[33:65])
	pub, _, err := becdsa.RecoverCompact(sig, keccak256(payload))
	if err != nil {
		return "", fmt.Errorf("stub: recover: %w", err)
	}
	return "0x" + hex.EncodeToString(keccak256(pub.SerializeUncompressed()[1:])[12:]), nil
}

// ---------- state transitions ----------

// applyTx mines one tx into a fresh block and replays the contract
// semantics, classified by calldata selector. Returns a JSON-RPC error
// string when the contract would revert.
func (c *stubChain) applyTx(tx *stubTx) string {
	c.height++
	tx.Block = c.height
	tx.Hash = txHashFor(c.height)
	c.txByHash[tx.Hash] = tx
	c.order = append(c.order, tx)
	if tx.To == "" {
		addr := createAddress(tx.From, c.nonce[tx.From])
		tx.Created = addr
		c.codeAt[addr] = true
		c.contract = addr
		return ""
	}
	target := strings.ToLower(tx.To)
	if !c.codeAt[target] {
		return "no code at " + target
	}
	if len(tx.Data) < 4 {
		return "empty calldata"
	}
	switch {
	case bytes.Equal(tx.Data[:4], selDeliver):
		return c.doDeliver(tx)
	case bytes.Equal(tx.Data[:4], selBurn):
		return c.doBurn(tx)
	default:
		return "unknown selector 0x" + hex.EncodeToString(tx.Data[:4])
	}
}

// deliver(address,bytes): selector(4) + to(32) + offset(32) + len(32) +
// payload — the exact calldata internal/evm's encodeDeliver builds.
func (c *stubChain) doDeliver(tx *stubTx) string {
	if len(tx.Data) < 100 {
		return "deliver: truncated calldata"
	}
	to := "0x" + hex.EncodeToString(tx.Data[16:36])
	if off := new(big.Int).SetBytes(tx.Data[36:68]).Uint64(); off != 64 {
		return fmt.Sprintf("deliver: unsupported bytes offset %d (want the ABI-standard 64)", off)
	}
	n := new(big.Int).SetBytes(tx.Data[68:100]).Uint64()
	if len(tx.Data) < 100+int(n) {
		return "deliver: payload shorter than declared length"
	}
	payload := make([]byte, n)
	copy(payload, tx.Data[100:100+n])
	if len(payload) == 0 {
		return "mailbox: empty payload"
	}
	if to == "0x0000000000000000000000000000000000000000" {
		return "mailbox: no zero recipient"
	}
	seq := c.nextSeq[to]
	c.nextSeq[to] = seq + 1
	c.msgs[to] = append(c.msgs[to], &msgEntry{from: tx.From, block: tx.Block, data: payload})
	c.emitInbox(to, tx.From, seq, payload, tx.Block)
	return ""
}

// burn(address,uint256): clears the payload, leaves the log, leaves
// length(to) alone. Matches the contract exactly.
func (c *stubChain) doBurn(tx *stubTx) string {
	if len(tx.Data) != 68 {
		return "burn: wrong calldata length"
	}
	to := "0x" + hex.EncodeToString(tx.Data[16:36])
	if to != tx.From {
		return "mailbox: only recipient"
	}
	seq := new(big.Int).SetBytes(tx.Data[36:68]).Uint64()
	list := c.msgs[to]
	if seq >= uint64(len(list)) {
		return "burn: no such message"
	}
	list[seq].data = nil
	list[seq].burned = true
	return ""
}

// emitInbox appends an Inbox log: four 32-byte topics (signature, to, from,
// seq) with addresses LEFT-padded — the exact shape decodeInboxLog in
// internal/evm/mailbox.go parses.
func (c *stubChain) emitInbox(to, from string, seq uint64, payload []byte, block uint64) {
	word := func(addr string) string {
		raw, _ := hex.DecodeString(strings.TrimPrefix(strings.ToLower(addr), "0x"))
		out := make([]byte, 32)
		copy(out[12:], raw)
		return "0x" + hex.EncodeToString(out)
	}
	seqWord := make([]byte, 32)
	new(big.Int).SetUint64(seq).FillBytes(seqWord)
	c.logs = append(c.logs, stubLog{
		Address:         c.contract,
		Topics:          []string{"0x" + hex.EncodeToString(inboxTopic), word(to), word(from), "0x" + hex.EncodeToString(seqWord)},
		Data:            "0x" + hex.EncodeToString(keccak256(payload)),
		BlockNumber:     "0x" + strconv.FormatUint(block, 16),
		TransactionHash: txHashFor(block),
	})
}

// txHashFor derives a stable 32-byte txid from the tx's block. Honest
// shortcut: it is not a keccak of the signed bytes (the stub would have to
// retain them). Every rehearsal assertion keys on contract STATE — empty-slot
// reads, Inbox logs, code presence — never on txid shape, which is why the
// shortcut is sound here and would not be on a real node.
func txHashFor(block uint64) string {
	b := bigEndian(block)
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return "0x" + hex.EncodeToString(out)
}

// txObject renders a mined tx the way eth_getTransactionByHash does, carrying
// the fields the burn reader needs: from, to (null on a creation), input, and
// the block it landed in.
func txObject(tx *stubTx) map[string]interface{} {
	obj := map[string]interface{}{
		"hash":        tx.Hash,
		"from":        tx.From,
		"input":       "0x" + hex.EncodeToString(tx.Data),
		"blockNumber": "0x" + strconv.FormatUint(tx.Block, 16),
	}
	if tx.To == "" {
		obj["to"] = nil
		obj["contractAddress"] = tx.Created
	} else {
		obj["to"] = tx.To
	}
	return obj
}

// blockObject summarizes a block with its transactions, oldest first. A real
// node's block carries a hash, and a reader that fetches it as a tx must get
// null back rather than a false match — so this hash is never a txid.
func (c *stubChain) blockObject(n uint64) map[string]interface{} {
	txs := []map[string]interface{}{}
	for _, tx := range c.order {
		if tx.Block == n {
			txs = append(txs, txObject(tx))
		}
	}
	return map[string]interface{}{
		"number":       "0x" + strconv.FormatUint(n, 16),
		"hash":         "0x" + hex.EncodeToString(keccak256([]byte("sepoliastub-block-"+strconv.FormatUint(n, 10)))),
		"transactions": txs,
	}
}

// createAddress is keccak256(rlp([sender, nonce]))[12:] — the same creation
// formula internal/evm/contract.go derives locally, so the stub's mined
// address must equal the deploy command's printed one or CI fails loudly.
func createAddress(from string, nonce uint64) string {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(from), "0x"))
	if err != nil || len(raw) != 20 {
		return ""
	}
	item1 := append([]byte{0x94}, raw...)
	item2 := rlpString(bigEndian(nonce))
	payload := append(append([]byte{}, item1...), item2...)
	return "0x" + hex.EncodeToString(keccak256(append(rlpLen(len(payload), 0xc0), payload...))[12:])
}

// ---------- JSON-RPC server ----------

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (c *stubChain) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		var req rpcReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "sepoliastub: bad json", http.StatusBadRequest)
			return
		}
		var id interface{}
		if len(req.ID) > 0 {
			_ = json.Unmarshal(req.ID, &id)
		}
		result, rpcErr := c.dispatch(req.Method, string(req.Params))
		if rpcErr != "" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32000, "message": rpcErr},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": id, "result": result,
		})
	})
}

func (c *stubChain) dispatch(method, rawParams string) (result interface{}, rpcErr string) {
	var params []json.RawMessage
	if rawParams != "" && rawParams != "null" && rawParams != "[]" {
		_ = json.Unmarshal([]byte(rawParams), &params)
	}
	arg := func(i int) string {
		if i < len(params) {
			return strings.Trim(string(params[i]), `"`)
		}
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch method {
	case "eth_chainId":
		return "0x" + strconv.FormatInt(chainID, 16), ""
	case "net_version":
		return strconv.Itoa(chainID), ""
	case "eth_gasPrice":
		return gasPriceHex, ""
	case "eth_blockNumber":
		return "0x" + strconv.FormatUint(c.height, 16), ""
	case "eth_getBalance":
		return startBalance, "" // faucet semantics: everyone funded
	case "eth_getTransactionCount":
		return "0x" + strconv.FormatUint(c.nonce[strings.ToLower(arg(0))], 16), ""
	case "eth_getCode":
		if c.codeAt[strings.ToLower(arg(0))] {
			return codeHex, ""
		}
		return "0x", ""
	case "eth_getTransactionByHash":
		// nil is the JSON-RPC null a real node answers for an unknown hash.
		tx, ok := c.txByHash[strings.ToLower(arg(0))]
		if !ok {
			return nil, ""
		}
		return txObject(tx), ""
	case "eth_getBlockByNumber":
		tag := strings.ToLower(arg(0))
		var n uint64
		switch tag {
		case "earliest":
			n = 0
		case "", "latest", "pending", "safe", "finalized":
			n = c.height
		default:
			parsed, err := strconv.ParseUint(strings.TrimPrefix(tag, "0x"), 16, 64)
			if err != nil {
				return nil, "unsupported block tag " + tag
			}
			n = parsed
		}
		if n > c.height {
			return nil, "" // null: that block does not exist yet
		}
		return c.blockObject(n), ""
	case "eth_estimateGas":
		// A simulation must never advance state — the burn-estimate branch
		// is the regression this guard exists for (an estimate that burned
		// for real would make the rehearsal's compost assertion lie).
		var obj map[string]interface{}
		if len(params) > 0 {
			_ = json.Unmarshal(params[0], &obj)
		}
		dataHex, _ := obj["data"].(string)
		raw, _ := hex.DecodeString(strings.TrimPrefix(strings.ToLower(dataHex), "0x"))
		to, _ := obj["to"].(string)
		switch {
		case strings.TrimSpace(to) == "" || strings.EqualFold(to, "0x"):
			return "0x3d090", "" // creation-shaped estimate
		case len(raw) >= 4 && bytes.Equal(raw[:4], selDeliver):
			return "0xf424", ""
		case len(raw) >= 4 && bytes.Equal(raw[:4], selBurn):
			if len(raw) < 68 {
				return nil, "burn: truncated calldata"
			}
			recipient := "0x" + hex.EncodeToString(raw[16:36])
			if len(c.msgs[recipient]) == 0 {
				// The documented node behavior behind the estimator's
				// BurnGasFallback: a fresh-slot burn cannot be estimated.
				return nil, "evm: execution reverted (burn of a missing message)"
			}
			return "0x7b0c", "" // a live estimate against a real slot
		default:
			return "0x5208", ""
		}
	case "eth_sendRawTransaction":
		var hexTx string
		if len(params) > 0 {
			_ = json.Unmarshal(params[0], &hexTx)
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(hexTx), "0x"))
		if err != nil || len(raw) == 0 {
			return nil, "bad raw tx hex"
		}
		from, to, data, err := decodeLegacyTx(raw)
		if err != nil {
			return nil, err.Error()
		}
		tx := &stubTx{From: strings.ToLower(from), To: strings.ToLower(to), Data: data}
		if rpcErr := c.applyTx(tx); rpcErr != "" {
			return nil, rpcErr
		}
		c.nonce[tx.From]++
		return tx.Hash, ""
	case "eth_sendTransaction":
		// params IS the one-object array (single unwrap) — the shape the
		// signing proxy's burn path sends and double-unwrap panics taught
		// the original stub to get right.
		var objs []map[string]interface{}
		_ = json.Unmarshal([]byte(rawParams), &objs)
		if len(objs) != 1 || objs[0] == nil {
			return nil, "eth_sendTransaction expects exactly one params object"
		}
		o := objs[0]
		from, _ := o["from"].(string)
		to, _ := o["to"].(string)
		dataHex, _ := o["data"].(string)
		raw, _ := hex.DecodeString(strings.TrimPrefix(strings.ToLower(dataHex), "0x"))
		tx := &stubTx{From: strings.ToLower(from), To: strings.ToLower(to), Data: raw}
		if rpcErr := c.applyTx(tx); rpcErr != "" {
			return nil, rpcErr
		}
		c.nonce[tx.From]++
		return tx.Hash, ""
	case "eth_getLogs":
		// params[0] IS the filter object (single unwrap — double-unwrap
		// into a slice was the original stub's panic).
		var filter struct {
			FromBlock string   `json:"fromBlock"`
			Address   string   `json:"address"`
			Topics    []string `json:"topics"`
		}
		if len(params) > 0 {
			_ = json.Unmarshal(params[0], &filter)
		}
		fromHeight := uint64(0)
		if f := strings.TrimPrefix(strings.ToLower(filter.FromBlock), "0x"); f != "" {
			if n, err := strconv.ParseUint(f, 16, 64); err == nil {
				fromHeight = n
			}
		}
		out := []stubLog{}
		for _, l := range c.logs {
			if block := mustHexUint(l.BlockNumber); block < fromHeight {
				continue
			}
			if filter.Address != "" && !strings.EqualFold(filter.Address, l.Address) {
				continue
			}
			match := true
			for i, want := range filter.Topics {
				if want == "" {
					continue
				}
				if i >= len(l.Topics) || !strings.EqualFold(want, l.Topics[i]) {
					match = false
					break
				}
			}
			if match {
				out = append(out, l)
			}
		}
		return out, ""
	case "eth_call":
		// read()/length() simulation. `from` matters: read() reverts unless
		// msg.sender == to (the recipient-only rule CI must keep proving).
		var obj map[string]interface{}
		if len(params) > 0 {
			_ = json.Unmarshal(params[0], &obj)
		}
		dataHex, _ := obj["data"].(string)
		raw, _ := hex.DecodeString(strings.TrimPrefix(strings.ToLower(dataHex), "0x"))
		from, _ := obj["from"].(string)
		if len(raw) < 68 {
			return nil, "eth_call: truncated calldata"
		}
		switch {
		case bytes.Equal(raw[:4], selLength):
			to := "0x" + hex.EncodeToString(raw[16:36])
			return "0x" + strconv.FormatUint(uint64(len(c.msgs[to])), 16), ""
		case bytes.Equal(raw[:4], selRead):
			to := "0x" + hex.EncodeToString(raw[16:36])
			seq := new(big.Int).SetBytes(raw[36:68]).Uint64()
			if strings.ToLower(from) != to {
				return nil, "execution reverted: mailbox: only recipient"
			}
			list := c.msgs[to]
			if seq >= uint64(len(list)) {
				return nil, "execution reverted: no such message"
			}
			entry := list[seq]
			return encodeReadResult(entry.from, entry.block, entry.data), ""
		default:
			return "0x", ""
		}
	default:
		return nil, "sepoliastub: method not simulated: " + method
	}
}

// encodeReadResult ABI-encodes read()'s return (address from, uint256
// blockNumber, bytes data): head words from + blockNumber + offset(96), then
// the bytes length + data. Three load-bearing details, each proven by the dry
// run's receiver loop: the offset sits at word2 (bytes 64:96) — where
// internal/evm's decodeReadResult reads it; its VALUE is 96 (the head is
// three words); and word1 carries the delivery block, which the real
// contract returns — dropping it shifts every later word and made the
// original dry run's ListIncoming silently skip every message.
func encodeReadResult(from string, block uint64, data []byte) string {
	fromWord := make([]byte, 32)
	raw, _ := hex.DecodeString(strings.TrimPrefix(strings.ToLower(from), "0x"))
	copy(fromWord[12:], raw)
	blockWord := make([]byte, 32)
	new(big.Int).SetUint64(block).FillBytes(blockWord)
	offWord := make([]byte, 32)
	new(big.Int).SetUint64(96).FillBytes(offWord)
	lenWord := make([]byte, 32)
	new(big.Int).SetUint64(uint64(len(data))).FillBytes(lenWord)
	buf := append(append(append(append(fromWord[:], blockWord[:]...), offWord[:]...), lenWord[:]...), data...)
	for len(buf)%32 != 0 {
		buf = append(buf, 0)
	}
	return "0x" + hex.EncodeToString(buf)
}

func mustHexUint(hexStr string) uint64 {
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(hexStr), "0x"), 16, 64)
	if err != nil {
		return 0
	}
	return n
}

func main() {
	addr := "127.0.0.1:8532"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	c := newStubChain()
	log.Printf("sepoliastub: serving EVM JSON-RPC on http://%s (chain id %d, stateful MyceliumMailbox simulation)", addr, chainID)
	log.Printf("sepoliastub: selectors deliver=%x burn=%x read=%x length=%x inbox=%x",
		selDeliver, selBurn, selRead, selLength, inboxTopic)
	if err := http.ListenAndServe(addr, c.handler()); err != nil {
		log.Fatalf("sepoliastub: %v", err)
	}
}
