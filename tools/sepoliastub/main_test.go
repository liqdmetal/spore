package main

// The stub's watch on the surface scripts/evm-burn-txid.sh reads.
//
// The E2 receive path's burn is deliberately unlogged, so the txid has to be
// read back off the chain — and the offline rehearsal smoke that runs the whole
// funded path against this stub is a dispatch-only CI job. Without a test here,
// a change to eth_getTransactionByHash / eth_getBlockByNumber would break a job
// nobody runs on a push, and the first symptom would be a rehearsal that cannot
// name the burn it just proved. These pin the contract the reader consumes:
// field names, the null answers it depends on, and the block window it scans.
//
// The last test closes the loop by running the REAL reader script against this
// stub over HTTP, so the two cannot drift apart silently either.

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

const (
	burnStubSender  = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
	burnStubMailbox = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
)

func word20(addr string) []byte {
	raw, _ := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	out := make([]byte, 32)
	copy(out[12:], raw)
	return out
}

func wordU64(n uint64) []byte {
	out := make([]byte, 32)
	new(big.Int).SetUint64(n).FillBytes(out)
	return out
}

// burnOnStub mines one burn-shaped tx against a live slot, the way the receive
// path's chain.Watch does, and returns the chain plus that tx's hash.
func burnOnStub(t *testing.T) (*stubChain, string) {
	t.Helper()
	c := newStubChain()
	c.contract = burnStubMailbox
	c.codeAt[burnStubMailbox] = true
	c.msgs[burnStubSender] = []*msgEntry{{from: "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a", block: c.height, data: []byte("payload")}}
	c.nextSeq[burnStubSender] = 1

	data := make([]byte, 0, 68)
	data = append(data, selBurn[:]...)
	data = append(data, word20(burnStubSender)...) // the recipient's own slot: msg.sender == to
	data = append(data, wordU64(0)...)

	res, rpcErr := c.dispatch("eth_sendTransaction",
		`[{"from":"`+burnStubSender+`","to":"`+burnStubMailbox+`","data":"0x`+hex.EncodeToString(data)+`"}]`)
	if rpcErr != "" {
		t.Fatalf("the stub refused a well-formed burn: %s", rpcErr)
	}
	hash, _ := res.(string)
	if !strings.HasPrefix(hash, "0x") || len(hash) != 66 {
		t.Fatalf("the stub returned %#v for a burn, want a 32-byte tx hash", res)
	}
	return c, hash
}

// resultJSON dispatches a method and decodes its result as an object. A nil
// return means the stub answered JSON-RPC null, which is a real answer here:
// both methods use it for "no such tx" and "that block does not exist".
func resultJSON(t *testing.T, c *stubChain, method, params string) map[string]interface{} {
	t.Helper()
	res, rpcErr := c.dispatch(method, params)
	if rpcErr != "" {
		t.Fatalf("%s: unexpected rpc error: %s", method, rpcErr)
	}
	if res == nil {
		return nil
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("%s: marshal result: %v", method, err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: result is not an object (%s): %v", method, raw, err)
	}
	return out
}

func TestStubServesMinedTxByHash(t *testing.T) {
	c, hash := burnOnStub(t)

	tx := resultJSON(t, c, "eth_getTransactionByHash", `["`+hash+`"]`)
	if tx == nil {
		t.Fatalf("eth_getTransactionByHash(%s) answered null for a tx the stub just mined", hash)
	}
	if tx["from"] != burnStubSender {
		t.Errorf("from = %v, want %s", tx["from"], burnStubSender)
	}
	if tx["to"] != burnStubMailbox {
		t.Errorf("to = %v, want %s", tx["to"], burnStubMailbox)
	}
	input, _ := tx["input"].(string)
	if !strings.HasPrefix(input, "0x"+hex.EncodeToString(selBurn[:])) {
		t.Errorf("input = %q, want the burn selector — the reader classifies by it", input)
	}
	if want := "0x" + strconv.FormatUint(c.height, 16); tx["blockNumber"] != want {
		t.Errorf("blockNumber = %v, want %s (the deliver-block bound the reader starts from)", tx["blockNumber"], want)
	}
}

func TestStubTxByHashIsNullForUnknownAndForABlockHash(t *testing.T) {
	c, _ := burnOnStub(t)

	unknown := "0x" + strings.Repeat("00", 32)
	if got := resultJSON(t, c, "eth_getTransactionByHash", `["`+unknown+`"]`); got != nil {
		t.Errorf("an unknown hash answered %v, want null", got)
	}

	// The reader fetches every "hash" the block JSON carries, and a real block
	// carries its own. If a block hash resolved as a tx, the reader could
	// mistake a block for a burn.
	blk := resultJSON(t, c, "eth_getBlockByNumber", `["latest",true]`)
	blockHash, _ := blk["hash"].(string)
	if !strings.HasPrefix(blockHash, "0x") {
		t.Fatalf("the block carries no hash, so this guard checked nothing: %v", blk)
	}
	if got := resultJSON(t, c, "eth_getTransactionByHash", `["`+blockHash+`"]`); got != nil {
		t.Errorf("a block hash resolved as a transaction (%v) — the burn reader would read a block as a burn", got)
	}
}

func TestStubBlockByNumberCarriesItsTransactions(t *testing.T) {
	c, hash := burnOnStub(t)
	n := "0x" + strconv.FormatUint(c.height, 16)

	blk := resultJSON(t, c, "eth_getBlockByNumber", `["`+n+`",true]`)
	if blk["number"] != n {
		t.Errorf("number = %v, want %s", blk["number"], n)
	}
	txs, _ := blk["transactions"].([]interface{})
	if len(txs) != 1 {
		t.Fatalf("block %s carries %d transactions, want exactly the one burn", n, len(txs))
	}
	first, _ := txs[0].(map[string]interface{})
	if first["hash"] != hash {
		t.Errorf("the block's transaction is %v, want the burn %s", first["hash"], hash)
	}

	// Past the head is null, not an empty block: that is how the reader's scan
	// window ends without inventing a burn.
	if got := resultJSON(t, c, "eth_getBlockByNumber", `["0xffffffff",true]`); got != nil {
		t.Errorf("a block above the head answered %v, want null", got)
	}
	// earliest is block 0, long before the first tx mines.
	if got := resultJSON(t, c, "eth_getBlockByNumber", `["earliest",true]`); got == nil || got["number"] != "0x0" {
		t.Errorf("earliest answered %v, want block 0x0", got)
	}
}

// TestBurnReaderFindsTheStubsBurn runs scripts/evm-burn-txid.sh — the real
// reader the rehearsal uses — against this stub over HTTP. It is the one check
// here that runs on every push and exercises BOTH sides of the contract:
// calldata shape, JSON field names, the block window and the null answers.
func TestBurnReaderFindsTheStubsBurn(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the reader is a shell script")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available; the reader talks JSON-RPC with curl")
	}
	c, hash := burnOnStub(t)
	srv := httptest.NewServer(c.handler())
	defer srv.Close()

	// cwd is tools/sepoliastub, so the script is two levels up.
	const reader = "../../scripts/evm-burn-txid.sh"
	run := func(fromBlock string) (string, error) {
		out, err := exec.Command("bash", reader,
			"-rpc", srv.URL,
			"-mailbox", burnStubMailbox,
			"-recipient", burnStubSender,
			"-from-block", fromBlock,
		).CombinedOutput()
		return string(out), err
	}

	// Two blocks: the empty one before the burn, and the burn's own — so the
	// scan has to walk a block with no transactions without calling it an error.
	before := "0x" + strconv.FormatUint(c.height-1, 16)
	out, err := run(before)
	if err != nil {
		t.Fatalf("the reader failed against the stub (%v): %s", err, out)
	}
	if !strings.Contains(out, hash) {
		t.Fatalf("the reader did not name the stub's burn %s, it said: %s", hash, out)
	}

	// And a window that starts after the burn must refuse, never report the
	// burn it was not asked about.
	after := "0x" + strconv.FormatUint(c.height+1, 16)
	if out, err := run(after); err == nil {
		t.Fatalf("the reader accepted a window past the burn and said: %s", out)
	}
}
