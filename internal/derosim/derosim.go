// Package derosim is a local DERO wallet-RPC simulator for two-party soaks.
//
// It implements exactly the wallet-RPC surface spore uses — transfer,
// get_transfers, getaddress, getheight, getbalance, sc_invoke — plus a small
// honest state machine for the three relay-dex contracts (RelayHTLC,
// RelayDEX, RelayWrappedDero). The CONTRACTS are simulated with their DVM
// semantics (hash-verified claims, expiry-gated refunds, constant-product
// min-out enforcement, DERO/token deposits); the ring signatures and blocks
// are not simulated at all — a soak exercises spore's CLI, session, envelope,
// ledger, and store logic against contract-shaped money movement, not DERO's
// cryptography, which is derohe's to test.
//
// Addresses are the all-zero G1 point bech32-encoded (the canonical "empty"
// DERO address): it passes spore's own ValidateAddress decompression check,
// and the simulator is the only thing these addresses are ever sent to.
//
// Per-party state: a caller points its client at /w/alice or /w/bob and each
// wallet keeps its own address, balance, and transfer history. Contract
// state (HTLC locks, pool reserves, wDERO supply) is SHARED, because on a
// real chain the contracts are global.
package derosim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

// ZeroAddress is the bech32 encoding of the all-zero G1 compressed point:
// the canonical valid-but-empty DERO address (verified against spore's own
// address validator in derosim_test.go).
const ZeroAddress = "dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4"

// bn256FieldPrime mirrors dero's address.go modulus: p = 36u⁴+36u³+24u²+6u+1.
const bn256FieldPrime = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"

const deroBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const maxSimHeight = uint64(^uint64(0) >> 1)

var bech32Generator = [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// DeriveAddress mints a DISTINCT, VALID mainnet dero1 address for a seed:
// it searches curve points (x, y) on BN256 with a tiny modular-arithmetic
// loop and bech32-encodes the 34-byte payload [0x01 || x || y-selector].
// Distinct addresses matter: contract payouts credit the RECIPIENT address,
// so two wallets sharing one address would make routing map-order-random.
func DeriveAddress(seed []byte) string {
	modulus, _ := new(big.Int).SetString(bn256FieldPrime, 16)
	payload := make([]byte, 34)
	payload[0] = 1
	for i := uint64(0); ; i++ {
		h := sha256.Sum256(append(append([]byte(nil), seed...), byte(i), byte(i>>8)))
		x := new(big.Int).SetBytes(h[:])
		if x.Cmp(modulus) >= 0 {
			continue
		}
		rhs := new(big.Int).Mul(x, x)
		rhs.Mul(rhs, x)
		rhs.Add(rhs, big.NewInt(3))
		rhs.Mod(rhs, modulus)
		y := new(big.Int).ModSqrt(rhs, modulus)
		if y == nil {
			continue // not a quadratic residue: next candidate
		}
		copy(payload[1:33], h[:])
		payload[33] = byte(y.Bit(0))
		if _, err := dero.ValidateAddress(bech32Encode("dero", payload)); err != nil {
			continue // defensive: never hand out an invalid address
		}
		return bech32Encode("dero", payload)
	}
}

// bech32Encode encodes payload (8-bit bytes) as bech32 under hrp, mirroring
// dero's decoder (charset, polymod, constant 1).
func bech32Encode(hrp string, payload []byte) string {
	data := convertBits8to5(payload)
	values := make([]int, 0, len(data)+8)
	values = append(values, bech32HrpExpand(hrp)...)
	for _, v := range data {
		values = append(values, int(v))
	}
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := uint32(1)
	for _, v := range values {
		top := polymod >> 25
		polymod = (polymod&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if top&(1<<i) != 0 {
				polymod ^= bech32Generator[i]
			}
		}
	}
	chk := polymod ^ 1
	var check [6]byte
	for i := 0; i < 6; i++ {
		check[i] = byte((chk >> uint(5*(5-i))) & 31)
	}
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, v := range data {
		b.WriteByte(deroBech32Charset[v])
	}
	for _, v := range check {
		b.WriteByte(deroBech32Charset[v])
	}
	return b.String()
}

func bech32HrpExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for _, c := range []byte(hrp) {
		out = append(out, int(c>>5))
	}
	out = append(out, 0)
	for _, c := range []byte(hrp) {
		out = append(out, int(c&31))
	}
	return out
}

func convertBits8to5(b []byte) []byte {
	out := make([]byte, 0, len(b)*8/5+1)
	acc, bits := uint32(0), uint(0)
	for _, v := range b {
		acc = acc<<8 | uint32(v)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		out = append(out, byte(acc<<(5-bits)&31))
	}
	return out
}

// Sim is the shared chain + contract state behind every simulated wallet.
type Sim struct {
	mu sync.Mutex

	height  uint64
	nextSeq uint64

	balances map[string]*wallet // route -> wallet

	// Shared contract state (global, like on-chain contracts).
	htlcs map[[32]byte]*htlcState
	poolA uint64 // RelayDEX reserve of token A
	poolB uint64 // RelayDEX reserve of token B
	wdero uint64 // RelayWrappedDero total supply
	feeDS uint64 // accumulated dex fee (token side), observable

	// Contract IDs the simulated sc_invoke recognizes. An sc_invoke against
	// any other SCID is rejected, exactly like a wallet rejecting a call to
	// a contract that does not exist.
	HTLCSCID  string
	DEXSCID   string
	WDEROSCID string
}

type wallet struct {
	addr    string
	balance uint64
	tokens  map[string]uint64
	entries []Entry
}

type htlcState struct {
	amount    uint64
	funder    string
	recipient string
	expiry    uint64
	claimed   bool
	refunded  bool
}

// Entry mirrors dero.Entry for the get_transfers wire.
type Entry struct {
	Height         uint64           `json:"height"`
	TransactionPos int64            `json:"tpos"`
	Pos            int64            `json:"pos"`
	TopoHeight     int64            `json:"topoheight"`
	Incoming       bool             `json:"incoming"`
	TXID           string           `json:"txid"`
	Sender         string           `json:"sender"`
	Amount         uint64           `json:"amount"`
	PayloadRPC     anchor.Arguments `json:"payload_rpc"`
}

// New builds a simulator with the given contract IDs. Pool liquidity is
// seeded so DEXSwap has reserves to trade against.
func New(htlcSCID, dexSCID, wderoSCID string) *Sim {
	return &Sim{
		balances:  map[string]*wallet{},
		htlcs:     map[[32]byte]*htlcState{},
		HTLCSCID:  htlcSCID,
		DEXSCID:   dexSCID,
		WDEROSCID: wderoSCID,
		// Constant-product reserves: 1_000_000_00000000 of each side
		// (1M whole units at 5 decimals). A small trade moves the price
		// negligibly; min-out bounds are enforced against the real math.
		poolA: 1_000_000 * 100_000,
		poolB: 1_000_000 * 100_000,
	}
}

// AddWallet provisions a simulated wallet at the given route (e.g. "alice")
// with its own deterministic address and test liquidity for the seeded tA/tB
// pool. Re-adding a route leaves its balances and history intact.
func (s *Sim) AddWallet(route string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(route) == "" {
		return
	}
	if _, ok := s.balances[route]; ok {
		return
	}
	s.balances[route] = &wallet{
		addr: DeriveAddress([]byte(route)), balance: 1_000_000 * 100_000,
		tokens: map[string]uint64{"ta": 1_000_000 * 100_000, "tb": 1_000_000 * 100_000},
	}
}

// Address reports a wallet's simulated address ("" for unknown routes).
func (s *Sim) Address(route string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.balances[route]; ok {
		return w.addr
	}
	return ""
}

// Handler returns the HTTP handler serving every wallet route. Point a
// dero.Client at http://127.0.0.1:PORT/w/<route> (NormalizeWalletRPCURL
// appends /json_rpc).
func (s *Sim) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := ""
		if rest, ok := strings.CutPrefix(r.URL.Path, "/w/"); ok {
			route = strings.TrimSuffix(rest, "/json_rpc")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeRPCError(w, -32700, "read: "+err.Error())
			return
		}
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      string          `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeRPCError(w, -32700, "bad json")
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.balances[route]; !ok {
			writeRPCError(w, 40, "no such wallet: "+route)
			return
		}
		result, rpcErr := s.dispatch(route, req.Method, req.Params)
		if rpcErr != nil {
			writeRPCError(w, rpcErr.code, rpcErr.message)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID, "result": result,
		})
	})
}

type rpcError struct {
	code    int
	message string
}

func writeRPCError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": "0",
		"error": map[string]interface{}{"code": code, "message": msg},
	})
}

func (s *Sim) dispatch(route, method string, params json.RawMessage) (interface{}, *rpcError) {
	switch method {
	case "getaddress":
		return map[string]string{"address": s.balances[route].addr}, nil
	case "getheight":
		return map[string]uint64{"height": s.height}, nil
	case "getbalance":
		w := s.balances[route]
		return map[string]interface{}{
			"balance": w.balance, "unlocked_balance": w.balance,
			"balance_string": fmt.Sprintf("%d", w.balance),
		}, nil
	case "get_transfers":
		var p struct {
			In        bool   `json:"in"`
			Out       bool   `json:"out"`
			Coinbase  bool   `json:"coinbase"`
			MinHeight uint64 `json:"min_height"`
		}
		_ = json.Unmarshal(params, &p)
		entries := []Entry{}
		for _, e := range s.balances[route].entries {
			if !(e.Incoming && p.In || !e.Incoming && p.Out) {
				continue
			}
			if e.Height < p.MinHeight {
				continue
			}
			entries = append(entries, e)
		}
		return map[string]interface{}{"entries": entries}, nil
	case "transfer":
		return s.doTransfer(route, params)
	case "sc_invoke":
		return s.doInvokeSC(route, params)
	default:
		return nil, &rpcError{-32601, "method not found: " + method}
	}
}

func (s *Sim) mintTxID() string {
	s.nextSeq++
	return fmt.Sprintf("sim-tx-%08x", s.nextSeq)
}

// doTransfer executes a transfer POST: move value, record the payload entry
// in the RECIPIENT's history (the sender gets a symmetric outgoing record).
// The simulator's ring members are implicit; every transfer is a single
// destination, which is all spore posts.
func (s *Sim) doTransfer(route string, params json.RawMessage) (interface{}, *rpcError) {
	var p struct {
		Transfers []struct {
			Destination string           `json:"destination"`
			Amount      uint64           `json:"amount"`
			PayloadRPC  anchor.Arguments `json:"payload_rpc"`
		} `json:"transfers"`
		Ringsize uint64 `json:"ringsize"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{-32602, "bad transfer params"}
	}
	if len(p.Transfers) == 0 {
		return nil, &rpcError{-32602, "no transfers"}
	}
	w := s.balances[route]
	var total uint64
	credits := make(map[*wallet]uint64)
	for _, t := range p.Transfers {
		if t.Amount > w.balance-total {
			return nil, &rpcError{-4, "insufficient funds"}
		}
		total += t.Amount
		if dst, ok := s.walletByAddr(t.Destination); ok {
			credits[dst] += t.Amount
		}
	}
	for dst, credit := range credits {
		balance := dst.balance
		if dst == w {
			balance -= total
		}
		if math.MaxUint64-balance < credit {
			return nil, &rpcError{-4, "recipient balance would overflow"}
		}
	}
	if s.height >= maxSimHeight || s.nextSeq == math.MaxUint64 {
		return nil, &rpcError{-1, "simulated chain height or transaction sequence exhausted"}
	}

	s.height++
	txid := s.mintTxID()
	w.balance -= total
	for dst, credit := range credits {
		dst.balance += credit
	}

	for _, t := range p.Transfers {
		entry := Entry{
			Height: s.height, TopoHeight: int64(s.height),
			TXID: txid, Sender: w.addr, Amount: t.Amount, Incoming: true,
			PayloadRPC: t.PayloadRPC,
		}
		if dst, ok := s.walletByAddr(t.Destination); ok {
			dst.entries = append(dst.entries, entry)
		}
		// Sender-side outgoing record (GetTransfers Out:true consumers).
		w.entries = append(w.entries, Entry{
			Height: s.height, TopoHeight: int64(s.height),
			TXID: txid, Sender: w.addr, Amount: t.Amount, Incoming: false,
			PayloadRPC: t.PayloadRPC,
		})
	}
	return map[string]string{"txid": txid}, nil
}

func (s *Sim) walletByAddr(addr string) (*wallet, bool) {
	for _, w := range s.balances {
		if w.addr == addr {
			return w, true
		}
	}
	return nil, false
}

type scInvokeParams struct {
	SCID           string           `json:"scid"`
	SCRpc          anchor.Arguments `json:"sc_rpc"`
	SCDERODeposit  uint64           `json:"sc_dero_deposit"`
	SCTOKENDeposit uint64           `json:"sc_token_deposit"`
	Ringsize       uint64           `json:"ringsize"`
	Fees           uint64           `json:"fees"`
}

func argValue(args anchor.Arguments, name string) (interface{}, bool) {
	for _, a := range args {
		if a.Name == name {
			return a.Value, true
		}
	}
	return nil, false
}

func argString(args anchor.Arguments, name string) string {
	v, ok := argValue(args, name)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func argUint64(args anchor.Arguments, name string) uint64 {
	v, ok := argValue(args, name)
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case uint64:
		return n
	case json.Number:
		if value, err := strconv.ParseUint(string(n), 10, 64); err == nil {
			return value
		}
	}
	return 0
}

func (s *Sim) doInvokeSC(route string, params json.RawMessage) (interface{}, *rpcError) {
	var p scInvokeParams
	dec := json.NewDecoder(strings.NewReader(string(params)))
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return nil, &rpcError{-32602, "bad sc_invoke params"}
	}
	w := s.balances[route]
	if p.SCID != s.HTLCSCID && p.SCID != s.DEXSCID && p.SCID != s.WDEROSCID {
		return nil, &rpcError{-2, "sc_invoke: unknown contract " + p.SCID}
	}
	if p.SCDERODeposit > w.balance {
		return nil, &rpcError{-4, "insufficient funds"}
	}
	if s.height >= maxSimHeight || s.nextSeq == math.MaxUint64 {
		return nil, &rpcError{-1, "simulated chain height or transaction sequence exhausted"}
	}

	// Contracts evaluate expiry against the block this invoke would enter.
	// Their methods validate before mutating; rejected calls roll the candidate
	// height back and do not consume a transaction sequence.
	s.height++
	if err := s.invokeContract(route, &p); err != nil {
		s.height--
		return nil, &rpcError{-1, err.Error()}
	}
	txid := s.mintTxID()
	return map[string]string{"txid": txid}, nil
}

func (s *Sim) invokeContract(route string, p *scInvokeParams) error {
	switch p.SCID {
	case s.HTLCSCID:
		if p.SCTOKENDeposit != 0 {
			return fmt.Errorf("HTLC does not accept a token deposit")
		}
		return s.htlcInvoke(route, p)
	case s.DEXSCID:
		return s.dexInvoke(route, p)
	case s.WDEROSCID:
		return s.wderoInvoke(route, p)
	default:
		return fmt.Errorf("unknown contract %s", p.SCID)
	}
}

// htlcInvoke simulates RelayHTLC.dvm: Fund (value rides the invoke deposit),
// Claim (preimage must hash to h, before expiry), Refund (after expiry).
// args names mirror the DVM: h, recipient, exp, pre.
func (s *Sim) htlcInvoke(route string, p *scInvokeParams) error {
	w := s.balances[route]
	var hash [32]byte
	if raw, err := hex.DecodeString(argString(p.SCRpc, "h")); err == nil && len(raw) == 32 {
		copy(hash[:], raw)
	}
	switch {
	case argString(p.SCRpc, "recipient") != "" && argUint64(p.SCRpc, "exp") != 0 && p.SCDERODeposit > 0:
		// Fund: lock the deposit behind the hash.
		if p.SCDERODeposit > w.balance {
			return fmt.Errorf("insufficient funds for HTLC fund")
		}
		if _, exists := s.htlcs[hash]; exists {
			return fmt.Errorf("HTLC hash already funded")
		}
		if argString(p.SCRpc, "h") == "" || len(hash) != 32 || hash == [32]byte{} {
			return fmt.Errorf("fund requires a 32-byte hash h")
		}
		w.balance -= p.SCDERODeposit
		s.htlcs[hash] = &htlcState{
			amount:    p.SCDERODeposit,
			funder:    route,
			recipient: argString(p.SCRpc, "recipient"),
			expiry:    argUint64(p.SCRpc, "exp"),
		}
		return nil
	case argString(p.SCRpc, "pre") != "":
		// Claim: sha256(preimage) must equal the funded hash, before expiry.
		st, ok := s.htlcs[hash]
		if !ok {
			return fmt.Errorf("no HTLC funded under this hash")
		}
		if st.claimed || st.refunded {
			return fmt.Errorf("HTLC already settled")
		}
		if s.height > st.expiry {
			return fmt.Errorf("HTLC expired at %d (height %d) — refund only", st.expiry, s.height)
		}
		var pre [32]byte
		if raw, err := hex.DecodeString(argString(p.SCRpc, "pre")); err != nil || len(raw) != 32 {
			return fmt.Errorf("claim pre must be 32 bytes")
		} else {
			copy(pre[:], raw)
		}
		// The DVM computes sha256(preimage) IN CONTRACT (DVM has SHA256());
		// the CLI verifies the same pairing locally before spending postage.
		if sha256.Sum256(pre[:]) != hash {
			return fmt.Errorf("sha256(pre) != h — contract would reject the claim")
		}
		if c, ok := s.walletByAddr(st.recipient); ok {
			if math.MaxUint64-c.balance < st.amount {
				return fmt.Errorf("HTLC payout would overflow recipient balance")
			}
			c.balance += st.amount
		}
		st.claimed = true
		return nil
	default:
		// Refund: only after expiry.
		st, ok := s.htlcs[hash]
		if !ok {
			return fmt.Errorf("no HTLC funded under this hash")
		}
		if st.claimed || st.refunded {
			return fmt.Errorf("HTLC already settled")
		}
		if s.height <= st.expiry {
			return fmt.Errorf("HTLC not yet expired (exp %d, height %d) — refund refuses", st.expiry, s.height)
		}
		funder, ok := s.balances[st.funder]
		if !ok {
			return fmt.Errorf("HTLC funder wallet is not available")
		}
		if math.MaxUint64-funder.balance < st.amount {
			return fmt.Errorf("HTLC refund would overflow funder balance")
		}
		funder.balance += st.amount
		st.refunded = true
		return nil
	}
}

// dexInvoke simulates RelayDEX.dvm: constant-product swap with min-out ("mo")
// enforcement and the in-contract fee. Token deposits ride sc_token_deposit.
func (s *Sim) dexInvoke(route string, p *scInvokeParams) error {
	if p.SCDERODeposit != 0 {
		return fmt.Errorf("DEX does not accept a DERO deposit")
	}
	ta := argString(p.SCRpc, "ta")
	tb := argString(p.SCRpc, "tb")
	mo := argUint64(p.SCRpc, "mo")
	if ta == "" || tb == "" {
		return fmt.Errorf("swap requires ta and tb")
	}
	if strings.EqualFold(ta, tb) {
		return fmt.Errorf("ta and tb must differ")
	}
	if p.SCTOKENDeposit == 0 {
		return fmt.Errorf("swap requires a token deposit (sc_token_deposit)")
	}
	w := s.balances[route]
	inputKey, outputKey := strings.ToLower(ta), strings.ToLower(tb)
	if p.SCTOKENDeposit > w.tokens[inputKey] {
		return fmt.Errorf("swap input %d %s exceeds simulated wallet balance %d", p.SCTOKENDeposit, ta, w.tokens[inputKey])
	}

	// The soak models one tA/tB pool. Refuse other pairs rather than report a
	// successful trade while mutating the wrong reserves.
	var reserveIn, reserveOut uint64
	switch {
	case strings.EqualFold(ta, "tA") && strings.EqualFold(tb, "tB"):
		reserveIn, reserveOut = s.poolA, s.poolB
	case strings.EqualFold(ta, "tB") && strings.EqualFold(tb, "tA"):
		reserveIn, reserveOut = s.poolB, s.poolA
	default:
		return fmt.Errorf("unsupported simulated pair %s->%s (only tA/tB is seeded)", ta, tb)
	}
	if math.MaxUint64-reserveIn < p.SCTOKENDeposit {
		return fmt.Errorf("swap input overflows pool reserve")
	}
	fee := p.SCTOKENDeposit/1000*3 + p.SCTOKENDeposit%1000*3/1000
	inAfterFee := p.SCTOKENDeposit - fee
	denominator := reserveIn + inAfterFee
	if inAfterFee == 0 || denominator < reserveIn {
		return fmt.Errorf("swap input is too large")
	}
	numerator := new(big.Int).Mul(new(big.Int).SetUint64(reserveOut), new(big.Int).SetUint64(inAfterFee))
	out := numerator.Quo(numerator, new(big.Int).SetUint64(denominator)).Uint64()
	if out == 0 || out < mo {
		return fmt.Errorf("swap would output %d, below min-out %d — contract rejects", out, mo)
	}
	if math.MaxUint64-w.tokens[outputKey] < out {
		return fmt.Errorf("swap output would overflow simulated wallet balance")
	}
	if math.MaxUint64-s.feeDS < fee {
		return fmt.Errorf("swap fee total would overflow")
	}

	w.tokens[inputKey] -= p.SCTOKENDeposit
	w.tokens[outputKey] += out
	s.feeDS += fee
	if strings.EqualFold(ta, "tA") {
		s.poolA += p.SCTOKENDeposit
		s.poolB -= out
	} else {
		s.poolB += p.SCTOKENDeposit
		s.poolA -= out
	}
	return nil
}

// wderoInvoke simulates RelayWrappedDero.dvm: wrap (DERO deposit mints
// wDERO 1:1, debiting the wrapper's wallet like any contract deposit),
// unwrap (token deposit burns wDERO for DERO).
func (s *Sim) wderoInvoke(route string, p *scInvokeParams) error {
	if p.SCDERODeposit > 0 && p.SCTOKENDeposit > 0 {
		return fmt.Errorf("wrap and unwrap are distinct: send exactly one deposit")
	}
	if p.SCDERODeposit > 0 {
		w := s.balances[route]
		if p.SCDERODeposit > w.balance {
			return fmt.Errorf("insufficient funds for wrap")
		}
		if math.MaxUint64-s.wdero < p.SCDERODeposit {
			return fmt.Errorf("wrap would overflow wDERO supply")
		}
		w.balance -= p.SCDERODeposit
		w.tokens["wdero"] += p.SCDERODeposit
		s.wdero += p.SCDERODeposit
		return nil
	}
	if p.SCTOKENDeposit > 0 {
		w := s.balances[route]
		if p.SCTOKENDeposit > w.tokens["wdero"] {
			return fmt.Errorf("unwrap %d exceeds wallet wDERO balance %d", p.SCTOKENDeposit, w.tokens["wdero"])
		}
		if math.MaxUint64-w.balance < p.SCTOKENDeposit {
			return fmt.Errorf("unwrap would overflow wallet balance")
		}
		w.tokens["wdero"] -= p.SCTOKENDeposit
		s.wdero -= p.SCTOKENDeposit
		w.balance += p.SCTOKENDeposit
		return nil
	}
	return fmt.Errorf("wDERO invoke requires a DERO deposit (wrap) or token deposit (unwrap)")
}

// State queries for harness assertions: balances, HTLC outcomes, pool
// reserves, and wDERO supply — the soak checks settle against these.
func (s *Sim) Balance(route string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.balances[route]; ok {
		return w.balance
	}
	return 0
}

func (s *Sim) TokenBalance(route, token string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.balances[route]; ok {
		return w.tokens[strings.ToLower(token)]
	}
	return 0
}

func (s *Sim) HTLCSettled(hashHex string) (claimed, refunded bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := hex.DecodeString(hashHex)
	if err != nil || len(raw) != 32 {
		return false, false, false
	}
	var h [32]byte
	copy(h[:], raw)
	st, exists := s.htlcs[h]
	if !exists {
		return false, false, false
	}
	return st.claimed, st.refunded, true
}

func (s *Sim) PoolReserves() (a, b uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.poolA, s.poolB
}

func (s *Sim) WDEROSupply() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wdero
}

// HTLCInfo is one HTLC's settled/funded state for harness inspection.
type HTLCInfo struct {
	HashHex   string `json:"hash_hex"`
	Amount    uint64 `json:"amount"`
	Recipient string `json:"recipient"`
	Expiry    uint64 `json:"expiry"`
	Claimed   bool   `json:"claimed"`
	Refunded  bool   `json:"refunded"`
}

// State is the full observable simulator state, JSON-shaped for the
// /debug/state route the soak driver polls.
type State struct {
	Addresses     map[string]string            `json:"addresses"`
	Balances      map[string]uint64            `json:"balances"`
	TokenBalances map[string]map[string]uint64 `json:"token_balances"`
	Height        uint64                       `json:"height"`
	PoolA         uint64                       `json:"pool_a"`
	PoolB         uint64                       `json:"pool_b"`
	WDERO         uint64                       `json:"wdero_supply"`
	FeeDS         uint64                       `json:"dex_fee_units"`
	HTLCs         []HTLCInfo                   `json:"htlcs"`
}

// State snapshots everything the soak asserts against.
func (s *Sim) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := State{
		Addresses: map[string]string{}, Balances: map[string]uint64{},
		TokenBalances: map[string]map[string]uint64{},
		PoolA:         s.poolA, PoolB: s.poolB, WDERO: s.wdero, FeeDS: s.feeDS,
		Height: s.height,
	}
	for name, w := range s.balances {
		st.Addresses[name] = w.addr
		st.Balances[name] = w.balance
		tokens := make(map[string]uint64, len(w.tokens))
		for token, balance := range w.tokens {
			tokens[token] = balance
		}
		st.TokenBalances[name] = tokens
	}
	for h, v := range s.htlcs {
		st.HTLCs = append(st.HTLCs, HTLCInfo{
			HashHex: hex.EncodeToString(h[:]), Amount: v.amount,
			Recipient: v.recipient, Expiry: v.expiry,
			Claimed: v.claimed, Refunded: v.refunded,
		})
	}
	return st
}

// Bump advances the simulated block height by n (the expiry knob the
// refund test drives through /debug/bump).
func (s *Sim) Bump(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.height >= maxSimHeight || n > maxSimHeight-s.height {
		s.height = maxSimHeight
		return
	}
	s.height += n
}

// WaitUntil polls cond every 200ms until it holds or the context expires.
// Soak drivers use it to wait for chain-visible effects without sleeps.
func WaitUntil(ctx context.Context, d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
		}
	}
	return cond()
}
