package evm

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/liqdmetal/spore/internal/chain"
	"golang.org/x/crypto/sha3"
)

// This file wires the MyceliumMailbox contract (contracts/MyceliumMailbox.sol)
// into the EVM backend as the robust, log-based delivery path.
//
// Instead of block-scanning every recent block for txs addressed to us, a
// recipient with a mailbox contract address does:
//
//	PostPayload  -> eth_sendTransaction { to: <mailbox>, data: deliver(to, payload) }
//	                The contract stores the opaque m³ envelope per recipient and
//	                emits  Inbox(to, from, seq, cid).
//	ListIncoming -> eth_getLogs(Inbox topic[1] == ourAddress) gives (from, seq);
//	                the actual payload bytes are fetched via
//	                eth_call { from: us, to: mailbox, data: read(to, seq) }.
//
// The ABI is hand-rolled (no go-ethereum dependency): function selector =
// keccak256(sig)[:4], addresses are 32-byte right-aligned words, and bytes is
// (offset, length, data) with 32-byte alignment. keccak256 comes from
// golang.org/x/crypto/sha3 which is already a module dependency.

// sigs and computed selectors/event topics. Computed once via keccak256.
var (
	mailboxDeliverSig = "deliver(address,bytes)"
	mailboxReadSig    = "read(address,uint256)"
	mailboxBurnSig    = "burn(address,uint256)"
	mailboxInboxSig   = "Inbox(address,address,uint256,bytes32)"

	deliverSelector [4]byte
	readSelector    [4]byte
	burnSelector    [4]byte
	inboxTopic      [32]byte
)

func init() {
	deliverSelector = sel4(mailboxDeliverSig)
	readSelector = sel4(mailboxReadSig)
	burnSelector = sel4(mailboxBurnSig)
	inboxTopic = keccak32(mailboxInboxSig)
}

func keccak32(s string) [32]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write([]byte(s))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func sel4(s string) [4]byte {
	k := keccak32(s)
	var out [4]byte
	copy(out[:], k[:4])
	return out
}

func bytes32ToHex(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }
func addrTopicToHex(b [32]byte) string {
	return "0x" + strings.ToLower(hex.EncodeToString(b[:]))
}

// padAddr20 returns an ABI word (32 bytes) holding a 20-byte address, right-aligned.
func padAddr20(addr string) ([32]byte, error) {
	var out [32]byte
	a := strings.TrimPrefix(addr, "0x")
	raw, err := hex.DecodeString(a)
	if err != nil {
		return out, fmt.Errorf("evm mailbox: bad address %q: %w", addr, err)
	}
	if len(raw) != 20 {
		return out, fmt.Errorf("evm mailbox: address %q is %d bytes, want 20", addr, len(raw))
	}
	copy(out[12:], raw) // right-align in 32-byte word
	return out, nil
}

func uintWord(v uint64) [32]byte {
	var out [32]byte
	b := new(big.Int).SetUint64(v)
	b.FillBytes(out[:]) // big-endian, left-padded to 32 bytes
	return out
}

// encodeDeliver builds the calldata for `deliver(address to, bytes data)`:
// selector || word(to) || word(offset=64) || word(len) || data(padded to 32).
func encodeDeliver(to string, data []byte) (string, error) {
	toWord, err := padAddr20(to)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 0, 4+32*3+len(data))
	buf = append(buf, deliverSelector[:]...)
	buf = append(buf, toWord[:]...)
	off := uintWord(64)
	buf = append(buf, off[:]...) // offset of the dynamic bytes arg
	ln := uintWord(uint64(len(data)))
	buf = append(buf, ln[:]...)
	buf = append(buf, data...)
	// pad to 32-byte boundary
	for len(buf)%32 != 0 {
		buf = append(buf, 0)
	}
	return "0x" + hex.EncodeToString(buf), nil
}

// encodeRead builds the calldata for `read(address to, uint256 seq)`.
func encodeRead(to string, seq uint64) (string, error) {
	toWord, err := padAddr20(to)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 0, 4+64)
	buf = append(buf, readSelector[:]...)
	buf = append(buf, toWord[:]...)
	sq := uintWord(seq)
	buf = append(buf, sq[:]...)
	return "0x" + hex.EncodeToString(buf), nil
}

// ethLog is the minimal eth_getLogs result shape.
type ethLog struct {
	Address         string   `json:"address"`
	Topics          []string `json:"topics"`
	Data            string   `json:"data"`
	BlockNumber     string   `json:"blockNumber"`
	TransactionHash string   `json:"transactionHash"`
}

// ethLogsResult holds eth_getLogs output.
type ethLogsResult []ethLog

// decodeInboxLog parses one Inbox(to,from,seq,cid) log. Returns the sender,
// sequence, and block number. ok=false if the log isn't an Inbox for us.
func decodeInboxLog(l *ethLog) (sender string, seq uint64, block uint64, ok bool) {
	if len(l.Topics) != 4 {
		return "", 0, 0, false
	}
	if !strings.EqualFold(l.Topics[0], bytes32ToHex(inboxTopic)) {
		return "", 0, 0, false
	}
	// topic[1]=to, topic[2]=from, topic[3]=seq. Addresses are right-aligned.
	fromRaw, err := hex.DecodeString(strings.TrimPrefix(l.Topics[2], "0x"))
	if err != nil || len(fromRaw) != 32 {
		return "", 0, 0, false
	}
	sender = "0x" + hex.EncodeToString(fromRaw[12:])
	seqRaw, err := hex.DecodeString(strings.TrimPrefix(l.Topics[3], "0x"))
	if err != nil {
		return "", 0, 0, false
	}
	seq = new(big.Int).SetBytes(seqRaw).Uint64()
	if n, ok := new(big.Int).SetString(strings.TrimPrefix(l.BlockNumber, "0x"), 16); ok {
		block = n.Uint64()
	} else {
		block = 0
	}
	return sender, seq, block, true
}

// decodeReadResult parses the ABI return of `read(address,uint256)`:
// (address from, uint256 blockNumber, bytes data). Returns the opaque payload.
func decodeReadResult(raw []byte) (data []byte, err error) {
	if len(raw) < 64 {
		return nil, fmt.Errorf("evm mailbox: short read() return (%d bytes)", len(raw))
	}
	// word0 = from (address right-aligned, unused), word1 = blockNumber (unused),
	// word2 = offset to bytes data (should be 64), word3 = length, then data.
	offset := new(big.Int).SetBytes(raw[64:96]).Uint64()
	if offset+32 > uint64(len(raw)) {
		return nil, fmt.Errorf("evm mailbox: bad read() offset %d (len %d)", offset, len(raw))
	}
	length := new(big.Int).SetBytes(raw[offset : offset+32]).Uint64()
	if offset+32+length > uint64(len(raw)) {
		return nil, fmt.Errorf("evm mailbox: read() data %d exceeds return len %d", length, len(raw))
	}
	data = make([]byte, length)
	copy(data, raw[offset+32:offset+32+length])
	return data, nil
}

// mailboxListIncoming uses eth_getLogs(Inbox to=us) + read() to recover payloads
// addressed to us, instead of block scanning. minHeight becomes the fromBlock.
func mailboxListIncoming(ctx context.Context, b *Backend, minHeight uint64) ([]chain.Incoming, error) {
	toTopic, err := padAddr20(b.from)
	if err != nil {
		return nil, err
	}
	filter := map[string]interface{}{
		"fromBlock": "0x" + new(big.Int).SetUint64(minHeight).Text(16),
		"toBlock":   "latest",
		"address":   strings.ToLower(b.mailbox),
		"topics": []string{
			bytes32ToHex(inboxTopic),
			addrTopicToHex(toTopic), // Inbox.to == us (indexed)
		},
	}
	var logs ethLogsResult
	if err := b.call(ctx, "eth_getLogs", []interface{}{filter}, &logs); err != nil {
		return nil, err
	}
	var out []chain.Incoming
	for i := range logs {
		l := &logs[i]
		sender, seq, block, ok := decodeInboxLog(l)
		if !ok {
			continue
		}
		// Fetch the stored payload via read(to, seq). msg.sender must == to,
		// so set the eth_call `from` to our own address.
		readCalldata, err := encodeRead(b.from, seq)
		if err != nil {
			continue
		}
		callObj := map[string]interface{}{
			"from": b.from,
			"to":   b.mailbox,
			"data": readCalldata,
		}
		var resHex string
		if err := b.call(ctx, "eth_call", []interface{}{callObj, "latest"}, &resHex); err != nil {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(resHex, "0x"))
		if err != nil {
			continue
		}
		data, err := decodeReadResult(raw)
		if err != nil || len(data) == 0 {
			continue
		}
		out = append(out, chain.Incoming{
			TxID:       l.TransactionHash,
			TopoHeight: int64(block),
			Sender:     sender,
			Payload:    data,
			// BurnKey is our own seq for this message; Burn() calls
			// burn(us, seq) on the mailbox contract, matching read()'s
			// "only recipient" rule.
			BurnKey: strconv.FormatUint(seq, 10),
		})
	}
	return out, nil
}

// encodeBurn builds the calldata for `burn(address to, uint256 seq)`.
func encodeBurn(to string, seq uint64) (string, error) {
	toWord, err := padAddr20(to)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 0, 4+64)
	buf = append(buf, burnSelector[:]...)
	buf = append(buf, toWord[:]...)
	sq := uintWord(seq)
	buf = append(buf, sq[:]...)
	return "0x" + hex.EncodeToString(buf), nil
}

// mailboxBurn erases the stored message at seq for our own address by
// calling the contract's burn(to, seq) — only the recipient may do this
// (msg.sender == to), matching read()'s rule. Best-effort: the caller
// (chain.Watch) never treats a burn failure as a delivery failure.
func mailboxBurn(ctx context.Context, b *Backend, burnKey string) error {
	seq, err := strconv.ParseUint(burnKey, 10, 64)
	if err != nil {
		return fmt.Errorf("evm mailbox: bad burn key %q: %w", burnKey, err)
	}
	calldata, err := encodeBurn(b.from, seq)
	if err != nil {
		return err
	}
	params := map[string]interface{}{
		"from": b.from,
		"to":   b.mailbox,
		"data": calldata,
	}
	var txhash string
	return b.call(ctx, "eth_sendTransaction", []interface{}{params}, &txhash)
}
