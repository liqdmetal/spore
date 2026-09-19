package evm

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestMailboxDeliverEncode checks the hand-rolled ABI encoding of
// deliver(address,bytes) produces the calldata cast/foundry would.
func TestMailboxDeliverEncode(t *testing.T) {
	to := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	payload := []byte("hello")
	calldata, err := encodeDeliver(to, payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(strings.TrimPrefix(calldata, "0x"))
	if len(raw) < 4 {
		t.Fatalf("calldata too short: %d", len(raw))
	}
	// selector == keccak256("deliver(address,bytes)")[:4]
	wantSel := sel4(mailboxDeliverSig)
	if !bytes.Equal(raw[:4], wantSel[:]) {
		t.Fatalf("selector = %x want %x", raw[:4], wantSel[:])
	}
	// arg0: address word right-aligned
	arg0 := raw[4:36]
	if !bytes.Equal(arg0[:12], make([]byte, 12)) {
		t.Fatalf("address word not left-padded with zeros: %x", arg0)
	}
	toRaw, _ := hex.DecodeString("70997970C51812dc3A010C7d01b50e0d17dc79C8")
	if !bytes.Equal(arg0[12:], toRaw) {
		t.Fatalf("address word right-aligned mismatch: %x", arg0[12:])
	}
	// offset word = 64 (0x40)
	off := raw[36:68]
	if !bytes.Equal(off, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64}) {
		t.Fatalf("offset word = %x, want 64", off)
	}
	// length word = 5
	ln := raw[68:100]
	if ln[31] != 5 {
		t.Fatalf("length word = %x, want 5", ln)
	}
	// payload bytes follow, zero-padded to 32
	if !bytes.Equal(raw[100:105], []byte("hello")) {
		t.Fatalf("payload = %q", raw[100:105])
	}
	if len(raw)%32 != 0 {
		t.Fatalf("calldata length %d not 32-aligned", len(raw))
	}
}

// TestMailboxReadEncode checks read(address,uint256) calldata.
func TestMailboxReadEncode(t *testing.T) {
	calldata, err := encodeRead("0x70997970C51812dc3A010C7d01b50e0d17dc79C8", 7)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(strings.TrimPrefix(calldata, "0x"))
	if len(raw) != 68 {
		t.Fatalf("read calldata len = %d, want 68", len(raw))
	}
	if !bytes.Equal(raw[:4], readSelector[:]) {
		t.Fatalf("selector = %x want %x", raw[:4], readSelector[:])
	}
	if raw[67] != 7 {
		t.Fatalf("seq word = %x, want 7", raw[64:68])
	}
}

// TestMailboxDecodeLog checks parsing an Inbox(to,from,seq,cid) log from topics.
func TestMailboxDecodeLog(t *testing.T) {
	// Build a realistic log as cast returned (see deployment output).
	mkWord := func(hexes ...string) []string {
		out := make([]string, 0, len(hexes))
		for _, h := range hexes {
			out = append(out, "0x"+h)
		}
		return out
	}
	toTopic := mkWord("00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8")[0]
	fromTopic := mkWord("000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266")[0]
	seqTopic := mkWord("0000000000000000000000000000000000000000000000000000000000000003")[0]

	log := &ethLog{
		Topics:          []string{bytes32ToHex(inboxTopic), toTopic, fromTopic, seqTopic},
		BlockNumber:     "0x2a",
		TransactionHash: "0xdeadbeef",
	}
	sender, seq, block, ok := decodeInboxLog(log)
	if !ok {
		t.Fatal("decodeInboxLog returned ok=false for a valid Inbox log")
	}
	if !strings.EqualFold(sender, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266") {
		t.Fatalf("sender = %s", sender)
	}
	if seq != 3 {
		t.Fatalf("seq = %d, want 3", seq)
	}
	if block != 42 {
		t.Fatalf("block = %d, want 42", block)
	}

	// Wrong topic0 (not Inbox) must be rejected.
	bad := &ethLog{Topics: []string{"0x1111", toTopic, fromTopic, seqTopic}, BlockNumber: "0x2a"}
	if _, _, _, ok := decodeInboxLog(bad); ok {
		t.Fatal("decodeInboxLog accepted a non-Inbox log")
	}
}

// TestMailboxDecodeReadResult checks parsing read()'s (address,uint256,bytes).
func TestMailboxDecodeReadResult(t *testing.T) {
	// ABI-encode a read() return exactly as Solidity/EVM produces it:
	// head = [from(0:32), blockNumber(32:64), offset(64:96)=96],
	// tail at byte 96 = [len(96:128), data(128:...)].
	fromWord := make([]byte, 32)
	copy(fromWord[12:], []byte{0x70, 0x99, 0x79, 0x70, 0xC5, 0x18, 0x12, 0xdc, 0x3A, 0x01, 0x0C, 0x7d, 0x01, 0xb5, 0x0e, 0x0d, 0x17, 0xdc, 0x79, 0xC8})
	w22 := uintWord(22)
	w96 := uintWord(96)
	w5 := uintWord(5)
	raw := make([]byte, 0, 32*5)
	raw = append(raw, fromWord...) // from
	raw = append(raw, w22[:]...)   // blockNumber
	raw = append(raw, w96[:]...)   // offset to bytes tail
	raw = append(raw, w5[:]...)    // length
	raw = append(raw, []byte("hello")...)
	for len(raw)%32 != 0 {
		raw = append(raw, 0)
	}
	data, err := decodeReadResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("data = %q, want hello", data)
	}
}
