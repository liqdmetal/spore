package solana

import (
	"encoding/binary"
	"fmt"
)

// StoredMessage is one envelope in a recipient's inbox, mirroring the mailbox
// program's StoredMessage{ from: [u8;32], data: Vec<u8>, seq: u64 }.
type StoredMessage struct {
	From [32]byte
	Data []byte
	Seq  uint64
}

// Inbox is a recipient's inbox: a borsh Vec<StoredMessage>.
type Inbox struct {
	Messages []StoredMessage
}

// borsh field widths.
const (
	borshVecLenBytes = 4 // u32 LE length prefix on a Vec
	borshU64Bytes    = 8
	pubkeyBytes      = 32
)

// EncodeInbox serializes an Inbox using the same borsh layout the mailbox
// program uses: a u32 LE length prefix followed by each message. Each message
// is [32]from || Vec<data> (u32 LE len + bytes) || u64 LE seq.
func EncodeInbox(in *Inbox) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("solana: nil inbox")
	}
	buf := make([]byte, 0, borshVecLenBytes)
	lenPrefix := make([]byte, borshVecLenBytes)
	binary.LittleEndian.PutUint32(lenPrefix, uint32(len(in.Messages)))
	buf = append(buf, lenPrefix...)
	for _, m := range in.Messages {
		buf = append(buf, m.From[:]...)
		blen := make([]byte, borshVecLenBytes)
		binary.LittleEndian.PutUint32(blen, uint32(len(m.Data)))
		buf = append(buf, blen...)
		buf = append(buf, m.Data...)
		seq := make([]byte, borshU64Bytes)
		binary.LittleEndian.PutUint64(seq, m.Seq)
		buf = append(buf, seq...)
	}
	return buf, nil
}

// DecodeInbox deserializes an Inbox from borsh bytes.
func DecodeInbox(raw []byte) (*Inbox, error) {
	in := &Inbox{}
	pos := 0
	if len(raw) < borshVecLenBytes {
		return nil, fmt.Errorf("solana: inbox too short for vec length prefix (%d bytes)", len(raw))
	}
	n := binary.LittleEndian.Uint32(raw[pos : pos+borshVecLenBytes])
	pos += borshVecLenBytes

	in.Messages = make([]StoredMessage, 0, int(n))
	for i := uint32(0); i < n; i++ {
		var m StoredMessage
		if pos+pubkeyBytes > len(raw) {
			return nil, fmt.Errorf("solana: inbox truncated reading message %d pubkey", i)
		}
		copy(m.From[:], raw[pos:pos+pubkeyBytes])
		pos += pubkeyBytes

		if pos+borshVecLenBytes > len(raw) {
			return nil, fmt.Errorf("solana: inbox truncated reading message %d data length", i)
		}
		dlen := binary.LittleEndian.Uint32(raw[pos : pos+borshVecLenBytes])
		pos += borshVecLenBytes
		if pos+int(dlen) > len(raw) {
			return nil, fmt.Errorf("solana: inbox truncated reading message %d data", i)
		}
		m.Data = append([]byte(nil), raw[pos:pos+int(dlen)]...)
		pos += int(dlen)

		if pos+borshU64Bytes > len(raw) {
			return nil, fmt.Errorf("solana: inbox truncated reading message %d seq", i)
		}
		m.Seq = binary.LittleEndian.Uint64(raw[pos : pos+borshU64Bytes])
		pos += borshU64Bytes

		in.Messages = append(in.Messages, m)
	}
	return in, nil
}
