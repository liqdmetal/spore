package dero

import (
	"crypto/sha256"
	"encoding/binary"
)

// EntryIdentity distinguishes multiple payload-bearing records in one
// transaction while remaining stable across inclusive get_transfers polls.
func EntryIdentity(e Entry, payload []byte) string {
	if e.TXID == "" {
		return ""
	}
	var b [40]byte
	binary.BigEndian.PutUint64(b[0:8], e.Height)
	binary.BigEndian.PutUint64(b[8:16], uint64(e.TopoHeight))
	binary.BigEndian.PutUint64(b[16:24], uint64(e.Amount))
	binary.BigEndian.PutUint64(b[24:32], uint64(e.TransactionPos))
	binary.BigEndian.PutUint64(b[32:40], uint64(e.Pos))
	h := sha256.New()
	h.Write([]byte(e.TXID))
	h.Write(b[:])
	h.Write([]byte(e.Sender))
	h.Write(payload)
	return string(h.Sum(nil))
}
