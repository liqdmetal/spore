package chain

import (
	"crypto/sha256"
	"encoding/binary"
)

// incomingIdentity is stable enough for one watcher process and does not
// collapse distinct records when a backend reuses a transaction ID.
func incomingIdentity(inc Incoming) string {
	if inc.TxID == "" {
		return ""
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], inc.ScanHeight)
	binary.BigEndian.PutUint64(b[8:16], uint64(inc.TopoHeight))
	h := sha256.New()
	h.Write([]byte(inc.TxID))
	h.Write(b[:])
	h.Write(inc.Payload)
	return string(h.Sum(nil))
}
