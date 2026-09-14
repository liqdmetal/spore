// Package receipts is the local invoice/payment ledger: an append-only JSONL
// file recording money envelopes (sent + received) so a user can answer "who
// invoiced me, what did I pay, when, and on which tx" from local data alone.
package receipts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Record is one money event: an invoice sent, or a payment sent/received.
type Record struct {
	At        int64  `json:"at"`
	Session   string `json:"session,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Direction string `json:"direction"` // sent | received
	Kind      string `json:"kind"`      // invoice | payment
	InvoiceID string `json:"invoice_id,omitempty"`
	Asset     string `json:"asset"`
	Atomic    uint64 `json:"atomic"`
	TxID      string `json:"txid,omitempty"`
	Note      string `json:"note,omitempty"`
	For       string `json:"for,omitempty"`
}

// Append writes one record to the JSONL ledger (0600), creating the file if
// needed.
func Append(path string, r Record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", line)
	return err
}

// List reads the ledger, newest first, optionally filtered to one session.
func List(path, session string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // never let one bad line break the ledger
		}
		if session != "" && !strings.EqualFold(r.Session, session) {
			continue
		}
		out = append(out, r)
	}
	// newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, sc.Err()
}
