package whisper

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// RecvState persists the receive cursor and the set of delivered entry
// identities. Without it, whisper recv re-delivers the wallet's ENTIRE
// transfer history on every restart: minHeight starts at 0 and the dedup map
// is in-memory only.
//
// Cursor keeps the poll efficient (scan resumes near the last delivered
// height), while Seen makes delivery exactly-once across restarts: R153
// get_transfers min_height is inclusive, so the boundary height re-matches
// on the next poll and only the delivered-identity set prevents a duplicate.
type RecvState struct {
	// Cursor is the block height committed after the last fully delivered
	// batch.
	Cursor uint64 `json:"cursor"`
	// Seen holds the EntryIdentity digests of every delivered message.
	Seen []string `json:"seen,omitempty"`
}

// LoadRecvState reads a previously saved state file. A missing file is not an
// error: it returns an empty state so the first run starts from the beginning.
// A corrupt file IS an error: silently ignoring it would re-deliver history
// (data missing) or skip it (data taken on faith), so the operator must
// delete the file explicitly to start fresh.
func LoadRecvState(path string) (*RecvState, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &RecvState{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("whisper: read recv state: %w", err)
	}
	var st RecvState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("whisper: corrupt recv state %s (delete it to start fresh): %w", path, err)
	}
	for i, hexID := range st.Seen {
		if len(hexID) != recvSeenHexLen {
			return nil, fmt.Errorf("whisper: corrupt recv state %s (delete it to start fresh): seen entry %d is %d chars, want %d", path, i, len(hexID), recvSeenHexLen)
		}
		if _, err := hex.DecodeString(hexID); err != nil {
			return nil, fmt.Errorf("whisper: corrupt recv state %s (delete it to start fresh): seen entry %d is not hex", path, i)
		}
	}
	return &st, nil
}

// SaveRecvState writes the state atomically (temp file + rename) so a crash
// mid-write can never leave a truncated JSON file that fails the next load.
func SaveRecvState(path string, st *RecvState) error {
	if path == "" {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// EntryIdentity digests are raw binary, but the state file must survive JSON:
// encoding/json replaces invalid UTF-8 bytes with U+FFFD, which silently
// corrupts a raw-digest Seen list and breaks the next run's dedup. So the file
// stores hex and the maps work on raw bytes.
const recvSeenHexLen = 64 // sha256 digest as hex

func (st *RecvState) seenSet() map[string]bool {
	m := make(map[string]bool, len(st.Seen))
	for _, hexID := range st.Seen {
		raw, err := hex.DecodeString(hexID)
		if err != nil {
			continue // LoadRecvState already rejected bad entries; be defensive anyway
		}
		m[string(raw)] = true
	}
	return m
}

func (st *RecvState) addSeen(rawID string) {
	st.Seen = append(st.Seen, hex.EncodeToString([]byte(rawID)))
}
