package channel

import (
	"encoding/json"
	"os"
)

// boxState is the on-disk snapshot of a box's rooms (lines + nextSeq).
type boxState struct {
	Rooms map[string]roomState `json:"rooms"`
}

type roomState struct {
	Lines   []Line `json:"lines"`
	NextSeq uint64 `json:"next_seq"`
}

// saveBox persists all rooms (minus live presence) to b.dir. Caller holds b.mu.
func saveBox(b *Box) error {
	if b.dir == "" {
		return nil
	}
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return err
	}
	st := boxState{Rooms: map[string]roomState{}}
	for name, r := range b.channels {
		st.Rooms[name] = roomState{Lines: r.lines, NextSeq: r.nextSeq}
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := b.savePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.savePath())
}

// loadBox reads persisted state into b. Rooms without any live lines are kept
// so a channel's nextSeq is preserved. Caller holds b.mu (via load).
func loadBox(b *Box) error {
	if b.dir == "" {
		return nil
	}
	raw, err := os.ReadFile(b.savePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil // first run
		}
		return err
	}
	var st boxState
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	for name, rs := range st.Rooms {
		b.channels[name] = &room{
			lines:    rs.Lines,
			nextSeq:  rs.NextSeq,
			presence: map[string]int64{},
		}
		if b.channels[name].nextSeq == 0 {
			b.channels[name].nextSeq = 1
		}
	}
	return nil
}
