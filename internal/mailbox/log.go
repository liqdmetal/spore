package mailbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// ErrCorrupt is returned when the message log has a malformed line.
var ErrCorrupt = errors.New("mailbox: corrupt message log")

// MessageLog is a durable JSON-lines store of decrypted messages. Each line is
// one Message. Writes dedupe on delivery key (txid, else cid) so a pointer
// re-delivered across restarts is not stored twice. It is safe for concurrent
// use within one process.
type MessageLog struct {
	mu   sync.Mutex
	path string
}

// OpenLog opens (creating if needed) the message log at path.
func OpenLog(path string) (*MessageLog, error) {
	if path == "" {
		return nil, errors.New("mailbox: empty log path")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &MessageLog{path: path}, f.Close()
}

// Add appends a message unless one with the same key already exists.
func (l *MessageLog) Add(m Message) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Has(keyOf(m)) {
		return nil
	}
	line, err := json.Marshal(m)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Has reports whether a message with key already exists in the log.
func (l *MessageLog) Has(key string) bool {
	all, err := l.readAll()
	if err != nil {
		return false
	}
	for _, m := range all {
		if keyOf(m) == key {
			return true
		}
	}
	return false
}

// All returns every stored message in append order.
func (l *MessageLog) All() ([]Message, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.readAll()
}

// Count returns the number of stored messages.
func (l *MessageLog) Count() (int, error) {
	all, err := l.All()
	if err != nil {
		return 0, err
	}
	return len(all), nil
}

func (l *MessageLog) readAll() ([]Message, error) {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Message
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var m Message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			return nil, ErrCorrupt
		}
		out = append(out, m)
	}
	return out, sc.Err()
}
