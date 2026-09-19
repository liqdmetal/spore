package mailbox

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ErrCorrupt is returned when the message log is unusable (missing key, etc.).
var ErrCorrupt = errors.New("mailbox: corrupt message log")

// DefaultLogTTL is how long a decrypted message stays in the on-disk log
// before Trim rewrites it away. The audit (H5) called out the old plaintext,
// forever log as contradicting the "messages rot" privacy model; this bound
// plus encryption closes that.
const DefaultLogTTL = 30 * 24 * time.Hour

// MessageLog is the durable store of decrypted messages. Every line is
// ENCRYPTED (XChaCha20-Poly1305, key derived from the mailbox's X25519 scalar
// via HKDF, fresh random nonce per line) and base64-encoded — the on-disk log
// no longer defeats the compost model (audit H5). Legacy PLAINTEXT JSON lines
// from older versions are still read (migration) and are re-encrypted whenever
// the log is rewritten by Trim.
//
// A delivery-key INDEX (txid, else cid) is held in memory and maintained on
// Add, so Has is O(1) instead of rescanning the whole file on every delivery
// (the old O(n²) behavior).
//
// Corruption tolerance: a malformed or undecryptable line is SKIPPED (counted
// via CorruptLines) instead of failing the whole log — a crash mid-write can
// no longer brick the mailbox.
//
// It is safe for concurrent use within one process.
type MessageLog struct {
	mu   sync.Mutex
	path string
	aead cipherAEAD
	// index of delivery keys (txid, else cid) -> present.
	index map[string]bool
	// corrupt counts undecryptable lines seen on the last full read.
	corrupt int
}

// cipherAEAD is the subset of cipher.AEAD used here (interface for tests).
type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
}

// LogKey derives the log encryption key from the mailbox's 32-byte X25519
// scalar. A distinct HKDF info keeps the log key separate from the message
// AEAD keys derived from the same secret.
func LogKey(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("mailbox: log key needs a 32-byte scalar")
	}
	h := hkdf.New(sha256.New, priv, nil, []byte("spore/mailbox/log/v1"))
	out := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

// OpenLog opens (creating if needed) the encrypted message log at path.
// logKey must be 32 bytes (see LogKey).
func OpenLog(path string, logKey []byte) (*MessageLog, error) {
	if path == "" {
		return nil, errors.New("mailbox: empty log path")
	}
	if len(logKey) != 32 {
		return nil, errors.New("mailbox: log key must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(logKey)
	if err != nil {
		return nil, err
	}
	l := &MessageLog{path: path, aead: aead, index: map[string]bool{}}
	// Warm the index once; this also surfaces legacy/corrupt lines.
	if _, err := l.readAll(); err != nil {
		return nil, err
	}
	return l, nil
}

// Add appends a message (encrypted) unless one with the same delivery key
// already exists. O(1) via the index.
func (l *MessageLog) Add(m Message) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := keyOf(m)
	if l.index[key] {
		return nil
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return err
	}
	line, err := l.sealLine(plain)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	l.index[key] = true
	return nil
}

// Has reports whether a message with the given delivery key already exists.
// O(1) via the in-memory index.
func (l *MessageLog) Has(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.index[key]
}

// All returns every stored message in append order. Corrupt lines are skipped.
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

// CorruptLines reports how many undecryptable lines were skipped on the last
// full read (a health signal for the daemon log).
func (l *MessageLog) CorruptLines() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.corrupt
}

// Trim rewrites the log, dropping (a) messages older than ttl and (b) any
// corrupt lines, and re-encrypting surviving LEGACY plaintext lines. Returns
// the number of messages kept. Atomic via temp-file + rename.
func (l *MessageLog) Trim(now time.Time, ttl time.Duration) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.readAll()
	if err != nil {
		return 0, err
	}
	cut := now.Add(-ttl).Unix()
	var kept []Message
	l.index = map[string]bool{}
	for _, m := range all {
		if ttl > 0 && m.ReceivedAt > 0 && m.ReceivedAt < cut {
			continue // rotted
		}
		kept = append(kept, m)
		l.index[keyOf(m)] = true
	}
	tmp := l.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	for _, m := range kept {
		plain, merr := json.Marshal(m)
		if merr != nil {
			f.Close()
			os.Remove(tmp)
			return 0, merr
		}
		line, serr := l.sealLine(plain)
		if serr != nil {
			f.Close()
			os.Remove(tmp)
			return 0, serr
		}
		if _, werr := f.Write(append(line, '\n')); werr != nil {
			f.Close()
			os.Remove(tmp)
			return 0, werr
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, l.path); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	l.corrupt = 0
	return len(kept), nil
}

// sealLine encrypts one JSON line: base64(nonce(24) || XChaCha20 ct).
func (l *MessageLog) sealLine(plain []byte) ([]byte, error) {
	nonce := make([]byte, l.aead.NonceSize())
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, err
	}
	ct := l.aead.Seal(nil, nonce, plain, nil)
	line := make([]byte, 0, len(nonce)+len(ct))
	line = append(line, nonce...)
	line = append(line, ct...)
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(line)))
	base64.StdEncoding.Encode(enc, line)
	return enc, nil
}

// openLine decrypts one base64 line. ok=false if it is not an encrypted line
// (legacy plaintext or corrupt — the caller decides by trying JSON).
func (l *MessageLog) openLine(line []byte) (plain []byte, ok bool) {
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(line)))
	n, err := base64.StdEncoding.Decode(raw, line)
	if err != nil || n < l.aead.NonceSize()+16 {
		return nil, false
	}
	raw = raw[:n]
	nonce, ct := raw[:l.aead.NonceSize()], raw[l.aead.NonceSize():]
	pt, err := l.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, false
	}
	return pt, true
}

// readAll loads and decrypts every line, rebuilding the index. Legacy
// plaintext JSON lines are accepted (migration); anything else corrupt is
// skipped and counted — never fatal.
func (l *MessageLog) readAll() ([]Message, error) {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			l.index = map[string]bool{}
			l.corrupt = 0
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Message
	l.index = map[string]bool{}
	l.corrupt = 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		plain, ok := l.openLine(line)
		if !ok {
			// Legacy plaintext JSON line (pre-encryption log): accept and
			// index it — Trim will re-encrypt it.
			var legacy Message
			if json.Unmarshal(line, &legacy) == nil {
				out = append(out, legacy)
				l.index[keyOf(legacy)] = true
				continue
			}
			l.corrupt++ // neither encrypted nor valid JSON: skip, don't fail
			continue
		}
		var m Message
		if err := json.Unmarshal(plain, &m); err != nil {
			l.corrupt++
			continue
		}
		out = append(out, m)
		l.index[keyOf(m)] = true
	}
	return out, sc.Err()
}

// randReader is indirected for tests.
var randReader io.Reader = rand.Reader
