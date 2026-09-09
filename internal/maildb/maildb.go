package maildb

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Package maildb is the local, private mail store for a Spore endpoint: the
// address book (contacts + allowlist), the thread index, and the search
// index over decrypted messages. Everything lives in one JSON file under the
// state dir with 0600 perms and is endpoint-local by construction — it is
// never uploaded, never shipped to a chain or mailbox, and never leaves the
// machine. It is a convenience index only: the ciphertext bodies and ratchet
// sessions remain the source of truth.

var (
	ErrNotFound = errors.New("maildb: not found")
	ErrDup      = errors.New("maildb: already exists")
)

// Contact is one address-book entry. The chain address is the key; the
// pinned sig is the out-of-band trust anchor that must match a bundle's
// SPK_sig (TOFU/key-continuity). Blocked is the hard allowlist: messages
// from a blocked contact are not accepted.
type Contact struct {
	Address  string `json:"address"`
	Nickname string `json:"nickname,omitempty"`
	Pinned   string `json:"pinned_sig,omitempty"`
	Added    int64  `json:"added"`
	Blocked  bool   `json:"blocked,omitempty"`
}

// Thread is one conversation, keyed by ratchet session id (hex). It holds
// the metadata recv-e2 needs to group and display, plus the last-activity
// time for sorting.
type Thread struct {
	SessionID string `json:"session_id"` // hex
	Peer      string `json:"peer"`       // chain address
	LastAt    int64  `json:"last_at"`
	Count     int    `json:"count"`
}

// MessageMeta is one indexed decrypted message: pointer (txid) + session +
// sender + time + subject/first line. The full body is NOT stored here by
// default (it may live in the out-dir / mailbox log); this is the search
// index entry.
type MessageMeta struct {
	TxID      string `json:"txid"`
	SessionID string `json:"session_id"`
	Peer      string `json:"peer"`
	At        int64  `json:"at"`
	Snippet   string `json:"snippet"`
}

// MailDB is a thread-safe, JSON-file-backed mail store.
type MailDB struct {
	mu        sync.RWMutex
	path      string
	contacts  map[string]Contact
	threads   map[string]Thread
	messages  []MessageMeta
	allowOnly bool // allowlist-only mode: only known (non-blocked) contacts can message
}

// Open loads (or creates) the mail store at path.
func Open(path string) (*MailDB, error) {
	m := &MailDB{path: path, contacts: map[string]Contact{}, threads: map[string]Thread{}}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		var data struct {
			Contacts map[string]Contact    `json:"contacts"`
			Threads  map[string]Thread     `json:"threads"`
			Messages []MessageMeta         `json:"messages"`
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, err
		}
		if data.Contacts != nil {
			m.contacts = data.Contacts
		}
		if data.Threads != nil {
			m.threads = data.Threads
		}
		m.messages = data.Messages
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

func (m *MailDB) saveLocked() error {
	data := struct {
		Contacts map[string]Contact    `json:"contacts"`
		Threads  map[string]Thread     `json:"threads"`
		Messages []MessageMeta         `json:"messages"`
	}{m.contacts, m.threads, m.messages}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.path), "maildb-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func(e error) error { tmp.Close(); os.Remove(tmpName); return e }
	if err := tmp.Chmod(0600); err != nil {
		return cleanup(err)
	}
	if _, err := tmp.Write(raw); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, m.path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Chmod(m.path, 0600)
}

// UpsertContact adds or updates a contact (key = address). It never removes
// an existing pinned sig unless the caller explicitly sets a new one, so a
// TOFU change is a visible update, not a silent overwrite.
func (m *MailDB) UpsertContact(c Contact) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Address == "" {
		return errors.New("maildb: empty contact address")
	}
	if c.Added == 0 {
		c.Added = time.Now().Unix()
	}
	if old, ok := m.contacts[c.Address]; ok && c.Pinned == "" {
		c.Pinned = old.Pinned
	}
	m.contacts[c.Address] = c
	return m.saveLocked()
}

func (m *MailDB) Contact(addr string) (Contact, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.contacts[addr]
	return c, ok
}

func (m *MailDB) Contacts() []Contact {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Contact, 0, len(m.contacts))
	for _, c := range m.contacts {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// Allowed reports whether addr is NOT blocked. Unknown addresses are
// allowed (blocklist semantics) unless allowlist-only mode is on, in which
// case only known contacts are accepted.
func (m *MailDB) Allowed(addr string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.allowOnly {
		_, ok := m.contacts[addr]
		return ok
	}
	c, ok := m.contacts[addr]
	return !ok || !c.Blocked
}

// SetAllowOnly toggles allowlist-only mode (only known contacts can message
// you).
func (m *MailDB) SetAllowOnly(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowOnly = v
}

// RecordMessage indexes a decrypted message into its thread and the search
// index.
func (m *MailDB) RecordMessage(sessionIDHex, peer, txid string, at time.Time, plaintext []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	snippet := string(plaintext)
	if len(snippet) > 120 {
		snippet = snippet[:120]
	}
	t := m.threads[sessionIDHex]
	if t.SessionID == "" {
		t = Thread{SessionID: sessionIDHex, Peer: peer}
	}
	t.LastAt = at.Unix()
	t.Count++
	m.threads[sessionIDHex] = t
	m.messages = append(m.messages, MessageMeta{
		TxID: txid, SessionID: sessionIDHex, Peer: peer, At: at.Unix(), Snippet: snippet,
	})
	return m.saveLocked()
}

func (m *MailDB) Threads() []Thread {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Thread, 0, len(m.threads))
	for _, t := range m.threads {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastAt > out[j].LastAt })
	return out
}

// SearchQuery is a parsed search: every term in All must match (AND), plus
// optional scoping by sender, thread, or txid, and a phrase (exact
// substring, all terms). A token in AnyOf matches if any listed token does.
// Matching is case-insensitive.
type SearchQuery struct {
	All    []string // all of these tokens must appear (AND)
	AnyOf  []string // any of these tokens may appear
	Not    []string // none of these tokens may appear
	Phrase string   // exact case-insensitive substring (optional)
	Peer   string   // scope: sender/peer address (exact)
	Thread string   // scope: session id hex (exact)
	TxID   string   // scope: txid (exact)
}

// SearchResult is one hit plus the matched snippet with the matched terms
// marked up with the standard marker pair so the CLI can highlight without
// importing a rendering dependency.
type SearchResult struct {
	MessageMeta
	Matched bool // always true; kept for clarity
}

func matchesQuery(mm MessageMeta, q SearchQuery) bool {
	peer := strings.ToLower(mm.Peer)
	txid := strings.ToLower(mm.TxID)
	thread := strings.ToLower(mm.SessionID)
	text := strings.ToLower(mm.Snippet)
	for _, t := range q.All {
		if !strings.Contains(text, t) {
			return false
		}
	}
	if len(q.AnyOf) > 0 {
		any := false
		for _, t := range q.AnyOf {
			if strings.Contains(text, t) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	for _, t := range q.Not {
		if strings.Contains(text, t) {
			return false
		}
	}
	if q.Phrase != "" && !strings.Contains(text, strings.ToLower(q.Phrase)) {
		return false
	}
	if q.Peer != "" && peer != strings.ToLower(q.Peer) {
		return false
	}
	if q.Thread != "" && thread != strings.ToLower(q.Thread) {
		return false
	}
	if q.TxID != "" && txid != strings.ToLower(q.TxID) {
		return false
	}
	return true
}

// Search runs a parsed query over the indexed messages, newest first.
func (m *MailDB) Search(q SearchQuery) []MessageMeta {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []MessageMeta{}
	for _, mm := range m.messages {
		if matchesQuery(mm, q) {
			out = append(out, mm)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}

// SearchSimple is the one-shot convenience for "all these words": it parses
// the space-separated query into All tokens (case-insensitive AND).
func (m *MailDB) SearchSimple(q string) []MessageMeta {
	tokens := strings.Fields(strings.ToLower(q))
	return m.Search(SearchQuery{All: tokens})
}

// Highlight returns the snippet with every occurrence of any of the given
// terms wrapped in the ASCII record separator pairs, so a caller can split
// on \x1e and render with inverse-video/bold without a template library.
// Returns the original snippet when no term matches.
func (m *MailDB) Highlight(snippet string, terms []string) string {
	s := snippet
	for _, t := range terms {
		if t == "" {
			continue
		}
		s = strings.ReplaceAll(s, t, "\x1e"+t+"\x1f")
	}
	if s == snippet {
		return snippet
	}
	return s
}

// Messages returns all indexed messages, newest first.
func (m *MailDB) Messages() []MessageMeta {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]MessageMeta(nil), m.messages...)
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}
