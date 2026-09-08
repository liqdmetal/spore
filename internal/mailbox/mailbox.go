// Package mailbox is the always-on, cross-chain RECIPIENT side of mycelium
// long-body delivery. A mailbox:
//
//   - holds the recipient's long-term mycelium X25519 key and a durable
//     DiskStore in one directory (the key is generated on first open and
//     persisted so bodies decrypt across restarts),
//   - accepts HTTP PUSH of ciphertext bodies by CID, so a sender whose node is
//     not publicly reachable can hand the body to the mailbox and then only
//     post the tiny pointer-whisper on-chain,
//   - runs a chain scanner over ANY chain.Chain backend (dero/evm/xmr/solana)
//     that watches for pointer-whispers and, on each one, fetches + verifies +
//     decrypts the referenced body and stores the plaintext durably, and
//   - exposes list/get over HTTP and direct calls so the user can read what
//     arrived while it runs headless.
//
// It is transport-agnostic by design: the body fetch is a pluggable FetchFunc
// (local store, a peer transport, or an in-memory transport in tests), so the
// decrypt-on-pointer-scan core is unit-testable with no live chain or node.
package mailbox

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/longmsg"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/store"
	"github.com/liqdmetal/spore/internal/whisper"
)

// keyFile is the name (inside the mailbox dir) of the hex-encoded 32-byte
// long-term X25519 scalar the mailbox decrypts with.
const keyFile = "key"

// msgsFile is the JSON-lines durable plaintext log inside the mailbox dir.
const msgsFile = "messages.log"

// Mailbox is one recipient's durable long-body receiver + body store.
type Mailbox struct {
	dir      string
	prekeyMu sync.RWMutex
	prekey   *ratchet.SPKBundle
	st       store.Store // durable ciphertext store (HTTP-pushed + local bodies)
	ep       *longmsg.Endpoint
	log      *MessageLog
	// logTTL bounds how long decrypted messages persist on disk (rot).
	logTTL time.Duration
	// noSenderLog, when set, blanks the Sender field before a message is
	// persisted to the durable plaintext log. A Model-B hosted mailbox operator
	// (who reads the log) then cannot tell WHO sent each message — only that one
	// arrived. The recipient on the phone learns the sender from context, not
	// from the service's on-disk record. Default off (local personal mailboxes
	// may want to keep the sender).
	noSenderLog bool
}

// CorruptLogLines reports how many undecryptable log lines were skipped on the
// last read/trim (health signal).
func (m *Mailbox) CorruptLogLines() int { return m.log.CorruptLines() }

// SetNoSenderLog toggles whether the durable log records the sender. Intended
// for a hosted/Model-B mailbox where the operator must not learn who messages
// whom. Safe to call at any time; affects messages persisted after the call.
func (m *Mailbox) SetNoSenderLog(on bool) { m.noSenderLog = on }

// SetLogTTL sets how long decrypted messages stay in the on-disk log before
// TrimLog rewrites them away (default DefaultLogTTL; <= 0 disables trimming).
func (m *Mailbox) SetLogTTL(ttl time.Duration) { m.logTTL = ttl }

// TrimLog rewrites the message log, dropping messages older than the log TTL
// (rot, audit H5), re-encrypting any legacy plaintext lines, and dropping
// corrupt lines. Returns the number of messages kept. Call periodically
// (mailbox run does, on the reap cadence).
func (m *Mailbox) TrimLog(now time.Time) (int, error) {
	return m.log.Trim(now, m.logTTL)
}

// sanitize blanks metadata the mailbox operator should not retain when
// noSenderLog is set.
func (m *Mailbox) sanitize(msg *Message) {
	if m.noSenderLog {
		msg.Sender = ""
	}
}

// Open opens (creating if needed) a mailbox rooted at dir. When priv is nil it
// is loaded from <dir>/key, or a fresh key is generated + persisted. Returns
// the mailbox ready to serve bodies, scan a chain, and read messages.
func Open(dir string, priv []byte) (*Mailbox, error) {
	if dir == "" {
		return nil, errors.New("mailbox: empty dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.NewDiskStore(dir)
	if err != nil {
		return nil, err
	}

	keyPath := filepath.Join(dir, keyFile)
	privRaw := priv
	if privRaw == nil {
		if b, rerr := os.ReadFile(keyPath); rerr == nil {
			d, derr := hex.DecodeString(strings.TrimSpace(string(b)))
			if derr != nil || len(d) != 32 {
				return nil, fmt.Errorf("mailbox: corrupt key file %s", keyPath)
			}
			privRaw = d
		}
	}
	if privRaw == nil {
		// First open: mint + persist a fresh long-term key.
		tmp, err := longmsg.NewEndpoint(st)
		if err != nil {
			return nil, err
		}
		privRaw = tmp.PrivKey()
		if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(privRaw)), 0o600); err != nil {
			crypto.Zero(privRaw)
			return nil, err
		}
	}
	if len(privRaw) != 32 {
		return nil, errors.New("mailbox: key must be 32 bytes")
	}
	ep, err := longmsg.NewEndpointFromPriv(st, privRaw)
	// NOTE: KeyPairFromPriv aliases privRaw as the endpoint's live private key,
	// so privRaw must NOT be zeroed here — zeroing it would wipe the key the
	// mailbox decrypts with.
	if err != nil {
		crypto.Zero(privRaw)
		return nil, err
	}
	// The message log is encrypted with a key derived from the mailbox scalar
	// (audit H5: the old plaintext JSONL log defeated the compost model).
	logKey, err := LogKey(privRaw)
	if err != nil {
		return nil, err
	}
	ml, err := OpenLog(filepath.Join(dir, msgsFile), logKey)
	if err != nil {
		return nil, err
	}
	prekey, err := loadPrekey(dir)
	if err != nil {
		return nil, err
	}
	return &Mailbox{dir: dir, st: st, ep: ep, log: ml, logTTL: DefaultLogTTL, prekey: prekey}, nil
}

// Dir returns the mailbox's data directory.
func (m *Mailbox) Dir() string { return m.dir }

// PublicKey is the long-term X25519 public key senders encrypt long bodies to
// (and, on public chains, the key senders wrap pointer-whispers to).
func (m *Mailbox) PublicKey() []byte { return m.ep.PublicKey() }

// Key returns a copy of the 32-byte private scalar the mailbox decrypts with.
func (m *Mailbox) Key() []byte { return m.ep.PrivKey() }

// Store exposes the durable ciphertext store (used to fetch pushed bodies).
func (m *Mailbox) Store() store.Store { return m.st }

// Reap evicts expired bodies from the ciphertext store and returns how many.
func (m *Mailbox) Reap(now time.Time) int { return m.st.Reap(now) }

// PutBody durably stores a pushed ciphertext body under cid, retained until
// deadline. If deadline is zero the body never burns.
func (m *Mailbox) PutBody(cid [32]byte, body []byte, deadline time.Time) error {
	return m.st.Put(cid, body, deadline)
}

// LocalFetch reads a body from the mailbox's own durable store — the bodies
// senders HTTP-push here. Returns store.ErrNotFound / store.ErrExpired.
func (m *Mailbox) LocalFetch(_ context.Context, cid [32]byte) ([]byte, error) {
	return m.st.Get(cid)
}

// Body serves a stored ciphertext body by CID (for remote peer pull). Returns
// store.ErrNotFound / store.ErrExpired when absent / burned.
func (m *Mailbox) Body(cid [32]byte) ([]byte, error) {
	return m.st.Get(cid)
}

// FetchFunc retrieves a body by CID. LocalFetch, a peer transport, or an
// in-memory transport (tests) all satisfy it. It matches rendezvous.FetchFunc
// so existing transports plug straight in.
type FetchFunc func(ctx context.Context, cid [32]byte) ([]byte, error)

// adaptFetch adapts a ctx-aware FetchFunc to longmsg.Endpoint.ReceiveBody's
// bare (cid) fetch closure.
func adaptFetch(ctx context.Context, fetch FetchFunc) func(cid [32]byte) ([]byte, error) {
	if fetch == nil {
		return nil
	}
	return func(cid [32]byte) ([]byte, error) { return fetch(ctx, cid) }
}

// Message is one decrypted thing the mailbox has received: either a short text
// whisper (Kind "text") or a fetched + decrypted long body (Kind "long").
type Message struct {
	Kind         string `json:"kind"` // "text" | "long"
	CID          string `json:"cid,omitempty"`
	TxID         string `json:"txid"`
	Sender       string `json:"sender,omitempty"`
	TopoHeight   int64  `json:"topo,omitempty"`
	ReceivedAt   int64  `json:"received_at"` // unix seconds
	BurnDeadline int64  `json:"burn_deadline,omitempty"`
	Size         int    `json:"size,omitempty"`
	Text         string `json:"text"`
}

func keyOf(m Message) string {
	if m.TxID != "" {
		return m.TxID
	}
	return m.CID
}

// Deliver decodes one incoming on-chain payload with codec and, if it is a
// pointer-whisper, fetches + verifies + decrypts the long body via fetch and
// stores the plaintext durably. It returns the messages stored (empty when the
// payload is not ours). A body that is burned (store- or deadline-expired)
// yields an error and is NOT stored.
func (m *Mailbox) Deliver(ctx context.Context, inc chain.Incoming, codec whisper.Codec, fetch FetchFunc) ([]Message, error) {
	if text, ok := codec.DecodeText(inc.Payload); ok {
		msg := Message{
			Kind:       "text",
			TxID:       inc.TxID,
			Sender:     inc.Sender,
			TopoHeight: inc.TopoHeight,
			ReceivedAt: time.Now().Unix(),
			Size:       len(text),
			Text:       text,
		}
		m.sanitize(&msg)
		if err := m.log.Add(msg); err != nil {
			return nil, err
		}
		return []Message{msg}, nil
	}
	if eph, cid, ok := codec.DecodePointer(inc.Payload); ok {
		return m.receiveLong(ctx, inc, &longmsg.Pointer{EphemeralPub: eph, CID: cid}, fetch)
	}
	return nil, nil
}

// ReceivePointer decrypts + stores a long body referenced by an explicit
// pointer (used when a chain carries the full pointer incl. burn deadline, or
// by tests). A pointer past its BurnDeadline is refused before any fetch.
func (m *Mailbox) ReceivePointer(ctx context.Context, ptr *longmsg.Pointer, txid, sender string, topo int64, fetch FetchFunc) (*Message, error) {
	inc := chain.Incoming{TxID: txid, Sender: sender, TopoHeight: topo}
	msgs, err := m.receiveLong(ctx, inc, ptr, fetch)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, nil
	}
	return &msgs[0], nil
}

func (m *Mailbox) receiveLong(ctx context.Context, inc chain.Incoming, ptr *longmsg.Pointer, fetch FetchFunc) ([]Message, error) {
	cid := hex.EncodeToString(ptr.CID[:])
	if m.log.Has(keyOf(Message{CID: cid})) {
		return nil, nil // already delivered this body
	}
	// longmsg.ReceiveBody enforces ptr.BurnDeadline (burned -> error) and the
	// CID == sha256(body) integrity gate before decryption.
	plain, err := m.ep.ReceiveBody(ptr, adaptFetch(ctx, fetch))
	if err != nil {
		return nil, err
	}
	msg := Message{
		Kind:         "long",
		CID:          cid,
		TxID:         inc.TxID,
		Sender:       inc.Sender,
		TopoHeight:   inc.TopoHeight,
		ReceivedAt:   time.Now().Unix(),
		BurnDeadline: int64(ptr.BurnDeadline),
		Size:         len(plain),
		Text:         string(plain),
	}
	m.sanitize(&msg)
	if err := m.log.Add(msg); err != nil {
		return nil, err
	}
	return []Message{msg}, nil
}

// List returns all stored (decrypted) messages, newest first.
func (m *Mailbox) List() ([]Message, error) {
	all, err := m.log.All()
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if all == nil {
		all = []Message{}
	}
	return all, nil
}

// Count reports how many messages the mailbox has stored.
func (m *Mailbox) Count() (int, error) {
	return m.log.Count()
}

// Get looks a message up by CID hex or txid.
func (m *Mailbox) Get(id string) (*Message, error) {
	all, err := m.log.All()
	if err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	for _, msg := range all {
		if msg.TxID == id || msg.CID == id {
			return &msg, nil
		}
	}
	return nil, store.ErrNotFound
}

// RunScanner polls the chain for incoming whispers/pointers and delivers each
// (fetching + decrypting long bodies via fetch). on, when non-nil, is invoked
// for every message stored so a headless `mailbox run` can report arrivals. It
// returns when ctx is done; transient chain/delivery errors are logged through
// errc and the loop continues.
func (m *Mailbox) RunScanner(ctx context.Context, c chain.Chain, codec whisper.Codec, opts chain.WatchOpts, fetch FetchFunc, on func(Message), errc chan<- error) {
	in, werr := chain.Watch(ctx, c, opts)
	for {
		select {
		case inc, ok := <-in:
			if !ok {
				return
			}
			msgs, err := m.Deliver(ctx, inc, codec, fetch)
			if err != nil {
				select {
				case errc <- fmt.Errorf("mailbox: deliver tx %s: %w", inc.TxID, err):
				case <-ctx.Done():
					return
				}
				continue
			}
			for _, msg := range msgs {
				if on != nil {
					on(msg)
				}
			}
		case err, ok := <-werr:
			if !ok {
				return
			}
			select {
			case errc <- err:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
