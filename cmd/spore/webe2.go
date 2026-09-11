package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// webE2 is the server-side 0xE2 state for `spore web`, enabled with -e2-dir.
//
// The browser cannot hold the identity key or run the ratchet itself, so the
// server holds the account's E2 material (the same trust model as the existing
// whisper proxy, which already proxies wallet spend and inbox reads). The
// server is YOURS: this is a self-hosted convenience surface, and the docs say
// so. The crypto is unchanged — X3DH + Double Ratchet end to end; the server
// holding the keys is equivalent to the user running the CLI on this box.
type webE2 struct {
	mu sync.Mutex

	dir      string
	identity []byte // identity.key
	spk      []byte // spk.key
	stateKey []byte // state.key

	states *ratchetwire.FileStateStore
	pool   *ratchetwire.OPKPool
	maildb *maildb.MailDB
	store  ratchetwire.BodyStore

	// Recv cursor. Persisted so the browser inbox resumes where it left off
	// across server restarts instead of replaying the whole history.
	cursor     uint64
	cursorFile string
	seen       map[string]bool // delivered identity keys, this process
}

func newWebE2(dir, storeURL, storeTok string) (*webE2, error) {
	if dir == "" {
		return nil, errors.New("-e2-dir is empty")
	}
	read := func(name string, n int) ([]byte, error) {
		b, err := readHexFile(filepath.Join(dir, name), n)
		if err != nil {
			return nil, fmt.Errorf("%s: %w (run `spore init -dir %s` to create a kit)", name, err, dir)
		}
		return b, nil
	}
	id, err := read("identity.key", 32)
	if err != nil {
		return nil, err
	}
	sk, err := read("spk.key", 32)
	if err != nil {
		return nil, err
	}
	stateKey, err := read("state.key", 32)
	if err != nil {
		return nil, err
	}
	states, err := ratchetwire.NewFileStateStore(filepath.Join(dir, "state"), stateKey)
	if err != nil {
		return nil, err
	}
	pool, err := ratchetwire.NewPersistentOPKPool(filepath.Join(dir, "opk-pool.json"))
	if err != nil {
		return nil, err
	}
	var mdb *maildb.MailDB
	if _, err := os.Stat(filepath.Join(dir, "mail.json")); err == nil {
		mdb, err = maildb.Open(filepath.Join(dir, "mail.json"))
		if err != nil {
			return nil, fmt.Errorf("maildb: %w", err)
		}
	}
	st, err := e2Store(storeURL, storeTok, "")
	if err != nil {
		return nil, err
	}
	e := &webE2{
		dir: dir, identity: id, spk: sk, stateKey: stateKey,
		states: states, pool: pool, maildb: mdb, store: st,
		cursorFile: filepath.Join(dir, "recv-cursor"),
		seen:       map[string]bool{},
	}
	// Resume the cursor.
	if b, err := os.ReadFile(e.cursorFile); err == nil {
		e.cursor, _ = strconv.ParseUint(string(b), 10, 64)
	}
	return e, nil
}

// send delivers one forward-private message. to is an address or a maildb
// contact nickname; the pinned sig and prekey route come from the contact
// (saved by `spore msg mail add -invite`). Returns txid and session id.
func (e *webE2) send(ctx context.Context, to, msg string, wrc, wlogin string) (txid, session string, err error) {
	if to == "" || msg == "" {
		return "", "", errors.New("to and msg are required")
	}
	maildbPath := filepath.Join(e.dir, "mail.json")
	addr, pinned, err := resolveTo(ctx, to, maildbPath, "")
	if err != nil {
		return "", "", err
	}
	if pinned == "" {
		return "", "", fmt.Errorf("no pinned sig known for %s — the sender must save it once, e.g. `spore msg mail add -invite <token>`; Spore will not guess your trust anchor", to)
	}
	sig, err := hex.DecodeString(pinned)
	if err != nil || len(sig) != 32 {
		return "", "", errors.New("pinned sig is not 32-byte hex")
	}
	var contact maildb.Contact
	haveContact := false
	if e.maildb != nil {
		if c, ok := contactForTo(maildbPath, to); ok {
			contact, haveContact = c, true
		}
	}
	b, err := pickBundle(ctx, "", "", "", contact, haveContact, fetchBundle,
		func(m string) { fmt.Fprintln(os.Stderr, "web e2:", m) })
	if err != nil {
		return "", "", err
	}
	u, p := parseLogin(wlogin)
	carrier := ratchetwire.ChainCarrier{
		Chain: dero.NewBackend(dero.NewClient(wrc, u, p)),
		Codec: ratchetwire.DeroChainCodec{},
	}
	ep, err := ratchetwire.NewDurableEndpoint(e.store, e.states, time.Now())
	if err != nil {
		return "", "", err
	}
	_, raw, sessID, err := ep.SendFirstSession(e.identity, b, sig, []byte(msg), time.Now().Add(24*time.Hour))
	if err != nil {
		return "", "", err
	}
	// Keep the multi-device ledger current so a second device can detect a
	// collision with this send. Best-effort: a ledger failure must not
	// cancel the message.
	if dev, derr := ratchetwire.LoadOrCreateDevice(filepath.Join(e.dir, "state")); derr == nil {
		_ = ratchetwire.RecordSend(filepath.Join(e.dir, "state"), sessID, dev)
	}
	res, err := carrier.PostPointer(ctx, addr, raw, 1)
	if err != nil {
		return "", "", err
	}
	return res.TxID, hex.EncodeToString(sessID[:]), nil
}

// webMsg is one delivered message returned to the browser inbox.
type webMsg struct {
	Txid string `json:"txid"`
	Text string `json:"text"`
}

// recvOnce performs one inbox scan: fetch incoming entries at/after the cursor,
// decode E2 pointers, fetch bodies, decrypt. Returns the newly delivered
// messages and advances the persisted cursor.
func (e *webE2) recvOnce(ctx context.Context, wrc, wlogin string) ([]webMsg, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	u, p := parseLogin(wlogin)
	client := dero.NewClient(wrc, u, p)
	entries, err := client.GetTransfers(ctx, dero.GetTransfersParams{In: true, MinHeight: e.cursor})
	if err != nil {
		return nil, err
	}
	carrier := ratchetwire.ChainCarrier{
		Chain: dero.NewBackend(client),
		Codec: ratchetwire.DeroChainCodec{},
	}
	ep, err := ratchetwire.NewDurableEndpoint(e.store, e.states, time.Now())
	if err != nil {
		return nil, err
	}
	var out []webMsg
	if entries == nil {
		out = []webMsg{} // encode as [], never null
	}
	maxHeight := e.cursor
	for _, entry := range entries {
		if entry.TXID == "" {
			continue
		}
		if entry.Height >= maxHeight {
			maxHeight = entry.Height + 1
		}
		payload, derr := dero.EntryPayload(entry)
		if derr != nil {
			continue
		}
		inc := chain.Incoming{TxID: entry.TXID, Sender: entry.Sender, Payload: payload}
		// Dedupe by the pointer's identity (the receive path's dedupe rule:
		// one message per identity, not per txid — a pointer may ride several
		// records on chain).
		entryID := dero.EntryIdentity(entry, payload)
		frame, ptr, ferr := carrier.FetchIncomingE2(e.store, inc, time.Now())
		if ferr != nil {
			continue
		}
		if entryID == "" || e.seen[entryID] {
			continue
		}
		var plain []byte
		var decErr error
		switch frame.Kind {
		case ratchetwire.FrameInit:
			plain, decErr = ep.ReceiveFirstFromOPKPool(e.identity, e.spk, e.pool, frame, mustBody(e.store, ptr))
		case ratchetwire.FrameMessage:
			plain, decErr = ep.ReceiveNext(ptr, time.Now())
		default:
			decErr = ratchetwire.ErrLegacyDowngrade
		}
		if decErr != nil {
			continue
		}
		e.seen[entryID] = true
		out = append(out, webMsg{Txid: entry.TXID, Text: string(plain)})
	}
	e.cursor = maxHeight
	if b := []byte(strconv.FormatUint(e.cursor, 10)); len(b) > 0 {
		_ = os.WriteFile(e.cursorFile, b, 0o600)
	}
	return out, nil
}

// mustBody mirrors the CLI's body fetch: the body must be present because the
// frame was decoded against it. A nil body would mean the store lied.
func mustBody(st ratchetwire.BodyStore, p ratchetwire.Pointer) []byte {
	b, err := ratchetwire.GetBody(st, p, time.Now())
	if err != nil {
		return nil
	}
	return b
}
