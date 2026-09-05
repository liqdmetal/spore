// Package channel is the group-communication layer for compost: an IRC-style
// channel box that relays TTL-bounded lines and tracks presence. The box is a
// rendezvous point only — it never holds a channel key, so it can store a
// private room's ciphertext without ever being able to read it.
//
// Three tiers live here, matching the design:
//
//	unicast        (session pkg) per-message ECDH — nothing in this package
//	private room   members seal each line under a shared channel key Kc;
//	               the box relays ciphertext it cannot read.
//	public room    lines are plaintext; anyone connected can read while live.
//
// Privacy is enforced by encryption (at the endpoints), NOT by the box
// deciding who may read — the box relays both kinds and TTL-reaps them. Access
// control to the key is out of the box's scope (that is the DERO-signature +
// membership layer).
//
// A channel's "online" state is the box's presence list: members heartbeat and
// stale entries are evicted. Presence necessarily lives on the always-on box —
// you cannot learn if an offline peer's own daemon is up (it is the thing that
// would answer).
package channel

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/liqdmetal/compost/internal/crypto"
)

// Line is one message as stored/relayed by the box.
type Line struct {
	Channel string `json:"channel"`
	Seq     uint64 `json:"seq"`
	TS      int64  `json:"ts"` // unix ms
	Sender  string `json:"sender"`
	Private bool   `json:"private"`
	// Data is the XChaCha20 ciphertext (Private=true) or raw UTF-8 (false).
	Data []byte `json:"data"`
}

// Presence is one member's last heartbeat.
type Presence struct {
	Channel string `json:"channel"`
	Addr    string `json:"addr"`
	TS      int64  `json:"ts"` // unix ms
}

// LineTTL / PresenceTTL bound how long the box keeps a line / marks someone on.
type BoxConfig struct {
	LineTTL     time.Duration // how long lines survive
	PresenceTTL time.Duration // how long a member is "online" without heartbeat
	ReapEvery   time.Duration // reaper cadence
	MaxLines    int           // per-channel ring cap (0 = unbounded)
}

// Box is a channel relay server. Thread-safe.
type Box struct {
	mu       sync.Mutex
	cfg      BoxConfig
	channels map[string]*room
	done     chan struct{}
}

type room struct {
	lines      []Line
	nextSeq    uint64
	presence   map[string]int64 // addr -> last heartbeat unix ms
	lastPruned time.Time
}

// NewBox builds an empty channel box. Reaper starts in the background.
func NewBox(cfg BoxConfig) *Box {
	if cfg.LineTTL <= 0 {
		cfg.LineTTL = 15 * time.Minute
	}
	if cfg.PresenceTTL <= 0 {
		cfg.PresenceTTL = time.Minute
	}
	if cfg.ReapEvery <= 0 {
		cfg.ReapEvery = 30 * time.Second
	}
	if cfg.MaxLines <= 0 {
		cfg.MaxLines = 2000
	}
	b := &Box{cfg: cfg, channels: map[string]*room{}, done: make(chan struct{})}
	go b.reaperLoop()
	return b
}

func (b *Box) reaperLoop() {
	t := time.NewTicker(b.cfg.ReapEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			b.Reap(time.Now())
		case <-b.done:
			return
		}
	}
}

// Stop halts the reaper.
func (b *Box) Stop() { close(b.done) }

func (b *Box) room(name string) *room {
	r, ok := b.channels[name]
	if !ok {
		r = &room{nextSeq: 1, presence: map[string]int64{}}
		b.channels[name] = r
	}
	return r
}

// Post appends a line (pre-sealed by the sender if private) and returns it
// with its assigned seq/ts.
func (b *Box) Post(ch string, sender string, private bool, data []byte) Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	r := b.room(ch)
	r.pruneLocked(now, b.cfg)
	ln := Line{Channel: ch, Seq: r.nextSeq, TS: now.UnixMilli(), Sender: sender, Private: private, Data: append([]byte(nil), data...)}
	r.nextSeq++
	r.lines = append(r.lines, ln)
	if b.cfg.MaxLines > 0 && len(r.lines) > b.cfg.MaxLines {
		drop := len(r.lines) - b.cfg.MaxLines
		r.lines = append([]Line(nil), r.lines[drop:]...)
	}
	return ln
}

// Poll returns live lines in ch with seq > after. Expired lines are dropped.
func (b *Box) Poll(ch string, after uint64) []Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	r := b.room(ch)
	r.pruneLocked(now, b.cfg)
	out := make([]Line, 0, 16)
	for _, ln := range r.lines {
		if ln.Seq > after {
			out = append(out, ln)
		}
	}
	return out
}

// Heartbeat marks addr present in ch.
func (b *Box) Heartbeat(ch, addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.room(ch).presence[addr] = time.Now().UnixMilli()
}

// Online returns the live members of ch (heartbeat within PresenceTTL).
func (b *Box) Online(ch string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.room(ch)
	cut := time.Now().Add(-b.cfg.PresenceTTL).UnixMilli()
	out := make([]string, 0, len(r.presence))
	for addr, ts := range r.presence {
		if ts >= cut {
			out = append(out, addr)
		}
	}
	return out
}

// Reap evicts expired lines and stale presence across all rooms.
func (b *Box) Reap(now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, r := range b.channels {
		n += r.pruneLocked(now, b.cfg)
		cut := now.Add(-b.cfg.PresenceTTL).UnixMilli()
		for addr, ts := range r.presence {
			if ts < cut {
				delete(r.presence, addr)
			}
		}
	}
	return n
}

func (r *room) pruneLocked(now time.Time, cfg BoxConfig) int {
	if cfg.LineTTL <= 0 {
		return 0
	}
	cut := now.Add(-cfg.LineTTL).UnixMilli()
	keep := 0
	for _, ln := range r.lines {
		if ln.TS >= cut {
			r.lines[keep] = ln
			keep++
		}
	}
	removed := len(r.lines) - keep
	r.lines = r.lines[:keep]
	return removed
}

// --- endpoint crypto helpers (the client side, NOT the box) ---

// Key is a per-channel symmetric key. Nil/zero-length means the channel is
// public (lines are plaintext). Private rooms share one Key among members.
type Key [32]byte

// SealLine encrypts a plaintext line under the channel key with a fresh random
// XChaCha20 nonce. Output is nonce(24) || ciphertext. The nonce rides in the
// clear (it is not secret); the box never holds the key, so it cannot read the
// room. Compost: rotate the Key and old lines become unrecoverable.
func SealLine(k *Key, ch string, plaintext []byte) ([]byte, error) {
	key, err := deriveChannelKey(k, ch)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)

	nonce := make([]byte, crypto.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct, err := crypto.Seal(plaintext, key, nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, crypto.NonceSize+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenLine decrypts a line sealed by SealLine. Wrong key/channel -> AEAD fail.
func OpenLine(k *Key, ch string, blob []byte) ([]byte, error) {
	if len(blob) <= crypto.NonceSize {
		return nil, errors.New("channel: short sealed line")
	}
	key, err := deriveChannelKey(k, ch)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)
	return crypto.Open(blob[crypto.NonceSize:], key, blob[:crypto.NonceSize])
}

// deriveChannelKey derives a deterministic per-channel AEAD key from the
// shared channel key. Nonce uniqueness comes from the random per-line nonce,
// so no sequence state needs to be shared between sender and box.
func deriveChannelKey(k *Key, ch string) ([]byte, error) {
	h := hkdf.New(sha256.New, k[:], nil, []byte("compost/channel/key/"+ch))
	key := make([]byte, crypto.KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Hex serializes a Key (for config/persistence).
func (k *Key) Hex() string { return hex.EncodeToString(k[:]) }

// KeyFromHex parses a 32-byte hex channel key.
func KeyFromHex(s string) (*Key, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, err
	}
	var k Key
	copy(k[:], b)
	return &k, nil
}
