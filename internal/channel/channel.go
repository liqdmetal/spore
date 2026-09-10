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
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/liqdmetal/spore/internal/crypto"
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

// BoxConfig bounds how long the box keeps lines / presence AND how big the
// box may grow (audit M3: unbounded rooms/presence/data = memory + I/O DoS).
type BoxConfig struct {
	LineTTL     time.Duration // how long lines survive
	PresenceTTL time.Duration // how long a member is "online" without heartbeat
	ReapEvery   time.Duration // reaper cadence
	MaxLines    int           // per-channel ring cap (0 = unbounded)
	// DoS caps (0 = default, negative = unlimited):
	MaxRooms     int           // total number of channels the box will create
	MaxPresence  int           // presence entries per channel
	MaxDataLen   int           // bytes per line payload
	MaxSenderLen int           // bytes per sender string
	MaxSaveEvery time.Duration // min interval between full-state saves (I/O amplification guard)
}

// Box is a channel relay server. Thread-safe.
type Box struct {
	mu       sync.Mutex
	cfg      BoxConfig
	channels map[string]*room
	done     chan struct{}
	stopOnce sync.Once
	dir      string    // optional persistence dir; empty = in-memory only
	lastSave time.Time // last full-state save (I/O amplification guard)
}

type room struct {
	lines      []Line
	nextSeq    uint64
	presence   map[string]int64 // addr -> last heartbeat unix ms
	lastPruned time.Time
}

// Defaults for the DoS caps (audit M3).
const (
	DefaultMaxRooms     = 256
	DefaultMaxPresence  = 512
	DefaultMaxDataLen   = 4096
	DefaultMaxSenderLen = 128
	DefaultMaxSaveEvery = 5 * time.Second
)

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
	// DoS cap defaults (0 = use default; negative = unlimited).
	if cfg.MaxRooms == 0 {
		cfg.MaxRooms = DefaultMaxRooms
	}
	if cfg.MaxPresence == 0 {
		cfg.MaxPresence = DefaultMaxPresence
	}
	if cfg.MaxDataLen == 0 {
		cfg.MaxDataLen = DefaultMaxDataLen
	}
	if cfg.MaxSenderLen == 0 {
		cfg.MaxSenderLen = DefaultMaxSenderLen
	}
	if cfg.MaxSaveEvery == 0 {
		cfg.MaxSaveEvery = DefaultMaxSaveEvery
	}
	b := &Box{cfg: cfg, channels: map[string]*room{}, done: make(chan struct{})}
	go b.reaperLoop()
	return b
}

// NewPersistentBox builds a channel box that persists rooms to dir, so lines
// survive process restarts (still honoring LineTTL for rot). Loads existing
// state on startup. Presence is never persisted (it is live-only).
func NewPersistentBox(cfg BoxConfig, dir string) (*Box, error) {
	b := NewBox(cfg)
	b.dir = dir
	if err := b.load(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Box) savePath() string  { return b.dir + "/channels.json" }
func (b *Box) saveLocked() error { return saveBox(b) }
func (b *Box) load() error       { return loadBox(b) }

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

// Stop halts the reaper and, for a persistent box, flushes any state not yet
// written (the MaxSaveEvery throttle may have deferred it). A graceful
// shutdown therefore never drops lines that were accepted; only a hard crash
// within MaxSaveEvery of the last save can lose the trailing window — that is
// the accepted trade of the I/O-amplification guard (audit M3). Idempotent.
func (b *Box) Stop() {
	b.mu.Lock()
	if b.dir != "" {
		_ = b.saveLocked() // best-effort final flush
	}
	b.mu.Unlock()
	b.stopOnce.Do(func() { close(b.done) })
}

func (b *Box) room(name string) (*room, error) {
	r, ok := b.channels[name]
	if ok {
		return r, nil
	}
	if b.cfg.MaxRooms > 0 && len(b.channels) >= b.cfg.MaxRooms {
		return nil, fmt.Errorf("channel: room limit (%d) exceeded — no new rooms", b.cfg.MaxRooms)
	}
	r = &room{nextSeq: 1, presence: map[string]int64{}}
	b.channels[name] = r
	return r, nil
}

func (b *Box) existingRoom(name string) *room {
	return b.channels[name]
}

// Post appends a line (pre-sealed by the sender if private) and returns it
// with its assigned seq/ts. Sender and data are bounded (DoS caps).
func (b *Box) Post(ch string, sender string, private bool, data []byte) (Line, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cfg.MaxSenderLen > 0 && len(sender) > b.cfg.MaxSenderLen {
		return Line{}, fmt.Errorf("channel: sender too long (%d > %d)", len(sender), b.cfg.MaxSenderLen)
	}
	if b.cfg.MaxDataLen > 0 && len(data) > b.cfg.MaxDataLen {
		return Line{}, fmt.Errorf("channel: data too long (%d > %d)", len(data), b.cfg.MaxDataLen)
	}
	r, err := b.room(ch)
	if err != nil {
		return Line{}, err
	}
	now := time.Now()
	r.pruneLocked(now, b.cfg)
	ln := Line{Channel: ch, Seq: r.nextSeq, TS: now.UnixMilli(), Sender: sender, Private: private, Data: append([]byte(nil), data...)}
	r.nextSeq++
	r.lines = append(r.lines, ln)
	if b.cfg.MaxLines > 0 && len(r.lines) > b.cfg.MaxLines {
		drop := len(r.lines) - b.cfg.MaxLines
		r.lines = append([]Line(nil), r.lines[drop:]...)
	}
	// Persist at most once per MaxSaveEvery (audit M3: the old code rewrote
	// the whole state file on EVERY post — an I/O amplification lever).
	if b.dir != "" && (b.lastSave.IsZero() || now.Sub(b.lastSave) >= b.cfg.MaxSaveEvery) {
		b.saveLocked() // best-effort
		b.lastSave = now
	}
	return ln, nil
}

// Poll returns live lines in ch with seq > after. Expired lines are dropped.
// Unknown channels are NOT created by polling (polling must not consume the
// room budget).
func (b *Box) Poll(ch string, after uint64) []Line {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Line
	r := b.existingRoom(ch)
	if r == nil {
		return out
	}
	now := time.Now()
	r.pruneLocked(now, b.cfg)
	out = make([]Line, 0, 16)
	for _, ln := range r.lines {
		if ln.Seq > after {
			out = append(out, ln)
		}
	}
	return out
}

// Heartbeat marks addr present in ch (bounded presence; no room creation).
func (b *Box) Heartbeat(ch, addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.existingRoom(ch)
	if r == nil {
		if b.cfg.MaxRooms > 0 && len(b.channels) >= b.cfg.MaxRooms {
			return // refuse to grow
		}
		r = &room{nextSeq: 1, presence: map[string]int64{}}
		b.channels[ch] = r
	}
	if b.cfg.MaxPresence > 0 {
		if _, known := r.presence[addr]; !known && len(r.presence) >= b.cfg.MaxPresence {
			return // presence full; do not grow
		}
	}
	r.presence[addr] = time.Now().UnixMilli()
}

// Online returns the live members of ch (heartbeat within PresenceTTL).
func (b *Box) Online(ch string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.existingRoom(ch)
	if r == nil {
		return nil
	}
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
	if n > 0 {
		b.saveLocked()
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
