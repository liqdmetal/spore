package roster

// Package roster is the publisher's subscriber list and the subscriber's
// channel state: the missing half of a newsletter system.
//
// `spore publish` produces an issue and a notice. Something has to remember WHO
// gets the notice, WHETHER they have paid, and WHERE each subscriber left off.
// That is this package.
//
// WHY THE ROSTER IS PUBLISHER-SIDE AND LOCAL
//
// There is no subscription server. A publisher keeps a local roster file; a
// subscriber keeps a local channel file. Nobody else holds the list, which
// means:
//
//   - No platform can deplatform a publisher: the list is the publisher's own
//     file, portable to any machine, any carrier.
//   - No platform can see the list: subscriber addresses never leave the
//     publisher's disk. There is no central directory to subpoena or leak.
//   - A publisher who loses the file loses the list. That is the trade for
//     having no custodian, so BackupHint exists to say so out loud.
//
// PAID SUBSCRIPTIONS WITHOUT AN ACCOUNT
//
// A paid subscription is normally an account: identity, billing record,
// payment history. That is exactly the linkage a private newsletter must not
// create. So paid access uses the same prepaid anonymous credits as metered
// messaging: a subscriber redeems a credit for N issues, and the roster stores
// only a COUNTER and an expiry — never a payment, an invoice, or an amount.
//
// The publisher can answer "is this subscriber entitled to issue 12?" without
// being able to answer "what did this person pay, and when".

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sub is one subscriber on one channel.
type Sub struct {
	// Addr is the carrier address the notice is sent to.
	Addr string `json:"addr"`
	// PinnedSig is the subscriber's out-of-band trust anchor, required to
	// start a pairwise session with them.
	PinnedSig string `json:"pinned_sig"`
	// Nick is optional local labelling for the publisher's own use.
	Nick string `json:"nick,omitempty"`
	// IssuesLeft is the remaining paid entitlement. -1 means unlimited (a
	// free/comped subscriber); 0 means lapsed.
	IssuesLeft int `json:"issues_left"`
	// Until is an optional expiry (RFC3339, empty = none). A subscription can
	// be time-based, count-based, or both.
	Until string `json:"until,omitempty"`
	// Added is a coarse UTC DAY, not a timestamp: a publisher does not need to
	// know the minute someone subscribed, and storing it would be a needless
	// metadata trail.
	Added string `json:"added"`
}

// Entitled reports whether this subscriber should receive the next issue.
func (s *Sub) Entitled(now time.Time) (bool, string) {
	if s.Until != "" {
		until, err := time.Parse(time.RFC3339, s.Until)
		if err != nil {
			return false, "unparseable expiry"
		}
		if now.After(until) {
			return false, "subscription expired " + s.Until
		}
	}
	if s.IssuesLeft == 0 {
		return false, "no issues remaining (lapsed)"
	}
	return true, ""
}

// Roster is a publisher's list for ONE channel.
type Roster struct {
	mu      sync.Mutex
	path    string
	Channel string          `json:"channel"`
	NextSeq uint64          `json:"next_seq"`
	Subs    map[string]*Sub `json:"subs"`
}

// Open loads or creates the roster for a channel.
func Open(path, channel string) (*Roster, error) {
	if path == "" {
		return nil, errors.New("roster: path is required")
	}
	r := &Roster{path: path, Channel: channel, NextSeq: 1, Subs: map[string]*Sub{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, err
	}
	if len(raw) == 0 {
		return r, nil
	}
	if err := json.Unmarshal(raw, r); err != nil {
		return nil, fmt.Errorf("roster: %s is corrupt: %w", path, err)
	}
	if r.Subs == nil {
		r.Subs = map[string]*Sub{}
	}
	if r.NextSeq == 0 {
		r.NextSeq = 1
	}
	if channel != "" && r.Channel != "" && r.Channel != channel {
		return nil, fmt.Errorf("roster: %s is for channel %q, not %q", path, r.Channel, channel)
	}
	if r.Channel == "" {
		r.Channel = channel
	}
	return r, nil
}

// Add inserts or updates a subscriber.
//
// issues is the entitlement to GRANT: a positive count, or -1 for unlimited.
// Adding an existing subscriber ADDS to their remaining issues rather than
// replacing, so a renewal never silently shortens a subscription.
func (r *Roster) Add(addr, pinnedSig, nick string, issues int, until time.Time, now time.Time) (*Sub, error) {
	if addr == "" {
		return nil, errors.New("roster: subscriber address is required")
	}
	if pinnedSig == "" {
		return nil, errors.New("roster: pinned-sig is required — it is the out-of-band trust anchor for sending to this subscriber")
	}
	if issues == 0 {
		return nil, errors.New("roster: grant a positive issue count, or -1 for unlimited")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	s, exists := r.Subs[addr]
	if !exists {
		s = &Sub{Addr: addr, Added: now.UTC().Format("2006-01-02")}
		r.Subs[addr] = s
	}
	if s.PinnedSig != "" && s.PinnedSig != pinnedSig {
		return nil, fmt.Errorf("roster: %s is already pinned to a DIFFERENT key (%s); refusing to silently re-pin — remove and re-add deliberately if the key really rotated", addr, s.PinnedSig)
	}
	s.PinnedSig = pinnedSig
	if nick != "" {
		s.Nick = nick
	}
	switch {
	case issues < 0:
		s.IssuesLeft = -1 // unlimited
	case s.IssuesLeft < 0:
		// already unlimited; leave it
	default:
		s.IssuesLeft += issues
	}
	if !until.IsZero() {
		s.Until = until.UTC().Format(time.RFC3339)
	}
	return s, r.saveLocked()
}

// Remove deletes a subscriber. Their past issues stay readable to them: they
// already have the plaintext, and pretending otherwise would be a lie.
func (r *Roster) Remove(addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.Subs[addr]; !ok {
		return fmt.Errorf("roster: %s is not subscribed", addr)
	}
	delete(r.Subs, addr)
	return r.saveLocked()
}

// Recipients returns the subscribers entitled to the next issue, plus the ones
// skipped and why. Both halves are returned so a publisher sees who lapsed
// instead of silently under-sending.
func (r *Roster) Recipients(now time.Time) (send []*Sub, skipped map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	skipped = map[string]string{}
	addrs := make([]string, 0, len(r.Subs))
	for a := range r.Subs {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs) // deterministic order for reproducible sends
	for _, a := range addrs {
		s := r.Subs[a]
		if ok, why := s.Entitled(now); ok {
			send = append(send, s)
		} else {
			skipped[a] = why
		}
	}
	return send, skipped
}

// CommitIssue decrements entitlements for the subscribers an issue was actually
// sent to, and advances the channel's next sequence number.
//
// It is called AFTER a successful send so a failed send does not consume a
// subscriber's paid issue.
func (r *Roster) CommitIssue(seq uint64, sent []*Sub) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range sent {
		live, ok := r.Subs[s.Addr]
		if !ok {
			continue
		}
		if live.IssuesLeft > 0 {
			live.IssuesLeft--
		}
	}
	if seq >= r.NextSeq {
		r.NextSeq = seq + 1
	}
	return r.saveLocked()
}

// saveLocked persists atomically. A truncated roster is a lost subscriber list,
// so the write is temp-then-rename.
func (r *Roster) saveLocked() error {
	type wire struct {
		Channel string          `json:"channel"`
		NextSeq uint64          `json:"next_seq"`
		Subs    map[string]*Sub `json:"subs"`
	}
	blob, err := json.MarshalIndent(wire{r.Channel, r.NextSeq, r.Subs}, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(r.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, append(blob, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// Count returns the number of subscribers on the roster.
func (r *Roster) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Subs)
}

// Get returns a copy of one subscriber's record.
func (r *Roster) Get(addr string) (*Sub, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.Subs[addr]
	if !ok {
		return nil, false
	}
	cp := *s
	return &cp, true
}

// BackupHint states the cost of having no custodian. It is surfaced by the CLI
// because "we cannot lose your list" and "nobody else holds your list" cannot
// both be true.
func (r *Roster) BackupHint() string {
	return fmt.Sprintf("Your subscriber list lives ONLY at %s. No platform holds a copy, "+
		"so nobody can deplatform you and nobody can leak your list — but if you lose "+
		"this file, the list is gone. Back it up.", r.path)
}

// Channel is a SUBSCRIBER's local state for one publication: the pinned
// publisher key and the highest issue accepted so far.
//
// LastSeq is the replay defence. Without persisting it, a relay could
// re-deliver an old issue as current and the subscriber would accept it.
type Channel struct {
	mu           sync.Mutex
	path         string
	Name         string `json:"name"`
	PublisherPub string `json:"publisher_pub"`
	LastSeq      uint64 `json:"last_seq"`
}

// OpenChannel loads or creates subscriber-side channel state.
//
// publisherPub is the pinned key. If the file already pins a DIFFERENT key,
// this fails: a silently changing publisher key is indistinguishable from an
// impersonation attempt, so it must be a deliberate act.
func OpenChannel(path, name, publisherPub string) (*Channel, error) {
	if path == "" {
		return nil, errors.New("roster: channel state path is required")
	}
	c := &Channel{path: path, Name: name, PublisherPub: publisherPub}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if publisherPub == "" {
				return nil, errors.New("roster: a new channel needs the publisher key you pinned out-of-band")
			}
			return c, c.save()
		}
		return nil, err
	}
	var onDisk Channel
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		return nil, fmt.Errorf("roster: channel state %s is corrupt: %w", path, err)
	}
	if publisherPub != "" && onDisk.PublisherPub != "" && onDisk.PublisherPub != publisherPub {
		return nil, fmt.Errorf("roster: channel %q is pinned to publisher %s but you supplied %s — "+
			"a changed publisher key is indistinguishable from impersonation; verify out-of-band and "+
			"delete this file only if the rotation is genuine", onDisk.Name, onDisk.PublisherPub, publisherPub)
	}
	onDisk.path = path
	if onDisk.Name == "" {
		onDisk.Name = name
	}
	return &onDisk, nil
}

// Accept records that an issue was accepted, advancing the replay floor.
func (c *Channel) Accept(seq uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seq <= c.LastSeq {
		return fmt.Errorf("roster: issue %d does not advance past %d", seq, c.LastSeq)
	}
	c.LastSeq = seq
	return c.saveLocked()
}

func (c *Channel) save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

func (c *Channel) saveLocked() error {
	type wire struct {
		Name         string `json:"name"`
		PublisherPub string `json:"publisher_pub"`
		LastSeq      uint64 `json:"last_seq"`
	}
	blob, err := json.MarshalIndent(wire{c.Name, c.PublisherPub, c.LastSeq}, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(c.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, append(blob, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Seq returns the highest accepted issue number.
func (c *Channel) Seq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.LastSeq
}

// FormatSub renders a subscriber line for CLI listing.
func FormatSub(s *Sub, now time.Time) string {
	ent := "OK"
	if ok, why := s.Entitled(now); !ok {
		ent = "SKIP: " + why
	}
	left := fmt.Sprintf("%d", s.IssuesLeft)
	if s.IssuesLeft < 0 {
		left = "unlimited"
	}
	nick := s.Nick
	if nick == "" {
		nick = "-"
	}
	until := s.Until
	if until == "" {
		until = "-"
	}
	return fmt.Sprintf("%-66s  %-12s  issues=%-9s until=%-20s added=%s  %s",
		trim(s.Addr, 66), trim(nick, 12), left, until, s.Added, ent)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// ParseUntil accepts "" (none), an RFC3339 timestamp, or a duration like
// "720h" meaning "from now".
func ParseUntil(v string, now time.Time) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return now.Add(d), nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("roster: -until must be a duration (e.g. 720h) or RFC3339 timestamp: %w", err)
	}
	return t, nil
}
