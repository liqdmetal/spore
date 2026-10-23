package bulletin

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	sporenostr "github.com/liqdmetal/spore/internal/nostr"
	"github.com/liqdmetal/spore/internal/store"
	nostr "github.com/nbd-wtf/go-nostr"
)

const bulletinBodyKind = sporenostr.BodyKind

type Pool interface {
	Publish(context.Context, nostr.Event) error
	Query(context.Context, nostr.Filter) ([]*nostr.Event, error)
}

// NostrRecord is the signed-Nostr event payload that binds a publisher's
// identity-authenticated notice to this public bulletin transport.
type NostrRecord struct {
	Publisher string  `json:"publisher"`
	Notice    *Notice `json:"notice"`
}

// RelayPool speaks to a configured set of Nostr relays. It is a public,
// best-effort transport, not a consensus service or durable registry.
type RelayPool struct {
	relays []string
}

const relayOperationTimeout = 20 * time.Second

func clampFilter(filter nostr.Filter) nostr.Filter {
	if filter.Limit <= 0 || filter.Limit > MaxRelayResults {
		filter.Limit = MaxRelayResults
	}
	return filter
}

func queryBatchLimit(filter nostr.Filter) int {
	limit := MaxRelayResults
	if filter.Limit > 0 && filter.Limit < limit {
		limit = filter.Limit
	}
	return limit
}

func boundedRelayContext(parent context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := parent.Deadline(); ok && time.Until(deadline) <= relayOperationTimeout {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, relayOperationTimeout)
}

func NewRelayPool(relays []string) (*RelayPool, error) {
	if len(relays) == 0 {
		return nil, errors.New("bulletin: at least one Nostr relay is required")
	}
	if len(relays) > MaxRelays {
		return nil, fmt.Errorf("bulletin: relay count %d exceeds cap %d", len(relays), MaxRelays)
	}
	seen := make(map[string]struct{}, len(relays))
	clean := make([]string, 0, len(relays))
	for _, relay := range relays {
		relay = strings.TrimSpace(relay)
		if relay == "" {
			continue
		}
		if !strings.Contains(relay, "://") {
			relay = "wss://" + relay
		}
		u, err := url.Parse(relay)
		if err != nil || (u.Scheme != "wss" && u.Scheme != "ws") || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("bulletin: invalid relay URL %q", relay)
		}
		if _, ok := seen[relay]; ok {
			continue
		}
		seen[relay] = struct{}{}
		clean = append(clean, relay)
	}
	if len(clean) == 0 {
		return nil, errors.New("bulletin: no usable Nostr relays")
	}
	return &RelayPool{relays: clean}, nil
}

func NewNostrBodyStore(pool Pool, privateKeyHex, indexPath string) (*sporenostr.NostrStore, error) {
	if pool == nil || strings.TrimSpace(privateKeyHex) == "" {
		return nil, errors.New("bulletin: body store requires a relay pool and dedicated Nostr key")
	}
	return sporenostr.NewNostrStore(sporenostr.NostrStoreConfig{
		PrivateKey:    privateKeyHex,
		IndexPath:     indexPath,
		MaxBody:       MaxNotice,
		MaxIndexBytes: MaxIndexBytes,
		MaxIndexItems: MaxIndexedBodies,
		Pool:          pool,
	})
}

func (p *RelayPool) Publish(ctx context.Context, event nostr.Event) error {
	if p == nil || len(p.relays) == 0 {
		return sporenostr.ErrNoRelay
	}
	if ctx == nil {
		return errors.New("bulletin: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var lastErr error
	published := 0
	for _, endpoint := range p.relays {
		if err := ctx.Err(); err != nil {
			return err
		}
		relayCtx, cancel := boundedRelayContext(ctx)
		relay, err := nostr.RelayConnect(relayCtx, endpoint)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		if relay == nil {
			cancel()
			lastErr = errors.New("bulletin: relay connect returned nil relay")
			continue
		}
		err = relay.Publish(relayCtx, event)
		cancel()
		_ = relay.Close()
		if err != nil {
			lastErr = err
			continue
		}
		published++
	}
	if published > 0 {
		return nil
	}
	if lastErr == nil {
		lastErr = sporenostr.ErrNoRelay
	}
	return fmt.Errorf("bulletin: no relay accepted event: %w", lastErr)
}

func (p *RelayPool) Query(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	if p == nil || len(p.relays) == 0 {
		return nil, sporenostr.ErrNoRelay
	}
	if ctx == nil {
		return nil, errors.New("bulletin: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filter = clampFilter(filter)
	seen := make(map[string]struct{})
	var events []*nostr.Event
	var lastErr error
	succeeded := false
	for _, endpoint := range p.relays {
		if len(events) >= MaxRelayResults {
			break
		}
		if ctx.Err() != nil {
			return events, ctx.Err()
		}
		relayCtx, cancel := boundedRelayContext(ctx)
		relay, err := nostr.RelayConnect(relayCtx, endpoint)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		if relay == nil {
			cancel()
			lastErr = errors.New("bulletin: relay connect returned nil relay")
			continue
		}
		batchFilter := filter
		batchFilter.Limit = queryBatchLimit(filter)
		batch, err := relay.QuerySync(relayCtx, batchFilter)
		cancel()
		_ = relay.Close()
		if ctx.Err() != nil {
			return events, ctx.Err()
		}
		if err != nil {
			lastErr = err
			continue
		}
		succeeded = true
		for _, event := range batch {
			if len(events) >= MaxRelayResults {
				break
			}
			if event == nil {
				continue
			}
			if _, ok := seen[event.ID]; ok {
				continue
			}
			seen[event.ID] = struct{}{}
			events = append(events, event)
		}
	}
	if !succeeded {
		if lastErr == nil {
			lastErr = sporenostr.ErrNoRelay
		}
		return nil, fmt.Errorf("bulletin: all relays failed: %w", lastErr)
	}
	return events, nil
}

// Publish stores the plaintext bulletin body in the configured public body
// store, signs its CID and metadata with the publisher's pinned Spore identity,
// and publishes a Nostr notice event with the dedicated relay key. The body is
// public; only the publisher notice is identity-authenticated.
func Publish(ctx context.Context, pool Pool, bodyStore store.Store, relayKeyHex string, publisherKey ed25519.PrivateKey, channel string, sequence uint64, body []byte, deadline time.Time) (*Notice, string, error) {
	if ctx == nil || pool == nil || bodyStore == nil || !validChannel(channel) || len(body) == 0 || len(body) > MaxNotice {
		return nil, "", ErrInvalid
	}
	if len(publisherKey) != ed25519.PrivateKeySize {
		return nil, "", ErrInvalid
	}
	if _, err := nostr.GetPublicKey(relayKeyHex); err != nil {
		return nil, "", fmt.Errorf("bulletin: invalid dedicated relay key: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	deadline = time.Unix(deadline.Unix(), 0)
	if !deadline.After(time.Now()) {
		return nil, "", ErrInvalid
	}
	notice, err := Sign(publisherKey, channel, sequence, body, deadline)
	if err != nil {
		return nil, "", err
	}
	cid, _ := decodeCID(notice.CID)
	if err := bodyStore.Put(cid, append([]byte(nil), body...), deadline); err != nil {
		return nil, "", fmt.Errorf("bulletin: store public body: %w", err)
	}
	id, err := PublishNotice(ctx, pool, relayKeyHex, publisherKey.Public().(ed25519.PublicKey), notice)
	if err != nil {
		// A failed notice broadcast can leave an unreferenced body until its
		// deadline. Deletion is best-effort on public relays.
		_ = bodyStore.Delete(cid)
		return nil, "", fmt.Errorf("bulletin: notice publish failed (body deletion best-effort): %w", err)
	}
	return notice, id, nil
}

func PublishNotice(ctx context.Context, pool Pool, relayKeyHex string, publisher ed25519.PublicKey, notice *Notice) (string, error) {
	if ctx == nil || pool == nil || len(publisher) != ed25519.PublicKeySize || notice == nil {
		return "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := verifyNoticeSignature(publisher, notice, time.Now()); err != nil {
		return "", err
	}
	if _, err := nostr.GetPublicKey(relayKeyHex); err != nil {
		return "", fmt.Errorf("bulletin: invalid dedicated relay key: %w", err)
	}
	content, err := json.Marshal(NostrRecord{Publisher: hex.EncodeToString(publisher), Notice: notice})
	if err != nil || len(content) > 4096 {
		return "", ErrInvalid
	}
	seq := strconv.FormatUint(notice.Sequence, 10)
	event := nostr.Event{
		Kind:      NoticeKind,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags: nostr.Tags{
			nostr.Tag{"channel", notice.Channel},
			nostr.Tag{"seq", seq},
			nostr.Tag{"cid", notice.CID},
			nostr.Tag{"exp", strconv.FormatInt(notice.Deadline, 10)},
		},
		Content: string(content),
	}
	if err := event.Sign(relayKeyHex); err != nil {
		return "", fmt.Errorf("bulletin: sign Nostr event: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := pool.Publish(ctx, event); err != nil {
		return "", err
	}
	return event.ID, nil
}

func FetchSequence(ctx context.Context, pool Pool, pinnedPublisher ed25519.PublicKey, channel string, sequence uint64, now time.Time) (*Notice, []byte, string, error) {
	if ctx == nil || pool == nil || len(pinnedPublisher) != ed25519.PublicKeySize || !validChannel(channel) || sequence == 0 || sequence > MaxSequence {
		return nil, nil, "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, "", err
	}
	seq := strconv.FormatUint(sequence, 10)
	events, err := pool.Query(ctx, nostr.Filter{Kinds: []int{NoticeKind}, Tags: nostr.TagMap{"channel": []string{channel}, "seq": []string{seq}}, Limit: MaxNoticeEvents})
	if err != nil {
		return nil, nil, "", err
	}
	for _, event := range events {
		if event == nil || event.Kind != NoticeKind {
			continue
		}
		if ok, err := event.CheckSignature(); err != nil || !ok {
			continue
		}
		var record NostrRecord
		decoder := json.NewDecoder(strings.NewReader(event.Content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil || record.Notice == nil {
			continue
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			continue
		}
		if record.Publisher != hex.EncodeToString(pinnedPublisher) || record.Notice.Channel != channel || record.Notice.Sequence != sequence {
			continue
		}
		eventChannel, channelOK := uniqueNostrTag(event.Tags, "channel")
		eventSequence, sequenceOK := uniqueNostrTag(event.Tags, "seq")
		eventCID, cidOK := uniqueNostrTag(event.Tags, "cid")
		eventDeadline, deadlineOK := uniqueNostrTag(event.Tags, "exp")
		if !channelOK || !sequenceOK || !cidOK || !deadlineOK ||
			eventChannel != channel || eventSequence != seq || eventCID != record.Notice.CID ||
			eventDeadline != strconv.FormatInt(record.Notice.Deadline, 10) {
			continue
		}
		body, err := FetchBody(ctx, pool, record.Notice.CID, record.Notice.Deadline, now)
		if err != nil {
			return nil, nil, "", err
		}
		if err := Verify(pinnedPublisher, record.Notice, body, now); err != nil {
			continue
		}
		return record.Notice, body, event.ID, nil
	}
	return nil, nil, "", store.ErrNotFound
}

func FetchBody(ctx context.Context, pool Pool, cidHex string, deadline int64, now time.Time) ([]byte, error) {
	if ctx == nil || pool == nil || deadline <= 0 || now.Unix() >= deadline {
		return nil, ErrInvalid
	}
	cid, err := decodeCID(cidHex)
	if err != nil {
		return nil, err
	}
	events, err := pool.Query(ctx, nostr.Filter{Kinds: []int{sporenostr.BodyKind}, Tags: nostr.TagMap{"cid": []string{cidHex}}, Limit: MaxBodyEvents})
	if err != nil {
		return nil, err
	}
	sawExpired := false
	for _, event := range events {
		if event == nil || event.Kind != sporenostr.BodyKind {
			continue
		}
		eventCID, cidOK := uniqueNostrTag(event.Tags, "cid")
		if !cidOK || eventCID != cidHex {
			continue
		}
		if ok, err := event.CheckSignature(); err != nil || !ok {
			continue
		}
		expTag, expOK := uniqueNostrTag(event.Tags, "exp")
		if !expOK {
			continue
		}
		exp, err := strconv.ParseInt(expTag, 10, 64)
		if err != nil || exp != deadline {
			continue
		}
		if now.Unix() >= exp {
			sawExpired = true
			continue
		}
		body, err := base64.StdEncoding.DecodeString(event.Content)
		if err != nil || len(body) == 0 || len(body) > MaxNotice {
			continue
		}
		if BodyCID(body) != cid {
			return nil, sporenostr.ErrCIDMismatch
		}
		return body, nil
	}
	if sawExpired {
		return nil, store.ErrExpired
	}
	return nil, store.ErrNotFound
}

func verifyNoticeSignature(publicKey ed25519.PublicKey, notice *Notice, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize || notice == nil || notice.Version != Version ||
		!validChannel(notice.Channel) || notice.Sequence == 0 || notice.Sequence > MaxSequence || notice.Deadline <= 0 || now.Unix() >= notice.Deadline {
		return ErrInvalid
	}
	if _, err := decodeCID(notice.CID); err != nil {
		return err
	}
	sig, err := hex.DecodeString(notice.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrSignature
	}
	if !ed25519.Verify(publicKey, transcript(notice.Channel, notice.Sequence, notice.CID, notice.Deadline), sig) {
		return ErrSignature
	}
	return nil
}

func nostrTag(tags nostr.Tags, name string) string {
	value, _ := uniqueNostrTag(tags, name)
	return value
}

// uniqueNostrTag rejects duplicate or malformed instances of a security- or
// content-binding NIP-01 tag instead of silently selecting the first one.
func uniqueNostrTag(tags nostr.Tags, name string) (string, bool) {
	value := ""
	found := false
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != name {
			continue
		}
		if len(tag) != 2 || found {
			return "", false
		}
		value = tag[1]
		found = true
	}
	return value, found
}

var _ Pool = (*RelayPool)(nil)
