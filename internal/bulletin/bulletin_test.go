package bulletin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	sporenostr "github.com/liqdmetal/spore/internal/nostr"
	"github.com/liqdmetal/spore/internal/store"
	nostr "github.com/nbd-wtf/go-nostr"
)

// bulletinTestPool is a hostile-relay-capable pool double: it returns exactly
// the events a test selects, without silently applying Nostr filter semantics.
type bulletinTestPool struct {
	mu       sync.Mutex
	events   []nostr.Event
	queryErr error
	queries  int
}

func (p *bulletinTestPool) Publish(_ context.Context, event nostr.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
	return nil
}

func (p *bulletinTestPool) Query(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	if filter.Limit < 0 || filter.Limit > MaxRelayResults {
		return nil, fmt.Errorf("test relay: unbounded result limit %d", filter.Limit)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.queries++
	if p.queryErr != nil {
		return nil, p.queryErr
	}
	out := make([]*nostr.Event, 0, len(p.events))
	for i := range p.events {
		event := p.events[i]
		if len(filter.Kinds) != 0 && !containsKind(filter.Kinds, event.Kind) {
			continue
		}
		if !testEventMatchesTags(event.Tags, filter.Tags) {
			continue
		}
		out = append(out, &event)
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func testEventMatchesTags(tags nostr.Tags, filter nostr.TagMap) bool {
	for key, values := range filter {
		matched := false
		for _, tag := range tags {
			if len(tag) < 2 || tag[0] != key {
				continue
			}
			for _, actual := range tag[1:] {
				for _, candidate := range values {
					if actual == candidate {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func containsKind(kinds []int, kind int) bool {
	for _, candidate := range kinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

var _ store.Store = (*sporenostr.NostrStore)(nil)
var _ Pool = (*bulletinTestPool)(nil)

func newBulletinTest(t *testing.T) (*bulletinTestPool, ed25519.PublicKey, ed25519.PrivateKey, string, *sporenostr.NostrStore) {
	t.Helper()
	publisherPub, publisherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayKey := "5ee1c8000be2852402b61ba7d79d06a2d8404e79b3c0c9d2ff1f8a7a1a6f0e2c"
	pool := &bulletinTestPool{}
	bodyStore, err := NewNostrBodyStore(pool, relayKey, "")
	if err != nil {
		t.Fatal(err)
	}
	return pool, publisherPub, publisherPriv, relayKey, bodyStore
}

func (p *bulletinTestPool) noticeEvents() []nostr.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]nostr.Event, 0, len(p.events))
	for _, event := range p.events {
		if event.Kind == NoticeKind {
			out = append(out, event)
		}
	}
	return out
}

func (p *bulletinTestPool) setNoticeEvents(events []nostr.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append([]nostr.Event(nil), events...)
}

func countNoticeEvents(events []nostr.Event) int {
	count := 0
	for _, event := range events {
		if event.Kind == NoticeKind {
			count++
		}
	}
	return count
}

func resignNoticeEvent(t *testing.T, event *nostr.Event) {
	t.Helper()
	if err := event.Sign("5ee1c8000be2852402b61ba7d79d06a2d8404e79b3c0c9d2ff1f8a7a1a6f0e2c"); err != nil {
		t.Fatal(err)
	}
}

func publishForTest(t *testing.T, pool Pool, bodyStore store.Store, relayKey string, publisher ed25519.PrivateKey, sequence uint64, body []byte) *Notice {
	t.Helper()
	notice, _, err := Publish(context.Background(), pool, bodyStore, relayKey, publisher, "forest", sequence, body, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return notice
}

func resequenceNoticeForTest(t *testing.T, publisher ed25519.PrivateKey, notice *Notice, sequence uint64) {
	t.Helper()
	sig := ed25519.Sign(publisher, transcript(notice.Channel, sequence, notice.CID, notice.Deadline))
	notice.Sequence = sequence
	notice.Sig = hex.EncodeToString(sig)
}

func encodeNoticeRecordForTest(t *testing.T, event *nostr.Event, publisher ed25519.PublicKey, notice *Notice) {
	t.Helper()
	content, err := json.Marshal(NostrRecord{Publisher: hex.EncodeToString(publisher), Notice: notice})
	if err != nil {
		t.Fatal(err)
	}
	event.Content = string(content)
}

func encodeBodyEventForTest(t *testing.T, body []byte, cid string, deadline int64) nostr.Event {
	t.Helper()
	event := nostr.Event{Kind: sporenostr.BodyKind, CreatedAt: nostr.Timestamp(time.Now().Unix()), Tags: nostr.Tags{nostr.Tag{"cid", cid}, nostr.Tag{"exp", fmt.Sprint(deadline)}}, Content: base64.StdEncoding.EncodeToString(body)}
	resignNoticeEvent(t, &event)
	return event
}

func TestPublicBulletinPublishAndFetchSequence(t *testing.T) {
	pool, publisherPub, publisherPriv, relayKey, bodyStore := newBulletinTest(t)
	body := []byte("signed public bulletin snapshot")
	deadline := time.Now().Add(time.Hour)
	notice, eventID, err := Publish(context.Background(), pool, bodyStore, relayKey, publisherPriv, "forest", 1, body, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if eventID == "" || notice.Sequence != 1 {
		t.Fatalf("publish returned event %q and notice %+v", eventID, notice)
	}
	if len(pool.noticeEvents()) != 1 {
		t.Fatalf("published notice event count = %d, want 1", len(pool.noticeEvents()))
	}
	gotNotice, gotBody, gotEventID, err := FetchSequence(context.Background(), pool, publisherPub, "forest", 1, time.Now())
	if err != nil {
		t.Fatalf("FetchSequence: %v", err)
	}
	if gotNotice.CID != notice.CID || gotEventID != eventID || string(gotBody) != string(body) {
		t.Fatalf("round trip mismatch: notice=%+v event=%q body=%q", gotNotice, gotEventID, gotBody)
	}
	if err := VerifySequence(publisherPub, gotNotice, gotBody, "forest", 1, time.Now()); err != nil {
		t.Fatalf("round-trip signature verification: %v", err)
	}
}

func TestFetchSequenceRejectsUnpinnedPublisher(t *testing.T) {
	pool, _, publisherPriv, relayKey, bodyStore := newBulletinTest(t)
	publishForTest(t, pool, bodyStore, relayKey, publisherPriv, 1, []byte("authentic bulletin"))
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := FetchSequence(context.Background(), pool, otherPub, "forest", 1, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("wrong pinned publisher error = %v, want not found", err)
	}
}

func TestFetchSequenceRejectsDuplicateBindingTags(t *testing.T) {
	for _, tagName := range []string{"channel", "seq", "cid", "exp"} {
		t.Run(tagName, func(t *testing.T) {
			pool, publisherPub, publisherPriv, relayKey, bodyStore := newBulletinTest(t)
			publishForTest(t, pool, bodyStore, relayKey, publisherPriv, 1, []byte("authentic bulletin"))
			events := pool.noticeEvents()
			if len(events) != 1 {
				t.Fatalf("notice events = %d, want 1", len(events))
			}
			event := events[0]
			duplicate := "forged-value"
			if tagName == "seq" {
				duplicate = "1"
			} else if tagName == "cid" {
				var record NostrRecord
				if err := json.Unmarshal([]byte(event.Content), &record); err != nil {
					t.Fatal(err)
				}
				duplicate = record.Notice.CID
			} else if tagName == "exp" {
				duplicate = strconv.FormatInt(time.Now().Add(2*time.Hour).Unix(), 10)
			} else if tagName == "channel" {
				duplicate = "forest"
			}
			event.Tags = append(event.Tags, nostr.Tag{tagName, duplicate})
			resignNoticeEvent(t, &event)
			pool.setNoticeEvents([]nostr.Event{event})
			if _, _, _, err := FetchSequence(context.Background(), pool, publisherPub, "forest", 1, time.Now()); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("duplicate tag accepted, err=%v", err)
			}
		})
	}
}

func TestFetchSequenceRejectsMalformedRecord(t *testing.T) {
	pool, publisherPub, publisherPriv, relayKey, bodyStore := newBulletinTest(t)
	publishForTest(t, pool, bodyStore, relayKey, publisherPriv, 1, []byte("authentic bulletin"))
	for _, content := range []string{
		`{"publisher":"not-hex","notice":{}} trailing`,
		`{"publisher":"not-hex","notice":{}} {"second":true}`,
		`{"publisher":"not-hex","notice":{},"unknown":true}`,
	} {
		event := pool.noticeEvents()[0]
		event.Content = content
		resignNoticeEvent(t, &event)
		pool.setNoticeEvents([]nostr.Event{event})
		if _, _, _, err := FetchSequence(context.Background(), pool, publisherPub, "forest", 1, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("malformed record %q accepted, err=%v", content, err)
		}
	}
}

func TestFetchBodyRejectsDuplicateBindingTags(t *testing.T) {
	body := []byte("signed ciphertext")
	cidBytes := BodyCID(body)
	cid := hex.EncodeToString(cidBytes[:])
	deadline := time.Now().Add(time.Hour).Unix()
	for _, tagName := range []string{"cid", "exp"} {
		t.Run(tagName, func(t *testing.T) {
			pool, _, _, _, _ := newBulletinTest(t)
			event := encodeBodyEventForTest(t, body, cid, deadline)
			done := "duplicate"
			if tagName == "cid" {
				done = cid
			} else {
				done = fmt.Sprint(deadline + 3600)
			}
			event.Tags = append(event.Tags, nostr.Tag{tagName, done})
			resignNoticeEvent(t, &event)
			pool.setNoticeEvents([]nostr.Event{event})
			if _, err := FetchBody(context.Background(), pool, cid, deadline, time.Now()); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("duplicate %s tag accepted, err=%v", tagName, err)
			}
		})
	}
}

func TestSignVerifyBindsChannelSequenceBodyAndDeadline(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("release 1: bulletin body")
	deadline := time.Now().Add(30 * time.Minute)
	notice, err := Sign(privateKey, "forest", 1, body, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySequence(publicKey, notice, body, "forest", 1, time.Now()); err != nil {
		t.Fatalf("valid bulletin rejected: %v", err)
	}
	cid := BodyCID(body)
	if len(notice.Sig) != ed25519.SignatureSize*2 || notice.CID != hex.EncodeToString(cid[:]) {
		t.Fatalf("unexpected signed notice: %+v", notice)
	}

	tampered := *notice
	tampered.Channel = "other"
	if err := Verify(publicKey, &tampered, body, time.Now()); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered channel error = %v, want signature error", err)
	}
	tampered = *notice
	tampered.Deadline++
	if err := Verify(publicKey, &tampered, body, time.Now()); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered deadline error = %v, want signature error", err)
	}
	if err := Verify(publicKey, notice, []byte("changed body"), time.Now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered body error = %v, want invalid", err)
	}
	if err := VerifySequence(publicKey, notice, body, "forest", 2, time.Now()); !errors.Is(err, ErrSequence) {
		t.Fatalf("replay sequence error = %v, want sequence error", err)
	}
	artifact, err := notice.SignatureArtifact()
	if err != nil || artifact.Sequence != notice.Sequence || artifact.CID != notice.CID {
		t.Fatalf("signature artifact = %+v, %v", artifact, err)
	}
}

func TestRelayPoolRejectsInvalidAndUnboundedEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		relays []string
	}{
		{name: "empty", relays: nil},
		{name: "no usable endpoint", relays: []string{"", "  "}},
		{name: "wrong scheme", relays: []string{"https://relay.example"}},
		{name: "embedded credentials", relays: []string{"wss://user:secret@relay.example"}},
		{name: "fragment", relays: []string{"wss://relay.example/path#fragment"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRelayPool(tc.relays); err == nil {
				t.Fatal("invalid relay configuration accepted")
			}
		})
	}
	if _, err := NewRelayPool([]string{"wss://relay.example", "relay.example"}); err != nil {
		t.Fatalf("valid/deduplicated relays rejected: %v", err)
	}
	tooMany := make([]string, MaxRelays+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("relay-%d.example", i)
	}
	if _, err := NewRelayPool(tooMany); err == nil {
		t.Fatal("relay count above cap accepted")
	}
}

func TestRelayPoolQueryRejectsCancelledContextBeforeDial(t *testing.T) {
	pool, err := NewRelayPool([]string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pool.Query(ctx, nostr.Filter{Kinds: []int{NoticeKind}, Limit: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled query error = %v, want context.Canceled", err)
	}
}

func TestClampFilterBoundsRelayResults(t *testing.T) {
	for _, limit := range []int{-1, 0, 1, MaxRelayResults, MaxRelayResults + 1} {
		original := nostr.Filter{Kinds: []int{NoticeKind}, Limit: limit}
		bounded := clampFilter(original)
		want := limit
		if want <= 0 || want > MaxRelayResults {
			want = MaxRelayResults
		}
		if bounded.Limit != want {
			t.Fatalf("clampFilter(%d).Limit=%d, want %d", limit, bounded.Limit, want)
		}
		if original.Limit != limit {
			t.Fatalf("clampFilter mutated caller filter: limit=%d want original=%d", original.Limit, limit)
		}
	}
	for _, limit := range []int{1, MaxRelayResults, MaxRelayResults + 1} {
		want := limit
		if want > MaxRelayResults {
			want = MaxRelayResults
		}
		if got := queryBatchLimit(nostr.Filter{Limit: limit}); got != want {
			t.Fatalf("queryBatchLimit(%d)=%d, want %d", limit, got, want)
		}
	}
}

func TestRelayPoolBoundsQueryLimit(t *testing.T) {
	requests := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		_, payload, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		requests <- payload
		_ = conn.Write(context.Background(), websocket.MessageText, []byte(`["EOSE","1"]`))
	}))
	defer server.Close()
	pool, err := NewRelayPool([]string{strings.Replace(server.URL, "http://", "ws://", 1)})
	if err != nil {
		t.Fatal(err)
	}
	filter := nostr.Filter{Kinds: []int{NoticeKind}, Limit: MaxRelayResults + 1}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := pool.Query(ctx, filter); err != nil {
		t.Fatalf("query: %v", err)
	}
	select {
	case raw := <-requests:
		var message []any
		if err := json.Unmarshal(raw, &message); err != nil {
			t.Fatalf("decode REQ: %v", err)
		}
		if len(message) != 3 {
			t.Fatalf("REQ element count=%d, want 3", len(message))
		}
		got, ok := message[2].(map[string]any)
		if !ok || got["limit"] != float64(MaxRelayResults) {
			t.Fatalf("relay REQ filter=%v, limit not clamped to %d", message[2], MaxRelayResults)
		}
	case <-ctx.Done():
		t.Fatalf("relay did not receive REQ: %v", ctx.Err())
	}
	if filter.Limit != MaxRelayResults+1 {
		t.Fatalf("caller filter mutated: limit=%d", filter.Limit)
	}
}

func TestRelayPoolQueryContextCancelsInflightRelay(t *testing.T) {
	connected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		connected <- struct{}{}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		_, _, _ = conn.Read(context.Background())
	}))
	defer server.Close()
	pool, err := NewRelayPool([]string{strings.Replace(server.URL, "http://", "ws://", 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := pool.Query(ctx, nostr.Filter{Kinds: []int{NoticeKind}, Limit: 1})
		result <- err
	}()
	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("query did not connect to local relay")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled in-flight query error=%v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("query did not stop after caller context cancellation")
	}
}

func TestRelayPoolPublishContextCancelsBeforeDial(t *testing.T) {
	pool, err := NewRelayPool([]string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pool.Publish(ctx, nostr.Event{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled publish error=%v, want context.Canceled", err)
	}
}

func TestRelayPoolQueryRejectsNilContext(t *testing.T) {
	pool, err := NewRelayPool([]string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Query(nil, nostr.Filter{Limit: 1}); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestRelayPoolPublishRejectsNilContext(t *testing.T) {
	pool, err := NewRelayPool([]string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Publish(nil, nostr.Event{}); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestRelayPoolUnavailableRelayFailsWithinBound(t *testing.T) {
	pool, err := NewRelayPool([]string{"ws://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err = pool.Query(ctx, nostr.Filter{Limit: 1})
	if err == nil {
		t.Fatal("unreachable relay query succeeded")
	}
	if time.Since(started) >= 2*time.Second {
		t.Fatalf("unreachable relay query exceeded test deadline: %v", time.Since(started))
	}
}

func TestSignAndVerifyRejectBoundaries(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validUntil := time.Now().Add(time.Hour)
	cases := []struct {
		name     string
		channel  string
		sequence uint64
		body     []byte
		deadline time.Time
	}{
		{name: "empty channel", channel: "", sequence: 1, body: []byte("x"), deadline: validUntil},
		{name: "colon channel", channel: "a:b", sequence: 1, body: []byte("x"), deadline: validUntil},
		{name: "zero sequence", channel: "forest", sequence: 0, body: []byte("x"), deadline: validUntil},
		{name: "empty body", channel: "forest", sequence: 1, body: nil, deadline: validUntil},
		{name: "expired", channel: "forest", sequence: 1, body: []byte("x"), deadline: time.Now().Add(-time.Second)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Sign(privateKey, tc.channel, tc.sequence, tc.body, tc.deadline); err == nil {
				t.Fatal("Sign accepted invalid input")
			}
		})
	}
	if _, err := Sign(privateKey[:ed25519.SeedSize], "forest", 1, []byte("x"), validUntil); err == nil {
		t.Fatal("Sign accepted seed instead of full Ed25519 private key")
	}
	valid, err := Sign(privateKey, "forest", 1, []byte("x"), validUntil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicKey, valid, []byte("x"), time.Unix(valid.Deadline, 0)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("notice at its inclusive deadline error = %v, want invalid", err)
	}
	if err := Verify(nil, valid, []byte("x"), time.Now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil publisher key error = %v, want invalid", err)
	}
	if _, err := ParseSequence("18446744073709551616"); err == nil {
		t.Fatal("ParseSequence accepted overflow")
	}
}

func TestBodyCIDRejectsMutationAndNoticeArtifactsValidate(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notice, err := Sign(privateKey, "forest", 7, []byte("snapshot"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	badCases := []*Notice{nil}
	bad := *notice
	bad.CID = "ABC"
	badCases = append(badCases, &bad)
	bad = *notice
	bad.Sig = "00"
	badCases = append(badCases, &bad)
	bad = *notice
	bad.Version++
	badCases = append(badCases, &bad)
	for i, candidate := range badCases {
		if err := Verify(publicKey, candidate, []byte("snapshot"), time.Now()); err == nil {
			t.Fatalf("invalid notice case %d accepted", i)
		}
	}
	if got := BodyCID([]byte("a")); got == BodyCID([]byte("b")) {
		t.Fatal("different body bytes produced the same CID")
	}
	if _, err := notice.SignatureArtifact(); err != nil {
		t.Fatal(err)
	}
	bad = *notice
	bad.CID = "ABC"
	if _, err := bad.SignatureArtifact(); err == nil {
		t.Fatal("artifact accepted malformed CID")
	}
}

func TestPublicBulletinDVMUsesGoTranscript(t *testing.T) {
	contract, err := os.ReadFile("public-bulletin-v1.dvm")
	if err != nil {
		t.Fatal(err)
	}
	want := "LET msg=" + strconv.Quote(Domain) + `+":"+channel+":"+ITOA(seq)+":"+cid+":"+ITOA(deadline)`
	if !strings.Contains(string(contract), want) {
		t.Fatalf("DVM transcript does not match Go transcript; wanted %q", want)
	}
}

func TestChannelGrammarAndSequenceCeiling(t *testing.T) {
	for _, channel := range []string{"a", "Forest_1.v2-3", strings.Repeat("x", 64)} {
		if !validChannel(channel) {
			t.Errorf("valid channel %q rejected", channel)
		}
	}
	for _, channel := range []string{"", strings.Repeat("x", 65), "a:b", "a/b", "a b", "a\\n", "é"} {
		if validChannel(channel) {
			t.Errorf("invalid channel %q accepted", channel)
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Hour)
	body := []byte("sequence-boundary")
	maxNotice, err := Sign(privateKey, "forest", MaxSequence, body, deadline)
	if err != nil {
		t.Fatalf("maximum DVM sequence rejected: %v", err)
	}
	if err := Verify(publicKey, maxNotice, body, time.Now()); err != nil {
		t.Fatalf("maximum DVM sequence failed verification: %v", err)
	}
	if _, err := maxNotice.SignatureArtifact(); err != nil {
		t.Fatalf("maximum DVM sequence artifact rejected: %v", err)
	}
	if parsed, err := ParseSequence(strconv.FormatUint(MaxSequence, 10)); err != nil || parsed != MaxSequence {
		t.Fatalf("maximum sequence parse=(%d,%v)", parsed, err)
	}

	tooHigh := uint64(MaxSequence) + 1
	if _, err := Sign(privateKey, "forest", tooHigh, body, deadline); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Sign above DVM ceiling error=%v, want ErrInvalid", err)
	}
	if _, err := ParseSequence(strconv.FormatUint(tooHigh, 10)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseSequence above DVM ceiling error=%v, want ErrInvalid", err)
	}
	if err := VerifySequence(publicKey, maxNotice, body, "forest", tooHigh, time.Now()); !errors.Is(err, ErrSequence) {
		t.Fatalf("VerifySequence above DVM ceiling error=%v, want ErrSequence", err)
	}
	bad := *maxNotice
	bad.Sequence = tooHigh
	if err := Verify(publicKey, &bad, body, time.Now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Verify above DVM ceiling error=%v, want ErrInvalid", err)
	}
	if _, err := bad.SignatureArtifact(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("artifact above DVM ceiling error=%v, want ErrInvalid", err)
	}
}
