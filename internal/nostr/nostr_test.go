package nostr

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	n "github.com/nbd-wtf/go-nostr"
)

type fakeRelay struct {
	published *n.Event
	events    []n.Event
}

func (f *fakeRelay) Publish(ctx context.Context, e n.Event) error { f.published = &e; return nil }
func (f *fakeRelay) QuerySync(context.Context, n.Filter) ([]*n.Event, error) {
	out := make([]*n.Event, len(f.events))
	for i := range f.events {
		out[i] = &f.events[i]
	}
	return out, nil
}
func canonicalPointer() []byte {
	p := make([]byte, PointerSize)
	p[0] = 1
	p[PointerSize-1] = 1
	return p
}

func TestRejectsMissingKey(t *testing.T) {
	_, e := New(Config{Relays: []string{"wss://x"}, Network: "mainnet"})
	if e == nil {
		t.Fatal("expected error")
	}
}
func TestPointerCodecStrict(t *testing.T) {
	p := canonicalPointer()
	s, err := encodePointer(p)
	if err != nil || len(s) != PointerSize*2 || s != strings.ToLower(s) {
		t.Fatalf("encode: %v %q", err, s)
	}
	got, err := decodePointer(s)
	if err != nil || string(got) != string(p) {
		t.Fatalf("decode: %v", err)
	}
	for _, bad := range []string{"hello", strings.Repeat("e2", PointerSize-1), "E" + s[1:], s[:len(s)-1] + "g"} {
		if _, err := decodePointer(bad); err == nil {
			t.Errorf("accepted invalid content %q", bad)
		}
	}
}
func TestPostAndListUseEncodedPointer(t *testing.T) {
	key := strings.Repeat("1", 64)
	r := &fakeRelay{}
	c, err := New(Config{PrivateKey: key, Relays: []string{"wss://x"}, Network: "mainnet", Relay: r})
	if err != nil {
		t.Fatal(err)
	}
	p := canonicalPointer()
	if _, err = c.PostPayload(context.Background(), "recipient", p, 0); err != nil {
		t.Fatal(err)
	}
	if r.published.Content != hex.EncodeToString(p) {
		t.Fatal("pointer was not lowercase hex encoded")
	}
	r.events = []n.Event{{Content: r.published.Content, CreatedAt: 1}}
	got, err := c.ListIncoming(context.Background(), 0)
	if err != nil || len(got) != 1 || string(got[0].Payload) != string(p) {
		t.Fatalf("list: %v %#v", err, got)
	}
}
