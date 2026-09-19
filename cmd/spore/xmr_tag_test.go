package main

import (
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/longmsg"
	"github.com/liqdmetal/spore/internal/store"
)

// TestXMRTagBody: xmrTagBody prepends the "xmr:<addr>\n" header line and leaves
// the body untouched when no XMR address is given.
func TestXMRTagBody(t *testing.T) {
	const addr = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wzn3CRVp9Fp7"
	body := []byte("meet me on the bounty")
	got := xmrTagBody(addr, body)
	if want := "xmr:" + addr + "\nmeet me on the bounty"; string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Original slice must not be mutated.
	if string(body) != "meet me on the bounty" {
		t.Fatalf("input mutated: %q", body)
	}
	if got := xmrTagBody("", body); string(got) != "meet me on the bounty" {
		t.Fatalf("empty addr should pass body through, got %q", got)
	}
}

// TestXMRHeaderSurvivesEncryption (B1 round trip): a body tagged with the XMR
// header line is encrypted with SendBody, held on the sender's store, fetched
// and decrypted by the receiver via ReceiveBody, and the decrypted plaintext
// still carries the "xmr:<addr>" header in front of the original message.
func TestXMRHeaderSurvivesEncryption(t *testing.T) {
	const addr = "4AdUndXHHZ6cfufTMvthY6D4uwDpRyZcHFSFw1tXAdbyCbgYwEytHfYfkG1y6kVtBwyNJZxMDphXQZgjbbyKJoAidhA1Nid"

	sender, err := longmsg.NewEndpoint(store.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := longmsg.NewEndpoint(store.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("bounty payload that never rides a block")
	tagged := xmrTagBody(addr, msg)

	ptr, err := sender.SendBody(receiver.PublicKey(), tagged, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Body stays on the sender's store; the receiver fetches it by CID.
	got, err := receiver.ReceiveBody(ptr, func(c [32]byte) ([]byte, error) {
		return sender.Store().Get(c)
	})
	if err != nil {
		t.Fatal(err)
	}
	gotStr := string(got)
	if !strings.HasPrefix(gotStr, "xmr:"+addr+"\n") {
		t.Fatalf("decrypted body missing xmr header: %q", gotStr)
	}
	if !strings.HasSuffix(gotStr, string(msg)) {
		t.Fatalf("decrypted body missing original message: %q", gotStr)
	}
}
