package ratchetwire

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/mailbox"
	"github.com/liqdmetal/spore/internal/notify"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// TestHostedTwoPartyE2Acceptance exercises the closed-beta path over real HTTP:
// publish and consume a single-use prekey, push an encrypted frame to an
// authenticated mailbox, carry only its opaque pointer through the DERO codec,
// decrypt it, restart the receiver from durable state, and decrypt a reply.
// This is intentionally broader than a package-level round-trip: it catches
// mismatches between the mailbox HTTP surface, HTTPStore, ratchet lifecycle,
// DERO pointer codec, and encrypted state persistence.
func TestHostedTwoPartyE2Acceptance(t *testing.T) {
	const mailboxToken = "hosted-beta-mailbox-token"
	mailboxDir := t.TempDir()
	m, err := mailbox.Open(mailboxDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(m.HandlerToken(mailboxToken))
	defer server.Close()

	aliceID := randomKey(t)
	bobID := randomKey(t)
	bobSPK := randomKey(t)
	bobOPK := randomKey(t)
	var bobOPKArray [32]byte
	copy(bobOPKArray[:], bobOPK)
	bundle, err := ratchet.BuildBundle(bobID, bobSPK, 7, &bobOPKArray, 19)
	if err != nil {
		t.Fatal(err)
	}

	publishPrekeyBatch(t, server.URL+"/prekey-batch", mailboxToken, []ratchet.SPKBundle{*bundle})
	gotBundle := fetchPrekey(t, server.URL+"/prekey", mailboxToken)
	if gotBundle.IKPub != bundle.IKPub || gotBundle.SPKPub != bundle.SPKPub || gotBundle.OPKPub == nil {
		t.Fatal("hosted prekey did not round-trip")
	}
	if resp := getWithToken(t, server.URL+"/prekey", mailboxToken); resp.StatusCode != http.StatusNotFound {
		resp.Body.Close()
		t.Fatalf("single-use prekey remained available: %s", resp.Status)
	} else {
		resp.Body.Close()
	}

	remote, err := store.NewHTTPStoreWithToken(server.URL, mailboxToken)
	if err != nil {
		t.Fatal(err)
	}
	wrongRemote, err := store.NewHTTPStoreWithToken(server.URL, "wrong-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongRemote.Put([32]byte{1}, []byte("should-not-store"), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("unauthorized HTTPStore PUT succeeded")
	}

	senderStateKey := randomKey(t)
	senderStates, err := NewFileStateStore(filepath.Join(t.TempDir(), "alice-state"), senderStateKey)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewDurableEndpoint(remote, senderStates, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	receiverStateDir := filepath.Join(t.TempDir(), "bob-state")
	receiverStateKey := randomKey(t)
	receiverStates, err := NewFileStateStore(receiverStateDir, receiverStateKey)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDurableEndpoint(remote, receiverStates, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	bobSig, err := secure.SigPubOf(bobID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Hour)
	firstPlain := []byte("hosted beta first message")
	ptr, rawPointer, err := sender.SendFirst(aliceID, &gotBundle, bobSig, firstPlain, deadline)
	if err != nil {
		t.Fatal(err)
	}

	// The DERO payload contains only W/R/C/D pointer arguments. It must not
	// contain either the plaintext or the serialized E2 frame.
	deroPayload, err := (DeroChainCodec{}).EncodePointer(PointerPayload{
		Version: PointerV1, Route: ptr.Route, CID: ptr.CID, BurnDeadline: ptr.BurnDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := (DeroChainCodec{}).DecodePointer(deroPayload)
	if !ok || decoded.Pointer() != ptr {
		t.Fatalf("DERO pointer did not round-trip: %#v %#v", decoded, ptr)
	}
	frame, err := FetchFrame(remote, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rawFrame, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(deroPayload, firstPlain) || bytes.Contains(deroPayload, rawFrame) || bytes.Contains(rawPointer, firstPlain) {
		t.Fatal("plaintext or serialized E2 body leaked into the chain pointer")
	}

	// The receiver identity is Bob's private identity. Keep this explicit so a
	// future refactor cannot accidentally use the sender key in the hosted path.
	plain, err := receiver.ReceiveFirst(bobID, bobSPK, &bobOPKArray, frame, rawFrame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, firstPlain) {
		t.Fatalf("first plaintext = %q", plain)
	}

	// Hosted arrival notification is metadata-only and must be emitted only
	// after local decryption. Exercise the real dispatcher over HTTP and assert
	// neither plaintext nor the serialized frame crosses the provider boundary.
	notificationBody := make(chan []byte, 1)
	notificationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer notification-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		notificationBody <- body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer notificationServer.Close()
	dispatcher, err := notify.New(notify.Options{
		WebhookURL:   notificationServer.URL,
		WebhookToken: "notification-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Send(notify.Event{
		TxID:     hex.EncodeToString(ptr.CID[:]),
		Subject:  "Spore private message",
		Received: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-notificationBody:
		if bytes.Contains(body, firstPlain) || bytes.Contains(body, rawFrame) {
			t.Fatal("notification leaked plaintext or serialized E2 frame")
		}
		if !bytes.Contains(body, []byte(hex.EncodeToString(ptr.CID[:]))) {
			t.Fatalf("notification omitted the message CID: %s", body)
		}
	case <-time.After(time.Second):
		t.Fatal("notification webhook was not called")
	}

	ids := sender.Sessions.IDs()
	if len(ids) != 1 {
		t.Fatalf("sender sessions = %d, want 1", len(ids))
	}
	if len(receiver.Sessions.IDs()) != 1 {
		t.Fatalf("receiver sessions = %d, want 1", len(receiver.Sessions.IDs()))
	}

	// Restart Bob from the encrypted durable state before receiving the
	// continuation. This is the beta's crash/restart acceptance criterion.
	receiverStates2, err := NewFileStateStore(receiverStateDir, receiverStateKey)
	if err != nil {
		t.Fatal(err)
	}
	receiverAfterRestart, err := NewDurableEndpoint(remote, receiverStates2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secondPlain := []byte("hosted beta reply after restart")
	ptr2, _, err := sender.SendNext(ids[0], secondPlain, deadline)
	if err != nil {
		t.Fatal(err)
	}
	gotSecond, err := receiverAfterRestart.ReceiveNext(ptr2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSecond, secondPlain) {
		t.Fatalf("continuation plaintext = %q", gotSecond)
	}

	// Complete the bidirectional acceptance path: Bob replies after the
	// restart, and Alice decrypts the reply using her persisted session.
	replyPlain := []byte("hosted beta reply from bob")
	replyPtr, _, err := receiverAfterRestart.SendNext(ids[0], replyPlain, deadline)
	if err != nil {
		t.Fatal(err)
	}
	gotReply, err := sender.ReceiveNext(replyPtr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotReply, replyPlain) {
		t.Fatalf("reply plaintext = %q", gotReply)
	}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func publishPrekeyBatch(t *testing.T, url, token string, bundles []ratchet.SPKBundle) {
	t.Helper()
	body, err := json.Marshal(struct {
		Bundles []ratchet.SPKBundle `json:"bundles"`
	}{Bundles: bundles})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("publish prekey batch: %s", resp.Status)
	}
}

func fetchPrekey(t *testing.T, url, token string) ratchet.SPKBundle {
	t.Helper()
	resp := getWithToken(t, url, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch prekey: %s", resp.Status)
	}
	var got mailbox.PrekeyBundle
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	return got.Bundle
}

func getWithToken(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
