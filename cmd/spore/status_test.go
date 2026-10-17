package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/evm"
	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/sporrelay"
	"github.com/liqdmetal/spore/internal/store"
)

// shippedMailbox registers a temporary shipped default so the status line can
// be exercised against a real registry entry without a live deployment. It is
// restored (or deleted) when the test ends.
func shippedMailbox(t *testing.T, key string, d evm.MailboxDeployment) {
	t.Helper()
	prev, had := evm.KnownMailboxDeployments[key]
	evm.KnownMailboxDeployments[key] = d
	t.Cleanup(func() {
		if had {
			evm.KnownMailboxDeployments[key] = prev
		} else {
			delete(evm.KnownMailboxDeployments, key)
		}
	})
}

func TestStatusJSONReportClassifiesConfiguredAndUnprobedAreas(t *testing.T) {
	report, err := buildStatusJSONReport([]statusProbe{{name: "cosmos", ok: true, address: "spore1test", height: 42}, {name: "evm", skipped: true, detail: "no RPC"}}, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != StatusJSONSchema || !report.ReadOnly || report.GeneratedAt == "" {
		t.Fatalf("invalid status envelope: %+v", report)
	}
	if report.Summary.Checks != len(report.Checks) || report.Summary.Status != "incomplete" || report.Summary.Skipped < 3 {
		t.Fatalf("bad status summary: %+v", report.Summary)
	}
	found := map[string]statusJSONCheck{}
	for _, check := range report.Checks {
		found[check.ID] = check
	}
	if found["carrier-cosmos"].Status != "ok" || found["carrier-evm"].Status != "skipped" {
		t.Fatalf("carrier statuses missing: %+v", found)
	}
	if found["body-store"].Status != "skipped" || found["message-gaps"].Status != "skipped" {
		t.Fatalf("durable gap ledger/no-session status or unprobed body store misrepresented: %+v", found)
	}
	var encoded bytes.Buffer
	if err := renderStatusJSON(&encoded, report); err != nil {
		t.Fatal(err)
	}
	var roundTrip statusJSONReport
	if err := json.Unmarshal(encoded.Bytes(), &roundTrip); err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	if err := renderStatusText(&text, report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"carrier-cosmos", "body-store", "next:", "incomplete:"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text status missing %q: %s", want, text.String())
		}
	}
	if err := renderStatusJSON(nil, report); err == nil {
		t.Fatal("JSON renderer accepted nil writer")
	}
	if err := renderStatusText(nil, report); err == nil {
		t.Fatal("text renderer accepted nil writer")
	}
}

func TestStatusReportsHumanActionsAndQueuedCarrierState(t *testing.T) {
	buyerKey := bytes.Repeat([]byte{0x11}, 32)
	providerKey := bytes.Repeat([]byte{0x22}, 32)
	buyerPub, err := secure.SigPubOf(buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	providerPub, err := secure.SigPubOf(providerKey)
	if err != nil {
		t.Fatal(err)
	}
	brief, policy := []byte("private brief"), []byte("buyer reviews the exact result")
	id, err := handoff.NewID()
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := handoff.NewID()
	if err != nil {
		t.Fatal(err)
	}
	terms := handoff.Terms{ID: id, Registration: handoff.Registration{Version: 1, RelayURL: "http://127.0.0.1:8720", ActorID: "did:relay:" + strings.Repeat("a", 40), ObservedAt: time.Now().Add(-time.Minute).Unix(), Objective: sporrelay.WorkOrder{ObjectiveID: "objective:status-test", OwnerPseudonym: "actor:buyer", DescriptionCommitment: handoff.Commitment(brief), PolicyHash: handoff.Commitment(policy)}}, Buyer: handoff.Peer{Address: "buyer", Pinned: hex.EncodeToString(buyerPub)}, Provider: handoff.Peer{Address: "provider", Pinned: hex.EncodeToString(providerPub)}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	event, err := handoff.Sign(handoff.Message{Version: 1, Terms: terms, EventID: eventID, Sequence: 1, Kind: "brief", Content: brief, Policy: policy}, buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	stateDir := filepath.Join(home, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, "state.key")
	key := bytes.Repeat([]byte{0x73}, 32)
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("73", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(stateDir, "handoffs.enc")
	store, err := handoff.Open(handoffPath, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(event, event.Message.Sender(), "0011223344556677", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	report, err := buildStatusJSONReport(nil, "", home, stateDir, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := findStatusJSONCheck(t, report, "handoffs"); got.Status != "warning" || !strings.Contains(got.Detail, "queued locally") {
		t.Fatalf("queued outbound handoff status not actionable: %+v", got)
	}
	providerHome := t.TempDir()
	providerStateDir := filepath.Join(providerHome, "state")
	if err := os.Mkdir(providerStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	providerKeyPath := filepath.Join(providerHome, "state.key")
	if err := os.WriteFile(providerKeyPath, []byte(strings.Repeat("73", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	providerStore, err := handoff.Open(filepath.Join(providerStateDir, "handoffs.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := providerStore.Apply(event, event.Message.Recipient(), "0011223344556677", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	providerReport, err := buildStatusJSONReport(nil, "", providerHome, providerStateDir, providerKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := findStatusJSONCheck(t, providerReport, "handoffs"); got.Status != "ok" || !strings.Contains(got.Detail, "queue clear") {
		t.Fatalf("inbound persisted handoff must not be counted as locally queued: %+v", got)
	}
	if got := findStatusJSONCheck(t, providerReport, "handoff-human-action"); got.Status != "warning" || !strings.Contains(got.Detail, "1 provider brief review") {
		t.Fatalf("provider human action missing: %+v", got)
	}
}

func TestStatusReadsDurableRecoverableGapsAfterRestart(t *testing.T) {
	fixture, err := lossStateFixture(t, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir, key := fixture.dir, fixture.key
	stateDir := filepath.Join(dir, "state")
	before, err := os.ReadFile(filepath.Join(stateDir, "session-"+fixture.session+".state"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := ratchetwire.ReadOnlyGaps(stateDir, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Pending) != 1 || report.Pending[0].N != 1 || report.LostTotal != 0 {
		t.Fatalf("read-only durable gap report = %+v", report)
	}
	after, err := os.ReadFile(filepath.Join(stateDir, "session-"+fixture.session+".state"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("gap status changed protected ratchet state: %v", err)
	}
}

type statusGapFixture struct {
	dir     string
	key     []byte
	session string
}

func lossStateFixture(t *testing.T, ttl time.Duration) (statusGapFixture, error) {
	t.Helper()
	body := store.NewMemStore()
	aliceID := bytes.Repeat([]byte{0x41}, 32)
	bobID := bytes.Repeat([]byte{0x42}, 32)
	bobSPK := bytes.Repeat([]byte{0x43}, 32)
	var opk [32]byte
	opk[0] = 0x44
	bundle, err := ratchet.BuildBundle(bobID, bobSPK, 1, &opk, 9)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x52}, 32)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	aliceStates, err := ratchetwire.NewFileStateStore(filepath.Join(dir, "alice"), key)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := ratchetwire.NewDurableEndpoint(body, aliceStates, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bobStates, err := ratchetwire.NewFileStateStore(stateDir, key)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ratchetwire.NewDurableEndpoint(body, bobStates, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pin, err := secure.SigPubOf(bobID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(ttl)
	first, _, session, err := alice.SendFirstSession(aliceID, bundle, pin, []byte("first"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	ptrs := make([]ratchetwire.Pointer, 3)
	ptrs[0] = first
	ptrs[1], _, err = alice.SendNext(session, []byte("second"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	ptrs[2], _, err = alice.SendNext(session, []byte("third"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := ratchetwire.FetchFrame(body, ptrs[0], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReceiveFirst(bobID, bobSPK, &opk, frame, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReceiveNext(ptrs[2], time.Now()); err != nil {
		t.Fatal(err)
	}
	sessionID := bob.Sessions.IDs()[0]
	return statusGapFixture{dir: dir, key: key, session: fmt.Sprintf("%x", sessionID)}, nil
}

func TestStatusConfigDefaultsCoverStatePaths(t *testing.T) {
	home := t.TempDir()
	stateDir := filepath.Join(home, "custom-state")
	keyPath := filepath.Join(home, "custom.key")
	configPath := filepath.Join(home, "config.json")
	configRaw, err := json.Marshal(Config{StateDir: stateDir, StateKey: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("status-test", flag.ContinueOnError)
	fs.String("config", "", "")
	fs.String("state-dir", "", "")
	fs.String("state-key", "", "")
	if err := fs.Parse([]string{"-config", configPath}); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigForFlags(fs); err != nil {
		t.Fatal(err)
	}
	report, err := buildStatusJSONReport(nil, "", home, fs.Lookup("state-dir").Value.String(), fs.Lookup("state-key").Value.String())
	if err != nil {
		t.Fatal(err)
	}
	if got := findStatusJSONCheck(t, report, "handoffs"); got.Status != "ok" {
		t.Fatalf("configured absent store should report empty without creating it: %+v", got)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("status created configured state directory: %v", err)
	}
}

func TestStatusReadOnlyHandoffRecoveryAndQueue(t *testing.T) {
	home := t.TempDir()
	stateDir := filepath.Join(home, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, "state.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("73", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	handoffPath := filepath.Join(stateDir, "handoffs.enc")
	if err := os.WriteFile(handoffPath, []byte("not an encrypted handoff store"), 0o600); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(stateDir, "receive-pending.enc")
	if err := os.WriteFile(journalPath, []byte("journal sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeStore, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := buildStatusJSONReport(nil, "", home, stateDir, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Errors == 0 {
		t.Fatal("invalid encrypted handoff store should be surfaced as an error")
	}
	if got := findStatusJSONCheck(t, report, "receive-recovery"); got.Status != "warning" {
		t.Fatalf("pending journal must be visible and advisory: %+v", got)
	}
	storeAfter, err := os.ReadFile(handoffPath)
	if err != nil || !bytes.Equal(beforeStore, storeAfter) {
		t.Fatalf("status changed encrypted handoff state: %v", err)
	}
	afterInfo, err := os.Stat(journalPath)
	if err != nil || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatalf("status changed receive journal metadata: %v", err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("status created/removed state artifacts: %v %v", entries, err)
	}
}

func findStatusJSONCheck(t *testing.T, report statusJSONReport, id string) statusJSONCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("status report missing check %q", id)
	return statusJSONCheck{}
}

func TestMailboxStatusLineShippedDefault(t *testing.T) {
	const addr = "0x1234567890ABCDEF1234567890abcdef12345678"
	shippedMailbox(t, "8453", evm.MailboxDeployment{
		ChainID: 8453, Address: addr, Default: "v0.9.0",
		ReceiptRef: "docs/LIVE_NODES.md §3",
	})

	line := mailboxStatusLine(addr, 8453, true)
	for _, want := range []string{"chain=8453", "shipped default", "v0.9.0"} {
		if !strings.Contains(line, want) {
			t.Fatalf("shipped-default line missing %q: %q", want, line)
		}
	}
	if strings.Contains(line, "user override") {
		t.Fatalf("a registry-backed address must not read as a user override: %q", line)
	}
	if strings.Contains(line, "⚠") {
		t.Fatalf("a shipped default on its own chain must not warn: %q", line)
	}
}

func TestMailboxStatusLineShippedDefaultChainMismatch(t *testing.T) {
	const addr = "0x1234567890ABCDEF1234567890abcdef12345678"
	shippedMailbox(t, "8453", evm.MailboxDeployment{
		ChainID: 8453, Address: addr, Default: "v0.9.0",
		ReceiptRef: "docs/LIVE_NODES.md §3",
	})

	// Same address, but the RPC is on Base Sepolia (84532) — the foot-gun the
	// registry exists to catch.
	line := mailboxStatusLine(addr, 84532, true)
	if !strings.Contains(line, "chain=8453") || !strings.Contains(line, "connected chain is 84532") {
		t.Fatalf("registry chain id and a differing connected chain must both show: %q", line)
	}
}

func TestMailboxStatusLineUserOverride(t *testing.T) {
	// A made-up address is nobody's shipped default — the operator's own.
	line := mailboxStatusLine("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD", 31337, true)
	if !strings.Contains(line, "user override") || !strings.Contains(line, "chain=31337") {
		t.Fatalf("user-override line wrong: %q", line)
	}
	if strings.Contains(line, "shipped default") {
		t.Fatalf("an unknown address must not read as a shipped default: %q", line)
	}
}

func TestMailboxStatusLineUserOverrideUnknownChain(t *testing.T) {
	line := mailboxStatusLine("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD", 0, false)
	if !strings.Contains(line, "user override") || !strings.Contains(line, "chain=unknown") {
		t.Fatalf("an override whose chain cannot be read must say unknown: %q", line)
	}
}

func TestMailboxStatusLineNoneConfigured(t *testing.T) {
	line := mailboxStatusLine("", 8453, true)
	if !strings.Contains(line, "none configured") {
		t.Fatalf("no-mailbox line wrong: %q", line)
	}
	if strings.Contains(line, "user override") || strings.Contains(line, "shipped default") {
		t.Fatalf("a missing mailbox must not claim a source: %q", line)
	}
}
