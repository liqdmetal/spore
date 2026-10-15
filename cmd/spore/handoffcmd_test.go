package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/sporrelay"
	"github.com/liqdmetal/spore/internal/store"
)

func handoffMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestHandoffRealCLIPrivateRoundTrip(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SPORE_HOME", root)
	t.Setenv("SPORE_CONFIG", filepath.Join(root, "absent.json"))
	body := store.NewMemStore()
	bodyServer := store.NewServer(body, time.Hour)
	defer bodyServer.Stop()
	httpStore := httptest.NewServer(bodyServer.Handler())
	defer httpStore.Close()
	type party struct {
		dir, config string
		key, spk    []byte
		peer        handoff.Peer
		bundle      *ratchet.SPKBundle
		ep          *ratchetwire.DurableEndpoint
	}
	makeParty := func(name string, fill byte) *party {
		p := &party{dir: filepath.Join(root, name), key: bytes.Repeat([]byte{fill}, 32), spk: bytes.Repeat([]byte{fill + 1}, 32)}
		handoffMust(t, os.MkdirAll(p.dir, 0700))
		pub, err := secure.SigPubOf(p.key)
		handoffMust(t, err)
		p.peer = handoff.Peer{Address: name, Pinned: hex.EncodeToString(pub)}
		p.bundle, err = ratchet.BuildBundle(p.key, p.spk, 1, nil, 0)
		handoffMust(t, err)
		idFile, spkFile, stateKey := filepath.Join(p.dir, "identity.key"), filepath.Join(p.dir, "spk.key"), filepath.Join(p.dir, "state.key")
		for path, key := range map[string][]byte{idFile: p.key, spkFile: p.spk, stateKey: bytes.Repeat([]byte{9}, 32)} {
			handoffMust(t, os.WriteFile(path, []byte(hex.EncodeToString(key)), 0600))
		}
		cfg := Config{Identity: idFile, SPK: spkFile, StateDir: filepath.Join(p.dir, "state"), StateKey: stateKey, Store: httpStore.URL, Maildb: filepath.Join(p.dir, "mail.json"), Address: name}
		raw, err := json.Marshal(cfg)
		handoffMust(t, err)
		p.config = filepath.Join(p.dir, "config.json")
		handoffMust(t, os.WriteFile(p.config, raw, 0600))
		states, err := ratchetwire.NewFileStateStore(cfg.StateDir, bytes.Repeat([]byte{9}, 32))
		handoffMust(t, err)
		p.ep, err = ratchetwire.NewDurableEndpoint(body, states, time.Now())
		handoffMust(t, err)
		return p
	}
	buyer, provider := makeParty("buyer", 11), makeParty("provider", 22)
	for _, pair := range [][2]*party{{buyer, provider}, {provider, buyer}} {
		db, err := maildb.Open(filepath.Join(pair[0].dir, "mail.json"))
		handoffMust(t, err)
		handoffMust(t, db.UpsertContact(maildb.Contact{Address: pair[1].peer.Address, Nickname: pair[1].peer.Address, Pinned: pair[1].peer.Pinned, Bundle: pair[1].bundle}))
	}
	pin, _ := hex.DecodeString(provider.peer.Pinned)
	ptr, _, sid, err := buyer.ep.SendFirstSession(buyer.key, provider.bundle, pin, []byte("normal conversation bootstrap"), time.Now().Add(24*time.Hour))
	handoffMust(t, err)
	frame, err := ratchetwire.FetchFrame(body, ptr, time.Now())
	handoffMust(t, err)
	raw, err := ratchetwire.GetBody(body, ptr, time.Now())
	handoffMust(t, err)
	_, err = provider.ep.ReceiveFirst(provider.key, provider.spk, nil, frame, raw)
	handoffMust(t, err)
	brief, policy, result := []byte("private brief: investigate service A\n"), []byte("human reviews exact report before acceptance\n"), []byte("private result: service A restored\x00\xff")
	briefPath, policyPath, resultPath := filepath.Join(root, "brief.txt"), filepath.Join(root, "policy.txt"), filepath.Join(root, "result.bin")
	for path, data := range map[string][]byte{briefPath: brief, policyPath: policy, resultPath: result} {
		handoffMust(t, os.WriteFile(path, data, 0600))
	}
	binary := filepath.Join(root, "spore")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	buildSporeCLI(t, binary)
	run := func(wantError bool, args ...string) string {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Env = workOrderTestEnv(os.Environ(), map[string]string{"SPORE_HOME": root, "SPORE_CONFIG": filepath.Join(root, "absent.json"), "SPORE_RELAY_API_TOKEN": ""})
		out, err := cmd.CombinedOutput()
		if wantError == (err == nil) {
			t.Fatalf("CLI %v: err=%v\n%s", args, err, out)
		}
		return string(out)
	}
	out := run(false, "work-order", "handoff", "commitments", "-brief-file", briefPath, "-policy-file", policyPath)
	if !strings.Contains(out, handoff.Commitment(brief)) || !strings.Contains(out, handoff.Commitment(policy)) {
		t.Fatal("wrong CLI commitments", out)
	}
	work := sporrelay.WorkOrder{ObjectiveID: "objective:private-handoff", OwnerPseudonym: "actor:buyer", DescriptionCommitment: handoff.Commitment(brief), PolicyHash: handoff.Commitment(policy)}
	actorFile, issuerFile, grantFile, _, _ := workOrderPreparationFiles(t, work)
	commandFile := filepath.Join(root, "command.json")
	run(false, "work-order", "prepare", "-actor-key", actorFile, "-issuer", issuerFile, "-grant", grantFile, "-objective-id", work.ObjectiveID, "-owner-pseudonym", work.OwnerPseudonym, "-description-commitment", work.DescriptionCommitment, "-policy-hash", work.PolicyHash, "-out", commandFile)
	var mu sync.Mutex
	posts := 0
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/commands" {
			http.Error(w, "unexpected", 400)
			return
		}
		mu.Lock()
		posts++
		mu.Unlock()
		var c sporrelay.AuthorizedWorkOrderCommand
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			t.Error(err)
			http.Error(w, "decode", 400)
			return
		}
		if c.Command.Payload != work {
			t.Error("registration changed terms")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": work})
	}))
	defer relay.Close()
	observation := filepath.Join(root, "registration.json")
	run(false, "work-order", "register", "-command", commandFile, "-relay-url", relay.URL, "-out", observation)
	run(true, "work-order", "register", "-command", commandFile, "-relay-url", relay.URL, "-out", observation)
	mu.Lock()
	n := posts
	mu.Unlock()
	if n != 1 {
		t.Fatal("overwrite triggered remote resubmission", n)
	}
	out = run(false, "work-order", "handoff", "brief", "-config", buyer.config, "-registration", observation, "-to", "provider", "-brief-file", briefPath, "-policy-file", policyPath, "-expires", "24h")
	fields := strings.Fields(out)
	if len(fields) < 2 {
		t.Fatal(out)
	}
	id := strings.TrimSuffix(fields[1], ":")
	var queued [][]byte
	var targets []string
	offline := true
	carrierServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/post" {
			http.Error(w, "unexpected", 400)
			return
		}
		var input map[string]string
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			http.Error(w, "decode", 400)
			return
		}
		p, err := hex.DecodeString(input["memo"])
		if err != nil {
			t.Error(err)
		}
		if len(p) != 74 || bytes.Contains(p, brief) || bytes.Contains(p, result) {
			t.Error("carrier received more than an opaque pointer")
		}
		mu.Lock()
		queued = append(queued, p)
		targets = append(targets, input["to"])
		fail := offline
		mu.Unlock()
		if fail {
			http.Error(w, "carrier offline", 503)
			return
		}
		fmt.Fprint(w, `{"txhash":"test-tx"}`)
	}))
	defer carrierServer.Close()
	flush := func(p *party, fail bool) {
		t.Helper()
		run(fail, "work-order", "handoff", "flush", "-config", p.config, "-chain", "cosmos", "-chain-id", "cosmos", "-base-url", carrierServer.URL, "-post-path", "/post", "-list-path", "/list", "-height-path", "/height", "-delivery-guaranteed")
	}
	flush(buyer, true)
	mu.Lock()
	first := append([]byte{}, queued[0]...)
	offline = false
	mu.Unlock()
	flush(buyer, false)
	mu.Lock()
	retry := append([]byte{}, queued[1]...)
	mu.Unlock()
	if !bytes.Equal(first, retry) {
		t.Fatal("CLI retry changed pointer")
	}
	injectedCrash := false
	receive := func(p *party, pointer []byte) {
		t.Helper()
		fs, _ := newRecvE2Flagset()
		handoffMust(t, fs.Parse([]string{"-config", p.config}))
		handoffMust(t, loadConfigForFlags(fs))
		ing, cleanup, err := openE2Receiver(fs, "", false)
		handoffMust(t, err)
		defer cleanup()
		defer closeBodyStore(ing.st)
		parsed, err := ratchetwire.ParsePointerPayload(pointer)
		handoffMust(t, err)
		frame, err := ratchetwire.FetchFrame(ing.st, parsed.Pointer(), time.Now())
		handoffMust(t, err)
		crashHere := p == provider && !injectedCrash
		lock := filepath.Join(p.dir, "state", "handoffs.enc.lock")
		if crashHere {
			handoffMust(t, os.WriteFile(lock, []byte("simulate application-store failure"), 0600))
		}
		ing.ingest(chain.Incoming{TxID: "fixture", Sender: "untrusted-chain-label"}, frame, parsed.Pointer(), false)
		if crashHere {
			injectedCrash = true
			pending, err := ing.ep.PendingReceive()
			handoffMust(t, err)
			if pending == nil {
				t.Fatal("failed application write lost receive journal")
			}
			handoffMust(t, os.Remove(lock))
			status := run(false, "work-order", "handoff", "status", "-config", p.config)
			if !strings.Contains(status, "receive-recovery-pending") || strings.Contains(status, string(brief)) {
				t.Fatal("pending status missing or leaks artifact", status)
			}
			run(true, "work-order", "handoff", "recover", "-config", p.config, "-discard-pending-cid", strings.Repeat("0", 64))
			handoffMust(t, body.Delete(parsed.CID))
			// The public CLI must recover locally without the old pointer/body,
			// then startup of the normal receiver must find no unfinished work.
			run(false, "work-order", "handoff", "recover", "-config", p.config)
			ing, _, err = openE2Receiver(fs, "", false)
			handoffMust(t, err)
			defer closeBodyStore(ing.st)
		}
		r, err := ing.handoffStore.Get(id, time.Now())
		handoffMust(t, err)
		if r.Session != hex.EncodeToString(sid[:]) {
			t.Fatal("session changed")
		}
		if len(ing.mdb.Messages()) != 0 {
			t.Fatal("private handoff indexed in plaintext maildb")
		}
	}
	receive(provider, retry)
	flush(provider, false)
	mu.Lock()
	briefReceipt := append([]byte{}, queued[len(queued)-1]...)
	mu.Unlock()
	receive(buyer, briefReceipt)
	status := run(false, "work-order", "handoff", "status", "-config", buyer.config)
	if !strings.Contains(status, "peer-persisted") {
		t.Fatal("status missed signed receipt", status)
	}
	run(false, "work-order", "handoff", "deliver", "-config", provider.config, "-id", id, "-result-file", resultPath)
	flush(provider, false)
	mu.Lock()
	delivery := append([]byte{}, queued[len(queued)-1]...)
	target := targets[len(targets)-1]
	mu.Unlock()
	if target != "buyer" {
		t.Fatal(target)
	}
	receive(buyer, delivery)
	flush(buyer, false)
	mu.Lock()
	resultReceipt := append([]byte{}, queued[len(queued)-1]...)
	mu.Unlock()
	receive(provider, resultReceipt)
	out = run(false, "work-order", "handoff", "show", "-config", buyer.config, "-id", id)
	var record handoff.Record
	handoffMust(t, json.Unmarshal([]byte(out), &record))
	if record.Status() != "deliver" || !bytes.Equal(record.Events[1].Message.Content, result) {
		t.Fatal("result not delivered intact")
	}
	export := filepath.Join(root, "review-result.bin")
	run(false, "work-order", "handoff", "export", "-config", buyer.config, "-id", id, "-artifact", "result", "-out", export)
	exported, err := os.ReadFile(export)
	handoffMust(t, err)
	if !bytes.Equal(exported, result) {
		t.Fatal("export corrupted binary deliverable")
	}
	run(true, "work-order", "handoff", "export", "-config", buyer.config, "-id", id, "-artifact", "result", "-out", export)
	run(true, "work-order", "handoff", "decide", "-config", provider.config, "-id", id, "-accept")
	run(false, "work-order", "handoff", "decide", "-config", buyer.config, "-id", id, "-accept")
	flush(buyer, false)
	mu.Lock()
	decision := append([]byte{}, queued[len(queued)-1]...)
	mu.Unlock()
	receive(provider, decision)
	flush(provider, false)
	mu.Lock()
	decisionReceipt := append([]byte{}, queued[len(queued)-1]...)
	mu.Unlock()
	receive(buyer, decisionReceipt)
	status = run(false, "work-order", "handoff", "status", "-config", buyer.config)
	if strings.Count(status, "peer-persisted") != 2 {
		t.Fatal("final decision lacks application receipt", status)
	}
	mu.Lock()
	postCount := len(queued)
	mu.Unlock()
	flush(buyer, false)
	flush(provider, false)
	mu.Lock()
	repeatedPosts := len(queued)
	mu.Unlock()
	if repeatedPosts != postCount {
		t.Fatal("receipt acknowledgement loop")
	}
	out = run(false, "work-order", "handoff", "show", "-config", provider.config, "-id", id)
	handoffMust(t, json.Unmarshal([]byte(out), &record))
	if record.Status() != "accept" || len(record.Events) != 3 {
		t.Fatal("acceptance not received")
	}
	out = run(false, "work-order", "handoff", "list", "-config", provider.config)
	if !strings.Contains(out, id) || !strings.Contains(out, "accept") {
		t.Fatal(out)
	}
	run(true, "work-order", "handoff", "deliver", "-config", provider.config, "-id", id, "-result-file", resultPath)
	for _, p := range []*party{buyer, provider} {
		encrypted, err := os.ReadFile(filepath.Join(p.dir, "state", "handoffs.enc"))
		handoffMust(t, err)
		if bytes.Contains(encrypted, brief) || bytes.Contains(encrypted, result) {
			t.Fatal("plaintext state")
		}
	}
}

func TestHandoffReceiverRejectsWrongPeerAndBlockedContact(t *testing.T) {
	// A real X3DH session authenticates identity A, not whichever address a
	// signed application envelope or chain metadata happens to name.
	body, ep, sid, _ := fabricDrainKit(t)
	db, err := maildb.Open(filepath.Join(t.TempDir(), "mail.json"))
	handoffMust(t, err)
	key := bytes.Repeat([]byte{8}, 32)
	pub, err := secure.SigPubOf(key)
	handoffMust(t, err)
	spk := bytes.Repeat([]byte{9}, 32)
	bundle, err := ratchet.BuildBundle(key, spk, 1, nil, 0)
	handoffMust(t, err)
	peer := handoff.Peer{Address: "attacker", Pinned: hex.EncodeToString(pub)}
	handoffMust(t, db.UpsertContact(maildb.Contact{Address: peer.Address, Pinned: peer.Pinned, Bundle: bundle}))
	if authorizeHandoffPeer(ep, db, peer, hex.EncodeToString(sid[:])) == nil {
		t.Fatal("unrelated session accepted")
	}
	actual := bytes.Repeat([]byte{1}, 32)
	pin, err := secure.SigPubOf(actual)
	handoffMust(t, err)
	actualBundle, err := ratchet.BuildBundle(actual, bytes.Repeat([]byte{2}, 32), 1, nil, 0)
	handoffMust(t, err)
	contact := maildb.Contact{Address: "actual", Pinned: hex.EncodeToString(pin), Bundle: actualBundle, Blocked: true}
	handoffMust(t, db.UpsertContact(contact))
	actualPeer := handoff.Peer{Address: "actual", Pinned: contact.Pinned}
	if authorizeHandoffPeer(ep, db, actualPeer, hex.EncodeToString(sid[:])) == nil {
		t.Fatal("blocked peer accepted")
	}
	contact.Blocked = false
	handoffMust(t, db.UpsertContact(contact))
	handoffMust(t, authorizeHandoffPeer(ep, db, actualPeer, hex.EncodeToString(sid[:])))
	st, err := handoff.Open(filepath.Join(t.TempDir(), "handoffs.enc"), bytes.Repeat([]byte{9}, 32))
	handoffMust(t, err)
	localPub, err := secure.SigPubOf(bytes.Repeat([]byte{7}, 32))
	handoffMust(t, err)
	local := handoff.Peer{Address: "local", Pinned: hex.EncodeToString(localPub)}
	ing := &e2Ingestor{st: body, ep: ep, mdb: db, handoffStore: st, handoffLocal: local}
	id, _ := handoff.NewID()
	eid, _ := handoff.NewID()
	m := handoff.Message{Version: 1, Terms: handoff.Terms{ID: id, Registration: handoff.Registration{Version: 1, RelayURL: "https://relay.example", ActorID: "did:relay:" + strings.Repeat("a", 40), ObservedAt: time.Now().Add(-time.Minute).Unix(), Objective: sporrelay.WorkOrder{ObjectiveID: "test", OwnerPseudonym: "buyer", DescriptionCommitment: handoff.Commitment([]byte("private")), PolicyHash: handoff.Commitment([]byte("review"))}}, Buyer: peer, Provider: local, ExpiresAt: time.Now().Add(time.Hour).Unix()}, EventID: eid, Kind: "brief", Sequence: 1, Content: []byte("private"), Policy: []byte("review")}
	e, err := handoff.Sign(m, key)
	handoffMust(t, err)
	raw, err := handoff.Encode(e)
	handoffMust(t, err)
	if !ing.handleHandoff(sid, raw) {
		t.Fatal("protocol escaped routing")
	}
	rows, err := st.List(time.Now())
	handoffMust(t, err)
	if len(rows) != 0 {
		t.Fatal("forged peer imported")
	}
}
