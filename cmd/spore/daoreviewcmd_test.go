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
	"github.com/liqdmetal/spore/internal/daoreview"
	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

func TestDAOReviewRealCLIThreeReviewerQuorum(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SPORE_HOME", root)
	t.Setenv("SPORE_CONFIG", filepath.Join(root, "absent.json"))
	body := store.NewMemStore()
	server := store.NewServer(body, time.Hour)
	defer server.Stop()
	httpBody := httptest.NewServer(server.Handler())
	defer httpBody.Close()
	type party struct {
		dir, config string
		key, spk    []byte
		peer        handoff.Peer
		bundle      *ratchet.SPKBundle
		ep          *ratchetwire.DurableEndpoint
	}
	makeParty := func(name string, n byte) *party {
		p := &party{dir: filepath.Join(root, name), key: bytes.Repeat([]byte{n}, 32), spk: bytes.Repeat([]byte{n + 1}, 32)}
		handoffMust(t, os.MkdirAll(p.dir, 0700))
		pin, err := secure.SigPubOf(p.key)
		handoffMust(t, err)
		p.peer = handoff.Peer{Address: name, Pinned: hex.EncodeToString(pin)}
		p.bundle, err = ratchet.BuildBundle(p.key, p.spk, 1, nil, 0)
		handoffMust(t, err)
		cfg := Config{Address: name, Identity: filepath.Join(p.dir, "identity.key"), SPK: filepath.Join(p.dir, "spk.key"), StateKey: filepath.Join(p.dir, "state.key"), StateDir: filepath.Join(p.dir, "state"), Maildb: filepath.Join(p.dir, "mail.json"), Store: httpBody.URL}
		for path, key := range map[string][]byte{cfg.Identity: p.key, cfg.SPK: p.spk, cfg.StateKey: bytes.Repeat([]byte{9}, 32)} {
			handoffMust(t, os.WriteFile(path, []byte(hex.EncodeToString(key)), 0600))
		}
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
	coordinator := makeParty("coordinator", 11)
	reviewers := []*party{makeParty("reviewer-a", 22), makeParty("reviewer-b", 33), makeParty("reviewer-c", 44)}
	parties := map[string]*party{coordinator.peer.Address: coordinator}
	for _, p := range reviewers {
		parties[p.peer.Address] = p
		for _, pair := range [][2]*party{{coordinator, p}, {p, coordinator}} {
			db, err := maildb.Open(filepath.Join(pair[0].dir, "mail.json"))
			handoffMust(t, err)
			handoffMust(t, db.UpsertContact(maildb.Contact{Address: pair[1].peer.Address, Nickname: pair[1].peer.Address, Pinned: pair[1].peer.Pinned, Bundle: pair[1].bundle}))
		}
		pin, _ := hex.DecodeString(p.peer.Pinned)
		ptr, _, _, err := coordinator.ep.SendFirstSession(coordinator.key, p.bundle, pin, []byte("normal E2 bootstrap"), time.Now().Add(24*time.Hour))
		handoffMust(t, err)
		frame, err := ratchetwire.FetchFrame(body, ptr, time.Now())
		handoffMust(t, err)
		raw, err := ratchetwire.GetBody(body, ptr, time.Now())
		handoffMust(t, err)
		_, err = p.ep.ReceiveFirst(p.key, p.spk, nil, frame, raw)
		handoffMust(t, err)
	}
	binary := filepath.Join(root, "spore")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	buildSporeCLI(t, binary)
	run := func(fail bool, args ...string) string {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Env = workOrderTestEnv(os.Environ(), map[string]string{"SPORE_HOME": root, "SPORE_CONFIG": filepath.Join(root, "absent.json")})
		raw, err := cmd.CombinedOutput()
		if fail == (err == nil) {
			t.Fatalf("CLI %v: %v\n%s", args, err, raw)
		}
		return string(raw)
	}
	evidence, policy := []byte("PRIVATE DAO EVIDENCE\x00\xff"), []byte("Approve iff the exact packet satisfies the treasury oversight checklist; no transfer authorized")
	evidenceFile, policyFile := filepath.Join(root, "evidence.bin"), filepath.Join(root, "policy.txt")
	handoffMust(t, os.WriteFile(evidenceFile, evidence, 0600))
	handoffMust(t, os.WriteFile(policyFile, policy, 0600))
	manifest := filepath.Join(root, "manifest.json")
	create := []string{"dao-review", "create", "-config", coordinator.config, "-dao", "dao:example", "-proposal", "proposal:42", "-epoch", "7", "-threshold", "2", "-to", "reviewer-a", "-to", "reviewer-b", "-to", "reviewer-c", "-evidence-file", evidenceFile, "-policy-file", policyFile, "-out", manifest}
	// Every failure must leave no partial invitation roster or exported manifest.
	invalid := append([]string{}, create...)
	for i, v := range invalid {
		if v == "reviewer-c" {
			invalid[i] = "missing-reviewer"
		}
	}
	run(true, invalid...)
	st, err := handoff.Open(filepath.Join(coordinator.dir, "state", "handoffs.enc"), bytes.Repeat([]byte{9}, 32))
	handoffMust(t, err)
	rows, err := st.List(time.Now())
	handoffMust(t, err)
	if len(rows) != 0 {
		t.Fatal("partial review queued")
	}
	if _, err := os.Stat(manifest); !os.IsNotExist(err) {
		t.Fatal("failed create exported manifest")
	}
	run(false, create...)
	raw, err := os.ReadFile(manifest)
	handoffMust(t, err)
	var signed daoreview.SignedManifest
	handoffMust(t, handoff.DecodeJSON(raw, &signed, daoreview.MaxCertificate))
	handoffMust(t, signed.Verify())
	reviewHash := signed.Hash()
	if bytes.Contains(raw, evidence) || bytes.Contains(raw, policy) {
		t.Fatal("manifest leaks private artifacts")
	}
	run(true, create...)
	rows, err = st.List(time.Now())
	handoffMust(t, err)
	if len(rows) != 3 {
		t.Fatal("create overwrite queued more invitations")
	}
	cert := filepath.Join(root, "certificate.json")
	run(true, "dao-review", "certificate", "-config", coordinator.config, "-expect-review-hash", reviewHash, "-out", cert)
	type post struct {
		to  string
		ptr []byte
	}
	var posts []post
	var mu sync.Mutex
	carrier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/post" {
			http.Error(w, "unexpected route", 400)
			return
		}
		var input map[string]string
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			http.Error(w, "bad JSON", 400)
			return
		}
		pointer, err := hex.DecodeString(input["memo"])
		if err != nil || len(pointer) != 74 || bytes.Contains(pointer, evidence) {
			t.Error("carrier exposed non-pointer data")
		}
		mu.Lock()
		posts = append(posts, post{input["to"], pointer})
		mu.Unlock()
		fmt.Fprint(w, `{"txhash":"local-test"}`)
	}))
	defer carrier.Close()
	flush := func(p *party) []post {
		t.Helper()
		mu.Lock()
		before := len(posts)
		mu.Unlock()
		run(false, "dao-review", "flush", "-config", p.config, "-chain", "cosmos", "-chain-id", "cosmos", "-base-url", carrier.URL, "-post-path", "/post", "-list-path", "/list", "-height-path", "/height", "-delivery-guaranteed")
		mu.Lock()
		defer mu.Unlock()
		return append([]post{}, posts[before:]...)
	}
	recovered := false
	receive := func(item post) {
		t.Helper()
		p := parties[item.to]
		if p == nil {
			t.Fatal("wrong target", item.to)
		}
		fs, _ := newRecvE2Flagset()
		handoffMust(t, fs.Parse([]string{"-config", p.config}))
		handoffMust(t, loadConfigForFlags(fs))
		ing, cleanup, err := openE2Receiver(fs, "", false)
		handoffMust(t, err)
		defer cleanup()
		defer closeBodyStore(ing.st)
		pointer, err := ratchetwire.ParsePointerPayload(item.ptr)
		handoffMust(t, err)
		frame, err := ratchetwire.FetchFrame(ing.st, pointer.Pointer(), time.Now())
		handoffMust(t, err)
		crash := p == reviewers[0] && !recovered
		lock := filepath.Join(p.dir, "state", "handoffs.enc.lock")
		if crash {
			handoffMust(t, os.WriteFile(lock, []byte("simulate failed application persistence"), 0600))
		}
		ing.ingest(chain.Incoming{TxID: "fixture", Sender: "untrusted-chain-sender"}, frame, pointer.Pointer(), false)
		if crash {
			pending, err := ing.ep.PendingReceive()
			handoffMust(t, err)
			if pending == nil {
				t.Fatal("DAO receive did not use journal")
			}
			handoffMust(t, os.Remove(lock))
			handoffMust(t, body.Delete(pointer.CID))
			run(false, "dao-review", "recover", "-config", p.config)
			recovered = true
		}
		if len(ing.mdb.Messages()) != 0 {
			t.Fatal("DAO evidence indexed in maildb")
		}
	}
	initialStatus := run(false, "dao-review", "status", "-config", coordinator.config)
	if strings.Count(initialStatus, "missing decision") != 3 {
		t.Fatal("missing reviewer visibility", initialStatus)
	}
	for _, item := range flush(coordinator) {
		receive(item)
	}
	policyExport := filepath.Join(root, "reviewer-policy.txt")
	run(false, "dao-review", "export", "-config", reviewers[0].config, "-id", daoreview.InvitationID(signed, reviewers[0].peer), "-artifact", "policy", "-out", policyExport)
	exportedPolicy, err := os.ReadFile(policyExport)
	handoffMust(t, err)
	if !bytes.Equal(exportedPolicy, policy) {
		t.Fatal("human policy export is not the exact original policy")
	}
	run(true, "dao-review", "export", "-config", reviewers[0].config, "-id", daoreview.InvitationID(signed, reviewers[0].peer), "-artifact", "policy", "-out", policyExport)
	for _, p := range reviewers {
		out := run(false, "dao-review", "status", "-config", p.config)
		if !strings.Contains(out, "reviewer-local-view") {
			t.Fatal("reviewer implied global tally", out)
		}
	}
	for i, p := range reviewers {
		id := daoreview.InvitationID(signed, p.peer)
		run(true, "dao-review", "decide", "-config", p.config, "-id", id, "-expect-review-hash", handoff.Commitment([]byte("wrong roster")), "-approve")
		run(true, "work-order", "handoff", "deliver", "-config", p.config, "-id", id, "-result-file", evidenceFile)
		choice := "-approve"
		if i == 2 {
			choice = "-reject"
		}
		run(false, "dao-review", "decide", "-config", p.config, "-id", id, "-expect-review-hash", reviewHash, choice)
		run(true, "dao-review", "decide", "-config", p.config, "-id", id, "-expect-review-hash", reviewHash, "-reject")
		for _, item := range flush(p) {
			receive(item)
		}
	}
	status := run(false, "dao-review", "status", "-config", coordinator.config)
	if !strings.Contains(status, "approval-quorum-met") || !strings.Contains(status, "approvals 2/2; rejects 1") {
		t.Fatal("incorrect quorum", status)
	}
	for _, item := range flush(coordinator) {
		receive(item)
	}
	run(false, "dao-review", "certificate", "-config", coordinator.config, "-expect-review-hash", reviewHash, "-out", cert)
	run(true, "dao-review", "certificate", "-config", coordinator.config, "-expect-review-hash", reviewHash, "-out", cert)
	out := run(false, "dao-review", "verify", "-certificate", cert, "-expect-review-hash", reviewHash)
	if !strings.Contains(out, "verified:") || !strings.Contains(out, "no membership discovery, execution, or spending") {
		t.Fatal(out)
	}
	run(true, "dao-review", "verify", "-certificate", cert)
	run(true, "dao-review", "verify", "-certificate", cert, "-expect-review-hash", handoff.Commitment([]byte("wrong epoch")))
	raw, err = os.ReadFile(cert)
	handoffMust(t, err)
	if bytes.Contains(raw, evidence) || bytes.Contains(raw, policy) {
		t.Fatal("certificate exported evidence/policy")
	}
	c, err := daoreview.DecodeCertificate(raw, reviewHash, time.Now())
	handoffMust(t, err)
	if len(c.Approvals) != 2 {
		t.Fatal("wrong distinct approval count")
	}
	mutated := bytes.Replace(raw, []byte(`"epoch": 7`), []byte(`"epoch": 8`), 1)
	bad := filepath.Join(root, "tampered.json")
	handoffMust(t, os.WriteFile(bad, mutated, 0600))
	run(true, "dao-review", "verify", "-certificate", bad, "-expect-review-hash", reviewHash)
	for _, p := range parties {
		raw, err := os.ReadFile(filepath.Join(p.dir, "state", "handoffs.enc"))
		handoffMust(t, err)
		if bytes.Contains(raw, evidence) || bytes.Contains(raw, policy) {
			t.Fatal("plaintext DAO disk state")
		}
	}
}
