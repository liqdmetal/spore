package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// prekeybatch — offline prekey material generation + upload.
//
//	spore prekeybatch gen -identity F -spk F -out F.json [-n 50] [-start-id 1]
//	spore prekeybatch push -in F.json -mailbox URL [-token SECRET]
//
// The gen step produces N single-use PUBLIC bundles (each with its own OPK),
// signed offline by your identity — the mailbox you upload them to never
// touches your identity/spk/OPK private keys. Each bundle is served to at
// most one sender (mailbox pops per GET /prekey), so OPK single-use holds
// end to end. Push uploads the batch to PUT /prekey-batch.
//
// The OPK PRIVATES are written to the local opk pool (-opk-pool, default
// from config) so recv-e2 can consume them exactly once per handshake —
// the pool's durable Take() already guarantees never-reuse-after-restart.
func prekeybatchcmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spore prekeybatch gen|push [flags]")
		os.Exit(2)
	}
	switch args[0] {
	case "gen":
		prekeyBatchGen(args[1:])
	case "push":
		prekeyBatchPush(args[1:])
	case "status":
		prekeyStatus(args[1:])
	case "-h", "--help":
		fmt.Fprintln(os.Stderr, `usage:
  spore prekeybatch gen -identity F -spk F -out F.json [-n 50] [-start-id 1] [-opk-pool F]
      (offline: sign N single-use public bundles; OPK privates go to your opk pool)
  spore prekeybatch push -in F.json -mailbox URL [-token SECRET]
      (upload the batch to a mailbox PUT /prekey-batch)`)
	default:
		fmt.Fprintf(os.Stderr, "prekeybatch: unknown subcommand %q (want gen|push)\n", args[0])
		os.Exit(2)
	}
}

// flagWasSet reports whether the user explicitly passed -name (vs. the
// flag's default).
func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func prekeyBatchGen(args []string) {
	fs := flag.NewFlagSet("prekeybatch gen", flag.ExitOnError)
	_ = fs.String("config", "", "config file path (default ~/.spore/config.json or $SPORE_CONFIG)")
	identity := fs.String("identity", "", "identity private key file (hex)")
	spk := fs.String("spk", "", "signed-prekey private key file (hex)")
	out := fs.String("out", "", "output batch JSON file")
	n := fs.Int("n", 50, "number of single-use bundles to generate")
	startID := fs.Uint("start-id", 1, "first OPK id")
	opkPoolPath := fs.String("opk-pool", "", "OPK pool file for the private halves (default: config opk_pool)")
	_ = fs.Parse(args)
	// loadConfigForFlags fills -identity/-spk/-opk-pool from config when the
	// user didn't set them explicitly (flag names match config keys).
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *identity == "" || *spk == "" || *out == "" {
		check(errors.New("prekeybatch gen requires -identity -spk -out (or `spore init` first)"))
	}
	if *n < 1 || *n > 1000 {
		check(errors.New("prekeybatch gen: -n must be 1..1000"))
	}
	ik, err := readHexFile(*identity, 32)
	check(err)
	sk, err := readHexFile(*spk, 32)
	check(err)

	// OPK pool receives the PRIVATE halves (local only, 0600); the batch
	// file receives only PUBLIC bundles.
	if *opkPoolPath == "" {
		check(errors.New("prekeybatch gen: no -opk-pool (and none in config) — refusing to generate privates with nowhere to put them"))
	}
	if err := os.MkdirAll(filepath.Dir(*opkPoolPath), 0o700); err != nil {
		check(err)
	}
	pool, err := ratchetwire.NewPersistentOPKPool(*opkPoolPath)
	check(err)
	// Auto-continue: unless the user explicitly chose -start-id, begin
	// above the pool's highest existing id so a refill never collides with
	// keys init (or a previous gen) already put in the pool.
	startAt := uint32(*startID)
	if !flagWasSet(fs, "start-id") {
		if mx := pool.MaxID(); mx >= startAt {
			startAt = mx + 1
		}
	}

	bundles := make([]ratchet.SPKBundle, 0, *n)
	for i := 0; i < *n; i++ {
		id := startAt + uint32(i)
		var opk [32]byte
		if _, err := rand.Read(opk[:]); err != nil {
			check(err)
		}
		b, err := ratchet.BuildBundle(ik, sk, 1, &opk, id)
		check(err)
		// Private half into the pool FIRST (durable, consume-once), public
		// bundle into the batch after. If the batch write later fails, the
		// pool simply holds unused OPKs — harmless.
		if err := pool.Add(id, opk); err != nil {
			// Duplicate id (pool already has it): skip this slot rather
			// than failing the whole batch; report at the end.
			fmt.Fprintf(os.Stderr, "opk id %d already in pool — skipped\n", id)
			continue
		}
		bundles = append(bundles, *b)
	}
	if len(bundles) == 0 {
		check(errors.New("prekeybatch gen: no new OPK ids available (all already in pool); raise -start-id"))
	}
	raw, err := json.MarshalIndent(struct {
		Bundles []ratchet.SPKBundle `json:"bundles"`
	}{bundles}, "", "  ")
	check(err)
	if err := os.WriteFile(*out, append(raw, '\n'), 0600); err != nil {
		check(err)
	}
	fmt.Printf("generated %d single-use bundles -> %s (opk privates -> %s)\n", len(bundles), *out, *opkPoolPath)
	fmt.Printf("push them with:\n  spore prekeybatch push -in %s -mailbox http://YOUR-MAILBOX/prekey-batch [-token SECRET]\n", *out)
}

func prekeyBatchPush(args []string) {
	fs := flag.NewFlagSet("prekeybatch push", flag.ExitOnError)
	in := fs.String("in", "", "batch JSON file (from prekeybatch gen)")
	mailboxURL := fs.String("mailbox", "", "mailbox base URL (PUT <base>/prekey-batch)")
	token := fs.String("token", "", "bearer token if the mailbox is auth-gated")
	_ = fs.Parse(args)
	if *in == "" || *mailboxURL == "" {
		check(errors.New("prekeybatch push requires -in and -mailbox"))
	}
	raw, err := os.ReadFile(*in)
	check(err)
	url := *mailboxURL
	if len(url) >= len("/prekey-batch") && url[len(url)-len("/prekey-batch"):] == "/prekey-batch" {
		// already the exact endpoint
	} else {
		url = url + "/prekey-batch"
	}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	check(err)
	req.Header.Set("Content-Type", "application/json")
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	check(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		check(fmt.Errorf("push rejected (%s): %s", resp.Status, bytes.TrimSpace(body)))
	}
	fmt.Printf("batch uploaded to %s\n", url)
}

// prekeyStatus shows what the mailbox currently has published (batch depth),
// so the operator knows when to regenerate before senders start getting
// degraded (3-DH) bundles.
func prekeyStatus(args []string) {
	fs := flag.NewFlagSet("prekeybatch status", flag.ExitOnError)
	mailboxURL := fs.String("mailbox", "", "mailbox base URL")
	token := fs.String("token", "", "bearer token")
	_ = fs.Parse(args)
	if *mailboxURL == "" {
		check(errors.New("status requires -mailbox"))
	}
	url := *mailboxURL + "/prekey"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	check(err)
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	check(err)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		fmt.Println("mailbox has NO prekey material published (senders cannot start E2 sessions)")
		fmt.Println("run: spore prekeybatch gen ... && spore prekeybatch push ...")
		return
	}
	if resp.StatusCode != http.StatusOK {
		check(fmt.Errorf("GET /prekey = %s", resp.Status))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var pb struct {
		Bundle ratchet.SPKBundle `json:"bundle"`
	}
	check(json.Unmarshal(body, &pb))
	opk := "none (degraded 3-DH)"
	if pb.Bundle.OPKPub != nil {
		opk = fmt.Sprintf("id %d %s", pb.Bundle.OPKID, hex.EncodeToString(pb.Bundle.OPKPub[:8])+"…")
	}
	fmt.Printf("mailbox is serving bundles; next one has OPK %s, spk id %d\n", opk, pb.Bundle.SPKID)
	fmt.Println("note: this probe CONSUMED one single-use bundle — don't poll it in a loop")
}
