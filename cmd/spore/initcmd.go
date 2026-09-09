package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/secure"
)

// initcmd — one-shot onboarding. Generates the complete E2 identity kit in
// one directory, writes config.json so every subsequent command is short,
// and prints the two things the user must do next (share bundle+pinned-sig
// out-of-band; run recv-e2). No flags required beyond the optional -dir.
//
//	spore init [-dir ~/.spore] [-opks 50] [-chain dero] [-store URL]
//
// Everything is created 0600 (private) except bundle.json (0644 — it is
// public by design: it contains only public keys + a signature).
func initcmd(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "", "spore home directory (default ~/.spore or $SPORE_HOME)")
	opks := fs.Int("opks", 50, "how many one-time prekeys to pre-generate")
	chainName := fs.String("chain", "dero", "default pointer carrier")
	storeURL := fs.String("store", "", "default off-chain body store URL (your mailbox or a relay you trust; can be set later in config.json)")
	force := fs.Bool("force", false, "re-initialize even if the directory already has an identity (DESTRUCTIVE: regenerates keys; old sessions become undecryptable)")
	_ = fs.Parse(args)

	home := *dir
	if home == "" {
		d, err := DefaultConfigDir()
		check(err)
		home = d
	}
	cfgFile := filepath.Join(home, "config.json")
	identityFile := filepath.Join(home, "identity.key")

	// Refuse to clobber an existing identity without -force: losing the
	// identity key loses every conversation and every contact's pinned
	// trust. This is the one mistake onboarding must make impossible.
	if _, err := os.Stat(identityFile); err == nil && !*force {
		check(fmt.Errorf("%s already exists — refusing to overwrite your identity (use -force ONLY if you understand that old sessions and pinned trust are lost)", identityFile))
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		check(err)
	}

	key := func(name string) []byte {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			check(err)
		}
		writePrivate(filepath.Join(home, name), b)
		return b
	}

	ik := key("identity.key")
	key("spk.key")
	key("state.key")

	// Pinned sig: the PUBLIC half others pin out-of-band to verify our
	// bundles. Derived from the identity key (same identity, one sig key —
	// docs/RATCHET.md §3), so it never has to be shared as a secret.
	sigPub, err := secure.SigPubOf(ik)
	check(err)

	// OPK pool: pre-generate one-time prekeys so the first N strangers can
	// each get a full 4-DH X3DH (degraded 3-DH only after exhaustion).
	poolPath := filepath.Join(home, "opk-pool.json")
	pool, err := ratchetwire.NewPersistentOPKPool(poolPath)
	check(err)
	for id := uint32(1); id <= uint32(*opks); id++ {
		var opk [32]byte
		if _, err := rand.Read(opk[:]); err != nil {
			check(err)
		}
		if err := pool.Add(id, opk); err != nil {
			check(err)
		}
	}

	// Public bundle for the FIRST opk id is NOT written here: bundles are
	// per-conversation artifacts recipients publish to their mailbox
	// (PUT /prekey). We write a bundle.json containing the long-lived
	// public identity so users can share it however they like; the mailbox
	// publication path stays the canonical one.
	bundlePath := filepath.Join(home, "bundle.json")
	pub := map[string]string{
		"ik_pub":     hex.EncodeToString(mustPub(ik)),
		"pinned_sig": hex.EncodeToString(sigPub),
	}
	raw, err := json.MarshalIndent(pub, "", "  ")
	check(err)
	if err := os.WriteFile(bundlePath, append(raw, '\n'), 0644); err != nil {
		check(err)
	}

	cfg := Config{
		Dir:       home,
		Identity:  identityFile,
		SPK:       filepath.Join(home, "spk.key"),
		OpkPool:   poolPath,
		StateDir:  filepath.Join(home, "state"),
		StateKey:  filepath.Join(home, "state.key"),
		PinnedSig: hex.EncodeToString(sigPub),
		Chain:     *chainName,
		Store:     *storeURL,
		Maildb:    filepath.Join(home, "mail.json"),
	}
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		check(err)
	}
	cfgRaw, err := json.MarshalIndent(cfg, "", "  ")
	check(err)
	if err := os.WriteFile(cfgFile, append(cfgRaw, '\n'), 0600); err != nil {
		check(err)
	}

	fmt.Printf("spore initialized in %s\n", home)
	fmt.Printf("  identity   %s\n", identityFile)
	fmt.Printf("  spk        %s\n", filepath.Join(home, "spk.key"))
	fmt.Printf("  opk pool   %s (%d keys)\n", poolPath, *opks)
	fmt.Printf("  state key  %s\n", filepath.Join(home, "state.key"))
	fmt.Printf("  config     %s\n", cfgFile)
	fmt.Println()
	fmt.Printf("your public identity (share OUT-OF-BAND so contacts can pin you):\n")
	fmt.Printf("  pinned-sig: %s\n", hex.EncodeToString(sigPub))
	fmt.Printf("  bundle:     %s\n", bundlePath)
	fmt.Println()
	fmt.Println("next steps:")
	fmt.Println("  1. run your mailbox so contacts can fetch your prekey bundle:")
	fmt.Printf("       spore mailbox run -dir %s -listen 127.0.0.1:8080\n", filepath.Join(home, "mailbox"))
	fmt.Println("  2. receive (foreground; Ctrl-C stops):")
	fmt.Println("       spore msg recv-e2")
	fmt.Println("  3. send to someone whose bundle+pinned-sig you have:")
	fmt.Println("       spore msg send-e2 -to ADDR -bundle-url http://THEIR-MAILBOX/prekey -pinned-sig THEIR_SIG")
	fmt.Println("       (plaintext via -msg-file or stdin — never argv)")
}

func writePrivate(path string, secret []byte) {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(secret)+"\n"), 0600); err != nil {
		check(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		check(err)
	}
}

func mustPub(priv []byte) []byte {
	kp, err := crypto.KeyPairFromPriv(priv)
	check(err)
	return kp.Pub
}
