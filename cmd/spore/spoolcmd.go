package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Offline compose queue: write messages now, send them when a carrier is
// reachable. The spool holds only send parameters and path references —
// plaintext stays in the -msg-file it was composed from (or is captured from
// stdin into a spool-local file at compose time), and keys are never copied
// into the spool. Flush replays each entry through the exact same
// sendE2Core path send-e2 uses.
type spoolEntry struct {
	To          string `json:"to"`
	Identity    string `json:"identity"`
	Pinned      string `json:"pinned_sig"`
	Bundle      string `json:"bundle,omitempty"`
	BundleURL   string `json:"bundle_url,omitempty"`
	BundleToken string `json:"bundle_token,omitempty"`
	MsgFile     string `json:"msg_file"`
	Amount      string `json:"amount,omitempty"` // pay-with-message, e.g. "5.5dero"
	TTLSeconds  int64  `json:"ttl_seconds"`

	// Carrier + state flags snapshot (e2Common), so flush needs no flags of
	// its own beyond -dir.
	Chain           string `json:"chain"`
	RPC             string `json:"rpc,omitempty"`
	RPCLogin        string `json:"rpc_login,omitempty"`
	From            string `json:"from,omitempty"`
	KeyFile         string `json:"keyfile,omitempty"`
	Program         string `json:"program,omitempty"`
	Network         string `json:"network,omitempty"`
	BaseURL         string `json:"base_url,omitempty"`
	Address         string `json:"address,omitempty"`
	ChainID         string `json:"chain_id,omitempty"`
	PostPath        string `json:"post_path,omitempty"`
	ListPath        string `json:"list_path,omitempty"`
	HeightPath      string `json:"height_path,omitempty"`
	MessageField    string `json:"message_field,omitempty"`
	RecipientField  string `json:"recipient_field,omitempty"`
	DeliveryGuarant bool   `json:"delivery_guaranteed,omitempty"`
	PrivateKey      string `json:"private_key,omitempty"`
	PrivateKeyFile  string `json:"private_key_file,omitempty"`
	Relays          string `json:"relays,omitempty"`
	Store           string `json:"store,omitempty"`
	StoreToken      string `json:"store_token,omitempty"`
	StateDir        string `json:"state_dir"`
	StateKey        string `json:"state_key"`
	SessionTTL      string `json:"session_ttl"`

	// Sig is a keyed HMAC-SHA256 over the canonical JSON of all other
	// fields, so a local attacker who can write the spool dir cannot
	// silently rewrite where a message goes or which key file is loaded.
	// The key is derived from the identity private-key file's contents via
	// a fixed domain-separated SHA-256, so no new secret is introduced and
	// only the party holding the identity key can compose+flush the spool.
	Sig string `json:"sig,omitempty"`
}

func msgCompose(args []string) {
	fs := flag.NewFlagSet("msg compose", flag.ExitOnError)
	to := fs.String("to", "", "recipient chain address")
	identity := fs.String("identity", "", "file containing sender identity private key hex")
	bundle := fs.String("bundle", "", "recipient SPK bundle JSON file")
	bundleURL := fs.String("bundle-url", "", "recipient SPK bundle GET /prekey URL")
	bundleToken := fs.String("bundle-token", "", "bearer token for -bundle-url")
	pinned := fs.String("pinned-sig", "", "recipient signing public key hex")
	msgFile := fs.String("msg-file", "", "file containing plaintext (use '-' or omit for stdin)")
	amount := fs.String("amount", "", "pay-with-message value attached at flush time, e.g. 5.5dero (value-carrying carriers only)")
	ttl := fs.Duration("ttl", 24*time.Hour, "frame retention")
	out := fs.String("out", "spool", "directory to hold the composed message")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *to == "" || *identity == "" || *pinned == "" {
		check(errors.New("compose requires -to -identity -pinned-sig, and exactly one of -bundle or -bundle-url"))
	}
	if (*bundle == "") == (*bundleURL == "") {
		check(errors.New("compose requires exactly one of -bundle or -bundle-url"))
	}
	// Capture plaintext into the spool dir at compose time so stdin-composed
	// messages survive until flush. The spool file itself holds only paths.
	if err := os.MkdirAll(*out, 0700); err != nil {
		check(err)
	}
	plain, err := readPlaintext(*msgFile)
	check(err)
	if len(plain) == 0 {
		check(errors.New("compose: empty plaintext"))
	}
	spoolMsg := filepath.Join(*out, fmt.Sprintf("msg-%d.plain", time.Now().UnixNano()))
	if err := os.WriteFile(spoolMsg, plain, 0600); err != nil {
		check(err)
	}

	e := spoolEntry{
		To: *to, Identity: *identity, Pinned: *pinned,
		Bundle: *bundle, BundleURL: *bundleURL, BundleToken: *bundleToken,
		MsgFile: spoolMsg, Amount: *amount, TTLSeconds: int64(ttl.Seconds()),
		Chain: fs.Lookup("chain").Value.String(), RPC: fs.Lookup("rpc").Value.String(),
		RPCLogin: fs.Lookup("rpc-login").Value.String(), From: fs.Lookup("from").Value.String(),
		KeyFile: fs.Lookup("keyfile").Value.String(), Program: fs.Lookup("program").Value.String(),
		Network: fs.Lookup("network").Value.String(), BaseURL: fs.Lookup("base-url").Value.String(),
		Address: fs.Lookup("address").Value.String(), ChainID: fs.Lookup("chain-id").Value.String(),
		PostPath: fs.Lookup("post-path").Value.String(), ListPath: fs.Lookup("list-path").Value.String(),
		HeightPath: fs.Lookup("height-path").Value.String(), MessageField: fs.Lookup("message-field").Value.String(),
		RecipientField: fs.Lookup("recipient-field").Value.String(),
		DeliveryGuarant: fs.Lookup("delivery-guaranteed").Value.String() == "true",
		PrivateKey: fs.Lookup("private-key").Value.String(), PrivateKeyFile: fs.Lookup("private-key-file").Value.String(),
		Relays: fs.Lookup("relays").Value.String(), Store: fs.Lookup("store").Value.String(),
		StoreToken: fs.Lookup("store-token").Value.String(),
		StateDir: fs.Lookup("state-dir").Value.String(), StateKey: fs.Lookup("state-key").Value.String(),
		SessionTTL: fs.Lookup("session-ttl").Value.String(),
	}
	raw, err := json.MarshalIndent(e, "", "  ")
	check(err)
	// Sign the canonical entry (without the sig field, which is empty here).
	e.Sig = spoolSig(&e)
	raw, err = json.MarshalIndent(e, "", "  ")
	check(err)
	spoolFile := filepath.Join(*out, fmt.Sprintf("send-%d.json", time.Now().UnixNano()))
	if err := os.WriteFile(spoolFile, raw, 0600); err != nil {
		check(err)
	}
	fmt.Printf("composed %s (plaintext at %s)\n", spoolFile, spoolMsg)
}

// spoolKey derives the HMAC key for a spool entry from the identity
// private-key file. Domain-separated so the key is not the identity key
// itself and cannot be confused with any other use.
func spoolKey(identityFile string) ([]byte, error) {
	raw, err := os.ReadFile(identityFile)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte("spore/spool/v1\x00" + string(raw)))
	return sum[:], nil
}

// spoolSig computes the HMAC-SHA256 tag over the canonical JSON of the
// entry's payload fields (excluding Sig).
func spoolSig(e *spoolEntry) string {
	cp := *e
	cp.Sig = ""
	raw, err := json.Marshal(cp)
	if err != nil {
		return ""
	}
	key, err := spoolKey(cp.Identity)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

// spoolVerify reports whether the entry's Sig is present and valid for the
// current identity key. A mismatch means the entry was tampered with (or the
// identity key changed since compose) — flush refuses it.
func spoolVerify(e *spoolEntry) bool {
	if e.Sig == "" {
		return false
	}
	got := spoolSig(e)
	return got != "" && hmac.Equal([]byte(got), []byte(e.Sig))
}

// spoolPathSafe reports whether a file path referenced by a spool entry is
// either absolute (keys and bundles are user-provided paths, so they may be
// anywhere) or, if relative, resolves inside the spool dir. It rejects
// relative paths that escape via .. so a tampered entry cannot read an
// arbitrary file during flush.
func spoolPathSafe(base, p string) bool {
	if p == "" {
		return false
	}
	if filepath.IsAbs(p) {
		return true
	}
	// Relative paths are interpreted RELATIVE TO BASE (the spool dir): the
	// spool is where msg bodies live, so "msg-1.plain" means
	// "<spool>/msg-1.plain". Resolve against base, not CWD.
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	pAbs, err := filepath.Abs(filepath.Join(base, p))
	if err != nil {
		return false
	}
	// Containment: pAbs must equal baseAbs or live under it.
	if pAbs == baseAbs {
		return true
	}
	prefix := baseAbs
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(pAbs, prefix)
}

func msgFlush(args []string) {
	fs := flag.NewFlagSet("msg flush", flag.ExitOnError)
	dir := fs.String("dir", "spool", "spool directory to drain")
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	entries, err := os.ReadDir(*dir)
	check(err)
	sent, failed := 0, 0
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasPrefix(name, "send-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(*dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "flush %s: %v\n", name, err)
			failed++
			continue
		}
		var e spoolEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			fmt.Fprintf(os.Stderr, "flush %s: malformed spool: %v\n", name, err)
			failed++
			continue
		}
		// Integrity: refuse a tampered entry (wrong HMAC) or one that
		// escapes the spool dir via relative paths.
		if !spoolVerify(&e) {
			fmt.Fprintf(os.Stderr, "flush %s: spool signature invalid (tampered or identity key changed) — refusing\n", name)
			failed++
			continue
		}
		if !spoolPathSafe(*dir, e.MsgFile) || !spoolPathSafe(*dir, e.Bundle) {
			fmt.Fprintf(os.Stderr, "flush %s: spool path escapes the spool dir — refusing\n", name)
			failed++
			continue
		}
		if err := flushOne(e); err != nil {
			fmt.Fprintf(os.Stderr, "flush %s: %v (will retry next flush)\n", name, err)
			failed++
			continue
		}
		// Success: remove the spool entry; the plaintext body goes with it.
		_ = os.Remove(path)
		_ = os.Remove(e.MsgFile)
		sent++
	}
	fmt.Printf("flush done: %d sent, %d failed\n", sent, failed)
}

// flushOne rebuilds a parsed e2Common FlagSet from the spool entry and runs
// the identical sendE2Core path send-e2 uses.
func flushOne(e spoolEntry) error {
	fs := flag.NewFlagSet("flush", flag.ExitOnError)
	e2Common(fs)
	set := func(name, val string) error {
		if val == "" {
			return nil
		}
		return fs.Set(name, val)
	}
	for _, kv := range [][2]string{
		{"chain", e.Chain}, {"rpc", e.RPC}, {"rpc-login", e.RPCLogin}, {"from", e.From},
		{"keyfile", e.KeyFile}, {"program", e.Program}, {"network", e.Network}, {"base-url", e.BaseURL},
		{"address", e.Address}, {"chain-id", e.ChainID}, {"post-path", e.PostPath}, {"list-path", e.ListPath},
		{"height-path", e.HeightPath}, {"message-field", e.MessageField}, {"recipient-field", e.RecipientField},
		{"private-key", e.PrivateKey}, {"private-key-file", e.PrivateKeyFile}, {"relays", e.Relays},
		{"store", e.Store}, {"store-token", e.StoreToken}, {"state-dir", e.StateDir}, {"state-key", e.StateKey},
		{"session-ttl", e.SessionTTL},
	} {
		if err := set(kv[0], kv[1]); err != nil {
			return err
		}
	}
	if e.DeliveryGuarant {
		_ = fs.Set("delivery-guaranteed", "true")
	}
	return sendE2Core(fs, e.To, e.Identity, e.Bundle, e.BundleURL, e.BundleToken, e.Pinned, e.MsgFile, e.Amount, time.Duration(e.TTLSeconds)*time.Second)
}
