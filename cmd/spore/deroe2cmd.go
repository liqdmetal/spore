package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// deroE2SendOptions is the compatibility-command view of the canonical E2
// sender. The old DERO whisper commands are convenience names only; they do
// not have their own crypto or body format anymore.
type deroE2SendOptions struct {
	chain       string
	to          string
	identity    string
	bundle      string
	bundleURL   string
	bundleToken string
	pinnedSig   string
	msgFile     string
	amount      string
}

func newDeroE2SendFlags(name string, longBody bool) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("to", "", "recipient DERO address, contact nickname, or DeroNS name")
	fs.String("identity", "", "file containing sender identity private key hex")
	fs.String("bundle", "", "recipient SPK bundle JSON file")
	fs.String("bundle-url", "", "fetch recipient SPK bundle from a mailbox GET /prekey URL")
	fs.String("bundle-token", "", "bearer token for -bundle-url, if required")
	fs.String("pinned-sig", "", "recipient signing public key hex")
	fs.String("msg-file", "", "plaintext file; use '-' or omit for stdin (never put plaintext in argv)")
	if longBody {
		fs.String("file", "", "long plaintext body file; mapped to the E2 frame body")
	}
	fs.String("amount", "", "optional value attached atomically to the DERO pointer")
	fs.Duration("ttl", 24*time.Hour, "encrypted body retention")
	// e2Common supplies the shared carrier, mailbox, and daemon flags.
	e2Common(fs)
	return fs
}

// deroCompatChain deliberately inspects only the explicit chain flag. The
// historical aliases are DERO-only; omitting -chain keeps the DERO default.
func deroCompatChain(args []string) bool {
	chain := "dero"
	for i, arg := range args {
		if (arg == "-chain" || arg == "--chain") && i+1 < len(args) {
			chain = args[i+1]
			continue
		}
		if strings.HasPrefix(arg, "-chain=") {
			chain = strings.TrimPrefix(arg, "-chain=")
		}
		if strings.HasPrefix(arg, "--chain=") {
			chain = strings.TrimPrefix(arg, "--chain=")
		}
	}
	return strings.EqualFold(chain, "dero")
}

// deroE2ReceiveArgs distinguishes the new ratcheted receiver from the
// compatibility-only legacy receiver. A user opting into any E2-only flag
// gets the E2 decoder; a bare command keeps reading old mail and never
// pretends that legacy ciphertext is forward-private.
func deroE2ReceiveArgs(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "-identity", "--identity", "-spk", "--spk", "-opk-pool", "--opk-pool", "-state-dir", "--state-dir", "-state-key", "--state-key", "-store", "--store":
			return true
		}
		for _, prefix := range []string{"-identity=", "--identity=", "-spk=", "--spk=", "-opk-pool=", "--opk-pool=", "-state-dir=", "--state-dir=", "-state-key=", "--state-key=", "-store=", "--store="} {
			if strings.HasPrefix(arg, prefix) {
				return true
			}
		}
	}
	return false
}

func deroE2ReceiveArgsForChain(args []string) bool {
	return deroCompatChain(args) && deroE2ReceiveArgs(args)
}

func deroE2SendOptionsFrom(fs *flag.FlagSet, longBody bool) (deroE2SendOptions, error) {
	get := func(name string) string {
		if f := fs.Lookup(name); f != nil {
			return f.Value.String()
		}
		return ""
	}
	o := deroE2SendOptions{
		chain:       get("chain"),
		to:          get("to"),
		identity:    get("identity"),
		bundle:      get("bundle"),
		bundleURL:   get("bundle-url"),
		bundleToken: get("bundle-token"),
		pinnedSig:   get("pinned-sig"),
		msgFile:     get("msg-file"),
		amount:      get("amount"),
	}
	if !strings.EqualFold(o.chain, "dero") {
		return o, fmt.Errorf("%s: only -chain dero is valid for this DERO compatibility command", fs.Name())
	}
	if _, err := deroRingSizeFromFlags(fs, o.chain); err != nil {
		return o, err
	}
	if o.to == "" || o.identity == "" {
		return o, errors.New("-to and -identity are required; E2 bundle/trust flags are also required unless a maildb contact supplies them")
	}
	if o.bundle != "" && o.bundleURL != "" {
		return o, errors.New("-bundle and -bundle-url are mutually exclusive")
	}
	if longBody {
		file := get("file")
		if file != "" && o.msgFile != "" {
			return o, errors.New("use exactly one of -file or -msg-file")
		}
		if file != "" {
			o.msgFile = file
		}
		if o.msgFile == "" {
			return o, errors.New("long E2 body requires -file or -msg-file")
		}
	} else if o.msgFile == "" {
		// stdin keeps plaintext out of argv and preserves the old short-send
		// convenience without reintroducing a static one-shot envelope.
		o.msgFile = "-"
	}
	return o, nil
}

// parseDeroE2SendArgs is intentionally separate from execution so the
// compatibility aliases can be regression-tested without a wallet, mailbox,
// or network.
func parseDeroE2SendArgs(name string, args []string, longBody bool) (deroE2SendOptions, error) {
	fs := newDeroE2SendFlags(name, longBody)
	if err := fs.Parse(args); err != nil {
		return deroE2SendOptions{}, err
	}
	return deroE2SendOptionsFrom(fs, longBody)
}

func sendDeroE2(args []string, name string, longBody bool) {
	fs := newDeroE2SendFlags(name, longBody)
	if err := fs.Parse(args); err != nil {
		check(err)
	}
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	o, err := deroE2SendOptionsFrom(fs, longBody)
	check(err)
	if err := sendE2Core(fs, o.to, o.identity, o.bundle, o.bundleURL, o.bundleToken, o.pinnedSig, o.msgFile, o.amount, fsDuration(fs, "ttl")); err != nil {
		check(err)
	}
}

func fsDuration(fs *flag.FlagSet, name string) time.Duration {
	f := fs.Lookup(name)
	if f == nil {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(f.Value.String())
	if err != nil {
		check(err)
	}
	return d
}
