package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/liqdmetal/spore/internal/backend"
	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/store"
)

// msgE2 is deliberately separate from legacy msg: it has no one-shot
// fallback and never accepts plaintext as a command-line flag (argv is
// visible to shell history, `ps`, and crash/monitoring reports). Bundles are
// supplied explicitly; discovery is not implied.
func msgE2(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spore msg send-e2|recv-e2 [flags]")
		return
	}
	switch args[0] {
	case "send-e2":
		msgSendE2(args[1:])
	case "recv-e2":
		msgRecvE2(args[1:])
	case "prekeygen":
		msgPrekeygen(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "msg: unknown e2 subcommand")
	}
}

func e2Store(url, token string) (ratchetwire.BodyStore, error) {
	if url == "" {
		return nil, errors.New("-store is required (E2 never uses a local-only implicit store)")
	}
	return store.NewHTTPStoreWithToken(url, token)
}
func e2Carrier(fs *flag.FlagSet) (ratchetwire.ChainCarrier, error) {
	cfg := backend.ChainConfig{Type: fs.Lookup("chain").Value.String(), RPC: fs.Lookup("rpc").Value.String(), Login: fs.Lookup("rpc-login").Value.String(), From: fs.Lookup("from").Value.String(), KeyFile: fs.Lookup("keyfile").Value.String(), ProgramID: fs.Lookup("program").Value.String()}
	c, err := backend.Build(context.Background(), cfg)
	if err != nil {
		return ratchetwire.ChainCarrier{}, err
	}
	var codec ratchetwire.ChainPayloadCodec
	switch strings.ToLower(c.Name()) {
	case "dero":
		codec = ratchetwire.DeroChainCodec{}
	case "evm", "solana":
		codec = ratchetwire.JSONCodec{}
	default:
		return ratchetwire.ChainCarrier{}, fmt.Errorf("E2 pointer carrier unsupported on %s; refusing downgrade", c.Name())
	}
	return ratchetwire.ChainCarrier{Chain: c, Codec: codec}, nil
}
func readHexFile(path string, n int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	x, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || (n > 0 && len(x) != n) {
		return nil, fmt.Errorf("%s must contain %d-byte hex", path, n)
	}
	return x, nil
}
func readBundle(path string) (*ratchet.SPKBundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out ratchet.SPKBundle
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// readPlaintext resolves the message body without ever putting it on the
// command line: shell history, `ps`/process listings, and crash/monitoring
// tools all read argv. -msg-file reads a file (use /dev/stdin or a named
// pipe for scripting); with neither flag set, plaintext is read from stdin
// so it never appears as a process argument.
func readPlaintext(msgFile string) ([]byte, error) {
	if msgFile != "" {
		if msgFile == "-" {
			return readAllTrimNewline(os.Stdin)
		}
		b, err := os.ReadFile(msgFile)
		if err != nil {
			return nil, err
		}
		return trimTrailingNewline(b), nil
	}
	return readAllTrimNewline(os.Stdin)
}

func readAllTrimNewline(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return trimTrailingNewline(b), nil
}

func trimTrailingNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b
}

func e2Common(fs *flag.FlagSet) {
	fs.String("chain", "dero", "pointer carrier: dero|evm|solana (xmr unsupported)")
	fs.String("rpc", "", "chain RPC")
	fs.String("rpc-login", "", "RPC user:pass")
	fs.String("from", "", "sender chain address")
	fs.String("keyfile", "", "Solana signer JSON")
	fs.String("program", "", "Solana program ID")
	fs.String("store", "", "HTTP off-chain frame store URL")
	fs.String("store-token", "", "bearer token for the HTTP off-chain frame store")
	fs.String("state-dir", "", "encrypted endpoint session state directory (required)")
	fs.String("state-key", "", "file containing 32-byte hex state encryption key (required)")
	fs.Duration("session-ttl", 0, "inactivity TTL for durable E2 sessions (zero disables expiry)")
}

func msgPrekeygen(args []string) {
	fs := flag.NewFlagSet("msg prekeygen", flag.ExitOnError)
	identity := fs.String("identity-out", "", "identity private key hex output (0600)")
	spk := fs.String("spk-out", "", "signed-prekey private key hex output (0600)")
	opk := fs.String("opk-out", "", "optional one-time-prekey private key hex output (0600)")
	bundle := fs.String("bundle-out", "", "public SPKBundle JSON output (0644)")
	spkID := fs.Uint("spk-id", 1, "signed-prekey identifier")
	opkID := fs.Uint("opk-id", 1, "one-time-prekey identifier")
	_ = fs.Parse(args)
	if *identity == "" || *spk == "" || *bundle == "" {
		check(errors.New("prekeygen requires -identity-out -spk-out -bundle-out"))
	}
	key := func() []byte {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			check(e)
		}
		return b
	}
	ik, sk := key(), key()
	var op *[32]byte
	if *opk != "" {
		x := key()
		op = &[32]byte{}
		copy(op[:], x)
	}
	b, err := ratchet.BuildBundle(ik, sk, uint32(*spkID), op, uint32(*opkID))
	check(err)
	write := func(path string, data []byte, mode os.FileMode) {
		if err := os.WriteFile(path, data, mode); err != nil {
			check(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			check(err)
		}
	}
	write(*identity, []byte(hex.EncodeToString(ik)+"\\n"), 0600)
	write(*spk, []byte(hex.EncodeToString(sk)+"\\n"), 0600)
	if *opk != "" {
		write(*opk, []byte(hex.EncodeToString(op[:])+"\\n"), 0600)
	}
	data, err := json.MarshalIndent(b, "", "  ")
	check(err)
	write(*bundle, append(data, '\n'), 0644)
}

func msgSendE2(args []string) {
	fs := flag.NewFlagSet("msg send-e2", flag.ExitOnError)
	to := fs.String("to", "", "recipient chain address")
	identity := fs.String("identity", "", "file containing sender identity private key hex")
	bundle := fs.String("bundle", "", "recipient SPK bundle JSON (explicit; no discovery)")
	pinned := fs.String("pinned-sig", "", "recipient signing public key hex")
	msgFile := fs.String("msg-file", "", "file containing plaintext (use '-' or omit for stdin; never pass plaintext as an argv flag — argv is visible to shell history, ps, and crash reports)")
	ttl := fs.Duration("ttl", 24*time.Hour, "frame retention")
	e2Common(fs)
	_ = fs.Parse(args)
	if *to == "" || *identity == "" || *bundle == "" || *pinned == "" {
		check(errors.New("send-e2 requires -to -identity -bundle -pinned-sig (plaintext via -msg-file or stdin)"))
	}
	plaintext, err := readPlaintext(*msgFile)
	check(err)
	if len(plaintext) == 0 {
		check(errors.New("send-e2: empty plaintext"))
	}
	st, err := e2Store(fs.Lookup("store").Value.String(), fs.Lookup("store-token").Value.String())
	check(err)
	id, err := readHexFile(*identity, 32)
	check(err)
	b, err := readBundle(*bundle)
	check(err)
	sig, err := hex.DecodeString(*pinned)
	check(err)
	if len(sig) != 32 {
		check(errors.New("-pinned-sig must be 32-byte hex"))
	}
	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" || stateKeyFile == "" {
		check(errors.New("E2 requires -state-dir and -state-key"))
	}
	stateKey, err := readHexFile(stateKeyFile, 32)
	check(err)
	sessionTTL, err := time.ParseDuration(fs.Lookup("session-ttl").Value.String())
	check(err)
	// Apply expiry before restoring any durable session so stale key material
	// cannot process a frame during this invocation.
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	check(err)
	ep, err := ratchetwire.NewDurableEndpointWithExpiry(st, states, sessionTTL, time.Now())
	check(err)
	_, raw, err := ep.SendFirst(id, b, sig, plaintext, time.Now().Add(*ttl))
	check(err)
	c, err := e2Carrier(fs)
	check(err)
	r, err := c.PostPointer(context.Background(), *to, raw, 1)
	check(err)
	fmt.Printf("sent-e2 txid %s pointer %x\n", r.TxID, raw)
}

func msgRecvE2(args []string) {
	fs := flag.NewFlagSet("msg recv-e2", flag.ExitOnError)
	identity := fs.String("identity", "", "our identity private key file")
	spk := fs.String("spk", "", "our signed-prekey private key file")
	opk := fs.String("opk", "", "legacy single one-time-prekey private key file")
	opkPool := fs.String("opk-pool", "", "endpoint-local persistent one-time-prekey pool JSON (preferred)")
	interval := fs.Duration("interval", 3*time.Second, "poll interval")
	min := fs.Uint64("min-height", 0, "scan height")
	e2Common(fs)
	_ = fs.Parse(args)
	if *identity == "" || *spk == "" {
		check(errors.New("recv-e2 requires -identity and -spk"))
	}
	st, err := e2Store(fs.Lookup("store").Value.String(), fs.Lookup("store-token").Value.String())
	check(err)
	ik, err := readHexFile(*identity, 32)
	check(err)
	sk, err := readHexFile(*spk, 32)
	check(err)
	var op *[32]byte
	var pool *ratchetwire.OPKPool
	if *opkPool != "" {
		pool, err = ratchetwire.NewPersistentOPKPool(*opkPool)
		check(err)
	}
	if *opk != "" {
		x, e := readHexFile(*opk, 32)
		check(e)
		op = &[32]byte{}
		copy(op[:], x)
	}
	c, err := e2Carrier(fs)
	check(err)
	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" || stateKeyFile == "" {
		check(errors.New("E2 requires -state-dir and -state-key"))
	}
	stateKey, err := readHexFile(stateKeyFile, 32)
	check(err)
	sessionTTL, err := time.ParseDuration(fs.Lookup("session-ttl").Value.String())
	check(err)
	states, err := ratchetwire.NewFileStateStore(stateDir, stateKey)
	check(err)
	ep, err := ratchetwire.NewDurableEndpointWithExpiry(st, states, sessionTTL, time.Now())
	check(err)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	in, errs := ratchetwire.WatchE2(ctx, c, chain.WatchOpts{MinHeight: *min, Interval: *interval})
	for {
		select {
		case inc, ok := <-in:
			if !ok {
				return
			}
			frame, p, e := c.FetchIncomingE2(st, inc, time.Now())
			if e != nil {
				fmt.Fprintln(os.Stderr, "e2 frame:", e)
				continue
			}
			var plain []byte
			switch frame.Kind {
			case ratchetwire.FrameInit:
				body, bodyErr := ratchetwire.GetBody(st, p, time.Now())
				if bodyErr != nil {
					fmt.Fprintln(os.Stderr, "e2 frame:", bodyErr)
					continue
				}
				if pool != nil {
					plain, e = ep.ReceiveFirstFromOPKPool(ik, sk, pool, frame, body)
				} else {
					plain, e = ep.ReceiveFirst(ik, sk, op, frame, body)
				}
			case ratchetwire.FrameMessage:
				// Continuations must use the installed ratchet session. Never
				// reinterpret them as a fresh handshake (downgrade resistance).
				plain, e = ep.ReceiveNext(p, time.Now())
			default:
				e = ratchetwire.ErrLegacyDowngrade
			}
			if e != nil {
				fmt.Fprintln(os.Stderr, "e2 decrypt:", e)
				continue
			}
			fmt.Printf("msg %s: %s\n", shortTx(inc.TxID), plain)
		case e := <-errs:
			if e != nil {
				fmt.Fprintln(os.Stderr, "e2 watch:", e)
			}
		case <-ctx.Done():
			return
		}
	}
}
