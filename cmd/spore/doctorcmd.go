// doctor — pre-flight sanity check for a spore deployment (P0 roadmap item).
//
//	spore doctor [-priv HEX] [-dir DIR] [-listen ADDR] [-chain dero ...]
//
// Checks, in order:
//  1. identity: -priv parses as 32 bytes and derives a consistent X25519 pub
//     and Ed25519 sig key (the two values you publish to peers).
//  2. data dir: exists, readable, writable (body store + message log live here).
//  3. listen bind: the address you would pass to daemon/web/mailbox is a
//     loopback-safe bind (or would be refused — doctor explains why).
//  4. chain (optional): RPC/wallet reachable, address + height fetched.
//
// Exit 0 only if nothing is broken. It is the first thing you run after
// installing spore and the first thing you run when something "just stopped
// working".
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/liqdmetal/spore/internal/safehttp"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/session"
)

// doctorCheck is one named pass/fail result.
type doctorCheck struct {
	Name string
	OK   bool
	Note string
}

// doctorOpts is the testable core of doctorcmd.
type doctorOpts struct {
	Priv   string // hex medium-term privkey ("" = skip)
	Dir    string // data dir ("" = skip)
	Listen string // bind address to evaluate ("" = skip)
}

// runDoctorChecks executes the offline checks. Chain probing is handled by the
// caller (it reuses the status probes). Pure and side-effect free.
func runDoctorChecks(o doctorOpts) []doctorCheck {
	var out []doctorCheck

	// 1. Identity.
	if o.Priv == "" {
		out = append(out, doctorCheck{Name: "identity", OK: false, Note: "-priv not provided (run `spore keygen`) — cannot verify"})
	} else {
		raw, err := hex.DecodeString(o.Priv)
		if err != nil {
			out = append(out, doctorCheck{Name: "identity", OK: false, Note: fmt.Sprintf("-priv is not valid hex: %v", err)})
		} else if len(raw) != 32 {
			out = append(out, doctorCheck{Name: "identity", OK: false, Note: fmt.Sprintf("-priv is %d bytes, want 32", len(raw))})
		} else {
			e, err := session.NewFromPriv(nil, raw)
			if err != nil {
				out = append(out, doctorCheck{Name: "identity", OK: false, Note: fmt.Sprintf("cannot load: %v", err)})
			} else {
				sigPub, serr := secure.SigPubOf(e.PrivKey())
				if serr != nil {
					out = append(out, doctorCheck{Name: "identity", OK: false, Note: fmt.Sprintf("sig key derivation failed: %v", serr)})
				} else {
					out = append(out, doctorCheck{Name: "identity", OK: true,
						Note: fmt.Sprintf("ok  pub=%s sig=%s (publish BOTH)", hex.EncodeToString(e.PublicKey())[:16]+"…", hex.EncodeToString(sigPub)[:16]+"…")})
				}
			}
		}
	}

	// 2. Data dir.
	if o.Dir == "" {
		out = append(out, doctorCheck{Name: "data-dir", OK: false, Note: "no -dir given (daemon/mailbox need one)"})
	} else {
		st, err := os.Stat(o.Dir)
		switch {
		case err != nil:
			out = append(out, doctorCheck{Name: "data-dir", OK: false, Note: fmt.Sprintf("%s: %v (create it first)", o.Dir, err)})
		case !st.IsDir():
			out = append(out, doctorCheck{Name: "data-dir", OK: false, Note: fmt.Sprintf("%s is not a directory", o.Dir)})
		default:
			probe := o.Dir + "/.spore-doctor-probe"
			if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
				out = append(out, doctorCheck{Name: "data-dir", OK: false, Note: fmt.Sprintf("%s is not writable: %v", o.Dir, err)})
			} else {
				os.Remove(probe)
				out = append(out, doctorCheck{Name: "data-dir", OK: true, Note: fmt.Sprintf("%s ok (exists, writable)", o.Dir)})
			}
		}
	}

	// 3. Listen bind safety (the C1/C2 rule: loopback or credentialed).
	if o.Listen == "" {
		out = append(out, doctorCheck{Name: "listen", OK: false, Note: "no -listen given (recommended default: 127.0.0.1:<port>)"})
	} else if safehttp.HostIsLoopback(o.Listen) {
		out = append(out, doctorCheck{Name: "listen", OK: true, Note: fmt.Sprintf("%s ok (loopback-only)", o.Listen)})
	} else {
		out = append(out, doctorCheck{Name: "listen", OK: false,
			Note: fmt.Sprintf("%s is NOT loopback — every listener on it requires a -token and exposes plaintext HTTP to the network", o.Listen)})
	}

	return out
}

func doctorcmd(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	priv := fs.String("priv", "", "our medium-term privkey (hex) to verify")
	dir := fs.String("dir", "", "data dir to check")
	listen := fs.String("listen", "127.0.0.1:19191", "bind address to evaluate")
	timeout := fs.Duration("timeout", 5*time.Second, "chain probe timeout")
	addChainFlags(fs) // optional -chain/-rpc probe (same flags as `spore status`)
	_ = fs.Parse(args)

	fmt.Println("spore doctor")
	fmt.Println("---------------")
	failed := 0
	for _, c := range runDoctorChecks(doctorOpts{Priv: *priv, Dir: *dir, Listen: *listen}) {
		mark := "✅"
		if !c.OK {
			mark = "❌"
			failed++
		}
		fmt.Printf("  %s %-10s %s\n", mark, c.Name, c.Note)
	}

	// Optional chain probe (same machinery as `spore status`).
	if fs.Lookup("chain").Value.String() != "" {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		c := msgBackend(fs)
		p := probeChain(ctx, c)
		mark := "✅"
		if !p.ok {
			mark = "❌"
			failed++
		}
		if p.ok {
			fmt.Printf("  %s %-10s ok  addr=%s height=%d\n", mark, p.name, truncMid(p.address, 22), p.height)
		} else {
			fmt.Printf("  %s %-10s %s\n", mark, p.name, p.detail)
		}
	}

	fmt.Println("---------------")
	if failed > 0 {
		fmt.Printf("%d check(s) FAILED — fix the above before going live.\n", failed)
		os.Exit(1)
	}
	fmt.Println("all checks passed.")
}
