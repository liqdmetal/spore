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
//  4. config: config.json parses (strict — unknown fields are typos) and
//     every path it references exists on disk.
//  5. listen port: the -listen port is bindable now (free, or already held
//     by what is probably your running daemon).
//  6. key files: the spore home's secret key files exist and are mode 0600
//     (identity/spk/state/store keys, opk pool, config, maildb) — the P0-4
//     "defaults do not leak" gate for data at rest.
//  7. chain (optional): RPC/wallet reachable, address + height fetched.
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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	Config string // config.json path ("" = default resolution)
	Home   string // spore home dir for key-file perms ("" = default resolution)
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

	// 4. config.json validity (optional file; corrupt or lying = fail).
	out = append(out, doctorConfigCheck(o.Config))

	// 5. listen port availability (can a daemon actually bind it now?).
	out = append(out, doctorListenPortCheck(o.Listen))

	// 6. key files on disk: present and mode 0600 (data-at-rest, P0-4/P0-5).
	out = append(out, doctorKeyFilesCheck(o.Home))

	return out
}

// doctorConfigCheck validates config.json: strict parse (LoadConfig rejects
// unknown fields, so a typo like "identty" is caught, not silently ignored)
// and every referenced path exists. A MISSING config is fine — every command
// works flag-driven without one (LoadConfig: missing = nil, nil) — so the
// check passes with a pointer to `spore init`. A config that PARSES but
// references files that do not exist is a lie that would surface as a
// mid-send failure; doctor catches it up front.
func doctorConfigCheck(explicit string) doctorCheck {
	path := explicit
	if path == "" {
		path = configPath("")
	}
	if path == "" {
		return doctorCheck{Name: "config", OK: true, Note: "skipped (no config path resolvable)"}
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return doctorCheck{Name: "config", OK: true,
			Note: fmt.Sprintf("none at %s (optional — flag-driven setup works; `spore init` writes one)", path)}
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return doctorCheck{Name: "config", OK: false,
			Note: fmt.Sprintf("%s is INVALID: %v (fix or remove it — a corrupt config makes your defaults silently not apply)", path, err)}
	}
	// Every non-empty path field must exist on disk. StateDir must be a dir.
	refs := []struct{ name, path string }{
		{"dir", cfg.Dir}, {"identity", cfg.Identity}, {"spk", cfg.SPK},
		{"opk_pool", cfg.OpkPool}, {"store_key", cfg.StoreKey},
		{"state_key", cfg.StateKey}, {"maildb", cfg.Maildb},
	}
	var missing []string
	for _, r := range refs {
		if r.path == "" {
			continue
		}
		if _, err := os.Stat(r.path); err != nil {
			missing = append(missing, fmt.Sprintf("%s=%s", r.name, r.path))
		}
	}
	if len(missing) > 0 {
		return doctorCheck{Name: "config", OK: false,
			Note: fmt.Sprintf("%s references missing file(s): %s", path, strings.Join(missing, ", "))}
	}
	if cfg.StateDir != "" {
		if st, err := os.Stat(cfg.StateDir); err == nil && !st.IsDir() {
			return doctorCheck{Name: "config", OK: false,
				Note: fmt.Sprintf("state_dir %s is not a directory", cfg.StateDir)}
		}
	}
	return doctorCheck{Name: "config", OK: true,
		Note: fmt.Sprintf("ok  %s (parses, referenced paths exist)", path)}
}

// doctorListenPortCheck answers the deployment question check 3 cannot:
// "can something actually bind this address right now?" Free = fine. Held =
// fine if it is your own daemon/mailbox/web (the common healthy case), so
// OK with a caveat — a hard fail here would fire for everyone running the
// thing doctor is validating. Unbindable for other reasons (permissions,
// malformed address) = fail.
func doctorListenPortCheck(addr string) doctorCheck {
	if addr == "" {
		return doctorCheck{Name: "listen-port", OK: true, Note: "skipped (no -listen given)"}
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return doctorCheck{Name: "listen-port", OK: false,
			Note: fmt.Sprintf("cannot parse a port from %q (want host:port)", addr)}
	}
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		ln.Close()
		return doctorCheck{Name: "listen-port", OK: true,
			Note: fmt.Sprintf("port %s free — a daemon can bind %s", port, addr)}
	}
	errStr := err.Error()
	inUse := strings.Contains(errStr, "in use") || strings.Contains(errStr, "Only one usage")
	if inUse {
		return doctorCheck{Name: "listen-port", OK: true,
			Note: fmt.Sprintf("port %s in use — ok if that is your running daemon/mailbox/web; otherwise pick another port", port)}
	}
	return doctorCheck{Name: "listen-port", OK: false,
		Note: fmt.Sprintf("cannot bind %s: %v", addr, err)}
}

// doctorKeyFilesCheck walks the spore home (~/.spore or -home) and verifies
// the data-at-rest story: identity.key exists, and every secret-bearing file
// (identity/spk/state/store keys, opk pool, config.json — it holds
// store_token — and mail.json, which holds decrypted snippets) is mode 0600.
// Mode bits are meaningless on Windows, so there the check reports what it
// found without grading (the init/panic paths still write 0600 where the OS
// honors it).
func doctorKeyFilesCheck(home string) doctorCheck {
	if home == "" {
		d, err := DefaultConfigDir()
		if err != nil {
			return doctorCheck{Name: "key-files", OK: false, Note: fmt.Sprintf("cannot resolve spore home: %v", err)}
		}
		home = d
	}
	st, err := os.Stat(home)
	switch {
	case os.IsNotExist(err):
		return doctorCheck{Name: "key-files", OK: false,
			Note: fmt.Sprintf("no spore home at %s (run `spore init`)", home)}
	case err != nil:
		return doctorCheck{Name: "key-files", OK: false, Note: fmt.Sprintf("%s: %v", home, err)}
	case !st.IsDir():
		return doctorCheck{Name: "key-files", OK: false, Note: fmt.Sprintf("%s is not a directory", home)}
	}
	if _, err := os.Stat(filepath.Join(home, "identity.key")); os.IsNotExist(err) {
		return doctorCheck{Name: "key-files", OK: false,
			Note: fmt.Sprintf("identity.key missing in %s (run `spore init` or point -home at your spore home)", home)}
	}
	if runtime.GOOS == "windows" {
		return doctorCheck{Name: "key-files", OK: true,
			Note: fmt.Sprintf("ok  %s (identity.key present; mode bits not enforced on windows)", home)}
	}
	// Secrets that must be 0600 if present.
	secrets := []string{
		"identity.key", "spk.key", "state.key", "store.key",
		"opk-pool.json", "config.json", "mail.json",
	}
	var bad []string
	for _, name := range secrets {
		p := filepath.Join(home, name)
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue // absent is fine (except identity.key, checked above)
		}
		if fi.Mode().Perm() != 0o600 {
			bad = append(bad, fmt.Sprintf("%s=%o (want 600)", name, fi.Mode().Perm()))
		}
	}
	if dst, err := os.Stat(home); err == nil && dst.Mode().Perm() != 0o700 {
		bad = append(bad, fmt.Sprintf("home dir=%o (want 700)", dst.Mode().Perm()))
	}
	if len(bad) > 0 {
		return doctorCheck{Name: "key-files", OK: false,
			Note: fmt.Sprintf("overly-wide permissions in %s: %s — fix with chmod 600", home, strings.Join(bad, ", "))}
	}
	return doctorCheck{Name: "key-files", OK: true,
		Note: fmt.Sprintf("ok  %s (key files present, modes private)", home)}
}

func doctorcmd(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	priv := fs.String("priv", "", "our medium-term privkey (hex) to verify")
	dir := fs.String("dir", "", "data dir to check")
	listen := fs.String("listen", "127.0.0.1:19191", "bind address to evaluate")
	config := fs.String("config", "", "config.json to validate (default: -config flag/SPORE_CONFIG/~/.spore/config.json)")
	home := fs.String("home", "", "spore home dir to scan for key files and permissions (default ~/.spore or $SPORE_HOME)")
	timeout := fs.Duration("timeout", 5*time.Second, "chain probe timeout")
	live := fs.Bool("live", false, "also run known-answer self-tests on the wire paths (address, payload-0, ring byte, E2 pointer, ratchet, wallet receive-readiness)")
	storeURL := fs.String("store", "", "with -live: mailbox base URL (https://host/u/<name>) for a real store round-trip")
	storeTok := fs.String("store-token", "", "with -live: bearer token for -store")
	relayHop := fs.String("relay", "", "with -live: anonymous relay hop base URL (e.g. https://relay.example.org) — probes body writes through the relay instead of straight to -store")
	addChainFlags(fs) // optional -chain/-rpc probe (same flags as `spore status`)
	_ = fs.Parse(args)

	fmt.Println("spore doctor")
	fmt.Println("---------------")
	failed := 0

	report := func(checks []doctorCheck) {
		for _, c := range checks {
			mark := "✅"
			if !c.OK {
				mark = "❌"
				failed++
			}
			fmt.Printf("  %s %-13s %s\n", mark, c.Name, c.Note)
		}
	}

	report(runDoctorChecks(doctorOpts{Priv: *priv, Dir: *dir, Listen: *listen, Config: *config, Home: *home}))

	// Self-tests: prove this build still decodes what the network sends.
	if *live {
		fmt.Println("  --- live self-tests ---")
		report(runLiveDoctorChecks(doctorLiveOpts{
			Store:    *storeURL,
			StoreTok: *storeTok,
			Relay:    *relayHop,
			RPC:      fs.Lookup("rpc").Value.String(),
			RPCLogin: fs.Lookup("rpc-login").Value.String(),
			Timeout:  *timeout,
		}))
	}

	// Optional chain probe (same machinery as `spore status`). Keyed off -rpc,
	// not -chain: -chain defaults to "dero", so testing it would fire the probe
	// on every plain `spore doctor` and fail for lack of an endpoint.
	if fs.Lookup("rpc").Value.String() != "" {
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
			fmt.Printf("  %s %-13s ok  addr=%s height=%d\n", mark, p.name, truncMid(p.address, 22), p.height)
		} else {
			fmt.Printf("  %s %-13s %s\n", mark, p.name, p.detail)
		}
	}

	fmt.Println("---------------")
	if failed > 0 {
		fmt.Printf("%d check(s) FAILED — fix the above before going live.\n", failed)
		os.Exit(1)
	}
	fmt.Println("all checks passed.")
}
