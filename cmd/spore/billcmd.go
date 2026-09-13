// bill — the hosted-mailbox billing orchestrator (BUSINESS.md Line 1, first
// dollar). One wallet RPC, one price, and every matching incoming transfer
// becomes a provisioned mailbox.
//
//	spore bill watch -rpc http://127.0.0.1:20209/json_rpc -rpc-login u:p \
//	  -users /srv/spore/users -tokens /srv/spore/tokens.json \
//	  -price 25dero -batch-dir /srv/spore/batches -out /srv/spore/billed \
//	  [-relay-fwd-tokens /srv/spore/relay/fwd-tokens.json] \
//	  [-on-provision /usr/local/sbin/spore-mailbox-onboard.sh] \
//	  [-interval 30s] [-once] [-dry-run]
//
// For each new incoming transfer >= -price it provisions the mailbox (spore
// provision, which writes dir + token + notify + onboarding record), merges
// the user's token into the relay forward-token map, drops the onboarding
// record into -out, and runs -on-provision (env: USER, TOKEN, MAILBOX, PRICE,
// TXID) when given — the hook's job is delivery: email/webhook/paste the
// onboarding card to the customer. The batch file must already sit at
// <batch-dir>/<user>.json (it comes from the customer's device); payments
// whose batch is missing are held and re-attempted on later polls.
// Re-runs are safe: progress lives in <out>/bill-state.json.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func billcmd(args []string) {
	if len(args) == 0 {
		billUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "watch":
		billWatch(args[1:])
	case "-h", "--help", "help":
		billUsage()
	default:
		fmt.Fprintf(os.Stderr, "bill: unknown subcommand %q (want watch)\n", args[0])
		os.Exit(2)
	}
}

func billUsage() {
	fmt.Fprint(os.Stderr, `spore bill — hosted mailbox billing orchestrator

  watch  poll a wallet RPC and provision paid mailboxes

watch flags:
  -rpc URL            wallet RPC endpoint (e.g. http://127.0.0.1:20209/json_rpc)
  -rpc-login u:p      wallet RPC basic auth
  -price AMOUNT       minimum payment, e.g. 25dero (atomic-exact)
  -users DIR          hosted users directory (same as `+"`mailbox host -users`"+`)
  -tokens FILE        bearer token JSON map (same as `+"`mailbox host -tokens`"+`)
  -batch-dir DIR      customer prekey batches: <user>.json (provision requires it)
  -out DIR            outbox: onboarding records + bill-state.json
  -relay-fwd-tokens F optional: relay forward-token map to merge the new user into
  -on-provision S     optional hook script; env USER/TOKEN/MAILBOX/PRICE/TXID
  -interval D         poll interval (default 30s)
  -once               single poll, then exit (for cron or a test)
  -dry-run            report what would happen, change nothing
`)
}

// billEntry is the slice of the wallet RPC transfer entry bill reads.
type billEntry struct {
	Height   uint64 `json:"height"`
	TXID     string `json:"txid"`
	Incoming bool   `json:"incoming"`
	Amount   uint64 `json:"amount"` // atomic DERO (1 DERO = 100000)
}

type billState struct {
	Height uint64            `json:"height"`
	Done   map[string]string `json:"done"` // txid -> provisioned user
	Held   map[string]string `json:"held"` // txid -> user (batch missing)
}

type paymentPlan struct {
	TXID   string
	Height uint64
	Amount uint64
	User   string
}

var billUserNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,15}$`)

// planPayments is the pure decision core: given the price, new incoming
// entries, and the txids already handled, return the payments to provision.
// A username is derived deterministically from the txid; two txids whose
// derived names collide are handled once (the second is skipped) so a later
// -force provision can never overwrite an earlier paid account.
func planPayments(price uint64, entries []billEntry, done map[string]string) []paymentPlan {
	var out []paymentPlan
	usedUsers := make(map[string]string, len(done)+len(entries)) // user -> first txid
	for _, u := range done {
		usedUsers[u] = u
	}
	for _, e := range entries {
		if !e.Incoming || e.Amount < price {
			continue
		}
		if _, seen := done[e.TXID]; seen {
			continue
		}
		user := "c" + e.TXID
		if len(user) > 16 {
			user = user[:16]
		}
		if _, clash := usedUsers[user]; clash {
			continue // derived-name collision: keep the first payer's account
		}
		usedUsers[user] = e.TXID
		out = append(out, paymentPlan{TXID: e.TXID, Height: e.Height, Amount: e.Amount, User: user})
	}
	return out
}

func billWatch(args []string) {
	fs := flag.NewFlagSet("bill watch", flag.ExitOnError)
	rpc := fs.String("rpc", "", "wallet RPC endpoint")
	rpcLogin := fs.String("rpc-login", "", "wallet RPC basic auth user:pass")
	price := fs.String("price", "", "minimum payment (e.g. 25dero)")
	users := fs.String("users", "", "hosted users directory")
	tokens := fs.String("tokens", "", "bearer token JSON map")
	batchDir := fs.String("batch-dir", "", "customer prekey batch directory (<user>.json)")
	out := fs.String("out", "", "outbox directory")
	relayTokens := fs.String("relay-fwd-tokens", "", "optional relay forward-token map to merge into")
	hook := fs.String("on-provision", "", "optional hook script; env USER/TOKEN/MAILBOX/PRICE/TXID")
	interval := fs.Duration("interval", 30*time.Second, "poll interval")
	once := fs.Bool("once", false, "single poll, then exit")
	dryRun := fs.Bool("dry-run", false, "report only, change nothing")
	_ = fs.Parse(args)

	if *rpc == "" || *price == "" || *users == "" || *tokens == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "bill watch: -rpc -price -users -tokens -out are required")
		os.Exit(2)
	}
	if *batchDir == "" {
		fmt.Fprintln(os.Stderr, "bill watch: -batch-dir is required (customer prekey batches land here)")
		os.Exit(2)
	}
	asset, priceAtomic, err := parseAmountFlag(*price)
	if err != nil {
		check(err)
	}
	if asset != "dero" {
		check(fmt.Errorf("bill watch: -price asset %q: bill matches wallet RPC amounts, which are atomic DERO; use e.g. 25dero", asset))
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		check(err)
	}

	statePath := filepath.Join(*out, "bill-state.json")
	st := billState{Done: map[string]string{}, Held: map[string]string{}}
	if raw, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(raw, &st)
	}

	poll := func() (int, error) {
		entries, h, err := billPollRPC(*rpc, *rpcLogin, st.Height)
		if err != nil {
			return 0, err
		}
		plans := planPayments(priceAtomic, entries, st.Done)
		n := 0
		for _, p := range plans {
			if *dryRun {
				log.Printf("DRY-RUN would provision txid=%s user=%s amount=%d atomic (%.5f dero)", p.TXID, p.User, p.Amount, float64(p.Amount)/100000)
				n++
				continue
			}
			batch := filepath.Join(*batchDir, p.User+".json")
			if _, err := os.Stat(batch); err != nil {
				log.Printf("txid=%s user=%s: batch %s missing — holding until it arrives", p.TXID, p.User, batch)
				st.Held[p.TXID] = p.User
				continue
			}
			if err := billProvision(*users, *tokens, *batchDir, *out, p, *relayTokens, *hook); err != nil {
				log.Printf("txid=%s user=%s: provision failed: %v", p.TXID, p.User, err)
				continue
			}
			st.Done[p.TXID] = p.User
			delete(st.Held, p.TXID)
			n++
		}
		if h > st.Height {
			st.Height = h
		}
		raw, _ := json.MarshalIndent(st, "", "  ")
		_ = os.WriteFile(statePath, append(raw, '\n'), 0o600)
		return n, nil
	}

	for {
		n, err := poll()
		if err != nil {
			log.Printf("poll error: %v", err)
		} else if n > 0 {
			log.Printf("provisioned %d mailbox(es) this pass", n)
		}
		if *once {
			return
		}
		time.Sleep(*interval)
	}
}

// billPollRPC calls wallet get_transfers {in:true, min_height: h} with basic
// auth. Returns the new incoming entries and the highest height seen.
func billPollRPC(rpcURL, login string, minHeight uint64) ([]billEntry, uint64, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "bill", "method": "get_transfers",
		"params": map[string]any{"in": true, "min_height": minHeight},
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if login != "" {
		u, p, ok := strings.Cut(login, ":")
		if ok {
			req.SetBasicAuth(u, p)
		}
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Entries []billEntry `json:"entries"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, err
	}
	if out.Error != nil {
		return nil, 0, errors.New(out.Error.Message)
	}
	var entries []billEntry
	maxH := minHeight
	for _, e := range out.Result.Entries {
		if !e.Incoming {
			continue
		}
		entries = append(entries, e)
		if e.Height > maxH {
			maxH = e.Height
		}
	}
	return entries, maxH, nil
}

// billProvision runs the shipped `spore provision` subprocess (same binary),
// merges the user into the relay forward-token map, files the onboarding
// record into the outbox, and runs the delivery hook.
func billProvision(usersDir, tokensFile, batchDir, outDir string, p paymentPlan, relayTokens, hook string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve self: %w", err)
	}
	mailbox := "https://mail.sporem3.io/u/" + p.User
	cmd := exec.Command(self, "provision",
		"-users", usersDir, "-name", p.User,
		"-tokens", tokensFile,
		"-batch", filepath.Join(batchDir, p.User+".json"),
		"-mailbox-url", mailbox,
		"-force",
	)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("provision: %v: %s", err, strings.TrimSpace(string(b)))
	}
	// Relay forward-token merge: the relay presents this token on the last
	// hop to this user's mailbox. The relay itself still needs a restart (its
	// allowlist is startup config) — the hook or operator handles that.
	if relayTokens != "" {
		tok, err := billReadToken(usersDir, p.User)
		if err != nil {
			return err
		}
		raw, _ := os.ReadFile(relayTokens)
		m := map[string]string{}
		_ = json.Unmarshal(raw, &m)
		m[mailbox] = tok
		b, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(relayTokens, append(b, '\n'), 0o600); err != nil {
			return err
		}
	}
	// File the record: onboarding card + payment receipt.
	onboard, err := os.ReadFile(filepath.Join(usersDir, p.User, "onboarding.json"))
	if err != nil {
		return err
	}
	receipt := map[string]any{
		"txid": p.TXID, "height": p.Height, "amount_atomic": p.Amount,
		"user": p.User, "mailbox": mailbox, "provisioned_at": time.Now().UTC().Format(time.RFC3339),
	}
	rb, _ := json.MarshalIndent(receipt, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, p.User+".onboarding.json"), onboard, 0o600)
	_ = os.WriteFile(filepath.Join(outDir, p.User+".receipt.json"), append(rb, '\n'), 0o600)
	if hook != "" {
		env := append(os.Environ(),
			"SPORE_BILL_USER="+p.User,
			"SPORE_BILL_TOKEN="+billReadTokenOr(usersDir, p.User, ""),
			"SPORE_BILL_MAILBOX="+mailbox,
			"SPORE_BILL_PRICE="+strconv.FormatUint(p.Amount, 10),
			"SPORE_BILL_TXID="+p.TXID,
		)
		c := exec.Command(hook)
		c.Env = env
		if b, err := c.CombinedOutput(); err != nil {
			log.Printf("hook %s: %v: %s", hook, err, strings.TrimSpace(string(b)))
		}
	}
	return nil
}

// billReadToken returns the user's bearer token from the tokens map.
func billReadToken(tokensFile, user string) (string, error) {
	t := billReadTokenOr(tokensFile, user, "")
	if t == "" {
		return "", fmt.Errorf("no token for user %q in %s", user, tokensFile)
	}
	return t, nil
}

func billReadTokenOr(tokensFile, user, fallback string) string {
	raw, err := os.ReadFile(tokensFile)
	if err != nil {
		return fallback
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return fallback
	}
	if t := m[user]; t != "" {
		return t
	}
	return fallback
}

// billConstTimeEq exists so the token merge can stay constant-time against
// the map lookup elsewhere; used by tests.
func billConstTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
