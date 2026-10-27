package main

// bill xmr — the Monero branch of the mailbox billing poller.
//
// The DERO path reads result.entries from DERO's wallet RPC and derives a
// customer name from the txid. Monero offers neither: get_transfers answers
// under result.in[], and it carries NO sender field, by design. So the payer is
// identified by *which subaddress was paid*, and the operator supplies the
// mapping. That is the whole shape of this file.
//
// Field names below are pinned twice over: against Monero v0.18.0.0 source
// (COMMAND_RPC_GET_TRANSFERS::transfer_entry and the incoming
// fill_transfer_entry), and against a populated result.in[] entry captured from
// a live v0.18.5.1 wallet (2026-10-27). Two things that capture settled:
//   - the auth scheme is Digest (see xmrRPCClient) — Basic gets a 401;
//   - an incoming entry carries address, amount, amounts, confirmations,
//     double_spend_seen, fee, height, locked, note, payment_id, subaddr_index,
//     subaddr_indices, suggested_confirmations_threshold, timestamp, txid,
//     type, unlock_time — and NOT destinations, which is set for outgoing
//     entries only.
//
// The command is still gated behind -xmr-unverified: what has been proven
// against the live wallet is auth, the response shape and the decision core, not
// a payment carried all the way through provisioning into a receipt.
// See docs/MONERO_SETTLEMENT.md §3, §5 and §9.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/icholy/digest"
)

// xmrTransferEntry is one entry of monero-wallet-rpc get_transfers result.in[].
// Only the fields this poller acts on are decoded; the response carries more
// (amounts, fee, destinations, note, timestamp, subaddr_indices, …), and Go's
// decoder ignores what is not listed here.
type xmrTransferEntry struct {
	TxID          string `json:"txid"`
	Height        uint64 `json:"height"`
	Amount        uint64 `json:"amount"`
	Confirmations uint64 `json:"confirmations"`
	// Type is a STRING, and in[] is not exclusively payments: the wallet RPC
	// sets "in" for a payment and "block" for a coinbase entry. Array
	// membership is not evidence that someone paid.
	Type string `json:"type"`
	// Locked is the live spendability signal. unlock_time is recorded for the
	// message only: it stays non-zero after a time lock has passed, so guarding
	// on it would hold a transfer forever.
	Locked       bool   `json:"locked"`
	UnlockTime   uint64 `json:"unlock_time"`
	DoubleSpend  bool   `json:"double_spend_seen"`
	Address      string `json:"address"`
	SubaddrIndex struct {
		Major uint32 `json:"major"`
		Minor uint32 `json:"minor"`
	} `json:"subaddr_index"`
}

// billXMRRefusal is an incoming transfer this poller refused to bill, and why.
//
// Retry says whether the refusal must pin the poll watermark (nextBillWatermark,
// billcmd.go). A deferred transfer — unconfirmed, locked, or awaiting a label —
// can still become billable, and nothing re-reads it once min_height has passed
// its height. A transfer that can never become billable (a coinbase entry, an
// underpayment) must NOT pin the watermark, or one of them would make every
// later poll re-scan from its height forever.
type billXMRRefusal struct {
	TXID   string
	Height uint64
	Minor  uint32
	Reason string
	Retry  bool
}

// billAssetAllowed reports whether -price ASSET can be billed by this poller,
// keeping two different operator problems apart: "there is no poller for this
// rail" and "the poller exists but has no live payment behind it".
func billAssetAllowed(asset string, xmrUnverified bool) error {
	switch asset {
	case "dero":
		return nil
	case "xmr":
		if !xmrUnverified {
			return errors.New("bill watch: -price asset \"xmr\" is experimental only (auth and the result.in[] shape are live-verified against a v0.18.5.1 wallet on 2026-10-27, but no live XMR payment has been carried through provisioning into a receipt): pass -xmr-unverified to use it anyway and treat every result as experimental — docs/MONERO_SETTLEMENT.md §5")
		}
		return nil
	default:
		return fmt.Errorf("bill watch: -price asset %q is not billable: the DERO poller reads get_transfers -> result.entries (sender-tagged), and Monero answers result.in[] and names no sender, so XMR billing needs per-order subaddress attribution via -xmr-subaddresses; use e.g. 25dero or 2.5xmr", asset)
	}
}

// loadXMRSubaddresses reads the operator's subaddress → customer map: a JSON
// object of subaddress minor index → hosted username, e.g. {"3":"cc4f19a2"}.
//
// It is required for XMR billing because Monero carries no sender, so the
// receiving subaddress is the only thing that identifies who paid. Values must
// be valid hosted usernames and must be unique: two indices mapping to the same
// customer would make the money hard to attribute rather than doubly paid, and
// the mailbox provision step would collide on one directory.
func loadXMRSubaddresses(path string) (map[uint32]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bill watch: -xmr-subaddresses: %w", err)
	}
	byName := map[string]string{}
	if err := json.Unmarshal(raw, &byName); err != nil {
		return nil, fmt.Errorf("bill watch: -xmr-subaddresses %s: want a JSON object of subaddress minor index -> hosted user: %w", path, err)
	}
	if len(byName) == 0 {
		return nil, fmt.Errorf("bill watch: -xmr-subaddresses %s is empty: with no labelled subaddress nothing can ever be billed", path)
	}
	labels := make(map[uint32]string, len(byName))
	seen := map[string]uint32{}
	for k, user := range byName {
		idx, err := strconv.ParseUint(strings.TrimSpace(k), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bill watch: -xmr-subaddresses %s: key %q is not a subaddress minor index (want a decimal integer, e.g. \"3\")", path, k)
		}
		minor := uint32(idx)
		if !billUserNameRe.MatchString(user) {
			return nil, fmt.Errorf("bill watch: -xmr-subaddresses %s: subaddress %d names user %q, which is not a valid hosted username (%s)", path, minor, user, billUserNameRe)
		}
		if first, dup := seen[user]; dup {
			return nil, fmt.Errorf("bill watch: -xmr-subaddresses %s: user %q is claimed by subaddresses %d and %d; one customer, one subaddress or the money is ambiguous", path, user, first, minor)
		}
		seen[user] = minor
		labels[minor] = user
	}
	return labels, nil
}

// planXMRPayments is the pure decision core for Monero billing: it applies
// MONERO_SETTLEMENT §5's guards to a get_transfers result and returns the
// provisionable payments, plus every transfer it refused and why.
//
// Nothing here is silent: a transfer that is refused is always reported, because
// the failure this branch exists to prevent is a poller that looks healthy while
// billing nothing.
func planXMRPayments(price, floor uint64, labels map[uint32]string, done map[string]string, entries []xmrTransferEntry) (plans []paymentPlan, refusals []billXMRRefusal) {
	for _, e := range entries {
		if _, seen := done[e.TxID]; seen {
			continue // already provisioned (or already billed under this txid)
		}
		refuse := func(reason string, retry bool) {
			refusals = append(refusals, billXMRRefusal{
				TXID: e.TxID, Height: e.Height, Minor: e.SubaddrIndex.Minor,
				Reason: reason, Retry: retry,
			})
		}
		// Fail closed on type: a coinbase entry ("block") is not a payment, and
		// an empty type means a build whose shape we have not seen — refuse it
		// loudly (the reason names the value) rather than bill a miner's block
		// reward as a customer.
		if e.Type != "in" {
			refuse(fmt.Sprintf("get_transfers type is %q, not \"in\" (a coinbase entry is not a payment)", e.Type), false)
			continue
		}
		if e.Locked {
			refuse(fmt.Sprintf("locked until block %d; received is not the same as spendable", e.UnlockTime), true)
			continue
		}
		if e.DoubleSpend {
			refuse("double_spend_seen: the wallet is reporting this transfer as already spent", false)
			continue
		}
		// This poller bills account 0 (the request asks for it), so a transfer
		// arriving under another account cannot be attributed by minor index.
		if e.SubaddrIndex.Major != 0 {
			refuse(fmt.Sprintf("subaddress is in account %d; this poller bills account 0 only", e.SubaddrIndex.Major), false)
			continue
		}
		user, labelled := labels[e.SubaddrIndex.Minor]
		if !labelled {
			refuse(fmt.Sprintf("subaddress minor=%d is unlabelled (%s); add it to -xmr-subaddresses", e.SubaddrIndex.Minor, shortOrDash(e.Address)), true)
			continue
		}
		if e.Confirmations < floor {
			refuse(fmt.Sprintf("unconfirmed (%d/%d); a mailbox cannot be un-provisioned, so this waits", e.Confirmations, floor), true)
			continue
		}
		if e.Amount < price {
			refuse(fmt.Sprintf("underpaid: %s xmr against a %s xmr price", formatAmount("xmr", e.Amount), formatAmount("xmr", price)), false)
			continue
		}
		plans = append(plans, paymentPlan{TXID: e.TxID, Height: e.Height, Amount: e.Amount, User: user})
	}
	return plans, refusals
}

// xmrRPCClient builds the HTTP client for monero-wallet-rpc.
//
// The auth scheme is the wallet's, not ours. Monero's epee server challenges
// with `WWW-Authenticate: Digest qop="auth",algorithm=MD5,realm="monero-rpc"`
// and answers a *valid* Basic header with 401 — confirmed against the live
// v0.18.5.1 wallet on 2026-10-27, where one credential returned 401 as Basic and
// 200 as Digest. The DERO rail (billPollRPC, billcmd.go) keeps SetBasicAuth,
// because DERO's wallet speaks plain Basic; this rail cannot use it, and the
// difference is not cosmetic. A scheme the server rejects makes every poll fail,
// and a poller whose failure looks like an empty result bills nothing while
// looking healthy — the failure MONERO_SETTLEMENT §5 exists to prevent.
//
// Deliberately the same transport internal/xmr uses: one rail should not hold
// two opinions about how to authenticate to the same wallet.
func xmrRPCClient(login string) *http.Client {
	var rt http.RoundTripper = http.DefaultTransport
	if u, p, ok := strings.Cut(login, ":"); ok {
		rt = &digest.Transport{Username: u, Password: p}
	}
	return &http.Client{Transport: rt, Timeout: 30 * time.Second}
}

// billPollRPCXMR calls monero-wallet-rpc get_transfers for incoming transfers
// and returns the entries plus the highest height seen. Auth is Digest (see
// xmrRPCClient): a 401 here is returned as an error, never as "no payments".
//
// filter_by_height is NOT optional. v0.18.0.0 gates height filtering on it, so a
// request that sends min_height without it re-scans every transfer the wallet
// holds on every poll while looking perfectly correct.
func billPollRPCXMR(rpcURL, login string, minHeight uint64) ([]xmrTransferEntry, uint64, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "bill", "method": "get_transfers",
		"params": map[string]any{
			"in": true, "out": false, "pending": false, "failed": false, "pool": false,
			"account_index":    0,
			"filter_by_height": true,
			"min_height":       minHeight,
		},
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := xmrRPCClient(login).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A rejected request (401, a wrong port, a proxy) must never read as
		// "no payments": that is the shape of a poller that bills nothing.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, 0, fmt.Errorf("bill watch: monero wallet RPC %s: HTTP %d: %s", rpcURL, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		Result struct {
			// "in" may be omitted entirely when it holds nothing: empty
			// categories are not guaranteed to serialize as []. A missing key is
			// no transfers, never an error.
			In []xmrTransferEntry `json:"in"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, fmt.Errorf("bill watch: monero wallet RPC %s: bad response: %w", rpcURL, err)
	}
	if out.Error != nil {
		return nil, 0, errors.New(out.Error.Message)
	}
	maxH := minHeight
	for _, e := range out.Result.In {
		if e.Height > maxH {
			maxH = e.Height
		}
	}
	return out.Result.In, maxH, nil
}

// xmrRefusalSummary renders a poll's refusals for the state file (txid → why),
// so an operator can still see what the poller would not bill after the log has
// scrolled away. encoding/json sorts map keys, so two polls that refuse the same
// transfers write identical bytes. A poll with no refusals clears the map: it is
// a view of the last poll, not an append-only record.
func xmrRefusalSummary(refusals []billXMRRefusal) map[string]string {
	if len(refusals) == 0 {
		return nil
	}
	byTx := make(map[string]string, len(refusals))
	for _, r := range refusals {
		byTx[r.TXID] = r.Reason
	}
	return byTx
}
