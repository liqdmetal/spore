package main

// bill address — issue one fresh Monero subaddress for one order, and record
// which order it is.
//
// MONERO_SETTLEMENT §3: Monero names no sender, so the only thing that says who
// paid is WHICH address was paid. That used to be a hand-written JSON map — the
// step most likely to go wrong after midnight, because a typo attributes a
// payment to the wrong customer and the poller has no way to notice. Issuing the
// address here makes the wallet and spore's ledger agree by construction: one
// create_address call, one entry naming the order and the mailbox it pays for,
// written before the address is ever given to a customer.
//
//	spore bill address -rpc URL [-rpc-login u:p] -out DIR -user USER [-order ID]
//
// The ledger is <out>/subaddresses.json, in the same directory `bill watch`
// keeps bill-state.json and the receipts, so the poller finds it without being
// told where it is. `-xmr-subaddresses FILE` still works for a map somebody
// already maintains by hand; the two are merged, and a conflict is refused
// rather than resolved.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/xmr"
)

// billSubaddressLedgerFile is the ledger's name inside the outbox directory.
// Fixed, because `bill watch -out DIR` has to find it without a second flag.
const billSubaddressLedgerFile = "subaddresses.json"

// billSubaddress is one issued address: the address itself, the order it was
// issued for, and the hosted mailbox a payment to it provisions.
type billSubaddress struct {
	// Address is recorded so the ledger can be reconciled against the wallet
	// without a wallet call, and so an operator can see what was handed out.
	Address string `json:"address,omitempty"`
	// User is the hosted mailbox this address pays for. Required: an address
	// nobody can be provisioned from is a payment waiting to be held forever.
	User string `json:"user"`
	// Order is the operator's own order reference. Optional, but it is the whole
	// point of issuing per order: it is what makes "which order was this?" a
	// lookup rather than an investigation.
	Order    string `json:"order,omitempty"`
	IssuedAt string `json:"issued_at,omitempty"`
}

// reBillOrder keeps an order reference to one line of printable characters: it
// travels into a wallet label, which is not the place for a newline.
var reBillOrder = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// billLedgerPath is the ledger's path inside an outbox directory.
func billLedgerPath(outDir string) string {
	return filepath.Join(outDir, billSubaddressLedgerFile)
}

// loadBillSubaddresses reads the issued-address ledger. A missing file is not an
// error: an instance that has issued nothing yet is a normal state, and the
// poller has its own, louder refusal for "nothing can be billed".
func loadBillSubaddresses(path string) (map[uint32]billSubaddress, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[uint32]billSubaddress{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("bill: read %s: %w", path, err)
	}
	var byKey map[string]billSubaddress
	if err := json.Unmarshal(raw, &byKey); err != nil {
		return nil, fmt.Errorf("bill: %s: want a JSON object of subaddress minor index -> {user, address, order}: %w", path, err)
	}
	out := make(map[uint32]billSubaddress, len(byKey))
	for k, e := range byKey {
		minor, err := strconv.ParseUint(k, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bill: %s: key %q is not a subaddress minor index (want a decimal integer, e.g. \"3\")", path, k)
		}
		if !billUserNameRe.MatchString(e.User) {
			return nil, fmt.Errorf("bill: %s: subaddress %s names user %q, which is not a valid hosted username (%s)", path, k, e.User, billUserNameRe)
		}
		out[uint32(minor)] = e
	}
	return out, nil
}

// saveBillSubaddresses writes the ledger atomically: a 0600 temp file in the
// same directory, then a rename. A crash mid-write must not leave a truncated
// ledger, because every address it named would silently become unlabelled and
// the payments to them would be held with no record of why.
func saveBillSubaddresses(path string, m map[uint32]billSubaddress) error {
	byKey := make(map[string]billSubaddress, len(m))
	for minor, e := range m {
		byKey[strconv.FormatUint(uint64(minor), 10)] = e
	}
	raw, err := json.MarshalIndent(byKey, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".subaddresses-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename has succeeded
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// mergeBillLabels resolves the two sources of attribution — the issued-address
// ledger and an optional hand-written map — into the minor→user map the poller
// bills from.
//
// Both sources are trusted to be about the same wallet, so a disagreement is a
// contradiction, not a preference: two customers on one address, or one customer
// on two addresses, makes money ambiguous and is refused. An identical entry in
// both is not a conflict — that is how an operator migrates from the old map to
// the ledger without a flag day.
func mergeBillLabels(issued map[uint32]billSubaddress, legacy map[uint32]string, legacyPath string) (map[uint32]string, error) {
	labels := make(map[uint32]string, len(issued)+len(legacy))
	owner := make(map[string]uint32, len(issued)+len(legacy))
	add := func(minor uint32, user, source string) error {
		if prev, seen := labels[minor]; seen {
			if prev == user {
				return nil
			}
			return fmt.Errorf("bill watch: subaddress %d is labelled %q by %s and %q by another source — one address, one customer", minor, prev, source, user)
		}
		if first, dup := owner[user]; dup {
			return fmt.Errorf("bill watch: user %q owns subaddresses %d and %d (%s) — issue one address per order, never two for one customer", user, first, minor, source)
		}
		labels[minor] = user
		owner[user] = minor
		return nil
	}
	// Sorted-by-construction is not needed here, but deterministic order makes
	// the first conflict an operator sees the same one on every run.
	for _, minor := range sortedMinors(issued) {
		if err := add(minor, issued[minor].User, "the issued-address ledger"); err != nil {
			return nil, err
		}
	}
	if len(legacy) > 0 {
		src := "the -xmr-subaddresses map"
		if legacyPath != "" {
			src = "-xmr-subaddresses " + legacyPath
		}
		for _, minor := range sortedMinorsLegacy(legacy) {
			if err := add(minor, legacy[minor], src); err != nil {
				return nil, err
			}
		}
	}
	return labels, nil
}

func sortedMinors(m map[uint32]billSubaddress) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortUints(out)
	return out
}

func sortedMinorsLegacy(m map[uint32]string) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortUints(out)
	return out
}

func sortUints(v []uint32) {
	// Insertion sort: these maps hold at most a few hundred orders, and a sorted
	// view exists only so two runs report the same conflict first.
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// billAddress issues one subaddress for one order and records it.
//
// Every refusal happens BEFORE the wallet call where it can: an address the
// wallet has already created but the ledger never learned is money nobody can
// attribute, and the retry cannot tell it apart from a fresh request.
func billAddress(args []string) {
	fs := flag.NewFlagSet("bill address", flag.ExitOnError)
	rpc := fs.String("rpc", "", "wallet RPC endpoint, e.g. http://127.0.0.1:18083/json_rpc")
	rpcLogin := fs.String("rpc-login", "", "wallet RPC credential: Digest on Monero")
	out := fs.String("out", "", "outbox directory `bill watch` uses (the ledger lands here)")
	addresses := fs.String("addresses", "", "ledger path (default: OUT/subaddresses.json)")
	user := fs.String("user", "", "hosted mailbox this address pays for")
	order := fs.String("order", "", "your order reference, recorded against the address")
	adopt := fs.Int("adopt", -1, "record an address the wallet already has, by minor index (recovery; see `bill reconcile`)")
	timeout := fs.Duration("timeout", 30*time.Second, "wallet RPC timeout")
	_ = fs.Parse(args)

	if *rpc == "" || *user == "" || (*out == "" && *addresses == "") {
		fmt.Fprintln(os.Stderr, "bill address: -rpc -user and one of -out/-addresses are required")
		os.Exit(2)
	}
	if !billUserNameRe.MatchString(*user) {
		check(fmt.Errorf("bill address: -user %q is not a valid hosted username (%s)", *user, billUserNameRe))
	}
	if *order != "" && !reBillOrder.MatchString(*order) {
		check(fmt.Errorf("bill address: -order %q must be 1-64 characters of [A-Za-z0-9._:-], starting with a letter or digit", *order))
	}

	ledgerPath := *addresses
	if ledgerPath == "" {
		ledgerPath = billLedgerPath(*out)
		if err := os.MkdirAll(*out, 0o700); err != nil {
			check(err)
		}
	}
	if *adopt >= 0 {
		billAdopt(*rpc, *rpcLogin, ledgerPath, *user, *order, uint32(*adopt), *timeout)
		return
	}
	ledger, err := loadBillSubaddresses(ledgerPath)
	check(err)
	check(billCheckIssued(ledger, *user, *order))

	label := "user:" + *user
	if *order != "" {
		label = "order:" + *order
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	addr, err := xmr.CreateAddress(ctx, *rpc, *rpcLogin, 0, label)
	check(err)
	// The poller bills account 0 only; an address under another account would be
	// issued and then never reconciled, which is worse than refusing now.
	if addr.Index.Major != 0 {
		check(fmt.Errorf("bill address: the wallet issued subaddress %d/%d under account %d, but `bill watch` bills account 0 only", addr.Index.Major, addr.Index.Minor, addr.Index.Major))
	}
	if prev, clash := ledger[addr.Index.Minor]; clash {
		check(fmt.Errorf("bill address: the wallet returned subaddress %d, which the ledger already labels %q (%s); reconcile the wallet and %s before issuing again", addr.Index.Minor, prev.User, orderOrDash(prev.Order), ledgerPath))
	}

	ledger[addr.Index.Minor] = billSubaddress{
		Address:  addr.Address,
		User:     *user,
		Order:    *order,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
	}
	check(saveBillSubaddresses(ledgerPath, ledger))

	fmt.Printf("subaddress  %s\n", addr.Address)
	fmt.Printf("minor       %d (account %d)\n", addr.Index.Minor, addr.Index.Major)
	fmt.Printf("order       %s\n", orderOrDash(*order))
	fmt.Printf("pays for    %s\n", *user)
	fmt.Printf("ledger      %s\n", ledgerPath)
	fmt.Println()
	fmt.Println("Give the subaddress to the payer. `bill watch -out` reads the ledger itself,")
	fmt.Println("so there is no map to edit — and do not hand the same address to a second order.")
}

// billAdopt records an address the wallet already has.
//
// It exists for one situation: create_address succeeded and the ledger write did
// not — a crash, a full disk, a killed process — so the wallet owns an address
// spore never learned and a payment to it would be held forever. `bill reconcile`
// finds those and prints this command; the wallet's own label supplies the order,
// which is why issuance writes one to the wallet and not only to the ledger.
func billAdopt(rpcURL, login, ledgerPath, user, order string, minor uint32, timeout time.Duration) {
	ledger, err := loadBillSubaddresses(ledgerPath)
	check(err)
	if prev, clash := ledger[minor]; clash {
		check(fmt.Errorf("bill address: the ledger already records subaddress %d for %q (%s); nothing to adopt — a payment there is already attributable", minor, prev.User, orderOrDash(prev.Order)))
	}
	check(billCheckIssued(ledger, user, order))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := xmr.GetAddresses(ctx, rpcURL, login, 0)
	check(err)
	var found *xmr.WalletAddress
	for i := range addrs {
		if addrs[i].Index == minor {
			found = &addrs[i]
			break
		}
	}
	if found == nil {
		indices := make([]string, 0, len(addrs))
		for _, a := range addrs {
			indices = append(indices, strconv.FormatUint(uint64(a.Index), 10))
		}
		check(fmt.Errorf("bill address: the wallet has no subaddress %d on account 0 (it has %s); nothing to adopt", minor, strings.Join(indices, ", ")))
	}
	// The wallet label is the only record of what an unrecorded address was for.
	// If the operator disagrees with it, refuse rather than pick: reconcile
	// matches on the label, so the two must say the same thing.
	if walletOrder, ok := orderFromLabel(found.Label); ok {
		if order != "" && order != walletOrder {
			check(fmt.Errorf("bill address: the wallet labels subaddress %d %q, but -order says %q; they have to agree or reconcile will never match this entry", minor, found.Label, order))
		}
		order = walletOrder
	}

	ledger[minor] = billSubaddress{
		Address:  found.Address,
		User:     user,
		Order:    order,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
	}
	check(saveBillSubaddresses(ledgerPath, ledger))

	fmt.Printf("adopted     %s\n", found.Address)
	fmt.Printf("minor       %d (account 0)\n", minor)
	fmt.Printf("order       %s\n", orderOrDash(order))
	if found.Label != "" {
		fmt.Printf("label       %s (the wallet's own)\n", found.Label)
	}
	fmt.Printf("pays for    %s\n", user)
	fmt.Printf("ledger      %s\n", ledgerPath)
	fmt.Println()
	fmt.Println("A payment to this address is now attributable. `bill reconcile` should be in step.")
}

// billCheckIssued refuses a user or order that already owns an address.
func billCheckIssued(ledger map[uint32]billSubaddress, user, order string) error {
	for _, minor := range sortedMinors(ledger) {
		e := ledger[minor]
		if e.User == user {
			return fmt.Errorf("bill address: %q already owns subaddress %d (%s); one customer, one address — never reuse across orders (MONERO_SETTLEMENT §3)", user, minor, orderOrDash(e.Order))
		}
		if order != "" && e.Order == order {
			return fmt.Errorf("bill address: order %q already has subaddress %d for %q; issue once per order rather than once per attempt", order, minor, e.User)
		}
	}
	return nil
}

// orderFromLabel reads an order id back out of a wallet label written as
// "order:<id>". A label in any other form is not an order, and guessing one
// would invent a reference the operator never chose.
func orderFromLabel(label string) (string, bool) {
	rest, ok := strings.CutPrefix(label, "order:")
	if !ok || !reBillOrder.MatchString(rest) {
		return "", false
	}
	return rest, true
}

func orderOrDash(order string) string {
	if order == "" {
		return "(unlabelled)"
	}
	return order
}

// errNoLedgerSource is returned to the poller when neither attribution source
// names a single address: without labels, every payment would be held forever.
var errNoLedgerSource = errors.New("bill watch: no subaddress is labelled, so no payment could ever be attributed")
