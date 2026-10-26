package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/attest"
	"github.com/liqdmetal/spore/internal/jobreceipt"
)

// sign receipt — emit, sign and verify the receipt specified in
// docs/JOB_RECEIPT_V1.md.
//
// The point of a dedicated command rather than three flags on `sign doc` is the
// role statements. A signature is only a receipt if it asserts the thing the
// protocol says it asserts, and `sign sheet` cannot tell — it verifies each
// envelope against whatever statement that envelope carries. So the statement is
// not a parameter here: `sign` derives it from -role, and `verify` rejects any
// envelope whose statement is not the exact constant for the role its key holds.

func signReceipt(args []string) {
	if len(args) == 0 {
		receiptUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		receiptCreate(args[1:])
	case "sign":
		receiptSign(args[1:])
	case "verify":
		receiptVerify(args[1:])
	case "-h", "--help":
		receiptUsage()
	default:
		fmt.Fprintf(os.Stderr, "sign receipt: unknown subcommand %q (want create|sign|verify)\n", args[0])
		os.Exit(2)
	}
}

func receiptUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore sign receipt create -out F -service-category C -service-summary S
        -provider-pub HEX [-client-pub HEX | -provider-only]
        -started-at RFC3339 -finished-at RFC3339
        -settlement rail=dero,network=dero-mainnet,asset=dero,amount=2500000000000,txid=HEX,settled=RFC3339
        [-settlement ...] [-deliverable label=before,digest=sha256:HEX,bytes=N]
        [-client-accepted [-client-rating 1..5] [-client-note TEXT]]
        [-work-order ID] [-thread HEX] [-supersedes sha256:HEX]
        (emit the canonical record; the file's SHA-256 is its receipt id)

  spore sign receipt sign -role client|provider -identity F -file F [-out SIG]
        (sign with the role's FIXED statement; refuses an identity that is not
         that role's key in the record)

  spore sign receipt verify -file F -sigs A.sig,B.sig [-required both|client|provider]
        (verify the signatures AND that each one carries its role's statement)

A receipt is optional. Nothing here creates one unless someone runs create, and a
provider-only record (no client key, no verdict) is not a reputation entry.`)
}

func receiptCreate(args []string) {
	fs := flag.NewFlagSet("sign receipt create", flag.ExitOnError)
	out := fs.String("out", "", "write the canonical record here (required)")
	category := fs.String("service-category", "", "e.g. plumbing.emergency (required)")
	summary := fs.String("service-summary", "", "one line of what the work was (required)")
	providerPub := fs.String("provider-pub", "", "provider signing key, hex (required)")
	clientPub := fs.String("client-pub", "", "client signing key, hex (required unless -provider-only)")
	providerOnly := fs.Bool("provider-only", false, "emit a one-signer record: no client key, no verdict")
	started := fs.String("started-at", "", "RFC 3339 UTC, e.g. 2026-10-24T15:02:11Z (required)")
	finished := fs.String("finished-at", "", "RFC 3339 UTC (required)")
	var settlements receiptList
	fs.Var(&settlements, "settlement", "rail=…,network=…,asset=…,amount=…,txid=…,settled=… (repeatable, at least one)")
	var deliverables receiptList
	fs.Var(&deliverables, "deliverable", "label=…,digest=sha256:…,bytes=N (repeatable)")
	accepted := fs.Bool("client-accepted", false, "record that the client accepted the work")
	rating := fs.Int("client-rating", 0, "1..5, requires -client-accepted")
	note := fs.String("client-note", "", "optional free-text note from the client")
	workOrder := fs.String("work-order", "", "optional work order id both sides agreed")
	thread := fs.String("thread", "", "optional hex session id of the spore thread")
	supersedes := fs.String("supersedes", "", "optional sha256:… of the record this one corrects")
	_ = fs.Parse(args)

	if *out == "" {
		check(errors.New("sign receipt create: -out is required"))
	}
	if *providerOnly && *clientPub != "" {
		check(errors.New("sign receipt create: -provider-only and -client-pub are mutually exclusive"))
	}

	rec := &jobreceipt.Record{
		Protocol: jobreceipt.Protocol,
		Version:  jobreceipt.Version,
		Kind:     jobreceipt.KindAttested,
		Service: jobreceipt.Service{
			Category: *category,
			Summary:  *summary,
		},
		Parties: jobreceipt.Parties{
			ProviderPub: *providerPub,
		},
		Work: jobreceipt.Work{
			StartedAt:  *started,
			FinishedAt: *finished,
		},
		Supersedes: *supersedes,
	}
	if *providerOnly {
		rec.Coverage = jobreceipt.CoverageProviderOnly
	} else {
		rec.Parties.ClientPub = *clientPub
	}

	for i, spec := range settlements {
		kv, err := receiptKV(spec)
		if err != nil {
			check(fmt.Errorf("sign receipt create: -settlement #%d: %w", i+1, err))
		}
		if err := receiptKeys(kv, i, "settlement", "rail", "network", "asset", "amount", "txid", "settled"); err != nil {
			check(fmt.Errorf("sign receipt create: %w", err))
		}
		rec.Settlement = append(rec.Settlement, jobreceipt.Settlement{
			Rail:         kv["rail"],
			Network:      kv["network"],
			Asset:        kv["asset"],
			AmountAtomic: kv["amount"],
			TxID:         kv["txid"],
			SettledAt:    kv["settled"],
		})
	}
	jobreceipt.SortSettlements(rec.Settlement)

	for i, spec := range deliverables {
		kv, err := receiptKV(spec)
		if err != nil {
			check(fmt.Errorf("sign receipt create: -deliverable #%d: %w", i+1, err))
		}
		if err := receiptKeys(kv, i, "deliverable", "label", "digest", "bytes"); err != nil {
			check(fmt.Errorf("sign receipt create: %w", err))
		}
		n, err := strconv.ParseInt(kv["bytes"], 10, 64)
		if err != nil {
			check(fmt.Errorf("sign receipt create: -deliverable #%d bytes=%q is not an integer", i+1, kv["bytes"]))
		}
		rec.Deliverables = append(rec.Deliverables, jobreceipt.Deliverable{
			Label:  kv["label"],
			Digest: kv["digest"],
			Bytes:  n,
		})
	}

	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if seen["client-accepted"] || seen["client-rating"] || seen["client-note"] {
		if *providerOnly {
			check(errors.New("sign receipt create: -provider-only cannot carry a client verdict"))
		}
		rec.ClientVerdict = &jobreceipt.ClientVerdict{
			Accepted: *accepted,
			Rating:   *rating,
			Note:     *note,
		}
	}

	if *workOrder != "" || *thread != "" {
		rec.Links = &jobreceipt.Links{WorkOrderID: *workOrder, ThreadSession: *thread}
	}

	body, err := rec.Encode()
	check(err)
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		check(err)
	}

	fmt.Printf("receipt     %s (%d bytes)\n", *out, len(body))
	fmt.Printf("receipt id  %s\n", jobreceipt.ID(body))
	fmt.Printf("protocol    %s v%d (%s)\n", rec.Protocol, rec.Version, rec.Kind)
	fmt.Printf("provider    %s\n", rec.Parties.ProviderPub)
	if rec.Parties.ClientPub != "" {
		fmt.Printf("client      %s\n", rec.Parties.ClientPub)
	} else {
		fmt.Printf("client      (none — coverage: %s, not a reputation entry)\n", rec.Coverage)
	}
	fmt.Printf("settlement  %d line(s)\n", len(rec.Settlement))
	fmt.Println()
	fmt.Printf("next: spore sign receipt sign -role provider -identity provider.key -file %s\n", *out)
	if rec.Parties.ClientPub != "" {
		fmt.Printf("      spore sign receipt sign -role client   -identity client.key   -file %s\n", *out)
	}
}

func receiptSign(args []string) {
	fs := flag.NewFlagSet("sign receipt sign", flag.ExitOnError)
	role := fs.String("role", "", "client|provider — selects the fixed statement (required)")
	identity := fs.String("identity", "", "file holding your identity private key hex (required)")
	file := fs.String("file", "", "the receipt record to sign (required)")
	out := fs.String("out", "", "write the signature here (default: FILE.ROLE.sig)")
	_ = fs.Parse(args)

	if *role != jobreceipt.RoleClient && *role != jobreceipt.RoleProvider {
		check(fmt.Errorf("sign receipt sign: -role must be %q or %q, got %q", jobreceipt.RoleClient, jobreceipt.RoleProvider, *role))
	}
	body, err := os.ReadFile(*file)
	check(err)
	rec, err := jobreceipt.Parse(body)
	check(err)

	// The statement is a protocol constant; the user picks a role, never wording.
	statement, err := jobreceipt.StatementFor(*role)
	check(err)
	wantPub, err := rec.PubFor(*role)
	check(err)

	key, err := identitySigKey(*identity)
	check(err)
	gotPub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if gotPub != wantPub {
		check(fmt.Errorf("sign receipt sign: this identity is %s, but the record's %s is %s — signing with the wrong key would produce a receipt nobody can attribute", gotPub, *role, wantPub))
	}

	sum := sha256.Sum256(body)
	env, err := attest.Sign(key, sum[:], int64(len(body)), statement, time.Now())
	check(err)

	dest := *out
	if dest == "" {
		dest = *file + "." + *role + ".sig"
	}
	blob, err := json.MarshalIndent(env, "", "  ")
	check(err)
	if err := os.WriteFile(dest, append(blob, '\n'), 0o600); err != nil {
		check(err)
	}

	fmt.Printf("signed      %s (%d bytes)\n", *file, len(body))
	fmt.Printf("role        %s\n", *role)
	fmt.Printf("signer      %s\n", gotPub)
	fmt.Printf("statement   %q\n", statement)
	fmt.Printf("sha256      %s\n", env.DocSHA256)
	fmt.Printf("wrote       %s\n", dest)
}

func receiptVerify(args []string) {
	fs := flag.NewFlagSet("sign receipt verify", flag.ExitOnError)
	file := fs.String("file", "", "the receipt record (required)")
	sigs := fs.String("sigs", "", "comma-separated signature files (required)")
	required := fs.String("required", "both", "both|client|provider")
	_ = fs.Parse(args)

	if *sigs == "" {
		check(errors.New("sign receipt verify: -sigs is required (comma-separated .sig files)"))
	}
	var need []string
	switch *required {
	case "both":
		need = []string{jobreceipt.RoleClient, jobreceipt.RoleProvider}
	case jobreceipt.RoleClient:
		need = []string{jobreceipt.RoleClient}
	case jobreceipt.RoleProvider:
		need = []string{jobreceipt.RoleProvider}
	default:
		check(fmt.Errorf("sign receipt verify: -required must be both|client|provider, got %q", *required))
	}

	body, err := os.ReadFile(*file)
	check(err)
	rec, err := jobreceipt.Parse(body)
	check(err)
	sum := sha256.Sum256(body)

	type signedRole struct {
		role      string
		signer    string
		statement string
	}
	var got []signedRole
	byRole := map[string]bool{}
	for _, path := range strings.Split(*sigs, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		raw, err := os.ReadFile(path)
		check(err)
		var env attest.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			check(fmt.Errorf("%s: not a signature envelope: %w", path, err))
		}
		role, err := rec.RoleOf(env.SignerPub)
		if err != nil {
			check(fmt.Errorf("%s: %w — only the record's own keys can sign it", path, err))
		}
		want, err := jobreceipt.StatementFor(role)
		check(err)
		// THE enforcement. A correct signature over a different assertion is not
		// this role's attestation, however valid the cryptography is.
		if env.Statement != want {
			check(fmt.Errorf("%s: statement is %q, but a %s signature must be %q — this signature asserts something else and does not execute the receipt", path, env.Statement, role, want))
		}
		if byRole[role] {
			check(fmt.Errorf("%s: the %s role is already signed; a receipt has at most one signature per party", path, role))
		}
		if err := env.Verify(sum[:]); err != nil {
			check(fmt.Errorf("%s: %w", path, err))
		}
		byRole[role] = true
		got = append(got, signedRole{role: role, signer: env.SignerPub, statement: env.Statement})
	}

	fmt.Printf("receipt     %s (%d bytes)\n", *file, len(body))
	fmt.Printf("receipt id  %s\n", jobreceipt.ID(body))
	fmt.Printf("signatures  %d valid\n", len(got))
	for _, s := range got {
		fmt.Printf("  OK  %-8s  %s  %q\n", s.role, s.signer, s.statement)
	}

	var missing []string
	for _, role := range need {
		if !byRole[role] {
			missing = append(missing, role)
		}
	}
	if len(missing) > 0 {
		fmt.Printf("\nINCOMPLETE: %d required signature(s) missing: %s\n", len(missing), strings.Join(missing, ", "))
		os.Exit(1)
	}
	if len(need) == 2 {
		fmt.Println("\nFULLY EXECUTED: both parties signed this receipt.")
		return
	}
	fmt.Printf("\nCOMPLETE for the %s role.\n", need[0])
}

// receiptList is a repeatable string flag.
type receiptList []string

func (l *receiptList) String() string { return strings.Join(*l, ";") }
func (l *receiptList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func receiptKV(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("want key=value pairs, got %q", part)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			return nil, fmt.Errorf("empty key in %q", part)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		out[k] = v
	}
	return out, nil
}

func receiptKeys(kv map[string]string, index int, kind string, names ...string) error {
	allowed := map[string]bool{}
	for _, n := range names {
		allowed[n] = true
		if kv[n] == "" {
			return fmt.Errorf("-%s #%d is missing %s=", kind, index+1, n)
		}
	}
	for k := range kv {
		if !allowed[k] {
			return fmt.Errorf("-%s #%d has unknown key %q (want %s)", kind, index+1, k, strings.Join(names, ", "))
		}
	}
	return nil
}
