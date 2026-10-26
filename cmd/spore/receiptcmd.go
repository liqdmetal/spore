package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	case "spend":
		receiptSpend(args[1:])
	case "export":
		receiptExport(args[1:])
	case "verify":
		receiptVerify(args[1:])
	case "-h", "--help":
		receiptUsage()
	default:
		fmt.Fprintf(os.Stderr, "sign receipt: unknown subcommand %q (want create|sign|spend|export|verify)\n", args[0])
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

  spore sign receipt spend -out F -identity F -service-category C -service-summary S
        -settlement rail=dero,network=dero-mainnet,asset=dero,amount=2500000000000,settled=RFC3339[,txid=HEX]
        [-settlement ...] [-period-from RFC3339 -period-to RFC3339]
        [-provider-pub HEX -salt-out FILE] [-sig-out SIG]
        (emit AND sign the provider-blind accounting record; a line without a
         txid makes the whole record self-declared, not chain-backed)

  spore sign receipt export -dir D [-format csv|jsonl] [-out F] [-allow-unsigned]
        (§9 accounting rows: one per settlement line, evidence per row, sorted by
         settlement time then txid; every input must carry a valid signature
         unless -allow-unsigned is given)

  spore sign receipt verify -file F -sigs A.sig,B.sig [-required both|client|provider]
        (verify the signatures AND that each one carries its role's statement;
         a spend receipt is dispatched by its own protocol)

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
	commitPub := fs.String("provider-pub", "", "optional (spend only): open the commitment to this provider")
	commitSalt := fs.String("salt", "", "optional (spend only): the salt you kept")
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
	proto, err := jobreceipt.ProtocolOf(body)
	check(err)
	if proto == jobreceipt.SpendProtocol {
		receiptVerifySpend(body, *sigs, *required, *commitPub, *commitSalt)
		return
	}
	if *commitPub != "" || *commitSalt != "" {
		check(errors.New("sign receipt verify: -provider-pub/-salt only apply to a spend receipt (an attested one names the provider outright)"))
	}
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

// receiptSpend emits the client's own accounting record: no provider key, no
// provider name, and a commitment the client can open later if it needs to prove
// who the row was for. The signature is applied here rather than by a separate
// command because a spend receipt is unilateral by definition — there is no
// second party to hand it to.
func receiptSpend(args []string) {
	fs := flag.NewFlagSet("sign receipt spend", flag.ExitOnError)
	out := fs.String("out", "", "write the canonical spend receipt here (required)")
	identity := fs.String("identity", "", "file holding the client's identity private key hex (required)")
	category := fs.String("service-category", "", "e.g. plumbing.emergency (required)")
	summary := fs.String("service-summary", "", "one line of what the money was for (required)")
	from := fs.String("period-from", "", "optional RFC 3339 UTC start of the period this row falls in")
	to := fs.String("period-to", "", "optional RFC 3339 UTC end of the period")
	var settlements receiptList
	fs.Var(&settlements, "settlement", "rail=…,network=…,asset=…,amount=…,settled=RFC3339[,txid=…] (repeatable)")
	providerPub := fs.String("provider-pub", "", "optional: blind commitment to this provider (requires -salt-out)")
	saltOut := fs.String("salt-out", "", "where to keep the 32-byte commitment salt; required with -provider-pub")
	sigOut := fs.String("sig-out", "", "where to write the signature (default: OUT.sig)")
	_ = fs.Parse(args)

	if *out == "" {
		check(errors.New("sign receipt spend: -out is required"))
	}
	if (*from == "") != (*to == "") {
		check(errors.New("sign receipt spend: -period-from and -period-to go together"))
	}
	if *providerPub != "" && *saltOut == "" {
		check(errors.New("sign receipt spend: -provider-pub needs -salt-out — the salt is the only way to open the commitment later, and keeping it in this file would defeat the blindness"))
	}
	if *providerPub == "" && *saltOut != "" {
		check(errors.New("sign receipt spend: -salt-out only makes sense with -provider-pub"))
	}

	key, err := identitySigKey(*identity)
	check(err)
	clientPub := hex.EncodeToString(key.Public().(ed25519.PublicKey))

	rec := &jobreceipt.SpendRecord{
		Protocol:  jobreceipt.SpendProtocol,
		Version:   jobreceipt.Version,
		Kind:      jobreceipt.KindSpend,
		ClientPub: clientPub,
		Service: jobreceipt.Service{
			Category: *category,
			Summary:  *summary,
		},
	}
	if *from != "" {
		rec.Period = &jobreceipt.Period{From: *from, To: *to}
	}

	for i, spec := range settlements {
		kv, err := receiptKV(spec)
		if err != nil {
			check(fmt.Errorf("sign receipt spend: -settlement #%d: %w", i+1, err))
		}
		allowed := map[string]bool{"rail": true, "network": true, "asset": true, "amount": true, "settled": true, "txid": true}
		for k := range kv {
			if !allowed[k] {
				check(fmt.Errorf("sign receipt spend: -settlement #%d has unknown key %q (want rail, network, asset, amount, settled, and optional txid)", i+1, k))
			}
		}
		for _, name := range []string{"rail", "network", "asset", "amount", "settled"} {
			if kv[name] == "" {
				check(fmt.Errorf("sign receipt spend: -settlement #%d is missing %s=", i+1, name))
			}
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

	// Derived, never asserted: a row without a txid is the client's word, and the
	// record has to say so rather than let a caller claim otherwise.
	rec.Evidence = jobreceipt.DeriveEvidence(rec.Settlement)

	var saltHex string
	if *providerPub != "" {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			check(fmt.Errorf("sign receipt spend: generate salt: %w", err))
		}
		value, err := jobreceipt.CommitmentFor(*providerPub, salt)
		check(err)
		rec.ProviderCommitment = &jobreceipt.ProviderCommitment{
			Scheme: jobreceipt.CommitmentScheme,
			Value:  value,
		}
		saltHex = hex.EncodeToString(salt)
		// Written before the record, so a receipt that exists always has a salt.
		if err := os.WriteFile(*saltOut, []byte(saltHex+"\n"), 0o600); err != nil {
			check(fmt.Errorf("sign receipt spend: write salt: %w", err))
		}
	}

	body, err := rec.Encode()
	check(err)
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		check(err)
	}

	sum := sha256.Sum256(body)
	env, err := attest.Sign(key, sum[:], int64(len(body)), jobreceipt.SpendStatement, time.Now())
	check(err)
	dest := *sigOut
	if dest == "" {
		dest = *out + ".sig"
	}
	blob, err := json.MarshalIndent(env, "", "  ")
	check(err)
	if err := os.WriteFile(dest, append(blob, '\n'), 0o600); err != nil {
		check(err)
	}

	txids := 0
	for _, s := range rec.Settlement {
		if s.TxID != "" {
			txids++
		}
	}
	fmt.Printf("receipt     %s (%d bytes)\n", *out, len(body))
	fmt.Printf("receipt id  %s\n", jobreceipt.ID(body))
	fmt.Printf("client      %s\n", clientPub)
	fmt.Printf("provider    not named\n")
	fmt.Printf("settlement  %d line(s), %d with a txid\n", len(rec.Settlement), txids)
	fmt.Printf("evidence    %s\n", rec.Evidence)
	if rec.ProviderCommitment != nil {
		fmt.Printf("commitment  %s (scheme %s)\n", rec.ProviderCommitment.Value, rec.ProviderCommitment.Scheme)
		fmt.Printf("salt        %s — keep this AWAY from the receipt: together they are the link\n", *saltOut)
	}
	fmt.Printf("statement   %q\n", jobreceipt.SpendStatement)
	fmt.Printf("wrote       %s and %s\n", *out, dest)
	fmt.Println()
	if rec.Evidence == jobreceipt.EvidenceSelf {
		fmt.Println("note: at least one line has no txid, so this whole record is self-declared —")
		fmt.Println("      an export must print it that way and must not present it as chain-verified.")
	}
}

// receiptExport turns a directory of spend receipts into §9 rows. It refuses to
// export a declaration it cannot verify unless told otherwise, because an export
// is what an accountant treats as fact — a missing signature is not a detail to
// discover later.
func receiptExport(args []string) {
	fs := flag.NewFlagSet("sign receipt export", flag.ExitOnError)
	dir := fs.String("dir", "", "directory holding spend receipts (required)")
	format := fs.String("format", "csv", "csv|jsonl")
	out := fs.String("out", "", "write here instead of stdout")
	allowUnsigned := fs.Bool("allow-unsigned", false, "include declarations with no .sig beside them (never use this for a verified export)")
	_ = fs.Parse(args)

	if *dir == "" {
		check(errors.New("sign receipt export: -dir is required"))
	}
	if *format != "csv" && *format != "jsonl" {
		check(fmt.Errorf("sign receipt export: -format must be csv or jsonl, got %q", *format))
	}

	entries, err := os.ReadDir(*dir)
	check(err)

	var rows []jobreceipt.ExportRow
	signed, unsigned, records, skipped := 0, 0, 0, 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(*dir, entry.Name())
		body, err := os.ReadFile(path)
		check(err)
		proto, err := jobreceipt.ProtocolOf(body)
		if err != nil {
			check(fmt.Errorf("%s: %w", path, err))
		}
		if proto != jobreceipt.SpendProtocol {
			// An attested receipt is evidence of work, not an expense row, and its
			// amounts are the provider's copy of the same money.
			skipped++
			continue
		}
		rec, err := jobreceipt.ParseSpend(body)
		if err != nil {
			check(fmt.Errorf("%s: %w", path, err))
		}
		sigPath := path + ".sig"
		if _, statErr := os.Stat(sigPath); statErr == nil {
			if _, err := checkSpendEnvelope(body, rec, sigPath); err != nil {
				check(err)
			}
			signed++
		} else if *allowUnsigned {
			unsigned++
		} else {
			check(fmt.Errorf("%s: no signature at %s — refusing to export a declaration nobody verified (pass -allow-unsigned to include it anyway)", path, sigPath))
		}
		records++
		rows = append(rows, jobreceipt.RowsFromSpend(rec, jobreceipt.ID(body))...)
	}

	jobreceipt.SortRows(rows)

	var buf bytes.Buffer
	if *format == "csv" {
		w := csv.NewWriter(&buf)
		if err := w.Write(jobreceipt.ExportColumns); err != nil {
			check(err)
		}
		for _, row := range rows {
			if err := w.Write(row.Fields()); err != nil {
				check(err)
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			check(err)
		}
	} else {
		for _, row := range rows {
			line, err := exportJSONLine(row)
			if err != nil {
				check(err)
			}
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}

	if *out == "" {
		_, err := os.Stdout.Write(buf.Bytes())
		check(err)
	} else {
		if err := os.WriteFile(*out, buf.Bytes(), 0o600); err != nil {
			check(err)
		}
	}

	fmt.Fprintf(os.Stderr, "exported %d row(s) from %d spend receipt(s): %d signed, %d unsigned, %d non-spend file(s) skipped\n",
		len(rows), records, signed, unsigned, skipped)
	if unsigned > 0 {
		fmt.Fprintln(os.Stderr, "WARNING: rows from unsigned declarations are not verified by anyone; treat them as the client's word")
	}
}

// exportJSONLine writes one row as a JSON object with the §9 column order (a
// map would sort keys, csv order would be lost).
func exportJSONLine(row jobreceipt.ExportRow) (string, error) {
	values := row.Fields()
	var b strings.Builder
	b.WriteByte('{')
	for i, name := range jobreceipt.ExportColumns {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(name)
		if err != nil {
			return "", err
		}
		val, err := json.Marshal(values[i])
		if err != nil {
			return "", err
		}
		b.Write(key)
		b.WriteByte(':')
		b.Write(val)
	}
	b.WriteByte('}')
	return b.String(), nil
}

// checkSpendEnvelope is the single rule for "is this the client's declaration":
// the right key, the right statement, a valid signature over these exact bytes.
func checkSpendEnvelope(body []byte, rec *jobreceipt.SpendRecord, path string) (*attest.Envelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env attest.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s: not a signature envelope: %w", path, err)
	}
	if env.SignerPub != rec.ClientPub {
		return nil, fmt.Errorf("%s: %s is not the client key on this spend receipt (%s) — a spend receipt is signed by the client alone", path, env.SignerPub, rec.ClientPub)
	}
	if env.Statement != jobreceipt.SpendStatement {
		return nil, fmt.Errorf("%s: statement is %q, but a spend declaration must be %q", path, env.Statement, jobreceipt.SpendStatement)
	}
	sum := sha256.Sum256(body)
	if err := env.Verify(sum[:]); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &env, nil
}

// receiptVerifySpend checks the only signature a spend receipt can have. The
// statement comparison is the same rule as the attested kind: the client's key
// over these bytes is not enough if it declared something else.
func receiptVerifySpend(body []byte, sigs, required, providerPub, saltPath string) {
	rec, err := jobreceipt.ParseSpend(body)
	check(err)
	if required == jobreceipt.RoleProvider {
		check(errors.New("sign receipt verify: a spend receipt has no provider signature; the client signs it alone"))
	}
	signed := ""
	for _, path := range strings.Split(sigs, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if signed != "" {
			check(fmt.Errorf("%s: the client already signed this receipt; a spend receipt carries one signature", path))
		}
		env, err := checkSpendEnvelope(body, rec, path)
		check(err)
		signed = env.SignerPub
	}

	fmt.Printf("receipt     spend receipt (%d bytes)\n", len(body))
	fmt.Printf("receipt id  %s\n", jobreceipt.ID(body))
	fmt.Printf("client      %s\n", rec.ClientPub)
	fmt.Printf("provider    not named (commitment: %s)\n", map[bool]string{true: "present, unopened", false: "none"}[rec.ProviderCommitment != nil])
	fmt.Printf("settlement  %d line(s)\n", len(rec.Settlement))
	fmt.Printf("evidence    %s\n", rec.Evidence)

	// Opening the commitment is the only thing the salt is for, so the verifier
	// is where it belongs: a client claiming "this row was for provider X" has to
	// produce a salt that actually hashes to the committed value.
	if providerPub != "" || saltPath != "" {
		if providerPub == "" || saltPath == "" {
			check(errors.New("sign receipt verify: opening a commitment needs both -provider-pub and -salt"))
		}
		if rec.ProviderCommitment == nil {
			check(errors.New("sign receipt verify: this receipt carries no provider_commitment to open"))
		}
		rawSalt, err := os.ReadFile(saltPath)
		check(err)
		salt, err := hex.DecodeString(strings.TrimSpace(string(rawSalt)))
		if err != nil || len(salt) != 32 {
			check(fmt.Errorf("sign receipt verify: %s is not a 32-byte hex salt", saltPath))
		}
		ok, err := jobreceipt.OpensCommitment(providerPub, salt, rec.ProviderCommitment.Value)
		check(err)
		if !ok {
			check(errors.New("sign receipt verify: the salt does NOT open this commitment to that provider — either the wrong salt, or the row was for someone else"))
		}
		fmt.Printf("commitment  MATCH: opens to %s\n", providerPub)
	}

	if signed == "" {
		fmt.Println("\nINCOMPLETE: the client has not signed this declaration.")
		os.Exit(1)
	}
	fmt.Printf("signatures  1 valid\n  OK  client    %s  %q\n", signed, jobreceipt.SpendStatement)
	fmt.Println("\nCOMPLETE: the client signed this declaration. It is not a reputation entry —")
	fmt.Println("nobody co-signed it, so it says what the client says it paid.")
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
