package main

import (
	"bytes"
	"context"
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
	"github.com/liqdmetal/spore/internal/xmr"
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
	case "tally":
		receiptTally(args[1:])
	case "verify":
		receiptVerify(args[1:])
	case "-h", "--help":
		receiptUsage()
	default:
		fmt.Fprintf(os.Stderr, "sign receipt: unknown subcommand %q (want create|sign|spend|export|tally|verify)\n", args[0])
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
        [-txproof txid=HEX,address=ADDR,signature=SIG[,scheme=monero-tx-proof-v1]]
        (emit the canonical record; the file's SHA-256 is its receipt id. A
         -txproof attaches the chain's OWN evidence to the settlement line that
         cites that txid, and create — not you — binds it to this record)

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

  spore sign receipt tally -dir D [-provider-pub HEX] [-json]
        [-verified-txids FILE | -proofs -rpc URL [-rpc-login u:p]]
        (§8 view: dual-signed receipts only, one count per client/provider PAIR,
         mean over rated pairs with the rated-client count, oldest and newest
         shown, no weighting of any kind. -proofs verifies each line's tx proof
         in the wallet that holds the payment, so the evidence is CHECKED rather
         than a txid list you built by hand)

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
	var txProofs receiptList
	fs.Var(&txProofs, "txproof", "txid=…,address=…,signature=…[,scheme=monero-tx-proof-v1] (repeatable; the chain's own evidence, bound to THIS record)")
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

	// Proofs are attached last, and the message is computed HERE rather than
	// taken from the caller. A proof is only evidence if it is about this
	// record, and a caller who could name the message could bind a real chain
	// proof to a receipt it does not describe (jobreceipt.ProofMessage).
	if len(txProofs) > 0 {
		binding, err := jobreceipt.ProofMessage(rec)
		check(err)
		for i, spec := range txProofs {
			kv, err := receiptKV(spec)
			if err != nil {
				check(fmt.Errorf("sign receipt create: -txproof #%d: %w", i+1, err))
			}
			for k := range kv {
				switch k {
				case "txid", "address", "signature", "scheme":
				default:
					check(fmt.Errorf("sign receipt create: -txproof #%d has unknown key %q (want txid, address, signature, scheme)", i+1, k))
				}
			}
			for _, k := range []string{"txid", "address", "signature"} {
				if kv[k] == "" {
					check(fmt.Errorf("sign receipt create: -txproof #%d is missing %s=", i+1, k))
				}
			}
			scheme := kv["scheme"]
			if scheme == "" {
				scheme = jobreceipt.SchemeMoneroTxProofV1
			}
			at := -1
			for j := range rec.Settlement {
				if rec.Settlement[j].TxID == kv["txid"] {
					if at >= 0 {
						check(fmt.Errorf("sign receipt create: -txproof #%d cites txid %s, which two settlement lines claim", i+1, kv["txid"]))
					}
					at = j
				}
			}
			if at < 0 {
				check(fmt.Errorf("sign receipt create: -txproof #%d cites txid %s, which no -settlement line carries — a proof answers for a payment this record already claims", i+1, kv["txid"]))
			}
			if rec.Settlement[at].TxProof != nil {
				check(fmt.Errorf("sign receipt create: -txproof #%d is a second proof for the same settlement line", i+1))
			}
			rec.Settlement[at].TxProof = &jobreceipt.TxProof{
				Scheme:    scheme,
				Address:   kv["address"],
				Message:   binding,
				Signature: kv["signature"],
			}
		}
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
	proofs := 0
	for _, s := range rec.Settlement {
		if s.TxProof != nil {
			proofs++
		}
	}
	if proofs > 0 {
		fmt.Printf("tx proofs   %d settlement line(s) carry the chain's own evidence, bound to this record\n", proofs)
	} else if receiptHasXMRLine(rec) {
		// The binding must be known BEFORE the final record exists, because
		// attaching a proof changes the file. So it is printed here: this is the
		// exact message the wallet has to sign.
		if binding, err := jobreceipt.ProofMessage(rec); err == nil {
			fmt.Printf("tx proof    none attached: the chain's evidence is optional and §7 keeps its\n")
			fmt.Printf("            caveat without it. To embed it, ask the receiving wallet for\n")
			fmt.Printf("            get_tx_proof with this message, then re-run create with\n")
			fmt.Printf("            -txproof txid=…,address=…,signature=…\n")
			fmt.Printf("            message:  %s\n", binding)
		}
	}
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

// receiptTally applies §8 to a directory of job receipts. The rules are strict
// on purpose: only dual-signed records count, a pair counts once, and the mean is
// shown next to the number of clients it came from. There is deliberately no
// weight, decay or recency flag — every such knob is a lever to sell placement.
func receiptTally(args []string) {
	fs := flag.NewFlagSet("sign receipt tally", flag.ExitOnError)
	dir := fs.String("dir", "", "directory holding job receipts (required)")
	providerFilter := fs.String("provider-pub", "", "only this provider (exit 1 when it has no admissible receipt)")
	verifiedTxids := fs.String("verified-txids", "", "file of txids YOU confirmed on-chain; only receipts citing one count")
	proofs := fs.Bool("proofs", false, "require a chain tx proof on every settlement line and VERIFY it in a wallet (needs -rpc), instead of trusting a txid list")
	rpcURL := fs.String("rpc", "", "with -proofs: the wallet RPC holding the payments, e.g. http://127.0.0.1:18083/json_rpc")
	rpcLogin := fs.String("rpc-login", "", "with -proofs: wallet RPC credential user:pass (Digest on Monero)")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)

	if *dir == "" {
		check(errors.New("sign receipt tally: -dir is required"))
	}
	if *proofs && *verifiedTxids != "" {
		check(errors.New("sign receipt tally: -proofs and -verified-txids are two answers to the same question; pass one"))
	}
	if *proofs && *rpcURL == "" {
		check(errors.New("sign receipt tally: -proofs needs -rpc: a tx proof is verified by a wallet that holds the payment (docs/MONERO_SETTLEMENT.md §4), and spore queries no chain of its own"))
	}

	verified := map[string]bool{}
	haveList := *verifiedTxids != ""
	if haveList {
		raw, err := os.ReadFile(*verifiedTxids)
		check(err)
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			verified[strings.ToLower(line)] = true
		}
		if len(verified) == 0 {
			check(fmt.Errorf("sign receipt tally: %s lists no txids", *verifiedTxids))
		}
	}

	entries, err := os.ReadDir(*dir)
	check(err)

	var admitted []jobreceipt.TallyEntry
	skipOrder := []string{"spend receipt", "not a receipt", "provider-only", "missing a signature", "no txid",
		"no tx proof", "proof rejected by the wallet", "proof did not verify", "proof amount mismatch"}
	skips := map[string]int{}
	proofLines := 0
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
		if proto == jobreceipt.SpendProtocol {
			skips["spend receipt"]++ // §8: never merged into reputation
			continue
		}
		if proto != jobreceipt.Protocol {
			skips["not a receipt"]++
			continue
		}
		rec, err := jobreceipt.Parse(body)
		if err != nil {
			check(fmt.Errorf("%s: %w", path, err))
		}
		if rec.Coverage == jobreceipt.CoverageProviderOnly {
			skips["provider-only"]++
			continue
		}

		clientSig := path + ".client.sig"
		providerSig := path + ".provider.sig"
		if _, err := os.Stat(clientSig); err != nil {
			skips["missing a signature"]++
			continue
		}
		if _, err := os.Stat(providerSig); err != nil {
			skips["missing a signature"]++
			continue
		}
		for role, sigPath := range map[string]string{jobreceipt.RoleClient: clientSig, jobreceipt.RoleProvider: providerSig} {
			if _, err := checkJobEnvelope(body, rec, sigPath, role); err != nil {
				check(err)
			}
		}

		if *proofs {
			n, bucket, err := verifyTxProofs(rec, *rpcURL, *rpcLogin)
			if err != nil {
				// Could not ask is not an answer: a wallet nobody can reach
				// leaves every receipt unchecked, and counting them anyway — or
				// reporting zero — would be the same lie in two directions.
				check(fmt.Errorf("%s: %w", path, err))
			}
			if bucket != "" {
				skips[bucket]++
				continue
			}
			proofLines += n
		} else {
			paid := false
			for _, s := range rec.Settlement {
				if s.TxID == "" {
					continue
				}
				if !haveList || verified[strings.ToLower(s.TxID)] {
					paid = true
					break
				}
			}
			if !paid {
				skips["no txid"]++
				continue
			}
		}

		admitted = append(admitted, jobreceipt.TallyEntry{Record: rec, ReceiptID: jobreceipt.ID(body)})
	}

	tallies := jobreceipt.TallyEntries(admitted)
	if *providerFilter != "" {
		filtered := tallies[:0:0]
		for _, t := range tallies {
			if t.ProviderPub == *providerFilter {
				filtered = append(filtered, t)
			}
		}
		tallies = filtered
		if len(tallies) == 0 {
			fmt.Fprintf(os.Stderr, "sign receipt tally: no admissible receipt for provider %s in %s — %s\n",
				*providerFilter, *dir, describeSkips(skipOrder, skips))
			os.Exit(1)
		}
	}

	if *jsonOut {
		type jsonTally struct {
			ProviderPub   string  `json:"provider_pub"`
			Records       int     `json:"records"`
			Pairs         int     `json:"pairs"`
			Rated         int     `json:"rated_pairs"`
			Mean          float64 `json:"mean"`
			Oldest        string  `json:"oldest"`
			Newest        string  `json:"newest"`
			OldestReceipt string  `json:"oldest_receipt"`
			NewestReceipt string  `json:"newest_receipt"`
		}
		payment := paymentCheckLabel(*proofs, haveList, proofLines)
		out := struct {
			Tallies []jsonTally    `json:"tallies"`
			Skipped map[string]int `json:"skipped"`
			Payment string         `json:"payment"`
		}{Skipped: skips, Payment: payment}
		for _, t := range tallies {
			out.Tallies = append(out.Tallies, jsonTally{
				ProviderPub: t.ProviderPub, Records: t.Records, Pairs: t.Pairs,
				Rated: t.Rated, Mean: t.Mean,
				Oldest: t.Oldest, Newest: t.Newest,
				OldestReceipt: t.OldestReceipt, NewestReceipt: t.NewestReceipt,
			})
		}
		blob, err := json.MarshalIndent(out, "", "  ")
		check(err)
		fmt.Println(string(blob))
		return
	}

	if len(tallies) == 0 {
		// Nothing counts: say why, and exit non-zero so a script asking "how does
		// this provider stand" cannot read silence as a result. The JSON form above
		// stays exit 0 — there, an empty array is a valid answer.
		fmt.Fprintf(os.Stderr, "no admissible receipt in %s — %s\n", *dir, describeSkips(skipOrder, skips))
		os.Exit(1)
	}
	for i, t := range tallies {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("provider    %s\n", t.ProviderPub)
		fmt.Printf("pairs       %d distinct client(s) from %d record(s)\n", t.Pairs, t.Records)
		if t.Rated == 0 {
			fmt.Printf("rating      no ratings (%d pair(s) counted anyway)\n", t.Pairs)
		} else {
			fmt.Printf("rating      mean %.2f over %d rated client(s) of %d pair(s)\n", t.Mean, t.Rated, t.Pairs)
		}
		fmt.Printf("window      %s .. %s\n", t.Oldest, t.Newest)
		if *proofs {
			fmt.Printf("payment     every settlement line's tx proof verified in the wallet (%d line(s): good, and received == amount_atomic)\n", proofLines)
		} else if haveList {
			fmt.Printf("payment     every pair cites a txid you listed as confirmed\n")
		} else {
			fmt.Printf("payment     cites at least one txid; NOT chain-checked (pass -verified-txids or -proofs to require evidence)\n")
		}
	}
	if len(skips) > 0 {
		fmt.Printf("\nnot counted: %s\n", describeSkips(skipOrder, skips))
	}
	fmt.Println("\none receipt per client counts; there is no weighting, decay or promoted tier.")
	fmt.Println("each counted pair cost a real payment and a distinct key — a price, not a proof.")
}

// verifyTxProofs checks one receipt's proof blocks in a wallet, line by line,
// and reports how many verified. A non-empty bucket names the reason the
// receipt does not count; a non-nil error means the check could not be performed
// at all, which is not the same answer as a failed proof and must not be
// reported as one.
//
// The rules are §7's, made concrete. A proof must verify (good), and what the
// chain says was received must equal the amount_atomic the record claims: a
// valid proof for a different sum is evidence of a DIFFERENT payment, which is
// exactly the substitution this check exists to catch. Note the check is one
// wallet's answer, so a receipt whose payment that wallet never saw cannot be
// counted here — the wallet must hold the payment (docs/MONERO_SETTLEMENT.md §4).
func verifyTxProofs(rec *jobreceipt.Record, rpcURL, login string) (int, string, error) {
	checked := 0
	for _, s := range rec.Settlement {
		p := s.TxProof
		if p == nil {
			return 0, "no tx proof", nil
		}
		amount, err := strconv.ParseUint(s.AmountAtomic, 10, 64)
		if err != nil {
			return 0, "proof amount mismatch", nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		chk, err := xmr.CheckTxProof(ctx, rpcURL, login, s.TxID, p.Address, p.Message, p.Signature)
		cancel()
		if err != nil {
			if errors.Is(err, xmr.ErrProofRejected) {
				return 0, "proof rejected by the wallet", nil
			}
			return 0, "", err
		}
		if !chk.Good {
			return 0, "proof did not verify", nil
		}
		if chk.Received != amount {
			return 0, "proof amount mismatch", nil
		}
		checked++
	}
	return checked, "", nil
}

// paymentCheckLabel names, for machine readers, what the payment column meant.
func paymentCheckLabel(proofs, haveList bool, proofLines int) string {
	switch {
	case proofs:
		return fmt.Sprintf("chain-proofs-verified-in-wallet:%d", proofLines)
	case haveList:
		return "txids-listed-by-viewer"
	}
	return "unchecked-cites-txid"
}

// receiptHasXMRLine reports whether a record settles on the one rail that can
// produce a tx proof today, so the create hint is printed where it can be acted
// on rather than on every DERO receipt.
func receiptHasXMRLine(rec *jobreceipt.Record) bool {
	rail, ok := jobreceipt.SchemeRail(jobreceipt.SchemeMoneroTxProofV1)
	if !ok {
		return false
	}
	for _, s := range rec.Settlement {
		if s.Rail == rail {
			return true
		}
	}
	return false
}

func describeSkips(order []string, skips map[string]int) string {
	var parts []string
	for _, name := range order {
		if n := skips[name]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, name))
		}
	}
	if len(parts) == 0 {
		return "nothing skipped"
	}
	return strings.Join(parts, ", ")
}

// checkJobEnvelope is the attested-receipt rule shared by verify and tally: the
// signer must hold the role the file claims, must have asserted that role's
// constant, and the signature must cover these bytes.
func checkJobEnvelope(body []byte, rec *jobreceipt.Record, path, wantRole string) (*attest.Envelope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env attest.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s: not a signature envelope: %w", path, err)
	}
	role, err := rec.RoleOf(env.SignerPub)
	if err != nil {
		return nil, fmt.Errorf("%s: %w — only the record's own keys can sign it", path, err)
	}
	if role != wantRole {
		return nil, fmt.Errorf("%s: signed by the %s key, but this file is the %s signature", path, role, wantRole)
	}
	want, err := jobreceipt.StatementFor(role)
	if err != nil {
		return nil, err
	}
	if env.Statement != want {
		return nil, fmt.Errorf("%s: statement is %q, but a %s signature must be %q", path, env.Statement, role, want)
	}
	sum := sha256.Sum256(body)
	if err := env.Verify(sum[:]); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &env, nil
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
