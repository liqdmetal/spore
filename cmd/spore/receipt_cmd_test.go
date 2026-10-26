package main

// End-to-end tests for `spore sign receipt`: the emitter must reproduce the
// published vector byte for byte, and the command — not the caller — must own
// the role statements, the signing key, and the party list.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const receiptVectorPath = "../../docs/job-receipt-v1.vector.json"

// receiptSeedKeys writes the three fixed identity seeds used by these tests and
// by the published vector: 0x52… is the client, 0x63… the provider, 0x33… a
// stranger whose signature is valid but irrelevant.
// signerFor discovers a key's public half the way a user would: sign something
// and read the signer line, rather than importing key derivation into the test.
func signerFor(t *testing.T, bin, keyPath string) string {
	t.Helper()
	doc := filepath.Join(t.TempDir(), "who.txt")
	if err := os.WriteFile(doc, []byte("who am i\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runSpore(t, bin, "sign", "doc", "-identity", keyPath, "-file", doc,
		"-statement", "probe", "-out", doc+".sig")
	if err != nil {
		t.Fatalf("probe signer: %v\n%s", err, out)
	}
	return signerLine(t, out)
}

func receiptSeedKeys(t *testing.T) (client, provider, stranger string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, seed string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(strings.Repeat(seed, 32)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return write("client.key", "52"), write("provider.key", "63"), write("stranger.key", "33")
}

func TestReceiptCommand(t *testing.T) {
	bin := buildSporeBinary(t)
	clientKey, providerKey, strangerKey := receiptSeedKeys(t)

	vector, err := os.ReadFile(receiptVectorPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	clientPub := fixtureClientPub(t, vector)
	providerPub := fixtureProviderPub(t, vector)
	txSum := sha256.Sum256([]byte("spore job receipt v1 vector: settlement"))
	txid := fmt.Sprintf("%x", txSum)

	createArgs := func(out string) []string {
		return []string{"sign", "receipt", "create",
			"-out", out,
			"-service-category", "plumbing.emergency",
			"-service-summary", "Replace failed shutoff valve, kitchen line",
			"-provider-pub", providerPub,
			"-client-pub", clientPub,
			"-started-at", "2026-10-24T15:02:11Z",
			"-finished-at", "2026-10-24T16:41:52Z",
			"-settlement", "rail=dero,network=dero-mainnet,asset=dero,amount=2500000000000,txid=" + txid + ",settled=2026-10-24T16:44:03Z",
			"-deliverable", "label=before,digest=sha256:6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb,bytes=6",
			"-deliverable", "label=after,digest=sha256:f39592393ef0859cb196a52693d2cea00fb2df784b3c04ae54aa7cadb8e562f8,bytes=5",
			"-client-accepted", "-client-rating", "5",
		}
	}

	// One record, created once and reused: the subtests below then test what the
	// command refuses, which is where the enforcement lives.
	dir := t.TempDir()
	record := filepath.Join(dir, "job.json")
	out, err := runSpore(t, bin, createArgs(record)...)
	if err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}

	t.Run("create reproduces the published vector", func(t *testing.T) {
		got, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, vector) {
			t.Fatalf("create did not reproduce the vector:\n--- got ---\n%s\n--- want ---\n%s", got, vector)
		}
		wantID := fmt.Sprintf("%x", sha256.Sum256(vector))
		if !strings.Contains(out, wantID) {
			t.Errorf("create did not print the receipt id %s:\n%s", wantID, out)
		}
	})

	t.Run("create refuses a fractional amount", func(t *testing.T) {
		args := createArgs(filepath.Join(t.TempDir(), "bad.json"))
		for i, a := range args {
			if strings.Contains(a, "amount=2500000000000") {
				args[i] = strings.Replace(a, "amount=2500000000000", "amount=0.25", 1)
			}
		}
		badOut, err := runSpore(t, bin, args...)
		if err == nil {
			t.Fatalf("create accepted a fractional amount:\n%s", badOut)
		}
		if !strings.Contains(badOut, "amount_atomic") {
			t.Errorf("rejection did not name the field:\n%s", badOut)
		}
	})

	t.Run("sign refuses a key that is not that role's", func(t *testing.T) {
		badOut, err := runSpore(t, bin, "sign", "receipt", "sign",
			"-role", "client", "-identity", strangerKey, "-file", record,
			"-out", filepath.Join(dir, "stranger.sig"))
		if err == nil {
			t.Fatalf("signed as the client with a stranger key:\n%s", badOut)
		}
		if !strings.Contains(badOut, "this identity is") {
			t.Errorf("rejection did not explain the key mismatch:\n%s", badOut)
		}
	})

	t.Run("sign derives the statement from the role", func(t *testing.T) {
		for _, tc := range []struct{ role, key string }{{"provider", providerKey}, {"client", clientKey}} {
			sigPath := record + "." + tc.role + ".sig"
			sigOut, err := runSpore(t, bin, "sign", "receipt", "sign",
				"-role", tc.role, "-identity", tc.key, "-file", record, "-out", sigPath)
			if err != nil {
				t.Fatalf("sign as %s: %v\n%s", tc.role, err, sigOut)
			}
			want := "spore.job-receipt/v1 " + tc.role + " " + map[string]string{"client": "acceptance", "provider": "attestation"}[tc.role]
			if !strings.Contains(sigOut, want) {
				t.Errorf("%s signature does not carry %q:\n%s", tc.role, want, sigOut)
			}
		}
	})

	t.Run("verify reports a complete receipt", func(t *testing.T) {
		verifyOut, err := runSpore(t, bin, "sign", "receipt", "verify",
			"-file", record,
			"-sigs", record+".client.sig,"+record+".provider.sig")
		if err != nil {
			t.Fatalf("verify: %v\n%s", err, verifyOut)
		}
		for _, want := range []string{"signatures  2 valid", "FULLY EXECUTED", clientPub, providerPub} {
			if !strings.Contains(verifyOut, want) {
				t.Errorf("verify output missing %q:\n%s", want, verifyOut)
			}
		}
	})

	t.Run("verify rejects a signature asserting something else", func(t *testing.T) {
		// The same client key, the same bytes, a different assertion. This is the
		// case `sign sheet` cannot catch and `sign receipt verify` must.
		para := filepath.Join(t.TempDir(), "paraphrased.sig")
		paraOut, err := runSpore(t, bin, "sign", "doc", "-identity", clientKey,
			"-file", record, "-statement", "I accepted the work described above", "-out", para)
		if err != nil {
			t.Fatalf("sign doc: %v\n%s", err, paraOut)
		}
		verifyOut, err := runSpore(t, bin, "sign", "receipt", "verify",
			"-file", record, "-sigs", record+".provider.sig,"+para)
		if err == nil {
			t.Fatalf("verify accepted a paraphrased statement:\n%s", verifyOut)
		}
		if !strings.Contains(verifyOut, "must be \"spore.job-receipt/v1 client acceptance\"") {
			t.Errorf("rejection did not cite the role constant:\n%s", verifyOut)
		}
	})

	t.Run("verify rejects a key that is not a party", func(t *testing.T) {
		foreign := filepath.Join(t.TempDir(), "foreign.sig")
		foreignOut, err := runSpore(t, bin, "sign", "doc", "-identity", strangerKey,
			"-file", record, "-statement", "spore.job-receipt/v1 client acceptance", "-out", foreign)
		if err != nil {
			t.Fatalf("sign doc: %v\n%s", err, foreignOut)
		}
		verifyOut, err := runSpore(t, bin, "sign", "receipt", "verify",
			"-file", record, "-sigs", record+".provider.sig,"+foreign)
		if err == nil {
			t.Fatalf("verify accepted a non-party signer:\n%s", verifyOut)
		}
		if !strings.Contains(verifyOut, "is not a party to this record") {
			t.Errorf("rejection did not name the party rule:\n%s", verifyOut)
		}
	})

	t.Run("one signature is not a complete receipt", func(t *testing.T) {
		verifyOut, err := runSpore(t, bin, "sign", "receipt", "verify",
			"-file", record, "-sigs", record+".provider.sig")
		if err == nil {
			t.Fatalf("provider-only verification reported complete:\n%s", verifyOut)
		}
		if !strings.Contains(verifyOut, "INCOMPLETE") || !strings.Contains(verifyOut, "client") {
			t.Errorf("incomplete report did not name the missing role:\n%s", verifyOut)
		}
	})

	// No comma in this subtest name: t.TempDir() inherits it, and -sigs is a
	// comma-separated list (the same list syntax `sign sheet` uses).
	t.Run("spend receipt is blind and openable", func(t *testing.T) {
		spendDir := t.TempDir()
		rec := filepath.Join(spendDir, "spend.json")
		salt := filepath.Join(spendDir, "spend.salt")
		out, err := runSpore(t, bin, "sign", "receipt", "spend",
			"-out", rec, "-identity", clientKey,
			"-service-category", "plumbing.emergency",
			"-service-summary", "Replace failed shutoff valve",
			"-period-from", "2026-10-01T00:00:00Z", "-period-to", "2026-10-31T23:59:59Z",
			"-settlement", "rail=dero,network=dero-mainnet,asset=dero,amount=2500000000000,txid="+txid+",settled=2026-10-24T16:44:03Z",
			"-provider-pub", providerPub, "-salt-out", salt)
		if err != nil {
			t.Fatalf("spend: %v\n%s", err, out)
		}
		body, err := os.ReadFile(rec)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(providerPub)) {
			t.Fatalf("spend receipt names the provider's key:\n%s", body)
		}
		if strings.Contains(string(body), "parties") || strings.Contains(string(body), "client_verdict") {
			t.Fatalf("spend receipt carries attested-kind fields:\n%s", body)
		}
		if !strings.Contains(out, "evidence    chain-backed") {
			t.Errorf("a fully txid-backed row should derive chain-backed:\n%s", out)
		}

		verifyOut, err := runSpore(t, bin, "sign", "receipt", "verify",
			"-file", rec, "-sigs", rec+".sig", "-provider-pub", providerPub, "-salt", salt)
		if err != nil {
			t.Fatalf("verify spend: %v\n%s", err, verifyOut)
		}
		for _, want := range []string{"not named", "commitment  MATCH", "COMPLETE", "not a reputation entry"} {
			if !strings.Contains(verifyOut, want) {
				t.Errorf("verify output missing %q:\n%s", want, verifyOut)
			}
		}

		wrongSalt := filepath.Join(spendDir, "wrong.salt")
		if err := os.WriteFile(wrongSalt, []byte(strings.Repeat("00", 32)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		badOut, err := runSpore(t, bin, "sign", "receipt", "verify",
			"-file", rec, "-sigs", rec+".sig", "-provider-pub", providerPub, "-salt", wrongSalt)
		if err == nil {
			t.Fatalf("a wrong salt opened the commitment:\n%s", badOut)
		}
		if !strings.Contains(badOut, "does NOT open") {
			t.Errorf("mismatch was not explained:\n%s", badOut)
		}
	})

	t.Run("spend receipt without a txid is self-declared", func(t *testing.T) {
		rec := filepath.Join(t.TempDir(), "cash.json")
		out, err := runSpore(t, bin, "sign", "receipt", "spend",
			"-out", rec, "-identity", clientKey,
			"-service-category", "plumbing.emergency",
			"-service-summary", "cash callout",
			"-settlement", "rail=cash,network=none,asset=usd,amount=12000,settled=2026-10-24T16:44:03Z")
		if err != nil {
			t.Fatalf("spend: %v\n%s", err, out)
		}
		if !strings.Contains(out, "evidence    self-declared") {
			t.Errorf("a row without a txid should derive self-declared:\n%s", out)
		}
		body, err := os.ReadFile(rec)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("txid")) {
			t.Errorf("a self-declared row must omit the txid entirely:\n%s", body)
		}
	})

	t.Run("spend receipt is signed by the client alone", func(t *testing.T) {
		rec := filepath.Join(t.TempDir(), "spend.json")
		if out, err := runSpore(t, bin, "sign", "receipt", "spend",
			"-out", rec, "-identity", clientKey,
			"-service-category", "plumbing.emergency",
			"-service-summary", "cash callout",
			"-settlement", "rail=cash,network=none,asset=usd,amount=12000,settled=2026-10-24T16:44:03Z"); err != nil {
			t.Fatalf("spend: %v\n%s", err, out)
		}

		// A provider's signature, however valid, is not part of this document.
		providerSig := filepath.Join(t.TempDir(), "provider.sig")
		if out, err := runSpore(t, bin, "sign", "doc", "-identity", providerKey,
			"-file", rec, "-statement", "spore.spend-receipt/v1 client declaration", "-out", providerSig); err != nil {
			t.Fatalf("sign doc: %v\n%s", err, out)
		}
		badOut, err := runSpore(t, bin, "sign", "receipt", "verify", "-file", rec, "-sigs", providerSig)
		if err == nil {
			t.Fatalf("a provider signature completed a spend receipt:\n%s", badOut)
		}
		if !strings.Contains(badOut, "not the client key") {
			t.Errorf("rejection did not explain the signer rule:\n%s", badOut)
		}

		// And a client signature asserting something else is not a declaration.
		para := filepath.Join(t.TempDir(), "para.sig")
		if out, err := runSpore(t, bin, "sign", "doc", "-identity", clientKey,
			"-file", rec, "-statement", "I spent this", "-out", para); err != nil {
			t.Fatalf("sign doc: %v\n%s", err, out)
		}
		paraOut, err := runSpore(t, bin, "sign", "receipt", "verify", "-file", rec, "-sigs", para)
		if err == nil {
			t.Fatalf("verify accepted a paraphrased spend declaration:\n%s", paraOut)
		}
		if !strings.Contains(paraOut, "spore.spend-receipt/v1 client declaration") {
			t.Errorf("rejection did not cite the constant:\n%s", paraOut)
		}
	})

	t.Run("spend refuses a commitment without a salt", func(t *testing.T) {
		badOut, err := runSpore(t, bin, "sign", "receipt", "spend",
			"-out", filepath.Join(t.TempDir(), "x.json"), "-identity", clientKey,
			"-service-category", "plumbing.emergency", "-service-summary", "x",
			"-settlement", "rail=cash,network=none,asset=usd,amount=100,settled=2026-10-24T16:44:03Z",
			"-provider-pub", providerPub)
		if err == nil {
			t.Fatalf("emitted a commitment with no salt to open it:\n%s", badOut)
		}
		if !strings.Contains(badOut, "-salt-out") {
			t.Errorf("rejection did not name the missing flag:\n%s", badOut)
		}
	})

	t.Run("export writes sorted rows and skips non-spend files", func(t *testing.T) {
		expDir := t.TempDir()
		// Two settlements, deliberately given out of order, plus a self-declared
		// cash row and an attested receipt that must not become an expense row.
		if out, err := runSpore(t, bin, "sign", "receipt", "spend",
			"-out", filepath.Join(expDir, "oct.json"), "-identity", clientKey,
			"-service-category", "plumbing.emergency", "-service-summary", "Replace valve, kitchen line",
			"-period-from", "2026-10-01T00:00:00Z", "-period-to", "2026-10-31T23:59:59Z",
			"-settlement", "rail=dero,network=dero-mainnet,asset=dero,amount=2500000000000,txid="+txid+",settled=2026-10-24T16:44:03Z",
			"-settlement", "rail=dero,network=dero-mainnet,asset=dero,amount=100,txid="+txid+",settled=2026-10-02T09:00:00Z"); err != nil {
			t.Fatalf("spend: %v\n%s", err, out)
		}
		if out, err := runSpore(t, bin, "sign", "receipt", "spend",
			"-out", filepath.Join(expDir, "cash.json"), "-identity", clientKey,
			"-service-category", "auto.bodywork", "-service-summary", "cash callout, no chain",
			"-settlement", "rail=cash,network=none,asset=usd,amount=12000,settled=2026-10-05T11:00:00Z"); err != nil {
			t.Fatalf("spend: %v\n%s", err, out)
		}
		if err := os.WriteFile(filepath.Join(expDir, "attested.json"), vector, 0o600); err != nil {
			t.Fatal(err)
		}

		csvOut, err := runSpore(t, bin, "sign", "receipt", "export", "-dir", expDir)
		if err != nil {
			t.Fatalf("export: %v\n%s", err, csvOut)
		}
		lines := strings.Split(strings.TrimSpace(strings.SplitN(csvOut, "exported", 2)[0]), "\n")
		if len(lines) != 4 { // header + three rows
			t.Fatalf("expected header + 3 rows, got %d:\n%s", len(lines), csvOut)
		}
		if lines[0] != strings.Join([]string{"period_start", "period_end", "category", "summary", "rail", "network", "asset", "amount_atomic", "txid", "settlement_time", "evidence", "receipt_id"}, ",") {
			t.Errorf("header is not the §9 column order:\n%s", lines[0])
		}
		// Ascending settlement time, whatever order the files were written in.
		if !strings.Contains(lines[1], "2026-10-02T09:00:00Z") || !strings.Contains(lines[2], "2026-10-05T11:00:00Z") || !strings.Contains(lines[3], "2026-10-24T16:44:03Z") {
			t.Errorf("rows are not sorted by settlement time:\n%s", csvOut)
		}
		if !strings.Contains(lines[2], "self-declared") {
			t.Errorf("the cash row did not keep its per-row evidence:\n%s", lines[2])
		}
		if !strings.Contains(csvOut, "1 non-spend file(s) skipped") {
			t.Errorf("attested receipt was not reported as skipped:\n%s", csvOut)
		}

		// Two exports of the same directory must be identical, or last month
		// cannot be diffed against this one.
		first := filepath.Join(t.TempDir(), "a.csv")
		second := filepath.Join(t.TempDir(), "b.csv")
		if out, err := runSpore(t, bin, "sign", "receipt", "export", "-dir", expDir, "-out", first); err != nil {
			t.Fatalf("export -out: %v\n%s", err, out)
		}
		if out, err := runSpore(t, bin, "sign", "receipt", "export", "-dir", expDir, "-out", second); err != nil {
			t.Fatalf("export -out: %v\n%s", err, out)
		}
		a, err := os.ReadFile(first)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(second)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("two exports of one directory differ:\n%s\n---\n%s", a, b)
		}
	})

	t.Run("export refuses an unsigned declaration", func(t *testing.T) {
		bare := t.TempDir()
		if out, err := runSpore(t, bin, "sign", "receipt", "spend",
			"-out", filepath.Join(bare, "cash.json"), "-identity", clientKey,
			"-service-category", "auto.bodywork", "-service-summary", "cash callout",
			"-settlement", "rail=cash,network=none,asset=usd,amount=12000,settled=2026-10-05T11:00:00Z"); err != nil {
			t.Fatalf("spend: %v\n%s", err, out)
		}
		if err := os.Remove(filepath.Join(bare, "cash.json.sig")); err != nil {
			t.Fatal(err)
		}
		badOut, err := runSpore(t, bin, "sign", "receipt", "export", "-dir", bare)
		if err == nil {
			t.Fatalf("exported a declaration nobody signed:\n%s", badOut)
		}
		if !strings.Contains(badOut, "refusing to export") {
			t.Errorf("rejection did not explain itself:\n%s", badOut)
		}
		allowed, err := runSpore(t, bin, "sign", "receipt", "export", "-dir", bare, "-allow-unsigned")
		if err != nil {
			t.Fatalf("-allow-unsigned: %v\n%s", err, allowed)
		}
		if !strings.Contains(allowed, "WARNING") {
			t.Errorf("-allow-unsigned exported without a warning:\n%s", allowed)
		}
	})

	t.Run("tally counts pairs and skips what it cannot admit", func(t *testing.T) {
		// A pair counts once, so the two jobs from the same client must not move the
		// mean: the newer one (rating 3) is that client's contribution.
		strangerPub := signerFor(t, bin, strangerKey)
		tallyDir := t.TempDir()
		mk := func(name, keyPath, pub, finished string, rating int) {
			t.Helper()
			rec := filepath.Join(tallyDir, name+".json")
			if out, err := runSpore(t, bin, "sign", "receipt", "create",
				"-out", rec,
				"-service-category", "plumbing.emergency",
				"-service-summary", "job "+name,
				"-provider-pub", providerPub, "-client-pub", pub,
				"-started-at", finished, "-finished-at", finished,
				"-settlement", "rail=dero,network=dero-mainnet,asset=dero,amount=1000,txid="+txid+",settled="+finished,
				"-client-accepted", "-client-rating", fmt.Sprint(rating)); err != nil {
				t.Fatalf("create %s: %v\n%s", name, err, out)
			}
			for role, key := range map[string]string{"provider": providerKey, "client": keyPath} {
				if out, err := runSpore(t, bin, "sign", "receipt", "sign",
					"-role", role, "-identity", key, "-file", rec); err != nil {
					t.Fatalf("sign %s as %s: %v\n%s", name, role, err, out)
				}
			}
		}
		mk("job1", clientKey, clientPub, "2026-10-02T09:00:00Z", 5)
		mk("job2", clientKey, clientPub, "2026-10-20T09:00:00Z", 3)
		mk("job3", strangerKey, strangerPub, "2026-10-24T09:00:00Z", 4)

		// Not admissible: a spend receipt, and a job receipt with only one signer.
		if out, err := runSpore(t, bin, "sign", "receipt", "spend",
			"-out", filepath.Join(tallyDir, "cash.json"), "-identity", clientKey,
			"-service-category", "plumbing.emergency", "-service-summary", "cash",
			"-settlement", "rail=cash,network=none,asset=usd,amount=100,settled=2026-10-05T00:00:00Z"); err != nil {
			t.Fatalf("spend: %v\n%s", err, out)
		}
		half := filepath.Join(tallyDir, "half.json")
		if body, err := os.ReadFile(filepath.Join(tallyDir, "job1.json")); err != nil {
			t.Fatal(err)
		} else if err := os.WriteFile(half, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if sig, err := os.ReadFile(filepath.Join(tallyDir, "job1.json.client.sig")); err != nil {
			t.Fatal(err)
		} else if err := os.WriteFile(half+".client.sig", sig, 0o600); err != nil {
			t.Fatal(err)
		}

		out, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", tallyDir)
		if err != nil {
			t.Fatalf("tally: %v\n%s", err, out)
		}
		for _, want := range []string{
			"pairs       2 distinct client(s) from 3 record(s)",
			"mean 3.50 over 2 rated client(s) of 2 pair(s)",
			"2026-10-02T09:00:00Z .. 2026-10-24T09:00:00Z",
			"1 spend receipt",
			"1 missing a signature",
			"NOT chain-checked",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("tally output missing %q:\n%s", want, out)
			}
		}

		jsonOut, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", tallyDir, "-json")
		if err != nil {
			t.Fatalf("tally -json: %v\n%s", err, jsonOut)
		}
		var parsed struct {
			Tallies []struct {
				Pairs int     `json:"pairs"`
				Rated int     `json:"rated_pairs"`
				Mean  float64 `json:"mean"`
			} `json:"tallies"`
		}
		if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
			t.Fatalf("tally -json is not JSON: %v\n%s", err, jsonOut)
		}
		if len(parsed.Tallies) != 1 || parsed.Tallies[0].Pairs != 2 || parsed.Tallies[0].Rated != 2 || parsed.Tallies[0].Mean != 3.5 {
			t.Fatalf("tally JSON disagrees with the text:\n%s", jsonOut)
		}

		// A txid list the viewer actually checked is the only way to move from
		// "cited" to "confirmed", and a list that matches nothing admits nothing.
		wrongList := filepath.Join(t.TempDir(), "wrong.txt")
		if err := os.WriteFile(wrongList, []byte(strings.Repeat("0", 64)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		badOut, err := runSpore(t, bin, "sign", "receipt", "tally", "-dir", tallyDir, "-verified-txids", wrongList)
		if err == nil {
			t.Fatalf("tally admitted receipts citing an unlisted txid:\n%s", badOut)
		}
	})

	t.Run("provider-only record carries no client fields", func(t *testing.T) {
		rec := filepath.Join(t.TempDir(), "solo.json")
		createOut, err := runSpore(t, bin, "sign", "receipt", "create",
			"-out", rec,
			"-service-category", "plumbing.emergency",
			"-service-summary", "Replace failed shutoff valve, kitchen line",
			"-provider-pub", providerPub,
			"-provider-only",
			"-started-at", "2026-10-24T15:02:11Z",
			"-finished-at", "2026-10-24T16:41:52Z",
			"-settlement", "rail=dero,network=dero-mainnet,asset=dero,amount=2500000000000,txid="+txid+",settled=2026-10-24T16:44:03Z")
		if err != nil {
			t.Fatalf("create provider-only: %v\n%s", err, createOut)
		}
		body, err := os.ReadFile(rec)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("client_pub")) {
			t.Fatalf("provider-only record names a client key:\n%s", body)
		}
		if !strings.Contains(createOut, "not a reputation entry") {
			t.Errorf("create did not flag the record as non-reputation:\n%s", createOut)
		}
	})
}
