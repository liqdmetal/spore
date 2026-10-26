package main

// Proves the receipt format in docs/JOB_RECEIPT_V1.md is EXECUTABLE with the
// shipped sign surface, using the cross-implementation vector in
// docs/job-receipt-v1.vector.json: the file is already canonical, both role
// constants sign the same bytes, `sign sheet -required` reports a complete
// receipt, and every way a receipt can lie is caught.
//
// It also pins a gap the spec has to own. `spore sign sheet` verifies each
// envelope against the statement stored IN that envelope, so a signature with a
// paraphrased statement still counts as a valid signature by the right key.
// Nothing in the CLI compares that statement to the role constant — that check
// is the verifier's, which is why §3 fixes the constants and why the subtest
// below asserts both halves: the sheet accepts it, and a role check rejects it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	jobReceiptVector = "../../docs/job-receipt-v1.vector.json"

	// The statements are part of the signed transcript, so they are protocol
	// constants, not free text. Changing either invalidates every receipt.
	jobReceiptClientStatement   = "spore.job-receipt/v1 client acceptance"
	jobReceiptProviderStatement = "spore.job-receipt/v1 provider attestation"
)

func runSpore(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// canonicalJSON re-emits a document the way §2 defines it: sorted keys, two
// space indent, "\n" line endings, one trailing newline, numbers preserved as
// their original literal. encoding/json sorts map keys and writes no HTML
// escapes once told not to, so this is the reference printer for the format.
func canonicalJSON(t *testing.T, body []byte) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("vector is not valid JSON: %v", err)
	}
	if dec.More() {
		t.Fatal("vector has trailing data after the record object")
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatalf("re-encode vector: %v", err)
	}
	return out.Bytes()
}

// assertNoFloatNumbers walks the decoded record: §2 forbids floating point
// anywhere, and a money field that arrives as a float is a rounding bug waiting
// for a total.
func assertNoFloatNumbers(t *testing.T, v any, path string) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			assertNoFloatNumbers(t, vv, path+"."+k)
		}
	case []any:
		for i, vv := range x {
			assertNoFloatNumbers(t, vv, fmt.Sprintf("%s[%d]", path, i))
		}
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			t.Errorf("float at %s = %s (money and counts are integer strings)", path, x)
		}
	}
}

// reverseKeyedJSON re-serializes the TOP level object with its keys in reverse
// order, so re-canonicalizing it proves the printer sorts rather than preserving
// whatever order the file happened to use.
func reverseKeyedJSON(t *testing.T, body []byte) []byte {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode top level: %v", err)
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(raw[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

// signerLine pulls the public key `spore sign doc` reports, so the test proves
// the CLI used the key the vector names instead of assuming it.
func signerLine(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "signer      "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no signer line in sign output:\n%s", out)
	return ""
}

func sha256Line(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "sha256      "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no sha256 line in sign output:\n%s", out)
	return ""
}

// jobReceiptFixture stages the vector and the two identity keys in a scratch
// directory and returns the paths. Seeds are fixed so the derived public keys
// are the ones the vector commits to.
func jobReceiptFixture(t *testing.T) (record, clientKey, providerKey string) {
	t.Helper()
	dir := t.TempDir()
	body, err := os.ReadFile(jobReceiptVector)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	record = filepath.Join(dir, "job.json")
	if err := os.WriteFile(record, body, 0o600); err != nil {
		t.Fatal(err)
	}
	clientKey = filepath.Join(dir, "client.key")
	providerKey = filepath.Join(dir, "provider.key")
	if err := os.WriteFile(clientKey, []byte(strings.Repeat("52", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(providerKey, []byte(strings.Repeat("63", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return record, clientKey, providerKey
}

func TestJobReceiptVectorIsExecutable(t *testing.T) {
	body, err := os.ReadFile(jobReceiptVector)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	bin := buildSporeBinary(t)

	t.Run("vector is already canonical", func(t *testing.T) {
		if bytes.ContainsRune(body, '\r') {
			t.Error("vector contains CR — §2 requires \\n line endings")
		}
		if !bytes.HasSuffix(body, []byte("\n")) || bytes.HasSuffix(body, []byte("\n\n")) {
			t.Error("vector must end with exactly one trailing newline")
		}
		if got := canonicalJSON(t, body); !bytes.Equal(got, body) {
			t.Errorf("vector is not in canonical form: re-printing it changes %d bytes:\n%s", len(got), got)
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		assertNoFloatNumbers(t, v, "record")
	})

	t.Run("key order does not change the receipt id", func(t *testing.T) {
		want := sha256.Sum256(body)
		reversed := reverseKeyedJSON(t, body)
		if bytes.Equal(reversed, body) {
			t.Fatal("reordering produced the same bytes; the test proves nothing")
		}
		got := canonicalJSON(t, reversed)
		if !bytes.Equal(got, body) {
			t.Fatalf("reordered record canonicalizes differently:\n%s", got)
		}
		if sum := sha256.Sum256(got); sum != want {
			t.Fatalf("receipt id changed with key order: %x != %x", sum, want)
		}
	})

	record, clientKey, providerKey := jobReceiptFixture(t)

	t.Run("both roles sign the same bytes", func(t *testing.T) {
		wantSum := fmt.Sprintf("%x", sha256.Sum256(body))

		clientOut, err := runSpore(t, bin, "sign", "doc", "-identity", clientKey,
			"-file", record, "-statement", jobReceiptClientStatement, "-out", record+".client.sig")
		if err != nil {
			t.Fatalf("client sign: %v\n%s", err, clientOut)
		}
		providerOut, err := runSpore(t, bin, "sign", "doc", "-identity", providerKey,
			"-file", record, "-statement", jobReceiptProviderStatement, "-out", record+".provider.sig")
		if err != nil {
			t.Fatalf("provider sign: %v\n%s", err, providerOut)
		}

		// The CLI's own digest has to be the vector's digest, otherwise the two
		// signatures cover something other than the published record.
		for role, out := range map[string]string{"client": clientOut, "provider": providerOut} {
			if got := sha256Line(t, out); got != wantSum {
				t.Errorf("%s signed sha256 %s, vector is %s", role, got, wantSum)
			}
		}

		var rec struct {
			Parties struct {
				ClientPub   string `json:"client_pub"`
				ProviderPub string `json:"provider_pub"`
			} `json:"parties"`
		}
		if err := json.Unmarshal(body, &rec); err != nil {
			t.Fatal(err)
		}
		if got := signerLine(t, clientOut); got != rec.Parties.ClientPub {
			t.Errorf("client signer = %s, vector names %s", got, rec.Parties.ClientPub)
		}
		if got := signerLine(t, providerOut); got != rec.Parties.ProviderPub {
			t.Errorf("provider signer = %s, vector names %s", got, rec.Parties.ProviderPub)
		}
	})

	t.Run("sheet reports a complete receipt", func(t *testing.T) {
		out, err := runSpore(t, bin, "sign", "sheet",
			"-file", record,
			"-sigs", record+".client.sig,"+record+".provider.sig",
			"-required", fixtureClientPub(t, body)+","+fixtureProviderPub(t, body))
		if err != nil {
			t.Fatalf("sheet on two signatures: %v\n%s", err, out)
		}
		for _, want := range []string{"signatures  2 valid", "FULLY EXECUTED", jobReceiptClientStatement, jobReceiptProviderStatement} {
			if !strings.Contains(out, want) {
				t.Errorf("sheet output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("a paraphrased statement still verifies as a signature", func(t *testing.T) {
		// The gap, stated as a test: the right key signed the right bytes, so
		// `sign sheet` counts it — even though the assertion is not the role's
		// constant. A verifier therefore has to compare the statement itself.
		paraphrase := filepath.Join(t.TempDir(), "paraphrased.sig")
		out, err := runSpore(t, bin, "sign", "doc", "-identity", clientKey,
			"-file", record, "-statement", "I accepted the work described above", "-out", paraphrase)
		if err != nil {
			t.Fatalf("sign with paraphrase: %v\n%s", err, out)
		}
		sheetOut, err := runSpore(t, bin, "sign", "sheet",
			"-file", record,
			"-sigs", record+".provider.sig,"+paraphrase,
			"-required", fixtureClientPub(t, body)+","+fixtureProviderPub(t, body))
		if err != nil {
			t.Fatalf("sheet should still count the paraphrased signature (it is a valid signature by the right key), got %v:\n%s", err, sheetOut)
		}
		if !strings.Contains(sheetOut, "FULLY EXECUTED") {
			t.Fatalf("expected the sheet to report completeness, got:\n%s", sheetOut)
		}

		// ...and the role rule the spec requires is what rejects it.
		var env struct {
			Statement string `json:"statement"`
		}
		raw, err := os.ReadFile(paraphrase)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		if env.Statement == jobReceiptClientStatement {
			t.Fatalf("paraphrase equals the role constant (%q); the subtest proves nothing", env.Statement)
		}
		if env.Statement == "" {
			t.Fatal("envelope carries no statement at all")
		}
	})

	t.Run("tampered amount breaks both signatures", func(t *testing.T) {
		tampered := bytes.Replace(body, []byte(`"amount_atomic": "2500000000000"`),
			[]byte(`"amount_atomic": "2500000000001"`), 1)
		if bytes.Equal(tampered, body) {
			t.Fatal("tamper replacement did not apply — the vector's amount field changed shape")
		}
		path := filepath.Join(t.TempDir(), "tampered.json")
		if err := os.WriteFile(path, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := runSpore(t, bin, "sign", "sheet",
			"-file", path,
			"-sigs", record+".client.sig,"+record+".provider.sig",
			"-required", fixtureClientPub(t, body)+","+fixtureProviderPub(t, body))
		if err == nil {
			t.Fatalf("sheet accepted a tampered record:\n%s", out)
		}
		if !strings.Contains(out, "DOES NOT MATCH") && !strings.Contains(out, "SHEET INVALID") {
			t.Errorf("tamper failure did not name the mismatch:\n%s", out)
		}
	})

	t.Run("one signature is not a receipt", func(t *testing.T) {
		out, err := runSpore(t, bin, "sign", "sheet",
			"-file", record,
			"-sigs", record+".provider.sig",
			"-required", fixtureClientPub(t, body)+","+fixtureProviderPub(t, body))
		if err == nil {
			t.Fatalf("provider-only record reported as complete:\n%s", out)
		}
		if !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, fixtureClientPub(t, body)) {
			t.Errorf("incomplete sheet did not name the missing signer:\n%s", out)
		}
	})
}

func fixtureClientPub(t *testing.T, body []byte) string {
	t.Helper()
	var rec struct {
		Parties struct {
			ClientPub string `json:"client_pub"`
		} `json:"parties"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := hex.DecodeString(rec.Parties.ClientPub); err != nil {
		t.Fatalf("vector client_pub is not hex: %v", err)
	}
	return rec.Parties.ClientPub
}

func fixtureProviderPub(t *testing.T, body []byte) string {
	t.Helper()
	var rec struct {
		Parties struct {
			ProviderPub string `json:"provider_pub"`
		} `json:"parties"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := hex.DecodeString(rec.Parties.ProviderPub); err != nil {
		t.Fatalf("vector provider_pub is not hex: %v", err)
	}
	return rec.Parties.ProviderPub
}
