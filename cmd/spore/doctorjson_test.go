package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/secure"
)

func writeDoctorTestKey(t *testing.T, path string, key []byte) {
	t.Helper()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findDoctorJSONCheck(t *testing.T, report doctorJSONReport, id string) doctorJSONCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("report missing check %q", id)
	return doctorJSONCheck{}
}

func TestDoctorJSONReportSchemaAndSummary(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := bytes.Repeat([]byte{0x31}, 32)
	pin, err := secure.SigPubOf(identity)
	if err != nil {
		t.Fatal(err)
	}
	writeDoctorTestKey(t, filepath.Join(home, "identity.key"), identity)
	writeDoctorTestKey(t, filepath.Join(home, "state.key"), bytes.Repeat([]byte{0x41}, 32))
	cfg := Config{Dir: home, Identity: filepath.Join(home, "identity.key"), StateDir: filepath.Join(home, "state"), StateKey: filepath.Join(home, "state.key"), PinnedSig: hex.EncodeToString(pin), RPC: "http://127.0.0.1:1", Store: "http://127.0.0.1:2", StoreToken: "must-not-leak"}
	configRaw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, "config.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, "state"), 0o700); err != nil {
		t.Fatal(err)
	}

	report := buildDoctorJSONReport(doctorJSONOptions{Doctor: doctorOpts{Config: configPath, Home: home}})
	if report.Schema != doctorJSONSchema || !report.ReadOnly || report.GeneratedAt == "" {
		t.Fatalf("invalid report envelope: %+v", report)
	}
	if report.Summary.Checks != len(report.Checks) || report.Summary.Errors != 0 || report.Summary.Status != "incomplete" {
		t.Fatalf("bad summary counts/status: %+v for %d checks", report.Summary, len(report.Checks))
	}
	for _, id := range []string{"config", "key-files", "identity", "data-dir", "state-key", "state-dir", "listen", "chain-reachability", "store-reachability"} {
		check := findDoctorJSONCheck(t, report, id)
		if check.Status == "" || check.Detail == "" {
			t.Errorf("check %q missing status/detail: %+v", id, check)
		}
	}
	if got := findDoctorJSONCheck(t, report, "chain-reachability"); got.Status != "skipped" {
		t.Fatalf("chain probe must remain skipped in read-only mode: %+v", got)
	}
	if got := findDoctorJSONCheck(t, report, "store-reachability"); got.Status != "skipped" {
		t.Fatalf("store probe must remain skipped in read-only mode: %+v", got)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, identity) || strings.Contains(string(raw), "must-not-leak") || strings.Contains(string(raw), hex.EncodeToString(identity)) {
		t.Fatal("report exposed identity bytes or store token")
	}
}

func TestDoctorJSONReportDetectsBadPinAndReadOnlyState(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	identity := bytes.Repeat([]byte{0x52}, 32)
	stateKey := bytes.Repeat([]byte{0x62}, 32)
	writeDoctorTestKey(t, filepath.Join(home, "identity.key"), identity)
	writeDoctorTestKey(t, filepath.Join(home, "state.key"), stateKey)
	if err := os.Mkdir(filepath.Join(home, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "state", "receive-pending.enc"), []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	badPinConfig := Config{Dir: home, Identity: filepath.Join(home, "identity.key"), StateDir: filepath.Join(home, "state"), StateKey: filepath.Join(home, "state.key"), PinnedSig: strings.Repeat("00", 32)}
	configRaw, err := json.Marshal(badPinConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, "config.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(home, "state", "receive-pending.enc")
	before, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	report := buildDoctorJSONReport(doctorJSONOptions{Doctor: doctorOpts{Config: configPath, Home: home, Listen: "0.0.0.0:8123"}, RPC: "http://127.0.0.1:1", Store: "http://127.0.0.1:2", ListenExplicit: true, Live: true})
	if report.Summary.Errors < 1 || report.Summary.Status != "error" {
		t.Fatalf("bad pin or exposed listener did not fail the report: %+v", report.Summary)
	}
	identityCheck := findDoctorJSONCheck(t, report, "identity")
	if identityCheck.Status != "error" || !strings.Contains(identityCheck.NextAction, "out of band") {
		t.Fatalf("identity pin mismatch lacks actionable error: %+v", identityCheck)
	}
	if got := findDoctorJSONCheck(t, report, "listen"); got.Status != "error" {
		t.Fatalf("non-loopback listener should be called out: %+v", got)
	}
	pending := findDoctorJSONCheck(t, report, "state-receive-pending")
	if pending.Status != "warning" || !strings.Contains(pending.NextAction, "recover") {
		t.Fatalf("pending receive should include cautious recovery guidance: %+v", pending)
	}
	if findDoctorJSONCheck(t, report, "live-probes").Status != "skipped" {
		t.Fatal("JSON mode ran or failed to disclose disabled live probes")
	}
	for _, path := range []string{stateFile, configPath, filepath.Join(home, "identity.key"), filepath.Join(home, "state.key")} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if path == stateFile && !bytes.Equal(got, before) {
			t.Fatal("read-only diagnostic changed receive journal bytes")
		}
		if path == stateFile {
			afterInfo, err := os.Stat(stateFile)
			if err != nil || !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
				t.Fatalf("read-only diagnostic changed receive journal metadata: %v", err)
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(home, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "receive-pending.enc" {
		t.Fatalf("JSON doctor created/removed state artifacts: %v", entries)
	}
}

func TestDoctorJSONWriterAndNoStateForMissingConfig(t *testing.T) {
	home := filepath.Join(t.TempDir(), "absent-home")
	report := buildDoctorJSONReport(doctorJSONOptions{Doctor: doctorOpts{Home: home}})
	if findDoctorJSONCheck(t, report, "key-files").Status != "skipped" {
		t.Fatalf("missing default home should be skipped, not break a flag-driven installation: %+v", report.Summary)
	}
	var out bytes.Buffer
	if err := writeDoctorJSON(&out, report); err != nil {
		t.Fatal(err)
	}
	var roundTrip doctorJSONReport
	if err := json.Unmarshal(out.Bytes(), &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Schema != doctorJSONSchema || roundTrip.Summary.Checks != len(roundTrip.Checks) {
		t.Fatalf("JSON writer produced an invalid schema: %+v", roundTrip)
	}
	if err := writeDoctorJSON(nil, report); err == nil {
		t.Fatal("nil output writer accepted")
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("read-only JSON report created home %q: %v", home, err)
	}
}
