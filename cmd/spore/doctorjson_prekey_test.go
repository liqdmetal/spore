package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRejectedPool writes an OPK pool file whose persisted rejection counts
// are lookup=2 validate=0 authenticate=1 commit=0 and returns its path.
func writeRejectedPool(t *testing.T) string {
	t.Helper()
	pool := filepath.Join(t.TempDir(), "opk-pool.json")
	body := `{"items":{},"rejected":{"lookup":2,"validate":0,"authenticate":1,"commit":0}}`
	if err := os.WriteFile(pool, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return pool
}

// assertPrekeyWarning checks that the JSON report carries the prekey-rejection
// warning with the persisted counts and a next-step hint.
func assertPrekeyWarning(t *testing.T, report doctorJSONReport) {
	t.Helper()
	check := findDoctorJSONCheck(t, report, "prekey-rejections")
	if check.Status != "warning" {
		t.Fatalf("status=%q, want warning: %+v", check.Status, check)
	}
	want := "lookup=2 validate=0 authenticate=1 commit=0"
	if !strings.Contains(check.Detail, want) {
		t.Fatalf("detail=%q, want it to contain %q", check.Detail, want)
	}
	if check.NextAction == "" {
		t.Fatalf("warning has no next_action: %+v", check)
	}
	if report.Summary.Warnings == 0 {
		t.Fatalf("summary counts no warnings: %+v", report.Summary)
	}
}

func TestDoctorJSONReportsPrekeyRejectionsFromFlag(t *testing.T) {
	pool := writeRejectedPool(t)
	report := buildDoctorJSONReport(doctorJSONOptions{
		Doctor:  doctorOpts{Config: filepath.Join(t.TempDir(), "absent.json"), Home: t.TempDir()},
		OpkPool: pool,
	})
	assertPrekeyWarning(t, report)
}

func TestDoctorJSONReportsPrekeyRejectionsFromConfig(t *testing.T) {
	pool := writeRejectedPool(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	raw, err := json.Marshal(Config{OpkPool: pool})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// No OpkPool option: the pool path must come from config opk_pool.
	report := buildDoctorJSONReport(doctorJSONOptions{
		Doctor: doctorOpts{Config: configPath, Home: t.TempDir()},
	})
	assertPrekeyWarning(t, report)
}

func TestDoctorJSONNoPrekeyCheckWithoutPool(t *testing.T) {
	report := buildDoctorJSONReport(doctorJSONOptions{
		Doctor: doctorOpts{Config: filepath.Join(t.TempDir(), "absent.json"), Home: t.TempDir()},
	})
	for _, c := range report.Checks {
		if c.ID == "prekey-rejections" {
			t.Fatalf("prekey-rejections check present without a pool: %+v", c)
		}
	}
}
