package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prekeyCheck(t *testing.T, opkPool string) (statusJSONCheck, bool) {
	t.Helper()
	report, err := buildStatusJSONReportWithPool(nil, "", t.TempDir(), t.TempDir(), "", opkPool)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range report.Checks {
		if c.ID == "prekey-rejections" {
			return c, true
		}
	}
	return statusJSONCheck{}, false
}

func TestStatusReportsPersistedPrekeyRejections(t *testing.T) {
	pool := filepath.Join(t.TempDir(), "opk-pool.json")
	body := `{"items":{},"rejected":{"lookup":0,"validate":1,"authenticate":2,"commit":0}}`
	if err := os.WriteFile(pool, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, ok := prekeyCheck(t, pool)
	if !ok {
		t.Fatal("no prekey-rejections check with a pool configured")
	}
	if c.Status != "warning" {
		t.Fatalf("status=%q, want warning for rejections", c.Status)
	}
	want := "lookup=0 validate=1 authenticate=2 commit=0"
	if !strings.Contains(c.Detail, want) {
		t.Fatalf("detail=%q, want it to contain %q", c.Detail, want)
	}
}

func TestStatusPrekeyCheckOKWhenNoRejections(t *testing.T) {
	pool := filepath.Join(t.TempDir(), "opk-pool.json")
	if err := os.WriteFile(pool, []byte(`{"items":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, ok := prekeyCheck(t, pool)
	if !ok || c.Status != "ok" {
		t.Fatalf("clean pool: ok=%v check=%+v, want ok", ok, c)
	}
}

func TestStatusPrekeyCheckMissingPoolFile(t *testing.T) {
	c, ok := prekeyCheck(t, filepath.Join(t.TempDir(), "absent.json"))
	if !ok || c.Status != "ok" {
		t.Fatalf("missing pool file: ok=%v check=%+v, want ok", ok, c)
	}
}

func TestStatusNoPrekeyCheckWithoutPool(t *testing.T) {
	if _, ok := prekeyCheck(t, ""); ok {
		t.Fatal("prekey-rejections check added with no pool configured")
	}
}
