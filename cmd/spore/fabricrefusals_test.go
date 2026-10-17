package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fabricRefusalCheck(t *testing.T, stateDir string) (statusJSONCheck, bool) {
	t.Helper()
	report, err := buildStatusJSONReportWithPool(nil, "", t.TempDir(), stateDir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range report.Checks {
		if c.ID == "fabric-refusals" {
			return c, true
		}
	}
	return statusJSONCheck{}, false
}

func TestNoteFabricRefusalPersistsCount(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := noteFabricRefusal(dir); err != nil {
			t.Fatal(err)
		}
	}
	n, err := readFabricRefusals(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("persisted refusals=%d, want 3", n)
	}
	// The count is read back by a fresh call, so it survives the subscriber exiting.
	if _, err := os.Stat(filepath.Join(dir, fabricRefusalFile)); err != nil {
		t.Fatalf("count file missing: %v", err)
	}
}

func TestNoteFabricRefusalWithoutStateDirRecordsNothing(t *testing.T) {
	if err := noteFabricRefusal(""); err != nil {
		t.Fatalf("empty state dir: %v", err)
	}
}

func TestStatusReportsFabricRefusals(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		if err := noteFabricRefusal(dir); err != nil {
			t.Fatal(err)
		}
	}
	c, ok := fabricRefusalCheck(t, dir)
	if !ok {
		t.Fatal("no fabric-refusals check after refusals were recorded")
	}
	if c.Status != "warning" {
		t.Fatalf("status=%q, want warning", c.Status)
	}
	if !strings.Contains(c.Detail, "refused fabric init pointers: 2") {
		t.Fatalf("detail=%q does not carry the count", c.Detail)
	}
}

func TestStatusOmitsFabricRefusalsWhenNoneRecorded(t *testing.T) {
	if _, ok := fabricRefusalCheck(t, t.TempDir()); ok {
		t.Fatal("fabric-refusals check added with no refusals recorded")
	}
}
