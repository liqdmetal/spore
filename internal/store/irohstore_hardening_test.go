package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type hardeningIrohRunner struct {
	addCalls int
	getCalls int
	body     []byte
	locator  [32]byte
}

func (r *hardeningIrohRunner) add(path string) ([]byte, error) {
	r.addCalls++
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r.body = append(r.body[:0], body...)
	return []byte(hex.EncodeToString(r.locator[:]) + "\n"), nil
}

func (r *hardeningIrohRunner) get(string) ([]byte, error) {
	r.getCalls++
	return r.body, nil
}

func TestIrohStoreRejectsOversizedPutBeforeSidecar(t *testing.T) {
	runner := &hardeningIrohRunner{locator: [32]byte{1}}
	body := make([]byte, maxIrohBodyBytes+1)
	cid := sha256.Sum256(body)
	st := &IrohStore{runner: runner, index: make(map[string]irohEntry)}

	if _, err := st.PutWithLocator(cid, body, time.Time{}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized Put error = %v", err)
	}
	if runner.addCalls != 0 || st.Len() != 0 {
		t.Fatalf("oversized body reached sidecar or index: add calls=%d index=%d", runner.addCalls, st.Len())
	}
}

func TestIrohStoreRejectsOversizedFetchedBody(t *testing.T) {
	locator := [32]byte{2}
	body := bytes.Repeat([]byte{0xA5}, maxIrohBodyBytes+1)
	runner := &hardeningIrohRunner{body: body}
	st := &IrohStore{runner: runner, index: make(map[string]irohEntry)}

	if _, err := st.GetWithLocator(sha256.Sum256(body), locator); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized fetch error = %v", err)
	}
}

func TestIrohIndexRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{' '}, maxIrohIndexBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	st := &IrohStore{idxPath: path, index: make(map[string]irohEntry)}
	if err := st.loadIndex(); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized index error = %v", err)
	}
}

func TestIrohIndexAtomicReplaceAndZeroDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.json")
	body := []byte("zero deadline is no-expiry")
	cid := sha256.Sum256(body)
	runner := &hardeningIrohRunner{locator: [32]byte{3}}
	st := &IrohStore{idxPath: path, runner: runner, index: make(map[string]irohEntry)}
	if _, err := st.PutWithLocator(cid, body, time.Time{}); err != nil {
		t.Fatal(err)
	}

	key := irohHex(cid)
	entry := st.index[key]
	entry.Size++
	st.index[key] = entry
	if err := st.saveIndexLocked(); err != nil {
		t.Fatalf("atomic replacement of existing index: %v", err)
	}
	loaded := &IrohStore{idxPath: path, index: make(map[string]irohEntry)}
	if err := loaded.loadIndex(); err != nil {
		t.Fatal(err)
	}
	loadedEntry := loaded.index[irohHex(cid)]
	if loadedEntry.Deadline != 0 || loadedEntry.Size != len(body)+1 {
		t.Fatalf("reloaded entry = %#v", loadedEntry)
	}
}

func TestIrohStoreDoesNotCommitIndexAfterPersistenceFailure(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.json")
	if err := os.Mkdir(indexPath, 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("index failure rollback")
	runner := &hardeningIrohRunner{locator: [32]byte{4}}
	st := &IrohStore{idxPath: indexPath, runner: runner, index: make(map[string]irohEntry)}
	if _, err := st.PutWithLocator(sha256.Sum256(body), body, time.Time{}); err == nil {
		t.Fatal("Put succeeded despite an index persistence failure")
	}
	if st.Len() != 0 {
		t.Fatalf("failed persistence left an in-memory mapping: %d entries", st.Len())
	}
}

func TestIrohGetWithLocatorHonorsExpiredLocalEntry(t *testing.T) {
	cid := sha256.Sum256([]byte("expired"))
	locator := [32]byte{5}
	runner := &hardeningIrohRunner{body: []byte("expired")}
	st := &IrohStore{
		runner: runner,
		index: map[string]irohEntry{
			irohHex(cid): {IrohHash: irohHex(locator), Deadline: time.Now().Add(-time.Minute).Unix(), Size: len(runner.body)},
		},
	}
	if _, err := st.GetWithLocator(cid, locator); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired portable fetch error = %v, want ErrExpired", err)
	}
	if runner.getCalls != 0 {
		t.Fatalf("expired locator reached sidecar: %d calls", runner.getCalls)
	}
}

func irohTestHelperEnv(mode string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if strings.EqualFold(name, "SPORE_IROH_TEST_HELPER") || strings.EqualFold(name, "SPORE_IROH_TEST_MODE") {
			continue
		}
		env = append(env, item)
	}
	return append(env, "SPORE_IROH_TEST_HELPER=1", "SPORE_IROH_TEST_MODE="+mode)
}

func TestIrohCommandHelper(t *testing.T) {
	if os.Getenv("SPORE_IROH_TEST_HELPER") != "1" {
		return
	}
	switch os.Getenv("SPORE_IROH_TEST_MODE") {
	case "large":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 4096))
	case "sleep":
		time.Sleep(10 * time.Second)
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func TestIrohCommandCapsStdoutAndEnforcesTimeout(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	largeOutput, err := runIrohCommandWithEnv(exe, time.Second, 32, irohTestHelperEnv("large"), "-test.run=^TestIrohCommandHelper$")
	if !errors.Is(err, errIrohOutputTooLarge) {
		t.Fatalf("oversized command output error = %v; bytes=%d; executable=%q", err, len(largeOutput), exe)
	}

	if _, err := runIrohCommandWithEnv(exe, 50*time.Millisecond, 32, irohTestHelperEnv("sleep"), "-test.run=^TestIrohCommandHelper$"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timed command error = %v", err)
	}
}

func TestIrohGetTimeoutCoversSerialProviderBudget(t *testing.T) {
	const (
		maxProviders         = 8
		providerAttempt      = 25 * time.Second
		queueAdmission       = 20 * time.Second
		providerWaitOverhead = 20 * time.Second
		processStartupMargin = 60 * time.Second
	)
	minimum := time.Duration(maxProviders)*providerAttempt + queueAdmission + providerWaitOverhead + processStartupMargin
	if irohGetTimeout < minimum {
		t.Fatalf("Get timeout = %s; need at least %s for provider, queue, and process budgets", irohGetTimeout, minimum)
	}
}
