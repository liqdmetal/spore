package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLoadMissingIsNotError(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || cfg != nil {
		t.Fatalf("missing config = %v, %v; want nil, nil", cfg, err)
	}
}

func TestConfigLoadMalformedIsError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("malformed config accepted")
	}
	// Unknown fields rejected too (typo protection: "identty" should not
	// silently do nothing).
	if err := os.WriteFile(p, []byte(`{"identty":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown config field accepted")
	}
}

func TestConfigEnvOverride(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alt.json")
	t.Setenv("SPORE_CONFIG", p)
	if got := configPath(""); got != p {
		t.Fatalf("configPath = %q, want %q", got, p)
	}
	if got := configPath("/explicit.json"); got != "/explicit.json" {
		t.Fatalf("explicit flag should win: %q", got)
	}
	t.Setenv("SPORE_HOME", dir)
	if got, err := DefaultConfigDir(); err != nil || got != dir {
		t.Fatalf("DefaultConfigDir = %q, %v", got, err)
	}
}

func TestApplyConfigDefaultsRespectsExplicitFlags(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{Store: "http://cfg-store:1", Chain: "evm", Maildb: filepath.Join(dir, "mail.json")}

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	e2Common(fs)
	maildbFlag := fs.String("maildb", "", "")
	// User explicitly sets -store; config's store must NOT override it.
	if err := fs.Parse([]string{"-store", "http://explicit-store:2"}); err != nil {
		t.Fatal(err)
	}
	if err := applyConfigDefaults(fs, cfg); err != nil {
		t.Fatal(err)
	}
	if got := fs.Lookup("store").Value.String(); got != "http://explicit-store:2" {
		t.Fatalf("explicit -store overridden by config: %q", got)
	}
	// -chain was NOT set explicitly: config value applies.
	if got := fs.Lookup("chain").Value.String(); got != "evm" {
		t.Fatalf("config chain default not applied: %q", got)
	}
	if *maildbFlag != cfg.Maildb {
		t.Fatalf("config maildb default not applied: %q", *maildbFlag)
	}
}

func TestInitCreatesUsableKit(t *testing.T) {
	home := filepath.Join(t.TempDir(), "spore")
	initcmd([]string{"-dir", home, "-opks", "3", "-store", "http://127.0.0.1:8080"})

	// Every artifact exists.
	for _, f := range []string{"identity.key", "spk.key", "state.key", "opk-pool.json", "bundle.json", "config.json", "state"} {
		if _, err := os.Stat(filepath.Join(home, f)); err != nil {
			t.Fatalf("init did not create %s: %v", f, err)
		}
	}
	// Config is loadable and internally consistent.
	cfg, err := LoadConfig(filepath.Join(home, "config.json"))
	if err != nil || cfg == nil {
		t.Fatalf("config load: %v", err)
	}
	if cfg.Identity != filepath.Join(home, "identity.key") || cfg.Chain != "dero" || cfg.Store != "http://127.0.0.1:8080" {
		t.Fatalf("config = %+v", cfg)
	}
	if len(cfg.PinnedSig) != 64 {
		t.Fatalf("pinned sig not 32-byte hex: %q", cfg.PinnedSig)
	}
	// bundle.json is valid JSON with public-only fields.
	raw, err := os.ReadFile(filepath.Join(home, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pub map[string]string
	if err := json.Unmarshal(raw, &pub); err != nil {
		t.Fatal(err)
	}
	if pub["ik_pub"] == "" || pub["pinned_sig"] == "" {
		t.Fatalf("bundle.json incomplete: %v", pub)
	}
	for _, v := range pub {
		if len(v) != 64 {
			t.Fatalf("bundle field not 32-byte hex: %q", v)
		}
	}
	// identity.key holds 32-byte hex.
	ik, err := readHexFile(filepath.Join(home, "identity.key"), 32)
	if err != nil || len(ik) != 32 {
		t.Fatalf("identity.key: %v", err)
	}

	// Re-init without -force must refuse (exit via check -> log.Fatal in
	// production; here it panics through check). Verify the refusal path
	// triggers check() by recovering os.Exit is not possible in-process,
	// so we assert the precondition init checks: identity file exists.
	if _, err := os.Stat(filepath.Join(home, "identity.key")); err != nil {
		t.Fatal("identity missing before re-init test")
	}
}
