package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/bounds"
	"github.com/liqdmetal/spore/internal/safehttp"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/session"
)

const doctorJSONSchema = "spore/doctor/v1"

type doctorJSONOptions struct {
	Doctor         doctorOpts
	RPC            string
	Store          string
	Chain          string
	ListenExplicit bool
	Live           bool
	OpkPool        string
}

type doctorJSONCheck struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	NextAction string `json:"next_action,omitempty"`
}

type doctorJSONSummary struct {
	Status   string `json:"status"`
	Checks   int    `json:"checks"`
	Errors   int    `json:"errors"`
	Warnings int    `json:"warnings"`
	Skipped  int    `json:"skipped"`
}

type doctorJSONReport struct {
	Schema      string            `json:"schema"`
	ReadOnly    bool              `json:"read_only"`
	GeneratedAt string            `json:"generated_at"`
	Summary     doctorJSONSummary `json:"summary"`
	Checks      []doctorJSONCheck `json:"checks"`
}

func buildDoctorJSONReport(o doctorJSONOptions) doctorJSONReport {
	r := doctorJSONReport{Schema: doctorJSONSchema, ReadOnly: true, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Checks: []doctorJSONCheck{}}
	add := func(id, status, detail, action string) {
		r.add(id, status, detail, action)
	}

	cfgPath := o.Doctor.Config
	if cfgPath == "" {
		cfgPath = configPath("")
	}
	cfg, configErr := LoadConfig(cfgPath)
	switch {
	case configErr != nil:
		add("config", "error", fmt.Sprintf("cannot load %s: %v", cfgPath, configErr), "Fix the invalid config file, then rerun doctor.")
	case cfg == nil:
		add("config", "skipped", "No config file; flag-driven operation is available.", "Run `spore init` to create a default identity and config if needed.")
	default:
		check := doctorConfigCheck(cfgPath)
		if check.OK {
			add("config", "ok", check.Note, "")
		} else {
			add("config", "error", check.Note, "Fix the missing paths or invalid fields, then rerun doctor.")
		}
	}

	home := o.Doctor.Home
	if home == "" && cfg != nil && cfg.Dir != "" {
		home = cfg.Dir
	}
	if home == "" {
		home, _ = DefaultConfigDir()
	}
	keyCheck := doctorKeyFilesCheck(home)
	if keyCheck.OK {
		add("key-files", "ok", keyCheck.Note, "")
	} else if cfg == nil && o.Doctor.Priv == "" && os.IsNotExist(homeError(home)) {
		add("key-files", "skipped", keyCheck.Note, "Run `spore init` to create a private local identity kit.")
	} else {
		add("key-files", "error", keyCheck.Note, "Review file and directory permissions; never paste private key contents into chat or logs.")
	}

	identityPath := ""
	if cfg != nil {
		identityPath = cfg.Identity
	}
	if identityPath == "" {
		identityPath = filepath.Join(home, "identity.key")
	}
	var identity []byte
	if o.Doctor.Priv != "" {
		var err error
		identity, err = decodeDoctorIdentity([]byte(o.Doctor.Priv))
		if err != nil {
			add("identity", "error", "The supplied -priv value is not valid 32-byte hex.", "Use a valid identity key from a protected file; avoid exposing private values in process listings.")
		} else {
			addDoctorIdentity(&r, identity, "command-line identity", cfg)
		}
	} else {
		key, err := readDoctorKey(identityPath)
		if err != nil {
			if os.IsNotExist(err) {
				add("identity", "skipped", "No identity key file found at the configured path.", "Run `spore init` or correct the configured identity path.")
			} else {
				add("identity", "error", fmt.Sprintf("Cannot read configured identity key (%s): %v", identityPath, err), "Check the path and file format without exposing its contents.")
			}
		} else {
			identity = key
			addDoctorIdentity(&r, identity, identityPath, cfg)
		}
	}
	for i := range identity {
		identity[i] = 0
	}

	dataDir := o.Doctor.Dir
	if dataDir == "" && cfg != nil {
		dataDir = cfg.Dir
	}
	addDirectoryCheck(add, "data-dir", dataDir, "Set -dir to an existing directory or create it with `spore init`.")

	stateKeyPath := filepath.Join(home, "state.key")
	stateDir := ""
	if cfg != nil {
		if cfg.StateKey != "" {
			stateKeyPath = cfg.StateKey
		}
		stateDir = cfg.StateDir
	}
	stateKey, stateKeyErr := readDoctorKey(stateKeyPath)
	if stateKeyErr != nil {
		if os.IsNotExist(stateKeyErr) && cfg == nil {
			add("state-key", "skipped", "No state encryption key configured; no state files were opened.", "Run `spore init` or configure state_key for encrypted E2 state.")
		} else {
			add("state-key", "error", fmt.Sprintf("Cannot read or validate the configured state key (%s): %v", stateKeyPath, stateKeyErr), "Restore the correct 32-byte hex state key; never replace it while encrypted session state exists.")
		}
	} else {
		for i := range stateKey {
			stateKey[i] = 0
		}
		add("state-key", "ok", "State encryption key is readable and contains 32-byte hex; key material omitted from report.", "")
	}
	addDirectoryCheck(add, "state-dir", stateDir, "Set state_dir to an existing private directory; do not restore over newer ratchet state.")
	if stateDir != "" {
		for _, name := range []string{"receive-pending.enc", "handoffs.enc.lock", "handoffs.enc.send-lock"} {
			path := filepath.Join(stateDir, name)
			if _, err := os.Lstat(path); err == nil {
				detail := fmt.Sprintf("%s exists; doctor did not open or modify state", name)
				action := "Inspect the owning process before acting; never delete a pending receive journal or live lock blindly."
				if name == "receive-pending.enc" {
					action = "Inspect `spore work-order handoff status`, then use `spore work-order handoff recover` after verifying identity and state key."
				}
				add("state-"+strings.TrimSuffix(name, ".enc"), "warning", detail, action)
			} else if !os.IsNotExist(err) {
				add("state-"+strings.TrimSuffix(name, ".enc"), "warning", fmt.Sprintf("cannot inspect %s: %v", name, err), "Check directory access and inspect state manually.")
			}
		}
	}

	if o.Doctor.Listen == "" {
		add("listen", "skipped", "No listen address was explicitly supplied; no socket was opened.", "When configuring a listener, prefer loopback unless remote access is intentional and authenticated.")
	} else if !o.ListenExplicit {
		add("listen", "skipped", fmt.Sprintf("Default listen address %s is shown for reference; no socket was opened.", o.Doctor.Listen), "Use -listen explicitly when checking a listener bind.")
	} else if safehttp.HostIsLoopback(o.Doctor.Listen) {
		add("listen", "ok", "Configured listen address is loopback-only; no socket was opened.", "")
	} else {
		add("listen", "error", "Configured listen address is not loopback; no socket was opened.", "Bind to 127.0.0.1 or ensure the listener is authenticated and intentionally exposed.")
	}

	poolPath := o.OpkPool
	if poolPath == "" && cfg != nil {
		poolPath = cfg.OpkPool
	}
	addPrekeyRejections(add, poolPath)

	rpc := o.RPC
	storeURL := o.Store
	chainName := o.Chain
	if cfg != nil {
		if rpc == "" {
			rpc = cfg.RPC
		}
		if storeURL == "" {
			storeURL = cfg.Store
		}
		if chainName == "" {
			chainName = cfg.Chain
		}
	}
	if rpc != "" || chainName != "" {
		add("chain-reachability", "skipped", "A chain is configured but no RPC request was made in read-only JSON mode.", "Run `spore doctor -rpc ...` without -json for the existing network probe.")
	} else {
		add("chain-reachability", "skipped", "No chain or RPC was configured; no network request was made.", "Configure -chain and -rpc to check connectivity.")
	}
	if storeURL != "" {
		// Keep endpoint paths and credentials out of output.
		add("store-reachability", "skipped", "A body store is configured but was not contacted in read-only JSON mode.", "Run the explicit `spore doctor -live -store ...` probe only when its store write/delete effects are acceptable.")
	} else {
		add("store-reachability", "skipped", "No body store was configured; no network request was made.", "Configure a store for E2 messaging and run its explicit live probe if desired.")
	}
	if o.Live {
		add("live-probes", "skipped", "-live was not run because JSON mode performs no network or store probes.", "Run `spore doctor -live` separately only when its effects are acceptable.")
	}

	r.finish()
	return r
}

func homeError(path string) error {
	_, err := os.Stat(path)
	return err
}

func decodeDoctorIdentity(raw []byte) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("invalid identity encoding")
	}
	return key, nil
}

func readDoctorKey(path string) ([]byte, error) {
	raw, err := bounds.ReadBound(path, 4096)
	if err != nil {
		return nil, err
	}
	return decodeDoctorIdentity(raw)
}

func addDoctorIdentity(r *doctorJSONReport, key []byte, source string, cfg *Config) {
	identity, err := session.NewFromPriv(nil, key)
	if err != nil {
		r.add("identity", "error", "The identity key cannot initialize the Spore identity.", "Use the matching 32-byte identity key file.")
		return
	}
	pin, err := secure.SigPubOf(identity.PrivKey())
	if err != nil {
		r.add("identity", "error", "Could not derive the identity signing pin.", "Check the key file and binary build.")
		return
	}
	if cfg != nil && cfg.PinnedSig != "" && !strings.EqualFold(cfg.PinnedSig, hex.EncodeToString(pin)) {
		r.add("identity", "error", fmt.Sprintf("Signing pin derived from %s does not match config pinned_sig.", source), "Restore the matching identity key or update config only after verifying the identity out of band.")
		return
	}
	detail := "Identity key parses and its signing pin derives successfully."
	if source == "command-line identity" {
		detail = "Supplied identity key parses and its signing pin derives successfully; key material omitted from report."
	}
	r.add("identity", "ok", detail, "")
}

func addDirectoryCheck(add func(string, string, string, string), id, path, action string) {
	if path == "" {
		add(id, "skipped", "No directory path was configured; no path was created.", "Configure a directory if this deployment needs local state.")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			add(id, "error", fmt.Sprintf("Configured directory does not exist: %s", path), action)
		} else {
			add(id, "error", fmt.Sprintf("Cannot inspect configured directory %s: %v", path, err), action)
		}
		return
	}
	if !info.IsDir() {
		add(id, "error", fmt.Sprintf("Configured path is not a directory: %s", path), action)
		return
	}
	if _, err := os.ReadDir(path); err != nil {
		add(id, "error", fmt.Sprintf("Configured directory cannot be read: %s (%v)", path, err), action)
		return
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o222 == 0 {
		add(id, "error", fmt.Sprintf("Configured directory has no write permission bits: %s", path), action)
		return
	}
	add(id, "ok", fmt.Sprintf("Configured directory exists and is readable: %s; write access was not tested to preserve read-only behavior.", path), "")
}

func (r *doctorJSONReport) add(id, status, detail, action string) {
	r.Checks = append(r.Checks, doctorJSONCheck{ID: id, Status: status, Detail: detail, NextAction: action})
	switch status {
	case "error":
		r.Summary.Errors++
	case "warning":
		r.Summary.Warnings++
	case "skipped":
		r.Summary.Skipped++
	}
}

func (r *doctorJSONReport) finish() {
	r.Summary.Checks = len(r.Checks)
	switch {
	case r.Summary.Errors > 0:
		r.Summary.Status = "error"
	case r.Summary.Warnings > 0:
		r.Summary.Status = "warning"
	case r.Summary.Skipped > 0:
		r.Summary.Status = "incomplete"
	default:
		r.Summary.Status = "ok"
	}
}

func writeDoctorJSON(w io.Writer, report doctorJSONReport) error {
	if w == nil {
		return fmt.Errorf("doctor: nil JSON output")
	}
	return json.NewEncoder(w).Encode(report)
}
