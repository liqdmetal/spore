package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
)

// Config is the on-disk defaults file (~/.spore/config.json). It holds PATHS
// and non-secret defaults so a user never retypes the same ten flags. The
// secrets themselves stay in their 0600 key files — config is 0600 too
// because store_token is a bearer secret.
type Config struct {
	Dir        string `json:"dir"`
	Identity   string `json:"identity,omitempty"`
	SPK        string `json:"spk,omitempty"`
	OpkPool    string `json:"opk_pool,omitempty"`
	StoreKey   string `json:"store_key,omitempty"`
	Bundle     string `json:"bundle,omitempty"`
	PinnedSig  string `json:"pinned_sig,omitempty"` // OUR public sig key others pin
	StateDir   string `json:"state_dir,omitempty"`
	StateKey   string `json:"state_key,omitempty"`
	Store      string `json:"store,omitempty"`
	StoreToken string `json:"store_token,omitempty"`
	Chain      string `json:"chain,omitempty"`
	Maildb     string `json:"maildb,omitempty"`
	RPC        string `json:"rpc,omitempty"`
	RPCLogin   string `json:"rpc_login,omitempty"`
	Network    string `json:"network,omitempty"`
	Relays     string `json:"relays,omitempty"`
	BaseURL    string `json:"base_url,omitempty"`
	Address    string `json:"address,omitempty"`
}

// DefaultConfigDir is ~/.spore unless SPORE_HOME overrides it.
func DefaultConfigDir() (string, error) {
	if v := os.Getenv("SPORE_HOME"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".spore"), nil
}

// configPath resolves the config file: explicit -config flag > SPORE_CONFIG
// env > ~/.spore/config.json.
func configPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("SPORE_CONFIG"); v != "" {
		return v
	}
	dir, err := DefaultConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "config.json")
}

// LoadConfig reads the config file. A missing file is not an error (nil,
// nil) — every command works fully flag-driven without one. Malformed JSON
// IS an error: silently ignoring a corrupt config would make users think
// their defaults applied when they didn't.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// flagValues maps config fields onto the e2Common/per-command flag names.
func (c *Config) flagValues() map[string]string {
	return map[string]string{
		"identity":    c.Identity,
		"spk":         c.SPK,
		"opk-pool":    c.OpkPool,
		"store-key":   c.StoreKey,
		"bundle":      c.Bundle,
		"state-dir":   c.StateDir,
		"state-key":   c.StateKey,
		"store":       c.Store,
		"store-token": c.StoreToken,
		"chain":       c.Chain,
		"maildb":      c.Maildb,
		"rpc":         c.RPC,
		"rpc-login":   c.RPCLogin,
		"network":     c.Network,
		"relays":      c.Relays,
		"base-url":    c.BaseURL,
		"address":     c.Address,
	}
}

// applyConfigDefaults fills every flag the user did NOT explicitly set from
// the config. Explicit CLI flags always win — the config is defaults, never
// overrides. Call AFTER fs.Parse.
func applyConfigDefaults(fs *flag.FlagSet, cfg *Config) error {
	if cfg == nil {
		return nil
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	for name, val := range cfg.flagValues() {
		if val == "" || explicit[name] {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // this command doesn't have that flag
		}
		if err := fs.Set(name, val); err != nil {
			return err
		}
	}
	return nil
}

// loadConfigForFlags is the one-liner commands use after fs.Parse: resolve
// the config path (from the -config flag when the command has one), load it,
// and apply defaults.
func loadConfigForFlags(fs *flag.FlagSet) error {
	explicit := ""
	if f := fs.Lookup("config"); f != nil {
		explicit = f.Value.String()
	}
	cfg, err := LoadConfig(configPath(explicit))
	if err != nil {
		return err
	}
	return applyConfigDefaults(fs, cfg)
}
