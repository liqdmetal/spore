package main

// Refused fabric init pointers. `spore fabric subscribe` never ingests an init
// frame: bootstrap rides the chain. Each refusal is counted in the endpoint
// state directory, so `spore status` can report it after the subscriber exits.
// Only the count is stored. The file holds no key or message material.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/liqdmetal/spore/internal/bounds"
)

const fabricRefusalFile = "fabric-refusals.json"

type fabricRefusalRecord struct {
	Refused uint64 `json:"refused"`
}

// readFabricRefusals returns the persisted refusal count in stateDir. A missing
// file means no refusals have been recorded.
func readFabricRefusals(stateDir string) (uint64, error) {
	data, err := bounds.ReadBound(filepath.Join(stateDir, fabricRefusalFile), 4<<10)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var rec fabricRefusalRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return 0, fmt.Errorf("decode %s: %w", fabricRefusalFile, err)
	}
	return rec.Refused, nil
}

// noteFabricRefusal adds one refusal to the persisted count in stateDir. An
// empty stateDir records nothing.
func noteFabricRefusal(stateDir string) error {
	if stateDir == "" {
		return nil
	}
	n, err := readFabricRefusals(stateDir)
	if err != nil {
		return err
	}
	return writeFabricRefusals(stateDir, n+1)
}

// writeFabricRefusals replaces the count atomically: a temp file is written and
// synced, then renamed over the old one.
func writeFabricRefusals(stateDir string, n uint64) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(fabricRefusalRecord{Refused: n})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".fabric-refusals-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(e error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return e
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, filepath.Join(stateDir, fabricRefusalFile)); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// addFabricRefusals reports the persisted refused-init count in stateDir. With
// no file, or a zero count, nothing is added, so status output is unchanged.
func addFabricRefusals(add func(id, status, detail, action string), stateDir string) {
	if stateDir == "" {
		return
	}
	n, err := readFabricRefusals(stateDir)
	if err != nil {
		add("fabric-refusals", "error", fmt.Sprintf("Cannot read refused fabric init count: %v", err), "Check the state directory permissions.")
		return
	}
	if n == 0 {
		return
	}
	add("fabric-refusals", "warning",
		fmt.Sprintf("refused fabric init pointers: %d (bootstrap rides the chain; these were not ingested)", n),
		"Init frames should arrive on chain, not over fabric. Check which relay or sender is delivering init pointers over fabric.")
}
