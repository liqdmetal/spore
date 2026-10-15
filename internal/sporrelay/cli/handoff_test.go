package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/sporrelay"
)

func TestRegisterExportsObservationOnlyAfterMatchingSuccess(t *testing.T) {
	keyPath, issuerPath, grantPath, _, _, work := prepareInputs(t)
	work.DescriptionCommitment = handoff.Commitment([]byte("brief"))
	work.PolicyHash = handoff.Commitment([]byte("policy"))
	commandFile := filepath.Join(t.TempDir(), "command.json")
	if err := Run(context.Background(), prepareArgs(keyPath, issuerPath, grantPath, commandFile, work), io.Discard); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var mode atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch mode.Load() {
		case 1:
			http.Error(w, "offline", 503)
			return
		case 2:
			_, _ = w.Write([]byte(`{"ok":false,"error":"refused"}`))
			return
		case 3:
			_, _ = w.Write([]byte(`{"ok":true,"result":{"objective_id":"other"}}`))
			return
		}
		var command sporrelay.AuthorizedWorkOrderCommand
		if err := json.NewDecoder(r.Body).Decode(&command); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": command.Command.Payload})
	}))
	defer server.Close()
	for _, m := range []int32{1, 2, 3} {
		mode.Store(m)
		output := filepath.Join(t.TempDir(), "observation.json")
		var stdout strings.Builder
		err := Run(context.Background(), []string{"register", "-command", commandFile, "-relay-url", server.URL, "-out", output}, &stdout)
		if err == nil {
			t.Fatal("export accepted failed registration")
		}
		if stdout.Len() != 0 {
			t.Fatal("failure reported success")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("failure left observation behind")
		}
	}
	mode.Store(0)
	output := filepath.Join(t.TempDir(), "observation.json")
	args := []string{"register", "-command", commandFile, "-relay-url", server.URL, "-out", output}
	if err := Run(context.Background(), args, io.Discard); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var observation handoff.Registration
	if err := handoff.DecodeJSON(raw, &observation, 16<<10); err != nil {
		t.Fatal(err)
	}
	if err := observation.Validate(); err != nil {
		t.Fatal(err)
	}
	if observation.Objective != work || observation.RelayURL != server.URL {
		t.Fatal("observation differs from registered terms")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(output)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatal("observation readable by others")
		}
	}
	before := requests.Load()
	if err := Run(context.Background(), args, io.Discard); err == nil {
		t.Fatal("overwrite accepted")
	}
	if requests.Load() != before {
		t.Fatal("resubmitted before checking output path")
	}
	bad := []string{"register", "-command", commandFile, "-relay-url", server.URL, "-out", "-"}
	if err := Run(context.Background(), bad, io.Discard); err == nil {
		t.Fatal("stdout export allowed")
	}
	if requests.Load() != before {
		t.Fatal("stdout failure submitted command")
	}
}

func TestRegisterObservationRejectsNonHashCommitmentsBeforeMutation(t *testing.T) {
	path := writeCommand(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "should not submit", 500) }))
	defer server.Close()
	err := Run(context.Background(), []string{"register", "-command", path, "-relay-url", server.URL, "-out", filepath.Join(t.TempDir(), "observation.json")}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("wrong validation: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid handoff commitments submitted")
	}
}
