package main

// Regression: `spore msg dex fees` doubles as the configuration doctor for
// the SPORE_SAP_* seam. It must report the contract IDs AS the settlement
// commands see them — i.e. after seeding from the environment. It previously
// read the sap globals directly and printed (unset) on a correctly
// configured deployment (env set, no prior sap call in the process), which is
// precisely the confusion the doctor exists to dispel.

import (
	"os"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/sap"
)

func TestDexFeesReportsEnvConfiguredContractIDs(t *testing.T) {
	// Save and restore the sap globals and the environment so this test
	// cannot leak state into other tests in the package.
	savedHTLC, savedDEX, savedWDERO := sap.ContractIDs()
	t.Cleanup(func() { sap.SetContractIDs(savedHTLC, savedDEX, savedWDERO) })

	const (
		envHTLC  = "test-htlc-scid"
		envDEX   = "test-dex-scid"
		envWDERO = "test-wdero-scid"
	)
	t.Setenv(sap.EnvHTLCSignature, envHTLC)
	t.Setenv(sap.EnvDEXSignature, envDEX)
	t.Setenv(sap.EnvWrappedDeroName, envWDERO)
	// Reset the globals to unconfigured so the test proves the ENV SEEDING
	// (the bug: fees read globals without seeding), not leftover state.
	sap.SetContractIDs("", "", "")

	out := e2eCaptureStdout(t, func() { msgDEXFees() })

	for _, want := range []string{envHTLC, envDEX, envWDERO} {
		if !strings.Contains(out, want) {
			t.Fatalf("msg dex fees output missing configured %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "(unset)") {
		t.Fatalf("configured deployment must never print (unset):\n%s", out)
	}
}

func TestDexFeesPrintsUnsetWhenUnconfigured(t *testing.T) {
	savedHTLC, savedDEX, savedWDERO := sap.ContractIDs()
	t.Cleanup(func() { sap.SetContractIDs(savedHTLC, savedDEX, savedWDERO) })

	for _, env := range []string{sap.EnvHTLCSignature, sap.EnvDEXSignature, sap.EnvWrappedDeroName} {
		if err := os.Unsetenv(env); err != nil {
			t.Fatal(err)
		}
	}
	sap.SetContractIDs("", "", "")

	out := e2eCaptureStdout(t, func() { msgDEXFees() })

	if got := strings.Count(out, "(unset)"); got != 3 {
		t.Fatalf("unconfigured deployment must print exactly 3 (unset) markers, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "90% to LPs, 10% to treasury") {
		t.Fatalf("fee schedule line missing:\n%s", out)
	}
}
