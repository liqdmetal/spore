package bitcoin

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/liqdmetal/spore/internal/chain"
)

func TestPointerScriptFitAndOverflow(t *testing.T) {
	p := make([]byte, 74)
	p[0] = 1
	p[66] = 1
	if _, err := PointerScript(p); err != nil {
		t.Fatal(err)
	}
	if _, err := PointerScript(make([]byte, 75)); err == nil {
		t.Fatal("expected overflow")
	}
}
func TestParseExactE2(t *testing.T) {
	p := make([]byte, 74)
	p[0] = 1
	p[66] = 1
	s, _ := PointerScript(p)
	got, ok := ParsePointerScript(s)
	if !ok || string(got) != string(p) {
		t.Fatal("not parsed")
	}
	bad := append([]byte{}, s...)
	bad = append(bad, 0)
	if _, ok := ParsePointerScript(bad); ok {
		t.Fatal("accepted malformed")
	}
}
func TestCanonicalPointerValidation(t *testing.T) {
	cases := [][]byte{
		append([]byte{2, 0}, make([]byte, 72)...),
		append([]byte{1, 1}, make([]byte, 72)...),
		append([]byte{1, 0}, make([]byte, 72)...),
	}
	for _, p := range cases {
		if _, err := PointerScript(p); err == nil {
			t.Fatal("accepted non-canonical pointer")
		}
	}
}

func TestBitcoinAddressToPkScript(t *testing.T) {
	addr := "1BitcoinEaterAddressDontSendf59kuE"
	a, err := btcutil.DecodeAddress(addr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	got, err := btcAddress(addr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	want, err := txscript.PayToAddrScript(a)
	if err != nil || string(got) != string(want) {
		t.Fatalf("not address pkScript: %x", got)
	}
	if _, err := btcAddress(addr, &chaincfg.TestNet3Params); err == nil {
		t.Fatal("accepted wrong network")
	}
}

func TestBackendInterface(t *testing.T) {
	var _ chain.Chain = (*Backend)(nil)
	_ = context.Background()
}
