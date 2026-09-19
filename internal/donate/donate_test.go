package donate

import "testing"

func TestRegisterGet(t *testing.T) {
	r := New()
	r.Register(Entry{Chain: "dero", Address: "d1", Note: "mainnet"})
	r.Register(Entry{Chain: "xmr", Address: "x1"})
	e, ok := r.Get("DERO") // case-insensitive
	if !ok || e.Address != "d1" {
		t.Fatalf("get dero: %+v ok=%v", e, ok)
	}
	if _, ok := r.Get("zcash"); ok {
		t.Fatal("unregistered chain should miss")
	}
}

func TestRender(t *testing.T) {
	r := New()
	r.Register(Entry{Chain: "dero", Address: "d1"})
	r.Register(Entry{Chain: "xmr", Address: "x1", Note: "note"})
	s := r.Render()
	if s == "" {
		t.Fatal("empty render")
	}
	if len(r.Chains()) != 2 {
		t.Fatalf("chains=%v", r.Chains())
	}
}
