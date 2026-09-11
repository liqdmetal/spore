package main

import (
	"strings"
	"testing"
)

func TestDeroWhisperSendRequiresE2Identity(t *testing.T) {
	_, err := parseDeroE2SendArgs("whisper send", []string{"-to", "dest", "-msg-file", "-"}, false)
	if err == nil || !strings.Contains(err.Error(), "-identity") {
		t.Fatalf("short DERO whisper accepted without ratchet identity: %v", err)
	}
}

func TestDeroCompatAliasesSelectOnlyDero(t *testing.T) {
	if !deroCompatChain([]string{"-to", "dest"}) {
		t.Fatal("omitted -chain must retain the DERO default")
	}
	if !deroCompatChain([]string{"-chain=dero"}) {
		t.Fatal("explicit DERO chain not selected")
	}
	if deroCompatChain([]string{"-chain", "evm"}) {
		t.Fatal("non-DERO chain incorrectly selected DERO compatibility path")
	}
}

func TestDeroReceiveAliasSelectsE2OnlyWithRatchetKit(t *testing.T) {
	if deroE2ReceiveArgsForChain([]string{"-chain", "dero"}) {
		t.Fatal("bare DERO receiver unexpectedly selected E2")
	}
	if !deroE2ReceiveArgsForChain([]string{"-chain", "dero", "-identity", "identity.key", "-spk", "spk.key", "-state-dir", "state", "-state-key", "state.key", "-store", "https://mailbox.invalid"}) {
		t.Fatal("DERO receiver with E2 kit was not routed to recv-e2")
	}
	if deroE2ReceiveArgsForChain([]string{"-chain", "evm", "-identity", "identity.key", "-spk", "spk.key"}) {
		t.Fatal("non-DERO receiver was routed to the DERO E2 alias")
	}
	if deroE2ReceiveArgs([]string{"-rpc", "http://wallet.invalid"}) {
		t.Fatal("bare receiver unexpectedly selected E2; it must remain legacy-compatible")
	}
}

func TestDeroRingSizePolicy(t *testing.T) {
	fs := newDeroE2SendFlags("ring-policy", false)
	for _, tc := range []struct {
		name string
		args []string
		want uint64
		ok   bool
	}{
		{name: "default", want: 16, ok: true},
		{name: "eight", args: []string{"-ringsize", "8"}, want: 8, ok: true},
		{name: "sixteen", args: []string{"-ringsize", "16"}, want: 16, ok: true},
		{name: "two", args: []string{"-ringsize", "2"}},
		{name: "nine", args: []string{"-ringsize", "9"}},
		{name: "thirty-two", args: []string{"-ringsize", "32"}},
	} {
		if err := fs.Parse(tc.args); err != nil {
			t.Fatalf("%s parse: %v", tc.name, err)
		}
		got, err := deroRingSizeFromFlags(fs, "dero")
		if tc.ok {
			if err != nil || got != tc.want {
				t.Fatalf("%s: got %d, err %v; want %d", tc.name, got, err, tc.want)
			}
		} else if err == nil {
			t.Fatalf("%s: invalid ring size accepted", tc.name)
		}
		fs = newDeroE2SendFlags("ring-policy", false)
	}
}

func TestDeroLongBodyMapsFileToE2Body(t *testing.T) {
	opts, err := parseDeroE2SendArgs("whisper send-long", []string{
		"-to", "dest", "-identity", "identity.key", "-file", "body.bin",
	}, true)
	if err != nil {
		t.Fatalf("long DERO path rejected valid E2 arguments: %v", err)
	}
	if opts.chain != "dero" {
		t.Fatalf("long DERO path selected chain %q", opts.chain)
	}
	if opts.msgFile != "body.bin" {
		t.Fatalf("long body was not routed to E2 msg-file: %q", opts.msgFile)
	}
}

func TestDeroE2ShortPathUsesStdinSafeBodyInput(t *testing.T) {
	opts, err := parseDeroE2SendArgs("whisper send", []string{
		"-to", "dest", "-identity", "identity.key",
	}, false)
	if err != nil {
		t.Fatalf("short DERO E2 path rejected stdin body input: %v", err)
	}
	if opts.msgFile != "-" {
		t.Fatalf("short DERO E2 default body source = %q, want stdin", opts.msgFile)
	}
}
