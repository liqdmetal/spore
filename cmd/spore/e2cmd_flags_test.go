package main

import (
	"testing"
)

// Audit H1/H2 regression tests, at the CLI layer. The -key/-peer-pub flags
// (envelope-v2 wrapping on ratcheted frames) were removed: they made the
// documented default send path undecryptable by default receivers. If anyone
// reintroduces them — or reintroduces SecureWire — these tests go red.

func TestE2SendFlagsetHasNoSecureWireFlags(t *testing.T) {
	fs, _ := newSendE2Flagset()
	if fs.Lookup("key") != nil {
		t.Fatal("send-e2 re-registered -key: envelope wrapping regression (audit H1)")
	}
	if fs.Lookup("peer-pub") != nil {
		t.Fatal("send-e2 re-registered -peer-pub: envelope wrapping regression (audit H1)")
	}
}

func TestE2RecvFlagsetHasNoSecureWireFlags(t *testing.T) {
	fs, _ := newRecvE2Flagset()
	if fs.Lookup("key") != nil {
		t.Fatal("recv-e2 re-registered -key: envelope unwrap regression (audit H1)")
	}
	if fs.Lookup("peer-pub") != nil {
		t.Fatal("recv-e2 re-registered -peer-pub on the receiver")
	}
}

func TestSendE2FlagsetKeepsCoreFlags(t *testing.T) {
	fs, _ := newSendE2Flagset()
	for _, name := range []string{"to", "identity", "bundle", "bundle-url", "bundle-token", "pinned-sig", "msg-file", "ttl", "state-dir", "state-key", "chain", "amount", "require-approval"} {
		if fs.Lookup(name) == nil {
			t.Fatalf("send-e2 lost the -%s flag", name)
		}
	}
}

func TestRecvE2FlagsetKeepsCoreFlags(t *testing.T) {
	fs, _ := newRecvE2Flagset()
	for _, name := range []string{"identity", "spk", "opk-pool", "interval", "auto-ack", "out-dir", "ntfy", "maildb", "store", "state-dir", "state-key"} {
		if fs.Lookup(name) == nil {
			t.Fatalf("recv-e2 lost the -%s flag", name)
		}
	}
}
