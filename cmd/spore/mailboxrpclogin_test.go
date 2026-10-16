package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func mailboxRPCLoginFlags(t *testing.T, args []string) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("mailbox host", flag.ContinueOnError)
	addChainFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestMailboxRPCLoginComesFromEnvironmentWhenFlagAbsent(t *testing.T) {
	t.Setenv(envRPCLogin, "wallet:secret")
	fs := mailboxRPCLoginFlags(t, nil)
	var warn bytes.Buffer
	if err := applyMailboxRPCLogin(fs, &warn); err != nil {
		t.Fatal(err)
	}
	if got := fs.Lookup("rpc-login").Value.String(); got != "wallet:secret" {
		t.Fatalf("rpc-login = %q, want the environment value", got)
	}
	if warn.Len() != 0 {
		t.Fatalf("environment-sourced login must not warn: %q", warn.String())
	}
}

func TestMailboxRPCLoginFlagWinsWithWarning(t *testing.T) {
	t.Setenv(envRPCLogin, "env:ignored")
	fs := mailboxRPCLoginFlags(t, []string{"-rpc-login", "flag:wins"})
	var warn bytes.Buffer
	if err := applyMailboxRPCLogin(fs, &warn); err != nil {
		t.Fatal(err)
	}
	if got := fs.Lookup("rpc-login").Value.String(); got != "flag:wins" {
		t.Fatalf("rpc-login = %q, want the explicit flag", got)
	}
	if !strings.Contains(warn.String(), "ps") || !strings.Contains(warn.String(), envRPCLogin) {
		t.Fatalf("command-line login must warn and name the environment alternative: %q", warn.String())
	}
}

func TestMailboxRPCLoginUnsetWhenNeitherPresent(t *testing.T) {
	t.Setenv(envRPCLogin, "")
	fs := mailboxRPCLoginFlags(t, nil)
	if err := applyMailboxRPCLogin(fs, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := fs.Lookup("rpc-login").Value.String(); got != "" {
		t.Fatalf("rpc-login = %q, want empty when nothing is configured", got)
	}
}
