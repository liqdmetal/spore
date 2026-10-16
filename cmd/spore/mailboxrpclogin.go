package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// envRPCLogin is the environment variable mailbox host reads for the wallet
// RPC basic-auth login when -rpc-login is not given.
const envRPCLogin = "SPORE_RPC_LOGIN"

// applyMailboxRPCLogin fills -rpc-login from SPORE_RPC_LOGIN when the flag was
// not set. Anything in argv is visible to every local user through ps, so the
// shipped systemd unit supplies the login through an EnvironmentFile instead.
// An explicit -rpc-login still works, with a warning, for compatibility.
func applyMailboxRPCLogin(fs *flag.FlagSet, warn io.Writer) error {
	f := fs.Lookup("rpc-login")
	if f == nil {
		return nil
	}
	if f.Value.String() != "" {
		fmt.Fprintln(warn, "mailbox host: WARNING -rpc-login on the command line is visible to other local users via ps; set SPORE_RPC_LOGIN in the environment instead")
		return nil
	}
	if v := os.Getenv(envRPCLogin); v != "" {
		return fs.Set("rpc-login", v)
	}
	return nil
}
