package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/liqdmetal/spore/internal/continuity"
	"github.com/liqdmetal/spore/internal/dero"
	"golang.org/x/term"
)

// continuityAnchorCreate makes an opaque chain commitment locally. It does not
// contact a wallet or post anything.
func continuityAnchorCreate(args []string) {
	fs := flag.NewFlagSet("continuity anchor-create", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	policyPath := fs.String("policy", "", "quorum policy JSON path")
	out := fs.String("out", "", "chain anchor JSON output path")
	_ = fs.Parse(args)
	if *vaultPath == "" || *policyPath == "" || *out == "" {
		check(errors.New("continuity anchor-create requires -vault -policy and -out"))
	}
	v := readContinuityVault(*vaultPath)
	policy := readQuorumPolicy(*policyPath)
	ca, err := continuity.NewChainAnchor(v, policy)
	check(err)
	check(writeJSONPrivate(*out, ca))
	fmt.Printf("continuity chain anchor created: %s\n", *out)
	fmt.Printf("vault id: %s\n", ca.VaultID)
	fmt.Printf("policy id: %s\n", ca.PolicyID)
	fmt.Printf("check-in sequence: %d\n", ca.CheckInSeq)
	fmt.Printf("deadline: %d\n", ca.Deadline)
}

func continuityAnchorVerify(args []string) {
	fs := flag.NewFlagSet("continuity anchor-verify", flag.ExitOnError)
	anchorPath := fs.String("anchor", "", "chain anchor JSON path")
	vaultPath := fs.String("vault", "", "vault JSON path")
	policyPath := fs.String("policy", "", "quorum policy JSON path")
	_ = fs.Parse(args)
	if *anchorPath == "" || *vaultPath == "" || *policyPath == "" {
		check(errors.New("continuity anchor-verify requires -anchor -vault and -policy"))
	}
	ca := readChainAnchor(*anchorPath)
	v := readContinuityVault(*vaultPath)
	policy := readQuorumPolicy(*policyPath)
	check(ca.VerifyAgainst(v, policy))
	fmt.Printf("VALID continuity chain anchor bound to vault %s\n", ca.VaultID)
}

// continuityAnchorPost is the only command in this slice that contacts the
// wallet. It requires a local vault and policy re-verification immediately
// before posting, and never runs automatically during release.
func continuityAnchorPost(args []string) {
	fs := flag.NewFlagSet("continuity anchor-post", flag.ExitOnError)
	anchorPath := fs.String("anchor", "", "chain anchor JSON path")
	vaultPath := fs.String("vault", "", "vault JSON path")
	policyPath := fs.String("policy", "", "quorum policy JSON path")
	to := fs.String("to", "", "DERO destination address for the minimum-postage commitment")
	ringsize := fs.Uint64("ringsize", dero.DefaultSporeRingSize, "DERO Spore ring size: 8 or 16 (default 16)")
	rpc := fs.String("rpc", "http://127.0.0.1:20209/json_rpc", "wallet RPC /json_rpc endpoint")
	rpcUser := fs.String("rpc-user", "", "wallet RPC basic-auth username (password is prompted securely)")
	_ = fs.Parse(args)
	if *anchorPath == "" || *vaultPath == "" || *policyPath == "" || *to == "" {
		check(errors.New("continuity anchor-post requires -anchor -vault -policy and -to"))
	}
	check(dero.ValidateSporeRingSize(*ringsize))
	ca := readChainAnchor(*anchorPath)
	v := readContinuityVault(*vaultPath)
	policy := readQuorumPolicy(*policyPath)
	check(ca.VerifyAgainst(v, policy))
	wire, err := ca.ToDEROAnchor()
	check(err)
	password := ""
	if *rpcUser != "" {
		password, err = promptRPCPassword()
		check(err)
	}
	txid, err := dero.NewClient(*rpc, *rpcUser, password).PostAnchor(context.Background(), *to, wire, *ringsize)
	check(err)
	fmt.Printf("continuity chain anchor posted: txid %s\n", txid)
	fmt.Printf("destination: %s\n", *to)
	fmt.Printf("ringsize: %d\n", *ringsize)
	fmt.Println("minimum postage was used; no payload plaintext or recipient key was sent")
}

func readChainAnchor(path string) *continuity.ChainAnchor {
	raw, err := readContinuityArtifact(path)
	check(err)
	ca, err := continuity.ParseChainAnchor(raw)
	check(err)
	return ca
}

func promptRPCPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("continuity anchor-post: wallet password requires an interactive terminal; use a local wallet without RPC auth")
	}
	fmt.Fprint(os.Stderr, "Wallet RPC password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(password), "\r\n"), nil
}
