package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/continuity"
)

func continuityQuorumCreate(args []string) {
	fs := flag.NewFlagSet("continuity quorum-create", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	threshold := fs.Uint("threshold", 0, "minimum number of independent attestations")
	attesterHex := fs.String("attester-pub", "", "comma-separated observer Ed25519 public keys")
	out := fs.String("out", "", "quorum policy JSON output path")
	_ = fs.Parse(args)
	if *vaultPath == "" || *threshold == 0 || *attesterHex == "" || *out == "" {
		check(errors.New("continuity quorum-create requires -vault -threshold -attester-pub and -out"))
	}
	v := readContinuityVault(*vaultPath)
	attesters, err := parseObserverPubs(*attesterHex)
	check(err)
	policy, err := continuity.NewQuorumPolicy(v, *threshold, attesters)
	check(err)
	check(writeJSONPrivate(*out, policy))
	fmt.Printf("continuity quorum policy created: %s\n", *out)
	fmt.Printf("policy id: %s\n", policy.PolicyID)
	fmt.Printf("threshold: %d of %d\n", policy.Threshold, len(policy.Attesters))
}

func continuityAttest(args []string) {
	fs := flag.NewFlagSet("continuity attest", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	policyPath := fs.String("policy", "", "quorum policy JSON path")
	keyPath := fs.String("observer-key", "", "approved observer Ed25519 private key file")
	out := fs.String("out", "", "attestation JSON output path")
	at := fs.Int64("at", 0, "evaluation time as Unix seconds (default: current time)")
	_ = fs.Parse(args)
	if *vaultPath == "" || *policyPath == "" || *keyPath == "" || *out == "" {
		check(errors.New("continuity attest requires -vault -policy -observer-key and -out"))
	}
	v := readContinuityVault(*vaultPath)
	policy := readQuorumPolicy(*policyPath)
	check(continuity.VerifyPolicyForVault(policy, v))
	key, err := readObserverKey(*keyPath)
	check(err)
	now := *at
	if now == 0 {
		now = time.Now().Unix()
	}
	att, err := continuity.Attest(policy, v, key, now)
	check(err)
	check(writeJSONPrivate(*out, att))
	fmt.Printf("continuity attestation written: %s\n", *out)
	fmt.Printf("attester: %s\n", att.Attester)
}

func continuityQuorum(args []string) {
	fs := flag.NewFlagSet("continuity quorum", flag.ExitOnError)
	policyPath := fs.String("policy", "", "quorum policy JSON path")
	attestationPaths := fs.String("attestations", "", "comma-separated attestation JSON paths")
	out := fs.String("out", "", "quorum release JSON output path")
	_ = fs.Parse(args)
	if *policyPath == "" || *attestationPaths == "" || *out == "" {
		check(errors.New("continuity quorum requires -policy -attestations and -out"))
	}
	policy := readQuorumPolicy(*policyPath)
	paths := splitNonEmpty(*attestationPaths)
	if len(paths) == 0 {
		check(errors.New("continuity quorum requires at least one attestation"))
	}
	atts := make([]continuity.QuorumAttestation, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		check(err)
		att, err := continuity.ParseQuorumAttestation(raw)
		check(err)
		atts = append(atts, *att)
	}
	q, err := continuity.NewQuorumRelease(policy, atts)
	check(err)
	check(writeJSONPrivate(*out, q))
	fmt.Printf("continuity quorum release written: %s\n", *out)
	fmt.Printf("quorum id: %s\n", q.QuorumID)
}

func continuityVerifyQuorum(args []string) {
	fs := flag.NewFlagSet("continuity verify-quorum", flag.ExitOnError)
	quorumPath := fs.String("quorum", "", "quorum release JSON path")
	vaultPath := fs.String("vault", "", "optional vault JSON path for exact binding verification")
	_ = fs.Parse(args)
	if *quorumPath == "" {
		check(errors.New("continuity verify-quorum requires -quorum"))
	}
	q := readQuorumRelease(*quorumPath)
	if *vaultPath != "" {
		check(continuity.VerifyNoticeQuorumForVault(readContinuityVault(*vaultPath), q))
		fmt.Printf("VALID continuity quorum bound to vault %s (%s)\n", q.Policy.VaultID, *quorumPath)
		return
	}
	check(q.Verify())
	fmt.Printf("VALID continuity quorum for vault %s (%s)\n", q.Policy.VaultID, *quorumPath)
}

func continuityReleaseQuorum(args []string) {
	fs := flag.NewFlagSet("continuity release-quorum", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	quorumPath := fs.String("quorum", "", "quorum release JSON path")
	recipientPath := fs.String("recipient-key", "", "designated recipient X25519 private key file")
	out := fs.String("out", "", "plaintext release output path")
	at := fs.Int64("at", 0, "evaluation time as Unix seconds (default: current time)")
	_ = fs.Parse(args)
	if *vaultPath == "" || *quorumPath == "" || *recipientPath == "" || *out == "" {
		check(errors.New("continuity release-quorum requires -vault -quorum -recipient-key and -out"))
	}
	v := readContinuityVault(*vaultPath)
	q := readQuorumRelease(*quorumPath)
	recipient, err := readContinuityKey(*recipientPath)
	check(err)
	now := *at
	if now == 0 {
		now = time.Now().Unix()
	}
	plain, err := continuity.ReleaseWithQuorum(v, q, recipient, now)
	check(err)
	check(writePrivateBytes(*out, plain))
	fmt.Printf("continuity quorum payload released to %s\n", *out)
}

func parseObserverPubs(raw string) ([][]byte, error) {
	parts := splitNonEmpty(raw)
	if len(parts) == 0 {
		return nil, errors.New("continuity: no observer public keys provided")
	}
	pubs := make([][]byte, 0, len(parts))
	for _, part := range parts {
		pub, err := hex.DecodeString(part)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("continuity: each observer public key must contain exactly 64 hex characters")
		}
		pubs = append(pubs, pub)
	}
	return pubs, nil
}

func splitNonEmpty(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func readQuorumPolicy(path string) *continuity.QuorumPolicy {
	raw, err := os.ReadFile(path)
	check(err)
	policy, err := continuity.ParseQuorumPolicy(raw)
	check(err)
	return policy
}

func readQuorumRelease(path string) *continuity.QuorumRelease {
	raw, err := os.ReadFile(path)
	check(err)
	q, err := continuity.ParseQuorumRelease(raw)
	check(err)
	return q
}

func writeJSONPrivate(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicPrivate(path, append(raw, '\n'))
}
