package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/continuity"
	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

// continuitycmd exposes the deliberately explicit continuity-vault workflow.
// It never contacts a network or moves funds: operators create/check-in/status
// locally, and a designated recipient explicitly releases after the deadline.
func continuitycmd(args []string) {
	if len(args) == 0 {
		continuityUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		continuityCreate(args[1:])
	case "check-in":
		continuityCheckIn(args[1:])
	case "status":
		continuityStatus(args[1:])
	case "release":
		continuityRelease(args[1:])
	case "verify":
		continuityVerify(args[1:])
	case "observer-keygen":
		continuityObserverKeygen(args[1:])
	case "observe":
		continuityObserve(args[1:])
	case "verify-notice":
		continuityVerifyNotice(args[1:])
	case "quorum-create":
		continuityQuorumCreate(args[1:])
	case "attest":
		continuityAttest(args[1:])
	case "quorum":
		continuityQuorum(args[1:])
	case "verify-quorum":
		continuityVerifyQuorum(args[1:])
	case "release-quorum":
		continuityReleaseQuorum(args[1:])
	case "anchor-create":
		continuityAnchorCreate(args[1:])
	case "anchor-verify":
		continuityAnchorVerify(args[1:])
	case "anchor-post":
		continuityAnchorPost(args[1:])
	case "-h", "--help":
		continuityUsage()
	default:
		fmt.Fprintf(os.Stderr, "continuity: unknown subcommand %q (want create|check-in|status|release|verify|observer-keygen|observe|verify-notice|quorum-create|attest|quorum|verify-quorum|release-quorum|anchor-create|anchor-verify|anchor-post)\n", args[0])
		os.Exit(2)
	}
}

func continuityUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore continuity create -owner-key FILE -recipient-pub HEX[,HEX,...] -file PAYLOAD \
      -out VAULT [-interval 24h] [-grace 24h]
  spore continuity check-in -vault VAULT -owner-key FILE
  spore continuity status -vault VAULT [-at UNIX]
  spore continuity release -vault VAULT -recipient-key FILE -out PAYLOAD [-at UNIX]
  spore continuity verify -vault VAULT
  spore continuity observer-keygen -out OBSERVER_KEY
  spore continuity observe -vault VAULT -observer-key OBSERVER_KEY -out NOTICE [-at UNIX]
  spore continuity verify-notice -notice NOTICE [-vault VAULT]
  spore continuity quorum-create -vault VAULT -threshold N -attester-pub HEX[,HEX,...] -out POLICY
  spore continuity attest -vault VAULT -policy POLICY -observer-key KEY -out ATTESTATION [-at UNIX]
  spore continuity quorum -policy POLICY -attestations A1[,A2,...] -out QUORUM
  spore continuity verify-quorum -quorum QUORUM [-vault VAULT]
  spore continuity release-quorum -vault VAULT -quorum QUORUM -recipient-key KEY -out PAYLOAD [-at UNIX]
  spore continuity anchor-create -vault VAULT -policy POLICY -out ANCHOR
  spore continuity anchor-verify -anchor ANCHOR -vault VAULT -policy POLICY
  spore continuity anchor-post -anchor ANCHOR -vault VAULT -policy POLICY -to DERO_ADDR [-rpc URL] [-rpc-user USER] [-ringsize 8|16]
    (with -rpc-user, the wallet password is read from a masked terminal prompt)

The vault contains ciphertext, recipient envelopes, and signed liveness records;
no plaintext or private key is written into it. Check-in must occur strictly
before the current deadline. Release is explicit and does not send money,
contact anyone, or trigger an on-chain action.`)
}

func continuityCreate(args []string) {
	fs := flag.NewFlagSet("continuity create", flag.ExitOnError)
	ownerPath := fs.String("owner-key", "", "owner X25519 private key file containing 64 hex characters")
	recipientHex := fs.String("recipient-pub", "", "comma-separated recipient X25519 public keys, each 64 hex characters")
	payloadPath := fs.String("file", "", "plaintext payload to seal")
	out := fs.String("out", "", "vault JSON output path")
	interval := fs.Duration("interval", 24*time.Hour, "check-in interval")
	grace := fs.Duration("grace", 24*time.Hour, "additional release grace")
	_ = fs.Parse(args)
	if *ownerPath == "" || *recipientHex == "" || *payloadPath == "" || *out == "" {
		check(errors.New("continuity create requires -owner-key -recipient-pub -file and -out"))
	}
	owner, err := readContinuityKey(*ownerPath)
	check(err)
	payload, err := os.ReadFile(*payloadPath)
	check(err)
	pubs, err := parseRecipientPubs(*recipientHex)
	check(err)
	v, err := continuity.Create(continuity.CreateOptions{
		OwnerPriv: owner, Recipients: pubs, Payload: payload,
		CreatedAt: time.Now().Unix(), Interval: *interval, Grace: *grace,
	})
	check(err)
	check(writeContinuityVault(*out, v))
	fmt.Printf("continuity vault created: %s\n", *out)
	fmt.Printf("vault id: %s\n", v.VaultID)
	fmt.Printf("release due: %s\n", time.Unix(v.Checkins[len(v.Checkins)-1].Deadline, 0).UTC().Format(time.RFC3339))
}

func continuityCheckIn(args []string) {
	fs := flag.NewFlagSet("continuity check-in", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	ownerPath := fs.String("owner-key", "", "owner X25519 private key file")
	_ = fs.Parse(args)
	if *vaultPath == "" || *ownerPath == "" {
		check(errors.New("continuity check-in requires -vault and -owner-key"))
	}
	v := readContinuityVault(*vaultPath)
	owner, err := readContinuityKey(*ownerPath)
	check(err)
	check(continuity.CheckIn(v, owner, time.Now().Unix()))
	check(writeContinuityVault(*vaultPath, v))
	last := v.Checkins[len(v.Checkins)-1]
	fmt.Printf("continuity check-in accepted: seq %d; next deadline %s\n", last.Seq, time.Unix(last.Deadline, 0).UTC().Format(time.RFC3339))
}

func continuityStatus(args []string) {
	fs := flag.NewFlagSet("continuity status", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	at := fs.Int64("at", 0, "evaluation time as Unix seconds (default: current time)")
	_ = fs.Parse(args)
	if *vaultPath == "" {
		check(errors.New("continuity status requires -vault"))
	}
	v := readContinuityVault(*vaultPath)
	now := *at
	if now == 0 {
		now = time.Now().Unix()
	}
	st, err := v.Status(now)
	check(err)
	state := "WAITING"
	if st.Releasable {
		state = "RELEASABLE"
	}
	fmt.Printf("%s vault=%s due=%s checkins=%d\n", state, st.VaultID, time.Unix(st.DueAt, 0).UTC().Format(time.RFC3339), st.CheckInCount)
}

func continuityRelease(args []string) {
	fs := flag.NewFlagSet("continuity release", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	recipientPath := fs.String("recipient-key", "", "designated recipient X25519 private key file")
	out := fs.String("out", "", "plaintext release output path")
	at := fs.Int64("at", 0, "evaluation time as Unix seconds (default: current time)")
	_ = fs.Parse(args)
	if *vaultPath == "" || *recipientPath == "" || *out == "" {
		check(errors.New("continuity release requires -vault -recipient-key and -out"))
	}
	v := readContinuityVault(*vaultPath)
	recipient, err := readContinuityKey(*recipientPath)
	check(err)
	now := *at
	if now == 0 {
		now = time.Now().Unix()
	}
	plain, err := continuity.Release(v, recipient, now)
	check(err)
	if err := writePrivateBytes(*out, plain); err != nil {
		check(err)
	}
	fmt.Printf("continuity payload released to %s\n", *out)
}

func continuityVerify(args []string) {
	fs := flag.NewFlagSet("continuity verify", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	_ = fs.Parse(args)
	if *vaultPath == "" {
		check(errors.New("continuity verify requires -vault"))
	}
	v := readContinuityVault(*vaultPath)
	check(v.Verify())
	fmt.Printf("VALID continuity vault %s (%s)\n", v.VaultID, *vaultPath)
}

func readContinuityKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != sporecrypto.KeySize {
		return nil, errors.New("continuity: key file must contain exactly 64 hex characters")
	}
	return key, nil
}

func parseRecipientPubs(raw string) ([][]byte, error) {
	parts := strings.Split(raw, ",")
	pubs := make([][]byte, 0, len(parts))
	for _, part := range parts {
		pub, err := hex.DecodeString(strings.TrimSpace(part))
		if err != nil || len(pub) != sporecrypto.KeySize {
			return nil, errors.New("continuity: each recipient public key must contain exactly 64 hex characters")
		}
		pubs = append(pubs, pub)
	}
	return pubs, nil
}

func readContinuityVault(path string) *continuity.Vault {
	raw, err := readContinuityArtifact(path)
	check(err)
	v, err := continuity.Parse(raw)
	check(err)
	return v
}

func readContinuityArtifact(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("continuity: artifact path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("continuity: artifact path must be a regular file")
	}
	if info.Size() > continuity.MaxArtifactBytes {
		return nil, continuity.ErrArtifactTooLarge
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, continuity.MaxArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > continuity.MaxArtifactBytes {
		return nil, continuity.ErrArtifactTooLarge
	}
	return raw, nil
}

func writeContinuityVault(path string, v *continuity.Vault) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicPrivate(path, append(raw, '\n'))
}

func writePrivateBytes(path string, body []byte) error {
	return writeAtomicPrivate(path, body)
}

func writeAtomicPrivate(path string, body []byte) error {
	if path == "" {
		return errors.New("continuity: output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".spore-continuity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replacePrivateFile(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// replacePrivateFile replaces the destination without exposing a partially
// written vault. Windows rename does not replace an existing file, so use the
// native replace primitive there; POSIX uses rename(2).
func replacePrivateFile(from, to string) error {
	return replaceFile(from, to)
}
