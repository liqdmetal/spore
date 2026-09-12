package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/continuity"
)

func continuityRevocationInit(args []string) {
	fs := flag.NewFlagSet("continuity revocation-init", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	out := fs.String("out", "", "revocation state JSON output path")
	checkpoint := fs.String("checkpoint", "", "optional signed checkpoint JSON output path")
	ownerPath := fs.String("owner-key", "", "owner X25519 private key file")
	_ = fs.Parse(args)
	if *vaultPath == "" || *out == "" {
		check(errors.New("continuity revocation-init requires -vault and -out"))
	}
	v := readContinuityVault(*vaultPath)
	state, err := continuity.NewRevocationState(v)
	check(err)
	check(writeJSONPrivate(*out, state))
	if *checkpoint != "" {
		if *ownerPath == "" {
			check(errors.New("continuity revocation-init requires -owner-key when -checkpoint is used"))
		}
		owner, err := readContinuityKey(*ownerPath)
		check(err)
		cp, err := continuity.NewRevocationCheckpoint(v, state, owner)
		check(err)
		check(writeJSONPrivate(*checkpoint, cp))
	}
	fmt.Printf("continuity revocation state written: %s\n", *out)
}

func continuityRevoke(args []string) {
	fs := flag.NewFlagSet("continuity revoke", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	statePath := fs.String("state", "", "revocation state JSON path")
	ownerPath := fs.String("owner-key", "", "owner X25519 private key file")
	kind := fs.String("kind", "", "recipient or observer")
	subject := fs.String("subject", "", "revoked public key hex")
	out := fs.String("out", "", "updated revocation state JSON output path")
	checkpointPath := fs.String("checkpoint", "", "updated signed checkpoint JSON output path")
	at := fs.Int64("at", 0, "revocation time as Unix seconds (default: current time)")
	_ = fs.Parse(args)
	if *vaultPath == "" || *statePath == "" || *ownerPath == "" || *kind == "" || *subject == "" || *out == "" || *checkpointPath == "" {
		check(errors.New("continuity revoke requires -vault -state -owner-key -kind -subject -out and -checkpoint"))
	}
	v := readContinuityVault(*vaultPath)
	stateRaw, err := readContinuityArtifact(*statePath)
	check(err)
	state, err := continuity.ParseRevocationState(stateRaw)
	check(err)
	owner, err := readContinuityKey(*ownerPath)
	check(err)
	pub, err := hex.DecodeString(*subject)
	check(err)
	var revocationKind continuity.RevocationKind
	switch *kind {
	case string(continuity.RevokedRecipient):
		revocationKind = continuity.RevokedRecipient
	case string(continuity.RevokedObserver):
		revocationKind = continuity.RevokedObserver
	default:
		check(errors.New("continuity revoke -kind must be recipient or observer"))
	}
	now := *at
	if now == 0 {
		now = time.Now().Unix()
	}
	check(state.Revoke(v, owner, revocationKind, pub, now))
	check(writeJSONPrivate(*out, state))
	cp, err := continuity.NewRevocationCheckpoint(v, state, owner)
	check(err)
	check(writeJSONPrivate(*checkpointPath, cp))
	fmt.Printf("continuity key revoked: kind=%s subject=%s\n", *kind, *subject)
}

func readRevocationPair(statePath, checkpointPath string) (*continuity.RevocationState, *continuity.RevocationCheckpoint, error) {
	if (statePath == "") != (checkpointPath == "") {
		return nil, nil, errors.New("continuity: revocation state and checkpoint must be supplied together")
	}
	if statePath == "" {
		return nil, nil, nil
	}
	stateRaw, err := readContinuityArtifact(statePath)
	if err != nil {
		return nil, nil, err
	}
	state, err := continuity.ParseRevocationState(stateRaw)
	if err != nil {
		return nil, nil, err
	}
	checkpointRaw, err := readContinuityArtifact(checkpointPath)
	if err != nil {
		return nil, nil, err
	}
	checkpoint, err := continuity.ParseRevocationCheckpoint(checkpointRaw)
	if err != nil {
		return nil, nil, err
	}
	return state, checkpoint, nil
}

func continuityRevocationCheck(args []string) {
	fs := flag.NewFlagSet("continuity revocation-check", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	statePath := fs.String("state", "", "revocation state JSON path")
	checkpointPath := fs.String("checkpoint", "", "signed checkpoint JSON path")
	_ = fs.Parse(args)
	if *vaultPath == "" || *statePath == "" || *checkpointPath == "" {
		check(errors.New("continuity revocation-check requires -vault -state and -checkpoint"))
	}
	v := readContinuityVault(*vaultPath)
	stateRaw, err := readContinuityArtifact(*statePath)
	check(err)
	state, err := continuity.ParseRevocationState(stateRaw)
	check(err)
	checkpointRaw, err := readContinuityArtifact(*checkpointPath)
	check(err)
	checkpoint, err := continuity.ParseRevocationCheckpoint(checkpointRaw)
	check(err)
	check(continuity.VerifyRevocationCheckpoint(v, state, checkpoint))
	fmt.Printf("VALID continuity revocation state: %d record(s)\n", len(state.Records))
}

func continuityRotate(args []string) {
	fs := flag.NewFlagSet("continuity rotate", flag.ExitOnError)
	oldVaultPath := fs.String("old-vault", "", "retired vault JSON path")
	oldOwnerPath := fs.String("old-owner-key", "", "old owner X25519 private key file")
	newOwnerPath := fs.String("new-owner-key", "", "new owner X25519 private key file")
	newRecipientHex := fs.String("new-recipient-pub", "", "new recipient X25519 public key hex list")
	payloadPath := fs.String("file", "", "replacement plaintext payload")
	vaultOut := fs.String("vault-out", "", "successor vault JSON output path")
	certOut := fs.String("certificate-out", "", "rotation certificate JSON output path")
	interval := fs.Duration("interval", 24*time.Hour, "successor check-in interval")
	grace := fs.Duration("grace", 24*time.Hour, "successor release grace")
	_ = fs.Parse(args)
	if *oldVaultPath == "" || *oldOwnerPath == "" || *newOwnerPath == "" || *newRecipientHex == "" || *payloadPath == "" || *vaultOut == "" || *certOut == "" {
		check(errors.New("continuity rotate requires -old-vault -old-owner-key -new-owner-key -new-recipient-pub -file -vault-out and -certificate-out"))
	}
	old := readContinuityVault(*oldVaultPath)
	oldOwner, err := readContinuityKey(*oldOwnerPath)
	check(err)
	newOwner, err := readContinuityKey(*newOwnerPath)
	check(err)
	payload, err := readContinuityArtifactLimit(*payloadPath, continuity.MaxPayloadBytes)
	check(err)
	pubs, err := parseRecipientPubs(*newRecipientHex)
	check(err)
	successor, cert, err := continuity.RotateVault(old, oldOwner, continuity.CreateOptions{OwnerPriv: newOwner, Recipients: pubs, Payload: payload, CreatedAt: time.Now().Unix(), Interval: *interval, Grace: *grace})
	check(err)
	check(writeContinuityVault(*vaultOut, successor))
	check(writeJSONPrivate(*certOut, cert))
	fmt.Printf("continuity vault rotated: successor=%s certificate=%s\n", *vaultOut, *certOut)
}

func readVaultRotation(path string) *continuity.VaultRotation {
	raw, err := readContinuityArtifact(path)
	check(err)
	rotation, err := continuity.ParseVaultRotation(raw)
	check(err)
	return rotation
}

func continuityVerifyRotation(args []string) {
	fs := flag.NewFlagSet("continuity rotation-verify", flag.ExitOnError)
	oldVaultPath := fs.String("old-vault", "", "old vault JSON path")
	successorPath := fs.String("successor-vault", "", "successor vault JSON path")
	certPath := fs.String("certificate", "", "rotation certificate JSON path")
	_ = fs.Parse(args)
	if *oldVaultPath == "" || *successorPath == "" || *certPath == "" {
		check(errors.New("continuity rotation-verify requires -old-vault -successor-vault and -certificate"))
	}
	old := readContinuityVault(*oldVaultPath)
	successor := readContinuityVault(*successorPath)
	raw, err := readContinuityArtifact(*certPath)
	check(err)
	cert, err := continuity.ParseVaultRotation(raw)
	check(err)
	check(continuity.VerifyRotation(old, successor, cert))
	fmt.Printf("VALID continuity vault rotation: %s -> %s\n", cert.OldVaultID, cert.NewVaultID)
}
