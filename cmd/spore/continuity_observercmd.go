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

func continuityObserverKeygen(args []string) {
	fs := flag.NewFlagSet("continuity observer-keygen", flag.ExitOnError)
	out := fs.String("out", "", "observer Ed25519 private key output file")
	_ = fs.Parse(args)
	if *out == "" {
		check(errors.New("continuity observer-keygen requires -out"))
	}
	priv, pub, err := continuity.NewObserverKey()
	check(err)
	check(writeAtomicPrivate(*out, []byte(hex.EncodeToString(priv)+"\n")))
	fmt.Printf("observer key written: %s\n", *out)
	fmt.Printf("observer public key: %s\n", hex.EncodeToString(pub))
}

func continuityObserve(args []string) {
	fs := flag.NewFlagSet("continuity observe", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	keyPath := fs.String("observer-key", "", "observer Ed25519 private key file")
	out := fs.String("out", "", "signed release notice output path")
	at := fs.Int64("at", 0, "evaluation time as Unix seconds (default: current time)")
	_ = fs.Parse(args)
	if *vaultPath == "" || *keyPath == "" || *out == "" {
		check(errors.New("continuity observe requires -vault -observer-key and -out"))
	}
	v := readContinuityVault(*vaultPath)
	key, err := readObserverKey(*keyPath)
	check(err)
	now := *at
	if now == 0 {
		now = time.Now().Unix()
	}
	n, err := continuity.Observe(v, key, now)
	check(err)
	raw, err := json.MarshalIndent(n, "", "  ")
	check(err)
	check(writeAtomicPrivate(*out, append(raw, '\n')))
	fmt.Printf("release-ready notice written: %s\n", *out)
	fmt.Printf("observer public key: %s\n", n.ObserverPub)
}

func continuityVerifyNotice(args []string) {
	fs := flag.NewFlagSet("continuity verify-notice", flag.ExitOnError)
	noticePath := fs.String("notice", "", "signed release notice JSON path")
	vaultPath := fs.String("vault", "", "optional vault JSON path for exact binding verification")
	_ = fs.Parse(args)
	if *noticePath == "" {
		check(errors.New("continuity verify-notice requires -notice"))
	}
	raw, err := os.ReadFile(*noticePath)
	check(err)
	n, err := continuity.ParseNotice(raw)
	check(err)
	if *vaultPath != "" {
		check(continuity.VerifyNoticeForVault(readContinuityVault(*vaultPath), n))
		fmt.Printf("VALID release notice bound to vault %s (%s)\n", n.VaultID, *noticePath)
		return
	}
	fmt.Printf("VALID release notice for vault %s (%s)\n", n.VaultID, *noticePath)
}

func readObserverKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("continuity: observer key file must contain exactly 128 hex characters")
	}
	return key, nil
}
