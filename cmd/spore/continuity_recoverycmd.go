package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/liqdmetal/spore/internal/continuity"
)

func continuityRecoveryCreate(args []string) {
	fs := flag.NewFlagSet("continuity recovery-create", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "continuity vault JSON path")
	policyPath := fs.String("policy", "", "optional quorum policy JSON path")
	quorumPath := fs.String("quorum", "", "optional quorum release JSON path")
	anchorPath := fs.String("anchor", "", "optional chain anchor JSON path")
	receiptPath := fs.String("receipt", "", "optional anchor receipt JSON path")
	watchPath := fs.String("watch", "", "optional signed watch checkpoint JSON path")
	noticePath := fs.String("notice", "", "optional signed release notice JSON path")
	revocationsPath := fs.String("revocations", "", "optional revocation state JSON path")
	checkpointPath := fs.String("checkpoint", "", "optional signed revocation checkpoint JSON path")
	rotationPath := fs.String("rotation", "", "optional signed vault rotation JSON path")
	out := fs.String("out", "", "recovery bundle JSON output path")
	_ = fs.Parse(args)
	if *vaultPath == "" || *out == "" {
		check(errors.New("continuity recovery-create requires -vault and -out"))
	}

	files := map[string][]byte{}
	add := func(name, path string) {
		if path == "" {
			return
		}
		raw, err := readContinuityArtifact(path)
		check(err)
		files[name] = raw
	}
	add("continuity-vault.json", *vaultPath)
	add("quorum-policy.json", *policyPath)
	add("quorum-release.json", *quorumPath)
	add("continuity-anchor.json", *anchorPath)
	add("continuity-anchor-receipt.json", *receiptPath)
	add("continuity-watch.json", *watchPath)
	add("continuity-release-notice.json", *noticePath)
	add("continuity-revocations.json", *revocationsPath)
	add("continuity-revocation-checkpoint.json", *checkpointPath)
	add("continuity-rotation.json", *rotationPath)
	if (*revocationsPath == "") != (*checkpointPath == "") {
		check(errors.New("continuity recovery-create requires both -revocations and -checkpoint"))
	}

	bundle, err := continuity.NewRecoveryBundle(files)
	check(err)
	raw, err := json.MarshalIndent(bundle, "", "  ")
	check(err)
	check(writeAtomicPrivate(*out, append(raw, '\n')))
	fmt.Printf("continuity recovery bundle written: %s\n", *out)
	fmt.Printf("bundle id: %s\n", bundle.BundleID)
	fmt.Printf("artifacts: %d\n", len(bundle.Artifacts))
	fmt.Println("private keys and released plaintext are not included")
}

func continuityRecoveryVerify(args []string) {
	fs := flag.NewFlagSet("continuity recovery-verify", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "recovery bundle JSON path")
	_ = fs.Parse(args)
	if *bundlePath == "" {
		check(errors.New("continuity recovery-verify requires -bundle"))
	}
	raw, err := readContinuityArtifactLimit(*bundlePath, continuity.RecoveryJSONLimit())
	check(err)
	bundle, err := continuity.ParseRecoveryBundle(raw)
	check(err)
	fmt.Printf("VALID continuity recovery bundle %s\n", bundle.BundleID)
	fmt.Printf("artifacts: %d\n", len(bundle.Artifacts))
}

func continuityRecoveryRestore(args []string) {
	fs := flag.NewFlagSet("continuity recovery-restore", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "recovery bundle JSON path")
	dir := fs.String("dir", "", "empty local recovery directory")
	_ = fs.Parse(args)
	if *bundlePath == "" || *dir == "" {
		check(errors.New("continuity recovery-restore requires -bundle and -dir"))
	}
	raw, err := readContinuityArtifactLimit(*bundlePath, continuity.RecoveryJSONLimit())
	check(err)
	bundle, err := continuity.ParseRecoveryBundle(raw)
	check(err)
	check(bundle.Restore(filepath.Clean(*dir)))
	fmt.Printf("continuity recovery restored: %s\n", *dir)
	fmt.Printf("bundle id: %s\n", bundle.BundleID)
}
