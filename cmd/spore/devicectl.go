package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// e2-device — multi-device state sync.
//
//	spore e2-device id                       show this device's id
//	spore e2-device status                   show the sync ledger (per-session writer + conflicts)
//	spore e2-device export -out FILE         package all session state into an encrypted bundle
//	spore e2-device import -in FILE          adopt another device's state
//	spore e2-device backup -out FILE -identity KEY -passphrase-file P
//	                                         seal the identity key and session state under a passphrase
//	spore e2-device restore -in FILE -identity KEY -passphrase-file P
//	                                         restore a backup; refuses an older generation or a rolled-back session
//
// State and key come from the E2 flags every other msg subcommand already uses
// (-state-dir / -state-key), or from config.json.
//
// The risk this exists to manage: two devices sharing one session and both
// sending reuse message keys, which breaks confidentiality of both messages.
// `import` therefore reports a conflict when both devices have sent since they
// last agreed, and the send path refuses to continue on a conflicting session.
func e2DeviceCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: spore e2-device id|status|export|import|backup|restore [flags]")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("e2-device "+sub, flag.ExitOnError)
	e2Common(fs)
	out := fs.String("out", "", "export: file to write the bundle to")
	in := fs.String("in", "", "import: bundle file to read")
	identityFile := fs.String("identity", "", "backup: identity key file to include; restore: where to write the restored identity key")
	passphraseFile := fs.String("passphrase-file", "", "backup/restore: file holding the passphrase (at least 12 characters); never pass it on the command line")
	anchorFile := fs.String("anchor", "", "backup/restore: external anchor file, kept outside the state dir; blocks rollback onto empty storage")
	anchorInit := fs.Bool("anchor-init", false, "restore: allow a missing -anchor file on this device's first restore")
	_ = fs.Parse(rest)
	check(loadConfigForFlags(fs))

	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" {
		check(errors.New("e2-device requires -state-dir (or state_dir in config.json)"))
	}
	// restore must not mint a device id first: the backup's own id decides
	// whether this state dir can take it.
	var dev *ratchetwire.DeviceState
	if sub != "restore" {
		d, err := ratchetwire.LoadOrCreateDevice(stateDir)
		check(err)
		dev = d
	}

	switch sub {
	case "id":
		fmt.Printf("device id  %s\n", dev.ID)
		fmt.Printf("state dir  %s\n", stateDir)
	case "status":
		check(printDeviceStatus(stateDir, dev))

	case "export":
		if *out == "" {
			check(errors.New("e2-device export requires -out FILE"))
		}
		if stateKeyFile == "" {
			check(errors.New("e2-device export requires -state-key (the state encryption key)"))
		}
		stateKey, err := readHexFile(stateKeyFile, 32)
		check(err)
		b, err := ratchetwire.ExportBundle(stateDir, stateKey, dev)
		check(err)
		raw, err := ratchetwire.EncodeBundle(b)
		check(err)
		if err := os.WriteFile(*out, raw, 0o600); err != nil {
			check(err)
		}
		fmt.Printf("exported device %s -> %s\n", dev.ID, *out)
		fmt.Println("the bundle is encrypted under your state key — move it over any channel;")
		fmt.Println("only a device that already holds this account's state key can open it.")

	case "import":
		if *in == "" {
			check(errors.New("e2-device import requires -in FILE"))
		}
		if stateKeyFile == "" {
			check(errors.New("e2-device import requires -state-key (the state encryption key)"))
		}
		stateKey, err := readHexFile(stateKeyFile, 32)
		check(err)
		raw, err := os.ReadFile(*in)
		check(err)
		b, err := ratchetwire.DecodeBundle(raw)
		check(err)
		rep, err := ratchetwire.ImportBundle(stateDir, stateKey, b, dev)
		check(err)
		fmt.Printf("imported %d session(s) from device %s\n", rep.Imported, shortID(b.Device))
		if len(rep.Conflict) > 0 {
			// Loud on purpose. A conflict means this device and the exporter
			// both advanced the same send chain from the same counter, so the
			// two chains may already have used the same message keys.
			fmt.Fprintf(os.Stderr, "\n⚠  %d session(s) COLLIDED — both devices sent without syncing:\n", len(rep.Conflict))
			for _, id := range rep.Conflict {
				fmt.Fprintf(os.Stderr, "   %s\n", id)
			}
			fmt.Fprintln(os.Stderr, "\nMessage keys in those sessions may have been reused. Do NOT keep")
			fmt.Fprintln(os.Stderr, "sending on them: start a NEW session with those contacts. Sending on a")
			fmt.Fprintln(os.Stderr, "flagged session is refused until you do.")
			os.Exit(1)
		}
		fmt.Println("sessions are now current on this device.")

	case "backup":
		if *out == "" {
			check(errors.New("e2-device backup requires -out FILE"))
		}
		if stateKeyFile == "" {
			check(errors.New("e2-device backup requires -state-key (the state encryption key)"))
		}
		if *identityFile == "" {
			check(errors.New("e2-device backup requires -identity (the identity key file to include)"))
		}
		pass := readPassphraseFile(*passphraseFile)
		stateKey, err := readHexFile(stateKeyFile, 32)
		check(err)
		identity, err := readHexFile(*identityFile, 32)
		check(err)
		raw, gen, err := ratchetwire.CreateBackup(stateDir, stateKey, pass, identity, dev)
		check(err)
		if *anchorFile != "" {
			check(ratchetwire.WriteBackupAnchor(*anchorFile, stateKey, dev.ID, gen))
		}
		check(os.WriteFile(*out, raw, 0o600))
		fmt.Printf("backed up device %s at generation %d -> %s\n", dev.ID, gen, *out)
		fmt.Println("the backup is sealed under your passphrase but holds the identity key:")
		fmt.Println("keep it private. A restore refuses any copy older than this device's last backup.")

	case "restore":
		if *in == "" {
			check(errors.New("e2-device restore requires -in FILE"))
		}
		if stateKeyFile == "" {
			check(errors.New("e2-device restore requires -state-key (the state encryption key)"))
		}
		if *identityFile == "" {
			check(errors.New("e2-device restore requires -identity (where to write the restored identity key)"))
		}
		pass := readPassphraseFile(*passphraseFile)
		stateKey, err := readHexFile(stateKeyFile, 32)
		check(err)
		raw, err := os.ReadFile(*in)
		check(err)
		opened, err := ratchetwire.OpenBackup(pass, raw)
		check(err)
		// Check the identity target before any write, so a conflict cannot
		// leave sessions restored and the identity missing.
		present, err := identityTargetState(*identityFile, opened.Identity)
		check(err)
		res, err := opened.Restore(stateDir, stateKey, ratchetwire.AnchorCheck{Path: *anchorFile, Init: *anchorInit})
		check(err)
		if !present {
			if err := os.WriteFile(*identityFile, []byte(hex.EncodeToString(opened.Identity)+"\n"), 0o600); err != nil {
				check(fmt.Errorf("sessions were restored but the identity key was not written: %w", err))
			}
		}
		fmt.Printf("restored device %s at generation %d: %d session(s)\n", shortID(res.Device), res.Generation, res.Sessions)
		if present {
			fmt.Printf("identity key already present at %s and matches the backup\n", *identityFile)
		}

	default:
		fmt.Fprintf(os.Stderr, "e2-device: unknown subcommand %q (want id|status|export|import|backup|restore)\n", sub)
		os.Exit(2)
	}
}

func printDeviceStatus(stateDir string, dev *ratchetwire.DeviceState) error {
	fmt.Printf("device id  %s\n", dev.ID)
	ids, err := ratchetwire.LedgerIDs(stateDir)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		fmt.Println("no sessions tracked yet (nothing sent or imported on this device).")
		return nil
	}
	fmt.Printf("%-20s %-20s %8s  %s\n", "SESSION", "LAST WRITER", "SENT", "STATE")
	conflicts := 0
	for _, id := range ids {
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) != 8 {
			continue
		}
		var sid [8]byte
		copy(sid[:], raw)
		e, _ := ratchetwire.LedgerEntry(stateDir, sid)
		writer := shortID(e.LastWriter)
		if e.LastWriter == dev.ID {
			writer = "this device"
		}
		state := "ok"
		if e.Conflict {
			state = "CONFLICT (do not send — replace the session)"
			conflicts++
		} else if e.MySends > 0 && e.LastWriter != "" && e.LastWriter != dev.ID {
			state = "stale (another device wrote this session; sync before sending)"
		}
		fmt.Printf("%-20s %-20s %8d  %s\n", id[:16]+"…", writer, e.MySends, state)
	}
	if conflicts > 0 {
		return fmt.Errorf("%d session(s) have colliding send chains", conflicts)
	}
	return nil
}

// readPassphraseFile reads a backup passphrase from a file. The passphrase is
// never taken from argv, where other local users can read it through ps.
func readPassphraseFile(path string) []byte {
	if path == "" {
		check(errors.New("requires -passphrase-file FILE (the passphrase is never read from the command line)"))
	}
	raw, err := os.ReadFile(path)
	check(err)
	return bytes.TrimRight(raw, "\r\n")
}

// identityTargetState reports whether path already holds this identity key. It
// returns an error when path holds a different key, so a restore never
// overwrites an identity it did not write.
func identityTargetState(path string, identity []byte) (bool, error) {
	existing, err := readHexFile(path, 32)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(existing, identity) {
		return false, fmt.Errorf("%s already holds a different identity key; refusing to overwrite it", path)
	}
	return true, nil
}

func shortID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// deviceLedgerSummary is used by doctor to surface conflicts without the full
// status table.
func deviceLedgerSummary(stateDir string) (sessions, conflicts int, err error) {
	ids, err := ratchetwire.LedgerIDs(stateDir)
	if err != nil {
		return 0, 0, err
	}
	for _, id := range ids {
		raw, derr := hex.DecodeString(id)
		if derr != nil || len(raw) != 8 {
			continue
		}
		var sid [8]byte
		copy(sid[:], raw)
		if e, ok := ratchetwire.LedgerEntry(stateDir, sid); ok && e.Conflict {
			conflicts++
		}
	}
	return len(ids), conflicts, nil
}
