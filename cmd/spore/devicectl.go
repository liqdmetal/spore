package main

import (
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
		fmt.Fprintln(os.Stderr, "usage: spore e2-device id|status|export|import [flags]")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("e2-device "+sub, flag.ExitOnError)
	e2Common(fs)
	out := fs.String("out", "", "export: file to write the bundle to")
	in := fs.String("in", "", "import: bundle file to read")
	_ = fs.Parse(rest)
	check(loadConfigForFlags(fs))

	stateDir := fs.Lookup("state-dir").Value.String()
	stateKeyFile := fs.Lookup("state-key").Value.String()
	if stateDir == "" {
		check(errors.New("e2-device requires -state-dir (or state_dir in config.json)"))
	}
	dev, err := ratchetwire.LoadOrCreateDevice(stateDir)
	check(err)

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

	default:
		fmt.Fprintf(os.Stderr, "e2-device: unknown subcommand %q (want id|status|export|import)\n", sub)
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
