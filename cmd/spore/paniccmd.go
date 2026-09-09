package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// paniccmd — the verifiable local wipe.
//
//	spore panic -state-dir D [-maildb F] [-spool D] [-out-dir D] [-confirm]
//
// Deletes every plaintext artifact Spore keeps on THIS machine:
//   - encrypted ratchet session state (state-dir): the keys themselves —
//     after this, even the bodies an attacker already holds cannot be
//     decrypted going forward, and past messages stay forward-secret.
//   - maildb JSON (decrypted snippets + contacts + search index)
//   - compose spool (queued plaintext + signed send params)
//   - recv -out-dir saves (decrypted message/attachment files)
//
// What it CANNOT erase (documented, honest): pointers already confirmed on
// immutable chains, off-chain ciphertext past its reaper but still inside
// TTL on a REMOTE store (that is the store operator's TTL job), and copies
// an adversary already made. The chain pointers are opaque and useless
// without the state being destroyed here — that is the compost model.
//
// Files are removed with os.Remove after a best-effort overwrite of regular
// files (SSD FTLs make overwrite no guarantee; it raises the bar for
// magnetic/ramdisk-backed stores). -confirm is required to actually run;
// without it, panic prints exactly what it WOULD delete (dry run).
func paniccmd(args []string) {
	flg := flag.NewFlagSet("panic", flag.ExitOnError)
	stateDir := flg.String("state-dir", "", "encrypted ratchet session state directory")
	maildbPath := flg.String("maildb", "", "maildb JSON file")
	spoolDir := flg.String("spool", "", "compose spool directory")
	outDir := flg.String("out-dir", "", "recv -out-dir save directory")
	confirm := flg.Bool("confirm", false, "actually delete (without this, dry-run listing only)")
	_ = flg.Parse(args)

	targets := []string{}
	if *stateDir != "" {
		targets = append(targets, *stateDir)
	}
	if *maildbPath != "" {
		targets = append(targets, *maildbPath)
	}
	if *spoolDir != "" {
		targets = append(targets, *spoolDir)
	}
	if *outDir != "" {
		targets = append(targets, *outDir)
	}
	if len(targets) == 0 {
		check(errors.New("panic: nothing to wipe — pass at least one of -state-dir -maildb -spool -out-dir"))
	}

	// Refuse to wipe the user's home or a drive root: a typo like
	// `-spool /` or `-state-dir C:\Users\me` must not become rm -rf ~.
	for _, t := range targets {
		abs, err := filepath.Abs(t)
		if err != nil {
			check(err)
		}
		if isDangerousWipeTarget(abs) {
			check(fmt.Errorf("panic: refusing to wipe %q — looks like a home/root/system directory", abs))
		}
	}

	// Collect the full file list first so the dry run and the real run see
	// the same set.
	var files []string
	for _, t := range targets {
		info, err := os.Stat(t)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("panic: %s (absent — nothing to do)\n", t)
				continue
			}
			check(err)
		}
		if !info.IsDir() {
			files = append(files, t)
			continue
		}
		err = filepath.WalkDir(t, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		check(err)
	}

	if !*confirm {
		fmt.Printf("panic DRY RUN — would delete %d file(s):\n", len(files))
		for _, f := range files {
			fmt.Printf("  %s\n", f)
		}
		for _, t := range targets {
			if info, err := os.Stat(t); err == nil && info.IsDir() {
				fmt.Printf("  %s%s (dir)\n", t, string(filepath.Separator))
			}
		}
		fmt.Println("re-run with -confirm to actually wipe.")
		fmt.Println("note: chain pointers and remote off-chain bodies are NOT erased by panic — see `spore panic -h` semantics above.")
		return
	}

	wiped := 0
	for _, f := range files {
		// Best-effort overwrite before unlink (see doc comment for the
		// honest limits of this on flash storage).
		if info, err := os.Stat(f); err == nil && !info.IsDir() && info.Mode().IsRegular() {
			if fh, oerr := os.OpenFile(f, os.O_WRONLY, 0); oerr == nil {
				zeros := make([]byte, 64*1024)
				for off := int64(0); off < info.Size(); off += int64(len(zeros)) {
					n := int64(len(zeros))
					if rem := info.Size() - off; rem < n {
						n = rem
					}
					_, _ = fh.WriteAt(zeros[:n], off)
				}
				_ = fh.Sync()
				_ = fh.Close()
			}
		}
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "panic: could not remove %s: %v\n", f, err)
			continue
		}
		wiped++
	}
	// Remove the now-empty directories (deepest first via reverse walk order
	// is unnecessary: RemoveAll only takes what's left).
	for _, t := range targets {
		if info, err := os.Stat(t); err == nil && info.IsDir() {
			if err := os.RemoveAll(t); err != nil {
				fmt.Fprintf(os.Stderr, "panic: could not remove dir %s: %v\n", t, err)
			}
		}
	}
	fmt.Printf("panic: wiped %d file(s) across %d target(s)\n", wiped, len(targets))
}

// isDangerousWipeTarget refuses home dirs, filesystem roots, and Windows
// system directories. The check is conservative: when in doubt, refuse.
func isDangerousWipeTarget(abs string) bool {
	clean := filepath.Clean(abs)
	// Filesystem roots: "/" on POSIX, "C:\" on Windows.
	if clean == string(filepath.Separator) || filepath.VolumeName(clean) == clean {
		return true
	}
	if len(filepath.Dir(clean)) <= 1 || filepath.Dir(clean) == filepath.VolumeName(clean)+string(filepath.Separator) {
		// One level under a root (e.g. /home, C:\Users) — too broad.
		return true
	}
	home, err := os.UserHomeDir()
	if err == nil {
		h := filepath.Clean(home)
		if clean == h || strings.EqualFold(clean, h) {
			return true
		}
	}
	low := strings.ToLower(filepath.ToSlash(clean))
	for _, bad := range []string{"/windows", "/system32", "/program files", "/usr", "/etc", "/var", "/bin", "/boot"} {
		if strings.Contains(low, bad) {
			return true
		}
	}
	return false
}
