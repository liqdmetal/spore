package main

// storecmd implements `spore store sweep`: list, and optionally reclaim,
// bodies in a hold directory that carry no deadline record at all.
//
// Why this exists: Reap finds candidates by globbing *.exp, so a body whose
// records are gone is never considered by any pass, while deadlineFor reads
// the absent record as "never expires" and serves it forever. Hiding that
// body is a permanent-retention failure the store cannot fix from the inside —
// it physically cannot see the file. This is the outside view, for any host's
// hold, without guessing which directory needs it.
//
// It is deliberately not eager. Once the record is gone the deadline is
// unknowable, so -min-age (default 24h) keeps anything that could still be
// inside its sender's TTL, and -dry-run reports without touching a byte. That
// also keeps it clear of the one legitimate producer of a recordless body: a
// harness that plants one on purpose to exercise the never-expires path.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

func storecmd(args []string) {
	if len(args) == 0 {
		storeUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "sweep":
		storeSweep(args[1:])
	case "-h", "--help", "help":
		storeUsage()
	default:
		fmt.Fprintf(os.Stderr, "spore store: unknown subcommand %q\n", args[0])
		storeUsage()
		os.Exit(2)
	}
}

func storeUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore store sweep -dir HOLD_DIR [-min-age 24h] [-dry-run]
      bodies with no deadline record are invisible to reap (it globs *.exp)
      and are served forever; list them and reclaim the ones older than
      -min-age, which is what keeps a body still inside its sender's TTL.
      -dry-run lists only. -min-age 0 reclaims everything.`)
}

func storeSweep(args []string) {
	fs := flag.NewFlagSet("store sweep", flag.ContinueOnError)
	dir := fs.String("dir", "", "hold directory to sweep (the same path passed to spore serve -dir)")
	minAge := fs.Duration("min-age", 24*time.Hour, "reclaim only bodies at least this old: a recordless body's deadline is unknowable, so anything younger may still be inside its sender's TTL (0 reclaims all)")
	dryRun := fs.Bool("dry-run", false, "list what would be reclaimed without removing anything")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "spore store sweep: -dir is required (the hold directory to sweep)")
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "spore store sweep: unexpected argument %q\n", fs.Arg(0))
		os.Exit(2)
	}
	now := time.Now()
	res, err := sweepHold(*dir, now, *minAge, *dryRun)
	if err := reportSweep(os.Stdout, *dir, now, *minAge, *dryRun, res, err); err != nil {
		logFatal(err)
	}
}

// reportSweep decides what a run is allowed to say. A run that failed before
// it could look at anything must not print the all-clear line first: "no
// bodies lack a deadline record" from a mistyped path is the exact false
// reassurance this command exists to rule out. Partial results are printed
// even when the run errored (some bodies reclaimed, then one file refused),
// because the operator needs to know what already moved.
func reportSweep(w io.Writer, dir string, now time.Time, minAge time.Duration, dryRun bool, res store.OrphanSweep, err error) error {
	looked := len(res.Removed)+len(res.Retained) > 0
	if err == nil || looked {
		printSweep(w, dir, now, minAge, dryRun, res)
	}
	return err
}

// sweepHold is the testable core. It refuses a path that is not already a
// directory instead of opening the store through NewDiskStore, which creates
// the directory: a typo must fail loudly, never produce an empty hold that
// then reports "nothing to reclaim" and looks like a clean bill of health.
func sweepHold(dir string, now time.Time, minAge time.Duration, dryRun bool) (store.OrphanSweep, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return store.OrphanSweep{}, fmt.Errorf("spore store sweep: %w", err)
	}
	if !fi.IsDir() {
		return store.OrphanSweep{}, fmt.Errorf("spore store sweep: %s is not a directory", dir)
	}
	ds, err := store.NewDiskStore(dir)
	if err != nil {
		return store.OrphanSweep{}, err
	}
	if dryRun {
		return ds.OrphanPlan(now, minAge)
	}
	return ds.SweepOrphans(now, minAge)
}

func printSweep(w io.Writer, dir string, now time.Time, minAge time.Duration, dryRun bool, res store.OrphanSweep) {
	total := len(res.Removed) + len(res.Retained)
	if total == 0 {
		// The full answer for this hold, not a skipped check: reap cannot see
		// a recordless body, so if this says none, there are none.
		fmt.Fprintf(w, "spore store sweep: %s: no bodies lack a deadline record\n", dir)
		return
	}
	verb := "reclaimed"
	if dryRun {
		verb = "would reclaim"
	}
	for _, o := range res.Removed {
		fmt.Fprintf(w, "  %x  %d bytes  %s old  %s\n", o.CID, o.Size, o.Age(now).Round(time.Second), verb)
	}
	for _, o := range res.Retained {
		fmt.Fprintf(w, "  %x  %d bytes  %s old  kept (younger than -min-age %s)\n",
			o.CID, o.Size, o.Age(now).Round(time.Second), minAge)
	}
	fmt.Fprintf(w, "spore store sweep: %s: %d recordless body(ies); %s %d (%d bytes), kept %d\n",
		dir, total, verb, len(res.Removed), res.Bytes, len(res.Retained))
	if dryRun && len(res.Removed) > 0 {
		fmt.Fprintln(w, "spore store sweep: nothing was removed (-dry-run); re-run without it to reclaim")
	}
}
