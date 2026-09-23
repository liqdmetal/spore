package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/continuity"
	"github.com/liqdmetal/spore/internal/notify"
)

// continuityWatchdog is the `continuity watch-reaper` subcommand: one pass of
// the stale-reaper check for the continuity watch loop. The state machine
// lives in internal/continuity (CheckReaper); this file is flag wiring plus
// the alert delivery through the shared durable outbox — the same delivery
// path, dedupe, and retry semantics as the release-ready notification.
func continuityWatchdog(args []string) {
	fs := flag.NewFlagSet("continuity watch-reaper", flag.ExitOnError)
	logPath := fs.String("log", "", "node daemon log file to scan for reaper status lines")
	statePath := fs.String("state", "", "durable watchdog state JSON (remembers the last pass count)")
	node := fs.String("node", "spore", "which daemon's heartbeat lines to read: spore or spore-peer")
	grace := fs.Int("grace", 0, "equal-count observations tolerated before alerting (0 = alert on first freeze)")
	outboxPath := fs.String("outbox", "", "durable metadata-only notification outbox JSONL path")
	webhookURL := fs.String("webhook", "", "metadata-only notification webhook URL")
	_ = fs.Parse(args)
	if *logPath == "" || *statePath == "" || *outboxPath == "" || *webhookURL == "" {
		check(errors.New("continuity watch-reaper requires -log -state -outbox and -webhook"))
	}
	if *node != "spore" && *node != "spore-peer" {
		check(fmt.Errorf("continuity watch-reaper: -node must be spore or spore-peer, got %q", *node))
	}
	if *grace < 0 {
		check(errors.New("continuity watch-reaper: -grace must be >= 0"))
	}

	status, err := continuity.LastReapStatus(*logPath)
	check(err)

	// Wrong daemon's lines: a spore log read with -node spore-peer would
	// silently make every watch compare nothing. Fail loudly instead.
	if status != nil && status.Source != *node {
		check(fmt.Errorf("continuity watch-reaper: log's reaper lines are from %q but -node is %q", status.Source, *node))
	}

	mem, err := continuity.LoadReapMemory(*statePath)
	check(err)

	res := continuity.CheckReaper(status, mem, *grace, time.Now().Unix())

	switch res.Outcome {
	case continuity.WatchdogBaseline:
		check(writeAtomicPrivate(*statePath, watchdogJSON(res.Memory)))
		fmt.Printf("continuity watch-reaper: baseline passes=%d (source=%s)\n", res.Memory.Passes, res.Memory.Source)
	case continuity.WatchdogOK:
		check(writeAtomicPrivate(*statePath, watchdogJSON(res.Memory)))
		fmt.Printf("continuity watch-reaper: ok passes=%d\n", res.Memory.Passes)
	case continuity.WatchdogRebaselined:
		check(writeAtomicPrivate(*statePath, watchdogJSON(res.Memory)))
		fmt.Printf("continuity watch-reaper: re-baselined passes=%d (log rotation or restart)\n", res.Memory.Passes)
	case continuity.WatchdogWithinGrace:
		check(writeAtomicPrivate(*statePath, watchdogJSON(res.Memory)))
		fmt.Printf("continuity watch-reaper: %s\n", res.Detail)
	case continuity.WatchdogAlreadyQueued:
		fmt.Printf("continuity watch-reaper: %s\n", res.Detail)
	case continuity.WatchdogNoHeartbeat:
		// Unverifiable — treated like dead. Alert each watch until a
		// heartbeat appears; that is the wanted nag for a down daemon.
		check(continuityWatchdogAlert(*outboxPath, *webhookURL, "no reaper status in log", res.Detail))
	case continuity.WatchdogFrozenAlert:
		check(continuityWatchdogAlert(*outboxPath, *webhookURL, "stale reaper", res.Detail))
		check(writeAtomicPrivate(*statePath, watchdogJSON(continuity.ApplyAlertLatch(res.Memory, res.Status.Passes))))
		fmt.Printf("continuity watch-reaper: ALERT queued: %s\n", res.Detail)
	}
}

// continuityWatchdogAlert queues and flushes one metadata-only alert.
func continuityWatchdogAlert(outboxPath, webhookURL, eventID, detail string) error {
	dispatch, err := notify.NewFromEnv(notify.Options{WebhookURL: webhookURL})
	if err != nil {
		return err
	}
	outbox, err := notify.NewOutbox(outboxPath, dispatch, 30*time.Second)
	if err != nil {
		return err
	}
	defer outbox.Close()
	if err := outbox.Enqueue(notify.Event{
		TxID:     "watchdog/reaper/" + eventID,
		Subject:  "Spore continuity: " + eventID,
		Received: time.Now().UTC(),
	}); err != nil {
		return err
	}
	return outbox.Flush(context.Background())
}

func watchdogJSON(m continuity.ReapMemory) []byte {
	raw, err := json.MarshalIndent(m, "", "  ")
	check(err)
	return append(raw, '\n')
}
