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

func continuityWatchInit(args []string) {
	fs := flag.NewFlagSet("continuity watch-init", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	observerKeyPath := fs.String("observer-key", "", "observer Ed25519 private key file")
	out := fs.String("out", "", "signed watch checkpoint JSON output path")
	_ = fs.Parse(args)
	if *vaultPath == "" || *observerKeyPath == "" || *out == "" {
		check(errors.New("continuity watch-init requires -vault -observer-key and -out"))
	}
	v := readContinuityVault(*vaultPath)
	observerKey, err := readObserverKey(*observerKeyPath)
	check(err)
	state, err := continuity.NewWatchState(v, observerKey)
	check(err)
	raw, err := json.MarshalIndent(state, "", "  ")
	check(err)
	check(writeAtomicPrivate(*out, append(raw, '\n')))
	fmt.Printf("continuity watch checkpoint written: %s\n", *out)
	fmt.Printf("watch event: %s\n", continuity.WatchEventID(state))
}

func continuityWatch(args []string) {
	fs := flag.NewFlagSet("continuity watch", flag.ExitOnError)
	vaultPath := fs.String("vault", "", "vault JSON path")
	observerKeyPath := fs.String("observer-key", "", "observer Ed25519 private key file")
	statePath := fs.String("state", "", "signed watch checkpoint JSON path")
	noticePath := fs.String("notice", "", "signed release-ready notice JSON output path")
	outboxPath := fs.String("outbox", "", "durable metadata-only notification outbox JSONL path")
	webhookURL := fs.String("webhook", "", "metadata-only notification webhook URL")
	at := fs.Int64("at", 0, "evaluation time as Unix seconds (default: current time)")
	flush := fs.Bool("flush", false, "synchronously attempt queued notifications")
	_ = fs.Parse(args)
	if *vaultPath == "" || *observerKeyPath == "" || *statePath == "" || *noticePath == "" || *outboxPath == "" || *webhookURL == "" {
		check(errors.New("continuity watch requires -vault -observer-key -state -notice -outbox and -webhook"))
	}
	v := readContinuityVault(*vaultPath)
	observerKey, err := readObserverKey(*observerKeyPath)
	check(err)
	stateRaw, err := readContinuityArtifact(*statePath)
	check(err)
	state, err := continuity.ParseWatchState(stateRaw)
	check(err)
	check(state.VerifyForVault(v))

	// Provider credentials remain environment-only through notify.NewFromEnv.
	dispatch, err := notify.NewFromEnv(notify.Options{WebhookURL: *webhookURL})
	check(err)
	outbox, err := notify.NewOutbox(*outboxPath, dispatch, 30*time.Second)
	check(err)
	defer outbox.Close()

	now := *at
	if now == 0 {
		now = time.Now().Unix()
	}
	if now < v.Checkins[len(v.Checkins)-1].Deadline {
		if *flush {
			check(outbox.Flush(context.Background()))
		}
		fmt.Printf("continuity watch: waiting; vault=%s due=%s\n", v.VaultID, time.Unix(v.Checkins[len(v.Checkins)-1].Deadline, 0).UTC().Format(time.RFC3339))
		return
	}
	if !state.NotificationQueued {
		notice, err := continuity.Observe(v, observerKey, now)
		check(err)
		noticeRaw, err := json.MarshalIndent(notice, "", "  ")
		check(err)
		check(writeAtomicPrivate(*noticePath, append(noticeRaw, '\n')))
		eventID := continuity.WatchEventID(state)
		if err := outbox.Enqueue(notify.Event{TxID: eventID, Subject: "Spore continuity release-ready", Received: time.Unix(now, 0).UTC()}); err != nil {
			check(err)
		}
		if err := state.MarkNotificationQueued(observerKey, notice, now); err != nil {
			check(err)
		}
		raw, err := json.MarshalIndent(state, "", "  ")
		check(err)
		check(writeAtomicPrivate(*statePath, append(raw, '\n')))
		fmt.Printf("continuity watch: release-ready notice and notification queued; event=%s\n", eventID)
	} else {
		fmt.Printf("continuity watch: release-ready notice already queued; event=%s\n", continuity.WatchEventID(state))
	}
	if *flush {
		check(outbox.Flush(context.Background()))
		fmt.Println("continuity watch: notification flush complete")
	}
}
