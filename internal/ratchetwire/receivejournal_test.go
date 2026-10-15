package ratchetwire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

func journalMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func journalKit(t *testing.T) (*DurableEndpoint, *DurableEndpoint, Pointer, [8]byte) {
	t.Helper()
	body := store.NewMemStore()
	a, b, spk := bytes.Repeat([]byte{11}, 32), bytes.Repeat([]byte{22}, 32), bytes.Repeat([]byte{33}, 32)
	newEP := func() *DurableEndpoint {
		states, err := NewFileStateStore(t.TempDir(), bytes.Repeat([]byte{9}, 32))
		journalMust(t, err)
		ep, err := NewDurableEndpoint(body, states, time.Now())
		journalMust(t, err)
		return ep
	}
	sender, recv := newEP(), newEP()
	bundle, err := ratchet.BuildBundle(b, spk, 1, nil, 0)
	journalMust(t, err)
	pin, err := secure.SigPubOf(b)
	journalMust(t, err)
	p, _, sid, err := sender.SendFirstSession(a, bundle, pin, []byte("bootstrap"), time.Now().Add(time.Hour))
	journalMust(t, err)
	frame, err := FetchFrame(body, p, time.Now())
	journalMust(t, err)
	raw, err := GetBody(body, p, time.Now())
	journalMust(t, err)
	_, err = recv.ReceiveFirst(b, spk, nil, frame, raw)
	journalMust(t, err)
	p, _, err = sender.SendNext(sid, []byte("private recoverable payload"), time.Now().Add(time.Hour))
	journalMust(t, err)
	return sender, recv, p, sid
}
func reopenJournal(t *testing.T, ep *DurableEndpoint) *DurableEndpoint {
	t.Helper()
	states, err := NewFileStateStore(ep.StateDir(), bytes.Repeat([]byte{9}, 32))
	journalMust(t, err)
	out, err := NewDurableEndpoint(ep.Store, states, time.Now())
	journalMust(t, err)
	return out
}
func prepareJournal(t *testing.T, ep *DurableEndpoint, p Pointer) *ReceivePending {
	t.Helper()
	f, err := FetchFrame(ep.Store, p, time.Now())
	journalMust(t, err)
	before, err := ep.Sessions.Export(f.SessionID)
	journalMust(t, err)
	session, err := ratchet.ImportState(before)
	journalMust(t, err)
	defer session.Erase()
	plain, err := session.DecryptWithDeadline(f.Message, f.DeadlineTime())
	journalMust(t, err)
	next, err := session.Export()
	journalMust(t, err)
	pending, err := ep.states.prepareReceive(f.SessionID, p.CID, int64(p.BurnDeadline), next, plain)
	journalMust(t, err)
	return pending
}

func TestReceiveJournalRecoversEveryCommitWindow(t *testing.T) {
	for _, stage := range []string{"journal-before-log", "torn-log", "log-before-head", "head-before-application", "application-before-journal-delete"} {
		t.Run(stage, func(t *testing.T) {
			sender, recv, p, sid := journalKit(t)
			pending := prepareJournal(t, recv, p)
			applied := 0
			switch stage {
			case "torn-log":
				f, err := os.OpenFile(recv.states.logPath(sid), os.O_APPEND|os.O_WRONLY, 0600)
				journalMust(t, err)
				_, err = f.Write([]byte{99, 88, 77})
				journalMust(t, err)
				journalMust(t, f.Close())
			case "log-before-head":
				seq, _, err := UnprotectSession(recv.states.protector, sid, pending.Record)
				journalMust(t, err)
				journalMust(t, recv.states.appendLog(sid, seq, StateDigest(pending.Record)))
			case "head-before-application", "application-before-journal-delete":
				_, err := recv.states.commitReceive(pending)
				journalMust(t, err)
				if stage == "application-before-journal-delete" {
					applied = 1
				}
			}
			recv = reopenJournal(t, recv)
			if _, _, err := recv.SendNext(sid, []byte("must block"), time.Now().Add(time.Hour)); err == nil {
				t.Fatal("send overtook pending receive")
			}
			journalMust(t, recv.RecoverReceive(func(got *ReceivePending) error {
				if !bytes.Equal(got.Payload, []byte("private recoverable payload")) || got.CID != p.CID {
					t.Fatal("wrong recovered application")
				}
				if applied == 0 {
					applied++
				}
				return nil
			}))
			journalMust(t, recv.RecoverReceive(func(*ReceivePending) error { t.Fatal("already recovered callback repeated"); return nil }))
			if applied != 1 {
				t.Fatal("application duplicated")
			}
			recv = reopenJournal(t, recv)
			if _, err := recv.ReceiveNext(p, time.Now()); err == nil {
				t.Fatal("committed ciphertext replayed")
			}
			next, _, err := sender.SendNext(sid, []byte("next event"), time.Now().Add(time.Hour))
			journalMust(t, err)
			plain, err := recv.ReceiveNext(next, time.Now())
			journalMust(t, err)
			if string(plain) != "next event" {
				t.Fatal("wrong subsequent decrypt")
			}
		})
	}
}

func TestReceiveJournalApplicationFailureSurvivesRestartAndBodyLoss(t *testing.T) {
	_, recv, p, sid := journalKit(t)
	_, err := recv.ReceiveNextJournaled(p, time.Now(), func([]byte) bool { return true }, func(*ReceivePending) error { return errors.New("disk full in application store") })
	if err == nil {
		t.Fatal("failed application was acknowledged")
	}
	pending, err := recv.PendingReceive()
	journalMust(t, err)
	if pending == nil {
		t.Fatal("application failure lost journal")
	}
	raw, err := os.ReadFile(recv.states.journalPath())
	journalMust(t, err)
	if bytes.Contains(raw, pending.Payload) || bytes.Contains(raw, []byte(`"record"`)) {
		t.Fatal("journal leaks state/plaintext")
	}
	journalMust(t, recv.Store.Delete(p.CID))
	recv = reopenJournal(t, recv)
	before, err := recv.Sessions.Export(sid)
	journalMust(t, err)
	journalMust(t, recv.RecoverReceive(func(got *ReceivePending) error {
		if !bytes.Equal(got.Payload, pending.Payload) {
			t.Fatal("payload not retained")
		}
		return nil
	}))
	after, err := recv.Sessions.Export(sid)
	journalMust(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("application recovery changed ratchet")
	}
}

func TestReceiveJournalWriteFailureDoesNotAdvanceRatchet(t *testing.T) {
	_, recv, p, sid := journalKit(t)
	before, err := recv.Sessions.Export(sid)
	journalMust(t, err)
	head, err := os.ReadFile(recv.states.path(sid))
	journalMust(t, err)
	journalMust(t, os.Mkdir(recv.states.journalPath(), 0700))
	if _, err := recv.ReceiveNextJournaled(p, time.Now(), func([]byte) bool { return true }, func(*ReceivePending) error { t.Fatal("applied despite journal error"); return nil }); err == nil {
		t.Fatal("journal failure hidden")
	}
	after, err := recv.Sessions.Export(sid)
	journalMust(t, err)
	disk, err := os.ReadFile(recv.states.path(sid))
	journalMust(t, err)
	if !bytes.Equal(before, after) || !bytes.Equal(head, disk) {
		t.Fatal("failed journal changed live/disk state")
	}
	journalMust(t, os.Remove(recv.states.journalPath()))
	_, err = recv.ReceiveNext(p, time.Now())
	journalMust(t, err)
}

func TestReceiveJournalRefusesStaleOrTamperedRecovery(t *testing.T) {
	for _, attack := range []string{"newer-head", "tampered-journal", "wrong-key", "conflicting-log"} {
		t.Run(attack, func(t *testing.T) {
			_, recv, p, sid := journalKit(t)
			pending := prepareJournal(t, recv, p)
			switch attack {
			case "newer-head":
				state, err := recv.Sessions.Export(sid)
				journalMust(t, err)
				journalMust(t, recv.states.Save(sid, state))
			case "tampered-journal":
				raw, err := os.ReadFile(recv.states.journalPath())
				journalMust(t, err)
				raw[len(raw)-1] ^= 1
				journalMust(t, os.WriteFile(recv.states.journalPath(), raw, 0600))
			case "conflicting-log":
				seq, _, err := UnprotectSession(recv.states.protector, sid, pending.Record)
				journalMust(t, err)
				journalMust(t, recv.states.appendLog(sid, seq, StateDigest([]byte("foreign record"))))
			}
			key := bytes.Repeat([]byte{9}, 32)
			if attack == "wrong-key" {
				key[0] = 8
			}
			states, err := NewFileStateStore(recv.StateDir(), key)
			journalMust(t, err)
			if _, err := NewDurableEndpoint(recv.Store, states, time.Now()); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
		})
	}
}

func TestReceiveJournalExplicitDiscardRequiresExactCID(t *testing.T) {
	_, recv, p, _ := journalKit(t)
	prepareJournal(t, recv, p)
	recv = reopenJournal(t, recv)
	if recv.DiscardReceive("wrong") == nil {
		t.Fatal("discard without exact confirmation")
	}
	journalMust(t, recv.DiscardReceive(hex.EncodeToString(p.CID[:])))
	if pending, err := recv.PendingReceive(); err != nil || pending != nil {
		t.Fatalf("not discarded: %v", err)
	}
	if _, err := recv.ReceiveNext(p, time.Now()); err == nil {
		t.Fatal("discard rolled back ratchet")
	}
}

// Run an actual separate process that exits after its durable application write
// but before journal deletion. Parent recovery must not depend on child memory.
func TestReceiveJournalProcessExitAfterApplicationCommit(t *testing.T) {
	if dir := os.Getenv("SPORE_TEST_RECEIVE_CRASH_DIR"); dir != "" {
		states, err := NewFileStateStore(dir, bytes.Repeat([]byte{9}, 32))
		journalMust(t, err)
		ep, err := NewDurableEndpoint(store.NewMemStore(), states, time.Now())
		journalMust(t, err)
		_ = ep.RecoverReceive(func(p *ReceivePending) error {
			marker := filepath.Join(dir, "application-committed")
			f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			journalMust(t, err)
			_, err = f.Write([]byte(hex.EncodeToString(p.CID[:])))
			journalMust(t, err)
			journalMust(t, f.Sync())
			journalMust(t, f.Close())
			os.Exit(73)
			return nil
		})
		t.Fatal("crash helper did not exit")
	}
	_, recv, p, _ := journalKit(t)
	prepareJournal(t, recv, p)
	cmd := exec.Command(os.Args[0], "-test.run=^TestReceiveJournalProcessExitAfterApplicationCommit$")
	cmd.Env = append(os.Environ(), "SPORE_TEST_RECEIVE_CRASH_DIR="+recv.StateDir())
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("crash helper exit: %v\n%s", err, out)
	}
	recv = reopenJournal(t, recv)
	journalMust(t, recv.RecoverReceive(func(got *ReceivePending) error {
		raw, err := os.ReadFile(filepath.Join(recv.StateDir(), "application-committed"))
		journalMust(t, err)
		if string(raw) != hex.EncodeToString(got.CID[:]) {
			t.Fatal("committed application did not survive process exit")
		}
		return nil
	}))
	if pending, err := recv.PendingReceive(); err != nil || pending != nil {
		t.Fatal("process crash not recovered", err)
	}
}

func TestReceiveJournalNormalMessageDoesNotCreateJournal(t *testing.T) {
	_, recv, p, _ := journalKit(t)
	plain, err := recv.ReceiveNextJournaled(p, time.Now(), func([]byte) bool { return false }, func(*ReceivePending) error { t.Fatal("non-application callback"); return nil })
	journalMust(t, err)
	if len(plain) == 0 {
		t.Fatal("lost message")
	}
	if _, err := os.Stat(filepath.Join(recv.StateDir(), receiveJournalFile)); !os.IsNotExist(err) {
		t.Fatal("normal message retained in journal")
	}
}
