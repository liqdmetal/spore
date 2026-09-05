package evm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/mycelium/internal/chain"
	"github.com/liqdmetal/mycelium/internal/whisper"
)

// TestMailboxLiveAnvil is an end-to-end round trip against a real anvil node:
// deploy MyceliumMailbox, PostPayload via deliver(), then ListIncoming via
// eth_getLogs + read(). It uses the whisper codec so the delivered message text
// is verified end to end. Skips if no anvil/forge is reachable or installed.
func TestMailboxLiveAnvil(t *testing.T) {
	rpc := os.Getenv("MYCELIUM_TEST_ANVIL")
	if rpc == "" {
		rpc = "http://127.0.0.1:8545"
	}
	// Skip cleanly if anvil isn't up or the contract isn't deployed.
	mailbox := os.Getenv("MYCELIUM_TEST_MAILBOX")
	if mailbox == "" {
		mailbox = probeMailbox(t, rpc)
	}
	if mailbox == "" {
		t.Skip("no anvil node with MyceliumMailbox deployed; set MYCELIUM_TEST_MAILBOX")
	}

	// account0 (sender) and account1 (recipient) — both unlocked on anvil.
	const sender = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	const recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// Sender posts via deliver().
	send := NewBackend(rpc, "evm", sender)
	send.SetMailbox(mailbox)
	codec := whisper.CanonicalCodec{}
	if _, err := whisper.SendChain(context.Background(), send, codec, recipient, "hello mailbox anvil"); err != nil {
		t.Fatalf("send via deliver(): %v", err)
	}

	// Recipient recovers via eth_getLogs(Inbox to=us) + read().
	recv := NewBackend(rpc, "evm", recipient)
	recv.SetMailbox(mailbox)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ch, _ := whisper.RecvChain(ctx, recv, codec, chain.WatchOpts{MinHeight: 0, Interval: 200 * time.Millisecond})
	for m := range ch {
		if m.Text == "hello mailbox anvil" {
			t.Logf("LIVE ROUND TRIP OK: recipient %s got text %q via mailbox logs", recipient, m.Text)
			return
		}
	}
	t.Fatal("did not receive the whisper through the mailbox contract (eth_getLogs+read)")
}

// probeMailbox deploys MyceliumMailbox via forge create if needed and returns
// the address, or "" if forge/anvil is unavailable. Kept light for CI-skip.
func probeMailbox(t *testing.T, rpc string) string {
	t.Helper()
	// Deploy with forge create using anvil's funded account0 private key.
	forgeBin := forgePath()
	if forgeBin == "" {
		return ""
	}
	repo, err := repoRoot()
	if err != nil {
		return ""
	}
	// Reuse an already-deployed address by querying none; simplest: deploy fresh.
	priv := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	cmd := exec.Command(forgeBin, "create", "contracts/MyceliumMailbox.sol:MyceliumMailbox",
		"--rpc-url", rpc, "--private-key", priv, "--broadcast")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("forge create failed (skipping live test): %v\n%s", err, out)
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Deployed to:") {
			addr := strings.TrimPrefix(line, "Deployed to:")
			return strings.TrimSpace(addr)
		}
	}
	t.Logf("could not parse deploy address from forge output:\n%s", out)
	return ""
}

func forgePath() string {
	if runtime.GOOS == "windows" {
		for _, cand := range []string{
			filepath.Join(os.Getenv("USERPROFILE"), ".cargo", "bin", "forge.exe"),
			filepath.Join(os.Getenv("HOME"), ".cargo", "bin", "forge.exe"),
		} {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand
			}
		}
		return ""
	}
	if p, err := exec.LookPath("forge"); err == nil {
		return p
	}
	return ""
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}
