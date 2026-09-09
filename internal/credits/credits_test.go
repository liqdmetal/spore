package credits

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func issuerKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// buy runs the full purchase flow the way a real client would.
func buy(t *testing.T, issuer ed25519.PrivateKey, denom string) *Credit {
	t.Helper()
	secret, req, err := NewRequest(denom)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := Issue(issuer, req)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Finalize(issued, secret)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBuyAndRedeem(t *testing.T) {
	issuer, issuerPub := issuerKey(t)
	l, err := OpenLedger(filepath.Join(t.TempDir(), "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := buy(t, issuer, "msg")
	if err := c.Verify(); err != nil {
		t.Fatalf("fresh credit invalid: %v", err)
	}
	if err := l.Redeem(c, issuerPub, "msg", time.Now()); err != nil {
		t.Fatalf("redeem failed: %v", err)
	}
	if l.Count() != 1 {
		t.Fatalf("ledger count = %d", l.Count())
	}
}

// TestDoubleSpendRejected is the core integrity property.
func TestDoubleSpendRejected(t *testing.T) {
	issuer, issuerPub := issuerKey(t)
	l, err := OpenLedger(filepath.Join(t.TempDir(), "l.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := buy(t, issuer, "msg")
	if err := l.Redeem(c, issuerPub, "msg", time.Now()); err != nil {
		t.Fatal(err)
	}
	err = l.Redeem(c, issuerPub, "msg", time.Now())
	if err == nil {
		t.Fatal("DOUBLE SPEND ACCEPTED")
	}
	if !strings.Contains(err.Error(), "ALREADY SPENT") {
		t.Fatalf("wrong error: %v", err)
	}
}

// TestDoubleSpendRejectedAcrossRestart: the ledger must be durable, or a
// restart mints free credits.
func TestDoubleSpendRejectedAcrossRestart(t *testing.T) {
	issuer, issuerPub := issuerKey(t)
	path := filepath.Join(t.TempDir(), "l.json")
	l1, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	c := buy(t, issuer, "msg")
	if err := l1.Redeem(c, issuerPub, "msg", time.Now()); err != nil {
		t.Fatal(err)
	}

	l2, err := OpenLedger(path) // simulate a service restart
	if err != nil {
		t.Fatal(err)
	}
	if l2.Count() != 1 {
		t.Fatalf("reloaded ledger lost the spend: count=%d", l2.Count())
	}
	if err := l2.Redeem(c, issuerPub, "msg", time.Now()); err == nil {
		t.Fatal("double spend accepted after restart — ledger is not durable")
	}
}

// TestConcurrentRedeemSpendsExactlyOnce: many workers racing on ONE credit
// must produce exactly one success.
func TestConcurrentRedeemSpendsExactlyOnce(t *testing.T) {
	issuer, issuerPub := issuerKey(t)
	l, err := OpenLedger(filepath.Join(t.TempDir(), "l.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := buy(t, issuer, "msg")

	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if err := l.Redeem(c, issuerPub, "msg", time.Now()); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("credit redeemed %d times concurrently, want exactly 1", ok)
	}
}

// TestForgedCreditRejected: nobody can mint credits without the issuer key.
func TestForgedCreditRejected(t *testing.T) {
	issuer, issuerPub := issuerKey(t)
	attacker, _ := issuerKey(t)
	l, err := OpenLedger(filepath.Join(t.TempDir(), "l.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Attacker signs their own credit with their own key.
	forged := buy(t, attacker, "msg")
	if err := l.Redeem(forged, issuerPub, "msg", time.Now()); err == nil {
		t.Fatal("credit signed by an unknown key was accepted")
	}

	// Attacker takes a real credit and swaps in their own secret, keeping the
	// genuine signature.
	real := buy(t, issuer, "msg")
	other := make([]byte, secretSize)
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	tampered := *real
	tampered.Secret = hex.EncodeToString(other)
	if err := tampered.Verify(); err == nil {
		t.Fatal("credit with a substituted secret verified")
	}
	if err := l.Redeem(&tampered, issuerPub, "msg", time.Now()); err == nil {
		t.Fatal("credit with a substituted secret was redeemed")
	}
}

// TestDenomCannotBeUpgraded: a cheap credit must not buy an expensive service.
func TestDenomCannotBeUpgraded(t *testing.T) {
	issuer, issuerPub := issuerKey(t)
	l, err := OpenLedger(filepath.Join(t.TempDir(), "l.json"))
	if err != nil {
		t.Fatal(err)
	}
	cheap := buy(t, issuer, "msg")

	// Relabel it as the expensive denom.
	upgraded := *cheap
	upgraded.Denom = "permanent"
	if err := upgraded.Verify(); err == nil {
		t.Fatal("relabelled credit verified — denom is not covered by the signature")
	}
	if err := l.Redeem(&upgraded, issuerPub, "permanent", time.Now()); err == nil {
		t.Fatal("relabelled credit was redeemed at the higher denom")
	}
	// And the genuine cheap credit must be refused for the expensive service.
	if err := l.Redeem(cheap, issuerPub, "permanent", time.Now()); err == nil {
		t.Fatal("a msg credit paid for a permanent-body service")
	}
}

// TestIssuerNeverLearnsTheSecret is the privacy property: what the issuer sees
// at purchase must not contain the secret that is revealed at spend.
func TestIssuerNeverLearnsTheSecret(t *testing.T) {
	issuer, _ := issuerKey(t)
	secret, req, err := NewRequest("msg")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(blob)), hex.EncodeToString(secret)) {
		t.Fatal("the purchase request leaks the secret — spend would be linkable to purchase")
	}
	issued, err := Issue(issuer, req)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Secret != "" {
		t.Fatal("Issue returned a credit containing the secret: the issuer could spend it")
	}
}

// TestIssuerCannotSubstituteADifferentCommitment: Finalize must catch an issuer
// that signs something other than what we asked for.
func TestIssuerCannotSubstituteADifferentCommitment(t *testing.T) {
	issuer, _ := issuerKey(t)
	ourSecret, _, err := NewRequest("msg")
	if err != nil {
		t.Fatal(err)
	}
	// Issuer signs a DIFFERENT request (its own commitment).
	_, otherReq, err := NewRequest("msg")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := Issue(issuer, otherReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Finalize(issued, ourSecret); err == nil {
		t.Fatal("Finalize accepted a signature over someone else's commitment")
	}
}

// TestLedgerStoresNoIdentifyingData inspects the ledger ON DISK. The privacy
// claim is only true if the file itself is clean.
func TestLedgerStoresNoIdentifyingData(t *testing.T) {
	issuer, issuerPub := issuerKey(t)
	path := filepath.Join(t.TempDir(), "l.json")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	c := buy(t, issuer, "msg")
	now := time.Date(2026, 9, 9, 13, 47, 22, 0, time.UTC)
	if err := l.Redeem(c, issuerPub, "msg", now); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := string(raw)

	// The spendable secret must NOT be on disk: a leaked ledger must not hand
	// out usable credits.
	if strings.Contains(disk, c.Secret) {
		t.Fatal("ledger stores the credit SECRET — a ledger leak would be a wallet leak")
	}
	// No exact time (which could be correlated with a connection log).
	if strings.Contains(disk, "13:47") || strings.Contains(disk, "22Z") {
		t.Fatalf("ledger stores an exact timestamp: %s", disk)
	}
	// Day granularity is expected and acceptable.
	if !strings.Contains(disk, "2026-09-09") {
		t.Fatalf("ledger should carry a coarse day bucket, got: %s", disk)
	}
}

func TestRevenueAndPrune(t *testing.T) {
	issuer, issuerPub := issuerKey(t)
	l, err := OpenLedger(filepath.Join(t.TempDir(), "l.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		if err := l.Redeem(buy(t, issuer, "msg"), issuerPub, "msg", old); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := l.Redeem(buy(t, issuer, "permanent"), issuerPub, "permanent", recent); err != nil {
			t.Fatal(err)
		}
	}

	rev := l.Revenue()
	if rev["msg"]["2026-01-01"] != 3 {
		t.Fatalf("revenue msg = %v", rev["msg"])
	}
	if rev["permanent"]["2026-09-09"] != 2 {
		t.Fatalf("revenue permanent = %v", rev["permanent"])
	}
	if got := l.Denoms(); len(got) != 2 || got[0] != "msg" || got[1] != "permanent" {
		t.Fatalf("denoms = %v", got)
	}

	if n := l.Prune(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)); n != 3 {
		t.Fatalf("pruned %d, want 3", n)
	}
	if l.Count() != 2 {
		t.Fatalf("after prune count = %d, want 2", l.Count())
	}
	// Pruning must persist.
	l2, err := OpenLedger(l.path)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Count() != 2 {
		t.Fatalf("prune not persisted: reloaded count = %d", l2.Count())
	}
}

func TestOpenLedgerRejectsCorruptFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l.json")
	if err := os.WriteFile(p, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLedger(p); err == nil {
		t.Fatal("corrupt ledger opened silently — spends would be lost and credits double-spendable")
	}
}

func TestRedeemRequiresExpectedIssuer(t *testing.T) {
	issuer, _ := issuerKey(t)
	l, err := OpenLedger(filepath.Join(t.TempDir(), "l.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := buy(t, issuer, "msg")
	if err := l.Redeem(c, "", "msg", time.Now()); err == nil {
		t.Fatal("Redeem accepted an empty expected-issuer key")
	}
}

func TestNewRequestRejectsEmptyDenom(t *testing.T) {
	if _, _, err := NewRequest(""); err == nil {
		t.Fatal("NewRequest accepted an empty denom")
	}
}

// TestEverySecretIsUnique guards against a broken RNG path.
func TestEverySecretIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		s, _, err := NewRequest("msg")
		if err != nil {
			t.Fatal(err)
		}
		h := hex.EncodeToString(s)
		if seen[h] {
			t.Fatalf("duplicate secret at iteration %d", i)
		}
		seen[h] = true
	}
}
