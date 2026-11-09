package continuity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

// envClone round-trips a vault through its wire form so a test can hold the
// kind of copy a recipient actually has on disk.
func envClone(t *testing.T, v *Vault) *Vault {
	t.Helper()
	raw, err := v.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	clone, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return clone
}

func envVault(t *testing.T) (*Vault, []byte, []byte) {
	t.Helper()
	owner, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := Create(CreateOptions{
		OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub},
		Payload: []byte("sealed instructions"), CreatedAt: 1000,
		Interval: 10 * time.Second, Grace: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, owner.Priv, recipient.Priv
}

func TestCheckInEnvelopeAdvancesAStaleCopy(t *testing.T) {
	v, owner, _ := envVault(t)
	stale := envClone(t, v)

	// The copy is releasable at 1021 (its only deadline is 1020). The owner
	// checked in twice before that, so the deadline the copy would release
	// against is already revoked.
	if st, err := stale.Status(1021); err != nil || !st.Releasable {
		t.Fatalf("stale copy should be releasable before merge: %+v %v", st, err)
	}
	if err := CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	if err := CheckIn(v, owner, 1010); err != nil {
		t.Fatal(err)
	}
	env, err := v.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Checkins) != 3 {
		t.Fatalf("envelope should carry the whole chain, got %d", len(env.Checkins))
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCheckInEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := stale.MergeCheckIns(parsed)
	if err != nil || merged != 2 {
		t.Fatalf("merge = %d, %v", merged, err)
	}
	if stale.VaultID != v.VaultID || stale.PayloadCiphertext != v.PayloadCiphertext {
		t.Fatal("merge changed vault identity or payload")
	}
	last := stale.Checkins[len(stale.Checkins)-1]
	if last.Deadline != 1030 || last.Seq != 2 {
		t.Fatalf("stale copy not advanced: %+v", last)
	}
	if st, err := stale.Status(1021); err != nil || st.Releasable {
		t.Fatalf("advance copy should not be releasable at 1021: %+v %v", st, err)
	}
	if _, err := stale.Status(1030); err != nil {
		t.Fatal(err)
	}
}

func TestCheckInEnvelopeReplayIsANoOp(t *testing.T) {
	v, owner, _ := envVault(t)
	if err := CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	env, err := v.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	copyV := envClone(t, v)
	merged, err := copyV.MergeCheckIns(env)
	if err != nil || merged != 0 {
		t.Fatalf("replay merged %d records: %v", merged, err)
	}
	if len(copyV.Checkins) != len(v.Checkins) {
		t.Fatalf("replay changed length: %d", len(copyV.Checkins))
	}
}

func TestCheckInEnvelopeRejectsTampering(t *testing.T) {
	v, owner, _ := envVault(t)
	if err := CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	if err := CheckIn(v, owner, 1010); err != nil {
		t.Fatal(err)
	}
	base, err := v.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	stale := envClone(t, v)
	before, err := stale.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	forgedDeadline := *base
	forgedDeadline.Checkins = append([]CheckInRecord(nil), base.Checkins...)
	forgedDeadline.Checkins[2].Deadline++
	badSig := *base
	badSig.Checkins = append([]CheckInRecord(nil), base.Checkins...)
	badSig.Checkins[1].Sig = strings.Repeat("00", 64)
	truncated := *base
	truncated.Checkins = []CheckInRecord{base.Checkins[0], base.Checkins[2]}
	wrongPrev := *base
	wrongPrev.Checkins = append([]CheckInRecord(nil), base.Checkins...)
	wrongPrev.Checkins[2].Prev = strings.Repeat("ab", 32)

	for name, env := range map[string]*CheckInEnvelope{
		"deadline":  &forgedDeadline,
		"signature": &badSig,
		"gap":       &truncated,
		"prev":      &wrongPrev,
	} {
		merged, err := stale.MergeCheckIns(env)
		if err == nil || merged != 0 {
			t.Fatalf("%s: accepted tampered envelope (%d, %v)", name, merged, err)
		}
		if !errors.Is(err, ErrCheckInChain) {
			t.Fatalf("%s: wrong error: %v", name, err)
		}
		after, err := stale.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatalf("%s: merge modified the vault on failure", name)
		}
	}
}

func TestCheckInEnvelopeRejectsForeignVault(t *testing.T) {
	v, _, _ := envVault(t)
	other, otherOwner, _ := envVault(t)
	if err := CheckIn(other, otherOwner, 1005); err != nil {
		t.Fatal(err)
	}
	env, err := other.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.MergeCheckIns(env); !errors.Is(err, ErrCheckInForeign) {
		t.Fatalf("accepted a foreign envelope: %v", err)
	}
	sameVaultWrongKey := *env
	sameVaultWrongKey.VaultID = v.VaultID
	if _, err := v.MergeCheckIns(&sameVaultWrongKey); !errors.Is(err, ErrCheckInForeign) {
		t.Fatalf("accepted a foreign owner key: %v", err)
	}
}

func TestCheckInEnvelopeCatchesUpAfterTheCopyDeadline(t *testing.T) {
	v, owner, _ := envVault(t)
	stale := envClone(t, v)
	if err := CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	env, err := v.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	// Merging is offline history, not a liveness claim: a copy recovered long
	// after the old deadline still adopts the owner's signed chain.
	merged, err := stale.MergeCheckIns(env)
	if err != nil || merged != 1 {
		t.Fatalf("late catch-up = %d, %v", merged, err)
	}
	if st, err := stale.Status(9000); err != nil || !st.Releasable || st.DueAt != 1025 {
		t.Fatalf("late catch-up produced wrong status: %+v %v", st, err)
	}
}

func TestParseCheckInEnvelopeIsStrict(t *testing.T) {
	v, owner, _ := envVault(t)
	if err := CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	env, err := v.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	good, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCheckInEnvelope(good); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	withUnknown := strings.Replace(string(good), `{"version"`, `{"extra":1,"version"`, 1)
	if _, err := ParseCheckInEnvelope([]byte(withUnknown)); !errors.Is(err, ErrCheckInChain) {
		t.Fatalf("accepted unknown field: %v", err)
	}
	if _, err := ParseCheckInEnvelope([]byte(`{}`)); !errors.Is(err, ErrCheckInChain) {
		t.Fatalf("accepted empty object: %v", err)
	}
	if _, err := ParseCheckInEnvelope([]byte(`[]`)); err == nil {
		t.Fatal("accepted a JSON array")
	}
}
