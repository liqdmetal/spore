package continuity

import (
	"encoding/json"
	"testing"
)

func TestObserverNoticeJSONRoundTrip(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	priv, _, err := NewObserverKey()
	if err != nil {
		t.Fatal(err)
	}
	n, err := Observe(v, priv, now+15)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseNotice(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNoticeForVault(v, parsed); err != nil {
		t.Fatal(err)
	}
}
