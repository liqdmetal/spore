package totp

import (
	"testing"
	"time"
)

// 6-digit vectors from the RFC 4226/Google Authenticator test secret
// "12345678901234567890" at the listed unix times.
var gaVectors = []struct {
	t    int64
	code string
}{
	{59, "287082"},
	{1111111109, "081804"},
	{1111111111, "050471"},
	{1234567890, "005924"},
	{2000000000, "279037"},
	{20000000000, "353130"},
}

func TestGenerateAgainstKnownVectors(t *testing.T) {
	// base32("12345678901234567890") — the RFC 4226 vectors use the raw
	// ASCII bytes as the HMAC key, so the base32 form is GEZD…QOJQ.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, v := range gaVectors {
		got, err := Generate(secret, time.Unix(v.t, 0))
		if err != nil {
			t.Fatalf("Generate(%d): %v", v.t, err)
		}
		if got != v.code {
			t.Errorf("t=%d: got %s want %s", v.t, got, v.code)
		}
	}
}

func TestGenerateRejectsBadSecret(t *testing.T) {
	if _, err := Generate("!!!not-base32!!!", time.Now()); err == nil {
		t.Fatal("bad base32 accepted")
	}
}

func TestVerifyWindowAndRejection(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, err := Generate(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(code, secret, now) {
		t.Fatal("current code must verify")
	}
	old, _ := Generate(secret, now.Add(-Step))
	if !Verify(old, secret, now) {
		t.Fatal("one-step-old code must verify within the window")
	}
	if Verify("000000", secret, now) {
		t.Fatal("wrong code verified")
	}
	if Verify("abc", secret, now) || Verify("12345", secret, now) {
		t.Fatal("malformed code verified")
	}
}

func TestNewSecretRoundTrip(t *testing.T) {
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(s, time.Now()); err != nil {
		t.Fatalf("generated secret unusable: %v", err)
	}
}
