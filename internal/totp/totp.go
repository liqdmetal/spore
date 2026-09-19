// Package totp implements RFC 6238 time-based one-time passwords
// (HMAC-SHA1, 30-second window, 6 digits) with zero dependencies. Used as a
// second factor on the hosted mailbox: a user with a TOTP secret configured
// must present a live code alongside their bearer token.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

const (
	// Step is the RFC 6238 time step (30 seconds).
	Step = 30 * time.Second
	// Window is the ±N steps a verifier tolerates (clock drift allowance).
	Window = 1
	// digits are the output length.
	digits = 6
)

// Generate returns the 6-digit code valid at time t for the given base32
// secret (RFC 6238: HOTP(K, T) with T = floor(unix / 30)).
func Generate(secretBase32 string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if err != nil || len(key) == 0 {
		return "", errors.New("totp: secret is not valid base32")
	}
	counter := uint64(t.Unix()) / uint64(Step/time.Second)
	mac := hmac.New(sha1.New, key)
	_ = binary.Write(mac, binary.BigEndian, counter)
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	code := bin % 1_000_000
	return pad(code), nil
}

func pad(code uint32) string {
	s := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		s[i] = byte('0' + code%10)
		code /= 10
	}
	return string(s)
}

// Verify checks a presented code against the secret at time t, tolerating
// ±Window steps of clock drift. Constant-time-ish: only hmac comparisons of
// equal-length strings (length is fixed at 6 digits).
func Verify(code, secretBase32 string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	for i := -Window; i <= Window; i++ {
		got, err := Generate(secretBase32, t.Add(time.Duration(i)*Step))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(got), []byte(code)) {
			return true
		}
	}
	return false
}

// NewSecret generates a random 20-byte base32 secret (160 bits, RFC 4226
// recommendation).
func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
