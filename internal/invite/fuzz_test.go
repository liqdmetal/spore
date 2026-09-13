package invite

import (
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzDecode drives the invite parser with hostile payloads: truncated
// base64url, garbage after the prefix, oversized bodies (the MaxEncoded
// guard), unknown JSON fields, huge nesting, and near-valid invites. The
// decoder must never panic and must never accept a payload without a
// version (the V==0 rejection in Decode).
func FuzzDecode(f *testing.F) {
	f.Add(Prefix + "eyJ2IjoxfQ")                       // minimal {"v":1}
	f.Add(Prefix)                                       // empty body
	f.Add(Prefix + strings.Repeat("A", 10000))          // oversized
	f.Add(Prefix + "!!!not-base64!!!")                  // bad encoding
	f.Add("not-an-invite")                              // wrong prefix
	f.Add(Prefix + base64.RawURLEncoding.EncodeToString([]byte(`{"v":0}`))) // version 0
	f.Add(Prefix + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"unknown_field":[]}`)))
	f.Add(Prefix + base64.RawURLEncoding.EncodeToString([]byte(`null`)))
	f.Add(Prefix + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"bundle":{"ik_pub":"zz"}}`)))
	f.Fuzz(func(t *testing.T, s string) {
		inv, err := Decode(s)
		if err == nil {
			if inv.V == 0 {
				t.Fatalf("Decode accepted a payload with no version")
			}
			// round-trip: re-encode must not panic and must decode again
			enc, err := inv.Encode()
			if err != nil {
				t.Fatalf("re-encode of accepted invite failed: %v", err)
			}
			if _, err := Decode(enc); err != nil {
				t.Fatalf("re-decode of accepted invite failed: %v", err)
			}
		}
	})
}
