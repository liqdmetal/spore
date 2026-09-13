package nostr

import "testing"

// FuzzDecodePointer drives the nostr pointer codec with hostile strings:
// truncated bech32, wrong hrp, garbage after decoding, huge inputs. It must
// never panic, and a successful decode must satisfy the canonical pointer
// validator.
func FuzzDecodePointer(f *testing.F) {
	f.Add("")
	f.Add("naddr1qq0gmmw")
	f.Add("note1abcdef")
	f.Add("spore1qqqqqq")
	f.Add("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhyetvv9ujuetcv9khqmr99e3k7mg8arnc9")
	f.Add("spore-invite-v1:eyJ2IjoxfQ")
	f.Fuzz(func(t *testing.T, s string) {
		raw, err := decodePointer(s)
		if err == nil {
			if !validPointer(raw) {
				t.Fatalf("decodePointer accepted %q but validPointer rejects it", s)
			}
		}
	})
}
