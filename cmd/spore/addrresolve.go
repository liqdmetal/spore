package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	derodaemon "github.com/liqdmetal/spore/internal/daemon"
	"github.com/liqdmetal/spore/internal/maildb"
)

// resolveTo turns a human-supplied -to value into (chain address, pinned-sig
// hex). This is the difference between "impressive demo" and "someone can
// actually message a friend": nobody should have to paste a 66-character
// bech32 address AND separately locate the matching 64-hex pinned sig.
//
// Resolution order matters, and it is deliberately:
//
//  1. A known-prefixed chain address (dero1…, 0x…, npub1…, bc1…) — passed
//     through unchanged. Checked first so an address can never be shadowed by
//     a same-named contact.
//  2. A maildb contact NICKNAME (case-insensitive, exact) — yields BOTH the
//     address AND that contact's pinned sig, so -pinned-sig can be omitted
//     entirely. This is the common case once a contact is added, and it is
//     checked before the generic address heuristic so a long nickname still
//     resolves to the person the user labelled.
//  3. A structurally-recognisable address from a chain with no fixed prefix
//     (Solana base58, TON raw/base64, generic long tokens). This step exists
//     for the compose→flush path: compose resolves a nickname to an address
//     and stores it, then flush re-resolves that stored value possibly WITHOUT
//     the address book. Missing this makes a correctly-queued message fail at
//     flush time — after the user believes it is safely queued.
//  4. A DeroNS name ("alice" / "alice.dero") resolved via -daemon. Yields the
//     ADDRESS ONLY: DeroNS stores an address, not a Spore ratchet sig key, so
//     -pinned-sig (or a maildb contact) is still required to verify bundles.
//     That is an honest limit, not an oversight.
//
// Returns pinnedHex == "" when resolution could not supply one; the caller
// then requires an explicit -pinned-sig.
func resolveTo(ctx context.Context, to, maildbPath, daemonURL string) (addr string, pinnedHex string, err error) {
	to = strings.TrimSpace(to)
	if to == "" {
		return "", "", errors.New("resolveTo: empty -to")
	}

	// 1. Known-prefixed address: never reinterpret it as a name.
	if looksLikeAddress(to) {
		return to, "", nil
	}

	// 2. Address book. Supplies the pinned sig too, which is the real win:
	// one remembered name replaces two opaque hex blobs. Checked BEFORE the
	// generic address heuristic so the user's own labels always win.
	if maildbPath != "" {
		if db, derr := maildb.Open(maildbPath); derr == nil {
			if c, ok := contactByNickname(db, to); ok {
				if c.Address == "" {
					return "", "", fmt.Errorf("contact %q has no address recorded", to)
				}
				return c.Address, c.Pinned, nil
			}
		}
		// A maildb we cannot open is not fatal here — fall through so a
		// corrupt address book does not block sending.
	}

	// 3. Structurally recognisable address from a prefix-less chain.
	if looksLikeStructuralAddress(to) {
		return to, "", nil
	}

	// 4. DeroNS. Address only; the pinned sig still has to come from
	// out-of-band trust (TOFU) or the address book.
	if daemonURL != "" {
		resolved, rerr := derodaemon.NewClient(daemonURL).ResolveName(ctx, to)
		if rerr != nil {
			return "", "", fmt.Errorf("resolve %q: not a contact and DeroNS lookup failed: %w", to, rerr)
		}
		return resolved, "", nil
	}

	return "", "", fmt.Errorf("cannot resolve %q: not a chain address, not a contact in your maildb (spore msg mail add -addr ADDR -nick %s -pinned SIG), and no -daemon given for DeroNS lookup", to, to)
}

// contactByNickname finds a contact whose nickname matches name
// case-insensitively. Nicknames are the user's own labels, so matching is
// exact-after-lowercasing (no fuzzy matching: silently messaging the wrong
// person is worse than an error).
func contactByNickname(db *maildb.MailDB, name string) (maildb.Contact, bool) {
	want := strings.ToLower(strings.TrimSpace(name))
	if want == "" {
		return maildb.Contact{}, false
	}
	for _, c := range db.Contacts() {
		if strings.ToLower(strings.TrimSpace(c.Nickname)) == want {
			return c, true
		}
	}
	return maildb.Contact{}, false
}

// looksLikeStructuralAddress recognises addresses from chains that have no
// fixed prefix (Solana base58, TON raw hex/base64), which looksLikeAddress
// cannot catch. It is deliberately CONSERVATIVE and runs AFTER the address
// book is consulted, so a user's own nickname always wins over this guess:
//
//   - length >= 32 (Solana pubkeys are 44 base58 chars, TON raw is 66;
//     no human nickname is that long)
//   - no whitespace (nicknames and DeroNS names are single tokens; a value
//     with a space is a label, not an address)
//   - a charset that is plausible for base58/base64/hex (no punctuation other
//     than TON's ":" workchain separator)
//
// The failure mode is chosen deliberately: when unsure, treat it as a NAME and
// let resolution fail loudly with guidance, rather than silently posting to a
// malformed destination.
func looksLikeStructuralAddress(s string) bool {
	if len(s) < 32 || strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			// base58 / base64 / hex alphanumerics
		case c == ':' || c == '=' || c == '+' || c == '/' || c == '-' || c == '_':
			// TON workchain separator, base64 padding/alphabet, bech32 sep
		default:
			return false
		}
	}
	return true
}

// looksLikeAddress reports whether s is a raw chain address rather than a
// nickname or DeroNS name. Deliberately CONSERVATIVE: it requires a known
// prefix plus a plausible minimum length, so short human names never match.
// Anything unrecognised falls through to nickname/DeroNS resolution, which
// fails loudly rather than silently posting to a wrong destination.
func looksLikeAddress(s string) bool {
	switch {
	case strings.HasPrefix(s, "dero1"):
		// DERO bech32 mainnet addresses are 66 chars; accept anything
		// plausibly long rather than pinning an exact count (testnet/other
		// hrp variants differ) while still refusing short strings.
		return len(s) >= 40
	case strings.HasPrefix(s, "0x"):
		// EVM: 20 bytes hex = 42 chars total.
		return len(s) == 42
	case strings.HasPrefix(s, "npub1"):
		// Nostr bech32 pubkey.
		return len(s) >= 58
	case strings.HasPrefix(s, "bc1"), strings.HasPrefix(s, "tb1"):
		// Bitcoin bech32 (mainnet/testnet).
		return len(s) >= 26
	case strings.HasPrefix(s, "cosmos1"):
		return len(s) >= 39
	default:
		return false
	}
}
