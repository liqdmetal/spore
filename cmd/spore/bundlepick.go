package main

import (
	"context"
	"fmt"

	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchet"
)

// fetchFunc matches fetchBundle's signature, injected so the resolution rules
// below are testable without a network or a mailbox.
type fetchFunc func(ctx context.Context, url, token string) (*ratchet.SPKBundle, error)

// pickBundle resolves the recipient's prekey bundle, in priority order:
//
//  1. an explicit -bundle file;
//  2. an explicit -bundle-url;
//  3. the contact's recorded PrekeyURL — preferred over the stored bundle
//     because a mailbox hands out a FRESH single-use prekey per sender;
//  4. the bundle the contact's signed invite carried.
//
// Step 4 is what makes `spore msg mail add -invite TOKEN` followed by
// `spore msg send-e2 -to <nick>` work with no bundle flags: the invite already
// carried a verified bundle. It is also the more fragile option, so it warns.
//
// Anything returned here is still verified against the pinned sig by
// EstablishInitiator — a stored bundle is a convenience, never a trust
// shortcut. That is why a stale or substituted stored bundle is not a security
// hole, only a delivery failure.
func pickBundle(
	ctx context.Context,
	explicitFile, explicitURL, explicitToken string,
	c maildb.Contact,
	haveContact bool,
	fetch fetchFunc,
	warn func(string),
) (*ratchet.SPKBundle, error) {
	if explicitFile != "" {
		return readBundle(explicitFile)
	}
	if explicitURL != "" {
		b, err := fetch(ctx, explicitURL, explicitToken)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", explicitURL, err)
		}
		return b, nil
	}

	if !haveContact {
		return nil, fmt.Errorf("no -bundle or -bundle-url given, and -to did not resolve to a contact " +
			"with a recorded prekey route (add one from a signed invite with " +
			"`spore msg mail add -invite TOKEN`)")
	}

	// 3. The contact's live prekey endpoint: a fresh single-use prekey.
	if c.PrekeyURL != "" {
		b, err := fetch(ctx, c.PrekeyURL, "")
		if err == nil {
			return b, nil
		}
		if c.Bundle == nil {
			return nil, fmt.Errorf("contact's prekey URL %s: %w", c.PrekeyURL, err)
		}
		if warn != nil {
			warn(fmt.Sprintf("prekey URL %s unreachable (%v) — falling back to the bundle "+
				"embedded in the invite", c.PrekeyURL, err))
		}
	}

	// 4. The bundle the invite carried.
	if c.Bundle != nil {
		if warn != nil && c.Bundle.OPKPub != nil {
			warn("using the invite's EMBEDDED single-use prekey: it works for exactly " +
				"one sender, so this may fail if it was already used")
		}
		return c.Bundle, nil
	}

	return nil, fmt.Errorf("contact has no recorded prekey route (no -bundle, no -bundle-url, "+
		"and no PrekeyURL or bundle stored) — re-add them from a fresh invite, or pass "+
		"-bundle-url https://THEIR-MAILBOX/prekey (contact %s)", c.Address)
}
