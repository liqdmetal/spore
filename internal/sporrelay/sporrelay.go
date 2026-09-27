// Package sporrelay is Spore's narrow adapter boundary to RelayOS.
//
// Spore can submit an already-authorized objective-registration command. It
// does not mint Relay identities or grants, execute work, verify outcomes, or
// settle funds. See docs/RELAY_WORK_ORDER.md for the wire contract and gaps.
package sporrelay

import "errors"

var (
	ErrNoRelayer                         = errors.New("sporrelay: no RelayOS URL configured (set SPORE_RELAY_URL)")
	ErrWorkExecutionUnsupported          = errors.New("sporrelay: work execution is unsupported by the inspected RelayOS HTTP service")
	ErrCompletionVerificationUnavailable = errors.New("sporrelay: completion is unverified; the available RelayOS API exposes no independently verifiable work outcome")
)

// Config names the RelayOS service. APIToken is only for an optional
// reverse-proxy bearer gate; it is not a substitute for RelayOS's signed
// AuthorityGrant and actor signature.
type Config struct {
	RelayerURL string `json:"relayer_url"`
	APIToken   string `json:"api_token,omitempty"`
}
