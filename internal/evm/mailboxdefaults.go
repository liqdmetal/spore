// Package evm: shipped per-chain MyceliumMailbox defaults.
//
// v0.9.0 pre-stage for roadmap must-do #3 ("Default -mailbox address wired
// into per-chain config defaults"). The address itself cannot exist until
// the Phase B mainnet deployment — so this registry ships EMPTY, with the
// read path and every guard in place, and deployment day becomes a
// one-entry commit plus a receipt: fill the entry, run go test, release.
//
// The receipt gate is the honest part: an entry without its LIVE_NODES §3
// citation (and vice versa) fails `go test` — the shipped default and the
// published receipt can never drift apart, which is the same honesty bar
// the DERO and Solana rows hold.
package evm

import "strings"

// MailboxDeployment is one shipped default-mailbox entry.
type MailboxDeployment struct {
	// ChainID is the EIP-155 chain id the deployment lives on (8453 = Base
	// mainnet, 84532 = Base Sepolia). An address alone is not a default:
	// sending a Base mainnet pointer to a contract address on another chain
	// would silently target a different (or absent) contract.
	ChainID uint64
	// Address is the deployed MyceliumMailbox contract (0x + 40 hex).
	Address string
	// Default names the release whose config defaults shipped this address
	// (e.g. "v0.9.0") — the value the LIVE_NODES §3 STATUS line records.
	Default string
	// ReceiptRef is the LIVE_NODES §3 anchor (a line-anchored section like
	// "§3 / STATUS / Base mainnet") that must cite this exact address,
	// creation tx, and deployer before the default ships.
	ReceiptRef string
}

// KnownMailboxDeployments holds every shipped default-mailbox address, keyed
// by decimal chain id. EMPTY until the Phase B Base mainnet deployment
// publishes its receipt in docs/LIVE_NODES.md §3 — that is the pre-agreed
// gate, not an oversight.
//
// Deployment day fills exactly one entry, e.g.:
//
//	"8453": {
//		ChainID: 8453,
//		Address: "0x…",
//		Default: "v0.9.0",
//		ReceiptRef: "docs/LIVE_NODES.md §3 STATUS / Base mainnet",
//	},
//
// …after pasting the receipt lines into the STATUS block, then flips
// docs/LIVE_NODES.md's "shipped in" line from <release> to the real one.
var KnownMailboxDeployments = map[string]MailboxDeployment{}

// DefaultMailboxContract returns the shipped default MyceliumMailbox address
// for an EVM chain id, or "" when none is shipped for that chain (the
// user's config evm_mailbox / -mailbox flag then remains the only source —
// same behavior as before this registry existed).
//
// Deliberately NOT consulted when the user set an explicit value: callers
// (mailboxContractOrDefault in cmd/spore) must resolve user config FIRST and
// only fall back here. A shipped default is an onboarding convenience, never
// an override of an operator's own deployment — a mix-your-own-network foot
// gun would be the failure mode of getting that order backwards.
func DefaultMailboxContract(chainID uint64) string {
	if d, ok := KnownMailboxDeployments[strings.ToLower(uintToString(chainID))]; ok {
		return d.Address
	}
	return ""
}

// DefaultMailboxDeployment is DefaultMailboxContract for callers that also
// want the receipt metadata (docs, doctor output).
func DefaultMailboxDeployment(chainID uint64) (MailboxDeployment, bool) {
	d, ok := KnownMailboxDeployments[strings.ToLower(uintToString(chainID))]
	return d, ok
}

// MailboxDeploymentByAddress returns the shipped deployment whose Address is
// addr (case-insensitive), if one exists. Callers use it to classify a
// configured mailbox: a match is a shipped default (its chain id and releasing
// version come from the registry — the address is only valid there), a miss is
// the operator's own override. This is the reverse of DefaultMailboxContract,
// which goes chain id → address.
func MailboxDeploymentByAddress(addr string) (MailboxDeployment, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return MailboxDeployment{}, false
	}
	for _, d := range KnownMailboxDeployments {
		if d.Address != "" && strings.EqualFold(d.Address, addr) {
			return d, true
		}
	}
	return MailboxDeployment{}, false
}

func uintToString(v uint64) string {
	// strconv would do; kept dependency-free and allocation-light for a
	// hot-ish lookup path.
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
