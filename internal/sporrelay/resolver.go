package sporrelay

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// --- Chain Resolver ----------------------------------------------------------

// ResolveChain returns the canonical chain name for a given address format.
// This maps human-readable formats (bech32, eth addr, sol pubkey, etc.)
// to the internal chain identifiers used throughout Spore's carrier system.
func ResolveChain(address string) string {
	switch {
	case len(address) >= 66 && strings.HasPrefix(address, "dero1"):
		return "dero"
	case len(address) == 42 && strings.HasPrefix(address, "0x"):
		return "evm"
	case len(address) >= 32 && strings.HasPrefix(address, "So1"):
		return "solana"
	case (len(address) == 34 || len(address) == 35) && (address[0] == '1' || address[0] == '3'):
		return "bitcoin"
	case len(address) == 87 || len(address) == 88:
		return "xmr"
	case len(address) >= 44:
		return "ton"
	default:
		return "" // unknown
	}
}

// ParseAmount parses strings like "50USDC", "2.5DERO", "100sats" into
// (asset string, atomic amount uint64, error). Asset names are case-insensitive.
func ParseAmount(s string) (asset string, atomic uint64, err error) {
	if s == "" {
		return "", 0, ErrInvalidAmount
	}

	// Handle satoshi notation: "100sats"
	if strings.HasSuffix(s, "sats") {
		n, perr := strconv.ParseUint(strings.TrimSpace(s[:len(s)-4]), 10, 64)
		return "BTC", n * 100, perr
	}

	// Find where digits end and letters begin
	i := 0
	for i < len(s) && isDigitOrDot(rune(s[i])) {
		i++
	}
	if i == 0 || i == len(s) {
		return "", 0, ErrInvalidAmount
	}

	numeric := s[:i]
	ticker := s[i:]

	// Convert numeric to atomic based on ticker suffix
	switch ticker = strings.ToUpper(ticker); ticker {
	case "DERO", "XDR":
		atomic, err = decimalToAtomic(numeric, 5)
		asset = "DERO"
	case "ETH", "WLFI", "WEVM":
		atomic, err = decimalToAtomic(numeric, 18)
		asset = "ETH"
	case "SOL", "WSOL":
		atomic, err = decimalToAtomic(numeric, 9)
		asset = "SOL"
	case "BTC":
		atomic, err = decimalToAtomic(numeric, 8)
		asset = "BTC"
	case "XMR", "WXMR":
		atomic, err = decimalToAtomic(numeric, 12)
		asset = "XMR"
	case "USDT", "USDT_EVM", "USDT_SOL":
		atomic, err = decimalToAtomic(numeric, 6)
		asset = "USDT"
	case "USDC", "USDC_EVM", "USDC_SOL":
		atomic, err = decimalToAtomic(numeric, 6)
		asset = "USDC"
	case "TON":
		atomic, err = decimalToAtomic(numeric, 9)
		asset = "TON"
	case "COSMOS", "ATOM":
		atomic, err = decimalToAtomic(numeric, 6)
		asset = "ATOM"
	default:
		// Assume smallest unit if no recognized suffix
		n, intErr := strconv.ParseUint(ticker, 10, 64)
		return ticker, n, intErr
	}

	return asset, atomic, err
}

// --- Routing Engine Helper ---------------------------------------------------

// RouteFromDiscover picks the best candidate from a discovery response.
// Returns nil if the best route would cost more than maxFeePct or has
// slippage above maxSlippageBps.
func RouteFromDiscover(resp *RouteDiscoveryResponse, maxFeePct float64, maxSlippageBps uint64) []RouteLeg {
	if resp == nil || len(resp.Candidates) == 0 {
		return nil
	}

	best := &resp.Candidates[0] // already sorted by Efficiency ascending

	if best.TotalFeesPct > maxFeePct {
		return nil
	}
	if best.SlippageBps > maxSlippageBps {
		return nil
	}
	return best.Route
}

// --- Fee Tracking ------------------------------------------------------------

// Ledger records every settlement's fees for accounting/monitoring.
type Ledger struct {
	entries []FeeEntry
}

type FeeEntry struct {
	ObjectiveID string    `json:"objective_id"`
	FeePaid     float64   `json:"fee_paid"`
	Asset       string    `json:"asset"`
	At          time.Time `json:"at"`
	Status      string    `json:"status"` // "complete", "partial", "failed"
}

func NewLedger() *Ledger {
	return &Ledger{entries: make([]FeeEntry, 0)}
}

func (l *Ledger) Record(res SettlementResult, asset string) {
	l.entries = append(l.entries, FeeEntry{
		ObjectiveID: res.ObjectiveID,
		FeePaid:     res.FeesPaid,
		Asset:       asset,
		At:          time.Now(),
		Status:      res.Status,
	})
}

func (l *Ledger) Total() float64 {
	total := 0.0
	for _, e := range l.entries {
		total += e.FeePaid
	}
	return total
}

func (l *Ledger) Count() int { return len(l.entries) }

// Helpers ---------------------------------------------------------------------

func isDigitOrDot(r rune) bool {
	return r >= '0' && r <= '9' || r == '.'
}

func decimalToAtomic(decimal string, decimals uint) (uint64, error) {
	parts := strings.Split(decimal, ".")
	whole, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, err
	}
	multiplier := uint64(1)
	for i := uint(0); i < decimals; i++ {
		multiplier *= 10
	}

	atomic := whole * multiplier
	if len(parts) > 1 {
		frac := parts[1]
		if len(frac) > int(decimals) {
			frac = frac[:decimals]
		}
		if frac == "" {
			return atomic, nil
		}
		fracPadding := strings.Repeat("0", int(decimals)-len(frac))
		val, ferr := strconv.ParseUint(frac+fracPadding, 10, 64)
		if ferr != nil {
			return 0, fmt.Errorf("sporrelay: parse fractional %q: %w", frac, ferr)
		}
		atomic += val
	}
	return atomic, nil
}
