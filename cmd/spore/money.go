package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Money envelopes ride the ratcheted session exactly like receipts: typed
// JSON plaintext inside an ordinary E2 frame. Two types:
//
//	spore/invoice/v1  — "please send me X of ASSET for THIS" (a bill)
//	spore/payment/v1  — "here is the txid paying invoice X" (a receipt of money)
//
// The actual value transfer rides the CHAIN LAYER (chain.Incoming.Amount on
// DERO/EVM/Bitcoin/TON: pointer + money in ONE atomic tx). The envelope
// carries only the human-readable intent and the settlement reference, so
// the two endpoints can match money to invoices without a server or a
// third party ever seeing either.
const (
	invoiceType = "spore/invoice/v1"
	paymentType = "spore/payment/v1"
)

type invoiceEnvelope struct {
	Type    string `json:"type"`
	ID      string `json:"id"`      // random id so payments can reference it
	Asset   string `json:"asset"`   // "dero" | "evm-native" | ... (chain unit)
	Amount  string `json:"amount"`  // decimal string in WHOLE units ("5.5")
	Atomic  uint64 `json:"atomic"`  // same amount in chain atomic units
	For     string `json:"for"`     // what it's for (free text)
	DueBy   int64  `json:"due_by"`  // unix seconds; 0 = no deadline
	Created int64  `json:"created"` // unix seconds
}

type paymentEnvelope struct {
	Type      string `json:"type"`
	InvoiceID string `json:"invoice_id"` // which invoice this settles ("" = spontaneous)
	Asset     string `json:"asset"`
	Atomic    uint64 `json:"atomic"` // amount that rode the tx (atomic units)
	TxID      string `json:"txid"`   // settlement txid on the carrier chain
	Note      string `json:"note"`
	At        int64  `json:"at"`
}

// assetDecimals maps a chain identifier to the decimal places of its atomic
// unit. DERO: 100000 atomic = 1 DERO (5). EVM/Bitcoin-class chains use 18/8.
// Unknown assets are rejected rather than guessed — money must never be
// unit-ambiguous.
func assetDecimals(asset string) (int, error) {
	switch strings.ToLower(asset) {
	case "dero":
		return 5, nil
	case "evm", "eth", "evm-native":
		return 18, nil
	case "btc", "bitcoin":
		return 8, nil
	case "ton":
		return 9, nil
	case "sol", "solana":
		return 9, nil
	default:
		return 0, fmt.Errorf("unknown asset %q (want dero|evm|btc|ton|sol)", asset)
	}
}

// parseAmount converts a whole-unit decimal string ("5.5") to the chain's
// atomic unit using big.Int — float arithmetic on money is forbidden. Exact
// precision is required: too many decimals is an error, not a truncation.
func parseAmount(asset, amount string) (uint64, error) {
	dec, err := assetDecimals(asset)
	if err != nil {
		return 0, err
	}
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return 0, errors.New("empty amount")
	}
	// Accept optional leading "+" only; no negatives (you cannot pay -5).
	if strings.HasPrefix(amount, "+") {
		amount = amount[1:]
	}
	if strings.HasPrefix(amount, "-") {
		return 0, errors.New("negative amount")
	}
	intPart, fracPart := amount, ""
	if i := strings.IndexByte(amount, '.'); i >= 0 {
		intPart, fracPart = amount[:i], amount[i+1:]
	}
	if len(fracPart) > dec {
		return 0, fmt.Errorf("amount %s exceeds %s precision (%d decimals)", amount, asset, dec)
	}
	fracPart += strings.Repeat("0", dec-len(fracPart))
	v, ok := new(big.Int).SetString(intPart+fracPart, 10)
	if !ok {
		return 0, fmt.Errorf("malformed amount %q", amount)
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("amount %s overflows uint64 atomic units", amount)
	}
	atomic := v.Uint64()
	if atomic == 0 {
		return 0, errors.New("amount must be greater than zero")
	}
	return atomic, nil
}

// formatAmount renders atomic units back to a whole-unit decimal string for
// human display.
func formatAmount(asset string, atomic uint64) string {
	dec, err := assetDecimals(asset)
	if err != nil {
		return fmt.Sprintf("%d atomic", atomic)
	}
	v := new(big.Int).SetUint64(atomic)
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(dec)), nil)
	whole := new(big.Int).Div(v, scale)
	frac := new(big.Int).Mod(v, scale)
	if frac.Sign() == 0 {
		return whole.String()
	}
	s := frac.String()
	s = strings.Repeat("0", dec-len(s)) + s
	s = strings.TrimRight(s, "0")
	return whole.String() + "." + s
}

// parseAmountFlag parses a CLI -amount value like "5.5dero" or "0.0001evm"
// into (asset, atomicUnits). The asset suffix is REQUIRED — money is never
// unit-ambiguous. An empty string returns (0, 0, nil) meaning "no payment,
// postage only".
func parseAmountFlag(s string) (asset string, atomic uint64, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, nil
	}
	// Split trailing alphabetic asset suffix from the numeric prefix.
	i := len(s)
	for i > 0 && isASCIILetter(s[i-1]) {
		i--
	}
	var num string
	num, asset = s[:i], strings.ToLower(s[i:])
	if asset == "" || num == "" {
		return "", 0, fmt.Errorf("malformed -amount %q: want <number><asset>, e.g. 5.5dero", s)
	}
	atomic, err = parseAmount(asset, num)
	if err != nil {
		return "", 0, err
	}
	return asset, atomic, nil
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// carrierCarriesValue reports whether the selected E2 pointer carrier can
// attach native transfer value to the pointer tx. VERIFIED per backend:
// DERO passes amountHint to PostPayloadAmount (wire-tested), EVM passes it
// as tx value on the calldata path the E2 carrier uses (the mailbox-contract
// path is NOT payable and is not what e2Carrier builds). Bitcoin and TON
// backends currently DISCARD amountHint (their PostPayload ignores it), so
// they are refused rather than silently dropping the payment. Nostr relays
// hold no value; Cosmos is a memo seam; Solana's program mailbox carries no
// value in the current integration.
func carrierCarriesValue(chainName string) bool {
	switch strings.ToLower(chainName) {
	case "dero", "evm":
		return true
	default:
		return false
	}
}

func newInvoiceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Deterministic fallback is unacceptable for ids that payments
		// reference; surface the error instead.
		return ""
	}
	return fmt.Sprintf("inv-%x", b)
}

func marshalInvoice(asset, amount, forWhat string, dueBy time.Time) ([]byte, invoiceEnvelope, error) {
	atomic, err := parseAmount(asset, amount)
	if err != nil {
		return nil, invoiceEnvelope{}, err
	}
	id := newInvoiceID()
	if id == "" {
		return nil, invoiceEnvelope{}, errors.New("cannot generate invoice id (crypto/rand failure)")
	}
	env := invoiceEnvelope{
		Type: invoiceType, ID: id, Asset: strings.ToLower(asset), Amount: amount,
		Atomic: atomic, For: forWhat, Created: time.Now().Unix(),
	}
	if !dueBy.IsZero() {
		env.DueBy = dueBy.Unix()
	}
	raw, err := json.Marshal(env)
	return raw, env, err
}

func marshalPayment(invoiceID, asset string, atomic uint64, txid, note string) ([]byte, error) {
	if atomic == 0 {
		return nil, errors.New("payment amount must be greater than zero")
	}
	return json.Marshal(paymentEnvelope{
		Type: paymentType, InvoiceID: invoiceID, Asset: strings.ToLower(asset),
		Atomic: atomic, TxID: txid, Note: note, At: time.Now().Unix(),
	})
}

// parseMoneyEnvelope recognizes invoice/payment plaintext. Returns the kind
// ("invoice"/"payment"), a one-line human summary, and ok.
func parseMoneyEnvelope(b []byte) (kind, summary string, ok bool) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return "", "", false
	}
	switch head.Type {
	case invoiceType:
		var env invoiceEnvelope
		if err := json.Unmarshal(b, &env); err != nil || env.ID == "" || env.Atomic == 0 {
			return "", "", false
		}
		due := ""
		if env.DueBy > 0 {
			due = fmt.Sprintf(" due %s", time.Unix(env.DueBy, 0).Format(time.RFC3339))
		}
		return "invoice", fmt.Sprintf("INVOICE %s: %s %s for %q%s", env.ID, formatAmount(env.Asset, env.Atomic), env.Asset, env.For, due), true
	case paymentType:
		var env paymentEnvelope
		if err := json.Unmarshal(b, &env); err != nil || env.Atomic == 0 || env.TxID == "" {
			return "", "", false
		}
		ref := "spontaneous"
		if env.InvoiceID != "" {
			ref = "for " + env.InvoiceID
		}
		return "payment", fmt.Sprintf("PAID %s %s (%s) tx %s", formatAmount(env.Asset, env.Atomic), env.Asset, ref, shortTx(env.TxID)), true
	}
	return "", "", false
}
