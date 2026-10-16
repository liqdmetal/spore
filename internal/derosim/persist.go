package derosim

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// stateVersion guards the on-disk format. Bump it when the layout changes so an
// old file is refused rather than misread.
const stateVersion = 1

// stateFile is the full persisted simulator state. Keys that are Go array types
// (the HTLC hash) are stored as hex strings, because JSON map keys must be strings.
type stateFile struct {
	Version   int                   `json:"version"`
	HTLCSCID  string                `json:"htlc_scid"`
	DEXSCID   string                `json:"dex_scid"`
	WDEROSCID string                `json:"wdero_scid"`
	Height    uint64                `json:"height"`
	NextSeq   uint64                `json:"next_seq"`
	PoolA     uint64                `json:"pool_a"`
	PoolB     uint64                `json:"pool_b"`
	WDERO     uint64                `json:"wdero"`
	FeeDS     uint64                `json:"fee_ds"`
	Wallets   map[string]walletFile `json:"wallets"`
	HTLCs     map[string]htlcFile   `json:"htlcs"`
}

type walletFile struct {
	Addr    string            `json:"addr"`
	Balance uint64            `json:"balance"`
	Tokens  map[string]uint64 `json:"tokens"`
	Entries []Entry           `json:"entries"`
}

type htlcFile struct {
	Amount    uint64 `json:"amount"`
	Funder    string `json:"funder"`
	Recipient string `json:"recipient"`
	Expiry    uint64 `json:"expiry"`
	Claimed   bool   `json:"claimed"`
	Refunded  bool   `json:"refunded"`
}

// OpenState returns a simulator that persists to path. If the file exists its
// state is restored and must have been written for the same contract IDs; if it
// does not exist a fresh simulator is returned and the file is created on the
// first save. Callers should AddWallet afterwards: AddWallet is idempotent, so
// restored balances are kept.
func OpenState(path, htlcSCID, dexSCID, wderoSCID string) (*Sim, error) {
	if path == "" {
		return nil, errors.New("derosim: empty state path")
	}
	s := New(htlcSCID, dexSCID, wderoSCID)
	s.statePath = path

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("derosim: read state: %w", err)
	}

	var f stateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("derosim: parse state %s: %w", path, err)
	}
	if f.Version != stateVersion {
		return nil, fmt.Errorf("derosim: state %s has version %d, want %d", path, f.Version, stateVersion)
	}
	if f.HTLCSCID != htlcSCID || f.DEXSCID != dexSCID || f.WDEROSCID != wderoSCID {
		return nil, fmt.Errorf("derosim: state %s was written for different contract IDs; refusing to mix chains", path)
	}

	s.height = f.Height
	s.nextSeq = f.NextSeq
	s.poolA, s.poolB, s.wdero, s.feeDS = f.PoolA, f.PoolB, f.WDERO, f.FeeDS
	for route, wf := range f.Wallets {
		tokens := wf.Tokens
		if tokens == nil {
			tokens = map[string]uint64{}
		}
		s.balances[route] = &wallet{addr: wf.Addr, balance: wf.Balance, tokens: tokens, entries: wf.Entries}
	}
	for hashHex, hf := range f.HTLCs {
		raw, err := hex.DecodeString(hashHex)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("derosim: state %s has bad htlc hash %q", path, hashHex)
		}
		var key [32]byte
		copy(key[:], raw)
		s.htlcs[key] = &htlcState{
			amount: hf.Amount, funder: hf.Funder, recipient: hf.Recipient,
			expiry: hf.Expiry, claimed: hf.Claimed, refunded: hf.Refunded,
		}
	}
	return s, nil
}

// Save writes the current state to the state path, if one is set. It takes the
// simulator lock itself, so it must not be called while the lock is held.
func (s *Sim) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// saveLocked writes the state atomically: a temp file in the same directory,
// then a rename, so a crash mid-write never leaves a truncated state file.
// Caller must hold s.mu.
func (s *Sim) saveLocked() error {
	if s.statePath == "" {
		return nil
	}
	f := stateFile{
		Version:   stateVersion,
		HTLCSCID:  s.HTLCSCID,
		DEXSCID:   s.DEXSCID,
		WDEROSCID: s.WDEROSCID,
		Height:    s.height,
		NextSeq:   s.nextSeq,
		PoolA:     s.poolA,
		PoolB:     s.poolB,
		WDERO:     s.wdero,
		FeeDS:     s.feeDS,
		Wallets:   make(map[string]walletFile, len(s.balances)),
		HTLCs:     make(map[string]htlcFile, len(s.htlcs)),
	}
	for route, w := range s.balances {
		f.Wallets[route] = walletFile{Addr: w.addr, Balance: w.balance, Tokens: w.tokens, Entries: w.entries}
	}
	for h, v := range s.htlcs {
		f.HTLCs[hex.EncodeToString(h[:])] = htlcFile{
			Amount: v.amount, Funder: v.funder, Recipient: v.recipient,
			Expiry: v.expiry, Claimed: v.claimed, Refunded: v.refunded,
		}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("derosim: encode state: %w", err)
	}
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("derosim: write state: %w", err)
	}
	if err := os.Rename(tmp, s.statePath); err != nil {
		return fmt.Errorf("derosim: replace state: %w", err)
	}
	return nil
}
