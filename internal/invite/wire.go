package invite

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// Compact wire form.
//
// ratchet.SPKBundle marshals its [32]byte fields as JSON arrays of 32 decimal
// numbers ("ik_pub":[154,117,...]), which costs roughly 120 characters where
// 64 hex characters would do. Measured, that made the bundle 830 of 1059 JSON
// bytes — the invite token came out at 1428 characters, which is an unpleasant
// thing to paste into a chat.
//
// This wire form encodes the same bytes as hex, cutting the token to roughly
// half. It is used ONLY for the invite envelope: ratchet.SPKBundle's own JSON
// is the mailbox wire format and is deliberately left alone, so nothing about
// prekey publication changes.
//
// The signature covers transcript(), which reads the bundle's BYTES, not this
// JSON — so the encoding here can change freely without invalidating anything.

type wireBundle struct {
	IKPub   string `json:"ik_pub"`
	SPKPub  string `json:"spk_pub"`
	SPKID   uint32 `json:"spk_id"`
	SPKSig  string `json:"spk_sig"`
	OPKPub  string `json:"opk_pub,omitempty"`
	OPKID   uint32 `json:"opk_id,omitempty"`
	OPKHash string `json:"opk_hash"`
}

type wireInvite struct {
	V         int        `json:"v"`
	Name      string     `json:"name,omitempty"`
	Chain     string     `json:"chain"`
	Address   string     `json:"address"`
	Bundle    wireBundle `json:"bundle"`
	PinnedSig string     `json:"pinned_sig"`
	PrekeyURL string     `json:"prekey_url,omitempty"`
	StoreURL  string     `json:"store_url,omitempty"`
	Note      string     `json:"note,omitempty"`
	IssuedAt  string     `json:"issued_at"`
	ExpiresAt string     `json:"expires_at,omitempty"`
	Sig       string     `json:"sig"`
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// decodeHexField requires exactly want bytes, so a truncated or oversized field
// is rejected at parse time rather than surfacing later as a verification
// failure that is blamed on the signature.
func decodeHexField(name, s string, want int) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invite: %s is not valid hex: %w", name, err)
	}
	if len(raw) != want {
		return nil, fmt.Errorf("invite: %s is %d bytes, want %d", name, len(raw), want)
	}
	return raw, nil
}

// MarshalJSON emits the compact wire form.
func (i Invite) MarshalJSON() ([]byte, error) {
	w := wireInvite{
		V:         i.V,
		Name:      i.Name,
		Chain:     i.Chain,
		Address:   i.Address,
		PinnedSig: i.PinnedSig,
		PrekeyURL: i.PrekeyURL,
		StoreURL:  i.StoreURL,
		Note:      i.Note,
		IssuedAt:  i.IssuedAt,
		ExpiresAt: i.ExpiresAt,
		Sig:       i.Sig,
		Bundle: wireBundle{
			IKPub:   hexOf(i.Bundle.IKPub[:]),
			SPKPub:  hexOf(i.Bundle.SPKPub[:]),
			SPKID:   i.Bundle.SPKID,
			SPKSig:  hexOf(i.Bundle.SPKSig[:]),
			OPKID:   i.Bundle.OPKID,
			OPKHash: hexOf(i.Bundle.OPKHash[:]),
		},
	}
	if i.Bundle.OPKPub != nil {
		w.Bundle.OPKPub = hexOf(i.Bundle.OPKPub[:])
	}
	return json.Marshal(w)
}

// UnmarshalJSON parses the compact wire form strictly: unknown fields are
// rejected, and every fixed-width field must be exactly the right size.
func (i *Invite) UnmarshalJSON(raw []byte) error {
	var w wireInvite
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return err
	}

	ik, err := decodeHexField("bundle.ik_pub", w.Bundle.IKPub, 32)
	if err != nil {
		return err
	}
	spk, err := decodeHexField("bundle.spk_pub", w.Bundle.SPKPub, 32)
	if err != nil {
		return err
	}
	sig, err := decodeHexField("bundle.spk_sig", w.Bundle.SPKSig, 64)
	if err != nil {
		return err
	}
	opkHash, err := decodeHexField("bundle.opk_hash", w.Bundle.OPKHash, 32)
	if err != nil {
		return err
	}

	bundle := ratchet.SPKBundle{SPKID: w.Bundle.SPKID, OPKID: w.Bundle.OPKID}
	copy(bundle.IKPub[:], ik)
	copy(bundle.SPKPub[:], spk)
	copy(bundle.SPKSig[:], sig)
	copy(bundle.OPKHash[:], opkHash)
	if w.Bundle.OPKPub != "" {
		opk, err := decodeHexField("bundle.opk_pub", w.Bundle.OPKPub, 32)
		if err != nil {
			return err
		}
		var arr [32]byte
		copy(arr[:], opk)
		bundle.OPKPub = &arr
	}

	*i = Invite{
		V:         w.V,
		Name:      w.Name,
		Chain:     w.Chain,
		Address:   w.Address,
		Bundle:    bundle,
		PinnedSig: w.PinnedSig,
		PrekeyURL: w.PrekeyURL,
		StoreURL:  w.StoreURL,
		Note:      w.Note,
		IssuedAt:  w.IssuedAt,
		ExpiresAt: w.ExpiresAt,
		Sig:       w.Sig,
	}
	return nil
}
