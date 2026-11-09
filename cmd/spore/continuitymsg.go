package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/continuity"
)

// Continuity check-in envelopes ride a ratchet session as one more typed
// plaintext, next to invoices and receipts: an owner who is away from the
// machine holding the vault can still prove liveness, and a holder merges the
// proof from the inbox instead of waiting for a file to be copied over.
//
// The message is the same owner-signed chain as `continuity check-in -emit`,
// with a type tag in front. It carries no payload ciphertext and no keys, and
// merging it needs no private key — only the owner signature it already has.
const continuityCheckInType = "spore/continuity-checkins/v1"

type continuityCheckInMessage struct {
	Type string `json:"type"`
	continuity.CheckInEnvelope
}

func marshalContinuityCheckInMessage(env *continuity.CheckInEnvelope) ([]byte, error) {
	if env == nil || env.VaultID == "" || len(env.Checkins) == 0 {
		return nil, errors.New("continuity: empty check-in envelope")
	}
	return json.Marshal(continuityCheckInMessage{Type: continuityCheckInType, CheckInEnvelope: *env})
}

// parseContinuityCheckInMessage decodes one typed message. isCheckIn is false
// when the plaintext is simply not a continuity message. A message that claims
// the type but fails validation returns isCheckIn=true with an error, so a
// receiver reports a refusal instead of printing protocol JSON as a chat line.
func parseContinuityCheckInMessage(raw []byte) (*continuity.CheckInEnvelope, bool, error) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.Type != continuityCheckInType {
		return nil, false, nil
	}
	var msg continuityCheckInMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&msg); err != nil {
		return nil, true, fmt.Errorf("continuity: malformed check-in message: %w", err)
	}
	envRaw, err := json.Marshal(msg.CheckInEnvelope)
	if err != nil {
		return nil, true, err
	}
	env, err := continuity.ParseCheckInEnvelope(envRaw)
	if err != nil {
		return nil, true, err
	}
	return env, true, nil
}

// adoptContinuityCheckInMessage merges a typed check-in message into the
// holder's vault copy and reports the outcome. It reads and writes the vault
// with the same strict parser and atomic private writer as every other
// continuity command, and appends nothing when the chain does not verify.
func adoptContinuityCheckInMessage(vaultPath string, raw []byte) (string, bool, error) {
	env, isCheckIn, err := parseContinuityCheckInMessage(raw)
	if !isCheckIn || err != nil {
		return "", isCheckIn, err
	}
	vaultRaw, err := readContinuityArtifact(vaultPath)
	if err != nil {
		return "", true, err
	}
	v, err := continuity.Parse(vaultRaw)
	if err != nil {
		return "", true, err
	}
	merged, err := v.MergeCheckIns(env)
	if err != nil {
		return "", true, err
	}
	if merged > 0 {
		if err := writeContinuityVault(vaultPath, v); err != nil {
			return "", true, err
		}
	}
	last := v.Checkins[len(v.Checkins)-1]
	due := time.Unix(last.Deadline, 0).UTC().Format(time.RFC3339)
	if merged == 0 {
		return fmt.Sprintf("continuity copy already current: seq %d due %s", last.Seq, due), true, nil
	}
	return fmt.Sprintf("continuity check-ins adopted: +%d (seq %d, due %s)", merged, last.Seq, due), true, nil
}

func continuityShortID(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

// msgCheckInE2 sends an existing owner-signed check-in envelope into an open
// session. It does not perform a check-in: the owner runs `continuity
// check-in -emit` where the vault and key live, then sends the artifact here.
func msgCheckInE2(args []string) {
	fs := flag.NewFlagSet("msg checkin", flag.ExitOnError)
	to := fs.String("to", "", "recipient chain address (a holder: recipient or observer)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	checkinsPath := fs.String("checkins", "", "owner-signed check-in envelope JSON (from `continuity check-in -emit`)")
	ttl := fs.Duration("ttl", 24*time.Hour, "frame retention")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	if *to == "" || *sessionHex == "" || *checkinsPath == "" {
		check(errors.New("msg checkin requires -to -session and -checkins"))
	}
	rawID, err := hex.DecodeString(*sessionHex)
	check(err)
	if len(rawID) != 8 {
		check(errors.New("-session must be 16 hex chars (8 bytes)"))
	}
	var sessionID [8]byte
	copy(sessionID[:], rawID)

	// Validate the envelope before the ratchet advances: a malformed artifact
	// must not consume a message key.
	envRaw, err := readContinuityArtifact(*checkinsPath)
	check(err)
	env, err := continuity.ParseCheckInEnvelope(envRaw)
	check(err)
	body, err := marshalContinuityCheckInMessage(env)
	check(err)

	ep, _ := durableEndpointFromFlags(fs)
	_, raw, err := ep.SendNext(sessionID, body, time.Now().Add(*ttl))
	check(err)
	c, err := e2Carrier(fs)
	check(err)
	r, err := c.PostPointer(context.Background(), *to, raw, 1)
	check(err)
	last := env.Checkins[len(env.Checkins)-1]
	fmt.Printf("continuity check-ins for vault %s (seq %d, due %s) sent on tx %s\n",
		continuityShortID(env.VaultID), last.Seq, time.Unix(last.Deadline, 0).UTC().Format(time.RFC3339), r.TxID)
}
