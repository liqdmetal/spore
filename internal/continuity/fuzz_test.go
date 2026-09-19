package continuity

import (
	"encoding/json"
	"testing"
	"time"

	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

func FuzzContinuityArtifactParsers(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("{"))
	f.Add([]byte("null"))
	f.Add([]byte("[] {}"))
	f.Add([]byte(`{"version":1,"future":true}`))

	owner, err := sporecrypto.GenerateKey()
	if err == nil {
		recipient, recipientErr := sporecrypto.GenerateKey()
		if recipientErr == nil {
			vault, vaultErr := Create(CreateOptions{
				OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub},
				Payload: []byte("fuzz seed"), CreatedAt: 1_800_000_000,
				Interval: time.Hour, Grace: time.Hour,
			})
			if vaultErr == nil {
				if raw, marshalErr := json.Marshal(vault); marshalErr == nil {
					f.Add(raw)
				}
			}
		}
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxArtifactBytes {
			t.Skip()
		}
		_, _ = Parse(raw)
		_, _ = ParseNotice(raw)
		_, _ = ParseQuorumPolicy(raw)
		_, _ = ParseQuorumAttestation(raw)
		_, _ = ParseQuorumRelease(raw)
		_, _ = ParseChainAnchor(raw)
		var generic any
		_, _ = generic, decodeStrict(raw, &generic)
	})
}

func FuzzContinuityStateVerification(f *testing.F) {
	f.Add([]byte("seed"), int64(1_800_000_000))
	f.Add([]byte{}, int64(1))
	f.Add([]byte("payload"), int64(0))
	f.Fuzz(func(t *testing.T, payload []byte, now int64) {
		if len(payload) > MaxPayloadBytes || now <= 0 {
			t.Skip()
		}
		owner, err := sporecrypto.GenerateKey()
		if err != nil {
			t.Skip()
		}
		recipient, err := sporecrypto.GenerateKey()
		if err != nil {
			t.Skip()
		}
		vault, err := Create(CreateOptions{
			OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub},
			Payload: payload, CreatedAt: now, Interval: time.Second, Grace: 0,
		})
		if err != nil {
			t.Skip()
		}
		_ = vault.Verify()
		_, _ = vault.Status(now)
	})
}
