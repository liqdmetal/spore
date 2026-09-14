// Second-device approval (money 2FA): a high-value send can require a
// signature from a second device before the pointer is posted. The approval
// binds the exact on-chain payload (chain, recipient, amount, pointer hash)
// and an expiry, so a stolen primary device cannot post payments alone.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

// ApprovalTTL is how long an approval signature stays valid.
const ApprovalTTL = 15 * time.Minute

// paymentIntent is the canonical, unambiguous commitment an approver signs:
// sha256 over length-prefixed fields — chain, recipient, amount, the pointer
// payload hash (which embeds the body CID), and the expiry unix time.
func paymentIntent(chain, to, amount string, pointerRaw []byte, expiresUnix int64) [32]byte {
	h := sha256.New()
	write := func(b []byte) {
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(b)))
		h.Write(lb[:])
		h.Write(b)
	}
	write([]byte(chain))
	write([]byte(to))
	write([]byte(amount))
	ph := sha256.Sum256(pointerRaw)
	write(ph[:])
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(expiresUnix))
	h.Write(eb[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// requireApproval enforces the second-device gate right before posting. It
// prints the intent the approver must sign, then verifies the presented
// signature (flag or file). Errors are returned, never the transaction
// posted.
func requireApproval(fs *flag.FlagSet, chain, to, amount string, pointerRaw []byte) error {
	approverHex := flagValueOr(fs, "require-approval", "")
	if approverHex == "" {
		return nil
	}
	approver, err := hex.DecodeString(approverHex)
	if err != nil || len(approver) != ed25519.PublicKeySize {
		return errors.New("-require-approval must be a 64-hex ed25519 public key")
	}
	expires := time.Now().Add(ApprovalTTL).Unix()
	intent := paymentIntent(chain, to, amount, pointerRaw, expires)
	intentHex := hex.EncodeToString(intent[:])

	sigHex := flagValueOr(fs, "approval-sig", "")
	if sigHex == "" {
		if f := flagValueOr(fs, "approval-file", ""); f != "" {
			raw, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("approval-file: %w", err)
			}
			sigHex = string(raw)
		}
	}
	if sigHex == "" {
		return fmt.Errorf("send requires second-device approval:\n"+
			"  intent  %s\n"+
			"  approve on the second device: spore msg approve -intent %s -identity APPROVER_IDENTITY_KEY\n"+
			"  then retry with -approval-sig <hex> (or -approval-file FILE). Valid for %s.",
			intentHex, intentHex, ApprovalTTL)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("-approval-sig is not a valid ed25519 signature (128 hex chars)")
	}
	if !ed25519.Verify(ed25519.PublicKey(approver), intent[:], sig) {
		return errors.New("approval signature does not verify against -require-approval; refusing to post")
	}
	fmt.Printf("approval verified (intent %s, expires %s)\n", intentHex[:16]+"…", expiresAt(expires))
	return nil
}

func expiresAt(unix int64) string {
	return time.Unix(unix, 0).Format(time.RFC3339)
}

// msgApprove signs a payment intent with the approver's identity key.
//
//	spore msg approve -intent HEX -identity FILE [-out FILE]
func msgApprove(args []string) {
	fs := flag.NewFlagSet("msg approve", flag.ExitOnError)
	intentHex := fs.String("intent", "", "64-hex intent hash to sign (printed by the sender)")
	identity := fs.String("identity", "", "approver identity private key file (hex, 32 bytes)")
	out := fs.String("out", "", "write the signature to this file (default: print)")
	_ = fs.Parse(args)
	if *intentHex == "" || *identity == "" {
		check(errors.New("approve requires -intent and -identity"))
	}
	intent, err := hex.DecodeString(*intentHex)
	check(err)
	if len(intent) != 32 {
		check(errors.New("-intent must be 64 hex chars (32 bytes)"))
	}
	ik, err := readHexFile(*identity, 32)
	check(err)
	sig := ed25519.Sign(ed25519.PrivateKey(ik), intent)
	sigHex := hex.EncodeToString(sig)
	if *out != "" {
		check(os.WriteFile(*out, append([]byte(sigHex), '\n'), 0o600))
		fmt.Printf("approval signature written to %s\n", *out)
		return
	}
	fmt.Println(sigHex)
}
