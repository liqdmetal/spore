// Package solana implements the chain.Chain backend for the Solana network.
//
// It talks to the deployed mycelium mailbox program (program ID
// 4a3DB9nd5q37nCJbgTSDaNML8Vn5nCJNAuJUHpMNmXpa on mainnet, v3) which stores
// per-recipient inboxes in program-derived accounts:
//
//	pda = find_program_address([b"mycelium", recipient_pubkey], program_id)
//
// Each inbox account holds a borsh-serialized Vec<StoredMessage> where
// StoredMessage{ from: [u8;32], data: Vec<u8>, seq: u64 }.
//
// The backend wraps a Solana JSON-RPC endpoint plus a funded signer keypair.
// For the demo the signer both sends and is the recipient of its own messages
// (self-messaging): PostPayload delivers into the signer's OWN inbox PDA and
// ListIncoming reads that same inbox. This mirrors the DERO/EVM backends while
// keeping the mailbox program's "recipient must sign" rule satisfiable by a
// single locally-held keypair.
package solana

import (
	"context"
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/liqdmetal/spore/internal/chain"
)

// DefaultRPCURL is the public Solana mainnet JSON-RPC endpoint used when none
// is supplied.
const DefaultRPCURL = "https://api.mainnet-beta.solana.com"

// DefaultProgramID is the deployed mycelium mailbox program on mainnet (v3).
var DefaultProgramID = solana.MustPublicKeyFromBase58("4a3DB9nd5q37nCJbgTSDaNML8Vn5nCJNAuJUHpMNmXpa")

// Backend adapts a Solana RPC client + signer to chain.Chain.
type Backend struct {
	client    *rpc.Client
	programID solana.PublicKey
	signer    solana.PrivateKey
}

// NewBackend builds a Solana chain.Chain from a JSON-RPC endpoint and a funded
// signer keypair.
func NewBackend(rpcURL string, programID solana.PublicKey, signer solana.PrivateKey) *Backend {
	if rpcURL == "" {
		rpcURL = DefaultRPCURL
	}
	return &Backend{
		client:    rpc.New(rpcURL),
		programID: programID,
		signer:    signer,
	}
}

// Name implements chain.Chain.
func (b *Backend) Name() string { return "solana" }

// Address implements chain.Chain. Returns the signer's base58 pubkey.
func (b *Backend) Address(ctx context.Context) (string, error) {
	return b.signer.PublicKey().String(), nil
}

// Height implements chain.Chain. Returns the current block height (slot) of the
// network.
func (b *Backend) Height(ctx context.Context) (uint64, error) {
	return b.client.GetBlockHeight(ctx, rpc.CommitmentFinalized)
}

// inboxPDA derives the recipient's inbox program address.
func (b *Backend) inboxPDA(recipient solana.PublicKey) (solana.PublicKey, error) {
	pda, _, err := solana.FindProgramAddress(
		[][]byte{[]byte("mycelium"), recipient.Bytes()},
		b.programID,
	)
	return pda, err
}

// signerFn returns a privateKeyGetter that returns the backend signer for its
// own pubkey and nil otherwise (so the transaction is signed by exactly the
// signer keypair).
func (b *Backend) signerFn() func(solana.PublicKey) *solana.PrivateKey {
	return func(key solana.PublicKey) *solana.PrivateKey {
		if key == b.signer.PublicKey() {
			return &b.signer
		}
		return nil
	}
}

// PostPayload implements chain.Chain.
//
// It builds and submits a `deliver` instruction to the spore mailbox
// program, posting the opaque payload (E2E envelope) to the RECIPIENT's inbox
// PDA. The signer is the sender/payer and does NOT need to be the recipient —
// anyone may deliver to an address (email semantics, matching the v3 program).
//
// Instruction data: tag(0x00) followed by the opaque payload bytes.
// Accounts: [sender(signer), recipient, inbox(PDA of recipient, writable),
// payer(signer), system_program].
func (b *Backend) PostPayload(ctx context.Context, recipientAddr string, p chain.Payload, amountHint uint64) (chain.PostResult, error) {
	sender := b.signer.PublicKey()
	recipient, err := solana.PublicKeyFromBase58(recipientAddr)
	if err != nil {
		return chain.PostResult{}, fmt.Errorf("solana: bad recipient address: %w", err)
	}
	inbox, err := b.inboxPDA(recipient)
	if err != nil {
		return chain.PostResult{}, fmt.Errorf("solana: derive inbox PDA: %w", err)
	}

	accounts := solana.AccountMetaSlice{
		solana.Meta(sender).SIGNER(),   // sender authorizes delivery
		solana.Meta(recipient).WRITE(), // recipient (its inbox gets the msg)
		solana.Meta(inbox).WRITE(),     // inbox PDA, writable
		solana.Meta(sender).SIGNER(),   // payer (sender pays)
		solana.Meta(solana.SystemProgramID),
	}

	// data = tag(0) || payload
	data := append([]byte{0x00}, []byte(p)...)
	instruction := solana.NewInstruction(b.programID, accounts, data)

	blockhash, err := b.client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return chain.PostResult{}, fmt.Errorf("solana: get latest blockhash: %w", err)
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{instruction},
		blockhash.Value.Blockhash,
		solana.TransactionPayer(sender),
	)
	if err != nil {
		return chain.PostResult{}, fmt.Errorf("solana: build transaction: %w", err)
	}

	if _, err := tx.Sign(b.signerFn()); err != nil {
		return chain.PostResult{}, fmt.Errorf("solana: sign transaction: %w", err)
	}

	sig, err := b.client.SendTransaction(ctx, tx)
	if err != nil {
		return chain.PostResult{}, fmt.Errorf("solana: send transaction: %w", err)
	}

	return chain.PostResult{TxID: sig.String()}, nil
}

// inboxToIncoming maps a decoded inbox into chain.Incoming entries. Every
// entry carries a STABLE, UNIQUE TxID derived from its sequence number —
// previously all entries had TxID "", and chain.Watch's txid dedup map then
// silently dropped every message after the first, forever (audit H2). The seq
// is monotonic per inbox PDA (assigned by the on-chain program), so it is a
// durable delivery key that also survives process restarts.
func inboxToIncoming(loaded *Inbox) []chain.Incoming {
	out := make([]chain.Incoming, 0, len(loaded.Messages))
	for _, m := range loaded.Messages {
		out = append(out, chain.Incoming{
			TxID:       fmt.Sprintf("sol-inbox-%d", m.Seq),
			TopoHeight: 0,
			Sender:     pubkeyBytesToBase58(m.From[:]),
			Payload:    chain.Payload(m.Data),
		})
	}
	return out
}

// ListIncoming implements chain.Chain.
//
// It reads the signer's own inbox PDA, deserializes the borsh Vec<StoredMessage>,
// and returns each envelope as a chain.Incoming (seq-keyed TxIDs; see
// inboxToIncoming). If the inbox account does not exist yet (nothing ever
// delivered), it returns an empty list.
func (b *Backend) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	recipient := b.signer.PublicKey()
	inbox, err := b.inboxPDA(recipient)
	if err != nil {
		return nil, fmt.Errorf("solana: derive inbox PDA: %w", err)
	}

	acct, err := b.client.GetAccountInfo(ctx, inbox)
	if err != nil {
		if errors.Is(err, rpc.ErrNotFound) {
			return []chain.Incoming{}, nil
		}
		return nil, fmt.Errorf("solana: get inbox account: %w", err)
	}
	if acct.Value == nil || acct.Value.Data == nil {
		return []chain.Incoming{}, nil
	}

	loaded, err := DecodeInbox(acct.Value.Data.GetBinary())
	if err != nil {
		return nil, fmt.Errorf("solana: decode inbox: %w", err)
	}

	return inboxToIncoming(loaded), nil
}

// pubkeyBytesToBase58 renders a 32-byte pubkey as base58 (or a placeholder if
// the slice is not 32 bytes).
func pubkeyBytesToBase58(b []byte) string {
	if len(b) != solana.PublicKeyLength {
		return ""
	}
	var pk solana.PublicKey
	copy(pk[:], b)
	return pk.String()
}
