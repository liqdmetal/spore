package evm

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/liqdmetal/mycelium/internal/chain"
)

// evmBlock is the minimal eth_getBlockByNumber result shape.
type evmBlock struct {
	Number       string  `json:"number"`
	Transactions []evmTx `json:"transactions"`
}

type evmTx struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	Input string `json:"input"` // calldata hex
}

// evmScanIncoming scans blocks from minHeight to current height (bounded to
// avoid archive-node needs) and returns txs whose `to` equals our address,
// treating each tx's calldata as a received mycelium payload.
func evmScanIncoming(ctx context.Context, b *Backend, minHeight uint64) ([]chain.Incoming, error) {
	top, err := b.Height(ctx)
	if err != nil {
		return nil, err
	}
	// Bound the scan to the last 200 blocks to stay node-friendly; a mailbox
	// contract + log indexer is the scalable path.
	if minHeight < 200 && top > 200 {
		minHeight = top - 200
	}
	if minHeight > top {
		return nil, nil
	}
	ours := strings.ToLower(b.from)
	var out []chain.Incoming
	for h := minHeight; h <= top; h++ {
		blk, err := b.getBlock(ctx, h)
		if err != nil {
			continue // skip unservable blocks
		}
		for _, tx := range blk.Transactions {
			if tx.To == "" {
				continue
			}
			if strings.EqualFold(tx.To, ours) && tx.Input != "" && tx.Input != "0x" {
				raw, err := hex.DecodeString(strings.TrimPrefix(tx.Input, "0x"))
				if err != nil {
					continue
				}
				out = append(out, chain.Incoming{
					TxID:       tx.Hash,
					TopoHeight: int64(h),
					Sender:     tx.From,
					Payload:    raw,
				})
			}
		}
	}
	return out, nil
}

func (b *Backend) getBlock(ctx context.Context, n uint64) (*evmBlock, error) {
	var blk evmBlock
	hexNum := "0x" + new(big.Int).SetUint64(n).Text(16)
	if err := b.call(ctx, "eth_getBlockByNumber", []interface{}{hexNum, true}, &blk); err != nil {
		return nil, err
	}
	return &blk, nil
}
