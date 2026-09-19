package sporrelay

import "testing"

func TestResolveChain(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"DERO bech32", "dero1qywrzl2mc2juju4ryqassffu47pmevmns909jnrq9jurdpveyvh27qgke8uqz", "dero"},
		{"EVM 0x", "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae", "evm"},
		{"Solana So1", "So11111111111111111111111111111111111111112", "solana"},
		{"Bitcoin Legacy", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bitcoin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveChain(tt.addr); got != tt.want {
				t.Errorf("ResolveChain(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestParseAmount(t *testing.T) {
	tests := []struct {
		input      string
		wantAsset  string
		wantAtomic uint64
		wantErr    bool
	}{
		{"50USDC", "USDC", 50000000, false},
		{"2.5DERO", "DERO", 250000, false},
		{"100sats", "BTC", 10000, false},
		{"1ETH", "ETH", 1000000000000000000, false},
		{"1SOL", "SOL", 1000000000, false},
		{"0.5XMR", "XMR", 500000000000, false},
		{"", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotAsset, gotAtomic, err := ParseAmount(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAmount(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if gotAsset != tt.wantAsset {
				t.Errorf("ParseAmount(%q) asset = %q, want %q", tt.input, gotAsset, tt.wantAsset)
			}
			if gotAtomic != tt.wantAtomic {
				t.Errorf("ParseAmount(%q) atomic = %d, want %d", tt.input, gotAtomic, tt.wantAtomic)
			}
		})
	}
}
