// Package sporrelay provides the bridge between Spore's messaging and value
// flows and RelayOS's objective-first economic coordination engine. It wraps
// Relay's agent-market discovery, multi-hop liquidity routing, and recursive ZK
// proof generation so Spore clients can send value across N chains with a single
// command like:  spore msg pay --to <address> --amount 50usdc --route auto
package sporrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// --- Configuration -----------------------------------------------------------

const (
	AssuranceNone = "none"
	AssuranceLight = "light"
	AssuranceFull  = "full"
)

// Config describes how to reach a local or remote RelayOS node and which
// contracts/binders to use during settlement.
type Config struct {
	// RelayerURL is the HTTP endpoint of a running RelayOS daemon
	// (e.g. "http://localhost:8976"). Empty = use embedded fallback.
	RelayerURL string `json:"relayer_url"`
	// APIToken is optional bearer auth for private relay nodes.
	APIToken string `json:"api_token,omitempty"`
	// FeePct is the percentage cut taken per routed leg (e.g. 0.002 = 0.2%).
	FeePct float64 `json:"fee_pct"`
	// AssuranceMode controls ZK proof depth: none, light, or full.
	// "none" = no proofs (fastest, lowest trust).
	// "light" = Nova folding depth 2 (good balance).
	// "full" = Nova folding depth 8 (maximum assurance).
	AssuranceMode string `json:"assurance_mode"`
}

func DefaultConfig() *Config {
	return &Config{
		RelayerURL:    "",
		APIToken:      "",
		FeePct:        0.002,     // 20bps default cut
		AssuranceMode: AssuranceLight,
	}
}

// Clone returns a deep copy of c.
func (c *Config) Clone() *Config {
	cp := *c
	return &cp
}

func (c *Config) String() string {
	return fmt.Sprintf("sporrelay{url=%q fee=%.3f%% assurance=%s}",
		c.RelayerURL, c.FeePct*100, c.AssuranceMode)
}

// Validate checks that c has sane defaults.
func (c *Config) Validate() error {
	if c.FeePct < 0 || c.FeePct > 0.1 {
		return fmt.Errorf("sporrelay: fee pct %f out of range [0, 0.1]", c.FeePct)
	}
	switch c.AssuranceMode {
	case AssuranceNone, AssuranceLight, AssuranceFull:
	default:
		return fmt.Errorf("sporrelay: unknown assurance mode %q", c.AssuranceMode)
	}
	return nil
}

// --- Types -------------------------------------------------------------------

// Source represents a chain source token/asset being routed out.
type Source struct {
	Chain    string  // "dero", "evm", "solana", etc.
	Address  string  // sender address on that chain
	Token    string  // asset identifier ("DERO", "USDC", etc.)
	Amount   uint64  // atomic amount
	RingSize uint64  // anonymity set (0 = chain default)
}

// Destination represents where value should arrive.
type Destination struct {
	Chain   string // "ethereum", "tron", etc.
	Address string // recipient address on target chain
	Token   string // requested asset on target chain
	Amount  uint64 // expected arrival amount (before fees)
}

// RouteLeg represents one hop in a multi-chain swap.
type RouteLeg struct {
	Index         int       // position in route (0-based)
	FromChain     string    // source chain of this leg
	ToChain       string    // target chain of this leg
	FromAddress   string    // who sends this leg
	ToAddress     string    // who receives this leg
	AssetIn       string    // asset entering this leg
	AssetOut      string    // asset exiting this leg
	AmountIn      uint64    // input amount
	AmountOut     uint64    // output amount (after spread + fee)
	FeePct        float64   // platform fee taken on this leg
	TxID          string    // txid after submission
	ContractAddr  string    // smart contract used (if any)
	Method        string    // contract method invoked
	BlockHeight   uint64    // confirming block on target
	Confirmations uint64    // confirmations received
}

// ExchangeRate captures the quoted price at route-building time.
type ExchangeRate struct {
	SrcAsset    string    // source asset
	DstAsset    string    // destination asset
	Rate        float64   // 1 SrcAsset = Rate DstAssets
	Liquidity   float64   // available liquidity at this rate
	SlippageBps uint64    // estimated slippage in basis points
	Provider    string    // liquidity pool / AMM ID
	Timestamp   time.Time // quote validity
}

// Objective is what gets sent to RelayOS for route finding.
// See OpenRelay Assurance 4.0 RC84 docs.
type Objective struct {
	ID        string        `json:"id"`             // unique objective UUID
	Source    Source        `json:"source"`
	Dest      Destination   `json:"destination"`
	MaxFeePct float64       `json:"max_fee_pct"`    // upper bound on total fees
	Timeout   time.Duration `json:"timeout"`        // max wait for completion
	CreatedAt time.Time     `json:"created_at"`
}

// NewObjective creates an objective from source → dest with defaults.
func NewObjective(src Source, dst Destination, maxFeePct float64) Objective {
	return Objective{
		ID:        generateObjID(),
		Source:    src,
		Dest:      dst,
		MaxFeePct: maxFeePct,
		Timeout:   5 * time.Minute,
		CreatedAt: time.Now(),
	}
}

func generateObjID() string { return "" } // TODO: cryptographically random UUID v7

// RouteDiscoveryResponse mirrors the RelayOS agent-market reply.
type RouteDiscoveryResponse struct {
	ObjectiveID string        `json:"objective_id"`
	BestRoute   []RouteLeg    `json:"best_route"`
	TotalFees   float64       `json:"total_fees_pct"`
	EstDuration time.Duration `json:"estimated_duration_ms"`
	Candidates  []Candidate   `json:"candidates"` // all viable routes ranked
}

// Candidate represents one discovered route with its scoring metadata.
type Candidate struct {
	Route         []RouteLeg `json:"route"`
	TotalFeesPct  float64    `json:"total_fees_pct"`
	SlippageBps   uint64     `json:"slippage_bps"`
	Efficiency    float64    `json:"efficiency"` // lower = better; combines fee + time + risk
	AgentIDs      []string   `json:"agent_ids"`  // which agents would execute each leg
	TrustScore    float64    `json:"trust_score"`
}

// AssuranceProof wraps the output of recursive ZK proof generation.
type AssuranceProof struct {
	ObjectiveID      string    `json:"objective_id"`
	ProofData        string    `json:"proof_data"`   // base64-encoded ZK proof blob
	VerificationKey  string    `json:"verification_key"`
	ProofType        string    `json:"proof_type"`   // "nova_ivc", "stark", "groth16_batch"
	Depth            uint      `json:"depth"`        // recursion layers (Nova folding rounds)
	GeneratedAt      time.Time `json:"generated_at"`
}

// SettlementResult captures final state after all legs settle.
type SettlementResult struct {
	ObjectiveID   string         `json:"objective_id"`
	Status        string         `json:"status"`       // "complete", "partial", "failed", "refund"
	Route         []RouteLeg     `json:"route"`
	TxHashes      []string       `json:"tx_hashes"`    // one per confirmed leg
	FeesPaid      float64        `json:"fees_paid"`    // total fees extracted
	Proof         *AssuranceProof `json:"proof,omitempty"`
	CompletedAt   time.Time      `json:"completed_at"`
	Error         string         `json:"error,omitempty"`
}

// --- Client ------------------------------------------------------------------

// Client talks to a RelayOS daemon over HTTP (the standard protocol).
type Client struct {
	cfg   *Config
	http  *http.Client
	baseURL string
}

// NewClient builds a SporRelay client backed by the given config.
func NewClient(cfg *Config) *Client {
	return &Client{
		cfg:   cfg.Clone(),
		http:  &http.Client{Timeout: 60 * time.Second},
		baseURL: cfg.RelayerURL,
	}
}

// DiscoverRoutes asks RelayOS for all viable multi-chain routes from src→dst.
func (cl *Client) DiscoverRoutes(ctx context.Context, obj Objective) (*RouteDiscoveryResponse, error) {
	if cl.baseURL == "" {
		return nil, ErrNoRelayer
	}

	endpoint := fmt.Sprintf("%s/api/v1/objectives/%s/discover", cl.baseURL, obj.ID)
	body, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("sporrelay: marshal objective: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sporrelay: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cl.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cl.cfg.APIToken)
	}

	resp, err := cl.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sporrelay: discover: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("sporrelay: discover %d: %s", resp.StatusCode, string(msg))
	}

	var result RouteDiscoveryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&result); err != nil {
		return nil, fmt.Errorf("sporrelay: decode discover response: %w", err)
	}
	return &result, nil
}

// Execute executes a discovered route through RelayOS. It submits each leg,
// waits for confirmation, then collects assurance proofs.
func (cl *Client) Execute(ctx context.Context, obj Objective, route []RouteLeg) (*SettlementResult, error) {
	if cl.baseURL == "" {
		return nil, ErrNoRelayer
	}

	endpoint := fmt.Sprintf("%s/api/v1/objectives/%s/execute", cl.baseURL, obj.ID)
	type execReq struct {
		Objective Objective `json:"objective"`
		Route     []RouteLeg `json:"route"`
	}

	payload, err := json.Marshal(execReq{Objective: obj, Route: route})
	if err != nil {
		return nil, fmt.Errorf("sporrelay: marshal exec request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("sporrelay: create exec request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cl.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cl.cfg.APIToken)
	}

	resp, err := cl.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sporrelay: execute: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("sporrelay: execute %d: %s", resp.StatusCode, string(msg))
	}

	// 202 Accepted = async execution; poll status endpoint.
	result := &SettlementResult{ObjectiveID: obj.ID}
	if resp.StatusCode == http.StatusOK {
		var tmp struct {
			Result *SettlementResult `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tmp); err != nil {
			return nil, fmt.Errorf("sporrelay: decode exec response: %w", err)
		}
		result = tmp.Result
	} else {
		// Poll until complete or timeout
		statusURL := fmt.Sprintf("%s/api/v1/objectives/%s/status", cl.baseURL, obj.ID)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				result.Status = "failed"
				result.Error = ctx.Err().Error()
				return result, nil
			case <-ticker.C:
				if time.Since(obj.CreatedAt) > obj.Timeout {
					result.Status = "failed"
					result.Error = "execution timed out"
					return result, nil
				}
				sreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
				if cl.cfg.APIToken != "" {
					sreq.Header.Set("Authorization", "Bearer "+cl.cfg.APIToken)
				}
				sresp, serr := cl.http.Do(sreq)
				if serr == nil {
					if sresp.StatusCode == http.StatusOK {
						var tmp struct {
							Result *SettlementResult `json:"result"`
						}
						if err := json.NewDecoder(sresp.Body).Decode(&tmp); err == nil {
							result = tmp.Result
							if result.Status == "complete" || result.Status == "failed" {
								return result, nil
							}
						}
						sresp.Body.Close()
					} else {
						sresp.Body.Close()
					}
				}
			}
		}
	}

	return result, nil
}

// GenerateAssurance produces a Nova-style recursive IVC proof for a settled
// objective. Depth=0 means no proof (fast), depth=N means N rounds of folding.
func (cl *Client) GenerateAssurance(ctx context.Context, result *SettlementResult) (*AssuranceProof, error) {
	if cl.cfg.AssuranceMode == AssuranceNone {
		return nil, nil
	}

	depthMap := map[string]uint{AssuranceLight: 2, AssuranceFull: 8}
	depth := depthMap[cl.cfg.AssuranceMode]
	if depth == 0 {
		depth = 2
	}

	endpoint := fmt.Sprintf("%s/api/v1/objectives/%s/assure", cl.baseURL, result.ObjectiveID)
	type assureReq struct {
		Result  SettlementResult `json:"result"`
		Depth   uint             `json:"depth"`
		Type    string           `json:"proof_type"` // "nova_ivc"
	}

	payload, err := json.Marshal(assureReq{Result: *result, Depth: depth, Type: "nova_ivc"})
	if err != nil {
		return nil, fmt.Errorf("sporrelay: marshal assure request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("sporrelay: create assure request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cl.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cl.cfg.APIToken)
	}

	resp, err := cl.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sporrelay: generate assurance: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("sporrelay: assure %d: %s", resp.StatusCode, string(msg))
	}

	var proof AssuranceProof
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("sporrelay: decode assurance: %w", err)
	}
	return &proof, nil
}

// CalculateFees computes the platform cut for a route.
func (cl *Client) CalculateFees(route []RouteLeg) float64 {
	totalFees := 0.0
	for _, leg := range route {
		fee := float64(leg.AmountIn) * cl.cfg.FeePct
		totalFees += fee
	}
	return totalFees
}

// Verify ensures every executed leg's txid appears in the corresponding chain's
// history before returning success. Pluggable per-chain backends.
func (cl *Client) Verify(_ context.Context, _ *SettlementResult) error {
	// TODO: wire actual chain verification via chain.Chain backends
	return nil
}

// Errors ---------------------------------------------------------------------

var (
	ErrNoRelayer     = fmt.Errorf("sporrelay: no relayer configured (set RelayerURL)")
	ErrInvalidRoute  = fmt.Errorf("sporrelay: invalid route (empty or circular)")
	ErrInvalidAmount = fmt.Errorf("sporrelay: invalid amount string")
)
