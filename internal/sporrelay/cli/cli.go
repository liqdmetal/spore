// Package cli provides Spore CLI subcommands that integrate with SporRelay's
// settlement infrastructure. Currently implements:
//
//	spore settle discover <source-amount> <dest-address>
//	  Query RelayOS for multi-chain routes
//	spore settle execute <objective-id> <route-index>
//	  Execute a discovered route through the relayer
//	spore settle assurance <objective-id> [none|light|full]
//	  Generate ZK proof for a settled objective
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/sporrelay"
)

// Discover executes "spore settle discover".
func Discover(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: spore settle discover <amount> <dest-addr> [--chain target-chain]")
		fmt.Fprintln(os.Stderr, "  amount: e.g. \"50USDC\", \"2.5DERO\", \"100sats\"")
		return
	}

	cfg := sporrelay.DefaultConfig()
	cfg.RelayerURL = getRelayerURL()

	srcAmount := args[0]
	destAddr := args[1]

	asset, atomic, err := sporrelay.ParseAmount(srcAmount)
	if err != nil {
		check(fmt.Errorf("parse amount: %w", err))
	}

	var destChain string
	for i := 2; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "--chain":
			if i+1 < len(args) {
				destChain = args[i+1]
				i++
			}
		case "--fee-pct":
			if i+1 < len(args) {
				_, ferr := fmt.Sscanf(args[i+1], "%f", &cfg.FeePct)
				if ferr != nil {
					check(fmt.Errorf("--fee-pct: %w", ferr))
				}
				i++
			}
		}
	}

	obj := sporrelay.NewObjective(
		sporrelay.Source{
			Chain:  "dero", // sender's chain
			Token:  asset,
			Amount: atomic,
		},
		sporrelay.Destination{
			Chain:   destChain,
			Address: destAddr,
			Token:   asset, // same asset unless specified
		},
		cfg.FeePct*100, // max fee pct
	)

	cl := sporrelay.NewClient(cfg)
	resp, err := cl.DiscoverRoutes(context.Background(), obj)
	if err != nil {
		check(fmt.Errorf("discover: %w", err))
	}

	printRouteResponse(resp)
}

// Execute executes "spore settle execute".
func Execute(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: spore settle execute <objective-id> <route-index>")
		return
	}

	objID := args[0]
	routeIdx, perr := parseRouteIdx(args[1])
	if perr != nil {
		check(perr)
	}

	cfg := sporrelay.DefaultConfig()
	cfg.RelayerURL = getRelayerURL()

	// First discover to get the route
	obj := sporrelay.NewObjective(
		sporrelay.Source{Token: "", Amount: 0},
		sporrelay.Destination{Address: ""},
		cfg.FeePct*100,
	)
	obj.ID = objID

	cl := sporrelay.NewClient(cfg)
	resp, err := cl.DiscoverRoutes(context.Background(), obj)
	if err != nil {
		check(fmt.Errorf("discover before execute: %w", err))
	}

	route, serr := selectRoute(resp, routeIdx)
	if serr != nil {
		check(serr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := cl.Execute(ctx, obj, route)
	if err != nil {
		check(fmt.Errorf("execute: %w", err))
	}

	printSettlementResult(result)
}

// Assurance executes "spore settle assurance".
func Assurance(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: spore settle assurance <objective-id> [none|light|full]")
		return
	}

	objID := args[0]
	mode := sporrelay.AssuranceLight
	if len(args) > 1 {
		mode = args[1]
	}

	cfg := sporrelay.DefaultConfig()
	cfg.RelayerURL = getRelayerURL()
	cfg.AssuranceMode = mode

	cl := sporrelay.NewClient(cfg)

	obj := sporrelay.NewObjective(
		sporrelay.Source{Token: "", Amount: 0},
		sporrelay.Destination{Address: ""},
		cfg.FeePct*100,
	)
	obj.ID = objID

	// Get result first
	ctx := context.Background()
	resp, err := cl.DiscoverRoutes(ctx, obj)
	if err != nil {
		check(fmt.Errorf("lookup result: %w", err))
	}

	result := &sporrelay.SettlementResult{ObjectiveID: objID}
	if resp != nil && len(resp.Candidates) > 0 {
		result.Status = "complete" // assume completed for proof gen
	}

	proof, err := cl.GenerateAssurance(ctx, result)
	if err != nil {
		check(fmt.Errorf("assurance: %w", err))
	}

	if proof == nil {
		fmt.Println("No proof generated (assurance mode = none)")
		return
	}

	data, _ := json.MarshalIndent(proof, "", "  ")
	fmt.Println(string(data))
}

// Helpers ---------------------------------------------------------------------

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// parseRouteIdx parses the <route-index> argument of `spore settle execute`.
// It must be a non-negative integer: the index selects among the routes the
// discover step printed (Route 0 = the best route, 1..N = alternatives).
func parseRouteIdx(s string) (int, error) {
	idx, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("route index %q is not an integer (usage: spore settle execute <objective-id> <route-index>)", s)
	}
	if idx < 0 {
		return 0, fmt.Errorf("route index %d is negative — routes are numbered 0..N", idx)
	}
	return idx, nil
}

// selectRoute picks the route to execute from a discovery response.
// Index 0 is the relay market's best route (resp.BestRoute); indices 1..N
// are the ranked alternatives in resp.Candidates (the same numbering
// printRouteResponse shows). Candidates[0] duplicates the best route, so
// index 0 intentionally reads BestRoute directly — it stays valid even when
// the relayer returns no candidate list.
func selectRoute(resp *sporrelay.RouteDiscoveryResponse, idx int) ([]sporrelay.RouteLeg, error) {
	if resp == nil {
		return nil, fmt.Errorf("no route discovery response")
	}
	if idx == 0 {
		if len(resp.BestRoute) == 0 {
			return nil, fmt.Errorf("no routes discovered for this objective")
		}
		return resp.BestRoute, nil
	}
	if idx >= len(resp.Candidates) {
		return nil, fmt.Errorf("route index %d out of range: only %d route(s) discovered (0..%d)",
			idx, len(resp.Candidates), len(resp.Candidates)-1)
	}
	return resp.Candidates[idx].Route, nil
}

func getRelayerURL() string {
	if v := os.Getenv("SPORE_RELAY_URL"); v != "" {
		return v
	}
	return ""
}

func printRouteResponse(resp *sporrelay.RouteDiscoveryResponse) {
	fmt.Printf("\n=== Route Discovery ===\n")
	fmt.Printf("Objective ID: %s\n", resp.ObjectiveID)
	fmt.Printf("Best Route: %d legs, total fees %.3f%%\n",
		len(resp.BestRoute), resp.TotalFees*100)
	fmt.Printf("Est Duration: %v\n\n", resp.EstDuration)

	for i, leg := range resp.BestRoute {
		fmt.Printf("Leg %d: %s → %s\n", i, leg.FromChain, leg.ToChain)
		fmt.Printf("  %s → %s\n", leg.AssetIn, leg.AssetOut)
		fmt.Printf("  In: %d, Out: %d\n", leg.AmountIn, leg.AmountOut)
		fmt.Printf("  Fee: %.3f%%\n", leg.FeePct*100)
		fmt.Printf("  Contract: %s (%s)\n", leg.ContractAddr, leg.Method)
		fmt.Printf("\n")
	}

	if len(resp.Candidates) > 1 {
		fmt.Printf("Also considered %d alternative routes:\n", len(resp.Candidates)-1)
		for j, c := range resp.Candidates[1:] {
			fmt.Printf("  Route %d: fees %.3f%% slippage %dbps trust %.2f\n",
				j+1, c.TotalFeesPct*100, c.SlippageBps, c.TrustScore)
		}
	}
}

func printSettlementResult(r *sporrelay.SettlementResult) {
	statusEmoji := "✓"
	if r.Status == "failed" {
		statusEmoji = "✗"
	}

	fmt.Printf("\n=== Settlement [%s] ===\n", statusEmoji)
	fmt.Printf("Objective: %s\n", r.ObjectiveID)
	fmt.Printf("Status: %s\n", r.Status)
	fmt.Printf("Fees Paid: %.6f\n", r.FeesPaid)
	fmt.Printf("Confirms: %d tx%s\n", len(r.TxHashes), plural(len(r.TxHashes)))

	for i, hash := range r.TxHashes {
		fmt.Printf("  #%d: %s\n", i+1, hash)
	}

	if r.Error != "" {
		fmt.Printf("Error: %s\n", r.Error)
	}

	if r.Proof != nil {
		fmt.Printf("\nZK Proof:\n")
		fmt.Printf("  Type: %s (depth %d)\n", r.Proof.ProofType, r.Proof.Depth)
		fmt.Printf("  Data size: %d bytes\n", len(r.Proof.ProofData))
		fmt.Printf("  Generated: %s\n", r.Proof.GeneratedAt.Format(time.RFC3339))
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
