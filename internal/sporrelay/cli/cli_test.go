package cli

import (
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/sporrelay"
)

// mkLeg builds a single identifiable route leg.
func mkLeg(tag string) sporrelay.RouteLeg {
	return sporrelay.RouteLeg{FromChain: tag + "-in", ToChain: tag + "-out", Index: 0}
}

// mkResp builds a discovery response shaped like the relayer's: one best
// route (2 legs) plus three ranked candidates whose [0] duplicates the best.
func mkResp() *sporrelay.RouteDiscoveryResponse {
	best := []sporrelay.RouteLeg{mkLeg("best1"), mkLeg("best2")}
	alt1 := []sporrelay.RouteLeg{mkLeg("alt1a"), mkLeg("alt1b")}
	alt2 := []sporrelay.RouteLeg{mkLeg("alt2a")}
	alt3 := []sporrelay.RouteLeg{mkLeg("alt3a"), mkLeg("alt3b"), mkLeg("alt3c")}
	return &sporrelay.RouteDiscoveryResponse{
		ObjectiveID: "obj-123",
		BestRoute:   best,
		Candidates: []sporrelay.Candidate{
			{Route: best, TotalFeesPct: 0.001, TrustScore: 0.99},
			{Route: alt1, TotalFeesPct: 0.002, TrustScore: 0.95},
			{Route: alt2, TotalFeesPct: 0.003, TrustScore: 0.90},
			{Route: alt3, TotalFeesPct: 0.004, TrustScore: 0.80},
		},
	}
}

func TestParseRouteIdx(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr string
	}{
		{"0", 0, ""},
		{"1", 1, ""},
		{"42", 42, ""},
		{"007", 7, ""}, // leading zeros are still integers
		{" 2 ", 0, "not an integer"}, // Atoi is strict: no whitespace tolerance
		{"", 0, "not an integer"},
		{"abc", 0, "not an integer"},
		{"1.5", 0, "not an integer"},
		{"-1", 0, "negative"},
		{"-99", 0, "negative"},
		{"0x10", 0, "not an integer"},
	}
	for _, tt := range tests {
		idx, err := parseRouteIdx(tt.in)
		if tt.wantErr != "" {
			if err == nil {
				t.Errorf("parseRouteIdx(%q) = %d, nil; want error containing %q", tt.in, idx, tt.wantErr)
				continue
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseRouteIdx(%q) error = %q; want containing %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRouteIdx(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if idx != tt.want {
			t.Errorf("parseRouteIdx(%q) = %d; want %d", tt.in, idx, tt.want)
		}
	}
}

func TestSelectRouteIndexZeroIsBestRoute(t *testing.T) {
	resp := mkResp()
	route, err := selectRoute(resp, 0)
	if err != nil {
		t.Fatalf("selectRoute(0): %v", err)
	}
	// Must be the best route's legs themselves, not a candidate copy.
	if len(route) != 2 || route[0].FromChain != "best1-in" || route[1].ToChain != "best2-out" {
		t.Errorf("index 0 returned wrong route: %+v", route)
	}
}

func TestSelectRouteAlternativesFollowPrintedNumbering(t *testing.T) {
	resp := mkResp()
	// printRouteResponse labels Candidates[1:] as "Route 1..N", so execute
	// route 2 must pick Candidates[2] (alt2a…), NOT Candidates[1].
	for idx, wantTag := range map[int]string{1: "alt1a", 2: "alt2a", 3: "alt3a"} {
		route, err := selectRoute(resp, idx)
		if err != nil {
			t.Fatalf("selectRoute(%d): %v", idx, err)
		}
		if route[0].FromChain != wantTag+"-in" {
			t.Errorf("selectRoute(%d) picked %q; want %q", idx, route[0].FromChain, wantTag+"-in")
		}
	}
}

func TestSelectRouteOutOfRange(t *testing.T) {
	resp := mkResp() // candidates 0..3 => valid indices 0..3
	for _, idx := range []int{4, 5, 100} {
		_, err := selectRoute(resp, idx)
		if err == nil {
			t.Errorf("selectRoute(%d) should fail", idx)
			continue
		}
		if !strings.Contains(err.Error(), "out of range") {
			t.Errorf("selectRoute(%d) error %q; want out-of-range note", idx, err)
		}
	}
}

func TestSelectRouteNilAndEmpty(t *testing.T) {
	if _, err := selectRoute(nil, 0); err == nil {
		t.Error("nil response should fail")
	}
	empty := &sporrelay.RouteDiscoveryResponse{}
	if _, err := selectRoute(empty, 0); err == nil {
		t.Error("index 0 with no best route should fail")
	}
	// An alternative index on a response without candidates says how many exist.
	_, err := selectRoute(empty, 2)
	if err == nil || !strings.Contains(err.Error(), "only 0 route(s)") {
		t.Errorf("alternative index on empty candidates should explain range; got %v", err)
	}
}

func TestSelectRouteZeroWorksWithoutCandidates(t *testing.T) {
	// A relayer that omits Candidates must still allow executing the best route.
	resp := &sporrelay.RouteDiscoveryResponse{BestRoute: []sporrelay.RouteLeg{mkLeg("solo")}}
	route, err := selectRoute(resp, 0)
	if err != nil {
		t.Fatalf("selectRoute(0) without candidates: %v", err)
	}
	if len(route) != 1 || route[0].FromChain != "solo-in" {
		t.Errorf("wrong route returned: %+v", route)
	}
}
