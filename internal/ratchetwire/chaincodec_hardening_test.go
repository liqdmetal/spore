package ratchetwire

import (
	"math"
	"testing"
)

func TestAsUintRejectsNonFiniteAndFractionalFloat(t *testing.T) {
	for _, v := range []float64{1.5, math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		if got, err := asUint(v); err == nil {
			t.Errorf("asUint(%v) = %d, want error", v, got)
		}
	}
	for _, v := range []float64{0, 1, 18446744073709549568} {
		if got, err := asUint(v); err != nil {
			t.Errorf("asUint(%v) error = %v", v, err)
		} else if got != uint64(v) {
			t.Errorf("asUint(%v) = %d, want %d", v, got, uint64(v))
		}
	}
}
