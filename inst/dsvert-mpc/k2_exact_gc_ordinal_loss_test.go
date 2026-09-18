package main

import (
	"math"
	"math/big"
	"testing"
)

func TestExactGCOrdinalLossCircuit(t *testing.T) {
	threshold := func(v int64) string { return new(big.Int).Lsh(big.NewInt(v), 46).String() }
	s := exactGCFamilyLossSpec{Classes: 3, GridBits: 18, Cap: 6000000, Thresholds: []string{threshold(-1), "0"}}
	src, err := exactGCOrdinalLossSource(s)
	if err != nil {
		t.Fatal(err)
	}
	c := familyLossCompile(t, src)
	slack := new(big.Int).Lsh(big.NewInt(9), 50)
	for _, dot := range []*big.Int{familyDot(-8), big.NewInt(0), familyDot(8), new(big.Int).Add(familyDot(8), slack), new(big.Int).Neg(new(big.Int).Add(familyDot(8), slack))} {
		for y := 0; y < 3; y++ {
			for _, v := range []int64{0, 1} {
				got, guard := familyLossCompute(t, c, []*big.Int{dot, big.NewInt(int64(y)), big.NewInt(v)})
				want := familyLossReference("ordinal", s, []*big.Int{dot}, y, v == 1)
				if !guard || got.Cmp(want) != 0 {
					t.Fatalf("dot=%s y=%d got=%s guard=%v want=%s", dot, y, got, guard, want)
				}
			}
		}
	}
	for _, values := range [][]*big.Int{{new(big.Int).Add(new(big.Int).Add(familyDot(8), slack), big.NewInt(1)), big.NewInt(0), big.NewInt(1)}, {big.NewInt(0), big.NewInt(3), big.NewInt(1)}, {big.NewInt(0), big.NewInt(0), big.NewInt(2)}} {
		got, guard := familyLossCompute(t, c, values)
		if guard || got.Sign() != 0 {
			t.Fatal("invalid ordinal input accepted")
		}
	}
}
func TestExactGCOrdinalThresholdValidation(t *testing.T) {
	base := exactGCFamilyLossSpec{Classes: 3, GridBits: 18, Cap: 6000000}
	for _, cs := range [][]string{nil, {"0"}, {"0", "0"}, {"1", "0"}, {"-0", "1"}, {"0", "01"}, {"0", "1"}, {"0", new(big.Int).Lsh(big.NewInt(9), 50).String()}} {
		s := base
		s.Thresholds = cs
		if _, err := exactGCOrdinalLossSource(s); err == nil {
			t.Fatal("invalid thresholds accepted")
		}
	}
	s := base
	s.Thresholds = []string{"0", new(big.Int).Lsh(big.NewInt(1), 46).String()}
	if _, err := exactGCOrdinalLossSource(s); err != nil {
		t.Fatal(err)
	}
}
func TestExactGCOrdinalReferenceAccuracy(t *testing.T) {
	// Include minimum gap at extreme signed threshold/predictor endpoints.
	for _, ts := range [][2]float64{{-8, -8 + 1.0/16}, {-1, 1}, {8 - 1.0/16, 8}, {-8, 8}} {
		s := exactGCFamilyLossSpec{Classes: 3, GridBits: 18, Cap: 6000000}
		for _, c := range ts {
			s.Thresholds = append(s.Thresholds, big.NewInt(int64(c*(1<<50))).String())
		}
		for _, eta := range []int64{-8, 0, 8} {
			for y := 0; y < 3; y++ {
				got := float64(familyLossReference("ordinal", s, []*big.Int{familyDot(eta)}, y, true).Int64()) / (1 << 18)
				hi, lo := ts[1]-float64(eta), ts[0]-float64(eta)
				var want float64
				if y == 0 {
					want = math.Log1p(math.Exp(-lo))
				} else if y == 2 {
					want = math.Log1p(math.Exp(hi))
				} else {
					want = math.Log1p(math.Exp(hi)) + math.Log1p(math.Exp(lo)) - hi - math.Log(-math.Expm1(lo-hi))
				}
				if math.Abs(got-want) > 0.00012 {
					t.Fatalf("ordinal error %g", got-want)
				}
			}
		}
	}
}
