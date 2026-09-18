package main

import (
	"math/big"
	"testing"
)

func TestGroupedGEEExactMomentComposition(t *testing.T) {
	for _, correlation := range []string{"independence", "exchangeable", "ar1"} {
		s := groupedGEESpec{Slots: 2, Predictors: 1, GridBits: 8, Family: "poisson", Correlation: correlation, ScoreClipQ16: 65536, RowLossCap: 10000, BreadCap: 2560, MaxOutcome: 4}
		if correlation != "independence" {
			s.RhoQ16 = 32768
		}
		factors := make([]groupedWord, 6)
		for i, v := range []int64{1, 2, 3, -2, 1, -1} {
			factors[i] = groupedWordFromBig(new(big.Int).Lsh(big.NewInt(v), 64))
		}
		x, y, err := groupedGEEMomentOperands(s, factors)
		if err != nil {
			t.Fatal(err)
		}
		products := make([]groupedWord, len(x))
		for i := range x {
			products[i] = x[i].mul(y[i])
		}
		sums, err := groupedGEEMomentSums(s, products)
		if err != nil {
			t.Fatal(err)
		}
		boundary, err := groupedGEEMomentBoundaryCompile(s)
		if err != nil {
			t.Fatal(err)
		}
		meat, err := groupedGEEMeatFinalCompile(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, valid := range []int64{0, 1, 2} {
			width := len(sums) + 1
			g, e := make([]*big.Int, 2*width), make([]*big.Int, width)
			for i := range g {
				g[i] = new(big.Int)
			}
			for i := range e {
				e[i] = new(big.Int)
			}
			for i, v := range sums {
				mask, err := groupedRandomWord()
				if err != nil {
					t.Fatal(err)
				}
				g[i] = groupedWordInteger(mask)
				e[i] = groupedWordInteger(v.sub(mask))
			}
			g[width-1] = big.NewInt(valid)
			got := primitiveVTestCompute(t, boundary, g, e)
			want := []int64{65536, 65536, 1280, 0, 1280, 1}
			if correlation != "independence" {
				for i := 2; i < 5; i++ {
					want[i] += 2560
				}
			}
			if valid != 1 {
				for i := range want {
					want[i] = 0
				}
			}
			for i, w := range want {
				if got[i].Int64() != w {
					t.Fatalf("%s moment coordinate %d got=%s want=%d", correlation, i, got[i], w)
				}
			}
			clipped := []groupedWord{groupedWordFromBig(got[0]), groupedWordFromBig(got[1])}
			mx, my, err := groupedGEEMeatOperands(s, clipped)
			if err != nil {
				t.Fatal(err)
			}
			mg, me := make([]*big.Int, 8), make([]*big.Int, 4)
			for i := range mg {
				mg[i] = new(big.Int)
			}
			for i := range me {
				me[i] = new(big.Int)
			}
			for i := range mx {
				mg[i] = groupedWordInteger(mx[i].mul(my[i]))
			}
			mg[3] = got[5]
			mout := primitiveVTestCompute(t, meat, mg, me)
			mw := int64(512)
			mv := int64(1)
			if valid != 1 {
				mw, mv = 0, 0
			}
			for i := 0; i < 3; i++ {
				if mout[i].Int64() != mw {
					t.Fatal("meat shift/quantization mismatch")
				}
			}
			if mout[3].Int64() != mv {
				t.Fatal("meat private validity mismatch")
			}
		}
	}
}
func TestGroupedGEEMomentShapeRejection(t *testing.T) {
	s := groupedGEESpec{Slots: 2, Predictors: 1, GridBits: 8, Family: "binomial", Correlation: "independence", ScoreClipQ16: 65536, RowLossCap: 10000, BreadCap: 2560, MaxOutcome: 1}
	if _, _, err := groupedGEEMomentOperands(s, nil); err == nil {
		t.Fatal("missing factors accepted")
	}
	if _, err := groupedGEEMomentSums(s, nil); err == nil {
		t.Fatal("missing products accepted")
	}
	if _, _, err := groupedGEEMeatOperands(s, nil); err == nil {
		t.Fatal("missing clipped scores accepted")
	}
}
