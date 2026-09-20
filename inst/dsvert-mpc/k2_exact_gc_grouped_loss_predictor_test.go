package main

import (
	"math/big"
	"testing"
)

func TestGroupedPredictorBoundary(t *testing.T) {
	for _, bound := range []int{1, 4} {
		p, err := groupedPredictorCompile(1, bound)
		if err != nil {
			t.Fatal(err)
		}
		limit := new(big.Int).Lsh(big.NewInt(int64(bound)), 100)
		// A q16 tie after rounding f100 -> q64 is deliberately different from
		// direct f100 -> q16 rounding. Preserve the frozen double boundary.
		tie := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 84), new(big.Int).Lsh(big.NewInt(1), 83))
		values := []*big.Int{new(big.Int), limit, new(big.Int).Neg(limit), new(big.Int).Add(limit, big.NewInt(1)), new(big.Int).Sub(tie, big.NewInt(1)), tie, new(big.Int).Add(tie, big.NewInt(1))}
		for _, x := range values {
			mask, err := groupedRandomWord()
			if err != nil {
				t.Fatal(err)
			}
			left := groupedWordInteger(mask)
			right := new(big.Int).Sub(x, left)
			got := primitiveVTestCompute(t, p, []*big.Int{left, big.NewInt(0), big.NewInt(0)}, []*big.Int{right})
			want := primitiveVRoundDivReference(primitiveVRoundDivReference(x, new(big.Int).Lsh(big.NewInt(1), 36)), new(big.Int).Lsh(big.NewInt(1), 48))
			valid := int64(1)
			if new(big.Int).Abs(x).Cmp(limit) > 0 {
				want.SetInt64(0)
				valid = 0
			}
			if got[0].Cmp(want) != 0 || got[1].Int64() != valid {
				t.Fatalf("predictor got=%v want=%s", got, want)
			}
		}
	}
}
