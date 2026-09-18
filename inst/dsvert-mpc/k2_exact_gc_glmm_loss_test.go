package main

import (
	"math/big"
	"testing"
)

func TestGroupedGLMMCircuitReference(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			s := groupedGLMMSpec{family, 2, 16, 16384}
			p, err := registerGroupedGLMMLoss().Compile(s)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("gates=%d table_bytes=%d", p.Circuit.NumGates, primitiveVTableBytes(p.Circuit))
			for _, x := range []int64{-1, 0, 1} {
				for _, live := range []int64{0, 1, 2} {
					eta := []*big.Int{new(big.Int).Mul(big.NewInt(x), primitiveVScale), new(big.Int)}
					flags := []int64{live, 1}
					ys := []int64{1, 0}
					want, valid, err := groupedGLMMReference(s, eta, flags, ys)
					if err != nil {
						t.Fatal(err)
					}
					g := []*big.Int{eta[0], big.NewInt(live), big.NewInt(1), eta[1], big.NewInt(1), new(big.Int), big.NewInt(27), big.NewInt(41)}
					e := make([]*big.Int, 6)
					for i := range e {
						e[i] = new(big.Int)
					}
					got := primitiveVTestCompute(t, p, g, e)
					got[0].Add(got[0], g[6])
					got[1].Add(got[1], g[7])
					if got[0].Int64() != want || (got[1].Int64() == 1) != valid {
						t.Fatalf("x=%d live=%d got=%v want=%d valid=%v", x, live, got, want, valid)
					}
				}
			}
		})
	}
}
