package main

import (
	"github.com/markkurossi/mpc/circuit"
	"math/big"
	"testing"
)

func TestGroupedWideScalarBridge(t *testing.T) {
	for _, name := range []string{"softplus", "exp", "exp_negative", "log", "sigmoid", "sqrt_variance", "inverse_sqrt_variance"} {
		t.Run(name, func(t *testing.T) {
			p, err := groupedWideScalarCompile(name, 4)
			if err != nil {
				t.Fatal(err)
			}
			if p.Circuit.Stats[circuit.AND] > 5000*4 {
				t.Fatalf("wide scalar gate exceeds allowance: %d", p.Circuit.Stats[circuit.AND])
			}
			lo, hi := int64(-262144), int64(262144)
			if profile, ok := groupedProfiles[name]; ok {
				lo, hi = profile.Lower, profile.Upper
			}
			if name == "exp_negative" {
				lo, hi = -1048576, 0
			}
			for _, bad := range []bool{false, true} {
				g, e := make([]*big.Int, 9), make([]*big.Int, 4)
				want := make([]int64, 4)
				for i := range e {
					x := lo + int64(i)*(hi-lo)/3
					want[i], _ = groupedProfileEval(name, x)
					if bad && i == 0 {
						x = lo - 1
					}
					mask, err := groupedRandomWord()
					if err != nil {
						t.Fatal(err)
					}
					g[i] = groupedWordInteger(mask)
					e[i] = new(big.Int).Sub(big.NewInt(x), g[i])
					g[4+i] = big.NewInt(int64(101 + i))
				}
				g[8] = big.NewInt(11)
				got := primitiveVTestCompute(t, p, g, e)
				for i := range want {
					got[i].Add(got[i], g[4+i])
					if bad {
						want[i] = 0
					}
					if got[i].Int64() != want[i] {
						t.Fatalf("%s mismatch", name)
					}
				}
				got[4].Add(got[4], g[8])
				if (got[4].Int64() == 1) == bad {
					t.Fatal("validity mismatch")
				}
			}
			t.Logf("profile=%s AND_per_value=%.2f tables=%d", name, float64(p.Circuit.Stats[circuit.AND])/4, primitiveVTableBytes(p.Circuit))
		})
	}
}
