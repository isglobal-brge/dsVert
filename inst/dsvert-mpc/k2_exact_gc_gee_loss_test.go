package main

import (
	"math/big"
	"testing"
)

func TestGroupedGEECircuitReference(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, corr := range []string{"independence", "exchangeable", "ar1"} {
			t.Run(family+"/"+corr, func(t *testing.T) {
				rho := int64(16384)
				if corr == "independence" {
					rho = 0
				}
				s := groupedGEESpec{Slots: 3, Predictors: 1, GridBits: 16, Family: family, Correlation: corr, RhoQ16: rho, ScoreClipQ16: 65536, RowLossCap: 1 << 24, BreadCap: 1 << 24, MaxOutcome: 1}
				if family == "poisson" {
					s.MaxOutcome = 4
				}
				p, err := groupedGEECompile(s)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("gates=%d table_bytes=%d", p.Circuit.NumGates, primitiveVTableBytes(p.Circuit))
				for _, middle := range []int64{0, 1, 2} {
					rows := make([]groupedGEERow, 3)
					g := make([]*big.Int, p.InputWordsG)
					e := make([]*big.Int, p.InputWordsE)
					for i := range g {
						g[i] = new(big.Int)
					}
					for i := range e {
						e[i] = new(big.Int)
					}
					for i := range rows {
						live := int64(1)
						if i == 1 {
							live = middle
						}
						rows[i] = groupedGEERow{new(big.Int).Mul(big.NewInt(int64(i-1)), primitiveVScale), []*big.Int{new(big.Int).Lsh(big.NewInt(1), 49)}, int64(i % 2), live}
						r := rows[i]
						g[4*i] = r.EtaQ64
						g[4*i+1] = big.NewInt(r.Outcome)
						g[4*i+2] = big.NewInt(live)
						g[4*i+3] = r.FeaturesF50[0]
					}
					want, valid, err := groupedGEEReference(s, rows)
					if err != nil {
						t.Fatal(err)
					}
					got := primitiveVTestCompute(t, p, g, e)
					for k, v := range want {
						if got[k].Int64() != v {
							t.Fatalf("live=%d coordinate=%d got=%s want=%d", middle, k, got[k], v)
						}
					}
					if (got[len(want)].Int64() == 1) != valid {
						t.Fatal("private validity differs")
					}
				}
			})
		}
	}
}
