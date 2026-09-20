package main

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
)

func TestGroupedGLMMPoissonFullWidthGuards(t *testing.T) {
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	for maximum := 1; maximum <= 4; maximum++ {
		program, err := groupedGLMMOutcomeGuardCompile(1, true, maximum)
		if err != nil {
			t.Fatal(err)
		}
		for _, live := range []int64{0, 1, 2} {
			for _, y := range []int64{-1, 0, 1, 2, 3, 4, 5} {
				g := []*big.Int{new(big.Int).Mul(f, big.NewInt(live)), new(big.Int).Mod(new(big.Int).Mul(f, big.NewInt(y)), exactGCModulus(192)), new(big.Int), new(big.Int), new(big.Int)}
				got := primitiveVTestCompute(t, program, g, []*big.Int{new(big.Int), new(big.Int)})
				valid := live <= 1 && y >= 0 && y <= int64(maximum) && (live == 1 || y == 0)
				if (got[2].Int64() == 1) != valid || (valid && (got[0].Int64() != live || got[1].Int64() != y)) {
					t.Fatalf("max=%d live=%d y=%d: %v", maximum, live, y, got)
				}
			}
		}
		for _, alias := range []uint{0, 32, 100, 128} {
			y := new(big.Int).Add(new(big.Int).Mul(f, big.NewInt(2)), new(big.Int).Lsh(big.NewInt(1), alias))
			g := []*big.Int{new(big.Int).Set(f), y, new(big.Int), new(big.Int), new(big.Int)}
			got := primitiveVTestCompute(t, program, g, []*big.Int{new(big.Int), new(big.Int)})
			if got[2].Sign() != 0 {
				t.Fatal("accepted nonlattice or high-word alias")
			}
		}
	}
}

func TestGroupedGLMMPoissonContractBinding(t *testing.T) {
	legacy := groupedGLMMStagedTestSpec()
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("Family")) || bytes.Contains(raw, []byte("MaxOutcome")) {
		t.Fatal("legacy spec serialization changed")
	}
	old := struct {
		Clusters, Slots, Predictors, GridBits int
		Beta                                  [][]*big.Int
		Caps                                  []int64
		VarianceGrid                          []int64
		SourceDigest, ProfileDigest           [32]byte
		RoutedStage                           string
	}{legacy.Clusters, legacy.Slots, legacy.Predictors, legacy.GridBits, legacy.Beta, legacy.Caps, legacy.VarianceGrid, legacy.SourceDigest, legacy.ProfileDigest, legacy.RoutedStage}
	before, _ := json.Marshal(old)
	if !bytes.Equal(before, raw) {
		t.Fatal("legacy bytes differ")
	}
	poisson := legacy
	poisson.Family, poisson.MaxOutcome = "poisson", 4
	a, err := groupedGLMMBuildStagedGraph(legacy, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := groupedGLMMBuildStagedGraph(poisson, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.Plans[0].ProfileDigest == b.Plans[0].ProfileDigest {
		t.Fatal("family not bound")
	}
	found := false
	for _, p := range b.Plans {
		if p.Kind == "glmm.gh5-exp" {
			found = true
		}
	}
	if !found {
		t.Fatal("Poisson did not select range exp")
	}
	for _, bad := range []struct {
		family  string
		maximum int
	}{{"", 4}, {"binomial", 4}, {"poisson", 0}, {"poisson", 5}, {"gee_poisson", 4}} {
		s := legacy
		s.Family, s.MaxOutcome = bad.family, bad.maximum
		if s.validate() == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	spec, sources, side, _ := groupedGLMMSourceFixture(t)
	spec.GLMM.Family, spec.GLMM.MaxOutcome = "poisson", 4
	spec.Route.OutcomeBound = new(big.Int).Lsh(big.NewInt(4), 50)
	if _, err := groupedGLMMSourcePlans(spec); err != nil {
		t.Fatal(err)
	}
	if _, err := groupedGLMMBuildSourceGraph(spec, 0, sources[0], side, crossGridStageTestKey(0)); err == nil {
		t.Fatal("binomial source replaced Poisson source")
	}
	spec.Route.OutcomeBound = new(big.Int).Lsh(big.NewInt(3), 50)
	if _, err := groupedGLMMSourcePlans(spec); err == nil {
		t.Fatal("wrong outcome routing bound accepted")
	}
}

func TestGroupedGLMMPoissonStagedTwoAuthority(t *testing.T) {
	for _, scenario := range []string{"fresh", "g18", "signed-cap", "bilateral-midstage-recovery", "unilateral-commit-recovery"} {
		t.Run(scenario, func(t *testing.T) {
			s := groupedGLMMStagedTestSpec()
			s.Family, s.MaxOutcome = "poisson", 4
			s.Clusters, s.Slots = 2, 3
			s.Caps = []int64{20000, 20000, 20000, 20000}
			if scenario == "g18" {
				s.GridBits = 18
				s.Caps = []int64{20000 << 10, 20000 << 10, 20000 << 10, 20000 << 10}
			}
			if scenario == "signed-cap" {
				s.Caps = []int64{100, 200, 300, 400}
			}
			rows := make([][]*big.Int, 6)
			for i := range rows {
				rows[i] = []*big.Int{new(big.Int).Lsh(big.NewInt(1), 50), new(big.Int).Lsh(big.NewInt(int64(i%2)), 50), new(big.Int).Lsh(big.NewInt(int64(i%5)), 50)}
			}
			rows[5] = []*big.Int{new(big.Int), new(big.Int), new(big.Int)}
			got, valid := groupedGLMMStagedRunTest(t, s, rows, false, scenario)
			for j := range s.Caps {
				want := groupedGLMMStagedOracle(s, rows, j)
				value := crossGridStageTestInteger(got[16*j : 16*(j+1)])
				if valid[j] != 1 || value.Cmp(want) != 0 {
					t.Fatalf("candidate %d got=%s valid=%d want=%s", j, value, valid[j], want)
				}
			}
		})
	}
}
