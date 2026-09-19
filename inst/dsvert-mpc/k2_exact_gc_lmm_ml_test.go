package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

func groupedLMMMLTestSpec() groupedLMMStagedSpec {
	s := groupedLMMStagedTestSpec()
	s.Objective = "ml"
	s.VarianceGrid = []groupedLMMVariance{
		{new(big.Int).Rsh(new(big.Int).Set(primitiveVScale), 2), new(big.Int)},
		{new(big.Int).Set(primitiveVScale), new(big.Int).Rsh(new(big.Int).Set(primitiveVScale), 2)},
	}
	s.Numeric.Sigma2Q64, s.Numeric.Tau2Q64 = s.VarianceGrid[0].Sigma2Q64, s.VarianceGrid[0].Tau2Q64
	s.Caps = []int64{2048, 2048, 2048, 2048}
	return s
}

// Independent 256-bit/180-term logarithms; the production certificate uses
// exact rational 32-term enclosures. Test fixtures never enter the protocol.
func groupedLMMMLHighLog(s groupedLMMSpec, n int) *big.Float {
	if n == 0 {
		return crossGridHighV1().SetInt64(0)
	}
	base := primitiveVHighLog(new(big.Int).Lsh(new(big.Int).Set(s.Sigma2Q64), 2))
	value := new(big.Int).Add(s.Sigma2Q64, new(big.Int).Mul(big.NewInt(int64(n)), s.Tau2Q64))
	last := primitiveVHighLog(new(big.Int).Lsh(value, 2))
	return last.Add(last, crossGridHighV1().Mul(base, crossGridHighV1().SetInt64(int64(n-1))))
}

func groupedLMMMLOracle(s groupedLMMSpec, rows [][]*big.Int, beta []*big.Int, cap int64) *big.Int {
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	sum, squares, n := new(big.Int), new(big.Int), 0
	for _, row := range rows {
		if row[0].Sign() == 0 {
			continue
		}
		n++
		r := new(big.Int).Mul(row[len(row)-1], f)
		for j, b := range beta {
			r.Sub(r, new(big.Int).Mul(row[j], b))
		}
		sum.Add(sum, r)
		squares.Add(squares, new(big.Int).Mul(r, r))
	}
	inv, lambda := groupedLMMTable(s)
	loss := new(big.Int).Sub(new(big.Int).Mul(squares, inv), new(big.Int).Mul(new(big.Int).Mul(sum, sum), lambda[n]))
	scaledLog := crossGridHighV1().Mul(groupedLMMMLHighLog(s, n), crossGridHighV1().SetInt(primitiveVScale))
	logInteger, accuracy := scaledLog.Int(nil)
	if accuracy == big.Below {
		logInteger.Add(logInteger, big.NewInt(1))
	}
	loss.Add(loss, new(big.Int).Lsh(logInteger, 200))
	loss = primitiveVRoundDivReference(loss, new(big.Int).Lsh(big.NewInt(1), uint(264-s.GridBits)))
	if loss.Sign() < 0 {
		loss.SetInt64(0)
	}
	if loss.Cmp(big.NewInt(cap)) > 0 {
		loss.SetInt64(cap)
	}
	return loss
}

func TestGroupedLMMMLLogCertificate(t *testing.T) {
	raw, err := os.ReadFile("../certificates/grouped_lmm_ml_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("invalid ML certificate manifest")
	}
	canonical, err := json.Marshal(manifest)
	digest := sha256.Sum256(canonical)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) || hex.EncodeToString(digest[:]) != groupedLMMMLCertificateSHA256 || manifest["profile"] != groupedLMMMLProfile {
		t.Fatal("ML certificate/profile digest drift")
	}
	for _, variances := range [][2]int64{{16384, 0}, {16384, 1}, {16385, 65535}, {65536, 65536}, {1048576, 1048576}} {
		s := groupedLMMTestSpec()
		s.Slots = 32
		s.Sigma2Q64 = new(big.Int).Lsh(big.NewInt(variances[0]), 48)
		s.Tau2Q64 = new(big.Int).Lsh(big.NewInt(variances[1]), 48)
		table, err := groupedLMMMLLogTable(s)
		if err != nil {
			t.Fatal(err)
		}
		if table[0].Sign() != 0 {
			t.Fatal("empty cluster acquired a log penalty")
		}
		for n, entry := range table {
			actual := crossGridHighV1().Quo(crossGridHighV1().SetInt(entry), crossGridHighV1().SetInt(primitiveVScale))
			error := crossGridHighV1().Sub(actual, groupedLMMMLHighLog(s, n))
			if error.Sign() < 0 || error.Cmp(crossGridHighV1().SetRat(new(big.Rat).SetFrac(big.NewInt(1), exactGCModulus(63)))) >= 0 {
				t.Fatalf("log enclosure violated at sigma/tau=%v n=%d", variances, n)
			}
		}
	}
	// The fixed tail proof covers the entire range, not just sampled tables.
	lower, upper := groupedLMMMLAtanhBounds(big.NewRat(1, 3))
	width := new(big.Rat).Mul(new(big.Rat).Sub(upper, lower), big.NewRat(32*12, 1))
	if width.Cmp(new(big.Rat).SetFrac(big.NewInt(1), exactGCModulus(80))) >= 0 || upper.Cmp(big.NewRat(1, 1)) >= 0 {
		t.Fatal("uniform rational tail/ln2 certificate failed")
	}
}

func TestGroupedLMMMLGraphContract(t *testing.T) {
	s := groupedLMMMLTestSpec()
	g, err := groupedLMMBuildStagedGraph(s, 0)
	if err != nil {
		t.Fatal(err)
	}
	products, moments := 0, 0
	for _, stage := range g.Plans {
		if strings.HasPrefix(stage.ID, "lmm.products.") {
			products++
		}
		if stage.ID == "lmm.moments" {
			moments++
		}
	}
	if products != (s.Moments.products()+1023)/1024 || moments != 1 {
		t.Fatal("ML recomputed candidate-dependent source products")
	}
	last := g.Plans[len(g.Plans)-1]
	if last.ID != "lmm.terminal" || len(last.CoordOrder) != len(s.Caps) || last.CoordOrder[2] != "variance:1:candidate:0" {
		t.Fatal("ML candidate ordering differs")
	}
	for _, change := range []string{"reml", "empty-grid", "duplicate-grid", "reversed-grid", "first-variance", "non-q16", "caps"} {
		t.Run(change, func(t *testing.T) {
			raw, _ := json.Marshal(s)
			var changed groupedLMMStagedSpec
			json.Unmarshal(raw, &changed)
			switch change {
			case "reml":
				changed.Objective = "reml"
			case "empty-grid":
				changed.VarianceGrid = nil
			case "duplicate-grid":
				changed.VarianceGrid[1] = changed.VarianceGrid[0]
			case "reversed-grid":
				changed.VarianceGrid[0], changed.VarianceGrid[1] = changed.VarianceGrid[1], changed.VarianceGrid[0]
			case "first-variance":
				changed.Numeric.Tau2Q64.SetInt64(1)
			case "non-q16":
				changed.VarianceGrid[1].Tau2Q64.SetInt64(1)
			case "caps":
				changed.Caps = changed.Caps[:len(changed.Caps)-1]
			}
			if changed.validate() == nil {
				t.Fatal("invalid ML policy admitted")
			}
		})
	}
	legacy := groupedLMMStagedTestSpec()
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("Objective")) || bytes.Contains(raw, []byte("VarianceGrid")) {
		t.Fatal("legacy profile identity changed")
	}
}

func TestGroupedLMMMLStagedTwoAuthority(t *testing.T) {
	s := groupedLMMMLTestSpec()
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	half, quarter := new(big.Int).Rsh(new(big.Int).Set(f), 1), new(big.Int).Rsh(new(big.Int).Set(f), 2)
	rows := [][]*big.Int{{f, new(big.Int), half}, {f, new(big.Int), half},
		{new(big.Int), new(big.Int), new(big.Int)}, {f, half, quarter}}
	want := make([]*big.Int, len(s.Caps))
	for v, variance := range s.VarianceGrid {
		numeric := s.Numeric
		numeric.Sigma2Q64, numeric.Tau2Q64 = variance.Sigma2Q64, variance.Tau2Q64
		for j, beta := range s.Beta {
			index := v*len(s.Beta) + j
			want[index] = new(big.Int)
			for c := 0; c < s.Moments.Clusters; c++ {
				want[index].Add(want[index], groupedLMMMLOracle(numeric, rows[c*s.Moments.Slots:(c+1)*s.Moments.Slots], beta, s.Caps[index]))
			}
		}
	}
	if want[0].Cmp(want[len(s.Beta)]) >= 0 {
		t.Fatal("fixture does not require determinant penalty to prefer smaller variance")
	}
	var prior []byte
	for _, scenario := range []string{"fresh", "new-randomness", "bilateral-midstage-recovery", "unilateral-commit-recovery", "source-invalid"} {
		t.Run(scenario, func(t *testing.T) {
			invalid := scenario == "source-invalid"
			got, validity := groupedLMMStagedRunTest(t, s, rows, invalid, scenario)
			for j, expected := range want {
				value := crossGridStageTestInteger(got[16*j : 16*(j+1)])
				if invalid {
					if validity[j] != 0 || value.Sign() != 0 {
						t.Fatal("invalid ML source escaped terminal")
					}
				} else if validity[j] != 1 || value.Cmp(expected) != 0 {
					t.Fatalf("ML coordinate %d got=%s want=%s validity=%d", j, value, expected, validity[j])
				}
			}
			if !invalid {
				if prior != nil && !bytes.Equal(prior, got) {
					t.Fatal("ML recovery changed exact artifact")
				}
				prior = got
			}
		})
	}
}
