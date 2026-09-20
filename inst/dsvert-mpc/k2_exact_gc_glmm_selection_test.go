package main

import (
	"math/big"
	"testing"
)

// Check the factorial-free scores independently, including y=3, missing rows,
// both variances and wrapped Ring192 shares. Common translations cancel BEFORE
// the max/exp/log boundary; no selected loss value is treated as a likelihood.
func TestGroupedGLMMSelectionTranslation(t *testing.T) {
	for _, variance := range []int64{0, 16384} {
		s := groupedGLMMSpec{Family: "poisson", Rows: 5, OutputBits: 16, VarianceQ16: variance}
		for _, mask := range []int{0, 1, 21, 31} {
			for _, eta := range []int64{-65536, 0, 65536} {
				values := make([][]groupedWord, 4)
				sizes := []int{25, 5, 5, 5}
				for k, n := range sizes {
					values[k] = make([]groupedWord, n)
				}
				legacy := groupedGLMMLogWeights
				shift := int64(0)
				for y := 0; y < 5; y++ {
					if mask&(1<<y) == 0 {
						continue
					}
					values[1][y] = groupedWordFromBig(big.NewInt(int64(y) * eta))
					values[2][y] = groupedWordFromBig(big.NewInt(int64(y)))
					values[3][y] = groupedWordFromBig(big.NewInt(1))
					shift += 2*65536 - groupedGLMMLogFactorials[y]
					for q := 0; q < 5; q++ {
						x := eta
						if variance != 0 {
							x += groupedGLMMNodes[q]
						}
						profile, err := groupedProfileEval("exp", x)
						if err != nil {
							t.Fatal(err)
						}
						values[0][5*y+q] = groupedWordFromBig(big.NewInt(profile))
						legacy[q] -= profile - int64(y)*x + groupedGLMMLogFactorials[y]
					}
				}
				a, b := make([][]groupedWord, 4), make([][]groupedWord, 4)
				for k := range values {
					a[k] = make([]groupedWord, len(values[k]))
					b[k] = make([]groupedWord, len(values[k]))
					for i, v := range values[k] {
						var err error
						a[k][i], err = groupedRandomWord()
						if err != nil {
							t.Fatal(err)
						}
						b[k][i] = v.sub(a[k][i])
					}
				}
				ga, err := groupedGLMMScoreShares(s, exactGCRoleGarbler, a[0], a[1], a[2], a[3])
				if err != nil {
					t.Fatal(err)
				}
				eb, err := groupedGLMMScoreShares(s, exactGCRoleEvaluator, b[0], b[1], b[2], b[3])
				if err != nil {
					t.Fatal(err)
				}
				for q := 0; q < 5; q++ {
					want := groupedWordFromBig(big.NewInt(legacy[q] - shift))
					if ga[q].add(eb[q]) != want {
						t.Fatalf("variance=%d mask=%d eta=%d q=%d translation mismatch", variance, mask, eta, q)
					}
				}
			}
		}
	}
}

func TestGroupedGLMMSelectionPositiveRowRange(t *testing.T) {
	// Dense independent check of the signed profile domain; analytic margins are
	// in NUMERIC_CERTIFICATE_GLMM_SELECTION.md, not inferred from this grid.
	for eta := int64(-65536); eta <= 65536; eta += 1024 {
		for _, node := range groupedGLMMNodes {
			x := eta + node
			mu, err := groupedProfileEval("exp", x)
			if err != nil {
				t.Fatal(err)
			}
			for y := int64(0); y <= 4; y++ {
				loss := mu - y*x + 2*65536
				if loss <= 0 || loss >= 32*65536 {
					t.Fatalf("selection range violated eta=%d y=%d loss=%d", x, y, loss)
				}
			}
		}
	}
}
