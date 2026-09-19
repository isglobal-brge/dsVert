package main

import (
	"math"
	"math/big"
	"testing"
)

// Exercise full-width wrapped input shares AND independent output masks.
func groupedGEETestBoundary(t *testing.T, p *primitiveVProgram, inputs []*big.Int, out int) []*big.Int {
	t.Helper()
	g, e := make([]*big.Int, len(inputs)+out), make([]*big.Int, len(inputs))
	masks := make([]groupedWord, out)
	for i, x := range inputs {
		m, err := groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		g[i] = groupedWordInteger(m)
		e[i] = groupedWordInteger(groupedWordFromBig(x).sub(m))
	}
	for i := 0; i < out; i++ {
		m, err := groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		masks[i] = m
		g[len(inputs)+i] = groupedWordInteger(m)
	}
	got := primitiveVTestCompute(t, p, g, e)
	for i := range got {
		got[i] = groupedWordInteger(groupedWordFromBig(got[i]).add(masks[i]))
		if got[i].Bit(191) == 1 {
			got[i].Sub(got[i], new(big.Int).Lsh(big.NewInt(1), 192))
		}
	}
	return got
}

func TestGroupedGEEWhiteningPrivatePatterns(t *testing.T) {
	for _, cor := range []string{"independence", "exchangeable", "ar1"} {
		for _, rho := range []int64{0, 16384, 32768} {
			if cor == "independence" && rho != 0 {
				continue
			}
			s := groupedGEESpec{Slots: 4, Predictors: 1, GridBits: 16, Family: "binomial", Correlation: cor, RhoQ16: rho, ScoreClipQ16: 65536, RowLossCap: 10000, BreadCap: 10000, MaxOutcome: 1}
			p, err := groupedGEEWhiteningCompile(s)
			if err != nil {
				t.Fatal(err)
			}
			for mask := 0; mask < 16; mask++ {
				in := make([]*big.Int, 5)
				live := []int{}
				for i := 0; i < 4; i++ {
					in[i] = big.NewInt(int64((mask >> i) & 1))
					if in[i].Sign() != 0 {
						live = append(live, i)
					}
				}
				in[4] = big.NewInt(1)
				got := groupedGEETestBoundary(t, p, in, 17)
				if got[16].Int64() != 1 {
					t.Fatal("validity")
				}
				// Independent real covariance inverse via Gauss-Jordan. In particular AR1
				// uses original distances, not positions in the compressed live array.
				m := len(live)
				a := make([][]float64, m)
				for i := 0; i < m; i++ {
					a[i] = make([]float64, 2*m)
					a[i][m+i] = 1
					for j := 0; j < m; j++ {
						if i == j {
							a[i][j] = 1
						} else if cor == "exchangeable" {
							a[i][j] = float64(rho) / 65536
						} else if cor == "ar1" {
							a[i][j] = math.Pow(float64(rho)/65536, math.Abs(float64(live[i]-live[j])))
						}
					}
				}
				for i := 0; i < m; i++ {
					pivot := a[i][i]
					for k := 0; k < 2*m; k++ {
						a[i][k] /= pivot
					}
					for j := 0; j < m; j++ {
						if j != i {
							v := a[j][i]
							for k := 0; k < 2*m; k++ {
								a[j][k] -= v * a[i][k]
							}
						}
					}
				}
				for i := 0; i < 4; i++ {
					for j := 0; j < 4; j++ {
						total := 0.0
						for r := 0; r < 4; r++ {
							x, _ := new(big.Rat).SetFrac(got[4*r+i], new(big.Int).Lsh(big.NewInt(1), 64)).Float64()
							y, _ := new(big.Rat).SetFrac(got[4*r+j], new(big.Int).Lsh(big.NewInt(1), 64)).Float64()
							total += x * y
						}
						want := 0.0
						for ii, v := range live {
							for jj, w := range live {
								if v == i && w == j {
									want = a[ii][m+jj]
								}
							}
						}
						if math.Abs(total-want) > 2e-14 {
							t.Fatalf("%s rho=%d mask=%d WtW[%d,%d]=%.17g inverse=%.17g", cor, rho, mask, i, j, total, want)
						}
					}
				}
			}
			for _, bad := range []int64{-1, 2, 1 << 40} {
				in := []*big.Int{big.NewInt(bad), big.NewInt(1), big.NewInt(0), big.NewInt(1), big.NewInt(1)}
				got := groupedGEETestBoundary(t, p, in, 17)
				for _, v := range got {
					if v.Sign() != 0 {
						t.Fatal("invalid live accepted")
					}
				}
			}
		}
	}
}

func TestGroupedGEEFactorInputs(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		s := groupedGEESpec{Slots: 2, Predictors: 1, GridBits: 16, Family: family, Correlation: "ar1", RhoQ16: 32768, ScoreClipQ16: 65536, RowLossCap: 10000, BreadCap: 10000, MaxOutcome: 1}
		if family == "poisson" {
			s.MaxOutcome = 4
		}
		p, err := groupedGEEInputCompile(s)
		if err != nil {
			t.Fatal(err)
		}
		in := []*big.Int{new(big.Int).Lsh(big.NewInt(-3), 100), new(big.Int).Lsh(big.NewInt(1), 49), big.NewInt(s.MaxOutcome), big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 180), big.NewInt(-1), big.NewInt(999), big.NewInt(0)}
		got := groupedGEETestBoundary(t, p, in, 17)
		expected := []int64{-196608, -98304, 98304, 65536, 32768, s.MaxOutcome * 65536, 1, 0, 0, 0, 0, 65536, 0, 0, 0, 0, 1}
		if family == "poisson" {
			expected[7] = 208277
		}
		for i, v := range got {
			if v.Int64() != expected[i] {
				t.Fatalf("%s input[%d]=%s want=%d", family, i, v, expected[i])
			}
		}
		for _, idx := range []int{0, 1, 2, 3} {
			invalid := append([]*big.Int(nil), in...)
			invalid[idx] = new(big.Int).Lsh(big.NewInt(1), 180)
			got = groupedGEETestBoundary(t, p, invalid, 17)
			for _, v := range got {
				if v.Sign() != 0 {
					t.Fatalf("invalid live input %d accepted", idx)
				}
			}
		}
		// Compile each stage, including the complete-width round/clip boundaries.
		if _, err = groupedGEEBaseBoundaryCompile(s); err != nil {
			t.Fatal(err)
		}
		if _, err = groupedGEEFactorBoundaryCompile(s); err != nil {
			t.Fatal(err)
		}
		if _, err = groupedGEELikelihoodCompile(s, 1000000); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGroupedGEEWhiteningCertificateAndLimits(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, cor := range []string{"independence", "exchangeable", "ar1"} {
			s := groupedGEESpec{Slots: 8, Predictors: 3, GridBits: 18, Family: family, Correlation: cor, ScoreClipQ16: 262144, RowLossCap: 1 << 30, BreadCap: 1 << 30, MaxOutcome: 1}
			if family == "poisson" {
				s.MaxOutcome = 4
			}
			if cor != "independence" {
				s.RhoQ16 = 32768
			}
			cert, err := groupedGEEWhiteningCertificate(s)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range []*big.Rat{cert.Likelihood, cert.Bread, cert.Meat, cert.FactorU, cert.FactorZ} {
				if v.Sign() <= 0 {
					t.Fatal("nonpositive error bound")
				}
			}
			for _, compile := range []func(groupedGEESpec) (*primitiveVProgram, error){groupedGEEInputCompile, groupedGEEWhiteningCompile, groupedGEEBaseBoundaryCompile, groupedGEEFactorBoundaryCompile} {
				p, err := compile(s)
				if err != nil {
					t.Fatal(err)
				}
				if p.Circuit.NumGates > 32000000 {
					t.Fatal("runner cap")
				}
			}
			// Coefficient enclosure checks use rational square inequalities, not floats.
			for _, den := range []int64{1, 2, 3, 4, 5, 7, 9} {
				value := big.NewRat(4, den)
				root := groupedGEESqrtQ64(value)
				target := new(big.Int).Lsh(new(big.Int).Set(value.Num()), 128)
				square := new(big.Int).Mul(new(big.Int).Mul(root, root), value.Denom())
				next := new(big.Int).Add(root, big.NewInt(1))
				upper := new(big.Int).Mul(new(big.Int).Mul(next, next), value.Denom())
				if square.Cmp(target) > 0 || upper.Cmp(target) <= 0 {
					t.Fatal("public square-root certificate")
				}
			}
			s.Slots = 9
			if _, err := groupedGEEWhiteningCertificate(s); err == nil {
				t.Fatal("uncertified shape accepted")
			}
		}
	}
	// Full-width values beyond the certified factor range and invalid inherited
	// flags are rejected before any terminal coordinate can become releasable.
	s := groupedGEESpec{Slots: 1, Predictors: 1, GridBits: 8, Family: "binomial", Correlation: "independence", ScoreClipQ16: 65536, RowLossCap: 10000, BreadCap: 10000, MaxOutcome: 1}
	p, err := groupedGEEFactorBoundaryCompile(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range [][]*big.Int{
		{new(big.Int).Lsh(big.NewInt(1), 180), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
		{new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 191)), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
		{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(2)},
		{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
	} {
		got := groupedGEETestBoundary(t, p, in, 4)
		for _, v := range got {
			if v.Sign() != 0 {
				t.Fatal("invalid factor accepted")
			}
		}
	}
}

func TestGroupedGEEFactorialCertificate(t *testing.T) {
	// Exact rational log(n)=2*sum z^(2k+1)/(2k+1), z=(n-1)/(n+1).
	// The omitted positive tail is <=2*z^(2N+1)/((2N+1)*(1-z^2)).
	// Factorials use log2, log6=log2+log3, log24=3log2+log3, so z<=1/2.
	enclosure := func(n int64) (*big.Rat, *big.Rat) {
		z := big.NewRat(n-1, n+1)
		square := new(big.Rat).Mul(z, z)
		power := new(big.Rat).Set(z)
		sum := new(big.Rat)
		const N = 64
		for k := 0; k < N; k++ {
			sum.Add(sum, new(big.Rat).Quo(power, big.NewRat(int64(2*k+1), 1)))
			power.Mul(power, square)
		}
		lower := new(big.Rat).Mul(big.NewRat(2, 1), sum)
		tail := new(big.Rat).Quo(new(big.Rat).Mul(big.NewRat(2, 1), power), new(big.Rat).Mul(big.NewRat(2*N+1, 1), new(big.Rat).Sub(big.NewRat(1, 1), square)))
		return lower, new(big.Rat).Add(lower, tail)
	}
	lo2, hi2 := enclosure(2)
	lo3, hi3 := enclosure(3)
	for y, weights := range [][2]int64{{0, 0}, {0, 0}, {1, 0}, {1, 1}, {3, 1}} {
		lower := new(big.Rat).Add(new(big.Rat).Mul(big.NewRat(weights[0], 1), lo2), new(big.Rat).Mul(big.NewRat(weights[1], 1), lo3))
		upper := new(big.Rat).Add(new(big.Rat).Mul(big.NewRat(weights[0], 1), hi2), new(big.Rat).Mul(big.NewRat(weights[1], 1), hi3))
		lowCell := big.NewRat(2*groupedGEEWhiteningLogFactorial[y]-1, 131072)
		highCell := big.NewRat(2*groupedGEEWhiteningLogFactorial[y]+1, 131072)
		if lower.Cmp(lowCell) <= 0 || upper.Cmp(highCell) >= 0 {
			t.Fatalf("log(%d!) is outside the claimed nearest-q16 cell", y)
		}
	}
}
