package main

import (
	"math/big"
	"testing"
)

func TestGroupedGLMMShareComposition(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, variance := range []int64{0, 16384} {
			s := groupedGLMMSpec{Family: family, Rows: 3, OutputBits: 16, VarianceQ16: variance}
			cap, err := groupedGLMMBounds(s)
			if err != nil {
				t.Fatal(err)
			}
			center, err := groupedGLMMCenterCompile(s)
			if err != nil {
				t.Fatal(err)
			}
			final, err := groupedGLMMFinalCompile(s, cap.UnitCap)
			if err != nil {
				t.Fatal(err)
			}
			for _, live := range [][]int64{{1, 1, 1}, {1, 0, 1}, {0, 0, 0}} {
				eta := []*big.Int{new(big.Int).Neg(new(big.Int).Set(primitiveVScale)), new(big.Int), new(big.Int).Set(primitiveVScale)}
				outcome := []int64{0, 1, 1}
				if family == "poisson" {
					outcome[2] = 4
				}
				values := make([][]groupedWord, 4)
				for k := range values {
					size := 3
					if k == 0 {
						size = 15
					}
					values[k] = make([]groupedWord, size)
				}
				count := int64(0)
				for i := 0; i < 3; i++ {
					if live[i] == 0 {
						continue
					}
					count++
					e := primitiveVRoundDivReference(eta[i], new(big.Int).Lsh(big.NewInt(1), 48)).Int64()
					values[1][i] = groupedWordFromBig(big.NewInt(outcome[i] * e))
					values[2][i] = groupedWordFromBig(big.NewInt(outcome[i]))
					values[3][i] = groupedWordFromBig(big.NewInt(groupedGLMMLogFactorials[outcome[i]]))
					for q := 0; q < 5; q++ {
						argument := e
						if variance != 0 {
							argument += groupedGLMMNodes[q]
						}
						name := "softplus"
						if family == "poisson" {
							name = "exp"
						}
						v, err := groupedProfileEval(name, argument)
						if err != nil {
							t.Fatal(err)
						}
						values[0][5*i+q] = groupedWordFromBig(big.NewInt(v))
					}
				}
				a, b := make([][]groupedWord, 4), make([][]groupedWord, 4)
				for k := range values {
					a[k] = make([]groupedWord, len(values[k]))
					b[k] = make([]groupedWord, len(values[k]))
					for i, v := range values[k] {
						a[k][i], err = groupedRandomWord()
						if err != nil {
							t.Fatal(err)
						}
						b[k][i] = v.sub(a[k][i])
					}
				}
				sa, err := groupedGLMMScoreShares(s, exactGCRoleGarbler, a[0], a[1], a[2], a[3])
				if err != nil {
					t.Fatal(err)
				}
				sb, err := groupedGLMMScoreShares(s, exactGCRoleEvaluator, b[0], b[1], b[2], b[3])
				if err != nil {
					t.Fatal(err)
				}
				g, e := make([]*big.Int, 13), make([]*big.Int, 6)
				for i := range g {
					g[i] = new(big.Int)
				}
				for i := 0; i < 5; i++ {
					g[i] = groupedWordInteger(sa[i])
					e[i] = groupedWordInteger(sb[i])
				}
				g[5] = big.NewInt(71)
				e[5] = big.NewInt(count - 71)
				centered := primitiveVTestCompute(t, center, g, e)
				if centered[6].Int64() != 1 {
					t.Fatal("valid center rejected")
				}
				sum := int64(0)
				for q := 0; q < 5; q++ {
					v, err := groupedProfileEval("exp_negative", centered[q].Int64())
					if err != nil {
						t.Fatal(err)
					}
					sum += v
				}
				log, err := groupedProfileEval("log", sum)
				if err != nil {
					t.Fatal(err)
				}
				got := primitiveVTestCompute(t, final, []*big.Int{centered[5], big.NewInt(log), big.NewInt(count), big.NewInt(1), new(big.Int), new(big.Int)}, []*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)})
				want, valid, err := groupedGLMMReference(s, eta, live, outcome)
				if err != nil || !valid || got[0].Int64() != want || got[1].Int64() != 1 {
					t.Fatalf("%s variance=%d got=%v want=%d err=%v", family, variance, got, want, err)
				}
			}
		}
	}
}
func TestGroupedGLMMShareBoundariesReject(t *testing.T) {
	s := groupedGLMMSpec{Family: "poisson", Rows: 3, OutputBits: 8}
	center, err := groupedGLMMCenterCompile(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []int{0, 5} {
		g, e := make([]*big.Int, 13), make([]*big.Int, 6)
		for i := range g {
			g[i] = new(big.Int)
		}
		for i := range e {
			e[i] = new(big.Int)
		}
		g[bad] = big.NewInt(99)
		got := primitiveVTestCompute(t, center, g, e)
		for _, v := range got {
			if v.Sign() != 0 {
				t.Fatal("invalid center leaked outputs")
			}
		}
	}
	final, err := groupedGLMMFinalCompile(s, 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []int64{0, 1, 2} {
		got := primitiveVTestCompute(t, final, []*big.Int{big.NewInt(-65536), big.NewInt(0), big.NewInt(1), big.NewInt(valid), big.NewInt(0), big.NewInt(0)}, []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)})
		want := int64(7)
		if valid != 1 {
			want = 0
		}
		if got[0].Int64() != want {
			t.Fatal("final cap/validity differs")
		}
	}
}
