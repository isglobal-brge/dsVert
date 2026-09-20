package main

import (
	"fmt"
	"math/big"
	"strings"
)

// This profile uses symmetric inverse-square-root whitening for exchangeable
// correlation and innovations on ORIGINAL slot gaps for AR1. It supersedes
// the legacy q16 inverse-matrix prototype; both target the same real statistic.
const groupedGEEWhiteningProfile = "grouped-gee-whitening-f96-q64-v3"

// Public coefficient generation is exact integer arithmetic. For positive
// rational r, a=floor(2^64 sqrt(r)) proves a^2 <= r*2^128 < (a+1)^2.
// No secret transcendental is evaluated and no floating coefficient is trusted.
func groupedGEESqrtQ64(r *big.Rat) *big.Int {
	n := new(big.Int).Lsh(new(big.Int).Set(r.Num()), 128)
	n.Quo(n, r.Denom())
	return new(big.Int).Sqrt(n)
}

func groupedGEESignedConstant(x *big.Int) string {
	if x.Sign() < 0 {
		return fmt.Sprintf("-int192(%s)", new(big.Int).Abs(x))
	}
	return fmt.Sprintf("int192(%s)", x)
}

func groupedGEEWhiteningConstants(s groupedGEESpec) (alpha *big.Int, correction []*big.Int, ar [][2]*big.Int) {
	rho := big.NewRat(s.RhoQ16, 65536)
	one := big.NewRat(1, 1)
	alpha = groupedGEESqrtQ64(new(big.Rat).Inv(new(big.Rat).Sub(one, rho)))
	correction = make([]*big.Int, s.Slots+1)
	correction[0] = new(big.Int)
	for m := 1; m <= s.Slots; m++ {
		den := new(big.Rat).Add(one, new(big.Rat).Mul(big.NewRat(int64(m-1), 1), rho))
		b := groupedGEESqrtQ64(new(big.Rat).Inv(den))
		correction[m] = primitiveVRoundDivReference(new(big.Int).Sub(b, alpha), big.NewInt(int64(m)))
	}
	ar = make([][2]*big.Int, s.Slots)
	a := big.NewRat(1, 1)
	for gap := 1; gap < s.Slots; gap++ {
		a.Mul(a, rho)
		den := new(big.Rat).Sub(one, new(big.Rat).Mul(a, a))
		diag := groupedGEESqrtQ64(new(big.Rat).Inv(den))
		off := primitiveVRoundDivReference(new(big.Int).Mul(diag, a.Num()), a.Denom())
		ar[gap] = [2]*big.Int{diag, off.Neg(off)}
	}
	return
}

// Inputs: private live bits in original slot order, and predecessor validity.
// Outputs: row-major q64 W and validity, freshly masked Ring192 shares.
// Only selectors run in GC; subsequent W*factor products use exact OT.
func groupedGEEWhiteningSource(s groupedGEESpec) (string, error) {
	if groupedGEEValidate(s) != nil {
		return "", primitiveVError()
	}
	n := s.Slots
	in := n + 1
	out := n*n + 1
	alpha, c, ar := groupedGEEWhiteningConstants(s)
	one := new(big.Int).Lsh(big.NewInt(1), 64)
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=g[%d]+e[%d]==1\ncount:=int32(0)\n", in+out, in, out, out, n, n)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "l%d:=g[%d]+e[%d]\nvalid=valid && (l%d==0 || l%d==1)\nif l%d==1 { count=count+1 }\n", i, i, i, i, i, i)
	}
	if s.Correlation == "exchangeable" {
		b.WriteString("c:=int192(0)\ndiagonal:=int192(0)\n")
		for m := 1; m <= n; m++ {
			fmt.Fprintf(&b, "if count==%d { c=%s\ndiagonal=%s }\n", m, groupedGEESignedConstant(c[m]), groupedGEESignedConstant(new(big.Int).Add(alpha, c[m])))
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			idx := i*n + j
			fmt.Fprintf(&b, "w%d:=int192(0)\n", idx)
			switch s.Correlation {
			case "independence":
				if i == j {
					fmt.Fprintf(&b, "if l%d==1 { w%d=int192(%s) }\n", i, idx, one)
				}
			case "exchangeable":
				value := "c"
				if i == j {
					value = "diagonal"
				}
				fmt.Fprintf(&b, "if l%d==1 && l%d==1 { w%d=%s }\n", i, j, idx, value)
			case "ar1":
				if i == j {
					fmt.Fprintf(&b, "if l%d==1 { w%d=int192(%s) }\n", i, idx, one)
					for prev := 0; prev < i; prev++ {
						fmt.Fprintf(&b, "if l%d==1 && l%d==1", i, prev)
						for k := prev + 1; k < i; k++ {
							fmt.Fprintf(&b, " && l%d==0", k)
						}
						fmt.Fprintf(&b, " { w%d=int192(%s) }\n", idx, ar[i-prev][0])
					}
				} else if j < i {
					fmt.Fprintf(&b, "if l%d==1 && l%d==1", i, j)
					for k := j + 1; k < i; k++ {
						fmt.Fprintf(&b, " && l%d==0", k)
					}
					fmt.Fprintf(&b, " { w%d=%s }\n", idx, groupedGEESignedConstant(ar[i-j][1]))
				}
			}
			fmt.Fprintf(&b, "if !valid { w%d=0 }\nout[%d]=w%d-g[%d]\n", idx, idx, idx, in+idx)
		}
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", out-1, in+out-1)
	return b.String(), nil
}

// Form W(q64)*base(q32) operands without opening a count, matrix or factor.
// Each party calls these linear maps on its own shares. Products must come
// from registerGroupedExactArithmetic, not independent local share products.
func groupedGEEWhiteningOperands(s groupedGEESpec, w, base []groupedWord) ([]groupedWord, []groupedWord, error) {
	n, d := s.Slots, s.Predictors+2
	if groupedGEEValidate(s) != nil || len(w) != n*n || len(base) != n*d {
		return nil, nil, primitiveVError()
	}
	x, y := make([]groupedWord, 0, n*n*d), make([]groupedWord, 0, n*n*d)
	for i := 0; i < n; i++ {
		for k := 0; k < d; k++ {
			for j := 0; j < n; j++ {
				x = append(x, w[i*n+j])
				y = append(y, base[j*d+k])
			}
		}
	}
	return x, y, nil
}
func groupedGEEWhiteningSums(s groupedGEESpec, products []groupedWord) ([]groupedWord, error) {
	n, d := s.Slots, s.Predictors+2
	if groupedGEEValidate(s) != nil || len(products) != n*n*d {
		return nil, primitiveVError()
	}
	out := make([]groupedWord, n*d)
	for i, p := range products {
		out[i/n] = out[i/n].add(p)
	}
	return out, nil
}

// Range-checked f96 -> q64 terminal factor boundary. Upstream validity must
// include raw-input, scalar and whitening receipts. Even an invalid mask cannot
// become a valid factor: every failure zeros the entire private output vector.
func groupedGEEFactorBoundaryCompile(s groupedGEESpec) (*primitiveVProgram, error) {
	if groupedGEEValidate(s) != nil {
		return nil, primitiveVError()
	}
	n := s.Slots * (s.Predictors + 2)
	width := n + 1
	limit := new(big.Int).Lsh(big.NewInt(2048), 96)
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(groupedGEEBoundaryRound("factorRound", 32))
	fmt.Fprintf(&b, "func main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=g[%d]+e[%d]==1\n", 2*width, width, width, width, n, n)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "x%d:=g[%d]+e[%d]\nvalid=valid && x%d>=-int192(%s) && x%d<=int192(%s)\n", i, i, i, i, limit, i, limit)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "v%d:=factorRound(x%d)\nif !valid { v%d=0 }\nout[%d]=v%d-g[%d]\n", i, i, i, i, i, width+i)
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", n, width+n)
	return primitiveVCompile(b.String(), 192, 2*width, width, width)
}

func groupedGEEWhiteningCompile(s groupedGEESpec) (*primitiveVProgram, error) {
	source, err := groupedGEEWhiteningSource(s)
	if err != nil {
		return nil, err
	}
	in, out := s.Slots+1, s.Slots*s.Slots+1
	return primitiveVCompile(source, 192, in+out, in, out)
}
