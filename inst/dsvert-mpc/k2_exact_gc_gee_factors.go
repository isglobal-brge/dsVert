package main

import (
	"fmt"
	"math/big"
	"strings"
)

// Correct RN-even q16 log(y!) coefficients for the v3 profile. The legacy
// prototype's y=3 constant is retained only by its own historical oracle.
var groupedGEEWhiteningLogFactorial = [5]int64{0, 0, 45426, 117425, 208277}

// Raw original-slot rows: complete f100 eta, p f50 features, integer y, live.
// The materializer must bind eta to the complete signed predictor; these
// internal arithmetic components cannot establish source provenance by itself.
// Normalized row: eta, RN(eta/2), -RN(eta/2), intercept/features, y*2^16,
// live, log(y!)*2^16. All arithmetic outputs are remasked Ring192 shares.
func groupedGEEInputCompile(s groupedGEESpec) (*primitiveVProgram, error) {
	if groupedGEEValidate(s) != nil {
		return nil, primitiveVError()
	}
	rw, ow := s.Predictors+3, s.Predictors+7
	in, out := s.Slots*rw, s.Slots*ow+1
	var b strings.Builder
	b.WriteString("package main\n")
	for _, shift := range []int{36, 48, 34, 1} {
		b.WriteString(groupedGEEBoundaryRound(fmt.Sprintf("inputRound%d", shift), shift))
	}
	fmt.Fprintf(&b, "func main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=true\n", in+out, in, out, out)
	etaCap := new(big.Int).Lsh(big.NewInt(4), 100)
	fCap := new(big.Int).Lsh(big.NewInt(1), 50)
	for r := 0; r < s.Slots; r++ {
		offset := r * rw
		fmt.Fprintf(&b, "l%d:=g[%d]+e[%d]\ny%d:=g[%d]+e[%d]\na%d:=g[%d]+e[%d]\nvalid=valid && (l%d==0 || l%d==1)\n", r, offset+rw-1, offset+rw-1, r, offset+rw-2, offset+rw-2, r, offset, offset, r, r)
		fmt.Fprintf(&b, "if l%d==1 { valid=valid && y%d>=0 && y%d<=%d && a%d>=-int192(%s) && a%d<=int192(%s) } else { y%d=0\na%d=0 }\n", r, r, r, s.MaxOutcome, r, etaCap, r, etaCap, r, r)
		// Bound before narrowing or rounding, including on a rejected live input.
		fmt.Fprintf(&b, "if a%d < -int192(%s) || a%d>int192(%s) { a%d=0 }\neta%d:=inputRound48(inputRound36(a%d))\nhalf%d:=inputRound1(eta%d)\n", r, etaCap, r, etaCap, r, r, r, r, r)
		for k := 0; k < s.Predictors; k++ {
			i := offset + 1 + k
			fmt.Fprintf(&b, "x%d_%d:=g[%d]+e[%d]\nif l%d==1 { valid=valid && x%d_%d>=0 && x%d_%d<=int192(%s) } else { x%d_%d=0 }\nif x%d_%d<0 || x%d_%d>int192(%s) { x%d_%d=0 }\nx%d_%d=inputRound34(x%d_%d)\n", r, k, i, i, r, r, k, r, k, fCap, r, k, r, k, r, k, fCap, r, k, r, k, r, k)
		}
		fmt.Fprintf(&b, "lf%d:=int192(0)\n", r)
		if s.Family == "poisson" {
			for y := 2; y <= int(s.MaxOutcome); y++ {
				fmt.Fprintf(&b, "if y%d==%d { lf%d=int192(%d) }\n", r, y, r, groupedGEEWhiteningLogFactorial[y])
			}
		}
	}
	for r := 0; r < s.Slots; r++ {
		values := []string{fmt.Sprintf("eta%d", r), fmt.Sprintf("half%d", r), fmt.Sprintf("-half%d", r), "int192(65536)"}
		for k := 0; k < s.Predictors; k++ {
			values = append(values, fmt.Sprintf("x%d_%d", r, k))
		}
		values = append(values, fmt.Sprintf("y%d<<16", r), fmt.Sprintf("l%d", r), fmt.Sprintf("lf%d", r))
		for k, v := range values {
			i := r*ow + k
			fmt.Fprintf(&b, "v%d:=%s\nif !valid { v%d=0 }\nout[%d]=v%d-g[%d]\n", i, v, i, i, i, in+i)
		}
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", out-1, in+out-1)
	return primitiveVCompile(b.String(), 192, in+out, in, out)
}

// Profiles are separate <=5000-AND scalar calls, fed only by InputCompile's
// guarded arguments and its receipt. Per row: mu, sqrt(V), invsqrt(V), loss
// profile (softplus for binomial; exp(eta) for Poisson). Three distinct calls
// suffice for Poisson. Every profile validity must reach the base boundary.
func groupedGEEBaseOperands(s groupedGEESpec, normalized, profiles []groupedWord) ([]groupedWord, []groupedWord, error) {
	n, d := s.Slots, s.Predictors+1
	ow := s.Predictors + 7
	if groupedGEEValidate(s) != nil || len(normalized) != n*ow || len(profiles) != n*4 {
		return nil, nil, primitiveVError()
	}
	x, y := make([]groupedWord, 0, n*(d+2)), make([]groupedWord, 0, n*(d+2))
	for r := 0; r < n; r++ {
		row, p := normalized[r*ow:(r+1)*ow], profiles[r*4:(r+1)*4]
		for k := 0; k < d; k++ {
			x = append(x, row[3+k])
			y = append(y, p[1])
		}
		x = append(x, row[3+d].sub(p[0]), row[3+d])
		y = append(y, p[2], row[0])
	}
	return x, y, nil
}

// Exact q32 base factors and row likelihood shares, prior to private live
// masking. All products here are outputs from the receipt-bound OT stage.
func groupedGEEBaseShares(s groupedGEESpec, normalized, profiles, products []groupedWord) ([]groupedWord, error) {
	n, d := s.Slots, s.Predictors+1
	ow := s.Predictors + 7
	if groupedGEEValidate(s) != nil || len(normalized) != n*ow || len(profiles) != n*4 || len(products) != n*(d+2) {
		return nil, primitiveVError()
	}
	out := append([]groupedWord(nil), products...)
	for r := 0; r < n; r++ {
		loss := profiles[4*r+3]
		if s.Family == "poisson" {
			loss = loss.add(normalized[r*ow+ow-1])
		}
		out[r*(d+2)+d+1] = loss.shl(16).sub(products[r*(d+2)+d+1])
	}
	return out, nil
}

// Inputs: base rows (d u, z, likelihood), live bits, one accumulated private
// validity. Bounds reject corrupt/out-of-domain arithmetic before whitening.
func groupedGEEBaseBoundaryCompile(s groupedGEESpec) (*primitiveVProgram, error) {
	if groupedGEEValidate(s) != nil {
		return nil, primitiveVError()
	}
	n, d := s.Slots, s.Predictors+1
	size := n * (d + 2)
	in, out := size+n+1, size+1
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=g[%d]+e[%d]==1\n", in+out, in, out, out, in-1, in-1)
	for r := 0; r < n; r++ {
		fmt.Fprintf(&b, "l%d:=g[%d]+e[%d]\nvalid=valid && (l%d==0 || l%d==1)\n", r, size+r, size+r, r, r)
		for k := 0; k < d+2; k++ {
			i := r*(d+2) + k
			fmt.Fprintf(&b, "x%d:=g[%d]+e[%d]\nvalid=valid && x%d>=-int192(2199023255552) && x%d<=int192(2199023255552)\nif l%d!=1 { x%d=0 }\n", i, i, i, i, i, r, i)
		}
	}
	for i := 0; i < size; i++ {
		fmt.Fprintf(&b, "if !valid { x%d=0 }\nout[%d]=x%d-g[%d]\n", i, i, i, in+i)
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", size, in+size)
	return primitiveVCompile(b.String(), 192, in+out, in, out)
}

// Sum masked row likelihood shares locally and clamp ONCE per cluster to the
// signed R coordinate cap. RowLossCap belongs only to the legacy prototype.
func groupedGEELikelihoodCompile(s groupedGEESpec, clusterCap int64) (*primitiveVProgram, error) {
	if groupedGEEValidate(s) != nil || clusterCap < 1 || clusterCap > 1<<40 {
		return nil, primitiveVError()
	}
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(groupedGEEBoundaryRound("lossRound", 32-s.GridBits))
	fmt.Fprintf(&b, "func main(g [4]int192,e [2]int192) [2]int192 {\nvar out [2]int192\nx:=g[0]+e[0]\nvalid:=g[1]+e[1]==1 && x>=-int192(17592186044416) && x<=int192(17592186044416)\nv:=int192(0)\nx=lossRound(x)\nif x<0 { x=0 }\nif x>int192(%d) { x=int192(%d) }\nif valid { v=1 } else { x=0 }\nout[0]=x-g[2]\nout[1]=v-g[3]\nreturn out\n}\n", clusterCap, clusterCap)
	return primitiveVCompile(b.String(), 192, 4, 2, 2)
}
