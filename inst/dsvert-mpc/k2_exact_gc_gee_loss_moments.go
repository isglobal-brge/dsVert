package main

import (
	"fmt"
	"math/big"
	"strings"
)

// Exact score/bread reduction after privately validated working-correlation
// whitening. Each row has d u coordinates and one z, all q64. Correlation
// construction/whitening is a separate mandatory predecessor receipt; these
// helpers neither construct R^-1 nor accept analyst-supplied factors.
func groupedGEEMomentOperands(s groupedGEESpec, factors []groupedWord) ([]groupedWord, []groupedWord, error) {
	if groupedGEEValidate(s) != nil || len(factors) != s.Slots*(s.Predictors+2) {
		return nil, nil, primitiveVError()
	}
	d := s.Predictors + 1
	tri := d * (d + 1) / 2
	x, y := make([]groupedWord, 0, s.Slots*(d+tri)), make([]groupedWord, 0, s.Slots*(d+tri))
	for r := 0; r < s.Slots; r++ {
		row := factors[r*(d+1) : (r+1)*(d+1)]
		for k := 0; k < d; k++ {
			x = append(x, row[k])
			y = append(y, row[d])
		}
		// Match signed R upper-triangle coordinate order: column then row.
		for l := 0; l < d; l++ {
			for k := 0; k <= l; k++ {
				x = append(x, row[k])
				y = append(y, row[l])
			}
		}
	}
	return x, y, nil
}
func groupedGEEMomentSums(s groupedGEESpec, products []groupedWord) ([]groupedWord, error) {
	d := s.Predictors + 1
	width := d + d*(d+1)/2
	if groupedGEEValidate(s) != nil || len(products) != s.Slots*width {
		return nil, primitiveVError()
	}
	out := make([]groupedWord, width)
	for i, v := range products {
		out[i%width] = out[i%width].add(v)
	}
	return out, nil
}

func groupedGEEBoundaryRound(name string, shift int) string {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(shift)), big.NewInt(1))
	half := new(big.Int).Lsh(big.NewInt(1), uint(shift-1))
	return fmt.Sprintf(`func %s(x int192) int192 {
 negative:=x<0
 a:=uint192(x)
 if negative { a=uint192(-x) }
 q:=a>>%d
 r:=a & uint192(%s)
 if r>uint192(%s) || (r==uint192(%s) && (q & 1)==1) { q=q+1 }
 value:=int192(q)
 if negative { value=-value }
 return value
}
`, name, shift, mask, half, half)
}

// Per-cluster boundary: clip each f128 score, then round it once to q16 for
// exact clipped-score outer products. Bread is quantized and cap/shift mapped
// independently. All outputs remain Ring192 shares, including private valid.
func groupedGEEMomentBoundaryCompile(s groupedGEESpec) (*primitiveVProgram, error) {
	if groupedGEEValidate(s) != nil {
		return nil, primitiveVError()
	}
	d := s.Predictors + 1
	tri := d * (d + 1) / 2
	width := d + tri + 1
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(groupedGEEBoundaryRound("scoreRound", 112))
	b.WriteString(groupedGEEBoundaryRound("breadRound", 128-s.GridBits))
	fmt.Fprintf(&b, "func main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=g[%d]+e[%d]==1\n", 2*width, width, width, width, width-1, width-1)
	clip := new(big.Int).Lsh(big.NewInt(s.ScoreClipQ16), 112)
	for k := 0; k < d; k++ {
		fmt.Fprintf(&b, "s%d:=g[%d]+e[%d]\nif s%d>int192(%s) { s%d=int192(%s) }\nif s%d < -int192(%s) { s%d=-int192(%s) }\ns%d=scoreRound(s%d)\nif !valid { s%d=0 }\nout[%d]=s%d-g[%d]\n", k, k, k, k, clip, k, clip, k, clip, k, clip, k, k, k, k, k, width+k)
	}
	shift, upper := int64(0), s.BreadCap
	if s.Correlation != "independence" {
		shift = s.BreadCap
		upper = 2 * s.BreadCap
	}
	for k := 0; k < tri; k++ {
		idx := d + k
		fmt.Fprintf(&b, "b%d:=breadRound(g[%d]+e[%d])+int192(%d)\nif b%d<0 { b%d=0 }\nif b%d>int192(%d) { b%d=int192(%d) }\nif !valid { b%d=0 }\nout[%d]=b%d-g[%d]\n", k, idx, idx, shift, k, k, k, upper, k, upper, k, idx, k, width+idx)
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", width-1, 2*width-1)
	return primitiveVCompile(b.String(), 192, 2*width, width, width)
}

func groupedGEEMeatOperands(s groupedGEESpec, clipped []groupedWord) ([]groupedWord, []groupedWord, error) {
	d := s.Predictors + 1
	if groupedGEEValidate(s) != nil || len(clipped) != d {
		return nil, nil, primitiveVError()
	}
	x, y := make([]groupedWord, 0, d*(d+1)/2), make([]groupedWord, 0, d*(d+1)/2)
	for l := 0; l < d; l++ {
		for k := 0; k <= l; k++ {
			x = append(x, clipped[k])
			y = append(y, clipped[l])
		}
	}
	return x, y, nil
}
func groupedGEEMeatFinalCompile(s groupedGEESpec) (*primitiveVProgram, error) {
	if groupedGEEValidate(s) != nil {
		return nil, primitiveVError()
	}
	d := s.Predictors + 1
	tri := d * (d + 1) / 2
	width := tri + 1
	shift := s.ScoreClipQ16 * s.ScoreClipQ16
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(groupedGEEBoundaryRound("meatRound", 32-s.GridBits))
	fmt.Fprintf(&b, "func main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=g[%d]+e[%d]==1\n", 2*width, width, width, width, width-1, width-1)
	for k := 0; k < tri; k++ {
		fmt.Fprintf(&b, "m%d:=g[%d]+e[%d]+int192(%d)\nif m%d<0 { m%d=0 }\nif m%d>int192(%d) { m%d=int192(%d) }\nm%d=meatRound(m%d)\nif !valid { m%d=0 }\nout[%d]=m%d-g[%d]\n", k, k, k, shift, k, k, k, 2*shift, k, 2*shift, k, k, k, k, k, width+k)
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", width-1, 2*width-1)
	return primitiveVCompile(b.String(), 192, 2*width, width, width)
}
