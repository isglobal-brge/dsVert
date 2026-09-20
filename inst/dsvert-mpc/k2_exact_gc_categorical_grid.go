package main

import (
	"fmt"
	"strings"
)

// Keep the lane's complete, certified row functions inside the Step-2 batch.
// Dots are formed linearly on Ring128 shares, then widened privately to the
// signed 192-bit family ABI before its single q16 rounding operation.
func crossGridCategoricalKernelSource(p crossGridKernelPlan) (string, error) {
	if p.validate() != nil || (p.Family != "multinomial" && p.Family != "ordinal") {
		return "", errCrossGridKernel
	}
	var s strings.Builder
	s.WriteString(exactGCFamilyMathSource())
	groups := p.predictorGroups()
	for j := range p.Beta {
		spec := exactGCFamilyLossSpec{Classes: p.Classes, GridBits: p.GridBits, Cap: int64(p.Caps[j])}
		var source string
		var err error
		if p.Family == "ordinal" {
			spec.Thresholds = p.Thresholds[j]
			source, err = exactGCOrdinalLossSource(spec)
		} else {
			source, err = exactGCMultinomialLossSource(spec)
		}
		if err != nil {
			return "", errCrossGridKernel
		}
		offset := strings.Index(source, "func main(")
		if offset < 0 {
			return "", errCrossGridKernel
		}
		s.WriteString(strings.Replace(source[offset:], "func main(", fmt.Sprintf("func categoricalRow%d(", j), 1))
	}
	n := p.sourceCount() + p.Rows*len(p.Beta)*groups
	fmt.Fprintf(&s, "func main(g [%d]uint128,e [%d]uint128) [%d]uint128 {\nvar out [%d]uint128\nvar sums [%d]uint64\n", n+len(p.Beta)+1, n, len(p.Beta)+1, len(p.Beta)+1, len(p.Beta))
	start := p.Rows * 2 * (p.Predictors + 1)
	fmt.Fprintf(&s, "a0:=g[%d]^e[%d]\na1:=g[%d]^e[%d]\naligned:=(a0!=0 || a1!=0)\n", start, start, start+1, start+1)
	for k := 1; k < p.Owners; k++ {
		i := start + 2*k
		fmt.Fprintf(&s, "aligned=aligned && (g[%d]^e[%d])==a0 && (g[%d]^e[%d])==a1\n", i, i, i+1, i+1)
	}
	s.WriteString("guard:=aligned\n")
	for r := 0; r < p.Rows; r++ {
		fmt.Fprintf(&s, "ok%d:=aligned\n", r)
		for k := 0; k <= p.Predictors; k++ {
			i := r*2*(p.Predictors+1) + 2*k
			bound := uint64(1 << 50)
			if k == p.Predictors {
				bound = uint64(p.MaxOutcome)
			}
			fmt.Fprintf(&s, "x%d_%d:=g[%d]+e[%d]\nok%d=ok%d && x%d_%d<=%d && (g[%d]+e[%d])==1\n", r, k, i, i, r, r, r, k, bound, i+1, i+1)
		}
		fmt.Fprintf(&s, "y%d:=uint3(x%d_%d & 7)\nif !ok%d {y%d=0}\n", r, r, p.Predictors, r, r)
		for j := range p.Beta {
			id := fmt.Sprintf("%d_%d", r, j)
			fmt.Fprintf(&s, "var a%s [%d]uint192\nvar b%s [%d]uint192\n", id, groups+4, id, groups+2)
			for group := 0; group < groups; group++ {
				dotid := fmt.Sprintf("%s_%d", id, group)
				i := p.sourceCount() + (r*len(p.Beta)+j)*groups + group
				fmt.Fprintf(&s, "dot%s:=int128(g[%d]+e[%d])\nif !ok%d {dot%s=0}\nwide%s:=int192(dot%s)\nif dot%s<0 {wide%s= -int192(-dot%s)}\na%s[%d]=uint192(wide%s)\n", dotid, i, i, r, dotid, dotid, dotid, dotid, dotid, dotid, id, group, dotid)
			}
			fmt.Fprintf(&s, "a%s[%d]=uint192(y%d)\nif ok%d {a%s[%d]=1}\nloss%s:=categoricalRow%d(a%s,b%s)\nguard=guard && loss%s[1]==1\nsums[%d]=sums[%d]+uint64(loss%s[0])\n", id, groups, r, r, id, groups+1, id, j, id, id, id, j, j, id)
		}
	}
	for j := range p.Beta {
		fmt.Fprintf(&s, "out[%d]=uint128(sums[%d])-g[%d]\n", j, j, n+j)
	}
	fmt.Fprintf(&s, "out[%d]=g[%d]\nif guard {out[%d]=out[%d]^1}\nreturn out\n}\n", len(p.Beta), n+len(p.Beta), len(p.Beta), len(p.Beta))
	return s.String(), nil
}
