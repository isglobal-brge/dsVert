package main

import (
	_ "embed"
	"fmt"
	"math/bits"
	"strings"
)

// The complete signed profile envelope is digest-checked by the lane builder.
//
//go:embed cross_grid_nb_profile_v1.json
var crossGridNBProfileJSON []byte

// NB uses the Step-2 source ABI, f100 shared dots, private alignment, output
// masks and durable batch protocol. Its pinned q64 loss assembly is unchanged.
func crossGridNBKernelSource(p crossGridKernelPlan) (string, error) {
	if p.validate() != nil || p.Family != "nb" {
		return "", errCrossGridKernel
	}
	var s strings.Builder
	s.WriteString("package main\n")
	s.WriteString(strings.ReplaceAll(crossGridKernelRoundSource("roundNBeta", 36), "int64", "int128"))
	kernels := make([]exactGCNBLossKernelV1, len(p.Beta))
	emitted := map[string]bool{}
	for j := range kernels {
		kernel, err := exactGCBuildNBLossWidthV1(crossGridNBProfileJSON, exactGCNBLossParametersV1{
			ThetaExponent: p.ThetaExponents[j], MaxOutcome: p.MaxOutcome, OutputGridBits: p.GridBits, PerPatientCap: int64(p.Caps[j]),
		}, 128)
		if err != nil {
			return "", errCrossGridKernel
		}
		kernels[j] = kernel
		if !emitted[kernel.Function] {
			s.WriteString(kernel.Declarations)
			emitted[kernel.Function] = true
		}
	}
	n := p.sourceCount() + p.Rows*len(p.Beta)
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
		fmt.Fprintf(&s, "y%d:=uint16(x%d_%d & %d)\nif !ok%d {y%d=0}\n", r, r, p.Predictors, (1<<bits.Len(uint(p.MaxOutcome)))-1, r, r)
		for j, kernel := range kernels {
			id := fmt.Sprintf("%d_%d", r, j)
			i := p.sourceCount() + r*len(p.Beta) + j
			fmt.Fprintf(&s, "dot%s:=int128(g[%d]+e[%d])\nif !ok%d {dot%s=0}\neta%s:=roundNBeta(dot%s)\n", id, i, i, r, id, id, id)
			fmt.Fprintf(&s, "loss%s,valid%s:=%s(eta%s,uint128(y%d),ok%d)\nguard=guard && valid%s\nsums[%d]=sums[%d]+uint64(loss%s)\n", id, id, kernel.Function, id, r, r, id, j, j, id)
		}
	}
	for j := range p.Beta {
		fmt.Fprintf(&s, "out[%d]=uint128(sums[%d])-g[%d]\n", j, j, n+j)
	}
	fmt.Fprintf(&s, "out[%d]=g[%d]\nif guard {out[%d]=out[%d]^1}\nreturn out\n}\n", len(p.Beta), n+len(p.Beta), len(p.Beta), len(p.Beta))
	return s.String(), nil
}
