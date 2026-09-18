package main

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// Scalar profiles use <=32-bit operands and one multiplication. The full
// product is widened; exact prefix sums and cohort losses use 64-bit lanes.
// A fixed binary mux tree selects public coefficients, never a secret index
// sent to either peer. All 64 branches have the same public circuit geometry.
func coxLossProfileSource() string {
	var b strings.Builder
	for _, name := range []string{"exp", "log"} {
		fmt.Fprintf(&b, "func cox%s(a int32) uint32 {\n", name)
		if name == "exp" {
			b.WriteString("x := uint32(a+524288)\nif x == 1048576 { x=1048575 }\n")
		} else {
			b.WriteString("x := uint32(a-1048576)\n")
		}
		b.WriteString("index := x >> 14\noffset := uint14(x & 16383)\n")
		for i := 0; i < 64; i++ {
			var lo, hi uint32
			if name == "exp" {
				lo = CoxGridCrossExpKnotsQ20[i]
				hi = CoxGridCrossExpKnotsQ20[i+1]
			} else {
				lo = uint32(CoxGridCrossLogKnotsQ20[i])
				hi = uint32(CoxGridCrossLogKnotsQ20[i+1])
			}
			fmt.Fprintf(&b, "v%d := uint32(%d)\nd%d := uint32(%d)\n", i, lo, i, hi-lo)
		}
		for span := 1; span < 64; span *= 2 {
			for i := 0; i < 64; i += span * 2 {
				fmt.Fprintf(&b, "if (index & %d) != 0 { v%d=v%d\nd%d=d%d }\n", span, i, i+span, i, i+span)
			}
		}
		b.WriteString("product := wideMul(uint32(d0),uint32(offset))\ny := v0+uint32(product >> 14)\n")
		if name == "exp" {
			fmt.Fprintf(&b, "if a == 524288 { y=uint32(%d) }\n", CoxGridCrossExpKnotsQ20[64])
		}
		b.WriteString("return y\n}\n")
	}
	b.WriteString("func coxlogrisk(a uint64) int64 {\nm := a\nk := int32(0)\n")
	for _, shift := range []int{16, 8, 4, 2, 1} {
		fmt.Fprintf(&b, "if m >= uint64(%d) { m=m >> %d\nk=k+%d }\n", uint64(1)<<uint(20+shift), shift, shift)
	}
	for _, shift := range []int{16, 8, 4, 2, 1} {
		fmt.Fprintf(&b, "if m < uint64(%d) { m=m << %d\nk=k-%d }\n", uint64(1)<<uint(21-shift), shift, shift)
	}
	fmt.Fprintf(&b, "return int64(coxlog(int32(m)))+int64(k)*%d\n}\n", CoxGridCrossLn2Q20)
	return b.String()
}

func coxLossEmitOutput(b *strings.Builder, values []string, inputWords int, width int) {
	fmt.Fprintf(b, "var out [%d]int%d\n", len(values), width)
	for i, v := range values {
		fmt.Fprintf(b, "out[%d]=int%d(%s)-g[%d]\n", i, width, v, inputWords+i)
	}
	b.WriteString("return out\n}\n")
}

func coxLossPrepareSource(rows int) (string, int, int, int, int) {
	// Input rows are complete f100 predictor dots, joined private live bits,
	// event bits; final lane is predecessor/source validity. Source Ring128 is
	// reconstructed modulo 2^128 BEFORE sign interpretation and downscaling.
	in := 3*rows + 1
	out := in
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]int128,e [%d]int128) [%d]int128 {\n", in+out, in, out)
	fmt.Fprintf(&b, "ok := g[%d]+e[%d] == 1\n", in-1, in-1)
	limit := new(big.Int).Lsh(big.NewInt(8), 100)
	limit.Add(limit, new(big.Int).Lsh(big.NewInt(8), 50)) // p<=16 coefficient rounding slack
	var values []string
	for r := 0; r < rows; r++ {
		i := 3 * r
		fmt.Fprintf(&b, "p%d:=g[%d]+e[%d]\nv%d:=g[%d]+e[%d]\nevent%d:=g[%d]+e[%d]\n", r, i, i, r, i+1, i+1, r, i+2, i+2)
		fmt.Fprintf(&b, "good%d := (v%d==0 || v%d==1) && (event%d==0 || event%d==1)\nif v%d==1 { good%d=good%d && p%d>=-int128(%s) && p%d<=int128(%s) }\nok=ok && good%d\n", r, r, r, r, r, r, r, r, r, limit, r, limit, r)
		fmt.Fprintf(&b, "if !good%d || v%d!=1 {p%d=0\nv%d=0\nevent%d=0}\nnegative%d:=p%d<0\nmagnitude%d:=uint128(p%d)\nif negative%d {magnitude%d=uint128(-p%d)}\n", r, r, r, r, r, r, r, r, r, r, r, r)
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 84), big.NewInt(1))
		half := new(big.Int).Lsh(big.NewInt(1), 83)
		fmt.Fprintf(&b, "q%d:=magnitude%d >> 84\nrem%d:=magnitude%d & uint128(%s)\nif rem%d>uint128(%s) || (rem%d==uint128(%s) && (q%d & 1)!=0) {q%d=q%d+1}\neta%d:=int128(q%d)\nif negative%d {eta%d=-eta%d}\n", r, r, r, r, mask, r, half, r, half, r, r, r, r, r, r, r, r)
		values = append(values, fmt.Sprintf("eta%d", r), fmt.Sprintf("v%d", r), fmt.Sprintf("event%d", r))
	}
	b.WriteString("valid:=int128(0)\nif ok {valid=1}\n")
	values = append(values, "valid")
	coxLossEmitOutput(&b, values, in, 128)
	return b.String(), 128, in + out, in, out
}

func coxLossPermutationRows(chunk coxLossChunk) []int {
	set := map[int]bool{}
	for _, s := range chunk.Switches {
		set[s.Left] = true
		set[s.Right] = true
	}
	rows := make([]int, 0, len(set))
	for row := range set {
		rows = append(rows, row)
	}
	sort.Ints(rows)
	return rows
}

func coxLossPermutationSource(chunk coxLossChunk) (string, int, int, int, int) {
	rows := coxLossPermutationRows(chunk)
	index := map[int]int{}
	for i, r := range rows {
		index[r] = i
	}
	// Garbler-only raw control words follow shared payload and validity. The
	// output masks follow those controls, never reuse any incoming share.
	shared := 3*len(rows) + 1
	inG := shared + len(chunk.Switches)
	out := shared
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]int64,e [%d]int64) [%d]int64 {\nvar x [%d]int64\n", inG+out, shared, out, shared-1)
	fmt.Fprintf(&b, "ok:=g[%d]+e[%d]==1\n", shared-1, shared-1)
	for i := 0; i < shared-1; i++ {
		fmt.Fprintf(&b, "x[%d]=g[%d]+e[%d]\n", i, i, i)
	}
	for i, s := range chunk.Switches {
		fmt.Fprintf(&b, "ok=ok && (g[%d]==0 || g[%d]==1)\n", shared+i, shared+i)
		for col := 0; col < 3; col++ {
			a, z := 3*index[s.Left]+col, 3*index[s.Right]+col
			fmt.Fprintf(&b, "d%d_%d:=x[%d]-x[%d]\nif g[%d]==1 {d%d_%d=x[%d]^x[%d]}\nx[%d]=x[%d]^d%d_%d\nx[%d]=x[%d]^d%d_%d\n", i, col, a, a, shared+i, i, col, a, z, a, a, i, col, z, z, i, col)
		}
	}
	var values []string
	for i := 0; i < shared-1; i++ {
		values = append(values, fmt.Sprintf("x[%d]", i))
	}
	b.WriteString("valid:=int64(0)\nif ok {valid=1}\n")
	values = append(values, "valid")
	coxLossEmitOutput(&b, values, inG, 64)
	return b.String(), 64, inG + out, shared, out
}

func coxLossScanSource(s coxLossSpec, chunk coxLossChunk) (string, int, int, int, int) {
	n := chunk.Rows
	forward := chunk.Kind == "forward"
	in := 4*n + 3
	out := 3
	if forward {
		in = 4*n + 2
		out = 4*n + 2
	}
	var b strings.Builder
	b.WriteString("package main\n")
	if forward {
		b.WriteString(coxLossProfileSource())
	}
	fmt.Fprintf(&b, "func main(g [%d]int64,e [%d]int64) [%d]int64 {\n", in+out, in, out)
	fmt.Fprintf(&b, "ok:=g[%d]+e[%d]==1\n", in-1, in-1)
	bound := int64(s.Capacity) * 32 * (1 << 20)
	var values []string
	if forward {
		maxRisk := uint64(s.Capacity) * uint64(CoxGridCrossExpKnotsQ20[64])
		fmt.Fprintf(&b, "risk:=g[%d]+e[%d]\nok=ok && risk>=0 && risk<=%d\nif risk<0 || risk>%d {risk=0}\n", 4*n, 4*n, maxRisk, maxRisk)
		for r := 0; r < n; r++ {
			for col, name := range []string{"eta", "live", "event", "end"} {
				fmt.Fprintf(&b, "%s%d:=g[%d]+e[%d]\n", name, r, 4*r+col, 4*r+col)
			}
			fmt.Fprintf(&b, "good%d:=(live%d==0 || live%d==1) && (event%d==0 || event%d==1) && (end%d==0 || end%d==1)\nif live%d==1 {good%d=good%d && eta%d>=-524288 && eta%d<=524288}\nok=ok && good%d\nif !good%d || live%d!=1 {eta%d=0\nevent%d=0\nlive%d=0}\n", r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r)
			fmt.Fprintf(&b, "w%d:=int64(coxexp(int32(eta%d)))\nif live%d==1 {risk=risk+w%d}\nz%d:=uint64(1048576)\nif end%d==1 && risk>0 {z%d=uint64(risk)}\nh%d:=coxlogrisk(z%d)\n", r, r, r, r, r, r, r, r, r)
			values = append(values, fmt.Sprintf("eta%d", r), fmt.Sprintf("event%d", r), fmt.Sprintf("end%d", r), fmt.Sprintf("h%d", r))
		}
		fmt.Fprintf(&b, "ok=ok && risk<=%d\n", maxRisk)
		if chunk.Start+n == intNextPowerOfTwo(s.Capacity) {
			fmt.Fprintf(&b, "ok=ok && end%d==1\n", n-1)
		}
		values = append(values, "risk")
	} else {
		fmt.Fprintf(&b, "h:=g[%d]+e[%d]\nloss:=g[%d]+e[%d]\nok=ok && h>=-9437184 && h<=18874368 && loss>=-%d && loss<=%d\nif !ok {h=0\nloss=0}\n", 4*n, 4*n, 4*n+1, 4*n+1, bound, bound)
		for r := n - 1; r >= 0; r-- {
			for col, name := range []string{"eta", "event", "end", "logrisk"} {
				fmt.Fprintf(&b, "%s%d:=g[%d]+e[%d]\n", name, r, 4*r+col, 4*r+col)
			}
			fmt.Fprintf(&b, "good%d:=eta%d>=-524288 && eta%d<=524288 && (event%d==0 || event%d==1) && (end%d==0 || end%d==1) && logrisk%d>=-9437184 && logrisk%d<=18874368\nok=ok && good%d\nif !good%d {eta%d=0\nevent%d=0\nend%d=0\nlogrisk%d=0}\nif end%d==1 {h=logrisk%d}\nif event%d==1 {loss=loss+h-(eta%d << 4)}\n", r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r)
		}
		fmt.Fprintf(&b, "ok=ok && loss>=-%d && loss<=%d\n", bound, bound)
		values = append(values, "h", "loss")
	}
	b.WriteString("valid:=int64(0)\nif ok {valid=1}\n")
	values = append(values, "valid")
	coxLossEmitOutput(&b, values, in, 64)
	return b.String(), 64, in + out, in, out
}

func intNextPowerOfTwo(n int) int {
	v := 1
	for v < n {
		v *= 2
	}
	return v
}

func coxLossFinalizeSource(s coxLossSpec, j int) (string, int, int, int, int) {
	shift := 20 - s.GridBits
	mask := (1 << uint(shift)) - 1
	half := 1 << uint(shift-1)
	cap := s.Caps[j]
	bound := int64(s.Capacity) * 32 * (1 << 20)
	source := fmt.Sprintf(`package main
func main(g [4]int64,e [2]int64) [2]int64 {
 loss:=g[0]+e[0]
 ok:=g[1]+e[1]==1 && loss>=-%d && loss<=%d
 if loss<0 {loss=0}
 q:=loss >> %d
 r:=loss & %d
 if r>%d || (r==%d && (q & 1)!=0) {q=q+1}
 if q>%d {q=%d}
 valid:=int64(0)
 if ok {valid=1} else {q=0}
 var out [2]int64
 out[0]=q-g[2]
 out[1]=valid-g[3]
 return out
}
`, bound, bound, shift, mask, half, half, cap, cap)
	return source, 64, 4, 2, 2
}

func coxLossCompileChunk(p coxLossSchedule, ordinal int) (*primitiveVProgram, error) {
	if _, err := p.digest(); err != nil || ordinal < 0 || ordinal >= len(p.Chunks) {
		return nil, coxLossError()
	}
	c := p.Chunks[ordinal]
	var source string
	var width, g, e, out int
	switch c.Kind {
	case "prepare":
		source, width, g, e, out = coxLossPrepareSource(c.Rows)
	case "permute":
		source, width, g, e, out = coxLossPermutationSource(c)
	case "forward", "backward":
		source, width, g, e, out = coxLossScanSource(p.Spec, c)
	case "finalize":
		source, width, g, e, out = coxLossFinalizeSource(p.Spec, c.Candidate)
	default:
		return nil, coxLossError()
	}
	program, err := primitiveVCompile(source, width, g, e, out)
	if err != nil {
		return nil, coxLossError()
	}
	return program, nil
}
