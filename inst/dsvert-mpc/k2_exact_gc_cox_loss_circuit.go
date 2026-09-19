package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
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
		var bases, differences [64]uint32
		for i := 0; i < 64; i++ {
			if name == "exp" {
				bases[i] = CoxGridCrossExpKnotsQ20[i]
				differences[i] = CoxGridCrossExpKnotsQ20[i+1] - bases[i]
			} else {
				bases[i] = uint32(CoxGridCrossLogKnotsQ20[i])
				differences[i] = uint32(CoxGridCrossLogKnotsQ20[i+1]) - bases[i]
			}
		}
		coxLossEmitCoefficients(&b, bases, differences)
		if name == "exp" {
			b.WriteString("product := wideMul(uint30(d0),uint30(offset))\n")
		} else {
			b.WriteString("product := wideMul(uint14(d0),offset)\n")
		}
		b.WriteString("y := uint32(v0)+uint32(product >> 14)\n")
		if name == "exp" {
			fmt.Fprintf(&b, "if a == 524288 { y=uint32(%d) }\n", CoxGridCrossExpKnotsQ20[64])
		}
		b.WriteString("return y\n}\n")
	}
	b.WriteString("func coxlogrisk(a uint64) int32 {\nm := uint45(a)\nk := int6(0)\n")
	for _, shift := range []int{16, 8, 4, 2, 1} {
		fmt.Fprintf(&b, "if m >= uint45(%d) { m=m >> %d\nk=k+%d }\n", uint64(1)<<uint(20+shift), shift, shift)
	}
	b.WriteString("small := uint21(m)\n")
	for _, shift := range []int{16, 8, 4, 2, 1} {
		fmt.Fprintf(&b, "if small < uint21(%d) { small=small << %d\nk=k-%d }\n", uint64(1)<<uint(21-shift), shift, shift)
	}
	fmt.Fprintf(&b, "return int32(coxlog(int32(small)))+int32(k)*%d\n}\n", CoxGridCrossLn2Q20)
	return b.String()
}

// Public coefficient-bit decision diagrams share identical subfunctions.
// Neither the source nor its geometry depends on a protected piece index.
func coxLossEmitCoefficients(b *strings.Builder, bases, differences [64]uint32) {
	for i := 0; i < 6; i++ {
		fmt.Fprintf(b, "bit%d := uint1(index >> %d)\n", i, i)
	}
	cache := map[string]string{}
	var emit func([]uint32, int) string
	emit = func(values []uint32, level int) string {
		same := true
		for _, v := range values {
			same = same && v == values[0]
		}
		if same {
			return fmt.Sprintf("uint1(%d)", values[0])
		}
		key := fmt.Sprintf("%d/%v", level, values)
		if v, ok := cache[key]; ok {
			return v
		}
		a, z := make([]uint32, len(values)/2), make([]uint32, len(values)/2)
		for i := range a {
			a[i] = values[2*i]
			z[i] = values[2*i+1]
		}
		lo, hi := emit(a, level+1), emit(z, level+1)
		if lo == hi {
			return lo
		}
		if lo == "uint1(0)" && hi == "uint1(1)" {
			return fmt.Sprintf("bit%d", level)
		}
		name := fmt.Sprintf("lookup%d", len(cache))
		cache[key] = name
		fmt.Fprintf(b, "%s := %s\nif bit%d==1 {%s=%s}\n", name, lo, level, name, hi)
		return name
	}
	for col, table := range [][64]uint32{bases, differences} {
		name := []string{"v0", "d0"}[col]
		fmt.Fprintf(b, "%s := uint32(0)\n", name)
		for bit := 0; bit < 32; bit++ {
			values := make([]uint32, 64)
			for i, v := range table {
				values[i] = (v >> bit) & 1
			}
			value := emit(values, 0)
			if value != "uint1(0)" {
				fmt.Fprintf(b, "%s = %s | (uint32(%s) << %d)\n", name, name, value, bit)
			}
		}
	}
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
			fmt.Fprintf(&b, "good%d:=(live%d==0 || live%d==1) && (event%d==0 || event%d==1) && (end%d==0 || end%d==1)\nif live%d==1 {good%d=good%d && eta%d>=-int64(524288) && eta%d<=524288}\nok=ok && good%d\nif !good%d || live%d!=1 {eta%d=0\nevent%d=0\nlive%d=0}\n", r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r)
			fmt.Fprintf(&b, "w%d:=int64(coxexp(int32(eta%d)))\nif live%d==1 {risk=risk+w%d}\nz%d:=uint64(1048576)\nif end%d==1 && risk>0 {z%d=uint64(risk)}\nh%d:=int64(coxlogrisk(z%d))\n", r, r, r, r, r, r, r, r, r)
			values = append(values, fmt.Sprintf("eta%d", r), fmt.Sprintf("event%d", r), fmt.Sprintf("end%d", r), fmt.Sprintf("h%d", r))
		}
		fmt.Fprintf(&b, "ok=ok && risk<=%d\n", maxRisk)
		if chunk.Start+n == intNextPowerOfTwo(s.Capacity) {
			fmt.Fprintf(&b, "ok=ok && end%d==1\n", n-1)
		}
		values = append(values, "risk")
	} else {
		fmt.Fprintf(&b, "h:=g[%d]+e[%d]\nloss:=g[%d]+e[%d]\nok=ok && h>=-int64(9437184) && h<=18874368 && loss>=-int64(%d) && loss<=%d\nif !ok {h=0\nloss=0}\n", 4*n, 4*n, 4*n+1, 4*n+1, bound, bound)
		for r := n - 1; r >= 0; r-- {
			for col, name := range []string{"eta", "event", "end", "logrisk"} {
				fmt.Fprintf(&b, "%s%d:=g[%d]+e[%d]\n", name, r, 4*r+col, 4*r+col)
			}
			fmt.Fprintf(&b, "good%d:=eta%d>=-int64(524288) && eta%d<=524288 && (event%d==0 || event%d==1) && (end%d==0 || end%d==1) && logrisk%d>=-int64(9437184) && logrisk%d<=18874368\nok=ok && good%d\nif !good%d {eta%d=0\nevent%d=0\nend%d=0\nlogrisk%d=0}\nif end%d==1 {h=logrisk%d}\nif event%d==1 {loss=loss+h-(eta%d << 4)}\n", r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r)
		}
		fmt.Fprintf(&b, "ok=ok && loss>=-int64(%d) && loss<=%d\n", bound, bound)
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
 ok:=g[1]+e[1]==1 && loss>=-int64(%d) && loss<=%d
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
	program, err := coxLossCompileSource(source, width, g, e, out)
	if err != nil {
		return nil, coxLossError()
	}
	return program, nil
}

// Family-local compiler options: standard backend dead-gate pruning and array
// multiplication. No shared primitive, protocol or circuit limits are changed.
// The signed numeric contract pins this compiler profile alongside the source.
func coxLossCompileSource(source string, bits, g, e, out int) (program *primitiveVProgram, failure error) {
	defer func() {
		if recover() != nil {
			program = nil
			failure = coxLossError()
		}
	}()
	if len(source) == 0 || len(source) > 2<<20 || bits < 2 || bits > 128 || g <= out || e < 1 || out < 1 ||
		g > exactGCMaxCircuitTypeBits/bits || e > exactGCMaxCircuitTypeBits/bits || out > exactGCMaxCircuitTypeBits/bits {
		return nil, coxLossError()
	}
	params := utils.NewParams()
	params.OptPruneGates = true
	params.CircMultArrayTreshold = 128
	c, _, err := compiler.New(params).Compile(source, nil)
	if err != nil || c == nil || len(c.Inputs) != 2 || int(c.Inputs[0].Type.Bits) != g*bits || int(c.Inputs[1].Type.Bits) != e*bits || c.Outputs.Size() != out*bits || c.NumGates > 32000000 {
		return nil, coxLossError()
	}
	return &primitiveVProgram{c, sha256.Sum256([]byte(source)), bits, g, e, out}, nil
}
