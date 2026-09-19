package main

// Worked family circuits are internal composition targets, not release routes.
// Every output, including the validity bit, remains additively shared.
import (
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"strings"
)

const (
	primitiveVCox  = "cox_breslow"
	primitiveVLMM  = "lmm_random_intercept"
	primitiveVGLMM = "binomial_glmm_gh5"
)

type primitiveVFamilySpec struct {
	Family   string
	Rows     int
	Cap      int64    // signed candidate cap on |eta|, or |residual| for LMM
	GroupCap int      // public upper bound; actual group count and sizes are private
	RhoQ64   *big.Int // LMM only; public candidate-signed variance ratio
}

type primitiveVFamilyShape struct {
	InputWordsG, InputWordsE, OutputWords, WordBits       int
	PaddedRows, BoundaryOffset, ControlOffset, MaskOffset int
}

func primitiveVFamilyInputShape(spec primitiveVFamilySpec) (primitiveVFamilyShape, error) {
	bad := errors.New("primitive-v: family specification rejected")
	if spec.Rows < 1 || spec.Rows > 10000 || spec.Cap < 1 || spec.Cap > 17 || spec.GroupCap < 1 || spec.GroupCap > spec.Rows {
		return primitiveVFamilyShape{}, bad
	}
	switch spec.Family {
	case primitiveVCox:
		if spec.RhoQ64 != nil {
			return primitiveVFamilyShape{}, bad
		}
	case primitiveVLMM:
		if spec.RhoQ64 == nil || spec.RhoQ64.Sign() < 0 || spec.RhoQ64.Cmp(new(big.Int).Lsh(big.NewInt(16), 64)) > 0 {
			return primitiveVFamilyShape{}, bad
		}
	case primitiveVGLMM:
		if spec.RhoQ64 != nil || spec.Cap > 14 {
			return primitiveVFamilyShape{}, bad
		}
	default:
		return primitiveVFamilyShape{}, bad
	}
	network, err := primitiveVPermutationShape(spec.Rows, 3, 192)
	if err != nil {
		return primitiveVFamilyShape{}, bad
	}
	shape := primitiveVFamilyShape{InputWordsE: 3 * spec.Rows, OutputWords: 2, WordBits: 192, PaddedRows: network.PaddedRows, BoundaryOffset: 3 * spec.Rows}
	shape.ControlOffset = shape.BoundaryOffset + shape.PaddedRows
	shape.MaskOffset = shape.ControlOffset + network.ControlBits
	shape.InputWordsG = shape.MaskOffset + 2
	return shape, nil
}

func primitiveVFamilyInteger(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("primitive-v: invalid public constant")
	}
	return v
}

// The pinned MPCL cast of a negative multiword literal loses its sign.
// Emit unary negation AFTER the positive-width cast, including GH log weights.
func primitiveVFamilyLiteral(v *big.Int) string {
	if v.Sign() < 0 {
		return "-int192(" + new(big.Int).Abs(v).String() + ")"
	}
	return "int192(" + v.String() + ")"
}

// These are nearest-even q64 encodings of the five standard-normal GH nodes
// 0, +/-sqrt(5-sqrt(10)), +/-sqrt(5+sqrt(10)). The positive weights sum to 2^64
// exactly: the central weight absorbs the one-ulp normalization residual.
func primitiveVGH5() (nodes, weights []*big.Int) {
	for _, s := range []string{"-52701794672174073167", "-25006889201605806900", "0", "25006889201605806900", "52701794672174073167"} {
		nodes = append(nodes, primitiveVFamilyInteger(s))
	}
	for _, s := range []string{"207662585694942394", "4096577698170619650", "9838263505978427528", "4096577698170619650", "207662585694942394"} {
		weights = append(weights, primitiveVFamilyInteger(s))
	}
	return
}

// Layout: each custodian inputs additive Ring192 row shares [eta/r, live,
// event/y]. Garbler then inputs post-permutation start flags, Beneš controls,
// and two fresh output masks. The start flags include every padded slot.
// The permuting custodian is the garbler for these worked wrappers; kernels may
// use the in-circuit emitter with evaluator-owned control wires instead.
func primitiveVFamilyCircuitSource(spec primitiveVFamilySpec) (string, error) {
	shape, err := primitiveVFamilyInputShape(spec)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(primitiveVNumericSource())
	fmt.Fprintf(&b, "func main(g [%d]int192, e [%d]int192) [2]int192 {\n", shape.InputWordsG, shape.InputWordsE)
	fmt.Fprintf(&b, "executionValid := true\nvar values [%d]int192\n", 3*shape.PaddedRows)
	capQ := new(big.Int).Lsh(big.NewInt(spec.Cap), 64)
	for i := 0; i < spec.Rows; i++ {
		for j := 0; j < 3; j++ {
			fmt.Fprintf(&b, "values[%d] = g[%d] + e[%d]\n", 3*i+j, 3*i+j, 3*i+j)
		}
		fmt.Fprintf(&b, "rowOK%d := (values[%d] == 0 || values[%d] == 1) && (values[%d] == 0 || values[%d] == 1)\n", i, 3*i+1, 3*i+1, 3*i+2, 3*i+2)
		fmt.Fprintf(&b, "if values[%d] == 1 { rowOK%d = rowOK%d && values[%d] >= -int192(%s) && values[%d] <= int192(%s) }\n", 3*i+1, i, i, 3*i, capQ, 3*i, capQ)
		fmt.Fprintf(&b, "executionValid = executionValid && rowOK%d\nif !rowOK%d || values[%d] != 1 { values[%d] = 0\n values[%d] = 0\n values[%d] = 0 }\n", i, i, 3*i+1, 3*i, 3*i+1, 3*i+2)
	}
	network, _ := primitiveVPermutationShape(spec.Rows, 3, 192)
	// MPCL forbids zero-sized arrays; n=1 has no controls and no switches.
	if network.ControlBits > 0 {
		fmt.Fprintf(&b, "var controls [%d]bool\n", network.ControlBits)
		for i := 0; i < network.ControlBits; i++ {
			fmt.Fprintf(&b, "executionValid = executionValid && (g[%d] == 0 || g[%d] == 1)\ncontrols[%d] = g[%d] == 1\n", shape.ControlOffset+i, shape.ControlOffset+i, i, shape.ControlOffset+i)
		}
		if err := primitiveVEmitPermutation(&b, spec.Rows, 3, 192, "values", "controls"); err != nil {
			return "", err
		}
	}
	x, live, starts := make([]string, shape.PaddedRows), make([]string, shape.PaddedRows), make([]string, shape.PaddedRows)
	for i := 0; i < shape.PaddedRows; i++ {
		x[i], live[i], starts[i] = fmt.Sprintf("values[%d]", 3*i), fmt.Sprintf("values[%d] == 1", 3*i+1), fmt.Sprintf("start%d", i)
		fmt.Fprintf(&b, "executionValid = executionValid && (g[%d] == 0 || g[%d] == 1)\nstart%d := g[%d] == 1\n", shape.BoundaryOffset+i, shape.BoundaryOffset+i, i, shape.BoundaryOffset+i)
	}
	b.WriteString("executionValid = executionValid && start0\nzero := values[0]-values[0]\nloss := zero\ngroupCount := zero\n")
	for i := 0; i < shape.PaddedRows; i++ {
		fmt.Fprintf(&b, "if %s { groupCount = zero }\nif %s { groupCount = groupCount + 1 }\nexecutionValid = executionValid && groupCount <= int192(%d)\n", starts[i], live[i], spec.GroupCap)
		fmt.Fprintf(&b, "count%d := groupCount\n", i)
	}
	switch spec.Family {
	case primitiveVCox:
		lse := primitiveVEmitPrefixLogSumExp(&b, "cox", x, live)
		fmt.Fprintf(&b, "executionValid = executionValid && %s\n", lse.Valid)
		b.WriteString("eventEta := zero\neventCount := zero\n")
		for i := 0; i < shape.PaddedRows; i++ {
			fmt.Fprintf(&b, "if %s { eventEta = zero\n eventCount = zero }\nif %s && values[%d] == 1 { eventEta = eventEta + %s\n eventCount = eventCount + 1 }\n", starts[i], live[i], 3*i+2, x[i])
			tail := "true"
			if i+1 < shape.PaddedRows {
				tail = starts[i+1]
			}
			fmt.Fprintf(&b, "if %s { loss = loss + eventEta - eventCount * %s }\n", tail, lse.PrefixLSE[i])
		}
	case primitiveVLMM:
		sums := primitiveVEmitSegmentedReduce(&b, "lmm", x, starts)
		for i := 0; i < shape.PaddedRows; i++ {
			tail := "true"
			if i+1 < shape.PaddedRows {
				tail = starts[i+1]
			}
			fmt.Fprintf(&b, "square%d := primitiveVMulQ64(%s, %s)\ncorrection%d := primitiveVRoundDiv(int192(%s) * square%d, int192(18446744073709551616) + count%d * int192(%s))\ncluster%d := %s - correction%d\nif cluster%d < 0 { cluster%d = 0 }\nif cluster%d > count%d * int192(%s) { cluster%d = count%d * int192(%s) }\nif %s { loss = loss + cluster%d }\n", i, sums.SegmentPrefix[i], sums.SegmentPrefix[i], i, spec.RhoQ64, i, i, spec.RhoQ64, i, sums.SegmentSquarePrefix[i], i, i, i, i, i, new(big.Int).Lsh(big.NewInt(spec.Cap*spec.Cap), 64), i, i, new(big.Int).Lsh(big.NewInt(spec.Cap*spec.Cap), 64), tail, i)
		}
	case primitiveVGLMM:
		nodes, weights := primitiveVGH5()
		scores := make([][]string, 5)
		for q := 0; q < 5; q++ {
			ll := make([]string, shape.PaddedRows)
			for i := 0; i < shape.PaddedRows; i++ {
				ll[i] = fmt.Sprintf("ll%d_%d", q, i)
				fmt.Fprintf(&b, "eta%d_%d := %s + %s\n%s := -primitiveVLogQ64(int192(18446744073709551616) + primitiveVExpQ64(eta%d_%d))\nif values[%d] == 1 { %s = %s + eta%d_%d }\nif !(%s) { %s = 0 }\n", q, i, x[i], primitiveVFamilyLiteral(nodes[q]), ll[i], q, i, 3*i+2, ll[i], ll[i], q, i, live[i], ll[i])
			}
			r := primitiveVEmitSegmentedReduce(&b, fmt.Sprintf("node%d", q), ll, starts)
			scores[q] = r.SegmentPrefix
			logw, err := primitiveVLogQ64Reference(weights[q])
			if err != nil {
				return "", errors.New("primitive-v: public quadrature rejected")
			}
			for i := 0; i < shape.PaddedRows; i++ {
				fmt.Fprintf(&b, "score%d_%d := %s + %s\n", q, i, scores[q][i], primitiveVFamilyLiteral(logw))
				scores[q][i] = fmt.Sprintf("score%d_%d", q, i)
			}
		}
		for i := 0; i < shape.PaddedRows; i++ {
			fmt.Fprintf(&b, "maximum%d := %s\n", i, scores[0][i])
			for q := 1; q < 5; q++ {
				fmt.Fprintf(&b, "if %s > maximum%d { maximum%d = %s }\n", scores[q][i], i, i, scores[q][i])
			}
			fmt.Fprintf(&b, "integral%d := int192(0)\n", i)
			for q := 0; q < 5; q++ {
				fmt.Fprintf(&b, "integral%d = integral%d + primitiveVExpNegativeQ64(%s - maximum%d)\n", i, i, scores[q][i], i)
			}
			tail := "true"
			if i+1 < shape.PaddedRows {
				tail = starts[i+1]
			}
			fmt.Fprintf(&b, "cluster%d := -maximum%d - primitiveVLogQ64(integral%d)\nif cluster%d < 0 { cluster%d = 0 }\nif cluster%d > count%d * int192(%s) { cluster%d = count%d * int192(%s) }\nif %s && count%d > 0 { loss = loss + cluster%d }\n", i, i, i, i, i, i, i, new(big.Int).Lsh(big.NewInt(spec.Cap+4), 64), i, i, new(big.Int).Lsh(big.NewInt(spec.Cap+4), 64), tail, i, i)
		}
	}
	if spec.Family == primitiveVCox {
		lower := new(big.Int).Lsh(big.NewInt(-int64(spec.Rows)*(2*spec.Cap+int64(bits.Len(uint(spec.Rows-1)))+1)), 64)
		fmt.Fprintf(&b, "if loss > 0 { loss = 0 }\nif loss < %s { loss = %s }\n", primitiveVFamilyLiteral(lower), primitiveVFamilyLiteral(lower))
	}
	fmt.Fprintf(&b, "validity := int192(0)\nif executionValid { validity = 1 } else { loss = 0 }\nvar output [2]int192\noutput[0] = loss - g[%d]\noutput[1] = validity - g[%d]\nreturn output\n}\n", shape.MaskOffset, shape.MaskOffset+1)
	return b.String(), nil
}
