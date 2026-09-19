package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"testing"
)

func primitiveVTestReductionProgram(t *testing.T, n int, lse bool) *primitiveVProgram {
	t.Helper()
	outputs := 6*n + 1
	if lse {
		outputs = n + 1
	}
	var s strings.Builder
	s.WriteString("package main\n" + primitiveVNumericSource())
	fmt.Fprintf(&s, "func main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid := true\n", 2*n+outputs, n, outputs, outputs)
	values, bits := make([]string, n), make([]string, n)
	for i := 0; i < n; i++ {
		values[i] = fmt.Sprintf("x%d", i)
		bits[i] = fmt.Sprintf("(g[%d]==1)", n+i)
		fmt.Fprintf(&s, "%s := g[%d]+e[%d]\nif g[%d] != 0 && g[%d] != 1 { valid=false }\n", values[i], i, i, n+i, n+i)
		if !lse {
			fmt.Fprintf(&s, "if %s < -int192(309485009821345068724781056) || %s > int192(309485009821345068724781056) { valid=false\n %s=0 }\n", values[i], values[i], values[i])
		}
	}
	var expressions []string
	if lse {
		r := primitiveVEmitPrefixLogSumExp(&s, "p", values, bits)
		expressions = r.PrefixLSE
		fmt.Fprintf(&s, "valid = valid && %s\n", r.Valid)
	} else {
		r := primitiveVEmitSegmentedReduce(&s, "r", values, bits)
		for _, v := range [][]string{r.Prefix, r.SegmentPrefix, r.SegmentSquarePrefix, r.SegmentSums, r.SegmentSquares, r.SegmentCounts} {
			expressions = append(expressions, v...)
		}
		fmt.Fprintf(&s, "valid = valid && %s\n", r.Valid)
	}
	for i, expression := range expressions {
		fmt.Fprintf(&s, "v%d := %s\nif !valid {v%d=0}\nout[%d]=v%d-g[%d]\n", i, expression, i, i, i, 2*n+i)
	}
	fmt.Fprintf(&s, "v := int192(0)\nif valid {v=1}\nout[%d]=v-g[%d]\nreturn out\n}\n", outputs-1, 2*n+outputs-1)
	p, err := primitiveVCompile(s.String(), 192, 2*n+outputs, n, outputs)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrimitiveVSegmentedReduceCircuitEquality(t *testing.T) {
	const n = 4
	p := primitiveVTestReductionProgram(t, n, false)
	rng := rand.New(rand.NewSource(817))
	for sample := 0; sample < 30; sample++ {
		values := make([]*big.Int, n)
		starts := make([]bool, n)
		g := make([]*big.Int, 2*n+p.OutputWords)
		e := make([]*big.Int, n)
		for i := range g {
			g[i] = new(big.Int)
		}
		for i := range values {
			values[i] = new(big.Int).Add(new(big.Int).Mul(big.NewInt(int64(rng.Intn(9)-4)), primitiveVScale), big.NewInt(int64(rng.Intn(17)-8)))
			starts[i] = i == 0 || rng.Intn(2) == 1
			e[i] = new(big.Int).SetUint64(rng.Uint64())
			g[i] = new(big.Int).Sub(values[i], e[i])
			if starts[i] {
				g[n+i].SetInt64(1)
			}
		}
		want, err := primitiveVSegmentedReduceReference(values, starts)
		if err != nil {
			t.Fatal(err)
		}
		var expected []*big.Int
		for _, v := range [][]*big.Int{want.Prefix, want.SegmentPrefix, want.SegmentSquarePrefix, want.SegmentSums, want.SegmentSquares} {
			expected = append(expected, v...)
		}
		for _, c := range want.SegmentCounts {
			expected = append(expected, big.NewInt(int64(c)))
		}
		expected = append(expected, big.NewInt(1))
		got := primitiveVTestCompute(t, p, g, e)
		for i := range expected {
			if got[i].Cmp(expected[i]) != 0 {
				t.Fatal("segmented circuit differs from plaintext reference")
			}
		}
		// First boundary, bit canonicality, and magnitude failures mask all outputs.
		for _, fault := range []int{0, 1, 2} {
			bad := make([]*big.Int, len(g))
			for i, v := range g {
				bad[i] = new(big.Int).Set(v)
			}
			switch fault {
			case 0:
				bad[n].SetInt64(0)
			case 1:
				bad[n+2].SetInt64(2)
			case 2:
				bad[0].Lsh(big.NewInt(1), 90)
			}
			rejected := primitiveVTestCompute(t, p, bad, e)
			for _, v := range rejected {
				if v.Sign() != 0 {
					t.Fatal("invalid private reduction was not masked")
				}
			}
		}
	}
}

func TestPrimitiveVPrefixLogSumExpCircuitEquality(t *testing.T) {
	const n = 3
	p := primitiveVTestReductionProgram(t, n, true)
	for _, sample := range []struct {
		eta  []int64
		live []bool
	}{
		{[]int64{-17, -17, -17}, []bool{true, true, true}},
		{[]int64{17, 0, -17}, []bool{true, true, true}},
		{[]int64{0, 4, -2}, []bool{false, true, false}},
		{[]int64{0, 0, 0}, []bool{false, false, false}},
	} {
		g := make([]*big.Int, 2*n+p.OutputWords)
		e := make([]*big.Int, n)
		values := make([]*big.Int, n)
		for i := range g {
			g[i] = new(big.Int)
		}
		for i, v := range sample.eta {
			values[i] = new(big.Int).Mul(big.NewInt(v), primitiveVScale)
			g[i] = values[i]
			e[i] = new(big.Int)
			if sample.live[i] {
				g[n+i].SetInt64(1)
			}
		}
		want, err := primitiveVPrefixLogSumExpReference(values, sample.live)
		if err != nil {
			t.Fatal(err)
		}
		got := primitiveVTestCompute(t, p, g, e)
		for i := range want {
			if got[i].Cmp(want[i]) != 0 {
				t.Fatal("prefix LSE circuit differs")
			}
		}
		if got[n].Int64() != 1 {
			t.Fatal("valid prefix rejected")
		}
		g[0] = new(big.Int).Mul(big.NewInt(18), primitiveVScale)
		for _, v := range primitiveVTestCompute(t, p, g, e) {
			if v.Sign() != 0 {
				t.Fatal("invalid eta not masked")
			}
		}
	}
}

func TestPrimitiveVReduceShapeAndLargePrefix(t *testing.T) {
	if _, err := primitiveVSegmentedReduceReference(nil, nil); err == nil {
		t.Fatal("empty admitted")
	}
	if _, err := primitiveVSegmentedReduceReference([]*big.Int{big.NewInt(0)}, []bool{false}); err == nil {
		t.Fatal("missing boundary admitted")
	}
	if _, err := primitiveVPrefixLogSumExpReference([]*big.Int{big.NewInt(0)}, nil); err == nil {
		t.Fatal("shape admitted")
	}
	values := make([]*big.Int, 10000)
	live := make([]bool, len(values))
	for i := range values {
		values[i] = new(big.Int).Mul(big.NewInt(-17), primitiveVScale)
		live[i] = true
	}
	got, err := primitiveVPrefixLogSumExpReference(values, live)
	if err != nil {
		t.Fatal(err)
	}
	expected := crossGridHighV1().Sub(primitiveVHighLog(new(big.Int).Mul(big.NewInt(10000), primitiveVScale)), crossGridHighV1().SetInt64(17))
	actual := crossGridHighV1().Quo(crossGridHighV1().SetInt(got[len(got)-1]), crossGridHighV1().SetInt(primitiveVScale))
	delta, _ := crossGridHighV1().Abs(crossGridHighV1().Sub(actual, expected)).Float64()
	if delta >= 7.1e-13 {
		t.Fatal("large prefix certificate failed")
	}
}
