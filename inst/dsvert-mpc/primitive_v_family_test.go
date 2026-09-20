package main

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
)

func primitiveVFamilyTestCompile(t testing.TB, spec primitiveVFamilySpec) (*circuit.Circuit, primitiveVFamilyShape) {
	t.Helper()
	shape, err := primitiveVFamilyInputShape(spec)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	program, err := primitiveVCompileFamily(spec)
	if err != nil {
		t.Fatal(err)
	}
	c := program.Circuit
	t.Logf("family=%s rows=%d gates=%d AND=%d compile=%s table_bytes=%d", spec.Family, spec.Rows, c.NumGates, c.Stats[circuit.AND], time.Since(start), primitiveVTableBytes(c))
	return c, shape
}

func primitiveVFamilyTestInputs(t testing.TB, spec primitiveVFamilySpec, values []*big.Int, live, response, starts []bool, perm []int) ([]*big.Int, []*big.Int) {
	t.Helper()
	shape, err := primitiveVFamilyInputShape(spec)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7493))
	g, e := make([]*big.Int, shape.InputWordsG), make([]*big.Int, shape.InputWordsE)
	for i := range g {
		g[i] = new(big.Int)
	}
	for i := range e {
		e[i] = new(big.Int)
	}
	for i := 0; i < spec.Rows; i++ {
		row := []*big.Int{new(big.Int).Mod(new(big.Int).Set(values[i]), exactGCModulus(192)), new(big.Int), new(big.Int)}
		if live[i] {
			row[1].SetInt64(1)
		}
		if response[i] {
			row[2].SetInt64(1)
		}
		for j := 0; j < 3; j++ {
			g[3*i+j].Rand(rng, exactGCModulus(192))
			e[3*i+j].Sub(row[j], g[3*i+j]).Mod(e[3*i+j], exactGCModulus(192))
		}
	}
	for i, v := range starts {
		if v {
			g[shape.BoundaryOffset+i].SetInt64(1)
		}
	}
	controls, err := primitiveVPermutationControls(perm)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range controls {
		if v {
			g[shape.ControlOffset+i].SetInt64(1)
		}
	}
	g[shape.MaskOffset].Rand(rng, exactGCModulus(192))
	g[shape.MaskOffset+1].Rand(rng, exactGCModulus(192))
	return g, e
}

func primitiveVFamilyTestCompute(t testing.TB, c *circuit.Circuit, shape primitiveVFamilyShape, g, e []*big.Int) (*big.Int, bool) {
	t.Helper()
	got, err := c.Compute([]*big.Int{exactGCPackChunks(g, 192), exactGCPackChunks(e, 192)})
	if err != nil {
		t.Fatal(err)
	}
	outputs := make([]*big.Int, 2)
	for i := range outputs {
		outputs[i] = new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(got[0]), uint(192*i)), exactGCMask(192))
		outputs[i].Add(outputs[i], g[shape.MaskOffset+i]).Mod(outputs[i], exactGCModulus(192))
	}
	if outputs[0].Bit(191) == 1 {
		outputs[0].Sub(outputs[0], exactGCModulus(192))
	}
	if outputs[1].Cmp(big.NewInt(1)) > 0 {
		t.Fatal("invalid secret validity output")
	}
	return outputs[0], outputs[1].Sign() == 1
}

func TestPrimitiveVFamilyCircuitEquality(t *testing.T) {
	for _, spec := range []primitiveVFamilySpec{
		{Family: primitiveVCox, Rows: 2, Cap: 4, GroupCap: 2},
		{Family: primitiveVLMM, Rows: 3, Cap: 4, GroupCap: 3, RhoQ64: new(big.Int).Rsh(new(big.Int).Set(primitiveVScale), 1)},
		{Family: primitiveVGLMM, Rows: 2, Cap: 4, GroupCap: 2},
	} {
		t.Run(spec.Family, func(t *testing.T) {
			c, shape := primitiveVFamilyTestCompile(t, spec)
			rng := rand.New(rand.NewSource(12521))
			for trial := 0; trial < 6; trial++ {
				values := make([]*big.Int, spec.Rows)
				live, response := make([]bool, spec.Rows), make([]bool, spec.Rows)
				starts := make([]bool, shape.PaddedRows)
				starts[0] = true
				for i := range values {
					values[i] = new(big.Int).Lsh(big.NewInt(int64(rng.Intn(25)-12)), 62)
					live[i] = trial != 5 && (trial != 2 || i != 0)
					response[i] = trial < 2 || rng.Intn(2) == 1
					if i > 0 {
						starts[i] = trial != 0 && rng.Intn(2) == 1
					}
				}
				perm := rng.Perm(spec.Rows)
				g, e := primitiveVFamilyTestInputs(t, spec, values, live, response, starts, perm)
				want, valid, err := primitiveVFamilyReference(spec, values, live, response, starts, perm)
				if err != nil {
					t.Fatal(err)
				}
				got, gotValid := primitiveVFamilyTestCompute(t, c, shape, g, e)
				if got.Cmp(want) != 0 || gotValid != valid {
					t.Fatalf("synthetic integer disagreement: family=%s trial=%d got=%s want=%s valid=%v/%v", spec.Family, trial, got, want, gotValid, valid)
				}
				if trial == 0 {
					// A private noncanonical boundary invalidates both shared outputs;
					// it never becomes a plaintext status or a value-bearing error.
					g[shape.BoundaryOffset].SetInt64(2)
					got, gotValid = primitiveVFamilyTestCompute(t, c, shape, g, e)
					if gotValid || got.Sign() != 0 {
						t.Fatal("private malformed boundary accepted")
					}
					g[shape.BoundaryOffset].SetInt64(1)
					// Reconstruct a value outside the signed cap without changing
					// the public shape or evaluating unsafe nonlinear arithmetic.
					tooLarge := new(big.Int).Lsh(big.NewInt(spec.Cap+1), 64)
					e[0].Sub(tooLarge, g[0]).Mod(e[0], exactGCModulus(192))
					got, gotValid = primitiveVFamilyTestCompute(t, c, shape, g, e)
					if gotValid || got.Sign() != 0 {
						t.Fatal("private value cap exceeded")
					}
				}
			}
		})
	}
}

func TestPrimitiveVFamilyPlaintextTargetsAndBreslowTies(t *testing.T) {
	q := func(x int64) *big.Int { return new(big.Int).Lsh(big.NewInt(x), 64) }
	natural := func(x *big.Int) float64 { v, _ := new(big.Rat).SetFrac(x, primitiveVScale).Float64(); return v }
	cox := primitiveVFamilySpec{Family: primitiveVCox, Rows: 3, Cap: 4, GroupCap: 3}
	values := []*big.Int{q(1), q(-1), q(0)}
	live, response, starts := []bool{true, true, false}, []bool{true, true, true}, []bool{true, false, false, false}
	loss, ok, err := primitiveVFamilyReference(cox, values, live, response, starts, []int{1, 0, 2})
	want := -2 * math.Log(math.Exp(1)+math.Exp(-1))
	if err != nil || !ok || math.Abs(natural(loss)-want) > 1e-10 {
		t.Fatal("Breslow denominator must include all tied live rows and exclude padding")
	}
	lmm := primitiveVFamilySpec{Family: primitiveVLMM, Rows: 3, Cap: 4, GroupCap: 3, RhoQ64: q(1)}
	loss, ok, err = primitiveVFamilyReference(lmm, []*big.Int{q(1), q(2), q(3)}, []bool{true, true, true}, []bool{false, false, false}, []bool{true, false, true, false}, []int{0, 1, 2})
	if err != nil || !ok || math.Abs(natural(loss)-6.5) > 1e-15 {
		t.Fatal("LMM target disagrees")
	}
	glmm := primitiveVFamilySpec{Family: primitiveVGLMM, Rows: 1, Cap: 4, GroupCap: 1}
	for _, outcome := range []bool{false, true} {
		loss, ok, err = primitiveVFamilyReference(glmm, []*big.Int{q(0)}, []bool{true}, []bool{outcome}, []bool{true}, []int{0})
		if err != nil || !ok || math.Abs(natural(loss)-math.Log(2)) > 1e-10 {
			t.Fatal("symmetric Bernoulli random-intercept quadrature disagrees")
		}
	}
	nodes, weights := primitiveVGH5()
	sum := new(big.Int)
	for i := range weights {
		if weights[i].Sign() <= 0 || nodes[i].Cmp(new(big.Int).Neg(nodes[4-i])) != 0 {
			t.Fatal("quadrature invalid")
		}
		sum.Add(sum, weights[i])
	}
	if sum.Cmp(primitiveVScale) != 0 {
		t.Fatal("quadrature weights not exactly normalized")
	}
}

func TestPrimitiveVFamilyFailClosed(t *testing.T) {
	q := func(x int64) *big.Int { return new(big.Int).Lsh(big.NewInt(x), 64) }
	for _, spec := range []primitiveVFamilySpec{{Family: primitiveVCox, Rows: 2, Cap: 1, GroupCap: 1}, {Family: primitiveVLMM, Rows: 2, Cap: 1, GroupCap: 1, RhoQ64: q(1)}, {Family: primitiveVGLMM, Rows: 2, Cap: 1, GroupCap: 1}} {
		for _, values := range [][]*big.Int{{q(0), q(0)}, {q(2), q(0)}} {
			loss, valid, err := primitiveVFamilyReference(spec, values, []bool{true, true}, []bool{true, false}, []bool{true, false}, []int{0, 1})
			if err != nil || valid || loss.Sign() != 0 {
				t.Fatal("private bound failure accepted")
			}
		}
	}
	bad := []primitiveVFamilySpec{{Family: primitiveVCox, Rows: 0, Cap: 1, GroupCap: 1}, {Family: primitiveVGLMM, Rows: 1, Cap: 15, GroupCap: 1}, {Family: primitiveVLMM, Rows: 1, Cap: 1, GroupCap: 1, RhoQ64: q(-1)}}
	for _, spec := range bad {
		if _, err := primitiveVFamilyCircuitSource(spec); err == nil {
			t.Fatal("invalid public family specification accepted")
		}
	}
}

// These public constants exercise the pinned compiler's negative multiword
// cast pitfall independently of family data, permutation, and numeric helpers.
func TestPrimitiveVFamilySignedLiterals(t *testing.T) {
	values := []*big.Int{new(big.Int), new(big.Int).Lsh(big.NewInt(4), 64), new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(4), 64)), primitiveVFamilyInteger("-52701794672174073167")}
	for _, v := range values {
		source := fmt.Sprintf("package main\nfunc main(g [2]int192,e [1]int192) [1]int192 {\nvar out [1]int192\nout[0]=%s+g[0]+e[0]-g[1]\nreturn out\n}\n", primitiveVFamilyLiteral(v))
		program, err := primitiveVCompile(source, 192, 2, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		got, err := program.Circuit.Compute([]*big.Int{new(big.Int), new(big.Int)})
		if err != nil {
			t.Fatal(err)
		}
		want := new(big.Int).Mod(new(big.Int).Set(v), exactGCModulus(192))
		if got[0].Cmp(want) != 0 {
			t.Fatal("public signed multiword literal changed sign")
		}
	}
}
