package main

import (
	"fmt"
	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

// Synthetic-only reconstruction. Production retains both shares and validity.
func coxTestCompute(t *testing.T, p *primitiveVProgram, values []*big.Int, controls []bool) []*big.Int {
	t.Helper()
	rng := rand.New(rand.NewSource(814))
	g, e := make([]*big.Int, p.InputWordsG), make([]*big.Int, p.InputWordsE)
	mod := exactGCModulus(p.WordBits)
	for i := range g {
		g[i] = new(big.Int).Rand(rng, mod)
	}
	for i := range e {
		e[i] = new(big.Int).Sub(values[i], g[i])
		e[i].Mod(e[i], mod)
	}
	for i, b := range controls {
		g[len(e)+i] = new(big.Int)
		if b {
			g[len(e)+i].SetInt64(1)
		}
	}
	packed, err := p.Circuit.Compute([]*big.Int{exactGCPackChunks(g, p.WordBits), exactGCPackChunks(e, p.WordBits)})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]*big.Int, p.OutputWords)
	for i := range out {
		z := new(big.Int).Rsh(new(big.Int).Set(packed[0]), uint(i*p.WordBits))
		z.And(z, exactGCMask(p.WordBits))
		z.Add(z, g[len(g)-len(out)+i]).Mod(z, mod)
		out[i] = exactGCReferenceSigned(z, p.WordBits)
	}
	return out
}
func coxTestInts(values ...int64) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, v := range values {
		out[i] = big.NewInt(v)
	}
	return out
}
func coxTestCompile(t *testing.T, source string, w, g, e, o int) *primitiveVProgram {
	t.Helper()
	p, err := coxLossCompileSource(source, w, g, e, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bits=%d inputs=%d/%d output=%d source=%d gates=%d AND=%d tables=%d", w, g, e, o, len(source), p.Circuit.NumGates, p.Circuit.Stats[circuit.AND], primitiveVTableBytes(p.Circuit))
	return p
}
func TestCoxGridCrossCompiledProfiles(t *testing.T) {
	for _, name := range []string{"exp", "logrisk"} {
		t.Run(name, func(t *testing.T) {
			cast := "int32"
			if name == "logrisk" {
				cast = "uint64"
			}
			src := "package main\n" + coxLossProfileSource() + fmt.Sprintf("func main(g [2]int64,e [1]int64) [1]int64 {\nvar out [1]int64\nout[0]=int64(cox%s(%s(g[0]+e[0])))-g[1]\nreturn out\n}\n", name, cast)
			p := coxTestCompile(t, src, 64, 2, 1, 1)
			f := coxReadProfileFixture(t)
			if name == "exp" {
				for _, c := range f.ExpCases {
					if got := coxTestCompute(t, p, coxTestInts(int64(c.Eta)), nil)[0].Int64(); got != int64(c.Exp) {
						t.Fatalf("exp %d: %d/%d", c.Eta, got, c.Exp)
					}
				}
			} else {
				for _, c := range f.LogCases {
					if got := coxTestCompute(t, p, coxTestInts(c.Risk), nil)[0].Int64(); got != c.Log {
						t.Fatalf("log %d: %d/%d", c.Risk, got, c.Log)
					}
				}
			}
		})
	}
}
func TestCoxGridCrossPrepareRoundingAndSlack(t *testing.T) {
	src, w, g, e, o := coxLossPrepareSource(1)
	p := coxTestCompile(t, src, w, g, e, o)
	half := new(big.Int).Lsh(big.NewInt(1), 83)
	limit := new(big.Int).Lsh(big.NewInt(8), 100)
	limit.Add(limit, new(big.Int).Lsh(big.NewInt(8), 50))
	cases := []*big.Int{new(big.Int), half, new(big.Int).Mul(half, big.NewInt(3)), new(big.Int).Set(limit), new(big.Int).Add(limit, big.NewInt(1))}
	for _, x := range cases {
		for _, sign := range []int64{-1, 1} {
			v := new(big.Int).Mul(x, big.NewInt(sign))
			out := coxTestCompute(t, p, []*big.Int{v, big.NewInt(1), big.NewInt(1), big.NewInt(1)}, nil)
			if x.Cmp(limit) > 0 {
				if out[3].Sign() != 0 {
					t.Fatal("slack overflow accepted")
				}
				continue
			}
			want := primitiveVRoundDivReference(v, new(big.Int).Lsh(big.NewInt(1), 84))
			if out[0].Cmp(want) != 0 || out[3].Int64() != 1 {
				t.Fatal("joined f100 rounding differs")
			}
		}
	}
	for _, bad := range []int64{0, 2} {
		out := coxTestCompute(t, p, coxTestInts(0, 1, 1, bad), nil)
		if out[3].Sign() != 0 {
			t.Fatal("source validity bypass")
		}
	}
}
func TestCoxGridCrossChunkScheduleAndEquality(t *testing.T) {
	// 35 rows pads to 64, forcing ties and carries across forward/reverse chunks.
	n := 35
	cap, _ := coxLossCap(n, 18, []float64{4, 4})
	s := coxLossSpec{n, 1, 18, []uint64{cap}, CoxGridCrossProfileID}
	plan, err := coxLossPlan(s)
	if err != nil {
		t.Fatal(err)
	}
	programs := map[string]*primitiveVProgram{}
	for i, c := range plan.Chunks {
		key := fmt.Sprintf("%s/%d/%d", c.Kind, c.Start, c.Rows)
		programs[key], err = coxLossCompileChunk(plan, i)
		if err != nil {
			t.Fatalf("compile %s: %v", key, err)
		}
	}
	for trial := 0; trial < 6; trial++ {
		rng := rand.New(rand.NewSource(int64(529 + trial)))
		eta := make([]int32, n)
		times := make([]float64, n)
		live, event := make([]bool, n), make([]bool, n)
		rows := make([][]*big.Int, plan.PaddedRows)
		perm := rng.Perm(n)
		controls, _ := primitiveVPermutationControls(perm)
		for i := range rows {
			rows[i] = coxTestInts(0, 0, 0)
		}
		for position, i := range perm {
			eta[i] = int32(rng.Intn(1048577) - 524288)
			times[i] = float64((n - position) / 3)
			if trial == 0 {
				times[i] = 1
			}
			live[i] = trial != 5 && (trial != 3 || i%4 != 0)
			event[i] = trial != 4 && i%3 != 0
			rows[i][0].SetInt64(int64(eta[i]))
			if live[i] {
				rows[i][1].SetInt64(1)
			}
			if event[i] {
				rows[i][2].SetInt64(1)
			}
		}
		ends := make([]int64, plan.PaddedRows)
		for i := range ends {
			if i == len(ends)-1 || i == n-1 || i < n-1 && times[perm[i]] != times[perm[i+1]] {
				ends[i] = 1
			}
		}
		risk, h, loss := big.NewInt(0), big.NewInt(0), big.NewInt(0)
		for _, c := range plan.Chunks {
			p := programs[fmt.Sprintf("%s/%d/%d", c.Kind, c.Start, c.Rows)]
			switch c.Kind {
			case "prepare":
				continue // tested separately at the actual frozen f100 boundary
			case "permute":
				touched := coxLossPermutationRows(c)
				var values []*big.Int
				for _, i := range touched {
					values = append(values, rows[i]...)
				}
				values = append(values, big.NewInt(1))
				bits := make([]bool, len(c.Switches))
				for i, sw := range c.Switches {
					bits[i] = controls[sw.Control]
				}
				out := coxTestCompute(t, p, values, bits)
				if out[len(out)-1].Int64() != 1 {
					t.Fatal("permutation validity")
				}
				for k, i := range touched {
					rows[i] = out[3*k : 3*k+3]
				}
			case "forward":
				var values []*big.Int
				for i := c.Start; i < c.Start+c.Rows; i++ {
					values = append(values, rows[i]...)
					values = append(values, big.NewInt(ends[i]))
				}
				values = append(values, risk, big.NewInt(1))
				out := coxTestCompute(t, p, values, nil)
				if out[len(out)-1].Int64() != 1 {
					t.Fatalf("forward validity trial=%d start=%d risk=%s outputRisk=%s values=%v", trial, c.Start, risk, out[len(out)-2], values)
				}
				risk = out[len(out)-2]
				for k := 0; k < c.Rows; k++ {
					rows[c.Start+k] = out[4*k : 4*k+4]
				}
			case "backward":
				var values []*big.Int
				for i := c.Start; i < c.Start+c.Rows; i++ {
					values = append(values, rows[i]...)
				}
				values = append(values, h, loss, big.NewInt(1))
				out := coxTestCompute(t, p, values, nil)
				if out[2].Int64() != 1 {
					t.Fatal("backward validity")
				}
				h, loss = out[0], out[1]
			case "finalize":
				out := coxTestCompute(t, p, []*big.Int{loss, big.NewInt(1)}, nil)
				want, err := coxLossReference(eta, times, event, live, cap, 18)
				if err != nil || out[1].Int64() != 1 || out[0].Uint64() != want {
					t.Fatalf("trial %d got=%s want=%d err=%v", trial, out[0], want, err)
				}
			}
		}
	}
}
func TestCoxGridCrossScheduleTamperAndEnvelope(t *testing.T) {
	s := coxLossSpec{10000, 50, 18, make([]uint64, 50), CoxGridCrossProfileID}
	for i := range s.Caps {
		s.Caps[i], _ = coxLossCap(10000, 18, []float64{4, 4})
	}
	p, err := registerCoxGridCrossLoss().Plan(s)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := p.digest()
	if err != nil || digest == [32]byte{} {
		t.Fatal("canonical plan")
	}
	if _, err = coxLossChunkBinding(p, 1, digest, [32]byte{}); err == nil {
		t.Fatal("unbound predecessor accepted")
	}
	b, _ := coxLossChunkBinding(p, 0, digest, [32]byte{})
	b2, _ := coxLossChunkBinding(p, 1, digest, b)
	if b == b2 {
		t.Fatal("ordinal binding")
	}
	p.Chunks[0].Rows--
	if _, err = p.digest(); err == nil {
		t.Fatal("mutated schedule accepted")
	}
	s.Caps[0] = 0
	if _, err = coxLossPlan(s); err == nil {
		t.Fatal("invalid cap")
	}
	if !reflect.DeepEqual(coxLossError().Error(), "cox-grid-cross: rejected") {
		t.Fatal("error")
	}
}

func TestCoxGridCrossForwardSingleRow(t *testing.T) {
	s := coxLossSpec{35, 1, 18, []uint64{1000000000}, CoxGridCrossProfileID}
	src, w, g, e, o := coxLossScanSource(s, coxLossChunk{Kind: "forward", Rows: 1})
	p := coxTestCompile(t, src, w, g, e, o)
	for _, eta := range []int64{0, -365259, 515402, 524288, -524288} {
		out := coxTestCompute(t, p, coxTestInts(eta, 1, 1, 1, 0, 1), nil)
		expected, _ := CoxGridCrossExpProfileQ16(int32(eta))
		if out[5].Int64() != 1 || out[4].Int64() != int64(expected) {
			t.Fatalf("eta %d out=%v expectedRisk=%d", eta, out, expected)
		}
	}
}

func TestCoxGridCrossPrivatePredicates(t *testing.T) {
	src := `package main
func main(g [8]int64,e [4]int64) [4]int64 {
 eta:=g[0]+e[0]
 live:=g[1]+e[1]
 event:=g[2]+e[2]
 end:=g[3]+e[3]
 good:=(live==0 || live==1) && (event==0 || event==1) && (end==0 || end==1)
 low:=eta>=-int64(524288)
 high:=eta<=524288
 if live==1 {good=good && low && high}
 var out [4]int64
 x:=int64(0)
 if good {x=1}
 out[0]=x-g[4]
 x=0
 if low {x=1}
 out[1]=x-g[5]
 x=0
 if high {x=1}
 out[2]=x-g[6]
 out[3]=live-g[7]
 return out
}`
	p := coxTestCompile(t, src, 64, 8, 4, 4)
	out := coxTestCompute(t, p, coxTestInts(0, 1, 1, 1), nil)
	t.Logf("predicates %v", out)
	if out[0].Int64() != 1 {
		t.Fatal("valid predicate failed")
	}
}

func TestCoxGridCrossFinalizeTiesClampValidity(t *testing.T) {
	for _, bits := range []int{8, 16, 18} {
		s := coxLossSpec{2, 1, bits, []uint64{17}, CoxGridCrossProfileID}
		src, w, g, e, o := coxLossFinalizeSource(s, 0)
		p := coxTestCompile(t, src, w, g, e, o)
		scale := int64(1) << uint(20-bits)
		for _, v := range []int64{-1, 0, scale / 2, 3 * scale / 2, 5 * scale / 2, 17 * scale, 30 * scale} {
			out := coxTestCompute(t, p, coxTestInts(v, 1), nil)
			want := primitiveVRoundDivReference(big.NewInt(v), big.NewInt(scale)).Int64()
			if want < 0 {
				want = 0
			}
			if want > 17 {
				want = 17
			}
			if out[0].Int64() != want || out[1].Int64() != 1 {
				t.Fatal("round/clamp differs")
			}
		}
		for _, v := range []int64{0, 2} {
			out := coxTestCompute(t, p, coxTestInts(10, v), nil)
			if out[0].Sign() != 0 || out[1].Sign() != 0 {
				t.Fatal("invalid result released")
			}
		}
	}
}
func TestCoxGridCrossEncryptedScan(t *testing.T) {
	s := coxLossSpec{2, 1, 18, []uint64{1000000}, CoxGridCrossProfileID}
	src, w, g, e, o := coxLossScanSource(s, coxLossChunk{Kind: "forward", Rows: 2})
	p := coxTestCompile(t, src, w, g, e, o)
	values := coxTestInts(65536, 1, 1, 0, -32768, 1, 1, 1, 0, 1)
	a, b := make([]*big.Int, len(values)), make([]*big.Int, len(values))
	for i, v := range values {
		a[i] = big.NewInt(int64(154 + i))
		b[i] = new(big.Int).Sub(v, a[i])
		b[i].Mod(b[i], exactGCModulus(w))
	}
	out, bytes := primitiveVTestProtocol(t, p, a, b)
	expected := coxTestCompute(t, p, values, nil)
	for i, v := range out {
		if exactGCReferenceSigned(v, w).Cmp(expected[i]) != 0 {
			t.Fatal("encrypted forward output differs")
		}
	}
	t.Logf("encrypted forward 2-row garbler wire bytes=%d", bytes)
}
func TestCoxGridCrossMaximumChunkCaps(t *testing.T) {
	cap, _ := coxLossCap(10000, 18, []float64{4, 4})
	s := coxLossSpec{10000, 1, 18, []uint64{cap}, CoxGridCrossProfileID}
	p, _ := coxLossPlan(s)
	seen := map[string]bool{}
	for _, chunk := range p.Chunks {
		if seen[chunk.Kind] {
			continue
		}
		seen[chunk.Kind] = true
		t.Run(chunk.Kind, func(t *testing.T) {
			var src string
			var w, g, e, o int
			switch chunk.Kind {
			case "prepare":
				src, w, g, e, o = coxLossPrepareSource(32)
			case "permute":
				src, w, g, e, o = coxLossPermutationSource(chunk)
			case "forward", "backward":
				src, w, g, e, o = coxLossScanSource(s, chunk)
			case "finalize":
				src, w, g, e, o = coxLossFinalizeSource(s, 0)
			}
			program := coxTestCompile(t, src, w, g, e, o)
			if program.Circuit.NumGates > 32000000 || len(src) > 2<<20 || max(g, e)*w > 512*1024 {
				t.Fatal("runner cap exceeded")
			}
		})
	}
}

func TestCoxGridCrossScalarGateTarget(t *testing.T) {
	for _, name := range []string{"exp", "logrisk"} {
		cast := "int32"
		if name == "logrisk" {
			cast = "uint64"
		}
		src := "package main\n" + coxLossProfileSource() + fmt.Sprintf("func main(g int64,e bool) int64 {\nx:=int64(cox%s(%s(g)))\nif e {x=x^1}\nreturn x\n}\n", name, cast)
		params := utils.NewParams()
		params.OptPruneGates = true
		params.CircMultArrayTreshold = 128
		c, _, err := compiler.New(params).Compile(src, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Core count excludes the separately measured share-join and output mask.
		t.Logf("scalar %s gates=%d AND=%d nonXOR=%d tables=%d", name, c.NumGates, c.Stats[circuit.AND], c.Stats.NumNonXOR(), primitiveVTableBytes(c))
		if c.Stats.NumNonXOR() > 2000 {
			t.Errorf("scalar target exceeded: %s", name)
		}
	}
}
