package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"testing"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
)

func primitiveVPermutationCheck(t testing.TB, permutation []int, columns int) {
	t.Helper()
	controls, err := primitiveVPermutationControls(permutation)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := primitiveVPermutationShape(len(permutation), columns, 192)
	if err != nil || len(controls) != cost.Switches {
		t.Fatal("permutation control shape mismatch")
	}
	values := make([]int, cost.PaddedRows*columns)
	for i := range values {
		values[i] = i
	}
	index := 0
	primitiveVWalkBenes(cost.PaddedRows, 0, 1, func(a, b int) {
		if controls[index] {
			for column := 0; column < columns; column++ {
				left, right := a*columns+column, b*columns+column
				values[left], values[right] = values[right], values[left]
			}
		}
		index++
	})
	for row := 0; row < cost.PaddedRows; row++ {
		source := row
		if row < len(permutation) {
			source = permutation[row]
		}
		for column := 0; column < columns; column++ {
			if values[row*columns+column] != source*columns+column {
				t.Fatalf("permutation mismatch at public row %d column %d", row, column)
			}
		}
	}
}

func TestPrimitiveVPermutationExhaustive(t *testing.T) {
	count := 0
	for n := 1; n <= 8; n++ {
		permutation := make([]int, n)
		for i := range permutation {
			permutation[i] = i
		}
		var visit func(int)
		visit = func(index int) {
			if index == n {
				primitiveVPermutationCheck(t, permutation, 3)
				count++
				return
			}
			for i := index; i < n; i++ {
				permutation[index], permutation[i] = permutation[i], permutation[index]
				visit(index + 1)
				permutation[index], permutation[i] = permutation[i], permutation[index]
			}
		}
		visit(0)
	}
	t.Logf("exhaustive permutations checked: %d", count)
}

func TestPrimitiveVPermutationRandomPaddedRecords(t *testing.T) {
	rng := rand.New(rand.NewSource(20260918))
	for _, n := range []int{9, 17, 31, 64, 127, 255, 512, 1025, 10000} {
		for sample := 0; sample < 12; sample++ {
			primitiveVPermutationCheck(t, rng.Perm(n), 5)
		}
	}
}

func primitiveVPermutationTestCompile(t testing.TB, rows, columns, width int, signed bool) (*circuit.Circuit, primitiveVPermutationCost) {
	t.Helper()
	cost, err := primitiveVPermutationShape(rows, columns, width)
	if err != nil {
		t.Fatal(err)
	}
	word := fmt.Sprintf("uint%d", width)
	if signed {
		word = fmt.Sprintf("int%d", width)
	}
	var source strings.Builder
	fmt.Fprintf(&source, "package main\nfunc main(values [%d]%s, controls [%d]bool) [%d]%s {\n",
		cost.PaddedRows*columns, word, max(1, cost.ControlBits), cost.PaddedRows*columns, word)
	if err := primitiveVEmitPermutation(&source, rows, columns, width, "values", "controls"); err != nil {
		t.Fatal(err)
	}
	source.WriteString("return values\n}\n")
	circ, _, err := compiler.New(utils.NewParams()).Compile(source.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return circ, cost
}

func TestPrimitiveVPermutationCompiledEqualityAndGateBound(t *testing.T) {
	rng := rand.New(rand.NewSource(71029))
	for _, test := range []struct {
		rows, columns, width int
		signed               bool
	}{{1, 1, 8, false}, {2, 3, 8, false}, {3, 2, 63, false},
		{4, 1, 128, false}, {5, 3, 192, true}, {8, 2, 192, true}, {17, 1, 16, true}} {
		t.Run(fmt.Sprintf("n%d_c%d_w%d", test.rows, test.columns, test.width), func(t *testing.T) {
			circ, cost := primitiveVPermutationTestCompile(t, test.rows, test.columns, test.width, test.signed)
			// Include the compiler's constant setup and possible passthrough
			// output copies separately from the fixed switch-only model.
			if circ.Stats[circuit.AND] > cost.AndGates+1 || circ.Stats.NumXOR() > cost.XorGates+uint64(cost.PaddedRows*cost.WordBits)+1 {
				t.Fatalf("compiled gate bound exceeded: %s, model %+v", circ.Stats, cost)
			}
			for sample := 0; sample < 16; sample++ {
				permutation := rng.Perm(test.rows)
				controls, err := primitiveVPermutationControls(permutation)
				if err != nil {
					t.Fatal(err)
				}
				inputs := make([]*big.Int, cost.PaddedRows*test.columns+max(1, len(controls)))
				for i := 0; i < cost.PaddedRows*test.columns; i++ {
					inputs[i] = new(big.Int).Rand(rng, exactGCModulus(test.width))
				}
				for i := 0; i < max(1, len(controls)); i++ {
					inputs[cost.PaddedRows*test.columns+i] = new(big.Int)
					if i < len(controls) && controls[i] {
						inputs[cost.PaddedRows*test.columns+i].SetInt64(1)
					}
				}
				got, err := circ.Compute([]*big.Int{
					exactGCPackChunks(inputs[:cost.PaddedRows*test.columns], test.width),
					exactGCPackChunks(inputs[cost.PaddedRows*test.columns:], 1),
				})
				if err != nil {
					t.Fatal(err)
				}
				for row := 0; row < cost.PaddedRows; row++ {
					source := row
					if row < test.rows {
						source = permutation[row]
					}
					for column := 0; column < test.columns; column++ {
						value := new(big.Int).Rsh(new(big.Int).Set(got[0]), uint((row*test.columns+column)*test.width))
						value.And(value, exactGCMask(test.width))
						if value.Cmp(inputs[source*test.columns+column]) != 0 {
							t.Fatal("compiled permutation differs from plaintext reference")
						}
					}
				}
			}
			t.Logf("switches=%d AND=%d XOR=%d", cost.Switches, circ.Stats[circuit.AND], circ.Stats.NumXOR())
		})
	}
}

func TestPrimitiveVPermutationRejectsInvalid(t *testing.T) {
	for _, permutation := range [][]int{nil, {}, {-1}, {1}, {0, 0}, {2, 0}, {1, 2, 3}} {
		_, err := primitiveVPermutationControls(permutation)
		if err == nil || err.Error() != "primitive-v: invalid permutation" {
			t.Fatal("invalid private permutation did not fail with fixed error")
		}
	}
	for _, shape := range [][3]int{{0, 1, 64}, {1 << 21, 1, 64}, {1, 0, 64}, {1, 4097, 64}, {1, 1, 0}, {1, 1, 4097}} {
		if _, err := primitiveVPermutationShape(shape[0], shape[1], shape[2]); err == nil {
			t.Fatal("invalid public shape accepted")
		}
	}
	for _, name := range []string{"", "g.Values", "values[0]", "1values", "x; return x", "été"} {
		var source strings.Builder
		if primitiveVEmitPermutation(&source, 4, 1, 64, name, "controls") == nil || source.Len() != 0 {
			t.Fatal("invalid source identifier accepted or partially emitted")
		}
	}
}

func TestPrimitiveVPermutationCostAtTarget(t *testing.T) {
	for _, columns := range []int{1, 2, 10, 20} {
		cost, err := primitiveVPermutationShape(10000, columns, 192)
		if err != nil || cost.PaddedRows != 16384 || cost.Switches != 221184 ||
			cost.AndGates != uint64(42467328*columns) || cost.XorGates != 5*cost.AndGates {
			t.Fatal("target analytic cost mismatch")
		}
		t.Logf("n=10000 columns=%d word_bits=192 padded=%d controls=%d AND=%d XOR=%d",
			columns, cost.PaddedRows, cost.ControlBits, cost.AndGates, cost.XorGates)
	}
}

func BenchmarkPrimitiveVPermutationControls10000(b *testing.B) {
	permutation := rand.New(rand.NewSource(18)).Perm(10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := primitiveVPermutationControls(permutation); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrimitiveVPermutationCompile32x3x192(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		primitiveVPermutationTestCompile(b, 32, 3, 192, true)
	}
}
