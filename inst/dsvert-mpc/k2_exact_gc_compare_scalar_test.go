package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
)

// Preserve the previous array-branch source as an independent regression oracle.
func TestExactGCCompareScalarMatchesArrayBranch(t *testing.T) {
	rng := rand.New(rand.NewSource(20260918))
	for _, width := range []int{7, 63, 127} {
		for _, threshold := range []int64{-2, 0, 2} {
			spec := exactGCCircuitSpec{Operation: exactGCCompareSigned, RingBits: width,
				VectorLen: 8, Threshold: big.NewInt(threshold)}
			u := fmt.Sprintf("uint%d", exactGCTypeBits(width))
			mask := exactGCMask(width).Text(16)
			sign := new(big.Int).Lsh(big.NewInt(1), uint(width-1)).Text(16)
			residue := new(big.Int).Mod(big.NewInt(threshold), exactGCModulus(width))
			op := "||"
			if threshold < 0 {
				op = "&&"
			}
			oldSource := fmt.Sprintf(`package main
func main(g [16]%s, e [8]%s) [8]%s {
 var out [8]%s
 var x [8]%s
 for i:=0; i<8; i++ {
  x[i]=(g[i]+e[i]) & %s(0x%s)
  out[i]=(%s(0)-g[8+i]) & %s(0x%s)
  if ((x[i] & %s(0x%s))!=0) %s x[i]<%s(%s) { out[i]=(%s(1)-g[8+i]) & %s(0x%s) }
 }
 return out
}`, u, u, u, u, u, u, mask, u, u, mask, u, sign, op, u, residue.String(), u, u, mask)
			old, _, err := compiler.New(utils.NewParams()).Compile(oldSource, nil)
			if err != nil {
				t.Fatal(err)
			}
			current, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatal(err)
			}
			for trial := 0; trial < 20; trial++ {
				a, b, masks := make([]*big.Int, 8), make([]*big.Int, 8), make([]*big.Int, 8)
				for i := range a {
					a[i] = exactGCTestRandomResidue(rng, width)
					b[i] = exactGCTestRandomResidue(rng, width)
					masks[i] = exactGCTestRandomResidue(rng, width)
				}
				inputs := []*big.Int{exactGCPackGarblerInput(a, masks, spec), exactGCPackChunks(b, exactGCTypeBits(width))}
				want, err := old.Compute(inputs)
				if err != nil {
					t.Fatal(err)
				}
				got, err := current.Compute(inputs)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 || len(want) != 1 || got[0].Cmp(want[0]) != 0 {
					t.Fatal("scalar comparison changed masked output")
				}
			}
		}
	}
}

func TestExactGCComparePSICapacityCompile(t *testing.T) {
	if os.Getenv("DSVERT_COMPARE_CAPACITY") != "1" {
		t.Skip("explicit public capacity measurement")
	}
	oversize := exactGCCircuitSpec{Operation: exactGCCompareSigned, RingBits: 63, VectorLen: 4096, Threshold: big.NewInt(2)}
	if oversize.validate() == nil {
		t.Fatal("the fixed typed-input cap was weakened")
	}
	for _, n := range []int{2048} {
		start := time.Now()
		c, err := exactGCCompileCircuit(exactGCCircuitSpec{Operation: exactGCCompareSigned, RingBits: 63, VectorLen: n, Threshold: big.NewInt(2)})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("public PSI comparison n=%d gates=%d compile_seconds=%.3f", n, len(c.Gates), time.Since(start).Seconds())
	}
}
