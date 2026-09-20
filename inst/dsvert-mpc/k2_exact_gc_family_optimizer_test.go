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

// Retain the lane's linear table selection as an independent compiler oracle.
func integratorLegacyFamilyMathSource() string {
	source := exactGCFamilyMathSource()
	for _, p := range []struct {
		name  string
		table [64][3]int64
		shift uint
	}{{"exppoly", exactGCFamilyExpProfile, 14}, {"logpoly", exactGCFamilyLogProfile, 10}, {"softpoly", exactGCFamilySoftProfile, 14}} {
		var current, old strings.Builder
		exactGCFamilyEmitPolynomial(&current, p.name, p.table, p.shift)
		fmt.Fprintf(&old, "func %s(x uint32) uint32 {\ni:=x>>%d\nt:=x&uint32(%d)\nif i>=uint32(64) { i=uint32(63)\nt=uint32(%d) }\n", p.name, p.shift, (1<<p.shift)-1, 1<<p.shift)
		for k, row := range p.table {
			assign := ":="
			if k > 0 {
				fmt.Fprintf(&old, "if i>=uint32(%d) {\n", k)
				assign = "="
			}
			fmt.Fprintf(&old, "a%suint32(%d)\nb%suint32(%d)\nc%suint32(%d)\n", assign, uint32(row[2]), assign, uint32(row[1]), assign, uint32(row[0]))
			if k > 0 {
				old.WriteString("}\n")
			}
		}
		old.WriteString("return rnd16((rnd16(a*t)+b)*t)+c\n}\n")
		source = strings.Replace(source, strings.ReplaceAll(current.String(), ";", "\n"), old.String(), 1)
	}
	return source
}

// Reuse the Step-2 Boolean optimizer without changing any profile arithmetic.
// This probe records costs; it does not admit a family or waive its cost gate.
func TestIntegratorFamilyProfileOptimizer(t *testing.T) {
	p, _, _ := crossGridNBFixtureV1(t)
	profiles := []struct{ name, source string }{
		{"nb_softplus", "package main\n" + exactGCNBSoftplusSourceV1(p, "softplusProfileV1") + "func main(g int32,e int32) int32 { return softplusProfileV1(g+e) }\n"},
	}
	for _, name := range []string{"exp16", "log16", "soft16"} {
		profiles = append(profiles, struct{ name, source string }{name, exactGCFamilyMathSource() + "func main(g uint32,e uint32) uint32 { return " + name + "(g+e) }\n"})
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			baselineSource := profile.source
			if profile.name != "nb_softplus" {
				baselineSource = integratorLegacyFamilyMathSource() + "func main(g uint32,e uint32) uint32 { return " + profile.name + "(g+e) }\n"
			}
			baseline, _, err := compiler.New(utils.NewParams()).Compile(baselineSource, nil)
			if err != nil {
				t.Fatal(err)
			}
			compiled, _, err := compiler.New(crossGridPWCompilerParams()).Compile(profile.source, nil)
			if err != nil {
				t.Fatal(err)
			}
			optimized := crossGridPWOptimize(compiled)
			count := func(c *circuit.Circuit) (and, bytes int) {
				for _, gate := range c.Gates {
					switch gate.Op {
					case circuit.AND:
						and++
						bytes += 32
					case circuit.OR:
						bytes += 48
					case circuit.INV:
						bytes += 16
					}
				}
				return
			}
			oldAND, oldBytes := count(baseline)
			newAND, newBytes := count(optimized)
			t.Logf("baseline_AND=%d optimized_AND=%d baseline_bytes=%d optimized_bytes=%d gate5000=%t", oldAND, newAND, oldBytes, newBytes, newAND <= 5000)
			if newAND > 5000 {
				t.Fatal("revised scalar gate exceeded")
			}
			values := []uint32{0, 1, 0x7fffffff, 0x80000000, 0xffffffff}
			for segment := int64(-88); segment <= 88; segment++ {
				for _, delta := range []int64{-1, 0, 1, 8192, 16383} {
					values = append(values, uint32(segment*16384+delta))
				}
			}
			rng := rand.New(rand.NewSource(20260919))
			for i := 0; i < 256; i++ {
				values = append(values, rng.Uint32())
			}
			for _, value := range values {
				split := rng.Uint32()
				input := []*big.Int{new(big.Int).SetUint64(uint64(split)), new(big.Int).SetUint64(uint64(value - split))}
				want, err := baseline.Compute(input)
				if err != nil {
					t.Fatal(err)
				}
				got, err := optimized.Compute(input)
				if err != nil {
					t.Fatal(err)
				}
				if len(want) != len(got) {
					t.Fatal("output shape changed")
				}
				for i := range want {
					if want[i].Cmp(got[i]) != 0 {
						t.Fatalf("value=%d output=%d baseline=%s optimized=%s", value, i, want[i], got[i])
					}
				}
			}
		})
	}
}
