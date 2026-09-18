package main

import (
	"fmt"
	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"math"
	"math/big"
	"testing"
)

func TestGroupedRangeExpCertificate(t *testing.T) {
	// M<=2, h=1/64; coefficient and interpolation rounding <=1/S.
	reduced := 2.0/(8*64*64) + 1.0/65536
	// |k|<=23, k<=6; exp(x)<=55 for positive-domain inputs.
	// |exp(k*(ln2-L))-1| <= 2*|k|*1.5e-6.
	if groupedExpError < 64*reduced+55*1.0001*6*1.5e-6+0.5/65536 ||
		groupedNegativeExpError < reduced+1.0001*23*1.5e-6+0.5/65536 {
		t.Fatal("range-reduction certificate does not enclose")
	}
	for _, name := range []string{"exp", "exp_negative"} {
		lo, hi, bound := int64(-262144), int64(262144), groupedExpError
		if name == "exp_negative" {
			lo, hi, bound = -1048576, 0, groupedNegativeExpError
		}
		worst := 0.0
		for x := lo; x <= hi; x++ {
			got, err := groupedProfileEval(name, x)
			if err != nil {
				t.Fatal(err)
			}
			e := math.Abs(float64(got)/65536 - math.Exp(float64(x)/65536))
			worst = math.Max(worst, e)
			if e > bound {
				t.Fatalf("%s x=%d error=%g bound=%g", name, x, e, bound)
			}
		}
		t.Logf("%s max_error=%g bound=%g", name, worst, bound)
		for _, x := range []int64{lo - 1, hi + 1} {
			if _, err := groupedProfileEval(name, x); err == nil {
				t.Fatal("domain accepted")
			}
		}
	}
}

func TestGroupedRangeExpCircuit(t *testing.T) {
	source := fmt.Sprintf("package main\n%s\nfunc main(g [2]int32,e [1]int32) [1]int32 { var out [1]int32\n out[0]=groupedRangeExp(g[0]+e[0])-g[1]\n return out }\n", groupedProfileSource())
	p, err := primitiveVCompile(source, 32, 2, 1, 1)
	if err != nil {
		_, _, detail := compiler.New(utils.NewParams()).Compile(source, nil)
		t.Fatalf("%v: %v", err, detail)
	}
	t.Logf("gates=%d AND=%d table_bytes=%d", p.Circuit.NumGates, p.Circuit.Stats[circuit.AND], primitiveVTableBytes(p.Circuit))
	if p.Circuit.Stats[circuit.AND] > 5000 {
		t.Fatal("revised scalar AND gate exceeded")
	}
	// Every q16 residual-table interval and exponent threshold, including ties
	// and underflow/rounding transitions. Nonzero additive shares and output mask.
	inputs := map[int64]bool{-1048576: true, 262144: true, 0: true}
	for k := int64(-23); k <= 6; k++ {
		for r := int64(-22713); r <= 22713; r += 1024 {
			for _, d := range []int64{-1, 0, 1} {
				inputs[k*45426+r+d] = true
			}
		}
		for _, r := range []int64{-22714, -22713, -22712, 22712, 22713, 22714} {
			inputs[k*45426+r] = true
		}
	}
	for x := range inputs {
		if x < -1048576 || x > 262144 {
			continue
		}
		want := groupedExpEval(x)
		mask := int64(73)
		g := new(big.Int).Mod(big.NewInt(x-101), exactGCModulus(32))
		g.Or(g, new(big.Int).Lsh(big.NewInt(mask), 32))
		got, err := p.Circuit.Compute([]*big.Int{g, big.NewInt(101)})
		if err != nil {
			t.Fatal(err)
		}
		restored := new(big.Int).Mod(new(big.Int).Add(got[0], big.NewInt(mask)), exactGCModulus(32))
		if restored.Int64() != want {
			t.Fatalf("x=%d got=%s want=%d", x, restored, want)
		}
	}
}
