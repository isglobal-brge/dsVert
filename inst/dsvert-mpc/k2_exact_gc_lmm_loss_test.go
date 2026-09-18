package main

import (
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"math/big"
	"strings"
	"testing"
)

func groupedLMMTestSpec() groupedLMMSpec {
	return groupedLMMSpec{Slots: 2, GridBits: 8, ResidualCap: 2, Sigma2Q64: new(big.Int).Set(primitiveVScale), Tau2Q64: new(big.Int).Set(primitiveVScale), OutputCap: 2048}
}

func TestGroupedLMMCircuitReference(t *testing.T) {
	s := groupedLMMTestSpec()
	p, err := groupedLMMCompile(s)
	if err != nil {
		source, _ := groupedLMMSource(s)
		_, _, detail := compiler.New(utils.NewParams()).Compile(source, nil)
		t.Fatalf("%v: %v", err, detail)
	}
	t.Logf("gates=%d table_bytes=%d", p.Circuit.NumGates, primitiveVTableBytes(p.Circuit))
	for _, r := range []int64{-2, -1, 0, 1, 2} {
		for _, v := range []int64{0, 1, 2} {
			x := []*big.Int{new(big.Int).Mul(big.NewInt(r), primitiveVScale), new(big.Int).Set(primitiveVScale)}
			live := []*big.Int{big.NewInt(v), big.NewInt(1)}
			want, valid, _ := groupedLMMReference(s, x, live)
			g := []*big.Int{x[0], live[0], x[1], live[1], big.NewInt(27), big.NewInt(41)}
			e := []*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
			got := primitiveVTestCompute(t, p, g, e)
			got[0].Add(got[0], g[4])
			got[1].Add(got[1], g[5])
			if got[0].Cmp(want) != 0 || (got[1].Int64() == 1) != valid {
				t.Fatalf("r=%d live=%d got=%v want=%s valid=%v", r, v, got, want, valid)
			}
		}
	}
	// One ulp outside the signed residual domain must mask all outputs closed.
	x := new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), primitiveVScale), big.NewInt(1))
	got := primitiveVTestCompute(t, p, []*big.Int{x, big.NewInt(1), new(big.Int), new(big.Int), new(big.Int), new(big.Int)}, []*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)})
	if got[0].Sign() != 0 || got[1].Sign() != 0 {
		t.Fatal("residual slack was not rejected")
	}
}

func TestGroupedLMMTargetsAndRounding(t *testing.T) {
	s := groupedLMMTestSpec()
	q := new(big.Int).Set(primitiveVScale)
	got, valid, err := groupedLMMReference(s, []*big.Int{q, q}, []*big.Int{big.NewInt(1), big.NewInt(1)})
	if err != nil || !valid || got.Int64() != 171 {
		t.Fatalf("two equal residuals: %v %v %v", got, valid, err)
	}
	s.Tau2Q64 = new(big.Int)
	got, _, _ = groupedLMMReference(s, []*big.Int{q, q}, []*big.Int{big.NewInt(1), big.NewInt(1)})
	if got.Int64() != 512 {
		t.Fatal("independent SSE differs")
	}
	s.OutputCap = 7
	got, _, _ = groupedLMMReference(s, []*big.Int{q, q}, []*big.Int{big.NewInt(1), big.NewInt(1)})
	if got.Int64() != 7 {
		t.Fatal("signed saturation cap differs")
	}
	s.Slots = 33
	if _, err := groupedLMMSource(s); err == nil {
		t.Fatal("unbounded cluster accepted")
	}
}

func TestGroupedLMMEncryptedProtocol(t *testing.T) {
	s := groupedLMMTestSpec()
	s.Slots = 1
	p, err := registerGroupedLMM()(s)
	if err != nil {
		source, _ := groupedLMMSource(s)
		_, _, detail := compiler.New(utils.NewParams()).Compile(source, nil)
		t.Fatalf("%v: %v", err, detail)
	}
	g := []*big.Int{big.NewInt(27), big.NewInt(42)}
	e := []*big.Int{exactGCEncodeSigned(new(big.Int).Sub(primitiveVScale, big.NewInt(27)), 192), exactGCEncodeSigned(big.NewInt(-41), 192)}
	got, bytes := primitiveVTestProtocol(t, p, g, e)
	if got[0].Int64() != 128 || got[1].Int64() != 1 {
		t.Fatalf("shared protocol loss differs: %v", got)
	}
	t.Logf("encrypted_garbler_bytes=%d", bytes)
	source, _ := groupedLMMSource(s)
	if strings.Contains(source, "primitiveVExp") || strings.Contains(source, "primitiveVLog") {
		t.Fatal("transcendental helper entered LMM")
	}
}

func TestGroupedLMMCertifiedExtremes(t *testing.T) {
	for _, tau := range []int64{0, 16} {
		s := groupedLMMSpec{Slots: 32, GridBits: 18, ResidualCap: 17, Sigma2Q64: new(big.Int).Rsh(new(big.Int).Set(primitiveVScale), 2), Tau2Q64: new(big.Int).Mul(big.NewInt(tau), primitiveVScale), OutputCap: 1 << 40}
		p, err := groupedLMMCompile(s)
		if err != nil {
			t.Fatal(err)
		}
		residual := make([]*big.Int, s.Slots)
		live := make([]*big.Int, s.Slots)
		g := make([]*big.Int, p.InputWordsG)
		e := make([]*big.Int, p.InputWordsE)
		for i := range g {
			g[i] = new(big.Int)
		}
		for i := range e {
			e[i] = new(big.Int)
		}
		for i := range residual {
			residual[i] = new(big.Int).Mul(big.NewInt(17), primitiveVScale)
			live[i] = big.NewInt(1)
			g[2*i] = residual[i]
			g[2*i+1] = live[i]
		}
		want, valid, err := groupedLMMReference(s, residual, live)
		if err != nil || !valid {
			t.Fatal(err)
		}
		got := primitiveVTestCompute(t, p, g, e)
		if got[0].Cmp(want) != 0 || got[1].Int64() != 1 {
			t.Fatalf("tau=%d got=%v want=%s", tau, got, want)
		}
	}
}
