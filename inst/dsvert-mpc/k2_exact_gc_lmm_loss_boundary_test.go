package main

import (
	"math/big"
	"testing"
)

func TestGroupedLMMWideLift(t *testing.T) {
	p, err := groupedLMMLiftCompile(1)
	if err != nil {
		t.Fatal(err)
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), 192)
	wide := new(big.Int).Lsh(big.NewInt(1), 384)
	for _, value := range []*big.Int{big.NewInt(-1), big.NewInt(0), big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 170), new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 170))} {
		for _, left := range []*big.Int{big.NewInt(0), big.NewInt(9), new(big.Int).Sub(modulus, big.NewInt(1))} {
			right := new(big.Int).Mod(new(big.Int).Sub(value, left), modulus)
			high := primitiveVTestCompute(t, p, []*big.Int{left, big.NewInt(7)}, []*big.Int{right})[0]
			high.Add(high, big.NewInt(7))
			got := new(big.Int).Lsh(high, 192)
			got.Add(got, left)
			got.Add(got, right)
			got.Mod(got, wide)
			want := new(big.Int).Mod(value, wide)
			if got.Cmp(want) != 0 {
				t.Fatalf("lift value=%s got=%s want=%s", value, got, want)
			}
		}
	}
}
func TestGroupedLMMPrivatePrecision(t *testing.T) {
	s := groupedLMMTestSpec()
	p, err := groupedLMMPrecisionCompile(s)
	if err != nil {
		t.Fatal(err)
	}
	_, table := groupedLMMTable(s)
	for n := -1; n <= s.Slots+1; n++ {
		input := new(big.Int).Lsh(big.NewInt(int64(n)), 50)
		got := primitiveVTestCompute(t, p, []*big.Int{big.NewInt(71), big.NewInt(0), big.NewInt(0)}, []*big.Int{new(big.Int).Sub(input, big.NewInt(71))})
		if n >= 0 && n <= s.Slots {
			if got[0].Cmp(table[n]) != 0 || got[1].Int64() != 1 {
				t.Fatal("private reciprocal differs")
			}
		} else if got[0].Sign() != 0 || got[1].Sign() != 0 {
			t.Fatal("count not rejected")
		}
	}
	got := primitiveVTestCompute(t, p, []*big.Int{big.NewInt(1), big.NewInt(0), big.NewInt(0)}, []*big.Int{big.NewInt(0)})
	if got[0].Sign() != 0 || got[1].Sign() != 0 {
		t.Fatal("fractional count accepted")
	}
}
func TestGroupedLMMFinalBoundary(t *testing.T) {
	p, err := groupedLMMFinalCompile(16, 999)
	if err != nil {
		t.Fatal(err)
	}
	shift := uint(248)
	unit := new(big.Int).Lsh(big.NewInt(1), shift)
	half := new(big.Int).Rsh(new(big.Int).Set(unit), 1)
	values := []*big.Int{big.NewInt(-1), new(big.Int), half, new(big.Int).Add(unit, half), new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), unit), half), new(big.Int).Mul(big.NewInt(1000), unit)}
	for _, x := range values {
		for _, valid := range []int64{0, 1, 2} {
			residue := new(big.Int).Mod(x, new(big.Int).Lsh(big.NewInt(1), 384))
			lo := groupedWordFromBig(residue)
			hi := groupedWordFromBig(new(big.Int).Rsh(residue, 192))
			got := primitiveVTestCompute(t, p, []*big.Int{groupedWordInteger(lo), groupedWordInteger(hi), big.NewInt(valid), big.NewInt(0), big.NewInt(0)}, []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)})
			want := primitiveVRoundDivReference(x, unit)
			if want.Sign() < 0 {
				want.SetInt64(0)
			}
			if want.Cmp(big.NewInt(999)) > 0 {
				want.SetInt64(999)
			}
			v := int64(1)
			if valid != 1 {
				want.SetInt64(0)
				v = 0
			}
			if got[0].Cmp(want) != 0 || got[1].Int64() != v {
				t.Fatalf("boundary got=%v want=%s", got, want)
			}
		}
	}
	t.Logf("final_boundary_gates=%d tables=%d", p.Circuit.NumGates, primitiveVTableBytes(p.Circuit))
}
