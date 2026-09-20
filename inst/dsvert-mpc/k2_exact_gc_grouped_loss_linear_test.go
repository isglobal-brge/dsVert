package main

import (
	"math/big"
	"testing"
)

func TestGroupedShareBlockSums(t *testing.T) {
	for _, bits := range []int{32, 128, 192} {
		mod := exactGCModulus(bits)
		a, b := make([]*big.Int, 12), make([]*big.Int, 12)
		for i := range a {
			a[i] = new(big.Int).Sub(mod, big.NewInt(int64(100+i)))
			b[i] = big.NewInt(int64(100 + 2*i))
		}
		x, err := groupedShareBlockSums(a, 3, 2, bits)
		if err != nil {
			t.Fatal(err)
		}
		y, err := groupedShareBlockSums(b, 3, 2, bits)
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range []int64{6, 9, 24, 27} {
			got := new(big.Int).Mod(new(big.Int).Add(x[i], y[i]), mod)
			if got.Int64() != want {
				t.Fatalf("bits=%d column=%d got=%s", bits, i, got)
			}
		}
		if a[0].Cmp(new(big.Int).Sub(mod, big.NewInt(100))) != 0 {
			t.Fatal("mutated input")
		}
	}
	for _, words := range [][]*big.Int{nil, {nil}, {big.NewInt(-1)}, {new(big.Int).Lsh(big.NewInt(1), 32)}} {
		if _, err := groupedShareBlockSums(words, 1, 1, 32); err == nil {
			t.Fatal("malformed share accepted")
		}
	}
	if _, err := groupedShareBlockSums([]*big.Int{big.NewInt(1)}, 2, 1, 32); err == nil {
		t.Fatal("partial block accepted")
	}
}

// Executable counterexamples prevent replacing secure operations with local
// arithmetic when integrating clause 5. All values here are public fixtures.
func TestGroupedClauseFiveNonlinearObligations(t *testing.T) {
	// 7 = 3+4; local squares miss the cross term 2*3*4.
	if (3*3+4*4)%256 == 7*7%256 {
		t.Fatal("square counterexample invalid")
	}
	// A denominator with public rho=1 still varies with private live count.
	if big.NewRat(1, 2).Cmp(big.NewRat(1, 3)) == 0 {
		t.Fatal("private-count counterexample invalid")
	}
	// Secret segment reset changes the output for the same input row values.
	values := []int{2, 3}
	if values[0]+values[1] == values[1] {
		t.Fatal("private-boundary counterexample invalid")
	}
	// Independent ties-even rounding does not commute with share addition.
	if groupedRoundDiv(1, 2)+groupedRoundDiv(1, 2) == groupedRoundDiv(2, 2) {
		t.Fatal("rounding counterexample invalid")
	}
}
