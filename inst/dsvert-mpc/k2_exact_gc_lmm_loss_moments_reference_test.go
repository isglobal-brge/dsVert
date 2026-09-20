package main

import (
	"math/big"
	"testing"
)

// Independent exact plaintext reference: form each residual at f100, square
// without rescaling, apply q64 reciprocal coefficients, then round once f264.
func groupedLMMStatsOracle(s groupedLMMSpec, rows [][]*big.Int, beta []*big.Int) *big.Int {
	scale := new(big.Int).Lsh(big.NewInt(1), 50)
	sum, squares := new(big.Int), new(big.Int)
	count := 0
	for _, row := range rows {
		if row[0].Sign() == 0 {
			continue
		}
		count++
		residual := new(big.Int).Mul(row[len(row)-1], scale)
		for j, b := range beta {
			residual.Sub(residual, new(big.Int).Mul(row[j], b))
		}
		sum.Add(sum, residual)
		squares.Add(squares, new(big.Int).Mul(residual, residual))
	}
	inv, table := groupedLMMTable(s)
	loss := new(big.Int).Mul(squares, inv)
	loss.Sub(loss, new(big.Int).Mul(new(big.Int).Mul(sum, sum), table[count]))
	unit := new(big.Int).Lsh(big.NewInt(1), uint(264-s.GridBits))
	loss = primitiveVRoundDivReference(loss, unit)
	if loss.Sign() < 0 {
		loss.SetInt64(0)
	}
	if loss.Cmp(big.NewInt(s.OutputCap)) > 0 {
		loss.SetInt64(s.OutputCap)
	}
	return loss
}
func TestGroupedLMMStatsGridOracle(t *testing.T) {
	s := groupedLMMTestSpec()
	p := groupedLMMMomentPlan{1, 2, 3}
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	rows := [][]*big.Int{{new(big.Int).Set(f), new(big.Int).Rsh(new(big.Int).Set(f), 1), new(big.Int).Rsh(new(big.Int).Set(f), 2)}, {new(big.Int).Set(f), new(big.Int).Rsh(new(big.Int).Set(f), 2), new(big.Int).Rsh(new(big.Int).Set(f), 1)}}
	packed := make([]groupedWord, 0, 6)
	for _, row := range rows {
		for _, v := range row {
			packed = append(packed, groupedWordFromBig(v))
		}
	}
	m, err := groupedLMMPrepareMoments(p, packed)
	if err != nil {
		t.Fatal(err)
	}
	x, y, err := m.operands(packed, 0, p.products())
	if err != nil {
		t.Fatal(err)
	}
	products := make([]groupedWord, len(x))
	for i := range x {
		products[i] = x[i].mul(y[i])
	}
	if err = m.accumulate(0, products); err != nil {
		t.Fatal(err)
	}
	_, table := groupedLMMTable(s)
	correction := make([]groupedWord, len(m.Between))
	for i, w := range m.Between {
		correction[i] = w.mul(groupedWordFromBig(table[2]))
	}
	gram, err := groupedLMMPrecisionShares(m, s, correction)
	if err != nil {
		t.Fatal(err)
	}
	// Random low shares, exact lift output, then all candidate arithmetic local.
	ga, gb, ha, hb := make([]groupedWord, len(gram)), make([]groupedWord, len(gram)), make([]groupedWord, len(gram)), make([]groupedWord, len(gram))
	lift, err := groupedLMMLiftCompile(1)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range gram {
		ga[i], err = groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		gb[i] = v.sub(ga[i])
		ha[i], err = groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		high := primitiveVTestCompute(t, lift, []*big.Int{groupedWordInteger(ga[i]), groupedWordInteger(ha[i])}, []*big.Int{groupedWordInteger(gb[i])})[0]
		hb[i] = groupedWordFromBig(high)
	}
	beta := [][]*big.Int{{big.NewInt(0), big.NewInt(0)}, {new(big.Int).Rsh(new(big.Int).Set(f), 2), new(big.Int).Rsh(new(big.Int).Set(f), 1)}, {new(big.Int).Neg(new(big.Int).Set(f)), new(big.Int).Mul(big.NewInt(2), f)}, {big.NewInt(1), big.NewInt(-1)}}
	a, err := groupedLMMGridShares(p, ga, ha, beta)
	if err != nil {
		t.Fatal(err)
	}
	b, err := groupedLMMGridShares(p, gb, hb, beta)
	if err != nil {
		t.Fatal(err)
	}
	final, err := groupedLMMFinalCompile(s.GridBits, s.OutputCap)
	if err != nil {
		t.Fatal(err)
	}
	for j := range beta {
		got := primitiveVTestCompute(t, final, []*big.Int{groupedWordInteger(a[j][0]), groupedWordInteger(a[j][1]), big.NewInt(12), big.NewInt(0), big.NewInt(0)}, []*big.Int{groupedWordInteger(b[j][0]), groupedWordInteger(b[j][1]), big.NewInt(-11)})
		want := groupedLMMStatsOracle(s, rows, beta[j])
		if got[0].Cmp(want) != 0 || got[1].Int64() != 1 {
			t.Fatalf("candidate %d got=%v want=%s", j, got, want)
		}
	}
}

func TestGroupedLMMStatsCertificateBound(t *testing.T) {
	// Exact rational outward checks, independent of dense sampling.
	delta := new(big.Rat).SetFrac(big.NewInt(34), new(big.Int).Lsh(big.NewInt(1), 51))
	delta.Add(delta, new(big.Rat).SetFrac(big.NewInt(17), new(big.Int).Lsh(big.NewInt(1), 102)))
	input := new(big.Rat).Mul(big.NewRat(128, 1), new(big.Rat).Mul(delta, new(big.Rat).Add(big.NewRat(34, 1), delta)))
	coefficient := new(big.Rat).SetFrac(big.NewInt((32+32*32)*18*18), new(big.Int).Lsh(big.NewInt(1), 65))
	total := new(big.Rat).Add(input, coefficient)
	if total.Cmp(big.NewRat(1, 100000000)) >= 0 {
		t.Fatal("LMM 1e-8 certificate does not enclose error")
	}
	if new(big.Int).Lsh(big.NewInt(256*18*18), 264).BitLen() >= 384 {
		t.Fatal("wide accumulator can overflow")
	}
}
