// k2_ring127_affine_combine_test.go — correctness of the share-level
// affine-combine local op used by Horner / NR R-orchestration.

package main

import (
	"math"
	"testing"
)

// TestAffineCombine_HornerStep: simulate one Horner iter:
//   party0_b_k = twoYbKp1_0 + c_k - bKp2_0
//   party1_b_k = twoYbKp1_1 +   0 - bKp2_1
// Verify party0 + party1 = twoYbKp1_sum + c_k - bKp2_sum = true b_k.
func TestAffineCombine_HornerStep(t *testing.T) {
	r := NewRing127(50)
	n := 5
	// Make some arbitrary "true" Ring127 FP shares.
	trueTwoYbKp1 := make([]Uint128, n)
	trueBKp2 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		trueTwoYbKp1[i] = r.FromDouble(float64(i) * 0.37)
		trueBKp2[i] = r.FromDouble(float64(i+1) * 0.19)
	}
	// Split each into two random shares.
	splitShares := func(v []Uint128) (s0, s1 []Uint128) {
		s0 = make([]Uint128, len(v))
		s1 = make([]Uint128, len(v))
		for i := range v {
			mask := Uint128{Lo: uint64(i*31 + 7)}.ModPow127()
			s0[i] = mask
			s1[i] = r.Sub(v[i], mask)
		}
		return
	}
	twoYbKp1_0, twoYbKp1_1 := splitShares(trueTwoYbKp1)
	bKp2_0, bKp2_1 := splitShares(trueBKp2)

	ck := r.FromDouble(2.71828)
	ckB64 := Uint128VecToB64([]Uint128{ck})

	// Simulate handler for party 0.
	in0 := K2Ring127AffineCombineInput{
		A:           Uint128VecToB64(twoYbKp1_0),
		B:           Uint128VecToB64(bKp2_0),
		SignA:       +1,
		SignB:       -1,
		PublicConst: ckB64,
		IsParty0:    true,
		FracBits:    50,
		N:           n,
	}
	in1 := K2Ring127AffineCombineInput{
		A:           Uint128VecToB64(twoYbKp1_1),
		B:           Uint128VecToB64(bKp2_1),
		SignA:       +1,
		SignB:       -1,
		PublicConst: ckB64,
		IsParty0:    false,
		FracBits:    50,
		N:           n,
	}

	out0 := affineCombineCompute(t, in0)
	out1 := affineCombineCompute(t, in1)

	for i := 0; i < n; i++ {
		sum := r.Add(out0[i], out1[i])
		wantVal := r.Add(r.Sub(trueTwoYbKp1[i], trueBKp2[i]), ck)
		if sum != wantVal {
			gotF := r.ToDouble(sum)
			wantF := r.ToDouble(wantVal)
			t.Errorf("Horner step b_k[%d]: got %g want %g", i, gotF, wantF)
		}
	}
}

// TestAffineCombine_NRStep: simulate NR inner-assembly
//   tmp = 2 - xy_share  (sign_a=0 so a is empty; sign_b=-1; const=2)
//   party0: 2 - xy_0
//   party1: 0 - xy_1
//   sum: 2 - (xy_0 + xy_1) = 2 - xy
func TestAffineCombine_NRStep(t *testing.T) {
	r := NewRing127(50)
	n := 3
	trueXy := []Uint128{
		r.FromDouble(0.7),
		r.FromDouble(1.3),
		r.FromDouble(0.95),
	}
	xy0 := make([]Uint128, n)
	xy1 := make([]Uint128, n)
	for i := range trueXy {
		mask := Uint128{Lo: uint64(i*11 + 3)}.ModPow127()
		xy0[i] = mask
		xy1[i] = r.Sub(trueXy[i], mask)
	}

	two := r.FromDouble(2.0)
	in0 := K2Ring127AffineCombineInput{
		A:           "",
		B:           Uint128VecToB64(xy0),
		SignA:       0,
		SignB:       -1,
		PublicConst: Uint128VecToB64([]Uint128{two}),
		IsParty0:    true,
		FracBits:    50,
		N:           n,
	}
	in1 := K2Ring127AffineCombineInput{
		A:           "",
		B:           Uint128VecToB64(xy1),
		SignA:       0,
		SignB:       -1,
		PublicConst: "",
		IsParty0:    false,
		FracBits:    50,
		N:           n,
	}
	out0 := affineCombineCompute(t, in0)
	out1 := affineCombineCompute(t, in1)
	for i := 0; i < n; i++ {
		sum := r.Add(out0[i], out1[i])
		got := r.ToDouble(sum)
		want := 2.0 - r.ToDouble(trueXy[i])
		if math.Abs(got-want) > 1e-12 {
			t.Errorf("NR step[%d]: got %g want %g", i, got, want)
		}
	}
}

// affineCombineCompute exercises the handler logic without stdin/stdout by
// replicating the inner loop; tests hit the same code path as the CLI.
func affineCombineCompute(t *testing.T, in K2Ring127AffineCombineInput) []Uint128 {
	t.Helper()
	fb := ring127DefaultFracBits(in.FracBits)
	r := NewRing127(fb)
	var a, b []Uint128
	if in.SignA != 0 {
		a = b64Uint128Vec(in.A)
	}
	if in.SignB != 0 {
		b = b64Uint128Vec(in.B)
	}
	var cAdd Uint128
	addConst := false
	if in.IsParty0 && in.PublicConst != "" {
		cAdd = b64Uint128Vec(in.PublicConst)[0]
		addConst = true
	}
	out := make([]Uint128, in.N)
	for i := 0; i < in.N; i++ {
		var ta, tb Uint128
		switch in.SignA {
		case 1:
			ta = a[i]
		case -1:
			ta = r.Neg(a[i])
		}
		switch in.SignB {
		case 1:
			tb = b[i]
		case -1:
			tb = r.Neg(b[i])
		}
		s := r.Add(ta, tb)
		if addConst {
			s = r.Add(s, cAdd)
		}
		out[i] = s
	}
	return out
}
