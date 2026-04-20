// k2_ring127_test.go — ULP budget + correctness tests for Ring127 primitive.
package main

import (
	"math"
	"testing"
)

func TestRing127_AddSubMul(t *testing.T) {
	r := NewRing127(63)
	a := r.FromDouble(3.5)
	b := r.FromDouble(2.25)
	sum := r.Add(a, b)
	if got := r.ToDouble(sum); math.Abs(got-5.75) > 1e-14 {
		t.Errorf("Add: got %v, want 5.75", got)
	}
	diff := r.Sub(a, b)
	if got := r.ToDouble(diff); math.Abs(got-1.25) > 1e-14 {
		t.Errorf("Sub: got %v, want 1.25", got)
	}
	prod := r.TruncMulSigned(a, b)
	if got := r.ToDouble(prod); math.Abs(got-7.875) > 1e-13 {
		t.Errorf("TruncMulSigned: got %v, want 7.875", got)
	}
}

func TestRing127_Negatives(t *testing.T) {
	r := NewRing127(63)
	a := r.FromDouble(-2.5)
	b := r.FromDouble(1.5)
	// (-2.5) * 1.5 = -3.75
	prod := r.TruncMulSigned(a, b)
	got := r.ToDouble(prod)
	if math.Abs(got-(-3.75)) > 1e-13 {
		t.Errorf("Signed mul of negative: got %v, want -3.75", got)
	}
	// (-2.5) * (-1.5) = 3.75
	c := r.FromDouble(-1.5)
	prod2 := r.TruncMulSigned(a, c)
	got2 := r.ToDouble(prod2)
	if math.Abs(got2-3.75) > 1e-13 {
		t.Errorf("Signed mul of two negatives: got %v, want 3.75", got2)
	}
}

// ULP budget: accumulate sum of 10000 products and compare to truth.
// With fracBits=63, single product ULP ~ 2^-63 ≈ 1e-19, accumulated over
// 10^4 ops ~ 1e-15 relative. Pass threshold 1e-12.
func TestRing127_ULPBudget(t *testing.T) {
	r := NewRing127(63)
	total := Uint128{}
	truth := 0.0
	for i := 0; i < 10000; i++ {
		a := 1.0 + float64(i)*1e-5
		b := 2.0 - float64(i)*1e-6
		prod := r.TruncMulSigned(r.FromDouble(a), r.FromDouble(b))
		total = r.Add(total, prod)
		truth += a * b
	}
	got := r.ToDouble(total)
	relErr := math.Abs(got-truth) / math.Abs(truth)
	if relErr > 1e-12 {
		t.Errorf("ULP budget 10k ops: rel err %v > 1e-12", relErr)
	}
	t.Logf("Ring127 10k accumulated: truth=%v MPC=%v rel=%.3e", truth, got, relErr)
}

// Ring63 comparison: same 10k ops at Ring63 fracBits=20 should give
// rel err ~10^-6 (2^-20 × n scales differently).
func TestRing127_VsRing63_Accuracy(t *testing.T) {
	r127 := NewRing127(63)
	r63 := NewRing63(20)
	totalFloat := 0.0
	tot127 := Uint128{}
	tot63 := uint64(0)
	for i := 0; i < 1000; i++ {
		a := 0.5 + float64(i)*0.001
		b := 0.3 + float64(i)*0.0005
		prod := a * b
		totalFloat += prod
		tot127 = r127.Add(tot127, r127.TruncMulSigned(r127.FromDouble(a), r127.FromDouble(b)))
		tot63 = r63.Add(tot63, r63.TruncMulSigned(r63.FromDouble(a), r63.FromDouble(b)))
	}
	rel127 := math.Abs(r127.ToDouble(tot127)-totalFloat) / math.Abs(totalFloat)
	rel63 := math.Abs(r63.ToDouble(tot63)-totalFloat) / math.Abs(totalFloat)
	if rel127 >= rel63 {
		t.Errorf("Ring127 rel %v NOT < Ring63 rel %v (expected Ring127 more accurate)", rel127, rel63)
	}
	t.Logf("1k ops: Ring63 rel=%.3e, Ring127 rel=%.3e (Ring127 better by %.1fx)",
		rel63, rel127, rel63/rel127)
}
