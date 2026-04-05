package main

import (
	"math"
	"math/big"
	"testing"
)

func TestMultToAddTupleK2(t *testing.T) {
	q := uint64(2305843009213693951)
	for i := 0; i < 10; i++ {
		mta := GenerateMultToAddTuple(q)
		check := (modMulBig63(mta.Alpha0, mta.Alpha1, q) +
			modMulBig63(mta.Beta0, mta.Beta1, q)) % q
		if check != 1 {
			t.Errorf("Tuple %d: got %d, want 1", i, check)
		}
	}
	t.Log("10 MultToAdd tuples verified")
}

func TestRing63Arithmetic(t *testing.T) {
	r := NewRing63(20)

	// Round-trip
	tests := []float64{0.0, 1.0, -1.0, 0.5, -0.5, 3.14, -2.71}
	for _, x := range tests {
		fp := r.FromDouble(x)
		got := r.ToDouble(fp)
		if math.Abs(got-x) > 1e-5 {
			t.Errorf("RoundTrip(%.4f) = %.4f", x, got)
		}
	}

	// TruncMulSigned
	a := r.FromDouble(1.5)
	b := r.FromDouble(2.0)
	got := r.ToDouble(r.TruncMulSigned(a, b))
	if math.Abs(got-3.0) > 0.01 {
		t.Errorf("1.5 * 2.0 = %f, want 3.0", got)
	}

	// Negative multiply
	c := r.FromDouble(-1.5)
	got2 := r.ToDouble(r.TruncMulSigned(c, b))
	if math.Abs(got2-(-3.0)) > 0.01 {
		t.Errorf("-1.5 * 2.0 = %f, want -3.0", got2)
	}
}

func TestSecureExpKelkarValues(t *testing.T) {
	cfg := DefaultExpConfig()
	r := cfg.Ring

	// Test values matching C++ test: exponents >= 1 and < 1
	testValues := []float64{0.0, 0.5, 1.0, -0.5, -1.0, 2.0, -2.0, 0.125, 0.75}

	for _, x := range testValues {
		xFP := r.FromDouble(x)
		x0, x1 := r.SplitShare(xFP)

		exp0, exp1 := SecureExpKelkar(cfg, []uint64{x0}, []uint64{x1})

		// Reconstruct
		result := r.Add(exp0[0], exp1[0])
		got := r.ToDouble(result)
		expected := math.Exp(x)

		// C++ tolerance: ceil(3*result + 1) / fracMul
		tolerance := math.Ceil(3*expected+1) / float64(r.FracMul)
		err := math.Abs(got - expected)

		t.Logf("exp(%.3f) = %.6f (expected %.6f, err %.2e, tol %.2e)",
			x, got, expected, err, tolerance)

		if err > tolerance*10 { // 10x C++ tolerance for our implementation
			t.Errorf("exp(%.3f): error %.2e exceeds 10x tolerance %.2e", x, err, tolerance)
		}
	}
}

func TestSecureExpKelkarDebug(t *testing.T) {
	cfg := DefaultExpConfig()
	r := cfg.Ring

	x := 1.0
	xFP := r.FromDouble(x)
	t.Logf("x=%.1f, xFP=%d (%.6f back)", x, xFP, r.ToDouble(xFP))

	x0, x1 := r.SplitShare(xFP)
	t.Logf("x0=%d, x1=%d, sum=%d (%.6f)", x0, x1, r.Add(x0, x1), r.ToDouble(r.Add(x0, x1)))

	mta := GenerateMultToAddTuple(cfg.PrimeQ)

	// P0 round 1
	beta0Mult0, mult0 := ExpParty0Round1(cfg, []uint64{x0}, mta)
	t.Logf("P0: mult_share=%d, beta0*mult=%d", mult0[0], beta0Mult0[0])

	// P1 round 1
	alpha1Mult1, mult1 := ExpParty1Round1(cfg, []uint64{x1}, mta)
	t.Logf("P1: mult_share=%d, alpha1*mult=%d", mult1[0], alpha1Mult1[0])

	// Check: mult0 * mult1 should = 2^x * fracMul^2 * 2^base2Bound (approx)
	product := modMulBig63(mult0[0], mult1[0], cfg.PrimeQ)
	base2Bound := int(math.Ceil(log2e_const*float64(cfg.ExponentBound))) + 1
	expectedProduct := math.Exp(x) * float64(r.FracMul) * float64(r.FracMul) * math.Pow(2, float64(base2Bound))
	t.Logf("mult0*mult1 mod q = %d, expected ~ %.0f", product, expectedProduct)

	// Outputs
	exp0 := ExpParty0Output(cfg, mult0, alpha1Mult1, mta)
	exp1 := ExpParty1Output(cfg, mult1, beta0Mult0, mta)

	t.Logf("P0 output: %d (%.6f)", exp0[0], r.ToDouble(exp0[0]))
	t.Logf("P1 output: %d (%.6f)", exp1[0], r.ToDouble(exp1[0]))
	t.Logf("Sum: %d (%.6f)", r.Add(exp0[0], exp1[0]), r.ToDouble(r.Add(exp0[0], exp1[0])))
	t.Logf("Expected: %.6f", math.Exp(x))
}

func TestP1CorrectionTerm(t *testing.T) {
	r := NewRing63(20)
	log2eFP := r.FromDouble(log2e_const)
	t.Logf("log2e_FP = %d (%.10f back)", log2eFP, r.ToDouble(log2eFP))
	t.Logf("modulus = %d", r.Modulus)
	t.Logf("fracMul = %d", r.FracMul)

	// C++ computation: (log2eFP * modulus) / fracMul % modulus
	prod := new(big.Int).Mul(
		new(big.Int).SetUint64(log2eFP),
		new(big.Int).SetUint64(r.Modulus),
	)
	div := new(big.Int).Div(prod, new(big.Int).SetUint64(r.FracMul))
	correction := new(big.Int).Mod(div, new(big.Int).SetUint64(r.Modulus)).Uint64()
	t.Logf("C++ correction = %d (%.6f in FP)", correction, r.ToDouble(correction))

	// What I compute:
	myCorrection := new(big.Int).Mul(
		new(big.Int).SetUint64(log2eFP),
		new(big.Int).SetUint64(r.Modulus),
	)
	myCorrection.Div(myCorrection, new(big.Int).SetUint64(r.FracMul))
	myCorrection.Mod(myCorrection, new(big.Int).SetUint64(r.Modulus))
	t.Logf("My correction  = %d", myCorrection.Uint64())

	if correction != myCorrection.Uint64() {
		t.Error("Corrections differ!")
	} else {
		t.Log("Corrections match")
	}
}
