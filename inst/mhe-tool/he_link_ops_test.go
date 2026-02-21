package main

import (
	"encoding/base64"
	"math"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// TestSigmoidPolynomialAccuracy validates the hardcoded sigmoid polynomial
// coefficients against the true sigmoid on 1000 sample points in [-8, 8].
func TestSigmoidPolynomialAccuracy(t *testing.T) {
	coeffs := SigmoidCoefficients()
	maxErr := ValidateSigmoidPoly(coeffs, 1000)
	t.Logf("Sigmoid polynomial max error on [-8,8]: %e", maxErr)
	if maxErr > 0.02 {
		t.Errorf("Sigmoid polynomial error too large: %e (want < 0.02)", maxErr)
	}
}

// TestCTAdd tests homomorphic ciphertext addition.
func TestCTAdd(t *testing.T) {
	logN := 14
	logScale := 40
	n := 32

	params, err := getParams(logN, logScale)
	if err != nil {
		t.Fatal(err)
	}

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)

	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	decryptor := rlwe.NewDecryptor(params, sk)

	// Create test vectors
	a := make([]float64, n)
	b := make([]float64, n)
	for i := range a {
		a[i] = float64(i) * 0.1
		b[i] = float64(n-i) * 0.05
	}

	// Encrypt
	ptA := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(a, ptA)
	ctA, _ := encryptor.EncryptNew(ptA)

	ptB := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(b, ptB)
	ctB, _ := encryptor.EncryptNew(ptB)

	// Serialize
	ctABytes, _ := ctA.MarshalBinary()
	ctBBytes, _ := ctB.MarshalBinary()

	// Call mheCTAdd
	output, err := mheCTAdd(&CTAddInput{
		CiphertextA: base64.StdEncoding.EncodeToString(ctABytes),
		CiphertextB: base64.StdEncoding.EncodeToString(ctBBytes),
		LogN:        logN,
		LogScale:    logScale,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt result
	ctSumBytes, _ := base64.StdEncoding.DecodeString(output.Ciphertext)
	ctSum := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	ctSum.UnmarshalBinary(ctSumBytes)

	ptResult := decryptor.DecryptNew(ctSum)
	result := make([]float64, params.MaxSlots())
	encoder.Decode(ptResult, result)

	// Verify
	maxErr := 0.0
	for i := 0; i < n; i++ {
		expected := a[i] + b[i]
		err := math.Abs(result[i] - expected)
		if err > maxErr {
			maxErr = err
		}
	}
	t.Logf("CT add max error: %e", maxErr)
	if maxErr > 1e-4 {
		t.Errorf("CT add error too large: %e", maxErr)
	}
}

// TestEvalPolySigmoid tests polynomial evaluation of sigmoid approximation
// on encrypted values.
func TestEvalPolySigmoid(t *testing.T) {
	logN := 14
	logScale := 40
	n := 32

	params, err := getParams(logN, logScale)
	if err != nil {
		t.Fatal(err)
	}

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	rlk := kgen.GenRelinearizationKeyNew(sk)

	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	decryptor := rlwe.NewDecryptor(params, sk)

	// Create test vector: random values in [-8, 8]
	xVals := make([]float64, n)
	for i := range xVals {
		xVals[i] = -8.0 + 16.0*float64(i)/float64(n-1)
	}

	// Encrypt
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(xVals, pt)
	ct, _ := encryptor.EncryptNew(pt)

	// Serialize
	ctBytes, _ := ct.MarshalBinary()
	rlkBytes, _ := rlk.MarshalBinary()

	coeffs := SigmoidCoefficients()

	output, err := mheEvalPoly(&EvalPolyInput{
		Ciphertext:         base64.StdEncoding.EncodeToString(ctBytes),
		Coefficients:       coeffs,
		RelinearizationKey: base64.StdEncoding.EncodeToString(rlkBytes),
		LogN:               logN,
		LogScale:           logScale,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Output level: %d", output.LevelOut)

	// Decrypt result
	ctResultBytes, _ := base64.StdEncoding.DecodeString(output.Ciphertext)
	ctResult := rlwe.NewCiphertext(params, 1, output.LevelOut)
	if err := ctResult.UnmarshalBinary(ctResultBytes); err != nil {
		t.Fatalf("failed to deserialize result: %v", err)
	}

	ptResult := decryptor.DecryptNew(ctResult)
	result := make([]float64, params.MaxSlots())
	encoder.Decode(ptResult, result)

	// Compare against true sigmoid
	maxErr := 0.0
	for i := 0; i < n; i++ {
		expected := 1.0 / (1.0 + math.Exp(-xVals[i]))
		err := math.Abs(result[i] - expected)
		if err > maxErr {
			maxErr = err
		}
		if i < 5 || i > n-3 {
			t.Logf("  x=%.2f: poly=%.6f, true=%.6f, err=%.2e",
				xVals[i], result[i], expected, err)
		}
	}
	t.Logf("Sigmoid eval max error (CKKS): %e", maxErr)
	// Allow larger tolerance: polynomial approx error + CKKS noise
	if maxErr > 0.05 {
		t.Errorf("Sigmoid eval error too large: %e (want < 0.05)", maxErr)
	}
}

// TestRLKGeneration tests the two-round multiparty RLK generation protocol
// and verifies ct×ct multiplication works correctly.
func TestRLKGeneration(t *testing.T) {
	logN := 14
	logScale := 40
	n := 32

	params, err := getParams(logN, logScale)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate 2-party RLK generation using the two-round protocol
	kgen := rlwe.NewKeyGenerator(params)
	sk0 := kgen.GenSecretKeyNew()
	sk1 := kgen.GenSecretKeyNew()

	// Shared PRNG seed for CRP generation
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	rlkGen := multiparty.NewRelinearizationKeyGenProtocol(params)

	// ---- Round 1: Each party generates ephSk + round1 share ----

	// Party 0
	prng0, _ := sampling.NewKeyedPRNG(seed)
	crp := rlkGen.SampleCRP(prng0)
	ephSk0, r1Share0, _ := rlkGen.AllocateShare()
	rlkGen.GenShareRoundOne(sk0, crp, ephSk0, &r1Share0)

	// Party 1 (must use same seed → same CRP)
	prng1, _ := sampling.NewKeyedPRNG(seed)
	_ = rlkGen.SampleCRP(prng1) // consume same CRP
	ephSk1, r1Share1, _ := rlkGen.AllocateShare()
	// Need to re-sample CRP for party 1's round 1
	prng1b, _ := sampling.NewKeyedPRNG(seed)
	crp1 := rlkGen.SampleCRP(prng1b)
	rlkGen.GenShareRoundOne(sk1, crp1, ephSk1, &r1Share1)

	// Aggregate round 1 shares
	aggR1 := r1Share0
	rlkGen.AggregateShares(r1Share1, aggR1, &aggR1)

	// ---- Round 2: Each party generates round2 from aggregated round1 ----
	_, _, r2Share0 := rlkGen.AllocateShare()
	rlkGen.GenShareRoundTwo(ephSk0, sk0, aggR1, &r2Share0)

	_, _, r2Share1 := rlkGen.AllocateShare()
	rlkGen.GenShareRoundTwo(ephSk1, sk1, aggR1, &r2Share1)

	// Aggregate round 2 shares
	aggR2 := r2Share0
	rlkGen.AggregateShares(r2Share1, aggR2, &aggR2)

	// ---- Finalize: Generate collective RLK ----
	rlk := rlwe.NewRelinearizationKey(params)
	rlkGen.GenRelinearizationKey(aggR1, aggR2, rlk)

	// Generate collective PK (for encryption)
	pkg := multiparty.NewPublicKeyGenProtocol(params)
	prng, _ := sampling.NewPRNG()
	pkCRP := pkg.SampleCRP(prng)
	pkShare0 := pkg.AllocateShare()
	pkg.GenShare(sk0, pkCRP, &pkShare0)
	pkShare1 := pkg.AllocateShare()
	pkg.GenShare(sk1, pkCRP, &pkShare1)
	aggPKShare := pkShare0
	pkg.AggregateShares(pkShare1, aggPKShare, &aggPKShare)
	cpk := rlwe.NewPublicKey(params)
	pkg.GenPublicKey(aggPKShare, pkCRP, cpk)

	// Test: encrypt two vectors, multiply them ct×ct, relinearize, decrypt
	encoder := ckks.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, cpk)

	a := make([]float64, n)
	b := make([]float64, n)
	for i := range a {
		a[i] = float64(i+1) * 0.1
		b[i] = float64(n-i) * 0.1
	}

	ptA := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(a, ptA)
	ctA, _ := encryptor.EncryptNew(ptA)

	ptB := ckks.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(b, ptB)
	ctB, _ := encryptor.EncryptNew(ptB)

	// ct×ct multiplication with relinearization
	evk := rlwe.NewMemEvaluationKeySet(rlk)
	eval := ckks.NewEvaluator(params, evk)

	ctMul, err := eval.MulRelinNew(ctA, ctB)
	if err != nil {
		t.Fatalf("ct×ct mul failed: %v", err)
	}
	if err := eval.Rescale(ctMul, ctMul); err != nil {
		t.Fatalf("rescale failed: %v", err)
	}

	// Threshold decrypt: combine sk0 + sk1 (Q part only)
	combinedSK := rlwe.NewSecretKey(params)
	sk0Q := sk0.Value.Q
	sk1Q := sk1.Value.Q
	combinedQ := combinedSK.Value.Q
	params.RingQ().Add(sk0Q, sk1Q, combinedQ)

	decryptor := rlwe.NewDecryptor(params, combinedSK)
	ptResult := decryptor.DecryptNew(ctMul)

	result := make([]float64, params.MaxSlots())
	encoder.Decode(ptResult, result)

	// Verify
	maxErr := 0.0
	for i := 0; i < n; i++ {
		expected := a[i] * b[i]
		errV := math.Abs(result[i] - expected)
		if errV > maxErr {
			maxErr = errV
		}
	}
	t.Logf("RLK ct×ct mul max error: %e", maxErr)
	if maxErr > 1e-3 {
		t.Errorf("RLK ct×ct mul error too large: %e", maxErr)
	}
}
