package main

import (
	"fmt"
	"math"
	"math/rand"
)

func handleTestSoftplus() {
	ring := NewRing63(20)

	testValues := []float64{-7.0, -5.0, -3.0, -1.0, 0.0, 0.5, 1.0, 3.0, 5.0, 7.0}
	n := len(testValues)

	// Convert to Ring63 FP and split into shares
	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	rng := rand.New(rand.NewSource(42))
	for i, v := range testValues {
		fp := ring.FromDouble(v)
		x0[i] = uint64(rng.Int63()) % ring.Modulus
		x1[i] = ring.Sub(fp, x0[i])
	}

	// Test sigmoid (baseline - known working)
	sig0, sig1 := WideSplineSigmoid(ring, x0, x1, 50)
	fmt.Println("=== Sigmoid (baseline) ===")
	maxSigErr := 0.0
	for i, v := range testValues {
		result := ring.ToDouble(ring.Add(sig0[i], sig1[i]))
		exact := 1.0 / (1.0 + math.Exp(-v))
		err := math.Abs(result - exact)
		if err > maxSigErr {
			maxSigErr = err
		}
		fmt.Printf("  η=%6.1f  sig=%.6f  exact=%.6f  err=%.2e\n", v, result, exact, err)
	}
	fmt.Printf("  Max sigmoid error: %.2e\n", maxSigErr)

	// Test softplus
	sp0, sp1 := WideSplineSoftplus(ring, x0, x1, 80)
	fmt.Println("\n=== Softplus ===")
	maxSpErr := 0.0
	for i, v := range testValues {
		result := ring.ToDouble(ring.Add(sp0[i], sp1[i]))
		exact := math.Log(1.0 + math.Exp(v))
		err := math.Abs(result - exact)
		if err > maxSpErr {
			maxSpErr = err
		}
		fmt.Printf("  η=%6.1f  sp=%.6f  exact=%.6f  err=%.2e\n", v, result, exact, err)
	}
	fmt.Printf("  Max softplus error: %.2e\n", maxSpErr)

	// Test sum of softplus (what we need for deviance)
	var sum0, sum1 uint64
	for i := 0; i < n; i++ {
		sum0 = ring.Add(sum0, sp0[i])
		sum1 = ring.Add(sum1, sp1[i])
	}
	sumResult := ring.ToDouble(ring.Add(sum0, sum1))
	sumExact := 0.0
	for _, v := range testValues {
		sumExact += math.Log(1.0 + math.Exp(v))
	}
	fmt.Printf("\n=== Sum softplus ===\n")
	fmt.Printf("  Sum: result=%.6f  exact=%.6f  err=%.2e\n", sumResult, sumExact, math.Abs(sumResult-sumExact))

	// Output as JSON
	output(map[string]interface{}{
		"sigmoid_max_err":  maxSigErr,
		"softplus_max_err": maxSpErr,
		"sum_result":       sumResult,
		"sum_exact":        sumExact,
		"sum_err":          math.Abs(sumResult - sumExact),
		"status":           "ok",
	})
}
