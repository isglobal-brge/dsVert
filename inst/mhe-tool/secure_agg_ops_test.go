package main

import (
	"encoding/base64"
	"math"
	"testing"
)

// generateTestX25519Keypair generates a keypair for testing.
// Uses transportKeygen from transport_ops.go.
func generateTestX25519Keypair(t *testing.T) (sk, pk string) {
	t.Helper()
	output, err := transportKeygen()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	return output.SecretKey, output.PublicKey
}

// TestDeriveSharedSeed_Symmetric verifies A→B and B→A derive the same seed.
func TestDeriveSharedSeed_Symmetric(t *testing.T) {
	skA, pkA := generateTestX25519Keypair(t)
	skB, pkB := generateTestX25519Keypair(t)

	seedAB, err := deriveSharedSeed(&DeriveSharedSeedInput{
		SelfSK:    skA,
		PeerPK:    pkB,
		SessionID: "session-001",
		SelfName:  "serverA",
		PeerName:  "serverB",
	})
	if err != nil {
		t.Fatalf("deriveSharedSeed A→B failed: %v", err)
	}

	seedBA, err := deriveSharedSeed(&DeriveSharedSeedInput{
		SelfSK:    skB,
		PeerPK:    pkA,
		SessionID: "session-001",
		SelfName:  "serverB",
		PeerName:  "serverA",
	})
	if err != nil {
		t.Fatalf("deriveSharedSeed B→A failed: %v", err)
	}

	if seedAB.Seed != seedBA.Seed {
		t.Errorf("Seeds not symmetric:\n  A→B: %s\n  B→A: %s", seedAB.Seed, seedBA.Seed)
	}

	// Verify seed is 32 bytes
	seedBytes, err := base64.StdEncoding.DecodeString(seedAB.Seed)
	if err != nil {
		t.Fatalf("failed to decode seed: %v", err)
	}
	if len(seedBytes) != 32 {
		t.Errorf("seed should be 32 bytes, got %d", len(seedBytes))
	}
}

// TestDeriveSharedSeed_SessionBound verifies different session → different seed.
func TestDeriveSharedSeed_SessionBound(t *testing.T) {
	skA, _ := generateTestX25519Keypair(t)
	_, pkB := generateTestX25519Keypair(t)

	seed1, err := deriveSharedSeed(&DeriveSharedSeedInput{
		SelfSK: skA, PeerPK: pkB,
		SessionID: "session-001",
		SelfName: "serverA", PeerName: "serverB",
	})
	if err != nil {
		t.Fatalf("seed1 failed: %v", err)
	}

	seed2, err := deriveSharedSeed(&DeriveSharedSeedInput{
		SelfSK: skA, PeerPK: pkB,
		SessionID: "session-002",
		SelfName: "serverA", PeerName: "serverB",
	})
	if err != nil {
		t.Fatalf("seed2 failed: %v", err)
	}

	if seed1.Seed == seed2.Seed {
		t.Error("Different sessions should produce different seeds")
	}
}

// TestPRGMaskVector_Deterministic verifies same (seed, iter) → same mask.
func TestPRGMaskVector_Deterministic(t *testing.T) {
	seed := base64.StdEncoding.EncodeToString(make([]byte, 32)) // zero seed

	mask1, err := prgMaskVector(&PRGMaskVectorInput{
		Seed: seed, Iteration: 1, Length: 100, ScaleBits: 20,
	})
	if err != nil {
		t.Fatalf("mask1 failed: %v", err)
	}

	mask2, err := prgMaskVector(&PRGMaskVectorInput{
		Seed: seed, Iteration: 1, Length: 100, ScaleBits: 20,
	})
	if err != nil {
		t.Fatalf("mask2 failed: %v", err)
	}

	for i := range mask1.MaskScaled {
		if mask1.MaskScaled[i] != mask2.MaskScaled[i] {
			t.Errorf("Mask not deterministic at index %d: %f vs %f",
				i, mask1.MaskScaled[i], mask2.MaskScaled[i])
		}
	}
}

// TestPRGMaskVector_IterChange verifies different iter → different mask.
func TestPRGMaskVector_IterChange(t *testing.T) {
	seed := base64.StdEncoding.EncodeToString(make([]byte, 32))

	mask1, err := prgMaskVector(&PRGMaskVectorInput{
		Seed: seed, Iteration: 1, Length: 100, ScaleBits: 20,
	})
	if err != nil {
		t.Fatalf("mask1 failed: %v", err)
	}

	mask2, err := prgMaskVector(&PRGMaskVectorInput{
		Seed: seed, Iteration: 2, Length: 100, ScaleBits: 20,
	})
	if err != nil {
		t.Fatalf("mask2 failed: %v", err)
	}

	same := true
	for i := range mask1.MaskScaled {
		if mask1.MaskScaled[i] != mask2.MaskScaled[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("Different iterations should produce different masks")
	}
}

// TestMaskCancellation_3Parties verifies masks cancel when summed for 3 parties.
// For parties A, B, C with pairs (A,B), (A,C), (B,C):
//   A: +mask_AB +mask_AC
//   B: -mask_AB +mask_BC
//   C: -mask_AC -mask_BC
// Sum: 0
func TestMaskCancellation_3Parties(t *testing.T) {
	skA, pkA := generateTestX25519Keypair(t)
	skB, pkB := generateTestX25519Keypair(t)
	skC, pkC := generateTestX25519Keypair(t)

	sessionID := "test-session-3p"
	n := 50
	iter := 1
	scaleBits := 20

	// Derive pairwise seeds
	seedAB := deriveSeedHelper(t, skA, pkB, sessionID, "A", "B")
	seedAC := deriveSeedHelper(t, skA, pkC, sessionID, "A", "C")
	seedBC := deriveSeedHelper(t, skB, pkC, sessionID, "B", "C")

	// Verify symmetry
	seedBA := deriveSeedHelper(t, skB, pkA, sessionID, "B", "A")
	seedCA := deriveSeedHelper(t, skC, pkA, sessionID, "C", "A")
	seedCB := deriveSeedHelper(t, skC, pkB, sessionID, "C", "B")

	if seedAB != seedBA {
		t.Fatal("seedAB != seedBA")
	}
	if seedAC != seedCA {
		t.Fatal("seedAC != seedCA")
	}
	if seedBC != seedCB {
		t.Fatal("seedBC != seedCB")
	}

	// Test eta vectors
	etaA := make([]float64, n)
	etaB := make([]float64, n)
	etaC := make([]float64, n)
	for i := 0; i < n; i++ {
		etaA[i] = float64(i) * 0.1
		etaB[i] = float64(i) * -0.05 + 1.0
		etaC[i] = float64(i) * 0.03 - 0.5
	}

	// Mask each party's eta
	// A: canonical pairs (A,B) → A<B so sign=+1; (A,C) → A<C so sign=+1
	maskedA, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etaA, Seeds: []string{seedAB, seedAC}, Signs: []int{1, 1},
		Iteration: iter, ScaleBits: scaleBits,
	})
	if err != nil {
		t.Fatalf("maskA failed: %v", err)
	}

	// B: (A,B) → B>A so sign=-1; (B,C) → B<C so sign=+1
	maskedB, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etaB, Seeds: []string{seedAB, seedBC}, Signs: []int{-1, 1},
		Iteration: iter, ScaleBits: scaleBits,
	})
	if err != nil {
		t.Fatalf("maskB failed: %v", err)
	}

	// C: (A,C) → C>A so sign=-1; (B,C) → C>B so sign=-1
	maskedC, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etaC, Seeds: []string{seedAC, seedBC}, Signs: []int{-1, -1},
		Iteration: iter, ScaleBits: scaleBits,
	})
	if err != nil {
		t.Fatalf("maskC failed: %v", err)
	}

	// Unmask: sum all masked vectors
	result, err := fixedPointUnmaskSum(&FixedPointUnmaskSumInput{
		MaskedVectors: [][]float64{maskedA.MaskedScaled, maskedB.MaskedScaled, maskedC.MaskedScaled},
		ScaleBits:     scaleBits,
	})
	if err != nil {
		t.Fatalf("unmaskSum failed: %v", err)
	}

	// Verify: result should match true sum within fixed-point precision.
	// Each party independently rounds eta to fixed-point, contributing up to
	// 0.5 units of quantization error. With K parties, tolerance = K / 2^scale_bits.
	nParties := 3
	tol := float64(nParties) / float64(int64(1)<<scaleBits)
	for i := 0; i < n; i++ {
		trueSum := etaA[i] + etaB[i] + etaC[i]
		if math.Abs(result.SumEta[i]-trueSum) > tol {
			t.Errorf("Index %d: got %.10f, want %.10f (diff %.2e, tol %.2e)",
				i, result.SumEta[i], trueSum, math.Abs(result.SumEta[i]-trueSum), tol)
		}
	}
}

// TestMaskCancellation_4Parties verifies masks cancel for 4 parties.
func TestMaskCancellation_4Parties(t *testing.T) {
	skA, _ := generateTestX25519Keypair(t)
	skB, pkB := generateTestX25519Keypair(t)
	skC, pkC := generateTestX25519Keypair(t)
	_, pkD := generateTestX25519Keypair(t)

	sessionID := "test-session-4p"
	n := 30
	iter := 5
	scaleBits := 20

	// 6 pairwise seeds: AB, AC, AD, BC, BD, CD
	seedAB := deriveSeedHelper(t, skA, pkB, sessionID, "A", "B")
	seedAC := deriveSeedHelper(t, skA, pkC, sessionID, "A", "C")
	seedAD := deriveSeedHelper(t, skA, pkD, sessionID, "A", "D")
	seedBC := deriveSeedHelper(t, skB, pkC, sessionID, "B", "C")
	seedBD := deriveSeedHelper(t, skB, pkD, sessionID, "B", "D")
	seedCD := deriveSeedHelper(t, skC, pkD, sessionID, "C", "D")

	etas := make([][]float64, 4)
	for k := 0; k < 4; k++ {
		etas[k] = make([]float64, n)
		for i := 0; i < n; i++ {
			etas[k][i] = float64(k*100+i) * 0.01
		}
	}

	// A: +AB +AC +AD (A < B,C,D)
	maskedA, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etas[0], Seeds: []string{seedAB, seedAC, seedAD}, Signs: []int{1, 1, 1},
		Iteration: iter, ScaleBits: scaleBits,
	})
	if err != nil {
		t.Fatalf("maskA: %v", err)
	}

	// B: -AB +BC +BD (B > A, B < C, B < D)
	maskedB, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etas[1], Seeds: []string{seedAB, seedBC, seedBD}, Signs: []int{-1, 1, 1},
		Iteration: iter, ScaleBits: scaleBits,
	})
	if err != nil {
		t.Fatalf("maskB: %v", err)
	}

	// C: -AC -BC +CD (C > A, C > B, C < D)
	maskedC, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etas[2], Seeds: []string{seedAC, seedBC, seedCD}, Signs: []int{-1, -1, 1},
		Iteration: iter, ScaleBits: scaleBits,
	})
	if err != nil {
		t.Fatalf("maskC: %v", err)
	}

	// D: -AD -BD -CD (D > A,B,C)
	maskedD, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etas[3], Seeds: []string{seedAD, seedBD, seedCD}, Signs: []int{-1, -1, -1},
		Iteration: iter, ScaleBits: scaleBits,
	})
	if err != nil {
		t.Fatalf("maskD: %v", err)
	}

	result, err := fixedPointUnmaskSum(&FixedPointUnmaskSumInput{
		MaskedVectors: [][]float64{
			maskedA.MaskedScaled, maskedB.MaskedScaled,
			maskedC.MaskedScaled, maskedD.MaskedScaled,
		},
		ScaleBits: scaleBits,
	})
	if err != nil {
		t.Fatalf("unmaskSum: %v", err)
	}

	// 4 parties → tolerance = 4 / 2^scale_bits
	nParties4 := 4
	tol := float64(nParties4) / float64(int64(1)<<scaleBits)
	for i := 0; i < n; i++ {
		trueSum := etas[0][i] + etas[1][i] + etas[2][i] + etas[3][i]
		if math.Abs(result.SumEta[i]-trueSum) > tol {
			t.Errorf("Index %d: got %.10f, want %.10f (diff %.2e, tol %.2e)",
				i, result.SumEta[i], trueSum, math.Abs(result.SumEta[i]-trueSum), tol)
		}
	}
}

// TestFixedPointRoundTrip tests the full mask → unmask pipeline.
func TestFixedPointRoundTrip(t *testing.T) {
	// Simple 2-server case (though secure_agg needs K≥3, the math works for 2)
	skA, _ := generateTestX25519Keypair(t)
	_, pkB := generateTestX25519Keypair(t)

	seedAB := deriveSeedHelper(t, skA, pkB, "rt-session", "sA", "sB")

	etaA := []float64{1.5, -2.3, 0.0, 100.7, -0.001}
	etaB := []float64{-0.5, 3.3, 1.0, -50.3, 0.999}

	maskedA, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etaA, Seeds: []string{seedAB}, Signs: []int{1},
		Iteration: 1, ScaleBits: 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	maskedB, err := fixedPointMaskEta(&FixedPointMaskEtaInput{
		Eta: etaB, Seeds: []string{seedAB}, Signs: []int{-1},
		Iteration: 1, ScaleBits: 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := fixedPointUnmaskSum(&FixedPointUnmaskSumInput{
		MaskedVectors: [][]float64{maskedA.MaskedScaled, maskedB.MaskedScaled},
		ScaleBits:     20,
	})
	if err != nil {
		t.Fatal(err)
	}

	tol := 1.0 / float64(int64(1)<<20)
	for i := range etaA {
		expected := etaA[i] + etaB[i]
		if math.Abs(result.SumEta[i]-expected) > tol {
			t.Errorf("Index %d: got %f, want %f", i, result.SumEta[i], expected)
		}
	}
}

// deriveSeedHelper is a test helper that calls deriveSharedSeed and returns the seed string.
func deriveSeedHelper(t *testing.T, sk, pk, sessionID, selfName, peerName string) string {
	t.Helper()
	out, err := deriveSharedSeed(&DeriveSharedSeedInput{
		SelfSK: sk, PeerPK: pk,
		SessionID: sessionID,
		SelfName: selfName, PeerName: peerName,
	})
	if err != nil {
		t.Fatalf("deriveSharedSeed(%s→%s) failed: %v", selfName, peerName, err)
	}
	return out.Seed
}
