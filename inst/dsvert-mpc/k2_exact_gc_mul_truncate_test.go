package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
)

func exactGCTestMulSpec(bits, frac, n int) exactGCCircuitSpec {
	bound := exactGCDefaultMulBound(bits, frac)
	backend := exactGCMulBackendDirect
	if bits == 127 && frac == 50 {
		backend = exactGCMulBackendHybrid
	}
	return exactGCCircuitSpec{
		Operation: exactGCMulTruncateChecked,
		RingBits:  bits, FracBits: frac, VectorLen: n,
		MulBackend: backend,
		BoundX:     new(big.Int).Set(bound), BoundY: new(big.Int).Set(bound),
	}
}

func exactGCTestMulCircuit(t *testing.T, spec exactGCCircuitSpec,
	xValues, yValues []*big.Int, rng *rand.Rand, validityMask bool) {

	t.Helper()
	if len(xValues) != spec.VectorLen || len(yValues) != spec.VectorLen {
		t.Fatal("invalid checked multiplication fixture shape")
	}
	xResidues := make([]*big.Int, spec.VectorLen)
	yResidues := make([]*big.Int, spec.VectorLen)
	for i := range xValues {
		xResidues[i] = exactGCEncodeSigned(xValues[i], spec.RingBits)
		yResidues[i] = exactGCEncodeSigned(yValues[i], spec.RingBits)
	}
	xa, xb := exactGCTestSplit(rng, xResidues, spec.RingBits)
	ya, yb := exactGCTestSplit(rng, yResidues, spec.RingBits)
	garblerShares := append(append([]*big.Int{}, xa...), ya...)
	evaluatorShares := append(append([]*big.Int{}, xb...), yb...)
	resultMasks := make([]*big.Int, spec.VectorLen+1)
	for i := 0; i < spec.VectorLen; i++ {
		resultMasks[i] = exactGCTestRandomResidue(rng, spec.RingBits)
	}
	resultMasks[spec.VectorLen] = big.NewInt(0)
	if validityMask {
		resultMasks[spec.VectorLen].SetInt64(1)
	}
	circ, err := exactGCCompileCircuit(spec)
	if err != nil {
		t.Logf("generated circuit:\n%s", exactGCCircuitSource(spec))
		t.Fatal(err)
	}
	garblerInput := exactGCPackGarblerInput(garblerShares, resultMasks, spec)
	evaluatorInput := exactGCPackChunks(evaluatorShares,
		exactGCTypeBits(spec.RingBits))
	packed, err := circ.Compute([]*big.Int{garblerInput, evaluatorInput})
	if err != nil {
		t.Fatal(err)
	}
	got := exactGCUnpackOutputs(packed[0], spec)
	allValid := true
	for i := 0; i < spec.VectorLen; i++ {
		want, valid := exactGCReferenceMulTruncateChecked(
			xa[i], xb[i], ya[i], yb[i], spec)
		allValid = allValid && valid
		want.Sub(want, resultMasks[i]).Mod(want, exactGCModulus(spec.RingBits))
		if got[i].Cmp(want) != 0 {
			t.Fatalf("element %d: x=%s y=%s got %s want %s valid=%v",
				i, xValues[i], yValues[i], got[i], want, valid)
		}
	}
	wantValidity := allValid != validityMask
	if (got[spec.VectorLen].Bit(0) == 1) != wantValidity {
		t.Fatalf("validity share got=%s want=%v", got[spec.VectorLen], wantValidity)
	}
}

func TestExactGCMulTruncateCheckedSignedFloorAndBounds(t *testing.T) {
	rng := rand.New(rand.NewSource(20260801))
	for _, tc := range []struct {
		bits int
		frac int
	}{{63, 20}, {127, 50}, {513, 50}} {
		t.Run(fmt.Sprintf("Ring%d", tc.bits), func(t *testing.T) {
			spec := exactGCTestMulSpec(tc.bits, tc.frac, 1)
			denom := new(big.Int).Lsh(big.NewInt(1), uint(tc.frac))
			values := []*big.Int{
				big.NewInt(0), big.NewInt(1), big.NewInt(-1),
				new(big.Int).Sub(new(big.Int).Set(denom), big.NewInt(1)),
				new(big.Int).Neg(new(big.Int).Add(new(big.Int).Set(denom), big.NewInt(1))),
				new(big.Int).Set(spec.BoundX),
				new(big.Int).Neg(new(big.Int).Set(spec.BoundX)),
			}
			for i, x := range values {
				for j, y := range values {
					exactGCTestMulCircuit(t, spec, []*big.Int{x}, []*big.Int{y},
						rng, (i+j)&1 == 1)
				}
			}
			// -3 / 2 must floor to -2, not truncate toward zero to -1.
			floorSpec := exactGCTestMulSpec(tc.bits, 1, 1)
			exactGCTestMulCircuit(t, floorSpec, []*big.Int{big.NewInt(-3)},
				[]*big.Int{big.NewInt(1)}, rng, false)

			overBound := new(big.Int).Add(spec.BoundX, big.NewInt(1))
			exactGCTestMulCircuit(t, spec, []*big.Int{overBound},
				[]*big.Int{big.NewInt(1)}, rng, true)
		})
	}
}

func TestExactGCMulTruncateCheckedRandomProperties(t *testing.T) {
	rng := rand.New(rand.NewSource(778899))
	for _, bits := range []int{63, 127} {
		frac := 20
		if bits == 127 {
			frac = 50
		}
		spec := exactGCTestMulSpec(bits, frac, 1)
		for i := 0; i < 64; i++ {
			x, err := crandIntForTest(rng, spec.BoundX)
			if err != nil {
				t.Fatal(err)
			}
			y, err := crandIntForTest(rng, spec.BoundY)
			if err != nil {
				t.Fatal(err)
			}
			if rng.Intn(2) == 1 {
				x.Neg(x)
			}
			if rng.Intn(2) == 1 {
				y.Neg(y)
			}
			exactGCTestMulCircuit(t, spec, []*big.Int{x}, []*big.Int{y}, rng,
				i&1 == 1)
		}
	}
}

func TestExactGCDirectMulInvalidVectorClearsEveryArithmeticOutput(t *testing.T) {
	spec := exactGCTestMulSpec(63, 1, 2)
	spec.MulBackend = exactGCMulBackendDirect
	rng := rand.New(rand.NewSource(20260806))
	xValues := []*big.Int{
		big.NewInt(-3),
		new(big.Int).Add(new(big.Int).Set(spec.BoundX), big.NewInt(1)),
	}
	yValues := []*big.Int{big.NewInt(1), big.NewInt(1)}
	xResidues := make([]*big.Int, spec.VectorLen)
	yResidues := make([]*big.Int, spec.VectorLen)
	for i := range xValues {
		xResidues[i] = exactGCEncodeSigned(xValues[i], spec.RingBits)
		yResidues[i] = exactGCEncodeSigned(yValues[i], spec.RingBits)
	}
	xa, xb := exactGCTestSplit(rng, xResidues, spec.RingBits)
	ya, yb := exactGCTestSplit(rng, yResidues, spec.RingBits)
	garblerShares := append(append([]*big.Int{}, xa...), ya...)
	evaluatorShares := append(append([]*big.Int{}, xb...), yb...)
	masks := []*big.Int{
		exactGCTestRandomResidue(rng, spec.RingBits),
		exactGCTestRandomResidue(rng, spec.RingBits),
		big.NewInt(0),
	}
	circ, err := exactGCCompileCircuit(spec)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := circ.Compute([]*big.Int{
		exactGCPackGarblerInput(garblerShares, masks, spec),
		exactGCPackChunks(evaluatorShares, exactGCTypeBits(spec.RingBits)),
	})
	if err != nil {
		t.Fatal(err)
	}
	output := exactGCUnpackOutputs(packed[0], spec)
	if output[spec.VectorLen].Bit(0) != 0 {
		t.Fatal("out-of-bound direct multiplication was marked valid")
	}
	for i := 0; i < spec.VectorLen; i++ {
		reconstructed := exactGCReferenceReconstruct(
			masks[i], output[i], spec.RingBits)
		if reconstructed.Sign() != 0 {
			t.Fatalf("invalid aggregate retained arithmetic output %d: %s",
				i, reconstructed)
		}
	}
}

// crandIntForTest samples deterministically from [0,max] using math/rand.
func crandIntForTest(rng *rand.Rand, max *big.Int) (*big.Int, error) {
	if max.Sign() < 0 {
		return nil, fmt.Errorf("negative test bound")
	}
	bytes := make([]byte, (max.BitLen()+7)/8)
	for {
		if _, err := rng.Read(bytes); err != nil {
			return nil, err
		}
		value := new(big.Int).SetBytes(bytes)
		if value.Cmp(max) <= 0 {
			return value, nil
		}
	}
}

func TestExactGCMulTruncateCheckedMultiprecisionCore(t *testing.T) {
	rng := rand.New(rand.NewSource(1234))
	for _, bits := range []int{256, 512, 513} {
		spec := exactGCTestMulSpec(bits, 50, 1)
		x := new(big.Int).Sub(new(big.Int).Set(spec.BoundX), big.NewInt(17))
		y := new(big.Int).Neg(new(big.Int).Sub(
			new(big.Int).Set(spec.BoundY), big.NewInt(31)))
		exactGCTestMulCircuit(t, spec, []*big.Int{x}, []*big.Int{y}, rng, true)
	}
}

func TestExactGCMulTruncateCheckedVectorShapes(t *testing.T) {
	for _, n := range []int{1, 64} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			spec := exactGCTestMulSpec(127, 50, n)
			x := make([]*big.Int, n)
			y := make([]*big.Int, n)
			for i := 0; i < n; i++ {
				x[i] = big.NewInt(int64(i - n/2))
				y[i] = big.NewInt(int64(3 - i%7))
			}
			circ, err := exactGCCompileCircuit(spec)
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, gate := range circ.Gates {
				counts[gate.Op.String()]++
			}
			t.Logf("Ring127 checked mul-truncate n=%d: gates=%d wires=%d ops=%v", n,
				circ.NumGates, circ.NumWires, counts)
			exactGCTestMulCircuit(t, spec, x, y,
				rand.New(rand.NewSource(int64(n))), true)
		})
	}
}

func TestExactGCMulTruncateCheckedResourcePolicy(t *testing.T) {
	spec := exactGCTestMulSpec(127, 50, 64)
	if got, want := exactGCCircuitInputBits(spec), 128*(7*64+1); got != want {
		t.Fatalf("checked multiplication input accounting got=%d want=%d", got, want)
	}
	tooLarge := exactGCTestMulSpec(127, 50, exactGCMaxHybridVectorLen+1)
	if err := tooLarge.validate(); err == nil {
		t.Fatal("checked multiplication accepted an unbounded hybrid shape")
	}
	directTooLarge := exactGCTestMulSpec(127, 50, exactGCMaxDirectMulLen+1)
	directTooLarge.MulBackend = exactGCMulBackendDirect
	if _, err := exactGCCompileCircuit(directTooLarge); err == nil {
		t.Fatal("direct checked multiplier accepted a hybrid-sized vector")
	}
}

func TestExactGCHybridMulProtocolExactGuardedAndFresh(t *testing.T) {
	for _, fracBits := range []int{16, 50} {
		t.Run(fmt.Sprintf("f%d", fracBits), func(t *testing.T) {
			spec := exactGCTestMulSpec(127, fracBits, 6)
			spec.MulBackend = exactGCMulBackendHybrid
			scale := new(big.Int).Lsh(big.NewInt(1), uint(fracBits))
			x := []*big.Int{
				big.NewInt(0), big.NewInt(1), big.NewInt(-1),
				new(big.Int).Add(new(big.Int).Set(scale), big.NewInt(3)),
				new(big.Int).Neg(new(big.Int).Add(new(big.Int).Set(scale), big.NewInt(7))),
				new(big.Int).Set(spec.BoundX),
			}
			y := []*big.Int{
				big.NewInt(-1), new(big.Int).Set(scale), new(big.Int).Neg(new(big.Int).Set(scale)),
				big.NewInt(-3), big.NewInt(5), new(big.Int).Set(spec.BoundY),
			}
			xResidues := make([]*big.Int, spec.VectorLen)
			yResidues := make([]*big.Int, spec.VectorLen)
			for i := range x {
				xResidues[i] = exactGCEncodeSigned(x[i], spec.RingBits)
				yResidues[i] = exactGCEncodeSigned(y[i], spec.RingBits)
			}
			rng := rand.New(rand.NewSource(20260805))
			xa, xb := exactGCTestSplit(rng, xResidues, spec.RingBits)
			ya, yb := exactGCTestSplit(rng, yResidues, spec.RingBits)
			garblerInput := append(append([]*big.Int{}, xa...), ya...)
			evaluatorInput := append(append([]*big.Int{}, xb...), yb...)
			g0, e0 := exactGCTestRunProtocol(t, spec, garblerInput, evaluatorInput)
			g1, e1 := exactGCTestRunProtocol(t, spec, garblerInput, evaluatorInput)
			if g0[spec.VectorLen].Bit(0) == e0[spec.VectorLen].Bit(0) ||
				g1[spec.VectorLen].Bit(0) == e1[spec.VectorLen].Bit(0) {
				t.Fatal("in-bound hybrid multiplication was not marked valid")
			}
			allGarblerSharesEqual := true
			for i := range x {
				want, valid := exactGCReferenceMulTruncateChecked(
					xa[i], xb[i], ya[i], yb[i], spec)
				if !valid {
					t.Fatalf("fixture %d unexpectedly violates the raw-product guard", i)
				}
				for run, shares := range [][2][]*big.Int{{g0, e0}, {g1, e1}} {
					got := exactGCReferenceReconstruct(shares[0][i], shares[1][i], spec.RingBits)
					if got.Cmp(want) != 0 {
						t.Fatalf("run %d element %d: got %s want %s", run, i, got, want)
					}
				}
				allGarblerSharesEqual = allGarblerSharesEqual && g0[i].Cmp(g1[i]) == 0
			}
			if allGarblerSharesEqual {
				t.Fatal("hybrid multiplication reused every arithmetic output share")
			}

			invalidX := append([]*big.Int{}, xResidues...)
			invalidX[0] = exactGCEncodeSigned(
				new(big.Int).Add(spec.BoundX, big.NewInt(1)), spec.RingBits)
			invalidXA, invalidXB := exactGCTestSplit(rng, invalidX, spec.RingBits)
			invalidG := append(append([]*big.Int{}, invalidXA...), ya...)
			invalidE := append(append([]*big.Int{}, invalidXB...), yb...)
			gInvalid, eInvalid := exactGCTestRunProtocol(t, spec, invalidG, invalidE)
			if gInvalid[spec.VectorLen].Bit(0) != eInvalid[spec.VectorLen].Bit(0) {
				t.Fatal("out-of-bound hybrid multiplication was marked valid")
			}
			for i := 0; i < spec.VectorLen; i++ {
				got := exactGCReferenceReconstruct(
					gInvalid[i], eInvalid[i], spec.RingBits)
				if got.Sign() != 0 {
					t.Fatalf("invalid hybrid aggregate exposed element %d: %s", i, got)
				}
			}
		})
	}
}

func TestExactGCCircuitCacheIsBounded(t *testing.T) {
	for frac := 0; frac < exactGCCircuitCacheEntries+3; frac++ {
		if _, err := exactGCCompileCircuit(exactGCTestMulSpec(63, frac, 1)); err != nil {
			t.Fatal(err)
		}
	}
	exactGCCircuitCache.Lock()
	defer exactGCCircuitCache.Unlock()
	if got := len(exactGCCircuitCache.entries); got > exactGCCircuitCacheEntries {
		t.Fatalf("circuit cache grew to %d entries, policy is %d", got,
			exactGCCircuitCacheEntries)
	}
}
