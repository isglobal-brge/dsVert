package main

import (
	"testing"
)

func TestHashToP256PointDeterminism(t *testing.T) {
	x1, y1 := hashToP256Point("PATIENT_001")
	x2, y2 := hashToP256Point("PATIENT_001")

	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.Error("hash-to-curve not deterministic")
	}
}

func TestHashToP256PointDistinct(t *testing.T) {
	x1, _ := hashToP256Point("PATIENT_001")
	x2, _ := hashToP256Point("PATIENT_002")

	if x1.Cmp(x2) == 0 {
		t.Error("different IDs produced the same point")
	}
}

func TestPointEncodeDecode(t *testing.T) {
	x, y := hashToP256Point("TEST")
	encoded := encodePoint(x, y)
	dx, dy, err := decodePoint(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if x.Cmp(dx) != 0 || y.Cmp(dy) != 0 {
		t.Error("point encode/decode round-trip failed")
	}
}

func TestCommutativity(t *testing.T) {
	alpha, err := generateScalar()
	if err != nil {
		t.Fatal(err)
	}
	beta, err := generateScalar()
	if err != nil {
		t.Fatal(err)
	}

	px, py := hashToP256Point("COMMUTATIVITY_TEST")

	// alpha * (beta * P)
	bpx, bpy := p256Curve.ScalarMult(px, py, beta.Bytes())
	abpx, abpy := p256Curve.ScalarMult(bpx, bpy, alpha.Bytes())

	// beta * (alpha * P)
	apx, apy := p256Curve.ScalarMult(px, py, alpha.Bytes())
	bapx, bapy := p256Curve.ScalarMult(apx, apy, beta.Bytes())

	if abpx.Cmp(bapx) != 0 || abpy.Cmp(bapy) != 0 {
		t.Error("scalar multiplication not commutative")
	}
}

func TestPSIFullProtocol(t *testing.T) {
	refIDs := []string{"A", "B", "C", "D", "E"}
	targetIDs := []string{"C", "X", "A", "Y", "E"}

	refResult, err := psiMask(&PSIMaskInput{IDs: refIDs})
	if err != nil {
		t.Fatal(err)
	}

	targetResult, err := psiMask(&PSIMaskInput{IDs: targetIDs})
	if err != nil {
		t.Fatal(err)
	}

	// Target double-masks ref points
	refDoubled, err := psiDoubleMask(&PSIDoubleMaskInput{
		Points: refResult.MaskedPoints,
		Scalar: targetResult.Scalar,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Ref double-masks target points
	targetDoubled, err := psiDoubleMask(&PSIDoubleMaskInput{
		Points: targetResult.MaskedPoints,
		Scalar: refResult.Scalar,
	})
	if err != nil {
		t.Fatal(err)
	}

	refIndices := make([]int, len(refIDs))
	for i := range refIndices {
		refIndices[i] = i
	}

	matchResult, err := psiMatch(&PSIMatchInput{
		OwnDoubled: targetDoubled.DoubleMaskedPoints,
		RefDoubled: refDoubled.DoubleMaskedPoints,
		RefIndices: refIndices,
	})
	if err != nil {
		t.Fatal(err)
	}

	if matchResult.NMatched != 3 {
		t.Fatalf("expected 3 matches, got %d", matchResult.NMatched)
	}

	// Verify matched IDs are correct
	for i, ownRow := range matchResult.MatchedOwnRows {
		refIdx := matchResult.MatchedRefIndices[i]
		if targetIDs[ownRow] != refIDs[refIdx] {
			t.Errorf("mismatch: target[%d]=%s != ref[%d]=%s",
				ownRow, targetIDs[ownRow], refIdx, refIDs[refIdx])
		}
	}
}

func TestPSINoOverlap(t *testing.T) {
	refResult, _ := psiMask(&PSIMaskInput{IDs: []string{"A", "B"}})
	targetResult, _ := psiMask(&PSIMaskInput{IDs: []string{"C", "D"}})

	refDoubled, _ := psiDoubleMask(&PSIDoubleMaskInput{
		Points: refResult.MaskedPoints, Scalar: targetResult.Scalar,
	})
	targetDoubled, _ := psiDoubleMask(&PSIDoubleMaskInput{
		Points: targetResult.MaskedPoints, Scalar: refResult.Scalar,
	})

	result, _ := psiMatch(&PSIMatchInput{
		OwnDoubled: targetDoubled.DoubleMaskedPoints,
		RefDoubled: refDoubled.DoubleMaskedPoints,
		RefIndices: []int{0, 1},
	})

	if result.NMatched != 0 {
		t.Errorf("expected 0 matches, got %d", result.NMatched)
	}
}

func TestPSIFullOverlap(t *testing.T) {
	ids := []string{"A", "B", "C"}
	refResult, _ := psiMask(&PSIMaskInput{IDs: ids})
	targetResult, _ := psiMask(&PSIMaskInput{IDs: ids})

	refDoubled, _ := psiDoubleMask(&PSIDoubleMaskInput{
		Points: refResult.MaskedPoints, Scalar: targetResult.Scalar,
	})
	targetDoubled, _ := psiDoubleMask(&PSIDoubleMaskInput{
		Points: targetResult.MaskedPoints, Scalar: refResult.Scalar,
	})

	result, _ := psiMatch(&PSIMatchInput{
		OwnDoubled: targetDoubled.DoubleMaskedPoints,
		RefDoubled: refDoubled.DoubleMaskedPoints,
		RefIndices: []int{0, 1, 2},
	})

	if result.NMatched != 3 {
		t.Errorf("expected 3 matches, got %d", result.NMatched)
	}
}

func TestPSISingleElement(t *testing.T) {
	refResult, _ := psiMask(&PSIMaskInput{IDs: []string{"ONLY"}})
	targetResult, _ := psiMask(&PSIMaskInput{IDs: []string{"ONLY"}})

	refDoubled, _ := psiDoubleMask(&PSIDoubleMaskInput{
		Points: refResult.MaskedPoints, Scalar: targetResult.Scalar,
	})
	targetDoubled, _ := psiDoubleMask(&PSIDoubleMaskInput{
		Points: targetResult.MaskedPoints, Scalar: refResult.Scalar,
	})

	result, _ := psiMatch(&PSIMatchInput{
		OwnDoubled: targetDoubled.DoubleMaskedPoints,
		RefDoubled: refDoubled.DoubleMaskedPoints,
		RefIndices: []int{0},
	})

	if result.NMatched != 1 {
		t.Errorf("expected 1 match, got %d", result.NMatched)
	}
}
