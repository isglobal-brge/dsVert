package main

import (
	"encoding/base64"
	"fmt"
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

// ============================================================================
// Binary EC Point Pack/Unpack Tests
// ============================================================================

func TestPackUnpackRoundTrip(t *testing.T) {
	// Generate 100 random points via PSI mask
	ids := make([]string, 100)
	for i := range ids {
		ids[i] = fmt.Sprintf("PACK_TEST_%d", i)
	}

	result, err := psiMask(&PSIMaskInput{IDs: ids})
	if err != nil {
		t.Fatal(err)
	}

	packed, err := marshalECPointsBinary(result.MaskedPoints)
	if err != nil {
		t.Fatal(err)
	}

	unpacked, err := unmarshalECPointsBinary(packed)
	if err != nil {
		t.Fatal(err)
	}

	if len(unpacked) != len(result.MaskedPoints) {
		t.Fatalf("expected %d points, got %d", len(result.MaskedPoints), len(unpacked))
	}
	for i, pt := range result.MaskedPoints {
		if unpacked[i] != pt {
			t.Errorf("point %d mismatch: expected %s, got %s", i, pt, unpacked[i])
		}
	}
}

func TestPackUnpackEmpty(t *testing.T) {
	packed, err := marshalECPointsBinary([]string{})
	if err != nil {
		t.Fatal(err)
	}

	if len(packed) != 4 {
		t.Fatalf("expected 4 bytes for empty pack, got %d", len(packed))
	}

	unpacked, err := unmarshalECPointsBinary(packed)
	if err != nil {
		t.Fatal(err)
	}

	if len(unpacked) != 0 {
		t.Fatalf("expected 0 points, got %d", len(unpacked))
	}
}

func TestPackUnpackSinglePoint(t *testing.T) {
	result, err := psiMask(&PSIMaskInput{IDs: []string{"SINGLE"}})
	if err != nil {
		t.Fatal(err)
	}

	packed, err := marshalECPointsBinary(result.MaskedPoints)
	if err != nil {
		t.Fatal(err)
	}

	if len(packed) != 4+33 {
		t.Fatalf("expected %d bytes, got %d", 4+33, len(packed))
	}

	unpacked, err := unmarshalECPointsBinary(packed)
	if err != nil {
		t.Fatal(err)
	}

	if len(unpacked) != 1 || unpacked[0] != result.MaskedPoints[0] {
		t.Errorf("single point round-trip failed")
	}
}

func TestPackInvalidPointLength(t *testing.T) {
	// A point that decodes to wrong length
	shortPoint := base64.StdEncoding.EncodeToString([]byte{0x02, 0x01, 0x02})
	_, err := marshalECPointsBinary([]string{shortPoint})
	if err == nil {
		t.Error("expected error for short point, got nil")
	}
}

func TestPackInvalidPointPrefix(t *testing.T) {
	// 33 bytes but wrong prefix
	bad := make([]byte, 33)
	bad[0] = 0x04 // uncompressed prefix (wrong)
	badB64 := base64.StdEncoding.EncodeToString(bad)
	_, err := marshalECPointsBinary([]string{badB64})
	if err == nil {
		t.Error("expected error for invalid prefix, got nil")
	}
}

func TestUnpackTruncatedData(t *testing.T) {
	// Claim 5 points but only provide 2 points of data
	result, err := psiMask(&PSIMaskInput{IDs: []string{"A", "B"}})
	if err != nil {
		t.Fatal(err)
	}

	packed, err := marshalECPointsBinary(result.MaskedPoints)
	if err != nil {
		t.Fatal(err)
	}

	// Truncate to just 1 point worth of data but leave count as 2
	truncated := packed[:4+33]
	// Tamper the count to 5
	truncated[0] = 5
	truncated[1] = 0
	truncated[2] = 0
	truncated[3] = 0

	_, err = unmarshalECPointsBinary(truncated)
	if err == nil {
		t.Error("expected error for truncated data, got nil")
	}
}

func TestPackUnpackSizeSavings(t *testing.T) {
	// Verify binary packing is smaller than comma-separated base64 strings
	// Compare raw byte sizes (what goes into AES-GCM plaintext)
	ids := make([]string, 500)
	for i := range ids {
		ids[i] = fmt.Sprintf("SIZE_TEST_%d", i)
	}

	result, err := psiMask(&PSIMaskInput{IDs: ids})
	if err != nil {
		t.Fatal(err)
	}

	packed, err := marshalECPointsBinary(result.MaskedPoints)
	if err != nil {
		t.Fatal(err)
	}

	// Old format: comma-separated base64 strings converted to raw bytes
	// (as charToRaw would do in R before transport-encrypt)
	oldFormat := ""
	for i, pt := range result.MaskedPoints {
		if i > 0 {
			oldFormat += ","
		}
		oldFormat += pt
	}
	oldRawSize := len([]byte(oldFormat))

	// New format: binary packed raw bytes (before base64 for transport-encrypt)
	newRawSize := len(packed)

	ratio := float64(oldRawSize) / float64(newRawSize)
	t.Logf("Old raw: %d bytes, Packed raw: %d bytes, ratio: %.2fx", oldRawSize, newRawSize, ratio)

	// Binary packing: 4 + 500*33 = 16504 vs ~22500 chars → ~1.36x
	if ratio < 1.3 {
		t.Errorf("expected at least 1.3x raw size reduction, got %.2fx", ratio)
	}
}
