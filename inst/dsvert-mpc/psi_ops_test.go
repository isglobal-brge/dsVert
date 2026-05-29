package main

import (
	"encoding/base64"
	"reflect"
	"strconv"
	"testing"
)

func scalarForSeed(seed string) (string, error) {
	k, err := deriveOPRFScalar(seed, "test-scalar-domain")
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), nil
}

func fixedScalar(t *testing.T, seed string) string {
	t.Helper()
	out, err := scalarForSeed(seed)
	if err != nil {
		t.Fatalf("derive scalar: %v", err)
	}
	return out
}

func runTwoPartyPSI(t *testing.T, refIDs, targetIDs []string, mode, key, study string) *PSIMatchOutput {
	t.Helper()
	ref, err := psiMask(&PSIMaskInput{
		IDs:           refIDs,
		Scalar:        fixedScalar(t, "ref"),
		PseudonymMode: mode,
		PseudonymKey:  key,
		StudyID:       study,
	})
	if err != nil {
		t.Fatalf("ref mask: %v", err)
	}
	target, err := psiMask(&PSIMaskInput{
		IDs:           targetIDs,
		Scalar:        fixedScalar(t, "target"),
		PseudonymMode: mode,
		PseudonymKey:  key,
		StudyID:       study,
	})
	if err != nil {
		t.Fatalf("target mask: %v", err)
	}
	refDoubled, err := psiDoubleMask(&PSIDoubleMaskInput{
		Points: ref.MaskedPoints,
		Scalar: target.Scalar,
	})
	if err != nil {
		t.Fatalf("double mask ref: %v", err)
	}
	targetDoubled, err := psiDoubleMask(&PSIDoubleMaskInput{
		Points: target.MaskedPoints,
		Scalar: ref.Scalar,
	})
	if err != nil {
		t.Fatalf("double mask target: %v", err)
	}
	refIndices := make([]int, len(refIDs))
	for i := range refIndices {
		refIndices[i] = i
	}
	match, err := psiMatch(&PSIMatchInput{
		OwnDoubled: targetDoubled.DoubleMaskedPoints,
		RefDoubled: refDoubled.DoubleMaskedPoints,
		RefIndices: refIndices,
	})
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	return match
}

func TestPSISharedKeyPreservesIntersection(t *testing.T) {
	match := runTwoPartyPSI(
		t,
		[]string{"id-A", "id-B", "id-C", "id-D"},
		[]string{"id-C", "id-A", "id-E"},
		"shared_key",
		"study-key-material",
		"study-1",
	)
	if match.NMatched != 2 {
		t.Fatalf("NMatched = %d, want 2", match.NMatched)
	}
	if !reflect.DeepEqual(match.MatchedRefIndices, []int{0, 2}) {
		t.Fatalf("MatchedRefIndices = %v, want [0 2]", match.MatchedRefIndices)
	}
	if !reflect.DeepEqual(match.MatchedOwnRows, []int{1, 0}) {
		t.Fatalf("MatchedOwnRows = %v, want [1 0]", match.MatchedOwnRows)
	}
}

func TestPSIRawAndSharedKeySemanticsMatchOnFixture(t *testing.T) {
	refIDs := []string{"id-1", "id-2", "id-3", "id-4", "id-5"}
	targetIDs := []string{"id-5", "id-3", "id-1", "id-X"}
	raw := runTwoPartyPSI(t, refIDs, targetIDs, "none", "", "")
	keyed := runTwoPartyPSI(t, refIDs, targetIDs, "shared_key", "k", "study")
	if !reflect.DeepEqual(raw.MatchedRefIndices, keyed.MatchedRefIndices) ||
		!reflect.DeepEqual(raw.MatchedOwnRows, keyed.MatchedOwnRows) {
		t.Fatalf("shared-key PSI changed intersection/order: raw=%+v keyed=%+v", raw, keyed)
	}
}

func TestPSISharedKeyCrossStudyUnlinkability(t *testing.T) {
	id := "patient-00042"
	key := "study-key-material"
	a, err := keyedPseudonymIdentifier(id, key, "study-A")
	if err != nil {
		t.Fatalf("pseudonym A: %v", err)
	}
	b, err := keyedPseudonymIdentifier(id, key, "study-B")
	if err != nil {
		t.Fatalf("pseudonym B: %v", err)
	}
	if a == b {
		t.Fatalf("same identifier produced identical pseudonym across studies")
	}
}

func TestPSINonKeyHolderCannotComputeSharedKeyToken(t *testing.T) {
	id := "patient-00042"
	scalar := fixedScalar(t, "same-mask-scalar")
	raw, err := psiMask(&PSIMaskInput{IDs: []string{id}, Scalar: scalar})
	if err != nil {
		t.Fatalf("raw mask: %v", err)
	}
	keyed, err := psiMask(&PSIMaskInput{
		IDs:           []string{id},
		Scalar:        scalar,
		PseudonymMode: "shared_key",
		PseudonymKey:  "study-key-material",
		StudyID:       "study-A",
	})
	if err != nil {
		t.Fatalf("keyed mask: %v", err)
	}
	if raw.MaskedPoints[0] == keyed.MaskedPoints[0] {
		t.Fatalf("raw identifier mapping unexpectedly equals keyed mapping")
	}
}

func TestPSISharedKeyRequiresKey(t *testing.T) {
	_, err := psiMask(&PSIMaskInput{
		IDs:           []string{"id-1"},
		PseudonymMode: "shared_key",
		StudyID:       "study",
	})
	if err == nil {
		t.Fatalf("shared_key mode without key succeeded")
	}
}

func BenchmarkPSIMaskRaw1000(b *testing.B) {
	ids := make([]string, 1000)
	for i := range ids {
		ids[i] = "patient-" + strconv.Itoa(i)
	}
	scalar, err := scalarForSeed("bench")
	if err != nil {
		b.Fatal(err)
	}
	input := &PSIMaskInput{IDs: ids, Scalar: scalar}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := psiMask(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPSIMaskSharedKey1000(b *testing.B) {
	ids := make([]string, 1000)
	for i := range ids {
		ids[i] = "patient-" + strconv.Itoa(i)
	}
	scalar, err := scalarForSeed("bench")
	if err != nil {
		b.Fatal(err)
	}
	input := &PSIMaskInput{
		IDs:           ids,
		Scalar:        scalar,
		PseudonymMode: "shared_key",
		PseudonymKey:  "study-key-material",
		StudyID:       "study-A",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := psiMask(input); err != nil {
			b.Fatal(err)
		}
	}
}
