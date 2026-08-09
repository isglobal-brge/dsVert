package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// This is the pre-fixed-limb v3 implementation retained only as a test oracle.
// It must never be used by the productive path because math/big operations and
// the Bernoulli branch have private-randomness-dependent timing.
func jointDPVectorConvolutionLegacyNoise(t testing.TB, seed [32]byte,
	spec jointDPVectorConvolutionSpec) []*big.Int {
	t.Helper()
	cipher, err := jointDPVectorConvolutionPrivateCipher(seed, spec)
	if err != nil {
		t.Fatal(err)
	}
	thresholds := make([]*big.Int, len(spec.plan.BernoulliThresholds))
	for index, text := range spec.plan.BernoulliThresholds {
		thresholds[index], err = jointDPVectorParseInt(
			text, "legacy Bernoulli threshold", false)
		if err != nil {
			t.Fatal(err)
		}
	}
	defer exactGCZeroBigInts(thresholds)
	bytesPerWord := spec.plan.UniformBits / 8
	coordinateBytes := 2 * spec.plan.BinaryGeometricBits * bytesPerWord
	stream := make([]byte, coordinateBytes)
	word := make([]byte, bytesPerWord)
	defer clear(stream)
	defer clear(word)
	result := make([]*big.Int, spec.input.CoordinateCount)
	var geometric [2]big.Int
	var random big.Int
	for coordinate := range result {
		clear(stream)
		cipher.XORKeyStream(stream, stream)
		geometric[0].SetInt64(0)
		geometric[1].SetInt64(0)
		for draw := range geometric {
			for bit, threshold := range thresholds {
				offset := (draw*spec.plan.BinaryGeometricBits + bit) * bytesPerWord
				for index := 0; index < bytesPerWord; index++ {
					word[bytesPerWord-index-1] = stream[offset+index]
				}
				random.SetBytes(word)
				if random.Cmp(threshold) < 0 {
					geometric[draw].SetBit(&geometric[draw], bit, 1)
				}
			}
		}
		result[coordinate] = new(big.Int).Sub(&geometric[0], &geometric[1])
	}
	geometric[0].SetInt64(0)
	geometric[1].SetInt64(0)
	random.SetInt64(0)
	return result
}

func jointDPVectorConvolutionLegacyNoisedShare(t testing.TB,
	input jointDPVectorConvolutionShareInput, noise []*big.Int) string {
	t.Helper()
	shareBytes, err := base64.StdEncoding.Strict().DecodeString(input.SourceShare)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(shareBytes)
	modulus := exactGCModulus(128)
	noised := make([]byte, len(shareBytes))
	defer clear(noised)
	for index := range noise {
		share := exactGCLittleEndianBig(shareBytes[index*16 : (index+1)*16])
		share.Lsh(share, uint(input.ScaleShifts[index]))
		share.Add(share, noise[index])
		share.Mod(share, modulus)
		record, encodeErr := exactGCBigLittleEndian(share, 16)
		share.SetInt64(0)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		copy(noised[index*16:], record)
		clear(record)
	}
	return base64.StdEncoding.EncodeToString(noised)
}

func jointDPVectorConvolutionTestInput(t testing.TB, peer string,
	seed [32]byte, source []*big.Int, rawUpper []int64,
	shifts []int) jointDPVectorConvolutionShareInput {
	t.Helper()
	transcript := sha256.Sum256([]byte("convolution/transcript/" + t.Name()))
	context := jointDPCommitmentContext(transcript, "convolution", peer)
	commitment := jointDPSeedCommitment(context, seed)
	release := sha256.Sum256([]byte("convolution/release/" + t.Name()))
	encoded, err := exactGCEncodeWorkerCanonicalShares(source,
		exactGCCircuitSpec{Operation: jointDPVectorOperation,
			RingBits: 128, FracBits: 0, VectorLen: len(source)})
	if err != nil {
		t.Fatal(err)
	}
	upper := make([]string, len(rawUpper))
	for index, value := range rawUpper {
		upper[index] = big.NewInt(value).String()
	}
	return jointDPVectorConvolutionShareInput{
		Version:  jointDPVectorConvolutionInputVersion,
		RingBits: 128, FracBits: 0,
		TotalCoordinateCount: len(source), ChunkStart: 0,
		CoordinateCount: len(source), OutputLatticeBits: 8,
		Epsilon: "1", AllocatedDelta: "7.888609052210118e-31",
		SensitivitySteps: "256", ScaleShifts: append([]int(nil), shifts...),
		RawUpperBounds:      upper,
		ReleaseContractHash: hex.EncodeToString(release[:]),
		TranscriptHash:      hex.EncodeToString(transcript[:]), PeerName: peer,
		CommitmentContext: hex.EncodeToString(context[:]),
		SeedCommitment:    hex.EncodeToString(commitment[:]),
		PrivateSeed:       hex.EncodeToString(seed[:]), SourceShare: encoded,
	}
}

func jointDPVectorConvolutionSplit(raw []*big.Int) ([]*big.Int, []*big.Int) {
	modulus := exactGCModulus(128)
	left := make([]*big.Int, len(raw))
	right := make([]*big.Int, len(raw))
	for index, value := range raw {
		digest := sha256.Sum256(
			[]byte("convolution-mask-" + string(rune(index))))
		mask := new(big.Int).SetBytes(digest[:])
		mask.Mod(mask, modulus)
		left[index] = mask
		right[index] = new(big.Int).Sub(value, mask)
		right[index].Mod(right[index], modulus)
	}
	return left, right
}

func jointDPVectorConvolutionDecodeOutputShare(t testing.TB,
	value string, count int) []*big.Int {
	t.Helper()
	records, err := exactGCDecodeWorkerCanonicalShares(value,
		exactGCCircuitSpec{Operation: jointDPVectorOperation,
			RingBits: 128, FracBits: 0, VectorLen: count})
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestJointDPVectorConvolutionPlanCertifiesEachCompletePeerDraw(t *testing.T) {
	plan, err := jointDPPlanVectorConvolutionLaplace(jointDPVectorPlanInput{
		Epsilon: "1", Delta: "7.888609052210118e-31",
		SensitivitySteps: "256", TotalCoordinateCount: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Version != jointDPVectorConvolutionPlanVersion ||
		plan.Sampler != jointDPVectorConvolutionSamplerVersion ||
		plan.IndependentNoisePeerCount != 2 ||
		!plan.CompleteEpsilonPerPeer || plan.EpsilonDividedByPeerCount ||
		plan.GeometricVariablesPerPeerPerCoordinate != 2 ||
		plan.GeometricVariablesTotalPerCoordinate != 4 {
		t.Fatalf("invalid convolution accounting contract: %#v", plan)
	}
	total := jointDPTestRat(t, plan.ImplementationDeltaNumerator,
		plan.ImplementationDeltaDenominator)
	perPeer := jointDPTestRat(t, plan.PerPeerImplementationDeltaNumerator,
		plan.PerPeerImplementationDeltaDenominator)
	idealTransfer := jointDPTestRat(t, plan.TwoPeerIdealTransferDeltaNumerator,
		plan.TwoPeerIdealTransferDeltaDenominator)
	if perPeer.Cmp(total) != 0 ||
		new(big.Rat).Mul(perPeer, big.NewRat(2, 1)).Cmp(idealTransfer) != 0 ||
		plan.ReleaseImplementationDeltaAggregation != "max_per_peer_not_sum" {
		t.Fatal("release delta did not use max(per-peer) with a separate two-peer ideal-transfer bound")
	}
	exactGCPlan, err := jointDPPlanVectorLaplace(jointDPVectorPlanInput{
		Epsilon: "1", Delta: "7.888609052210118e-31",
		SensitivitySteps: "256", TotalCoordinateCount: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.BinaryGeometricBits != exactGCPlan.BinaryGeometricBits ||
		plan.ImplementationDeltaBound != exactGCPlan.ImplementationDeltaBound {
		t.Fatal("one complete convolution peer differs from the one-mechanism exact-GC certificate")
	}
}

func TestJointDPVectorConvolutionEndToEndCommonLatticeAndClamp(t *testing.T) {
	raw := []*big.Int{big.NewInt(0), big.NewInt(17), big.NewInt(20)}
	leftSource, rightSource := jointDPVectorConvolutionSplit(raw)
	leftSeed := sha256.Sum256([]byte("convolution-left-seed"))
	rightSeed := sha256.Sum256([]byte("convolution-right-seed"))
	shifts := []int{8, 0, 8}
	upper := []int64{10, 100, 20}
	leftInput := jointDPVectorConvolutionTestInput(
		t, "peer-a", leftSeed, leftSource, upper, shifts)
	rightInput := jointDPVectorConvolutionTestInput(
		t, "peer-b", rightSeed, rightSource, upper, shifts)
	// Both peer contracts belong to the same release/transcript.
	rightInput.ReleaseContractHash = leftInput.ReleaseContractHash
	rightInput.TranscriptHash = leftInput.TranscriptHash
	transcript, _ := jointDPDecodeHex32(leftInput.TranscriptHash, "transcript")
	rightContext := jointDPCommitmentContext(transcript, "convolution", "peer-b")
	rightCommitment := jointDPSeedCommitment(rightContext, rightSeed)
	rightInput.CommitmentContext = hex.EncodeToString(rightContext[:])
	rightInput.SeedCommitment = hex.EncodeToString(rightCommitment[:])

	leftSpec, err := jointDPVectorConvolutionParseSpec(leftInput)
	if err != nil {
		t.Fatal(err)
	}
	rightSpec, err := jointDPVectorConvolutionParseSpec(rightInput)
	if err != nil {
		t.Fatal(err)
	}
	leftNoise, err := jointDPVectorConvolutionNoise(leftSeed, leftSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(leftNoise)
	rightNoise, err := jointDPVectorConvolutionNoise(rightSeed, rightSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rightNoise)

	left, err := jointDPVectorConvolutionSampleShare(leftInput)
	if err != nil {
		t.Fatal(err)
	}
	right, err := jointDPVectorConvolutionSampleShare(rightInput)
	if err != nil {
		t.Fatal(err)
	}
	finalized, err := jointDPVectorConvolutionFinalize(
		jointDPVectorConvolutionFinalizerInput{
			Version:  jointDPVectorConvolutionFinalizerInputVersion,
			RingBits: 128, FracBits: 0,
			TotalCoordinateCount: len(raw), ChunkStart: 0,
			CoordinateCount: len(raw), OutputLatticeBits: 8,
			Epsilon:          leftInput.Epsilon,
			AllocatedDelta:   leftInput.AllocatedDelta,
			SensitivitySteps: leftInput.SensitivitySteps,
			ScaleShifts:      shifts, RawUpperBounds: leftInput.RawUpperBounds,
			ReleaseContractHash: leftInput.ReleaseContractHash,
			TranscriptHash:      leftInput.TranscriptHash,
			LeftNoisedShare:     left.NoisedShare,
			RightNoisedShare:    right.NoisedShare,
		})
	if err != nil {
		t.Fatal(err)
	}
	for index := range raw {
		want := new(big.Int).Lsh(new(big.Int).Set(raw[index]), uint(shifts[index]))
		want.Add(want, big.NewInt(leftNoise[index]))
		want.Add(want, big.NewInt(rightNoise[index]))
		bound := new(big.Int).Lsh(big.NewInt(upper[index]), uint(shifts[index]))
		if want.Sign() < 0 {
			want.SetInt64(0)
		} else if want.Cmp(bound) > 0 {
			want.Set(bound)
		}
		if finalized.ClampedScaledValues[index] != want.String() {
			t.Fatalf("coordinate %d=%s want=%s", index,
				finalized.ClampedScaledValues[index], want.String())
		}
	}
	if finalized.PreclampValuesReturned || !finalized.NoWrapHeadroomCertified {
		t.Fatal("finalizer exposed a pre-clamp value or omitted headroom proof")
	}
}

func TestJointDPVectorConvolutionStickyReplayRestartAndDataIndependentStream(t *testing.T) {
	raw := []*big.Int{big.NewInt(7), big.NewInt(11)}
	left, _ := jointDPVectorConvolutionSplit(raw)
	seed := sha256.Sum256([]byte("convolution-restart-seed"))
	input := jointDPVectorConvolutionTestInput(
		t, "peer-a", seed, left, []int64{20, 20}, []int{8, 8})
	first, err := jointDPVectorConvolutionSampleShare(input)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := jointDPVectorConvolutionDecode[jointDPVectorConvolutionShareInput](bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := jointDPVectorConvolutionSampleShare(restarted)
	if err != nil {
		t.Fatal(err)
	}
	if first.NoisedShare != replay.NoisedShare ||
		first.SamplerContractHash != replay.SamplerContractHash {
		t.Fatal("same durable capsule/chunk rerolled after restart")
	}

	// Changing the protected additive share must translate the output but must
	// not select a fresh random stream.
	changedSource := []*big.Int{
		new(big.Int).Add(left[0], big.NewInt(1)),
		new(big.Int).Add(left[1], big.NewInt(2)),
	}
	changed := input
	changed.SourceShare, err = exactGCEncodeWorkerCanonicalShares(changedSource,
		exactGCCircuitSpec{Operation: jointDPVectorOperation,
			RingBits: 128, VectorLen: len(changedSource)})
	if err != nil {
		t.Fatal(err)
	}
	translated, err := jointDPVectorConvolutionSampleShare(changed)
	if err != nil {
		t.Fatal(err)
	}
	firstResidues := jointDPVectorConvolutionDecodeOutputShare(
		t, first.NoisedShare, len(raw))
	changedResidues := jointDPVectorConvolutionDecodeOutputShare(
		t, translated.NoisedShare, len(raw))
	modulus := exactGCModulus(128)
	for index, delta := range []int64{1, 2} {
		got := new(big.Int).Sub(changedResidues[index], firstResidues[index])
		got.Mod(got, modulus)
		want := new(big.Int).Lsh(big.NewInt(delta), 8)
		if got.Cmp(want) != 0 {
			t.Fatalf("source change rerolled noise at %d: %s want %s",
				index, got, want)
		}
	}
}

func TestJointDPVectorConvolutionStreamingMatchesCanonicalWordOrder(t *testing.T) {
	seed := sha256.Sum256([]byte("convolution-stream-order-seed"))
	input := jointDPVectorConvolutionTestInput(t, "peer-a", seed,
		[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
		[]int64{10, 10, 10}, []int{8, 8, 8})
	spec, err := jointDPVectorConvolutionParseSpec(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := jointDPVectorConvolutionNoise(seed, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	want := jointDPVectorConvolutionLegacyNoise(t, seed, spec)
	defer exactGCZeroBigInts(want)
	for coordinate := 0; coordinate < spec.input.CoordinateCount; coordinate++ {
		if !want[coordinate].IsInt64() || got[coordinate] != want[coordinate].Int64() {
			t.Fatalf("coordinate %d stream order changed: got=%d want=%s",
				coordinate, got[coordinate], want[coordinate])
		}
	}
}

func jointDPVectorConvolutionTestLittleEndianWord(
	value *big.Int, uniformBits int,
) []byte {
	word := make([]byte, uniformBits/8)
	value.FillBytes(word)
	for left, right := 0, len(word)-1; left < right; left, right = left+1, right-1 {
		word[left], word[right] = word[right], word[left]
	}
	return word
}

func TestJointDPVectorConvolutionFixedThresholdMatchesBigIntOracle(t *testing.T) {
	for _, uniformBits := range []int{128, 256} {
		modulus := new(big.Int).Lsh(big.NewInt(1), uint(uniformBits))
		maximum := new(big.Int).Sub(new(big.Int).Set(modulus), big.NewInt(1))
		thresholds := []*big.Int{
			big.NewInt(0), big.NewInt(1),
			new(big.Int).Rsh(new(big.Int).Set(maximum), 1),
			new(big.Int).Set(maximum),
		}
		for thresholdIndex, threshold := range thresholds {
			fixed, err := jointDPVectorConvolutionFixedThreshold(
				threshold, uniformBits)
			if err != nil {
				t.Fatal(err)
			}
			values := []*big.Int{
				big.NewInt(0), new(big.Int).Set(threshold),
				new(big.Int).Set(maximum),
			}
			if threshold.Sign() > 0 {
				values = append(values,
					new(big.Int).Sub(new(big.Int).Set(threshold), big.NewInt(1)))
			}
			if threshold.Cmp(maximum) < 0 {
				values = append(values,
					new(big.Int).Add(new(big.Int).Set(threshold), big.NewInt(1)))
			}
			for sample := 0; sample < 64; sample++ {
				digest := sha256.Sum256([]byte{
					byte(uniformBits), byte(thresholdIndex), byte(sample)})
				candidate := new(big.Int).SetBytes(digest[:])
				candidate.Mod(candidate, modulus)
				values = append(values, candidate)
			}
			for _, value := range values {
				word := jointDPVectorConvolutionTestLittleEndianWord(
					value, uniformBits)
				got := jointDPVectorConvolutionLessFixed(
					word, fixed, uniformBits/64)
				want := uint64(0)
				if value.Cmp(threshold) < 0 {
					want = 1
				}
				clear(word)
				if got != want {
					t.Fatalf("u=%d threshold=%s value=%s: got=%d want=%d",
						uniformBits, threshold, value, got, want)
				}
				value.SetInt64(0)
			}
		}
		maximum.SetInt64(0)
		modulus.SetInt64(0)
	}
}

func TestJointDPVectorConvolutionFixedLimbMatchesLegacyAcrossChunkGeometries(
	t *testing.T,
) {
	type widthCase struct {
		name  string
		delta string
		bits  int
	}
	type geometryCase struct {
		total int
		start int
		count int
	}
	widths := []widthCase{
		{name: "uniform128", delta: "1e-30", bits: 128},
		{name: "uniform256", delta: "1e-38", bits: 256},
	}
	geometries := []geometryCase{
		{total: 1, start: 0, count: 1},
		{total: 17, start: 0, count: 7},
		{total: 64, start: 23, count: 19},
	}
	for _, width := range widths {
		t.Run(width.name, func(t *testing.T) {
			for geometryIndex, geometry := range geometries {
				source := make([]*big.Int, geometry.count)
				upper := make([]int64, geometry.count)
				shifts := make([]int, geometry.count)
				for index := range source {
					digest := sha256.Sum256([]byte{
						byte(width.bits), byte(geometryIndex), byte(index), 0xa7})
					source[index] = new(big.Int).SetBytes(digest[:16])
					upper[index] = int64(100 + index)
					shifts[index] = index % 9
				}
				seed := sha256.Sum256([]byte{
					byte(width.bits), byte(geometryIndex), 0x5c})
				input := jointDPVectorConvolutionTestInput(
					t, "peer-a", seed, source, upper, shifts)
				input.TotalCoordinateCount = geometry.total
				input.ChunkStart = geometry.start
				input.AllocatedDelta = width.delta
				input.SensitivitySteps = "1"
				spec, err := jointDPVectorConvolutionParseSpec(input)
				if err != nil {
					t.Fatal(err)
				}
				if spec.plan.UniformBits != width.bits {
					t.Fatalf("selected uniform width=%d want=%d",
						spec.plan.UniformBits, width.bits)
				}
				gotNoise, err := jointDPVectorConvolutionNoise(seed, spec)
				if err != nil {
					t.Fatal(err)
				}
				legacyNoise := jointDPVectorConvolutionLegacyNoise(t, seed, spec)
				for index := range gotNoise {
					if !legacyNoise[index].IsInt64() ||
						gotNoise[index] != legacyNoise[index].Int64() {
						t.Fatalf("geometry=%+v coordinate=%d noise=%d legacy=%s",
							geometry, index, gotNoise[index], legacyNoise[index])
					}
				}
				output, err := jointDPVectorConvolutionSampleShare(input)
				if err != nil {
					t.Fatal(err)
				}
				wantShare := jointDPVectorConvolutionLegacyNoisedShare(
					t, input, legacyNoise)
				if output.NoisedShare != wantShare {
					t.Fatalf("geometry=%+v changed sticky noised-share bytes",
						geometry)
				}
				clear(gotNoise)
				exactGCZeroBigInts(legacyNoise)
				exactGCZeroBigInts(source)
			}
		})
	}
}

func TestJointDPVectorConvolutionFixedRing128AddMatchesBigIntBoundaries(t *testing.T) {
	const maximumNoise int64 = 1<<63 - 1
	type addCase struct {
		low   uint64
		high  uint64
		shift int
		noise int64
	}
	cases := []addCase{
		{low: 0, high: 0, shift: 0, noise: -maximumNoise},
		{low: ^uint64(0), high: ^uint64(0), shift: 62, noise: maximumNoise},
		{low: 0x0123456789abcdef, high: 0xfedcba9876543210, shift: 17, noise: 0},
		{low: 0, high: 1 << 63, shift: 0, noise: -1},
	}
	share := make([]byte, 16*len(cases))
	shifts := make([]int, len(cases))
	noise := make([]int64, len(cases))
	for index, testCase := range cases {
		offset := 16 * index
		binary.LittleEndian.PutUint64(share[offset:offset+8], testCase.low)
		binary.LittleEndian.PutUint64(share[offset+8:offset+16], testCase.high)
		shifts[index] = testCase.shift
		noise[index] = testCase.noise
	}
	got := jointDPVectorConvolutionAddNoise(share, shifts, noise)
	defer clear(got)
	modulus := exactGCModulus(128)
	for index, testCase := range cases {
		offset := 16 * index
		want := exactGCLittleEndianBig(share[offset : offset+16])
		want.Lsh(want, uint(testCase.shift))
		want.Add(want, big.NewInt(testCase.noise))
		want.Mod(want, modulus)
		record, err := exactGCBigLittleEndian(want, 16)
		want.SetInt64(0)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[offset:offset+16], record) {
			t.Fatalf("case %d fixed Ring128 add differs: got=%x want=%x",
				index, got[offset:offset+16], record)
		}
		clear(record)
	}
	clear(share)
	clear(noise)
}

func TestJointDPVectorConvolutionAnalystPlusEitherPeerView(t *testing.T) {
	plan, err := jointDPPlanVectorConvolutionLaplace(jointDPVectorPlanInput{
		Epsilon: "1", Delta: "7.888609052210118e-31",
		SensitivitySteps: "1", TotalCoordinateCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	stop, _ := new(big.Int).SetString(plan.StopNumerator, 10)
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(plan.StopBits))
	pNumerator := new(big.Int).Sub(new(big.Int).Set(denominator), stop)
	// For the ideal hidden peer draw, adjacent density ratios are at most 1/p.
	// The exact dyadic planner proves 1/p <= exp(epsilon/sensitivity).
	ratio := new(big.Rat).SetFrac(denominator, pNumerator)
	expUpper, err := jointDPExpUpper(big.NewRat(1, 1))
	if err != nil || ratio.Cmp(expUpper) > 0 {
		t.Fatalf("complete hidden-peer mechanism exceeds epsilon: %s", ratio)
	}
	for _, corruptPeer := range []string{"peer-a", "peer-b"} {
		if !plan.CompleteEpsilonPerPeer || plan.EpsilonDividedByPeerCount ||
			plan.PerPeerImplementationDeltaBound == "" {
			t.Fatalf("analyst+%s view lacks one complete certified mechanism",
				corruptPeer)
		}
	}
}

func TestJointDPVectorConvolutionK2K3SourceAggregationInvariant(t *testing.T) {
	modulus := exactGCModulus(128)
	for _, ownerCount := range []int{2, 3} {
		leftAggregate := big.NewInt(0)
		rightAggregate := big.NewInt(0)
		want := big.NewInt(0)
		for owner := 0; owner < ownerCount; owner++ {
			value := big.NewInt(int64(owner + 3))
			maskHash := sha256.Sum256([]byte{
				byte(ownerCount), byte(owner), 0xa5})
			mask := new(big.Int).SetBytes(maskHash[:])
			mask.Mod(mask, modulus)
			other := new(big.Int).Sub(value, mask)
			other.Mod(other, modulus)
			leftAggregate.Add(leftAggregate, mask).Mod(leftAggregate, modulus)
			rightAggregate.Add(rightAggregate, other).Mod(rightAggregate, modulus)
			want.Add(want, value)
		}
		got := new(big.Int).Add(leftAggregate, rightAggregate)
		got.Mod(got, modulus)
		if got.Cmp(want) != 0 {
			t.Fatalf("K=%d source aggregation changed the statistic: %s want %s",
				ownerCount, got, want)
		}
	}
}

func TestJointDPVectorConvolutionRejectsHeadroomAndLeaksNoIntermediate(t *testing.T) {
	seed := sha256.Sum256([]byte("convolution-headroom-seed"))
	input := jointDPVectorConvolutionTestInput(t, "peer-a", seed,
		[]*big.Int{big.NewInt(1)}, []int64{1}, []int{0})
	input.RawUpperBounds = []string{exactGCMaxSigned(128).String()}
	if _, err := jointDPVectorConvolutionSampleShare(input); err == nil ||
		!strings.Contains(err.Error(), "headroom") {
		t.Fatalf("unsafe Ring128 headroom was accepted: %v", err)
	}
	input.RawUpperBounds = []string{"10"}
	output, err := jointDPVectorConvolutionSampleShare(input)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"private_seed", "source_share", "noise", "preclamp_values",
	} {
		if _, found := fields[forbidden]; found {
			t.Fatalf("sampler output exposed forbidden field %q", forbidden)
		}
	}
	decodedSeed, _ := hex.DecodeString(input.PrivateSeed)
	decodedSource, _ := base64.StdEncoding.DecodeString(input.SourceShare)
	if bytes.Contains(wire, decodedSeed) || bytes.Contains(wire, decodedSource) ||
		output.SourceValuesReturned || output.NoiseValuesReturned ||
		output.PrivateSeedReturned || output.PreclampValuesReturned {
		t.Fatal("sampler output contains protected intermediate material")
	}
}

func TestJointDPVectorConvolutionDecoderRejectsUnknownFields(t *testing.T) {
	if _, err := jointDPVectorConvolutionDecode[jointDPVectorConvolutionShareInput](strings.NewReader(
		`{"version":"x","unknown":true}`)); err == nil {
		t.Fatal("unknown convolution input field was accepted")
	}
}

func BenchmarkJointDPVectorConvolutionSample8192(b *testing.B) {
	const coordinates = jointDPVectorConvolutionMaxChunk
	source := make([]*big.Int, coordinates)
	upper := make([]int64, coordinates)
	shifts := make([]int, coordinates)
	for index := range source {
		source[index] = big.NewInt(0)
		upper[index] = 100
		shifts[index] = 8
	}
	seed := sha256.Sum256([]byte("convolution-8192-benchmark-seed"))
	input := jointDPVectorConvolutionTestInput(
		b, "peer-a", seed, source, upper, shifts)
	input.AllocatedDelta = "0.000001"
	b.ReportAllocs()
	b.SetBytes(int64(coordinates * 16))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := jointDPVectorConvolutionSampleShare(input); err != nil {
			b.Fatal(err)
		}
	}
}
