package main

// Productive scalable sampler for one immutable biomedical capsule vector.
//
// Each of the two pinned, non-colluding noise peers independently adds one
// complete discrete-Laplace vector draw to its local Ring128 aggregate share.
// Conditional on either peer's complete view, the other peer's hidden draw is
// still a full (epsilon, delta_impl_per_peer)-DP mechanism.  Adding the known
// peer contribution and the second independent draw is post-processing; it
// does not divide epsilon between peers and does not compose epsilon twice.
//
// Each peer's public certificate charges its two geometric variables per
// coordinate to the complete allocated delta.  Release privacy uses the
// maximum of the two equal per-peer deltas, not their sum: conditioned on one
// corrupt peer, the other complete mechanism provides the guarantee, and the
// known contribution is post-processing.  A separate four-geometric bound is
// reported only as distance from the two-peer approximate distribution to the
// ideal convolution. Sampling is local O(d log M); only already-noised
// Ring128 shares are transported.

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"os"
	"strconv"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

const (
	jointDPVectorConvolutionPlanVersion            = "dsvert-joint-dp-vector-independent-full-draw-convolution-plan-v3"
	jointDPVectorConvolutionInputVersion           = "dsvert-joint-dp-vector-independent-full-draw-convolution-input-v3"
	jointDPVectorConvolutionOutputVersion          = "dsvert-joint-dp-vector-independent-full-draw-convolution-share-v3"
	jointDPVectorConvolutionFinalizerInputVersion  = "dsvert-joint-dp-vector-independent-full-draw-finalizer-input-v3"
	jointDPVectorConvolutionFinalizerOutputVersion = "dsvert-joint-dp-vector-independent-full-draw-finalizer-v3"
	jointDPVectorConvolutionSamplerVersion         = "hkdf-sha256-chacha20-independent-full-draw-binary-geometric-tv-v3"
	jointDPVectorConvolutionBackend                = "independent_full_global_draw_convolution_ring128_v3"
	jointDPVectorConvolutionMaxChunk               = 8192
	jointDPVectorConvolutionMaxInputBytes          = 8 << 20
)

type jointDPVectorConvolutionPlanOutput struct {
	jointDPVectorPlanOutput
	IndependentNoisePeerCount              int    `json:"independent_noise_peer_count"`
	CompleteEpsilonPerPeer                 bool   `json:"complete_epsilon_per_peer"`
	EpsilonDividedByPeerCount              bool   `json:"epsilon_divided_by_peer_count"`
	GeometricVariablesPerPeerPerCoordinate int    `json:"geometric_variables_per_peer_per_coordinate"`
	GeometricVariablesTotalPerCoordinate   int    `json:"geometric_variables_total_per_coordinate"`
	PerPeerImplementationDeltaNumerator    string `json:"per_peer_implementation_delta_numerator"`
	PerPeerImplementationDeltaDenominator  string `json:"per_peer_implementation_delta_denominator"`
	PerPeerImplementationDeltaBound        string `json:"per_peer_implementation_delta_bound"`
	ReleaseImplementationDeltaAggregation  string `json:"release_implementation_delta_aggregation"`
	TwoPeerIdealTransferDeltaNumerator     string `json:"two_peer_ideal_transfer_delta_numerator"`
	TwoPeerIdealTransferDeltaDenominator   string `json:"two_peer_ideal_transfer_delta_denominator"`
	TwoPeerIdealTransferDeltaBound         string `json:"two_peer_ideal_transfer_delta_bound"`
	ThreatModel                            string `json:"threat_model"`
	PrivacyArgument                        string `json:"privacy_argument"`
}

func jointDPPlanVectorConvolutionLaplace(
	input jointDPVectorPlanInput,
) (jointDPVectorConvolutionPlanOutput, error) {
	var zero jointDPVectorConvolutionPlanOutput
	plan, err := jointDPPlanVectorLaplaceAccounting(
		input, 2, jointDPVectorConvolutionPlanVersion,
		jointDPVectorConvolutionSamplerVersion,
		jointDPVectorConvolutionMaxChunk,
		"each independent peer mechanism uses the complete global epsilon, complete global L1 sensitivity, and its own complete delta allocation; per-peer vector TV<=2*d*one_geometric_TV; delta_impl_peer=(1+exp(epsilon_declared))*per_peer_vector_TV; release delta_impl=max(peer deltas), not their sum, because the other independent draw is post-processing and an analyst plus either one peer is protected by the remaining complete mechanism")
	if err != nil {
		return zero, err
	}
	perPeer := new(big.Rat)
	if _, ok := perPeer.SetString(plan.ImplementationDeltaBound); !ok {
		return zero, fmt.Errorf("invalid convolution implementation certificate")
	}
	twoPeerIdealTransfer := new(big.Rat).Mul(perPeer, big.NewRat(2, 1))
	return jointDPVectorConvolutionPlanOutput{
		jointDPVectorPlanOutput:                plan,
		IndependentNoisePeerCount:              2,
		CompleteEpsilonPerPeer:                 true,
		EpsilonDividedByPeerCount:              false,
		GeometricVariablesPerPeerPerCoordinate: 2,
		GeometricVariablesTotalPerCoordinate:   4,
		PerPeerImplementationDeltaNumerator:    perPeer.Num().String(),
		PerPeerImplementationDeltaDenominator:  perPeer.Denom().String(),
		PerPeerImplementationDeltaBound:        perPeer.RatString(),
		ReleaseImplementationDeltaAggregation:  "max_per_peer_not_sum",
		TwoPeerIdealTransferDeltaNumerator:     twoPeerIdealTransfer.Num().String(),
		TwoPeerIdealTransferDeltaDenominator:   twoPeerIdealTransfer.Denom().String(),
		TwoPeerIdealTransferDeltaBound:         twoPeerIdealTransfer.RatString(),
		ThreatModel:                            "pinned_semi_honest_noncolluding_noise_peers; analyst_may_collude_with_at_most_one_noise_peer",
		PrivacyArgument:                        "conditioned on either peer's source share, seed, draw, and transcript, the other peer contributes one hidden complete-epsilon global-sensitivity discrete-Laplace vector mechanism; translation, the second independent draw, signed decoding, and fixed clamping are post-processing",
	}, nil
}

func handleJointDPVectorConvolutionPlan() {
	var input jointDPVectorPlanInput
	mpcReadInput(&input)
	plan, err := jointDPPlanVectorConvolutionLaplace(input)
	if err != nil {
		outputError("joint-DP vector convolution plan unavailable: " + err.Error())
		return
	}
	mpcWriteOutput(plan)
}

type jointDPVectorConvolutionShareInput struct {
	Version              string   `json:"version"`
	RingBits             int      `json:"ring_bits"`
	FracBits             int      `json:"frac_bits"`
	TotalCoordinateCount int      `json:"total_coordinate_count"`
	ChunkStart           int      `json:"chunk_start"`
	CoordinateCount      int      `json:"coordinate_count"`
	OutputLatticeBits    int      `json:"output_lattice_bits"`
	Epsilon              string   `json:"epsilon"`
	AllocatedDelta       string   `json:"allocated_delta"`
	SensitivitySteps     string   `json:"sensitivity_steps"`
	ScaleShifts          []int    `json:"scale_shifts"`
	RawUpperBounds       []string `json:"raw_upper_bounds"`
	ReleaseContractHash  string   `json:"release_contract_hash"`
	TranscriptHash       string   `json:"transcript_hash"`
	PeerName             string   `json:"peer_name"`
	CommitmentContext    string   `json:"commitment_context"`
	SeedCommitment       string   `json:"seed_commitment"`
	PrivateSeed          string   `json:"private_seed"`
	SourceShare          string   `json:"source_share"`
}

type jointDPVectorConvolutionShareOutput struct {
	Version                       string                             `json:"version"`
	Backend                       string                             `json:"backend"`
	Sampler                       string                             `json:"sampler"`
	ReleaseContractHash           string                             `json:"release_contract_hash"`
	SamplerContractHash           string                             `json:"sampler_contract_hash"`
	TranscriptHash                string                             `json:"transcript_hash"`
	PeerName                      string                             `json:"peer_name"`
	SeedCommitment                string                             `json:"seed_commitment"`
	RingBits                      int                                `json:"ring_bits"`
	FracBits                      int                                `json:"frac_bits"`
	TotalCoordinateCount          int                                `json:"total_coordinate_count"`
	ChunkStart                    int                                `json:"chunk_start"`
	CoordinateCount               int                                `json:"coordinate_count"`
	NoisedShare                   string                             `json:"noised_share"`
	MaximumNoiseMagnitudePerPeer  string                             `json:"maximum_noise_magnitude_per_peer"`
	MaximumNoiseMagnitudeTwoPeers string                             `json:"maximum_noise_magnitude_two_peers"`
	FullCapsuleParametersPerPeer  bool                               `json:"full_capsule_parameters_per_peer"`
	EpsilonDividedByPeerCount     bool                               `json:"epsilon_divided_by_peer_count"`
	SourceValuesReturned          bool                               `json:"source_values_returned"`
	NoiseValuesReturned           bool                               `json:"noise_values_returned"`
	PrivateSeedReturned           bool                               `json:"private_seed_returned"`
	PreclampValuesReturned        bool                               `json:"preclamp_values_returned"`
	NoWrapHeadroomCertified       bool                               `json:"no_wrap_headroom_certified"`
	SourceBoundPrecondition       string                             `json:"source_bound_precondition"`
	NominalVarianceMultiplier     int                                `json:"nominal_variance_multiplier"`
	Plan                          jointDPVectorConvolutionPlanOutput `json:"plan"`
}

// A planner threshold is public, but the comparison operand drawn from the
// private stream is not.  Keeping every threshold in the largest supported
// fixed-width container lets the sampler compare either two or four complete
// uint64 limbs without math/big normalization, early exits, or allocations.
type jointDPVectorConvolutionThreshold [4]uint64

type jointDPVectorConvolutionSpec struct {
	input          jointDPVectorConvolutionShareInput
	plan           jointDPVectorConvolutionPlanOutput
	thresholds     []jointDPVectorConvolutionThreshold
	rawUpperBounds []*big.Int
	transcript     [32]byte
	context        [32]byte
	commitment     [32]byte
	releaseHash    [32]byte
	contractDigest [32]byte
	maxNoise       *big.Int
}

func jointDPVectorConvolutionFixedThreshold(
	value *big.Int, uniformBits int,
) (jointDPVectorConvolutionThreshold, error) {
	var result jointDPVectorConvolutionThreshold
	if value == nil || value.Sign() < 0 ||
		(uniformBits != 128 && uniformBits != 256) ||
		value.BitLen() > uniformBits {
		return result, fmt.Errorf("invalid fixed-width Bernoulli threshold")
	}
	var encoded [32]byte
	byteCount := uniformBits / 8
	value.FillBytes(encoded[len(encoded)-byteCount:])
	for limb := 0; limb < uniformBits/64; limb++ {
		end := len(encoded) - 8*limb
		result[limb] = binary.BigEndian.Uint64(encoded[end-8 : end])
	}
	clear(encoded[:])
	return result, nil
}

// jointDPVectorConvolutionLessFixed returns one exactly when the little-endian
// private word is below the public threshold.  The loop count is selected only
// by the public 128/256-bit plan.  A full subtraction chain deliberately avoids
// the value-dependent normalization and early exit of math/big.Int.Cmp.
func jointDPVectorConvolutionLessFixed(
	word []byte, threshold jointDPVectorConvolutionThreshold, limbCount int,
) uint64 {
	var borrow uint64
	for limb := 0; limb < limbCount; limb++ {
		value := binary.LittleEndian.Uint64(word[8*limb : 8*(limb+1)])
		_, borrow = bits.Sub64(value, threshold[limb], borrow)
	}
	return borrow
}

func jointDPVectorConvolutionDecode[T any](reader io.Reader) (T, error) {
	var result T
	data, err := io.ReadAll(io.LimitReader(
		reader, jointDPVectorConvolutionMaxInputBytes+1))
	if err != nil || len(data) == 0 ||
		len(data) > jointDPVectorConvolutionMaxInputBytes {
		return result, fmt.Errorf("invalid joint-DP vector convolution input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("invalid joint-DP vector convolution input")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return result, fmt.Errorf("invalid joint-DP vector convolution input")
	}
	return result, nil
}

func jointDPVectorConvolutionCanonicalBase64(
	value, what string, expectedBytes int,
) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value ||
		len(decoded) != expectedBytes {
		return nil, fmt.Errorf("invalid %s", what)
	}
	return decoded, nil
}

func jointDPVectorConvolutionContractDigest(
	input jointDPVectorConvolutionShareInput,
	plan jointDPVectorConvolutionPlanOutput,
) [32]byte {
	// v3 deliberately binds chunk geometry and its local scale/bound vectors.
	// Therefore a different chunk_start/count is a different private stream,
	// even for the same logical vector. Rechunk-invariant sticky noise would
	// require a coordinated, versioned domain change rather than a silent v3
	// compatibility break.
	h := sha256.New()
	h.Write([]byte(jointDPVectorConvolutionOutputVersion))
	write := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		h.Write(length[:])
		h.Write([]byte(value))
	}
	for _, value := range []string{
		strconv.Itoa(input.RingBits), strconv.Itoa(input.FracBits),
		strconv.Itoa(input.TotalCoordinateCount), strconv.Itoa(input.ChunkStart),
		strconv.Itoa(input.CoordinateCount), strconv.Itoa(input.OutputLatticeBits),
		input.Epsilon, input.AllocatedDelta, input.SensitivitySteps,
		input.ReleaseContractHash, input.TranscriptHash, input.PeerName,
		input.CommitmentContext, input.SeedCommitment,
		plan.StopNumerator, strconv.Itoa(plan.StopBits),
		strconv.Itoa(plan.UniformBits), strconv.Itoa(plan.BinaryGeometricBits),
		plan.ImplementationDeltaNumerator,
		plan.ImplementationDeltaDenominator,
	} {
		write(value)
	}
	for _, threshold := range plan.BernoulliThresholds {
		write(threshold)
	}
	for _, shift := range input.ScaleShifts {
		write(strconv.Itoa(shift))
	}
	for _, upper := range input.RawUpperBounds {
		write(upper)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func jointDPVectorConvolutionParseSpec(
	input jointDPVectorConvolutionShareInput,
) (jointDPVectorConvolutionSpec, error) {
	var zero jointDPVectorConvolutionSpec
	if input.Version != jointDPVectorConvolutionInputVersion ||
		input.RingBits != 128 || input.FracBits != 0 ||
		input.TotalCoordinateCount < 1 ||
		input.TotalCoordinateCount > jointDPVectorMaxTotal ||
		input.CoordinateCount < 1 ||
		input.CoordinateCount > jointDPVectorConvolutionMaxChunk ||
		input.ChunkStart < 0 ||
		input.ChunkStart > input.TotalCoordinateCount-input.CoordinateCount ||
		input.OutputLatticeBits < 1 || input.OutputLatticeBits > 62 ||
		len(input.ScaleShifts) != input.CoordinateCount ||
		len(input.RawUpperBounds) != input.CoordinateCount ||
		!jointDPConvolutionPeer.MatchString(input.PeerName) {
		return zero, fmt.Errorf("invalid purpose-bound convolution shape")
	}
	plan, err := jointDPPlanVectorConvolutionLaplace(jointDPVectorPlanInput{
		Epsilon: input.Epsilon, Delta: input.AllocatedDelta,
		SensitivitySteps:     input.SensitivitySteps,
		TotalCoordinateCount: input.TotalCoordinateCount,
	})
	if err != nil || input.CoordinateCount > plan.MaximumChunkCoordinates {
		return zero, fmt.Errorf("invalid convolution privacy certificate")
	}
	transcript, err := jointDPDecodeHex32(input.TranscriptHash, "transcript hash")
	if err != nil || transcript == ([32]byte{}) {
		return zero, fmt.Errorf("invalid convolution transcript hash")
	}
	context, err := jointDPDecodeHex32(input.CommitmentContext, "commitment context")
	if err != nil {
		return zero, err
	}
	commitment, err := jointDPDecodeHex32(input.SeedCommitment, "seed commitment")
	if err != nil {
		return zero, err
	}
	releaseHash, err := jointDPDecodeHex32(
		input.ReleaseContractHash, "release contract hash")
	if err != nil || releaseHash == ([32]byte{}) {
		return zero, fmt.Errorf("invalid release contract hash")
	}
	expectedContext := jointDPCommitmentContext(
		transcript, "convolution", input.PeerName)
	if context != expectedContext {
		return zero, fmt.Errorf("convolution seed commitment context mismatch")
	}
	thresholds := make([]jointDPVectorConvolutionThreshold,
		len(plan.BernoulliThresholds))
	for index, text := range plan.BernoulliThresholds {
		parsed, parseErr := jointDPVectorParseInt(
			text, "Bernoulli threshold", false)
		if parseErr != nil {
			return zero, parseErr
		}
		thresholds[index], err = jointDPVectorConvolutionFixedThreshold(
			parsed, plan.UniformBits)
		parsed.SetInt64(0)
		if err != nil {
			return zero, err
		}
	}
	upperBounds := make([]*big.Int, input.CoordinateCount)
	maxNoise, ok := new(big.Int).SetString(plan.MaximumNoiseMagnitude, 10)
	if !ok || maxNoise.Sign() < 0 {
		return zero, fmt.Errorf("invalid maximum noise certificate")
	}
	twoNoise := new(big.Int).Lsh(new(big.Int).Set(maxNoise), 1)
	maxSigned := exactGCMaxSigned(128)
	minSigned := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	if new(big.Int).Neg(new(big.Int).Set(twoNoise)).Cmp(minSigned) < 0 {
		return zero, fmt.Errorf("Ring128 lacks negative two-draw headroom")
	}
	for index, text := range input.RawUpperBounds {
		upperBounds[index], err = jointDPVectorParseInt(
			text, "raw upper bound", false)
		shift := input.ScaleShifts[index]
		if err != nil || shift < 0 || shift > input.OutputLatticeBits {
			return zero, fmt.Errorf("invalid convolution lattice bound")
		}
		scaledUpper := new(big.Int).Lsh(
			new(big.Int).Set(upperBounds[index]), uint(shift))
		if scaledUpper.Sign() < 0 ||
			new(big.Int).Add(scaledUpper, twoNoise).Cmp(maxSigned) > 0 {
			return zero, fmt.Errorf(
				"Ring128 lacks certified two-draw no-wrap headroom at coordinate %d",
				index)
		}
	}
	return jointDPVectorConvolutionSpec{
		input: input, plan: plan, thresholds: thresholds,
		rawUpperBounds: upperBounds, transcript: transcript,
		context: context, commitment: commitment, releaseHash: releaseHash,
		contractDigest: jointDPVectorConvolutionContractDigest(input, plan),
		maxNoise:       maxNoise,
	}, nil
}

func jointDPVectorConvolutionPrivateCipher(
	seed [32]byte, spec jointDPVectorConvolutionSpec,
) (*chacha20.Cipher, error) {
	info := append(
		[]byte("dsVert/joint-dp/vector-convolution-private-stream/v3/"),
		spec.contractDigest[:]...)
	reader := hkdf.New(sha256.New, seed[:], spec.transcript[:], info)
	material := make([]byte, chacha20.KeySize+chacha20.NonceSize)
	if _, err := io.ReadFull(reader, material); err != nil {
		return nil, fmt.Errorf("derive convolution private stream")
	}
	defer clear(material)
	cipher, err := chacha20.NewUnauthenticatedCipher(
		material[:chacha20.KeySize], material[chacha20.KeySize:])
	if err != nil {
		return nil, fmt.Errorf("initialize convolution private stream")
	}
	return cipher, nil
}

func jointDPVectorConvolutionSeedCommitmentMatches(
	context [32]byte, seed [32]byte, expected [32]byte,
) bool {
	actual := jointDPSeedCommitment(context, seed)
	match := subtle.ConstantTimeCompare(actual[:], expected[:])
	clear(actual[:])
	return match == 1
}

func jointDPVectorConvolutionCanonicalSeedHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	valid := 1
	for index := 0; index < 64; index++ {
		character := int(value[index])
		digit := subtle.ConstantTimeLessOrEq(int('0'), character) &
			subtle.ConstantTimeLessOrEq(character, int('9'))
		lower := subtle.ConstantTimeLessOrEq(int('a'), character) &
			subtle.ConstantTimeLessOrEq(character, int('f'))
		valid &= digit | lower
	}
	return valid == 1
}

func jointDPVectorConvolutionNoise(
	seed [32]byte, spec jointDPVectorConvolutionSpec,
) ([]int64, error) {
	if !jointDPVectorConvolutionSeedCommitmentMatches(
		spec.context, seed, spec.commitment) {
		return nil, fmt.Errorf("local convolution seed commitment mismatch")
	}
	cipher, err := jointDPVectorConvolutionPrivateCipher(seed, spec)
	if err != nil {
		return nil, err
	}
	bytesPerWord := spec.plan.UniformBits / 8
	limbCount := spec.plan.UniformBits / 64
	coordinateBytes := 2 * spec.plan.BinaryGeometricBits * bytesPerWord
	stream := make([]byte, coordinateBytes)
	defer clear(stream)
	result := make([]int64, spec.input.CoordinateCount)
	var geometric [2]uint64
	for coordinate := range result {
		clear(stream)
		cipher.XORKeyStream(stream, stream)
		geometric[0] = 0
		geometric[1] = 0
		for draw := range geometric {
			for bit, threshold := range spec.thresholds {
				offset := (draw*spec.plan.BinaryGeometricBits + bit) * bytesPerWord
				accepted := jointDPVectorConvolutionLessFixed(
					stream[offset:offset+bytesPerWord], threshold, limbCount)
				geometric[draw] |= accepted << uint(bit)
			}
		}
		// Each geometric is at most 2^63-1, so the mathematical difference
		// is representable as int64 and this unsigned subtraction has the same
		// two's-complement bit pattern without a sign-dependent branch.
		result[coordinate] = int64(geometric[0] - geometric[1])
	}
	clear(geometric[:])
	return result, nil
}

// jointDPVectorConvolutionAddNoise performs the complete protected Ring128
// transform with two fixed little-endian limbs.  Shifts are public and in
// [0,62]; source residues and signed noise never control a branch, loop bound,
// allocation size, or variable-width encoding.
func jointDPVectorConvolutionAddNoise(
	shareBytes []byte, scaleShifts []int, noise []int64,
) []byte {
	noised := make([]byte, len(shareBytes))
	for index, signedNoise := range noise {
		offset := 16 * index
		low := binary.LittleEndian.Uint64(shareBytes[offset : offset+8])
		high := binary.LittleEndian.Uint64(shareBytes[offset+8 : offset+16])
		shift := uint(scaleShifts[index])
		scaledLow := low << shift
		scaledHigh := (high << shift) | (low >> (64 - shift))
		noiseLow := uint64(signedNoise)
		noiseHigh := uint64(signedNoise >> 63)
		resultLow, carry := bits.Add64(scaledLow, noiseLow, 0)
		resultHigh, _ := bits.Add64(scaledHigh, noiseHigh, carry)
		binary.LittleEndian.PutUint64(noised[offset:offset+8], resultLow)
		binary.LittleEndian.PutUint64(noised[offset+8:offset+16], resultHigh)
	}
	return noised
}

func jointDPVectorConvolutionSampleShare(
	input jointDPVectorConvolutionShareInput,
) (jointDPVectorConvolutionShareOutput, error) {
	var zero jointDPVectorConvolutionShareOutput
	spec, err := jointDPVectorConvolutionParseSpec(input)
	if err != nil {
		return zero, err
	}
	seedBytes, err := hex.DecodeString(input.PrivateSeed)
	if err != nil || len(seedBytes) != 32 ||
		!jointDPVectorConvolutionCanonicalSeedHex(input.PrivateSeed) {
		return zero, fmt.Errorf("invalid convolution private seed")
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	clear(seedBytes)
	defer clear(seed[:])
	if !jointDPVectorConvolutionSeedCommitmentMatches(
		spec.context, seed, spec.commitment) {
		return zero, fmt.Errorf("local convolution seed commitment mismatch")
	}
	shareBytes, err := jointDPVectorConvolutionCanonicalBase64(
		input.SourceShare, "Ring128 source share",
		16*input.CoordinateCount)
	if err != nil {
		return zero, err
	}
	defer clear(shareBytes)
	noise, err := jointDPVectorConvolutionNoise(seed, spec)
	if err != nil {
		return zero, err
	}
	defer clear(noise)
	noised := jointDPVectorConvolutionAddNoise(
		shareBytes, input.ScaleShifts, noise)
	defer clear(noised)
	twoNoise := new(big.Int).Lsh(new(big.Int).Set(spec.maxNoise), 1)
	return jointDPVectorConvolutionShareOutput{
		Version:             jointDPVectorConvolutionOutputVersion,
		Backend:             jointDPVectorConvolutionBackend,
		Sampler:             jointDPVectorConvolutionSamplerVersion,
		ReleaseContractHash: input.ReleaseContractHash,
		SamplerContractHash: hex.EncodeToString(spec.contractDigest[:]),
		TranscriptHash:      input.TranscriptHash, PeerName: input.PeerName,
		SeedCommitment: input.SeedCommitment,
		RingBits:       128, FracBits: 0,
		TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart:           input.ChunkStart, CoordinateCount: input.CoordinateCount,
		NoisedShare:                   base64.StdEncoding.EncodeToString(noised),
		MaximumNoiseMagnitudePerPeer:  spec.maxNoise.String(),
		MaximumNoiseMagnitudeTwoPeers: twoNoise.String(),
		FullCapsuleParametersPerPeer:  true,
		EpsilonDividedByPeerCount:     false,
		SourceValuesReturned:          false, NoiseValuesReturned: false,
		PrivateSeedReturned: false, PreclampValuesReturned: false,
		NoWrapHeadroomCertified:   true,
		SourceBoundPrecondition:   "authenticated_semi_honest_capsule_materializer_and_source_transport",
		NominalVarianceMultiplier: 2, Plan: spec.plan,
	}, nil
}

type jointDPVectorConvolutionFinalizerInput struct {
	Version              string   `json:"version"`
	RingBits             int      `json:"ring_bits"`
	FracBits             int      `json:"frac_bits"`
	TotalCoordinateCount int      `json:"total_coordinate_count"`
	ChunkStart           int      `json:"chunk_start"`
	CoordinateCount      int      `json:"coordinate_count"`
	OutputLatticeBits    int      `json:"output_lattice_bits"`
	Epsilon              string   `json:"epsilon"`
	AllocatedDelta       string   `json:"allocated_delta"`
	SensitivitySteps     string   `json:"sensitivity_steps"`
	ScaleShifts          []int    `json:"scale_shifts"`
	RawUpperBounds       []string `json:"raw_upper_bounds"`
	ReleaseContractHash  string   `json:"release_contract_hash"`
	TranscriptHash       string   `json:"transcript_hash"`
	LeftNoisedShare      string   `json:"left_noised_share"`
	RightNoisedShare     string   `json:"right_noised_share"`
}

type jointDPVectorConvolutionFinalizerOutput struct {
	Version                 string                             `json:"version"`
	Backend                 string                             `json:"backend"`
	Sampler                 string                             `json:"sampler"`
	ReleaseContractHash     string                             `json:"release_contract_hash"`
	TranscriptHash          string                             `json:"transcript_hash"`
	RingBits                int                                `json:"ring_bits"`
	FracBits                int                                `json:"frac_bits"`
	TotalCoordinateCount    int                                `json:"total_coordinate_count"`
	ChunkStart              int                                `json:"chunk_start"`
	CoordinateCount         int                                `json:"coordinate_count"`
	OutputLatticeBits       int                                `json:"output_lattice_bits"`
	ClampedScaledValues     []string                           `json:"clamped_scaled_values"`
	PreclampValuesReturned  bool                               `json:"preclamp_values_returned"`
	SignedDecode            string                             `json:"signed_decode"`
	Clamping                string                             `json:"clamping"`
	NoWrapHeadroomCertified bool                               `json:"no_wrap_headroom_certified"`
	Plan                    jointDPVectorConvolutionPlanOutput `json:"plan"`
}

func jointDPVectorConvolutionFinalize(
	input jointDPVectorConvolutionFinalizerInput,
) (jointDPVectorConvolutionFinalizerOutput, error) {
	var zero jointDPVectorConvolutionFinalizerOutput
	// Reuse the complete public policy/headroom parser with a synthetic peer.
	transcript, err := jointDPDecodeHex32(input.TranscriptHash, "transcript hash")
	if err != nil {
		return zero, err
	}
	context := jointDPCommitmentContext(transcript, "convolution", "finalizer")
	seed := sha256.Sum256([]byte("dsVert/vector-convolution/finalizer-validation-only"))
	commitment := jointDPSeedCommitment(context, seed)
	shareInput := jointDPVectorConvolutionShareInput{
		Version:  jointDPVectorConvolutionInputVersion,
		RingBits: input.RingBits, FracBits: input.FracBits,
		TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart:           input.ChunkStart, CoordinateCount: input.CoordinateCount,
		OutputLatticeBits: input.OutputLatticeBits,
		Epsilon:           input.Epsilon, AllocatedDelta: input.AllocatedDelta,
		SensitivitySteps: input.SensitivitySteps,
		ScaleShifts:      input.ScaleShifts, RawUpperBounds: input.RawUpperBounds,
		ReleaseContractHash: input.ReleaseContractHash,
		TranscriptHash:      input.TranscriptHash, PeerName: "finalizer",
		CommitmentContext: hex.EncodeToString(context[:]),
		SeedCommitment:    hex.EncodeToString(commitment[:]),
	}
	if input.Version != jointDPVectorConvolutionFinalizerInputVersion {
		return zero, fmt.Errorf("invalid convolution finalizer version")
	}
	spec, err := jointDPVectorConvolutionParseSpec(shareInput)
	clear(seed[:])
	if err != nil {
		return zero, err
	}
	left, err := jointDPVectorConvolutionCanonicalBase64(
		input.LeftNoisedShare, "left noised share", 16*input.CoordinateCount)
	if err != nil {
		return zero, err
	}
	defer clear(left)
	right, err := jointDPVectorConvolutionCanonicalBase64(
		input.RightNoisedShare, "right noised share", 16*input.CoordinateCount)
	if err != nil {
		return zero, err
	}
	defer clear(right)
	modulus := exactGCModulus(128)
	sign := new(big.Int).Lsh(big.NewInt(1), 127)
	values := make([]string, input.CoordinateCount)
	for index := 0; index < input.CoordinateCount; index++ {
		opened := exactGCLittleEndianBig(left[index*16 : (index+1)*16])
		opened.Add(opened,
			exactGCLittleEndianBig(right[index*16:(index+1)*16]))
		opened.Mod(opened, modulus)
		if opened.Cmp(sign) >= 0 {
			opened.Sub(opened, modulus)
		}
		upper := new(big.Int).Lsh(
			new(big.Int).Set(spec.rawUpperBounds[index]),
			uint(input.ScaleShifts[index]))
		if opened.Sign() < 0 {
			opened.SetInt64(0)
		} else if opened.Cmp(upper) > 0 {
			opened.Set(upper)
		}
		values[index] = opened.String()
		opened.SetInt64(0)
	}
	return jointDPVectorConvolutionFinalizerOutput{
		Version:             jointDPVectorConvolutionFinalizerOutputVersion,
		Backend:             jointDPVectorConvolutionBackend,
		Sampler:             jointDPVectorConvolutionSamplerVersion,
		ReleaseContractHash: input.ReleaseContractHash,
		TranscriptHash:      input.TranscriptHash,
		RingBits:            128, FracBits: 0,
		TotalCoordinateCount: input.TotalCoordinateCount,
		ChunkStart:           input.ChunkStart, CoordinateCount: input.CoordinateCount,
		OutputLatticeBits:   input.OutputLatticeBits,
		ClampedScaledValues: values, PreclampValuesReturned: false,
		SignedDecode:            "canonical_Ring128_twos_complement_after_proven_no_wrap",
		Clamping:                "single_fixed_public_per_coordinate_interval_postprocessing",
		NoWrapHeadroomCertified: true, Plan: spec.plan,
	}, nil
}

func handleJointDPVectorConvolutionShareV3() {
	input, err := jointDPVectorConvolutionDecode[jointDPVectorConvolutionShareInput](os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := jointDPVectorConvolutionSampleShare(input)
	input.PrivateSeed = ""
	input.SourceShare = ""
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}

func handleJointDPVectorConvolutionFinalizeV3() {
	input, err := jointDPVectorConvolutionDecode[jointDPVectorConvolutionFinalizerInput](os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := jointDPVectorConvolutionFinalize(input)
	input.LeftNoisedShare = ""
	input.RightNoisedShare = ""
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}
