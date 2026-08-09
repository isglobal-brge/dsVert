package main

// Scalable exact-GC sampler for one immutable biomedical capsule vector.
//
// Each pinned peer expands its own sticky 256-bit seed locally with
// HKDF-SHA256/ChaCha20.  The two private streams enter Yao as ordinary private
// inputs and are XORed in the circuit.  Hence the joint stream is
// computationally indistinguishable from uniform when at least one of the two
// peers follows the protocol and keeps its seed secret.  No seed, stream,
// source share, or unnoised coordinate crosses the relay boundary.
//
// A geometric random variable with continuation probability p has the exact
// independent-bit representation
//
//   G = sum_j 2^j B_j,
//   Pr[B_j=1] = p^(2^j)/(1+p^(2^j)).
//
// This reduces the circuit from O(L) Bernoulli trials to O(log L).  The finite
// bit prefix and the dyadic Bernoulli thresholds are coupled to the ideal
// geometric distribution.  Outward-rounded big.Rat intervals produce an
// exact rational upper bound for both the omitted tail and every rounding
// error; the complete d-coordinate transfer bound is charged to delta.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/p2p"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

const (
	jointDPVectorPlanVersion     = "dsvert-joint-dp-vector-laplace-plan-v3"
	jointDPVectorTemplateVersion = "dsvert-joint-dp-vector-laplace-gc-template-v3"
	jointDPVectorSamplerVersion  = "hkdf-sha256-chacha20-xor-binary-geometric-tv-v3"
	jointDPVectorOperation       = exactGCOperation("joint-dp-vector-laplace-v3")

	jointDPVectorStopBits       = 128
	jointDPVectorMaxBinaryBits  = 63
	jointDPVectorMaxCoordinates = 128
	jointDPVectorMaxTotal       = 1000000
)

type jointDPVectorPlanInput struct {
	Epsilon              string `json:"epsilon"`
	Delta                string `json:"delta"`
	SensitivitySteps     string `json:"sensitivity_steps"`
	TotalCoordinateCount int    `json:"total_coordinate_count"`
}

type jointDPVectorPlanOutput struct {
	Version                          string   `json:"version"`
	Sampler                          string   `json:"sampler"`
	StopBits                         int      `json:"stop_bits"`
	StopNumerator                    string   `json:"stop_numerator"`
	UniformBits                      int      `json:"uniform_bits"`
	BinaryGeometricBits              int      `json:"binary_geometric_bits"`
	BernoulliThresholds              []string `json:"bernoulli_thresholds"`
	SensitivitySteps                 string   `json:"sensitivity_steps"`
	TotalCoordinateCount             int      `json:"total_coordinate_count"`
	EpsilonEffectiveUpperNumerator   string   `json:"epsilon_effective_upper_numerator"`
	EpsilonEffectiveUpperDenominator string   `json:"epsilon_effective_upper_denominator"`
	OneGeometricTVNumerator          string   `json:"one_geometric_tv_numerator"`
	OneGeometricTVDenominator        string   `json:"one_geometric_tv_denominator"`
	TailUpperNumerator               string   `json:"tail_upper_numerator"`
	TailUpperDenominator             string   `json:"tail_upper_denominator"`
	RoundingUpperNumerator           string   `json:"rounding_upper_numerator"`
	RoundingUpperDenominator         string   `json:"rounding_upper_denominator"`
	ImplementationDeltaNumerator     string   `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator   string   `json:"implementation_delta_denominator"`
	ImplementationDeltaBound         string   `json:"implementation_delta_bound"`
	MaximumNoiseMagnitude            string   `json:"maximum_noise_magnitude"`
	MaximumChunkCoordinates          int      `json:"maximum_chunk_coordinates"`
	PrivateStreamBytesPerCoordinate  int      `json:"private_stream_bytes_per_coordinate"`
	Accounting                       string   `json:"accounting"`
	CapabilityAvailable              bool     `json:"capability_available"`
}

type jointDPVectorProbabilityInterval struct {
	thresholds []*big.Int
	rounding   *big.Rat
	tail       *big.Rat
}

func handleJointDPVectorPlan() {
	var input jointDPVectorPlanInput
	mpcReadInput(&input)
	plan, err := jointDPPlanVectorLaplace(input)
	if err != nil {
		outputError("joint-DP vector Laplace plan unavailable: " + err.Error())
		return
	}
	mpcWriteOutput(plan)
}

func jointDPVectorFloorRat(value *big.Rat) *big.Int {
	return new(big.Int).Quo(value.Num(), value.Denom())
}

func jointDPVectorCeilRat(value *big.Rat) *big.Int {
	quotient := new(big.Int).Quo(value.Num(), value.Denom())
	if new(big.Int).Mod(value.Num(), value.Denom()).Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}

// Quantise one positive rational interval outwards to a fixed dyadic grid.
// All subsequent probability planning is exact big.Int/big.Rat arithmetic;
// no binary or decimal floating-point value enters the certificate.
func jointDPVectorSquareInterval(lower, upper *big.Rat,
	grid *big.Int) (*big.Rat, *big.Rat) {
	lowerSquare := new(big.Rat).Mul(lower, lower)
	upperSquare := new(big.Rat).Mul(upper, upper)
	lowerScaled := new(big.Rat).Mul(lowerSquare, new(big.Rat).SetInt(grid))
	upperScaled := new(big.Rat).Mul(upperSquare, new(big.Rat).SetInt(grid))
	return new(big.Rat).SetFrac(
			jointDPVectorFloorRat(lowerScaled), new(big.Int).Set(grid)),
		new(big.Rat).SetFrac(
			jointDPVectorCeilRat(upperScaled), new(big.Int).Set(grid))
}

func jointDPVectorThetaBounds(lower, upper *big.Rat) (*big.Rat, *big.Rat) {
	// a/(1+a) is monotone on non-negative a.
	thetaLower := new(big.Rat).Quo(
		new(big.Rat).Set(lower), new(big.Rat).Add(big.NewRat(1, 1), lower))
	thetaUpper := new(big.Rat).Quo(
		new(big.Rat).Set(upper), new(big.Rat).Add(big.NewRat(1, 1), upper))
	return thetaLower, thetaUpper
}

func jointDPVectorRoundMidpoint(
	lower, upper *big.Rat, denominator *big.Int,
) *big.Int {
	middle := new(big.Rat).Add(new(big.Rat).Set(lower), upper)
	middle.Quo(middle, big.NewRat(2, 1))
	scaled := new(big.Rat).Mul(middle, new(big.Rat).SetInt(denominator))
	quotient := new(big.Int).Quo(scaled.Num(), scaled.Denom())
	remainder := new(big.Int).Mod(scaled.Num(), scaled.Denom())
	if new(big.Int).Lsh(remainder, 1).Cmp(scaled.Denom()) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if quotient.Sign() < 0 {
		return big.NewInt(0)
	}
	if quotient.Cmp(denominator) >= 0 {
		return new(big.Int).Sub(new(big.Int).Set(denominator), big.NewInt(1))
	}
	return quotient
}

func jointDPVectorAbsRat(value *big.Rat) *big.Rat {
	if value.Sign() < 0 {
		return new(big.Rat).Neg(value)
	}
	return value
}

// jointDPVectorProbabilityIntervals uses exact rational arithmetic and an
// outward dyadic grid after every squaring.  The returned bound is therefore
// independent of host floating-point semantics and transcendental functions.
func jointDPVectorProbabilityIntervals(
	p *big.Rat, uniformBits, binaryBits int,
) (jointDPVectorProbabilityInterval, error) {
	var zero jointDPVectorProbabilityInterval
	if p == nil || p.Sign() <= 0 || p.Cmp(big.NewRat(1, 1)) >= 0 ||
		(uniformBits != 128 && uniformBits != 256) ||
		binaryBits < 1 || binaryBits > jointDPVectorMaxBinaryBits {
		return zero, fmt.Errorf("invalid binary-geometric interval request")
	}
	intervalGrid := new(big.Int).Lsh(big.NewInt(1), uint(uniformBits+128))
	lower := new(big.Rat).Set(p)
	upper := new(big.Rat).Set(p)
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(uniformBits))
	thresholds := make([]*big.Int, binaryBits)
	rounding := new(big.Rat)
	for bit := 0; bit < binaryBits; bit++ {
		thetaLower, thetaUpper := jointDPVectorThetaBounds(lower, upper)
		threshold := jointDPVectorRoundMidpoint(thetaLower, thetaUpper, denominator)
		thresholds[bit] = threshold
		// theta(a)=a/(1+a) is 1-Lipschitz for a>=0.  Rounding the
		// midpoint of its enclosing interval to the nearest R-bit dyadic
		// therefore errs by at most width(a)/2 + 2^(-R-1).  This looser
		// dyadic bound keeps the public exact certificate compact while the
		// independently tested threshold itself still uses the tighter exact
		// rational theta interval above.
		intervalWidth := new(big.Rat).Sub(
			new(big.Rat).Set(upper), lower)
		intervalWidth.Quo(intervalWidth, big.NewRat(2, 1))
		quantisation := new(big.Rat).SetFrac(
			big.NewInt(1), new(big.Int).Lsh(new(big.Int).Set(denominator), 1))
		rounding.Add(rounding, intervalWidth.Add(intervalWidth, quantisation))
		lower, upper = jointDPVectorSquareInterval(lower, upper, intervalGrid)
	}
	return jointDPVectorProbabilityInterval{
		thresholds: thresholds,
		rounding:   rounding,
		tail:       new(big.Rat).Set(upper),
	}, nil
}

func jointDPVectorMaxChunk(binaryBits, uniformBits int) int {
	// Both peers provide d source shares and 2*d*J uniform words.  The
	// garbler additionally provides d public upper bounds, d output masks and
	// one validity mask.  This is a per-circuit resource bound, never a query
	// count or history gate.
	bitsPerCoordinate := 4*128 + 4*binaryBits*uniformBits
	maximum := (exactGCMaxCircuitTypeBits - 1) / bitsPerCoordinate
	if maximum > jointDPVectorMaxCoordinates {
		maximum = jointDPVectorMaxCoordinates
	}
	return maximum
}

func jointDPPlanVectorLaplace(
	input jointDPVectorPlanInput,
) (jointDPVectorPlanOutput, error) {
	return jointDPPlanVectorLaplaceAccounting(
		input, 2, jointDPVectorPlanVersion, jointDPVectorSamplerVersion,
		0,
		"global iid discrete Laplace calibrated once to the workload joint L1 sensitivity; exact binary-geometric coupling TV<=tail+sum(dyadic interval errors); vector TV<=2*d*one_geometric_TV; delta_impl=(1+exp(epsilon_declared))*vector_TV")
}

// jointDPPlanVectorLaplaceAccounting is shared by the exact-GC reference
// mechanism and the productive two-peer convolution mechanism.  The caller
// states the complete number of geometric variables per coordinate whose
// finite-support/dyadic error is charged to the public delta certificate: two
// for one discrete-Laplace draw, four for two independent peer draws.
func jointDPPlanVectorLaplaceAccounting(
	input jointDPVectorPlanInput, geometricVariablesPerCoordinate int,
	version, sampler string, fixedMaximumChunk int, accounting string,
) (jointDPVectorPlanOutput, error) {
	var zero jointDPVectorPlanOutput
	if geometricVariablesPerCoordinate != 2 &&
		geometricVariablesPerCoordinate != 4 {
		return zero, fmt.Errorf("invalid vector sampler accounting multiplicity")
	}
	epsilon, err := jointDPParseDecimalRat(input.Epsilon, "epsilon", false)
	if err != nil {
		return zero, err
	}
	delta, err := jointDPParseDecimalRat(input.Delta, "delta", false)
	if err != nil || (err == nil && delta.Cmp(big.NewRat(1, 1)) >= 0) {
		return zero, fmt.Errorf("delta must be in (0,1)")
	}
	sensitivity, err := jointDPParseDecimalRat(
		input.SensitivitySteps, "sensitivity_steps", false)
	if err != nil || (err == nil && !sensitivity.IsInt()) {
		return zero, fmt.Errorf("sensitivity_steps must be a positive integer")
	}
	if input.TotalCoordinateCount < 1 ||
		input.TotalCoordinateCount > jointDPVectorMaxTotal {
		return zero, fmt.Errorf("total_coordinate_count must be in [1,%d]",
			jointDPVectorMaxTotal)
	}
	stopDenominator := new(big.Int).Lsh(
		big.NewInt(1), jointDPVectorStopBits)
	stop, err := jointDPMaxCertifiedStopNumerator(
		epsilon, sensitivity, stopDenominator)
	if err != nil {
		return zero, err
	}
	pNumerator := new(big.Int).Sub(new(big.Int).Set(stopDenominator), stop)
	p := new(big.Rat).SetFrac(pNumerator, new(big.Int).Set(stopDenominator))
	expUpper, err := jointDPExpUpper(epsilon)
	if err != nil {
		return zero, err
	}
	factor := new(big.Rat).Mul(
		new(big.Rat).Add(big.NewRat(1, 1), expUpper),
		new(big.Rat).SetInt64(int64(
			geometricVariablesPerCoordinate*input.TotalCoordinateCount)))

	var selected jointDPVectorProbabilityInterval
	selectedBits := 0
	selectedUniform := 0
	var implementationDelta *big.Rat
	for _, uniformBits := range []int{128, 256} {
		for binaryBits := 1; binaryBits <= jointDPVectorMaxBinaryBits; binaryBits++ {
			candidate, candidateErr := jointDPVectorProbabilityIntervals(
				p, uniformBits, binaryBits)
			if candidateErr != nil {
				return zero, candidateErr
			}
			oneGeom := new(big.Rat).Add(
				new(big.Rat).Set(candidate.tail), candidate.rounding)
			candidateDelta := new(big.Rat).Mul(factor, oneGeom)
			if candidateDelta.Cmp(delta) <= 0 {
				selected = candidate
				selectedBits = binaryBits
				selectedUniform = uniformBits
				implementationDelta = candidateDelta
				break
			}
		}
		if selectedBits != 0 {
			break
		}
	}
	if selectedBits == 0 {
		return zero, fmt.Errorf(
			"allocated delta cannot certify the finite binary-geometric sampler")
	}
	maxChunk := fixedMaximumChunk
	if maxChunk == 0 {
		maxChunk = jointDPVectorMaxChunk(selectedBits, selectedUniform)
	}
	if maxChunk > input.TotalCoordinateCount {
		maxChunk = input.TotalCoordinateCount
	}
	if maxChunk < 1 {
		return zero, fmt.Errorf("certified sampler exceeds the chunk policy")
	}
	thresholds := make([]string, len(selected.thresholds))
	for i, threshold := range selected.thresholds {
		thresholds[i] = threshold.String()
	}
	oneGeom := new(big.Rat).Add(
		new(big.Rat).Set(selected.tail), selected.rounding)
	maxNoise := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), uint(selectedBits)), big.NewInt(1))
	return jointDPVectorPlanOutput{
		Version: version, Sampler: sampler,
		StopBits: jointDPVectorStopBits, StopNumerator: stop.String(),
		UniformBits: selectedUniform, BinaryGeometricBits: selectedBits,
		BernoulliThresholds:              thresholds,
		SensitivitySteps:                 sensitivity.Num().String(),
		TotalCoordinateCount:             input.TotalCoordinateCount,
		EpsilonEffectiveUpperNumerator:   epsilon.Num().String(),
		EpsilonEffectiveUpperDenominator: epsilon.Denom().String(),
		OneGeometricTVNumerator:          oneGeom.Num().String(),
		OneGeometricTVDenominator:        oneGeom.Denom().String(),
		TailUpperNumerator:               selected.tail.Num().String(),
		TailUpperDenominator:             selected.tail.Denom().String(),
		RoundingUpperNumerator:           selected.rounding.Num().String(),
		RoundingUpperDenominator:         selected.rounding.Denom().String(),
		ImplementationDeltaNumerator:     implementationDelta.Num().String(),
		ImplementationDeltaDenominator:   implementationDelta.Denom().String(),
		ImplementationDeltaBound:         implementationDelta.RatString(),
		MaximumNoiseMagnitude:            maxNoise.String(),
		MaximumChunkCoordinates:          maxChunk,
		PrivateStreamBytesPerCoordinate:  2 * selectedBits * (selectedUniform / 8),
		Accounting:                       accounting,
		CapabilityAvailable:              true,
	}, nil
}

type jointDPVectorSpec struct {
	RingBits                   int
	FracBits                   int
	OutputLatticeBits          int
	TotalCoordinateCount       int
	ChunkStart                 int
	CoordinateCount            int
	SensitivitySteps           *big.Int
	StopNumerator              *big.Int
	StopBits                   int
	UniformBits                int
	BinaryGeometricBits        int
	BernoulliThresholds        []*big.Int
	ScaleShifts                []int
	RawUpperBounds             []*big.Int
	TranscriptHash             [32]byte
	GarblerCommitmentContext   [32]byte
	EvaluatorCommitmentContext [32]byte
	GarblerSeedCommitment      [32]byte
	EvaluatorSeedCommitment    [32]byte
}

type jointDPVectorWorkerPolicy struct {
	Version                        string   `json:"version"`
	Sampler                        string   `json:"sampler"`
	TotalCoordinateCount           int      `json:"total_coordinate_count"`
	ChunkStart                     int      `json:"chunk_start"`
	CoordinateCount                int      `json:"coordinate_count"`
	OutputLatticeBits              int      `json:"output_lattice_bits"`
	SensitivitySteps               string   `json:"sensitivity_steps"`
	Epsilon                        string   `json:"epsilon"`
	AllocatedDelta                 string   `json:"allocated_delta"`
	StopBits                       int      `json:"stop_bits"`
	StopNumerator                  string   `json:"stop_numerator"`
	UniformBits                    int      `json:"uniform_bits"`
	BinaryGeometricBits            int      `json:"binary_geometric_bits"`
	BernoulliThresholds            []string `json:"bernoulli_thresholds"`
	ScaleShifts                    []int    `json:"scale_shifts"`
	RawUpperBounds                 []string `json:"raw_upper_bounds"`
	TranscriptHash                 string   `json:"transcript_hash"`
	GarblerCommitmentContext       string   `json:"garbler_commitment_context"`
	EvaluatorCommitmentContext     string   `json:"evaluator_commitment_context"`
	GarblerSeedCommitment          string   `json:"garbler_seed_commitment"`
	EvaluatorSeedCommitment        string   `json:"evaluator_seed_commitment"`
	CircuitDigest                  string   `json:"circuit_digest"`
	ImplementationDeltaNumerator   string   `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator string   `json:"implementation_delta_denominator"`
}

func (s jointDPVectorSpec) validate() error {
	if s.RingBits != 128 || s.FracBits != 0 ||
		s.OutputLatticeBits < 1 || s.OutputLatticeBits > 62 ||
		s.TotalCoordinateCount < 1 || s.TotalCoordinateCount > jointDPVectorMaxTotal ||
		s.CoordinateCount < 1 || s.CoordinateCount > jointDPVectorMaxCoordinates ||
		s.ChunkStart < 0 || s.ChunkStart > s.TotalCoordinateCount-s.CoordinateCount ||
		s.SensitivitySteps == nil || s.SensitivitySteps.Sign() <= 0 ||
		s.StopBits != jointDPVectorStopBits || s.StopNumerator == nil ||
		s.StopNumerator.Sign() <= 0 ||
		s.StopNumerator.Cmp(new(big.Int).Lsh(big.NewInt(1), jointDPVectorStopBits)) >= 0 ||
		(s.UniformBits != 128 && s.UniformBits != 256) ||
		s.BinaryGeometricBits < 1 ||
		s.BinaryGeometricBits > jointDPVectorMaxBinaryBits ||
		len(s.BernoulliThresholds) != s.BinaryGeometricBits ||
		len(s.ScaleShifts) != s.CoordinateCount ||
		len(s.RawUpperBounds) != s.CoordinateCount ||
		s.CoordinateCount > jointDPVectorMaxChunk(
			s.BinaryGeometricBits, s.UniformBits) {
		return fmt.Errorf("joint-dp-vector-gc: invalid sampler shape")
	}
	uniformDenominator := new(big.Int).Lsh(big.NewInt(1), uint(s.UniformBits))
	for _, threshold := range s.BernoulliThresholds {
		if threshold == nil || threshold.Sign() < 0 ||
			threshold.Cmp(uniformDenominator) >= 0 {
			return fmt.Errorf("joint-dp-vector-gc: invalid Bernoulli threshold")
		}
	}
	maxSigned := exactGCMaxSigned(128)
	for index, upper := range s.RawUpperBounds {
		shift := s.ScaleShifts[index]
		if shift < 0 || shift > s.OutputLatticeBits || upper == nil ||
			upper.Sign() < 0 || upper.Cmp(maxSigned) > 0 ||
			new(big.Int).Lsh(new(big.Int).Set(upper), uint(shift)).Cmp(maxSigned) > 0 {
			return exactGCFailure(exactGCFailureBoundExceeded,
				fmt.Errorf("joint-dp-vector-gc: scaled coordinate bound lacks Ring128 headroom"))
		}
	}
	if bytes.Equal(s.TranscriptHash[:], make([]byte, 32)) {
		return fmt.Errorf("joint-dp-vector-gc: transcript hash must be non-zero")
	}
	return nil
}

func (s jointDPVectorSpec) contractDigest() [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPVectorTemplateVersion))
	write := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		h.Write(length[:])
		h.Write([]byte(value))
	}
	for _, value := range []string{
		strconv.Itoa(s.RingBits), strconv.Itoa(s.FracBits),
		strconv.Itoa(s.OutputLatticeBits),
		strconv.Itoa(s.TotalCoordinateCount), strconv.Itoa(s.ChunkStart),
		strconv.Itoa(s.CoordinateCount), s.SensitivitySteps.String(),
		s.StopNumerator.String(), strconv.Itoa(s.StopBits),
		strconv.Itoa(s.UniformBits), strconv.Itoa(s.BinaryGeometricBits),
		hex.EncodeToString(s.TranscriptHash[:]),
		hex.EncodeToString(s.GarblerCommitmentContext[:]),
		hex.EncodeToString(s.EvaluatorCommitmentContext[:]),
		hex.EncodeToString(s.GarblerSeedCommitment[:]),
		hex.EncodeToString(s.EvaluatorSeedCommitment[:]),
	} {
		write(value)
	}
	for _, threshold := range s.BernoulliThresholds {
		write(threshold.String())
	}
	for _, shift := range s.ScaleShifts {
		write(strconv.Itoa(shift))
	}
	for _, upper := range s.RawUpperBounds {
		write(upper.String())
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s jointDPVectorSpec) circuitShapeDigest() [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPVectorTemplateVersion + "/shape"))
	for _, value := range []string{
		strconv.Itoa(s.CoordinateCount), strconv.Itoa(s.UniformBits),
		strconv.Itoa(s.BinaryGeometricBits), strconv.Itoa(s.OutputLatticeBits),
	} {
		h.Write([]byte{0})
		h.Write([]byte(value))
	}
	for _, threshold := range s.BernoulliThresholds {
		h.Write([]byte{0})
		h.Write([]byte(threshold.String()))
	}
	for _, shift := range s.ScaleShifts {
		h.Write([]byte{0})
		h.Write([]byte(strconv.Itoa(shift)))
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s jointDPVectorSpec) digest() [32]byte {
	contract := s.contractDigest()
	shape := s.circuitShapeDigest()
	assets := jointDPMPCLManifestDigest()
	h := sha256.New()
	h.Write([]byte(jointDPVectorTemplateVersion))
	h.Write([]byte{0})
	h.Write(contract[:])
	h.Write([]byte{0})
	h.Write(shape[:])
	h.Write([]byte{0})
	h.Write(assets[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s jointDPVectorSpec) purpose() string {
	digest := s.digest()
	return string(jointDPVectorOperation) + "/" + hex.EncodeToString(digest[:])
}

func jointDPVectorCircuitSource(s jointDPVectorSpec) string {
	randomType := fmt.Sprintf("uint%d", s.UniformBits)
	var source strings.Builder
	source.WriteString("package main\n")
	fmt.Fprintf(&source,
		"type Garbler struct {\n\tStat [%d]uint128\n\tRandom [%d]%s\n\tRawUpper [%d]uint128\n\tOutputMask [%d]uint128\n\tValidityMask bool\n}\n",
		s.CoordinateCount, 2*s.CoordinateCount*s.BinaryGeometricBits,
		randomType, s.CoordinateCount, s.CoordinateCount)
	fmt.Fprintf(&source,
		"type Evaluator struct {\n\tStat [%d]uint128\n\tRandom [%d]%s\n}\n",
		s.CoordinateCount, 2*s.CoordinateCount*s.BinaryGeometricBits,
		randomType)
	fmt.Fprintf(&source, "func main(g Garbler, e Evaluator) [%d]uint128 {\n",
		s.CoordinateCount+1)
	fmt.Fprintf(&source, "\tvar geom [%d]uint128\n", 2*s.CoordinateCount)
	for coordinate := 0; coordinate < 2*s.CoordinateCount; coordinate++ {
		for bit, threshold := range s.BernoulliThresholds {
			index := coordinate*s.BinaryGeometricBits + bit
			fmt.Fprintf(&source,
				"\tu_%d_%d := g.Random[%d] ^ e.Random[%d]\n",
				coordinate, bit, index, index)
			if threshold.Sign() != 0 {
				fmt.Fprintf(&source,
					"\tif u_%d_%d < %s(%s) { geom[%d] = geom[%d] | (uint128(1) << %d) }\n",
					coordinate, bit, randomType, threshold.String(), coordinate,
					coordinate, bit)
			}
		}
	}
	source.WriteString("\tvalid := true\n")
	for coordinate := 0; coordinate < s.CoordinateCount; coordinate++ {
		fmt.Fprintf(&source,
			"\traw%d := g.Stat[%d] + e.Stat[%d]\n\tvalid = valid && raw%d <= g.RawUpper[%d]\n",
			coordinate, coordinate, coordinate, coordinate, coordinate)
		fmt.Fprintf(&source,
			"\tx%d := raw%d << %d\n\tupper%d := g.RawUpper[%d] << %d\n",
			coordinate, coordinate, s.ScaleShifts[coordinate], coordinate,
			coordinate, s.ScaleShifts[coordinate])
	}
	fmt.Fprintf(&source, "\tvar out [%d]uint128\n", s.CoordinateCount+1)
	for coordinate := 0; coordinate < s.CoordinateCount; coordinate++ {
		left := 2 * coordinate
		right := left + 1
		fmt.Fprintf(&source, "\tresult%d := x%d\n", coordinate, coordinate)
		fmt.Fprintf(&source,
			"\tif geom[%d] >= geom[%d] {\n\t\tpositive%d := geom[%d] - geom[%d]\n\t\troom%d := upper%d - x%d\n\t\tif positive%d > room%d { result%d = upper%d } else { result%d = x%d + positive%d }\n\t} else {\n\t\tnegative%d := geom[%d] - geom[%d]\n\t\tif negative%d > x%d { result%d = 0 } else { result%d = x%d - negative%d }\n\t}\n",
			left, right, coordinate, left, right, coordinate, coordinate,
			coordinate, coordinate, coordinate, coordinate, coordinate,
			coordinate, coordinate, coordinate, coordinate, right, left,
			coordinate, coordinate, coordinate, coordinate, coordinate,
			coordinate)
		fmt.Fprintf(&source,
			"\tif !valid { result%d = 0 }\n\tout[%d] = result%d - g.OutputMask[%d]\n",
			coordinate, coordinate, coordinate, coordinate)
	}
	fmt.Fprintf(&source,
		"\tout[%d] = uint128(0)\n\tif valid != g.ValidityMask { out[%d] = uint128(1) }\n\treturn out\n}\n",
		s.CoordinateCount, s.CoordinateCount)
	return source.String()
}

var jointDPVectorGCCache = struct {
	sync.Mutex
	entries map[string]*circuit.Circuit
	order   []string
}{entries: make(map[string]*circuit.Circuit)}

func jointDPVectorGCCompile(s jointDPVectorSpec) (*circuit.Circuit, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	shape := s.circuitShapeDigest()
	key := hex.EncodeToString(shape[:])
	jointDPVectorGCCache.Lock()
	if cached := jointDPVectorGCCache.entries[key]; cached != nil {
		jointDPVectorGCCache.Unlock()
		return cached, nil
	}
	jointDPVectorGCCache.Unlock()
	source := jointDPVectorCircuitSource(s)
	var circ *circuit.Circuit
	err := jointDPWithMPCLRuntime(func() error {
		var compileErr error
		circ, _, compileErr = compiler.New(utils.NewParams()).Compile(source, nil)
		return compileErr
	})
	if err != nil {
		return nil, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-vector-gc: compile circuit: %w", err))
	}
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		circ.Outputs.Size() != (s.CoordinateCount+1)*128 {
		return nil, fmt.Errorf("joint-dp-vector-gc: compiler produced an invalid circuit shape")
	}
	jointDPVectorGCCache.Lock()
	if len(jointDPVectorGCCache.order) >= exactGCCircuitCacheEntries {
		oldest := jointDPVectorGCCache.order[0]
		delete(jointDPVectorGCCache.entries, oldest)
		jointDPVectorGCCache.order = jointDPVectorGCCache.order[1:]
	}
	jointDPVectorGCCache.entries[key] = circ
	jointDPVectorGCCache.order = append(jointDPVectorGCCache.order, key)
	jointDPVectorGCCache.Unlock()
	return circ, nil
}

func jointDPVectorPrivateStream(seed [32]byte, s jointDPVectorSpec,
	role string) ([]byte, error) {
	if role != "garbler" && role != "evaluator" {
		return nil, fmt.Errorf("joint-dp-vector-gc: invalid stream role")
	}
	digest := s.digest()
	info := append([]byte("dsVert/joint-dp/vector-private-stream/v3/"+role+"/"),
		digest[:]...)
	reader := hkdf.New(sha256.New, seed[:], s.TranscriptHash[:], info)
	material := make([]byte, chacha20.KeySize+chacha20.NonceSize)
	if _, err := io.ReadFull(reader, material); err != nil {
		return nil, fmt.Errorf("joint-dp-vector-gc: derive private stream")
	}
	defer clear(material)
	cipher, err := chacha20.NewUnauthenticatedCipher(
		material[:chacha20.KeySize], material[chacha20.KeySize:])
	if err != nil {
		return nil, fmt.Errorf("joint-dp-vector-gc: initialize private stream")
	}
	count := 2 * s.CoordinateCount * s.BinaryGeometricBits * (s.UniformBits / 8)
	result := make([]byte, count)
	cipher.XORKeyStream(result, result)
	return result, nil
}

func jointDPVectorStreamWords(stream []byte, bits int) ([]*big.Int, error) {
	bytesPerWord := bits / 8
	if (bits != 128 && bits != 256) || len(stream)%bytesPerWord != 0 {
		return nil, fmt.Errorf("joint-dp-vector-gc: invalid private stream shape")
	}
	result := make([]*big.Int, len(stream)/bytesPerWord)
	for index := range result {
		word := append([]byte(nil), stream[index*bytesPerWord:(index+1)*bytesPerWord]...)
		for left, right := 0, len(word)-1; left < right; left, right = left+1, right-1 {
			word[left], word[right] = word[right], word[left]
		}
		result[index] = new(big.Int).SetBytes(word)
		clear(word)
	}
	return result, nil
}

func jointDPVectorDeterministicMasks(seed [32]byte, digest [32]byte,
	count int) ([]*big.Int, bool) {
	result := make([]*big.Int, count)
	for index := range result {
		mac := hmac.New(sha256.New, seed[:])
		mac.Write([]byte("dsVert/joint-dp/vector-output-mask/v3"))
		mac.Write(digest[:])
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], uint32(index))
		mac.Write(encoded[:])
		result[index] = new(big.Int).SetBytes(mac.Sum(nil)[:16])
	}
	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte("dsVert/joint-dp/vector-validity-mask/v3"))
	mac.Write(digest[:])
	return result, mac.Sum(nil)[0]&1 == 1
}

func jointDPVectorPackInput(shares []*big.Int, random []*big.Int,
	upper, masks []*big.Int, validityMask bool, s jointDPVectorSpec,
	garbler bool) *big.Int {
	fields := make([]struct {
		value *big.Int
		bits  int
	}, 0, len(shares)+len(random)+len(upper)+len(masks)+1)
	add := func(value *big.Int, bits int) {
		fields = append(fields, struct {
			value *big.Int
			bits  int
		}{value: value, bits: bits})
	}
	for _, share := range shares {
		add(share, 128)
	}
	for _, word := range random {
		add(word, s.UniformBits)
	}
	if garbler {
		for _, bound := range upper {
			add(bound, 128)
		}
		for _, mask := range masks {
			add(mask, 128)
		}
		add(new(big.Int).SetUint64(boolToUint64(validityMask)), 1)
	}
	return jointDPPackFields(fields)
}

func jointDPVectorValidateSession(session exactGCSession,
	s jointDPVectorSpec) error {
	if err := session.validate(); err != nil {
		return err
	}
	if session.Spec.Operation != jointDPVectorOperation ||
		session.Spec.RingBits != 128 || session.Spec.FracBits != 0 ||
		session.Spec.VectorLen != s.CoordinateCount || session.Purpose != s.purpose() {
		return fmt.Errorf("joint-dp-vector-gc: session is not bound to the sampler contract")
	}
	return s.validate()
}

func jointDPVectorRunGarbler(rw io.ReadWriter, session exactGCSession,
	s jointDPVectorSpec, shares []*big.Int, seed [32]byte) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("joint-dp-vector-gc: nil peer channel")
	}
	if err := jointDPVectorValidateSession(session, s); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	if jointDPSeedCommitment(s.GarblerCommitmentContext, seed) !=
		s.GarblerSeedCommitment {
		return nil, fmt.Errorf("joint-dp-vector-gc: local garbler seed commitment mismatch")
	}
	stream, err := jointDPVectorPrivateStream(seed, s, "garbler")
	if err != nil {
		return nil, err
	}
	defer clear(stream)
	random, err := jointDPVectorStreamWords(stream, s.UniformBits)
	if err != nil {
		return nil, err
	}
	defer exactGCZeroBigInts(random)
	circ, err := jointDPVectorGCCompile(s)
	if err != nil {
		return nil, err
	}
	digest := s.digest()
	masks, validityMask := jointDPVectorDeterministicMasks(
		seed, digest, s.CoordinateCount)
	defer exactGCZeroBigInts(masks)
	input := jointDPVectorPackInput(
		shares, random, s.RawUpperBounds, masks, validityMask, s, true)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	result := make([]*big.Int, 0, len(masks)+1)
	for _, mask := range masks {
		result = append(result, new(big.Int).Set(mask))
	}
	result = append(result, new(big.Int).SetUint64(boolToUint64(validityMask)))
	return result, nil
}

func jointDPVectorRunEvaluator(rw io.ReadWriter, session exactGCSession,
	s jointDPVectorSpec, shares []*big.Int, seed [32]byte) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("joint-dp-vector-gc: nil peer channel")
	}
	if err := jointDPVectorValidateSession(session, s); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	if jointDPSeedCommitment(s.EvaluatorCommitmentContext, seed) !=
		s.EvaluatorSeedCommitment {
		return nil, fmt.Errorf("joint-dp-vector-gc: local evaluator seed commitment mismatch")
	}
	stream, err := jointDPVectorPrivateStream(seed, s, "evaluator")
	if err != nil {
		return nil, err
	}
	defer clear(stream)
	random, err := jointDPVectorStreamWords(stream, s.UniformBits)
	if err != nil {
		return nil, err
	}
	defer exactGCZeroBigInts(random)
	circ, err := jointDPVectorGCCompile(s)
	if err != nil {
		return nil, err
	}
	input := jointDPVectorPackInput(shares, random, nil, nil, false, s, false)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	result, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return jointDPVectorUnpackOutputs(result, s), nil
}

func jointDPVectorUnpackOutputs(value *big.Int,
	s jointDPVectorSpec) []*big.Int {
	result := make([]*big.Int, s.CoordinateCount+1)
	for index := range result {
		result[index] = new(big.Int).Rsh(new(big.Int).Set(value), uint(index*128))
		bits := 128
		if index == s.CoordinateCount {
			bits = 1
		}
		result[index].And(result[index], exactGCMask(bits))
	}
	return result
}

func jointDPVectorReferenceNoise(s jointDPVectorSpec, garblerSeed,
	evaluatorSeed [32]byte) ([]*big.Int, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if jointDPSeedCommitment(s.GarblerCommitmentContext, garblerSeed) !=
		s.GarblerSeedCommitment ||
		jointDPSeedCommitment(s.EvaluatorCommitmentContext, evaluatorSeed) !=
			s.EvaluatorSeedCommitment {
		return nil, fmt.Errorf("joint-dp-vector-gc: seed commitment mismatch")
	}
	left, err := jointDPVectorPrivateStream(garblerSeed, s, "garbler")
	if err != nil {
		return nil, err
	}
	defer clear(left)
	right, err := jointDPVectorPrivateStream(evaluatorSeed, s, "evaluator")
	if err != nil {
		return nil, err
	}
	defer clear(right)
	for index := range left {
		left[index] ^= right[index]
	}
	words, err := jointDPVectorStreamWords(left, s.UniformBits)
	if err != nil {
		return nil, err
	}
	defer exactGCZeroBigInts(words)
	geom := make([]*big.Int, 2*s.CoordinateCount)
	for coordinate := range geom {
		geom[coordinate] = new(big.Int)
		for bit, threshold := range s.BernoulliThresholds {
			index := coordinate*s.BinaryGeometricBits + bit
			if words[index].Cmp(threshold) < 0 {
				geom[coordinate].SetBit(geom[coordinate], bit, 1)
			}
		}
	}
	result := make([]*big.Int, s.CoordinateCount)
	for coordinate := range result {
		result[coordinate] = new(big.Int).Sub(
			geom[2*coordinate], geom[2*coordinate+1])
	}
	exactGCZeroBigInts(geom)
	return result, nil
}
