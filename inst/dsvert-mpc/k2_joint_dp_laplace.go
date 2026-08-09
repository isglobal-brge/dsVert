package main

// This file contains the finite, reviewable sampler contract used by the
// joint two-peer DP prototype.  It deliberately does not expose a command
// which accepts protected statistics.  The only command handler below plans
// public sampler parameters; protected shares and seeds are consumed only by
// the authenticated exact-GC worker path.

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/p2p"
)

const (
	jointDPLaplacePlanVersion    = "dsvert-joint-dp-laplace-plan-v2"
	jointDPGCTemplateVersion     = "dsvert-joint-dp-laplace-gc-template-v2"
	jointDPSamplerVersion        = "hkdf-sha256-aes128ctr-two-geometric-tv-v2"
	jointDPSeedCommitmentVersion = "dsvert-joint-dp-private-seed-commitment-v2"
	jointDPMaxCoordinates        = 64
	jointDPMaxGeometricSteps     = 4096
	jointDPMaxAESBlocks          = 1024
)

var jointDPDecimalRE = regexp.MustCompile(`^([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)

type jointDPLaplacePlanInput struct {
	Epsilon          string `json:"epsilon"`
	Delta            string `json:"delta"`
	SensitivitySteps string `json:"sensitivity_steps"`
	CoordinateCount  int    `json:"coordinate_count"`
	BernoulliBits    int    `json:"bernoulli_bits"`
	MaxSteps         int    `json:"max_steps,omitempty"`
}

type jointDPLaplacePlanOutput struct {
	Version                        string `json:"version"`
	Sampler                        string `json:"sampler"`
	BernoulliBits                  int    `json:"bernoulli_bits"`
	StopNumerator                  string `json:"stop_numerator"`
	MaxGeometricSteps              int    `json:"max_geometric_steps"`
	SensitivitySteps               string `json:"sensitivity_steps"`
	CoordinateCount                int    `json:"coordinate_count"`
	EpsilonEffectiveUpperNumerator string `json:"epsilon_effective_upper_numerator"`
	EpsilonEffectiveUpperDenom     string `json:"epsilon_effective_upper_denominator"`
	ImplementationDeltaNumerator   string `json:"implementation_delta_numerator"`
	ImplementationDeltaDenom       string `json:"implementation_delta_denominator"`
	ImplementationDeltaBound       string `json:"implementation_delta_bound"`
	Accounting                     string `json:"accounting"`
	BernoulliTrials                int    `json:"bernoulli_trials"`
	AESBlocks                      int    `json:"aes_blocks"`
	CapabilityAvailable            bool   `json:"capability_available"`
	UnavailableReason              string `json:"unavailable_reason"`
}

func handleJointDPLaplacePlan() {
	var input jointDPLaplacePlanInput
	mpcReadInput(&input)
	plan, err := jointDPPlanLaplace(input)
	if err != nil {
		outputError("joint-DP Laplace plan unavailable: " + err.Error())
		return
	}
	mpcWriteOutput(plan)
}

// jointDPParseDecimalRat parses a finite non-negative base-10 decimal without
// first rounding it through float64.  The exact rational is used for both the
// epsilon certificate and the implementation-delta reservation.
func jointDPParseDecimalRat(value, name string, allowZero bool) (*big.Rat, error) {
	// These values come from a public, signed policy, but still cross a JSON
	// boundary.  Bound parsing work before allocating big.Int limbs.
	if len(value) == 0 || len(value) > 128 {
		return nil, fmt.Errorf("invalid %s decimal length", name)
	}
	if strings.HasPrefix(value, ".") {
		value = "0" + value
	}
	matches := jointDPDecimalRE.FindStringSubmatch(value)
	if matches == nil {
		return nil, fmt.Errorf("invalid %s decimal", name)
	}
	digits := matches[1] + matches[2]
	numerator, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil, fmt.Errorf("invalid %s decimal", name)
	}
	exponent := -len(matches[2])
	if matches[3] != "" {
		parsed, err := strconv.Atoi(matches[3])
		if err != nil || parsed < -10000 || parsed > 10000 {
			return nil, fmt.Errorf("invalid %s exponent", name)
		}
		exponent += parsed
	}
	denominator := big.NewInt(1)
	if exponent >= 0 {
		numerator.Mul(numerator, new(big.Int).Exp(big.NewInt(10),
			big.NewInt(int64(exponent)), nil))
	} else {
		denominator.Exp(big.NewInt(10), big.NewInt(int64(-exponent)), nil)
	}
	result := new(big.Rat).SetFrac(numerator, denominator)
	if result.Sign() < 0 || (!allowZero && result.Sign() == 0) {
		return nil, fmt.Errorf("%s must be positive", name)
	}
	return result, nil
}

// jointDPExpUpper returns a rational upper bound on exp(x).  With
// N=ceil(x)+64, the Taylor prefix is exact and the remaining positive terms
// are bounded by a geometric series whose ratio is at most x/(N+2).
func jointDPExpUpper(x *big.Rat) (*big.Rat, error) {
	if x == nil || x.Sign() < 0 {
		return nil, fmt.Errorf("invalid exponent")
	}
	ceil := new(big.Int).Quo(x.Num(), x.Denom())
	if new(big.Int).Mod(x.Num(), x.Denom()).Sign() != 0 {
		ceil.Add(ceil, big.NewInt(1))
	}
	if !ceil.IsInt64() || ceil.Int64() > 10000 {
		return nil, fmt.Errorf("epsilon is outside the certified range")
	}
	n := int(ceil.Int64()) + 64
	sum := new(big.Rat).SetInt64(1)
	term := new(big.Rat).SetInt64(1)
	for k := 1; k <= n+1; k++ {
		term.Mul(term, x)
		term.Quo(term, new(big.Rat).SetInt64(int64(k)))
		if k <= n {
			sum.Add(sum, term)
		}
	}
	ratio := new(big.Rat).Quo(new(big.Rat).Set(x),
		new(big.Rat).SetInt64(int64(n+2)))
	if ratio.Cmp(big.NewRat(1, 1)) >= 0 {
		return nil, fmt.Errorf("epsilon is outside the certified range")
	}
	remainder := new(big.Rat).Quo(term,
		new(big.Rat).Sub(big.NewRat(1, 1), ratio))
	return sum.Add(sum, remainder), nil
}

// jointDPExpLowerCapped returns an exact Taylor-prefix lower bound on exp(x).
// The caller only needs to compare exp(x) with a small public dyadic ratio,
// so evaluation stops once the lower bound reaches cap.  A finite Taylor
// prefix is always below exp(x); stopping at the cap therefore cannot make an
// unsafe Bernoulli parameter pass.  The fixed term limit is ample at the only
// supported dyadic precisions (8 and 16 bits), while the cap avoids building
// enormous rationals for large public epsilon values.
func jointDPExpLowerCapped(x, cap *big.Rat) (*big.Rat, error) {
	if x == nil || x.Sign() < 0 || cap == nil || cap.Sign() <= 0 ||
		x.Cmp(big.NewRat(10000, 1)) > 0 {
		return nil, fmt.Errorf("invalid exponent lower-bound request")
	}
	const terms = 128
	sum := new(big.Rat).SetInt64(1)
	term := new(big.Rat).SetInt64(1)
	for k := 1; k <= terms && sum.Cmp(cap) < 0; k++ {
		term.Mul(term, x)
		term.Quo(term, new(big.Rat).SetInt64(int64(k)))
		sum.Add(sum, term)
	}
	return sum, nil
}

// jointDPMaxCertifiedStopNumerator chooses the largest dyadic q=m/2^B for
// which the exact lower-bound certificate proves
//
//	sensitivity * -log(1-q) <= epsilon.
//
// Equivalently, 1/(1-q) <= exp(epsilon/sensitivity).  Comparing the left hand
// side with a rational Taylor-prefix *lower* bound on exp makes the decision
// conservative without the much looser -log(1-q) <= q/(1-q) inequality.
func jointDPMaxCertifiedStopNumerator(
	epsilon, sensitivity *big.Rat, denominator *big.Int,
) (*big.Int, error) {
	if epsilon == nil || epsilon.Sign() <= 0 || sensitivity == nil ||
		sensitivity.Sign() <= 0 || denominator == nil ||
		denominator.Cmp(big.NewInt(2)) < 0 {
		return nil, fmt.Errorf("invalid dyadic epsilon certificate")
	}
	x := new(big.Rat).Quo(new(big.Rat).Set(epsilon), sensitivity)
	// For q >= 1/D, -log(1-q) > q >= 1/D.  This exact early rejection
	// prevents pathological tiny decimal inputs from creating huge rationals.
	if x.Cmp(new(big.Rat).SetFrac(big.NewInt(1), denominator)) <= 0 {
		return nil, fmt.Errorf("epsilon is too small for the selected dyadic precision")
	}
	cap := new(big.Rat).SetInt(denominator)
	expLower, err := jointDPExpLowerCapped(x, cap)
	if err != nil {
		return nil, err
	}
	low := big.NewInt(0)
	high := new(big.Int).Sub(new(big.Int).Set(denominator), big.NewInt(1))
	one := big.NewInt(1)
	for low.Cmp(high) < 0 {
		mid := new(big.Int).Add(low, high)
		mid.Add(mid, one)
		mid.Rsh(mid, 1)
		pNum := new(big.Int).Sub(new(big.Int).Set(denominator), mid)
		ratio := new(big.Rat).SetFrac(new(big.Int).Set(denominator), pNum)
		if ratio.Cmp(expLower) <= 0 {
			low.Set(mid)
		} else {
			high.Sub(mid, one)
		}
	}
	if low.Sign() <= 0 || low.Cmp(denominator) >= 0 {
		return nil, fmt.Errorf("epsilon is too small for the selected dyadic precision")
	}
	return new(big.Int).Set(low), nil
}

func jointDPPlanLaplace(input jointDPLaplacePlanInput) (jointDPLaplacePlanOutput, error) {
	var zero jointDPLaplacePlanOutput
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
	if input.CoordinateCount < 1 || input.CoordinateCount > jointDPMaxCoordinates {
		return zero, fmt.Errorf("coordinate_count must be in [1,%d]", jointDPMaxCoordinates)
	}
	if input.BernoulliBits != 8 && input.BernoulliBits != 16 {
		return zero, fmt.Errorf("bernoulli_bits must be 8 or 16")
	}
	maxSteps := input.MaxSteps
	if maxSteps == 0 {
		maxSteps = jointDPMaxGeometricSteps
	}
	if maxSteps < 1 || maxSteps > jointDPMaxGeometricSteps {
		return zero, fmt.Errorf("max_steps must be in [1,%d]", jointDPMaxGeometricSteps)
	}
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(input.BernoulliBits))
	q, err := jointDPMaxCertifiedStopNumerator(
		epsilon, sensitivity, denominator)
	if err != nil {
		return zero, err
	}
	pNum := new(big.Int).Sub(new(big.Int).Set(denominator), q)
	// The exact exp-lower comparison above proves the effective epsilon is no
	// larger than the declared value.  Report that declared rational as the
	// conservative upper certificate; no floating logarithm enters the proof.
	epsilonUpper := new(big.Rat).Set(epsilon)
	expUpper, err := jointDPExpUpper(epsilon)
	if err != nil {
		return zero, err
	}
	factor := new(big.Rat).Mul(
		new(big.Rat).Add(big.NewRat(1, 1), expUpper),
		new(big.Rat).SetInt64(int64(2*input.CoordinateCount)))
	p := new(big.Rat).SetFrac(new(big.Int).Set(pNum), new(big.Int).Set(denominator))
	pPower := new(big.Rat).Set(p) // p^(L+1), initially L=0.
	var implementationDelta *big.Rat
	steps := -1
	for l := 0; l <= maxSteps; l++ {
		candidate := new(big.Rat).Mul(new(big.Rat).Set(factor), pPower)
		if candidate.Cmp(delta) <= 0 {
			steps = l
			implementationDelta = candidate
			break
		}
		pPower.Mul(pPower, p)
	}
	if steps < 1 {
		return zero, fmt.Errorf("allocated delta cannot certify a finite sampler within max_steps")
	}
	randomBytes := (2*input.CoordinateCount*steps*input.BernoulliBits + 7) / 8
	blocks := (randomBytes + aes.BlockSize - 1) / aes.BlockSize
	if blocks > jointDPMaxAESBlocks {
		return zero, fmt.Errorf("certified sampler exceeds the fixed circuit block policy")
	}
	return jointDPLaplacePlanOutput{
		Version: jointDPLaplacePlanVersion, Sampler: jointDPSamplerVersion,
		BernoulliBits: input.BernoulliBits, StopNumerator: q.String(),
		MaxGeometricSteps: steps, SensitivitySteps: sensitivity.Num().String(),
		CoordinateCount:                input.CoordinateCount,
		EpsilonEffectiveUpperNumerator: epsilonUpper.Num().String(),
		EpsilonEffectiveUpperDenom:     epsilonUpper.Denom().String(),
		ImplementationDeltaNumerator:   implementationDelta.Num().String(),
		ImplementationDeltaDenom:       implementationDelta.Denom().String(),
		ImplementationDeltaBound:       implementationDelta.RatString(),
		Accounting:                     "epsilon: exact Taylor-prefix lower bound proves 1/(1-q)<=exp(epsilon_declared/sensitivity); TV<=2*d*(1-q)^(L+1) by coupling each G with min(G,L); delta_impl=(1+exp(epsilon_declared))*TV with an exact rational Taylor upper bound",
		BernoulliTrials:                2 * input.CoordinateCount * steps,
		AESBlocks:                      blocks,
		CapabilityAvailable:            false,
		UnavailableReason:              "linear_fixed_trial_sampler_not_promoted_for_general_biomedical_workloads",
	}, nil
}

type jointDPGCLaplaceSpec struct {
	RingBits                   int
	FracBits                   int
	CoordinateCount            int
	BernoulliBits              int
	StopNumerator              uint32
	MaxGeometricSteps          int
	SensitivitySteps           *big.Int
	EncodedLower               *big.Int // signed fixed-point integer
	EncodedUpper               *big.Int // signed fixed-point integer
	TranscriptHash             [32]byte
	GarblerCommitmentContext   [32]byte
	EvaluatorCommitmentContext [32]byte
	GarblerSeedCommitment      [32]byte
	EvaluatorSeedCommitment    [32]byte
}

// jointDPGCWorkerPolicy is the JSON representation of the public circuit
// contract.  Decimal and hexadecimal strings avoid platform-dependent JSON
// number rounding.  It is nested under the exact worker config and is never a
// DataSHIELD method argument.
type jointDPGCWorkerPolicy struct {
	Version                        string `json:"version"`
	Sampler                        string `json:"sampler"`
	BernoulliBits                  int    `json:"bernoulli_bits"`
	StopNumerator                  string `json:"stop_numerator"`
	MaxGeometricSteps              int    `json:"max_geometric_steps"`
	SensitivitySteps               string `json:"sensitivity_steps"`
	Epsilon                        string `json:"epsilon"`
	AllocatedDelta                 string `json:"allocated_delta"`
	EncodedLower                   string `json:"encoded_lower"`
	EncodedUpper                   string `json:"encoded_upper"`
	TranscriptHash                 string `json:"transcript_hash"`
	GarblerCommitmentContext       string `json:"garbler_commitment_context"`
	EvaluatorCommitmentContext     string `json:"evaluator_commitment_context"`
	GarblerSeedCommitment          string `json:"garbler_seed_commitment"`
	EvaluatorSeedCommitment        string `json:"evaluator_seed_commitment"`
	CircuitDigest                  string `json:"circuit_digest"`
	ImplementationDeltaNumerator   string `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator string `json:"implementation_delta_denominator"`
}

func jointDPDecodeHex32(value, name string) ([32]byte, error) {
	var result [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) ||
		hex.EncodeToString(decoded) != value {
		return result, fmt.Errorf("joint-dp-gc: invalid %s", name)
	}
	copy(result[:], decoded)
	return result, nil
}

func jointDPGCWorkerInputs(config exactGCWorkerConfig,
	session exactGCSession) (jointDPGCLaplaceSpec, [32]byte, error) {
	var zeroSpec jointDPGCLaplaceSpec
	var zeroSeed [32]byte
	policy := config.JointDP
	if policy == nil || policy.Version != jointDPGCTemplateVersion ||
		policy.Sampler != jointDPSamplerVersion {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-gc: missing public worker contract")
	}
	parsePositive := func(value, name string) (*big.Int, error) {
		result := new(big.Int)
		if _, ok := result.SetString(value, 10); !ok || result.Sign() <= 0 {
			return nil, fmt.Errorf("joint-dp-gc: invalid %s", name)
		}
		return result, nil
	}
	parseSigned := func(value, name string) (*big.Int, error) {
		result := new(big.Int)
		if _, ok := result.SetString(value, 10); !ok {
			return nil, fmt.Errorf("joint-dp-gc: invalid %s", name)
		}
		return result, nil
	}
	stop, err := strconv.ParseUint(policy.StopNumerator, 10, 32)
	if err != nil {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-gc: invalid stop numerator")
	}
	sensitivity, err := parsePositive(policy.SensitivitySteps, "sensitivity steps")
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	lower, err := parseSigned(policy.EncodedLower, "encoded lower bound")
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	upper, err := parseSigned(policy.EncodedUpper, "encoded upper bound")
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	transcript, err := jointDPDecodeHex32(policy.TranscriptHash, "transcript hash")
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	gctx, err := jointDPDecodeHex32(policy.GarblerCommitmentContext,
		"garbler commitment context")
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	ectx, err := jointDPDecodeHex32(policy.EvaluatorCommitmentContext,
		"evaluator commitment context")
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	gcommit, err := jointDPDecodeHex32(policy.GarblerSeedCommitment,
		"garbler seed commitment")
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	ecommit, err := jointDPDecodeHex32(policy.EvaluatorSeedCommitment,
		"evaluator seed commitment")
	if err != nil {
		return zeroSpec, zeroSeed, err
	}
	spec := jointDPGCLaplaceSpec{
		RingBits: session.Spec.RingBits, FracBits: session.Spec.FracBits,
		CoordinateCount: session.Spec.VectorLen,
		BernoulliBits:   policy.BernoulliBits, StopNumerator: uint32(stop),
		MaxGeometricSteps: policy.MaxGeometricSteps,
		SensitivitySteps:  sensitivity, EncodedLower: lower, EncodedUpper: upper,
		TranscriptHash: transcript, GarblerCommitmentContext: gctx,
		EvaluatorCommitmentContext: ectx, GarblerSeedCommitment: gcommit,
		EvaluatorSeedCommitment: ecommit,
	}
	if err := spec.validate(); err != nil {
		return zeroSpec, zeroSeed, err
	}
	digest := spec.digest()
	if policy.CircuitDigest != hex.EncodeToString(digest[:]) ||
		session.Purpose != spec.purpose() {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-gc: worker circuit digest mismatch")
	}
	// Recompute the exact public accounting certificate.  A signed-looking
	// numerator/denominator is not trusted on its own: q, L, epsilon, delta,
	// sensitivity and dimension must all reproduce the unique minimal plan.
	plan, err := jointDPPlanLaplace(jointDPLaplacePlanInput{
		Epsilon: policy.Epsilon, Delta: policy.AllocatedDelta,
		SensitivitySteps: policy.SensitivitySteps,
		CoordinateCount:  session.Spec.VectorLen,
		BernoulliBits:    policy.BernoulliBits,
		MaxSteps:         policy.MaxGeometricSteps,
	})
	if err != nil || plan.MaxGeometricSteps != policy.MaxGeometricSteps ||
		plan.StopNumerator != policy.StopNumerator ||
		plan.ImplementationDeltaNumerator != policy.ImplementationDeltaNumerator ||
		plan.ImplementationDeltaDenom != policy.ImplementationDeltaDenominator {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-gc: invalid implementation delta certificate")
	}
	seedBytes, err := exactGCStrictBase64(config.PrivateSeed, 32)
	if err != nil {
		return zeroSpec, zeroSeed, fmt.Errorf("joint-dp-gc: invalid private seed")
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	return spec, seed, nil
}

func (s jointDPGCLaplaceSpec) validate() error {
	if s.RingBits < 63 || s.RingBits > 127 ||
		(s.RingBits != 63 && s.RingBits != 127) {
		return exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-gc: only Ring63 and Ring127 are supported"))
	}
	if s.FracBits < 0 || s.FracBits >= s.RingBits {
		return fmt.Errorf("joint-dp-gc: invalid fractional bits")
	}
	if s.CoordinateCount < 1 || s.CoordinateCount > jointDPMaxCoordinates ||
		s.MaxGeometricSteps < 1 || s.MaxGeometricSteps > jointDPMaxGeometricSteps ||
		(s.BernoulliBits != 8 && s.BernoulliBits != 16) {
		return fmt.Errorf("joint-dp-gc: invalid fixed sampler shape")
	}
	den := uint32(1) << uint(s.BernoulliBits)
	if s.StopNumerator == 0 || s.StopNumerator >= den {
		return fmt.Errorf("joint-dp-gc: invalid dyadic stop probability")
	}
	if s.SensitivitySteps == nil || s.SensitivitySteps.Sign() <= 0 {
		return fmt.Errorf("joint-dp-gc: invalid sensitivity steps")
	}
	if !exactGCFitsSigned(s.EncodedLower, s.RingBits) ||
		!exactGCFitsSigned(s.EncodedUpper, s.RingBits) ||
		s.EncodedLower.Cmp(s.EncodedUpper) > 0 {
		return exactGCFailure(exactGCFailureBoundExceeded,
			fmt.Errorf("joint-dp-gc: encoded bounds are outside the signed ring"))
	}
	noiseMax := new(big.Int).Lsh(big.NewInt(int64(s.MaxGeometricSteps)),
		uint(s.FracBits))
	minSigned := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(s.RingBits-1)))
	if new(big.Int).Sub(s.EncodedLower, noiseMax).Cmp(minSigned) < 0 ||
		new(big.Int).Add(s.EncodedUpper, noiseMax).Cmp(exactGCMaxSigned(s.RingBits)) > 0 {
		return exactGCFailure(exactGCFailureBoundExceeded,
			fmt.Errorf("joint-dp-gc: encoded bounds lack worst-case sampler headroom"))
	}
	randomBytes := 2 * s.CoordinateCount * s.MaxGeometricSteps * (s.BernoulliBits / 8)
	if (randomBytes+aes.BlockSize-1)/aes.BlockSize > jointDPMaxAESBlocks {
		return exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-gc: fixed sampler exceeds circuit block policy"))
	}
	if bytes.Equal(s.TranscriptHash[:], make([]byte, 32)) {
		return fmt.Errorf("joint-dp-gc: transcript hash must be non-zero")
	}
	return nil
}

func jointDPCommitmentContext(transcript [32]byte, role, peerID string) [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPSeedCommitmentVersion))
	h.Write([]byte{0})
	h.Write(transcript[:])
	h.Write([]byte{0})
	h.Write([]byte(role))
	h.Write([]byte{0})
	h.Write([]byte(peerID))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func jointDPSeedCommitment(context [32]byte, seed [32]byte) [32]byte {
	var preimage [64]byte
	copy(preimage[:32], context[:])
	copy(preimage[32:], seed[:])
	return sha256.Sum256(preimage[:])
}

func (s jointDPGCLaplaceSpec) contractDigest() [32]byte {
	h := sha256.New()
	h.Write([]byte(jointDPGCTemplateVersion))
	write := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		h.Write(length[:])
		h.Write([]byte(value))
	}
	for _, value := range []string{
		strconv.Itoa(s.RingBits), strconv.Itoa(s.FracBits),
		strconv.Itoa(s.CoordinateCount), strconv.Itoa(s.BernoulliBits),
		strconv.FormatUint(uint64(s.StopNumerator), 10),
		strconv.Itoa(s.MaxGeometricSteps), s.SensitivitySteps.String(),
		s.EncodedLower.String(), s.EncodedUpper.String(),
		hex.EncodeToString(s.TranscriptHash[:]),
		hex.EncodeToString(s.GarblerCommitmentContext[:]),
		hex.EncodeToString(s.EvaluatorCommitmentContext[:]),
		hex.EncodeToString(s.GarblerSeedCommitment[:]),
		hex.EncodeToString(s.EvaluatorSeedCommitment[:]),
	} {
		write(value)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// digest binds both the canonical public contract and the exact generated
// MPCL source and the digest manifest of every reviewed native SHA/HMAC/AES
// dependency asset embedded in the packaged runtime.
func (s jointDPGCLaplaceSpec) digest() [32]byte {
	assets := jointDPMPCLManifestDigest()
	return s.digestWithAssets(assets)
}

func (s jointDPGCLaplaceSpec) digestWithAssets(assets [32]byte) [32]byte {
	contract := s.contractDigest()
	source := jointDPGCCircuitSource(s)
	h := sha256.New()
	h.Write([]byte(jointDPGCTemplateVersion))
	h.Write([]byte{0})
	h.Write(contract[:])
	h.Write([]byte{0})
	h.Write([]byte(source))
	h.Write([]byte{0})
	h.Write(assets[:])
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (s jointDPGCLaplaceSpec) purpose() string {
	digest := s.digest()
	return "joint-dp-laplace-v2/" + hex.EncodeToString(digest[:])
}

func jointDPDeriveAESKey(transcript [32]byte, garblerSeed,
	evaluatorSeed [32]byte) [16]byte {
	var ikm [64]byte
	copy(ikm[:32], garblerSeed[:])
	copy(ikm[32:], evaluatorSeed[:])
	extract := hmac.New(sha256.New, transcript[:])
	extract.Write(ikm[:])
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte("dsVert/joint-dp/aes128ctr-prg/v2"))
	expand.Write(transcript[:])
	expand.Write([]byte{1})
	var key [16]byte
	copy(key[:], expand.Sum(nil))
	clear(prk)
	return key
}

func jointDPAESCTRBytes(key [16]byte, transcript [32]byte, count int) []byte {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	result := make([]byte, count)
	var input [aes.BlockSize]byte
	copy(input[:12], transcript[:12])
	for offset, counter := 0, uint32(0); offset < count; counter++ {
		binary.BigEndian.PutUint32(input[12:], counter)
		var output [aes.BlockSize]byte
		block.Encrypt(output[:], input[:])
		offset += copy(result[offset:], output[:])
	}
	return result
}

func jointDPSampleTruncatedGeometric(random []byte, offset *int,
	bits int, stop uint32, steps int) (uint32, error) {
	bytesPerDraw := bits / 8
	var count uint32
	active := true
	for i := 0; i < steps; i++ {
		if *offset+bytesPerDraw > len(random) {
			return 0, io.ErrUnexpectedEOF
		}
		var u uint32
		if bits == 8 {
			u = uint32(random[*offset])
		} else {
			u = uint32(binary.LittleEndian.Uint16(random[*offset : *offset+2]))
		}
		*offset += bytesPerDraw
		if active && u >= stop {
			count++
		} else {
			active = false
		}
	}
	return count, nil
}

func jointDPReferenceNoise(s jointDPGCLaplaceSpec, garblerSeed,
	evaluatorSeed [32]byte) ([]int64, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if jointDPSeedCommitment(s.GarblerCommitmentContext, garblerSeed) !=
		s.GarblerSeedCommitment ||
		jointDPSeedCommitment(s.EvaluatorCommitmentContext, evaluatorSeed) !=
			s.EvaluatorSeedCommitment {
		return nil, fmt.Errorf("joint-dp-gc: private seed commitment mismatch")
	}
	randomBytes := 2 * s.CoordinateCount * s.MaxGeometricSteps * (s.BernoulliBits / 8)
	key := jointDPDeriveAESKey(s.TranscriptHash, garblerSeed, evaluatorSeed)
	random := jointDPAESCTRBytes(key, s.TranscriptHash, randomBytes)
	clear(key[:])
	defer clear(random)
	result := make([]int64, s.CoordinateCount)
	offset := 0
	for i := range result {
		left, err := jointDPSampleTruncatedGeometric(random, &offset,
			s.BernoulliBits, s.StopNumerator, s.MaxGeometricSteps)
		if err != nil {
			return nil, err
		}
		right, err := jointDPSampleTruncatedGeometric(random, &offset,
			s.BernoulliBits, s.StopNumerator, s.MaxGeometricSteps)
		if err != nil {
			return nil, err
		}
		result[i] = int64(left) - int64(right)
	}
	return result, nil
}

var jointDPGCCache = struct {
	sync.Mutex
	entries map[string]*circuit.Circuit
}{entries: make(map[string]*circuit.Circuit)}

func jointDPGCCompile(s jointDPGCLaplaceSpec) (*circuit.Circuit, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	digest := s.digest()
	key := hex.EncodeToString(digest[:])
	jointDPGCCache.Lock()
	if cached := jointDPGCCache.entries[key]; cached != nil {
		jointDPGCCache.Unlock()
		return cached, nil
	}
	jointDPGCCache.Unlock()
	source := jointDPGCCircuitSource(s)
	var circ *circuit.Circuit
	err := jointDPWithMPCLRuntime(func() error {
		var compileErr error
		circ, _, compileErr = compiler.New(utils.NewParams()).Compile(source, nil)
		return compileErr
	})
	if err != nil {
		return nil, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-gc: compile circuit with pinned MPCL runtime: %w", err))
	}
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		circ.Outputs.Size() != (s.CoordinateCount+1)*exactGCTypeBits(s.RingBits) {
		return nil, fmt.Errorf("joint-dp-gc: compiler produced an invalid circuit shape")
	}
	jointDPGCCache.Lock()
	jointDPGCCache.entries[key] = circ
	jointDPGCCache.Unlock()
	return circ, nil
}

func jointDPWriteByteArray(source *strings.Builder, name string, value []byte) {
	for i, b := range value {
		fmt.Fprintf(source, "\t%s[%d] = byte(0x%02x)\n", name, i, b)
	}
}

func jointDPResidue(value *big.Int, bits int) *big.Int {
	result := new(big.Int).Set(value)
	if result.Sign() < 0 {
		result.Add(result, exactGCModulus(bits))
	}
	return result
}

func jointDPGCCircuitSource(s jointDPGCLaplaceSpec) string {
	typeBits := exactGCTypeBits(s.RingBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	mask := exactGCMask(s.RingBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(s.RingBits-1)).Text(16)
	lower := jointDPResidue(s.EncodedLower, s.RingBits).Text(16)
	upper := jointDPResidue(s.EncodedUpper, s.RingBits).Text(16)
	randomBytes := 2 * s.CoordinateCount * s.MaxGeometricSteps * (s.BernoulliBits / 8)
	blocks := (randomBytes + aes.BlockSize - 1) / aes.BlockSize
	var source strings.Builder
	source.WriteString("package main\nimport (\n\t\"crypto/aes\"\n\t\"crypto/hmac\"\n\t\"crypto/sha256\"\n)\n")
	fmt.Fprintf(&source, "type Garbler struct {\n\tStat [%d]%s\n\tSeed [32]byte\n\tOutputMask [%d]%s\n\tValidityMask bool\n}\n",
		s.CoordinateCount, uintType, s.CoordinateCount, uintType)
	fmt.Fprintf(&source, "type Evaluator struct {\n\tStat [%d]%s\n\tSeed [32]byte\n}\n",
		s.CoordinateCount, uintType)
	fmt.Fprintf(&source, "func signedLess(a, b %s) bool {\n\tan := (a & %s(0x%s)) != 0\n\tbn := (b & %s(0x%s)) != 0\n\treturn (an && !bn) || (an == bn && a < b)\n}\n",
		uintType, uintType, sign, uintType, sign)
	fmt.Fprintf(&source, "func main(g Garbler, e Evaluator) [%d]%s {\n",
		s.CoordinateCount+1, uintType)
	source.WriteString("\tvar gpre [64]byte\n\tvar epre [64]byte\n")
	jointDPWriteByteArray(&source, "gpre", s.GarblerCommitmentContext[:])
	jointDPWriteByteArray(&source, "epre", s.EvaluatorCommitmentContext[:])
	source.WriteString("\tfor i := 0; i < 32; i++ {\n\t\tgpre[32+i] = g.Seed[i]\n\t\tepre[32+i] = e.Seed[i]\n\t}\n")
	source.WriteString("\tghash := sha256.Sum256(gpre[:])\n\tehash := sha256.Sum256(epre[:])\n\tvalid := true\n")
	for i := 0; i < 32; i++ {
		fmt.Fprintf(&source, "\tvalid = valid && ghash[%d] == byte(0x%02x) && ehash[%d] == byte(0x%02x)\n",
			i, s.GarblerSeedCommitment[i], i, s.EvaluatorSeedCommitment[i])
	}
	source.WriteString("\tvar salt [32]byte\n")
	jointDPWriteByteArray(&source, "salt", s.TranscriptHash[:])
	source.WriteString("\tvar ikm [64]byte\n\tfor i := 0; i < 32; i++ {\n\t\tikm[i] = g.Seed[i]\n\t\tikm[32+i] = e.Seed[i]\n\t}\n")
	source.WriteString("\tprk := hmac.SumSHA256(ikm[:], salt[:])\n")
	info := append([]byte("dsVert/joint-dp/aes128ctr-prg/v2"), s.TranscriptHash[:]...)
	info = append(info, 1)
	fmt.Fprintf(&source, "\tvar info [%d]byte\n", len(info))
	jointDPWriteByteArray(&source, "info", info)
	source.WriteString("\tfullkey := hmac.SumSHA256(info[:], prk[:])\n\tvar key [16]byte\n\tfor i := 0; i < 16; i++ { key[i] = fullkey[i] }\n")
	fmt.Fprintf(&source, "\tvar random [%d]byte\n", blocks*aes.BlockSize)
	for block := 0; block < blocks; block++ {
		fmt.Fprintf(&source, "\tvar counter%d [16]byte\n", block)
		jointDPWriteByteArray(&source, fmt.Sprintf("counter%d", block), s.TranscriptHash[:12])
		counter := make([]byte, 4)
		binary.BigEndian.PutUint32(counter, uint32(block))
		for j, b := range counter {
			fmt.Fprintf(&source, "\tcounter%d[%d] = byte(0x%02x)\n", block, 12+j, b)
		}
		fmt.Fprintf(&source, "\tblock%d := aes.Block128(key, counter%d)\n", block, block)
		fmt.Fprintf(&source, "\tfor j := 0; j < 16; j++ { random[%d+j] = block%d[j] }\n",
			block*aes.BlockSize, block)
	}
	fmt.Fprintf(&source, "\tvar geom [%d]uint32\n\tvar active [%d]bool\n",
		2*s.CoordinateCount, 2*s.CoordinateCount)
	fmt.Fprintf(&source, "\tfor j := 0; j < %d; j++ { active[j] = true }\n", 2*s.CoordinateCount)
	bytesPerDraw := s.BernoulliBits / 8
	for step := 0; step < s.MaxGeometricSteps; step++ {
		for j := 0; j < 2*s.CoordinateCount; j++ {
			// Each geometric owns one contiguous, fixed-size slice.  This keeps
			// the circuit byte-for-byte aligned with the independent reference
			// sampler and makes coordinate prefix tests meaningful.
			offset := (j*s.MaxGeometricSteps + step) * bytesPerDraw
			if s.BernoulliBits == 8 {
				fmt.Fprintf(&source, "\tu_%d_%d := uint32(random[%d])\n", step, j, offset)
			} else {
				fmt.Fprintf(&source, "\tu_%d_%d := uint32(random[%d]) | (uint32(random[%d]) << 8)\n",
					step, j, offset, offset+1)
			}
			fmt.Fprintf(&source, "\tcont_%d_%d := u_%d_%d >= uint32(%d)\n",
				step, j, step, j, s.StopNumerator)
			fmt.Fprintf(&source, "\tif active[%d] && cont_%d_%d { geom[%d] = geom[%d] + 1 }\n",
				j, step, j, j, j)
			fmt.Fprintf(&source, "\tactive[%d] = active[%d] && cont_%d_%d\n", j, j, step, j)
		}
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", s.CoordinateCount+1, uintType)
	for i := 0; i < s.CoordinateCount; i++ {
		fmt.Fprintf(&source, "\tx%d := (g.Stat[%d] + e.Stat[%d]) & %s(0x%s)\n",
			i, i, i, uintType, mask)
		fmt.Fprintf(&source, "\tvalid = valid && !signedLess(x%d, %s(0x%s)) && !signedLess(%s(0x%s), x%d)\n",
			i, uintType, lower, uintType, upper, i)
	}
	// Compute every payload only after all coordinates and both commitments
	// have contributed to the single validity bit.  Invalid inputs therefore
	// produce an all-zero masked payload, never a valid prefix.
	for i := 0; i < s.CoordinateCount; i++ {
		fmt.Fprintf(&source, "\tvar noise%d %s\n", i, uintType)
		fmt.Fprintf(&source, "\tif geom[%d] >= geom[%d] { noise%d = (%s(geom[%d]-geom[%d]) << %d) & %s(0x%s) } else { noise%d = (%s(0) - (%s(geom[%d]-geom[%d]) << %d)) & %s(0x%s) }\n",
			2*i, 2*i+1, i, uintType, 2*i, 2*i+1, s.FracBits, uintType, mask,
			i, uintType, uintType, 2*i+1, 2*i, s.FracBits, uintType, mask)
		fmt.Fprintf(&source, "\tcandidate%d := (x%d + noise%d) & %s(0x%s)\n",
			i, i, i, uintType, mask)
		fmt.Fprintf(&source, "\tresult%d := candidate%d\n", i, i)
		fmt.Fprintf(&source, "\tif signedLess(candidate%d, %s(0x%s)) { result%d = %s(0x%s) }\n",
			i, uintType, lower, i, uintType, lower)
		fmt.Fprintf(&source, "\tif signedLess(%s(0x%s), candidate%d) { result%d = %s(0x%s) }\n",
			uintType, upper, i, i, uintType, upper)
		fmt.Fprintf(&source, "\tif !valid { result%d = 0 }\n", i)
		fmt.Fprintf(&source, "\tout[%d] = (result%d - g.OutputMask[%d]) & %s(0x%s)\n",
			i, i, i, uintType, mask)
	}
	fmt.Fprintf(&source, "\tout[%d] = %s(0)\n\tif valid != g.ValidityMask { out[%d] = %s(1) }\n\treturn out\n}\n",
		s.CoordinateCount, uintType, s.CoordinateCount, uintType)
	return source.String()
}

func jointDPPackFields(fields []struct {
	value *big.Int
	bits  int
}) *big.Int {
	result := new(big.Int)
	offset := 0
	for _, field := range fields {
		result.Or(result, new(big.Int).Lsh(new(big.Int).Set(field.value), uint(offset)))
		offset += field.bits
	}
	return result
}

func jointDPPackInput(shares []*big.Int, seed [32]byte, masks []*big.Int,
	validityMask bool, s jointDPGCLaplaceSpec, garbler bool) *big.Int {
	typeBits := exactGCTypeBits(s.RingBits)
	fields := make([]struct {
		value *big.Int
		bits  int
	}, 0, len(shares)+32+len(masks)+1)
	add := func(value *big.Int, bits int) {
		fields = append(fields, struct {
			value *big.Int
			bits  int
		}{value, bits})
	}
	for _, share := range shares {
		add(share, typeBits)
	}
	for _, b := range seed {
		add(new(big.Int).SetUint64(uint64(b)), 8)
	}
	if garbler {
		for _, mask := range masks {
			add(mask, typeBits)
		}
		if validityMask {
			add(big.NewInt(1), 1)
		} else {
			add(big.NewInt(0), 1)
		}
	}
	return jointDPPackFields(fields)
}

func jointDPDeterministicMasks(seed [32]byte, digest [32]byte,
	s jointDPGCLaplaceSpec) ([]*big.Int, bool) {
	result := make([]*big.Int, s.CoordinateCount)
	modulus := exactGCModulus(s.RingBits)
	for i := range result {
		mac := hmac.New(sha256.New, seed[:])
		mac.Write([]byte("dsVert/joint-dp/output-mask/v2"))
		mac.Write(digest[:])
		var index [4]byte
		binary.BigEndian.PutUint32(index[:], uint32(i))
		mac.Write(index[:])
		result[i] = new(big.Int).Mod(new(big.Int).SetBytes(mac.Sum(nil)), modulus)
	}
	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte("dsVert/joint-dp/validity-mask/v2"))
	mac.Write(digest[:])
	return result, mac.Sum(nil)[0]&1 == 1
}

func jointDPValidateSession(session exactGCSession, s jointDPGCLaplaceSpec) error {
	if err := session.validate(); err != nil {
		return err
	}
	if session.Spec.Operation != exactGCJointDPLaplace ||
		session.Spec.RingBits != s.RingBits || session.Spec.FracBits != s.FracBits ||
		session.Spec.VectorLen != s.CoordinateCount || session.Purpose != s.purpose() {
		return fmt.Errorf("joint-dp-gc: exact-GC session is not bound to the sampler contract")
	}
	return s.validate()
}

func jointDPGCRunGarbler(rw io.ReadWriter, session exactGCSession,
	s jointDPGCLaplaceSpec, shares []*big.Int, seed [32]byte) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("joint-dp-gc: nil peer channel")
	}
	if err := jointDPValidateSession(session, s); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	if jointDPSeedCommitment(s.GarblerCommitmentContext, seed) != s.GarblerSeedCommitment {
		return nil, fmt.Errorf("joint-dp-gc: local garbler seed commitment mismatch")
	}
	circ, err := jointDPGCCompile(s)
	if err != nil {
		return nil, err
	}
	digest := s.digest()
	masks, validityMask := jointDPDeterministicMasks(seed, digest, s)
	input := jointDPPackInput(shares, seed, masks, validityMask, s, true)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return append(masks, new(big.Int).SetUint64(boolToUint64(validityMask))), nil
}

func jointDPGCRunEvaluator(rw io.ReadWriter, session exactGCSession,
	s jointDPGCLaplaceSpec, shares []*big.Int, seed [32]byte) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("joint-dp-gc: nil peer channel")
	}
	if err := jointDPValidateSession(session, s); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	if jointDPSeedCommitment(s.EvaluatorCommitmentContext, seed) != s.EvaluatorSeedCommitment {
		return nil, fmt.Errorf("joint-dp-gc: local evaluator seed commitment mismatch")
	}
	circ, err := jointDPGCCompile(s)
	if err != nil {
		return nil, err
	}
	input := jointDPPackInput(shares, seed, nil, false, s, false)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	result, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return jointDPUnpackOutputs(result, s), nil
}

func jointDPUnpackOutputs(value *big.Int, s jointDPGCLaplaceSpec) []*big.Int {
	typeBits := exactGCTypeBits(s.RingBits)
	result := make([]*big.Int, s.CoordinateCount+1)
	for i := range result {
		result[i] = new(big.Int).Rsh(new(big.Int).Set(value), uint(i*typeBits))
		bits := s.RingBits
		if i == s.CoordinateCount {
			bits = 1
		}
		result[i].And(result[i], exactGCMask(bits))
	}
	return result
}

func boolToUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
