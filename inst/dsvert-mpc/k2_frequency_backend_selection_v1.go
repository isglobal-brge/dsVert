package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
)

const (
	jointDPFrequencyBackendSelectionRequestVersion = "dsvert-joint-dp-frequency-backend-selection-request-v1"
	jointDPFrequencyBackendSelectionVersion        = "dsvert-joint-dp-frequency-backend-selection-v1"
	jointDPFrequencySelectionCertificateVersion    = "dsvert-joint-dp-frequency-backend-selection-certificate-v1"
	jointDPFrequencySelectionPolicy                = "minimum_certified_simultaneous_95_abs_convolution_tie_v1"
	jointDPFrequencySelectionObjective             = "minimum_certified_simultaneous_95_abs"
	jointDPFrequencySelectionTieBreak              = "convolution_laplace_v3_on_equal_certified_radius"
	jointDPFrequencyPublicInputScope               = "public_adjacency_planner_requests_and_coordinate_upper_bound_only"
	jointDPFrequencyPlanHashDomain                 = "dsVert/frequency/full-plan/v1"
	jointDPFrequencyAccuracyEvent                  = "max_j_abs_error_gt_radius"
	jointDPFrequencyExactTailMethod                = "exact_two_discrete_laplace_convolution_tail_v1"
	jointDPFrequencyEnvelopeMethod                 = "dyadic_exponential_envelope_v1"
	jointDPFrequencySupportMethod                  = "finite_support_v1"
	jointDPFrequencyGaussianMethod                 = "gaussian_plan_v2_subgaussian_mgf_tv_transfer"
	jointDPFrequencyBackendSelectionMaxInputBytes  = 4096
	jointDPFrequencyExactRadiusCap                 = 4096
	jointDPFrequencyEnvelopeMaxShift               = 1 << 20
)

type jointDPFrequencyBackendSelectionInput struct {
	Version              string                   `json:"version"`
	Adjacency            string                   `json:"adjacency"`
	CoordinateUpperBound string                   `json:"coordinate_upper_bound"`
	ConvolutionRequest   jointDPVectorPlanInput   `json:"convolution_request"`
	GaussianRequest      jointDPGaussianPlanInput `json:"gaussian_request"`
}
type jointDPFrequencyAccuracyCertificate struct {
	Primitive                 string `json:"primitive"`
	PlanSHA256                string `json:"plan_sha256"`
	Event                     string `json:"event"`
	Method                    string `json:"method"`
	ReleaseTVUpperNumerator   string `json:"release_tv_upper_numerator"`
	ReleaseTVUpperDenominator string `json:"release_tv_upper_denominator"`
	Simultaneous95Abs         string `json:"simultaneous_95_abs"`
	AbsoluteSupport           string `json:"absolute_support"`
}
type jointDPFrequencySelectionCertificate struct {
	Version                    string `json:"version"`
	Policy                     string `json:"policy"`
	Objective                  string `json:"objective"`
	SelectedPrimitive          string `json:"selected_primitive"`
	SelectedPlanSHA256         string `json:"selected_plan_sha256"`
	SelectedSimultaneous95Abs  string `json:"selected_simultaneous_95_abs"`
	TieBreak                   string `json:"tie_break"`
	InputScope                 string `json:"input_scope"`
	SourceMaterialConsulted    bool   `json:"source_material_consulted"`
	PrivateRandomnessConsulted bool   `json:"private_randomness_consulted"`
	RuntimeFailureConsulted    bool   `json:"runtime_failure_consulted"`
	AutomaticFallback          bool   `json:"automatic_fallback"`
	UtilityOptimalityClaimed   bool   `json:"utility_optimality_claimed"`
}
type jointDPFrequencyBackendSelectionOutput struct {
	Version                string                                `json:"version"`
	Request                jointDPFrequencyBackendSelectionInput `json:"request"`
	ConvolutionPlan        jointDPVectorConvolutionPlanOutput    `json:"convolution_plan"`
	GaussianPlan           jointDPGaussianPlanOutput             `json:"gaussian_plan"`
	ConvolutionCertificate jointDPFrequencyAccuracyCertificate   `json:"convolution_certificate"`
	GaussianCertificate    jointDPFrequencyAccuracyCertificate   `json:"gaussian_certificate"`
	SelectionCertificate   jointDPFrequencySelectionCertificate  `json:"selection_certificate"`
}

func decodeJointDPFrequencyBackendSelection(
	reader io.Reader) (jointDPFrequencyBackendSelectionInput, error) {
	var input jointDPFrequencyBackendSelectionInput
	data, err := io.ReadAll(io.LimitReader(
		reader, jointDPFrequencyBackendSelectionMaxInputBytes+1))
	if err != nil {
		return input, fmt.Errorf("read frequency backend selector: %w", err)
	}
	if len(data) > jointDPFrequencyBackendSelectionMaxInputBytes {
		return input, fmt.Errorf("input exceeds %d bytes",
			jointDPFrequencyBackendSelectionMaxInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("parse frequency backend selector: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return input, err
	}
	return input, nil
}

func jointDPFrequencyPlanHash(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return "", err
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return "", err
	}
	message := append([]byte(jointDPFrequencyPlanHashDomain+"|"),
		bytes.TrimSuffix(canonical.Bytes(), []byte("\n"))...)
	digest := sha256.Sum256(message)
	return fmt.Sprintf("%x", digest), nil
}

func jointDPFrequencyCanonicalFloat(value float64) string {
	formatted := strconv.FormatFloat(value, 'e', 16, 64)
	separator := strings.IndexByte(formatted, 'e')
	mantissa := strings.TrimSuffix(strings.TrimRight(
		formatted[:separator], "0"), ".")
	return mantissa + formatted[separator:]
}

func jointDPFrequencyPairedFloat(convolution, gaussian, name string) error {
	value, err := strconv.ParseFloat(convolution, 64)
	if err != nil || value <= 0 || math.IsNaN(value) || math.IsInf(value, 0) ||
		jointDPFrequencyCanonicalFloat(value) != convolution {
		return fmt.Errorf("invalid canonical convolution %s", name)
	}
	machineEpsilon := math.Nextafter(1, 2) - 1
	if gaussian != jointDPFrequencyCanonicalFloat(
		value*(1-128*machineEpsilon)) {
		return fmt.Errorf("Gaussian %s is not paired to convolution", name)
	}
	return nil
}

func jointDPFrequencyValidateWorkload(
	input jointDPFrequencyBackendSelectionInput) error {
	wantL1, baseL2 := "", 0.0
	machineEpsilon := math.Nextafter(1, 2) - 1
	switch input.Adjacency {
	case "add_remove_patient":
		wantL1, baseL2 = "1", 1
	case "replace_one_fixed_cohort":
		wantL1, baseL2 = "2", math.Sqrt2
	default:
		return fmt.Errorf("invalid Frequency adjacency")
	}
	wantL2 := jointDPFrequencyCanonicalFloat(baseL2 * (1 + 128*machineEpsilon))
	if input.ConvolutionRequest.SensitivitySteps != wantL1 ||
		input.GaussianRequest.L2SensitivitySteps != wantL2 {
		return fmt.Errorf("planner sensitivities do not match Frequency adjacency")
	}
	if input.ConvolutionRequest.TotalCoordinateCount !=
		input.GaussianRequest.TotalCoordinateCount {
		return fmt.Errorf("planner coordinate counts must match")
	}
	if err := jointDPFrequencyPairedFloat(input.ConvolutionRequest.Epsilon,
		input.GaussianRequest.Epsilon, "epsilon"); err != nil {
		return err
	}
	return jointDPFrequencyPairedFloat(input.ConvolutionRequest.Delta,
		input.GaussianRequest.Delta, "delta")
}

func jointDPFrequencyPlanRat(numerator, denominator, name string) (*big.Rat, error) {
	n, nOK := new(big.Int).SetString(numerator, 10)
	d, dOK := new(big.Int).SetString(denominator, 10)
	if !nOK || !dOK || d.Sign() <= 0 || n.Sign() < 0 ||
		n.String() != numerator || d.String() != denominator {
		return nil, fmt.Errorf("invalid %s certificate", name)
	}
	return new(big.Rat).SetFrac(n, d), nil
}

// Exact ideal-law P(|X1+X2|>radius) for two discrete-Laplace draws.
func jointDPFrequencyConvolutionTail(p *big.Rat, radius int) (*big.Rat, error) {
	if p == nil || p.Sign() <= 0 || p.Cmp(big.NewRat(1, 1)) >= 0 || radius < 0 {
		return nil, fmt.Errorf("invalid convolution tail request")
	}
	exponent := big.NewInt(int64(radius + 1))
	pPower := new(big.Rat).SetFrac(
		new(big.Int).Exp(new(big.Int).Set(p.Num()), exponent, nil),
		new(big.Int).Exp(new(big.Int).Set(p.Denom()), exponent, nil))
	oneMinusP := new(big.Rat).Sub(big.NewRat(1, 1), p)
	onePlusP := new(big.Rat).Add(big.NewRat(1, 1), p)
	pSquared := new(big.Rat).Mul(p, p)
	shape := new(big.Rat).Quo(
		new(big.Rat).Add(big.NewRat(1, 1), pSquared), onePlusP)
	shape.Add(shape, p)
	shape.Add(shape, new(big.Rat).Mul(
		big.NewRat(int64(radius+1), 1), oneMinusP))
	numerator := new(big.Rat).Mul(big.NewRat(2, 1), pPower)
	numerator.Mul(numerator, shape)
	return numerator.Quo(numerator,
		new(big.Rat).Mul(onePlusP, onePlusP)), nil
}

// Beyond the exact cap, certify T(r)<=6*exp(-2*(r+1)*q/3) dyadically.
func jointDPFrequencyEnvelopeRadius(stop, denominator *big.Int,
	alpha *big.Rat, dimensions int, support *big.Int,
) (*big.Int, bool, error) {
	if stop == nil || denominator == nil || alpha == nil || support == nil ||
		stop.Sign() <= 0 || stop.Cmp(denominator) >= 0 ||
		alpha.Sign() <= 0 || dimensions < 1 || support.Sign() < 0 {
		return nil, false, fmt.Errorf("invalid convolution envelope request")
	}
	left := new(big.Int).Mul(big.NewInt(int64(6*dimensions)), alpha.Denom())
	right := new(big.Int).Set(alpha.Num())
	k := left.BitLen() - right.BitLen()
	if k < 0 {
		k = 0
	}
	if k > jointDPFrequencyEnvelopeMaxShift {
		return new(big.Int).Set(support), true, nil
	}
	if new(big.Int).Lsh(new(big.Int).Set(right), uint(k)).Cmp(left) < 0 {
		k++
	}
	if k > jointDPFrequencyEnvelopeMaxShift {
		return new(big.Int).Set(support), true, nil
	}
	numerator := new(big.Int).Mul(big.NewInt(int64(21*k)), denominator)
	divisor := new(big.Int).Mul(big.NewInt(20), stop)
	numerator.Add(numerator, new(big.Int).Sub(divisor, big.NewInt(1)))
	n := numerator.Quo(numerator, divisor)
	if n.Sign() <= 0 {
		return nil, false, fmt.Errorf("invalid convolution envelope radius")
	}
	radius := n.Sub(n, big.NewInt(1))
	if radius.Cmp(support) >= 0 {
		return new(big.Int).Set(support), true, nil
	}
	return radius, false, nil
}

func jointDPFrequencyConvolutionAccuracy(
	plan jointDPVectorConvolutionPlanOutput,
) (jointDPFrequencyAccuracyCertificate, error) {
	var certificate jointDPFrequencyAccuracyCertificate
	dimensions := plan.TotalCoordinateCount
	if !plan.CapabilityAvailable || plan.StopBits != jointDPVectorStopBits ||
		plan.BinaryGeometricBits < 1 ||
		plan.BinaryGeometricBits > jointDPVectorMaxBinaryBits ||
		dimensions < 1 || dimensions > jointDPVectorMaxTotal {
		return certificate, fmt.Errorf("invalid convolution plan certificate")
	}
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(plan.StopBits))
	stop, ok := new(big.Int).SetString(plan.StopNumerator, 10)
	if !ok || stop.Sign() <= 0 || stop.Cmp(denominator) >= 0 ||
		stop.String() != plan.StopNumerator {
		return certificate, fmt.Errorf("invalid convolution stop certificate")
	}
	p := new(big.Rat).SetFrac(
		new(big.Int).Sub(new(big.Int).Set(denominator), stop),
		new(big.Int).Set(denominator))
	tau, err := jointDPFrequencyPlanRat(plan.OneGeometricTVNumerator,
		plan.OneGeometricTVDenominator, "one-geometric TV")
	if err != nil {
		return certificate, err
	}
	eta := new(big.Rat).Mul(tau, big.NewRat(int64(4*dimensions), 1))
	alpha := new(big.Rat).Sub(big.NewRat(1, 20), eta)
	releaseTV := new(big.Rat).Set(eta)
	if releaseTV.Cmp(big.NewRat(1, 1)) > 0 {
		releaseTV.SetInt64(1)
	}
	support := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), uint(plan.BinaryGeometricBits)),
		big.NewInt(1))
	support.Lsh(support, 1)
	certificate = jointDPFrequencyAccuracyCertificate{
		Primitive: jointDPVectorConvolutionBackend, Event: jointDPFrequencyAccuracyEvent,
		ReleaseTVUpperNumerator:   releaseTV.Num().String(),
		ReleaseTVUpperDenominator: releaseTV.Denom().String(),
		AbsoluteSupport:           support.String(),
	}
	if alpha.Sign() <= 0 {
		certificate.Method = jointDPFrequencySupportMethod
		certificate.Simultaneous95Abs = support.String()
		return certificate, nil
	}
	maximum := jointDPFrequencyExactRadiusCap
	if support.Cmp(big.NewInt(int64(maximum+1))) < 0 {
		maximum = int(new(big.Int).Sub(support, big.NewInt(1)).Int64())
	}
	predicate := func(radius int) (bool, error) {
		tail, tailErr := jointDPFrequencyConvolutionTail(p, radius)
		if tailErr != nil {
			return false, tailErr
		}
		tail.Mul(tail, big.NewRat(int64(dimensions), 1))
		return tail.Cmp(alpha) <= 0, nil
	}
	certified, err := predicate(maximum)
	if err != nil {
		return certificate, err
	}
	if certified {
		low, high := 0, maximum
		for low < high {
			middle := low + (high-low)/2
			pass, predicateErr := predicate(middle)
			if predicateErr != nil {
				return certificate, predicateErr
			}
			if pass {
				high = middle
			} else {
				low = middle + 1
			}
		}
		certificate.Method = jointDPFrequencyExactTailMethod
		certificate.Simultaneous95Abs = big.NewInt(int64(low)).String()
		return certificate, nil
	}
	radius, fallback, err := jointDPFrequencyEnvelopeRadius(
		stop, denominator, alpha, dimensions, support)
	if err != nil {
		return certificate, err
	}
	certificate.Method = jointDPFrequencyEnvelopeMethod
	if fallback {
		certificate.Method = jointDPFrequencySupportMethod
	}
	certificate.Simultaneous95Abs = radius.String()
	return certificate, nil
}

func jointDPFrequencyGaussianAccuracy(
	plan jointDPGaussianPlanOutput,
) (jointDPFrequencyAccuracyCertificate, error) {
	var certificate jointDPFrequencyAccuracyCertificate
	if !plan.CapabilityAvailable || plan.TotalCoordinateCount < 1 ||
		plan.TotalCoordinateCount > jointDPVectorMaxTotal {
		return certificate, fmt.Errorf("invalid Gaussian plan certificate")
	}
	tv, err := jointDPFrequencyPlanRat(plan.VectorTotalTVUpperNumerator,
		plan.VectorTotalTVUpperDenominator, "Gaussian vector TV")
	if err != nil {
		return certificate, err
	}
	transfer := new(big.Rat).Mul(big.NewRat(2, 1), tv)
	if new(big.Rat).Sub(big.NewRat(1, 20), transfer).Sign() <= 0 {
		return certificate, fmt.Errorf("Gaussian TV exhausts accuracy alpha")
	}
	radius, err := jointDPConvolutionParseUnsigned(
		plan.Simultaneous95Abs, "Gaussian simultaneous radius")
	if err != nil {
		return certificate, err
	}
	support, err := jointDPConvolutionParseUnsigned(
		plan.MaximumNoiseMagnitudeTwoPeers, "Gaussian support")
	if err != nil || radius.Cmp(support) > 0 {
		return certificate, fmt.Errorf("invalid Gaussian accuracy certificate")
	}
	return jointDPFrequencyAccuracyCertificate{
		Primitive: jointDPGaussianBackend, Event: jointDPFrequencyAccuracyEvent,
		Method:                    jointDPFrequencyGaussianMethod,
		ReleaseTVUpperNumerator:   transfer.Num().String(),
		ReleaseTVUpperDenominator: transfer.Denom().String(),
		Simultaneous95Abs:         radius.String(), AbsoluteSupport: support.String(),
	}, nil
}

func jointDPFrequencyNoWrap(upper, support *big.Int) bool {
	if upper == nil || support == nil || upper.Sign() < 0 || support.Sign() < 0 {
		return false
	}
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127),
		big.NewInt(1))
	return new(big.Int).Add(upper, support).Cmp(maximum) <= 0
}

func jointDPFrequencyChoose(convolution, gaussian *big.Int) string {
	if gaussian.Cmp(convolution) < 0 {
		return jointDPGaussianBackend
	}
	return jointDPVectorConvolutionBackend
}

func selectJointDPFrequencyBackend(
	input jointDPFrequencyBackendSelectionInput,
) (jointDPFrequencyBackendSelectionOutput, error) {
	var output jointDPFrequencyBackendSelectionOutput
	if input.Version != jointDPFrequencyBackendSelectionRequestVersion {
		return output, fmt.Errorf("invalid frequency backend selector version")
	}
	if err := jointDPFrequencyValidateWorkload(input); err != nil {
		return output, err
	}
	upper, err := jointDPConvolutionParseUnsigned(
		input.CoordinateUpperBound, "coordinate_upper_bound")
	if err != nil || upper.Sign() == 0 {
		return output, fmt.Errorf("coordinate_upper_bound must be positive")
	}
	convolution, err := jointDPPlanVectorConvolutionLaplace(
		input.ConvolutionRequest)
	if err != nil || !convolution.CapabilityAvailable {
		return output, fmt.Errorf("convolution planner unavailable: %v", err)
	}
	gaussian, err := jointDPPlanVectorGaussian(input.GaussianRequest)
	if err != nil || !gaussian.CapabilityAvailable {
		return output, fmt.Errorf("Gaussian planner unavailable: %v", err)
	}
	convolutionCertificate, err := jointDPFrequencyConvolutionAccuracy(convolution)
	if err != nil {
		return output, err
	}
	gaussianCertificate, err := jointDPFrequencyGaussianAccuracy(gaussian)
	if err != nil {
		return output, err
	}
	convolutionCertificate.PlanSHA256, err = jointDPFrequencyPlanHash(convolution)
	if err != nil {
		return output, err
	}
	gaussianCertificate.PlanSHA256, err = jointDPFrequencyPlanHash(gaussian)
	if err != nil {
		return output, err
	}
	convolutionSupport, _ := new(big.Int).SetString(
		convolutionCertificate.AbsoluteSupport, 10)
	gaussianSupport, _ := new(big.Int).SetString(
		gaussianCertificate.AbsoluteSupport, 10)
	if !jointDPFrequencyNoWrap(upper, convolutionSupport) ||
		!jointDPFrequencyNoWrap(upper, gaussianSupport) {
		return output, fmt.Errorf("both complete noise supports must fit Ring128")
	}
	convolutionRadius, _ := new(big.Int).SetString(
		convolutionCertificate.Simultaneous95Abs, 10)
	gaussianRadius, _ := new(big.Int).SetString(
		gaussianCertificate.Simultaneous95Abs, 10)
	selected := jointDPFrequencyChoose(convolutionRadius, gaussianRadius)
	selectedHash := convolutionCertificate.PlanSHA256
	selectedRadius := convolutionCertificate.Simultaneous95Abs
	if selected == jointDPGaussianBackend {
		selectedHash = gaussianCertificate.PlanSHA256
		selectedRadius = gaussianCertificate.Simultaneous95Abs
	}
	return jointDPFrequencyBackendSelectionOutput{
		Version: jointDPFrequencyBackendSelectionVersion, Request: input,
		ConvolutionPlan: convolution, GaussianPlan: gaussian,
		ConvolutionCertificate: convolutionCertificate,
		GaussianCertificate:    gaussianCertificate,
		SelectionCertificate: jointDPFrequencySelectionCertificate{
			Version:           jointDPFrequencySelectionCertificateVersion,
			Policy:            jointDPFrequencySelectionPolicy,
			Objective:         jointDPFrequencySelectionObjective,
			SelectedPrimitive: selected, SelectedPlanSHA256: selectedHash,
			SelectedSimultaneous95Abs: selectedRadius,
			TieBreak:                  jointDPFrequencySelectionTieBreak,
			InputScope:                jointDPFrequencyPublicInputScope,
		},
	}, nil
}

func handleJointDPFrequencyBackendSelection() {
	input, err := decodeJointDPFrequencyBackendSelection(os.Stdin)
	if err != nil {
		outputError("joint-DP Frequency backend selector: " + err.Error())
		return
	}
	output, err := selectJointDPFrequencyBackend(input)
	if err != nil {
		outputError("joint-DP Frequency backend selector: " + err.Error())
		return
	}
	mpcWriteOutput(output)
}
