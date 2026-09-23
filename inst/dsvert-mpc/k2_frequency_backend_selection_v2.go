package main

import (
	"fmt"
	"math"
	"math/big"
	"os"
	"strconv"
)

const (
	jointDPFrequencyBackendSelectionRequestVersionV2 = "dsvert-joint-dp-frequency-backend-selection-request-v2"
	jointDPFrequencyBackendSelectionVersionV2        = "dsvert-joint-dp-frequency-backend-selection-v2"
	jointDPFrequencySelectionCertificateVersionV2    = "dsvert-joint-dp-frequency-backend-selection-certificate-v2"
	jointDPFrequencySelectionPolicyV2                = "minimum_certified_simultaneous_95_abs_convolution_tie_v2"
	jointDPFrequencySelectionTieBreakV2              = "convolution_laplace_v4_on_equal_certified_radius"
	jointDPFrequencyExactModularMethod               = "exact_two_draw_exponential_union_modular_clamp_v1"
)

// If both draws have magnitude <=T, their sum has magnitude <=2T.
// P(any |Z|>T) <=4*d*exp(-alpha*(T+1)). For k=ceil(log10(80*d))
// and T=ceil(3*k/alpha), exp(3)>10 makes that probability less than .05.
// The certified radius only uses that event when it also implies signed-ring
// headroom; otherwise the fixed [0,U] clamp supplies a deterministic radius U.
func jointDPFrequencyExactConvolutionAccuracy(plan jointDPVectorConvolutionPlanOutput, upper *big.Int) (jointDPFrequencyAccuracyCertificate, error) {
	var zero jointDPFrequencyAccuracyCertificate
	if plan.Version != jointDPVectorConvolutionPlanVersionV4 || !plan.CapabilityAvailable || upper == nil || upper.Sign() <= 0 || upper.Cmp(exactGCMaxSigned(128)) > 0 {
		return zero, fmt.Errorf("invalid exact convolution accuracy request")
	}
	alpha := jointDPVectorConvolutionExactRate(plan)
	factor, k := int64(1), int64(0)
	for factor < int64(80*plan.TotalCoordinateCount) {
		factor *= 10
		k++
	}
	threshold := jointDPVectorCeilRat(new(big.Rat).Quo(big.NewRat(3*k, 1), alpha))
	radius := new(big.Int).Lsh(threshold, 1)
	if radius.Cmp(upper) > 0 || new(big.Int).Add(new(big.Int).Set(upper), radius).Cmp(exactGCMaxSigned(128)) > 0 {
		radius.Set(upper)
	}
	return jointDPFrequencyAccuracyCertificate{
		Primitive: jointDPVectorConvolutionBackendV4, Event: jointDPFrequencyAccuracyEvent, Method: jointDPFrequencyExactModularMethod,
		ReleaseTVUpperNumerator: "0", ReleaseTVUpperDenominator: "1", Simultaneous95Abs: radius.String(), AbsoluteSupport: upper.String(),
	}, nil
}

func jointDPFrequencyValidateWorkloadV2(input jointDPFrequencyBackendSelectionInput) error {
	// Retain v1's public adjacency, sensitivity, dimension and epsilon pairing.
	shape := input
	shape.ConvolutionRequest.Delta = jointDPFrequencyCanonicalFloat(.01)
	shape.GaussianRequest.Delta = jointDPFrequencyCanonicalFloat(.01 * (1 - 128*(math.Nextafter(1, 2)-1)))
	if err := jointDPFrequencyValidateWorkload(shape); err != nil {
		return err
	}
	value, err := strconv.ParseFloat(input.ConvolutionRequest.Delta, 64)
	if err != nil || value < 0 || value >= 1 || math.IsNaN(value) || jointDPFrequencyCanonicalFloat(value) != input.ConvolutionRequest.Delta {
		return fmt.Errorf("invalid canonical convolution delta")
	}
	if input.GaussianRequest.Delta != jointDPFrequencyCanonicalFloat(value*(1-128*(math.Nextafter(1, 2)-1))) {
		return fmt.Errorf("Gaussian delta is not paired to convolution")
	}
	return nil
}

func selectJointDPFrequencyBackendV2(input jointDPFrequencyBackendSelectionInput) (jointDPFrequencyBackendSelectionOutput, error) {
	var zero jointDPFrequencyBackendSelectionOutput
	if input.Version != jointDPFrequencyBackendSelectionRequestVersionV2 {
		return zero, fmt.Errorf("invalid frequency backend selector version")
	}
	if err := jointDPFrequencyValidateWorkloadV2(input); err != nil {
		return zero, err
	}
	upper, err := jointDPConvolutionParseUnsigned(input.CoordinateUpperBound, "coordinate_upper_bound")
	if err != nil || upper.Sign() <= 0 || upper.Cmp(exactGCMaxSigned(128)) > 0 {
		return zero, fmt.Errorf("coordinate_upper_bound must fit positive signed Ring128")
	}
	convolution, err := jointDPPlanVectorConvolutionLaplaceV4(input.ConvolutionRequest)
	if err != nil {
		return zero, fmt.Errorf("exact convolution planner unavailable: %v", err)
	}
	certificate, err := jointDPFrequencyExactConvolutionAccuracy(convolution, upper)
	if err != nil {
		return zero, err
	}
	certificate.PlanSHA256, err = jointDPFrequencyPlanHash(convolution)
	if err != nil {
		return zero, err
	}
	output := jointDPFrequencyBackendSelectionOutput{
		Version: jointDPFrequencyBackendSelectionVersionV2, Request: input, ConvolutionPlan: convolution, ConvolutionCertificate: certificate,
		SelectionCertificate: jointDPFrequencySelectionCertificate{
			Version: jointDPFrequencySelectionCertificateVersionV2, Policy: jointDPFrequencySelectionPolicyV2, Objective: jointDPFrequencySelectionObjective,
			SelectedPrimitive: jointDPVectorConvolutionBackendV4, SelectedPlanSHA256: certificate.PlanSHA256, SelectedSimultaneous95Abs: certificate.Simultaneous95Abs,
			TieBreak: jointDPFrequencySelectionTieBreakV2, InputScope: jointDPFrequencyPublicInputScope,
		},
	}
	gaussian, err := jointDPPlanVectorGaussian(input.GaussianRequest)
	if err != nil {
		output.GaussianUnavailableReason = "public_gaussian_plan_unavailable: " + err.Error()
		return output, nil
	}
	gaussianCertificate, err := jointDPFrequencyGaussianAccuracy(gaussian)
	if err != nil {
		return zero, err
	}
	support, _ := new(big.Int).SetString(gaussianCertificate.AbsoluteSupport, 10)
	if !jointDPFrequencyNoWrap(upper, support) {
		output.GaussianUnavailableReason = "public_gaussian_plan_lacks_Ring128_no_wrap_headroom"
		return output, nil
	}
	gaussianCertificate.PlanSHA256, err = jointDPFrequencyPlanHash(gaussian)
	if err != nil {
		return zero, err
	}
	output.GaussianPlan, output.GaussianCertificate = &gaussian, &gaussianCertificate
	convolutionRadius, _ := new(big.Int).SetString(certificate.Simultaneous95Abs, 10)
	gaussianRadius, _ := new(big.Int).SetString(gaussianCertificate.Simultaneous95Abs, 10)
	if gaussianRadius.Cmp(convolutionRadius) < 0 {
		output.SelectionCertificate.SelectedPrimitive = jointDPGaussianBackend
		output.SelectionCertificate.SelectedPlanSHA256 = gaussianCertificate.PlanSHA256
		output.SelectionCertificate.SelectedSimultaneous95Abs = gaussianCertificate.Simultaneous95Abs
	}
	return output, nil
}

func handleJointDPFrequencyBackendSelectionV2() {
	input, err := decodeJointDPFrequencyBackendSelection(os.Stdin)
	if err != nil {
		outputError("joint-DP Frequency backend selector: " + err.Error())
		return
	}
	output, err := selectJointDPFrequencyBackendV2(input)
	if err != nil {
		outputError("joint-DP Frequency backend selector: " + err.Error())
		return
	}
	mpcWriteOutput(output)
}
