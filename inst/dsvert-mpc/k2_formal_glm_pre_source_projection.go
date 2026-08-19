package main

// Pure, pre-source projection of the formal-GLM DP lattice.  It contains
// only values determined by the cross-approved Phase-1.5 plan.  In
// particular it has no receipt, transcript, attempt, source path or secret.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
)

const (
	formalGLMPreSourceDPProjectionVersion = "dsvert-formal-glm-pre-source-dp-projection-v1"
	formalGLMPreSourceDPProjectionPurpose = "formal_glm_phase15_phase16_exact_dp_projection_v1"
	formalGLMCanonicalPreSourceDPVersion  = "dsvert-formal-glm-canonical-pre-source-dp-v1"
	formalGLMCanonicalPreSourceDPPurpose  = "formal_glm_registry_stable_dp_projection_v1"
	formalGLMCanonicalPreSourceDPDomain   = "dsVert/formal-glm/canonical-pre-source-dp/v1"
)

type formalGLMPreSourceDPProjectionV1 struct {
	Version                              string                                   `json:"version"`
	Purpose                              string                                   `json:"purpose"`
	Phase15PlanSHA256                    string                                   `json:"phase15_plan_sha256"`
	SnapshotSHA256                       string                                   `json:"snapshot_sha256"`
	PinsetSHA256                         string                                   `json:"pinset_sha256"`
	Family                               string                                   `json:"family"`
	Adjacency                            string                                   `json:"adjacency"`
	SourceRingBits                       int                                      `json:"source_ring_bits"`
	SourceFracBits                       int                                      `json:"source_frac_bits"`
	OutputRingBits                       int                                      `json:"output_ring_bits"`
	OutputLatticeBits                    int                                      `json:"output_lattice_bits"`
	QuantizationShift                    int                                      `json:"quantization_shift"`
	CoordinateCount                      int                                      `json:"coordinate_count"`
	ShiftedUpperBounds                   []string                                 `json:"shifted_upper_bounds"`
	SelectedSensitivitySteps             string                                   `json:"selected_sensitivity_steps"`
	SelectedSensitivityProof             string                                   `json:"selected_sensitivity_proof"`
	SelectedSensitivityCertificate       formalGLMPhase15DPSensitivityCertificate `json:"selected_sensitivity_certificate"`
	SelectedSensitivityCertificateSHA256 string                                   `json:"selected_sensitivity_certificate_sha256"`
	Quantization                         string                                   `json:"quantization"`
	BoundsSHA256                         string                                   `json:"bounds_sha256"`
	QuantizationSHA256                   string                                   `json:"quantization_sha256"`
	CoordinateOrderSHA256                string                                   `json:"coordinate_order_sha256"`
}

// This is the stable registry/key projection. The full projection above is
// retained as byte-equivalent Phase15/16 evidence, but its plan/certificate
// hashes include RunID and must never split a canonical artifact.
type formalGLMCanonicalPreSourceDPV1 struct {
	Version                        string   `json:"version"`
	Purpose                        string   `json:"purpose"`
	CanonicalPlanSHA256            string   `json:"canonical_plan_sha256"`
	SnapshotSHA256                 string   `json:"snapshot_sha256"`
	PinsetSHA256                   string   `json:"pinset_sha256"`
	Family                         string   `json:"family"`
	Adjacency                      string   `json:"adjacency"`
	SourceFractionBits             int      `json:"source_fraction_bits"`
	OutputLatticeBits              int      `json:"output_lattice_bits"`
	QuantizationShift              int      `json:"quantization_shift"`
	CoordinateCount                int      `json:"coordinate_count"`
	ShiftedUpperBounds             []string `json:"shifted_upper_bounds"`
	SelectedSensitivitySteps       string   `json:"selected_sensitivity_steps"`
	SelectedSensitivityProof       string   `json:"selected_sensitivity_proof"`
	Quantization                   string   `json:"quantization"`
	BoundsSHA256                   string   `json:"bounds_sha256"`
	QuantizationSHA256             string   `json:"quantization_sha256"`
	TransportCoordinateOrderSHA256 string   `json:"transport_coordinate_order_sha256"`
}

func formalGLMPhase16BoundsSHA256V1(
	plan formalGLMPhase15Plan,
) (string, error) {
	return formalGLMPhase16DomainDigest(
		"dsVert/formal-glm/phase16/bounds/v1", struct {
			XKind, XLower, XUpper                               []string
			WeightUpper, OutcomeUpper, OffsetLower, OffsetUpper string
			Ridge, CoefficientBox                               []string
			Adjacency, Missingness, PatientCollapse             string
		}{plan.Kernel.XKind, plan.Kernel.XLower, plan.Kernel.XUpper,
			plan.Kernel.WeightUpper, plan.Kernel.OutcomeUpper,
			plan.Kernel.OffsetLower, plan.Kernel.OffsetUpper,
			plan.Kernel.Ridge, plan.Kernel.CoefficientBox,
			plan.Kernel.Adjacency, plan.Kernel.Missingness,
			plan.Kernel.PatientCollapse})
}

func formalGLMPhase16QuantizationSHA256V1(sourceFracBits,
	outputLatticeBits, quantizationShift int, quantization string,
) (string, error) {
	return formalGLMPhase16DomainDigest(
		"dsVert/formal-glm/phase16/quantization/v1", struct {
			SourceFracBits, OutputLatticeBits, QuantizationShift int
			Quantization                                         string
		}{sourceFracBits, outputLatticeBits, quantizationShift, quantization})
}

func buildFormalGLMPreSourceDPProjectionForLatticeV1(
	plan formalGLMPhase15Plan, outputLatticeBits int,
) (formalGLMPreSourceDPProjectionV1, error) {
	var zero formalGLMPreSourceDPProjectionV1
	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil {
		return zero, err
	}
	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		return zero, err
	}
	if outputLatticeBits < 1 || outputLatticeBits > 62 ||
		outputLatticeBits > plan.Kernel.FracBits {
		return zero, fmt.Errorf("formal-glm: invalid DP output lattice")
	}
	quantizationShift := plan.Kernel.FracBits - outputLatticeBits
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(quantizationShift))
	shifted := make([]*big.Int, len(parsed.box))
	shiftedText := make([]string, len(parsed.box))
	maxRing128 := exactGCMaxSigned(128)
	for index, box := range parsed.box {
		quantizedBox := exactGCCeilDiv(box, denominator)
		shifted[index] = new(big.Int).Lsh(
			new(big.Int).Set(quantizedBox), 1)
		if shifted[index].Cmp(maxRing128) > 0 {
			return zero, &formalGLMNumericBackendError{
				Code:         "dp_projection_ring128_unrepresentable",
				RequiredBits: shifted[index].BitLen() + 1,
			}
		}
		shiftedText[index] = shifted[index].String()
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return zero, err
	}
	certificate, err := buildFormalGLMPhase15L2SensitivityCertificate(
		plan, parsed, outputLatticeBits, shifted, planDigest)
	if err != nil {
		return zero, err
	}
	certificateDigest, err := formalGLMPhase15DPSensitivityCertificateDigest(
		certificate)
	if err != nil {
		return zero, err
	}
	boundsSHA256, err := formalGLMPhase16BoundsSHA256V1(plan)
	if err != nil {
		return zero, err
	}
	const quantization = "signed_floor_then_public_box_translation_inside_exact_gc_v1"
	quantizationSHA256, err := formalGLMPhase16QuantizationSHA256V1(
		plan.Kernel.FracBits, outputLatticeBits, quantizationShift,
		quantization)
	if err != nil {
		return zero, err
	}
	return formalGLMPreSourceDPProjectionV1{
		Version:           formalGLMPreSourceDPProjectionVersion,
		Purpose:           formalGLMPreSourceDPProjectionPurpose,
		Phase15PlanSHA256: hex.EncodeToString(planDigest[:]),
		SnapshotSHA256:    plan.Kernel.SnapshotSHA256,
		PinsetSHA256:      plan.Kernel.PinsetSHA256,
		Family:            plan.Kernel.Family, Adjacency: plan.Kernel.Adjacency,
		SourceRingBits: plan.RingBits,
		SourceFracBits: plan.Kernel.FracBits, OutputRingBits: 128,
		OutputLatticeBits:                    outputLatticeBits,
		QuantizationShift:                    quantizationShift,
		CoordinateCount:                      plan.Kernel.CoefficientCount,
		ShiftedUpperBounds:                   shiftedText,
		SelectedSensitivitySteps:             certificate.SelectedBoundSteps,
		SelectedSensitivityProof:             certificate.SelectedProof,
		SelectedSensitivityCertificate:       certificate,
		SelectedSensitivityCertificateSHA256: hex.EncodeToString(certificateDigest[:]),
		Quantization:                         quantization, BoundsSHA256: boundsSHA256,
		QuantizationSHA256: quantizationSHA256,
		CoordinateOrderSHA256: formalGLMPhase16CoefficientOrderSHA256(
			plan.Kernel.CoefficientCount),
	}, nil
}

// The production Phase-1.9 schedule fixes the DP output lattice to the
// cross-approved common fraction bits.  It is not an analyst input.
func buildFormalGLMPreSourceDPProjectionV1(
	plan formalGLMPhase15Plan,
) (formalGLMPreSourceDPProjectionV1, error) {
	return buildFormalGLMPreSourceDPProjectionForLatticeV1(
		plan, plan.Kernel.FracBits)
}

func buildFormalGLMCanonicalPreSourceDPV1(
	plan formalGLMPhase15Plan,
) (formalGLMCanonicalPreSourceDPV1, error) {
	var zero formalGLMCanonicalPreSourceDPV1
	evidence, err := buildFormalGLMPreSourceDPProjectionV1(plan)
	if err != nil {
		return zero, err
	}
	canonicalPlanSHA256, err := formalGLMPhase21CanonicalPlanSHA256(plan)
	if err != nil {
		return zero, err
	}
	result := formalGLMCanonicalPreSourceDPV1{
		Version:             formalGLMCanonicalPreSourceDPVersion,
		Purpose:             formalGLMCanonicalPreSourceDPPurpose,
		CanonicalPlanSHA256: canonicalPlanSHA256,
		SnapshotSHA256:      evidence.SnapshotSHA256,
		PinsetSHA256:        evidence.PinsetSHA256,
		Family:              evidence.Family, Adjacency: evidence.Adjacency,
		SourceFractionBits: evidence.SourceFracBits,
		OutputLatticeBits:  evidence.OutputLatticeBits,
		QuantizationShift:  evidence.QuantizationShift,
		CoordinateCount:    evidence.CoordinateCount,
		ShiftedUpperBounds: append([]string(nil),
			evidence.ShiftedUpperBounds...),
		SelectedSensitivitySteps:       evidence.SelectedSensitivitySteps,
		SelectedSensitivityProof:       evidence.SelectedSensitivityProof,
		Quantization:                   evidence.Quantization,
		BoundsSHA256:                   evidence.BoundsSHA256,
		QuantizationSHA256:             evidence.QuantizationSHA256,
		TransportCoordinateOrderSHA256: evidence.CoordinateOrderSHA256,
	}
	if err := formalGLMValidateCanonicalPreSourceDPV1(result); err != nil {
		return zero, err
	}
	return result, nil
}

func formalGLMValidateCanonicalPreSourceDPV1(
	value formalGLMCanonicalPreSourceDPV1,
) error {
	if value.Version != formalGLMCanonicalPreSourceDPVersion ||
		value.Purpose != formalGLMCanonicalPreSourceDPPurpose ||
		(value.Family != "binomial" && value.Family != "poisson") ||
		(value.Adjacency != "add_remove" && value.Adjacency != "replace_one") ||
		value.SourceFractionBits < 1 || value.SourceFractionBits > 256 ||
		value.OutputLatticeBits < 1 || value.OutputLatticeBits > 62 ||
		value.OutputLatticeBits > value.SourceFractionBits ||
		value.QuantizationShift !=
			value.SourceFractionBits-value.OutputLatticeBits ||
		value.CoordinateCount < 1 || value.CoordinateCount > 4 ||
		len(value.ShiftedUpperBounds) != value.CoordinateCount ||
		(value.SelectedSensitivityProof != formalGLMPhase15DPUniversalProof &&
			value.SelectedSensitivityProof != formalGLMPhase15DPTightProof) ||
		value.Quantization !=
			"signed_floor_then_public_box_translation_inside_exact_gc_v1" {
		return fmt.Errorf("formal-glm: invalid canonical pre-source DP projection")
	}
	for _, digest := range []string{
		value.CanonicalPlanSHA256, value.SnapshotSHA256, value.PinsetSHA256,
		value.BoundsSHA256, value.QuantizationSHA256,
		value.TransportCoordinateOrderSHA256,
	} {
		if !formalGLMIsSHA256(digest) {
			return fmt.Errorf("formal-glm: invalid canonical pre-source DP hash")
		}
	}
	sensitivity, err := jointDPBiomedicalGaussianParseCanonicalInt(
		value.SelectedSensitivitySteps,
		"canonical pre-source DP sensitivity", true)
	if err != nil || sensitivity.Sign() <= 0 ||
		sensitivity.Cmp(exactGCMaxSigned(128)) > 0 {
		return fmt.Errorf("formal-glm: invalid canonical pre-source DP sensitivity")
	}
	for _, encoded := range value.ShiftedUpperBounds {
		upper, err := jointDPBiomedicalGaussianParseCanonicalInt(
			encoded, "canonical pre-source shifted upper bound", true)
		if err != nil || upper.Sign() <= 0 || upper.Bit(0) != 0 ||
			upper.Cmp(exactGCMaxSigned(128)) > 0 {
			return fmt.Errorf("formal-glm: invalid canonical pre-source DP bounds")
		}
	}
	return nil
}

func formalGLMCanonicalPreSourceDPSHA256V1(
	value formalGLMCanonicalPreSourceDPV1,
) (string, error) {
	if err := formalGLMValidateCanonicalPreSourceDPV1(value); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMCanonicalPreSourceDPDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPreSourceDPProjectionFromPhase16V1(
	bridge formalGLMPhase15DPBridgePlan,
	binding formalGLMPhase16ReleaseBinding,
) formalGLMPreSourceDPProjectionV1 {
	return formalGLMPreSourceDPProjectionV1{
		Version:           formalGLMPreSourceDPProjectionVersion,
		Purpose:           formalGLMPreSourceDPProjectionPurpose,
		Phase15PlanSHA256: bridge.Phase15PlanSHA256,
		SnapshotSHA256:    bridge.SnapshotSHA256,
		PinsetSHA256:      bridge.PinsetSHA256,
		Family:            binding.Family, Adjacency: bridge.Adjacency,
		SourceRingBits:    bridge.SourceRingBits,
		SourceFracBits:    bridge.SourceFracBits,
		OutputRingBits:    bridge.OutputRingBits,
		OutputLatticeBits: bridge.OutputLatticeBits,
		QuantizationShift: bridge.QuantizationShift,
		CoordinateCount:   bridge.CoordinateCount,
		ShiftedUpperBounds: append([]string(nil),
			bridge.ShiftedUpperBounds...),
		SelectedSensitivitySteps:             bridge.SelectedSensitivitySteps,
		SelectedSensitivityProof:             bridge.SelectedSensitivityProof,
		SelectedSensitivityCertificate:       bridge.SelectedSensitivityCertificate,
		SelectedSensitivityCertificateSHA256: bridge.SelectedSensitivityCertificateSHA256,
		Quantization:                         bridge.Quantization,
		BoundsSHA256:                         binding.BoundsSHA256,
		QuantizationSHA256:                   binding.QuantizationSHA256,
		CoordinateOrderSHA256:                binding.CoordinateOrderSHA256,
	}
}
