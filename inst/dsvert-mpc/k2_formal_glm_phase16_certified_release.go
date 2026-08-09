package main

// Public, self-describing formal-GLM result.  It binds the final DP vector to
// the K-signed automatic backend decision, so a caller always sees the reason
// for fallback and its exact utility cost together with the numeric/no-wrap
// certificate.  The nested release retains the designated-peer signatures.

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
)

const formalGLMPhase16CertifiedReleaseVersion = "dsvert-formal-glm-phase16-certified-common-dp-release-v1"

var formalGLMPhase16CertifiedReleaseBlockers = []string{
	"r_dsi_verified_formal_glm_projection_not_wired_v1",
	"mixed_arithmetic_boolean_scalability_backend_not_benchmarked_v1",
	"physical_wall_clock_and_retransmission_cadence_dp_not_certified_v1",
	"semi_honest_two_compute_peer_protocol_only_v1",
	"unlimited_distinct_release_composition_has_no_finite_global_dp_bound_v1",
}

type formalGLMPhase16CertifiedRelease struct {
	Version                      string                                         `json:"version"`
	BackendSelectionSHA256       string                                         `json:"backend_selection_sha256"`
	BackendSelection             formalGLMPhase16BackendSelectionAttestation    `json:"backend_selection"`
	SourceReleaseInstanceID      string                                         `json:"source_release_instance_id"`
	DPReleaseInstanceID          string                                         `json:"dp_release_instance_id"`
	ReleaseContractSHA256        string                                         `json:"release_contract_sha256"`
	ReleaseBindingSHA256         string                                         `json:"release_binding_sha256"`
	Family                       string                                         `json:"family"`
	SelectedBackend              string                                         `json:"selected_backend"`
	SelectionReason              string                                         `json:"selection_reason"`
	NominalVarianceMultiplier    int                                            `json:"nominal_variance_multiplier"`
	NominalStandardDeviation     string                                         `json:"nominal_standard_deviation_factor"`
	Simultaneous95AbsSteps       string                                         `json:"simultaneous_95_abs_steps"`
	Epsilon                      string                                         `json:"epsilon"`
	Delta                        string                                         `json:"delta"`
	L2SensitivitySteps           string                                         `json:"l2_sensitivity_steps"`
	SensitivityCertificateSHA256 string                                         `json:"sensitivity_certificate_sha256"`
	SourceRingBits               int                                            `json:"source_ring_bits"`
	DPCommonRingBits             int                                            `json:"dp_common_ring_bits"`
	OutputLatticeBits            int                                            `json:"output_lattice_bits"`
	NoWrapCertificate            string                                         `json:"no_wrap_certificate"`
	ThreatModel                  string                                         `json:"threat_model"`
	UtilityCertificate           string                                         `json:"utility_certificate"`
	ObservableWorkerShape        string                                         `json:"observable_worker_shape"`
	HostConstantTimeClaim        bool                                           `json:"host_constant_time_claim"`
	TranscriptDPClaim            bool                                           `json:"transcript_dp_claim"`
	LogicalTranscriptFixedShape  bool                                           `json:"logical_transcript_fixed_shape"`
	PhysicalTimingDPClaim        bool                                           `json:"physical_timing_dp_claim"`
	VectorSHA256                 string                                         `json:"vector_sha256"`
	ClampedScaledValues          []string                                       `json:"clamped_scaled_values"`
	SingleCommonDPVector         bool                                           `json:"single_common_dp_vector"`
	ExactlyOnceRelease           bool                                           `json:"exactly_once_release"`
	UnlimitedDeterministicReplay bool                                           `json:"unlimited_deterministic_replay"`
	UnlimitedPostprocessing      bool                                           `json:"unlimited_postprocessing"`
	HistoryCanDenyOperation      bool                                           `json:"history_can_deny_operation"`
	OperationLimit               bool                                           `json:"operation_limit"`
	RequestLimit                 bool                                           `json:"request_limit"`
	OpeningsPerformed            int                                            `json:"openings_performed"`
	ProductionReady              bool                                           `json:"production_ready"`
	Blockers                     []string                                       `json:"blockers"`
	OneDraw                      *jointDPBiomedicalGaussianOneDrawCommonRelease `json:"one_draw_release,omitempty"`
	IndependentFull              *jointDPBiomedicalGaussianFullCommonRelease    `json:"independent_full_release,omitempty"`
}

func formalGLMPhase16CertifiedReleaseBase(
	selection formalGLMPhase16BackendSelectionAttestation,
	binding formalGLMPhase16ReleaseBinding,
) (formalGLMPhase16CertifiedRelease, error) {
	selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(selection)
	if err != nil {
		return formalGLMPhase16CertifiedRelease{}, err
	}
	contract := selection.Contract
	return formalGLMPhase16CertifiedRelease{
		Version:                   formalGLMPhase16CertifiedReleaseVersion,
		BackendSelectionSHA256:    selectionSHA256,
		BackendSelection:          selection,
		SourceReleaseInstanceID:   binding.ReleaseInstanceID,
		ReleaseBindingSHA256:      binding.BindingSHA256,
		Family:                    binding.Family,
		SelectedBackend:           contract.SelectedBackend,
		SelectionReason:           contract.SelectionReason,
		NominalVarianceMultiplier: contract.SelectedVarianceMultiplier,
		NominalStandardDeviation:  contract.SelectedStandardDeviation,
		Simultaneous95AbsSteps:    contract.SelectedSimultaneous95Abs,
		Epsilon:                   binding.Epsilon, Delta: binding.AllocatedDelta,
		L2SensitivitySteps:           binding.SensitivitySteps,
		SensitivityCertificateSHA256: binding.SensitivityCertificateSHA256,
		SourceRingBits:               binding.SourceRingBits,
		DPCommonRingBits:             binding.CommonRingBits,
		OutputLatticeBits:            binding.OutputLatticeBits,
		NoWrapCertificate:            binding.NoWrapCertificate,
		ThreatModel:                  contract.SelectedThreatModel,
		UtilityCertificate:           contract.SelectedUtilityCertificate,
		ObservableWorkerShape:        contract.SelectedObservableWorkerShape,
		HostConstantTimeClaim:        contract.SelectedHostConstantTimeClaim,
		TranscriptDPClaim:            contract.SelectedTranscriptDPClaim,
		LogicalTranscriptFixedShape:  contract.SelectedLogicalTranscriptFixed,
		PhysicalTimingDPClaim:        contract.SelectedPhysicalTimingDPClaim,
		SingleCommonDPVector:         true, ExactlyOnceRelease: true,
		UnlimitedDeterministicReplay: true,
		UnlimitedPostprocessing:      true,
		HistoryCanDenyOperation:      false,
		OperationLimit:               false, RequestLimit: false,
		OpeningsPerformed: 1, ProductionReady: false,
		Blockers: append([]string(nil),
			formalGLMPhase16CertifiedReleaseBlockers...),
	}, nil
}

func formalGLMPhase16CertifyOneDrawRelease(
	admission formalGLMPhase16ProductiveAdmission,
	release jointDPBiomedicalGaussianOneDrawCommonRelease,
) (formalGLMPhase16CertifiedRelease, error) {
	var zero formalGLMPhase16CertifiedRelease
	pins, _, err := jointDPBiomedicalGaussianTrustPins(admission.Trust)
	if err != nil {
		return zero, err
	}
	if _, err := formalGLMPhase16ValidateBackendSelection(
		admission.BackendSelection, admission.Compiled.Binding,
		admission.Token, pins); err != nil {
		return zero, err
	}
	if admission.BackendSelection.Contract.SelectedBackend !=
		formalGLMPhase16BackendOneDraw {
		return zero, fmt.Errorf("formal-glm: one-draw result disagrees with backend selection")
	}
	if err := jointDPBiomedicalGaussianValidateOneDrawCommonRelease(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{admission.Envelope},
		admission.Trust, release); err != nil {
		return zero, err
	}
	result, err := formalGLMPhase16CertifiedReleaseBase(
		admission.BackendSelection, admission.Compiled.Binding)
	if err != nil {
		return zero, err
	}
	result.DPReleaseInstanceID = release.ReleaseInstanceID
	result.ReleaseContractSHA256 = release.ReleaseContractSHA256
	result.VectorSHA256 = release.VectorSHA256
	result.ClampedScaledValues = append([]string(nil),
		release.ClampedScaledValues...)
	copyRelease := release
	result.OneDraw = &copyRelease
	return result, nil
}

func formalGLMPhase16CertifyFullRelease(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	release jointDPBiomedicalGaussianFullCommonRelease,
) (formalGLMPhase16CertifiedRelease, error) {
	var zero formalGLMPhase16CertifiedRelease
	if admission.formalSelection == nil || admission.formalBinding == nil ||
		admission.formalToken == nil {
		return zero, fmt.Errorf("formal-glm: missing formal fallback authority")
	}
	if _, err := formalGLMPhase16ValidateBackendSelection(
		*admission.formalSelection, *admission.formalBinding,
		*admission.formalToken, pins); err != nil {
		return zero, err
	}
	if admission.formalSelection.Contract.SelectedBackend !=
		formalGLMPhase16BackendFull {
		return zero, fmt.Errorf("formal-glm: full result disagrees with backend selection")
	}
	if err := jointDPBiomedicalGaussianValidateFullCommonRelease(
		admission, pins, release); err != nil {
		return zero, err
	}
	result, err := formalGLMPhase16CertifiedReleaseBase(
		*admission.formalSelection, *admission.formalBinding)
	if err != nil {
		return zero, err
	}
	result.DPReleaseInstanceID = release.ReleaseInstanceID
	result.ReleaseContractSHA256 = release.ReleaseContractSHA256
	result.VectorSHA256 = release.VectorSHA256
	result.ClampedScaledValues = append([]string(nil),
		release.ClampedScaledValues...)
	copyRelease := release
	result.IndependentFull = &copyRelease
	return result, nil
}

func formalGLMPhase16ValidateCertifiedRelease(
	result formalGLMPhase16CertifiedRelease,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	pins map[string]ed25519.PublicKey,
) error {
	if _, err := formalGLMPhase16ValidateBackendSelection(
		result.BackendSelection, binding, token, pins); err != nil {
		return err
	}
	expected, err := formalGLMPhase16CertifiedReleaseBase(
		result.BackendSelection, binding)
	if err != nil {
		return err
	}
	probe := result
	probe.DPReleaseInstanceID = ""
	probe.ReleaseContractSHA256 = ""
	probe.VectorSHA256 = ""
	probe.ClampedScaledValues = nil
	probe.OneDraw = nil
	probe.IndependentFull = nil
	if !reflect.DeepEqual(probe, expected) ||
		!formalGLMIsSHA256(result.DPReleaseInstanceID) ||
		!formalGLMIsSHA256(result.ReleaseContractSHA256) ||
		!formalGLMIsSHA256(result.VectorSHA256) ||
		len(result.ClampedScaledValues) != binding.CoordinateCount ||
		(result.OneDraw == nil) == (result.IndependentFull == nil) {
		return fmt.Errorf("formal-glm: modified certified common release")
	}
	var message []byte
	var signatures []jointDPBiomedicalGaussianSignature
	var releaseInstance, releaseContract, vectorSHA256, epsilon, delta string
	var values []string
	if result.OneDraw != nil {
		if result.SelectedBackend != formalGLMPhase16BackendOneDraw {
			return fmt.Errorf("formal-glm: selected backend/result kind mismatch")
		}
		message, err = jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(
			*result.OneDraw)
		signatures = result.OneDraw.Signatures
		releaseInstance = result.OneDraw.ReleaseInstanceID
		releaseContract = result.OneDraw.ReleaseContractSHA256
		vectorSHA256 = result.OneDraw.VectorSHA256
		epsilon, delta = result.OneDraw.Epsilon, result.OneDraw.Delta
		values = result.OneDraw.ClampedScaledValues
	} else {
		if result.SelectedBackend != formalGLMPhase16BackendFull {
			return fmt.Errorf("formal-glm: selected backend/result kind mismatch")
		}
		message, err = jointDPBiomedicalGaussianFullCommonReleaseMessage(
			*result.IndependentFull)
		signatures = result.IndependentFull.Signatures
		releaseInstance = result.IndependentFull.ReleaseInstanceID
		releaseContract = result.IndependentFull.ReleaseContractSHA256
		vectorSHA256 = result.IndependentFull.VectorSHA256
		epsilon, delta = result.IndependentFull.Epsilon,
			result.IndependentFull.Delta
		values = result.IndependentFull.ClampedScaledValues
	}
	if err != nil || releaseInstance != result.DPReleaseInstanceID ||
		releaseContract != result.ReleaseContractSHA256 ||
		vectorSHA256 != result.VectorSHA256 ||
		epsilon != binding.Epsilon || delta != binding.AllocatedDelta ||
		!reflect.DeepEqual(values, result.ClampedScaledValues) {
		return fmt.Errorf("formal-glm: nested common release does not match its certificate")
	}
	computePins := make(map[string]ed25519.PublicKey, 2)
	for _, peer := range result.BackendSelection.Contract.DesignatedComputePeers {
		computePins[peer] = pins[peer]
	}
	if err := jointDPBiomedicalGaussianVerifySignatures(
		message, signatures, result.BackendSelection.Contract.DesignatedComputePeers,
		computePins, "formal GLM common DP release"); err != nil {
		return err
	}
	for index, text := range values {
		value, valueErr := jointDPBiomedicalGaussianParseCanonicalInt(
			text, "formal GLM released coordinate", false)
		upper, upperErr := jointDPBiomedicalGaussianParseCanonicalInt(
			binding.ShiftedUpperBounds[index],
			"formal GLM released coordinate upper bound", false)
		if valueErr != nil || upperErr != nil || value.Cmp(upper) > 0 {
			return fmt.Errorf("formal-glm: certified release exceeds its signed range")
		}
	}
	return nil
}
