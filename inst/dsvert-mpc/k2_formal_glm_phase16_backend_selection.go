package main

// Deterministic, K-signed backend selection for the formal GLM DP release.
//
// The selector is intentionally data-free.  It compares the two reviewed
// implementations using only the signed release bounds, sensitivity and
// privacy parameters.  A relay can neither force the cheaper backend nor hide
// the variance/accuracy cost of the scalable backend: every custodian signs
// the exact decision and both complete public plans before a protected source
// share is accepted by either worker.

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"reflect"
	"sort"
)

const (
	formalGLMPhase16BackendSelectionVersion = "dsvert-formal-glm-phase16-dp-backend-selection-v1"
	formalGLMPhase16BackendSelectionDomain  = "dsVert/formal-glm/phase16/dp-backend-selection/v1"
	formalGLMPhase16BackendSelectionPolicy  = "prefer_exact_gc_one_draw_if_resource_and_no_wrap_certified_else_two_independent_full_draws_v1"

	formalGLMPhase16BackendOneDraw = "exact_gc_joint_discrete_gaussian_one_global_draw_v1"
	formalGLMPhase16BackendFull    = "two_independent_complete_discrete_gaussian_draws_v1"
)

type formalGLMPhase16BackendSelectionContract struct {
	Version                   string   `json:"version"`
	Policy                    string   `json:"policy"`
	ReleaseBindingSHA256      string   `json:"release_binding_sha256"`
	ReleaseInstanceID         string   `json:"release_instance_id"`
	ReleaseContractSHA256     string   `json:"release_contract_sha256"`
	Phase19PostTokenSHA256    string   `json:"phase19_post_token_sha256"`
	PostExecutionRootSHA256   string   `json:"post_execution_root_sha256"`
	MaterializationRootSHA256 string   `json:"materialization_root_sha256"`
	PinsetSHA256              string   `json:"pinset_sha256"`
	CustodianPeers            []string `json:"custodian_peers"`
	CustodianCount            int      `json:"custodian_count"`
	DesignatedComputePeers    []string `json:"designated_compute_peers"`

	Family                       string `json:"family"`
	Epsilon                      string `json:"epsilon"`
	Delta                        string `json:"delta"`
	L2SensitivitySteps           string `json:"l2_sensitivity_steps"`
	SensitivityCertificateKind   string `json:"sensitivity_certificate_kind"`
	SensitivityCertificateSHA256 string `json:"sensitivity_certificate_sha256"`
	CoordinateCount              int    `json:"coordinate_count"`
	ShiftedUpperBoundsSHA256     string `json:"shifted_upper_bounds_sha256"`

	OneDrawPlanSHA256          string `json:"one_draw_plan_sha256"`
	OneDrawCapabilityAvailable bool   `json:"one_draw_capability_available"`
	OneDrawUnavailableReason   string `json:"one_draw_unavailable_reason"`
	OneDrawMaximumChunk        int    `json:"one_draw_maximum_chunk_coordinates"`
	OneDrawVarianceMultiplier  int    `json:"one_draw_nominal_variance_multiplier"`
	OneDrawStandardDeviation   string `json:"one_draw_nominal_standard_deviation_factor"`
	OneDrawSimultaneous95Abs   string `json:"one_draw_simultaneous_95_abs"`
	OneDrawNoWrapCertified     bool   `json:"one_draw_no_wrap_certified"`

	FullPlanSHA256          string `json:"independent_full_plan_sha256"`
	FullCapabilityAvailable bool   `json:"independent_full_capability_available"`
	FullUnavailableReason   string `json:"independent_full_unavailable_reason"`
	FullMaximumChunk        int    `json:"independent_full_maximum_chunk_coordinates"`
	FullVarianceMultiplier  int    `json:"independent_full_nominal_variance_multiplier"`
	FullStandardDeviation   string `json:"independent_full_nominal_standard_deviation_factor"`
	FullSimultaneous95Abs   string `json:"independent_full_simultaneous_95_abs"`
	FullNoWrapCertified     bool   `json:"independent_full_no_wrap_certified"`

	SelectedBackend                  string `json:"selected_backend"`
	SelectionReason                  string `json:"selection_reason"`
	SelectionAutomatic               bool   `json:"selection_automatic"`
	SelectionExplicitAndCrossSigned  bool   `json:"selection_explicit_and_cross_signed"`
	SelectedVarianceMultiplier       int    `json:"selected_nominal_variance_multiplier"`
	SelectedStandardDeviation        string `json:"selected_nominal_standard_deviation_factor"`
	SelectedSimultaneous95Abs        string `json:"selected_simultaneous_95_abs"`
	SelectedMechanism                string `json:"selected_mechanism"`
	SelectedPrivacyTheorem           string `json:"selected_privacy_theorem"`
	SelectedUtilityCertificate       string `json:"selected_utility_certificate"`
	SelectedThreatModel              string `json:"selected_threat_model"`
	SelectedObservableWorkerShape    string `json:"selected_observable_worker_shape"`
	SelectedHostConstantTimeClaim    bool   `json:"selected_host_constant_time_claim"`
	SelectedTranscriptDPClaim        bool   `json:"selected_transcript_dp_claim"`
	SelectedLogicalTranscriptFixed   bool   `json:"selected_logical_transcript_fixed_shape"`
	SelectedPhysicalTimingDPClaim    bool   `json:"selected_physical_timing_dp_claim"`
	AtLeastOneHonestNoisePeer        bool   `json:"at_least_one_honest_noise_peer"`
	MaximumColludingNoisePeers       int    `json:"maximum_colluding_noise_peers"`
	BothNoisePeersCollusionProtected bool   `json:"both_noise_peers_collusion_protected"`
	RelayTamperDetected              bool   `json:"relay_tamper_detected"`
	RelayAvailabilityGuaranteed      bool   `json:"relay_availability_guaranteed"`
	MaliciousSecurityClaim           bool   `json:"malicious_security_claim"`
	NoWrapCertified                  bool   `json:"no_wrap_certified"`
	OperationLimit                   bool   `json:"operation_limit"`
	RequestLimit                     bool   `json:"request_limit"`
	HistoryCanDenyOperation          bool   `json:"history_can_deny_operation"`
}

type formalGLMPhase16BackendSelectionAttestation struct {
	Contract   formalGLMPhase16BackendSelectionContract `json:"contract"`
	Signatures []jointDPBiomedicalGaussianSignature     `json:"signatures"`
}

type formalGLMPhase16BackendPlans struct {
	OneDraw jointDPGaussianOneDrawPlanOutput
	Full    jointDPGaussianPlanOutput
}

func formalGLMPhase16FullPlanForBinding(
	binding formalGLMPhase16ReleaseBinding,
) (jointDPGaussianPlanOutput, bool, string) {
	plan, err := jointDPPlanVectorGaussian(jointDPGaussianPlanInput{
		Epsilon: binding.Epsilon, Delta: binding.AllocatedDelta,
		L2SensitivitySteps:   binding.SensitivitySteps,
		TotalCoordinateCount: binding.CoordinateCount,
	})
	if err != nil {
		return jointDPGaussianPlanOutput{}, false,
			"independent_full_planner_unavailable"
	}
	if !plan.CapabilityAvailable || plan.IndependentNoisePeerCount != 2 ||
		!plan.CompleteEpsilonPerPeer || plan.EpsilonDividedByPeerCount ||
		plan.NominalVarianceMultiplier != 2 {
		reason := plan.UnavailableReason
		if reason == "" {
			reason = "independent_full_capability_contract_unavailable"
		}
		return plan, false, reason
	}
	maximumNoise, ok := new(big.Int).SetString(
		plan.MaximumNoiseMagnitudeTwoPeers, 10)
	if !ok || maximumNoise.Sign() < 0 {
		return plan, false, "independent_full_invalid_noise_headroom_certificate"
	}
	maximumSigned := exactGCMaxSigned(128)
	for _, text := range binding.ShiftedUpperBounds {
		upper, ok := new(big.Int).SetString(text, 10)
		if !ok || upper.Sign() < 0 ||
			new(big.Int).Add(upper, maximumNoise).Cmp(maximumSigned) > 0 {
			return plan, false, "independent_full_ring128_no_wrap_headroom_unavailable"
		}
	}
	return plan, true, ""
}

func formalGLMPhase16BuildBackendSelection(
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase16BackendSelectionContract,
	formalGLMPhase16BackendPlans, error) {
	var zero formalGLMPhase16BackendSelectionContract
	var plans formalGLMPhase16BackendPlans
	if digest, err := formalGLMPhase16ReleaseBindingDigest(binding); err != nil ||
		digest != binding.BindingSHA256 ||
		!token.verified || !formalGLMIsSHA256(token.TokenSHA256) ||
		token.CapsuleSHA256 != binding.CapsuleID ||
		token.PinsetSHA256 != binding.PinsetSHA256 ||
		token.GlobalMaterializationRoot == "" ||
		token.CustodianCount != binding.CustodianCount ||
		!token.ExecutionValidSealed || token.ExecutionValidityOpened ||
		token.OpeningsPerformed != 0 {
		return zero, plans,
			fmt.Errorf("formal-glm: backend selection lacks sealed Phase-1.9 authority")
	}
	roles, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || roles != binding.PinsetSHA256 || len(pins) != binding.CustodianCount {
		return zero, plans, fmt.Errorf("formal-glm: backend selection pinset mismatch")
	}
	custodians := make([]string, 0, len(pins))
	for name := range pins {
		custodians = append(custodians, name)
	}
	sort.Strings(custodians)
	compute := []string{binding.GarblerPeerName, binding.EvaluatorPeerName}
	if !reflect.DeepEqual(token.ComputePeers, compute) &&
		!reflect.DeepEqual(token.ComputePeers,
			[]string{binding.EvaluatorPeerName, binding.GarblerPeerName}) {
		return zero, plans, fmt.Errorf("formal-glm: backend selection compute-peer mismatch")
	}
	// The formal binding fixes cryptographic roles by peer ID.  Canonicalize
	// the public compute-peer list to that same order for every signer.
	if !reflect.DeepEqual(token.ComputePeers, compute) {
		compute[0], compute[1] = compute[1], compute[0]
	}
	oneDraw, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: binding.Epsilon, Delta: binding.AllocatedDelta,
		L2SensitivitySteps:   binding.SensitivitySteps,
		TotalCoordinateCount: binding.CoordinateCount,
	})
	if err != nil {
		return zero, plans, err
	}
	full, fullAvailable, fullReason := formalGLMPhase16FullPlanForBinding(binding)
	plans = formalGLMPhase16BackendPlans{OneDraw: oneDraw, Full: full}
	oneHash, err := jointDPBiomedicalGaussianHash(oneDraw)
	if err != nil {
		return zero, plans, err
	}
	fullHash := ""
	if full.Version != "" {
		fullHash, err = jointDPBiomedicalGaussianHash(full)
		if err != nil {
			return zero, plans, err
		}
	} else {
		// Keep a canonical digest even when planning itself is unavailable.
		fullHash, err = jointDPBiomedicalGaussianHash(struct {
			Version string `json:"version"`
			Reason  string `json:"reason"`
		}{"dsvert-formal-glm-independent-full-unavailable-v1", fullReason})
		if err != nil {
			return zero, plans, err
		}
	}
	boundsDigest, err := formalGLMPhase16DomainDigest(
		formalGLMPhase16BackendSelectionDomain+"/shifted-upper-bounds",
		binding.ShiftedUpperBounds)
	if err != nil {
		return zero, plans, err
	}
	selected := ""
	reason := ""
	variance := 0
	sd, accuracy, theorem, utility, observable := "", "", "", "", ""
	hostConstantTime, transcriptDP := false, false
	logicalTranscriptFixed, physicalTimingDP := false, false
	if oneDraw.CapabilityAvailable && oneDraw.NoWrapCertified {
		selected = formalGLMPhase16BackendOneDraw
		reason = "exact_gc_one_draw_fits_public_cdf_gate_memory_input_and_no_wrap_envelopes_v1"
		variance, sd, accuracy = 1, "1_relative_to_one_full_draw", oneDraw.Simultaneous95Abs
		theorem = oneDraw.PrivacyTheorem
		utility = "one_complete_joint_draw_preserves_target_variance_and_reported_simultaneous_95_radius_v1"
		observable = "fixed_public_exact_gc_circuit_and_message_shape_wall_clock_not_certified_v1"
		logicalTranscriptFixed, transcriptDP = true, true
	} else if fullAvailable {
		selected = formalGLMPhase16BackendFull
		reason = "one_draw_unavailable_under_signed_resource_envelope_selected_scalable_independent_full_backend_v1"
		variance, sd, accuracy = 2,
			"sqrt(2)_relative_to_one_full_draw", full.Simultaneous95Abs
		theorem = full.PrivacyTheorem
		utility = "two_independent_complete_discrete_gaussian_draws_variances_add_exactly_nominal_variance_x2_sd_x_sqrt2_v1"
		observable = full.ObservableWorkerShape
		hostConstantTime = full.HostConstantTimeClaim
		transcriptDP = full.TranscriptDPClaim
		logicalTranscriptFixed = full.LogicalTranscriptFixedShape
		physicalTimingDP = full.PhysicalTimingDPClaim
	} else {
		return zero, plans, exactGCFailure(
			exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("formal-glm: neither signed Gaussian backend fits: one_draw=%s independent_full=%s",
				oneDraw.UnavailableReason, fullReason))
	}
	contract := formalGLMPhase16BackendSelectionContract{
		Version:                   formalGLMPhase16BackendSelectionVersion,
		Policy:                    formalGLMPhase16BackendSelectionPolicy,
		ReleaseBindingSHA256:      binding.BindingSHA256,
		ReleaseInstanceID:         binding.ReleaseInstanceID,
		ReleaseContractSHA256:     binding.ReleaseContractSHA256,
		Phase19PostTokenSHA256:    token.TokenSHA256,
		PostExecutionRootSHA256:   token.PostExecutionRootSHA256,
		MaterializationRootSHA256: token.GlobalMaterializationRoot,
		PinsetSHA256:              binding.PinsetSHA256,
		CustodianPeers:            custodians, CustodianCount: len(custodians),
		DesignatedComputePeers: compute,
		Family:                 binding.Family, Epsilon: binding.Epsilon,
		Delta:                        binding.AllocatedDelta,
		L2SensitivitySteps:           binding.SensitivitySteps,
		SensitivityCertificateKind:   binding.SensitivityCertificateKind,
		SensitivityCertificateSHA256: binding.SensitivityCertificateSHA256,
		CoordinateCount:              binding.CoordinateCount,
		ShiftedUpperBoundsSHA256:     boundsDigest,
		OneDrawPlanSHA256:            oneHash,
		OneDrawCapabilityAvailable:   oneDraw.CapabilityAvailable,
		OneDrawUnavailableReason:     oneDraw.UnavailableReason,
		OneDrawMaximumChunk:          oneDraw.MaximumChunkCoordinates,
		OneDrawVarianceMultiplier:    1,
		OneDrawStandardDeviation:     "1_relative_to_one_full_draw",
		OneDrawSimultaneous95Abs:     oneDraw.Simultaneous95Abs,
		OneDrawNoWrapCertified:       oneDraw.NoWrapCertified,
		FullPlanSHA256:               fullHash,
		FullCapabilityAvailable:      fullAvailable,
		FullUnavailableReason:        fullReason,
		FullMaximumChunk:             full.MaximumChunkCoordinates,
		FullVarianceMultiplier:       2,
		FullStandardDeviation:        "sqrt(2)_relative_to_one_full_draw",
		FullSimultaneous95Abs:        full.Simultaneous95Abs,
		FullNoWrapCertified:          fullAvailable,
		SelectedBackend:              selected, SelectionReason: reason,
		SelectionAutomatic: true, SelectionExplicitAndCrossSigned: true,
		SelectedVarianceMultiplier:       variance,
		SelectedStandardDeviation:        sd,
		SelectedSimultaneous95Abs:        accuracy,
		SelectedMechanism:                jointDPGaussianMechanism,
		SelectedPrivacyTheorem:           theorem,
		SelectedUtilityCertificate:       utility,
		SelectedThreatModel:              "authenticated_pinned_semi_honest_two_compute_peers_with_at_least_one_honest_noncolluding_noise_peer_v1",
		SelectedObservableWorkerShape:    observable,
		SelectedHostConstantTimeClaim:    hostConstantTime,
		SelectedTranscriptDPClaim:        transcriptDP,
		SelectedLogicalTranscriptFixed:   logicalTranscriptFixed,
		SelectedPhysicalTimingDPClaim:    physicalTimingDP,
		AtLeastOneHonestNoisePeer:        true,
		MaximumColludingNoisePeers:       1,
		BothNoisePeersCollusionProtected: false,
		RelayTamperDetected:              true,
		RelayAvailabilityGuaranteed:      false,
		MaliciousSecurityClaim:           false,
		NoWrapCertified:                  true,
		OperationLimit:                   false, RequestLimit: false,
		HistoryCanDenyOperation: false,
	}
	return contract, plans, nil
}

func formalGLMPhase16SignBackendSelection(
	contract formalGLMPhase16BackendSelectionContract,
	signer string, privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianSignature, error) {
	return jointDPBiomedicalGaussianSign(
		formalGLMPhase16BackendSelectionDomain, contract, signer, privateKey)
}

func formalGLMPhase16ValidateBackendSelection(
	attestation formalGLMPhase16BackendSelectionAttestation,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase16BackendPlans, error) {
	expected, plans, err := formalGLMPhase16BuildBackendSelection(
		binding, token, pins)
	if err != nil {
		return plans, err
	}
	if !reflect.DeepEqual(attestation.Contract, expected) {
		return plans, fmt.Errorf("formal-glm: modified DP backend selection")
	}
	message, err := jointDPBiomedicalGaussianDomainMessage(
		formalGLMPhase16BackendSelectionDomain, expected)
	if err != nil {
		return plans, err
	}
	if err := jointDPBiomedicalGaussianVerifySignatures(
		message, attestation.Signatures, expected.CustodianPeers, pins,
		"formal GLM DP backend selection"); err != nil {
		return plans, err
	}
	return plans, nil
}

func formalGLMPhase16BackendSelectionSHA256(
	attestation formalGLMPhase16BackendSelectionAttestation,
) (string, error) {
	return formalGLMPhase16DomainDigest(
		formalGLMPhase16BackendSelectionDomain+"/attestation", attestation)
}
