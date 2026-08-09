package main

// Internal purpose-bound bridge from the sealed Cox kernel to the common
// one-draw Gaussian sampler and release authority.  It deliberately exposes no
// command/capability.  The relay-visible envelope contains only opaque handles
// and K signatures; the Cox policy, release binding and seed material remain
// local worker state.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
)

const formalCoxRuntimeAdmissionVersion = "dsvert-formal-cox-runtime-admission-v1"

var formalCoxRuntimeAdmissionBlockers = []string{
	"r_dsi_recipient_encrypted_typed_source_bridge_not_executed_v1",
	"end_to_end_nonlinear_numeric_error_certificate_incomplete_v1",
	"dp_safe_identification_certificate_unavailable_v1",
	"r_dsi_server_to_peer_end_to_end_not_executed_v1",
}

// All fields are server-authoritative commitments.  They must be durable and
// release-stable, and must not be unkeyed hashes of protected row membership.
type formalCoxRuntimeAuthority struct {
	ManifestSHA256              string `json:"manifest_sha256"`
	SchemaManifestSHA256        string `json:"schema_manifest_sha256"`
	WorkloadSHA256              string `json:"workload_sha256"`
	SourceFanInTranscriptSHA256 string `json:"source_fan_in_transcript_sha256"`
	ReleaseInstanceID           string `json:"release_instance_id"`
	ReleaseContractSHA256       string `json:"release_contract_sha256"`
}

type formalCoxRuntimeAdmissionRequest struct {
	Authority                   formalCoxRuntimeAuthority
	LogicalSnapshotHandleSHA256 string
	PrivacyEpochSHA256          string
	MaterializationRootSHA256   string
	SourceContractHandleSHA256  string
	RunNonceSHA256              string
	WorkerImplementationSHA256  string
	NoiseSeedCommitmentsByPeer  map[string]string
	LedgerOpeningTokens         []formalCoxRuntimeLedgerOpeningToken
	ReceiptReferences           []jointDPBiomedicalGaussianReceiptReference
}

type formalCoxRuntimeRoles struct {
	PinsetSHA256      string `json:"pinset_sha256"`
	GarblerPeerName   string `json:"garbler_peer_name"`
	GarblerPeerID     string `json:"garbler_peer_id"`
	EvaluatorPeerName string `json:"evaluator_peer_name"`
	EvaluatorPeerID   string `json:"evaluator_peer_id"`
}

type formalCoxRuntimeAdmission struct {
	Version                  string                                          `json:"version"`
	Policy                   formalCoxPhase1Policy                           `json:"-"`
	Phase1Plan               formalCoxPhase1Plan                             `json:"phase1_plan"`
	DPPlan                   formalCoxDPPlan                                 `json:"dp_plan"`
	NumericCertificate       formalCoxRuntimeNumericCertificate              `json:"numeric_certificate"`
	NumericCertificateSHA256 string                                          `json:"numeric_certificate_sha256"`
	Roles                    formalCoxRuntimeRoles                           `json:"roles"`
	Binding                  formalCoxRuntimeReleaseBinding                  `json:"-"`
	BindingCanonicalJSON     string                                          `json:"-"`
	Workers                  []jointDPGaussianOneDrawWorkerContractOutput    `json:"-"`
	Envelopes                []jointDPBiomedicalGaussianSignedWorkerEnvelope `json:"envelopes"`
	Trust                    jointDPBiomedicalGaussianWorkerTrustRoot        `json:"-"`
	NoiseCenter              string                                          `json:"noise_center"`
	CommonUpperBound         string                                          `json:"common_upper_bound"`
	FinalCoefficientShift    string                                          `json:"final_coefficient_shift"`
	CommonLedgerVerified     bool                                            `json:"common_ledger_verified"`
	RuntimeNoiseConnected    bool                                            `json:"runtime_noise_connected"`
	DurableOpeningConnected  bool                                            `json:"durable_opening_connected"`
	ProductionReady          bool                                            `json:"production_ready"`
	Blockers                 []string                                        `json:"blockers"`
}

func formalCoxRuntimeCommonAdjacency(value string) (string, error) {
	switch value {
	case "add_remove_patient":
		return value, nil
	case "replace_one_patient":
		return "replace_one_fixed_cohort", nil
	default:
		return "", fmt.Errorf("formal-cox: unsupported runtime adjacency")
	}
}

func formalCoxRuntimeRolesFromPins(policy formalCoxPhase1Policy,
	pins map[string]ed25519.PublicKey,
) (formalCoxRuntimeRoles, error) {
	var zero formalCoxRuntimeRoles
	if len(pins) != len(policy.CustodianPeers) {
		return zero, fmt.Errorf("formal-cox: pinset does not cover every custodian")
	}
	for _, peer := range policy.CustodianPeers {
		if len(pins[peer]) != ed25519.PublicKeySize {
			return zero, fmt.Errorf("formal-cox: pinset does not cover every custodian")
		}
	}
	pinset, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || pinset != policy.PinsetSHA256 {
		return zero, fmt.Errorf("formal-cox: pinned consortium digest mismatch")
	}
	type peerRole struct{ name, id string }
	compute := make([]peerRole, len(policy.ComputePeers))
	for index, name := range policy.ComputePeers {
		id, idErr := formalGLMPhase16PeerID(pins[name])
		if idErr != nil {
			return zero, idErr
		}
		compute[index] = peerRole{name: name, id: id}
	}
	sort.Slice(compute, func(i, j int) bool { return compute[i].id < compute[j].id })
	if len(compute) != 2 || compute[0].id == compute[1].id ||
		policy.ComputePeers[0] != compute[0].name ||
		policy.ComputePeers[1] != compute[1].name {
		return zero, fmt.Errorf("formal-cox: compute peers are not in pinned cryptographic role order")
	}
	return formalCoxRuntimeRoles{
		PinsetSHA256:    pinset,
		GarblerPeerName: compute[0].name, GarblerPeerID: compute[0].id,
		EvaluatorPeerName: compute[1].name, EvaluatorPeerID: compute[1].id,
	}, nil
}

func formalCoxRuntimeCoordinateOrderSHA256(iterations, covariates int) string {
	coordinates := make([]string, 0, iterations*covariates)
	for iteration := 0; iteration < iterations; iteration++ {
		for coefficient := 0; coefficient < covariates; coefficient++ {
			coordinates = append(coordinates, fmt.Sprintf(
				"adaptive_score_noise[%d,%d]", iteration, coefficient))
		}
	}
	encoded, _ := json.Marshal(struct {
		Version          string   `json:"version"`
		Coordinates      []string `json:"coordinates"`
		FinalCarrierRule string   `json:"final_carrier_rule"`
	}{
		"formal-cox-runtime-coordinate-order-v1", coordinates,
		"beta_in_first_p_coordinates_then_public_zero_padding_v1",
	})
	digest := formalCoxSHA256Domain(
		"dsVert/formal-cox/runtime-coordinate-order/v1|", encoded)
	return hex.EncodeToString(digest[:])
}

func formalCoxRuntimeQuantizationSHA256(fracBits int) string {
	encoded, _ := json.Marshal(struct {
		Version        string `json:"version"`
		CommonRingBits int    `json:"common_ring_bits"`
		OutputFracBits int    `json:"output_frac_bits"`
		Rule           string `json:"rule"`
	}{
		"formal-cox-runtime-quantization-v1", 128, fracBits,
		"noise_integer_lattice_then_exact_fixed_point_cox_beta_v1",
	})
	digest := formalCoxSHA256Domain("dsVert/formal-cox/runtime-quantization/v1|", encoded)
	return hex.EncodeToString(digest[:])
}

func formalCoxRuntimeValidateAuthority(request formalCoxRuntimeAdmissionRequest,
	policy formalCoxPhase1Policy, roles formalCoxRuntimeRoles,
	pins map[string]ed25519.PublicKey,
) error {
	authority := request.Authority
	for _, value := range []string{
		authority.ManifestSHA256, authority.SchemaManifestSHA256,
		authority.WorkloadSHA256, authority.SourceFanInTranscriptSHA256,
		authority.ReleaseInstanceID, authority.ReleaseContractSHA256,
		request.LogicalSnapshotHandleSHA256, request.PrivacyEpochSHA256,
		request.MaterializationRootSHA256, request.SourceContractHandleSHA256,
		request.RunNonceSHA256, request.WorkerImplementationSHA256,
	} {
		if !formalCoxIsSHA256(value) {
			return fmt.Errorf("formal-cox: invalid runtime authority commitment")
		}
	}
	if len(request.NoiseSeedCommitmentsByPeer) != 2 ||
		jointDPBiomedicalGaussianValidateReceiptReferences(
			request.ReceiptReferences) != nil {
		return fmt.Errorf("formal-cox: incomplete runtime authority")
	}
	for _, peer := range policy.ComputePeers {
		if !formalCoxIsSHA256(request.NoiseSeedCommitmentsByPeer[peer]) {
			return fmt.Errorf("formal-cox: invalid pinned noise-seed commitment")
		}
	}
	return formalCoxRuntimeValidateCommonLedgerAuthority(
		policy, roles, pins, request.NoiseSeedCommitmentsByPeer,
		request.LedgerOpeningTokens, request.ReceiptReferences)
}

func formalCoxRuntimeSensitivityCertificateForPlan(
	policy formalCoxPhase1Policy, plan formalCoxDPPlan,
) formalCoxRuntimeSensitivityCertificate {
	return formalCoxRuntimeSensitivityCertificate{
		Version: formalCoxRuntimeSensitivityVersion,
		Status:  formalCoxRuntimeSensitivityStatus, Norm: "l2",
		SelectedProof:         formalCoxRuntimeSensitivityProof,
		SelectedBoundSteps:    plan.AdaptiveStackSensitivitySteps,
		ScoreSensitivitySteps: plan.ScoreSensitivitySteps,
		Iterations:            policy.Iterations, CovariateCount: policy.CovariateCount,
		NoiseCoordinates:               plan.NoiseCoordinates,
		RiskMeanRoundingPerCoordinate:  plan.RiskMeanRoundingPerCoordinate,
		NormalizedRoundingL2Steps:      plan.NormalizedRoundingL2Steps,
		FiniteSupportTransferToDelta:   plan.FiniteSupportTransferCharged,
		ClientSensitivityOverrideUsed:  false,
		ImplementedArithmeticCertified: plan.PrivacyPlanCertified,
	}
}

func formalCoxRuntimeBuildEnvelope(
	binding formalCoxRuntimeReleaseBinding,
	worker jointDPGaussianOneDrawWorkerContractOutput,
	request formalCoxRuntimeAdmissionRequest,
	policy formalCoxPhase1Policy,
) (jointDPBiomedicalGaussianSignedWorkerEnvelope, error) {
	var zero jointDPBiomedicalGaussianSignedWorkerEnvelope
	epsilon, err := jointDPBiomedicalGaussianCanonicalDecimal(
		binding.Epsilon, "epsilon")
	if err != nil {
		return zero, err
	}
	delta, err := jointDPBiomedicalGaussianCanonicalDecimal(
		binding.AllocatedDelta, "delta")
	if err != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return zero, fmt.Errorf("formal-cox: invalid runtime delta")
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(worker.Plan)
	if err != nil {
		return zero, err
	}
	spec, err := jointDPGaussianOneDrawPolicySpec(worker.WorkerPolicy)
	if err != nil {
		return zero, err
	}
	shape := spec.circuitShapeDigest()
	shapeSHA256 := hex.EncodeToString(shape[:])
	publicPolicySHA256, err := jointDPBiomedicalGaussianPublicWorkerPolicySHA256(
		worker.WorkerPolicy, planSHA256, shapeSHA256)
	if err != nil {
		return zero, err
	}
	workerContractSHA256, err := jointDPBiomedicalGaussianWorkerContractSHA256(
		publicPolicySHA256, planSHA256, shapeSHA256,
		request.WorkerImplementationSHA256)
	if err != nil {
		return zero, err
	}
	custodians := append([]string(nil), policy.CustodianPeers...)
	preimage := jointDPBiomedicalGaussianWorkerEnvelopePreimage{
		Version:                  jointDPBiomedicalGaussianWorkerEnvelopeVersion,
		Route:                    jointDPBiomedicalGaussianWorkerRoute,
		PublicIdentifierContract: jointDPBiomedicalGaussianPublicIdentifierRule,
		CapsuleID:                binding.CapsuleID, ManifestSHA256: binding.ManifestSHA256,
		SchemaManifestSHA256:        binding.SchemaManifestSHA256,
		WorkloadSHA256:              binding.WorkloadSHA256,
		LogicalSnapshotHandleSHA256: request.LogicalSnapshotHandleSHA256,
		LogicalSnapshotHandleKind:   jointDPBiomedicalGaussianOpaqueSnapshotHandle,
		PrivacyEpochSHA256:          request.PrivacyEpochSHA256,
		ReleaseInstanceID:           binding.ReleaseInstanceID,
		ReleaseContractSHA256:       binding.ReleaseContractSHA256,
		WorkerTranscriptSHA256:      binding.ReleaseContractSHA256,
		WorkerTranscriptKind:        jointDPBiomedicalGaussianWorkerTranscriptKind,
		Mechanism:                   binding.Mechanism, Allocation: binding.Allocation,
		Adjacency: binding.Adjacency,
		Epsilon:   binding.Epsilon, EpsilonNumerator: epsilon.Num().String(),
		EpsilonDenominator: epsilon.Denom().String(),
		Delta:              binding.AllocatedDelta, DeltaNumerator: delta.Num().String(),
		DeltaDenominator: delta.Denom().String(),
		PinsetSHA256:     binding.PinsetSHA256, CustodianPeers: custodians,
		CustodianCount:         len(custodians),
		GarblerPeerName:        binding.GarblerPeerName,
		GarblerPeerID:          binding.GarblerPeerID,
		EvaluatorPeerName:      binding.EvaluatorPeerName,
		EvaluatorPeerID:        binding.EvaluatorPeerID,
		DesignatedComputeCount: 2,
		CoordinateOrderSHA256:  binding.CoordinateOrderSHA256,
		LatticeTransformSHA256: binding.QuantizationSHA256,
		CommonLattice:          jointDPBiomedicalGaussianCommonLattice,
		OutputLatticeBits:      binding.OutputLatticeBits,
		TotalCoordinateCount:   binding.CoordinateCount,
		ChunkStart:             worker.WorkerPolicy.ChunkStart,
		CoordinateCount:        worker.WorkerPolicy.CoordinateCount,
		CommonLatticeUpperBounds: append([]string(nil),
			binding.ShiftedUpperBounds...),
		L2SensitivitySteps:        binding.SensitivitySteps,
		SensitivityAuthority:      jointDPBiomedicalGaussianSensitivityAuthority,
		SensitivityCertificateSHA: binding.SensitivityCertificateSHA256,
		WorkerSensitivitySHA256:   binding.SensitivityCertificateSHA256,
		PlanSHA256:                planSHA256, CircuitShapeSHA256: shapeSHA256,
		WorkerPublicPolicySHA256:   publicPolicySHA256,
		WorkerContractSHA256:       workerContractSHA256,
		WorkerImplementationSHA256: request.WorkerImplementationSHA256,
		MaterializationRootSHA256:  request.MaterializationRootSHA256,
		MaterializationRootKind:    jointDPBiomedicalGaussianOpaqueSourceRoot,
		SourceContractHandleSHA256: request.SourceContractHandleSHA256,
		SourceContractHandleKind:   jointDPBiomedicalGaussianOpaqueSourceContract,
		RunNonceSHA256:             request.RunNonceSHA256,
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			request.ReceiptReferences...),
		GenericMachineProvenAuthorizes: false,
		SourceShareMayBeUnbound:        false,
		OperationLimit:                 false, RequestLimit: false,
		HistoryCanDenyOperation: false, OpeningsAuthorized: 0,
		ProductionReady: false,
		Blockers:        append([]string(nil), jointDPBiomedicalGaussianWorkerBlockers...),
	}
	preimage.ProductiveStreamSHA256, err =
		jointDPBiomedicalGaussianProductiveStreamSHA256(preimage)
	if err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianSignedWorkerEnvelope{
		Preimage: preimage, WorkerPolicy: worker.WorkerPolicy,
	}, nil
}

func buildFormalCoxRuntimeAdmission(policy formalCoxPhase1Policy,
	pins map[string]ed25519.PublicKey, request formalCoxRuntimeAdmissionRequest,
) (formalCoxRuntimeAdmission, error) {
	var zero formalCoxRuntimeAdmission
	parsed, err := parseFormalCoxPhase1Policy(policy)
	if err != nil {
		return zero, err
	}
	phase1, err := planFormalCoxPhase1(policy)
	if err != nil {
		return zero, err
	}
	dpPlan, err := planFormalCoxDP(policy)
	if err != nil {
		return zero, err
	}
	if !dpPlan.PrivacyPlanCertified || !dpPlan.PolicyNoiseBoundMatches ||
		!dpPlan.PolicyNoiseChunkCountMatches ||
		dpPlan.NoiseCoordinates != policy.Iterations*policy.CovariateCount {
		return zero, fmt.Errorf("formal-cox: signed finite-support DP plan is incomplete")
	}
	roles, err := formalCoxRuntimeRolesFromPins(policy, pins)
	if err != nil {
		return zero, err
	}
	if err := formalCoxRuntimeValidateAuthority(
		request, policy, roles, pins); err != nil {
		return zero, err
	}
	ledgerTokenSetSHA256, err := formalCoxRuntimeLedgerTokenSetSHA256(
		request.LedgerOpeningTokens)
	if err != nil {
		return zero, err
	}
	trust, err := formalGLMPhase16ProductiveTrust(
		pins, request.WorkerImplementationSHA256)
	if err != nil || trust.PinsetSHA256 != roles.PinsetSHA256 {
		return zero, fmt.Errorf("formal-cox: invalid local productive trust root")
	}
	trustedNames := make([]string, len(trust.PinnedPeers))
	for index := range trust.PinnedPeers {
		trustedNames[index] = trust.PinnedPeers[index].Name
	}
	if !reflect.DeepEqual(trustedNames, policy.CustodianPeers) {
		return zero, fmt.Errorf("formal-cox: trust root escaped the policy consortium")
	}
	transcript, err := jointDPGaussianOneDrawDecodeHex(
		request.Authority.ReleaseContractSHA256, "formal Cox release contract")
	if err != nil {
		return zero, err
	}
	garblerContext := jointDPCommitmentContext(transcript,
		jointDPGaussianOneDrawCommitmentPurpose+"/garbler", roles.GarblerPeerID)
	evaluatorContext := jointDPCommitmentContext(transcript,
		jointDPGaussianOneDrawCommitmentPurpose+"/evaluator", roles.EvaluatorPeerID)
	garblerCommitment := request.NoiseSeedCommitmentsByPeer[roles.GarblerPeerName]
	evaluatorCommitment := request.NoiseSeedCommitmentsByPeer[roles.EvaluatorPeerName]
	certificate := formalCoxRuntimeSensitivityCertificateForPlan(policy, dpPlan)
	certificateSHA256, err := formalCoxRuntimeSensitivityDigest(certificate)
	if err != nil {
		return zero, err
	}
	numericCertificate, err := formalCoxRuntimeNumericCertificateForPolicy(
		policy, phase1)
	if err != nil {
		return zero, err
	}
	if err := formalCoxRuntimeValidateNumericCertificate(
		policy, phase1, numericCertificate); err != nil {
		return zero, err
	}
	numericCertificateSHA256, err := formalCoxRuntimeNumericCertificateSHA256(
		numericCertificate)
	if err != nil {
		return zero, err
	}
	policyDigest, err := formalCoxPolicyDigest(policy)
	if err != nil {
		return zero, err
	}
	adjacency, err := formalCoxRuntimeCommonAdjacency(policy.Adjacency)
	if err != nil {
		return zero, err
	}
	noiseCenter := new(big.Int).Set(parsed.noiseBound)
	carrierMagnitude := formalCoxMax(noiseCenter, parsed.betaNorm)
	commonUpper := new(big.Int).Mul(big.NewInt(2), carrierMagnitude)
	if commonUpper.Cmp(exactGCMaxSigned(128)) > 0 {
		return zero, exactGCFailure(exactGCFailureBoundExceeded,
			fmt.Errorf("formal-cox: sampler/final carrier exceeds Ring128"))
	}
	upperBounds := make([]string, dpPlan.NoiseCoordinates)
	for index := range upperBounds {
		upperBounds[index] = commonUpper.String()
	}
	binding := formalCoxRuntimeReleaseBinding{
		Version:                     formalCoxRuntimeReleaseVersion,
		PolicySHA256:                hex.EncodeToString(policyDigest[:]),
		CapsuleID:                   policy.CapsuleSHA256,
		ManifestSHA256:              request.Authority.ManifestSHA256,
		SchemaManifestSHA256:        request.Authority.SchemaManifestSHA256,
		WorkloadSHA256:              request.Authority.WorkloadSHA256,
		SnapshotSHA256:              policy.SnapshotSHA256,
		SourceFanInTranscriptSHA256: request.Authority.SourceFanInTranscriptSHA256,
		LedgerOpeningTokenSetSHA256: ledgerTokenSetSHA256,
		ReleaseInstanceID:           request.Authority.ReleaseInstanceID,
		ReleaseContractSHA256:       request.Authority.ReleaseContractSHA256,
		FinalReceiptPairSHA256:      request.Authority.ReleaseContractSHA256,
		Adjacency:                   adjacency, Mechanism: jointDPGaussianOneDrawMechanism,
		Allocation: jointDPGaussianOneDrawAllocation,
		Epsilon:    policy.Epsilon, AllocatedDelta: policy.Delta,
		CommonRingBits: 128, OutputLatticeBits: policy.FracBits,
		CoordinateCount: dpPlan.NoiseCoordinates,
		CoordinateOrderSHA256: formalCoxRuntimeCoordinateOrderSHA256(
			policy.Iterations, policy.CovariateCount),
		QuantizationSHA256: formalCoxRuntimeQuantizationSHA256(policy.FracBits),
		ShiftedUpperBounds: upperBounds,
		SensitivitySteps:   dpPlan.AdaptiveStackSensitivitySteps,
		SensitivityNorm:    "l2", SensitivityProof: formalCoxRuntimeSensitivityProof,
		SensitivityCertificateKind:   jointDPGaussianOneDrawSensitivityCertificateKind,
		SensitivityCertificateSHA256: certificateSHA256,
		SensitivityCertificate:       certificate,
		NumericCertificateSHA256:     numericCertificateSHA256,
		NumericCertificate:           numericCertificate,
		PinsetSHA256:                 roles.PinsetSHA256,
		CustodianCount:               len(policy.CustodianPeers),
		GarblerPeerName:              roles.GarblerPeerName,
		GarblerPeerID:                roles.GarblerPeerID,
		EvaluatorPeerName:            roles.EvaluatorPeerName,
		EvaluatorPeerID:              roles.EvaluatorPeerID,
		GarblerCommitmentContext:     hex.EncodeToString(garblerContext[:]),
		GarblerSeedCommitment:        garblerCommitment,
		EvaluatorCommitmentContext:   hex.EncodeToString(evaluatorContext[:]),
		EvaluatorSeedCommitment:      evaluatorCommitment,
		OpeningCount:                 1, ExactIntermediateOpenings: 0,
		ProductionReady: false, BindingSHA256: "",
	}
	canonical, err := formalCoxRuntimeReleaseBindingPreimage(binding)
	if err != nil {
		return zero, err
	}
	bindingSHA256, err := formalCoxRuntimeReleaseBindingDigest(binding)
	if err != nil {
		return zero, err
	}
	workers := make([]jointDPGaussianOneDrawWorkerContractOutput, 0,
		dpPlan.SamplerChunkCount)
	envelopes := make([]jointDPBiomedicalGaussianSignedWorkerEnvelope, 0,
		dpPlan.SamplerChunkCount)
	for start := 0; start < dpPlan.NoiseCoordinates; {
		count := dpPlan.CommonPlan.MaximumChunkCoordinates
		if remaining := dpPlan.NoiseCoordinates - start; count > remaining {
			count = remaining
		}
		shifts := make([]int, count)
		rawUpper := make([]string, count)
		for index := range rawUpper {
			rawUpper[index] = commonUpper.String()
		}
		worker, compileErr := jointDPCompileGaussianOneDrawWorkerContract(
			jointDPGaussianOneDrawWorkerContractInput{
				Version:  jointDPGaussianOneDrawWorkerContractInputVersion,
				RingBits: 128, FracBits: 0,
				TotalCoordinateCount: dpPlan.NoiseCoordinates,
				ChunkStart:           start, CoordinateCount: count,
				OutputLatticeBits: policy.FracBits,
				Epsilon:           policy.Epsilon, AllocatedDelta: policy.Delta,
				L2SensitivitySteps:             dpPlan.AdaptiveStackSensitivitySteps,
				L2SensitivityCertificateKind:   jointDPGaussianOneDrawSensitivityCertificateKind,
				L2SensitivityCertificateSHA256: certificateSHA256,
				ReleaseBindingDomain:           formalCoxRuntimeReleaseDomain,
				ReleaseBindingCanonicalJSON:    string(canonical),
				ScaleShifts:                    shifts, RawUpperBounds: rawUpper,
				ReleaseBindingSHA256:       bindingSHA256,
				CrossSignedPolicySHA256:    bindingSHA256,
				TranscriptHash:             request.Authority.ReleaseContractSHA256,
				PinsetSHA256:               roles.PinsetSHA256,
				CustodianCount:             len(policy.CustodianPeers),
				DesignatedComputePeerCount: 2,
				GarblerPeerID:              roles.GarblerPeerID,
				EvaluatorPeerID:            roles.EvaluatorPeerID,
				GarblerCommitmentContext:   binding.GarblerCommitmentContext,
				EvaluatorCommitmentContext: binding.EvaluatorCommitmentContext,
				GarblerSeedCommitment:      binding.GarblerSeedCommitment,
				EvaluatorSeedCommitment:    binding.EvaluatorSeedCommitment,
			})
		if compileErr != nil || !worker.CapabilityAvailable {
			if compileErr == nil {
				compileErr = fmt.Errorf("formal-cox: common one-draw worker unavailable")
			}
			return zero, compileErr
		}
		envelope, envelopeErr := formalCoxRuntimeBuildEnvelope(
			binding, worker, request, policy)
		if envelopeErr != nil {
			return zero, envelopeErr
		}
		workers = append(workers, worker)
		envelopes = append(envelopes, envelope)
		start += count
	}
	if len(workers) != policy.NoiseChunkCount {
		return zero, fmt.Errorf("formal-cox: runtime chunk count escaped signed policy")
	}
	return formalCoxRuntimeAdmission{
		Version: formalCoxRuntimeAdmissionVersion,
		Policy:  policy, Phase1Plan: phase1, DPPlan: dpPlan, Roles: roles,
		NumericCertificate:       numericCertificate,
		NumericCertificateSHA256: numericCertificateSHA256,
		Binding:                  binding, BindingCanonicalJSON: string(canonical),
		Workers: workers, Envelopes: envelopes, Trust: trust,
		NoiseCenter: noiseCenter.String(), CommonUpperBound: commonUpper.String(),
		FinalCoefficientShift: parsed.betaNorm.String(),
		CommonLedgerVerified:  true,
		RuntimeNoiseConnected: false, DurableOpeningConnected: false,
		ProductionReady: false,
		Blockers:        append([]string(nil), formalCoxRuntimeAdmissionBlockers...),
	}, nil
}
