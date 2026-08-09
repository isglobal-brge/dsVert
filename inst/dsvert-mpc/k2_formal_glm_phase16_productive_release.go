package main

// Authoritative formal-GLM admission into the reviewed one-draw Gaussian
// worker.  It reuses the existing K-signed worker envelope and durable common
// release implementation; no analyst-facing command is registered here.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
)

type formalGLMPhase16ProductiveRequest struct {
	LogicalSnapshotHandleSHA256 string
	PrivacyEpochSHA256          string
	RunNonceSHA256              string
	WorkerImplementationSHA256  string
	ReceiptReferences           []jointDPBiomedicalGaussianReceiptReference
}

type formalGLMPhase16ProductiveAdmission struct {
	Compiled         formalGLMPhase16CompiledRelease
	Envelope         jointDPBiomedicalGaussianSignedWorkerEnvelope
	Trust            jointDPBiomedicalGaussianWorkerTrustRoot
	Token            formalGLMPhase19PostExecutionToken
	BackendSelection formalGLMPhase16BackendSelectionAttestation
	BackendPlans     formalGLMPhase16BackendPlans
}

func formalGLMPhase16ProductiveTrust(pins map[string]ed25519.PublicKey,
	workerImplementationSHA256 string) (jointDPBiomedicalGaussianWorkerTrustRoot, error) {
	if !formalGLMIsSHA256(workerImplementationSHA256) {
		return jointDPBiomedicalGaussianWorkerTrustRoot{},
			fmt.Errorf("formal-glm: invalid pinned worker implementation")
	}
	pinset, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		return jointDPBiomedicalGaussianWorkerTrustRoot{}, err
	}
	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}
	sort.Strings(names)
	peers := make([]jointDPBiomedicalGaussianPinnedPeer, len(names))
	for index, name := range names {
		peers[index] = jointDPBiomedicalGaussianPinnedPeer{
			Name:             name,
			Ed25519PublicKey: append([]byte(nil), pins[name]...),
		}
	}
	trust := jointDPBiomedicalGaussianWorkerTrustRoot{
		Version:                    jointDPBiomedicalGaussianWorkerTrustVersion,
		AllowedRoute:               jointDPBiomedicalGaussianWorkerRoute,
		PinsetSHA256:               pinset,
		WorkerImplementationSHA256: workerImplementationSHA256,
		PinnedPeers:                peers,
	}
	if _, trusted, err := jointDPBiomedicalGaussianTrustPins(trust); err != nil ||
		!reflect.DeepEqual(trusted, names) {
		return jointDPBiomedicalGaussianWorkerTrustRoot{},
			fmt.Errorf("formal-glm: invalid productive trust root")
	}
	return trust, nil
}

func formalGLMPhase16BuildProductiveEnvelope(plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt, pins map[string]ed25519.PublicKey,
	bridge formalGLMPhase15DPBridgePlan, capsule formalGLMPhase16CapsuleBinding,
	token formalGLMPhase19PostExecutionToken, backendKey [32]byte,
	request formalGLMPhase16ProductiveRequest) (
	formalGLMPhase16ProductiveAdmission, error) {

	var zero formalGLMPhase16ProductiveAdmission
	if err := formalGLMPhase19VerifyPostExecutionToken(token, backendKey); err != nil {
		return zero, err
	}
	if !formalGLMIsSHA256(request.LogicalSnapshotHandleSHA256) ||
		!formalGLMIsSHA256(request.PrivacyEpochSHA256) ||
		!formalGLMIsSHA256(request.RunNonceSHA256) ||
		!formalGLMIsSHA256(request.WorkerImplementationSHA256) ||
		jointDPBiomedicalGaussianValidateReceiptReferences(
			request.ReceiptReferences) != nil {
		return zero, fmt.Errorf("formal-glm: invalid productive release request")
	}
	receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(receipts)
	if err != nil {
		return zero, err
	}
	receiptSHA256 := hex.EncodeToString(receiptDigest[:])
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return zero, err
	}
	if capsule.ReleaseContractSHA256 != receiptSHA256 ||
		token.CapsuleSHA256 != capsule.CapsuleID ||
		token.Phase15PlanSHA256 != hex.EncodeToString(planDigest[:]) ||
		token.PinsetSHA256 != plan.Kernel.PinsetSHA256 ||
		token.GlobalMaterializationRoot == "" ||
		token.FinalCheckpointTranscriptSHA256 != bridge.ExecutionTranscriptSHA256 ||
		token.Phase15ExecutionTranscriptSHA256 != bridge.ExecutionTranscriptSHA256 ||
		token.CustodianCount != len(plan.Kernel.CustodianPeers) ||
		!reflect.DeepEqual(token.ComputePeers, plan.Kernel.ComputePeers) {
		return zero, fmt.Errorf("formal-glm: Phase-1.9 evidence is not the productive release source")
	}
	binding, err := buildFormalGLMPhase16ReleaseBinding(
		plan, receipts, pins, bridge, capsule)
	if err != nil {
		return zero, err
	}
	selectionContract, backendPlans, err :=
		formalGLMPhase16BuildBackendSelection(binding, token, pins)
	if err != nil {
		return zero, err
	}
	compiled := formalGLMPhase16CompiledRelease{Binding: binding}
	if binding.FinalReceiptPairSHA256 != receiptSHA256 ||
		binding.ReleaseContractSHA256 != receiptSHA256 ||
		binding.SourceFanInTranscriptSHA256 !=
			token.FinalCheckpointTranscriptSHA256 {
		return zero, fmt.Errorf("formal-glm: productive worker escaped the final checkpoint")
	}
	custodians := append([]string(nil), plan.Kernel.CustodianPeers...)
	sort.Strings(custodians)
	trust, err := formalGLMPhase16ProductiveTrust(
		pins, request.WorkerImplementationSHA256)
	if err != nil || trust.PinsetSHA256 != binding.PinsetSHA256 ||
		!reflect.DeepEqual(custodians, func() []string {
			values := make([]string, len(trust.PinnedPeers))
			for index := range trust.PinnedPeers {
				values[index] = trust.PinnedPeers[index].Name
			}
			return values
		}()) {
		if err == nil {
			err = fmt.Errorf("formal-glm: productive trust does not match the plan")
		}
		return zero, err
	}
	baseAdmission := formalGLMPhase16ProductiveAdmission{
		Compiled: compiled, Trust: trust, Token: token,
		BackendSelection: formalGLMPhase16BackendSelectionAttestation{
			Contract: selectionContract,
		},
		BackendPlans: backendPlans,
	}
	if selectionContract.SelectedBackend == formalGLMPhase16BackendFull {
		// The K signatures on BackendSelection are admitted next.  Each
		// designated peer can then contribute its persistent root epoch and
		// commitment to the separately K-signed full release contract.
		return baseAdmission, nil
	}
	compiled, err = formalGLMPhase16CompileSealedWorker(
		plan, receipts, pins, bridge, capsule)
	if err != nil || compiled.Worker == nil ||
		!compiled.Worker.CapabilityAvailable ||
		!reflect.DeepEqual(compiled.Worker.Plan, backendPlans.OneDraw) {
		if err == nil {
			err = fmt.Errorf("formal-glm: selected one-draw worker is unavailable")
		}
		return zero, err
	}
	baseAdmission.Compiled = compiled
	worker := compiled.Worker
	epsilon, err := jointDPBiomedicalGaussianCanonicalDecimal(
		binding.Epsilon, "epsilon")
	if err != nil {
		return zero, err
	}
	delta, err := jointDPBiomedicalGaussianCanonicalDecimal(
		binding.AllocatedDelta, "delta")
	if err != nil {
		return zero, err
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
	preimage := jointDPBiomedicalGaussianWorkerEnvelopePreimage{
		Version:                     jointDPBiomedicalGaussianWorkerEnvelopeVersion,
		Route:                       jointDPBiomedicalGaussianWorkerRoute,
		PublicIdentifierContract:    jointDPBiomedicalGaussianPublicIdentifierRule,
		CapsuleID:                   binding.CapsuleID,
		ManifestSHA256:              binding.ManifestSHA256,
		SchemaManifestSHA256:        binding.SchemaManifestSHA256,
		WorkloadSHA256:              binding.WorkloadSHA256,
		LogicalSnapshotHandleSHA256: request.LogicalSnapshotHandleSHA256,
		LogicalSnapshotHandleKind:   jointDPBiomedicalGaussianOpaqueSnapshotHandle,
		PrivacyEpochSHA256:          request.PrivacyEpochSHA256,
		ReleaseInstanceID:           binding.ReleaseInstanceID,
		ReleaseContractSHA256:       binding.ReleaseContractSHA256,
		WorkerTranscriptSHA256:      binding.ReleaseContractSHA256,
		WorkerTranscriptKind:        jointDPBiomedicalGaussianWorkerTranscriptKind,
		Mechanism:                   binding.Mechanism,
		Allocation:                  binding.Allocation,
		Adjacency:                   binding.Adjacency,
		Epsilon:                     binding.Epsilon,
		EpsilonNumerator:            epsilon.Num().String(),
		EpsilonDenominator:          epsilon.Denom().String(),
		Delta:                       binding.AllocatedDelta,
		DeltaNumerator:              delta.Num().String(),
		DeltaDenominator:            delta.Denom().String(),
		PinsetSHA256:                binding.PinsetSHA256,
		CustodianPeers:              custodians,
		CustodianCount:              len(custodians),
		GarblerPeerName:             binding.GarblerPeerName,
		GarblerPeerID:               binding.GarblerPeerID,
		EvaluatorPeerName:           binding.EvaluatorPeerName,
		EvaluatorPeerID:             binding.EvaluatorPeerID,
		DesignatedComputeCount:      2,
		CoordinateOrderSHA256:       binding.CoordinateOrderSHA256,
		LatticeTransformSHA256:      binding.QuantizationSHA256,
		CommonLattice:               jointDPBiomedicalGaussianCommonLattice,
		OutputLatticeBits:           binding.OutputLatticeBits,
		TotalCoordinateCount:        binding.CoordinateCount,
		ChunkStart:                  0,
		CoordinateCount:             binding.CoordinateCount,
		CommonLatticeUpperBounds: append([]string(nil),
			binding.ShiftedUpperBounds...),
		L2SensitivitySteps:         binding.SensitivitySteps,
		SensitivityAuthority:       jointDPBiomedicalGaussianSensitivityAuthority,
		SensitivityCertificateSHA:  binding.SensitivityCertificateSHA256,
		WorkerSensitivitySHA256:    binding.SensitivityCertificateSHA256,
		PlanSHA256:                 planSHA256,
		CircuitShapeSHA256:         shapeSHA256,
		WorkerPublicPolicySHA256:   publicPolicySHA256,
		WorkerContractSHA256:       workerContractSHA256,
		WorkerImplementationSHA256: request.WorkerImplementationSHA256,
		MaterializationRootSHA256:  token.GlobalMaterializationRoot,
		MaterializationRootKind:    jointDPBiomedicalGaussianOpaqueSourceRoot,
		SourceContractHandleSHA256: binding.SourceContextSHA256,
		SourceContractHandleKind:   jointDPBiomedicalGaussianOpaqueSourceContract,
		RunNonceSHA256:             request.RunNonceSHA256,
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			request.ReceiptReferences...),
		GenericMachineProvenAuthorizes: false,
		SourceShareMayBeUnbound:        false,
		OperationLimit:                 false,
		RequestLimit:                   false,
		HistoryCanDenyOperation:        false,
		OpeningsAuthorized:             0,
		ProductionReady:                false,
		Blockers: append([]string(nil),
			jointDPBiomedicalGaussianWorkerBlockers...),
	}
	preimage.ProductiveStreamSHA256, err =
		jointDPBiomedicalGaussianProductiveStreamSHA256(preimage)
	if err != nil {
		return zero, err
	}
	baseAdmission.Envelope = jointDPBiomedicalGaussianSignedWorkerEnvelope{
		Preimage: preimage, WorkerPolicy: worker.WorkerPolicy,
	}
	return baseAdmission, nil
}

func formalGLMPhase16SignProductiveEnvelope(
	preimage jointDPBiomedicalGaussianWorkerEnvelopePreimage,
	signer string, privateKey ed25519.PrivateKey) (
	jointDPBiomedicalGaussianSignature, error) {
	return jointDPBiomedicalGaussianSignWorkerEnvelope(
		preimage, signer, privateKey)
}

func formalGLMPhase16AdmitProductiveSignatures(
	admission formalGLMPhase16ProductiveAdmission,
	signatures []jointDPBiomedicalGaussianSignature) (
	formalGLMPhase16ProductiveAdmission, error) {
	if admission.BackendSelection.Contract.SelectedBackend !=
		formalGLMPhase16BackendOneDraw {
		return formalGLMPhase16ProductiveAdmission{},
			fmt.Errorf("formal-glm: productive envelope signatures apply only to one-draw")
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(admission.Trust)
	if err != nil {
		return formalGLMPhase16ProductiveAdmission{}, err
	}
	if _, err := formalGLMPhase16ValidateBackendSelection(
		admission.BackendSelection, admission.Compiled.Binding,
		admission.Token, pins); err != nil {
		return formalGLMPhase16ProductiveAdmission{}, err
	}
	admission.Envelope.Signatures = append(
		[]jointDPBiomedicalGaussianSignature(nil), signatures...)
	if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		admission.Envelope, admission.Trust); err != nil {
		admission.Envelope.Signatures = nil
		return formalGLMPhase16ProductiveAdmission{}, err
	}
	return admission, nil
}

func formalGLMPhase16AdmitProductiveBackendSignatures(
	admission formalGLMPhase16ProductiveAdmission,
	signatures []jointDPBiomedicalGaussianSignature,
) (formalGLMPhase16ProductiveAdmission, error) {
	pins, _, err := jointDPBiomedicalGaussianTrustPins(admission.Trust)
	if err != nil {
		return formalGLMPhase16ProductiveAdmission{}, err
	}
	admission.BackendSelection.Signatures =
		jointDPBiomedicalGaussianFullCloneSignatures(signatures)
	plans, err := formalGLMPhase16ValidateBackendSelection(
		admission.BackendSelection, admission.Compiled.Binding,
		admission.Token, pins)
	if err != nil || !reflect.DeepEqual(plans, admission.BackendPlans) {
		return formalGLMPhase16ProductiveAdmission{},
			fmt.Errorf("formal-glm: invalid signed productive backend selection")
	}
	return admission, nil
}
