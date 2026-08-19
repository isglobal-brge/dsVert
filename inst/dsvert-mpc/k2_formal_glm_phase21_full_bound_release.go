package main

// Phase-2.1b applies the same authoritative handoff boundary as the one-draw
// runner to the independently sampled full fallback.  The exact range guard,
// the source binding and the sampler all consume the share loaded from the
// Phase-2.0 AEAD slot; no integration caller supplies any of them.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
)

const formalGLMPhase21FullBoundReleaseVersion = "dsvert-formal-glm-phase21-full-source-bound-release-v1"

// All fields are explicitly non-serializable. PeerShare contains a protected
// noised additive share and must travel only through the authenticated
// peer-to-peer handoff, never through relay JSON.
type formalGLMPhase21FullLocalOutput struct {
	Version          string                                        `json:"-"`
	Peer             string                                        `json:"-"`
	Role             string                                        `json:"-"`
	HandoffSHA256    string                                        `json:"-"`
	HandoffBytes     int64                                         `json:"-"`
	Productive       formalGLMPhase16ProductiveAdmission           `json:"-"`
	Admission        jointDPBiomedicalGaussianFullAdmission        `json:"-"`
	RangeGuard       formalGLMPhase16FullRangeGuardReceipt         `json:"-"`
	PeerShare        jointDPBiomedicalGaussianFullPhase19PeerShare `json:"-"`
	capsule          formalGLMPhase16CapsuleBinding
	request          formalGLMPhase16ProductiveRequest
	fullRequest      formalGLMPhase16FullFallbackRequest
	attestation      formalGLMPhase16FullFallbackContractAttestation
	sourceBindingSHA string
}

func (output *formalGLMPhase21FullLocalOutput) clear() {
	if output != nil {
		*output = formalGLMPhase21FullLocalOutput{}
	}
}

func formalGLMPhase21LoadAndAdmitFull(
	store *formalGLMPhase20HandoffStore,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures []jointDPBiomedicalGaussianSignature,
	fullRequest formalGLMPhase16FullFallbackRequest,
	attestation formalGLMPhase16FullFallbackContractAttestation,
) (formalGLMPhase20LocalRuntime, formalGLMPhase20HandoffCommit, error) {
	var zero formalGLMPhase20LocalRuntime
	if store == nil {
		return zero, formalGLMPhase20HandoffCommit{},
			fmt.Errorf("formal-glm: missing Phase-2.1 full source handoff")
	}
	source, commit, err := store.Load()
	if err != nil {
		return zero, formalGLMPhase20HandoffCommit{}, err
	}
	productive, err := formalGLMPhase16BuildProductiveEnvelope(
		source.Plan, source.Result.FinalReceipts, store.pins,
		source.Result.DPBridge, capsule, source.Result.PostExecutionToken,
		source.backend, request)
	if err != nil {
		source.clear()
		return zero, formalGLMPhase20HandoffCommit{}, err
	}
	runtime := formalGLMPhase20LocalRuntime{
		Source: source,
		Admission: formalGLMPhase20RuntimeAdmission{
			Productive: productive,
		},
		capsule: capsule,
		request: request,
	}
	runtime, err = formalGLMPhase20AdmitLocalRuntime(
		runtime, backendSignatures, nil, &fullRequest, &attestation,
		store.pins)
	if err != nil {
		source.clear()
		return zero, formalGLMPhase20HandoffCommit{}, err
	}
	if runtime.Admission.Full == nil ||
		runtime.Admission.Productive.BackendSelection.Contract.SelectedBackend !=
			formalGLMPhase16BackendFull {
		runtime.clear()
		return zero, formalGLMPhase20HandoffCommit{},
			fmt.Errorf("formal-glm: Phase-2.1 full runner requires the signed full fallback")
	}
	return runtime, commit, nil
}

func formalGLMPhase21RunFullLocal(
	rw io.ReadWriter,
	store *formalGLMPhase20HandoffStore,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures []jointDPBiomedicalGaussianSignature,
	fullRequest formalGLMPhase16FullFallbackRequest,
	attestation formalGLMPhase16FullFallbackContractAttestation,
	root [32]byte,
	signer ed25519.PrivateKey,
) (formalGLMPhase21FullLocalOutput, error) {
	var zero formalGLMPhase21FullLocalOutput
	if rw == nil {
		return zero, fmt.Errorf("formal-glm: nil Phase-2.1 full peer channel")
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmitFull(
		store, capsule, request, backendSignatures, fullRequest, attestation)
	if err != nil {
		return zero, err
	}
	defer runtime.clear()
	role, encoded, source, session, err :=
		formalGLMPhase21FullSourceMaterialWithPins(runtime, store.pins)
	if err != nil {
		return zero, err
	}
	admission := *runtime.Admission.Full
	binding := admission.formalBinding
	var guard formalGLMPhase16FullRangeGuardReceipt
	if role == "garbler" {
		guard, err = formalGLMPhase16RunFullRangeGuardGarbler(
			rw, admission, store.pins, session, runtime.Source.DPShares,
			binding.ShiftedUpperBounds, source.source.BindingSHA256, 0,
			root, signer)
	} else {
		guard, err = formalGLMPhase16RunFullRangeGuardEvaluator(
			rw, admission, store.pins, session, runtime.Source.DPShares,
			binding.ShiftedUpperBounds, source.source.BindingSHA256, 0,
			signer)
	}
	if err != nil {
		return zero, err
	}
	peerShare, err := jointDPBiomedicalGaussianRunFullPhase19Peer(
		admission, store.pins, source, runtime.Source.backend, root,
		signer, encoded)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase21FullLocalOutput{
		Version:          formalGLMPhase21FullBoundReleaseVersion,
		Peer:             runtime.Source.Result.Peer,
		Role:             role,
		HandoffSHA256:    commit.SHA256,
		HandoffBytes:     commit.Bytes,
		Productive:       runtime.Admission.Productive,
		Admission:        admission,
		RangeGuard:       guard,
		PeerShare:        peerShare,
		capsule:          capsule,
		request:          request,
		fullRequest:      fullRequest,
		attestation:      attestation,
		sourceBindingSHA: source.source.BindingSHA256,
	}, nil
}

func formalGLMPhase21RunFullLocalV2(
	rw io.ReadWriter,
	store *formalGLMPhase20HandoffStore,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures []jointDPBiomedicalGaussianSignature,
	fullRequest formalGLMPhase16FullFallbackRequest,
	attestation formalGLMPhase16FullFallbackContractAttestation,
	authorityRoot [32]byte,
	signer ed25519.PrivateKey,
	contract formalGLMPhase21SamplerV2Contract,
	authorizations []formalGLMPhase21SamplerV2Authorization,
) (formalGLMPhase21FullLocalOutput, error) {
	var zero formalGLMPhase21FullLocalOutput
	if rw == nil || store == nil {
		return zero, fmt.Errorf("formal-glm: nil sampler-v2 full boundary")
	}
	if contract.SamplerMode != formalGLMPhase21SamplerV2Full {
		return zero, fmt.Errorf("formal-glm: sampler-v2 full mode mismatch")
	}
	if err := formalGLMPhase21ValidateSamplerV2Authorizations(
		contract, authorizations, store.pins); err != nil {
		return zero, err
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmitFull(
		store, capsule, request, backendSignatures, fullRequest, attestation)
	if err != nil {
		return zero, err
	}
	defer runtime.clear()
	if runtime.Admission.Full == nil ||
		runtime.Admission.Full.formalBinding == nil {
		return zero, fmt.Errorf("formal-glm: sampler-v2 full binding is missing")
	}
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		*runtime.Admission.Full.formalBinding, runtime.Source.Plan, store.pins)
	if err != nil || artifactID != contract.ArtifactID ||
		!reflect.DeepEqual(artifact, contract.Artifact) {
		return zero, fmt.Errorf("formal-glm: sampler-v2 full artifact mismatch")
	}
	role, encoded, source, session, err :=
		formalGLMPhase21FullSourceMaterialWithPins(runtime, store.pins)
	if err != nil {
		return zero, err
	}
	position := 0
	if role == "evaluator" {
		position = 1
	}
	authority := contract.Artifact.NoiseAuthorities[position]
	maskRoot, commitment, err := formalGLMPhase21SamplerV2Derive(
		authorityRoot, contract.ArtifactID, contract.SamplerMode,
		role, authority.PeerName, authority.PeerID)
	if err != nil || !reflect.DeepEqual(
		commitment, contract.NoiseCommitments[position]) {
		clear(maskRoot[:])
		return zero, fmt.Errorf("formal-glm: sampler-v2 full root mismatch")
	}
	defer clear(maskRoot[:])
	admission := *runtime.Admission.Full
	binding := admission.formalBinding
	var guard formalGLMPhase16FullRangeGuardReceipt
	if role == "garbler" {
		guard, err = formalGLMPhase16RunFullRangeGuardGarbler(
			rw, admission, store.pins, session, runtime.Source.DPShares,
			binding.ShiftedUpperBounds, source.source.BindingSHA256, 0,
			maskRoot, signer)
	} else {
		guard, err = formalGLMPhase16RunFullRangeGuardEvaluator(
			rw, admission, store.pins, session, runtime.Source.DPShares,
			binding.ShiftedUpperBounds, source.source.BindingSHA256, 0,
			signer)
	}
	if err != nil {
		return zero, err
	}
	peerShare, err := jointDPBiomedicalGaussianRunFullPhase19PeerV2(
		admission, store.pins, source, runtime.Source.backend,
		authorityRoot, signer, encoded, contract)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase21FullLocalOutput{
		Version: formalGLMPhase21FullBoundReleaseVersion,
		Peer:    runtime.Source.Result.Peer, Role: role,
		HandoffSHA256: commit.SHA256, HandoffBytes: commit.Bytes,
		Productive: runtime.Admission.Productive,
		Admission:  admission, RangeGuard: guard, PeerShare: peerShare,
		capsule: capsule, request: request,
		fullRequest: fullRequest, attestation: attestation,
		sourceBindingSHA: source.source.BindingSHA256,
	}, nil
}

func formalGLMPhase21FullSourceMaterialWithPins(
	runtime formalGLMPhase20LocalRuntime,
	pins map[string]ed25519.PublicKey,
) (string, string, jointDPBiomedicalGaussianFullPhase19SourceBinding,
	exactGCSession, error) {
	var zero jointDPBiomedicalGaussianFullPhase19SourceBinding
	if runtime.Admission.Full == nil {
		return "", "", zero, exactGCSession{},
			fmt.Errorf("formal-glm: missing Phase-2.1 full admission")
	}
	admission := *runtime.Admission.Full
	binding := admission.formalBinding
	if binding == nil {
		return "", "", zero, exactGCSession{},
			fmt.Errorf("formal-glm: missing Phase-2.1 formal binding")
	}
	peer := runtime.Source.Result.Peer
	role := ""
	switch peer {
	case binding.GarblerPeerName:
		role = "garbler"
	case binding.EvaluatorPeerName:
		role = "evaluator"
	default:
		return "", "", zero, exactGCSession{},
			fmt.Errorf("formal-glm: Phase-2.1 full handoff peer has no range-guard role")
	}
	encoded, err := exactGCEncodeWorkerCanonicalShares(
		runtime.Source.DPShares, exactGCCircuitSpec{
			Operation: jointDPGaussianOneDrawOperation,
			RingBits:  128,
			FracBits:  0,
			VectorLen: binding.CoordinateCount,
		})
	if err != nil {
		return "", "", zero, exactGCSession{}, err
	}
	source, err := jointDPBiomedicalGaussianBindFullPhase19Source(
		admission, pins, runtime.Source.Result.PostExecutionToken,
		runtime.Source.backend, peer, 0, binding.CoordinateCount, encoded)
	if err != nil {
		return "", "", zero, exactGCSession{}, err
	}
	selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(
		*admission.formalSelection)
	if err != nil {
		return "", "", zero, exactGCSession{}, err
	}
	contractDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullSelectionDomain,
		admission.selection.Contract)
	if err != nil {
		return "", "", zero, exactGCSession{}, err
	}
	session, err := formalGLMPhase16FullRangeGuardSession(exactGCSession{
		MasterKey:   runtime.Source.backend,
		GarblerID:   binding.GarblerPeerID,
		EvaluatorID: binding.EvaluatorPeerID,
	}, selectionSHA256, hex.EncodeToString(contractDigest[:]), 0,
		binding.CoordinateCount)
	if err != nil {
		return "", "", zero, exactGCSession{}, err
	}
	return role, encoded, source, session, nil
}

func formalGLMPhase21ValidateFullLocalOutputSource(
	store *formalGLMPhase20HandoffStore,
	output formalGLMPhase21FullLocalOutput,
) error {
	if store == nil ||
		output.Version != formalGLMPhase21FullBoundReleaseVersion ||
		output.Peer != store.peer || output.HandoffBytes < 64 ||
		!formalGLMIsSHA256(output.HandoffSHA256) ||
		!formalGLMIsSHA256(output.sourceBindingSHA) {
		return fmt.Errorf("formal-glm: invalid Phase-2.1 full local output")
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmitFull(
		store, output.capsule, output.request,
		output.Productive.BackendSelection.Signatures,
		output.fullRequest, output.attestation)
	if err != nil {
		return err
	}
	defer runtime.clear()
	if commit.SHA256 != output.HandoffSHA256 ||
		commit.Bytes != output.HandoffBytes ||
		!reflect.DeepEqual(runtime.Admission.Productive, output.Productive) ||
		runtime.Admission.Full == nil ||
		!reflect.DeepEqual(*runtime.Admission.Full, output.Admission) {
		return fmt.Errorf("formal-glm: Phase-2.1 full output escaped its durable handoff")
	}
	role, _, source, _, err := formalGLMPhase21FullSourceMaterialWithPins(
		runtime, store.pins)
	if err != nil || role != output.Role ||
		source.source.BindingSHA256 != output.sourceBindingSHA {
		return fmt.Errorf("formal-glm: Phase-2.1 full source binding changed")
	}
	if output.PeerShare.PeerName != output.Peer ||
		output.PeerShare.source.SourceBindingSHA256 != output.sourceBindingSHA ||
		output.PeerShare.source.source.BindingSHA256 != output.sourceBindingSHA ||
		output.PeerShare.share.SourceBindingSHA256 != output.sourceBindingSHA {
		return fmt.Errorf("formal-glm: Phase-2.1 full peer output escaped its source binding")
	}
	if err := formalGLMPhase16ValidateFullRangeGuardReceipt(
		output.Admission, store.pins, output.RangeGuard,
		output.sourceBindingSHA, output.Role); err != nil {
		return err
	}
	return jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
		output.Admission, store.pins, output.PeerShare, store.backend)
}

func formalGLMPhase21PairFullOutputs(
	left, right formalGLMPhase21FullLocalOutput,
	pins map[string]ed25519.PublicKey,
	backend [32]byte,
) (formalGLMPhase16FullFallbackHandoff, error) {
	var zero formalGLMPhase16FullFallbackHandoff
	if left.Version != formalGLMPhase21FullBoundReleaseVersion ||
		right.Version != formalGLMPhase21FullBoundReleaseVersion ||
		left.Peer == right.Peer || left.Role == right.Role ||
		!reflect.DeepEqual(left.Productive, right.Productive) ||
		!reflect.DeepEqual(left.Admission, right.Admission) ||
		left.Admission.formalToken == nil ||
		left.Admission.formalBinding == nil {
		return zero, fmt.Errorf("formal-glm: incompatible Phase-2.1 full outputs")
	}
	for _, output := range []formalGLMPhase21FullLocalOutput{left, right} {
		if output.PeerShare.PeerName != output.Peer ||
			output.PeerShare.source.SourceBindingSHA256 !=
				output.sourceBindingSHA ||
			output.PeerShare.source.source.BindingSHA256 !=
				output.sourceBindingSHA ||
			output.PeerShare.share.SourceBindingSHA256 !=
				output.sourceBindingSHA {
			return zero, fmt.Errorf("formal-glm: mismatched Phase-2.1 full peer source")
		}
		if err := formalGLMPhase16ValidateFullRangeGuardReceipt(
			output.Admission, pins, output.RangeGuard,
			output.sourceBindingSHA, output.Role); err != nil {
			return zero, err
		}
		if err := jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
			output.Admission, pins, output.PeerShare, backend); err != nil {
			return zero, err
		}
	}
	full, err := jointDPBiomedicalGaussianBuildFullPhase19FinalizerHandoff(
		left.Admission, pins, *left.Admission.formalToken, backend,
		left.PeerShare, right.PeerShare)
	if err != nil {
		return zero, err
	}
	guards := map[string]formalGLMPhase16FullRangeGuardReceipt{
		left.Role:  left.RangeGuard,
		right.Role: right.RangeGuard,
	}
	garbler, garblerOK := guards["garbler"]
	evaluator, evaluatorOK := guards["evaluator"]
	if !garblerOK || !evaluatorOK || len(guards) != 2 {
		return zero, fmt.Errorf("formal-glm: incomplete Phase-2.1 full range guard")
	}
	return formalGLMPhase16BuildFullFallbackHandoff(
		left.Admission, pins, full, garbler, evaluator, backend)
}

func formalGLMPhase21FinalizeFullLocal(
	sourceStore *formalGLMPhase20HandoffStore,
	releaseStore *formalGLMPhase16FullDurableReleaseStore,
	local, other formalGLMPhase21FullLocalOutput,
	phaseHook func(string),
) (jointDPBiomedicalGaussianFullLocalRelease, error) {
	var zero jointDPBiomedicalGaussianFullLocalRelease
	if releaseStore == nil || releaseStore.peer != local.Peer {
		return zero, fmt.Errorf("formal-glm: misrouted Phase-2.1 full release store")
	}
	if err := formalGLMPhase21ValidateFullLocalOutputSource(
		sourceStore, local); err != nil {
		return zero, err
	}
	handoff, err := formalGLMPhase21PairFullOutputs(
		local, other, sourceStore.pins, sourceStore.backend)
	if err != nil {
		return zero, err
	}
	return releaseStore.FinalizeVector(
		local.Admission, sourceStore.pins,
		[]formalGLMPhase16FullFallbackHandoff{handoff},
		sourceStore.backend, phaseHook)
}

func formalGLMPhase21CertifyFullRelease(
	left, right jointDPBiomedicalGaussianFullLocalRelease,
	output formalGLMPhase21FullLocalOutput,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase16CertifiedRelease, error) {
	var zero formalGLMPhase16CertifiedRelease
	common, err := jointDPBiomedicalGaussianPairFullLocalReleases(
		output.Admission, pins, left.Receipt, right.Receipt)
	if err != nil {
		return zero, err
	}
	result, err := formalGLMPhase16CertifyFullRelease(
		output.Admission, pins, common)
	if err != nil {
		return zero, err
	}
	if output.Admission.formalBinding == nil ||
		output.Admission.formalToken == nil {
		return zero, fmt.Errorf("formal-glm: missing Phase-2.1 full certificate authority")
	}
	if err := formalGLMPhase16ValidateCertifiedRelease(
		result, *output.Admission.formalBinding,
		*output.Admission.formalToken, pins); err != nil {
		return zero, err
	}
	return result, nil
}

func formalGLMPhase21CleanupFullReleasedSource(
	store *formalGLMPhase20HandoffStore,
	output formalGLMPhase21FullLocalOutput,
	release formalGLMPhase16CertifiedRelease,
) (int64, error) {
	if err := formalGLMPhase21ValidateFullLocalOutputSource(
		store, output); err != nil {
		return 0, err
	}
	if output.Admission.formalBinding == nil ||
		output.Admission.formalToken == nil {
		return 0, fmt.Errorf("formal-glm: missing Phase-2.1 full cleanup authority")
	}
	if err := formalGLMPhase16ValidateCertifiedRelease(
		release, *output.Admission.formalBinding,
		*output.Admission.formalToken, store.pins); err != nil {
		return 0, err
	}
	contract := output.Admission.selection.Contract
	if release.OneDraw != nil || release.IndependentFull == nil ||
		release.DPReleaseInstanceID != contract.ReleaseInstanceID ||
		release.ReleaseContractSHA256 != contract.ReleaseContractSHA256 {
		return 0, fmt.Errorf("formal-glm: release does not authorize Phase-2.1 full cleanup")
	}
	return store.Consume(output.HandoffSHA256)
}
