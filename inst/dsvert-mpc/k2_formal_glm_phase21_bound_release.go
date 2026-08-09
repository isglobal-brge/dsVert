package main

// Phase-2.1 closes the server-local source-substitution gap between the
// durable Phase-2.0 handoff and the existing one-draw release worker.  The
// caller supplies the already K-signed contracts, but never supplies a source
// share or its local binding: both are derived from the authenticated handoff
// slot immediately before GC execution.  This remains an internal boundary;
// it adds no command, capability, R export, or DataSHIELD method.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"reflect"
)

const formalGLMPhase21BoundReleaseVersion = "dsvert-formal-glm-phase21-source-bound-release-v1"

// formalGLMPhase21OneDrawLocalOutput is process-local.  Shares and the local
// source-binding digest are deliberately excluded from JSON by having no JSON
// surface at all; only the signed chunk receipt is suitable for peer handoff.
type formalGLMPhase21OneDrawLocalOutput struct {
	Version          string                                       `json:"-"`
	Peer             string                                       `json:"-"`
	Role             string                                       `json:"-"`
	HandoffSHA256    string                                       `json:"-"`
	HandoffBytes     int64                                        `json:"-"`
	Admission        formalGLMPhase16ProductiveAdmission          `json:"-"`
	Receipt          jointDPBiomedicalGaussianOneDrawChunkReceipt `json:"-"`
	Shares           []*big.Int                                   `json:"-"`
	capsule          formalGLMPhase16CapsuleBinding
	request          formalGLMPhase16ProductiveRequest
	sourceBindingSHA string
}

func (output *formalGLMPhase21OneDrawLocalOutput) clear() {
	if output == nil {
		return
	}
	exactGCZeroBigInts(output.Shares)
	*output = formalGLMPhase21OneDrawLocalOutput{}
}

// formalGLMPhase21LoadAndAdmit performs both Phase-2.0 rounds from one
// authenticated slot.  Keeping this operation here prevents an integration
// caller from replacing runtime.Source after admission but before execution.
func formalGLMPhase21LoadAndAdmit(
	store *formalGLMPhase20HandoffStore,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
) (formalGLMPhase20LocalRuntime, formalGLMPhase20HandoffCommit, error) {
	var zero formalGLMPhase20LocalRuntime
	if store == nil {
		return zero, formalGLMPhase20HandoffCommit{},
			fmt.Errorf("formal-glm: missing Phase-2.1 source handoff")
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
		runtime, backendSignatures, workerSignatures, nil, nil, store.pins)
	if err != nil {
		source.clear()
		return zero, formalGLMPhase20HandoffCommit{}, err
	}
	if runtime.Admission.Full != nil ||
		runtime.Admission.Productive.BackendSelection.Contract.SelectedBackend !=
			formalGLMPhase16BackendOneDraw {
		runtime.clear()
		return zero, formalGLMPhase20HandoffCommit{},
			fmt.Errorf("formal-glm: Phase-2.1 increment admits only signed one-draw releases")
	}
	return runtime, commit, nil
}

func formalGLMPhase21SourceMaterial(
	runtime formalGLMPhase20LocalRuntime,
) (jointDPGaussianOneDrawSpec, exactGCSession, string, string,
	jointDPBiomedicalGaussianLocalSourceBinding, error) {
	var zeroSpec jointDPGaussianOneDrawSpec
	var zeroBinding jointDPBiomedicalGaussianLocalSourceBinding
	admission := runtime.Admission.Productive
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		admission.Envelope, admission.Trust)
	if err != nil {
		return zeroSpec, exactGCSession{}, "", "", zeroBinding, err
	}
	runNonceBytes, err := hex.DecodeString(admission.Envelope.Preimage.RunNonceSHA256)
	if err != nil || len(runNonceBytes) != 32 ||
		hex.EncodeToString(runNonceBytes) !=
			admission.Envelope.Preimage.RunNonceSHA256 {
		clear(runNonceBytes)
		return zeroSpec, exactGCSession{}, "", "", zeroBinding,
			fmt.Errorf("formal-glm: invalid Phase-2.1 run nonce")
	}
	var runNonce [32]byte
	copy(runNonce[:], runNonceBytes)
	clear(runNonceBytes)
	session := exactGCSession{
		SessionID:   runNonce,
		MasterKey:   runtime.Source.backend,
		GarblerID:   spec.GarblerPeerID,
		EvaluatorID: spec.EvaluatorPeerID,
		Purpose:     spec.purpose(),
		Spec: exactGCCircuitSpec{
			Operation: jointDPGaussianOneDrawOperation,
			RingBits:  128,
			FracBits:  0,
			VectorLen: spec.CoordinateCount,
		},
	}
	role := ""
	switch runtime.Source.Result.Peer {
	case admission.Envelope.Preimage.GarblerPeerName:
		role = "garbler"
	case admission.Envelope.Preimage.EvaluatorPeerName:
		role = "evaluator"
	default:
		return zeroSpec, exactGCSession{}, "", "", zeroBinding,
			fmt.Errorf("formal-glm: Phase-2.1 handoff peer has no worker role")
	}
	encoded, err := exactGCEncodeWorkerCanonicalShares(
		runtime.Source.DPShares, session.Spec)
	if err != nil {
		return zeroSpec, exactGCSession{}, "", "", zeroBinding, err
	}
	binding, err := jointDPBiomedicalGaussianBuildLocalSourceBinding(
		admission.Envelope.Preimage,
		admission.Compiled.Binding.SnapshotSHA256,
		admission.Compiled.Binding.SourceFanInTranscriptSHA256,
		runtime.Source.Result.Peer, role, encoded)
	if err != nil {
		return zeroSpec, exactGCSession{}, "", "", zeroBinding, err
	}
	return spec, session, role, encoded, binding, nil
}

// formalGLMPhase21RunOneDrawLocal is the first execution-shaped boundary that
// accepts no source-share argument.  The private seed is still supplied by
// the server-local secret store and is verified against the K-signed
// commitment before the worker can use it.
func formalGLMPhase21RunOneDrawLocal(
	rw io.ReadWriter,
	store *formalGLMPhase20HandoffStore,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	privateSeed [32]byte,
	signer ed25519.PrivateKey,
) (formalGLMPhase21OneDrawLocalOutput, error) {
	var zero formalGLMPhase21OneDrawLocalOutput
	if rw == nil {
		return zero, fmt.Errorf("formal-glm: nil Phase-2.1 peer channel")
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmit(
		store, capsule, request, backendSignatures, workerSignatures)
	if err != nil {
		return zero, err
	}
	defer runtime.clear()
	_, session, role, encoded, binding, err :=
		formalGLMPhase21SourceMaterial(runtime)
	if err != nil {
		return zero, err
	}
	seed := base64.StdEncoding.EncodeToString(privateSeed[:])
	var shares []*big.Int
	if role == "garbler" {
		shares, err = jointDPBiomedicalGaussianRunProductiveGarbler(
			rw, runtime.Admission.Productive.Envelope,
			runtime.Admission.Productive.Trust, binding, session, encoded, seed)
	} else {
		shares, err = jointDPBiomedicalGaussianRunProductiveEvaluator(
			rw, runtime.Admission.Productive.Envelope,
			runtime.Admission.Productive.Trust, binding, session, encoded, seed)
	}
	if err != nil {
		exactGCZeroBigInts(shares)
		return zero, err
	}
	receipt, err := jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
		runtime.Admission.Productive.Envelope,
		runtime.Admission.Productive.Trust, role, shares, signer)
	if err != nil {
		exactGCZeroBigInts(shares)
		return zero, err
	}
	return formalGLMPhase21OneDrawLocalOutput{
		Version:          formalGLMPhase21BoundReleaseVersion,
		Peer:             runtime.Source.Result.Peer,
		Role:             role,
		HandoffSHA256:    commit.SHA256,
		HandoffBytes:     commit.Bytes,
		Admission:        runtime.Admission.Productive,
		Receipt:          receipt,
		Shares:           shares,
		capsule:          capsule,
		request:          request,
		sourceBindingSHA: binding.BindingSHA256,
	}, nil
}

func formalGLMPhase21ValidateLocalOutputSource(
	store *formalGLMPhase20HandoffStore,
	output formalGLMPhase21OneDrawLocalOutput,
) error {
	if store == nil || output.Version != formalGLMPhase21BoundReleaseVersion ||
		output.Peer != store.peer || output.HandoffBytes < 64 ||
		!formalGLMIsSHA256(output.HandoffSHA256) ||
		!formalGLMIsSHA256(output.sourceBindingSHA) {
		return fmt.Errorf("formal-glm: invalid Phase-2.1 local output")
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmit(
		store, output.capsule, output.request,
		output.Admission.BackendSelection.Signatures,
		output.Admission.Envelope.Signatures)
	if err != nil {
		return err
	}
	defer runtime.clear()
	if commit.SHA256 != output.HandoffSHA256 ||
		commit.Bytes != output.HandoffBytes ||
		!reflect.DeepEqual(runtime.Admission.Productive, output.Admission) {
		return fmt.Errorf("formal-glm: Phase-2.1 output escaped its durable handoff")
	}
	_, _, role, _, binding, err := formalGLMPhase21SourceMaterial(runtime)
	if err != nil || role != output.Role ||
		binding.BindingSHA256 != output.sourceBindingSHA {
		return fmt.Errorf("formal-glm: Phase-2.1 local source binding changed")
	}
	payload, _, err := jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
		output.Admission.Envelope, output.Admission.Trust,
		output.Receipt, output.Role, output.Shares)
	clear(payload)
	return err
}

func formalGLMPhase21PairOneDrawOutputs(
	left, right formalGLMPhase21OneDrawLocalOutput,
) (jointDPBiomedicalGaussianOneDrawChunkHandoff, error) {
	var zero jointDPBiomedicalGaussianOneDrawChunkHandoff
	if left.Version != formalGLMPhase21BoundReleaseVersion ||
		right.Version != formalGLMPhase21BoundReleaseVersion ||
		left.Peer == right.Peer || left.Role == right.Role ||
		!reflect.DeepEqual(left.Admission, right.Admission) {
		return zero, fmt.Errorf("formal-glm: incompatible Phase-2.1 local outputs")
	}
	leftPayload, _, err := jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
		left.Admission.Envelope, left.Admission.Trust,
		left.Receipt, left.Role, left.Shares)
	clear(leftPayload)
	if err != nil {
		return zero, err
	}
	rightPayload, _, err := jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
		right.Admission.Envelope, right.Admission.Trust,
		right.Receipt, right.Role, right.Shares)
	clear(rightPayload)
	if err != nil {
		return zero, err
	}
	handoff := jointDPBiomedicalGaussianOneDrawChunkHandoff{
		Envelope: left.Admission.Envelope,
	}
	for _, output := range []formalGLMPhase21OneDrawLocalOutput{left, right} {
		if output.Role == "garbler" {
			handoff.Garbler = output.Receipt
			handoff.GarblerShares = output.Shares
		} else {
			handoff.Evaluator = output.Receipt
			handoff.EvaluatorShares = output.Shares
		}
	}
	return handoff, nil
}

// FinalizeOneDrawLocal durably records either a release or an invalid-source
// no-release in the existing reviewed store.  It intentionally does not
// delete the Phase-2.0 source; cleanup is authorized only after the common
// signed release has been certified below.
func formalGLMPhase21FinalizeOneDrawLocal(
	sourceStore *formalGLMPhase20HandoffStore,
	releaseStore *jointDPBiomedicalGaussianOneDrawDurableReleaseStore,
	local, other formalGLMPhase21OneDrawLocalOutput,
	phaseHook func(string),
) (jointDPBiomedicalGaussianOneDrawLocalRelease, error) {
	var zero jointDPBiomedicalGaussianOneDrawLocalRelease
	if releaseStore == nil || releaseStore.peer != local.Peer {
		return zero, fmt.Errorf("formal-glm: misrouted Phase-2.1 release store")
	}
	if err := formalGLMPhase21ValidateLocalOutputSource(
		sourceStore, local); err != nil {
		return zero, err
	}
	handoff, err := formalGLMPhase21PairOneDrawOutputs(local, other)
	if err != nil {
		return zero, err
	}
	return releaseStore.FinalizeVector(
		[]jointDPBiomedicalGaussianOneDrawChunkHandoff{handoff},
		local.Admission.Trust, phaseHook)
}

func formalGLMPhase21CertifyOneDrawRelease(
	left, right jointDPBiomedicalGaussianOneDrawLocalRelease,
	admission formalGLMPhase16ProductiveAdmission,
) (formalGLMPhase16CertifiedRelease, error) {
	var zero formalGLMPhase16CertifiedRelease
	preimage := admission.Envelope.Preimage
	receipts := map[string]jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt{
		left.Receipt.PeerName:  left.Receipt,
		right.Receipt.PeerName: right.Receipt,
	}
	garbler, garblerOK := receipts[preimage.GarblerPeerName]
	evaluator, evaluatorOK := receipts[preimage.EvaluatorPeerName]
	if !garblerOK || !evaluatorOK || len(receipts) != 2 {
		return zero, fmt.Errorf("formal-glm: incomplete Phase-2.1 local release pair")
	}
	common, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{admission.Envelope},
		admission.Trust, evaluator, garbler)
	if err != nil {
		return zero, err
	}
	result, err := formalGLMPhase16CertifyOneDrawRelease(admission, common)
	if err != nil {
		return zero, err
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(admission.Trust)
	if err != nil {
		return zero, err
	}
	if err := formalGLMPhase16ValidateCertifiedRelease(
		result, admission.Compiled.Binding, admission.Token, pins); err != nil {
		return zero, err
	}
	return result, nil
}

// CleanupReleasedSource accepts only a fully validated, two-peer signed
// common release for the same Phase-1.9 token and release binding.  A wrong or
// tampered certificate cannot remove the sealed source slot.
func formalGLMPhase21CleanupReleasedSource(
	store *formalGLMPhase20HandoffStore,
	output formalGLMPhase21OneDrawLocalOutput,
	release formalGLMPhase16CertifiedRelease,
) (int64, error) {
	if err := formalGLMPhase21ValidateLocalOutputSource(store, output); err != nil {
		return 0, err
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(output.Admission.Trust)
	if err != nil {
		return 0, err
	}
	if err := formalGLMPhase16ValidateCertifiedRelease(
		release, output.Admission.Compiled.Binding,
		output.Admission.Token, pins); err != nil {
		return 0, err
	}
	if release.OneDraw == nil || release.IndependentFull != nil ||
		release.DPReleaseInstanceID !=
			output.Admission.Envelope.Preimage.ReleaseInstanceID ||
		release.ReleaseContractSHA256 !=
			output.Admission.Envelope.Preimage.ReleaseContractSHA256 {
		return 0, fmt.Errorf("formal-glm: release does not authorize Phase-2.1 cleanup")
	}
	return store.Consume(output.HandoffSHA256)
}
