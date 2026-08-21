package main

// Authenticated final barrier between the completed registered computation and
// Phase20 terminal sealing.  It carries only commitments already common to the
// two compute peers: never a DP share, prepared evidence, path, or key.

import (
	"crypto/ed25519"
	"fmt"
	"io"
)

const (
	formalGLMRegisteredPhase20ComputeReadyVersionV1 = "dsvert-formal-glm-registered-phase20-compute-ready-v1"
	formalGLMRegisteredPhase20ComputeReadyPurposeV1 = "formal_glm_registered_phase20_authenticated_compute_barrier_v1"
	formalGLMRegisteredPhase20ComputeReadyLabelV1   = "registered-phase20/compute-ready"
)

type formalGLMRegisteredPhase20ComputeReadyV1 struct {
	Version                    string `json:"version"`
	Purpose                    string `json:"purpose"`
	AttemptID                  string `json:"attempt_id"`
	ClaimAcceptSHA256          string `json:"claim_accept_sha256"`
	Peer                       string `json:"peer"`
	Role                       string `json:"role"`
	PostExecutionRootSHA256    string `json:"post_execution_root_sha256"`
	ExecutionReceiptPairSHA256 string `json:"execution_receipt_pair_sha256"`
	FinalReceiptSetSeal        string `json:"final_receipt_set_seal"`
	OpeningsPerformed          int    `json:"openings_performed"`
	ProductionReady            bool   `json:"production_ready"`
}

func formalGLMRegisteredPhase20BuildComputeReadyV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
) (formalGLMRegisteredPhase20ComputeReadyV1, error) {
	var zero formalGLMRegisteredPhase20ComputeReadyV1
	if runtime == nil || evidence.Attempt != accept.Binding {
		return zero, fmt.Errorf("formal-glm registered Phase20 compute-ready: invalid attempt")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.validateLocked(); err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase20ValidatePreparedIdentityLockedV1(
		runtime, record, contract, accept.Binding, evidence, pins); err != nil {
		return zero, err
	}
	role, err := formalGLMRegisteredPhase19AccumulatorRoleV1(
		runtime.context, evidence.Peer)
	if err != nil {
		return zero, err
	}
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase20ComputeReadyV1{
		Version:                    formalGLMRegisteredPhase20ComputeReadyVersionV1,
		Purpose:                    formalGLMRegisteredPhase20ComputeReadyPurposeV1,
		AttemptID:                  accept.Binding.AttemptID,
		ClaimAcceptSHA256:          acceptSHA256,
		Peer:                       evidence.Peer,
		Role:                       role,
		PostExecutionRootSHA256:    evidence.PostEvidence.PostExecutionRootSHA256,
		ExecutionReceiptPairSHA256: evidence.ExecutionPair.ExecutionReceiptPairSHA256,
		FinalReceiptSetSeal:        evidence.PostEvidence.FinalReceiptSetSeal,
		OpeningsPerformed:          0,
		ProductionReady:            false,
	}, nil
}

func formalGLMRegisteredPhase20ValidateComputeReadyPairV1(
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
	local, remote formalGLMRegisteredPhase20ComputeReadyV1,
) error {
	want, err := formalGLMRegisteredPhase20BuildComputeReadyV1(
		runtime, record, contract, pins, accept, evidence)
	if err != nil {
		return err
	}
	if local != want {
		return fmt.Errorf("formal-glm registered Phase20 compute-ready: local receipt mismatch")
	}
	if remote.Version != want.Version || remote.Purpose != want.Purpose ||
		remote.AttemptID != want.AttemptID ||
		remote.ClaimAcceptSHA256 != want.ClaimAcceptSHA256 ||
		remote.PostExecutionRootSHA256 != want.PostExecutionRootSHA256 ||
		remote.ExecutionReceiptPairSHA256 != want.ExecutionReceiptPairSHA256 ||
		remote.FinalReceiptSetSeal != want.FinalReceiptSetSeal ||
		remote.OpeningsPerformed != 0 || remote.ProductionReady ||
		remote.Peer == want.Peer {
		return fmt.Errorf("formal-glm registered Phase20 compute-ready: remote receipt mismatch")
	}
	runtime.mu.Lock()
	context := formalGLMRegisteredPhase19CloneContextV1(runtime.context)
	runtime.mu.Unlock()
	remoteRole, err := formalGLMRegisteredPhase19AccumulatorRoleV1(context, remote.Peer)
	if err != nil || remote.Role != remoteRole || remoteRole == want.Role {
		return fmt.Errorf("formal-glm registered Phase20 compute-ready: remote role mismatch")
	}
	return nil
}

func formalGLMRegisteredPhase20ExchangeComputeReadyV1(
	rw io.ReadWriter,
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
) error {
	if rw == nil || runtime == nil {
		return fmt.Errorf("formal-glm registered Phase20 compute-ready: nil peer channel")
	}
	local, err := formalGLMRegisteredPhase20BuildComputeReadyV1(
		runtime, record, contract, pins, accept, evidence)
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	if err := runtime.validateLocked(); err != nil {
		runtime.mu.Unlock()
		return err
	}
	plan := formalGLMRegisteredPhase19ClonePlanV1(runtime.legacyPlan)
	context := formalGLMRegisteredPhase19CloneContextV1(runtime.context)
	backend := runtime.backendKey
	runtime.mu.Unlock()
	defer clear(backend[:])
	root, err := formalGLMPhase19ScheduleDecodeHex32(
		accept.Binding.ScheduleRootSHA256, "root")
	if err != nil {
		return err
	}
	defer clear(root[:])
	var remote formalGLMRegisteredPhase20ComputeReadyV1
	if err := formalGLMPhase19RuntimeExchangeJSON(
		rw, plan, context, backend, root, local.Role,
		formalGLMRegisteredPhase20ComputeReadyLabelV1, 0, local, &remote); err != nil {
		return err
	}
	return formalGLMRegisteredPhase20ValidateComputeReadyPairV1(
		runtime, record, contract, pins, accept, evidence, local, remote)
}
