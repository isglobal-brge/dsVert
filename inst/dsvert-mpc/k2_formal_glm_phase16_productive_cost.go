package main

// Public-shape cost certificate for the currently implemented formal GLM
// route.  It deliberately separates measured/compiler-derived quantities from
// unverified end-to-end transport claims.  A future mixed arithmetic/Boolean
// kernel can replace the versioned execution-kernel id without changing the
// signed estimand, DP release, or coefficient order.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	formalGLMPhase16ProductiveCostVersion = "dsvert-formal-glm-phase16-public-cost-v1"
	formalGLMPhase16CurrentKernel         = "pure_boolean_exact_gc_fixed_schedule_v1"
)

type formalGLMPhase16ProductiveCost struct {
	Version                      string `json:"version"`
	Phase15PlanSHA256            string `json:"phase15_plan_sha256"`
	BackendSelectionSHA256       string `json:"backend_selection_sha256"`
	Family                       string `json:"family"`
	CustodianCount               int    `json:"custodian_count"`
	DesignatedComputePeerCount   int    `json:"designated_compute_peer_count"`
	TotalCapacity                int    `json:"total_capacity"`
	BlockCapacity                int    `json:"block_capacity"`
	TotalBlocks                  int    `json:"total_blocks"`
	Iterations                   int    `json:"iterations"`
	FixedScheduleSteps           int    `json:"fixed_schedule_steps"`
	BlockCircuitEvaluations      int    `json:"block_circuit_evaluations"`
	FinalizeCircuitEvaluations   int    `json:"finalize_circuit_evaluations"`
	BlockGates                   int    `json:"block_gates"`
	BlockNonXORGates             uint64 `json:"block_non_xor_gates"`
	BlockEstimatedWorkingBytes   uint64 `json:"block_estimated_working_bytes"`
	FinalizeGates                int    `json:"finalize_gates"`
	FinalizeNonXORGates          uint64 `json:"finalize_non_xor_gates"`
	FinalizeEstimatedWorkingByte uint64 `json:"finalize_estimated_working_bytes"`
	SelectedDPBackend            string `json:"selected_dp_backend"`
	DPMaximumChunkCoordinates    int    `json:"dp_maximum_chunk_coordinates"`
	DPProjectedGatesPerChunk     int64  `json:"dp_projected_gates_per_chunk"`
	DPProjectedNonXORPerChunk    int64  `json:"dp_projected_non_xor_gates_per_chunk"`
	DPProjectedGarbledBytes      int64  `json:"dp_projected_garbled_bytes_per_chunk"`
	RangeGuardTotalCoordinates   int    `json:"range_guard_total_coordinates"`
	RangeGuardChunkCoordinates   int    `json:"range_guard_maximum_chunk_coordinates"`
	RangeGuardCircuitCount       int    `json:"range_guard_circuit_count"`
	RangeGuardGates              int    `json:"range_guard_gates"`
	RangeGuardNonXORGates        uint64 `json:"range_guard_non_xor_gates"`
	RangeGuardWorkingBytes       uint64 `json:"range_guard_estimated_working_bytes"`
	ExecutionKernel              string `json:"execution_kernel"`
	KernelReplacementBoundary    string `json:"kernel_replacement_boundary"`
	KernelReplacementEstimand    string `json:"kernel_replacement_estimand"`
	AsymptoticRowScaling         string `json:"asymptotic_row_scaling"`
	EndToEndDSIBenchmarked       bool   `json:"end_to_end_dsi_benchmarked"`
	LogicalTranscriptFixedShape  bool   `json:"logical_transcript_fixed_shape"`
	PhysicalTimingDPCertified    bool   `json:"physical_timing_dp_certified"`
	ProductionReady              bool   `json:"production_ready"`
	Blocker                      string `json:"blocker"`
}

func formalGLMPhase16BuildProductiveCost(plan formalGLMPhase15Plan,
	binding formalGLMPhase16ReleaseBinding,
	token formalGLMPhase19PostExecutionToken,
	selection formalGLMPhase16BackendSelectionAttestation,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase16ProductiveCost, error) {
	var zero formalGLMPhase16ProductiveCost
	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		return zero, err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil || binding.Phase15PlanSHA256 != hex.EncodeToString(planDigest[:]) {
		return zero, fmt.Errorf("formal-glm: public cost plan/binding mismatch")
	}
	plans, err := formalGLMPhase16ValidateBackendSelection(
		selection, binding, token, pins)
	if err != nil {
		return zero, err
	}
	selectionDigest, err := formalGLMPhase16BackendSelectionSHA256(selection)
	if err != nil {
		return zero, err
	}
	contract := selection.Contract
	result := formalGLMPhase16ProductiveCost{
		Version:                      formalGLMPhase16ProductiveCostVersion,
		Phase15PlanSHA256:            binding.Phase15PlanSHA256,
		BackendSelectionSHA256:       selectionDigest,
		Family:                       binding.Family,
		CustodianCount:               binding.CustodianCount,
		DesignatedComputePeerCount:   len(contract.DesignatedComputePeers),
		TotalCapacity:                plan.TotalCapacity,
		BlockCapacity:                plan.BlockCapacity,
		TotalBlocks:                  plan.TotalBlocks,
		Iterations:                   plan.Iterations,
		FixedScheduleSteps:           plan.ScheduleSteps,
		BlockCircuitEvaluations:      plan.Iterations * plan.TotalBlocks,
		FinalizeCircuitEvaluations:   plan.Iterations,
		BlockGates:                   plan.BlockCost.Gates,
		BlockNonXORGates:             plan.BlockCost.NonXORGates,
		BlockEstimatedWorkingBytes:   plan.BlockCost.EstimatedWorkingByte,
		FinalizeGates:                plan.FinalizeCost.Gates,
		FinalizeNonXORGates:          plan.FinalizeCost.NonXORGates,
		FinalizeEstimatedWorkingByte: plan.FinalizeCost.EstimatedWorkingByte,
		SelectedDPBackend:            contract.SelectedBackend,
		ExecutionKernel:              formalGLMPhase16CurrentKernel,
		KernelReplacementBoundary:    "phase15_iteration_kernel_behind_unchanged_signed_plan_and_phase16_release_v1",
		KernelReplacementEstimand:    "must_preserve_exact_fixed_point_recurrence_rounding_schedule_and_coefficient_order_v1",
		AsymptoticRowScaling:         "fixed_iterations_times_ceil(total_capacity/block_capacity)_exact_gc_blocks_v1",
		EndToEndDSIBenchmarked:       false,
		LogicalTranscriptFixedShape:  contract.SelectedLogicalTranscriptFixed,
		PhysicalTimingDPCertified:    contract.SelectedPhysicalTimingDPClaim,
		ProductionReady:              false,
		Blocker:                      "mixed_arithmetic_boolean_kernel_and_real_multi_process_dsi_benchmark_pending_v1",
	}
	if contract.SelectedBackend == formalGLMPhase16BackendOneDraw {
		result.DPMaximumChunkCoordinates = plans.OneDraw.MaximumChunkCoordinates
		result.DPProjectedGatesPerChunk = plans.OneDraw.ProjectedGateCountUpper
		result.DPProjectedNonXORPerChunk = plans.OneDraw.ProjectedNonXORGateCountUpper
		result.DPProjectedGarbledBytes = plans.OneDraw.ProjectedGarbledTableBytesUpper
		return result, nil
	}
	if contract.SelectedBackend != formalGLMPhase16BackendFull {
		return zero, fmt.Errorf("formal-glm: unknown selected DP backend")
	}
	result.DPMaximumChunkCoordinates = plans.Full.MaximumChunkCoordinates
	result.RangeGuardTotalCoordinates = binding.CoordinateCount
	result.RangeGuardChunkCoordinates = binding.CoordinateCount
	if result.RangeGuardChunkCoordinates >
		formalGLMPhase16FullRangeGuardMaxCoordinates {
		result.RangeGuardChunkCoordinates =
			formalGLMPhase16FullRangeGuardMaxCoordinates
	}
	result.RangeGuardCircuitCount = (binding.CoordinateCount +
		result.RangeGuardChunkCoordinates - 1) /
		result.RangeGuardChunkCoordinates
	spec := exactGCCircuitSpec{
		Operation: exactGCCountGuard, RingBits: 128, FracBits: 0,
		Threshold: big.NewInt(1),
		VectorLen: 2 * result.RangeGuardChunkCoordinates,
	}
	circ, err := exactGCCompileCircuit(spec)
	if err != nil {
		return zero, err
	}
	guard, err := formalGLMPhase15CircuitCostOf(
		exactGCCircuitSource(spec), circ)
	if err != nil {
		return zero, err
	}
	result.RangeGuardGates = guard.Gates
	result.RangeGuardNonXORGates = guard.NonXORGates
	result.RangeGuardWorkingBytes = guard.EstimatedWorkingByte
	return result, nil
}
