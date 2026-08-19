package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
)

const (
	formalGLMRegisteredExecutionPlanVersion = "dsvert-formal-glm-registered-execution-plan-v1"
	formalGLMRegisteredExecutionPlanPurpose = "formal_glm_registered_capsule_free_phase18_phase20_execution_v1"
	formalGLMRegisteredExecutionPlanDomain  = "dsVert/formal-glm/registered-execution-plan/v1"
	formalGLMRegisteredExecutionPlanMaxJSON = 8 << 20
)

type formalGLMRegisteredExecutionAuthorityV1 struct {
	Role     string `json:"role"`
	PeerName string `json:"peer_name"`
	PeerID   string `json:"peer_id"`
}

type formalGLMRegisteredExecutionCircuitCostV1 struct {
	CircuitSourceSHA256  string `json:"circuit_source_sha256"`
	Gates                int    `json:"gates"`
	Wires                int    `json:"wires"`
	XORGates             uint64 `json:"xor_gates"`
	NonXORGates          uint64 `json:"non_xor_gates"`
	CompilerRelativeCost uint64 `json:"compiler_relative_cost"`
	GarblerInputBits     int    `json:"garbler_input_bits"`
	EvaluatorInputBits   int    `json:"evaluator_input_bits"`
	OutputBits           int    `json:"output_bits"`
	EstimatedWorkingByte uint64 `json:"estimated_working_bytes"`
}

type formalGLMRegisteredExecutionKernelV1 struct {
	Version          string `json:"version"`
	CompilerSHA256   string `json:"compiler_sha256"`
	TheoremSHA256    string `json:"theorem_sha256"`
	Adjacency        string `json:"adjacency"`
	Capacity         int    `json:"capacity"`
	CoefficientCount int    `json:"coefficient_count"`
	Iterations       int    `json:"iterations"`
	FractionBits     int    `json:"fraction_bits"`

	XKind           []string `json:"x_kind"`
	XLower          []string `json:"x_lower"`
	XUpper          []string `json:"x_upper"`
	WeightUpper     string   `json:"weight_upper"`
	OutcomeUpper    string   `json:"outcome_upper"`
	OffsetLower     string   `json:"offset_lower"`
	OffsetUpper     string   `json:"offset_upper"`
	BetaStart       []string `json:"beta_start"`
	Ridge           []string `json:"ridge"`
	CoefficientBox  []string `json:"coefficient_box"`
	Alpha           string   `json:"alpha"`
	LinkKnots       []string `json:"link_knots"`
	LinkValues      []string `json:"link_values"`
	LinkSlopes      []string `json:"link_slopes"`
	LinkErrorUpper  string   `json:"link_error_upper"`
	LinkTableSHA256 string   `json:"link_table_sha256"`

	Missingness     string `json:"missingness"`
	PatientCollapse string `json:"patient_collapse"`
	ReductionOrder  string `json:"reduction_order"`
	Truncation      string `json:"truncation"`
	InputLayout     string `json:"input_layout"`
	InputSharing    string `json:"input_sharing"`
	Output          string `json:"output"`
}

type formalGLMRegisteredExecutionPlanV1 struct {
	Version    string `json:"version"`
	Purpose    string `json:"purpose"`
	PlanSHA256 string `json:"plan_sha256"`

	ArtifactID                     string                            `json:"artifact_id"`
	Artifact                       formalGLMPhase21StickyArtifact    `json:"sticky_artifact"`
	DescriptorCore                 formalGLMPublicDescriptorCoreV1   `json:"descriptor_core"`
	DescriptorCoreSHA256           string                            `json:"descriptor_core_sha256"`
	CanonicalScienceSHA256         string                            `json:"canonical_science_sha256"`
	CanonicalPlanSHA256            string                            `json:"canonical_plan_sha256"`
	CanonicalDP                    formalGLMCanonicalPreSourceDPV1   `json:"canonical_dp"`
	CanonicalPreSourceDPSHA256     string                            `json:"canonical_pre_source_dp_sha256"`
	ProjectedSchemaSHA256          string                            `json:"projected_schema_sha256"`
	SnapshotSHA256                 string                            `json:"snapshot_sha256"`
	PinsetSHA256                   string                            `json:"pinset_sha256"`
	BoundsSHA256                   string                            `json:"bounds_sha256"`
	QuantizationSHA256             string                            `json:"quantization_sha256"`
	TransportCoordinateOrderSHA256 string                            `json:"transport_coordinate_order_sha256"`
	CanonicalLinkSHA256            string                            `json:"canonical_link_sha256"`
	SamplerMode                    string                            `json:"sampler_mode"`
	SamplerV2ContractCoreSHA256    string                            `json:"sampler_v2_contract_core_sha256"`
	TranscriptBoundSHA256          string                            `json:"transcript_bound_sha256"`
	WireABISHA256                  string                            `json:"wire_abi_sha256"`
	TranscriptBound                formalGLMPhase19TranscriptBoundV1 `json:"transcript_bound"`

	SourcePlanVersion      string                                    `json:"source_plan_version"`
	Family                 string                                    `json:"family"`
	ExecutionKernel        formalGLMRegisteredExecutionKernelV1      `json:"execution_kernel"`
	TotalCapacity          int                                       `json:"total_capacity"`
	BlockCapacity          int                                       `json:"block_capacity"`
	TotalBlocks            int                                       `json:"total_blocks"`
	Iterations             int                                       `json:"iterations"`
	ScheduleSteps          int                                       `json:"schedule_steps"`
	CustodianPeers         []string                                  `json:"custodian_peers"`
	CustodianCount         int                                       `json:"custodian_count"`
	DesignatedComputePeers []string                                  `json:"designated_compute_peers"`
	NoiseAuthorities       []formalGLMRegisteredExecutionAuthorityV1 `json:"noise_authorities"`
	CoordinateOwners       []string                                  `json:"coordinate_owners"`
	RingBits               int                                       `json:"ring_bits"`
	ContainerBits          int                                       `json:"container_bits"`
	MaximumMagnitude       string                                    `json:"maximum_magnitude"`
	RhoTotalUpper          string                                    `json:"rho_total_upper"`
	BlockCost              formalGLMRegisteredExecutionCircuitCostV1 `json:"block_cost"`
	FinalizeCost           formalGLMRegisteredExecutionCircuitCostV1 `json:"finalize_cost"`
	BackendSelection       string                                    `json:"backend_selection"`
	TranscriptShape        string                                    `json:"transcript_shape"`
	CrashRecovery          string                                    `json:"crash_recovery"`
	Output                 string                                    `json:"output"`
	ProductionReady        bool                                      `json:"production_ready"`
}

func formalGLMRegisteredExecutionCostFromPhase15V1(
	value formalGLMPhase15CircuitCost,
) formalGLMRegisteredExecutionCircuitCostV1 {
	return formalGLMRegisteredExecutionCircuitCostV1{
		CircuitSourceSHA256: value.CircuitSourceSHA256,
		Gates:               value.Gates, Wires: value.Wires, XORGates: value.XORGates,
		NonXORGates:          value.NonXORGates,
		CompilerRelativeCost: value.CompilerRelativeCost,
		GarblerInputBits:     value.GarblerInputBits,
		EvaluatorInputBits:   value.EvaluatorInputBits,
		OutputBits:           value.OutputBits,
		EstimatedWorkingByte: value.EstimatedWorkingByte,
	}
}

func formalGLMBuildRegisteredExecutionPlanV1(
	legacy formalGLMPhase15Plan, resolution formalGLMArtifactRegistryResolutionV1,
	artifact formalGLMPhase21StickyArtifact,
	dp formalGLMCanonicalPreSourceDPV1,
	contract formalGLMPhase21SamplerV2Contract,
	bound formalGLMPhase19TranscriptBoundV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredExecutionPlanV1, error) {
	var zero formalGLMRegisteredExecutionPlanV1
	if err := validateFormalGLMPhase15Plan(legacy); err != nil ||
		legacy.Kernel.Family != "binomial" ||
		formalGLMValidateSignedPublicDescriptorV1(
			resolution.Descriptor, pins) != nil ||
		resolution.ArtifactID != resolution.Descriptor.ArtifactID ||
		formalGLMPhase21ValidateStickyArtifact(artifact, pins) != nil ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			resolution.Descriptor, artifact) != nil {
		return zero, fmt.Errorf("formal-glm: invalid registered execution input")
	}
	artifactID, err := formalGLMPhase21StickyArtifactID(artifact)
	if err != nil || artifactID != resolution.ArtifactID {
		return zero, fmt.Errorf("formal-glm: registered execution artifact mismatch")
	}
	dpSHA256, err := formalGLMCanonicalPreSourceDPSHA256V1(dp)
	if err != nil || dpSHA256 !=
		resolution.Descriptor.Descriptor.CanonicalPreSourceDPSHA256 {
		return zero, fmt.Errorf("formal-glm: registered execution DP mismatch")
	}
	canonicalPlanSHA256, err := formalGLMPhase21CanonicalPlanSHA256(legacy)
	if err != nil || canonicalPlanSHA256 != dp.CanonicalPlanSHA256 ||
		canonicalPlanSHA256 != artifact.CanonicalPlanSHA256 {
		return zero, fmt.Errorf("formal-glm: registered execution plan mismatch")
	}
	canonicalLinkSHA256, err := formalGLMPhase21CanonicalLinkSHA256(legacy.Kernel)
	if err != nil || canonicalLinkSHA256 != artifact.CanonicalLinkSHA256 {
		return zero, fmt.Errorf("formal-glm: registered execution link mismatch")
	}
	projectedSchemaSHA256, err := formalGLMProjectedSchemaSHA256V1(
		resolution.Descriptor.Descriptor.SnapshotSHA256,
		resolution.Descriptor.Descriptor.UsedColumns)
	if err != nil || projectedSchemaSHA256 != artifact.SchemaManifestSHA256 {
		return zero, fmt.Errorf("formal-glm: registered execution schema mismatch")
	}
	if err := formalGLMPhase19ValidateTranscriptBoundV1(
		bound, legacy, dp); err != nil {
		return zero, err
	}
	samplerCoreSHA256, err := formalGLMPhase21SamplerV2ContractCoreSHA256V1(
		contract, pins)
	if err != nil || contract.ArtifactID != artifactID ||
		!reflect.DeepEqual(contract.Artifact, artifact) ||
		contract.SamplerMode != formalGLMPhase21SamplerV2OneDraw {
		return zero, fmt.Errorf("formal-glm: registered execution sampler mismatch")
	}
	roles, err := formalGLMPhase16PinnedRoles(legacy, pins)
	if err != nil || roles.PinsetSHA256 != artifact.PinsetSHA256 ||
		!reflect.DeepEqual(legacy.Kernel.CustodianPeers,
			artifact.CustodianPeers) ||
		legacy.Kernel.CanonicalScienceSHA256 !=
			artifact.CanonicalScienceSHA256 ||
		legacy.Kernel.SnapshotSHA256 != artifact.SnapshotSHA256 ||
		legacy.Kernel.PinsetSHA256 != artifact.PinsetSHA256 ||
		legacy.Kernel.Family != artifact.Family {
		return zero, fmt.Errorf("formal-glm: registered execution identity mismatch")
	}
	if !reflect.DeepEqual([]string{roles.GarblerPeerName, roles.EvaluatorPeerName},
		artifact.DesignatedComputePeers) ||
		!formalGLMRegisteredExecutionSamePeerSetV1(
			legacy.Kernel.ComputePeers, artifact.DesignatedComputePeers) {
		return zero, fmt.Errorf("formal-glm: registered execution authority mismatch")
	}
	if legacy.Kernel.Adjacency != dp.Adjacency ||
		dp.SnapshotSHA256 != artifact.SnapshotSHA256 ||
		dp.PinsetSHA256 != artifact.PinsetSHA256 ||
		dp.Family != artifact.Family ||
		dp.BoundsSHA256 != artifact.BoundsSHA256 ||
		dp.QuantizationSHA256 != artifact.QuantizationSHA256 ||
		dp.TransportCoordinateOrderSHA256 != artifact.CoordinateOrderSHA256 ||
		dp.CoordinateCount != artifact.CoordinateCount ||
		dp.SourceFractionBits != artifact.SourceFractionBits ||
		dp.QuantizationShift != artifact.QuantizationShift ||
		dp.OutputLatticeBits != artifact.OutputLatticeBits {
		return zero, fmt.Errorf("formal-glm: registered execution DP evidence mismatch")
	}

	result := formalGLMRegisteredExecutionPlanV1{
		Version:    formalGLMRegisteredExecutionPlanVersion,
		Purpose:    formalGLMRegisteredExecutionPlanPurpose,
		ArtifactID: artifactID, Artifact: artifact,
		DescriptorCore:         resolution.Descriptor.Descriptor,
		DescriptorCoreSHA256:   resolution.Descriptor.DescriptorCoreSHA256,
		CanonicalScienceSHA256: artifact.CanonicalScienceSHA256,
		CanonicalPlanSHA256:    canonicalPlanSHA256,
		CanonicalDP:            dp, CanonicalPreSourceDPSHA256: dpSHA256,
		ProjectedSchemaSHA256:          artifact.SchemaManifestSHA256,
		SnapshotSHA256:                 artifact.SnapshotSHA256,
		PinsetSHA256:                   artifact.PinsetSHA256,
		BoundsSHA256:                   artifact.BoundsSHA256,
		QuantizationSHA256:             artifact.QuantizationSHA256,
		TransportCoordinateOrderSHA256: artifact.CoordinateOrderSHA256,
		CanonicalLinkSHA256:            artifact.CanonicalLinkSHA256,
		SamplerMode:                    contract.SamplerMode,
		SamplerV2ContractCoreSHA256:    samplerCoreSHA256,
		TranscriptBoundSHA256:          bound.ShapeSHA256,
		WireABISHA256:                  bound.WireABISHA256,
		TranscriptBound:                bound,
		SourcePlanVersion:              legacy.Version,
		Family:                         legacy.Kernel.Family,
		ExecutionKernel: formalGLMRegisteredExecutionKernelFromPhase15V1(
			legacy.Kernel),
		TotalCapacity:  legacy.TotalCapacity,
		BlockCapacity:  legacy.BlockCapacity,
		TotalBlocks:    legacy.TotalBlocks,
		Iterations:     legacy.Iterations,
		ScheduleSteps:  legacy.ScheduleSteps,
		CustodianPeers: append([]string(nil), legacy.Kernel.CustodianPeers...),
		CustodianCount: len(legacy.Kernel.CustodianPeers),
		DesignatedComputePeers: append(
			[]string(nil), artifact.DesignatedComputePeers...),
		NoiseAuthorities: []formalGLMRegisteredExecutionAuthorityV1{
			{Role: "garbler", PeerName: roles.GarblerPeerName,
				PeerID: roles.GarblerPeerID},
			{Role: "evaluator", PeerName: roles.EvaluatorPeerName,
				PeerID: roles.EvaluatorPeerID},
		},
		CoordinateOwners: append([]string(nil), legacy.CoordinateOwners...),
		RingBits:         legacy.RingBits, ContainerBits: legacy.ContainerBits,
		MaximumMagnitude: legacy.MaximumMagnitude,
		RhoTotalUpper:    legacy.RhoTotalUpper,
		BlockCost: formalGLMRegisteredExecutionCostFromPhase15V1(
			legacy.BlockCost),
		FinalizeCost: formalGLMRegisteredExecutionCostFromPhase15V1(
			legacy.FinalizeCost),
		BackendSelection: legacy.BackendSelection,
		TranscriptShape:  legacy.TranscriptShape,
		CrashRecovery:    legacy.CrashRecovery,
		Output:           legacy.Output, ProductionReady: false,
	}
	result, err = formalGLMRegisteredExecutionCloneV1(result)
	if err != nil {
		return zero, err
	}
	result.PlanSHA256, err = formalGLMRegisteredExecutionPlanSHA256V1(result)
	if err != nil {
		return zero, err
	}
	if err := formalGLMValidateRegisteredExecutionPlanV1(result, pins); err != nil {
		return zero, err
	}
	return result, nil
}

func formalGLMBuildRegisteredExecutionPlanFromEntryV1(
	legacy formalGLMPhase15Plan, entry formalGLMArtifactRegistryEntryV1,
	artifact formalGLMPhase21StickyArtifact,
	dp formalGLMCanonicalPreSourceDPV1,
	contract formalGLMPhase21SamplerV2Contract,
	bound formalGLMPhase19TranscriptBoundV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredExecutionPlanV1, error) {
	if err := formalGLMValidateArtifactRegistryEntryV1(entry, pins); err != nil {
		return formalGLMRegisteredExecutionPlanV1{}, err
	}
	return formalGLMBuildRegisteredExecutionPlanV1(
		legacy, formalGLMArtifactRegistryResolutionV1{
			ArtifactID: entry.ArtifactID, Descriptor: entry.Descriptor,
		}, artifact, dp, contract, bound, pins)
}

func formalGLMValidateRegisteredExecutionPlanV1(
	value formalGLMRegisteredExecutionPlanV1,
	pins map[string]ed25519.PublicKey,
) error {
	if value.Version != formalGLMRegisteredExecutionPlanVersion ||
		value.Purpose != formalGLMRegisteredExecutionPlanPurpose ||
		value.Family != "binomial" || value.ProductionReady ||
		value.SourcePlanVersion != formalGLMPhase15PlanVersion ||
		!formalGLMIsSHA256(value.PlanSHA256) ||
		!formalGLMIsSHA256(value.ArtifactID) ||
		!formalGLMIsSHA256(value.DescriptorCoreSHA256) ||
		!formalGLMIsSHA256(value.SamplerV2ContractCoreSHA256) ||
		value.SamplerMode != formalGLMPhase21SamplerV2OneDraw ||
		value.CustodianCount != len(pins) ||
		value.CustodianCount != len(value.CustodianPeers) ||
		!sort.StringsAreSorted(value.CustodianPeers) ||
		len(value.DesignatedComputePeers) != 2 ||
		len(value.NoiseAuthorities) != 2 {
		return fmt.Errorf("formal-glm: invalid registered execution plan")
	}
	for index, peer := range value.CustodianPeers {
		if len(pins[peer]) != ed25519.PublicKeySize ||
			(index > 0 && peer == value.CustodianPeers[index-1]) {
			return fmt.Errorf("formal-glm: invalid registered execution custodians")
		}
	}
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || pinsetSHA256 != value.PinsetSHA256 ||
		formalGLMPhase21ValidateStickyArtifact(value.Artifact, pins) != nil {
		return fmt.Errorf("formal-glm: invalid registered execution pinset")
	}
	artifactID, err := formalGLMPhase21StickyArtifactID(value.Artifact)
	if err != nil || artifactID != value.ArtifactID {
		return fmt.Errorf("formal-glm: invalid registered execution artifact")
	}
	coreSHA256, err := formalGLMPublicDescriptorCoreSHA256V1(
		value.DescriptorCore)
	if err != nil || coreSHA256 != value.DescriptorCoreSHA256 {
		return fmt.Errorf("formal-glm: invalid registered execution descriptor")
	}
	descriptor := formalGLMSignedPublicDescriptorV1{
		Descriptor:           value.DescriptorCore,
		DescriptorCoreSHA256: value.DescriptorCoreSHA256,
		ArtifactID:           value.ArtifactID,
	}
	if formalGLMValidatePublicDescriptorAgainstArtifactV1(
		descriptor, value.Artifact) != nil {
		return fmt.Errorf("formal-glm: registered execution descriptor mismatch")
	}
	dpSHA256, err := formalGLMCanonicalPreSourceDPSHA256V1(value.CanonicalDP)
	if err != nil || dpSHA256 != value.CanonicalPreSourceDPSHA256 ||
		dpSHA256 != value.DescriptorCore.CanonicalPreSourceDPSHA256 {
		return fmt.Errorf("formal-glm: invalid registered execution DP")
	}
	legacy, err := formalGLMRegisteredExecutionLegacyPlanV1(value)
	if err != nil || validateFormalGLMPhase15Plan(legacy) != nil ||
		formalGLMPhase19ValidateTranscriptBoundV1(
			value.TranscriptBound, legacy, value.CanonicalDP) != nil {
		return fmt.Errorf("formal-glm: invalid registered execution geometry")
	}
	canonicalPlanSHA256, err := formalGLMPhase21CanonicalPlanSHA256(legacy)
	if err != nil || canonicalPlanSHA256 != value.CanonicalPlanSHA256 ||
		canonicalPlanSHA256 != value.CanonicalDP.CanonicalPlanSHA256 ||
		canonicalPlanSHA256 != value.Artifact.CanonicalPlanSHA256 ||
		value.TranscriptBoundSHA256 != value.TranscriptBound.ShapeSHA256 ||
		value.WireABISHA256 != value.TranscriptBound.WireABISHA256 {
		return fmt.Errorf("formal-glm: registered execution transcript mismatch")
	}
	canonicalLinkSHA256, err := formalGLMPhase21CanonicalLinkSHA256(legacy.Kernel)
	projectedSchemaSHA256, schemaErr := formalGLMProjectedSchemaSHA256V1(
		value.DescriptorCore.SnapshotSHA256,
		value.DescriptorCore.UsedColumns)
	commonAdjacency, adjacencyErr := formalGLMPhase16CommonAdjacency(
		legacy.Kernel.Adjacency)
	wantAuthorities := []formalGLMRegisteredExecutionAuthorityV1{
		{Role: value.Artifact.NoiseAuthorities[0].Role,
			PeerName: value.Artifact.NoiseAuthorities[0].PeerName,
			PeerID:   value.Artifact.NoiseAuthorities[0].PeerID},
		{Role: value.Artifact.NoiseAuthorities[1].Role,
			PeerName: value.Artifact.NoiseAuthorities[1].PeerName,
			PeerID:   value.Artifact.NoiseAuthorities[1].PeerID},
	}
	if err != nil || schemaErr != nil ||
		adjacencyErr != nil ||
		canonicalLinkSHA256 != value.CanonicalLinkSHA256 ||
		projectedSchemaSHA256 != value.ProjectedSchemaSHA256 ||
		value.CanonicalScienceSHA256 != value.Artifact.CanonicalScienceSHA256 ||
		value.CanonicalScienceSHA256 != legacy.Kernel.CanonicalScienceSHA256 ||
		value.Family != value.Artifact.Family ||
		commonAdjacency != value.Artifact.Adjacency ||
		value.CanonicalDP.Adjacency != legacy.Kernel.Adjacency ||
		value.CanonicalDP.Family != value.Family ||
		value.CanonicalDP.SelectedSensitivitySteps !=
			value.Artifact.SensitivitySteps ||
		!reflect.DeepEqual(value.CustodianPeers,
			value.Artifact.CustodianPeers) ||
		!reflect.DeepEqual(value.DesignatedComputePeers,
			value.Artifact.DesignatedComputePeers) ||
		!reflect.DeepEqual(value.NoiseAuthorities, wantAuthorities) ||
		value.ProjectedSchemaSHA256 != value.Artifact.SchemaManifestSHA256 ||
		value.SnapshotSHA256 != value.Artifact.SnapshotSHA256 ||
		value.BoundsSHA256 != value.Artifact.BoundsSHA256 ||
		value.QuantizationSHA256 != value.Artifact.QuantizationSHA256 ||
		value.TransportCoordinateOrderSHA256 !=
			value.Artifact.CoordinateOrderSHA256 {
		return fmt.Errorf("formal-glm: registered execution semantic mismatch")
	}
	wantHash, err := formalGLMRegisteredExecutionPlanSHA256V1(value)
	if err != nil || wantHash != value.PlanSHA256 {
		return fmt.Errorf("formal-glm: registered execution plan hash mismatch")
	}
	return nil
}

func formalGLMValidateRegisteredExecutionPlanAgainstInputsV1(
	value formalGLMRegisteredExecutionPlanV1, legacy formalGLMPhase15Plan,
	resolution formalGLMArtifactRegistryResolutionV1,
	artifact formalGLMPhase21StickyArtifact,
	dp formalGLMCanonicalPreSourceDPV1,
	contract formalGLMPhase21SamplerV2Contract,
	bound formalGLMPhase19TranscriptBoundV1,
	pins map[string]ed25519.PublicKey,
) error {
	want, err := formalGLMBuildRegisteredExecutionPlanV1(
		legacy, resolution, artifact, dp, contract, bound, pins)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(value, want) {
		return fmt.Errorf("formal-glm: registered execution plan differs from inputs")
	}
	return nil
}

func formalGLMRegisteredExecutionPlanSHA256V1(
	value formalGLMRegisteredExecutionPlanV1,
) (string, error) {
	if value.Version != formalGLMRegisteredExecutionPlanVersion ||
		value.Purpose != formalGLMRegisteredExecutionPlanPurpose ||
		(value.PlanSHA256 != "" && !formalGLMIsSHA256(value.PlanSHA256)) {
		return "", fmt.Errorf("formal-glm: invalid registered execution plan hash input")
	}
	value.PlanSHA256 = ""
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredExecutionPlanDomain+"/plan", value)
}

func formalGLMDecodeRegisteredExecutionPlanV1(
	encoded []byte, pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredExecutionPlanV1, error) {
	var value formalGLMRegisteredExecutionPlanV1
	if len(encoded) < 2 || len(encoded) > formalGLMRegisteredExecutionPlanMaxJSON ||
		encoded[0] != '{' {
		return value, fmt.Errorf("formal-glm: invalid registered execution JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("formal-glm: invalid registered execution JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return value, fmt.Errorf("formal-glm: trailing registered execution JSON")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return value, fmt.Errorf("formal-glm: non-canonical registered execution JSON")
	}
	if err := formalGLMValidateRegisteredExecutionPlanV1(value, pins); err != nil {
		return formalGLMRegisteredExecutionPlanV1{}, err
	}
	return value, nil
}

func formalGLMPhase21SamplerV2ContractCoreSHA256V1(
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) (string, error) {
	if err := formalGLMPhase21ValidateSamplerV2ContractCore(
		contract, pins); err != nil {
		return "", err
	}
	if len(contract.CustodianSignatures) != 0 {
		if err := formalGLMPhase21ValidateSamplerV2Contract(
			contract, pins); err != nil {
			return "", err
		}
	}
	message, err := formalGLMPhase21SamplerV2ContractMessage(contract)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMRegisteredExecutionKernelFromPhase15V1(
	value formalGLMPhase1Policy,
) formalGLMRegisteredExecutionKernelV1 {
	return formalGLMRegisteredExecutionKernelV1{
		Version: value.Version, CompilerSHA256: value.CompilerSHA256,
		TheoremSHA256: value.TheoremSHA256, Adjacency: value.Adjacency,
		Capacity: value.Capacity, CoefficientCount: value.CoefficientCount,
		Iterations: value.Iterations, FractionBits: value.FracBits,
		XKind:       append([]string(nil), value.XKind...),
		XLower:      append([]string(nil), value.XLower...),
		XUpper:      append([]string(nil), value.XUpper...),
		WeightUpper: value.WeightUpper, OutcomeUpper: value.OutcomeUpper,
		OffsetLower: value.OffsetLower, OffsetUpper: value.OffsetUpper,
		BetaStart:       append([]string(nil), value.BetaStart...),
		Ridge:           append([]string(nil), value.Ridge...),
		CoefficientBox:  append([]string(nil), value.CoefficientBox...),
		Alpha:           value.Alpha,
		LinkKnots:       append([]string(nil), value.LinkKnots...),
		LinkValues:      append([]string(nil), value.LinkValues...),
		LinkSlopes:      append([]string(nil), value.LinkSlopes...),
		LinkErrorUpper:  value.LinkErrorUpper,
		LinkTableSHA256: value.LinkTableSHA256,
		Missingness:     value.Missingness, PatientCollapse: value.PatientCollapse,
		ReductionOrder: value.ReductionOrder, Truncation: value.Truncation,
		InputLayout: value.InputLayout, InputSharing: value.InputSharing,
		Output: value.Output,
	}
}

func formalGLMRegisteredExecutionLegacyPlanV1(
	value formalGLMRegisteredExecutionPlanV1,
) (formalGLMPhase15Plan, error) {
	kernel := value.ExecutionKernel
	placeholder := sha256.Sum256([]byte(
		formalGLMRegisteredExecutionPlanDomain + "/legacy-validation-placeholder"))
	placeholderSHA256 := hex.EncodeToString(placeholder[:])
	legacy := formalGLMPhase15Plan{
		Version: value.SourcePlanVersion, RunID: placeholderSHA256,
		Kernel: formalGLMPhase1Policy{
			Version: kernel.Version, ArtifactSHA256: placeholderSHA256,
			CanonicalScienceSHA256: value.CanonicalScienceSHA256,
			CapsuleSHA256:          placeholderSHA256,
			SnapshotSHA256:         value.SnapshotSHA256,
			PinsetSHA256:           value.PinsetSHA256,
			CompilerSHA256:         kernel.CompilerSHA256,
			TheoremSHA256:          kernel.TheoremSHA256,
			CustodianPeers:         append([]string(nil), value.CustodianPeers...),
			ComputePeers:           append([]string(nil), value.DesignatedComputePeers...),
			Family:                 value.Family, Adjacency: kernel.Adjacency,
			Capacity:         kernel.Capacity,
			CoefficientCount: kernel.CoefficientCount,
			Iterations:       kernel.Iterations, FracBits: kernel.FractionBits,
			XKind:       append([]string(nil), kernel.XKind...),
			XLower:      append([]string(nil), kernel.XLower...),
			XUpper:      append([]string(nil), kernel.XUpper...),
			WeightUpper: kernel.WeightUpper, OutcomeUpper: kernel.OutcomeUpper,
			OffsetLower: kernel.OffsetLower, OffsetUpper: kernel.OffsetUpper,
			BetaStart:       append([]string(nil), kernel.BetaStart...),
			Ridge:           append([]string(nil), kernel.Ridge...),
			CoefficientBox:  append([]string(nil), kernel.CoefficientBox...),
			Alpha:           kernel.Alpha,
			LinkKnots:       append([]string(nil), kernel.LinkKnots...),
			LinkValues:      append([]string(nil), kernel.LinkValues...),
			LinkSlopes:      append([]string(nil), kernel.LinkSlopes...),
			LinkErrorUpper:  kernel.LinkErrorUpper,
			LinkTableSHA256: kernel.LinkTableSHA256,
			Missingness:     kernel.Missingness,
			PatientCollapse: kernel.PatientCollapse,
			ReductionOrder:  kernel.ReductionOrder,
			Truncation:      kernel.Truncation,
			InputLayout:     kernel.InputLayout,
			InputSharing:    kernel.InputSharing, Output: kernel.Output,
		},
		TotalCapacity: value.TotalCapacity,
		BlockCapacity: value.BlockCapacity,
		TotalBlocks:   value.TotalBlocks, Iterations: value.Iterations,
		CoordinateOwners: append([]string(nil), value.CoordinateOwners...),
		RingBits:         value.RingBits, ContainerBits: value.ContainerBits,
		MaximumMagnitude: value.MaximumMagnitude,
		RhoTotalUpper:    value.RhoTotalUpper,
		ScheduleSteps:    value.ScheduleSteps,
		BlockCost: formalGLMPhase15CircuitCost{
			CircuitSourceSHA256: value.BlockCost.CircuitSourceSHA256,
			Gates:               value.BlockCost.Gates, Wires: value.BlockCost.Wires,
			XORGates:             value.BlockCost.XORGates,
			NonXORGates:          value.BlockCost.NonXORGates,
			CompilerRelativeCost: value.BlockCost.CompilerRelativeCost,
			GarblerInputBits:     value.BlockCost.GarblerInputBits,
			EvaluatorInputBits:   value.BlockCost.EvaluatorInputBits,
			OutputBits:           value.BlockCost.OutputBits,
			EstimatedWorkingByte: value.BlockCost.EstimatedWorkingByte,
		},
		FinalizeCost: formalGLMPhase15CircuitCost{
			CircuitSourceSHA256: value.FinalizeCost.CircuitSourceSHA256,
			Gates:               value.FinalizeCost.Gates, Wires: value.FinalizeCost.Wires,
			XORGates:             value.FinalizeCost.XORGates,
			NonXORGates:          value.FinalizeCost.NonXORGates,
			CompilerRelativeCost: value.FinalizeCost.CompilerRelativeCost,
			GarblerInputBits:     value.FinalizeCost.GarblerInputBits,
			EvaluatorInputBits:   value.FinalizeCost.EvaluatorInputBits,
			OutputBits:           value.FinalizeCost.OutputBits,
			EstimatedWorkingByte: value.FinalizeCost.EstimatedWorkingByte,
		},
		BackendSelection: value.BackendSelection,
		TranscriptShape:  value.TranscriptShape,
		CrashRecovery:    value.CrashRecovery,
		Output:           value.Output, ProductionReady: false,
	}
	return legacy, nil
}

func formalGLMRegisteredExecutionCloneV1(
	value formalGLMRegisteredExecutionPlanV1,
) (formalGLMRegisteredExecutionPlanV1, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return formalGLMRegisteredExecutionPlanV1{}, err
	}
	var cloned formalGLMRegisteredExecutionPlanV1
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return formalGLMRegisteredExecutionPlanV1{}, err
	}
	return cloned, nil
}

func formalGLMRegisteredExecutionSamePeerSetV1(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	return reflect.DeepEqual(leftCopy, rightCopy)
}
