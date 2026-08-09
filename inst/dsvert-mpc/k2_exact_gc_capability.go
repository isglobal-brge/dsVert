package main

// exactGCCapabilityOutput is a local runtime attestation consumed by the
// server-side numeric router. It is never an analyst-facing result endpoint.
type exactGCCapabilityOutput struct {
	CapabilityID              string   `json:"capability_id"`
	ProtocolVersion           string   `json:"protocol_version"`
	SupportedRingBits         []int    `json:"supported_ring_bits"`
	WireContainerBits         []int    `json:"wire_container_bits"`
	MinRingBits               int      `json:"min_ring_bits"`
	MaxRingBits               int      `json:"max_ring_bits"`
	MaxFracBits               int      `json:"max_frac_bits"`
	MaxVectorLen              int      `json:"max_vector_len"`
	MaxDecimalBoundDigits     int      `json:"max_decimal_bound_digits"`
	MaxCircuitTypeBits        int      `json:"max_circuit_type_bits"`
	DirectMulBitWorkBudget    int      `json:"direct_mul_bit_work_budget"`
	Operations                []string `json:"operations"`
	CoreOperations            []string `json:"core_operations"`
	VerifiedPurposes          []string `json:"verified_purposes"`
	TruncationSemantics       string   `json:"truncation_semantics"`
	CanonicalEncoding         bool     `json:"canonical_encoding"`
	CanonicalInputEncoding    bool     `json:"canonical_input_encoding"`
	ShapeBoundsEnforced       bool     `json:"shape_bounds_enforced"`
	FailClosedOverflow        bool     `json:"fail_closed_overflow"`
	RuntimeBoundsEnforced     bool     `json:"runtime_bounds_enforced"`
	RawProductOverflowGuard   bool     `json:"raw_product_overflow_guard"`
	CheckedMulTruncate        bool     `json:"checked_mul_truncate"`
	DynamicRingFallback       bool     `json:"dynamic_ring_fallback"`
	VecmulNumericPrecondition string   `json:"vecmul_numeric_precondition"`
	ExactTruncation           bool     `json:"exact_truncation"`
	ExactComparison           bool     `json:"exact_comparison"`
	CoreExactComparison       bool     `json:"core_exact_comparison"`
	ComparisonE2EVerified     bool     `json:"comparison_e2e_verified"`
	VecmulE2EVerified         bool     `json:"vecmul_truncation_e2e_verified"`
	CountGuardE2EVerified     bool     `json:"count_guard_e2e_verified"`
	ClampCountE2EVerified     bool     `json:"clamp_count_e2e_verified"`
	JointDPCountE2EVerified   bool     `json:"joint_dp_count_e2e_verified"`
	JointDPVectorE2EVerified  bool     `json:"joint_dp_vector_e2e_verified"`
	AlignmentMaskE2EVerified  bool     `json:"alignment_mask_e2e_verified"`
	MultiprecisionE2E         bool     `json:"multiprecision_truncation_e2e_verified"`
	WorkloadGLME2E            bool     `json:"workload_glm_e2e_verified"`
	KOSCheckedOT              bool     `json:"kos_checked_ot"`
	AuthenticatedRecords      bool     `json:"authenticated_records"`
	SelectiveOutput           bool     `json:"selective_output"`
	PinnedPeersRequired       bool     `json:"pinned_peers_required"`
	RelayOpaque               bool     `json:"relay_opaque"`
	E2EVerified               bool     `json:"e2e_verified"`
	SecurityModel             string   `json:"security_model"`
}

func handleExactGCCapability() {
	supported := make([]int, exactGCMaxRingBits-63+1)
	for i := range supported {
		supported[i] = 63 + i
	}
	mpcWriteOutput(exactGCCapabilityOutput{
		CapabilityID:           "exact_gc_v1",
		ProtocolVersion:        exactGCWorkerConfigVersion,
		SupportedRingBits:      supported,
		WireContainerBits:      []int{64, 128, 256, 512, 1024, 2048, 4096},
		MinRingBits:            63,
		MaxRingBits:            exactGCMaxRingBits,
		MaxFracBits:            exactGCMaxRingBits - 1,
		MaxVectorLen:           exactGCMaxVectorLen,
		MaxDecimalBoundDigits:  exactGCMaxDecimalBoundDigits,
		MaxCircuitTypeBits:     exactGCMaxCircuitTypeBits,
		DirectMulBitWorkBudget: exactGCMaxDirectMulBitWork,
		// Operations names only routes that are consumable through the R/DSI
		// adapter. The comparison circuit is deliberately reported separately
		// until a signed, purpose-bound adapter is available end to end.
		Operations: []string{
			"truncate-floor", "count-guard", "clamp-count", "joint-dp-laplace-v2",
			"joint-dp-vector-laplace-v3", "alignment-mask-ring128",
		},
		CoreOperations: []string{
			"compare-signed", "truncate-floor", "mul-truncate-checked", "count-guard", "clamp-count",
			"joint-dp-laplace-v2", "joint-dp-vector-laplace-v3", "alignment-mask-ring128",
		},
		VerifiedPurposes: []string{
			"count-guard",
			"multiprecision-truncate",
			"joint-dp-count-clamp",
			"joint-dp-count-one-draw",
			"joint-dp-biomedical-vector-one-draw",
			"private-alignment-mask-ring128",
		},
		TruncationSemantics: "floor",
		CanonicalEncoding:   true, CanonicalInputEncoding: true,
		ShapeBoundsEnforced: true,
		// The checked core is implemented and property-tested, but its strict
		// producer-minted workload adapter is not yet release-certified.
		FailClosedOverflow: false, RuntimeBoundsEnforced: false,
		RawProductOverflowGuard: false, CheckedMulTruncate: false,
		DynamicRingFallback:       true,
		VecmulNumericPrecondition: "strict producer-minted input manifest required for promotion",
		ExactTruncation:           true, ExactComparison: false,
		CoreExactComparison: true, ComparisonE2EVerified: false,
		VecmulE2EVerified: false, CountGuardE2EVerified: true,
		ClampCountE2EVerified: true, JointDPCountE2EVerified: true,
		JointDPVectorE2EVerified: true,
		AlignmentMaskE2EVerified: true,
		MultiprecisionE2E:        true, WorkloadGLME2E: false,
		KOSCheckedOT: true, AuthenticatedRecords: true, SelectiveOutput: true,
		PinnedPeersRequired: true, RelayOpaque: true, E2EVerified: true,
		SecurityModel: "two pinned semi-honest non-colluding peers; untrusted opaque relay",
	})
}
