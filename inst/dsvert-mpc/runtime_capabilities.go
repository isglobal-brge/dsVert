package main

const (
	runtimeManifestSchemaVersion    = 1
	runtimeProtocolVersion          = "dsvert-mpc-runtime-v1"
	runtimePackageVersion           = "1.1.0"
	runtimeAPIVersion               = "1.2.0"
	dpNoiseProtocolVersion          = "dsvert-dp-noise-int64-v2"
	dpGaussianProtocolVersion       = "dsvert-dp-gaussian-int64-v3"
	typedSourceProtocolVersion      = "dsvert-typed-source-stream-v1"
	jointDPVectorProtocolVersion    = "dsvert-joint-dp-vector-hybrid-v5"
	jointDPFrequencyProtocolVersion = "dsvert-joint-dp-frequency-backend-selection-v1"
)

// runtimeVersion is intentionally a variable so release builds can inject the
// package version with -X main.runtimeVersion. The source-build default stays
// aligned with the dsVert and dsVertClient package versions. The runtime API
// version changes independently when the exact bilateral manifest changes.
var runtimeVersion = runtimePackageVersion

type runtimeFeatureManifest struct {
	Available       bool     `json:"available"`
	CapabilityID    string   `json:"capability_id"`
	ProtocolVersion string   `json:"protocol_version"`
	Commands        []string `json:"commands"`
	Operations      []string `json:"operations"`
	CoreOperations  []string `json:"core_operations,omitempty"`
}

type runtimeFeatureSet struct {
	DPNoiseInt64                     runtimeFeatureManifest `json:"dp_noise_int64"`
	DPGaussianInt64                  runtimeFeatureManifest `json:"dp_gaussian_int64"`
	ExactGC                          runtimeFeatureManifest `json:"exact_gc"`
	TypedSourceStream                runtimeFeatureManifest `json:"typed_source_stream"`
	JointDPVector                    runtimeFeatureManifest `json:"joint_dp_vector_convolution"`
	JointDPFrequencyBackendSelection runtimeFeatureManifest `json:"joint_dp_frequency_backend_selection"`
}

type runtimeCapabilitiesOutput struct {
	SchemaVersion   int               `json:"schema_version"`
	ProtocolVersion string            `json:"protocol_version"`
	RuntimeVersion  string            `json:"runtime_version"`
	APIVersion      string            `json:"api_version"`
	Capabilities    runtimeFeatureSet `json:"capabilities"`
}

func runtimeCapabilities() runtimeCapabilitiesOutput {
	return runtimeCapabilitiesOutput{
		SchemaVersion:   runtimeManifestSchemaVersion,
		ProtocolVersion: runtimeProtocolVersion,
		RuntimeVersion:  runtimeVersion,
		APIVersion:      runtimeAPIVersion,
		Capabilities: runtimeFeatureSet{
			DPNoiseInt64: runtimeFeatureManifest{
				Available:       true,
				CapabilityID:    "dp_noise_int64_v2",
				ProtocolVersion: dpNoiseProtocolVersion,
				Commands:        []string{"dp-noise-int64"},
				Operations:      []string{"deterministic-granular-laplace-int64"},
			},
			DPGaussianInt64: runtimeFeatureManifest{
				Available:       true,
				CapabilityID:    "dp_gaussian_int64_v3",
				ProtocolVersion: dpGaussianProtocolVersion,
				Commands: []string{
					"dp-gaussian-int64", "dp-noise-select-int64",
				},
				Operations: []string{
					"deterministic-approximate-gaussian-int64-l2-dp-transfer-tv-accounted",
					"minimum-conservative-95-radius-v3",
				},
			},
			ExactGC: runtimeFeatureManifest{
				Available:       true,
				CapabilityID:    "exact_gc_v1",
				ProtocolVersion: exactGCWorkerConfigVersion,
				Commands: []string{
					"exact-gc-derive-master",
					"exact-gc-capability",
					"exact-gc-plan-mul",
					"joint-dp-laplace-plan-v2",
					"joint-dp-laplace-worker-contract-v2",
					"joint-dp-vector-laplace-plan-v3",
					"joint-dp-vector-worker-contract-v3",
					"exact-gc-worker",
				},
				// Operations are the routes currently consumable through the R/DSI
				// adapter. compare-signed remains a tested core operation only.
				Operations: []string{
					"truncate-floor", "count-guard", "clamp-count", "joint-dp-laplace-v2",
					"joint-dp-vector-laplace-v3", "alignment-mask-ring128",
				},
				CoreOperations: []string{
					"compare-signed", "truncate-floor", "mul-truncate-checked",
					"count-guard", "clamp-count", "joint-dp-laplace-v2",
					"joint-dp-vector-laplace-v3", "alignment-mask-ring128",
				},
			},
			TypedSourceStream: runtimeFeatureManifest{
				Available:       true,
				CapabilityID:    "typed_source_stream_probe_v1",
				ProtocolVersion: typedSourceProtocolVersion,
				Commands:        []string{"typed-source-stream-probe"},
				Operations:      []string{"data-free-random-source-probe"},
			},
			JointDPVector: runtimeFeatureManifest{
				Available:       true,
				CapabilityID:    "joint_dp_vector_hybrid_v5",
				ProtocolVersion: jointDPVectorProtocolVersion,
				Commands: []string{
					"joint-dp-vector-convolution-plan-v3",
					"joint-dp-vector-convolution-share-v3",
					"joint-dp-vector-convolution-finalize-v3",
					"joint-dp-vector-gaussian-plan-v2",
					"joint-dp-vector-gaussian-share-v2",
					"joint-dp-vector-gaussian-finalize-v2",
				},
				Operations: []string{
					"sticky-independent-complete-vector-discrete-laplace-ring128-v3",
					"sticky-independent-complete-vector-dyadic-discrete-gaussian-tv-bounded-ring128-v2",
					"signed-decode-fixed-public-clamp-no-wrap-v3",
				},
			},
			JointDPFrequencyBackendSelection: runtimeFeatureManifest{
				Available:       true,
				CapabilityID:    "joint_dp_frequency_backend_selection_v1",
				ProtocolVersion: jointDPFrequencyProtocolVersion,
				Commands: []string{
					"joint-dp-frequency-backend-select-v1",
				},
				Operations: []string{
					"public-data-free-certified-frequency-backend-selection-v1",
				},
			},
		},
	}
}

func handleRuntimeCapabilities() {
	output(runtimeCapabilities())
}
