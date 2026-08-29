package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestRuntimeCapabilitiesContract(t *testing.T) {
	manifest := runtimeCapabilities()
	if manifest.SchemaVersion != 1 ||
		manifest.ProtocolVersion != "dsvert-mpc-runtime-v1" ||
		manifest.APIVersion != "1.2.0" ||
		manifest.RuntimeVersion != "1.2.0" ||
		manifest.RuntimeVersion != runtimeVersion {
		t.Fatalf("unexpected runtime manifest header: %+v", manifest)
	}
	if !manifest.Capabilities.DPNoiseInt64.Available ||
		manifest.Capabilities.DPNoiseInt64.CapabilityID != "dp_noise_int64_v2" ||
		manifest.Capabilities.DPNoiseInt64.ProtocolVersion !=
			"dsvert-dp-noise-int64-v2" ||
		!reflect.DeepEqual(manifest.Capabilities.DPNoiseInt64.Commands,
			[]string{"dp-noise-int64"}) ||
		!reflect.DeepEqual(manifest.Capabilities.DPNoiseInt64.Operations,
			[]string{"deterministic-granular-laplace-int64"}) {
		t.Fatalf("invalid DP capability: %+v", manifest.Capabilities.DPNoiseInt64)
	}
	if !manifest.Capabilities.DPGaussianInt64.Available ||
		manifest.Capabilities.DPGaussianInt64.CapabilityID !=
			"dp_gaussian_int64_v3" ||
		manifest.Capabilities.DPGaussianInt64.ProtocolVersion !=
			"dsvert-dp-gaussian-int64-v3" ||
		!reflect.DeepEqual(manifest.Capabilities.DPGaussianInt64.Commands,
			[]string{"dp-gaussian-int64", "dp-noise-select-int64"}) ||
		!reflect.DeepEqual(manifest.Capabilities.DPGaussianInt64.Operations,
			[]string{"deterministic-approximate-gaussian-int64-l2-dp-transfer-tv-accounted",
				"minimum-conservative-95-radius-v3"}) {
		t.Fatalf("invalid Gaussian DP capability: %+v",
			manifest.Capabilities.DPGaussianInt64)
	}
	if !manifest.Capabilities.ExactGC.Available ||
		manifest.Capabilities.ExactGC.CapabilityID != "exact_gc_v1" ||
		!reflect.DeepEqual(manifest.Capabilities.ExactGC.Commands,
			[]string{"exact-gc-derive-master", "exact-gc-capability",
				"exact-gc-plan-mul", "joint-dp-laplace-plan-v2",
				"joint-dp-laplace-worker-contract-v2",
				"joint-dp-vector-laplace-plan-v3",
				"joint-dp-vector-worker-contract-v3", "exact-gc-worker"}) ||
		!reflect.DeepEqual(manifest.Capabilities.ExactGC.Operations,
			[]string{"truncate-floor", "count-guard", "clamp-count",
				"joint-dp-laplace-v2", "joint-dp-vector-laplace-v3",
				"alignment-mask-ring128"}) ||
		!reflect.DeepEqual(manifest.Capabilities.ExactGC.CoreOperations,
			[]string{"compare-signed", "truncate-floor", "mul-truncate-checked",
				"categorical-product-ring128",
				"count-guard", "clamp-count", "joint-dp-laplace-v2",
				"joint-dp-vector-laplace-v3", "alignment-mask-ring128"}) {
		t.Fatalf("invalid exact-GC capability: %+v", manifest.Capabilities.ExactGC)
	}
	if !manifest.Capabilities.TypedSourceStream.Available ||
		manifest.Capabilities.TypedSourceStream.CapabilityID !=
			"typed_source_stream_probe_v1" ||
		manifest.Capabilities.TypedSourceStream.ProtocolVersion !=
			"dsvert-typed-source-stream-v1" ||
		!reflect.DeepEqual(manifest.Capabilities.TypedSourceStream.Commands,
			[]string{"typed-source-stream-probe"}) ||
		!reflect.DeepEqual(manifest.Capabilities.TypedSourceStream.Operations,
			[]string{"data-free-random-source-probe"}) {
		t.Fatalf("invalid typed-source capability: %+v",
			manifest.Capabilities.TypedSourceStream)
	}
	if !manifest.Capabilities.JointDPVector.Available ||
		manifest.Capabilities.JointDPVector.CapabilityID !=
			"joint_dp_vector_hybrid_v5" ||
		manifest.Capabilities.JointDPVector.ProtocolVersion !=
			"dsvert-joint-dp-vector-hybrid-v5" ||
		!reflect.DeepEqual(manifest.Capabilities.JointDPVector.Commands,
			[]string{"joint-dp-vector-convolution-plan-v3",
				"joint-dp-vector-convolution-share-v3",
				"joint-dp-vector-convolution-finalize-v3",
				"joint-dp-vector-gaussian-plan-v2",
				"joint-dp-vector-gaussian-share-v2",
				"joint-dp-vector-gaussian-finalize-v2"}) ||
		!reflect.DeepEqual(manifest.Capabilities.JointDPVector.Operations,
			[]string{
				"sticky-independent-complete-vector-discrete-laplace-ring128-v3",
				"sticky-independent-complete-vector-dyadic-discrete-gaussian-tv-bounded-ring128-v2",
				"signed-decode-fixed-public-clamp-no-wrap-v3"}) {
		t.Fatalf("invalid joint-DP vector capability: %+v",
			manifest.Capabilities.JointDPVector)
	}
	if !manifest.Capabilities.JointDPFrequencyBackendSelection.Available ||
		manifest.Capabilities.JointDPFrequencyBackendSelection.CapabilityID !=
			"joint_dp_frequency_backend_selection_v1" ||
		manifest.Capabilities.JointDPFrequencyBackendSelection.ProtocolVersion !=
			"dsvert-joint-dp-frequency-backend-selection-v1" ||
		!reflect.DeepEqual(
			manifest.Capabilities.JointDPFrequencyBackendSelection.Commands,
			[]string{"joint-dp-frequency-backend-select-v1"}) ||
		!reflect.DeepEqual(
			manifest.Capabilities.JointDPFrequencyBackendSelection.Operations,
			[]string{
				"public-data-free-certified-frequency-backend-selection-v1"}) {
		t.Fatalf("invalid joint-DP Frequency selector capability: %+v",
			manifest.Capabilities.JointDPFrequencyBackendSelection)
	}
}

func TestRuntimeCapabilitiesJSONIsDeterministic(t *testing.T) {
	first, err := json.Marshal(runtimeCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(runtimeCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("runtime manifest is not deterministic:\n%s\n%s", first, second)
	}
}
