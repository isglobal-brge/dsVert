package main

// This adapter is linked only into the synthetic oracle test binary. It records
// all native inputs needed to replay the deployed sampler, never production keys.
import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

type crossGridNativeCall struct {
	Command               string         `json:"command"`
	Input                 map[string]any `json:"input"`
	Output                map[string]any `json:"output,omitempty"`
	SyntheticSource       bool           `json:"synthetic_source,omitempty"`
	FinalizerCommand      string         `json:"finalizer_command,omitempty"`
	FinalizerInputVersion string         `json:"finalizer_input_version,omitempty"`
}

func crossGridNativeRun(t *testing.T, call crossGridNativeCall) map[string]any {
	t.Helper()
	data, err := json.Marshal(call.Input)
	if err != nil {
		t.Fatal(err)
	}
	var output any
	version := jointDPVectorConvolutionInputVersion[strings.LastIndex(jointDPVectorConvolutionInputVersion, "-")+1:]
	switch {
	case call.Command == "joint-dp-vector-convolution-share-"+version || call.Command == "joint-dp-vector-convolution-share-v4":
		var input jointDPVectorConvolutionShareInput
		if input, err = jointDPVectorConvolutionDecode[jointDPVectorConvolutionShareInput](bytes.NewReader(data)); err == nil {
			expected := jointDPVectorConvolutionInputVersion
			if strings.HasSuffix(call.Command, "-v4") {
				expected = jointDPVectorConvolutionInputVersionV4
			}
			if input.Version != expected {
				t.Fatal("synthetic sampler input version differs from command")
			}
			output, err = jointDPVectorConvolutionSampleShare(input)
		}
	case call.Command == "joint-dp-vector-convolution-finalize-"+version || call.Command == "joint-dp-vector-convolution-finalize-v4":
		var input jointDPVectorConvolutionFinalizerInput
		if input, err = jointDPVectorConvolutionDecode[jointDPVectorConvolutionFinalizerInput](bytes.NewReader(data)); err == nil {
			expected := jointDPVectorConvolutionFinalizerInputVersion
			if strings.HasSuffix(call.Command, "-v4") {
				expected = jointDPVectorConvolutionFinalizerInputVersionV4
			}
			if input.Version != expected {
				t.Fatal("synthetic finalizer input version differs from command")
			}
			output, err = jointDPVectorConvolutionFinalize(input)
		}
	case call.Command == "joint-dp-vector-gaussian-share-v2":
		var input jointDPGaussianShareInput
		if input, err = jointDPVectorConvolutionDecode[jointDPGaussianShareInput](bytes.NewReader(data)); err == nil {
			output, err = jointDPGaussianSampleShare(input)
		}
	case call.Command == "joint-dp-vector-gaussian-finalize-v2":
		var input jointDPGaussianFinalizerInput
		if input, err = jointDPVectorConvolutionDecode[jointDPGaussianFinalizerInput](bytes.NewReader(data)); err == nil {
			output, err = jointDPGaussianFinalize(input)
		}
	default:
		t.Fatal("unsupported synthetic native command", call.Command)
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if call.Output != nil && !reflect.DeepEqual(call.Output, value) {
		t.Fatal("synthetic native output differs from captured production output")
	}
	return value
}

func crossGridNativeRelease(t *testing.T, raw []*big.Int, calls []crossGridNativeCall) ([]string, []crossGridNativeCall) {
	t.Helper()
	released := make([]string, len(raw))
	groups := make(map[string][]crossGridNativeCall)
	finals := make(map[string]crossGridNativeCall)
	var order []string
	key := func(input map[string]any) string {
		return fmt.Sprint(input["release_contract_hash"], "/", input["chunk_start"], "/", input["coordinate_count"])
	}
	for _, call := range calls {
		k := key(call.Input)
		if strings.Contains(call.Command, "-share-v") {
			if len(groups[k]) == 0 {
				order = append(order, k)
			}
			groups[k] = append(groups[k], call)
		} else if prior, ok := finals[k]; ok && !reflect.DeepEqual(prior, call) {
			t.Fatal("conflicting synthetic finalizer calls")
		} else {
			finals[k] = call
		}
	}
	var retained []crossGridNativeCall
	for _, k := range order {
		pair := groups[k]
		if len(pair) != 2 || pair[0].Input["peer_name"] == pair[1].Input["peer_name"] {
			t.Fatal("synthetic native replay requires exactly two distinct peers per chunk")
		}
		start := int(pair[0].Input["chunk_start"].(float64))
		count := int(pair[0].Input["coordinate_count"].(float64))
		if start < 0 || count < 1 || start+count > len(raw) {
			t.Fatal("invalid synthetic native chunk")
		}
		public := func(input map[string]any) map[string]any {
			out := make(map[string]any)
			for name, value := range input {
				switch name {
				case "private_seed", "source_share", "peer_name", "commitment_context", "seed_commitment":
					continue
				}
				out[name] = value
			}
			return out
		}
		if !reflect.DeepEqual(public(pair[0].Input), public(pair[1].Input)) {
			t.Fatal("synthetic peers disagree on public sampler input")
		}
		sources := make([][]byte, 2)
		for i := range pair {
			if pair[i].SyntheticSource {
				source := make([]byte, 16*count)
				if i == 0 {
					for j := 0; j < count; j++ {
						encoded, err := exactGCBigLittleEndian(raw[start+j], 16)
						if err != nil {
							t.Fatal(err)
						}
						copy(source[16*j:], encoded)
					}
				}
				pair[i].Input["source_share"] = base64.StdEncoding.EncodeToString(source)
			}
			var err error
			sources[i], err = base64.StdEncoding.DecodeString(pair[i].Input["source_share"].(string))
			if err != nil || len(sources[i]) != 16*count {
				t.Fatal("invalid synthetic source share")
			}
			pair[i].Output = crossGridNativeRun(t, pair[i])
			pair[i].SyntheticSource = false
			retained = append(retained, pair[i])
		}
		for j := 0; j < count; j++ {
			value := exactGCLittleEndianBig(sources[0][16*j : 16*(j+1)])
			value.Add(value, exactGCLittleEndianBig(sources[1][16*j:16*(j+1)]))
			value.Mod(value, exactGCModulus(128))
			if value.Cmp(raw[start+j]) != 0 {
				t.Fatal("synthetic source shares differ from independent exact integers")
			}
		}
		final, present := finals[k]
		if !present {
			final = crossGridNativeCall{Command: pair[0].FinalizerCommand, Input: public(pair[0].Input)}
			final.Input["version"] = pair[0].FinalizerInputVersion
			final.Input["left_noised_share"] = pair[0].Output["noised_share"]
			final.Input["right_noised_share"] = pair[1].Output["noised_share"]
		}
		for name, value := range public(pair[0].Input) {
			if name != "version" && !reflect.DeepEqual(value, final.Input[name]) {
				t.Fatal("synthetic finalizer public policy differs from the sampler")
			}
		}
		left, right := pair[0].Output["noised_share"], pair[1].Output["noised_share"]
		if !(final.Input["left_noised_share"] == left && final.Input["right_noised_share"] == right ||
			final.Input["left_noised_share"] == right && final.Input["right_noised_share"] == left) {
			t.Fatal("synthetic finalizer does not consume the replayed peer outputs")
		}
		final.Output = crossGridNativeRun(t, final)
		values, ok := final.Output["clamped_scaled_values"].([]any)
		if !ok || len(values) != count {
			t.Fatal("invalid synthetic release coordinates")
		}
		for j, value := range values {
			if released[start+j] != "" {
				t.Fatal("duplicate synthetic release coordinate")
			}
			released[start+j] = value.(string)
		}
		retained = append(retained, final)
		delete(finals, k)
	}
	if len(finals) > 0 {
		t.Fatal("synthetic finalizer has no matching peer inputs")
	}
	for _, value := range released {
		if value == "" {
			t.Fatal("incomplete synthetic native workload")
		}
	}
	return released, retained
}

func TestJointDPVectorSyntheticNativeReplay(t *testing.T) {
	for _, version := range []string{"v3", "v4"} {
		t.Run(version, func(t *testing.T) { jointDPVectorSyntheticNativeReplayVersion(t, version) })
	}
}

func jointDPVectorSyntheticNativeReplayVersion(t *testing.T, version string) {
	raw := []*big.Int{big.NewInt(4), big.NewInt(12345), big.NewInt(54321)}
	var calls []crossGridNativeCall
	for _, peer := range []string{"site_a", "site_b"} {
		seed := sha256.Sum256([]byte("public-synthetic-replay/" + peer))
		input := jointDPVectorConvolutionTestInput(t, peer, seed, raw,
			[]int64{10, 100000, 100000}, []int{0, 1, 2})
		if version == "v4" {
			input.Version, input.AllocatedDelta = jointDPVectorConvolutionInputVersionV4, "0"
		}
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err = json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		delete(value, "source_share")
		finalizerInputVersion := jointDPVectorConvolutionFinalizerInputVersion
		if version == "v4" {
			finalizerInputVersion = jointDPVectorConvolutionFinalizerInputVersionV4
		}
		calls = append(calls, crossGridNativeCall{
			Command: "joint-dp-vector-convolution-share-" + version,
			Input:   value, SyntheticSource: true,
			FinalizerCommand:      "joint-dp-vector-convolution-finalize-" + version,
			FinalizerInputVersion: finalizerInputVersion})
	}
	released, retained := crossGridNativeRelease(t, raw, calls)
	if len(retained) != 3 || retained[0].Input["source_share"] == nil ||
		retained[1].Input["source_share"] == nil || retained[0].SyntheticSource {
		t.Fatal("native replay record did not retain concrete peer inputs")
	}
	encoded, err := json.Marshal(retained)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip []crossGridNativeCall
	if err = json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	replayed, _ := crossGridNativeRelease(t, raw, roundtrip)
	if !reflect.DeepEqual(released, replayed) {
		t.Fatal("record-only native replay changed the release")
	}
}
