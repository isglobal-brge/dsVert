package main

// Closed server-internal projections used before any formal-binomial source
// operation. The caller supplies the already cross-approved Phase-1.5 plan or
// Phase0 model; no path, action, seed or runtime state is accepted here.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

const formalGLMPublicModelCommandMaxJSON = 16 << 20

type formalGLMPublicCanonicalDPRequestV1 struct {
	Phase15Plan formalGLMPhase15Plan `json:"phase15_plan"`
}

type formalGLMPublicCanonicalDPResponseV1 struct {
	CanonicalDP       formalGLMCanonicalPreSourceDPV1 `json:"canonical_dp"`
	CanonicalDPSHA256 string                          `json:"canonical_dp_sha256"`
}

type formalGLMPublicModelProjectRequestV1 struct {
	Model formalGLMPreSourceModelCoreV1 `json:"model"`
	Pins  map[string]string             `json:"pins"`
}

type formalGLMPublicModelProjectResponseV1 struct {
	UnsignedModelJSON string `json:"unsigned_model_json"`
	ModelSHA256       string `json:"model_sha256"`
}

type formalGLMPublicProvisionTemplateRequestV1 struct {
	UnsignedModelJSON string                               `json:"unsigned_model_json"`
	DatasetBindings   []formalGLMPreSourceDatasetBindingV1 `json:"dataset_bindings"`
	Phase15Plan       formalGLMPhase15Plan                 `json:"phase15_plan"`
	Pins              map[string]string                    `json:"pins"`
	FormalAnalysisIDs []string                             `json:"formal_analysis_ids"`
}

type formalGLMPublicProvisionTemplateResponseV1 struct {
	TemplateJSON           string `json:"template_json"`
	UnsignedDescriptorJSON string `json:"unsigned_descriptor_json"`
	DescriptorCoreSHA256   string `json:"descriptor_core_sha256"`
	ArtifactID             string `json:"artifact_id"`
}

func formalGLMPublicModelDecodeStrictV1(encoded []byte, value any) error {
	if len(encoded) < 2 || len(encoded) > formalGLMPublicModelCommandMaxJSON {
		return fmt.Errorf("formal-glm public model: invalid command size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("formal-glm public model: invalid command")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-glm public model: trailing command")
	}
	return nil
}

func formalGLMPublicSupportedFamilyV1(family string) bool {
	return family == "binomial" || family == "poisson"
}

func formalGLMRunPublicCanonicalDPV1(
	encoded []byte,
) (formalGLMPublicCanonicalDPResponseV1, error) {
	var zero formalGLMPublicCanonicalDPResponseV1
	var request formalGLMPublicCanonicalDPRequestV1
	if err := formalGLMPublicModelDecodeStrictV1(encoded, &request); err != nil {
		return zero, err
	}
	if !formalGLMPublicSupportedFamilyV1(request.Phase15Plan.Kernel.Family) {
		return zero, fmt.Errorf("formal-glm public model: unsupported family")
	}
	canonical, err := buildFormalGLMCanonicalPreSourceDPV1(
		request.Phase15Plan)
	if err != nil {
		return zero, err
	}
	digest, err := formalGLMCanonicalPreSourceDPSHA256V1(canonical)
	if err != nil {
		return zero, err
	}
	return formalGLMPublicCanonicalDPResponseV1{
		CanonicalDP: canonical, CanonicalDPSHA256: digest,
	}, nil
}

func formalGLMPublicModelDecodePinsV1(
	values map[string]string,
) (map[string]ed25519.PublicKey, error) {
	if len(values) < 2 || len(values) > 64 {
		return nil, fmt.Errorf("formal-glm public model: invalid pinset")
	}
	pins := make(map[string]ed25519.PublicKey, len(values))
	for peer, encoded := range values {
		if !formalGLMRegistryLabelV1(peer, 128) {
			return nil, fmt.Errorf("formal-glm public model: invalid peer")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			clear(decoded)
			return nil, fmt.Errorf("formal-glm public model: invalid pin")
		}
		pins[peer] = ed25519.PublicKey(append([]byte(nil), decoded...))
		clear(decoded)
	}
	if _, err := formalGLMPhase16PinsetSHA256(pins); err != nil {
		return nil, err
	}
	return pins, nil
}

func formalGLMRunPublicModelProjectV1(
	encoded []byte,
) (formalGLMPublicModelProjectResponseV1, error) {
	var zero formalGLMPublicModelProjectResponseV1
	var request formalGLMPublicModelProjectRequestV1
	if err := formalGLMPublicModelDecodeStrictV1(encoded, &request); err != nil {
		return zero, err
	}
	if !formalGLMPublicSupportedFamilyV1(request.Model.Family) {
		return zero, fmt.Errorf("formal-glm public model: unsupported family")
	}
	pins, err := formalGLMPublicModelDecodePinsV1(request.Pins)
	if err != nil {
		return zero, err
	}
	modelSHA256, err := formalGLMPreSourceModelSHA256V1(request.Model)
	if err != nil {
		return zero, err
	}
	peers := make([]string, 0, len(pins))
	for peer := range pins {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	unsigned := formalGLMSignedPreSourceModelV1{
		Version: formalGLMSignedPreSourceModelVersion,
		Purpose: formalGLMSignedPreSourceModelPurpose,
		Model:   request.Model, ModelSHA256: modelSHA256,
		CustodianPeers: peers, CustodianCount: len(peers),
		ProductionReady: false, CustodianApprovals: nil,
	}
	if err := formalGLMValidateSignedPreSourceModelCoreV1(
		unsigned, pins); err != nil {
		return zero, err
	}
	unsignedJSON, err := json.Marshal(unsigned)
	if err != nil {
		return zero, err
	}
	return formalGLMPublicModelProjectResponseV1{
		UnsignedModelJSON: string(unsignedJSON), ModelSHA256: modelSHA256,
	}, nil
}

func formalGLMRunPublicProvisionTemplateV1(
	encoded []byte,
) (formalGLMPublicProvisionTemplateResponseV1, error) {
	var zero formalGLMPublicProvisionTemplateResponseV1
	var request formalGLMPublicProvisionTemplateRequestV1
	if err := formalGLMPublicModelDecodeStrictV1(encoded, &request); err != nil {
		return zero, err
	}
	if len(request.UnsignedModelJSON) < 2 ||
		len(request.UnsignedModelJSON) > formalGLMPublicModelCommandMaxJSON {
		return zero, fmt.Errorf("formal-glm public model: invalid unsigned model")
	}
	var model formalGLMSignedPreSourceModelV1
	if err := formalGLMPublicModelDecodeStrictV1(
		[]byte(request.UnsignedModelJSON), &model); err != nil {
		return zero, err
	}
	canonicalModel, err := json.Marshal(model)
	if err != nil || string(canonicalModel) != request.UnsignedModelJSON ||
		len(model.CustodianApprovals) != 0 ||
		!formalGLMPublicSupportedFamilyV1(model.Model.Family) {
		return zero, fmt.Errorf("formal-glm public model: invalid unsigned model")
	}
	pins, err := formalGLMPublicModelDecodePinsV1(request.Pins)
	if err != nil {
		return zero, err
	}
	template, err := formalGLMBuildPreSourceProvisionTemplateV1(
		model, request.DatasetBindings, request.Phase15Plan, pins,
		request.FormalAnalysisIDs)
	if err != nil {
		return zero, err
	}
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return zero, err
	}
	descriptorJSON, err := json.Marshal(template.UnsignedDescriptor)
	if err != nil {
		return zero, err
	}
	return formalGLMPublicProvisionTemplateResponseV1{
		TemplateJSON:           string(templateJSON),
		UnsignedDescriptorJSON: string(descriptorJSON),
		DescriptorCoreSHA256:   template.DescriptorCoreSHA256,
		ArtifactID:             template.ArtifactID,
	}, nil
}

func formalGLMPublicModelReadCommandV1() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalGLMPublicModelCommandMaxJSON)+1))
	if err != nil || len(encoded) > formalGLMPublicModelCommandMaxJSON {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm public model: invalid command input")
	}
	return encoded, nil
}

func handleFormalGLMPublicCanonicalDPV1() {
	encoded, err := formalGLMPublicModelReadCommandV1()
	if err != nil {
		mpcFatalError("formal-glm public canonical DP failed")
	}
	defer clear(encoded)
	value, err := formalGLMRunPublicCanonicalDPV1(encoded)
	if err != nil {
		mpcFatalError("formal-glm public canonical DP failed")
	}
	output(value)
}

func handleFormalGLMPublicModelProjectV1() {
	encoded, err := formalGLMPublicModelReadCommandV1()
	if err != nil {
		mpcFatalError("formal-glm public model projection failed")
	}
	defer clear(encoded)
	value, err := formalGLMRunPublicModelProjectV1(encoded)
	if err != nil {
		mpcFatalError("formal-glm public model projection failed")
	}
	output(value)
}

func handleFormalGLMPublicProvisionTemplateV1() {
	encoded, err := formalGLMPublicModelReadCommandV1()
	if err != nil {
		mpcFatalError("formal-glm public provision template failed")
	}
	defer clear(encoded)
	value, err := formalGLMRunPublicProvisionTemplateV1(encoded)
	if err != nil {
		mpcFatalError("formal-glm public provision template failed")
	}
	output(value)
}
