package main

// The Phase20 job must retain the signed Phase21 sampler authorization that
// was approved with its registered source contract.  This private record is
// deliberately not a public certificate and it does not itself admit a
// release: Phase21 still verifies the capsule/request/backend/worker evidence
// against the Selected handoff immediately before sampling.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

const (
	formalGLMRegisteredPhase21PublicationContextVersionV1 = "dsvert-formal-glm-registered-phase21-publication-context-v1"
	formalGLMRegisteredPhase21PublicationContextPurposeV1 = "formal_glm_registered_phase21_private_publication_context_v1"
	formalGLMRegisteredPhase21PublicationContextMaxV1     = 8 << 20
)

// All fields are held only in the owner-only Phase20 host bootstrap.  The
// sampler contract and authorization chain are checked at provisioning time;
// the remaining Phase16 inputs are checked only at the point where the
// Selected handoff exists, because that handoff supplies their final receipts
// and transcript binding.
type formalGLMRegisteredPhase21PublicationContextV1 struct {
	Version                  string                                   `json:"version"`
	Purpose                  string                                   `json:"purpose"`
	SourceContractCoreSHA256 string                                   `json:"source_contract_core_sha256"`
	SamplerContract          formalGLMPhase21SamplerV2Contract        `json:"sampler_contract"`
	RegistryResolution       formalGLMArtifactRegistryResolutionV1    `json:"registry_resolution"`
	Capsule                  formalGLMPhase16CapsuleBinding           `json:"capsule"`
	Request                  formalGLMPhase16ProductiveRequest        `json:"request"`
	BackendSignatures        []jointDPBiomedicalGaussianSignature     `json:"backend_signatures"`
	WorkerSignatures         []jointDPBiomedicalGaussianSignature     `json:"worker_signatures"`
	SamplerAuthorizations    []formalGLMPhase21SamplerV2Authorization `json:"sampler_authorizations"`
	ProductionReady          bool                                     `json:"production_ready"`
}

func formalGLMRegisteredPhase21PublicationContextValidateV1(
	context formalGLMRegisteredPhase21PublicationContextV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	if context.Version != formalGLMRegisteredPhase21PublicationContextVersionV1 ||
		context.Purpose != formalGLMRegisteredPhase21PublicationContextPurposeV1 ||
		context.ProductionReady ||
		context.SourceContractCoreSHA256 != contract.CoreSHA256 ||
		formalGLMValidateSourceContractV1(contract, pins) != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(context.SamplerContract, pins) != nil ||
		formalGLMPhase21ValidateSamplerV2Authorizations(
			context.SamplerContract, context.SamplerAuthorizations, pins) != nil {
		return fmt.Errorf("formal-glm registered Phase21 publication context: invalid signed sampler")
	}
	unsigned := context.SamplerContract
	unsigned.CustodianSignatures = nil
	if context.SamplerContract.ArtifactID != contract.Core.ArtifactID ||
		!reflect.DeepEqual(unsigned, contract.Core.SamplerV2ContractCore) {
		return fmt.Errorf("formal-glm registered Phase21 publication context: sampler differs from source contract")
	}
	artifact := context.SamplerContract.Artifact
	if context.RegistryResolution.ArtifactID != context.SamplerContract.ArtifactID ||
		context.RegistryResolution.Descriptor.ArtifactID != context.SamplerContract.ArtifactID ||
		formalGLMValidateSignedPublicDescriptorV1(
			context.RegistryResolution.Descriptor, pins) != nil ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			context.RegistryResolution.Descriptor, artifact) != nil {
		return fmt.Errorf("formal-glm registered Phase21 publication context: invalid registry resolution")
	}
	return nil
}

func formalGLMRegisteredPhase21PublicationContextEncodeV1(
	context formalGLMRegisteredPhase21PublicationContextV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) ([]byte, error) {
	if err := formalGLMRegisteredPhase21PublicationContextValidateV1(
		context, contract, pins); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(context)
	if err != nil || len(encoded) < 2 ||
		len(encoded) > formalGLMRegisteredPhase21PublicationContextMaxV1 {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm registered Phase21 publication context: invalid encoding")
	}
	return encoded, nil
}

func formalGLMRegisteredPhase21PublicationContextDecodeV1(
	encoded []byte,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase21PublicationContextV1, error) {
	var context formalGLMRegisteredPhase21PublicationContextV1
	if len(encoded) < 2 || len(encoded) > formalGLMRegisteredPhase21PublicationContextMaxV1 ||
		encoded[0] != '{' {
		return context, fmt.Errorf("formal-glm registered Phase21 publication context: invalid encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&context); err != nil {
		formalGLMRegisteredPhase21PublicationContextClearV1(&context)
		return formalGLMRegisteredPhase21PublicationContextV1{},
			fmt.Errorf("formal-glm registered Phase21 publication context: invalid encoding")
	}
	var trailing any
	canonical, err := json.Marshal(context)
	if err != nil || decoder.Decode(&trailing) != io.EOF || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		formalGLMRegisteredPhase21PublicationContextClearV1(&context)
		return formalGLMRegisteredPhase21PublicationContextV1{},
			fmt.Errorf("formal-glm registered Phase21 publication context: non-canonical encoding")
	}
	clear(canonical)
	if err := formalGLMRegisteredPhase21PublicationContextValidateV1(
		context, contract, pins); err != nil {
		formalGLMRegisteredPhase21PublicationContextClearV1(&context)
		return formalGLMRegisteredPhase21PublicationContextV1{}, err
	}
	return context, nil
}

func formalGLMRegisteredPhase21PublicationContextCloneV1(
	context formalGLMRegisteredPhase21PublicationContextV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase21PublicationContextV1, error) {
	encoded, err := formalGLMRegisteredPhase21PublicationContextEncodeV1(
		context, contract, pins)
	if err != nil {
		return formalGLMRegisteredPhase21PublicationContextV1{}, err
	}
	defer clear(encoded)
	return formalGLMRegisteredPhase21PublicationContextDecodeV1(
		encoded, contract, pins)
}

func formalGLMRegisteredPhase21PublicationContextClearV1(
	context *formalGLMRegisteredPhase21PublicationContextV1,
) {
	if context == nil {
		return
	}
	for index := range context.BackendSignatures {
		clear(context.BackendSignatures[index].Signature)
	}
	for index := range context.WorkerSignatures {
		clear(context.WorkerSignatures[index].Signature)
	}
	for index := range context.SamplerAuthorizations {
		clear(context.SamplerAuthorizations[index].Signature)
	}
	for index := range context.SamplerContract.CustodianSignatures {
		clear(context.SamplerContract.CustodianSignatures[index].Signature)
	}
	for index := range context.RegistryResolution.Descriptor.CustodianApprovals {
		clear(context.RegistryResolution.Descriptor.CustodianApprovals[index].Signature)
	}
	*context = formalGLMRegisteredPhase21PublicationContextV1{}
}
