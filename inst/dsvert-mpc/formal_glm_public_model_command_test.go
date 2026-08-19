package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestFormalGLMPublicCanonicalDPCommandK2K3K5RunIDInvariant(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			plan, identities := formalGLMPreSourceDescriptorTestPlan(
				t, "binomial", custodians)
			request := formalGLMPublicCanonicalDPRequestV1{Phase15Plan: plan}
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			first, err := formalGLMRunPublicCanonicalDPV1(encoded)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := buildFormalGLMCanonicalPreSourceDPV1(plan)
			if err != nil {
				t.Fatal(err)
			}
			expectedSHA256, err := formalGLMCanonicalPreSourceDPSHA256V1(expected)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first.CanonicalDP, expected) ||
				first.CanonicalDPSHA256 != expectedSHA256 {
				t.Fatal("public canonical DP command diverged from frozen builder")
			}

			changed := plan
			changed.RunID = sha256Hex([]byte("different-public-command-run"))
			changedRequest, err := json.Marshal(
				formalGLMPublicCanonicalDPRequestV1{Phase15Plan: changed})
			if err != nil {
				t.Fatal(err)
			}
			second, err := formalGLMRunPublicCanonicalDPV1(changedRequest)
			if err != nil {
				t.Fatal(err)
			}
			firstJSON, _ := json.Marshal(first)
			secondJSON, _ := json.Marshal(second)
			if !bytes.Equal(firstJSON, secondJSON) {
				t.Fatal("RunID split the public canonical DP command identity")
			}

			model := formalGLMPreSourceDescriptorTestSignedModel(
				t, plan, identities, sha256Hex([]byte("schema")), nil).Model
			pins := make(map[string]string, len(identities.public))
			for peer, pin := range identities.public {
				pins[peer] = formalGLMIdentityPKV1(pin)
			}
			projectRequest, err := json.Marshal(formalGLMPublicModelProjectRequestV1{
				Model: model, Pins: pins,
			})
			if err != nil {
				t.Fatal(err)
			}
			projected, err := formalGLMRunPublicModelProjectV1(projectRequest)
			if err != nil {
				t.Fatal(err)
			}
			var unsigned formalGLMSignedPreSourceModelV1
			if err := json.Unmarshal([]byte(projected.UnsignedModelJSON),
				&unsigned); err != nil {
				t.Fatal(err)
			}
			if err := formalGLMValidateSignedPreSourceModelCoreV1(
				unsigned, identities.public); err != nil {
				t.Fatal(err)
			}
			if unsigned.CustodianApprovals != nil || unsigned.ProductionReady ||
				unsigned.ModelSHA256 != projected.ModelSHA256 ||
				!reflect.DeepEqual(unsigned.Model, model) {
				t.Fatalf("unexpected unsigned model projection: %+v", unsigned)
			}
			message, err := formalGLMSignedPreSourceModelMessageV1(unsigned)
			if err != nil {
				t.Fatal(err)
			}
			expectedMessage := append(
				[]byte(formalGLMSignedPreSourceModelDomain+"|"),
				[]byte(projected.UnsignedModelJSON)...)
			if !bytes.Equal(message, expectedMessage) {
				t.Fatal("R signing bytes differ from Go signed-model message")
			}
		})
	}
}

func TestFormalGLMPublicModelCommandsFailClosed(t *testing.T) {
	plan, identities := formalGLMPreSourceDescriptorTestPlan(t, "binomial", 2)
	model := formalGLMPreSourceDescriptorTestSignedModel(
		t, plan, identities, sha256Hex([]byte("schema")), nil).Model
	pins := make(map[string]string, len(identities.public))
	for peer, pin := range identities.public {
		pins[peer] = formalGLMIdentityPKV1(pin)
	}
	validCanonical, _ := json.Marshal(
		formalGLMPublicCanonicalDPRequestV1{Phase15Plan: plan})
	validProject, _ := json.Marshal(
		formalGLMPublicModelProjectRequestV1{Model: model, Pins: pins})

	var canonicalObject map[string]any
	if err := json.Unmarshal(validCanonical, &canonicalObject); err != nil {
		t.Fatal(err)
	}
	canonicalObject["action"] = "advance"
	unknownCanonical, _ := json.Marshal(canonicalObject)
	if _, err := formalGLMRunPublicCanonicalDPV1(unknownCanonical); err == nil {
		t.Fatal("canonical DP command accepted an unknown action")
	}

	var projectObject map[string]any
	if err := json.Unmarshal(validProject, &projectObject); err != nil {
		t.Fatal(err)
	}
	projectObject["state_root"] = "/tmp/analyst-selected"
	unknownProject, _ := json.Marshal(projectObject)
	if _, err := formalGLMRunPublicModelProjectV1(unknownProject); err == nil {
		t.Fatal("model projection accepted an analyst-selected path")
	}

	badPins := make(map[string]string, len(pins))
	for peer, pin := range pins {
		badPins[peer] = pin
	}
	badPins[plan.Kernel.CustodianPeers[0]] = badPins[plan.Kernel.CustodianPeers[1]]
	badPinRequest, _ := json.Marshal(
		formalGLMPublicModelProjectRequestV1{Model: model, Pins: badPins})
	if _, err := formalGLMRunPublicModelProjectV1(badPinRequest); err == nil {
		t.Fatal("model projection accepted a mismatched pinned consortium")
	}

	poisson, poissonIdentities := formalGLMPreSourceDescriptorTestPlan(
		t, "poisson", 2)
	poissonModel := formalGLMPreSourceDescriptorTestSignedModel(
		t, poisson, poissonIdentities, sha256Hex([]byte("schema-poisson")), nil).Model
	poissonPins := make(map[string]string, len(poissonIdentities.public))
	for peer, pin := range poissonIdentities.public {
		poissonPins[peer] = formalGLMIdentityPKV1(pin)
	}
	poissonDP, _ := json.Marshal(
		formalGLMPublicCanonicalDPRequestV1{Phase15Plan: poisson})
	poissonProject, _ := json.Marshal(
		formalGLMPublicModelProjectRequestV1{Model: poissonModel, Pins: poissonPins})
	if _, err := formalGLMRunPublicCanonicalDPV1(poissonDP); err == nil {
		t.Fatal("first public slice accepted Poisson canonical DP")
	}
	if _, err := formalGLMRunPublicModelProjectV1(poissonProject); err == nil {
		t.Fatal("first public slice accepted Poisson model projection")
	}
}

func TestFormalGLMPublicProvisionTemplateMatchesKReceiptsK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			plan, identities := formalGLMPreSourceDescriptorTestPlan(
				t, "binomial", custodians)
			context := formalGLMPreSourceDescriptorTestBuild(
				t, plan, identities,
				`{"columns":["outcome","group","unselected"],"version":"v1"}`,
				nil, nil)
			unsigned := context.model
			unsigned.CustodianApprovals = nil
			bindings := make([]formalGLMPreSourceDatasetBindingV1,
				len(context.receipts))
			for index, receipt := range context.receipts {
				bindings[index] = formalGLMPreSourceDatasetBindingV1{
					Owner:          receipt.Core.SignerPeerName,
					DatasetID:      receipt.Core.DatasetID,
					DatasetVersion: receipt.Core.DatasetVersion,
				}
			}
			template, err := formalGLMBuildPreSourceProvisionTemplateV1(
				unsigned, bindings, plan, identities.public,
				[]string{"analysis-primary"})
			if err != nil {
				t.Fatal(err)
			}
			if template.DescriptorCoreSHA256 != context.draft.DescriptorCoreSHA256 ||
				template.ArtifactID != context.draft.ArtifactID ||
				!reflect.DeepEqual(template.DescriptorCore,
					context.draft.DescriptorCore) ||
				!reflect.DeepEqual(template.Artifact, context.draft.Artifact) ||
				!reflect.DeepEqual(template.UnsignedDescriptor,
					context.draft.UnsignedDescriptor) {
				t.Fatal("signed-schema template differed from K-receipt draft")
			}

			changedRun := plan
			changedRun.RunID = sha256Hex([]byte("template-run-replay"))
			replay, err := formalGLMBuildPreSourceProvisionTemplateV1(
				unsigned, bindings, changedRun, identities.public,
				[]string{"analysis-primary"})
			if err != nil || replay.ArtifactID != template.ArtifactID ||
				replay.DescriptorCoreSHA256 != template.DescriptorCoreSHA256 {
				t.Fatalf("RunID split provision template: %+v / %v", replay, err)
			}

			changedDataset := append([]formalGLMPreSourceDatasetBindingV1(nil),
				bindings...)
			changedDataset[0].DatasetVersion = "v2"
			diverged, err := formalGLMBuildPreSourceProvisionTemplateV1(
				unsigned, changedDataset, plan, identities.public,
				[]string{"analysis-primary"})
			if err != nil {
				t.Fatal(err)
			}
			if diverged.ArtifactID == template.ArtifactID ||
				diverged.DescriptorCoreSHA256 == template.DescriptorCoreSHA256 {
				t.Fatal("selected dataset version did not split provision identity")
			}

			if _, err := formalGLMBuildPreSourceProvisionTemplateV1(
				unsigned, bindings[:len(bindings)-1], plan, identities.public,
				[]string{"analysis-primary"}); err == nil {
				t.Fatal("provision template accepted an incomplete owner map")
			}
		})
	}
}

func TestFormalGLMPublicProvisionTemplateCommandK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			plan, identities := formalGLMPreSourceDescriptorTestPlan(
				t, "binomial", custodians)
			context := formalGLMPreSourceDescriptorTestBuild(
				t, plan, identities,
				`{"columns":["outcome","group"],"version":"v1"}`,
				nil, nil)
			unsigned := context.model
			unsigned.CustodianApprovals = nil
			unsignedJSON, err := json.Marshal(unsigned)
			if err != nil {
				t.Fatal(err)
			}
			bindings := make([]formalGLMPreSourceDatasetBindingV1,
				len(context.receipts))
			for index, receipt := range context.receipts {
				bindings[index] = formalGLMPreSourceDatasetBindingV1{
					Owner:          receipt.Core.SignerPeerName,
					DatasetID:      receipt.Core.DatasetID,
					DatasetVersion: receipt.Core.DatasetVersion,
				}
			}
			pins := make(map[string]string, len(identities.public))
			for peer, pin := range identities.public {
				pins[peer] = formalGLMIdentityPKV1(pin)
			}
			request, err := json.Marshal(formalGLMPublicProvisionTemplateRequestV1{
				UnsignedModelJSON: string(unsignedJSON),
				DatasetBindings:   bindings, Phase15Plan: plan, Pins: pins,
				FormalAnalysisIDs: []string{"analysis-primary"},
			})
			if err != nil {
				t.Fatal(err)
			}
			response, err := formalGLMRunPublicProvisionTemplateV1(request)
			if err != nil {
				t.Fatal(err)
			}
			var template formalGLMPreSourceProvisionTemplateV1
			if err := json.Unmarshal([]byte(response.TemplateJSON),
				&template); err != nil {
				t.Fatal(err)
			}
			if template.ArtifactID != context.draft.ArtifactID ||
				response.ArtifactID != template.ArtifactID ||
				response.DescriptorCoreSHA256 != template.DescriptorCoreSHA256 {
				t.Fatalf("unexpected provision command template: %+v", response)
			}
			descriptorJSON, _ := json.Marshal(template.UnsignedDescriptor)
			if response.UnsignedDescriptorJSON != string(descriptorJSON) {
				t.Fatal("descriptor signing JSON is not the exact Go preimage")
			}
			message, err := formalGLMSignedPublicDescriptorMessageV1(
				template.UnsignedDescriptor)
			if err != nil {
				t.Fatal(err)
			}
			expected := append(
				[]byte(formalGLMSignedPublicDescriptorDomain+"|"),
				[]byte(response.UnsignedDescriptorJSON)...)
			if !bytes.Equal(message, expected) {
				t.Fatal("R descriptor signing bytes differ from Go message")
			}

			var requestObject map[string]any
			if err := json.Unmarshal(request, &requestObject); err != nil {
				t.Fatal(err)
			}
			requestObject["formal_analysis_ids"] = []string{}
			missingAlias, _ := json.Marshal(requestObject)
			if _, err := formalGLMRunPublicProvisionTemplateV1(
				missingAlias); err == nil {
				t.Fatal("provision command accepted no server-owned alias")
			}
		})
	}
}
