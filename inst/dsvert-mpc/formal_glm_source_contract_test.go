package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type formalGLMSourceContractTestFixtureV1 struct {
	inputs   formalGLMRegisteredExecutionTestInputs
	plan     formalGLMRegisteredExecutionPlanV1
	core     formalGLMSourceContractCoreV1
	contract formalGLMSourceContractV1
}

var formalGLMSourceContractTestFixtures = struct {
	sync.Mutex
	values map[int]formalGLMSourceContractTestFixtureV1
}{values: make(map[int]formalGLMSourceContractTestFixtureV1)}

func formalGLMSourceContractTestFixture(t testing.TB,
	custodians int,
) formalGLMSourceContractTestFixtureV1 {
	t.Helper()
	formalGLMSourceContractTestFixtures.Lock()
	defer formalGLMSourceContractTestFixtures.Unlock()
	if fixture, ok := formalGLMSourceContractTestFixtures.values[custodians]; ok {
		return fixture
	}
	inputs := formalGLMRegisteredExecutionTestInputsV1(
		t, "binomial", custodians, 2, 1)
	plan := formalGLMRegisteredExecutionTestBuild(t, inputs)
	core, err := formalGLMBuildSourceContractCoreV1(
		inputs.entry, inputs.context.receipts, plan, inputs.contract,
		inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	approvals := make([]jointDPBiomedicalGaussianSignature, 0, custodians)
	for _, peer := range plan.CustodianPeers {
		approval, err := formalGLMSignSourceContractV1(
			core, peer, inputs.identities.private[peer],
			inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, approval)
	}
	contract, err := formalGLMSealSourceContractV1(
		core, approvals, inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	fixture := formalGLMSourceContractTestFixtureV1{
		inputs: inputs, plan: plan, core: core, contract: contract,
	}
	formalGLMSourceContractTestFixtures.values[custodians] = fixture
	return fixture
}

func formalGLMSourceContractTestCloneCore(t testing.TB,
	core formalGLMSourceContractCoreV1,
) formalGLMSourceContractCoreV1 {
	t.Helper()
	cloned, err := formalGLMSourceContractCloneCoreV1(core)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestFormalGLMSourceContractK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMSourceContractTestFixture(t, custodians)
			if err := formalGLMValidateSourceContractCoreV1(
				fixture.core, fixture.inputs.identities.public); err != nil {
				t.Fatal(err)
			}
			if err := formalGLMValidateSourceContractV1(
				fixture.contract, fixture.inputs.identities.public); err != nil {
				t.Fatal(err)
			}
			if fixture.core.ArtifactID != fixture.inputs.entry.ArtifactID ||
				fixture.core.BridgeSetSHA256 !=
					fixture.inputs.entry.BridgeSetSHA256 ||
				fixture.core.RegisteredExecutionPlan.PlanSHA256 !=
					fixture.plan.PlanSHA256 ||
				len(fixture.core.SamplerV2ContractCore.CustodianSignatures) != 0 ||
				len(fixture.contract.CustodianApprovals) != custodians ||
				fixture.core.ProductionReady || fixture.contract.ProductionReady {
				t.Fatalf("incomplete source contract: %+v", fixture.contract)
			}
			coreSHA256, err := formalGLMSourceContractCoreSHA256V1(
				fixture.core)
			if err != nil || coreSHA256 != fixture.contract.CoreSHA256 {
				t.Fatalf("core hash mismatch: %q %v", coreSHA256, err)
			}
			contractSHA256, err := formalGLMSourceContractSHA256V1(
				fixture.contract)
			if err != nil || !formalGLMIsSHA256(contractSHA256) {
				t.Fatalf("sealed hash missing: %q %v", contractSHA256, err)
			}
			encoded, err := json.Marshal(fixture.contract)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := formalGLMDecodeSourceContractV1(
				encoded, fixture.inputs.identities.public)
			if err != nil || !reflect.DeepEqual(decoded, fixture.contract) {
				t.Fatalf("canonical decode differs: %v %v",
					reflect.DeepEqual(decoded, fixture.contract), err)
			}
		})
	}
}

func TestFormalGLMSourceBindingSetPreservesExistingProjectionBytes(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 5)
	receipts := fixture.inputs.context.receipts
	type existingSourceProjection struct {
		SignerPeerName  string `json:"signer_peer_name"`
		CohortID        string `json:"cohort_id"`
		SourceBindingID string `json:"source_binding_id"`
		DatasetID       string `json:"dataset_id"`
		DatasetVersion  string `json:"dataset_version"`
	}
	existing := struct {
		Version               string                     `json:"version"`
		Sources               []existingSourceProjection `json:"sources"`
		LogicalSnapshotJSON   string                     `json:"logical_snapshot_json"`
		LogicalSnapshotSHA256 string                     `json:"logical_snapshot_sha256"`
		RPinsetID             string                     `json:"r_pinset_id"`
		GoPinsetSHA256        string                     `json:"go_pinset_sha256"`
		PeerIdentities        []formalGLMPeerIdentityV1  `json:"peer_identities"`
		DescriptorCoreSHA256  string                     `json:"descriptor_core_sha256"`
	}{
		Version:               "dsvert-formal-glm-psi-source-binding-set-v1",
		Sources:               make([]existingSourceProjection, len(receipts)),
		LogicalSnapshotJSON:   receipts[0].Core.LogicalSnapshotJSON,
		LogicalSnapshotSHA256: receipts[0].Core.LogicalSnapshotSHA256,
		RPinsetID:             receipts[0].Core.RPinsetID,
		GoPinsetSHA256:        receipts[0].Core.GoPinsetSHA256,
		PeerIdentities: append([]formalGLMPeerIdentityV1(nil),
			receipts[0].Core.PeerIdentities...),
		DescriptorCoreSHA256: receipts[0].Core.DescriptorCoreSHA256,
	}
	for index, receipt := range receipts {
		existing.Sources[index] = existingSourceProjection{
			SignerPeerName:  receipt.Core.SignerPeerName,
			CohortID:        receipt.Core.CohortID,
			SourceBindingID: receipt.Core.SourceBindingID,
			DatasetID:       receipt.Core.DatasetID,
			DatasetVersion:  receipt.Core.DatasetVersion,
		}
	}
	want, err := formalGLMCanonicalJSONV1(existing)
	if err != nil {
		t.Fatal(err)
	}
	got, err := formalGLMSourceBindingSetJSONV1(
		fixture.core.SourceBindingSet)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("named source projection changed bytes: equal=%v err=%v\n%s\n%s",
			bytes.Equal(got, want), err, got, want)
	}
	wantSHA256, err := formalGLMPSISourceBridgeSetSHA256V1(
		receipts, fixture.inputs.identities.public)
	gotSHA256, gotErr := formalGLMSourceBindingSetSHA256V1(
		fixture.core.SourceBindingSet, fixture.inputs.identities.public)
	if err != nil || gotErr != nil || wantSHA256 != gotSHA256 {
		t.Fatalf("named source projection changed digest: %q %q %v %v",
			wantSHA256, gotSHA256, err, gotErr)
	}
}

func TestFormalGLMSourceContractIsAliasInvariantAndSamplerCoreOnly(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	unsignedEntry := fixture.inputs.entry
	unsignedEntry.CustodianApprovals = nil
	unsignedSampler := fixture.inputs.contract
	unsignedSampler.CustodianSignatures = nil
	want, err := formalGLMBuildSourceContractCoreV1(
		unsignedEntry, fixture.inputs.context.receipts, fixture.plan,
		unsignedSampler, fixture.inputs.identities.public)
	if err != nil || !reflect.DeepEqual(want, fixture.core) {
		t.Fatalf("unsigned two-round inputs changed core: equal=%v err=%v",
			reflect.DeepEqual(want, fixture.core), err)
	}
	unsignedEntry.FormalAnalysisIDs = []string{"different-alias"}
	got, err := formalGLMBuildSourceContractCoreV1(
		unsignedEntry, fixture.inputs.context.receipts, fixture.plan,
		unsignedSampler, fixture.inputs.identities.public)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("alias split source contract: equal=%v err=%v",
			reflect.DeepEqual(got, want), err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"formal_analysis_ids", "bridge_receipts", "descriptor_message_sha256",
	} {
		if strings.Contains(string(encoded), `"`+forbidden+`"`) {
			t.Fatalf("transient field %q entered source core", forbidden)
		}
	}
}

func TestFormalGLMSourceContractRejectsTamperedBindings(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	tests := map[string]func(*formalGLMSourceContractCoreV1){
		"artifact": func(core *formalGLMSourceContractCoreV1) {
			core.ArtifactID = sha256Hex([]byte("another artifact"))
		},
		"source": func(core *formalGLMSourceContractCoreV1) {
			core.SourceBindingSet.Sources[0].DatasetVersion = "v2"
		},
		"bridge-hash": func(core *formalGLMSourceContractCoreV1) {
			core.BridgeSetSHA256 = sha256Hex([]byte("another bridge"))
		},
		"plan": func(core *formalGLMSourceContractCoreV1) {
			core.RegisteredExecutionPlan.PlanSHA256 = sha256Hex([]byte("another plan"))
		},
		"sampler": func(core *formalGLMSourceContractCoreV1) {
			core.SamplerV2ContractCore.NoiseCommitments[0].SeedCommitmentSHA256 =
				sha256Hex([]byte("another commitment"))
		},
		"sealed-sampler": func(core *formalGLMSourceContractCoreV1) {
			core.SamplerV2ContractCore = fixture.inputs.contract
		},
		"production": func(core *formalGLMSourceContractCoreV1) {
			core.ProductionReady = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			core := formalGLMSourceContractTestCloneCore(t, fixture.core)
			mutate(&core)
			if err := formalGLMValidateSourceContractCoreV1(
				core, fixture.inputs.identities.public); err == nil {
				t.Fatal("tampered source core was accepted")
			}
		})
	}
}

func TestFormalGLMSourceContractRequiresOrderedKApprovals(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 5)
	approvals := append([]jointDPBiomedicalGaussianSignature(nil),
		fixture.contract.CustodianApprovals...)
	if _, err := formalGLMSealSourceContractV1(
		fixture.core, approvals[:4], fixture.inputs.identities.public); err == nil {
		t.Fatal("K-1 source approvals were accepted")
	}
	approvals[0], approvals[1] = approvals[1], approvals[0]
	if _, err := formalGLMSealSourceContractV1(
		fixture.core, approvals, fixture.inputs.identities.public); err == nil {
		t.Fatal("reordered source approvals were accepted")
	}
	outsiderPublic, outsiderPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = outsiderPublic
	if _, err := formalGLMSignSourceContractV1(
		fixture.core, "outsider", outsiderPrivate,
		fixture.inputs.identities.public); err == nil {
		t.Fatal("outsider signed source contract")
	}
	tampered := fixture.contract
	tampered.CustodianApprovals = append(
		[]jointDPBiomedicalGaussianSignature(nil),
		fixture.contract.CustodianApprovals...)
	tampered.CustodianApprovals[0].Signature = append(
		[]byte(nil), tampered.CustodianApprovals[0].Signature...)
	tampered.CustodianApprovals[0].Signature[0] ^= 1
	if err := formalGLMValidateSourceContractV1(
		tampered, fixture.inputs.identities.public); err == nil {
		t.Fatal("tampered source approval was accepted")
	}
}
