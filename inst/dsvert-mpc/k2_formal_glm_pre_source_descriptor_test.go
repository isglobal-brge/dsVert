package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const formalGLMPreSourceDescriptorTestSnapshotJSON = `{"alignment_protocol_version":3,"logical_snapshot_id":"cohort-stable-v1","version":"v1"}`

type formalGLMPreSourceDescriptorTestContext struct {
	plan       formalGLMPhase15Plan
	identities formalGLMPhase15TestIdentities
	model      formalGLMSignedPreSourceModelV1
	receipts   []formalGLMPSISourceBridgeReceiptV1
	draft      formalGLMPreSourceProvisionDraftV1
}

func formalGLMPreSourceDescriptorTestPlan(t testing.TB, family string,
	custodians int,
) (formalGLMPhase15Plan, formalGLMPhase15TestIdentities) {
	t.Helper()
	plan := formalGLMPhase15TestPlan(t, family, custodians, 1, 2, 2, 1)
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(identities.public)
	if err != nil {
		t.Fatal(err)
	}
	plan.Kernel.PinsetSHA256 = pinsetSHA256
	plan.Kernel.SnapshotSHA256 = sha256Hex(
		[]byte(formalGLMPreSourceDescriptorTestSnapshotJSON))
	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		t.Fatal(err)
	}
	return plan, identities
}

func formalGLMPreSourceDescriptorTestSignedModel(t testing.TB,
	plan formalGLMPhase15Plan, identities formalGLMPhase15TestIdentities,
	schemaManifestSHA256 string,
	mutate func(*formalGLMPreSourceModelCoreV1),
) formalGLMSignedPreSourceModelV1 {
	t.Helper()
	formula, err := formalGLMCanonicalQualifiedFormulaV1(fmt.Sprintf(
		"%s$outcome ~ 1 + %s$group", plan.Kernel.CustodianPeers[0],
		plan.Kernel.CustodianPeers[1]))
	if err != nil {
		t.Fatal(err)
	}
	dp, err := buildFormalGLMCanonicalPreSourceDPV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	dpSHA256, err := formalGLMCanonicalPreSourceDPSHA256V1(dp)
	if err != nil {
		t.Fatal(err)
	}
	responseKind, responseUpper := "binary", "1"
	if plan.Kernel.Family == "poisson" {
		responseKind, responseUpper = "count", "8"
	}
	coefficientOrder := []string{
		"(Intercept)", plan.Kernel.CustodianPeers[1] + "$group[treated]",
	}
	core := formalGLMPreSourceModelCoreV1{
		Version:                   formalGLMPreSourceModelVersion,
		Purpose:                   formalGLMPreSourceModelPurpose,
		ScientificArtifactSHA256:  plan.Kernel.ArtifactSHA256,
		CanonicalScienceSHA256:    plan.Kernel.CanonicalScienceSHA256,
		Family:                    plan.Kernel.Family,
		CanonicalQualifiedFormula: formula.Canonical,
		FormulaSHA256:             formula.SHA256,
		CoefficientOrder:          coefficientOrder,
		TermMap: []formalGLMPublicTermV1{
			{Index: 0, Coefficient: "(Intercept)", Kind: "intercept"},
			{Index: 1, Coefficient: coefficientOrder[1], Kind: "factor_level",
				Owner: plan.Kernel.CustodianPeers[1], SourceColumn: "group",
				SourceLevel: "treated"},
		},
		UsedColumns: []formalGLMPreSourceColumnV1{
			{Owner: plan.Kernel.CustodianPeers[0], Column: "outcome",
				Role: "response", Kind: responseKind, LowerRational: "0",
				UpperRational: responseUpper},
			{Owner: plan.Kernel.CustodianPeers[1], Column: "group",
				Role: "predictor", Kind: "factor",
				Levels:         []string{"control", "treated"},
				ReferenceLevel: "control", Contrast: "treatment"},
		},
		Mechanism:            formalGLMPhase16RequiredMechanism,
		Allocation:           formalGLMPhase16RequiredAllocation,
		EpsilonRational:      "1",
		DeltaRational:        "1/1000000",
		SchemaManifestSHA256: schemaManifestSHA256,
		SnapshotSHA256:       plan.Kernel.SnapshotSHA256,
		PinsetSHA256:         plan.Kernel.PinsetSHA256,
		CanonicalDP:          dp,
		CanonicalDPSHA256:    dpSHA256,
	}
	if mutate != nil {
		mutate(&core)
	}
	modelSHA256, err := formalGLMPreSourceModelSHA256V1(core)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := formalGLMSignedPreSourceModelV1{
		Version: formalGLMSignedPreSourceModelVersion,
		Purpose: formalGLMSignedPreSourceModelPurpose,
		Model:   core, ModelSHA256: modelSHA256,
		CustodianPeers:  append([]string(nil), plan.Kernel.CustodianPeers...),
		CustodianCount:  len(plan.Kernel.CustodianPeers),
		ProductionReady: false,
	}
	approvals := make([]jointDPBiomedicalGaussianSignature, 0,
		len(unsigned.CustodianPeers))
	for _, peer := range unsigned.CustodianPeers {
		approval, err := formalGLMSignPreSourceModelV1(
			unsigned, peer, identities.private[peer], identities.public)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, approval)
	}
	sealed, err := formalGLMSealPreSourceModelV1(
		unsigned, approvals, identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func formalGLMPreSourceDescriptorTestBridgeReceipts(t testing.TB,
	plan formalGLMPhase15Plan, identities formalGLMPhase15TestIdentities,
	schemaManifestJSON, descriptorCoreSHA256 string,
	mutate func(int, *formalGLMPSISourceBridgeCoreV1),
) []formalGLMPSISourceBridgeReceiptV1 {
	t.Helper()
	psiPinsetID, err := formalGLMPSIPinsetIDV1(identities.public)
	if err != nil {
		t.Fatal(err)
	}
	peerIdentities := make([]formalGLMPeerIdentityV1, 0,
		len(plan.Kernel.CustodianPeers))
	for _, peer := range plan.Kernel.CustodianPeers {
		peerIdentities = append(peerIdentities, formalGLMPeerIdentityV1{
			PeerName: peer, IdentityPK: formalGLMIdentityPKV1(identities.public[peer]),
		})
	}
	result := make([]formalGLMPSISourceBridgeReceiptV1, 0,
		len(plan.Kernel.CustodianPeers))
	for index, peer := range plan.Kernel.CustodianPeers {
		attestation := formalGLMPSIPublicAttestationV3{
			AttestationVersion: 3, AlignmentAttested: true,
			AlignmentProtocol: "dsvert-pinned-padded-psi-v5",
			AttestationID:     fmt.Sprintf("attest_%064x", index+1),
			ContractSHA256:    sha256Hex([]byte(fmt.Sprintf("contract-%d", index))),
			PolicyID:          fmt.Sprintf("policy_%064x", 91),
			AlignmentPurpose:  "aligned-patient-cohort-v1",
			DatasetID:         fmt.Sprintf("dataset-%c", 'a'+index), DatasetVersion: "v1",
			IDColumn:        "patient_id",
			SourceBindingID: fmt.Sprintf("source_%064x", index+11),
			PinsetID:        psiPinsetID, CapacityBucket: 1024,
			RelayFrameBytes: 65536, InlineMaxBytes: 65536,
			PeerCount:     len(plan.Kernel.CustodianPeers),
			ReferencePeer: plan.Kernel.ComputePeers[0],
			ComputePeers:  append([]string(nil), plan.Kernel.ComputePeers...),
		}
		core := formalGLMPSISourceBridgeCoreV1{
			Version:          formalGLMPSISourceBridgeVersion,
			Purpose:          formalGLMPSISourceBridgePurpose,
			SignerPeerName:   peer,
			SignerIdentityPK: formalGLMIdentityPKV1(identities.public[peer]),
			PSIAttestation:   attestation, CohortID: "cohort-stable-v1",
			SourceBindingID: attestation.SourceBindingID,
			DatasetID:       attestation.DatasetID, DatasetVersion: attestation.DatasetVersion,
			LogicalSnapshotJSON:   formalGLMPreSourceDescriptorTestSnapshotJSON,
			LogicalSnapshotSHA256: plan.Kernel.SnapshotSHA256,
			SchemaManifestJSON:    schemaManifestJSON,
			SchemaManifestSHA256:  sha256Hex([]byte(schemaManifestJSON)),
			RPinsetID:             psiPinsetID, GoPinsetSHA256: plan.Kernel.PinsetSHA256,
			PeerIdentities:       peerIdentities,
			DescriptorCoreSHA256: descriptorCoreSHA256,
		}
		if mutate != nil {
			mutate(index, &core)
			core.PSIAttestation.DatasetID = core.DatasetID
			core.PSIAttestation.DatasetVersion = core.DatasetVersion
		}
		message, err := formalGLMPSISourceBridgeMessageV1(core)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, formalGLMPSISourceBridgeReceiptV1{
			Core: core,
			Signature: formalGLMSignatureBase64URLV1(
				ed25519.Sign(identities.private[peer], message)),
		})
	}
	return result
}

func formalGLMPreSourceDescriptorTestBuild(t testing.TB,
	plan formalGLMPhase15Plan, identities formalGLMPhase15TestIdentities,
	schemaManifestJSON string,
	mutateModel func(*formalGLMPreSourceModelCoreV1),
	mutateReceipt func(int, *formalGLMPSISourceBridgeCoreV1),
) formalGLMPreSourceDescriptorTestContext {
	t.Helper()
	schemaSHA256 := sha256Hex([]byte(schemaManifestJSON))
	model := formalGLMPreSourceDescriptorTestSignedModel(
		t, plan, identities, schemaSHA256, mutateModel)
	placeholder := formalGLMPreSourceDescriptorTestBridgeReceipts(
		t, plan, identities, schemaManifestJSON,
		sha256Hex([]byte("pending-descriptor")), mutateReceipt)
	_, descriptorSHA256, err := formalGLMDescriptorCoreFromPreSourceV1(
		model, placeholder, identities.public, false)
	if err != nil {
		t.Fatal(err)
	}
	receipts := formalGLMPreSourceDescriptorTestBridgeReceipts(
		t, plan, identities, schemaManifestJSON, descriptorSHA256, mutateReceipt)
	draft, err := formalGLMBuildPreSourceProvisionDraftV1(
		model, receipts, plan, identities.public, []string{"analysis-primary"})
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMPreSourceDescriptorTestContext{
		plan: plan, identities: identities, model: model,
		receipts: receipts, draft: draft,
	}
}

func formalGLMPreSourceDescriptorTestEntry(t testing.TB,
	context formalGLMPreSourceDescriptorTestContext,
) formalGLMArtifactRegistryEntryV1 {
	t.Helper()
	unsignedDescriptor := context.draft.UnsignedDescriptor
	descriptorApprovals := make([]jointDPBiomedicalGaussianSignature, 0,
		len(unsignedDescriptor.CustodianPeers))
	for _, peer := range unsignedDescriptor.CustodianPeers {
		approval, err := formalGLMSignPublicDescriptorV1(unsignedDescriptor, peer,
			context.identities.private[peer], context.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		descriptorApprovals = append(descriptorApprovals, approval)
	}
	sealedDescriptor, err := formalGLMSealPublicDescriptorV1(
		unsignedDescriptor, descriptorApprovals,
		context.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	entry := formalGLMArtifactRegistryEntryV1{
		Version:         formalGLMArtifactRegistryEntryVersion,
		Purpose:         formalGLMArtifactRegistryEntryPurpose,
		BridgeSetSHA256: context.draft.BridgeSetSHA256,
		FormalAnalysisIDs: append([]string(nil),
			context.draft.FormalAnalysisIDs...),
		ArtifactID: context.draft.ArtifactID, Descriptor: sealedDescriptor,
		DescriptorCoreSHA256: context.draft.DescriptorCoreSHA256,
		CustodianPeers: append([]string(nil),
			context.model.CustodianPeers...),
		CustodianCount: context.model.CustodianCount, ProductionReady: false,
	}
	entryApprovals := make([]jointDPBiomedicalGaussianSignature, 0,
		len(entry.CustodianPeers))
	for _, peer := range entry.CustodianPeers {
		approval, err := formalGLMSignArtifactRegistryEntryV1(
			entry, peer, context.identities.private[peer], context.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		entryApprovals = append(entryApprovals, approval)
	}
	entry.CustodianApprovals = entryApprovals
	if err := formalGLMValidateArtifactRegistryEntryV1(
		entry, context.identities.public); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestFormalGLMProjectedSchemaIgnoresUnrelatedManifestMetadata(t *testing.T) {
	columns := []formalGLMPublicColumnV1{
		{Owner: "peer-a", DatasetID: "dataset-a", DatasetVersion: "v1",
			Column: "outcome", Role: "response", Kind: "binary",
			LowerRational: "0", UpperRational: "1"},
		{Owner: "peer-b", DatasetID: "dataset-b", DatasetVersion: "v1",
			Column: "group", Role: "predictor", Kind: "factor",
			Levels:         []string{"control", "treated"},
			ReferenceLevel: "control", Contrast: "treatment"},
	}
	first, err := formalGLMProjectedSchemaSHA256V1(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		columns)
	if err != nil {
		t.Fatal(err)
	}
	second, err := formalGLMProjectedSchemaSHA256V1(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		columns)
	if err != nil || first != second {
		t.Fatalf("unrelated full-schema metadata split projected identity: %s %v",
			second, err)
	}
	changed := append([]formalGLMPublicColumnV1(nil), columns...)
	changed[1].Levels = []string{"control", "case"}
	third, err := formalGLMProjectedSchemaSHA256V1(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		changed)
	if err != nil || third == first {
		t.Fatalf("selected factor levels did not change projected identity: %s %v",
			third, err)
	}
}

func TestFormalGLMPreSourceProvisionK2K3K5CASRestart(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 5} {
			t.Run(fmt.Sprintf("%s/K%d", family, custodians), func(t *testing.T) {
				plan, identities := formalGLMPreSourceDescriptorTestPlan(
					t, family, custodians)
				context := formalGLMPreSourceDescriptorTestBuild(
					t, plan, identities,
					`{"columns":["outcome","group","unused"],"version":"v1"}`,
					nil, nil)
				entry := formalGLMPreSourceDescriptorTestEntry(t, context)
				if context.draft.UnsignedDescriptor.ProductionReady ||
					entry.ProductionReady || entry.Descriptor.ProductionReady {
					t.Fatal("pre-source provisioning was marked production-ready")
				}
				root := filepath.Join(t.TempDir(), "formal-glm-artifact-registry-v1")
				store, err := newFormalGLMArtifactRegistryStoreV1(
					root, identities.public)
				if err != nil {
					t.Fatal(err)
				}
				if replay, err := store.Commit(entry); err != nil || replay {
					t.Fatalf("first CAS: replay=%v err=%v", replay, err)
				}
				if replay, err := store.Commit(entry); err != nil || !replay {
					t.Fatalf("idempotent CAS: replay=%v err=%v", replay, err)
				}
				paths, err := store.entryPaths()
				if err != nil || len(paths) != 1 {
					t.Fatalf("unexpected registry paths: %v %v", paths, err)
				}
				rootInfo, err := os.Stat(root)
				if err != nil || rootInfo.Mode().Perm()&0o077 != 0 {
					t.Fatalf("registry root is not owner-only: %v %v", rootInfo, err)
				}
				recordInfo, err := os.Stat(filepath.Join(root, paths[0]))
				if err != nil || recordInfo.Mode().Perm()&0o077 != 0 {
					t.Fatalf("registry record is not owner-only: %v %v", recordInfo, err)
				}
				query := formalGLMArtifactRegistryQueryV1{
					BridgeReceipts: context.receipts,
					Family:         family,
					Formula:        context.model.Model.CanonicalQualifiedFormula,
				}
				resolved, err := store.Resolve(query)
				if err != nil || resolved.ArtifactID != context.draft.ArtifactID {
					t.Fatalf("resolve after CAS: %+v %v", resolved, err)
				}
				store.Close()
				store, err = newFormalGLMArtifactRegistryStoreV1(
					root, identities.public)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				restarted, err := store.Resolve(query)
				if err != nil || !reflect.DeepEqual(restarted, resolved) {
					t.Fatalf("restart changed provisioning: %+v %v", restarted, err)
				}
			})
		}
	}
}

func TestFormalGLMPreSourceProvisionIdentityUsesOnlySelectedSchema(t *testing.T) {
	plan, identities := formalGLMPreSourceDescriptorTestPlan(t, "binomial", 3)
	first := formalGLMPreSourceDescriptorTestBuild(
		t, plan, identities,
		`{"columns":["outcome","group","unused-a"],"version":"v1"}`,
		nil, nil)
	second := formalGLMPreSourceDescriptorTestBuild(
		t, plan, identities,
		`{"columns":["outcome","group","unused-b"],"gaussian":{"x":1},"version":"v1"}`,
		nil, nil)
	firstModel, _ := json.Marshal(first.model)
	secondModel, _ := json.Marshal(second.model)
	firstReceipts, _ := json.Marshal(first.receipts)
	secondReceipts, _ := json.Marshal(second.receipts)
	if bytes.Equal(firstModel, secondModel) || bytes.Equal(firstReceipts, secondReceipts) {
		t.Fatal("changed full schema did not change signed authorization evidence")
	}
	firstCore, _ := json.Marshal(first.draft.DescriptorCore)
	secondCore, _ := json.Marshal(second.draft.DescriptorCore)
	if !bytes.Equal(firstCore, secondCore) ||
		first.draft.DescriptorCoreSHA256 != second.draft.DescriptorCoreSHA256 ||
		first.draft.ArtifactID != second.draft.ArtifactID ||
		first.draft.BridgeSetSHA256 != second.draft.BridgeSetSHA256 {
		t.Fatal("unrelated full-schema metadata rerolled projected identity")
	}
	changedRun := plan
	changedRun.RunID = sha256Hex([]byte("different-execution-run"))
	changedNonce := formalGLMPreSourceDescriptorTestBuild(
		t, changedRun, identities,
		`{"columns":["outcome","group","unused-b"],"gaussian":{"x":1},"version":"v1"}`,
		nil, func(index int, core *formalGLMPSISourceBridgeCoreV1) {
			core.PSIAttestation.AttestationID = fmt.Sprintf(
				"attest_%064x", index+100)
		})
	if changedNonce.draft.ArtifactID != first.draft.ArtifactID ||
		changedNonce.draft.DescriptorCoreSHA256 != first.draft.DescriptorCoreSHA256 ||
		changedNonce.draft.BridgeSetSHA256 != first.draft.BridgeSetSHA256 {
		t.Fatal("RunID or PSI nonce rerolled projected identity")
	}

	root := filepath.Join(t.TempDir(), "formal-glm-artifact-registry-v1")
	store, err := newFormalGLMArtifactRegistryStoreV1(root, identities.public)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	firstEntry := formalGLMPreSourceDescriptorTestEntry(t, first)
	secondEntry := formalGLMPreSourceDescriptorTestEntry(t, second)
	if replay, err := store.Commit(firstEntry); err != nil || replay {
		t.Fatalf("first schema CAS: replay=%v err=%v", replay, err)
	}
	pathsBefore, err := store.entryPaths()
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.Commit(secondEntry); err != nil || !replay {
		t.Fatalf("unrelated schema did not hit same CAS: replay=%v err=%v", replay, err)
	}
	pathsAfter, err := store.entryPaths()
	if err != nil || !reflect.DeepEqual(pathsBefore, pathsAfter) ||
		len(pathsAfter) != 1 {
		t.Fatalf("unrelated schema changed registry path: %v %v", pathsAfter, err)
	}
}

func TestFormalGLMPreSourceProvisionSelectedSemanticsDiverge(t *testing.T) {
	plan, identities := formalGLMPreSourceDescriptorTestPlan(t, "poisson", 3)
	schema := `{"columns":["outcome","group"],"version":"v1"}`
	base := formalGLMPreSourceDescriptorTestBuild(
		t, plan, identities, schema, nil, nil)
	for name, mutate := range map[string]func(int, *formalGLMPSISourceBridgeCoreV1){
		"dataset-id": func(index int, core *formalGLMPSISourceBridgeCoreV1) {
			if index == 1 {
				core.DatasetID = "selected-dataset-b"
			}
		},
		"dataset-version": func(index int, core *formalGLMPSISourceBridgeCoreV1) {
			if index == 1 {
				core.DatasetVersion = "v2"
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := formalGLMPreSourceDescriptorTestBuild(
				t, plan, identities, schema, nil, mutate)
			if changed.draft.DescriptorCoreSHA256 == base.draft.DescriptorCoreSHA256 ||
				changed.draft.ArtifactID == base.draft.ArtifactID ||
				changed.draft.BridgeSetSHA256 == base.draft.BridgeSetSHA256 {
				t.Fatal("selected dataset mutation did not split identity")
			}
		})
	}
	changedBounds := formalGLMPreSourceDescriptorTestBuild(
		t, plan, identities, schema,
		func(model *formalGLMPreSourceModelCoreV1) {
			model.UsedColumns[0].UpperRational = "9"
		}, nil)
	if changedBounds.draft.DescriptorCoreSHA256 == base.draft.DescriptorCoreSHA256 ||
		changedBounds.draft.ArtifactID == base.draft.ArtifactID {
		t.Fatal("selected column bounds did not split identity")
	}

	bad := base.model
	bad.CustodianApprovals = append([]jointDPBiomedicalGaussianSignature(nil),
		bad.CustodianApprovals[:len(bad.CustodianApprovals)-1]...)
	if _, _, err := formalGLMDescriptorCoreFromPreSourceV1(
		bad, base.receipts, identities.public, true); err == nil {
		t.Fatal("missing K model approval reached descriptor construction")
	}
	tampered := append([]formalGLMPSISourceBridgeReceiptV1(nil), base.receipts...)
	tampered[0].Core.DatasetVersion = "tampered"
	if _, _, err := formalGLMDescriptorCoreFromPreSourceV1(
		base.model, tampered, identities.public, true); err == nil {
		t.Fatal("tampered PSI receipt reached descriptor construction")
	}
}
