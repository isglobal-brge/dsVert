package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func formalGLMRegisteredPhase18AuthorizationTestBuild(t testing.TB,
	fixture formalGLMSourceContractTestFixtureV1,
	localPeer string,
) formalGLMRegisteredPhase18AuthorizationV1 {
	t.Helper()
	authorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		fixture.contract, localPeer, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidateRegisteredPhase18AuthorizationV1(
		authorization, fixture.contract,
		fixture.inputs.identities.public); err != nil {
		t.Fatal(err)
	}
	return authorization
}

func formalGLMRegisteredPhase18AuthorizationTestClone(t testing.TB,
	value formalGLMRegisteredPhase18AuthorizationV1,
) formalGLMRegisteredPhase18AuthorizationV1 {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned formalGLMRegisteredPhase18AuthorizationV1
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func formalGLMRegisteredPhase18AuthorizationTestSeal(t testing.TB,
	fixture formalGLMSourceContractTestFixtureV1,
	core formalGLMSourceContractCoreV1,
) formalGLMSourceContractV1 {
	t.Helper()
	approvals := make([]jointDPBiomedicalGaussianSignature, 0,
		len(core.RegisteredExecutionPlan.CustodianPeers))
	for _, peer := range core.RegisteredExecutionPlan.CustodianPeers {
		approval, err := formalGLMSignSourceContractV1(
			core, peer, fixture.inputs.identities.private[peer],
			fixture.inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, approval)
	}
	contract, err := formalGLMSealSourceContractV1(
		core, approvals, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func TestFormalGLMRegisteredPhase18AuthorizationK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMSourceContractTestFixture(t, custodians)
			for _, localPeer := range fixture.plan.CustodianPeers {
				authorization :=
					formalGLMRegisteredPhase18AuthorizationTestBuild(
						t, fixture, localPeer)
				if authorization.ArtifactID != fixture.core.ArtifactID ||
					authorization.SourceContractCoreSHA256 !=
						fixture.contract.CoreSHA256 ||
					authorization.BridgeSetSHA256 !=
						fixture.core.BridgeSetSHA256 ||
					authorization.LogicalSnapshotJSON !=
						fixture.core.SourceBindingSet.LogicalSnapshotJSON ||
					authorization.LogicalSnapshotSHA256 !=
						fixture.core.SourceBindingSet.LogicalSnapshotSHA256 ||
					authorization.RPinsetID !=
						fixture.core.SourceBindingSet.RPinsetID ||
					authorization.RegisteredExecutionPlanSHA256 !=
						fixture.plan.PlanSHA256 ||
					authorization.CanonicalScienceSHA256 !=
						fixture.plan.CanonicalScienceSHA256 ||
					!reflect.DeepEqual(
						authorization.ExecutionKernel,
						fixture.plan.ExecutionKernel) ||
					authorization.LocalSource.SignerPeerName != localPeer ||
					authorization.LocalPeerIdentity.PeerName != localPeer ||
					authorization.CustodianCount != custodians ||
					len(authorization.CustodianPeers) != custodians ||
					len(authorization.DesignatedComputePeers) != 2 ||
					len(authorization.NoiseAuthorities) != 2 ||
					authorization.Geometry.TotalBlocks !=
						fixture.plan.TotalBlocks ||
					authorization.Geometry.CoordinateCount !=
						fixture.plan.ExecutionKernel.CoefficientCount+3 ||
					authorization.Geometry.RecordBytes !=
						fixture.plan.ContainerBits/8 ||
					authorization.OpeningsPerformed != 0 ||
					authorization.ProductionReady {
					t.Fatalf("incomplete registered Phase18 authorization: %+v",
						authorization)
				}
				for _, column := range authorization.LocalColumns {
					if column.Owner != localPeer ||
						column.DatasetID != authorization.LocalSource.DatasetID ||
						column.DatasetVersion !=
							authorization.LocalSource.DatasetVersion {
						t.Fatal("local materializer column escaped its source binding")
					}
				}
				digest, err :=
					formalGLMRegisteredPhase18AuthorizationSHA256V1(
						authorization)
				if err != nil || digest != authorization.AuthorizationSHA256 {
					t.Fatalf("authorization hash mismatch: %q %v", digest, err)
				}
				encoded, err := json.Marshal(authorization)
				if err != nil {
					t.Fatal(err)
				}
				wantSchemaOrder := fmt.Sprintf(
					`"registered_execution_plan_sha256":%q,`+
						`"canonical_science_sha256":%q,"execution_kernel":`,
					authorization.RegisteredExecutionPlanSHA256,
					authorization.CanonicalScienceSHA256)
				if !strings.Contains(string(encoded), wantSchemaOrder) {
					t.Fatal("registered Phase18 science/kernel schema order changed")
				}
				decoded, err := formalGLMDecodeRegisteredPhase18AuthorizationV1(
					encoded, fixture.contract, fixture.inputs.identities.public)
				if err != nil || !reflect.DeepEqual(decoded, authorization) {
					t.Fatalf("canonical decode differs: equal=%v err=%v",
						reflect.DeepEqual(decoded, authorization), err)
				}
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18AuthorizationContainsNoOperationalIdentity(
	t *testing.T,
) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	authorization := formalGLMRegisteredPhase18AuthorizationTestBuild(
		t, fixture, fixture.plan.CustodianPeers[0])
	encoded, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"capsule", "run_id", "analysis", "request", "lifetime", "ttl",
		"path", "private_key", "secret_key", "table_handle", "psi_token",
		"alignment_secret", "signature", "formal_analysis_ids",
		"attestation_id", "nonce", "authority",
	}
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				lower := strings.ToLower(key)
				for _, fragment := range forbidden {
					if strings.Contains(lower, fragment) {
						t.Errorf("forbidden registered Phase18 field %q", key)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(decoded)
	if authorization.PrivateCarrierRequirement !=
		formalGLMRegisteredPhase18PrivateCarrierRequirement {
		t.Fatal("private Rock-local carrier requirement is not explicit")
	}
}

func TestFormalGLMRegisteredPhase18AuthorizationAliasNonceAndRunInvariant(
	t *testing.T,
) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	localPeer := fixture.plan.CustodianPeers[0]
	want := formalGLMRegisteredPhase18AuthorizationTestBuild(
		t, fixture, localPeer)

	unsignedEntry := fixture.inputs.entry
	unsignedEntry.CustodianApprovals = nil
	unsignedEntry.FormalAnalysisIDs = []string{"another-alias"}
	unsignedSampler := fixture.inputs.contract
	unsignedSampler.CustodianSignatures = nil
	aliasCore, err := formalGLMBuildSourceContractCoreV1(
		unsignedEntry, fixture.inputs.context.receipts, fixture.plan,
		unsignedSampler, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	aliasContract := formalGLMRegisteredPhase18AuthorizationTestSeal(
		t, fixture, aliasCore)
	aliasAuthorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		aliasContract, localPeer, fixture.inputs.identities.public)
	if err != nil || !reflect.DeepEqual(aliasAuthorization, want) {
		t.Fatalf("registry alias split authorization: equal=%v err=%v",
			reflect.DeepEqual(aliasAuthorization, want), err)
	}

	receipts := make([]formalGLMPSISourceBridgeReceiptV1,
		len(fixture.inputs.context.receipts))
	for index, receipt := range fixture.inputs.context.receipts {
		receipts[index] = receipt
		receipts[index].Core.PSIAttestation.AttestationID =
			fmt.Sprintf("attest_%064x", 1000+index)
		message, err := formalGLMPSISourceBridgeMessageV1(receipts[index].Core)
		if err != nil {
			t.Fatal(err)
		}
		receipts[index].Signature = formalGLMSignatureBase64URLV1(
			ed25519.Sign(
				fixture.inputs.identities.private[receipt.Core.SignerPeerName],
				message))
	}
	nonceCore, err := formalGLMBuildSourceContractCoreV1(
		unsignedEntry, receipts, fixture.plan, unsignedSampler,
		fixture.inputs.identities.public)
	if err != nil || !reflect.DeepEqual(nonceCore, fixture.core) {
		t.Fatalf("PSI nonce split source core: equal=%v err=%v",
			reflect.DeepEqual(nonceCore, fixture.core), err)
	}
	nonceContract := formalGLMRegisteredPhase18AuthorizationTestSeal(
		t, fixture, nonceCore)
	nonceAuthorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		nonceContract, localPeer, fixture.inputs.identities.public)
	if err != nil || !reflect.DeepEqual(nonceAuthorization, want) {
		t.Fatalf("PSI nonce split authorization: equal=%v err=%v",
			reflect.DeepEqual(nonceAuthorization, want), err)
	}

	legacy := fixture.inputs.plan
	legacy.RunID = sha256Hex([]byte("another legacy execution run"))
	legacy.Kernel.CapsuleSHA256 =
		sha256Hex([]byte("another legacy execution capsule"))
	registered, err := formalGLMBuildRegisteredExecutionPlanV1(
		legacy, fixture.inputs.resolution, fixture.inputs.artifact,
		fixture.inputs.dp, fixture.inputs.contract, fixture.inputs.bound,
		fixture.inputs.identities.public)
	if err != nil || !reflect.DeepEqual(registered, fixture.plan) {
		t.Fatalf("legacy run/capsule changed registered plan: equal=%v err=%v",
			reflect.DeepEqual(registered, fixture.plan), err)
	}
	runCore, err := formalGLMBuildSourceContractCoreV1(
		fixture.inputs.entry, fixture.inputs.context.receipts, registered,
		fixture.inputs.contract, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	runContract := formalGLMRegisteredPhase18AuthorizationTestSeal(
		t, fixture, runCore)
	runAuthorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		runContract, localPeer, fixture.inputs.identities.public)
	if err != nil || !reflect.DeepEqual(runAuthorization, want) {
		t.Fatalf("legacy run/capsule split authorization: equal=%v err=%v",
			reflect.DeepEqual(runAuthorization, want), err)
	}
}

func TestFormalGLMRegisteredPhase18AuthorizationKernelDeepCopy(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	encoded, err := json.Marshal(fixture.contract)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := formalGLMDecodeSourceContractV1(
		encoded, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		contract, fixture.plan.CustodianPeers[0], fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	contractKernel := &contract.Core.RegisteredExecutionPlan.ExecutionKernel
	authorizationKernel := &authorization.ExecutionKernel

	contractValue := reflect.ValueOf(contractKernel).Elem()
	authorizationValue := reflect.ValueOf(authorizationKernel).Elem()
	for index := 0; index < contractValue.NumField(); index++ {
		contractField := contractValue.Field(index)
		if contractField.Kind() != reflect.Slice {
			continue
		}
		name := contractValue.Type().Field(index).Name
		if contractField.Len() == 0 ||
			authorizationValue.Field(index).Len() != contractField.Len() {
			t.Fatalf("execution-kernel slice %s was not projected", name)
		}
		wantAuthorization := authorizationValue.Field(index).Index(0).String()
		contractField.Index(0).SetString("mutated-contract-" + name)
		if authorizationValue.Field(index).Index(0).String() != wantAuthorization {
			t.Fatalf("execution-kernel slice %s aliases source contract", name)
		}
		wantContract := contractField.Index(0).String()
		authorizationValue.Field(index).Index(0).SetString(
			"mutated-authorization-" + name)
		if contractField.Index(0).String() != wantContract {
			t.Fatalf("source-contract slice %s aliases authorization", name)
		}
	}
}

func TestFormalGLMRegisteredPhase18AuthorizationScienceKernelTamperDiverges(
	t *testing.T,
) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	want := formalGLMRegisteredPhase18AuthorizationTestBuild(
		t, fixture, fixture.plan.CustodianPeers[0])
	mutations := map[string]func(*formalGLMRegisteredPhase18AuthorizationV1){
		"canonical science": func(value *formalGLMRegisteredPhase18AuthorizationV1) {
			value.CanonicalScienceSHA256 = sha256Hex([]byte("other science"))
		},
		"kernel scalar": func(value *formalGLMRegisteredPhase18AuthorizationV1) {
			value.ExecutionKernel.FractionBits++
		},
		"kernel slice": func(value *formalGLMRegisteredPhase18AuthorizationV1) {
			value.ExecutionKernel.XUpper[0] = "1"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := formalGLMRegisteredPhase18AuthorizationTestClone(t, want)
			mutate(&changed)
			changed.AuthorizationSHA256 = ""
			digest, err := formalGLMRegisteredPhase18AuthorizationSHA256V1(changed)
			if err != nil || digest == want.AuthorizationSHA256 {
				t.Fatalf("tamper did not diverge: %q %v", digest, err)
			}
			changed.AuthorizationSHA256 = digest
			if err := formalGLMValidateRegisteredPhase18AuthorizationV1(
				changed, fixture.contract,
				fixture.inputs.identities.public); err == nil {
				t.Fatal("self-consistent science/kernel tamper was accepted")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase18AuthorizationRejectsContractAndLocalPeer(
	t *testing.T,
) {
	fixture := formalGLMSourceContractTestFixture(t, 5)
	localPeer := fixture.plan.CustodianPeers[0]
	if _, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		fixture.contract, "outsider", fixture.inputs.identities.public); err == nil {
		t.Fatal("outsider obtained a registered Phase18 authorization")
	}
	missing := fixture.contract
	missing.CustodianApprovals = append(
		[]jointDPBiomedicalGaussianSignature(nil),
		fixture.contract.CustodianApprovals[:4]...)
	if _, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		missing, localPeer, fixture.inputs.identities.public); err == nil {
		t.Fatal("K-1 source contract authorized Phase18")
	}
	tampered := fixture.contract
	tampered.CustodianApprovals = append(
		[]jointDPBiomedicalGaussianSignature(nil),
		fixture.contract.CustodianApprovals...)
	tampered.CustodianApprovals[0].Signature = append(
		[]byte(nil), tampered.CustodianApprovals[0].Signature...)
	tampered.CustodianApprovals[0].Signature[0] ^= 1
	if _, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		tampered, localPeer, fixture.inputs.identities.public); err == nil {
		t.Fatal("tampered K source contract authorized Phase18")
	}
}

func TestFormalGLMRegisteredPhase18AuthorizationDatasetAndPlanTamperDiverge(
	t *testing.T,
) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	localPeer := fixture.plan.CustodianPeers[0]
	want := formalGLMRegisteredPhase18AuthorizationTestBuild(
		t, fixture, localPeer)

	dataset := formalGLMRegisteredPhase18AuthorizationTestClone(t, want)
	dataset.LocalSource.DatasetVersion = "v2"
	dataset.AuthorizationSHA256 = ""
	datasetHash, err := formalGLMRegisteredPhase18AuthorizationSHA256V1(dataset)
	if err != nil || datasetHash == want.AuthorizationSHA256 {
		t.Fatalf("dataset tamper did not diverge: %q %v", datasetHash, err)
	}
	dataset.AuthorizationSHA256 = datasetHash
	if err := formalGLMValidateRegisteredPhase18AuthorizationV1(
		dataset, fixture.contract, fixture.inputs.identities.public); err == nil {
		t.Fatal("self-consistent dataset tamper was accepted")
	}

	geometry := formalGLMRegisteredPhase18AuthorizationTestClone(t, want)
	geometry.Geometry.TotalCapacity++
	geometry.AuthorizationSHA256 = ""
	geometryHash, err := formalGLMRegisteredPhase18AuthorizationSHA256V1(
		geometry)
	if err != nil || geometryHash == want.AuthorizationSHA256 {
		t.Fatalf("plan tamper did not diverge: %q %v", geometryHash, err)
	}
	geometry.AuthorizationSHA256 = geometryHash
	if err := formalGLMValidateRegisteredPhase18AuthorizationV1(
		geometry, fixture.contract, fixture.inputs.identities.public); err == nil {
		t.Fatal("self-consistent plan geometry tamper was accepted")
	}
}

func TestFormalGLMRegisteredPhase18AuthorizationSourceContextTamperDiverges(
	t *testing.T,
) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	want := formalGLMRegisteredPhase18AuthorizationTestBuild(
		t, fixture, fixture.plan.CustodianPeers[0])
	mutations := map[string]func(*formalGLMRegisteredPhase18AuthorizationV1){
		"bridge set": func(value *formalGLMRegisteredPhase18AuthorizationV1) {
			value.BridgeSetSHA256 = sha256Hex([]byte("another bridge set"))
		},
		"logical snapshot JSON": func(value *formalGLMRegisteredPhase18AuthorizationV1) {
			value.LogicalSnapshotJSON = `{"logical_snapshot_id":"other"}`
		},
		"logical snapshot hash": func(value *formalGLMRegisteredPhase18AuthorizationV1) {
			value.LogicalSnapshotSHA256 = sha256Hex([]byte("another snapshot"))
		},
		"R pinset": func(value *formalGLMRegisteredPhase18AuthorizationV1) {
			value.RPinsetID = "pinset_" + strings.Repeat("a", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := formalGLMRegisteredPhase18AuthorizationTestClone(t, want)
			mutate(&changed)
			changed.AuthorizationSHA256 = ""
			digest, err := formalGLMRegisteredPhase18AuthorizationSHA256V1(changed)
			if err != nil || digest == want.AuthorizationSHA256 {
				t.Fatalf("source context tamper did not diverge: %q %v", digest, err)
			}
			changed.AuthorizationSHA256 = digest
			if err := formalGLMValidateRegisteredPhase18AuthorizationV1(
				changed, fixture.contract,
				fixture.inputs.identities.public); err == nil {
				t.Fatal("self-consistent source context tamper was accepted")
			}
		})
	}
}
