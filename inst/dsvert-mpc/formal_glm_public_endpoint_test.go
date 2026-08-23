package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type formalGLMPublicEndpointTestFixture struct {
	phase21    formalGLMPhase21SamplerV2TestFixture
	store      *formalGLMArtifactRegistryStoreV1
	receipts   []formalGLMPSISourceBridgeReceiptV1
	selector   formalGLMPublicSelectorV1
	resolution formalGLMArtifactRegistryResolutionV1
}

type formalGLMPublicEndpointProvisionTestRock struct {
	peer               string
	registryDir        string
	bridgeStoreDir     string
	samplerRootDir     string
	samplerContractDir string
	sourceContractDir  string
	store              *formalGLMArtifactRegistryStoreV1
	bridgeStore        *formalGLMPublicBridgeStoreV1
	samplerRoot        *formalGLMSamplerV2AuthorityRootStoreV1
	samplerContracts   *formalGLMSamplerV2ContractStoreV1
	sourceContracts    *formalGLMSourceContractStoreV1
	endpoint           *formalGLMPublicEndpointV1
	prepareCalls       int
	approveCalls       int
	commitCalls        int
	lifecycleCalls     int
}

func formalGLMPublicEndpointProvisionTestBundle(
	t testing.TB, receipts []string,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(formalGLMPublicProvisionBundleV1{
		Version:           formalGLMPublicProvisionBundleVersion,
		Purpose:           formalGLMPublicProvisionPurpose,
		ReceiptFramesJSON: append([]string(nil), receipts...),
		ProductionReady:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalGLMPublicEndpointProvisionTestSignUnchecked(
	t testing.TB, endpoint *formalGLMPublicEndpointV1,
	receipt formalGLMPublicReceiptFrameV1,
) string {
	t.Helper()
	receipt.Version = formalGLMPublicReceiptVersion
	receipt.Purpose = formalGLMPublicReceiptPurpose
	receipt.SignerPeerName = endpoint.signerPeer
	receipt.SignerIdentityPK = formalGLMIdentityPKV1(
		endpoint.pins[endpoint.signerPeer])
	receipt.ProductionReady = false
	receipt.Signature = ""
	message, err := formalGLMPublicReceiptMessageV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = formalGLMSignatureBase64URLV1(
		ed25519.Sign(endpoint.signerKey, message))
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestFormalGLMPublicEndpointSourceContractTwoRoundShape(t *testing.T) {
	tests := []struct {
		value any
		field string
		tag   string
	}{
		{formalGLMPublicProvisionApproveV1{}, "UnsignedSourceContractCore",
			"unsigned_source_contract_core"},
		{formalGLMPublicProvisionApproveV1{}, "SourceContractApproval",
			"source_contract_approval"},
		{formalGLMPublicProvisionApproveSetV1{}, "SourceContract", ""},
		{formalGLMPublicProvisionerV1{}, "SourceContractStore", ""},
	}
	for _, test := range tests {
		field, ok := reflect.TypeOf(test.value).FieldByName(test.field)
		if !ok {
			t.Fatalf("%T lacks %s", test.value, test.field)
		}
		if test.tag != "" && field.Tag.Get("json") != test.tag {
			t.Fatalf("%T.%s JSON tag = %q, want %q",
				test.value, test.field, field.Tag.Get("json"), test.tag)
		}
	}
}

func TestFormalGLMPublicEndpointRejectsInvalidSourceContractStore(t *testing.T) {
	fixture := formalGLMPublicEndpointTestSetup(t, 2)
	root := t.TempDir()
	samplerStore, err := newFormalGLMSamplerV2ContractStoreV1(
		filepath.Join(root, "sampler"), fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(samplerStore.Close)
	sourceStore, err := newFormalGLMSourceContractStoreV1(
		filepath.Join(root, "source"), fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sourceStore.Close)
	provisioner := formalGLMPublicProvisionerV1{
		SamplerV2ContractStore: samplerStore,
		SourceContractStore:    sourceStore,
		Prepare: func(formalGLMPublicSelectorV1) (
			formalGLMPublicProvisionPrepareV1, bool, error,
		) {
			return formalGLMPublicProvisionPrepareV1{}, false,
				fmt.Errorf("unexpected prepare")
		},
		Approve: func(formalGLMPublicProvisionPrepareSetV1) (
			formalGLMPublicProvisionApproveDraftV1, error,
		) {
			return formalGLMPublicProvisionApproveDraftV1{},
				fmt.Errorf("unexpected approve")
		},
		Commit: func(formalGLMArtifactRegistryEntryV1) (
			formalGLMArtifactRegistryResolutionV1, bool, error,
		) {
			return formalGLMArtifactRegistryResolutionV1{}, false,
				fmt.Errorf("unexpected commit")
		},
	}
	newEndpoint := func(candidate formalGLMPublicProvisionerV1) error {
		peer := fixture.phase21.artifact.CustodianPeers[0]
		_, endpointErr := newFormalGLMPublicEndpointV1(
			fixture.store, fixture.receipts, fixture.phase21.pins,
			peer, fixture.phase21.keys[peer], nil, candidate)
		return endpointErr
	}
	if err := newEndpoint(provisioner); err != nil {
		t.Fatalf("valid source contract store rejected: %v", err)
	}

	missing := provisioner
	missing.SourceContractStore = nil
	if err := newEndpoint(missing); err == nil {
		t.Fatal("nil source contract store accepted")
	}

	mismatchedPins := make(map[string]ed25519.PublicKey,
		len(fixture.phase21.pins))
	for peer, pin := range fixture.phase21.pins {
		mismatchedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	mismatchedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedPins[fixture.phase21.artifact.CustodianPeers[0]] =
		mismatchedPublic
	mismatchedStore, err := newFormalGLMSourceContractStoreV1(
		filepath.Join(root, "mismatched-source"), mismatchedPins)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mismatchedStore.Close)
	mismatched := provisioner
	mismatched.SourceContractStore = mismatchedStore
	if err := newEndpoint(mismatched); err == nil {
		t.Fatal("source contract store with different pinset accepted")
	}
}

func TestFormalGLMPublicEndpointAcceptsPoissonSelectorK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			plan, identities := formalGLMPreSourceDescriptorTestPlan(
				t, "poisson", custodians)
			context := formalGLMPreSourceDescriptorTestBuild(
				t, plan, identities,
				`{"columns":["outcome","group"],"version":"v1"}`,
				nil, nil)
			columns := make([]formalGLMPublicSelectorColumnV1,
				len(context.draft.DescriptorCore.UsedColumns))
			for index, column := range context.draft.DescriptorCore.UsedColumns {
				columns[index] = formalGLMPublicSelectorColumnV1{
					Owner: column.Owner, Column: column.Column,
					Kind: column.Kind, Role: column.Role,
				}
			}
			selector := formalGLMPublicSelectorV1{
				Version:                   formalGLMPublicSelectorVersion,
				Purpose:                   formalGLMPublicSelectorPurpose,
				Family:                    "poisson",
				CanonicalQualifiedFormula: context.draft.DescriptorCore.CanonicalQualifiedFormula,
				FormalAnalysisID:          "poisson-analysis",
				Federation: formalGLMPublicFederationSelectorV1{
					Version:     formalGLMPublicFederationSelectorVersion,
					Symbol:      "study",
					Attestation: context.receipts[0].Core.PSIAttestation,
					UsedColumns: columns,
				},
			}
			if err := formalGLMValidatePublicSelectorV1(
				selector, context.receipts, identities.public); err != nil {
				t.Fatal(err)
			}
			binomial := selector
			binomial.Family = "binomial"
			if err := formalGLMValidatePublicSelectorV1(
				binomial, context.receipts, identities.public); err == nil {
				t.Fatal("binomial selector accepted a count response")
			}
			invalid := selector
			invalid.Federation.UsedColumns = append(
				[]formalGLMPublicSelectorColumnV1(nil),
				selector.Federation.UsedColumns...)
			invalid.Federation.UsedColumns[0].Role = "predictor"
			invalid.Federation.UsedColumns[1].Role = "response"
			if err := formalGLMValidatePublicSelectorV1(
				invalid, context.receipts, identities.public); err == nil {
				t.Fatal("Poisson selector accepted a count predictor")
			}
		})
	}
}

func TestFormalGLMPublicEndpointColdProvisionTwoRoundsK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			plan, identities := formalGLMPreSourceDescriptorTestPlan(
				t, "binomial", custodians)
			context := formalGLMPreSourceDescriptorTestBuild(
				t, plan, identities,
				`{"columns":["outcome","group","unselected"],"version":"v1"}`,
				nil, nil)
			aliases := []string{"analysis-primary", "analysis-secondary"}
			unsignedModel := context.model
			unsignedModel.CustodianApprovals = nil
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
				unsignedModel, bindings, plan, identities.public, aliases)
			if err != nil {
				t.Fatal(err)
			}
			draft, err := formalGLMBuildPreSourceProvisionDraftV1(
				context.model, context.receipts, plan, identities.public, aliases)
			if err != nil || template.ArtifactID != draft.ArtifactID ||
				template.DescriptorCoreSHA256 != draft.DescriptorCoreSHA256 ||
				!reflect.DeepEqual(template.UnsignedDescriptor,
					draft.UnsignedDescriptor) {
				t.Fatalf("provision template differs from K draft: %v", err)
			}
			canonicalDP, err := buildFormalGLMCanonicalPreSourceDPV1(plan)
			if err != nil {
				t.Fatal(err)
			}
			transcriptBound, err := formalGLMPhase19BuildTranscriptBoundV1(
				plan, canonicalDP)
			if err != nil {
				t.Fatal(err)
			}
			columns := make([]formalGLMPublicSelectorColumnV1,
				len(template.DescriptorCore.UsedColumns))
			for index, column := range template.DescriptorCore.UsedColumns {
				columns[index] = formalGLMPublicSelectorColumnV1{
					Owner: column.Owner, Column: column.Column,
					Kind: column.Kind, Role: column.Role,
				}
			}
			selector := formalGLMPublicSelectorV1{
				Version:                   formalGLMPublicSelectorVersion,
				Purpose:                   formalGLMPublicSelectorPurpose,
				Family:                    "binomial",
				CanonicalQualifiedFormula: template.DescriptorCore.CanonicalQualifiedFormula,
				FormalAnalysisID:          aliases[0],
				Federation: formalGLMPublicFederationSelectorV1{
					Version:     formalGLMPublicFederationSelectorVersion,
					Symbol:      "study",
					Attestation: context.receipts[0].Core.PSIAttestation,
					UsedColumns: columns,
				},
			}
			selectorSHA256, err := formalGLMPublicSelectorSHA256V1(selector)
			if err != nil {
				t.Fatal(err)
			}
			prepareFrames := make([]formalGLMPublicProvisionPrepareV1, custodians)
			for index, peer := range unsignedModel.CustodianPeers {
				descriptorApproval, err := formalGLMSignPublicDescriptorV1(
					template.UnsignedDescriptor, peer,
					identities.private[peer], identities.public)
				if err != nil {
					t.Fatal(err)
				}
				prepareFrames[index] = formalGLMPublicProvisionPrepareV1{
					Version:            formalGLMPublicProvisionPrepareVersion,
					Purpose:            formalGLMPublicProvisionPurpose,
					UnsignedModel:      unsignedModel,
					ModelApproval:      context.model.CustodianApprovals[index],
					PSIReceipt:         context.receipts[index],
					UnsignedDescriptor: template.UnsignedDescriptor,
					DescriptorApproval: descriptorApproval,
					Artifact:           template.Artifact,
					SamplerMode:        formalGLMPhase21SamplerV2OneDraw,
					ServerOwnedAliases: append([]string(nil), aliases...),
					ProductionReady:    false,
				}
			}

			root := t.TempDir()
			rocks := make([]formalGLMPublicEndpointProvisionTestRock, custodians)
			for index, peer := range unsignedModel.CustodianPeers {
				peerRoot := filepath.Join(root, peer)
				if err := os.Mkdir(peerRoot, 0700); err != nil {
					t.Fatal(err)
				}
				registryDir := filepath.Join(peerRoot, "registry")
				store, err := newFormalGLMArtifactRegistryStoreV1(
					registryDir, identities.public)
				if err != nil {
					t.Fatal(err)
				}
				bridgeStoreDir := filepath.Join(peerRoot, "public-bridge")
				bridgeStore, err := newFormalGLMPublicBridgeStoreV1(
					bridgeStoreDir, identities.public)
				if err != nil {
					store.Close()
					t.Fatal(err)
				}
				samplerRootDir := filepath.Join(peerRoot, "sampler-root")
				var samplerRoot *formalGLMSamplerV2AuthorityRootStoreV1
				authorityIndex := formalGLMPublicSamplerV2AuthorityIndexV1(
					template.Artifact, peer)
				if authorityIndex >= 0 {
					samplerRoot, err = newFormalGLMSamplerV2AuthorityRootStoreV1(
						samplerRootDir, peer,
						template.Artifact.NoiseAuthorities[authorityIndex].Role,
						identities.private[peer], identities.public)
					if err != nil {
						store.Close()
						bridgeStore.Close()
						t.Fatal(err)
					}
				}
				samplerContractDir := filepath.Join(peerRoot, "sampler-contract")
				samplerContracts, err := newFormalGLMSamplerV2ContractStoreV1(
					samplerContractDir, identities.public)
				if err != nil {
					store.Close()
					bridgeStore.Close()
					if samplerRoot != nil {
						samplerRoot.Close()
					}
					t.Fatal(err)
				}
				sourceContractDir := filepath.Join(peerRoot, "source-contract")
				sourceContracts, err := newFormalGLMSourceContractStoreV1(
					sourceContractDir, identities.public)
				if err != nil {
					store.Close()
					bridgeStore.Close()
					if samplerRoot != nil {
						samplerRoot.Close()
					}
					samplerContracts.Close()
					t.Fatal(err)
				}
				rocks[index] = formalGLMPublicEndpointProvisionTestRock{
					peer: peer, registryDir: registryDir,
					bridgeStoreDir: bridgeStoreDir, samplerRootDir: samplerRootDir,
					samplerContractDir: samplerContractDir,
					sourceContractDir:  sourceContractDir,
					store:              store, bridgeStore: bridgeStore,
					samplerRoot: samplerRoot, samplerContracts: samplerContracts,
					sourceContracts: sourceContracts,
				}
			}
			t.Cleanup(func() {
				for index := range rocks {
					rocks[index].store.Close()
					rocks[index].bridgeStore.Close()
					if rocks[index].samplerRoot != nil {
						rocks[index].samplerRoot.Close()
					}
					rocks[index].samplerContracts.Close()
					rocks[index].sourceContracts.Close()
				}
			})
			validatedPrepare := prepareFrames[0]
			commitment, err := rocks[0].samplerRoot.DeriveCommitment(
				template.ArtifactID, formalGLMPhase21SamplerV2OneDraw)
			if err != nil {
				t.Fatal(err)
			}
			validatedPrepare.NoiseCommitment = &commitment
			for _, invalidAliases := range [][]string{
				{"analysis-primary", "analysis-primary"},
				{"invalid alias"},
			} {
				invalid := validatedPrepare
				invalid.ServerOwnedAliases = invalidAliases
				if formalGLMValidatePublicProvisionPrepareV1(
					invalid, identities.public) == nil {
					t.Fatalf("invalid server-owned aliases accepted: %q",
						invalidAliases)
				}
			}

			provisionerFor := func(index int) formalGLMPublicProvisionerV1 {
				rock := &rocks[index]
				return formalGLMPublicProvisionerV1{
					SamplerV2AuthorityRootStore: rock.samplerRoot,
					SamplerV2ContractStore:      rock.samplerContracts,
					SourceContractStore:         rock.sourceContracts,
					Prepare: func(request formalGLMPublicSelectorV1) (
						formalGLMPublicProvisionPrepareV1, bool, error,
					) {
						rock.prepareCalls++
						return prepareFrames[index],
							request.Family == "binomial", nil
					},
					Approve: func(set formalGLMPublicProvisionPrepareSetV1) (
						formalGLMPublicProvisionApproveDraftV1, error,
					) {
						rock.approveCalls++
						if _, err := rock.bridgeStore.Commit(
							selectorSHA256, set.Descriptor.ArtifactID,
							set.Receipts); err != nil {
							return formalGLMPublicProvisionApproveDraftV1{}, err
						}
						bridgeSHA256, err := formalGLMPSISourceBridgeSetSHA256V1(
							set.Receipts, identities.public)
						if err != nil {
							return formalGLMPublicProvisionApproveDraftV1{}, err
						}
						entry := formalGLMArtifactRegistryEntryV1{
							Version:              formalGLMArtifactRegistryEntryVersion,
							Purpose:              formalGLMArtifactRegistryEntryPurpose,
							BridgeSetSHA256:      bridgeSHA256,
							FormalAnalysisIDs:    append([]string(nil), set.Aliases...),
							ArtifactID:           set.Descriptor.ArtifactID,
							Descriptor:           set.Descriptor,
							DescriptorCoreSHA256: set.Descriptor.DescriptorCoreSHA256,
							CustodianPeers:       append([]string(nil), set.Model.CustodianPeers...),
							CustodianCount:       set.Model.CustodianCount,
							ProductionReady:      false,
						}
						registeredPlan, err := formalGLMBuildRegisteredExecutionPlanV1(
							plan, formalGLMArtifactRegistryResolutionV1{
								ArtifactID: entry.ArtifactID, Descriptor: entry.Descriptor,
							}, set.Artifact, canonicalDP,
							set.UnsignedSamplerV2Contract, transcriptBound,
							identities.public)
						if err != nil {
							return formalGLMPublicProvisionApproveDraftV1{}, err
						}
						return formalGLMPublicProvisionApproveDraftV1{
							Descriptor: set.Descriptor, UnsignedEntry: entry,
							RegisteredExecutionPlan: registeredPlan,
						}, nil
					},
					Commit: func(entry formalGLMArtifactRegistryEntryV1) (
						formalGLMArtifactRegistryResolutionV1, bool, error,
					) {
						source, sourceErr := rock.sourceContracts.Load(entry.ArtifactID)
						if sourceErr != nil ||
							source.Core.ArtifactID != entry.ArtifactID {
							return formalGLMArtifactRegistryResolutionV1{}, false,
								fmt.Errorf("registry commit preceded source contract CAS")
						}
						contract, loadErr := rock.samplerContracts.Load(
							entry.ArtifactID)
						if loadErr != nil || contract.ArtifactID != entry.ArtifactID {
							return formalGLMArtifactRegistryResolutionV1{}, false,
								fmt.Errorf("registry commit preceded sampler-v2 contract CAS")
						}
						rock.commitCalls++
						replayed, err := rock.store.Commit(entry)
						return formalGLMArtifactRegistryResolutionV1{
							ArtifactID: entry.ArtifactID,
							Descriptor: entry.Descriptor,
						}, replayed, err
					},
				}
			}

			for index := range rocks {
				rock := &rocks[index]
				endpoint, err := newFormalGLMPublicEndpointV1(
					rock.store,
					[]formalGLMPSISourceBridgeReceiptV1{context.receipts[index]},
					identities.public, rock.peer, identities.private[rock.peer],
					func(formalGLMPublicAdvanceContextV1) (
						formalGLMPublicAdvanceObservationV1, error,
					) {
						rock.lifecycleCalls++
						return formalGLMPublicAdvanceObservationV1{}, nil
					}, provisionerFor(index))
				if err != nil {
					t.Fatal(err)
				}
				rock.endpoint = endpoint
			}

			prepareReceipts := make([]string, custodians)
			commitmentFrames := 0
			for index := range rocks {
				response, receipt := formalGLMPublicEndpointTestResolve(
					t, rocks[index].endpoint, selector)
				if receipt.State != formalGLMPublicStateProvisionPrepare ||
					receipt.Step != 0 || receipt.Provision == nil ||
					receipt.Resolution != nil || rocks[index].prepareCalls != 1 ||
					response.Version != formalGLMPublicResolveResponseVersion {
					t.Fatalf("cold local Resolve did not prepare: %+v", receipt)
				}
				prepareJSON, err := json.Marshal(receipt.Provision.Prepare)
				if err != nil {
					t.Fatal(err)
				}
				var samplerFields map[string]json.RawMessage
				if err := json.Unmarshal(prepareJSON, &samplerFields); err != nil ||
					samplerFields["artifact"] == nil ||
					samplerFields["sampler_mode"] == nil ||
					!reflect.DeepEqual(receipt.Provision.Prepare.Artifact,
						template.Artifact) ||
					receipt.Provision.Prepare.SamplerMode !=
						formalGLMPhase21SamplerV2OneDraw {
					t.Fatalf("prepare omits SamplerV2 binding: %s %v",
						prepareJSON, err)
				}
				authorityIndex := formalGLMPublicSamplerV2AuthorityIndexV1(
					template.Artifact, rocks[index].peer)
				if authorityIndex < 0 {
					if receipt.Provision.Prepare.NoiseCommitment != nil ||
						samplerFields["noise_commitment"] != nil ||
						rocks[index].samplerRoot != nil {
						t.Fatalf("witness received sampler-v2 authority state: %s",
							prepareJSON)
					}
				} else {
					want, deriveErr := rocks[index].samplerRoot.DeriveCommitment(
						template.ArtifactID, formalGLMPhase21SamplerV2OneDraw)
					if deriveErr != nil ||
						receipt.Provision.Prepare.NoiseCommitment == nil ||
						samplerFields["noise_commitment"] == nil ||
						!reflect.DeepEqual(
							*receipt.Provision.Prepare.NoiseCommitment, want) {
						t.Fatalf("authority did not publish its local commitment: %v",
							deriveErr)
					}
					commitmentFrames++
				}
				prepareReceipts[index] = response.ReceiptFrameJSON
			}
			if commitmentFrames != 2 {
				t.Fatalf("prepare published %d commitments, want exactly 2",
					commitmentFrames)
			}
			privateTokens := make([]string, 0, 16)
			for index := range rocks {
				privateTokens = append(privateTokens,
					rocks[index].samplerRootDir,
					rocks[index].samplerContractDir)
				if rocks[index].samplerRoot == nil {
					continue
				}
				keyBytes, readErr := os.ReadFile(filepath.Join(
					rocks[index].samplerRootDir,
					formalGLMSamplerV2AuthorityRootDir, rocks[index].peer,
					"authority-root.key"))
				if readErr != nil || len(keyBytes) != 32 {
					t.Fatalf("read test authority root: %v", readErr)
				}
				var authorityRoot [32]byte
				copy(authorityRoot[:], keyBytes)
				authorityIndex := formalGLMPublicSamplerV2AuthorityIndexV1(
					template.Artifact, rocks[index].peer)
				seed, _, deriveErr := formalGLMPhase21SamplerV2Derive(
					authorityRoot, template.ArtifactID,
					formalGLMPhase21SamplerV2OneDraw,
					template.Artifact.NoiseAuthorities[authorityIndex].Role,
					rocks[index].peer,
					template.Artifact.NoiseAuthorities[authorityIndex].PeerID)
				if deriveErr != nil {
					t.Fatal(deriveErr)
				}
				for _, secret := range [][]byte{keyBytes, seed[:]} {
					privateTokens = append(privateTokens,
						hex.EncodeToString(secret),
						base64.StdEncoding.EncodeToString(secret),
						base64.RawStdEncoding.EncodeToString(secret),
						base64.RawURLEncoding.EncodeToString(secret))
				}
				clear(authorityRoot[:])
				clear(seed[:])
				clear(keyBytes)
			}
			assertPublicOnly := func(label string, encoded []byte) {
				t.Helper()
				for _, token := range privateTokens {
					if token != "" && strings.Contains(string(encoded), token) {
						t.Fatalf("%s leaked private sampler-v2 material", label)
					}
				}
			}
			for _, encodedReceipt := range prepareReceipts {
				assertPublicOnly("prepare receipt", []byte(encodedReceipt))
			}
			prepareBundle := formalGLMPublicEndpointProvisionTestBundle(
				t, prepareReceipts)
			assertPublicOnly("prepare bundle", prepareBundle)
			mixedPrepareReceipts := make([]string, custodians)
			for index, encodedReceipt := range prepareReceipts {
				receipt, err := formalGLMValidatePublicEndpointReceiptV1(
					[]byte(encodedReceipt), identities.public)
				if err != nil {
					t.Fatal(err)
				}
				prepare := *receipt.Provision.Prepare
				prepare.ServerOwnedAliases = []string{
					"analysis-primary", "analysis-secondary", "analysis-third",
				}
				provision := *receipt.Provision
				provision.Prepare = &prepare
				receipt.Provision = &provision
				mixedPrepareReceipts[index], err =
					rocks[index].endpoint.signReceipt(receipt)
				if err != nil {
					t.Fatal(err)
				}
			}

			badPrepare := [][]string{
				append([]string(nil), prepareReceipts[:custodians-1]...),
				append(append([]string(nil), prepareReceipts...), prepareReceipts[0]),
				append([]string(nil), prepareReceipts...),
				append([]string(nil), prepareReceipts...),
				append([]string(nil), prepareReceipts...),
				mixedPrepareReceipts,
			}
			badPrepare[2][custodians-1] = badPrepare[2][0]
			badPrepare[3][0], badPrepare[3][1] = badPrepare[3][1], badPrepare[3][0]
			tampered := []byte(badPrepare[4][0])
			if tampered[len(tampered)-3] == 'A' {
				tampered[len(tampered)-3] = 'B'
			} else {
				tampered[len(tampered)-3] = 'A'
			}
			badPrepare[4][0] = string(tampered)

			secondAuthority, err := formalGLMValidatePublicEndpointReceiptV1(
				[]byte(prepareReceipts[1]), identities.public)
			if err != nil {
				t.Fatal(err)
			}
			missingCommitment := append([]string(nil), prepareReceipts...)
			missingFrame := secondAuthority
			missingPrepare := *missingFrame.Provision.Prepare
			missingPrepare.NoiseCommitment = nil
			missingPayload := *missingFrame.Provision
			missingPayload.Prepare = &missingPrepare
			missingFrame.Provision = &missingPayload
			missingCommitment[1] =
				formalGLMPublicEndpointProvisionTestSignUnchecked(
					t, rocks[1].endpoint, missingFrame)

			firstAuthority, err := formalGLMValidatePublicEndpointReceiptV1(
				[]byte(prepareReceipts[0]), identities.public)
			if err != nil || firstAuthority.Provision.Prepare.NoiseCommitment == nil {
				t.Fatal("missing first authority commitment fixture")
			}
			reorderedCommitment := append([]string(nil), prepareReceipts...)
			reorderedFrame := secondAuthority
			reorderedPrepare := *reorderedFrame.Provision.Prepare
			reorderedValue := *firstAuthority.Provision.Prepare.NoiseCommitment
			reorderedPrepare.NoiseCommitment = &reorderedValue
			reorderedPayload := *reorderedFrame.Provision
			reorderedPayload.Prepare = &reorderedPrepare
			reorderedFrame.Provision = &reorderedPayload
			reorderedCommitment[1] =
				formalGLMPublicEndpointProvisionTestSignUnchecked(
					t, rocks[1].endpoint, reorderedFrame)

			crossArtifact := append([]string(nil), prepareReceipts...)
			crossFrame := secondAuthority
			crossPrepare := *crossFrame.Provision.Prepare
			crossPrepare.Artifact.CanonicalLinkSHA256 =
				sha256Hex([]byte(t.Name() + "/cross-artifact-link"))
			crossArtifactID, err := formalGLMPhase21StickyArtifactID(
				crossPrepare.Artifact)
			if err != nil {
				t.Fatal(err)
			}
			crossPrepare.UnsignedDescriptor.ArtifactID = crossArtifactID
			crossPrepare.DescriptorApproval, err = formalGLMSignPublicDescriptorV1(
				crossPrepare.UnsignedDescriptor, rocks[1].peer,
				identities.private[rocks[1].peer], identities.public)
			if err != nil {
				t.Fatal(err)
			}
			crossCommitment, err := rocks[1].samplerRoot.DeriveCommitment(
				crossArtifactID, formalGLMPhase21SamplerV2OneDraw)
			if err != nil {
				t.Fatal(err)
			}
			crossPrepare.NoiseCommitment = &crossCommitment
			crossPayload := *crossFrame.Provision
			crossPayload.Prepare = &crossPrepare
			crossFrame.Provision = &crossPayload
			crossArtifact[1], err = rocks[1].endpoint.signReceipt(crossFrame)
			if err != nil {
				t.Fatalf("cross-Artifact fixture was not individually valid: %v", err)
			}

			badPrepare = append(badPrepare,
				missingCommitment, reorderedCommitment, crossArtifact)
			if custodians > 2 {
				extraCommitment := append([]string(nil), prepareReceipts...)
				witnessFrame, decodeErr := formalGLMValidatePublicEndpointReceiptV1(
					[]byte(prepareReceipts[2]), identities.public)
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				witnessPrepare := *witnessFrame.Provision.Prepare
				extraValue := *firstAuthority.Provision.Prepare.NoiseCommitment
				witnessPrepare.NoiseCommitment = &extraValue
				witnessPayload := *witnessFrame.Provision
				witnessPayload.Prepare = &witnessPrepare
				witnessFrame.Provision = &witnessPayload
				extraCommitment[2] =
					formalGLMPublicEndpointProvisionTestSignUnchecked(
						t, rocks[2].endpoint, witnessFrame)
				badPrepare = append(badPrepare, extraCommitment)
			}
			for _, frames := range badPrepare {
				failed, err := rocks[0].endpoint.Advance(
					[]byte(prepareReceipts[0]),
					formalGLMPublicEndpointProvisionTestBundle(t, frames))
				if err != nil || failed.State != formalGLMPublicStateFailed ||
					rocks[0].approveCalls != 0 ||
					len(rocks[0].endpoint.advanceInputs) != 0 ||
					len(rocks[0].endpoint.advanceCache) != 0 {
					t.Fatalf("invalid prepare bundle wedged receipt: %+v %v", failed, err)
				}
			}

			approveReceipts := make([]string, custodians)
			var unsignedSamplerV2 formalGLMPhase21SamplerV2Contract
			var unsignedSourceCore formalGLMSourceContractCoreV1
			for index := range rocks {
				response, err := rocks[index].endpoint.Advance(
					[]byte(prepareReceipts[index]), prepareBundle)
				if err != nil || response.State != formalGLMPublicStateProvision ||
					response.Relay != nil || response.PeerFrameJSON != "" ||
					response.PublicV2JSON != "" ||
					rocks[index].approveCalls != 1 ||
					rocks[index].lifecycleCalls != 0 {
					t.Fatalf("prepare Advance failed: %+v %v", response, err)
				}
				receipt, err := formalGLMValidatePublicEndpointReceiptV1(
					[]byte(response.ReceiptFrameJSON), identities.public)
				if err != nil || receipt.State != formalGLMPublicStateProvisionApprove ||
					receipt.Step != 1 || receipt.Resolution != nil ||
					receipt.Provision == nil || receipt.Provision.Approve == nil ||
					receipt.Provision.Approve.SamplerV2Approval.Signer !=
						rocks[index].peer ||
					receipt.Provision.Approve.SourceContractApproval.Signer !=
						rocks[index].peer ||
					len(receipt.Provision.Approve.UnsignedSamplerV2Contract.
						CustodianSignatures) != 0 {
					t.Fatalf("invalid approve receipt: %+v %v", receipt, err)
				}
				if index == 0 {
					unsignedSamplerV2 =
						receipt.Provision.Approve.UnsignedSamplerV2Contract
					unsignedSourceCore =
						receipt.Provision.Approve.UnsignedSourceContractCore
				} else if !reflect.DeepEqual(
					receipt.Provision.Approve.UnsignedSamplerV2Contract,
					unsignedSamplerV2) || !reflect.DeepEqual(
					receipt.Provision.Approve.UnsignedSourceContractCore,
					unsignedSourceCore) {
					t.Fatal("custodians signed different unsigned provision contracts")
				}
				intent, intentErr := rocks[index].sourceContracts.LoadIntent(
					template.ArtifactID)
				if intentErr != nil || !reflect.DeepEqual(intent,
					receipt.Provision.Approve.UnsignedSourceContractCore) {
					t.Fatalf("source approval returned before exact durable intent: %v",
						intentErr)
				}
				if _, loadErr := rocks[index].sourceContracts.Load(
					template.ArtifactID); loadErr == nil {
					t.Fatal("source contract committed before K/K approval")
				}
				approveReceipts[index] = response.ReceiptFrameJSON
				replayedPrepare, replayErr := rocks[index].endpoint.Advance(
					[]byte(prepareReceipts[index]), prepareBundle)
				if replayErr != nil || !replayedPrepare.Replayed ||
					replayedPrepare.ReceiptFrameJSON != response.ReceiptFrameJSON ||
					rocks[index].approveCalls != 1 {
					t.Fatalf("prepare replay changed sampler-v2 approval: %+v %v",
						replayedPrepare, replayErr)
				}
			}
			approveBundle := formalGLMPublicEndpointProvisionTestBundle(
				t, approveReceipts)
			for _, encodedReceipt := range approveReceipts {
				assertPublicOnly("approve receipt", []byte(encodedReceipt))
			}
			assertPublicOnly("approve bundle", approveBundle)
			approveSet, err := formalGLMPublicValidateApproveBundleV1(
				approveBundle, selectorSHA256, rocks[0].peer,
				formalGLMPublicReceiptSHA256V1([]byte(approveReceipts[0])),
				identities.public)
			if err != nil ||
				formalGLMValidateSourceContractV1(
					approveSet.SourceContract, identities.public) != nil ||
				len(approveSet.SourceContract.CustodianApprovals) != custodians ||
				formalGLMPhase21ValidateSamplerV2Contract(
					approveSet.SamplerV2Contract, identities.public) != nil ||
				len(approveSet.SamplerV2Contract.CustodianSignatures) != custodians {
				t.Fatalf("approve bundle did not seal K/K source/sampler: %+v %v",
					approveSet, err)
			}
			if custodians == 5 {
				alternateCore, cloneErr := formalGLMSourceContractCloneCoreV1(
					approveSet.SourceContract.Core)
				if cloneErr != nil {
					t.Fatal(cloneErr)
				}
				alternateCore.SourceBindingSet.Sources[0].SourceBindingID =
					"source_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				alternateCore.BridgeSetSHA256, err =
					formalGLMSourceBindingSetSHA256V1(
						alternateCore.SourceBindingSet, identities.public)
				if err != nil {
					t.Fatal(err)
				}
				alternateApprovals := make(
					[]jointDPBiomedicalGaussianSignature, custodians)
				for index, peer := range alternateCore.RegisteredExecutionPlan.
					CustodianPeers {
					alternateApprovals[index], err = formalGLMSignSourceContractV1(
						alternateCore, peer, identities.private[peer], identities.public)
					if err != nil {
						t.Fatal(err)
					}
				}
				alternateContract, sealErr := formalGLMSealSourceContractV1(
					alternateCore, alternateApprovals, identities.public)
				if sealErr != nil {
					t.Fatal(sealErr)
				}
				sourceConflictStore, openErr := newFormalGLMSourceContractStoreV1(
					filepath.Join(root, "source-conflict-"+rocks[0].peer),
					identities.public)
				if openErr != nil {
					t.Fatal(openErr)
				}
				if replayed, reserveErr := sourceConflictStore.Reserve(
					alternateCore); reserveErr != nil || replayed {
					sourceConflictStore.Close()
					t.Fatalf("stage conflicting source intent: %v %v",
						replayed, reserveErr)
				}
				if replayed, commitErr := sourceConflictStore.Commit(
					alternateContract); commitErr != nil || replayed {
					sourceConflictStore.Close()
					t.Fatalf("stage conflicting source contract: %v %v",
						replayed, commitErr)
				}
				samplerOrderStore, openErr := newFormalGLMSamplerV2ContractStoreV1(
					filepath.Join(root, "source-conflict-sampler-"+rocks[0].peer),
					identities.public)
				if openErr != nil {
					sourceConflictStore.Close()
					t.Fatal(openErr)
				}
				conflictProvisioner := provisionerFor(0)
				conflictProvisioner.SourceContractStore = sourceConflictStore
				conflictProvisioner.SamplerV2ContractStore = samplerOrderStore
				registryAttempts := 0
				conflictProvisioner.Commit = func(
					formalGLMArtifactRegistryEntryV1,
				) (formalGLMArtifactRegistryResolutionV1, bool, error) {
					registryAttempts++
					return formalGLMArtifactRegistryResolutionV1{}, false, nil
				}
				conflictEndpoint, endpointErr := newFormalGLMPublicEndpointV1(
					rocks[0].store, rocks[0].endpoint.bridgeReceipts,
					identities.public, rocks[0].peer,
					identities.private[rocks[0].peer], nil, conflictProvisioner)
				if endpointErr != nil {
					sourceConflictStore.Close()
					samplerOrderStore.Close()
					t.Fatal(endpointErr)
				}
				failed, advanceErr := conflictEndpoint.Advance(
					[]byte(approveReceipts[0]), approveBundle)
				_, samplerLoadErr := samplerOrderStore.Load(template.ArtifactID)
				sourceConflictStore.Close()
				samplerOrderStore.Close()
				if advanceErr != nil || failed.State != formalGLMPublicStateFailed ||
					samplerLoadErr == nil || registryAttempts != 0 {
					t.Fatalf("source conflict reached sampler/registry: %+v %v",
						failed, advanceErr)
				}
			}
			conflictingUnsigned := unsignedSamplerV2
			conflictingUnsigned.NoiseCommitments = append(
				[]formalGLMPhase21SamplerV2Commitment(nil),
				conflictingUnsigned.NoiseCommitments...)
			conflictingUnsigned.NoiseCommitments[0].SeedCommitmentSHA256 =
				sha256Hex([]byte(t.Name() + "/contract-cas-conflict"))
			conflictingApprovals := make(
				[]jointDPBiomedicalGaussianSignature, custodians)
			for index, peer := range conflictingUnsigned.CustodianPeers {
				conflictingApprovals[index], err =
					formalGLMPhase21SignSamplerV2Contract(
						conflictingUnsigned, peer, identities.private[peer])
				if err != nil {
					t.Fatal(err)
				}
			}
			conflictingContract, err := formalGLMPhase21SealSamplerV2Contract(
				conflictingUnsigned, conflictingApprovals, identities.public)
			if err != nil {
				t.Fatal(err)
			}
			conflictStore, err := newFormalGLMSamplerV2ContractStoreV1(
				filepath.Join(root, "contract-conflict-"+rocks[0].peer),
				identities.public)
			if err != nil {
				t.Fatal(err)
			}
			if replayed, commitErr := conflictStore.Commit(conflictingContract); commitErr != nil || replayed {
				conflictStore.Close()
				t.Fatalf("stage conflicting sampler-v2 contract: %v %v",
					replayed, commitErr)
			}
			conflictProvisioner := provisionerFor(0)
			conflictProvisioner.SamplerV2ContractStore = conflictStore
			registryAttempts := 0
			conflictProvisioner.Commit = func(
				formalGLMArtifactRegistryEntryV1,
			) (formalGLMArtifactRegistryResolutionV1, bool, error) {
				registryAttempts++
				return formalGLMArtifactRegistryResolutionV1{}, false, nil
			}
			conflictEndpoint, err := newFormalGLMPublicEndpointV1(
				rocks[0].store, rocks[0].endpoint.bridgeReceipts,
				identities.public, rocks[0].peer,
				identities.private[rocks[0].peer],
				func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					rocks[0].lifecycleCalls++
					return formalGLMPublicAdvanceObservationV1{}, nil
				}, conflictProvisioner)
			if err != nil {
				conflictStore.Close()
				t.Fatal(err)
			}
			conflictResponse, err := conflictEndpoint.Advance(
				[]byte(approveReceipts[0]), approveBundle)
			committedSource, sourceLoadErr := rocks[0].sourceContracts.Load(
				template.ArtifactID)
			conflictStore.Close()
			if err != nil || conflictResponse.State != formalGLMPublicStateFailed ||
				registryAttempts != 0 || rocks[0].lifecycleCalls != 0 ||
				sourceLoadErr != nil || !reflect.DeepEqual(
				committedSource, approveSet.SourceContract) {
				t.Fatalf("contract CAS conflict reached registry/lifecycle: %+v %v",
					conflictResponse, err)
			}

			badApprove := [][]string{
				append([]string(nil), approveReceipts[:custodians-1]...),
				append(append([]string(nil), approveReceipts...), approveReceipts[0]),
				append([]string(nil), approveReceipts...),
				append([]string(nil), approveReceipts...),
				append([]string(nil), approveReceipts...),
				append([]string(nil), approveReceipts...),
			}
			badApprove[2][custodians-1] = badApprove[2][0]
			badApprove[3][0], badApprove[3][1] = badApprove[3][1], badApprove[3][0]
			tampered = []byte(badApprove[4][0])
			if tampered[len(tampered)-3] == 'A' {
				tampered[len(tampered)-3] = 'B'
			} else {
				tampered[len(tampered)-3] = 'A'
			}
			badApprove[4][0] = string(tampered)
			originalApprove, err := formalGLMValidatePublicEndpointReceiptV1(
				[]byte(approveReceipts[0]), identities.public)
			if err != nil {
				t.Fatal(err)
			}
			relinked := originalApprove
			relinked.PreviousReceiptSHA256 = sha256Hex([]byte("other-chain"))
			relinked.PeerFrameSHA256 = sha256Hex([]byte("other-bundle"))
			relinkedJSON, err := rocks[0].endpoint.signReceipt(relinked)
			if err != nil {
				t.Fatal(err)
			}
			badApprove[5][0] = relinkedJSON

			secondApprove, err := formalGLMValidatePublicEndpointReceiptV1(
				[]byte(approveReceipts[1]), identities.public)
			if err != nil {
				t.Fatal(err)
			}
			disagreeingContract := append([]string(nil), approveReceipts...)
			disagreeingFrame := secondApprove
			disagreeingApprove := *disagreeingFrame.Provision.Approve
			disagreeingApprove.UnsignedSamplerV2Contract.NoiseCommitments = append(
				[]formalGLMPhase21SamplerV2Commitment(nil),
				disagreeingApprove.UnsignedSamplerV2Contract.NoiseCommitments...)
			disagreeingApprove.UnsignedSamplerV2Contract.
				NoiseCommitments[0].SeedCommitmentSHA256 =
				sha256Hex([]byte(t.Name() + "/tampered-contract-commitment"))
			samplerCoreSHA256, err :=
				formalGLMPhase21SamplerV2ContractCoreSHA256V1(
					disagreeingApprove.UnsignedSamplerV2Contract,
					identities.public)
			if err != nil {
				t.Fatal(err)
			}
			disagreeingApprove.UnsignedSourceContractCore.
				SamplerV2ContractCore =
				disagreeingApprove.UnsignedSamplerV2Contract
			disagreeingApprove.UnsignedSourceContractCore.
				RegisteredExecutionPlan.SamplerV2ContractCoreSHA256 =
				samplerCoreSHA256
			disagreeingApprove.UnsignedSourceContractCore.
				RegisteredExecutionPlan.PlanSHA256, err =
				formalGLMRegisteredExecutionPlanSHA256V1(
					disagreeingApprove.UnsignedSourceContractCore.
						RegisteredExecutionPlan)
			if err != nil {
				t.Fatal(err)
			}
			disagreeingApprove.SamplerV2Approval, err =
				formalGLMPhase21SignSamplerV2Contract(
					disagreeingApprove.UnsignedSamplerV2Contract,
					rocks[1].peer, identities.private[rocks[1].peer])
			if err != nil {
				t.Fatal(err)
			}
			disagreeingApprove.SourceContractApproval, err =
				formalGLMSignSourceContractV1(
					disagreeingApprove.UnsignedSourceContractCore,
					rocks[1].peer, identities.private[rocks[1].peer],
					identities.public)
			if err != nil {
				t.Fatal(err)
			}
			disagreeingPayload := *disagreeingFrame.Provision
			disagreeingPayload.Approve = &disagreeingApprove
			disagreeingFrame.Provision = &disagreeingPayload
			disagreeingContract[1], err = rocks[1].endpoint.signReceipt(
				disagreeingFrame)
			if err != nil {
				t.Fatalf("disagreeing contract fixture was not valid: %v", err)
			}

			crossSourceBinding := append([]string(nil), approveReceipts...)
			crossApprove := *secondApprove.Provision.Approve
			crossApprove.UnsignedSourceContractCore.SourceBindingSet.Sources[0].
				SourceBindingID = "source_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			crossApprove.UnsignedSourceContractCore.BridgeSetSHA256, err =
				formalGLMSourceBindingSetSHA256V1(
					crossApprove.UnsignedSourceContractCore.SourceBindingSet,
					identities.public)
			if err != nil {
				t.Fatal(err)
			}
			crossApprove.UnsignedEntry.BridgeSetSHA256 =
				crossApprove.UnsignedSourceContractCore.BridgeSetSHA256
			crossApprove.EntryApproval, err = formalGLMSignArtifactRegistryEntryV1(
				crossApprove.UnsignedEntry, rocks[1].peer,
				identities.private[rocks[1].peer], identities.public)
			if err != nil {
				t.Fatal(err)
			}
			crossApprove.SourceContractApproval, err =
				formalGLMSignSourceContractV1(
					crossApprove.UnsignedSourceContractCore,
					rocks[1].peer, identities.private[rocks[1].peer],
					identities.public)
			if err != nil {
				t.Fatal(err)
			}
			crossApproveFrame := secondApprove
			crossApprovePayload := *crossApproveFrame.Provision
			crossApprovePayload.Approve = &crossApprove
			crossApproveFrame.Provision = &crossApprovePayload
			crossSourceBinding[1], err = rocks[1].endpoint.signReceipt(
				crossApproveFrame)
			if err != nil {
				t.Fatalf("cross-source approve fixture was not valid: %v", err)
			}
			badApprove = append(badApprove,
				disagreeingContract, crossSourceBinding)
			for _, frames := range badApprove {
				failed, err := rocks[0].endpoint.Advance(
					[]byte(approveReceipts[0]),
					formalGLMPublicEndpointProvisionTestBundle(t, frames))
				if err != nil || failed.State != formalGLMPublicStateFailed ||
					rocks[0].commitCalls != 0 ||
					len(rocks[0].endpoint.advanceInputs) != 1 ||
					len(rocks[0].endpoint.advanceCache) != 1 {
					t.Fatalf("invalid approve bundle wedged receipt: %+v %v", failed, err)
				}
				if _, loadErr := rocks[0].samplerContracts.Load(
					draft.ArtifactID); loadErr == nil {
					t.Fatal("invalid approve bundle reached sampler-v2 contract CAS")
				}
			}

			uniqueReceipts := make([]string, custodians)
			for index := range rocks {
				response, err := rocks[index].endpoint.Advance(
					[]byte(approveReceipts[index]), approveBundle)
				if err != nil || response.State != formalGLMPublicStateProvision ||
					response.Replayed || rocks[index].commitCalls != 1 ||
					rocks[index].lifecycleCalls != 0 {
					t.Fatalf("approve Advance failed: %+v %v", response, err)
				}
				durableContract, loadErr := rocks[index].samplerContracts.Load(
					draft.ArtifactID)
				if loadErr != nil || !reflect.DeepEqual(
					durableContract, approveSet.SamplerV2Contract) {
					t.Fatalf("durable sampler-v2 contract differs: %+v %v",
						durableContract, loadErr)
				}
				durableSource, sourceErr := rocks[index].sourceContracts.Load(
					draft.ArtifactID)
				if sourceErr != nil || !reflect.DeepEqual(
					durableSource, approveSet.SourceContract) {
					t.Fatalf("durable source contract differs: %+v %v",
						durableSource, sourceErr)
				}
				receipt, err := formalGLMValidatePublicEndpointReceiptV1(
					[]byte(response.ReceiptFrameJSON), identities.public)
				if err != nil || receipt.State != formalGLMPublicResolveUnique ||
					receipt.Step != 2 || receipt.Resolution == nil ||
					receipt.Resolution.ArtifactID != draft.ArtifactID {
					t.Fatalf("invalid provisioned unique receipt: %+v %v", receipt, err)
				}
				uniqueReceipts[index] = response.ReceiptFrameJSON
				replayedApprove, replayErr := rocks[index].endpoint.Advance(
					[]byte(approveReceipts[index]), approveBundle)
				if replayErr != nil || !replayedApprove.Replayed ||
					replayedApprove.ReceiptFrameJSON != response.ReceiptFrameJSON ||
					rocks[index].commitCalls != 1 {
					t.Fatalf("approve replay changed provision result: %+v %v",
						replayedApprove, replayErr)
				}
			}

			for index := range rocks {
				rocks[index].store.Close()
				rocks[index].bridgeStore.Close()
				rocks[index].samplerContracts.Close()
				rocks[index].sourceContracts.Close()
				if rocks[index].samplerRoot != nil {
					rocks[index].samplerRoot.Close()
				}
				reopened, err := newFormalGLMArtifactRegistryStoreV1(
					rocks[index].registryDir, identities.public)
				if err != nil {
					t.Fatal(err)
				}
				rocks[index].store = reopened
				reopenedBridge, err := newFormalGLMPublicBridgeStoreV1(
					rocks[index].bridgeStoreDir, identities.public)
				if err != nil {
					t.Fatal(err)
				}
				rocks[index].bridgeStore = reopenedBridge
				reopenedContracts, err := newFormalGLMSamplerV2ContractStoreV1(
					rocks[index].samplerContractDir, identities.public)
				if err != nil {
					t.Fatal(err)
				}
				rocks[index].samplerContracts = reopenedContracts
				reopenedSource, err := newFormalGLMSourceContractStoreV1(
					rocks[index].sourceContractDir, identities.public)
				if err != nil {
					t.Fatal(err)
				}
				rocks[index].sourceContracts = reopenedSource
				authorityIndex := formalGLMPublicSamplerV2AuthorityIndexV1(
					template.Artifact, rocks[index].peer)
				rocks[index].samplerRoot = nil
				if authorityIndex >= 0 {
					reopenedRoot, openErr :=
						newFormalGLMSamplerV2AuthorityRootStoreV1(
							rocks[index].samplerRootDir, rocks[index].peer,
							template.Artifact.NoiseAuthorities[authorityIndex].Role,
							identities.private[rocks[index].peer], identities.public)
					if openErr != nil {
						t.Fatal(openErr)
					}
					rocks[index].samplerRoot = reopenedRoot
					want, deriveErr := reopenedRoot.DeriveCommitment(
						template.ArtifactID, formalGLMPhase21SamplerV2OneDraw)
					prepared, decodeErr := formalGLMValidatePublicEndpointReceiptV1(
						[]byte(prepareReceipts[index]), identities.public)
					if deriveErr != nil || decodeErr != nil ||
						prepared.Provision == nil || prepared.Provision.Prepare == nil ||
						prepared.Provision.Prepare.NoiseCommitment == nil ||
						!reflect.DeepEqual(
							*prepared.Provision.Prepare.NoiseCommitment, want) {
						t.Fatalf("authority-root restart changed commitment: %v %v",
							deriveErr, decodeErr)
					}
				}
				restartedContract, loadErr := reopenedContracts.Load(
					template.ArtifactID)
				if loadErr != nil || !reflect.DeepEqual(
					restartedContract, approveSet.SamplerV2Contract) {
					t.Fatalf("sampler-v2 contract restart mismatch: %+v %v",
						restartedContract, loadErr)
				}
				restartedSource, sourceErr := reopenedSource.Load(
					template.ArtifactID)
				if sourceErr != nil || !reflect.DeepEqual(
					restartedSource, approveSet.SourceContract) {
					t.Fatalf("source contract restart mismatch: %+v %v",
						restartedSource, sourceErr)
				}
				durableRecord, err := reopenedBridge.Load(selectorSHA256)
				if err != nil || durableRecord.ArtifactID != draft.ArtifactID {
					t.Fatalf("durable bridge binding differs: %+v %v",
						durableRecord, err)
				}
				endpoint, err := newFormalGLMPublicEndpointV1(
					reopened, durableRecord.Receipts, identities.public,
					rocks[index].peer, identities.private[rocks[index].peer],
					func(formalGLMPublicAdvanceContextV1) (
						formalGLMPublicAdvanceObservationV1, error,
					) {
						rocks[index].lifecycleCalls++
						return formalGLMPublicAdvanceObservationV1{}, nil
					}, provisionerFor(index))
				if err != nil {
					t.Fatal(err)
				}
				rocks[index].endpoint = endpoint
				replayed, err := endpoint.Advance(
					[]byte(approveReceipts[index]), approveBundle)
				if err != nil || replayed.State != formalGLMPublicStateProvision ||
					!replayed.Replayed || rocks[index].commitCalls != 2 ||
					replayed.ReceiptFrameJSON != uniqueReceipts[index] {
					t.Fatalf("restart CAS replay failed: %+v %v", replayed, err)
				}
				for _, alias := range aliases {
					selected := selector
					selected.FormalAnalysisID = alias
					_, receipt := formalGLMPublicEndpointTestResolve(
						t, endpoint, selected)
					if receipt.State != formalGLMPublicResolveUnique ||
						receipt.Resolution == nil ||
						receipt.Resolution.ArtifactID != draft.ArtifactID ||
						rocks[index].prepareCalls != 1 ||
						rocks[index].lifecycleCalls != 0 {
						t.Fatalf("restart alias did not resolve existing artifact: %+v",
							receipt)
					}
				}
			}
		})
	}
}

func formalGLMPublicEndpointTestSetup(
	t testing.TB, custodians int,
) formalGLMPublicEndpointTestFixture {
	t.Helper()
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, custodians, formalGLMPhase21SamplerV2OneDraw)
	formalGLMRegistryDescriptorTestNormalizeArtifact(&fixture)
	core := formalGLMRegistryDescriptorTestCore(t, fixture)
	coreSHA256, err := formalGLMPublicDescriptorCoreSHA256V1(core)
	if err != nil {
		t.Fatal(err)
	}
	artifact := fixture.artifact
	artifact.DescriptorCoreSHA256 = coreSHA256
	artifactID, err := formalGLMPhase21StickyArtifactID(artifact)
	if err != nil {
		t.Fatal(err)
	}
	fixture.artifact = artifact
	fixture.artifactID = artifactID
	fixture.contract = formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
		fixture.pins, fixture.keys, fixture.roots)
	descriptor := formalGLMRegistryDescriptorTestSignedDescriptor(
		t, fixture, core, artifactID)
	receipts := formalGLMRegistryDescriptorTestBridgeReceipts(
		t, fixture, coreSHA256)
	store, err := newFormalGLMArtifactRegistryStoreV1(
		filepath.Join(t.TempDir(), "registry"), fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	for _, entry := range []formalGLMArtifactRegistryEntryV1{
		formalGLMRegistryDescriptorTestEntry(
			t, fixture, receipts, descriptor, "primary"),
		formalGLMRegistryDescriptorTestEntry(
			t, fixture, receipts, descriptor, "alias"),
	} {
		if replay, commitErr := store.Commit(entry); commitErr != nil || replay {
			t.Fatalf("commit endpoint fixture: replay=%v err=%v", replay, commitErr)
		}
	}
	usedColumns := make([]formalGLMPublicSelectorColumnV1, len(core.UsedColumns))
	for index, column := range core.UsedColumns {
		usedColumns[index] = formalGLMPublicSelectorColumnV1{
			Owner: column.Owner, Column: column.Column,
			Kind: column.Kind, Role: column.Role,
		}
	}
	return formalGLMPublicEndpointTestFixture{
		phase21: fixture, store: store, receipts: receipts,
		resolution: formalGLMArtifactRegistryResolutionV1{
			ArtifactID: artifactID, Descriptor: descriptor,
		},
		selector: formalGLMPublicSelectorV1{
			Version:                   formalGLMPublicSelectorVersion,
			Purpose:                   formalGLMPublicSelectorPurpose,
			Family:                    "binomial",
			CanonicalQualifiedFormula: core.CanonicalQualifiedFormula,
			FormalAnalysisID:          "",
			Federation: formalGLMPublicFederationSelectorV1{
				Version: formalGLMPublicFederationSelectorVersion, Symbol: "study",
				Attestation: receipts[0].Core.PSIAttestation,
				UsedColumns: usedColumns,
			},
		},
	}
}

func formalGLMPublicEndpointTestNew(
	t testing.TB, fixture formalGLMPublicEndpointTestFixture,
	driver formalGLMPublicAdvanceFuncV1,
) *formalGLMPublicEndpointV1 {
	t.Helper()
	endpoint, err := newFormalGLMPublicEndpointV1(
		fixture.store, fixture.receipts, fixture.phase21.pins,
		fixture.phase21.artifact.CustodianPeers[0],
		fixture.phase21.keys[fixture.phase21.artifact.CustodianPeers[0]],
		driver)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func formalGLMPublicEndpointTestResolve(
	t testing.TB, endpoint *formalGLMPublicEndpointV1,
	selector formalGLMPublicSelectorV1,
) (formalGLMPublicResolveResponseV1, formalGLMPublicReceiptFrameV1) {
	t.Helper()
	selectorJSON, err := json.Marshal(selector)
	if err != nil {
		t.Fatal(err)
	}
	response, err := endpoint.Resolve(selectorJSON)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := formalGLMValidatePublicEndpointReceiptV1(
		[]byte(response.ReceiptFrameJSON), endpoint.pins)
	if err != nil {
		t.Fatal(err)
	}
	return response, receipt
}

func formalGLMPublicEndpointTestTerminal(
	t testing.TB, fixture formalGLMPublicEndpointTestFixture,
) formalGLMPublicTerminalEvidenceV1 {
	t.Helper()
	internal := formalGLMPhase21SamplerV2TestUnsignedCertificate(
		t, fixture.phase21)
	promoted, err := formalGLMPhase21PromoteDurableV2(
		internal, fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := formalGLMPhase21BuildPublicCertificateV2(
		promoted, fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := fixture.resolution.Descriptor
	publication.PublicDescriptor = &descriptor
	approvals := make([]jointDPBiomedicalGaussianSignature, 2)
	for index, authority := range fixture.phase21.artifact.NoiseAuthorities {
		approvals[index], err = formalGLMPhase21SignPublicCertificateV2(
			publication, authority.PeerName,
			fixture.phase21.keys[authority.PeerName], fixture.phase21.pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	publication, err = formalGLMPhase21SealPublicCertificateV2(
		publication, approvals, fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	authorities := make([]formalFinalizerHandoffAuthority, 2)
	for index, authority := range fixture.phase21.artifact.NoiseAuthorities {
		authorities[index] = formalFinalizerHandoffAuthority{
			PeerName: authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role,
		}
	}
	binding := formalFinalizerHandoffBinding{
		Family:              formalFinalizerHandoffFamilyGLM,
		Purpose:             formalFinalizerHandoffGLMPurpose,
		ArtifactID:          fixture.resolution.ArtifactID,
		FinalPairRootSHA256: sha256Hex([]byte(t.Name() + "/pair-root")),
		PlanSHA256:          fixture.phase21.artifact.CanonicalPlanSHA256,
		PinsetSHA256:        fixture.phase21.artifact.PinsetSHA256,
		Authorities:         authorities, Finalizer: authorities[0],
	}
	transport, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := formalFinalizerHandoffIssueTicket(
		binding, transport.PublicKey().Bytes(),
		fixture.phase21.keys[binding.Finalizer.PeerName], fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	certificateSHA256, err := formalGLMPhase21RockPublicCertificateDigest(
		publication)
	if err != nil {
		t.Fatal(err)
	}
	var commits [2]formalGLMPhase21RockCommitRecord
	var cleanups [2]formalGLMPhase21RockCleanupRecord
	for index, authority := range authorities {
		commitReceipt := formalGLMPhase21RockCommitReceipt{
			Version:           formalGLMPhase21RockRecordVersion,
			Purpose:           formalGLMPhase21RockCommitPurpose,
			ArtifactID:        fixture.resolution.ArtifactID,
			CertificateSHA256: certificateSHA256,
			PeerName:          authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role,
		}
		commitMessage, messageErr := formalGLMPhase21RockCommitMessage(
			commitReceipt)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		commitReceipt.Signature = ed25519.Sign(
			fixture.phase21.keys[authority.PeerName], commitMessage)
		commits[index] = formalGLMPhase21RockCommitRecord{
			Version: formalGLMPhase21RockRecordVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Purpose: formalGLMPhase21RockCommitPurpose,
			Receipt: commitReceipt, Publication: publication,
		}

		cleanupReceipt := formalGLMPhase21RockCleanupReceipt{
			Version:           formalGLMPhase21RockRecordVersion,
			Purpose:           formalGLMPhase21RockCleanupPurpose,
			ArtifactID:        fixture.resolution.ArtifactID,
			CertificateSHA256: certificateSHA256,
			PeerName:          authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role, SourceCleaned: true,
			LocalSpoolCleaned: true, TransportCleaned: true,
		}
		cleanupMessage, messageErr := formalGLMPhase21RockCleanupMessage(
			cleanupReceipt)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		cleanupReceipt.Signature = ed25519.Sign(
			fixture.phase21.keys[authority.PeerName], cleanupMessage)
		cleanups[index] = formalGLMPhase21RockCleanupRecord{
			Version: formalGLMPhase21RockRecordVersion,
			Family:  formalFinalizerHandoffFamilyGLM,
			Purpose: formalGLMPhase21RockCleanupPurpose,
			Receipt: cleanupReceipt, Publication: publication,
		}
	}
	ticketSHA256, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := formalFinalizerHandoffBuildCommitProof(
		binding, ticketSHA256, certificateSHA256,
		fixture.phase21.keys[binding.Finalizer.PeerName], fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMPublicTerminalEvidenceV1{
		Contract: fixture.phase21.contract, Binding: binding, Ticket: ticket,
		Publication: publication, Commits: commits,
		Ack: formalGLMPhase21RockAckRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockAckPurpose,
			ArtifactID: fixture.resolution.ArtifactID, Proof: proof,
		},
		Cleanups: cleanups,
	}
}

func formalGLMPublicEndpointTestCloneTerminal(
	t testing.TB, value formalGLMPublicTerminalEvidenceV1,
) formalGLMPublicTerminalEvidenceV1 {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned formalGLMPublicTerminalEvidenceV1
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestFormalGLMPublicEndpointCompleteRequiresDualCleanupK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicEndpointTestSetup(t, custodians)
			valid := formalGLMPublicEndpointTestTerminal(t, fixture)
			cases := []struct {
				name string
				edit func(*formalGLMPublicTerminalEvidenceV1)
				want string
			}{
				{name: "complete", want: formalGLMPublicStateComplete},
				{name: "missing-commit", want: formalGLMPublicStateFailed,
					edit: func(value *formalGLMPublicTerminalEvidenceV1) {
						value.Commits[1] = formalGLMPhase21RockCommitRecord{}
					}},
				{name: "reordered-commit", want: formalGLMPublicStateFailed,
					edit: func(value *formalGLMPublicTerminalEvidenceV1) {
						value.Commits[0], value.Commits[1] =
							value.Commits[1], value.Commits[0]
					}},
				{name: "tampered-ack", want: formalGLMPublicStateFailed,
					edit: func(value *formalGLMPublicTerminalEvidenceV1) {
						value.Ack.Proof.CertificateSHA256 = sha256Hex([]byte("tampered"))
					}},
				{name: "missing-cleanup", want: formalGLMPublicStateFailed,
					edit: func(value *formalGLMPublicTerminalEvidenceV1) {
						value.Cleanups[1] = formalGLMPhase21RockCleanupRecord{}
					}},
				{name: "reordered-cleanup", want: formalGLMPublicStateFailed,
					edit: func(value *formalGLMPublicTerminalEvidenceV1) {
						value.Cleanups[0], value.Cleanups[1] =
							value.Cleanups[1], value.Cleanups[0]
					}},
				{name: "tampered-cleanup", want: formalGLMPublicStateFailed,
					edit: func(value *formalGLMPublicTerminalEvidenceV1) {
						value.Cleanups[0].Receipt.TransportCleaned = false
					}},
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					evidence := formalGLMPublicEndpointTestCloneTerminal(t, valid)
					if test.edit != nil {
						test.edit(&evidence)
					}
					driverCalls := 0
					endpoint := formalGLMPublicEndpointTestNew(
						t, fixture, func(formalGLMPublicAdvanceContextV1) (
							formalGLMPublicAdvanceObservationV1, error,
						) {
							driverCalls++
							return formalGLMPublicAdvanceObservationV1{
								Terminal: &evidence,
							}, nil
						})
					resolved, receipt := formalGLMPublicEndpointTestResolve(
						t, endpoint, fixture.selector)
					response, err := endpoint.Advance(
						[]byte(resolved.ReceiptFrameJSON), nil)
					if err != nil {
						t.Fatal(err)
					}
					if response.State != test.want || driverCalls != 1 {
						t.Fatalf("state=%s calls=%d", response.State, driverCalls)
					}
					next, err := formalGLMValidatePublicEndpointReceiptV1(
						[]byte(response.ReceiptFrameJSON), fixture.phase21.pins)
					if err != nil || next.State != test.want ||
						next.Step != receipt.Step+1 {
						t.Fatalf("invalid terminal receipt: %+v %v", next, err)
					}
					if test.want == formalGLMPublicStateComplete {
						if response.PublicV2JSON == "" ||
							!formalGLMIsSHA256(response.CertificateSHA256) ||
							response.Relay != nil || response.PeerFrameJSON != "" {
							t.Fatalf("invalid complete response: %+v", response)
						}
						replayed, err := endpoint.Advance(
							[]byte(resolved.ReceiptFrameJSON), nil)
						if err != nil || !replayed.Replayed || driverCalls != 1 ||
							replayed.ReceiptFrameJSON != response.ReceiptFrameJSON ||
							replayed.PublicV2JSON != response.PublicV2JSON {
							t.Fatalf("terminal replay reran driver: %+v calls=%d err=%v",
								replayed, driverCalls, err)
						}
					} else if response.PublicV2JSON != "" ||
						response.CertificateSHA256 != "" || response.Relay != nil {
						t.Fatalf("failed terminal leaked output: %+v", response)
					}
				})
			}
		})
	}
}

func TestFormalGLMPublicEndpointResolveStatesAndAliasCollapseK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicEndpointTestSetup(t, custodians)
			driverCalls := 0
			endpoint := formalGLMPublicEndpointTestNew(
				t, fixture, func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					driverCalls++
					return formalGLMPublicAdvanceObservationV1{Failed: true}, nil
				})

			response, receipt := formalGLMPublicEndpointTestResolve(
				t, endpoint, fixture.selector)
			if response.Version != formalGLMPublicResolveResponseVersion ||
				receipt.State != formalGLMPublicResolveUnique ||
				receipt.Resolution == nil ||
				!reflect.DeepEqual(*receipt.Resolution, fixture.resolution) {
				t.Fatalf("aliases did not collapse: response=%+v receipt=%+v",
					response, receipt)
			}
			encodedResponse, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			var responseFields map[string]json.RawMessage
			if err := json.Unmarshal(encodedResponse, &responseFields); err != nil ||
				len(responseFields) != 2 || responseFields["version"] == nil ||
				responseFields["receipt_frame_json"] == nil {
				t.Fatalf("Resolve response schema drifted: %s %v", encodedResponse, err)
			}

			alias := fixture.selector
			alias.FormalAnalysisID = "alias"
			_, aliasReceipt := formalGLMPublicEndpointTestResolve(t, endpoint, alias)
			if aliasReceipt.State != formalGLMPublicResolveUnique ||
				aliasReceipt.Resolution == nil ||
				aliasReceipt.Resolution.ArtifactID != fixture.resolution.ArtifactID {
				t.Fatalf("alias filter changed artifact: %+v", aliasReceipt)
			}

			missing := fixture.selector
			missing.FormalAnalysisID = "missing"
			_, missingReceipt := formalGLMPublicEndpointTestResolve(
				t, endpoint, missing)
			if missingReceipt.State != formalGLMPublicResolveAbsent ||
				missingReceipt.Resolution != nil {
				t.Fatalf("missing selector was not signed absent: %+v", missingReceipt)
			}

			alternateID := sha256Hex([]byte(t.Name() + "/alternate"))
			alternateDescriptor := formalGLMRegistryDescriptorTestSignedDescriptor(
				t, fixture.phase21, fixture.resolution.Descriptor.Descriptor,
				alternateID)
			alternateEntry := formalGLMRegistryDescriptorTestEntry(
				t, fixture.phase21, fixture.receipts, alternateDescriptor, "other")
			if replay, err := fixture.store.Commit(alternateEntry); err != nil || replay {
				t.Fatalf("commit alternate: replay=%v err=%v", replay, err)
			}
			_, ambiguous := formalGLMPublicEndpointTestResolve(
				t, endpoint, fixture.selector)
			if ambiguous.State != formalGLMPublicResolveAmbiguous ||
				ambiguous.Resolution != nil {
				t.Fatalf("many-match selector was not signed ambiguous: %+v", ambiguous)
			}

			tamperedReceipt := []byte(response.ReceiptFrameJSON)
			tamperedReceipt = append([]byte(nil), tamperedReceipt...)
			tamperedReceipt[len(tamperedReceipt)-2] ^= 1
			if _, err := endpoint.Advance(tamperedReceipt, nil); err == nil ||
				driverCalls != 0 {
				t.Fatalf("tampered receipt reached driver: calls=%d err=%v",
					driverCalls, err)
			}
		})
	}
}

func formalGLMPublicEndpointTestControlFrame(
	t *testing.T, fixture formalGLMPublicEndpointTestFixture,
	terminal formalGLMPublicTerminalEvidenceV1,
) []byte {
	t.Helper()
	handoff := formalFinalizerHandoffTestFixture{
		binding: terminal.Binding, public: fixture.phase21.pins,
		private: fixture.phase21.keys,
	}
	record := formalGLMControlTestRecord(
		t, formalGLMControlRecordStage, "garbler", handoff, terminal.Ticket)
	recipient := terminal.Binding.Authorities[1]
	transport, signature := formalGLMControlTestTransport(
		t, fixture.phase21.keys[recipient.PeerName])
	envelope, err := formalGLMOneDrawControlSeal(
		terminal.Binding, formalGLMControlRecordStage, "garbler", record,
		terminal.Ticket, transport.PublicKey().Bytes(), signature,
		fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := formalGLMControlMarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalGLMPublicEndpointRelayBoundsAndReplayK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicEndpointTestSetup(t, custodians)
			terminal := formalGLMPublicEndpointTestTerminal(t, fixture)
			controlFrame := formalGLMPublicEndpointTestControlFrame(
				t, fixture, terminal)
			driverCalls := 0
			endpoint := formalGLMPublicEndpointTestNew(
				t, fixture, func(context formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					driverCalls++
					if len(context.PeerFrameJSON) != 0 {
						t.Fatal("first server-owned transition received a peer frame")
					}
					return formalGLMPublicAdvanceObservationV1{
						Binding: &terminal.Binding, ControlFrameJSON: controlFrame,
					}, nil
				})
			resolved, _ := formalGLMPublicEndpointTestResolve(
				t, endpoint, fixture.selector)
			response, err := endpoint.Advance(
				[]byte(resolved.ReceiptFrameJSON), nil)
			if err != nil || response.State != formalGLMPublicStateRelay ||
				response.Relay == nil ||
				response.Relay.Channel != formalGLMPublicRelayControl ||
				response.Relay.SenderPeerName != terminal.Binding.Authorities[0].PeerName ||
				response.Relay.RecipientPeerName != terminal.Binding.Authorities[1].PeerName ||
				response.PeerFrameJSON != string(controlFrame) ||
				response.PeerFrameRecipient != terminal.Binding.Authorities[1].PeerName ||
				response.PublicV2JSON != "" || response.CertificateSHA256 != "" {
				t.Fatalf("invalid control relay: %+v %v", response, err)
			}
			replayed, err := endpoint.Advance(
				[]byte(resolved.ReceiptFrameJSON), nil)
			if err != nil || !replayed.Replayed || driverCalls != 1 ||
				replayed.ReceiptFrameJSON != response.ReceiptFrameJSON {
				t.Fatalf("relay replay reran driver: %+v calls=%d err=%v",
					replayed, driverCalls, err)
			}

			opening := []byte(`{"version":"opaque-opening-v1"}`)
			openingEndpoint := formalGLMPublicEndpointTestNew(
				t, fixture, func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					return formalGLMPublicAdvanceObservationV1{
						Binding: &terminal.Binding, OpeningFrameJSON: opening,
						OpeningSender:    terminal.Binding.Authorities[1].PeerName,
						OpeningRecipient: terminal.Binding.Authorities[0].PeerName,
					}, nil
				})
			openingResolved, _ := formalGLMPublicEndpointTestResolve(
				t, openingEndpoint, fixture.selector)
			openingResponse, err := openingEndpoint.Advance(
				[]byte(openingResolved.ReceiptFrameJSON), nil)
			if err != nil || openingResponse.State != formalGLMPublicStateRelay ||
				openingResponse.Relay == nil ||
				openingResponse.Relay.Channel != formalGLMPublicRelayOpening ||
				openingResponse.PeerFrameJSON != string(opening) {
				t.Fatalf("invalid opening relay: %+v %v", openingResponse, err)
			}

			boundedCalls := 0
			boundedEndpoint := formalGLMPublicEndpointTestNew(
				t, fixture, func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					boundedCalls++
					return formalGLMPublicAdvanceObservationV1{}, nil
				})
			boundedResolved, _ := formalGLMPublicEndpointTestResolve(
				t, boundedEndpoint, fixture.selector)
			oversized := make([]byte, formalGLMPublicMaxPeerFrameJSON+1)
			for index := range oversized {
				oversized[index] = 'x'
			}
			if _, err := boundedEndpoint.Advance(
				[]byte(boundedResolved.ReceiptFrameJSON), oversized); err == nil ||
				boundedCalls != 0 {
				t.Fatalf("oversized peer frame reached driver: calls=%d err=%v",
					boundedCalls, err)
			}

			var tamperedEnvelope formalGLMOneDrawControlEnvelope
			if err := json.Unmarshal(controlFrame, &tamperedEnvelope); err != nil {
				t.Fatal(err)
			}
			tamperedEnvelope.Ciphertext[0] ^= 1
			tamperedFrame, err := json.Marshal(tamperedEnvelope)
			if err != nil {
				t.Fatal(err)
			}
			tamperedEndpoint := formalGLMPublicEndpointTestNew(
				t, fixture, func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					return formalGLMPublicAdvanceObservationV1{
						Binding:          &terminal.Binding,
						ControlFrameJSON: tamperedFrame,
					}, nil
				})
			tamperedResolved, _ := formalGLMPublicEndpointTestResolve(
				t, tamperedEndpoint, fixture.selector)
			tamperedResponse, err := tamperedEndpoint.Advance(
				[]byte(tamperedResolved.ReceiptFrameJSON), nil)
			if err != nil || tamperedResponse.State != formalGLMPublicStateFailed ||
				tamperedResponse.Relay != nil || tamperedResponse.PeerFrameJSON != "" {
				t.Fatalf("tampered control frame did not fail closed: %+v %v",
					tamperedResponse, err)
			}
		})
	}
}

func TestFormalGLMPublicEndpointResolveK2ClosedSelector(t *testing.T) {
	fixture := formalGLMPublicEndpointTestSetup(t, 2)
	driverCalls := 0
	endpoint, err := newFormalGLMPublicEndpointV1(
		fixture.store, fixture.receipts, fixture.phase21.pins,
		fixture.phase21.artifact.CustodianPeers[0],
		fixture.phase21.keys[fixture.phase21.artifact.CustodianPeers[0]],
		func(context formalGLMPublicAdvanceContextV1) (
			formalGLMPublicAdvanceObservationV1, error,
		) {
			driverCalls++
			return formalGLMPublicAdvanceObservationV1{}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	selectorJSON, err := json.Marshal(fixture.selector)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := endpoint.Resolve(selectorJSON)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Version != formalGLMPublicResolveResponseVersion ||
		resolved.ReceiptFrameJSON == "" {
		t.Fatalf("unexpected resolve response: %+v", resolved)
	}
	receipt, err := formalGLMValidatePublicEndpointReceiptV1(
		[]byte(resolved.ReceiptFrameJSON), fixture.phase21.pins)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != formalGLMPublicResolveUnique ||
		receipt.Resolution == nil ||
		receipt.Resolution.ArtifactID != fixture.phase21.artifactID ||
		!reflect.DeepEqual(receipt.Resolution.Descriptor,
			formalGLMRegistryDescriptorTestSignedDescriptor(
				t, fixture.phase21,
				formalGLMRegistryDescriptorTestCore(t, fixture.phase21),
				fixture.phase21.artifactID)) ||
		receipt.ProductionReady {
		t.Fatalf("unexpected signed resolution receipt: %+v", receipt)
	}

	var unknown map[string]any
	if err := json.Unmarshal(selectorJSON, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["action"] = "seal"
	unknownJSON, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Resolve(unknownJSON); err == nil {
		t.Fatal("Resolve accepted analyst-controlled action")
	}

	tampered := fixture.selector
	tampered.Family = "poisson"
	tamperedJSON, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Resolve(tamperedJSON); err == nil {
		t.Fatal("Resolve accepted non-binomial selector tamper")
	}

	var receiptObject map[string]any
	if err := json.Unmarshal([]byte(resolved.ReceiptFrameJSON), &receiptObject); err != nil {
		t.Fatal(err)
	}
	receiptObject["action"] = "seal"
	tamperedReceipt, err := json.Marshal(receiptObject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Advance(tamperedReceipt, nil); err == nil {
		t.Fatal("Advance accepted caller-selected action")
	}
	if driverCalls != 0 {
		t.Fatalf("invalid Advance reached internal driver %d times", driverCalls)
	}
}
