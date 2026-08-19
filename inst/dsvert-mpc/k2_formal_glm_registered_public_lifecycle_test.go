package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func formalGLMRegisteredLifecycleTestResolution(t testing.TB,
	fixture formalGLMPhase21TestFixture,
	source formalGLMPhase21StickyArtifact,
	binding formalGLMPhase16ReleaseBinding,
) (formalGLMPhase21StickyArtifact, string,
	formalGLMArtifactRegistryResolutionV1) {
	t.Helper()
	peers := append([]string(nil), source.CustodianPeers...)
	response := peers[0] + "$outcome"
	predictors := make([]string, source.CoordinateCount-1)
	coefficientOrder := make([]string, source.CoordinateCount)
	termMap := make([]formalGLMPublicTermV1, source.CoordinateCount)
	coefficientOrder[0] = "(Intercept)"
	termMap[0] = formalGLMPublicTermV1{
		Index: 0, Coefficient: "(Intercept)", Kind: "intercept",
	}
	columns := []formalGLMPublicColumnV1{{
		Owner: peers[0], DatasetID: "dataset-" + peers[0],
		DatasetVersion: "v1", Column: "outcome", Role: "response",
		Kind: "binary", LowerRational: "0", UpperRational: "1",
	}}
	for index := range predictors {
		owner := peers[(index+1)%len(peers)]
		column := fmt.Sprintf("x%03d", index+1)
		predictors[index] = owner + "$" + column
		coefficientOrder[index+1] = predictors[index]
		termMap[index+1] = formalGLMPublicTermV1{
			Index: index + 1, Coefficient: predictors[index], Kind: "numeric",
			Owner: owner, SourceColumn: column,
		}
		columns = append(columns, formalGLMPublicColumnV1{
			Owner: owner, DatasetID: "dataset-" + owner,
			DatasetVersion: "v1", Column: column, Role: "predictor",
			Kind: "numeric", LowerRational: "-4", UpperRational: "4",
		})
	}
	sort.Slice(columns, func(i, j int) bool {
		return formalGLMPreSourceColumnSortKeyV1(columns[i]) <
			formalGLMPreSourceColumnSortKeyV1(columns[j])
	})
	formula, err := formalGLMCanonicalQualifiedFormulaV1(
		response + " ~ 1" + func() string {
			if len(predictors) == 0 {
				return ""
			}
			return " + " + strings.Join(predictors, " + ")
		}())
	if err != nil {
		t.Fatal(err)
	}
	projectedSchema := sha256Hex([]byte(t.Name() + "/selected-schema"))
	core := formalGLMPublicDescriptorCoreV1{
		Version:                        formalGLMPublicDescriptorCoreVersion,
		Purpose:                        formalGLMPublicDescriptorCorePurpose,
		Family:                         source.Family,
		CanonicalQualifiedFormula:      formula.Canonical,
		FormulaSHA256:                  formula.SHA256,
		CoefficientOrder:               coefficientOrder,
		TermMap:                        termMap,
		UsedColumns:                    columns,
		ShiftedUpperBounds:             append([]string(nil), binding.ShiftedUpperBounds...),
		OutputLatticeScale:             fmt.Sprintf("2^-%d", source.OutputLatticeBits),
		SourceFractionBits:             source.SourceFractionBits,
		QuantizationShift:              source.QuantizationShift,
		OutputLatticeBits:              source.OutputLatticeBits,
		Quantization:                   "signed_integer_shift_then_clamp_v1",
		CanonicalPreSourceDPSHA256:     sha256Hex([]byte(t.Name() + "/canonical-dp")),
		SnapshotSHA256:                 source.SnapshotSHA256,
		SchemaManifestSHA256:           projectedSchema,
		TransportCoordinateOrderSHA256: source.CoordinateOrderSHA256,
		PinsetSHA256:                   source.PinsetSHA256,
		BoundsSHA256:                   source.BoundsSHA256,
		QuantizationSHA256:             source.QuantizationSHA256,
	}
	core.CoefficientOrderSHA256, err = formalGLMCoefficientOrderSHA256V1(
		core.CoefficientOrder, core.TermMap)
	if err != nil || formalGLMValidatePublicDescriptorCoreV1(core) != nil {
		t.Fatalf("registered test descriptor: %v", err)
	}
	coreSHA256, err := formalGLMPublicDescriptorCoreSHA256V1(core)
	if err != nil {
		t.Fatal(err)
	}
	registered := source
	registered.SchemaManifestSHA256 = projectedSchema
	registered.DescriptorCoreSHA256 = coreSHA256
	artifactID, err := formalGLMPhase21StickyArtifactID(registered)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := formalGLMSignedPublicDescriptorV1{
		Version:    formalGLMSignedPublicDescriptorVersion,
		Purpose:    formalGLMSignedPublicDescriptorPurpose,
		Descriptor: core, DescriptorCoreSHA256: coreSHA256,
		ArtifactID: artifactID, CustodianPeers: peers,
		CustodianCount: len(peers), ProductionReady: false,
	}
	approvals := make([]jointDPBiomedicalGaussianSignature, 0, len(peers))
	for _, peer := range peers {
		approval, signErr := formalGLMSignPublicDescriptorV1(
			unsigned, peer, fixture.formal.identities.private[peer],
			fixture.formal.identities.public)
		if signErr != nil {
			t.Fatal(signErr)
		}
		approvals = append(approvals, approval)
	}
	descriptor, err := formalGLMSealPublicDescriptorV1(
		unsigned, approvals, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return registered, artifactID, formalGLMArtifactRegistryResolutionV1{
		ArtifactID: artifactID, Descriptor: descriptor,
	}
}

func formalGLMRegisteredLifecycleTestContract(t testing.TB,
	fixture formalGLMPhase21TestFixture,
	artifact formalGLMPhase21StickyArtifact, artifactID string,
) formalGLMPhase21SamplerV2Contract {
	t.Helper()
	roots := make(map[string][32]byte, 2)
	for _, authority := range artifact.NoiseAuthorities {
		roots[authority.PeerName] = fixture.seeds[authority.PeerName]
	}
	return formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
		fixture.formal.identities.public,
		fixture.formal.identities.private, roots)
}

func formalGLMRegisteredLifecycleRunStage(t *testing.T,
	fixture formalGLMPhase21TestFixture,
	contract formalGLMPhase21SamplerV2Contract,
	resolution formalGLMArtifactRegistryResolutionV1,
) ([2]formalGLMPhase21RockStageTestAuthority,
	[2]formalGLMPhase21RockStageRecord, formalFinalizerHandoffBinding) {
	t.Helper()
	authorizations := formalGLMPhase21SamplerV2TestAuthorize(
		t, contract, fixture.formal.identities.public,
		fixture.formal.identities.private, fixture.seeds)
	authorities := formalGLMPhase21RockTestStageAuthorities(
		t, fixture, contract, authorizations)
	for index := range authorities {
		path := filepath.Join(authorities[index].root,
			"assets-v1", "registry-resolution.json")
		formalGLMPhase21RockTestWriteJSON(t, path, resolution)
		authorities[index].operation.RegistryResolutionPath = path
	}
	type result struct {
		index    int
		response formalGLMPhase21RockLifecycleResponse
		err      error
	}
	results := make(chan result, 2)
	for index := range authorities {
		operation, err := json.Marshal(authorities[index].operation)
		if err != nil {
			t.Fatal(err)
		}
		go func(index int, encoded []byte) {
			response, runErr := formalGLMPhase21RockRun(
				authorities[index].root, false,
				formalGLMPhase21RockActionStage, encoded)
			results <- result{index, response, runErr}
		}(index, operation)
	}
	responses := [2]formalGLMPhase21RockLifecycleResponse{}
	offsets := [2]int64{}
	completed := 0
	deadline := time.Now().Add(90 * time.Second)
	for completed < 2 && time.Now().Before(deadline) {
		select {
		case got := <-results:
			if got.err != nil {
				for _, authority := range authorities {
					_ = os.WriteFile(filepath.Join(authority.spool, "abort"),
						[]byte("1"), 0o600)
				}
				t.Fatalf("registered Stage %d: %v", got.index, got.err)
			}
			responses[got.index] = got.response
			completed++
		default:
			offsets[0] = exactGCTestRelaySpool(
				t, authorities[0].spool, authorities[1].spool, offsets[0])
			offsets[1] = exactGCTestRelaySpool(
				t, authorities[1].spool, authorities[0].spool, offsets[1])
			now := time.Now()
			for _, authority := range authorities {
				if err := os.Chtimes(filepath.Join(
					authority.spool, "exchange.hb"), now, now); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(time.Millisecond)
		}
	}
	if completed != 2 {
		t.Fatal("registered Stage timed out")
	}
	var records [2]formalGLMPhase21RockStageRecord
	for index := range responses {
		if responses[index].ArtifactID != contract.ArtifactID ||
			responses[index].State != formalGLMPhase21RockStateStaged ||
			responses[index].Stage == nil {
			t.Fatalf("invalid registered Stage: %+v", responses[index])
		}
		records[index] = *responses[index].Stage
	}
	binding, err := formalGLMPhase21RockStagePair(
		records, contract, fixture.formal.identities.public)
	if err != nil || binding.ArtifactID != contract.ArtifactID {
		t.Fatalf("registered Stage pair: %+v / %v", binding, err)
	}
	return authorities, records, binding
}

func formalGLMRegisteredLifecyclePublicV2(t testing.TB,
	fixture formalGLMPhase21TestFixture,
	contract formalGLMPhase21SamplerV2Contract,
	resolution formalGLMArtifactRegistryResolutionV1,
) (formalGLMPhase21StickyCertificate,
	formalGLMPhase21PublicCertificateV2) {
	t.Helper()
	if contract.Artifact.CoordinateCount != 2 {
		t.Fatalf("registered PublicV2 fixture has %d coordinates",
			contract.Artifact.CoordinateCount)
	}
	publicFixture := formalGLMPhase21SamplerV2TestFixture{
		artifact: contract.Artifact, artifactID: contract.ArtifactID,
		pins:  fixture.formal.identities.public,
		keys:  fixture.formal.identities.private,
		roots: fixture.seeds, contract: contract,
	}
	candidate := formalGLMPhase21SamplerV2TestUnsignedCertificate(
		t, publicFixture)
	promoted, err := formalGLMPhase21PromoteDurableV2(
		candidate, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMPhase21BuildRegisteredPublicCertificateV2(
		promoted, formalGLMArtifactRegistryResolutionV1{},
		fixture.formal.identities.public); err == nil {
		t.Fatal("registered PublicV2 accepted an empty registry resolution")
	}
	public, err := formalGLMPhase21BuildRegisteredPublicCertificateV2(
		promoted, resolution, fixture.formal.identities.public)
	if err != nil || public.PublicDescriptor == nil ||
		!reflect.DeepEqual(*public.PublicDescriptor, resolution.Descriptor) ||
		len(resolution.Descriptor.CustodianApprovals) !=
			contract.Artifact.CustodianCount {
		t.Fatalf("registered PublicV2 descriptor: %+v / %v", public, err)
	}
	stickyMessage, err := formalGLMPhase21StickyCertificateMessage(promoted)
	if err != nil {
		t.Fatal(err)
	}
	stickyReceipts := make([]jointDPBiomedicalGaussianSignature, 2)
	publicReceipts := make([]jointDPBiomedicalGaussianSignature, 2)
	for index, authority := range contract.Artifact.NoiseAuthorities {
		stickyReceipts[index] = jointDPBiomedicalGaussianSignature{
			Signer: authority.PeerName,
			Signature: ed25519.Sign(
				fixture.formal.identities.private[authority.PeerName],
				stickyMessage),
		}
		publicReceipts[index], err = formalGLMPhase21SignPublicCertificateV2(
			public, authority.PeerName,
			fixture.formal.identities.private[authority.PeerName],
			fixture.formal.identities.public)
		if err != nil {
			t.Fatal(err)
		}
	}
	internal, err := formalGLMPhase21SealStickyCertificate(
		promoted, stickyReceipts, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := formalGLMPhase21SealPublicCertificateV2(
		public, publicReceipts, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	named, err := formalGLMPhase21DecodeNamedPublicV2(
		sealed, fixture.formal.identities.public)
	if err != nil || len(named) != contract.Artifact.CoordinateCount {
		t.Fatalf("registered named PublicV2 decode: %+v / %v", named, err)
	}
	return internal, sealed
}

func TestFormalGLMRegisteredPublicFullLifecycleK2K3K5(t *testing.T) {
	formalGLMPhase21RockFullLifecycleK2K3K5(t, true)
}

func TestFormalGLMRegisteredPublicStageK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPhase21TestSetup(t, custodians, "binomial")
			defer fixture.close()
			reference := fixture.formal.ctx.ComputePeers[0]
			runtime, _, err := formalGLMPhase21LoadAndAdmit(
				fixture.stores[reference], fixture.capsule, fixture.request,
				fixture.backendSignatures, fixture.workerSignatures)
			if err != nil {
				t.Fatal(err)
			}
			source, _, err := formalGLMPhase21BuildCanonicalArtifact(
				runtime.Admission.Productive.Compiled.Binding,
				runtime.Source.Plan, fixture.formal.identities.public)
			binding := runtime.Admission.Productive.Compiled.Binding
			runtime.clear()
			if err != nil {
				t.Fatal(err)
			}
			artifact, artifactID, resolution :=
				formalGLMRegisteredLifecycleTestResolution(
					t, fixture, source, binding)
			contract := formalGLMRegisteredLifecycleTestContract(
				t, fixture, artifact, artifactID)
			authorizations := formalGLMPhase21SamplerV2TestAuthorize(
				t, contract, fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			authorities := formalGLMPhase21RockTestStageAuthorities(
				t, fixture, contract, authorizations)
			for index := range authorities {
				path := filepath.Join(authorities[index].root,
					"assets-v1", "registry-resolution.json")
				formalGLMPhase21RockTestWriteJSON(t, path, resolution)
				authorities[index].operation.RegistryResolutionPath = path
			}
			type result struct {
				index    int
				response formalGLMPhase21RockLifecycleResponse
				err      error
			}
			results := make(chan result, 2)
			for index := range authorities {
				operation, marshalErr := json.Marshal(authorities[index].operation)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				go func(index int, encoded []byte) {
					response, runErr := formalGLMPhase21RockRun(
						authorities[index].root, false,
						formalGLMPhase21RockActionStage, encoded)
					results <- result{index, response, runErr}
				}(index, operation)
			}
			responses := [2]formalGLMPhase21RockLifecycleResponse{}
			offsets := [2]int64{}
			completed := 0
			deadline := time.Now().Add(90 * time.Second)
			for completed < 2 && time.Now().Before(deadline) {
				select {
				case got := <-results:
					if got.err != nil {
						for _, authority := range authorities {
							_ = os.WriteFile(filepath.Join(authority.spool, "abort"),
								[]byte("1"), 0o600)
						}
						t.Fatalf("registered Stage %d: %v", got.index, got.err)
					}
					responses[got.index] = got.response
					completed++
				default:
					offsets[0] = exactGCTestRelaySpool(
						t, authorities[0].spool, authorities[1].spool, offsets[0])
					offsets[1] = exactGCTestRelaySpool(
						t, authorities[1].spool, authorities[0].spool, offsets[1])
					now := time.Now()
					for _, authority := range authorities {
						if err := os.Chtimes(filepath.Join(
							authority.spool, "exchange.hb"), now, now); err != nil {
							t.Fatal(err)
						}
					}
					time.Sleep(time.Millisecond)
				}
			}
			if completed != 2 {
				t.Fatal("registered Stage timed out")
			}
			for index := range authorities {
				if responses[index].ArtifactID != artifactID ||
					responses[index].State != formalGLMPhase21RockStateStaged ||
					responses[index].Stage == nil {
					t.Fatalf("invalid registered Stage: %+v", responses[index])
				}
				formalGLMPhase21RockTestRefreshStageSecret(
					t, fixture, contract, index, authorities[index])
				operation, _ := json.Marshal(authorities[index].operation)
				replay, replayErr := formalGLMPhase21RockRunWithHook(
					authorities[index].root, false,
					formalGLMPhase21RockActionStage, operation,
					func(phase string) error {
						t.Fatalf("registered replay re-entered %s", phase)
						return nil
					})
				if replayErr != nil || !replay.Replayed || replay.Stage == nil {
					t.Fatalf("registered Stage replay: %+v / %v", replay, replayErr)
				}
			}
		})
	}
}

func TestFormalGLMRegisteredPublicRejectsBroadOrTamperedBeforeSampler(t *testing.T) {
	fixture := formalGLMPhase21TestSetup(t, 3, "binomial")
	defer fixture.close()
	reference := fixture.formal.ctx.ComputePeers[0]
	runtime, _, err := formalGLMPhase21LoadAndAdmit(
		fixture.stores[reference], fixture.capsule, fixture.request,
		fixture.backendSignatures, fixture.workerSignatures)
	if err != nil {
		t.Fatal(err)
	}
	source, sourceID, err := formalGLMPhase21BuildCanonicalArtifact(
		runtime.Admission.Productive.Compiled.Binding,
		runtime.Source.Plan, fixture.formal.identities.public)
	binding := runtime.Admission.Productive.Compiled.Binding
	runtime.clear()
	if err != nil {
		t.Fatal(err)
	}
	artifact, artifactID, resolution := formalGLMRegisteredLifecycleTestResolution(
		t, fixture, source, binding)
	contract := formalGLMRegisteredLifecycleTestContract(
		t, fixture, artifact, artifactID)
	authorizations := formalGLMPhase21SamplerV2TestAuthorize(
		t, contract, fixture.formal.identities.public,
		fixture.formal.identities.private, fixture.seeds)
	authorities := formalGLMPhase21RockTestStageAuthorities(
		t, fixture, contract, authorizations)

	tests := []struct {
		name       string
		resolution *formalGLMArtifactRegistryResolutionV1
		contract   formalGLMPhase21SamplerV2Contract
	}{
		{name: "missing-resolution", resolution: nil, contract: contract},
		{name: "broad-artifact", resolution: &resolution,
			contract: formalGLMRegisteredLifecycleTestContract(
				t, fixture, source, sourceID)},
		{name: "unselected-schema", resolution: func() *formalGLMArtifactRegistryResolutionV1 {
			value := resolution
			value.Descriptor.Descriptor.SchemaManifestSHA256 =
				sha256Hex([]byte(t.Name() + "/unselected-schema"))
			return &value
		}(), contract: contract},
		{name: "descriptor-hash", resolution: func() *formalGLMArtifactRegistryResolutionV1 {
			value := resolution
			value.Descriptor.DescriptorCoreSHA256 =
				sha256Hex([]byte(t.Name() + "/wrong-descriptor"))
			return &value
		}(), contract: contract},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := authorities[0]
			contractPath := filepath.Join(authority.root, "assets-v1",
				fmt.Sprintf("negative-contract-%d.json", index))
			formalGLMPhase21RockTestWriteJSON(t, contractPath, test.contract)
			authority.operation.ArtifactContractPath = contractPath
			if test.resolution != nil {
				path := filepath.Join(authority.root, "assets-v1",
					fmt.Sprintf("negative-resolution-%d.json", index))
				formalGLMPhase21RockTestWriteJSON(t, path, *test.resolution)
				authority.operation.RegistryResolutionPath = path
			}
			encoded, marshalErr := json.Marshal(authority.operation)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			entered := false
			_, runErr := formalGLMPhase21RockRunWithHook(
				authority.root, false, formalGLMPhase21RockActionStage,
				encoded, func(string) error { entered = true; return nil })
			if runErr == nil || entered {
				t.Fatalf("unsafe registered Stage: err=%v entered=%v", runErr, entered)
			}
		})
	}
}
