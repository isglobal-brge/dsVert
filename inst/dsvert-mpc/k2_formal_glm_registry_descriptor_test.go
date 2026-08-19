package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	formalGLMRegistryDescriptorTestSnapshotJSON = `{"alignment_protocol_version":3,"logical_snapshot_id":"cohort-stable-v1","version":"v1"}`
	formalGLMRegistryDescriptorTestSchemaJSON   = `{"purpose":"formal-glm-projected-schema-v1","version":"v1"}`
)

func formalGLMRegistryDescriptorTestNormalizeArtifact(
	fixture *formalGLMPhase21SamplerV2TestFixture,
) {
	fixture.artifact.SnapshotSHA256 = sha256Hex(
		[]byte(formalGLMRegistryDescriptorTestSnapshotJSON))
	fixture.artifact.SchemaManifestSHA256 = sha256Hex(
		[]byte(formalGLMRegistryDescriptorTestSchemaJSON))
}

func formalGLMRegistryDescriptorTestBridgeReceipts(
	t testing.TB, fixture formalGLMPhase21SamplerV2TestFixture,
	descriptorCoreSHA256 string,
) []formalGLMPSISourceBridgeReceiptV1 {
	t.Helper()
	psiPinsetID, err := formalGLMPSIPinsetIDV1(fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	identities := make([]formalGLMPeerIdentityV1, 0, len(fixture.pins))
	for _, peer := range fixture.artifact.CustodianPeers {
		identities = append(identities, formalGLMPeerIdentityV1{
			PeerName: peer, IdentityPK: formalGLMIdentityPKV1(fixture.pins[peer]),
		})
	}
	receipts := make([]formalGLMPSISourceBridgeReceiptV1, 0, len(identities))
	for index, identity := range identities {
		attestation := formalGLMPSIPublicAttestationV3{
			AttestationVersion: 3, AlignmentAttested: true,
			AlignmentProtocol: "dsvert-pinned-padded-psi-v5",
			AttestationID:     fmt.Sprintf("attest_%064x", index+1),
			ContractSHA256:    sha256Hex([]byte(fmt.Sprintf("contract-%d", index))),
			PolicyID:          fmt.Sprintf("policy_%064x", 91),
			AlignmentPurpose:  "aligned-patient-cohort-v1",
			DatasetID:         fmt.Sprintf("cohort-%d", index), DatasetVersion: "v1",
			IDColumn:        "patient_id",
			SourceBindingID: fmt.Sprintf("source_%064x", index+11),
			PinsetID:        psiPinsetID, CapacityBucket: 1024,
			RelayFrameBytes: 65536, InlineMaxBytes: 65536,
			PeerCount:     len(identities),
			ReferencePeer: fixture.artifact.DesignatedComputePeers[0],
			ComputePeers: append([]string(nil),
				fixture.artifact.DesignatedComputePeers...),
		}
		core := formalGLMPSISourceBridgeCoreV1{
			Version:          formalGLMPSISourceBridgeVersion,
			Purpose:          formalGLMPSISourceBridgePurpose,
			SignerPeerName:   identity.PeerName,
			SignerIdentityPK: identity.IdentityPK,
			PSIAttestation:   attestation,
			SourceBindingID:  attestation.SourceBindingID,
			DatasetID:        attestation.DatasetID, DatasetVersion: attestation.DatasetVersion,
			CohortID:              "cohort-stable-v1",
			LogicalSnapshotJSON:   formalGLMRegistryDescriptorTestSnapshotJSON,
			LogicalSnapshotSHA256: fixture.artifact.SnapshotSHA256,
			SchemaManifestJSON:    formalGLMRegistryDescriptorTestSchemaJSON,
			SchemaManifestSHA256:  fixture.artifact.SchemaManifestSHA256,
			RPinsetID:             psiPinsetID, GoPinsetSHA256: pinsetSHA256,
			DescriptorCoreSHA256: descriptorCoreSHA256,
			PeerIdentities:       identities,
		}
		unsigned := formalGLMPSISourceBridgeReceiptV1{Core: core}
		message, err := formalGLMPSISourceBridgeMessageV1(unsigned.Core)
		if err != nil {
			t.Fatal(err)
		}
		unsigned.Signature = formalGLMSignatureBase64URLV1(
			ed25519.Sign(fixture.keys[identity.PeerName], message))
		receipts = append(receipts, unsigned)
	}
	return receipts
}

func formalGLMRegistryDescriptorTestCore(
	t testing.TB, fixture formalGLMPhase21SamplerV2TestFixture,
) formalGLMPublicDescriptorCoreV1 {
	t.Helper()
	formula, err := formalGLMCanonicalQualifiedFormulaV1(fmt.Sprintf(
		"%s$outcome ~ 1 + %s$group", fixture.artifact.CustodianPeers[0],
		fixture.artifact.CustodianPeers[1]))
	if err != nil {
		t.Fatal(err)
	}
	coefficientOrder := []string{
		"(Intercept)", fixture.artifact.CustodianPeers[1] + "$group[treated]",
	}
	core := formalGLMPublicDescriptorCoreV1{
		Version:                   formalGLMPublicDescriptorCoreVersion,
		Purpose:                   formalGLMPublicDescriptorCorePurpose,
		Family:                    fixture.artifact.Family,
		CanonicalQualifiedFormula: formula.Canonical,
		FormulaSHA256:             formula.SHA256,
		CoefficientOrder:          coefficientOrder,
		TermMap: []formalGLMPublicTermV1{
			{Index: 0, Coefficient: "(Intercept)", Kind: "intercept"},
			{Index: 1, Coefficient: coefficientOrder[1], Kind: "factor_level",
				Owner: fixture.artifact.CustodianPeers[1], SourceColumn: "group",
				SourceLevel: "treated"},
		},
		UsedColumns: []formalGLMPublicColumnV1{
			{Owner: fixture.artifact.CustodianPeers[0], DatasetID: "cohort-0",
				DatasetVersion: "v1", Column: "outcome", Role: "response",
				Kind: "binary", LowerRational: "0", UpperRational: "1"},
			{Owner: fixture.artifact.CustodianPeers[1], DatasetID: "cohort-1",
				DatasetVersion: "v1", Column: "group", Role: "predictor",
				Kind: "factor", Levels: []string{"control", "treated"},
				ReferenceLevel: "control", Contrast: "treatment"},
		},
		ShiftedUpperBounds:             []string{"9007199254740994", "9007199254740996"},
		OutputLatticeScale:             fmt.Sprintf("2^-%d", fixture.artifact.OutputLatticeBits),
		SourceFractionBits:             fixture.artifact.SourceFractionBits,
		QuantizationShift:              fixture.artifact.QuantizationShift,
		OutputLatticeBits:              fixture.artifact.OutputLatticeBits,
		Quantization:                   "signed_integer_shift_then_clamp_v1",
		CanonicalPreSourceDPSHA256:     sha256Hex([]byte("canonical-pre-source-dp")),
		SnapshotSHA256:                 fixture.artifact.SnapshotSHA256,
		SchemaManifestSHA256:           fixture.artifact.SchemaManifestSHA256,
		TransportCoordinateOrderSHA256: fixture.artifact.CoordinateOrderSHA256,
		PinsetSHA256:                   fixture.artifact.PinsetSHA256,
		BoundsSHA256:                   fixture.artifact.BoundsSHA256,
		QuantizationSHA256:             fixture.artifact.QuantizationSHA256,
	}
	core.CoefficientOrderSHA256, err = formalGLMCoefficientOrderSHA256V1(
		core.CoefficientOrder, core.TermMap)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidatePublicDescriptorCoreV1(core); err != nil {
		t.Fatal(err)
	}
	return core
}

func formalGLMRegistryDescriptorTestSignedDescriptor(
	t testing.TB, fixture formalGLMPhase21SamplerV2TestFixture,
	core formalGLMPublicDescriptorCoreV1, artifactID string,
) formalGLMSignedPublicDescriptorV1 {
	t.Helper()
	coreSHA256, err := formalGLMPublicDescriptorCoreSHA256V1(core)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := formalGLMSignedPublicDescriptorV1{
		Version:    formalGLMSignedPublicDescriptorVersion,
		Purpose:    formalGLMSignedPublicDescriptorPurpose,
		Descriptor: core, DescriptorCoreSHA256: coreSHA256,
		ArtifactID:     artifactID,
		CustodianPeers: append([]string(nil), fixture.artifact.CustodianPeers...),
		CustodianCount: len(fixture.artifact.CustodianPeers), ProductionReady: false,
	}
	approvals := make([]jointDPBiomedicalGaussianSignature, 0,
		len(unsigned.CustodianPeers))
	for _, peer := range unsigned.CustodianPeers {
		approval, err := formalGLMSignPublicDescriptorV1(
			unsigned, peer, fixture.keys[peer], fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
		approvals = append(approvals, approval)
	}
	sealed, err := formalGLMSealPublicDescriptorV1(
		unsigned, approvals, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func formalGLMRegistryDescriptorTestEntry(
	t testing.TB, fixture formalGLMPhase21SamplerV2TestFixture,
	receipts []formalGLMPSISourceBridgeReceiptV1,
	descriptor formalGLMSignedPublicDescriptorV1, aliases ...string,
) formalGLMArtifactRegistryEntryV1 {
	t.Helper()
	bridgeSHA256, err := formalGLMPSISourceBridgeSetSHA256V1(receipts, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	entry := formalGLMArtifactRegistryEntryV1{
		Version:           formalGLMArtifactRegistryEntryVersion,
		Purpose:           formalGLMArtifactRegistryEntryPurpose,
		BridgeSetSHA256:   bridgeSHA256,
		FormalAnalysisIDs: append([]string(nil), aliases...),
		ArtifactID:        descriptor.ArtifactID, Descriptor: descriptor,
		DescriptorCoreSHA256: descriptor.DescriptorCoreSHA256,
		CustodianPeers:       append([]string(nil), fixture.artifact.CustodianPeers...),
		CustodianCount:       len(fixture.artifact.CustodianPeers), ProductionReady: false,
	}
	entry.FormalAnalysisIDs = formalGLMSortedUniqueLabelsV1(entry.FormalAnalysisIDs)
	for _, peer := range entry.CustodianPeers {
		approval, err := formalGLMSignArtifactRegistryEntryV1(
			entry, peer, fixture.keys[peer], fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
		entry.CustodianApprovals = append(entry.CustodianApprovals, approval)
	}
	if err := formalGLMValidateArtifactRegistryEntryV1(entry, fixture.pins); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestFormalGLMRegistryDescriptorK2K3K5AndPublicV2(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPhase21SamplerV2TestSetup(
				t, custodians, formalGLMPhase21SamplerV2OneDraw)
			formalGLMRegistryDescriptorTestNormalizeArtifact(&fixture)
			core := formalGLMRegistryDescriptorTestCore(t, fixture)
			coreSHA256, _ := formalGLMPublicDescriptorCoreSHA256V1(core)
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
			entryA := formalGLMRegistryDescriptorTestEntry(
				t, fixture, receipts, descriptor, "primary")
			entryB := formalGLMRegistryDescriptorTestEntry(
				t, fixture, receipts, descriptor, "alias")

			root := filepath.Join(t.TempDir(), "registry")
			store, err := newFormalGLMArtifactRegistryStoreV1(root, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if replay, err := store.Commit(entryA); err != nil || replay {
				t.Fatalf("commit primary: replay=%v err=%v", replay, err)
			}
			if replay, err := store.Commit(entryB); err != nil || replay {
				t.Fatalf("commit alias: replay=%v err=%v", replay, err)
			}
			query := formalGLMArtifactRegistryQueryV1{
				BridgeReceipts: receipts, Family: core.Family,
				Formula: core.CanonicalQualifiedFormula,
			}
			resolved, err := store.Resolve(query)
			if err != nil || resolved.ArtifactID != artifactID ||
				resolved.Descriptor.DescriptorCoreSHA256 != coreSHA256 {
				t.Fatalf("resolve aliases: %+v %v", resolved, err)
			}
			query.FormalAnalysisID = "alias"
			if filtered, err := store.Resolve(query); err != nil ||
				filtered.ArtifactID != resolved.ArtifactID {
				t.Fatalf("alias filter changed identity: %+v %v", filtered, err)
			}
			store.Close()
			store, err = newFormalGLMArtifactRegistryStoreV1(root, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if restarted, err := store.Resolve(query); err != nil ||
				!reflect.DeepEqual(restarted, resolved) {
				t.Fatalf("registry restart changed resolution: %+v %v", restarted, err)
			}

			internal := formalGLMPhase21SamplerV2TestUnsignedCertificate(t, fixture)
			internal.Artifact = artifact
			internal.ArtifactID = artifactID
			contract := formalGLMPhase21SamplerV2TestContractForArtifact(
				t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
				fixture.pins, fixture.keys, fixture.roots)
			internal.SamplerV2Contract = &contract
			promoted, err := formalGLMPhase21PromoteDurableV2(internal, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			public, err := formalGLMPhase21BuildRegisteredPublicCertificateV2(
				promoted, resolved, fixture.pins)
			if err != nil || public.PublicDescriptor == nil || public.ProductionReady {
				t.Fatalf("build registered PublicV2: %+v %v", public, err)
			}
			authorityReceipts := make([]jointDPBiomedicalGaussianSignature, 0,
				len(artifact.NoiseAuthorities))
			for _, authority := range artifact.NoiseAuthorities {
				approval, err := formalGLMPhase21SignPublicCertificateV2(
					public, authority.PeerName, fixture.keys[authority.PeerName],
					fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
				authorityReceipts = append(authorityReceipts, approval)
			}
			public, err = formalGLMPhase21SealPublicCertificateV2(
				public, authorityReceipts, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if err := formalGLMPhase21ValidatePublicCertificateV2(public, fixture.pins); err != nil {
				t.Fatal(err)
			}
			named, err := formalGLMPhase21DecodeNamedPublicV2(public, fixture.pins)
			if err != nil || len(named) != 2 || named[0].Coefficient != "(Intercept)" ||
				named[0].SignedSteps != "-4503599627370486" ||
				named[1].SignedSteps != "-4503599627370491" ||
				named[0].OutputLatticeBits != artifact.OutputLatticeBits {
				t.Fatalf("invalid exact named decode: %+v %v", named, err)
			}
			encoded, _ := json.Marshal(public.PublicDescriptor)
			for _, forbidden := range []string{
				"run_id", "capsule", "release", "reservation", "ledger", "epoch",
				"pair_root", "ticket", "formal_analysis_id", "attestation_id",
				"source_binding_id",
			} {
				if bytes.Contains(bytes.ToLower(encoded), []byte(forbidden)) {
					t.Fatalf("public descriptor exposed %q", forbidden)
				}
			}
		})
	}
}

func TestFormalGLMRegistryResolutionZeroManyCanonicalFormulaAndTamper(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 3, formalGLMPhase21SamplerV2OneDraw)
	formalGLMRegistryDescriptorTestNormalizeArtifact(&fixture)
	core := formalGLMRegistryDescriptorTestCore(t, fixture)
	coreSHA256, _ := formalGLMPublicDescriptorCoreSHA256V1(core)
	artifact := fixture.artifact
	artifact.DescriptorCoreSHA256 = coreSHA256
	artifactID, _ := formalGLMPhase21StickyArtifactID(artifact)
	descriptor := formalGLMRegistryDescriptorTestSignedDescriptor(
		t, fixture, core, artifactID)
	receipts := formalGLMRegistryDescriptorTestBridgeReceipts(t, fixture, coreSHA256)
	entry := formalGLMRegistryDescriptorTestEntry(
		t, fixture, receipts, descriptor, "primary")
	store, err := newFormalGLMArtifactRegistryStoreV1(
		filepath.Join(t.TempDir(), "registry"), fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Commit(entry); err != nil {
		t.Fatal(err)
	}
	refreshed := append([]formalGLMPSISourceBridgeReceiptV1(nil), receipts...)
	for index := range refreshed {
		refreshed[index].Core.PSIAttestation.AttestationID = fmt.Sprintf(
			"attest_%064x", index+1000)
		message, messageErr := formalGLMPSISourceBridgeMessageV1(
			refreshed[index].Core)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		peer := refreshed[index].Core.SignerPeerName
		refreshed[index].Signature = formalGLMSignatureBase64URLV1(
			ed25519.Sign(fixture.keys[peer], message))
	}
	originalBridge, err := formalGLMPSISourceBridgeSetSHA256V1(
		receipts, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	refreshedBridge, err := formalGLMPSISourceBridgeSetSHA256V1(
		refreshed, fixture.pins)
	if err != nil || refreshedBridge != originalBridge {
		t.Fatalf("fresh PSI nonce rerolled stable source binding: %s %v",
			refreshedBridge, err)
	}
	query := formalGLMArtifactRegistryQueryV1{
		BridgeReceipts: refreshed, Family: "poisson",
		Formula: core.CanonicalQualifiedFormula,
	}
	if _, err := store.Resolve(query); !formalGLMRegistryResolutionIsV1(err, "not_found", 0) {
		t.Fatalf("zero-match resolution was not typed: %v", err)
	}
	query.Family = core.Family
	if resolved, err := store.Resolve(query); err != nil ||
		resolved.ArtifactID != artifactID {
		t.Fatalf("fresh valid PSI receipt did not resolve sticky artifact: %+v %v",
			resolved, err)
	}

	alternate := descriptor
	alternate.ArtifactID = sha256Hex([]byte("alternate-artifact"))
	alternate.CustodianApprovals = nil
	alternate = formalGLMRegistryDescriptorTestSignedDescriptor(
		t, fixture, core, alternate.ArtifactID)
	alternateEntry := formalGLMRegistryDescriptorTestEntry(
		t, fixture, receipts, alternate, "other")
	if _, err := store.Commit(alternateEntry); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(query); !formalGLMRegistryResolutionIsV1(err, "ambiguous", 2) {
		t.Fatalf("many-match resolution was not typed: %v", err)
	}
	query.FormalAnalysisID = "primary"
	if resolved, err := store.Resolve(query); err != nil ||
		resolved.ArtifactID != artifactID {
		t.Fatalf("analysis-id filter did not narrow semantic matches: %+v %v",
			resolved, err)
	}
	changed := receipts
	changed = append([]formalGLMPSISourceBridgeReceiptV1(nil), changed...)
	changed[0].Core.DatasetVersion = "v2"
	query.BridgeReceipts = changed
	if _, err := store.Resolve(query); err == nil {
		t.Fatal("tampered bridge receipt reached registry selection")
	}

	left, err := formalGLMCanonicalQualifiedFormulaV1(
		"peer-a$y ~ peer-c$z + peer-b$x + 1")
	if err != nil {
		t.Fatal(err)
	}
	right, err := formalGLMCanonicalQualifiedFormulaV1(
		"peer-a$y ~ 1 + peer-b$x + peer-c$z")
	if err != nil || !reflect.DeepEqual(left, right) {
		t.Fatalf("term permutation changed canonical formula: %+v %+v %v",
			left, right, err)
	}
	for _, invalid := range []string{
		"peer-a$y ~ log(peer-b$x)", "peer-a$y ~ peer-b$x:peer-c$z",
		"y ~ x", "peer-a$y ~ peer-b$x + peer-b$x",
	} {
		if _, err := formalGLMCanonicalQualifiedFormulaV1(invalid); err == nil {
			t.Fatalf("unsafe formula accepted: %s", invalid)
		}
	}

	badFactor := core
	badFactor.UsedColumns = append([]formalGLMPublicColumnV1(nil), core.UsedColumns...)
	badFactor.UsedColumns[1].ReferenceLevel = "missing"
	if err := formalGLMValidatePublicDescriptorCoreV1(badFactor); err == nil {
		t.Fatal("invalid factor reference was accepted")
	}
	badApprovals := descriptor
	badApprovals.CustodianApprovals = append(
		[]jointDPBiomedicalGaussianSignature(nil), descriptor.CustodianApprovals...)
	badApprovals.CustodianApprovals[0], badApprovals.CustodianApprovals[1] =
		badApprovals.CustodianApprovals[1], badApprovals.CustodianApprovals[0]
	if err := formalGLMValidateSignedPublicDescriptorV1(
		badApprovals, fixture.pins); err == nil {
		t.Fatal("reordered K approvals were accepted")
	}
}

func TestFormalGLMRegistryDescriptorPreservesPhase0TermOrder(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2OneDraw)
	formalGLMRegistryDescriptorTestNormalizeArtifact(&fixture)
	core := formalGLMRegistryDescriptorTestCore(t, fixture)
	left, right := fixture.artifact.CustodianPeers[0],
		fixture.artifact.CustodianPeers[1]
	formula, err := formalGLMCanonicalQualifiedFormulaV1(fmt.Sprintf(
		"%s$outcome ~ 1 + %s$bmi + %s$age", left, left, right))
	if err != nil {
		t.Fatal(err)
	}
	core.CanonicalQualifiedFormula = formula.Canonical
	core.FormulaSHA256 = formula.SHA256
	core.CoefficientOrder = []string{
		"(Intercept)", right + "$age", left + "$bmi",
	}
	core.TermMap = []formalGLMPublicTermV1{
		{Index: 0, Coefficient: "(Intercept)", Kind: "intercept"},
		{Index: 1, Coefficient: right + "$age", Kind: "numeric",
			Owner: right, SourceColumn: "age"},
		{Index: 2, Coefficient: left + "$bmi", Kind: "numeric",
			Owner: left, SourceColumn: "bmi"},
	}
	core.UsedColumns = []formalGLMPublicColumnV1{
		{Owner: left, DatasetID: "cohort-0", DatasetVersion: "v1",
			Column: "bmi", Role: "predictor", Kind: "numeric",
			LowerRational: "-1", UpperRational: "1"},
		{Owner: left, DatasetID: "cohort-0", DatasetVersion: "v1",
			Column: "outcome", Role: "response", Kind: "binary",
			LowerRational: "0", UpperRational: "1"},
		{Owner: right, DatasetID: "cohort-1", DatasetVersion: "v1",
			Column: "age", Role: "predictor", Kind: "numeric",
			LowerRational: "0", UpperRational: "120"},
	}
	core.ShiftedUpperBounds = []string{"2", "2", "2"}
	core.CoefficientOrderSHA256, err = formalGLMCoefficientOrderSHA256V1(
		core.CoefficientOrder, core.TermMap)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidatePublicDescriptorCoreV1(core); err != nil {
		t.Fatalf("Phase0 coordinate order was rejected: %v", err)
	}
}

func TestFormalGLMRegistryDescriptorMatchesPhase0FactorSemantics(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2OneDraw)
	formalGLMRegistryDescriptorTestNormalizeArtifact(&fixture)
	core := formalGLMRegistryDescriptorTestCore(t, fixture)
	left, right := fixture.artifact.CustodianPeers[0],
		fixture.artifact.CustodianPeers[1]
	formula, err := formalGLMCanonicalQualifiedFormulaV1(fmt.Sprintf(
		"%s$outcome ~ 0 + %s$group", left, right))
	if err != nil {
		t.Fatal(err)
	}
	levels := []string{"control group", "Á/B"}
	core.CanonicalQualifiedFormula = formula.Canonical
	core.FormulaSHA256 = formula.SHA256
	core.CoefficientOrder = []string{
		right + "$group[control group]", right + "$group[Á/B]",
	}
	core.TermMap = []formalGLMPublicTermV1{
		{Index: 0, Coefficient: core.CoefficientOrder[0],
			Kind: "factor_level", Owner: right, SourceColumn: "group",
			SourceLevel: levels[0]},
		{Index: 1, Coefficient: core.CoefficientOrder[1],
			Kind: "factor_level", Owner: right, SourceColumn: "group",
			SourceLevel: levels[1]},
	}
	core.UsedColumns = []formalGLMPublicColumnV1{
		{Owner: left, DatasetID: "cohort-0", DatasetVersion: "v1",
			Column: "outcome", Role: "response", Kind: "binary",
			LowerRational: "0", UpperRational: "1"},
		{Owner: right, DatasetID: "cohort-1", DatasetVersion: "v1",
			Column: "group", Role: "predictor", Kind: "factor",
			Levels: levels, ReferenceLevel: levels[0], Contrast: "treatment"},
	}
	core.ShiftedUpperBounds = []string{"2", "2"}
	core.CoefficientOrderSHA256, err = formalGLMCoefficientOrderSHA256V1(
		core.CoefficientOrder, core.TermMap)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidatePublicDescriptorCoreV1(core); err != nil {
		t.Fatalf("Phase0 no-intercept/UTF-8 factor was rejected: %v", err)
	}

	longOwner := "p" + strings.Repeat("o", 127)
	longColumn := "c" + strings.Repeat("x", 127)
	longLevel := strings.Repeat("L", 256)
	longFormula, err := formalGLMCanonicalQualifiedFormulaV1(fmt.Sprintf(
		"%s$outcome ~ 0 + %s$%s", left, longOwner, longColumn))
	if err != nil {
		t.Fatal(err)
	}
	longCoefficient := longOwner + "$" + longColumn + "[" + longLevel + "]"
	referenceCoefficient := longOwner + "$" + longColumn + "[reference]"
	core.CanonicalQualifiedFormula = longFormula.Canonical
	core.FormulaSHA256 = longFormula.SHA256
	core.CoefficientOrder = []string{referenceCoefficient, longCoefficient}
	core.TermMap = []formalGLMPublicTermV1{
		{Index: 0, Coefficient: referenceCoefficient, Kind: "factor_level",
			Owner: longOwner, SourceColumn: longColumn,
			SourceLevel: "reference"},
		{Index: 1, Coefficient: longCoefficient, Kind: "factor_level",
			Owner: longOwner, SourceColumn: longColumn, SourceLevel: longLevel},
	}
	core.UsedColumns = []formalGLMPublicColumnV1{
		{Owner: left, DatasetID: "cohort-0", DatasetVersion: "v1",
			Column: "outcome", Role: "response", Kind: "binary",
			LowerRational: "0", UpperRational: "1"},
		{Owner: longOwner, DatasetID: "cohort-long", DatasetVersion: "v1",
			Column: longColumn, Role: "predictor", Kind: "factor",
			Levels:         []string{"reference", longLevel},
			ReferenceLevel: "reference", Contrast: "treatment"},
	}
	core.ShiftedUpperBounds = []string{"2", "2"}
	core.CoefficientOrderSHA256, err = formalGLMCoefficientOrderSHA256V1(
		core.CoefficientOrder, core.TermMap)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidatePublicDescriptorCoreV1(core); err != nil {
		t.Fatalf("maximum Phase0 factor coordinate was rejected: %v", err)
	}
}

func TestFormalGLMRegistryRockRecordTamperAndLinks(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2OneDraw)
	formalGLMRegistryDescriptorTestNormalizeArtifact(&fixture)
	core := formalGLMRegistryDescriptorTestCore(t, fixture)
	coreSHA256, _ := formalGLMPublicDescriptorCoreSHA256V1(core)
	artifact := fixture.artifact
	artifact.DescriptorCoreSHA256 = coreSHA256
	artifactID, _ := formalGLMPhase21StickyArtifactID(artifact)
	descriptor := formalGLMRegistryDescriptorTestSignedDescriptor(
		t, fixture, core, artifactID)
	receipts := formalGLMRegistryDescriptorTestBridgeReceipts(t, fixture, coreSHA256)
	entry := formalGLMRegistryDescriptorTestEntry(t, fixture, receipts, descriptor, "a")
	for _, attack := range []string{"tamper", "mode", "hardlink"} {
		t.Run(attack, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "registry")
			store, err := newFormalGLMArtifactRegistryStoreV1(root, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(entry); err != nil {
				t.Fatal(err)
			}
			paths, err := store.entryPaths()
			if err != nil || len(paths) != 1 {
				t.Fatalf("registry paths: %v %v", paths, err)
			}
			path := filepath.Join(root, paths[0])
			store.Close()
			switch attack {
			case "tamper":
				encoded, _ := os.ReadFile(path)
				encoded[len(encoded)/2] ^= 1
				if err := os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err := newFormalGLMArtifactRegistryStoreV1(root, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			query := formalGLMArtifactRegistryQueryV1{
				BridgeReceipts: receipts, Family: core.Family,
				Formula: core.CanonicalQualifiedFormula, FormalAnalysisID: "a",
			}
			if _, err := reopened.Resolve(query); err == nil {
				t.Fatal("unsafe Rock registry record was accepted")
			}
		})
	}
}

func TestFormalGLMRegistryGoldenPinsetsAndFormula(t *testing.T) {
	seedA := sha256.Sum256([]byte("glm-registry-golden-a"))
	seedB := sha256.Sum256([]byte("glm-registry-golden-b"))
	privateA := ed25519.NewKeyFromSeed(seedA[:])
	privateB := ed25519.NewKeyFromSeed(seedB[:])
	pins := map[string]ed25519.PublicKey{
		"peer_a": privateA.Public().(ed25519.PublicKey),
		"peer_b": privateB.Public().(ed25519.PublicKey),
	}
	psi, err := formalGLMPSIPinsetIDV1(pins)
	if err != nil {
		t.Fatal(err)
	}
	glm, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		t.Fatal(err)
	}
	formula, err := formalGLMCanonicalQualifiedFormulaV1(
		"peer_a$outcome ~ peer_b$group + peer_a$age + 1")
	if err != nil {
		t.Fatal(err)
	}
	const wantPSI = "pinset_24a0f9230e9eb495b490082817b678f93aa03922e8fe4679c892c5012bd80cea"
	const wantGLM = "5e08130a50da69988c4ac5fad3a204de34cea9f4b46226aaf7b7447993ce99af"
	const wantFormula = "9ce971fded2bc35df21a6f46537cf08e3ef74800864a0d27d8c0981b9bc03262"
	if psi != wantPSI || glm != wantGLM || formula.SHA256 != wantFormula {
		t.Fatalf("cross-language golden changed: psi=%s glm=%s formula=%s",
			psi, glm, formula.SHA256)
	}
}

var _ = strings.Contains
