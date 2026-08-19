package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
)

const (
	formalGLMSourceContractCoreVersion = "dsvert-formal-glm-source-contract-core-v1"
	formalGLMSourceContractCorePurpose = "formal_glm_registered_phase18_phase20_source_binding_v1"
	formalGLMSourceContractVersion     = "dsvert-formal-glm-source-contract-v1"
	formalGLMSourceContractPurpose     = "formal_glm_k_signed_registered_source_contract_v1"
	formalGLMSourceContractDomain      = "dsVert/formal-glm/source-contract/v1"
	formalGLMSourceContractMaxJSON     = 32 << 20
)

// formalGLMSourceContractCoreV1 is the alias-invariant authorization for the
// registered Phase18-to-Phase20 source path. It intentionally contains the
// unsigned sampler core: K signatures over this core can therefore be made in
// the same approval round as the sampler and registry-entry signatures.
type formalGLMSourceContractCoreV1 struct {
	Version                 string                             `json:"version"`
	Purpose                 string                             `json:"purpose"`
	ArtifactID              string                             `json:"artifact_id"`
	SourceBindingSet        formalGLMSourceBindingSetV1        `json:"source_binding_set"`
	BridgeSetSHA256         string                             `json:"bridge_set_sha256"`
	RegisteredExecutionPlan formalGLMRegisteredExecutionPlanV1 `json:"registered_execution_plan"`
	SamplerV2ContractCore   formalGLMPhase21SamplerV2Contract  `json:"sampler_v2_contract_core"`
	ProductionReady         bool                               `json:"production_ready"`
}

// These two named types preserve the field order and JSON representation of
// the projection hashed by formalGLMPSISourceBridgeSetSHA256V1. Receipt
// signatures and other transient PSI metadata never enter the source core.
type formalGLMSourceBindingV1 struct {
	SignerPeerName  string `json:"signer_peer_name"`
	CohortID        string `json:"cohort_id"`
	SourceBindingID string `json:"source_binding_id"`
	DatasetID       string `json:"dataset_id"`
	DatasetVersion  string `json:"dataset_version"`
}

type formalGLMSourceBindingSetV1 struct {
	Version               string                     `json:"version"`
	Sources               []formalGLMSourceBindingV1 `json:"sources"`
	LogicalSnapshotJSON   string                     `json:"logical_snapshot_json"`
	LogicalSnapshotSHA256 string                     `json:"logical_snapshot_sha256"`
	RPinsetID             string                     `json:"r_pinset_id"`
	GoPinsetSHA256        string                     `json:"go_pinset_sha256"`
	PeerIdentities        []formalGLMPeerIdentityV1  `json:"peer_identities"`
	DescriptorCoreSHA256  string                     `json:"descriptor_core_sha256"`
}

type formalGLMSourceContractV1 struct {
	Version            string                               `json:"version"`
	Purpose            string                               `json:"purpose"`
	Core               formalGLMSourceContractCoreV1        `json:"core"`
	CoreSHA256         string                               `json:"core_sha256"`
	ProductionReady    bool                                 `json:"production_ready"`
	CustodianApprovals []jointDPBiomedicalGaussianSignature `json:"custodian_approvals"`
}

func formalGLMBuildSourceContractCoreV1(
	entry formalGLMArtifactRegistryEntryV1,
	receipts []formalGLMPSISourceBridgeReceiptV1,
	plan formalGLMRegisteredExecutionPlanV1,
	sampler formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) (formalGLMSourceContractCoreV1, error) {
	var zero formalGLMSourceContractCoreV1
	if err := formalGLMValidateArtifactRegistryEntryCoreV1(entry, pins); err != nil {
		return zero, err
	}
	if len(entry.CustodianApprovals) != 0 {
		if err := formalGLMValidateArtifactRegistryEntryV1(entry, pins); err != nil {
			return zero, err
		}
	}
	if err := formalGLMValidateRegisteredExecutionPlanV1(plan, pins); err != nil {
		return zero, err
	}
	sourceBindingSet, err := formalGLMSourceBindingSetFromReceiptsV1(
		receipts, pins)
	if err != nil {
		return zero, err
	}
	bridgeSetSHA256, err := formalGLMSourceBindingSetSHA256V1(
		sourceBindingSet, pins)
	legacyBridgeSetSHA256, legacyErr := formalGLMPSISourceBridgeSetSHA256V1(
		receipts, pins)
	if err != nil || legacyErr != nil ||
		bridgeSetSHA256 != legacyBridgeSetSHA256 ||
		bridgeSetSHA256 != entry.BridgeSetSHA256 {
		return zero, fmt.Errorf("formal-glm source contract: bridge set mismatch")
	}
	if len(sampler.CustodianSignatures) != 0 {
		if err := formalGLMPhase21ValidateSamplerV2Contract(sampler, pins); err != nil {
			return zero, err
		}
	}
	unsignedSampler := sampler
	unsignedSampler.CustodianSignatures = nil
	if err := formalGLMPhase21ValidateSamplerV2ContractCore(
		unsignedSampler, pins); err != nil {
		return zero, err
	}
	samplerCoreSHA256, err := formalGLMPhase21SamplerV2ContractCoreSHA256V1(
		unsignedSampler, pins)
	if err != nil {
		return zero, err
	}
	if entry.ArtifactID != plan.ArtifactID ||
		entry.ArtifactID != unsignedSampler.ArtifactID ||
		entry.DescriptorCoreSHA256 != plan.DescriptorCoreSHA256 ||
		!reflect.DeepEqual(entry.Descriptor.Descriptor, plan.DescriptorCore) ||
		plan.SamplerV2ContractCoreSHA256 != samplerCoreSHA256 ||
		!reflect.DeepEqual(plan.Artifact, unsignedSampler.Artifact) {
		return zero, fmt.Errorf("formal-glm source contract: registered binding mismatch")
	}
	for _, receipt := range receipts {
		if receipt.Core.DescriptorCoreSHA256 != entry.DescriptorCoreSHA256 {
			return zero, fmt.Errorf("formal-glm source contract: bridge descriptor mismatch")
		}
	}
	core := formalGLMSourceContractCoreV1{
		Version:    formalGLMSourceContractCoreVersion,
		Purpose:    formalGLMSourceContractCorePurpose,
		ArtifactID: entry.ArtifactID, ProductionReady: false,
		SourceBindingSet: sourceBindingSet, BridgeSetSHA256: bridgeSetSHA256,
		RegisteredExecutionPlan: plan,
		SamplerV2ContractCore:   unsignedSampler,
	}
	core, err = formalGLMSourceContractCloneCoreV1(core)
	if err != nil {
		return zero, err
	}
	if err := formalGLMValidateSourceContractCoreV1(core, pins); err != nil {
		return zero, err
	}
	return core, nil
}

func formalGLMValidateSourceContractCoreV1(
	core formalGLMSourceContractCoreV1,
	pins map[string]ed25519.PublicKey,
) error {
	if core.Version != formalGLMSourceContractCoreVersion ||
		core.Purpose != formalGLMSourceContractCorePurpose ||
		core.ProductionReady || !formalGLMIsSHA256(core.ArtifactID) ||
		!formalGLMIsSHA256(core.BridgeSetSHA256) ||
		len(core.SamplerV2ContractCore.CustodianSignatures) != 0 {
		return fmt.Errorf("formal-glm source contract: invalid core")
	}
	bridgeSetSHA256, bridgeErr := formalGLMSourceBindingSetSHA256V1(
		core.SourceBindingSet, pins)
	if bridgeErr != nil || bridgeSetSHA256 != core.BridgeSetSHA256 ||
		formalGLMValidateRegisteredExecutionPlanV1(
			core.RegisteredExecutionPlan, pins) != nil ||
		formalGLMPhase21ValidateSamplerV2ContractCore(
			core.SamplerV2ContractCore, pins) != nil {
		return fmt.Errorf("formal-glm source contract: invalid evidence")
	}
	samplerCoreSHA256, samplerErr :=
		formalGLMPhase21SamplerV2ContractCoreSHA256V1(
			core.SamplerV2ContractCore, pins)
	plan := core.RegisteredExecutionPlan
	if samplerErr != nil || core.ArtifactID != plan.ArtifactID ||
		core.ArtifactID != core.SamplerV2ContractCore.ArtifactID ||
		core.SourceBindingSet.DescriptorCoreSHA256 !=
			plan.DescriptorCoreSHA256 ||
		samplerCoreSHA256 != plan.SamplerV2ContractCoreSHA256 ||
		!reflect.DeepEqual(core.SamplerV2ContractCore.Artifact, plan.Artifact) ||
		core.SourceBindingSet.LogicalSnapshotSHA256 != plan.SnapshotSHA256 ||
		core.SourceBindingSet.GoPinsetSHA256 != plan.PinsetSHA256 ||
		!reflect.DeepEqual(core.SourceBindingSet.PeerIdentities,
			formalGLMSourceContractPeerIdentitiesV1(
				plan.CustodianPeers, pins)) {
		return fmt.Errorf("formal-glm source contract: evidence differs")
	}
	for _, source := range core.SourceBindingSet.Sources {
		for _, column := range plan.DescriptorCore.UsedColumns {
			if column.Owner == source.SignerPeerName &&
				(column.DatasetID != source.DatasetID ||
					column.DatasetVersion != source.DatasetVersion) {
				return fmt.Errorf("formal-glm source contract: selected dataset differs")
			}
		}
	}
	return nil
}

func formalGLMSourceBindingSetFromReceiptsV1(
	receipts []formalGLMPSISourceBridgeReceiptV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMSourceBindingSetV1, error) {
	var zero formalGLMSourceBindingSetV1
	if err := formalGLMValidatePSISourceBridgeSetV1(receipts, pins); err != nil {
		return zero, err
	}
	set := formalGLMSourceBindingSetV1{
		Version:               "dsvert-formal-glm-psi-source-binding-set-v1",
		Sources:               make([]formalGLMSourceBindingV1, len(receipts)),
		LogicalSnapshotJSON:   receipts[0].Core.LogicalSnapshotJSON,
		LogicalSnapshotSHA256: receipts[0].Core.LogicalSnapshotSHA256,
		RPinsetID:             receipts[0].Core.RPinsetID,
		GoPinsetSHA256:        receipts[0].Core.GoPinsetSHA256,
		PeerIdentities: append([]formalGLMPeerIdentityV1(nil),
			receipts[0].Core.PeerIdentities...),
		DescriptorCoreSHA256: receipts[0].Core.DescriptorCoreSHA256,
	}
	for index, receipt := range receipts {
		set.Sources[index] = formalGLMSourceBindingV1{
			SignerPeerName:  receipt.Core.SignerPeerName,
			CohortID:        receipt.Core.CohortID,
			SourceBindingID: receipt.Core.SourceBindingID,
			DatasetID:       receipt.Core.DatasetID,
			DatasetVersion:  receipt.Core.DatasetVersion,
		}
	}
	if err := formalGLMValidateSourceBindingSetV1(set, pins); err != nil {
		return zero, err
	}
	return set, nil
}

func formalGLMValidateSourceBindingSetV1(
	set formalGLMSourceBindingSetV1,
	pins map[string]ed25519.PublicKey,
) error {
	psiPinset, psiErr := formalGLMPSIPinsetIDV1(pins)
	goPinset, goErr := formalGLMPhase16PinsetSHA256(pins)
	snapshotDigest := sha256.Sum256([]byte(set.LogicalSnapshotJSON))
	if set.Version != "dsvert-formal-glm-psi-source-binding-set-v1" ||
		len(set.Sources) != len(pins) || len(set.Sources) < 2 ||
		len(set.PeerIdentities) != len(pins) ||
		psiErr != nil || goErr != nil || set.RPinsetID != psiPinset ||
		set.GoPinsetSHA256 != goPinset ||
		!formalGLMCanonicalJSONStringV1(set.LogicalSnapshotJSON, 64<<10) ||
		hex.EncodeToString(snapshotDigest[:]) != set.LogicalSnapshotSHA256 ||
		!formalGLMIsSHA256(set.DescriptorCoreSHA256) {
		return fmt.Errorf("formal-glm source contract: invalid source binding set")
	}
	var snapshot map[string]any
	if json.Unmarshal([]byte(set.LogicalSnapshotJSON), &snapshot) != nil {
		return fmt.Errorf("formal-glm source contract: invalid source snapshot")
	}
	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}
	sort.Strings(names)
	for index, peer := range names {
		source := set.Sources[index]
		identity := set.PeerIdentities[index]
		if source.SignerPeerName != peer ||
			snapshot["logical_snapshot_id"] != source.CohortID ||
			!formalGLMRegistryHexLabelV1(source.SourceBindingID, "source_") ||
			!formalGLMRegistryLabelV1(source.DatasetID, 128) ||
			!formalGLMRegistryLabelV1(source.DatasetVersion, 128) ||
			identity.PeerName != peer ||
			identity.IdentityPK != formalGLMIdentityPKV1(pins[peer]) {
			return fmt.Errorf("formal-glm source contract: invalid source binding")
		}
	}
	return nil
}

func formalGLMSourceBindingSetJSONV1(
	set formalGLMSourceBindingSetV1,
) ([]byte, error) {
	return formalGLMCanonicalJSONV1(set)
}

func formalGLMSourceBindingSetSHA256V1(
	set formalGLMSourceBindingSetV1,
	pins map[string]ed25519.PublicKey,
) (string, error) {
	if err := formalGLMValidateSourceBindingSetV1(set, pins); err != nil {
		return "", err
	}
	encoded, err := formalGLMSourceBindingSetJSONV1(set)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPSISourceBridgeDomain+"/set|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMSourceContractPeerIdentitiesV1(
	peers []string,
	pins map[string]ed25519.PublicKey,
) []formalGLMPeerIdentityV1 {
	identities := make([]formalGLMPeerIdentityV1, len(peers))
	for index, peer := range peers {
		identities[index] = formalGLMPeerIdentityV1{
			PeerName: peer, IdentityPK: formalGLMIdentityPKV1(pins[peer]),
		}
	}
	return identities
}

func formalGLMSourceContractCoreSHA256V1(
	core formalGLMSourceContractCoreV1,
) (string, error) {
	if core.Version != formalGLMSourceContractCoreVersion ||
		core.Purpose != formalGLMSourceContractCorePurpose {
		return "", fmt.Errorf("formal-glm source contract: invalid core hash input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMSourceContractDomain+"/core", core)
}

func formalGLMSourceContractMessageV1(
	core formalGLMSourceContractCoreV1,
) ([]byte, error) {
	encoded, err := json.Marshal(core)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMSourceContractDomain+"/custodian|"),
		encoded...), nil
}

func formalGLMSignSourceContractV1(
	core formalGLMSourceContractCoreV1,
	signer string,
	privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSignature, error) {
	var zero jointDPBiomedicalGaussianSignature
	if formalGLMValidateSourceContractCoreV1(core, pins) != nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey), pins[signer]) {
		return zero, fmt.Errorf("formal-glm source contract: invalid signer")
	}
	peers := core.RegisteredExecutionPlan.CustodianPeers
	index := sort.SearchStrings(peers, signer)
	if index == len(peers) || peers[index] != signer {
		return zero, fmt.Errorf("formal-glm source contract: signer is not a custodian")
	}
	message, err := formalGLMSourceContractMessageV1(core)
	if err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianSignature{
		Signer: signer, Signature: ed25519.Sign(privateKey, message),
	}, nil
}

func formalGLMSealSourceContractV1(
	core formalGLMSourceContractCoreV1,
	approvals []jointDPBiomedicalGaussianSignature,
	pins map[string]ed25519.PublicKey,
) (formalGLMSourceContractV1, error) {
	var zero formalGLMSourceContractV1
	if err := formalGLMValidateSourceContractCoreV1(core, pins); err != nil ||
		len(approvals) != core.RegisteredExecutionPlan.CustodianCount {
		return zero, fmt.Errorf("formal-glm source contract: requires K-of-K approvals")
	}
	message, err := formalGLMSourceContractMessageV1(core)
	if err != nil {
		return zero, err
	}
	sealed := formalGLMSourceContractV1{
		Version: formalGLMSourceContractVersion,
		Purpose: formalGLMSourceContractPurpose,
		Core:    core, ProductionReady: false,
		CustodianApprovals: make(
			[]jointDPBiomedicalGaussianSignature, len(approvals)),
	}
	sealed.CoreSHA256, err = formalGLMSourceContractCoreSHA256V1(core)
	if err != nil {
		return zero, err
	}
	for index, peer := range core.RegisteredExecutionPlan.CustodianPeers {
		approval := approvals[index]
		if approval.Signer != peer ||
			len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, approval.Signature) {
			return zero, fmt.Errorf("formal-glm source contract: invalid approval")
		}
		sealed.CustodianApprovals[index] =
			jointDPBiomedicalGaussianSignature{
				Signer:    peer,
				Signature: append([]byte(nil), approval.Signature...),
			}
	}
	if err := formalGLMValidateSourceContractV1(sealed, pins); err != nil {
		return zero, err
	}
	return sealed, nil
}

func formalGLMValidateSourceContractV1(
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	coreSHA256, hashErr := formalGLMSourceContractCoreSHA256V1(contract.Core)
	if contract.Version != formalGLMSourceContractVersion ||
		contract.Purpose != formalGLMSourceContractPurpose ||
		contract.ProductionReady || hashErr != nil ||
		contract.CoreSHA256 != coreSHA256 ||
		formalGLMValidateSourceContractCoreV1(contract.Core, pins) != nil ||
		len(contract.CustodianApprovals) !=
			contract.Core.RegisteredExecutionPlan.CustodianCount {
		return fmt.Errorf("formal-glm source contract: invalid sealed contract")
	}
	message, err := formalGLMSourceContractMessageV1(contract.Core)
	if err != nil {
		return err
	}
	for index, peer := range contract.Core.RegisteredExecutionPlan.CustodianPeers {
		approval := contract.CustodianApprovals[index]
		if approval.Signer != peer ||
			len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, approval.Signature) {
			return fmt.Errorf("formal-glm source contract: invalid K approval")
		}
	}
	return nil
}

func formalGLMSourceContractSHA256V1(
	contract formalGLMSourceContractV1,
) (string, error) {
	if contract.Version != formalGLMSourceContractVersion ||
		contract.Purpose != formalGLMSourceContractPurpose {
		return "", fmt.Errorf("formal-glm source contract: invalid hash input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMSourceContractDomain+"/sealed-contract", contract)
}

func formalGLMDecodeSourceContractV1(
	encoded []byte,
	pins map[string]ed25519.PublicKey,
) (formalGLMSourceContractV1, error) {
	var contract formalGLMSourceContractV1
	if len(encoded) < 2 || len(encoded) > formalGLMSourceContractMaxJSON ||
		encoded[0] != '{' {
		return contract, fmt.Errorf("formal-glm source contract: invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return formalGLMSourceContractV1{},
			fmt.Errorf("formal-glm source contract: invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return formalGLMSourceContractV1{},
			fmt.Errorf("formal-glm source contract: trailing JSON")
	}
	canonical, err := json.Marshal(contract)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return formalGLMSourceContractV1{},
			fmt.Errorf("formal-glm source contract: non-canonical JSON")
	}
	if err := formalGLMValidateSourceContractV1(contract, pins); err != nil {
		return formalGLMSourceContractV1{}, err
	}
	return contract, nil
}

func formalGLMSourceContractCloneCoreV1(
	core formalGLMSourceContractCoreV1,
) (formalGLMSourceContractCoreV1, error) {
	encoded, err := json.Marshal(core)
	if err != nil {
		return formalGLMSourceContractCoreV1{}, err
	}
	var cloned formalGLMSourceContractCoreV1
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return formalGLMSourceContractCoreV1{}, err
	}
	return cloned, nil
}
