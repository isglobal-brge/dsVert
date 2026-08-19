package main

// K-signed Phase0/model projection and Rock-local pre-source registry draft.
// The projection contains only scientific metadata already validated by the
// server Phase0/Phase18 path. Dataset identities are filled from the ordered
// K-of-K PSI bridge receipt set, never from an analyst selector.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

const (
	formalGLMPreSourceModelVersion = "dsvert-formal-glm-pre-source-model-v1"
	formalGLMPreSourceModelPurpose = "formal_glm_k_signed_phase0_model_projection_v1"
	formalGLMPreSourceModelDomain  = "dsVert/formal-glm/pre-source-model/v1"

	formalGLMSignedPreSourceModelVersion = "dsvert-formal-glm-signed-pre-source-model-v1"
	formalGLMSignedPreSourceModelPurpose = "formal_glm_k_signed_pre_source_model_v1"
	formalGLMSignedPreSourceModelDomain  = "dsVert/formal-glm/signed-pre-source-model/v1"

	formalGLMProjectedSchemaVersion = "dsvert-formal-glm-projected-schema-v1"
	formalGLMProjectedSchemaPurpose = "formal_glm_used_column_schema_projection_v1"
	formalGLMProjectedSchemaDomain  = "dsVert/formal-glm/projected-schema/v1"
)

type formalGLMPreSourceColumnV1 struct {
	Owner          string   `json:"owner"`
	Column         string   `json:"column"`
	Role           string   `json:"role"`
	Kind           string   `json:"kind"`
	LowerRational  string   `json:"lower_rational,omitempty"`
	UpperRational  string   `json:"upper_rational,omitempty"`
	Levels         []string `json:"levels,omitempty"`
	ReferenceLevel string   `json:"reference_level,omitempty"`
	Contrast       string   `json:"contrast,omitempty"`
}

type formalGLMPreSourceModelCoreV1 struct {
	Version                   string                          `json:"version"`
	Purpose                   string                          `json:"purpose"`
	ScientificArtifactSHA256  string                          `json:"scientific_artifact_sha256"`
	CanonicalScienceSHA256    string                          `json:"canonical_science_sha256"`
	Family                    string                          `json:"family"`
	CanonicalQualifiedFormula string                          `json:"canonical_qualified_formula"`
	FormulaSHA256             string                          `json:"formula_sha256"`
	CoefficientOrder          []string                        `json:"coefficient_order"`
	TermMap                   []formalGLMPublicTermV1         `json:"term_map"`
	UsedColumns               []formalGLMPreSourceColumnV1    `json:"used_columns"`
	Mechanism                 string                          `json:"mechanism"`
	Allocation                string                          `json:"allocation"`
	EpsilonRational           string                          `json:"epsilon_rational"`
	DeltaRational             string                          `json:"delta_rational"`
	SchemaManifestSHA256      string                          `json:"schema_manifest_sha256"`
	SnapshotSHA256            string                          `json:"snapshot_sha256"`
	PinsetSHA256              string                          `json:"pinset_sha256"`
	CanonicalDP               formalGLMCanonicalPreSourceDPV1 `json:"canonical_dp"`
	CanonicalDPSHA256         string                          `json:"canonical_dp_sha256"`
}

type formalGLMSignedPreSourceModelV1 struct {
	Version            string                               `json:"version"`
	Purpose            string                               `json:"purpose"`
	Model              formalGLMPreSourceModelCoreV1        `json:"model"`
	ModelSHA256        string                               `json:"model_sha256"`
	CustodianPeers     []string                             `json:"custodian_peers"`
	CustodianCount     int                                  `json:"custodian_count"`
	ProductionReady    bool                                 `json:"production_ready"`
	CustodianApprovals []jointDPBiomedicalGaussianSignature `json:"custodian_approvals"`
}

type formalGLMPreSourceProvisionDraftV1 struct {
	DescriptorCore       formalGLMPublicDescriptorCoreV1   `json:"descriptor_core"`
	DescriptorCoreSHA256 string                            `json:"descriptor_core_sha256"`
	Artifact             formalGLMPhase21StickyArtifact    `json:"artifact"`
	ArtifactID           string                            `json:"artifact_id"`
	BridgeSetSHA256      string                            `json:"bridge_set_sha256"`
	FormalAnalysisIDs    []string                          `json:"formal_analysis_ids"`
	UnsignedDescriptor   formalGLMSignedPublicDescriptorV1 `json:"unsigned_descriptor"`
}

type formalGLMPreSourceDatasetBindingV1 struct {
	Owner          string `json:"owner"`
	DatasetID      string `json:"dataset_id"`
	DatasetVersion string `json:"dataset_version"`
}

type formalGLMPreSourceProvisionTemplateV1 struct {
	DescriptorCore       formalGLMPublicDescriptorCoreV1   `json:"descriptor_core"`
	DescriptorCoreSHA256 string                            `json:"descriptor_core_sha256"`
	Artifact             formalGLMPhase21StickyArtifact    `json:"artifact"`
	ArtifactID           string                            `json:"artifact_id"`
	FormalAnalysisIDs    []string                          `json:"formal_analysis_ids"`
	UnsignedDescriptor   formalGLMSignedPublicDescriptorV1 `json:"unsigned_descriptor"`
}

func formalGLMProjectedSchemaSHA256V1(snapshotSHA256 string,
	columns []formalGLMPublicColumnV1,
) (string, error) {
	if !formalGLMIsSHA256(snapshotSHA256) || len(columns) < 1 ||
		len(columns) > 4096 {
		return "", fmt.Errorf("formal-glm: invalid projected schema")
	}
	for index, column := range columns {
		if !formalGLMRegistryLabelV1(column.Owner, 128) ||
			!formalGLMRegistryLabelV1(column.DatasetID, 128) ||
			!formalGLMRegistryLabelV1(column.DatasetVersion, 128) ||
			!formalGLMRegistryLabelV1(column.Column, 128) ||
			(index > 0 && formalGLMPreSourceColumnSortKeyV1(columns[index-1]) >=
				formalGLMPreSourceColumnSortKeyV1(column)) {
			return "", fmt.Errorf("formal-glm: invalid projected schema columns")
		}
	}
	projection := struct {
		Version        string                    `json:"version"`
		Purpose        string                    `json:"purpose"`
		SnapshotSHA256 string                    `json:"snapshot_sha256"`
		UsedColumns    []formalGLMPublicColumnV1 `json:"used_columns"`
	}{
		Version:        formalGLMProjectedSchemaVersion,
		Purpose:        formalGLMProjectedSchemaPurpose,
		SnapshotSHA256: snapshotSHA256,
		UsedColumns:    append([]formalGLMPublicColumnV1(nil), columns...),
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMProjectedSchemaDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPreSourceColumnSortKeyV1(column formalGLMPublicColumnV1) string {
	return column.Owner + "\x00" + column.DatasetID + "\x00" +
		column.DatasetVersion + "\x00" + column.Column
}

func formalGLMPreSourceModelSHA256V1(
	model formalGLMPreSourceModelCoreV1,
) (string, error) {
	if err := formalGLMValidatePreSourceModelCoreV1(model); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPreSourceModelDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMValidatePreSourceModelCoreV1(
	model formalGLMPreSourceModelCoreV1,
) error {
	canonicalDPSHA256, dpErr := formalGLMCanonicalPreSourceDPSHA256V1(
		model.CanonicalDP)
	formula, formulaErr := formalGLMCanonicalQualifiedFormulaV1(
		model.CanonicalQualifiedFormula)
	if model.Version != formalGLMPreSourceModelVersion ||
		model.Purpose != formalGLMPreSourceModelPurpose ||
		!formalGLMIsSHA256(model.ScientificArtifactSHA256) ||
		!formalGLMIsSHA256(model.CanonicalScienceSHA256) ||
		!formalGLMIsSHA256(model.SchemaManifestSHA256) ||
		!formalGLMIsSHA256(model.SnapshotSHA256) ||
		!formalGLMIsSHA256(model.PinsetSHA256) || dpErr != nil ||
		model.CanonicalDPSHA256 != canonicalDPSHA256 ||
		model.CanonicalDP.SnapshotSHA256 != model.SnapshotSHA256 ||
		model.CanonicalDP.PinsetSHA256 != model.PinsetSHA256 ||
		model.CanonicalDP.Family != model.Family || formulaErr != nil ||
		formula.Canonical != model.CanonicalQualifiedFormula ||
		formula.SHA256 != model.FormulaSHA256 ||
		model.Mechanism != formalGLMPhase16RequiredMechanism ||
		model.Allocation != formalGLMPhase16RequiredAllocation ||
		len(model.UsedColumns) < 1 || len(model.UsedColumns) > 4096 {
		return fmt.Errorf("formal-glm: invalid pre-source model projection")
	}
	if err := formalGLMPhase21ValidateCanonicalRational(
		model.EpsilonRational, "pre-source epsilon", false); err != nil {
		return err
	}
	if err := formalGLMPhase21ValidateCanonicalRational(
		model.DeltaRational, "pre-source delta", true); err != nil {
		return err
	}
	columns := make([]formalGLMPublicColumnV1, len(model.UsedColumns))
	for index, column := range model.UsedColumns {
		columns[index] = formalGLMPublicColumnV1{
			Owner: column.Owner, DatasetID: "pending", DatasetVersion: "v1",
			Column: column.Column, Role: column.Role, Kind: column.Kind,
			LowerRational:  column.LowerRational,
			UpperRational:  column.UpperRational,
			Levels:         append([]string(nil), column.Levels...),
			ReferenceLevel: column.ReferenceLevel, Contrast: column.Contrast,
		}
	}
	orderSHA256, err := formalGLMCoefficientOrderSHA256V1(
		model.CoefficientOrder, model.TermMap)
	if err != nil {
		return err
	}
	template := formalGLMPublicDescriptorCoreV1{
		Version:                   formalGLMPublicDescriptorCoreVersion,
		Purpose:                   formalGLMPublicDescriptorCorePurpose,
		Family:                    model.Family,
		CanonicalQualifiedFormula: model.CanonicalQualifiedFormula,
		FormulaSHA256:             model.FormulaSHA256,
		CoefficientOrder:          append([]string(nil), model.CoefficientOrder...),
		CoefficientOrderSHA256:    orderSHA256,
		TermMap:                   append([]formalGLMPublicTermV1(nil), model.TermMap...),
		UsedColumns:               columns,
		ShiftedUpperBounds: append([]string(nil),
			model.CanonicalDP.ShiftedUpperBounds...),
		OutputLatticeScale: fmt.Sprintf("2^-%d",
			model.CanonicalDP.OutputLatticeBits),
		SourceFractionBits:             model.CanonicalDP.SourceFractionBits,
		QuantizationShift:              model.CanonicalDP.QuantizationShift,
		OutputLatticeBits:              model.CanonicalDP.OutputLatticeBits,
		Quantization:                   "signed_integer_shift_then_clamp_v1",
		CanonicalPreSourceDPSHA256:     model.CanonicalDPSHA256,
		SnapshotSHA256:                 model.SnapshotSHA256,
		SchemaManifestSHA256:           model.SchemaManifestSHA256,
		TransportCoordinateOrderSHA256: model.CanonicalDP.TransportCoordinateOrderSHA256,
		PinsetSHA256:                   model.PinsetSHA256,
		BoundsSHA256:                   model.CanonicalDP.BoundsSHA256,
		QuantizationSHA256:             model.CanonicalDP.QuantizationSHA256,
	}
	return formalGLMValidatePublicDescriptorCoreV1(template)
}

func formalGLMSignedPreSourceModelMessageV1(
	value formalGLMSignedPreSourceModelV1,
) ([]byte, error) {
	value.CustodianApprovals = nil
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMSignedPreSourceModelDomain+"|"), encoded...), nil
}

func formalGLMValidateSignedPreSourceModelCoreV1(
	value formalGLMSignedPreSourceModelV1,
	pins map[string]ed25519.PublicKey,
) error {
	modelSHA256, err := formalGLMPreSourceModelSHA256V1(value.Model)
	peers := make([]string, 0, len(pins))
	for peer := range pins {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	if err != nil || value.Version != formalGLMSignedPreSourceModelVersion ||
		value.Purpose != formalGLMSignedPreSourceModelPurpose ||
		value.ModelSHA256 != modelSHA256 || value.CustodianCount < 2 ||
		value.CustodianCount != len(pins) ||
		value.CustodianCount != len(value.CustodianPeers) ||
		!reflect.DeepEqual(value.CustodianPeers, peers) ||
		value.Model.PinsetSHA256 == "" || value.ProductionReady {
		return fmt.Errorf("formal-glm: invalid signed pre-source model")
	}
	pinset, pinErr := formalGLMPhase16PinsetSHA256(pins)
	if pinErr != nil || pinset != value.Model.PinsetSHA256 {
		return fmt.Errorf("formal-glm: pre-source model pinset mismatch")
	}
	return nil
}

func formalGLMSignPreSourceModelV1(value formalGLMSignedPreSourceModelV1,
	peer string, privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSignature, error) {
	if len(value.CustodianApprovals) != 0 ||
		formalGLMValidateSignedPreSourceModelCoreV1(value, pins) != nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey), pins[peer]) {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("formal-glm: invalid pre-source model signer")
	}
	message, err := formalGLMSignedPreSourceModelMessageV1(value)
	if err != nil {
		return jointDPBiomedicalGaussianSignature{}, err
	}
	return jointDPBiomedicalGaussianSignature{
		Signer: peer, Signature: ed25519.Sign(privateKey, message),
	}, nil
}

func formalGLMSealPreSourceModelV1(value formalGLMSignedPreSourceModelV1,
	approvals []jointDPBiomedicalGaussianSignature,
	pins map[string]ed25519.PublicKey,
) (formalGLMSignedPreSourceModelV1, error) {
	value.CustodianApprovals = append(
		[]jointDPBiomedicalGaussianSignature(nil), approvals...)
	if err := formalGLMValidateSignedPreSourceModelV1(value, pins); err != nil {
		return formalGLMSignedPreSourceModelV1{}, err
	}
	return value, nil
}

func formalGLMValidateSignedPreSourceModelV1(
	value formalGLMSignedPreSourceModelV1,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMValidateSignedPreSourceModelCoreV1(value, pins); err != nil {
		return err
	}
	if len(value.CustodianApprovals) != value.CustodianCount {
		return fmt.Errorf("formal-glm: pre-source model lacks K approvals")
	}
	message, err := formalGLMSignedPreSourceModelMessageV1(value)
	if err != nil {
		return err
	}
	for index, peer := range value.CustodianPeers {
		approval := value.CustodianApprovals[index]
		if approval.Signer != peer ||
			len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, approval.Signature) {
			return fmt.Errorf("formal-glm: invalid ordered pre-source model approval")
		}
	}
	return nil
}

func formalGLMDescriptorCoreFromPreSourceV1(
	model formalGLMSignedPreSourceModelV1,
	receipts []formalGLMPSISourceBridgeReceiptV1,
	pins map[string]ed25519.PublicKey, requireDescriptorBinding bool,
) (formalGLMPublicDescriptorCoreV1, string, error) {
	var zero formalGLMPublicDescriptorCoreV1
	if formalGLMValidateSignedPreSourceModelV1(model, pins) != nil ||
		formalGLMValidatePSISourceBridgeSetV1(receipts, pins) != nil {
		return zero, "", fmt.Errorf("formal-glm: invalid pre-source evidence")
	}
	datasets := make(map[string]formalGLMPreSourceDatasetBindingV1, len(receipts))
	for _, receipt := range receipts {
		core := receipt.Core
		if core.SchemaManifestSHA256 != model.Model.SchemaManifestSHA256 ||
			core.LogicalSnapshotSHA256 != model.Model.SnapshotSHA256 ||
			core.GoPinsetSHA256 != model.Model.PinsetSHA256 {
			return zero, "", fmt.Errorf("formal-glm: PSI/model projection mismatch")
		}
		datasets[core.SignerPeerName] = formalGLMPreSourceDatasetBindingV1{
			Owner: core.SignerPeerName, DatasetID: core.DatasetID,
			DatasetVersion: core.DatasetVersion,
		}
	}
	core, coreSHA256, err := formalGLMDescriptorCoreFromDatasetMapV1(
		model.Model, datasets)
	if err != nil {
		return zero, "", err
	}
	if requireDescriptorBinding {
		for _, receipt := range receipts {
			if receipt.Core.DescriptorCoreSHA256 != coreSHA256 {
				return zero, "", fmt.Errorf("formal-glm: PSI receipt descriptor mismatch")
			}
		}
	}
	return core, coreSHA256, nil
}

func formalGLMDescriptorCoreFromDatasetBindingsV1(
	model formalGLMSignedPreSourceModelV1,
	bindings []formalGLMPreSourceDatasetBindingV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMPublicDescriptorCoreV1, string, error) {
	var zero formalGLMPublicDescriptorCoreV1
	if formalGLMValidateSignedPreSourceModelCoreV1(model, pins) != nil ||
		len(bindings) != model.CustodianCount {
		return zero, "", fmt.Errorf("formal-glm: invalid pre-source schema bindings")
	}
	datasets := make(map[string]formalGLMPreSourceDatasetBindingV1, len(bindings))
	for _, binding := range bindings {
		if !formalGLMRegistryLabelV1(binding.Owner, 128) ||
			!formalGLMRegistryLabelV1(binding.DatasetID, 128) ||
			!formalGLMRegistryLabelV1(binding.DatasetVersion, 128) ||
			len(pins[binding.Owner]) != ed25519.PublicKeySize {
			return zero, "", fmt.Errorf("formal-glm: invalid pre-source dataset binding")
		}
		if _, exists := datasets[binding.Owner]; exists {
			return zero, "", fmt.Errorf("formal-glm: duplicate pre-source dataset binding")
		}
		datasets[binding.Owner] = binding
	}
	for _, peer := range model.CustodianPeers {
		if _, exists := datasets[peer]; !exists {
			return zero, "", fmt.Errorf("formal-glm: incomplete pre-source dataset bindings")
		}
	}
	return formalGLMDescriptorCoreFromDatasetMapV1(model.Model, datasets)
}

func formalGLMDescriptorCoreFromDatasetMapV1(
	model formalGLMPreSourceModelCoreV1,
	datasets map[string]formalGLMPreSourceDatasetBindingV1,
) (formalGLMPublicDescriptorCoreV1, string, error) {
	var zero formalGLMPublicDescriptorCoreV1
	columns := make([]formalGLMPublicColumnV1, len(model.UsedColumns))
	for index, column := range model.UsedColumns {
		dataset, ok := datasets[column.Owner]
		if !ok {
			return zero, "", fmt.Errorf("formal-glm: missing owner dataset receipt")
		}
		columns[index] = formalGLMPublicColumnV1{
			Owner: column.Owner, DatasetID: dataset.DatasetID,
			DatasetVersion: dataset.DatasetVersion, Column: column.Column,
			Role: column.Role, Kind: column.Kind,
			LowerRational:  column.LowerRational,
			UpperRational:  column.UpperRational,
			Levels:         append([]string(nil), column.Levels...),
			ReferenceLevel: column.ReferenceLevel, Contrast: column.Contrast,
		}
	}
	sort.Slice(columns, func(i, j int) bool {
		return formalGLMPreSourceColumnSortKeyV1(columns[i]) <
			formalGLMPreSourceColumnSortKeyV1(columns[j])
	})
	projectedSchemaSHA256, err := formalGLMProjectedSchemaSHA256V1(
		model.SnapshotSHA256, columns)
	if err != nil {
		return zero, "", err
	}
	orderSHA256, err := formalGLMCoefficientOrderSHA256V1(
		model.CoefficientOrder, model.TermMap)
	if err != nil {
		return zero, "", err
	}
	dp := model.CanonicalDP
	core := formalGLMPublicDescriptorCoreV1{
		Version:                    formalGLMPublicDescriptorCoreVersion,
		Purpose:                    formalGLMPublicDescriptorCorePurpose,
		Family:                     model.Family,
		CanonicalQualifiedFormula:  model.CanonicalQualifiedFormula,
		FormulaSHA256:              model.FormulaSHA256,
		CoefficientOrder:           append([]string(nil), model.CoefficientOrder...),
		CoefficientOrderSHA256:     orderSHA256,
		TermMap:                    append([]formalGLMPublicTermV1(nil), model.TermMap...),
		UsedColumns:                columns,
		ShiftedUpperBounds:         append([]string(nil), dp.ShiftedUpperBounds...),
		OutputLatticeScale:         fmt.Sprintf("2^-%d", dp.OutputLatticeBits),
		SourceFractionBits:         dp.SourceFractionBits,
		QuantizationShift:          dp.QuantizationShift,
		OutputLatticeBits:          dp.OutputLatticeBits,
		Quantization:               "signed_integer_shift_then_clamp_v1",
		CanonicalPreSourceDPSHA256: model.CanonicalDPSHA256,
		SnapshotSHA256:             model.SnapshotSHA256,
		// The full signed schema remains PSI/model authorization evidence.
		// Public identity binds only the selected used-column projection.
		SchemaManifestSHA256:           projectedSchemaSHA256,
		TransportCoordinateOrderSHA256: dp.TransportCoordinateOrderSHA256,
		PinsetSHA256:                   model.PinsetSHA256,
		BoundsSHA256:                   dp.BoundsSHA256,
		QuantizationSHA256:             dp.QuantizationSHA256,
	}
	coreSHA256, err := formalGLMPublicDescriptorCoreSHA256V1(core)
	if err != nil {
		return zero, "", err
	}
	return core, coreSHA256, nil
}

func formalGLMBuildUnboundStickyArtifactFromPreSourceCoreV1(
	model formalGLMSignedPreSourceModelV1, plan formalGLMPhase15Plan,
	projectedSchemaSHA256 string, pins map[string]ed25519.PublicKey,
	requireApprovals bool,
) (formalGLMPhase21StickyArtifact, string, error) {
	var zero formalGLMPhase21StickyArtifact
	modelErr := formalGLMValidateSignedPreSourceModelCoreV1(model, pins)
	if requireApprovals {
		modelErr = formalGLMValidateSignedPreSourceModelV1(model, pins)
	}
	if modelErr != nil ||
		!formalGLMIsSHA256(projectedSchemaSHA256) ||
		validateFormalGLMPhase15Plan(plan) != nil {
		return zero, "", fmt.Errorf("formal-glm: invalid pre-source artifact input")
	}
	dp := model.Model.CanonicalDP
	canonicalPlanSHA256, err := formalGLMPhase21CanonicalPlanSHA256(plan)
	if err != nil || canonicalPlanSHA256 != dp.CanonicalPlanSHA256 ||
		plan.Kernel.ArtifactSHA256 != model.Model.ScientificArtifactSHA256 ||
		plan.Kernel.CanonicalScienceSHA256 != model.Model.CanonicalScienceSHA256 ||
		plan.Kernel.SnapshotSHA256 != model.Model.SnapshotSHA256 ||
		plan.Kernel.PinsetSHA256 != model.Model.PinsetSHA256 ||
		plan.Kernel.Family != model.Model.Family ||
		plan.Kernel.Adjacency != dp.Adjacency {
		return zero, "", fmt.Errorf("formal-glm: pre-source plan/model mismatch")
	}
	roles, err := formalGLMPhase16PinnedRoles(plan, pins)
	if err != nil {
		return zero, "", err
	}
	adjacency, err := formalGLMPhase16CommonAdjacency(plan.Kernel.Adjacency)
	if err != nil {
		return zero, "", err
	}
	canonicalLinkSHA256, err := formalGLMPhase21CanonicalLinkSHA256(plan.Kernel)
	if err != nil {
		return zero, "", err
	}
	artifact := formalGLMPhase21StickyArtifact{
		Version: formalGLMPhase21StickyVersion, Purpose: formalGLMPhase21StickyPurpose,
		CanonicalScienceSHA256:  model.Model.CanonicalScienceSHA256,
		ScientificArtifactScope: "phase0_formula_estimand_adjacency_optimizer_link_numeric_dp_projection_v1",
		CanonicalPlanSHA256:     canonicalPlanSHA256,
		SchemaManifestSHA256:    projectedSchemaSHA256,
		SnapshotSHA256:          model.Model.SnapshotSHA256,
		PinsetSHA256:            model.Model.PinsetSHA256,
		CustodianPeers:          append([]string(nil), model.CustodianPeers...),
		CustodianCount:          model.CustodianCount,
		DesignatedComputePeers:  []string{roles.GarblerPeerName, roles.EvaluatorPeerName},
		NoiseAuthorities: []formalGLMPhase21StickyNoiseAuthority{
			{Role: "garbler", PeerName: roles.GarblerPeerName, PeerID: roles.GarblerPeerID},
			{Role: "evaluator", PeerName: roles.EvaluatorPeerName, PeerID: roles.EvaluatorPeerID},
		},
		Family: model.Model.Family, Adjacency: adjacency,
		Mechanism: model.Model.Mechanism, Allocation: model.Model.Allocation,
		EpsilonRational:       model.Model.EpsilonRational,
		DeltaRational:         model.Model.DeltaRational,
		SensitivitySteps:      dp.SelectedSensitivitySteps,
		BoundsSHA256:          dp.BoundsSHA256,
		QuantizationSHA256:    dp.QuantizationSHA256,
		CanonicalLinkSHA256:   canonicalLinkSHA256,
		CoordinateOrderSHA256: dp.TransportCoordinateOrderSHA256,
		CoordinateCount:       dp.CoordinateCount,
		SourceFractionBits:    dp.SourceFractionBits,
		QuantizationShift:     dp.QuantizationShift,
		OutputLatticeBits:     dp.OutputLatticeBits,
	}
	if err := formalGLMPhase21ValidateStickyArtifact(artifact, pins); err != nil {
		return zero, "", err
	}
	id, err := formalGLMPhase21StickyArtifactID(artifact)
	return artifact, id, err
}

func formalGLMBuildUnboundStickyArtifactFromPreSourceV1(
	model formalGLMSignedPreSourceModelV1, plan formalGLMPhase15Plan,
	projectedSchemaSHA256 string, pins map[string]ed25519.PublicKey,
) (formalGLMPhase21StickyArtifact, string, error) {
	return formalGLMBuildUnboundStickyArtifactFromPreSourceCoreV1(
		model, plan, projectedSchemaSHA256, pins, true)
}

func formalGLMBuildPreSourceProvisionTemplateV1(
	model formalGLMSignedPreSourceModelV1,
	bindings []formalGLMPreSourceDatasetBindingV1,
	plan formalGLMPhase15Plan, pins map[string]ed25519.PublicKey,
	formalAnalysisIDs []string,
) (formalGLMPreSourceProvisionTemplateV1, error) {
	var zero formalGLMPreSourceProvisionTemplateV1
	core, coreSHA256, err := formalGLMDescriptorCoreFromDatasetBindingsV1(
		model, bindings, pins)
	if err != nil {
		return zero, err
	}
	unbound, _, err := formalGLMBuildUnboundStickyArtifactFromPreSourceCoreV1(
		model, plan, core.SchemaManifestSHA256, pins, false)
	if err != nil {
		return zero, err
	}
	artifact, artifactID, err := formalGLMPhase21BindDescriptorCore(
		unbound, coreSHA256, pins)
	if err != nil {
		return zero, err
	}
	aliases := formalGLMSortedUniqueLabelsV1(formalAnalysisIDs)
	if len(aliases) < 1 {
		return zero, fmt.Errorf("formal-glm: missing pre-source registry alias")
	}
	for _, alias := range aliases {
		if !formalGLMRegistryLabelV1(alias, 256) {
			return zero, fmt.Errorf("formal-glm: invalid pre-source registry alias")
		}
	}
	descriptor := formalGLMSignedPublicDescriptorV1{
		Version:    formalGLMSignedPublicDescriptorVersion,
		Purpose:    formalGLMSignedPublicDescriptorPurpose,
		Descriptor: core, DescriptorCoreSHA256: coreSHA256,
		ArtifactID:     artifactID,
		CustodianPeers: append([]string(nil), model.CustodianPeers...),
		CustodianCount: model.CustodianCount, ProductionReady: false,
	}
	if err := formalGLMValidateSignedPublicDescriptorCoreV1(
		descriptor, pins); err != nil {
		return zero, err
	}
	return formalGLMPreSourceProvisionTemplateV1{
		DescriptorCore: core, DescriptorCoreSHA256: coreSHA256,
		Artifact: artifact, ArtifactID: artifactID,
		FormalAnalysisIDs: aliases, UnsignedDescriptor: descriptor,
	}, nil
}

func formalGLMBuildPreSourceProvisionDraftV1(
	model formalGLMSignedPreSourceModelV1,
	receipts []formalGLMPSISourceBridgeReceiptV1,
	plan formalGLMPhase15Plan, pins map[string]ed25519.PublicKey,
	formalAnalysisIDs []string,
) (formalGLMPreSourceProvisionDraftV1, error) {
	var zero formalGLMPreSourceProvisionDraftV1
	core, coreSHA256, err := formalGLMDescriptorCoreFromPreSourceV1(
		model, receipts, pins, true)
	if err != nil {
		return zero, err
	}
	unbound, _, err := formalGLMBuildUnboundStickyArtifactFromPreSourceV1(
		model, plan, core.SchemaManifestSHA256, pins)
	if err != nil {
		return zero, err
	}
	artifact, artifactID, err := formalGLMPhase21BindDescriptorCore(
		unbound, coreSHA256, pins)
	if err != nil {
		return zero, err
	}
	aliases := formalGLMSortedUniqueLabelsV1(formalAnalysisIDs)
	if len(aliases) < 1 {
		return zero, fmt.Errorf("formal-glm: missing pre-source registry alias")
	}
	for _, alias := range aliases {
		if !formalGLMRegistryLabelV1(alias, 256) {
			return zero, fmt.Errorf("formal-glm: invalid pre-source registry alias")
		}
	}
	bridgeSetSHA256, err := formalGLMPSISourceBridgeSetSHA256V1(receipts, pins)
	if err != nil {
		return zero, err
	}
	descriptor := formalGLMSignedPublicDescriptorV1{
		Version:    formalGLMSignedPublicDescriptorVersion,
		Purpose:    formalGLMSignedPublicDescriptorPurpose,
		Descriptor: core, DescriptorCoreSHA256: coreSHA256,
		ArtifactID:     artifactID,
		CustodianPeers: append([]string(nil), model.CustodianPeers...),
		CustodianCount: model.CustodianCount, ProductionReady: false,
	}
	if err := formalGLMValidateSignedPublicDescriptorCoreV1(
		descriptor, pins); err != nil {
		return zero, err
	}
	return formalGLMPreSourceProvisionDraftV1{
		DescriptorCore: core, DescriptorCoreSHA256: coreSHA256,
		Artifact: artifact, ArtifactID: artifactID,
		BridgeSetSHA256:   bridgeSetSHA256,
		FormalAnalysisIDs: aliases, UnsignedDescriptor: descriptor,
	}, nil
}
