package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

const (
	formalGLMRegisteredPhase18AuthorizationVersion = "dsvert-formal-glm-registered-phase18-authorization-v1"
	formalGLMRegisteredPhase18AuthorizationPhase   = "registered_pre_execution_materialization_authorized"
	formalGLMRegisteredPhase18AuthorizationPurpose = "formal_glm_registered_source_bound_phase18_materialization_v1"
	formalGLMRegisteredPhase18AuthorizationDomain  = "dsVert/formal-glm/registered-phase18-authorization/v1"
	formalGLMRegisteredPhase18AuthorizationMaxJSON = 2 << 20

	formalGLMRegisteredPhase18PrivateCarrierRequirement = "rock_local_nonserialized_materializer_inputs_required_v1"
)

// formalGLMRegisteredPhase18GeometryV1 is the fixed public shape consumed by
// the local materializer. Patient columns, table handles, resolved snapshots,
// PSI state and alignment secrets belong to a separate Rock-local private
// carrier and have no representation in this authorization.
type formalGLMRegisteredPhase18GeometryV1 struct {
	TotalCapacity    int      `json:"total_capacity"`
	BlockCapacity    int      `json:"block_capacity"`
	TotalBlocks      int      `json:"total_blocks"`
	CoordinateCount  int      `json:"coordinate_count"`
	CoordinateOwners []string `json:"coordinate_owners"`
	RingBits         int      `json:"ring_bits"`
	ContainerBits    int      `json:"container_bits"`
	RecordBytes      int      `json:"record_bytes"`
}

type formalGLMRegisteredPhase18ScienceV1 struct {
	Family           string                  `json:"family"`
	Adjacency        string                  `json:"adjacency"`
	CoefficientOrder []string                `json:"coefficient_order"`
	TermMap          []formalGLMPublicTermV1 `json:"term_map"`
	FractionBits     int                     `json:"fraction_bits"`
	Missingness      string                  `json:"missingness"`
	PatientCollapse  string                  `json:"patient_collapse"`
	InputLayout      string                  `json:"input_layout"`
	InputSharing     string                  `json:"input_sharing"`
}

// formalGLMRegisteredPhase18AuthorizationV1 is a public, capsule-free and
// run-invariant projection of one K-of-K source contract for one local
// custodian. It is not itself an authority-bearing signature envelope: the
// authenticated source contract hash and its exact K approvals authorize all
// projected fields.
type formalGLMRegisteredPhase18AuthorizationV1 struct {
	Version             string `json:"version"`
	Phase               string `json:"phase"`
	Purpose             string `json:"purpose"`
	AuthorizationSHA256 string `json:"authorization_sha256"`

	ArtifactID                    string                                    `json:"artifact_id"`
	SourceContractCoreSHA256      string                                    `json:"source_contract_core_sha256"`
	SourceContractSHA256          string                                    `json:"source_contract_sha256"`
	BridgeSetSHA256               string                                    `json:"bridge_set_sha256"`
	LogicalSnapshotJSON           string                                    `json:"logical_snapshot_json"`
	LogicalSnapshotSHA256         string                                    `json:"logical_snapshot_sha256"`
	RPinsetID                     string                                    `json:"r_pinset_id"`
	RegisteredExecutionPlanSHA256 string                                    `json:"registered_execution_plan_sha256"`
	CanonicalScienceSHA256        string                                    `json:"canonical_science_sha256"`
	ExecutionKernel               formalGLMRegisteredExecutionKernelV1      `json:"execution_kernel"`
	DescriptorCoreSHA256          string                                    `json:"descriptor_core_sha256"`
	ProjectedSchemaSHA256         string                                    `json:"projected_schema_sha256"`
	SnapshotSHA256                string                                    `json:"snapshot_sha256"`
	PinsetSHA256                  string                                    `json:"pinset_sha256"`
	LocalSource                   formalGLMSourceBindingV1                  `json:"local_source"`
	LocalPeerIdentity             formalGLMPeerIdentityV1                   `json:"local_peer_identity"`
	LocalColumns                  []formalGLMPublicColumnV1                 `json:"local_columns"`
	CustodianPeers                []string                                  `json:"custodian_peers"`
	CustodianCount                int                                       `json:"custodian_count"`
	DesignatedComputePeers        []string                                  `json:"designated_compute_peers"`
	NoiseAuthorities              []formalGLMRegisteredExecutionAuthorityV1 `json:"noise_authorities"`
	Geometry                      formalGLMRegisteredPhase18GeometryV1      `json:"geometry"`
	Science                       formalGLMRegisteredPhase18ScienceV1       `json:"science"`
	ValiditySharing               string                                    `json:"validity_sharing"`
	AlignmentSharing              string                                    `json:"alignment_sharing"`
	CoordinateEncoding            string                                    `json:"coordinate_encoding"`
	PrivateCarrierRequirement     string                                    `json:"private_carrier_requirement"`
	OpeningsPerformed             int                                       `json:"openings_performed"`
	ProductionReady               bool                                      `json:"production_ready"`
}

func formalGLMBuildRegisteredPhase18AuthorizationV1(
	contract formalGLMSourceContractV1,
	localPeer string,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18AuthorizationV1, error) {
	var zero formalGLMRegisteredPhase18AuthorizationV1
	if err := formalGLMValidateSourceContractV1(contract, pins); err != nil {
		return zero, err
	}
	authorization, err := formalGLMProjectRegisteredPhase18AuthorizationV1(
		contract, localPeer, pins)
	if err != nil {
		return zero, err
	}
	authorization.AuthorizationSHA256, err =
		formalGLMRegisteredPhase18AuthorizationSHA256V1(authorization)
	if err != nil {
		return zero, err
	}
	if err := formalGLMValidateRegisteredPhase18AuthorizationV1(
		authorization, contract, pins); err != nil {
		return zero, err
	}
	return authorization, nil
}

func formalGLMProjectRegisteredPhase18AuthorizationV1(
	contract formalGLMSourceContractV1,
	localPeer string,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18AuthorizationV1, error) {
	var zero formalGLMRegisteredPhase18AuthorizationV1
	plan := contract.Core.RegisteredExecutionPlan
	if len(pins[localPeer]) != ed25519.PublicKeySize ||
		len(plan.DesignatedComputePeers) != 2 ||
		len(plan.NoiseAuthorities) != 2 ||
		plan.CustodianCount != len(pins) ||
		plan.CustodianCount != len(plan.CustodianPeers) ||
		plan.TotalCapacity < 1 || plan.BlockCapacity < 1 ||
		plan.TotalBlocks !=
			(plan.TotalCapacity+plan.BlockCapacity-1)/plan.BlockCapacity ||
		plan.ExecutionKernel.CoefficientCount < 1 ||
		len(plan.CoordinateOwners) !=
			plan.ExecutionKernel.CoefficientCount+3 ||
		plan.ContainerBits != exactGCTypeBits(plan.RingBits) ||
		plan.ContainerBits%8 != 0 ||
		exactGCRecordBytes(plan.RingBits) != plan.ContainerBits/8 {
		return zero, fmt.Errorf("formal-glm: invalid registered Phase18 geometry")
	}

	var localSource formalGLMSourceBindingV1
	var localIdentity formalGLMPeerIdentityV1
	foundSource := false
	foundIdentity := false
	for _, source := range contract.Core.SourceBindingSet.Sources {
		if source.SignerPeerName == localPeer {
			if foundSource {
				return zero, fmt.Errorf("formal-glm: duplicate registered Phase18 source")
			}
			localSource = source
			foundSource = true
		}
	}
	for _, identity := range contract.Core.SourceBindingSet.PeerIdentities {
		if identity.PeerName == localPeer {
			if foundIdentity {
				return zero, fmt.Errorf("formal-glm: duplicate registered Phase18 identity")
			}
			localIdentity = identity
			foundIdentity = true
		}
	}
	if !foundSource || !foundIdentity ||
		localIdentity.IdentityPK != formalGLMIdentityPKV1(pins[localPeer]) {
		return zero, fmt.Errorf("formal-glm: local registered Phase18 source is not pinned")
	}

	localColumns := make([]formalGLMPublicColumnV1, 0)
	for _, column := range plan.DescriptorCore.UsedColumns {
		if column.Owner != localPeer {
			continue
		}
		if column.DatasetID != localSource.DatasetID ||
			column.DatasetVersion != localSource.DatasetVersion {
			return zero, fmt.Errorf("formal-glm: local registered Phase18 dataset differs")
		}
		cloned := column
		cloned.Levels = append([]string(nil), column.Levels...)
		localColumns = append(localColumns, cloned)
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(contract)
	if err != nil {
		return zero, err
	}
	executionKernel := plan.ExecutionKernel
	executionKernel.XKind = append([]string(nil), plan.ExecutionKernel.XKind...)
	executionKernel.XLower = append([]string(nil), plan.ExecutionKernel.XLower...)
	executionKernel.XUpper = append([]string(nil), plan.ExecutionKernel.XUpper...)
	executionKernel.BetaStart = append(
		[]string(nil), plan.ExecutionKernel.BetaStart...)
	executionKernel.Ridge = append([]string(nil), plan.ExecutionKernel.Ridge...)
	executionKernel.CoefficientBox = append(
		[]string(nil), plan.ExecutionKernel.CoefficientBox...)
	executionKernel.LinkKnots = append(
		[]string(nil), plan.ExecutionKernel.LinkKnots...)
	executionKernel.LinkValues = append(
		[]string(nil), plan.ExecutionKernel.LinkValues...)
	executionKernel.LinkSlopes = append(
		[]string(nil), plan.ExecutionKernel.LinkSlopes...)
	authorization := formalGLMRegisteredPhase18AuthorizationV1{
		Version:                       formalGLMRegisteredPhase18AuthorizationVersion,
		Phase:                         formalGLMRegisteredPhase18AuthorizationPhase,
		Purpose:                       formalGLMRegisteredPhase18AuthorizationPurpose,
		ArtifactID:                    contract.Core.ArtifactID,
		SourceContractCoreSHA256:      contract.CoreSHA256,
		SourceContractSHA256:          contractSHA256,
		BridgeSetSHA256:               contract.Core.BridgeSetSHA256,
		LogicalSnapshotJSON:           contract.Core.SourceBindingSet.LogicalSnapshotJSON,
		LogicalSnapshotSHA256:         contract.Core.SourceBindingSet.LogicalSnapshotSHA256,
		RPinsetID:                     contract.Core.SourceBindingSet.RPinsetID,
		RegisteredExecutionPlanSHA256: plan.PlanSHA256,
		CanonicalScienceSHA256:        plan.CanonicalScienceSHA256,
		ExecutionKernel:               executionKernel,
		DescriptorCoreSHA256:          plan.DescriptorCoreSHA256,
		ProjectedSchemaSHA256:         plan.ProjectedSchemaSHA256,
		SnapshotSHA256:                plan.SnapshotSHA256,
		PinsetSHA256:                  plan.PinsetSHA256,
		LocalSource:                   localSource,
		LocalPeerIdentity:             localIdentity,
		LocalColumns:                  localColumns,
		CustodianPeers:                append([]string(nil), plan.CustodianPeers...),
		CustodianCount:                plan.CustodianCount,
		DesignatedComputePeers: append(
			[]string(nil), plan.DesignatedComputePeers...),
		NoiseAuthorities: append(
			[]formalGLMRegisteredExecutionAuthorityV1(nil),
			plan.NoiseAuthorities...),
		Geometry: formalGLMRegisteredPhase18GeometryV1{
			TotalCapacity:    plan.TotalCapacity,
			BlockCapacity:    plan.BlockCapacity,
			TotalBlocks:      plan.TotalBlocks,
			CoordinateCount:  plan.ExecutionKernel.CoefficientCount + 3,
			CoordinateOwners: append([]string(nil), plan.CoordinateOwners...),
			RingBits:         plan.RingBits, ContainerBits: plan.ContainerBits,
			RecordBytes: exactGCRecordBytes(plan.RingBits),
		},
		Science: formalGLMRegisteredPhase18ScienceV1{
			Family: plan.Family, Adjacency: plan.ExecutionKernel.Adjacency,
			CoefficientOrder: append(
				[]string(nil), plan.DescriptorCore.CoefficientOrder...),
			TermMap: append(
				[]formalGLMPublicTermV1(nil), plan.DescriptorCore.TermMap...),
			FractionBits:    plan.ExecutionKernel.FractionBits,
			Missingness:     plan.ExecutionKernel.Missingness,
			PatientCollapse: plan.ExecutionKernel.PatientCollapse,
			InputLayout:     plan.ExecutionKernel.InputLayout,
			InputSharing:    plan.ExecutionKernel.InputSharing,
		},
		ValiditySharing:           formalGLMPhase18ValiditySharing,
		AlignmentSharing:          formalGLMPhase18AlignmentSharing,
		CoordinateEncoding:        formalGLMPhase18CoordinateEncoding,
		PrivateCarrierRequirement: formalGLMRegisteredPhase18PrivateCarrierRequirement,
		OpeningsPerformed:         0,
		ProductionReady:           false,
	}
	return authorization, nil
}

func formalGLMValidateRegisteredPhase18AuthorizationV1(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMValidateSourceContractV1(contract, pins); err != nil {
		return err
	}
	if authorization.Version !=
		formalGLMRegisteredPhase18AuthorizationVersion ||
		authorization.Phase != formalGLMRegisteredPhase18AuthorizationPhase ||
		authorization.Purpose != formalGLMRegisteredPhase18AuthorizationPurpose ||
		!formalGLMIsSHA256(authorization.AuthorizationSHA256) ||
		authorization.ValiditySharing != formalGLMPhase18ValiditySharing ||
		authorization.AlignmentSharing != formalGLMPhase18AlignmentSharing ||
		authorization.CoordinateEncoding != formalGLMPhase18CoordinateEncoding ||
		authorization.PrivateCarrierRequirement !=
			formalGLMRegisteredPhase18PrivateCarrierRequirement ||
		authorization.OpeningsPerformed != 0 || authorization.ProductionReady {
		return fmt.Errorf("formal-glm: invalid registered Phase18 authorization")
	}
	expected, err := formalGLMProjectRegisteredPhase18AuthorizationV1(
		contract, authorization.LocalSource.SignerPeerName, pins)
	if err != nil {
		return err
	}
	expected.AuthorizationSHA256, err =
		formalGLMRegisteredPhase18AuthorizationSHA256V1(expected)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(authorization, expected) {
		return fmt.Errorf("formal-glm: registered Phase18 authorization differs from source contract")
	}
	return nil
}

func formalGLMRegisteredPhase18AuthorizationSHA256V1(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
) (string, error) {
	if authorization.Version !=
		formalGLMRegisteredPhase18AuthorizationVersion ||
		authorization.Phase != formalGLMRegisteredPhase18AuthorizationPhase ||
		authorization.Purpose != formalGLMRegisteredPhase18AuthorizationPurpose ||
		(authorization.AuthorizationSHA256 != "" &&
			!formalGLMIsSHA256(authorization.AuthorizationSHA256)) {
		return "", fmt.Errorf("formal-glm: invalid registered Phase18 hash input")
	}
	authorization.AuthorizationSHA256 = ""
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18AuthorizationDomain+"/authorization",
		authorization)
}

func formalGLMDecodeRegisteredPhase18AuthorizationV1(
	encoded []byte,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18AuthorizationV1, error) {
	var authorization formalGLMRegisteredPhase18AuthorizationV1
	if len(encoded) < 2 ||
		len(encoded) > formalGLMRegisteredPhase18AuthorizationMaxJSON ||
		encoded[0] != '{' {
		return authorization, fmt.Errorf("formal-glm: invalid registered Phase18 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&authorization); err != nil {
		return formalGLMRegisteredPhase18AuthorizationV1{},
			fmt.Errorf("formal-glm: invalid registered Phase18 JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return formalGLMRegisteredPhase18AuthorizationV1{},
			fmt.Errorf("formal-glm: trailing registered Phase18 JSON")
	}
	canonical, err := json.Marshal(authorization)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return formalGLMRegisteredPhase18AuthorizationV1{},
			fmt.Errorf("formal-glm: non-canonical registered Phase18 JSON")
	}
	if err := formalGLMValidateRegisteredPhase18AuthorizationV1(
		authorization, contract, pins); err != nil {
		return formalGLMRegisteredPhase18AuthorizationV1{}, err
	}
	return authorization, nil
}
