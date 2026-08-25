package main

// Pre-source, Rock-local registry and clean public descriptor for formal GLM.
// This file deliberately registers no command, handler, relay capability or
// analyst-facing endpoint.  The only accepted PSI evidence is a K-of-K set of
// Ed25519 receipts produced after each Rock has verified its own token-bound
// persistent PSI attestation.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	formalGLMPSISourceBridgeVersion = "dsvert-formal-glm-psi-source-bridge-v1"
	formalGLMPSISourceBridgePurpose = "formal_glm_pre_source_local_psi_attestation_bridge_v1"
	formalGLMPSISourceBridgeDomain  = "dsVert/formal-glm/psi-source-bridge/v1"

	formalGLMPublicDescriptorCoreVersion = "dsvert-formal-glm-public-descriptor-core-v1"
	formalGLMPublicDescriptorCorePurpose = "formal_glm_pre_source_public_descriptor_core_v1"
	formalGLMPublicDescriptorCoreDomain  = "dsVert/formal-glm/public-descriptor-core/v1"

	formalGLMSignedPublicDescriptorVersion = "dsvert-formal-glm-signed-public-descriptor-v1"
	formalGLMSignedPublicDescriptorPurpose = "formal_glm_k_signed_public_descriptor_v1"
	formalGLMSignedPublicDescriptorDomain  = "dsVert/formal-glm/signed-public-descriptor/v1"

	formalGLMArtifactRegistryEntryVersion = "dsvert-formal-glm-artifact-registry-entry-v1"
	formalGLMArtifactRegistryEntryPurpose = "formal_glm_k_signed_pre_source_artifact_registry_v1"
	formalGLMArtifactRegistryEntryDomain  = "dsVert/formal-glm/artifact-registry-entry/v1"

	formalGLMArtifactRegistryMaxRecord = 2 << 20
	formalGLMArtifactRegistryMaxEntry  = 10000
)

type formalGLMPeerIdentityV1 struct {
	PeerName   string `json:"peer_name"`
	IdentityPK string `json:"identity_pk"`
}

type formalGLMPSIPublicAttestationV3 struct {
	AttestationVersion int      `json:"attestation_version"`
	AlignmentAttested  bool     `json:"alignment_attested"`
	AlignmentProtocol  string   `json:"alignment_protocol"`
	AttestationID      string   `json:"attestation_id"`
	ContractSHA256     string   `json:"contract_hash"`
	PolicyID           string   `json:"policy_id"`
	AlignmentPurpose   string   `json:"alignment_purpose"`
	DatasetID          string   `json:"dataset_id"`
	DatasetVersion     string   `json:"dataset_version"`
	IDColumn           string   `json:"id_column"`
	SourceBindingID    string   `json:"source_binding_id"`
	PinsetID           string   `json:"pinset_id"`
	CapacityBucket     int      `json:"capacity_bucket"`
	RelayFrameBytes    int      `json:"relay_frame_bytes"`
	InlineMaxBytes     int      `json:"inline_max_bytes"`
	PeerCount          int      `json:"peer_count"`
	ReferencePeer      string   `json:"reference_peer"`
	ComputePeers       []string `json:"compute_peers"`
}

type formalGLMPSISourceBridgeCoreV1 struct {
	Version               string                          `json:"version"`
	Purpose               string                          `json:"purpose"`
	SignerPeerName        string                          `json:"signer_peer_name"`
	SignerIdentityPK      string                          `json:"signer_identity_pk"`
	PSIAttestation        formalGLMPSIPublicAttestationV3 `json:"psi_attestation"`
	CohortID              string                          `json:"cohort_id"`
	SourceBindingID       string                          `json:"source_binding_id"`
	DatasetID             string                          `json:"dataset_id"`
	DatasetVersion        string                          `json:"dataset_version"`
	LogicalSnapshotJSON   string                          `json:"logical_snapshot_json"`
	LogicalSnapshotSHA256 string                          `json:"logical_snapshot_sha256"`
	SchemaManifestJSON    string                          `json:"schema_manifest_json"`
	SchemaManifestSHA256  string                          `json:"schema_manifest_sha256"`
	RPinsetID             string                          `json:"r_pinset_id"`
	GoPinsetSHA256        string                          `json:"go_pinset_sha256"`
	PeerIdentities        []formalGLMPeerIdentityV1       `json:"peer_identities"`
	DescriptorCoreSHA256  string                          `json:"descriptor_core_sha256"`
}

type formalGLMPSISourceBridgeReceiptV1 struct {
	Core      formalGLMPSISourceBridgeCoreV1 `json:"core"`
	Signature string                         `json:"signature"`
}

type formalGLMPublicTermV1 struct {
	Index        int    `json:"index"`
	Coefficient  string `json:"coefficient"`
	Kind         string `json:"kind"`
	Owner        string `json:"owner,omitempty"`
	SourceColumn string `json:"source_column,omitempty"`
	SourceLevel  string `json:"source_level,omitempty"`
}

type formalGLMPublicColumnV1 struct {
	Owner          string   `json:"owner"`
	DatasetID      string   `json:"dataset_id"`
	DatasetVersion string   `json:"dataset_version"`
	Column         string   `json:"column"`
	Role           string   `json:"role"`
	Kind           string   `json:"kind"`
	LowerRational  string   `json:"lower_rational,omitempty"`
	UpperRational  string   `json:"upper_rational,omitempty"`
	Levels         []string `json:"levels,omitempty"`
	ReferenceLevel string   `json:"reference_level,omitempty"`
	Contrast       string   `json:"contrast,omitempty"`
}

type formalGLMPublicDescriptorCoreV1 struct {
	Version                        string                    `json:"version"`
	Purpose                        string                    `json:"purpose"`
	Family                         string                    `json:"family"`
	CanonicalQualifiedFormula      string                    `json:"canonical_qualified_formula"`
	FormulaSHA256                  string                    `json:"formula_sha256"`
	CoefficientOrder               []string                  `json:"coefficient_order"`
	CoefficientOrderSHA256         string                    `json:"coefficient_order_sha256"`
	TermMap                        []formalGLMPublicTermV1   `json:"term_map"`
	UsedColumns                    []formalGLMPublicColumnV1 `json:"used_columns"`
	ShiftedUpperBounds             []string                  `json:"shifted_upper_bounds"`
	OutputLatticeScale             string                    `json:"output_lattice_scale"`
	SourceFractionBits             int                       `json:"source_fraction_bits"`
	QuantizationShift              int                       `json:"quantization_shift"`
	OutputLatticeBits              int                       `json:"output_lattice_bits"`
	Quantization                   string                    `json:"quantization"`
	CanonicalPreSourceDPSHA256     string                    `json:"canonical_pre_source_dp_sha256"`
	SnapshotSHA256                 string                    `json:"snapshot_sha256"`
	SchemaManifestSHA256           string                    `json:"schema_manifest_sha256"`
	TransportCoordinateOrderSHA256 string                    `json:"transport_coordinate_order_sha256"`
	PinsetSHA256                   string                    `json:"pinset_sha256"`
	BoundsSHA256                   string                    `json:"bounds_sha256"`
	QuantizationSHA256             string                    `json:"quantization_sha256"`
}

type formalGLMSignedPublicDescriptorV1 struct {
	Version              string                               `json:"version"`
	Purpose              string                               `json:"purpose"`
	Descriptor           formalGLMPublicDescriptorCoreV1      `json:"descriptor"`
	DescriptorCoreSHA256 string                               `json:"descriptor_core_sha256"`
	ArtifactID           string                               `json:"artifact_id"`
	CustodianPeers       []string                             `json:"custodian_peers"`
	CustodianCount       int                                  `json:"custodian_count"`
	ProductionReady      bool                                 `json:"production_ready"`
	CustodianApprovals   []jointDPBiomedicalGaussianSignature `json:"custodian_approvals"`
}

type formalGLMArtifactRegistryEntryV1 struct {
	Version              string                               `json:"version"`
	Purpose              string                               `json:"purpose"`
	BridgeSetSHA256      string                               `json:"bridge_set_sha256"`
	FormalAnalysisIDs    []string                             `json:"formal_analysis_ids"`
	ArtifactID           string                               `json:"artifact_id"`
	Descriptor           formalGLMSignedPublicDescriptorV1    `json:"descriptor"`
	DescriptorCoreSHA256 string                               `json:"descriptor_core_sha256"`
	CustodianPeers       []string                             `json:"custodian_peers"`
	CustodianCount       int                                  `json:"custodian_count"`
	ProductionReady      bool                                 `json:"production_ready"`
	CustodianApprovals   []jointDPBiomedicalGaussianSignature `json:"custodian_approvals"`
}

type formalGLMArtifactRegistryQueryV1 struct {
	BridgeReceipts   []formalGLMPSISourceBridgeReceiptV1
	Family           string
	Formula          string
	FormalAnalysisID string
}

type formalGLMArtifactRegistryResolutionV1 struct {
	ArtifactID string                            `json:"artifact_id"`
	Descriptor formalGLMSignedPublicDescriptorV1 `json:"descriptor"`
}

type formalGLMRegistryResolutionErrorV1 struct {
	Code    string
	Matches int
}

func (err *formalGLMRegistryResolutionErrorV1) Error() string {
	return "formal-glm: requested registered analysis is unavailable"
}

type formalGLMArtifactRegistryStoreV1 struct {
	mu   sync.Mutex
	dir  string
	root *os.Root
	pins map[string]ed25519.PublicKey
}

type formalGLMCanonicalQualifiedFormulaResultV1 struct {
	Canonical  string
	SHA256     string
	Response   string
	Predictors []string
	Intercept  bool
}

type formalGLMNamedCoefficientV2 struct {
	Coefficient       string `json:"coefficient"`
	SignedSteps       string `json:"signed_steps"`
	OutputLatticeBits int    `json:"output_lattice_bits"`
}

func formalGLMSignatureBase64URLV1(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func formalGLMIdentityPKV1(pin ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pin)
}

func formalGLMRegistryLabelV1(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for index := range value {
		character := value[index]
		alphanumeric := character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if !alphanumeric && (index == 0 ||
			(character != '.' && character != '_' && character != '-' &&
				character != ':')) {
			return false
		}
	}
	return true
}

func formalGLMRegistryHexLabelV1(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) &&
		len(value) == len(prefix)+64 && formalGLMIsSHA256(value[len(prefix):])
}

func formalGLMSortedUniqueLabelsV1(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if len(result) == 0 {
		return result
	}
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] != result[write-1] {
			result[write] = result[read]
			write++
		}
	}
	return result[:write]
}

func formalGLMCanonicalJSONV1(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func formalGLMPSIPinsetIDV1(pins map[string]ed25519.PublicKey) (string, error) {
	if len(pins) < 2 {
		return "", fmt.Errorf("formal-glm: incomplete PSI pinset")
	}
	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	seen := make(map[string]bool, len(names))
	for index, name := range names {
		pin := pins[name]
		encoded := formalGLMIdentityPKV1(pin)
		if !formalGLMRegistryLabelV1(name, 128) ||
			len(pin) != ed25519.PublicKeySize || seen[encoded] {
			return "", fmt.Errorf("formal-glm: invalid PSI pinset")
		}
		seen[encoded] = true
		parts[index] = fmt.Sprintf("%d:%s=%d:%s",
			len(name), name, len(encoded), encoded)
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "pinset_" + hex.EncodeToString(digest[:]), nil
}

func formalGLMQualifiedReferenceV1(value string) bool {
	parts := strings.Split(value, "$")
	return len(parts) == 2 && formalGLMRegistryLabelV1(parts[0], 128) &&
		formalGLMRegistryLabelV1(parts[1], 128)
}

func formalGLMCanonicalQualifiedFormulaV1(
	value string,
) (formalGLMCanonicalQualifiedFormulaResultV1, error) {
	var zero formalGLMCanonicalQualifiedFormulaResultV1
	if len(value) < 5 || len(value) > 4096 || strings.Count(value, "~") != 1 {
		return zero, fmt.Errorf("formal-glm: invalid qualified formula")
	}
	sides := strings.SplitN(value, "~", 2)
	response := strings.TrimSpace(sides[0])
	if !formalGLMQualifiedReferenceV1(response) {
		return zero, fmt.Errorf("formal-glm: formula response is not qualified")
	}
	terms := strings.Split(sides[1], "+")
	intercept := true
	interceptSeen := false
	predictors := make([]string, 0, len(terms))
	seen := make(map[string]bool, len(terms))
	for _, raw := range terms {
		term := strings.TrimSpace(raw)
		if term == "0" || term == "1" {
			if interceptSeen {
				return zero, fmt.Errorf("formal-glm: duplicate formula intercept")
			}
			interceptSeen = true
			intercept = term == "1"
			continue
		}
		if !formalGLMQualifiedReferenceV1(term) || term == response || seen[term] {
			return zero, fmt.Errorf("formal-glm: invalid qualified predictor")
		}
		seen[term] = true
		predictors = append(predictors, term)
	}
	if len(predictors) == 0 && !intercept {
		return zero, fmt.Errorf("formal-glm: empty qualified formula")
	}
	sort.Strings(predictors)
	right := append([]string{map[bool]string{true: "1", false: "0"}[intercept]},
		predictors...)
	canonical := response + " ~ " + strings.Join(right, " + ")
	digest := sha256.Sum256([]byte(
		"dsVert/formal-glm/qualified-formula/v1|" + canonical))
	return formalGLMCanonicalQualifiedFormulaResultV1{
		Canonical: canonical, SHA256: hex.EncodeToString(digest[:]),
		Response: response, Predictors: predictors, Intercept: intercept,
	}, nil
}

func formalGLMPSISourceBridgeMessageV1(
	core formalGLMPSISourceBridgeCoreV1,
) ([]byte, error) {
	encoded, err := formalGLMCanonicalJSONV1(core)
	if err != nil {
		return nil, err
	}
	domain := []byte(formalGLMPSISourceBridgeDomain)
	message := make([]byte, 16+len(domain)+len(encoded))
	binary.BigEndian.PutUint64(message[:8], uint64(len(domain)))
	copy(message[8:], domain)
	offset := 8 + len(domain)
	binary.BigEndian.PutUint64(message[offset:offset+8], uint64(len(encoded)))
	copy(message[offset+8:], encoded)
	return message, nil
}

func formalGLMCanonicalJSONStringV1(value string, maximum int) bool {
	if len(value) < 2 || len(value) > maximum {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false
	}
	encoded, err := json.Marshal(decoded)
	return err == nil && value == string(encoded)
}

func formalGLMValidatePSIPublicAttestationV3(
	value formalGLMPSIPublicAttestationV3,
) error {
	if value.AttestationVersion != 3 || !value.AlignmentAttested ||
		value.AlignmentProtocol != "dsvert-pinned-padded-psi-v5" ||
		!formalGLMRegistryHexLabelV1(value.AttestationID, "attest_") ||
		!formalGLMIsSHA256(value.ContractSHA256) ||
		!formalGLMRegistryHexLabelV1(value.PolicyID, "policy_") ||
		!formalGLMRegistryLabelV1(value.AlignmentPurpose, 128) ||
		!formalGLMRegistryLabelV1(value.DatasetID, 128) ||
		!formalGLMRegistryLabelV1(value.DatasetVersion, 128) ||
		!formalGLMRegistryLabelV1(value.IDColumn, 128) ||
		!formalGLMRegistryHexLabelV1(value.SourceBindingID, "source_") ||
		!formalGLMRegistryHexLabelV1(value.PinsetID, "pinset_") ||
		value.CapacityBucket < 64 || value.CapacityBucket > 1048576 ||
		value.RelayFrameBytes < 16<<10 || value.RelayFrameBytes > 64<<20 ||
		value.InlineMaxBytes < 16<<10 || value.InlineMaxBytes > 64<<20 ||
		value.PeerCount < 2 || len(value.ComputePeers) != 2 ||
		value.ComputePeers[0] == value.ComputePeers[1] ||
		!formalGLMRegistryLabelV1(value.ReferencePeer, 128) ||
		(value.ReferencePeer != value.ComputePeers[0] &&
			value.ReferencePeer != value.ComputePeers[1]) {
		return fmt.Errorf("formal-glm: invalid bridged PSI attestation")
	}
	for _, peer := range value.ComputePeers {
		if !formalGLMRegistryLabelV1(peer, 128) {
			return fmt.Errorf("formal-glm: invalid bridged PSI compute peer")
		}
	}
	return nil
}

func formalGLMValidatePSISourceBridgeCoreV1(
	core formalGLMPSISourceBridgeCoreV1,
	pins map[string]ed25519.PublicKey,
) error {
	psiPinset, psiErr := formalGLMPSIPinsetIDV1(pins)
	goPinset, goErr := formalGLMPhase16PinsetSHA256(pins)
	logicalSnapshotDigest := sha256.Sum256([]byte(core.LogicalSnapshotJSON))
	schemaManifestDigest := sha256.Sum256([]byte(core.SchemaManifestJSON))
	if core.Version != formalGLMPSISourceBridgeVersion ||
		core.Purpose != formalGLMPSISourceBridgePurpose ||
		psiErr != nil || goErr != nil || core.RPinsetID != psiPinset ||
		core.GoPinsetSHA256 != goPinset ||
		!formalGLMRegistryLabelV1(core.SignerPeerName, 128) ||
		len(pins[core.SignerPeerName]) != ed25519.PublicKeySize ||
		core.SignerIdentityPK != formalGLMIdentityPKV1(pins[core.SignerPeerName]) ||
		!formalGLMRegistryLabelV1(core.CohortID, 128) ||
		!formalGLMRegistryHexLabelV1(core.SourceBindingID, "source_") ||
		!formalGLMRegistryLabelV1(core.DatasetID, 128) ||
		!formalGLMRegistryLabelV1(core.DatasetVersion, 128) ||
		!formalGLMIsSHA256(core.LogicalSnapshotSHA256) ||
		!formalGLMIsSHA256(core.SchemaManifestSHA256) ||
		!formalGLMIsSHA256(core.DescriptorCoreSHA256) ||
		!formalGLMCanonicalJSONStringV1(core.LogicalSnapshotJSON, 64<<10) ||
		!formalGLMCanonicalJSONStringV1(core.SchemaManifestJSON, 1<<20) ||
		hex.EncodeToString(logicalSnapshotDigest[:]) != core.LogicalSnapshotSHA256 ||
		hex.EncodeToString(schemaManifestDigest[:]) != core.SchemaManifestSHA256 ||
		formalGLMValidatePSIPublicAttestationV3(core.PSIAttestation) != nil ||
		core.PSIAttestation.SourceBindingID != core.SourceBindingID ||
		core.PSIAttestation.DatasetID != core.DatasetID ||
		core.PSIAttestation.DatasetVersion != core.DatasetVersion ||
		core.PSIAttestation.PinsetID != core.RPinsetID ||
		core.PSIAttestation.PeerCount != len(pins) ||
		len(core.PeerIdentities) != len(pins) {
		return fmt.Errorf("formal-glm: invalid PSI source bridge core")
	}
	var snapshot map[string]any
	if err := json.Unmarshal([]byte(core.LogicalSnapshotJSON), &snapshot); err != nil ||
		snapshot["logical_snapshot_id"] != core.CohortID {
		return fmt.Errorf("formal-glm: PSI bridge cohort differs from logical snapshot")
	}
	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}
	sort.Strings(names)
	for index, name := range names {
		identity := core.PeerIdentities[index]
		if identity.PeerName != name ||
			identity.IdentityPK != formalGLMIdentityPKV1(pins[name]) {
			return fmt.Errorf("formal-glm: PSI bridge peer identities differ from pins")
		}
	}
	return nil
}

func formalGLMValidatePSISourceBridgeSetV1(
	receipts []formalGLMPSISourceBridgeReceiptV1,
	pins map[string]ed25519.PublicKey,
) error {
	if len(receipts) != len(pins) || len(receipts) < 2 {
		return fmt.Errorf("formal-glm: incomplete PSI bridge receipt set")
	}
	names := make([]string, 0, len(pins))
	for name := range pins {
		names = append(names, name)
	}
	sort.Strings(names)
	var common *formalGLMPSISourceBridgeCoreV1
	seenDatasets := make(map[string]bool, len(receipts))
	for index, receipt := range receipts {
		core := receipt.Core
		if err := formalGLMValidatePSISourceBridgeCoreV1(core, pins); err != nil ||
			core.SignerPeerName != names[index] {
			return fmt.Errorf("formal-glm: invalid ordered PSI bridge receipt")
		}
		signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
		message, messageErr := formalGLMPSISourceBridgeMessageV1(core)
		if err != nil || messageErr != nil || len(signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[core.SignerPeerName], message, signature) {
			return fmt.Errorf("formal-glm: invalid PSI bridge signature")
		}
		key := core.SignerPeerName + "\x00" + core.DatasetID + "\x00" + core.DatasetVersion
		if seenDatasets[key] {
			return fmt.Errorf("formal-glm: duplicate PSI bridge dataset")
		}
		seenDatasets[key] = true
		if common == nil {
			copyCore := core
			common = &copyCore
		} else if core.CohortID != common.CohortID ||
			core.LogicalSnapshotJSON != common.LogicalSnapshotJSON ||
			core.LogicalSnapshotSHA256 != common.LogicalSnapshotSHA256 ||
			core.SchemaManifestJSON != common.SchemaManifestJSON ||
			core.SchemaManifestSHA256 != common.SchemaManifestSHA256 ||
			core.RPinsetID != common.RPinsetID ||
			core.GoPinsetSHA256 != common.GoPinsetSHA256 ||
			core.DescriptorCoreSHA256 != common.DescriptorCoreSHA256 ||
			!reflect.DeepEqual(core.PeerIdentities, common.PeerIdentities) {
			return fmt.Errorf("formal-glm: PSI bridge receipts disagree")
		}
	}
	return nil
}

func formalGLMPSISourceBridgeSetSHA256V1(
	receipts []formalGLMPSISourceBridgeReceiptV1,
	pins map[string]ed25519.PublicKey,
) (string, error) {
	if err := formalGLMValidatePSISourceBridgeSetV1(receipts, pins); err != nil {
		return "", err
	}
	type sourceProjection struct {
		SignerPeerName  string `json:"signer_peer_name"`
		CohortID        string `json:"cohort_id"`
		SourceBindingID string `json:"source_binding_id"`
		DatasetID       string `json:"dataset_id"`
		DatasetVersion  string `json:"dataset_version"`
	}
	projection := struct {
		Version               string                    `json:"version"`
		Sources               []sourceProjection        `json:"sources"`
		LogicalSnapshotJSON   string                    `json:"logical_snapshot_json"`
		LogicalSnapshotSHA256 string                    `json:"logical_snapshot_sha256"`
		RPinsetID             string                    `json:"r_pinset_id"`
		GoPinsetSHA256        string                    `json:"go_pinset_sha256"`
		PeerIdentities        []formalGLMPeerIdentityV1 `json:"peer_identities"`
		DescriptorCoreSHA256  string                    `json:"descriptor_core_sha256"`
	}{
		Version:               "dsvert-formal-glm-psi-source-binding-set-v1",
		Sources:               make([]sourceProjection, len(receipts)),
		LogicalSnapshotJSON:   receipts[0].Core.LogicalSnapshotJSON,
		LogicalSnapshotSHA256: receipts[0].Core.LogicalSnapshotSHA256,
		RPinsetID:             receipts[0].Core.RPinsetID,
		GoPinsetSHA256:        receipts[0].Core.GoPinsetSHA256,
		PeerIdentities: append([]formalGLMPeerIdentityV1(nil),
			receipts[0].Core.PeerIdentities...),
		DescriptorCoreSHA256: receipts[0].Core.DescriptorCoreSHA256,
	}
	for index, receipt := range receipts {
		projection.Sources[index] = sourceProjection{
			SignerPeerName:  receipt.Core.SignerPeerName,
			CohortID:        receipt.Core.CohortID,
			SourceBindingID: receipt.Core.SourceBindingID,
			DatasetID:       receipt.Core.DatasetID,
			DatasetVersion:  receipt.Core.DatasetVersion,
		}
	}
	encoded, err := formalGLMCanonicalJSONV1(projection)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPSISourceBridgeDomain+"/set|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMCoefficientOrderSHA256V1(
	order []string, terms []formalGLMPublicTermV1,
) (string, error) {
	if len(order) == 0 || len(order) != len(terms) {
		return "", fmt.Errorf("formal-glm: incomplete semantic coefficient order")
	}
	projection := struct {
		Version string                  `json:"version"`
		Order   []string                `json:"coefficient_order"`
		Terms   []formalGLMPublicTermV1 `json:"term_map"`
	}{
		Version: "dsvert-formal-glm-semantic-coefficient-order-v1",
		Order:   append([]string(nil), order...),
		Terms:   append([]formalGLMPublicTermV1(nil), terms...),
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte("dsVert/formal-glm/semantic-coefficient-order/v1|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMCanonicalRationalV1(value string) (*big.Rat, error) {
	parsed := new(big.Rat)
	if _, ok := parsed.SetString(value); !ok || parsed.RatString() != value {
		return nil, fmt.Errorf("formal-glm: noncanonical public rational")
	}
	return parsed, nil
}

func formalGLMColumnReferenceV1(column formalGLMPublicColumnV1) string {
	return column.Owner + "$" + column.Column
}

func formalGLMValidatePublicDescriptorCoreV1(
	core formalGLMPublicDescriptorCoreV1,
) error {
	formula, err := formalGLMCanonicalQualifiedFormulaV1(
		core.CanonicalQualifiedFormula)
	if err != nil || formula.Canonical != core.CanonicalQualifiedFormula ||
		formula.SHA256 != core.FormulaSHA256 ||
		core.Version != formalGLMPublicDescriptorCoreVersion ||
		core.Purpose != formalGLMPublicDescriptorCorePurpose ||
		(core.Family != "binomial" && core.Family != "poisson") ||
		len(core.CoefficientOrder) < 1 || len(core.CoefficientOrder) > 4 ||
		len(core.TermMap) != len(core.CoefficientOrder) ||
		len(core.ShiftedUpperBounds) != len(core.CoefficientOrder) ||
		len(core.UsedColumns) < 1 || len(core.UsedColumns) > 4096 ||
		core.SourceFractionBits < 0 || core.SourceFractionBits > 256 ||
		core.QuantizationShift < 0 || core.QuantizationShift > 256 ||
		core.OutputLatticeBits < 0 || core.OutputLatticeBits > 127 ||
		core.OutputLatticeScale != fmt.Sprintf("2^-%d", core.OutputLatticeBits) ||
		core.Quantization != "signed_integer_shift_then_clamp_v1" {
		return fmt.Errorf("formal-glm: invalid public descriptor core")
	}
	for _, digest := range []string{
		core.CoefficientOrderSHA256, core.SnapshotSHA256,
		core.SchemaManifestSHA256, core.TransportCoordinateOrderSHA256,
		core.PinsetSHA256, core.BoundsSHA256, core.QuantizationSHA256,
		core.CanonicalPreSourceDPSHA256,
	} {
		if !formalGLMIsSHA256(digest) {
			return fmt.Errorf("formal-glm: invalid public descriptor hash")
		}
	}
	wantOrderSHA256, err := formalGLMCoefficientOrderSHA256V1(
		core.CoefficientOrder, core.TermMap)
	if err != nil || wantOrderSHA256 != core.CoefficientOrderSHA256 {
		return fmt.Errorf("formal-glm: public descriptor order is not bound")
	}
	for index, upperText := range core.ShiftedUpperBounds {
		upper, err := jointDPBiomedicalGaussianParseCanonicalInt(
			upperText, "public descriptor shifted upper bound", true)
		if err != nil || upper.Sign() <= 0 || upper.Bit(0) != 0 ||
			upper.BitLen() > 128 || core.TermMap[index].Index != index ||
			core.TermMap[index].Coefficient != core.CoefficientOrder[index] ||
			len(core.CoefficientOrder[index]) < 1 ||
			len(core.CoefficientOrder[index]) > 1024 ||
			!utf8.ValidString(core.CoefficientOrder[index]) {
			return fmt.Errorf("formal-glm: invalid public coefficient coordinate")
		}
	}
	columns := make(map[string]formalGLMPublicColumnV1, len(core.UsedColumns))
	previous := ""
	for _, column := range core.UsedColumns {
		key := column.Owner + "\x00" + column.DatasetID + "\x00" +
			column.DatasetVersion + "\x00" + column.Column
		if !formalGLMRegistryLabelV1(column.Owner, 128) ||
			!formalGLMRegistryLabelV1(column.DatasetID, 128) ||
			!formalGLMRegistryLabelV1(column.DatasetVersion, 128) ||
			!formalGLMRegistryLabelV1(column.Column, 128) ||
			(column.Role != "response" && column.Role != "predictor") ||
			key <= previous {
			return fmt.Errorf("formal-glm: invalid public descriptor column order")
		}
		previous = key
		reference := formalGLMColumnReferenceV1(column)
		if _, exists := columns[reference]; exists {
			return fmt.Errorf("formal-glm: duplicate public descriptor column")
		}
		if column.Kind == "factor" {
			if column.Role != "predictor" || len(column.Levels) < 2 ||
				column.LowerRational != "" || column.UpperRational != "" ||
				column.Contrast != "treatment" {
				return fmt.Errorf("formal-glm: invalid public factor column")
			}
			seenLevels := make(map[string]bool, len(column.Levels))
			referenceFound := false
			for _, level := range column.Levels {
				if len(level) < 1 || len(level) > 256 ||
					!utf8.ValidString(level) || strings.ContainsRune(level, '\x00') ||
					seenLevels[level] {
					return fmt.Errorf("formal-glm: invalid public factor levels")
				}
				seenLevels[level] = true
				referenceFound = referenceFound || level == column.ReferenceLevel
			}
			if !referenceFound {
				return fmt.Errorf("formal-glm: invalid public factor reference")
			}
		} else {
			if len(column.Levels) != 0 || column.ReferenceLevel != "" ||
				column.Contrast != "" ||
				(column.Kind != "binary" && column.Kind != "count" &&
					column.Kind != "numeric" && column.Kind != "offset" &&
					column.Kind != "weight") {
				return fmt.Errorf("formal-glm: invalid bounded public column")
			}
			lower, lowerErr := formalGLMCanonicalRationalV1(column.LowerRational)
			upper, upperErr := formalGLMCanonicalRationalV1(column.UpperRational)
			if lowerErr != nil || upperErr != nil || lower.Cmp(upper) > 0 ||
				(column.Kind == "binary" &&
					(column.LowerRational != "0" || column.UpperRational != "1")) ||
				(column.Kind == "count" && lower.Sign() < 0) {
				return fmt.Errorf("formal-glm: invalid exact public column bounds")
			}
		}
		columns[reference] = column
	}
	response, ok := columns[formula.Response]
	if !ok || response.Role != "response" ||
		(core.Family == "binomial" && response.Kind != "binary") ||
		(core.Family == "poisson" && response.Kind != "count") ||
		len(columns) != len(formula.Predictors)+1 {
		return fmt.Errorf("formal-glm: public response differs from formula")
	}
	remaining := make(map[string]bool, len(formula.Predictors))
	for _, predictor := range formula.Predictors {
		column, ok := columns[predictor]
		if !ok || column.Role != "predictor" {
			return fmt.Errorf("formal-glm: formula predictor lacks a public column")
		}
		remaining[predictor] = true
	}
	termIndex := 0
	if formula.Intercept {
		want := formalGLMPublicTermV1{
			Index: 0, Coefficient: "(Intercept)", Kind: "intercept",
		}
		if len(core.TermMap) == 0 || core.TermMap[0] != want ||
			core.CoefficientOrder[0] != want.Coefficient {
			return fmt.Errorf("formal-glm: public term map differs from formula")
		}
		termIndex = 1
	}
	for termIndex < len(core.TermMap) {
		term := core.TermMap[termIndex]
		predictor := term.Owner + "$" + term.SourceColumn
		column, ok := columns[predictor]
		if !ok || !remaining[predictor] {
			return fmt.Errorf("formal-glm: public term map differs from formula")
		}
		delete(remaining, predictor)
		if column.Kind != "factor" {
			want := formalGLMPublicTermV1{
				Index: termIndex, Coefficient: predictor, Kind: "numeric",
				Owner: column.Owner, SourceColumn: column.Column,
			}
			if term != want || core.CoefficientOrder[termIndex] != want.Coefficient {
				return fmt.Errorf("formal-glm: public term map differs from formula")
			}
			termIndex++
			continue
		}
		for _, level := range column.Levels {
			if formula.Intercept && level == column.ReferenceLevel {
				continue
			}
			if termIndex >= len(core.TermMap) {
				return fmt.Errorf("formal-glm: public term expansion is incomplete")
			}
			coefficient := predictor + "[" + level + "]"
			want := formalGLMPublicTermV1{
				Index: termIndex, Coefficient: coefficient, Kind: "factor_level",
				Owner: column.Owner, SourceColumn: column.Column,
				SourceLevel: level,
			}
			if core.TermMap[termIndex] != want ||
				core.CoefficientOrder[termIndex] != coefficient {
				return fmt.Errorf("formal-glm: public term map differs from formula")
			}
			termIndex++
		}
	}
	if len(remaining) != 0 {
		return fmt.Errorf("formal-glm: public term expansion is incomplete")
	}
	return nil
}

func formalGLMValidatePublicDescriptorAgainstArtifactV1(
	descriptor formalGLMSignedPublicDescriptorV1,
	artifact formalGLMPhase21StickyArtifact,
) error {
	core := descriptor.Descriptor
	artifactID, err := formalGLMPhase21StickyArtifactID(artifact)
	if err != nil || descriptor.ArtifactID != artifactID ||
		artifact.DescriptorCoreSHA256 == "" ||
		descriptor.DescriptorCoreSHA256 != artifact.DescriptorCoreSHA256 ||
		core.Family != artifact.Family ||
		core.SnapshotSHA256 != artifact.SnapshotSHA256 ||
		core.SchemaManifestSHA256 != artifact.SchemaManifestSHA256 ||
		core.TransportCoordinateOrderSHA256 != artifact.CoordinateOrderSHA256 ||
		core.PinsetSHA256 != artifact.PinsetSHA256 ||
		core.BoundsSHA256 != artifact.BoundsSHA256 ||
		core.QuantizationSHA256 != artifact.QuantizationSHA256 ||
		len(core.CoefficientOrder) != artifact.CoordinateCount ||
		core.SourceFractionBits != artifact.SourceFractionBits ||
		core.QuantizationShift != artifact.QuantizationShift ||
		core.OutputLatticeBits != artifact.OutputLatticeBits {
		return fmt.Errorf("formal-glm: public descriptor differs from sticky artifact")
	}
	return nil
}

func formalGLMPublicDescriptorCoreSHA256V1(
	core formalGLMPublicDescriptorCoreV1,
) (string, error) {
	if err := formalGLMValidatePublicDescriptorCoreV1(core); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(core)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPublicDescriptorCoreDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMSignPublicDescriptorV1(
	descriptor formalGLMSignedPublicDescriptorV1, peer string,
	privateKey ed25519.PrivateKey, pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSignature, error) {
	if len(descriptor.CustodianApprovals) != 0 ||
		formalGLMValidateSignedPublicDescriptorCoreV1(descriptor, pins) != nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!hmacEqualV1(privateKey.Public().(ed25519.PublicKey), pins[peer]) {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("formal-glm: invalid public descriptor signer")
	}
	found := false
	for _, custodian := range descriptor.CustodianPeers {
		found = found || custodian == peer
	}
	if !found {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("formal-glm: public descriptor signer is not a custodian")
	}
	message, err := formalGLMSignedPublicDescriptorMessageV1(descriptor)
	if err != nil {
		return jointDPBiomedicalGaussianSignature{}, err
	}
	return jointDPBiomedicalGaussianSignature{
		Signer: peer, Signature: ed25519.Sign(privateKey, message),
	}, nil
}

func formalGLMSealPublicDescriptorV1(
	descriptor formalGLMSignedPublicDescriptorV1,
	approvals []jointDPBiomedicalGaussianSignature,
	pins map[string]ed25519.PublicKey,
) (formalGLMSignedPublicDescriptorV1, error) {
	descriptor.CustodianApprovals = make(
		[]jointDPBiomedicalGaussianSignature, len(approvals))
	for index, approval := range approvals {
		descriptor.CustodianApprovals[index] = jointDPBiomedicalGaussianSignature{
			Signer:    approval.Signer,
			Signature: append([]byte(nil), approval.Signature...),
		}
	}
	if err := formalGLMValidateSignedPublicDescriptorV1(descriptor, pins); err != nil {
		return formalGLMSignedPublicDescriptorV1{}, err
	}
	return descriptor, nil
}

func formalGLMValidateSignedPublicDescriptorV1(
	descriptor formalGLMSignedPublicDescriptorV1,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMValidateSignedPublicDescriptorCoreV1(
		descriptor, pins); err != nil {
		return err
	}
	if len(descriptor.CustodianApprovals) != descriptor.CustodianCount {
		return fmt.Errorf("formal-glm: public descriptor lacks K approvals")
	}
	message, err := formalGLMSignedPublicDescriptorMessageV1(descriptor)
	if err != nil {
		return err
	}
	for index, peer := range descriptor.CustodianPeers {
		approval := descriptor.CustodianApprovals[index]
		if approval.Signer != peer || len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, approval.Signature) {
			return fmt.Errorf("formal-glm: invalid ordered public descriptor approval")
		}
	}
	return nil
}

func hmacEqualV1(left, right []byte) bool {
	return len(left) == len(right) && bytes.Equal(left, right)
}

func formalGLMSignedPublicDescriptorMessageV1(
	descriptor formalGLMSignedPublicDescriptorV1,
) ([]byte, error) {
	descriptor.CustodianApprovals = nil
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMSignedPublicDescriptorDomain+"|"),
		encoded...), nil
}

func formalGLMValidateSignedPublicDescriptorCoreV1(
	descriptor formalGLMSignedPublicDescriptorV1,
	pins map[string]ed25519.PublicKey,
) error {
	coreSHA256, err := formalGLMPublicDescriptorCoreSHA256V1(
		descriptor.Descriptor)
	pinsetSHA256, pinErr := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || pinErr != nil ||
		descriptor.Version != formalGLMSignedPublicDescriptorVersion ||
		descriptor.Purpose != formalGLMSignedPublicDescriptorPurpose ||
		descriptor.DescriptorCoreSHA256 != coreSHA256 ||
		!formalGLMIsSHA256(descriptor.ArtifactID) ||
		descriptor.CustodianCount < 2 ||
		descriptor.CustodianCount != len(pins) ||
		len(descriptor.CustodianPeers) != descriptor.CustodianCount ||
		!sort.StringsAreSorted(descriptor.CustodianPeers) ||
		descriptor.Descriptor.PinsetSHA256 != pinsetSHA256 ||
		descriptor.ProductionReady {
		return fmt.Errorf("formal-glm: invalid signed public descriptor")
	}
	for index, peer := range descriptor.CustodianPeers {
		if index > 0 && peer == descriptor.CustodianPeers[index-1] ||
			len(pins[peer]) != ed25519.PublicKeySize {
			return fmt.Errorf("formal-glm: invalid public descriptor custodian set")
		}
	}
	return nil
}

func formalGLMArtifactRegistryEntryMessageV1(
	entry formalGLMArtifactRegistryEntryV1,
) ([]byte, error) {
	entry.CustodianApprovals = nil
	encoded, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMArtifactRegistryEntryDomain+"|"),
		encoded...), nil
}

func formalGLMValidateArtifactRegistryEntryCoreV1(
	entry formalGLMArtifactRegistryEntryV1,
	pins map[string]ed25519.PublicKey,
) error {
	if entry.Version != formalGLMArtifactRegistryEntryVersion ||
		entry.Purpose != formalGLMArtifactRegistryEntryPurpose ||
		!formalGLMIsSHA256(entry.BridgeSetSHA256) ||
		!formalGLMIsSHA256(entry.ArtifactID) ||
		!formalGLMIsSHA256(entry.DescriptorCoreSHA256) ||
		entry.ArtifactID != entry.Descriptor.ArtifactID ||
		entry.DescriptorCoreSHA256 != entry.Descriptor.DescriptorCoreSHA256 ||
		formalGLMValidateSignedPublicDescriptorV1(entry.Descriptor, pins) != nil ||
		entry.CustodianCount < 2 || entry.CustodianCount != len(pins) ||
		entry.CustodianCount != len(entry.CustodianPeers) ||
		!reflect.DeepEqual(entry.CustodianPeers,
			entry.Descriptor.CustodianPeers) ||
		entry.ProductionReady || entry.Descriptor.ProductionReady {
		return fmt.Errorf("formal-glm: invalid artifact registry entry")
	}
	if len(entry.FormalAnalysisIDs) < 1 ||
		len(entry.FormalAnalysisIDs) > formalGLMArtifactRegistryMaxEntry ||
		!sort.StringsAreSorted(entry.FormalAnalysisIDs) {
		return fmt.Errorf("formal-glm: invalid artifact registry aliases")
	}
	for index, alias := range entry.FormalAnalysisIDs {
		if !formalGLMRegistryLabelV1(alias, 256) ||
			(index > 0 && entry.FormalAnalysisIDs[index-1] == alias) {
			return fmt.Errorf("formal-glm: invalid artifact registry alias")
		}
	}
	return nil
}

func formalGLMSignArtifactRegistryEntryV1(
	entry formalGLMArtifactRegistryEntryV1, peer string,
	privateKey ed25519.PrivateKey, pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSignature, error) {
	if formalGLMValidateArtifactRegistryEntryCoreV1(entry, pins) != nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey), pins[peer]) {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("formal-glm: invalid artifact registry signer")
	}
	index := sort.SearchStrings(entry.CustodianPeers, peer)
	if index == len(entry.CustodianPeers) || entry.CustodianPeers[index] != peer {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("formal-glm: artifact registry signer is not a custodian")
	}
	message, err := formalGLMArtifactRegistryEntryMessageV1(entry)
	if err != nil {
		return jointDPBiomedicalGaussianSignature{}, err
	}
	return jointDPBiomedicalGaussianSignature{
		Signer: peer, Signature: ed25519.Sign(privateKey, message),
	}, nil
}

func formalGLMValidateArtifactRegistryEntryV1(
	entry formalGLMArtifactRegistryEntryV1,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMValidateArtifactRegistryEntryCoreV1(entry, pins); err != nil {
		return err
	}
	if len(entry.CustodianApprovals) != entry.CustodianCount {
		return fmt.Errorf("formal-glm: artifact registry entry lacks K approvals")
	}
	message, err := formalGLMArtifactRegistryEntryMessageV1(entry)
	if err != nil {
		return err
	}
	for index, peer := range entry.CustodianPeers {
		approval := entry.CustodianApprovals[index]
		if approval.Signer != peer ||
			len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, approval.Signature) {
			return fmt.Errorf("formal-glm: invalid ordered artifact registry approval")
		}
	}
	return nil
}

func newFormalGLMArtifactRegistryStoreV1(
	dir string, pins map[string]ed25519.PublicKey,
) (*formalGLMArtifactRegistryStoreV1, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || len(pins) < 2 {
		return nil, fmt.Errorf("formal-glm: invalid artifact registry root")
	}
	if err := formalGLMPhase18EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(root, "entries-v1"); err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	if _, err := formalGLMPhase16PinsetSHA256(clonedPins); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &formalGLMArtifactRegistryStoreV1{
		dir: dir, root: root, pins: clonedPins,
	}, nil
}

func (store *formalGLMArtifactRegistryStoreV1) Close() {
	if store != nil && store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
}

func (store *formalGLMArtifactRegistryStoreV1) Commit(
	entry formalGLMArtifactRegistryEntryV1,
) (bool, error) {
	if store == nil || store.root == nil {
		return false, fmt.Errorf("formal-glm: artifact registry is closed")
	}
	if err := formalGLMValidateArtifactRegistryEntryV1(entry, store.pins); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(entry)
	if err != nil || len(encoded) > formalGLMArtifactRegistryMaxRecord {
		return false, fmt.Errorf("formal-glm: invalid artifact registry record")
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMArtifactRegistryEntryDomain+"/record|"), encoded...))
	relative := filepath.Join("entries-v1", "entry-"+
		hex.EncodeToString(digest[:])+".json")
	store.mu.Lock()
	defer store.mu.Unlock()
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return false, err
	}
	if created {
		return false, nil
	}
	existing, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMArtifactRegistryMaxRecord)
	if err != nil || !bytes.Equal(existing, encoded) {
		return false, fmt.Errorf("formal-glm: artifact registry CAS conflict")
	}
	return true, nil
}

func (store *formalGLMArtifactRegistryStoreV1) Resolve(
	query formalGLMArtifactRegistryQueryV1,
) (formalGLMArtifactRegistryResolutionV1, error) {
	var zero formalGLMArtifactRegistryResolutionV1
	if store == nil || store.root == nil {
		return zero, fmt.Errorf("formal-glm: artifact registry is closed")
	}
	bridgeSHA256, err := formalGLMPSISourceBridgeSetSHA256V1(
		query.BridgeReceipts, store.pins)
	if err != nil {
		return zero, err
	}
	formula, err := formalGLMCanonicalQualifiedFormulaV1(query.Formula)
	if err != nil || (query.Family != "binomial" && query.Family != "poisson") ||
		(query.FormalAnalysisID != "" &&
			!formalGLMRegistryLabelV1(query.FormalAnalysisID, 256)) {
		return zero, fmt.Errorf("formal-glm: invalid artifact registry query")
	}
	paths, err := store.entryPaths()
	if err != nil {
		return zero, err
	}
	matches := make(map[string]formalGLMArtifactRegistryResolutionV1)
	for _, relative := range paths {
		encoded, readErr := formalGLMPhase21RootReadRecord(
			store.root, relative, formalGLMArtifactRegistryMaxRecord)
		if readErr != nil {
			return zero, readErr
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		var entry formalGLMArtifactRegistryEntryV1
		if decoder.Decode(&entry) != nil || decoder.Decode(new(any)) != io.EOF ||
			formalGLMValidateArtifactRegistryEntryV1(entry, store.pins) != nil {
			return zero, fmt.Errorf("formal-glm: invalid persisted artifact registry entry")
		}
		if entry.BridgeSetSHA256 != bridgeSHA256 ||
			entry.Descriptor.Descriptor.Family != query.Family ||
			entry.Descriptor.Descriptor.CanonicalQualifiedFormula != formula.Canonical {
			continue
		}
		if query.FormalAnalysisID != "" {
			index := sort.SearchStrings(entry.FormalAnalysisIDs,
				query.FormalAnalysisID)
			if index == len(entry.FormalAnalysisIDs) ||
				entry.FormalAnalysisIDs[index] != query.FormalAnalysisID {
				continue
			}
		}
		candidate := formalGLMArtifactRegistryResolutionV1{
			ArtifactID: entry.ArtifactID, Descriptor: entry.Descriptor,
		}
		if previous, exists := matches[entry.ArtifactID]; exists &&
			!reflect.DeepEqual(previous, candidate) {
			return zero, fmt.Errorf("formal-glm: conflicting artifact registry aliases")
		}
		matches[entry.ArtifactID] = candidate
	}
	if len(matches) != 1 {
		code := "not_found"
		if len(matches) > 1 {
			code = "ambiguous"
		}
		return zero, &formalGLMRegistryResolutionErrorV1{
			Code: code, Matches: len(matches),
		}
	}
	for _, match := range matches {
		return match, nil
	}
	panic("unreachable")
}

func (store *formalGLMArtifactRegistryStoreV1) entryPaths() ([]string, error) {
	if store == nil || store.root == nil {
		return nil, fmt.Errorf("formal-glm: artifact registry is closed")
	}
	directory, err := store.root.Open("entries-v1")
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "entry-") ||
			!strings.HasSuffix(name, ".json") ||
			len(name) != len("entry-")+64+len(".json") ||
			!formalGLMIsSHA256(name[len("entry-"):len(name)-len(".json")]) {
			return nil, fmt.Errorf("formal-glm: unexpected artifact registry record")
		}
		paths = append(paths, filepath.Join("entries-v1", name))
	}
	if len(paths) > formalGLMArtifactRegistryMaxEntry {
		return nil, fmt.Errorf("formal-glm: artifact registry is too large")
	}
	sort.Strings(paths)
	return paths, nil
}

func formalGLMRegistryResolutionIsV1(err error, code string, matches int) bool {
	var typed *formalGLMRegistryResolutionErrorV1
	return errors.As(err, &typed) && typed.Code == code && typed.Matches == matches
}

func formalGLMPhase21BuildRegisteredPublicCertificateV2(
	internal formalGLMPhase21StickyCertificate,
	resolution formalGLMArtifactRegistryResolutionV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21PublicCertificateV2, error) {
	var zero formalGLMPhase21PublicCertificateV2
	if resolution.ArtifactID != internal.ArtifactID ||
		resolution.Descriptor.ArtifactID != internal.ArtifactID ||
		formalGLMValidateSignedPublicDescriptorV1(resolution.Descriptor, pins) != nil ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			resolution.Descriptor, internal.Artifact) != nil {
		return zero, fmt.Errorf("formal-glm: registry resolution differs from release")
	}
	public, err := formalGLMPhase21BuildPublicCertificateV2(internal, pins)
	if err != nil {
		return zero, err
	}
	encoded, err := json.Marshal(resolution.Descriptor)
	if err != nil {
		return zero, err
	}
	var descriptor formalGLMSignedPublicDescriptorV1
	if err := json.Unmarshal(encoded, &descriptor); err != nil {
		return zero, err
	}
	public.PublicDescriptor = &descriptor
	if err := formalGLMPhase21ValidatePublicCertificateV2Core(
		public, pins); err != nil {
		return zero, err
	}
	return public, nil
}

// formalGLMPhase21ProjectRegisteredArtifactV1 is the single compatibility
// seam between the retained Phase16 execution evidence (which binds the full
// signed schema manifest) and the public pre-source identity (which binds only
// the selected-column schema plus the K-signed descriptor core). No other
// scientific or DP field may change.
func formalGLMPhase21ProjectRegisteredArtifactV1(
	source, registered formalGLMPhase21StickyArtifact,
	resolution formalGLMArtifactRegistryResolutionV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21StickyArtifact, string, error) {
	var zero formalGLMPhase21StickyArtifact
	if source.DescriptorCoreSHA256 != "" ||
		registered.DescriptorCoreSHA256 == "" ||
		resolution.ArtifactID == "" ||
		formalGLMValidateSignedPublicDescriptorV1(
			resolution.Descriptor, pins) != nil ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			resolution.Descriptor, registered) != nil {
		return zero, "", fmt.Errorf(
			"formal-glm: invalid registered artifact projection")
	}
	projected := source
	projected.SchemaManifestSHA256 = registered.SchemaManifestSHA256
	projected.DescriptorCoreSHA256 = registered.DescriptorCoreSHA256
	artifactID, err := formalGLMPhase21StickyArtifactID(projected)
	if err != nil || artifactID != resolution.ArtifactID ||
		artifactID != resolution.Descriptor.ArtifactID ||
		!reflect.DeepEqual(projected, registered) {
		return zero, "", fmt.Errorf(
			"formal-glm: registered artifact differs from Phase16 evidence")
	}
	return projected, artifactID, nil
}

func formalGLMPhase21DecodeNamedPublicV2(
	certificate formalGLMPhase21PublicCertificateV2,
	pins map[string]ed25519.PublicKey,
) ([]formalGLMNamedCoefficientV2, error) {
	if formalGLMPhase21ValidatePublicCertificateV2(certificate, pins) != nil ||
		certificate.PublicDescriptor == nil {
		return nil, fmt.Errorf("formal-glm: invalid named public-v2 certificate")
	}
	descriptor := certificate.PublicDescriptor.Descriptor
	if len(certificate.ClampedScaledValues) != len(descriptor.CoefficientOrder) {
		return nil, fmt.Errorf("formal-glm: public descriptor coordinate mismatch")
	}
	result := make([]formalGLMNamedCoefficientV2,
		len(certificate.ClampedScaledValues))
	for index, encoded := range certificate.ClampedScaledValues {
		value, valueErr := jointDPBiomedicalGaussianParseCanonicalInt(
			encoded, "named public-v2 coordinate", false)
		upper, upperErr := jointDPBiomedicalGaussianParseCanonicalInt(
			descriptor.ShiftedUpperBounds[index],
			"named public-v2 shifted upper bound", true)
		if valueErr != nil || upperErr != nil || value.Sign() < 0 ||
			upper.Sign() <= 0 || upper.Bit(0) != 0 || value.Cmp(upper) > 0 {
			return nil, fmt.Errorf("formal-glm: invalid exact named public-v2 coordinate")
		}
		signed := new(big.Int).Sub(value, new(big.Int).Rsh(upper, 1))
		result[index] = formalGLMNamedCoefficientV2{
			Coefficient:       descriptor.CoefficientOrder[index],
			SignedSteps:       signed.String(),
			OutputLatticeBits: descriptor.OutputLatticeBits,
		}
	}
	return result, nil
}
