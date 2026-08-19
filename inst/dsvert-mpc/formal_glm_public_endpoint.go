package main

// Internal core for the deliberately narrow formal-binomial public endpoint.
// The caller selects a signed registered artifact and then only round-trips an
// opaque receipt plus an optional peer frame. Lifecycle transitions, roles,
// record kinds and Rock paths remain server-owned.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"
)

const (
	formalGLMPublicSelectorVersion           = "dsvert-formal-glm-public-selector-v1"
	formalGLMPublicSelectorPurpose           = "formal_glm_binomial_registry_resolve_v1"
	formalGLMPublicFederationSelectorVersion = "dsvert-formal-glm-federation-selector-v1"

	formalGLMPublicReceiptVersion          = "dsvert-formal-glm-public-receipt-v1"
	formalGLMPublicReceiptPurpose          = "formal_glm_registered_public_lifecycle_receipt_v1"
	formalGLMPublicReceiptDomain           = "dsVert/formal-glm/public-endpoint/receipt/v1"
	formalGLMPublicProvisionPayloadVersion = "dsvert-formal-glm-provision-payload-v1"
	formalGLMPublicProvisionPrepareVersion = "dsvert-formal-glm-provision-prepare-v1"
	formalGLMPublicProvisionApproveVersion = "dsvert-formal-glm-provision-approve-v1"
	formalGLMPublicProvisionBundleVersion  = "dsvert-formal-glm-provision-bundle-v1"
	formalGLMPublicProvisionPurpose        = "formal_glm_binomial_registry_provision_v1"

	formalGLMPublicResolveResponseVersion = "dsvert-formal-glm-resolve-response-v1"
	formalGLMPublicAdvanceResponseVersion = "dsvert-formal-glm-advance-response-v1"

	formalGLMPublicResolveAbsent         = "absent"
	formalGLMPublicResolveUnique         = "unique"
	formalGLMPublicResolveAmbiguous      = "ambiguous"
	formalGLMPublicStateProvisionPrepare = "provision_prepare"
	formalGLMPublicStateProvisionApprove = "provision_approve"

	formalGLMPublicStateProvision = "provision"
	formalGLMPublicStateRelay     = "relay"
	formalGLMPublicStateComplete  = "complete"
	formalGLMPublicStateFailed    = "failed"

	formalGLMPublicRelayControl = "control"
	formalGLMPublicRelayOpening = "opening"

	formalGLMPublicMaxSelectorJSON  = 256 << 10
	formalGLMPublicMaxReceiptJSON   = 16 << 20
	formalGLMPublicMaxPeerFrameJSON = 16 << 20
)

type formalGLMPublicSelectorColumnV1 struct {
	Owner  string `json:"owner"`
	Column string `json:"column"`
	Kind   string `json:"kind"`
	Role   string `json:"role"`
}

type formalGLMPublicFederationSelectorV1 struct {
	Version     string                            `json:"version"`
	Symbol      string                            `json:"symbol"`
	Attestation formalGLMPSIPublicAttestationV3   `json:"attestation"`
	UsedColumns []formalGLMPublicSelectorColumnV1 `json:"used_columns"`
}

type formalGLMPublicSelectorV1 struct {
	Version                   string                              `json:"version"`
	Purpose                   string                              `json:"purpose"`
	Family                    string                              `json:"family"`
	CanonicalQualifiedFormula string                              `json:"canonical_qualified_formula"`
	FormalAnalysisID          string                              `json:"formal_analysis_id"`
	Federation                formalGLMPublicFederationSelectorV1 `json:"federation"`
}

type formalGLMPublicProvisionPrepareV1 struct {
	Version            string                               `json:"version"`
	Purpose            string                               `json:"purpose"`
	UnsignedModel      formalGLMSignedPreSourceModelV1      `json:"unsigned_model"`
	ModelApproval      jointDPBiomedicalGaussianSignature   `json:"model_approval"`
	PSIReceipt         formalGLMPSISourceBridgeReceiptV1    `json:"psi_receipt"`
	UnsignedDescriptor formalGLMSignedPublicDescriptorV1    `json:"unsigned_descriptor"`
	DescriptorApproval jointDPBiomedicalGaussianSignature   `json:"descriptor_approval"`
	Artifact           formalGLMPhase21StickyArtifact       `json:"artifact"`
	SamplerMode        string                               `json:"sampler_mode"`
	NoiseCommitment    *formalGLMPhase21SamplerV2Commitment `json:"noise_commitment,omitempty"`
	ServerOwnedAliases []string                             `json:"server_owned_aliases"`
	ProductionReady    bool                                 `json:"production_ready"`
}

type formalGLMPublicProvisionApproveV1 struct {
	Version                    string                             `json:"version"`
	Purpose                    string                             `json:"purpose"`
	Descriptor                 formalGLMSignedPublicDescriptorV1  `json:"descriptor"`
	UnsignedEntry              formalGLMArtifactRegistryEntryV1   `json:"unsigned_entry"`
	EntryApproval              jointDPBiomedicalGaussianSignature `json:"entry_approval"`
	UnsignedSamplerV2Contract  formalGLMPhase21SamplerV2Contract  `json:"unsigned_sampler_v2_contract"`
	SamplerV2Approval          jointDPBiomedicalGaussianSignature `json:"sampler_v2_approval"`
	UnsignedSourceContractCore formalGLMSourceContractCoreV1      `json:"unsigned_source_contract_core"`
	SourceContractApproval     jointDPBiomedicalGaussianSignature `json:"source_contract_approval"`
	ProductionReady            bool                               `json:"production_ready"`
}

type formalGLMPublicProvisionPayloadV1 struct {
	Version         string                             `json:"version"`
	Stage           string                             `json:"stage"`
	Prepare         *formalGLMPublicProvisionPrepareV1 `json:"prepare,omitempty"`
	Approve         *formalGLMPublicProvisionApproveV1 `json:"approve,omitempty"`
	ProductionReady bool                               `json:"production_ready"`
}

type formalGLMPublicProvisionBundleV1 struct {
	Version           string   `json:"version"`
	Purpose           string   `json:"purpose"`
	ReceiptFramesJSON []string `json:"receipt_frames_json"`
	ProductionReady   bool     `json:"production_ready"`
}

type formalGLMPublicReceiptFrameV1 struct {
	Version               string                                 `json:"version"`
	Purpose               string                                 `json:"purpose"`
	State                 string                                 `json:"state"`
	SelectorSHA256        string                                 `json:"selector_sha256"`
	Provision             *formalGLMPublicProvisionPayloadV1     `json:"provision,omitempty"`
	Resolution            *formalGLMArtifactRegistryResolutionV1 `json:"resolution,omitempty"`
	Step                  int                                    `json:"step"`
	PreviousReceiptSHA256 string                                 `json:"previous_receipt_sha256,omitempty"`
	PeerFrameSHA256       string                                 `json:"peer_frame_sha256,omitempty"`
	SignerPeerName        string                                 `json:"signer_peer_name"`
	SignerIdentityPK      string                                 `json:"signer_identity_pk"`
	ProductionReady       bool                                   `json:"production_ready"`
	Signature             string                                 `json:"signature"`
}

type formalGLMPublicResolveResponseV1 struct {
	Version          string `json:"version"`
	ReceiptFrameJSON string `json:"receipt_frame_json"`
}

type formalGLMPublicRelayV1 struct {
	Channel           string `json:"channel"`
	SenderPeerName    string `json:"sender_peer_name"`
	RecipientPeerName string `json:"recipient_peer_name"`
}

type formalGLMPublicAdvanceResponseV1 struct {
	Version            string                  `json:"version"`
	State              string                  `json:"state"`
	ReceiptFrameJSON   string                  `json:"receipt_frame_json"`
	Relay              *formalGLMPublicRelayV1 `json:"relay"`
	PeerFrameJSON      string                  `json:"peer_frame_json"`
	PeerFrameRecipient string                  `json:"peer_frame_recipient"`
	PublicV2JSON       string                  `json:"public_v2_json"`
	CertificateSHA256  string                  `json:"certificate_sha256"`
	Replayed           bool                    `json:"replayed"`
}

type formalGLMPublicTerminalEvidenceV1 struct {
	Contract    formalGLMPhase21SamplerV2Contract
	Binding     formalFinalizerHandoffBinding
	Ticket      formalFinalizerHandoffTicket
	Publication formalGLMPhase21PublicCertificateV2
	Commits     [2]formalGLMPhase21RockCommitRecord
	Ack         formalGLMPhase21RockAckRecord
	Cleanups    [2]formalGLMPhase21RockCleanupRecord
}

type formalGLMPublicAdvanceContextV1 struct {
	Resolution      formalGLMArtifactRegistryResolutionV1
	Receipt         formalGLMPublicReceiptFrameV1
	ReceiptJSON     []byte
	PeerFrameJSON   []byte
	PeerFrameSHA256 string
}

type formalGLMPublicProvisionPrepareSetV1 struct {
	Model                     formalGLMSignedPreSourceModelV1
	Receipts                  []formalGLMPSISourceBridgeReceiptV1
	Descriptor                formalGLMSignedPublicDescriptorV1
	Artifact                  formalGLMPhase21StickyArtifact
	UnsignedSamplerV2Contract formalGLMPhase21SamplerV2Contract
	Aliases                   []string
}

type formalGLMPublicProvisionApproveSetV1 struct {
	Entry             formalGLMArtifactRegistryEntryV1
	SamplerV2Contract formalGLMPhase21SamplerV2Contract
	SourceContract    formalGLMSourceContractV1
}

type formalGLMPublicProvisionApproveDraftV1 struct {
	Descriptor              formalGLMSignedPublicDescriptorV1
	UnsignedEntry           formalGLMArtifactRegistryEntryV1
	RegisteredExecutionPlan formalGLMRegisteredExecutionPlanV1
}

type formalGLMPublicProvisionerV1 struct {
	SamplerV2AuthorityRootStore *formalGLMSamplerV2AuthorityRootStoreV1
	SamplerV2ContractStore      *formalGLMSamplerV2ContractStoreV1
	SourceContractStore         *formalGLMSourceContractStoreV1
	Prepare                     func(formalGLMPublicSelectorV1) (
		formalGLMPublicProvisionPrepareV1, bool, error)
	Approve func(formalGLMPublicProvisionPrepareSetV1) (
		formalGLMPublicProvisionApproveDraftV1, error)
	Commit func(formalGLMArtifactRegistryEntryV1) (
		formalGLMArtifactRegistryResolutionV1, bool, error)
}

type formalGLMPublicAdvanceObservationV1 struct {
	Binding          *formalFinalizerHandoffBinding
	ControlFrameJSON []byte
	OpeningFrameJSON []byte
	OpeningSender    string
	OpeningRecipient string
	Terminal         *formalGLMPublicTerminalEvidenceV1
	Failed           bool
	Replayed         bool
}

type formalGLMPublicAdvanceFuncV1 func(
	formalGLMPublicAdvanceContextV1,
) (formalGLMPublicAdvanceObservationV1, error)

type formalGLMPublicEndpointV1 struct {
	registry       *formalGLMArtifactRegistryStoreV1
	bridgeReceipts []formalGLMPSISourceBridgeReceiptV1
	pins           map[string]ed25519.PublicKey
	signerPeer     string
	signerKey      ed25519.PrivateKey
	advance        formalGLMPublicAdvanceFuncV1
	provisioner    *formalGLMPublicProvisionerV1
	advanceMu      sync.Mutex
	advanceInputs  map[string]string
	advanceCache   map[string]formalGLMPublicAdvanceResponseV1
}

func formalGLMPublicStrictCanonicalJSONV1(
	encoded []byte, maximum int, output any,
) error {
	if len(encoded) < 2 || len(encoded) > maximum || encoded[0] != '{' {
		return fmt.Errorf("formal-glm public endpoint: invalid JSON frame")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("formal-glm public endpoint: invalid typed frame")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-glm public endpoint: trailing JSON frame")
	}
	canonical, err := json.Marshal(output)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("formal-glm public endpoint: non-canonical JSON frame")
	}
	return nil
}

func formalGLMPublicSelectorSHA256V1(
	selector formalGLMPublicSelectorV1,
) (string, error) {
	encoded, err := json.Marshal(selector)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte("dsVert/formal-glm/public-endpoint/selector/v1|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMValidatePublicSelectorV1(
	selector formalGLMPublicSelectorV1,
	receipts []formalGLMPSISourceBridgeReceiptV1,
	pins map[string]ed25519.PublicKey,
) error {
	formula, formulaErr := formalGLMCanonicalQualifiedFormulaV1(
		selector.CanonicalQualifiedFormula)
	receiptsValid := formalGLMValidatePSISourceBridgeSetV1(receipts, pins) == nil
	if len(receipts) == 1 {
		receiptsValid = formalGLMValidatePublicLocalPSIReceiptV1(
			receipts[0], pins) == nil
	}
	if selector.Version != formalGLMPublicSelectorVersion ||
		selector.Purpose != formalGLMPublicSelectorPurpose ||
		selector.Family != "binomial" || formulaErr != nil ||
		formula.Canonical != selector.CanonicalQualifiedFormula ||
		(selector.FormalAnalysisID != "" &&
			!formalGLMRegistryLabelV1(selector.FormalAnalysisID, 256)) ||
		selector.Federation.Version != formalGLMPublicFederationSelectorVersion ||
		!formalGLMRegistryLabelV1(selector.Federation.Symbol, 128) ||
		formalGLMValidatePSIPublicAttestationV3(
			selector.Federation.Attestation) != nil ||
		!receiptsValid ||
		selector.Federation.Attestation.PeerCount != len(pins) ||
		len(selector.Federation.UsedColumns) == 0 ||
		len(selector.Federation.UsedColumns) > 4096 {
		return fmt.Errorf("formal-glm public endpoint: invalid selector")
	}
	matchedAttestation := false
	for _, receipt := range receipts {
		attestation := selector.Federation.Attestation
		if receipt.Core.RPinsetID != attestation.PinsetID ||
			receipt.Core.PSIAttestation.PinsetID != attestation.PinsetID ||
			receipt.Core.PSIAttestation.AlignmentProtocol !=
				attestation.AlignmentProtocol ||
			receipt.Core.PSIAttestation.AlignmentPurpose !=
				attestation.AlignmentPurpose ||
			receipt.Core.PSIAttestation.PeerCount != attestation.PeerCount ||
			receipt.Core.PSIAttestation.ReferencePeer !=
				attestation.ReferencePeer ||
			!reflect.DeepEqual(receipt.Core.PSIAttestation.ComputePeers,
				attestation.ComputePeers) {
			return fmt.Errorf("formal-glm public endpoint: selector pinset mismatch")
		}
		exactSource := receipt.Core.SourceBindingID == attestation.SourceBindingID &&
			receipt.Core.DatasetID == attestation.DatasetID &&
			receipt.Core.DatasetVersion == attestation.DatasetVersion
		if exactSource || (len(receipts) == 1 &&
			receipt.Core.SignerPeerName != attestation.ReferencePeer) {
			matchedAttestation = true
		}
	}
	if !matchedAttestation {
		return fmt.Errorf("formal-glm public endpoint: selector PSI source mismatch")
	}
	responses := 0
	seen := make(map[string]bool, len(selector.Federation.UsedColumns))
	for _, column := range selector.Federation.UsedColumns {
		key := column.Owner + "\x00" + column.Column
		if !formalGLMRegistryLabelV1(column.Owner, 128) ||
			!formalGLMRegistryLabelV1(column.Column, 128) || seen[key] ||
			(column.Kind != "binary" && column.Kind != "numeric" &&
				column.Kind != "categorical" && column.Kind != "factor") ||
			(column.Role != "response" && column.Role != "predictor") {
			return fmt.Errorf("formal-glm public endpoint: invalid selector column")
		}
		seen[key] = true
		if column.Role == "response" {
			responses++
		}
	}
	if responses != 1 {
		return fmt.Errorf("formal-glm public endpoint: invalid selector response")
	}
	return nil
}

func formalGLMValidatePublicLocalPSIReceiptV1(
	receipt formalGLMPSISourceBridgeReceiptV1,
	pins map[string]ed25519.PublicKey,
) error {
	message, messageErr := formalGLMPSISourceBridgeMessageV1(receipt.Core)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(
		receipt.Signature)
	pin := pins[receipt.Core.SignerPeerName]
	if formalGLMValidatePSISourceBridgeCoreV1(receipt.Core, pins) != nil ||
		messageErr != nil || signatureErr != nil ||
		len(signature) != ed25519.SignatureSize ||
		len(pin) != ed25519.PublicKeySize ||
		!ed25519.Verify(pin, message, signature) {
		return fmt.Errorf("formal-glm public endpoint: invalid local PSI receipt")
	}
	return nil
}

func formalGLMPublicSelectorMatchesResolutionV1(
	selector formalGLMPublicSelectorV1,
	resolution formalGLMArtifactRegistryResolutionV1,
	pins map[string]ed25519.PublicKey,
) error {
	if resolution.ArtifactID == "" ||
		formalGLMValidateSignedPublicDescriptorV1(
			resolution.Descriptor, pins) != nil ||
		resolution.Descriptor.ArtifactID != resolution.ArtifactID {
		return fmt.Errorf("formal-glm public endpoint: invalid registry resolution")
	}
	return formalGLMPublicSelectorMatchesDescriptorV1(
		selector, resolution.Descriptor)
}

func formalGLMPublicSelectorMatchesDescriptorV1(
	selector formalGLMPublicSelectorV1,
	descriptor formalGLMSignedPublicDescriptorV1,
) error {
	core := descriptor.Descriptor
	if core.Family != selector.Family ||
		core.CanonicalQualifiedFormula != selector.CanonicalQualifiedFormula ||
		core.PinsetSHA256 == "" || len(core.UsedColumns) !=
		len(selector.Federation.UsedColumns) {
		return fmt.Errorf("formal-glm public endpoint: selector resolution mismatch")
	}
	for index, selected := range selector.Federation.UsedColumns {
		registered := core.UsedColumns[index]
		if selected.Owner != registered.Owner ||
			selected.Column != registered.Column ||
			selected.Kind != registered.Kind || selected.Role != registered.Role {
			return fmt.Errorf("formal-glm public endpoint: selector column mismatch")
		}
	}
	return nil
}

func formalGLMPublicReceiptMessageV1(
	receipt formalGLMPublicReceiptFrameV1,
) ([]byte, error) {
	receipt.Signature = ""
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPublicReceiptDomain+"|"), encoded...), nil
}

func formalGLMPublicReceiptSHA256V1(encoded []byte) string {
	digest := sha256.Sum256(append(
		[]byte(formalGLMPublicReceiptDomain+"/frame|"), encoded...))
	return hex.EncodeToString(digest[:])
}

func formalGLMPublicReceiptStateV1(state string) bool {
	switch state {
	case formalGLMPublicResolveAbsent, formalGLMPublicResolveUnique,
		formalGLMPublicResolveAmbiguous,
		formalGLMPublicStateProvisionPrepare,
		formalGLMPublicStateProvisionApprove, formalGLMPublicStateRelay,
		formalGLMPublicStateComplete, formalGLMPublicStateFailed:
		return true
	default:
		return false
	}
}

func formalGLMPublicVerifyApprovalV1(
	approval jointDPBiomedicalGaussianSignature, message []byte,
	pins map[string]ed25519.PublicKey,
) error {
	pin := pins[approval.Signer]
	if !formalGLMRegistryLabelV1(approval.Signer, 128) ||
		len(pin) != ed25519.PublicKeySize ||
		len(approval.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, message, approval.Signature) {
		return fmt.Errorf("formal-glm public endpoint: invalid provision approval")
	}
	return nil
}

func formalGLMPublicSamplerV2AuthorityIndexV1(
	artifact formalGLMPhase21StickyArtifact, peer string,
) int {
	for index, authority := range artifact.NoiseAuthorities {
		if authority.PeerName == peer {
			return index
		}
	}
	return -1
}

func formalGLMValidatePublicSamplerV2CommitmentV1(
	commitment formalGLMPhase21SamplerV2Commitment,
	artifact formalGLMPhase21StickyArtifact,
	artifactID, samplerMode string, position int,
) error {
	if position < 0 || position >= len(artifact.NoiseAuthorities) {
		return fmt.Errorf("formal-glm public endpoint: invalid sampler-v2 commitment")
	}
	authority := artifact.NoiseAuthorities[position]
	contextValue, err := formalGLMPhase21SamplerV2Context(
		artifactID, samplerMode, authority.Role,
		authority.PeerName, authority.PeerID)
	purpose := formalGLMPhase21SamplerV2Purpose + "/" +
		samplerMode + "/" + authority.Role
	if err != nil || commitment.Role != authority.Role ||
		commitment.PeerName != authority.PeerName ||
		commitment.PeerID != authority.PeerID ||
		commitment.SamplerPurpose != purpose ||
		commitment.CommitmentContextSHA256 !=
			hex.EncodeToString(contextValue[:]) ||
		!formalGLMIsSHA256(commitment.SeedCommitmentSHA256) {
		return fmt.Errorf("formal-glm public endpoint: invalid sampler-v2 commitment")
	}
	return nil
}

func formalGLMValidatePublicProvisionPrepareV1(
	frame formalGLMPublicProvisionPrepareV1,
	pins map[string]ed25519.PublicKey,
) error {
	modelMessage, modelErr := formalGLMSignedPreSourceModelMessageV1(
		frame.UnsignedModel)
	descriptorMessage, descriptorErr := formalGLMSignedPublicDescriptorMessageV1(
		frame.UnsignedDescriptor)
	psiMessage, psiErr := formalGLMPSISourceBridgeMessageV1(
		frame.PSIReceipt.Core)
	psiSignature, psiSignatureErr := base64.RawURLEncoding.Strict().DecodeString(
		frame.PSIReceipt.Signature)
	signer := frame.ModelApproval.Signer
	artifactID, artifactIDErr := formalGLMPhase21StickyArtifactID(frame.Artifact)
	adjacency, adjacencyErr := formalGLMPhase16CommonAdjacency(
		frame.UnsignedModel.Model.CanonicalDP.Adjacency)
	authorityIndex := formalGLMPublicSamplerV2AuthorityIndexV1(
		frame.Artifact, signer)
	commitmentValid := authorityIndex < 0 && frame.NoiseCommitment == nil
	if authorityIndex >= 0 && frame.NoiseCommitment != nil {
		commitmentValid = formalGLMValidatePublicSamplerV2CommitmentV1(
			*frame.NoiseCommitment, frame.Artifact, artifactID,
			frame.SamplerMode, authorityIndex) == nil
	}
	if frame.Version != formalGLMPublicProvisionPrepareVersion ||
		frame.Purpose != formalGLMPublicProvisionPurpose || frame.ProductionReady ||
		len(frame.ServerOwnedAliases) < 1 ||
		len(frame.ServerOwnedAliases) > formalGLMArtifactRegistryMaxEntry ||
		!sort.StringsAreSorted(frame.ServerOwnedAliases) ||
		len(frame.UnsignedModel.CustodianApprovals) != 0 ||
		formalGLMValidateSignedPreSourceModelCoreV1(
			frame.UnsignedModel, pins) != nil || modelErr != nil ||
		formalGLMPublicVerifyApprovalV1(
			frame.ModelApproval, modelMessage, pins) != nil ||
		len(frame.UnsignedDescriptor.CustodianApprovals) != 0 ||
		formalGLMValidateSignedPublicDescriptorCoreV1(
			frame.UnsignedDescriptor, pins) != nil || descriptorErr != nil ||
		formalGLMPublicVerifyApprovalV1(
			frame.DescriptorApproval, descriptorMessage, pins) != nil ||
		formalGLMValidatePSISourceBridgeCoreV1(
			frame.PSIReceipt.Core, pins) != nil || psiErr != nil ||
		psiSignatureErr != nil || len(psiSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[frame.PSIReceipt.Core.SignerPeerName],
			psiMessage, psiSignature) ||
		frame.PSIReceipt.Core.SignerPeerName != signer ||
		frame.DescriptorApproval.Signer != signer ||
		frame.PSIReceipt.Core.DescriptorCoreSHA256 !=
			frame.UnsignedDescriptor.DescriptorCoreSHA256 ||
		!reflect.DeepEqual(frame.UnsignedModel.CustodianPeers,
			frame.UnsignedDescriptor.CustodianPeers) ||
		formalGLMPhase21ValidateStickyArtifact(frame.Artifact, pins) != nil ||
		artifactIDErr != nil || artifactID != frame.UnsignedDescriptor.ArtifactID ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			frame.UnsignedDescriptor, frame.Artifact) != nil ||
		frame.SamplerMode != formalGLMPhase21SamplerV2OneDraw ||
		!commitmentValid ||
		frame.Artifact.CanonicalScienceSHA256 !=
			frame.UnsignedModel.Model.CanonicalScienceSHA256 ||
		frame.Artifact.CanonicalPlanSHA256 !=
			frame.UnsignedModel.Model.CanonicalDP.CanonicalPlanSHA256 ||
		frame.Artifact.SnapshotSHA256 != frame.UnsignedModel.Model.SnapshotSHA256 ||
		frame.Artifact.PinsetSHA256 != frame.UnsignedModel.Model.PinsetSHA256 ||
		frame.Artifact.Family != frame.UnsignedModel.Model.Family ||
		adjacencyErr != nil || frame.Artifact.Adjacency != adjacency ||
		frame.Artifact.Mechanism != frame.UnsignedModel.Model.Mechanism ||
		frame.Artifact.Allocation != frame.UnsignedModel.Model.Allocation ||
		frame.Artifact.SensitivitySteps !=
			frame.UnsignedModel.Model.CanonicalDP.SelectedSensitivitySteps ||
		frame.Artifact.BoundsSHA256 !=
			frame.UnsignedModel.Model.CanonicalDP.BoundsSHA256 ||
		frame.Artifact.QuantizationSHA256 !=
			frame.UnsignedModel.Model.CanonicalDP.QuantizationSHA256 ||
		frame.Artifact.CoordinateOrderSHA256 !=
			frame.UnsignedModel.Model.CanonicalDP.TransportCoordinateOrderSHA256 ||
		frame.Artifact.CoordinateCount !=
			frame.UnsignedModel.Model.CanonicalDP.CoordinateCount ||
		frame.Artifact.SourceFractionBits !=
			frame.UnsignedModel.Model.CanonicalDP.SourceFractionBits ||
		frame.Artifact.QuantizationShift !=
			frame.UnsignedModel.Model.CanonicalDP.QuantizationShift ||
		frame.Artifact.OutputLatticeBits !=
			frame.UnsignedModel.Model.CanonicalDP.OutputLatticeBits ||
		!reflect.DeepEqual(frame.Artifact.CustodianPeers,
			frame.UnsignedModel.CustodianPeers) ||
		frame.Artifact.CustodianCount != frame.UnsignedModel.CustodianCount {
		return fmt.Errorf("formal-glm public endpoint: invalid provision prepare")
	}
	for index, alias := range frame.ServerOwnedAliases {
		if !formalGLMRegistryLabelV1(alias, 256) ||
			(index > 0 && frame.ServerOwnedAliases[index-1] == alias) {
			return fmt.Errorf("formal-glm public endpoint: invalid server aliases")
		}
	}
	return nil
}

func formalGLMPublicProvisionHasAliasV1(aliases []string, want string) bool {
	index := sort.SearchStrings(aliases, want)
	return index < len(aliases) && aliases[index] == want
}

func formalGLMValidatePublicProvisionApproveV1(
	frame formalGLMPublicProvisionApproveV1,
	pins map[string]ed25519.PublicKey,
) error {
	entryMessage, entryErr := formalGLMArtifactRegistryEntryMessageV1(
		frame.UnsignedEntry)
	contractMessage, contractErr := formalGLMPhase21SamplerV2ContractMessage(
		frame.UnsignedSamplerV2Contract)
	sourceMessage, sourceErr := formalGLMSourceContractMessageV1(
		frame.UnsignedSourceContractCore)
	if frame.Version != formalGLMPublicProvisionApproveVersion ||
		frame.Purpose != formalGLMPublicProvisionPurpose || frame.ProductionReady ||
		formalGLMValidateSignedPublicDescriptorV1(frame.Descriptor, pins) != nil ||
		len(frame.UnsignedEntry.CustodianApprovals) != 0 ||
		formalGLMValidateArtifactRegistryEntryCoreV1(
			frame.UnsignedEntry, pins) != nil ||
		!reflect.DeepEqual(frame.UnsignedEntry.Descriptor, frame.Descriptor) ||
		entryErr != nil || formalGLMPublicVerifyApprovalV1(
		frame.EntryApproval, entryMessage, pins) != nil ||
		formalGLMPhase21ValidateSamplerV2ContractCore(
			frame.UnsignedSamplerV2Contract, pins) != nil ||
		len(frame.UnsignedSamplerV2Contract.CustodianSignatures) != 0 ||
		contractErr != nil || formalGLMPublicVerifyApprovalV1(
		frame.SamplerV2Approval, contractMessage, pins) != nil ||
		formalGLMValidateSourceContractCoreV1(
			frame.UnsignedSourceContractCore, pins) != nil ||
		sourceErr != nil || formalGLMPublicVerifyApprovalV1(
		frame.SourceContractApproval, sourceMessage, pins) != nil ||
		frame.SamplerV2Approval.Signer != frame.EntryApproval.Signer ||
		frame.SourceContractApproval.Signer != frame.EntryApproval.Signer ||
		frame.UnsignedSamplerV2Contract.ArtifactID !=
			frame.UnsignedEntry.ArtifactID ||
		!reflect.DeepEqual(frame.UnsignedSamplerV2Contract.CustodianPeers,
			frame.UnsignedEntry.CustodianPeers) ||
		frame.UnsignedSamplerV2Contract.CustodianCount !=
			frame.UnsignedEntry.CustodianCount ||
		frame.UnsignedSourceContractCore.ArtifactID !=
			frame.UnsignedEntry.ArtifactID ||
		frame.UnsignedSourceContractCore.BridgeSetSHA256 !=
			frame.UnsignedEntry.BridgeSetSHA256 ||
		frame.UnsignedSourceContractCore.SourceBindingSet.DescriptorCoreSHA256 !=
			frame.UnsignedEntry.DescriptorCoreSHA256 ||
		frame.UnsignedSourceContractCore.RegisteredExecutionPlan.
			DescriptorCoreSHA256 != frame.UnsignedEntry.DescriptorCoreSHA256 ||
		!reflect.DeepEqual(
			frame.UnsignedSourceContractCore.RegisteredExecutionPlan.DescriptorCore,
			frame.UnsignedEntry.Descriptor.Descriptor) ||
		!reflect.DeepEqual(frame.UnsignedSourceContractCore.SamplerV2ContractCore,
			frame.UnsignedSamplerV2Contract) ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			frame.Descriptor, frame.UnsignedSamplerV2Contract.Artifact) != nil {
		return fmt.Errorf("formal-glm public endpoint: invalid provision approve")
	}
	return nil
}

func formalGLMValidatePublicProvisionPayloadV1(
	payload *formalGLMPublicProvisionPayloadV1,
	state, signer string, pins map[string]ed25519.PublicKey,
) error {
	if payload == nil || payload.Version != formalGLMPublicProvisionPayloadVersion ||
		payload.Stage != state || payload.ProductionReady {
		return fmt.Errorf("formal-glm public endpoint: invalid provision payload")
	}
	switch state {
	case formalGLMPublicStateProvisionPrepare:
		if payload.Prepare == nil || payload.Approve != nil ||
			formalGLMValidatePublicProvisionPrepareV1(*payload.Prepare, pins) != nil ||
			payload.Prepare.ModelApproval.Signer != signer {
			return fmt.Errorf("formal-glm public endpoint: invalid prepare payload")
		}
	case formalGLMPublicStateProvisionApprove:
		if payload.Approve == nil || payload.Prepare != nil ||
			formalGLMValidatePublicProvisionApproveV1(*payload.Approve, pins) != nil ||
			payload.Approve.EntryApproval.Signer != signer {
			return fmt.Errorf("formal-glm public endpoint: invalid approve payload")
		}
	default:
		return fmt.Errorf("formal-glm public endpoint: invalid provision stage")
	}
	return nil
}

func formalGLMPublicProvisionBundleReceiptsV1(
	encoded []byte, wantState, selectorSHA256,
	localPeer, localReceiptSHA256 string,
	pins map[string]ed25519.PublicKey,
) ([]formalGLMPublicReceiptFrameV1, error) {
	var bundle formalGLMPublicProvisionBundleV1
	if err := formalGLMPublicStrictCanonicalJSONV1(
		encoded, formalGLMPublicMaxPeerFrameJSON, &bundle); err != nil ||
		bundle.Version != formalGLMPublicProvisionBundleVersion ||
		bundle.Purpose != formalGLMPublicProvisionPurpose || bundle.ProductionReady ||
		len(bundle.ReceiptFramesJSON) != len(pins) {
		return nil, fmt.Errorf("formal-glm public endpoint: invalid provision bundle")
	}
	peers := make([]string, 0, len(pins))
	for peer := range pins {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	receipts := make([]formalGLMPublicReceiptFrameV1, len(peers))
	for index, encodedReceipt := range bundle.ReceiptFramesJSON {
		receipt, err := formalGLMValidatePublicEndpointReceiptV1(
			[]byte(encodedReceipt), pins)
		if err != nil || receipt.State != wantState ||
			receipt.SelectorSHA256 != selectorSHA256 ||
			receipt.SignerPeerName != peers[index] ||
			(receipt.SignerPeerName == localPeer &&
				formalGLMPublicReceiptSHA256V1([]byte(encodedReceipt)) !=
					localReceiptSHA256) {
			return nil, fmt.Errorf("formal-glm public endpoint: invalid ordered provision bundle")
		}
		receipts[index] = receipt
	}
	return receipts, nil
}

func formalGLMPublicValidatePrepareBundleV1(
	encoded []byte, selectorSHA256, localPeer, localReceiptSHA256 string,
	pins map[string]ed25519.PublicKey,
) (formalGLMPublicProvisionPrepareSetV1, error) {
	var zero formalGLMPublicProvisionPrepareSetV1
	receiptFrames, err := formalGLMPublicProvisionBundleReceiptsV1(
		encoded, formalGLMPublicStateProvisionPrepare, selectorSHA256,
		localPeer, localReceiptSHA256, pins)
	if err != nil {
		return zero, err
	}
	first := *receiptFrames[0].Provision.Prepare
	modelApprovals := make([]jointDPBiomedicalGaussianSignature,
		len(receiptFrames))
	descriptorApprovals := make([]jointDPBiomedicalGaussianSignature,
		len(receiptFrames))
	psiReceipts := make([]formalGLMPSISourceBridgeReceiptV1, len(receiptFrames))
	commitments := make([]formalGLMPhase21SamplerV2Commitment,
		len(first.Artifact.NoiseAuthorities))
	commitmentSeen := make([]bool, len(commitments))
	for index, receipt := range receiptFrames {
		frame := *receipt.Provision.Prepare
		if !reflect.DeepEqual(frame.UnsignedModel, first.UnsignedModel) ||
			!reflect.DeepEqual(frame.UnsignedDescriptor, first.UnsignedDescriptor) ||
			!reflect.DeepEqual(frame.Artifact, first.Artifact) ||
			frame.SamplerMode != first.SamplerMode ||
			!reflect.DeepEqual(frame.ServerOwnedAliases,
				first.ServerOwnedAliases) {
			return zero, fmt.Errorf("formal-glm public endpoint: provision drafts disagree")
		}
		authorityIndex := formalGLMPublicSamplerV2AuthorityIndexV1(
			first.Artifact, receipt.SignerPeerName)
		if authorityIndex >= 0 {
			if frame.NoiseCommitment == nil || commitmentSeen[authorityIndex] {
				return zero, fmt.Errorf(
					"formal-glm public endpoint: invalid authority commitment set")
			}
			commitments[authorityIndex] = *frame.NoiseCommitment
			commitmentSeen[authorityIndex] = true
		} else if frame.NoiseCommitment != nil {
			return zero, fmt.Errorf(
				"formal-glm public endpoint: witness supplied authority commitment")
		}
		modelApprovals[index] = frame.ModelApproval
		descriptorApprovals[index] = frame.DescriptorApproval
		psiReceipts[index] = frame.PSIReceipt
	}
	for _, seen := range commitmentSeen {
		if !seen {
			return zero, fmt.Errorf(
				"formal-glm public endpoint: sampler-v2 requires two commitments")
		}
	}
	model, err := formalGLMSealPreSourceModelV1(
		first.UnsignedModel, modelApprovals, pins)
	if err != nil || formalGLMValidatePSISourceBridgeSetV1(
		psiReceipts, pins) != nil {
		return zero, fmt.Errorf("formal-glm public endpoint: invalid K prepare set")
	}
	descriptor, err := formalGLMSealPublicDescriptorV1(
		first.UnsignedDescriptor, descriptorApprovals, pins)
	if err != nil {
		return zero, fmt.Errorf("formal-glm public endpoint: invalid K descriptor set")
	}
	core, coreSHA256, err := formalGLMDescriptorCoreFromPreSourceV1(
		model, psiReceipts, pins, true)
	if err != nil || coreSHA256 != descriptor.DescriptorCoreSHA256 ||
		!reflect.DeepEqual(core, descriptor.Descriptor) {
		return zero, fmt.Errorf("formal-glm public endpoint: provision descriptor mismatch")
	}
	unsignedContract, err := formalGLMPhase21BuildSamplerV2Contract(
		first.Artifact, descriptor.ArtifactID, first.SamplerMode,
		commitments, pins)
	if err != nil {
		return zero, fmt.Errorf(
			"formal-glm public endpoint: invalid sampler-v2 prepare set")
	}
	return formalGLMPublicProvisionPrepareSetV1{
		Model: model, Receipts: psiReceipts,
		Descriptor: descriptor, Artifact: first.Artifact,
		UnsignedSamplerV2Contract: unsignedContract,
		Aliases:                   append([]string(nil), first.ServerOwnedAliases...),
	}, nil
}

func formalGLMPublicValidateApproveBundleV1(
	encoded []byte, selectorSHA256, localPeer, localReceiptSHA256 string,
	pins map[string]ed25519.PublicKey,
) (formalGLMPublicProvisionApproveSetV1, error) {
	var zero formalGLMPublicProvisionApproveSetV1
	receiptFrames, err := formalGLMPublicProvisionBundleReceiptsV1(
		encoded, formalGLMPublicStateProvisionApprove, selectorSHA256,
		localPeer, localReceiptSHA256, pins)
	if err != nil {
		return zero, err
	}
	first := *receiptFrames[0].Provision.Approve
	approvals := make([]jointDPBiomedicalGaussianSignature, len(receiptFrames))
	contractApprovals := make([]jointDPBiomedicalGaussianSignature,
		len(receiptFrames))
	sourceApprovals := make([]jointDPBiomedicalGaussianSignature,
		len(receiptFrames))
	for index, receipt := range receiptFrames {
		frame := *receipt.Provision.Approve
		if !reflect.DeepEqual(frame.Descriptor, first.Descriptor) ||
			!reflect.DeepEqual(frame.UnsignedEntry, first.UnsignedEntry) ||
			!reflect.DeepEqual(frame.UnsignedSamplerV2Contract,
				first.UnsignedSamplerV2Contract) ||
			!reflect.DeepEqual(frame.UnsignedSourceContractCore,
				first.UnsignedSourceContractCore) {
			return zero, fmt.Errorf("formal-glm public endpoint: provision entries disagree")
		}
		approvals[index] = frame.EntryApproval
		contractApprovals[index] = frame.SamplerV2Approval
		sourceApprovals[index] = frame.SourceContractApproval
	}
	sourceContract, err := formalGLMSealSourceContractV1(
		first.UnsignedSourceContractCore, sourceApprovals, pins)
	if err != nil {
		return zero, fmt.Errorf(
			"formal-glm public endpoint: invalid K source-contract approve set")
	}
	contract, err := formalGLMPhase21SealSamplerV2Contract(
		first.UnsignedSamplerV2Contract, contractApprovals, pins)
	if err != nil {
		return zero, fmt.Errorf(
			"formal-glm public endpoint: invalid K sampler-v2 approve set")
	}
	entry := first.UnsignedEntry
	entry.CustodianApprovals = approvals
	if formalGLMValidateArtifactRegistryEntryV1(entry, pins) != nil {
		return zero, fmt.Errorf("formal-glm public endpoint: invalid K approve set")
	}
	if contract.ArtifactID != entry.ArtifactID ||
		!reflect.DeepEqual(contract.CustodianPeers, entry.CustodianPeers) ||
		contract.CustodianCount != entry.CustodianCount ||
		sourceContract.Core.ArtifactID != entry.ArtifactID ||
		sourceContract.Core.BridgeSetSHA256 != entry.BridgeSetSHA256 ||
		!reflect.DeepEqual(sourceContract.Core.SamplerV2ContractCore,
			first.UnsignedSamplerV2Contract) {
		return zero, fmt.Errorf(
			"formal-glm public endpoint: invalid K sampler-v2 approve set")
	}
	return formalGLMPublicProvisionApproveSetV1{
		Entry: entry, SamplerV2Contract: contract,
		SourceContract: sourceContract,
	}, nil
}

func formalGLMValidatePublicEndpointReceiptV1(
	encoded []byte, pins map[string]ed25519.PublicKey,
) (formalGLMPublicReceiptFrameV1, error) {
	var receipt formalGLMPublicReceiptFrameV1
	if err := formalGLMPublicStrictCanonicalJSONV1(
		encoded, formalGLMPublicMaxReceiptJSON, &receipt); err != nil {
		return receipt, err
	}
	signature, signatureErr := base64.RawURLEncoding.DecodeString(
		receipt.Signature)
	message, messageErr := formalGLMPublicReceiptMessageV1(receipt)
	pin := pins[receipt.SignerPeerName]
	if receipt.Version != formalGLMPublicReceiptVersion ||
		receipt.Purpose != formalGLMPublicReceiptPurpose ||
		!formalGLMPublicReceiptStateV1(receipt.State) ||
		!formalGLMIsSHA256(receipt.SelectorSHA256) || receipt.Step < 0 ||
		receipt.Step > 100000 || receipt.ProductionReady ||
		!formalGLMRegistryLabelV1(receipt.SignerPeerName, 128) ||
		receipt.SignerIdentityPK != formalGLMIdentityPKV1(pin) ||
		len(pin) != ed25519.PublicKeySize || signatureErr != nil ||
		len(signature) != ed25519.SignatureSize || messageErr != nil ||
		!ed25519.Verify(pin, message, signature) {
		return receipt, fmt.Errorf("formal-glm public endpoint: invalid receipt")
	}
	hasPrevious := formalGLMIsSHA256(receipt.PreviousReceiptSHA256)
	hasPeer := formalGLMIsSHA256(receipt.PeerFrameSHA256)
	validResolution := receipt.Resolution != nil &&
		formalGLMValidateSignedPublicDescriptorV1(
			receipt.Resolution.Descriptor, pins) == nil &&
		receipt.Resolution.ArtifactID == receipt.Resolution.Descriptor.ArtifactID
	switch receipt.State {
	case formalGLMPublicResolveAbsent, formalGLMPublicResolveAmbiguous:
		if receipt.Step != 0 || receipt.PreviousReceiptSHA256 != "" ||
			receipt.PeerFrameSHA256 != "" || receipt.Provision != nil ||
			receipt.Resolution != nil {
			return receipt, fmt.Errorf("formal-glm public endpoint: invalid unavailable receipt")
		}
	case formalGLMPublicStateProvisionPrepare:
		if receipt.Step != 0 || receipt.PreviousReceiptSHA256 != "" ||
			receipt.PeerFrameSHA256 != "" || receipt.Resolution != nil ||
			formalGLMValidatePublicProvisionPayloadV1(
				receipt.Provision, receipt.State,
				receipt.SignerPeerName, pins) != nil {
			return receipt, fmt.Errorf("formal-glm public endpoint: invalid prepare receipt")
		}
	case formalGLMPublicStateProvisionApprove:
		if receipt.Step != 1 || !hasPrevious || !hasPeer ||
			receipt.Resolution != nil ||
			formalGLMValidatePublicProvisionPayloadV1(
				receipt.Provision, receipt.State,
				receipt.SignerPeerName, pins) != nil {
			return receipt, fmt.Errorf("formal-glm public endpoint: invalid approve receipt")
		}
	case formalGLMPublicResolveUnique:
		if !validResolution || receipt.Provision != nil ||
			(receipt.Step != 0 && receipt.Step != 2) ||
			(receipt.Step == 0 && (receipt.PreviousReceiptSHA256 != "" ||
				receipt.PeerFrameSHA256 != "")) ||
			(receipt.Step == 2 && (!hasPrevious || !hasPeer)) {
			return receipt, fmt.Errorf("formal-glm public endpoint: invalid unique receipt")
		}
	case formalGLMPublicStateRelay, formalGLMPublicStateComplete:
		if receipt.Step < 1 || !hasPrevious ||
			(receipt.PeerFrameSHA256 != "" && !hasPeer) ||
			!validResolution || receipt.Provision != nil {
			return receipt, fmt.Errorf("formal-glm public endpoint: invalid lifecycle receipt")
		}
	case formalGLMPublicStateFailed:
		if receipt.Step < 1 || !hasPrevious ||
			(receipt.PeerFrameSHA256 != "" && !hasPeer) || receipt.Provision != nil ||
			(receipt.Resolution != nil && !validResolution) {
			return receipt, fmt.Errorf("formal-glm public endpoint: invalid failed receipt")
		}
	}
	return receipt, nil
}

func (endpoint *formalGLMPublicEndpointV1) signReceipt(
	receipt formalGLMPublicReceiptFrameV1,
) (string, error) {
	receipt.Version = formalGLMPublicReceiptVersion
	receipt.Purpose = formalGLMPublicReceiptPurpose
	receipt.SignerPeerName = endpoint.signerPeer
	receipt.SignerIdentityPK = formalGLMIdentityPKV1(endpoint.pins[endpoint.signerPeer])
	receipt.ProductionReady = false
	receipt.Signature = ""
	message, err := formalGLMPublicReceiptMessageV1(receipt)
	if err != nil {
		return "", err
	}
	receipt.Signature = formalGLMSignatureBase64URLV1(
		ed25519.Sign(endpoint.signerKey, message))
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	if _, err := formalGLMValidatePublicEndpointReceiptV1(
		encoded, endpoint.pins); err != nil {
		return "", err
	}
	return string(encoded), nil
}

func newFormalGLMPublicEndpointV1(
	registry *formalGLMArtifactRegistryStoreV1,
	bridgeReceipts []formalGLMPSISourceBridgeReceiptV1,
	pins map[string]ed25519.PublicKey,
	signerPeer string,
	signerKey ed25519.PrivateKey,
	advance formalGLMPublicAdvanceFuncV1,
	provisioners ...formalGLMPublicProvisionerV1,
) (*formalGLMPublicEndpointV1, error) {
	pin := pins[signerPeer]
	if len(provisioners) > 1 {
		return nil, fmt.Errorf("formal-glm public endpoint: invalid provisioner")
	}
	receiptsValid := formalGLMValidatePSISourceBridgeSetV1(
		bridgeReceipts, pins) == nil
	if len(provisioners) == 1 && len(bridgeReceipts) == 1 &&
		bridgeReceipts[0].Core.SignerPeerName == signerPeer {
		receiptsValid = formalGLMValidatePublicLocalPSIReceiptV1(
			bridgeReceipts[0], pins) == nil
	}
	if registry == nil || registry.root == nil || len(pins) < 2 ||
		len(pin) != ed25519.PublicKeySize ||
		len(signerKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(signerKey.Public().(ed25519.PublicKey), pin) ||
		!receiptsValid {
		return nil, fmt.Errorf("formal-glm public endpoint: invalid server configuration")
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, value := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), value...)
	}
	endpointPinsetSHA256, err := formalGLMPhase16PinsetSHA256(clonedPins)
	if err != nil {
		return nil, fmt.Errorf("formal-glm public endpoint: invalid server pinset")
	}
	endpoint := &formalGLMPublicEndpointV1{
		registry: registry,
		bridgeReceipts: append([]formalGLMPSISourceBridgeReceiptV1(nil),
			bridgeReceipts...),
		pins: clonedPins, signerPeer: signerPeer,
		signerKey:     append(ed25519.PrivateKey(nil), signerKey...),
		advance:       advance,
		advanceInputs: make(map[string]string),
		advanceCache:  make(map[string]formalGLMPublicAdvanceResponseV1),
	}
	if len(provisioners) == 1 {
		provisioner := provisioners[0]
		if provisioner.Prepare == nil || provisioner.Approve == nil ||
			provisioner.Commit == nil ||
			provisioner.SamplerV2ContractStore == nil ||
			provisioner.SamplerV2ContractStore.root == nil ||
			provisioner.SourceContractStore == nil ||
			provisioner.SourceContractStore.root == nil ||
			provisioner.SamplerV2ContractStore.pinsetSHA256 !=
				endpointPinsetSHA256 ||
			provisioner.SourceContractStore.pinsetSHA256 !=
				endpointPinsetSHA256 {
			return nil, fmt.Errorf("formal-glm public endpoint: incomplete provisioner")
		}
		if rootStore := provisioner.SamplerV2AuthorityRootStore; rootStore != nil && (rootStore.root == nil ||
			rootStore.peer != signerPeer ||
			rootStore.pinsetSHA256 !=
				provisioner.SamplerV2ContractStore.pinsetSHA256) {
			return nil, fmt.Errorf(
				"formal-glm public endpoint: invalid local sampler-v2 authority")
		}
		endpoint.provisioner = &provisioner
	}
	return endpoint, nil
}

func (endpoint *formalGLMPublicEndpointV1) localizeSamplerV2Prepare(
	prepare *formalGLMPublicProvisionPrepareV1,
) error {
	if endpoint == nil || endpoint.provisioner == nil || prepare == nil ||
		prepare.NoiseCommitment != nil ||
		formalGLMPhase21ValidateStickyArtifact(
			prepare.Artifact, endpoint.pins) != nil ||
		prepare.SamplerMode != formalGLMPhase21SamplerV2OneDraw {
		return fmt.Errorf("formal-glm public endpoint: invalid local sampler-v2 draft")
	}
	artifactID, err := formalGLMPhase21StickyArtifactID(prepare.Artifact)
	if err != nil || artifactID != prepare.UnsignedDescriptor.ArtifactID {
		return fmt.Errorf("formal-glm public endpoint: invalid local sampler-v2 artifact")
	}
	position := formalGLMPublicSamplerV2AuthorityIndexV1(
		prepare.Artifact, endpoint.signerPeer)
	rootStore := endpoint.provisioner.SamplerV2AuthorityRootStore
	if position < 0 {
		if rootStore != nil {
			return fmt.Errorf(
				"formal-glm public endpoint: witness has sampler-v2 authority state")
		}
		return nil
	}
	authority := prepare.Artifact.NoiseAuthorities[position]
	if rootStore == nil || rootStore.peer != authority.PeerName ||
		rootStore.role != authority.Role || rootStore.peerID != authority.PeerID {
		return fmt.Errorf(
			"formal-glm public endpoint: local sampler-v2 authority unavailable")
	}
	commitment, err := rootStore.DeriveCommitment(
		artifactID, prepare.SamplerMode)
	if err != nil {
		return fmt.Errorf(
			"formal-glm public endpoint: local sampler-v2 commitment unavailable")
	}
	prepare.NoiseCommitment = &commitment
	return nil
}

func (endpoint *formalGLMPublicEndpointV1) Resolve(
	selectorFrame []byte,
) (formalGLMPublicResolveResponseV1, error) {
	var zero formalGLMPublicResolveResponseV1
	if endpoint == nil || endpoint.registry == nil {
		return zero, fmt.Errorf("formal-glm public endpoint: unavailable")
	}
	var selector formalGLMPublicSelectorV1
	if err := formalGLMPublicStrictCanonicalJSONV1(
		selectorFrame, formalGLMPublicMaxSelectorJSON, &selector); err != nil {
		return zero, err
	}
	if err := formalGLMValidatePublicSelectorV1(
		selector, endpoint.bridgeReceipts, endpoint.pins); err != nil {
		return zero, err
	}
	selectorSHA256, err := formalGLMPublicSelectorSHA256V1(selector)
	if err != nil {
		return zero, err
	}
	var resolution formalGLMArtifactRegistryResolutionV1
	var resolveErr error
	if len(endpoint.bridgeReceipts) == len(endpoint.pins) {
		resolution, resolveErr = endpoint.registry.Resolve(
			formalGLMArtifactRegistryQueryV1{
				BridgeReceipts: endpoint.bridgeReceipts,
				Family:         selector.Family, Formula: selector.CanonicalQualifiedFormula,
				FormalAnalysisID: selector.FormalAnalysisID,
			})
	} else {
		resolveErr = &formalGLMRegistryResolutionErrorV1{
			Code: "not_found", Matches: 0,
		}
	}
	state := formalGLMPublicResolveUnique
	var receiptResolution *formalGLMArtifactRegistryResolutionV1
	var provisionPayload *formalGLMPublicProvisionPayloadV1
	if resolveErr == nil {
		if err := formalGLMPublicSelectorMatchesResolutionV1(
			selector, resolution, endpoint.pins); err != nil {
			return zero, err
		}
		copy := resolution
		receiptResolution = &copy
	} else {
		var unavailable *formalGLMRegistryResolutionErrorV1
		if !errors.As(resolveErr, &unavailable) {
			return zero, resolveErr
		}
		switch unavailable.Code {
		case "not_found":
			state = formalGLMPublicResolveAbsent
			if endpoint.provisioner != nil {
				prepare, matched, prepareErr := endpoint.provisioner.Prepare(selector)
				if prepareErr != nil {
					return zero, prepareErr
				}
				if matched {
					if endpoint.localizeSamplerV2Prepare(&prepare) != nil ||
						formalGLMValidatePublicProvisionPrepareV1(
							prepare, endpoint.pins) != nil ||
						prepare.ModelApproval.Signer != endpoint.signerPeer ||
						(selector.FormalAnalysisID != "" &&
							!formalGLMPublicProvisionHasAliasV1(
								prepare.ServerOwnedAliases,
								selector.FormalAnalysisID)) ||
						formalGLMPublicSelectorMatchesDescriptorV1(
							selector, prepare.UnsignedDescriptor) != nil ||
						len(endpoint.bridgeReceipts) != 1 ||
						!reflect.DeepEqual(prepare.PSIReceipt,
							endpoint.bridgeReceipts[0]) {
						return zero, fmt.Errorf("formal-glm public endpoint: invalid local provision draft")
					}
					state = formalGLMPublicStateProvisionPrepare
					prepareCopy := prepare
					provisionPayload = &formalGLMPublicProvisionPayloadV1{
						Version: formalGLMPublicProvisionPayloadVersion,
						Stage:   formalGLMPublicStateProvisionPrepare,
						Prepare: &prepareCopy, ProductionReady: false,
					}
				}
			}
		case "ambiguous":
			state = formalGLMPublicResolveAmbiguous
		default:
			return zero, resolveErr
		}
	}
	receiptJSON, err := endpoint.signReceipt(formalGLMPublicReceiptFrameV1{
		State: state, SelectorSHA256: selectorSHA256,
		Provision: provisionPayload, Resolution: receiptResolution, Step: 0,
	})
	if err != nil {
		return zero, err
	}
	return formalGLMPublicResolveResponseV1{
		Version:          formalGLMPublicResolveResponseVersion,
		ReceiptFrameJSON: receiptJSON,
	}, nil
}

func formalGLMPublicValidateOpaquePeerFrameV1(encoded []byte) (string, error) {
	if len(encoded) == 0 {
		return "", nil
	}
	if len(encoded) > formalGLMPublicMaxPeerFrameJSON {
		return "", fmt.Errorf("formal-glm public endpoint: peer frame too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var opaque any
	if err := decoder.Decode(&opaque); err != nil {
		return "", fmt.Errorf("formal-glm public endpoint: invalid peer frame JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "", fmt.Errorf("formal-glm public endpoint: trailing peer frame JSON")
	}
	digest := sha256.Sum256(append(
		[]byte("dsVert/formal-glm/public-endpoint/peer-frame/v1|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func (endpoint *formalGLMPublicEndpointV1) Advance(
	receiptFrame []byte, peerFrameJSON []byte,
) (formalGLMPublicAdvanceResponseV1, error) {
	var zero formalGLMPublicAdvanceResponseV1
	if endpoint == nil {
		return zero, fmt.Errorf("formal-glm public endpoint: unavailable")
	}
	receipt, err := formalGLMValidatePublicEndpointReceiptV1(
		receiptFrame, endpoint.pins)
	if err != nil || receipt.SignerPeerName != endpoint.signerPeer ||
		(receipt.State != formalGLMPublicStateProvisionPrepare &&
			receipt.State != formalGLMPublicStateProvisionApprove &&
			receipt.State != formalGLMPublicResolveUnique &&
			receipt.State != formalGLMPublicStateRelay) {
		return zero, fmt.Errorf("formal-glm public endpoint: invalid advance receipt")
	}
	peerSHA256, err := formalGLMPublicValidateOpaquePeerFrameV1(peerFrameJSON)
	if err != nil {
		return zero, err
	}
	receiptSHA256 := formalGLMPublicReceiptSHA256V1(receiptFrame)
	if receipt.State == formalGLMPublicStateProvisionPrepare {
		if _, err := formalGLMPublicValidatePrepareBundleV1(
			peerFrameJSON, receipt.SelectorSHA256, endpoint.signerPeer,
			receiptSHA256, endpoint.pins); err != nil {
			return endpoint.provisionFailed(receipt, receiptSHA256, peerSHA256)
		}
	}
	if receipt.State == formalGLMPublicStateProvisionApprove {
		if _, err := formalGLMPublicValidateApproveBundleV1(
			peerFrameJSON, receipt.SelectorSHA256, endpoint.signerPeer,
			receiptSHA256, endpoint.pins); err != nil {
			return endpoint.provisionFailed(receipt, receiptSHA256, peerSHA256)
		}
	}
	cacheKey := receiptSHA256 + "\x00" + peerSHA256
	endpoint.advanceMu.Lock()
	defer endpoint.advanceMu.Unlock()
	if previousPeerSHA256, exists := endpoint.advanceInputs[receiptSHA256]; exists && previousPeerSHA256 != peerSHA256 {
		return zero, fmt.Errorf("formal-glm public endpoint: receipt already consumed")
	}
	if cached, exists := endpoint.advanceCache[cacheKey]; exists {
		cached.Replayed = true
		if cached.Relay != nil {
			relay := *cached.Relay
			cached.Relay = &relay
		}
		return cached, nil
	}
	endpoint.advanceInputs[receiptSHA256] = peerSHA256
	if receipt.State == formalGLMPublicStateProvisionPrepare ||
		receipt.State == formalGLMPublicStateProvisionApprove {
		response, advanceErr := endpoint.advanceProvision(
			receipt, receiptSHA256, peerSHA256, peerFrameJSON)
		if advanceErr == nil {
			endpoint.advanceCache[cacheKey] = response
		}
		return response, advanceErr
	}
	if endpoint.advance == nil || receipt.Resolution == nil {
		return zero, fmt.Errorf("formal-glm public endpoint: lifecycle driver unavailable")
	}
	observation, driverErr := endpoint.advance(formalGLMPublicAdvanceContextV1{
		Resolution: *receipt.Resolution, Receipt: receipt,
		ReceiptJSON:     append([]byte(nil), receiptFrame...),
		PeerFrameJSON:   append([]byte(nil), peerFrameJSON...),
		PeerFrameSHA256: peerSHA256,
	})
	state := formalGLMPublicStateFailed
	var relay *formalGLMPublicRelayV1
	var publication *formalGLMPhase21PublicCertificateV2
	if driverErr == nil && !observation.Failed {
		control := len(observation.ControlFrameJSON) != 0
		opening := len(observation.OpeningFrameJSON) != 0
		switch {
		case observation.Terminal != nil && !control && !opening &&
			observation.Binding == nil && observation.OpeningSender == "" &&
			observation.OpeningRecipient == "":
			validated, terminalErr := endpoint.validateTerminalObservation(
				*receipt.Resolution, *observation.Terminal)
			if terminalErr == nil {
				state = formalGLMPublicStateComplete
				publication = &validated
			}
		case observation.Terminal == nil && control != opening:
			validated, relayErr := endpoint.validateRelayObservation(
				*receipt.Resolution, observation)
			if relayErr == nil {
				state = formalGLMPublicStateRelay
				relay = &validated
			}
		}
	}
	nextJSON, signErr := endpoint.signReceipt(formalGLMPublicReceiptFrameV1{
		State: state, SelectorSHA256: receipt.SelectorSHA256,
		Resolution: receipt.Resolution, Step: receipt.Step + 1,
		PreviousReceiptSHA256: receiptSHA256,
		PeerFrameSHA256:       peerSHA256,
	})
	if signErr != nil {
		return zero, signErr
	}
	response := formalGLMPublicAdvanceResponseV1{
		Version: formalGLMPublicAdvanceResponseVersion,
		State:   state, ReceiptFrameJSON: nextJSON,
		Replayed: observation.Replayed,
	}
	if state == formalGLMPublicStateRelay {
		response.Relay = relay
		if len(observation.ControlFrameJSON) != 0 {
			response.PeerFrameJSON = string(observation.ControlFrameJSON)
		} else {
			response.PeerFrameJSON = string(observation.OpeningFrameJSON)
		}
		response.PeerFrameRecipient = relay.RecipientPeerName
	}
	if state == formalGLMPublicStateComplete {
		publicJSON, marshalErr := json.Marshal(*publication)
		certificateSHA256, digestErr := formalGLMPhase21RockPublicCertificateDigest(
			*publication)
		if marshalErr != nil || digestErr != nil {
			return zero, fmt.Errorf("formal-glm public endpoint: terminal encoding failed")
		}
		response.PublicV2JSON = string(publicJSON)
		response.CertificateSHA256 = certificateSHA256
	}
	endpoint.advanceCache[cacheKey] = response
	return response, nil
}

func (endpoint *formalGLMPublicEndpointV1) advanceProvision(
	receipt formalGLMPublicReceiptFrameV1,
	receiptSHA256, peerSHA256 string, peerFrameJSON []byte,
) (formalGLMPublicAdvanceResponseV1, error) {
	fail := func() (formalGLMPublicAdvanceResponseV1, error) {
		return endpoint.provisionFailed(receipt, receiptSHA256, peerSHA256)
	}
	if endpoint.provisioner == nil || len(peerFrameJSON) == 0 ||
		peerSHA256 == "" {
		return fail()
	}
	switch receipt.State {
	case formalGLMPublicStateProvisionPrepare:
		prepareSet, err := formalGLMPublicValidatePrepareBundleV1(
			peerFrameJSON, receipt.SelectorSHA256, endpoint.signerPeer,
			receiptSHA256, endpoint.pins)
		if err != nil {
			return fail()
		}
		draft, err := endpoint.provisioner.Approve(prepareSet)
		bridgeSHA256, bridgeErr := formalGLMPSISourceBridgeSetSHA256V1(
			prepareSet.Receipts, endpoint.pins)
		if err == nil && (bridgeErr != nil ||
			len(draft.UnsignedEntry.CustodianApprovals) != 0 ||
			!reflect.DeepEqual(draft.Descriptor, prepareSet.Descriptor) ||
			draft.UnsignedEntry.BridgeSetSHA256 != bridgeSHA256 ||
			!reflect.DeepEqual(draft.UnsignedEntry.FormalAnalysisIDs,
				prepareSet.Aliases)) {
			err = fmt.Errorf("formal-glm public endpoint: invalid provision draft")
		}
		var sourceCore formalGLMSourceContractCoreV1
		if err == nil {
			sourceCore, err = formalGLMBuildSourceContractCoreV1(
				draft.UnsignedEntry, prepareSet.Receipts,
				draft.RegisteredExecutionPlan,
				prepareSet.UnsignedSamplerV2Contract, endpoint.pins)
		}
		var sourceApproval jointDPBiomedicalGaussianSignature
		if err == nil {
			sourceApproval, err = endpoint.provisioner.SourceContractStore.Sign(
				sourceCore, endpoint.signerPeer, endpoint.signerKey)
		}
		var samplerApproval jointDPBiomedicalGaussianSignature
		if err == nil {
			samplerApproval, err = formalGLMPhase21SignSamplerV2Contract(
				prepareSet.UnsignedSamplerV2Contract,
				endpoint.signerPeer, endpoint.signerKey)
		}
		var entryApproval jointDPBiomedicalGaussianSignature
		if err == nil {
			entryApproval, err = formalGLMSignArtifactRegistryEntryV1(
				draft.UnsignedEntry, endpoint.signerPeer,
				endpoint.signerKey, endpoint.pins)
		}
		approve := formalGLMPublicProvisionApproveV1{
			Version:    formalGLMPublicProvisionApproveVersion,
			Purpose:    formalGLMPublicProvisionPurpose,
			Descriptor: draft.Descriptor, UnsignedEntry: draft.UnsignedEntry,
			EntryApproval:              entryApproval,
			UnsignedSamplerV2Contract:  prepareSet.UnsignedSamplerV2Contract,
			SamplerV2Approval:          samplerApproval,
			UnsignedSourceContractCore: sourceCore,
			SourceContractApproval:     sourceApproval,
			ProductionReady:            false,
		}
		if err != nil ||
			formalGLMValidatePublicProvisionApproveV1(
				approve, endpoint.pins) != nil ||
			approve.EntryApproval.Signer != endpoint.signerPeer ||
			!reflect.DeepEqual(approve.Descriptor, prepareSet.Descriptor) ||
			approve.UnsignedEntry.BridgeSetSHA256 != bridgeSHA256 ||
			!reflect.DeepEqual(approve.UnsignedEntry.FormalAnalysisIDs,
				prepareSet.Aliases) {
			return fail()
		}
		endpoint.bridgeReceipts = append(
			[]formalGLMPSISourceBridgeReceiptV1(nil), prepareSet.Receipts...)
		approveCopy := approve
		nextJSON, err := endpoint.signReceipt(formalGLMPublicReceiptFrameV1{
			State:          formalGLMPublicStateProvisionApprove,
			SelectorSHA256: receipt.SelectorSHA256,
			Provision: &formalGLMPublicProvisionPayloadV1{
				Version: formalGLMPublicProvisionPayloadVersion,
				Stage:   formalGLMPublicStateProvisionApprove,
				Approve: &approveCopy, ProductionReady: false,
			},
			Step:                  receipt.Step + 1,
			PreviousReceiptSHA256: receiptSHA256,
			PeerFrameSHA256:       peerSHA256,
		})
		if err != nil {
			return formalGLMPublicAdvanceResponseV1{}, err
		}
		return formalGLMPublicAdvanceResponseV1{
			Version:          formalGLMPublicAdvanceResponseVersion,
			State:            formalGLMPublicStateProvision,
			ReceiptFrameJSON: nextJSON,
		}, nil
	case formalGLMPublicStateProvisionApprove:
		approveSet, err := formalGLMPublicValidateApproveBundleV1(
			peerFrameJSON, receipt.SelectorSHA256, endpoint.signerPeer,
			receiptSHA256, endpoint.pins)
		if err != nil {
			return fail()
		}
		sourceReplayed, err := endpoint.provisioner.SourceContractStore.Commit(
			approveSet.SourceContract)
		if err != nil {
			return fail()
		}
		contractReplayed, err := endpoint.provisioner.SamplerV2ContractStore.Commit(
			approveSet.SamplerV2Contract)
		if err != nil {
			return fail()
		}
		entry := approveSet.Entry
		resolution, registryReplayed, err := endpoint.provisioner.Commit(entry)
		if err != nil ||
			formalGLMValidateSignedPublicDescriptorV1(
				resolution.Descriptor, endpoint.pins) != nil ||
			resolution.ArtifactID != entry.ArtifactID ||
			!reflect.DeepEqual(resolution.Descriptor, entry.Descriptor) {
			return fail()
		}
		resolutionCopy := resolution
		nextJSON, err := endpoint.signReceipt(formalGLMPublicReceiptFrameV1{
			State:          formalGLMPublicResolveUnique,
			SelectorSHA256: receipt.SelectorSHA256,
			Resolution:     &resolutionCopy, Step: receipt.Step + 1,
			PreviousReceiptSHA256: receiptSHA256,
			PeerFrameSHA256:       peerSHA256,
		})
		if err != nil {
			return formalGLMPublicAdvanceResponseV1{}, err
		}
		return formalGLMPublicAdvanceResponseV1{
			Version:          formalGLMPublicAdvanceResponseVersion,
			State:            formalGLMPublicStateProvision,
			ReceiptFrameJSON: nextJSON,
			Replayed:         sourceReplayed && contractReplayed && registryReplayed,
		}, nil
	default:
		return fail()
	}
}

func (endpoint *formalGLMPublicEndpointV1) provisionFailed(
	receipt formalGLMPublicReceiptFrameV1,
	receiptSHA256, peerSHA256 string,
) (formalGLMPublicAdvanceResponseV1, error) {
	nextJSON, err := endpoint.signReceipt(formalGLMPublicReceiptFrameV1{
		State:                 formalGLMPublicStateFailed,
		SelectorSHA256:        receipt.SelectorSHA256,
		Step:                  receipt.Step + 1,
		PreviousReceiptSHA256: receiptSHA256,
		PeerFrameSHA256:       peerSHA256,
	})
	if err != nil {
		return formalGLMPublicAdvanceResponseV1{}, err
	}
	return formalGLMPublicAdvanceResponseV1{
		Version:          formalGLMPublicAdvanceResponseVersion,
		State:            formalGLMPublicStateFailed,
		ReceiptFrameJSON: nextJSON,
	}, nil
}

func (endpoint *formalGLMPublicEndpointV1) failedAdvance(
	receipt formalGLMPublicReceiptFrameV1, receiptFrame []byte,
	peerSHA256 string,
) (formalGLMPublicAdvanceResponseV1, error) {
	nextJSON, err := endpoint.signReceipt(formalGLMPublicReceiptFrameV1{
		State:          formalGLMPublicStateFailed,
		SelectorSHA256: receipt.SelectorSHA256,
		Resolution:     receipt.Resolution, Step: receipt.Step + 1,
		PreviousReceiptSHA256: formalGLMPublicReceiptSHA256V1(receiptFrame),
		PeerFrameSHA256:       peerSHA256,
	})
	if err != nil {
		return formalGLMPublicAdvanceResponseV1{}, err
	}
	return formalGLMPublicAdvanceResponseV1{
		Version:          formalGLMPublicAdvanceResponseVersion,
		State:            formalGLMPublicStateFailed,
		ReceiptFrameJSON: nextJSON,
	}, nil
}

func (endpoint *formalGLMPublicEndpointV1) validateRelayObservation(
	resolution formalGLMArtifactRegistryResolutionV1,
	observation formalGLMPublicAdvanceObservationV1,
) (formalGLMPublicRelayV1, error) {
	var zero formalGLMPublicRelayV1
	control := len(observation.ControlFrameJSON) != 0
	opening := len(observation.OpeningFrameJSON) != 0
	if control == opening || observation.Binding == nil ||
		observation.Terminal != nil || observation.Failed ||
		formalFinalizerHandoffValidateBinding(
			*observation.Binding, endpoint.pins) != nil ||
		observation.Binding.ArtifactID != resolution.ArtifactID {
		return zero, fmt.Errorf("formal-glm public endpoint: invalid relay observation")
	}
	if control {
		if len(observation.ControlFrameJSON) > formalGLMPublicMaxPeerFrameJSON {
			return zero, fmt.Errorf("formal-glm public endpoint: control relay too large")
		}
		envelope, err := formalGLMControlDecodeEnvelope(
			observation.ControlFrameJSON)
		if err != nil || formalGLMControlValidateAAD(
			*observation.Binding, envelope.AAD) != nil ||
			envelope.Version != formalGLMControlEnvelopeVersion ||
			envelope.Protocol != formalGLMOneDrawControlProtocol ||
			envelope.ProductionReady ||
			!formalGLMIsSHA256(envelope.RecordSHA256) ||
			!formalGLMIsSHA256(envelope.RecipientTransportKeySHA256) ||
			envelope.CiphertextSHA256 != formalGLMControlSHA(
				formalGLMControlCipherDomain, envelope.Ciphertext) {
			return zero, fmt.Errorf("formal-glm public endpoint: invalid control relay")
		}
		return formalGLMPublicRelayV1{
			Channel:           formalGLMPublicRelayControl,
			SenderPeerName:    envelope.AAD.SenderPeerName,
			RecipientPeerName: envelope.AAD.RecipientPeerName,
		}, nil
	}
	if _, err := formalGLMPublicValidateOpaquePeerFrameV1(
		observation.OpeningFrameJSON); err != nil ||
		!formalGLMRegistryLabelV1(observation.OpeningSender, 128) ||
		!formalGLMRegistryLabelV1(observation.OpeningRecipient, 128) ||
		observation.OpeningSender == observation.OpeningRecipient ||
		!formalFinalizerHandoffBindingHasPeerName(
			*observation.Binding, observation.OpeningSender) ||
		!formalFinalizerHandoffBindingHasPeerName(
			*observation.Binding, observation.OpeningRecipient) {
		return zero, fmt.Errorf("formal-glm public endpoint: invalid opening relay")
	}
	return formalGLMPublicRelayV1{
		Channel:           formalGLMPublicRelayOpening,
		SenderPeerName:    observation.OpeningSender,
		RecipientPeerName: observation.OpeningRecipient,
	}, nil
}

func formalFinalizerHandoffBindingHasPeerName(
	binding formalFinalizerHandoffBinding, peer string,
) bool {
	for _, authority := range binding.Authorities {
		if authority.PeerName == peer {
			return true
		}
	}
	return false
}

func (endpoint *formalGLMPublicEndpointV1) validateTerminalObservation(
	resolution formalGLMArtifactRegistryResolutionV1,
	terminal formalGLMPublicTerminalEvidenceV1,
) (formalGLMPhase21PublicCertificateV2, error) {
	var zero formalGLMPhase21PublicCertificateV2
	context := formalGLMPhase21RockContext{
		contract: terminal.Contract, pins: endpoint.pins,
		artifactID: resolution.ArtifactID,
	}
	certificateSHA256, certificateErr := formalGLMPhase21RockPublicCertificateDigest(
		terminal.Publication)
	if certificateErr != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(
			terminal.Contract, endpoint.pins) != nil ||
		terminal.Contract.ArtifactID != resolution.ArtifactID ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			resolution.Descriptor, terminal.Contract.Artifact) != nil ||
		formalFinalizerHandoffValidateBinding(
			terminal.Binding, endpoint.pins) != nil ||
		terminal.Binding.ArtifactID != resolution.ArtifactID ||
		formalFinalizerHandoffValidateTicket(
			terminal.Ticket, terminal.Binding, endpoint.pins) != nil ||
		formalGLMPhase21ValidatePublicCertificateV2(
			terminal.Publication, endpoint.pins) != nil ||
		terminal.Publication.ArtifactID != resolution.ArtifactID ||
		terminal.Publication.PublicDescriptor == nil ||
		!reflect.DeepEqual(*terminal.Publication.PublicDescriptor,
			resolution.Descriptor) {
		return zero, fmt.Errorf("formal-glm public endpoint: invalid terminal evidence")
	}
	for index, authority := range terminal.Contract.Artifact.NoiseAuthorities {
		local := formalFinalizerHandoffAuthority{
			PeerName: authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role,
		}
		if formalGLMPhase21RockValidateCommitRecord(
			terminal.Commits[index], context, local) != nil ||
			terminal.Commits[index].Receipt.CertificateSHA256 != certificateSHA256 ||
			!reflect.DeepEqual(terminal.Commits[index].Publication,
				terminal.Publication) {
			return zero, fmt.Errorf("formal-glm public endpoint: invalid dual commit")
		}
		if formalGLMPhase21RockValidateCleanupRecord(
			terminal.Cleanups[index], context, local) != nil ||
			terminal.Cleanups[index].Receipt.CertificateSHA256 != certificateSHA256 ||
			!reflect.DeepEqual(terminal.Cleanups[index].Publication,
				terminal.Publication) {
			return zero, fmt.Errorf("formal-glm public endpoint: invalid dual cleanup")
		}
	}
	if formalGLMPhase21RockValidateAckRecord(
		terminal.Ack, context, terminal.Binding, terminal.Ticket,
		certificateSHA256) != nil {
		return zero, fmt.Errorf("formal-glm public endpoint: invalid terminal ACK")
	}
	publication := terminal.Publication
	return publication, nil
}
