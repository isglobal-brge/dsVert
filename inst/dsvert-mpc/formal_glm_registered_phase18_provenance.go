package main

import (
	"bytes"
	"crypto/ecdh"
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
	formalGLMRegisteredPhase18RecipientTicketVersion = "dsvert-formal-glm-registered-phase18-recipient-ticket-v1"
	formalGLMRegisteredPhase18RecipientTicketPurpose = "formal_glm_registered_source_contract_recipient_key_v1"
	formalGLMRegisteredPhase18RecipientTicketDomain  = "dsVert/formal-glm/registered-phase18/recipient-ticket/v1"

	formalGLMRegisteredPhase18SourceEnvelopeVersion = "dsvert-formal-glm-registered-phase18-source-envelope-v1"
	formalGLMRegisteredPhase18SourceEnvelopePurpose = "formal_glm_registered_encrypted_source_block_v1"
	formalGLMRegisteredPhase18SourceEnvelopeDomain  = "dsVert/formal-glm/registered-phase18/source-envelope/v1"

	formalGLMRegisteredPhase18BlockPairVersion = "dsvert-formal-glm-registered-phase18-block-pair-v1"
	formalGLMRegisteredPhase18BlockPairPurpose = "formal_glm_registered_encrypted_source_block_pair_v1"
	formalGLMRegisteredPhase18PairDomain       = "dsVert/formal-glm/registered-phase18/encrypted-pair/v1"
	formalGLMRegisteredPhase18BlockDomain      = "dsVert/formal-glm/registered-phase18/block-commitment/v1"

	formalGLMRegisteredPhase18LocalReceiptVersion = "dsvert-formal-glm-registered-phase18-local-receipt-v1"
	formalGLMRegisteredPhase18LocalReceiptPhase   = "registered_local_materialization_committed"
	formalGLMRegisteredPhase18LocalReceiptPurpose = "formal_glm_registered_local_materialization_receipt_v1"
	formalGLMRegisteredPhase18LocalReceiptDomain  = "dsVert/formal-glm/registered-phase18/local-receipt/v1"

	formalGLMRegisteredPhase18ReceiptSetVersion = "dsvert-formal-glm-registered-phase18-receipt-set-v1"
	formalGLMRegisteredPhase18ReceiptSetPurpose = "formal_glm_registered_k_materialization_root_v1"
	formalGLMRegisteredPhase18ReceiptSetDomain  = "dsVert/formal-glm/registered-phase18/receipt-set/v1"

	formalGLMRegisteredPhase18TicketMaxJSON       = 64 << 10
	formalGLMRegisteredPhase18BlockPairMaxJSON    = 8 << 20
	formalGLMRegisteredPhase18LocalReceiptMaxJSON = 8 << 20
	formalGLMRegisteredPhase18ReceiptSetMaxJSON   = 32 << 20
)

type formalGLMRegisteredPhase18RecipientTicketV1 struct {
	Version                       string   `json:"version"`
	Purpose                       string   `json:"purpose"`
	ArtifactID                    string   `json:"artifact_id"`
	SourceContractCoreSHA256      string   `json:"source_contract_core_sha256"`
	SourceContractSHA256          string   `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string   `json:"registered_execution_plan_sha256"`
	PinsetSHA256                  string   `json:"pinset_sha256"`
	RecipientName                 string   `json:"recipient_name"`
	RecipientIdentityPK           string   `json:"recipient_identity_pk"`
	TransportPKSHA256             string   `json:"transport_pk_sha256"`
	TransportPK                   []byte   `json:"transport_pk"`
	DesignatedComputePeers        []string `json:"designated_compute_peers"`
	TotalCapacity                 int      `json:"total_capacity"`
	BlockCapacity                 int      `json:"block_capacity"`
	TotalBlocks                   int      `json:"total_blocks"`
	CoordinateCount               int      `json:"coordinate_count"`
	RingBits                      int      `json:"ring_bits"`
	RecordBytes                   int      `json:"record_bytes"`
	Persistent                    bool     `json:"persistent"`
	OpeningsPerformed             int      `json:"openings_performed"`
	ProductionReady               bool     `json:"production_ready"`
	Signature                     []byte   `json:"signature"`
}

type formalGLMRegisteredPhase18SourceEnvelopeV1 struct {
	Version                              string `json:"version"`
	Purpose                              string `json:"purpose"`
	ArtifactID                           string `json:"artifact_id"`
	SourceContractCoreSHA256             string `json:"source_contract_core_sha256"`
	SourceContractSHA256                 string `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256        string `json:"registered_execution_plan_sha256"`
	RegisteredPhase18AuthorizationSHA256 string `json:"registered_phase18_authorization_sha256"`
	SourceName                           string `json:"source_name"`
	SourceIdentityPK                     string `json:"source_identity_pk"`
	RecipientName                        string `json:"recipient_name"`
	RecipientTicketSHA256                string `json:"recipient_ticket_sha256"`
	BlockIndex                           int    `json:"block_index"`
	TotalBlocks                          int    `json:"total_blocks"`
	GlobalSlotOffset                     int    `json:"global_slot_offset"`
	SlotsInBlock                         int    `json:"slots_in_block"`
	CoordinateCount                      int    `json:"coordinate_count"`
	CoordinateRecords                    int    `json:"coordinate_records"`
	RingBits                             int    `json:"ring_bits"`
	RecordBytes                          int    `json:"record_bytes"`
	ValidityRecords                      int    `json:"validity_records"`
	PairCommitmentSHA256                 string `json:"pair_commitment_sha256"`
	CiphertextSHA256                     string `json:"ciphertext_sha256"`
	CiphertextBytes                      int    `json:"ciphertext_bytes"`
	Ciphertext                           []byte `json:"ciphertext"`
	OpeningsPerformed                    int    `json:"openings_performed"`
	ProductionReady                      bool   `json:"production_ready"`
	Signature                            []byte `json:"signature"`
}

type formalGLMRegisteredPhase18BlockPairV1 struct {
	Version                              string                                       `json:"version"`
	Purpose                              string                                       `json:"purpose"`
	ArtifactID                           string                                       `json:"artifact_id"`
	SourceContractCoreSHA256             string                                       `json:"source_contract_core_sha256"`
	SourceContractSHA256                 string                                       `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256        string                                       `json:"registered_execution_plan_sha256"`
	RegisteredPhase18AuthorizationSHA256 string                                       `json:"registered_phase18_authorization_sha256"`
	SourceName                           string                                       `json:"source_name"`
	SourceIdentityPK                     string                                       `json:"source_identity_pk"`
	Recipients                           []string                                     `json:"recipients"`
	BlockIndex                           int                                          `json:"block_index"`
	TotalBlocks                          int                                          `json:"total_blocks"`
	GlobalSlotOffset                     int                                          `json:"global_slot_offset"`
	SlotsInBlock                         int                                          `json:"slots_in_block"`
	CoordinateCount                      int                                          `json:"coordinate_count"`
	CoordinateRecords                    int                                          `json:"coordinate_records"`
	RingBits                             int                                          `json:"ring_bits"`
	RecordBytes                          int                                          `json:"record_bytes"`
	ValidityRecords                      int                                          `json:"validity_records"`
	PairCommitmentSHA256                 string                                       `json:"pair_commitment_sha256"`
	BlockCommitmentSHA256                string                                       `json:"block_commitment_sha256"`
	Envelopes                            []formalGLMRegisteredPhase18SourceEnvelopeV1 `json:"envelopes"`
	OpeningsPerformed                    int                                          `json:"openings_performed"`
	ProductionReady                      bool                                         `json:"production_ready"`
}

type formalGLMRegisteredPhase18BlockCommitmentV1 struct {
	BlockIndex            int    `json:"block_index"`
	PairCommitmentSHA256  string `json:"pair_commitment_sha256"`
	BlockCommitmentSHA256 string `json:"block_commitment_sha256"`
}

type formalGLMRegisteredPhase18LocalReceiptV1 struct {
	Version                              string                                        `json:"version"`
	Phase                                string                                        `json:"phase"`
	Purpose                              string                                        `json:"purpose"`
	ArtifactID                           string                                        `json:"artifact_id"`
	SourceContractCoreSHA256             string                                        `json:"source_contract_core_sha256"`
	SourceContractSHA256                 string                                        `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256        string                                        `json:"registered_execution_plan_sha256"`
	RegisteredPhase18AuthorizationSHA256 string                                        `json:"registered_phase18_authorization_sha256"`
	SourceName                           string                                        `json:"source_name"`
	SourceIdentityPK                     string                                        `json:"source_identity_pk"`
	PinsetSHA256                         string                                        `json:"pinset_sha256"`
	TotalCapacity                        int                                           `json:"total_capacity"`
	BlockCapacity                        int                                           `json:"block_capacity"`
	TotalBlocks                          int                                           `json:"total_blocks"`
	CoordinateCount                      int                                           `json:"coordinate_count"`
	RingBits                             int                                           `json:"ring_bits"`
	RecordBytes                          int                                           `json:"record_bytes"`
	ValiditySharing                      string                                        `json:"validity_sharing"`
	AlignmentSharing                     string                                        `json:"alignment_sharing"`
	CoordinateEncoding                   string                                        `json:"coordinate_encoding"`
	BlockCommitments                     []formalGLMRegisteredPhase18BlockCommitmentV1 `json:"block_commitments"`
	LocalMaterializationRootSHA256       string                                        `json:"local_materialization_root_sha256"`
	Phase19RequiredOperation             string                                        `json:"phase19_required_operation"`
	OpeningsPerformed                    int                                           `json:"openings_performed"`
	ProductionReady                      bool                                          `json:"production_ready"`
	Signature                            []byte                                        `json:"signature"`
}

type formalGLMRegisteredPhase18ReceiptSetV1 struct {
	Version                         string                                     `json:"version"`
	Purpose                         string                                     `json:"purpose"`
	ArtifactID                      string                                     `json:"artifact_id"`
	SourceContractCoreSHA256        string                                     `json:"source_contract_core_sha256"`
	SourceContractSHA256            string                                     `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256   string                                     `json:"registered_execution_plan_sha256"`
	PinsetSHA256                    string                                     `json:"pinset_sha256"`
	Receipts                        []formalGLMRegisteredPhase18LocalReceiptV1 `json:"receipts"`
	ReceiptSetSHA256                string                                     `json:"receipt_set_sha256"`
	GlobalMaterializationRootSHA256 string                                     `json:"global_materialization_root_sha256"`
	OpeningsPerformed               int                                        `json:"openings_performed"`
	ProductionReady                 bool                                       `json:"production_ready"`
}

func formalGLMRegisteredPhase18SignatureMessageV1(domain string, value any) (
	[]byte, error,
) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain+"|"), encoded...), nil
}

func formalGLMRegisteredPhase18ContractSHA256V1(
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (string, error) {
	if err := formalGLMValidateSourceContractV1(contract, pins); err != nil {
		return "", err
	}
	return formalGLMSourceContractSHA256V1(contract)
}

type formalGLMRegisteredPhase18ProvenanceContextV1 struct {
	contract       formalGLMSourceContractV1
	contractSHA256 string
	pins           map[string]ed25519.PublicKey
}

func formalGLMRegisteredPhase18NewProvenanceContextV1(
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18ProvenanceContextV1, error) {
	contractSHA256, err := formalGLMRegisteredPhase18ContractSHA256V1(
		contract, pins)
	if err != nil {
		return formalGLMRegisteredPhase18ProvenanceContextV1{}, err
	}
	return formalGLMRegisteredPhase18ProvenanceContextV1{
		contract: contract, contractSHA256: contractSHA256, pins: pins,
	}, nil
}

func formalGLMRegisteredPhase18ValidateAuthorizationWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
) error {
	expected, err := formalGLMProjectRegisteredPhase18AuthorizationV1(
		context.contract, authorization.LocalSource.SignerPeerName, context.pins)
	if err != nil {
		return err
	}
	expected.AuthorizationSHA256, err =
		formalGLMRegisteredPhase18AuthorizationSHA256V1(expected)
	if err != nil || !reflect.DeepEqual(authorization, expected) {
		return fmt.Errorf("formal-glm: registered Phase18 authorization differs from source contract")
	}
	return nil
}

func formalGLMRegisteredPhase18TransportPKV1(publicKey []byte) (string, error) {
	if len(publicKey) != 32 || bytes.Equal(publicKey, make([]byte, 32)) {
		return "", fmt.Errorf("formal-glm: invalid registered Phase18 transport key")
	}
	if _, err := ecdh.X25519().NewPublicKey(publicKey); err != nil {
		return "", fmt.Errorf("formal-glm: invalid registered Phase18 transport key")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18RecipientTicketDomain+"/transport-pk",
		append([]byte(nil), publicKey...))
}

func formalGLMRegisteredPhase18ProjectRecipientTicketV1(
	contract formalGLMSourceContractV1,
	recipient string,
	transportPK []byte,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18RecipientTicketV1, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return formalGLMRegisteredPhase18RecipientTicketV1{}, err
	}
	return formalGLMRegisteredPhase18ProjectRecipientTicketWithContextV1(
		context, recipient, transportPK)
}

func formalGLMRegisteredPhase18ProjectRecipientTicketWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	recipient string,
	transportPK []byte,
) (formalGLMRegisteredPhase18RecipientTicketV1, error) {
	var zero formalGLMRegisteredPhase18RecipientTicketV1
	contract := context.contract
	plan := contract.Core.RegisteredExecutionPlan
	recipientIndex := -1
	for index, peer := range plan.DesignatedComputePeers {
		if peer == recipient {
			recipientIndex = index
		}
	}
	transportSHA256, err := formalGLMRegisteredPhase18TransportPKV1(transportPK)
	if err != nil || recipientIndex < 0 ||
		len(context.pins[recipient]) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("formal-glm: invalid registered Phase18 recipient")
	}
	return formalGLMRegisteredPhase18RecipientTicketV1{
		Version:                       formalGLMRegisteredPhase18RecipientTicketVersion,
		Purpose:                       formalGLMRegisteredPhase18RecipientTicketPurpose,
		ArtifactID:                    contract.Core.ArtifactID,
		SourceContractCoreSHA256:      contract.CoreSHA256,
		SourceContractSHA256:          context.contractSHA256,
		RegisteredExecutionPlanSHA256: plan.PlanSHA256,
		PinsetSHA256:                  plan.PinsetSHA256,
		RecipientName:                 recipient,
		RecipientIdentityPK: formalGLMIdentityPKV1(
			context.pins[recipient]),
		TransportPKSHA256:      transportSHA256,
		TransportPK:            append([]byte(nil), transportPK...),
		DesignatedComputePeers: append([]string(nil), plan.DesignatedComputePeers...),
		TotalCapacity:          plan.TotalCapacity,
		BlockCapacity:          plan.BlockCapacity,
		TotalBlocks:            plan.TotalBlocks,
		CoordinateCount:        plan.ExecutionKernel.CoefficientCount + 3,
		RingBits:               plan.RingBits,
		RecordBytes:            exactGCRecordBytes(plan.RingBits),
		Persistent:             true,
		OpeningsPerformed:      0,
		ProductionReady:        false,
		Signature:              nil,
	}, nil
}

func formalGLMRegisteredPhase18BuildRecipientTicketV1(
	contract formalGLMSourceContractV1,
	recipient string,
	transportPK []byte,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18RecipientTicketV1, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return formalGLMRegisteredPhase18RecipientTicketV1{}, err
	}
	ticket, err := formalGLMRegisteredPhase18ProjectRecipientTicketWithContextV1(
		context, recipient, transportPK)
	if err != nil {
		return formalGLMRegisteredPhase18RecipientTicketV1{}, err
	}
	if err := formalGLMRegisteredPhase18ValidateRecipientTicketCoreWithContextV1(
		context, ticket); err != nil {
		return formalGLMRegisteredPhase18RecipientTicketV1{}, err
	}
	return ticket, nil
}

func formalGLMRegisteredPhase18ValidateRecipientTicketCoreV1(
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateRecipientTicketCoreWithContextV1(
		context, ticket)
}

func formalGLMRegisteredPhase18ValidateRecipientTicketCoreWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
) error {
	if len(ticket.Signature) != 0 || ticket.OpeningsPerformed != 0 ||
		ticket.ProductionReady || !ticket.Persistent {
		return fmt.Errorf("formal-glm: invalid unsigned registered Phase18 ticket")
	}
	expected, err := formalGLMRegisteredPhase18ProjectRecipientTicketWithContextV1(
		context, ticket.RecipientName, ticket.TransportPK)
	if err != nil || !reflect.DeepEqual(ticket, expected) {
		return fmt.Errorf("formal-glm: registered Phase18 ticket differs from source contract")
	}
	return nil
}

func formalGLMRegisteredPhase18SignRecipientTicketV1(
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	contract formalGLMSourceContractV1,
	privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18RecipientTicketV1, error) {
	if err := formalGLMRegisteredPhase18ValidateRecipientTicketCoreV1(
		ticket, contract, pins); err != nil {
		return formalGLMRegisteredPhase18RecipientTicketV1{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize ||
		len(pins[ticket.RecipientName]) != ed25519.PublicKeySize ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey),
			pins[ticket.RecipientName]) {
		return formalGLMRegisteredPhase18RecipientTicketV1{},
			fmt.Errorf("formal-glm: invalid registered Phase18 ticket signer")
	}
	unsigned := ticket
	if len(unsigned.Signature) != 0 {
		return formalGLMRegisteredPhase18RecipientTicketV1{},
			fmt.Errorf("formal-glm: registered Phase18 ticket is already signed")
	}
	message, err := formalGLMRegisteredPhase18SignatureMessageV1(
		formalGLMRegisteredPhase18RecipientTicketDomain, unsigned)
	if err != nil {
		return formalGLMRegisteredPhase18RecipientTicketV1{}, err
	}
	ticket.Signature = ed25519.Sign(privateKey, message)
	return ticket, nil
}

func formalGLMRegisteredPhase18ValidateRecipientTicketV1(
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateRecipientTicketWithContextV1(
		context, ticket)
}

func formalGLMRegisteredPhase18ValidateRecipientTicketWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
) error {
	if len(ticket.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("formal-glm: invalid registered Phase18 ticket signature")
	}
	unsigned := ticket
	unsigned.Signature = nil
	if err := formalGLMRegisteredPhase18ValidateRecipientTicketCoreWithContextV1(
		context, unsigned); err != nil {
		return err
	}
	message, err := formalGLMRegisteredPhase18SignatureMessageV1(
		formalGLMRegisteredPhase18RecipientTicketDomain, unsigned)
	if err != nil || !ed25519.Verify(
		context.pins[ticket.RecipientName], message, ticket.Signature) {
		return fmt.Errorf("formal-glm: invalid registered Phase18 ticket signature")
	}
	return nil
}

func formalGLMRegisteredPhase18RecipientTicketSHA256V1(
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
) (string, error) {
	if ticket.Version != formalGLMRegisteredPhase18RecipientTicketVersion ||
		ticket.Purpose != formalGLMRegisteredPhase18RecipientTicketPurpose ||
		len(ticket.Signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("formal-glm: invalid registered Phase18 ticket hash input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18RecipientTicketDomain+"/signed", ticket)
}

func formalGLMRegisteredPhase18CanonicalTicketsV1(
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) ([]formalGLMRegisteredPhase18RecipientTicketV1, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return nil, err
	}
	return formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(
		context, tickets)
}

func formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) ([]formalGLMRegisteredPhase18RecipientTicketV1, error) {
	designated := context.contract.Core.RegisteredExecutionPlan.DesignatedComputePeers
	if len(designated) != 2 || len(tickets) != 2 {
		return nil, fmt.Errorf("formal-glm: registered Phase18 requires two recipient tickets")
	}
	byRecipient := make(map[string]formalGLMRegisteredPhase18RecipientTicketV1, 2)
	for _, ticket := range tickets {
		if err := formalGLMRegisteredPhase18ValidateRecipientTicketWithContextV1(
			context, ticket); err != nil {
			return nil, err
		}
		if _, exists := byRecipient[ticket.RecipientName]; exists {
			return nil, fmt.Errorf("formal-glm: duplicate registered Phase18 recipient ticket")
		}
		byRecipient[ticket.RecipientName] = ticket
	}
	ordered := make([]formalGLMRegisteredPhase18RecipientTicketV1, 2)
	for index, recipient := range designated {
		ticket, ok := byRecipient[recipient]
		if !ok {
			return nil, fmt.Errorf("formal-glm: incomplete registered Phase18 recipient tickets")
		}
		ordered[index] = ticket
	}
	return ordered, nil
}

type formalGLMRegisteredPhase18CiphertextCommitmentV1 struct {
	RecipientName         string `json:"recipient_name"`
	RecipientTicketSHA256 string `json:"recipient_ticket_sha256"`
	CiphertextSHA256      string `json:"ciphertext_sha256"`
	CiphertextBytes       int    `json:"ciphertext_bytes"`
}

type formalGLMRegisteredPhase18PairCommitmentInputV1 struct {
	Version                              string                                             `json:"version"`
	Purpose                              string                                             `json:"purpose"`
	ArtifactID                           string                                             `json:"artifact_id"`
	SourceContractCoreSHA256             string                                             `json:"source_contract_core_sha256"`
	SourceContractSHA256                 string                                             `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256        string                                             `json:"registered_execution_plan_sha256"`
	RegisteredPhase18AuthorizationSHA256 string                                             `json:"registered_phase18_authorization_sha256"`
	SourceName                           string                                             `json:"source_name"`
	BlockIndex                           int                                                `json:"block_index"`
	Recipients                           []formalGLMRegisteredPhase18CiphertextCommitmentV1 `json:"recipients"`
}

type formalGLMRegisteredPhase18EnvelopeCommitmentV1 struct {
	RecipientName  string `json:"recipient_name"`
	EnvelopeSHA256 string `json:"envelope_sha256"`
}

type formalGLMRegisteredPhase18BlockCommitmentInputV1 struct {
	Version                              string                                           `json:"version"`
	Purpose                              string                                           `json:"purpose"`
	ArtifactID                           string                                           `json:"artifact_id"`
	SourceContractCoreSHA256             string                                           `json:"source_contract_core_sha256"`
	SourceContractSHA256                 string                                           `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256        string                                           `json:"registered_execution_plan_sha256"`
	RegisteredPhase18AuthorizationSHA256 string                                           `json:"registered_phase18_authorization_sha256"`
	SourceName                           string                                           `json:"source_name"`
	BlockIndex                           int                                              `json:"block_index"`
	PairCommitmentSHA256                 string                                           `json:"pair_commitment_sha256"`
	Envelopes                            []formalGLMRegisteredPhase18EnvelopeCommitmentV1 `json:"envelopes"`
}

func formalGLMRegisteredPhase18CiphertextSizeV1(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
	ciphertext []byte,
) error {
	_, slots, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, blockIndex)
	if err != nil {
		return err
	}
	shareBytes := slots*authorization.Geometry.CoordinateCount*
		authorization.Geometry.RecordBytes + slots
	minimum := formalGLMRegisteredPhase18TransportOverheadV3 + 4 + 2 + shareBytes
	maximum := formalGLMRegisteredPhase18TransportOverheadV3 + 4 +
		formalGLMRegisteredPhase18MaxPrivateHeaderV3 + shareBytes
	if len(ciphertext) < minimum || len(ciphertext) > maximum ||
		len(ciphertext)+4096 > formalGLMRegisteredPhase18MaxIngressFrameV3 {
		return fmt.Errorf("formal-glm: registered Phase18 ciphertext is outside its fixed bound")
	}
	return nil
}

func formalGLMRegisteredPhase18PairCommitmentV1(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	ciphertexts map[string][]byte,
	pins map[string]ed25519.PublicKey,
) (string, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return "", err
	}
	return formalGLMRegisteredPhase18PairCommitmentWithContextV1(
		context, authorization, tickets, blockIndex, ciphertexts)
}

func formalGLMRegisteredPhase18PairCommitmentWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	ciphertexts map[string][]byte,
) (string, error) {
	if err := formalGLMRegisteredPhase18ValidateAuthorizationWithContextV1(
		context, authorization); err != nil {
		return "", err
	}
	orderedTickets, err := formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(
		context, tickets)
	if err != nil || len(ciphertexts) != 2 {
		return "", fmt.Errorf("formal-glm: incomplete registered Phase18 ciphertext pair")
	}
	recipients := make(
		[]formalGLMRegisteredPhase18CiphertextCommitmentV1, 2)
	for index, ticket := range orderedTickets {
		ciphertext, ok := ciphertexts[ticket.RecipientName]
		if !ok || formalGLMRegisteredPhase18CiphertextSizeV1(
			authorization, blockIndex, ciphertext) != nil {
			return "", fmt.Errorf("formal-glm: incomplete registered Phase18 ciphertext pair")
		}
		ticketSHA256, hashErr :=
			formalGLMRegisteredPhase18RecipientTicketSHA256V1(ticket)
		if hashErr != nil {
			return "", hashErr
		}
		digest := sha256.Sum256(ciphertext)
		recipients[index] = formalGLMRegisteredPhase18CiphertextCommitmentV1{
			RecipientName:         ticket.RecipientName,
			RecipientTicketSHA256: ticketSHA256,
			CiphertextSHA256:      hex.EncodeToString(digest[:]),
			CiphertextBytes:       len(ciphertext),
		}
	}
	for recipient := range ciphertexts {
		if recipient != orderedTickets[0].RecipientName &&
			recipient != orderedTickets[1].RecipientName {
			return "", fmt.Errorf("formal-glm: unexpected registered Phase18 ciphertext recipient")
		}
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18PairDomain,
		formalGLMRegisteredPhase18PairCommitmentInputV1{
			Version:                              formalGLMRegisteredPhase18BlockPairVersion,
			Purpose:                              formalGLMRegisteredPhase18BlockPairPurpose,
			ArtifactID:                           authorization.ArtifactID,
			SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
			SourceContractSHA256:                 authorization.SourceContractSHA256,
			RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
			RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
			SourceName:                           authorization.LocalSource.SignerPeerName,
			BlockIndex:                           blockIndex,
			Recipients:                           recipients,
		})
}

func formalGLMRegisteredPhase18ProjectSourceEnvelopeV1(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	pairCommitment string,
	ciphertext []byte,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18SourceEnvelopeV1, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return formalGLMRegisteredPhase18SourceEnvelopeV1{}, err
	}
	return formalGLMRegisteredPhase18ProjectSourceEnvelopeWithContextV1(
		context, authorization, ticket, blockIndex, pairCommitment, ciphertext)
}

func formalGLMRegisteredPhase18ProjectSourceEnvelopeWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	pairCommitment string,
	ciphertext []byte,
) (formalGLMRegisteredPhase18SourceEnvelopeV1, error) {
	var zero formalGLMRegisteredPhase18SourceEnvelopeV1
	if err := formalGLMRegisteredPhase18ValidateAuthorizationWithContextV1(
		context, authorization); err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase18ValidateRecipientTicketWithContextV1(
		context, ticket); err != nil {
		return zero, err
	}
	if !formalGLMIsSHA256(pairCommitment) ||
		formalGLMRegisteredPhase18CiphertextSizeV1(
			authorization, blockIndex, ciphertext) != nil {
		return zero, fmt.Errorf("formal-glm: invalid registered Phase18 source ciphertext")
	}
	recipientIndex := -1
	for index, recipient := range authorization.DesignatedComputePeers {
		if recipient == ticket.RecipientName {
			recipientIndex = index
		}
	}
	if recipientIndex < 0 {
		return zero, fmt.Errorf("formal-glm: registered Phase18 envelope recipient differs")
	}
	offset, slots, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, blockIndex)
	if err != nil {
		return zero, err
	}
	ticketSHA256, err :=
		formalGLMRegisteredPhase18RecipientTicketSHA256V1(ticket)
	if err != nil {
		return zero, err
	}
	digest := sha256.Sum256(ciphertext)
	return formalGLMRegisteredPhase18SourceEnvelopeV1{
		Version:                              formalGLMRegisteredPhase18SourceEnvelopeVersion,
		Purpose:                              formalGLMRegisteredPhase18SourceEnvelopePurpose,
		ArtifactID:                           authorization.ArtifactID,
		SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
		SourceContractSHA256:                 authorization.SourceContractSHA256,
		RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
		RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
		SourceName:                           authorization.LocalSource.SignerPeerName,
		SourceIdentityPK:                     authorization.LocalPeerIdentity.IdentityPK,
		RecipientName:                        ticket.RecipientName,
		RecipientTicketSHA256:                ticketSHA256,
		BlockIndex:                           blockIndex,
		TotalBlocks:                          authorization.Geometry.TotalBlocks,
		GlobalSlotOffset:                     offset,
		SlotsInBlock:                         slots,
		CoordinateCount:                      authorization.Geometry.CoordinateCount,
		CoordinateRecords:                    slots * authorization.Geometry.CoordinateCount,
		RingBits:                             authorization.Geometry.RingBits,
		RecordBytes:                          authorization.Geometry.RecordBytes,
		ValidityRecords:                      slots,
		PairCommitmentSHA256:                 pairCommitment,
		CiphertextSHA256:                     hex.EncodeToString(digest[:]),
		CiphertextBytes:                      len(ciphertext),
		Ciphertext:                           append([]byte(nil), ciphertext...),
		OpeningsPerformed:                    0,
		ProductionReady:                      false,
		Signature:                            nil,
	}, nil
}

func formalGLMRegisteredPhase18ValidateSourceEnvelopeCoreV1(
	envelope formalGLMRegisteredPhase18SourceEnvelopeV1,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	pairCommitment string,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateSourceEnvelopeCoreWithContextV1(
		context, envelope, authorization, ticket, pairCommitment)
}

func formalGLMRegisteredPhase18ValidateSourceEnvelopeCoreWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	envelope formalGLMRegisteredPhase18SourceEnvelopeV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	pairCommitment string,
) error {
	if len(envelope.Signature) != 0 || envelope.OpeningsPerformed != 0 ||
		envelope.ProductionReady {
		return fmt.Errorf("formal-glm: invalid unsigned registered Phase18 envelope")
	}
	expected, err := formalGLMRegisteredPhase18ProjectSourceEnvelopeWithContextV1(
		context, authorization, ticket, envelope.BlockIndex,
		pairCommitment, envelope.Ciphertext)
	if err != nil || !reflect.DeepEqual(envelope, expected) {
		return fmt.Errorf("formal-glm: registered Phase18 source envelope differs")
	}
	return nil
}

func formalGLMRegisteredPhase18SignSourceEnvelopeV1(
	envelope formalGLMRegisteredPhase18SourceEnvelopeV1,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	pairCommitment string,
	privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18SourceEnvelopeV1, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return formalGLMRegisteredPhase18SourceEnvelopeV1{}, err
	}
	return formalGLMRegisteredPhase18SignSourceEnvelopeWithContextV1(
		context, envelope, authorization, ticket, pairCommitment, privateKey)
}

func formalGLMRegisteredPhase18SignSourceEnvelopeWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	envelope formalGLMRegisteredPhase18SourceEnvelopeV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	pairCommitment string,
	privateKey ed25519.PrivateKey,
) (formalGLMRegisteredPhase18SourceEnvelopeV1, error) {
	if err := formalGLMRegisteredPhase18ValidateSourceEnvelopeCoreWithContextV1(
		context, envelope, authorization, ticket, pairCommitment); err != nil {
		return formalGLMRegisteredPhase18SourceEnvelopeV1{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey),
			context.pins[envelope.SourceName]) {
		return formalGLMRegisteredPhase18SourceEnvelopeV1{},
			fmt.Errorf("formal-glm: invalid registered Phase18 source signer")
	}
	message, err := formalGLMRegisteredPhase18SignatureMessageV1(
		formalGLMRegisteredPhase18SourceEnvelopeDomain, envelope)
	if err != nil {
		return formalGLMRegisteredPhase18SourceEnvelopeV1{}, err
	}
	envelope.Signature = ed25519.Sign(privateKey, message)
	return envelope, nil
}

func formalGLMRegisteredPhase18ValidateSourceEnvelopeV1(
	envelope formalGLMRegisteredPhase18SourceEnvelopeV1,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	pairCommitment string,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateSourceEnvelopeWithContextV1(
		context, envelope, authorization, ticket, pairCommitment)
}

func formalGLMRegisteredPhase18ValidateSourceEnvelopeWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	envelope formalGLMRegisteredPhase18SourceEnvelopeV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	pairCommitment string,
) error {
	if len(envelope.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("formal-glm: invalid registered Phase18 source signature")
	}
	unsigned := envelope
	unsigned.Signature = nil
	if err := formalGLMRegisteredPhase18ValidateSourceEnvelopeCoreWithContextV1(
		context, unsigned, authorization, ticket, pairCommitment); err != nil {
		return err
	}
	message, err := formalGLMRegisteredPhase18SignatureMessageV1(
		formalGLMRegisteredPhase18SourceEnvelopeDomain, unsigned)
	if err != nil || !ed25519.Verify(
		context.pins[envelope.SourceName], message, envelope.Signature) {
		return fmt.Errorf("formal-glm: invalid registered Phase18 source signature")
	}
	return nil
}

func formalGLMRegisteredPhase18SourceEnvelopeSHA256V1(
	envelope formalGLMRegisteredPhase18SourceEnvelopeV1,
) (string, error) {
	if envelope.Version != formalGLMRegisteredPhase18SourceEnvelopeVersion ||
		envelope.Purpose != formalGLMRegisteredPhase18SourceEnvelopePurpose ||
		len(envelope.Signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("formal-glm: invalid registered Phase18 envelope hash input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18SourceEnvelopeDomain+"/signed", envelope)
}

func formalGLMRegisteredPhase18BlockCommitmentSHA256V1(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
	pairCommitment string,
	envelopes []formalGLMRegisteredPhase18SourceEnvelopeV1,
) (string, error) {
	if len(envelopes) != 2 || !formalGLMIsSHA256(pairCommitment) {
		return "", fmt.Errorf("formal-glm: incomplete registered Phase18 source envelopes")
	}
	commitments := make([]formalGLMRegisteredPhase18EnvelopeCommitmentV1, 2)
	for index, recipient := range authorization.DesignatedComputePeers {
		if envelopes[index].RecipientName != recipient ||
			envelopes[index].BlockIndex != blockIndex {
			return "", fmt.Errorf("formal-glm: non-canonical registered Phase18 source envelopes")
		}
		digest, err := formalGLMRegisteredPhase18SourceEnvelopeSHA256V1(
			envelopes[index])
		if err != nil {
			return "", err
		}
		commitments[index] = formalGLMRegisteredPhase18EnvelopeCommitmentV1{
			RecipientName: recipient, EnvelopeSHA256: digest,
		}
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18BlockDomain,
		formalGLMRegisteredPhase18BlockCommitmentInputV1{
			Version:                              formalGLMRegisteredPhase18BlockPairVersion,
			Purpose:                              formalGLMRegisteredPhase18BlockPairPurpose,
			ArtifactID:                           authorization.ArtifactID,
			SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
			SourceContractSHA256:                 authorization.SourceContractSHA256,
			RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
			RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
			SourceName:                           authorization.LocalSource.SignerPeerName,
			BlockIndex:                           blockIndex,
			PairCommitmentSHA256:                 pairCommitment,
			Envelopes:                            commitments,
		})
}

func formalGLMRegisteredPhase18ProjectBlockPairV1(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
	pairCommitment, blockCommitment string,
	envelopes []formalGLMRegisteredPhase18SourceEnvelopeV1,
) (formalGLMRegisteredPhase18BlockPairV1, error) {
	offset, slots, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, blockIndex)
	if err != nil || !formalGLMIsSHA256(pairCommitment) ||
		!formalGLMIsSHA256(blockCommitment) || len(envelopes) != 2 {
		return formalGLMRegisteredPhase18BlockPairV1{},
			fmt.Errorf("formal-glm: invalid registered Phase18 block pair")
	}
	return formalGLMRegisteredPhase18BlockPairV1{
		Version:                              formalGLMRegisteredPhase18BlockPairVersion,
		Purpose:                              formalGLMRegisteredPhase18BlockPairPurpose,
		ArtifactID:                           authorization.ArtifactID,
		SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
		SourceContractSHA256:                 authorization.SourceContractSHA256,
		RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
		RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
		SourceName:                           authorization.LocalSource.SignerPeerName,
		SourceIdentityPK:                     authorization.LocalPeerIdentity.IdentityPK,
		Recipients:                           append([]string(nil), authorization.DesignatedComputePeers...),
		BlockIndex:                           blockIndex,
		TotalBlocks:                          authorization.Geometry.TotalBlocks,
		GlobalSlotOffset:                     offset,
		SlotsInBlock:                         slots,
		CoordinateCount:                      authorization.Geometry.CoordinateCount,
		CoordinateRecords:                    slots * authorization.Geometry.CoordinateCount,
		RingBits:                             authorization.Geometry.RingBits,
		RecordBytes:                          authorization.Geometry.RecordBytes,
		ValidityRecords:                      slots,
		PairCommitmentSHA256:                 pairCommitment,
		BlockCommitmentSHA256:                blockCommitment,
		Envelopes: append(
			[]formalGLMRegisteredPhase18SourceEnvelopeV1(nil), envelopes...),
		OpeningsPerformed: 0,
		ProductionReady:   false,
	}, nil
}

func formalGLMRegisteredPhase18BuildBlockPairV1(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	ciphertexts map[string][]byte,
	privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18BlockPairV1, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	return formalGLMRegisteredPhase18BuildBlockPairWithContextV1(
		context, authorization, tickets, blockIndex, ciphertexts, privateKey)
}

func formalGLMRegisteredPhase18BuildBlockPairWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	ciphertexts map[string][]byte,
	privateKey ed25519.PrivateKey,
) (formalGLMRegisteredPhase18BlockPairV1, error) {
	if blockIndex < 0 {
		return formalGLMRegisteredPhase18BlockPairV1{},
			fmt.Errorf("formal-glm: registered Phase18 block index is required")
	}
	orderedTickets, err := formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(
		context, tickets)
	if err != nil {
		return formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	pairCommitment, err := formalGLMRegisteredPhase18PairCommitmentWithContextV1(
		context, authorization, orderedTickets, blockIndex, ciphertexts)
	if err != nil {
		return formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	envelopes := make([]formalGLMRegisteredPhase18SourceEnvelopeV1, 2)
	for index, ticket := range orderedTickets {
		unsigned, buildErr := formalGLMRegisteredPhase18ProjectSourceEnvelopeWithContextV1(
			context, authorization, ticket, blockIndex, pairCommitment,
			ciphertexts[ticket.RecipientName])
		if buildErr != nil {
			return formalGLMRegisteredPhase18BlockPairV1{}, buildErr
		}
		envelopes[index], buildErr =
			formalGLMRegisteredPhase18SignSourceEnvelopeWithContextV1(
				context, unsigned, authorization, ticket, pairCommitment,
				privateKey)
		if buildErr != nil {
			return formalGLMRegisteredPhase18BlockPairV1{}, buildErr
		}
	}
	blockCommitment, err := formalGLMRegisteredPhase18BlockCommitmentSHA256V1(
		context.contract, authorization, blockIndex, pairCommitment, envelopes)
	if err != nil {
		return formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	pair, err := formalGLMRegisteredPhase18ProjectBlockPairV1(
		authorization, blockIndex, pairCommitment, blockCommitment, envelopes)
	if err != nil {
		return formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	if err := formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
		context, pair, authorization, orderedTickets); err != nil {
		return formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	return pair, nil
}

func formalGLMRegisteredPhase18ValidateBlockPairV1(
	pair formalGLMRegisteredPhase18BlockPairV1,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
		context, pair, authorization, tickets)
}

func formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	pair formalGLMRegisteredPhase18BlockPairV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) error {
	if err := formalGLMRegisteredPhase18ValidateAuthorizationWithContextV1(
		context, authorization); err != nil {
		return err
	}
	orderedTickets, err := formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(
		context, tickets)
	if err != nil || len(pair.Envelopes) != 2 || len(pair.Recipients) != 2 {
		return fmt.Errorf("formal-glm: incomplete registered Phase18 block pair")
	}
	ciphertexts := make(map[string][]byte, 2)
	for index, ticket := range orderedTickets {
		if pair.Recipients[index] != ticket.RecipientName ||
			pair.Envelopes[index].RecipientName != ticket.RecipientName {
			return fmt.Errorf("formal-glm: non-canonical registered Phase18 block pair")
		}
		ciphertexts[ticket.RecipientName] = pair.Envelopes[index].Ciphertext
	}
	pairCommitment, err := formalGLMRegisteredPhase18PairCommitmentWithContextV1(
		context, authorization, orderedTickets, pair.BlockIndex, ciphertexts)
	if err != nil || pair.PairCommitmentSHA256 != pairCommitment {
		return fmt.Errorf("formal-glm: registered Phase18 pair commitment mismatch")
	}
	for index, ticket := range orderedTickets {
		if err := formalGLMRegisteredPhase18ValidateSourceEnvelopeWithContextV1(
			context, pair.Envelopes[index], authorization, ticket,
			pairCommitment); err != nil {
			return err
		}
	}
	blockCommitment, err := formalGLMRegisteredPhase18BlockCommitmentSHA256V1(
		context.contract, authorization, pair.BlockIndex, pairCommitment,
		pair.Envelopes)
	if err != nil || pair.BlockCommitmentSHA256 != blockCommitment {
		return fmt.Errorf("formal-glm: registered Phase18 block commitment mismatch")
	}
	expected, err := formalGLMRegisteredPhase18ProjectBlockPairV1(
		authorization, pair.BlockIndex, pairCommitment, blockCommitment,
		pair.Envelopes)
	if err != nil || !reflect.DeepEqual(pair, expected) {
		return fmt.Errorf("formal-glm: registered Phase18 block pair differs")
	}
	return nil
}

type formalGLMRegisteredPhase18LocalRootInputV1 struct {
	Version                              string                                        `json:"version"`
	Purpose                              string                                        `json:"purpose"`
	ArtifactID                           string                                        `json:"artifact_id"`
	SourceContractCoreSHA256             string                                        `json:"source_contract_core_sha256"`
	SourceContractSHA256                 string                                        `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256        string                                        `json:"registered_execution_plan_sha256"`
	RegisteredPhase18AuthorizationSHA256 string                                        `json:"registered_phase18_authorization_sha256"`
	SourceName                           string                                        `json:"source_name"`
	BlockCommitments                     []formalGLMRegisteredPhase18BlockCommitmentV1 `json:"block_commitments"`
}

func formalGLMRegisteredPhase18LocalRootSHA256V1(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	commitments []formalGLMRegisteredPhase18BlockCommitmentV1,
) (string, error) {
	if len(commitments) != authorization.Geometry.TotalBlocks {
		return "", fmt.Errorf("formal-glm: incomplete registered Phase18 local blocks")
	}
	for index, commitment := range commitments {
		if commitment.BlockIndex != index ||
			!formalGLMIsSHA256(commitment.PairCommitmentSHA256) ||
			!formalGLMIsSHA256(commitment.BlockCommitmentSHA256) {
			return "", fmt.Errorf("formal-glm: non-canonical registered Phase18 local blocks")
		}
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18LocalReceiptDomain+"/root",
		formalGLMRegisteredPhase18LocalRootInputV1{
			Version:                              formalGLMRegisteredPhase18LocalReceiptVersion,
			Purpose:                              formalGLMRegisteredPhase18LocalReceiptPurpose,
			ArtifactID:                           authorization.ArtifactID,
			SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
			SourceContractSHA256:                 authorization.SourceContractSHA256,
			RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
			RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
			SourceName:                           authorization.LocalSource.SignerPeerName,
			BlockCommitments: append(
				[]formalGLMRegisteredPhase18BlockCommitmentV1(nil),
				commitments...),
		})
}

func formalGLMRegisteredPhase18ProjectLocalReceiptV1(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	commitments []formalGLMRegisteredPhase18BlockCommitmentV1,
	localRoot string,
) (formalGLMRegisteredPhase18LocalReceiptV1, error) {
	if !formalGLMIsSHA256(localRoot) ||
		len(commitments) != authorization.Geometry.TotalBlocks {
		return formalGLMRegisteredPhase18LocalReceiptV1{},
			fmt.Errorf("formal-glm: invalid registered Phase18 local receipt")
	}
	return formalGLMRegisteredPhase18LocalReceiptV1{
		Version:                              formalGLMRegisteredPhase18LocalReceiptVersion,
		Phase:                                formalGLMRegisteredPhase18LocalReceiptPhase,
		Purpose:                              formalGLMRegisteredPhase18LocalReceiptPurpose,
		ArtifactID:                           authorization.ArtifactID,
		SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
		SourceContractSHA256:                 authorization.SourceContractSHA256,
		RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
		RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
		SourceName:                           authorization.LocalSource.SignerPeerName,
		SourceIdentityPK:                     authorization.LocalPeerIdentity.IdentityPK,
		PinsetSHA256:                         authorization.PinsetSHA256,
		TotalCapacity:                        authorization.Geometry.TotalCapacity,
		BlockCapacity:                        authorization.Geometry.BlockCapacity,
		TotalBlocks:                          authorization.Geometry.TotalBlocks,
		CoordinateCount:                      authorization.Geometry.CoordinateCount,
		RingBits:                             authorization.Geometry.RingBits,
		RecordBytes:                          authorization.Geometry.RecordBytes,
		ValiditySharing:                      authorization.ValiditySharing,
		AlignmentSharing:                     authorization.AlignmentSharing,
		CoordinateEncoding:                   authorization.CoordinateEncoding,
		BlockCommitments: append(
			[]formalGLMRegisteredPhase18BlockCommitmentV1(nil),
			commitments...),
		LocalMaterializationRootSHA256: localRoot,
		Phase19RequiredOperation:       formalGLMPhase18RequiredOperation,
		OpeningsPerformed:              0,
		ProductionReady:                false,
		Signature:                      nil,
	}, nil
}

func formalGLMRegisteredPhase18BuildLocalReceiptV1(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pairs []formalGLMRegisteredPhase18BlockPairV1,
	privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18LocalReceiptV1, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	return formalGLMRegisteredPhase18BuildLocalReceiptWithContextV1(
		context, authorization, tickets, pairs, privateKey)
}

func formalGLMRegisteredPhase18BuildLocalReceiptWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pairs []formalGLMRegisteredPhase18BlockPairV1,
	privateKey ed25519.PrivateKey,
) (formalGLMRegisteredPhase18LocalReceiptV1, error) {
	if err := formalGLMRegisteredPhase18ValidateAuthorizationWithContextV1(
		context, authorization); err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	if _, err := formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(
		context, tickets); err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	if len(pairs) != authorization.Geometry.TotalBlocks {
		return formalGLMRegisteredPhase18LocalReceiptV1{},
			fmt.Errorf("formal-glm: every registered Phase18 block is required")
	}
	ordered := append([]formalGLMRegisteredPhase18BlockPairV1(nil), pairs...)
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].BlockIndex < ordered[right].BlockIndex
	})
	commitments := make(
		[]formalGLMRegisteredPhase18BlockCommitmentV1, len(ordered))
	for index, pair := range ordered {
		if pair.BlockIndex != index {
			return formalGLMRegisteredPhase18LocalReceiptV1{},
				fmt.Errorf("formal-glm: missing or duplicate registered Phase18 block")
		}
		if err := formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
			context, pair, authorization, tickets); err != nil {
			return formalGLMRegisteredPhase18LocalReceiptV1{}, err
		}
		commitments[index] = formalGLMRegisteredPhase18BlockCommitmentV1{
			BlockIndex:            index,
			PairCommitmentSHA256:  pair.PairCommitmentSHA256,
			BlockCommitmentSHA256: pair.BlockCommitmentSHA256,
		}
	}
	localRoot, err := formalGLMRegisteredPhase18LocalRootSHA256V1(
		authorization, commitments)
	if err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	receipt, err := formalGLMRegisteredPhase18ProjectLocalReceiptV1(
		authorization, commitments, localRoot)
	if err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey),
			context.pins[receipt.SourceName]) {
		return formalGLMRegisteredPhase18LocalReceiptV1{},
			fmt.Errorf("formal-glm: invalid registered Phase18 receipt signer")
	}
	message, err := formalGLMRegisteredPhase18SignatureMessageV1(
		formalGLMRegisteredPhase18LocalReceiptDomain, receipt)
	if err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	if err := formalGLMRegisteredPhase18ValidateLocalReceiptWithContextV1(
		context, receipt); err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	return receipt, nil
}

func formalGLMRegisteredPhase18ValidateLocalReceiptV1(
	receipt formalGLMRegisteredPhase18LocalReceiptV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateLocalReceiptWithContextV1(
		context, receipt)
}

func formalGLMRegisteredPhase18ValidateLocalReceiptWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	receipt formalGLMRegisteredPhase18LocalReceiptV1,
) error {
	if len(receipt.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("formal-glm: invalid registered Phase18 receipt signature")
	}
	authorization, err := formalGLMProjectRegisteredPhase18AuthorizationV1(
		context.contract, receipt.SourceName, context.pins)
	if err != nil {
		return err
	}
	authorization.AuthorizationSHA256, err =
		formalGLMRegisteredPhase18AuthorizationSHA256V1(authorization)
	if err != nil {
		return err
	}
	localRoot, err := formalGLMRegisteredPhase18LocalRootSHA256V1(
		authorization, receipt.BlockCommitments)
	if err != nil || receipt.LocalMaterializationRootSHA256 != localRoot {
		return fmt.Errorf("formal-glm: registered Phase18 local root mismatch")
	}
	expected, err := formalGLMRegisteredPhase18ProjectLocalReceiptV1(
		authorization, receipt.BlockCommitments, localRoot)
	if err != nil {
		return err
	}
	unsigned := receipt
	unsigned.Signature = nil
	if !reflect.DeepEqual(unsigned, expected) {
		return fmt.Errorf("formal-glm: registered Phase18 local receipt differs")
	}
	message, err := formalGLMRegisteredPhase18SignatureMessageV1(
		formalGLMRegisteredPhase18LocalReceiptDomain, unsigned)
	if err != nil || !ed25519.Verify(
		context.pins[receipt.SourceName], message, receipt.Signature) {
		return fmt.Errorf("formal-glm: invalid registered Phase18 receipt signature")
	}
	return nil
}

func formalGLMRegisteredPhase18LocalReceiptSHA256V1(
	receipt formalGLMRegisteredPhase18LocalReceiptV1,
) (string, error) {
	if receipt.Version != formalGLMRegisteredPhase18LocalReceiptVersion ||
		receipt.Purpose != formalGLMRegisteredPhase18LocalReceiptPurpose ||
		len(receipt.Signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("formal-glm: invalid registered Phase18 receipt hash input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18LocalReceiptDomain+"/signed", receipt)
}

type formalGLMRegisteredPhase18ReceiptSetEntryV1 struct {
	SourceName                           string `json:"source_name"`
	RegisteredPhase18AuthorizationSHA256 string `json:"registered_phase18_authorization_sha256"`
	LocalMaterializationRootSHA256       string `json:"local_materialization_root_sha256"`
	SignedReceiptSHA256                  string `json:"signed_receipt_sha256"`
}

type formalGLMRegisteredPhase18ReceiptSetHashInputV1 struct {
	Version                       string                                        `json:"version"`
	Purpose                       string                                        `json:"purpose"`
	ArtifactID                    string                                        `json:"artifact_id"`
	SourceContractCoreSHA256      string                                        `json:"source_contract_core_sha256"`
	SourceContractSHA256          string                                        `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string                                        `json:"registered_execution_plan_sha256"`
	PinsetSHA256                  string                                        `json:"pinset_sha256"`
	Entries                       []formalGLMRegisteredPhase18ReceiptSetEntryV1 `json:"entries"`
}

type formalGLMRegisteredPhase18GlobalRootInputV1 struct {
	Version                       string                                        `json:"version"`
	Purpose                       string                                        `json:"purpose"`
	ArtifactID                    string                                        `json:"artifact_id"`
	SourceContractCoreSHA256      string                                        `json:"source_contract_core_sha256"`
	SourceContractSHA256          string                                        `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string                                        `json:"registered_execution_plan_sha256"`
	ReceiptSetSHA256              string                                        `json:"receipt_set_sha256"`
	Entries                       []formalGLMRegisteredPhase18ReceiptSetEntryV1 `json:"entries"`
}

func formalGLMRegisteredPhase18ReceiptSetDigestsV1(
	contract formalGLMSourceContractV1,
	receipts []formalGLMRegisteredPhase18LocalReceiptV1,
	pins map[string]ed25519.PublicKey,
	requireCanonical bool,
) ([]formalGLMRegisteredPhase18LocalReceiptV1,
	[]formalGLMRegisteredPhase18ReceiptSetEntryV1, error,
) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return nil, nil, err
	}
	return formalGLMRegisteredPhase18ReceiptSetDigestsWithContextV1(
		context, receipts, requireCanonical)
}

func formalGLMRegisteredPhase18ReceiptSetDigestsWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	receipts []formalGLMRegisteredPhase18LocalReceiptV1,
	requireCanonical bool,
) ([]formalGLMRegisteredPhase18LocalReceiptV1,
	[]formalGLMRegisteredPhase18ReceiptSetEntryV1, error,
) {
	peers := context.contract.Core.RegisteredExecutionPlan.CustodianPeers
	if len(receipts) != len(peers) || len(peers) != len(context.pins) {
		return nil, nil, fmt.Errorf("formal-glm: registered Phase18 requires K receipts")
	}
	bySource := make(map[string]formalGLMRegisteredPhase18LocalReceiptV1,
		len(receipts))
	for index, receipt := range receipts {
		if err := formalGLMRegisteredPhase18ValidateLocalReceiptWithContextV1(
			context, receipt); err != nil {
			return nil, nil, err
		}
		if _, exists := bySource[receipt.SourceName]; exists {
			return nil, nil, fmt.Errorf("formal-glm: duplicate registered Phase18 receipt")
		}
		if requireCanonical && (index >= len(peers) ||
			receipt.SourceName != peers[index]) {
			return nil, nil, fmt.Errorf("formal-glm: non-canonical registered Phase18 receipt order")
		}
		bySource[receipt.SourceName] = receipt
	}
	ordered := make([]formalGLMRegisteredPhase18LocalReceiptV1, len(peers))
	entries := make([]formalGLMRegisteredPhase18ReceiptSetEntryV1, len(peers))
	for index, peer := range peers {
		receipt, ok := bySource[peer]
		if !ok {
			return nil, nil, fmt.Errorf("formal-glm: incomplete registered Phase18 receipts")
		}
		receiptSHA256, err := formalGLMRegisteredPhase18LocalReceiptSHA256V1(
			receipt)
		if err != nil {
			return nil, nil, err
		}
		ordered[index] = receipt
		entries[index] = formalGLMRegisteredPhase18ReceiptSetEntryV1{
			SourceName:                           peer,
			RegisteredPhase18AuthorizationSHA256: receipt.RegisteredPhase18AuthorizationSHA256,
			LocalMaterializationRootSHA256:       receipt.LocalMaterializationRootSHA256,
			SignedReceiptSHA256:                  receiptSHA256,
		}
	}
	return ordered, entries, nil
}

func formalGLMRegisteredPhase18ReceiptSetHashesV1(
	contract formalGLMSourceContractV1,
	entries []formalGLMRegisteredPhase18ReceiptSetEntryV1,
	pins map[string]ed25519.PublicKey,
) (string, string, error) {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return "", "", err
	}
	return formalGLMRegisteredPhase18ReceiptSetHashesWithContextV1(
		context, entries)
}

func formalGLMRegisteredPhase18ReceiptSetHashesWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	entries []formalGLMRegisteredPhase18ReceiptSetEntryV1,
) (string, string, error) {
	contract := context.contract
	plan := contract.Core.RegisteredExecutionPlan
	hashInput := formalGLMRegisteredPhase18ReceiptSetHashInputV1{
		Version:                       formalGLMRegisteredPhase18ReceiptSetVersion,
		Purpose:                       formalGLMRegisteredPhase18ReceiptSetPurpose,
		ArtifactID:                    contract.Core.ArtifactID,
		SourceContractCoreSHA256:      contract.CoreSHA256,
		SourceContractSHA256:          context.contractSHA256,
		RegisteredExecutionPlanSHA256: plan.PlanSHA256,
		PinsetSHA256:                  plan.PinsetSHA256,
		Entries: append([]formalGLMRegisteredPhase18ReceiptSetEntryV1(nil),
			entries...),
	}
	receiptSetSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18ReceiptSetDomain+"/receipts", hashInput)
	if err != nil {
		return "", "", err
	}
	globalRoot, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase18ReceiptSetDomain+"/global-root",
		formalGLMRegisteredPhase18GlobalRootInputV1{
			Version:                       formalGLMRegisteredPhase18ReceiptSetVersion,
			Purpose:                       formalGLMRegisteredPhase18ReceiptSetPurpose,
			ArtifactID:                    contract.Core.ArtifactID,
			SourceContractCoreSHA256:      contract.CoreSHA256,
			SourceContractSHA256:          context.contractSHA256,
			RegisteredExecutionPlanSHA256: plan.PlanSHA256,
			ReceiptSetSHA256:              receiptSetSHA256,
			Entries: append([]formalGLMRegisteredPhase18ReceiptSetEntryV1(nil),
				entries...),
		})
	return receiptSetSHA256, globalRoot, err
}

func formalGLMRegisteredPhase18BuildReceiptSetV1(
	contract formalGLMSourceContractV1,
	receipts []formalGLMRegisteredPhase18LocalReceiptV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18ReceiptSetV1, error) {
	var zero formalGLMRegisteredPhase18ReceiptSetV1
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return zero, err
	}
	ordered, entries, err :=
		formalGLMRegisteredPhase18ReceiptSetDigestsWithContextV1(
			context, receipts, false)
	if err != nil {
		return zero, err
	}
	receiptSetSHA256, globalRoot, err :=
		formalGLMRegisteredPhase18ReceiptSetHashesWithContextV1(context, entries)
	if err != nil {
		return zero, err
	}
	set := formalGLMRegisteredPhase18ReceiptSetV1{
		Version:                         formalGLMRegisteredPhase18ReceiptSetVersion,
		Purpose:                         formalGLMRegisteredPhase18ReceiptSetPurpose,
		ArtifactID:                      contract.Core.ArtifactID,
		SourceContractCoreSHA256:        contract.CoreSHA256,
		SourceContractSHA256:            context.contractSHA256,
		RegisteredExecutionPlanSHA256:   contract.Core.RegisteredExecutionPlan.PlanSHA256,
		PinsetSHA256:                    contract.Core.RegisteredExecutionPlan.PinsetSHA256,
		Receipts:                        ordered,
		ReceiptSetSHA256:                receiptSetSHA256,
		GlobalMaterializationRootSHA256: globalRoot,
		OpeningsPerformed:               0,
		ProductionReady:                 false,
	}
	if err := formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
		context, set); err != nil {
		return zero, err
	}
	return set, nil
}

func formalGLMRegisteredPhase18ValidateReceiptSetV1(
	set formalGLMRegisteredPhase18ReceiptSetV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		contract, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
		context, set)
}

func formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
	set formalGLMRegisteredPhase18ReceiptSetV1,
) error {
	contract := context.contract
	plan := contract.Core.RegisteredExecutionPlan
	if set.Version != formalGLMRegisteredPhase18ReceiptSetVersion ||
		set.Purpose != formalGLMRegisteredPhase18ReceiptSetPurpose ||
		set.ArtifactID != contract.Core.ArtifactID ||
		set.SourceContractCoreSHA256 != contract.CoreSHA256 ||
		set.SourceContractSHA256 != context.contractSHA256 ||
		set.RegisteredExecutionPlanSHA256 != plan.PlanSHA256 ||
		set.PinsetSHA256 != plan.PinsetSHA256 ||
		set.OpeningsPerformed != 0 || set.ProductionReady {
		return fmt.Errorf("formal-glm: invalid registered Phase18 receipt set")
	}
	_, entries, err := formalGLMRegisteredPhase18ReceiptSetDigestsWithContextV1(
		context, set.Receipts, true)
	if err != nil {
		return err
	}
	receiptSetSHA256, globalRoot, err :=
		formalGLMRegisteredPhase18ReceiptSetHashesWithContextV1(context, entries)
	if err != nil || set.ReceiptSetSHA256 != receiptSetSHA256 ||
		set.GlobalMaterializationRootSHA256 != globalRoot {
		return fmt.Errorf("formal-glm: registered Phase18 K root mismatch")
	}
	return nil
}

func formalGLMDecodeRegisteredPhase18CanonicalV1[T any](
	encoded []byte,
	maximum int,
) (T, error) {
	var zero T
	if len(encoded) < 2 || len(encoded) > maximum || encoded[0] != '{' {
		return zero, fmt.Errorf("formal-glm: invalid registered Phase18 provenance JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded T
	if err := decoder.Decode(&decoded); err != nil {
		return zero, fmt.Errorf("formal-glm: invalid registered Phase18 provenance JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing registered Phase18 provenance JSON")
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return zero, fmt.Errorf("formal-glm: non-canonical registered Phase18 provenance JSON")
	}
	return decoded, nil
}

func formalGLMDecodeRegisteredPhase18RecipientTicketV1(
	encoded []byte,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18RecipientTicketV1, error) {
	decoded, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18RecipientTicketV1](
		encoded, formalGLMRegisteredPhase18TicketMaxJSON)
	if err != nil {
		return formalGLMRegisteredPhase18RecipientTicketV1{}, err
	}
	if err := formalGLMRegisteredPhase18ValidateRecipientTicketV1(
		decoded, contract, pins); err != nil {
		return formalGLMRegisteredPhase18RecipientTicketV1{}, err
	}
	return decoded, nil
}

func formalGLMDecodeRegisteredPhase18BlockPairV1(
	encoded []byte,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18BlockPairV1, error) {
	decoded, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18BlockPairV1](
		encoded, formalGLMRegisteredPhase18BlockPairMaxJSON)
	if err != nil {
		return formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	if err := formalGLMRegisteredPhase18ValidateBlockPairV1(
		decoded, contract, authorization, tickets, pins); err != nil {
		return formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	return decoded, nil
}

func formalGLMDecodeRegisteredPhase18LocalReceiptV1(
	encoded []byte,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18LocalReceiptV1, error) {
	decoded, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18LocalReceiptV1](
		encoded, formalGLMRegisteredPhase18LocalReceiptMaxJSON)
	if err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	if err := formalGLMRegisteredPhase18ValidateLocalReceiptV1(
		decoded, contract, pins); err != nil {
		return formalGLMRegisteredPhase18LocalReceiptV1{}, err
	}
	return decoded, nil
}

func formalGLMDecodeRegisteredPhase18ReceiptSetV1(
	encoded []byte,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18ReceiptSetV1, error) {
	decoded, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18ReceiptSetV1](
		encoded, formalGLMRegisteredPhase18ReceiptSetMaxJSON)
	if err != nil {
		return formalGLMRegisteredPhase18ReceiptSetV1{}, err
	}
	if err := formalGLMRegisteredPhase18ValidateReceiptSetV1(
		decoded, contract, pins); err != nil {
		return formalGLMRegisteredPhase18ReceiptSetV1{}, err
	}
	return decoded, nil
}
