package main

// Capsule-free, source-contract-bound Phase-1.8 ingress codec. This file only
// defines the authenticated wire and private-block boundary; durable runtime
// and Phase-1.9 construction deliberately remain outside this cut.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
)

const (
	formalGLMRegisteredPhase18IngressMagicV3      = "DSVFG183"
	formalGLMRegisteredPhase18IngressMACDomainV3  = "dsVert/formal-glm/phase18/local-ingress-frame/v3"
	formalGLMRegisteredPhase18IngressSlotDomainV3 = "dsVert/formal-glm/phase18/local-ingress-slot/v3"

	formalGLMRegisteredPhase18PrivateBlockVersionV3 = "dsvert-formal-glm-phase18-private-block-v3"
	formalGLMRegisteredPhase18PrivateBlockPurposeV3 = "formal_glm_registered_fixed_rows_and_local_validity_shares_phase19_only_v3"
	formalGLMRegisteredPhase18RecordsDirectoryV3    = "records-v3"

	formalGLMRegisteredPhase18MaxPrivateHeaderV3  = 65535
	formalGLMRegisteredPhase18MaxIngressFrameV3   = 2 << 20
	formalGLMRegisteredPhase18TransportOverheadV3 = 32 + 12 + 16
)

// formalGLMRegisteredPhase18IngressFrameV3 is public routing metadata plus a
// recipient-encrypted private block. The authorization hash is the sole
// per-source materialization-context commitment.
type formalGLMRegisteredPhase18IngressFrameV3 struct {
	ArtifactID                           string
	SourceContractCoreSHA256             string
	SourceContractSHA256                 string
	RegisteredExecutionPlanSHA256        string
	RegisteredPhase18AuthorizationSHA256 string
	GlobalMaterializationRoot            string
	Source                               string
	Recipient                            string
	RecipientTicketSHA256                string
	PairCommitment                       string
	BlockCommitment                      string
	CiphertextSHA256                     string
	EnvelopeSHA256                       string
	SourceSlot                           int
	RecipientSlot                        int
	BlockIndex                           int
	TotalBlocks                          int
	GlobalSlotOffset                     int
	SlotsInBlock                         int
	CoordinateCount                      int
	CoordinateRecords                    int
	RingBits                             int
	RecordBytes                          int
	ValidityRecords                      int
	Ciphertext                           []byte
}

// Field order is alphabetical so json.Marshal is the canonical cross-language
// representation of the encrypted private header.
type formalGLMRegisteredPhase18PrivateBlockHeaderV3 struct {
	AlignmentSharing                     string `json:"alignment_sharing"`
	ArtifactID                           string `json:"artifact_id"`
	BlockIndex                           int    `json:"block_index"`
	CoordinateCount                      int    `json:"coordinate_count"`
	CoordinateEncoding                   string `json:"coordinate_encoding"`
	CoordinateShareBytes                 int    `json:"coordinate_share_bytes"`
	GlobalSlotOffset                     int    `json:"global_slot_offset"`
	OpeningsPerformed                    int    `json:"openings_performed"`
	Phase19RequiredOperation             string `json:"phase19_required_operation"`
	PrivateAlignmentConsensusShare       string `json:"private_alignment_consensus_share"`
	PrivateAlignmentGateShare            int    `json:"private_alignment_gate_share"`
	ProductionReady                      bool   `json:"production_ready"`
	Purpose                              string `json:"purpose"`
	RecipientName                        string `json:"recipient_name"`
	RecipientRole                        string `json:"recipient_role"`
	RecipientTicketSHA256                string `json:"recipient_ticket_sha256"`
	RecordBytes                          int    `json:"record_bytes"`
	RegisteredExecutionPlanSHA256        string `json:"registered_execution_plan_sha256"`
	RegisteredPhase18AuthorizationSHA256 string `json:"registered_phase18_authorization_sha256"`
	RingBits                             int    `json:"ring_bits"`
	SlotsInBlock                         int    `json:"slots_in_block"`
	SourceContractCoreSHA256             string `json:"source_contract_core_sha256"`
	SourceContractSHA256                 string `json:"source_contract_sha256"`
	SourceName                           string `json:"source_name"`
	SourceSlot                           int    `json:"source_slot"`
	TotalBlocks                          int    `json:"total_blocks"`
	ValidityShareBytes                   int    `json:"validity_share_bytes"`
	ValiditySharing                      string `json:"validity_sharing"`
	Version                              string `json:"version"`
}

// formalGLMRegisteredPhase18ValidationContextV3 is an operation-local trust
// context. It validates the sealed source contract once, derives the exact K
// authorizations from that contract, and lets per-frame codecs repeat all
// route, shape, commitment and canonical-wire checks without re-running the
// expensive source-contract proof graph.
type formalGLMRegisteredPhase18ValidationContextV3 struct {
	sourceContractCoreSHA256      string
	sourceContractSHA256          string
	registeredExecutionPlanSHA256 string
	pinsetSHA256                  string
	custodianCount                int
	authorizations                map[string]formalGLMRegisteredPhase18AuthorizationV1
}

func formalGLMRegisteredPhase18NewValidationContextV3(
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase18ValidationContextV3, error) {
	if err := formalGLMValidateSourceContractV1(contract, pins); err != nil {
		return nil, err
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(contract)
	if err != nil {
		return nil, err
	}
	plan := contract.Core.RegisteredExecutionPlan
	context := &formalGLMRegisteredPhase18ValidationContextV3{
		sourceContractCoreSHA256:      contract.CoreSHA256,
		sourceContractSHA256:          contractSHA256,
		registeredExecutionPlanSHA256: plan.PlanSHA256,
		pinsetSHA256:                  plan.PinsetSHA256,
		custodianCount:                plan.CustodianCount,
		authorizations: make(
			map[string]formalGLMRegisteredPhase18AuthorizationV1,
			plan.CustodianCount),
	}
	for _, source := range plan.CustodianPeers {
		authorization, projectErr :=
			formalGLMProjectRegisteredPhase18AuthorizationV1(
				contract, source, pins)
		if projectErr != nil {
			return nil, projectErr
		}
		authorization.AuthorizationSHA256, projectErr =
			formalGLMRegisteredPhase18AuthorizationSHA256V1(authorization)
		if projectErr != nil {
			return nil, projectErr
		}
		if _, duplicate := context.authorizations[source]; duplicate {
			return nil, fmt.Errorf(
				"formal-glm: duplicate registered Phase-1.8 validation source")
		}
		context.authorizations[source] = authorization
	}
	if !context.valid() {
		return nil, fmt.Errorf(
			"formal-glm: incomplete registered Phase-1.8 validation context")
	}
	return context, nil
}

func formalGLMRegisteredPhase18CheckedValidationContextV3(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase18ValidationContextV3, error) {
	context, err := formalGLMRegisteredPhase18NewValidationContextV3(
		contract, pins)
	if err != nil {
		return nil, err
	}
	expected, found := context.authorizations[authorization.LocalSource.SignerPeerName]
	if !found || !reflect.DeepEqual(authorization, expected) {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase18 authorization differs from source contract")
	}
	return context, nil
}

func (context *formalGLMRegisteredPhase18ValidationContextV3) valid() bool {
	return context != nil &&
		formalGLMIsSHA256(context.sourceContractCoreSHA256) &&
		formalGLMIsSHA256(context.sourceContractSHA256) &&
		formalGLMIsSHA256(context.registeredExecutionPlanSHA256) &&
		formalGLMIsSHA256(context.pinsetSHA256) &&
		context.custodianCount >= 2 &&
		len(context.authorizations) == context.custodianCount
}

func (context *formalGLMRegisteredPhase18ValidationContextV3) authorization(
	source string,
) (formalGLMRegisteredPhase18AuthorizationV1, bool) {
	if !context.valid() {
		return formalGLMRegisteredPhase18AuthorizationV1{}, false
	}
	authorization, found := context.authorizations[source]
	return authorization, found &&
		authorization.LocalSource.SignerPeerName == source
}

func formalGLMRegisteredPhase18ExpectedShapeV3(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
) (int, int, error) {
	geometry := authorization.Geometry
	if blockIndex < 0 || blockIndex >= geometry.TotalBlocks ||
		geometry.TotalCapacity < 1 || geometry.BlockCapacity < 1 ||
		geometry.TotalBlocks !=
			(geometry.TotalCapacity+geometry.BlockCapacity-1)/geometry.BlockCapacity {
		return 0, 0, fmt.Errorf("formal-glm: invalid registered Phase-1.8 block")
	}
	offset := blockIndex * geometry.BlockCapacity
	if offset >= geometry.TotalCapacity {
		return 0, 0, fmt.Errorf("formal-glm: invalid registered Phase-1.8 block")
	}
	// The wire remains fixed-shape on the final block. Slots beyond
	// TotalCapacity carry private invalid padding rather than shortening the
	// public frame.
	return offset, geometry.BlockCapacity, nil
}

func formalGLMRegisteredPhase18ValidateFrameBindingV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	pins map[string]ed25519.PublicKey,
	requireCiphertext bool,
) error {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateFrameBindingWithContextV3(
		frame, context, requireCiphertext)
}

func formalGLMRegisteredPhase18ValidateFrameBindingWithContextV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	context *formalGLMRegisteredPhase18ValidationContextV3,
	requireCiphertext bool,
) error {
	authorization, found := context.authorization(frame.Source)
	if !found {
		return fmt.Errorf("formal-glm: registered Phase-1.8 authority mismatch")
	}
	if frame.ArtifactID != authorization.ArtifactID ||
		frame.SourceContractCoreSHA256 != authorization.SourceContractCoreSHA256 ||
		frame.SourceContractCoreSHA256 != context.sourceContractCoreSHA256 ||
		frame.SourceContractSHA256 != authorization.SourceContractSHA256 ||
		frame.SourceContractSHA256 != context.sourceContractSHA256 ||
		frame.RegisteredExecutionPlanSHA256 !=
			authorization.RegisteredExecutionPlanSHA256 ||
		frame.RegisteredExecutionPlanSHA256 !=
			context.registeredExecutionPlanSHA256 ||
		frame.RegisteredPhase18AuthorizationSHA256 !=
			authorization.AuthorizationSHA256 ||
		frame.Source != authorization.LocalSource.SignerPeerName {
		return fmt.Errorf("formal-glm: registered Phase-1.8 authority mismatch")
	}
	for _, value := range []string{
		frame.SourceContractCoreSHA256, frame.SourceContractSHA256,
		frame.RegisteredExecutionPlanSHA256,
		frame.RegisteredPhase18AuthorizationSHA256,
		frame.RecipientTicketSHA256,
		frame.PairCommitment, frame.BlockCommitment,
	} {
		if !formalGLMIsSHA256(value) {
			return fmt.Errorf("formal-glm: invalid registered Phase-1.8 commitment")
		}
	}
	if exactGCValidateLabel("registered Phase-1.8 source", frame.Source, 128) != nil ||
		exactGCValidateLabel("registered Phase-1.8 recipient", frame.Recipient, 128) != nil {
		return fmt.Errorf("formal-glm: invalid registered Phase-1.8 route")
	}
	sourceSlot := -1
	for index, peer := range authorization.CustodianPeers {
		if peer == frame.Source {
			sourceSlot = index
		}
	}
	recipientSlot := -1
	for index, peer := range authorization.DesignatedComputePeers {
		if peer == frame.Recipient {
			recipientSlot = index
		}
	}
	offset, slots, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, frame.BlockIndex)
	if err != nil {
		return err
	}
	geometry := authorization.Geometry
	if frame.SourceSlot != sourceSlot || sourceSlot < 0 ||
		frame.RecipientSlot != recipientSlot || recipientSlot < 0 ||
		frame.TotalBlocks != geometry.TotalBlocks ||
		frame.GlobalSlotOffset != offset || frame.SlotsInBlock != slots ||
		frame.CoordinateCount != geometry.CoordinateCount ||
		frame.CoordinateRecords != slots*geometry.CoordinateCount ||
		frame.RingBits != geometry.RingBits ||
		frame.RecordBytes != geometry.RecordBytes ||
		frame.ValidityRecords != slots {
		return fmt.Errorf("formal-glm: misrouted or shape-confused registered Phase-1.8 ingress frame")
	}
	if !requireCiphertext {
		return nil
	}
	if !formalGLMIsSHA256(frame.CiphertextSHA256) ||
		!formalGLMIsSHA256(frame.EnvelopeSHA256) {
		return fmt.Errorf("formal-glm: invalid registered Phase-1.8 ciphertext commitment")
	}
	shareBytes := frame.CoordinateRecords*frame.RecordBytes +
		frame.ValidityRecords
	maximumCiphertext := formalGLMRegisteredPhase18TransportOverheadV3 + 4 +
		formalGLMRegisteredPhase18MaxPrivateHeaderV3 + shareBytes
	minimumCiphertext := formalGLMRegisteredPhase18TransportOverheadV3 + 4 +
		2 + shareBytes
	if shareBytes < 1 || len(frame.Ciphertext) < minimumCiphertext ||
		len(frame.Ciphertext) > maximumCiphertext ||
		len(frame.Ciphertext)+4096 > formalGLMRegisteredPhase18MaxIngressFrameV3 {
		return fmt.Errorf("formal-glm: registered Phase-1.8 ciphertext is outside its fixed bound")
	}
	digest := sha256.Sum256(frame.Ciphertext)
	if frame.CiphertextSHA256 != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("formal-glm: registered Phase-1.8 ciphertext hash mismatch")
	}
	return nil
}

func formalGLMRegisteredPhase18ValidateIngressFrameV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	expectedGlobalMaterializationRoot string,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidateIngressFrameWithContextV3(
		frame, context, expectedGlobalMaterializationRoot)
}

func formalGLMRegisteredPhase18ValidateIngressFrameWithContextV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	context *formalGLMRegisteredPhase18ValidationContextV3,
	expectedGlobalMaterializationRoot string,
) error {
	if !formalGLMIsSHA256(expectedGlobalMaterializationRoot) ||
		frame.GlobalMaterializationRoot != expectedGlobalMaterializationRoot {
		return fmt.Errorf("formal-glm: registered Phase-1.8 materialization root mismatch")
	}
	return formalGLMRegisteredPhase18ValidateFrameBindingWithContextV3(
		frame, context, true)
}

func formalGLMRegisteredPhase18IngressMessageV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	expectedGlobalMaterializationRoot string,
	pins map[string]ed25519.PublicKey,
) ([]byte, error) {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return nil, err
	}
	return formalGLMRegisteredPhase18IngressMessageWithContextV3(
		frame, context, expectedGlobalMaterializationRoot)
}

func formalGLMRegisteredPhase18IngressMessageWithContextV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	context *formalGLMRegisteredPhase18ValidationContextV3,
	expectedGlobalMaterializationRoot string,
) ([]byte, error) {
	if err := formalGLMRegisteredPhase18ValidateIngressFrameWithContextV3(
		frame, context, expectedGlobalMaterializationRoot); err != nil {
		return nil, err
	}
	message := append([]byte(nil),
		[]byte(formalGLMRegisteredPhase18IngressMagicV3)...)
	var err error
	for _, value := range []string{
		frame.ArtifactID, frame.SourceContractCoreSHA256,
		frame.SourceContractSHA256, frame.RegisteredExecutionPlanSHA256,
		frame.RegisteredPhase18AuthorizationSHA256,
		frame.GlobalMaterializationRoot, frame.Source, frame.Recipient,
		frame.RecipientTicketSHA256, frame.PairCommitment,
		frame.BlockCommitment, frame.CiphertextSHA256, frame.EnvelopeSHA256,
	} {
		message, err = formalGLMPhase18FrameAppendString(message, value)
		if err != nil {
			return nil, err
		}
	}
	for _, value := range []int{
		frame.SourceSlot, frame.RecipientSlot, frame.BlockIndex,
		frame.TotalBlocks, frame.GlobalSlotOffset, frame.SlotsInBlock,
		frame.CoordinateCount, frame.CoordinateRecords, frame.RingBits,
		frame.RecordBytes, frame.ValidityRecords,
	} {
		message, err = formalGLMPhase18FrameAppendInt(message, value)
		if err != nil {
			return nil, err
		}
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(frame.Ciphertext)))
	message = append(message, size[:]...)
	message = append(message, frame.Ciphertext...)
	return message, nil
}

func formalGLMRegisteredPhase18EncodeIngressFrameV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	expectedGlobalMaterializationRoot string,
	pins map[string]ed25519.PublicKey,
	localKey [32]byte,
) ([]byte, error) {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return nil, err
	}
	return formalGLMRegisteredPhase18EncodeIngressFrameWithContextV3(
		frame, context, expectedGlobalMaterializationRoot, localKey)
}

func formalGLMRegisteredPhase18EncodeIngressFrameWithContextV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	context *formalGLMRegisteredPhase18ValidationContextV3,
	expectedGlobalMaterializationRoot string,
	localKey [32]byte,
) ([]byte, error) {
	if !formalGLMPhase19KeyValid(localKey) {
		return nil, fmt.Errorf("formal-glm: missing registered Phase-1.8 ingress key")
	}
	message, err := formalGLMRegisteredPhase18IngressMessageWithContextV3(
		frame, context, expectedGlobalMaterializationRoot)
	if err != nil {
		return nil, err
	}
	mac := formalGLMPhase19MAC(
		localKey, formalGLMRegisteredPhase18IngressMACDomainV3, message)
	encoded := append(append([]byte(nil), message...), mac[:]...)
	if len(encoded) > formalGLMRegisteredPhase18MaxIngressFrameV3 {
		return nil, fmt.Errorf("formal-glm: registered Phase-1.8 ingress frame exceeds its fixed bound")
	}
	return encoded, nil
}

func formalGLMRegisteredPhase18DecodeIngressFrameV3(
	encoded []byte,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	expectedGlobalMaterializationRoot string,
	pins map[string]ed25519.PublicKey,
	localKey [32]byte,
) (formalGLMRegisteredPhase18IngressFrameV3, error) {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return formalGLMRegisteredPhase18IngressFrameV3{}, err
	}
	return formalGLMRegisteredPhase18DecodeIngressFrameWithContextV3(
		encoded, context, expectedGlobalMaterializationRoot, localKey)
}

func formalGLMRegisteredPhase18DecodeIngressFrameWithContextV3(
	encoded []byte,
	context *formalGLMRegisteredPhase18ValidationContextV3,
	expectedGlobalMaterializationRoot string,
	localKey [32]byte,
) (formalGLMRegisteredPhase18IngressFrameV3, error) {
	var zero formalGLMRegisteredPhase18IngressFrameV3
	if !formalGLMPhase19KeyValid(localKey) ||
		len(encoded) < len(formalGLMRegisteredPhase18IngressMagicV3)+32 ||
		len(encoded) > formalGLMRegisteredPhase18MaxIngressFrameV3 {
		return zero, fmt.Errorf("formal-glm: invalid registered Phase-1.8 ingress frame")
	}
	message := encoded[:len(encoded)-32]
	gotMAC := encoded[len(encoded)-32:]
	wantMAC := formalGLMPhase19MAC(
		localKey, formalGLMRegisteredPhase18IngressMACDomainV3, message)
	if !hmac.Equal(wantMAC[:], gotMAC) {
		return zero, fmt.Errorf("formal-glm: registered Phase-1.8 ingress authentication failed")
	}
	reader := formalGLMPhase18FrameReader{value: message}
	magic, err := reader.take(len(formalGLMRegisteredPhase18IngressMagicV3))
	if err != nil || string(magic) != formalGLMRegisteredPhase18IngressMagicV3 {
		return zero, fmt.Errorf("formal-glm: legacy or invalid registered Phase-1.8 ingress frame")
	}
	stringsRead := make([]string, 13)
	for index := range stringsRead {
		stringsRead[index], err = reader.readString()
		if err != nil {
			return zero, err
		}
	}
	intsRead := make([]int, 11)
	for index := range intsRead {
		intsRead[index], err = reader.readInt()
		if err != nil {
			return zero, err
		}
	}
	sizeBytes, err := reader.take(4)
	if err != nil {
		return zero, err
	}
	ciphertextBytes := int(binary.BigEndian.Uint32(sizeBytes))
	ciphertext, err := reader.take(ciphertextBytes)
	if err != nil || reader.offset != len(reader.value) {
		return zero, fmt.Errorf("formal-glm: truncated or trailing registered Phase-1.8 ingress data")
	}
	frame := formalGLMRegisteredPhase18IngressFrameV3{
		ArtifactID:                           stringsRead[0],
		SourceContractCoreSHA256:             stringsRead[1],
		SourceContractSHA256:                 stringsRead[2],
		RegisteredExecutionPlanSHA256:        stringsRead[3],
		RegisteredPhase18AuthorizationSHA256: stringsRead[4],
		GlobalMaterializationRoot:            stringsRead[5], Source: stringsRead[6],
		Recipient: stringsRead[7], RecipientTicketSHA256: stringsRead[8],
		PairCommitment: stringsRead[9], BlockCommitment: stringsRead[10],
		CiphertextSHA256: stringsRead[11], EnvelopeSHA256: stringsRead[12],
		SourceSlot: intsRead[0], RecipientSlot: intsRead[1],
		BlockIndex: intsRead[2], TotalBlocks: intsRead[3],
		GlobalSlotOffset: intsRead[4], SlotsInBlock: intsRead[5],
		CoordinateCount: intsRead[6], CoordinateRecords: intsRead[7],
		RingBits: intsRead[8], RecordBytes: intsRead[9],
		ValidityRecords: intsRead[10],
		Ciphertext:      append([]byte(nil), ciphertext...),
	}
	if err := formalGLMRegisteredPhase18ValidateIngressFrameWithContextV3(
		frame, context, expectedGlobalMaterializationRoot); err != nil {
		return zero, err
	}
	reencoded, err := formalGLMRegisteredPhase18EncodeIngressFrameWithContextV3(
		frame, context, expectedGlobalMaterializationRoot, localKey)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return zero, fmt.Errorf("formal-glm: non-canonical registered Phase-1.8 ingress frame")
	}
	return frame, nil
}

func formalGLMRegisteredPhase18IngressSlotIDV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	expectedGlobalMaterializationRoot string,
	pins map[string]ed25519.PublicKey,
) (string, error) {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return "", err
	}
	return formalGLMRegisteredPhase18IngressSlotIDWithContextV3(
		frame, context, expectedGlobalMaterializationRoot)
}

func formalGLMRegisteredPhase18IngressSlotIDWithContextV3(
	frame formalGLMRegisteredPhase18IngressFrameV3,
	context *formalGLMRegisteredPhase18ValidationContextV3,
	expectedGlobalMaterializationRoot string,
) (string, error) {
	if err := formalGLMRegisteredPhase18ValidateIngressFrameWithContextV3(
		frame, context, expectedGlobalMaterializationRoot); err != nil {
		return "", err
	}
	message := formalGLMPhase15AppendString(
		nil, formalGLMRegisteredPhase18IngressSlotDomainV3)
	message = formalGLMPhase15AppendString(message, frame.SourceContractSHA256)
	message = formalGLMPhase15AppendString(
		message, frame.RegisteredPhase18AuthorizationSHA256)
	message = formalGLMPhase15AppendString(
		message, frame.GlobalMaterializationRoot)
	message = formalGLMPhase15AppendString(message, frame.Source)
	message = formalGLMPhase15AppendString(message, frame.Recipient)
	message = formalGLMPhase15AppendUint64(message, uint64(frame.BlockIndex))
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMRegisteredPhase18ValidatePrivateBlockHeaderV3(
	header formalGLMRegisteredPhase18PrivateBlockHeaderV3,
	frame formalGLMRegisteredPhase18IngressFrameV3,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	pins map[string]ed25519.PublicKey,
) error {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return err
	}
	return formalGLMRegisteredPhase18ValidatePrivateBlockHeaderWithContextV3(
		header, frame, context)
}

func formalGLMRegisteredPhase18ValidatePrivateBlockHeaderWithContextV3(
	header formalGLMRegisteredPhase18PrivateBlockHeaderV3,
	frame formalGLMRegisteredPhase18IngressFrameV3,
	context *formalGLMRegisteredPhase18ValidationContextV3,
) error {
	if err := formalGLMRegisteredPhase18ValidateFrameBindingWithContextV3(
		frame, context, false); err != nil {
		return err
	}
	authorization, found := context.authorization(frame.Source)
	if !found {
		return fmt.Errorf("formal-glm: registered Phase-1.8 authority mismatch")
	}
	expectedRole := "garbler"
	if frame.RecipientSlot == 1 {
		expectedRole = "evaluator"
	}
	coordinateBytes := frame.CoordinateRecords * frame.RecordBytes
	if header.Version != formalGLMRegisteredPhase18PrivateBlockVersionV3 ||
		header.Purpose != formalGLMRegisteredPhase18PrivateBlockPurposeV3 ||
		header.ArtifactID != frame.ArtifactID ||
		header.SourceContractCoreSHA256 != frame.SourceContractCoreSHA256 ||
		header.SourceContractSHA256 != frame.SourceContractSHA256 ||
		header.RegisteredExecutionPlanSHA256 !=
			frame.RegisteredExecutionPlanSHA256 ||
		header.RegisteredPhase18AuthorizationSHA256 !=
			frame.RegisteredPhase18AuthorizationSHA256 ||
		header.SourceName != frame.Source || header.SourceSlot != frame.SourceSlot ||
		header.RecipientName != frame.Recipient ||
		header.RecipientRole != expectedRole ||
		header.RecipientTicketSHA256 != frame.RecipientTicketSHA256 ||
		header.BlockIndex != frame.BlockIndex ||
		header.TotalBlocks != frame.TotalBlocks ||
		header.GlobalSlotOffset != frame.GlobalSlotOffset ||
		header.SlotsInBlock != frame.SlotsInBlock ||
		header.CoordinateCount != frame.CoordinateCount ||
		header.CoordinateEncoding != authorization.CoordinateEncoding ||
		header.CoordinateShareBytes != coordinateBytes ||
		header.ValidityShareBytes != frame.ValidityRecords ||
		header.RingBits != frame.RingBits ||
		header.RecordBytes != frame.RecordBytes ||
		header.ValiditySharing != formalGLMPhase18ValiditySharing ||
		header.AlignmentSharing != formalGLMPhase18AlignmentSharing ||
		header.PrivateAlignmentGateShare < 0 ||
		header.PrivateAlignmentGateShare > 1 ||
		header.Phase19RequiredOperation != formalGLMPhase18RequiredOperation ||
		header.OpeningsPerformed != 0 || header.ProductionReady {
		return fmt.Errorf("formal-glm: misrouted or malformed registered Phase-1.8 private header")
	}
	consensusShare, err := base64.RawURLEncoding.Strict().DecodeString(
		header.PrivateAlignmentConsensusShare)
	if err != nil || len(consensusShare) != 32 ||
		base64.RawURLEncoding.EncodeToString(consensusShare) !=
			header.PrivateAlignmentConsensusShare {
		return fmt.Errorf("formal-glm: invalid registered Phase-1.8 consensus share")
	}
	return nil
}

func formalGLMRegisteredPhase18EncodePrivateBlockV3(
	header formalGLMRegisteredPhase18PrivateBlockHeaderV3,
	coordinates []*big.Int,
	validity []byte,
	frame formalGLMRegisteredPhase18IngressFrameV3,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	pins map[string]ed25519.PublicKey,
) ([]byte, error) {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return nil, err
	}
	return formalGLMRegisteredPhase18EncodePrivateBlockWithContextV3(
		header, coordinates, validity, frame, context)
}

func formalGLMRegisteredPhase18EncodePrivateBlockWithContextV3(
	header formalGLMRegisteredPhase18PrivateBlockHeaderV3,
	coordinates []*big.Int,
	validity []byte,
	frame formalGLMRegisteredPhase18IngressFrameV3,
	context *formalGLMRegisteredPhase18ValidationContextV3,
) ([]byte, error) {
	if err := formalGLMRegisteredPhase18ValidatePrivateBlockHeaderWithContextV3(
		header, frame, context); err != nil {
		return nil, err
	}
	if len(coordinates) != frame.CoordinateRecords ||
		len(validity) != frame.ValidityRecords {
		return nil, fmt.Errorf("formal-glm: invalid registered Phase-1.8 private shares")
	}
	for _, value := range validity {
		if value > 1 {
			return nil, fmt.Errorf("formal-glm: invalid registered Phase-1.8 validity share")
		}
	}
	coordinateBytes, err := formalGLMPhase15EncodeRecords(
		coordinates, frame.RingBits)
	if err != nil {
		return nil, err
	}
	headerJSON, err := json.Marshal(header)
	if err != nil || len(headerJSON) < 2 ||
		len(headerJSON) > formalGLMRegisteredPhase18MaxPrivateHeaderV3 {
		return nil, fmt.Errorf("formal-glm: invalid registered Phase-1.8 private header")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(headerJSON)))
	result := append([]byte(nil), size[:]...)
	result = append(result, headerJSON...)
	result = append(result, coordinateBytes...)
	return append(result, validity...), nil
}

func formalGLMRegisteredPhase18DecodePrivateBlockV3(
	plaintext []byte,
	frame formalGLMRegisteredPhase18IngressFrameV3,
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	expectedGlobalMaterializationRoot string,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18PrivateBlockHeaderV3, []*big.Int, []byte, error) {
	context, err := formalGLMRegisteredPhase18CheckedValidationContextV3(
		contract, authorization, pins)
	if err != nil {
		return formalGLMRegisteredPhase18PrivateBlockHeaderV3{}, nil, nil, err
	}
	return formalGLMRegisteredPhase18DecodePrivateBlockWithContextV3(
		plaintext, frame, context, expectedGlobalMaterializationRoot)
}

func formalGLMRegisteredPhase18DecodePrivateBlockWithContextV3(
	plaintext []byte,
	frame formalGLMRegisteredPhase18IngressFrameV3,
	context *formalGLMRegisteredPhase18ValidationContextV3,
	expectedGlobalMaterializationRoot string,
) (formalGLMRegisteredPhase18PrivateBlockHeaderV3, []*big.Int, []byte, error) {
	var zero formalGLMRegisteredPhase18PrivateBlockHeaderV3
	if err := formalGLMRegisteredPhase18ValidateIngressFrameWithContextV3(
		frame, context, expectedGlobalMaterializationRoot); err != nil {
		return zero, nil, nil, err
	}
	if len(plaintext) < 4 {
		return zero, nil, nil,
			fmt.Errorf("formal-glm: truncated registered Phase-1.8 private block")
	}
	headerBytes := int(binary.BigEndian.Uint32(plaintext[:4]))
	shareBytes := frame.CoordinateRecords*frame.RecordBytes +
		frame.ValidityRecords
	if headerBytes < 2 ||
		headerBytes > formalGLMRegisteredPhase18MaxPrivateHeaderV3 ||
		len(plaintext) != 4+headerBytes+shareBytes {
		return zero, nil, nil,
			fmt.Errorf("formal-glm: invalid registered Phase-1.8 private block shape")
	}
	encodedHeader := plaintext[4 : 4+headerBytes]
	decoder := json.NewDecoder(bytes.NewReader(encodedHeader))
	decoder.DisallowUnknownFields()
	var header formalGLMRegisteredPhase18PrivateBlockHeaderV3
	if err := decoder.Decode(&header); err != nil {
		return zero, nil, nil,
			fmt.Errorf("formal-glm: invalid registered Phase-1.8 private header: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, nil, nil,
			fmt.Errorf("formal-glm: trailing registered Phase-1.8 private header")
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(canonical, encodedHeader) {
		return zero, nil, nil,
			fmt.Errorf("formal-glm: non-canonical registered Phase-1.8 private header")
	}
	if err := formalGLMRegisteredPhase18ValidatePrivateBlockHeaderWithContextV3(
		header, frame, context); err != nil {
		return zero, nil, nil, err
	}
	coordinateBytes := frame.CoordinateRecords * frame.RecordBytes
	shares := plaintext[4+headerBytes:]
	coordinates, err := formalGLMPhase18DecodeCoordinateShares(
		shares[:coordinateBytes], frame.CoordinateRecords,
		frame.RingBits, frame.RecordBytes)
	if err != nil {
		return zero, nil, nil, err
	}
	validity := append([]byte(nil), shares[coordinateBytes:]...)
	for _, value := range validity {
		if value > 1 {
			return zero, nil, nil,
				fmt.Errorf("formal-glm: invalid registered Phase-1.8 validity share")
		}
	}
	reencoded, err := formalGLMRegisteredPhase18EncodePrivateBlockWithContextV3(
		header, coordinates, validity, frame, context)
	if err != nil || !bytes.Equal(reencoded, plaintext) {
		return zero, nil, nil,
			fmt.Errorf("formal-glm: non-canonical registered Phase-1.8 private block")
	}
	return header, coordinates, validity, nil
}
