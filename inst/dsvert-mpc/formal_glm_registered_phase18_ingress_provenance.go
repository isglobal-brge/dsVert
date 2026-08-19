package main

// Pure, recipient-local composition of an authenticated ingress frame from
// already signed registered Phase-1.8 provenance. This does not persist,
// decrypt, or claim that the private payload has been verified.

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
)

// formalGLMRegisteredPhase18ValidationContextFromProvenanceV3 projects the
// frame-codec context from an already validated provenance context. It does
// not re-run the sealed SourceContract proof graph.
func formalGLMRegisteredPhase18ValidationContextFromProvenanceV3(
	context formalGLMRegisteredPhase18ProvenanceContextV1,
) (*formalGLMRegisteredPhase18ValidationContextV3, error) {
	contractSHA256, err := formalGLMSourceContractSHA256V1(context.contract)
	if err != nil || contractSHA256 != context.contractSHA256 {
		return nil, fmt.Errorf(
			"formal-glm: invalid registered Phase-1.8 provenance context")
	}
	plan := context.contract.Core.RegisteredExecutionPlan
	validation := &formalGLMRegisteredPhase18ValidationContextV3{
		sourceContractCoreSHA256:      context.contract.CoreSHA256,
		sourceContractSHA256:          context.contractSHA256,
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
				context.contract, source, context.pins)
		if projectErr != nil {
			return nil, projectErr
		}
		authorization.AuthorizationSHA256, projectErr =
			formalGLMRegisteredPhase18AuthorizationSHA256V1(authorization)
		if projectErr != nil {
			return nil, projectErr
		}
		if _, duplicate := validation.authorizations[source]; duplicate {
			return nil, fmt.Errorf(
				"formal-glm: duplicate registered Phase-1.8 validation source")
		}
		validation.authorizations[source] = authorization
	}
	if !validation.valid() {
		return nil, fmt.Errorf(
			"formal-glm: incomplete registered Phase-1.8 validation context")
	}
	return validation, nil
}

func formalGLMRegisteredPhase18ComposeIngressFrameV3(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	encodedTickets [][]byte,
	encodedBlockPair []byte,
	encodedReceiptSet []byte,
	recipient string,
	pins map[string]ed25519.PublicKey,
	localKey [32]byte,
) ([]byte, error) {
	provenanceContext, err :=
		formalGLMRegisteredPhase18NewProvenanceContextV1(contract, pins)
	if err != nil {
		return nil, err
	}
	validationContext, err :=
		formalGLMRegisteredPhase18ValidationContextFromProvenanceV3(
			provenanceContext)
	if err != nil {
		return nil, err
	}
	if len(encodedTickets) != 2 ||
		len(authorization.DesignatedComputePeers) != 2 {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 ingress requires two recipient tickets")
	}
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 2)
	for index := range encodedTickets {
		decoded, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18RecipientTicketV1](
			encodedTickets[index], formalGLMRegisteredPhase18TicketMaxJSON)
		if err != nil {
			return nil, err
		}
		if decoded.RecipientName != authorization.DesignatedComputePeers[index] {
			return nil, fmt.Errorf(
				"formal-glm: non-canonical registered Phase-1.8 ticket order")
		}
		tickets[index] = decoded
	}
	pair, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18BlockPairV1](
		encodedBlockPair, formalGLMRegisteredPhase18BlockPairMaxJSON)
	if err != nil {
		return nil, err
	}
	receiptSet, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18ReceiptSetV1](
		encodedReceiptSet, formalGLMRegisteredPhase18ReceiptSetMaxJSON)
	if err != nil {
		return nil, err
	}
	return formalGLMRegisteredPhase18ComposeIngressFrameWithContextV3(
		provenanceContext, validationContext, authorization, tickets, pair,
		receiptSet, recipient, localKey)
}

func formalGLMRegisteredPhase18ComposeIngressFrameWithContextV3(
	provenanceContext formalGLMRegisteredPhase18ProvenanceContextV1,
	validationContext *formalGLMRegisteredPhase18ValidationContextV3,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pair formalGLMRegisteredPhase18BlockPairV1,
	receiptSet formalGLMRegisteredPhase18ReceiptSetV1,
	recipient string,
	localKey [32]byte,
) ([]byte, error) {
	if len(tickets) != 2 ||
		len(authorization.DesignatedComputePeers) != 2 ||
		validationContext == nil ||
		provenanceContext.contractSHA256 !=
			validationContext.sourceContractSHA256 ||
		provenanceContext.contract.CoreSHA256 !=
			validationContext.sourceContractCoreSHA256 ||
		provenanceContext.contract.Core.RegisteredExecutionPlan.PlanSHA256 !=
			validationContext.registeredExecutionPlanSHA256 {
		return nil, fmt.Errorf(
			"formal-glm: inconsistent registered Phase-1.8 composition context")
	}
	expectedAuthorization, found := validationContext.authorization(
		authorization.LocalSource.SignerPeerName)
	if !found || !reflect.DeepEqual(expectedAuthorization, authorization) {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 authority mismatch")
	}
	for index, ticket := range tickets {
		if ticket.RecipientName != authorization.DesignatedComputePeers[index] ||
			formalGLMRegisteredPhase18ValidateRecipientTicketWithContextV1(
				provenanceContext, ticket) != nil {
			return nil, fmt.Errorf(
				"formal-glm: non-canonical registered Phase-1.8 ticket order")
		}
	}
	if err := formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
		provenanceContext, pair, authorization, tickets); err != nil {
		return nil, err
	}
	if err := formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
		provenanceContext, receiptSet); err != nil {
		return nil, err
	}
	return formalGLMRegisteredPhase18ComposeValidatedIngressFrameWithContextV3(
		validationContext, tickets, pair, receiptSet, recipient,
		localKey)
}

// formalGLMRegisteredPhase18ComposeValidatedIngressFrameWithContextV3 binds
// one already validated pair to one already validated K/K receipt set. Bulk
// finalizers validate the common tickets and receipt set once before entering
// this per-block helper.
func formalGLMRegisteredPhase18ComposeValidatedIngressFrameWithContextV3(
	validationContext *formalGLMRegisteredPhase18ValidationContextV3,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pair formalGLMRegisteredPhase18BlockPairV1,
	receiptSet formalGLMRegisteredPhase18ReceiptSetV1,
	recipient string,
	localKey [32]byte,
) ([]byte, error) {
	if validationContext == nil || len(tickets) != 2 {
		return nil, fmt.Errorf(
			"formal-glm: incomplete registered Phase-1.8 composition input")
	}
	authorization, found := validationContext.authorization(pair.SourceName)
	if !found {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 source is not authorized")
	}
	if len(receiptSet.Receipts) != len(authorization.CustodianPeers) {
		return nil, fmt.Errorf(
			"formal-glm: incomplete registered Phase-1.8 receipt set")
	}

	sourceSlot := -1
	for index, peer := range authorization.CustodianPeers {
		if peer == pair.SourceName {
			sourceSlot = index
			break
		}
	}
	if sourceSlot < 0 || sourceSlot >= len(receiptSet.Receipts) ||
		pair.SourceName != authorization.LocalSource.SignerPeerName {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 source is not authorized")
	}
	sourceReceipt := receiptSet.Receipts[sourceSlot]
	if sourceReceipt.SourceName != pair.SourceName ||
		sourceReceipt.RegisteredPhase18AuthorizationSHA256 !=
			authorization.AuthorizationSHA256 ||
		pair.BlockIndex < 0 ||
		pair.BlockIndex >= len(sourceReceipt.BlockCommitments) {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 pair is absent from its source receipt")
	}
	receiptCommitment := sourceReceipt.BlockCommitments[pair.BlockIndex]
	if receiptCommitment.BlockIndex != pair.BlockIndex ||
		receiptCommitment.PairCommitmentSHA256 != pair.PairCommitmentSHA256 ||
		receiptCommitment.BlockCommitmentSHA256 != pair.BlockCommitmentSHA256 {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 pair is not committed by the K root")
	}

	recipientSlot := -1
	for index, peer := range authorization.DesignatedComputePeers {
		if peer == recipient {
			recipientSlot = index
			break
		}
	}
	if recipientSlot < 0 || recipientSlot >= len(pair.Envelopes) {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 recipient is not designated")
	}
	ticket := tickets[recipientSlot]
	envelope := pair.Envelopes[recipientSlot]
	if ticket.RecipientName != recipient || envelope.RecipientName != recipient ||
		envelope.SourceName != pair.SourceName {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 recipient envelope mismatch")
	}
	ticketSHA256, err := formalGLMRegisteredPhase18RecipientTicketSHA256V1(
		ticket)
	if err != nil || envelope.RecipientTicketSHA256 != ticketSHA256 {
		return nil, fmt.Errorf(
			"formal-glm: registered Phase-1.8 recipient ticket mismatch")
	}
	envelopeSHA256, err := formalGLMRegisteredPhase18SourceEnvelopeSHA256V1(
		envelope)
	if err != nil {
		return nil, err
	}
	frame := formalGLMRegisteredPhase18IngressFrameV3{
		ArtifactID:                           authorization.ArtifactID,
		SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
		SourceContractSHA256:                 authorization.SourceContractSHA256,
		RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
		RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
		GlobalMaterializationRoot:            receiptSet.GlobalMaterializationRootSHA256,
		Source:                               pair.SourceName,
		Recipient:                            recipient,
		RecipientTicketSHA256:                ticketSHA256,
		PairCommitment:                       pair.PairCommitmentSHA256,
		BlockCommitment:                      pair.BlockCommitmentSHA256,
		CiphertextSHA256:                     envelope.CiphertextSHA256,
		EnvelopeSHA256:                       envelopeSHA256,
		SourceSlot:                           sourceSlot,
		RecipientSlot:                        recipientSlot,
		BlockIndex:                           pair.BlockIndex,
		TotalBlocks:                          pair.TotalBlocks,
		GlobalSlotOffset:                     pair.GlobalSlotOffset,
		SlotsInBlock:                         pair.SlotsInBlock,
		CoordinateCount:                      pair.CoordinateCount,
		CoordinateRecords:                    pair.CoordinateRecords,
		RingBits:                             pair.RingBits,
		RecordBytes:                          pair.RecordBytes,
		ValidityRecords:                      pair.ValidityRecords,
		Ciphertext: append(
			[]byte(nil), envelope.Ciphertext...),
	}
	return formalGLMRegisteredPhase18EncodeIngressFrameWithContextV3(
		frame, validationContext,
		receiptSet.GlobalMaterializationRootSHA256, localKey)
}
