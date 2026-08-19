package main

// Owner-local durable receipt over a complete registered Phase-1.8 source
// outbox. This reads already persisted intents and encrypted block pairs; it
// never rematerializes values or rebuilds ciphertext.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const (
	formalGLMRegisteredPhase18LocalReceiptDirV3        = formalGLMRegisteredPhase18SourceOutboxDirV3 + "/local-receipts-v1"
	formalGLMRegisteredPhase18LocalReceiptSlotDomainV3 = formalGLMRegisteredPhase18SourceOutboxDomainV3 + "/local-receipt-slot"
)

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) localReceiptRelativeLocked(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	create bool,
) (string, string, error) {
	if outbox == nil || outbox.root == nil {
		return "", "", fmt.Errorf(
			"formal-glm registered Phase-1.8 local receipt: unavailable")
	}
	identity := struct {
		SourceContractSHA256 string `json:"source_contract_sha256"`
		AuthorizationSHA256  string `json:"authorization_sha256"`
		Source               string `json:"source"`
	}{
		SourceContractSHA256: authorization.SourceContractSHA256,
		AuthorizationSHA256:  authorization.AuthorizationSHA256,
		Source:               outbox.source,
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", "", err
	}
	mac := formalGLMPhase19MAC(
		outbox.localKey, formalGLMRegisteredPhase18LocalReceiptSlotDomainV3,
		encoded)
	handle := hex.EncodeToString(mac[:])
	shard := filepath.Join(
		formalGLMRegisteredPhase18LocalReceiptDirV3,
		handle[:2], handle[2:4])
	if create {
		err = formalGLMRegisteredPhase18SourceOutboxEnsureDirV3(
			outbox.root, shard)
	} else {
		err = formalGLMRegisteredPhase18SourceOutboxValidateDirV3(
			outbox.root, shard)
	}
	if err != nil {
		return "", "", err
	}
	return handle, filepath.Join(shard, "receipt-"+handle+".json"), nil
}

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) loadIntentForLocalReceiptLocked(
	relative string,
	handle string,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
) (formalGLMRegisteredPhase18SourceOutboxIntentV3, error) {
	var intent formalGLMRegisteredPhase18SourceOutboxIntentV3
	encoded, err := formalGLMRegisteredPhase18SourceOutboxReadV3(
		outbox.root, relative,
		formalGLMRegisteredPhase18SourceOutboxIntentMaxV3)
	if err != nil {
		return intent, err
	}
	defer clear(encoded)
	if err := formalGLMPhase21RockStrictDecode(encoded, &intent); err != nil {
		return intent, err
	}
	if intent.Version != formalGLMRegisteredPhase18SourceOutboxIntentVersionV3 ||
		intent.Purpose != formalGLMRegisteredPhase18SourceOutboxIntentPurposeV3 ||
		intent.Handle != handle || intent.ArtifactID != authorization.ArtifactID ||
		intent.SourceContractSHA256 != authorization.SourceContractSHA256 ||
		intent.AuthorizationSHA256 != authorization.AuthorizationSHA256 ||
		intent.Source != outbox.source || intent.BlockIndex != blockIndex ||
		!formalGLMRegisteredPhase18SourceOutboxMACValidV3(
			intent.InputCommitmentMAC) || intent.ProductionReady {
		return intent, fmt.Errorf(
			"formal-glm registered Phase-1.8 local receipt: invalid intent")
	}
	return intent, nil
}

// CommitLocalReceipt signs and durably commits the receipt for every block
// already present in this source outbox. It returns only canonical signed
// receipt JSON and whether that exact receipt was already durable.
func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) CommitLocalReceipt(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) ([]byte, bool, error) {
	if outbox == nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 local receipt: unavailable")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if outbox.root == nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 local receipt: unavailable")
	}
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		outbox.contract, outbox.pins)
	if err != nil ||
		formalGLMRegisteredPhase18ValidateAuthorizationWithContextV1(
			context, authorization) != nil ||
		authorization.LocalSource.SignerPeerName != outbox.source {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 local receipt: invalid authorization")
	}
	orderedTickets, err :=
		formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(context, tickets)
	if err != nil {
		return nil, false, err
	}
	pairs := make([]formalGLMRegisteredPhase18BlockPairV1,
		authorization.Geometry.TotalBlocks)
	for blockIndex := range pairs {
		handle, intentRelative, pairRelative, slotErr := outbox.slotLocked(
			authorization, blockIndex, false)
		if slotErr != nil {
			return nil, false, slotErr
		}
		intent, loadErr := outbox.loadIntentForLocalReceiptLocked(
			intentRelative, handle, authorization, blockIndex)
		if loadErr != nil {
			return nil, false, loadErr
		}
		pair, _, loadErr := outbox.loadPairLocked(
			pairRelative, handle, intent.InputCommitmentMAC,
			authorization, orderedTickets)
		if loadErr != nil || pair.BlockIndex != blockIndex ||
			pair.SourceName != outbox.source {
			return nil, false, fmt.Errorf(
				"formal-glm registered Phase-1.8 local receipt: incomplete outbox")
		}
		pairs[blockIndex] = pair
	}
	receipt, err := formalGLMRegisteredPhase18BuildLocalReceiptWithContextV1(
		context, authorization, orderedTickets, pairs, outbox.sourcePrivateKey)
	if err != nil {
		return nil, false, err
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil || len(receiptJSON) >
		formalGLMRegisteredPhase18LocalReceiptMaxJSON {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 local receipt: invalid receipt")
	}
	if _, err := formalGLMDecodeRegisteredPhase18LocalReceiptV1(
		receiptJSON, outbox.contract, outbox.pins); err != nil {
		return nil, false, err
	}
	_, receiptRelative, err := outbox.localReceiptRelativeLocked(
		authorization, true)
	if err != nil {
		return nil, false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(
		outbox.root, receiptRelative, receiptJSON)
	if err != nil {
		return nil, false, err
	}
	persisted, err := formalGLMRegisteredPhase18SourceOutboxReadV3(
		outbox.root, receiptRelative,
		formalGLMRegisteredPhase18LocalReceiptMaxJSON)
	if err != nil {
		return nil, false, err
	}
	if _, err := formalGLMDecodeRegisteredPhase18LocalReceiptV1(
		persisted, outbox.contract, outbox.pins); err != nil ||
		!bytes.Equal(persisted, receiptJSON) {
		clear(persisted)
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 local receipt: receipt CAS conflict")
	}
	return persisted, !created, nil
}
