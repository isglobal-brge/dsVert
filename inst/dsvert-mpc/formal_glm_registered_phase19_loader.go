package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"math/big"
)

const formalGLMRegisteredPhase19PrivateBlockVersionV1 = "dsvert-formal-glm-registered-phase19-private-block-v1"

// formalGLMRegisteredPhase19PrivateBlockV1 has no exported fields by design.
// It is a recipient-local, in-memory trust type and has no JSON surface.
type formalGLMRegisteredPhase19PrivateBlockV1 struct {
	version                       string
	semanticRootSHA256            string
	receiptSetSHA256              string
	registeredAuthorizationSHA256 string
	source                        string
	recipient                     string
	recipientRole                 string
	sourceSlot                    int
	recipientSlot                 int
	blockIndex                    int
	totalBlocks                   int
	globalSlotOffset              int
	slotsInBlock                  int
	rowsInBlock                   int
	coordinateCount               int
	ringBits                      int
	recordBytes                   int
	pairCommitmentSHA256          string
	blockCommitmentSHA256         string
	coordinateShares              []*big.Int
	validityShares                []byte
	alignmentGateShare            byte
	alignmentConsensusShare       [32]byte
	openingsPerformed             int
	verified                      bool
}

func formalGLMRegisteredPhase19ClearSharesV1(
	coordinates []*big.Int,
	validity []byte,
) {
	for _, value := range coordinates {
		if value != nil {
			value.SetInt64(0)
		}
	}
	clear(validity)
}

func formalGLMRegisteredPhase19ClearPrivateBlocksV1(
	blocks []formalGLMRegisteredPhase19PrivateBlockV1,
) {
	for index := range blocks {
		formalGLMRegisteredPhase19ClearSharesV1(
			blocks[index].coordinateShares, blocks[index].validityShares)
		blocks[index].coordinateShares = nil
		blocks[index].validityShares = nil
		clear(blocks[index].alignmentConsensusShare[:])
		blocks[index].alignmentGateShare = 0
		blocks[index].verified = false
	}
}

// formalGLMRegisteredPhase19PrivateLoadContextV1 is valid only while its
// ingress store remains locked. It contains public routing data, never a
// recipient secret or a decoded private block.
type formalGLMRegisteredPhase19PrivateLoadContextV1 struct {
	validationContext *formalGLMRegisteredPhase18ValidationContextV3
	recipientSlot     int
	ticketSHA256      string
}

// loadRegisteredPhase19FrameLockedV1 is the sole rooted frame seam used by
// the registered loader. The caller must hold store.mu. Raw record bytes are
// authenticated and cleared here and never leave this method.
func (store *formalGLMRegisteredPhase18IngressStoreV3) loadRegisteredPhase19FrameLockedV1(
	context *formalGLMRegisteredPhase18ValidationContextV3,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
) (formalGLMRegisteredPhase18IngressFrameV3, error) {
	var zero formalGLMRegisteredPhase18IngressFrameV3
	if store == nil || store.root == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 loader: ingress store is closed")
	}
	handle, relative, err := store.recordRelativePathWithContextLocked(
		authorization.LocalSource.SignerPeerName, blockIndex, false, context)
	if err != nil {
		return zero, err
	}
	encoded, err := formalGLMRegisteredPhase18ReadStoreRecordV3(
		store.root, relative)
	if err != nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: incomplete rooted ingress: %w",
			err)
	}
	defer clear(encoded)
	frame, err := formalGLMRegisteredPhase18DecodeIngressFrameWithContextV3(
		encoded, context, store.expectedGlobalMaterializationRoot, store.localKey)
	if err != nil {
		return zero, err
	}
	if frame.Recipient != store.recipient || frame.BlockIndex != blockIndex {
		clear(frame.Ciphertext)
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: rooted ingress route mismatch")
	}
	frameHandle, err := formalGLMRegisteredPhase18IngressSlotIDWithContextV3(
		frame, context, store.expectedGlobalMaterializationRoot)
	if err != nil || frameHandle != handle {
		clear(frame.Ciphertext)
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: rooted ingress slot mismatch")
	}
	return frame, nil
}

func formalGLMRegisteredPhase19DecodePrivateFrameV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	frame formalGLMRegisteredPhase18IngressFrameV3,
	recipientPrivateKey []byte,
	context *formalGLMRegisteredPhase18ValidationContextV3,
) (formalGLMRegisteredPhase19PrivateBlockV1, error) {
	var zero formalGLMRegisteredPhase19PrivateBlockV1
	defer clear(frame.Ciphertext)
	plaintext, err := transportDecryptBytes(
		frame.Ciphertext, recipientPrivateKey)
	if err != nil {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: decrypt private ingress: %w", err)
	}
	defer clear(plaintext)
	header, coordinates, validity, err :=
		formalGLMRegisteredPhase18DecodePrivateBlockWithContextV3(
			plaintext, frame, context,
			record.Binding.GlobalMaterializationRootSHA256)
	if err != nil {
		return zero, err
	}
	consensusBytes, err := base64.RawURLEncoding.Strict().DecodeString(
		header.PrivateAlignmentConsensusShare)
	if err != nil || len(consensusBytes) != 32 {
		formalGLMRegisteredPhase19ClearSharesV1(coordinates, validity)
		clear(consensusBytes)
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: invalid consensus share")
	}
	var consensus [32]byte
	copy(consensus[:], consensusBytes)
	clear(consensusBytes)
	rows := authorization.Geometry.TotalCapacity - frame.GlobalSlotOffset
	if rows > authorization.Geometry.BlockCapacity {
		rows = authorization.Geometry.BlockCapacity
	}
	if rows < 1 {
		formalGLMRegisteredPhase19ClearSharesV1(coordinates, validity)
		clear(consensus[:])
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: invalid private block rows")
	}
	return formalGLMRegisteredPhase19PrivateBlockV1{
		version:                       formalGLMRegisteredPhase19PrivateBlockVersionV1,
		semanticRootSHA256:            record.Binding.SemanticRootSHA256,
		receiptSetSHA256:              record.Binding.ReceiptSetSHA256,
		registeredAuthorizationSHA256: authorization.AuthorizationSHA256,
		source:                        frame.Source,
		recipient:                     frame.Recipient,
		recipientRole:                 header.RecipientRole,
		sourceSlot:                    frame.SourceSlot,
		recipientSlot:                 frame.RecipientSlot,
		blockIndex:                    frame.BlockIndex,
		totalBlocks:                   frame.TotalBlocks,
		globalSlotOffset:              frame.GlobalSlotOffset,
		slotsInBlock:                  frame.SlotsInBlock,
		rowsInBlock:                   rows,
		coordinateCount:               frame.CoordinateCount,
		ringBits:                      frame.RingBits,
		recordBytes:                   frame.RecordBytes,
		pairCommitmentSHA256:          frame.PairCommitment,
		blockCommitmentSHA256:         frame.BlockCommitment,
		coordinateShares:              coordinates,
		validityShares:                validity,
		alignmentGateShare:            byte(header.PrivateAlignmentGateShare),
		alignmentConsensusShare:       consensus,
		openingsPerformed:             header.OpeningsPerformed,
		verified:                      true,
	}, nil
}

func formalGLMRegisteredPhase19PreparePrivateLoadLockedV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
	store *formalGLMRegisteredPhase18IngressStoreV3,
	recipientPrivateKey []byte,
) (formalGLMRegisteredPhase19PrivateLoadContextV1, error) {
	var zero formalGLMRegisteredPhase19PrivateLoadContextV1
	if store.root == nil || len(recipientPrivateKey) != 32 ||
		formalGLMValidateRegisteredPhase19BindingRecordV1(
			record, store.contract, store.pins) != nil ||
		store.expectedGlobalMaterializationRoot !=
			record.Binding.GlobalMaterializationRootSHA256 {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: invalid execution evidence")
	}
	validationContext := store.context
	if !validationContext.valid() {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: invalid validation context")
	}
	plan := store.contract.Core.RegisteredExecutionPlan
	recipientSlot := -1
	for index, peer := range plan.DesignatedComputePeers {
		if peer == store.recipient {
			recipientSlot = index
		}
	}
	if recipientSlot < 0 || recipientSlot >= len(record.RecipientTickets) ||
		recipientSlot >= len(record.Binding.RecipientBindings) {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: recipient is not bound")
	}
	ticket := record.RecipientTickets[recipientSlot]
	ticketBinding := record.Binding.RecipientBindings[recipientSlot]
	ticketSHA256, err := formalGLMRegisteredPhase18RecipientTicketSHA256V1(
		ticket)
	if err != nil || ticket.RecipientName != store.recipient ||
		ticketBinding.RecipientName != store.recipient ||
		ticketBinding.RecipientTicketSHA256 != ticketSHA256 {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: recipient ticket mismatch")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(recipientPrivateKey)
	if err != nil || !bytes.Equal(
		privateKey.PublicKey().Bytes(), ticket.TransportPK) {
		return zero, fmt.Errorf(
			"formal-glm registered Phase19 loader: recipient key does not match its signed ticket")
	}
	return formalGLMRegisteredPhase19PrivateLoadContextV1{
		validationContext: validationContext,
		recipientSlot:     recipientSlot,
		ticketSHA256:      ticketSHA256,
	}, nil
}

// formalGLMLoadRegisteredPhase19PrivateBlockSetLockedV1 loads exactly one
// source-complete block. The caller holds store.mu and clears the returned
// shares on error or after fan-in.
func formalGLMLoadRegisteredPhase19PrivateBlockSetLockedV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
	store *formalGLMRegisteredPhase18IngressStoreV3,
	recipientPrivateKey []byte,
	loadContext formalGLMRegisteredPhase19PrivateLoadContextV1,
	blockIndex int,
) (result []formalGLMRegisteredPhase19PrivateBlockV1, err error) {
	plan := store.contract.Core.RegisteredExecutionPlan
	if blockIndex < 0 || blockIndex >= plan.TotalBlocks {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 loader: invalid private block index")
	}
	defer func() {
		if err != nil {
			formalGLMRegisteredPhase19ClearPrivateBlocksV1(result)
			result = nil
		}
	}()
	result = make([]formalGLMRegisteredPhase19PrivateBlockV1, 0,
		len(plan.CustodianPeers))
	for sourceSlot, source := range plan.CustodianPeers {
		authorization, found := loadContext.validationContext.authorization(source)
		if !found {
			return nil, fmt.Errorf(
				"formal-glm registered Phase19 loader: source authorization is absent")
		}
		receipt := record.ReceiptSet.Receipts[sourceSlot]
		if receipt.SourceName != source ||
			receipt.RegisteredPhase18AuthorizationSHA256 !=
				authorization.AuthorizationSHA256 ||
			len(receipt.BlockCommitments) != plan.TotalBlocks {
			return nil, fmt.Errorf(
				"formal-glm registered Phase19 loader: source receipt route mismatch")
		}
		commitment := receipt.BlockCommitments[blockIndex]
		if commitment.BlockIndex != blockIndex {
			return nil, fmt.Errorf(
				"formal-glm registered Phase19 loader: non-canonical block commitment")
		}
		frame, loadErr := store.loadRegisteredPhase19FrameLockedV1(
			loadContext.validationContext, authorization, blockIndex)
		if loadErr != nil {
			return nil, loadErr
		}
		if frame.Source != source || frame.SourceSlot != sourceSlot ||
			frame.Recipient != store.recipient ||
			frame.RecipientSlot != loadContext.recipientSlot ||
			frame.RecipientTicketSHA256 != loadContext.ticketSHA256 ||
			frame.PairCommitment != commitment.PairCommitmentSHA256 ||
			frame.BlockCommitment != commitment.BlockCommitmentSHA256 {
			clear(frame.Ciphertext)
			return nil, fmt.Errorf(
				"formal-glm registered Phase19 loader: frame is absent from its receipt")
		}
		block, decodeErr := formalGLMRegisteredPhase19DecodePrivateFrameV1(
			record, authorization, frame, recipientPrivateKey,
			loadContext.validationContext)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result = append(result, block)
	}
	return result, nil
}

// formalGLMLoadRegisteredPhase19PrivateBlockSetV1 is the bounded-memory
// ingress seam: it returns one private block for every custodian, never the
// historical source-major K×TotalBlocks materialization.
func formalGLMLoadRegisteredPhase19PrivateBlockSetV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
	store *formalGLMRegisteredPhase18IngressStoreV3,
	recipientPrivateKey []byte,
	blockIndex int,
) (result []formalGLMRegisteredPhase19PrivateBlockV1, err error) {
	if store == nil {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 loader: ingress store is unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	loadContext, err := formalGLMRegisteredPhase19PreparePrivateLoadLockedV1(
		record, store, recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	return formalGLMLoadRegisteredPhase19PrivateBlockSetLockedV1(
		record, store, recipientPrivateKey, loadContext, blockIndex)
}

func formalGLMLoadRegisteredPhase19PrivateBlocksV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
	store *formalGLMRegisteredPhase18IngressStoreV3,
	recipientPrivateKey []byte,
) (result []formalGLMRegisteredPhase19PrivateBlockV1, err error) {
	if store == nil {
		return nil, fmt.Errorf(
			"formal-glm registered Phase19 loader: ingress store is unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	defer func() {
		if err != nil {
			formalGLMRegisteredPhase19ClearPrivateBlocksV1(result)
			result = nil
		}
	}()
	loadContext, err := formalGLMRegisteredPhase19PreparePrivateLoadLockedV1(
		record, store, recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	plan := store.contract.Core.RegisteredExecutionPlan

	result = make([]formalGLMRegisteredPhase19PrivateBlockV1,
		len(plan.CustodianPeers)*plan.TotalBlocks)
	for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
		blockSet, loadErr := formalGLMLoadRegisteredPhase19PrivateBlockSetLockedV1(
			record, store, recipientPrivateKey, loadContext, blockIndex)
		if loadErr != nil {
			err = loadErr
			return
		}
		for sourceIndex := range blockSet {
			result[sourceIndex*plan.TotalBlocks+blockIndex] = blockSet[sourceIndex]
		}
	}
	return result, nil
}
