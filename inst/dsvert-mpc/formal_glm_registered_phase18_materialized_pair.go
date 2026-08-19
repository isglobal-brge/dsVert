package main

// This file turns one already-attested, source-local materialized block into
// the two encrypted registered Phase-1.8 recipient envelopes. It does not
// attest source data, persist ingress, mint receipts, or advance Phase-1.9.

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

func formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	values []string,
	validity []bool,
	privateConsensus []byte,
	sourcePrivateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18BlockPairV1, error) {
	return formalGLMRegisteredPhase18BuildMaterializedBlockPairWithRandomnessV3(
		contract, authorization, tickets, blockIndex, values, validity,
		privateConsensus, sourcePrivateKey, pins, crand.Reader,
		transportEncryptBytes)
}

// The injected dependencies are private test seams. Production callers use
// formalGLMRegisteredPhase18BuildMaterializedBlockPairV3 above.
func formalGLMRegisteredPhase18BuildMaterializedBlockPairWithRandomnessV3(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	values []string,
	validity []bool,
	privateConsensus []byte,
	sourcePrivateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
	randomness io.Reader,
	encryptor func([]byte, []byte) ([]byte, error),
) (formalGLMRegisteredPhase18BlockPairV1, error) {
	var zero formalGLMRegisteredPhase18BlockPairV1
	if randomness == nil || encryptor == nil || len(privateConsensus) != 32 {
		return zero, fmt.Errorf(
			"formal-glm: invalid registered Phase-1.8 private materialization input")
	}
	if err := formalGLMValidateRegisteredPhase18AuthorizationV1(
		authorization, contract, pins); err != nil {
		return zero, err
	}
	orderedTickets, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		tickets, contract, pins)
	if err != nil {
		return zero, err
	}
	source := authorization.LocalSource.SignerPeerName
	if len(sourcePrivateKey) != ed25519.PrivateKeySize ||
		len(pins[source]) != ed25519.PublicKeySize ||
		!bytes.Equal(sourcePrivateKey.Public().(ed25519.PublicKey), pins[source]) {
		return zero, fmt.Errorf(
			"formal-glm: invalid registered Phase-1.8 materialization signer")
	}
	offset, slots, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, blockIndex)
	if err != nil {
		return zero, err
	}
	geometry := authorization.Geometry
	coordinateRecords := slots * geometry.CoordinateCount
	if len(values) != coordinateRecords || len(validity) != slots {
		return zero, fmt.Errorf(
			"formal-glm: invalid registered Phase-1.8 materialized block shape")
	}
	sourceSlot := -1
	for index, peer := range authorization.CustodianPeers {
		if peer == source {
			sourceSlot = index
			break
		}
	}
	if sourceSlot < 0 {
		return zero, fmt.Errorf(
			"formal-glm: registered Phase-1.8 materialization source is not pinned")
	}

	modulus := exactGCModulus(geometry.RingBits)
	half := new(big.Int).Rsh(new(big.Int).Set(modulus), 1)
	maximum := new(big.Int).Sub(new(big.Int).Set(half), big.NewInt(1))
	minimum := new(big.Int).Neg(new(big.Int).Set(half))
	residues := make([]*big.Int, coordinateRecords)
	for index, text := range values {
		signed, parseErr := formalGLMCanonicalSigned(
			text, fmt.Sprintf("registered Phase-1.8 value[%d]", index))
		if parseErr != nil || signed.Cmp(minimum) < 0 || signed.Cmp(maximum) > 0 {
			return zero, fmt.Errorf(
				"formal-glm: registered Phase-1.8 value is outside its signed ring")
		}
		row := index / geometry.CoordinateCount
		coordinate := index % geometry.CoordinateCount
		globalSlot := offset + row
		if (globalSlot >= geometry.TotalCapacity || !validity[row] ||
			geometry.CoordinateOwners[coordinate] != source) && signed.Sign() != 0 {
			return zero, fmt.Errorf(
				"formal-glm: nonzero unowned, invalid, or padded Phase-1.8 value")
		}
		residues[index] = new(big.Int).Mod(signed, modulus)
	}
	for row, valid := range validity {
		if offset+row >= geometry.TotalCapacity && valid {
			return zero, fmt.Errorf(
				"formal-glm: registered Phase-1.8 padding cannot be valid")
		}
	}

	coordinateShares := [2][]*big.Int{
		make([]*big.Int, coordinateRecords),
		make([]*big.Int, coordinateRecords),
	}
	for index, residue := range residues {
		maskBytes := make([]byte, geometry.RecordBytes)
		if _, err := io.ReadFull(randomness, maskBytes); err != nil {
			return zero, fmt.Errorf(
				"formal-glm: generate registered Phase-1.8 coordinate share: %w", err)
		}
		usedBytes := (geometry.RingBits + 7) / 8
		for byteIndex := usedBytes; byteIndex < len(maskBytes); byteIndex++ {
			maskBytes[byteIndex] = 0
		}
		if remainder := geometry.RingBits % 8; remainder != 0 {
			maskBytes[usedBytes-1] &= byte((1 << uint(remainder)) - 1)
		}
		left := exactGCLittleEndianBig(maskBytes)
		clear(maskBytes)
		right := new(big.Int).Mod(
			new(big.Int).Sub(residue, left), modulus)
		coordinateShares[0][index] = left
		coordinateShares[1][index] = right
	}
	validityShares := [2][]byte{make([]byte, slots), make([]byte, slots)}
	for index, valid := range validity {
		var random [1]byte
		if _, err := io.ReadFull(randomness, random[:]); err != nil {
			return zero, fmt.Errorf(
				"formal-glm: generate registered Phase-1.8 validity share: %w", err)
		}
		validityShares[0][index] = random[0] & 1
		validityShares[1][index] = validityShares[0][index]
		if valid {
			validityShares[1][index] ^= 1
		}
	}
	var gateRandom [1]byte
	if _, err := io.ReadFull(randomness, gateRandom[:]); err != nil {
		return zero, fmt.Errorf(
			"formal-glm: generate registered Phase-1.8 gate share: %w", err)
	}
	gateShares := [2]byte{gateRandom[0] & 1, (gateRandom[0] & 1) ^ 1}
	consensusShares := [2][]byte{make([]byte, 32), make([]byte, 32)}
	if _, err := io.ReadFull(randomness, consensusShares[0]); err != nil {
		return zero, fmt.Errorf(
			"formal-glm: generate registered Phase-1.8 consensus share: %w", err)
	}
	for index := range privateConsensus {
		consensusShares[1][index] =
			consensusShares[0][index] ^ privateConsensus[index]
	}

	placeholder := func(label string) string {
		digest := sha256.Sum256([]byte(
			"dsVert/formal-glm/registered-phase18/private-precommit/v3|" +
				authorization.AuthorizationSHA256 + "|" + label))
		return hex.EncodeToString(digest[:])
	}
	ciphertexts := make(map[string][]byte, 2)
	for recipientSlot, ticket := range orderedTickets {
		ticketSHA256, hashErr :=
			formalGLMRegisteredPhase18RecipientTicketSHA256V1(ticket)
		if hashErr != nil {
			return zero, hashErr
		}
		frame := formalGLMRegisteredPhase18IngressFrameV3{
			ArtifactID:                           authorization.ArtifactID,
			SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
			SourceContractSHA256:                 authorization.SourceContractSHA256,
			RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
			RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
			Source:                               source,
			Recipient:                            ticket.RecipientName,
			RecipientTicketSHA256:                ticketSHA256,
			PairCommitment:                       placeholder("pair"),
			BlockCommitment:                      placeholder("block"),
			SourceSlot:                           sourceSlot,
			RecipientSlot:                        recipientSlot,
			BlockIndex:                           blockIndex,
			TotalBlocks:                          geometry.TotalBlocks,
			GlobalSlotOffset:                     offset,
			SlotsInBlock:                         slots,
			CoordinateCount:                      geometry.CoordinateCount,
			CoordinateRecords:                    coordinateRecords,
			RingBits:                             geometry.RingBits,
			RecordBytes:                          geometry.RecordBytes,
			ValidityRecords:                      slots,
		}
		role := "garbler"
		if recipientSlot == 1 {
			role = "evaluator"
		}
		header := formalGLMRegisteredPhase18PrivateBlockHeaderV3{
			AlignmentSharing:                     authorization.AlignmentSharing,
			ArtifactID:                           frame.ArtifactID,
			BlockIndex:                           blockIndex,
			CoordinateCount:                      geometry.CoordinateCount,
			CoordinateEncoding:                   authorization.CoordinateEncoding,
			CoordinateShareBytes:                 coordinateRecords * geometry.RecordBytes,
			GlobalSlotOffset:                     offset,
			OpeningsPerformed:                    0,
			Phase19RequiredOperation:             formalGLMPhase18RequiredOperation,
			PrivateAlignmentConsensusShare:       base64.RawURLEncoding.EncodeToString(consensusShares[recipientSlot]),
			PrivateAlignmentGateShare:            int(gateShares[recipientSlot]),
			ProductionReady:                      false,
			Purpose:                              formalGLMRegisteredPhase18PrivateBlockPurposeV3,
			RecipientName:                        ticket.RecipientName,
			RecipientRole:                        role,
			RecipientTicketSHA256:                ticketSHA256,
			RecordBytes:                          geometry.RecordBytes,
			RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
			RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
			RingBits:                             geometry.RingBits,
			SlotsInBlock:                         slots,
			SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
			SourceContractSHA256:                 authorization.SourceContractSHA256,
			SourceName:                           source,
			SourceSlot:                           sourceSlot,
			TotalBlocks:                          geometry.TotalBlocks,
			ValidityShareBytes:                   slots,
			ValiditySharing:                      authorization.ValiditySharing,
			Version:                              formalGLMRegisteredPhase18PrivateBlockVersionV3,
		}
		plaintext, encodeErr := formalGLMRegisteredPhase18EncodePrivateBlockV3(
			header, coordinateShares[recipientSlot],
			validityShares[recipientSlot], frame, contract, authorization, pins)
		if encodeErr != nil {
			return zero, encodeErr
		}
		ciphertext, encryptErr := encryptor(plaintext, ticket.TransportPK)
		clear(plaintext)
		if encryptErr != nil {
			return zero, fmt.Errorf(
				"formal-glm: encrypt registered Phase-1.8 private block: %w",
				encryptErr)
		}
		ciphertexts[ticket.RecipientName] = ciphertext
	}
	pair, err := formalGLMRegisteredPhase18BuildBlockPairV1(
		contract, authorization, orderedTickets, blockIndex, ciphertexts,
		sourcePrivateKey, pins)
	if err != nil {
		return zero, err
	}
	return pair, nil
}
