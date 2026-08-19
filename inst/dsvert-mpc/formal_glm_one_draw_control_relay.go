package main

// Closed encrypted relay for the signed records of the formal GLM one-draw
// lifecycle. Record selection and persistence are server-owned; this file only
// accepts the eight concrete record schemas and their fixed role directions.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

const (
	formalGLMOneDrawControlProtocol = "formal_glm_one_draw_lifecycle_control_v1"
	formalGLMControlEnvelopeVersion = "dsvert-formal-glm-one-draw-control-envelope-v1"
	formalGLMControlAADDomain       = "dsVert/formal-glm-one-draw-control/aad/v1|"
	formalGLMControlCipherDomain    = "dsVert/formal-glm-one-draw-control/ciphertext/v1|"
	formalGLMControlRecordDomain    = "dsVert/formal-glm-one-draw-control/record/v1|"

	formalGLMControlRecordStage           = "stage"
	formalGLMControlRecordTicket          = "ticket"
	formalGLMControlRecordSealReceipt     = "seal_receipt"
	formalGLMControlRecordCandidate       = "candidate"
	formalGLMControlRecordLocalRelease    = "local_release"
	formalGLMControlRecordBaseCertificate = "base_certificate"
	formalGLMControlRecordAuthorization   = "authorization"
	formalGLMControlRecordAck             = "ack"

	formalGLMControlMaxRecord   = formalGLMPhase21RockMaxRecord
	formalGLMControlMaxEnvelope = formalGLMControlMaxRecord + 8192
)

type formalGLMOneDrawControlAAD struct {
	Family              string `json:"family"`
	ArtifactID          string `json:"artifact_id"`
	PlanSHA256          string `json:"plan_sha256"`
	FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
	PinsetSHA256        string `json:"pinset_sha256"`
	TicketSHA256        string `json:"ticket_sha256"`
	SenderPeerName      string `json:"sender_peer_name"`
	SenderPeerID        string `json:"sender_peer_id"`
	SenderRole          string `json:"sender_role"`
	RecipientPeerName   string `json:"recipient_peer_name"`
	RecipientPeerID     string `json:"recipient_peer_id"`
	RecipientRole       string `json:"recipient_role"`
	RecordType          string `json:"record_type"`
}

type formalGLMOneDrawControlEnvelope struct {
	Version                     string                     `json:"version"`
	Protocol                    string                     `json:"protocol"`
	AAD                         formalGLMOneDrawControlAAD `json:"aad"`
	RecordSHA256                string                     `json:"record_sha256"`
	RecipientTransportKeySHA256 string                     `json:"recipient_transport_key_sha256"`
	CiphertextSHA256            string                     `json:"ciphertext_sha256"`
	Ciphertext                  []byte                     `json:"ciphertext"`
	ProductionReady             bool                       `json:"-"`
}

func formalGLMControlDirection(recordType, senderRole string) (
	string, error,
) {
	switch recordType {
	case formalGLMControlRecordStage,
		formalGLMControlRecordAuthorization:
		if senderRole == "garbler" {
			return "evaluator", nil
		}
		if senderRole == "evaluator" {
			return "garbler", nil
		}
	case formalGLMControlRecordTicket,
		formalGLMControlRecordCandidate,
		formalGLMControlRecordBaseCertificate,
		formalGLMControlRecordAck:
		if senderRole == "garbler" {
			return "evaluator", nil
		}
	case formalGLMControlRecordSealReceipt,
		formalGLMControlRecordLocalRelease:
		if senderRole == "evaluator" {
			return "garbler", nil
		}
	}
	return "", fmt.Errorf("formal-glm control: invalid record direction")
}

func formalGLMControlAADBytes(aad formalGLMOneDrawControlAAD) ([]byte, error) {
	encoded, err := json.Marshal(aad)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMControlAADDomain), encoded...), nil
}

func formalGLMControlSHA(domain string, value []byte) string {
	digest := sha256.Sum256(append([]byte(domain), value...))
	return hex.EncodeToString(digest[:])
}

func formalGLMControlDecodeCanonical(encoded []byte, value any) error {
	if len(encoded) < 64 || len(encoded) > formalGLMControlMaxRecord ||
		encoded[0] != '{' {
		return fmt.Errorf("formal-glm control: invalid record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("formal-glm control: invalid typed record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-glm control: trailing typed record")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("formal-glm control: non-canonical typed record")
	}
	return nil
}

func formalGLMControlValidateRecipientTransport(
	binding formalFinalizerHandoffBinding,
	recipientRole string, transportPublic, transportSignature []byte,
	pins map[string]ed25519.PublicKey,
) (formalFinalizerHandoffAuthority, error) {
	var zero formalFinalizerHandoffAuthority
	recipient, err := formalFinalizerHandoffPeer(binding, recipientRole)
	if err != nil || len(transportPublic) != 32 ||
		len(transportSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[recipient.PeerName], transportPublic,
			transportSignature) {
		return zero,
			fmt.Errorf("formal-glm control: recipient transport is not identity-bound")
	}
	peer, err := ecdh.X25519().NewPublicKey(transportPublic)
	if err != nil {
		return zero, fmt.Errorf("formal-glm control: invalid recipient transport")
	}
	probeSeed := sha256.Sum256([]byte(formalGLMControlAADDomain + "probe"))
	probe, probeErr := ecdh.X25519().NewPrivateKey(probeSeed[:])
	if probeErr != nil {
		return zero, fmt.Errorf("formal-glm control: invalid recipient transport")
	}
	if _, err := probe.ECDH(peer); err != nil {
		return zero, fmt.Errorf("formal-glm control: invalid recipient transport")
	}
	return recipient, nil
}

func formalGLMControlValidateAAD(binding formalFinalizerHandoffBinding,
	aad formalGLMOneDrawControlAAD,
) error {
	recipientRole, err := formalGLMControlDirection(
		aad.RecordType, aad.SenderRole)
	sender, senderErr := formalFinalizerHandoffPeer(binding, aad.SenderRole)
	recipient, recipientErr := formalFinalizerHandoffPeer(binding, recipientRole)
	if err != nil || senderErr != nil || recipientErr != nil ||
		aad.Family != formalFinalizerHandoffFamilyGLM ||
		aad.Family != binding.Family || aad.ArtifactID != binding.ArtifactID ||
		aad.PlanSHA256 != binding.PlanSHA256 ||
		aad.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		aad.PinsetSHA256 != binding.PinsetSHA256 ||
		aad.SenderPeerName != sender.PeerName ||
		aad.SenderPeerID != sender.PeerID ||
		aad.RecipientRole != recipientRole ||
		aad.RecipientPeerName != recipient.PeerName ||
		aad.RecipientPeerID != recipient.PeerID ||
		(aad.RecordType == formalGLMControlRecordStage &&
			aad.TicketSHA256 != "") ||
		(aad.RecordType != formalGLMControlRecordStage &&
			!formalGLMIsSHA256(aad.TicketSHA256)) {
		return fmt.Errorf("formal-glm control: invalid exact AAD binding")
	}
	return nil
}

func formalGLMControlValidateRecord(recordType, senderRole string,
	encoded []byte, binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	pins map[string]ed25519.PublicKey,
) (string, error) {
	if formalFinalizerHandoffValidateBinding(binding, pins) != nil ||
		binding.Family != formalFinalizerHandoffFamilyGLM ||
		binding.Purpose != formalFinalizerHandoffGLMPurpose {
		return "", fmt.Errorf("formal-glm control: invalid lifecycle binding")
	}
	sender, err := formalFinalizerHandoffPeer(binding, senderRole)
	if err != nil {
		return "", err
	}
	postTicket := recordType != formalGLMControlRecordStage
	ticketSHA := ""
	if postTicket {
		if formalFinalizerHandoffValidateTicket(ticket, binding, pins) != nil {
			return "", fmt.Errorf("formal-glm control: invalid lifecycle ticket")
		}
		ticketSHA, err = formalFinalizerHandoffTicketSHA256(ticket)
		if err != nil {
			return "", err
		}
	}
	validCommon := func(version, family, purpose, artifact, expectedPurpose string,
		production bool,
	) bool {
		return version == formalGLMPhase21RockRecordVersion &&
			family == formalFinalizerHandoffFamilyGLM &&
			purpose == expectedPurpose && artifact == binding.ArtifactID &&
			!production
	}
	switch recordType {
	case formalGLMControlRecordStage:
		var record formalGLMPhase21RockStageRecord
		if formalGLMControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalGLMPhase21RockStagePurpose,
				record.ProductionReady) ||
			!reflect.DeepEqual(record.Binding, binding) ||
			record.Receipt.PeerName != sender.PeerName ||
			record.Receipt.PeerID != sender.PeerID ||
			record.Receipt.Role != senderRole ||
			record.Receipt.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
			record.Receipt.PlanSHA256 != binding.PlanSHA256 {
			return "", fmt.Errorf("formal-glm control: invalid stage record")
		}
		message, messageErr := formalGLMPhase21RockStageMessage(record.Receipt)
		if messageErr != nil || len(record.Receipt.Signature) !=
			ed25519.SignatureSize || !ed25519.Verify(
			pins[sender.PeerName], message, record.Receipt.Signature) {
			return "", fmt.Errorf("formal-glm control: unsigned stage record")
		}
	case formalGLMControlRecordTicket:
		var record formalGLMPhase21RockTicketRecord
		if senderRole != "garbler" ||
			formalGLMControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalGLMPhase21RockTicketPurpose,
				record.ProductionReady) ||
			!reflect.DeepEqual(record.Binding, binding) ||
			!reflect.DeepEqual(record.Ticket, ticket) {
			return "", fmt.Errorf("formal-glm control: invalid ticket record")
		}
	case formalGLMControlRecordSealReceipt:
		var record formalGLMPhase21RockSealRecord
		if senderRole != "evaluator" ||
			formalGLMControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalGLMPhase21RockSealPurpose,
				record.ProductionReady) ||
			record.Receipt.TicketSHA256 != ticketSHA ||
			record.Receipt.PeerName != sender.PeerName ||
			record.Receipt.PeerID != sender.PeerID ||
			record.Receipt.Role != senderRole {
			return "", fmt.Errorf("formal-glm control: invalid seal receipt")
		}
		message, messageErr := formalGLMPhase21RockSealMessage(record.Receipt)
		if messageErr != nil || !ed25519.Verify(
			pins[sender.PeerName], message, record.Receipt.Signature) {
			return "", fmt.Errorf("formal-glm control: unsigned seal receipt")
		}
	case formalGLMControlRecordCandidate:
		var record formalGLMPhase21RockCandidateRecord
		if senderRole != "garbler" ||
			formalGLMControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalGLMPhase21RockCandidatePurpose,
				record.ProductionReady) ||
			record.Receipt.TicketSHA256 != ticketSHA ||
			record.Receipt.FinalizerPeerName != sender.PeerName ||
			record.Receipt.FinalizerPeerID != sender.PeerID ||
			record.Receipt.FinalizerRole != senderRole ||
			!formalGLMIsSHA256(record.Receipt.CandidateSHA256) {
			return "", fmt.Errorf("formal-glm control: invalid candidate record")
		}
		message, messageErr := formalGLMPhase21RockCandidateMessage(record.Receipt)
		if messageErr != nil || !ed25519.Verify(
			pins[sender.PeerName], message, record.Receipt.Signature) {
			return "", fmt.Errorf("formal-glm control: unsigned candidate record")
		}
	case formalGLMControlRecordLocalRelease:
		var record formalGLMPhase21RockLocalReleaseRecord
		if senderRole != "evaluator" ||
			formalGLMControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalGLMPhase21RockLocalReleasePurpose,
				record.ProductionReady) ||
			record.Binding.TicketSHA256 != ticketSHA ||
			record.Binding.PeerName != sender.PeerName ||
			record.Binding.PeerID != sender.PeerID ||
			record.Binding.Role != senderRole {
			return "", fmt.Errorf("formal-glm control: invalid local release record")
		}
		message, messageErr := formalGLMPhase21RockLocalReleaseMessage(record.Binding)
		if messageErr != nil || !ed25519.Verify(
			pins[sender.PeerName], message, record.Binding.Signature) {
			return "", fmt.Errorf("formal-glm control: unsigned local release record")
		}
	case formalGLMControlRecordBaseCertificate:
		var record formalGLMPhase21RockBaseCertificateRecord
		if senderRole != "garbler" ||
			formalGLMControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalGLMPhase21RockBaseCertificatePurpose,
				record.ProductionReady) ||
			record.Receipt.TicketSHA256 != ticketSHA ||
			record.Receipt.FinalizerPeerName != sender.PeerName ||
			record.Receipt.FinalizerPeerID != sender.PeerID ||
			record.Receipt.FinalizerRole != senderRole {
			return "", fmt.Errorf("formal-glm control: invalid base certificate")
		}
		message, messageErr := formalGLMPhase21RockBaseCertificateMessage(
			record.Receipt)
		if messageErr != nil || !ed25519.Verify(
			pins[sender.PeerName], message, record.Receipt.Signature) {
			return "", fmt.Errorf("formal-glm control: unsigned base certificate")
		}
	case formalGLMControlRecordAuthorization:
		var record formalGLMPhase21RockAuthorizationRecord
		if formalGLMControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalGLMPhase21RockAuthorizationPurpose,
				record.ProductionReady) || record.Role != senderRole ||
			record.IntentSHA256 != record.TransportAuthorization.IntentSHA256 ||
			formalFinalizerHandoffValidateIntentAuthorization(
				record.TransportAuthorization, binding, ticketSHA, pins) != nil {
			return "", fmt.Errorf("formal-glm control: invalid ordered authorization")
		}
	case formalGLMControlRecordAck:
		var record formalGLMPhase21RockAckRecord
		if senderRole != "garbler" ||
			formalGLMControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalGLMPhase21RockAckPurpose,
				record.ProductionReady) ||
			formalFinalizerHandoffValidateCommitProof(
				record.Proof, binding, ticketSHA, pins) != nil {
			return "", fmt.Errorf("formal-glm control: invalid terminal ACK")
		}
	default:
		return "", fmt.Errorf("formal-glm control: unknown record type")
	}
	return ticketSHA, nil
}

func formalGLMOneDrawControlSeal(binding formalFinalizerHandoffBinding,
	recordType, senderRole string, record []byte,
	ticket formalFinalizerHandoffTicket,
	recipientTransportPublic, recipientTransportSignature []byte,
	pins map[string]ed25519.PublicKey,
) (formalGLMOneDrawControlEnvelope, error) {
	var zero formalGLMOneDrawControlEnvelope
	recipientRole, err := formalGLMControlDirection(recordType, senderRole)
	if err != nil || len(record) > formalGLMControlMaxRecord {
		return zero, fmt.Errorf("formal-glm control: invalid seal request")
	}
	sender, senderErr := formalFinalizerHandoffPeer(binding, senderRole)
	recipient, recipientErr := formalGLMControlValidateRecipientTransport(
		binding, recipientRole, recipientTransportPublic,
		recipientTransportSignature, pins)
	ticketSHA, recordErr := formalGLMControlValidateRecord(
		recordType, senderRole, record, binding, ticket, pins)
	if senderErr != nil || recipientErr != nil || recordErr != nil {
		return zero, fmt.Errorf("formal-glm control: rejected typed source record")
	}
	aad := formalGLMOneDrawControlAAD{
		Family:     formalFinalizerHandoffFamilyGLM,
		ArtifactID: binding.ArtifactID, PlanSHA256: binding.PlanSHA256,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PinsetSHA256:        binding.PinsetSHA256, TicketSHA256: ticketSHA,
		SenderPeerName: sender.PeerName, SenderPeerID: sender.PeerID,
		SenderRole:        sender.Role,
		RecipientPeerName: recipient.PeerName,
		RecipientPeerID:   recipient.PeerID, RecipientRole: recipient.Role,
		RecordType: recordType,
	}
	aadBytes, err := formalGLMControlAADBytes(aad)
	if err != nil {
		return zero, err
	}
	defer clear(aadBytes)
	ciphertext, err := transportEncryptBytesAAD(
		record, recipientTransportPublic, aadBytes)
	if err != nil || len(ciphertext) > formalGLMControlMaxEnvelope {
		clear(ciphertext)
		return zero, fmt.Errorf("formal-glm control: control seal failed")
	}
	transportSHA := formalGLMControlSHA(
		formalGLMControlAADDomain+"recipient-key|", recipientTransportPublic)
	return formalGLMOneDrawControlEnvelope{
		Version:  formalGLMControlEnvelopeVersion,
		Protocol: formalGLMOneDrawControlProtocol, AAD: aad,
		RecordSHA256:                formalGLMControlSHA(formalGLMControlRecordDomain, record),
		RecipientTransportKeySHA256: transportSHA,
		CiphertextSHA256: formalGLMControlSHA(
			formalGLMControlCipherDomain, ciphertext),
		Ciphertext: append([]byte(nil), ciphertext...), ProductionReady: false,
	}, nil
}

func formalGLMOneDrawControlOpen(binding formalFinalizerHandoffBinding,
	envelope formalGLMOneDrawControlEnvelope,
	ticket formalFinalizerHandoffTicket, recipientTransportSecret []byte,
	pins map[string]ed25519.PublicKey,
) ([]byte, error) {
	if envelope.Version != formalGLMControlEnvelopeVersion ||
		envelope.Protocol != formalGLMOneDrawControlProtocol ||
		envelope.ProductionReady || len(envelope.Ciphertext) < 60 ||
		len(envelope.Ciphertext) > formalGLMControlMaxEnvelope ||
		!formalGLMIsSHA256(envelope.RecordSHA256) ||
		envelope.CiphertextSHA256 != formalGLMControlSHA(
			formalGLMControlCipherDomain, envelope.Ciphertext) ||
		formalGLMControlValidateAAD(binding, envelope.AAD) != nil ||
		len(recipientTransportSecret) != 32 {
		return nil, fmt.Errorf("formal-glm control: invalid sealed envelope")
	}
	secret, err := ecdh.X25519().NewPrivateKey(recipientTransportSecret)
	if err != nil || envelope.RecipientTransportKeySHA256 !=
		formalGLMControlSHA(formalGLMControlAADDomain+"recipient-key|",
			secret.PublicKey().Bytes()) {
		return nil, fmt.Errorf("formal-glm control: wrong recipient transport")
	}
	recipient, err := formalFinalizerHandoffPeer(
		binding, envelope.AAD.RecipientRole)
	if err != nil || recipient.PeerName != envelope.AAD.RecipientPeerName ||
		recipient.PeerID != envelope.AAD.RecipientPeerID {
		return nil, fmt.Errorf("formal-glm control: wrong recipient authority")
	}
	if envelope.AAD.RecordType == formalGLMControlRecordStage {
		if envelope.AAD.TicketSHA256 != "" {
			return nil, fmt.Errorf("formal-glm control: pre-ticket stage was ticket-bound")
		}
	} else if envelope.AAD.RecordType != formalGLMControlRecordTicket {
		ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
		if ticketErr != nil ||
			formalFinalizerHandoffValidateTicket(ticket, binding, pins) != nil ||
			!hmac.Equal([]byte(ticketSHA), []byte(envelope.AAD.TicketSHA256)) {
			return nil, fmt.Errorf("formal-glm control: ticket binding mismatch")
		}
	}
	aadBytes, err := formalGLMControlAADBytes(envelope.AAD)
	if err != nil {
		return nil, err
	}
	defer clear(aadBytes)
	plaintext, err := transportDecryptBytesAAD(
		envelope.Ciphertext, recipientTransportSecret, aadBytes)
	if err != nil {
		return nil, fmt.Errorf("formal-glm control: authenticated open failed")
	}
	defer clear(plaintext)
	if envelope.RecordSHA256 != formalGLMControlSHA(
		formalGLMControlRecordDomain, plaintext) {
		return nil, fmt.Errorf("formal-glm control: record hash mismatch")
	}
	if envelope.AAD.RecordType == formalGLMControlRecordTicket {
		var record formalGLMPhase21RockTicketRecord
		if formalGLMControlDecodeCanonical(plaintext, &record) != nil {
			return nil, fmt.Errorf("formal-glm control: invalid encrypted ticket")
		}
		ticket = record.Ticket
		ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
		if ticketErr != nil ||
			formalFinalizerHandoffValidateTicket(ticket, binding, pins) != nil ||
			!hmac.Equal([]byte(ticketSHA), []byte(envelope.AAD.TicketSHA256)) {
			return nil, fmt.Errorf("formal-glm control: ticket binding mismatch")
		}
	}
	if _, err := formalGLMControlValidateRecord(
		envelope.AAD.RecordType, envelope.AAD.SenderRole, plaintext,
		binding, ticket, pins); err != nil {
		return nil, err
	}
	return append([]byte(nil), plaintext...), nil
}
