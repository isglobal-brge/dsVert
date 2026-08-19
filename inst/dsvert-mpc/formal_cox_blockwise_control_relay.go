package main

// Closed encrypted relay contract for the formal Cox blockwise lifecycle.
// The Rock-owned store selects one of the nine concrete record schemas below;
// callers never select a record kind, path, role, or lifecycle action.

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
	formalCoxBlockwiseControlProtocol = "formal_cox_blockwise_lifecycle_control_v1"
	formalCoxControlEnvelopeVersion   = "dsvert-formal-cox-blockwise-control-envelope-v1"
	formalCoxControlContextVersion    = "dsvert-formal-cox-blockwise-control-execution-v1"
	formalCoxControlAADDomain         = "dsVert/formal-cox/blockwise-control/aad/v1|"
	formalCoxControlCipherDomain      = "dsVert/formal-cox/blockwise-control/ciphertext/v1|"
	formalCoxControlRecordDomain      = "dsVert/formal-cox/blockwise-control/record/v1|"
	formalCoxControlExecutionDomain   = "dsVert/formal-cox/blockwise-control/execution/v1|"

	formalCoxControlRecordPreflight     = "preflight"
	formalCoxControlRecordHeader        = "header"
	formalCoxControlRecordTicket        = "ticket"
	formalCoxControlRecordEnvelope      = "envelope"
	formalCoxControlRecordCandidate     = "candidate"
	formalCoxControlRecordAuthorization = "authorization"
	formalCoxControlRecordPublication   = "publication"
	formalCoxControlRecordCommit        = "commit"
	formalCoxControlRecordAck           = "ack"

	formalCoxControlMaxRecord   = formalCoxBlockwiseRockMaxRecord
	formalCoxControlMaxEnvelope = formalCoxControlMaxRecord + 8192
)

type formalCoxBlockwiseControlContext struct {
	Version         string                            `json:"version"`
	Family          string                            `json:"family"`
	Purpose         string                            `json:"purpose"`
	ArtifactID      string                            `json:"artifact_id"`
	PlanSHA256      string                            `json:"plan_sha256"`
	RunID           string                            `json:"run_id"`
	ExecutionSHA256 string                            `json:"execution_sha256"`
	PinsetSHA256    string                            `json:"pinset_sha256"`
	Authorities     []formalFinalizerHandoffAuthority `json:"authorities"`
	Finalizer       formalFinalizerHandoffAuthority   `json:"finalizer"`
	ProductionReady bool                              `json:"-"`

	plan     formalCoxBlockwisePlan
	artifact formalCoxBlockwiseStickyArtifact
	pins     map[string]ed25519.PublicKey
}

type formalCoxBlockwiseControlAAD struct {
	Family              string `json:"family"`
	ArtifactID          string `json:"artifact_id"`
	PlanSHA256          string `json:"plan_sha256"`
	RunID               string `json:"run_id"`
	ExecutionSHA256     string `json:"execution_sha256"`
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
	RecordSHA256        string `json:"record_sha256"`
}

type formalCoxBlockwiseControlEnvelope struct {
	Version                     string                       `json:"version"`
	Protocol                    string                       `json:"protocol"`
	AAD                         formalCoxBlockwiseControlAAD `json:"aad"`
	RecipientTransportKeySHA256 string                       `json:"recipient_transport_key_sha256"`
	CiphertextSHA256            string                       `json:"ciphertext_sha256"`
	Ciphertext                  []byte                       `json:"ciphertext"`
	ProductionReady             bool                         `json:"-"`
}

// Related records are loaded from fixed Rock-local lifecycle slots. They are
// never decoded from an analyst request or carried in the outer envelope.
type formalCoxBlockwiseControlRelated struct {
	Candidate            *formalCoxBlockwiseRockCandidateRecord
	GarblerAuthorization *formalCoxBlockwiseRockAuthorizationRecord
	Publication          *formalCoxBlockwiseRockPublicationRecord
}

func formalCoxControlSHA(domain string, value []byte) string {
	digest := sha256.Sum256(append([]byte(domain), value...))
	return hex.EncodeToString(digest[:])
}

func formalCoxControlContextFor(plan formalCoxBlockwisePlan,
	pins map[string]ed25519.PublicKey,
) (formalCoxBlockwiseControlContext, error) {
	var zero formalCoxBlockwiseControlContext
	artifact, artifactID, err := formalCoxBlockwiseBuildStickyArtifact(plan, pins)
	if err != nil || len(artifact.NoiseAuthorities) != 2 {
		return zero, fmt.Errorf("formal-cox control: invalid execution context")
	}
	planSHA, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil || !formalCoxIsSHA256(plan.RunID) ||
		!formalCoxIsSHA256(planSHA) || !formalCoxIsSHA256(artifact.PinsetSHA256) {
		return zero, fmt.Errorf("formal-cox control: invalid execution context")
	}
	authorities := make([]formalFinalizerHandoffAuthority, 2)
	for index, authority := range artifact.NoiseAuthorities {
		authorities[index] = formalFinalizerHandoffAuthority{
			PeerName: authority.PeerName, PeerID: authority.PeerID,
			Role: authority.Role,
		}
	}
	executionJSON, err := json.Marshal(struct {
		ArtifactID   string                            `json:"artifact_id"`
		PlanSHA256   string                            `json:"plan_sha256"`
		RunID        string                            `json:"run_id"`
		PinsetSHA256 string                            `json:"pinset_sha256"`
		Authorities  []formalFinalizerHandoffAuthority `json:"authorities"`
	}{artifactID, planSHA, plan.RunID, artifact.PinsetSHA256, authorities})
	if err != nil {
		return zero, err
	}
	executionSHA := formalCoxControlSHA(
		formalCoxControlExecutionDomain, executionJSON)
	clear(executionJSON)
	copyPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		copyPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return formalCoxBlockwiseControlContext{
		Version:    formalCoxControlContextVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalFinalizerHandoffCoxPurpose,
		ArtifactID: artifactID, PlanSHA256: planSHA, RunID: plan.RunID,
		ExecutionSHA256: executionSHA, PinsetSHA256: artifact.PinsetSHA256,
		Authorities: authorities, Finalizer: authorities[0],
		ProductionReady: false, plan: plan, artifact: artifact, pins: copyPins,
	}, nil
}

func formalCoxControlDirection(recordType, senderRole string) (string, error) {
	switch recordType {
	case formalCoxControlRecordPreflight, formalCoxControlRecordHeader,
		formalCoxControlRecordAuthorization:
		if senderRole == "garbler" {
			return "evaluator", nil
		}
		if senderRole == "evaluator" {
			return "garbler", nil
		}
	case formalCoxControlRecordTicket, formalCoxControlRecordCandidate,
		formalCoxControlRecordPublication, formalCoxControlRecordAck:
		if senderRole == "garbler" {
			return "evaluator", nil
		}
	case formalCoxControlRecordEnvelope, formalCoxControlRecordCommit:
		if senderRole == "evaluator" {
			return "garbler", nil
		}
	}
	return "", fmt.Errorf("formal-cox control: invalid record direction")
}

func formalCoxControlAuthority(context formalCoxBlockwiseControlContext,
	role string,
) (formalFinalizerHandoffAuthority, error) {
	for _, authority := range context.Authorities {
		if authority.Role == role {
			return authority, nil
		}
	}
	return formalFinalizerHandoffAuthority{},
		fmt.Errorf("formal-cox control: invalid authority role")
}

func formalCoxControlValidateAAD(context formalCoxBlockwiseControlContext,
	aad formalCoxBlockwiseControlAAD,
) error {
	recipientRole, directionErr := formalCoxControlDirection(
		aad.RecordType, aad.SenderRole)
	sender, senderErr := formalCoxControlAuthority(context, aad.SenderRole)
	recipient, recipientErr := formalCoxControlAuthority(context, recipientRole)
	preTicket := aad.RecordType == formalCoxControlRecordPreflight ||
		aad.RecordType == formalCoxControlRecordHeader
	if directionErr != nil || senderErr != nil || recipientErr != nil ||
		context.Version != formalCoxControlContextVersion ||
		context.Family != formalFinalizerHandoffFamilyCox ||
		context.Purpose != formalFinalizerHandoffCoxPurpose ||
		context.ProductionReady || aad.Family != context.Family ||
		aad.ArtifactID != context.ArtifactID ||
		aad.PlanSHA256 != context.PlanSHA256 || aad.RunID != context.RunID ||
		aad.ExecutionSHA256 != context.ExecutionSHA256 ||
		aad.PinsetSHA256 != context.PinsetSHA256 ||
		aad.SenderPeerName != sender.PeerName ||
		aad.SenderPeerID != sender.PeerID ||
		aad.RecipientRole != recipientRole ||
		aad.RecipientPeerName != recipient.PeerName ||
		aad.RecipientPeerID != recipient.PeerID ||
		!formalCoxIsSHA256(aad.RecordSHA256) ||
		(preTicket && (aad.FinalPairRootSHA256 != "" || aad.TicketSHA256 != "")) ||
		(!preTicket && (!formalCoxIsSHA256(aad.FinalPairRootSHA256) ||
			!formalCoxIsSHA256(aad.TicketSHA256))) {
		return fmt.Errorf("formal-cox control: invalid exact AAD binding")
	}
	return nil
}

func formalCoxControlAADBytes(aad formalCoxBlockwiseControlAAD) ([]byte, error) {
	encoded, err := json.Marshal(aad)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxControlAADDomain), encoded...), nil
}

func formalCoxControlDecodeCanonical(encoded []byte, value any) error {
	if len(encoded) < 64 || len(encoded) > formalCoxControlMaxRecord ||
		encoded[0] != '{' {
		return fmt.Errorf("formal-cox control: invalid record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("formal-cox control: invalid typed record")
	}
	var trailing any
	canonical, err := json.Marshal(value)
	if decoder.Decode(&trailing) != io.EOF || err != nil ||
		!bytes.Equal(canonical, encoded) {
		clear(canonical)
		return fmt.Errorf("formal-cox control: non-canonical typed record")
	}
	clear(canonical)
	return nil
}

func formalCoxControlValidateBinding(
	context formalCoxBlockwiseControlContext,
	binding formalFinalizerHandoffBinding,
) error {
	if formalFinalizerHandoffValidateBinding(binding, context.pins) != nil ||
		binding.Family != context.Family || binding.Purpose != context.Purpose ||
		binding.ArtifactID != context.ArtifactID ||
		binding.PlanSHA256 != context.PlanSHA256 ||
		binding.PinsetSHA256 != context.PinsetSHA256 ||
		!reflect.DeepEqual(binding.Authorities, context.Authorities) ||
		!formalFinalizerHandoffAuthorityEqual(binding.Finalizer,
			context.Finalizer) {
		return fmt.Errorf("formal-cox control: invalid lifecycle binding")
	}
	return nil
}

func formalCoxControlRockContext(
	context formalCoxBlockwiseControlContext,
) formalCoxBlockwiseRockContext {
	return formalCoxBlockwiseRockContext{
		plan: context.plan, pins: context.pins, artifact: context.artifact,
		artifactID: context.ArtifactID,
	}
}

func formalCoxControlValidateRecord(
	context formalCoxBlockwiseControlContext,
	binding formalFinalizerHandoffBinding, recordType, senderRole string,
	encoded []byte, ticket formalFinalizerHandoffTicket,
	related formalCoxBlockwiseControlRelated,
) (string, error) {
	if _, err := formalCoxControlDirection(recordType, senderRole); err != nil {
		return "", err
	}
	preTicket := recordType == formalCoxControlRecordPreflight ||
		recordType == formalCoxControlRecordHeader
	ticketSHA := ""
	if !preTicket {
		if formalCoxControlValidateBinding(context, binding) != nil ||
			formalFinalizerHandoffValidateTicket(
				ticket, binding, context.pins) != nil {
			return "", fmt.Errorf("formal-cox control: invalid lifecycle ticket")
		}
		var err error
		ticketSHA, err = formalFinalizerHandoffTicketSHA256(ticket)
		if err != nil {
			return "", err
		}
	}
	validCommon := func(version, family, purpose, artifact, wantPurpose string,
		production bool,
	) bool {
		return version == formalCoxBlockwiseRockRecordVersion &&
			family == formalFinalizerHandoffFamilyCox && purpose == wantPurpose &&
			artifact == context.ArtifactID && !production
	}
	sender, err := formalCoxControlAuthority(context, senderRole)
	if err != nil {
		return "", err
	}
	switch recordType {
	case formalCoxControlRecordPreflight:
		var record formalCoxBlockwiseRockPreflightRecord
		if formalCoxControlDecodeCanonical(encoded, &record) != nil ||
			record.Version != formalCoxBlockwiseRockRecordVersion ||
			record.Family != formalFinalizerHandoffFamilyCox ||
			record.Purpose != formalCoxBlockwiseRockPreflightPurpose ||
			record.ProductionReady ||
			record.Receipt.Version != formalCoxBlockwiseRockRecordVersion ||
			record.Receipt.Purpose != formalCoxBlockwiseRockPreflightPurpose ||
			record.Receipt.ArtifactID != context.ArtifactID ||
			record.Receipt.PinsetSHA256 != context.PinsetSHA256 ||
			record.Receipt.PeerName != sender.PeerName ||
			record.Receipt.PeerID != sender.PeerID ||
			record.Receipt.Role != senderRole || record.Receipt.ProductionReady {
			return "", fmt.Errorf("formal-cox control: invalid preflight record")
		}
		message, messageErr := formalCoxBlockwiseRockPreflightMessage(record.Receipt)
		if messageErr != nil || len(record.Receipt.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(context.pins[sender.PeerName],
				message, record.Receipt.Signature) {
			return "", fmt.Errorf("formal-cox control: unsigned preflight record")
		}
		switch record.Receipt.State {
		case formalCoxBlockwiseRockStateAbsent:
			if record.Receipt.CertificateSHA256 != "" || record.Publication != nil {
				return "", fmt.Errorf("formal-cox control: invalid absent preflight")
			}
		case formalCoxBlockwiseRockStatePublished:
			if record.Publication == nil ||
				record.Receipt.CertificateSHA256 != record.Publication.CertificateSHA256 {
				return "", fmt.Errorf("formal-cox control: invalid published preflight")
			}
			if _, err := formalCoxBlockwiseRockValidatePublication(
				*record.Publication, formalCoxControlRockContext(context)); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("formal-cox control: invalid preflight state")
		}
	case formalCoxControlRecordHeader:
		var record formalCoxBlockwiseRockHeaderRecord
		validator := &formalCoxBlockwiseOpeningStore{
			plan: context.plan, planSHA256: context.PlanSHA256,
			pins: context.pins, artifact: context.artifact,
			artifactID: context.ArtifactID,
		}
		if formalCoxControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalCoxBlockwiseRockPurpose,
				record.ProductionReady) ||
			record.Header.PeerName != sender.PeerName ||
			record.Header.PeerID != sender.PeerID ||
			record.Header.Role != senderRole ||
			validator.validateHandoffHeader(record.Header) != nil {
			return "", fmt.Errorf("formal-cox control: invalid signed header record")
		}
	case formalCoxControlRecordTicket:
		var record formalCoxBlockwiseRockTicketRecord
		if senderRole != "garbler" ||
			formalCoxControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalCoxBlockwiseRockPurpose,
				record.ProductionReady) ||
			!reflect.DeepEqual(record.Ticket, ticket) {
			return "", fmt.Errorf("formal-cox control: invalid ticket record")
		}
	case formalCoxControlRecordEnvelope:
		var record formalCoxBlockwiseRockEnvelopeRecord
		if senderRole != "evaluator" ||
			formalCoxControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalCoxBlockwiseRockPurpose,
				record.ProductionReady) || record.Role != senderRole ||
			record.Envelope.SenderRole != senderRole ||
			record.Envelope.SenderPeerName != sender.PeerName ||
			record.Envelope.SenderPeerID != sender.PeerID ||
			record.Envelope.PayloadKind != formalFinalizerHandoffCoxOpeningKind ||
			formalFinalizerHandoffValidateEnvelope(
				binding, ticket, record.Envelope, context.pins) != nil {
			return "", fmt.Errorf("formal-cox control: invalid evaluator envelope")
		}
	case formalCoxControlRecordCandidate:
		var record formalCoxBlockwiseRockCandidateRecord
		wantIntent := formalCoxBlockwiseOpeningIntent{}
		var intentErr error
		if formalCoxControlDecodeCanonical(encoded, &record) == nil {
			wantIntent, intentErr = formalCoxBlockwiseOpeningIntentFor(
				record.Candidate)
		}
		if senderRole != "garbler" ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalCoxBlockwiseRockPurpose,
				record.ProductionReady) || intentErr != nil ||
			record.Candidate.ArtifactID != context.ArtifactID ||
			record.Candidate.PlanSHA256 != context.PlanSHA256 ||
			record.Candidate.FinalPairRootSHA256 !=
				binding.FinalPairRootSHA256 ||
			formalCoxBlockwiseValidateOpeningCandidateCore(
				record.Candidate, context.pins) != nil ||
			!formalCoxBlockwiseOpeningEqual(record.Intent, wantIntent) {
			return "", fmt.Errorf("formal-cox control: invalid candidate record")
		}
	case formalCoxControlRecordAuthorization:
		var record formalCoxBlockwiseRockAuthorizationRecord
		if formalCoxControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalCoxBlockwiseRockPurpose,
				record.ProductionReady) || record.Role != senderRole ||
			record.Authorization.Version !=
				formalCoxBlockwiseRemoteOpeningAuthorizationVersion ||
			record.Authorization.Purpose !=
				formalCoxBlockwiseRemoteOpeningAuthorizationPurpose ||
			record.Authorization.ArtifactID != context.ArtifactID ||
			record.Authorization.FinalPairRootSHA256 !=
				binding.FinalPairRootSHA256 ||
			record.Authorization.ProductionReady || related.Candidate == nil {
			return "", fmt.Errorf("formal-cox control: invalid authorization record")
		}
		intent := related.Candidate.Intent
		intentSHA, hashErr := formalCoxBlockwiseDistributedOpeningIntentSHA256(intent)
		transport := record.Authorization.TransportAuthorization
		if hashErr != nil || record.Authorization.IntentSHA256 != intentSHA ||
			transport.SignerRole != senderRole ||
			transport.SignerPeerName != sender.PeerName ||
			transport.SignerPeerID != sender.PeerID ||
			transport.IntentSHA256 != intentSHA ||
			formalFinalizerHandoffValidateIntentAuthorization(
				transport, binding, ticketSHA, context.pins) != nil ||
			record.Authorization.OpeningReceipt.Signer != sender.PeerName {
			return "", fmt.Errorf("formal-cox control: invalid ordered authorization")
		}
		receipts := []jointDPBiomedicalGaussianSignature{
			record.Authorization.OpeningReceipt}
		position := 0
		if senderRole == "garbler" {
			if transport.PredecessorReceiptSHA256 != "" {
				return "", fmt.Errorf("formal-cox control: garbler authorization has predecessor")
			}
		} else {
			position = 1
			predecessor := related.GarblerAuthorization
			if predecessor == nil {
				return "", fmt.Errorf("formal-cox control: evaluator authorization lacks predecessor")
			}
			prior := predecessor.Authorization
			priorTransport := prior.TransportAuthorization
			priorSHA, priorErr := formalFinalizerHandoffIntentSHA256(priorTransport)
			if priorErr != nil || predecessor.Role != "garbler" ||
				prior.IntentSHA256 != intentSHA ||
				priorTransport.SignerRole != "garbler" ||
				formalFinalizerHandoffValidateIntentAuthorization(
					priorTransport, binding, ticketSHA, context.pins) != nil ||
				transport.PredecessorReceiptSHA256 != priorSHA {
				return "", fmt.Errorf("formal-cox control: evaluator authorization predecessor mismatch")
			}
			receipts = []jointDPBiomedicalGaussianSignature{
				prior.OpeningReceipt, record.Authorization.OpeningReceipt}
			wantOpeningSHA, openingErr := formalCoxBlockwiseOpeningReceiptSHA256(
				prior.OpeningReceipt)
			message, messageErr := formalCoxBlockwiseOpeningAuthorityMessage(
				intent, sender.PeerName, senderRole, wantOpeningSHA)
			if openingErr != nil || messageErr != nil ||
				!ed25519.Verify(context.pins[sender.PeerName], message,
					record.Authorization.OpeningReceipt.Signature) {
				return "", fmt.Errorf("formal-cox control: evaluator opening predecessor mismatch")
			}
		}
		if formalCoxBlockwiseValidateOpeningReceiptAt(
			intent, receipts, position, context.artifact, context.pins) != nil {
			return "", fmt.Errorf("formal-cox control: invalid ordered opening receipt")
		}
	case formalCoxControlRecordPublication:
		var record formalCoxBlockwiseRockPublicationRecord
		if senderRole != "garbler" ||
			formalCoxControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalCoxBlockwiseRockPurpose,
				record.ProductionReady) || related.Candidate == nil {
			return "", fmt.Errorf("formal-cox control: invalid publication record")
		}
		publication, publicationErr := formalCoxBlockwiseRockValidatePublication(
			record.Publication, formalCoxControlRockContext(context))
		certificate, certificateErr := formalCoxBlockwiseDecodeOpeningPublication(
			publication, context.pins)
		if publicationErr != nil || certificateErr != nil ||
			certificate.Candidate.FinalPairRootSHA256 !=
				binding.FinalPairRootSHA256 ||
			!formalCoxBlockwiseOpeningEqual(
				certificate.Candidate, related.Candidate.Candidate) ||
			!formalCoxBlockwiseOpeningEqual(
				certificate.Intent, related.Candidate.Intent) {
			return "", fmt.Errorf("formal-cox control: publication changed candidate")
		}
	case formalCoxControlRecordCommit:
		var record formalCoxBlockwiseRockCommitRecord
		if senderRole != "evaluator" ||
			formalCoxControlDecodeCanonical(encoded, &record) != nil ||
			record.Version != formalCoxBlockwiseRockRecordVersion ||
			record.Family != formalFinalizerHandoffFamilyCox ||
			record.Purpose != formalCoxBlockwiseRockCommitPurpose ||
			record.ProductionReady ||
			formalCoxBlockwiseRockValidateCommitReceipt(
				record.Receipt, formalCoxControlRockContext(context), 1) != nil ||
			related.Publication == nil ||
			record.Receipt.CertificateSHA256 !=
				related.Publication.Publication.CertificateSHA256 {
			return "", fmt.Errorf("formal-cox control: invalid evaluator commit")
		}
	case formalCoxControlRecordAck:
		var record formalCoxBlockwiseRockAckRecord
		if senderRole != "garbler" ||
			formalCoxControlDecodeCanonical(encoded, &record) != nil ||
			!validCommon(record.Version, record.Family, record.Purpose,
				record.ArtifactID, formalCoxBlockwiseRockPurpose,
				record.ProductionReady) ||
			formalFinalizerHandoffValidateCommitProof(
				record.Proof, binding, ticketSHA, context.pins) != nil ||
			related.Publication == nil ||
			record.Proof.CertificateSHA256 !=
				related.Publication.Publication.CertificateSHA256 {
			return "", fmt.Errorf("formal-cox control: invalid terminal ACK")
		}
	default:
		return "", fmt.Errorf("formal-cox control: unknown record type")
	}
	return ticketSHA, nil
}

func formalCoxControlValidateRecipientTransport(
	context formalCoxBlockwiseControlContext, recipientRole string,
	transportPublic, transportSignature []byte,
) (formalFinalizerHandoffAuthority, error) {
	var zero formalFinalizerHandoffAuthority
	recipient, err := formalCoxControlAuthority(context, recipientRole)
	if err != nil || len(transportPublic) != 32 ||
		len(transportSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(context.pins[recipient.PeerName],
			transportPublic, transportSignature) {
		return zero,
			fmt.Errorf("formal-cox control: recipient transport is not identity-bound")
	}
	peer, err := ecdh.X25519().NewPublicKey(transportPublic)
	probeSeed := sha256.Sum256([]byte(formalCoxControlAADDomain + "probe"))
	probe, probeErr := ecdh.X25519().NewPrivateKey(probeSeed[:])
	if err != nil || probeErr != nil {
		return zero, fmt.Errorf("formal-cox control: invalid recipient transport")
	}
	if shared, err := probe.ECDH(peer); err != nil || len(shared) != 32 ||
		bytes.Equal(shared, make([]byte, 32)) {
		clear(shared)
		return zero, fmt.Errorf("formal-cox control: invalid recipient transport")
	} else {
		clear(shared)
	}
	return recipient, nil
}

func formalCoxBlockwiseControlSeal(
	context formalCoxBlockwiseControlContext,
	binding formalFinalizerHandoffBinding, recordType, senderRole string,
	record []byte, ticket formalFinalizerHandoffTicket,
	recipientTransportPublic, recipientTransportSignature []byte,
	related formalCoxBlockwiseControlRelated,
) (formalCoxBlockwiseControlEnvelope, error) {
	var zero formalCoxBlockwiseControlEnvelope
	recipientRole, err := formalCoxControlDirection(recordType, senderRole)
	if err != nil || len(record) > formalCoxControlMaxRecord {
		return zero, fmt.Errorf("formal-cox control: invalid seal request")
	}
	sender, senderErr := formalCoxControlAuthority(context, senderRole)
	recipient, recipientErr := formalCoxControlValidateRecipientTransport(
		context, recipientRole, recipientTransportPublic,
		recipientTransportSignature)
	ticketSHA, recordErr := formalCoxControlValidateRecord(
		context, binding, recordType, senderRole, record, ticket, related)
	if senderErr != nil || recipientErr != nil || recordErr != nil {
		return zero, fmt.Errorf("formal-cox control: rejected typed source record")
	}
	recordSHA := formalCoxControlSHA(formalCoxControlRecordDomain, record)
	aad := formalCoxBlockwiseControlAAD{
		Family: context.Family, ArtifactID: context.ArtifactID,
		PlanSHA256: context.PlanSHA256, RunID: context.RunID,
		ExecutionSHA256: context.ExecutionSHA256,
		PinsetSHA256:    context.PinsetSHA256, TicketSHA256: ticketSHA,
		SenderPeerName: sender.PeerName, SenderPeerID: sender.PeerID,
		SenderRole: sender.Role, RecipientPeerName: recipient.PeerName,
		RecipientPeerID: recipient.PeerID, RecipientRole: recipient.Role,
		RecordType: recordType, RecordSHA256: recordSHA,
	}
	if recordType != formalCoxControlRecordPreflight &&
		recordType != formalCoxControlRecordHeader {
		aad.FinalPairRootSHA256 = binding.FinalPairRootSHA256
	}
	if err := formalCoxControlValidateAAD(context, aad); err != nil {
		return zero, err
	}
	aadBytes, err := formalCoxControlAADBytes(aad)
	if err != nil {
		return zero, err
	}
	defer clear(aadBytes)
	ciphertext, err := transportEncryptBytesAAD(
		record, recipientTransportPublic, aadBytes)
	if err != nil || len(ciphertext) > formalCoxControlMaxEnvelope {
		clear(ciphertext)
		return zero, fmt.Errorf("formal-cox control: control seal failed")
	}
	return formalCoxBlockwiseControlEnvelope{
		Version:  formalCoxControlEnvelopeVersion,
		Protocol: formalCoxBlockwiseControlProtocol, AAD: aad,
		RecipientTransportKeySHA256: formalCoxControlSHA(
			formalCoxControlAADDomain+"recipient-key|",
			recipientTransportPublic),
		CiphertextSHA256: formalCoxControlSHA(
			formalCoxControlCipherDomain, ciphertext),
		Ciphertext: append([]byte(nil), ciphertext...), ProductionReady: false,
	}, nil
}

func formalCoxBlockwiseControlOpen(
	context formalCoxBlockwiseControlContext,
	binding formalFinalizerHandoffBinding,
	envelope formalCoxBlockwiseControlEnvelope,
	ticket formalFinalizerHandoffTicket, recipientTransportSecret []byte,
	related formalCoxBlockwiseControlRelated,
) ([]byte, error) {
	if envelope.Version != formalCoxControlEnvelopeVersion ||
		envelope.Protocol != formalCoxBlockwiseControlProtocol ||
		envelope.ProductionReady || len(envelope.Ciphertext) < 60 ||
		len(envelope.Ciphertext) > formalCoxControlMaxEnvelope ||
		envelope.CiphertextSHA256 != formalCoxControlSHA(
			formalCoxControlCipherDomain, envelope.Ciphertext) ||
		formalCoxControlValidateAAD(context, envelope.AAD) != nil ||
		len(recipientTransportSecret) != 32 {
		return nil, fmt.Errorf("formal-cox control: invalid sealed envelope")
	}
	preTicket := envelope.AAD.RecordType == formalCoxControlRecordPreflight ||
		envelope.AAD.RecordType == formalCoxControlRecordHeader
	if !preTicket {
		if formalCoxControlValidateBinding(context, binding) != nil ||
			binding.FinalPairRootSHA256 != envelope.AAD.FinalPairRootSHA256 {
			return nil, fmt.Errorf("formal-cox control: pair-root binding mismatch")
		}
	}
	secret, err := ecdh.X25519().NewPrivateKey(recipientTransportSecret)
	if err != nil || envelope.RecipientTransportKeySHA256 !=
		formalCoxControlSHA(formalCoxControlAADDomain+"recipient-key|",
			secret.PublicKey().Bytes()) {
		return nil, fmt.Errorf("formal-cox control: wrong recipient transport")
	}
	recipient, err := formalCoxControlAuthority(context, envelope.AAD.RecipientRole)
	if err != nil || recipient.PeerName != envelope.AAD.RecipientPeerName ||
		recipient.PeerID != envelope.AAD.RecipientPeerID {
		return nil, fmt.Errorf("formal-cox control: wrong recipient authority")
	}
	if !preTicket && envelope.AAD.RecordType != formalCoxControlRecordTicket {
		ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
		if ticketErr != nil || formalFinalizerHandoffValidateTicket(
			ticket, binding, context.pins) != nil ||
			!hmac.Equal([]byte(ticketSHA), []byte(envelope.AAD.TicketSHA256)) {
			return nil, fmt.Errorf("formal-cox control: ticket binding mismatch")
		}
	}
	aadBytes, err := formalCoxControlAADBytes(envelope.AAD)
	if err != nil {
		return nil, err
	}
	defer clear(aadBytes)
	plaintext, err := transportDecryptBytesAAD(
		envelope.Ciphertext, recipientTransportSecret, aadBytes)
	if err != nil {
		return nil, fmt.Errorf("formal-cox control: authenticated open failed")
	}
	defer clear(plaintext)
	if envelope.AAD.RecordSHA256 != formalCoxControlSHA(
		formalCoxControlRecordDomain, plaintext) {
		return nil, fmt.Errorf("formal-cox control: record hash mismatch")
	}
	if envelope.AAD.RecordType == formalCoxControlRecordTicket {
		var record formalCoxBlockwiseRockTicketRecord
		if formalCoxControlDecodeCanonical(plaintext, &record) != nil {
			return nil, fmt.Errorf("formal-cox control: invalid encrypted ticket")
		}
		ticket = record.Ticket
	}
	ticketSHA, err := formalCoxControlValidateRecord(
		context, binding, envelope.AAD.RecordType, envelope.AAD.SenderRole,
		plaintext, ticket, related)
	if err != nil || ticketSHA != envelope.AAD.TicketSHA256 {
		return nil, fmt.Errorf("formal-cox control: encrypted record binding mismatch")
	}
	return append([]byte(nil), plaintext...), nil
}
