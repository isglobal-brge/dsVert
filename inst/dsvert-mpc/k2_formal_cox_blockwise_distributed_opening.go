package main

// Cox-local adapter for the closed typed finalizer-handoff bridge. It is not
// registered as a command, capability, API, DSI method, or transport route.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

const (
	formalCoxBlockwiseRemoteOpeningAuthorizationVersion = "dsvert-formal-cox-remote-opening-authorization-v1"
	formalCoxBlockwiseRemoteOpeningAuthorizationPurpose = "formal_cox_remote_ordered_sign_once_v1"
)

type formalCoxBlockwiseOpeningTransitPayload struct {
	Version             string                                  `json:"version"`
	Purpose             string                                  `json:"purpose"`
	ArtifactID          string                                  `json:"artifact_id"`
	PlanSHA256          string                                  `json:"plan_sha256"`
	FinalPairRootSHA256 string                                  `json:"final_pair_root_sha256"`
	TicketSHA256        string                                  `json:"ticket_sha256"`
	SenderPeerName      string                                  `json:"sender_peer_name"`
	SenderPeerID        string                                  `json:"sender_peer_id"`
	SenderRole          string                                  `json:"sender_role"`
	Handoff             formalCoxBlockwiseOpeningPrivateHandoff `json:"handoff"`
	ProductionReady     bool                                    `json:"-"`
}

type formalCoxBlockwiseRemoteOpeningAuthorization struct {
	Version                string                                    `json:"version"`
	Purpose                string                                    `json:"purpose"`
	ArtifactID             string                                    `json:"artifact_id"`
	FinalPairRootSHA256    string                                    `json:"final_pair_root_sha256"`
	IntentSHA256           string                                    `json:"intent_sha256"`
	TransportAuthorization formalFinalizerHandoffIntentAuthorization `json:"transport_authorization"`
	OpeningReceipt         jointDPBiomedicalGaussianSignature        `json:"opening_receipt"`
	ProductionReady        bool                                      `json:"-"`
}

func formalCoxBlockwiseClearOpeningTransit(
	payload *formalCoxBlockwiseOpeningTransitPayload,
) {
	if payload == nil {
		return
	}
	for index := range payload.Handoff.CoefficientShares {
		payload.Handoff.CoefficientShares[index] = ""
	}
	payload.Handoff.ValidityShare = false
}

func formalCoxBlockwiseMarshalOpeningTransitCanonical(
	payload formalCoxBlockwiseOpeningTransitPayload,
) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func formalCoxBlockwiseDecodeOpeningTransitCanonical(
	encoded []byte, payload *formalCoxBlockwiseOpeningTransitPayload,
) error {
	if payload == nil || formalFinalizerHandoffCanonicalObject(
		encoded, formalFinalizerHandoffMaxPayload) != nil {
		return fmt.Errorf("formal-cox: invalid canonical opening transit")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(payload); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-cox: trailing opening transit")
	}
	return nil
}

func formalCoxBlockwiseOpeningFinalizerBinding(
	store *formalCoxBlockwiseOpeningStore,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
) (formalFinalizerHandoffBinding, error) {
	var zero formalFinalizerHandoffBinding
	if store == nil || store.root == nil {
		return zero, fmt.Errorf("formal-cox: invalid distributed opening store")
	}
	pairRoot, err := store.pairRoot(headers[0], headers[1])
	if err != nil {
		return zero, err
	}
	if len(store.artifact.NoiseAuthorities) != 2 {
		return zero, fmt.Errorf("formal-cox: invalid opening authorities")
	}
	authorities := make([]formalFinalizerHandoffAuthority, 2)
	for index, authority := range store.artifact.NoiseAuthorities {
		authorities[index] = formalFinalizerHandoffAuthority{
			PeerName: authority.PeerName,
			PeerID:   authority.PeerID,
			Role:     authority.Role,
		}
	}
	binding := formalFinalizerHandoffBinding{
		Family:              formalFinalizerHandoffFamilyCox,
		Purpose:             formalFinalizerHandoffCoxPurpose,
		ArtifactID:          store.artifactID,
		FinalPairRootSHA256: pairRoot,
		PlanSHA256:          store.planSHA256,
		PinsetSHA256:        store.artifact.PinsetSHA256,
		Authorities:         authorities,
		Finalizer:           authorities[0],
	}
	if err := formalFinalizerHandoffValidateBinding(binding, store.pins); err != nil {
		return zero, err
	}
	return binding, nil
}

func formalCoxBlockwiseValidateOpeningTransit(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	payload formalCoxBlockwiseOpeningTransitPayload,
	pins map[string]ed25519.PublicKey,
) error {
	if formalFinalizerHandoffValidateTicket(ticket, binding, pins) != nil ||
		binding.Family != formalFinalizerHandoffFamilyCox ||
		binding.Purpose != formalFinalizerHandoffCoxPurpose ||
		payload.ProductionReady {
		return fmt.Errorf("formal-cox: invalid typed opening transit binding")
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return err
	}
	authority, err := formalFinalizerHandoffPeer(binding, payload.SenderRole)
	if err != nil || payload.Version != formalFinalizerHandoffCoxPayloadVersion ||
		payload.Purpose != binding.Purpose ||
		payload.ArtifactID != binding.ArtifactID ||
		payload.PlanSHA256 != binding.PlanSHA256 ||
		payload.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		payload.TicketSHA256 != ticketSHA ||
		payload.SenderPeerName != authority.PeerName ||
		payload.SenderPeerID != authority.PeerID {
		return fmt.Errorf("formal-cox: typed opening transit mismatch")
	}
	header := payload.Handoff.Header
	message, messageErr := formalCoxBlockwiseOpeningHandoffMessage(header)
	receiptMessage, receiptErr := formalCoxBlockwiseReceiptUnsigned(
		header.FinalReceipt)
	completionDigest, completionErr := formalCoxBlockwiseCompletionDigest(
		header.Completion)
	if messageErr != nil || receiptErr != nil || completionErr != nil ||
		header.Version != formalCoxBlockwiseOpeningVersion ||
		header.Purpose != formalCoxBlockwiseOpeningPurpose ||
		header.ArtifactID != binding.ArtifactID ||
		header.PlanSHA256 != binding.PlanSHA256 ||
		header.PinsetSHA256 != binding.PinsetSHA256 ||
		header.PeerName != authority.PeerName || header.PeerID != authority.PeerID ||
		header.Role != authority.Role || header.ProductionReady ||
		header.CoefficientCount < 1 ||
		header.CoefficientCount > formalCoxPhase1MaxCovariates ||
		header.CoefficientCount != len(payload.Handoff.CoefficientShares) ||
		header.RingBits < 128 || header.RingBits > exactGCMaxRingBits ||
		header.FractionBits < 8 || header.FractionBits > 60 ||
		!formalCoxIsSHA256(header.RunID) ||
		!formalCoxIsSHA256(header.LocalOutputSHA256) ||
		header.Completion.ProductionReady ||
		header.Completion.CompletionSHA256 != completionDigest ||
		header.FinalReceipt.Peer != authority.PeerName ||
		header.FinalReceipt.PlanSHA256 != binding.PlanSHA256 ||
		len(header.FinalReceipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[authority.PeerName], receiptMessage,
			header.FinalReceipt.Signature) ||
		len(header.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[authority.PeerName], message, header.Signature) {
		return fmt.Errorf("formal-cox: invalid typed local opening handoff")
	}
	values, err := formalCoxBlockwiseDecodeValues(
		payload.Handoff.CoefficientShares, header.CoefficientCount, header.RingBits)
	if err != nil {
		return err
	}
	exactGCZeroBigInts(values)
	localSHA, err := formalCoxBlockwiseOpeningLocalOutputSHA256(
		binding.ArtifactID, binding.PlanSHA256, authority.PeerName, authority.Role,
		payload.Handoff.CoefficientShares, payload.Handoff.ValidityShare)
	if err != nil || localSHA != header.LocalOutputSHA256 {
		return fmt.Errorf("formal-cox: typed local output digest mismatch")
	}
	return nil
}

func formalFinalizerHandoffSealCox(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	payload formalCoxBlockwiseOpeningTransitPayload,
	signingKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalFinalizerHandoffEnvelope, error) {
	var zero formalFinalizerHandoffEnvelope
	if err := formalCoxBlockwiseValidateOpeningTransit(
		binding, ticket, payload, pins); err != nil {
		return zero, err
	}
	encoded, err := formalCoxBlockwiseMarshalOpeningTransitCanonical(payload)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	return formalFinalizerHandoffSealCanonical(
		binding, ticket, payload.SenderPeerName,
		formalFinalizerHandoffCoxOpeningKind, encoded, signingKey, pins)
}

func formalFinalizerHandoffOpenCox(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	envelope formalFinalizerHandoffEnvelope,
	recipientSecret []byte,
	pins map[string]ed25519.PublicKey,
) (formalCoxBlockwiseOpeningTransitPayload, error) {
	var zero formalCoxBlockwiseOpeningTransitPayload
	encoded, err := formalFinalizerHandoffOpenCanonical(
		binding, ticket, envelope, recipientSecret, pins)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var payload formalCoxBlockwiseOpeningTransitPayload
	if err := formalCoxBlockwiseDecodeOpeningTransitCanonical(
		encoded, &payload); err != nil {
		return zero, err
	}
	if err := formalCoxBlockwiseValidateOpeningTransit(
		binding, ticket, payload, pins); err != nil {
		formalCoxBlockwiseClearOpeningTransit(&payload)
		return zero, err
	}
	return payload, nil
}

func formalCoxBlockwiseBuildOpeningTransit(
	store *formalCoxBlockwiseOpeningStore,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	peer string,
) (formalCoxBlockwiseOpeningTransitPayload, error) {
	var zero formalCoxBlockwiseOpeningTransitPayload
	wantBinding, err := formalCoxBlockwiseOpeningFinalizerBinding(store, headers)
	if err != nil || !formalCoxBlockwiseOpeningEqual(wantBinding, binding) ||
		formalFinalizerHandoffValidateTicket(ticket, binding, store.pins) != nil {
		return zero, fmt.Errorf("formal-cox: distributed opening binding mismatch")
	}
	handoff, err := store.loadPrivateHandoffPayload(peer)
	if err != nil {
		return zero, err
	}
	authority, err := formalFinalizerHandoffPeer(binding, handoff.Header.Role)
	if err != nil || authority.PeerName != peer {
		for index := range handoff.CoefficientShares {
			handoff.CoefficientShares[index] = ""
		}
		return zero, fmt.Errorf("formal-cox: local transit authority mismatch")
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	payload := formalCoxBlockwiseOpeningTransitPayload{
		Version:             formalFinalizerHandoffCoxPayloadVersion,
		Purpose:             formalFinalizerHandoffCoxPurpose,
		ArtifactID:          binding.ArtifactID,
		PlanSHA256:          binding.PlanSHA256,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		TicketSHA256:        ticketSHA,
		SenderPeerName:      authority.PeerName,
		SenderPeerID:        authority.PeerID,
		SenderRole:          authority.Role,
		Handoff:             handoff,
		ProductionReady:     false,
	}
	if err := formalCoxBlockwiseValidateOpeningTransit(
		binding, ticket, payload, store.pins); err != nil {
		formalCoxBlockwiseClearOpeningTransit(&payload)
		return zero, err
	}
	return payload, nil
}

func (store *formalCoxBlockwiseOpeningStore) ImportRemoteHandoff(
	handoff formalCoxBlockwiseOpeningPrivateHandoff,
) (formalCoxBlockwiseOpeningHandoffHeader, bool, error) {
	var zero formalCoxBlockwiseOpeningHandoffHeader
	if store == nil || store.root == nil ||
		store.validateHandoffHeader(handoff.Header) != nil ||
		len(handoff.CoefficientShares) != store.plan.Policy.CovariateCount {
		return zero, false, fmt.Errorf("formal-cox: invalid remote opening handoff")
	}
	values, err := formalCoxBlockwiseDecodeValues(handoff.CoefficientShares,
		store.plan.Policy.CovariateCount, store.plan.RingBits)
	if err != nil {
		return zero, false, err
	}
	exactGCZeroBigInts(values)
	wantSHA, err := formalCoxBlockwiseOpeningLocalOutputSHA256(
		store.artifactID, store.planSHA256, handoff.Header.PeerName,
		handoff.Header.Role, handoff.CoefficientShares, handoff.ValidityShare)
	if err != nil || wantSHA != handoff.Header.LocalOutputSHA256 {
		return zero, false, fmt.Errorf("formal-cox: remote opening digest mismatch")
	}
	role, err := store.roleForPeer(handoff.Header.PeerName)
	if err != nil || role != handoff.Header.Role {
		return zero, false, fmt.Errorf("formal-cox: remote opening role mismatch")
	}
	encoded, err := store.encodePrivate("handoff", role, handoff)
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	path, err := store.privateRelativePath(
		store.artifactID, "handoff", handoff.Header.PeerName, true)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	created, err := formalCoxBlockwiseGuardRootCreateRecord(store.root, path, encoded)
	if err == nil {
		encoded, err = formalCoxBlockwiseGuardRootReadRecord(
			store.root, path, formalCoxBlockwiseOpeningPrivateMax)
	}
	store.mu.Unlock()
	if err != nil {
		return zero, false, err
	}
	var existing formalCoxBlockwiseOpeningPrivateHandoff
	if err := store.decodePrivate(encoded, "handoff", role, &existing); err != nil {
		return zero, false, err
	}
	defer func() {
		for index := range existing.CoefficientShares {
			existing.CoefficientShares[index] = ""
		}
	}()
	if !formalCoxBlockwiseOpeningEqual(existing, handoff) {
		return zero, false, fmt.Errorf("formal-cox: conflicting remote opening handoff")
	}
	return existing.Header, !created, nil
}

func formalCoxBlockwiseSealLocalOpening(
	local *formalCoxBlockwiseOpeningStore,
	outbox *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	peer string,
	privateKey ed25519.PrivateKey,
) (formalFinalizerHandoffEnvelope, bool, error) {
	var zero formalFinalizerHandoffEnvelope
	if local == nil || outbox == nil {
		return zero, false, fmt.Errorf("formal-cox: invalid local opening transport")
	}
	if ack, found, err := outbox.PreflightAck(); err != nil {
		return zero, false, err
	} else if found {
		return zero, true, &formalFinalizerHandoffTerminalAckError{Proof: ack}
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(local, headers)
	if err != nil || !formalCoxBlockwiseOpeningEqual(binding, outbox.binding) {
		return zero, false, fmt.Errorf("formal-cox: local transport binding mismatch")
	}
	if _, _, err := outbox.CommitTicket(ticket); err != nil {
		return zero, false, err
	}
	payload, err := formalCoxBlockwiseBuildOpeningTransit(
		local, binding, ticket, headers, peer)
	if err != nil {
		return zero, false, err
	}
	defer formalCoxBlockwiseClearOpeningTransit(&payload)
	envelope, err := formalFinalizerHandoffSealCox(
		binding, ticket, payload, privateKey, local.pins)
	if err != nil {
		return zero, false, err
	}
	return outbox.CommitOutbox(envelope)
}

func formalCoxBlockwiseTerminalOpeningReplay(
	finalizer *formalCoxBlockwiseOpeningStore,
	proof formalFinalizerHandoffCommitProof,
) (formalCoxBlockwiseOpeningPublication, error) {
	var zero formalCoxBlockwiseOpeningPublication
	if finalizer == nil || proof.ArtifactID != finalizer.artifactID {
		return zero, fmt.Errorf("formal-cox: invalid terminal opening ACK")
	}
	publication, err := finalizer.Replay(proof.ArtifactID)
	if err != nil || publication.CertificateSHA256 != proof.CertificateSHA256 {
		return zero, fmt.Errorf("formal-cox: terminal ACK lacks exact publication")
	}
	return publication, nil
}

func formalCoxBlockwiseTerminalOpeningErrorReplay(
	finalizer *formalCoxBlockwiseOpeningStore, err error,
) (formalCoxBlockwiseOpeningPublication, bool, error) {
	var terminal *formalFinalizerHandoffTerminalAckError
	if !errors.As(err, &terminal) {
		return formalCoxBlockwiseOpeningPublication{}, false, err
	}
	publication, replayErr := formalCoxBlockwiseTerminalOpeningReplay(
		finalizer, terminal.Proof)
	return publication, true, replayErr
}

// Preflight checks the ArtifactID-keyed publication and ACK before inspecting
// any run-bound header, pair root, ticket, or ciphertext.
func formalCoxBlockwiseOpeningDistributedPreflight(
	finalizer *formalCoxBlockwiseOpeningStore,
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	envelopes [2]formalFinalizerHandoffEnvelope,
) (formalCoxBlockwiseOpeningPublication, bool, error) {
	var zero formalCoxBlockwiseOpeningPublication
	if finalizer == nil || ingress == nil {
		return zero, false, fmt.Errorf("formal-cox: invalid distributed preflight")
	}
	if publication, err := finalizer.Replay(finalizer.artifactID); err == nil {
		return publication, true, nil
	} else if !os.IsNotExist(err) {
		return zero, false, err
	}
	if ack, found, err := ingress.PreflightAck(); err != nil {
		return zero, false, err
	} else if found {
		publication, err := formalCoxBlockwiseTerminalOpeningReplay(finalizer, ack)
		return publication, true, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(finalizer, headers)
	if err != nil || !formalCoxBlockwiseOpeningEqual(binding, ingress.binding) ||
		formalFinalizerHandoffValidateTicket(ticket, binding, finalizer.pins) != nil {
		return zero, false, fmt.Errorf("formal-cox: distributed preflight binding mismatch")
	}
	for index, role := range []string{"garbler", "evaluator"} {
		envelope := envelopes[index]
		header := headers[index]
		if envelope.SenderRole != role || envelope.SenderPeerName != header.PeerName ||
			envelope.SenderPeerID != header.PeerID ||
			envelope.PayloadKind != formalFinalizerHandoffCoxOpeningKind ||
			formalFinalizerHandoffValidateEnvelope(
				binding, ticket, envelope, finalizer.pins) != nil {
			return zero, false, fmt.Errorf("formal-cox: invalid ordered ingress envelope")
		}
	}
	if _, _, err := ingress.CommitTicket(ticket); err != nil {
		return zero, false, err
	}
	for _, envelope := range envelopes {
		if _, _, err := ingress.CommitIngress(envelope); err != nil {
			if publication, found, terminalErr :=
				formalCoxBlockwiseTerminalOpeningErrorReplay(finalizer, err); found {
				return publication, true, terminalErr
			}
			return zero, false, err
		}
	}
	return zero, false, nil
}

func formalCoxBlockwiseOpenDurableTransit(
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	role string,
) (formalCoxBlockwiseOpeningTransitPayload, error) {
	var zero formalCoxBlockwiseOpeningTransitPayload
	encoded, err := ingress.OpenIngressDurableCanonical(role, ticket)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var payload formalCoxBlockwiseOpeningTransitPayload
	if err := formalCoxBlockwiseDecodeOpeningTransitCanonical(
		encoded, &payload); err != nil {
		return zero, err
	}
	if payload.SenderRole != role || formalCoxBlockwiseValidateOpeningTransit(
		ingress.binding, ticket, payload, ingress.pins) != nil {
		formalCoxBlockwiseClearOpeningTransit(&payload)
		return zero, fmt.Errorf("formal-cox: invalid durable typed ingress")
	}
	return payload, nil
}

// OpenAndPrepare imports one decrypted handoff at a time. The only scope that
// ever reconstructs both shares remains openingStore.buildCandidate.
func formalCoxBlockwiseOpeningDistributedOpenAndPrepare(
	finalizer *formalCoxBlockwiseOpeningStore,
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	phaseHook func(string) error,
) (formalCoxBlockwiseOpeningIntent, formalCoxBlockwiseOpeningPublication,
	bool, error,
) {
	var zeroIntent formalCoxBlockwiseOpeningIntent
	var zeroPublication formalCoxBlockwiseOpeningPublication
	if finalizer == nil || ingress == nil {
		return zeroIntent, zeroPublication, false,
			fmt.Errorf("formal-cox: invalid distributed finalizer")
	}
	// This lookup intentionally precedes header/pair-root validation.
	if publication, err := finalizer.Replay(finalizer.artifactID); err == nil {
		return zeroIntent, publication, true, nil
	} else if !os.IsNotExist(err) {
		return zeroIntent, zeroPublication, false, err
	}
	if ack, found, err := ingress.PreflightAck(); err != nil {
		return zeroIntent, zeroPublication, false, err
	} else if found {
		publication, err := formalCoxBlockwiseTerminalOpeningReplay(finalizer, ack)
		return zeroIntent, publication, true, err
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(finalizer, headers)
	storedTicket, ticketErr := ingress.loadTicket()
	wantTicket, _ := json.Marshal(ticket)
	gotTicket, _ := json.Marshal(storedTicket)
	if err != nil || ticketErr != nil ||
		!formalCoxBlockwiseOpeningEqual(binding, ingress.binding) ||
		!bytes.Equal(wantTicket, gotTicket) {
		return zeroIntent, zeroPublication, false,
			fmt.Errorf("formal-cox: durable preflight binding mismatch")
	}
	for index, role := range []string{"garbler", "evaluator"} {
		envelope, err := ingress.loadEnvelope("ingress-v1", role)
		if err != nil || envelope.SenderRole != role ||
			envelope.SenderPeerName != headers[index].PeerName ||
			envelope.SenderPeerID != headers[index].PeerID {
			return zeroIntent, zeroPublication, false,
				fmt.Errorf("formal-cox: distributed preflight is incomplete")
		}
	}
	if phaseHook != nil {
		if err := phaseHook("after_public_preflight"); err != nil {
			return zeroIntent, zeroPublication, false, err
		}
	}
	for _, role := range []string{"garbler", "evaluator"} {
		payload, err := formalCoxBlockwiseOpenDurableTransit(ingress, ticket, role)
		if err != nil {
			return zeroIntent, zeroPublication, false, err
		}
		_, _, importErr := finalizer.ImportRemoteHandoff(payload.Handoff)
		formalCoxBlockwiseClearOpeningTransit(&payload)
		if importErr != nil {
			return zeroIntent, zeroPublication, false, importErr
		}
		if phaseHook != nil {
			if err := phaseHook("after_import_" + role); err != nil {
				return zeroIntent, zeroPublication, false, err
			}
		}
	}
	return finalizer.Prepare(phaseHook)
}

func formalCoxBlockwiseDistributedOpeningIntentSHA256(
	intent formalCoxBlockwiseOpeningIntent,
) (string, error) {
	return formalCoxBlockwiseOpeningHash("distributed-opening-intent", intent)
}

func formalCoxBlockwiseValidateDistributedOpeningIntent(
	binding formalFinalizerHandoffBinding,
	intent formalCoxBlockwiseOpeningIntent,
) error {
	if intent.Version != formalCoxBlockwiseOpeningVersion ||
		intent.Purpose != formalCoxBlockwiseOpeningPurpose ||
		intent.ArtifactID != binding.ArtifactID ||
		intent.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		!formalCoxIsSHA256(intent.CandidateSHA256) ||
		intent.OpeningMode != formalCoxBlockwiseOpeningMode ||
		intent.ExpPostprocessMode != formalCoxBlockwiseExpOpeningMode ||
		intent.ProductionReady {
		return fmt.Errorf("formal-cox: invalid distributed opening intent")
	}
	return nil
}

// Each signer verifies the candidate against both signed handoff digests
// without receiving the other peer's share. Given beta and its own additive
// share, the opposite share is fixed uniquely in Z/2^kZ.
func formalCoxBlockwiseValidateCandidateFromLocalHandoff(
	local *formalCoxBlockwiseOpeningStore,
	binding formalFinalizerHandoffBinding,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	candidate formalCoxBlockwiseOpeningCandidate,
	role string,
) error {
	if local == nil || local.validateCandidate(candidate) != nil ||
		candidate.FinalPairRootSHA256 != binding.FinalPairRootSHA256 {
		return fmt.Errorf("formal-cox: candidate is not bound to the opening pair")
	}
	position := 0
	if role == "evaluator" {
		position = 1
	} else if role != "garbler" {
		return fmt.Errorf("formal-cox: invalid candidate verifier role")
	}
	authority, err := formalFinalizerHandoffPeer(binding, role)
	if err != nil || authority.PeerName != local.plan.Policy.ComputePeers[position] {
		return fmt.Errorf("formal-cox: candidate verifier authority mismatch")
	}
	payload, err := local.loadPrivateHandoffPayload(authority.PeerName)
	if err != nil {
		return err
	}
	defer func() {
		for index := range payload.CoefficientShares {
			payload.CoefficientShares[index] = ""
		}
	}()
	if !formalCoxBlockwiseOpeningEqual(payload.Header, headers[position]) {
		return fmt.Errorf("formal-cox: candidate verifier handoff changed")
	}
	modulus := exactGCModulus(candidate.RingBits)
	for index, coefficient := range candidate.Coefficients {
		beta, ok := new(big.Int).SetString(coefficient.BetaSteps, 10)
		localShare, shareOK := new(big.Int).SetString(
			payload.CoefficientShares[index], 16)
		if !ok || !shareOK || localShare.Sign() < 0 ||
			localShare.Cmp(modulus) >= 0 {
			return fmt.Errorf("formal-cox: invalid candidate beta")
		}
		residue := formalCoxResidue(beta, candidate.RingBits)
		other := new(big.Int).Sub(residue, localShare)
		other.Mod(other, modulus)
		// Overwrite the local coordinate before advancing. No object outside the
		// private finalizer ever contains both complete share vectors.
		payload.CoefficientShares[index] = other.Text(16)
		localShare.SetInt64(0)
		residue.SetInt64(0)
		other.SetInt64(0)
	}
	otherPosition := 1 - position
	otherHeader := headers[otherPosition]
	otherRole := binding.Authorities[otherPosition].Role
	otherValidity := candidate.Valid != payload.ValidityShare
	wantDigest, err := formalCoxBlockwiseOpeningLocalOutputSHA256(
		binding.ArtifactID, binding.PlanSHA256,
		binding.Authorities[otherPosition].PeerName, otherRole,
		payload.CoefficientShares, otherValidity)
	if err != nil || wantDigest != otherHeader.LocalOutputSHA256 {
		return fmt.Errorf("formal-cox: candidate does not reconstruct signed handoffs")
	}
	return nil
}

func formalCoxBlockwiseRemoteOpeningSignOnce(
	local *formalCoxBlockwiseOpeningStore,
	outbox *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	candidate formalCoxBlockwiseOpeningCandidate,
	role string,
	privateKey ed25519.PrivateKey,
	transportPredecessors []formalFinalizerHandoffIntentAuthorization,
	openingPredecessors []jointDPBiomedicalGaussianSignature,
) (formalCoxBlockwiseRemoteOpeningAuthorization, bool, error) {
	var zero formalCoxBlockwiseRemoteOpeningAuthorization
	if local == nil || outbox == nil {
		return zero, false, fmt.Errorf("formal-cox: invalid remote opening signer")
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(local, headers)
	if err != nil {
		return zero, false, err
	}
	if err := formalCoxBlockwiseValidateCandidateFromLocalHandoff(
		local, binding, headers, candidate, role); err != nil {
		return zero, false, err
	}
	intent, err := formalCoxBlockwiseOpeningIntentFor(candidate)
	if err != nil {
		return zero, false, err
	}
	authority, err := formalFinalizerHandoffPeer(binding, role)
	if err != nil || !formalCoxBlockwiseOpeningEqual(binding, outbox.binding) ||
		formalFinalizerHandoffValidateTicket(ticket, binding, local.pins) != nil ||
		formalCoxBlockwiseValidateDistributedOpeningIntent(binding, intent) != nil {
		return zero, false, fmt.Errorf("formal-cox: remote signer binding mismatch")
	}
	position := 0
	if role == "garbler" {
		if len(transportPredecessors) != 0 || len(openingPredecessors) != 0 {
			return zero, false, fmt.Errorf("formal-cox: garbler signer has predecessor")
		}
	} else {
		position = 1
		if len(transportPredecessors) != 1 || len(openingPredecessors) != 1 ||
			formalCoxBlockwiseValidateOpeningReceiptAt(
				intent, openingPredecessors, 0, local.artifact, local.pins) != nil {
			return zero, false,
				fmt.Errorf("formal-cox: evaluator lacks ordered predecessor")
		}
	}
	if authority.PeerName != local.plan.Policy.ComputePeers[position] {
		return zero, false, fmt.Errorf("formal-cox: remote signer role mismatch")
	}
	localHeader, err := local.loadPrivateHandoff(authority.PeerName)
	if err != nil || !formalCoxBlockwiseOpeningEqual(
		localHeader, headers[position]) {
		return zero, false, fmt.Errorf("formal-cox: signer lacks its local handoff")
	}
	outboxEnvelope, err := outbox.loadEnvelope("outbox-v1", role)
	if err != nil || outboxEnvelope.SenderPeerName != authority.PeerName {
		return zero, false, fmt.Errorf("formal-cox: signer lacks durable outbox")
	}
	intentSHA, err := formalCoxBlockwiseDistributedOpeningIntentSHA256(intent)
	if err != nil {
		return zero, false, err
	}
	transportAuthorization, replayed, err := outbox.SignIntentOnce(
		ticket, role, intentSHA, outboxEnvelope.PayloadSHA256,
		transportPredecessors, privateKey)
	if err != nil {
		return zero, false, err
	}
	predecessorSHA := ""
	if position == 1 {
		predecessorSHA, err = formalCoxBlockwiseOpeningReceiptSHA256(
			openingPredecessors[0])
		if err != nil {
			return zero, false, err
		}
	}
	message, err := formalCoxBlockwiseOpeningAuthorityMessage(
		intent, authority.PeerName, role, predecessorSHA)
	if err != nil {
		return zero, false, err
	}
	receipt := jointDPBiomedicalGaussianSignature{
		Signer: authority.PeerName, Signature: ed25519.Sign(privateKey, message),
	}
	allReceipts := append(
		[]jointDPBiomedicalGaussianSignature(nil), openingPredecessors...)
	allReceipts = append(allReceipts, receipt)
	if formalCoxBlockwiseValidateOpeningReceiptAt(
		intent, allReceipts, position, local.artifact, local.pins) != nil {
		return zero, false, fmt.Errorf("formal-cox: invalid remote opening receipt")
	}
	return formalCoxBlockwiseRemoteOpeningAuthorization{
		Version:    formalCoxBlockwiseRemoteOpeningAuthorizationVersion,
		Purpose:    formalCoxBlockwiseRemoteOpeningAuthorizationPurpose,
		ArtifactID: binding.ArtifactID, FinalPairRootSHA256: binding.FinalPairRootSHA256,
		IntentSHA256: intentSHA, TransportAuthorization: transportAuthorization,
		OpeningReceipt: receipt, ProductionReady: false,
	}, replayed, nil
}

func formalCoxBlockwiseValidateRemoteOpeningAuthorization(
	finalizer *formalCoxBlockwiseOpeningStore,
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	intent formalCoxBlockwiseOpeningIntent,
	role string,
	authorization formalCoxBlockwiseRemoteOpeningAuthorization,
	transportPredecessors []formalFinalizerHandoffIntentAuthorization,
	openingPredecessors []jointDPBiomedicalGaussianSignature,
) error {
	if finalizer == nil || ingress == nil {
		return fmt.Errorf("formal-cox: invalid remote authorization verifier")
	}
	candidate, err := finalizer.loadCandidate()
	wantIntent, intentErr := formalCoxBlockwiseOpeningIntentFor(candidate)
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	intentSHA, hashErr := formalCoxBlockwiseDistributedOpeningIntentSHA256(intent)
	authority, authorityErr := formalFinalizerHandoffPeer(ingress.binding, role)
	if err != nil || intentErr != nil || ticketErr != nil || hashErr != nil ||
		authorityErr != nil ||
		!formalCoxBlockwiseOpeningEqual(intent, wantIntent) ||
		authorization.Version != formalCoxBlockwiseRemoteOpeningAuthorizationVersion ||
		authorization.Purpose != formalCoxBlockwiseRemoteOpeningAuthorizationPurpose ||
		authorization.ArtifactID != ingress.binding.ArtifactID ||
		authorization.FinalPairRootSHA256 != ingress.binding.FinalPairRootSHA256 ||
		authorization.IntentSHA256 != intentSHA || authorization.ProductionReady ||
		formalFinalizerHandoffValidateIntentAuthorization(
			authorization.TransportAuthorization, ingress.binding,
			ticketSHA, ingress.pins) != nil ||
		authorization.TransportAuthorization.SignerRole != role ||
		authorization.TransportAuthorization.SignerPeerName != authority.PeerName ||
		authorization.TransportAuthorization.IntentSHA256 != intentSHA ||
		authorization.OpeningReceipt.Signer != authority.PeerName {
		return fmt.Errorf("formal-cox: remote opening authorization mismatch")
	}
	ingressEnvelope, err := ingress.loadEnvelope("ingress-v1", role)
	if err != nil || authorization.TransportAuthorization.LocalGuardSHA256 !=
		ingressEnvelope.PayloadSHA256 {
		return fmt.Errorf("formal-cox: remote authorization lost local guard")
	}
	position := 0
	if role == "garbler" {
		if len(transportPredecessors) != 0 || len(openingPredecessors) != 0 ||
			authorization.TransportAuthorization.PredecessorReceiptSHA256 != "" {
			return fmt.Errorf("formal-cox: garbler authorization has predecessor")
		}
	} else {
		position = 1
		if len(transportPredecessors) != 1 || len(openingPredecessors) != 1 ||
			formalFinalizerHandoffValidateIntentAuthorization(
				transportPredecessors[0], ingress.binding,
				ticketSHA, ingress.pins) != nil ||
			transportPredecessors[0].SignerRole != "garbler" ||
			transportPredecessors[0].IntentSHA256 != intentSHA {
			return fmt.Errorf("formal-cox: evaluator authorization lacks predecessor")
		}
		predecessorSHA, err := formalFinalizerHandoffIntentSHA256(
			transportPredecessors[0])
		if err != nil || authorization.TransportAuthorization.PredecessorReceiptSHA256 !=
			predecessorSHA {
			return fmt.Errorf("formal-cox: evaluator transport predecessor mismatch")
		}
	}
	receipts := append(
		[]jointDPBiomedicalGaussianSignature(nil), openingPredecessors...)
	receipts = append(receipts, authorization.OpeningReceipt)
	if formalCoxBlockwiseValidateOpeningReceiptAt(
		intent, receipts, position, finalizer.artifact, finalizer.pins) != nil {
		return fmt.Errorf("formal-cox: invalid ordered remote opening receipt")
	}
	return nil
}

func formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
	finalizer *formalCoxBlockwiseOpeningStore,
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	intent formalCoxBlockwiseOpeningIntent,
	role string,
	authorization formalCoxBlockwiseRemoteOpeningAuthorization,
	transportPredecessors []formalFinalizerHandoffIntentAuthorization,
	openingPredecessors []jointDPBiomedicalGaussianSignature,
) (jointDPBiomedicalGaussianSignature, bool, error) {
	var zero jointDPBiomedicalGaussianSignature
	if err := formalCoxBlockwiseValidateRemoteOpeningAuthorization(
		finalizer, ingress, ticket, intent, role, authorization,
		transportPredecessors, openingPredecessors); err != nil {
		return zero, false, err
	}
	authority, _ := formalFinalizerHandoffPeer(ingress.binding, role)
	predecessorSHA := ""
	if role == "evaluator" {
		predecessorSHA, _ = formalCoxBlockwiseOpeningReceiptSHA256(
			openingPredecessors[0])
	}
	record := formalCoxBlockwiseOpeningSignerRecord{
		Version:    formalCoxBlockwiseOpeningVersion,
		Purpose:    formalCoxBlockwiseOpeningPurpose,
		ArtifactID: finalizer.artifactID, CandidateSHA256: intent.CandidateSHA256,
		Signer: authority.PeerName, Role: role,
		PredecessorReceiptSHA256: predecessorSHA,
		Receipt:                  authorization.OpeningReceipt,
	}
	encoded, err := finalizer.encodeSigner(record)
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	path, err := finalizer.signerRelativePath(
		finalizer.artifactID, authority.PeerName, true)
	if err != nil {
		return zero, false, err
	}
	finalizer.mu.Lock()
	created, err := formalCoxBlockwiseGuardRootCreateRecord(
		finalizer.root, path, encoded)
	if err == nil {
		encoded, err = formalCoxBlockwiseGuardRootReadRecord(
			finalizer.root, path, formalCoxBlockwiseOpeningSignerMax)
	}
	finalizer.mu.Unlock()
	if err != nil {
		return zero, false, err
	}
	existing, err := finalizer.decodeSigner(encoded)
	if err != nil || existing.CandidateSHA256 != intent.CandidateSHA256 ||
		existing.PredecessorReceiptSHA256 != predecessorSHA ||
		!formalCoxBlockwiseOpeningEqual(existing.Receipt,
			authorization.OpeningReceipt) {
		return zero, false, fmt.Errorf("formal-cox: conflicting remote SignOnce")
	}
	return existing.Receipt, !created, nil
}

func formalCoxBlockwiseDistributedPublishAndAck(
	finalizer *formalCoxBlockwiseOpeningStore,
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	intent formalCoxBlockwiseOpeningIntent,
	authorizations [2]formalCoxBlockwiseRemoteOpeningAuthorization,
	finalizerPrivateKey ed25519.PrivateKey,
	phaseHook func(string) error,
) (formalCoxBlockwiseOpeningPublication, formalFinalizerHandoffCommitProof,
	bool, error,
) {
	var zeroPublication formalCoxBlockwiseOpeningPublication
	var zeroProof formalFinalizerHandoffCommitProof
	if finalizer == nil || ingress == nil {
		return zeroPublication, zeroProof, false,
			fmt.Errorf("formal-cox: invalid distributed publication")
	}
	if ack, found, err := ingress.PreflightAck(); err != nil {
		return zeroPublication, zeroProof, false, err
	} else if found {
		publication, err := formalCoxBlockwiseTerminalOpeningReplay(finalizer, ack)
		return publication, ack, true, err
	}
	receipts := []jointDPBiomedicalGaussianSignature{
		authorizations[0].OpeningReceipt,
		authorizations[1].OpeningReceipt,
	}
	publication, err := finalizer.Publish(intent, receipts, phaseHook)
	if err != nil {
		return zeroPublication, zeroProof, false, err
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zeroPublication, zeroProof, false, err
	}
	proof, err := formalFinalizerHandoffBuildCommitProof(
		ingress.binding, ticketSHA, publication.CertificateSHA256,
		finalizerPrivateKey, ingress.pins)
	if err != nil {
		return zeroPublication, zeroProof, false, err
	}
	stored, replayed, err := ingress.AckAfterCommit(proof, finalizer)
	if err != nil {
		return zeroPublication, zeroProof, false, err
	}
	return publication, stored, replayed, nil
}

func formalCoxBlockwiseDistributedCleanupAfterAck(
	ingress *formalFinalizerHandoffStore,
	proof formalFinalizerHandoffCommitProof,
) (int, error) {
	if ingress == nil {
		return 0, fmt.Errorf("formal-cox: invalid distributed cleanup")
	}
	return ingress.CleanupTransportAfterAck(proof)
}
