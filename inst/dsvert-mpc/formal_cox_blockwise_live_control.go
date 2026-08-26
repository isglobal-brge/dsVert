package main

// This is the private bridge between a completed live Cox worker and the
// already-established encrypted finalizer-control relay.  It stores only the
// local, signed lifecycle records in Rock.  The relay is still responsible for
// encrypting every cross-authority record; in particular the opening candidate
// is never returned by this bridge.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type formalCoxBlockwiseLiveControlStageV1 struct {
	ArtifactID      string `json:"artifact_id"`
	CandidateSHA256 string `json:"candidate_sha256,omitempty"`
	LocalRole       string `json:"local_role"`
	ProductionReady bool   `json:"production_ready"`
}

// formalCoxBlockwiseLiveControlAdvanceV1 is intentionally share-free.  It
// reports only the next durable lifecycle boundary; candidate material stays
// in the authority-local opening store and crosses authorities exclusively in
// the existing encrypted control relay.
type formalCoxBlockwiseLiveControlAdvanceV1 struct {
	ArtifactID        string `json:"artifact_id"`
	State             string `json:"state"`
	CertificateSHA256 string `json:"certificate_sha256"`
	ProductionReady   bool   `json:"production_ready"`
}

func formalCoxBlockwiseLiveControlAuthorization(
	store *formalCoxBlockwiseControlStore,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate *formalCoxBlockwiseRockCandidateRecord,
	role string,
) (*formalCoxBlockwiseRockAuthorizationRecord, error) {
	if store == nil || candidate == nil || (role != "garbler" && role != "evaluator") {
		return nil, fmt.Errorf("formal-cox live control: invalid authorization lookup")
	}
	encoded, err := store.readLifecycleRaw(formalCoxControlRecordAuthorization, role)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	var record formalCoxBlockwiseRockAuthorizationRecord
	related := formalCoxBlockwiseControlRelated{Candidate: candidate}
	if role == "evaluator" {
		garbler, err := formalCoxBlockwiseLiveControlAuthorization(
			store, binding, ticket, candidate, "garbler")
		if err != nil {
			return nil, err
		}
		related.GarblerAuthorization = garbler
	}
	if formalCoxControlDecodeCanonical(encoded, &record) != nil {
		return nil, fmt.Errorf("formal-cox live control: invalid durable authorization")
	}
	if _, err := formalCoxControlValidateRecord(
		store.context, binding, formalCoxControlRecordAuthorization, role,
		encoded, ticket, related); err != nil {
		return nil, err
	}
	return &record, nil
}

func formalCoxBlockwiseLiveControlPublication(
	store *formalCoxBlockwiseControlStore,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	candidate *formalCoxBlockwiseRockCandidateRecord,
) (*formalCoxBlockwiseRockPublicationRecord, error) {
	if store == nil || candidate == nil {
		return nil, fmt.Errorf("formal-cox live control: invalid publication lookup")
	}
	encoded, err := store.readLifecycleRaw(formalCoxControlRecordPublication, "garbler")
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	var record formalCoxBlockwiseRockPublicationRecord
	if formalCoxControlDecodeCanonical(encoded, &record) != nil {
		return nil, fmt.Errorf("formal-cox live control: invalid durable publication")
	}
	if _, err := formalCoxControlValidateRecord(
		store.context, binding, formalCoxControlRecordPublication, "garbler",
		encoded, ticket, formalCoxBlockwiseControlRelated{Candidate: candidate}); err != nil {
		return nil, err
	}
	return &record, nil
}

func formalCoxBlockwiseLiveControlAbsent(err error) bool { return os.IsNotExist(err) }

func formalCoxBlockwiseLiveControlWriteRecord(
	store *formalCoxBlockwiseControlStore, recordType, role string, value any,
) error {
	if store == nil || store.guard == nil {
		return fmt.Errorf("formal-cox live control: unavailable relay store")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(encoded)
	path, err := store.lifecyclePath(recordType, role)
	if err != nil {
		return err
	}
	relative, err := formalGLMPhase21RockRelative(store.guard.dir, path)
	if err != nil || filepath.IsAbs(relative) {
		return fmt.Errorf("formal-cox live control: invalid lifecycle location")
	}
	_, err = store.createRecord(relative, encoded, formalCoxControlMaxRecord)
	return err
}

func formalCoxBlockwiseLiveControlContext(
	bridge *formalCoxBlockwiseSourceBridge,
) (formalCoxBlockwiseControlContext, formalFinalizerHandoffAuthority,
	ed25519.PrivateKey, error) {
	var zero formalCoxBlockwiseControlContext
	if bridge == nil {
		return zero, formalFinalizerHandoffAuthority{}, nil,
			fmt.Errorf("formal-cox live control: unavailable source bridge")
	}
	bridge.mu.Lock()
	if bridge.closed || bridge.source == nil ||
		len(bridge.signingKey) != ed25519.PrivateKeySize {
		bridge.mu.Unlock()
		return zero, formalFinalizerHandoffAuthority{}, nil,
			fmt.Errorf("formal-cox live control: unavailable source bridge")
	}
	source, peer, plan := bridge.source, bridge.peer, bridge.plan
	privateKey := append(ed25519.PrivateKey(nil), bridge.signingKey...)
	bridge.mu.Unlock()

	source.mu.Lock()
	valid := !source.closed && source.session != nil &&
		source.session.context != nil && source.recipient == peer
	role, peerID := "", ""
	pins := map[string]ed25519.PublicKey(nil)
	if valid {
		role, peerID = source.session.context.roles[peer], source.session.context.peerIDs[peer]
		pins = make(map[string]ed25519.PublicKey, len(source.session.context.pins))
		for name, pin := range source.session.context.pins {
			pins[name] = append(ed25519.PublicKey(nil), pin...)
		}
	}
	source.mu.Unlock()
	if !valid {
		clear(privateKey)
		formalCoxBlockwiseClearPinsV1(pins)
		return zero, formalFinalizerHandoffAuthority{}, nil,
			fmt.Errorf("formal-cox live control: unavailable source context")
	}
	context, err := formalCoxControlContextFor(plan, pins)
	formalCoxBlockwiseClearPinsV1(pins)
	if err != nil {
		clear(privateKey)
		return zero, formalFinalizerHandoffAuthority{}, nil, err
	}
	local, err := formalCoxControlAuthority(context, role)
	if err != nil || local.PeerName != peer || local.PeerID != peerID ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey), context.pins[peer]) {
		clear(privateKey)
		formalCoxBlockwiseClearPinsV1(context.pins)
		return zero, formalFinalizerHandoffAuthority{}, nil,
			fmt.Errorf("formal-cox live control: invalid local authority")
	}
	return context, local, privateKey, nil
}

// StageFinalizerControlAtRootV1 is deliberately private to the worker host.
// Both compute peers stage their own preflight/header records; the garbler
// additionally stages the ticket and the candidate after the existing
// encrypted finalizer ingress has prepared it, while the evaluator stages its
// own sealed envelope.  No remote record is written directly.
func (controller *formalCoxBlockwiseExchangeController) StageFinalizerControlAtRootV1(
	ticket formalFinalizerHandoffTicket,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	envelopes [2]formalFinalizerHandoffEnvelope,
	stateRoot string, production bool,
) (formalCoxBlockwiseLiveControlStageV1, error) {
	var zero formalCoxBlockwiseLiveControlStageV1
	if controller == nil {
		return zero, fmt.Errorf("formal-cox live control: unavailable worker")
	}
	controller.mu.Lock()
	if controller.closed || !controller.committed || controller.peer == "" {
		controller.mu.Unlock()
		return zero, fmt.Errorf("formal-cox live control: unavailable worker")
	}
	peer := controller.peer
	controller.mu.Unlock()

	// Preparing the candidate needs the controller's finalizer bridge.  Do it
	// before entering the staging callback so that no controller lock is
	// recursively acquired.
	localRole := ""
	for _, header := range headers {
		if header.PeerName == peer {
			localRole = header.Role
			break
		}
	}
	if localRole != "garbler" && localRole != "evaluator" {
		return zero, fmt.Errorf("formal-cox live control: missing local header")
	}
	var prepared formalCoxBlockwiseExchangeDaemonFinalizerPrepareResultV1
	if localRole == "garbler" {
		var err error
		prepared, err = controller.PrepareFinalizerAtRootV1(
			ticket, headers, envelopes, stateRoot, production)
		if err != nil {
			return zero, err
		}
		if prepared.Finalized {
			if !formalCoxIsSHA256(prepared.CertificateSHA256) || prepared.Intent != nil {
				return zero, fmt.Errorf("formal-cox live control: invalid publication replay")
			}
			return formalCoxBlockwiseLiveControlStageV1{
				ArtifactID: ticket.ArtifactID, LocalRole: localRole,
				ProductionReady: false,
			}, nil
		}
		if prepared.Intent == nil {
			return zero, fmt.Errorf("formal-cox live control: missing prepared intent")
		}
	}

	result := zero
	err := controller.finalizerBridgeAtRootV1(headers,
		func(bridge *formalCoxBlockwiseSourceBridge,
			opening *formalCoxBlockwiseOpeningStore) error {
			context, local, privateKey, err := formalCoxBlockwiseLiveControlContext(bridge)
			if err != nil {
				return err
			}
			defer clear(privateKey)
			defer formalCoxBlockwiseClearPinsV1(context.pins)
			if local.Role != localRole || !formalCoxControlContextHasAuthority(context, local) {
				return fmt.Errorf("formal-cox live control: local role changed")
			}
			store, err := newFormalCoxBlockwiseControlStore(
				filepath.Join(stateRoot, local.PeerName), context, local, production)
			if err != nil {
				return err
			}
			defer store.Close()
			binding, err := formalCoxBlockwiseOpeningFinalizerBinding(opening, headers)
			if err != nil || formalFinalizerHandoffValidateBinding(binding, context.pins) != nil {
				return fmt.Errorf("formal-cox live control: invalid opening binding")
			}
			position := -1
			for index, header := range headers {
				if header.PeerName == local.PeerName && header.PeerID == local.PeerID &&
					header.Role == local.Role {
					position = index
				}
			}
			if position < 0 {
				return fmt.Errorf("formal-cox live control: invalid local header")
			}
			preflight := formalCoxBlockwiseRockPreflightReceipt{
				Version:    formalCoxBlockwiseRockRecordVersion,
				Purpose:    formalCoxBlockwiseRockPreflightPurpose,
				ArtifactID: context.ArtifactID, PinsetSHA256: context.PinsetSHA256,
				PeerName: local.PeerName, PeerID: local.PeerID, Role: local.Role,
				State: formalCoxBlockwiseRockStateAbsent, ProductionReady: false,
			}
			message, err := formalCoxBlockwiseRockPreflightMessage(preflight)
			if err != nil {
				return err
			}
			preflight.Signature = ed25519.Sign(privateKey, message)
			if err := formalCoxBlockwiseLiveControlWriteRecord(store,
				formalCoxControlRecordPreflight, local.Role,
				formalCoxBlockwiseRockPreflightRecord{
					Version: formalCoxBlockwiseRockRecordVersion,
					Family:  formalFinalizerHandoffFamilyCox,
					Purpose: formalCoxBlockwiseRockPreflightPurpose,
					Receipt: preflight, ProductionReady: false,
				}); err != nil {
				return err
			}
			if err := formalCoxBlockwiseLiveControlWriteRecord(store,
				formalCoxControlRecordHeader, local.Role,
				formalCoxBlockwiseRockHeaderRecord{
					Version: formalCoxBlockwiseRockRecordVersion,
					Family:  formalFinalizerHandoffFamilyCox,
					Purpose: formalCoxBlockwiseRockPurpose, ArtifactID: context.ArtifactID,
					Header: headers[position], ProductionReady: false,
				}); err != nil {
				return err
			}
			if local.Role == "garbler" {
				if formalFinalizerHandoffValidateTicket(ticket, binding, context.pins) != nil {
					return fmt.Errorf("formal-cox live control: invalid finalizer ticket")
				}
				if err := formalCoxBlockwiseLiveControlWriteRecord(store,
					formalCoxControlRecordTicket, local.Role,
					formalCoxBlockwiseRockTicketRecord{
						Version: formalCoxBlockwiseRockRecordVersion,
						Family:  formalFinalizerHandoffFamilyCox,
						Purpose: formalCoxBlockwiseRockPurpose, ArtifactID: context.ArtifactID,
						Ticket: ticket, ProductionReady: false,
					}); err != nil {
					return err
				}
				candidate, err := opening.loadCandidate()
				if err != nil {
					return err
				}
				wantIntent, err := formalCoxBlockwiseOpeningIntentFor(candidate)
				if err != nil || prepared.Intent == nil ||
					!formalCoxBlockwiseOpeningEqual(wantIntent, *prepared.Intent) {
					return fmt.Errorf("formal-cox live control: prepared candidate mismatch")
				}
				if err := formalCoxBlockwiseLiveControlWriteRecord(store,
					formalCoxControlRecordCandidate, local.Role,
					formalCoxBlockwiseRockCandidateRecord{
						Version: formalCoxBlockwiseRockRecordVersion,
						Family:  formalFinalizerHandoffFamilyCox,
						Purpose: formalCoxBlockwiseRockPurpose, ArtifactID: context.ArtifactID,
						Candidate: candidate, Intent: wantIntent, ProductionReady: false,
					}); err != nil {
					return err
				}
				result = formalCoxBlockwiseLiveControlStageV1{
					ArtifactID: context.ArtifactID, CandidateSHA256: prepared.Intent.CandidateSHA256,
					LocalRole: local.Role, ProductionReady: false,
				}
				return nil
			}
			var envelope *formalFinalizerHandoffEnvelope
			for index := range envelopes {
				if envelopes[index].SenderPeerName == local.PeerName &&
					envelopes[index].SenderPeerID == local.PeerID &&
					envelopes[index].SenderRole == local.Role {
					envelope = &envelopes[index]
				}
			}
			if envelope == nil || formalFinalizerHandoffValidateEnvelope(
				binding, ticket, *envelope, context.pins) != nil {
				return fmt.Errorf("formal-cox live control: invalid local envelope")
			}
			if err := formalCoxBlockwiseLiveControlWriteRecord(store,
				formalCoxControlRecordEnvelope, local.Role,
				formalCoxBlockwiseRockEnvelopeRecord{
					Version: formalCoxBlockwiseRockRecordVersion,
					Family:  formalFinalizerHandoffFamilyCox,
					Purpose: formalCoxBlockwiseRockPurpose, ArtifactID: context.ArtifactID,
					Role: local.Role, Envelope: *envelope, ProductionReady: false,
				}); err != nil {
				return err
			}
			result = formalCoxBlockwiseLiveControlStageV1{
				ArtifactID: context.ArtifactID, LocalRole: local.Role,
				ProductionReady: false,
			}
			return nil
		})
	if err != nil {
		return zero, err
	}
	return result, nil
}

// AdvanceFinalizerControlAtRootV1 advances exactly one authority-local Cox
// publication transition after the encrypted relay has imported its ordered
// predecessor.  It never accepts a candidate, authorization, certificate,
// path, or key from the caller.
func (controller *formalCoxBlockwiseExchangeController) AdvanceFinalizerControlAtRootV1(
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	stateRoot string, production bool,
) (formalCoxBlockwiseLiveControlAdvanceV1, error) {
	var zero formalCoxBlockwiseLiveControlAdvanceV1
	if controller == nil {
		return zero, fmt.Errorf("formal-cox live control: unavailable worker")
	}
	result := zero
	err := controller.finalizerBridgeAtRootV1(headers,
		func(bridge *formalCoxBlockwiseSourceBridge,
			opening *formalCoxBlockwiseOpeningStore) error {
			context, local, privateKey, err := formalCoxBlockwiseLiveControlContext(bridge)
			if err != nil {
				return err
			}
			defer clear(privateKey)
			defer formalCoxBlockwiseClearPinsV1(context.pins)
			store, err := newFormalCoxBlockwiseControlStore(
				filepath.Join(stateRoot, local.PeerName), context, local, production)
			if err != nil {
				return err
			}
			closeStore := func() {
				if store != nil {
					store.Close()
					store = nil
				}
			}
			defer closeStore()
			reopenStore := func() error {
				closeStore()
				store, err = newFormalCoxBlockwiseControlStore(
					filepath.Join(stateRoot, local.PeerName), context, local, production)
				return err
			}
			binding, err := formalCoxBlockwiseOpeningFinalizerBinding(opening, headers)
			if err != nil || formalFinalizerHandoffValidateBinding(binding, context.pins) != nil {
				return fmt.Errorf("formal-cox live control: invalid advance binding")
			}
			ticket, err := store.loadTicket(binding)
			if err != nil {
				return fmt.Errorf("formal-cox live control: missing staged ticket")
			}
			candidate, err := store.decodeCandidate(binding, ticket)
			if local.Role == "evaluator" && formalCoxBlockwiseLiveControlAbsent(err) {
				result = formalCoxBlockwiseLiveControlAdvanceV1{
					ArtifactID: context.ArtifactID, State: "awaiting_candidate",
				}
				return nil
			}
			if err != nil {
				return err
			}

			if local.Role == "garbler" {
				present, err := store.lifecycleRecordPresent(
					formalCoxControlRecordAuthorization, "garbler")
				if err != nil {
					return err
				}
				if !present {
					envelope, err := store.lifecycleRecordPresent(
						formalCoxControlRecordEnvelope, "evaluator")
					if err != nil {
						return err
					}
					if !envelope {
						result = formalCoxBlockwiseLiveControlAdvanceV1{
							ArtifactID: context.ArtifactID, State: "awaiting_evaluator_envelope",
						}
						return nil
					}
					closeStore()
					outbox, err := bridge.openFinalizerOutboxAtRootV1(
						opening, headers, stateRoot, production)
					if err != nil {
						return err
					}
					authorization, _, signErr := formalCoxBlockwiseRemoteOpeningSignOnce(
						opening, outbox, ticket, headers, candidate.Candidate, "garbler",
						privateKey, nil, nil)
					outbox.Close()
					if signErr != nil {
						return signErr
					}
					if err := reopenStore(); err != nil {
						return err
					}
					if err := formalCoxBlockwiseLiveControlWriteRecord(store,
						formalCoxControlRecordAuthorization, "garbler",
						formalCoxBlockwiseRockAuthorizationRecord{
							Version:    formalCoxBlockwiseRockRecordVersion,
							Family:     formalFinalizerHandoffFamilyCox,
							Purpose:    formalCoxBlockwiseRockPurpose,
							ArtifactID: context.ArtifactID, Role: "garbler",
							Authorization: authorization, ProductionReady: false,
						}); err != nil {
						return err
					}
				}
				evaluator, err := formalCoxBlockwiseLiveControlAuthorization(
					store, binding, ticket, candidate, "evaluator")
				if formalCoxBlockwiseLiveControlAbsent(err) {
					result = formalCoxBlockwiseLiveControlAdvanceV1{
						ArtifactID: context.ArtifactID, State: "awaiting_evaluator_authorization",
					}
					return nil
				}
				if err != nil {
					return err
				}
				publication, err := formalCoxBlockwiseLiveControlPublication(
					store, binding, ticket, candidate)
				if formalCoxBlockwiseLiveControlAbsent(err) {
					garbler, err := formalCoxBlockwiseLiveControlAuthorization(
						store, binding, ticket, candidate, "garbler")
					if err != nil {
						return err
					}
					closeStore()
					ingress, err := bridge.openFinalizerIngressAtRootV1(
						opening, headers, stateRoot, production)
					if err != nil {
						return err
					}
					garblerReceipt, _, acceptErr := formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
						opening, ingress, ticket, candidate.Intent, "garbler",
						garbler.Authorization, nil, nil)
					if acceptErr == nil {
						_, _, acceptErr = formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
							opening, ingress, ticket, candidate.Intent, "evaluator",
							evaluator.Authorization,
							[]formalFinalizerHandoffIntentAuthorization{
								garbler.Authorization.TransportAuthorization,
							}, []jointDPBiomedicalGaussianSignature{garblerReceipt})
					}
					if acceptErr != nil {
						ingress.Close()
						return acceptErr
					}
					opened, proof, _, publishErr := formalCoxBlockwiseDistributedPublishAndAck(
						opening, ingress, ticket, candidate.Intent,
						[2]formalCoxBlockwiseRemoteOpeningAuthorization{
							garbler.Authorization, evaluator.Authorization,
						}, privateKey, nil)
					ingress.Close()
					if publishErr != nil {
						return publishErr
					}
					if err := reopenStore(); err != nil {
						return err
					}
					publication = &formalCoxBlockwiseRockPublicationRecord{
						Version:         formalCoxBlockwiseRockRecordVersion,
						Family:          formalFinalizerHandoffFamilyCox,
						Purpose:         formalCoxBlockwiseRockPurpose,
						ArtifactID:      context.ArtifactID,
						Publication:     formalCoxBlockwiseRockPublicationFromOpening(opened),
						ProductionReady: false,
					}
					if err := formalCoxBlockwiseLiveControlWriteRecord(store,
						formalCoxControlRecordPublication, "garbler", *publication); err != nil {
						return err
					}
					if err := formalCoxBlockwiseLiveControlWriteRecord(store,
						formalCoxControlRecordAck, "garbler",
						formalCoxBlockwiseRockAckRecord{
							Version:    formalCoxBlockwiseRockRecordVersion,
							Family:     formalFinalizerHandoffFamilyCox,
							Purpose:    formalCoxBlockwiseRockPurpose,
							ArtifactID: context.ArtifactID, Proof: proof,
							ProductionReady: false,
						}); err != nil {
						return err
					}
				}
				result = formalCoxBlockwiseLiveControlAdvanceV1{
					ArtifactID: context.ArtifactID, State: "publication_ready",
					CertificateSHA256: publication.Publication.CertificateSHA256,
				}
				return nil
			}

			if local.Role != "evaluator" {
				return fmt.Errorf("formal-cox live control: invalid local role")
			}
			present, err := store.lifecycleRecordPresent(
				formalCoxControlRecordAuthorization, "evaluator")
			if err != nil {
				return err
			}
			if !present {
				garbler, err := formalCoxBlockwiseLiveControlAuthorization(
					store, binding, ticket, candidate, "garbler")
				if formalCoxBlockwiseLiveControlAbsent(err) {
					result = formalCoxBlockwiseLiveControlAdvanceV1{
						ArtifactID: context.ArtifactID, State: "awaiting_garbler_authorization",
					}
					return nil
				}
				if err != nil {
					return err
				}
				closeStore()
				outbox, err := bridge.openFinalizerOutboxAtRootV1(
					opening, headers, stateRoot, production)
				if err != nil {
					return err
				}
				authorization, _, signErr := formalCoxBlockwiseRemoteOpeningSignOnce(
					opening, outbox, ticket, headers, candidate.Candidate, "evaluator",
					privateKey,
					[]formalFinalizerHandoffIntentAuthorization{
						garbler.Authorization.TransportAuthorization,
					}, []jointDPBiomedicalGaussianSignature{garbler.Authorization.OpeningReceipt})
				outbox.Close()
				if signErr != nil {
					return signErr
				}
				if err := reopenStore(); err != nil {
					return err
				}
				if err := formalCoxBlockwiseLiveControlWriteRecord(store,
					formalCoxControlRecordAuthorization, "evaluator",
					formalCoxBlockwiseRockAuthorizationRecord{
						Version:    formalCoxBlockwiseRockRecordVersion,
						Family:     formalFinalizerHandoffFamilyCox,
						Purpose:    formalCoxBlockwiseRockPurpose,
						ArtifactID: context.ArtifactID, Role: "evaluator",
						Authorization: authorization, ProductionReady: false,
					}); err != nil {
					return err
				}
			}
			publication, err := formalCoxBlockwiseLiveControlPublication(
				store, binding, ticket, candidate)
			if formalCoxBlockwiseLiveControlAbsent(err) {
				result = formalCoxBlockwiseLiveControlAdvanceV1{
					ArtifactID: context.ArtifactID, State: "awaiting_publication",
				}
				return nil
			}
			if err != nil {
				return err
			}
			openingPublication := formalCoxBlockwiseRockPublicationToOpening(
				publication.Publication)
			stored, _, err := opening.ImportPublicPublication(openingPublication)
			clear(openingPublication.Certificate)
			if err != nil || stored.CertificateSHA256 != publication.Publication.CertificateSHA256 {
				clear(stored.Certificate)
				return fmt.Errorf("formal-cox live control: invalid publication import")
			}
			clear(stored.Certificate)
			receipt := formalCoxBlockwiseRockCommitReceipt{
				Version:           formalCoxBlockwiseRockRecordVersion,
				Purpose:           formalCoxBlockwiseRockCommitPurpose,
				ArtifactID:        context.ArtifactID,
				CertificateSHA256: publication.Publication.CertificateSHA256,
				PeerName:          local.PeerName, PeerID: local.PeerID, Role: local.Role,
				ProductionReady: false,
			}
			message, err := formalCoxBlockwiseRockCommitMessage(receipt)
			if err != nil {
				return err
			}
			receipt.Signature = ed25519.Sign(privateKey, message)
			clear(message)
			if err := formalCoxBlockwiseLiveControlWriteRecord(store,
				formalCoxControlRecordCommit, "evaluator",
				formalCoxBlockwiseRockCommitRecord{
					Version: formalCoxBlockwiseRockRecordVersion,
					Family:  formalFinalizerHandoffFamilyCox,
					Purpose: formalCoxBlockwiseRockCommitPurpose,
					Receipt: receipt, ProductionReady: false,
				}); err != nil {
				return err
			}
			result = formalCoxBlockwiseLiveControlAdvanceV1{
				ArtifactID: context.ArtifactID, State: "commit_ready",
				CertificateSHA256: publication.Publication.CertificateSHA256,
			}
			return nil
		})
	if err != nil {
		return zero, err
	}
	return result, nil
}
