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
	"path/filepath"
)

type formalCoxBlockwiseLiveControlStageV1 struct {
	ArtifactID      string `json:"artifact_id"`
	CandidateSHA256 string `json:"candidate_sha256,omitempty"`
	LocalRole       string `json:"local_role"`
	ProductionReady bool   `json:"-"`
}

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
