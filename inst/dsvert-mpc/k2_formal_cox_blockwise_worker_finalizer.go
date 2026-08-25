package main

// The live Cox worker owns the only source-derived secret needed to persist
// its opaque finalizer envelope.  This file deliberately derives that outbox
// locally: a relay may carry signed headers and an encrypted envelope, but it
// never selects a Rock path, storage key, or replacement opening store.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

const formalCoxBlockwiseWorkerFinalizerOutboxDomain = "dsVert/formal-cox/blockwise-worker-finalizer-outbox/v1"

func formalCoxBlockwiseWorkerFinalizerOutboxKey(secret []byte,
	binding formalFinalizerHandoffBinding,
	local formalFinalizerHandoffAuthority,
) ([32]byte, error) {
	var key [32]byte
	if len(secret) != sha256.Size || !formalCoxIsSHA256(binding.ArtifactID) ||
		!formalCoxIsSHA256(binding.FinalPairRootSHA256) ||
		!formalCoxIsSHA256(binding.PlanSHA256) ||
		!formalCoxIsSHA256(binding.PinsetSHA256) ||
		!formalFinalizerHandoffBindingHasAuthority(binding, local) {
		return key, fmt.Errorf("formal-cox: invalid worker finalizer outbox binding")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(formalCoxBlockwiseWorkerFinalizerOutboxDomain + "|"))
	for _, value := range []string{
		binding.ArtifactID, binding.FinalPairRootSHA256, binding.PlanSHA256,
		binding.PinsetSHA256, local.PeerName, local.PeerID, local.Role,
	} {
		_, _ = mac.Write([]byte(value + "|"))
	}
	copy(key[:], mac.Sum(nil))
	return key, nil
}

func (bridge *formalCoxBlockwiseSourceBridge) openFinalizerOutboxAtRootV1(
	opening *formalCoxBlockwiseOpeningStore,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	stateRoot string, production bool,
) (*formalFinalizerHandoffStore, error) {
	if bridge == nil || opening == nil || !filepath.IsAbs(stateRoot) ||
		filepath.Clean(stateRoot) != stateRoot ||
		(production && stateRoot != formalFinalizerHandoffStateRoot) {
		return nil, fmt.Errorf("formal-cox: invalid worker finalizer outbox root")
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(opening, headers)
	if err != nil {
		return nil, err
	}
	bridge.mu.Lock()
	if bridge.closed || bridge.source == nil || bridge.worker == nil ||
		len(bridge.signingKey) != ed25519.PrivateKeySize {
		bridge.mu.Unlock()
		return nil, fmt.Errorf("formal-cox: worker finalizer bridge is unavailable")
	}
	source, peer, plan := bridge.source, bridge.peer, bridge.plan
	source.mu.Lock()
	valid := !source.closed && source.session != nil &&
		source.session.context != nil && source.recipient == peer &&
		len(source.recipientSK) == sha256.Size
	var contextPlanSHA, contextArtifactID, contextPinsetSHA, role, peerID string
	pins := map[string]ed25519.PublicKey(nil)
	secret := []byte(nil)
	if valid {
		context := source.session.context
		contextPlanSHA, contextArtifactID, contextPinsetSHA =
			context.planSHA256, context.artifactID, context.pinsetSHA256
		role, peerID = context.roles[peer], context.peerIDs[peer]
		pins = make(map[string]ed25519.PublicKey, len(context.pins))
		for name, pin := range context.pins {
			pins[name] = append(ed25519.PublicKey(nil), pin...)
		}
		secret = append([]byte(nil), source.recipientSK...)
	}
	source.mu.Unlock()
	bridge.mu.Unlock()
	defer clear(secret)
	defer formalCoxBlockwiseClearPinsV1(pins)
	planSHA, planErr := formalCoxBlockwisePlanSHA256(plan)
	if !valid || planErr != nil || planSHA != contextPlanSHA ||
		binding.ArtifactID != contextArtifactID ||
		binding.PlanSHA256 != contextPlanSHA ||
		binding.PinsetSHA256 != contextPinsetSHA {
		return nil, fmt.Errorf("formal-cox: worker finalizer binding changed")
	}
	local, err := formalFinalizerHandoffPeer(binding, role)
	if err != nil || local.PeerName != peer || local.PeerID != peerID ||
		formalFinalizerHandoffValidateBinding(binding, pins) != nil {
		return nil, fmt.Errorf("formal-cox: worker finalizer authority mismatch")
	}
	storageRoot, err := formalCoxBlockwiseWorkerFinalizerOutboxKey(
		secret, binding, local)
	if err != nil {
		return nil, err
	}
	defer clear(storageRoot[:])
	dir := filepath.Join(stateRoot, local.PeerName)
	if production {
		return newFormalFinalizerHandoffAuthorityStore(
			dir, binding, local, storageRoot, pins)
	}
	return newFormalFinalizerHandoffAuthorityStoreForTest(
		dir, binding, local, storageRoot, pins)
}

// SealStickyOpeningToFinalizerAtRootV1 is the closed continuation used by a
// live worker host.  Its public inputs are already signed headers and a
// finalizer ticket; all persistence parameters stay bound to the local
// recipient source secret.  The returned envelope is encrypted for the
// designated finalizer and contains no coefficient or validity share.
func (bridge *formalCoxBlockwiseSourceBridge) SealStickyOpeningToFinalizerAtRootV1(
	opening *formalCoxBlockwiseOpeningStore,
	ticket formalFinalizerHandoffTicket,
	headers [2]formalCoxBlockwiseOpeningHandoffHeader,
	stateRoot string, production bool,
) (formalFinalizerHandoffEnvelope, bool, error) {
	var zero formalFinalizerHandoffEnvelope
	outbox, err := bridge.openFinalizerOutboxAtRootV1(
		opening, headers, stateRoot, production)
	if err != nil {
		return zero, false, err
	}
	envelope, replayed, sealErr := bridge.SealStickyOpeningToFinalizerV1(
		opening, outbox, ticket, headers)
	outbox.Close()
	if sealErr != nil {
		return zero, false, sealErr
	}
	return envelope, replayed, nil
}
