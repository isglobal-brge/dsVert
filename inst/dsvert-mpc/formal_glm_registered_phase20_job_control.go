package main

// Non-production control and restart gate for one registered K2 job. Claim
// proposal/accept frames are their existing signed canonical DTOs. A JobRef is
// claimed only by a live controller after its run epoch has been burned.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sync"
)

const (
	formalGLMRegisteredPhase20JobControlVersionV1  = "dsvert-formal-glm-registered-phase20-job-control-v1"
	formalGLMRegisteredPhase20JobControlPurposeV1  = "formal_glm_registered_phase20_job_control_v1"
	formalGLMRegisteredPhase20JobControlDomainV1   = "dsVert/formal-glm/registered-phase20/job-control/v1"
	formalGLMRegisteredPhase20JobControlMaxFrameV1 = 2 << 20

	formalGLMRegisteredPhase20JobControlPeerJobRefKindV1 = "peer_job_ref"

	formalGLMRegisteredPhase20JobControlWaitingProposalStateV1 = "waiting_proposal"
	formalGLMRegisteredPhase20JobControlProposalStateV1        = "proposal"
	formalGLMRegisteredPhase20JobControlAcceptedStateV1        = "accepted"
)

// This is the sole new wire DTO. Proposal and Accept already carry signatures;
// JobRef needs an explicit role-bound signature before it can bind either
// durable relay metadata or the live in-memory transport.
type formalGLMRegisteredPhase20PeerJobRefClaimV1 struct {
	Version           string                             `json:"version"`
	Purpose           string                             `json:"purpose"`
	Kind              string                             `json:"kind"`
	ClaimAcceptSHA256 string                             `json:"claim_accept_sha256"`
	PeerName          string                             `json:"peer_name"`
	PeerID            string                             `json:"peer_id"`
	Role              string                             `json:"role"`
	JobRef            formalGLMRegisteredPhase20JobRefV1 `json:"job_ref"`
	ProductionReady   bool                               `json:"production_ready"`
	Signature         []byte                             `json:"signature"`
}

// All fields remain private. The handle borrows both stores; their owner must
// keep them alive until control is handed to a later lifecycle owner.
type formalGLMRegisteredPhase20JobControlV1 struct {
	mu       sync.Mutex
	attempts *formalGLMRegisteredPhase19AttemptStoreV1
	jobKeys  *formalGLMRegisteredPhase20JobKeyProviderV1
}

type formalGLMRegisteredPhase20JobControlStartResultV1 struct {
	state           string
	outbound        []byte
	productionReady bool
}

type formalGLMRegisteredPhase20JobControlGateV1 struct {
	proposal        formalGLMRegisteredPhase19ClaimProposalV1
	accept          formalGLMRegisteredPhase19ClaimAcceptV1
	epoch           formalGLMRegisteredPhase20JobTransportEpochV1
	startAllowed    bool
	inspectOnly     bool
	productionReady bool
}

type formalGLMRegisteredPhase20JobControlHeadV1 struct {
	previous *formalGLMRegisteredPhase19AbandonedV1
	status   formalGLMRegisteredPhase19AttemptStatusV1
}

type formalGLMRegisteredPhase20JobControlAcceptedV1 struct {
	proposal        formalGLMRegisteredPhase19ClaimProposalV1
	accept          formalGLMRegisteredPhase19ClaimAcceptV1
	claimAcceptSHA  string
	epoch           formalGLMRegisteredPhase20JobTransportEpochV1
	ref             formalGLMRegisteredPhase20JobRefV1
	root            *os.Root
	attemptRelative string
	binding         formalGLMRegisteredPhase20JobTransportBindingV1
}

func formalGLMRegisteredPhase20JobControlAuthorityLockedV1(
	store *formalGLMRegisteredPhase19AttemptStoreV1, index int,
) (peer, peerID, role string, err error) {
	if store == nil || store.root == nil || index < 0 || index > 1 {
		return "", "", "", fmt.Errorf("formal-glm registered Phase20 job control: authority unavailable")
	}
	plan := store.contract.Core.RegisteredExecutionPlan
	if len(plan.NoiseAuthorities) != 2 || len(plan.DesignatedComputePeers) != 2 ||
		plan.NoiseAuthorities[0].Role != "garbler" ||
		plan.NoiseAuthorities[1].Role != "evaluator" {
		return "", "", "", fmt.Errorf("formal-glm registered Phase20 job control: invalid K2 authorities")
	}
	for position := range 2 {
		if plan.NoiseAuthorities[position].PeerName !=
			plan.DesignatedComputePeers[position] {
			return "", "", "", fmt.Errorf("formal-glm registered Phase20 job control: compute authority mismatch")
		}
	}
	authority := plan.NoiseAuthorities[index]
	if authority.PeerName == "" || authority.PeerID == "" ||
		len(store.pins[authority.PeerName]) != ed25519.PublicKeySize {
		return "", "", "", fmt.Errorf("formal-glm registered Phase20 job control: invalid authority identity")
	}
	return authority.PeerName, authority.PeerID, authority.Role, nil
}

func newFormalGLMRegisteredPhase20JobControlV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
) (*formalGLMRegisteredPhase20JobControlV1, error) {
	if attempts == nil || jobKeys == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: missing owner")
	}
	attempts.mu.Lock()
	localIndex := attempts.localIndex
	peer, _, _, authorityErr :=
		formalGLMRegisteredPhase20JobControlAuthorityLockedV1(attempts, localIndex)
	validSigner := authorityErr == nil && len(attempts.signingKey) ==
		ed25519.PrivateKeySize && bytes.Equal(
		attempts.signingKey.Public().(ed25519.PublicKey), attempts.pins[peer])
	record, contract, attemptRoot := attempts.record, attempts.contract, attempts.root
	pins := formalGLMRegisteredPhase19ScheduleTailClonePinsV1(attempts.pins)
	attempts.mu.Unlock()
	if !validSigner {
		formalGLMRegisteredPhase19ScheduleTailClearPinsV1(pins)
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: invalid local signer")
	}
	context, contextErr := formalGLMRegisteredPhase20JobKeyContextFromEvidenceV1(
		contract, pins, record, peer)
	formalGLMRegisteredPhase19ScheduleTailClearPinsV1(pins)
	jobKeys.mu.Lock()
	keyRoot := jobKeys.root
	contextOK := contextErr == nil && jobKeys.validateLocked() == nil &&
		jobKeys.context == context
	jobKeys.mu.Unlock()
	if !contextOK || !formalGLMRegisteredPhase19ScheduleTailSameRootV1(
		attemptRoot, keyRoot) {
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: split storage owners")
	}
	return &formalGLMRegisteredPhase20JobControlV1{
		attempts: attempts, jobKeys: jobKeys,
	}, nil
}

func formalGLMRegisteredPhase20JobControlDecodeCanonicalV1[T any](
	encoded []byte,
) (T, error) {
	var zero T
	if len(encoded) == 0 || len(encoded) > formalGLMRegisteredPhase20JobControlMaxFrameV1 ||
		formalGLMPhase21RockStrictDecode(encoded, &zero) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job control: invalid canonical frame")
	}
	return zero, nil
}

func formalGLMRegisteredPhase20JobControlDecodeProposalV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1, encoded []byte,
) (formalGLMRegisteredPhase19ClaimProposalV1, error) {
	proposal, err := formalGLMRegisteredPhase20JobControlDecodeCanonicalV1[formalGLMRegisteredPhase19ClaimProposalV1](encoded)
	if err != nil || attempts == nil {
		return proposal, fmt.Errorf("formal-glm registered Phase20 job control: invalid proposal frame")
	}
	attempts.mu.Lock()
	valid := attempts.root != nil && attempts.validateProposalV1(proposal) == nil
	attempts.mu.Unlock()
	if !valid {
		return proposal, fmt.Errorf("formal-glm registered Phase20 job control: unauthenticated proposal frame")
	}
	return proposal, nil
}

func formalGLMRegisteredPhase20JobControlDecodeAcceptV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	encoded []byte,
) (formalGLMRegisteredPhase19ClaimAcceptV1, error) {
	accept, err := formalGLMRegisteredPhase20JobControlDecodeCanonicalV1[formalGLMRegisteredPhase19ClaimAcceptV1](encoded)
	if err != nil || attempts == nil {
		return accept, fmt.Errorf("formal-glm registered Phase20 job control: invalid accept frame")
	}
	attempts.mu.Lock()
	valid := attempts.root != nil && attempts.validateAcceptV1(proposal, accept) == nil
	attempts.mu.Unlock()
	if !valid {
		return accept, fmt.Errorf("formal-glm registered Phase20 job control: unauthenticated accept frame")
	}
	return accept, nil
}

func (control *formalGLMRegisteredPhase20JobControlV1) validateStartV1(
	start formalGLMRegisteredPhase20JobStartV1,
) error {
	if control == nil || control.attempts == nil ||
		!formalGLMIsSHA256(start.ArtifactID) ||
		!formalGLMIsSHA256(start.ReceiptSetSHA256) {
		return fmt.Errorf("formal-glm registered Phase20 job control: invalid JobStart")
	}
	control.attempts.mu.Lock()
	valid := control.attempts.root != nil &&
		start.ArtifactID == control.attempts.record.Binding.ArtifactID &&
		start.ReceiptSetSHA256 == control.attempts.record.Binding.ReceiptSetSHA256
	control.attempts.mu.Unlock()
	if !valid {
		return fmt.Errorf("formal-glm registered Phase20 job control: JobStart mismatch")
	}
	return nil
}

func (control *formalGLMRegisteredPhase20JobControlV1) localIndexV1() (int, error) {
	if control == nil || control.attempts == nil {
		return -1, fmt.Errorf("formal-glm registered Phase20 job control: unavailable")
	}
	control.attempts.mu.Lock()
	index := control.attempts.localIndex
	_, _, _, err := formalGLMRegisteredPhase20JobControlAuthorityLockedV1(
		control.attempts, index)
	control.attempts.mu.Unlock()
	return index, err
}

func (control *formalGLMRegisteredPhase20JobControlV1) loadHeadV1() (
	formalGLMRegisteredPhase20JobControlHeadV1, error,
) {
	var zero formalGLMRegisteredPhase20JobControlHeadV1
	var previous *formalGLMRegisteredPhase19AbandonedV1
	for {
		status, err := control.attempts.LoadStatus(previous)
		if err != nil {
			return zero, err
		}
		if status.abandoned != nil {
			value := *status.abandoned
			previous = &value
			continue
		}
		if status.votes[0] != nil || status.votes[1] != nil {
			return zero, fmt.Errorf("formal-glm registered Phase20 job control: attempt is abandoning")
		}
		return formalGLMRegisteredPhase20JobControlHeadV1{
			previous: previous, status: status,
		}, nil
	}
}

func (control *formalGLMRegisteredPhase20JobControlV1) encodeProposalV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
) ([]byte, error) {
	control.attempts.mu.Lock()
	valid := control.attempts.root != nil &&
		control.attempts.validateProposalV1(proposal) == nil
	control.attempts.mu.Unlock()
	if !valid {
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: invalid local proposal")
	}
	return json.Marshal(proposal)
}

func (control *formalGLMRegisteredPhase20JobControlV1) encodeAcceptV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) ([]byte, error) {
	control.attempts.mu.Lock()
	valid := control.attempts.root != nil &&
		control.attempts.validateAcceptV1(proposal, accept) == nil
	control.attempts.mu.Unlock()
	if !valid {
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: invalid local accept")
	}
	return json.Marshal(accept)
}

func (control *formalGLMRegisteredPhase20JobControlV1) persistAcceptV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) error {
	control.attempts.mu.Lock()
	if control.attempts.root == nil || control.attempts.localIndex < 0 ||
		control.attempts.localIndex > 1 {
		control.attempts.mu.Unlock()
		return fmt.Errorf("formal-glm registered Phase20 job control: attempt owner unavailable")
	}
	peer := control.attempts.contract.Core.RegisteredExecutionPlan.
		DesignatedComputePeers[control.attempts.localIndex]
	record, contract := control.attempts.record, control.attempts.contract
	pins := formalGLMRegisteredPhase19ScheduleTailClonePinsV1(control.attempts.pins)
	control.attempts.mu.Unlock()
	defer formalGLMRegisteredPhase19ScheduleTailClearPinsV1(pins)
	return formalGLMRegisteredPhase19ScheduleTailPersistClaimV1(
		control.attempts, record, contract, pins, peer, proposal, accept)
}

// StartV1 is intentionally role-dependent: the garbler begins and later
// adopts a canonical Accept; the evaluator waits for and accepts a canonical
// Proposal. It never creates or reopens a transport.
func (control *formalGLMRegisteredPhase20JobControlV1) StartV1(
	start formalGLMRegisteredPhase20JobStartV1, inbound []byte,
) (formalGLMRegisteredPhase20JobControlStartResultV1, error) {
	var zero formalGLMRegisteredPhase20JobControlStartResultV1
	if control == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job control: unavailable")
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if err := control.validateStartV1(start); err != nil {
		return zero, err
	}
	head, err := control.loadHeadV1()
	if err != nil {
		return zero, err
	}
	localIndex, err := control.localIndexV1()
	if err != nil {
		return zero, err
	}
	if localIndex == 0 {
		if head.status.proposal == nil {
			if len(inbound) != 0 {
				return zero, fmt.Errorf("formal-glm registered Phase20 job control: accept preceded proposal")
			}
			proposal, _, err := control.attempts.Begin(head.previous)
			if err != nil {
				return zero, err
			}
			encoded, err := control.encodeProposalV1(proposal)
			return formalGLMRegisteredPhase20JobControlStartResultV1{
				state:    formalGLMRegisteredPhase20JobControlProposalStateV1,
				outbound: encoded,
			}, err
		}
		proposal := *head.status.proposal
		if head.status.accept == nil {
			if len(inbound) == 0 {
				encoded, err := control.encodeProposalV1(proposal)
				return formalGLMRegisteredPhase20JobControlStartResultV1{
					state:    formalGLMRegisteredPhase20JobControlProposalStateV1,
					outbound: encoded,
				}, err
			}
			accept, err := formalGLMRegisteredPhase20JobControlDecodeAcceptV1(
				control.attempts, proposal, inbound)
			if err != nil || control.persistAcceptV1(proposal, accept) != nil {
				return zero, fmt.Errorf("formal-glm registered Phase20 job control: remote accept was not adopted")
			}
			return formalGLMRegisteredPhase20JobControlStartResultV1{
				state: formalGLMRegisteredPhase20JobControlAcceptedStateV1,
			}, nil
		}
		if len(inbound) != 0 {
			accept, err := formalGLMRegisteredPhase20JobControlDecodeAcceptV1(
				control.attempts, proposal, inbound)
			if err != nil || !reflect.DeepEqual(accept, *head.status.accept) ||
				control.persistAcceptV1(proposal, accept) != nil {
				return zero, fmt.Errorf("formal-glm registered Phase20 job control: conflicting accept replay")
			}
		}
		return formalGLMRegisteredPhase20JobControlStartResultV1{
			state: formalGLMRegisteredPhase20JobControlAcceptedStateV1,
		}, nil
	}

	if head.status.proposal == nil {
		if len(inbound) == 0 {
			return formalGLMRegisteredPhase20JobControlStartResultV1{
				state: formalGLMRegisteredPhase20JobControlWaitingProposalStateV1,
			}, nil
		}
		proposal, err := formalGLMRegisteredPhase20JobControlDecodeProposalV1(
			control.attempts, inbound)
		if err != nil || !reflect.DeepEqual(proposal.Binding, head.status.binding) {
			return zero, fmt.Errorf("formal-glm registered Phase20 job control: stale proposal frame")
		}
		accept, _, err := control.attempts.Accept(proposal)
		if err != nil {
			return zero, err
		}
		encoded, err := control.encodeAcceptV1(proposal, accept)
		return formalGLMRegisteredPhase20JobControlStartResultV1{
			state:    formalGLMRegisteredPhase20JobControlAcceptedStateV1,
			outbound: encoded,
		}, err
	}
	proposal := *head.status.proposal
	if head.status.accept == nil {
		if len(inbound) == 0 {
			return formalGLMRegisteredPhase20JobControlStartResultV1{
				state: formalGLMRegisteredPhase20JobControlWaitingProposalStateV1,
			}, nil
		}
		candidate, err := formalGLMRegisteredPhase20JobControlDecodeProposalV1(
			control.attempts, inbound)
		if err != nil || !reflect.DeepEqual(candidate, proposal) {
			return zero, fmt.Errorf("formal-glm registered Phase20 job control: proposal replay mismatch")
		}
		accept, _, err := control.attempts.Accept(proposal)
		if err != nil {
			return zero, err
		}
		encoded, err := control.encodeAcceptV1(proposal, accept)
		return formalGLMRegisteredPhase20JobControlStartResultV1{
			state:    formalGLMRegisteredPhase20JobControlAcceptedStateV1,
			outbound: encoded,
		}, err
	}
	if len(inbound) != 0 {
		candidate, err := formalGLMRegisteredPhase20JobControlDecodeProposalV1(
			control.attempts, inbound)
		if err != nil || !reflect.DeepEqual(candidate, proposal) {
			return zero, fmt.Errorf("formal-glm registered Phase20 job control: unexpected accepted frame")
		}
	}
	encoded, err := control.encodeAcceptV1(proposal, *head.status.accept)
	return formalGLMRegisteredPhase20JobControlStartResultV1{
		state:    formalGLMRegisteredPhase20JobControlAcceptedStateV1,
		outbound: encoded,
	}, err
}

func (control *formalGLMRegisteredPhase20JobControlV1) acceptedV1() (
	formalGLMRegisteredPhase20JobControlAcceptedV1, error,
) {
	var zero formalGLMRegisteredPhase20JobControlAcceptedV1
	head, err := control.loadHeadV1()
	if err != nil || head.status.proposal == nil || head.status.accept == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job control: accepted attempt unavailable")
	}
	proposal, accept := *head.status.proposal, *head.status.accept
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil {
		return zero, err
	}
	epoch := formalGLMRegisteredPhase20JobTransportEpochV1{
		Mode:        formalGLMRegisteredPhase20JobRunTransportV1,
		BasisSHA256: acceptSHA256,
	}
	root, relative, binding, err :=
		formalGLMRegisteredPhase20JobWorkerStartBindingV1(
			control.attempts, control.jobKeys, proposal, accept, epoch)
	if err != nil {
		return zero, err
	}
	jobSHA256, transportSHA256, err :=
		formalGLMRegisteredPhase20JobTransportIdentityV1(binding, epoch)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase20JobControlAcceptedV1{
		proposal: proposal, accept: accept, claimAcceptSHA: acceptSHA256,
		epoch: epoch, root: root, attemptRelative: relative, binding: binding,
		ref: formalGLMRegisteredPhase20JobRefV1{
			ArtifactID: binding.ArtifactID, ReceiptSetSHA256: binding.ReceiptSetSHA256,
			AttemptID: binding.AttemptID, JobSHA256: jobSHA256,
			TransportSHA256: transportSHA256, ProductionReady: false,
		},
	}, nil
}

func (control *formalGLMRegisteredPhase20JobControlV1) ResolveV1(
	start formalGLMRegisteredPhase20JobStartV1,
) (formalGLMRegisteredPhase20JobControlGateV1, error) {
	var zero formalGLMRegisteredPhase20JobControlGateV1
	if control == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job control: unavailable")
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if err := control.validateStartV1(start); err != nil {
		return zero, err
	}
	accepted, err := control.acceptedV1()
	if err != nil {
		return zero, err
	}
	burned, err := formalGLMRegisteredPhase20JobTransportBurnedV1(
		accepted.root, accepted.attemptRelative, accepted.binding, accepted.epoch)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase20JobControlGateV1{
		proposal: accepted.proposal, accept: accepted.accept, epoch: accepted.epoch,
		startAllowed: !burned, inspectOnly: burned, productionReady: false,
	}, nil
}

func formalGLMRegisteredPhase20PeerJobRefClaimMessageV1(
	claim formalGLMRegisteredPhase20PeerJobRefClaimV1,
) ([]byte, error) {
	ref := claim.JobRef
	if claim.Version != formalGLMRegisteredPhase20JobControlVersionV1 ||
		claim.Purpose != formalGLMRegisteredPhase20JobControlPurposeV1 ||
		claim.Kind != formalGLMRegisteredPhase20JobControlPeerJobRefKindV1 ||
		!formalGLMIsSHA256(claim.ClaimAcceptSHA256) || claim.PeerName == "" ||
		claim.PeerID == "" || claim.Role != "garbler" && claim.Role != "evaluator" ||
		ref.ProductionReady || claim.ProductionReady {
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: invalid peer JobRef claim")
	}
	for _, value := range []string{
		ref.ArtifactID, ref.ReceiptSetSHA256, ref.AttemptID,
		ref.JobSHA256, ref.TransportSHA256,
	} {
		if !formalGLMIsSHA256(value) {
			return nil, fmt.Errorf("formal-glm registered Phase20 job control: invalid peer JobRef identity")
		}
	}
	claim.Signature = nil
	encoded, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMRegisteredPhase20JobControlDomainV1+
		"/peer-job-ref-claim|"), encoded...), nil
}

func formalGLMRegisteredPhase20JobControlDecodePeerJobRefClaimV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1, encoded []byte,
) (formalGLMRegisteredPhase20PeerJobRefClaimV1, error) {
	claim, err := formalGLMRegisteredPhase20JobControlDecodeCanonicalV1[formalGLMRegisteredPhase20PeerJobRefClaimV1](encoded)
	if err != nil || attempts == nil || len(claim.Signature) != ed25519.SignatureSize {
		return claim, fmt.Errorf("formal-glm registered Phase20 job control: invalid peer JobRef frame")
	}
	message, err := formalGLMRegisteredPhase20PeerJobRefClaimMessageV1(claim)
	if err != nil {
		return claim, err
	}
	defer clear(message)
	attempts.mu.Lock()
	index := -1
	if claim.Role == "garbler" {
		index = 0
	} else if claim.Role == "evaluator" {
		index = 1
	}
	peer, peerID, role, authorityErr :=
		formalGLMRegisteredPhase20JobControlAuthorityLockedV1(attempts, index)
	valid := authorityErr == nil && claim.PeerName == peer &&
		claim.PeerID == peerID && claim.Role == role &&
		ed25519.Verify(attempts.pins[peer], message, claim.Signature)
	attempts.mu.Unlock()
	if !valid {
		return claim, fmt.Errorf("formal-glm registered Phase20 job control: unauthenticated peer JobRef frame")
	}
	return claim, nil
}

func (control *formalGLMRegisteredPhase20JobControlV1) signJobRefV1(
	accepted formalGLMRegisteredPhase20JobControlAcceptedV1,
	ref formalGLMRegisteredPhase20JobRefV1,
) ([]byte, error) {
	control.attempts.mu.Lock()
	index := control.attempts.localIndex
	peer, peerID, role, authorityErr :=
		formalGLMRegisteredPhase20JobControlAuthorityLockedV1(control.attempts, index)
	claim := formalGLMRegisteredPhase20PeerJobRefClaimV1{
		Version:           formalGLMRegisteredPhase20JobControlVersionV1,
		Purpose:           formalGLMRegisteredPhase20JobControlPurposeV1,
		Kind:              formalGLMRegisteredPhase20JobControlPeerJobRefKindV1,
		ClaimAcceptSHA256: accepted.claimAcceptSHA,
		PeerName:          peer, PeerID: peerID, Role: role, JobRef: ref,
		ProductionReady: false,
	}
	message, messageErr := formalGLMRegisteredPhase20PeerJobRefClaimMessageV1(claim)
	if authorityErr != nil || messageErr != nil || len(control.attempts.signingKey) !=
		ed25519.PrivateKeySize {
		control.attempts.mu.Unlock()
		clear(message)
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: JobRef signer unavailable")
	}
	claim.Signature = ed25519.Sign(control.attempts.signingKey, message)
	control.attempts.mu.Unlock()
	clear(message)
	return json.Marshal(claim)
}

func formalGLMRegisteredPhase20JobControlControllerLockedV1(
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
	accepted formalGLMRegisteredPhase20JobControlAcceptedV1,
) error {
	if controller == nil || controller.closed || controller.transport == nil ||
		controller.metadata == nil || controller.ownerLock == nil ||
		!reflect.DeepEqual(controller.transport.ref, accepted.ref) ||
		!reflect.DeepEqual(controller.metadata.ref, accepted.ref) {
		return fmt.Errorf("formal-glm registered Phase20 job control: foreign or closed controller")
	}
	wantLock, err := formalGLMRegisteredPhase20JobWorkerOwnerLockSHA256V1(
		accepted.ref.TransportSHA256)
	if err != nil || controller.ownerLockSHA256 != wantLock ||
		formalGLMRegisteredPhase20JobWorkerValidateLifetimeLockV1(
			controller.metadata.scratch, wantLock, controller.ownerLock) != nil {
		return fmt.Errorf("formal-glm registered Phase20 job control: controller authority unavailable")
	}
	relative, err := formalGLMRegisteredPhase20JobTransportRelativeV1(
		accepted.attemptRelative, accepted.ref.TransportSHA256)
	if err != nil {
		return err
	}
	wantInfo, wantErr := accepted.root.Lstat(relative)
	metadataInfo, metadataErr := controller.metadata.scratch.Stat(".")
	transportInfo, transportErr := controller.transport.scratch.Stat(".")
	if wantErr != nil || metadataErr != nil || transportErr != nil ||
		!os.SameFile(wantInfo, metadataInfo) || !os.SameFile(wantInfo, transportInfo) {
		return fmt.Errorf("formal-glm registered Phase20 job control: controller storage mismatch")
	}
	controller.transport.mu.Lock()
	running := !controller.transport.closed &&
		controller.transport.state == formalGLMRegisteredPhase20JobRunningV1
	controller.transport.mu.Unlock()
	if !running {
		return fmt.Errorf("formal-glm registered Phase20 job control: controller is not running")
	}
	if formalGLMRegisteredPhase20JobTransportAbortValidV1(
		controller.transport.scratch) {
		return fmt.Errorf("formal-glm registered Phase20 job control: controller is stopping")
	}
	return nil
}

func (control *formalGLMRegisteredPhase20JobControlV1) JobRefV1(
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
) (formalGLMRegisteredPhase20JobRefV1, []byte, error) {
	var zero formalGLMRegisteredPhase20JobRefV1
	if control == nil || controller == nil {
		return zero, nil, fmt.Errorf("formal-glm registered Phase20 job control: controller unavailable")
	}
	fence, err := control.controllerFenceV1(controller)
	if err != nil {
		return zero, nil, err
	}
	defer fence.Close()
	return control.jobRefWithFenceV1(fence, controller)
}

func (control *formalGLMRegisteredPhase20JobControlV1) controllerFenceV1(
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
) (*formalGLMRegisteredPhase20AttemptFenceV1, error) {
	if control == nil || control.attempts == nil || controller == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: controller unavailable")
	}
	controller.mu.Lock()
	attemptID := ""
	if !controller.closed && controller.transport != nil {
		attemptID = controller.transport.ref.AttemptID
	}
	controller.mu.Unlock()
	if attemptID == "" {
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: controller unavailable")
	}
	return formalGLMRegisteredPhase20AcquireAttemptFenceV1(
		control.attempts, attemptID)
}

func (control *formalGLMRegisteredPhase20JobControlV1) jobRefWithFenceV1(
	fence *formalGLMRegisteredPhase20AttemptFenceV1,
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
) (formalGLMRegisteredPhase20JobRefV1, []byte, error) {
	var zero formalGLMRegisteredPhase20JobRefV1
	control.mu.Lock()
	defer control.mu.Unlock()
	accepted, err := control.acceptedV1()
	if err != nil {
		return zero, nil, err
	}
	if err := formalGLMRegisteredPhase20AttemptPairV1(
		control.attempts, fence, accepted.proposal, accepted.accept, true); err != nil {
		return zero, nil, err
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	err = formalGLMRegisteredPhase20JobControlControllerLockedV1(
		controller, accepted)
	ref := accepted.ref
	if err != nil {
		return zero, nil, err
	}
	encoded, err := control.signJobRefV1(accepted, ref)
	if err != nil {
		return zero, nil, err
	}
	return ref, encoded, nil
}

func (control *formalGLMRegisteredPhase20JobControlV1) BindPeerJobRefV1(
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
	encoded []byte,
) error {
	if control == nil || controller == nil {
		return fmt.Errorf("formal-glm registered Phase20 job control: controller unavailable")
	}
	fence, err := control.controllerFenceV1(controller)
	if err != nil {
		return err
	}
	defer fence.Close()
	return control.bindPeerJobRefWithFenceV1(fence, controller, encoded)
}

func (control *formalGLMRegisteredPhase20JobControlV1) bindPeerJobRefWithFenceV1(
	fence *formalGLMRegisteredPhase20AttemptFenceV1,
	controller *formalGLMRegisteredPhase20JobWorkerControllerV1,
	encoded []byte,
) error {
	control.mu.Lock()
	defer control.mu.Unlock()
	accepted, err := control.acceptedV1()
	if err != nil {
		return err
	}
	if err := formalGLMRegisteredPhase20AttemptPairV1(
		control.attempts, fence, accepted.proposal, accepted.accept, true); err != nil {
		return err
	}
	claim, err := formalGLMRegisteredPhase20JobControlDecodePeerJobRefClaimV1(
		control.attempts, encoded)
	if err != nil {
		return err
	}
	localIndex, err := control.localIndexV1()
	if err != nil {
		return err
	}
	control.attempts.mu.Lock()
	peer, peerID, role, peerErr :=
		formalGLMRegisteredPhase20JobControlAuthorityLockedV1(
			control.attempts, 1-localIndex)
	control.attempts.mu.Unlock()
	if peerErr != nil || claim.PeerName != peer || claim.PeerID != peerID ||
		claim.Role != role || claim.ClaimAcceptSHA256 != accepted.claimAcceptSHA ||
		!reflect.DeepEqual(claim.JobRef, accepted.ref) {
		return fmt.Errorf("formal-glm registered Phase20 job control: peer JobRef mismatch")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if err := formalGLMRegisteredPhase20JobControlControllerLockedV1(
		controller, accepted); err != nil {
		return err
	}
	// Persist the exact full peer ref before allowing any in-memory worker byte.
	if err := controller.metadata.BindPeerEpochV1(claim.JobRef); err != nil {
		return err
	}
	return controller.transport.BindPeerEpochV1(
		claim.JobRef.TransportSHA256)
}
