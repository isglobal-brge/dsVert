package main

// Durable, public-only negotiation for one registered Phase19 execution
// attempt. Execution inputs, workers and Phase20 handoff are intentionally out
// of scope. Every path is derived from the sealed semantic root and attempt
// chain; there is no mutable latest-attempt pointer.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

const (
	formalGLMRegisteredPhase19ClaimProposalVersionV1 = "dsvert-formal-glm-registered-phase19-claim-proposal-v1"
	formalGLMRegisteredPhase19ClaimProposalPurposeV1 = "formal_glm_registered_phase19_garbler_claim_v1"
	formalGLMRegisteredPhase19ClaimProposalDomainV1  = "dsVert/formal-glm/registered-phase19/claim-proposal/v1"

	formalGLMRegisteredPhase19ClaimAcceptVersionV1 = "dsvert-formal-glm-registered-phase19-claim-accept-v1"
	formalGLMRegisteredPhase19ClaimAcceptPurposeV1 = "formal_glm_registered_phase19_evaluator_accept_v1"
	formalGLMRegisteredPhase19ClaimAcceptDomainV1  = "dsVert/formal-glm/registered-phase19/claim-accept/v1"

	formalGLMRegisteredPhase19DecisionVoteVersionV1 = "dsvert-formal-glm-registered-phase19-decision-vote-v1"
	formalGLMRegisteredPhase19DecisionVotePurposeV1 = "formal_glm_registered_phase19_abandon_vote_v1"
	formalGLMRegisteredPhase19DecisionVoteDomainV1  = "dsVert/formal-glm/registered-phase19/decision-vote/v1"

	formalGLMRegisteredPhase19AbandonedVersionV1 = "dsvert-formal-glm-registered-phase19-abandoned-v1"
	formalGLMRegisteredPhase19AbandonedPurposeV1 = "formal_glm_registered_phase19_k2_abandoned_v1"
	formalGLMRegisteredPhase19AbandonedDomainV1  = "dsVert/formal-glm/registered-phase19/abandoned/v1"

	formalGLMRegisteredPhase19AttemptDomainV1 = "dsVert/formal-glm/registered-phase19/attempt-negotiation/v1"
	formalGLMRegisteredPhase19AttemptDirV1    = "registered-phase19-attempt-negotiation-v1"

	formalGLMRegisteredPhase19ClaimProposalFileV1 = "claim-proposal.json"
	formalGLMRegisteredPhase19ClaimAcceptFileV1   = "claim-accept.json"
	formalGLMRegisteredPhase19DecisionVote0FileV1 = "decision-vote-0.json"
	formalGLMRegisteredPhase19DecisionVote1FileV1 = "decision-vote-1.json"
	formalGLMRegisteredPhase19AbandonedFileV1     = "abandoned.json"

	formalGLMRegisteredPhase19AttemptMaxRecordV1    = int64(2 << 20)
	formalGLMRegisteredPhase19AttemptZeroPreviousV1 = "0000000000000000000000000000000000000000000000000000000000000000"
)

type formalGLMRegisteredPhase19AttemptBindingV1 struct {
	ArtifactID                    string `json:"artifact_id"`
	SourceContractCoreSHA256      string `json:"source_contract_core_sha256"`
	SourceContractSHA256          string `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string `json:"registered_execution_plan_sha256"`
	PinsetSHA256                  string `json:"pinset_sha256"`
	BindingRecordSHA256           string `json:"binding_record_sha256"`
	SemanticRootSHA256            string `json:"semantic_root_sha256"`
	PreviousAbandonSHA256         string `json:"previous_abandon_sha256"`
	PreviousAttemptID             string `json:"previous_attempt_id"`
	AttemptID                     string `json:"attempt_id"`
	ScheduleRootSHA256            string `json:"schedule_root_sha256"`
	OpeningsPerformed             int    `json:"openings_performed"`
	ProductionReady               bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase19ClaimProposalV1 struct {
	Version         string                                     `json:"version"`
	Purpose         string                                     `json:"purpose"`
	Binding         formalGLMRegisteredPhase19AttemptBindingV1 `json:"binding"`
	GarblerPeerName string                                     `json:"garbler_peer_name"`
	GarblerPeerID   string                                     `json:"garbler_peer_id"`
	Signature       []byte                                     `json:"signature"`
}

type formalGLMRegisteredPhase19ClaimAcceptV1 struct {
	Version             string                                     `json:"version"`
	Purpose             string                                     `json:"purpose"`
	Binding             formalGLMRegisteredPhase19AttemptBindingV1 `json:"binding"`
	ClaimProposalSHA256 string                                     `json:"claim_proposal_sha256"`
	EvaluatorPeerName   string                                     `json:"evaluator_peer_name"`
	EvaluatorPeerID     string                                     `json:"evaluator_peer_id"`
	Signature           []byte                                     `json:"signature"`
}

type formalGLMRegisteredPhase19DecisionVoteV1 struct {
	Version             string                                     `json:"version"`
	Purpose             string                                     `json:"purpose"`
	Binding             formalGLMRegisteredPhase19AttemptBindingV1 `json:"binding"`
	ClaimProposalSHA256 string                                     `json:"claim_proposal_sha256"`
	ClaimAcceptSHA256   string                                     `json:"claim_accept_sha256"`
	Decision            string                                     `json:"decision"`
	VoterRole           string                                     `json:"voter_role"`
	VoterPeerName       string                                     `json:"voter_peer_name"`
	VoterPeerID         string                                     `json:"voter_peer_id"`
	Signature           []byte                                     `json:"signature"`
}

type formalGLMRegisteredPhase19AbandonedV1 struct {
	Version         string                                     `json:"version"`
	Purpose         string                                     `json:"purpose"`
	Binding         formalGLMRegisteredPhase19AttemptBindingV1 `json:"binding"`
	ClaimProposal   formalGLMRegisteredPhase19ClaimProposalV1  `json:"claim_proposal"`
	ClaimAccept     formalGLMRegisteredPhase19ClaimAcceptV1    `json:"claim_accept"`
	DecisionVotes   []formalGLMRegisteredPhase19DecisionVoteV1 `json:"decision_votes"`
	AbandonedSHA256 string                                     `json:"abandoned_sha256"`
}

// This snapshot is server-internal and deliberately has no exported fields,
// so it cannot become another public wire DTO by accidental JSON marshalling.
type formalGLMRegisteredPhase19AttemptStatusV1 struct {
	binding   formalGLMRegisteredPhase19AttemptBindingV1
	proposal  *formalGLMRegisteredPhase19ClaimProposalV1
	accept    *formalGLMRegisteredPhase19ClaimAcceptV1
	votes     [2]*formalGLMRegisteredPhase19DecisionVoteV1
	abandoned *formalGLMRegisteredPhase19AbandonedV1
}

type formalGLMRegisteredPhase19AttemptStoreV1 struct {
	mu           sync.Mutex
	root         *os.Root
	record       formalGLMRegisteredPhase19BindingRecordV1
	contract     formalGLMSourceContractV1
	recordSHA256 string
	pins         map[string]ed25519.PublicKey
	localIndex   int
	signingKey   ed25519.PrivateKey
}

type formalGLMRegisteredPhase19AttemptIDInputV1 struct {
	SemanticRootSHA256    string `json:"semantic_root_sha256"`
	PreviousAbandonSHA256 string `json:"previous_abandon_sha256"`
}

type formalGLMRegisteredPhase19ScheduleRootInputV1 struct {
	SemanticRootSHA256 string `json:"semantic_root_sha256"`
	AttemptID          string `json:"attempt_id"`
}

func formalGLMRegisteredPhase19AttemptIDV1(
	semanticRootSHA256, previousAbandonSHA256 string,
) (string, error) {
	if !formalGLMIsSHA256(semanticRootSHA256) ||
		!formalGLMIsSHA256(previousAbandonSHA256) {
		return "", fmt.Errorf("formal-glm registered Phase19 attempt: invalid identity input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/attempt-id",
		formalGLMRegisteredPhase19AttemptIDInputV1{
			SemanticRootSHA256:    semanticRootSHA256,
			PreviousAbandonSHA256: previousAbandonSHA256,
		})
}

func formalGLMRegisteredPhase19AttemptScheduleRootV1(
	semanticRootSHA256, attemptID string,
) (string, error) {
	if !formalGLMIsSHA256(semanticRootSHA256) ||
		!formalGLMIsSHA256(attemptID) {
		return "", fmt.Errorf("formal-glm registered Phase19 attempt: invalid schedule input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/schedule-root",
		formalGLMRegisteredPhase19ScheduleRootInputV1{
			SemanticRootSHA256: semanticRootSHA256, AttemptID: attemptID,
		})
}

func formalGLMRegisteredPhase19AttemptSignatureMessageV1(
	domain string, value any,
) ([]byte, error) {
	switch typed := value.(type) {
	case formalGLMRegisteredPhase19ClaimProposalV1:
		typed.Signature = nil
		value = typed
	case formalGLMRegisteredPhase19ClaimAcceptV1:
		typed.Signature = nil
		value = typed
	case formalGLMRegisteredPhase19DecisionVoteV1:
		typed.Signature = nil
		value = typed
	default:
		return nil, fmt.Errorf("formal-glm registered Phase19 attempt: invalid signature type")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain+"|"), encoded...), nil
}

func formalGLMRegisteredPhase19ClaimProposalSHA256V1(
	value formalGLMRegisteredPhase19ClaimProposalV1,
) (string, error) {
	if value.Version != formalGLMRegisteredPhase19ClaimProposalVersionV1 ||
		value.Purpose != formalGLMRegisteredPhase19ClaimProposalPurposeV1 ||
		len(value.Signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("formal-glm registered Phase19 attempt: invalid claim hash input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19ClaimProposalDomainV1+"/signed", value)
}

func formalGLMRegisteredPhase19ClaimAcceptSHA256V1(
	value formalGLMRegisteredPhase19ClaimAcceptV1,
) (string, error) {
	if value.Version != formalGLMRegisteredPhase19ClaimAcceptVersionV1 ||
		value.Purpose != formalGLMRegisteredPhase19ClaimAcceptPurposeV1 ||
		len(value.Signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("formal-glm registered Phase19 attempt: invalid accept hash input")
	}
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19ClaimAcceptDomainV1+"/signed", value)
}

func formalGLMRegisteredPhase19AttemptAbandonedSHA256V1(
	value formalGLMRegisteredPhase19AbandonedV1,
) (string, error) {
	if value.Version != formalGLMRegisteredPhase19AbandonedVersionV1 ||
		value.Purpose != formalGLMRegisteredPhase19AbandonedPurposeV1 ||
		(value.AbandonedSHA256 != "" &&
			!formalGLMIsSHA256(value.AbandonedSHA256)) {
		return "", fmt.Errorf("formal-glm registered Phase19 attempt: invalid abandoned hash input")
	}
	value.AbandonedSHA256 = ""
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AbandonedDomainV1+"/aggregate", value)
}

func newFormalGLMRegisteredPhase19AttemptStoreV1(
	rockRoot string,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	localPeer string,
	signingKey ed25519.PrivateKey,
) (*formalGLMRegisteredPhase19AttemptStoreV1, error) {
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}
	clonedContract, err := formalGLMDecodeSourceContractV1(
		contractJSON, clonedPins)
	clear(contractJSON)
	if err != nil {
		return nil, err
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	var clonedRecord formalGLMRegisteredPhase19BindingRecordV1
	if formalGLMPhase21RockStrictDecode(recordJSON, &clonedRecord) != nil ||
		formalGLMValidateRegisteredPhase19BindingRecordV1(
			clonedRecord, clonedContract, clonedPins) != nil {
		clear(recordJSON)
		return nil, fmt.Errorf("formal-glm registered Phase19 attempt: invalid binding record")
	}
	clear(recordJSON)
	plan := clonedContract.Core.RegisteredExecutionPlan
	localIndex := -1
	for index, authority := range plan.NoiseAuthorities {
		if authority.PeerName == localPeer {
			localIndex = index
		}
	}
	if localIndex < 0 || len(plan.NoiseAuthorities) != 2 ||
		len(signingKey) != ed25519.PrivateKeySize ||
		len(clonedPins[localPeer]) != ed25519.PublicKeySize ||
		!bytes.Equal(signingKey.Public().(ed25519.PublicKey),
			clonedPins[localPeer]) {
		return nil, fmt.Errorf("formal-glm registered Phase19 attempt: invalid local signer")
	}
	recordSHA256, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19AttemptDomainV1+"/binding-record",
		clonedRecord)
	if err != nil {
		return nil, err
	}
	root, err := formalGLMRegisteredPhase19OpenRockRootV1(rockRoot)
	if err != nil {
		return nil, err
	}
	store := &formalGLMRegisteredPhase19AttemptStoreV1{
		root: root, record: clonedRecord, contract: clonedContract,
		recordSHA256: recordSHA256, pins: clonedPins, localIndex: localIndex,
		signingKey: append(ed25519.PrivateKey(nil), signingKey...),
	}
	if err := formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
		root, store.baseRelativeDirV1()); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) baseRelativeDirV1() string {
	if store == nil || !formalGLMIsSHA256(store.record.Binding.ArtifactID) ||
		!formalGLMIsSHA256(store.record.Binding.SemanticRootSHA256) ||
		store.localIndex < 0 || store.localIndex > 1 {
		return ""
	}
	artifact := store.record.Binding.ArtifactID
	return filepath.Join(formalGLMRegisteredPhase19AttemptDirV1,
		artifact[:2], artifact[2:4], artifact,
		store.record.Binding.SemanticRootSHA256,
		fmt.Sprintf("local-peer-%d", store.localIndex))
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) attemptRelativeDirV1(
	attemptID string,
) string {
	if store == nil || !formalGLMIsSHA256(attemptID) {
		return ""
	}
	return filepath.Join(store.baseRelativeDirV1(), "attempts", attemptID)
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) attemptRelativePathV1(
	attemptID, file string,
) string {
	directory := store.attemptRelativeDirV1(attemptID)
	if directory == "" || file == "" || filepath.Base(file) != file {
		return ""
	}
	return filepath.Join(directory, file)
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) bindingV1(
	previousAbandonSHA256, previousAttemptID string,
) (formalGLMRegisteredPhase19AttemptBindingV1, error) {
	var zero formalGLMRegisteredPhase19AttemptBindingV1
	first := previousAbandonSHA256 ==
		formalGLMRegisteredPhase19AttemptZeroPreviousV1 &&
		previousAttemptID == formalGLMRegisteredPhase19AttemptZeroPreviousV1
	if !first && (!formalGLMIsSHA256(previousAbandonSHA256) ||
		!formalGLMIsSHA256(previousAttemptID) ||
		previousAbandonSHA256 == formalGLMRegisteredPhase19AttemptZeroPreviousV1 ||
		previousAttemptID == formalGLMRegisteredPhase19AttemptZeroPreviousV1) {
		return zero, fmt.Errorf("formal-glm registered Phase19 attempt: invalid predecessor")
	}
	semantic := store.record.Binding.SemanticRootSHA256
	attemptID, err := formalGLMRegisteredPhase19AttemptIDV1(
		semantic, previousAbandonSHA256)
	if err != nil {
		return zero, err
	}
	scheduleRoot, err := formalGLMRegisteredPhase19AttemptScheduleRootV1(
		semantic, attemptID)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase19AttemptBindingV1{
		ArtifactID:                    store.record.Binding.ArtifactID,
		SourceContractCoreSHA256:      store.record.Binding.SourceContractCoreSHA256,
		SourceContractSHA256:          store.record.Binding.SourceContractSHA256,
		RegisteredExecutionPlanSHA256: store.record.Binding.RegisteredExecutionPlanSHA256,
		PinsetSHA256:                  store.record.Binding.PinsetSHA256,
		BindingRecordSHA256:           store.recordSHA256,
		SemanticRootSHA256:            semantic,
		PreviousAbandonSHA256:         previousAbandonSHA256,
		PreviousAttemptID:             previousAttemptID,
		AttemptID:                     attemptID,
		ScheduleRootSHA256:            scheduleRoot,
		OpeningsPerformed:             0,
		ProductionReady:               false,
	}, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) proposalV1(
	binding formalGLMRegisteredPhase19AttemptBindingV1,
) formalGLMRegisteredPhase19ClaimProposalV1 {
	authority := store.contract.Core.RegisteredExecutionPlan.NoiseAuthorities[0]
	return formalGLMRegisteredPhase19ClaimProposalV1{
		Version: formalGLMRegisteredPhase19ClaimProposalVersionV1,
		Purpose: formalGLMRegisteredPhase19ClaimProposalPurposeV1,
		Binding: binding, GarblerPeerName: authority.PeerName,
		GarblerPeerID: authority.PeerID,
	}
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) validateProposalV1(
	value formalGLMRegisteredPhase19ClaimProposalV1,
) error {
	binding, err := store.bindingV1(
		value.Binding.PreviousAbandonSHA256,
		value.Binding.PreviousAttemptID)
	expected := store.proposalV1(binding)
	unsigned := value
	unsigned.Signature = nil
	message, messageErr := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19ClaimProposalDomainV1, unsigned)
	if err != nil || messageErr != nil || !reflect.DeepEqual(unsigned, expected) ||
		len(value.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(store.pins[expected.GarblerPeerName],
			message, value.Signature) {
		return fmt.Errorf("formal-glm registered Phase19 attempt: invalid claim proposal")
	}
	return nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) acceptV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
) (formalGLMRegisteredPhase19ClaimAcceptV1, error) {
	proposalSHA256, err := formalGLMRegisteredPhase19ClaimProposalSHA256V1(
		proposal)
	if err != nil {
		return formalGLMRegisteredPhase19ClaimAcceptV1{}, err
	}
	authority := store.contract.Core.RegisteredExecutionPlan.NoiseAuthorities[1]
	return formalGLMRegisteredPhase19ClaimAcceptV1{
		Version: formalGLMRegisteredPhase19ClaimAcceptVersionV1,
		Purpose: formalGLMRegisteredPhase19ClaimAcceptPurposeV1,
		Binding: proposal.Binding, ClaimProposalSHA256: proposalSHA256,
		EvaluatorPeerName: authority.PeerName, EvaluatorPeerID: authority.PeerID,
	}, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) validateAcceptV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	value formalGLMRegisteredPhase19ClaimAcceptV1,
) error {
	if err := store.validateProposalV1(proposal); err != nil {
		return err
	}
	expected, err := store.acceptV1(proposal)
	unsigned := value
	unsigned.Signature = nil
	message, messageErr := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19ClaimAcceptDomainV1, unsigned)
	if err != nil || messageErr != nil || !reflect.DeepEqual(unsigned, expected) ||
		len(value.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(store.pins[expected.EvaluatorPeerName],
			message, value.Signature) {
		return fmt.Errorf("formal-glm registered Phase19 attempt: invalid claim accept")
	}
	return nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) voteV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	voterIndex int,
) (formalGLMRegisteredPhase19DecisionVoteV1, error) {
	proposalSHA256, err := formalGLMRegisteredPhase19ClaimProposalSHA256V1(
		proposal)
	if err != nil {
		return formalGLMRegisteredPhase19DecisionVoteV1{}, err
	}
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil {
		return formalGLMRegisteredPhase19DecisionVoteV1{}, err
	}
	if voterIndex < 0 || voterIndex > 1 {
		return formalGLMRegisteredPhase19DecisionVoteV1{},
			fmt.Errorf("formal-glm registered Phase19 attempt: invalid voter")
	}
	authority := store.contract.Core.RegisteredExecutionPlan.NoiseAuthorities[voterIndex]
	return formalGLMRegisteredPhase19DecisionVoteV1{
		Version: formalGLMRegisteredPhase19DecisionVoteVersionV1,
		Purpose: formalGLMRegisteredPhase19DecisionVotePurposeV1,
		Binding: proposal.Binding, ClaimProposalSHA256: proposalSHA256,
		ClaimAcceptSHA256: acceptSHA256, Decision: "abandon",
		VoterRole: authority.Role, VoterPeerName: authority.PeerName,
		VoterPeerID: authority.PeerID,
	}, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) voteIndexV1(
	vote formalGLMRegisteredPhase19DecisionVoteV1,
) int {
	for index, authority := range store.contract.Core.RegisteredExecutionPlan.NoiseAuthorities {
		if vote.VoterRole == authority.Role &&
			vote.VoterPeerName == authority.PeerName &&
			vote.VoterPeerID == authority.PeerID {
			return index
		}
	}
	return -1
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) validateVoteV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	value formalGLMRegisteredPhase19DecisionVoteV1,
) (int, error) {
	if err := store.validateAcceptV1(proposal, accept); err != nil {
		return -1, err
	}
	index := store.voteIndexV1(value)
	expected, err := store.voteV1(proposal, accept, index)
	unsigned := value
	unsigned.Signature = nil
	message, messageErr := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19DecisionVoteDomainV1, unsigned)
	if err != nil || messageErr != nil || !reflect.DeepEqual(unsigned, expected) ||
		len(value.Signature) != ed25519.SignatureSize || index < 0 ||
		!ed25519.Verify(store.pins[expected.VoterPeerName],
			message, value.Signature) {
		return -1, fmt.Errorf("formal-glm registered Phase19 attempt: invalid abandonment vote")
	}
	return index, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) abandonedV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	votes []formalGLMRegisteredPhase19DecisionVoteV1,
) (formalGLMRegisteredPhase19AbandonedV1, error) {
	var zero formalGLMRegisteredPhase19AbandonedV1
	if len(votes) != 2 || store.validateAcceptV1(proposal, accept) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 attempt: incomplete abandonment pair")
	}
	ordered := make([]formalGLMRegisteredPhase19DecisionVoteV1, 2)
	seen := [2]bool{}
	for _, vote := range votes {
		index, err := store.validateVoteV1(proposal, accept, vote)
		if err != nil || seen[index] {
			return zero, fmt.Errorf("formal-glm registered Phase19 attempt: invalid abandonment pair")
		}
		seen[index] = true
		ordered[index] = vote
	}
	if !seen[0] || !seen[1] {
		return zero, fmt.Errorf("formal-glm registered Phase19 attempt: incomplete abandonment pair")
	}
	value := formalGLMRegisteredPhase19AbandonedV1{
		Version: formalGLMRegisteredPhase19AbandonedVersionV1,
		Purpose: formalGLMRegisteredPhase19AbandonedPurposeV1,
		Binding: proposal.Binding, ClaimProposal: proposal,
		ClaimAccept: accept, DecisionVotes: ordered,
	}
	var err error
	value.AbandonedSHA256, err =
		formalGLMRegisteredPhase19AttemptAbandonedSHA256V1(value)
	if err != nil {
		return zero, err
	}
	return value, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) validateAbandonedV1(
	value formalGLMRegisteredPhase19AbandonedV1,
) error {
	expected, err := store.abandonedV1(
		value.ClaimProposal, value.ClaimAccept, value.DecisionVotes)
	if err != nil || !reflect.DeepEqual(value, expected) {
		return fmt.Errorf("formal-glm registered Phase19 attempt: invalid abandoned aggregate")
	}
	return nil
}

func formalGLMRegisteredPhase19AttemptReadV1[T any](
	root *os.Root, relative string,
) (T, bool, error) {
	var zero T
	encoded, err := formalGLMPhase21RootReadRecord(
		root, relative, formalGLMRegisteredPhase19AttemptMaxRecordV1)
	if os.IsNotExist(err) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	defer clear(encoded)
	var value T
	if err := formalGLMPhase21RockStrictDecode(encoded, &value); err != nil {
		return zero, false, err
	}
	return value, true, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) commitV1(
	relative string, value any,
) (bool, error) {
	if relative == "" {
		return false, fmt.Errorf("formal-glm registered Phase19 attempt: invalid durable path")
	}
	if err := formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
		store.root, filepath.Dir(relative)); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > int(formalGLMRegisteredPhase19AttemptMaxRecordV1) {
		return false, fmt.Errorf("formal-glm registered Phase19 attempt: invalid record encoding")
	}
	defer clear(encoded)
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return false, err
	}
	persisted, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMRegisteredPhase19AttemptMaxRecordV1)
	if err != nil {
		return false, err
	}
	defer clear(persisted)
	if !bytes.Equal(persisted, encoded) {
		return false, fmt.Errorf("formal-glm registered Phase19 attempt: durable CAS conflict")
	}
	return !created, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) requirePreviousBindingV1(
	binding formalGLMRegisteredPhase19AttemptBindingV1,
) error {
	if binding.PreviousAbandonSHA256 ==
		formalGLMRegisteredPhase19AttemptZeroPreviousV1 &&
		binding.PreviousAttemptID ==
			formalGLMRegisteredPhase19AttemptZeroPreviousV1 {
		return nil
	}
	previous, found, err := formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19AbandonedV1](store.root,
		store.attemptRelativePathV1(binding.PreviousAttemptID,
			formalGLMRegisteredPhase19AbandonedFileV1))
	if err != nil || !found || store.validateAbandonedV1(previous) != nil ||
		previous.Binding.AttemptID != binding.PreviousAttemptID ||
		previous.AbandonedSHA256 != binding.PreviousAbandonSHA256 {
		return fmt.Errorf("formal-glm registered Phase19 attempt: previous abandonment unavailable")
	}
	return nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) previousV1(
	previous *formalGLMRegisteredPhase19AbandonedV1,
) (string, string, error) {
	if previous == nil {
		return formalGLMRegisteredPhase19AttemptZeroPreviousV1,
			formalGLMRegisteredPhase19AttemptZeroPreviousV1, nil
	}
	if err := store.validateAbandonedV1(*previous); err != nil {
		return "", "", err
	}
	binding, err := store.bindingV1(
		previous.AbandonedSHA256, previous.Binding.AttemptID)
	if err != nil || store.requirePreviousBindingV1(binding) != nil {
		return "", "", fmt.Errorf("formal-glm registered Phase19 attempt: prior chain is not committed")
	}
	persisted, found, err := formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19AbandonedV1](store.root,
		store.attemptRelativePathV1(previous.Binding.AttemptID,
			formalGLMRegisteredPhase19AbandonedFileV1))
	if err != nil || !found || !reflect.DeepEqual(persisted, *previous) {
		return "", "", fmt.Errorf("formal-glm registered Phase19 attempt: prior chain differs")
	}
	return previous.AbandonedSHA256, previous.Binding.AttemptID, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) commitProposalV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
) (bool, error) {
	if err := store.validateProposalV1(proposal); err != nil {
		return false, err
	}
	if err := store.requirePreviousBindingV1(proposal.Binding); err != nil {
		return false, err
	}
	return store.commitV1(store.attemptRelativePathV1(
		proposal.Binding.AttemptID,
		formalGLMRegisteredPhase19ClaimProposalFileV1), proposal)
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) commitAcceptV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) (bool, error) {
	if err := store.validateAcceptV1(proposal, accept); err != nil {
		return false, err
	}
	if _, err := store.commitProposalV1(proposal); err != nil {
		return false, err
	}
	return store.commitV1(store.attemptRelativePathV1(
		proposal.Binding.AttemptID,
		formalGLMRegisteredPhase19ClaimAcceptFileV1), accept)
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) commitVoteV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	vote formalGLMRegisteredPhase19DecisionVoteV1,
) (bool, error) {
	index, err := store.validateVoteV1(proposal, accept, vote)
	if err != nil {
		return false, err
	}
	if _, err := store.commitAcceptV1(proposal, accept); err != nil {
		return false, err
	}
	file := []string{
		formalGLMRegisteredPhase19DecisionVote0FileV1,
		formalGLMRegisteredPhase19DecisionVote1FileV1,
	}[index]
	return store.commitV1(store.attemptRelativePathV1(
		proposal.Binding.AttemptID, file), vote)
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) Begin(
	previous *formalGLMRegisteredPhase19AbandonedV1,
) (formalGLMRegisteredPhase19ClaimProposalV1, bool, error) {
	var zero formalGLMRegisteredPhase19ClaimProposalV1
	if store == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: store unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || store.localIndex != 0 {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: local peer is not garbler")
	}
	previousSHA256, previousAttemptID, err := store.previousV1(previous)
	if err != nil {
		return zero, false, err
	}
	binding, err := store.bindingV1(previousSHA256, previousAttemptID)
	if err != nil {
		return zero, false, err
	}
	proposal := store.proposalV1(binding)
	message, err := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19ClaimProposalDomainV1, proposal)
	if err != nil {
		return zero, false, err
	}
	proposal.Signature = ed25519.Sign(store.signingKey, message)
	clear(message)
	replayed, err := store.commitProposalV1(proposal)
	if err != nil {
		return zero, false, err
	}
	return proposal, replayed, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) Accept(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
) (formalGLMRegisteredPhase19ClaimAcceptV1, bool, error) {
	var zero formalGLMRegisteredPhase19ClaimAcceptV1
	if store == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: store unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || store.localIndex != 1 {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: local peer is not evaluator")
	}
	if err := store.validateProposalV1(proposal); err != nil ||
		store.requirePreviousBindingV1(proposal.Binding) != nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: claim is not admissible")
	}
	accept, err := store.acceptV1(proposal)
	if err != nil {
		return zero, false, err
	}
	message, err := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19ClaimAcceptDomainV1, accept)
	if err != nil {
		return zero, false, err
	}
	accept.Signature = ed25519.Sign(store.signingKey, message)
	clear(message)
	replayed, err := store.commitAcceptV1(proposal, accept)
	if err != nil {
		return zero, false, err
	}
	return accept, replayed, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) VoteAbandon(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) (formalGLMRegisteredPhase19DecisionVoteV1, bool, error) {
	var zero formalGLMRegisteredPhase19DecisionVoteV1
	if store == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: store unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || store.localIndex < 0 || store.localIndex > 1 ||
		store.requirePreviousBindingV1(proposal.Binding) != nil ||
		store.validateAcceptV1(proposal, accept) != nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: claim pair is not admissible")
	}
	vote, err := store.voteV1(proposal, accept, store.localIndex)
	if err != nil {
		return zero, false, err
	}
	message, err := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19DecisionVoteDomainV1, vote)
	if err != nil {
		return zero, false, err
	}
	vote.Signature = ed25519.Sign(store.signingKey, message)
	clear(message)
	replayed, err := store.commitVoteV1(proposal, accept, vote)
	if err != nil {
		return zero, false, err
	}
	return vote, replayed, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) CommitAbandoned(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	votes []formalGLMRegisteredPhase19DecisionVoteV1,
) (formalGLMRegisteredPhase19AbandonedV1, bool, error) {
	var zero formalGLMRegisteredPhase19AbandonedV1
	if store == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: store unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || store.requirePreviousBindingV1(proposal.Binding) != nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase19 attempt: claim pair is not admissible")
	}
	abandoned, err := store.abandonedV1(proposal, accept, votes)
	if err != nil {
		return zero, false, err
	}
	for _, vote := range abandoned.DecisionVotes {
		if _, err := store.commitVoteV1(proposal, accept, vote); err != nil {
			return zero, false, err
		}
	}
	replayed, err := store.commitV1(store.attemptRelativePathV1(
		proposal.Binding.AttemptID,
		formalGLMRegisteredPhase19AbandonedFileV1), abandoned)
	if err != nil {
		return zero, false, err
	}
	return abandoned, replayed, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) LoadStatus(
	previous *formalGLMRegisteredPhase19AbandonedV1,
) (formalGLMRegisteredPhase19AttemptStatusV1, error) {
	var zero formalGLMRegisteredPhase19AttemptStatusV1
	if store == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 attempt: store unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 attempt: store is closed")
	}
	previousSHA256, previousAttemptID, err := store.previousV1(previous)
	if err != nil {
		return zero, err
	}
	binding, err := store.bindingV1(previousSHA256, previousAttemptID)
	if err != nil {
		return zero, err
	}
	status := formalGLMRegisteredPhase19AttemptStatusV1{binding: binding}
	directory := store.attemptRelativeDirV1(binding.AttemptID)
	if _, err := store.root.Lstat(directory); os.IsNotExist(err) {
		return status, nil
	} else if err != nil {
		return zero, err
	}
	if err := formalGLMRegisteredPhase18TicketStoreValidateDirV1(
		store.root, directory); err != nil {
		return zero, err
	}
	proposal, hasProposal, proposalErr := formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19ClaimProposalV1](store.root,
		store.attemptRelativePathV1(binding.AttemptID,
			formalGLMRegisteredPhase19ClaimProposalFileV1))
	accept, hasAccept, acceptErr := formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19ClaimAcceptV1](store.root,
		store.attemptRelativePathV1(binding.AttemptID,
			formalGLMRegisteredPhase19ClaimAcceptFileV1))
	vote0, hasVote0, vote0Err := formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19DecisionVoteV1](store.root,
		store.attemptRelativePathV1(binding.AttemptID,
			formalGLMRegisteredPhase19DecisionVote0FileV1))
	vote1, hasVote1, vote1Err := formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19DecisionVoteV1](store.root,
		store.attemptRelativePathV1(binding.AttemptID,
			formalGLMRegisteredPhase19DecisionVote1FileV1))
	abandoned, hasAbandoned, abandonedErr := formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19AbandonedV1](store.root,
		store.attemptRelativePathV1(binding.AttemptID,
			formalGLMRegisteredPhase19AbandonedFileV1))
	if proposalErr != nil || acceptErr != nil || vote0Err != nil ||
		vote1Err != nil || abandonedErr != nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 attempt: invalid durable status")
	}
	if !hasProposal {
		if hasAccept || hasVote0 || hasVote1 || hasAbandoned {
			return zero, fmt.Errorf("formal-glm registered Phase19 attempt: orphan durable status")
		}
		return status, nil
	}
	if store.validateProposalV1(proposal) != nil ||
		!reflect.DeepEqual(proposal.Binding, binding) {
		return zero, fmt.Errorf("formal-glm registered Phase19 attempt: invalid durable proposal")
	}
	status.proposal = &proposal
	if !hasAccept {
		if hasVote0 || hasVote1 || hasAbandoned {
			return zero, fmt.Errorf("formal-glm registered Phase19 attempt: orphan durable status")
		}
		return status, nil
	}
	if store.validateAcceptV1(proposal, accept) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 attempt: invalid durable accept")
	}
	status.accept = &accept
	for index, candidate := range []struct {
		value formalGLMRegisteredPhase19DecisionVoteV1
		found bool
	}{{vote0, hasVote0}, {vote1, hasVote1}} {
		if !candidate.found {
			continue
		}
		voteIndex, err := store.validateVoteV1(proposal, accept, candidate.value)
		if err != nil || voteIndex != index {
			return zero, fmt.Errorf("formal-glm registered Phase19 attempt: invalid durable vote")
		}
		value := candidate.value
		status.votes[index] = &value
	}
	if hasAbandoned {
		if status.votes[0] == nil || status.votes[1] == nil ||
			store.validateAbandonedV1(abandoned) != nil ||
			!reflect.DeepEqual(abandoned.DecisionVotes[0], *status.votes[0]) ||
			!reflect.DeepEqual(abandoned.DecisionVotes[1], *status.votes[1]) {
			return zero, fmt.Errorf("formal-glm registered Phase19 attempt: invalid durable abandonment")
		}
		status.abandoned = &abandoned
	}
	return status, nil
}

func (store *formalGLMRegisteredPhase19AttemptStoreV1) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	clear(store.signingKey)
	store.signingKey = nil
	for peer := range store.pins {
		clear(store.pins[peer])
		delete(store.pins, peer)
	}
}
