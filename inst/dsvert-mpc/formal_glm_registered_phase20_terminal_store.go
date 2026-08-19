package main

// Rock-local, role-ordered terminal two-phase commit for one accepted attempt.
// Private evidence is sealed before any DP-share receipt can be emitted. The
// evaluator alone chooses prepare or abandon; every later transition is an
// immutable owner-only Rock CAS.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

const (
	formalGLMRegisteredPhase20TerminalDomainV1 = "dsVert/formal-glm/registered-phase20/terminal/v1"
	formalGLMRegisteredPhase20TerminalDirV1    = "registered-phase20-terminal-v1"

	formalGLMRegisteredPhase20EncryptedDraftVersionV1  = "dsvert-formal-glm-registered-phase20-encrypted-draft-v1"
	formalGLMRegisteredPhase20EncryptedDraftPurposeV1  = "formal_glm_registered_phase20_local_evidence_draft_v1"
	formalGLMRegisteredPhase20PrepareReceiptVersionV1  = "dsvert-formal-glm-registered-phase20-prepare-receipt-v1"
	formalGLMRegisteredPhase20PrepareReceiptPurposeV1  = "formal_glm_registered_phase20_durable_prepare_receipt_v1"
	formalGLMRegisteredPhase20EvaluatorBundleVersionV1 = "dsvert-formal-glm-registered-phase20-evaluator-prepare-bundle-v1"
	formalGLMRegisteredPhase20EvaluatorBundlePurposeV1 = "formal_glm_registered_phase20_evaluator_prepare_bundle_v1"
	formalGLMRegisteredPhase20ChoiceVersionV1          = "dsvert-formal-glm-registered-phase20-terminal-choice-v1"
	formalGLMRegisteredPhase20ChoicePurposeV1          = "formal_glm_registered_phase20_prepare_or_abandon_v1"
	formalGLMRegisteredPhase20SelectVoteVersionV1      = "dsvert-formal-glm-registered-phase20-select-vote-v1"
	formalGLMRegisteredPhase20SelectVotePurposeV1      = "formal_glm_registered_phase20_select_vote_v1"
	formalGLMRegisteredPhase20SelectedVersionV1        = "dsvert-formal-glm-registered-phase20-selected-v1"
	formalGLMRegisteredPhase20SelectedPurposeV1        = "formal_glm_registered_phase20_k2_selected_v1"

	formalGLMRegisteredPhase20TerminalSelectedStateV1  = "selected"
	formalGLMRegisteredPhase20TerminalSelectDecisionV1 = "select"
	formalGLMRegisteredPhase20TerminalPrepareChoiceV1  = "prepare"
	formalGLMRegisteredPhase20TerminalAbandonChoiceV1  = "abandon"

	formalGLMRegisteredPhase20TerminalDraftFileV1    = "sealed-evidence.bin"
	formalGLMRegisteredPhase20TerminalChoiceFileV1   = "choice.json"
	formalGLMRegisteredPhase20TerminalVoteFileV1     = "select-vote.json"
	formalGLMRegisteredPhase20TerminalSelectedFileV1 = "selected.json"
	formalGLMRegisteredPhase20TerminalMaxRecordV1    = int64(8 << 20)
)

type formalGLMRegisteredPhase20EncryptedDraftV1 struct {
	Version              string `json:"version"`
	Purpose              string `json:"purpose"`
	State                string `json:"state"`
	AttemptID            string `json:"attempt_id"`
	ClaimAcceptSHA256    string `json:"claim_accept_sha256"`
	Role                 string `json:"role"`
	CommonEvidenceSHA256 string `json:"common_evidence_sha256"`
	Nonce                string `json:"nonce"`
	Ciphertext           string `json:"ciphertext"`
}

type formalGLMRegisteredPhase20DraftPayloadV1 struct {
	Evidence formalGLMRegisteredPhase20PreparedEvidenceV1 `json:"prepared_evidence"`
}

type formalGLMRegisteredPhase20PrepareReceiptV1 struct {
	Version                  string `json:"version"`
	Purpose                  string `json:"purpose"`
	State                    string `json:"state"`
	AttemptID                string `json:"attempt_id"`
	ClaimAcceptSHA256        string `json:"claim_accept_sha256"`
	Role                     string `json:"role"`
	CommonEvidenceSHA256     string `json:"common_evidence_sha256"`
	DPShareReceiptPairSHA256 string `json:"dp_share_receipt_pair_sha256"`
	DraftRecordSHA256        string `json:"draft_record_sha256"`
	Signature                []byte `json:"signature"`
}

type formalGLMRegisteredPhase20EvaluatorPrepareBundleV1 struct {
	Version          string                                         `json:"version"`
	Purpose          string                                         `json:"purpose"`
	Pair             formalGLMRegisteredPhase20DPShareReceiptPairV1 `json:"dp_share_receipt_pair"`
	EvaluatorPrepare formalGLMRegisteredPhase20PrepareReceiptV1     `json:"evaluator_prepare"`
}

type formalGLMRegisteredPhase20PreparedRecordV1 struct {
	Pair    formalGLMRegisteredPhase20DPShareReceiptPairV1 `json:"dp_share_receipt_pair"`
	Receipt formalGLMRegisteredPhase20PrepareReceiptV1     `json:"prepare_receipt"`
}

type formalGLMRegisteredPhase20TerminalChoiceV1 struct {
	Version           string                                      `json:"version"`
	Purpose           string                                      `json:"purpose"`
	Decision          string                                      `json:"decision"`
	AttemptID         string                                      `json:"attempt_id"`
	ClaimAcceptSHA256 string                                      `json:"claim_accept_sha256"`
	Role              string                                      `json:"role"`
	Prepared          *formalGLMRegisteredPhase20PreparedRecordV1 `json:"prepared,omitempty"`
	Signature         []byte                                      `json:"signature"`
}

type formalGLMRegisteredPhase20PrepareSetV1 struct {
	Garbler   formalGLMRegisteredPhase20PrepareReceiptV1 `json:"garbler"`
	Evaluator formalGLMRegisteredPhase20PrepareReceiptV1 `json:"evaluator"`
}

type formalGLMRegisteredPhase20SelectVoteV1 struct {
	Version                  string `json:"version"`
	Purpose                  string `json:"purpose"`
	Decision                 string `json:"decision"`
	AttemptID                string `json:"attempt_id"`
	ClaimAcceptSHA256        string `json:"claim_accept_sha256"`
	Role                     string `json:"role"`
	CommonEvidenceSHA256     string `json:"common_evidence_sha256"`
	DPShareReceiptPairSHA256 string `json:"dp_share_receipt_pair_sha256"`
	PrepareReceiptSetSHA256  string `json:"prepare_receipt_set_sha256"`
	Signature                []byte `json:"signature"`
}

type formalGLMRegisteredPhase20SelectVoteRecordV1 struct {
	PrepareSet formalGLMRegisteredPhase20PrepareSetV1 `json:"prepare_set"`
	Vote       formalGLMRegisteredPhase20SelectVoteV1 `json:"vote"`
}

type formalGLMRegisteredPhase20SelectedV1 struct {
	Version                 string                                         `json:"version"`
	Purpose                 string                                         `json:"purpose"`
	State                   string                                         `json:"state"`
	AttemptID               string                                         `json:"attempt_id"`
	ClaimAcceptSHA256       string                                         `json:"claim_accept_sha256"`
	CommonEvidenceSHA256    string                                         `json:"common_evidence_sha256"`
	DPShareReceiptPair      formalGLMRegisteredPhase20DPShareReceiptPairV1 `json:"dp_share_receipt_pair"`
	GarblerPrepare          formalGLMRegisteredPhase20PrepareReceiptV1     `json:"garbler_prepare"`
	EvaluatorPrepare        formalGLMRegisteredPhase20PrepareReceiptV1     `json:"evaluator_prepare"`
	PrepareReceiptSetSHA256 string                                         `json:"prepare_receipt_set_sha256"`
	GarblerVote             formalGLMRegisteredPhase20SelectVoteV1         `json:"garbler_vote"`
	EvaluatorVote           formalGLMRegisteredPhase20SelectVoteV1         `json:"evaluator_vote"`
	SelectedSHA256          string                                         `json:"selected_sha256"`
	OpeningsPerformed       int                                            `json:"openings_performed"`
	ProductionReady         bool                                           `json:"production_ready"`
}

// Private restart status. It intentionally has no JSON-visible fields.
type formalGLMRegisteredPhase20TerminalStatusV1 struct {
	draftSealed    bool
	abandonChosen  bool
	prepareReceipt *formalGLMRegisteredPhase20PrepareReceiptV1
	selectVote     *formalGLMRegisteredPhase20SelectVoteV1
	selected       *formalGLMRegisteredPhase20SelectedV1
}

type formalGLMRegisteredPhase20TerminalDraftLoadedV1 struct {
	evidence     formalGLMRegisteredPhase20PreparedEvidenceV1
	receipt      formalGLMRegisteredPhase20DPShareReceiptV1
	recordSHA256 string
}

func (draft *formalGLMRegisteredPhase20TerminalDraftLoadedV1) clear() {
	if draft != nil {
		draft.evidence.CanonicalDPShare = ""
		for index := range draft.evidence.FinalReceipts {
			clear(draft.evidence.FinalReceipts[index].Signature)
		}
		clear(draft.receipt.Signature)
		*draft = formalGLMRegisteredPhase20TerminalDraftLoadedV1{}
	}
}

func formalGLMRegisteredPhase20TerminalCloneDraftLoadedV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
) (formalGLMRegisteredPhase20TerminalDraftLoadedV1, error) {
	var zero formalGLMRegisteredPhase20TerminalDraftLoadedV1
	evidence, err := formalGLMRegisteredPhase20TerminalCloneV1(draft.evidence)
	if err != nil {
		return zero, err
	}
	loaded := formalGLMRegisteredPhase20TerminalDraftLoadedV1{
		evidence: evidence, recordSHA256: draft.recordSHA256,
	}
	receipt, err := formalGLMRegisteredPhase20TerminalCloneV1(draft.receipt)
	if err != nil {
		loaded.clear()
		return zero, err
	}
	loaded.receipt = receipt
	return loaded, nil
}

type formalGLMRegisteredPhase20TerminalLoadedV1 struct {
	status   formalGLMRegisteredPhase20TerminalStatusV1
	draft    formalGLMRegisteredPhase20TerminalDraftLoadedV1
	choice   *formalGLMRegisteredPhase20TerminalChoiceV1
	prepared *formalGLMRegisteredPhase20PreparedRecordV1
	vote     *formalGLMRegisteredPhase20SelectVoteRecordV1
}

func (loaded *formalGLMRegisteredPhase20TerminalLoadedV1) clear() {
	if loaded != nil {
		loaded.draft.clear()
		*loaded = formalGLMRegisteredPhase20TerminalLoadedV1{}
	}
}

type formalGLMRegisteredPhase20TerminalDecisionStateV1 struct {
	votes     [2]bool
	abandoned bool
}

// AttemptStore and JobKeyProvider ownership transfers on successful creation.
// Runtime is borrowed and must outlive the owner.
type formalGLMRegisteredPhase20TerminalOwnerV1 struct {
	mu sync.Mutex

	attempts *formalGLMRegisteredPhase19AttemptStoreV1
	jobKeys  *formalGLMRegisteredPhase20JobKeyProviderV1
	runtime  *formalGLMRegisteredPhase19EphemeralRuntimeV1

	record   formalGLMRegisteredPhase19BindingRecordV1
	contract formalGLMSourceContractV1
	pins     map[string]ed25519.PublicKey
	proposal formalGLMRegisteredPhase19ClaimProposalV1
	accept   formalGLMRegisteredPhase19ClaimAcceptV1

	claimAcceptSHA256    string
	peer                 string
	role                 string
	localIndex           int
	relativeDir          string
	draftRelativePath    string
	choiceRelativePath   string
	voteRelativePath     string
	selectedRelativePath string
	draftCache           *formalGLMRegisteredPhase20TerminalDraftLoadedV1
	closed               bool
}

func formalGLMRegisteredPhase20TerminalCloneV1[T any](value T) (T, error) {
	var zero T
	encoded, err := json.Marshal(value)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var cloned T
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return zero, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase20TerminalDecodeV1[T any](encoded []byte) (T, error) {
	var zero T
	var value T
	if formalGLMPhase21RockStrictDecode(encoded, &value) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid durable record")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: non-canonical durable record")
	}
	clear(canonical)
	return value, nil
}

func formalGLMRegisteredPhase20TerminalClonePinsV1(
	pins map[string]ed25519.PublicKey,
) map[string]ed25519.PublicKey {
	cloned := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		cloned[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return cloned
}

func formalGLMRegisteredPhase20TerminalClearPinsV1(
	pins map[string]ed25519.PublicKey,
) {
	for peer := range pins {
		clear(pins[peer])
		delete(pins, peer)
	}
}

func formalGLMRegisteredPhase20TerminalRoleIndexV1(role string) int {
	if role == "garbler" {
		return 0
	}
	if role == "evaluator" {
		return 1
	}
	return -1
}

func formalGLMRegisteredPhase20TerminalRecordSHA256V1(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func formalGLMRegisteredPhase20TerminalValidateDirV1(
	owner *formalGLMRegisteredPhase20TerminalOwnerV1,
) error {
	if owner == nil || owner.attempts == nil || owner.attempts.root == nil ||
		formalGLMPhase21ValidateRootPrivateDir(
			owner.attempts.root, owner.relativeDir, false) != nil {
		return fmt.Errorf("formal-glm registered Phase20 terminal: unsafe directory")
	}
	info, err := owner.attempts.root.Lstat(owner.relativeDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return fmt.Errorf("formal-glm registered Phase20 terminal: unsafe directory")
	}
	return nil
}

func formalGLMRegisteredPhase20TerminalEnsureDirV1(
	owner *formalGLMRegisteredPhase20TerminalOwnerV1,
) error {
	if owner == nil || owner.attempts == nil || owner.attempts.root == nil {
		return fmt.Errorf("formal-glm registered Phase20 terminal: unavailable owner")
	}
	created := false
	if err := owner.attempts.root.Mkdir(owner.relativeDir, 0o700); err == nil {
		created = true
	} else if !os.IsExist(err) {
		return err
	}
	if err := formalGLMRegisteredPhase20TerminalValidateDirV1(owner); err != nil {
		return err
	}
	if created {
		return formalGLMPhase21RootSyncDir(
			owner.attempts.root, owner.relativeDir)
	}
	return nil
}

func formalGLMRegisteredPhase20TerminalReadV1(
	owner *formalGLMRegisteredPhase20TerminalOwnerV1,
	relative string,
) ([]byte, bool, error) {
	owner.attempts.mu.Lock()
	defer owner.attempts.mu.Unlock()
	if owner.attempts.root == nil ||
		formalGLMRegisteredPhase20TerminalValidateDirV1(owner) != nil {
		return nil, false, fmt.Errorf("formal-glm registered Phase20 terminal: unavailable store")
	}
	info, err := owner.attempts.root.Lstat(relative)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, false, fmt.Errorf("formal-glm registered Phase20 terminal: unsafe record mode")
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		owner.attempts.root, relative,
		formalGLMRegisteredPhase20TerminalMaxRecordV1)
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

func formalGLMRegisteredPhase20TerminalCommitV1(
	owner *formalGLMRegisteredPhase20TerminalOwnerV1,
	relative string,
	value any,
) (bool, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > int(formalGLMRegisteredPhase20TerminalMaxRecordV1) {
		clear(encoded)
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: invalid record encoding")
	}
	defer clear(encoded)
	owner.attempts.mu.Lock()
	defer owner.attempts.mu.Unlock()
	if owner.attempts.root == nil ||
		formalGLMRegisteredPhase20TerminalValidateDirV1(owner) != nil {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: unavailable store")
	}
	created, err := formalGLMPhase21RootCreateRecord(
		owner.attempts.root, relative, encoded)
	if err != nil {
		return false, err
	}
	persisted, err := formalGLMPhase21RootReadRecord(
		owner.attempts.root, relative,
		formalGLMRegisteredPhase20TerminalMaxRecordV1)
	if err != nil {
		return false, err
	}
	defer clear(persisted)
	info, infoErr := owner.attempts.root.Lstat(relative)
	if infoErr != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: unsafe committed record")
	}
	if !bytes.Equal(persisted, encoded) {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: durable CAS conflict")
	}
	return !created, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) decisionStateV1() (
	formalGLMRegisteredPhase20TerminalDecisionStateV1, error,
) {
	var zero formalGLMRegisteredPhase20TerminalDecisionStateV1
	if owner == nil || owner.attempts == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: unavailable attempt owner")
	}
	var previous *formalGLMRegisteredPhase19AbandonedV1
	binding := owner.proposal.Binding
	if binding.PreviousAttemptID != formalGLMRegisteredPhase19AttemptZeroPreviousV1 {
		owner.attempts.mu.Lock()
		root := owner.attempts.root
		var value formalGLMRegisteredPhase19AbandonedV1
		found, err := false, fmt.Errorf("closed")
		if root != nil {
			value, found, err = formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19AbandonedV1](
				root, owner.attempts.attemptRelativePathV1(
					binding.PreviousAttemptID, formalGLMRegisteredPhase19AbandonedFileV1))
		}
		owner.attempts.mu.Unlock()
		if err != nil || !found {
			return zero, fmt.Errorf("formal-glm registered Phase20 terminal: prior attempt unavailable")
		}
		previous = &value
	}
	status, err := owner.attempts.LoadStatus(previous)
	if err != nil || status.proposal == nil || status.accept == nil ||
		status.binding != binding || !reflect.DeepEqual(*status.proposal, owner.proposal) ||
		!reflect.DeepEqual(*status.accept, owner.accept) {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: accepted claim is not durable")
	}
	state := formalGLMRegisteredPhase20TerminalDecisionStateV1{
		votes:     [2]bool{status.votes[0] != nil, status.votes[1] != nil},
		abandoned: status.abandoned != nil,
	}
	if state.votes[0] && !state.votes[1] {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: garbler initiated abandonment")
	}
	return state, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) requireNoAbandonV1() error {
	state, err := owner.decisionStateV1()
	if err != nil {
		return err
	}
	if state.votes[0] || state.votes[1] || state.abandoned {
		return fmt.Errorf("formal-glm registered Phase20 terminal: attempt is abandoning")
	}
	return nil
}

func newFormalGLMRegisteredPhase20TerminalOwnerV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) (*formalGLMRegisteredPhase20TerminalOwnerV1, error) {
	if attempts == nil || jobKeys == nil || runtime == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: missing dependency")
	}
	attempts.mu.Lock()
	plan := attempts.contract.Core.RegisteredExecutionPlan
	if attempts.root == nil || attempts.localIndex < 0 || attempts.localIndex > 1 ||
		len(plan.NoiseAuthorities) != 2 || len(plan.DesignatedComputePeers) != 2 ||
		attempts.validateAcceptV1(proposal, accept) != nil ||
		attempts.requirePreviousBindingV1(proposal.Binding) != nil {
		attempts.mu.Unlock()
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: invalid accepted attempt")
	}
	record, recordErr := formalGLMRegisteredPhase20TerminalCloneV1(attempts.record)
	contract, contractErr := formalGLMRegisteredPhase20TerminalCloneV1(attempts.contract)
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(attempts.pins)
	attemptRecordSHA256 := attempts.recordSHA256
	localIndex := attempts.localIndex
	attemptRoot := attempts.root
	peer := plan.DesignatedComputePeers[localIndex]
	role := plan.NoiseAuthorities[localIndex].Role
	validSigner := len(attempts.signingKey) == ed25519.PrivateKeySize &&
		bytes.Equal(attempts.signingKey.Public().(ed25519.PublicKey), pins[peer])
	attempts.mu.Unlock()
	if recordErr != nil || contractErr != nil || !validSigner ||
		formalGLMRegisteredPhase20TerminalRoleIndexV1(role) != localIndex ||
		plan.NoiseAuthorities[localIndex].PeerName != peer {
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: invalid attempt owner")
	}

	wantContext := formalGLMRegisteredPhase20JobKeyContextV1{
		artifactID:                    record.Binding.ArtifactID,
		sourceContractCoreSHA256:      record.Binding.SourceContractCoreSHA256,
		sourceContractSHA256:          record.Binding.SourceContractSHA256,
		pinsetSHA256:                  record.Binding.PinsetSHA256,
		semanticRootSHA256:            record.Binding.SemanticRootSHA256,
		bindingRecordSHA256:           attemptRecordSHA256,
		registeredExecutionPlanSHA256: record.Binding.RegisteredExecutionPlanSHA256,
		localPeer:                     peer,
		localIndex:                    localIndex,
	}
	jobKeys.mu.Lock()
	jobRoot := jobKeys.root
	contextOK := jobKeys.validateLocked() == nil &&
		jobKeys.context == wantContext
	jobKeys.mu.Unlock()
	if !contextOK || !formalGLMRegisteredPhase19ScheduleTailSameRootV1(
		attemptRoot, jobRoot) {
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: storage owners differ")
	}

	proposalClone, proposalErr := formalGLMRegisteredPhase20TerminalCloneV1(proposal)
	acceptClone, acceptErr := formalGLMRegisteredPhase20TerminalCloneV1(accept)
	claimAcceptSHA256, claimErr :=
		formalGLMRegisteredPhase19ClaimAcceptSHA256V1(acceptClone)
	if proposalErr != nil || acceptErr != nil || claimErr != nil {
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: invalid claim pair")
	}
	ephemeralRecordSHA256, ephemeralRecordErr := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19EphemeralDomainV1+"/validated-binding-record",
		record)
	runtime.mu.Lock()
	runtimeErr := runtime.validateLocked()
	if runtimeErr == nil && (ephemeralRecordErr != nil ||
		runtime.semanticRootSHA256 != record.Binding.SemanticRootSHA256 ||
		runtime.bindingRecordSHA256 != ephemeralRecordSHA256 ||
		runtime.receiptSetSHA256 != record.Binding.ReceiptSetSHA256 ||
		runtime.globalMaterializationSHA256 !=
			record.Binding.GlobalMaterializationRootSHA256 ||
		runtime.registeredExecutionPlanSHA256 !=
			record.Binding.RegisteredExecutionPlanSHA256) {
		runtimeErr = fmt.Errorf("formal-glm registered Phase20 terminal: runtime binding mismatch")
	}
	runtime.mu.Unlock()
	if runtimeErr != nil {
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		return nil, runtimeErr
	}

	owner := &formalGLMRegisteredPhase20TerminalOwnerV1{
		attempts: attempts, jobKeys: jobKeys, runtime: runtime,
		record: record, contract: contract, pins: pins,
		proposal: proposalClone, accept: acceptClone,
		claimAcceptSHA256: claimAcceptSHA256,
		peer:              peer, role: role, localIndex: localIndex,
	}
	owner.relativeDir = filepath.Join(
		attempts.attemptRelativeDirV1(proposal.Binding.AttemptID),
		formalGLMRegisteredPhase20TerminalDirV1)
	owner.draftRelativePath = filepath.Join(
		owner.relativeDir, formalGLMRegisteredPhase20TerminalDraftFileV1)
	owner.choiceRelativePath = filepath.Join(
		owner.relativeDir, formalGLMRegisteredPhase20TerminalChoiceFileV1)
	owner.voteRelativePath = filepath.Join(
		owner.relativeDir, formalGLMRegisteredPhase20TerminalVoteFileV1)
	owner.selectedRelativePath = filepath.Join(
		owner.relativeDir, formalGLMRegisteredPhase20TerminalSelectedFileV1)

	attempts.mu.Lock()
	dirErr := formalGLMRegisteredPhase20TerminalEnsureDirV1(owner)
	attempts.mu.Unlock()
	key, keyErr := jobKeys.DeriveAttemptKey(proposal.Binding)
	clear(key[:])
	if dirErr != nil || keyErr != nil {
		formalGLMRegisteredPhase20TerminalClearPinsV1(owner.pins)
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: owner validation failed")
	}
	owner.mu.Lock()
	loaded, loadErr := owner.loadLockedV1()
	loaded.clear()
	if loadErr != nil {
		owner.clearDraftCacheV1()
	}
	owner.mu.Unlock()
	if loadErr != nil {
		formalGLMRegisteredPhase20TerminalClearPinsV1(owner.pins)
		return nil, loadErr
	}
	return owner, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) signV1(
	message []byte,
) ([]byte, error) {
	owner.attempts.mu.Lock()
	defer owner.attempts.mu.Unlock()
	if owner.attempts.root == nil ||
		len(owner.attempts.signingKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(owner.attempts.signingKey.Public().(ed25519.PublicKey),
			owner.pins[owner.peer]) {
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: signer unavailable")
	}
	return ed25519.Sign(owner.attempts.signingKey, message), nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) localDPShareReceiptV1(
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
) (formalGLMRegisteredPhase20DPShareReceiptV1, error) {
	var zero formalGLMRegisteredPhase20DPShareReceiptV1
	context, err := formalGLMRegisteredPhase20DeriveDPShareReceiptContextV1(
		owner.runtime, owner.record, owner.contract, owner.pins,
		owner.proposal, owner.accept, evidence)
	if err != nil || context.peer != owner.peer || context.role != owner.role {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid local evidence")
	}
	receipt := formalGLMRegisteredPhase20DPShareReceiptFromContextV1(context)
	message, err := formalGLMRegisteredPhase20DPShareReceiptMessageV1(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature, err = owner.signV1(message)
	clear(message)
	if err != nil {
		return zero, err
	}
	return receipt, nil
}

func formalGLMRegisteredPhase20TerminalDraftAADV1(
	draft formalGLMRegisteredPhase20EncryptedDraftV1,
) ([]byte, error) {
	if draft.Version != formalGLMRegisteredPhase20EncryptedDraftVersionV1 ||
		draft.Purpose != formalGLMRegisteredPhase20EncryptedDraftPurposeV1 ||
		draft.State != formalGLMRegisteredPhase20PreparedStateV1 ||
		!formalGLMIsSHA256(draft.AttemptID) ||
		!formalGLMIsSHA256(draft.ClaimAcceptSHA256) ||
		formalGLMRegisteredPhase20TerminalRoleIndexV1(draft.Role) < 0 ||
		!formalGLMIsSHA256(draft.CommonEvidenceSHA256) {
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: invalid encrypted draft")
	}
	nonce, err := base64.StdEncoding.DecodeString(draft.Nonce)
	if err != nil || base64.StdEncoding.EncodeToString(nonce) != draft.Nonce {
		clear(nonce)
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: invalid draft nonce")
	}
	clear(nonce)
	draft.Ciphertext = ""
	encoded, err := json.Marshal(draft)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMRegisteredPhase20TerminalDomainV1+
		"/encrypted-draft/aad|"), encoded...), nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) sealDraftV1(
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
) (formalGLMRegisteredPhase20EncryptedDraftV1,
	formalGLMRegisteredPhase20TerminalDraftLoadedV1, error,
) {
	var draftZero formalGLMRegisteredPhase20EncryptedDraftV1
	var loadedZero formalGLMRegisteredPhase20TerminalDraftLoadedV1
	evidence, err := formalGLMRegisteredPhase20TerminalCloneV1(evidence)
	if err != nil {
		return draftZero, loadedZero, err
	}
	loaded := formalGLMRegisteredPhase20TerminalDraftLoadedV1{
		evidence: evidence,
	}
	succeeded := false
	defer func() {
		if !succeeded {
			loaded.clear()
		}
	}()
	receipt, err := owner.localDPShareReceiptV1(evidence)
	if err != nil {
		return draftZero, loadedZero, err
	}
	loaded.receipt = receipt
	draft := formalGLMRegisteredPhase20EncryptedDraftV1{
		Version:              formalGLMRegisteredPhase20EncryptedDraftVersionV1,
		Purpose:              formalGLMRegisteredPhase20EncryptedDraftPurposeV1,
		State:                formalGLMRegisteredPhase20PreparedStateV1,
		AttemptID:            owner.proposal.Binding.AttemptID,
		ClaimAcceptSHA256:    owner.claimAcceptSHA256,
		Role:                 owner.role,
		CommonEvidenceSHA256: receipt.CommonEvidenceSHA256,
	}
	key, err := owner.jobKeys.DeriveAttemptKey(owner.proposal.Binding)
	if err != nil {
		return draftZero, loadedZero, err
	}
	defer clear(key[:])
	aead, err := formalGLMPhase20HandoffAEAD(key)
	if err != nil {
		return draftZero, loadedZero, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		clear(nonce)
		return draftZero, loadedZero, err
	}
	draft.Nonce = base64.StdEncoding.EncodeToString(nonce)
	aad, err := formalGLMRegisteredPhase20TerminalDraftAADV1(draft)
	if err != nil {
		clear(nonce)
		return draftZero, loadedZero, err
	}
	defer clear(aad)
	payload := formalGLMRegisteredPhase20DraftPayloadV1{
		Evidence: evidence,
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		clear(nonce)
		return draftZero, loadedZero, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	clear(nonce)
	clear(plaintext)
	draft.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	clear(ciphertext)
	succeeded = true
	return draft, loaded, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) rememberDraftV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
) error {
	if !formalGLMIsSHA256(draft.recordSHA256) {
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid draft cache binding")
	}
	if owner.draftCache != nil {
		if owner.draftCache.recordSHA256 != draft.recordSHA256 {
			return fmt.Errorf("formal-glm registered Phase20 terminal: durable draft changed")
		}
		return nil
	}
	cached, err := formalGLMRegisteredPhase20TerminalCloneDraftLoadedV1(draft)
	if err != nil {
		return err
	}
	owner.draftCache = &cached
	return nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) clearDraftCacheV1() {
	if owner.draftCache == nil {
		return
	}
	owner.draftCache.clear()
	owner.draftCache = nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) loadDraftV1(
	encoded []byte,
) (formalGLMRegisteredPhase20TerminalDraftLoadedV1, error) {
	var zero formalGLMRegisteredPhase20TerminalDraftLoadedV1
	recordSHA256 := formalGLMRegisteredPhase20TerminalRecordSHA256V1(encoded)
	if owner.draftCache != nil {
		if owner.draftCache.recordSHA256 != recordSHA256 {
			return zero, fmt.Errorf("formal-glm registered Phase20 terminal: durable draft changed")
		}
		return formalGLMRegisteredPhase20TerminalCloneDraftLoadedV1(
			*owner.draftCache)
	}
	draft, err := formalGLMRegisteredPhase20TerminalDecodeV1[formalGLMRegisteredPhase20EncryptedDraftV1](encoded)
	if err != nil || draft.AttemptID != owner.proposal.Binding.AttemptID ||
		draft.ClaimAcceptSHA256 != owner.claimAcceptSHA256 ||
		draft.Role != owner.role {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid local draft binding")
	}
	aad, err := formalGLMRegisteredPhase20TerminalDraftAADV1(draft)
	if err != nil {
		return zero, err
	}
	defer clear(aad)
	nonce, nonceErr := base64.StdEncoding.DecodeString(draft.Nonce)
	ciphertext, ciphertextErr := base64.StdEncoding.DecodeString(draft.Ciphertext)
	if nonceErr != nil || ciphertextErr != nil ||
		base64.StdEncoding.EncodeToString(ciphertext) != draft.Ciphertext {
		clear(nonce)
		clear(ciphertext)
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid encrypted draft encoding")
	}
	key, err := owner.jobKeys.DeriveAttemptKey(owner.proposal.Binding)
	if err != nil {
		clear(nonce)
		clear(ciphertext)
		return zero, err
	}
	aead, err := formalGLMPhase20HandoffAEAD(key)
	clear(key[:])
	if err != nil || len(nonce) != aead.NonceSize() {
		clear(nonce)
		clear(ciphertext)
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid draft nonce")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	clear(nonce)
	clear(ciphertext)
	if err != nil {
		clear(plaintext)
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: draft authentication failed")
	}
	defer clear(plaintext)
	payload, err := formalGLMRegisteredPhase20TerminalDecodeV1[formalGLMRegisteredPhase20DraftPayloadV1](plaintext)
	if err != nil || payload.Evidence.Peer != owner.peer ||
		!reflect.DeepEqual(payload.Evidence.Attempt, owner.proposal.Binding) {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid draft payload")
	}
	receipt, err := owner.localDPShareReceiptV1(payload.Evidence)
	if err != nil || receipt.CommonEvidenceSHA256 != draft.CommonEvidenceSHA256 {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: draft evidence mismatch")
	}
	loaded := formalGLMRegisteredPhase20TerminalDraftLoadedV1{
		evidence: payload.Evidence, receipt: receipt,
		recordSHA256: recordSHA256,
	}
	if err := owner.rememberDraftV1(loaded); err != nil {
		loaded.clear()
		return zero, err
	}
	return loaded, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) SealLocalEvidenceV1(
	evidence formalGLMRegisteredPhase20PreparedEvidenceV1,
) (bool, error) {
	if owner == nil {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.attempts == nil || owner.jobKeys == nil {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: owner is closed")
	}
	existing, found, err := formalGLMRegisteredPhase20TerminalReadV1(
		owner, owner.draftRelativePath)
	if err != nil {
		return false, err
	}
	if owner.draftCache != nil && !found {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: durable draft disappeared")
	}
	if found {
		defer clear(existing)
		loaded, err := owner.loadDraftV1(existing)
		defer loaded.clear()
		if err != nil || !reflect.DeepEqual(loaded.evidence, evidence) {
			return false, fmt.Errorf("formal-glm registered Phase20 terminal: durable draft conflict")
		}
		return true, nil
	}
	if _, chosen, err := owner.readChoiceV1(); err != nil || chosen {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: terminal choice already exists")
	}
	if err := owner.requireNoAbandonV1(); err != nil {
		return false, err
	}
	draft, loaded, err := owner.sealDraftV1(evidence)
	if err != nil {
		return false, err
	}
	defer loaded.clear()
	if err := owner.requireNoAbandonV1(); err != nil {
		return false, err
	}
	replayed, err := formalGLMRegisteredPhase20TerminalCommitV1(
		owner, owner.draftRelativePath, draft)
	if err != nil {
		return false, err
	}
	if replayed {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: unexpected draft race")
	}
	persisted, found, err := formalGLMRegisteredPhase20TerminalReadV1(
		owner, owner.draftRelativePath)
	if err != nil || !found {
		clear(persisted)
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: draft readback failed")
	}
	want, err := json.Marshal(draft)
	if err != nil || !bytes.Equal(persisted, want) {
		clear(want)
		clear(persisted)
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: draft readback changed")
	}
	clear(want)
	loaded.recordSHA256 = formalGLMRegisteredPhase20TerminalRecordSHA256V1(persisted)
	clear(persisted)
	if err := owner.rememberDraftV1(loaded); err != nil {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: draft readback changed")
	}
	return false, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) PublishDPShareReceiptV1() (
	formalGLMRegisteredPhase20DPShareReceiptV1, error,
) {
	var zero formalGLMRegisteredPhase20DPShareReceiptV1
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.role != "garbler" {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: only garbler publishes first")
	}
	if err := owner.requireNoAbandonV1(); err != nil {
		return zero, err
	}
	if choice, found, err := owner.readChoiceV1(); err != nil ||
		(found && choice.Decision == formalGLMRegisteredPhase20TerminalAbandonChoiceV1) {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: attempt chose abandonment")
	}
	encoded, found, err := formalGLMRegisteredPhase20TerminalReadV1(
		owner, owner.draftRelativePath)
	if err != nil || !found {
		clear(encoded)
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: garbler evidence is not sealed")
	}
	defer clear(encoded)
	draft, err := owner.loadDraftV1(encoded)
	defer draft.clear()
	if err != nil {
		return zero, err
	}
	receipt, err := formalGLMRegisteredPhase20TerminalCloneV1(draft.receipt)
	if err != nil {
		return zero, err
	}
	return receipt, nil
}

func formalGLMRegisteredPhase20PrepareReceiptMessageV1(
	receipt formalGLMRegisteredPhase20PrepareReceiptV1,
) ([]byte, error) {
	if receipt.Version != formalGLMRegisteredPhase20PrepareReceiptVersionV1 ||
		receipt.Purpose != formalGLMRegisteredPhase20PrepareReceiptPurposeV1 ||
		receipt.State != formalGLMRegisteredPhase20PreparedStateV1 ||
		!formalGLMIsSHA256(receipt.AttemptID) ||
		!formalGLMIsSHA256(receipt.ClaimAcceptSHA256) ||
		formalGLMRegisteredPhase20TerminalRoleIndexV1(receipt.Role) < 0 ||
		!formalGLMIsSHA256(receipt.CommonEvidenceSHA256) ||
		!formalGLMIsSHA256(receipt.DPShareReceiptPairSHA256) ||
		!formalGLMIsSHA256(receipt.DraftRecordSHA256) {
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: invalid prepare receipt")
	}
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMRegisteredPhase20TerminalDomainV1+
		"/prepare-receipt|"), encoded...), nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) validatePrepareReceiptV1(
	receipt formalGLMRegisteredPhase20PrepareReceiptV1,
) error {
	index := formalGLMRegisteredPhase20TerminalRoleIndexV1(receipt.Role)
	plan := owner.contract.Core.RegisteredExecutionPlan
	if index < 0 || len(plan.NoiseAuthorities) != 2 ||
		receipt.AttemptID != owner.proposal.Binding.AttemptID ||
		receipt.ClaimAcceptSHA256 != owner.claimAcceptSHA256 {
		return fmt.Errorf("formal-glm registered Phase20 terminal: prepare receipt binding mismatch")
	}
	peer := plan.NoiseAuthorities[index].PeerName
	message, err := formalGLMRegisteredPhase20PrepareReceiptMessageV1(receipt)
	if err != nil || len(receipt.Signature) != ed25519.SignatureSize ||
		len(owner.pins[peer]) != ed25519.PublicKeySize ||
		!ed25519.Verify(owner.pins[peer], message, receipt.Signature) {
		clear(message)
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid prepare receipt signature")
	}
	clear(message)
	return nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) validateLocalPairV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
	pair formalGLMRegisteredPhase20DPShareReceiptPairV1,
) error {
	if owner.draftCache == nil ||
		draft.recordSHA256 != owner.draftCache.recordSHA256 ||
		!reflect.DeepEqual(draft.receipt, owner.draftCache.receipt) {
		return fmt.Errorf("formal-glm registered Phase20 terminal: untrusted local draft")
	}
	local := pair.Garbler
	if owner.role == "evaluator" {
		local = pair.Evaluator
	} else if owner.role != "garbler" {
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid local role")
	}
	wantPairSHA256, err :=
		formalGLMRegisteredPhase20DPShareReceiptPairSHA256V1(pair)
	if err != nil || pair.PairSHA256 != wantPairSHA256 ||
		!reflect.DeepEqual(local, draft.receipt) ||
		pair.Garbler.ClaimAcceptSHA256 != owner.claimAcceptSHA256 ||
		pair.Evaluator.ClaimAcceptSHA256 != owner.claimAcceptSHA256 ||
		pair.Garbler.DPBridgeSessionContextSHA256 !=
			pair.Evaluator.DPBridgeSessionContextSHA256 ||
		pair.Garbler.CommonEvidenceSHA256 != pair.Evaluator.CommonEvidenceSHA256 ||
		pair.Garbler.CommonEvidenceSHA256 != draft.receipt.CommonEvidenceSHA256 ||
		formalGLMRegisteredPhase20ValidateDPShareReceiptSignatureV1(
			owner.contract, owner.pins, pair.Garbler) != nil ||
		formalGLMRegisteredPhase20ValidateDPShareReceiptSignatureV1(
			owner.contract, owner.pins, pair.Evaluator) != nil {
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid local receipt pair")
	}
	return nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) pairLocalReceiptsV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
	remote formalGLMRegisteredPhase20DPShareReceiptV1,
) (formalGLMRegisteredPhase20DPShareReceiptPairV1, error) {
	var zero formalGLMRegisteredPhase20DPShareReceiptPairV1
	local, err := formalGLMRegisteredPhase20TerminalCloneV1(draft.receipt)
	if err != nil {
		return zero, err
	}
	remote, err = formalGLMRegisteredPhase20TerminalCloneV1(remote)
	if err != nil {
		clear(local.Signature)
		return zero, err
	}
	pair := formalGLMRegisteredPhase20DPShareReceiptPairV1{
		Version: formalGLMRegisteredPhase20DPShareReceiptPairVersionV1,
		Purpose: formalGLMRegisteredPhase20DPShareReceiptPairPurposeV1,
	}
	if owner.role == "garbler" {
		pair.Garbler, pair.Evaluator = local, remote
	} else if owner.role == "evaluator" {
		pair.Garbler, pair.Evaluator = remote, local
	} else {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid local role")
	}
	pair.PairSHA256, err =
		formalGLMRegisteredPhase20DPShareReceiptPairSHA256V1(pair)
	if err != nil || owner.validateLocalPairV1(draft, pair) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: inadmissible receipt pair")
	}
	return pair, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) prepareReceiptV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
	pair formalGLMRegisteredPhase20DPShareReceiptPairV1,
) (formalGLMRegisteredPhase20PrepareReceiptV1, error) {
	var zero formalGLMRegisteredPhase20PrepareReceiptV1
	if owner.validateLocalPairV1(draft, pair) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid local receipt pair")
	}
	receipt := formalGLMRegisteredPhase20PrepareReceiptV1{
		Version:                  formalGLMRegisteredPhase20PrepareReceiptVersionV1,
		Purpose:                  formalGLMRegisteredPhase20PrepareReceiptPurposeV1,
		State:                    formalGLMRegisteredPhase20PreparedStateV1,
		AttemptID:                owner.proposal.Binding.AttemptID,
		ClaimAcceptSHA256:        owner.claimAcceptSHA256,
		Role:                     owner.role,
		CommonEvidenceSHA256:     draft.receipt.CommonEvidenceSHA256,
		DPShareReceiptPairSHA256: pair.PairSHA256,
		DraftRecordSHA256:        draft.recordSHA256,
	}
	message, err := formalGLMRegisteredPhase20PrepareReceiptMessageV1(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature, err = owner.signV1(message)
	clear(message)
	if err != nil {
		return zero, err
	}
	return receipt, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) preparedRecordV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
	pair formalGLMRegisteredPhase20DPShareReceiptPairV1,
) (formalGLMRegisteredPhase20PreparedRecordV1, error) {
	var zero formalGLMRegisteredPhase20PreparedRecordV1
	receipt, err := owner.prepareReceiptV1(draft, pair)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase20PreparedRecordV1{
		Pair: pair, Receipt: receipt,
	}, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) validatePreparedRecordV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
	record formalGLMRegisteredPhase20PreparedRecordV1,
) error {
	want, err := owner.preparedRecordV1(draft, record.Pair)
	if err != nil || !reflect.DeepEqual(record, want) ||
		owner.validatePrepareReceiptV1(record.Receipt) != nil {
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid prepared record")
	}
	return nil
}

func formalGLMRegisteredPhase20TerminalEvaluatorBundleV1(
	record formalGLMRegisteredPhase20PreparedRecordV1,
) (formalGLMRegisteredPhase20EvaluatorPrepareBundleV1, error) {
	var zero formalGLMRegisteredPhase20EvaluatorPrepareBundleV1
	if record.Receipt.Role != "evaluator" {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: not evaluator prepared")
	}
	return formalGLMRegisteredPhase20EvaluatorPrepareBundleV1{
		Version: formalGLMRegisteredPhase20EvaluatorBundleVersionV1,
		Purpose: formalGLMRegisteredPhase20EvaluatorBundlePurposeV1,
		Pair:    record.Pair, EvaluatorPrepare: record.Receipt,
	}, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) readDraftLockedV1() (
	formalGLMRegisteredPhase20TerminalDraftLoadedV1, error,
) {
	var zero formalGLMRegisteredPhase20TerminalDraftLoadedV1
	encoded, found, err := formalGLMRegisteredPhase20TerminalReadV1(
		owner, owner.draftRelativePath)
	if err != nil || !found {
		clear(encoded)
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: local evidence is not sealed")
	}
	defer clear(encoded)
	return owner.loadDraftV1(encoded)
}

func formalGLMRegisteredPhase20TerminalChoiceMessageV1(
	choice formalGLMRegisteredPhase20TerminalChoiceV1,
) ([]byte, error) {
	validDecision := (choice.Decision == formalGLMRegisteredPhase20TerminalPrepareChoiceV1 && choice.Prepared != nil) ||
		(choice.Decision == formalGLMRegisteredPhase20TerminalAbandonChoiceV1 && choice.Prepared == nil)
	if choice.Version != formalGLMRegisteredPhase20ChoiceVersionV1 ||
		choice.Purpose != formalGLMRegisteredPhase20ChoicePurposeV1 ||
		!formalGLMIsSHA256(choice.AttemptID) ||
		!formalGLMIsSHA256(choice.ClaimAcceptSHA256) ||
		formalGLMRegisteredPhase20TerminalRoleIndexV1(choice.Role) < 0 ||
		!validDecision {
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: invalid choice")
	}
	choice.Signature = nil
	encoded, err := json.Marshal(choice)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMRegisteredPhase20TerminalDomainV1+
		"/choice|"), encoded...), nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) validateChoiceV1(
	choice formalGLMRegisteredPhase20TerminalChoiceV1,
) error {
	if choice.AttemptID != owner.proposal.Binding.AttemptID ||
		choice.ClaimAcceptSHA256 != owner.claimAcceptSHA256 ||
		choice.Role != owner.role {
		return fmt.Errorf("formal-glm registered Phase20 terminal: choice binding mismatch")
	}
	message, err := formalGLMRegisteredPhase20TerminalChoiceMessageV1(choice)
	if err != nil || len(choice.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(owner.pins[owner.peer], message, choice.Signature) {
		clear(message)
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid choice signature")
	}
	clear(message)
	return nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) choiceV1(
	decision string, prepared *formalGLMRegisteredPhase20PreparedRecordV1,
) (formalGLMRegisteredPhase20TerminalChoiceV1, error) {
	var zero formalGLMRegisteredPhase20TerminalChoiceV1
	choice := formalGLMRegisteredPhase20TerminalChoiceV1{
		Version:  formalGLMRegisteredPhase20ChoiceVersionV1,
		Purpose:  formalGLMRegisteredPhase20ChoicePurposeV1,
		Decision: decision, AttemptID: owner.proposal.Binding.AttemptID,
		ClaimAcceptSHA256: owner.claimAcceptSHA256, Role: owner.role,
		Prepared: prepared,
	}
	message, err := formalGLMRegisteredPhase20TerminalChoiceMessageV1(choice)
	if err != nil {
		return zero, err
	}
	choice.Signature, err = owner.signV1(message)
	clear(message)
	if err != nil {
		return zero, err
	}
	return choice, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) readChoiceV1() (
	formalGLMRegisteredPhase20TerminalChoiceV1, bool, error,
) {
	var zero formalGLMRegisteredPhase20TerminalChoiceV1
	encoded, found, err := formalGLMRegisteredPhase20TerminalReadV1(
		owner, owner.choiceRelativePath)
	if err != nil || !found {
		clear(encoded)
		return zero, found, err
	}
	defer clear(encoded)
	choice, err := formalGLMRegisteredPhase20TerminalDecodeV1[formalGLMRegisteredPhase20TerminalChoiceV1](encoded)
	if err != nil || owner.validateChoiceV1(choice) != nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: invalid durable choice")
	}
	return choice, true, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) chooseV1(
	choice formalGLMRegisteredPhase20TerminalChoiceV1,
) (bool, error) {
	if err := owner.validateChoiceV1(choice); err != nil {
		return false, err
	}
	replayed, err := formalGLMRegisteredPhase20TerminalCommitV1(
		owner, owner.choiceRelativePath, choice)
	if err != nil {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: prepare/abandon choice conflict")
	}
	return replayed, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) commitPreparedV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
	pair formalGLMRegisteredPhase20DPShareReceiptPairV1,
) (formalGLMRegisteredPhase20PreparedRecordV1, bool, error) {
	var zero formalGLMRegisteredPhase20PreparedRecordV1
	if err := owner.requireNoAbandonV1(); err != nil {
		return zero, false, err
	}
	want, err := owner.preparedRecordV1(draft, pair)
	if err != nil {
		return zero, false, err
	}
	if err := owner.requireNoAbandonV1(); err != nil {
		return zero, false, err
	}
	choice, err := owner.choiceV1(
		formalGLMRegisteredPhase20TerminalPrepareChoiceV1, &want)
	if err != nil {
		return zero, false, err
	}
	replayed, err := owner.chooseV1(choice)
	if err != nil {
		return zero, false, err
	}
	return want, replayed, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) PrepareFromGarblerReceiptV1(
	garblerReceipt formalGLMRegisteredPhase20DPShareReceiptV1,
) (formalGLMRegisteredPhase20EvaluatorPrepareBundleV1, bool, error) {
	var zero formalGLMRegisteredPhase20EvaluatorPrepareBundleV1
	if owner == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.role != "evaluator" {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: only evaluator accepts garbler receipt")
	}
	draft, err := owner.readDraftLockedV1()
	defer draft.clear()
	if err != nil {
		return zero, false, err
	}
	pair, err := owner.pairLocalReceiptsV1(draft, garblerReceipt)
	if err != nil {
		return zero, false, err
	}
	record, replayed, err := owner.commitPreparedV1(draft, pair)
	if err != nil {
		return zero, false, err
	}
	bundle, err := formalGLMRegisteredPhase20TerminalEvaluatorBundleV1(record)
	return bundle, replayed, err
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) PrepareFromEvaluatorBundleV1(
	bundle formalGLMRegisteredPhase20EvaluatorPrepareBundleV1,
) (formalGLMRegisteredPhase20PrepareReceiptV1, bool, error) {
	var zero formalGLMRegisteredPhase20PrepareReceiptV1
	if owner == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.role != "garbler" ||
		bundle.Version != formalGLMRegisteredPhase20EvaluatorBundleVersionV1 ||
		bundle.Purpose != formalGLMRegisteredPhase20EvaluatorBundlePurposeV1 {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: invalid evaluator bundle")
	}
	draft, err := owner.readDraftLockedV1()
	defer draft.clear()
	if err != nil {
		return zero, false, err
	}
	if err := owner.validateEvaluatorBundleV1(draft, bundle); err != nil {
		return zero, false, err
	}
	record, replayed, err := owner.commitPreparedV1(draft, bundle.Pair)
	if err != nil {
		return zero, false, err
	}
	return record.Receipt, replayed, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) validateEvaluatorBundleV1(
	draft formalGLMRegisteredPhase20TerminalDraftLoadedV1,
	bundle formalGLMRegisteredPhase20EvaluatorPrepareBundleV1,
) error {
	if bundle.Version != formalGLMRegisteredPhase20EvaluatorBundleVersionV1 ||
		bundle.Purpose != formalGLMRegisteredPhase20EvaluatorBundlePurposeV1 ||
		owner.validateLocalPairV1(draft, bundle.Pair) != nil ||
		!reflect.DeepEqual(bundle.Pair.Garbler, draft.receipt) ||
		bundle.EvaluatorPrepare.Role != "evaluator" ||
		bundle.EvaluatorPrepare.CommonEvidenceSHA256 !=
			bundle.Pair.Garbler.CommonEvidenceSHA256 ||
		bundle.EvaluatorPrepare.DPShareReceiptPairSHA256 != bundle.Pair.PairSHA256 ||
		owner.validatePrepareReceiptV1(bundle.EvaluatorPrepare) != nil {
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid evaluator bundle")
	}
	return nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) prepareSetV1(
	local, remote formalGLMRegisteredPhase20PrepareReceiptV1,
	pair formalGLMRegisteredPhase20DPShareReceiptPairV1,
) (formalGLMRegisteredPhase20PrepareSetV1, string, error) {
	var zero formalGLMRegisteredPhase20PrepareSetV1
	if owner.validatePrepareReceiptV1(local) != nil ||
		owner.validatePrepareReceiptV1(remote) != nil ||
		local.Role != owner.role || remote.Role == owner.role ||
		local.AttemptID != remote.AttemptID ||
		local.ClaimAcceptSHA256 != remote.ClaimAcceptSHA256 ||
		local.CommonEvidenceSHA256 != remote.CommonEvidenceSHA256 ||
		local.CommonEvidenceSHA256 != pair.Garbler.CommonEvidenceSHA256 ||
		local.DPShareReceiptPairSHA256 != pair.PairSHA256 ||
		remote.DPShareReceiptPairSHA256 != pair.PairSHA256 ||
		local.DraftRecordSHA256 == remote.DraftRecordSHA256 {
		return zero, "", fmt.Errorf("formal-glm registered Phase20 terminal: prepare receipts do not form one K2 set")
	}
	set := formalGLMRegisteredPhase20PrepareSetV1{
		Garbler: local, Evaluator: remote,
	}
	if local.Role == "evaluator" {
		set.Garbler, set.Evaluator = remote, local
	}
	hash, err := formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20TerminalDomainV1+"/prepare-receipt-set", set)
	if err != nil {
		return zero, "", err
	}
	return set, hash, nil
}

func formalGLMRegisteredPhase20SelectVoteMessageV1(
	vote formalGLMRegisteredPhase20SelectVoteV1,
) ([]byte, error) {
	if vote.Version != formalGLMRegisteredPhase20SelectVoteVersionV1 ||
		vote.Purpose != formalGLMRegisteredPhase20SelectVotePurposeV1 ||
		vote.Decision != formalGLMRegisteredPhase20TerminalSelectDecisionV1 ||
		!formalGLMIsSHA256(vote.AttemptID) ||
		!formalGLMIsSHA256(vote.ClaimAcceptSHA256) ||
		formalGLMRegisteredPhase20TerminalRoleIndexV1(vote.Role) < 0 ||
		!formalGLMIsSHA256(vote.CommonEvidenceSHA256) ||
		!formalGLMIsSHA256(vote.DPShareReceiptPairSHA256) ||
		!formalGLMIsSHA256(vote.PrepareReceiptSetSHA256) {
		return nil, fmt.Errorf("formal-glm registered Phase20 terminal: invalid select vote")
	}
	vote.Signature = nil
	encoded, err := json.Marshal(vote)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMRegisteredPhase20TerminalDomainV1+
		"/select-vote|"), encoded...), nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) validateSelectVoteV1(
	vote formalGLMRegisteredPhase20SelectVoteV1,
) error {
	index := formalGLMRegisteredPhase20TerminalRoleIndexV1(vote.Role)
	plan := owner.contract.Core.RegisteredExecutionPlan
	if index < 0 || len(plan.NoiseAuthorities) != 2 ||
		vote.AttemptID != owner.proposal.Binding.AttemptID ||
		vote.ClaimAcceptSHA256 != owner.claimAcceptSHA256 {
		return fmt.Errorf("formal-glm registered Phase20 terminal: select vote binding mismatch")
	}
	peer := plan.NoiseAuthorities[index].PeerName
	message, err := formalGLMRegisteredPhase20SelectVoteMessageV1(vote)
	if err != nil || len(vote.Signature) != ed25519.SignatureSize ||
		len(owner.pins[peer]) != ed25519.PublicKeySize ||
		!ed25519.Verify(owner.pins[peer], message, vote.Signature) {
		clear(message)
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid select vote signature")
	}
	clear(message)
	return nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) selectVoteV1(
	prepared formalGLMRegisteredPhase20PreparedRecordV1,
	setHash string,
) (formalGLMRegisteredPhase20SelectVoteV1, error) {
	var zero formalGLMRegisteredPhase20SelectVoteV1
	vote := formalGLMRegisteredPhase20SelectVoteV1{
		Version:                  formalGLMRegisteredPhase20SelectVoteVersionV1,
		Purpose:                  formalGLMRegisteredPhase20SelectVotePurposeV1,
		Decision:                 formalGLMRegisteredPhase20TerminalSelectDecisionV1,
		AttemptID:                owner.proposal.Binding.AttemptID,
		ClaimAcceptSHA256:        owner.claimAcceptSHA256,
		Role:                     owner.role,
		CommonEvidenceSHA256:     prepared.Receipt.CommonEvidenceSHA256,
		DPShareReceiptPairSHA256: prepared.Pair.PairSHA256,
		PrepareReceiptSetSHA256:  setHash,
	}
	message, err := formalGLMRegisteredPhase20SelectVoteMessageV1(vote)
	if err != nil {
		return zero, err
	}
	vote.Signature, err = owner.signV1(message)
	clear(message)
	if err != nil {
		return zero, err
	}
	return vote, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) validateVoteRecordV1(
	prepared formalGLMRegisteredPhase20PreparedRecordV1,
	record formalGLMRegisteredPhase20SelectVoteRecordV1,
) error {
	if record.Vote.Role != owner.role ||
		owner.validateSelectVoteV1(record.Vote) != nil {
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid durable select vote")
	}
	local, remote := record.PrepareSet.Garbler, record.PrepareSet.Evaluator
	if owner.role == "evaluator" {
		local, remote = remote, local
	}
	wantSet, wantHash, err := owner.prepareSetV1(
		local, remote, prepared.Pair)
	if err != nil || !reflect.DeepEqual(record.PrepareSet, wantSet) ||
		record.Vote.PrepareReceiptSetSHA256 != wantHash ||
		record.Vote.CommonEvidenceSHA256 != prepared.Receipt.CommonEvidenceSHA256 ||
		record.Vote.DPShareReceiptPairSHA256 != prepared.Pair.PairSHA256 ||
		!reflect.DeepEqual(local, prepared.Receipt) {
		return fmt.Errorf("formal-glm registered Phase20 terminal: durable select vote fork")
	}
	return nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) VoteSelectV1(
	remote formalGLMRegisteredPhase20PrepareReceiptV1,
) (formalGLMRegisteredPhase20SelectVoteV1, bool, error) {
	var zero formalGLMRegisteredPhase20SelectVoteV1
	if owner == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner is closed")
	}
	loaded, err := owner.loadLockedV1()
	defer loaded.clear()
	if err != nil || loaded.prepared == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: local prepare is not durable")
	}
	set, setHash, err := owner.prepareSetV1(
		loaded.prepared.Receipt, remote, loaded.prepared.Pair)
	if err != nil {
		return zero, false, err
	}
	if loaded.vote != nil {
		if !reflect.DeepEqual(loaded.vote.PrepareSet, set) ||
			loaded.vote.Vote.PrepareReceiptSetSHA256 != setHash {
			return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: durable select vote conflict")
		}
		return loaded.vote.Vote, true, nil
	}
	vote, err := owner.selectVoteV1(*loaded.prepared, setHash)
	if err != nil {
		return zero, false, err
	}
	record := formalGLMRegisteredPhase20SelectVoteRecordV1{
		PrepareSet: set, Vote: vote,
	}
	replayed, err := formalGLMRegisteredPhase20TerminalCommitV1(
		owner, owner.voteRelativePath, record)
	if err != nil {
		return zero, false, err
	}
	if replayed {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: unexpected select-vote race")
	}
	return vote, false, nil
}

func formalGLMRegisteredPhase20SelectedSHA256V1(
	selected formalGLMRegisteredPhase20SelectedV1,
) (string, error) {
	if selected.Version != formalGLMRegisteredPhase20SelectedVersionV1 ||
		selected.Purpose != formalGLMRegisteredPhase20SelectedPurposeV1 ||
		selected.State != formalGLMRegisteredPhase20TerminalSelectedStateV1 ||
		!formalGLMIsSHA256(selected.AttemptID) ||
		!formalGLMIsSHA256(selected.ClaimAcceptSHA256) ||
		!formalGLMIsSHA256(selected.CommonEvidenceSHA256) ||
		!formalGLMIsSHA256(selected.DPShareReceiptPair.PairSHA256) ||
		!formalGLMIsSHA256(selected.PrepareReceiptSetSHA256) ||
		(selected.SelectedSHA256 != "" &&
			!formalGLMIsSHA256(selected.SelectedSHA256)) ||
		selected.OpeningsPerformed != 0 || selected.ProductionReady {
		return "", fmt.Errorf("formal-glm registered Phase20 terminal: invalid Selected record")
	}
	selected.SelectedSHA256 = ""
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase20TerminalDomainV1+"/selected", selected)
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) selectedV1(
	prepared formalGLMRegisteredPhase20PreparedRecordV1,
	record formalGLMRegisteredPhase20SelectVoteRecordV1,
	remote formalGLMRegisteredPhase20SelectVoteV1,
) (formalGLMRegisteredPhase20SelectedV1, error) {
	var zero formalGLMRegisteredPhase20SelectedV1
	if owner.validateVoteRecordV1(prepared, record) != nil ||
		owner.validateSelectVoteV1(remote) != nil ||
		remote.Role == owner.role ||
		remote.PrepareReceiptSetSHA256 != record.Vote.PrepareReceiptSetSHA256 ||
		remote.CommonEvidenceSHA256 != record.Vote.CommonEvidenceSHA256 ||
		remote.DPShareReceiptPairSHA256 != record.Vote.DPShareReceiptPairSHA256 {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: select votes do not form one K2 decision")
	}
	garblerVote, evaluatorVote := record.Vote, remote
	if garblerVote.Role == "evaluator" {
		garblerVote, evaluatorVote = evaluatorVote, garblerVote
	}
	if garblerVote.Role != "garbler" || evaluatorVote.Role != "evaluator" {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid select vote roles")
	}
	selected := formalGLMRegisteredPhase20SelectedV1{
		Version:                 formalGLMRegisteredPhase20SelectedVersionV1,
		Purpose:                 formalGLMRegisteredPhase20SelectedPurposeV1,
		State:                   formalGLMRegisteredPhase20TerminalSelectedStateV1,
		AttemptID:               owner.proposal.Binding.AttemptID,
		ClaimAcceptSHA256:       owner.claimAcceptSHA256,
		CommonEvidenceSHA256:    prepared.Receipt.CommonEvidenceSHA256,
		DPShareReceiptPair:      prepared.Pair,
		GarblerPrepare:          record.PrepareSet.Garbler,
		EvaluatorPrepare:        record.PrepareSet.Evaluator,
		PrepareReceiptSetSHA256: record.Vote.PrepareReceiptSetSHA256,
		GarblerVote:             garblerVote, EvaluatorVote: evaluatorVote,
		OpeningsPerformed: 0, ProductionReady: false,
	}
	var err error
	selected.SelectedSHA256, err =
		formalGLMRegisteredPhase20SelectedSHA256V1(selected)
	if err != nil {
		return zero, err
	}
	return selected, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) validateSelectedV1(
	prepared formalGLMRegisteredPhase20PreparedRecordV1,
	record formalGLMRegisteredPhase20SelectVoteRecordV1,
	selected formalGLMRegisteredPhase20SelectedV1,
) error {
	remote := selected.EvaluatorVote
	if owner.role == "evaluator" {
		remote = selected.GarblerVote
	}
	want, err := owner.selectedV1(prepared, record, remote)
	if err != nil || !reflect.DeepEqual(selected, want) {
		return fmt.Errorf("formal-glm registered Phase20 terminal: invalid durable Selected record")
	}
	return nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) CommitSelectedV1(
	remote formalGLMRegisteredPhase20SelectVoteV1,
) (formalGLMRegisteredPhase20SelectedV1, bool, error) {
	var zero formalGLMRegisteredPhase20SelectedV1
	if owner == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner is closed")
	}
	loaded, err := owner.loadLockedV1()
	defer loaded.clear()
	if err != nil || loaded.prepared == nil || loaded.vote == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: local select vote is not durable")
	}
	selected, err := owner.selectedV1(*loaded.prepared, *loaded.vote, remote)
	if err != nil {
		return zero, false, err
	}
	if loaded.status.selected != nil {
		if !reflect.DeepEqual(*loaded.status.selected, selected) {
			return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: durable Selected conflict")
		}
		return *loaded.status.selected, true, nil
	}
	replayed, err := formalGLMRegisteredPhase20TerminalCommitV1(
		owner, owner.selectedRelativePath, selected)
	if err != nil {
		return zero, false, err
	}
	if replayed {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: unexpected Selected race")
	}
	return selected, false, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) loadLockedV1() (
	formalGLMRegisteredPhase20TerminalLoadedV1, error,
) {
	var zero formalGLMRegisteredPhase20TerminalLoadedV1
	if owner == nil || owner.closed || owner.attempts == nil || owner.jobKeys == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	decision, err := owner.decisionStateV1()
	if err != nil {
		return zero, err
	}
	draftJSON, hasDraft, draftErr := formalGLMRegisteredPhase20TerminalReadV1(
		owner, owner.draftRelativePath)
	choice, hasChoice, choiceErr := owner.readChoiceV1()
	voteJSON, hasVote, voteErr := formalGLMRegisteredPhase20TerminalReadV1(
		owner, owner.voteRelativePath)
	selectedJSON, hasSelected, selectedErr := formalGLMRegisteredPhase20TerminalReadV1(
		owner, owner.selectedRelativePath)
	defer clear(draftJSON)
	defer clear(voteJSON)
	defer clear(selectedJSON)
	if draftErr != nil || choiceErr != nil || voteErr != nil || selectedErr != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid durable status")
	}
	if owner.draftCache != nil && !hasDraft {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: durable draft disappeared")
	}
	loaded := formalGLMRegisteredPhase20TerminalLoadedV1{}
	if hasDraft {
		loaded.draft, err = owner.loadDraftV1(draftJSON)
		if err != nil {
			loaded.clear()
			return zero, err
		}
		loaded.status.draftSealed = true
	}
	if !hasChoice {
		if hasVote || hasSelected || decision.votes[0] || decision.votes[1] || decision.abandoned {
			loaded.clear()
			return zero, fmt.Errorf("formal-glm registered Phase20 terminal: choice prefix missing")
		}
		return loaded, nil
	}
	loaded.choice = &choice
	if choice.Decision == formalGLMRegisteredPhase20TerminalAbandonChoiceV1 {
		if hasVote || hasSelected {
			loaded.clear()
			return zero, fmt.Errorf("formal-glm registered Phase20 terminal: abandon has select descendants")
		}
		loaded.status.abandonChosen = true
		return loaded, nil
	}
	if !hasDraft || decision.votes[0] || decision.votes[1] || decision.abandoned {
		loaded.clear()
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: prepare/abandon equivocation")
	}
	prepared := *choice.Prepared
	if owner.validatePreparedRecordV1(loaded.draft, prepared) != nil {
		loaded.clear()
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid durable prepare")
	}
	loaded.prepared = &prepared
	prepareReceipt := prepared.Receipt
	loaded.status.prepareReceipt = &prepareReceipt
	if !hasVote {
		if hasSelected {
			loaded.clear()
			return zero, fmt.Errorf("formal-glm registered Phase20 terminal: select-vote prefix missing")
		}
		return loaded, nil
	}
	vote, err := formalGLMRegisteredPhase20TerminalDecodeV1[formalGLMRegisteredPhase20SelectVoteRecordV1](voteJSON)
	if err != nil || owner.validateVoteRecordV1(prepared, vote) != nil {
		loaded.clear()
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid durable select vote")
	}
	loaded.vote = &vote
	selectVote := vote.Vote
	loaded.status.selectVote = &selectVote
	if !hasSelected {
		return loaded, nil
	}
	selected, err := formalGLMRegisteredPhase20TerminalDecodeV1[formalGLMRegisteredPhase20SelectedV1](selectedJSON)
	if err != nil || owner.validateSelectedV1(prepared, vote, selected) != nil {
		loaded.clear()
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: invalid durable Selected")
	}
	loaded.status.selected = &selected
	return loaded, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) LoadStatusV1() (
	formalGLMRegisteredPhase20TerminalStatusV1, error,
) {
	var zero formalGLMRegisteredPhase20TerminalStatusV1
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	loaded, err := owner.loadLockedV1()
	if err != nil {
		return zero, err
	}
	status := loaded.status
	loaded.clear()
	return status, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) LoadSelectedSourceV1() (
	formalGLMRegisteredPhase20SelectedV1,
	formalGLMRegisteredPhase20TrustSourceV1,
	error,
) {
	var selectedZero formalGLMRegisteredPhase20SelectedV1
	var sourceZero formalGLMRegisteredPhase20TrustSourceV1
	if owner == nil {
		return selectedZero, sourceZero,
			fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	loaded, err := owner.loadLockedV1()
	defer loaded.clear()
	if err != nil || loaded.status.selected == nil || loaded.prepared == nil {
		return selectedZero, sourceZero,
			fmt.Errorf("formal-glm registered Phase20 terminal: attempt is not Selected")
	}
	trusted, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
		owner.runtime, owner.record, owner.contract, owner.proposal.Binding,
		loaded.draft.evidence, owner.pins)
	if err != nil {
		return selectedZero, sourceZero, err
	}
	return *loaded.status.selected, trusted, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) chooseAbandonV1() (
	bool, error,
) {
	choice, found, err := owner.readChoiceV1()
	if err != nil {
		return false, err
	}
	if found && choice.Decision != formalGLMRegisteredPhase20TerminalAbandonChoiceV1 {
		return false, fmt.Errorf("formal-glm registered Phase20 terminal: prepare blocks abandonment")
	}
	if !found {
		state, err := owner.decisionStateV1()
		if err != nil || state.votes[0] || state.votes[1] || state.abandoned {
			return false, fmt.Errorf("formal-glm registered Phase20 terminal: abandonment choice missing")
		}
	}
	want, err := owner.choiceV1(
		formalGLMRegisteredPhase20TerminalAbandonChoiceV1, nil)
	if err != nil {
		return false, err
	}
	return owner.chooseV1(want)
}

// Only the evaluator can initiate abandonment in the role-ordered handshake.
func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) VoteAbandonBeforePrepareV1() (
	formalGLMRegisteredPhase19DecisionVoteV1, bool, error,
) {
	var zero formalGLMRegisteredPhase19DecisionVoteV1
	if owner == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.role != "evaluator" {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: only evaluator initiates abandonment")
	}
	choiceReplayed, err := owner.chooseAbandonV1()
	if err != nil {
		return zero, false, err
	}
	vote, voteReplayed, err := owner.attempts.VoteAbandon(
		owner.proposal, owner.accept)
	return vote, choiceReplayed && voteReplayed, err
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) AcceptEvaluatorAbandonV1(
	evaluatorVote formalGLMRegisteredPhase19DecisionVoteV1,
) (formalGLMRegisteredPhase19DecisionVoteV1, bool, error) {
	var zero formalGLMRegisteredPhase19DecisionVoteV1
	if owner == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.role != "garbler" {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: only garbler co-signs abandonment")
	}
	store := owner.attempts
	store.mu.Lock()
	if store.root == nil || store.validateAcceptV1(owner.proposal, owner.accept) != nil ||
		store.requirePreviousBindingV1(owner.proposal.Binding) != nil {
		store.mu.Unlock()
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: invalid accepted attempt")
	}
	index, err := store.validateVoteV1(
		owner.proposal, owner.accept, evaluatorVote)
	store.mu.Unlock()
	if err != nil || index != 1 {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: invalid evaluator abandonment vote")
	}
	choiceReplayed, err := owner.chooseAbandonV1()
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil || store.validateAcceptV1(owner.proposal, owner.accept) != nil ||
		store.requirePreviousBindingV1(owner.proposal.Binding) != nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: accepted attempt changed")
	}
	remoteReplayed, err := store.commitVoteV1(
		owner.proposal, owner.accept, evaluatorVote)
	if err != nil {
		return zero, false, err
	}
	garblerVote, err := store.voteV1(owner.proposal, owner.accept, 0)
	if err != nil {
		return zero, false, err
	}
	message, err := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
		formalGLMRegisteredPhase19DecisionVoteDomainV1, garblerVote)
	if err != nil {
		return zero, false, err
	}
	garblerVote.Signature = ed25519.Sign(store.signingKey, message)
	clear(message)
	localReplayed, err := store.commitVoteV1(
		owner.proposal, owner.accept, garblerVote)
	if err != nil {
		return zero, false, err
	}
	return garblerVote, choiceReplayed && remoteReplayed && localReplayed, nil
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) CommitAbandonedBeforePrepareV1(
	votes []formalGLMRegisteredPhase19DecisionVoteV1,
) (formalGLMRegisteredPhase19AbandonedV1, bool, error) {
	var zero formalGLMRegisteredPhase19AbandonedV1
	if owner == nil {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: owner is closed")
	}
	choice, found, err := owner.readChoiceV1()
	if err != nil || !found ||
		choice.Decision != formalGLMRegisteredPhase20TerminalAbandonChoiceV1 {
		return zero, false, fmt.Errorf("formal-glm registered Phase20 terminal: abandonment choice is not durable")
	}
	return owner.attempts.CommitAbandoned(owner.proposal, owner.accept, votes)
}

func (owner *formalGLMRegisteredPhase20TerminalOwnerV1) Close() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	if owner.closed {
		owner.mu.Unlock()
		return nil
	}
	owner.closed = true
	attempts, jobKeys := owner.attempts, owner.jobKeys
	owner.attempts, owner.jobKeys, owner.runtime = nil, nil, nil
	formalGLMRegisteredPhase20TerminalClearPinsV1(owner.pins)
	owner.pins = nil
	owner.record = formalGLMRegisteredPhase19BindingRecordV1{}
	owner.contract = formalGLMSourceContractV1{}
	owner.proposal = formalGLMRegisteredPhase19ClaimProposalV1{}
	owner.accept = formalGLMRegisteredPhase19ClaimAcceptV1{}
	owner.clearDraftCacheV1()
	owner.claimAcceptSHA256 = ""
	owner.mu.Unlock()
	var closeErr error
	if jobKeys != nil {
		closeErr = jobKeys.Close()
	}
	if attempts != nil {
		attempts.Close()
	}
	return closeErr
}
