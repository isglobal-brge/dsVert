package main

import (
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
)

// formalGLMRegisteredPhase20CommitSelectedHandoffV1 is the only compatibility
// boundary from a registered Selected terminal into the existing Phase21
// handoff store. The legacy plan/context/result are rehydrated locally from
// sealed evidence and are written only to the owner-only encrypted handoff;
// neither source nor share is returned to a caller.
func formalGLMRegisteredPhase20CommitSelectedHandoffV1(
	owner *formalGLMRegisteredPhase20TerminalOwnerV1,
) (formalGLMPhase20HandoffCommit, error) {
	var zero formalGLMPhase20HandoffCommit
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 handoff: owner unavailable")
	}

	owner.mu.Lock()
	if owner.closed || owner.attempts == nil || owner.jobKeys == nil ||
		owner.runtime == nil {
		owner.mu.Unlock()
		return zero, fmt.Errorf("formal-glm registered Phase20 handoff: owner is closed")
	}
	loaded, err := owner.loadLockedV1()
	if err != nil || loaded.status.selected == nil || loaded.prepared == nil ||
		loaded.status.selected.OpeningsPerformed != 0 ||
		loaded.status.selected.ProductionReady {
		loaded.clear()
		owner.mu.Unlock()
		return zero, fmt.Errorf("formal-glm registered Phase20 handoff: attempt is not Selected")
	}
	trusted, err := formalGLMRegisteredPhase20RehydrateEvidenceV1(
		owner.runtime, owner.record, owner.contract, owner.proposal.Binding,
		loaded.draft.evidence, owner.pins)
	loaded.clear()
	if err != nil {
		owner.mu.Unlock()
		return zero, err
	}
	source := trusted.source
	trusted.source = formalGLMPhase20HandoffSource{}

	attempts, jobKeys := owner.attempts, owner.jobKeys
	attempts.mu.Lock()
	attemptRoot := attempts.root
	var attemptInfo os.FileInfo
	if attemptRoot != nil {
		attemptInfo, err = attemptRoot.Stat(".")
	}
	rockRoot := ""
	if attemptRoot != nil {
		rockRoot = attemptRoot.Name()
	}
	attempts.mu.Unlock()
	if err != nil || attemptRoot == nil || rockRoot == "" {
		source.clear()
		owner.mu.Unlock()
		return zero, fmt.Errorf("formal-glm registered Phase20 handoff: attempt root unavailable")
	}

	var storageRoot [32]byte
	jobKeys.mu.Lock()
	jobRoot := jobKeys.root
	contextOK := jobKeys.validateLocked() == nil &&
		jobKeys.validateAttemptLocked(owner.proposal.Binding) == nil &&
		formalGLMRegisteredPhase19ScheduleTailSameRootV1(attemptRoot, jobRoot)
	if contextOK {
		storageRoot, err = formalGLMRegisteredPhase20ReadJobStorageRootV1(
			jobKeys.root, jobKeys.slotRelativeDir, jobKeys.keyRelativePath)
		contextOK = err == nil && subtle.ConstantTimeCompare(
			storageRoot[:], jobKeys.storageRoot[:]) == 1
	}
	jobKeys.mu.Unlock()
	semanticRoot, peer := owner.record.Binding.SemanticRootSHA256, owner.peer
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(owner.pins)
	owner.mu.Unlock()
	defer source.clear()
	defer clear(storageRoot[:])
	defer formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
	if !contextOK || !formalGLMIsSHA256(semanticRoot) || source.Result.Peer != peer ||
		source.Result.SemanticRootSHA256 != semanticRoot {
		return zero, fmt.Errorf("formal-glm registered Phase20 handoff: owner binding changed")
	}

	openedRoot, err := formalGLMRegisteredPhase19OpenRockRootV1(rockRoot)
	if err != nil {
		return zero, err
	}
	openedInfo, openedErr := openedRoot.Stat(".")
	closeErr := openedRoot.Close()
	if openedErr != nil || closeErr != nil || !os.SameFile(attemptInfo, openedInfo) {
		return zero, fmt.Errorf("formal-glm registered Phase20 handoff: Rock root changed")
	}
	store, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(rockRoot, "formal-glm-phase20-handoff"), semanticRoot, peer,
		storageRoot, source.backend, pins)
	if err != nil {
		return zero, err
	}
	defer store.close()
	return store.Commit(source.Plan, source.Context, source.Result)
}
