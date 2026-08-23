package main

// Process-wide attempt fence shared by worker start, run control, and
// abandonment. Callers acquire it before any AttemptStore mutex; guarded
// helpers revalidate the exact durable pair after acquisition.

import (
	"fmt"
	"os"
	"reflect"
)

type formalGLMRegisteredPhase20AttemptFenceV1 struct {
	store     *formalGLMRegisteredPhase19AttemptStoreV1
	attemptID string
	root      *os.Root
	lock      *os.File
	lifetime  *os.File
	voteReady bool
}

func formalGLMRegisteredPhase20AcquireAttemptFenceV1(
	store *formalGLMRegisteredPhase19AttemptStoreV1,
	attemptID string,
) (*formalGLMRegisteredPhase20AttemptFenceV1, error) {
	if store == nil || !formalGLMIsSHA256(attemptID) {
		return nil, fmt.Errorf("formal-glm registered Phase20 attempt fence: invalid attempt")
	}
	// Snapshot only long enough to locate the immutable attempt directory.
	// Never wait for the process fence while holding store.mu.
	store.mu.Lock()
	base := store.root
	relative := store.attemptRelativeDirV1(attemptID)
	store.mu.Unlock()
	if base == nil || relative == "" ||
		formalGLMRegisteredPhase18TicketStoreValidateDirV1(base, relative) != nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 attempt fence: attempt unavailable")
	}
	root, err := base.OpenRoot(relative)
	if err != nil {
		return nil, err
	}
	lock, err := formalGLMRegisteredPhase20JobOwnerAcquireFlockV1(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	fence := &formalGLMRegisteredPhase20AttemptFenceV1{
		store: store, attemptID: attemptID, root: root, lock: lock,
	}
	store.mu.Lock()
	valid := fence.validLockedV1(store, attemptID)
	store.mu.Unlock()
	if !valid {
		fence.Close()
		return nil, fmt.Errorf("formal-glm registered Phase20 attempt fence: attempt changed")
	}
	return fence, nil
}

func (fence *formalGLMRegisteredPhase20AttemptFenceV1) validLockedV1(
	store *formalGLMRegisteredPhase19AttemptStoreV1,
	attemptID string,
) bool {
	if fence == nil || fence.store != store || store == nil || store.root == nil ||
		fence.attemptID != attemptID || fence.root == nil || fence.lock == nil {
		return false
	}
	relative := store.attemptRelativeDirV1(attemptID)
	current, currentErr := store.root.Lstat(relative)
	opened, openedErr := fence.root.Stat(".")
	lockPath, pathErr := fence.root.Lstat(
		formalGLMRegisteredPhase20JobOwnerLockFileV1)
	lockFile, fileErr := fence.lock.Stat()
	return currentErr == nil && openedErr == nil && pathErr == nil && fileErr == nil &&
		current.IsDir() && current.Mode()&os.ModeSymlink == 0 &&
		current.Mode().Perm() == 0o700 &&
		formalFinalizerHandoffPrivateOwnedDirectory(current) &&
		os.SameFile(current, opened) && os.SameFile(lockPath, lockFile) &&
		lockPath.Mode().IsRegular() && lockPath.Mode()&os.ModeSymlink == 0 &&
		lockPath.Mode().Perm() == 0o600 && exactGCPrivateOwnedRegular(lockPath)
}

func (fence *formalGLMRegisteredPhase20AttemptFenceV1) Close() {
	if fence == nil {
		return
	}
	formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(fence.lifetime)
	formalGLMRegisteredPhase20JobOwnerReleaseFlockV1(fence.lock)
	if fence.root != nil {
		_ = fence.root.Close()
	}
	fence.store = nil
	fence.attemptID = ""
	fence.root = nil
	fence.lock = nil
	fence.lifetime = nil
	fence.voteReady = false
}

func formalGLMRegisteredPhase20AttemptPairLockedV1(
	store *formalGLMRegisteredPhase19AttemptStoreV1,
	fence *formalGLMRegisteredPhase20AttemptFenceV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	rejectDecision bool,
) error {
	if !fence.validLockedV1(store, proposal.Binding.AttemptID) ||
		store.requirePreviousBindingV1(proposal.Binding) != nil ||
		store.validateAcceptV1(proposal, accept) != nil ||
		!reflect.DeepEqual(proposal.Binding, accept.Binding) {
		return fmt.Errorf("formal-glm registered Phase20 attempt fence: invalid accepted pair")
	}
	persistedProposal, hasProposal, proposalErr :=
		formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19ClaimProposalV1](
			store.root, store.attemptRelativePathV1(proposal.Binding.AttemptID,
				formalGLMRegisteredPhase19ClaimProposalFileV1))
	persistedAccept, hasAccept, acceptErr :=
		formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19ClaimAcceptV1](
			store.root, store.attemptRelativePathV1(proposal.Binding.AttemptID,
				formalGLMRegisteredPhase19ClaimAcceptFileV1))
	// The evaluator writes its accept locally before it sends it.  The garbler
	// may therefore hold a valid signed accept before its own Rock replica has
	// been written; commitVoteV1 below atomically imports that exact accept
	// under this fence.  A present replica must still be byte-for-byte the same.
	if proposalErr != nil || acceptErr != nil || !hasProposal ||
		!reflect.DeepEqual(persistedProposal, proposal) ||
		(hasAccept && !reflect.DeepEqual(persistedAccept, accept)) {
		return fmt.Errorf("formal-glm registered Phase20 attempt fence: durable pair changed")
	}
	if !rejectDecision {
		return nil
	}
	_, hasVote0, vote0Err :=
		formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19DecisionVoteV1](
			store.root, store.attemptRelativePathV1(proposal.Binding.AttemptID,
				formalGLMRegisteredPhase19DecisionVote0FileV1))
	_, hasVote1, vote1Err :=
		formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19DecisionVoteV1](
			store.root, store.attemptRelativePathV1(proposal.Binding.AttemptID,
				formalGLMRegisteredPhase19DecisionVote1FileV1))
	_, hasAbandoned, abandonedErr :=
		formalGLMRegisteredPhase19AttemptReadV1[formalGLMRegisteredPhase19AbandonedV1](
			store.root, store.attemptRelativePathV1(proposal.Binding.AttemptID,
				formalGLMRegisteredPhase19AbandonedFileV1))
	if vote0Err != nil || vote1Err != nil || abandonedErr != nil ||
		hasVote0 || hasVote1 || hasAbandoned {
		return fmt.Errorf("formal-glm registered Phase20 attempt fence: attempt is abandoning")
	}
	return nil
}

func formalGLMRegisteredPhase20AttemptPairV1(
	store *formalGLMRegisteredPhase19AttemptStoreV1,
	fence *formalGLMRegisteredPhase20AttemptFenceV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	rejectDecision bool,
) error {
	if store == nil {
		return fmt.Errorf("formal-glm registered Phase20 attempt fence: store unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return formalGLMRegisteredPhase20AttemptPairLockedV1(
		store, fence, proposal, accept, rejectDecision)
}

func formalGLMRegisteredPhase20AttemptVoteQuiescenceV1(
	store *formalGLMRegisteredPhase19AttemptStoreV1,
	fence *formalGLMRegisteredPhase20AttemptFenceV1,
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) error {
	if fence != nil && fence.voteReady {
		return nil
	}
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil {
		return err
	}
	epoch := formalGLMRegisteredPhase20JobTransportEpochV1{
		Mode: formalGLMRegisteredPhase20JobRunTransportV1, BasisSHA256: acceptSHA256,
	}
	store.mu.Lock()
	if err := formalGLMRegisteredPhase20AttemptPairLockedV1(
		store, fence, proposal, accept, false); err != nil {
		store.mu.Unlock()
		return err
	}
	binding := formalGLMRegisteredPhase20JobTransportBindingV1{
		ArtifactID:          proposal.Binding.ArtifactID,
		ReceiptSetSHA256:    store.record.Binding.ReceiptSetSHA256,
		SemanticRootSHA256:  proposal.Binding.SemanticRootSHA256,
		BindingRecordSHA256: proposal.Binding.BindingRecordSHA256,
		AttemptID:           proposal.Binding.AttemptID,
		ScheduleRootSHA256:  proposal.Binding.ScheduleRootSHA256,
		ProductionReady:     false,
	}
	root := store.root
	attemptRelative := store.attemptRelativeDirV1(proposal.Binding.AttemptID)
	burned, burnErr := formalGLMRegisteredPhase20JobTransportBurnedV1(
		root, attemptRelative, binding, epoch)
	var scratch *os.Root
	var transportSHA256 string
	if burnErr == nil && burned {
		_, transportSHA256, burnErr =
			formalGLMRegisteredPhase20JobTransportIdentityV1(binding, epoch)
		if burnErr == nil {
			var relative string
			relative, burnErr = formalGLMRegisteredPhase20JobTransportRelativeV1(
				attemptRelative, transportSHA256)
			if burnErr == nil {
				scratch, burnErr = root.OpenRoot(relative)
			}
		}
	}
	store.mu.Unlock()
	if burnErr != nil {
		return burnErr
	}
	if !burned {
		fence.voteReady = true
		return nil
	}
	defer scratch.Close()
	if err := formalGLMRegisteredPhase20JobTransportSignalAbortV1(scratch); err != nil {
		return err
	}
	lockSHA256, err := formalGLMRegisteredPhase20JobWorkerOwnerLockSHA256V1(
		transportSHA256)
	if err != nil {
		return err
	}
	held, acquired, err := formalGLMRegisteredPhase20JobWorkerLifetimeLockHeldV1(
		scratch, lockSHA256)
	if err != nil {
		return err
	}
	if held {
		return errFormalGLMRegisteredPhase20JobWorkerOwnerLockBusyV1
	}
	if acquired == nil {
		acquired, err = formalGLMRegisteredPhase20JobWorkerAcquireLifetimeLockV1(
			scratch, lockSHA256)
		if err != nil {
			return err
		}
	}
	fence.lifetime = acquired
	fence.voteReady = true
	return nil
}
