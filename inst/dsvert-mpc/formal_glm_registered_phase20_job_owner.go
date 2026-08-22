package main

// Sole-owner, non-production control plane for one registered Phase20 job.
// It consumes the attempt/key owners by contract and exposes only canonical
// control frames. Raw stores, paths, keys, and the worker transport never
// leave this seam. The next compute milestone owns the live worker through
// this type rather than reopening a burned epoch.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"syscall"
)

const (
	formalGLMRegisteredPhase20JobOwnerLockFileV1 = "job-owner.lock"

	formalGLMRegisteredPhase20JobOwnerRunningStateV1   = "running"
	formalGLMRegisteredPhase20JobOwnerInspectStateV1   = "inspect_only"
	formalGLMRegisteredPhase20JobOwnerPendingStateV1   = "abandon_pending"
	formalGLMRegisteredPhase20JobOwnerVotedStateV1     = "abandon_voted"
	formalGLMRegisteredPhase20JobOwnerAbandonedStateV1 = "abandoned"
)

var errFormalGLMRegisteredPhase20JobOwnerBusyV1 = errors.New(
	"formal-glm registered Phase20 job owner: attempt fence busy")

// All fields are deliberately private. A caller which creates this owner
// transfers exclusive use of attempts/jobKeys to it until a later owner takes
// over; direct raw calls are lower-level primitives, not this control plane.
type formalGLMRegisteredPhase20JobOwnerV1 struct {
	mu sync.Mutex

	attempts *formalGLMRegisteredPhase19AttemptStoreV1
	jobKeys  *formalGLMRegisteredPhase20JobKeyProviderV1
	start    formalGLMRegisteredPhase20JobStartV1
	control  *formalGLMRegisteredPhase20JobControlV1

	proposal formalGLMRegisteredPhase19ClaimProposalV1
	accept   formalGLMRegisteredPhase19ClaimAcceptV1
	votes    [2]*formalGLMRegisteredPhase19DecisionVoteV1

	controller *formalGLMRegisteredPhase20JobWorkerControllerV1
	terminal   *formalGLMRegisteredPhase20TerminalOwnerV1

	computeStarted  bool
	computeRunning  bool
	computeDone     chan struct{}
	terminalRunning bool
	terminalDone    chan struct{}
	closed          bool
}

type formalGLMRegisteredPhase20JobOwnerResultV1 struct {
	state           string
	outbound        []byte
	inspectOnly     bool
	productionReady bool
}

type formalGLMRegisteredPhase20JobOwnerHeadV1 struct {
	previous *formalGLMRegisteredPhase19AbandonedV1
	status   formalGLMRegisteredPhase19AttemptStatusV1
}

func newFormalGLMRegisteredPhase20JobOwnerV1(
	attempts *formalGLMRegisteredPhase19AttemptStoreV1,
	jobKeys *formalGLMRegisteredPhase20JobKeyProviderV1,
	start formalGLMRegisteredPhase20JobStartV1,
) (*formalGLMRegisteredPhase20JobOwnerV1, error) {
	control, err := newFormalGLMRegisteredPhase20JobControlV1(attempts, jobKeys)
	if err != nil {
		return nil, err
	}
	if err := control.validateStartV1(start); err != nil {
		return nil, err
	}
	return &formalGLMRegisteredPhase20JobOwnerV1{
		attempts: attempts, jobKeys: jobKeys, start: start, control: control,
	}, nil
}

func formalGLMRegisteredPhase20JobOwnerAcquireFlockV1(
	root *os.Root,
) (*os.File, error) {
	if root == nil || !formalGLMRegisteredPhase20JobWorkerLockSupportedV1() {
		return nil, fmt.Errorf("formal-glm registered Phase20 job owner: fence unavailable")
	}
	for attempt := 0; attempt < 4; attempt++ {
		info, statErr := root.Lstat(formalGLMRegisteredPhase20JobOwnerLockFileV1)
		flags := os.O_RDWR
		if os.IsNotExist(statErr) {
			flags |= os.O_CREATE | os.O_EXCL
		} else if statErr != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
			!exactGCPrivateOwnedRegular(info) {
			return nil, fmt.Errorf("formal-glm registered Phase20 job owner: unsafe fence")
		}
		file, err := root.OpenFile(formalGLMRegisteredPhase20JobOwnerLockFileV1,
			flags, 0o600)
		if err != nil {
			if os.IsExist(err) || os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if flags&os.O_CREATE != 0 {
			if err := file.Chmod(0o600); err != nil {
				_ = file.Close()
				return nil, err
			}
			if err := file.Sync(); err != nil {
				_ = file.Close()
				return nil, err
			}
			if err := formalGLMPhase21RootSyncDir(root,
				formalGLMRegisteredPhase20JobOwnerLockFileV1); err != nil {
				_ = file.Close()
				return nil, err
			}
		}
		opened, openErr := file.Stat()
		current, currentErr := root.Lstat(formalGLMRegisteredPhase20JobOwnerLockFileV1)
		if openErr != nil || currentErr != nil || !os.SameFile(opened, current) ||
			!current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
			current.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(current) {
			_ = file.Close()
			return nil, fmt.Errorf("formal-glm registered Phase20 job owner: fence changed")
		}
		if err := formalFinalizerHandoffTryAuthorityLock(file); err != nil {
			_ = file.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
				return nil, errFormalGLMRegisteredPhase20JobOwnerBusyV1
			}
			return nil, fmt.Errorf("formal-glm registered Phase20 job owner: fence failed: %w", err)
		}
		return file, nil
	}
	return nil, fmt.Errorf("formal-glm registered Phase20 job owner: fence changed")
}

func formalGLMRegisteredPhase20JobOwnerReleaseFlockV1(file *os.File) {
	if file != nil {
		_ = formalFinalizerHandoffUnlockAuthority(file)
		_ = file.Close()
	}
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) closedV1() error {
	if owner == nil || owner.closed || owner.control == nil ||
		owner.attempts == nil || owner.jobKeys == nil {
		return fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	return nil
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) loadHeadV1() (
	formalGLMRegisteredPhase20JobOwnerHeadV1, error,
) {
	var zero formalGLMRegisteredPhase20JobOwnerHeadV1
	var previous *formalGLMRegisteredPhase19AbandonedV1
	for {
		status, err := owner.attempts.LoadStatus(previous)
		if err != nil {
			return zero, err
		}
		if status.abandoned == nil {
			return formalGLMRegisteredPhase20JobOwnerHeadV1{
				previous: previous, status: status,
			}, nil
		}
		value := *status.abandoned
		previous = &value
	}
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) rememberPairV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
	status formalGLMRegisteredPhase19AttemptStatusV1,
) {
	owner.proposal, owner.accept = proposal, accept
	for index := range 2 {
		owner.votes[index] = nil
		if status.votes[index] != nil {
			value := *status.votes[index]
			owner.votes[index] = &value
		}
	}
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) pairV1(
	allowVotes bool,
) (formalGLMRegisteredPhase20JobOwnerHeadV1,
	formalGLMRegisteredPhase19ClaimProposalV1,
	formalGLMRegisteredPhase19ClaimAcceptV1, error) {
	var zeroHead formalGLMRegisteredPhase20JobOwnerHeadV1
	var zeroProposal formalGLMRegisteredPhase19ClaimProposalV1
	var zeroAccept formalGLMRegisteredPhase19ClaimAcceptV1
	head, err := owner.loadHeadV1()
	if err != nil || head.status.proposal == nil || head.status.accept == nil {
		return zeroHead, zeroProposal, zeroAccept,
			fmt.Errorf("formal-glm registered Phase20 job owner: accepted attempt unavailable")
	}
	if !allowVotes && (head.status.votes[0] != nil || head.status.votes[1] != nil) {
		return zeroHead, zeroProposal, zeroAccept,
			fmt.Errorf("formal-glm registered Phase20 job owner: attempt is abandoning")
	}
	proposal, accept := *head.status.proposal, *head.status.accept
	owner.rememberPairV1(proposal, accept, head.status)
	return head, proposal, accept, nil
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) activeV1() (
	formalGLMRegisteredPhase20JobControlAcceptedV1, error,
) {
	accepted, err := owner.control.acceptedV1()
	if err != nil {
		return accepted, err
	}
	owner.proposal, owner.accept = accepted.proposal, accepted.accept
	return accepted, nil
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) fenceV1(
	attemptID string,
) (*formalGLMRegisteredPhase20AttemptFenceV1, error) {
	return formalGLMRegisteredPhase20AcquireAttemptFenceV1(
		owner.attempts, attemptID)
}

func formalGLMRegisteredPhase20JobOwnerResultFromControlV1(
	value formalGLMRegisteredPhase20JobControlStartResultV1,
) formalGLMRegisteredPhase20JobOwnerResultV1 {
	return formalGLMRegisteredPhase20JobOwnerResultV1{
		state: value.state, outbound: append([]byte(nil), value.outbound...),
		productionReady: false,
	}
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) NegotiateV1(
	inbound []byte,
) (formalGLMRegisteredPhase20JobOwnerResultV1, error) {
	var zero formalGLMRegisteredPhase20JobOwnerResultV1
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.closedV1(); err != nil {
		return zero, err
	}
	result, err := owner.control.StartV1(owner.start, inbound)
	if err != nil {
		return zero, err
	}
	if result.state == formalGLMRegisteredPhase20JobControlAcceptedStateV1 {
		if _, err := owner.activeV1(); err != nil {
			return zero, err
		}
	}
	return formalGLMRegisteredPhase20JobOwnerResultFromControlV1(result), nil
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) StartOrInspectV1() (
	formalGLMRegisteredPhase20JobOwnerResultV1, error,
) {
	var zero formalGLMRegisteredPhase20JobOwnerResultV1
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.closedV1(); err != nil {
		return zero, err
	}
	accepted, err := owner.activeV1()
	if err != nil {
		return zero, err
	}
	fence, err := owner.fenceV1(accepted.proposal.Binding.AttemptID)
	if err != nil {
		return zero, err
	}
	defer fence.Close()
	// The fence covers the only pre-burn window. Re-read the active attempt
	// after acquiring it; a conforming abandon path cannot race this point.
	accepted, err = owner.activeV1()
	if err != nil {
		return zero, err
	}
	if owner.controller != nil {
		owner.controller.mu.Lock()
		controllerErr := formalGLMRegisteredPhase20JobControlControllerLockedV1(
			owner.controller, accepted)
		owner.controller.mu.Unlock()
		if controllerErr == nil {
			return formalGLMRegisteredPhase20JobOwnerResultV1{
				state: formalGLMRegisteredPhase20JobOwnerRunningStateV1,
			}, nil
		}
	}
	burned, err := formalGLMRegisteredPhase20JobTransportBurnedV1(
		accepted.root, accepted.attemptRelative, accepted.binding, accepted.epoch)
	if err != nil {
		return zero, err
	}
	if burned {
		observation, observeErr := inspectFormalGLMRegisteredPhase20JobWorkerControllerV1(
			owner.attempts, owner.jobKeys, accepted.proposal, accepted.accept, accepted.epoch)
		if observeErr != nil {
			return zero, observeErr
		}
		return formalGLMRegisteredPhase20JobOwnerResultV1{
			state: observation.state, inspectOnly: true,
		}, nil
	}
	controller, err := startFormalGLMRegisteredPhase20JobWorkerControllerWithFenceV1(
		fence, owner.attempts, owner.jobKeys,
		accepted.proposal, accepted.accept, accepted.epoch)
	if err != nil {
		return zero, err
	}
	// A raw lower-level VoteAbandon is outside this owner's contract. Still
	// fail closed if durable state changed before the worker became available.
	if refreshed, refreshErr := owner.activeV1(); refreshErr != nil ||
		!reflect.DeepEqual(refreshed.proposal, accepted.proposal) ||
		!reflect.DeepEqual(refreshed.accept, accepted.accept) {
		_ = controller.Close()
		if refreshErr != nil {
			return zero, refreshErr
		}
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: attempt changed during start")
	}
	owner.controller = controller
	return formalGLMRegisteredPhase20JobOwnerResultV1{
		state: formalGLMRegisteredPhase20JobOwnerRunningStateV1,
	}, nil
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) runControlV1(
	fn func(formalGLMRegisteredPhase20JobControlAcceptedV1,
		*formalGLMRegisteredPhase20AttemptFenceV1) error,
) error {
	if err := owner.closedV1(); err != nil {
		return err
	}
	accepted, err := owner.activeV1()
	if err != nil {
		return err
	}
	fence, err := owner.fenceV1(accepted.proposal.Binding.AttemptID)
	if err != nil {
		return err
	}
	defer fence.Close()
	accepted, err = owner.activeV1()
	if err != nil {
		return err
	}
	if owner.controller == nil {
		return fmt.Errorf("formal-glm registered Phase20 job owner: worker unavailable")
	}
	// Heartbeat verifies the live owner, relay state, and all abort markers
	// before a control frame can expose or bind the run epoch.
	if err := owner.controller.HeartbeatV1(); err != nil {
		return err
	}
	return fn(accepted, fence)
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) JobRefV1() (
	formalGLMRegisteredPhase20JobRefV1, []byte, error,
) {
	var zero formalGLMRegisteredPhase20JobRefV1
	if owner == nil {
		return zero, nil, fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	var ref formalGLMRegisteredPhase20JobRefV1
	var frame []byte
	err := owner.runControlV1(func(_ formalGLMRegisteredPhase20JobControlAcceptedV1,
		fence *formalGLMRegisteredPhase20AttemptFenceV1) error {
		var callErr error
		ref, frame, callErr = owner.control.jobRefWithFenceV1(
			fence, owner.controller)
		return callErr
	})
	if err != nil {
		return zero, nil, err
	}
	return ref, frame, nil
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) BindPeerJobRefV1(
	encoded []byte,
) error {
	if owner == nil {
		return fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.runControlV1(func(_ formalGLMRegisteredPhase20JobControlAcceptedV1,
		fence *formalGLMRegisteredPhase20AttemptFenceV1) error {
		return owner.control.bindPeerJobRefWithFenceV1(
			fence, owner.controller, encoded)
	})
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) HeartbeatV1() error {
	if owner == nil {
		return fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.runControlV1(func(_ formalGLMRegisteredPhase20JobControlAcceptedV1,
		_ *formalGLMRegisteredPhase20AttemptFenceV1) error {
		return nil
	})
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) burnedV1() (bool, error) {
	_, proposal, accept, err := owner.pairForAbandonV1()
	if err != nil {
		return false, err
	}
	root, relative, binding, epoch, err := owner.transportForPairV1(proposal, accept)
	if err != nil {
		return false, err
	}
	return formalGLMRegisteredPhase20JobTransportBurnedV1(
		root, relative, binding, epoch)
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) pairForAbandonV1() (
	formalGLMRegisteredPhase20JobOwnerHeadV1,
	formalGLMRegisteredPhase19ClaimProposalV1,
	formalGLMRegisteredPhase19ClaimAcceptV1, error,
) {
	head, proposal, accept, err := owner.pairV1(true)
	if err == nil {
		return head, proposal, accept, nil
	}
	if owner.proposal.Binding.AttemptID != "" && owner.accept.Binding.AttemptID != "" {
		return formalGLMRegisteredPhase20JobOwnerHeadV1{}, owner.proposal, owner.accept, nil
	}
	return head, proposal, accept, err
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) transportForPairV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) (*os.Root, string, formalGLMRegisteredPhase20JobTransportBindingV1,
	formalGLMRegisteredPhase20JobTransportEpochV1, error) {
	var zero formalGLMRegisteredPhase20JobTransportBindingV1
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil {
		return nil, "", zero, formalGLMRegisteredPhase20JobTransportEpochV1{}, err
	}
	epoch := formalGLMRegisteredPhase20JobTransportEpochV1{
		Mode: formalGLMRegisteredPhase20JobRunTransportV1, BasisSHA256: acceptSHA256,
	}
	root, relative, binding, err := formalGLMRegisteredPhase20JobWorkerStartBindingV1(
		owner.attempts, owner.jobKeys, proposal, accept, epoch)
	if err != nil {
		return nil, "", zero, formalGLMRegisteredPhase20JobTransportEpochV1{}, err
	}
	return root, relative, binding, epoch, nil
}

func formalGLMRegisteredPhase20JobOwnerLocalIndexV1(
	store *formalGLMRegisteredPhase19AttemptStoreV1,
) (int, error) {
	if store == nil {
		return -1, fmt.Errorf("formal-glm registered Phase20 job owner: attempt owner unavailable")
	}
	store.mu.Lock()
	index := store.localIndex
	valid := store.root != nil && index >= 0 && index < 2
	store.mu.Unlock()
	if !valid {
		return -1, fmt.Errorf("formal-glm registered Phase20 job owner: attempt owner unavailable")
	}
	return index, nil
}

func formalGLMRegisteredPhase20JobOwnerEncodeV1(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) abortBurnedV1(
	proposal formalGLMRegisteredPhase19ClaimProposalV1,
	accept formalGLMRegisteredPhase19ClaimAcceptV1,
) (*os.File, error) {
	acceptSHA256, err := formalGLMRegisteredPhase19ClaimAcceptSHA256V1(accept)
	if err != nil {
		return nil, err
	}
	epoch := formalGLMRegisteredPhase20JobTransportEpochV1{
		Mode: formalGLMRegisteredPhase20JobRunTransportV1, BasisSHA256: acceptSHA256,
	}
	store, err := openFormalGLMRegisteredPhase20JobTransportRelayStoreV1(
		owner.attempts, owner.jobKeys, proposal, accept, epoch)
	if err != nil {
		return nil, err
	}
	defer store.CloseRelayV1()
	lock, err := store.acquireRelayLockV1()
	if err != nil {
		return nil, err
	}
	defer store.releaseRelayLockV1(lock)
	if err := formalGLMRegisteredPhase20JobWorkerAbortLockedV1(store); err != nil {
		return nil, err
	}
	lockSHA256, err := formalGLMRegisteredPhase20JobWorkerOwnerLockSHA256V1(
		store.ref.TransportSHA256)
	if err != nil {
		return nil, err
	}
	held, lease, err := formalGLMRegisteredPhase20JobWorkerLifetimeLockHeldV1(
		store.scratch, lockSHA256)
	if err != nil {
		return nil, err
	}
	if held {
		return nil, nil
	}
	if lease != nil {
		return lease, nil
	}
	return formalGLMRegisteredPhase20JobWorkerAcquireLifetimeLockV1(
		store.scratch, lockSHA256)
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) InitiateAbandonV1() (
	formalGLMRegisteredPhase20JobOwnerResultV1, error,
) {
	var zero formalGLMRegisteredPhase20JobOwnerResultV1
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.closedV1(); err != nil {
		return zero, err
	}
	_, proposal, accept, err := owner.pairForAbandonV1()
	if err != nil {
		return zero, err
	}
	index, err := formalGLMRegisteredPhase20JobOwnerLocalIndexV1(owner.attempts)
	if err != nil || index != 1 {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: evaluator initiates abandonment")
	}
	fence, err := owner.fenceV1(proposal.Binding.AttemptID)
	if err != nil {
		return zero, err
	}
	defer fence.Close()
	head, proposal, accept, err := owner.pairForAbandonV1()
	if err != nil {
		return zero, err
	}
	if head.status.votes[1] != nil {
		encoded, marshalErr := formalGLMRegisteredPhase20JobOwnerEncodeV1(*head.status.votes[1])
		return formalGLMRegisteredPhase20JobOwnerResultV1{
			state: formalGLMRegisteredPhase20JobOwnerVotedStateV1, outbound: encoded,
		}, marshalErr
	}
	transportRoot, relative, binding, epoch, err := owner.transportForPairV1(proposal, accept)
	if err != nil {
		return zero, err
	}
	burned, err := formalGLMRegisteredPhase20JobTransportBurnedV1(
		transportRoot, relative, binding, epoch)
	if err != nil {
		return zero, err
	}
	var lifetime *os.File
	if burned {
		lifetime, err = owner.abortBurnedV1(proposal, accept)
		if err != nil {
			return zero, err
		}
		if lifetime == nil {
			return formalGLMRegisteredPhase20JobOwnerResultV1{
				state: formalGLMRegisteredPhase20JobOwnerPendingStateV1,
			}, nil
		}
		formalGLMRegisteredPhase20JobWorkerReleaseLifetimeLockV1(lifetime)
	}
	vote, _, err := owner.attempts.voteAbandonWithFenceV1(
		fence, proposal, accept)
	if errors.Is(err, errFormalGLMRegisteredPhase20JobWorkerOwnerLockBusyV1) {
		return formalGLMRegisteredPhase20JobOwnerResultV1{
			state: formalGLMRegisteredPhase20JobOwnerPendingStateV1,
		}, nil
	}
	if err != nil {
		return zero, err
	}
	value := vote
	owner.votes[1] = &value
	encoded, err := formalGLMRegisteredPhase20JobOwnerEncodeV1(vote)
	return formalGLMRegisteredPhase20JobOwnerResultV1{
		state: formalGLMRegisteredPhase20JobOwnerVotedStateV1, outbound: encoded,
	}, err
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) AcceptEvaluatorAbandonV1(
	encoded []byte,
) (formalGLMRegisteredPhase20JobOwnerResultV1, error) {
	var zero formalGLMRegisteredPhase20JobOwnerResultV1
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.closedV1(); err != nil {
		return zero, err
	}
	_, proposal, accept, err := owner.pairForAbandonV1()
	if err != nil {
		return zero, err
	}
	index, err := formalGLMRegisteredPhase20JobOwnerLocalIndexV1(owner.attempts)
	if err != nil || index != 0 {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: garbler accepts evaluator abandonment")
	}
	var evaluatorVote formalGLMRegisteredPhase19DecisionVoteV1
	if len(encoded) == 0 || formalGLMPhase21RockStrictDecode(encoded, &evaluatorVote) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: invalid evaluator vote")
	}
	fence, err := owner.fenceV1(proposal.Binding.AttemptID)
	if err != nil {
		return zero, err
	}
	defer fence.Close()
	_, proposal, accept, err = owner.pairForAbandonV1()
	if err != nil {
		return zero, err
	}
	owner.attempts.mu.Lock()
	voteIndex, voteErr := owner.attempts.validateVoteV1(proposal, accept, evaluatorVote)
	owner.attempts.mu.Unlock()
	if voteErr != nil || voteIndex != 1 {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: invalid evaluator vote")
	}
	if err := formalGLMRegisteredPhase20AttemptVoteQuiescenceV1(
		owner.attempts, fence, proposal, accept); err != nil {
		if errors.Is(err, errFormalGLMRegisteredPhase20JobWorkerOwnerLockBusyV1) {
			return formalGLMRegisteredPhase20JobOwnerResultV1{
				state: formalGLMRegisteredPhase20JobOwnerPendingStateV1,
			}, nil
		}
		return zero, err
	}
	owner.attempts.mu.Lock()
	voteIndex, voteErr = owner.attempts.validateVoteV1(
		proposal, accept, evaluatorVote)
	if voteErr == nil && voteIndex == 1 {
		_, voteErr = owner.attempts.commitVoteV1(
			fence, proposal, accept, evaluatorVote)
	}
	if voteErr != nil || voteIndex != 1 {
		owner.attempts.mu.Unlock()
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: invalid evaluator vote")
	}
	local, localErr := owner.attempts.voteV1(proposal, accept, 0)
	if localErr == nil {
		message, messageErr := formalGLMRegisteredPhase19AttemptSignatureMessageV1(
			formalGLMRegisteredPhase19DecisionVoteDomainV1, local)
		if messageErr != nil {
			localErr = messageErr
		} else {
			local.Signature = ed25519.Sign(owner.attempts.signingKey, message)
			clear(message)
			_, localErr = owner.attempts.commitVoteV1(
				fence, proposal, accept, local)
		}
	}
	owner.attempts.mu.Unlock()
	if localErr != nil {
		return zero, localErr
	}
	remoteCopy, localCopy := evaluatorVote, local
	owner.votes[1], owner.votes[0] = &remoteCopy, &localCopy
	result, err := formalGLMRegisteredPhase20JobOwnerEncodeV1(local)
	return formalGLMRegisteredPhase20JobOwnerResultV1{
		state: formalGLMRegisteredPhase20JobOwnerVotedStateV1, outbound: result,
	}, err
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) CommitAbandonedV1(
	encoded []byte,
) (formalGLMRegisteredPhase20JobOwnerResultV1, error) {
	var zero formalGLMRegisteredPhase20JobOwnerResultV1
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job owner: unavailable")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := owner.closedV1(); err != nil {
		return zero, err
	}
	_, proposal, accept, err := owner.pairForAbandonV1()
	if err != nil {
		return zero, err
	}
	fence, err := owner.fenceV1(proposal.Binding.AttemptID)
	if err != nil {
		return zero, err
	}
	defer fence.Close()
	index, err := formalGLMRegisteredPhase20JobOwnerLocalIndexV1(owner.attempts)
	if err != nil {
		return zero, err
	}
	votes := [2]formalGLMRegisteredPhase19DecisionVoteV1{}
	if index == 0 {
		if len(encoded) != 0 {
			return zero, fmt.Errorf("formal-glm registered Phase20 job owner: garbler does not import vote0")
		}
		if owner.votes[0] == nil || owner.votes[1] == nil {
			return zero, fmt.Errorf("formal-glm registered Phase20 job owner: votes unavailable")
		}
		votes[0], votes[1] = *owner.votes[0], *owner.votes[1]
	} else {
		if len(encoded) == 0 || formalGLMPhase21RockStrictDecode(encoded, &votes[0]) != nil {
			return zero, fmt.Errorf("formal-glm registered Phase20 job owner: invalid garbler vote")
		}
		if owner.votes[1] == nil {
			return zero, fmt.Errorf("formal-glm registered Phase20 job owner: evaluator vote unavailable")
		}
		votes[1] = *owner.votes[1]
	}
	abandoned, _, err := owner.attempts.commitAbandonedWithFenceV1(
		fence, proposal, accept, votes[:])
	if err != nil {
		return zero, err
	}
	result, err := formalGLMRegisteredPhase20JobOwnerEncodeV1(abandoned)
	return formalGLMRegisteredPhase20JobOwnerResultV1{
		state: formalGLMRegisteredPhase20JobOwnerAbandonedStateV1, outbound: result,
	}, err
}

func (owner *formalGLMRegisteredPhase20JobOwnerV1) Close() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	if owner.closed {
		owner.mu.Unlock()
		return nil
	}
	owner.closed = true
	controller := owner.controller
	if owner.computeRunning || owner.terminalRunning {
		done := owner.computeDone
		if owner.terminalRunning {
			done = owner.terminalDone
		}
		owner.mu.Unlock()
		if controller != nil {
			_ = controller.Close()
		}
		if done != nil {
			<-done
		}
		owner.mu.Lock()
	}
	terminal, attempts, jobKeys := owner.terminal, owner.attempts, owner.jobKeys
	owner.controller, owner.terminal, owner.attempts, owner.jobKeys, owner.control =
		nil, nil, nil, nil, nil
	owner.computeDone = nil
	owner.terminalDone = nil
	owner.proposal = formalGLMRegisteredPhase19ClaimProposalV1{}
	owner.accept = formalGLMRegisteredPhase19ClaimAcceptV1{}
	owner.votes = [2]*formalGLMRegisteredPhase19DecisionVoteV1{}
	owner.mu.Unlock()
	var closeErr error
	if terminal != nil {
		closeErr = terminal.Close()
	}
	if controller != nil {
		if err := controller.Close(); closeErr == nil {
			closeErr = err
		}
	}
	if attempts != nil {
		attempts.Close()
	}
	if jobKeys != nil {
		if err := jobKeys.Close(); closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}
