package main

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	formalGLMRegisteredPhase20TerminalWireVersionV1 = "dsvert-formal-glm-registered-phase20-terminal-wire-v1"
	formalGLMRegisteredPhase20TerminalWirePurposeV1 = "formal_glm_registered_phase20_authenticated_terminal_selection_v1"
	formalGLMRegisteredPhase20TerminalWireLabelV1   = "registered-phase20/terminal"

	formalGLMRegisteredPhase20TerminalReceiptPhaseV1 = "garbler_dp_share_receipt"
	formalGLMRegisteredPhase20TerminalBundlePhaseV1  = "evaluator_prepare_bundle"
	formalGLMRegisteredPhase20TerminalPreparePhaseV1 = "garbler_prepare"
	formalGLMRegisteredPhase20TerminalEVotePhaseV1   = "evaluator_select_vote"
	formalGLMRegisteredPhase20TerminalGVotePhaseV1   = "garbler_select_vote"
)

// The terminal wire carries only signed commitments and two-party receipts.
// It never serializes evidence, an output share, a path, or a key.
type formalGLMRegisteredPhase20TerminalWireV1 struct {
	Version string `json:"version"`
	Purpose string `json:"purpose"`
	Phase   string `json:"phase"`

	GarblerReceipt  *formalGLMRegisteredPhase20DPShareReceiptV1         `json:"garbler_receipt,omitempty"`
	EvaluatorBundle *formalGLMRegisteredPhase20EvaluatorPrepareBundleV1 `json:"evaluator_bundle,omitempty"`
	GarblerPrepare  *formalGLMRegisteredPhase20PrepareReceiptV1         `json:"garbler_prepare,omitempty"`
	EvaluatorVote   *formalGLMRegisteredPhase20SelectVoteV1             `json:"evaluator_vote,omitempty"`
	GarblerVote     *formalGLMRegisteredPhase20SelectVoteV1             `json:"garbler_vote,omitempty"`
}

type formalGLMRegisteredPhase20TerminalSessionV1 struct {
	plan    formalGLMPhase15Plan
	context formalGLMPhase19Context
	backend [32]byte
	root    [32]byte
	role    string
}

func (session *formalGLMRegisteredPhase20TerminalSessionV1) clearV1() {
	if session != nil {
		clear(session.backend[:])
		clear(session.root[:])
		*session = formalGLMRegisteredPhase20TerminalSessionV1{}
	}
}

func newFormalGLMRegisteredPhase20TerminalWireV1(
	phase string,
) formalGLMRegisteredPhase20TerminalWireV1 {
	return formalGLMRegisteredPhase20TerminalWireV1{
		Version: formalGLMRegisteredPhase20TerminalWireVersionV1,
		Purpose: formalGLMRegisteredPhase20TerminalWirePurposeV1,
		Phase:   phase,
	}
}

func (wire formalGLMRegisteredPhase20TerminalWireV1) validateV1(
	phase string, field any,
) error {
	if wire.Version != formalGLMRegisteredPhase20TerminalWireVersionV1 ||
		wire.Purpose != formalGLMRegisteredPhase20TerminalWirePurposeV1 ||
		wire.Phase != phase {
		return fmt.Errorf("formal-glm registered Phase20 job terminal: invalid wire frame")
	}
	count := 0
	if wire.GarblerReceipt != nil {
		count++
	}
	if wire.EvaluatorBundle != nil {
		count++
	}
	if wire.GarblerPrepare != nil {
		count++
	}
	if wire.EvaluatorVote != nil {
		count++
	}
	if wire.GarblerVote != nil {
		count++
	}
	if field == nil {
		if count != 0 {
			return fmt.Errorf("formal-glm registered Phase20 job terminal: invalid acknowledgement")
		}
		return nil
	}
	if count != 1 {
		return fmt.Errorf("formal-glm registered Phase20 job terminal: invalid wire payload")
	}
	switch field.(type) {
	case *formalGLMRegisteredPhase20DPShareReceiptV1:
		if wire.GarblerReceipt == nil {
			return fmt.Errorf("formal-glm registered Phase20 job terminal: missing garbler receipt")
		}
	case *formalGLMRegisteredPhase20EvaluatorPrepareBundleV1:
		if wire.EvaluatorBundle == nil {
			return fmt.Errorf("formal-glm registered Phase20 job terminal: missing evaluator bundle")
		}
	case *formalGLMRegisteredPhase20PrepareReceiptV1:
		if wire.GarblerPrepare == nil {
			return fmt.Errorf("formal-glm registered Phase20 job terminal: missing garbler prepare")
		}
	case *formalGLMRegisteredPhase20SelectVoteV1:
		if phase == formalGLMRegisteredPhase20TerminalEVotePhaseV1 &&
			wire.EvaluatorVote == nil {
			return fmt.Errorf("formal-glm registered Phase20 job terminal: missing evaluator vote")
		}
		if phase == formalGLMRegisteredPhase20TerminalGVotePhaseV1 &&
			wire.GarblerVote == nil {
			return fmt.Errorf("formal-glm registered Phase20 job terminal: missing garbler vote")
		}
	default:
		return fmt.Errorf("formal-glm registered Phase20 job terminal: invalid wire expectation")
	}
	return nil
}

func formalGLMRegisteredPhase20TerminalSessionFromOwnerV1(
	owner *formalGLMRegisteredPhase20TerminalOwnerV1,
) (formalGLMRegisteredPhase20TerminalSessionV1, error) {
	var zero formalGLMRegisteredPhase20TerminalSessionV1
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job terminal: terminal unavailable")
	}
	owner.mu.Lock()
	if owner.closed || owner.runtime == nil || owner.role != "garbler" && owner.role != "evaluator" {
		owner.mu.Unlock()
		return zero, fmt.Errorf("formal-glm registered Phase20 job terminal: terminal unavailable")
	}
	runtime, accept, peer, role := owner.runtime, owner.accept, owner.peer, owner.role
	owner.mu.Unlock()
	runtime.mu.Lock()
	err := runtime.validateLocked()
	plan := formalGLMRegisteredPhase19ClonePlanV1(runtime.legacyPlan)
	context := formalGLMRegisteredPhase19CloneContextV1(runtime.context)
	backend := runtime.backendKey
	runtime.mu.Unlock()
	if err != nil {
		clear(backend[:])
		return zero, err
	}
	root, err := formalGLMPhase19ScheduleDecodeHex32(
		accept.Binding.ScheduleRootSHA256, "root")
	if err != nil {
		clear(backend[:])
		return zero, err
	}
	if expected, roleErr := formalGLMRegisteredPhase19AccumulatorRoleV1(context, peer); roleErr != nil || expected != role {
		clear(backend[:])
		clear(root[:])
		return zero, fmt.Errorf("formal-glm registered Phase20 job terminal: invalid runtime roles")
	}
	return formalGLMRegisteredPhase20TerminalSessionV1{
		plan: plan, context: context, backend: backend, root: root, role: role,
	}, nil
}

func formalGLMRegisteredPhase20TerminalExchangeV1(
	rw io.ReadWriter, session formalGLMRegisteredPhase20TerminalSessionV1,
	phase string, index int, local formalGLMRegisteredPhase20TerminalWireV1,
) (formalGLMRegisteredPhase20TerminalWireV1, error) {
	var peer formalGLMRegisteredPhase20TerminalWireV1
	if rw == nil || local.Version != formalGLMRegisteredPhase20TerminalWireVersionV1 ||
		local.Purpose != formalGLMRegisteredPhase20TerminalWirePurposeV1 ||
		local.Phase != phase {
		return peer, fmt.Errorf("formal-glm registered Phase20 job terminal: invalid exchange")
	}
	encoded, err := json.Marshal(local)
	if err != nil {
		return peer, err
	}
	defer clear(encoded)
	exact, err := formalGLMPhase19RuntimeControlSession(
		session.plan, session.context, session.backend, session.root,
		formalGLMRegisteredPhase20TerminalWireLabelV1+"/"+phase, index)
	if err != nil {
		return peer, err
	}
	received, err := formalGLMPhase19RuntimeControlExchange(
		rw, exact, session.role, encoded, 2<<20)
	if err != nil {
		return peer, err
	}
	defer clear(received)
	if err := formalGLMPhase21RockStrictDecode(received, &peer); err != nil {
		return peer, fmt.Errorf("formal-glm registered Phase20 job terminal: invalid authenticated peer frame")
	}
	return peer, nil
}

func formalGLMRegisteredPhase20RunTerminalPeerV1(
	rw io.ReadWriter, owner *formalGLMRegisteredPhase20TerminalOwnerV1,
) (formalGLMPhase20HandoffCommit, error) {
	var zero formalGLMPhase20HandoffCommit
	session, err := formalGLMRegisteredPhase20TerminalSessionFromOwnerV1(owner)
	if err != nil {
		return zero, err
	}
	defer session.clearV1()

	receiptFrame := newFormalGLMRegisteredPhase20TerminalWireV1(
		formalGLMRegisteredPhase20TerminalReceiptPhaseV1)
	if session.role == "garbler" {
		receipt, receiptErr := owner.PublishDPShareReceiptV1()
		if receiptErr != nil {
			return zero, receiptErr
		}
		receiptFrame.GarblerReceipt = &receipt
	}
	peerReceipt, err := formalGLMRegisteredPhase20TerminalExchangeV1(
		rw, session, receiptFrame.Phase, 0, receiptFrame)
	if err != nil {
		return zero, err
	}
	var bundle formalGLMRegisteredPhase20EvaluatorPrepareBundleV1
	if session.role == "evaluator" {
		if err := peerReceipt.validateV1(receiptFrame.Phase,
			(*formalGLMRegisteredPhase20DPShareReceiptV1)(nil)); err != nil {
			return zero, err
		}
		bundle, _, err = owner.PrepareFromGarblerReceiptV1(*peerReceipt.GarblerReceipt)
		if err != nil {
			return zero, err
		}
	} else if err := peerReceipt.validateV1(receiptFrame.Phase, nil); err != nil {
		return zero, err
	}

	bundleFrame := newFormalGLMRegisteredPhase20TerminalWireV1(
		formalGLMRegisteredPhase20TerminalBundlePhaseV1)
	if session.role == "evaluator" {
		bundleFrame.EvaluatorBundle = &bundle
	}
	peerBundle, err := formalGLMRegisteredPhase20TerminalExchangeV1(
		rw, session, bundleFrame.Phase, 1, bundleFrame)
	if err != nil {
		return zero, err
	}
	var garblerPrepare, evaluatorPrepare formalGLMRegisteredPhase20PrepareReceiptV1
	if session.role == "garbler" {
		if err := peerBundle.validateV1(bundleFrame.Phase,
			(*formalGLMRegisteredPhase20EvaluatorPrepareBundleV1)(nil)); err != nil {
			return zero, err
		}
		evaluatorPrepare = peerBundle.EvaluatorBundle.EvaluatorPrepare
		garblerPrepare, _, err = owner.PrepareFromEvaluatorBundleV1(*peerBundle.EvaluatorBundle)
		if err != nil {
			return zero, err
		}
	} else if err := peerBundle.validateV1(bundleFrame.Phase, nil); err != nil {
		return zero, err
	}

	prepareFrame := newFormalGLMRegisteredPhase20TerminalWireV1(
		formalGLMRegisteredPhase20TerminalPreparePhaseV1)
	if session.role == "garbler" {
		prepareFrame.GarblerPrepare = &garblerPrepare
	}
	peerPrepare, err := formalGLMRegisteredPhase20TerminalExchangeV1(
		rw, session, prepareFrame.Phase, 2, prepareFrame)
	if err != nil {
		return zero, err
	}
	var evaluatorVote formalGLMRegisteredPhase20SelectVoteV1
	if session.role == "evaluator" {
		if err := peerPrepare.validateV1(prepareFrame.Phase,
			(*formalGLMRegisteredPhase20PrepareReceiptV1)(nil)); err != nil {
			return zero, err
		}
		evaluatorVote, _, err = owner.VoteSelectV1(*peerPrepare.GarblerPrepare)
		if err != nil {
			return zero, err
		}
	} else if err := peerPrepare.validateV1(prepareFrame.Phase, nil); err != nil {
		return zero, err
	}

	evaluatorVoteFrame := newFormalGLMRegisteredPhase20TerminalWireV1(
		formalGLMRegisteredPhase20TerminalEVotePhaseV1)
	if session.role == "evaluator" {
		evaluatorVoteFrame.EvaluatorVote = &evaluatorVote
	}
	peerEvaluatorVote, err := formalGLMRegisteredPhase20TerminalExchangeV1(
		rw, session, evaluatorVoteFrame.Phase, 3, evaluatorVoteFrame)
	if err != nil {
		return zero, err
	}
	var garblerVote formalGLMRegisteredPhase20SelectVoteV1
	if session.role == "garbler" {
		if err := peerEvaluatorVote.validateV1(evaluatorVoteFrame.Phase,
			(*formalGLMRegisteredPhase20SelectVoteV1)(nil)); err != nil {
			return zero, err
		}
		garblerVote, _, err = owner.VoteSelectV1(evaluatorPrepare)
		if err != nil {
			return zero, err
		}
	} else if err := peerEvaluatorVote.validateV1(evaluatorVoteFrame.Phase, nil); err != nil {
		return zero, err
	}

	garblerVoteFrame := newFormalGLMRegisteredPhase20TerminalWireV1(
		formalGLMRegisteredPhase20TerminalGVotePhaseV1)
	if session.role == "garbler" {
		garblerVoteFrame.GarblerVote = &garblerVote
	}
	peerGarblerVote, err := formalGLMRegisteredPhase20TerminalExchangeV1(
		rw, session, garblerVoteFrame.Phase, 4, garblerVoteFrame)
	if err != nil {
		return zero, err
	}
	if session.role == "garbler" {
		if err := peerGarblerVote.validateV1(garblerVoteFrame.Phase, nil); err != nil {
			return zero, err
		}
		if _, _, err := owner.CommitSelectedV1(*peerEvaluatorVote.EvaluatorVote); err != nil {
			return zero, err
		}
	} else {
		if err := peerGarblerVote.validateV1(garblerVoteFrame.Phase,
			(*formalGLMRegisteredPhase20SelectVoteV1)(nil)); err != nil {
			return zero, err
		}
		if _, _, err := owner.CommitSelectedV1(*peerGarblerVote.GarblerVote); err != nil {
			return zero, err
		}
	}
	return formalGLMRegisteredPhase20CommitSelectedHandoffV1(owner)
}

// RunTerminalV1 completes the authenticated terminal selection after the
// registered compute pipeline has sealed local evidence. It returns only the
// encrypted handoff digest and size; the trusted source remains Rock-local.
func (owner *formalGLMRegisteredPhase20JobOwnerV1) RunTerminalV1() (
	formalGLMPhase20HandoffCommit, error,
) {
	var zero formalGLMPhase20HandoffCommit
	if owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job terminal: owner unavailable")
	}
	owner.mu.Lock()
	if owner.closed || owner.computeRunning || owner.terminalRunning ||
		owner.terminal == nil || owner.controller == nil {
		owner.mu.Unlock()
		return zero, fmt.Errorf("formal-glm registered Phase20 job terminal: owner unavailable")
	}
	terminal, controller := owner.terminal, owner.controller
	owner.terminalRunning = true
	owner.terminalDone = make(chan struct{})
	done := owner.terminalDone
	owner.mu.Unlock()
	defer func() {
		owner.mu.Lock()
		owner.terminalRunning = false
		if owner.terminalDone == done {
			close(done)
			owner.terminalDone = nil
		}
		owner.mu.Unlock()
	}()

	if err := controller.HeartbeatV1(); err != nil {
		return zero, err
	}
	transport, err := formalGLMRegisteredPhase20JobComputePeerBoundV1(controller)
	if err != nil {
		return zero, err
	}
	heartbeatStop := make(chan struct{})
	heartbeatDone := make(chan struct{})
	heartbeatFailure := make(chan error, 1)
	go formalGLMRegisteredPhase20JobComputeHeartbeatV1(
		controller, heartbeatStop, heartbeatDone, heartbeatFailure)
	commit, runErr := formalGLMRegisteredPhase20RunTerminalPeerV1(transport, terminal)
	close(heartbeatStop)
	<-heartbeatDone
	select {
	case heartbeatErr := <-heartbeatFailure:
		if runErr == nil {
			runErr = fmt.Errorf("formal-glm registered Phase20 job terminal: heartbeat failed: %w", heartbeatErr)
		}
	default:
	}
	if runErr != nil {
		return zero, runErr
	}
	return commit, nil
}
