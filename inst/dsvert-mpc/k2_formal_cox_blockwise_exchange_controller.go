package main

// Controller for one live, source-bound Cox worker step. It owns the source
// bridge and the sole segmented spool until the sealed local receipt is
// recorded. An authenticated process/controller layer must establish the
// matching remote public root before calling Start; this private type neither
// accepts wire JSON nor restarts a burned worker attempt.

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
	"sync"
)

type formalCoxBlockwiseExchangeController struct {
	mu sync.Mutex

	bridge    *formalCoxBlockwiseSourceBridge
	transport *formalCoxBlockwiseExchangeTransport
	plan      formalCoxBlockwisePlan
	peer      string

	started   bool
	running   bool
	committed bool
	closed    bool
	receipt   formalCoxBlockwiseStepReceipt
	runErr    error
}

func newFormalCoxBlockwiseExchangeController(bridge *formalCoxBlockwiseSourceBridge,
	lease *formalCoxBlockwiseExchangeLease,
) (*formalCoxBlockwiseExchangeController, error) {
	if bridge == nil {
		return nil, fmt.Errorf("formal-cox: exchange controller bridge is unavailable")
	}
	bridge.mu.Lock()
	plan, peer := bridge.plan, bridge.peer
	valid := !bridge.closed && bridge.source != nil && bridge.worker != nil &&
		len(bridge.signingKey) == ed25519.PrivateKeySize
	bridge.mu.Unlock()
	if _, err := formalCoxBlockwiseValidateShape(plan); !valid || err != nil {
		return nil, fmt.Errorf("formal-cox: exchange controller bridge is invalid")
	}
	transport, err := newFormalCoxBlockwiseExchangeTransport(lease, plan, peer)
	if err != nil {
		return nil, err
	}
	return &formalCoxBlockwiseExchangeController{
		bridge: bridge, transport: transport, plan: plan, peer: peer,
	}, nil
}

func (controller *formalCoxBlockwiseExchangeController) BindPeer(peer string) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.started || controller.transport == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	return controller.transport.BindPeer(peer)
}

// PublicInputRoot computes only the source's signed public commitment. The
// caller must establish equality with the opposite compute role through its
// authenticated control channel before passing that common value to Start.
func (controller *formalCoxBlockwiseExchangeController) PublicInputRoot(
	step formalCoxBlockwiseWorkerStep,
) (string, error) {
	if controller == nil {
		return "", fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.started || controller.transport == nil ||
		!controller.transport.peerBound {
		return "", fmt.Errorf("formal-cox: exchange controller is not peer-bound")
	}
	return controller.bridge.PublicInputRoot(step)
}

func (controller *formalCoxBlockwiseExchangeController) Start(
	step formalCoxBlockwiseWorkerStep, attempt, master [32]byte, pairedRoot string,
) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.started || controller.transport == nil ||
		!controller.transport.peerBound {
		return fmt.Errorf("formal-cox: exchange controller is not peer-bound")
	}
	bound, err := controller.bridge.BeginAttempt(step, attempt, pairedRoot)
	if err != nil {
		return err
	}
	session, err := formalCoxBlockwiseWorkerSession(
		controller.plan, bound, attempt, master)
	if err != nil {
		return err
	}
	controller.started, controller.running = true, true
	bridge, transport := controller.bridge, controller.transport
	go func() {
		receipt, runErr := bridge.RunPendingWorkerStep(transport, session)
		controller.mu.Lock()
		defer controller.mu.Unlock()
		controller.running = false
		controller.receipt, controller.runErr = receipt, runErr
	}()
	return nil
}

func (controller *formalCoxBlockwiseExchangeController) Poll(ack int64) (
	*formalCoxBlockwiseExchangeChunk, int64, error,
) {
	if controller == nil {
		return nil, 0, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	transport := controller.transport
	valid := !controller.closed && controller.started && transport != nil
	controller.mu.Unlock()
	if !valid {
		return nil, 0, fmt.Errorf("formal-cox: exchange controller is not running")
	}
	return transport.Poll(ack)
}

func (controller *formalCoxBlockwiseExchangeController) Relay(
	chunk formalCoxBlockwiseExchangeChunk,
) (int64, error) {
	if controller == nil {
		return 0, fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	transport := controller.transport
	valid := !controller.closed && controller.started && transport != nil
	controller.mu.Unlock()
	if !valid {
		return 0, fmt.Errorf("formal-cox: exchange controller is not running")
	}
	return transport.Relay(chunk)
}

func (controller *formalCoxBlockwiseExchangeController) Result() (
	formalCoxBlockwiseStepReceipt, bool, error,
) {
	if controller == nil {
		return formalCoxBlockwiseStepReceipt{}, false,
			fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed {
		return formalCoxBlockwiseStepReceipt{}, false,
			fmt.Errorf("formal-cox: exchange controller is closed")
	}
	if !controller.started || controller.running {
		return formalCoxBlockwiseStepReceipt{}, false, nil
	}
	if controller.runErr != nil {
		return formalCoxBlockwiseStepReceipt{}, true, controller.runErr
	}
	return controller.receipt, true, nil
}

func (controller *formalCoxBlockwiseExchangeController) Commit(
	receipts []formalCoxBlockwiseStepReceipt, pins map[string]ed25519.PublicKey,
) error {
	if controller == nil {
		return fmt.Errorf("formal-cox: exchange controller is unavailable")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || !controller.started || controller.running ||
		controller.runErr != nil || controller.committed {
		return fmt.Errorf("formal-cox: exchange controller cannot commit")
	}
	matched := false
	for _, receipt := range receipts {
		if reflect.DeepEqual(receipt, controller.receipt) {
			matched = true
		}
	}
	if !matched {
		return fmt.Errorf("formal-cox: exchange controller commit omits local receipt")
	}
	if err := controller.bridge.worker.CommitPending(receipts, pins); err != nil {
		return err
	}
	controller.committed = true
	return nil
}

func (controller *formalCoxBlockwiseExchangeController) Close() error {
	if controller == nil {
		return nil
	}
	controller.mu.Lock()
	if controller.closed {
		controller.mu.Unlock()
		return nil
	}
	controller.closed = true
	transport, bridge := controller.transport, controller.bridge
	controller.transport, controller.bridge = nil, nil
	controller.mu.Unlock()
	var transportErr error
	if transport != nil {
		transportErr = transport.Close()
	}
	if bridge != nil {
		if err := bridge.Close(); transportErr == nil {
			transportErr = err
		}
	}
	return transportErr
}
