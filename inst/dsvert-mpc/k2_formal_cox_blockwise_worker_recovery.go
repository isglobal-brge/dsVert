package main

// Recovery for the narrow crash boundary after a Cox worker has sealed its
// local output and before the two signed receipts cross the commit barrier.
// It deliberately never opens an exact-GC lease or spool: that lease remains
// burned, and recovery may only replay the already sealed receipt or commit
// the exact K=2 receipt pair.

import (
	"crypto/ed25519"
	"fmt"
	"sync"
)

type formalCoxBlockwiseWorkerRecovery struct {
	mu          sync.Mutex
	bridge      *formalCoxBlockwiseSourceBridge
	closeSource func()
}

func openFormalCoxBlockwiseWorkerRecoveryAtRoot(encoded []byte, stateRoot string,
	production bool,
) (*formalCoxBlockwiseWorkerRecovery, error) {
	command, err := formalCoxBlockwiseWorkerBootstrapDecodeCommand(encoded)
	if err != nil {
		return nil, err
	}
	source, closeSource, err := formalCoxBlockwiseSourceImportOpen(
		command.Source, stateRoot, production)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			closeSource()
		}
	}()
	canonicalDelivery, err := command.Source.Delivery.Encode(source.session)
	if err != nil {
		return nil, err
	}
	defer clear(canonicalDelivery)
	if _, err := source.AcceptDelivery(canonicalDelivery); err != nil {
		return nil, err
	}
	source.mu.Lock()
	planSHA, peer := source.session.context.planSHA256, source.recipient
	secret := append([]byte(nil), source.recipientSK...)
	source.mu.Unlock()
	defer clear(secret)
	checkpointDir, _, err := formalCoxBlockwiseWorkerBootstrapPaths(
		stateRoot, production, planSHA, peer)
	if err != nil {
		return nil, err
	}
	workerKey, err := formalCoxBlockwiseWorkerCheckpointKey(
		secret, planSHA, peer)
	if err != nil {
		return nil, err
	}
	defer clear(workerKey[:])
	signer, err := formalCoxBlockwiseSourceProducerCommandDecodeKey(
		command.Source.RecipientSigningKey)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	bridge, err := newFormalCoxBlockwiseSourceBridgeFromOpenStore(
		source, checkpointDir, workerKey, signer)
	if err != nil {
		return nil, err
	}
	state, err := bridge.worker.Load()
	if err != nil || state.Pending == nil || !state.Pending.OutputRecorded ||
		state.Pending.AttemptID != command.AttemptID {
		_ = bridge.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("formal-cox: no sealed worker receipt requires recovery")
	}
	closeOnError = false
	return &formalCoxBlockwiseWorkerRecovery{
		bridge: bridge, closeSource: closeSource,
	}, nil
}

func (recovery *formalCoxBlockwiseWorkerRecovery) PendingReceiptV1() (
	formalCoxBlockwiseStepReceipt, error,
) {
	if recovery == nil {
		return formalCoxBlockwiseStepReceipt{},
			fmt.Errorf("formal-cox: worker recovery is unavailable")
	}
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	bridge := recovery.bridge
	if bridge == nil {
		return formalCoxBlockwiseStepReceipt{},
			fmt.Errorf("formal-cox: worker recovery is closed")
	}
	bridge.mu.Lock()
	if bridge.closed || bridge.worker == nil ||
		len(bridge.signingKey) != ed25519.PrivateKeySize {
		bridge.mu.Unlock()
		return formalCoxBlockwiseStepReceipt{},
			fmt.Errorf("formal-cox: worker recovery is unavailable")
	}
	worker := bridge.worker
	signingKey := append(ed25519.PrivateKey(nil), bridge.signingKey...)
	bridge.mu.Unlock()
	defer clear(signingKey)
	return worker.PendingReceipt(signingKey)
}

// CommitV1 validates the receipt pair against the pins carried by the
// recipient-local signed source session. Callers cannot select a pinset or a
// checkpoint path while recovering a sealed result.
func (recovery *formalCoxBlockwiseWorkerRecovery) CommitV1(
	receipts []formalCoxBlockwiseStepReceipt,
) error {
	if recovery == nil {
		return fmt.Errorf("formal-cox: worker recovery is unavailable")
	}
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	bridge := recovery.bridge
	if bridge == nil {
		return fmt.Errorf("formal-cox: worker recovery is closed")
	}
	bridge.mu.Lock()
	if bridge.closed || bridge.worker == nil || bridge.source == nil {
		bridge.mu.Unlock()
		return fmt.Errorf("formal-cox: worker recovery is unavailable")
	}
	worker, source := bridge.worker, bridge.source
	source.mu.Lock()
	if source.closed || source.session == nil || source.session.context == nil {
		source.mu.Unlock()
		bridge.mu.Unlock()
		return fmt.Errorf("formal-cox: worker recovery source is unavailable")
	}
	pins := make(map[string]ed25519.PublicKey, len(source.session.context.pins))
	for peer, pin := range source.session.context.pins {
		pins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	source.mu.Unlock()
	bridge.mu.Unlock()
	defer func() {
		for peer := range pins {
			clear(pins[peer])
		}
	}()
	return worker.CommitPending(receipts, pins)
}

func (recovery *formalCoxBlockwiseWorkerRecovery) Close() error {
	if recovery == nil {
		return nil
	}
	recovery.mu.Lock()
	bridge, closeSource := recovery.bridge, recovery.closeSource
	recovery.bridge, recovery.closeSource = nil, nil
	recovery.mu.Unlock()
	var result error
	if bridge != nil {
		result = bridge.Close()
	}
	if closeSource != nil {
		closeSource()
	}
	return result
}
