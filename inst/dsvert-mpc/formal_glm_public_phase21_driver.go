package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"sync"
)

// formalGLMPublicPhase21TerminalDriverV1 is the durable, read-only endpoint
// continuation for a Phase21 release which has already completed in Rock. It
// deliberately has no action, relay, source, or secret input: the only
// successful outcome is the independently revalidated public terminal.
type formalGLMPublicPhase21TerminalDriverV1 struct {
	mu sync.Mutex

	root     string
	rootInfo os.FileInfo
	contract formalGLMPhase21SamplerV2Contract
	pins     map[string]ed25519.PublicKey
	closed   bool
}

func newFormalGLMPublicPhase21TerminalDriverV1(
	root string,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
) (*formalGLMPublicPhase21TerminalDriverV1, error) {
	if formalGLMPhase21ValidateSamplerV2Contract(contract, pins) != nil {
		return nil, fmt.Errorf("formal-glm public Phase21 driver: invalid contract")
	}
	opened, err := formalGLMPhase21RockOpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("formal-glm public Phase21 driver: invalid Rock root")
	}
	rootInfo, statErr := opened.Stat(".")
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil || rootInfo == nil {
		return nil, fmt.Errorf("formal-glm public Phase21 driver: Rock root close failed")
	}
	clonedContract, cloneErr := formalGLMRegisteredPhase20TerminalCloneV1(contract)
	if cloneErr != nil {
		return nil, fmt.Errorf("formal-glm public Phase21 driver: contract clone failed")
	}
	return &formalGLMPublicPhase21TerminalDriverV1{
		root: root, rootInfo: rootInfo, contract: clonedContract,
		pins: formalGLMRegisteredPhase20TerminalClonePinsV1(pins),
	}, nil
}

func (driver *formalGLMPublicPhase21TerminalDriverV1) AdvanceV1(
	context formalGLMPublicAdvanceContextV1,
) (formalGLMPublicAdvanceObservationV1, error) {
	var zero formalGLMPublicAdvanceObservationV1
	if driver == nil {
		return zero, fmt.Errorf("formal-glm public Phase21 driver: unavailable")
	}
	driver.mu.Lock()
	if driver.closed {
		driver.mu.Unlock()
		return zero, fmt.Errorf("formal-glm public Phase21 driver: closed")
	}
	root, rootInfo := driver.root, driver.rootInfo
	contract, cloneErr := formalGLMRegisteredPhase20TerminalCloneV1(driver.contract)
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(driver.pins)
	driver.mu.Unlock()
	defer formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
	if cloneErr != nil {
		return zero, fmt.Errorf("formal-glm public Phase21 driver: contract clone failed")
	}
	opened, openErr := formalGLMPhase21RockOpenRoot(root)
	if openErr != nil {
		return zero, fmt.Errorf("formal-glm public Phase21 driver: Rock root unavailable")
	}
	currentInfo, statErr := opened.Stat(".")
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil || currentInfo == nil || rootInfo == nil ||
		!os.SameFile(rootInfo, currentInfo) {
		return zero, fmt.Errorf("formal-glm public Phase21 driver: Rock root changed")
	}
	terminal, err := formalGLMPhase21RockLoadPublicTerminalEvidenceV1(
		root, contract, pins, context.Resolution)
	if err != nil {
		return zero, fmt.Errorf("formal-glm public Phase21 driver: terminal unavailable")
	}
	return formalGLMPublicAdvanceObservationV1{Terminal: &terminal}, nil
}

func (driver *formalGLMPublicPhase21TerminalDriverV1) Close() {
	if driver == nil {
		return
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.closed {
		return
	}
	driver.closed = true
	driver.root = ""
	driver.rootInfo = nil
	driver.contract = formalGLMPhase21SamplerV2Contract{}
	formalGLMRegisteredPhase20TerminalClearPinsV1(driver.pins)
	driver.pins = nil
}
