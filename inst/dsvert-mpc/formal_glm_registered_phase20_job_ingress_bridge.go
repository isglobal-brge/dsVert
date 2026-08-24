package main

// This bridge turns the recipient-local, signed Phase18 pending-pair matrix
// into the ingress store consumed by the live Phase20 job. It owns every
// short-lived store handle and derives its MAC key from the already pinned
// pair backend; callers never supply an ingress key or path.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
)

type formalGLMRegisteredPhase20JobIngressBridgeV1 struct {
	mu       sync.Mutex
	record   formalGLMRegisteredPhase19BindingRecordV1
	provider *formalGLMRegisteredPhase19PairKeyProviderV1
	ingress  *formalGLMRegisteredPhase18IngressStoreV3
	tickets  *formalGLMRegisteredPhase18RecipientTicketStoreV1
	pending  *formalGLMRegisteredPhase18PendingPairStoreV1
}

func formalGLMRegisteredPhase20JobIngressBridgeCloneRecordV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
) (formalGLMRegisteredPhase19BindingRecordV1, error) {
	var cloned formalGLMRegisteredPhase19BindingRecordV1
	encoded, err := json.Marshal(record)
	if err != nil {
		return cloned, err
	}
	defer clear(encoded)
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return formalGLMRegisteredPhase19BindingRecordV1{}, err
	}
	return cloned, nil
}

func newFormalGLMRegisteredPhase20JobIngressBridgeV1(
	rockRoot, peer string,
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase20JobIngressBridgeV1, error) {
	clonedRecord, err := formalGLMRegisteredPhase20JobIngressBridgeCloneRecordV1(record)
	if err != nil || formalGLMValidateRegisteredPhase19BindingRecordV1(
		clonedRecord, contract, pins) != nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 job ingress: invalid binding")
	}
	provider, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
		rockRoot, peer, contract, pins)
	if err != nil {
		return nil, err
	}
	bridge := &formalGLMRegisteredPhase20JobIngressBridgeV1{
		record: clonedRecord, provider: provider,
	}
	fail := func(cause error) (*formalGLMRegisteredPhase20JobIngressBridgeV1, error) {
		bridge.Close()
		return nil, cause
	}
	backend, err := provider.DeriveBackendV1(clonedRecord)
	if err != nil {
		return fail(err)
	}
	key, keyErr := formalGLMRegisteredPhase20JobIngressKeyV1(
		backend, clonedRecord, peer)
	clear(backend[:])
	if keyErr != nil {
		return fail(keyErr)
	}
	ingress, err := newFormalGLMRegisteredPhase18IngressStoreV3(
		rockRoot, peer, key, contract,
		clonedRecord.ReceiptSet.GlobalMaterializationRootSHA256, pins)
	clear(key[:])
	if err != nil {
		return fail(err)
	}
	bridge.ingress = ingress
	tickets, err := newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
		rockRoot, contract, pins)
	if err != nil {
		return fail(err)
	}
	bridge.tickets = tickets
	persistedTickets, err := tickets.LoadSet()
	if err != nil || !reflect.DeepEqual(persistedTickets, clonedRecord.RecipientTickets) {
		return fail(fmt.Errorf("formal-glm registered Phase20 job ingress: ticket set mismatch"))
	}
	pending, err := newFormalGLMRegisteredPhase18PendingPairStoreV1(
		rockRoot, peer, contract, pins, tickets)
	if err != nil {
		return fail(err)
	}
	bridge.pending = pending
	provider.mu.Lock()
	providerRoot := provider.root
	provider.mu.Unlock()
	ingress.mu.Lock()
	ingressRoot := ingress.root
	ingress.mu.Unlock()
	tickets.mu.Lock()
	ticketRoot := tickets.root
	tickets.mu.Unlock()
	pending.mu.Lock()
	pendingRoot := pending.root
	pending.mu.Unlock()
	if !formalGLMRegisteredPhase19ScheduleTailSameRootV1(providerRoot, ingressRoot) ||
		!formalGLMRegisteredPhase19ScheduleTailSameRootV1(providerRoot, ticketRoot) ||
		!formalGLMRegisteredPhase19ScheduleTailSameRootV1(providerRoot, pendingRoot) {
		return fail(fmt.Errorf("formal-glm registered Phase20 job ingress: Rock root mismatch"))
	}
	return bridge, nil
}

func (bridge *formalGLMRegisteredPhase20JobIngressBridgeV1) FinalizeV1() (
	[]formalGLMRegisteredPhase18IngressStoreReceiptV3, bool, error,
) {
	if bridge == nil {
		return nil, false, fmt.Errorf("formal-glm registered Phase20 job ingress: unavailable")
	}
	bridge.mu.Lock()
	pending, ingress, record := bridge.pending, bridge.ingress, bridge.record
	bridge.mu.Unlock()
	if pending == nil || ingress == nil {
		return nil, false, fmt.Errorf("formal-glm registered Phase20 job ingress: closed")
	}
	encoded, err := json.Marshal(record.ReceiptSet)
	if err != nil {
		return nil, false, err
	}
	defer clear(encoded)
	return pending.Finalize(encoded, ingress)
}

func (bridge *formalGLMRegisteredPhase20JobIngressBridgeV1) ComputeInputsV1() (
	*formalGLMRegisteredPhase19PairKeyProviderV1,
	*formalGLMRegisteredPhase18IngressStoreV3,
	error,
) {
	if bridge == nil {
		return nil, nil, fmt.Errorf("formal-glm registered Phase20 job ingress: unavailable")
	}
	bridge.mu.Lock()
	provider, ingress := bridge.provider, bridge.ingress
	bridge.mu.Unlock()
	if provider == nil || ingress == nil {
		return nil, nil, fmt.Errorf("formal-glm registered Phase20 job ingress: closed")
	}
	return provider, ingress, nil
}

func (bridge *formalGLMRegisteredPhase20JobIngressBridgeV1) Close() {
	if bridge == nil {
		return
	}
	bridge.mu.Lock()
	pending, tickets := bridge.pending, bridge.tickets
	ingress, provider := bridge.ingress, bridge.provider
	bridge.pending, bridge.tickets = nil, nil
	bridge.ingress, bridge.provider = nil, nil
	bridge.record = formalGLMRegisteredPhase19BindingRecordV1{}
	bridge.mu.Unlock()
	if pending != nil {
		pending.Close()
	}
	if tickets != nil {
		tickets.Close()
	}
	if ingress != nil {
		ingress.Close()
	}
	if provider != nil {
		provider.Close()
	}
}
