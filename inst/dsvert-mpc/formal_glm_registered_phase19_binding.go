package main

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
	formalGLMRegisteredPhase19BindingVersion = "dsvert-formal-glm-registered-phase19-binding-v1"
	formalGLMRegisteredPhase19BindingPurpose = "formal_glm_registered_phase19_execution_binding_v1"
	formalGLMRegisteredPhase19BindingDomain  = "dsVert/formal-glm/registered-phase19/binding/v1"

	formalGLMRegisteredPhase19BindingRecordVersion = "dsvert-formal-glm-registered-phase19-binding-record-v1"
	formalGLMRegisteredPhase19BindingRecordPurpose = "formal_glm_registered_phase19_restart_record_v1"
	formalGLMRegisteredPhase19BindingRecordDir     = "registered-phase19-bindings-v1"
	formalGLMRegisteredPhase19BindingMaxRecord     = formalGLMRegisteredPhase18ReceiptSetMaxJSON +
		2*formalGLMRegisteredPhase18TicketMaxJSON + (2 << 20)
)

type formalGLMRegisteredPhase19RecipientBindingV1 struct {
	RecipientName         string `json:"recipient_name"`
	RecipientTicketSHA256 string `json:"recipient_ticket_sha256"`
}

type formalGLMRegisteredPhase19BindingV1 struct {
	Version string `json:"version"`
	Purpose string `json:"purpose"`

	ArtifactID                      string                                         `json:"artifact_id"`
	SourceContractCoreSHA256        string                                         `json:"source_contract_core_sha256"`
	SourceContractSHA256            string                                         `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256   string                                         `json:"registered_execution_plan_sha256"`
	PinsetSHA256                    string                                         `json:"pinset_sha256"`
	ReceiptSetSHA256                string                                         `json:"receipt_set_sha256"`
	GlobalMaterializationRootSHA256 string                                         `json:"global_materialization_root_sha256"`
	RecipientBindings               []formalGLMRegisteredPhase19RecipientBindingV1 `json:"recipient_bindings"`
	CustodianCount                  int                                            `json:"custodian_count"`
	CustodianPeers                  []string                                       `json:"custodian_peers"`
	DesignatedComputePeers          []string                                       `json:"designated_compute_peers"`
	Geometry                        formalGLMRegisteredPhase18GeometryV1           `json:"geometry"`
	SemanticRootSHA256              string                                         `json:"semantic_root_sha256"`
}

type formalGLMRegisteredPhase19SemanticInputV1 struct {
	Version string `json:"version"`
	Purpose string `json:"purpose"`

	ArtifactID                      string                                         `json:"artifact_id"`
	SourceContractCoreSHA256        string                                         `json:"source_contract_core_sha256"`
	SourceContractSHA256            string                                         `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256   string                                         `json:"registered_execution_plan_sha256"`
	PinsetSHA256                    string                                         `json:"pinset_sha256"`
	ReceiptSetSHA256                string                                         `json:"receipt_set_sha256"`
	GlobalMaterializationRootSHA256 string                                         `json:"global_materialization_root_sha256"`
	RecipientBindings               []formalGLMRegisteredPhase19RecipientBindingV1 `json:"recipient_bindings"`
	CustodianCount                  int                                            `json:"custodian_count"`
	CustodianPeers                  []string                                       `json:"custodian_peers"`
	DesignatedComputePeers          []string                                       `json:"designated_compute_peers"`
	Geometry                        formalGLMRegisteredPhase18GeometryV1           `json:"geometry"`
}

type formalGLMRegisteredPhase19BindingRecordV1 struct {
	Version          string                                        `json:"version"`
	Purpose          string                                        `json:"purpose"`
	Binding          formalGLMRegisteredPhase19BindingV1           `json:"binding"`
	ReceiptSet       formalGLMRegisteredPhase18ReceiptSetV1        `json:"receipt_set"`
	RecipientTickets []formalGLMRegisteredPhase18RecipientTicketV1 `json:"recipient_tickets"`
}

func formalGLMRegisteredPhase19CloneTicketV1(
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
) formalGLMRegisteredPhase18RecipientTicketV1 {
	cloned := ticket
	cloned.TransportPK = append([]byte(nil), ticket.TransportPK...)
	cloned.DesignatedComputePeers = append(
		[]string(nil), ticket.DesignatedComputePeers...)
	cloned.Signature = append([]byte(nil), ticket.Signature...)
	return cloned
}

func formalGLMRegisteredPhase19SemanticRootV1(
	binding formalGLMRegisteredPhase19BindingV1,
) (string, error) {
	if binding.Version != formalGLMRegisteredPhase19BindingVersion ||
		binding.Purpose != formalGLMRegisteredPhase19BindingPurpose {
		return "", fmt.Errorf("formal-glm registered Phase19: invalid binding identity")
	}
	input := formalGLMRegisteredPhase19SemanticInputV1{
		Version:                         binding.Version,
		Purpose:                         binding.Purpose,
		ArtifactID:                      binding.ArtifactID,
		SourceContractCoreSHA256:        binding.SourceContractCoreSHA256,
		SourceContractSHA256:            binding.SourceContractSHA256,
		RegisteredExecutionPlanSHA256:   binding.RegisteredExecutionPlanSHA256,
		PinsetSHA256:                    binding.PinsetSHA256,
		ReceiptSetSHA256:                binding.ReceiptSetSHA256,
		GlobalMaterializationRootSHA256: binding.GlobalMaterializationRootSHA256,
		RecipientBindings: append(
			[]formalGLMRegisteredPhase19RecipientBindingV1(nil),
			binding.RecipientBindings...),
		CustodianCount: binding.CustodianCount,
		CustodianPeers: append([]string(nil), binding.CustodianPeers...),
		DesignatedComputePeers: append(
			[]string(nil), binding.DesignatedComputePeers...),
		Geometry: binding.Geometry,
	}
	input.Geometry.CoordinateOwners = append(
		[]string(nil), binding.Geometry.CoordinateOwners...)
	return formalGLMPhase21StickyHash(
		formalGLMRegisteredPhase19BindingDomain+"/semantic-root", input)
}

func formalGLMRegisteredPhase19ProjectBindingV1(
	contract formalGLMSourceContractV1,
	receiptSet formalGLMRegisteredPhase18ReceiptSetV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase19BindingV1,
	[]formalGLMRegisteredPhase18RecipientTicketV1, error,
) {
	var zero formalGLMRegisteredPhase19BindingV1
	if err := formalGLMValidateSourceContractV1(contract, pins); err != nil {
		return zero, nil, err
	}
	if err := formalGLMRegisteredPhase18ValidateReceiptSetV1(
		receiptSet, contract, pins); err != nil {
		return zero, nil, err
	}
	orderedTickets, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		tickets, contract, pins)
	if err != nil {
		return zero, nil, err
	}
	for index := range orderedTickets {
		orderedTickets[index] = formalGLMRegisteredPhase19CloneTicketV1(
			orderedTickets[index])
	}

	plan := contract.Core.RegisteredExecutionPlan
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || pinsetSHA256 != plan.PinsetSHA256 {
		return zero, nil,
			fmt.Errorf("formal-glm registered Phase19: pinset mismatch")
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(contract)
	if err != nil {
		return zero, nil, err
	}
	authorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		contract, plan.CustodianPeers[0], pins)
	if err != nil {
		return zero, nil, err
	}

	recipientBindings := make(
		[]formalGLMRegisteredPhase19RecipientBindingV1, len(orderedTickets))
	for index, ticket := range orderedTickets {
		ticketSHA256, hashErr :=
			formalGLMRegisteredPhase18RecipientTicketSHA256V1(ticket)
		if hashErr != nil {
			return zero, nil, hashErr
		}
		recipientBindings[index] =
			formalGLMRegisteredPhase19RecipientBindingV1{
				RecipientName:         ticket.RecipientName,
				RecipientTicketSHA256: ticketSHA256,
			}
	}
	binding := formalGLMRegisteredPhase19BindingV1{
		Version:                         formalGLMRegisteredPhase19BindingVersion,
		Purpose:                         formalGLMRegisteredPhase19BindingPurpose,
		ArtifactID:                      contract.Core.ArtifactID,
		SourceContractCoreSHA256:        contract.CoreSHA256,
		SourceContractSHA256:            contractSHA256,
		RegisteredExecutionPlanSHA256:   plan.PlanSHA256,
		PinsetSHA256:                    pinsetSHA256,
		ReceiptSetSHA256:                receiptSet.ReceiptSetSHA256,
		GlobalMaterializationRootSHA256: receiptSet.GlobalMaterializationRootSHA256,
		RecipientBindings:               recipientBindings,
		CustodianCount:                  plan.CustodianCount,
		CustodianPeers: append(
			[]string(nil), plan.CustodianPeers...),
		DesignatedComputePeers: append(
			[]string(nil), plan.DesignatedComputePeers...),
		Geometry: authorization.Geometry,
	}
	binding.Geometry.CoordinateOwners = append(
		[]string(nil), authorization.Geometry.CoordinateOwners...)
	binding.SemanticRootSHA256, err =
		formalGLMRegisteredPhase19SemanticRootV1(binding)
	if err != nil {
		return zero, nil, err
	}
	return binding, orderedTickets, nil
}

func formalGLMBuildRegisteredPhase19BindingV1(
	contract formalGLMSourceContractV1,
	receiptSet formalGLMRegisteredPhase18ReceiptSetV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase19BindingV1, error) {
	binding, _, err := formalGLMRegisteredPhase19ProjectBindingV1(
		contract, receiptSet, tickets, pins)
	return binding, err
}

func formalGLMValidateRegisteredPhase19BindingV1(
	binding formalGLMRegisteredPhase19BindingV1,
	contract formalGLMSourceContractV1,
	receiptSet formalGLMRegisteredPhase18ReceiptSetV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	pins map[string]ed25519.PublicKey,
) error {
	expected, _, err := formalGLMRegisteredPhase19ProjectBindingV1(
		contract, receiptSet, tickets, pins)
	if err != nil || !reflect.DeepEqual(binding, expected) {
		return fmt.Errorf("formal-glm registered Phase19: binding differs from evidence")
	}
	return nil
}

func formalGLMValidateRegisteredPhase19BindingRecordV1(
	record formalGLMRegisteredPhase19BindingRecordV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) error {
	expected, orderedTickets, err :=
		formalGLMRegisteredPhase19ProjectBindingV1(
			contract, record.ReceiptSet, record.RecipientTickets, pins)
	if record.Version != formalGLMRegisteredPhase19BindingRecordVersion ||
		record.Purpose != formalGLMRegisteredPhase19BindingRecordPurpose ||
		err != nil || !reflect.DeepEqual(record.Binding, expected) ||
		!reflect.DeepEqual(record.RecipientTickets, orderedTickets) {
		return fmt.Errorf("formal-glm registered Phase19 store: invalid restart record")
	}
	return nil
}

type formalGLMRegisteredPhase19BindingStoreV1 struct {
	mu       sync.Mutex
	root     *os.Root
	contract formalGLMSourceContractV1
	pins     map[string]ed25519.PublicKey
}

func formalGLMRegisteredPhase19OpenRockRootV1(
	rockRoot string,
) (*os.Root, error) {
	if !filepath.IsAbs(rockRoot) || filepath.Clean(rockRoot) != rockRoot {
		return nil, fmt.Errorf("formal-glm registered Phase19 store: invalid Rock root")
	}
	if info, err := os.Lstat(rockRoot); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) {
			return nil, fmt.Errorf("formal-glm registered Phase19 store: unsafe Rock root")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else {
		if err := os.MkdirAll(rockRoot, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(rockRoot, 0o700); err != nil {
			return nil, err
		}
	}
	rootInfo, err := os.Lstat(rockRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		rootInfo.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(rootInfo) {
		return nil, fmt.Errorf("formal-glm registered Phase19 store: unsafe Rock root")
	}
	resolved, err := filepath.EvalSymlinks(rockRoot)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, fmt.Errorf("formal-glm registered Phase19 store: redirected Rock root")
	}
	root, err := os.OpenRoot(filepath.Clean(resolved))
	if err != nil {
		return nil, err
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedInfo) ||
		openedInfo.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(openedInfo) {
		_ = root.Close()
		return nil, fmt.Errorf("formal-glm registered Phase19 store: Rock root changed while opening")
	}
	return root, nil
}

func newFormalGLMRegisteredPhase19BindingStoreV1(
	rockRoot string,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase19BindingStoreV1, error) {
	if err := formalGLMValidateSourceContractV1(contract, pins); err != nil {
		return nil, err
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}
	clonedContract, err := formalGLMDecodeSourceContractV1(contractJSON, pins)
	if err != nil {
		return nil, err
	}
	root, err := formalGLMRegisteredPhase19OpenRockRootV1(rockRoot)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase21EnsureRootPrivateDir(
		root, formalGLMRegisteredPhase19BindingRecordDir); err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return &formalGLMRegisteredPhase19BindingStoreV1{
		root: root, contract: clonedContract, pins: clonedPins,
	}, nil
}

func (store *formalGLMRegisteredPhase19BindingStoreV1) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	for peer := range store.pins {
		clear(store.pins[peer])
		delete(store.pins, peer)
	}
}

func (store *formalGLMRegisteredPhase19BindingStoreV1) recordRelativePathLocked(
	artifactID, receiptSetSHA256 string,
	create bool,
) (string, error) {
	if store == nil || store.root == nil ||
		artifactID != store.contract.Core.ArtifactID ||
		!formalGLMIsSHA256(artifactID) ||
		!formalGLMIsSHA256(receiptSetSHA256) {
		return "", fmt.Errorf("formal-glm registered Phase19 store: invalid record key")
	}
	rootInfo, err := store.root.Stat(".")
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(rootInfo) {
		return "", fmt.Errorf("formal-glm registered Phase19 store: unsafe Rock root")
	}
	shard := filepath.Join(formalGLMRegisteredPhase19BindingRecordDir,
		artifactID[:2], artifactID[2:4])
	if create {
		err = formalGLMPhase21EnsureRootPrivateDir(store.root, shard)
	} else {
		err = formalGLMPhase21ValidateRootPrivateDir(store.root, shard, false)
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(shard,
		"binding-"+artifactID+"-"+receiptSetSHA256+".json"), nil
}

func (store *formalGLMRegisteredPhase19BindingStoreV1) decodeRecordLocked(
	encoded []byte,
	artifactID, receiptSetSHA256 string,
) (formalGLMRegisteredPhase19BindingRecordV1, error) {
	var record formalGLMRegisteredPhase19BindingRecordV1
	if err := formalGLMPhase21RockStrictDecode(encoded, &record); err != nil ||
		record.Binding.ArtifactID != artifactID ||
		record.Binding.ReceiptSetSHA256 != receiptSetSHA256 ||
		formalGLMValidateRegisteredPhase19BindingRecordV1(
			record, store.contract, store.pins) != nil {
		return formalGLMRegisteredPhase19BindingRecordV1{},
			fmt.Errorf("formal-glm registered Phase19 store: invalid persisted record")
	}
	return record, nil
}

func (store *formalGLMRegisteredPhase19BindingStoreV1) Commit(
	receiptSet formalGLMRegisteredPhase18ReceiptSetV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) (formalGLMRegisteredPhase19BindingRecordV1, bool, error) {
	var zero formalGLMRegisteredPhase19BindingRecordV1
	if store == nil {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase19 store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase19 store: closed")
	}
	binding, orderedTickets, err :=
		formalGLMRegisteredPhase19ProjectBindingV1(
			store.contract, receiptSet, tickets, store.pins)
	if err != nil {
		return zero, false, err
	}
	record := formalGLMRegisteredPhase19BindingRecordV1{
		Version: formalGLMRegisteredPhase19BindingRecordVersion,
		Purpose: formalGLMRegisteredPhase19BindingRecordPurpose,
		Binding: binding, ReceiptSet: receiptSet,
		RecipientTickets: orderedTickets,
	}
	if err := formalGLMValidateRegisteredPhase19BindingRecordV1(
		record, store.contract, store.pins); err != nil {
		return zero, false, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > formalGLMRegisteredPhase19BindingMaxRecord {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase19 store: invalid record size")
	}
	relative, err := store.recordRelativePathLocked(
		binding.ArtifactID, binding.ReceiptSetSHA256, true)
	if err != nil {
		return zero, false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(
		store.root, relative, encoded)
	if err != nil {
		return zero, false, err
	}
	persisted, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMRegisteredPhase19BindingMaxRecord)
	if err != nil {
		return zero, false, err
	}
	if !bytes.Equal(persisted, encoded) {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase19 store: CAS conflict")
	}
	decoded, err := store.decodeRecordLocked(
		persisted, binding.ArtifactID, binding.ReceiptSetSHA256)
	if err != nil {
		return zero, false, err
	}
	return decoded, !created, nil
}

func (store *formalGLMRegisteredPhase19BindingStoreV1) Load(
	artifactID, receiptSetSHA256 string,
) (formalGLMRegisteredPhase19BindingRecordV1, error) {
	var zero formalGLMRegisteredPhase19BindingRecordV1
	if store == nil {
		return zero,
			fmt.Errorf("formal-glm registered Phase19 store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, fmt.Errorf("formal-glm registered Phase19 store: closed")
	}
	relative, err := store.recordRelativePathLocked(
		artifactID, receiptSetSHA256, false)
	if err != nil {
		return zero, err
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, relative, formalGLMRegisteredPhase19BindingMaxRecord)
	if err != nil {
		return zero, err
	}
	return store.decodeRecordLocked(encoded, artifactID, receiptSetSHA256)
}
