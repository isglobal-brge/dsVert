package main

// Durable, Rock-local CAS for the two recipient tickets authorized by a
// sealed registered SourceContract. The record contains the signed ticket so
// restart validation is self-contained; the returned receipt contains hashes
// only and is safe to use as routing evidence.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

const (
	formalGLMRegisteredPhase18RecipientTicketRecordVersionV1  = "dsvert-formal-glm-registered-phase18-recipient-ticket-record-v1"
	formalGLMRegisteredPhase18RecipientTicketRecordPurposeV1  = "formal_glm_registered_phase18_recipient_ticket_record_v1"
	formalGLMRegisteredPhase18RecipientTicketReceiptVersionV1 = "dsvert-formal-glm-registered-phase18-recipient-ticket-receipt-v1"
	formalGLMRegisteredPhase18RecipientTicketReceiptPurposeV1 = "formal_glm_registered_phase18_recipient_ticket_receipt_v1"

	formalGLMRegisteredPhase18RecipientTicketRecordDirV1 = "formal-glm-registered-phase18-recipient-tickets-v1"
	formalGLMRegisteredPhase18RecipientTicketRecordMaxV1 = int64(128 << 10)
)

type formalGLMRegisteredPhase18RecipientTicketRecordV1 struct {
	Version                       string                                      `json:"version"`
	Purpose                       string                                      `json:"purpose"`
	ArtifactID                    string                                      `json:"artifact_id"`
	SourceContractCoreSHA256      string                                      `json:"source_contract_core_sha256"`
	SourceContractSHA256          string                                      `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string                                      `json:"registered_execution_plan_sha256"`
	PinsetSHA256                  string                                      `json:"pinset_sha256"`
	RecipientName                 string                                      `json:"recipient_name"`
	RecipientTicketSHA256         string                                      `json:"recipient_ticket_sha256"`
	Ticket                        formalGLMRegisteredPhase18RecipientTicketV1 `json:"ticket"`
	ProductionReady               bool                                        `json:"production_ready"`
}

// formalGLMRegisteredPhase18RecipientTicketReceiptV1 intentionally carries no
// filesystem path, key material, transport key, signature, or ticket payload.
type formalGLMRegisteredPhase18RecipientTicketReceiptV1 struct {
	Version                       string `json:"version"`
	Purpose                       string `json:"purpose"`
	ArtifactID                    string `json:"artifact_id"`
	SourceContractCoreSHA256      string `json:"source_contract_core_sha256"`
	SourceContractSHA256          string `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256 string `json:"registered_execution_plan_sha256"`
	PinsetSHA256                  string `json:"pinset_sha256"`
	RecipientName                 string `json:"recipient_name"`
	RecipientTicketSHA256         string `json:"recipient_ticket_sha256"`
	ProductionReady               bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase18RecipientTicketStoreV1 struct {
	mu      sync.Mutex
	root    *os.Root
	context formalGLMRegisteredPhase18ProvenanceContextV1
}

func formalGLMRegisteredPhase18TicketStoreValidateRootV1(root *os.Root) error {
	if root == nil {
		return fmt.Errorf("formal-glm registered Phase18 ticket store: unavailable Rock root")
	}
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return fmt.Errorf("formal-glm registered Phase18 ticket store: unsafe Rock root")
	}
	return nil
}

func formalGLMRegisteredPhase18TicketStoreOpenRootV1(
	rockRoot string,
) (*os.Root, error) {
	if !filepath.IsAbs(rockRoot) || filepath.Clean(rockRoot) != rockRoot {
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: invalid Rock root")
	}
	existed := false
	if info, err := os.Lstat(rockRoot); err == nil {
		existed = true
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) {
			return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: unsafe Rock root")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else if err := os.MkdirAll(rockRoot, 0o700); err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(rockRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(rootInfo) ||
		(existed && rootInfo.Mode().Perm() != 0o700) {
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: unsafe Rock root")
	}
	resolved, err := filepath.EvalSymlinks(rockRoot)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: redirected Rock root")
	}
	root, err := os.OpenRoot(filepath.Clean(resolved))
	if err != nil {
		return nil, err
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedInfo) ||
		!openedInfo.IsDir() ||
		!formalFinalizerHandoffPrivateOwnedDirectory(openedInfo) {
		_ = root.Close()
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: Rock root changed while opening")
	}
	if !existed {
		if err := root.Chmod(".", 0o700); err != nil {
			_ = root.Close()
			return nil, err
		}
	}
	if err := formalGLMRegisteredPhase18TicketStoreValidateRootV1(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func formalGLMRegisteredPhase18TicketStoreValidateDirV1(root *os.Root,
	name string,
) error {
	if err := formalGLMRegisteredPhase18TicketStoreValidateRootV1(root); err != nil {
		return err
	}
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name {
		return fmt.Errorf("formal-glm registered Phase18 ticket store: invalid durable directory")
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("formal-glm registered Phase18 ticket store: invalid durable directory")
		}
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) {
			return fmt.Errorf("formal-glm registered Phase18 ticket store: unsafe durable directory")
		}
	}
	return nil
}

func formalGLMRegisteredPhase18TicketStoreEnsureDirV1(root *os.Root,
	name string,
) error {
	if err := formalGLMRegisteredPhase18TicketStoreValidateRootV1(root); err != nil ||
		name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name {
		return fmt.Errorf("formal-glm registered Phase18 ticket store: invalid durable directory")
	}
	if err := root.MkdirAll(name, 0o700); err != nil {
		return err
	}
	return formalGLMRegisteredPhase18TicketStoreValidateDirV1(root, name)
}

func newFormalGLMRegisteredPhase18RecipientTicketStoreV1(
	rockRoot string,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase18RecipientTicketStoreV1, error) {
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}
	clonedContract, err := formalGLMDecodeSourceContractV1(
		contractJSON, clonedPins)
	clear(contractJSON)
	if err != nil {
		return nil, err
	}
	designated := clonedContract.Core.RegisteredExecutionPlan.DesignatedComputePeers
	if len(designated) != 2 || designated[0] == designated[1] {
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: invalid designated recipients")
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(clonedContract)
	if err != nil {
		return nil, err
	}
	root, err := formalGLMRegisteredPhase18TicketStoreOpenRootV1(rockRoot)
	if err != nil {
		return nil, err
	}
	if err := formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
		root, formalGLMRegisteredPhase18RecipientTicketRecordDirV1); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &formalGLMRegisteredPhase18RecipientTicketStoreV1{
		root: root,
		context: formalGLMRegisteredPhase18ProvenanceContextV1{
			contract: clonedContract, contractSHA256: contractSHA256,
			pins: clonedPins,
		},
	}, nil
}

func (store *formalGLMRegisteredPhase18RecipientTicketStoreV1) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	for peer := range store.context.pins {
		clear(store.context.pins[peer])
		delete(store.context.pins, peer)
	}
}

func (store *formalGLMRegisteredPhase18RecipientTicketStoreV1) recipientIndexLocked(
	recipient string,
) (int, error) {
	if store == nil || store.root == nil {
		return -1, fmt.Errorf("formal-glm registered Phase18 ticket store: closed")
	}
	for index, peer := range store.context.contract.Core.RegisteredExecutionPlan.DesignatedComputePeers {
		if peer == recipient {
			return index, nil
		}
	}
	return -1, fmt.Errorf("formal-glm registered Phase18 ticket store: recipient is not designated")
}

func (store *formalGLMRegisteredPhase18RecipientTicketStoreV1) recordRelativePathLocked(
	recipient string,
	create bool,
) (string, error) {
	index, err := store.recipientIndexLocked(recipient)
	artifactID := store.context.contract.Core.ArtifactID
	if err != nil || !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm registered Phase18 ticket store: invalid record key")
	}
	shard := filepath.Join(formalGLMRegisteredPhase18RecipientTicketRecordDirV1,
		artifactID[:2], artifactID[2:4], artifactID)
	if create {
		err = formalGLMRegisteredPhase18TicketStoreEnsureDirV1(store.root, shard)
	} else {
		err = formalGLMRegisteredPhase18TicketStoreValidateDirV1(store.root, shard)
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(shard,
		fmt.Sprintf("ticket-recipient-%d.json", index)), nil
}

func formalGLMRegisteredPhase18ProjectRecipientTicketRecordV1(
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
	context formalGLMRegisteredPhase18ProvenanceContextV1,
) (formalGLMRegisteredPhase18RecipientTicketRecordV1, error) {
	if err := formalGLMRegisteredPhase18ValidateRecipientTicketWithContextV1(
		context, ticket); err != nil {
		return formalGLMRegisteredPhase18RecipientTicketRecordV1{}, err
	}
	ticketSHA256, err := formalGLMRegisteredPhase18RecipientTicketSHA256V1(ticket)
	if err != nil {
		return formalGLMRegisteredPhase18RecipientTicketRecordV1{}, err
	}
	contract := context.contract
	plan := contract.Core.RegisteredExecutionPlan
	return formalGLMRegisteredPhase18RecipientTicketRecordV1{
		Version:                       formalGLMRegisteredPhase18RecipientTicketRecordVersionV1,
		Purpose:                       formalGLMRegisteredPhase18RecipientTicketRecordPurposeV1,
		ArtifactID:                    contract.Core.ArtifactID,
		SourceContractCoreSHA256:      contract.CoreSHA256,
		SourceContractSHA256:          context.contractSHA256,
		RegisteredExecutionPlanSHA256: plan.PlanSHA256,
		PinsetSHA256:                  plan.PinsetSHA256,
		RecipientName:                 ticket.RecipientName,
		RecipientTicketSHA256:         ticketSHA256,
		Ticket:                        ticket,
		ProductionReady:               false,
	}, nil
}

func formalGLMRegisteredPhase18RecipientTicketReceiptForRecordV1(
	record formalGLMRegisteredPhase18RecipientTicketRecordV1,
) formalGLMRegisteredPhase18RecipientTicketReceiptV1 {
	return formalGLMRegisteredPhase18RecipientTicketReceiptV1{
		Version:                       formalGLMRegisteredPhase18RecipientTicketReceiptVersionV1,
		Purpose:                       formalGLMRegisteredPhase18RecipientTicketReceiptPurposeV1,
		ArtifactID:                    record.ArtifactID,
		SourceContractCoreSHA256:      record.SourceContractCoreSHA256,
		SourceContractSHA256:          record.SourceContractSHA256,
		RegisteredExecutionPlanSHA256: record.RegisteredExecutionPlanSHA256,
		PinsetSHA256:                  record.PinsetSHA256,
		RecipientName:                 record.RecipientName,
		RecipientTicketSHA256:         record.RecipientTicketSHA256,
		ProductionReady:               false,
	}
}

func formalGLMRegisteredPhase18TicketStoreReadRecordV1(root *os.Root,
	relative string,
) ([]byte, error) {
	encoded, err := formalGLMPhase21RootReadRecord(
		root, relative, formalGLMRegisteredPhase18RecipientTicketRecordMaxV1)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(relative)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() != int64(len(encoded)) {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: unsafe durable record")
	}
	return encoded, nil
}

func (store *formalGLMRegisteredPhase18RecipientTicketStoreV1) decodeRecordLocked(
	encoded []byte,
	recipient string,
) (formalGLMRegisteredPhase18RecipientTicketRecordV1, error) {
	var record formalGLMRegisteredPhase18RecipientTicketRecordV1
	if len(encoded) < 64 ||
		len(encoded) > int(formalGLMRegisteredPhase18RecipientTicketRecordMaxV1) ||
		formalGLMPhase21RockStrictDecode(encoded, &record) != nil ||
		record.RecipientName != recipient {
		return formalGLMRegisteredPhase18RecipientTicketRecordV1{},
			fmt.Errorf("formal-glm registered Phase18 ticket store: invalid persisted record")
	}
	expected, err := formalGLMRegisteredPhase18ProjectRecipientTicketRecordV1(
		record.Ticket, store.context)
	if err != nil || !reflect.DeepEqual(record, expected) {
		return formalGLMRegisteredPhase18RecipientTicketRecordV1{},
			fmt.Errorf("formal-glm registered Phase18 ticket store: invalid persisted record")
	}
	return record, nil
}

func (store *formalGLMRegisteredPhase18RecipientTicketStoreV1) Commit(
	ticket formalGLMRegisteredPhase18RecipientTicketV1,
) (formalGLMRegisteredPhase18RecipientTicketReceiptV1, bool, error) {
	var zero formalGLMRegisteredPhase18RecipientTicketReceiptV1
	if store == nil {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase18 ticket store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase18 ticket store: closed")
	}
	record, err := formalGLMRegisteredPhase18ProjectRecipientTicketRecordV1(
		ticket, store.context)
	if err != nil {
		return zero, false, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > int(formalGLMRegisteredPhase18RecipientTicketRecordMaxV1) {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase18 ticket store: invalid record encoding")
	}
	relative, err := store.recordRelativePathLocked(ticket.RecipientName, true)
	if err != nil {
		return zero, false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return zero, false, err
	}
	persisted, err := formalGLMRegisteredPhase18TicketStoreReadRecordV1(
		store.root, relative)
	if err != nil {
		return zero, false, err
	}
	defer clear(persisted)
	if !bytes.Equal(persisted, encoded) {
		return zero, false,
			fmt.Errorf("formal-glm registered Phase18 ticket store: durable CAS conflict")
	}
	decoded, err := store.decodeRecordLocked(persisted, ticket.RecipientName)
	if err != nil {
		return zero, false, err
	}
	return formalGLMRegisteredPhase18RecipientTicketReceiptForRecordV1(decoded),
		!created, nil
}

func (store *formalGLMRegisteredPhase18RecipientTicketStoreV1) validateSetFilesLocked(
	relativePaths []string,
) error {
	if len(relativePaths) != 2 || filepath.Dir(relativePaths[0]) != filepath.Dir(relativePaths[1]) {
		return fmt.Errorf("formal-glm registered Phase18 ticket store: invalid durable set")
	}
	directory, err := store.root.Open(filepath.Dir(relativePaths[0]))
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	expected := map[string]bool{
		filepath.Base(relativePaths[0]): false,
		filepath.Base(relativePaths[1]): false,
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; ok {
			expected[entry.Name()] = true
			continue
		}
		if strings.HasPrefix(entry.Name(), ".formal-glm-sticky-") {
			continue
		}
		return fmt.Errorf("formal-glm registered Phase18 ticket store: unexpected durable record")
	}
	for _, present := range expected {
		if !present {
			return fmt.Errorf("formal-glm registered Phase18 ticket store: incomplete durable set")
		}
	}
	return nil
}

func (store *formalGLMRegisteredPhase18RecipientTicketStoreV1) LoadSet() (
	[]formalGLMRegisteredPhase18RecipientTicketV1, error,
) {
	if store == nil {
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: closed")
	}
	designated := store.context.contract.Core.RegisteredExecutionPlan.DesignatedComputePeers
	if len(designated) != 2 {
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: invalid designated recipients")
	}
	paths := make([]string, 2)
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 2)
	for index, recipient := range designated {
		relative, err := store.recordRelativePathLocked(recipient, false)
		if err != nil {
			return nil, err
		}
		encoded, err := formalGLMRegisteredPhase18TicketStoreReadRecordV1(
			store.root, relative)
		if err != nil {
			return nil, err
		}
		record, decodeErr := store.decodeRecordLocked(encoded, recipient)
		clear(encoded)
		if decodeErr != nil {
			return nil, decodeErr
		}
		paths[index] = relative
		tickets[index] = record.Ticket
	}
	if err := store.validateSetFilesLocked(paths); err != nil {
		return nil, err
	}
	ordered, err := formalGLMRegisteredPhase18CanonicalTicketsWithContextV1(
		store.context, tickets)
	if err != nil || !reflect.DeepEqual(ordered, tickets) {
		return nil, fmt.Errorf("formal-glm registered Phase18 ticket store: invalid durable set")
	}
	return ordered, nil
}
