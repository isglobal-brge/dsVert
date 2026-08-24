package main

// Recipient-local durable staging for signed registered Phase-1.8 block
// pairs. Pairs remain pending until one canonical K/K receipt set commits
// their exact pair and block commitments; only then are recipient frames
// written to the ingress CAS.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

const (
	formalGLMRegisteredPhase18PendingPairDirV1 = "formal-glm-registered-phase18-pending-pairs-v1"

	formalGLMRegisteredPhase18PendingPairRecordVersionV1  = "dsvert-formal-glm-registered-phase18-pending-pair-record-v1"
	formalGLMRegisteredPhase18PendingPairRecordPurposeV1  = "formal_glm_recipient_local_pending_signed_pair_v1"
	formalGLMRegisteredPhase18PendingPairReceiptVersionV1 = "dsvert-formal-glm-registered-phase18-pending-pair-receipt-v1"
	formalGLMRegisteredPhase18PendingPairReceiptPurposeV1 = "formal_glm_recipient_local_pending_pair_committed_v1"

	formalGLMRegisteredPhase18PendingPairRecordMaxV1 = int64(16 << 20)
)

type formalGLMRegisteredPhase18PendingPairRecordV1 struct {
	Version                              string `json:"version"`
	Purpose                              string `json:"purpose"`
	ArtifactID                           string `json:"artifact_id"`
	SourceContractCoreSHA256             string `json:"source_contract_core_sha256"`
	SourceContractSHA256                 string `json:"source_contract_sha256"`
	RegisteredExecutionPlanSHA256        string `json:"registered_execution_plan_sha256"`
	RegisteredPhase18AuthorizationSHA256 string `json:"registered_phase18_authorization_sha256"`
	Recipient                            string `json:"recipient"`
	Source                               string `json:"source"`
	BlockIndex                           int    `json:"block_index"`
	PairCommitmentSHA256                 string `json:"pair_commitment_sha256"`
	BlockCommitmentSHA256                string `json:"block_commitment_sha256"`
	PairSHA256                           string `json:"pair_sha256"`
	PairJSON                             []byte `json:"pair_json"`
	ProductionReady                      bool   `json:"production_ready"`
}

// This receipt contains routing commitments only. It intentionally carries
// no pair payload, ciphertext, key material, or filesystem path.
type formalGLMRegisteredPhase18PendingPairReceiptV1 struct {
	Version              string `json:"version"`
	Purpose              string `json:"purpose"`
	ArtifactID           string `json:"artifact_id"`
	SourceContractSHA256 string `json:"source_contract_sha256"`
	AuthorizationSHA256  string `json:"authorization_sha256"`
	Recipient            string `json:"recipient"`
	Source               string `json:"source"`
	BlockIndex           int    `json:"block_index"`
	PairCommitment       string `json:"pair_commitment"`
	BlockCommitment      string `json:"block_commitment"`
	PairSHA256           string `json:"pair_sha256"`
	ProductionReady      bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase18PendingPairStoreV1 struct {
	mu                sync.Mutex
	root              *os.Root
	recipient         string
	ticketStore       *formalGLMRegisteredPhase18RecipientTicketStoreV1
	provenanceContext formalGLMRegisteredPhase18ProvenanceContextV1
	validationContext *formalGLMRegisteredPhase18ValidationContextV3
}

func newFormalGLMRegisteredPhase18PendingPairStoreV1(
	rockRoot string,
	recipient string,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	ticketStore *formalGLMRegisteredPhase18RecipientTicketStoreV1,
) (*formalGLMRegisteredPhase18PendingPairStoreV1, error) {
	if !filepath.IsAbs(rockRoot) || filepath.Clean(rockRoot) != rockRoot ||
		exactGCValidateLabel("registered Phase-1.8 pending recipient",
			recipient, 128) != nil || ticketStore == nil {
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: invalid policy")
	}
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
	recipientFound := false
	for _, peer := range designated {
		if peer == recipient {
			recipientFound = true
		}
	}
	if len(designated) != 2 || !recipientFound {
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: recipient is not designated")
	}
	contractSHA256, err := formalGLMSourceContractSHA256V1(clonedContract)
	if err != nil {
		return nil, err
	}
	provenanceContext := formalGLMRegisteredPhase18ProvenanceContextV1{
		contract: clonedContract, contractSHA256: contractSHA256,
		pins: clonedPins,
	}
	validationContext, err :=
		formalGLMRegisteredPhase18ValidationContextFromProvenanceV3(
			provenanceContext)
	if err != nil {
		return nil, err
	}
	root, err := formalGLMRegisteredPhase18TicketStoreOpenRootV1(rockRoot)
	if err != nil {
		return nil, err
	}
	if err := formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
		root, formalGLMRegisteredPhase18PendingPairDirV1); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &formalGLMRegisteredPhase18PendingPairStoreV1{
		root: root, recipient: recipient, ticketStore: ticketStore,
		provenanceContext: provenanceContext,
		validationContext: validationContext,
	}, nil
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) Close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	for peer := range store.provenanceContext.pins {
		clear(store.provenanceContext.pins[peer])
		delete(store.provenanceContext.pins, peer)
	}
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) routeLocked(
	source string,
	blockIndex int,
) (formalGLMRegisteredPhase18AuthorizationV1, int, int, error) {
	if store == nil || store.root == nil || store.validationContext == nil {
		return formalGLMRegisteredPhase18AuthorizationV1{}, -1, -1,
			fmt.Errorf("formal-glm registered Phase-1.8 pending pair store: closed")
	}
	authorization, found := store.validationContext.authorization(source)
	if !found {
		return formalGLMRegisteredPhase18AuthorizationV1{}, -1, -1,
			fmt.Errorf("formal-glm registered Phase-1.8 pending pair store: invalid source")
	}
	if _, _, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, blockIndex); err != nil {
		return formalGLMRegisteredPhase18AuthorizationV1{}, -1, -1, err
	}
	sourceIndex := -1
	for index, peer := range authorization.CustodianPeers {
		if peer == source {
			sourceIndex = index
		}
	}
	recipientIndex := -1
	for index, peer := range authorization.DesignatedComputePeers {
		if peer == store.recipient {
			recipientIndex = index
		}
	}
	if sourceIndex < 0 || recipientIndex < 0 {
		return formalGLMRegisteredPhase18AuthorizationV1{}, -1, -1,
			fmt.Errorf("formal-glm registered Phase-1.8 pending pair store: invalid route")
	}
	return authorization, sourceIndex, recipientIndex, nil
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) recordRelativeLocked(
	source string,
	blockIndex int,
	create bool,
) (string, error) {
	_, sourceIndex, recipientIndex, err := store.routeLocked(source, blockIndex)
	artifactID := store.provenanceContext.contract.Core.ArtifactID
	if err != nil || !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: invalid record key")
	}
	directory := filepath.Join(
		formalGLMRegisteredPhase18PendingPairDirV1,
		artifactID[:2], artifactID[2:4], artifactID,
		fmt.Sprintf("recipient-%d", recipientIndex),
		fmt.Sprintf("source-%d", sourceIndex))
	if create {
		err = formalGLMRegisteredPhase18TicketStoreEnsureDirV1(
			store.root, directory)
	} else {
		err = formalGLMRegisteredPhase18TicketStoreValidateDirV1(
			store.root, directory)
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(directory,
		fmt.Sprintf("pair-block-%08d.json", blockIndex)), nil
}

func formalGLMRegisteredPhase18PendingPairReadV1(
	root *os.Root,
	relative string,
) ([]byte, error) {
	encoded, err := formalGLMPhase21RootReadRecord(
		root, relative, formalGLMRegisteredPhase18PendingPairRecordMaxV1)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(relative)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() != int64(len(encoded)) {
		clear(encoded)
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: unsafe durable record")
	}
	return encoded, nil
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) projectRecordLocked(
	pairJSON []byte,
	pair formalGLMRegisteredPhase18BlockPairV1,
) (formalGLMRegisteredPhase18PendingPairRecordV1, error) {
	authorization, _, _, err := store.routeLocked(
		pair.SourceName, pair.BlockIndex)
	if err != nil {
		return formalGLMRegisteredPhase18PendingPairRecordV1{}, err
	}
	digest := sha256.Sum256(pairJSON)
	return formalGLMRegisteredPhase18PendingPairRecordV1{
		Version:                              formalGLMRegisteredPhase18PendingPairRecordVersionV1,
		Purpose:                              formalGLMRegisteredPhase18PendingPairRecordPurposeV1,
		ArtifactID:                           authorization.ArtifactID,
		SourceContractCoreSHA256:             authorization.SourceContractCoreSHA256,
		SourceContractSHA256:                 authorization.SourceContractSHA256,
		RegisteredExecutionPlanSHA256:        authorization.RegisteredExecutionPlanSHA256,
		RegisteredPhase18AuthorizationSHA256: authorization.AuthorizationSHA256,
		Recipient:                            store.recipient, Source: pair.SourceName,
		BlockIndex:            pair.BlockIndex,
		PairCommitmentSHA256:  pair.PairCommitmentSHA256,
		BlockCommitmentSHA256: pair.BlockCommitmentSHA256,
		PairSHA256:            hex.EncodeToString(digest[:]),
		PairJSON:              append([]byte(nil), pairJSON...),
		ProductionReady:       false,
	}, nil
}

func formalGLMRegisteredPhase18PendingPairReceiptForRecordV1(
	record formalGLMRegisteredPhase18PendingPairRecordV1,
) formalGLMRegisteredPhase18PendingPairReceiptV1 {
	return formalGLMRegisteredPhase18PendingPairReceiptV1{
		Version:              formalGLMRegisteredPhase18PendingPairReceiptVersionV1,
		Purpose:              formalGLMRegisteredPhase18PendingPairReceiptPurposeV1,
		ArtifactID:           record.ArtifactID,
		SourceContractSHA256: record.SourceContractSHA256,
		AuthorizationSHA256:  record.RegisteredPhase18AuthorizationSHA256,
		Recipient:            record.Recipient, Source: record.Source,
		BlockIndex:      record.BlockIndex,
		PairCommitment:  record.PairCommitmentSHA256,
		BlockCommitment: record.BlockCommitmentSHA256,
		PairSHA256:      record.PairSHA256,
		ProductionReady: false,
	}
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) decodeRecordLocked(
	encoded []byte,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	source string,
	blockIndex int,
) (formalGLMRegisteredPhase18PendingPairRecordV1,
	formalGLMRegisteredPhase18BlockPairV1, error,
) {
	var record formalGLMRegisteredPhase18PendingPairRecordV1
	if len(encoded) < 64 ||
		len(encoded) > int(formalGLMRegisteredPhase18PendingPairRecordMaxV1) ||
		formalGLMPhase21RockStrictDecode(encoded, &record) != nil ||
		record.Source != source || record.BlockIndex != blockIndex ||
		record.Recipient != store.recipient {
		return formalGLMRegisteredPhase18PendingPairRecordV1{},
			formalGLMRegisteredPhase18BlockPairV1{}, fmt.Errorf(
				"formal-glm registered Phase-1.8 pending pair store: invalid persisted record")
	}
	pair, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18BlockPairV1](
		record.PairJSON, formalGLMRegisteredPhase18BlockPairMaxJSON)
	if err != nil {
		return formalGLMRegisteredPhase18PendingPairRecordV1{},
			formalGLMRegisteredPhase18BlockPairV1{}, err
	}
	authorization, found := store.validationContext.authorization(source)
	if !found || formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
		store.provenanceContext, pair, authorization, tickets) != nil {
		return formalGLMRegisteredPhase18PendingPairRecordV1{},
			formalGLMRegisteredPhase18BlockPairV1{}, fmt.Errorf(
				"formal-glm registered Phase-1.8 pending pair store: invalid persisted pair")
	}
	expected, err := store.projectRecordLocked(record.PairJSON, pair)
	if err != nil || !reflect.DeepEqual(record, expected) {
		return formalGLMRegisteredPhase18PendingPairRecordV1{},
			formalGLMRegisteredPhase18BlockPairV1{}, fmt.Errorf(
				"formal-glm registered Phase-1.8 pending pair store: invalid persisted record")
	}
	return record, pair, nil
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) CommitPair(
	pairJSON []byte,
) (formalGLMRegisteredPhase18PendingPairReceiptV1, bool, error) {
	var zero formalGLMRegisteredPhase18PendingPairReceiptV1
	if store == nil {
		return zero, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.commitPairLocked(pairJSON)
}

// commitPairLocked is shared with the bounded pair-fragment receiver.  The
// caller must hold store.mu so a completed fragment stream cannot race a
// direct legacy import of the same signed pair.
func (store *formalGLMRegisteredPhase18PendingPairStoreV1) commitPairLocked(
	pairJSON []byte,
) (formalGLMRegisteredPhase18PendingPairReceiptV1, bool, error) {
	var zero formalGLMRegisteredPhase18PendingPairReceiptV1
	if store.root == nil {
		return zero, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: closed")
	}
	candidate := append([]byte(nil), pairJSON...)
	defer clear(candidate)
	pair, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18BlockPairV1](
		candidate, formalGLMRegisteredPhase18BlockPairMaxJSON)
	if err != nil {
		return zero, false, err
	}
	tickets, err := store.ticketStore.LoadSet()
	if err != nil {
		return zero, false, err
	}
	authorization, found := store.validationContext.authorization(pair.SourceName)
	if !found || formalGLMRegisteredPhase18ValidateBlockPairWithContextV1(
		store.provenanceContext, pair, authorization, tickets) != nil {
		return zero, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: invalid signed pair")
	}
	record, err := store.projectRecordLocked(candidate, pair)
	if err != nil {
		return zero, false, err
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > int(formalGLMRegisteredPhase18PendingPairRecordMaxV1) {
		return zero, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: invalid record encoding")
	}
	relative, err := store.recordRelativeLocked(pair.SourceName, pair.BlockIndex, true)
	if err != nil {
		return zero, false, err
	}
	created, err := formalGLMPhase21RootCreateRecord(store.root, relative, encoded)
	if err != nil {
		return zero, false, err
	}
	persisted, err := formalGLMRegisteredPhase18PendingPairReadV1(
		store.root, relative)
	if err != nil {
		return zero, false, err
	}
	defer clear(persisted)
	if !bytes.Equal(persisted, encoded) {
		return zero, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: durable CAS conflict")
	}
	decoded, _, err := store.decodeRecordLocked(
		persisted, tickets, pair.SourceName, pair.BlockIndex)
	if err != nil {
		return zero, false, err
	}
	return formalGLMRegisteredPhase18PendingPairReceiptForRecordV1(decoded),
		!created, nil
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) validateSourceFilesLocked(
	directory string,
	totalBlocks int,
) error {
	opened, err := store.root.Open(directory)
	if err != nil {
		return err
	}
	entries, readErr := opened.ReadDir(-1)
	closeErr := opened.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	expected := make(map[string]bool, totalBlocks)
	for blockIndex := 0; blockIndex < totalBlocks; blockIndex++ {
		expected[fmt.Sprintf("pair-block-%08d.json", blockIndex)] = false
	}
	for _, entry := range entries {
		if _, found := expected[entry.Name()]; found {
			expected[entry.Name()] = true
			continue
		}
		if strings.HasPrefix(entry.Name(), ".formal-glm-sticky-") {
			continue
		}
		return fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: unexpected durable record")
	}
	for _, present := range expected {
		if !present {
			return fmt.Errorf(
				"formal-glm registered Phase-1.8 pending pair store: incomplete durable pairs")
		}
	}
	return nil
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) loadAllLocked(
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) ([]formalGLMRegisteredPhase18BlockPairV1, error) {
	plan := store.provenanceContext.contract.Core.RegisteredExecutionPlan
	pairs := make([]formalGLMRegisteredPhase18BlockPairV1, 0,
		plan.CustodianCount*plan.TotalBlocks)
	for _, source := range plan.CustodianPeers {
		sourceDirectory := ""
		for blockIndex := 0; blockIndex < plan.TotalBlocks; blockIndex++ {
			relative, err := store.recordRelativeLocked(source, blockIndex, false)
			if err != nil {
				return nil, err
			}
			encoded, err := formalGLMRegisteredPhase18PendingPairReadV1(
				store.root, relative)
			if err != nil {
				return nil, err
			}
			_, pair, decodeErr := store.decodeRecordLocked(
				encoded, tickets, source, blockIndex)
			clear(encoded)
			if decodeErr != nil {
				return nil, decodeErr
			}
			sourceDirectory = filepath.Dir(relative)
			pairs = append(pairs, pair)
		}
		if err := store.validateSourceFilesLocked(
			sourceDirectory, plan.TotalBlocks); err != nil {
			return nil, err
		}
	}
	return pairs, nil
}

func formalGLMRegisteredPhase18PendingContextBindingV1(
	provenance formalGLMRegisteredPhase18ProvenanceContextV1,
	validation *formalGLMRegisteredPhase18ValidationContextV3,
) bool {
	plan := provenance.contract.Core.RegisteredExecutionPlan
	return validation != nil &&
		provenance.contract.CoreSHA256 == validation.sourceContractCoreSHA256 &&
		provenance.contractSHA256 == validation.sourceContractSHA256 &&
		plan.PlanSHA256 == validation.registeredExecutionPlanSHA256 &&
		plan.PinsetSHA256 == validation.pinsetSHA256 &&
		plan.CustodianCount == validation.custodianCount
}

func (store *formalGLMRegisteredPhase18PendingPairStoreV1) Finalize(
	receiptSetJSON []byte,
	ingressStore *formalGLMRegisteredPhase18IngressStoreV3,
) ([]formalGLMRegisteredPhase18IngressStoreReceiptV3, bool, error) {
	if store == nil || ingressStore == nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: unavailable finalizer")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: closed")
	}
	receiptSet, err := formalGLMDecodeRegisteredPhase18CanonicalV1[formalGLMRegisteredPhase18ReceiptSetV1](
		receiptSetJSON, formalGLMRegisteredPhase18ReceiptSetMaxJSON)
	if err != nil || formalGLMRegisteredPhase18ValidateReceiptSetWithContextV1(
		store.provenanceContext, receiptSet) != nil {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: invalid K receipt set")
	}

	ingressStore.mu.Lock()
	if ingressStore.root == nil {
		ingressStore.mu.Unlock()
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: ingress store is closed")
	}
	ingressRecipient := ingressStore.recipient
	ingressRoot := ingressStore.expectedGlobalMaterializationRoot
	ingressContext := ingressStore.context
	ingressKey := ingressStore.localKey
	ingressStore.mu.Unlock()
	defer clear(ingressKey[:])
	if ingressRecipient != store.recipient ||
		ingressRoot != receiptSet.GlobalMaterializationRootSHA256 ||
		!formalGLMRegisteredPhase18PendingContextBindingV1(
			store.provenanceContext, ingressContext) {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: ingress binding mismatch")
	}

	tickets, err := store.ticketStore.LoadSet()
	if err != nil {
		return nil, false, err
	}
	pairs, err := store.loadAllLocked(tickets)
	if err != nil {
		return nil, false, err
	}
	plan := store.provenanceContext.contract.Core.RegisteredExecutionPlan
	if len(pairs) != plan.CustodianCount*plan.TotalBlocks ||
		len(receiptSet.Receipts) != plan.CustodianCount {
		return nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 pending pair store: incomplete pending matrix")
	}
	frames := make([][]byte, len(pairs))
	defer func() {
		for _, frame := range frames {
			clear(frame)
		}
	}()
	for pairIndex, pair := range pairs {
		sourceIndex := pairIndex / plan.TotalBlocks
		receipt := receiptSet.Receipts[sourceIndex]
		if receipt.SourceName != pair.SourceName ||
			pair.BlockIndex >= len(receipt.BlockCommitments) {
			return nil, false, fmt.Errorf(
				"formal-glm registered Phase-1.8 pending pair store: pair is absent from K root")
		}
		commitment := receipt.BlockCommitments[pair.BlockIndex]
		if commitment.BlockIndex != pair.BlockIndex ||
			commitment.PairCommitmentSHA256 != pair.PairCommitmentSHA256 ||
			commitment.BlockCommitmentSHA256 != pair.BlockCommitmentSHA256 {
			return nil, false, fmt.Errorf(
				"formal-glm registered Phase-1.8 pending pair store: pair differs from K root")
		}
		frames[pairIndex], err =
			formalGLMRegisteredPhase18ComposeValidatedIngressFrameWithContextV3(
				ingressContext, tickets, pair, receiptSet,
				store.recipient, ingressKey)
		if err != nil {
			return nil, false, err
		}
	}

	receipts := make([]formalGLMRegisteredPhase18IngressStoreReceiptV3,
		len(frames))
	allReplayed := true
	for index, frame := range frames {
		receipt, replayed, commitErr := ingressStore.CommitWithContextV3(
			frame, ingressContext)
		if commitErr != nil {
			return nil, false, commitErr
		}
		receipts[index] = receipt
		allReplayed = allReplayed && replayed
	}
	return receipts, allReplayed, nil
}
