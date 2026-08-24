package main

// Owner-local, durable source outbox for registered Phase-1.8 block pairs.
// This cut reserves an input intent before materialization randomness and
// durably commits the signed encrypted pair. It does not mint a local receipt
// or advance the pair into recipient ingress.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

const (
	formalGLMRegisteredPhase18SourceOutboxDirV3 = "registered-phase18-source-outbox-v3"

	formalGLMRegisteredPhase18SourceOutboxIntentVersionV3  = "dsvert-formal-glm-registered-phase18-source-outbox-intent-v3"
	formalGLMRegisteredPhase18SourceOutboxIntentPurposeV3  = "formal_glm_owner_local_source_block_input_intent_v3"
	formalGLMRegisteredPhase18SourceOutboxPairVersionV3    = "dsvert-formal-glm-registered-phase18-source-outbox-pair-v3"
	formalGLMRegisteredPhase18SourceOutboxPairPurposeV3    = "formal_glm_owner_local_signed_encrypted_block_pair_v3"
	formalGLMRegisteredPhase18SourceOutboxReceiptVersionV3 = "dsvert-formal-glm-registered-phase18-source-outbox-receipt-v3"
	formalGLMRegisteredPhase18SourceOutboxReceiptPurposeV3 = "formal_glm_owner_local_durable_source_block_pair_v3"

	formalGLMRegisteredPhase18SourceOutboxDomainV3    = "dsVert/formal-glm/registered-phase18/source-outbox/v3"
	formalGLMRegisteredPhase18SourceOutboxIntentMaxV3 = 64 << 10
	formalGLMRegisteredPhase18SourceOutboxPairMaxV3   = 16 << 20
	// A pair is an authenticated opaque block payload.  The fixed frame limit
	// is a physical transport bound, never a privacy or admission budget.
	formalGLMRegisteredPhase18SourceOutboxChunkMaxV3 = 1 << 20
)

type formalGLMRegisteredPhase18SourceOutboxIntentV3 struct {
	Version              string `json:"version"`
	Purpose              string `json:"purpose"`
	Handle               string `json:"handle"`
	ArtifactID           string `json:"artifact_id"`
	SourceContractSHA256 string `json:"source_contract_sha256"`
	AuthorizationSHA256  string `json:"authorization_sha256"`
	Source               string `json:"source"`
	BlockIndex           int    `json:"block_index"`
	InputCommitmentMAC   string `json:"input_commitment_mac"`
	ProductionReady      bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase18SourceOutboxPairRecordV3 struct {
	Version              string `json:"version"`
	Purpose              string `json:"purpose"`
	Handle               string `json:"handle"`
	ArtifactID           string `json:"artifact_id"`
	SourceContractSHA256 string `json:"source_contract_sha256"`
	AuthorizationSHA256  string `json:"authorization_sha256"`
	Source               string `json:"source"`
	BlockIndex           int    `json:"block_index"`
	InputCommitmentMAC   string `json:"input_commitment_mac"`
	PairJSON             []byte `json:"pair_json"`
	RecordMAC            string `json:"record_mac"`
	ProductionReady      bool   `json:"production_ready"`
}

// This receipt is safe routing evidence only. It contains no input
// commitment, values, validity, consensus, plaintext, key, or filesystem
// path, and it is not a registered local materialization receipt.
type formalGLMRegisteredPhase18SourceOutboxReceiptV3 struct {
	Version              string `json:"version"`
	Purpose              string `json:"purpose"`
	Handle               string `json:"handle"`
	ArtifactID           string `json:"artifact_id"`
	SourceContractSHA256 string `json:"source_contract_sha256"`
	AuthorizationSHA256  string `json:"authorization_sha256"`
	Source               string `json:"source"`
	BlockIndex           int    `json:"block_index"`
	PairCommitment       string `json:"pair_commitment"`
	BlockCommitment      string `json:"block_commitment"`
	PairBytes            int    `json:"pair_bytes"`
	ProductionReady      bool   `json:"production_ready"`
}

// Chunk receipts bind an opaque bounded transport frame to one already
// durable, source-signed pair. They intentionally contain neither the frame
// itself nor values, validity, consensus, keys, or a local pathname.
type formalGLMRegisteredPhase18SourceOutboxChunkReceiptV3 struct {
	Version              string `json:"version"`
	Purpose              string `json:"purpose"`
	Handle               string `json:"handle"`
	ArtifactID           string `json:"artifact_id"`
	SourceContractSHA256 string `json:"source_contract_sha256"`
	AuthorizationSHA256  string `json:"authorization_sha256"`
	Source               string `json:"source"`
	BlockIndex           int    `json:"block_index"`
	PairSHA256           string `json:"pair_sha256"`
	PairBytes            int    `json:"pair_bytes"`
	Offset               int64  `json:"offset"`
	ChunkSHA256          string `json:"chunk_sha256"`
	ChunkBytes           int    `json:"chunk_bytes"`
	Complete             bool   `json:"complete"`
	ProductionReady      bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase18SourceOutboxBuildV3 func(
	formalGLMSourceContractV1,
	formalGLMRegisteredPhase18AuthorizationV1,
	[]formalGLMRegisteredPhase18RecipientTicketV1,
	int, []string, []bool, []byte, []byte,
	map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18BlockPairV1, error)

type formalGLMRegisteredPhase18SourceOutboxHooksV3 struct {
	AfterIntent func() error
	BuildPair   formalGLMRegisteredPhase18SourceOutboxBuildV3
}

type formalGLMRegisteredPhase18SourceOutboxV3 struct {
	mu               sync.Mutex
	root             *os.Root
	contract         formalGLMSourceContractV1
	source           string
	sourcePrivateKey ed25519.PrivateKey
	localKey         [32]byte
	pins             map[string]ed25519.PublicKey
	afterIntent      func() error
	buildPair        formalGLMRegisteredPhase18SourceOutboxBuildV3
}

type formalGLMRegisteredPhase18SourceOutboxInputV3 struct {
	Version              string                                        `json:"version"`
	Purpose              string                                        `json:"purpose"`
	SourceContractSHA256 string                                        `json:"source_contract_sha256"`
	AuthorizationSHA256  string                                        `json:"authorization_sha256"`
	Source               string                                        `json:"source"`
	BlockIndex           int                                           `json:"block_index"`
	Tickets              []formalGLMRegisteredPhase18RecipientTicketV1 `json:"tickets"`
	Values               []string                                      `json:"values"`
	Validity             []bool                                        `json:"validity"`
	PrivateConsensus     []byte                                        `json:"private_consensus"`
}

func formalGLMRegisteredPhase18SourceOutboxDefaultBuildV3(
	contract formalGLMSourceContractV1,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	values []string,
	validity []bool,
	consensus []byte,
	key []byte,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase18BlockPairV1, error) {
	return formalGLMRegisteredPhase18BuildMaterializedBlockPairV3(
		contract, authorization, tickets, blockIndex, values, validity,
		consensus, ed25519.PrivateKey(key), pins)
}

func newFormalGLMRegisteredPhase18SourceOutboxV3(
	rockRoot string,
	contract formalGLMSourceContractV1,
	source string,
	sourcePrivateKey ed25519.PrivateKey,
	localKey [32]byte,
	pins map[string]ed25519.PublicKey,
) (*formalGLMRegisteredPhase18SourceOutboxV3, error) {
	return newFormalGLMRegisteredPhase18SourceOutboxWithHooksV3(
		rockRoot, contract, source, sourcePrivateKey, localKey, pins,
		formalGLMRegisteredPhase18SourceOutboxHooksV3{})
}

func newFormalGLMRegisteredPhase18SourceOutboxWithHooksV3(
	rockRoot string,
	contract formalGLMSourceContractV1,
	source string,
	sourcePrivateKey ed25519.PrivateKey,
	localKey [32]byte,
	pins map[string]ed25519.PublicKey,
	hooks formalGLMRegisteredPhase18SourceOutboxHooksV3,
) (*formalGLMRegisteredPhase18SourceOutboxV3, error) {
	if !filepath.IsAbs(rockRoot) || filepath.Clean(rockRoot) != rockRoot ||
		!formalGLMPhase19KeyValid(localKey) ||
		formalGLMValidateSourceContractV1(contract, pins) != nil ||
		exactGCValidateLabel("registered Phase-1.8 outbox source", source, 128) != nil ||
		len(pins[source]) != ed25519.PublicKeySize ||
		len(sourcePrivateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(sourcePrivateKey.Public().(ed25519.PublicKey), pins[source]) {
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid policy")
	}
	foundSource := false
	for _, peer := range contract.Core.RegisteredExecutionPlan.CustodianPeers {
		if peer == source {
			foundSource = true
		}
	}
	if !foundSource {
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: source is not registered")
	}
	if hooks.BuildPair == nil {
		hooks.BuildPair = formalGLMRegisteredPhase18SourceOutboxDefaultBuildV3
	}
	if err := formalFinalizerHandoffEnsurePrivateDir(rockRoot); err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(rockRoot)
	if err != nil || rootInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: unsafe Rock root")
	}
	resolved, err := filepath.EvalSymlinks(rockRoot)
	if err != nil || filepath.Clean(resolved) != rockRoot {
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: redirected Rock root")
	}
	root, err := os.OpenRoot(rockRoot)
	if err != nil {
		return nil, err
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedInfo) ||
		openedInfo.Mode().Perm() != 0o700 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(openedInfo) {
		_ = root.Close()
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: Rock root changed")
	}
	if err := formalGLMRegisteredPhase18SourceOutboxEnsureDirV3(
		root, formalGLMRegisteredPhase18SourceOutboxDirV3); err != nil {
		_ = root.Close()
		return nil, err
	}
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedContract, err := formalGLMDecodeSourceContractV1(contractJSON, pins)
	clear(contractJSON)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	clonedPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		clonedPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return &formalGLMRegisteredPhase18SourceOutboxV3{
		root: root, contract: clonedContract, source: source,
		sourcePrivateKey: append(ed25519.PrivateKey(nil), sourcePrivateKey...),
		localKey:         localKey, pins: clonedPins, afterIntent: hooks.AfterIntent,
		buildPair: hooks.BuildPair,
	}, nil
}

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) Close() {
	if outbox == nil {
		return
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if outbox.root != nil {
		_ = outbox.root.Close()
		outbox.root = nil
	}
	clear(outbox.sourcePrivateKey)
	clear(outbox.localKey[:])
	for peer := range outbox.pins {
		clear(outbox.pins[peer])
		delete(outbox.pins, peer)
	}
}

func formalGLMRegisteredPhase18SourceOutboxEnsureDirV3(
	root *os.Root, name string,
) error {
	if err := formalGLMPhase21EnsureRootPrivateDir(root, name); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) {
			return fmt.Errorf(
				"formal-glm registered Phase-1.8 source outbox: unsafe directory")
		}
	}
	return nil
}

func formalGLMRegisteredPhase18SourceOutboxValidateDirV3(
	root *os.Root, name string,
) error {
	if err := formalGLMPhase21ValidateRootPrivateDir(root, name, false); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 ||
			!formalFinalizerHandoffPrivateOwnedDirectory(info) {
			return fmt.Errorf(
				"formal-glm registered Phase-1.8 source outbox: unsafe directory")
		}
	}
	return nil
}

func formalGLMRegisteredPhase18SourceOutboxReadV3(
	root *os.Root, relative string, maximum int64,
) ([]byte, error) {
	encoded, err := formalGLMPhase21RootReadRecord(root, relative, maximum)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(relative)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() != int64(len(encoded)) {
		clear(encoded)
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: unsafe record")
	}
	return encoded, nil
}

func formalGLMRegisteredPhase18SourceOutboxMACValidV3(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) validateInputLocked(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	values []string,
	validity []bool,
	privateConsensus []byte,
) ([]formalGLMRegisteredPhase18RecipientTicketV1, error) {
	if outbox == nil || outbox.root == nil || len(privateConsensus) != 32 ||
		formalGLMValidateRegisteredPhase18AuthorizationV1(
			authorization, outbox.contract, outbox.pins) != nil ||
		authorization.LocalSource.SignerPeerName != outbox.source {
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid input binding")
	}
	orderedTickets, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		tickets, outbox.contract, outbox.pins)
	if err != nil {
		return nil, err
	}
	offset, slots, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, blockIndex)
	if err != nil {
		return nil, err
	}
	geometry := authorization.Geometry
	if len(values) != slots*geometry.CoordinateCount || len(validity) != slots {
		return nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid block shape")
	}
	modulus := exactGCModulus(geometry.RingBits)
	half := new(big.Int).Rsh(new(big.Int).Set(modulus), 1)
	maximum := new(big.Int).Sub(new(big.Int).Set(half), big.NewInt(1))
	minimum := new(big.Int).Neg(new(big.Int).Set(half))
	for index, text := range values {
		signed, parseErr := formalGLMCanonicalSigned(
			text, fmt.Sprintf("registered Phase-1.8 outbox value[%d]", index))
		if parseErr != nil || signed.Cmp(minimum) < 0 || signed.Cmp(maximum) > 0 {
			return nil, fmt.Errorf(
				"formal-glm registered Phase-1.8 source outbox: value outside signed ring")
		}
		row := index / geometry.CoordinateCount
		coordinate := index % geometry.CoordinateCount
		if (offset+row >= geometry.TotalCapacity || !validity[row] ||
			geometry.CoordinateOwners[coordinate] != outbox.source) &&
			signed.Sign() != 0 {
			return nil, fmt.Errorf(
				"formal-glm registered Phase-1.8 source outbox: invalid local value")
		}
	}
	for row, valid := range validity {
		if offset+row >= geometry.TotalCapacity && valid {
			return nil, fmt.Errorf(
				"formal-glm registered Phase-1.8 source outbox: valid padding")
		}
	}
	return orderedTickets, nil
}

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) inputCommitmentLocked(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	values []string,
	validity []bool,
	privateConsensus []byte,
) (string, error) {
	input := formalGLMRegisteredPhase18SourceOutboxInputV3{
		Version:              formalGLMRegisteredPhase18SourceOutboxIntentVersionV3,
		Purpose:              formalGLMRegisteredPhase18SourceOutboxIntentPurposeV3,
		SourceContractSHA256: authorization.SourceContractSHA256,
		AuthorizationSHA256:  authorization.AuthorizationSHA256,
		Source:               outbox.source, BlockIndex: blockIndex,
		Tickets: tickets, Values: append([]string(nil), values...),
		Validity:         append([]bool(nil), validity...),
		PrivateConsensus: append([]byte(nil), privateConsensus...),
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	mac := formalGLMPhase19MAC(
		outbox.localKey,
		formalGLMRegisteredPhase18SourceOutboxDomainV3+"/input", encoded)
	clear(encoded)
	return hex.EncodeToString(mac[:]), nil
}

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) slotLocked(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
	create bool,
) (string, string, string, error) {
	identity := struct {
		SourceContractSHA256 string `json:"source_contract_sha256"`
		AuthorizationSHA256  string `json:"authorization_sha256"`
		Source               string `json:"source"`
		BlockIndex           int    `json:"block_index"`
	}{
		SourceContractSHA256: authorization.SourceContractSHA256,
		AuthorizationSHA256:  authorization.AuthorizationSHA256,
		Source:               outbox.source, BlockIndex: blockIndex,
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", "", "", err
	}
	mac := formalGLMPhase19MAC(
		outbox.localKey,
		formalGLMRegisteredPhase18SourceOutboxDomainV3+"/slot", encoded)
	handle := hex.EncodeToString(mac[:])
	shard := filepath.Join(formalGLMRegisteredPhase18SourceOutboxDirV3,
		handle[:2], handle[2:4])
	if create {
		err = formalGLMRegisteredPhase18SourceOutboxEnsureDirV3(
			outbox.root, shard)
	} else {
		err = formalGLMRegisteredPhase18SourceOutboxValidateDirV3(
			outbox.root, shard)
	}
	if err != nil {
		return "", "", "", err
	}
	return handle,
		filepath.Join(shard, "intent-"+handle+".json"),
		filepath.Join(shard, "pair-"+handle+".json"), nil
}

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) pairRecordMACLocked(
	record formalGLMRegisteredPhase18SourceOutboxPairRecordV3,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := formalGLMPhase19MAC(
		outbox.localKey,
		formalGLMRegisteredPhase18SourceOutboxDomainV3+"/pair-record", encoded)
	clear(encoded)
	return hex.EncodeToString(mac[:]), nil
}

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) loadPairLocked(
	relative string,
	handle string,
	requiredInputCommitment string,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) (formalGLMRegisteredPhase18BlockPairV1, []byte, error) {
	var zero formalGLMRegisteredPhase18BlockPairV1
	encoded, err := formalGLMRegisteredPhase18SourceOutboxReadV3(
		outbox.root, relative, formalGLMRegisteredPhase18SourceOutboxPairMaxV3)
	if err != nil {
		return zero, nil, err
	}
	defer clear(encoded)
	var record formalGLMRegisteredPhase18SourceOutboxPairRecordV3
	if err := formalGLMPhase21RockStrictDecode(encoded, &record); err != nil {
		return zero, nil, err
	}
	wantMAC, err := outbox.pairRecordMACLocked(record)
	if err != nil || record.Version !=
		formalGLMRegisteredPhase18SourceOutboxPairVersionV3 ||
		record.Purpose != formalGLMRegisteredPhase18SourceOutboxPairPurposeV3 ||
		record.Handle != handle || record.ArtifactID != authorization.ArtifactID ||
		record.SourceContractSHA256 != authorization.SourceContractSHA256 ||
		record.AuthorizationSHA256 != authorization.AuthorizationSHA256 ||
		record.Source != outbox.source ||
		record.BlockIndex < 0 ||
		(requiredInputCommitment != "" &&
			record.InputCommitmentMAC != requiredInputCommitment) ||
		!formalGLMRegisteredPhase18SourceOutboxMACValidV3(record.RecordMAC) ||
		record.RecordMAC != wantMAC || record.ProductionReady {
		return zero, nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid pair record")
	}
	pair, err := formalGLMDecodeRegisteredPhase18BlockPairV1(
		record.PairJSON, outbox.contract, authorization, tickets, outbox.pins)
	if err != nil || pair.BlockIndex != record.BlockIndex ||
		pair.SourceName != record.Source {
		return zero, nil, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid durable pair")
	}
	return pair, append([]byte(nil), record.PairJSON...), nil
}

// ReadBlockChunk returns at most one fixed-size opaque frame of a pair that
// has already been sealed in this source's Rock outbox.  The caller cannot use
// it to choose a source, a recipient, a path, or a different materialization:
// the signed authorization and the exact two-ticket set select the sole
// durable block slot.
func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) ReadBlockChunk(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	offset int64,
) (formalGLMRegisteredPhase18SourceOutboxChunkReceiptV3, []byte, bool, error) {
	var zero formalGLMRegisteredPhase18SourceOutboxChunkReceiptV3
	if outbox == nil || offset < 0 {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid chunk request")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if outbox.root == nil ||
		formalGLMValidateRegisteredPhase18AuthorizationV1(
			authorization, outbox.contract, outbox.pins) != nil ||
		authorization.LocalSource.SignerPeerName != outbox.source {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid chunk binding")
	}
	orderedTickets, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		tickets, outbox.contract, outbox.pins)
	if err != nil || !reflect.DeepEqual(tickets, orderedTickets) {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: non-canonical chunk tickets")
	}
	if _, _, err := formalGLMRegisteredPhase18ExpectedShapeV3(
		authorization, blockIndex); err != nil {
		return zero, nil, false, err
	}
	handle, _, pairRelative, err := outbox.slotLocked(authorization, blockIndex, false)
	if err != nil {
		return zero, nil, false, err
	}
	pair, pairJSON, err := outbox.loadPairLocked(
		pairRelative, handle, "", authorization, orderedTickets)
	if err != nil {
		return zero, nil, false, err
	}
	defer clear(pairJSON)
	if offset >= int64(len(pairJSON)) {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: chunk offset outside pair")
	}
	end := offset + formalGLMRegisteredPhase18SourceOutboxChunkMaxV3
	if end > int64(len(pairJSON)) {
		end = int64(len(pairJSON))
	}
	chunk := append([]byte(nil), pairJSON[offset:end]...)
	pairDigest := sha256.Sum256(pairJSON)
	chunkDigest := sha256.Sum256(chunk)
	receipt := formalGLMRegisteredPhase18SourceOutboxChunkReceiptV3{
		Version:              formalGLMRegisteredPhase18SourceOutboxReceiptVersionV3,
		Purpose:              "formal_glm_owner_local_bounded_signed_pair_chunk_v3",
		Handle:               handle,
		ArtifactID:           pair.ArtifactID,
		SourceContractSHA256: pair.SourceContractSHA256,
		AuthorizationSHA256:  pair.RegisteredPhase18AuthorizationSHA256,
		Source:               pair.SourceName,
		BlockIndex:           pair.BlockIndex,
		PairSHA256:           hex.EncodeToString(pairDigest[:]),
		PairBytes:            len(pairJSON),
		Offset:               offset,
		ChunkSHA256:          hex.EncodeToString(chunkDigest[:]),
		ChunkBytes:           len(chunk),
		Complete:             end == int64(len(pairJSON)),
		ProductionReady:      false,
	}
	return receipt, chunk, receipt.Complete, nil
}

func formalGLMRegisteredPhase18SourceOutboxReceiptForPairV3(
	handle string,
	pair formalGLMRegisteredPhase18BlockPairV1,
	pairBytes int,
) formalGLMRegisteredPhase18SourceOutboxReceiptV3 {
	return formalGLMRegisteredPhase18SourceOutboxReceiptV3{
		Version: formalGLMRegisteredPhase18SourceOutboxReceiptVersionV3,
		Purpose: formalGLMRegisteredPhase18SourceOutboxReceiptPurposeV3,
		Handle:  handle, ArtifactID: pair.ArtifactID,
		SourceContractSHA256: pair.SourceContractSHA256,
		AuthorizationSHA256:  pair.RegisteredPhase18AuthorizationSHA256,
		Source:               pair.SourceName, BlockIndex: pair.BlockIndex,
		PairCommitment:  pair.PairCommitmentSHA256,
		BlockCommitment: pair.BlockCommitmentSHA256,
		PairBytes:       pairBytes, ProductionReady: false,
	}
}

func (outbox *formalGLMRegisteredPhase18SourceOutboxV3) CommitBlock(
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
	blockIndex int,
	values []string,
	validity []bool,
	privateConsensus []byte,
) (formalGLMRegisteredPhase18SourceOutboxReceiptV3, []byte, bool, error) {
	var zero formalGLMRegisteredPhase18SourceOutboxReceiptV3
	if outbox == nil {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: unavailable")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	orderedTickets, err := outbox.validateInputLocked(
		authorization, tickets, blockIndex, values, validity, privateConsensus)
	if err != nil {
		return zero, nil, false, err
	}
	inputCommitment, err := outbox.inputCommitmentLocked(
		authorization, orderedTickets, blockIndex, values, validity,
		privateConsensus)
	if err != nil {
		return zero, nil, false, err
	}
	handle, intentRelative, pairRelative, err := outbox.slotLocked(
		authorization, blockIndex, true)
	if err != nil {
		return zero, nil, false, err
	}
	intent := formalGLMRegisteredPhase18SourceOutboxIntentV3{
		Version: formalGLMRegisteredPhase18SourceOutboxIntentVersionV3,
		Purpose: formalGLMRegisteredPhase18SourceOutboxIntentPurposeV3,
		Handle:  handle, ArtifactID: authorization.ArtifactID,
		SourceContractSHA256: authorization.SourceContractSHA256,
		AuthorizationSHA256:  authorization.AuthorizationSHA256,
		Source:               outbox.source, BlockIndex: blockIndex,
		InputCommitmentMAC: inputCommitment, ProductionReady: false,
	}
	intentJSON, err := json.Marshal(intent)
	if err != nil || len(intentJSON) > formalGLMRegisteredPhase18SourceOutboxIntentMaxV3 ||
		!formalGLMRegisteredPhase18SourceOutboxMACValidV3(inputCommitment) {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid intent")
	}
	if _, err := formalGLMPhase21RootCreateRecord(
		outbox.root, intentRelative, intentJSON); err != nil {
		return zero, nil, false, err
	}
	persistedIntent, err := formalGLMRegisteredPhase18SourceOutboxReadV3(
		outbox.root, intentRelative,
		formalGLMRegisteredPhase18SourceOutboxIntentMaxV3)
	if err != nil || !bytes.Equal(persistedIntent, intentJSON) {
		clear(persistedIntent)
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: intent CAS conflict")
	}
	clear(persistedIntent)

	if _, err := outbox.root.Lstat(pairRelative); err == nil {
		pair, pairJSON, loadErr := outbox.loadPairLocked(
			pairRelative, handle, inputCommitment, authorization, orderedTickets)
		if loadErr != nil {
			return zero, nil, false, loadErr
		}
		return formalGLMRegisteredPhase18SourceOutboxReceiptForPairV3(
			handle, pair, len(pairJSON)), pairJSON, true, nil
	} else if !os.IsNotExist(err) {
		return zero, nil, false, err
	}
	if outbox.afterIntent != nil {
		if err := outbox.afterIntent(); err != nil {
			return zero, nil, false, err
		}
	}
	pair, err := outbox.buildPair(
		outbox.contract, authorization, orderedTickets, blockIndex,
		append([]string(nil), values...), append([]bool(nil), validity...),
		append([]byte(nil), privateConsensus...),
		append([]byte(nil), outbox.sourcePrivateKey...), outbox.pins)
	if err != nil {
		return zero, nil, false, err
	}
	pairJSON, err := json.Marshal(pair)
	if err != nil || len(pairJSON) > formalGLMRegisteredPhase18BlockPairMaxJSON {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid pair size")
	}
	if _, err := formalGLMDecodeRegisteredPhase18BlockPairV1(
		pairJSON, outbox.contract, authorization, orderedTickets,
		outbox.pins); err != nil {
		return zero, nil, false, err
	}
	record := formalGLMRegisteredPhase18SourceOutboxPairRecordV3{
		Version: formalGLMRegisteredPhase18SourceOutboxPairVersionV3,
		Purpose: formalGLMRegisteredPhase18SourceOutboxPairPurposeV3,
		Handle:  handle, ArtifactID: authorization.ArtifactID,
		SourceContractSHA256: authorization.SourceContractSHA256,
		AuthorizationSHA256:  authorization.AuthorizationSHA256,
		Source:               outbox.source, BlockIndex: blockIndex,
		InputCommitmentMAC: inputCommitment,
		PairJSON:           append([]byte(nil), pairJSON...), ProductionReady: false,
	}
	record.RecordMAC, err = outbox.pairRecordMACLocked(record)
	if err != nil {
		return zero, nil, false, err
	}
	recordJSON, err := json.Marshal(record)
	if err != nil || len(recordJSON) > formalGLMRegisteredPhase18SourceOutboxPairMaxV3 {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: invalid pair record size")
	}
	created, err := formalGLMPhase21RootCreateRecord(
		outbox.root, pairRelative, recordJSON)
	if err != nil {
		return zero, nil, false, err
	}
	persistedPair, persistedJSON, err := outbox.loadPairLocked(
		pairRelative, handle, inputCommitment, authorization, orderedTickets)
	if err != nil {
		return zero, nil, false, err
	}
	if created && !bytes.Equal(persistedJSON, pairJSON) {
		return zero, nil, false, fmt.Errorf(
			"formal-glm registered Phase-1.8 source outbox: pair CAS conflict")
	}
	return formalGLMRegisteredPhase18SourceOutboxReceiptForPairV3(
		handle, persistedPair, len(persistedJSON)), persistedJSON, !created, nil
}
