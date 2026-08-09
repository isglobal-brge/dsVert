package main

// Fixed-memory private block store for the durable formal-GLM schedule.
//
// Phase-1.5 revisits every protected block for each fixed optimizer
// iteration. Keeping all additive shares as []*big.Int therefore makes peak
// RAM proportional to TotalBlocks. This store writes one fixed-size,
// backend-MACed record per block and supports authenticated O(1) reads. The
// relay never receives this file and one compute peer's records remain only
// additive shares.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"path/filepath"
)

const (
	formalGLMPhase19StreamStoreName   = "formal-phase19-blocks-v1.bin"
	formalGLMPhase19StreamStoreDomain = "dsVert/formal-glm/phase19/private-block-store/v1"
	formalGLMPhase19StreamRecordFixed = 4 + 1 + 32 + 32 + 32
)

type formalGLMPhase19StoredBlock struct {
	BlockIndex        int
	TupleShares       []*big.Int
	ExecutionShare    byte
	PairRoot          string
	ReceiptPairSHA256 string
}

type formalGLMPhase19BlockScheduleSummary struct {
	TotalBlocks            int
	AccumulatorRoot        string
	FanInTranscriptSHA256  string
	BlockCommitmentSHA256  string
	BlockReceiptRootSHA256 string
}

type formalGLMPhase19StreamStore struct {
	path        string
	file        *os.File
	plan        formalGLMPhase15Plan
	ctx         formalGLMPhase19Context
	peer        string
	key         [32]byte
	context     [32]byte
	tupleBytes  int
	recordBytes int64
	required    int64
	next        int
	complete    bool
}

func formalGLMPhase19StreamStoreRequiredBytes(plan formalGLMPhase15Plan) (
	int64, int64, error) {
	if _, err := formalGLMPhase15ValidateShape(plan); err != nil {
		return 0, 0, err
	}
	coordinates := plan.BlockCapacity * (plan.Kernel.CoefficientCount + 3)
	recordBytes := int64(coordinates*(plan.ContainerBits/8) +
		formalGLMPhase19StreamRecordFixed)
	if recordBytes < formalGLMPhase19StreamRecordFixed ||
		int64(plan.TotalBlocks) > exactGCMaxAbsoluteOffset/recordBytes {
		return 0, 0, fmt.Errorf("formal-glm: private block-store size overflow")
	}
	required := int64(plan.TotalBlocks) * recordBytes
	return recordBytes, required, nil
}

func newFormalGLMPhase19StreamStore(dir string, maxBytes int64,
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context, peer string,
	backendKey [32]byte) (*formalGLMPhase19StreamStore, error) {
	if formalGLMPhase19RuntimeValidatePath(dir, "private block store") != nil ||
		(peer != ctx.ComputePeers[0] && peer != ctx.ComputePeers[1]) ||
		!formalGLMPhase19KeyValid(backendKey) {
		return nil, fmt.Errorf("formal-glm: invalid private block-store policy")
	}
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return nil, err
	}
	recordBytes, required, err := formalGLMPhase19StreamStoreRequiredBytes(plan)
	if err != nil {
		return nil, err
	}
	if maxBytes < required || maxBytes > exactGCMaxAbsoluteOffset {
		return nil, fmt.Errorf(
			"formal-glm: private block store exceeds its declared resource bound")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("formal-glm: unsafe private block-store directory")
	}
	path := filepath.Join(dir, formalGLMPhase19StreamStoreName)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &formalGLMPhase19StreamStore{
		path: path, file: file, plan: plan, ctx: ctx, peer: peer,
		key: backendKey, context: ctxDigest,
		tupleBytes: plan.BlockCapacity * (plan.Kernel.CoefficientCount + 3) *
			(plan.ContainerBits / 8),
		recordBytes: recordBytes, required: required,
	}, nil
}

func formalGLMPhase19StreamDecodeRoot(value, name string) ([32]byte, error) {
	var result [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) ||
		hex.EncodeToString(decoded) != value {
		clear(decoded)
		return result, fmt.Errorf("formal-glm: invalid private block %s", name)
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, nil
}

func (store *formalGLMPhase19StreamStore) recordMAC(record []byte) [32]byte {
	message := formalGLMPhase15AppendString(nil,
		formalGLMPhase19StreamStoreDomain)
	message = append(message, store.context[:]...)
	message = formalGLMPhase15AppendString(message, store.peer)
	message = formalGLMPhase15AppendBytes(message, record)
	return formalGLMPhase19MAC(store.key,
		formalGLMPhase19StreamStoreDomain+"/record", message)
}

func (store *formalGLMPhase19StreamStore) Append(
	block formalGLMPhase19MaskedBlock,
	pair formalGLMPhase19MaskedBlockReceiptPair) error {
	if store == nil || store.file == nil || store.complete ||
		store.next >= store.plan.TotalBlocks ||
		block.Receipt.BlockIndex != store.next || pair.BlockIndex != store.next {
		return fmt.Errorf("formal-glm: invalid private block-store append order")
	}
	if err := formalGLMPhase19VerifyMaskedBlockReceiptPair(
		store.ctx, pair, store.key); err != nil {
		return err
	}
	expected := pair.EvaluatorReceiptSHA256
	if store.peer == store.ctx.ComputePeers[0] {
		expected = pair.GarblerReceiptSHA256
	}
	if err := formalGLMPhase19VerifyMaskedBlockForAccumulator(
		store.plan, store.ctx, block, expected, store.peer, store.key); err != nil {
		return err
	}
	encoded, err := formalGLMPhase15EncodeRecords(
		block.tupleShares, store.plan.RingBits)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if len(encoded) != store.tupleBytes {
		return fmt.Errorf("formal-glm: invalid private block-store tuple width")
	}
	pairRoot, err := formalGLMPhase19StreamDecodeRoot(pair.PairRoot, "pair root")
	if err != nil {
		return err
	}
	receiptRoot, err := formalGLMPhase19StreamDecodeRoot(
		pair.ReceiptPairSHA256, "receipt root")
	if err != nil {
		return err
	}
	record := make([]byte, int(store.recordBytes))
	defer clear(record)
	binary.BigEndian.PutUint32(record[:4], uint32(store.next))
	offset := 4
	copy(record[offset:offset+store.tupleBytes], encoded)
	offset += store.tupleBytes
	record[offset] = block.executionShare
	offset++
	copy(record[offset:offset+32], pairRoot[:])
	offset += 32
	copy(record[offset:offset+32], receiptRoot[:])
	offset += 32
	mac := store.recordMAC(record[:offset])
	copy(record[offset:], mac[:])
	if _, err := store.file.Seek(int64(store.next)*store.recordBytes, io.SeekStart); err != nil {
		return err
	}
	if err := exactGCWriteFull(store.file, record); err != nil {
		return err
	}
	store.next++
	return nil
}

func (store *formalGLMPhase19StreamStore) Complete() error {
	if store == nil || store.file == nil || store.complete ||
		store.next != store.plan.TotalBlocks {
		return fmt.Errorf("formal-glm: incomplete private block store")
	}
	if err := store.file.Sync(); err != nil {
		return err
	}
	info, err := store.file.Stat()
	if err != nil || info.Size() != store.required {
		return fmt.Errorf("formal-glm: private block-store size mismatch")
	}
	store.complete = true
	return nil
}

func (store *formalGLMPhase19StreamStore) readRecord(index int,
	decodeShares bool) (formalGLMPhase19StoredBlock, error) {
	var zero formalGLMPhase19StoredBlock
	if store == nil || store.file == nil || !store.complete || index < 0 ||
		index >= store.plan.TotalBlocks {
		return zero, fmt.Errorf("formal-glm: invalid private block-store read")
	}
	record := make([]byte, int(store.recordBytes))
	defer clear(record)
	n, err := store.file.ReadAt(record, int64(index)*store.recordBytes)
	if err != nil && err != io.EOF {
		return zero, err
	}
	if n != len(record) || int(binary.BigEndian.Uint32(record[:4])) != index {
		return zero, fmt.Errorf("formal-glm: truncated or reordered private block")
	}
	offset := 4 + store.tupleBytes
	execution := record[offset]
	offset++
	if execution > 1 {
		return zero, fmt.Errorf("formal-glm: invalid stored execution share")
	}
	pairRoot := hex.EncodeToString(record[offset : offset+32])
	offset += 32
	receiptRoot := hex.EncodeToString(record[offset : offset+32])
	offset += 32
	want := store.recordMAC(record[:offset])
	if !hmac.Equal(want[:], record[offset:]) {
		return zero, fmt.Errorf("formal-glm: private block-store authentication failed")
	}
	result := formalGLMPhase19StoredBlock{
		BlockIndex: index, ExecutionShare: execution,
		PairRoot: pairRoot, ReceiptPairSHA256: receiptRoot,
	}
	if decodeShares {
		result.TupleShares, err = formalGLMPhase15DecodeRecords(
			record[4:4+store.tupleBytes],
			store.plan.BlockCapacity*(store.plan.Kernel.CoefficientCount+3),
			store.plan.RingBits)
		if err != nil {
			return zero, err
		}
	}
	return result, nil
}

func (store *formalGLMPhase19StreamStore) ReadBlock(index int) (
	formalGLMPhase19StoredBlock, error) {
	return store.readRecord(index, true)
}

func (store *formalGLMPhase19StreamStore) ReadMetadata(index int) (
	formalGLMPhase19StoredBlock, error) {
	return store.readRecord(index, false)
}

func formalGLMPhase19StreamHashPrefix(domain string,
	ctx formalGLMPhase19Context) hash.Hash {
	h := sha256.New()
	message := formalGLMPhase15AppendString(nil, domain)
	message = formalGLMPhase15AppendString(
		message, ctx.ContextSHA256ForPhase19())
	message = formalGLMPhase15AppendString(
		message, ctx.GlobalMaterializationRoot)
	_, _ = h.Write(message)
	clear(message)
	return h
}

func formalGLMPhase19StreamHashString(h hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}

func (store *formalGLMPhase19StreamStore) Summary() (
	formalGLMPhase19BlockScheduleSummary, error) {
	var zero formalGLMPhase19BlockScheduleSummary
	if store == nil || !store.complete {
		return zero, fmt.Errorf("formal-glm: incomplete private block summary")
	}
	accumulator := sha256.New()
	message := formalGLMPhase15AppendString(nil,
		formalGLMPhase19ExecDomain+"/plan")
	message = append(message, store.context[:]...)
	_, _ = accumulator.Write(message)
	clear(message)
	fanIn := formalGLMPhase19StreamHashPrefix(
		formalGLMPhase19PostTokenDomain+"/fanin", store.ctx)
	commitments := formalGLMPhase19StreamHashPrefix(
		formalGLMPhase19PostTokenDomain+"/commitments", store.ctx)
	receipts := formalGLMPhase19StreamHashPrefix(
		formalGLMPhase19PostTokenDomain+"/receipts", store.ctx)
	for index := 0; index < store.plan.TotalBlocks; index++ {
		block, err := store.ReadMetadata(index)
		if err != nil {
			return zero, err
		}
		formalGLMPhase19StreamHashString(accumulator, block.ReceiptPairSHA256)
		formalGLMPhase19StreamHashString(fanIn, block.PairRoot)
		formalGLMPhase19StreamHashString(commitments, block.PairRoot)
		formalGLMPhase19StreamHashString(receipts, block.ReceiptPairSHA256)
	}
	return formalGLMPhase19BlockScheduleSummary{
		TotalBlocks:            store.plan.TotalBlocks,
		AccumulatorRoot:        hex.EncodeToString(accumulator.Sum(nil)),
		FanInTranscriptSHA256:  hex.EncodeToString(fanIn.Sum(nil)),
		BlockCommitmentSHA256:  hex.EncodeToString(commitments.Sum(nil)),
		BlockReceiptRootSHA256: hex.EncodeToString(receipts.Sum(nil)),
	}, nil
}

func (store *formalGLMPhase19StreamStore) Destroy() error {
	if store == nil {
		return nil
	}
	var closeErr error
	if store.file != nil {
		closeErr = store.file.Close()
		store.file = nil
	}
	removeErr := os.Remove(store.path)
	if os.IsNotExist(removeErr) {
		removeErr = nil
	}
	clear(store.key[:])
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}
