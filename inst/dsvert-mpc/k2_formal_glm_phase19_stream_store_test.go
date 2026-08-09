package main

import (
	"crypto/sha256"
	"math/big"
	"os"
	"testing"
)

func TestFormalGLMPhase19StreamStoreAuthenticatesAndMatchesLegacyRoots(
	t *testing.T) {
	bundle := formalGLMPhase19TestBuild(t, 3, 1, 1, nil)
	attempt := sha256.Sum256([]byte(t.Name() + "/block-attempt"))
	session, err := formalGLMPhase19BlockSession(
		bundle.plan, bundle.ctx, bundle.pair, attempt, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	leftShares := make([]*big.Int, len(bundle.complete))
	rightShares := make([]*big.Int, len(bundle.complete))
	for index := range leftShares {
		leftShares[index] = new(big.Int).SetUint64(uint64(index + 1))
		rightShares[index] = new(big.Int).Sub(
			bundle.complete[index], leftShares[index])
		rightShares[index].Mod(rightShares[index], exactGCModulus(bundle.plan.RingBits))
	}
	left, err := formalGLMPhase19BuildMaskedBlock(
		bundle.plan, bundle.ctx, bundle.pair, session,
		bundle.ctx.ComputePeers[0], leftShares, 0, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	right, err := formalGLMPhase19BuildMaskedBlock(
		bundle.plan, bundle.ctx, bundle.pair, session,
		bundle.ctx.ComputePeers[1], rightShares, 1, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := formalGLMPhase19PairMaskedBlockReceipts(
		bundle.ctx, bundle.pair, left.Receipt, right.Receipt, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	_, required, err := formalGLMPhase19StreamStoreRequiredBytes(bundle.plan)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newFormalGLMPhase19StreamStore(
		dir, required, bundle.plan, bundle.ctx,
		bundle.ctx.ComputePeers[0], bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Destroy()
	if err := store.Append(left, pair); err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.ReadBlock(0)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ExecutionShare != left.executionShare ||
		loaded.PairRoot != pair.PairRoot ||
		loaded.ReceiptPairSHA256 != pair.ReceiptPairSHA256 ||
		len(loaded.TupleShares) != len(left.tupleShares) {
		t.Fatal("private stream store changed a protected block")
	}
	for index := range loaded.TupleShares {
		if loaded.TupleShares[index].Cmp(left.tupleShares[index]) != 0 {
			t.Fatalf("stored tuple share %d changed", index)
		}
	}
	exactGCZeroBigInts(loaded.TupleShares)
	summary, err := store.Summary()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := formalGLMPhase19BuildAccumulatorPlan(
		bundle.ctx, []formalGLMPhase19MaskedBlockReceiptPair{pair}, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	fanIn, commitments, receipts, err := formalGLMPhase19PublicExecutionRoots(
		bundle.ctx, []formalGLMPhase19MaskedBlockReceiptPair{pair}, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	if summary.AccumulatorRoot != legacy.AccumulatorRoot ||
		summary.FanInTranscriptSHA256 != fanIn ||
		summary.BlockCommitmentSHA256 != commitments ||
		summary.BlockReceiptRootSHA256 != receipts {
		t.Fatal("streaming roots differ from the reviewed in-memory roots")
	}
	if _, err := store.file.WriteAt([]byte{0xff}, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadMetadata(0); err == nil {
		t.Fatal("private stream store accepted a modified share record")
	}
}
