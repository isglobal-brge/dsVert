package main

import (
	"crypto/sha256"
	"math/big"
	"os"
	"path/filepath"
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

func TestFormalGLMPhase19StreamStoreRootedCreationPinsRockDirectory(
	t *testing.T,
) {
	bundle := formalGLMPhase19TestBuild(t, 3, 1, 1, nil)
	_, required, err := formalGLMPhase19StreamStoreRequiredBytes(bundle.plan)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	rock := filepath.Join(parent, "rock")
	if err := os.Mkdir(rock, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rock)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if _, err := newFormalGLMPhase19StreamStoreRootedV1(
		root, "../escape", required, bundle.plan, bundle.ctx,
		bundle.ctx.ComputePeers[0], bundle.key); err == nil {
		t.Fatal("rooted stream store accepted parent traversal")
	}
	if _, err := newFormalGLMPhase19StreamStoreRootedV1(
		root, filepath.Join(parent, "escape"), required, bundle.plan,
		bundle.ctx, bundle.ctx.ComputePeers[0], bundle.key); err == nil {
		t.Fatal("rooted stream store accepted an absolute path")
	}

	// The caller retains the opened Root. Renaming its pathname must not cause
	// the block store to appear under a replacement directory.
	anchored := filepath.Join(parent, "anchored")
	if err := os.Rename(rock, anchored); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rock, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newFormalGLMPhase19StreamStoreRootedV1(
		root, "blocks", required, bundle.plan, bundle.ctx,
		bundle.ctx.ComputePeers[0], bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(anchored, "blocks",
		formalGLMPhase19StreamStoreName)
	info, err := os.Lstat(storePath)
	if err != nil {
		t.Fatalf("rooted store was not created beneath the pinned directory: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || !exactGCPrivateOwnedRegular(info) {
		t.Fatal("rooted store created an unsafe private file")
	}
	if _, err := os.Stat(filepath.Join(rock, "blocks",
		formalGLMPhase19StreamStoreName)); !os.IsNotExist(err) {
		t.Fatalf("rooted store followed the replacement directory: %v", err)
	}
	if err := store.Destroy(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(anchored, "blocks",
		formalGLMPhase19StreamStoreName)); !os.IsNotExist(err) {
		t.Fatalf("rooted store did not remove its private file: %v", err)
	}
}
