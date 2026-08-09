package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func formalGLMPhase19BoundedAccumulatorTestPlan(
	t testing.TB, blocks int) (formalGLMPhase15Plan,
	formalGLMPhase19Context, formalGLMPhase19AccumulatorPlan) {
	t.Helper()
	plan := formalGLMPhase15TestPlan(
		t, "binomial", 2, 1, 1, blocks, 2)
	ctx := formalGLMPhase19TestContext(t, plan)
	receipts := make([]string, blocks)
	for index := range receipts {
		digest := sha256.Sum256([]byte(t.Name() + "/receipt/" +
			string(rune(index))))
		receipts[index] = hexString(digest[:])
	}
	root := sha256.Sum256([]byte(t.Name() + "/accumulator-root"))
	return plan, ctx, formalGLMPhase19AccumulatorPlan{
		Version:                 formalGLMPhase19ExecVersion,
		ContextSHA256:           ctx.ContextSHA256ForPhase19(),
		BlockReceiptPairSHA256:  receipts,
		AccumulatorRoot:         hexString(root[:]),
		ExecutionValidSealed:    true,
		ExecutionValidityOpened: false,
		OpeningsPerformed:       0,
		ProductionReady:         false,
		verified:                true,
	}
}

func TestFormalGLMPhase19BoundedAccumulatorCircuitShapes(t *testing.T) {
	for _, count := range []int{1, 2, formalGLMPhase19AccumulatorMaxFanIn} {
		leaf, err := compileFormalGLMPhase19BoundedAccumulator("leaf", count)
		if err != nil {
			t.Fatalf("leaf %d: %v", count, err)
		}
		if got, want := int(leaf.Inputs[0].Type.Bits), (count+2)*8; got != want {
			t.Fatalf("leaf garbler bits %d want %d", got, want)
		}
		state, err := compileFormalGLMPhase19BoundedAccumulator("state", count)
		if err != nil {
			t.Fatalf("state %d: %v", count, err)
		}
		if got, want := int(state.Inputs[0].Type.Bits), (2*count+2)*8; got != want {
			t.Fatalf("state garbler bits %d want %d", got, want)
		}
	}
	if _, err := compileFormalGLMPhase19BoundedAccumulator(
		"leaf", formalGLMPhase19AccumulatorMaxFanIn+1); err == nil {
		t.Fatal("bounded accumulator accepted an oversized leaf circuit")
	}
	if _, err := compileFormalGLMPhase19BoundedAccumulator(
		"state", formalGLMPhase19AccumulatorMaxFanIn+1); err == nil {
		t.Fatal("bounded accumulator accepted an oversized state circuit")
	}
}

func TestFormalGLMPhase19BoundedAccumulatorPreservesGlobalValidity(t *testing.T) {
	const blocks = formalGLMPhase19AccumulatorMaxFanIn + 1
	for _, test := range []struct {
		name  string
		left  func([]byte)
		right func([]byte)
		want  byte
	}{
		{name: "no-active-row", want: 0},
		{name: "active-in-second-leaf", left: func(value []byte) {
			value[len(value)-1] = 1
		}, want: 1},
		{name: "invalid-first-leaf-cannot-hide-behind-active-second-leaf",
			left: func(value []byte) {
				value[0] = 2
				value[len(value)-1] = 1
			}, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, ctx, accumulator :=
				formalGLMPhase19BoundedAccumulatorTestPlan(t, blocks)
			leftShares := make([]byte, blocks)
			rightShares := make([]byte, blocks)
			if test.left != nil {
				test.left(leftShares)
			}
			if test.right != nil {
				test.right(rightShares)
			}
			backend := sha256.Sum256([]byte(t.Name() + "/backend"))
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(45 * time.Second))
			_ = right.SetDeadline(time.Now().Add(45 * time.Second))
			var garbler, evaluator formalGLMPhase19ExecutionSeal
			var garblerErr, evaluatorErr error
			var wait sync.WaitGroup
			wait.Add(2)
			go func() {
				defer wait.Done()
				garbler, garblerErr = formalGLMPhase19RunBoundedAccumulatorTree(
					left, plan, ctx, accumulator, attempt, "garbler",
					leftShares, backend)
			}()
			go func() {
				defer wait.Done()
				evaluator, evaluatorErr = formalGLMPhase19RunBoundedAccumulatorTree(
					right, plan, ctx, accumulator, attempt, "evaluator",
					rightShares, backend)
			}()
			wait.Wait()
			if garblerErr != nil || evaluatorErr != nil {
				t.Fatalf("garbler=%v evaluator=%v", garblerErr, evaluatorErr)
			}
			if got := garbler.share ^ evaluator.share; got != test.want {
				t.Fatalf("execution validity %d want %d", got, test.want)
			}
			if garbler.Receipt.SessionID != evaluator.Receipt.SessionID ||
				garbler.Receipt.AccumulatorRoot != accumulator.AccumulatorRoot ||
				evaluator.Receipt.AccumulatorRoot != accumulator.AccumulatorRoot {
				t.Fatal("bounded accumulator receipts changed the final session")
			}
		})
	}
}

func TestFormalGLMPhase19ExternalAccumulatorMatchesBoundedTree(t *testing.T) {
	const blocks = formalGLMPhase19AccumulatorMaxFanIn + 1
	plan, ctx, _ := formalGLMPhase19BoundedAccumulatorTestPlan(t, blocks)
	message := formalGLMPhase15AppendString(nil,
		formalGLMPhase19ExecDomain+"/plan")
	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	message = append(message, ctxDigest[:]...)
	for index := 0; index < blocks; index++ {
		receipt := sha256.Sum256([]byte(t.Name() + "/receipt/" +
			string(rune(index))))
		message = formalGLMPhase15AppendString(
			message, hex.EncodeToString(receipt[:]))
	}
	root := sha256.Sum256(message)
	backend := sha256.Sum256([]byte(t.Name() + "/backend"))
	accumulator, err := formalGLMPhase19BuildStreamAccumulatorPlan(
		ctx, formalGLMPhase19BlockScheduleSummary{
			TotalBlocks: blocks, AccumulatorRoot: hex.EncodeToString(root[:]),
		}, backend)
	if err != nil {
		t.Fatal(err)
	}
	leftShares := make([]byte, blocks)
	rightShares := make([]byte, blocks)
	leftShares[blocks-1] = 1
	workLeft, workRight := t.TempDir(), t.TempDir()
	for _, path := range []string{workLeft, workRight} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(45 * time.Second))
	_ = right.SetDeadline(time.Now().Add(45 * time.Second))
	var garbler, evaluator formalGLMPhase19ExecutionSeal
	var garblerErr, evaluatorErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		garbler, garblerErr = formalGLMPhase19RunBoundedAccumulatorExternal(
			left, plan, ctx, accumulator, workLeft,
			func(index int) (byte, error) { return leftShares[index], nil },
			attempt, "garbler", backend)
	}()
	go func() {
		defer wait.Done()
		evaluator, evaluatorErr = formalGLMPhase19RunBoundedAccumulatorExternal(
			right, plan, ctx, accumulator, workRight,
			func(index int) (byte, error) { return rightShares[index], nil },
			attempt, "evaluator", backend)
	}()
	wait.Wait()
	if garblerErr != nil || evaluatorErr != nil {
		t.Fatalf("garbler=%v evaluator=%v", garblerErr, evaluatorErr)
	}
	if got := garbler.share ^ evaluator.share; got != 1 {
		t.Fatalf("streamed execution validity %d want 1", got)
	}
	for _, dir := range []string{workLeft, workRight} {
		matches, err := filepath.Glob(
			filepath.Join(dir, "formal-phase19-acc-level-*.bin"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("external accumulator left private spill files: %v %v",
				matches, err)
		}
	}
}
