package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
)

func formalGLMPhase19TestContext(t testing.TB, plan formalGLMPhase15Plan) formalGLMPhase19Context {
	t.Helper()
	pre := sha256.Sum256([]byte("phase19/pre/" + t.Name()))
	root := sha256.Sum256([]byte("phase19/materialization/" + t.Name()))
	ctx, err := formalGLMPhase19BuildContext(plan, hexString(pre[:]), hexString(root[:]))
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestFormalGLMPhase19CircuitsCompileForK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		plan := formalGLMPhase15TestPlan(t, "binomial", custodians, 1, 1, 1, 2)
		ctx := formalGLMPhase19TestContext(t, plan)
		if _, err := compileFormalGLMPhase19Block(plan, ctx, 0); err != nil {
			t.Fatalf("K=%d: %v", custodians, err)
		}
	}
	for coefficients := 2; coefficients <= formalGLMPhase1MaxCoefficients; coefficients++ {
		policy := formalGLMPhase15TestPolicy("binomial", 3, 1, coefficients)
		policy.LinkKnots = []string{"-8192", "0", "8192"}
		policy.LinkValues = []string{"128", "128", "128"}
		policy.LinkSlopes = []string{"0", "0"}
		runID := sha256.Sum256([]byte("phase19/p-shape/" + string(rune('0'+coefficients))))
		plan, err := buildFormalGLMPhase15Plan(policy, 1, 2,
			formalGLMPhase15TestOwners(policy), hexString(runID[:]))
		if err != nil {
			t.Fatalf("p=%d plan: %v", coefficients, err)
		}
		ctx := formalGLMPhase19TestContext(t, plan)
		if _, err = compileFormalGLMPhase19Block(plan, ctx, 0); err != nil {
			t.Fatalf("p=%d: %v", coefficients, err)
		}
	}
}

type formalGLMPhase19TestBundle struct {
	plan        formalGLMPhase15Plan
	ctx         formalGLMPhase19Context
	key         [32]byte
	left        formalGLMPhase19FanInResult
	right       formalGLMPhase19FanInResult
	pair        formalGLMPhase19PairedFanIn
	complete    []*big.Int
	sourceLeft  []formalGLMPhase19VerifiedSourceBlock
	sourceRight []formalGLMPhase19VerifiedSourceBlock
}

type formalGLMPhase19TestMutation func(source, recipient, row int,
	coordinate []*big.Int, validity *byte, gate *byte, consensus *[32]byte)

func formalGLMPhase19TestBuild(t testing.TB, custodians, blockCapacity,
	total int, mutate formalGLMPhase19TestMutation) formalGLMPhase19TestBundle {
	return formalGLMPhase19TestBuildFamily(
		t, "binomial", custodians, blockCapacity, total, mutate)
}

func formalGLMPhase19TestBuildFamily(t testing.TB, family string,
	custodians, blockCapacity, total int,
	mutate formalGLMPhase19TestMutation) formalGLMPhase19TestBundle {

	t.Helper()
	plan := formalGLMPhase15TestPlan(t, family, custodians,
		blockCapacity, 1, total, 2)
	ctx := formalGLMPhase19TestContext(t, plan)
	key := sha256.Sum256([]byte("phase19/backend-key/" + t.Name()))
	complete := formalGLMPhase15TestBlock(
		plan, formalGLMPhase15TestInput(plan), 0)
	rng := rand.New(rand.NewSource(1900 + int64(custodians*10+blockCapacity)))
	byRecipient := map[string][]formalGLMPhase19VerifiedSourceBlock{
		ctx.ComputePeers[0]: {}, ctx.ComputePeers[1]: {},
	}
	for sourceIndex, source := range ctx.CustodianPeers {
		local := make([]*big.Int, len(complete))
		for i := range local {
			local[i] = new(big.Int)
			if plan.CoordinateOwners[i%ctx.CoordinatesPerRow] == source {
				local[i].Set(complete[i])
			}
		}
		leftCoordinates, rightCoordinates := exactGCTestSplit(rng, local, plan.RingBits)
		validityLeft := make([]byte, plan.BlockCapacity)
		validityRight := make([]byte, plan.BlockCapacity)
		for row := 0; row < plan.BlockCapacity; row++ {
			bit := byte(0)
			if row < total {
				bit = 1
			}
			validityLeft[row] = byte(rng.Intn(2))
			validityRight[row] = validityLeft[row] ^ bit
		}
		gateLeft := byte(rng.Intn(2))
		gateRight := gateLeft ^ 1
		consensus := sha256.Sum256([]byte("phase19/private-consensus/" + t.Name()))
		var consensusLeft, consensusRight [32]byte
		for i := range consensusLeft {
			consensusLeft[i] = byte(rng.Intn(256))
			consensusRight[i] = consensusLeft[i] ^ consensus[i]
		}
		pairCommitment := sha256Hex([]byte("phase19/pair/" + t.Name() + "/" + source))
		for recipientIndex, recipient := range ctx.ComputePeers {
			coordinates := leftCoordinates
			validity := append([]byte(nil), validityLeft...)
			gate := gateLeft
			if recipientIndex == 1 {
				coordinates = rightCoordinates
				validity = append([]byte(nil), validityRight...)
				gate = gateRight
			}
			localConsensus := consensusLeft
			if recipientIndex == 1 {
				localConsensus = consensusRight
			}
			for row := 0; row < plan.BlockCapacity; row++ {
				if mutate != nil {
					mutate(sourceIndex, recipientIndex, row, coordinates,
						&validity[row], &gate, &localConsensus)
				}
			}
			blockCommitment := sha256Hex([]byte("phase19/block/" + t.Name() +
				"/" + source + "/" + recipient))
			sealed, err := formalGLMPhase19SealSourceBlock(
				plan, ctx, source, recipient, 0, coordinates, validity,
				gate, localConsensus, pairCommitment, blockCommitment, key)
			if err != nil {
				t.Fatal(err)
			}
			byRecipient[recipient] = append(byRecipient[recipient], sealed)
		}
	}
	left, err := formalGLMPhase19FanIn(plan, ctx, ctx.ComputePeers[0], 0,
		byRecipient[ctx.ComputePeers[0]], newFormalGLMPhase19ReplayLedger(), key)
	if err != nil {
		t.Fatal(err)
	}
	right, err := formalGLMPhase19FanIn(plan, ctx, ctx.ComputePeers[1], 0,
		byRecipient[ctx.ComputePeers[1]], newFormalGLMPhase19ReplayLedger(), key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := formalGLMPhase19PairFanIn(ctx, left.Receipt, right.Receipt, key)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMPhase19TestBundle{
		plan: plan, ctx: ctx, key: key, left: left, right: right,
		pair: pair, complete: complete,
		sourceLeft:  byRecipient[ctx.ComputePeers[0]],
		sourceRight: byRecipient[ctx.ComputePeers[1]],
	}
}

func formalGLMPhase19TestDirect(t testing.TB,
	bundle formalGLMPhase19TestBundle) ([]*big.Int, bool) {

	t.Helper()
	layout, err := formalGLMPhase19Layout(bundle.plan, bundle.ctx)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1919))
	masks := make([]*big.Int, layout.CoordinateCount)
	for i := range masks {
		masks[i] = exactGCTestRandomResidue(rng, bundle.plan.RingBits)
	}
	executionMask := byte(rng.Intn(2))
	g, err := formalGLMPhase19GarblerInputValues(bundle.plan, bundle.ctx,
		bundle.pair, bundle.left, masks, executionMask, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	e, err := formalGLMPhase19LocalInputValues(bundle.plan, bundle.ctx,
		bundle.pair, bundle.right, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	circ, err := compileFormalGLMPhase19Block(
		bundle.plan, bundle.ctx, bundle.pair.BlockIndex)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := circ.Compute([]*big.Int{
		exactGCPackChunks(g, bundle.plan.ContainerBits),
		exactGCPackChunks(e, bundle.plan.ContainerBits),
	})
	if err != nil || len(packed) != 1 {
		if err == nil {
			t.Fatal("unexpected Phase-1.9 circuit output arity")
		}
		t.Fatal(err)
	}
	evaluator, executionEvaluator, err := formalGLMPhase19DecodeCircuitOutput(
		packed[0], layout.CoordinateCount, bundle.plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]*big.Int, layout.CoordinateCount)
	modulus := exactGCModulus(bundle.plan.RingBits)
	for i := range result {
		result[i] = new(big.Int).Add(masks[i], evaluator[i])
		result[i].Mod(result[i], modulus)
	}
	return result, executionMask^executionEvaluator == 1
}

func formalGLMPhase19AllZero(values []*big.Int) bool {
	for _, value := range values {
		if value.Sign() != 0 {
			return false
		}
	}
	return true
}

func formalGLMPhase19TestFinalReceipts(t testing.TB,
	plan formalGLMPhase15Plan) ([]formalGLMPhase15StepReceipt,
	map[string]ed25519.PublicKey, string) {

	t.Helper()
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	attempt := sha256.Sum256([]byte("phase19/final-receipt/" + t.Name()))
	transcript := sha256Hex([]byte("phase19/final-checkpoint-transcript/" + t.Name()))
	receipts := make([]formalGLMPhase15StepReceipt, 2)
	for i, peer := range plan.Kernel.ComputePeers {
		receipt := formalGLMPhase15StepReceipt{
			Version:          formalGLMPhase15ReceiptVersion,
			PlanSHA256:       hexString(planDigest[:]),
			Peer:             peer,
			StepIndex:        plan.ScheduleSteps - 1,
			AttemptID:        hexString(attempt[:]),
			StateSHA256:      sha256Hex([]byte("phase19/sealed-state/" + peer + "/" + t.Name())),
			TranscriptSHA256: transcript,
		}
		receipt.Signature = ed25519.Sign(
			identities.private[peer], formalGLMPhase15ReceiptUnsigned(receipt))
		receipts[i] = receipt
	}
	return receipts, identities.public, transcript
}

func TestFormalGLMPhase19ExactAllKFanInAndFullTupleMask(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			valid := formalGLMPhase19TestBuild(t, custodians, 1, 1, nil)
			got, executionValid := formalGLMPhase19TestDirect(t, valid)
			if !executionValid || len(got) != len(valid.complete) {
				t.Fatal("valid all-K block did not retain hidden execution validity")
			}
			for i := range got {
				if got[i].Cmp(valid.complete[i]) != 0 {
					t.Fatalf("coordinate %d changed: got %s want %s", i, got[i], valid.complete[i])
				}
			}

			invalidLane := formalGLMPhase19TestBuild(t, custodians, 1, 1,
				func(source, recipient, row int, _ []*big.Int, validity, _ *byte, _ *[32]byte) {
					if source == custodians-1 && recipient == 1 && row == 0 {
						*validity ^= 1
					}
				})
			got, executionValid = formalGLMPhase19TestDirect(t, invalidLane)
			if executionValid || !formalGLMPhase19AllZero(got) {
				t.Fatal("one false custodian lane did not mask the complete p+3 tuple")
			}

			invalidBit := formalGLMPhase19TestBuild(t, custodians, 1, 1,
				func(source, recipient, row int, _ []*big.Int, validity, _ *byte, _ *[32]byte) {
					if source == 0 && recipient == 0 && row == 0 {
						*validity = 2
					}
				})
			got, executionValid = formalGLMPhase19TestDirect(t, invalidBit)
			if executionValid || !formalGLMPhase19AllZero(got) {
				t.Fatal("out-of-domain validity share did not fail closed inside GC")
			}

			consensusMismatch := formalGLMPhase19TestBuild(t, custodians, 1, 1,
				func(source, recipient, row int, _ []*big.Int, _ *byte, _ *byte, consensus *[32]byte) {
					if source == custodians-1 && recipient == 1 && row == 0 {
						*consensus = sha256.Sum256([]byte("different private consensus"))
					}
				})
			got, executionValid = formalGLMPhase19TestDirect(t, consensusMismatch)
			if executionValid || !formalGLMPhase19AllZero(got) {
				t.Fatal("cross-peer consensus mismatch did not mask the complete tuple")
			}

			zeroConsensus := formalGLMPhase19TestBuild(t, custodians, 1, 1,
				func(_, _, _ int, _ []*big.Int, _ *byte, _ *byte, consensus *[32]byte) {
					*consensus = [32]byte{}
				})
			got, executionValid = formalGLMPhase19TestDirect(t, zeroConsensus)
			if executionValid || !formalGLMPhase19AllZero(got) {
				t.Fatal("absent private consensus did not fail closed inside GC")
			}

			falseGate := formalGLMPhase19TestBuild(t, custodians, 1, 1,
				func(source, recipient, row int, _ []*big.Int, _ *byte, gate *byte, _ *[32]byte) {
					if source == 0 && recipient == 1 && row == 0 {
						*gate ^= 1
					}
				})
			got, executionValid = formalGLMPhase19TestDirect(t, falseGate)
			if executionValid || !formalGLMPhase19AllZero(got) {
				t.Fatal("one rejected alignment gate did not mask the complete tuple")
			}

			invalidGate := formalGLMPhase19TestBuild(t, custodians, 1, 1,
				func(source, recipient, row int, _ []*big.Int, _ *byte, gate *byte, _ *[32]byte) {
					if source == 0 && recipient == 0 && row == 0 {
						*gate = 2
					}
				})
			got, executionValid = formalGLMPhase19TestDirect(t, invalidGate)
			if executionValid || !formalGLMPhase19AllZero(got) {
				t.Fatal("invalid alignment-gate share did not fail closed inside GC")
			}
		})
	}
}

func TestFormalGLMPhase19PaddingAndOutOfDomainNeverWrap(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			bundle := formalGLMPhase19TestBuild(t, custodians, 2, 1, nil)
			got, executionValid := formalGLMPhase19TestDirect(t, bundle)
			if !executionValid || !formalGLMPhase19AllZero(got[bundle.ctx.CoordinatesPerRow:]) {
				t.Fatal("public padding slot was not fully masked")
			}

			for _, coordinate := range []int{0, 1, 2, 3} {
				outOfDomain := formalGLMPhase19TestBuild(t, custodians, 1, 1,
					func(source, recipient, row int, coordinates []*big.Int, _ *byte, _ *byte, _ *[32]byte) {
						if source == 0 && recipient == 0 && row == 0 {
							delta := big.NewInt(1)
							if coordinate == 0 || coordinate == 3 {
								// Force a huge signed representative for weight/offset.
								delta = exactGCMaxSigned(128)
							}
							coordinates[coordinate].Add(coordinates[coordinate], delta)
							coordinates[coordinate].Mod(coordinates[coordinate], exactGCModulus(128))
						}
					})
				got, executionValid = formalGLMPhase19TestDirect(t, outOfDomain)
				if executionValid || !formalGLMPhase19AllZero(got) {
					t.Fatalf("out-of-domain coordinate %d wrapped into an accepted tuple", coordinate)
				}
			}
		})
	}
}

func TestFormalGLMPhase19PoissonIntegerOutcomeDomain(t *testing.T) {
	valid := formalGLMPhase19TestBuildFamily(t, "poisson", 3, 1, 1, nil)
	got, executionValid := formalGLMPhase19TestDirect(t, valid)
	if !executionValid {
		t.Fatal("valid Poisson tuple was rejected")
	}
	for i := range got {
		if got[i].Cmp(valid.complete[i]) != 0 {
			t.Fatalf("valid Poisson coordinate %d changed", i)
		}
	}
	fractional := formalGLMPhase19TestBuildFamily(t, "poisson", 3, 1, 1,
		func(source, recipient, row int, coordinates []*big.Int, _ *byte, _ *byte, _ *[32]byte) {
			if source == 0 && recipient == 0 && row == 0 {
				coordinates[2].Add(coordinates[2], big.NewInt(1))
				coordinates[2].Mod(coordinates[2], exactGCModulus(128))
			}
		})
	got, executionValid = formalGLMPhase19TestDirect(t, fractional)
	if executionValid || !formalGLMPhase19AllZero(got) {
		t.Fatal("fractional Poisson outcome did not mask the complete tuple")
	}
}

func TestFormalGLMPhase19FanInRejectsMissingDuplicateTamperReplayAndTypeConfusion(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			bundle := formalGLMPhase19TestBuild(t, custodians, 1, 1, nil)
			blocks := append([]formalGLMPhase19VerifiedSourceBlock(nil), bundle.sourceLeft...)
			if _, err := formalGLMPhase19FanIn(bundle.plan, bundle.ctx,
				bundle.ctx.ComputePeers[0], 0, blocks[:len(blocks)-1],
				newFormalGLMPhase19ReplayLedger(), bundle.key); err == nil {
				t.Fatal("missing custodian was accepted")
			}
			duplicate := append([]formalGLMPhase19VerifiedSourceBlock(nil), blocks...)
			duplicate[len(duplicate)-1] = duplicate[0]
			if _, err := formalGLMPhase19FanIn(bundle.plan, bundle.ctx,
				bundle.ctx.ComputePeers[0], 0, duplicate,
				newFormalGLMPhase19ReplayLedger(), bundle.key); err == nil {
				t.Fatal("duplicate custodian was accepted")
			}
			tampered := blocks[0]
			tampered.validityShares = append([]byte(nil), tampered.validityShares...)
			tampered.validityShares[0] ^= 1
			if err := formalGLMPhase19VerifySourceBlock(
				bundle.plan, bundle.ctx, tampered, bundle.key); err == nil {
				t.Fatal("post-authentication private tamper was accepted")
			}
			typeConfused := blocks[0]
			typeConfused.Version = formalGLMPhase19FanInVersion
			if err := formalGLMPhase19VerifySourceBlock(
				bundle.plan, bundle.ctx, typeConfused, bundle.key); err == nil {
				t.Fatal("type-confused block was accepted")
			}
			swapped := blocks[0]
			swapped.Recipient = bundle.ctx.ComputePeers[1]
			if err := formalGLMPhase19VerifySourceBlock(
				bundle.plan, bundle.ctx, swapped, bundle.key); err == nil {
				t.Fatal("recipient-swapped block was accepted")
			}
			tamperedReceipt := bundle.left.Receipt
			tamperedReceipt.PairCommitments = make(map[string]string,
				len(bundle.left.Receipt.PairCommitments))
			for source, value := range bundle.left.Receipt.PairCommitments {
				tamperedReceipt.PairCommitments[source] = value
			}
			tamperedReceipt.PairCommitments[bundle.ctx.CustodianPeers[0]] =
				sha256Hex([]byte("tampered public pair commitment"))
			if _, err := formalGLMPhase19PairFanIn(
				bundle.ctx, tamperedReceipt, bundle.right.Receipt, bundle.key); err == nil {
				t.Fatal("tampered public fan-in receipt was accepted")
			}
			if _, err := formalGLMPhase19PairFanIn(
				bundle.ctx, bundle.right.Receipt, bundle.left.Receipt, bundle.key); err == nil {
				t.Fatal("swapped designated compute-peer pair was accepted")
			}
			ledger := newFormalGLMPhase19ReplayLedger()
			if _, err := formalGLMPhase19FanIn(bundle.plan, bundle.ctx,
				bundle.ctx.ComputePeers[0], 0, blocks, ledger, bundle.key); err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMPhase19FanIn(bundle.plan, bundle.ctx,
				bundle.ctx.ComputePeers[0], 0, blocks, ledger, bundle.key); err != nil {
				t.Fatalf("identical retry was not idempotent: %v", err)
			}
			conflicting := append([]formalGLMPhase19VerifiedSourceBlock(nil), blocks...)
			changed := conflicting[0]
			changed.BlockCommitment = sha256Hex([]byte("conflicting authenticated retry"))
			message, err := formalGLMPhase19SourceBlockMessage(bundle.plan, changed)
			if err != nil {
				t.Fatal(err)
			}
			changed.seal = formalGLMPhase19MAC(bundle.key, formalGLMPhase19BlockDomain, message)
			conflicting[0] = changed
			if _, err := formalGLMPhase19FanIn(bundle.plan, bundle.ctx,
				bundle.ctx.ComputePeers[0], 0, conflicting, ledger, bundle.key); err == nil ||
				!strings.Contains(err.Error(), "conflicting") {
				t.Fatal("conflicting authenticated replay was accepted")
			}
		})
	}
}

func TestFormalGLMPhase19ExactGCNetworkPathIsExecutable(t *testing.T) {
	bundle := formalGLMPhase19TestBuild(t, 3, 1, 1, nil)
	attempt := sha256.Sum256([]byte("phase19/network/attempt"))
	session, err := formalGLMPhase19BlockSession(
		bundle.plan, bundle.ctx, bundle.pair, attempt, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	leftConn, rightConn := net.Pipe()
	defer leftConn.Close()
	defer rightConn.Close()
	var left, right formalGLMPhase19MaskedBlock
	var leftErr, rightErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		left, leftErr = formalGLMPhase19RunGarbler(leftConn, bundle.plan,
			bundle.ctx, bundle.pair, bundle.left, session, bundle.key)
	}()
	go func() {
		defer wg.Done()
		right, rightErr = formalGLMPhase19RunEvaluator(rightConn, bundle.plan,
			bundle.ctx, bundle.pair, bundle.right, session, bundle.key)
	}()
	wg.Wait()
	if leftErr != nil || rightErr != nil {
		t.Fatalf("garbler=%v evaluator=%v", leftErr, rightErr)
	}
	if err := formalGLMPhase19VerifyMaskedBlock(
		bundle.plan, bundle.ctx, bundle.pair, left, bundle.key); err != nil {
		t.Fatal(err)
	}
	if err := formalGLMPhase19VerifyMaskedBlock(
		bundle.plan, bundle.ctx, bundle.pair, right, bundle.key); err != nil {
		t.Fatal(err)
	}
	modulus := exactGCModulus(bundle.plan.RingBits)
	for i := range bundle.complete {
		got := new(big.Int).Add(left.tupleShares[i], right.tupleShares[i])
		got.Mod(got, modulus)
		if got.Cmp(bundle.complete[i]) != 0 {
			t.Fatalf("network output coordinate %d mismatch", i)
		}
	}
	if left.executionShare^right.executionShare != 1 {
		t.Fatal("network path lost hidden execution-valid bit")
	}
	blockReceiptPair, err := formalGLMPhase19PairMaskedBlockReceipts(
		bundle.ctx, bundle.pair, left.Receipt, right.Receipt, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	accumulator, err := formalGLMPhase19BuildAccumulatorPlan(
		bundle.ctx, []formalGLMPhase19MaskedBlockReceiptPair{blockReceiptPair}, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	accAttempt := sha256.Sum256([]byte("phase19/network/accumulator-attempt"))
	accSession, err := formalGLMPhase19AccumulatorSession(
		bundle.plan, bundle.ctx, accumulator, accAttempt, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	accLeftConn, accRightConn := net.Pipe()
	defer accLeftConn.Close()
	defer accRightConn.Close()
	var accLeft, accRight formalGLMPhase19ExecutionSeal
	leftErr, rightErr = nil, nil
	wg.Add(2)
	go func() {
		defer wg.Done()
		accLeft, leftErr = formalGLMPhase19RunAccumulatorGarbler(
			accLeftConn, bundle.plan, bundle.ctx, accumulator,
			[]formalGLMPhase19MaskedBlockReceiptPair{blockReceiptPair},
			[]formalGLMPhase19MaskedBlock{left}, accSession, bundle.key)
	}()
	go func() {
		defer wg.Done()
		accRight, rightErr = formalGLMPhase19RunAccumulatorEvaluator(
			accRightConn, bundle.plan, bundle.ctx, accumulator,
			[]formalGLMPhase19MaskedBlockReceiptPair{blockReceiptPair},
			[]formalGLMPhase19MaskedBlock{right}, accSession, bundle.key)
	}()
	wg.Wait()
	if leftErr != nil || rightErr != nil {
		t.Fatalf("accumulator garbler=%v evaluator=%v", leftErr, rightErr)
	}
	if err := formalGLMPhase19VerifyExecutionSeal(
		bundle.ctx, accumulator, accLeft, bundle.key); err != nil {
		t.Fatal(err)
	}
	if err := formalGLMPhase19VerifyExecutionSeal(
		bundle.ctx, accumulator, accRight, bundle.key); err != nil {
		t.Fatal(err)
	}
	if accLeft.share^accRight.share != 1 {
		t.Fatal("execution accumulator silently accepted a zero dataset")
	}
	executionPair, err := formalGLMPhase19PairExecutionReceipts(
		bundle.ctx, accumulator, accLeft.Receipt, accRight.Receipt, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	finalReceipts, pins, checkpointTranscript :=
		formalGLMPhase19TestFinalReceipts(t, bundle.plan)
	evidence := formalGLMPhase19ExecutionEvidence{
		Phase15ExecutionTranscriptSHA256: sha256Hex([]byte("phase19/phase15-transcript")),
		FinalCheckpointTranscriptSHA256:  checkpointTranscript,
		WorkerTranscriptSHA256:           sha256Hex([]byte("phase19/worker-transcript")),
		CheckpointEvidenceSHA256:         sha256Hex([]byte("phase19/private-checkpoint-evidence")),
	}
	token, err := formalGLMPhase19BuildPostExecutionToken(
		bundle.plan, bundle.ctx,
		[]formalGLMPhase19MaskedBlockReceiptPair{blockReceiptPair},
		accumulator, executionPair, finalReceipts, pins, evidence, bundle.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMPhase19VerifyPostExecutionToken(token, bundle.key); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	privateConsensus := sha256Hex([]byte("phase19/private-consensus/" + t.Name()))
	for _, forbidden := range []string{
		privateConsensus, evidence.CheckpointEvidenceSHA256,
		`"execution_valid":`, `"state_sha256":`, "accepted_phase19", "rejected_phase19",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("post token exposed forbidden private material %q", forbidden)
		}
	}
	if token.ProtectedDataE2EVerified || token.OpeningAuthorized ||
		token.ProductionReady || token.OpeningsPerformed != 0 ||
		token.ExecutionValidityOpened || len(token.RemainingBlockers) != 2 {
		t.Fatal("post token overstated its release or production status")
	}
	tamperedToken := token
	tamperedToken.RunID = sha256Hex([]byte("replayed run"))
	if err := formalGLMPhase19VerifyPostExecutionToken(
		tamperedToken, bundle.key); err == nil {
		t.Fatal("run-replayed post token was accepted")
	}
}

func TestFormalGLMPhase19ExecutionAccumulatorIsExactAndFailClosed(t *testing.T) {
	circ, err := compileFormalGLMPhase19Accumulator(3)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		g    []byte
		e    []byte
		mask byte
		want bool
	}{
		{name: "one active", g: []byte{0, 1, 0}, e: []byte{0, 0, 0}, mask: 1, want: true},
		{name: "all zero", g: []byte{1, 0, 1}, e: []byte{1, 0, 1}, mask: 0, want: false},
		{name: "invalid share", g: []byte{0, 2, 0}, e: []byte{0, 1, 0}, mask: 1, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := make([]*big.Int, 0, 4)
			e := make([]*big.Int, 0, 3)
			for _, value := range test.g {
				g = append(g, new(big.Int).SetUint64(uint64(value)))
			}
			g = append(g, new(big.Int).SetUint64(uint64(test.mask)))
			for _, value := range test.e {
				e = append(e, new(big.Int).SetUint64(uint64(value)))
			}
			out, err := circ.Compute([]*big.Int{
				exactGCPackChunks(g, 8), exactGCPackChunks(e, 8),
			})
			if err != nil || len(out) != 1 {
				t.Fatal(err)
			}
			got := test.mask^byte(out[0].Uint64()) == 1
			if got != test.want {
				t.Fatalf("got %v want %v", got, test.want)
			}
		})
	}
}
