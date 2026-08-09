package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"path/filepath"
	"testing"
)

func formalGLMPhase15TestExecutionTranscript(t testing.TB,
	plan formalGLMPhase15Plan, tag string) (string, [32]byte) {
	t.Helper()
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	root := formalGLMPhase15InitialTranscript(hexString(planDigest[:]))
	master := sha256.Sum256([]byte("phase15-dp-transcript-master/" + tag))
	var finalAttempt [32]byte
	for index := 0; index < plan.ScheduleSteps; index++ {
		iteration := index / (plan.TotalBlocks + 1)
		within := index % (plan.TotalBlocks + 1)
		step := formalGLMPhase15Step{Iteration: iteration, BlockIndex: within}
		if within == plan.TotalBlocks {
			step.BlockIndex = -1
		} else {
			step.SourceRoot = sha256Hex([]byte(
				tag + "/fanin/" + string(rune('0'+within))))
		}
		attempt := sha256.Sum256([]byte(
			tag + "/attempt/" + string(rune(index+1))))
		session, err := formalGLMPhase15StepSession(plan, step, attempt, master)
		if err != nil {
			t.Fatal(err)
		}
		root, err = formalGLMPhase15AdvanceTranscript(root, index, session.Purpose)
		if err != nil {
			t.Fatal(err)
		}
		finalAttempt = attempt
	}
	return root, finalAttempt
}

func formalGLMPhase15TestFinalReceipts(t testing.TB,
	plan formalGLMPhase15Plan, identities formalGLMPhase15TestIdentities,
	transcript string, attempt [32]byte,
	beta map[string][]*big.Int) []formalGLMPhase15StepReceipt {
	t.Helper()
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]formalGLMPhase15StepReceipt, 0, 2)
	for _, peer := range plan.Kernel.ComputePeers {
		encoded, err := formalGLMPhase15EncodeStateValues(beta[peer], plan.RingBits)
		if err != nil {
			t.Fatal(err)
		}
		receipt := formalGLMPhase15StepReceipt{
			Version:    formalGLMPhase15ReceiptVersion,
			PlanSHA256: hexString(planDigest[:]), Peer: peer,
			StepIndex:        plan.ScheduleSteps - 1,
			AttemptID:        hexString(attempt[:]),
			StateSHA256:      formalGLMPhase15StateDigest(encoded, nil),
			TranscriptSHA256: transcript,
		}
		receipt.Signature = ed25519.Sign(
			identities.private[peer], formalGLMPhase15ReceiptUnsigned(receipt))
		result = append(result, receipt)
	}
	return []formalGLMPhase15StepReceipt{result[1], result[0]}
}

func formalGLMPhase15TestBridgeContext(t testing.TB,
	plan formalGLMPhase15Plan, tag string) (
	formalGLMPhase15TestIdentities, []formalGLMPhase15StepReceipt,
	map[string][]*big.Int) {
	t.Helper()
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.ComputePeers)
	beta := make(map[string][]*big.Int, 2)
	for peerIndex, peer := range plan.Kernel.ComputePeers {
		beta[peer] = make([]*big.Int, plan.Kernel.CoefficientCount)
		for coordinate := range beta[peer] {
			beta[peer][coordinate] = big.NewInt(
				int64(17 + 13*peerIndex + coordinate))
		}
	}
	transcript, attempt := formalGLMPhase15TestExecutionTranscript(t, plan, tag)
	receipts := formalGLMPhase15TestFinalReceipts(
		t, plan, identities, transcript, attempt, beta)
	return identities, receipts, beta
}

func TestFormalGLMPhase15DPBridgeUsesOnlyMachineProvenSensitivity(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 3, 1, 2, 2, 2)
	identities, receipts, _ := formalGLMPhase15TestBridgeContext(
		t, plan, "phase15-dp-plan")
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, 6)
	if err != nil {
		t.Fatal(err)
	}
	// B=512 source steps, d=4, so each translated coordinate spans 256
	// release steps and the box L2 diameter is ceil(sqrt(2*256^2))=363.
	// The exact fixed-point recurrence proves source deltas [65,65]; signed
	// floor lifts those coordinatewise to [17,17], hence ceil(sqrt(578))=25.
	if bridge.QuantizationShift != 2 ||
		len(bridge.ShiftedUpperBounds) != 2 ||
		bridge.ShiftedUpperBounds[0] != "256" ||
		bridge.ShiftedUpperBounds[1] != "256" ||
		bridge.UniversalSensitivity.Status != "machine_proven" ||
		bridge.UniversalSensitivity.BoundSteps != "363" ||
		bridge.TightSensitivity.Status != "machine_proven" ||
		bridge.TightSensitivity.BoundSteps != "25" ||
		bridge.SelectedSensitivitySteps != "25" ||
		bridge.SelectedSensitivityProof != formalGLMPhase15DPTightProof ||
		bridge.SelectedSensitivityCertificate.SelectedBoundSteps != "25" ||
		bridge.SelectedSensitivityCertificate.RecurrenceL2Squared != "578" ||
		!formalGLMIsSHA256(bridge.SelectedSensitivityCertificateSHA256) ||
		bridge.ProductionReady {
		t.Fatalf("unexpected DP bridge certificate: %+v", bridge)
	}
	// The endpoint distance attains the advertised per-coordinate box ranges.
	distanceSquared := new(big.Int)
	for _, value := range bridge.ShiftedUpperBounds {
		coordinate, _ := new(big.Int).SetString(value, 10)
		distanceSquared.Add(distanceSquared,
			new(big.Int).Mul(coordinate, coordinate))
	}
	if formalGLMPhase15CeilSqrt(distanceSquared).String() !=
		bridge.UniversalSensitivity.BoundSteps {
		t.Fatalf("box L2 diameter %s != universal sensitivity %s",
			distanceSquared, bridge.UniversalSensitivity.BoundSteps)
	}

	forged := bridge
	forged.TightSensitivity.BoundSteps = "1"
	forged.SelectedSensitivitySteps = "1"
	forged.SelectedSensitivityProof = formalGLMPhase15DPTightProof
	if err := validateFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, forged); err == nil {
		t.Fatal("an asserted but unverified tight sensitivity was accepted")
	}
	forged = bridge
	forged.SelectedSensitivityCertificate.Recurrence = append(
		[]formalGLMPhase15DPSensitivityStep(nil),
		bridge.SelectedSensitivityCertificate.Recurrence...)
	forged.SelectedSensitivityCertificate.Recurrence[1].MuDeltaUpper = "0"
	if err := validateFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, forged); err == nil {
		t.Fatal("a mutated fixed-point recurrence certificate was accepted")
	}
	_, err = formalGLMPhase15CompileAuthenticatedDPRelease(
		plan, receipts, identities.public, bridge)
	var blocker *formalGLMPhase15DPReleaseBlocker
	if !errors.As(err, &blocker) ||
		blocker.Code != formalGLMPhase15DPReleaseBlockerCode ||
		len(blocker.Missing) != 2 {
		t.Fatalf("expected typed common-release blocker, got %T %v", err, err)
	}
}

func TestFormalGLMPhase15SignedFloorL2IncludesSimultaneousBoundaryCrossings(t *testing.T) {
	// With d=10, both (9,9)->(10,10) and (-1,-1)->(0,0) move one
	// lattice step in each coordinate. ceil(sqrt(2)/10)=1 is therefore an
	// invalid vector bound; coordinatewise lifting gives ceil(sqrt(2))=2.
	quantized, squared, bound, err := formalGLMPhase15QuantizedL2Upper(
		[]*big.Int{big.NewInt(1), big.NewInt(1)}, big.NewInt(10),
		[]*big.Int{big.NewInt(100), big.NewInt(100)})
	if err != nil {
		t.Fatal(err)
	}
	if quantized[0].String() != "1" || quantized[1].String() != "1" ||
		squared.String() != "2" || bound.String() != "2" {
		t.Fatalf("signed-floor amplification was omitted: q=%v sq=%s bound=%s",
			quantized, squared, bound)
	}
	maxSquared := int64(0)
	for x0 := int64(-12); x0 <= 12; x0++ {
		for x1 := int64(-12); x1 <= 12; x1++ {
			for y0 := x0 - 1; y0 <= x0+1; y0++ {
				for y1 := x1 - 1; y1 <= x1+1; y1++ {
					if absInt64(x0-y0) > 1 || absInt64(x1-y1) > 1 {
						continue
					}
					d0 := floorDivInt64(x0, 10) - floorDivInt64(y0, 10)
					d1 := floorDivInt64(x1, 10) - floorDivInt64(y1, 10)
					candidate := d0*d0 + d1*d1
					if candidate > maxSquared {
						maxSquared = candidate
					}
				}
			}
		}
	}
	if maxSquared != 2 || new(big.Int).SetInt64(maxSquared).Cmp(squared) > 0 {
		t.Fatalf("exhaustive signed-floor maximum=%d certificate=%s",
			maxSquared, squared)
	}
}

func floorDivInt64(value, denominator int64) int64 {
	quotient := value / denominator
	if value < 0 && value%denominator != 0 {
		quotient--
	}
	return quotient
}

func absInt64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func TestFormalGLMPhase15FixedPointL2RecurrenceCoversExhaustiveAdjacentRows(t *testing.T) {
	type evaluated struct {
		row       []*big.Int
		quantized []*big.Int
	}
	for _, adjacency := range []string{"add_remove", "replace_one"} {
		t.Run(adjacency, func(t *testing.T) {
			policy := formalGLMPhase15TestPolicy("binomial", 3, 1, 2)
			policy.Adjacency = adjacency
			run := sha256.Sum256([]byte("phase15-exhaustive-" + adjacency))
			plan, err := buildFormalGLMPhase15Plan(policy, 1, 2,
				formalGLMPhase15TestOwners(policy), hexString(run[:]))
			if err != nil {
				t.Fatal(err)
			}
			identities, receipts, _ := formalGLMPhase15TestBridgeContext(
				t, plan, "phase15-exhaustive-"+adjacency)
			bridge, err := buildFormalGLMPhase15DPBridgePlan(
				plan, receipts, identities.public, 4)
			if err != nil {
				t.Fatal(err)
			}
			bound, _ := new(big.Int).SetString(
				bridge.SelectedSensitivitySteps, 10)
			boundSquared := new(big.Int).Mul(bound, bound)

			rows := make([][]*big.Int, 0, 24)
			for _, weight := range []int64{64, 256} {
				for _, indicator := range []int64{0, 256} {
					for _, outcome := range []int64{0, 256} {
						for _, offset := range []int64{-128, 0, 128} {
							rows = append(rows, []*big.Int{
								big.NewInt(weight), big.NewInt(256),
								big.NewInt(indicator), big.NewInt(outcome),
								formalGLMResidue(big.NewInt(offset), plan.RingBits),
							})
						}
					}
				}
			}
			absent := []*big.Int{
				big.NewInt(0), big.NewInt(256), big.NewInt(0),
				big.NewInt(0), big.NewInt(0),
			}
			if adjacency == "add_remove" {
				rows = append(rows, absent)
			}
			evaluatedRows := make([]evaluated, len(rows))
			for index, row := range rows {
				beta, err := referenceFormalGLMPhase15(plan, row)
				if err != nil {
					t.Fatalf("row %d: %v", index, err)
				}
				quantized, err := referenceFormalGLMPhase15DPBridge(
					plan, bridge, beta)
				if err != nil {
					t.Fatal(err)
				}
				evaluatedRows[index] = evaluated{row: row, quantized: quantized}
			}
			pairs := 0
			for left := range evaluatedRows {
				for right := range evaluatedRows {
					if adjacency == "add_remove" &&
						left != len(evaluatedRows)-1 && right != len(evaluatedRows)-1 {
						continue
					}
					squared := new(big.Int)
					for coordinate := range evaluatedRows[left].quantized {
						delta := new(big.Int).Sub(
							evaluatedRows[left].quantized[coordinate],
							evaluatedRows[right].quantized[coordinate])
						squared.Add(squared, new(big.Int).Mul(delta, delta))
					}
					if squared.Cmp(boundSquared) > 0 {
						t.Fatalf("%s pair (%d,%d) has squared distance %s > %s",
							adjacency, left, right, squared, boundSquared)
					}
					pairs++
				}
			}
			if pairs < len(rows) {
				t.Fatalf("too few exhaustive adjacency pairs: %d", pairs)
			}
		})
	}
}

func TestFormalGLMPhase15DPBridgeBindsTheCompleteFanInTranscript(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 2, 1, 1, 1, 2)
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.ComputePeers)
	beta := map[string][]*big.Int{
		plan.Kernel.ComputePeers[0]: {big.NewInt(7)},
		plan.Kernel.ComputePeers[1]: {big.NewInt(11)},
	}
	rootA, attemptA := formalGLMPhase15TestExecutionTranscript(t, plan, "fanin-a")
	rootB, attemptB := formalGLMPhase15TestExecutionTranscript(t, plan, "fanin-b")
	if rootA == rootB {
		t.Fatal("different fan-in roots produced the same execution transcript")
	}
	receiptsA := formalGLMPhase15TestFinalReceipts(
		t, plan, identities, rootA, attemptA, beta)
	receiptsB := formalGLMPhase15TestFinalReceipts(
		t, plan, identities, rootB, attemptB, beta)
	bridgeA, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receiptsA, identities.public, 8)
	if err != nil {
		t.Fatal(err)
	}
	bridgeB, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receiptsB, identities.public, 8)
	if err != nil {
		t.Fatal(err)
	}
	digestA, _ := formalGLMPhase15DPBridgePlanDigest(bridgeA)
	digestB, _ := formalGLMPhase15DPBridgePlanDigest(bridgeB)
	if digestA == digestB || bridgeA.ExecutionTranscriptSHA256 ==
		bridgeB.ExecutionTranscriptSHA256 {
		t.Fatal("DP release identity did not bind the fan-in transcript")
	}
	mixed := append([]formalGLMPhase15StepReceipt(nil), receiptsA...)
	mixed[1] = receiptsB[1]
	if _, err := buildFormalGLMPhase15DPBridgePlan(
		plan, mixed, identities.public, 8); err == nil {
		t.Fatal("mixed final transcript receipts were accepted")
	}
}

func TestFormalGLMPhase15DPBridgeCircuitQuantizesDynamicRingWithoutOpening(t *testing.T) {
	policy := formalGLMPhase15TestPolicy("binomial", 2, 1, 1)
	policy.WeightUpper = new(big.Int).Lsh(big.NewInt(1), 150).String()
	policy.LinkValues = []string{"128", "128", "128"}
	policy.LinkSlopes = []string{"0", "0"}
	run := sha256.Sum256([]byte("phase15-dp-dynamic-plan"))
	plan, err := buildFormalGLMPhase15Plan(policy, 1, 1,
		formalGLMPhase15TestOwners(policy), hexString(run[:]))
	if err != nil {
		t.Fatal(err)
	}
	if plan.RingBits <= 128 {
		t.Fatalf("test did not select a dynamic ring: %d", plan.RingBits)
	}
	identities, receipts, _ := formalGLMPhase15TestBridgeContext(
		t, plan, "phase15-dp-dynamic")
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, 6)
	if err != nil {
		t.Fatal(err)
	}
	circ, err := compileFormalGLMPhase15DPBridge(plan, bridge)
	if err != nil {
		t.Fatal(err)
	}
	quantum := big.NewInt(4)
	secretSigned := new(big.Int).Neg(new(big.Int).Add(quantum, big.NewInt(1)))
	secret := []*big.Int{formalGLMResidue(secretSigned, plan.RingBits)}
	rng := rand.New(rand.NewSource(151502))
	garbler, evaluator := exactGCTestSplit(rng, secret, plan.RingBits)
	masks := []*big.Int{big.NewInt(73)}
	garblerInput, err := formalGLMPhase15PackDPBridgeGarbler(
		garbler, masks, plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := circ.Compute([]*big.Int{
		garblerInput,
		exactGCPackChunks(append(evaluator, new(big.Int)),
			formalGLMPhase15DPBridgeInputTypeBits(plan.RingBits)),
	})
	if err != nil || len(packed) != 1 {
		t.Fatalf("dynamic DP bridge compute failed: %v", err)
	}
	evaluatorOutput := new(big.Int).And(packed[0], exactGCMask(128))
	got := exactGCReferenceReconstruct(masks[0], evaluatorOutput, 128)
	want, err := referenceFormalGLMPhase15DPBridge(plan, bridge, secret)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(want[0]) != 0 || got.String() != "126" {
		t.Fatalf("dynamic signed-floor bridge got %s, want %s", got, want[0])
	}
}

func TestFormalGLMPhase15DPBridgeKeepsFullRing128OutputMask(t *testing.T) {
	for _, sourceBits := range []int{63, 127, 129} {
		t.Run(fmt.Sprintf("Ring%d", sourceBits), func(t *testing.T) {
			box := new(big.Int).Lsh(big.NewInt(1), 20)
			shiftedUpper := new(big.Int).Rsh(new(big.Int).Set(box), 2)
			shiftedUpper.Lsh(shiftedUpper, 1)
			source, err := formalGLMPhase15DPBridgeCircuitSourceForBounds(
				sourceBits, 2, []*big.Int{box}, []*big.Int{shiftedUpper})
			if err != nil {
				t.Fatal(err)
			}
			circ, err := compileFormalGLMPhase15Source(
				source, fmt.Sprintf("Ring%d DP bridge", sourceBits))
			if err != nil {
				t.Fatal(err)
			}
			inputBits := formalGLMPhase15DPBridgeInputTypeBits(sourceBits)
			// beta + Ring128 output mask + one hidden Phase-1.9
			// execution-valid share occupy distinct compiler words.
			if got, want := int(circ.Inputs[0].Type.Bits), 3*inputBits; got != want {
				t.Fatalf("garbler input width %d, want %d", got, want)
			}
			if got, want := int(circ.Inputs[1].Type.Bits), 2*inputBits; got != want {
				t.Fatalf("evaluator input width %d, want %d", got, want)
			}

			secret := formalGLMResidue(big.NewInt(-9), sourceBits)
			left := new(big.Int).Sub(exactGCModulus(sourceBits), big.NewInt(3))
			right := exactGCReferenceReconstruct(
				secret, new(big.Int).Neg(left), sourceBits)
			// This mask deliberately has bits above 64. Packing it at the
			// Ring63 container width would overlap/truncate it.
			mask := new(big.Int).Add(
				new(big.Int).Lsh(big.NewInt(1), 100), big.NewInt(73))
			garblerInput, err := formalGLMPhase15PackDPBridgeGarbler(
				[]*big.Int{left}, []*big.Int{mask}, sourceBits)
			if err != nil {
				t.Fatal(err)
			}
			packed, err := circ.Compute([]*big.Int{
				garblerInput,
				exactGCPackChunks([]*big.Int{right, new(big.Int)}, inputBits),
			})
			if err != nil || len(packed) != 1 {
				t.Fatalf("Ring%d DP bridge compute failed: %v", sourceBits, err)
			}
			evaluator := new(big.Int).And(packed[0], exactGCMask(128))
			got := exactGCReferenceReconstruct(mask, evaluator, 128)
			// floor(-9/4) + B/4 = -3 + 2^18.
			want := new(big.Int).Sub(
				new(big.Int).Lsh(big.NewInt(1), 18), big.NewInt(3))
			if got.Cmp(want) != 0 {
				t.Fatalf("Ring%d bridge with high mask got %s, want %s",
					sourceBits, got, want)
			}
		})
	}
}

func TestFormalGLMPhase15DPBridgeCircuitBudgetUsesOutputMaskWidth(t *testing.T) {
	for _, test := range []struct {
		ring int
		want int
	}{
		{ring: 63, want: 3 * 128 * 2},
		{ring: 127, want: 3 * 128 * 2},
		{ring: 129, want: 3 * 256 * 2},
	} {
		spec := exactGCCircuitSpec{
			Operation: exactGCFormalGLMDPBridge,
			RingBits:  test.ring, FracBits: 8, VectorLen: 2,
		}
		if err := spec.validate(); err != nil {
			t.Fatalf("Ring%d bridge spec: %v", test.ring, err)
		}
		if got := exactGCCircuitInputBits(spec); got != test.want {
			t.Fatalf("Ring%d input budget %d, want %d", test.ring, got, test.want)
		}
	}
}

func TestFormalGLMPhase15DPBridgeRejectsUnrepresentableRing128Projection(t *testing.T) {
	policy := formalGLMPhase15TestPolicy("binomial", 2, 1, 1)
	policy.CoefficientBox = []string{
		new(big.Int).Lsh(big.NewInt(1), 150).String(),
	}
	policy.XKind = []string{"numeric"}
	policy.XLower, policy.XUpper = []string{"0"}, []string{"0"}
	policy.LinkValues = []string{"128", "128", "128"}
	policy.LinkSlopes = []string{"0", "0"}
	run := sha256.Sum256([]byte("phase15-dp-unrepresentable-plan"))
	plan, err := buildFormalGLMPhase15Plan(policy, 1, 1,
		formalGLMPhase15TestOwners(policy), hexString(run[:]))
	if err != nil {
		t.Fatal(err)
	}
	identities, receipts, _ := formalGLMPhase15TestBridgeContext(
		t, plan, "phase15-dp-unrepresentable")
	_, err = buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, 8)
	var numeric *formalGLMNumericBackendError
	if !errors.As(err, &numeric) ||
		numeric.Code != "dp_projection_ring128_unrepresentable" ||
		numeric.RequiredBits <= 128 {
		t.Fatalf("expected typed DP projection failure, got %T %v", err, err)
	}
}

func TestFormalGLMPhase15DPBridgeCarriesAggregateSensitivityWithoutCasting(t *testing.T) {
	policy := formalGLMPhase15TestPolicy("binomial", 2, 1, 3)
	box := new(big.Int).Sub(
		new(big.Int).Mul(big.NewInt(3), new(big.Int).Lsh(big.NewInt(1), 124)),
		big.NewInt(1))
	policy.CoefficientBox = []string{box.String(), box.String(), box.String()}
	policy.XKind = []string{"numeric", "numeric", "numeric"}
	policy.XLower, policy.XUpper = []string{"0", "0", "0"}, []string{"0", "0", "0"}
	policy.LinkValues = []string{"128", "128", "128"}
	policy.LinkSlopes = []string{"0", "0"}
	run := sha256.Sum256([]byte("phase15-dp-sensitivity-overflow-plan"))
	plan, err := buildFormalGLMPhase15Plan(policy, 1, 1,
		formalGLMPhase15TestOwners(policy), hexString(run[:]))
	if err != nil {
		t.Fatal(err)
	}
	identities, receipts, _ := formalGLMPhase15TestBridgeContext(
		t, plan, "phase15-dp-sensitivity-overflow")
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, plan.Kernel.FracBits)
	if err != nil {
		t.Fatal(err)
	}
	sensitivity, ok := new(big.Int).SetString(
		bridge.UniversalSensitivity.BoundSteps, 10)
	if !ok || sensitivity.Cmp(exactGCMaxSigned(128)) <= 0 {
		t.Fatalf("test did not preserve the >Ring128 L2 certificate: %v", sensitivity)
	}
}

func TestFormalGLMPhase15DPBridgeRunsActualYaoAndLoadsOnlyCompletedCheckpoint(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "poisson", 2, 1, 1, 1, 1)
	identities, receipts, checkpointBeta := formalGLMPhase15TestBridgeContext(
		t, plan, "phase15-dp-yao")
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, 8)
	if err != nil {
		t.Fatal(err)
	}

	checkpointKey := sha256.Sum256([]byte("phase15-dp-checkpoint-key"))
	stores := make(map[string]*formalGLMPhase15CheckpointStore, 2)
	for _, peer := range plan.Kernel.ComputePeers {
		store, err := newFormalGLMPhase15CheckpointStore(
			filepath.Join(t.TempDir(), peer), checkpointKey, plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Bootstrap(); err != nil {
			t.Fatal(err)
		}
		state, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		state.NextStep = plan.ScheduleSteps
		state.Beta, err = formalGLMPhase15EncodeStateValues(
			checkpointBeta[peer], plan.RingBits)
		if err != nil {
			t.Fatal(err)
		}
		state.TranscriptSHA256 = bridge.ExecutionTranscriptSHA256
		if err := store.writeUnlocked(state); err != nil {
			t.Fatal(err)
		}
		stores[peer] = store
	}
	leftPeer, rightPeer := bridge.GarblerPeerName, bridge.EvaluatorPeerName
	leftBeta, err := formalGLMPhase15DPBridgeLoadLocalSource(
		stores[leftPeer], receipts, identities.public, bridge)
	if err != nil {
		t.Fatal(err)
	}
	rightBeta, err := formalGLMPhase15DPBridgeLoadLocalSource(
		stores[rightPeer], receipts, identities.public, bridge)
	if err != nil {
		t.Fatal(err)
	}

	attempt := sha256.Sum256([]byte("phase15-dp-bridge-attempt"))
	master := sha256.Sum256([]byte("phase15-dp-bridge-master"))
	session, err := formalGLMPhase15DPBridgeSession(plan, bridge, attempt, master)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	type result struct {
		shares []*big.Int
		err    error
	}
	garblerResult := make(chan result, 1)
	go func() {
		shares, err := formalGLMPhase15RunDPBridgeGarbler(
			left, plan, bridge, session, leftBeta)
		garblerResult <- result{shares: shares, err: err}
	}()
	evaluatorShares, evaluatorErr := formalGLMPhase15RunDPBridgeEvaluator(
		right, plan, bridge, session, rightBeta)
	garbler := <-garblerResult
	if garbler.err != nil || evaluatorErr != nil {
		t.Fatalf("actual DP bridge Yao failed: %v / %v",
			garbler.err, evaluatorErr)
	}
	secret := []*big.Int{exactGCReferenceReconstruct(
		leftBeta[0], rightBeta[0], plan.RingBits)}
	want, err := referenceFormalGLMPhase15DPBridge(plan, bridge, secret)
	if err != nil {
		t.Fatal(err)
	}
	got := exactGCReferenceReconstruct(
		garbler.shares[0], evaluatorShares[0], 128)
	if got.Cmp(want[0]) != 0 {
		t.Fatalf("actual Yao bridge got %s, want %s", got, want[0])
	}

	// A different but correctly signed execution transcript is still not the
	// one committed in this checkpoint.
	otherRoot, otherAttempt := formalGLMPhase15TestExecutionTranscript(
		t, plan, "phase15-dp-other-transcript")
	otherReceipts := formalGLMPhase15TestFinalReceipts(
		t, plan, identities, otherRoot, otherAttempt, checkpointBeta)
	otherBridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, otherReceipts, identities.public, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMPhase15DPBridgeLoadLocalSource(
		stores[leftPeer], otherReceipts, identities.public, otherBridge); err == nil {
		t.Fatal("checkpoint was rebound to a different signed execution transcript")
	}
}

func TestFormalGLMPhase15DPBridgeConsumesHiddenInvalidExecution(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 3, 1, 1, 1, 1)
	identities, receipts, beta := formalGLMPhase15TestBridgeContext(
		t, plan, "phase15-dp-hidden-invalid")
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, 8)
	if err != nil {
		t.Fatal(err)
	}
	attempt := sha256.Sum256([]byte("phase15-dp-hidden-invalid-attempt"))
	master := sha256.Sum256([]byte("phase15-dp-hidden-invalid-master"))
	session, err := formalGLMPhase15DPBridgeSession(
		plan, bridge, attempt, master)
	if err != nil {
		t.Fatal(err)
	}
	garbler, evaluator := net.Pipe()
	defer garbler.Close()
	defer evaluator.Close()
	type outcome struct {
		shares []*big.Int
		err    error
	}
	garblerDone := make(chan outcome, 1)
	go func() {
		shares, runErr := formalGLMPhase15RunDPBridgeGarblerWithExecution(
			garbler, plan, bridge, session, beta[bridge.GarblerPeerName], 0)
		garblerDone <- outcome{shares: shares, err: runErr}
	}()
	evaluatorShares, evaluatorErr :=
		formalGLMPhase15RunDPBridgeEvaluatorWithExecution(
			evaluator, plan, bridge, session,
			beta[bridge.EvaluatorPeerName], 0)
	garblerResult := <-garblerDone
	if garblerResult.err != nil || evaluatorErr != nil {
		t.Fatalf("hidden-invalid bridge failed: %v / %v",
			garblerResult.err, evaluatorErr)
	}
	upper, ok := new(big.Int).SetString(bridge.ShiftedUpperBounds[0], 10)
	if !ok {
		t.Fatal("invalid test bridge upper bound")
	}
	want := new(big.Int).Add(upper, big.NewInt(1))
	got := exactGCReferenceReconstruct(
		garblerResult.shares[0], evaluatorShares[0], 128)
	if got.Cmp(want) != 0 {
		t.Fatalf("invalid execution was not converted to the bound sentinel: got %s want %s",
			got, want)
	}
}
