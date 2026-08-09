package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func formalGLMPhase19RuntimeTestInputs(t testing.TB,
	fixture formalGLMPhase18FinalizerFixture) map[string]formalGLMPhase19RuntimeLocalInput {
	t.Helper()
	root := t.TempDir()
	backend := sha256.Sum256([]byte("formal-glm/phase19/runtime/backend/" + t.Name()))
	result := make(map[string]formalGLMPhase19RuntimeLocalInput, 2)
	for _, recipient := range fixture.ctx.ComputePeers {
		ingressDir := filepath.Join(root, "ingress", recipient)
		if err := os.MkdirAll(ingressDir, 0o700); err != nil {
			t.Fatal(err)
		}
		paths := make([]string, len(fixture.frames[recipient]))
		for i, frame := range fixture.frames[recipient] {
			path := filepath.Join(ingressDir, "frame-"+string(rune('a'+i))+".bin")
			if err := os.WriteFile(path, frame, 0o600); err != nil {
				t.Fatal(err)
			}
			paths[i] = path
		}
		localIngressKey := fixture.localKeys[recipient]
		result[recipient] = formalGLMPhase19RuntimeLocalInput{
			Version:                     formalGLMPhase19RuntimePrepareVersion,
			Plan:                        fixture.plan,
			PreExecutionTokenSHA256:     fixture.ctx.PreExecutionTokenSHA256,
			GlobalMaterializationRoot:   fixture.ctx.GlobalMaterializationRoot,
			Recipient:                   recipient,
			FinalizerDir:                filepath.Join(root, "finalizer", recipient),
			IngressPaths:                paths,
			LocalIngressKey:             base64.StdEncoding.EncodeToString(localIngressKey[:]),
			RecipientTransportSecretKey: base64.StdEncoding.EncodeToString(fixture.recipientSK[recipient]),
			BackendKey:                  base64.StdEncoding.EncodeToString(backend[:]),
			BlockIndex:                  0,
		}
	}
	return result
}

func formalGLMPhase19RuntimeExpected(fixture formalGLMPhase18FinalizerFixture) []*big.Int {
	result := make([]*big.Int, len(fixture.localBySource[0]))
	modulus := exactGCModulus(fixture.plan.RingBits)
	for i := range result {
		result[i] = new(big.Int)
		for source := range fixture.localBySource {
			result[i].Add(result[i], fixture.localBySource[source][i])
		}
		result[i].Mod(result[i], modulus)
	}
	return result
}

func TestFormalGLMPhase19RuntimeConsumesDurablePhase18K2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase18TestBuildFinalizerFixture(t, custodians)
			inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
			prepared := make(map[string]formalGLMPhase19RuntimePrepareOutput, 2)
			for _, recipient := range fixture.ctx.ComputePeers {
				value, err := formalGLMPhase19RuntimePrepare(inputs[recipient])
				if err != nil {
					t.Fatal(err)
				}
				if value.ProductionReady || value.OpeningsPerformed != 0 ||
					value.Receipt.Recipient != recipient {
					t.Fatal("runtime prepare overstated readiness or changed its route")
				}
				prepared[recipient] = value
				// A process restart needs no source retransmission: only the
				// authenticated durable Phase-1.8 slots are re-opened.
				restart := inputs[recipient]
				restart.IngressPaths = nil
				replayed, err := formalGLMPhase19RuntimePrepare(restart)
				if err != nil || !formalGLMPhase19RuntimeReceiptsEqual(
					value.Receipt, replayed.Receipt) {
					t.Fatalf("restart changed the durable fan-in: %v", err)
				}
			}

			leftPeer, rightPeer := fixture.ctx.ComputePeers[0], fixture.ctx.ComputePeers[1]
			leftConn, rightConn := net.Pipe()
			defer leftConn.Close()
			defer rightConn.Close()
			attempt := sha256.Sum256([]byte("formal-glm/phase19/runtime/attempt/" + t.Name()))
			var left, right formalGLMPhase19MaskedBlock
			var leftErr, rightErr error
			var wait sync.WaitGroup
			wait.Add(2)
			go func() {
				defer wait.Done()
				left, leftErr = formalGLMPhase19RuntimeRunPeer(
					leftConn, inputs[leftPeer], prepared[rightPeer].Receipt, attempt)
			}()
			go func() {
				defer wait.Done()
				right, rightErr = formalGLMPhase19RuntimeRunPeer(
					rightConn, inputs[rightPeer], prepared[leftPeer].Receipt, attempt)
			}()
			wait.Wait()
			if leftErr != nil || rightErr != nil {
				t.Fatalf("garbler=%v evaluator=%v", leftErr, rightErr)
			}
			want := formalGLMPhase19RuntimeExpected(fixture)
			modulus := exactGCModulus(fixture.plan.RingBits)
			for i := range want {
				got := new(big.Int).Add(left.tupleShares[i], right.tupleShares[i])
				got.Mod(got, modulus)
				if got.Cmp(want[i]) != 0 {
					t.Fatalf("coordinate %d mismatch", i)
				}
			}
			if left.executionShare^right.executionShare != 1 {
				t.Fatal("the hidden all-K execution-valid bit was lost")
			}
			encoded, err := formalGLMPhase19RuntimeEncodeResult(
				inputs[leftPeer], left, attempt)
			if err != nil || encoded.ProductionReady ||
				encoded.OpeningsPerformed != 0 || encoded.TupleShare == "" {
				t.Fatalf("invalid private runtime result: %v", err)
			}
		})
	}
}

func TestFormalGLMPhase19RuntimeRejectsTamperReplayAndPartialRestart(t *testing.T) {
	fixture := formalGLMPhase18TestBuildFinalizerFixture(t, 3)
	inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
	left, right := fixture.ctx.ComputePeers[0], fixture.ctx.ComputePeers[1]

	partial := inputs[left]
	partial.IngressPaths = partial.IngressPaths[:len(partial.IngressPaths)-1]
	if _, err := formalGLMPhase19RuntimePrepare(partial); err == nil {
		t.Fatal("a partial first materialization was accepted")
	}

	leftPrepared, err := formalGLMPhase19RuntimePrepare(inputs[left])
	if err != nil {
		t.Fatal(err)
	}
	rightPrepared, err := formalGLMPhase19RuntimePrepare(inputs[right])
	if err != nil {
		t.Fatal(err)
	}

	duplicate := inputs[left]
	duplicate.IngressPaths = append([]string(nil), duplicate.IngressPaths...)
	duplicate.IngressPaths[1] = duplicate.IngressPaths[0]
	if _, err := formalGLMPhase19RuntimePrepare(duplicate); err == nil {
		t.Fatal("a duplicate source frame was accepted")
	}

	tampered := rightPrepared.Receipt
	tampered.FanInRoot = sha256Hex([]byte("relay changed the public receipt"))
	attempt := sha256.Sum256([]byte("formal-glm/phase19/runtime/tamper"))
	if _, err := formalGLMPhase19RuntimeRunPeer(
		bytes.NewBuffer(nil), inputs[left], tampered, attempt); err == nil {
		t.Fatal("a relay-tampered peer fan-in receipt was accepted")
	}

	changed := inputs[left]
	changed.BackendKey = base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x44}, 32))
	changedPrepared, err := formalGLMPhase19RuntimePrepare(changed)
	if err != nil {
		t.Fatal(err)
	}
	if formalGLMPhase19RuntimeReceiptsEqual(
		leftPrepared.Receipt, changedPrepared.Receipt) {
		t.Fatal("a backend privacy epoch change reused the old receipt MAC")
	}
	if _, err := formalGLMPhase19RuntimeRunPeer(
		bytes.NewBuffer(nil), changed, rightPrepared.Receipt, attempt); err == nil {
		t.Fatal("a cross-epoch receipt replay was accepted")
	}
}

func TestFormalGLMPhase19RuntimeFullScheduleBinomialPoissonK2K3K4K5(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 4, 5} {
			t.Run(family+"-K"+string(rune('0'+custodians)), func(t *testing.T) {
				fixture := formalGLMPhase18TestBuildFinalizerFixtureFamily(
					t, custodians, family)
				inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
				leftPeer, rightPeer := fixture.ctx.ComputePeers[0], fixture.ctx.ComputePeers[1]
				leftPrepared, err := formalGLMPhase19RuntimePrepare(inputs[leftPeer])
				if err != nil {
					t.Fatal(err)
				}
				rightPrepared, err := formalGLMPhase19RuntimePrepare(inputs[rightPeer])
				if err != nil {
					t.Fatal(err)
				}
				leftConn, rightConn := net.Pipe()
				defer leftConn.Close()
				defer rightConn.Close()
				_ = leftConn.SetDeadline(time.Now().Add(90 * time.Second))
				_ = rightConn.SetDeadline(time.Now().Add(90 * time.Second))
				root := sha256.Sum256([]byte(
					"formal-glm/runtime/full-schedule/" + t.Name()))
				var left, right formalGLMPhase19RuntimeScheduleResult
				var leftErr, rightErr error
				var wait sync.WaitGroup
				wait.Add(2)
				go func() {
					defer wait.Done()
					left, leftErr = formalGLMPhase19RuntimeRunSchedule(
						leftConn, []formalGLMPhase19RuntimeLocalInput{inputs[leftPeer]},
						[]formalGLMPhase19FanInReceipt{rightPrepared.Receipt}, root)
				}()
				go func() {
					defer wait.Done()
					right, rightErr = formalGLMPhase19RuntimeRunSchedule(
						rightConn, []formalGLMPhase19RuntimeLocalInput{inputs[rightPeer]},
						[]formalGLMPhase19FanInReceipt{leftPrepared.Receipt}, root)
				}()
				wait.Wait()
				if leftErr != nil || rightErr != nil {
					t.Fatalf("garbler=%v evaluator=%v", leftErr, rightErr)
				}
				complete := formalGLMPhase19RuntimeExpected(fixture)
				want, err := referenceFormalGLMPhase15(fixture.plan, complete)
				if err != nil {
					t.Fatal(err)
				}
				modulus := exactGCModulus(fixture.plan.RingBits)
				for index := range want {
					got := new(big.Int).Add(
						left.betaShares[index], right.betaShares[index])
					got.Mod(got, modulus)
					if got.Cmp(want[index]) != 0 {
						t.Fatalf("coefficient %d got %s want %s",
							index, got, want[index])
					}
				}
				if left.executionSeal.share^right.executionSeal.share != 1 ||
					left.executionPair.ExecutionValidSealed != true ||
					left.executionPair.ExecutionValidityOpened ||
					left.executionPair.OpeningsPerformed != 0 ||
					left.executionPair.ExecutionReceiptPairSHA256 !=
						right.executionPair.ExecutionReceiptPairSHA256 {
					t.Fatal("hidden execution validity was not carried to the sealed schedule")
				}
				clear(left.backend[:])
				clear(right.backend[:])
				exactGCZeroBigInts(left.betaShares)
				exactGCZeroBigInts(right.betaShares)
			})
		}
	}
}

func TestFormalGLMPhase19RuntimeDurableCheckpointBridgeK2K3K5(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 5} {
			t.Run(family+"-K"+string(rune('0'+custodians)), func(t *testing.T) {
				fixture := formalGLMPhase18TestBuildFinalizerFixtureFamily(
					t, custodians, family)
				inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
				leftPeer, rightPeer := fixture.ctx.ComputePeers[0], fixture.ctx.ComputePeers[1]
				leftPrepared, err := formalGLMPhase19RuntimePrepare(inputs[leftPeer])
				if err != nil {
					t.Fatal(err)
				}
				rightPrepared, err := formalGLMPhase19RuntimePrepare(inputs[rightPeer])
				if err != nil {
					t.Fatal(err)
				}
				rootDir := t.TempDir()
				configs := map[string]formalGLMPhase19RuntimeDurableConfig{}
				for _, peer := range fixture.ctx.ComputePeers {
					key := sha256.Sum256([]byte(t.Name() + "/checkpoint/" + peer))
					configs[peer] = formalGLMPhase19RuntimeDurableConfig{
						CheckpointDir:     filepath.Join(rootDir, "checkpoint", peer),
						CheckpointKey:     key,
						SigningKey:        fixture.identities.private[peer],
						Pins:              fixture.identities.public,
						OutputLatticeBits: fixture.plan.Kernel.FracBits,
					}
				}
				root := sha256.Sum256([]byte(
					"formal-glm/runtime/durable/" + t.Name()))
				run := func(restart bool) (formalGLMPhase19RuntimeScheduleResult,
					formalGLMPhase19RuntimeScheduleResult) {
					leftInput, rightInput := inputs[leftPeer], inputs[rightPeer]
					if restart {
						leftInput.IngressPaths = nil
						rightInput.IngressPaths = nil
					}
					leftConn, rightConn := net.Pipe()
					defer leftConn.Close()
					defer rightConn.Close()
					_ = leftConn.SetDeadline(time.Now().Add(90 * time.Second))
					_ = rightConn.SetDeadline(time.Now().Add(90 * time.Second))
					var left, right formalGLMPhase19RuntimeScheduleResult
					var leftErr, rightErr error
					var wait sync.WaitGroup
					wait.Add(2)
					go func() {
						defer wait.Done()
						left, leftErr = formalGLMPhase19RuntimeRunDurableSchedule(
							leftConn, []formalGLMPhase19RuntimeLocalInput{leftInput},
							[]formalGLMPhase19FanInReceipt{rightPrepared.Receipt},
							root, configs[leftPeer])
					}()
					go func() {
						defer wait.Done()
						right, rightErr = formalGLMPhase19RuntimeRunDurableSchedule(
							rightConn, []formalGLMPhase19RuntimeLocalInput{rightInput},
							[]formalGLMPhase19FanInReceipt{leftPrepared.Receipt},
							root, configs[rightPeer])
					}()
					wait.Wait()
					if leftErr != nil || rightErr != nil {
						t.Fatalf("durable garbler=%v evaluator=%v", leftErr, rightErr)
					}
					return left, right
				}
				verify := func(left, right formalGLMPhase19RuntimeScheduleResult) {
					if err := formalGLMPhase15VerifyReceiptPair(
						fixture.plan, left.finalReceipts,
						fixture.identities.public); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(left.dpBridge, right.dpBridge) ||
						left.postToken.TokenSHA256 != right.postToken.TokenSHA256 ||
						len(left.dpShares) != fixture.plan.Kernel.CoefficientCount ||
						len(right.dpShares) != fixture.plan.Kernel.CoefficientCount {
						t.Fatal("durable peers did not agree on the sealed DP bridge")
					}
					complete := formalGLMPhase19RuntimeExpected(fixture)
					beta, err := referenceFormalGLMPhase15(fixture.plan, complete)
					if err != nil {
						t.Fatal(err)
					}
					want, err := referenceFormalGLMPhase15DPBridge(
						fixture.plan, left.dpBridge, beta)
					if err != nil {
						t.Fatal(err)
					}
					for index := range want {
						got := exactGCReferenceReconstruct(
							left.dpShares[index], right.dpShares[index], 128)
						if got.Cmp(want[index]) != 0 {
							t.Fatalf("DP bridge coordinate %d got %s want %s",
								index, got, want[index])
						}
					}
				}
				left, right := run(false)
				verify(left, right)
				firstTranscript := left.finalReceipts[0].TranscriptSHA256
				exactGCZeroBigInts(left.dpShares)
				exactGCZeroBigInts(right.dpShares)
				clear(left.backend[:])
				clear(right.backend[:])
				left, right = run(true)
				verify(left, right)
				if left.finalReceipts[0].TranscriptSHA256 != firstTranscript {
					t.Fatal("restart changed the committed Phase-1.5 transcript")
				}
				exactGCZeroBigInts(left.dpShares)
				exactGCZeroBigInts(right.dpShares)
				clear(left.backend[:])
				clear(right.backend[:])
			})
		}
	}
}

func TestFormalGLMPhase19RuntimeCommandsRemainInternal(t *testing.T) {
	manifest := runtimeCapabilities()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"formal-glm-phase19-prepare", "formal-glm-phase19-worker",
		"formal-glm-phase19-schedule-worker",
	} {
		if bytes.Contains(encoded, []byte(command)) {
			t.Fatalf("internal incomplete runtime command %q was advertised", command)
		}
	}
	if reflect.ValueOf(formalGLMPhase19RuntimePrepareOutput{}).FieldByName(
		"Receipt").IsZero() == false {
		t.Fatal("unexpected non-zero prepare output")
	}
}
