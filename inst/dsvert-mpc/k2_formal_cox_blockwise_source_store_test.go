package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFormalCoxBlockwiseSourceRecipientTicketsFailClosedK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
		transportPK, transportSK := formalCoxBlockwiseSourceTestTransportKeys(t, plan)
		context, err := newFormalCoxBlockwiseSourceContext(plan, pins)
		if err != nil {
			t.Fatal(err)
		}
		tickets := make([]formalCoxBlockwiseSourceRecipientTicket, 2)
		for index, recipient := range plan.Policy.ComputePeers {
			tickets[index], err = context.signRecipientTicket(
				recipient, transportPK[recipient], signing[recipient])
			if err != nil {
				t.Fatal(err)
			}
		}
		session, err := context.bindRecipientManifest(tickets)
		if err != nil {
			t.Fatalf("valid K=%d recipient manifest: %v", custodians, err)
		}
		key := sha256.Sum256([]byte("formal-cox/source/wrong-recipient-key"))
		if _, err := newFormalCoxBlockwiseSourceStore(
			filepath.Join(t.TempDir(), "wrong-key"), key, session,
			plan.Policy.ComputePeers[0],
			transportSK[plan.Policy.ComputePeers[1]]); err == nil {
			t.Fatal("a source store accepted the other recipient's secret key")
		}

		for name, mutate := range map[string]func(
			[]formalCoxBlockwiseSourceRecipientTicket,
		) []formalCoxBlockwiseSourceRecipientTicket{
			"missing": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				return value[:1]
			},
			"extra": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				return append(value, value[0])
			},
			"reordered": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				value[0], value[1] = value[1], value[0]
				return value
			},
			"forged_signature": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				value[0].Signature[0] ^= 1
				return value
			},
			"wrong_plan": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				value[0].PlanSHA256 = strings.Repeat("0", 64)
				return value
			},
			"wrong_pinset": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				value[0].PinsetSHA256 = strings.Repeat("0", 64)
				return value
			},
			"wrong_run": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				value[0].RunID = strings.Repeat("0", 64)
				return value
			},
			"swapped_role": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				value[0].RecipientRole = "evaluator"
				return value
			},
			"substituted_transport_key": func(value []formalCoxBlockwiseSourceRecipientTicket) []formalCoxBlockwiseSourceRecipientTicket {
				value[0].TransportPublicKey = append(
					[]byte(nil), value[1].TransportPublicKey...)
				value[0].TransportKeySHA256 = value[1].TransportKeySHA256
				return value
			},
		} {
			t.Run("K"+big.NewInt(int64(custodians)).String()+"/"+name,
				func(t *testing.T) {
					candidate := make([]formalCoxBlockwiseSourceRecipientTicket, len(tickets))
					for index := range tickets {
						candidate[index] = tickets[index]
						candidate[index].TransportPublicKey = append(
							[]byte(nil), tickets[index].TransportPublicKey...)
						candidate[index].Signature = append(
							[]byte(nil), tickets[index].Signature...)
					}
					if _, err := context.bindRecipientManifest(mutate(candidate)); err == nil {
						t.Fatal("malformed recipient manifest was accepted")
					}
				})
		}

		duplicate := append([]formalCoxBlockwiseSourceRecipientTicket(nil), tickets...)
		duplicate[1], err = context.signRecipientTicket(
			plan.Policy.ComputePeers[1], tickets[0].TransportPublicKey,
			signing[plan.Policy.ComputePeers[1]])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := context.bindRecipientManifest(duplicate); err == nil {
			t.Fatal("the two Cox compute roles shared one transport key")
		}
		if _, err := context.signRecipientTicket(
			plan.Policy.ComputePeers[0], transportPK[plan.Policy.ComputePeers[0]],
			signing[plan.Policy.ComputePeers[1]]); err == nil {
			t.Fatal("a transport ticket was signed by the wrong pinned identity")
		}
	}
}

func TestFormalCoxBlockwiseSourceContextFreezesPlanAndPins(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
	callerPlan, err := formalCoxBlockwiseSourceClonePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	callerPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		callerPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	context, err := newFormalCoxBlockwiseSourceContext(callerPlan, callerPins)
	if err != nil {
		t.Fatal(err)
	}
	callerPlan.Policy.CustodianPeers[0] = "mutated-caller-plan"
	callerPlan.Policy.ComputePeers[0] = "mutated-compute-role"
	callerPins[plan.Policy.CustodianPeers[0]][0] ^= 1

	public, _ := formalCoxBlockwiseSourceTestTransportKeys(t, plan)
	tickets := make([]formalCoxBlockwiseSourceRecipientTicket, 2)
	for index, recipient := range plan.Policy.ComputePeers {
		tickets[index], err = context.signRecipientTicket(
			recipient, public[recipient], signing[recipient])
		if err != nil {
			t.Fatalf("frozen source context changed with its caller: %v", err)
		}
	}
	session, err := context.bindRecipientManifest(tickets)
	if err != nil {
		t.Fatal(err)
	}
	step := formalCoxBlockwiseSourceTestStep(
		t, plan, formalCoxBlockwiseStepBlock, 0)
	values, _ := formalCoxBlockwiseSourceTestShares(plan, step, 0, 0)
	if _, err := formalCoxBlockwiseSealSourceInput(
		session, plan.Policy.CustodianPeers[0], plan.Policy.ComputePeers[0],
		step, values, nil, signing[plan.Policy.CustodianPeers[0]]); err != nil {
		t.Fatalf("frozen context could not seal after caller mutation: %v", err)
	}
}

type formalCoxBlockwiseSourceCachedPlan struct {
	plan    formalCoxBlockwisePlan
	pins    map[string]ed25519.PublicKey
	private map[string]ed25519.PrivateKey
	err     error
}

var formalCoxBlockwiseSourcePlanCache = struct {
	sync.Mutex
	values map[int]formalCoxBlockwiseSourceCachedPlan
}{values: make(map[int]formalCoxBlockwiseSourceCachedPlan)}

func formalCoxBlockwiseSourceTestPlan(t testing.TB, custodians int) (
	formalCoxBlockwisePlan, map[string]ed25519.PublicKey,
	map[string]ed25519.PrivateKey) {
	t.Helper()
	formalCoxBlockwiseSourcePlanCache.Lock()
	defer formalCoxBlockwiseSourcePlanCache.Unlock()
	if cached, ok := formalCoxBlockwiseSourcePlanCache.values[custodians]; ok {
		if cached.err != nil {
			t.Fatal(cached.err)
		}
		return cached.plan, cached.pins, cached.private
	}
	pins, private := formalCoxBlockwiseWorkerTestIdentities(t, custodians)
	policy := formalCoxBlockwiseTestPolicy(t, custodians, 3)
	// Keep the transport/bridge fixture inside the certified one-draw sampler
	// resource envelope now exercised by the pre-sampler sticky guard.
	policy.XLower = []string{"-16", "-16"}
	policy.XUpper = []string{"16", "16"}
	policy.CovariateL2Bound = "16"
	dpPlan, err := planFormalCoxBlockwiseDP(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.NoiseBound = dpPlan.MaximumNoiseMagnitude
	pinset, err := formalCoxBlockwisePinsetSHA256(pins)
	if err != nil {
		t.Fatal(err)
	}
	policy.PinsetSHA256 = pinset
	runID := sha256.Sum256([]byte("formal-cox-source-plan/" +
		big.NewInt(int64(custodians)).String()))
	plan, err := buildFormalCoxBlockwisePlan(
		policy, 2, hex.EncodeToString(runID[:]))
	if err != nil {
		formalCoxBlockwiseSourcePlanCache.values[custodians] =
			formalCoxBlockwiseSourceCachedPlan{err: err}
		t.Fatal(err)
	}
	formalCoxBlockwiseSourcePlanCache.values[custodians] =
		formalCoxBlockwiseSourceCachedPlan{
			plan: plan, pins: pins, private: private,
		}
	return plan, pins, private
}

func formalCoxBlockwiseSourceTestTransportKeys(t testing.TB,
	plan formalCoxBlockwisePlan) (map[string][]byte, map[string][]byte) {
	t.Helper()
	public := make(map[string][]byte, 2)
	private := make(map[string][]byte, 2)
	for _, peer := range plan.Policy.ComputePeers {
		seed := sha256.Sum256([]byte("formal-cox-source-x25519/" + peer))
		key, err := ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		private[peer] = append([]byte(nil), key.Bytes()...)
		public[peer] = append([]byte(nil), key.PublicKey().Bytes()...)
	}
	return public, private
}

func formalCoxBlockwiseSourceTestSession(t testing.TB,
	plan formalCoxBlockwisePlan, pins map[string]ed25519.PublicKey,
	signing map[string]ed25519.PrivateKey) (
	*formalCoxBlockwiseSourceSession, map[string][]byte, map[string][]byte) {
	t.Helper()
	public, private := formalCoxBlockwiseSourceTestTransportKeys(t, plan)
	context, err := newFormalCoxBlockwiseSourceContext(plan, pins)
	if err != nil {
		t.Fatal(err)
	}
	tickets := make([]formalCoxBlockwiseSourceRecipientTicket, 2)
	for index, recipient := range plan.Policy.ComputePeers {
		tickets[index], err = context.signRecipientTicket(
			recipient, public[recipient], signing[recipient])
		if err != nil {
			t.Fatal(err)
		}
	}
	session, err := context.bindRecipientManifest(tickets)
	if err != nil {
		t.Fatal(err)
	}
	return session, public, private
}

func formalCoxBlockwiseSourceTestStep(t testing.TB,
	plan formalCoxBlockwisePlan, kind string, index int) formalCoxBlockwiseWorkerStep {
	t.Helper()
	perIteration := formalCoxBlockwiseWorkerStepsPerIteration(plan)
	schedule := index
	if kind == formalCoxBlockwiseStepUpdate {
		schedule = index*perIteration + plan.TotalBlocks +
			plan.Policy.GridTickCount*plan.Policy.CovariateCount
	}
	step, err := formalCoxBlockwiseWorkerStepAt(plan, schedule)
	if err != nil || step.Kind != kind {
		t.Fatalf("source test step: kind=%s index=%d err=%v", kind, index, err)
	}
	return step
}

func formalCoxBlockwiseSourceTestShares(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep, sourceIndex, recipientIndex int) (
	[]*big.Int, *bool) {
	count := plan.Policy.CovariateCount
	if step.Kind == formalCoxBlockwiseStepBlock {
		count = plan.BlockCapacity * plan.RowWidth
	}
	values := make([]*big.Int, count)
	modulus := exactGCModulus(plan.RingBits)
	for index := range values {
		value := new(big.Int).Lsh(big.NewInt(1), 60)
		if plan.RingBits > 128 && index == 0 {
			value.Lsh(big.NewInt(1), 170)
		}
		value.Add(value, big.NewInt(int64(
			1+sourceIndex*1009+recipientIndex*101+index)))
		values[index] = value.Mod(value, modulus)
	}
	if step.Kind == formalCoxBlockwiseStepBlock {
		rows := formalCoxBlockwiseSourceRowsInBlock(plan, step.BlockIndex)
		for index := rows * plan.RowWidth; index < len(values); index++ {
			values[index].SetInt64(0)
		}
		return values, nil
	}
	valid := (sourceIndex+recipientIndex+step.Iteration)%2 == 0
	return values, &valid
}

func formalCoxBlockwiseSourceTestSeal(t testing.TB,
	session *formalCoxBlockwiseSourceSession,
	private map[string]ed25519.PrivateKey,
	source, recipient string, step formalCoxBlockwiseWorkerStep,
	values []*big.Int, validity *bool) []byte {
	t.Helper()
	encoded, err := formalCoxBlockwiseSealSourceInput(
		session, source, recipient, step, values, validity, private[source])
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalCoxBlockwiseSourceTestSealBlockPair(t testing.TB,
	session *formalCoxBlockwiseSourceSession,
	signing map[string]ed25519.PrivateKey, source string,
	step formalCoxBlockwiseWorkerStep,
	values map[string][]*big.Int) (map[string][]byte, []byte) {
	t.Helper()
	envelopes := make(map[string][]byte, 2)
	ordered := make([][]byte, 2)
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		envelopes[recipient] = formalCoxBlockwiseSourceTestSeal(
			t, session, signing, source, recipient, step, values[recipient], nil)
		ordered[index] = envelopes[recipient]
	}
	manifest, err := formalCoxBlockwisePairSourceEnvelopes(
		session, source, step, ordered, signing[source])
	if err != nil {
		t.Fatal(err)
	}
	return envelopes, manifest
}

func formalCoxBlockwiseSourceTestSealLocalBlockPair(t testing.TB,
	session *formalCoxBlockwiseSourceSession,
	signing map[string]ed25519.PrivateKey, source, recipient string,
	step formalCoxBlockwiseWorkerStep, localValues []*big.Int) ([]byte, []byte) {
	t.Helper()
	values := make(map[string][]*big.Int, 2)
	for _, peer := range session.context.plan.Policy.ComputePeers {
		values[peer] = make([]*big.Int, len(localValues))
		for index := range values[peer] {
			values[peer][index] = new(big.Int)
		}
	}
	values[recipient] = localValues
	envelopes, manifest := formalCoxBlockwiseSourceTestSealBlockPair(
		t, session, signing, source, step, values)
	return envelopes[recipient], manifest
}

func formalCoxBlockwiseSourceTestSealNoisePair(t testing.TB,
	session *formalCoxBlockwiseSourceSession,
	signing map[string]ed25519.PrivateKey,
	step formalCoxBlockwiseWorkerStep,
	values map[string][]*big.Int, validity map[string]bool) (
	map[string][]byte, []byte) {
	t.Helper()
	contract, authorizations := formalCoxBlockwiseStickyGuardTestPreflight(
		t, session, signing)
	envelopes := make(map[string][]byte, 2)
	ordered := make([][]byte, 2)
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		valid := validity[recipient]
		envelopes[recipient] = formalCoxBlockwiseSourceTestSeal(
			t, session, signing, recipient, recipient, step,
			values[recipient], &valid)
		ordered[index] = envelopes[recipient]
	}
	barrier, err := formalCoxBlockwiseNewGuardedNoiseBarrier(
		session, step, ordered, contract, authorizations)
	if err != nil {
		t.Fatal(err)
	}
	approvals := make([]formalCoxBlockwiseNoiseApproval, 2)
	for index, signer := range session.context.plan.Policy.ComputePeers {
		approvals[index], err = formalCoxBlockwiseSignNoiseBarrier(
			session, barrier, ordered, signer, signing[signer])
		if err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := formalCoxBlockwiseFinalizeGuardedNoiseBarrier(
		session, contract, authorizations, barrier, approvals)
	if err != nil {
		t.Fatal(err)
	}
	return envelopes, encoded
}

func formalCoxBlockwiseSourceTestStore(t testing.TB, dir string,
	session *formalCoxBlockwiseSourceSession,
	recipient string, recipientSK []byte) *formalCoxBlockwiseSourceStore {
	t.Helper()
	key := sha256.Sum256([]byte("formal-cox-source-store/" + recipient))
	store, err := newFormalCoxBlockwiseSourceStore(
		dir, key, session, recipient, recipientSK)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func formalCoxBlockwiseSourceAdd(sum, values []*big.Int, ringBits int) {
	modulus := exactGCModulus(ringBits)
	for index := range sum {
		sum[index].Add(sum[index], values[index])
		sum[index].Mod(sum[index], modulus)
	}
}

func TestFormalCoxBlockwiseSourceCodecStoreK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+big.NewInt(int64(custodians)).String(), func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
			session, _, transportSK := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			if plan.RingBits != 128 {
				t.Fatalf("unexpected test-plan ring for K=%d: %d", custodians, plan.RingBits)
			}
			root := t.TempDir()
			stores := make(map[string]*formalCoxBlockwiseSourceStore, 2)
			for _, recipient := range plan.Policy.ComputePeers {
				stores[recipient] = formalCoxBlockwiseSourceTestStore(
					t, filepath.Join(root, recipient), session,
					recipient, transportSK[recipient])
				defer stores[recipient].Close()
			}

			blockExpected := make(map[string][][]*big.Int, 2)
			for _, recipient := range plan.Policy.ComputePeers {
				blockExpected[recipient] = make([][]*big.Int, plan.TotalBlocks)
			}
			for block := 0; block < plan.TotalBlocks; block++ {
				step := formalCoxBlockwiseSourceTestStep(
					t, plan, formalCoxBlockwiseStepBlock, block)
				expected := make(map[string][]*big.Int, 2)
				for _, recipient := range plan.Policy.ComputePeers {
					expected[recipient] = make([]*big.Int,
						plan.BlockCapacity*plan.RowWidth)
					for index := range expected[recipient] {
						expected[recipient][index] = new(big.Int)
					}
				}
				for sourceIndex, source := range plan.Policy.CustodianPeers {
					values := make(map[string][]*big.Int, 2)
					for recipientIndex, recipient := range plan.Policy.ComputePeers {
						values[recipient], _ = formalCoxBlockwiseSourceTestShares(
							plan, step, sourceIndex, recipientIndex)
						formalCoxBlockwiseSourceAdd(
							expected[recipient], values[recipient], plan.RingBits)
					}
					envelopes, manifest := formalCoxBlockwiseSourceTestSealBlockPair(
						t, session, signing, source, step, values)
					for recipientIndex, recipient := range plan.Policy.ComputePeers {
						envelope := envelopes[recipient]
						var public formalCoxBlockwiseSourceEnvelope
						if err := json.Unmarshal(envelope, &public); err != nil {
							t.Fatal(err)
						}
						wantRole := "garbler"
						if recipientIndex == 1 {
							wantRole = "evaluator"
						}
						if public.Header.PlanSHA256 == "" ||
							public.Header.PinsetSHA256 != plan.Policy.PinsetSHA256 ||
							!formalCoxIsSHA256(public.Header.RecipientTicketSHA256) ||
							!formalCoxIsSHA256(public.Header.RecipientManifestSHA256) ||
							public.Header.RecipientRole != wantRole ||
							public.Header.StepKind != formalCoxBlockwiseStepBlock ||
							public.Header.BlockIndex != block ||
							public.Header.CoordinateOffset !=
								block*plan.BlockCapacity*plan.RowWidth ||
							public.Header.RecordBytes != exactGCRecordBytes(plan.RingBits) ||
							len(public.Ciphertext) <= 60 || len(public.Signature) != 64 {
							t.Fatal("source envelope omitted a purpose-bound header field")
						}
						other := plan.Policy.ComputePeers[1-recipientIndex]
						if _, err := transportDecryptBytes(
							public.Ciphertext, transportSK[other]); err == nil {
							t.Fatal("the other recipient decrypted a Cox source share")
						}
						records, err := formalCoxBlockwiseSourceEncodeRecords(
							values[recipient], plan.RingBits)
						if err != nil {
							t.Fatal(err)
						}
						if bytes.Contains(envelope, []byte("shares")) || bytes.Contains(
							envelope, []byte(base64.StdEncoding.EncodeToString(records))) {
							t.Fatal("relay-visible source envelope exposed plaintext shares")
						}
						replayed, err := stores[recipient].Accept(envelope, manifest)
						if err != nil || replayed {
							t.Fatalf("accept K=%d block=%d source=%d recipient=%s: replay=%v err=%v",
								custodians, block, sourceIndex, recipient, replayed, err)
						}
					}
				}
				for _, recipient := range plan.Policy.ComputePeers {
					blockExpected[recipient][block] = expected[recipient]
				}
			}

			noiseExpected := make(map[string][][]*big.Int, 2)
			noiseValidity := make(map[string][]bool, 2)
			for _, recipient := range plan.Policy.ComputePeers {
				noiseExpected[recipient] = make([][]*big.Int, plan.Iterations)
				noiseValidity[recipient] = make([]bool, plan.Iterations)
			}
			for iteration := 0; iteration < plan.Iterations; iteration++ {
				step := formalCoxBlockwiseSourceTestStep(
					t, plan, formalCoxBlockwiseStepUpdate, iteration)
				values := make(map[string][]*big.Int, 2)
				validity := make(map[string]bool, 2)
				for recipientIndex, recipient := range plan.Policy.ComputePeers {
					shares, valid := formalCoxBlockwiseSourceTestShares(
						plan, step, recipientIndex, recipientIndex)
					values[recipient], validity[recipient] = shares, *valid
					noiseExpected[recipient][iteration] = shares
					noiseValidity[recipient][iteration] = *valid
				}
				envelopes, barrier := formalCoxBlockwiseSourceTestSealNoisePair(
					t, session, signing, step, values, validity)
				for _, recipient := range plan.Policy.ComputePeers {
					if _, err := stores[recipient].Accept(
						envelopes[recipient], barrier); err != nil {
						t.Fatalf("noise iteration=%d recipient=%s: %v",
							iteration, recipient, err)
					}
				}
			}

			roots := make(map[string]string, 2)
			for _, recipient := range plan.Policy.ComputePeers {
				for block := 0; block < plan.TotalBlocks; block++ {
					step := formalCoxBlockwiseSourceTestStep(
						t, plan, formalCoxBlockwiseStepBlock, block)
					input, err := stores[recipient].Load(step)
					if err != nil || input.ValidityShare != nil ||
						!bigIntSlicesEqual(input.Shares, blockExpected[recipient][block]) {
						t.Fatalf("loaded block differs for K=%d recipient=%s: %v",
							custodians, recipient, err)
					}
					serialized, err := json.Marshal(input)
					if err != nil || bytes.Contains(serialized, []byte("Shares")) ||
						bytes.Contains(serialized, []byte("ValidityShare")) {
						t.Fatalf("private source input was serializable: %s (%v)",
							serialized, err)
					}
					if block == plan.TotalBlocks-1 {
						rows := formalCoxBlockwiseSourceRowsInBlock(plan, block)
						for _, value := range input.Shares[rows*plan.RowWidth:] {
							if value.Sign() != 0 {
								t.Fatal("last Cox source block was not canonically padded")
							}
						}
					}
					roots[recipient] = input.RecipientRootSHA256
				}
				for iteration := 0; iteration < plan.Iterations; iteration++ {
					step := formalCoxBlockwiseSourceTestStep(
						t, plan, formalCoxBlockwiseStepUpdate, iteration)
					input, err := stores[recipient].Load(step)
					if err != nil || input.ValidityShare == nil ||
						*input.ValidityShare != noiseValidity[recipient][iteration] ||
						!bigIntSlicesEqual(
							input.Shares, noiseExpected[recipient][iteration]) ||
						!formalCoxIsSHA256(input.RecipientRootSHA256) {
						t.Fatalf("loaded noise differs for K=%d recipient=%s iteration=%d: %v",
							custodians, recipient, iteration, err)
					}
				}
			}
			if roots[plan.Policy.ComputePeers[0]] == roots[plan.Policy.ComputePeers[1]] {
				t.Fatal("recipient-bound source roots unexpectedly collided")
			}
		})
	}
}

func TestFormalCoxBlockwiseSourcePairedRootsK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+big.NewInt(int64(custodians)).String(), func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
			session, _, transportSK := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			stores := make(map[string]*formalCoxBlockwiseSourceStore, 2)
			for _, recipient := range plan.Policy.ComputePeers {
				stores[recipient] = formalCoxBlockwiseSourceTestStore(
					t, filepath.Join(t.TempDir(), recipient), session,
					recipient, transportSK[recipient])
				defer stores[recipient].Close()
			}

			step := formalCoxBlockwiseSourceTestStep(
				t, plan, formalCoxBlockwiseStepBlock, 0)
			for sourceIndex, source := range plan.Policy.CustodianPeers {
				values := make(map[string][]*big.Int, 2)
				for recipientIndex, recipient := range plan.Policy.ComputePeers {
					values[recipient], _ = formalCoxBlockwiseSourceTestShares(
						plan, step, sourceIndex, recipientIndex)
				}
				envelopes, manifest := formalCoxBlockwiseSourceTestSealBlockPair(
					t, session, signing, source, step, values)
				for _, recipient := range plan.Policy.ComputePeers {
					if _, err := stores[recipient].Accept(
						envelopes[recipient], manifest); err != nil {
						t.Fatalf("paired block source=%s recipient=%s: %v",
							source, recipient, err)
					}
				}
			}
			blockInputs := make([]formalCoxBlockwiseSourceInput, 2)
			for index, recipient := range plan.Policy.ComputePeers {
				var err error
				blockInputs[index], err = stores[recipient].Load(step)
				if err != nil || !formalCoxIsSHA256(
					blockInputs[index].PairedInputRootSHA256) {
					t.Fatalf("paired block load recipient=%s: %v", recipient, err)
				}
			}
			if blockInputs[0].PairedInputRootSHA256 !=
				blockInputs[1].PairedInputRootSHA256 ||
				blockInputs[0].RecipientRootSHA256 ==
					blockInputs[1].RecipientRootSHA256 {
				t.Fatal("recipient-local roots did not converge on one paired block root")
			}

			for block := 1; block < plan.TotalBlocks; block++ {
				blockStep := formalCoxBlockwiseSourceTestStep(
					t, plan, formalCoxBlockwiseStepBlock, block)
				for sourceIndex, source := range plan.Policy.CustodianPeers {
					values := make(map[string][]*big.Int, 2)
					for recipientIndex, recipient := range plan.Policy.ComputePeers {
						values[recipient], _ = formalCoxBlockwiseSourceTestShares(
							plan, blockStep, sourceIndex, recipientIndex)
					}
					envelopes, manifest := formalCoxBlockwiseSourceTestSealBlockPair(
						t, session, signing, source, blockStep, values)
					for _, recipient := range plan.Policy.ComputePeers {
						if _, err := stores[recipient].Accept(
							envelopes[recipient], manifest); err != nil {
							t.Fatal(err)
						}
					}
				}
			}

			noiseStep := formalCoxBlockwiseSourceTestStep(
				t, plan, formalCoxBlockwiseStepUpdate, 0)
			noiseValues := make(map[string][]*big.Int, 2)
			noiseValidity := make(map[string]bool, 2)
			for recipientIndex, recipient := range plan.Policy.ComputePeers {
				values, validity := formalCoxBlockwiseSourceTestShares(
					plan, noiseStep, recipientIndex, recipientIndex)
				noiseValues[recipient] = values
				noiseValidity[recipient] = *validity
			}
			noiseEnvelopes, barrier := formalCoxBlockwiseSourceTestSealNoisePair(
				t, session, signing, noiseStep, noiseValues, noiseValidity)
			for _, recipient := range plan.Policy.ComputePeers {
				if _, err := stores[recipient].Accept(
					noiseEnvelopes[recipient], barrier); err != nil {
					t.Fatalf("paired noise recipient=%s: %v", recipient, err)
				}
			}
			noiseInputs := make([]formalCoxBlockwiseSourceInput, 2)
			for index, recipient := range plan.Policy.ComputePeers {
				var err error
				noiseInputs[index], err = stores[recipient].Load(noiseStep)
				if err != nil {
					t.Fatal(err)
				}
			}
			if noiseInputs[0].PairedInputRootSHA256 !=
				noiseInputs[1].PairedInputRootSHA256 ||
				!formalCoxIsSHA256(noiseInputs[0].PairedInputRootSHA256) {
				t.Fatal("noise authorities did not derive one paired noise root")
			}

			for _, store := range stores {
				for slot := 0; slot <= plan.TotalBlocks*len(
					plan.Policy.CustodianPeers); slot++ {
					encoded, err := os.ReadFile(store.slotPath(slot))
					if err != nil {
						continue
					}
					lower := bytes.ToLower(encoded)
					for _, forbidden := range [][]byte{
						[]byte(`"shares"`), []byte(`"validity_share"`),
						[]byte(`"plaintext"`),
					} {
						if bytes.Contains(lower, forbidden) {
							t.Fatalf("persisted pair artifact exposed private input: %s",
								forbidden)
						}
					}
				}
			}
		})
	}
}

func TestFormalCoxBlockwiseSourcePairBindingsRejectAdversarialMixes(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+big.NewInt(int64(custodians)).String(), func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
			session, _, transportSK := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			step := formalCoxBlockwiseSourceTestStep(
				t, plan, formalCoxBlockwiseStepBlock, 0)
			source := plan.Policy.CustodianPeers[0]
			values := make(map[string][]*big.Int, 2)
			for index, recipient := range plan.Policy.ComputePeers {
				values[recipient], _ = formalCoxBlockwiseSourceTestShares(
					plan, step, 0, index)
			}
			envelopes, manifest := formalCoxBlockwiseSourceTestSealBlockPair(
				t, session, signing, source, step, values)
			left, right := plan.Policy.ComputePeers[0], plan.Policy.ComputePeers[1]
			newStore := func(label string) *formalCoxBlockwiseSourceStore {
				return formalCoxBlockwiseSourceTestStore(t,
					filepath.Join(t.TempDir(), label), session, left, transportSK[left])
			}

			swap := newStore("swap")
			if _, err := swap.Accept(envelopes[right], manifest); err == nil {
				t.Fatal("a recipient-swapped envelope entered the paired store")
			}
			_ = swap.Close()
			missingBinding := newStore("missing-binding")
			if _, err := missingBinding.Accept(envelopes[left], nil); err == nil {
				t.Fatal("a source ciphertext without its pair manifest was accepted")
			}
			_ = missingBinding.Close()

			rerollValues := make(map[string][]*big.Int, 2)
			for recipient, original := range values {
				rerollValues[recipient] = make([]*big.Int, len(original))
				for index, value := range original {
					rerollValues[recipient][index] = new(big.Int).Set(value)
				}
				rerollValues[recipient][0].Add(
					rerollValues[recipient][0], big.NewInt(1))
			}
			rerolled, rerolledManifest := formalCoxBlockwiseSourceTestSealBlockPair(
				t, session, signing, source, step, rerollValues)
			mix := newStore("mix")
			if _, err := mix.Accept(envelopes[left], rerolledManifest); err == nil {
				t.Fatal("an envelope from another signed pair was mixed in")
			}
			_ = mix.Close()

			replay := newStore("reroll")
			if _, err := replay.Accept(envelopes[left], manifest); err != nil {
				t.Fatal(err)
			}
			if _, err := replay.Accept(rerolled[left], rerolledManifest); err == nil {
				t.Fatal("a signed reroll replaced the sticky source pair")
			}
			_ = replay.Close()

			var decoded formalCoxBlockwiseSourcePairManifest
			if err := json.Unmarshal(manifest, &decoded); err != nil {
				t.Fatal(err)
			}
			bindingMutations := []struct {
				name  string
				apply func(*formalCoxBlockwiseSourcePairManifest)
			}{
				{"plan", func(value *formalCoxBlockwiseSourcePairManifest) {
					value.PlanSHA256 = strings.Repeat("0", 64)
				}},
				{"run", func(value *formalCoxBlockwiseSourcePairManifest) {
					value.RunID = strings.Repeat("0", 64)
				}},
				{"pinset", func(value *formalCoxBlockwiseSourcePairManifest) {
					value.PinsetSHA256 = strings.Repeat("0", 64)
				}},
				{"ticket-manifest", func(value *formalCoxBlockwiseSourcePairManifest) {
					value.RecipientManifestSHA256 = strings.Repeat("0", 64)
				}},
				{"role", func(value *formalCoxBlockwiseSourcePairManifest) {
					value.Recipients[0].RecipientRole = "evaluator"
				}},
				{"ticket", func(value *formalCoxBlockwiseSourcePairManifest) {
					value.Recipients[0].RecipientTicketSHA256 = strings.Repeat("0", 64)
				}},
				{"slot", func(value *formalCoxBlockwiseSourcePairManifest) {
					value.Recipients[0].AssetSlot++
				}},
			}
			for _, mutation := range bindingMutations {
				mutated := decoded
				mutated.Recipients = append(
					[]formalCoxBlockwiseSourcePairRecipient(nil), decoded.Recipients...)
				mutation.apply(&mutated)
				mutated.Signature = nil
				root, rootErr := formalCoxBlockwiseSourcePairManifestRoot(mutated)
				if rootErr != nil {
					t.Fatal(rootErr)
				}
				mutated.PairedInputRootSHA256 = root
				message, messageErr := formalCoxBlockwiseSourcePairManifestMessage(mutated)
				if messageErr != nil {
					t.Fatal(messageErr)
				}
				mutated.Signature = ed25519.Sign(signing[source], message)
				mutatedBytes, _ := json.Marshal(mutated)
				mutatedStore := newStore("binding-" + mutation.name)
				if _, err := mutatedStore.Accept(
					envelopes[left], mutatedBytes); err == nil {
					t.Fatalf("a re-signed pair with wrong %s was accepted", mutation.name)
				}
				_ = mutatedStore.Close()
			}
			reordered := decoded
			reordered.Recipients = append(
				[]formalCoxBlockwiseSourcePairRecipient(nil), decoded.Recipients...)
			reordered.Recipients[0], reordered.Recipients[1] =
				reordered.Recipients[1], reordered.Recipients[0]
			reordered.Signature = nil
			message, err := formalCoxBlockwiseSourcePairManifestMessage(reordered)
			if err != nil {
				t.Fatal(err)
			}
			reordered.Signature = ed25519.Sign(signing[source], message)
			reorderedBytes, _ := json.Marshal(reordered)
			reorderStore := newStore("reorder")
			if _, err := reorderStore.Accept(
				envelopes[left], reorderedBytes); err == nil {
				t.Fatal("a re-signed reordered recipient pair was accepted")
			}
			_ = reorderStore.Close()

			oneSided := decoded
			oneSided.Recipients = append(
				[]formalCoxBlockwiseSourcePairRecipient(nil), decoded.Recipients[:1]...)
			oneSided.Signature = nil
			message, _ = formalCoxBlockwiseSourcePairManifestMessage(oneSided)
			oneSided.Signature = ed25519.Sign(signing[source], message)
			oneSidedBytes, _ := json.Marshal(oneSided)
			oneStore := newStore("one-sided")
			if _, err := oneStore.Accept(envelopes[left], oneSidedBytes); err == nil {
				t.Fatal("a one-sided source pair was accepted")
			}
			_ = oneStore.Close()

			duplicate := decoded
			duplicate.Recipients = append(
				[]formalCoxBlockwiseSourcePairRecipient(nil), decoded.Recipients...)
			duplicate.Recipients[1].EnvelopeSHA256 =
				duplicate.Recipients[0].EnvelopeSHA256
			duplicate.Signature = nil
			duplicate.PairedInputRootSHA256, err =
				formalCoxBlockwiseSourcePairManifestRoot(duplicate)
			if err != nil {
				t.Fatal(err)
			}
			message, _ = formalCoxBlockwiseSourcePairManifestMessage(duplicate)
			duplicate.Signature = ed25519.Sign(signing[source], message)
			duplicateBytes, _ := json.Marshal(duplicate)
			duplicateStore := newStore("duplicate-ciphertext")
			if _, err := duplicateStore.Accept(
				envelopes[left], duplicateBytes); err == nil {
				t.Fatal("the local ciphertext appeared twice in its source pair")
			}
			_ = duplicateStore.Close()

			wrongSigner := decoded
			wrongSigner.Signature = nil
			message, _ = formalCoxBlockwiseSourcePairManifestMessage(wrongSigner)
			wrongSigner.Signature = ed25519.Sign(signing[right], message)
			wrongBytes, _ := json.Marshal(wrongSigner)
			wrongStore := newStore("wrong-signer")
			if _, err := wrongStore.Accept(envelopes[left], wrongBytes); err == nil {
				t.Fatal("a pair manifest signed by the wrong authority was accepted")
			}
			_ = wrongStore.Close()

			tampered := append([]byte(nil), manifest...)
			tampered[len(tampered)/2] ^= 1
			tamperStore := newStore("tamper")
			if _, err := tamperStore.Accept(envelopes[left], tampered); err == nil {
				t.Fatal("a tampered pair manifest was accepted")
			}
			_ = tamperStore.Close()
		})
	}
}

func TestFormalCoxBlockwiseNoiseBarrierRejectsAdversarialMixesK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+big.NewInt(int64(custodians)).String(), func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
			session, _, transportSK := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			step := formalCoxBlockwiseSourceTestStep(
				t, plan, formalCoxBlockwiseStepUpdate, 0)
			values := make(map[string][]*big.Int, 2)
			validity := make(map[string]bool, 2)
			for index, recipient := range plan.Policy.ComputePeers {
				local, valid := formalCoxBlockwiseSourceTestShares(
					plan, step, index, index)
				values[recipient], validity[recipient] = local, *valid
			}
			envelopes, encodedBarrier := formalCoxBlockwiseSourceTestSealNoisePair(
				t, session, signing, step, values, validity)
			left, right := plan.Policy.ComputePeers[0], plan.Policy.ComputePeers[1]
			leftStore := formalCoxBlockwiseSourceTestStore(t,
				filepath.Join(t.TempDir(), "left"), session, left, transportSK[left])
			defer leftStore.Close()
			rightStore := formalCoxBlockwiseSourceTestStore(t,
				filepath.Join(t.TempDir(), "right"), session, right, transportSK[right])
			defer rightStore.Close()
			leftSlot, err := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[left], encodedBarrier)
			if err != nil {
				t.Fatal(err)
			}
			rightSlot, err := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[right], encodedBarrier)
			if err != nil {
				t.Fatal(err)
			}
			_, _, leftRoot, leftShares, _, leftErr :=
				leftStore.validateBoundSlot(leftSlot)
			_, _, rightRoot, rightShares, _, rightErr :=
				rightStore.validateBoundSlot(rightSlot)
			exactGCZeroBigInts(leftShares)
			exactGCZeroBigInts(rightShares)
			if leftErr != nil || rightErr != nil || leftRoot != rightRoot ||
				!formalCoxIsSHA256(leftRoot) {
				t.Fatalf("valid noise barrier diverged: left=%v right=%v", leftErr, rightErr)
			}

			if _, _, _, shares, _, err := leftStore.validateBoundSlot(
				rightSlot); err == nil {
				exactGCZeroBigInts(shares)
				t.Fatal("a recipient-swapped noise ciphertext was accepted")
			}

			rerolledValues := make(map[string][]*big.Int, 2)
			for recipient, original := range values {
				rerolledValues[recipient] = make([]*big.Int, len(original))
				for index, value := range original {
					rerolledValues[recipient][index] = new(big.Int).Set(value)
				}
				rerolledValues[recipient][0].Add(
					rerolledValues[recipient][0], big.NewInt(1))
			}
			rerolled, rerolledBarrier := formalCoxBlockwiseSourceTestSealNoisePair(
				t, session, signing, step, rerolledValues, validity)
			mixedSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				rerolled[left], encodedBarrier)
			if _, _, _, shares, _, err := leftStore.validateBoundSlot(
				mixedSlot); err == nil {
				exactGCZeroBigInts(shares)
				t.Fatal("noise ciphertext from another barrier was mixed in")
			}
			rerolledSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				rerolled[left], rerolledBarrier)
			_, _, rerolledRoot, rerolledShares, _, err :=
				leftStore.validateBoundSlot(rerolledSlot)
			exactGCZeroBigInts(rerolledShares)
			if err != nil || rerolledRoot == leftRoot {
				t.Fatal("a valid noise reroll did not change its paired root")
			}

			var guarded formalCoxBlockwiseGuardedNoiseBarrier
			if err := json.Unmarshal(encodedBarrier, &guarded); err != nil {
				t.Fatal(err)
			}
			barrier := guarded.Barrier
			barrierMutations := []struct {
				name  string
				apply func(*formalCoxBlockwiseNoiseBarrier)
			}{
				{"plan", func(value *formalCoxBlockwiseNoiseBarrier) {
					value.PlanSHA256 = strings.Repeat("0", 64)
				}},
				{"run", func(value *formalCoxBlockwiseNoiseBarrier) {
					value.RunID = strings.Repeat("0", 64)
				}},
				{"pinset", func(value *formalCoxBlockwiseNoiseBarrier) {
					value.PinsetSHA256 = strings.Repeat("0", 64)
				}},
				{"ticket-manifest", func(value *formalCoxBlockwiseNoiseBarrier) {
					value.RecipientManifestSHA256 = strings.Repeat("0", 64)
				}},
				{"role", func(value *formalCoxBlockwiseNoiseBarrier) {
					value.NoiseRoots[0].RecipientRole = "evaluator"
				}},
				{"ticket", func(value *formalCoxBlockwiseNoiseBarrier) {
					value.NoiseRoots[0].RecipientTicketSHA256 = strings.Repeat("0", 64)
				}},
				{"slot", func(value *formalCoxBlockwiseNoiseBarrier) {
					value.NoiseRoots[0].AssetSlot++
				}},
				{"schedule", func(value *formalCoxBlockwiseNoiseBarrier) {
					value.CanonicalScheduleIndex++
				}},
			}
			for _, mutation := range barrierMutations {
				mutated := barrier
				mutated.NoiseRoots = append(
					[]formalCoxBlockwiseNoiseRootCommitment(nil), barrier.NoiseRoots...)
				mutated.Approvals = nil
				mutation.apply(&mutated)
				mutated.PairedNoiseRootSHA256, err =
					formalCoxBlockwiseNoiseBarrierRoot(mutated)
				if err != nil {
					t.Fatal(err)
				}
				message, messageErr := formalCoxBlockwiseNoiseBarrierMessage(mutated)
				if messageErr != nil {
					t.Fatal(messageErr)
				}
				for _, signer := range plan.Policy.ComputePeers {
					mutated.Approvals = append(mutated.Approvals,
						formalCoxBlockwiseNoiseApproval{
							SignerPeerName: signer,
							SignerPeerID:   session.context.peerIDs[signer],
							SignerRole:     session.context.roles[signer],
							Signature:      ed25519.Sign(signing[signer], message),
						})
				}
				mutatedBytes, _ := json.Marshal(mutated)
				mutatedSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
					envelopes[left], mutatedBytes)
				if _, _, _, shares, _, err := leftStore.validateBoundSlot(
					mutatedSlot); err == nil {
					exactGCZeroBigInts(shares)
					t.Fatalf("a fully signed noise barrier with wrong %s was accepted",
						mutation.name)
				}
			}
			oneSided := barrier
			oneSided.Approvals = append(
				[]formalCoxBlockwiseNoiseApproval(nil), barrier.Approvals[:1]...)
			oneSidedBytes, _ := json.Marshal(oneSided)
			oneSidedSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[left], oneSidedBytes)
			if _, _, _, shares, _, err := leftStore.validateBoundSlot(
				oneSidedSlot); err == nil {
				exactGCZeroBigInts(shares)
				t.Fatal("a one-sided noise approval crossed the barrier")
			}

			oneRoot := barrier
			oneRoot.NoiseRoots = append(
				[]formalCoxBlockwiseNoiseRootCommitment(nil), barrier.NoiseRoots[:1]...)
			oneRoot.Approvals = nil
			oneRoot.PairedNoiseRootSHA256, err =
				formalCoxBlockwiseNoiseBarrierRoot(oneRoot)
			if err != nil {
				t.Fatal(err)
			}
			message, _ := formalCoxBlockwiseNoiseBarrierMessage(oneRoot)
			for _, signer := range plan.Policy.ComputePeers {
				oneRoot.Approvals = append(oneRoot.Approvals,
					formalCoxBlockwiseNoiseApproval{
						SignerPeerName: signer,
						SignerPeerID:   session.context.peerIDs[signer],
						SignerRole:     session.context.roles[signer],
						Signature:      ed25519.Sign(signing[signer], message),
					})
			}
			oneRootBytes, _ := json.Marshal(oneRoot)
			oneRootSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[left], oneRootBytes)
			if _, _, _, shares, _, err := leftStore.validateBoundSlot(
				oneRootSlot); err == nil {
				exactGCZeroBigInts(shares)
				t.Fatal("a fully signed one-sided noise commitment was accepted")
			}

			duplicateRoot := barrier
			duplicateRoot.NoiseRoots = append(
				[]formalCoxBlockwiseNoiseRootCommitment(nil), barrier.NoiseRoots...)
			duplicateRoot.NoiseRoots[1].EnvelopeSHA256 =
				duplicateRoot.NoiseRoots[0].EnvelopeSHA256
			duplicateRoot.Approvals = nil
			duplicateRoot.PairedNoiseRootSHA256, err =
				formalCoxBlockwiseNoiseBarrierRoot(duplicateRoot)
			if err != nil {
				t.Fatal(err)
			}
			message, _ = formalCoxBlockwiseNoiseBarrierMessage(duplicateRoot)
			for _, signer := range plan.Policy.ComputePeers {
				duplicateRoot.Approvals = append(duplicateRoot.Approvals,
					formalCoxBlockwiseNoiseApproval{
						SignerPeerName: signer,
						SignerPeerID:   session.context.peerIDs[signer],
						SignerRole:     session.context.roles[signer],
						Signature:      ed25519.Sign(signing[signer], message),
					})
			}
			duplicateRootBytes, _ := json.Marshal(duplicateRoot)
			duplicateRootSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[left], duplicateRootBytes)
			if _, _, _, shares, _, err := leftStore.validateBoundSlot(
				duplicateRootSlot); err == nil {
				exactGCZeroBigInts(shares)
				t.Fatal("the local noise ciphertext appeared twice in its barrier")
			}

			wrongSigner := barrier
			wrongSigner.Approvals = append(
				[]formalCoxBlockwiseNoiseApproval(nil), barrier.Approvals...)
			message, err = formalCoxBlockwiseNoiseBarrierMessage(wrongSigner)
			if err != nil {
				t.Fatal(err)
			}
			wrongSigner.Approvals[0].Signature = ed25519.Sign(signing[right], message)
			wrongBytes, _ := json.Marshal(wrongSigner)
			wrongSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[left], wrongBytes)
			if _, _, _, shares, _, err := leftStore.validateBoundSlot(
				wrongSlot); err == nil {
				exactGCZeroBigInts(shares)
				t.Fatal("a noise barrier approval used the wrong signer")
			}

			reordered := barrier
			reordered.NoiseRoots = append(
				[]formalCoxBlockwiseNoiseRootCommitment(nil), barrier.NoiseRoots...)
			reordered.NoiseRoots[0], reordered.NoiseRoots[1] =
				reordered.NoiseRoots[1], reordered.NoiseRoots[0]
			reordered.Approvals = nil
			reordered.PairedNoiseRootSHA256, err =
				formalCoxBlockwiseNoiseBarrierRoot(reordered)
			if err != nil {
				t.Fatal(err)
			}
			message, _ = formalCoxBlockwiseNoiseBarrierMessage(reordered)
			for _, signer := range plan.Policy.ComputePeers {
				reordered.Approvals = append(reordered.Approvals,
					formalCoxBlockwiseNoiseApproval{
						SignerPeerName: signer,
						SignerPeerID:   session.context.peerIDs[signer],
						SignerRole:     session.context.roles[signer],
						Signature:      ed25519.Sign(signing[signer], message),
					})
			}
			reorderedBytes, _ := json.Marshal(reordered)
			reorderedSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[left], reorderedBytes)
			if _, _, _, shares, _, err := leftStore.validateBoundSlot(
				reorderedSlot); err == nil {
				exactGCZeroBigInts(shares)
				t.Fatal("a fully signed reordered noise pair was accepted")
			}

			tampered := append([]byte(nil), encodedBarrier...)
			tampered[len(tampered)/2] ^= 1
			tamperedSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[left], tampered)
			if _, _, _, shares, _, err := leftStore.validateBoundSlot(
				tamperedSlot); err == nil {
				exactGCZeroBigInts(shares)
				t.Fatal("a tampered paired noise barrier was accepted")
			}
		})
	}
}

func TestFormalCoxBlockwiseSourceCanonicalDynamicLimbEncoding(t *testing.T) {
	for _, ringBits := range []int{128, 130, 256, 512} {
		values := []*big.Int{
			big.NewInt(0),
			new(big.Int).Lsh(big.NewInt(1), uint(ringBits-1)),
			new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(ringBits)),
				big.NewInt(1)),
		}
		encoded, err := formalCoxBlockwiseSourceEncodeRecords(values, ringBits)
		if err != nil || len(encoded) != len(values)*exactGCRecordBytes(ringBits) {
			t.Fatalf("Ring%d encode: bytes=%d err=%v", ringBits, len(encoded), err)
		}
		decoded, err := formalCoxBlockwiseSourceDecodeRecords(
			encoded, len(values), ringBits)
		if err != nil || !bigIntSlicesEqual(values, decoded) {
			t.Fatalf("Ring%d limb roundtrip failed: %v", ringBits, err)
		}
		validity := true
		header := formalCoxBlockwiseSourceHeader{
			Version:         formalCoxBlockwiseSourceEnvelopeVersion,
			Purpose:         formalCoxBlockwiseSourcePurpose,
			StepKind:        formalCoxBlockwiseStepUpdate,
			CoordinateCount: len(values), RingBits: ringBits,
			RecordBytes: exactGCRecordBytes(ringBits), HasValidityShare: true,
		}
		payload, err := formalCoxBlockwiseSourcePrivatePayload(
			header, values, &validity)
		if err != nil {
			t.Fatalf("Ring%d private payload: %v", ringBits, err)
		}
		privateValues, privateValidity, err :=
			formalCoxBlockwiseSourceDecodePrivate(header, payload)
		if err != nil || privateValidity == nil || !*privateValidity ||
			!bigIntSlicesEqual(values, privateValues) {
			t.Fatalf("Ring%d private codec roundtrip failed: %v", ringBits, err)
		}
		tampered := append([]byte(nil), encoded...)
		tampered[exactGCRecordBytes(ringBits)-1] = 0xff
		if ringBits%8 != 0 {
			if _, err := formalCoxBlockwiseSourceDecodeRecords(
				tampered, len(values), ringBits); err == nil {
				t.Fatalf("Ring%d non-zero high limb padding was accepted", ringBits)
			}
		}
	}
}

func TestFormalCoxBlockwiseSourceRing128StoreWrapsExactly(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
	if plan.RingBits != 128 {
		t.Fatalf("wrap fixture changed to Ring%d", plan.RingBits)
	}
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	recipient := plan.Policy.ComputePeers[0]
	store := formalCoxBlockwiseSourceTestStore(
		t, filepath.Join(t.TempDir(), "ring128-wrap"), session,
		recipient, transportSK[recipient])
	defer store.Close()
	step := formalCoxBlockwiseSourceTestStep(
		t, plan, formalCoxBlockwiseStepBlock, 0)
	modulus := exactGCModulus(plan.RingBits)
	for sourceIndex, source := range plan.Policy.CustodianPeers {
		values := make([]*big.Int, plan.BlockCapacity*plan.RowWidth)
		for index := range values {
			values[index] = new(big.Int)
		}
		if sourceIndex == 0 {
			values[0].Sub(modulus, big.NewInt(1))
		} else if sourceIndex == 1 {
			values[0].SetInt64(2)
		}
		envelope, manifest := formalCoxBlockwiseSourceTestSealLocalBlockPair(
			t, session, signing, source, recipient, step, values)
		if _, err := store.Accept(envelope, manifest); err != nil {
			t.Fatal(err)
		}
	}
	input, err := store.Load(step)
	if err != nil || input.Shares[0].Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("Ring128 modular wrap changed: %v (%v)", input.Shares[0], err)
	}
	if new(big.Int).Sub(modulus, big.NewInt(1)).BitLen() <= 53 {
		t.Fatal("Ring128 fixture did not exercise values above 2^53")
	}
}

func TestFormalCoxBlockwiseSourceRecipientsHoldOnlyComplementaryShares(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	stores := make(map[string]*formalCoxBlockwiseSourceStore, 2)
	root := t.TempDir()
	for _, recipient := range plan.Policy.ComputePeers {
		stores[recipient] = formalCoxBlockwiseSourceTestStore(
			t, filepath.Join(root, recipient), session,
			recipient, transportSK[recipient])
		defer stores[recipient].Close()
	}
	step := formalCoxBlockwiseSourceTestStep(
		t, plan, formalCoxBlockwiseStepBlock, 0)
	count := plan.BlockCapacity * plan.RowWidth
	modulus := exactGCModulus(plan.RingBits)
	original := make([]*big.Int, count)
	for index := range original {
		original[index] = new(big.Int)
	}
	original[0].SetInt64(424242)
	left := new(big.Int).Lsh(big.NewInt(1), 70)
	right := new(big.Int).Sub(original[0], left)
	right.Mod(right, modulus)
	for sourceIndex, source := range plan.Policy.CustodianPeers {
		values := make(map[string][]*big.Int, 2)
		for recipientIndex, recipient := range plan.Policy.ComputePeers {
			values[recipient] = make([]*big.Int, count)
			for index := range values[recipient] {
				values[recipient][index] = new(big.Int)
			}
			if sourceIndex == 0 {
				if recipientIndex == 0 {
					values[recipient][0].Set(left)
				} else {
					values[recipient][0].Set(right)
				}
			}
		}
		envelopes, manifest := formalCoxBlockwiseSourceTestSealBlockPair(
			t, session, signing, source, step, values)
		for _, recipient := range plan.Policy.ComputePeers {
			if _, err := stores[recipient].Accept(
				envelopes[recipient], manifest); err != nil {
				t.Fatal(err)
			}
		}
	}
	loaded := make([]formalCoxBlockwiseSourceInput, 2)
	for index, recipient := range plan.Policy.ComputePeers {
		var err error
		loaded[index], err = stores[recipient].Load(step)
		if err != nil {
			t.Fatal(err)
		}
		if loaded[index].Shares[0].Cmp(original[0]) == 0 {
			t.Fatal("one compute recipient received the reconstructed source value")
		}
	}
	reconstructed := new(big.Int).Add(
		loaded[0].Shares[0], loaded[1].Shares[0])
	reconstructed.Mod(reconstructed, modulus)
	if reconstructed.Cmp(original[0]) != 0 {
		t.Fatalf("recipient shares did not reconstruct exactly: %s", reconstructed)
	}
	if loaded[0].RecipientRootSHA256 == loaded[1].RecipientRootSHA256 {
		t.Fatal("complementary recipient shares had the same authenticated root")
	}
	if loaded[0].PairedInputRootSHA256 != loaded[1].PairedInputRootSHA256 ||
		!formalCoxIsSHA256(loaded[0].PairedInputRootSHA256) {
		t.Fatal("complementary shares did not bind one common input root")
	}
}

func bigIntSlicesEqual(left, right []*big.Int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] == nil || right[index] == nil || left[index].Cmp(right[index]) != 0 {
			return false
		}
	}
	return true
}

func TestFormalCoxBlockwiseSourceFailsClosedOnTamperOrderAndReplay(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	recipient := plan.Policy.ComputePeers[0]
	store := formalCoxBlockwiseSourceTestStore(
		t, filepath.Join(t.TempDir(), "store"), session,
		recipient, transportSK[recipient])
	defer store.Close()
	step := formalCoxBlockwiseSourceTestStep(
		t, plan, formalCoxBlockwiseStepBlock, 0)
	firstValues, _ := formalCoxBlockwiseSourceTestShares(plan, step, 0, 0)
	secondValues, _ := formalCoxBlockwiseSourceTestShares(plan, step, 1, 0)
	first, firstManifest := formalCoxBlockwiseSourceTestSealLocalBlockPair(
		t, session, signing, plan.Policy.CustodianPeers[0], recipient, step,
		firstValues)
	second, secondManifest := formalCoxBlockwiseSourceTestSealLocalBlockPair(
		t, session, signing, plan.Policy.CustodianPeers[1], recipient, step,
		secondValues)
	if _, err := store.Accept(second, secondManifest); err == nil {
		t.Fatal("reordered source envelope was accepted")
	}
	tampered := append([]byte(nil), first...)
	tampered[len(tampered)/2] ^= 1
	if _, err := store.Accept(tampered, firstManifest); err == nil {
		t.Fatal("tampered source envelope was accepted")
	}
	var signed formalCoxBlockwiseSourceEnvelope
	if err := json.Unmarshal(first, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Ciphertext[0] ^= 1
	cipherSHA := sha256.Sum256(signed.Ciphertext)
	signed.CiphertextSHA256 = hex.EncodeToString(cipherSHA[:])
	reserialized, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Accept(reserialized, firstManifest); err == nil {
		t.Fatal("source ciphertext changed without a new signature was accepted")
	}
	if replayed, err := store.Accept(first, firstManifest); err != nil || replayed {
		t.Fatalf("valid source envelope after tamper: replay=%v err=%v", replayed, err)
	}
	if replayed, err := store.Accept(first, firstManifest); err != nil || !replayed {
		t.Fatalf("byte-identical source replay failed: replay=%v err=%v", replayed, err)
	}
	conflict, conflictManifest := formalCoxBlockwiseSourceTestSealLocalBlockPair(
		t, session, signing, plan.Policy.CustodianPeers[0], recipient, step,
		firstValues)
	if bytes.Equal(first, conflict) {
		t.Fatal("fresh transport nonce did not change the envelope")
	}
	if _, err := store.Accept(conflict, conflictManifest); err == nil {
		t.Fatal("conflicting source replay was accepted")
	}
	if _, err := store.Accept(first[:len(first)-1], firstManifest); err == nil {
		t.Fatal("truncated source envelope was accepted")
	}
	wrongRecipient := plan.Policy.ComputePeers[1]
	misrouted, misroutedManifest := formalCoxBlockwiseSourceTestSealLocalBlockPair(
		t, session, signing, plan.Policy.CustodianPeers[1], wrongRecipient, step,
		secondValues)
	if _, err := store.Accept(misrouted, misroutedManifest); err == nil {
		t.Fatal("source envelope for the other recipient was accepted")
	}
	missingPin := make(map[string]ed25519.PublicKey, len(pins)-1)
	for peer, pin := range pins {
		if peer != plan.Policy.CustodianPeers[0] {
			missingPin[peer] = pin
		}
	}
	if _, err := newFormalCoxBlockwiseSourceContext(plan, missingPin); err == nil {
		t.Fatal("incomplete Cox source pinset was accepted")
	}

	lastStep := formalCoxBlockwiseSourceTestStep(
		t, plan, formalCoxBlockwiseStepBlock, plan.TotalBlocks-1)
	padding, _ := formalCoxBlockwiseSourceTestShares(plan, lastStep, 0, 0)
	rows := formalCoxBlockwiseSourceRowsInBlock(plan, lastStep.BlockIndex)
	padding[rows*plan.RowWidth].SetInt64(1)
	if _, err := formalCoxBlockwiseSealSourceInput(
		session, plan.Policy.CustodianPeers[0], recipient, lastStep,
		padding, nil,
		signing[plan.Policy.CustodianPeers[0]]); err == nil {
		t.Fatal("non-zero padded source coordinate was accepted")
	}
}

func TestFormalCoxBlockwiseSourceRestartMissingAndTruncatedSlots(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 2)
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	recipient := plan.Policy.ComputePeers[0]
	dir := filepath.Join(t.TempDir(), "store")
	store := formalCoxBlockwiseSourceTestStore(
		t, dir, session, recipient, transportSK[recipient])
	step := formalCoxBlockwiseSourceTestStep(
		t, plan, formalCoxBlockwiseStepBlock, 0)
	envelopes := make([][]byte, len(plan.Policy.CustodianPeers))
	bindings := make([][]byte, len(plan.Policy.CustodianPeers))
	for sourceIndex, source := range plan.Policy.CustodianPeers {
		values, _ := formalCoxBlockwiseSourceTestShares(plan, step, sourceIndex, 0)
		envelopes[sourceIndex], bindings[sourceIndex] =
			formalCoxBlockwiseSourceTestSealLocalBlockPair(
				t, session, signing, source, recipient, step, values)
		if _, err := store.Accept(
			envelopes[sourceIndex], bindings[sourceIndex]); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.Load(step)
	if err != nil {
		t.Fatal(err)
	}
	committedTemp := filepath.Join(store.slotDir, ".formal-cox-source-crash-window")
	if err := os.Link(store.slotPath(0), committedTemp); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := formalCoxBlockwiseSourceTestStore(
		t, dir, session, recipient, transportSK[recipient])
	second, err := restarted.Load(step)
	if err != nil || first.RecipientRootSHA256 != second.RecipientRootSHA256 ||
		!bigIntSlicesEqual(first.Shares, second.Shares) {
		t.Fatalf("restart changed source input: %v", err)
	}
	if replayed, err := restarted.Accept(
		envelopes[0], bindings[0]); err != nil || !replayed {
		t.Fatalf("restart replay failed: replay=%v err=%v", replayed, err)
	}
	path := restarted.slotPath(0)
	if _, err := os.Lstat(committedTemp); !os.IsNotExist(err) {
		t.Fatalf("restart did not repair committed temp link: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) {
		mode := os.FileMode(0)
		if info != nil {
			mode = info.Mode()
		}
		t.Fatalf("durable source slot is not owner-only: mode=%v err=%v", mode, err)
	}
	alias := path + ".hardlink"
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Load(step); err == nil {
		t.Fatal("hard-linked durable source slot was accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	backup := path + ".backup"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, path); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Load(step); err == nil {
		t.Fatal("symlinked durable source slot was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Load(step); err == nil {
		t.Fatal("truncated durable source slot was accepted")
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}

	missingDir := filepath.Join(t.TempDir(), "missing")
	missing := formalCoxBlockwiseSourceTestStore(
		t, missingDir, session, recipient, transportSK[recipient])
	for sourceIndex, envelope := range envelopes {
		if _, err := missing.Accept(envelope, bindings[sourceIndex]); err != nil {
			t.Fatalf("missing fixture source %d: %v", sourceIndex, err)
		}
	}
	if err := os.Remove(missing.slotPath(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := missing.Load(step); err == nil {
		t.Fatal("missing durable source slot was accepted")
	}
	_ = missing.Close()
}

func TestFormalCoxBlockwiseSourcePrivatePathsAreNoFollow(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sentinel, 0o644); err != nil {
		t.Fatal(err)
	}
	wantInfo, err := os.Stat(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(root, "owner.lock")
	if err := os.Symlink(sentinel, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := formalCoxBlockwiseSourceAcquireOwner(lock); err == nil {
		t.Fatal("a symlink source-owner lock was followed")
	}
	afterInfo, err := os.Stat(sentinel)
	if err != nil || afterInfo.Mode().Perm() != wantInfo.Mode().Perm() {
		t.Fatalf("rejecting a lock symlink changed its target: %v", err)
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil || string(contents) != "sentinel" {
		t.Fatalf("rejecting a lock symlink changed its contents: %v", err)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(sentinel, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := formalCoxBlockwiseSourceAcquireOwner(lock); err == nil {
		t.Fatal("a hard-linked source-owner lock was accepted")
	}
	afterInfo, err = os.Stat(sentinel)
	if err != nil || afterInfo.Mode().Perm() != wantInfo.Mode().Perm() {
		t.Fatalf("rejecting a lock hardlink changed its target: %v", err)
	}

	actual := filepath.Join(root, "actual-source-root")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "source-root-alias")
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(alias); err == nil {
		t.Fatal("a symlink source root was accepted")
	}
	tooOpen := filepath.Join(root, "too-open-source-root")
	if err := os.Mkdir(tooOpen, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tooOpen, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(tooOpen); err == nil {
		t.Fatal("an open source root was silently repaired")
	}
	info, err := os.Stat(tooOpen)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("rejecting an open source root changed its mode: %v", err)
	}
}

func TestFormalCoxBlockwiseSourceConcurrentReplayAndFsyncRecovery(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	recipient := plan.Policy.ComputePeers[0]
	step := formalCoxBlockwiseSourceTestStep(
		t, plan, formalCoxBlockwiseStepBlock, 0)
	values, _ := formalCoxBlockwiseSourceTestShares(plan, step, 0, 0)
	envelope, binding := formalCoxBlockwiseSourceTestSealLocalBlockPair(
		t, session, signing, plan.Policy.CustodianPeers[0], recipient,
		step, values)

	concurrent := formalCoxBlockwiseSourceTestStore(
		t, filepath.Join(t.TempDir(), "concurrent"), session,
		recipient, transportSK[recipient])
	type acceptResult struct {
		replayed bool
		err      error
	}
	results := make(chan acceptResult, 8)
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			replayed, err := concurrent.Accept(envelope, binding)
			results <- acceptResult{replayed: replayed, err: err}
		}()
	}
	wait.Wait()
	close(results)
	fresh, replayed := 0, 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.replayed {
			replayed++
		} else {
			fresh++
		}
	}
	if fresh != 1 || replayed != 7 {
		t.Fatalf("concurrent replay split was fresh=%d replay=%d", fresh, replayed)
	}
	if err := concurrent.Close(); err != nil {
		t.Fatal(err)
	}

	faultDir := filepath.Join(t.TempDir(), "fsync-retry")
	fault := formalCoxBlockwiseSourceTestStore(
		t, faultDir, session, recipient, transportSK[recipient])
	syncCalls := 0
	fault.syncSlotDir = func(dir string) error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected slot-directory fsync failure")
		}
		return exactGCSyncDir(dir)
	}
	if _, err := fault.Accept(envelope, binding); err == nil {
		t.Fatal("an injected slot-directory fsync failure was ignored")
	}
	if replay, err := fault.Accept(envelope, binding); err != nil || !replay {
		t.Fatalf("existing slot was not re-synced before cursor advance: %v", err)
	}
	if syncCalls < 2 {
		t.Fatal("the existing source-slot branch skipped directory fsync")
	}
	if err := fault.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := formalCoxBlockwiseSourceTestStore(
		t, faultDir, session, recipient, transportSK[recipient])
	if replay, err := restarted.Accept(envelope, binding); err != nil || !replay {
		t.Fatalf("fsync-recovered source replay failed: %v", err)
	}
	_ = restarted.Close()

	aheadDir := filepath.Join(t.TempDir(), "slot-ahead-of-cursor")
	ahead := formalCoxBlockwiseSourceTestStore(
		t, aheadDir, session, recipient, transportSK[recipient])
	boundSlot, err := formalCoxBlockwiseSourceEncodeBoundSlot(envelope, binding)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := ahead.persistSlot(0, boundSlot); err != nil || replay {
		t.Fatalf("stage recoverable source slot: replay=%v err=%v", replay, err)
	}
	if err := ahead.Close(); err != nil {
		t.Fatal(err)
	}
	ahead = formalCoxBlockwiseSourceTestStore(
		t, aheadDir, session, recipient, transportSK[recipient])
	state, err := ahead.readState()
	if err != nil || state.NextSlot != 1 {
		t.Fatalf("restart did not advance over a durable source slot: %+v %v",
			state, err)
	}
	_ = ahead.Close()
}

func TestFormalCoxBlockwiseSourceCursorAuthenticationFailsClosed(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 2)
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	recipient := plan.Policy.ComputePeers[0]
	dir := filepath.Join(t.TempDir(), "cursor-tamper")
	store := formalCoxBlockwiseSourceTestStore(
		t, dir, session, recipient, transportSK[recipient])
	statePath := store.statePath
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	wrongKey := sha256.Sum256([]byte("formal-cox/source/wrong-cursor-key"))
	if reopened, err := newFormalCoxBlockwiseSourceStore(
		dir, wrongKey, session, recipient, transportSK[recipient]); err == nil {
		_ = reopened.Close()
		t.Fatal("a source cursor authenticated under the wrong local key")
	}
	encoded, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state formalCoxBlockwiseSourceState
	if err := json.Unmarshal(encoded, &state); err != nil {
		t.Fatal(err)
	}
	state.ManifestSHA256 = strings.Repeat("0", 64)
	encoded, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := exactGCAtomicReplace(statePath, encoded); err != nil {
		t.Fatalf("stage cursor tamper: %v", err)
	}
	key := sha256.Sum256([]byte("formal-cox-source-store/" + recipient))
	if reopened, err := newFormalCoxBlockwiseSourceStore(
		dir, key, session, recipient, transportSK[recipient]); err == nil {
		_ = reopened.Close()
		t.Fatal("a tampered source cursor was accepted")
	}
}

func TestFormalCoxBlockwiseSourceOwnerLockIsMultiprocess(t *testing.T) {
	if helper := os.Getenv("DSVERT_COX_SOURCE_LOCK_HELPER"); helper != "" {
		owner, err := formalCoxBlockwiseSourceAcquireOwner(
			filepath.Join(helper, "owner.lock"))
		if err == nil {
			_ = owner.Close()
			t.Fatal("second process acquired the source spool")
		}
		if !strings.Contains(err.Error(), "already has an owner") {
			t.Fatalf("unexpected multiprocess lock error: %v", err)
		}
		return
	}
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(
		t, plan, pins, signing)
	recipient := plan.Policy.ComputePeers[0]
	dir := filepath.Join(t.TempDir(), "store")
	store := formalCoxBlockwiseSourceTestStore(
		t, dir, session, recipient, transportSK[recipient])
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable,
		"-test.run=^TestFormalCoxBlockwiseSourceOwnerLockIsMultiprocess$")
	command.Env = append(os.Environ(), "DSVERT_COX_SOURCE_LOCK_HELPER="+dir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("multiprocess lock helper: %v\n%s", err, output)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := formalCoxBlockwiseSourceTestStore(
		t, dir, session, recipient, transportSK[recipient])
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
