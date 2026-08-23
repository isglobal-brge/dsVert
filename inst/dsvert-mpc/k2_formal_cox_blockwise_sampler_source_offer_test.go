package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type formalCoxBlockwiseSamplerSourceOfferTestFixture struct {
	runtime formalCoxRuntimeTestFixture
	plan    formalCoxBlockwisePlan
	dpPlan  formalCoxDPPlan
	session *formalCoxBlockwiseSourceSession
	secret  map[string][]byte
}

func newFormalCoxBlockwiseSamplerSourceOfferTestFixture(t testing.TB,
	custodians int,
) formalCoxBlockwiseSamplerSourceOfferTestFixture {
	t.Helper()
	runtime := formalCoxRuntimeTestFixtureForK(t, custodians, t.Name())
	policy := runtime.policy
	// The streamed worker has a positive public ridge. Rebuild the reusable
	// sampler admission against that exact signed policy.
	policy.Ridge = "16"
	initial, err := planFormalCoxDP(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.NoiseBound = initial.MaximumNoiseMagnitude
	policy.NoiseChunkCount = initial.SamplerChunkCount
	admission, err := buildFormalCoxRuntimeAdmission(
		policy, runtime.pins, runtime.request)
	if err != nil {
		t.Fatal(err)
	}
	runtime.policy, runtime.admission = policy, admission
	formalCoxRuntimeTestSignEnvelopes(t, &runtime)
	dpPlan, err := planFormalCoxBlockwiseDP(policy)
	if err != nil {
		t.Fatal(err)
	}
	runID := sha256.Sum256([]byte(t.Name() + "/blockwise-plan"))
	plan, err := buildFormalCoxBlockwisePlan(
		policy, 1, hex.EncodeToString(runID[:]))
	if err != nil {
		t.Fatal(err)
	}
	session, _, secret := formalCoxBlockwiseSourceTestSession(
		t, plan, runtime.pins, runtime.private)
	return formalCoxBlockwiseSamplerSourceOfferTestFixture{
		runtime: runtime, plan: plan, dpPlan: dpPlan,
		session: session, secret: secret,
	}
}

func formalCoxBlockwiseSamplerSourceOfferTestExpected(
	t testing.TB, sampler formalCoxRuntimeSamplerRoleChunk, role, center string,
) ([]*big.Int, bool) {
	t.Helper()
	value, ok := new(big.Int).SetString(center, 10)
	if !ok {
		t.Fatal("invalid test sampler center")
	}
	want := make([]*big.Int, len(sampler.RawOutputShares)-1)
	mask := exactGCMask(128)
	for index := range want {
		want[index] = new(big.Int).Set(sampler.RawOutputShares[index])
		if role == "garbler" {
			want[index].Sub(want[index], value)
			want[index].And(want[index], mask)
		}
	}
	return want, sampler.ValidityShare
}

// formalCoxBlockwiseSamplerSourceOfferTestPreflight builds the existing
// guarded-noise binding with the same identities as the generic sampler. The
// generic sticky-guard fixture deliberately creates independent test keys, so
// it cannot be mixed with this source session.
func formalCoxBlockwiseSamplerSourceOfferTestPreflight(t testing.TB,
	fixture formalCoxBlockwiseSamplerSourceOfferTestFixture,
) (formalCoxBlockwiseSamplerContract, []formalCoxBlockwiseSamplerAuthorization) {
	t.Helper()
	artifact := fixture.session.context.artifact
	roots := make(map[string][32]byte, 2)
	storageRoots := make(map[string][32]byte, 2)
	commitments := make([]formalCoxBlockwiseSamplerCommitment, 2)
	for index, authority := range artifact.NoiseAuthorities {
		roots[authority.PeerName] = sha256.Sum256([]byte(
			t.Name() + "/authority/" + authority.PeerName))
		storageRoots[authority.PeerName] = sha256.Sum256([]byte(
			t.Name() + "/storage/" + authority.PeerName))
		seed, commitment, err := formalCoxBlockwiseDeriveSamplerSeed(
			roots[authority.PeerName], artifact, fixture.session.context.artifactID,
			authority.Role)
		clear(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		commitments[index] = commitment
	}
	contract, err := formalCoxBlockwiseBuildSamplerContract(
		artifact, fixture.session.context.artifactID, commitments, fixture.runtime.pins)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]jointDPBiomedicalGaussianSignature,
		len(artifact.CustodianPeers))
	for index, peer := range artifact.CustodianPeers {
		signatures[index], err = formalCoxBlockwiseSignSamplerContract(
			contract, peer, fixture.runtime.private[peer], fixture.runtime.pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	contract, err = formalCoxBlockwiseSealSamplerContract(
		contract, signatures, fixture.runtime.pins)
	if err != nil {
		t.Fatal(err)
	}
	authorizations := make([]formalCoxBlockwiseSamplerAuthorization, 2)
	for index, authority := range artifact.NoiseAuthorities {
		store, err := newFormalCoxBlockwiseSamplerGuardStore(
			t.TempDir()+"/"+authority.Role, authority.PeerName,
			storageRoots[authority.PeerName], fixture.runtime.pins)
		if err != nil {
			t.Fatal(err)
		}
		predecessors := []formalCoxBlockwiseSamplerAuthorization(nil)
		if index == 1 {
			predecessors = authorizations[:1]
		}
		authorizations[index], _, err = store.AuthorizeOnce(
			contract, roots[authority.PeerName], fixture.runtime.private[authority.PeerName],
			predecessors)
		closeErr := store.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("formal Cox sampler source preflight: %v / close=%v", err, closeErr)
		}
	}
	return contract, authorizations
}

func formalCoxBlockwiseSamplerSourceOfferTestStageBlocks(t testing.TB,
	fixture formalCoxBlockwiseSamplerSourceOfferTestFixture,
	stores map[string]*formalCoxBlockwiseSourceStore,
) {
	t.Helper()
	for block := 0; block < fixture.plan.TotalBlocks; block++ {
		step := formalCoxBlockwiseSourceTestStep(
			t, fixture.plan, formalCoxBlockwiseStepBlock, block)
		for sourceIndex, source := range fixture.plan.Policy.CustodianPeers {
			values := make(map[string][]*big.Int, 2)
			for recipientIndex, recipient := range fixture.plan.Policy.ComputePeers {
				values[recipient], _ = formalCoxBlockwiseSourceTestShares(
					fixture.plan, step, sourceIndex, recipientIndex)
			}
			envelopes, binding := formalCoxBlockwiseSourceTestSealBlockPair(
				t, fixture.session, fixture.runtime.private, source, step, values)
			for _, recipient := range fixture.plan.Policy.ComputePeers {
				replayed, err := stores[recipient].Accept(envelopes[recipient], binding)
				if err != nil || replayed {
					t.Fatalf("stage block %d from %s to %s: replay=%v err=%v",
						block, source, recipient, replayed, err)
				}
			}
			exactGCZeroBigInts(values[fixture.plan.Policy.ComputePeers[0]])
			exactGCZeroBigInts(values[fixture.plan.Policy.ComputePeers[1]])
		}
	}
}

// formalCoxBlockwiseSamplerSourceOfferTestBridgeFixture connects every Cox
// update to the actual one-draw sampler outputs.  The older source-bridge
// fixture uses synthetic sealed noise to test transport geometry; this helper
// is deliberately separate so that an end-to-end worker run cannot mistake
// those synthetic lanes for a privacy mechanism.
func formalCoxBlockwiseSamplerSourceOfferTestBridgeFixture(t testing.TB,
	fixture formalCoxBlockwiseSamplerSourceOfferTestFixture,
) *formalCoxBlockwiseSourceBridgeTestFixture {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{filepath.Join(root, "source"), filepath.Join(root, "worker")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	result := &formalCoxBlockwiseSourceBridgeTestFixture{
		plan:        fixture.plan,
		pins:        fixture.runtime.pins,
		signing:     fixture.runtime.private,
		session:     fixture.session,
		transportSK: fixture.secret,
		sourceDir:   make(map[string]string, 2),
		workerDir:   make(map[string]string, 2),
		sourceKey:   make(map[string][32]byte, 2),
		workerKey:   make(map[string][32]byte, 2),
	}
	stores := make(map[string]*formalCoxBlockwiseSourceStore, 2)
	for _, peer := range fixture.plan.Policy.ComputePeers {
		result.sourceDir[peer] = filepath.Join(root, "source", peer)
		result.workerDir[peer] = filepath.Join(root, "worker", peer)
		result.sourceKey[peer] = sha256.Sum256([]byte(t.Name() + "/source/" + peer))
		result.workerKey[peer] = sha256.Sum256([]byte(t.Name() + "/worker/" + peer))
		store, err := newFormalCoxBlockwiseSourceStore(
			result.sourceDir[peer], result.sourceKey[peer], fixture.session, peer,
			fixture.secret[peer])
		if err != nil {
			t.Fatal(err)
		}
		stores[peer] = store
	}
	defer func() {
		for _, store := range stores {
			_ = store.Close()
		}
	}()

	formalCoxBlockwiseSamplerSourceOfferTestStageBlocks(t, fixture, stores)
	garbler, evaluator := formalCoxRuntimeTestSamplerPair(t, fixture.runtime)
	defer func() {
		for _, chunks := range [][]formalCoxRuntimeSamplerRoleChunk{garbler, evaluator} {
			for index := range chunks {
				exactGCZeroBigInts(chunks[index].RawOutputShares)
				exactGCZeroBigInts(chunks[index].NoiseShares)
			}
		}
	}()
	contract, authorizations := formalCoxBlockwiseSamplerSourceOfferTestPreflight(t, fixture)
	layout, err := formalCoxBlockwiseSamplerLayout(
		fixture.dpPlan.NoiseCoordinates, fixture.dpPlan.CovariateCount,
		fixture.dpPlan.CommonPlan.MaximumChunkCoordinates)
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < fixture.plan.Policy.Iterations; iteration++ {
		step, chunkIndex, _, err := formalCoxBlockwiseSamplerSourceOfferChunk(
			fixture.plan, layout, iteration)
		if err != nil {
			t.Fatal(err)
		}
		offers := make([]formalCoxBlockwiseSamplerSourceOffer, 2)
		for index, peer := range fixture.plan.Policy.ComputePeers {
			sampler := garbler[chunkIndex]
			if index == 1 {
				sampler = evaluator[chunkIndex]
			}
			offers[index], err = formalCoxBlockwiseBuildSamplerSourceOffer(
				fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
				fixture.runtime.admission.NoiseCenter, peer, iteration,
				fixture.runtime.admission.Envelopes[chunkIndex], sampler,
				fixture.runtime.private[peer])
			if err != nil {
				t.Fatalf("iteration %d build %s sampler offer: %v", iteration, peer, err)
			}
		}
		barrier, err := formalCoxBlockwiseNewGuardedSamplerSourceOfferBarrier(
			fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
			step, offers, contract, authorizations)
		if err != nil {
			t.Fatalf("iteration %d sampler barrier: %v", iteration, err)
		}
		approvals := make([]formalCoxBlockwiseNoiseApproval, 2)
		for index, peer := range fixture.plan.Policy.ComputePeers {
			approvals[index], err = formalCoxBlockwiseSignGuardedSamplerSourceOfferBarrier(
				fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
				barrier, offers, contract, authorizations, peer,
				fixture.runtime.private[peer])
			if err != nil {
				t.Fatalf("iteration %d sign %s sampler barrier: %v", iteration, peer, err)
			}
		}
		binding, err := formalCoxBlockwiseFinalizeGuardedSamplerSourceOfferBarrier(
			fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
			offers, contract, authorizations, barrier, approvals)
		if err != nil {
			t.Fatalf("iteration %d finalize sampler barrier: %v", iteration, err)
		}
		for _, peer := range fixture.plan.Policy.ComputePeers {
			if replayed, acceptErr := stores[peer].AcceptGuardedSamplerSourceOffers(
				fixture.dpPlan, fixture.runtime.admission.Trust, offers, binding); acceptErr != nil || replayed {
				t.Fatalf("iteration %d accept %s sampler offer: replay=%v err=%v",
					iteration, peer, replayed, acceptErr)
			}
		}
	}
	return result
}

func formalCoxBlockwiseSamplerSourceOfferTestRejectBarrierCommitmentSwap(
	t testing.TB, session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	offers []formalCoxBlockwiseSamplerSourceOffer, binding []byte,
	private map[string]ed25519.PrivateKey,
) {
	t.Helper()
	var guarded formalCoxBlockwiseGuardedNoiseBarrier
	if err := formalCoxBlockwiseSourceDecodeCanonical(binding,
		formalCoxBlockwiseSourceBindingMax, "test guarded sampler offer", &guarded); err != nil {
		t.Fatal(err)
	}
	guarded.Barrier.SamplerOfferCommitments[0].SamplerOfferSHA256 =
		strings.Repeat("0", 64)
	root, err := formalCoxBlockwiseSamplerSourceOfferCommitmentRoot(
		guarded.Barrier.SamplerOfferCommitments)
	if err != nil {
		t.Fatal(err)
	}
	guarded.Barrier.SamplerOfferRootSHA256 = root
	guarded.Barrier.PairedNoiseRootSHA256, err =
		formalCoxBlockwiseNoiseBarrierRoot(guarded.Barrier)
	if err != nil {
		t.Fatal(err)
	}
	message, err := formalCoxBlockwiseNoiseBarrierMessage(guarded.Barrier)
	if err != nil {
		t.Fatal(err)
	}
	for index, peer := range session.context.plan.Policy.ComputePeers {
		guarded.Barrier.Approvals[index] = formalCoxBlockwiseNoiseApproval{
			SignerPeerName: peer, SignerPeerID: session.context.peerIDs[peer],
			SignerRole: session.context.roles[peer],
			Signature:  ed25519.Sign(private[peer], message),
		}
	}
	encoded, err := json.Marshal(guarded)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalCoxBlockwiseValidateGuardedSamplerSourceOfferBinding(
		session, dpPlan, trust, offers, encoded); err == nil {
		t.Fatal("barrier accepted a substituted sampler offer commitment")
	}
}

func TestFormalCoxBlockwiseSamplerSourceOfferK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+big.NewInt(int64(custodians)).String(), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseSamplerSourceOfferTestFixture(
				t, custodians)
			stores := make(map[string]*formalCoxBlockwiseSourceStore, 2)
			for _, peer := range fixture.plan.Policy.ComputePeers {
				stores[peer] = formalCoxBlockwiseSourceTestStore(
					t, t.TempDir()+"/"+peer, fixture.session, peer,
					fixture.secret[peer])
				defer stores[peer].Close()
			}
			formalCoxBlockwiseSamplerSourceOfferTestStageBlocks(t, fixture, stores)
			garbler, evaluator := formalCoxRuntimeTestSamplerPair(t, fixture.runtime)
			offers := make(map[string]formalCoxBlockwiseSamplerSourceOffer, 2)
			for index, peer := range fixture.plan.Policy.ComputePeers {
				sampler := garbler[0]
				if index == 1 {
					sampler = evaluator[0]
				}
				offer, err := formalCoxBlockwiseBuildSamplerSourceOffer(
					fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
					fixture.runtime.admission.NoiseCenter, peer, 0,
					fixture.runtime.admission.Envelopes[0], sampler,
					fixture.runtime.private[peer])
				if err != nil {
					t.Fatalf("build %s offer: %v", peer, err)
				}
				if err := formalCoxBlockwiseValidateSamplerSourceOffer(
					fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
					offer); err != nil {
					t.Fatalf("validate %s offer: %v", peer, err)
				}
				encoded, err := json.Marshal(offer)
				if err != nil || strings.Contains(string(encoded), "raw_output") ||
					strings.Contains(string(encoded), "noise_shares") ||
					strings.Contains(string(encoded), "private_seed") ||
					strings.Contains(string(encoded), "worker_policy") {
					t.Fatalf("offer for %s exposed a private sampler field: %v", peer, err)
				}
				offers[peer] = offer
			}
			ordered := make([]formalCoxBlockwiseSamplerSourceOffer, 2)
			for index, peer := range fixture.plan.Policy.ComputePeers {
				ordered[index] = offers[peer]
			}
			contract, authorizations := formalCoxBlockwiseSamplerSourceOfferTestPreflight(
				t, fixture)
			step := formalCoxBlockwiseSourceTestStep(
				t, fixture.plan, formalCoxBlockwiseStepUpdate, 0)
			barrier, err := formalCoxBlockwiseNewGuardedSamplerSourceOfferBarrier(
				fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
				step, ordered, contract, authorizations)
			if err != nil {
				t.Fatal(err)
			}
			approvals := make([]formalCoxBlockwiseNoiseApproval, 2)
			for index, peer := range fixture.plan.Policy.ComputePeers {
				approvals[index], err = formalCoxBlockwiseSignGuardedSamplerSourceOfferBarrier(
					fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
					barrier, ordered, contract, authorizations, peer,
					fixture.runtime.private[peer])
				if err != nil {
					t.Fatal(err)
				}
			}
			binding, err := formalCoxBlockwiseFinalizeGuardedSamplerSourceOfferBarrier(
				fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
				ordered, contract, authorizations, barrier, approvals)
			if err != nil {
				t.Fatal(err)
			}
			if err := formalCoxBlockwiseValidateGuardedSamplerSourceOfferBinding(
				fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
				ordered, binding); err != nil {
				t.Fatal(err)
			}
			if custodians == 2 {
				formalCoxBlockwiseSamplerSourceOfferTestRejectBarrierCommitmentSwap(
					t, fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
					ordered, binding, fixture.runtime.private)
			}
			for index, peer := range fixture.plan.Policy.ComputePeers {
				state, err := stores[peer].readState()
				if err != nil {
					t.Fatal(err)
				}
				invalid := append([]formalCoxBlockwiseSamplerSourceOffer(nil), ordered...)
				invalid[0].Signature = append([]byte(nil), invalid[0].Signature...)
				invalid[0].Signature[0] ^= 1
				if _, err := stores[peer].AcceptGuardedSamplerSourceOffers(
					fixture.dpPlan, fixture.runtime.admission.Trust, invalid, binding); err == nil {
					t.Fatal("tampered sampler offer reached the source store")
				}
				unchanged, err := stores[peer].readState()
				if err != nil || unchanged.NextSlot != state.NextSlot {
					t.Fatalf("tampered sampler offer mutated %s source state: %+v / %v",
						peer, unchanged, err)
				}
				replayed, err := stores[peer].AcceptGuardedSamplerSourceOffers(
					fixture.dpPlan, fixture.runtime.admission.Trust, ordered, binding)
				if err != nil || replayed {
					t.Fatalf("accept %s sampler offer: replay=%v err=%v", peer, replayed, err)
				}
				replayed, err = stores[peer].AcceptGuardedSamplerSourceOffers(
					fixture.dpPlan, fixture.runtime.admission.Trust, ordered, binding)
				if err != nil || !replayed {
					t.Fatalf("replay %s sampler offer: replay=%v err=%v", peer, replayed, err)
				}
				current, err := stores[peer].readState()
				if err != nil || current.NextSlot != state.NextSlot+1 {
					t.Fatalf("sampler offer did not advance %s source state: %+v / %v",
						peer, current, err)
				}
				input, err := stores[peer].Load(step)
				shares, validity := input.Shares, input.ValidityShare
				if err != nil {
					exactGCZeroBigInts(shares)
					t.Fatalf("load %s sampler source: %v", peer, err)
				}
				sampler := garbler[0]
				if index == 1 {
					sampler = evaluator[0]
				}
				role, roleErr := formalCoxBlockwiseSourceRole(fixture.plan, peer)
				if roleErr != nil {
					t.Fatal(roleErr)
				}
				want, valid := formalCoxBlockwiseSamplerSourceOfferTestExpected(
					t, sampler, role, fixture.runtime.admission.NoiseCenter)
				if validity == nil || *validity != valid || !bigIntSlicesEqual(shares, want) {
					exactGCZeroBigInts(shares)
					exactGCZeroBigInts(want)
					t.Fatalf("loaded %s sampler input differs from its authenticated output", peer)
				}
				exactGCZeroBigInts(shares)
				exactGCZeroBigInts(want)
			}
		})
	}
}

// TestFormalCoxBlockwiseSamplerOffersDriveFullWorkerK2K3K5 proves the
// private compute chain that a future public Cox route must inherit: every
// update is produced by the certified fixed-work sampler, accepted through a
// two-authority guarded barrier, consumed by the recipient-local source
// store, and then used by the whole durable worker schedule.  It intentionally
// stops before opening or promoting the resulting coefficients.
func TestFormalCoxBlockwiseSamplerOffersDriveFullWorkerK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+big.NewInt(int64(custodians)).String(), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseSamplerSourceOfferTestFixture(t, custodians)
			bridgeFixture := formalCoxBlockwiseSamplerSourceOfferTestBridgeFixture(t, fixture)
			sealed := formalCoxBlockwiseSourceBridgeTestRunFullScheduleSealed(t, bridgeFixture)
			for index := range sealed {
				if len(sealed[index].CoefficientShares) != fixture.plan.Policy.CovariateCount {
					t.Fatalf("K=%d peer=%d sealed coefficient shape escaped plan", custodians, index)
				}
				exactGCZeroBigInts(sealed[index].CoefficientShares)
			}
		})
	}
}

func TestFormalCoxBlockwiseSamplerSourceOfferRejectsTamper(t *testing.T) {
	fixture := newFormalCoxBlockwiseSamplerSourceOfferTestFixture(t, 2)
	garbler, _ := formalCoxRuntimeTestSamplerPair(t, fixture.runtime)
	peer := fixture.plan.Policy.ComputePeers[0]
	offer, err := formalCoxBlockwiseBuildSamplerSourceOffer(
		fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
		fixture.runtime.admission.NoiseCenter, peer, 0,
		fixture.runtime.admission.Envelopes[0], garbler[0],
		fixture.runtime.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	badShare := garbler[0]
	badShare.RawOutputShares = make([]*big.Int, len(garbler[0].RawOutputShares))
	for index, value := range garbler[0].RawOutputShares {
		badShare.RawOutputShares[index] = new(big.Int).Set(value)
	}
	badShare.RawOutputShares[0].Xor(badShare.RawOutputShares[0], big.NewInt(1))
	if _, err := formalCoxBlockwiseBuildSamplerSourceOffer(
		fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
		fixture.runtime.admission.NoiseCenter, peer, 0,
		fixture.runtime.admission.Envelopes[0], badShare,
		fixture.runtime.private[peer]); err == nil {
		t.Fatal("tampered private sampler output was accepted")
	}
	exactGCZeroBigInts(badShare.RawOutputShares)
	for _, mutate := range []func(*formalCoxBlockwiseSamplerSourceOffer){
		func(value *formalCoxBlockwiseSamplerSourceOffer) {
			value.Signature = append([]byte(nil), value.Signature...)
			value.Signature[0] ^= 1
		},
		func(value *formalCoxBlockwiseSamplerSourceOffer) {
			value.SourceEnvelope = append([]byte(nil), value.SourceEnvelope...)
			value.SourceEnvelope[len(value.SourceEnvelope)/2] ^= 1
		},
		func(value *formalCoxBlockwiseSamplerSourceOffer) {
			value.SamplerReceipt.Signature = append(
				[]byte(nil), value.SamplerReceipt.Signature...)
			value.SamplerReceipt.Signature[0] ^= 1
		},
	} {
		candidate := offer
		mutate(&candidate)
		if err := formalCoxBlockwiseValidateSamplerSourceOffer(
			fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
			candidate); err == nil {
			t.Fatal("tampered sampler source offer was accepted")
		}
	}
	// Re-signing the outer offer cannot replace the K-signed generic sampler
	// provenance. The recipient's own key is deliberately insufficient here.
	for _, mutate := range []func(*formalCoxBlockwiseSamplerSourceOffer){
		func(value *formalCoxBlockwiseSamplerSourceOffer) {
			value.SamplerEnvelope.Preimage.WorkerContractSHA256 =
				strings.Repeat("0", 64)
		},
		func(value *formalCoxBlockwiseSamplerSourceOffer) {
			value.SamplerEnvelope.Signatures = append(
				[]jointDPBiomedicalGaussianSignature(nil),
				value.SamplerEnvelope.Signatures...)
			value.SamplerEnvelope.Signatures[0].Signature = append([]byte(nil),
				value.SamplerEnvelope.Signatures[0].Signature...)
			value.SamplerEnvelope.Signatures[0].Signature[0] ^= 1
		},
	} {
		candidate := offer
		mutate(&candidate)
		message, messageErr := formalCoxBlockwiseSamplerSourceOfferMessage(candidate)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		candidate.Signature = ed25519.Sign(fixture.runtime.private[peer], message)
		if err := formalCoxBlockwiseValidateSamplerSourceOffer(
			fixture.session, fixture.dpPlan, fixture.runtime.admission.Trust,
			candidate); err == nil {
			t.Fatal("outer re-signing replaced signed sampler provenance")
		}
	}
	if bytes.Contains(offer.SourceEnvelope, []byte("private_seed")) {
		t.Fatal("ciphertext exposed a private sampler field")
	}
}
