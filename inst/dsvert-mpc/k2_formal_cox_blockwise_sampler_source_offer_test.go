package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
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
				store := formalCoxBlockwiseSourceTestStore(
					t, t.TempDir()+"/"+peer, fixture.session, peer,
					fixture.secret[peer])
				bound, err := formalCoxBlockwiseSourceEncodeBoundSlot(
					offers[peer].SourceEnvelope, binding)
				if err != nil {
					_ = store.Close()
					t.Fatalf("bind %s offer: %v", peer, err)
				}
				_, _, _, shares, validity, err := store.validateBoundSlot(bound)
				closeErr := store.Close()
				if err != nil || closeErr != nil {
					exactGCZeroBigInts(shares)
					t.Fatalf("open %s offer: %v / close=%v", peer, err, closeErr)
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
