package main

import (
	"crypto/sha256"
	"encoding/hex"
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

type formalGLMPhase21FullTestFixture struct {
	full              formalGLMPhase16FullFallbackTestFixture
	stores            map[string]*formalGLMPhase20HandoffStore
	capsule           formalGLMPhase16CapsuleBinding
	productiveRequest formalGLMPhase16ProductiveRequest
	backendSignatures []jointDPBiomedicalGaussianSignature
}

func formalGLMPhase21FullTestSetup(t testing.TB, custodians int,
	family string,
) formalGLMPhase21FullTestFixture {
	t.Helper()
	formal, runtime := formalGLMPhase16TestDurableRuntime(
		t, custodians, family)
	return formalGLMPhase21FullTestSetupFromRuntime(
		t, formal, runtime, family)
}

func formalGLMPhase21FullTestSetupFromRuntime(t testing.TB,
	formal formalGLMPhase18FinalizerFixture,
	runtime map[string]formalGLMPhase19RuntimeScheduleResult,
	family string,
) formalGLMPhase21FullTestFixture {
	t.Helper()
	legacy, _, _, err := formalGLMPhase16TestProductiveAdmission(
		t, formal, runtime)
	if err != nil {
		t.Fatal(err)
	}

	// Pick the least restrictive test epsilon that exceeds the reviewed
	// one-draw resource envelope while the independently sampled backend still
	// has a Ring128 no-wrap certificate. This exercises both GLM families
	// without encoding planner thresholds in the integration boundary.
	var binding formalGLMPhase16ReleaseBinding
	var selectionContract formalGLMPhase16BackendSelectionContract
	for _, epsilon := range []string{"1", "0.1", "0.01", "0.001", "0.0001"} {
		candidate := legacy.Compiled.Binding
		candidate.Epsilon = epsilon
		candidate.BindingSHA256, err =
			formalGLMPhase16ReleaseBindingDigest(candidate)
		if err != nil {
			t.Fatal(err)
		}
		contract, _, buildErr := formalGLMPhase16BuildBackendSelection(
			candidate, legacy.Token, formal.identities.public)
		if buildErr == nil && contract.SelectedBackend ==
			formalGLMPhase16BackendFull {
			binding, selectionContract = candidate, contract
			break
		}
	}
	if selectionContract.SelectedBackend != formalGLMPhase16BackendFull {
		t.Fatalf("%s fixture could not select the signed full fallback", family)
	}
	selection := formalGLMPhase16BackendSelectionAttestation{
		Contract: selectionContract,
		Signatures: formalGLMPhase16TestSignBackendSelection(
			t, selectionContract, formal.identities.private),
	}
	hash := func(label string) string {
		value := sha256.Sum256([]byte(t.Name() + "/" + label))
		return hex.EncodeToString(value[:])
	}
	roots := make(map[string][32]byte, 2)
	epochs := make([]jointDPBiomedicalGaussianNoiseRootEpoch, 0, 2)
	for _, peer := range selectionContract.DesignatedComputePeers {
		root := sha256.Sum256([]byte(t.Name() + "/full-noise-root/" + peer))
		roots[peer] = root
		epoch, epochErr := jointDPBiomedicalGaussianFullNoiseRootEpoch(
			root, peer)
		if epochErr != nil {
			t.Fatal(epochErr)
		}
		epochs = append(epochs, jointDPBiomedicalGaussianNoiseRootEpoch{
			PeerName: peer, EpochSHA256: epoch,
		})
	}
	fullRequest := formalGLMPhase16FullFallbackRequest{
		LogicalReleaseSHA256:        hash("logical-release"),
		PrivacyEpochSHA256:          hash("privacy-epoch"),
		LogicalSnapshotHandleSHA256: hash("logical-snapshot"),
		NoiseRootEpochs:             epochs,
		ReceiptReferences: jointDPBiomedicalGaussianTestReceipts(
			t.Name() + "/formal-full"),
	}
	identity, err := formalGLMPhase16FullFallbackIdentity(
		selection, binding, legacy.Token, formal.identities.public,
		fullRequest)
	if err != nil {
		t.Fatal(err)
	}
	for _, epoch := range epochs {
		seed, context, commitment, seedErr :=
			jointDPBiomedicalGaussianFullSeedMaterial(
				roots[epoch.PeerName], epoch.PeerName, identity)
		if seedErr != nil {
			t.Fatal(seedErr)
		}
		fullRequest.NoiseCommitments = append(
			fullRequest.NoiseCommitments,
			jointDPBiomedicalGaussianFullNoiseCommitment{
				PeerName: epoch.PeerName, ContextSHA256: context,
				SeedSHA256: commitment,
			})
		clear(seed[:])
	}
	fullContract, err := formalGLMPhase16BuildFullFallbackContract(
		selection, binding, legacy.Token, formal.identities.public,
		fullRequest)
	if err != nil {
		t.Fatal(err)
	}
	fullSignatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(fullContract.CustodianPeers))
	for _, peer := range fullContract.CustodianPeers {
		signature, signErr := formalGLMPhase16SignFullFallbackContract(
			fullContract, peer, formal.identities.private[peer])
		if signErr != nil {
			t.Fatal(signErr)
		}
		fullSignatures = append(fullSignatures, signature)
	}
	attestation := formalGLMPhase16FullFallbackContractAttestation{
		Contract: fullContract, Signatures: fullSignatures,
	}
	admission, err := formalGLMPhase16AdmitFullFallback(
		selection, binding, legacy.Token, formal.identities.public,
		fullRequest, attestation)
	if err != nil {
		t.Fatal(err)
	}
	stores := formalGLMPhase20TestPersistStores(t, formal, runtime)
	capsule := formalGLMPhase20CapsuleFromBinding(binding)
	productiveRequest := formalGLMPhase16ProductiveRequest{
		LogicalSnapshotHandleSHA256: fullRequest.LogicalSnapshotHandleSHA256,
		PrivacyEpochSHA256:          fullRequest.PrivacyEpochSHA256,
		RunNonceSHA256:              hash("full-run-nonce"),
		WorkerImplementationSHA256:  hash("worker"),
		ReceiptReferences:           fullRequest.ReceiptReferences,
	}
	reference := formal.ctx.ComputePeers[0]
	draft, err := formalGLMPhase20BuildLocalRuntime(
		stores[reference], formal.identities.public, capsule,
		productiveRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(draft.Admission.Productive.BackendSelection.Contract,
		selectionContract) {
		draft.clear()
		t.Fatal("Phase-2.0 derived a different full backend decision")
	}
	backendSignatures := formalGLMPhase16TestSignBackendSelection(
		t, draft.Admission.Productive.BackendSelection.Contract,
		formal.identities.private)
	draft.clear()
	return formalGLMPhase21FullTestFixture{
		full: formalGLMPhase16FullFallbackTestFixture{
			formal: formal, runtime: runtime, binding: binding,
			token: legacy.Token, selection: selection, request: fullRequest,
			contract: attestation, admission: admission, roots: roots,
			backend: runtime[reference].backend,
		},
		stores: stores, capsule: capsule,
		productiveRequest: productiveRequest,
		backendSignatures: backendSignatures,
	}
}

func (fixture *formalGLMPhase21FullTestFixture) close() {
	for _, store := range fixture.stores {
		store.close()
	}
}

func formalGLMPhase21FullTestRun(t testing.TB,
	fixture formalGLMPhase21FullTestFixture,
) map[string]formalGLMPhase21FullLocalOutput {
	t.Helper()
	peers := fixture.full.formal.ctx.ComputePeers
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(90 * time.Second))
	_ = right.SetDeadline(time.Now().Add(90 * time.Second))
	outputs := make(map[string]formalGLMPhase21FullLocalOutput, 2)
	errorsByPeer := make(map[string]error, 2)
	var lock sync.Mutex
	var wait sync.WaitGroup
	wait.Add(2)
	for index, peer := range peers {
		index, peer := index, peer
		connection := net.Conn(left)
		if index == 1 {
			connection = right
		}
		go func() {
			defer wait.Done()
			value, err := formalGLMPhase21RunFullLocal(
				connection, fixture.stores[peer], fixture.capsule,
				fixture.productiveRequest, fixture.backendSignatures,
				fixture.full.request, fixture.full.contract,
				fixture.full.roots[peer],
				fixture.full.formal.identities.private[peer])
			lock.Lock()
			outputs[peer], errorsByPeer[peer] = value, err
			lock.Unlock()
		}()
	}
	wait.Wait()
	for _, peer := range peers {
		if errorsByPeer[peer] != nil {
			t.Fatalf("Phase-2.1 full peer %s: %v", peer, errorsByPeer[peer])
		}
	}
	return outputs
}

// Build a fully self-consistent lower-layer execution over substituted shares:
// source bindings, exact-GC guard receipts and noised peer shares are all
// recomputed and signed. The lower layer can validate this execution, but the
// Phase21 reload boundary must reject it because no alternate share was ever
// committed to either authoritative Phase20 slot.
func formalGLMPhase21FullTestAlternateOutputs(t testing.TB,
	fixture formalGLMPhase21FullTestFixture,
	templates map[string]formalGLMPhase21FullLocalOutput,
) map[string]formalGLMPhase21FullLocalOutput {
	t.Helper()
	peers := fixture.full.formal.ctx.ComputePeers
	runtimes := make(map[string]formalGLMPhase20LocalRuntime, 2)
	changed := make(map[string][]*big.Int, 2)
	encoded := make(map[string]string, 2)
	sources := make(map[string]jointDPBiomedicalGaussianFullPhase19SourceBinding, 2)
	defer func() {
		for _, peer := range peers {
			runtime := runtimes[peer]
			runtime.clear()
			exactGCZeroBigInts(changed[peer])
		}
	}()
	var session exactGCSession
	for peerIndex, peer := range peers {
		runtime, _, err := formalGLMPhase21LoadAndAdmitFull(
			fixture.stores[peer], fixture.capsule,
			fixture.productiveRequest, fixture.backendSignatures,
			fixture.full.request, fixture.full.contract)
		if err != nil {
			t.Fatal(err)
		}
		runtimes[peer] = runtime
		changed[peer] = make([]*big.Int, len(runtime.Source.DPShares))
		for index := range changed[peer] {
			changed[peer][index] = new(big.Int).Set(
				runtime.Source.DPShares[index])
		}
		changed[peer][0].Add(changed[peer][0],
			big.NewInt(int64(peerIndex+1)))
		changed[peer][0].And(changed[peer][0], exactGCMask(128))
		encoded[peer], err = exactGCEncodeWorkerCanonicalShares(
			changed[peer], exactGCCircuitSpec{
				Operation: jointDPGaussianOneDrawOperation,
				RingBits:  128, FracBits: 0,
				VectorLen: fixture.full.binding.CoordinateCount,
			})
		if err != nil {
			t.Fatal(err)
		}
		admission := templates[peer].Admission
		sources[peer], err = jointDPBiomedicalGaussianBindFullPhase19Source(
			admission, fixture.full.formal.identities.public,
			runtime.Source.Result.PostExecutionToken, runtime.Source.backend,
			peer, 0, fixture.full.binding.CoordinateCount, encoded[peer])
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, candidateSession, err :=
			formalGLMPhase21FullSourceMaterialWithPins(
				runtime, fixture.full.formal.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		if peerIndex == 0 {
			session = candidateSession
		} else if !reflect.DeepEqual(session, candidateSession) {
			t.Fatal("alternate full peers derived different range-guard sessions")
		}
	}
	garbler := fixture.full.binding.GarblerPeerName
	evaluator := fixture.full.binding.EvaluatorPeerName
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(90 * time.Second))
	_ = right.SetDeadline(time.Now().Add(90 * time.Second))
	type guardOutcome struct {
		receipt formalGLMPhase16FullRangeGuardReceipt
		err     error
	}
	garblerDone := make(chan guardOutcome, 1)
	go func() {
		receipt, err := formalGLMPhase16RunFullRangeGuardGarbler(
			left, templates[garbler].Admission,
			fixture.full.formal.identities.public, session, changed[garbler],
			fixture.full.binding.ShiftedUpperBounds,
			sources[garbler].source.BindingSHA256, 0,
			fixture.full.roots[garbler],
			fixture.full.formal.identities.private[garbler])
		garblerDone <- guardOutcome{receipt: receipt, err: err}
	}()
	evaluatorGuard, evaluatorErr :=
		formalGLMPhase16RunFullRangeGuardEvaluator(
			right, templates[evaluator].Admission,
			fixture.full.formal.identities.public, session, changed[evaluator],
			fixture.full.binding.ShiftedUpperBounds,
			sources[evaluator].source.BindingSHA256, 0,
			fixture.full.formal.identities.private[evaluator])
	garblerResult := <-garblerDone
	if garblerResult.err != nil || evaluatorErr != nil {
		t.Fatalf("alternate full range guard: %v / %v",
			garblerResult.err, evaluatorErr)
	}
	guards := map[string]formalGLMPhase16FullRangeGuardReceipt{
		garbler: garblerResult.receipt, evaluator: evaluatorGuard,
	}
	result := make(map[string]formalGLMPhase21FullLocalOutput, 2)
	for _, peer := range peers {
		peerShare, err := jointDPBiomedicalGaussianRunFullPhase19Peer(
			templates[peer].Admission,
			fixture.full.formal.identities.public, sources[peer],
			fixture.full.backend, fixture.full.roots[peer],
			fixture.full.formal.identities.private[peer], encoded[peer])
		if err != nil {
			t.Fatal(err)
		}
		output := templates[peer]
		output.sourceBindingSHA = sources[peer].source.BindingSHA256
		output.RangeGuard = guards[peer]
		output.PeerShare = peerShare
		result[peer] = output
	}
	return result
}

func TestFormalGLMPhase21FullSourceBoundReleaseBinomialPoissonK2K3K5(
	t *testing.T,
) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 5} {
			t.Run(family+"-K"+string(rune('0'+custodians)), func(t *testing.T) {
				fixture := formalGLMPhase21FullTestSetup(t, custodians, family)
				defer fixture.close()
				first := formalGLMPhase21FullTestRun(t, fixture)
				defer func() {
					for peer := range first {
						value := first[peer]
						value.clear()
					}
				}()
				peers := fixture.full.formal.ctx.ComputePeers
				encodedOutput, err := json.Marshal(first[peers[0]])
				if err != nil || string(encodedOutput) != "{}" {
					t.Fatalf("Phase-2.1 full private output acquired a JSON surface: %s / %v",
						encodedOutput, err)
				}

				for _, peer := range peers {
					old := fixture.stores[peer]
					dir, semanticRoot := old.dir, old.semanticRoot
					old.close()
					storageRoot := sha256.Sum256(
						[]byte(t.Name() + "/handoff-key/" + peer))
					restarted, restartErr := newFormalGLMPhase20HandoffStore(
						dir, semanticRoot, peer, storageRoot,
						fixture.full.backend,
						fixture.full.formal.identities.public)
					if restartErr != nil {
						t.Fatal(restartErr)
					}
					fixture.stores[peer] = restarted
				}
				restarted := formalGLMPhase21FullTestRun(t, fixture)
				defer func() {
					for peer := range restarted {
						value := restarted[peer]
						value.clear()
					}
				}()
				for _, peer := range peers {
					if !reflect.DeepEqual(first[peer].RangeGuard,
						restarted[peer].RangeGuard) ||
						!reflect.DeepEqual(first[peer].PeerShare,
							restarted[peer].PeerShare) ||
						first[peer].HandoffSHA256 !=
							restarted[peer].HandoffSHA256 ||
						first[peer].sourceBindingSHA !=
							restarted[peer].sourceBindingSHA {
						t.Fatal("Phase-2.1 full restart changed a source-bound output")
					}
				}

				substituted := formalGLMPhase21FullTestAlternateOutputs(
					t, fixture, restarted)
				// Every lower-layer object is mutually consistent and authentic.
				// Only the authoritative Phase20 reload can distinguish this
				// execution from the one actually committed by the materializer.
				if _, err := formalGLMPhase21PairFullOutputs(
					substituted[peers[0]], substituted[peers[1]],
					fixture.full.formal.identities.public,
					fixture.full.backend); err != nil {
					t.Fatalf("self-consistent lower-layer substitution was malformed: %v",
						err)
				}
				for _, peer := range peers {
					if substituted[peer].sourceBindingSHA ==
						restarted[peer].sourceBindingSHA ||
						substituted[peer].PeerShare.source.SourceBindingSHA256 !=
							substituted[peer].sourceBindingSHA ||
						substituted[peer].RangeGuard.SourceBindingSHA256 !=
							substituted[peer].sourceBindingSHA {
						t.Fatal("alternate full execution was not source-self-consistent")
					}
					if err := formalGLMPhase21ValidateFullLocalOutputSource(
						fixture.stores[peer], substituted[peer]); err == nil {
						t.Fatal("Phase-2.1 full admitted a fully signed source substitution")
					}
					if !fileExists(fixture.stores[peer].recordPath) {
						t.Fatal("rejected full substitution removed the source handoff")
					}
				}
				rejectStore, err := newFormalGLMPhase16FullDurableReleaseStore(
					filepath.Join(t.TempDir(), peers[0]), peers[0],
					fixture.full.backend,
					fixture.full.formal.identities.private[peers[0]])
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalGLMPhase21FinalizeFullLocal(
					fixture.stores[peers[0]], rejectStore,
					substituted[peers[0]], substituted[peers[1]], nil); err == nil {
					t.Fatal("fully signed source substitution reached durable release")
				}

				localReleases := make(
					map[string]jointDPBiomedicalGaussianFullLocalRelease, 2)
				for _, peer := range peers {
					releaseRoot := filepath.Join(t.TempDir(), peer)
					releaseStore, storeErr :=
						newFormalGLMPhase16FullDurableReleaseStore(
							releaseRoot, peer, fixture.full.backend,
							fixture.full.formal.identities.private[peer])
					if storeErr != nil {
						t.Fatal(storeErr)
					}
					other := peers[0]
					if other == peer {
						other = peers[1]
					}
					localReleases[peer], err = formalGLMPhase21FinalizeFullLocal(
						fixture.stores[peer], releaseStore,
						restarted[peer], restarted[other], nil)
					if err != nil {
						t.Fatal(err)
					}
					reopened, reopenErr :=
						newFormalGLMPhase16FullDurableReleaseStore(
							releaseRoot, peer, fixture.full.backend,
							fixture.full.formal.identities.private[peer])
					if reopenErr != nil {
						t.Fatal(reopenErr)
					}
					replay, replayErr := formalGLMPhase21FinalizeFullLocal(
						fixture.stores[peer], reopened,
						restarted[peer], restarted[other],
						func(string) { t.Fatal("full restart replay performed new work") })
					if replayErr != nil || !replay.Replayed ||
						!reflect.DeepEqual(replay.Receipt,
							localReleases[peer].Receipt) {
						t.Fatalf("Phase-2.1 full durable replay changed: %#v / %v",
							replay, replayErr)
					}
				}
				certified, err := formalGLMPhase21CertifyFullRelease(
					localReleases[peers[0]], localReleases[peers[1]],
					restarted[peers[0]],
					fixture.full.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				if certified.ProductionReady || certified.OpeningsPerformed != 1 ||
					len(certified.Blockers) == 0 ||
					certified.SelectedBackend != formalGLMPhase16BackendFull {
					t.Fatal("Phase-2.1 full overstated public formal-GLM readiness")
				}
				for _, peer := range peers {
					wrong := certified
					wrong.VectorSHA256 = sha256Hex([]byte("tampered public vector"))
					if _, err := formalGLMPhase21CleanupFullReleasedSource(
						fixture.stores[peer], restarted[peer], wrong); err == nil {
						t.Fatal("tampered full release authorized source cleanup")
					}
					if !fileExists(fixture.stores[peer].recordPath) {
						t.Fatal("failed full cleanup removed the durable source")
					}
					removed, cleanupErr := formalGLMPhase21CleanupFullReleasedSource(
						fixture.stores[peer], restarted[peer], certified)
					if cleanupErr != nil ||
						removed != restarted[peer].HandoffBytes ||
						fileExists(fixture.stores[peer].recordPath) {
						t.Fatalf("full release-bound cleanup failed: %d / %v",
							removed, cleanupErr)
					}
				}
			})
		}
	}
}

func TestFormalGLMPhase21FullHiddenInvalidityIsDurableNoRelease(
	t *testing.T,
) {
	formal := formalGLMPhase18TestBuildFinalizerFixtureFamily(
		t, 2, "poisson")
	formalGLMPhase21TestInvalidateValidity(t, &formal)
	runtime := formalGLMPhase21TestRuntimeFromFixture(t, formal)
	fixture := formalGLMPhase21FullTestSetupFromRuntime(
		t, formal, runtime, "poisson")
	defer fixture.close()
	outputs := formalGLMPhase21FullTestRun(t, fixture)
	defer func() {
		for peer := range outputs {
			value := outputs[peer]
			value.clear()
		}
	}()
	peers := formal.ctx.ComputePeers
	guards := map[string]formalGLMPhase16FullRangeGuardReceipt{
		outputs[peers[0]].Role: outputs[peers[0]].RangeGuard,
		outputs[peers[1]].Role: outputs[peers[1]].RangeGuard,
	}
	if guards["garbler"].validityShare^
		guards["evaluator"].validityShare != 0 {
		t.Fatal("hidden-invalid Phase-1.8 execution passed the full exact range gate")
	}
	peer, other := peers[0], peers[1]
	releaseRoot := filepath.Join(t.TempDir(), peer)
	store, err := newFormalGLMPhase16FullDurableReleaseStore(
		releaseRoot, peer, fixture.full.backend,
		formal.identities.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	phases := []string{}
	_, err = formalGLMPhase21FinalizeFullLocal(
		fixture.stores[peer], store, outputs[peer], outputs[other],
		func(phase string) { phases = append(phases, phase) })
	if err == nil || exactGCFailureCodeOf(err) != exactGCFailureBoundExceeded {
		t.Fatalf("hidden-invalid full source was not rejected without release: %v", err)
	}
	if !reflect.DeepEqual(phases, []string{
		"after_ledger_append_before_validity_or_release",
		"after_invalid_source_durable_no_release",
	}) {
		t.Fatalf("hidden-invalid full durability order changed: %v", phases)
	}
	reopened, err := newFormalGLMPhase16FullDurableReleaseStore(
		releaseRoot, peer, fixture.full.backend,
		formal.identities.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	_, err = formalGLMPhase21FinalizeFullLocal(
		fixture.stores[peer], reopened, outputs[peer], outputs[other],
		func(string) { t.Fatal("hidden-invalid full replay performed new work") })
	if err == nil || exactGCFailureCodeOf(err) != exactGCFailureBoundExceeded {
		t.Fatalf("hidden-invalid full restart was not terminal: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(reopened.inner.records,
		fixture.full.contract.Contract.ReleaseInstanceID[:2])); !os.IsNotExist(statErr) {
		t.Fatal("hidden-invalid source reached the independent-full release store")
	}
	for _, name := range peers {
		if !fileExists(fixture.stores[name].recordPath) {
			t.Fatal("terminal hidden-invalid result consumed its source handoff")
		}
	}
}
