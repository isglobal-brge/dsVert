package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func formalGLMPhase20TestPersistStores(t testing.TB,
	fixture formalGLMPhase18FinalizerFixture,
	runtime map[string]formalGLMPhase19RuntimeScheduleResult) map[string]*formalGLMPhase20HandoffStore {

	t.Helper()
	semantic := sha256.Sum256([]byte(t.Name() + "/semantic-root"))
	schedule := sha256.Sum256([]byte(t.Name() + "/schedule-root"))
	attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
	semanticText := hex.EncodeToString(semantic[:])
	stores := make(map[string]*formalGLMPhase20HandoffStore, 2)
	for _, peer := range fixture.ctx.ComputePeers {
		storageRoot := sha256.Sum256([]byte(t.Name() + "/handoff-key/" + peer))
		decoded := formalGLMPhase19ScheduleWorkerDecoded{
			config: formalGLMPhase19ScheduleWorkerConfig{
				SemanticRootSHA256: semanticText,
				ScheduleRootSHA256: hex.EncodeToString(schedule[:]),
				AttemptID:          hex.EncodeToString(attempt[:]),
				LocalTemplate: formalGLMPhase19RuntimeLocalInput{
					Plan: fixture.plan, Recipient: peer,
				},
			},
			durable: formalGLMPhase19RuntimeDurableConfig{
				Pins: fixture.identities.public,
			},
		}
		result, err := formalGLMPhase19ScheduleEncodeResult(
			decoded, runtime[peer])
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "handoff", peer)
		store, err := newFormalGLMPhase20HandoffStore(
			dir, semanticText, peer, storageRoot, runtime[peer].backend,
			fixture.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		commit, err := store.Commit(fixture.plan, runtime[peer].context, result)
		if err != nil {
			t.Fatal(err)
		}
		if commit.Replayed || !formalGLMIsSHA256(commit.SHA256) ||
			commit.Bytes < 64 {
			t.Fatalf("invalid initial handoff commit: %#v", commit)
		}
		replayed, err := store.Commit(
			fixture.plan, runtime[peer].context, result)
		if err != nil {
			t.Fatal(err)
		}
		if !replayed.Replayed || replayed.SHA256 != commit.SHA256 ||
			replayed.Bytes != commit.Bytes {
			t.Fatalf("handoff replay changed the durable slot: %#v / %#v",
				commit, replayed)
		}
		encoded, err := os.ReadFile(store.recordPath)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(`"dp_share"`)) ||
			bytes.Contains(encoded, []byte(result.DPShare)) {
			t.Fatal("durable handoff exposed its sealed source share")
		}
		store.close()
		store, err = newFormalGLMPhase20HandoffStore(
			dir, semanticText, peer, storageRoot, runtime[peer].backend,
			fixture.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		source, restarted, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if !restarted.Replayed || restarted.SHA256 != commit.SHA256 ||
			len(source.DPShares) != fixture.plan.Kernel.CoefficientCount {
			t.Fatal("restarted handoff did not recover the committed source")
		}
		for index := range source.DPShares {
			if source.DPShares[index].Cmp(runtime[peer].dpShares[index]) != 0 {
				t.Fatal("restarted handoff changed a source share")
			}
		}
		source.clear()
		stores[peer] = store
	}
	return stores
}

func formalGLMPhase20TestOneDrawInputs(t testing.TB,
	fixture formalGLMPhase18FinalizerFixture,
	runtime map[string]formalGLMPhase19RuntimeScheduleResult) (
	formalGLMPhase16CapsuleBinding, formalGLMPhase16ProductiveRequest,
	map[string][32]byte, [32]byte) {

	t.Helper()
	first := runtime[fixture.ctx.ComputePeers[0]]
	receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(
		first.finalReceipts)
	if err != nil {
		t.Fatal(err)
	}
	roles, err := formalGLMPhase16PinnedRoles(
		fixture.plan, fixture.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	commitments := make(map[string]formalGLMPhase16NoiseCommitment, 2)
	seeds := make(map[string][32]byte, 2)
	for _, role := range []struct{ name, id, role string }{
		{roles.GarblerPeerName, roles.GarblerPeerID, "garbler"},
		{roles.EvaluatorPeerName, roles.EvaluatorPeerID, "evaluator"},
	} {
		seed := sha256.Sum256([]byte(t.Name() + "/sticky-root/" + role.name))
		seeds[role.name] = seed
		context := jointDPCommitmentContext(receiptDigest,
			jointDPGaussianOneDrawCommitmentPurpose+"/"+role.role, role.id)
		commitment := jointDPSeedCommitment(context, seed)
		commitments[role.id] = formalGLMPhase16NoiseCommitment{
			ContextSHA256: hex.EncodeToString(context[:]),
			SeedSHA256:    hex.EncodeToString(commitment[:]),
		}
	}
	hash := func(label string) string {
		value := sha256.Sum256([]byte(t.Name() + "/" + label))
		return hex.EncodeToString(value[:])
	}
	capsule := formalGLMPhase16CapsuleBinding{
		CapsuleID:      first.postToken.CapsuleSHA256,
		ManifestSHA256: hash("manifest"), SchemaManifestSHA256: hash("schema"),
		WorkloadSHA256: hash("workload"), SourceContextSHA256: hash("source"),
		CoordinateOrderSHA256: formalGLMPhase16CoefficientOrderSHA256(
			fixture.plan.Kernel.CoefficientCount),
		ReleaseInstanceID:     hash("release"),
		ReleaseContractSHA256: hex.EncodeToString(receiptDigest[:]),
		Mechanism:             formalGLMPhase16RequiredMechanism,
		Allocation:            formalGLMPhase16RequiredAllocation,
		Epsilon: func() string {
			if fixture.plan.Kernel.Family == "poisson" {
				return "10"
			}
			return "1"
		}(),
		AllocatedDelta: "0.000001", NoiseCommitments: commitments,
	}
	runNonce := sha256.Sum256([]byte(t.Name() + "/run"))
	request := formalGLMPhase16ProductiveRequest{
		LogicalSnapshotHandleSHA256: hash("snapshot"),
		PrivacyEpochSHA256:          hash("privacy-epoch"),
		RunNonceSHA256:              hex.EncodeToString(runNonce[:]),
		WorkerImplementationSHA256:  hash("worker"),
		ReceiptReferences: jointDPBiomedicalGaussianTestReceipts(
			t.Name() + "/receipts"),
	}
	return capsule, request, seeds, runNonce
}

func formalGLMPhase20TestFinalizeOneDraw(t testing.TB,
	fixture formalGLMPhase18FinalizerFixture, sources map[string][]*big.Int,
	backend [32]byte,
	admission formalGLMPhase16ProductiveAdmission,
	seeds map[string][32]byte, runNonce [32]byte) {

	t.Helper()
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		admission.Envelope, admission.Trust)
	if err != nil {
		t.Fatal(err)
	}
	session := exactGCSession{
		SessionID: runNonce, MasterKey: backend,
		GarblerID: spec.GarblerPeerID, EvaluatorID: spec.EvaluatorPeerID,
		Purpose: spec.purpose(),
		Spec: exactGCCircuitSpec{
			Operation: jointDPGaussianOneDrawOperation,
			RingBits:  128, FracBits: 0, VectorLen: spec.CoordinateCount,
		},
	}
	preimage := admission.Envelope.Preimage
	type localInput struct {
		encoded string
		binding jointDPBiomedicalGaussianLocalSourceBinding
	}
	locals := make(map[string]localInput, 2)
	for _, entry := range []struct{ name, role string }{
		{preimage.GarblerPeerName, "garbler"},
		{preimage.EvaluatorPeerName, "evaluator"},
	} {
		encoded, err := exactGCEncodeWorkerCanonicalShares(
			sources[entry.name], session.Spec)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := jointDPBiomedicalGaussianBuildLocalSourceBinding(
			preimage, admission.Compiled.Binding.SnapshotSHA256,
			admission.Compiled.Binding.SourceFanInTranscriptSHA256,
			entry.name, entry.role, encoded)
		if err != nil {
			t.Fatal(err)
		}
		locals[entry.name] = localInput{encoded: encoded, binding: binding}
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(90 * time.Second))
	_ = right.SetDeadline(time.Now().Add(90 * time.Second))
	type outcome struct {
		shares []*big.Int
		err    error
	}
	garblerDone := make(chan outcome, 1)
	go func() {
		local := locals[preimage.GarblerPeerName]
		seed := seeds[preimage.GarblerPeerName]
		shares, runErr := jointDPBiomedicalGaussianRunProductiveGarbler(
			left, admission.Envelope, admission.Trust, local.binding,
			session, local.encoded, base64.StdEncoding.EncodeToString(seed[:]))
		garblerDone <- outcome{shares: shares, err: runErr}
	}()
	evaluatorLocal := locals[preimage.EvaluatorPeerName]
	evaluatorSeed := seeds[preimage.EvaluatorPeerName]
	evaluatorShares, evaluatorErr :=
		jointDPBiomedicalGaussianRunProductiveEvaluator(
			right, admission.Envelope, admission.Trust,
			evaluatorLocal.binding, session, evaluatorLocal.encoded,
			base64.StdEncoding.EncodeToString(evaluatorSeed[:]))
	garbler := <-garblerDone
	if garbler.err != nil || evaluatorErr != nil {
		t.Fatalf("Phase-2.0 one-draw execution: %v / %v",
			garbler.err, evaluatorErr)
	}
	defer exactGCZeroBigInts(garbler.shares)
	defer exactGCZeroBigInts(evaluatorShares)
	garblerReceipt, err := jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
		admission.Envelope, admission.Trust, "garbler", garbler.shares,
		fixture.identities.private[preimage.GarblerPeerName])
	if err != nil {
		t.Fatal(err)
	}
	evaluatorReceipt, err := jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
		admission.Envelope, admission.Trust, "evaluator", evaluatorShares,
		fixture.identities.private[preimage.EvaluatorPeerName])
	if err != nil {
		t.Fatal(err)
	}
	handoff := jointDPBiomedicalGaussianOneDrawChunkHandoff{
		Envelope: admission.Envelope,
		Garbler:  garblerReceipt, Evaluator: evaluatorReceipt,
		GarblerShares: garbler.shares, EvaluatorShares: evaluatorShares,
	}
	localReleases := make(map[string]jointDPBiomedicalGaussianOneDrawLocalRelease, 2)
	for _, peer := range []string{
		preimage.GarblerPeerName, preimage.EvaluatorPeerName,
	} {
		storeKey := sha256.Sum256([]byte(t.Name() + "/release-store/" + peer))
		store, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
			filepath.Join(t.TempDir(), peer), peer, storeKey,
			fixture.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		local, err := store.FinalizeVector(
			[]jointDPBiomedicalGaussianOneDrawChunkHandoff{handoff},
			admission.Trust, nil)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := store.FinalizeVector(
			[]jointDPBiomedicalGaussianOneDrawChunkHandoff{handoff},
			admission.Trust, nil)
		if err != nil || !replay.Replayed ||
			!reflect.DeepEqual(local.Receipt, replay.Receipt) {
			t.Fatalf("Phase-2.0 sticky one-draw replay changed: %#v %v",
				replay, err)
		}
		localReleases[peer] = local
	}
	common, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{admission.Envelope},
		admission.Trust,
		localReleases[preimage.EvaluatorPeerName].Receipt,
		localReleases[preimage.GarblerPeerName].Receipt)
	if err != nil {
		t.Fatal(err)
	}
	certified, err := formalGLMPhase16CertifyOneDrawRelease(admission, common)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMPhase16ValidateCertifiedRelease(
		certified, admission.Compiled.Binding, admission.Token,
		fixture.identities.public); err != nil {
		t.Fatal(err)
	}
	if common.OpeningsPerformed != 1 || common.OperationLimit ||
		common.RequestLimit || common.HistoryCanDenyOperation ||
		!common.UnlimitedDeterministicReplay {
		t.Fatalf("invalid Phase-2.0 sticky one-draw release: %#v", common)
	}
}

func TestFormalGLMPhase20DurableHandoffAndOneDrawAdmissionK2K3K4K5(
	t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 4, 5} {
			t.Run(family+"-K"+string(rune('0'+custodians)), func(t *testing.T) {
				fixture, runtime := formalGLMPhase16TestDurableRuntime(
					t, custodians, family)
				stores := formalGLMPhase20TestPersistStores(t, fixture, runtime)
				defer func() {
					for _, store := range stores {
						store.close()
					}
				}()
				capsule, request, seeds, runNonce :=
					formalGLMPhase20TestOneDrawInputs(t, fixture, runtime)
				locals := make(map[string]*formalGLMPhase20LocalRuntime, 2)
				defer func() {
					for _, local := range locals {
						local.clear()
					}
				}()
				for _, peer := range fixture.ctx.ComputePeers {
					local, err := formalGLMPhase20BuildLocalRuntime(
						stores[peer], fixture.identities.public, capsule, request)
					if err != nil {
						t.Fatal(err)
					}
					locals[peer] = &local
				}
				reference := locals[fixture.ctx.ComputePeers[0]].Admission
				for _, peer := range fixture.ctx.ComputePeers[1:] {
					if !reflect.DeepEqual(reference, locals[peer].Admission) {
						t.Fatal("compute peers derived different Phase-2.0 contracts")
					}
				}
				backendSignatures := formalGLMPhase16TestSignBackendSelection(
					t, reference.Productive.BackendSelection.Contract,
					fixture.identities.private)
				names := append([]string(nil), fixture.plan.Kernel.CustodianPeers...)
				sort.Strings(names)
				workerSignatures := make([]jointDPBiomedicalGaussianSignature, 0,
					len(names))
				for _, name := range names {
					signature, err := formalGLMPhase16SignProductiveEnvelope(
						reference.Productive.Envelope.Preimage, name,
						fixture.identities.private[name])
					if err != nil {
						t.Fatal(err)
					}
					workerSignatures = append(workerSignatures, signature)
				}
				if _, err := formalGLMPhase20AdmitLocalRuntime(
					*locals[fixture.ctx.ComputePeers[0]],
					backendSignatures[:len(backendSignatures)-1],
					workerSignatures, nil, nil,
					fixture.identities.public); err == nil {
					t.Fatal("Phase-2.0 admitted fewer than K backend signatures")
				}
				if _, err := formalGLMPhase20AdmitLocalRuntime(
					*locals[fixture.ctx.ComputePeers[0]], backendSignatures,
					workerSignatures[:len(workerSignatures)-1], nil, nil,
					fixture.identities.public); err == nil {
					t.Fatal("Phase-2.0 admitted fewer than K worker signatures")
				}
				if family == "binomial" && custodians == 2 {
					modified := *locals[fixture.ctx.ComputePeers[0]]
					modified.Admission.Productive.Compiled.Binding.Epsilon = "2"
					if _, err := formalGLMPhase20AdmitLocalRuntime(
						modified, backendSignatures, workerSignatures, nil, nil,
						fixture.identities.public); err == nil {
						t.Fatal("Phase-2.0 admitted a modified local runtime")
					}
				}
				for _, peer := range fixture.ctx.ComputePeers {
					admitted, err := formalGLMPhase20AdmitLocalRuntime(
						*locals[peer], backendSignatures, workerSignatures,
						nil, nil, fixture.identities.public)
					if err != nil {
						t.Fatal(err)
					}
					*locals[peer] = admitted
				}
				admitted := locals[fixture.ctx.ComputePeers[0]].Admission
				if admitted.Full != nil ||
					len(admitted.Productive.Envelope.Signatures) != custodians {
					t.Fatal("Phase-2.0 did not retain the K-signed one-draw backend")
				}
				sources := make(map[string][]*big.Int, 2)
				backend := locals[fixture.ctx.ComputePeers[0]].Source.backend
				for _, peer := range fixture.ctx.ComputePeers {
					if locals[peer].Source.backend != backend {
						t.Fatal("compute peers recovered different Phase-2.0 backends")
					}
					sources[peer] = locals[peer].Source.DPShares
				}
				formalGLMPhase20TestFinalizeOneDraw(
					t, fixture, sources, backend, admitted.Productive,
					seeds, runNonce)

				if family == "binomial" && custodians == 2 {
					peer := fixture.ctx.ComputePeers[0]
					store := stores[peer]
					original, err := os.ReadFile(store.recordPath)
					if err != nil {
						t.Fatal(err)
					}
					tampered := append([]byte(nil), original...)
					tampered[len(tampered)/2] ^= 1
					if err := os.WriteFile(store.recordPath, tampered, 0o600); err != nil {
						t.Fatal(err)
					}
					if _, _, err := store.Load(); err == nil {
						t.Fatal("tampered durable handoff authenticated")
					}
					if err := os.WriteFile(store.recordPath, original, 0o600); err != nil {
						t.Fatal(err)
					}
					backup := store.recordPath + ".saved"
					if err := os.Rename(store.recordPath, backup); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(backup, store.recordPath); err != nil {
						t.Fatal(err)
					}
					if _, _, err := store.Load(); err == nil {
						t.Fatal("symbolic-link handoff authenticated")
					}
					if err := os.Remove(store.recordPath); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(backup, store.recordPath); err != nil {
						t.Fatal(err)
					}
					committedTemp := filepath.Join(
						filepath.Dir(store.recordPath), ".gaussian-release-crash")
					if err := os.Link(store.recordPath, committedTemp); err != nil {
						t.Fatal(err)
					}
					recovered, _, err := store.Load()
					if err != nil {
						t.Fatal(err)
					}
					recovered.clear()
					if fileExists(committedTemp) {
						t.Fatal("Phase-2.0 retained a committed CAS temporary after restart")
					}
					old := time.Now().Add(-formalGLMPhase18TempGrace - time.Hour)
					for _, name := range []string{
						".gaussian-release-orphan", ".phase20-consume-" +
							hex.EncodeToString(original[:16]) + ".bin",
					} {
						path := filepath.Join(filepath.Dir(store.recordPath), name)
						if err := os.WriteFile(path, original, 0o600); err != nil {
							t.Fatal(err)
						}
						if err := os.Chtimes(path, old, old); err != nil {
							t.Fatal(err)
						}
					}
					staleIncomplete := map[string][]byte{
						".gaussian-release-stale-zero":    {},
						".gaussian-release-stale-partial": {1, 2, 3},
					}
					for name, contents := range staleIncomplete {
						path := filepath.Join(filepath.Dir(store.recordPath), name)
						if err := os.WriteFile(path, contents, 0o600); err != nil {
							t.Fatal(err)
						}
						if err := os.Chtimes(path, old, old); err != nil {
							t.Fatal(err)
						}
					}
					freshTemp := filepath.Join(
						filepath.Dir(store.recordPath), ".gaussian-release-active")
					if err := os.WriteFile(freshTemp, original, 0o600); err != nil {
						t.Fatal(err)
					}
					freshIncomplete := map[string][]byte{
						".gaussian-release-fresh-zero":    {},
						".gaussian-release-fresh-partial": {1, 2, 3},
					}
					for name, contents := range freshIncomplete {
						path := filepath.Join(filepath.Dir(store.recordPath), name)
						if err := os.WriteFile(path, contents, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					storageRoot := sha256.Sum256(
						[]byte(t.Name() + "/handoff-key/" + peer))
					reopened, err := newFormalGLMPhase20HandoffStore(
						store.dir, store.semanticRoot, peer, storageRoot,
						runtime[peer].backend, fixture.identities.public)
					if err != nil {
						t.Fatal(err)
					}
					reopened.close()
					if fileExists(filepath.Join(
						filepath.Dir(store.recordPath), ".gaussian-release-orphan")) ||
						fileExists(filepath.Join(filepath.Dir(store.recordPath),
							".phase20-consume-"+hex.EncodeToString(original[:16])+".bin")) {
						t.Fatal("Phase-2.0 bootstrap retained stale crash files")
					}
					if !fileExists(freshTemp) {
						t.Fatal("Phase-2.0 bootstrap reaped an active CAS temporary")
					}
					for name := range staleIncomplete {
						if fileExists(filepath.Join(filepath.Dir(store.recordPath), name)) {
							t.Fatal("Phase-2.0 bootstrap retained an incomplete stale CAS temporary")
						}
					}
					for name := range freshIncomplete {
						path := filepath.Join(filepath.Dir(store.recordPath), name)
						if !fileExists(path) {
							t.Fatal("Phase-2.0 bootstrap reaped an incomplete active CAS temporary")
						}
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Remove(freshTemp); err != nil {
						t.Fatal(err)
					}
					conflict := stores[peer]
					source, _, err := conflict.Load()
					if err != nil {
						t.Fatal(err)
					}
					changed := source.Result
					changedShares := make([]*big.Int, len(source.DPShares))
					for index := range source.DPShares {
						changedShares[index] = new(big.Int).Set(source.DPShares[index])
					}
					changedShares[0].Add(changedShares[0], big.NewInt(1))
					changedShares[0].And(changedShares[0], exactGCMask(128))
					changed.DPShare, err = exactGCEncodeWorkerCanonicalShares(
						changedShares, exactGCCircuitSpec{
							Operation: exactGCFormalGLMDPBridge,
							RingBits:  128, FracBits: 0,
							VectorLen: len(changedShares),
						})
					exactGCZeroBigInts(changedShares)
					source.clear()
					if err != nil {
						t.Fatal(err)
					}
					if _, err := conflict.Commit(
						fixture.plan, runtime[peer].context, changed); err == nil {
						t.Fatal("conflicting durable handoff replay replaced first commit")
					}
					retained, cleanupReceipt, err := conflict.Load()
					if err != nil {
						t.Fatal(err)
					}
					retained.clear()
					wrong := sha256.Sum256([]byte("wrong Phase-2.0 cleanup receipt"))
					if _, err := conflict.Consume(
						hex.EncodeToString(wrong[:])); err == nil {
						t.Fatal("handoff cleanup accepted a different release receipt")
					}
					alias := conflict.recordPath + ".hardlink"
					if err := os.Link(conflict.recordPath, alias); err != nil {
						t.Fatal(err)
					}
					if _, err := conflict.Consume(cleanupReceipt.SHA256); err == nil {
						t.Fatal("handoff cleanup accepted a hard-linked slot")
					}
					if err := os.Remove(alias); err != nil {
						t.Fatal(err)
					}
					removed, err := conflict.Consume(cleanupReceipt.SHA256)
					if err != nil || removed != cleanupReceipt.Bytes ||
						fileExists(conflict.recordPath) {
						t.Fatalf("authenticated handoff cleanup failed: %d / %v",
							removed, err)
					}
					quarantines, err := filepath.Glob(filepath.Join(
						filepath.Dir(conflict.recordPath), ".phase20-consume-*.bin"))
					if err != nil || len(quarantines) != 0 {
						t.Fatalf("handoff cleanup retained quarantine files: %v / %v",
							quarantines, err)
					}
				}
			})
		}
	}
}

func formalGLMPhase20CapsuleFromBinding(
	binding formalGLMPhase16ReleaseBinding) formalGLMPhase16CapsuleBinding {
	return formalGLMPhase16CapsuleBinding{
		CapsuleID: binding.CapsuleID, ManifestSHA256: binding.ManifestSHA256,
		SchemaManifestSHA256:  binding.SchemaManifestSHA256,
		WorkloadSHA256:        binding.WorkloadSHA256,
		SourceContextSHA256:   binding.SourceContextSHA256,
		CoordinateOrderSHA256: binding.CoordinateOrderSHA256,
		ReleaseInstanceID:     binding.ReleaseInstanceID,
		ReleaseContractSHA256: binding.ReleaseContractSHA256,
		Mechanism:             binding.Mechanism, Allocation: binding.Allocation,
		Epsilon: binding.Epsilon, AllocatedDelta: binding.AllocatedDelta,
		NoiseCommitments: map[string]formalGLMPhase16NoiseCommitment{
			binding.GarblerPeerID: {
				ContextSHA256: binding.GarblerCommitmentContext,
				SeedSHA256:    binding.GarblerSeedCommitment,
			},
			binding.EvaluatorPeerID: {
				ContextSHA256: binding.EvaluatorCommitmentContext,
				SeedSHA256:    binding.EvaluatorSeedCommitment,
			},
		},
	}
}

func TestFormalGLMPhase20AdmitsSignedFullFallbackK2K3K4K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 4, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase16FullFallbackTestSetup(t, custodians)
			stores := formalGLMPhase20TestPersistStores(
				t, fixture.formal, fixture.runtime)
			defer func() {
				for _, store := range stores {
					store.close()
				}
			}()
			hash := func(label string) string {
				value := sha256.Sum256([]byte(t.Name() + "/" + label))
				return hex.EncodeToString(value[:])
			}
			request := formalGLMPhase16ProductiveRequest{
				LogicalSnapshotHandleSHA256: fixture.request.LogicalSnapshotHandleSHA256,
				PrivacyEpochSHA256:          fixture.request.PrivacyEpochSHA256,
				RunNonceSHA256:              hash("full-run-nonce"),
				WorkerImplementationSHA256:  hash("worker"),
				ReceiptReferences:           fixture.request.ReceiptReferences,
			}
			capsule := formalGLMPhase20CapsuleFromBinding(fixture.binding)
			locals := make(map[string]*formalGLMPhase20LocalRuntime, 2)
			defer func() {
				for _, local := range locals {
					local.clear()
				}
			}()
			for _, peer := range fixture.formal.ctx.ComputePeers {
				local, err := formalGLMPhase20BuildLocalRuntime(
					stores[peer], fixture.formal.identities.public,
					capsule, request)
				if err != nil {
					t.Fatal(err)
				}
				locals[peer] = &local
			}
			reference := locals[fixture.formal.ctx.ComputePeers[0]].Admission
			for _, peer := range fixture.formal.ctx.ComputePeers[1:] {
				if !reflect.DeepEqual(reference, locals[peer].Admission) {
					t.Fatal("compute peers derived different Phase-2.0 full contracts")
				}
			}
			if reference.Productive.BackendSelection.Contract.SelectedBackend !=
				formalGLMPhase16BackendFull {
				t.Fatal("Phase-2.0 failed to retain the full fallback decision")
			}
			backendSignatures := formalGLMPhase16TestSignBackendSelection(
				t, reference.Productive.BackendSelection.Contract,
				fixture.formal.identities.private)
			partialContract := fixture.contract
			partialContract.Signatures = partialContract.Signatures[:len(partialContract.Signatures)-1]
			if _, err := formalGLMPhase20AdmitLocalRuntime(
				*locals[fixture.formal.ctx.ComputePeers[0]], backendSignatures,
				nil, &fixture.request, &partialContract,
				fixture.formal.identities.public); err == nil {
				t.Fatal("Phase-2.0 admitted fewer than K full-contract signatures")
			}
			for _, peer := range fixture.formal.ctx.ComputePeers {
				admitted, err := formalGLMPhase20AdmitLocalRuntime(
					*locals[peer], backendSignatures, nil, &fixture.request,
					&fixture.contract, fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				*locals[peer] = admitted
			}
			admitted := locals[fixture.formal.ctx.ComputePeers[0]].Admission
			if admitted.Full == nil ||
				admitted.Full.SelectionContractSHA256 !=
					fixture.admission.SelectionContractSHA256 {
				t.Fatal("Phase-2.0 changed the signed full fallback contract")
			}
			releaseFixture := fixture
			releaseFixture.admission = *admitted.Full
			sources := make(map[string][]*big.Int, 2)
			for _, peer := range fixture.formal.ctx.ComputePeers {
				if locals[peer].Source.backend != fixture.backend {
					t.Fatal("compute peer recovered a different full backend")
				}
				sources[peer] = locals[peer].Source.DPShares
			}
			handoff := formalGLMPhase16FullFallbackTestHandoff(
				t, releaseFixture, sources)
			local := make(map[string]jointDPBiomedicalGaussianFullLocalRelease, 2)
			for _, peer := range fixture.contract.Contract.DesignatedComputePeers {
				store, err := newFormalGLMPhase16FullDurableReleaseStore(
					filepath.Join(t.TempDir(), peer), peer, fixture.backend,
					fixture.formal.identities.private[peer])
				if err != nil {
					t.Fatal(err)
				}
				local[peer], err = store.FinalizeVector(
					*admitted.Full, fixture.formal.identities.public,
					[]formalGLMPhase16FullFallbackHandoff{handoff},
					fixture.backend, nil)
				if err != nil {
					t.Fatal(err)
				}
				replay, err := store.FinalizeVector(
					*admitted.Full, fixture.formal.identities.public,
					[]formalGLMPhase16FullFallbackHandoff{handoff},
					fixture.backend, nil)
				if err != nil || !replay.Replayed ||
					!reflect.DeepEqual(replay.Receipt, local[peer].Receipt) {
					t.Fatalf("Phase-2.0 sticky full replay changed: %#v %v",
						replay, err)
				}
			}
			peers := fixture.contract.Contract.DesignatedComputePeers
			common, err := jointDPBiomedicalGaussianPairFullLocalReleases(
				*admitted.Full, fixture.formal.identities.public,
				local[peers[1]].Receipt, local[peers[0]].Receipt)
			if err != nil {
				t.Fatal(err)
			}
			certified, err := formalGLMPhase16CertifyFullRelease(
				*admitted.Full, fixture.formal.identities.public, common)
			if err != nil {
				t.Fatal(err)
			}
			if err := formalGLMPhase16ValidateCertifiedRelease(
				certified, fixture.binding, fixture.token,
				fixture.formal.identities.public); err != nil {
				t.Fatal(err)
			}
			if common.OpeningsPerformed != 1 || common.OperationLimit ||
				common.RequestLimit || common.HistoryCanDenyOperation {
				t.Fatalf("invalid Phase-2.0 sticky full release: %#v", common)
			}
		})
	}
}
