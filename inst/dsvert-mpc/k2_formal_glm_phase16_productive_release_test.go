package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func formalGLMPhase16TestDurableRuntime(t testing.TB, custodians int,
	family string) (formalGLMPhase18FinalizerFixture,
	map[string]formalGLMPhase19RuntimeScheduleResult) {
	t.Helper()
	fixture := formalGLMPhase18TestBuildFinalizerFixtureFamily(
		t, custodians, family)
	inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
	peers := fixture.ctx.ComputePeers
	prepared := make(map[string]formalGLMPhase19RuntimePrepareOutput, 2)
	for _, peer := range peers {
		value, err := formalGLMPhase19RuntimePrepare(inputs[peer])
		if err != nil {
			t.Fatal(err)
		}
		prepared[peer] = value
	}
	configs := make(map[string]formalGLMPhase19RuntimeDurableConfig, 2)
	checkpointRoot := t.TempDir()
	for _, peer := range peers {
		configs[peer] = formalGLMPhase19RuntimeDurableConfig{
			CheckpointDir:     filepath.Join(checkpointRoot, peer),
			CheckpointKey:     sha256.Sum256([]byte(t.Name() + "/checkpoint/" + peer)),
			SigningKey:        fixture.identities.private[peer],
			Pins:              fixture.identities.public,
			OutputLatticeBits: fixture.plan.Kernel.FracBits,
		}
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(90 * time.Second))
	_ = right.SetDeadline(time.Now().Add(90 * time.Second))
	root := sha256.Sum256([]byte(t.Name() + "/runtime-root"))
	results := make(map[string]formalGLMPhase19RuntimeScheduleResult, 2)
	errors := make(map[string]error, 2)
	var lock sync.Mutex
	var wait sync.WaitGroup
	wait.Add(2)
	for index, peer := range peers {
		index, peer := index, peer
		conn := net.Conn(left)
		other := peers[1]
		if index == 1 {
			conn, other = right, peers[0]
		}
		go func() {
			defer wait.Done()
			value, err := formalGLMPhase19RuntimeRunDurableSchedule(
				conn, []formalGLMPhase19RuntimeLocalInput{inputs[peer]},
				[]formalGLMPhase19FanInReceipt{prepared[other].Receipt},
				root, configs[peer])
			lock.Lock()
			results[peer], errors[peer] = value, err
			lock.Unlock()
		}()
	}
	wait.Wait()
	for _, peer := range peers {
		if errors[peer] != nil {
			t.Fatalf("runtime %s: %v", peer, errors[peer])
		}
	}
	return fixture, results
}

func formalGLMPhase16TestProductiveAdmission(t testing.TB,
	fixture formalGLMPhase18FinalizerFixture,
	results map[string]formalGLMPhase19RuntimeScheduleResult) (
	formalGLMPhase16ProductiveAdmission, map[string][32]byte,
	exactGCSession, error) {
	t.Helper()
	first := results[fixture.ctx.ComputePeers[0]]
	receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(
		first.finalReceipts)
	if err != nil {
		return formalGLMPhase16ProductiveAdmission{}, nil, exactGCSession{}, err
	}
	releaseContract := hex.EncodeToString(receiptDigest[:])
	roles, err := formalGLMPhase16PinnedRoles(
		fixture.plan, fixture.identities.public)
	if err != nil {
		return formalGLMPhase16ProductiveAdmission{}, nil, exactGCSession{}, err
	}
	seeds := make(map[string][32]byte, 2)
	commitments := make(map[string]formalGLMPhase16NoiseCommitment, 2)
	for _, role := range []struct {
		name, id, role string
	}{
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
		CapsuleID:            first.postToken.CapsuleSHA256,
		ManifestSHA256:       hash("manifest"),
		SchemaManifestSHA256: hash("schema"),
		WorkloadSHA256:       hash("workload"),
		SourceContextSHA256:  hash("source-context"),
		CoordinateOrderSHA256: formalGLMPhase16CoefficientOrderSHA256(
			fixture.plan.Kernel.CoefficientCount),
		ReleaseInstanceID:     hash("release-instance"),
		ReleaseContractSHA256: releaseContract,
		Mechanism:             formalGLMPhase16RequiredMechanism,
		Allocation:            formalGLMPhase16RequiredAllocation,
		Epsilon: func() string {
			if fixture.plan.Kernel.Family == "poisson" {
				return "10"
			}
			return "1"
		}(),
		AllocatedDelta:   "0.000001",
		NoiseCommitments: commitments,
	}
	runNonce := sha256.Sum256([]byte(t.Name() + "/productive-run"))
	request := formalGLMPhase16ProductiveRequest{
		LogicalSnapshotHandleSHA256: hash("logical-snapshot"),
		PrivacyEpochSHA256:          hash("privacy-epoch"),
		RunNonceSHA256:              hex.EncodeToString(runNonce[:]),
		WorkerImplementationSHA256:  hash("worker-implementation"),
		ReceiptReferences: jointDPBiomedicalGaussianTestReceipts(
			t.Name() + "/formal-glm"),
	}
	admission, err := formalGLMPhase16BuildProductiveEnvelope(
		fixture.plan, first.finalReceipts, fixture.identities.public,
		first.dpBridge, capsule, first.postToken, first.backend, request)
	if err != nil {
		return formalGLMPhase16ProductiveAdmission{}, nil, exactGCSession{}, err
	}
	backendSignatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(admission.BackendSelection.Contract.CustodianPeers))
	for _, name := range admission.BackendSelection.Contract.CustodianPeers {
		signature, signErr := formalGLMPhase16SignBackendSelection(
			admission.BackendSelection.Contract, name,
			fixture.identities.private[name])
		if signErr != nil {
			return formalGLMPhase16ProductiveAdmission{}, nil, exactGCSession{}, signErr
		}
		backendSignatures = append(backendSignatures, signature)
	}
	admission, err = formalGLMPhase16AdmitProductiveBackendSignatures(
		admission, backendSignatures)
	if err != nil {
		return formalGLMPhase16ProductiveAdmission{}, nil, exactGCSession{}, err
	}
	names := append([]string(nil), fixture.plan.Kernel.CustodianPeers...)
	sort.Strings(names)
	signatures := make([]jointDPBiomedicalGaussianSignature, 0, len(names))
	for _, name := range names {
		signature, err := formalGLMPhase16SignProductiveEnvelope(
			admission.Envelope.Preimage, name,
			fixture.identities.private[name])
		if err != nil {
			return formalGLMPhase16ProductiveAdmission{}, nil, exactGCSession{}, err
		}
		signatures = append(signatures, signature)
	}
	admission, err = formalGLMPhase16AdmitProductiveSignatures(
		admission, signatures)
	if err != nil {
		return formalGLMPhase16ProductiveAdmission{}, nil, exactGCSession{}, err
	}
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		admission.Envelope, admission.Trust)
	if err != nil {
		return formalGLMPhase16ProductiveAdmission{}, nil, exactGCSession{}, err
	}
	session := exactGCSession{
		SessionID: runNonce, MasterKey: first.backend,
		GarblerID: spec.GarblerPeerID, EvaluatorID: spec.EvaluatorPeerID,
		Purpose: spec.purpose(),
		Spec: exactGCCircuitSpec{
			Operation: jointDPGaussianOneDrawOperation,
			RingBits:  128, FracBits: 0, VectorLen: spec.CoordinateCount,
		},
	}
	return admission, seeds, session, nil
}

func TestFormalGLMPhase16ProductiveOneDrawCommonReleaseK2K3K4K5(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 4, 5} {
			t.Run(family+"-K"+string(rune('0'+custodians)), func(t *testing.T) {
				fixture, runtime := formalGLMPhase16TestDurableRuntime(
					t, custodians, family)
				admission, seeds, session, err :=
					formalGLMPhase16TestProductiveAdmission(t, fixture, runtime)
				if err != nil {
					t.Fatal(err)
				}
				if family == "binomial" && custodians == 2 {
					tampered := admission.Envelope
					tampered.Preimage.WorkloadSHA256 = sha256Hex(
						[]byte("relay-tampered-formal-workload"))
					if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
						tampered, admission.Trust); err == nil {
						t.Fatal("relay-tampered formal envelope retained K signatures")
					}
					tampered = admission.Envelope
					tampered.WorkerPolicy.ReleaseBindingCanonicalJSON += " "
					if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
						tampered, admission.Trust); err == nil {
						t.Fatal("tampered formal release-binding bytes were accepted")
					}
				}
				preimage := admission.Envelope.Preimage
				byPeer := make(map[string][]*big.Int, 2)
				for _, peer := range fixture.ctx.ComputePeers {
					byPeer[peer] = runtime[peer].dpShares
				}
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
						byPeer[entry.name], session.Spec)
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
						session, local.encoded,
						base64.StdEncoding.EncodeToString(seed[:]))
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
					t.Fatalf("productive one-draw: %v / %v",
						garbler.err, evaluatorErr)
				}
				garblerReceipt, err :=
					jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
						admission.Envelope, admission.Trust, "garbler",
						garbler.shares,
						fixture.identities.private[preimage.GarblerPeerName])
				if err != nil {
					t.Fatal(err)
				}
				evaluatorReceipt, err :=
					jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
						admission.Envelope, admission.Trust, "evaluator",
						evaluatorShares,
						fixture.identities.private[preimage.EvaluatorPeerName])
				if err != nil {
					t.Fatal(err)
				}
				handoff := jointDPBiomedicalGaussianOneDrawChunkHandoff{
					Envelope: admission.Envelope,
					Garbler:  garblerReceipt, Evaluator: evaluatorReceipt,
					GarblerShares:   garbler.shares,
					EvaluatorShares: evaluatorShares,
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
						t.Fatalf("formal sticky replay changed: %#v %v", replay, err)
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
				if common.OperationLimit || common.RequestLimit ||
					common.HistoryCanDenyOperation || common.OpeningsPerformed != 1 ||
					!common.ExactlyOnceRelease || !common.UnlimitedDeterministicReplay ||
					len(common.ClampedScaledValues) != fixture.plan.Kernel.CoefficientCount {
					t.Fatalf("invalid formal common DP release: %#v", common)
				}
				certified, err := formalGLMPhase16CertifyOneDrawRelease(
					admission, common)
				if err != nil {
					t.Fatal(err)
				}
				if err := formalGLMPhase16ValidateCertifiedRelease(
					certified, admission.Compiled.Binding, admission.Token,
					fixture.identities.public); err != nil {
					t.Fatal(err)
				}
				if certified.SelectedBackend != formalGLMPhase16BackendOneDraw ||
					certified.NominalVarianceMultiplier != 1 ||
					certified.SelectionReason == "" ||
					certified.Simultaneous95AbsSteps == "" ||
					certified.ObservableWorkerShape == "" ||
					certified.HostConstantTimeClaim ||
					!certified.TranscriptDPClaim ||
					!certified.LogicalTranscriptFixedShape ||
					certified.PhysicalTimingDPClaim {
					t.Fatalf("one-draw result hid backend/cost metadata: %#v", certified)
				}
				spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
					admission.Envelope, admission.Trust)
				if err != nil {
					t.Fatal(err)
				}
				garblerRandom, garblerSigns, err :=
					jointDPBiomedicalGaussianProductivePrivateInputs(
						seeds[preimage.GarblerPeerName], spec, "garbler",
						preimage.ProductiveStreamSHA256)
				if err != nil {
					t.Fatal(err)
				}
				evaluatorRandom, evaluatorSigns, err :=
					jointDPBiomedicalGaussianProductivePrivateInputs(
						seeds[preimage.EvaluatorPeerName], spec, "evaluator",
						preimage.ProductiveStreamSHA256)
				if err != nil {
					t.Fatal(err)
				}
				defer exactGCZeroBigInts(garblerRandom)
				defer exactGCZeroBigInts(evaluatorRandom)
				for index, text := range common.ClampedScaledValues {
					source := exactGCReferenceReconstruct(
						byPeer[preimage.GarblerPeerName][index],
						byPeer[preimage.EvaluatorPeerName][index], 128)
					draw := new(big.Int).Xor(
						garblerRandom[index], evaluatorRandom[index])
					magnitude, err := jointDPGaussianOneDrawSelectMagnitude(
						draw, spec.CDFCumulative)
					if err != nil {
						t.Fatal(err)
					}
					if garblerSigns[index] != evaluatorSigns[index] {
						magnitude.Neg(magnitude)
					}
					want := new(big.Int).Add(source, magnitude)
					upper := new(big.Int).Set(spec.RawUpperBounds[index])
					if want.Sign() < 0 {
						want.SetInt64(0)
					} else if want.Cmp(upper) > 0 {
						want.Set(upper)
					}
					if text != want.String() {
						t.Fatalf("formal DP coordinate %d got %s want %s",
							index, text, want)
					}
				}
				exactGCZeroBigInts(garbler.shares)
				exactGCZeroBigInts(evaluatorShares)
				for _, peer := range fixture.ctx.ComputePeers {
					value := runtime[peer]
					exactGCZeroBigInts(value.betaShares)
					exactGCZeroBigInts(value.dpShares)
					clear(value.backend[:])
				}
			})
		}
	}
}

func TestFormalGLMPhase16SensitivityStatusFamiliesDoNotCross(t *testing.T) {
	formal := formalGLMPhase16ReleaseBinding{Family: "binomial"}
	formal.SensitivityCertificate.Status = "machine_proven"
	if !jointDPBiomedicalGaussianWorkerSensitivityStatusAllowed(formal) {
		t.Fatal("verified formal machine_proven status was rejected")
	}
	formal.SensitivityCertificate.Status =
		jointDPBiomedicalGaussianWorkerSensitivityStatus
	if jointDPBiomedicalGaussianWorkerSensitivityStatusAllowed(formal) {
		t.Fatal("formal GLM inherited the biomedical pending status")
	}
	biomedical := formalGLMPhase16ReleaseBinding{
		Family:           "biomedical_capsule_vector",
		SensitivityProof: jointDPBiomedicalGaussianL2Proof,
	}
	biomedical.SensitivityCertificate.Status =
		jointDPBiomedicalGaussianWorkerSensitivityStatus
	if !jointDPBiomedicalGaussianWorkerSensitivityStatusAllowed(biomedical) {
		t.Fatal("biomedical typed-layout status was rejected")
	}
	biomedical.SensitivityCertificate.Status = "machine_proven"
	if jointDPBiomedicalGaussianWorkerSensitivityStatusAllowed(biomedical) {
		t.Fatal("biomedical route promoted generic machine_proven")
	}
	unknown := formalGLMPhase16ReleaseBinding{Family: "negative-binomial"}
	unknown.SensitivityCertificate.Status = "machine_proven"
	if jointDPBiomedicalGaussianWorkerSensitivityStatusAllowed(unknown) {
		t.Fatal("unknown family acquired a DP sensitivity authority")
	}
}
