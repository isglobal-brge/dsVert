package main

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type formalGLMPhase16FullFallbackTestFixture struct {
	formal    formalGLMPhase18FinalizerFixture
	runtime   map[string]formalGLMPhase19RuntimeScheduleResult
	binding   formalGLMPhase16ReleaseBinding
	token     formalGLMPhase19PostExecutionToken
	selection formalGLMPhase16BackendSelectionAttestation
	request   formalGLMPhase16FullFallbackRequest
	contract  formalGLMPhase16FullFallbackContractAttestation
	admission jointDPBiomedicalGaussianFullAdmission
	roots     map[string][32]byte
	backend   [32]byte
}

func formalGLMPhase16FullFallbackTestHandoff(t testing.TB,
	fixture formalGLMPhase16FullFallbackTestFixture,
	shares map[string][]*big.Int,
) formalGLMPhase16FullFallbackHandoff {
	t.Helper()
	encoded := make(map[string]string, 2)
	bindings := make(map[string]jointDPBiomedicalGaussianFullPhase19SourceBinding, 2)
	for _, peer := range fixture.formal.ctx.ComputePeers {
		value, err := exactGCEncodeWorkerCanonicalShares(
			shares[peer], exactGCCircuitSpec{
				Operation: jointDPGaussianOneDrawOperation,
				RingBits:  128, FracBits: 0,
				VectorLen: fixture.binding.CoordinateCount,
			})
		if err != nil {
			t.Fatal(err)
		}
		encoded[peer] = value
		bindings[peer], err = jointDPBiomedicalGaussianBindFullPhase19Source(
			fixture.admission, fixture.formal.identities.public,
			fixture.token, fixture.backend, peer, 0,
			fixture.binding.CoordinateCount, value)
		if err != nil {
			t.Fatal(err)
		}
	}
	selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(
		fixture.selection)
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullSelectionDomain,
		fixture.contract.Contract)
	if err != nil {
		t.Fatal(err)
	}
	session, err := formalGLMPhase16FullRangeGuardSession(exactGCSession{
		MasterKey:   fixture.backend,
		GarblerID:   fixture.binding.GarblerPeerID,
		EvaluatorID: fixture.binding.EvaluatorPeerID,
	}, selectionSHA256, hex.EncodeToString(contractDigest[:]), 0,
		fixture.binding.CoordinateCount)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(30 * time.Second))
	_ = right.SetDeadline(time.Now().Add(30 * time.Second))
	type outcome struct {
		receipt formalGLMPhase16FullRangeGuardReceipt
		err     error
	}
	garblerDone := make(chan outcome, 1)
	garbler := fixture.binding.GarblerPeerName
	evaluator := fixture.binding.EvaluatorPeerName
	go func() {
		receipt, runErr := formalGLMPhase16RunFullRangeGuardGarbler(
			left, fixture.admission, fixture.formal.identities.public,
			session, shares[garbler], fixture.binding.ShiftedUpperBounds,
			bindings[garbler].source.BindingSHA256, 0,
			fixture.roots[garbler], fixture.formal.identities.private[garbler])
		garblerDone <- outcome{receipt, runErr}
	}()
	evaluatorReceipt, evaluatorErr :=
		formalGLMPhase16RunFullRangeGuardEvaluator(
			right, fixture.admission, fixture.formal.identities.public,
			session, shares[evaluator], fixture.binding.ShiftedUpperBounds,
			bindings[evaluator].source.BindingSHA256, 0,
			fixture.formal.identities.private[evaluator])
	garblerResult := <-garblerDone
	if garblerResult.err != nil || evaluatorErr != nil {
		t.Fatalf("range guard: %v / %v", garblerResult.err, evaluatorErr)
	}
	peerOutputs := make([]jointDPBiomedicalGaussianFullPhase19PeerShare, 0, 2)
	for _, peer := range fixture.contract.Contract.DesignatedComputePeers {
		output, err := jointDPBiomedicalGaussianRunFullPhase19Peer(
			fixture.admission, fixture.formal.identities.public,
			bindings[peer], fixture.backend, fixture.roots[peer],
			fixture.formal.identities.private[peer], encoded[peer])
		if err != nil {
			t.Fatal(err)
		}
		peerOutputs = append(peerOutputs, output)
	}
	full, err := jointDPBiomedicalGaussianBuildFullPhase19FinalizerHandoff(
		fixture.admission, fixture.formal.identities.public,
		fixture.token, fixture.backend, peerOutputs[0], peerOutputs[1])
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := formalGLMPhase16BuildFullFallbackHandoff(
		fixture.admission, fixture.formal.identities.public, full,
		garblerResult.receipt, evaluatorReceipt, fixture.backend)
	if err != nil {
		t.Fatal(err)
	}
	return handoff
}

func formalGLMPhase16FullFallbackTestSetup(t testing.TB,
	custodians int,
) formalGLMPhase16FullFallbackTestFixture {
	t.Helper()
	fixture, runtime := formalGLMPhase16TestDurableRuntime(
		t, custodians, "poisson")
	legacy, _, _, err := formalGLMPhase16TestProductiveAdmission(
		t, fixture, runtime)
	if err != nil {
		t.Fatal(err)
	}
	binding := legacy.Compiled.Binding
	binding.Epsilon = "1"
	binding.BindingSHA256, err = formalGLMPhase16ReleaseBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	selectionContract, _, err := formalGLMPhase16BuildBackendSelection(
		binding, legacy.Token, fixture.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	if selectionContract.SelectedBackend != formalGLMPhase16BackendFull {
		t.Fatalf("Poisson epsilon=1 fixture did not select full fallback: %#v",
			selectionContract)
	}
	selection := formalGLMPhase16BackendSelectionAttestation{
		Contract: selectionContract,
		Signatures: formalGLMPhase16TestSignBackendSelection(
			t, selectionContract, fixture.identities.private),
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
		epoch, err := jointDPBiomedicalGaussianFullNoiseRootEpoch(root, peer)
		if err != nil {
			t.Fatal(err)
		}
		epochs = append(epochs, jointDPBiomedicalGaussianNoiseRootEpoch{
			PeerName: peer, EpochSHA256: epoch,
		})
	}
	request := formalGLMPhase16FullFallbackRequest{
		LogicalReleaseSHA256:        hash("logical-release"),
		PrivacyEpochSHA256:          hash("privacy-epoch"),
		LogicalSnapshotHandleSHA256: hash("logical-snapshot"),
		NoiseRootEpochs:             epochs,
		ReceiptReferences: jointDPBiomedicalGaussianTestReceipts(
			t.Name() + "/formal-full"),
	}
	identity, err := formalGLMPhase16FullFallbackIdentity(
		selection, binding, legacy.Token, fixture.identities.public, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, epoch := range epochs {
		seed, context, commitment, err :=
			jointDPBiomedicalGaussianFullSeedMaterial(
				roots[epoch.PeerName], epoch.PeerName, identity)
		if err != nil {
			t.Fatal(err)
		}
		request.NoiseCommitments = append(request.NoiseCommitments,
			jointDPBiomedicalGaussianFullNoiseCommitment{
				PeerName: epoch.PeerName, ContextSHA256: context,
				SeedSHA256: commitment,
			})
		clear(seed[:])
	}
	fullContract, err := formalGLMPhase16BuildFullFallbackContract(
		selection, binding, legacy.Token, fixture.identities.public, request)
	if err != nil {
		t.Fatal(err)
	}
	fullSignatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(fullContract.CustodianPeers))
	for _, peer := range fullContract.CustodianPeers {
		signature, err := formalGLMPhase16SignFullFallbackContract(
			fullContract, peer, fixture.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		fullSignatures = append(fullSignatures, signature)
	}
	contract := formalGLMPhase16FullFallbackContractAttestation{
		Contract: fullContract, Signatures: fullSignatures,
	}
	admission, err := formalGLMPhase16AdmitFullFallback(
		selection, binding, legacy.Token, fixture.identities.public,
		request, contract)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMPhase16FullFallbackTestFixture{
		formal: fixture, runtime: runtime, binding: binding,
		token: legacy.Token, selection: selection, request: request,
		contract: contract, admission: admission, roots: roots,
		backend: runtime[fixture.ctx.ComputePeers[0]].backend,
	}
}

func TestFormalGLMPhase16FullFallbackAdmissionAndExactRangeGuardK2K3K4K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 4, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase16FullFallbackTestSetup(t, custodians)
			if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
				fixture.admission, fixture.formal.identities.public); err != nil {
				t.Fatal(err)
			}
			certificate := fixture.admission.Certificate
			if !certificate.AutomaticFallbackUsed ||
				!certificate.OneDrawSubstituted ||
				certificate.NominalVarianceMultiplier != 2 ||
				certificate.NominalStandardDeviationFactor !=
					"sqrt(2)_relative_to_one_full_draw" ||
				certificate.DerivedSensitivitySteps != "1024" {
				t.Fatalf("fallback cost was hidden: %#v", certificate)
			}

			byPeer := make(map[string]string, 2)
			bindings := make(map[string]jointDPBiomedicalGaussianFullPhase19SourceBinding, 2)
			for _, peer := range fixture.formal.ctx.ComputePeers {
				encoded, err := exactGCEncodeWorkerCanonicalShares(
					fixture.runtime[peer].dpShares, exactGCCircuitSpec{
						Operation: jointDPGaussianOneDrawOperation,
						RingBits:  128, FracBits: 0,
						VectorLen: fixture.binding.CoordinateCount,
					})
				if err != nil {
					t.Fatal(err)
				}
				byPeer[peer] = encoded
				bindings[peer], err = jointDPBiomedicalGaussianBindFullPhase19Source(
					fixture.admission, fixture.formal.identities.public,
					fixture.token, fixture.backend, peer, 0,
					fixture.binding.CoordinateCount, encoded)
				if err != nil {
					t.Fatal(err)
				}
			}
			selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(
				fixture.selection)
			if err != nil {
				t.Fatal(err)
			}
			contractDigest, err := jointDPBiomedicalGaussianDomainDigest(
				jointDPBiomedicalGaussianFullSelectionDomain,
				fixture.contract.Contract)
			if err != nil {
				t.Fatal(err)
			}
			base := exactGCSession{
				SessionID:   sha256.Sum256([]byte(t.Name() + "/range-session")),
				MasterKey:   fixture.backend,
				GarblerID:   fixture.binding.GarblerPeerID,
				EvaluatorID: fixture.binding.EvaluatorPeerID,
			}
			session, err := formalGLMPhase16FullRangeGuardSession(
				base, selectionSHA256, hex.EncodeToString(contractDigest[:]), 0,
				fixture.binding.CoordinateCount)
			if err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(30 * time.Second))
			_ = right.SetDeadline(time.Now().Add(30 * time.Second))
			type result struct {
				receipt formalGLMPhase16FullRangeGuardReceipt
				err     error
			}
			garblerDone := make(chan result, 1)
			garbler := fixture.binding.GarblerPeerName
			evaluator := fixture.binding.EvaluatorPeerName
			go func() {
				receipt, runErr := formalGLMPhase16RunFullRangeGuardGarbler(
					left, fixture.admission, fixture.formal.identities.public,
					session, fixture.runtime[garbler].dpShares,
					fixture.binding.ShiftedUpperBounds,
					bindings[garbler].source.BindingSHA256, 0,
					fixture.roots[garbler],
					fixture.formal.identities.private[garbler])
				garblerDone <- result{receipt, runErr}
			}()
			evaluatorReceipt, evaluatorErr :=
				formalGLMPhase16RunFullRangeGuardEvaluator(
					right, fixture.admission, fixture.formal.identities.public,
					session, fixture.runtime[evaluator].dpShares,
					fixture.binding.ShiftedUpperBounds,
					bindings[evaluator].source.BindingSHA256, 0,
					fixture.formal.identities.private[evaluator])
			garblerResult := <-garblerDone
			if garblerResult.err != nil || evaluatorErr != nil {
				t.Fatalf("range guard: %v / %v",
					garblerResult.err, evaluatorErr)
			}
			if garblerResult.receipt.validityShare^
				evaluatorReceipt.validityShare != 1 {
				t.Fatal("valid formal source failed the exact pre-noise gate")
			}
			if err := formalGLMPhase16ValidateFullRangeGuardReceipt(
				fixture.admission, fixture.formal.identities.public,
				garblerResult.receipt,
				bindings[garbler].source.BindingSHA256, "garbler"); err != nil {
				t.Fatal(err)
			}
			if err := formalGLMPhase16ValidateFullRangeGuardReceipt(
				fixture.admission, fixture.formal.identities.public,
				evaluatorReceipt,
				bindings[evaluator].source.BindingSHA256, "evaluator"); err != nil {
				t.Fatal(err)
			}

			peerOutputs := make([]jointDPBiomedicalGaussianFullPhase19PeerShare,
				0, 2)
			for _, peer := range fixture.contract.Contract.DesignatedComputePeers {
				output, err := jointDPBiomedicalGaussianRunFullPhase19Peer(
					fixture.admission, fixture.formal.identities.public,
					bindings[peer], fixture.backend, fixture.roots[peer],
					fixture.formal.identities.private[peer], byPeer[peer])
				if err != nil {
					t.Fatal(err)
				}
				peerOutputs = append(peerOutputs, output)
			}
			full, err := jointDPBiomedicalGaussianBuildFullPhase19FinalizerHandoff(
				fixture.admission, fixture.formal.identities.public,
				fixture.token, fixture.backend, peerOutputs[0], peerOutputs[1])
			if err != nil {
				t.Fatal(err)
			}
			handoff, err := formalGLMPhase16BuildFullFallbackHandoff(
				fixture.admission, fixture.formal.identities.public, full,
				garblerResult.receipt, evaluatorReceipt, fixture.backend)
			if err != nil {
				t.Fatal(err)
			}
			// The generic durable entry point must not be a bypass around the
			// formal hidden-validity barrier.
			direct, err := newJointDPBiomedicalGaussianFullDurableReleaseStore(
				t.TempDir(), fixture.contract.Contract.DesignatedComputePeers[0],
				fixture.backend, fixture.formal.identities.private[fixture.contract.Contract.DesignatedComputePeers[0]])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := direct.FinalizeVector(
				fixture.admission, fixture.formal.identities.public,
				[]jointDPBiomedicalGaussianFullPhase19FinalizerHandoff{full},
				nil); err == nil {
				t.Fatal("formal full release bypassed the durable exact range gate")
			}

			local := make(map[string]jointDPBiomedicalGaussianFullLocalRelease, 2)
			for _, peer := range fixture.contract.Contract.DesignatedComputePeers {
				root := filepath.Join(t.TempDir(), peer)
				store, err := newFormalGLMPhase16FullDurableReleaseStore(
					root, peer, fixture.backend,
					fixture.formal.identities.private[peer])
				if err != nil {
					t.Fatal(err)
				}
				phases := []string{}
				local[peer], err = store.FinalizeVector(
					fixture.admission, fixture.formal.identities.public,
					[]formalGLMPhase16FullFallbackHandoff{handoff},
					fixture.backend,
					func(phase string) { phases = append(phases, phase) })
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(phases, []string{
					"after_ledger_append_before_validity_or_release",
					"after_validity_durable_before_dp_release",
					"after_ledger_append_before_release",
					"after_dp_vector_durable",
				}) {
					t.Fatalf("formal full durability order changed: %v", phases)
				}
				replay, err := store.FinalizeVector(
					fixture.admission, fixture.formal.identities.public,
					[]formalGLMPhase16FullFallbackHandoff{handoff},
					fixture.backend,
					func(string) { t.Fatal("sticky replay performed new work") })
				if err != nil || !replay.Replayed ||
					!reflect.DeepEqual(replay.Receipt, local[peer].Receipt) {
					t.Fatalf("formal full sticky replay changed: %#v %v", replay, err)
				}
				restarted, err := newFormalGLMPhase16FullDurableReleaseStore(
					root, peer, fixture.backend,
					fixture.formal.identities.private[peer])
				if err != nil {
					t.Fatal(err)
				}
				restartReplay, err := restarted.FinalizeVector(
					fixture.admission, fixture.formal.identities.public,
					[]formalGLMPhase16FullFallbackHandoff{handoff},
					fixture.backend,
					func(string) { t.Fatal("restart replay performed new work") })
				if err != nil || !restartReplay.Replayed ||
					!reflect.DeepEqual(restartReplay.Receipt, local[peer].Receipt) {
					t.Fatalf("formal full restart replay changed: %#v %v",
						restartReplay, err)
				}
			}
			peers := fixture.contract.Contract.DesignatedComputePeers
			common, err := jointDPBiomedicalGaussianPairFullLocalReleases(
				fixture.admission, fixture.formal.identities.public,
				local[peers[1]].Receipt, local[peers[0]].Receipt)
			if err != nil {
				t.Fatal(err)
			}
			if common.OperationLimit || common.RequestLimit ||
				common.HistoryCanDenyOperation ||
				common.NominalVarianceMultiplier != 2 ||
				common.OpeningsPerformed != 1 ||
				len(common.ClampedScaledValues) != fixture.binding.CoordinateCount {
				t.Fatalf("invalid formal full common release: %#v", common)
			}
			certified, err := formalGLMPhase16CertifyFullRelease(
				fixture.admission, fixture.formal.identities.public, common)
			if err != nil {
				t.Fatal(err)
			}
			if err := formalGLMPhase16ValidateCertifiedRelease(
				certified, fixture.binding, fixture.token,
				fixture.formal.identities.public); err != nil {
				t.Fatal(err)
			}
			if certified.SelectedBackend != formalGLMPhase16BackendFull ||
				certified.NominalVarianceMultiplier != 2 ||
				certified.Simultaneous95AbsSteps == "" ||
				certified.SelectionReason == "" ||
				certified.ObservableWorkerShape == "" ||
				certified.HostConstantTimeClaim ||
				!certified.TranscriptDPClaim ||
				!certified.LogicalTranscriptFixedShape ||
				certified.PhysicalTimingDPClaim ||
				certified.OperationLimit || certified.RequestLimit ||
				certified.HistoryCanDenyOperation {
				t.Fatalf("full result hid backend/cost metadata: %#v", certified)
			}
		})
	}
}

func TestFormalGLMPhase16FullFallbackInvalidSourceIsDurableAndNeverReleased(t *testing.T) {
	fixture := formalGLMPhase16FullFallbackTestSetup(t, 2)
	shares := make(map[string][]*big.Int, 2)
	for _, peer := range fixture.formal.ctx.ComputePeers {
		shares[peer] = make([]*big.Int, len(fixture.runtime[peer].dpShares))
		for index, value := range fixture.runtime[peer].dpShares {
			shares[peer][index] = new(big.Int).Set(value)
		}
	}
	// Reconstruct upper+1 in the first coordinate without ever opening the
	// original value.  This is the exact sentinel produced when hidden
	// Phase-1.9 execution validity is false.
	garbler := fixture.binding.GarblerPeerName
	evaluator := fixture.binding.EvaluatorPeerName
	upper, ok := new(big.Int).SetString(
		fixture.binding.ShiftedUpperBounds[0], 10)
	if !ok {
		t.Fatal("invalid test bound")
	}
	target := new(big.Int).Add(upper, big.NewInt(1))
	shares[garbler][0].Sub(target, shares[evaluator][0])
	shares[garbler][0].And(shares[garbler][0], exactGCMask(128))
	handoff := formalGLMPhase16FullFallbackTestHandoff(t, fixture, shares)
	if handoff.Garbler.validityShare^handoff.Evaluator.validityShare != 0 {
		t.Fatal("upper+1 source passed the exact pre-noise range gate")
	}
	peer := fixture.contract.Contract.DesignatedComputePeers[0]
	store, err := newFormalGLMPhase16FullDurableReleaseStore(
		t.TempDir(), peer, fixture.backend,
		fixture.formal.identities.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	phases := []string{}
	if _, err := store.FinalizeVector(
		fixture.admission, fixture.formal.identities.public,
		[]formalGLMPhase16FullFallbackHandoff{handoff}, fixture.backend,
		func(phase string) { phases = append(phases, phase) }); err == nil ||
		exactGCFailureCodeOf(err) != exactGCFailureBoundExceeded {
		t.Fatalf("invalid source was not rejected without release: %v", err)
	}
	if !reflect.DeepEqual(phases, []string{
		"after_ledger_append_before_validity_or_release",
		"after_invalid_source_durable_no_release",
	}) {
		t.Fatalf("invalid-source durability order changed: %v", phases)
	}
	if _, err := store.FinalizeVector(
		fixture.admission, fixture.formal.identities.public,
		[]formalGLMPhase16FullFallbackHandoff{handoff}, fixture.backend,
		func(string) { t.Fatal("invalid replay performed new work") }); err == nil ||
		exactGCFailureCodeOf(err) != exactGCFailureBoundExceeded {
		t.Fatalf("durable invalid replay was not terminal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.inner.records,
		fixture.contract.Contract.ReleaseInstanceID[:2])); !os.IsNotExist(err) {
		t.Fatal("invalid source reached the independent-full release store")
	}
}
