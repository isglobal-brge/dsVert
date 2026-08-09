package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

type jointDPBiomedicalGaussianFullTestFixture struct {
	base      jointDPBiomedicalGaussianTestFixture
	roots     map[string][32]byte
	selection jointDPBiomedicalGaussianFullSelectionAttestation
	admission jointDPBiomedicalGaussianFullAdmission
}

func jointDPBiomedicalGaussianFullTestReceipts(label string) []jointDPBiomedicalGaussianReceiptReference {
	receipts := make([]jointDPBiomedicalGaussianReceiptReference,
		len(jointDPBiomedicalGaussianRequiredReceiptKinds))
	for index, kind := range jointDPBiomedicalGaussianRequiredReceiptKinds {
		receipts[index] = jointDPBiomedicalGaussianReceiptReference{
			Version:    jointDPBiomedicalGaussianReceiptVersion,
			Kind:       kind,
			SHA256:     jointDPBiomedicalGaussianTestHash(label + "/receipt/" + kind),
			DigestKind: jointDPBiomedicalGaussianReceiptDigestRule,
		}
	}
	return receipts
}

func jointDPBiomedicalGaussianFullTestSign(t testing.TB,
	contract jointDPBiomedicalGaussianFullSelectionContract,
	private map[string]ed25519.PrivateKey,
) []jointDPBiomedicalGaussianSignature {
	t.Helper()
	signatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(contract.CustodianPeers))
	for _, peer := range contract.CustodianPeers {
		signature, err := jointDPBiomedicalGaussianSign(
			jointDPBiomedicalGaussianFullSelectionDomain, contract,
			peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	return signatures
}

func jointDPBiomedicalGaussianFullTestSetup(t testing.TB, custodians,
	coordinates int, label string,
) jointDPBiomedicalGaussianFullTestFixture {
	t.Helper()
	base := jointDPBiomedicalGaussianTestSetup(t, custodians, coordinates,
		label+"/base")
	roots := make(map[string][32]byte, 2)
	epochs := make([]jointDPBiomedicalGaussianNoiseRootEpoch, 0, 2)
	for _, peer := range base.manifest.Contract.DesignatedComputePeers {
		root := sha256.Sum256([]byte(label + "/noise-root/" + peer))
		roots[peer] = root
		epoch, err := jointDPBiomedicalGaussianFullNoiseRootEpoch(root, peer)
		if err != nil {
			t.Fatal(err)
		}
		epochs = append(epochs, jointDPBiomedicalGaussianNoiseRootEpoch{
			PeerName: peer, EpochSHA256: epoch,
		})
	}
	request := jointDPBiomedicalGaussianFullSelectionRequest{
		LogicalReleaseSHA256:      jointDPBiomedicalGaussianTestHash(label + "/logical-release"),
		PrivacyEpochSHA256:        jointDPBiomedicalGaussianTestHash(label + "/privacy-epoch"),
		MaterializationRootSHA256: jointDPBiomedicalGaussianTestHash(label + "/materialization"),
		ReservationSHA256:         jointDPBiomedicalGaussianTestHash(label + "/reservation"),
		Epsilon:                   "1", Delta: "0.000001",
		NoiseRootEpochs:   epochs,
		ReceiptReferences: jointDPBiomedicalGaussianFullTestReceipts(label),
	}
	// The reservation handle is the K-signed append-before-release ledger
	// receipt. It is opaque and never patient-derived.
	for index := range request.ReceiptReferences {
		if request.ReceiptReferences[index].Kind ==
			jointDPBiomedicalGaussianReceiptPrivacyLedger {
			request.ReceiptReferences[index].SHA256 = request.ReservationSHA256
		}
	}
	identity, err := jointDPBiomedicalGaussianFullReleaseIdentityForRequest(
		base.manifest, base.pins, request)
	if err != nil {
		t.Fatal(err)
	}
	request.NoiseCommitments = make([]jointDPBiomedicalGaussianFullNoiseCommitment,
		0, 2)
	for _, epoch := range epochs {
		seed, context, commitment, err :=
			jointDPBiomedicalGaussianFullSeedMaterial(
				roots[epoch.PeerName], epoch.PeerName, identity)
		if err != nil {
			t.Fatal(err)
		}
		request.NoiseCommitments = append(request.NoiseCommitments,
			jointDPBiomedicalGaussianFullNoiseCommitment{
				PeerName:      epoch.PeerName,
				ContextSHA256: context,
				SeedSHA256:    commitment,
			})
		clear(seed[:])
	}
	contract, err := jointDPBiomedicalGaussianBuildFullSelectionContract(
		base.manifest, base.pins, request)
	if err != nil {
		t.Fatal(err)
	}
	selection := jointDPBiomedicalGaussianFullSelectionAttestation{
		Contract: contract,
		Signatures: jointDPBiomedicalGaussianFullTestSign(
			t, contract, base.private),
	}
	admission, err := jointDPBiomedicalGaussianAdmitFullSelection(
		base.manifest, selection, base.pins)
	if err != nil {
		t.Fatal(err)
	}
	return jointDPBiomedicalGaussianFullTestFixture{
		base: base, roots: roots, selection: selection, admission: admission,
	}
}

func jointDPBiomedicalGaussianFullTestSourceShare(t testing.TB,
	coordinates int, start byte,
) string {
	t.Helper()
	value := make([]byte, 16*coordinates)
	for index := 0; index < coordinates; index++ {
		value[index*16] = start + byte(index)
	}
	return base64.StdEncoding.EncodeToString(value)
}

func jointDPBiomedicalGaussianFullTestNoisedBytes(t testing.TB,
	share jointDPBiomedicalGaussianFullPeerShare,
) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(share.output.NoisedShare)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func jointDPBiomedicalGaussianFullTestRunPeer(t testing.TB,
	admission jointDPBiomedicalGaussianFullAdmission,
	base jointDPBiomedicalGaussianTestFixture, roots map[string][32]byte,
	peer string, chunkStart, coordinateCount int, sourceShare string,
) jointDPBiomedicalGaussianFullPeerShare {
	t.Helper()
	binding, err := jointDPBiomedicalGaussianBuildFullLocalSourceBinding(
		admission, base.pins, peer,
		jointDPBiomedicalGaussianTestHash(peer+"/local-snapshot-contract"),
		jointDPBiomedicalGaussianTestHash(peer+"/local-source-contract"),
		chunkStart, coordinateCount, sourceShare)
	if err != nil {
		t.Fatal(err)
	}
	share, err := jointDPBiomedicalGaussianRunFullPeer(
		admission, base.pins, binding, peer, roots[peer],
		base.private[peer], sourceShare)
	if err != nil {
		t.Fatal(err)
	}
	return share
}

func TestJointDPBiomedicalGaussianFullK2K3K5ExplicitAndSealed(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := jointDPBiomedicalGaussianFullTestSetup(
				t, custodians, 3, t.Name())
			certificate := fixture.admission.Certificate
			if certificate.Backend != jointDPGaussianBackend ||
				certificate.BackendSelection !=
					"all_k_server_authoritative_cross_signed_exact_backend_v1" ||
				!certificate.CompleteEpsilonDeltaPerPeer ||
				certificate.EpsilonPerPeerNumerator != "1" ||
				certificate.EpsilonPerPeerDenominator != "1" ||
				certificate.DeltaPerPeerNumerator != "1" ||
				certificate.DeltaPerPeerDenominator != "1000000" ||
				certificate.ReleaseDeltaAggregation != "max_per_peer_not_sum" ||
				certificate.NominalVarianceMultiplier != 2 ||
				certificate.NominalStandardDeviationFactor !=
					"sqrt(2)_relative_to_one_full_draw" ||
				!certificate.RequiresAtLeastOneHonestDesignatedPeer ||
				!certificate.IndependentNoiseRootCustodyRequired ||
				!certificate.DistinctNoiseRootEpochsVerified ||
				certificate.MaximumColludingDesignatedPeers != 1 ||
				certificate.BothDesignatedCollusionProtected ||
				certificate.MaliciousCustodianSecurityClaim ||
				!certificate.RelayTamperDetection ||
				certificate.RelayAvailabilityGuaranteed ||
				!certificate.FiniteSupportTransferCharged ||
				!certificate.FixedWorkSampler ||
				certificate.HostConstantTimeClaim ||
				!certificate.TranscriptDPClaim ||
				!certificate.LogicalTranscriptFixedShape ||
				certificate.PhysicalTimingDPClaim ||
				!certificate.NoWrapHeadroomCertified ||
				certificate.OneDrawSubstituted || certificate.AutomaticFallbackUsed ||
				certificate.OpeningsPerformed != 0 ||
				certificate.ProductionReady || len(certificate.Blockers) == 0 {
				t.Fatalf("invalid productive certificate: %#v", certificate)
			}
			if fixture.selection.Contract.Backend != jointDPGaussianBackend ||
				fixture.selection.Contract.PublicIdentifierContract !=
					jointDPBiomedicalGaussianPublicIdentifierRule ||
				fixture.selection.Contract.LogicalSnapshotHandleKind !=
					jointDPBiomedicalGaussianOpaqueSnapshotHandle ||
				fixture.selection.Contract.SourceContractHandleKind !=
					jointDPBiomedicalGaussianOpaqueSourceContract ||
				fixture.selection.Contract.MaterializationRootKind !=
					jointDPBiomedicalGaussianOpaqueSourceRoot ||
				fixture.selection.Contract.ReservationDigestKind !=
					jointDPBiomedicalGaussianReceiptDigestRule ||
				fixture.selection.Contract.OperationLimit ||
				fixture.selection.Contract.RequestLimit ||
				fixture.selection.Contract.HistoryCanDenyOperation {
				t.Fatalf("invalid K=%d selection", custodians)
			}
			for _, peer := range fixture.base.manifest.Contract.DesignatedComputePeers {
				output := jointDPBiomedicalGaussianFullTestRunPeer(
					t, fixture.admission, fixture.base, fixture.roots, peer,
					0, 3, jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 1))
				if output.Backend != jointDPGaussianBackend ||
					!output.output.FullCapsuleParametersPerPeer ||
					output.output.EpsilonDividedByPeerCount ||
					output.output.SourceValuesReturned ||
					output.output.NoiseValuesReturned ||
					output.output.PrivateSeedReturned ||
					output.output.PreclampValuesReturned {
					t.Fatalf("worker escaped its envelope: %#v", output)
				}
			}
		})
	}
}

func TestJointDPBiomedicalGaussianFullRejectsClonedNoiseRoot(t *testing.T) {
	base := jointDPBiomedicalGaussianTestSetup(t, 3, 2, t.Name())
	root := sha256.Sum256([]byte(t.Name() + "/cloned-root"))
	epochs := make([]jointDPBiomedicalGaussianNoiseRootEpoch, 0, 2)
	for _, peer := range base.manifest.Contract.DesignatedComputePeers {
		epoch, err := jointDPBiomedicalGaussianFullNoiseRootEpoch(root, peer)
		if err != nil {
			t.Fatal(err)
		}
		epochs = append(epochs, jointDPBiomedicalGaussianNoiseRootEpoch{
			PeerName: peer, EpochSHA256: epoch,
		})
	}
	request := jointDPBiomedicalGaussianFullSelectionRequest{
		LogicalReleaseSHA256:      jointDPBiomedicalGaussianTestHash(t.Name() + "/release"),
		PrivacyEpochSHA256:        jointDPBiomedicalGaussianTestHash(t.Name() + "/epoch"),
		MaterializationRootSHA256: jointDPBiomedicalGaussianTestHash(t.Name() + "/materialization"),
		ReservationSHA256:         jointDPBiomedicalGaussianTestHash(t.Name() + "/reservation"),
		Epsilon:                   "1",
		Delta:                     "0.000001",
		NoiseRootEpochs:           epochs,
	}
	if _, err := jointDPBiomedicalGaussianFullReleaseIdentityForRequest(
		base.manifest, base.pins, request); err == nil {
		t.Fatal("K-signed admission accepted a root cloned across designated peers")
	}
}

func TestJointDPBiomedicalGaussianFullRejectsBackendAndBindingSubstitution(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 3, 3, t.Name())
	for name, mutate := range map[string]func(*jointDPBiomedicalGaussianFullSelectionContract){
		"one-draw": func(value *jointDPBiomedicalGaussianFullSelectionContract) {
			value.Backend = "one_draw_exact_gc_sealed_reference"
		},
		"release": func(value *jointDPBiomedicalGaussianFullSelectionContract) {
			value.ReleaseInstanceID = jointDPBiomedicalGaussianTestHash("forged-release")
		},
		"snapshot": func(value *jointDPBiomedicalGaussianFullSelectionContract) {
			value.LogicalSnapshotHandleSHA256 = jointDPBiomedicalGaussianTestHash("forged-snapshot")
		},
		"source": func(value *jointDPBiomedicalGaussianFullSelectionContract) {
			value.SourceContractHandleSHA256 = jointDPBiomedicalGaussianTestHash("forged-source")
		},
		"materialization": func(value *jointDPBiomedicalGaussianFullSelectionContract) {
			value.MaterializationRootSHA256 = jointDPBiomedicalGaussianTestHash("forged-materialization")
		},
		"reservation": func(value *jointDPBiomedicalGaussianFullSelectionContract) {
			value.ReservationSHA256 = jointDPBiomedicalGaussianTestHash("forged-reservation")
		},
		"plan": func(value *jointDPBiomedicalGaussianFullSelectionContract) {
			value.PlanSHA256 = jointDPBiomedicalGaussianTestHash("forged-plan")
		},
		"quota": func(value *jointDPBiomedicalGaussianFullSelectionContract) {
			value.HistoryCanDenyOperation = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := jointDPBiomedicalGaussianTestClone(t, fixture.selection)
			mutate(&changed.Contract)
			changed.Signatures = jointDPBiomedicalGaussianFullTestSign(
				t, changed.Contract, fixture.base.private)
			if _, err := jointDPBiomedicalGaussianAdmitFullSelection(
				fixture.base.manifest, changed, fixture.base.pins); err == nil {
				t.Fatalf("re-signed %s substitution was accepted", name)
			}
		})
	}

	peer := fixture.base.manifest.Contract.DesignatedComputePeers[0]
	leftSource := jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 1)
	left := jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, peer,
		0, 3, leftSource)
	other := fixture.base.manifest.Contract.DesignatedComputePeers[1]
	right := jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, other,
		0, 3, jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 11))
	left.Backend = "substituted"
	if _, err := jointDPBiomedicalGaussianBuildFullFinalizerHandoff(
		fixture.admission, fixture.base.pins, left, right); err == nil {
		t.Fatal("finalizer accepted a substituted backend")
	}

	mutatedAdmission := fixture.admission
	mutatedAdmission.Certificate.Backend = "substituted"
	binding, err := jointDPBiomedicalGaussianBuildFullLocalSourceBinding(
		fixture.admission, fixture.base.pins, peer,
		jointDPBiomedicalGaussianTestHash(peer+"/local-snapshot-contract"),
		jointDPBiomedicalGaussianTestHash(peer+"/local-source-contract"),
		0, 3, leftSource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jointDPBiomedicalGaussianRunFullPeer(
		mutatedAdmission, fixture.base.pins, binding, peer,
		fixture.roots[peer], fixture.base.private[peer], leftSource); err == nil {
		t.Fatal("cached worker accepted a mutated public admission certificate")
	}
	mutatedSelectionAdmission := fixture.admission
	mutatedSelectionAdmission.selection.Contract.BackendSelection = "substituted"
	if _, err := jointDPBiomedicalGaussianRunFullPeer(
		mutatedSelectionAdmission, fixture.base.pins, binding, peer,
		fixture.roots[peer], fixture.base.private[peer], leftSource); err == nil {
		t.Fatal("cached worker accepted a mutated private selection contract")
	}
	otherSource := jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 40)
	if _, err := jointDPBiomedicalGaussianRunFullPeer(
		fixture.admission, fixture.base.pins, binding, peer,
		fixture.roots[peer], fixture.base.private[peer], otherSource); err == nil {
		t.Fatal("worker accepted a SourceShare different from its local materializer binding")
	}
	wrongSigner := fixture.base.private[other]
	if _, err := jointDPBiomedicalGaussianRunFullPeer(
		fixture.admission, fixture.base.pins, binding, peer,
		fixture.roots[peer], wrongSigner, leftSource); err == nil {
		t.Fatal("worker accepted a signer different from the pinned local peer")
	}

	validLeft := jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, peer,
		0, 3, leftSource)
	validRight := jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, other,
		0, 3, jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 11))
	validLeft.output.NoisedShare = validRight.output.NoisedShare
	if _, err := jointDPBiomedicalGaussianBuildFullFinalizerHandoff(
		fixture.admission, fixture.base.pins,
		validLeft, validRight); err == nil {
		t.Fatal("finalizer accepted a relay-substituted signed peer payload")
	}
}

func TestJointDPBiomedicalGaussianFullRequiresExactlyKSelectionSignatures(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 3, 2, t.Name())
	for name, mutate := range map[string]func(*jointDPBiomedicalGaussianFullSelectionAttestation){
		"omitted": func(value *jointDPBiomedicalGaussianFullSelectionAttestation) {
			value.Signatures = value.Signatures[:2]
		},
		"duplicate": func(value *jointDPBiomedicalGaussianFullSelectionAttestation) {
			value.Signatures[2] = value.Signatures[0]
		},
		"extra": func(value *jointDPBiomedicalGaussianFullSelectionAttestation) {
			value.Signatures = append(value.Signatures, value.Signatures[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := jointDPBiomedicalGaussianTestClone(t, fixture.selection)
			mutate(&changed)
			if _, err := jointDPBiomedicalGaussianAdmitFullSelection(
				fixture.base.manifest, changed, fixture.base.pins); err == nil {
				t.Fatalf("%s K-of-K selection was accepted", name)
			}
		})
	}

	// Admission owns deep copies, so caller mutation after admission cannot
	// alter the cached worker contract.
	fixture.selection.Contract.NoiseRootEpochs[0].EpochSHA256 =
		jointDPBiomedicalGaussianTestHash("external-alias-mutation")
	peer := fixture.base.manifest.Contract.DesignatedComputePeers[0]
	_ = jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, peer,
		0, 2, jointDPBiomedicalGaussianFullTestSourceShare(t, 2, 1))
}

func TestJointDPBiomedicalGaussianFullStickyRetryRechunkRestart(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 3, 4, t.Name())
	peer := fixture.base.manifest.Contract.DesignatedComputePeers[0]
	fullShare := jointDPBiomedicalGaussianFullTestSourceShare(t, 4, 7)
	full := jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, peer,
		0, 4, fullShare)
	retry := jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, peer,
		0, 4, fullShare)
	fullJSON, _ := json.Marshal(full.output)
	retryJSON, _ := json.Marshal(retry.output)
	if !bytes.Equal(fullJSON, retryJSON) ||
		!bytes.Equal(full.Signature, retry.Signature) {
		t.Fatal("retry rerolled a sticky full-draw share")
	}

	shareBytes, _ := base64.StdEncoding.DecodeString(fullShare)
	firstShare := base64.StdEncoding.EncodeToString(shareBytes[:16])
	secondShare := base64.StdEncoding.EncodeToString(shareBytes[16:])
	first := jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, peer,
		0, 1, firstShare)
	second := jointDPBiomedicalGaussianFullTestRunPeer(
		t, fixture.admission, fixture.base, fixture.roots, peer,
		1, 3, secondShare)
	joined := append(jointDPBiomedicalGaussianFullTestNoisedBytes(t, first),
		jointDPBiomedicalGaussianFullTestNoisedBytes(t, second)...)
	if !bytes.Equal(joined, jointDPBiomedicalGaussianFullTestNoisedBytes(t, full)) {
		t.Fatal("public rechunking changed an absolute-coordinate draw")
	}

	restarted, err := jointDPBiomedicalGaussianAdmitFullSelection(
		jointDPBiomedicalGaussianTestClone(t, fixture.base.manifest),
		jointDPBiomedicalGaussianTestClone(t, fixture.selection), fixture.base.pins)
	if err != nil {
		t.Fatal(err)
	}
	afterRestart := jointDPBiomedicalGaussianFullTestRunPeer(
		t, restarted, fixture.base, fixture.roots, peer, 0, 4, fullShare)
	afterRestartJSON, _ := json.Marshal(afterRestart.output)
	if !bytes.Equal(fullJSON, afterRestartJSON) ||
		!bytes.Equal(full.Signature, afterRestart.Signature) {
		t.Fatal("reconstructed admission rerolled a sticky release")
	}
}

func TestJointDPBiomedicalGaussianFullRootAndPeerRotationRequireNewRelease(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 3, 2, t.Name())
	peer := fixture.base.manifest.Contract.DesignatedComputePeers[0]
	rotatedRoot := sha256.Sum256([]byte("rotated-root"))
	sourceShare := jointDPBiomedicalGaussianFullTestSourceShare(t, 2, 1)
	binding, err := jointDPBiomedicalGaussianBuildFullLocalSourceBinding(
		fixture.admission, fixture.base.pins, peer,
		jointDPBiomedicalGaussianTestHash(peer+"/local-snapshot-contract"),
		jointDPBiomedicalGaussianTestHash(peer+"/local-source-contract"),
		0, 2, sourceShare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jointDPBiomedicalGaussianRunFullPeer(
		fixture.admission, fixture.base.pins, binding, peer, rotatedRoot,
		fixture.base.private[peer], sourceShare); err == nil {
		t.Fatal("rotated root reused the old release instance")
	}
	contract := fixture.selection.Contract
	request := jointDPBiomedicalGaussianFullSelectionRequest{
		LogicalReleaseSHA256:      contract.LogicalReleaseSHA256,
		PrivacyEpochSHA256:        contract.PrivacyEpochSHA256,
		MaterializationRootSHA256: contract.MaterializationRootSHA256,
		ReservationSHA256:         contract.ReservationSHA256,
		Epsilon:                   contract.Epsilon, Delta: contract.Delta,
		NoiseRootEpochs: append([]jointDPBiomedicalGaussianNoiseRootEpoch(nil),
			contract.NoiseRootEpochs...),
		ReceiptReferences: append([]jointDPBiomedicalGaussianReceiptReference(nil),
			contract.ReceiptReferences...),
	}
	rotatedRoots := make(map[string][32]byte, len(fixture.roots))
	for name, root := range fixture.roots {
		rotatedRoots[name] = root
	}
	rotatedRoots[peer] = rotatedRoot
	for index := range request.NoiseRootEpochs {
		if request.NoiseRootEpochs[index].PeerName == peer {
			epoch, err := jointDPBiomedicalGaussianFullNoiseRootEpoch(
				rotatedRoot, peer)
			if err != nil {
				t.Fatal(err)
			}
			request.NoiseRootEpochs[index].EpochSHA256 = epoch
		}
	}
	identity, err := jointDPBiomedicalGaussianFullReleaseIdentityForRequest(
		fixture.base.manifest, fixture.base.pins, request)
	if err != nil {
		t.Fatal(err)
	}
	request.NoiseCommitments = make([]jointDPBiomedicalGaussianFullNoiseCommitment,
		0, 2)
	for _, epoch := range request.NoiseRootEpochs {
		seed, context, commitment, err :=
			jointDPBiomedicalGaussianFullSeedMaterial(
				rotatedRoots[epoch.PeerName], epoch.PeerName, identity)
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
	rotatedContract, err := jointDPBiomedicalGaussianBuildFullSelectionContract(
		fixture.base.manifest, fixture.base.pins, request)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedContract.ReleaseInstanceID ==
		fixture.selection.Contract.ReleaseInstanceID {
		t.Fatal("root epoch rotation did not create a new release instance")
	}
	rotatedSelection := jointDPBiomedicalGaussianFullSelectionAttestation{
		Contract: rotatedContract,
		Signatures: jointDPBiomedicalGaussianFullTestSign(
			t, rotatedContract, fixture.base.private),
	}
	rotatedAdmission, err := jointDPBiomedicalGaussianAdmitFullSelection(
		fixture.base.manifest, rotatedSelection, fixture.base.pins)
	if err != nil {
		t.Fatal(err)
	}
	_ = jointDPBiomedicalGaussianFullTestRunPeer(
		t, rotatedAdmission, fixture.base, rotatedRoots, peer, 0, 2, sourceShare)
	peerRotated := jointDPBiomedicalGaussianFullTestSetup(t, 3, 2, t.Name())
	if peerRotated.base.manifest.Contract.PinsetSHA256 ==
		fixture.base.manifest.Contract.PinsetSHA256 ||
		peerRotated.selection.Contract.ReleaseInstanceID ==
			fixture.selection.Contract.ReleaseInstanceID {
		t.Fatal("pinned-peer rotation did not create a new release instance")
	}
}

func TestJointDPBiomedicalGaussianFullHasNoFreeSensitivityAndNoOpening(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 2, 3, t.Name())
	encoded, err := json.Marshal(fixture.selection.Contract)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte(`"l2_sensitivity_steps"`),
		[]byte(`"sensitivity"`),
		[]byte(`"openings_authorized":1`),
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("selection retained caller-controlled field %s", forbidden)
		}
	}
	if fixture.admission.Certificate.DerivedSensitivitySteps != "2" ||
		fixture.admission.Certificate.OpeningsPerformed != 0 {
		t.Fatalf("unexpected derived certificate: %#v",
			fixture.admission.Certificate)
	}

	peers := fixture.base.manifest.Contract.DesignatedComputePeers
	outputs := make([]jointDPBiomedicalGaussianFullPeerShare, 2)
	for index, peer := range peers {
		outputs[index] = jointDPBiomedicalGaussianFullTestRunPeer(
			t, fixture.admission, fixture.base, fixture.roots, peer,
			0, 3, jointDPBiomedicalGaussianFullTestSourceShare(
				t, 3, byte(1+index*10)))
	}
	handoff, err := jointDPBiomedicalGaussianBuildFullFinalizerHandoff(
		fixture.admission, fixture.base.pins, outputs[0], outputs[1])
	if err != nil {
		t.Fatal(err)
	}
	if handoff.Backend != jointDPGaussianBackend || handoff.OpeningAuthorized ||
		handoff.OpeningsPerformed != 0 || handoff.ProductionReady ||
		!reflect.DeepEqual(handoff.Blockers,
			jointDPBiomedicalGaussianFullFinalizerBlockers) ||
		handoff.finalizerInput.LeftNoisedShare == "" ||
		handoff.finalizerInput.RightNoisedShare == "" {
		t.Fatalf("invalid sealed finalizer handoff: %#v", handoff)
	}
	public, err := json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte(outputs[0].output.NoisedShare)) ||
		bytes.Contains(public, []byte(outputs[1].output.NoisedShare)) {
		t.Fatal("sealed handoff serialized private noised shares")
	}
	peerPublic, err := json.Marshal(outputs[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(peerPublic, []byte(outputs[0].output.NoisedShare)) ||
		bytes.Contains(peerPublic, []byte(outputs[0].OutputSHA256)) ||
		bytes.Contains(peerPublic, []byte(outputs[0].SourceBindingSHA256)) ||
		bytes.Contains(peerPublic, outputs[0].Signature) {
		t.Fatal("peer-share routing JSON exposed its protected payload binding")
	}
	bindingPublic, err := json.Marshal(outputs[0].binding)
	if err != nil || string(bindingPublic) != "{}" {
		t.Fatalf("local source binding became serializable: %s %v",
			bindingPublic, err)
	}
}

func TestJointDPBiomedicalGaussianFullRing128NoWrapMatchesPlan(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 2, 1, t.Name())
	plan := fixture.admission.plan
	maximumNoise, ok := new(big.Int).SetString(
		plan.MaximumNoiseMagnitudeTwoPeers, 10)
	if !ok {
		t.Fatal("invalid maximum noise certificate")
	}
	bound, _ := new(big.Int).SetString(
		fixture.admission.certificate.ShiftedUpperBounds[0], 10)
	if new(big.Int).Add(bound, maximumNoise).Cmp(exactGCMaxSigned(128)) > 0 {
		t.Fatal("admission certified an impossible Ring128 headroom bound")
	}
}

func BenchmarkJointDPBiomedicalGaussianFullValidate8192(b *testing.B) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(b, 3, 8192, b.Name())
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if err := jointDPBiomedicalGaussianValidateFullAdmission(
			fixture.admission, fixture.base.pins); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJointDPBiomedicalGaussianFullValidateCached8192(b *testing.B) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(b, 3, 8192, b.Name())
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
			fixture.admission, fixture.base.pins); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJointDPBiomedicalGaussianFullRunPeer8192(b *testing.B) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(b, 3, 8192, b.Name())
	peer := fixture.base.manifest.Contract.DesignatedComputePeers[0]
	sourceShare := jointDPBiomedicalGaussianFullTestSourceShare(b, 8192, 1)
	binding, err := jointDPBiomedicalGaussianBuildFullLocalSourceBinding(
		fixture.admission, fixture.base.pins, peer,
		jointDPBiomedicalGaussianTestHash(peer+"/local-snapshot-contract"),
		jointDPBiomedicalGaussianTestHash(peer+"/local-source-contract"),
		0, 8192, sourceShare)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := jointDPBiomedicalGaussianRunFullPeer(
			fixture.admission, fixture.base.pins, binding, peer,
			fixture.roots[peer], fixture.base.private[peer], sourceShare); err != nil {
			b.Fatal(err)
		}
	}
}
