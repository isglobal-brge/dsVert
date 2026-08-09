package main

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
)

type jointDPBiomedicalGaussianWorkerTestFixture struct {
	base       jointDPBiomedicalGaussianTestFixture
	trust      jointDPBiomedicalGaussianWorkerTrustRoot
	request    jointDPBiomedicalGaussianWorkerEnvelopeRequest
	envelope   jointDPBiomedicalGaussianSignedWorkerEnvelope
	session    exactGCSession
	source     string
	local      jointDPBiomedicalGaussianLocalSourceBinding
	privateB64 string
}

func jointDPBiomedicalGaussianTestCommonLatticeFixture(t testing.TB,
	custodians, coordinates int, label string,
) jointDPBiomedicalGaussianTestFixture {
	t.Helper()
	fixture := jointDPBiomedicalGaussianTestSetup(
		t, custodians, coordinates, label+"/base")
	manifest := jointDPBiomedicalGaussianTestClone(t, fixture.manifest)
	for index := range manifest.Contract.ScaleShifts {
		manifest.Contract.ScaleShifts[index] = 0
	}
	manifest.Contract.LatticeTransformSHA256 =
		jointDPBiomedicalGaussianTestHash(label + "/common-lattice")
	manifest.Signatures = jointDPBiomedicalGaussianTestSignManifest(
		t, manifest.Contract, fixture.private)
	candidate, err := jointDPBiomedicalGaussianPrepareCandidate(
		manifest, fixture.release, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	signed := jointDPBiomedicalGaussianSignedAdmission{
		Preimage: candidate.preimage,
		Signatures: jointDPBiomedicalGaussianTestSignAdmission(
			t, candidate.preimage, manifest.Contract.CustodianPeers,
			fixture.private),
	}
	admission, err := admitJointDPBiomedicalGaussianOneDraw(
		manifest, fixture.release, fixture.pins, signed)
	var blocker *jointDPBiomedicalGaussianReleaseBlocker
	if !errors.As(err, &blocker) || blocker.OpeningsPerformed != 0 {
		t.Fatalf("expected sealed common-lattice admission: %T %v", err, err)
	}
	fixture.manifest = manifest
	fixture.candidate = candidate
	fixture.signed = signed
	fixture.admission = admission
	return fixture
}

func jointDPBiomedicalGaussianTestReceipts(label string) []jointDPBiomedicalGaussianReceiptReference {
	receipts := make([]jointDPBiomedicalGaussianReceiptReference, 0,
		len(jointDPBiomedicalGaussianRequiredReceiptKinds))
	for _, kind := range jointDPBiomedicalGaussianRequiredReceiptKinds {
		receipts = append(receipts, jointDPBiomedicalGaussianReceiptReference{
			Version: jointDPBiomedicalGaussianReceiptVersion,
			Kind:    kind,
			SHA256: jointDPBiomedicalGaussianTestHash(
				label + "/receipt/" + kind),
			DigestKind: jointDPBiomedicalGaussianReceiptDigestRule,
		})
	}
	return receipts
}

func jointDPBiomedicalGaussianTestTrust(t testing.TB,
	fixture jointDPBiomedicalGaussianTestFixture, implementation string,
) jointDPBiomedicalGaussianWorkerTrustRoot {
	t.Helper()
	peers := make([]jointDPBiomedicalGaussianPinnedPeer, 0, len(fixture.pins))
	for _, name := range fixture.manifest.Contract.CustodianPeers {
		peers = append(peers, jointDPBiomedicalGaussianPinnedPeer{
			Name:             name,
			Ed25519PublicKey: append([]byte(nil), fixture.pins[name]...),
		})
	}
	return jointDPBiomedicalGaussianWorkerTrustRoot{
		Version:                    jointDPBiomedicalGaussianWorkerTrustVersion,
		AllowedRoute:               jointDPBiomedicalGaussianWorkerRoute,
		PinsetSHA256:               fixture.manifest.Contract.PinsetSHA256,
		WorkerImplementationSHA256: implementation,
		PinnedPeers:                peers,
	}
}

func jointDPBiomedicalGaussianTestSignWorkerEnvelope(t testing.TB,
	envelope *jointDPBiomedicalGaussianSignedWorkerEnvelope,
	peers []string, private map[string]ed25519.PrivateKey,
) {
	t.Helper()
	envelope.Signatures = nil
	for _, peer := range peers {
		signature, err := jointDPBiomedicalGaussianSignWorkerEnvelope(
			envelope.Preimage, peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
		envelope.Signatures = append(envelope.Signatures, signature)
	}
}

func jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t testing.TB,
	value jointDPBiomedicalGaussianSignedWorkerEnvelope,
) jointDPBiomedicalGaussianSignedWorkerEnvelope {
	t.Helper()
	result := jointDPBiomedicalGaussianTestClone(t, value)
	result.WorkerPolicy = jointDPBiomedicalGaussianTestClone(t, value.WorkerPolicy)
	return result
}

func jointDPBiomedicalGaussianTestWorkerFixture(t testing.TB,
	custodians, coordinates int, label string,
) jointDPBiomedicalGaussianWorkerTestFixture {
	t.Helper()
	base := jointDPBiomedicalGaussianTestCommonLatticeFixture(
		t, custodians, coordinates, label)
	chunk, err := compileJointDPBiomedicalGaussianChunk(
		base.admission, 0, coordinates)
	if err != nil {
		t.Fatal(err)
	}
	runNonce := jointDPBiomedicalGaussianTestHash(label + "/run-nonce")
	implementation := jointDPBiomedicalGaussianTestHash(label + "/worker-binary")
	request := jointDPBiomedicalGaussianWorkerEnvelopeRequest{
		LogicalSnapshotHandleSHA256: jointDPBiomedicalGaussianTestHash(
			label + "/opaque-snapshot-handle"),
		SourceContractHandleSHA256: jointDPBiomedicalGaussianTestHash(
			label + "/opaque-source-contract-handle"),
		PrivacyEpochSHA256: jointDPBiomedicalGaussianTestHash(label + "/epoch"),
		MaterializationRootSHA256: jointDPBiomedicalGaussianTestHash(
			label + "/opaque-materialization-root"),
		RunNonceSHA256:             runNonce,
		WorkerImplementationSHA256: implementation,
		ReceiptReferences:          jointDPBiomedicalGaussianTestReceipts(label),
	}
	envelope, err := jointDPBiomedicalGaussianBuildWorkerEnvelope(
		base.admission, chunk, request)
	if err != nil {
		t.Fatal(err)
	}
	jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &envelope,
		base.manifest.Contract.CustodianPeers, base.private)
	trust := jointDPBiomedicalGaussianTestTrust(t, base, implementation)
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(envelope, trust)
	if err != nil {
		t.Fatal(err)
	}
	sessionIDBytes, err := hex.DecodeString(runNonce)
	if err != nil || len(sessionIDBytes) != sha256.Size {
		t.Fatal("invalid test run nonce")
	}
	var sessionID [32]byte
	copy(sessionID[:], sessionIDBytes)
	master := sha256.Sum256([]byte(label + "/master"))
	session := exactGCSession{
		SessionID: sessionID, MasterKey: master,
		GarblerID: spec.GarblerPeerID, EvaluatorID: spec.EvaluatorPeerID,
		Purpose: spec.purpose(),
		Spec: exactGCCircuitSpec{
			Operation: jointDPGaussianOneDrawOperation,
			RingBits:  128, FracBits: 0, VectorLen: coordinates,
		},
	}
	shares := make([]*big.Int, coordinates)
	for index := range shares {
		shares[index] = big.NewInt(int64(index + 1))
	}
	source, err := exactGCEncodeWorkerCanonicalShares(shares, session.Spec)
	if err != nil {
		t.Fatal(err)
	}
	local, err := jointDPBiomedicalGaussianBuildLocalSourceBinding(
		envelope.Preimage, base.candidate.preimage.LogicalSnapshotSHA256,
		base.candidate.preimage.SourceContractSHA256,
		envelope.Preimage.GarblerPeerName,
		"garbler", source)
	if err != nil {
		t.Fatal(err)
	}
	return jointDPBiomedicalGaussianWorkerTestFixture{
		base: base, trust: trust, request: request, envelope: envelope,
		session: session, source: source, local: local,
		privateB64: base64.StdEncoding.EncodeToString(base.garblerSeed[:]),
	}
}

func TestJointDPBiomedicalGaussianWorkerEnvelopeK2K3K5UsesLocalTrust(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := jointDPBiomedicalGaussianTestWorkerFixture(
				t, custodians, 3, t.Name())
			spec, seed, err := jointDPBiomedicalGaussianVerifyProductiveWorkerInput(
				fixture.envelope, fixture.trust, fixture.local,
				fixture.session, "garbler", fixture.source, fixture.privateB64)
			defer clear(seed[:])
			if err != nil {
				t.Fatal(err)
			}
			if spec.CoordinateCount != 3 || fixture.envelope.Preimage.ProductionReady ||
				fixture.envelope.Preimage.OpeningsAuthorized != 0 ||
				fixture.envelope.Preimage.GenericMachineProvenAuthorizes ||
				fixture.envelope.Preimage.SourceShareMayBeUnbound ||
				fixture.base.candidate.workerCertificate.Status == "machine_proven" ||
				fixture.base.candidate.workerCertificate.Status !=
					jointDPBiomedicalGaussianWorkerSensitivityStatus ||
				fixture.envelope.Preimage.WorkerTranscriptKind !=
					jointDPBiomedicalGaussianWorkerTranscriptKind {
				t.Fatalf("invalid sealed K=%d worker envelope", custodians)
			}
			encoded, err := json.Marshal(fixture.envelope)
			if err != nil {
				t.Fatal(err)
			}
			fullPolicySHA256, err :=
				jointDPBiomedicalGaussianHash(fixture.envelope.WorkerPolicy)
			if err != nil {
				t.Fatal(err)
			}
			if fullPolicySHA256 ==
				fixture.envelope.Preimage.WorkerPublicPolicySHA256 {
				t.Fatal("public policy projection retained the private full-policy commitment")
			}
			localSpec, err := jointDPGaussianOneDrawPolicySpec(
				fixture.envelope.WorkerPolicy)
			if err != nil {
				t.Fatal(err)
			}
			fullCircuitDigest := localSpec.digest()
			if bytes.Contains(encoded, []byte("ed25519_public_key")) {
				t.Fatal("worker token embedded a caller-substitutable trust root")
			}
			for _, forbidden := range []string{
				`"worker_policy":`, `"release_binding_canonical_json":`,
				`"worker_policy_sha256":`, `"circuit_digest":`, `"worker_purpose":`,
				`"logical_snapshot_sha256":`, `"source_context_sha256":`,
				`"source_contract_sha256":`, `"local_snapshot_contract_sha256":`,
				`"local_source_contract_sha256":`, `"source_share":`, `"private_seed":`,
			} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("relay-visible envelope exposed local field %q", forbidden)
				}
			}
			if fixture.envelope.Preimage.LogicalSnapshotHandleKind !=
				jointDPBiomedicalGaussianOpaqueSnapshotHandle ||
				fixture.envelope.Preimage.MaterializationRootKind !=
					jointDPBiomedicalGaussianOpaqueSourceRoot ||
				fixture.envelope.Preimage.SourceContractHandleKind !=
					jointDPBiomedicalGaussianOpaqueSourceContract ||
				fixture.envelope.Preimage.PublicIdentifierContract !=
					jointDPBiomedicalGaussianPublicIdentifierRule {
				t.Fatal("public snapshot/materialization identifiers lack opaque-handle semantics")
			}
			for name, canary := range map[string]string{
				"snapshot":                   fixture.base.candidate.preimage.LogicalSnapshotSHA256,
				"source-context":             fixture.base.candidate.preimage.SourceContextSHA256,
				"source-contract":            fixture.base.candidate.preimage.SourceContractSHA256,
				"source-share":               fixture.source,
				"private-seed":               fixture.privateB64,
				"release-binding":            fixture.envelope.WorkerPolicy.ReleaseBindingCanonicalJSON,
				"full-policy-digest":         fullPolicySHA256,
				"full-circuit-digest":        hex.EncodeToString(fullCircuitDigest[:]),
				"worker-purpose":             localSpec.purpose(),
				"release-binding-digest":     fixture.envelope.WorkerPolicy.ReleaseBindingSHA256,
				"cross-signed-policy-digest": fixture.envelope.WorkerPolicy.CrossSignedPolicySHA256,
			} {
				if canary != "" && bytes.Contains(encoded, []byte(canary)) {
					t.Fatalf("relay-visible envelope exposed %s canary", name)
				}
			}
			for _, peer := range fixture.trust.PinnedPeers {
				if bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(
					peer.Ed25519PublicKey))) {
					t.Fatal("worker token embedded a pinned public key")
				}
			}
		})
	}
}

func TestJointDPBiomedicalGaussianWorkerEnvelopeRejectsSignaturesAndInjectedPinsK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := jointDPBiomedicalGaussianTestWorkerFixture(
				t, custodians, 1, t.Name())
			omitted := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
			omitted.Signatures = omitted.Signatures[:len(omitted.Signatures)-1]
			if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
				omitted, fixture.trust); err == nil {
				t.Fatal("K-1 signatures were accepted")
			}
			duplicate := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
			duplicate.Signatures[len(duplicate.Signatures)-1] = duplicate.Signatures[0]
			if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
				duplicate, fixture.trust); err == nil {
				t.Fatal("duplicate signatures were accepted")
			}
			foreign := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
			message, err := jointDPBiomedicalGaussianWorkerEnvelopeMessage(
				foreign.Preimage)
			if err != nil {
				t.Fatal(err)
			}
			_, foreignKey, err := ed25519.GenerateKey(crand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			foreign.Signatures[0].Signature = ed25519.Sign(foreignKey, message)
			if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
				foreign, fixture.trust); err == nil {
				t.Fatal("signature by a foreign key was accepted")
			}
			injected := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
			injected.Preimage.PinsetSHA256 =
				jointDPBiomedicalGaussianTestHash(t.Name() + "/attacker-pinset")
			jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &injected,
				fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
			if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
				injected, fixture.trust); err == nil {
				t.Fatal("token-injected pinset replaced local trust")
			}
		})
	}
}

func TestJointDPBiomedicalGaussianWorkerEnvelopeRejectsSourceSwap(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 3, 2, t.Name())
	swapped := exactGCTestEncodeSource(t,
		[]*big.Int{big.NewInt(8), big.NewInt(9)}, fixture.session.Spec)
	if _, seed, err := jointDPBiomedicalGaussianVerifyProductiveWorkerInput(
		fixture.envelope, fixture.trust, fixture.local, fixture.session,
		"garbler", swapped, fixture.privateB64); err == nil {
		clear(seed[:])
		t.Fatal("SourceShare swap retained the local materialization binding")
	}
	changedLocal := fixture.local
	changedLocal.MaterializationRootSHA256 =
		jointDPBiomedicalGaussianTestHash(t.Name() + "/other-materialization")
	changedLocal.BindingSHA256, _ =
		jointDPBiomedicalGaussianLocalSourceBindingSHA256(changedLocal)
	if _, seed, err := jointDPBiomedicalGaussianVerifyProductiveWorkerInput(
		fixture.envelope, fixture.trust, changedLocal, fixture.session,
		"garbler", fixture.source, fixture.privateB64); err == nil {
		clear(seed[:])
		t.Fatal("materialization-root substitution was accepted")
	}
}

func TestJointDPBiomedicalGaussianProductiveRunnerBindsNoiseAndMasks(t *testing.T) {
	if testing.Short() {
		t.Skip("real KOS/GC protocol")
	}
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 2, 1, t.Name())
	evaluatorSource, err := exactGCEncodeWorkerCanonicalShares(
		[]*big.Int{big.NewInt(6)}, fixture.session.Spec)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorLocal, err := jointDPBiomedicalGaussianBuildLocalSourceBinding(
		fixture.envelope.Preimage,
		fixture.base.candidate.preimage.LogicalSnapshotSHA256,
		fixture.base.candidate.preimage.SourceContractSHA256,
		fixture.envelope.Preimage.EvaluatorPeerName,
		"evaluator", evaluatorSource)
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
	gdone, edone := make(chan outcome, 1), make(chan outcome, 1)
	go func() {
		shares, runErr := jointDPBiomedicalGaussianRunProductiveGarbler(
			garbler, fixture.envelope, fixture.trust, fixture.local,
			fixture.session, fixture.source, fixture.privateB64)
		gdone <- outcome{shares, runErr}
	}()
	go func() {
		shares, runErr := jointDPBiomedicalGaussianRunProductiveEvaluator(
			evaluator, fixture.envelope, fixture.trust, evaluatorLocal,
			fixture.session, evaluatorSource,
			base64.StdEncoding.EncodeToString(fixture.base.evaluatorSeed[:]))
		edone <- outcome{shares, runErr}
	}()
	gout, eout := <-gdone, <-edone
	if gout.err != nil || eout.err != nil {
		t.Fatalf("productive GC: garbler=%v evaluator=%v", gout.err, eout.err)
	}
	defer exactGCZeroBigInts(gout.shares)
	defer exactGCZeroBigInts(eout.shares)
	if len(gout.shares) != 2 || len(eout.shares) != 2 ||
		new(big.Int).Xor(gout.shares[1], eout.shares[1]).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("productive GC did not return one valid masked coordinate")
	}
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		fixture.envelope, fixture.trust)
	if err != nil {
		t.Fatal(err)
	}
	gwords, gsigns, err := jointDPBiomedicalGaussianProductivePrivateInputs(
		fixture.base.garblerSeed, spec, "garbler",
		fixture.envelope.Preimage.ProductiveStreamSHA256)
	if err != nil {
		t.Fatal(err)
	}
	ewords, esigns, err := jointDPBiomedicalGaussianProductivePrivateInputs(
		fixture.base.evaluatorSeed, spec, "evaluator",
		fixture.envelope.Preimage.ProductiveStreamSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer exactGCZeroBigInts(gwords)
	defer exactGCZeroBigInts(ewords)
	draw := new(big.Int).Xor(gwords[0], ewords[0])
	magnitude, err := jointDPGaussianOneDrawSelectMagnitude(
		draw, spec.CDFCumulative)
	if err != nil {
		t.Fatal(err)
	}
	if gsigns[0] != esigns[0] {
		magnitude.Neg(magnitude)
	}
	want := new(big.Int).Add(big.NewInt(7), magnitude)
	if want.Sign() < 0 {
		want.SetInt64(0)
	} else if want.Cmp(big.NewInt(10)) > 0 {
		want.SetInt64(10)
	}
	got := exactGCReferenceReconstruct(gout.shares[0], eout.shares[0], 128)
	if got.Cmp(want) != 0 {
		t.Fatalf("productive GC=%s reference=%s", got, want)
	}

	// A second source under the same signed release cannot reach the runner,
	// so y1-y2 cannot cancel one sticky draw to reveal x1-x2.
	swapped := exactGCTestEncodeSource(t,
		[]*big.Int{big.NewInt(2)}, fixture.session.Spec)
	if _, err := jointDPBiomedicalGaussianRunProductiveGarbler(
		nilReadWriter{}, fixture.envelope, fixture.trust, fixture.local,
		fixture.session, swapped, fixture.privateB64); err == nil ||
		!strings.Contains(err.Error(), "swapped SourceShare") {
		t.Fatalf("same-release source cancellation was not rejected: %v", err)
	}
}

func TestJointDPBiomedicalGaussianWorkerEnvelopeRejectsReplayAcrossReleaseSnapshotEpochAndRun(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 3, 1, t.Name())
	for name, mutate := range map[string]func(*jointDPBiomedicalGaussianWorkerEnvelopePreimage){
		"release-instance": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.ReleaseInstanceID = jointDPBiomedicalGaussianTestHash("other release")
		},
		"release-contract": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.ReleaseContractSHA256 = jointDPBiomedicalGaussianTestHash("other release contract")
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
			mutate(&changed.Preimage)
			changed.Preimage.ProductiveStreamSHA256, _ =
				jointDPBiomedicalGaussianProductiveStreamSHA256(changed.Preimage)
			jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &changed,
				fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
			if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
				changed, fixture.trust); err == nil {
				t.Fatalf("K-resigned %s replay escaped the embedded release", name)
			}
		})
	}
	for name, mutate := range map[string]func(*jointDPBiomedicalGaussianWorkerEnvelopePreimage){
		"privacy-epoch": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.PrivacyEpochSHA256 = jointDPBiomedicalGaussianTestHash("other epoch")
		},
		"snapshot-handle": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.LogicalSnapshotHandleSHA256 = jointDPBiomedicalGaussianTestHash("other opaque snapshot handle")
		},
		"source-contract-handle": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.SourceContractHandleSHA256 = jointDPBiomedicalGaussianTestHash("other opaque source contract handle")
		},
		"run-nonce": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.RunNonceSHA256 = jointDPBiomedicalGaussianTestHash("other run")
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
			mutate(&changed.Preimage)
			changed.Preimage.ProductiveStreamSHA256, _ =
				jointDPBiomedicalGaussianProductiveStreamSHA256(changed.Preimage)
			jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &changed,
				fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
			if _, seed, err := jointDPBiomedicalGaussianVerifyProductiveWorkerInput(
				changed, fixture.trust, fixture.local, fixture.session,
				"garbler", fixture.source, fixture.privateB64); err == nil {
				clear(seed[:])
				t.Fatalf("%s replay escaped local epoch/run binding", name)
			}
		})
	}
}

func TestJointDPBiomedicalGaussianWorkerEnvelopeCanonicalRationalsAndLattice(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 3, 2, t.Name())
	for _, epsilon := range []string{"1.0", "1e0", "1/1", "01"} {
		t.Run(strings.ReplaceAll(epsilon, "/", "_"), func(t *testing.T) {
			changed := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
			changed.Preimage.Epsilon = epsilon
			jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &changed,
				fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
			if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
				changed, fixture.trust); err == nil {
				t.Fatalf("non-canonical epsilon %q was accepted", epsilon)
			}
		})
	}
	nonReduced := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
	nonReduced.Preimage.EpsilonNumerator = "2"
	nonReduced.Preimage.EpsilonDenominator = "2"
	jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &nonReduced,
		fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
	if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		nonReduced, fixture.trust); err == nil {
		t.Fatal("non-reduced rational epsilon was accepted")
	}

	factored := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, fixture.envelope)
	factored.WorkerPolicy.ScaleShifts[0] = 1
	raw, ok := new(big.Int).SetString(factored.WorkerPolicy.RawUpperBounds[0], 10)
	if !ok || raw.Bit(0) != 0 {
		t.Fatal("test bound must be even")
	}
	factored.WorkerPolicy.RawUpperBounds[0] = new(big.Int).Rsh(raw, 1).String()
	factoredSpec, err := jointDPGaussianOneDrawPolicySpec(factored.WorkerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	factoredCircuit := factoredSpec.digest()
	factored.WorkerPolicy.CircuitDigest = hex.EncodeToString(factoredCircuit[:])
	factoredShape := factoredSpec.circuitShapeDigest()
	factored.Preimage.CircuitShapeSHA256 = hex.EncodeToString(factoredShape[:])
	factored.Preimage.WorkerPublicPolicySHA256, _ =
		jointDPBiomedicalGaussianPublicWorkerPolicySHA256(
			factored.WorkerPolicy, factored.Preimage.PlanSHA256,
			factored.Preimage.CircuitShapeSHA256)
	factored.Preimage.WorkerContractSHA256, _ =
		jointDPBiomedicalGaussianWorkerContractSHA256(
			factored.Preimage.WorkerPublicPolicySHA256,
			factored.Preimage.PlanSHA256,
			factored.Preimage.CircuitShapeSHA256,
			factored.Preimage.WorkerImplementationSHA256)
	jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &factored,
		fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
	if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		factored, fixture.trust); err == nil {
		t.Fatal("alternate raw/shift factorization was accepted")
	}

	nonCommon := jointDPBiomedicalGaussianTestSetup(t, 3, 2, t.Name()+"/shifted")
	chunk, err := compileJointDPBiomedicalGaussianChunk(nonCommon.admission, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jointDPBiomedicalGaussianBuildWorkerEnvelope(
		nonCommon.admission, chunk, fixture.request); err == nil {
		t.Fatal("non-canonical shifted lattice entered the productive route")
	}
}

func TestJointDPBiomedicalGaussianWorkerEnvelopeChunkingIsStickyAndTyped(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestWorkerFixture(t, 5, 3, t.Name())
	build := func(start, count int) jointDPBiomedicalGaussianSignedWorkerEnvelope {
		chunk, err := compileJointDPBiomedicalGaussianChunk(
			fixture.base.admission, start, count)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := jointDPBiomedicalGaussianBuildWorkerEnvelope(
			fixture.base.admission, chunk, fixture.request)
		if err != nil {
			t.Fatal(err)
		}
		jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &envelope,
			fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
		return envelope
	}
	full := build(0, 3)
	first := build(0, 1)
	second := build(1, 2)
	fullSpec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(full, fixture.trust)
	if err != nil {
		t.Fatal(err)
	}
	firstSpec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(first, fixture.trust)
	if err != nil {
		t.Fatal(err)
	}
	secondSpec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(second, fixture.trust)
	if err != nil {
		t.Fatal(err)
	}
	if fullSpec.globalStreamDigest() != firstSpec.globalStreamDigest() ||
		fullSpec.globalStreamDigest() != secondSpec.globalStreamDigest() {
		t.Fatal("productive envelope made sticky noise depend on chunk geometry")
	}
	if full.Preimage.ProductiveStreamSHA256 !=
		first.Preimage.ProductiveStreamSHA256 ||
		full.Preimage.ProductiveStreamSHA256 !=
			second.Preimage.ProductiveStreamSHA256 {
		t.Fatal("productive stream binding depends on chunk geometry")
	}
	retryRequest := fixture.request
	retryRequest.RunNonceSHA256 =
		jointDPBiomedicalGaussianTestHash(t.Name() + "/retry-session")
	retryChunk, err := compileJointDPBiomedicalGaussianChunk(
		fixture.base.admission, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := jointDPBiomedicalGaussianBuildWorkerEnvelope(
		fixture.base.admission, retryChunk, retryRequest)
	if err != nil {
		t.Fatal(err)
	}
	jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &retry,
		fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
	retrySpec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		retry, fixture.trust)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Preimage.ProductiveStreamSHA256 !=
		full.Preimage.ProductiveStreamSHA256 {
		t.Fatal("retry/reconnect session nonce rerolled productive noise")
	}
	reissuedReceipts := jointDPBiomedicalGaussianTestReceipts(t.Name())
	if !reflect.DeepEqual(reissuedReceipts, fixture.request.ReceiptReferences) {
		t.Fatal("idempotently reissued release reservations changed digest")
	}
	restartRequest := fixture.request
	restartRequest.ReceiptReferences = reissuedReceipts
	restart, err := jointDPBiomedicalGaussianBuildWorkerEnvelope(
		fixture.base.admission, retryChunk, restartRequest)
	if err != nil {
		t.Fatal(err)
	}
	jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &restart,
		fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
	restartSpec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		restart, fixture.trust)
	if err != nil {
		t.Fatal(err)
	}
	if restart.Preimage.ProductiveStreamSHA256 !=
		full.Preimage.ProductiveStreamSHA256 {
		t.Fatal("reconstructing the same logical release rerolled productive noise")
	}
	transportReceipt := fixture.request
	transportReceipt.ReceiptReferences =
		append([]jointDPBiomedicalGaussianReceiptReference(nil),
			fixture.request.ReceiptReferences...)
	transportReceipt.ReceiptReferences[0].Kind = "transport_ack"
	if _, err := jointDPBiomedicalGaussianBuildWorkerEnvelope(
		fixture.base.admission, retryChunk, transportReceipt); err == nil {
		t.Fatal("transport/ACK receipt entered release-stable DP stream state")
	}
	fullWords, fullSigns, err := jointDPBiomedicalGaussianProductivePrivateInputs(
		fixture.base.garblerSeed, fullSpec, "garbler",
		full.Preimage.ProductiveStreamSHA256)
	if err != nil {
		t.Fatal(err)
	}
	firstWords, firstSigns, err := jointDPBiomedicalGaussianProductivePrivateInputs(
		fixture.base.garblerSeed, firstSpec, "garbler",
		first.Preimage.ProductiveStreamSHA256)
	if err != nil {
		t.Fatal(err)
	}
	secondWords, secondSigns, err := jointDPBiomedicalGaussianProductivePrivateInputs(
		fixture.base.garblerSeed, secondSpec, "garbler",
		second.Preimage.ProductiveStreamSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer exactGCZeroBigInts(fullWords)
	defer exactGCZeroBigInts(firstWords)
	defer exactGCZeroBigInts(secondWords)
	joinedWords := append(firstWords, secondWords...)
	joinedSigns := append(firstSigns, secondSigns...)
	for index := range fullWords {
		if fullWords[index].Cmp(joinedWords[index]) != 0 ||
			fullSigns[index] != joinedSigns[index] {
			t.Fatalf("productive absolute coordinate %d rerolled after rechunking", index)
		}
	}
	fullStream, _ := jointDPGaussianOneDrawDecodeHex(
		full.Preimage.ProductiveStreamSHA256, "test productive stream")
	firstStream, _ := jointDPGaussianOneDrawDecodeHex(
		first.Preimage.ProductiveStreamSHA256, "test productive stream")
	secondStream, _ := jointDPGaussianOneDrawDecodeHex(
		second.Preimage.ProductiveStreamSHA256, "test productive stream")
	fullMasks, fullValidityMask := jointDPGaussianOneDrawDeterministicMasksBound(
		fixture.base.garblerSeed, fullSpec, &fullStream)
	firstMasks, _ := jointDPGaussianOneDrawDeterministicMasksBound(
		fixture.base.garblerSeed, firstSpec, &firstStream)
	secondMasks, _ := jointDPGaussianOneDrawDeterministicMasksBound(
		fixture.base.garblerSeed, secondSpec, &secondStream)
	defer exactGCZeroBigInts(fullMasks)
	defer exactGCZeroBigInts(firstMasks)
	defer exactGCZeroBigInts(secondMasks)
	joinedMasks := append(firstMasks, secondMasks...)
	for index := range fullMasks {
		if fullMasks[index].Cmp(joinedMasks[index]) != 0 {
			t.Fatalf("productive output mask %d changed after rechunking", index)
		}
	}
	fullValidityMaterial := jointDPGaussianOneDrawValidityMaskMaterial(
		fixture.base.garblerSeed, fullSpec, fullStream)
	firstValidityMaterial := jointDPGaussianOneDrawValidityMaskMaterial(
		fixture.base.garblerSeed, firstSpec, firstStream)
	secondValidityMaterial := jointDPGaussianOneDrawValidityMaskMaterial(
		fixture.base.garblerSeed, secondSpec, secondStream)
	if bytes.Equal(fullValidityMaterial[:], firstValidityMaterial[:]) ||
		bytes.Equal(fullValidityMaterial[:], secondValidityMaterial[:]) ||
		bytes.Equal(firstValidityMaterial[:], secondValidityMaterial[:]) {
		t.Fatal("productive validity controls were not domain-separated by chunk")
	}
	retryStream, _ := jointDPGaussianOneDrawDecodeHex(
		retry.Preimage.ProductiveStreamSHA256, "test productive stream")
	retryMasks, retryValidityMask := jointDPGaussianOneDrawDeterministicMasksBound(
		fixture.base.garblerSeed, retrySpec, &retryStream)
	defer exactGCZeroBigInts(retryMasks)
	if !reflect.DeepEqual(retryMasks, fullMasks) ||
		retryValidityMask != fullValidityMask {
		t.Fatal("retry/reconnect changed productive output masks")
	}
	restartWords, restartSigns, err :=
		jointDPBiomedicalGaussianProductivePrivateInputs(
			fixture.base.garblerSeed, restartSpec, "garbler",
			restart.Preimage.ProductiveStreamSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer exactGCZeroBigInts(restartWords)
	if !reflect.DeepEqual(restartWords, fullWords) ||
		!reflect.DeepEqual(restartSigns, fullSigns) {
		t.Fatal("crash/restart reconstruction changed productive sampler inputs")
	}
	restartStream, _ := jointDPGaussianOneDrawDecodeHex(
		restart.Preimage.ProductiveStreamSHA256, "test productive stream")
	restartMasks, restartValidityMask :=
		jointDPGaussianOneDrawDeterministicMasksBound(
			fixture.base.garblerSeed, restartSpec, &restartStream)
	defer exactGCZeroBigInts(restartMasks)
	if !reflect.DeepEqual(restartMasks, fullMasks) ||
		restartValidityMask != fullValidityMask {
		t.Fatal("crash/restart reconstruction changed productive masks")
	}

	// A materialization-root replacement under the same release cannot pass
	// the already-authoritative local handoff. Durable cross-restart
	// memoization is an explicit production blocker; a legitimate rotation is
	// represented by a new, composition-accounted release instance.
	sameReleaseOtherRoot := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, full)
	sameReleaseOtherRoot.Preimage.MaterializationRootSHA256 =
		jointDPBiomedicalGaussianTestHash(t.Name() + "/invalid-same-release-root")
	sameReleaseOtherRoot.Preimage.ProductiveStreamSHA256, _ =
		jointDPBiomedicalGaussianProductiveStreamSHA256(
			sameReleaseOtherRoot.Preimage)
	jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &sameReleaseOtherRoot,
		fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
	if _, seed, verifyErr := jointDPBiomedicalGaussianVerifyProductiveWorkerInput(
		sameReleaseOtherRoot, fixture.trust, fixture.local, fixture.session,
		"garbler", fixture.source, fixture.privateB64); verifyErr == nil {
		clear(seed[:])
		t.Fatal("same-release materialization-root replacement escaped local handoff")
	}
	rotatedRelease := full.Preimage
	rotatedRelease.ReleaseInstanceID =
		jointDPBiomedicalGaussianTestHash(t.Name() + "/new-release-instance")
	rotatedRelease.MaterializationRootSHA256 =
		jointDPBiomedicalGaussianTestHash(t.Name() + "/new-release-root")
	rotatedReleaseStream, err :=
		jointDPBiomedicalGaussianProductiveStreamSHA256(rotatedRelease)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedReleaseStream ==
		full.Preimage.ProductiveStreamSHA256 {
		t.Fatal("new release instance reused a productive stream")
	}
	otherWords, otherSigns, err := jointDPBiomedicalGaussianProductivePrivateInputs(
		fixture.base.garblerSeed, fullSpec, "garbler",
		rotatedReleaseStream)
	if err != nil {
		t.Fatal(err)
	}
	defer exactGCZeroBigInts(otherWords)
	if otherWords[0].Cmp(fullWords[0]) == 0 &&
		otherSigns[0] == fullSigns[0] {
		t.Fatal("different source/materialization roots reused the first productive draw")
	}
	otherStream, _ := jointDPGaussianOneDrawDecodeHex(
		rotatedReleaseStream, "test productive stream")
	otherMasks, otherValidityMask := jointDPGaussianOneDrawDeterministicMasksBound(
		fixture.base.garblerSeed, fullSpec, &otherStream)
	defer exactGCZeroBigInts(otherMasks)
	if otherMasks[0].Cmp(fullMasks[0]) == 0 &&
		otherValidityMask == fullValidityMask {
		t.Fatal("different source/materialization roots reused productive masks")
	}
	for name, mutate := range map[string]func(*jointDPBiomedicalGaussianWorkerEnvelopePreimage){
		"release-instance": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.ReleaseInstanceID = jointDPBiomedicalGaussianTestHash("stream/other-release")
		},
		"source-contract-handle": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.SourceContractHandleSHA256 = jointDPBiomedicalGaussianTestHash("stream/other-source-root")
		},
		"privacy-epoch": func(value *jointDPBiomedicalGaussianWorkerEnvelopePreimage) {
			value.PrivacyEpochSHA256 = jointDPBiomedicalGaussianTestHash("stream/other-epoch")
		},
	} {
		changed := full.Preimage
		mutate(&changed)
		stream, err := jointDPBiomedicalGaussianProductiveStreamSHA256(changed)
		if err != nil {
			t.Fatal(err)
		}
		if stream == full.Preimage.ProductiveStreamSHA256 {
			t.Fatalf("%s change reused a productive stream", name)
		}
	}

	typeConfused := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, full)
	typeConfused.Preimage.SensitivityAuthority = "machine_proven"
	typeConfused.Preimage.GenericMachineProvenAuthorizes = true
	jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &typeConfused,
		fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
	if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		typeConfused, fixture.trust); err == nil {
		t.Fatal("generic machine_proven authority entered the biomedical route")
	}

	wrongReceipt := jointDPBiomedicalGaussianTestCloneWorkerEnvelope(t, full)
	wrongReceipt.Preimage.ReceiptReferences[0].Kind =
		jointDPBiomedicalGaussianReceiptMaterialization
	jointDPBiomedicalGaussianTestSignWorkerEnvelope(t, &wrongReceipt,
		fixture.base.manifest.Contract.CustodianPeers, fixture.base.private)
	if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		wrongReceipt, fixture.trust); err == nil {
		t.Fatal("receipt type confusion was accepted")
	}

	if !reflect.DeepEqual(full.Preimage.CommonLatticeUpperBounds,
		first.Preimage.CommonLatticeUpperBounds) ||
		!reflect.DeepEqual(full.Preimage.CommonLatticeUpperBounds,
			second.Preimage.CommonLatticeUpperBounds) {
		t.Fatal("chunks did not bind the same full common-lattice capsule")
	}
}
