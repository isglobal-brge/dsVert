package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/rand"
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type formalCoxRuntimeTestFixture struct {
	policy     formalCoxPhase1Policy
	pins       map[string]ed25519.PublicKey
	private    map[string]ed25519.PrivateKey
	noiseSeeds map[string][32]byte
	request    formalCoxRuntimeAdmissionRequest
	admission  formalCoxRuntimeAdmission
}

func formalCoxRuntimeTestHash(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func formalCoxRuntimeTestReceipts(label string) []jointDPBiomedicalGaussianReceiptReference {
	result := make([]jointDPBiomedicalGaussianReceiptReference,
		len(jointDPBiomedicalGaussianRequiredReceiptKinds))
	for index, kind := range jointDPBiomedicalGaussianRequiredReceiptKinds {
		result[index] = jointDPBiomedicalGaussianReceiptReference{
			Version:    jointDPBiomedicalGaussianReceiptVersion,
			Kind:       kind,
			SHA256:     formalCoxRuntimeTestHash(label + "/receipt/" + kind),
			DigestKind: jointDPBiomedicalGaussianReceiptDigestRule,
		}
	}
	return result
}

func formalCoxRuntimeTestLedgerTokens(t testing.TB,
	policy formalCoxPhase1Policy, private map[string]ed25519.PrivateKey,
	commitments map[string]string, label string,
) []formalCoxRuntimeLedgerOpeningToken {
	t.Helper()
	common := formalCoxRuntimeLedgerOpeningToken{
		Version:      formalCoxRuntimeLedgerTokenVersion,
		Phase:        formalCoxRuntimeLedgerTokenPhase,
		ConsortiumID: "jdpc1_" + formalCoxRuntimeTestHash(label+"/consortium"),
		CapsuleID:    policy.CapsuleSHA256, QueryID: policy.CapsuleSHA256,
		AllocationIndex:      "0",
		NewChain:             formalCoxRuntimeTestHash(label + "/new-chain"),
		JointRecordHash:      formalCoxRuntimeTestHash(label + "/joint-record"),
		AuthorizationSetHash: formalCoxRuntimeTestHash(label + "/authorization-set"),
		ReleaseScope:         formalCoxRuntimeLedgerScope, CapabilityAvailable: false,
	}
	tokens := make([]formalCoxRuntimeLedgerOpeningToken, 0, 2)
	for _, peer := range policy.ComputePeers {
		token := common
		token.PeerName = peer
		token.PeerIdentityPK = base64.RawURLEncoding.EncodeToString(
			private[peer].Public().(ed25519.PublicKey))
		token.SeedCommitment = commitments[peer]
		message, err := formalCoxRuntimeLedgerTokenMessage(token)
		if err != nil {
			t.Fatal(err)
		}
		token.Signature = base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(private[peer], message))
		tokens = append(tokens, token)
	}
	return tokens
}

func formalCoxRuntimeTestResignLedgerToken(t testing.TB,
	token *formalCoxRuntimeLedgerOpeningToken, signer ed25519.PrivateKey,
) {
	t.Helper()
	token.Signature = ""
	message, err := formalCoxRuntimeLedgerTokenMessage(*token)
	if err != nil {
		t.Fatal(err)
	}
	token.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(signer, message))
}

func formalCoxRuntimeTestFixtureForK(t testing.TB, custodians int,
	label string) formalCoxRuntimeTestFixture {
	t.Helper()
	policy := formalCoxTestPolicy(t, custodians)
	policy.XLower = []string{"-16"}
	policy.XUpper = []string{"16"}
	policy.CovariateL2Bound = "16"
	pins := make(map[string]ed25519.PublicKey, custodians)
	private := make(map[string]ed25519.PrivateKey, custodians)
	for _, peer := range policy.CustodianPeers {
		seed := sha256.Sum256([]byte(label + "/signing/" + peer))
		key := ed25519.NewKeyFromSeed(seed[:])
		private[peer] = key
		pins[peer] = append(ed25519.PublicKey(nil), key.Public().(ed25519.PublicKey)...)
	}
	policy.PinsetSHA256, _ = formalGLMPhase16PinsetSHA256(pins)
	type computeRole struct{ name, id string }
	compute := make([]computeRole, 2)
	for index, name := range policy.ComputePeers {
		compute[index].name = name
		compute[index].id, _ = formalGLMPhase16PeerID(pins[name])
	}
	sort.Slice(compute, func(i, j int) bool { return compute[i].id < compute[j].id })
	policy.ComputePeers = []string{compute[0].name, compute[1].name}
	initial, err := planFormalCoxDP(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.NoiseBound = initial.MaximumNoiseMagnitude
	policy.NoiseChunkCount = initial.SamplerChunkCount
	authority := formalCoxRuntimeAuthority{
		ManifestSHA256:              formalCoxRuntimeTestHash(label + "/manifest"),
		SchemaManifestSHA256:        formalCoxRuntimeTestHash(label + "/schema"),
		WorkloadSHA256:              formalCoxRuntimeTestHash(label + "/workload"),
		SourceFanInTranscriptSHA256: formalCoxRuntimeTestHash(label + "/source-fanin"),
		ReleaseInstanceID:           formalCoxRuntimeTestHash(label + "/release-instance"),
		ReleaseContractSHA256:       formalCoxRuntimeTestHash(label + "/release-contract"),
	}
	transcriptBytes, _ := hex.DecodeString(authority.ReleaseContractSHA256)
	var transcript [32]byte
	copy(transcript[:], transcriptBytes)
	noiseSeeds := make(map[string][32]byte, 2)
	commitments := make(map[string]string, 2)
	for index, role := range []struct{ name, id, role string }{
		{compute[0].name, compute[0].id, "garbler"},
		{compute[1].name, compute[1].id, "evaluator"},
	} {
		seed := sha256.Sum256([]byte(label + "/noise-seed/" + role.name))
		noiseSeeds[role.name] = seed
		context := jointDPCommitmentContext(transcript,
			jointDPGaussianOneDrawCommitmentPurpose+"/"+role.role, role.id)
		commitment := jointDPSeedCommitment(context, seed)
		commitments[role.name] = hex.EncodeToString(commitment[:])
		_ = index
	}
	ledgerTokens := formalCoxRuntimeTestLedgerTokens(
		t, policy, private, commitments, label)
	receipts := formalCoxRuntimeTestReceipts(label)
	ledgerSHA256, err := formalCoxRuntimeLedgerTokenSetSHA256(ledgerTokens)
	if err != nil {
		t.Fatal(err)
	}
	for index := range receipts {
		if receipts[index].Kind == jointDPBiomedicalGaussianReceiptPrivacyLedger {
			receipts[index].SHA256 = ledgerSHA256
		}
	}
	request := formalCoxRuntimeAdmissionRequest{
		Authority:                   authority,
		LogicalSnapshotHandleSHA256: formalCoxRuntimeTestHash(label + "/opaque-snapshot"),
		PrivacyEpochSHA256:          formalCoxRuntimeTestHash(label + "/epoch"),
		MaterializationRootSHA256:   formalCoxRuntimeTestHash(label + "/materialization"),
		SourceContractHandleSHA256:  formalCoxRuntimeTestHash(label + "/source-handle"),
		RunNonceSHA256:              formalCoxRuntimeTestHash(label + "/run-nonce"),
		WorkerImplementationSHA256:  formalCoxRuntimeTestHash(label + "/worker"),
		NoiseSeedCommitmentsByPeer:  commitments,
		LedgerOpeningTokens:         ledgerTokens,
		ReceiptReferences:           receipts,
	}
	admission, err := buildFormalCoxRuntimeAdmission(policy, pins, request)
	if err != nil {
		t.Fatal(err)
	}
	return formalCoxRuntimeTestFixture{
		policy: policy, pins: pins, private: private, noiseSeeds: noiseSeeds,
		request: request, admission: admission,
	}
}

func formalCoxRuntimeTestSignEnvelopes(t testing.TB,
	fixture *formalCoxRuntimeTestFixture) {
	t.Helper()
	for index := range fixture.admission.Envelopes {
		envelope := &fixture.admission.Envelopes[index]
		for _, peer := range fixture.policy.CustodianPeers {
			signature, err := jointDPBiomedicalGaussianSignWorkerEnvelope(
				envelope.Preimage, peer, fixture.private[peer])
			if err != nil {
				t.Fatal(err)
			}
			envelope.Signatures = append(envelope.Signatures, signature)
		}
	}
}

func TestFormalCoxRuntimeAdmissionK2K3K4K5UsesOneCommonControlPlane(t *testing.T) {
	for _, custodians := range []int{2, 3, 4, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalCoxRuntimeTestFixtureForK(
				t, custodians, t.Name())
			formalCoxRuntimeTestSignEnvelopes(t, &fixture)
			admission := fixture.admission
			if admission.Version != formalCoxRuntimeAdmissionVersion ||
				admission.DPPlan.NoiseCoordinates !=
					fixture.policy.Iterations*fixture.policy.CovariateCount ||
				len(admission.Envelopes) != fixture.policy.NoiseChunkCount ||
				!admission.CommonLedgerVerified || admission.RuntimeNoiseConnected ||
				admission.DurableOpeningConnected ||
				admission.ProductionReady || len(admission.Blockers) == 0 {
				t.Fatalf("dishonest K=%d runtime admission: %+v", custodians, admission)
			}
			for _, envelope := range admission.Envelopes {
				if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
					envelope, admission.Trust); err != nil {
					t.Fatalf("K=%d envelope: %v", custodians, err)
				}
				encoded, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range [][]byte{
					[]byte(formalCoxRuntimeReleaseDomain),
					[]byte(admission.BindingCanonicalJSON),
					[]byte(`"worker_policy"`),
				} {
					if len(forbidden) != 0 && bytes.Contains(encoded, forbidden) {
						t.Fatal("relay-visible envelope exposed local Cox authority")
					}
				}
			}
			maximum, _ := new(big.Int).SetString(admission.DPPlan.MaximumNoiseMagnitude, 10)
			upper, _ := new(big.Int).SetString(admission.CommonUpperBound, 10)
			if maximum == nil || upper == nil ||
				upper.Cmp(new(big.Int).Mul(big.NewInt(2), maximum)) < 0 {
				t.Fatal("common carrier cannot hold the full finite support")
			}
		})
	}
}

func TestFormalCoxRuntimeVerifiesRealCommonLedgerOpeningTokens(t *testing.T) {
	fixture := formalCoxRuntimeTestFixtureForK(t, 3, t.Name())
	base := fixture.request

	badSignature := base
	badSignature.LedgerOpeningTokens = append(
		[]formalCoxRuntimeLedgerOpeningToken(nil), base.LedgerOpeningTokens...)
	badSignature.LedgerOpeningTokens[0].Signature =
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := buildFormalCoxRuntimeAdmission(
		fixture.policy, fixture.pins, badSignature); err == nil {
		t.Fatal("forged common-ledger signature was accepted")
	}

	conflictingAllocation := base
	conflictingAllocation.LedgerOpeningTokens = append(
		[]formalCoxRuntimeLedgerOpeningToken(nil), base.LedgerOpeningTokens...)
	conflictingAllocation.LedgerOpeningTokens[0].AllocationIndex = "1"
	peer := conflictingAllocation.LedgerOpeningTokens[0].PeerName
	formalCoxRuntimeTestResignLedgerToken(t,
		&conflictingAllocation.LedgerOpeningTokens[0], fixture.private[peer])
	if _, err := buildFormalCoxRuntimeAdmission(
		fixture.policy, fixture.pins, conflictingAllocation); err == nil {
		t.Fatal("two valid signatures for different ledger allocations were accepted")
	}

	wrongSeed := base
	wrongSeed.LedgerOpeningTokens = append(
		[]formalCoxRuntimeLedgerOpeningToken(nil), base.LedgerOpeningTokens...)
	wrongSeed.LedgerOpeningTokens[0].SeedCommitment =
		formalCoxRuntimeTestHash(t.Name() + "/wrong-seed")
	peer = wrongSeed.LedgerOpeningTokens[0].PeerName
	formalCoxRuntimeTestResignLedgerToken(
		t, &wrongSeed.LedgerOpeningTokens[0], fixture.private[peer])
	if _, err := buildFormalCoxRuntimeAdmission(
		fixture.policy, fixture.pins, wrongSeed); err == nil {
		t.Fatal("ledger allocation detached from the productive sampler seed was accepted")
	}

	staleReference := base
	staleReference.LedgerOpeningTokens = append(
		[]formalCoxRuntimeLedgerOpeningToken(nil), base.LedgerOpeningTokens...)
	staleReference.LedgerOpeningTokens[0].NewChain =
		formalCoxRuntimeTestHash(t.Name() + "/new-valid-chain")
	staleReference.LedgerOpeningTokens[1].NewChain =
		staleReference.LedgerOpeningTokens[0].NewChain
	for index := range staleReference.LedgerOpeningTokens {
		peer = staleReference.LedgerOpeningTokens[index].PeerName
		formalCoxRuntimeTestResignLedgerToken(t,
			&staleReference.LedgerOpeningTokens[index], fixture.private[peer])
	}
	if _, err := buildFormalCoxRuntimeAdmission(
		fixture.policy, fixture.pins, staleReference); err == nil {
		t.Fatal("valid replacement tokens with a stale ledger receipt digest were accepted")
	}
}

func TestFormalCoxRuntimeLedgerMessageMatchesRCanonicalContract(t *testing.T) {
	token := formalCoxRuntimeLedgerOpeningToken{
		Version:      formalCoxRuntimeLedgerTokenVersion,
		Phase:        formalCoxRuntimeLedgerTokenPhase,
		ConsortiumID: "jdpc1_" + strings.Repeat("1", 64),
		PeerName:     "site1", PeerIdentityPK: "pk", CapsuleID: strings.Repeat("2", 64),
		QueryID: strings.Repeat("2", 64), AllocationIndex: "0",
		NewChain: strings.Repeat("3", 64), JointRecordHash: strings.Repeat("4", 64),
		AuthorizationSetHash: strings.Repeat("5", 64),
		SeedCommitment:       strings.Repeat("6", 64),
		ReleaseScope:         formalCoxRuntimeLedgerScope, CapabilityAvailable: false,
	}
	message, err := formalCoxRuntimeLedgerTokenMessage(token)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"allocation_index":"0","authorization_set_hash":"` +
		strings.Repeat("5", 64) + `","capability_available":false,"capsule_id":"` +
		strings.Repeat("2", 64) + `","consortium_id":"jdpc1_` +
		strings.Repeat("1", 64) + `","joint_record_hash":"` +
		strings.Repeat("4", 64) + `","new_chain":"` + strings.Repeat("3", 64) +
		`","peer_identity_pk":"pk","peer_name":"site1","phase":"open_authorized",` +
		`"query_id":"` + strings.Repeat("2", 64) +
		`","release_scope":"joint_mpc_single_opening","seed_commitment":"` +
		strings.Repeat("6", 64) + `","version":"dsvert-joint-dp-opening-token-v1"}`
	if string(message) != formalCoxRuntimeLedgerMessageDomain+wantJSON {
		t.Fatalf("Go/R ledger signature preimages differ:\n%s", message)
	}
}

func TestFormalCoxRuntimeAdmissionRejectsRolePinAndBindingSubstitution(t *testing.T) {
	fixture := formalCoxRuntimeTestFixtureForK(t, 3, t.Name())
	wrongOrder := fixture.policy
	wrongOrder.ComputePeers = []string{
		fixture.policy.ComputePeers[1], fixture.policy.ComputePeers[0]}
	if _, err := buildFormalCoxRuntimeAdmission(
		wrongOrder, fixture.pins, fixture.request); err == nil {
		t.Fatal("non-canonical pinned compute roles were accepted")
	}
	wrongPinset := fixture.policy
	wrongPinset.PinsetSHA256 = formalCoxRuntimeTestHash(t.Name() + "/wrong-pinset")
	if _, err := buildFormalCoxRuntimeAdmission(
		wrongPinset, fixture.pins, fixture.request); err == nil {
		t.Fatal("caller-substituted pinset was accepted")
	}
	missingLedger := fixture.request
	missingLedger.ReceiptReferences = nil
	for _, receipt := range fixture.request.ReceiptReferences {
		if receipt.Kind != jointDPBiomedicalGaussianReceiptPrivacyLedger {
			missingLedger.ReceiptReferences = append(
				missingLedger.ReceiptReferences, receipt)
		}
	}
	if _, err := buildFormalCoxRuntimeAdmission(
		fixture.policy, fixture.pins, missingLedger); err == nil {
		t.Fatal("envelope was built before the common ledger/finalizer receipts")
	}
	formalCoxRuntimeTestSignEnvelopes(t, &fixture)
	tampered := fixture.admission.Envelopes[0]
	tampered.WorkerPolicy.ReleaseBindingCanonicalJSON += " "
	if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		tampered, fixture.admission.Trust); err == nil {
		t.Fatal("tampered Cox release binding was accepted")
	}
}

func TestFormalCoxRuntimeNumericCertificateSeparatesExactArithmeticFromInference(t *testing.T) {
	fixture := formalCoxRuntimeTestFixtureForK(t, 3, t.Name())
	certificate := fixture.admission.NumericCertificate
	if !certificate.DeterministicNoWrapCertified ||
		!certificate.FiniteNoiseNoWrapCertified ||
		!certificate.ExpTableOutwardCertified ||
		!certificate.CircuitMatchesBigIntLatticeOracle ||
		certificate.CircuitVsLatticeOracleErrorSteps != "0" ||
		certificate.ContinuousCoxTrajectoryCertified ||
		certificate.OptimizerDistanceCertified ||
		certificate.IdentificationCertified ||
		certificate.EndToEndNumericCertified || certificate.ProductionReady ||
		len(certificate.Blockers) < 3 {
		t.Fatalf("numeric certificate over- or understates the unpenalized route: %+v",
			certificate)
	}
	if digest, err := formalCoxRuntimeNumericCertificateSHA256(certificate); err != nil || digest != fixture.admission.NumericCertificateSHA256 ||
		digest != fixture.admission.Binding.NumericCertificateSHA256 {
		t.Fatalf("numeric certificate is not release-bound: %s %v", digest, err)
	}

	ridge := fixture.policy
	ridge.Ridge = "1"
	ridgePlan, err := planFormalCoxPhase1(ridge)
	if err != nil {
		t.Fatal(err)
	}
	ridgeCertificate, err := formalCoxRuntimeNumericCertificateForPolicy(
		ridge, ridgePlan)
	if err != nil {
		t.Fatal(err)
	}
	if !ridgeCertificate.IdentificationCertified ||
		ridgeCertificate.DataDependentIdentificationOpened ||
		ridgeCertificate.EndToEndNumericCertified ||
		ridgeCertificate.IdentificationRoute !=
			"public_positive_ridge_strongly_identifies_bounded_penalized_target_v1" {
		t.Fatalf("positive public ridge did not produce the honest identification route: %+v",
			ridgeCertificate)
	}

	overstated := certificate
	overstated.EndToEndNumericCertified = true
	if err := formalCoxRuntimeValidateNumericCertificate(
		fixture.policy, fixture.admission.Phase1Plan, overstated); err == nil {
		t.Fatal("overstated end-to-end numeric certificate was accepted")
	}
	malformedScale := certificate
	scale, ok := new(big.Int).SetString(certificate.Scale, 10)
	if !ok {
		t.Fatal("fixture certificate has an invalid scale")
	}
	malformedScale.Scale = new(big.Int).Mul(scale, big.NewInt(3)).String()
	malformedScale.ExpAbsoluteErrorUpperDenominator = malformedScale.Scale
	if err := formalCoxRuntimeValidateNumericCertificate(
		fixture.policy, fixture.admission.Phase1Plan, malformedScale); err == nil {
		t.Fatal("non-power-of-two fixed-point scale was accepted")
	}
	workerPolicy := fixture.admission.Envelopes[0].WorkerPolicy
	binding := fixture.admission.Binding
	binding.NumericCertificate.EndToEndNumericCertified = true
	binding.NumericCertificateSHA256, _ =
		formalCoxRuntimeNumericCertificateSHA256(binding.NumericCertificate)
	canonical, _ := formalCoxRuntimeReleaseBindingPreimage(binding)
	digest, _ := formalCoxRuntimeReleaseBindingDigest(binding)
	workerPolicy.ReleaseBindingCanonicalJSON = string(canonical)
	workerPolicy.ReleaseBindingSHA256 = digest
	workerPolicy.CrossSignedPolicySHA256 = digest
	if err := formalCoxValidateRuntimeReleaseBinding(workerPolicy); err == nil {
		t.Fatal("rehash of an overstated numeric certificate was accepted")
	}
}

func TestFormalCoxRuntimeStickyNoiseDoesNotRerollAcrossFreshRunNonce(t *testing.T) {
	fixture := formalCoxRuntimeTestFixtureForK(t, 3, t.Name())
	formalCoxRuntimeTestSignEnvelopes(t, &fixture)
	retryRequest := fixture.request
	retryRequest.RunNonceSHA256 = formalCoxRuntimeTestHash(t.Name() + "/retry-run-nonce")
	retry, err := buildFormalCoxRuntimeAdmission(
		fixture.policy, fixture.pins, retryRequest)
	if err != nil {
		t.Fatal(err)
	}
	retryFixture := fixture
	retryFixture.request = retryRequest
	retryFixture.admission = retry
	formalCoxRuntimeTestSignEnvelopes(t, &retryFixture)
	if len(retry.Envelopes) != len(fixture.admission.Envelopes) {
		t.Fatal("retry changed the fixed sampler schedule")
	}
	for index := range retry.Envelopes {
		first, second := fixture.admission.Envelopes[index], retry.Envelopes[index]
		if first.Preimage.RunNonceSHA256 == second.Preimage.RunNonceSHA256 ||
			first.Preimage.ProductiveStreamSHA256 !=
				second.Preimage.ProductiveStreamSHA256 {
			t.Fatal("retry nonce either repeated or rerolled the productive stream")
		}
		firstSpec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
			first, fixture.admission.Trust)
		if err != nil {
			t.Fatal(err)
		}
		secondSpec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
			second, retry.Trust)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []struct {
			name string
			role string
		}{
			{fixture.admission.Roles.GarblerPeerName, "garbler"},
			{fixture.admission.Roles.EvaluatorPeerName, "evaluator"},
		} {
			seed := fixture.noiseSeeds[role.name]
			firstWords, firstSigns, err :=
				jointDPBiomedicalGaussianProductivePrivateInputs(
					seed, firstSpec, role.role,
					first.Preimage.ProductiveStreamSHA256)
			if err != nil {
				t.Fatal(err)
			}
			secondWords, secondSigns, err :=
				jointDPBiomedicalGaussianProductivePrivateInputs(
					seed, secondSpec, role.role,
					second.Preimage.ProductiveStreamSHA256)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(firstWords, secondWords) ||
				!reflect.DeepEqual(firstSigns, secondSigns) {
				t.Fatal("fresh transport nonce rerolled sticky Cox noise")
			}
			exactGCZeroBigInts(firstWords)
			exactGCZeroBigInts(secondWords)
		}
	}
}

func TestFormalCoxRuntimeFinalCarrierReducesDynamicRingSharesExactly(t *testing.T) {
	ringBits := 256
	shift := big.NewInt(256)
	beta := big.NewInt(-128)
	betaResidue := formalCoxResidue(beta, ringBits)
	garblerShare := new(big.Int).Add(
		new(big.Int).Lsh(big.NewInt(1), 200), big.NewInt(987654321))
	evaluatorShare := new(big.Int).Sub(betaResidue, garblerShare)
	evaluatorShare.Mod(evaluatorShare, exactGCModulus(ringBits))
	garbler, err := formalCoxRuntimeFinalCarrierShares(
		"garbler", formalCoxSealedOutput{
			CoefficientShares: []*big.Int{garblerShare}, ValidityShare: true,
		}, 1, 2, shift)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := formalCoxRuntimeFinalCarrierShares(
		"evaluator", formalCoxSealedOutput{
			CoefficientShares: []*big.Int{evaluatorShare}, ValidityShare: false,
		}, 1, 2, shift)
	if err != nil {
		t.Fatal(err)
	}
	opened := exactGCReferenceReconstruct(garbler[0], evaluator[0], 128)
	if opened.Cmp(big.NewInt(128)) != 0 || garbler[1].Sign() != 0 ||
		evaluator[1].Sign() != 0 ||
		new(big.Int).Sub(opened, shift).Cmp(beta) != 0 {
		t.Fatalf("Ring256 carrier reduction changed beta: %s", opened)
	}
}

func TestFormalCoxRuntimeTypedSourceFanInIsAuthenticatedAndShareFreeOnRelay(t *testing.T) {
	fixture := formalCoxRuntimeTestFixtureForK(t, 4, t.Name())
	plain := formalCoxTestInput(
		fixture.policy, fixture.admission.Phase1Plan.RingBits)
	left, _ := formalCoxTestSplitSourceAndNoise128(
		rand.New(rand.NewSource(444)), plain, fixture.admission.Phase1Plan)
	receipts := make([]string, len(fixture.policy.CustodianPeers))
	for index, peer := range fixture.policy.CustodianPeers {
		receipts[index] = formalCoxRuntimeTestHash(t.Name() + "/source/" + peer)
	}
	rowShares := left[:fixture.admission.Phase1Plan.RowCoordinates]
	fanIn, err := formalCoxRuntimeBuildSourceFanIn(
		fixture.admission, "garbler", receipts, rowShares,
		fixture.private[fixture.admission.Roles.GarblerPeerName])
	if err != nil {
		t.Fatal(err)
	}
	if err := formalCoxRuntimeValidateSourceFanIn(
		fixture.admission, "garbler", fanIn); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(fanIn)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("aggregate_shares")) ||
		bytes.Contains(encoded, []byte(rowShares[0].String())) ||
		fanIn.RelayVisiblePlaintextShares || fanIn.ProductionReady {
		t.Fatal("recipient aggregate share escaped into relay-visible fan-in metadata")
	}

	tamperedShare := fanIn
	tamperedShare.AggregateShares = append(
		[]*big.Int(nil), fanIn.AggregateShares...)
	tamperedShare.AggregateShares[0] = new(big.Int).Xor(
		new(big.Int).Set(fanIn.AggregateShares[0]), big.NewInt(1))
	if err := formalCoxRuntimeValidateSourceFanIn(
		fixture.admission, "garbler", tamperedShare); err == nil {
		t.Fatal("tampered recipient aggregate share was accepted")
	}
	tamperedReceipt := fanIn
	tamperedReceipt.SourceReceiptSHA256 = append(
		[]string(nil), fanIn.SourceReceiptSHA256...)
	tamperedReceipt.SourceReceiptSHA256[0] =
		formalCoxRuntimeTestHash(t.Name() + "/forged-source-receipt")
	if err := formalCoxRuntimeValidateSourceFanIn(
		fixture.admission, "garbler", tamperedReceipt); err == nil {
		t.Fatal("tampered typed-source receipt schedule was accepted")
	}
	duplicate := fanIn
	duplicate.SourceReceiptSHA256 = append(
		[]string(nil), fanIn.SourceReceiptSHA256...)
	duplicate.SourceReceiptSHA256[1] = duplicate.SourceReceiptSHA256[0]
	if err := formalCoxRuntimeValidateSourceFanIn(
		fixture.admission, "garbler", duplicate); err == nil {
		t.Fatal("duplicate source receipt was accepted as K-source coverage")
	}
}

func formalCoxRuntimeTestSamplerPair(t testing.TB,
	fixture formalCoxRuntimeTestFixture,
) ([]formalCoxRuntimeSamplerRoleChunk, []formalCoxRuntimeSamplerRoleChunk) {
	t.Helper()
	garblerResult := make([]formalCoxRuntimeSamplerRoleChunk,
		len(fixture.admission.Envelopes))
	evaluatorResult := make([]formalCoxRuntimeSamplerRoleChunk,
		len(fixture.admission.Envelopes))
	for index := range fixture.admission.Envelopes {
		left, right := net.Pipe()
		_ = left.SetDeadline(time.Now().Add(90 * time.Second))
		_ = right.SetDeadline(time.Now().Add(90 * time.Second))
		master := sha256.Sum256([]byte(t.Name() + "/sampler-master/" +
			big.NewInt(int64(index)).String()))
		type outcome struct {
			chunk formalCoxRuntimeSamplerRoleChunk
			err   error
		}
		garblerDone := make(chan outcome, 1)
		garblerSeed := fixture.noiseSeeds[fixture.admission.Roles.GarblerPeerName]
		go func() {
			chunk, err := formalCoxRuntimeRunSamplerRoleChunk(
				left, fixture.admission, index, "garbler", master,
				base64.StdEncoding.EncodeToString(garblerSeed[:]),
				fixture.private[fixture.admission.Roles.GarblerPeerName])
			garblerDone <- outcome{chunk: chunk, err: err}
		}()
		evaluatorSeed := fixture.noiseSeeds[fixture.admission.Roles.EvaluatorPeerName]
		evaluator, evaluatorErr := formalCoxRuntimeRunSamplerRoleChunk(
			right, fixture.admission, index, "evaluator", master,
			base64.StdEncoding.EncodeToString(evaluatorSeed[:]),
			fixture.private[fixture.admission.Roles.EvaluatorPeerName])
		garbler := <-garblerDone
		left.Close()
		right.Close()
		if garbler.err != nil || evaluatorErr != nil {
			t.Fatalf("sampler chunk %d: garbler=%v evaluator=%v",
				index, garbler.err, evaluatorErr)
		}
		garblerResult[index] = garbler.chunk
		evaluatorResult[index] = evaluator
	}
	return garblerResult, evaluatorResult
}

func formalCoxRuntimeTestCoxSession(t testing.TB,
	fixture formalCoxRuntimeTestFixture) exactGCSession {
	t.Helper()
	purpose, err := formalCoxPurpose(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	return exactGCSession{
		SessionID:   sha256.Sum256([]byte(t.Name() + "/cox-session")),
		MasterKey:   sha256.Sum256([]byte(t.Name() + "/cox-master")),
		GarblerID:   fixture.policy.ComputePeers[0],
		EvaluatorID: fixture.policy.ComputePeers[1], Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalCoxIterations,
			RingBits:  fixture.admission.Phase1Plan.RingBits,
			FracBits:  fixture.policy.FracBits,
			VectorLen: fixture.admission.Phase1Plan.InputCoordinates,
		},
	}
}

func formalCoxRuntimeTestRunCoxPair(t testing.TB,
	fixture formalCoxRuntimeTestFixture,
	garblerSamplers, evaluatorSamplers []formalCoxRuntimeSamplerRoleChunk,
) (formalCoxRuntimeCoxRoleResult, formalCoxRuntimeCoxRoleResult,
	[]*big.Int) {
	t.Helper()
	plain := formalCoxTestInput(
		fixture.policy, fixture.admission.Phase1Plan.RingBits)
	rowCount := fixture.admission.Phase1Plan.RowCoordinates
	leftAll, rightAll := formalCoxTestSplitSourceAndNoise128(
		rand.New(rand.NewSource(int64(900+len(fixture.policy.CustodianPeers)))),
		plain, fixture.admission.Phase1Plan)
	sourceReceipts := make([]string, len(fixture.policy.CustodianPeers))
	for index, peer := range fixture.policy.CustodianPeers {
		sourceReceipts[index] = formalCoxRuntimeTestHash(
			t.Name() + "/typed-source-receipt/" + peer)
	}
	garblerFanIn, err := formalCoxRuntimeBuildSourceFanIn(
		fixture.admission, "garbler", sourceReceipts, leftAll[:rowCount],
		fixture.private[fixture.admission.Roles.GarblerPeerName])
	if err != nil {
		t.Fatal(err)
	}
	evaluatorFanIn, err := formalCoxRuntimeBuildSourceFanIn(
		fixture.admission, "evaluator", sourceReceipts, rightAll[:rowCount],
		fixture.private[fixture.admission.Roles.EvaluatorPeerName])
	if err != nil {
		t.Fatal(err)
	}
	session := formalCoxRuntimeTestCoxSession(t, fixture)
	left, right := net.Pipe()
	_ = left.SetDeadline(time.Now().Add(120 * time.Second))
	_ = right.SetDeadline(time.Now().Add(120 * time.Second))
	type outcome struct {
		result formalCoxRuntimeCoxRoleResult
		err    error
	}
	garblerDone := make(chan outcome, 1)
	go func() {
		result, runErr := formalCoxRuntimeRunCoxRole(
			left, fixture.admission, "garbler", session, garblerFanIn,
			garblerSamplers,
			fixture.private[fixture.admission.Roles.GarblerPeerName])
		garblerDone <- outcome{result: result, err: runErr}
	}()
	evaluator, evaluatorErr := formalCoxRuntimeRunCoxRole(
		right, fixture.admission, "evaluator", session, evaluatorFanIn,
		evaluatorSamplers,
		fixture.private[fixture.admission.Roles.EvaluatorPeerName])
	garbler := <-garblerDone
	left.Close()
	right.Close()
	if garbler.err != nil || evaluatorErr != nil {
		t.Fatalf("Cox GC: garbler=%v evaluator=%v", garbler.err, evaluatorErr)
	}
	// Build the independent clear oracle only inside the test.  No runtime
	// path reconstructs these noise shares.
	oracle := make([]*big.Int, 0, fixture.admission.Phase1Plan.InputCoordinates)
	for index := 0; index < rowCount; index++ {
		bits := fixture.admission.Phase1Plan.RingBits
		if index < fixture.admission.Phase1Plan.RowCoordinates {
			bits = 128
		}
		residue := exactGCReferenceReconstruct(leftAll[index], rightAll[index], bits)
		if bits == 128 && fixture.admission.Phase1Plan.RingBits > 128 {
			residue = formalCoxResidue(exactGCReferenceSigned(residue, 128),
				fixture.admission.Phase1Plan.RingBits)
		}
		oracle = append(oracle, residue)
	}
	for index := 0; index < fixture.admission.Phase1Plan.ZeroBlindCoordinates; index++ {
		oracle = append(oracle, new(big.Int))
	}
	for index := range garblerSamplers {
		for local := range garblerSamplers[index].NoiseShares {
			residue128 := exactGCReferenceReconstruct(
				garblerSamplers[index].NoiseShares[local],
				evaluatorSamplers[index].NoiseShares[local], 128)
			oracle = append(oracle, formalCoxResidue(
				exactGCReferenceSigned(residue128, 128),
				fixture.admission.Phase1Plan.RingBits))
		}
	}
	for index := range garblerSamplers {
		valid := garblerSamplers[index].ValidityShare !=
			evaluatorSamplers[index].ValidityShare
		oracle = append(oracle, new(big.Int).SetUint64(boolToUint64(valid)))
	}
	return garbler.result, evaluator, oracle
}

func TestFormalCoxRuntimeRealSamplerCoxDurableE2EK2K3K4K5(t *testing.T) {
	if testing.Short() {
		t.Skip("real sampler and Cox KOS/GC protocols")
	}
	for _, custodians := range []int{2, 3, 4, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalCoxRuntimeTestFixtureForK(t, custodians, t.Name())
			formalCoxRuntimeTestSignEnvelopes(t, &fixture)
			garblerSampler, evaluatorSampler :=
				formalCoxRuntimeTestSamplerPair(t, fixture)
			garblerCox, evaluatorCox, oracleInput :=
				formalCoxRuntimeTestRunCoxPair(
					t, fixture, garblerSampler, evaluatorSampler)
			if err := formalCoxRuntimeValidateExecutionReceipt(
				fixture.admission, garblerCox); err != nil {
				t.Fatal(err)
			}
			if err := formalCoxRuntimeValidateExecutionReceipt(
				fixture.admission, evaluatorCox); err != nil {
				t.Fatal(err)
			}
			garblerFinal, err := formalCoxRuntimeBuildFinalRoleSchedule(
				fixture.admission, garblerCox,
				fixture.private[fixture.admission.Roles.GarblerPeerName])
			if err != nil {
				t.Fatal(err)
			}
			evaluatorFinal, err := formalCoxRuntimeBuildFinalRoleSchedule(
				fixture.admission, evaluatorCox,
				fixture.private[fixture.admission.Roles.EvaluatorPeerName])
			if err != nil {
				t.Fatal(err)
			}
			handoffs, err := formalCoxRuntimePairFinalHandoffs(
				fixture.admission, garblerFinal, evaluatorFinal)
			if err != nil {
				t.Fatal(err)
			}
			backendKey := sha256.Sum256([]byte(t.Name() + "/durable-key"))
			dir := t.TempDir()
			leftStore, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				filepath.Join(dir, "garbler"),
				fixture.admission.Roles.GarblerPeerName, backendKey,
				fixture.private[fixture.admission.Roles.GarblerPeerName])
			if err != nil {
				t.Fatal(err)
			}
			rightStore, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				filepath.Join(dir, "evaluator"),
				fixture.admission.Roles.EvaluatorPeerName, backendKey,
				fixture.private[fixture.admission.Roles.EvaluatorPeerName])
			if err != nil {
				t.Fatal(err)
			}
			left, err := leftStore.FinalizeVector(
				handoffs, fixture.admission.Trust, nil)
			if err != nil {
				t.Fatal(err)
			}
			right, err := rightStore.FinalizeVector(
				handoffs, fixture.admission.Trust, nil)
			if err != nil {
				t.Fatal(err)
			}
			common, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
				fixture.admission.Envelopes, fixture.admission.Trust,
				left.Receipt, right.Receipt)
			if err != nil {
				t.Fatal(err)
			}
			release, err := formalCoxRuntimeDecodeCommonRelease(
				fixture.admission, common)
			if err != nil {
				t.Fatal(err)
			}
			want, wantValid, err := referenceFormalCoxIterations(
				fixture.policy, oracleInput,
				fixture.admission.Phase1Plan.RingBits)
			if err != nil || !wantValid || len(want) != 1 {
				t.Fatalf("oracle: %v %v %v", want, wantValid, err)
			}
			wantSigned := exactGCReferenceSigned(
				want[0], fixture.admission.Phase1Plan.RingBits).String()
			if !reflect.DeepEqual(release.ScaledCoefficients,
				[]string{wantSigned}) || release.OpeningCount != 1 ||
				!release.RuntimeNoiseConnected || !release.ProvenanceConnected ||
				!release.DurableOpeningConnected || release.ProductionReady ||
				len(release.Blockers) == 0 {
				t.Fatalf("K=%d release=%+v want=%s",
					custodians, release, wantSigned)
			}

			// Restart with the same durable identities: no reroll and byte-for-byte
			// identical signed common release.
			leftStore, _ = newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				filepath.Join(dir, "garbler"),
				fixture.admission.Roles.GarblerPeerName, backendKey,
				fixture.private[fixture.admission.Roles.GarblerPeerName])
			rightStore, _ = newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				filepath.Join(dir, "evaluator"),
				fixture.admission.Roles.EvaluatorPeerName, backendKey,
				fixture.private[fixture.admission.Roles.EvaluatorPeerName])
			leftReplay, err := leftStore.FinalizeVector(
				handoffs, fixture.admission.Trust, nil)
			if err != nil || !leftReplay.Replayed {
				t.Fatalf("left durable replay: %+v %v", leftReplay, err)
			}
			rightReplay, err := rightStore.FinalizeVector(
				handoffs, fixture.admission.Trust, nil)
			if err != nil || !rightReplay.Replayed {
				t.Fatalf("right durable replay: %+v %v", rightReplay, err)
			}
			replayed, err := jointDPBiomedicalGaussianPairOneDrawLocalReleases(
				fixture.admission.Envelopes, fixture.admission.Trust,
				leftReplay.Receipt, rightReplay.Receipt)
			if err != nil {
				t.Fatal(err)
			}
			firstJSON, _ := json.Marshal(common)
			replayJSON, _ := json.Marshal(replayed)
			if !bytes.Equal(firstJSON, replayJSON) {
				t.Fatal("durable Cox release changed across restart")
			}
		})
	}
}

func TestFormalCoxRuntimeProvenanceRejectsSamplerAndOutputSubstitution(t *testing.T) {
	if testing.Short() {
		t.Skip("real sampler and Cox KOS/GC protocols")
	}
	fixture := formalCoxRuntimeTestFixtureForK(t, 2, t.Name())
	formalCoxRuntimeTestSignEnvelopes(t, &fixture)
	garblerSampler, evaluatorSampler := formalCoxRuntimeTestSamplerPair(t, fixture)
	garblerCox, _, _ := formalCoxRuntimeTestRunCoxPair(
		t, fixture, garblerSampler, evaluatorSampler)
	tamperedNoise := append([]formalCoxRuntimeSamplerRoleChunk(nil), garblerSampler...)
	tamperedNoise[0].NoiseShares = append([]*big.Int(nil),
		garblerSampler[0].NoiseShares...)
	tamperedNoise[0].NoiseShares[0] = new(big.Int).Add(
		new(big.Int).Set(tamperedNoise[0].NoiseShares[0]), big.NewInt(1))
	prefixCount := fixture.admission.Phase1Plan.RowCoordinates +
		fixture.admission.Phase1Plan.ZeroBlindCoordinates
	if _, err := formalCoxRuntimeAssembleCoxRoleInput(
		fixture.admission, "garbler", garblerCox.InputShares[:prefixCount],
		tamperedNoise); err == nil {
		t.Fatal("sampler-to-noise substitution was accepted")
	}
	tamperedOutput := garblerCox
	tamperedOutput.Output.CoefficientShares = append([]*big.Int(nil),
		garblerCox.Output.CoefficientShares...)
	tamperedOutput.Output.CoefficientShares[0] = new(big.Int).Add(
		new(big.Int).Set(tamperedOutput.Output.CoefficientShares[0]), big.NewInt(1))
	if err := formalCoxRuntimeValidateExecutionReceipt(
		fixture.admission, tamperedOutput); err == nil {
		t.Fatal("post-Cox output substitution retained provenance")
	}
}
