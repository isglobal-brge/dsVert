package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func jointDPBiomedicalGaussianFullTestResealPhase19Token(t testing.TB,
	token *formalGLMPhase19PostExecutionToken, backendKey [32]byte,
) {
	t.Helper()
	preimage, err := formalGLMPhase19PostTokenPreimage(*token)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase19PostTokenDomain+"|"), preimage...))
	token.TokenSHA256 = hexString(digest[:])
	token.seal = formalGLMPhase19MAC(backendKey,
		formalGLMPhase19PostTokenDomain+"/seal", digest[:])
}

func jointDPBiomedicalGaussianFullTestPhase19Token(t testing.TB,
	fixture jointDPBiomedicalGaussianFullTestFixture, backendKey [32]byte,
	label string,
) formalGLMPhase19PostExecutionToken {
	t.Helper()
	contract := fixture.selection.Contract
	token := formalGLMPhase19PostExecutionToken{
		Version:                          formalGLMPhase19PostTokenVersion,
		ContextSHA256:                    jointDPBiomedicalGaussianTestHash(label + "/context"),
		CapsuleSHA256:                    contract.CapsuleID,
		Phase15PlanSHA256:                jointDPBiomedicalGaussianTestHash(label + "/plan"),
		PreExecutionTokenSHA256:          jointDPBiomedicalGaussianTestHash(label + "/pre"),
		RunID:                            jointDPBiomedicalGaussianTestHash(label + "/run"),
		PinsetSHA256:                     contract.PinsetSHA256,
		GlobalMaterializationRoot:        contract.MaterializationRootSHA256,
		FanInTranscriptSHA256:            jointDPBiomedicalGaussianTestHash(label + "/fanin"),
		BlockCommitmentRootSHA256:        jointDPBiomedicalGaussianTestHash(label + "/blocks"),
		BlockReceiptRootSHA256:           jointDPBiomedicalGaussianTestHash(label + "/block-receipts"),
		AccumulatorRoot:                  jointDPBiomedicalGaussianTestHash(label + "/accumulator"),
		ExecutionReceiptPairSHA256:       jointDPBiomedicalGaussianTestHash(label + "/execution-pair"),
		FinalReceiptSetSeal:              jointDPBiomedicalGaussianTestHash(label + "/final-receipts"),
		CheckpointEvidenceSeal:           jointDPBiomedicalGaussianTestHash(label + "/checkpoint-seal"),
		Phase15ExecutionTranscriptSHA256: jointDPBiomedicalGaussianTestHash(label + "/phase15-transcript"),
		FinalCheckpointTranscriptSHA256:  jointDPBiomedicalGaussianTestHash(label + "/checkpoint-transcript"),
		WorkerTranscriptSHA256:           jointDPBiomedicalGaussianTestHash(label + "/worker-transcript"),
		PostExecutionRootSHA256:          jointDPBiomedicalGaussianTestHash(label + "/post-root"),
		CustodianCount:                   contract.CustodianCount,
		ComputePeers: append([]string(nil),
			contract.DesignatedComputePeers...),
		FanInExecuted:                  true,
		ExactAllKValidityInsideGC:      true,
		ConsensusComparedInsideGC:      true,
		FullTupleMaskInsideGC:          true,
		ExecutionValidSealed:           true,
		ExecutionValidityOpened:        false,
		PatientDependentDigestsExposed: false,
		ProtectedDataE2EVerified:       false,
		OpeningAuthorized:              false,
		OpeningsPerformed:              0,
		DPReleaseStatus:                "blocked_until_joint_dp_release_consumes_hidden_execution_validity_v1",
		RemainingBlockers: []string{
			"registered_r_dsi_lifecycle_and_real_multiprocess_e2e_unavailable_v1",
			"joint_dp_release_consuming_hidden_execution_validity_v1",
		},
		ProductionReady: false,
		verified:        true,
	}
	jointDPBiomedicalGaussianFullTestResealPhase19Token(
		t, &token, backendKey)
	if err := formalGLMPhase19VerifyPostExecutionToken(token, backendKey); err != nil {
		t.Fatal(err)
	}
	return token
}

func jointDPBiomedicalGaussianFullTestSliceShare(t testing.TB, full string,
	start, count int,
) string {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(full)
	if err != nil {
		t.Fatal(err)
	}
	first := start * 16
	return base64.StdEncoding.EncodeToString(decoded[first : first+count*16])
}

func jointDPBiomedicalGaussianFullTestPhase19Handoffs(t testing.TB,
	fixture jointDPBiomedicalGaussianFullTestFixture,
	token formalGLMPhase19PostExecutionToken, backendKey [32]byte,
	geometry [][2]int, leftFull, rightFull string,
) []jointDPBiomedicalGaussianFullPhase19FinalizerHandoff {
	t.Helper()
	peers := fixture.base.manifest.Contract.DesignatedComputePeers
	result := make([]jointDPBiomedicalGaussianFullPhase19FinalizerHandoff,
		0, len(geometry))
	for _, chunk := range geometry {
		shares := make([]jointDPBiomedicalGaussianFullPhase19PeerShare, 2)
		for index, peer := range peers {
			full := leftFull
			if index == 1 {
				full = rightFull
			}
			source := jointDPBiomedicalGaussianFullTestSliceShare(
				t, full, chunk[0], chunk[1])
			binding, err := jointDPBiomedicalGaussianBindFullPhase19Source(
				fixture.admission, fixture.base.pins, token, backendKey,
				peer, chunk[0], chunk[1], source)
			if err != nil {
				t.Fatal(err)
			}
			shares[index], err = jointDPBiomedicalGaussianRunFullPhase19Peer(
				fixture.admission, fixture.base.pins, binding, backendKey,
				fixture.roots[peer], fixture.base.private[peer], source)
			if err != nil {
				t.Fatal(err)
			}
		}
		handoff, err := jointDPBiomedicalGaussianBuildFullPhase19FinalizerHandoff(
			fixture.admission, fixture.base.pins, token, backendKey,
			shares[0], shares[1])
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, handoff)
	}
	return result
}

func TestJointDPBiomedicalGaussianFullPhase19BindingK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := jointDPBiomedicalGaussianFullTestSetup(
				t, custodians, 3, t.Name())
			backendKey := sha256.Sum256([]byte(t.Name() + "/backend-key"))
			token := jointDPBiomedicalGaussianFullTestPhase19Token(
				t, fixture, backendKey, t.Name())
			left := jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 1)
			right := jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 2)
			handoffs := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
				t, fixture, token, backendKey, [][2]int{{0, 3}}, left, right)
			if len(handoffs) != 1 || handoffs[0].OpeningAuthorized ||
				handoffs[0].OpeningsPerformed != 0 || handoffs[0].ProductionReady ||
				handoffs[0].Phase19PostExecutionRootSHA256 !=
					token.PostExecutionRootSHA256 {
				t.Fatalf("invalid sealed K=%d handoff: %#v", custodians, handoffs)
			}
			encoded, err := json.Marshal(handoffs[0])
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{left, right,
				token.CheckpointEvidenceSeal, token.FinalReceiptSetSeal} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("sealed handoff exposed private material %q", forbidden)
				}
			}
		})
	}
}

func TestJointDPBiomedicalGaussianFullPhase19RejectsTamperAndUnboundSource(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 3, 3, t.Name())
	backendKey := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	token := jointDPBiomedicalGaussianFullTestPhase19Token(
		t, fixture, backendKey, t.Name())
	peer := fixture.base.manifest.Contract.DesignatedComputePeers[0]
	source := jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 1)
	binding, err := jointDPBiomedicalGaussianBindFullPhase19Source(
		fixture.admission, fixture.base.pins, token, backendKey,
		peer, 0, 3, source)
	if err != nil {
		t.Fatal(err)
	}

	changedToken := token
	changedToken.ExecutionValidityOpened = true
	jointDPBiomedicalGaussianFullTestResealPhase19Token(
		t, &changedToken, backendKey)
	if _, err := jointDPBiomedicalGaussianBindFullPhase19Source(
		fixture.admission, fixture.base.pins, changedToken, backendKey,
		peer, 0, 3, source); err == nil {
		t.Fatal("an opened Phase-1.9 validity token was accepted")
	}
	changedToken = token
	changedToken.ComputePeers = append([]string(nil), token.ComputePeers...)
	changedToken.ComputePeers[0], changedToken.ComputePeers[1] =
		changedToken.ComputePeers[1], changedToken.ComputePeers[0]
	jointDPBiomedicalGaussianFullTestResealPhase19Token(
		t, &changedToken, backendKey)
	if _, err := jointDPBiomedicalGaussianBindFullPhase19Source(
		fixture.admission, fixture.base.pins, changedToken, backendKey,
		peer, 0, 3, source); err == nil {
		t.Fatal("a reordered compute-peer binding was accepted")
	}
	changedToken = token
	changedToken.CapsuleSHA256 = fixture.selection.Contract.ManifestSHA256
	jointDPBiomedicalGaussianFullTestResealPhase19Token(
		t, &changedToken, backendKey)
	if _, err := jointDPBiomedicalGaussianBindFullPhase19Source(
		fixture.admission, fixture.base.pins, changedToken, backendKey,
		peer, 0, 3, source); err == nil {
		t.Fatal("the historical capsule_sha256 field accepted manifest_sha256 instead of capsule_id")
	}
	changedToken = token
	changedToken.RemainingBlockers = append([]string(nil),
		token.RemainingBlockers...)
	changedToken.RemainingBlockers[0], changedToken.RemainingBlockers[1] =
		changedToken.RemainingBlockers[1], changedToken.RemainingBlockers[0]
	jointDPBiomedicalGaussianFullTestResealPhase19Token(
		t, &changedToken, backendKey)
	if _, err := jointDPBiomedicalGaussianBindFullPhase19Source(
		fixture.admission, fixture.base.pins, changedToken, backendKey,
		peer, 0, 3, source); err == nil {
		t.Fatal("a Phase-1.9 token with changed blocker semantics was accepted")
	}
	otherSource := jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 21)
	if _, err := jointDPBiomedicalGaussianRunFullPhase19Peer(
		fixture.admission, fixture.base.pins, binding, backendKey,
		fixture.roots[peer], fixture.base.private[peer], otherSource); err == nil {
		t.Fatal("a relay-substituted local source share was accepted")
	}
	wrongKey := sha256.Sum256([]byte(t.Name() + "/wrong-backend-key"))
	if _, err := jointDPBiomedicalGaussianRunFullPhase19Peer(
		fixture.admission, fixture.base.pins, binding, wrongKey,
		fixture.roots[peer], fixture.base.private[peer], source); err == nil {
		t.Fatal("a foreign server-local Phase-1.9 seal was accepted")
	}
}

func TestJointDPBiomedicalGaussianFullDurableReleaseIsAppendFirstStickyAndCommon(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 3, 4, t.Name())
	backendKey := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	token := jointDPBiomedicalGaussianFullTestPhase19Token(
		t, fixture, backendKey, t.Name())
	left := jointDPBiomedicalGaussianFullTestSourceShare(t, 4, 1)
	right := jointDPBiomedicalGaussianFullTestSourceShare(t, 4, 2)
	full := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
		t, fixture, token, backendKey, [][2]int{{0, 4}}, left, right)
	rechunked := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
		t, fixture, token, backendKey, [][2]int{{0, 1}, {1, 3}}, left, right)
	reorderedDelivery := []jointDPBiomedicalGaussianFullPhase19FinalizerHandoff{
		rechunked[1], rechunked[0],
	}
	peers := fixture.base.manifest.Contract.DesignatedComputePeers
	stores := make([]*jointDPBiomedicalGaussianFullDurableReleaseStore, 2)
	local := make([]jointDPBiomedicalGaussianFullLocalRelease, 2)
	for index, peer := range peers {
		var err error
		stores[index], err = newJointDPBiomedicalGaussianFullDurableReleaseStore(
			t.TempDir(), peer, backendKey, fixture.base.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		phases := []string{}
		local[index], err = stores[index].FinalizeVector(
			fixture.admission, fixture.base.pins, full,
			func(phase string) { phases = append(phases, phase) })
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(phases, []string{
			"after_ledger_append_before_release", "after_dp_vector_durable"}) {
			t.Fatalf("release durability order changed: %v", phases)
		}
		if local[index].Replayed || local[index].Receipt.OpeningsPerformed != 1 ||
			local[index].Receipt.HistoryCanDenyOperation ||
			local[index].Receipt.OperationLimit || local[index].Receipt.RequestLimit ||
			!local[index].Receipt.UnlimitedDeterministicReplay ||
			!local[index].Receipt.UnlimitedPostprocessing {
			t.Fatalf("invalid local durable release: %#v", local[index])
		}
		firstJSON, _ := json.Marshal(local[index].Receipt)
		replay, err := stores[index].FinalizeVector(
			fixture.admission, fixture.base.pins, reorderedDelivery,
			func(string) { t.Fatal("exact replay performed new durable work") })
		if err != nil || !replay.Replayed {
			t.Fatalf("rechunk replay failed: %#v %v", replay, err)
		}
		replayJSON, _ := json.Marshal(replay.Receipt)
		if !bytes.Equal(firstJSON, replayJSON) {
			t.Fatal("retry/rechunk changed the signed DP release bytes")
		}
		restarted, err := newJointDPBiomedicalGaussianFullDurableReleaseStore(
			stores[index].dir, peer, backendKey, fixture.base.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		afterRestart, err := restarted.FinalizeVector(
			fixture.admission, fixture.base.pins, full, nil)
		if err != nil || !afterRestart.Replayed {
			t.Fatalf("restart replay failed: %#v %v", afterRestart, err)
		}
		afterJSON, _ := json.Marshal(afterRestart.Receipt)
		if !bytes.Equal(firstJSON, afterJSON) {
			t.Fatal("restart changed the signed DP release bytes")
		}
	}
	common, err := jointDPBiomedicalGaussianPairFullLocalReleases(
		fixture.admission, fixture.base.pins,
		local[1].Receipt, local[0].Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := jointDPBiomedicalGaussianValidateFullCommonRelease(
		fixture.admission, fixture.base.pins, common); err != nil {
		t.Fatal(err)
	}
	if common.OpeningsPerformed != 1 || !common.SingleCommonDPVector ||
		common.HistoryCanDenyOperation || common.OperationLimit ||
		common.RequestLimit || !common.UnlimitedDeterministicReplay ||
		!common.UnlimitedPostprocessing ||
		common.RouteRole != jointDPBiomedicalGaussianFullRouteRole ||
		common.TargetVarianceOptimal || common.NominalVarianceMultiplier != 2 ||
		len(common.ClampedScaledValues) != 4 {
		t.Fatalf("invalid common release: %#v", common)
	}
}

func TestJointDPBiomedicalGaussianFullDurableReleaseRejectsCrossReleaseReplay(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 2, 2, t.Name())
	backendKey := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	token := jointDPBiomedicalGaussianFullTestPhase19Token(
		t, fixture, backendKey, t.Name())
	left := jointDPBiomedicalGaussianFullTestSourceShare(t, 2, 1)
	right := jointDPBiomedicalGaussianFullTestSourceShare(t, 2, 2)
	handoffs := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
		t, fixture, token, backendKey, [][2]int{{0, 2}}, left, right)
	peer := fixture.base.manifest.Contract.DesignatedComputePeers[0]
	store, err := newJointDPBiomedicalGaussianFullDurableReleaseStore(
		t.TempDir(), peer, backendKey, fixture.base.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinalizeVector(
		fixture.admission, fixture.base.pins, handoffs, nil); err != nil {
		t.Fatal(err)
	}

	changed := append([]jointDPBiomedicalGaussianFullPhase19FinalizerHandoff(nil),
		handoffs...)
	changed[0].ReleaseInstanceID = jointDPBiomedicalGaussianTestHash("other-release")
	if _, err := store.FinalizeVector(
		fixture.admission, fixture.base.pins, changed, nil); err == nil {
		t.Fatal("a relay-replayed handoff under another release was accepted")
	}
	changed = append([]jointDPBiomedicalGaussianFullPhase19FinalizerHandoff(nil),
		handoffs...)
	changed[0].phase19Seal[0] ^= 1
	if _, err := store.FinalizeVector(
		fixture.admission, fixture.base.pins, changed, nil); err == nil {
		t.Fatal("a tampered Phase-1.9 handoff seal was accepted")
	}
	split := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
		t, fixture, token, backendKey, [][2]int{{0, 1}, {1, 1}}, left, right)
	if _, err := store.FinalizeVector(
		fixture.admission, fixture.base.pins,
		[]jointDPBiomedicalGaussianFullPhase19FinalizerHandoff{
			split[0], split[0],
		}, nil); err == nil {
		t.Fatal("a duplicated release chunk was accepted")
	}
}

func TestJointDPBiomedicalGaussianFullCommonReleaseIsOfflineVerifiable(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 3, 3, t.Name())
	backendKey := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	token := jointDPBiomedicalGaussianFullTestPhase19Token(
		t, fixture, backendKey, t.Name())
	left := jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 1)
	right := jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 2)
	handoffs := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
		t, fixture, token, backendKey, [][2]int{{0, 3}}, left, right)
	peers := fixture.selection.Contract.DesignatedComputePeers
	locals := make([]jointDPBiomedicalGaussianFullLocalReleaseReceipt, 2)
	for index, peer := range peers {
		store, err := newJointDPBiomedicalGaussianFullDurableReleaseStore(
			t.TempDir(), peer, backendKey, fixture.base.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		local, err := store.FinalizeVector(
			fixture.admission, fixture.base.pins, handoffs, nil)
		if err != nil {
			t.Fatal(err)
		}
		locals[index] = local.Receipt
	}
	common, err := jointDPBiomedicalGaussianPairFullLocalReleases(
		fixture.admission, fixture.base.pins, locals[1], locals[0])
	if err != nil {
		t.Fatal(err)
	}
	message, err := jointDPBiomedicalGaussianFullCommonReleaseMessage(common)
	if err != nil {
		t.Fatal(err)
	}
	for index, peer := range peers {
		if common.Signatures[index].Signer != peer ||
			!ed25519.Verify(fixture.base.pins[peer], message,
				common.Signatures[index].Signature) {
			t.Fatalf("peer %q did not sign the common byte-identical preimage", peer)
		}
	}
	encoded, err := json.Marshal(common)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`"peer_identity_sha256"`, `"common_release_signature"`,
		`"left_noised_share"`, `"right_noised_share"`,
		`"source_binding_sha256"`, `"noise_root"`,
		`"checkpoint_evidence_seal"`, `"final_receipt_set_seal"`,
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("common release exposed private/internal field %s", forbidden)
		}
	}

	swapped := common
	swapped.Signatures = append([]jointDPBiomedicalGaussianSignature(nil),
		common.Signatures...)
	swapped.Signatures[0], swapped.Signatures[1] =
		swapped.Signatures[1], swapped.Signatures[0]
	if err := jointDPBiomedicalGaussianValidateFullCommonRelease(
		fixture.admission, fixture.base.pins, swapped); err == nil {
		t.Fatal("reordered common signatures were accepted")
	}
	localSignatures := common
	localSignatures.Signatures = []jointDPBiomedicalGaussianSignature{
		{Signer: peers[0], Signature: append([]byte(nil), locals[0].Signature...)},
		{Signer: peers[1], Signature: append([]byte(nil), locals[1].Signature...)},
	}
	if err := jointDPBiomedicalGaussianValidateFullCommonRelease(
		fixture.admission, fixture.base.pins, localSignatures); err == nil {
		t.Fatal("peer-local receipt signatures were accepted as common signatures")
	}
	tampered := common
	tampered.ReleaseInstanceID = jointDPBiomedicalGaussianTestHash("other-release")
	if err := jointDPBiomedicalGaussianValidateFullCommonRelease(
		fixture.admission, fixture.base.pins, tampered); err == nil {
		t.Fatal("a common release replayed under another release id was accepted")
	}

	// Even two valid signing keys cannot turn an out-of-range value into a
	// numerically certified release: the public verifier rechecks every bound.
	outside := common
	outside.ClampedScaledValues = append([]string(nil),
		common.ClampedScaledValues...)
	upper, ok := new(big.Int).SetString(
		fixture.admission.certificate.ShiftedUpperBounds[0], 10)
	if !ok {
		t.Fatal("invalid test upper bound")
	}
	outside.ClampedScaledValues[0] = upper.Add(upper, big.NewInt(1)).String()
	vectorDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullLocalReleaseDomain+"/vector",
		outside.ClampedScaledValues)
	if err != nil {
		t.Fatal(err)
	}
	outside.VectorSHA256 = hexString(vectorDigest[:])
	outsideMessage, err := jointDPBiomedicalGaussianFullCommonReleaseMessage(outside)
	if err != nil {
		t.Fatal(err)
	}
	outside.Signatures = make([]jointDPBiomedicalGaussianSignature, 2)
	for index, peer := range peers {
		outside.Signatures[index] = jointDPBiomedicalGaussianSignature{
			Signer: peer,
			Signature: ed25519.Sign(
				fixture.base.private[peer], outsideMessage),
		}
	}
	if err := jointDPBiomedicalGaussianValidateFullCommonRelease(
		fixture.admission, fixture.base.pins, outside); err == nil {
		t.Fatal("a correctly signed value above its certified bound was accepted")
	}
}

func TestJointDPBiomedicalGaussianFullDurableReleaseRecoversAfterLedgerCrash(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 2, 3, t.Name())
	backendKey := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	token := jointDPBiomedicalGaussianFullTestPhase19Token(
		t, fixture, backendKey, t.Name())
	handoffs := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
		t, fixture, token, backendKey, [][2]int{{0, 3}},
		jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 1),
		jointDPBiomedicalGaussianFullTestSourceShare(t, 3, 2))
	peer := fixture.selection.Contract.DesignatedComputePeers[0]
	dir := t.TempDir()
	store, err := newJointDPBiomedicalGaussianFullDurableReleaseStore(
		dir, peer, backendKey, fixture.base.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	crashed := false
	func() {
		defer func() {
			crashed = recover() != nil
		}()
		_, _ = store.FinalizeVector(
			fixture.admission, fixture.base.pins, handoffs,
			func(phase string) {
				if phase != "after_ledger_append_before_release" {
					return
				}
				path, pathErr := store.recordPath(
					fixture.selection.Contract.ReleaseInstanceID, false)
				encoded, readErr := jointDPBiomedicalGaussianFullReadDurableRecord(path)
				record, decodeErr := jointDPBiomedicalGaussianFullDecodeRecord(
					backendKey, encoded)
				if pathErr != nil || readErr != nil || decodeErr != nil ||
					record.State != "ledger_committed" ||
					!record.LedgerAppendBeforeRelease {
					t.Errorf("ledger was not durably committed before release: %#v %v %v %v",
						record, pathErr, readErr, decodeErr)
				}
				panic("simulated process crash")
			})
	}()
	if !crashed {
		t.Fatal("the simulated post-ledger crash did not occur")
	}
	restarted, err := newJointDPBiomedicalGaussianFullDurableReleaseStore(
		dir, peer, backendKey, fixture.base.private[peer])
	if err != nil {
		t.Fatal(err)
	}
	phases := []string{}
	resumed, err := restarted.FinalizeVector(
		fixture.admission, fixture.base.pins, handoffs,
		func(phase string) { phases = append(phases, phase) })
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Replayed || !reflect.DeepEqual(phases,
		[]string{"after_dp_vector_durable"}) {
		t.Fatalf("pending ledger did not resume exactly once: %#v %v",
			resumed, phases)
	}
	replay, err := restarted.FinalizeVector(
		fixture.admission, fixture.base.pins, handoffs,
		func(string) { t.Fatal("released crash recovery repeated work") })
	if err != nil || !replay.Replayed ||
		!reflect.DeepEqual(resumed.Receipt, replay.Receipt) {
		t.Fatalf("crash-recovered release was not sticky: %#v %v", replay, err)
	}
}

func TestJointDPBiomedicalGaussianFullDurableReleaseConcurrentCAS(t *testing.T) {
	fixture := jointDPBiomedicalGaussianFullTestSetup(t, 3, 4, t.Name())
	backendKey := sha256.Sum256([]byte(t.Name() + "/backend-key"))
	token := jointDPBiomedicalGaussianFullTestPhase19Token(
		t, fixture, backendKey, t.Name())
	left := jointDPBiomedicalGaussianFullTestSourceShare(t, 4, 1)
	right := jointDPBiomedicalGaussianFullTestSourceShare(t, 4, 2)
	full := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
		t, fixture, token, backendKey, [][2]int{{0, 4}}, left, right)
	rechunked := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
		t, fixture, token, backendKey, [][2]int{{0, 2}, {2, 2}}, left, right)
	peer := fixture.selection.Contract.DesignatedComputePeers[0]
	dir := t.TempDir()
	const workers = 8
	stores := make([]*jointDPBiomedicalGaussianFullDurableReleaseStore, workers)
	for index := range stores {
		var err error
		stores[index], err = newJointDPBiomedicalGaussianFullDurableReleaseStore(
			dir, peer, backendKey, fixture.base.private[peer])
		if err != nil {
			t.Fatal(err)
		}
	}
	results := make([]jointDPBiomedicalGaussianFullLocalRelease, workers)
	errs := make([]error, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	var ledgerHooks, durableHooks atomic.Int32
	for index := range stores {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			chunks := full
			if index%2 == 1 {
				chunks = []jointDPBiomedicalGaussianFullPhase19FinalizerHandoff{
					rechunked[1], rechunked[0],
				}
			}
			results[index], errs[index] = stores[index].FinalizeVector(
				fixture.admission, fixture.base.pins, chunks,
				func(phase string) {
					switch phase {
					case "after_ledger_append_before_release":
						ledgerHooks.Add(1)
					case "after_dp_vector_durable":
						durableHooks.Add(1)
					}
				})
		}(index)
	}
	close(start)
	wait.Wait()
	var canonical []byte
	for index := range results {
		if errs[index] != nil {
			t.Fatalf("concurrent finalizer %d failed: %v", index, errs[index])
		}
		encoded, err := json.Marshal(results[index].Receipt)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			canonical = encoded
		} else if !bytes.Equal(canonical, encoded) {
			t.Fatal("concurrent finalizers returned different release bytes")
		}
	}
	if ledgerHooks.Load() != 1 || durableHooks.Load() < 1 {
		t.Fatalf("append-first CAS phases were not canonical: ledger=%d durable=%d",
			ledgerHooks.Load(), durableHooks.Load())
	}
}

func TestJointDPBiomedicalGaussianFullDurableReadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, bytes.Repeat([]byte{'x'}, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "release.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := jointDPBiomedicalGaussianFullReadDurableRecord(path); err == nil ||
		!strings.Contains(err.Error(), "unsafe durable release record") {
		t.Fatalf("durable release symlink was not rejected: %v", err)
	}
}

func TestJointDPBiomedicalGaussianFullDurableReleaseRotationDoesNotBlock(t *testing.T) {
	fixtures := []jointDPBiomedicalGaussianFullTestFixture{
		jointDPBiomedicalGaussianFullTestSetup(t, 3, 2, t.Name()+"/epoch-a"),
		jointDPBiomedicalGaussianFullTestSetup(t, 3, 2, t.Name()+"/epoch-b"),
	}
	var releaseIDs []string
	var firstStores []*jointDPBiomedicalGaussianFullDurableReleaseStore
	var firstHandoffs []jointDPBiomedicalGaussianFullPhase19FinalizerHandoff
	siteDirs := make(map[string]string, 2)
	for epoch, fixture := range fixtures {
		backendKey := sha256.Sum256([]byte(t.Name() + "/backend-key/" + string(rune('a'+epoch))))
		token := jointDPBiomedicalGaussianFullTestPhase19Token(
			t, fixture, backendKey, t.Name()+"/token/"+string(rune('a'+epoch)))
		handoffs := jointDPBiomedicalGaussianFullTestPhase19Handoffs(
			t, fixture, token, backendKey, [][2]int{{0, 2}},
			jointDPBiomedicalGaussianFullTestSourceShare(t, 2, byte(1+epoch*2)),
			jointDPBiomedicalGaussianFullTestSourceShare(t, 2, byte(2+epoch*2)))
		peers := fixture.selection.Contract.DesignatedComputePeers
		locals := make([]jointDPBiomedicalGaussianFullLocalReleaseReceipt, 2)
		stores := make([]*jointDPBiomedicalGaussianFullDurableReleaseStore, 2)
		for index, peer := range peers {
			if siteDirs[peer] == "" {
				siteDirs[peer] = t.TempDir()
			}
			var err error
			stores[index], err = newJointDPBiomedicalGaussianFullDurableReleaseStore(
				siteDirs[peer], peer, backendKey, fixture.base.private[peer])
			if err != nil {
				t.Fatal(err)
			}
			local, err := stores[index].FinalizeVector(
				fixture.admission, fixture.base.pins, handoffs, nil)
			if err != nil {
				t.Fatalf("rotated epoch %d was blocked: %v", epoch, err)
			}
			locals[index] = local.Receipt
		}
		common, err := jointDPBiomedicalGaussianPairFullLocalReleases(
			fixture.admission, fixture.base.pins, locals[0], locals[1])
		if err != nil {
			t.Fatalf("rotated epoch %d could not form a common release: %v", epoch, err)
		}
		releaseIDs = append(releaseIDs, common.ReleaseInstanceID)
		if epoch == 0 {
			firstStores, firstHandoffs = stores, handoffs
		}
	}
	if releaseIDs[0] == releaseIDs[1] {
		t.Fatal("root/pin/backend-key rotation reused a release instance")
	}
	old := fixtures[0]
	for _, store := range firstStores {
		replay, err := store.FinalizeVector(
			old.admission, old.base.pins, firstHandoffs, nil)
		if err != nil || !replay.Replayed {
			t.Fatalf("rotation made an earlier release unavailable: %#v %v", replay, err)
		}
	}
}
