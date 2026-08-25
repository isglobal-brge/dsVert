package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type formalGLMPhase21StickyTestFixture struct {
	phase21      formalGLMPhase21TestFixture
	outputs      map[string]formalGLMPhase21OneDrawLocalOutput
	releaseStore map[string]*jointDPBiomedicalGaussianOneDrawDurableReleaseStore
	releaseRoot  map[string]string
	local        map[string]jointDPBiomedicalGaussianOneDrawLocalRelease
	certified    formalGLMPhase16CertifiedRelease
	certificate  formalGLMPhase21StickyCertificate
	plan         formalGLMPhase15Plan
}

type formalGLMPhase21SamplerV2TestFixture struct {
	artifact   formalGLMPhase21StickyArtifact
	artifactID string
	pins       map[string]ed25519.PublicKey
	keys       map[string]ed25519.PrivateKey
	roots      map[string][32]byte
	contract   formalGLMPhase21SamplerV2Contract
}

func formalGLMPhase21SamplerV2TestSetup(t testing.TB, custodians int,
	mode string,
) formalGLMPhase21SamplerV2TestFixture {
	t.Helper()
	peers := make([]string, custodians)
	for index := range peers {
		peers[index] = "peer-" + string(rune('a'+index))
	}
	identities := formalGLMPhase15TestIdentitySet(t, peers)
	pinset, err := formalGLMPhase16PinsetSHA256(identities.public)
	if err != nil {
		t.Fatal(err)
	}
	peerIDs := make([]string, 2)
	for index := range peerIDs {
		peerIDs[index], err = formalGLMPhase16PeerID(identities.public[peers[index]])
		if err != nil {
			t.Fatal(err)
		}
	}
	hash := func(label string) string {
		return sha256Hex([]byte(t.Name() + "/" + label))
	}
	artifact := formalGLMPhase21StickyArtifact{
		Version: formalGLMPhase21StickyVersion, Purpose: formalGLMPhase21StickyPurpose,
		CanonicalScienceSHA256:  hash("science"),
		ScientificArtifactScope: "phase0_formula_estimand_adjacency_optimizer_link_numeric_dp_projection_v1",
		CanonicalPlanSHA256:     hash("plan"), SchemaManifestSHA256: hash("schema"),
		SnapshotSHA256: hash("snapshot"), PinsetSHA256: pinset,
		CustodianPeers: append([]string(nil), peers...), CustodianCount: custodians,
		DesignatedComputePeers: []string{peers[0], peers[1]},
		NoiseAuthorities: []formalGLMPhase21StickyNoiseAuthority{
			{Role: "garbler", PeerName: peers[0], PeerID: peerIDs[0]},
			{Role: "evaluator", PeerName: peers[1], PeerID: peerIDs[1]},
		},
		Family: "binomial", Adjacency: "add_remove_patient",
		Mechanism:       formalGLMPhase16RequiredMechanism,
		Allocation:      formalGLMPhase16RequiredAllocation,
		EpsilonRational: "1", DeltaRational: "1/1000000",
		SensitivitySteps: "17",
		BoundsSHA256:     hash("bounds"), QuantizationSHA256: hash("quantization"),
		CanonicalLinkSHA256: hash("link"), CoordinateOrderSHA256: hash("coordinates"),
		CoordinateCount:    2,
		SourceFractionBits: 0, QuantizationShift: 0, OutputLatticeBits: 20,
	}
	artifactID, err := formalGLMPhase21StickyArtifactID(artifact)
	if err != nil {
		t.Fatal(err)
	}
	roots := make(map[string][32]byte, 2)
	commitments := make([]formalGLMPhase21SamplerV2Commitment, 2)
	for index, authority := range artifact.NoiseAuthorities {
		root := sha256.Sum256([]byte(t.Name() + "/authority-root/" + authority.PeerName))
		roots[authority.PeerName] = root
		_, commitments[index], err = formalGLMPhase21SamplerV2Derive(
			root, artifactID, mode, authority.Role,
			authority.PeerName, authority.PeerID)
		if err != nil {
			t.Fatal(err)
		}
	}
	unsigned, err := formalGLMPhase21BuildSamplerV2Contract(
		artifact, artifactID, mode, commitments, identities.public)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]jointDPBiomedicalGaussianSignature, 0, custodians)
	for _, peer := range peers {
		signature, signErr := formalGLMPhase21SignSamplerV2Contract(
			unsigned, peer, identities.private[peer])
		if signErr != nil {
			t.Fatal(signErr)
		}
		signatures = append(signatures, signature)
	}
	contract, err := formalGLMPhase21SealSamplerV2Contract(
		unsigned, signatures, identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMPhase21SamplerV2TestFixture{
		artifact: artifact, artifactID: artifactID,
		pins: identities.public, keys: identities.private,
		roots: roots, contract: contract,
	}
}

func formalGLMPhase21SamplerV2TestUnsignedCertificate(
	t testing.TB, fixture formalGLMPhase21SamplerV2TestFixture,
) formalGLMPhase21StickyCertificate {
	t.Helper()
	hash := func(label string) string {
		return sha256Hex([]byte(t.Name() + "/durable-certificate/" + label))
	}
	values := []string{"11", "7"}
	vectorSHA256, err := jointDPBiomedicalGaussianOneDrawVectorSHA256(values)
	if err != nil {
		t.Fatal(err)
	}
	evidence := make([]formalGLMPhase21StickyNoiseEvidence, 2)
	for index, commitment := range fixture.contract.NoiseCommitments {
		evidence[index] = formalGLMPhase21StickyNoiseEvidence{
			Role: commitment.Role, PeerName: commitment.PeerName,
			PeerID:                  commitment.PeerID,
			CommitmentContextSHA256: commitment.CommitmentContextSHA256,
			SeedCommitmentSHA256:    commitment.SeedCommitmentSHA256,
		}
	}
	contract := fixture.contract
	certificate := formalGLMPhase21StickyCertificate{
		Version: formalGLMPhase21StickyVersion, Purpose: formalGLMPhase21StickyPurpose,
		ArtifactID: fixture.artifactID, Artifact: fixture.artifact,
		SamplerV2Contract:              &contract,
		SourceScientificArtifactSHA256: hash("source-science"),
		SourceWorkloadSHA256:           hash("source-workload"),
		SourceContextSHA256:            hash("source-context"),
		SourceLinkTableSHA256:          hash("source-link"),
		Phase15PlanSHA256:              hash("plan"), KernelSpecSHA256: hash("kernel"),
		CapsuleID: hash("capsule"), ManifestSHA256: hash("manifest"),
		ReleaseBindingSHA256:         hash("binding"),
		BackendSelectionSHA256:       hash("backend"),
		SourceReleaseContractSHA256:  hash("source-contract"),
		NoiseCommitmentEvidence:      evidence,
		SourceCertificateSHA256:      hash("source-certificate"),
		CustodianApprovalSetSHA256:   hash("custodian-approvals"),
		SourceAuthoritySetSHA256:     hash("source-authorities"),
		SourceReleaseInstanceID:      hash("source-instance"),
		DPReleaseInstanceID:          hash("dp-instance"),
		ReleaseContractSHA256:        hash("release-contract"),
		Family:                       fixture.artifact.Family,
		SelectedBackend:              formalGLMPhase16BackendOneDraw,
		SelectionReason:              "sampler_v2_test_finalizer",
		NominalVarianceMultiplier:    1,
		NominalStandardDeviation:     "one_full_draw",
		Simultaneous95AbsSteps:       "23",
		Epsilon:                      fixture.artifact.EpsilonRational,
		Delta:                        "0.000001",
		L2SensitivitySteps:           fixture.artifact.SensitivitySteps,
		SensitivityCertificateSHA256: hash("sensitivity-certificate"),
		OutputLatticeBits:            fixture.artifact.OutputLatticeBits,
		NoWrapCertificate:            "ring128_headroom_checked_v1",
		VectorSHA256:                 vectorSHA256,
		ClampedScaledValues:          values,
		PrivacyScope:                 "per_canonical_artifact_v1",
		GlobalCompositionClaim:       false,
		SingleCommonDPVector:         true,
		ExactlyOnceDPOpening:         false,
		UnlimitedDeterministicReplay: true,
		UnlimitedPostprocessing:      true,
		HistoryCanDenyOperation:      false,
		AdmissionPolicy:              "none_v1",
		OpeningsPerformed:            1,
		ReplayReadsSource:            false,
		ReplayInvokesSampler:         false,
		ReplayInvokesFinalizer:       false,
		ProductionReady:              false,
		Blockers: []string{
			"formal_glm_phase21_sampler_v2_inflight_output_not_durable_by_canonical_artifact_v1",
		},
		AuthorityReceipts: nil,
	}
	if err := formalGLMPhase21ValidateStickyCertificateCore(
		certificate, fixture.pins); err != nil {
		t.Fatal(err)
	}
	return certificate
}

func formalGLMPhase21SamplerV2TestContractForArtifact(
	t testing.TB,
	artifact formalGLMPhase21StickyArtifact,
	artifactID, mode string,
	pins map[string]ed25519.PublicKey,
	keys map[string]ed25519.PrivateKey,
	roots map[string][32]byte,
) formalGLMPhase21SamplerV2Contract {
	t.Helper()
	commitments := make([]formalGLMPhase21SamplerV2Commitment, 2)
	for index, authority := range artifact.NoiseAuthorities {
		var err error
		_, commitments[index], err = formalGLMPhase21SamplerV2Derive(
			roots[authority.PeerName], artifactID, mode, authority.Role,
			authority.PeerName, authority.PeerID)
		if err != nil {
			t.Fatal(err)
		}
	}
	unsigned, err := formalGLMPhase21BuildSamplerV2Contract(
		artifact, artifactID, mode, commitments, pins)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(artifact.CustodianPeers))
	for _, peer := range artifact.CustodianPeers {
		signature, signErr := formalGLMPhase21SignSamplerV2Contract(
			unsigned, peer, keys[peer])
		if signErr != nil {
			t.Fatal(signErr)
		}
		signatures = append(signatures, signature)
	}
	sealed, err := formalGLMPhase21SealSamplerV2Contract(
		unsigned, signatures, pins)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func formalGLMPhase21SamplerV2TestAuthorize(
	t testing.TB,
	contract formalGLMPhase21SamplerV2Contract,
	pins map[string]ed25519.PublicKey,
	keys map[string]ed25519.PrivateKey,
	roots map[string][32]byte,
) []formalGLMPhase21SamplerV2Authorization {
	t.Helper()
	authorizations := make([]formalGLMPhase21SamplerV2Authorization, 0, 2)
	for _, authority := range contract.Artifact.NoiseAuthorities {
		storageRoot := sha256.Sum256(
			[]byte(t.Name() + "/authorize/" + authority.PeerName))
		store, err := newFormalGLMPhase21StickyReleaseStore(
			filepath.Join(t.TempDir(), authority.PeerName), authority.PeerName,
			storageRoot, pins)
		if err != nil {
			t.Fatal(err)
		}
		authorization, replayed, err := store.AuthorizeSamplerV2Once(
			contract, roots[authority.PeerName], keys[authority.PeerName],
			authorizations)
		store.close()
		if err != nil || replayed {
			t.Fatalf("sampler-v2 authorization: %v / replay=%v", err, replayed)
		}
		authorizations = append(authorizations, authorization)
	}
	return authorizations
}

func formalGLMPhase21SamplerV2TestRunOneDraw(
	t testing.TB,
	fixture formalGLMPhase21TestFixture,
	contract formalGLMPhase21SamplerV2Contract,
	authorizations []formalGLMPhase21SamplerV2Authorization,
) map[string]formalGLMPhase21OneDrawLocalOutput {
	t.Helper()
	peers := fixture.formal.ctx.ComputePeers
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(90 * time.Second))
	_ = right.SetDeadline(time.Now().Add(90 * time.Second))
	outputs := make(map[string]formalGLMPhase21OneDrawLocalOutput, 2)
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
			value, err := formalGLMPhase21RunOneDrawLocalV2(
				connection, fixture.stores[peer], fixture.capsule,
				fixture.request, fixture.backendSignatures,
				fixture.workerSignatures, fixture.seeds[peer],
				fixture.seeds[peer],
				fixture.formal.identities.private[peer], contract,
				authorizations, nil)
			lock.Lock()
			outputs[peer], errorsByPeer[peer] = value, err
			lock.Unlock()
		}()
	}
	wait.Wait()
	for _, peer := range peers {
		if errorsByPeer[peer] != nil {
			t.Fatalf("sampler-v2 one-draw peer %s: %v", peer, errorsByPeer[peer])
		}
	}
	return outputs
}

func formalGLMPhase21SamplerV2TestRunFull(
	t testing.TB,
	fixture formalGLMPhase21FullTestFixture,
	contract formalGLMPhase21SamplerV2Contract,
	authorizations []formalGLMPhase21SamplerV2Authorization,
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
			value, err := formalGLMPhase21RunFullLocalV2(
				connection, fixture.stores[peer], fixture.capsule,
				fixture.productiveRequest, fixture.backendSignatures,
				fixture.full.request, fixture.full.contract,
				fixture.full.roots[peer],
				fixture.full.formal.identities.private[peer],
				contract, authorizations)
			lock.Lock()
			outputs[peer], errorsByPeer[peer] = value, err
			lock.Unlock()
		}()
	}
	wait.Wait()
	for _, peer := range peers {
		if errorsByPeer[peer] != nil {
			t.Fatalf("sampler-v2 full peer %s: %v", peer, errorsByPeer[peer])
		}
	}
	return outputs
}

func formalGLMPhase21StickyTestSetup(t testing.TB,
	custodians int) formalGLMPhase21StickyTestFixture {
	t.Helper()
	phase21 := formalGLMPhase21TestSetup(t, custodians, "binomial")
	outputs := formalGLMPhase21TestRun(t, phase21)
	peers := phase21.formal.ctx.ComputePeers
	releaseStore := make(map[string]*jointDPBiomedicalGaussianOneDrawDurableReleaseStore, 2)
	releaseRoot := make(map[string]string, 2)
	local := make(map[string]jointDPBiomedicalGaussianOneDrawLocalRelease, 2)
	for _, peer := range peers {
		root := filepath.Join(t.TempDir(), "local-release", peer)
		store, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
			root, peer, phase21.runtime[peer].backend,
			phase21.formal.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		other := peers[0]
		if other == peer {
			other = peers[1]
		}
		local[peer], err = formalGLMPhase21FinalizeOneDrawLocal(
			phase21.stores[peer], store, outputs[peer], outputs[other], nil)
		if err != nil {
			t.Fatal(err)
		}
		releaseStore[peer], releaseRoot[peer] = store, root
	}
	certified, err := formalGLMPhase21CertifyOneDrawRelease(
		local[peers[0]], local[peers[1]], outputs[peers[0]].Admission)
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := phase21.stores[peers[0]].Load()
	if err != nil {
		t.Fatal(err)
	}
	plan := source.Plan
	source.clear()
	unsigned, err := formalGLMPhase21BuildStickyCertificate(
		certified, outputs[peers[0]].Admission.Compiled.Binding,
		outputs[peers[0]].Admission.Token, plan,
		phase21.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]jointDPBiomedicalGaussianSignature, 0, 2)
	for _, authority := range unsigned.Artifact.NoiseAuthorities {
		root := filepath.Join(t.TempDir(), "sticky-signer", authority.PeerName)
		store := formalGLMPhase21StickyTestStore(t,
			formalGLMPhase21StickyTestFixture{phase21: phase21},
			authority.PeerName, root)
		receipt, replayed, signErr := store.SignOnce(
			unsigned, phase21.formal.identities.private[authority.PeerName],
			receipts)
		store.close()
		if signErr != nil {
			t.Fatal(signErr)
		}
		if replayed {
			t.Fatal("initial sticky authority signature was a replay")
		}
		receipts = append(receipts, receipt)
	}
	certificate, err := formalGLMPhase21SealStickyCertificate(
		unsigned, receipts, phase21.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return formalGLMPhase21StickyTestFixture{
		phase21: phase21, outputs: outputs,
		releaseStore: releaseStore, releaseRoot: releaseRoot, local: local,
		certified: certified, certificate: certificate, plan: plan,
	}
}

func (fixture *formalGLMPhase21StickyTestFixture) close() {
	for peer := range fixture.outputs {
		value := fixture.outputs[peer]
		value.clear()
	}
	fixture.phase21.close()
}

func formalGLMPhase21StickyTestStore(t testing.TB,
	fixture formalGLMPhase21StickyTestFixture, peer, root string,
) *formalGLMPhase21StickyReleaseStore {
	t.Helper()
	storageRoot := sha256.Sum256([]byte(t.Name() + "/sticky-store/" + peer))
	store, err := newFormalGLMPhase21StickyReleaseStore(
		root, peer, storageRoot, fixture.phase21.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func formalGLMPhase21StickyAssertNoForbiddenFields(t testing.TB,
	encoded []byte,
) {
	t.Helper()
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"ledger", "reservation", "lifetime", "request", "rate_limit",
		"catalog", "quota", "preclamp", "pre_clamp", "dp_share",
		"protected_share", "private_key", "seed_key",
	}
	var inspect func(any)
	inspect = func(candidate any) {
		switch typed := candidate.(type) {
		case map[string]any:
			for name, child := range typed {
				lower := strings.ToLower(name)
				for _, disallowed := range forbidden {
					if strings.Contains(lower, disallowed) {
						t.Fatalf("sticky persistence exposed forbidden field %q", name)
					}
				}
				if name == "certificate_json" {
					if nested, ok := child.(string); ok {
						var decoded any
						if err := json.Unmarshal([]byte(nested), &decoded); err != nil {
							t.Fatal(err)
						}
						inspect(decoded)
						continue
					}
				}
				inspect(child)
			}
		case []any:
			for _, child := range typed {
				inspect(child)
			}
		}
	}
	inspect(value)
}

func TestFormalGLMPhase21SamplerV2ContractGuardK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase21SamplerV2TestSetup(
				t, custodians, formalGLMPhase21SamplerV2OneDraw)
			if err := formalGLMPhase21ValidateSamplerV2Contract(
				fixture.contract, fixture.pins); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(fixture.contract)
			if err != nil {
				t.Fatal(err)
			}
			formalGLMPhase21StickyAssertNoForbiddenFields(t, encoded)
			lower := bytes.ToLower(encoded)
			for _, forbidden := range []string{
				"run_id", "epoch", "receipt", "backend_selection",
				"release_instance", "handoff", "ledger", "reservation",
				"lifetime", "request", "rate", "catalog", "quota",
			} {
				if bytes.Contains(lower, []byte(forbidden)) {
					t.Fatalf("sampler-v2 contract contains operational field %q", forbidden)
				}
			}

			authorizations := make([]formalGLMPhase21SamplerV2Authorization, 0, 2)
			roots := make(map[string]string, 2)
			for _, authority := range fixture.artifact.NoiseAuthorities {
				root := filepath.Join(t.TempDir(), "sampler-v2-guard", authority.PeerName)
				roots[authority.PeerName] = root
				storageRoot := sha256.Sum256(
					[]byte(t.Name() + "/guard-store/" + authority.PeerName))
				store, storeErr := newFormalGLMPhase21StickyReleaseStore(
					root, authority.PeerName, storageRoot, fixture.pins)
				if storeErr != nil {
					t.Fatal(storeErr)
				}
				receipt, replayed, authErr := store.AuthorizeSamplerV2Once(
					fixture.contract, fixture.roots[authority.PeerName],
					fixture.keys[authority.PeerName], authorizations)
				store.close()
				if authErr != nil || replayed {
					t.Fatalf("initial sampler-v2 guard: %v / replay=%v",
						authErr, replayed)
				}
				authorizations = append(authorizations, receipt)
			}
			if err := formalGLMPhase21ValidateSamplerV2Authorizations(
				fixture.contract, authorizations, fixture.pins); err != nil {
				t.Fatal(err)
			}
			independent := append(
				[]formalGLMPhase21SamplerV2Authorization(nil), authorizations...)
			independent[1].PredecessorAuthorizationSHA256 =
				sha256Hex([]byte(t.Name() + "/not-the-garbler-authorization"))
			independent[1].Signature = nil
			message, messageErr := formalGLMPhase21SamplerV2AuthorizationMessage(
				independent[1])
			if messageErr != nil {
				t.Fatal(messageErr)
			}
			independent[1].Signature = ed25519.Sign(
				fixture.keys[fixture.artifact.NoiseAuthorities[1].PeerName], message)
			if err := formalGLMPhase21ValidateSamplerV2Authorizations(
				fixture.contract, independent, fixture.pins); err == nil {
				t.Fatal("independently signed evaluator authorization escaped predecessor binding")
			}

			for index, authority := range fixture.artifact.NoiseAuthorities {
				storageRoot := sha256.Sum256(
					[]byte(t.Name() + "/guard-store/" + authority.PeerName))
				restarted, restartErr := newFormalGLMPhase21StickyReleaseStore(
					roots[authority.PeerName], authority.PeerName,
					storageRoot, fixture.pins)
				if restartErr != nil {
					t.Fatal(restartErr)
				}
				replayedReceipt, replayed, authErr :=
					restarted.AuthorizeSamplerV2Once(
						fixture.contract, fixture.roots[authority.PeerName],
						fixture.keys[authority.PeerName], authorizations[:index])
				if authErr != nil || !replayed ||
					!reflect.DeepEqual(replayedReceipt, authorizations[index]) {
					t.Fatalf("sampler-v2 guard restart changed receipt: %v", authErr)
				}
				guardPath, pathErr := restarted.samplerV2GuardRelativePath(
					fixture.artifactID, false)
				if pathErr != nil {
					t.Fatal(pathErr)
				}
				guardBytes, readErr := os.ReadFile(filepath.Join(restarted.dir, guardPath))
				if readErr != nil {
					t.Fatal(readErr)
				}
				formalGLMPhase21StickyAssertNoForbiddenFields(t, guardBytes)
				restarted.close()
			}
		})
	}
}

func TestFormalGLMPhase21SamplerV2CanonicalPurposeAndDivergentStores(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 3, formalGLMPhase21SamplerV2OneDraw)
	garbler := fixture.artifact.NoiseAuthorities[0]
	seedA, commitmentA, err := formalGLMPhase21SamplerV2Derive(
		fixture.roots[garbler.PeerName], fixture.artifactID,
		formalGLMPhase21SamplerV2OneDraw, garbler.Role,
		garbler.PeerName, garbler.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	seedB, commitmentB, err := formalGLMPhase21SamplerV2Derive(
		fixture.roots[garbler.PeerName], fixture.artifactID,
		formalGLMPhase21SamplerV2OneDraw, garbler.Role,
		garbler.PeerName, garbler.PeerID)
	if err != nil || seedA != seedB || !reflect.DeepEqual(commitmentA, commitmentB) {
		t.Fatal("operationally equivalent request changed sampler-v2 material")
	}
	changedArtifact := fixture.artifact
	changedArtifact.CanonicalScienceSHA256 =
		sha256Hex([]byte(t.Name() + "/different-science"))
	changedID, err := formalGLMPhase21StickyArtifactID(changedArtifact)
	if err != nil || changedID == fixture.artifactID {
		t.Fatal("scientific divergence did not change canonical artifact id")
	}
	changedSeed, _, err := formalGLMPhase21SamplerV2Derive(
		fixture.roots[garbler.PeerName], changedID,
		formalGLMPhase21SamplerV2OneDraw, garbler.Role,
		garbler.PeerName, garbler.PeerID)
	if err != nil || changedSeed == seedA {
		t.Fatal("scientific divergence reused sampler-v2 seed")
	}
	clear(seedA[:])
	clear(seedB[:])
	clear(changedSeed[:])

	fullContract := formalGLMPhase21SamplerV2TestContractForArtifact(
		t, fixture.artifact, fixture.artifactID,
		formalGLMPhase21SamplerV2Full, fixture.pins, fixture.keys, fixture.roots)
	garblerRoot := filepath.Join(t.TempDir(), "store-a-garbler")
	evaluatorRoot := filepath.Join(t.TempDir(), "store-b-evaluator")
	garblerStorage := sha256.Sum256([]byte(t.Name() + "/store-a"))
	evaluatorStorage := sha256.Sum256([]byte(t.Name() + "/store-b"))
	garblerStore, err := newFormalGLMPhase21StickyReleaseStore(
		garblerRoot, fixture.artifact.NoiseAuthorities[0].PeerName,
		garblerStorage, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	garblerAuthorization, replayed, err := garblerStore.AuthorizeSamplerV2Once(
		fixture.contract, fixture.roots[garbler.PeerName],
		fixture.keys[garbler.PeerName], nil)
	if err != nil || replayed {
		t.Fatalf("store A authorization: %v / %v", err, replayed)
	}
	defer garblerStore.close()
	evaluator := fixture.artifact.NoiseAuthorities[1]
	evaluatorStore, err := newFormalGLMPhase21StickyReleaseStore(
		evaluatorRoot, evaluator.PeerName, evaluatorStorage, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	defer evaluatorStore.close()
	if _, _, err := evaluatorStore.AuthorizeSamplerV2Once(
		fullContract, fixture.roots[evaluator.PeerName],
		fixture.keys[evaluator.PeerName],
		[]formalGLMPhase21SamplerV2Authorization{garblerAuthorization}); err == nil {
		t.Fatal("divergent store B combined another sampler mode with store A")
	}
	evaluatorAuthorization, replayed, err := evaluatorStore.AuthorizeSamplerV2Once(
		fixture.contract, fixture.roots[evaluator.PeerName],
		fixture.keys[evaluator.PeerName],
		[]formalGLMPhase21SamplerV2Authorization{garblerAuthorization})
	if err != nil || replayed {
		t.Fatalf("matching store B authorization: %v / %v", err, replayed)
	}
	if err := formalGLMPhase21ValidateSamplerV2Authorizations(
		fixture.contract,
		[]formalGLMPhase21SamplerV2Authorization{
			garblerAuthorization, evaluatorAuthorization,
		}, fixture.pins); err != nil {
		t.Fatal(err)
	}
	if _, _, err := garblerStore.AuthorizeSamplerV2Once(
		fullContract, fixture.roots[garbler.PeerName],
		fixture.keys[garbler.PeerName], nil); err == nil {
		t.Fatal("one artifact acquired two durable sampler modes")
	}
}

func TestFormalGLMPhase21SamplerV2OneDrawErasesLegacyRunIdentity(t *testing.T) {
	fixture := formalGLMPhase21TestSetup(t, 2, "binomial")
	defer fixture.close()
	peer := fixture.formal.ctx.ComputePeers[0]
	runtime, _, err := formalGLMPhase21LoadAndAdmit(
		fixture.stores[peer], fixture.capsule, fixture.request,
		fixture.backendSignatures, fixture.workerSignatures)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.clear()
	legacy, _, _, _, _, err := formalGLMPhase21SourceMaterial(runtime)
	if err != nil {
		t.Fatal(err)
	}
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		runtime.Admission.Productive.Compiled.Binding,
		runtime.Source.Plan, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	contract := formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
		fixture.formal.identities.public, fixture.formal.identities.private,
		fixture.seeds)
	canonicalA, err := formalGLMPhase21OneDrawSamplerV2Spec(legacy, contract)
	if err != nil {
		t.Fatal(err)
	}
	legacyB := legacy
	legacyB.TranscriptHash = sha256.Sum256([]byte(t.Name() + "/epoch-run"))
	legacyB.ReleaseBinding = sha256.Sum256([]byte(t.Name() + "/release"))
	legacyB.CrossSignedPolicy = legacyB.ReleaseBinding
	legacyB.GarblerCommitmentContext = sha256.Sum256([]byte(t.Name() + "/g-context"))
	legacyB.EvaluatorCommitmentContext = sha256.Sum256([]byte(t.Name() + "/e-context"))
	legacyB.GarblerSeedCommitment = sha256.Sum256([]byte(t.Name() + "/g-seed"))
	legacyB.EvaluatorSeedCommitment = sha256.Sum256([]byte(t.Name() + "/e-seed"))
	legacyB.ReleaseBindingCanonicalJSON = `{"legacy":"different"}`
	canonicalB, err := formalGLMPhase21OneDrawSamplerV2Spec(legacyB, contract)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(canonicalA, canonicalB) ||
		canonicalA.globalStreamDigest() != canonicalB.globalStreamDigest() ||
		canonicalA.purpose() != canonicalB.purpose() {
		t.Fatal("legacy run/epoch/release evidence rerolled sampler-v2")
	}
	changed := contract
	changed.Artifact.EpsilonRational = "2"
	changed.ArtifactID, err = formalGLMPhase21StickyArtifactID(changed.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMPhase21OneDrawSamplerV2Spec(
		legacy, changed); err == nil {
		t.Fatal("changed DP semantics reused the one-draw sampler-v2 spec")
	}
}

func TestFormalGLMPhase21SamplerV2OneDrawExecutionK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase21TestSetup(t, custodians, "binomial")
			defer fixture.close()
			peer := fixture.formal.ctx.ComputePeers[0]
			runtime, _, err := formalGLMPhase21LoadAndAdmit(
				fixture.stores[peer], fixture.capsule, fixture.request,
				fixture.backendSignatures, fixture.workerSignatures)
			if err != nil {
				t.Fatal(err)
			}
			artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
				runtime.Admission.Productive.Compiled.Binding,
				runtime.Source.Plan, fixture.formal.identities.public)
			runtime.clear()
			if err != nil {
				t.Fatal(err)
			}
			contract := formalGLMPhase21SamplerV2TestContractForArtifact(
				t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
				fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			authorizations := formalGLMPhase21SamplerV2TestAuthorize(
				t, contract, fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			first := formalGLMPhase21SamplerV2TestRunOneDraw(
				t, fixture, contract, authorizations)
			defer func() {
				for peer := range first {
					value := first[peer]
					value.clear()
				}
			}()
			second := formalGLMPhase21SamplerV2TestRunOneDraw(
				t, fixture, contract, authorizations)
			defer func() {
				for peer := range second {
					value := second[peer]
					value.clear()
				}
			}()
			for _, peer := range fixture.formal.ctx.ComputePeers {
				if !reflect.DeepEqual(first[peer].Shares, second[peer].Shares) ||
					!reflect.DeepEqual(first[peer].Receipt, second[peer].Receipt) {
					t.Fatalf("sampler-v2 retry changed peer %s output", peer)
				}
			}
		})
	}
}

func TestFormalGLMPhase21SamplerV2FullExecutionK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase21FullTestSetup(t, custodians, "binomial")
			defer fixture.close()
			peer := fixture.full.formal.ctx.ComputePeers[0]
			runtime, _, err := formalGLMPhase21LoadAndAdmitFull(
				fixture.stores[peer], fixture.capsule,
				fixture.productiveRequest, fixture.backendSignatures,
				fixture.full.request, fixture.full.contract)
			if err != nil {
				t.Fatal(err)
			}
			artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
				*runtime.Admission.Full.formalBinding,
				runtime.Source.Plan, fixture.full.formal.identities.public)
			runtime.clear()
			if err != nil {
				t.Fatal(err)
			}
			contract := formalGLMPhase21SamplerV2TestContractForArtifact(
				t, artifact, artifactID, formalGLMPhase21SamplerV2Full,
				fixture.full.formal.identities.public,
				fixture.full.formal.identities.private, fixture.full.roots)
			authorizations := formalGLMPhase21SamplerV2TestAuthorize(
				t, contract, fixture.full.formal.identities.public,
				fixture.full.formal.identities.private, fixture.full.roots)
			outputs := formalGLMPhase21SamplerV2TestRunFull(
				t, fixture, contract, authorizations)
			for _, peer := range fixture.full.formal.ctx.ComputePeers {
				output := outputs[peer]
				if output.PeerShare.share.samplerV2 == nil ||
					output.PeerShare.share.output.ReleaseContractHash != artifactID ||
					output.PeerShare.share.output.TranscriptHash != artifactID {
					t.Fatalf("full peer %s did not use canonical sampler-v2 input", peer)
				}
				if err := jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
					output.Admission, fixture.full.formal.identities.public,
					output.PeerShare, fixture.full.backend); err != nil {
					t.Fatal(err)
				}
				output.clear()
			}
		})
	}
}

func TestFormalGLMPhase21SamplerV2FullStickyLifecycleK2(t *testing.T) {
	fixture := formalGLMPhase21FullTestSetup(t, 2, "binomial")
	defer fixture.close()
	peers := fixture.full.formal.ctx.ComputePeers
	reference := peers[0]
	runtime, _, err := formalGLMPhase21LoadAndAdmitFull(
		fixture.stores[reference], fixture.capsule,
		fixture.productiveRequest, fixture.backendSignatures,
		fixture.full.request, fixture.full.contract)
	if err != nil {
		t.Fatal(err)
	}
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		*runtime.Admission.Full.formalBinding,
		runtime.Source.Plan, fixture.full.formal.identities.public)
	plan := runtime.Source.Plan
	runtime.clear()
	if err != nil {
		t.Fatal(err)
	}
	contract := formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, artifactID, formalGLMPhase21SamplerV2Full,
		fixture.full.formal.identities.public,
		fixture.full.formal.identities.private, fixture.full.roots)
	authorizations := formalGLMPhase21SamplerV2TestAuthorize(
		t, contract, fixture.full.formal.identities.public,
		fixture.full.formal.identities.private, fixture.full.roots)
	outputs := formalGLMPhase21SamplerV2TestRunFull(
		t, fixture, contract, authorizations)
	defer func() {
		for peer := range outputs {
			value := outputs[peer]
			value.clear()
		}
	}()
	local := make(map[string]jointDPBiomedicalGaussianFullLocalRelease, 2)
	for _, peer := range peers {
		releaseStore, storeErr := newFormalGLMPhase16FullDurableReleaseStore(
			filepath.Join(t.TempDir(), "v2-full-release", peer), peer,
			fixture.full.backend, fixture.full.formal.identities.private[peer])
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		other := peers[0]
		if other == peer {
			other = peers[1]
		}
		local[peer], storeErr = formalGLMPhase21FinalizeFullLocal(
			fixture.stores[peer], releaseStore,
			outputs[peer], outputs[other], nil)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
	}
	certified, err := formalGLMPhase21CertifyFullRelease(
		local[peers[0]], local[peers[1]], outputs[peers[0]],
		fixture.full.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := formalGLMPhase21BuildStickyCertificateV2(
		certified, *outputs[reference].Admission.formalBinding,
		*outputs[reference].Admission.formalToken, plan,
		fixture.full.formal.identities.public, contract)
	if err != nil || unsigned.ExactlyOnceDPOpening ||
		unsigned.SelectedBackend != formalGLMPhase16BackendFull ||
		unsigned.ProductionReady || !formalGLMPhase19Contains(unsigned.Blockers,
		"formal_glm_phase21_sampler_v2_inflight_output_not_durable_by_canonical_artifact_v1") {
		t.Fatalf("invalid full sampler-v2 sticky certificate: %v", err)
	}
	receipts := make([]jointDPBiomedicalGaussianSignature, 0, 2)
	signerStores := make(map[string]*formalGLMPhase21StickyReleaseStore, 2)
	var durable formalGLMPhase21StickyCertificate
	for _, authority := range artifact.NoiseAuthorities {
		storageRoot := sha256.Sum256(
			[]byte(t.Name() + "/full-post-output/" + authority.PeerName))
		signerStore, storeErr := newFormalGLMPhase21StickyReleaseStore(
			filepath.Join(t.TempDir(), "full-post-output", authority.PeerName),
			authority.PeerName, storageRoot,
			fixture.full.formal.identities.public)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		signerStores[authority.PeerName] = signerStore
		defer signerStore.close()
		candidate, finalizedReplay, storeErr := signerStore.FinalizeSamplerV2Once(
			contract, func() (formalGLMPhase21StickyCertificate, error) {
				return unsigned, nil
			}, nil)
		if storeErr != nil || finalizedReplay {
			t.Fatalf("full sampler-v2 durable finalizer: %v / %v",
				storeErr, finalizedReplay)
		}
		if durable.ArtifactID == "" {
			durable = candidate
		} else if !reflect.DeepEqual(durable, candidate) {
			t.Fatal("full authorities staged divergent durable candidates")
		}
		receipt, replayed, storeErr := signerStore.SignOnce(
			candidate, fixture.full.formal.identities.private[authority.PeerName],
			receipts)
		if storeErr != nil || replayed {
			t.Fatalf("full sampler-v2 SignOnce: %v / %v", storeErr, replayed)
		}
		receipts = append(receipts, receipt)
	}
	certificate, err := formalGLMPhase21SealStickyCertificate(
		durable, receipts, fixture.full.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	publicationStore := signerStores[reference]
	crashAfterConsume := errors.New("crash after full source consume")
	publication, removed, err := formalGLMPhase21CommitFullAndCleanup(
		publicationStore, fixture.stores[reference], outputs[reference],
		certified, certificate, func(phase string) error {
			if phase == "after_source_consume_before_durable_ack" {
				return crashAfterConsume
			}
			return nil
		})
	if !errors.Is(err, crashAfterConsume) ||
		removed != outputs[reference].HandoffBytes ||
		fileExists(fixture.stores[reference].recordPath) {
		t.Fatalf("full sampler-v2 sticky commit: %d / %v", removed, err)
	}
	removed, err = formalGLMPhase21CleanupCommittedFull(
		publicationStore, fixture.stores[reference], publication.ArtifactID,
		fixture.capsule, fixture.productiveRequest,
		fixture.backendSignatures, fixture.full.request, fixture.full.contract)
	if err != nil || removed != 0 {
		t.Fatalf("full durable ack recovery: %d / %v", removed, err)
	}
	replay, err := publicationStore.Replay(publication.ArtifactID)
	if err != nil || !bytes.Equal(replay.Certificate, publication.Certificate) {
		t.Fatal("full sampler-v2 sticky replay changed public bytes")
	}
	formalGLMPhase21StickyAssertNoForbiddenFields(t, replay.Certificate)
}

func TestFormalGLMPhase21SamplerV2PreflightBeforePhase20AndPublicReplay(t *testing.T) {
	fixture := formalGLMPhase21TestSetup(t, 2, "binomial")
	defer fixture.close()
	peers := fixture.formal.ctx.ComputePeers
	reference := peers[0]
	runtime, _, err := formalGLMPhase21LoadAndAdmit(
		fixture.stores[reference], fixture.capsule, fixture.request,
		fixture.backendSignatures, fixture.workerSignatures)
	if err != nil {
		t.Fatal(err)
	}
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		runtime.Admission.Productive.Compiled.Binding,
		runtime.Source.Plan, fixture.formal.identities.public)
	plan := runtime.Source.Plan
	binding := runtime.Admission.Productive.Compiled.Binding
	runtime.clear()
	if err != nil {
		t.Fatal(err)
	}
	contract := formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
		fixture.formal.identities.public, fixture.formal.identities.private,
		fixture.seeds)
	authorizations := formalGLMPhase21SamplerV2TestAuthorize(
		t, contract, fixture.formal.identities.public,
		fixture.formal.identities.private, fixture.seeds)

	samplerCalls := 0
	outputs := formalGLMPhase21SamplerV2TestRunOneDraw(
		t, fixture, contract, authorizations)
	samplerCalls += len(outputs)
	defer func() {
		for peer := range outputs {
			value := outputs[peer]
			value.clear()
		}
	}()
	local := make(map[string]jointDPBiomedicalGaussianOneDrawLocalRelease, 2)
	finalizerCalls := 0
	for _, peer := range peers {
		other := peers[0]
		if other == peer {
			other = peers[1]
		}
		releaseStore, storeErr :=
			newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				filepath.Join(t.TempDir(), "v2-local-release", peer), peer,
				fixture.runtime[peer].backend,
				fixture.formal.identities.private[peer])
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		local[peer], storeErr = formalGLMPhase21FinalizeOneDrawLocal(
			fixture.stores[peer], releaseStore,
			outputs[peer], outputs[other], nil)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		finalizerCalls++
	}
	certified, err := formalGLMPhase21CertifyOneDrawRelease(
		local[peers[0]], local[peers[1]], outputs[peers[0]].Admission)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := formalGLMPhase21BuildStickyCertificateV2(
		certified, binding, outputs[reference].Admission.Token,
		plan, fixture.formal.identities.public, contract)
	if err != nil {
		t.Fatal(err)
	}
	if unsigned.ExactlyOnceDPOpening || unsigned.ProductionReady ||
		formalGLMPhase19Contains(unsigned.Blockers,
			"formal_glm_phase21_preflight_not_wired_before_phase20_v1") ||
		formalGLMPhase19Contains(unsigned.Blockers,
			"formal_glm_phase21_noise_purpose_not_derived_from_canonical_artifact_id_v1") {
		t.Fatal("sampler-v2 certificate did not close only its two lifecycle blockers")
	}
	if !formalGLMPhase19Contains(unsigned.Blockers,
		"formal_glm_phase21_sampler_v2_inflight_output_not_durable_by_canonical_artifact_v1") {
		t.Fatal("sampler-v2 certificate overstated inflight durability")
	}
	receipts := make([]jointDPBiomedicalGaussianSignature, 0, 2)
	signerStores := make(map[string]*formalGLMPhase21StickyReleaseStore, 2)
	var durable formalGLMPhase21StickyCertificate
	for _, authority := range artifact.NoiseAuthorities {
		storageRoot := sha256.Sum256(
			[]byte(t.Name() + "/post-output-sign/" + authority.PeerName))
		signerStore, storeErr := newFormalGLMPhase21StickyReleaseStore(
			filepath.Join(t.TempDir(), "post-output-sign", authority.PeerName),
			authority.PeerName, storageRoot, fixture.formal.identities.public)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		signerStores[authority.PeerName] = signerStore
		defer signerStore.close()
		candidate, finalizedReplay, storeErr := signerStore.FinalizeSamplerV2Once(
			contract, func() (formalGLMPhase21StickyCertificate, error) {
				return unsigned, nil
			}, nil)
		if storeErr != nil || finalizedReplay {
			t.Fatalf("sampler-v2 durable finalizer spool: %v / %v",
				storeErr, finalizedReplay)
		}
		if durable.ArtifactID == "" {
			durable = candidate
		} else if !reflect.DeepEqual(durable, candidate) {
			t.Fatal("sampler-v2 authorities finalized different durable candidates")
		}
		receipt, replayed, storeErr := signerStore.SignOnce(
			candidate, fixture.formal.identities.private[authority.PeerName], receipts)
		if storeErr != nil || replayed {
			t.Fatalf("sampler-v2 post-output SignOnce: %v / %v", storeErr, replayed)
		}
		receipts = append(receipts, receipt)
	}
	certificate, err := formalGLMPhase21SealStickyCertificate(
		durable, receipts, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.ExactlyOnceDPOpening ||
		certificate.DurablePublicationProtocol != formalGLMPhase21DurableV2Version ||
		formalGLMPhase19Contains(certificate.Blockers,
			"formal_glm_phase21_sampler_v2_inflight_output_not_durable_by_canonical_artifact_v1") {
		t.Fatal("sampler-v2 durable certificate did not close inflight blocker")
	}
	publicationStore := signerStores[reference]
	crashAfterSticky := errors.New("sampler-v2 crash after sticky commit")
	publication, removed, err := formalGLMPhase21CommitOneDrawAndCleanup(
		publicationStore, fixture.stores[reference], outputs[reference],
		certified, certificate, func(phase string) error {
			if phase != "after_sticky_commit_before_source_consume" ||
				!fileExists(fixture.stores[reference].recordPath) {
				t.Fatal("sampler-v2 source was consumed before sticky commit")
			}
			return crashAfterSticky
		})
	if !errors.Is(err, crashAfterSticky) || removed != 0 ||
		!fileExists(fixture.stores[reference].recordPath) {
		t.Fatalf("sampler-v2 commit-before-consume failed: %d / %v", removed, err)
	}
	removed, err = formalGLMPhase21CleanupCommittedOneDraw(
		publicationStore, fixture.stores[reference], publication.ArtifactID,
		fixture.capsule, fixture.request, fixture.backendSignatures,
		fixture.workerSignatures)
	if err != nil || removed != outputs[reference].HandoffBytes ||
		fileExists(fixture.stores[reference].recordPath) {
		t.Fatalf("sampler-v2 crash recovery failed: %d / %v", removed, err)
	}
	if ackReplayed, ackErr := publicationStore.AckDurableV2(publication); ackErr != nil || !ackReplayed {
		t.Fatalf("sampler-v2 cleanup did not durably ack: %v / %v",
			ackErr, ackReplayed)
	}
	formalGLMPhase21StickyAssertNoForbiddenFields(t, publication.Certificate)

	hookCalls := 0
	beforeSampler, beforeFinalizer := samplerCalls, finalizerCalls
	replay, err := formalGLMPhase21PreflightOrCommitHandoffV2(
		publicationStore, nil, binding, plan,
		formalGLMPhase19Context{}, formalGLMPhase19ScheduleResult{},
		formalGLMPhase21SamplerV2Contract{}, nil,
		func(string) error { hookCalls++; return nil })
	if err != nil || !replay.Replayed ||
		!bytes.Equal(replay.Publication.Certificate, publication.Certificate) ||
		hookCalls != 0 || samplerCalls != beforeSampler ||
		finalizerCalls != beforeFinalizer {
		t.Fatalf("public replay touched Phase20/sampler/finalizer: %#v / %v",
			replay, err)
	}
}

func TestFormalGLMPhase21SamplerV2PrePhase20CrashRestartAndConcurrency(t *testing.T) {
	fixture := formalGLMPhase21TestSetup(t, 2, "binomial")
	defer fixture.close()
	peer := fixture.formal.ctx.ComputePeers[0]
	runtime, _, err := formalGLMPhase21LoadAndAdmit(
		fixture.stores[peer], fixture.capsule, fixture.request,
		fixture.backendSignatures, fixture.workerSignatures)
	if err != nil {
		t.Fatal(err)
	}
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		runtime.Admission.Productive.Compiled.Binding,
		runtime.Source.Plan, fixture.formal.identities.public)
	plan := runtime.Source.Plan
	ctx := runtime.Source.Context
	result := runtime.Source.Result
	binding := runtime.Admission.Productive.Compiled.Binding
	semanticRoot := fixture.stores[peer].semanticRoot
	runtime.clear()
	if err != nil {
		t.Fatal(err)
	}
	contract := formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
		fixture.formal.identities.public, fixture.formal.identities.private,
		fixture.seeds)
	authorizations := formalGLMPhase21SamplerV2TestAuthorize(
		t, contract, fixture.formal.identities.public,
		fixture.formal.identities.private, fixture.seeds)
	publicationStorage := sha256.Sum256([]byte(t.Name() + "/empty-publication"))
	publicationStore, err := newFormalGLMPhase21StickyReleaseStore(
		filepath.Join(t.TempDir(), "empty-publication"), peer,
		publicationStorage, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	defer publicationStore.close()
	handoffRoot := filepath.Join(t.TempDir(), "v2-handoff")
	handoffStorage := sha256.Sum256([]byte(t.Name() + "/v2-handoff"))
	handoffStore, err := newFormalGLMPhase20HandoffStore(
		handoffRoot, semanticRoot, peer, handoffStorage,
		fixture.runtime[peer].backend, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	crashBefore := errors.New("crash after sampler-v2 guard")
	_, err = formalGLMPhase21PreflightOrCommitHandoffV2(
		publicationStore, handoffStore, binding, plan, ctx, result,
		contract, authorizations, func(phase string) error {
			if phase != "after_sampler_v2_guard_before_phase20" {
				t.Fatalf("unexpected first crash phase %q", phase)
			}
			return crashBefore
		})
	if !errors.Is(err, crashBefore) || fileExists(handoffStore.recordPath) {
		t.Fatalf("pre-Phase20 crash materialized a handoff: %v", err)
	}
	crashAfter := errors.New("crash after Phase20 commit")
	crashed, err := formalGLMPhase21PreflightOrCommitHandoffV2(
		publicationStore, handoffStore, binding, plan, ctx, result,
		contract, authorizations, func(phase string) error {
			if phase == "after_phase20_commit_before_sampler" {
				return crashAfter
			}
			return nil
		})
	if !errors.Is(err, crashAfter) || crashed.Handoff.Replayed ||
		!fileExists(handoffStore.recordPath) {
		t.Fatalf("post-Phase20 crash lost durable handoff: %#v / %v", crashed, err)
	}
	handoffStore.close()
	restarted, err := newFormalGLMPhase20HandoffStore(
		handoffRoot, semanticRoot, peer, handoffStorage,
		fixture.runtime[peer].backend, fixture.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	recovered, err := formalGLMPhase21PreflightOrCommitHandoffV2(
		publicationStore, restarted, binding, plan, ctx, result,
		contract, authorizations, nil)
	if err != nil || !recovered.Handoff.Replayed ||
		recovered.Handoff.SHA256 != crashed.Handoff.SHA256 {
		t.Fatalf("Phase20 restart changed guarded handoff: %#v / %v", recovered, err)
	}

	concurrentRoot := filepath.Join(t.TempDir(), "concurrent-handoff")
	concurrentStorage := sha256.Sum256([]byte(t.Name() + "/concurrent-handoff"))
	const callers = 12
	concurrentStores := make([]*formalGLMPhase20HandoffStore, callers)
	for index := range concurrentStores {
		concurrentStores[index], err = newFormalGLMPhase20HandoffStore(
			concurrentRoot, semanticRoot, peer, concurrentStorage,
			fixture.runtime[peer].backend, fixture.formal.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		defer concurrentStores[index].close()
	}
	results := make(chan formalGLMPhase21SamplerV2HandoffResult, callers)
	errorsOut := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := range concurrentStores {
		go func(index int) {
			defer wait.Done()
			value, callErr := formalGLMPhase21PreflightOrCommitHandoffV2(
				publicationStore, concurrentStores[index], binding, plan, ctx, result,
				contract, authorizations, nil)
			results <- value
			errorsOut <- callErr
		}(index)
	}
	wait.Wait()
	close(results)
	close(errorsOut)
	for callErr := range errorsOut {
		if callErr != nil {
			t.Fatal(callErr)
		}
	}
	created := 0
	var digest string
	for value := range results {
		if !value.Handoff.Replayed {
			created++
		}
		if digest == "" {
			digest = value.Handoff.SHA256
		} else if value.Handoff.SHA256 != digest {
			t.Fatal("concurrent guarded handoff returned divergent bytes")
		}
	}
	if created != 1 {
		t.Fatalf("concurrent guarded handoff created %d records", created)
	}
}

func TestFormalGLMPhase21SamplerV2GuardConcurrentTamperAndNoFollow(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 5, formalGLMPhase21SamplerV2OneDraw)
	authority := fixture.artifact.NoiseAuthorities[0]
	root := filepath.Join(t.TempDir(), "shared-guard")
	storageRoot := sha256.Sum256([]byte(t.Name() + "/shared-guard"))
	const callers = 10
	stores := make([]*formalGLMPhase21StickyReleaseStore, callers)
	for index := range stores {
		var err error
		stores[index], err = newFormalGLMPhase21StickyReleaseStore(
			root, authority.PeerName, storageRoot, fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	type answer struct {
		receipt  formalGLMPhase21SamplerV2Authorization
		replayed bool
		err      error
	}
	answers := make(chan answer, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for _, store := range stores {
		store := store
		go func() {
			defer wait.Done()
			receipt, replayed, err := store.AuthorizeSamplerV2Once(
				fixture.contract, fixture.roots[authority.PeerName],
				fixture.keys[authority.PeerName], nil)
			answers <- answer{receipt, replayed, err}
		}()
	}
	wait.Wait()
	close(answers)
	created := 0
	var canonical formalGLMPhase21SamplerV2Authorization
	for value := range answers {
		if value.err != nil {
			t.Fatal(value.err)
		}
		if !value.replayed {
			created++
		}
		if canonical.PeerName == "" {
			canonical = value.receipt
		} else if !reflect.DeepEqual(canonical, value.receipt) {
			t.Fatal("concurrent sampler-v2 guard returned divergent signatures")
		}
	}
	if created != 1 {
		t.Fatalf("sampler-v2 guard created %d concurrent records", created)
	}
	path, err := stores[0].samplerV2GuardRelativePath(
		fixture.artifactID, false)
	if err != nil {
		t.Fatal(err)
	}
	absolute := filepath.Join(stores[0].dir, path)
	info, err := os.Lstat(absolute)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("sampler-v2 guard is not owner-only: %#v / %v", info, err)
	}
	encoded, err := os.ReadFile(absolute)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)/2] ^= 1
	if err := os.WriteFile(absolute, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, store := range stores {
		store.close()
	}
	restarted, err := newFormalGLMPhase21StickyReleaseStore(
		root, authority.PeerName, storageRoot, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.AuthorizeSamplerV2Once(
		fixture.contract, fixture.roots[authority.PeerName],
		fixture.keys[authority.PeerName], nil); err == nil {
		t.Fatal("tampered sampler-v2 guard survived restart authentication")
	}
	restarted.close()

	symlinkRoot := filepath.Join(t.TempDir(), "symlink-guard")
	symlinkStore, err := newFormalGLMPhase21StickyReleaseStore(
		symlinkRoot, authority.PeerName,
		sha256.Sum256([]byte(t.Name()+"/symlink-store")), fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	firstShard := filepath.Join(symlinkStore.dir, "guards-v2", fixture.artifactID[:2])
	if err := os.Symlink(outside, firstShard); err != nil {
		t.Fatal(err)
	}
	if _, _, err := symlinkStore.AuthorizeSamplerV2Once(
		fixture.contract, fixture.roots[authority.PeerName],
		fixture.keys[authority.PeerName], nil); err == nil {
		t.Fatal("sampler-v2 guard followed a rooted symlink")
	}
	symlinkStore.close()
}

func TestFormalGLMPhase21SamplerV2DurableFinalizerSpoolCrashK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase21SamplerV2TestSetup(
				t, custodians, formalGLMPhase21SamplerV2OneDraw)
			base := formalGLMPhase21SamplerV2TestUnsignedCertificate(t, fixture)
			authority := fixture.artifact.NoiseAuthorities[0]
			root := filepath.Join(t.TempDir(), "durable-finalizer", authority.PeerName)
			storageRoot := sha256.Sum256(
				[]byte(t.Name() + "/durable-finalizer/" + authority.PeerName))
			open := func() *formalGLMPhase21StickyReleaseStore {
				store, err := newFormalGLMPhase21StickyReleaseStore(
					root, authority.PeerName, storageRoot, fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
				return store
			}
			store := open()
			finalizerCalls := 0
			finalizer := func() (formalGLMPhase21StickyCertificate, error) {
				finalizerCalls++
				return base, nil
			}
			crashBefore := errors.New("crash before durable spool")
			_, _, err := store.FinalizeSamplerV2Once(
				fixture.contract, finalizer, func(phase string) error {
					if phase != "after_finalizer_before_durable_spool" {
						t.Fatalf("unexpected pre-spool phase %q", phase)
					}
					return crashBefore
				})
			if !errors.Is(err, crashBefore) || finalizerCalls != 1 {
				t.Fatalf("pre-spool crash was not exposed: %d / %v",
					finalizerCalls, err)
			}
			relative, err := store.durableV2SpoolRelativePath(
				fixture.artifactID, true)
			if err != nil {
				t.Fatal(err)
			}
			if fileExists(filepath.Join(root, relative)) {
				t.Fatal("pre-spool crash persisted a candidate")
			}

			crashAfter := errors.New("crash after durable spool")
			staged, _, err := store.FinalizeSamplerV2Once(
				fixture.contract, finalizer, func(phase string) error {
					if phase == "after_durable_spool" {
						return crashAfter
					}
					return nil
				})
			if !errors.Is(err, crashAfter) || finalizerCalls != 2 ||
				!fileExists(filepath.Join(root, relative)) {
				t.Fatalf("post-spool crash lost candidate: %d / %v",
					finalizerCalls, err)
			}
			store.close()
			store = open()
			recovered, replayed, err := store.FinalizeSamplerV2Once(
				fixture.contract, finalizer, nil)
			if err != nil || !replayed || finalizerCalls != 2 ||
				!reflect.DeepEqual(recovered, staged) ||
				!recovered.ExactlyOnceDPOpening ||
				recovered.DurablePublicationProtocol !=
					formalGLMPhase21DurableV2Version ||
				formalGLMPhase19Contains(recovered.Blockers,
					"formal_glm_phase21_sampler_v2_inflight_output_not_durable_by_canonical_artifact_v1") ||
				recovered.ProductionReady {
				t.Fatalf("durable spool replay changed finalizer state: %#v / %v",
					recovered, err)
			}
			spoolBytes, err := os.ReadFile(filepath.Join(root, relative))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(spoolBytes, []byte("clamped_scaled_values")) ||
				bytes.Contains(spoolBytes, []byte("source_release_instance_id")) {
				t.Fatal("durable spool exposed finalizer plaintext")
			}
			formalGLMPhase21StickyAssertNoForbiddenFields(t, spoolBytes)
			info, err := os.Lstat(filepath.Join(root, relative))
			if err != nil || info.Mode().Perm() != 0o600 ||
				!exactGCPrivateOwnedRegular(info) {
				t.Fatalf("durable spool is not owner-only: %v / %v", info, err)
			}
			unrelatedLink := filepath.Join(root, "unrelated-durable-link")
			if err := os.Link(filepath.Join(root, relative), unrelatedLink); err != nil {
				t.Fatal(err)
			}
			store.close()
			store = open()
			if _, _, err := store.FinalizeSamplerV2Once(
				fixture.contract, finalizer, nil); err == nil {
				t.Fatal("multiply-linked durable spool was accepted")
			}
			if err := os.Remove(unrelatedLink); err != nil {
				t.Fatal(err)
			}
			store.close()
			store = open()
			tampered := append([]byte(nil), spoolBytes...)
			tampered[len(tampered)-1] ^= 1
			if err := os.WriteFile(filepath.Join(root, relative), tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			store.close()
			store = open()
			if _, _, err := store.FinalizeSamplerV2Once(
				fixture.contract, finalizer, nil); err == nil {
				t.Fatal("tampered durable spool was accepted")
			}
			store.close()
		})
	}
}

func TestFormalGLMPhase21SamplerV2DurableSignPublishAckK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase21SamplerV2TestSetup(
				t, custodians, formalGLMPhase21SamplerV2OneDraw)
			base := formalGLMPhase21SamplerV2TestUnsignedCertificate(t, fixture)
			promoted, err := formalGLMPhase21PromoteDurableV2(base, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			garblerAuthority := fixture.artifact.NoiseAuthorities[0]
			unspooled, err := newFormalGLMPhase21StickyReleaseStore(
				filepath.Join(t.TempDir(), "unspooled-signer"),
				garblerAuthority.PeerName,
				sha256.Sum256([]byte(t.Name()+"/unspooled-signer")), fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := unspooled.SignOnce(
				promoted, fixture.keys[garblerAuthority.PeerName], nil); err == nil {
				t.Fatal("durable SignOnce accepted a candidate without local spool")
			}
			unspooled.close()
			divergent := base
			divergent.ClampedScaledValues = append(
				[]string(nil), base.ClampedScaledValues...)
			divergent.ClampedScaledValues[0] = "12"
			divergent.VectorSHA256, err =
				jointDPBiomedicalGaussianOneDrawVectorSHA256(
					divergent.ClampedScaledValues)
			if err != nil || formalGLMPhase21ValidateStickyCertificateCore(
				divergent, fixture.pins) != nil {
				t.Fatal("invalid divergent durable test candidate")
			}
			evaluatorAuthority := fixture.artifact.NoiseAuthorities[1]
			divergentGarbler, err := newFormalGLMPhase21StickyReleaseStore(
				filepath.Join(t.TempDir(), "divergent-garbler"),
				garblerAuthority.PeerName,
				sha256.Sum256([]byte(t.Name()+"/divergent-garbler")), fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			divergentEvaluator, err := newFormalGLMPhase21StickyReleaseStore(
				filepath.Join(t.TempDir(), "divergent-evaluator"),
				evaluatorAuthority.PeerName,
				sha256.Sum256([]byte(t.Name()+"/divergent-evaluator")), fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			candidateA, _, err := divergentGarbler.FinalizeSamplerV2Once(
				fixture.contract, func() (formalGLMPhase21StickyCertificate, error) {
					return base, nil
				}, nil)
			if err != nil {
				t.Fatal(err)
			}
			candidateB, _, err := divergentEvaluator.FinalizeSamplerV2Once(
				fixture.contract, func() (formalGLMPhase21StickyCertificate, error) {
					return divergent, nil
				}, nil)
			if err != nil {
				t.Fatal(err)
			}
			firstDivergent, _, err := divergentGarbler.SignOnce(
				candidateA, fixture.keys[garblerAuthority.PeerName], nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := divergentEvaluator.SignOnce(
				candidateB, fixture.keys[evaluatorAuthority.PeerName],
				[]jointDPBiomedicalGaussianSignature{firstDivergent}); err == nil {
				t.Fatal("divergent authority spools acquired two ordered signatures")
			}
			divergentGarbler.close()
			divergentEvaluator.close()
			roots := make(map[string]string, 2)
			storage := make(map[string][32]byte, 2)
			stores := make(map[string]*formalGLMPhase21StickyReleaseStore, 2)
			for _, authority := range fixture.artifact.NoiseAuthorities {
				roots[authority.PeerName] = filepath.Join(
					t.TempDir(), "durable-authority", authority.PeerName)
				storage[authority.PeerName] = sha256.Sum256(
					[]byte(t.Name() + "/durable-authority/" + authority.PeerName))
				store, err := newFormalGLMPhase21StickyReleaseStore(
					roots[authority.PeerName], authority.PeerName,
					storage[authority.PeerName], fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
				stores[authority.PeerName] = store
				defer store.close()
			}
			var durable formalGLMPhase21StickyCertificate
			for _, authority := range fixture.artifact.NoiseAuthorities {
				candidate, replayed, err := stores[authority.PeerName].
					FinalizeSamplerV2Once(fixture.contract, func() (
						formalGLMPhase21StickyCertificate, error) {
						return base, nil
					}, nil)
				if err != nil || replayed {
					t.Fatalf("initial durable finalizer: %v / %v", err, replayed)
				}
				if durable.ArtifactID == "" {
					durable = candidate
				} else if !reflect.DeepEqual(durable, candidate) {
					t.Fatal("authorities staged divergent durable candidates")
				}
			}

			receipts := make([]jointDPBiomedicalGaussianSignature, 0, 2)
			garbler := fixture.artifact.NoiseAuthorities[0]
			first, replayed, err := stores[garbler.PeerName].SignOnce(
				durable, fixture.keys[garbler.PeerName], nil)
			if err != nil || replayed {
				t.Fatalf("first durable signature: %v / %v", err, replayed)
			}
			receipts = append(receipts, first)
			stores[garbler.PeerName].close()
			restarted, err := newFormalGLMPhase21StickyReleaseStore(
				roots[garbler.PeerName], garbler.PeerName,
				storage[garbler.PeerName], fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			stores[garbler.PeerName] = restarted
			replayedFirst, replayed, err := restarted.SignOnce(
				durable, fixture.keys[garbler.PeerName], nil)
			if err != nil || !replayed || !reflect.DeepEqual(replayedFirst, first) {
				t.Fatalf("first durable signature restart: %v / %v", err, replayed)
			}
			evaluator := fixture.artifact.NoiseAuthorities[1]
			second, replayed, err := stores[evaluator.PeerName].SignOnce(
				durable, fixture.keys[evaluator.PeerName], receipts)
			if err != nil || replayed {
				t.Fatalf("second durable signature: %v / %v", err, replayed)
			}
			receipts = append(receipts, second)
			sealed, err := formalGLMPhase21SealStickyCertificate(
				durable, receipts, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			unboundPublisher, err := newFormalGLMPhase21StickyReleaseStore(
				filepath.Join(t.TempDir(), "unbound-publisher"),
				garbler.PeerName,
				sha256.Sum256([]byte(t.Name()+"/unbound-publisher")), fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := unboundPublisher.Commit(sealed); err == nil {
				t.Fatal("durable Commit accepted no local spool/SignOnce evidence")
			}
			unboundPublisher.close()

			const callers = 12
			instances := make([]*formalGLMPhase21StickyReleaseStore, callers)
			for index := range instances {
				instances[index], err = newFormalGLMPhase21StickyReleaseStore(
					roots[garbler.PeerName], garbler.PeerName,
					storage[garbler.PeerName], fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
				defer instances[index].close()
			}
			publications := make(chan formalGLMPhase21StickyPublication, callers)
			errorsOut := make(chan error, callers)
			var wait sync.WaitGroup
			wait.Add(callers)
			for index := range instances {
				go func(index int) {
					defer wait.Done()
					publication, callErr := instances[index].Commit(sealed)
					publications <- publication
					errorsOut <- callErr
				}(index)
			}
			wait.Wait()
			close(publications)
			close(errorsOut)
			for callErr := range errorsOut {
				if callErr != nil {
					t.Fatal(callErr)
				}
			}
			created := 0
			var reference formalGLMPhase21StickyPublication
			for publication := range publications {
				if !publication.Replayed {
					created++
				}
				if len(reference.Certificate) == 0 {
					reference = publication
				} else if !bytes.Equal(reference.Certificate, publication.Certificate) ||
					reference.CertificateSHA256 != publication.CertificateSHA256 {
					t.Fatal("concurrent durable publication returned divergent bytes")
				}
			}
			if created != 1 {
				t.Fatalf("durable publication created %d records", created)
			}

			crashAfterCommit := errors.New("crash after durable commit")
			_, _, err = restarted.PublishDurableV2(
				sealed, func(phase string) error {
					if phase == "after_durable_commit_before_ack" {
						return crashAfterCommit
					}
					return nil
				})
			if !errors.Is(err, crashAfterCommit) {
				t.Fatalf("durable commit crash window was skipped: %v", err)
			}
			restarted.close()
			restarted, err = newFormalGLMPhase21StickyReleaseStore(
				roots[garbler.PeerName], garbler.PeerName,
				storage[garbler.PeerName], fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			stores[garbler.PeerName] = restarted
			crashAfterAck := errors.New("crash after durable ack")
			recoveredPublication, ackReplayed, err := restarted.PublishDurableV2(
				sealed, func(phase string) error {
					if phase == "after_durable_ack" {
						return crashAfterAck
					}
					return nil
				})
			if !errors.Is(err, crashAfterAck) || ackReplayed ||
				!bytes.Equal(recoveredPublication.Certificate, reference.Certificate) {
				t.Fatalf("durable publication recovery: %v / ack replay=%v",
					err, ackReplayed)
			}
			_, ackReplayed, err = restarted.PublishDurableV2(sealed, nil)
			if err != nil || !ackReplayed {
				t.Fatalf("durable ack replay: %v / %v", err, ackReplayed)
			}
			ackRelative, err := restarted.durableV2AckRelativePath(
				fixture.artifactID, false)
			if err != nil {
				t.Fatal(err)
			}
			ackBytes, err := os.ReadFile(filepath.Join(
				roots[garbler.PeerName], ackRelative))
			if err != nil {
				t.Fatal(err)
			}
			formalGLMPhase21StickyAssertNoForbiddenFields(t, ackBytes)
			ackInfo, err := os.Lstat(filepath.Join(
				roots[garbler.PeerName], ackRelative))
			if err != nil || ackInfo.Mode().Perm() != 0o600 ||
				!exactGCPrivateOwnedRegular(ackInfo) {
				t.Fatalf("durable ack is not owner-only: %v / %v", ackInfo, err)
			}
			formalGLMPhase21StickyAssertNoForbiddenFields(
				t, recoveredPublication.Certificate)
			decoded, err := formalGLMPhase21DecodeStickyPublication(
				recoveredPublication)
			if err != nil || !decoded.ExactlyOnceDPOpening ||
				decoded.DurablePublicationProtocol != formalGLMPhase21DurableV2Version {
				t.Fatalf("durable public claim is not bound: %#v / %v", decoded, err)
			}
			tamperedAck := append([]byte(nil), ackBytes...)
			tamperedAck[len(tamperedAck)-1] ^= 1
			if err := os.WriteFile(filepath.Join(
				roots[garbler.PeerName], ackRelative), tamperedAck, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.AckDurableV2(recoveredPublication); err == nil {
				t.Fatal("tampered durable acknowledgment was accepted")
			}
		})
	}
}

func TestFormalGLMPhase21SamplerV2DurableSpoolNoFollowAndBound(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2OneDraw)
	base := formalGLMPhase21SamplerV2TestUnsignedCertificate(t, fixture)
	authority := fixture.artifact.NoiseAuthorities[0]
	storage := sha256.Sum256([]byte(t.Name() + "/storage"))

	symlinkRoot := filepath.Join(t.TempDir(), "symlink-store")
	symlinkStore, err := newFormalGLMPhase21StickyReleaseStore(
		symlinkRoot, authority.PeerName, storage, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(symlinkRoot, "finalized-v2")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := symlinkStore.FinalizeSamplerV2Once(
		fixture.contract, func() (formalGLMPhase21StickyCertificate, error) {
			return base, nil
		}, nil); err == nil {
		t.Fatal("durable spool followed a rooted symlink")
	}
	symlinkStore.close()

	boundRoot := filepath.Join(t.TempDir(), "bounded-store")
	boundStore, err := newFormalGLMPhase21StickyReleaseStore(
		boundRoot, authority.PeerName,
		sha256.Sum256([]byte(t.Name()+"/bounded")), fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := boundStore.durableV2SpoolRelativePath(
		fixture.artifactID, true)
	if err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, formalGLMPhase21DurableV2MaxBytes+1)
	if err := os.WriteFile(filepath.Join(boundRoot, relative), oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(oversized)
	if _, _, err := boundStore.FinalizeSamplerV2Once(
		fixture.contract, func() (formalGLMPhase21StickyCertificate, error) {
			return base, nil
		}, nil); err == nil {
		t.Fatal("oversized durable spool was accepted")
	}
	boundStore.close()
}

func formalGLMPhase21StickyAlternateGeometry(t testing.TB,
	plan formalGLMPhase15Plan,
) formalGLMPhase15Plan {
	t.Helper()
	for capacity := 1; capacity <= formalGLMPhase1MaxCapacity; capacity++ {
		if capacity == plan.BlockCapacity {
			continue
		}
		kernel := plan.Kernel
		kernel.Capacity = capacity
		candidate, err := buildFormalGLMPhase15Plan(
			kernel, plan.TotalCapacity, plan.Iterations,
			plan.CoordinateOwners,
			sha256Hex([]byte(t.Name()+"/alternate-run")))
		if err == nil && candidate.BlockCapacity != plan.BlockCapacity {
			return candidate
		}
	}
	t.Fatal("test fixture has no alternate valid physical geometry")
	return formalGLMPhase15Plan{}
}

func TestFormalGLMPhase21StickyCanonicalIdentityK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase21StickyTestSetup(t, custodians)
			defer fixture.close()
			peer := fixture.phase21.formal.ctx.ComputePeers[0]
			binding := fixture.outputs[peer].Admission.Compiled.Binding
			pins := fixture.phase21.formal.identities.public
			artifact, artifactID, err :=
				formalGLMPhase21BuildCanonicalArtifact(binding, fixture.plan, pins)
			if err != nil || artifactID != fixture.certificate.ArtifactID ||
				!reflect.DeepEqual(artifact, fixture.certificate.Artifact) {
				t.Fatalf("canonical artifact mismatch: %s / %v", artifactID, err)
			}

			newRun := fixture.plan
			newRun.RunID = sha256Hex([]byte(t.Name() + "/fresh-run-id"))
			_, newRunID, err := formalGLMPhase21BuildCanonicalArtifact(
				binding, newRun, pins)
			if err != nil || newRunID != artifactID {
				t.Fatalf("RunID split canonical release: %s / %v", newRunID, err)
			}
			alternate := formalGLMPhase21StickyAlternateGeometry(t, fixture.plan)
			_, geometryID, err := formalGLMPhase21BuildCanonicalArtifact(
				binding, alternate, pins)
			if err != nil || geometryID != artifactID {
				t.Fatalf("physical geometry split canonical release: %s / %v",
					geometryID, err)
			}
			canonicalPlan, err := formalGLMPhase21CanonicalPlanSHA256(fixture.plan)
			if err != nil {
				t.Fatal(err)
			}
			ringBackend := fixture.plan
			ringBackend.RingBits += 64
			ringBackend.ContainerBits = exactGCTypeBits(ringBackend.RingBits)
			ringPlan, err := formalGLMPhase21CanonicalPlanSHA256(ringBackend)
			if err != nil || ringPlan != canonicalPlan {
				t.Fatalf("ring backend split canonical plan: %s / %v", ringPlan, err)
			}
			capacityEstimand := fixture.plan
			capacityEstimand.TotalCapacity++
			capacityPlan, err := formalGLMPhase21CanonicalPlanSHA256(capacityEstimand)
			if err != nil || capacityPlan == canonicalPlan {
				t.Fatalf("capacity-normalized estimand reused canonical plan: %s / %v",
					capacityPlan, err)
			}
			alias := binding
			if strings.Contains(binding.Epsilon, ".") {
				alias.Epsilon = binding.Epsilon + "0"
			} else {
				alias.Epsilon = binding.Epsilon + ".0"
			}
			_, aliasID, err := formalGLMPhase21BuildCanonicalArtifact(
				alias, fixture.plan, pins)
			if err != nil || aliasID != artifactID {
				t.Fatalf("decimal alias split canonical release: %s / %v", aliasID, err)
			}

			operationalMutations := map[string]func(
				*formalGLMPhase15Plan, *formalGLMPhase16ReleaseBinding){
				"lifetime policy workload": func(
					_ *formalGLMPhase15Plan, value *formalGLMPhase16ReleaseBinding) {
					value.WorkloadSHA256 = sha256Hex([]byte("other lifetime policy"))
				},
				"privacy budget gate": func(
					_ *formalGLMPhase15Plan, value *formalGLMPhase16ReleaseBinding) {
					value.WorkloadSHA256 = sha256Hex([]byte("other privacy budget gate"))
				},
				"unrelated workload catalog": func(
					_ *formalGLMPhase15Plan, value *formalGLMPhase16ReleaseBinding) {
					value.SourceContextSHA256 = sha256Hex([]byte("other unrelated catalog"))
				},
				"quota metadata": func(
					_ *formalGLMPhase15Plan, value *formalGLMPhase16ReleaseBinding) {
					value.WorkloadSHA256 = sha256Hex([]byte("other quota metadata"))
				},
				"compiler evidence": func(
					plan *formalGLMPhase15Plan, _ *formalGLMPhase16ReleaseBinding) {
					plan.Kernel.CompilerSHA256 = sha256Hex([]byte("other compiler"))
					plan.Kernel.ArtifactSHA256 = sha256Hex([]byte("compiler-only artifact"))
				},
				"theorem evidence": func(
					plan *formalGLMPhase15Plan, _ *formalGLMPhase16ReleaseBinding) {
					plan.Kernel.TheoremSHA256 = sha256Hex([]byte("other theorem"))
					plan.Kernel.ArtifactSHA256 = sha256Hex([]byte("theorem-only artifact"))
				},
				"artifact status evidence": func(
					plan *formalGLMPhase15Plan, _ *formalGLMPhase16ReleaseBinding) {
					plan.Kernel.ArtifactSHA256 = sha256Hex([]byte("other status-only artifact"))
				},
				"legacy capsule evidence": func(
					plan *formalGLMPhase15Plan, value *formalGLMPhase16ReleaseBinding) {
					capsule := sha256Hex([]byte("other legacy capsule"))
					plan.Kernel.CapsuleSHA256 = capsule
					plan.Kernel.ArtifactSHA256 = sha256Hex([]byte("capsule-only artifact"))
					value.CapsuleID = capsule
				},
				"sensitivity proof evidence": func(
					_ *formalGLMPhase15Plan, value *formalGLMPhase16ReleaseBinding) {
					value.SensitivityCertificateSHA256 =
						sha256Hex([]byte("other sensitivity proof encoding"))
				},
				"link proof evidence": func(
					plan *formalGLMPhase15Plan, value *formalGLMPhase16ReleaseBinding) {
					link := sha256Hex([]byte("other link proof encoding"))
					plan.Kernel.LinkTableSHA256 = link
					value.LinkTableSHA256 = link
				},
				"epoch and reservation evidence": func(
					_ *formalGLMPhase15Plan, value *formalGLMPhase16ReleaseBinding) {
					value.ReleaseInstanceID = sha256Hex([]byte("other epoch"))
					value.ReleaseContractSHA256 = sha256Hex([]byte("other reservation"))
					value.GarblerCommitmentContext = sha256Hex([]byte("other context"))
					value.GarblerSeedCommitment = sha256Hex([]byte("other commitment"))
				},
			}
			for name, mutate := range operationalMutations {
				candidatePlan := fixture.plan
				candidateBinding := binding
				mutate(&candidatePlan, &candidateBinding)
				_, candidateID, buildErr := formalGLMPhase21BuildCanonicalArtifact(
					candidateBinding, candidatePlan, pins)
				if buildErr != nil || candidateID != artifactID {
					t.Fatalf("operational mutation %s split canonical release: %s / %v",
						name, candidateID, buildErr)
				}
			}

			encoded, err := json.Marshal(artifact)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"run_id", "block_capacity", "release_instance",
				"release_contract", "reservation", "privacy_epoch",
				"receipt", "noise_root_epoch", "seed_commitment",
				"commitment_context", "selected_backend",
				"workload_sha256", "source_context_sha256",
				"sensitivity_certificate_sha256", "link_table_sha256",
				"source_ring_bits", "common_ring_bits", "ring_bits",
			} {
				if bytes.Contains(bytes.ToLower(encoded), []byte(forbidden)) {
					t.Fatalf("canonical artifact contains operational field %q", forbidden)
				}
			}

			mutations := map[string]func(*formalGLMPhase21StickyArtifact){
				"formula": func(value *formalGLMPhase21StickyArtifact) {
					value.CanonicalScienceSHA256 = sha256Hex([]byte("other formula"))
				},
				"schema": func(value *formalGLMPhase21StickyArtifact) {
					value.SchemaManifestSHA256 = sha256Hex([]byte("other schema"))
				},
				"snapshot": func(value *formalGLMPhase21StickyArtifact) {
					value.SnapshotSHA256 = sha256Hex([]byte("other snapshot"))
				},
				"bounds": func(value *formalGLMPhase21StickyArtifact) {
					value.BoundsSHA256 = sha256Hex([]byte("other bounds"))
				},
				"family": func(value *formalGLMPhase21StickyArtifact) {
					value.Family = "poisson"
				},
				"epsilon": func(value *formalGLMPhase21StickyArtifact) {
					value.EpsilonRational = "2/1"
				},
				"delta": func(value *formalGLMPhase21StickyArtifact) {
					value.DeltaRational = "1/2000000"
				},
				"sensitivity": func(value *formalGLMPhase21StickyArtifact) {
					value.SensitivitySteps = "18"
				},
				"coordinate order": func(value *formalGLMPhase21StickyArtifact) {
					value.CoordinateOrderSHA256 = sha256Hex([]byte("other order"))
				},
				"link values": func(value *formalGLMPhase21StickyArtifact) {
					value.CanonicalLinkSHA256 = sha256Hex([]byte("other link values"))
				},
				"pinset": func(value *formalGLMPhase21StickyArtifact) {
					value.PinsetSHA256 = sha256Hex([]byte("other pinset"))
				},
				"authority": func(value *formalGLMPhase21StickyArtifact) {
					value.NoiseAuthorities[0].PeerID =
						"dsv1_" + sha256Hex([]byte("other authority"))
				},
			}
			for name, mutate := range mutations {
				changed := artifact
				changed.CustodianPeers = append([]string(nil), artifact.CustodianPeers...)
				changed.DesignatedComputePeers = append(
					[]string(nil), artifact.DesignatedComputePeers...)
				changed.NoiseAuthorities = append(
					[]formalGLMPhase21StickyNoiseAuthority(nil),
					artifact.NoiseAuthorities...)
				mutate(&changed)
				changedID, hashErr := formalGLMPhase21StickyArtifactID(changed)
				if hashErr != nil || changedID == artifactID {
					t.Fatalf("semantic mutation %s reused canonical id: %v", name, hashErr)
				}
			}

			missing := make(map[string]ed25519.PublicKey, len(pins)-1)
			for name, pin := range pins {
				if name != fixture.phase21.formal.ctx.CustodianPeers[0] {
					missing[name] = pin
				}
			}
			if _, _, err := formalGLMPhase21BuildCanonicalArtifact(
				binding, fixture.plan, missing); err == nil {
				t.Fatal("incomplete pinset reached canonical artifact")
			}
			aliasedPins := make(map[string]ed25519.PublicKey, len(pins)+1)
			for name, pin := range pins {
				aliasedPins[name] = pin
			}
			aliasedPins["alias"] = append(ed25519.PublicKey(nil), pins[peer]...)
			if _, _, err := formalGLMPhase21BuildCanonicalArtifact(
				binding, fixture.plan, aliasedPins); err == nil {
				t.Fatal("duplicate-key pin alias reached canonical artifact")
			}
		})
	}
}

func TestFormalGLMPhase21StickyOrderedSignOnceK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase21StickyTestSetup(t, custodians)
			defer fixture.close()
			unsignedA := fixture.certificate
			unsignedA.AuthorityReceipts = nil
			unsignedB := unsignedA
			unsignedB.ClampedScaledValues = append(
				[]string(nil), unsignedA.ClampedScaledValues...)
			if unsignedB.ClampedScaledValues[0] == "0" {
				unsignedB.ClampedScaledValues[0] = "1"
			} else {
				unsignedB.ClampedScaledValues[0] = "0"
			}
			if err := formalGLMPhase21ValidateStickyCertificateCore(
				unsignedB,
				fixture.phase21.formal.identities.public); err == nil {
				t.Fatal("sticky core accepted a vector/digest mismatch")
			}
			var err error
			unsignedB.VectorSHA256, err =
				jointDPBiomedicalGaussianOneDrawVectorSHA256(
					unsignedB.ClampedScaledValues)
			if err != nil {
				t.Fatal(err)
			}
			unsignedB.SourceCertificateSHA256 =
				sha256Hex([]byte(t.Name() + "/competing-source"))

			authorities := unsignedA.Artifact.NoiseAuthorities
			garblerRoot := filepath.Join(t.TempDir(), "garbler-sign-once")
			evaluatorRoot := filepath.Join(t.TempDir(), "evaluator-sign-once")
			garbler := formalGLMPhase21StickyTestStore(
				t, fixture, authorities[0].PeerName, garblerRoot)
			garblerReceipt, replayed, err := garbler.SignOnce(
				unsignedA,
				fixture.phase21.formal.identities.private[authorities[0].PeerName],
				nil)
			if err != nil || replayed {
				t.Fatalf("garbler first SignOnce: %v / replay=%v", err, replayed)
			}
			if _, _, err := garbler.SignOnce(
				unsignedB,
				fixture.phase21.formal.identities.private[authorities[0].PeerName],
				nil); err == nil {
				t.Fatal("garbler signed two certificates for one canonical artifact")
			}
			signerRelative, err := garbler.signerRelativePath(
				unsignedA.ArtifactID, false)
			if err != nil {
				t.Fatal(err)
			}
			signerBytes, err := os.ReadFile(
				filepath.Join(garbler.dir, signerRelative))
			if err != nil {
				t.Fatal(err)
			}
			formalGLMPhase21StickyAssertNoForbiddenFields(t, signerBytes)
			garbler.close()
			garbler = formalGLMPhase21StickyTestStore(
				t, fixture, authorities[0].PeerName, garblerRoot)
			recoveredGarbler, replayed, err := garbler.SignOnce(
				unsignedA,
				fixture.phase21.formal.identities.private[authorities[0].PeerName],
				nil)
			if err != nil || !replayed ||
				!reflect.DeepEqual(recoveredGarbler, garblerReceipt) {
				t.Fatalf("garbler restart changed SignOnce receipt: %v", err)
			}

			evaluator := formalGLMPhase21StickyTestStore(
				t, fixture, authorities[1].PeerName, evaluatorRoot)
			if _, _, err := evaluator.SignOnce(
				unsignedB,
				fixture.phase21.formal.identities.private[authorities[1].PeerName],
				[]jointDPBiomedicalGaussianSignature{garblerReceipt}); err == nil {
				t.Fatal("evaluator accepted a garbler receipt for another certificate")
			}
			evaluatorReceipt, replayed, err := evaluator.SignOnce(
				unsignedA,
				fixture.phase21.formal.identities.private[authorities[1].PeerName],
				[]jointDPBiomedicalGaussianSignature{garblerReceipt})
			if err != nil || replayed {
				t.Fatalf("evaluator ordered SignOnce: %v / replay=%v", err, replayed)
			}
			if _, _, err := evaluator.SignOnce(
				unsignedB,
				fixture.phase21.formal.identities.private[authorities[1].PeerName],
				[]jointDPBiomedicalGaussianSignature{garblerReceipt}); err == nil {
				t.Fatal("evaluator signed two certificates for one canonical artifact")
			}
			evaluator.close()
			evaluator = formalGLMPhase21StickyTestStore(
				t, fixture, authorities[1].PeerName, evaluatorRoot)
			recoveredEvaluator, replayed, err := evaluator.SignOnce(
				unsignedA,
				fixture.phase21.formal.identities.private[authorities[1].PeerName],
				[]jointDPBiomedicalGaussianSignature{garblerReceipt})
			if err != nil || !replayed ||
				!reflect.DeepEqual(recoveredEvaluator, evaluatorReceipt) {
				t.Fatalf("evaluator restart changed SignOnce receipt: %v", err)
			}

			sealed, err := formalGLMPhase21SealStickyCertificate(
				unsignedA,
				[]jointDPBiomedicalGaussianSignature{
					garblerReceipt, evaluatorReceipt,
				}, fixture.phase21.formal.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			left, err := garbler.Commit(sealed)
			if err != nil {
				t.Fatal(err)
			}
			right, err := evaluator.Commit(sealed)
			if err != nil || !bytes.Equal(left.Certificate, right.Certificate) {
				t.Fatalf("authority stores diverged after ordered SignOnce: %v", err)
			}
			garbler.close()
			evaluator.close()
		})
	}
}

func TestFormalGLMPhase21StickyReleaseK2K3K5RestartReplay(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase21StickyTestSetup(t, custodians)
			defer fixture.close()
			if fixture.certificate.ExactlyOnceDPOpening ||
				fixture.certificate.ProductionReady {
				t.Fatal("unwired canonical preflight was certified as production exactly-once")
			}
			for _, blocker := range []string{
				"formal_glm_phase21_preflight_not_wired_before_phase20_v1",
				"formal_glm_phase21_noise_purpose_not_derived_from_canonical_artifact_id_v1",
			} {
				if !formalGLMPhase19Contains(fixture.certificate.Blockers, blocker) {
					t.Fatalf("missing honest sticky blocker %q", blocker)
				}
			}
			peers := fixture.phase21.formal.ctx.ComputePeers
			var canonical []byte
			for _, peer := range peers {
				root := filepath.Join(t.TempDir(), "sticky", peer)
				store := formalGLMPhase21StickyTestStore(t, fixture, peer, root)
				first, err := store.Commit(fixture.certificate)
				if err != nil || first.Replayed || first.ArtifactID !=
					fixture.certificate.ArtifactID {
					t.Fatalf("initial sticky commit: %#v / %v", first, err)
				}
				replay, err := store.Commit(fixture.certificate)
				if err != nil || !replay.Replayed ||
					!bytes.Equal(first.Certificate, replay.Certificate) {
					t.Fatalf("same-process sticky replay changed: %#v / %v",
						replay, err)
				}
				if canonical == nil {
					canonical = append([]byte(nil), first.Certificate...)
				} else if !bytes.Equal(canonical, first.Certificate) {
					t.Fatal("compute peers persisted different public certificates")
				}
				binding := fixture.outputs[peer].Admission.Compiled.Binding
				preflightArtifact, preflightID, preflight, found, preflightErr :=
					store.Preflight(binding, fixture.plan)
				if preflightErr != nil || !found || preflightID != first.ArtifactID ||
					!reflect.DeepEqual(preflightArtifact,
						fixture.certificate.Artifact) ||
					!bytes.Equal(preflight.Certificate, first.Certificate) {
					t.Fatalf("preflight did not short-circuit to sticky replay: %v",
						preflightErr)
				}
				newRun := fixture.plan
				newRun.RunID = sha256Hex([]byte(t.Name() + "/preflight-restart"))
				_, newRunID, newRunReplay, found, preflightErr :=
					store.Preflight(binding, newRun)
				if preflightErr != nil || !found || newRunID != first.ArtifactID ||
					!bytes.Equal(newRunReplay.Certificate, first.Certificate) {
					t.Fatalf("fresh RunID bypassed sticky preflight: %v", preflightErr)
				}
				path, err := store.recordPath(first.ArtifactID, false)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(path)
				if err != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("sticky record is not owner-only: %#v / %v", info, err)
				}
				record, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				formalGLMPhase21StickyAssertNoForbiddenFields(t, record)
				for _, forbidden := range []string{
					"ledger", "reservation", "lifetime", "quota",
					"preclamp", "dp_share", "private_key", "seed_key",
				} {
					if bytes.Contains(bytes.ToLower(record), []byte(forbidden)) {
						t.Fatalf("sticky record exposed forbidden %q", forbidden)
					}
				}
				store.close()
				restarted := formalGLMPhase21StickyTestStore(t, fixture, peer, root)
				cold, err := restarted.Replay(first.ArtifactID)
				if err != nil || !cold.Replayed ||
					!bytes.Equal(canonical, cold.Certificate) {
					t.Fatalf("restart replay changed public bytes: %#v / %v",
						cold, err)
				}
				restarted.close()
				wrongPins := make(map[string]ed25519.PublicKey,
					len(fixture.phase21.formal.identities.public))
				for name, pin := range fixture.phase21.formal.identities.public {
					wrongPins[name] = append(ed25519.PublicKey(nil), pin...)
				}
				firstPeer, secondPeer := peers[0], peers[1]
				wrongPins[firstPeer], wrongPins[secondPeer] =
					wrongPins[secondPeer], wrongPins[firstPeer]
				storageRoot := sha256.Sum256(
					[]byte(t.Name() + "/sticky-store/" + peer))
				wrongStore, openErr := newFormalGLMPhase21StickyReleaseStore(
					root, peer, storageRoot, wrongPins)
				if openErr != nil {
					t.Fatal(openErr)
				}
				if _, replayErr := wrongStore.Replay(first.ArtifactID); replayErr == nil {
					t.Fatal("sticky replay accepted a rotated actual pinset")
				}
				wrongStore.close()
			}
		})
	}
}

func TestFormalGLMPhase21StickyReleaseTamperRerollReorderAndCAS(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			formalGLMPhase21StickyTestTamperRerollAndCAS(t, custodians)
		})
	}
}

func formalGLMPhase21StickyTestTamperRerollAndCAS(t *testing.T,
	custodians int,
) {
	fixture := formalGLMPhase21StickyTestSetup(t, custodians)
	defer fixture.close()
	peer := fixture.phase21.formal.ctx.ComputePeers[0]
	root := filepath.Join(t.TempDir(), "sticky", peer)
	store := formalGLMPhase21StickyTestStore(t, fixture, peer, root)
	first, err := store.Commit(fixture.certificate)
	if err != nil {
		t.Fatal(err)
	}

	tampered := fixture.certificate
	tampered.Artifact.SnapshotSHA256 = sha256Hex([]byte("wrong snapshot"))
	if _, err := store.Commit(tampered); err == nil {
		t.Fatal("signed artifact tamper reached the sticky store")
	}
	reordered := fixture.certificate
	reordered.AuthorityReceipts = append(
		[]jointDPBiomedicalGaussianSignature(nil),
		fixture.certificate.AuthorityReceipts...)
	reordered.AuthorityReceipts[0], reordered.AuthorityReceipts[1] =
		reordered.AuthorityReceipts[1], reordered.AuthorityReceipts[0]
	if _, err := store.Commit(reordered); err == nil {
		t.Fatal("authority receipt reorder reached the sticky store")
	}

	reroll := fixture.certificate
	reroll.ClampedScaledValues = append(
		[]string(nil), fixture.certificate.ClampedScaledValues...)
	reroll.ClampedScaledValues[0] = "1"
	reroll.VectorSHA256, err = jointDPBiomedicalGaussianOneDrawVectorSHA256(
		reroll.ClampedScaledValues)
	if err != nil {
		t.Fatal(err)
	}
	reroll.SourceCertificateSHA256 = sha256Hex([]byte("second DP draw"))
	reroll.AuthorityReceipts = nil
	message, err := formalGLMPhase21StickyCertificateMessage(reroll)
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range reroll.Artifact.NoiseAuthorities {
		reroll.AuthorityReceipts = append(reroll.AuthorityReceipts,
			jointDPBiomedicalGaussianSignature{
				Signer: authority.PeerName,
				Signature: ed25519.Sign(
					fixture.phase21.formal.identities.private[authority.PeerName],
					message),
			})
	}
	if err := formalGLMPhase21ValidateStickyCertificate(
		reroll, fixture.phase21.formal.identities.public); err != nil {
		t.Fatalf("reroll fixture is not independently authority-signed: %v", err)
	}
	if _, err := store.Commit(reroll); err == nil ||
		!strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("first sticky release did not defeat a fully signed reroll: %v", err)
	}
	replayed, err := store.Replay(first.ArtifactID)
	if err != nil || !bytes.Equal(first.Certificate, replayed.Certificate) {
		t.Fatal("rejected reroll changed the first publication")
	}
	store.close()

	concurrentRoot := filepath.Join(t.TempDir(), "concurrent", peer)
	const writers = 12
	results := make(chan formalGLMPhase21StickyPublication, writers)
	errorsByWriter := make(chan error, writers)
	var wait sync.WaitGroup
	wait.Add(writers)
	for index := 0; index < writers; index++ {
		go func() {
			defer wait.Done()
			candidate := formalGLMPhase21StickyTestStore(
				t, fixture, peer, concurrentRoot)
			defer candidate.close()
			result, commitErr := candidate.Commit(fixture.certificate)
			results <- result
			errorsByWriter <- commitErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsByWriter)
	created := 0
	for err := range errorsByWriter {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if !result.Replayed {
			created++
		}
		if !bytes.Equal(first.Certificate, result.Certificate) {
			t.Fatal("concurrent CAS returned different public bytes")
		}
	}
	if created != 1 {
		t.Fatalf("hard-link CAS created %d first publications, want 1", created)
	}
}

func TestFormalGLMPhase21StickyReleaseCrashRecoveryAndPathSafety(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			formalGLMPhase21StickyTestCrashRecoveryAndPath(t, custodians)
		})
	}
}

func formalGLMPhase21StickyTestCrashRecoveryAndPath(t *testing.T,
	custodians int,
) {
	fixture := formalGLMPhase21StickyTestSetup(t, custodians)
	defer fixture.close()
	peer := fixture.phase21.formal.ctx.ComputePeers[0]
	root := filepath.Join(t.TempDir(), "sticky", peer)
	store := formalGLMPhase21StickyTestStore(t, fixture, peer, root)
	crash := errors.New("simulated crash after durable publication")
	publication, removed, err := formalGLMPhase21CommitOneDrawAndCleanup(
		store, fixture.phase21.stores[peer], fixture.outputs[peer],
		fixture.certified, fixture.certificate, func(phase string) error {
			if phase != "after_sticky_commit_before_source_consume" {
				t.Fatalf("unexpected publication phase %q", phase)
			}
			if !fileExists(fixture.phase21.stores[peer].recordPath) {
				t.Fatal("source was consumed before the sticky commit")
			}
			return crash
		})
	if !errors.Is(err, crash) || removed != 0 || publication.Replayed ||
		!fileExists(fixture.phase21.stores[peer].recordPath) {
		t.Fatalf("commit-before-consume crash contract failed: %#v %d %v",
			publication, removed, err)
	}
	store.close()
	restarted := formalGLMPhase21StickyTestStore(t, fixture, peer, root)
	removed, err = formalGLMPhase21CleanupCommittedOneDraw(
		restarted, fixture.phase21.stores[peer], publication.ArtifactID,
		fixture.phase21.capsule, fixture.phase21.request,
		fixture.phase21.backendSignatures, fixture.phase21.workerSignatures)
	if err != nil || removed != fixture.outputs[peer].HandoffBytes ||
		fileExists(fixture.phase21.stores[peer].recordPath) {
		t.Fatalf("post-commit restart did not resume consume: %d / %v", removed, err)
	}
	replay, err := restarted.Replay(publication.ArtifactID)
	if err != nil || !bytes.Equal(publication.Certificate, replay.Certificate) {
		t.Fatal("post-consume replay touched or changed the source")
	}

	// A durable local finalizer can be recovered before publication without
	// invoking the sampler or finalizer again.
	otherPeer := fixture.phase21.formal.ctx.ComputePeers[1]
	runtime, _, err := formalGLMPhase21LoadAndAdmit(
		fixture.phase21.stores[otherPeer], fixture.phase21.capsule,
		fixture.phase21.request, fixture.phase21.backendSignatures,
		fixture.phase21.workerSignatures)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.clear()
	recovered := make(map[string]jointDPBiomedicalGaussianOneDrawLocalRelease, 2)
	for _, name := range fixture.phase21.formal.ctx.ComputePeers {
		reopened, reopenErr :=
			newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				fixture.releaseRoot[name], name,
				fixture.phase21.runtime[name].backend,
				fixture.phase21.formal.identities.private[name])
		if reopenErr != nil {
			t.Fatal(reopenErr)
		}
		loaded, loadErr := reopened.loadReleasedForFormalGLMPhase21(
			runtime.Admission.Productive)
		if loadErr != nil || !loaded.Replayed ||
			!reflect.DeepEqual(loaded.Receipt, fixture.local[name].Receipt) {
			t.Fatalf("finalize-before-commit recovery did new work: %#v / %v",
				loaded, loadErr)
		}
		recovered[name] = loaded
	}
	recoveredCommon, err := formalGLMPhase21CertifyOneDrawRelease(
		recovered[fixture.phase21.formal.ctx.ComputePeers[0]],
		recovered[fixture.phase21.formal.ctx.ComputePeers[1]],
		runtime.Admission.Productive)
	if err != nil || !reflect.DeepEqual(recoveredCommon, fixture.certified) {
		t.Fatalf("durable local releases did not recover the common result: %v", err)
	}
	otherRoot := filepath.Join(t.TempDir(), "recovered-sticky", otherPeer)
	otherStore := formalGLMPhase21StickyTestStore(
		t, fixture, otherPeer, otherRoot)
	recoveredPublication, err := otherStore.Commit(fixture.certificate)
	if err != nil || recoveredPublication.Replayed ||
		!bytes.Equal(publication.Certificate, recoveredPublication.Certificate) {
		t.Fatalf("finalize-before-commit recovery changed publication: %#v / %v",
			recoveredPublication, err)
	}

	path, err := restarted.recordPath(publication.ArtifactID, false)
	if err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(filepath.Dir(path), "attacker-hardlink")
	if err := os.Link(path, extra); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Replay(publication.ArtifactID); err == nil {
		t.Fatal("hard-linked sticky record was accepted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Replay(publication.ArtifactID); err == nil {
		t.Fatal("group-readable sticky record was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)/2] ^= 1
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Replay(publication.ArtifactID); err == nil {
		t.Fatal("tampered sticky record passed its local MAC")
	}
	oversized := make([]byte, formalGLMPhase21StickyMaxBytes+1)
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Replay(publication.ArtifactID); err == nil {
		t.Fatal("oversized sticky record bypassed its read bound")
	}

	symlinkRoot := filepath.Join(t.TempDir(), "symlink-root")
	realRoot := filepath.Join(t.TempDir(), "real-root")
	if err := os.MkdirAll(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	storageRoot := sha256.Sum256([]byte(t.Name() + "/symlink-store"))
	if _, err := newFormalGLMPhase21StickyReleaseStore(
		symlinkRoot, peer, storageRoot,
		fixture.phase21.formal.identities.public); err == nil {
		t.Fatal("symlinked sticky store root was accepted")
	}

	ancestorTarget := filepath.Join(t.TempDir(), "ancestor-target")
	if err := os.MkdirAll(ancestorTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	ancestorLink := filepath.Join(t.TempDir(), "ancestor-link")
	if err := os.Symlink(ancestorTarget, ancestorLink); err != nil {
		t.Fatal(err)
	}
	ancestorStore, err := newFormalGLMPhase21StickyReleaseStore(
		filepath.Join(ancestorLink, "store"), peer, storageRoot,
		fixture.phase21.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ancestorLink); err != nil {
		t.Fatal(err)
	}
	replacementTarget := filepath.Join(t.TempDir(), "replacement-target")
	if err := os.MkdirAll(replacementTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacementTarget, ancestorLink); err != nil {
		t.Fatal(err)
	}
	ancestorPublication, err := ancestorStore.Commit(fixture.certificate)
	if err != nil {
		t.Fatal(err)
	}
	ancestorRecord, err := ancestorStore.recordPath(
		ancestorPublication.ArtifactID, false)
	if err != nil || !fileExists(ancestorRecord) ||
		fileExists(filepath.Join(replacementTarget, "store")) {
		t.Fatalf("rooted sticky store followed a replaced ancestor: %v", err)
	}
	ancestorStore.close()

	internalRoot := filepath.Join(t.TempDir(), "internal-symlink", peer)
	internal := formalGLMPhase21StickyTestStore(t, fixture, peer, internalRoot)
	shard := fixture.certificate.ArtifactID[:2]
	outside := filepath.Join(t.TempDir(), "outside-shard")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside,
		filepath.Join(internalRoot, "records-v1", shard)); err != nil {
		t.Fatal(err)
	}
	if _, err := internal.Commit(fixture.certificate); err == nil {
		t.Fatal("sticky commit followed an internal shard symlink")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("internal symlink escaped rooted store: %v / %d", err, len(entries))
	}
	internal.close()
}

func TestFormalGLMPhase21StickyFullFallbackCommitRecovery(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			formalGLMPhase21StickyTestFullFallback(t, custodians)
		})
	}
}

func formalGLMPhase21StickyTestFullFallback(t *testing.T, custodians int) {
	fixture := formalGLMPhase21FullTestSetup(t, custodians, "poisson")
	defer fixture.close()
	outputs := formalGLMPhase21FullTestRun(t, fixture)
	defer func() {
		for peer := range outputs {
			value := outputs[peer]
			value.clear()
		}
	}()
	peers := fixture.full.formal.ctx.ComputePeers
	local := make(map[string]jointDPBiomedicalGaussianFullLocalRelease, 2)
	for _, peer := range peers {
		root := filepath.Join(t.TempDir(), "full-release", peer)
		store, err := newFormalGLMPhase16FullDurableReleaseStore(
			root, peer, fixture.full.backend,
			fixture.full.formal.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		other := peers[0]
		if other == peer {
			other = peers[1]
		}
		local[peer], err = formalGLMPhase21FinalizeFullLocal(
			fixture.stores[peer], store, outputs[peer], outputs[other], nil)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := store.loadReleasedForFormalGLMPhase21(
			outputs[peer].Admission, fixture.full.formal.identities.public)
		if err != nil || !loaded.Replayed ||
			!reflect.DeepEqual(loaded.Receipt, local[peer].Receipt) {
			t.Fatalf("full durable recovery invoked new work: %#v / %v", loaded, err)
		}
	}
	certified, err := formalGLMPhase21CertifyFullRelease(
		local[peers[0]], local[peers[1]], outputs[peers[0]],
		fixture.full.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	source, _, err := fixture.stores[peers[0]].Load()
	if err != nil {
		t.Fatal(err)
	}
	plan := source.Plan
	source.clear()
	unsigned, err := formalGLMPhase21BuildStickyCertificate(
		certified, *outputs[peers[0]].Admission.formalBinding,
		*outputs[peers[0]].Admission.formalToken, plan,
		fixture.full.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	alternateRequest := fixture.full.request
	alternateRequest.PrivacyEpochSHA256 =
		sha256Hex([]byte(t.Name() + "/alternate-privacy-epoch"))
	alternateRequest.ReceiptReferences =
		jointDPBiomedicalGaussianTestReceipts(t.Name() + "/alternate-receipts")
	alternateRequest.NoiseRootEpochs = nil
	alternateRequest.NoiseCommitments = nil
	for _, authority := range unsigned.Artifact.NoiseAuthorities {
		root := sha256.Sum256(
			[]byte(t.Name() + "/alternate-noise-root/" + authority.PeerName))
		epoch, epochErr := jointDPBiomedicalGaussianFullNoiseRootEpoch(
			root, authority.PeerName)
		if epochErr != nil {
			t.Fatal(epochErr)
		}
		alternateRequest.NoiseRootEpochs = append(
			alternateRequest.NoiseRootEpochs,
			jointDPBiomedicalGaussianNoiseRootEpoch{
				PeerName: authority.PeerName, EpochSHA256: epoch,
			})
	}
	alternateIdentity, err := formalGLMPhase16FullFallbackIdentity(
		fixture.full.selection, *outputs[peers[0]].Admission.formalBinding,
		*outputs[peers[0]].Admission.formalToken,
		fixture.full.formal.identities.public, alternateRequest)
	if err != nil {
		t.Fatal(err)
	}
	if alternateIdentity.ReleaseInstanceID ==
		fixture.full.contract.Contract.ReleaseInstanceID {
		t.Fatal("changed legacy epoch/reservation/receipts reused release instance")
	}
	changedEvidence := unsigned
	changedEvidence.Phase15PlanSHA256 = sha256Hex([]byte("new execution plan"))
	changedEvidence.BackendSelectionSHA256 =
		sha256Hex([]byte("new backend evidence"))
	changedEvidence.SelectedBackend = formalGLMPhase16BackendOneDraw
	changedEvidence.SourceReleaseInstanceID =
		sha256Hex([]byte("new legacy source release instance"))
	changedEvidence.SourceReleaseContractSHA256 =
		sha256Hex([]byte("new legacy source release contract"))
	changedEvidence.DPReleaseInstanceID = alternateIdentity.ReleaseInstanceID
	changedEvidence.ReleaseContractSHA256 =
		sha256Hex([]byte("new legacy DP release contract"))
	changedID, err := formalGLMPhase21StickyArtifactID(changedEvidence.Artifact)
	if err != nil || changedID != unsigned.ArtifactID {
		t.Fatalf("legacy operational evidence split canonical artifact: %v", err)
	}
	receipts := make([]jointDPBiomedicalGaussianSignature, 0, 2)
	for _, authority := range unsigned.Artifact.NoiseAuthorities {
		signerRoot := filepath.Join(
			t.TempDir(), "full-sticky-signer", authority.PeerName)
		storageRoot := sha256.Sum256(
			[]byte(t.Name() + "/full-sticky-signer/" + authority.PeerName))
		signer, storeErr := newFormalGLMPhase21StickyReleaseStore(
			signerRoot, authority.PeerName, storageRoot,
			fixture.full.formal.identities.public)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		receipt, replayed, signErr := signer.SignOnce(
			unsigned,
			fixture.full.formal.identities.private[authority.PeerName], receipts)
		signer.close()
		if signErr != nil {
			t.Fatal(signErr)
		}
		if replayed {
			t.Fatal("initial full sticky authority signature was a replay")
		}
		receipts = append(receipts, receipt)
	}
	certificate, err := formalGLMPhase21SealStickyCertificate(
		unsigned, receipts, fixture.full.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	peer := peers[0]
	root := filepath.Join(t.TempDir(), "full-sticky", peer)
	storageRoot := sha256.Sum256([]byte(t.Name() + "/full-sticky/" + peer))
	store, err := newFormalGLMPhase21StickyReleaseStore(
		root, peer, storageRoot, fixture.full.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	crash := errors.New("simulated full crash after durable publication")
	publication, removed, err := formalGLMPhase21CommitFullAndCleanup(
		store, fixture.stores[peer], outputs[peer], certified, certificate,
		func(phase string) error {
			if phase != "after_sticky_commit_before_source_consume" ||
				!fileExists(fixture.stores[peer].recordPath) {
				t.Fatal("full source was consumed before publication")
			}
			return crash
		})
	if !errors.Is(err, crash) || removed != 0 || publication.Replayed {
		t.Fatalf("full commit-before-consume crash contract failed: %#v %d %v",
			publication, removed, err)
	}
	store.close()
	restarted, err := newFormalGLMPhase21StickyReleaseStore(
		root, peer, storageRoot, fixture.full.formal.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	removed, err = formalGLMPhase21CleanupCommittedFull(
		restarted, fixture.stores[peer], publication.ArtifactID,
		fixture.capsule, fixture.productiveRequest,
		fixture.backendSignatures, fixture.full.request, fixture.full.contract)
	if err != nil || removed != outputs[peer].HandoffBytes ||
		fileExists(fixture.stores[peer].recordPath) {
		t.Fatalf("full post-commit recovery did not consume source: %d / %v",
			removed, err)
	}
	replay, err := restarted.Replay(publication.ArtifactID)
	if err != nil || !bytes.Equal(publication.Certificate, replay.Certificate) {
		t.Fatal("full replay changed bytes after source cleanup")
	}
}
