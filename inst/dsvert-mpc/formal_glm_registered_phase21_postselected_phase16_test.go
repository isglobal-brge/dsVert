package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func formalGLMRegisteredPhase21PostSelectedPolicyTestV1(
	t testing.TB,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	private map[string]ed25519.PrivateKey,
) formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1 {
	t.Helper()
	policy := formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1{
		Version:                    formalGLMRegisteredPhase21PostSelectedPhase16PolicyVersionV1,
		Purpose:                    formalGLMRegisteredPhase21PostSelectedPhase16PolicyPurposeV1,
		ArtifactID:                 contract.Core.ArtifactID,
		SourceContractCoreSHA256:   contract.CoreSHA256,
		ManifestSHA256:             sha256Hex([]byte(t.Name() + "/manifest")),
		WorkloadSHA256:             sha256Hex([]byte(t.Name() + "/workload")),
		PrivacyEpochSHA256:         sha256Hex([]byte(t.Name() + "/privacy-epoch")),
		WorkerImplementationSHA256: sha256Hex([]byte(t.Name() + "/worker")),
		ReceiptReferences: jointDPBiomedicalGaussianTestReceipts(
			t.Name() + "/receipt"),
		Epsilon:             "1",
		AllocatedDelta:      "0.000001",
		ProductionReady:     false,
		CustodianSignatures: nil,
	}
	signatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(contract.Core.RegisteredExecutionPlan.CustodianPeers))
	for _, peer := range contract.Core.RegisteredExecutionPlan.CustodianPeers {
		signature, err := formalGLMRegisteredPhase21SignPostSelectedPhase16PolicyV1(
			policy, peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	policy.CustodianSignatures = signatures
	if err := formalGLMRegisteredPhase21ValidatePostSelectedPhase16PolicyV1(
		policy, contract, pins); err != nil {
		t.Fatal(err)
	}
	return policy
}

func formalGLMRegisteredPhase21PostSelectedSamplerTestV1(
	t testing.TB,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	private map[string]ed25519.PrivateKey,
) formalGLMPhase21SamplerV2Contract {
	t.Helper()
	unsigned := contract.Core.SamplerV2ContractCore
	signatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(unsigned.CustodianPeers))
	for _, peer := range unsigned.CustodianPeers {
		signature, err := formalGLMPhase21SignSamplerV2Contract(
			unsigned, peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	sealed, err := formalGLMPhase21SealSamplerV2Contract(unsigned, signatures, pins)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func formalGLMRegisteredPhase21PostSelectedCommitmentsTestV1(
	t testing.TB,
	selected formalGLMRegisteredPhase20SelectedV1,
	source formalGLMPhase20HandoffSource,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
	private map[string]ed25519.PrivateKey,
) []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1 {
	t.Helper()
	receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(source.Result.FinalReceipts)
	if err != nil {
		t.Fatal(err)
	}
	policySHA256, err := formalGLMRegisteredPhase21PostSelectedPhase16PolicySHA256V1(policy)
	if err != nil {
		t.Fatal(err)
	}
	commitments := make([]formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1, 0, 2)
	for _, authority := range contract.Core.RegisteredExecutionPlan.NoiseAuthorities {
		root := sha256.Sum256([]byte(t.Name() + "/authority-root/" + authority.PeerName))
		commitment, deriveErr := formalGLMRegisteredPhase21DerivePostSelectedAuthorityCommitmentV1(
			root, selected.SelectedSHA256, policySHA256,
			fmt.Sprintf("%x", receiptDigest), authority, private[authority.PeerName])
		if deriveErr != nil {
			t.Fatal(deriveErr)
		}
		commitments = append(commitments, commitment)
	}
	if err := formalGLMRegisteredPhase21ValidatePostSelectedAuthorityCommitmentsV1(
		commitments, selected.SelectedSHA256, policySHA256,
		fmt.Sprintf("%x", receiptDigest), contract.Core.RegisteredExecutionPlan, pins); err != nil {
		t.Fatal(err)
	}
	return commitments
}

func formalGLMRegisteredPhase21PostSelectedTestOwnersV1(
	t *testing.T,
) ([2]*formalGLMRegisteredPhase20TerminalOwnerV1,
	formalGLMRegisteredPhase20DPShareReceiptTestFixtureV1) {
	t.Helper()
	fixture := formalGLMRegisteredPhase20DPShareReceiptTestBuildV1(t)
	base := fixture.evidence
	peers := base.source.plan.DesignatedComputePeers
	roots := [2]string{
		filepath.Join(t.TempDir(), "garbler-rock"),
		filepath.Join(t.TempDir(), "evaluator-rock"),
	}
	for _, root := range roots {
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var attempts [2]*formalGLMRegisteredPhase19AttemptStoreV1
	for index, peer := range peers {
		var err error
		attempts[index], err = newFormalGLMRegisteredPhase19AttemptStoreV1(
			roots[index], base.record, base.source.contract,
			base.source.inputs.identities.public, peer,
			base.source.inputs.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
	}
	proposal, _, err := attempts[0].Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := attempts[1].Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var owners [2]*formalGLMRegisteredPhase20TerminalOwnerV1
	for index, peer := range peers {
		if err := formalGLMRegisteredPhase19ScheduleTailPersistClaimV1(
			attempts[index], base.record, base.source.contract,
			base.source.inputs.identities.public, peer, proposal, accept); err != nil {
			t.Fatal(err)
		}
		keys, keyErr := newFormalGLMRegisteredPhase20JobKeyProviderV1(
			roots[index], base.source.contract, base.source.inputs.identities.public,
			base.record, peer)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		owner, ownerErr := newFormalGLMRegisteredPhase20TerminalOwnerV1(
			attempts[index], keys, base.runtime, proposal, accept)
		if ownerErr != nil {
			t.Fatal(ownerErr)
		}
		owners[index] = owner
		t.Cleanup(func() { _ = owner.Close() })
	}
	return owners, fixture
}

func TestFormalGLMRegisteredPhase21PostSelectedPhase16PolicyK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMSourceContractTestFixture(t, custodians)
			policy := formalGLMRegisteredPhase21PostSelectedPolicyTestV1(
				t, fixture.contract, fixture.inputs.identities.public,
				fixture.inputs.identities.private)
			if _, err := formalGLMRegisteredPhase21PostSelectedPhase16PolicySHA256V1(policy); err != nil {
				t.Fatal(err)
			}
			tampered := policy
			tampered.CustodianSignatures = append(
				[]jointDPBiomedicalGaussianSignature(nil), policy.CustodianSignatures...)
			tampered.CustodianSignatures[0].Signature = append(
				[]byte(nil), tampered.CustodianSignatures[0].Signature...)
			tampered.CustodianSignatures[0].Signature[0] ^= 1
			if err := formalGLMRegisteredPhase21ValidatePostSelectedPhase16PolicyV1(
				tampered, fixture.contract, fixture.inputs.identities.public); err == nil {
				t.Fatal("tampered K-of-K post-Selected policy was accepted")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase21BuildPostSelectedPhase16K2(t *testing.T) {
	owners, fixture := formalGLMRegisteredPhase21PostSelectedTestOwnersV1(t)
	evidence := [2]formalGLMRegisteredPhase20PreparedEvidenceV1{
		fixture.garbler, fixture.evaluator,
	}
	selected, err := formalGLMRegisteredPhase20HandoffAdapterTestSelectV1(t, owners, evidence)
	if err != nil || !reflect.DeepEqual(selected[0], selected[1]) {
		t.Fatalf("Selected: %v", err)
	}
	base := fixture.evidence
	policy := formalGLMRegisteredPhase21PostSelectedPolicyTestV1(
		t, base.source.contract, base.source.inputs.identities.public,
		base.source.inputs.identities.private)
	var proposals [2]formalGLMRegisteredPhase21PostSelectedPhase16V1
	var commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1
	for index, owner := range owners {
		selectedLocal, trusted, loadErr := owner.LoadSelectedSourceV1()
		if loadErr != nil || !reflect.DeepEqual(selectedLocal, selected[index]) {
			trusted.clear()
			t.Fatalf("load Selected %d: %v", index, loadErr)
		}
		if commitments == nil {
			commitments = formalGLMRegisteredPhase21PostSelectedCommitmentsTestV1(
				t, selectedLocal, trusted.source, policy, base.source.contract,
				base.source.inputs.identities.public, base.source.inputs.identities.private)
			tamperedCommitments := append(
				[]formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1(nil), commitments...)
			tamperedCommitments[0].Signature.Signature = append(
				[]byte(nil), tamperedCommitments[0].Signature.Signature...)
			tamperedCommitments[0].Signature.Signature[0] ^= 1
			if _, tamperErr := formalGLMRegisteredPhase21BuildPostSelectedPhase16V1(
				selectedLocal, trusted.source, policy, base.source.contract,
				tamperedCommitments, base.source.inputs.identities.public); tamperErr == nil {
				trusted.clear()
				t.Fatal("tampered authority commitment was accepted")
			}
		}
		proposal, buildErr := formalGLMRegisteredPhase21BuildPostSelectedPhase16V1(
			selectedLocal, trusted.source, policy, base.source.contract,
			commitments,
			base.source.inputs.identities.public)
		trusted.clear()
		if buildErr != nil {
			t.Fatalf("build proposal %d: %v", index, buildErr)
		}
		proposals[index] = proposal
	}
	if !reflect.DeepEqual(proposals[0], proposals[1]) {
		encoded, _ := json.Marshal(proposals)
		t.Fatalf("compute peers derived different post-Selected Phase16 proposals: %s", encoded)
	}
	if proposals[0].ProductionReady || proposals[0].SelectedSHA256 != selected[0].SelectedSHA256 ||
		len(proposals[0].BackendSelection.CustodianPeers) != 2 ||
		proposals[0].WorkerPreimage.OpeningsAuthorized != 0 {
		t.Fatalf("invalid post-Selected proposal: %+v", proposals[0])
	}
	tampered := proposals[0]
	tampered.WorkerPreimage.WorkloadSHA256 = sha256Hex([]byte("tampered"))
	if err := formalGLMRegisteredPhase21ValidatePostSelectedPhase16V1(
		tampered, policy, base.source.contract, base.source.inputs.identities.public); err == nil {
		t.Fatal("tampered post-Selected proposal was accepted")
	}
}
