package main

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type formalGLMPhase17TestContext struct {
	plan       formalGLMPhase15Plan
	approvals  []formalGLMPhase15Approval
	receipts   []formalGLMPhase15StepReceipt
	identities formalGLMPhase15TestIdentities
	bridge     formalGLMPhase15DPBridgePlan
	capsule    formalGLMPhase16CapsuleBinding
	manifest   formalGLMPhase17ManifestBinding
	source     formalGLMPhase17SourceContributionAttestation
	preimage   formalGLMPhase17AdmissionPreimage
	signed     formalGLMPhase17SignedAdmission
}

func formalGLMPhase17TestSignSource(t testing.TB,
	contract formalGLMPhase17SourceContributionContract,
	plan formalGLMPhase15Plan,
	identities formalGLMPhase15TestIdentities) []formalGLMPhase17CustodianSignature {
	t.Helper()
	result := make([]formalGLMPhase17CustodianSignature,
		len(plan.Kernel.CustodianPeers))
	for index, peer := range plan.Kernel.CustodianPeers {
		signature, err := formalGLMPhase17SignSourceContribution(
			contract, peer, identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		result[index] = signature
	}
	return result
}

func formalGLMPhase17TestSignAdmission(t testing.TB,
	preimage formalGLMPhase17AdmissionPreimage, plan formalGLMPhase15Plan,
	identities formalGLMPhase15TestIdentities) []formalGLMPhase17CustodianSignature {
	t.Helper()
	result := make([]formalGLMPhase17CustodianSignature,
		len(plan.Kernel.CustodianPeers))
	for index, peer := range plan.Kernel.CustodianPeers {
		signature, err := formalGLMPhase17SignAdmission(
			preimage, peer, identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		result[index] = signature
	}
	return result
}

func formalGLMPhase17TestManifest(t testing.TB, plan formalGLMPhase15Plan,
	receipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey, bridge formalGLMPhase15DPBridgePlan,
	capsule formalGLMPhase16CapsuleBinding,
	contract formalGLMPhase17SourceContributionContract) formalGLMPhase17ManifestBinding {
	t.Helper()
	binding, err := buildFormalGLMPhase16ReleaseBinding(
		plan, receipts, pins, bridge, capsule)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := formalGLMPhase17SourceContributionContractDigest(contract)
	if err != nil {
		t.Fatal(err)
	}
	return buildFormalGLMPhase17ManifestBinding(
		plan, binding, hex.EncodeToString(digest[:]))
}

func formalGLMPhase17TestSetup(t testing.TB, custodians int,
	tag string) formalGLMPhase17TestContext {
	t.Helper()
	plan, receipts, identities, bridge, capsule :=
		formalGLMPhase16TestContext(t, custodians, tag)
	approvals := formalGLMPhase15TestApprovals(t, plan, identities)
	contract, err := buildFormalGLMPhase17SourceContributionContract(
		plan, bridge, capsule)
	if err != nil {
		t.Fatal(err)
	}
	source := formalGLMPhase17SourceContributionAttestation{
		Contract: contract,
		Signatures: formalGLMPhase17TestSignSource(
			t, contract, plan, identities),
	}
	manifest := formalGLMPhase17TestManifest(
		t, plan, receipts, identities.public, bridge, capsule, contract)
	preimage, err := formalGLMPhase17PrepareAdmissionPreimage(
		plan, approvals, receipts, identities.public, bridge, capsule,
		manifest, source)
	if err != nil {
		t.Fatal(err)
	}
	signed := formalGLMPhase17SignedAdmission{
		Preimage: preimage,
		Signatures: formalGLMPhase17TestSignAdmission(
			t, preimage, plan, identities),
	}
	return formalGLMPhase17TestContext{
		plan: plan, approvals: approvals, receipts: receipts,
		identities: identities, bridge: bridge, capsule: capsule,
		manifest: manifest, source: source, preimage: preimage, signed: signed,
	}
}

func TestFormalGLMPhase17AuthenticatesK2K3K5ButKeepsOpeningSealed(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			ctx := formalGLMPhase17TestSetup(t, custodians, t.Name())
			admission, err := admitFormalGLMPhase17(
				ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
				ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed)
			var blocker *formalGLMPhase17ReleaseBlocker
			if !errors.As(err, &blocker) ||
				blocker.Code != formalGLMPhase17MaterializerBlockerCode ||
				blocker.OpeningsPerformed != 0 || len(blocker.Missing) != 2 {
				t.Fatalf("expected exact materializer blocker, got %T %v", err, err)
			}
			if err := validateFormalGLMPhase17AuthenticatedAdmission(admission); err != nil {
				t.Fatal(err)
			}
			if admission.worker == nil ||
				admission.worker.WorkerPolicy.TranscriptHash !=
					ctx.preimage.ReleaseContractSHA256 ||
				ctx.preimage.ReleaseContractSHA256 !=
					ctx.preimage.WorkerTranscriptSHA256 ||
				ctx.preimage.CustodianCount != custodians ||
				len(ctx.preimage.CustodianPeers) != custodians ||
				ctx.preimage.TotalCapacity != ctx.plan.TotalCapacity ||
				ctx.preimage.MaximumActiveRowsPerPatient != 1 ||
				ctx.preimage.CapacitySemantics != formalGLMPhase17CapacitySemantics ||
				ctx.preimage.PatientContribution != formalGLMPhase17PatientContribution ||
				admission.ProtectedDataE2EVerified || admission.ProductionReady ||
				admission.OpeningsPerformed != 0 {
				t.Fatalf("invalid authenticated but sealed admission: %+v", admission)
			}
			if err := formalGLMPhase17AuthorizeOpening(admission); !errors.As(err, &blocker) || blocker.OpeningsPerformed != 0 {
				t.Fatalf("opening was not sealed: %T %v", err, err)
			}
			encoded, err := json.Marshal(admission)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"worker_policy", "private_seed", "beta_share", "gradient_share",
			} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("serialized admission exposed %q", forbidden)
				}
			}
		})
	}
}

func TestFormalGLMPhase17RequiresExactKSignaturesAtBothBarriers(t *testing.T) {
	ctx := formalGLMPhase17TestSetup(t, 3, t.Name())

	for name, mutate := range map[string]func(*formalGLMPhase17SignedAdmission){
		"omitted": func(value *formalGLMPhase17SignedAdmission) {
			value.Signatures = value.Signatures[:2]
		},
		"duplicate": func(value *formalGLMPhase17SignedAdmission) {
			value.Signatures[2] = value.Signatures[0]
		},
		"extra": func(value *formalGLMPhase17SignedAdmission) {
			value.Signatures = append(value.Signatures, value.Signatures[0])
		},
		"wrong-key": func(value *formalGLMPhase17SignedAdmission) {
			_, wrong, err := ed25519.GenerateKey(crand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			message, err := formalGLMPhase17AdmissionMessage(value.Preimage)
			if err != nil {
				t.Fatal(err)
			}
			value.Signatures[0].Signature = ed25519.Sign(wrong, message)
		},
	} {
		t.Run("admission-"+name, func(t *testing.T) {
			changed := ctx.signed
			changed.Signatures = append(
				[]formalGLMPhase17CustodianSignature(nil), ctx.signed.Signatures...)
			mutate(&changed)
			if _, err := admitFormalGLMPhase17(
				ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
				ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, changed); err == nil {
				t.Fatalf("%s Phase-1.7 signature set was accepted", name)
			}
		})
	}

	for name, mutate := range map[string]func(*formalGLMPhase17SourceContributionAttestation){
		"omitted": func(value *formalGLMPhase17SourceContributionAttestation) {
			value.Signatures = value.Signatures[:2]
		},
		"duplicate": func(value *formalGLMPhase17SourceContributionAttestation) {
			value.Signatures[2] = value.Signatures[0]
		},
		"extra": func(value *formalGLMPhase17SourceContributionAttestation) {
			value.Signatures = append(value.Signatures, value.Signatures[0])
		},
		"wrong-key": func(value *formalGLMPhase17SourceContributionAttestation) {
			_, wrong, err := ed25519.GenerateKey(crand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			message, err := formalGLMPhase17SourceContributionMessage(value.Contract)
			if err != nil {
				t.Fatal(err)
			}
			value.Signatures[0].Signature = ed25519.Sign(wrong, message)
		},
	} {
		t.Run("source-"+name, func(t *testing.T) {
			changed := ctx.source
			changed.Signatures = append(
				[]formalGLMPhase17CustodianSignature(nil), ctx.source.Signatures...)
			mutate(&changed)
			if _, err := formalGLMPhase17PrepareAdmissionPreimage(
				ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
				ctx.bridge, ctx.capsule, ctx.manifest, changed); err == nil {
				t.Fatalf("%s source signature set was accepted", name)
			}
		})
	}

	if _, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals[:2], ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("incomplete Phase-1.5 approval set was accepted")
	}
	wrongNamedApproval := append([]formalGLMPhase15Approval(nil), ctx.approvals...)
	wrongNamedApproval[0].Signer, wrongNamedApproval[1].Signer =
		wrongNamedApproval[1].Signer, wrongNamedApproval[0].Signer
	if _, err := admitFormalGLMPhase17(
		ctx.plan, wrongNamedApproval, ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("plan approval signed by a different named identity was accepted")
	}
	badReceipt := append([]formalGLMPhase15StepReceipt(nil), ctx.receipts...)
	badReceipt[0].Signature = append([]byte(nil), badReceipt[0].Signature...)
	badReceipt[0].Signature[0] ^= 1
	if _, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, badReceipt, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("invalid final receipt was accepted")
	}
	wrongRoleReceipt := append([]formalGLMPhase15StepReceipt(nil), ctx.receipts...)
	wrongRoleReceipt[0].Peer = ctx.plan.Kernel.CustodianPeers[2]
	wrongRoleReceipt[0].Signature = ed25519.Sign(
		ctx.identities.private[wrongRoleReceipt[0].Peer],
		formalGLMPhase15ReceiptUnsigned(wrongRoleReceipt[0]))
	if _, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, wrongRoleReceipt, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("valid custodian key signed a receipt for a non-compute role")
	}
}

func TestFormalGLMPhase17RejectsCallerSuppliedSensitivityAndGenericWorker(t *testing.T) {
	ctx := formalGLMPhase17TestSetup(t, 3, t.Name())
	tampered := ctx.bridge
	tampered.SelectedSensitivityCertificate.SelectedBoundSteps = "1"
	tampered.SelectedSensitivityCertificate.SelectedProof =
		formalGLMPhase15DPUniversalProof
	digest, err := formalGLMPhase15DPSensitivityCertificateDigest(
		tampered.SelectedSensitivityCertificate)
	if err != nil {
		t.Fatal(err)
	}
	tampered.SelectedSensitivitySteps = "1"
	tampered.SelectedSensitivityProof = formalGLMPhase15DPUniversalProof
	tampered.SelectedSensitivityCertificateSHA256 = hex.EncodeToString(digest[:])
	if _, err := formalGLMPhase17PrepareAdmissionPreimage(
		ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
		tampered, ctx.capsule, ctx.manifest, ctx.source); err == nil {
		t.Fatal("self-consistent caller-supplied sensitivity certificate was accepted")
	}

	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("phase17-arbitrary-certificate-g"))
	eseed := sha256.Sum256([]byte("phase17-arbitrary-certificate-e"))
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"10"}, gseed, eseed, 3)
	generic, err := jointDPCompileGaussianOneDrawWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	forged := formalGLMPhase17AuthenticatedAdmission{
		Version:                 formalGLMPhase17AdmissionVersion,
		AuthenticatedGatePassed: true, worker: &generic,
	}
	if err := validateFormalGLMPhase17AuthenticatedAdmission(forged); err == nil {
		t.Fatal("generic worker with arbitrary machine_proven certificate became a typed admission")
	}
	if err := formalGLMPhase17AuthorizeOpening(forged); err == nil {
		t.Fatal("generic worker reached the opening boundary")
	}
}

func TestFormalGLMPhase17RejectsReleaseTranscriptMismatchInGenericWorker(t *testing.T) {
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	gseed := sha256.Sum256([]byte("phase17-release-mismatch-g"))
	eseed := sha256.Sum256([]byte("phase17-release-mismatch-e"))
	input := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"10"}, gseed, eseed, 3)
	var binding formalGLMPhase16ReleaseBinding
	if err := json.Unmarshal([]byte(input.ReleaseBindingCanonicalJSON), &binding); err != nil {
		t.Fatal(err)
	}
	binding.ReleaseContractSHA256 = sha256Hex([]byte("different release contract"))
	preimage, err := formalGLMPhase16ReleaseBindingPreimage(binding)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := formalGLMPhase16ReleaseBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	input.ReleaseBindingCanonicalJSON = string(preimage)
	input.ReleaseBindingSHA256 = digest
	input.CrossSignedPolicySHA256 = digest
	if _, err := jointDPCompileGaussianOneDrawWorkerContract(input); err == nil {
		t.Fatal("release binding differing from worker transcript was accepted")
	}
}

func TestFormalGLMPhase17ContributionAndSemanticHashSubstitutionsFail(t *testing.T) {
	ctx := formalGLMPhase17TestSetup(t, 3, t.Name())
	for name, mutate := range map[string]func(*formalGLMPhase17SourceContributionContract){
		"capacity": func(value *formalGLMPhase17SourceContributionContract) {
			value.TotalCapacity++
		},
		"max-active": func(value *formalGLMPhase17SourceContributionContract) {
			value.MaximumActiveRowsPerPatient = 2
		},
		"patient": func(value *formalGLMPhase17SourceContributionContract) {
			value.PatientContribution = "unbounded"
		},
		"adjacency": func(value *formalGLMPhase17SourceContributionContract) {
			value.AdjacencySemantics = "variable_denominator"
		},
		"false-e2e": func(value *formalGLMPhase17SourceContributionContract) {
			value.ProtectedDataE2EVerified = true
		},
	} {
		t.Run("source-"+name, func(t *testing.T) {
			changed := ctx.source
			mutate(&changed.Contract)
			changed.Signatures = formalGLMPhase17TestSignSource(
				t, changed.Contract, ctx.plan, ctx.identities)
			if _, err := formalGLMPhase17PrepareAdmissionPreimage(
				ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
				ctx.bridge, ctx.capsule, ctx.manifest, changed); err == nil {
				t.Fatalf("modified %s contribution contract was accepted", name)
			}
		})
	}

	tamper := sha256Hex([]byte("phase17 semantic substitution"))
	for name, mutate := range map[string]func(*formalGLMPhase17ManifestBinding){
		"plan":            func(value *formalGLMPhase17ManifestBinding) { value.Phase15PlanSHA256 = tamper },
		"kernel":          func(value *formalGLMPhase17ManifestBinding) { value.KernelSpecSHA256 = tamper },
		"bounds":          func(value *formalGLMPhase17ManifestBinding) { value.BoundsSHA256 = tamper },
		"source":          func(value *formalGLMPhase17ManifestBinding) { value.SourceContextSHA256 = tamper },
		"source-contract": func(value *formalGLMPhase17ManifestBinding) { value.SourceContractSHA256 = tamper },
		"snapshot":        func(value *formalGLMPhase17ManifestBinding) { value.SnapshotSHA256 = tamper },
		"fan-in":          func(value *formalGLMPhase17ManifestBinding) { value.SourceFanInTranscriptSHA256 = tamper },
		"bridge":          func(value *formalGLMPhase17ManifestBinding) { value.Phase15BridgeSHA256 = tamper },
		"certificate":     func(value *formalGLMPhase17ManifestBinding) { value.SensitivityCertificateSHA256 = tamper },
		"order":           func(value *formalGLMPhase17ManifestBinding) { value.CoordinateOrderSHA256 = tamper },
		"manifest":        func(value *formalGLMPhase17ManifestBinding) { value.ManifestSHA256 = tamper },
		"workload":        func(value *formalGLMPhase17ManifestBinding) { value.WorkloadSHA256 = tamper },
		"release":         func(value *formalGLMPhase17ManifestBinding) { value.ReleaseContractSHA256 = tamper },
	} {
		t.Run("manifest-"+name, func(t *testing.T) {
			changed := ctx.manifest
			mutate(&changed)
			if _, err := formalGLMPhase17PrepareAdmissionPreimage(
				ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
				ctx.bridge, ctx.capsule, changed, ctx.source); err == nil {
				t.Fatalf("%s hash substitution was accepted", name)
			}
		})
	}

	changedSigned := ctx.signed
	changedSigned.Preimage.WorkerTranscriptSHA256 = tamper
	if _, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, changedSigned); err == nil {
		t.Fatal("signed-preimage hash substitution was accepted")
	}
}

func TestFormalGLMPhase17ReplayIsIdempotentAndCrossInstanceReplayFails(t *testing.T) {
	ctx := formalGLMPhase17TestSetup(t, 3, t.Name())
	first, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed)
	var blocker *formalGLMPhase17ReleaseBlocker
	if !errors.As(err, &blocker) {
		t.Fatalf("expected blocker, got %T %v", err, err)
	}
	reversed := ctx.signed
	reversed.Signatures = append(
		[]formalGLMPhase17CustodianSignature(nil), ctx.signed.Signatures...)
	for left, right := 0, len(reversed.Signatures)-1; left < right; left, right = left+1, right-1 {
		reversed.Signatures[left], reversed.Signatures[right] =
			reversed.Signatures[right], reversed.Signatures[left]
	}
	second, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, reversed)
	if !errors.As(err, &blocker) || !reflect.DeepEqual(first, second) {
		t.Fatal("identical signed replay was not idempotent")
	}
	reorderedSource := ctx.source
	reorderedSource.Signatures = append(
		[]formalGLMPhase17CustodianSignature(nil), ctx.source.Signatures...)
	for left, right := 0, len(reorderedSource.Signatures)-1; left < right; left, right = left+1, right-1 {
		reorderedSource.Signatures[left], reorderedSource.Signatures[right] =
			reorderedSource.Signatures[right], reorderedSource.Signatures[left]
	}
	reorderedPreimage, err := formalGLMPhase17PrepareAdmissionPreimage(
		ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, reorderedSource)
	if err != nil || !reflect.DeepEqual(reorderedPreimage, ctx.preimage) {
		t.Fatal("signature ordering changed the canonical source attestation")
	}

	changedCapsule := ctx.capsule
	changedCapsule.ReleaseInstanceID = sha256Hex([]byte("phase17 changed release instance"))
	changedManifest := formalGLMPhase17TestManifest(
		t, ctx.plan, ctx.receipts, ctx.identities.public, ctx.bridge,
		changedCapsule, ctx.source.Contract)
	if _, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
		ctx.bridge, changedCapsule, changedManifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("old Phase-1.7 signatures replayed into a new release instance")
	}
}

func TestFormalGLMPhase17TypedAdmissionSealRejectsMutation(t *testing.T) {
	ctx := formalGLMPhase17TestSetup(t, 2, t.Name())
	admission, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed)
	var blocker *formalGLMPhase17ReleaseBlocker
	if !errors.As(err, &blocker) {
		t.Fatalf("expected blocker, got %T %v", err, err)
	}

	changed := admission
	changed.PreimageSHA256 = sha256Hex([]byte("changed Phase-1.7 preimage"))
	if err := validateFormalGLMPhase17AuthenticatedAdmission(changed); err == nil {
		t.Fatal("changed preimage digest retained a valid admission seal")
	}
	changed = admission
	changed.AdmissionTokenSHA256 = sha256Hex([]byte("changed Phase-1.7 token"))
	if err := validateFormalGLMPhase17AuthenticatedAdmission(changed); err == nil {
		t.Fatal("changed token retained a valid admission seal")
	}
	changed = admission
	worker := *admission.worker
	worker.WorkerPolicy.TranscriptHash = sha256Hex([]byte("changed worker transcript"))
	changed.worker = &worker
	if err := validateFormalGLMPhase17AuthenticatedAdmission(changed); err == nil {
		t.Fatal("changed worker retained a valid admission seal")
	}
}

func TestFormalGLMPhase17PinsetAndRemoteSurfaceStayClosed(t *testing.T) {
	ctx := formalGLMPhase17TestSetup(t, 3, t.Name())
	copyPins := func() map[string]ed25519.PublicKey {
		result := make(map[string]ed25519.PublicKey, len(ctx.identities.public))
		for peer, pin := range ctx.identities.public {
			result[peer] = append(ed25519.PublicKey(nil), pin...)
		}
		return result
	}
	wrongPins := copyPins()
	wrongPins[ctx.plan.Kernel.CustodianPeers[2]][0] ^= 1
	if _, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, ctx.receipts, wrongPins,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("wrong custodian pin was accepted")
	}
	omittedPins := copyPins()
	delete(omittedPins, ctx.plan.Kernel.CustodianPeers[2])
	if _, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, ctx.receipts, omittedPins,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("omitted custodian pin was accepted")
	}
	extraPins := copyPins()
	extraPublic, _, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extraPins["peer-extra"] = extraPublic
	if _, err := admitFormalGLMPhase17(
		ctx.plan, ctx.approvals, ctx.receipts, extraPins,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("extra custodian pin was accepted")
	}

	unsortedPlan := ctx.plan
	unsortedPlan.Kernel.CustodianPeers = append(
		[]string(nil), ctx.plan.Kernel.CustodianPeers...)
	unsortedPlan.Kernel.CustodianPeers[0], unsortedPlan.Kernel.CustodianPeers[1] =
		unsortedPlan.Kernel.CustodianPeers[1], unsortedPlan.Kernel.CustodianPeers[0]
	if _, err := admitFormalGLMPhase17(
		unsortedPlan, ctx.approvals, ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("unsorted custodian set was accepted")
	}
	duplicatePlan := ctx.plan
	duplicatePlan.Kernel.CustodianPeers = append(
		[]string(nil), ctx.plan.Kernel.CustodianPeers...)
	duplicatePlan.Kernel.CustodianPeers[1] = duplicatePlan.Kernel.CustodianPeers[0]
	if _, err := admitFormalGLMPhase17(
		duplicatePlan, ctx.approvals, ctx.receipts, ctx.identities.public,
		ctx.bridge, ctx.capsule, ctx.manifest, ctx.source, ctx.signed); err == nil {
		t.Fatal("duplicate custodian set was accepted")
	}

	encoded, err := json.Marshal(runtimeCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"phase17", "phase-1.7", "formal-glm", "formal_glm",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("Phase-1.7 was promoted through runtime capabilities: %s", forbidden)
		}
	}
	typeOfAdmission := reflect.TypeOf(formalGLMPhase17AuthenticatedAdmission{})
	for _, fieldName := range []string{"worker", "seal"} {
		field, ok := typeOfAdmission.FieldByName(fieldName)
		if !ok || field.PkgPath == "" {
			t.Fatalf("Phase-1.7 %s is not package-private", fieldName)
		}
	}
	for _, file := range []string{
		"main.go", "runtime_capabilities.go", "k2_exact_gc_worker.go",
	} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "formalGLMPhase17") ||
			strings.Contains(string(source), "formal-glm-phase17") {
			t.Fatalf("%s exposes or unmarshals Phase-1.7", file)
		}
	}
}
