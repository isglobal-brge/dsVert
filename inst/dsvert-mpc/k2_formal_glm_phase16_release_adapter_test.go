package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"testing"
)

func formalGLMPhase16TestCapsule(t testing.TB, plan formalGLMPhase15Plan,
	pins map[string]ed25519.PublicKey, tag string) formalGLMPhase16CapsuleBinding {
	t.Helper()
	roles, err := formalGLMPhase16PinnedRoles(plan, pins)
	if err != nil {
		t.Fatal(err)
	}
	hash := func(label string) string {
		value := sha256.Sum256([]byte("phase16/" + tag + "/" + label))
		return hex.EncodeToString(value[:])
	}
	releaseContractRaw := sha256.Sum256(
		[]byte("phase16/" + tag + "/release-contract"))
	releaseContract := hex.EncodeToString(releaseContractRaw[:])
	commitments := make(map[string]formalGLMPhase16NoiseCommitment, 2)
	for _, entry := range []struct {
		peerID, role string
	}{
		{roles.GarblerPeerID, "garbler"},
		{roles.EvaluatorPeerID, "evaluator"},
	} {
		context := jointDPCommitmentContext(releaseContractRaw,
			jointDPGaussianOneDrawCommitmentPurpose+"/"+entry.role,
			entry.peerID)
		seed := sha256.Sum256([]byte("phase16/" + tag + "/" + entry.role + "/seed"))
		commitment := jointDPSeedCommitment(context, seed)
		commitments[entry.peerID] = formalGLMPhase16NoiseCommitment{
			ContextSHA256: hex.EncodeToString(context[:]),
			SeedSHA256:    hex.EncodeToString(commitment[:]),
		}
	}
	return formalGLMPhase16CapsuleBinding{
		CapsuleID:            hash("capsule"),
		ManifestSHA256:       hash("manifest"),
		SchemaManifestSHA256: hash("schema"),
		WorkloadSHA256:       hash("workload"),
		SourceContextSHA256:  hash("source-context"),
		CoordinateOrderSHA256: formalGLMPhase16CoefficientOrderSHA256(
			plan.Kernel.CoefficientCount),
		ReleaseInstanceID:     hash("release-instance"),
		ReleaseContractSHA256: releaseContract,
		Mechanism:             formalGLMPhase16RequiredMechanism,
		Allocation:            formalGLMPhase16RequiredAllocation,
		Epsilon:               "1",
		AllocatedDelta:        "0.000001",
		NoiseCommitments:      commitments,
	}
}

func formalGLMPhase16TestContext(t testing.TB, custodians int, tag string) (
	formalGLMPhase15Plan, []formalGLMPhase15StepReceipt,
	formalGLMPhase15TestIdentities, formalGLMPhase15DPBridgePlan,
	formalGLMPhase16CapsuleBinding) {
	t.Helper()
	plan := formalGLMPhase15TestPlan(t, "binomial", custodians, 1, 2, 2, 1)
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
	pinset, err := formalGLMPhase16PinsetSHA256(identities.public)
	if err != nil {
		t.Fatal(err)
	}
	plan.Kernel.PinsetSHA256 = pinset
	beta := make(map[string][]*big.Int, 2)
	for index, peer := range plan.Kernel.ComputePeers {
		beta[peer] = []*big.Int{big.NewInt(int64(3 + index)), big.NewInt(int64(7 + index))}
	}
	transcript, attempt := formalGLMPhase15TestExecutionTranscript(t, plan, tag)
	receipts := formalGLMPhase15TestFinalReceipts(
		t, plan, identities, transcript, attempt, beta)
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, 6)
	if err != nil {
		t.Fatal(err)
	}
	capsule := formalGLMPhase16TestCapsule(t, plan, identities.public, tag)
	return plan, receipts, identities, bridge, capsule
}

func TestFormalGLMPhase16BuildsGaussianBindingForK2K3K5WithoutLaplaceSubstitution(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			plan, receipts, identities, bridge, capsule :=
				formalGLMPhase16TestContext(t, custodians, t.Name())
			compiled, err := compileFormalGLMPhase16ReleaseAdapter(
				plan, receipts, identities.public, bridge, capsule)
			var blocker *formalGLMPhase16ReleaseBlocker
			if !errors.As(err, &blocker) ||
				blocker.Code != formalGLMPhase16ManifestBlockerCode ||
				blocker.OpeningsPerformed != 0 || len(blocker.Missing) != 1 {
				t.Fatalf("expected exact zero-opening manifest blocker: %T %v", err, err)
			}
			if compiled.Binding.CustodianCount != custodians ||
				compiled.Binding.GarblerPeerID >= compiled.Binding.EvaluatorPeerID ||
				bridge.GarblerPeerID != compiled.Binding.GarblerPeerID ||
				bridge.EvaluatorPeerID != compiled.Binding.EvaluatorPeerID ||
				compiled.Binding.RoleSelection !=
					"lexicographic_pinned_cryptographic_peer_id_v1" ||
				compiled.Binding.SourceFanInTranscriptSHA256 !=
					bridge.ExecutionTranscriptSHA256 ||
				compiled.Binding.OpeningCount != 1 ||
				compiled.Binding.Mechanism != formalGLMPhase16RequiredMechanism ||
				compiled.Binding.Allocation != formalGLMPhase16RequiredAllocation ||
				compiled.Binding.SensitivityNorm != "l2" ||
				compiled.Binding.SensitivityProof != formalGLMPhase15DPTightProof ||
				compiled.Binding.SensitivitySteps != "12" ||
				compiled.Binding.SensitivityCertificateSHA256 !=
					bridge.SelectedSensitivityCertificateSHA256 ||
				compiled.Worker == nil || !compiled.Worker.CapabilityAvailable ||
				compiled.Worker.WorkerPolicy.ReleaseBindingSHA256 !=
					compiled.Binding.BindingSHA256 ||
				compiled.Worker.WorkerPolicy.PinsetSHA256 != compiled.Binding.PinsetSHA256 {
				t.Fatalf("invalid Phase-1.6/common contract: %+v", compiled)
			}
			attempt := sha256.Sum256([]byte("phase16/role-session/" + t.Name()))
			master := sha256.Sum256([]byte("phase16/role-master/" + t.Name()))
			session, err := formalGLMPhase15DPBridgeSession(
				plan, bridge, attempt, master)
			if err != nil {
				t.Fatal(err)
			}
			if session.GarblerID != compiled.Binding.GarblerPeerID ||
				session.EvaluatorID != compiled.Binding.EvaluatorPeerID {
				t.Fatal("Go bridge session used logical names instead of pinned IDs")
			}
			encoded, _ := json.Marshal(compiled)
			for _, forbidden := range []string{
				`"beta_share":`, `"private_seed":`, `"exact_beta":`,
				`"gradient_share":`,
			} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("compiled public contract exposed %q", forbidden)
				}
			}
		})
	}
}

func TestFormalGLMPhase16PinsetAndPeerIDsMatchRCanonicalContract(t *testing.T) {
	left := make(ed25519.PublicKey, ed25519.PublicKeySize)
	right := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for index := range left {
		left[index] = byte(index)
		right[index] = byte(index + 32)
	}
	pins := map[string]ed25519.PublicKey{"peer-b": right, "peer-a": left}
	digest, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "4233747f2bbc6b5156d86c63c70806f84e2a5709b3a9a5b58a4df4364c9ec851" {
		t.Fatalf("Go/R pinset canonicalization differs: %s", digest)
	}
	leftID, _ := formalGLMPhase16PeerID(left)
	rightID, _ := formalGLMPhase16PeerID(right)
	if leftID != "dsv1_14b36e0d42f51f76b15d754b9e77071aeaa4eabee312c8a9f9123103d98edded" ||
		rightID != "dsv1_daa34a545a35bf94768085ab7d03a6ab503c7e82da15e7f1a49c693e5db9441a" {
		t.Fatalf("Go/R peer-ID derivation differs: %s / %s", leftID, rightID)
	}
}

func TestFormalGLMPhase16HasNoPromotedRuntimeCapability(t *testing.T) {
	encoded, err := json.Marshal(runtimeCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"formal-glm", "formal_glm",
		"joint-dp-vector-gaussian-one-draw",
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("unverified Phase-1.6 capability was promoted: %s", forbidden)
		}
	}
}

func TestFormalGLMPhase16ReplayRestartAndTamperBinding(t *testing.T) {
	plan, receipts, identities, bridge, capsule :=
		formalGLMPhase16TestContext(t, 3, t.Name())
	first, err := compileFormalGLMPhase16ReleaseAdapter(
		plan, receipts, identities.public, bridge, capsule)
	var blocker *formalGLMPhase16ReleaseBlocker
	if !errors.As(err, &blocker) {
		t.Fatalf("expected mechanism blocker, got %T %v", err, err)
	}
	// Recompilation represents restart/replay: the complete future sticky-noise
	// release binding remains identical while openings stay at zero.
	second, err := compileFormalGLMPhase16ReleaseAdapter(
		plan, receipts, identities.public, bridge, capsule)
	if !errors.As(err, &blocker) {
		t.Fatalf("expected mechanism blocker on replay, got %T %v", err, err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("identical release-instance replay changed the compiled contract")
	}

	changed := capsule
	changed.ReleaseInstanceID = sha256Hex([]byte("phase16/new-release-instance"))
	third, err := compileFormalGLMPhase16ReleaseAdapter(
		plan, receipts, identities.public, bridge, changed)
	if !errors.As(err, &blocker) {
		t.Fatalf("expected mechanism blocker for new instance, got %T %v", err, err)
	}
	if third.Binding.BindingSHA256 == first.Binding.BindingSHA256 ||
		third.Binding.ReleaseInstanceID == first.Binding.ReleaseInstanceID {
		t.Fatal("a different release instance reused the sticky-noise purpose")
	}

	tamperHash := sha256Hex([]byte("phase16-tampered-binding-field"))
	for name, mutate := range map[string]func(*formalGLMPhase16ReleaseBinding){
		"capsule":          func(value *formalGLMPhase16ReleaseBinding) { value.CapsuleID = tamperHash },
		"manifest":         func(value *formalGLMPhase16ReleaseBinding) { value.ManifestSHA256 = tamperHash },
		"schema":           func(value *formalGLMPhase16ReleaseBinding) { value.SchemaManifestSHA256 = tamperHash },
		"workload":         func(value *formalGLMPhase16ReleaseBinding) { value.WorkloadSHA256 = tamperHash },
		"source":           func(value *formalGLMPhase16ReleaseBinding) { value.SourceContextSHA256 = tamperHash },
		"release-instance": func(value *formalGLMPhase16ReleaseBinding) { value.ReleaseInstanceID = tamperHash },
		"release-contract": func(value *formalGLMPhase16ReleaseBinding) { value.ReleaseContractSHA256 = tamperHash },
		"fan-in":           func(value *formalGLMPhase16ReleaseBinding) { value.SourceFanInTranscriptSHA256 = tamperHash },
		"checkpoint":       func(value *formalGLMPhase16ReleaseBinding) { value.FinalCheckpointTranscriptSHA256 = tamperHash },
		"family":           func(value *formalGLMPhase16ReleaseBinding) { value.Family = "poisson" },
		"link":             func(value *formalGLMPhase16ReleaseBinding) { value.LinkTableSHA256 = tamperHash },
		"spec":             func(value *formalGLMPhase16ReleaseBinding) { value.KernelSpecSHA256 = tamperHash },
		"bounds":           func(value *formalGLMPhase16ReleaseBinding) { value.BoundsSHA256 = tamperHash },
		"quantization":     func(value *formalGLMPhase16ReleaseBinding) { value.QuantizationSHA256 = tamperHash },
		"order":            func(value *formalGLMPhase16ReleaseBinding) { value.CoordinateOrderSHA256 = tamperHash },
		"epsilon":          func(value *formalGLMPhase16ReleaseBinding) { value.Epsilon = "2" },
		"delta":            func(value *formalGLMPhase16ReleaseBinding) { value.AllocatedDelta = "0.000002" },
		"sensitivity":      func(value *formalGLMPhase16ReleaseBinding) { value.SensitivitySteps = "1" },
		"sensitivity-proof": func(value *formalGLMPhase16ReleaseBinding) {
			value.SensitivityProof = formalGLMPhase15DPUniversalProof
		},
		"sensitivity-certificate-hash": func(value *formalGLMPhase16ReleaseBinding) {
			value.SensitivityCertificateSHA256 = tamperHash
		},
		"sensitivity-certificate-body": func(value *formalGLMPhase16ReleaseBinding) {
			value.SensitivityCertificate.SelectedBoundSteps = "1"
		},
	} {
		t.Run("tamper-"+name, func(t *testing.T) {
			tampered := first.Binding
			mutate(&tampered)
			if err := validateFormalGLMPhase16ReleaseBinding(
				plan, receipts, identities.public, bridge, capsule, tampered); err == nil {
				t.Fatalf("%s tamper was accepted", name)
			}
		})
	}
	tampered := first.Binding
	tampered.GarblerPeerID, tampered.EvaluatorPeerID =
		tampered.EvaluatorPeerID, tampered.GarblerPeerID
	if err := validateFormalGLMPhase16ReleaseBinding(
		plan, receipts, identities.public, bridge, capsule, tampered); err == nil {
		t.Fatal("role swap was accepted")
	}
	wrongPins := make(map[string]ed25519.PublicKey, len(identities.public))
	for name, pin := range identities.public {
		wrongPins[name] = append(ed25519.PublicKey(nil), pin...)
	}
	wrongPins[plan.Kernel.ComputePeers[0]][0] ^= 1
	if _, err := compileFormalGLMPhase16ReleaseAdapter(
		plan, receipts, wrongPins, bridge, capsule); err == nil {
		t.Fatal("pinset tamper was accepted")
	}
	wrongMechanism := capsule
	wrongMechanism.Mechanism = "discrete-laplace"
	if _, err := compileFormalGLMPhase16ReleaseAdapter(
		plan, receipts, identities.public, bridge, wrongMechanism); err == nil {
		t.Fatal("the Phase-0 Gaussian contract was silently changed to Laplace")
	}
}

func TestFormalGLMPhase16CannotOpenBeforeGaussianBackendAndManifestAdmission(t *testing.T) {
	plan, receipts, identities, bridge, capsule :=
		formalGLMPhase16TestContext(t, 2, t.Name())
	compiled, err := compileFormalGLMPhase16ReleaseAdapter(
		plan, receipts, identities.public, bridge, capsule)
	var compileBlocker *formalGLMPhase16ReleaseBlocker
	if !errors.As(err, &compileBlocker) {
		t.Fatalf("expected compile blocker, got %T %v", err, err)
	}
	err = formalGLMPhase16AuthorizeOpening(compiled)
	var blocker *formalGLMPhase16ReleaseBlocker
	if !errors.As(err, &blocker) ||
		blocker.Code != formalGLMPhase16ManifestBlockerCode ||
		blocker.OpeningsPerformed != 0 || len(blocker.Missing) != 1 {
		t.Fatalf("expected zero-opening manifest blocker, got %T %v", err, err)
	}
}

func TestFormalGLMPhase16UsesProvenRecurrenceWhenUniversalBoxL2ExceedsRing128(t *testing.T) {
	policy := formalGLMPhase15TestPolicy("binomial", 2, 1, 4)
	box := new(big.Int).Lsh(big.NewInt(1), 125)
	policy.CoefficientBox = []string{
		box.String(), box.String(), box.String(), box.String(),
	}
	policy.XKind = []string{"numeric", "numeric", "numeric", "numeric"}
	policy.XLower = []string{"0", "0", "0", "0"}
	policy.XUpper = []string{"0", "0", "0", "0"}
	policy.LinkValues = []string{"128", "128", "128"}
	policy.LinkSlopes = []string{"0", "0"}
	run := sha256.Sum256([]byte("phase16-l2-overflow-plan"))
	plan, err := buildFormalGLMPhase15Plan(policy, 1, 1,
		formalGLMPhase15TestOwners(policy), hexString(run[:]))
	if err != nil {
		t.Fatal(err)
	}
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
	plan.Kernel.PinsetSHA256, err = formalGLMPhase16PinsetSHA256(identities.public)
	if err != nil {
		t.Fatal(err)
	}
	beta := map[string][]*big.Int{}
	for _, peer := range plan.Kernel.ComputePeers {
		beta[peer] = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	}
	transcript, attempt := formalGLMPhase15TestExecutionTranscript(t, plan, t.Name())
	receipts := formalGLMPhase15TestFinalReceipts(
		t, plan, identities, transcript, attempt, beta)
	bridge, err := buildFormalGLMPhase15DPBridgePlan(
		plan, receipts, identities.public, plan.Kernel.FracBits)
	if err != nil {
		t.Fatal(err)
	}
	capsule := formalGLMPhase16TestCapsule(t, plan, identities.public, t.Name())
	compiled, err := compileFormalGLMPhase16ReleaseAdapter(
		plan, receipts, identities.public, bridge, capsule)
	var blocker *formalGLMPhase16ReleaseBlocker
	universal, _ := new(big.Int).SetString(
		bridge.UniversalSensitivity.BoundSteps, 10)
	selected, _ := new(big.Int).SetString(bridge.SelectedSensitivitySteps, 10)
	if !errors.As(err, &blocker) ||
		blocker.Code != formalGLMPhase16ManifestBlockerCode ||
		universal.Cmp(exactGCMaxSigned(128)) <= 0 ||
		selected.Cmp(exactGCMaxSigned(128)) > 0 ||
		bridge.SelectedSensitivityProof != formalGLMPhase15DPTightProof ||
		compiled.Worker == nil || !compiled.Worker.CapabilityAvailable {
		t.Fatalf("proven recurrence was not selected over unusable box L2: universal=%s selected=%s err=%T %v",
			universal, selected, err, err)
	}
}
