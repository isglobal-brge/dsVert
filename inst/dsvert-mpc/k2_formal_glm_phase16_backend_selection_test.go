package main

import (
	"crypto/ed25519"
	"math/big"
	"reflect"
	"testing"
)

func formalGLMPhase16TestSignBackendSelection(t testing.TB,
	contract formalGLMPhase16BackendSelectionContract,
	private map[string]ed25519.PrivateKey,
) []jointDPBiomedicalGaussianSignature {
	t.Helper()
	result := make([]jointDPBiomedicalGaussianSignature, 0,
		len(contract.CustodianPeers))
	for _, peer := range contract.CustodianPeers {
		signature, err := formalGLMPhase16SignBackendSelection(
			contract, peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, signature)
	}
	return result
}

func TestFormalGLMPhase16BackendSelectionIsExplicitSignedAndDeterministic(t *testing.T) {
	for _, custodians := range []int{2, 3, 4, 5} {
		for _, family := range []string{"binomial", "poisson"} {
			t.Run(family+"-K"+string(rune('0'+custodians)), func(t *testing.T) {
				fixture, runtime := formalGLMPhase16TestDurableRuntime(
					t, custodians, family)
				admission, _, _, err := formalGLMPhase16TestProductiveAdmission(
					t, fixture, runtime)
				if err != nil {
					t.Fatal(err)
				}
				binding := admission.Compiled.Binding
				// Exercise the requested common epsilon=1 policy for both
				// families.  The existing productive fixture used epsilon=10
				// for Poisson solely to keep its older one-draw-only test small.
				binding.Epsilon = "1"
				binding.BindingSHA256, err =
					formalGLMPhase16ReleaseBindingDigest(binding)
				if err != nil {
					t.Fatal(err)
				}
				contract, plans, err := formalGLMPhase16BuildBackendSelection(
					binding, admission.Token, fixture.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("selected=%s sensitivity=%s one_draw=%v reason=%s magnitude_count=%d full95=%s",
					contract.SelectedBackend, binding.SensitivitySteps,
					contract.OneDrawCapabilityAvailable,
					contract.OneDrawUnavailableReason,
					plans.OneDraw.SamplerMagnitudeCount,
					plans.Full.Simultaneous95Abs)
				attestation := formalGLMPhase16BackendSelectionAttestation{
					Contract: contract,
					Signatures: formalGLMPhase16TestSignBackendSelection(
						t, contract, fixture.identities.private),
				}
				validated, err := formalGLMPhase16ValidateBackendSelection(
					attestation, binding, admission.Token,
					fixture.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				if contract.OperationLimit || contract.RequestLimit ||
					contract.HistoryCanDenyOperation ||
					!contract.SelectionAutomatic ||
					!contract.SelectionExplicitAndCrossSigned ||
					contract.RelayAvailabilityGuaranteed ||
					contract.MaliciousSecurityClaim ||
					contract.BothNoisePeersCollusionProtected ||
					!contract.AtLeastOneHonestNoisePeer ||
					contract.MaximumColludingNoisePeers != 1 ||
					contract.SelectedSimultaneous95Abs == "" ||
					contract.SelectedPrivacyTheorem == "" ||
					contract.SelectedUtilityCertificate == "" ||
					contract.SelectedThreatModel == "" ||
					contract.SelectedObservableWorkerShape == "" ||
					contract.SelectedHostConstantTimeClaim ||
					!contract.SelectedTranscriptDPClaim ||
					!contract.SelectedLogicalTranscriptFixed ||
					contract.SelectedPhysicalTimingDPClaim {
					t.Fatalf("incomplete backend decision: %#v", contract)
				}
				if contract.OneDrawCapabilityAvailable {
					if contract.SelectedBackend != formalGLMPhase16BackendOneDraw ||
						contract.SelectedVarianceMultiplier != 1 {
						t.Fatalf("available one-draw route was not preferred: %#v", contract)
					}
				} else if contract.SelectedBackend != formalGLMPhase16BackendFull ||
					contract.SelectedVarianceMultiplier != 2 ||
					!contract.FullCapabilityAvailable {
					t.Fatalf("resource fallback was not explicit: %#v", contract)
				}
				if !reflect.DeepEqual(plans, validated) {
					t.Fatal("validation changed a signed public backend plan")
				}
				cost, err := formalGLMPhase16BuildProductiveCost(
					fixture.plan, binding, admission.Token, attestation,
					fixture.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				if cost.ExecutionKernel != formalGLMPhase16CurrentKernel ||
					cost.FixedScheduleSteps != fixture.plan.ScheduleSteps ||
					cost.BlockCircuitEvaluations !=
						fixture.plan.Iterations*fixture.plan.TotalBlocks ||
					cost.EndToEndDSIBenchmarked || cost.ProductionReady ||
					!cost.LogicalTranscriptFixedShape ||
					cost.PhysicalTimingDPCertified || cost.Blocker == "" {
					t.Fatalf("incomplete productive cost certificate: %#v", cost)
				}
				if contract.SelectedBackend == formalGLMPhase16BackendFull &&
					(cost.RangeGuardCircuitCount < 1 ||
						cost.RangeGuardGates < 1 ||
						cost.RangeGuardNonXORGates < 1) {
					t.Fatalf("full fallback omitted exact range-guard cost: %#v", cost)
				}
				changed := attestation
				changed.Contract.SelectedVarianceMultiplier++
				if _, err := formalGLMPhase16ValidateBackendSelection(
					changed, binding, admission.Token,
					fixture.identities.public); err == nil {
					t.Fatal("relay-modified variance certificate retained K authority")
				}
			})
		}
	}
}

func BenchmarkFormalGLMPhase16FullRangeGuardCircuitP8(b *testing.B) {
	spec := exactGCCircuitSpec{
		Operation: exactGCCountGuard, RingBits: 128, FracBits: 0,
		Threshold: big.NewInt(1), VectorLen: 16,
	}
	circ, err := exactGCCompileCircuit(spec)
	if err != nil {
		b.Fatal(err)
	}
	garbler := make([]*big.Int, 17)
	evaluator := make([]*big.Int, 16)
	for index := range garbler {
		garbler[index] = new(big.Int)
	}
	for index := range evaluator {
		evaluator[index] = new(big.Int)
	}
	g := exactGCPackChunks(garbler, 128)
	e := exactGCPackChunks(evaluator, 128)
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := circ.Compute([]*big.Int{g, e}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(circ.NumGates), "gates/circuit")
	b.ReportMetric(float64(circ.Stats.NumNonXOR()), "non-xor-gates/circuit")
}
