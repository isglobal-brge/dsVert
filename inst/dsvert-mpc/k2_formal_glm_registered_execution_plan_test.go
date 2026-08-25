package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const formalGLMRegisteredExecutionTestSchemaJSON = `{"purpose":"formal-glm-registered-execution-test-schema-v1","version":"v1"}`

type formalGLMRegisteredExecutionTestInputs struct {
	plan       formalGLMPhase15Plan
	identities formalGLMPhase15TestIdentities
	context    formalGLMPreSourceDescriptorTestContext
	entry      formalGLMArtifactRegistryEntryV1
	resolution formalGLMArtifactRegistryResolutionV1
	artifact   formalGLMPhase21StickyArtifact
	dp         formalGLMCanonicalPreSourceDPV1
	contract   formalGLMPhase21SamplerV2Contract
	bound      formalGLMPhase19TranscriptBoundV1
}

func formalGLMRegisteredExecutionTestPlan(t testing.TB, family string,
	custodians, total, iterations int,
) (formalGLMPhase15Plan, formalGLMPhase15TestIdentities) {
	t.Helper()
	plan, identities := formalGLMPreSourceDescriptorTestPlan(
		t, family, custodians)
	if total == plan.TotalCapacity && iterations == plan.Iterations {
		return plan, identities
	}
	runID := sha256.Sum256([]byte(fmt.Sprintf(
		"registered-execution/%s/%d/%d/%d", t.Name(), custodians, total,
		iterations)))
	var err error
	plan, err = buildFormalGLMPhase15Plan(plan.Kernel, total, iterations,
		formalGLMPhase15TestOwners(plan.Kernel), hexString(runID[:]))
	if err != nil {
		t.Fatal(err)
	}
	return plan, identities
}

func formalGLMRegisteredExecutionTestInputsForPlan(t testing.TB,
	plan formalGLMPhase15Plan, identities formalGLMPhase15TestIdentities,
	mutateModel func(*formalGLMPreSourceModelCoreV1),
	mutateReceipt func(int, *formalGLMPSISourceBridgeCoreV1),
) formalGLMRegisteredExecutionTestInputs {
	t.Helper()
	context := formalGLMPreSourceDescriptorTestBuild(
		t, plan, identities, formalGLMRegisteredExecutionTestSchemaJSON,
		mutateModel, mutateReceipt)
	entry := formalGLMPreSourceDescriptorTestEntry(t, context)
	resolution := formalGLMArtifactRegistryResolutionV1{
		ArtifactID: entry.ArtifactID, Descriptor: entry.Descriptor,
	}
	artifact := context.draft.Artifact
	dp := context.model.Model.CanonicalDP
	bound, err := formalGLMPhase19BuildTranscriptBoundV1(plan, dp)
	if err != nil {
		t.Fatal(err)
	}
	roots := make(map[string][32]byte, 2)
	for _, authority := range artifact.NoiseAuthorities {
		roots[authority.PeerName] = sha256.Sum256([]byte(
			"registered-execution/authority-root/" + authority.PeerName))
	}
	contract := formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, entry.ArtifactID, formalGLMPhase21SamplerV2OneDraw,
		identities.public, identities.private, roots)
	return formalGLMRegisteredExecutionTestInputs{
		plan: plan, identities: identities, context: context, entry: entry,
		resolution: resolution, artifact: artifact, dp: dp,
		contract: contract, bound: bound,
	}
}

func formalGLMRegisteredExecutionTestInputsV1(t testing.TB, family string,
	custodians, total, iterations int,
) formalGLMRegisteredExecutionTestInputs {
	t.Helper()
	plan, identities := formalGLMRegisteredExecutionTestPlan(
		t, family, custodians, total, iterations)
	return formalGLMRegisteredExecutionTestInputsForPlan(
		t, plan, identities, nil, nil)
}

func formalGLMRegisteredExecutionTestBuild(t testing.TB,
	inputs formalGLMRegisteredExecutionTestInputs,
) formalGLMRegisteredExecutionPlanV1 {
	t.Helper()
	value, err := formalGLMBuildRegisteredExecutionPlanFromEntryV1(
		inputs.plan, inputs.entry, inputs.artifact, inputs.dp,
		inputs.contract, inputs.bound, inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidateRegisteredExecutionPlanAgainstInputsV1(
		value, inputs.plan, inputs.resolution, inputs.artifact, inputs.dp,
		inputs.contract, inputs.bound, inputs.identities.public); err != nil {
		t.Fatal(err)
	}
	return value
}

func formalGLMRegisteredExecutionTestAssertLegacyEquivalence(t testing.TB,
	value formalGLMRegisteredExecutionPlanV1, legacy formalGLMPhase15Plan,
) {
	t.Helper()
	kernel := value.ExecutionKernel
	wantKernel := legacy.Kernel
	if value.Family != wantKernel.Family ||
		value.TotalCapacity != legacy.TotalCapacity ||
		value.BlockCapacity != legacy.BlockCapacity ||
		value.TotalBlocks != legacy.TotalBlocks ||
		value.Iterations != legacy.Iterations ||
		value.ScheduleSteps != legacy.ScheduleSteps ||
		!reflect.DeepEqual(value.CoordinateOwners, legacy.CoordinateOwners) ||
		value.RingBits != legacy.RingBits ||
		value.ContainerBits != legacy.ContainerBits ||
		value.MaximumMagnitude != legacy.MaximumMagnitude ||
		value.RhoTotalUpper != legacy.RhoTotalUpper ||
		value.BackendSelection != legacy.BackendSelection ||
		value.TranscriptShape != legacy.TranscriptShape ||
		value.CrashRecovery != legacy.CrashRecovery ||
		value.Output != legacy.Output || value.ProductionReady ||
		kernel.Version != wantKernel.Version ||
		kernel.CompilerSHA256 != wantKernel.CompilerSHA256 ||
		kernel.TheoremSHA256 != wantKernel.TheoremSHA256 ||
		kernel.Adjacency != wantKernel.Adjacency ||
		kernel.Capacity != wantKernel.Capacity ||
		kernel.CoefficientCount != wantKernel.CoefficientCount ||
		kernel.Iterations != wantKernel.Iterations ||
		kernel.FractionBits != wantKernel.FracBits ||
		!reflect.DeepEqual(kernel.XKind, wantKernel.XKind) ||
		!reflect.DeepEqual(kernel.XLower, wantKernel.XLower) ||
		!reflect.DeepEqual(kernel.XUpper, wantKernel.XUpper) ||
		kernel.WeightUpper != wantKernel.WeightUpper ||
		kernel.OutcomeUpper != wantKernel.OutcomeUpper ||
		kernel.OffsetLower != wantKernel.OffsetLower ||
		kernel.OffsetUpper != wantKernel.OffsetUpper ||
		!reflect.DeepEqual(kernel.BetaStart, wantKernel.BetaStart) ||
		!reflect.DeepEqual(kernel.Ridge, wantKernel.Ridge) ||
		!reflect.DeepEqual(kernel.CoefficientBox, wantKernel.CoefficientBox) ||
		kernel.Alpha != wantKernel.Alpha ||
		!reflect.DeepEqual(kernel.LinkKnots, wantKernel.LinkKnots) ||
		!reflect.DeepEqual(kernel.LinkValues, wantKernel.LinkValues) ||
		!reflect.DeepEqual(kernel.LinkSlopes, wantKernel.LinkSlopes) ||
		kernel.LinkErrorUpper != wantKernel.LinkErrorUpper ||
		kernel.LinkTableSHA256 != wantKernel.LinkTableSHA256 ||
		kernel.Missingness != wantKernel.Missingness ||
		kernel.PatientCollapse != wantKernel.PatientCollapse ||
		kernel.ReductionOrder != wantKernel.ReductionOrder ||
		kernel.Truncation != wantKernel.Truncation ||
		kernel.InputLayout != wantKernel.InputLayout ||
		kernel.InputSharing != wantKernel.InputSharing ||
		kernel.Output != wantKernel.Output ||
		value.BlockCost != formalGLMRegisteredExecutionCostFromPhase15V1(
			legacy.BlockCost) ||
		value.FinalizeCost != formalGLMRegisteredExecutionCostFromPhase15V1(
			legacy.FinalizeCost) {
		t.Fatal("registered execution projection changed legacy numeric/circuit geometry")
	}
}

func formalGLMRegisteredExecutionTestForbiddenJSONKey(t testing.TB,
	value any,
) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"run_id", "capsule", "artifact_sha256", "analysis", "request",
		"lifetime", "ttl", "path", "approval", "signature",
	}
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				lower := strings.ToLower(key)
				for _, fragment := range forbidden {
					if strings.Contains(lower, fragment) {
						t.Errorf("forbidden recursive field %q", key)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(decoded)
}

func TestFormalGLMRegisteredExecutionPlanK2K3K5SupportedFamilies(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		seen := make(map[string]bool)
		for _, custodians := range []int{2, 3, 5} {
			t.Run(fmt.Sprintf("%s/K%d", family, custodians), func(t *testing.T) {
				inputs := formalGLMRegisteredExecutionTestInputsV1(
					t, family, custodians, 2, 1)
				value := formalGLMRegisteredExecutionTestBuild(t, inputs)
				formalGLMRegisteredExecutionTestAssertLegacyEquivalence(
					t, value, inputs.plan)
				if value.CustodianCount != custodians ||
					len(value.CustodianPeers) != custodians ||
					value.ArtifactID != inputs.entry.ArtifactID ||
					value.DescriptorCoreSHA256 !=
						inputs.entry.DescriptorCoreSHA256 ||
					value.CanonicalPreSourceDPSHA256 !=
						inputs.context.model.Model.CanonicalDPSHA256 ||
					value.TranscriptBoundSHA256 != inputs.bound.ShapeSHA256 ||
					value.WireABISHA256 != inputs.bound.WireABISHA256 ||
					!formalGLMIsSHA256(value.PlanSHA256) {
					t.Fatalf("incomplete registered execution binding: %+v", value)
				}
				calculated, err := formalGLMRegisteredExecutionPlanSHA256V1(value)
				if err != nil || calculated != value.PlanSHA256 {
					t.Fatalf("plan hash is not recalculable: %q %v", calculated, err)
				}
				if seen[value.PlanSHA256] {
					t.Fatal("K change did not distinguish registered plan")
				}
				seen[value.PlanSHA256] = true
				formalGLMRegisteredExecutionTestForbiddenJSONKey(t, value)
			})
		}
	}
}

func TestFormalGLMRegisteredExecutionPlanIgnoresLegacyRunAndCapsule(t *testing.T) {
	inputs := formalGLMRegisteredExecutionTestInputsV1(
		t, "binomial", 3, 2, 1)
	want := formalGLMRegisteredExecutionTestBuild(t, inputs)

	changed := inputs.plan
	changed.RunID = sha256Hex([]byte("another operational run"))
	got, err := formalGLMBuildRegisteredExecutionPlanV1(
		changed, inputs.resolution, inputs.artifact, inputs.dp,
		inputs.contract, inputs.bound, inputs.identities.public)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("RunID split registered plan: equal=%v err=%v",
			reflect.DeepEqual(got, want), err)
	}

	changed = inputs.plan
	changed.Kernel.CapsuleSHA256 = sha256Hex([]byte("another legacy capsule"))
	got, err = formalGLMBuildRegisteredExecutionPlanV1(
		changed, inputs.resolution, inputs.artifact, inputs.dp,
		inputs.contract, inputs.bound, inputs.identities.public)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy capsule split registered plan: equal=%v err=%v",
			reflect.DeepEqual(got, want), err)
	}

	changed = inputs.plan
	changed.Kernel.ArtifactSHA256 = sha256Hex([]byte("another legacy artifact"))
	got, err = formalGLMBuildRegisteredExecutionPlanV1(
		changed, inputs.resolution, inputs.artifact, inputs.dp,
		inputs.contract, inputs.bound, inputs.identities.public)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy artifact identity split registered plan: equal=%v err=%v",
			reflect.DeepEqual(got, want), err)
	}
}

func TestFormalGLMRegisteredExecutionPlanBindsUnsignedSamplerCore(t *testing.T) {
	inputs := formalGLMRegisteredExecutionTestInputsV1(
		t, "binomial", 3, 2, 1)
	want := formalGLMRegisteredExecutionTestBuild(t, inputs)
	unsigned := inputs.contract
	unsigned.CustodianSignatures = nil
	got, err := formalGLMBuildRegisteredExecutionPlanV1(
		inputs.plan, inputs.resolution, inputs.artifact, inputs.dp,
		unsigned, inputs.bound, inputs.identities.public)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("sampler signatures split registered plan: equal=%v err=%v",
			reflect.DeepEqual(got, want), err)
	}

	tampered := inputs.contract
	tampered.CustodianSignatures = append(
		[]jointDPBiomedicalGaussianSignature(nil),
		inputs.contract.CustodianSignatures...)
	tampered.CustodianSignatures[0].Signature = append(
		[]byte(nil), tampered.CustodianSignatures[0].Signature...)
	tampered.CustodianSignatures[0].Signature[0] ^= 1
	if _, err := formalGLMBuildRegisteredExecutionPlanV1(
		inputs.plan, inputs.resolution, inputs.artifact, inputs.dp,
		tampered, inputs.bound, inputs.identities.public); err == nil {
		t.Fatal("tampered sampler signature was accepted")
	}
}

func TestFormalGLMRegisteredExecutionPlanDistinguishesSelectedInputs(t *testing.T) {
	baseInputs := formalGLMRegisteredExecutionTestInputsV1(
		t, "binomial", 3, 2, 1)
	base := formalGLMRegisteredExecutionTestBuild(t, baseInputs)

	datasetInputs := formalGLMRegisteredExecutionTestInputsForPlan(
		t, baseInputs.plan, baseInputs.identities, nil,
		func(index int, core *formalGLMPSISourceBridgeCoreV1) {
			if index == 0 {
				core.DatasetVersion = "v2"
			}
		})
	dataset := formalGLMRegisteredExecutionTestBuild(t, datasetInputs)
	if dataset.PlanSHA256 == base.PlanSHA256 {
		t.Fatal("selected dataset change did not distinguish registered plan")
	}

	boundKernel := baseInputs.plan.Kernel
	boundKernel.CoefficientBox = append([]string(nil),
		boundKernel.CoefficientBox...)
	boundKernel.CoefficientBox[1] = "384"
	boundPlan, err := buildFormalGLMPhase15Plan(
		boundKernel, baseInputs.plan.TotalCapacity, baseInputs.plan.Iterations,
		formalGLMPhase15TestOwners(boundKernel), baseInputs.plan.RunID)
	if err != nil {
		t.Fatal(err)
	}
	boundInputs := formalGLMRegisteredExecutionTestInputsForPlan(
		t, boundPlan, baseInputs.identities, nil, nil)
	selectedBounds := formalGLMRegisteredExecutionTestBuild(t, boundInputs)
	if selectedBounds.PlanSHA256 == base.PlanSHA256 {
		t.Fatal("selected bounds change did not distinguish registered plan")
	}

	geometryPlan, err := buildFormalGLMPhase15Plan(
		baseInputs.plan.Kernel, 3, baseInputs.plan.Iterations,
		formalGLMPhase15TestOwners(baseInputs.plan.Kernel), baseInputs.plan.RunID)
	if err != nil {
		t.Fatal(err)
	}
	geometryInputs := formalGLMRegisteredExecutionTestInputsForPlan(
		t, geometryPlan, baseInputs.identities, nil, nil)
	geometry := formalGLMRegisteredExecutionTestBuild(t, geometryInputs)
	if geometry.PlanSHA256 == base.PlanSHA256 {
		t.Fatal("physical plan geometry did not distinguish registered plan")
	}

	iterationPlan, err := buildFormalGLMPhase15Plan(
		baseInputs.plan.Kernel, baseInputs.plan.TotalCapacity, 2,
		formalGLMPhase15TestOwners(baseInputs.plan.Kernel), baseInputs.plan.RunID)
	if err != nil {
		t.Fatal(err)
	}
	iterationInputs := formalGLMRegisteredExecutionTestInputsForPlan(
		t, iterationPlan, baseInputs.identities, nil, nil)
	iteration := formalGLMRegisteredExecutionTestBuild(t, iterationInputs)
	if iteration.PlanSHA256 == base.PlanSHA256 {
		t.Fatal("iteration schedule did not distinguish registered plan")
	}

	latticeDP, err := formalGLMPhase19CanonicalPreSourceDPForLatticeV1(
		baseInputs.plan, baseInputs.plan.Kernel.FracBits-1)
	if err != nil {
		t.Fatal(err)
	}
	latticeSHA256, err := formalGLMCanonicalPreSourceDPSHA256V1(latticeDP)
	if err != nil {
		t.Fatal(err)
	}
	latticeInputs := formalGLMRegisteredExecutionTestInputsForPlan(
		t, baseInputs.plan, baseInputs.identities,
		func(core *formalGLMPreSourceModelCoreV1) {
			core.CanonicalDP = latticeDP
			core.CanonicalDPSHA256 = latticeSHA256
		}, nil)
	lattice := formalGLMRegisteredExecutionTestBuild(t, latticeInputs)
	if lattice.PlanSHA256 == base.PlanSHA256 {
		t.Fatal("output lattice did not distinguish registered plan")
	}

	wrongABI := baseInputs.bound
	wrongABI.WireABISHA256 = sha256Hex([]byte("another exact-GC ABI"))
	wrongABI.ShapeSHA256, err = formalGLMPhase19TranscriptShapeSHA256V1(wrongABI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMBuildRegisteredExecutionPlanV1(
		baseInputs.plan, baseInputs.resolution, baseInputs.artifact,
		baseInputs.dp, baseInputs.contract, wrongABI,
		baseInputs.identities.public); err == nil {
		t.Fatal("changed wire ABI was accepted")
	}
}

func TestFormalGLMRegisteredExecutionPlanStrictDecodeAndTamper(t *testing.T) {
	inputs := formalGLMRegisteredExecutionTestInputsV1(
		t, "binomial", 3, 2, 1)
	value := formalGLMRegisteredExecutionTestBuild(t, inputs)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := formalGLMDecodeRegisteredExecutionPlanV1(
		encoded, inputs.identities.public)
	if err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatalf("canonical decode failed: equal=%v err=%v",
			reflect.DeepEqual(decoded, value), err)
	}

	tampered := value
	tampered.RhoTotalUpper = "1"
	tampered.PlanSHA256, err = formalGLMRegisteredExecutionPlanSHA256V1(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidateRegisteredExecutionPlanV1(
		tampered, inputs.identities.public); err == nil {
		t.Fatal("numeric tamper with a recalculated hash was accepted")
	}

	tampered = value
	tampered.NoiseAuthorities = append(
		[]formalGLMRegisteredExecutionAuthorityV1(nil),
		value.NoiseAuthorities...)
	tampered.NoiseAuthorities[0].PeerID =
		"dsv1_" + sha256Hex([]byte("another registered authority"))
	tampered.PlanSHA256, err = formalGLMRegisteredExecutionPlanSHA256V1(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidateRegisteredExecutionPlanV1(
		tampered, inputs.identities.public); err == nil {
		t.Fatal("authority tamper with a recalculated hash was accepted")
	}

	extra := append([]byte(`{"unexpected":true,`), encoded[1:]...)
	if _, err := formalGLMDecodeRegisteredExecutionPlanV1(
		extra, inputs.identities.public); err == nil {
		t.Fatal("extra JSON field was accepted")
	}

	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	delete(generic, "canonical_dp")
	missing, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMDecodeRegisteredExecutionPlanV1(
		missing, inputs.identities.public); err == nil {
		t.Fatal("missing JSON field was accepted")
	}

	reordered := value
	reordered.TranscriptBound.CircuitInventory = append(
		[]formalGLMPhase19TranscriptCircuitV1(nil),
		reordered.TranscriptBound.CircuitInventory...)
	if len(reordered.TranscriptBound.CircuitInventory) < 2 {
		t.Fatal("test requires multiple transcript circuits")
	}
	reordered.TranscriptBound.CircuitInventory[0],
		reordered.TranscriptBound.CircuitInventory[1] =
		reordered.TranscriptBound.CircuitInventory[1],
		reordered.TranscriptBound.CircuitInventory[0]
	reordered.TranscriptBound.ShapeSHA256, err =
		formalGLMPhase19TranscriptShapeSHA256V1(reordered.TranscriptBound)
	if err != nil {
		t.Fatal(err)
	}
	reordered.TranscriptBoundSHA256 = reordered.TranscriptBound.ShapeSHA256
	reordered.PlanSHA256, err = formalGLMRegisteredExecutionPlanSHA256V1(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if err := formalGLMValidateRegisteredExecutionPlanV1(
		reordered, inputs.identities.public); err == nil {
		t.Fatal("reordered transcript inventory was accepted")
	}
}
