package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

type formalGLMCountingConn struct {
	net.Conn
	writeCalls int64
	writeBytes int64
}

func (c *formalGLMCountingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.writeCalls++
	c.writeBytes += int64(n)
	return n, err
}

func formalGLMTestPolicy(family string, custodians int) formalGLMPhase1Policy {
	peers := []string{"peer-a", "peer-b"}
	if custodians >= 3 {
		peers = append(peers, "peer-c")
	}
	values, slopes, outcome := []string{"16", "128", "240"},
		[]string{"28", "28"}, "256"
	if family == "poisson" {
		values, slopes, outcome = []string{"32", "256", "480"},
			[]string{"56", "56"}, "2048"
	}
	hash := func(value byte) string { return strings.Repeat(string(value), 64) }
	return formalGLMPhase1Policy{
		Version:        formalGLMPhase1PolicyVersion,
		ArtifactSHA256: hash('1'), CapsuleSHA256: hash('2'),
		CanonicalScienceSHA256: hash('8'),
		SnapshotSHA256:         hash('3'), PinsetSHA256: hash('4'),
		CompilerSHA256: hash('5'), TheoremSHA256: hash('6'),
		LinkTableSHA256: hash('7'), LinkErrorUpper: "8",
		CustodianPeers: peers, ComputePeers: []string{"peer-a", "peer-b"},
		Family: family, Adjacency: "add_remove",
		Capacity: 1, CoefficientCount: 1,
		Iterations: 1, FracBits: 8,
		XKind: []string{"intercept"}, XLower: []string{"256"},
		XUpper: []string{"256"}, WeightUpper: "256",
		OutcomeUpper: outcome, OffsetLower: "-512", OffsetUpper: "512",
		BetaStart: []string{"0"}, Ridge: []string{"128"},
		CoefficientBox: []string{"512"}, Alpha: "64",
		LinkKnots:  []string{"-1024", "0", "1024"},
		LinkValues: values, LinkSlopes: slopes,
		Missingness:     "complete_tuple_zero_weight",
		PatientCollapse: "one_aligned_record_duplicates_zero_weight_v1",
		ReductionOrder:  "capacity_slot_then_coefficient_v1",
		Truncation:      "signed_floor_after_each_multiply_v1",
		InputLayout:     "capacity_major_weight_design_outcome_offset_v1",
		InputSharing:    "additive_mod_2k_two_recipient_v1",
		Output:          "sealed_coefficient_additive_shares_only_v1",
	}
}

func formalGLMTestSession(t testing.TB, policy formalGLMPhase1Policy) exactGCSession {
	t.Helper()
	plan, err := planFormalGLMPhase1(policy)
	if err != nil {
		t.Fatal(err)
	}
	purpose, err := formalGLMPurpose(policy)
	if err != nil {
		t.Fatal(err)
	}
	return exactGCSession{
		SessionID: sha256.Sum256([]byte("formal-glm/session/test")),
		MasterKey: sha256.Sum256([]byte("formal-glm/master/test")),
		GarblerID: policy.ComputePeers[0], EvaluatorID: policy.ComputePeers[1],
		Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalGLMOneIteration,
			RingBits:  plan.RingBits, FracBits: policy.FracBits,
			VectorLen: plan.InputCoordinates,
		},
	}
}

func formalGLMTestInput(policy formalGLMPhase1Policy, outcome int64) []*big.Int {
	// One row: weight, x, outcome, offset, all in the common 2^8 lattice.
	return []*big.Int{big.NewInt(256), big.NewInt(256), big.NewInt(outcome), big.NewInt(0)}
}

func formalGLMTestExpandedPolicy(family string, capacity, coefficients int) formalGLMPhase1Policy {
	policy := formalGLMTestPolicy(family, 3)
	policy.Capacity = capacity
	policy.CoefficientCount = coefficients
	policy.XKind = make([]string, coefficients)
	policy.XLower = make([]string, coefficients)
	policy.XUpper = make([]string, coefficients)
	policy.BetaStart = make([]string, coefficients)
	policy.Ridge = make([]string, coefficients)
	policy.CoefficientBox = make([]string, coefficients)
	for j := 0; j < coefficients; j++ {
		policy.XKind[j] = "numeric"
		policy.XLower[j], policy.XUpper[j] = "-256", "256"
		if j == 0 {
			policy.XKind[j] = "intercept"
			policy.XLower[j], policy.XUpper[j] = "256", "256"
		}
		if j == 1 {
			policy.XKind[j] = "categorical_indicator"
			policy.XLower[j], policy.XUpper[j] = "0", "256"
		}
		policy.BetaStart[j] = "0"
		policy.Ridge[j] = "128"
		policy.CoefficientBox[j] = "512"
	}
	if coefficients > 1 {
		policy.LinkKnots = []string{"-2048", "0", "2048"}
		if family == "binomial" {
			policy.LinkSlopes = []string{"14", "14"}
		} else {
			policy.LinkSlopes = []string{"28", "28"}
		}
	}
	return policy
}

func formalGLMTestExpandedInput(policy formalGLMPhase1Policy, ringBits int) []*big.Int {
	p, c := policy.CoefficientCount, policy.Capacity
	result := make([]*big.Int, 0, c*(p+3))
	for row := 0; row < c; row++ {
		weight := big.NewInt(256)
		if row == c-1 && c > 2 {
			weight.SetInt64(0)
		}
		result = append(result, weight)
		for j := 0; j < p; j++ {
			value := big.NewInt(256)
			if j == 1 && row%2 == 0 {
				value.SetInt64(0)
			}
			if j > 1 && row%2 == 0 {
				value.SetInt64(-128)
			}
			result = append(result, formalGLMResidue(value, ringBits))
		}
		outcome := int64((row % 2) * 256)
		if policy.Family == "poisson" {
			outcome = int64((row % 3) * 256)
		}
		result = append(result, big.NewInt(outcome))
		offset := big.NewInt(int64((row%3 - 1) * 64))
		result = append(result, formalGLMResidue(offset, ringBits))
	}
	return result
}

func TestFormalGLMPhase1PlanBindsK2AndK3FixedShape(t *testing.T) {
	for _, k := range []int{2, 3} {
		policy := formalGLMTestPolicy("binomial", k)
		plan, err := planFormalGLMPhase1(policy)
		if err != nil {
			t.Fatal(err)
		}
		if plan.RingBits != 128 || plan.ContainerBits != 128 ||
			plan.InputCoordinates != 4 || plan.OutputCoordinates != 1 ||
			plan.ProductionReleaseReady ||
			plan.Phase2OpeningStatus != "sealed_shares_only_no_opening" {
			t.Fatalf("unexpected plan: %+v", plan)
		}
		purpose, err := formalGLMPurpose(policy)
		if err != nil || !strings.HasPrefix(purpose, "formal-glm/phase1-v1/") {
			t.Fatalf("invalid purpose: %q %v", purpose, err)
		}
		second, err := planFormalGLMPhase1(policy)
		if err != nil || second != plan {
			t.Fatal("formal GLM plan is not deterministic")
		}
	}
}

func TestFormalGLMPhase1PlannerSelectsDynamicRingAndFailsTyped(t *testing.T) {
	policy := formalGLMTestPolicy("binomial", 2)
	large := new(big.Int).Lsh(big.NewInt(1), 150).String()
	policy.CoefficientBox = []string{large}
	policy.XKind = []string{"numeric"}
	policy.XLower, policy.XUpper = []string{"0"}, []string{"0"}
	policy.LinkKnots = []string{"-512", "0", "512"}
	policy.LinkValues = []string{"128", "128", "128"}
	policy.LinkSlopes = []string{"0", "0"}
	plan, err := planFormalGLMPhase1(policy)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RingBits <= 128 || plan.RingBits > exactGCMaxRingBits {
		t.Fatalf("dynamic ring was not selected: %+v", plan)
	}

	policy = formalGLMTestPolicy("poisson", 2)
	huge := "1" + strings.Repeat("0", 1199)
	policy.WeightUpper, policy.OutcomeUpper = huge, huge
	policy.LinkValues = []string{huge, huge, huge}
	policy.LinkSlopes = []string{"0", "0"}
	_, err = planFormalGLMPhase1(policy)
	var typed *formalGLMNumericBackendError
	if !errors.As(err, &typed) || typed.Code != "numeric_backend_unrepresentable" ||
		typed.RequiredBits <= exactGCMaxRingBits {
		t.Fatalf("expected typed Ring4096 failure, got %T %v", err, err)
	}
}

func TestFormalGLMPhase1PlannerFailsTypedBeforeOversizedCircuit(t *testing.T) {
	policy := formalGLMTestExpandedPolicy("binomial", 8, 4)
	large := new(big.Int).Lsh(big.NewInt(1), 3000).String()
	for i := range policy.CoefficientBox {
		policy.CoefficientBox[i] = large
		policy.XKind[i] = "numeric"
		policy.XLower[i], policy.XUpper[i] = "0", "0"
	}
	_, err := planFormalGLMPhase1(policy)
	var typed *formalGLMResourcePlanError
	if !errors.As(err, &typed) || typed.Code != "public_circuit_shape_unrepresentable" ||
		typed.TypedInputBits <= typed.MaximumInputBits {
		t.Fatalf("expected typed public shape rejection, got %T %v", err, err)
	}
}

func TestFormalGLMPhase1PlannerAcceptsAsymmetricCoveredEtaDomain(t *testing.T) {
	policy := formalGLMTestPolicy("binomial", 2)
	policy.XKind = []string{"numeric"}
	policy.XLower, policy.XUpper = []string{"0"}, []string{"0"}
	policy.OffsetLower, policy.OffsetUpper = "0", "512"
	policy.LinkKnots = []string{"0", "512", "1024"}
	policy.LinkValues = []string{"16", "128", "240"}
	policy.LinkSlopes = []string{"56", "56"}
	if _, err := planFormalGLMPhase1(policy); err != nil {
		t.Fatalf("covered asymmetric eta interval was rejected: %v", err)
	}
	policy.OffsetLower = "-1"
	if _, err := planFormalGLMPhase1(policy); err == nil ||
		!strings.Contains(err.Error(), "link domain") {
		t.Fatalf("uncovered eta interval was accepted: %v", err)
	}
}

func TestFormalGLMPhase1PolicyRejectsUncertifiedScientificContracts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*formalGLMPhase1Policy)
	}{
		{name: "fractional Poisson cap", mutate: func(policy *formalGLMPhase1Policy) {
			policy.OutcomeUpper = "257"
		}},
		{name: "invalid intercept", mutate: func(policy *formalGLMPhase1Policy) {
			policy.XLower[0] = "0"
		}},
		{name: "discontinuous link", mutate: func(policy *formalGLMPhase1Policy) {
			policy.LinkSlopes[0] = "27"
		}},
		{name: "adaptive iteration count", mutate: func(policy *formalGLMPhase1Policy) {
			policy.Iterations = 2
		}},
		{name: "non-contractive step", mutate: func(policy *formalGLMPhase1Policy) {
			policy.Alpha = "4096"
		}},
		{name: "unknown layout", mutate: func(policy *formalGLMPhase1Policy) {
			policy.InputLayout = "analyst_selected_sparse_rows"
		}},
		{name: "unknown sharing", mutate: func(policy *formalGLMPhase1Policy) {
			policy.InputSharing = "relay_reconstructs_then_reshares"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := formalGLMTestPolicy("poisson", 3)
			test.mutate(&policy)
			if _, err := parseFormalGLMPhase1Policy(policy); err == nil {
				t.Fatal("uncertified policy was accepted")
			}
		})
	}
}

func TestFormalGLMPhase1ReferenceBinomialPoissonAndRho(t *testing.T) {
	fixtures := []struct {
		family  string
		outcome int64
		want    int64
	}{
		{family: "binomial", outcome: 256, want: 32},
		{family: "poisson", outcome: 512, want: 64},
	}
	for _, fixture := range fixtures {
		policy := formalGLMTestPolicy(fixture.family, 3)
		plan, err := planFormalGLMPhase1(policy)
		if err != nil {
			t.Fatal(err)
		}
		input := formalGLMTestInput(policy, fixture.outcome)
		lattice, err := referenceFormalGLMOneIteration(policy, input, plan.RingBits)
		if err != nil {
			t.Fatal(err)
		}
		signed := exactGCReferenceSigned(lattice[0], plan.RingBits)
		if signed.Cmp(big.NewInt(fixture.want)) != 0 {
			t.Fatalf("%s got %s, want %d", fixture.family, signed, fixture.want)
		}
		rational, err := referenceFormalGLMRationalOneIteration(
			policy, input, plan.RingBits)
		if err != nil {
			t.Fatal(err)
		}
		decoded := new(big.Rat).SetFrac(signed, big.NewInt(256))
		difference := new(big.Rat).Sub(decoded, rational[0])
		if difference.Sign() < 0 {
			difference.Neg(difference)
		}
		difference.Mul(difference, big.NewRat(256, 1))
		rho, _ := new(big.Int).SetString(plan.RhoStepsUpper, 10)
		if difference.Cmp(new(big.Rat).SetInt(rho)) > 0 {
			t.Fatalf("fixed-point difference %s exceeds rho %s", difference, rho)
		}
	}
}

func TestFormalGLMPhase1CircuitMatchesIndependentOracle(t *testing.T) {
	policy := formalGLMTestPolicy("binomial", 2)
	plan, err := planFormalGLMPhase1(policy)
	if err != nil {
		t.Fatal(err)
	}
	input := formalGLMTestInput(policy, 256)
	left, right := exactGCTestSplit(rand.New(rand.NewSource(17)), input, plan.RingBits)
	mask := []*big.Int{big.NewInt(1234567)}
	circ, err := compileFormalGLMCircuit(policy, plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	garblerInput := exactGCPackChunks(append(append([]*big.Int{}, left...), mask...),
		exactGCTypeBits(plan.RingBits))
	evaluatorInput := exactGCPackChunks(right, exactGCTypeBits(plan.RingBits))
	outputs, err := circ.Compute([]*big.Int{garblerInput, evaluatorInput})
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != policy.CoefficientCount {
		t.Fatalf("got %d outputs", len(outputs))
	}
	reconstructed := exactGCReferenceReconstruct(mask[0], outputs[0], plan.RingBits)
	want, err := referenceFormalGLMOneIteration(policy, input, plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	if reconstructed.Cmp(want[0]) != 0 {
		t.Fatalf("circuit %s != oracle %s", reconstructed, want[0])
	}
}

func TestFormalGLMPhase1DynamicRingCircuitMatchesOracle(t *testing.T) {
	policy := formalGLMTestPolicy("binomial", 2)
	policy.CoefficientBox = []string{
		new(big.Int).Lsh(big.NewInt(1), 126).String(),
	}
	policy.XKind = []string{"numeric"}
	policy.XLower, policy.XUpper = []string{"0"}, []string{"0"}
	plan, err := planFormalGLMPhase1(policy)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RingBits <= 128 || plan.ContainerBits != 256 {
		t.Fatalf("expected dynamic uint256 circuit, got %+v", plan)
	}
	input := formalGLMTestExpandedInput(policy, plan.RingBits)
	left, right := exactGCTestSplit(rand.New(rand.NewSource(29)), input, plan.RingBits)
	mask := []*big.Int{big.NewInt(7654321)}
	circ, err := compileFormalGLMCircuit(policy, plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	garblerInput := exactGCPackChunks(append(append([]*big.Int{}, left...), mask...),
		plan.ContainerBits)
	evaluatorInput := exactGCPackChunks(right, plan.ContainerBits)
	outputs, err := circ.Compute([]*big.Int{garblerInput, evaluatorInput})
	if err != nil {
		t.Fatal(err)
	}
	got := exactGCReferenceReconstruct(mask[0], outputs[0], plan.RingBits)
	want, err := referenceFormalGLMOneIteration(policy, input, plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(want[0]) != 0 {
		t.Fatalf("dynamic circuit %s != oracle %s", got, want[0])
	}
}

func TestFormalGLMPhase1CompositeCircuitMatrixMatchesOracle(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, shape := range [][2]int{{1, 1}, {2, 2}} {
			policy := formalGLMTestExpandedPolicy(family, shape[0], shape[1])
			plan, err := planFormalGLMPhase1(policy)
			if err != nil {
				t.Fatal(err)
			}
			input := formalGLMTestExpandedInput(policy, plan.RingBits)
			left, right := exactGCTestSplit(
				rand.New(rand.NewSource(int64(101+shape[0]+shape[1]))),
				input, plan.RingBits)
			masks := make([]*big.Int, policy.CoefficientCount)
			for j := range masks {
				masks[j] = big.NewInt(int64(7001 + j))
			}
			circ, err := compileFormalGLMCircuit(policy, plan.RingBits)
			if err != nil {
				t.Fatal(err)
			}
			garblerInput := exactGCPackChunks(
				append(append([]*big.Int{}, left...), masks...), plan.ContainerBits)
			evaluatorInput := exactGCPackChunks(right, plan.ContainerBits)
			outputs, err := circ.Compute([]*big.Int{garblerInput, evaluatorInput})
			if err != nil {
				t.Fatal(err)
			}
			if len(outputs) != 1 {
				t.Fatalf("%s C=%d p=%d output shape=%d", family,
					shape[0], shape[1], len(outputs))
			}
			want, err := referenceFormalGLMOneIteration(policy, input, plan.RingBits)
			if err != nil {
				t.Fatal(err)
			}
			for j := 0; j < policy.CoefficientCount; j++ {
				outputShare := new(big.Int).Rsh(new(big.Int).Set(outputs[0]),
					uint(j*plan.ContainerBits))
				outputShare.And(outputShare, exactGCMask(plan.RingBits))
				got := exactGCReferenceReconstruct(masks[j], outputShare, plan.RingBits)
				if got.Cmp(want[j]) != 0 {
					t.Fatalf("%s C=%d p=%d coefficient=%d circuit=%s oracle=%s",
						family, shape[0], shape[1], j, got, want[j])
				}
			}
		}
	}
}

func TestFormalGLMPhase1RandomizedBoundariesMatchIntegerAndRationalOracles(t *testing.T) {
	for familyIndex, family := range []string{"binomial", "poisson"} {
		policy := formalGLMTestExpandedPolicy(family, 2, 2)
		plan, err := planFormalGLMPhase1(policy)
		if err != nil {
			t.Fatal(err)
		}
		circ, err := compileFormalGLMCircuit(policy, plan.RingBits)
		if err != nil {
			t.Fatal(err)
		}
		rng := rand.New(rand.NewSource(int64(811 + familyIndex)))
		weights := []int64{-256, 0, 128, 256, 512}
		numericX := []int64{-512, -256, -17, 0, 256, 512}
		indicators := []int64{-256, 0, 17, 256, 512}
		binomialY := []int64{-256, 0, 17, 256, 512}
		poissonY := []int64{-256, 0, 17, 256, 512, 2304}
		offsets := []int64{-1024, -512, -17, 0, 512, 1024}
		for iteration := 0; iteration < 24; iteration++ {
			input := make([]*big.Int, 0, plan.InputCoordinates)
			for row := 0; row < policy.Capacity; row++ {
				pick := func(values []int64) *big.Int {
					value := big.NewInt(values[rng.Intn(len(values))])
					return formalGLMResidue(value, plan.RingBits)
				}
				input = append(input, pick(weights), pick(numericX), pick(indicators))
				if family == "binomial" {
					input = append(input, pick(binomialY))
				} else {
					input = append(input, pick(poissonY))
				}
				input = append(input, pick(offsets))
			}
			left, right := exactGCTestSplit(rng, input, plan.RingBits)
			masks := []*big.Int{exactGCTestRandomResidue(rng, plan.RingBits),
				exactGCTestRandomResidue(rng, plan.RingBits)}
			garblerInput := exactGCPackChunks(
				append(append([]*big.Int{}, left...), masks...), plan.ContainerBits)
			evaluatorInput := exactGCPackChunks(right, plan.ContainerBits)
			outputs, err := circ.Compute([]*big.Int{garblerInput, evaluatorInput})
			if err != nil {
				t.Fatal(err)
			}
			integerWant, err := referenceFormalGLMOneIteration(
				policy, input, plan.RingBits)
			if err != nil {
				t.Fatal(err)
			}
			rationalWant, err := referenceFormalGLMRationalOneIteration(
				policy, input, plan.RingBits)
			if err != nil {
				t.Fatal(err)
			}
			totalSteps := new(big.Rat)
			for j := 0; j < policy.CoefficientCount; j++ {
				outputShare := new(big.Int).Rsh(new(big.Int).Set(outputs[0]),
					uint(j*plan.ContainerBits))
				outputShare.And(outputShare, exactGCMask(plan.RingBits))
				got := exactGCReferenceReconstruct(masks[j], outputShare, plan.RingBits)
				if got.Cmp(integerWant[j]) != 0 {
					t.Fatalf("%s iteration=%d coefficient=%d circuit=%s oracle=%s",
						family, iteration, j, got, integerWant[j])
				}
				decoded := new(big.Rat).SetFrac(
					exactGCReferenceSigned(got, plan.RingBits), big.NewInt(256))
				difference := new(big.Rat).Sub(decoded, rationalWant[j])
				if difference.Sign() < 0 {
					difference.Neg(difference)
				}
				difference.Mul(difference, big.NewRat(256, 1))
				totalSteps.Add(totalSteps, difference)
			}
			rho, _ := new(big.Int).SetString(plan.RhoStepsUpper, 10)
			if totalSteps.Cmp(new(big.Rat).SetInt(rho)) > 0 {
				t.Fatalf("%s iteration=%d error=%s exceeds rho=%s",
					family, iteration, totalSteps, rho)
			}
		}
	}
}

func TestFormalGLMPhase1PublicCostIsDeterministicAndPreData(t *testing.T) {
	policy := formalGLMTestExpandedPolicy("binomial", 2, 2)
	first, err := formalGLMPhase1PublicCost(policy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := formalGLMPhase1PublicCost(policy)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Gates <= 0 || first.Wires <= first.Gates ||
		first.NonXORGates == 0 || first.GarblerInputBits != 12*128 ||
		first.EvaluatorInputBits != 10*128 || first.OutputBits != 2*128 ||
		first.ProductionReleaseReady ||
		!strings.Contains(first.BackendSelection, "no_runtime_fallback") ||
		!strings.Contains(first.TranscriptShapeStatus, "padding_audit_pending") {
		t.Fatalf("invalid public cost contract: %+v / %+v", first, second)
	}
	t.Logf("formal GLM public cost C=2 p=2: gates=%d non-XOR=%d wires=%d relative=%d",
		first.Gates, first.NonXORGates, first.Wires, first.CompilerRelativeCost)
}

func TestFormalGLMPhase1TwoPartyProtocolReturnsOnlyShares(t *testing.T) {
	fixtures := []formalGLMPhase1Policy{
		formalGLMTestPolicy("binomial", 2),
		formalGLMTestExpandedPolicy("poisson", 2, 2),
	}
	for index, policy := range fixtures {
		session := formalGLMTestSession(t, policy)
		input := formalGLMTestExpandedInput(policy, session.Spec.RingBits)
		leftShares, rightShares := exactGCTestSplit(
			rand.New(rand.NewSource(int64(31+index))), input, session.Spec.RingBits)
		left, right := net.Pipe()
		_ = left.SetDeadline(time.Now().Add(45 * time.Second))
		_ = right.SetDeadline(time.Now().Add(45 * time.Second))
		type result struct {
			shares []*big.Int
			err    error
		}
		garbler := make(chan result, 1)
		go func() {
			shares, err := runFormalGLMGarbler(left, session, policy, leftShares)
			garbler <- result{shares: shares, err: err}
		}()
		evaluatorShares, err := runFormalGLMEvaluator(
			right, session, policy, rightShares)
		if err != nil {
			left.Close()
			right.Close()
			t.Fatal(err)
		}
		garblerResult := <-garbler
		left.Close()
		right.Close()
		if garblerResult.err != nil {
			t.Fatal(garblerResult.err)
		}
		if len(garblerResult.shares) != policy.CoefficientCount ||
			len(evaluatorShares) != policy.CoefficientCount {
			t.Fatal("sealed output shares have an invalid shape")
		}
		for j := range evaluatorShares {
			if garblerResult.shares[j].Cmp(evaluatorShares[j]) == 0 {
				t.Fatal("sealed output shares unexpectedly match")
			}
		}
		opened, err := reconstructFormalGLMShares(
			garblerResult.shares, evaluatorShares, session.Spec.RingBits)
		if err != nil {
			t.Fatal(err)
		}
		want, err := referenceFormalGLMOneIteration(
			policy, input, session.Spec.RingBits)
		if err != nil {
			t.Fatal(err)
		}
		for j := range opened {
			if opened[j].Cmp(want[j]) != 0 {
				t.Fatalf("%s C=%d p=%d coefficient=%d result=%s oracle=%s",
					policy.Family, policy.Capacity, policy.CoefficientCount,
					j, opened[j], want[j])
			}
		}
	}
}

func TestFormalGLMPhase1RejectsTamperRoleAndKeySubstitution(t *testing.T) {
	policy := formalGLMTestPolicy("binomial", 3)
	session := formalGLMTestSession(t, policy)
	input := formalGLMTestInput(policy, 256)

	tampered := policy
	tampered.SnapshotSHA256 = strings.Repeat("a", 64)
	if _, _, err := validateFormalGLMSession(session, tampered); err == nil {
		t.Fatal("snapshot substitution was accepted")
	}
	role := session
	role.GarblerID, role.EvaluatorID = role.EvaluatorID, role.GarblerID
	if _, _, err := validateFormalGLMSession(role, policy); err == nil {
		t.Fatal("compute-role substitution was accepted")
	}
	peers := policy
	peers.ComputePeers = []string{"peer-a", "peer-c"}
	if _, _, err := validateFormalGLMSession(session, peers); err == nil {
		t.Fatal("pinned compute-peer substitution was accepted")
	}
	adjacency := policy
	adjacency.Adjacency = "replace_one"
	if _, _, err := validateFormalGLMSession(session, adjacency); err == nil {
		t.Fatal("adjacency substitution was accepted")
	}
	linkCertificate := policy
	linkCertificate.LinkErrorUpper = "9"
	if _, _, err := validateFormalGLMSession(session, linkCertificate); err == nil {
		t.Fatal("link-certificate substitution was accepted")
	}

	leftShares, rightShares := exactGCTestSplit(rand.New(rand.NewSource(43)), input,
		session.Spec.RingBits)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(5 * time.Second))
	_ = right.SetDeadline(time.Now().Add(5 * time.Second))
	wrongKey := session
	wrongKey.MasterKey = sha256.Sum256([]byte("substituted formal GLM key"))
	garbler := make(chan error, 1)
	go func() {
		_, err := runFormalGLMGarbler(left, session, policy, leftShares)
		garbler <- err
	}()
	_, evaluatorErr := runFormalGLMEvaluator(right, wrongKey, policy, rightShares)
	garblerErr := <-garbler
	if evaluatorErr == nil || garblerErr == nil {
		t.Fatalf("key substitution did not fail both peers: %v / %v",
			garblerErr, evaluatorErr)
	}
}

func TestFormalGLMPhase1SecureRecordRejectsReplay(t *testing.T) {
	policy := formalGLMTestPolicy("binomial", 3)
	session := formalGLMTestSession(t, policy)
	plaintext := []byte("formal-glm-private-source-share")
	one := exactGCTestRecord(session, plaintext)
	raw := append(append([]byte{}, one...), one...)
	receiver, err := newExactGCSecureRecordRW(
		&readWriter{Reader: bytes.NewReader(raw)}, session, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	if _, err := io.ReadFull(receiver, got); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("first authenticated record failed: %v", err)
	}
	if _, err := io.ReadFull(receiver, got); err == nil ||
		!strings.Contains(err.Error(), "replayed or out-of-order") {
		t.Fatalf("formal GLM record replay was accepted: %v", err)
	}
}

func TestFormalGLMPhase1PrivateValuesCannotChangePublicShape(t *testing.T) {
	policy := formalGLMTestPolicy("binomial", 2)
	plan, err := planFormalGLMPhase1(policy)
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]*big.Int{
		formalGLMTestInput(policy, 0),
		formalGLMTestInput(policy, 256),
		{big.NewInt(0), big.NewInt(0), big.NewInt(17), big.NewInt(0)},
		{exactGCMaxSigned(plan.RingBits), exactGCMaxSigned(plan.RingBits),
			exactGCMaxSigned(plan.RingBits), exactGCMaxSigned(plan.RingBits)},
	}
	for _, input := range inputs {
		result, err := referenceFormalGLMOneIteration(policy, input, plan.RingBits)
		if err != nil || len(result) != plan.OutputCoordinates {
			t.Fatalf("private input changed public result shape: %v", err)
		}
	}
}

func TestFormalGLMPhase1PrivateValuesCannotChangeTranscriptSchedule(t *testing.T) {
	policy := formalGLMTestPolicy("binomial", 3)
	inputs := [][]*big.Int{
		{big.NewInt(0), big.NewInt(0), big.NewInt(17), big.NewInt(0)},
		{exactGCMaxSigned(128), exactGCMaxSigned(128),
			exactGCMaxSigned(128), exactGCMaxSigned(128)},
	}
	type transcript struct {
		garblerCalls, garblerBytes     int64
		evaluatorCalls, evaluatorBytes int64
	}
	run := func(index int, input []*big.Int) transcript {
		session := formalGLMTestSession(t, policy)
		session.SessionID = sha256.Sum256(
			[]byte(fmt.Sprintf("formal-glm/transcript/%d", index)))
		leftShares, rightShares := exactGCTestSplit(
			rand.New(rand.NewSource(int64(901+index))), input, session.Spec.RingBits)
		leftRaw, rightRaw := net.Pipe()
		left := &formalGLMCountingConn{Conn: leftRaw}
		right := &formalGLMCountingConn{Conn: rightRaw}
		_ = left.SetDeadline(time.Now().Add(45 * time.Second))
		_ = right.SetDeadline(time.Now().Add(45 * time.Second))
		garbler := make(chan error, 1)
		go func() {
			_, err := runFormalGLMGarbler(left, session, policy, leftShares)
			garbler <- err
		}()
		_, evaluatorErr := runFormalGLMEvaluator(right, session, policy, rightShares)
		garblerErr := <-garbler
		left.Close()
		right.Close()
		if evaluatorErr != nil || garblerErr != nil {
			t.Fatalf("transcript run failed: %v / %v", garblerErr, evaluatorErr)
		}
		return transcript{
			garblerCalls: left.writeCalls, garblerBytes: left.writeBytes,
			evaluatorCalls: right.writeCalls, evaluatorBytes: right.writeBytes,
		}
	}
	first, second := run(0, inputs[0]), run(1, inputs[1])
	if first.garblerCalls != second.garblerCalls ||
		first.evaluatorCalls != second.evaluatorCalls ||
		first.garblerCalls == 0 || first.evaluatorCalls == 0 {
		t.Fatalf("private values changed the logical frame schedule: %+v / %+v",
			first, second)
	}
	t.Logf("fixed frame schedule; randomized OT/garbling encoding bytes were %+v / %+v",
		first, second)
}

func BenchmarkFormalGLMPhase1ReferenceFixedShape(b *testing.B) {
	for _, family := range []string{"binomial", "poisson"} {
		b.Run(family, func(b *testing.B) {
			policy := formalGLMTestPolicy(family, 3)
			plan, _ := planFormalGLMPhase1(policy)
			input := formalGLMTestInput(policy, 256)
			b.ReportMetric(float64(plan.InputCoordinates), "input-coordinates")
			b.ReportMetric(float64(plan.LogicalFixedShapeMul), "logical-muls")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = referenceFormalGLMOneIteration(policy, input, plan.RingBits)
			}
		})
	}
}

func BenchmarkFormalGLMPhase1CircuitCompute(b *testing.B) {
	for _, fixture := range []struct {
		name         string
		capacity     int
		coefficients int
	}{
		{name: "C1_p1", capacity: 1, coefficients: 1},
		{name: "C4_p2", capacity: 4, coefficients: 2},
	} {
		b.Run(fixture.name, func(b *testing.B) {
			policy := formalGLMTestExpandedPolicy(
				"binomial", fixture.capacity, fixture.coefficients)
			plan, err := planFormalGLMPhase1(policy)
			if err != nil {
				b.Fatal(err)
			}
			circ, err := compileFormalGLMCircuit(policy, plan.RingBits)
			if err != nil {
				b.Fatal(err)
			}
			input := formalGLMTestExpandedInput(policy, plan.RingBits)
			masks := make([]*big.Int, fixture.coefficients)
			zeros := make([]*big.Int, len(input))
			for i := range masks {
				masks[i] = big.NewInt(0)
			}
			for i := range zeros {
				zeros[i] = big.NewInt(0)
			}
			garblerInput := exactGCPackChunks(append(input, masks...), plan.ContainerBits)
			evaluatorInput := exactGCPackChunks(zeros, plan.ContainerBits)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := circ.Compute([]*big.Int{garblerInput, evaluatorInput}); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(circ.NumGates), "gates")
			b.ReportMetric(float64(circ.Stats.NumNonXOR()), "non-xor-gates")
			b.ReportMetric(float64(plan.InputCoordinates), "input-coordinates")
		})
	}
}

func BenchmarkFormalGLMPhase1InProcessTwoParty(b *testing.B) {
	for _, fixture := range []struct {
		name         string
		capacity     int
		coefficients int
	}{
		{name: "C1_p1", capacity: 1, coefficients: 1},
		{name: "C2_p2", capacity: 2, coefficients: 2},
	} {
		b.Run(fixture.name, func(b *testing.B) {
			policy := formalGLMTestExpandedPolicy(
				"binomial", fixture.capacity, fixture.coefficients)
			session := formalGLMTestSession(b, policy)
			input := formalGLMTestExpandedInput(policy, session.Spec.RingBits)
			leftShares, rightShares := exactGCTestSplit(
				rand.New(rand.NewSource(717)), input, session.Spec.RingBits)
			circ, err := compileFormalGLMCircuit(policy, session.Spec.RingBits)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				left, right := net.Pipe()
				_ = left.SetDeadline(time.Now().Add(45 * time.Second))
				_ = right.SetDeadline(time.Now().Add(45 * time.Second))
				garbler := make(chan error, 1)
				go func() {
					_, err := runFormalGLMGarbler(left, session, policy, leftShares)
					garbler <- err
				}()
				_, evaluatorErr := runFormalGLMEvaluator(
					right, session, policy, rightShares)
				garblerErr := <-garbler
				left.Close()
				right.Close()
				if evaluatorErr != nil || garblerErr != nil {
					b.Fatalf("protocol failed: %v / %v", garblerErr, evaluatorErr)
				}
			}
			b.ReportMetric(float64(circ.NumGates), "gates")
			b.ReportMetric(float64(circ.Stats.NumNonXOR()), "non-xor-gates")
			b.ReportMetric(float64(len(input)), "input-coordinates")
		})
	}
}

func FuzzFormalGLMCanonicalSigned(f *testing.F) {
	for _, seed := range []string{"0", "-1", "1", "+1", "01", "-0", "", "1e3"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > exactGCMaxDecimalBoundDigits+2 {
			return
		}
		parsed, err := formalGLMCanonicalSigned(value, "fuzz value")
		if err != nil {
			return
		}
		if parsed.String() != value || len(value) > exactGCMaxDecimalBoundDigits ||
			strings.HasPrefix(value, "+") || value == "-0" {
			t.Fatalf("non-canonical decimal was accepted: %q", value)
		}
	})
}
