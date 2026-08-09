package main

// Phase 1.5 bounded-memory, multi-iteration execution for the sealed formal
// GLM.  Source blocks and optimizer state enter only as additive shares.  Each
// exact-GC step emits fresh shares; neither peer nor the relay receives beta,
// a gradient, a residual, a validity flag, or a row-level opening.
//
// This remains an internal research path.  It is intentionally absent from
// main.go, the R command surface, advertised capabilities, and release
// binaries until the DSI E2E and measured memory gates are complete.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/p2p"
)

const (
	formalGLMPhase15PlanVersion = "dsvert-formal-glm-phase15-plan-v1"
	formalGLMPhase15CostVersion = "dsvert-formal-glm-phase15-cost-v1"
	formalGLMPhase15MaxTotal    = 1 << 31
	formalGLMPhase15MaxIters    = 10000

	// This is a per-circuit, public-shape safety envelope, not a query or
	// privacy budget.  Larger datasets are streamed through more blocks.
	formalGLMPhase15MaxEstimatedWorkingBytes uint64 = 768 << 20
	formalGLMPhase15BytesPerGateEstimate     uint64 = 320
	formalGLMPhase15BytesPerWireEstimate     uint64 = 24
	formalGLMPhase15MaxBlockCoefficientWork         = 4
)

type formalGLMPhase15CircuitCost struct {
	CircuitSourceSHA256  string `json:"circuit_source_sha256"`
	Gates                int    `json:"gates"`
	Wires                int    `json:"wires"`
	XORGates             uint64 `json:"xor_gates"`
	NonXORGates          uint64 `json:"non_xor_gates"`
	CompilerRelativeCost uint64 `json:"compiler_relative_cost"`
	GarblerInputBits     int    `json:"garbler_input_bits"`
	EvaluatorInputBits   int    `json:"evaluator_input_bits"`
	OutputBits           int    `json:"output_bits"`
	EstimatedWorkingByte uint64 `json:"estimated_working_bytes"`
}

// Kernel is the signed scientific kernel template.  Its Capacity is the
// physical block capacity and Iterations must be one; TotalCapacity and
// Iterations below define the complete optimizer schedule.
type formalGLMPhase15Plan struct {
	Version          string                      `json:"version"`
	RunID            string                      `json:"run_id"`
	Kernel           formalGLMPhase1Policy       `json:"kernel"`
	TotalCapacity    int                         `json:"total_capacity"`
	BlockCapacity    int                         `json:"block_capacity"`
	TotalBlocks      int                         `json:"total_blocks"`
	Iterations       int                         `json:"iterations"`
	CoordinateOwners []string                    `json:"coordinate_owners"`
	RingBits         int                         `json:"ring_bits"`
	ContainerBits    int                         `json:"container_bits"`
	MaximumMagnitude string                      `json:"maximum_magnitude"`
	RhoTotalUpper    string                      `json:"rho_total_upper"`
	ScheduleSteps    int                         `json:"schedule_steps"`
	BlockCost        formalGLMPhase15CircuitCost `json:"block_cost"`
	FinalizeCost     formalGLMPhase15CircuitCost `json:"finalize_cost"`
	BackendSelection string                      `json:"backend_selection"`
	TranscriptShape  string                      `json:"transcript_shape"`
	CrashRecovery    string                      `json:"crash_recovery"`
	Output           string                      `json:"output"`
	ProductionReady  bool                        `json:"production_ready"`
}

type formalGLMPhase15ResourceError struct {
	Code                  string
	MinimumEstimatedBytes uint64
}

func (e *formalGLMPhase15ResourceError) Error() string {
	return fmt.Sprintf("formal-glm: %s (minimum estimated working bytes %d)",
		e.Code, e.MinimumEstimatedBytes)
}

func formalGLMPhase15PlanDigest(plan formalGLMPhase15Plan) ([32]byte, error) {
	encoded, err := json.Marshal(plan)
	if err != nil {
		return [32]byte{}, fmt.Errorf("formal-glm: encode Phase-1.5 plan: %w", err)
	}
	return sha256.Sum256(append(
		[]byte("dsVert/formal-glm/phase15-plan/v1|"), encoded...)), nil
}

func formalGLMPhase15ValidateShape(plan formalGLMPhase15Plan) (
	formalGLMParsedPolicy, error) {

	var zero formalGLMParsedPolicy
	maxInt := int(^uint(0) >> 1)
	scheduleValid := plan.Iterations >= 1 && plan.TotalBlocks >= 1 &&
		plan.TotalBlocks+1 <= maxInt/plan.Iterations &&
		plan.ScheduleSteps == plan.Iterations*(plan.TotalBlocks+1)
	if plan.Version != formalGLMPhase15PlanVersion ||
		!formalGLMIsSHA256(plan.RunID) ||
		plan.TotalCapacity < 1 || plan.TotalCapacity > formalGLMPhase15MaxTotal ||
		plan.BlockCapacity < 1 || plan.BlockCapacity > formalGLMPhase1MaxCapacity ||
		plan.BlockCapacity*plan.Kernel.CoefficientCount >
			formalGLMPhase15MaxBlockCoefficientWork ||
		plan.BlockCapacity != plan.Kernel.Capacity || plan.Kernel.Iterations != 1 ||
		plan.Iterations < 1 || plan.Iterations > formalGLMPhase15MaxIters ||
		plan.TotalBlocks != (plan.TotalCapacity+plan.BlockCapacity-1)/plan.BlockCapacity ||
		!scheduleValid ||
		plan.RingBits < 128 || plan.RingBits > exactGCMaxRingBits ||
		plan.ContainerBits != exactGCTypeBits(plan.RingBits) ||
		plan.BackendSelection != "streamed_exact_gc_ot_no_runtime_fallback_v1" ||
		plan.TranscriptShape != "fixed_public_step_schedule_transport_padding_audit_pending" ||
		plan.CrashRecovery != "commit_barrier_or_fresh_session_never_resume_mid_gc_v1" ||
		plan.Output != "sealed_coefficient_additive_shares_only_v1" ||
		plan.ProductionReady {
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.5 plan shape")
	}
	parsed, err := parseFormalGLMPhase1Policy(plan.Kernel)
	if err != nil {
		return zero, err
	}
	coordinates := plan.Kernel.CoefficientCount + 3
	if len(plan.CoordinateOwners) != coordinates {
		return zero, fmt.Errorf("formal-glm: invalid coordinate-ownership shape")
	}
	custodians := make(map[string]bool, len(plan.Kernel.CustodianPeers))
	for _, peer := range plan.Kernel.CustodianPeers {
		custodians[peer] = true
	}
	for _, owner := range plan.CoordinateOwners {
		if !custodians[owner] {
			return zero, fmt.Errorf("formal-glm: coordinate owner is not a custodian")
		}
	}
	return parsed, nil
}

func formalGLMPhase15NumericEnvelope(kernel formalGLMPhase1Policy,
	totalCapacity, iterations int) (maximum, rho *big.Int, requiredBits int, err error) {

	parsed, err := parseFormalGLMPhase1Policy(kernel)
	if err != nil {
		return nil, nil, 0, err
	}
	p := kernel.CoefficientCount
	maximum = formalGLMMax(parsed.scale, parsed.weightUpper,
		parsed.outcomeUpper, formalGLMAbs(parsed.offsetLower),
		formalGLMAbs(parsed.offsetUpper), parsed.alpha)
	etaLower := new(big.Int).Set(parsed.offsetLower)
	etaUpper := new(big.Int).Set(parsed.offsetUpper)
	for j := 0; j < p; j++ {
		xMagnitude := formalGLMMax(formalGLMAbs(parsed.xLower[j]),
			formalGLMAbs(parsed.xUpper[j]))
		etaContribution := formalGLMCeilMul(xMagnitude, parsed.box[j], parsed.scale)
		etaLower.Sub(etaLower, etaContribution)
		etaUpper.Add(etaUpper, etaContribution)
		maximum = formalGLMMax(maximum, xMagnitude, parsed.box[j], parsed.ridge[j])
	}
	if etaLower.Cmp(parsed.knots[0]) < 0 ||
		etaUpper.Cmp(parsed.knots[len(parsed.knots)-1]) > 0 {
		return nil, nil, 0, fmt.Errorf("formal-glm: link domain does not cover all streamed eta bounds")
	}
	linkMagnitude := big.NewInt(0)
	slopeMax := big.NewInt(0)
	for i, value := range parsed.values {
		linkMagnitude = formalGLMMax(linkMagnitude, formalGLMAbs(value))
		maximum = formalGLMMax(maximum, formalGLMAbs(value), formalGLMAbs(parsed.knots[i]))
		if i < len(parsed.slopes) {
			slopeMax = formalGLMMax(slopeMax, parsed.slopes[i])
			maximum = formalGLMMax(maximum, parsed.slopes[i])
		}
	}
	residual := new(big.Int).Add(linkMagnitude, parsed.outcomeUpper)
	weighted := formalGLMCeilMul(parsed.weightUpper, residual, parsed.scale)
	maximum = formalGLMMax(maximum, formalGLMAbs(etaLower),
		formalGLMAbs(etaUpper), linkMagnitude, residual, weighted)
	rhoOne := big.NewInt(0)
	for j := 0; j < p; j++ {
		xMagnitude := formalGLMMax(formalGLMAbs(parsed.xLower[j]),
			formalGLMAbs(parsed.xUpper[j]))
		rowScore := formalGLMCeilMul(xMagnitude, weighted, parsed.scale)
		accumulator := new(big.Int).Mul(rowScore, big.NewInt(int64(totalCapacity)))
		average := exactGCCeilDiv(accumulator, big.NewInt(int64(totalCapacity)))
		ridge := formalGLMCeilMul(parsed.ridge[j], parsed.box[j], parsed.scale)
		gradient := new(big.Int).Add(average, ridge)
		step := formalGLMCeilMul(parsed.alpha, gradient, parsed.scale)
		candidate := new(big.Int).Add(parsed.box[j], step)
		maximum = formalGLMMax(maximum, rowScore, accumulator, average,
			ridge, gradient, step, candidate)

		etaError := big.NewInt(int64(p))
		muError := new(big.Int).Add(
			formalGLMCeilMul(slopeMax, etaError, parsed.scale), big.NewInt(1))
		weightedError := new(big.Int).Add(
			formalGLMCeilMul(parsed.weightUpper, muError, parsed.scale), big.NewInt(1))
		scoreError := new(big.Int).Add(
			formalGLMCeilMul(xMagnitude, weightedError, parsed.scale), big.NewInt(1))
		averageError := new(big.Int).Add(scoreError, big.NewInt(1))
		gradientError := new(big.Int).Add(averageError, big.NewInt(2))
		stepError := new(big.Int).Add(
			formalGLMCeilMul(parsed.alpha, gradientError, parsed.scale), big.NewInt(1))
		rhoOne.Add(rhoOne, stepError)
	}
	rho = new(big.Int).Mul(rhoOne, big.NewInt(int64(iterations)))
	requiredBits = maximum.BitLen() + 2
	if requiredBits < 128 {
		requiredBits = 128
	}
	if requiredBits > exactGCMaxRingBits {
		return nil, nil, requiredBits, &formalGLMNumericBackendError{
			Code: "numeric_backend_unrepresentable", RequiredBits: requiredBits}
	}
	return maximum, rho, requiredBits, nil
}

func formalGLMPhase15CircuitCostOf(source string, circ *circuit.Circuit) (
	formalGLMPhase15CircuitCost, error) {

	if circ == nil || len(circ.Inputs) != 2 || len(circ.Outputs) != 1 {
		return formalGLMPhase15CircuitCost{}, fmt.Errorf("formal-glm: invalid compiled Phase-1.5 circuit")
	}
	digest := sha256.Sum256([]byte(source))
	gates := uint64(circ.NumGates)
	wires := uint64(circ.NumWires)
	if gates > (^uint64(0))/formalGLMPhase15BytesPerGateEstimate ||
		wires > (^uint64(0))/formalGLMPhase15BytesPerWireEstimate {
		return formalGLMPhase15CircuitCost{}, fmt.Errorf("formal-glm: circuit resource estimate overflow")
	}
	estimated := gates*formalGLMPhase15BytesPerGateEstimate +
		wires*formalGLMPhase15BytesPerWireEstimate
	return formalGLMPhase15CircuitCost{
		CircuitSourceSHA256: hex.EncodeToString(digest[:]),
		Gates:               circ.NumGates, Wires: circ.NumWires,
		XORGates: circ.Stats.NumXOR(), NonXORGates: circ.Stats.NumNonXOR(),
		CompilerRelativeCost: circ.Cost(),
		GarblerInputBits:     int(circ.Inputs[0].Type.Bits),
		EvaluatorInputBits:   int(circ.Inputs[1].Type.Bits),
		OutputBits:           circ.Outputs.Size(), EstimatedWorkingByte: estimated,
	}, nil
}

// buildFormalGLMPhase15Plan automatically reduces only the physical block
// size until the public per-circuit memory envelope fits.  It never reduces
// rows, iterations, methods, or the number of permitted requests.
func buildFormalGLMPhase15Plan(kernel formalGLMPhase1Policy,
	totalCapacity, iterations int, coordinateOwners []string,
	runID string) (formalGLMPhase15Plan, error) {

	requestedBlock := kernel.Capacity
	if requestedBlock < 1 || requestedBlock > formalGLMPhase1MaxCapacity ||
		kernel.CoefficientCount < 1 ||
		kernel.CoefficientCount > formalGLMPhase1MaxCoefficients {
		return formalGLMPhase15Plan{}, fmt.Errorf("formal-glm: invalid requested stream block capacity")
	}
	if totalCapacity < 1 || totalCapacity > formalGLMPhase15MaxTotal ||
		iterations < 1 || iterations > formalGLMPhase15MaxIters {
		return formalGLMPhase15Plan{}, fmt.Errorf("formal-glm: invalid complete stream schedule")
	}
	analyticBlock := formalGLMPhase15MaxBlockCoefficientWork / kernel.CoefficientCount
	if analyticBlock < 1 {
		analyticBlock = 1
	}
	if requestedBlock > analyticBlock {
		requestedBlock = analyticBlock
	}
	var minimum uint64
	for block := requestedBlock; block >= 1; block-- {
		candidateKernel := kernel
		candidateKernel.Capacity = block
		candidateKernel.Iterations = 1
		maximum, rho, ringBits, err := formalGLMPhase15NumericEnvelope(
			candidateKernel, totalCapacity, iterations)
		if err != nil {
			return formalGLMPhase15Plan{}, err
		}
		plan := formalGLMPhase15Plan{
			Version: formalGLMPhase15PlanVersion, RunID: runID,
			Kernel: candidateKernel, TotalCapacity: totalCapacity,
			BlockCapacity:    block,
			TotalBlocks:      (totalCapacity + block - 1) / block,
			Iterations:       iterations,
			CoordinateOwners: append([]string(nil), coordinateOwners...),
			RingBits:         ringBits, ContainerBits: exactGCTypeBits(ringBits),
			MaximumMagnitude: maximum.String(), RhoTotalUpper: rho.String(),
			BackendSelection: "streamed_exact_gc_ot_no_runtime_fallback_v1",
			TranscriptShape:  "fixed_public_step_schedule_transport_padding_audit_pending",
			CrashRecovery:    "commit_barrier_or_fresh_session_never_resume_mid_gc_v1",
			Output:           "sealed_coefficient_additive_shares_only_v1",
			ProductionReady:  false,
		}
		plan.ScheduleSteps = plan.Iterations * (plan.TotalBlocks + 1)
		if _, err := formalGLMPhase15ValidateShape(plan); err != nil {
			return formalGLMPhase15Plan{}, err
		}
		blockSource, err := formalGLMPhase15BlockCircuitSource(plan)
		if err != nil {
			return formalGLMPhase15Plan{}, err
		}
		blockCircuit, err := compileFormalGLMPhase15Source(blockSource,
			"stream block")
		if err != nil {
			return formalGLMPhase15Plan{}, err
		}
		finalSource, err := formalGLMPhase15FinalizeCircuitSource(plan)
		if err != nil {
			return formalGLMPhase15Plan{}, err
		}
		finalCircuit, err := compileFormalGLMPhase15Source(finalSource,
			"iteration finalizer")
		if err != nil {
			return formalGLMPhase15Plan{}, err
		}
		plan.BlockCost, err = formalGLMPhase15CircuitCostOf(blockSource, blockCircuit)
		if err != nil {
			return formalGLMPhase15Plan{}, err
		}
		plan.FinalizeCost, err = formalGLMPhase15CircuitCostOf(finalSource, finalCircuit)
		if err != nil {
			return formalGLMPhase15Plan{}, err
		}
		minimum = plan.BlockCost.EstimatedWorkingByte
		if plan.FinalizeCost.EstimatedWorkingByte > minimum {
			minimum = plan.FinalizeCost.EstimatedWorkingByte
		}
		if minimum <= formalGLMPhase15MaxEstimatedWorkingBytes {
			return plan, nil
		}
	}
	return formalGLMPhase15Plan{}, &formalGLMPhase15ResourceError{
		Code:                  "minimum_stream_block_exceeds_public_memory_envelope",
		MinimumEstimatedBytes: minimum}
}

func validateFormalGLMPhase15Plan(plan formalGLMPhase15Plan) error {
	if _, err := formalGLMPhase15ValidateShape(plan); err != nil {
		return err
	}
	maximum, rho, ringBits, err := formalGLMPhase15NumericEnvelope(
		plan.Kernel, plan.TotalCapacity, plan.Iterations)
	if err != nil {
		return err
	}
	if plan.RingBits != ringBits || plan.MaximumMagnitude != maximum.String() ||
		plan.RhoTotalUpper != rho.String() {
		return fmt.Errorf("formal-glm: invalid numeric certificate")
	}
	blockSource, err := formalGLMPhase15BlockCircuitSource(plan)
	if err != nil {
		return err
	}
	blockCircuit, err := compileFormalGLMPhase15Source(blockSource, "stream block")
	if err != nil {
		return err
	}
	wantBlock, err := formalGLMPhase15CircuitCostOf(blockSource, blockCircuit)
	if err != nil {
		return err
	}
	finalSource, err := formalGLMPhase15FinalizeCircuitSource(plan)
	if err != nil {
		return err
	}
	finalCircuit, err := compileFormalGLMPhase15Source(finalSource, "iteration finalizer")
	if err != nil {
		return err
	}
	wantFinal, err := formalGLMPhase15CircuitCostOf(finalSource, finalCircuit)
	if err != nil {
		return err
	}
	if plan.BlockCost != wantBlock || plan.FinalizeCost != wantFinal ||
		plan.BlockCost.EstimatedWorkingByte > formalGLMPhase15MaxEstimatedWorkingBytes ||
		plan.FinalizeCost.EstimatedWorkingByte > formalGLMPhase15MaxEstimatedWorkingBytes {
		return fmt.Errorf("formal-glm: invalid or excessive public circuit cost contract")
	}
	return nil
}

var formalGLMPhase15CircuitCache = struct {
	sync.Mutex
	entries map[string]*circuit.Circuit
}{entries: make(map[string]*circuit.Circuit)}

func compileFormalGLMPhase15Source(source, label string) (*circuit.Circuit, error) {
	digest := sha256.Sum256([]byte(source))
	key := hex.EncodeToString(digest[:])
	formalGLMPhase15CircuitCache.Lock()
	if cached := formalGLMPhase15CircuitCache.entries[key]; cached != nil {
		formalGLMPhase15CircuitCache.Unlock()
		return cached, nil
	}
	formalGLMPhase15CircuitCache.Unlock()
	circ, _, err := compiler.New(utils.NewParams()).Compile(source, nil)
	if err != nil {
		return nil, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("formal-glm: compile %s: %w", label, err))
	}
	formalGLMPhase15CircuitCache.Lock()
	// Two circuits per active plan are sufficient; cap this research cache so
	// untrusted public plans cannot retain unbounded compiled circuits.
	if len(formalGLMPhase15CircuitCache.entries) >= 4 {
		formalGLMPhase15CircuitCache.entries = make(map[string]*circuit.Circuit)
	}
	formalGLMPhase15CircuitCache.entries[key] = circ
	formalGLMPhase15CircuitCache.Unlock()
	return circ, nil
}

func formalGLMPhase15CircuitPreamble(parsed formalGLMParsedPolicy,
	ringBits int) (string, string, string, func(*big.Int) string) {
	typeBits := exactGCTypeBits(ringBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	wideType := fmt.Sprintf("uint%d", 2*typeBits)
	mask := exactGCMask(ringBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(ringBits-1)).Text(16)
	fracMask := new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1)).Text(16)
	constant := func(value *big.Int) string {
		return fmt.Sprintf("%s(0x%s)", uintType, formalGLMHex(value, ringBits))
	}
	var source strings.Builder
	fmt.Fprintf(&source, `package main
func signedLess(a %s, b %s) bool {
	aNeg := (a & %s(0x%s)) != 0
	bNeg := (b & %s(0x%s)) != 0
	if aNeg != bNeg { return aNeg }
	return a < b
}
func mulFloor(a %s, b %s) %s {
	aNeg := (a & %s(0x%s)) != 0
	bNeg := (b & %s(0x%s)) != 0
	aMag := a
	bMag := b
	if aNeg { aMag = (%s(0) - a) & %s(0x%s) }
	if bNeg { bMag = (%s(0) - b) & %s(0x%s) }
	product := wideMul(aMag, bMag)
	quotient := product >> %d
	remainder := product & %s(0x%s)
	negative := aNeg != bNeg
	if negative && remainder != 0 { quotient = quotient + 1 }
	result := %s(quotient)
	if negative { result = (%s(0) - result) & %s(0x%s) }
	return result
}
func divFloor(a %s, denominator %s) %s {
	negative := (a & %s(0x%s)) != 0
	magnitude := a
	if negative { magnitude = (%s(0) - a) & %s(0x%s) }
	quotient := magnitude / denominator
	remainder := magnitude %% denominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	if negative { quotient = (%s(0) - quotient) & %s(0x%s) }
	return quotient
}
`, uintType, uintType, uintType, sign, uintType, sign,
		uintType, uintType, uintType,
		uintType, sign, uintType, sign,
		uintType, uintType, mask, uintType, uintType, mask,
		parsed.policy.FracBits, wideType, fracMask, uintType,
		uintType, uintType, mask,
		uintType, uintType, uintType, uintType, sign,
		uintType, uintType, mask, uintType, uintType, mask)
	return source.String(), uintType, mask, constant
}

func formalGLMPhase15BlockCircuitSource(plan formalGLMPhase15Plan) (string, error) {
	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil {
		return "", err
	}
	p, block := plan.Kernel.CoefficientCount, plan.BlockCapacity
	rows := block * (p + 3)
	local := rows + 2*p
	preamble, uintType, mask, constant := formalGLMPhase15CircuitPreamble(
		parsed, plan.RingBits)
	fracMask := new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1)).Text(16)
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		local+2*p, uintType, local, uintType, 2*p, uintType)
	for j := 0; j < p; j++ {
		fmt.Fprintf(&source,
			"\tbeta%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			j, rows+j, rows+j, uintType, mask)
		negativeBox := new(big.Int).Neg(new(big.Int).Set(parsed.box[j]))
		fmt.Fprintf(&source, "\tif signedLess(beta%d, %s) { beta%d = %s }\n",
			j, constant(negativeBox), j, constant(negativeBox))
		fmt.Fprintf(&source, "\tif signedLess(%s, beta%d) { beta%d = %s }\n",
			constant(parsed.box[j]), j, j, constant(parsed.box[j]))
		fmt.Fprintf(&source,
			"\tgradient%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			j, rows+p+j, rows+p+j, uintType, mask)
	}
	for row := 0; row < block; row++ {
		base := row * (p + 3)
		fmt.Fprintf(&source, "\tw%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			row, base, base, uintType, mask)
		fmt.Fprintf(&source, "\tif signedLess(w%d, %s(0)) { w%d = %s(0) }\n",
			row, uintType, row, uintType)
		fmt.Fprintf(&source, "\tif signedLess(%s, w%d) { w%d = %s }\n",
			constant(parsed.weightUpper), row, row, constant(parsed.weightUpper))
		fmt.Fprintf(&source, "\trowValid%d := true\n", row)
		for j := 0; j < p; j++ {
			index := base + 1 + j
			fmt.Fprintf(&source, "\tx%d_%d := (g[%d] + e[%d]) & %s(0x%s)\n",
				row, j, index, index, uintType, mask)
			if formalGLMIndicatorKind(plan.Kernel.XKind[j]) {
				fmt.Fprintf(&source,
					"\txValid%d_%d := x%d_%d == %s(0) || x%d_%d == %s\n",
					row, j, row, j, uintType, row, j, constant(parsed.scale))
				fmt.Fprintf(&source,
					"\trowValid%d = rowValid%d && xValid%d_%d\n", row, row, row, j)
				fmt.Fprintf(&source, "\tif !xValid%d_%d { x%d_%d = %s(0) }\n",
					row, j, row, j, uintType)
			} else {
				fmt.Fprintf(&source, "\tif signedLess(x%d_%d, %s) { x%d_%d = %s }\n",
					row, j, constant(parsed.xLower[j]), row, j, constant(parsed.xLower[j]))
				fmt.Fprintf(&source, "\tif signedLess(%s, x%d_%d) { x%d_%d = %s }\n",
					constant(parsed.xUpper[j]), row, j, row, j, constant(parsed.xUpper[j]))
			}
		}
		yIndex, offsetIndex := base+p+1, base+p+2
		fmt.Fprintf(&source, "\ty%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			row, yIndex, yIndex, uintType, mask)
		if plan.Kernel.Family == "binomial" {
			fmt.Fprintf(&source, "\tyValid%d := y%d == %s(0) || y%d == %s\n",
				row, row, uintType, row, constant(parsed.scale))
		} else {
			fmt.Fprintf(&source, "\tyValid%d := (y%d & %s(0x%s)) == 0\n",
				row, row, uintType, fracMask)
		}
		fmt.Fprintf(&source, "\trowValid%d = rowValid%d && yValid%d\n",
			row, row, row)
		fmt.Fprintf(&source, "\tif !yValid%d { y%d = %s(0) }\n", row, row, uintType)
		fmt.Fprintf(&source, "\tif signedLess(y%d, %s(0)) { y%d = %s(0) }\n",
			row, uintType, row, uintType)
		fmt.Fprintf(&source, "\tif signedLess(%s, y%d) { y%d = %s }\n",
			constant(parsed.outcomeUpper), row, row, constant(parsed.outcomeUpper))
		fmt.Fprintf(&source, "\to%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			row, offsetIndex, offsetIndex, uintType, mask)
		fmt.Fprintf(&source, "\tif signedLess(o%d, %s) { o%d = %s }\n",
			row, constant(parsed.offsetLower), row, constant(parsed.offsetLower))
		fmt.Fprintf(&source, "\tif signedLess(%s, o%d) { o%d = %s }\n",
			constant(parsed.offsetUpper), row, row, constant(parsed.offsetUpper))
		fmt.Fprintf(&source, "\tif !rowValid%d { w%d = %s(0) }\n", row, row, uintType)
		fmt.Fprintf(&source, "\teta%d := o%d\n", row, row)
		for j := 0; j < p; j++ {
			fmt.Fprintf(&source,
				"\teta%d = (eta%d + mulFloor(x%d_%d, beta%d)) & %s(0x%s)\n",
				row, row, row, j, j, uintType, mask)
		}
		fmt.Fprintf(&source, "\tif signedLess(eta%d, %s) { eta%d = %s }\n",
			row, constant(parsed.knots[0]), row, constant(parsed.knots[0]))
		fmt.Fprintf(&source, "\tif signedLess(%s, eta%d) { eta%d = %s }\n",
			constant(parsed.knots[len(parsed.knots)-1]), row, row,
			constant(parsed.knots[len(parsed.knots)-1]))
		fmt.Fprintf(&source, "\tknot%d := %s\n\tmuBase%d := %s\n\tslope%d := %s\n",
			row, constant(parsed.knots[0]), row, constant(parsed.values[0]),
			row, constant(parsed.slopes[0]))
		for segment := 1; segment < len(parsed.slopes); segment++ {
			fmt.Fprintf(&source, "\tif !signedLess(eta%d, %s) {\n",
				row, constant(parsed.knots[segment]))
			fmt.Fprintf(&source,
				"\t\tknot%d = %s\n\t\tmuBase%d = %s\n\t\tslope%d = %s\n\t}\n",
				row, constant(parsed.knots[segment]), row,
				constant(parsed.values[segment]), row, constant(parsed.slopes[segment]))
		}
		fmt.Fprintf(&source,
			"\tmu%d := (muBase%d + mulFloor(slope%d, (eta%d - knot%d) & %s(0x%s))) & %s(0x%s)\n",
			row, row, row, row, row, uintType, mask, uintType, mask)
		fmt.Fprintf(&source, "\tresidual%d := (mu%d - y%d) & %s(0x%s)\n",
			row, row, row, uintType, mask)
		fmt.Fprintf(&source, "\tweighted%d := mulFloor(w%d, residual%d)\n",
			row, row, row)
		for j := 0; j < p; j++ {
			fmt.Fprintf(&source,
				"\tgradient%d = (gradient%d + mulFloor(x%d_%d, weighted%d)) & %s(0x%s)\n",
				j, j, row, j, row, uintType, mask)
		}
	}
	maskStart := local
	for j := 0; j < p; j++ {
		fmt.Fprintf(&source, "\toutBeta%d := (beta%d - g[%d]) & %s(0x%s)\n",
			j, j, maskStart+j, uintType, mask)
		fmt.Fprintf(&source, "\toutGradient%d := (gradient%d - g[%d]) & %s(0x%s)\n",
			j, j, maskStart+p+j, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", 2*p, uintType)
	for j := 0; j < p; j++ {
		fmt.Fprintf(&source, "\tout[%d] = outBeta%d\n", j, j)
		fmt.Fprintf(&source, "\tout[%d] = outGradient%d\n", p+j, j)
	}
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func formalGLMPhase15FinalizeCircuitSource(plan formalGLMPhase15Plan) (string, error) {
	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil {
		return "", err
	}
	p := plan.Kernel.CoefficientCount
	local := 2 * p
	preamble, uintType, mask, constant := formalGLMPhase15CircuitPreamble(
		parsed, plan.RingBits)
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		local+p, uintType, local, uintType, p, uintType)
	for j := 0; j < p; j++ {
		fmt.Fprintf(&source, "\tbeta%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			j, j, j, uintType, mask)
		fmt.Fprintf(&source, "\tgradient%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			j, p+j, p+j, uintType, mask)
		fmt.Fprintf(&source, "\taverage%d := divFloor(gradient%d, %s(%d))\n",
			j, j, uintType, plan.TotalCapacity)
		fmt.Fprintf(&source, "\tridgeTerm%d := mulFloor(%s, beta%d)\n",
			j, constant(parsed.ridge[j]), j)
		fmt.Fprintf(&source, "\tfullGradient%d := (average%d + ridgeTerm%d) & %s(0x%s)\n",
			j, j, j, uintType, mask)
		fmt.Fprintf(&source, "\tstep%d := mulFloor(%s, fullGradient%d)\n",
			j, constant(parsed.alpha), j)
		fmt.Fprintf(&source, "\tnewBeta%d := (beta%d - step%d) & %s(0x%s)\n",
			j, j, j, uintType, mask)
		negativeBox := new(big.Int).Neg(new(big.Int).Set(parsed.box[j]))
		fmt.Fprintf(&source, "\tif signedLess(newBeta%d, %s) { newBeta%d = %s }\n",
			j, constant(negativeBox), j, constant(negativeBox))
		fmt.Fprintf(&source, "\tif signedLess(%s, newBeta%d) { newBeta%d = %s }\n",
			constant(parsed.box[j]), j, j, constant(parsed.box[j]))
		fmt.Fprintf(&source, "\tout%d := (newBeta%d - g[%d]) & %s(0x%s)\n",
			j, j, local+j, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", p, uintType)
	for j := 0; j < p; j++ {
		fmt.Fprintf(&source, "\tout[%d] = out%d\n", j, j)
	}
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func compileFormalGLMPhase15Block(plan formalGLMPhase15Plan) (*circuit.Circuit, error) {
	source, err := formalGLMPhase15BlockCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMPhase15Source(source, "stream block")
	if err != nil {
		return nil, err
	}
	p := plan.Kernel.CoefficientCount
	rows := plan.BlockCapacity * (p + 3)
	typeBits := exactGCTypeBits(plan.RingBits)
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		int(circ.Inputs[0].Type.Bits) != (rows+4*p)*typeBits ||
		int(circ.Inputs[1].Type.Bits) != (rows+2*p)*typeBits ||
		circ.Outputs.Size() != 2*p*typeBits {
		return nil, fmt.Errorf("formal-glm: compiler produced invalid stream-block arity")
	}
	return circ, nil
}

func compileFormalGLMPhase15Finalize(plan formalGLMPhase15Plan) (*circuit.Circuit, error) {
	source, err := formalGLMPhase15FinalizeCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMPhase15Source(source, "iteration finalizer")
	if err != nil {
		return nil, err
	}
	p := plan.Kernel.CoefficientCount
	typeBits := exactGCTypeBits(plan.RingBits)
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		int(circ.Inputs[0].Type.Bits) != 3*p*typeBits ||
		int(circ.Inputs[1].Type.Bits) != 2*p*typeBits ||
		circ.Outputs.Size() != p*typeBits {
		return nil, fmt.Errorf("formal-glm: compiler produced invalid finalizer arity")
	}
	return circ, nil
}

type formalGLMPhase15Step struct {
	Iteration  int
	BlockIndex int // -1 denotes the iteration finalizer.
	SourceRoot string
}

func formalGLMPhase15StepPurpose(plan formalGLMPhase15Plan,
	step formalGLMPhase15Step, attemptID [32]byte) (string, error) {

	digest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return "", err
	}
	phase := "finalize"
	index := 0
	if step.BlockIndex >= 0 {
		phase = "block"
		index = step.BlockIndex
		if !formalGLMIsSHA256(step.SourceRoot) {
			return "", fmt.Errorf("formal-glm: streamed block is missing its verified fan-in root")
		}
	} else if step.SourceRoot != "" {
		return "", fmt.Errorf("formal-glm: finalizer cannot bind a source block")
	}
	return fmt.Sprintf("formal-glm/phase15-v1/%s/i/%d/%s/%d/source/%s/attempt/%s",
		hex.EncodeToString(digest[:]), step.Iteration, phase, index,
		step.SourceRoot,
		hex.EncodeToString(attemptID[:])), nil
}

func formalGLMPhase15StepSession(plan formalGLMPhase15Plan,
	step formalGLMPhase15Step, attemptID, masterKey [32]byte) (exactGCSession, error) {

	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		return exactGCSession{}, err
	}
	if step.Iteration < 0 || step.Iteration >= plan.Iterations ||
		(step.BlockIndex < -1 || step.BlockIndex >= plan.TotalBlocks) {
		return exactGCSession{}, fmt.Errorf("formal-glm: invalid fixed-schedule step")
	}
	p := plan.Kernel.CoefficientCount
	vectorLen := 2 * p
	if step.BlockIndex >= 0 {
		vectorLen += plan.BlockCapacity * (p + 3)
	}
	purpose, err := formalGLMPhase15StepPurpose(plan, step, attemptID)
	if err != nil {
		return exactGCSession{}, err
	}
	session := exactGCSession{
		SessionID: attemptID, MasterKey: masterKey,
		GarblerID:   plan.Kernel.ComputePeers[0],
		EvaluatorID: plan.Kernel.ComputePeers[1], Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalGLMOneIteration,
			RingBits:  plan.RingBits, FracBits: plan.Kernel.FracBits,
			VectorLen: vectorLen,
		},
	}
	if err := session.validate(); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func validateFormalGLMPhase15StepSession(plan formalGLMPhase15Plan,
	step formalGLMPhase15Step, session exactGCSession) error {

	want, err := formalGLMPhase15StepSession(plan, step, session.SessionID,
		session.MasterKey)
	if err != nil {
		return err
	}
	if session.GarblerID != want.GarblerID ||
		session.EvaluatorID != want.EvaluatorID || session.Purpose != want.Purpose ||
		session.Spec.Operation != want.Spec.Operation ||
		session.Spec.RingBits != want.Spec.RingBits ||
		session.Spec.FracBits != want.Spec.FracBits ||
		session.Spec.VectorLen != want.Spec.VectorLen {
		return fmt.Errorf("formal-glm: Phase-1.5 step/session binding mismatch")
	}
	return nil
}

func formalGLMPhase15RunGarbler(rw io.ReadWriter, plan formalGLMPhase15Plan,
	step formalGLMPhase15Step, session exactGCSession,
	localShares []*big.Int) ([]*big.Int, error) {

	if err := validateFormalGLMPhase15StepSession(plan, step, session); err != nil {
		return nil, err
	}
	if rw == nil {
		return nil, fmt.Errorf("formal-glm: nil Phase-1.5 peer channel")
	}
	if err := exactGCValidateShares(localShares, session.Spec); err != nil {
		return nil, err
	}
	outputCount := plan.Kernel.CoefficientCount
	var circ *circuit.Circuit
	var err error
	if step.BlockIndex >= 0 {
		outputCount *= 2
		circ, err = compileFormalGLMPhase15Block(plan)
	} else {
		circ, err = compileFormalGLMPhase15Finalize(plan)
	}
	if err != nil {
		return nil, err
	}
	masks, err := formalGLMRandomMasks(outputCount, plan.RingBits)
	if err != nil {
		return nil, err
	}
	input := exactGCPackChunks(append(append([]*big.Int{}, localShares...), masks...),
		exactGCTypeBits(plan.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return masks, nil
}

func formalGLMPhase15RunEvaluator(rw io.ReadWriter, plan formalGLMPhase15Plan,
	step formalGLMPhase15Step, session exactGCSession,
	localShares []*big.Int) ([]*big.Int, error) {

	if err := validateFormalGLMPhase15StepSession(plan, step, session); err != nil {
		return nil, err
	}
	if rw == nil {
		return nil, fmt.Errorf("formal-glm: nil Phase-1.5 peer channel")
	}
	if err := exactGCValidateShares(localShares, session.Spec); err != nil {
		return nil, err
	}
	outputCount := plan.Kernel.CoefficientCount
	var circ *circuit.Circuit
	var err error
	if step.BlockIndex >= 0 {
		outputCount *= 2
		circ, err = compileFormalGLMPhase15Block(plan)
	} else {
		circ, err = compileFormalGLMPhase15Finalize(plan)
	}
	if err != nil {
		return nil, err
	}
	input := exactGCPackChunks(localShares, exactGCTypeBits(plan.RingBits))
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	packed, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	result := make([]*big.Int, outputCount)
	stride := exactGCTypeBits(plan.RingBits)
	for i := range result {
		result[i] = new(big.Int).Rsh(new(big.Int).Set(packed), uint(i*stride))
		result[i].And(result[i], exactGCMask(plan.RingBits))
	}
	return result, nil
}

func formalGLMPhase15ReferenceRow(parsed formalGLMParsedPolicy,
	row []*big.Int, beta, gradient []*big.Int, ringBits int) error {

	p := parsed.policy.CoefficientCount
	if len(row) != p+3 || len(beta) != p || len(gradient) != p {
		return fmt.Errorf("formal-glm: invalid streamed reference row shape")
	}
	values := make([]*big.Int, len(row))
	for i, value := range row {
		if value == nil || value.Sign() < 0 || value.Cmp(exactGCModulus(ringBits)) >= 0 {
			return fmt.Errorf("formal-glm: invalid streamed reference residue")
		}
		values[i] = exactGCReferenceSigned(value, ringBits)
	}
	weight := formalGLMClamp(values[0], big.NewInt(0), parsed.weightUpper)
	valid := true
	x := make([]*big.Int, p)
	for j := 0; j < p; j++ {
		x[j] = new(big.Int).Set(values[1+j])
		if formalGLMIndicatorKind(parsed.policy.XKind[j]) {
			if x[j].Sign() != 0 && x[j].Cmp(parsed.scale) != 0 {
				valid = false
				x[j].SetInt64(0)
			}
		} else {
			x[j] = formalGLMClamp(x[j], parsed.xLower[j], parsed.xUpper[j])
		}
	}
	y := new(big.Int).Set(values[p+1])
	if parsed.policy.Family == "binomial" {
		if y.Sign() != 0 && y.Cmp(parsed.scale) != 0 {
			valid = false
			y.SetInt64(0)
		}
	} else if new(big.Int).And(new(big.Int).Set(y),
		new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1))).Sign() != 0 {
		valid = false
		y.SetInt64(0)
	}
	y = formalGLMClamp(y, big.NewInt(0), parsed.outcomeUpper)
	offset := formalGLMClamp(values[p+2], parsed.offsetLower, parsed.offsetUpper)
	if !valid {
		weight.SetInt64(0)
	}
	eta := new(big.Int).Set(offset)
	for j := 0; j < p; j++ {
		boundedBeta := formalGLMClamp(beta[j],
			new(big.Int).Neg(new(big.Int).Set(parsed.box[j])), parsed.box[j])
		eta.Add(eta, formalGLMFloorMul(x[j], boundedBeta, parsed.scale))
	}
	eta = formalGLMClamp(eta, parsed.knots[0], parsed.knots[len(parsed.knots)-1])
	segment := 0
	for segment+1 < len(parsed.slopes) && eta.Cmp(parsed.knots[segment+1]) >= 0 {
		segment++
	}
	mu := new(big.Int).Add(parsed.values[segment], formalGLMFloorMul(
		parsed.slopes[segment], new(big.Int).Sub(eta, parsed.knots[segment]), parsed.scale))
	weighted := formalGLMFloorMul(weight, new(big.Int).Sub(mu, y), parsed.scale)
	for j := 0; j < p; j++ {
		gradient[j].Add(gradient[j], formalGLMFloorMul(x[j], weighted, parsed.scale))
	}
	return nil
}

// referenceFormalGLMPhase15 is independent of circuit compilation and block
// grouping.  It specifies the exact signed-floor lattice schedule for T>=1.
func referenceFormalGLMPhase15(plan formalGLMPhase15Plan,
	input []*big.Int) ([]*big.Int, error) {

	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil {
		return nil, err
	}
	p := plan.Kernel.CoefficientCount
	coordinates := p + 3
	if len(input) != plan.TotalCapacity*coordinates {
		return nil, fmt.Errorf("formal-glm: invalid complete streamed reference shape")
	}
	beta := make([]*big.Int, p)
	for j := range beta {
		beta[j] = new(big.Int).Set(parsed.betaStart[j])
	}
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		gradient := make([]*big.Int, p)
		for j := range gradient {
			gradient[j] = new(big.Int)
		}
		for row := 0; row < plan.TotalCapacity; row++ {
			if err := formalGLMPhase15ReferenceRow(parsed,
				input[row*coordinates:(row+1)*coordinates], beta,
				gradient, plan.RingBits); err != nil {
				return nil, err
			}
		}
		for j := 0; j < p; j++ {
			average, remainder := new(big.Int), new(big.Int)
			average.QuoRem(gradient[j], big.NewInt(int64(plan.TotalCapacity)), remainder)
			if gradient[j].Sign() < 0 && remainder.Sign() != 0 {
				average.Sub(average, big.NewInt(1))
			}
			fullGradient := average.Add(average,
				formalGLMFloorMul(parsed.ridge[j], beta[j], parsed.scale))
			candidate := new(big.Int).Sub(beta[j],
				formalGLMFloorMul(parsed.alpha, fullGradient, parsed.scale))
			beta[j] = formalGLMClamp(candidate,
				new(big.Int).Neg(new(big.Int).Set(parsed.box[j])), parsed.box[j])
		}
	}
	result := make([]*big.Int, p)
	for j := range result {
		result[j] = formalGLMResidue(beta[j], plan.RingBits)
	}
	return result, nil
}

// referenceFormalGLMPhase15Rational follows the same public clipped PWL
// optimizer without any fixed-point floors.  It is independent of both the
// integer oracle and compiler and is used to audit the signed rho certificate.
func referenceFormalGLMPhase15Rational(plan formalGLMPhase15Plan,
	input []*big.Int) ([]*big.Rat, error) {

	parsed, err := formalGLMPhase15ValidateShape(plan)
	if err != nil {
		return nil, err
	}
	p := plan.Kernel.CoefficientCount
	coordinates := p + 3
	if len(input) != plan.TotalCapacity*coordinates {
		return nil, fmt.Errorf("formal-glm: invalid rational stream shape")
	}
	integers := make([]*big.Int, len(input))
	for i, value := range input {
		if value == nil || value.Sign() < 0 ||
			value.Cmp(exactGCModulus(plan.RingBits)) >= 0 {
			return nil, fmt.Errorf("formal-glm: invalid rational stream residue")
		}
		integers[i] = exactGCReferenceSigned(value, plan.RingBits)
	}
	rat := func(value *big.Int) *big.Rat {
		return new(big.Rat).SetFrac(new(big.Int).Set(value),
			new(big.Int).Set(parsed.scale))
	}
	beta := make([]*big.Rat, p)
	for j := range beta {
		beta[j] = rat(parsed.betaStart[j])
	}
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		gradient := make([]*big.Rat, p)
		for j := range gradient {
			gradient[j] = new(big.Rat)
		}
		for row := 0; row < plan.TotalCapacity; row++ {
			base := row * coordinates
			weightInt := formalGLMClamp(integers[base], big.NewInt(0), parsed.weightUpper)
			valid := true
			xInt := make([]*big.Int, p)
			for j := 0; j < p; j++ {
				xInt[j] = new(big.Int).Set(integers[base+1+j])
				if formalGLMIndicatorKind(plan.Kernel.XKind[j]) {
					if xInt[j].Sign() != 0 && xInt[j].Cmp(parsed.scale) != 0 {
						valid = false
						xInt[j].SetInt64(0)
					}
				} else {
					xInt[j] = formalGLMClamp(xInt[j], parsed.xLower[j], parsed.xUpper[j])
				}
			}
			yInt := new(big.Int).Set(integers[base+p+1])
			if plan.Kernel.Family == "binomial" {
				if yInt.Sign() != 0 && yInt.Cmp(parsed.scale) != 0 {
					valid = false
					yInt.SetInt64(0)
				}
			} else if new(big.Int).And(new(big.Int).Set(yInt),
				new(big.Int).Sub(new(big.Int).Set(parsed.scale), big.NewInt(1))).Sign() != 0 {
				valid = false
				yInt.SetInt64(0)
			}
			yInt = formalGLMClamp(yInt, big.NewInt(0), parsed.outcomeUpper)
			offsetInt := formalGLMClamp(integers[base+p+2],
				parsed.offsetLower, parsed.offsetUpper)
			if !valid {
				weightInt.SetInt64(0)
			}
			eta := rat(offsetInt)
			for j := 0; j < p; j++ {
				eta.Add(eta, new(big.Rat).Mul(rat(xInt[j]), beta[j]))
			}
			lowerEta := rat(parsed.knots[0])
			upperEta := rat(parsed.knots[len(parsed.knots)-1])
			if eta.Cmp(lowerEta) < 0 {
				eta.Set(lowerEta)
			}
			if eta.Cmp(upperEta) > 0 {
				eta.Set(upperEta)
			}
			segment := 0
			for segment+1 < len(parsed.slopes) &&
				eta.Cmp(rat(parsed.knots[segment+1])) >= 0 {
				segment++
			}
			mu := new(big.Rat).Add(rat(parsed.values[segment]),
				new(big.Rat).Mul(rat(parsed.slopes[segment]),
					new(big.Rat).Sub(eta, rat(parsed.knots[segment]))))
			weighted := new(big.Rat).Mul(rat(weightInt),
				new(big.Rat).Sub(mu, rat(yInt)))
			for j := 0; j < p; j++ {
				gradient[j].Add(gradient[j],
					new(big.Rat).Mul(rat(xInt[j]), weighted))
			}
		}
		capacity := new(big.Rat).SetInt64(int64(plan.TotalCapacity))
		for j := 0; j < p; j++ {
			average := new(big.Rat).Quo(gradient[j], capacity)
			fullGradient := new(big.Rat).Add(average,
				new(big.Rat).Mul(rat(parsed.ridge[j]), beta[j]))
			candidate := new(big.Rat).Sub(beta[j],
				new(big.Rat).Mul(rat(parsed.alpha), fullGradient))
			lower := new(big.Rat).Neg(rat(parsed.box[j]))
			upper := rat(parsed.box[j])
			if candidate.Cmp(lower) < 0 {
				candidate.Set(lower)
			}
			if candidate.Cmp(upper) > 0 {
				candidate.Set(upper)
			}
			beta[j] = candidate
		}
	}
	return beta, nil
}
