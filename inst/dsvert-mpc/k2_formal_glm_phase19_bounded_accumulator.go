package main

// Bounded Phase-1.9 execution-validity reduction.
//
// The original accumulator compiled one circuit whose typed inputs grew with
// TotalBlocks.  That is correct for small schedules but makes compiler memory
// and garbling cost peak at the full dataset shape.  This reducer keeps every
// circuit at a fixed public fan-in and carries two independently XOR-shared
// predicates through the tree:
//
//   1. every child share was canonical and every child was valid; and
//   2. at least one child was active.
//
// Keeping those predicates separate is essential.  Folding them at an
// intermediate node would let an invalid group disappear when another group
// contains an active row.  Only the final constant-size circuit computes
// allValid && anyActive.  No intermediate predicate is opened.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/p2p"
)

const formalGLMPhase19AccumulatorMaxFanIn = 64

type formalGLMPhase19AccumulatorStateShare struct {
	valid  byte
	active byte
}

func formalGLMPhase19AccumulatorLeafCircuitSource(count int) (string, error) {
	if count < 1 || count > formalGLMPhase19AccumulatorMaxFanIn {
		return "", fmt.Errorf("formal-glm: invalid bounded accumulator leaf shape")
	}
	var source strings.Builder
	fmt.Fprintf(&source,
		"package main\nfunc main(g [%d]uint8, e [%d]uint8) [2]uint8 {\n",
		count+2, count)
	source.WriteString("\tallValid := true\n\tanyActive := false\n")
	for index := 0; index < count; index++ {
		fmt.Fprintf(&source,
			"\tgValid%d := g[%d] == uint8(0) || g[%d] == uint8(1)\n",
			index, index, index)
		fmt.Fprintf(&source,
			"\teValid%d := e[%d] == uint8(0) || e[%d] == uint8(1)\n",
			index, index, index)
		fmt.Fprintf(&source,
			"\tallValid = allValid && gValid%d && eValid%d\n",
			index, index)
		fmt.Fprintf(&source,
			"\tanyActive = anyActive || (g[%d] != e[%d] && gValid%d && eValid%d)\n",
			index, index, index, index)
	}
	fmt.Fprintf(&source, "\tvalidMask := g[%d]\n", count)
	fmt.Fprintf(&source, "\tactiveMask := g[%d]\n", count+1)
	source.WriteString("\tvalidMaskOK := validMask == uint8(0) || validMask == uint8(1)\n")
	source.WriteString("\tactiveMaskOK := activeMask == uint8(0) || activeMask == uint8(1)\n")
	source.WriteString("\tvalidShare := uint8(0)\n\tactiveShare := uint8(0)\n")
	source.WriteString("\tif validMaskOK {\n\t\tvalidShare = validMask\n")
	source.WriteString("\t\tif allValid { validShare = uint8(1) - validMask }\n\t}\n")
	source.WriteString("\tif activeMaskOK {\n\t\tactiveShare = activeMask\n")
	source.WriteString("\t\tif allValid && anyActive { activeShare = uint8(1) - activeMask }\n\t}\n")
	source.WriteString("\tvar out [2]uint8\n\tout[0] = validShare\n\tout[1] = activeShare\n\treturn out\n}\n")
	return source.String(), nil
}

func formalGLMPhase19AccumulatorStateCircuitSource(count int) (string, error) {
	if count < 1 || count > formalGLMPhase19AccumulatorMaxFanIn {
		return "", fmt.Errorf("formal-glm: invalid bounded accumulator state shape")
	}
	var source strings.Builder
	fmt.Fprintf(&source,
		"package main\nfunc main(g [%d]uint8, e [%d]uint8) [2]uint8 {\n",
		2*count+2, 2*count)
	source.WriteString("\tallValid := true\n\tanyActive := false\n")
	for index := 0; index < count; index++ {
		valid := 2 * index
		active := valid + 1
		fmt.Fprintf(&source,
			"\tgvOK%d := g[%d] == uint8(0) || g[%d] == uint8(1)\n",
			index, valid, valid)
		fmt.Fprintf(&source,
			"\tevOK%d := e[%d] == uint8(0) || e[%d] == uint8(1)\n",
			index, valid, valid)
		fmt.Fprintf(&source,
			"\tgaOK%d := g[%d] == uint8(0) || g[%d] == uint8(1)\n",
			index, active, active)
		fmt.Fprintf(&source,
			"\teaOK%d := e[%d] == uint8(0) || e[%d] == uint8(1)\n",
			index, active, active)
		fmt.Fprintf(&source,
			"\twellFormed%d := gvOK%d && evOK%d && gaOK%d && eaOK%d\n",
			index, index, index, index, index)
		fmt.Fprintf(&source,
			"\titemValid%d := g[%d] != e[%d]\n", index, valid, valid)
		fmt.Fprintf(&source,
			"\titemActive%d := g[%d] != e[%d]\n", index, active, active)
		fmt.Fprintf(&source,
			"\tallValid = allValid && wellFormed%d && itemValid%d\n",
			index, index)
		fmt.Fprintf(&source,
			"\tanyActive = anyActive || (wellFormed%d && itemActive%d)\n",
			index, index)
	}
	fmt.Fprintf(&source, "\tvalidMask := g[%d]\n", 2*count)
	fmt.Fprintf(&source, "\tactiveMask := g[%d]\n", 2*count+1)
	source.WriteString("\tvalidMaskOK := validMask == uint8(0) || validMask == uint8(1)\n")
	source.WriteString("\tactiveMaskOK := activeMask == uint8(0) || activeMask == uint8(1)\n")
	source.WriteString("\tvalidShare := uint8(0)\n\tactiveShare := uint8(0)\n")
	source.WriteString("\tif validMaskOK {\n\t\tvalidShare = validMask\n")
	source.WriteString("\t\tif allValid { validShare = uint8(1) - validMask }\n\t}\n")
	source.WriteString("\tif activeMaskOK {\n\t\tactiveShare = activeMask\n")
	source.WriteString("\t\tif anyActive { activeShare = uint8(1) - activeMask }\n\t}\n")
	source.WriteString("\tvar out [2]uint8\n\tout[0] = validShare\n\tout[1] = activeShare\n\treturn out\n}\n")
	return source.String(), nil
}

func formalGLMPhase19AccumulatorFinalCircuitSource() string {
	return "package main\n" +
		"func main(g [3]uint8, e [2]uint8) [1]uint8 {\n" +
		"\tgvOK := g[0] == uint8(0) || g[0] == uint8(1)\n" +
		"\tevOK := e[0] == uint8(0) || e[0] == uint8(1)\n" +
		"\tgaOK := g[1] == uint8(0) || g[1] == uint8(1)\n" +
		"\teaOK := e[1] == uint8(0) || e[1] == uint8(1)\n" +
		"\tmask := g[2]\n" +
		"\tmaskOK := mask == uint8(0) || mask == uint8(1)\n" +
		"\texecutionValid := gvOK && evOK && gaOK && eaOK && " +
		"(g[0] != e[0]) && (g[1] != e[1])\n" +
		"\toutShare := uint8(0)\n" +
		"\tif maskOK {\n\t\toutShare = mask\n" +
		"\t\tif executionValid { outShare = uint8(1) - mask }\n\t}\n" +
		"\tvar out [1]uint8\n\tout[0] = outShare\n\treturn out\n}\n"
}

func compileFormalGLMPhase19BoundedAccumulator(
	kind string, count int) (*circuit.Circuit, error) {
	var source string
	var err error
	garblerBytes, evaluatorBytes, outputBits := 0, 0, 0
	switch kind {
	case "leaf":
		source, err = formalGLMPhase19AccumulatorLeafCircuitSource(count)
		garblerBytes, evaluatorBytes, outputBits = count+2, count, 16
	case "state":
		source, err = formalGLMPhase19AccumulatorStateCircuitSource(count)
		garblerBytes, evaluatorBytes, outputBits = 2*count+2, 2*count, 16
	case "final":
		if count != 1 {
			return nil, fmt.Errorf("formal-glm: invalid bounded accumulator final shape")
		}
		source = formalGLMPhase19AccumulatorFinalCircuitSource()
		garblerBytes, evaluatorBytes, outputBits = 3, 2, 8
	default:
		return nil, fmt.Errorf("formal-glm: invalid bounded accumulator circuit kind")
	}
	if err != nil {
		return nil, err
	}
	circ, err := compileFormalGLMPhase15Source(
		source, "Phase-1.9 bounded execution accumulator")
	if err != nil {
		return nil, err
	}
	if len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		int(circ.Inputs[0].Type.Bits) != garblerBytes*8 ||
		int(circ.Inputs[1].Type.Bits) != evaluatorBytes*8 ||
		circ.Outputs.Size() != outputBits {
		return nil, fmt.Errorf("formal-glm: compiler produced invalid bounded accumulator arity")
	}
	return circ, nil
}

func formalGLMPhase19BoundedAccumulatorSession(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan, attempt [32]byte,
	kind string, level, group, count int, masterKey [32]byte) (
	exactGCSession, error) {
	if !accumulator.verified || !formalGLMIsSHA256(accumulator.AccumulatorRoot) ||
		(kind != "leaf" && kind != "state" && kind != "final") ||
		level < 0 || group < 0 || count < 1 ||
		count > formalGLMPhase19AccumulatorMaxFanIn {
		return exactGCSession{}, fmt.Errorf("formal-glm: invalid bounded accumulator session")
	}
	message := formalGLMPhase15AppendString(nil,
		formalGLMPhase19ExecDomain+"/bounded-session/v1")
	message = append(message, attempt[:]...)
	message = formalGLMPhase15AppendString(message, accumulator.AccumulatorRoot)
	message = formalGLMPhase15AppendString(message, kind)
	message = formalGLMPhase15AppendUint64(message, uint64(level))
	message = formalGLMPhase15AppendUint64(message, uint64(group))
	message = formalGLMPhase15AppendUint64(message, uint64(count))
	sessionID := sha256.Sum256(message)
	purpose := fmt.Sprintf(
		"formal-glm/phase19-v2/execution-bounded/%s/root/%s/attempt/%s/kind/%s/level/%d/group/%d/count/%d",
		accumulator.ContextSHA256, accumulator.AccumulatorRoot,
		hex.EncodeToString(attempt[:]), kind, level, group, count)
	session := exactGCSession{
		SessionID: sessionID, MasterKey: masterKey,
		GarblerID: ctx.ComputePeers[0], EvaluatorID: ctx.ComputePeers[1],
		Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalGLMOneIteration,
			RingBits:  plan.RingBits, FracBits: plan.Kernel.FracBits,
			VectorLen: count,
		},
	}
	if err := session.validate(); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func formalGLMPhase19BoundedAccumulatorRunCircuit(
	rw io.ReadWriter, role string, circ *circuit.Circuit,
	session exactGCSession, values []*big.Int) (*big.Int, error) {
	if rw == nil || (role != "garbler" && role != "evaluator") {
		return nil, fmt.Errorf("formal-glm: invalid bounded accumulator peer")
	}
	defer exactGCZeroBigInts(values)
	secureRole := exactGCRoleGarbler
	if role == "evaluator" {
		secureRole = exactGCRoleEvaluator
	}
	secure, err := newExactGCSecureRecordRW(rw, session, secureRole)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	if role == "garbler" {
		protocolErr := exactGCGarblerProtocol(
			conn, circ, exactGCPackChunks(values, 8), session)
		return nil, exactGCFinishConn(conn, rw, protocolErr)
	}
	packed, protocolErr := exactGCEvaluatorProtocol(
		conn, circ, exactGCPackChunks(values, 8), session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return packed, nil
}

func formalGLMPhase19BoundedAccumulatorDecodeState(
	packed *big.Int) (formalGLMPhase19AccumulatorStateShare, error) {
	if packed == nil || packed.Sign() < 0 || new(big.Int).Rsh(
		new(big.Int).Set(packed), 16).Sign() != 0 {
		return formalGLMPhase19AccumulatorStateShare{},
			fmt.Errorf("formal-glm: bounded accumulator emitted invalid state")
	}
	low := new(big.Int).And(new(big.Int).Set(packed), big.NewInt(255))
	high := new(big.Int).And(
		new(big.Int).Rsh(new(big.Int).Set(packed), 8), big.NewInt(255))
	if low.Cmp(big.NewInt(1)) > 0 || high.Cmp(big.NewInt(1)) > 0 {
		return formalGLMPhase19AccumulatorStateShare{},
			fmt.Errorf("formal-glm: bounded accumulator emitted non-bit state")
	}
	return formalGLMPhase19AccumulatorStateShare{
		valid: byte(low.Uint64()), active: byte(high.Uint64()),
	}, nil
}

func formalGLMPhase19RunBoundedAccumulatorTree(
	rw io.ReadWriter, plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan, attempt [32]byte,
	role string, rawShares []byte, backendKey [32]byte) (
	formalGLMPhase19ExecutionSeal, error) {

	var zero formalGLMPhase19ExecutionSeal
	if rw == nil || len(rawShares) < 1 || len(rawShares) != ctx.TotalBlocks ||
		(role != "garbler" && role != "evaluator") ||
		!formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: invalid bounded accumulator schedule")
	}
	type circuitKey struct {
		kind  string
		count int
	}
	compiled := make(map[circuitKey]*circuit.Circuit)
	getCircuit := func(kind string, count int) (*circuit.Circuit, error) {
		key := circuitKey{kind: kind, count: count}
		if value := compiled[key]; value != nil {
			return value, nil
		}
		value, err := compileFormalGLMPhase19BoundedAccumulator(kind, count)
		if err == nil {
			compiled[key] = value
		}
		return value, err
	}
	runState := func(kind string, level, group int, input []byte) (
		formalGLMPhase19AccumulatorStateShare, error) {
		count := len(input)
		if kind == "state" {
			if count < 2 || count%2 != 0 {
				return formalGLMPhase19AccumulatorStateShare{},
					fmt.Errorf("formal-glm: invalid bounded accumulator state input")
			}
			count /= 2
		}
		circ, err := getCircuit(kind, count)
		if err != nil {
			return formalGLMPhase19AccumulatorStateShare{}, err
		}
		session, err := formalGLMPhase19BoundedAccumulatorSession(
			plan, ctx, accumulator, attempt, kind, level, group, count,
			backendKey)
		if err != nil {
			return formalGLMPhase19AccumulatorStateShare{}, err
		}
		values := make([]*big.Int, 0, len(input)+2)
		for _, value := range input {
			values = append(values, new(big.Int).SetUint64(uint64(value)))
		}
		if role == "garbler" {
			validMask, maskErr := formalGLMPhase19RandomExecutionMask()
			if maskErr != nil {
				exactGCZeroBigInts(values)
				return formalGLMPhase19AccumulatorStateShare{}, maskErr
			}
			activeMask, maskErr := formalGLMPhase19RandomExecutionMask()
			if maskErr != nil {
				exactGCZeroBigInts(values)
				return formalGLMPhase19AccumulatorStateShare{}, maskErr
			}
			values = append(values,
				new(big.Int).SetUint64(uint64(validMask)),
				new(big.Int).SetUint64(uint64(activeMask)))
			if _, err := formalGLMPhase19BoundedAccumulatorRunCircuit(
				rw, role, circ, session, values); err != nil {
				return formalGLMPhase19AccumulatorStateShare{}, err
			}
			return formalGLMPhase19AccumulatorStateShare{
				valid: validMask, active: activeMask,
			}, nil
		}
		packed, err := formalGLMPhase19BoundedAccumulatorRunCircuit(
			rw, role, circ, session, values)
		if err != nil {
			return formalGLMPhase19AccumulatorStateShare{}, err
		}
		return formalGLMPhase19BoundedAccumulatorDecodeState(packed)
	}

	states := make([]formalGLMPhase19AccumulatorStateShare, 0,
		(len(rawShares)+formalGLMPhase19AccumulatorMaxFanIn-1)/
			formalGLMPhase19AccumulatorMaxFanIn)
	for start, group := 0, 0; start < len(rawShares); group++ {
		end := start + formalGLMPhase19AccumulatorMaxFanIn
		if end > len(rawShares) {
			end = len(rawShares)
		}
		state, err := runState("leaf", 0, group, rawShares[start:end])
		if err != nil {
			return zero, err
		}
		states = append(states, state)
		start = end
	}
	for level := 1; len(states) > 1; level++ {
		next := make([]formalGLMPhase19AccumulatorStateShare, 0,
			(len(states)+formalGLMPhase19AccumulatorMaxFanIn-1)/
				formalGLMPhase19AccumulatorMaxFanIn)
		for start, group := 0, 0; start < len(states); group++ {
			end := start + formalGLMPhase19AccumulatorMaxFanIn
			if end > len(states) {
				end = len(states)
			}
			encoded := make([]byte, 0, 2*(end-start))
			for _, state := range states[start:end] {
				encoded = append(encoded, state.valid, state.active)
			}
			state, err := runState("state", level, group, encoded)
			clear(encoded)
			if err != nil {
				return zero, err
			}
			next = append(next, state)
			start = end
		}
		clear(states)
		states = next
	}

	finalCircuit, err := getCircuit("final", 1)
	if err != nil {
		return zero, err
	}
	finalSession, err := formalGLMPhase19BoundedAccumulatorSession(
		plan, ctx, accumulator, attempt, "final", 0, 0, 1, backendKey)
	if err != nil {
		return zero, err
	}
	values := []*big.Int{
		new(big.Int).SetUint64(uint64(states[0].valid)),
		new(big.Int).SetUint64(uint64(states[0].active)),
	}
	var share byte
	if role == "garbler" {
		share, err = formalGLMPhase19RandomExecutionMask()
		if err != nil {
			exactGCZeroBigInts(values)
			return zero, err
		}
		values = append(values, new(big.Int).SetUint64(uint64(share)))
		_, err = formalGLMPhase19BoundedAccumulatorRunCircuit(
			rw, role, finalCircuit, finalSession, values)
	} else {
		var packed *big.Int
		packed, err = formalGLMPhase19BoundedAccumulatorRunCircuit(
			rw, role, finalCircuit, finalSession, values)
		if err == nil && (packed == nil || packed.Sign() < 0 ||
			packed.Cmp(big.NewInt(1)) > 0) {
			err = fmt.Errorf("formal-glm: bounded accumulator emitted invalid execution share")
		}
		if err == nil {
			share = byte(packed.Uint64())
		}
	}
	clear(states)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase19BuildExecutionSeal(
		ctx, accumulator, finalSession, func() string {
			if role == "garbler" {
				return ctx.ComputePeers[0]
			}
			return ctx.ComputePeers[1]
		}(), share, backendKey)
}

func formalGLMPhase19RunBoundedAccumulatorGarbler(
	rw io.ReadWriter, plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	pairs []formalGLMPhase19MaskedBlockReceiptPair,
	blocks []formalGLMPhase19MaskedBlock, attempt [32]byte,
	backendKey [32]byte) (formalGLMPhase19ExecutionSeal, error) {
	if err := formalGLMPhase19VerifyAccumulatorPlan(
		ctx, accumulator, backendKey); err != nil {
		return formalGLMPhase19ExecutionSeal{}, err
	}
	shares, err := formalGLMPhase19AccumulatorLocalShares(
		plan, ctx, accumulator, pairs, blocks, ctx.ComputePeers[0], backendKey)
	if err != nil {
		return formalGLMPhase19ExecutionSeal{}, err
	}
	defer clear(shares)
	return formalGLMPhase19RunBoundedAccumulatorTree(
		rw, plan, ctx, accumulator, attempt, "garbler", shares, backendKey)
}

func formalGLMPhase19RunBoundedAccumulatorEvaluator(
	rw io.ReadWriter, plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	pairs []formalGLMPhase19MaskedBlockReceiptPair,
	blocks []formalGLMPhase19MaskedBlock, attempt [32]byte,
	backendKey [32]byte) (formalGLMPhase19ExecutionSeal, error) {
	if err := formalGLMPhase19VerifyAccumulatorPlan(
		ctx, accumulator, backendKey); err != nil {
		return formalGLMPhase19ExecutionSeal{}, err
	}
	shares, err := formalGLMPhase19AccumulatorLocalShares(
		plan, ctx, accumulator, pairs, blocks, ctx.ComputePeers[1], backendKey)
	if err != nil {
		return formalGLMPhase19ExecutionSeal{}, err
	}
	defer clear(shares)
	return formalGLMPhase19RunBoundedAccumulatorTree(
		rw, plan, ctx, accumulator, attempt, "evaluator", shares, backendKey)
}
