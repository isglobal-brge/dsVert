package main

// Test-only constant folding for the cost probe. Complements use free XNOR
// gates, and duplicate Boolean expressions are shared. The production compiler
// and all existing circuits are untouched. This is not a security transform.
import "github.com/markkurossi/mpc/circuit"

type crossGridPWNode struct {
	op   circuit.Operation
	a, b int
}

func crossGridPWOptimize(c *circuit.Circuit) *circuit.Circuit {
	inputCount := c.Inputs.Size()
	nodes := make([]crossGridPWNode, inputCount+1)
	memo := make(map[crossGridPWNode]int)
	add := func(op circuit.Operation, a, b int) int {
		if a > b {
			a, b = b, a
		}
		key := crossGridPWNode{op, a, b}
		if id, ok := memo[key]; ok {
			return id
		}
		id := 2 * len(nodes)
		nodes = append(nodes, key)
		memo[key] = id
		return id
	}
	xor := func(a, b int) int {
		sign := (a ^ b) & 1
		a &^= 1
		b &^= 1
		if a == b {
			return sign
		}
		if a == 0 {
			return b ^ sign
		}
		if b == 0 {
			return a ^ sign
		}
		return add(circuit.XOR, a, b) ^ sign
	}
	and := func(a, b int) int {
		if a == 0 || b == 0 || a == b^1 {
			return 0
		}
		if a == 1 || a == b {
			return b
		}
		if b == 1 {
			return a
		}
		return add(circuit.AND, a, b)
	}
	wires := make([]int, c.NumWires)
	for i := 0; i < inputCount; i++ {
		wires[i] = 2 * (i + 1)
	}
	for _, g := range c.Gates {
		a, b := wires[g.Input0], wires[g.Input1]
		switch g.Op {
		case circuit.XOR:
			wires[g.Output] = xor(a, b)
		case circuit.XNOR:
			wires[g.Output] = xor(a, b) ^ 1
		case circuit.AND:
			wires[g.Output] = and(a, b)
		case circuit.OR:
			wires[g.Output] = and(a^1, b^1) ^ 1
		case circuit.INV:
			wires[g.Output] = a ^ 1
		default:
			panic("unsupported public circuit gate")
		}
	}
	outputs := wires[c.NumWires-c.Outputs.Size():]
	live := make([]bool, len(nodes))
	var mark func(int)
	mark = func(lit int) {
		id := lit / 2
		if id <= inputCount || live[id] {
			return
		}
		live[id] = true
		mark(nodes[id].a)
		mark(nodes[id].b)
	}
	for _, lit := range outputs {
		mark(lit)
	}
	out := &circuit.Circuit{Inputs: c.Inputs, Outputs: c.Outputs, NumWires: inputCount}
	emit := func(op circuit.Operation, a, b circuit.Wire) circuit.Wire {
		w := circuit.Wire(out.NumWires)
		out.NumWires++
		out.Gates = append(out.Gates, circuit.Gate{Op: op, Input0: a, Input1: b, Output: w})
		out.Stats[op]++
		return w
	}
	translated := make(map[int]circuit.Wire)
	for i := 0; i < inputCount; i++ {
		translated[2*(i+1)] = circuit.Wire(i)
	}
	zero := emit(circuit.XOR, 0, 0)
	translated[0] = zero
	var wire func(int) circuit.Wire
	wire = func(lit int) circuit.Wire {
		if w, ok := translated[lit]; ok {
			return w
		}
		if lit&1 == 0 {
			panic("public circuit order invalid")
		}
		w := emit(circuit.XNOR, translated[lit^1], zero)
		translated[lit] = w
		return w
	}
	for id, node := range nodes {
		if id <= inputCount || !live[id] {
			continue
		}
		translated[2*id] = emit(node.op, wire(node.a), wire(node.b))
	}
	// Resolve complements before emitting the contiguous output block.
	outputWires := make([]circuit.Wire, len(outputs))
	for i, lit := range outputs {
		outputWires[i] = wire(lit)
	}
	for _, w := range outputWires {
		emit(circuit.XOR, w, zero)
	}
	out.NumGates = len(out.Gates)
	return out
}
