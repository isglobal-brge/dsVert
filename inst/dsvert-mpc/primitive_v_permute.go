package main

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

// primitiveVPermutationCost describes the fixed, public Beneš topology. For
// N=2^ceil(log2(rows)), S=N*log2(N)-N/2 switches carry columns*width bits each.
// A conditional XOR swap ideally uses one AND and three XORs per carried bit.
// The pinned MPCL compiler's generic mux retains two additional XORs against
// zero, so this emitter's switch-only cost is one AND and five XORs per bit.
// Circuit-level constant setup and output copying are counted separately.
type primitiveVPermutationCost struct {
	PaddedRows  int
	Switches    int
	ControlBits int
	WordBits    int
	AndGates    uint64
	XorGates    uint64
}

func primitiveVPermutationShape(rows, columns, width int) (primitiveVPermutationCost, error) {
	if rows < 1 || rows > 1<<20 || columns < 1 || columns > 4096 ||
		width < 1 || width > exactGCMaxRingBits {
		return primitiveVPermutationCost{}, errors.New("primitive-v: invalid permutation shape")
	}
	levels := bits.Len(uint(rows - 1))
	n := 1 << uint(levels)
	switches := 0
	if n > 1 {
		switches = n*levels - n/2
	}
	and := uint64(switches) * uint64(columns) * uint64(width)
	return primitiveVPermutationCost{PaddedRows: n, Switches: switches,
		ControlBits: switches, WordBits: columns * width, AndGates: and,
		XorGates: 5 * and}, nil
}

// primitiveVPermutationControls runs only at the owner who knows the order.
// It realizes out[i]=in[permutation[i]], fixing each padded slot. Neither the
// permutation nor these bits may be placed in source, public context, or logs:
// only the fixed topology is public, and bits enter GC as that owner's input.
func primitiveVPermutationControls(permutation []int) ([]bool, error) {
	cost, err := primitiveVPermutationShape(len(permutation), 1, 1)
	if err != nil {
		return nil, errors.New("primitive-v: invalid permutation")
	}
	seen := make([]bool, len(permutation))
	padded := make([]int, cost.PaddedRows)
	for i, source := range permutation {
		if source < 0 || source >= len(permutation) || seen[source] {
			return nil, errors.New("primitive-v: invalid permutation")
		}
		seen[source] = true
		padded[i] = source
	}
	for i := len(permutation); i < len(padded); i++ {
		padded[i] = i
	}
	controls := make([]bool, 0, cost.ControlBits)
	primitiveVRouteBenes(padded, &controls)
	return controls, nil
}

// Two-color the degree-two input-pair/output-pair graph. Each color gets one
// edge at each input and output pair, hence defines a permutation for one
// half-sized subnet. Recursion proves every permutation can be routed.
func primitiveVRouteBenes(permutation []int, controls *[]bool) {
	n := len(permutation)
	if n == 1 {
		return
	}
	if n == 2 {
		*controls = append(*controls, permutation[0] == 1)
		return
	}
	destination := make([]int, n)
	color := make([]int8, n)
	for out, in := range permutation {
		destination[in] = out
		color[in] = -1
	}
	stack := make([]int, 0, n)
	for seed := 0; seed < n; seed++ {
		if color[seed] >= 0 {
			continue
		}
		color[seed] = 0
		stack = append(stack, seed)
		for len(stack) > 0 {
			in := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, neighbor := range [2]int{in ^ 1, permutation[destination[in]^1]} {
				if color[neighbor] < 0 {
					color[neighbor] = 1 - color[in]
					stack = append(stack, neighbor)
				}
			}
		}
	}
	upper, lower := make([]int, n/2), make([]int, n/2)
	for pair := 0; pair < n/2; pair++ {
		*controls = append(*controls, color[2*pair] == 1)
		for side := 0; side < 2; side++ {
			in := permutation[2*pair+side]
			if color[in] == 0 {
				upper[pair] = in / 2
			} else {
				lower[pair] = in / 2
			}
		}
	}
	primitiveVRouteBenes(upper, controls)
	primitiveVRouteBenes(lower, controls)
	for pair := 0; pair < n/2; pair++ {
		*controls = append(*controls, color[permutation[2*pair]] == 1)
	}
}

// primitiveVWalkBenes enumerates switches in exactly the control-routing
// order. base and stride represent the fixed interconnection of each subnet.
func primitiveVWalkBenes(n, base, stride int, visit func(int, int)) {
	if n == 1 {
		return
	}
	for i := 0; i < n/2; i++ {
		visit(base+2*i*stride, base+(2*i+1)*stride)
	}
	if n == 2 {
		return
	}
	primitiveVWalkBenes(n/2, base, 2*stride, visit)
	primitiveVWalkBenes(n/2, base+stride, 2*stride, visit)
	for i := 0; i < n/2; i++ {
		visit(base+2*i*stride, base+(2*i+1)*stride)
	}
}

func primitiveVPermutationIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, char := range value {
		if char != '_' && (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') && (i == 0 || char < '0' || char > '9') {
			return false
		}
	}
	return true
}

// primitiveVEmitPermutation appends MPCL statements inside a circuit function.
// valuesName must name a flattened [PaddedRows*columns] signed or unsigned
// width-bit word array; controlsName names a private [ControlBits]bool array.
// All columns of a row use the same control. The caller pads rows with zero
// words and must keep results as circuit wires or freshly masked shares.
// In particular, opening a reordered vector would disclose the private order.
// Reconstruction of additive shares can precede this emitter inside the GC;
// alternatively, carry both share columns and reconstruct after permutation.
func primitiveVEmitPermutation(b *strings.Builder, rows, columns, width int,
	valuesName, controlsName string) error {
	cost, err := primitiveVPermutationShape(rows, columns, width)
	if err != nil || b == nil || !primitiveVPermutationIdentifier(valuesName) ||
		!primitiveVPermutationIdentifier(controlsName) {
		return errors.New("primitive-v: invalid permutation circuit")
	}
	if cost.Switches == 0 {
		return nil
	}
	// Source position makes this local name unique when composing emitters.
	delta := fmt.Sprintf("pvPermuteDelta%d", b.Len())
	fmt.Fprintf(b, "%s := %s[0]\n", delta, valuesName)
	control := 0
	primitiveVWalkBenes(cost.PaddedRows, 0, 1, func(left, right int) {
		for column := 0; column < columns; column++ {
			a, z := left*columns+column, right*columns+column
			fmt.Fprintf(b, "%s = 0\n", delta)
			fmt.Fprintf(b, "if %s[%d] { %s = %s[%d] ^ %s[%d] }\n",
				controlsName, control, delta, valuesName, a, valuesName, z)
			fmt.Fprintf(b, "%s[%d] = %s[%d] ^ %s\n", valuesName, a, valuesName, a, delta)
			fmt.Fprintf(b, "%s[%d] = %s[%d] ^ %s\n", valuesName, z, valuesName, z, delta)
		}
		control++
	})
	return nil
}
