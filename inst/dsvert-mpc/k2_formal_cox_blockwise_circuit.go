package main

// Purpose-bound exact circuits for one Cox row block and one iteration
// finalizer.  Both circuits consume and emit only shares.  Their public shape
// depends on the signed policy and physical block size, never on protected row
// contents.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/markkurossi/mpc/circuit"
)

type formalCoxBlockwiseOffsets struct {
	beta, riskCount, eventCount, s0, s1, eventX, total int
}

func formalCoxBlockwiseStateOffsets(policy formalCoxPhase1Policy) formalCoxBlockwiseOffsets {
	p, g := policy.CovariateCount, policy.GridTickCount
	o := formalCoxBlockwiseOffsets{beta: 0}
	o.riskCount = p
	o.eventCount = o.riskCount + g
	o.s0 = o.eventCount + g
	o.s1 = o.s0 + g
	o.eventX = o.s1 + g*p
	o.total = o.eventX + g*p
	return o
}

func formalCoxBlockwiseCircuitPreamble(parsed formalCoxParsedPolicy,
	ringBits int) (string, string, string, string, func(*big.Int) string) {

	typeBits := exactGCTypeBits(ringBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	wideType := fmt.Sprintf("uint%d", 2*typeBits)
	mask := exactGCMask(ringBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(ringBits-1)).Text(16)
	fracMask := new(big.Int).Sub(
		new(big.Int).Set(parsed.scale), big.NewInt(1)).Text(16)
	constant := func(value *big.Int) string {
		return fmt.Sprintf("%s(0x%s)", uintType, formalCoxHex(value, ringBits))
	}
	var source strings.Builder
	fmt.Fprintf(&source, `package main
func signedLess(a %[1]s, b %[1]s) bool {
	aNeg := (a & %[1]s(0x%[2]s)) != 0
	bNeg := (b & %[1]s(0x%[2]s)) != 0
	if aNeg != bNeg { return aNeg }
	return a < b
}
func mulFloor(a %[1]s, b %[1]s) %[1]s {
	aNeg := (a & %[1]s(0x%[2]s)) != 0
	bNeg := (b & %[1]s(0x%[2]s)) != 0
	aMag := a
	bMag := b
	if aNeg { aMag = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	if bNeg { bMag = (%[1]s(0) - b) & %[1]s(0x%[3]s) }
	product := wideMul(aMag, bMag)
	quotient := product >> %[4]d
	remainder := product & %[5]s(0x%[6]s)
	negative := aNeg != bNeg
	if negative && remainder != 0 { quotient = quotient + 1 }
	result := %[1]s(quotient)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
`, uintType, sign, mask, parsed.policy.FracBits, wideType, fracMask)
	return source.String(), uintType, wideType, mask, constant
}

func formalCoxBlockwiseEmitRing128Input(source *strings.Builder,
	name string, index, ringBits int, uintType, mask string) {

	if ringBits == 128 {
		fmt.Fprintf(source, "\t%s := (g[%d] + e[%d]) & %s(0x%s)\n",
			name, index, index, uintType, mask)
		return
	}
	fmt.Fprintf(source, "\t%sLow128 := uint128(g[%d]) + uint128(e[%d])\n",
		name, index, index)
	fmt.Fprintf(source,
		"\texecutionValid = executionValid && (g[%d] >> 128) == 0 && (e[%d] >> 128) == 0\n",
		index, index)
	fmt.Fprintf(source, "\t%s := %s(%sLow128)\n", name, uintType, name)
	highMask := new(big.Int).Xor(exactGCMask(ringBits), exactGCMask(128))
	fmt.Fprintf(source,
		"\tif (%sLow128 & uint128(0x80000000000000000000000000000000)) != 0 { %s = %s | %s(0x%s) }\n",
		name, name, name, uintType, highMask.Text(16))
}

func formalCoxBlockwiseBlockCircuitSource(plan formalCoxBlockwisePlan) (string, error) {
	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return "", err
	}
	policy := plan.Policy
	p, g, k, block := policy.CovariateCount, policy.GridTickCount,
		len(policy.CustodianPeers), plan.BlockCapacity
	offsets := formalCoxBlockwiseStateOffsets(policy)
	if offsets.total != plan.StateArithmetic {
		return "", fmt.Errorf("formal-cox: blockwise state layout mismatch")
	}
	rowCoordinates := block * plan.RowWidth
	local := rowCoordinates + plan.StateCoordinates
	preamble, uintType, wideType, mask, constant :=
		formalCoxBlockwiseCircuitPreamble(parsed, plan.RingBits)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(plan.RingBits-1)).Text(16)
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		local+plan.StateCoordinates, uintType, local, uintType,
		plan.StateCoordinates, uintType)
	validityIndex := rowCoordinates + plan.StateArithmetic
	fmt.Fprintf(&source,
		"\texecutionValid := (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		validityIndex, validityIndex, uintType, uintType)
	for index := 0; index < plan.StateArithmetic; index++ {
		input := rowCoordinates + index
		fmt.Fprintf(&source,
			"\tstate%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			index, input, input, uintType, mask)
	}
	// A state forged outside the signed beta ball cannot influence the next
	// block.  Normal chained state is already projected by the finalizer.
	fmt.Fprintf(&source, "\tstateBetaNormSquared := %s(0)\n", wideType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tstateBetaMagnitude%d := state%d\n",
			coefficient, offsets.beta+coefficient)
		fmt.Fprintf(&source,
			"\tif (state%d & %s(0x%s)) != 0 { stateBetaMagnitude%d = (%s(0) - state%d) & %s(0x%s) }\n",
			offsets.beta+coefficient, uintType, sign, coefficient, uintType,
			offsets.beta+coefficient, uintType, mask)
		fmt.Fprintf(&source,
			"\tstateBetaNormSquared = stateBetaNormSquared + wideMul(stateBetaMagnitude%d, stateBetaMagnitude%d)\n",
			coefficient, coefficient)
	}
	betaBoundSquared := new(big.Int).Mul(
		new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	fmt.Fprintf(&source,
		"\tstateBetaValid := stateBetaNormSquared <= %s(0x%s)\n",
		wideType, betaBoundSquared.Text(16))
	source.WriteString("\texecutionValid = executionValid && stateBetaValid\n")
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tif !stateBetaValid { state%d = %s(0) }\n",
			offsets.beta+coefficient, uintType)
	}

	xNormSquaredBound := new(big.Int).Mul(
		new(big.Int).Set(parsed.xNorm), parsed.xNorm)
	for row := 0; row < block; row++ {
		base := row * plan.RowWidth
		fmt.Fprintf(&source, "\trowValid%d := true\n", row)
		for peer := 0; peer < k; peer++ {
			formalCoxBlockwiseEmitRing128Input(
				&source, fmt.Sprintf("validity%d_%d", row, peer),
				base+peer, plan.RingBits, uintType, mask)
			fmt.Fprintf(&source,
				"\trowValid%d = rowValid%d && validity%d_%d == %s(1)\n",
				row, row, row, peer, uintType)
		}
		entryIndex, stopIndex, statusIndex := base+k, base+k+1, base+k+2
		formalCoxBlockwiseEmitRing128Input(
			&source, fmt.Sprintf("entry%d", row), entryIndex,
			plan.RingBits, uintType, mask)
		formalCoxBlockwiseEmitRing128Input(
			&source, fmt.Sprintf("stop%d", row), stopIndex,
			plan.RingBits, uintType, mask)
		formalCoxBlockwiseEmitRing128Input(
			&source, fmt.Sprintf("status%d", row), statusIndex,
			plan.RingBits, uintType, mask)
		fmt.Fprintf(&source,
			"\tresponseValid%d := entry%d < %s(%d) && stop%d >= %s(1) && stop%d <= %s(%d) && entry%d < stop%d && (status%d == %s(0) || status%d == %s(1))\n",
			row, row, uintType, g, row, uintType, row, uintType, g,
			row, row, row, uintType, row, uintType)
		if policy.EntryMode == "none" {
			fmt.Fprintf(&source,
				"\tresponseValid%d = responseValid%d && entry%d == %s(0)\n",
				row, row, row, uintType)
		}
		fmt.Fprintf(&source, "\trowValid%d = rowValid%d && responseValid%d\n",
			row, row, row)
		fmt.Fprintf(&source, "\txNormSquared%d := %s(0)\n", row, wideType)
		for coefficient := 0; coefficient < p; coefficient++ {
			index := base + k + 3 + coefficient
			formalCoxBlockwiseEmitRing128Input(
				&source, fmt.Sprintf("x%d_%d", row, coefficient), index,
				plan.RingBits, uintType, mask)
			fmt.Fprintf(&source,
				"\txValid%d_%d := !signedLess(x%d_%d, %s) && !signedLess(%s, x%d_%d)\n",
				row, coefficient, row, coefficient,
				constant(parsed.xLower[coefficient]),
				constant(parsed.xUpper[coefficient]), row, coefficient)
			fmt.Fprintf(&source,
				"\trowValid%d = rowValid%d && xValid%d_%d\n",
				row, row, row, coefficient)
			fmt.Fprintf(&source, "\txMagnitude%d_%d := x%d_%d\n",
				row, coefficient, row, coefficient)
			fmt.Fprintf(&source,
				"\tif (x%d_%d & %s(0x%s)) != 0 { xMagnitude%d_%d = (%s(0) - x%d_%d) & %s(0x%s) }\n",
				row, coefficient, uintType, sign, row, coefficient,
				uintType, row, coefficient, uintType, mask)
			fmt.Fprintf(&source,
				"\txNormSquared%d = xNormSquared%d + wideMul(xMagnitude%d_%d, xMagnitude%d_%d)\n",
				row, row, row, coefficient, row, coefficient)
		}
		fmt.Fprintf(&source,
			"\trowValid%d = rowValid%d && xNormSquared%d <= %s(0x%s)\n",
			row, row, row, wideType, xNormSquaredBound.Text(16))
		fmt.Fprintf(&source, "\tif !rowValid%d {\n", row)
		fmt.Fprintf(&source,
			"\t\tentry%d = %s(0)\n\t\tstop%d = %s(1)\n\t\tstatus%d = %s(0)\n",
			row, uintType, row, uintType, row, uintType)
		for coefficient := 0; coefficient < p; coefficient++ {
			fmt.Fprintf(&source, "\t\tx%d_%d = %s(0)\n",
				row, coefficient, uintType)
		}
		source.WriteString("\t}\n")
		fmt.Fprintf(&source, "\teta%d := %s(0)\n", row, uintType)
		for coefficient := 0; coefficient < p; coefficient++ {
			fmt.Fprintf(&source,
				"\teta%d = (eta%d + mulFloor(x%d_%d, state%d)) & %s(0x%s)\n",
				row, row, row, coefficient, offsets.beta+coefficient,
				uintType, mask)
		}
		fmt.Fprintf(&source,
			"\tetaValid%d := !signedLess(eta%d, %s) && !signedLess(%s, eta%d)\n",
			row, row, constant(parsed.expKnots[0]),
			constant(parsed.expKnots[len(parsed.expKnots)-1]), row)
		fmt.Fprintf(&source, "\texecutionValid = executionValid && etaValid%d\n", row)
		fmt.Fprintf(&source, "\tif signedLess(eta%d, %s) { eta%d = %s }\n",
			row, constant(parsed.expKnots[0]), row, constant(parsed.expKnots[0]))
		fmt.Fprintf(&source, "\tif signedLess(%s, eta%d) { eta%d = %s }\n",
			constant(parsed.expKnots[len(parsed.expKnots)-1]), row, row,
			constant(parsed.expKnots[len(parsed.expKnots)-1]))
		fmt.Fprintf(&source, "\tweight%d := %s\n", row,
			constant(parsed.expValues[0]))
		for segment := 1; segment < len(parsed.expValues); segment++ {
			fmt.Fprintf(&source,
				"\tif !signedLess(eta%d, %s) { weight%d = %s }\n",
				row, constant(parsed.expKnots[segment]), row,
				constant(parsed.expValues[segment]))
		}
		for coefficient := 0; coefficient < p; coefficient++ {
			fmt.Fprintf(&source,
				"\tweightedX%d_%d := mulFloor(weight%d, x%d_%d)\n",
				row, coefficient, row, row, coefficient)
		}
	}

	for grid := 1; grid <= g; grid++ {
		for row := 0; row < block; row++ {
			fmt.Fprintf(&source,
				"\tatRisk%d_%d := rowValid%d && entry%d < %s(%d) && stop%d >= %s(%d)\n",
				grid, row, row, row, uintType, grid, row, uintType, grid)
			fmt.Fprintf(&source,
				"\tevent%d_%d := rowValid%d && status%d == %s(1) && stop%d == %s(%d)\n",
				grid, row, row, row, uintType, row, uintType, grid)
			fmt.Fprintf(&source, "\tif atRisk%d_%d {\n", grid, row)
			fmt.Fprintf(&source, "\t\tstate%d = state%d + %s(1)\n",
				offsets.riskCount+grid-1, offsets.riskCount+grid-1, uintType)
			fmt.Fprintf(&source,
				"\t\tstate%d = (state%d + weight%d) & %s(0x%s)\n",
				offsets.s0+grid-1, offsets.s0+grid-1, row, uintType, mask)
			for coefficient := 0; coefficient < p; coefficient++ {
				index := offsets.s1 + (grid-1)*p + coefficient
				fmt.Fprintf(&source,
					"\t\tstate%d = (state%d + weightedX%d_%d) & %s(0x%s)\n",
					index, index, row, coefficient, uintType, mask)
			}
			source.WriteString("\t}\n")
			fmt.Fprintf(&source, "\tif event%d_%d {\n", grid, row)
			fmt.Fprintf(&source, "\t\tstate%d = state%d + %s(1)\n",
				offsets.eventCount+grid-1, offsets.eventCount+grid-1, uintType)
			for coefficient := 0; coefficient < p; coefficient++ {
				index := offsets.eventX + (grid-1)*p + coefficient
				fmt.Fprintf(&source,
					"\t\tstate%d = (state%d + x%d_%d) & %s(0x%s)\n",
					index, index, row, coefficient, uintType, mask)
			}
			source.WriteString("\t}\n")
		}
	}
	maskStart := local
	for index := 0; index < plan.StateArithmetic; index++ {
		fmt.Fprintf(&source,
			"\tout%d := (state%d - g[%d]) & %s(0x%s)\n",
			index, index, maskStart+index, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", plan.StateCoordinates, uintType)
	for index := 0; index < plan.StateArithmetic; index++ {
		fmt.Fprintf(&source, "\tout[%d] = out%d\n", index, index)
	}
	fmt.Fprintf(&source, "\texecutionValue := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\tif executionValid { executionValue = %s(1) }\n",
		uintType)
	fmt.Fprintf(&source, "\tout[%d] = (executionValue + (g[%d] & %s(1))) & %s(1)\n",
		plan.StateArithmetic, maskStart+plan.StateArithmetic, uintType, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func formalCoxBlockwiseGridCircuitSource(plan formalCoxBlockwisePlan) (string, error) {
	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return "", err
	}
	p := plan.Policy.CovariateCount
	// risk count, event count, S0, S1[p], event-X[p], score[p], validity.
	local := 3 + 3*p + 1
	preamble, uintType, wideType, mask, _ :=
		formalCoxBlockwiseCircuitPreamble(parsed, plan.RingBits)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(plan.RingBits-1)).Text(16)
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, `func divScaledFloor(a %[1]s, denominator %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	numerator := wideMul(magnitude, %[1]s(0x%[4]s))
	wideDenominator := %[5]s(denominator)
	quotient := numerator / wideDenominator
	remainder := numerator %% wideDenominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	result := %[1]s(quotient)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
func mulInteger(a %[1]s, integer %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	product := wideMul(magnitude, integer)
	result := %[1]s(product)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
`, uintType, sign, mask, parsed.scale.Text(16), wideType)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		local+p+1, uintType, local, uintType, p+1, uintType)
	for index := 0; index < local-1; index++ {
		fmt.Fprintf(&source, "\tvalue%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			index, index, index, uintType, mask)
	}
	validityIndex := local - 1
	fmt.Fprintf(&source,
		"\texecutionValid := (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		validityIndex, validityIndex, uintType, uintType)
	fmt.Fprintf(&source,
		"\triskFloorValid := value1 == %s(0) || value0 >= %s(%d)\n",
		uintType, uintType, plan.Policy.MinimumAtRisk)
	source.WriteString("\texecutionValid = executionValid && riskFloorValid\n")
	source.WriteString("\tdenominator := value2\n")
	fmt.Fprintf(&source,
		"\tif denominator == %s(0) { denominator = %s(1) }\n",
		uintType, uintType)
	maskStart := local
	for coefficient := 0; coefficient < p; coefficient++ {
		s1 := 3 + coefficient
		eventX := 3 + p + coefficient
		score := 3 + 2*p + coefficient
		fmt.Fprintf(&source,
			"\tmean%d := divScaledFloor(value%d, denominator)\n",
			coefficient, s1)
		fmt.Fprintf(&source,
			"\triskTerm%d := mulInteger(mean%d, value1)\n",
			coefficient, coefficient)
		fmt.Fprintf(&source,
			"\tnewScore%d := (value%d + value%d - riskTerm%d) & %s(0x%s)\n",
			coefficient, score, eventX, coefficient, uintType, mask)
		fmt.Fprintf(&source,
			"\toutScore%d := (newScore%d - g[%d]) & %s(0x%s)\n",
			coefficient, coefficient, maskStart+coefficient, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", p+1, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tout[%d] = outScore%d\n", coefficient, coefficient)
	}
	fmt.Fprintf(&source, "\texecutionValue := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\tif executionValid { executionValue = %s(1) }\n",
		uintType)
	fmt.Fprintf(&source, "\tout[%d] = (executionValue + (g[%d] & %s(1))) & %s(1)\n",
		p, maskStart+p, uintType, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func formalCoxBlockwiseGridCoefficientCircuitSource(plan formalCoxBlockwisePlan) (string, error) {
	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return "", err
	}
	// risk count, event count, S0, one S1, one event-X, score, validity.
	const local = 7
	preamble, uintType, wideType, mask, _ :=
		formalCoxBlockwiseCircuitPreamble(parsed, plan.RingBits)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(plan.RingBits-1)).Text(16)
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, `func divScaledFloor(a %[1]s, denominator %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	numerator := wideMul(magnitude, %[1]s(0x%[4]s))
	wideDenominator := %[5]s(denominator)
	quotient := numerator / wideDenominator
	remainder := numerator %% wideDenominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	result := %[1]s(quotient)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
func mulInteger(a %[1]s, integer %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	product := wideMul(magnitude, integer)
	result := %[1]s(product)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
`, uintType, sign, mask, parsed.scale.Text(16), wideType)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [2]%s {\n",
		local+2, uintType, local, uintType, uintType)
	for index := 0; index < 6; index++ {
		fmt.Fprintf(&source, "\tvalue%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			index, index, index, uintType, mask)
	}
	fmt.Fprintf(&source,
		"\texecutionValid := (((g[6] + e[6]) & %s(1)) == %s(1))\n",
		uintType, uintType)
	fmt.Fprintf(&source,
		"\triskFloorValid := value1 == %s(0) || value0 >= %s(%d)\n",
		uintType, uintType, plan.Policy.MinimumAtRisk)
	source.WriteString("\texecutionValid = executionValid && riskFloorValid\n")
	source.WriteString("\tdenominator := value2\n")
	fmt.Fprintf(&source,
		"\tif denominator == %s(0) { denominator = %s(1) }\n", uintType, uintType)
	source.WriteString("\tmean := divScaledFloor(value3, denominator)\n")
	source.WriteString("\triskTerm := mulInteger(mean, value1)\n")
	fmt.Fprintf(&source,
		"\tnewScore := (value5 + value4 - riskTerm) & %s(0x%s)\n",
		uintType, mask)
	fmt.Fprintf(&source,
		"\toutScore := (newScore - g[7]) & %s(0x%s)\n", uintType, mask)
	fmt.Fprintf(&source, "\texecutionValue := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\tif executionValid { executionValue = %s(1) }\n",
		uintType)
	fmt.Fprintf(&source,
		"\toutValidity := (executionValue + (g[8] & %s(1))) & %s(1)\n",
		uintType, uintType)
	source.WriteString("\tvar out [2]" + uintType + "\n")
	source.WriteString("\tout[0] = outScore\n\tout[1] = outValidity\n")
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func formalCoxBlockwiseFinalizeCircuitSource(plan formalCoxBlockwisePlan) (string, error) {
	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return "", err
	}
	p := plan.Policy.CovariateCount
	// beta[p], reduced score[p], noise[p], execution validity, noise validity.
	local := 3*p + 2
	preamble, uintType, wideType, mask, constant :=
		formalCoxBlockwiseCircuitPreamble(parsed, plan.RingBits)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(plan.RingBits-1)).Text(16)
	projectionRoot, ok := new(big.Int).SetString(plan.ProjectionRootUpper, 10)
	if !ok || projectionRoot.Sign() <= 0 {
		return "", fmt.Errorf("formal-cox: invalid blockwise projection root")
	}
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, `func divFloorInteger(a %[1]s, denominator %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	quotient := magnitude / denominator
	remainder := magnitude %% denominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	if negative { quotient = (%[1]s(0) - quotient) & %[1]s(0x%[3]s) }
	return quotient
}
func projectTowardZero(a %[1]s, bound %[1]s, denominator %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	product := wideMul(magnitude, bound)
	quotient := product / %[4]s(denominator)
	result := %[1]s(quotient)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
`, uintType, sign, mask, wideType)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		local+p+1, uintType, local, uintType, p+1, uintType)
	fmt.Fprintf(&source,
		"\texecutionValid := (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		3*p, 3*p, uintType, uintType)
	fmt.Fprintf(&source,
		"\texecutionValid = executionValid && (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		3*p+1, 3*p+1, uintType, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tbeta%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			coefficient, coefficient, coefficient, uintType, mask)
		fmt.Fprintf(&source, "\tscore%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			coefficient, p+coefficient, p+coefficient, uintType, mask)
		formalCoxBlockwiseEmitRing128Input(&source,
			fmt.Sprintf("noise%d", coefficient), 2*p+coefficient,
			plan.RingBits, uintType, mask)
		negativeBound := new(big.Int).Neg(new(big.Int).Set(parsed.noiseBound))
		fmt.Fprintf(&source,
			"\tnoiseValid%d := !signedLess(noise%d, %s) && !signedLess(%s, noise%d)\n",
			coefficient, coefficient, constant(negativeBound),
			constant(parsed.noiseBound), coefficient)
		fmt.Fprintf(&source, "\texecutionValid = executionValid && noiseValid%d\n",
			coefficient)
		fmt.Fprintf(&source, "\tif !noiseValid%d { noise%d = %s(0) }\n",
			coefficient, coefficient, uintType)
	}
	fmt.Fprintf(&source, "\tinputBetaNormSquared := %s(0)\n", wideType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tinputBetaMagnitude%d := beta%d\n",
			coefficient, coefficient)
		fmt.Fprintf(&source,
			"\tif (beta%d & %s(0x%s)) != 0 { inputBetaMagnitude%d = (%s(0) - beta%d) & %s(0x%s) }\n",
			coefficient, uintType, sign, coefficient, uintType, coefficient,
			uintType, mask)
		fmt.Fprintf(&source,
			"\tinputBetaNormSquared = inputBetaNormSquared + wideMul(inputBetaMagnitude%d, inputBetaMagnitude%d)\n",
			coefficient, coefficient)
	}
	betaBoundSquared := new(big.Int).Mul(
		new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	fmt.Fprintf(&source, "\tinputBetaValid := inputBetaNormSquared <= %s(0x%s)\n",
		wideType, betaBoundSquared.Text(16))
	source.WriteString("\texecutionValid = executionValid && inputBetaValid\n")
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tif !inputBetaValid { beta%d = %s(0) }\n",
			coefficient, uintType)
		if plan.TotalCapacity == 1 {
			fmt.Fprintf(&source, "\taverage%d := score%d\n", coefficient, coefficient)
		} else {
			fmt.Fprintf(&source,
				"\taverage%d := divFloorInteger(score%d, %s(%d))\n",
				coefficient, coefficient, uintType, plan.TotalCapacity)
		}
		fmt.Fprintf(&source, "\tridge%d := mulFloor(%s, beta%d)\n",
			coefficient, constant(parsed.ridge), coefficient)
		fmt.Fprintf(&source,
			"\tgradient%d := (average%d - ridge%d + noise%d) & %s(0x%s)\n",
			coefficient, coefficient, coefficient, coefficient, uintType, mask)
		fmt.Fprintf(&source, "\tstep%d := mulFloor(%s, gradient%d)\n",
			coefficient, constant(parsed.alpha), coefficient)
		fmt.Fprintf(&source, "\tcandidate%d := (beta%d + step%d) & %s(0x%s)\n",
			coefficient, coefficient, coefficient, uintType, mask)
	}
	fmt.Fprintf(&source, "\tbetaNormSquared := %s(0)\n", wideType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tcandidateMagnitude%d := candidate%d\n",
			coefficient, coefficient)
		fmt.Fprintf(&source,
			"\tif (candidate%d & %s(0x%s)) != 0 { candidateMagnitude%d = (%s(0) - candidate%d) & %s(0x%s) }\n",
			coefficient, uintType, sign, coefficient, uintType, coefficient,
			uintType, mask)
		fmt.Fprintf(&source,
			"\tbetaNormSquared = betaNormSquared + wideMul(candidateMagnitude%d, candidateMagnitude%d)\n",
			coefficient, coefficient)
	}
	fmt.Fprintf(&source, "\toutsideBall := betaNormSquared > %s(0x%s)\n",
		wideType, betaBoundSquared.Text(16))
	fmt.Fprintf(&source, "\trootLow := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\trootHigh := %s(0x%s)\n",
		uintType, projectionRoot.Text(16))
	firstRootMid := new(big.Int).Rsh(new(big.Int).Set(projectionRoot), 1)
	firstRootSquare := new(big.Int).Mul(new(big.Int).Set(firstRootMid), firstRootMid)
	fmt.Fprintf(&source, "\trootLess0 := %s(0x%s) < betaNormSquared\n",
		wideType, firstRootSquare.Text(16))
	fmt.Fprintf(&source, "\tif rootLess0 { rootLow = %s(0x%s) }\n",
		uintType, new(big.Int).Add(new(big.Int).Set(firstRootMid), big.NewInt(1)).Text(16))
	fmt.Fprintf(&source, "\tif !rootLess0 { rootHigh = %s(0x%s) }\n",
		uintType, firstRootMid.Text(16))
	for search := 1; search < plan.ProjectionSearchSteps; search++ {
		fmt.Fprintf(&source, "\trootMid%d := rootLow + ((rootHigh - rootLow) >> 1)\n",
			search)
		fmt.Fprintf(&source, "\trootSquare%d := wideMul(rootMid%d, rootMid%d)\n",
			search, search, search)
		fmt.Fprintf(&source, "\trootLess%d := rootSquare%d < betaNormSquared\n",
			search, search)
		fmt.Fprintf(&source, "\tnextRootLow%d := rootLow\n", search)
		fmt.Fprintf(&source, "\tnextRootHigh%d := rootHigh\n", search)
		fmt.Fprintf(&source,
			"\tif rootLess%d { nextRootLow%d = rootMid%d + %s(1) }\n",
			search, search, search, uintType)
		fmt.Fprintf(&source,
			"\tif !rootLess%d { nextRootHigh%d = rootMid%d }\n",
			search, search, search)
		fmt.Fprintf(&source, "\trootLow = nextRootLow%d\n", search)
		fmt.Fprintf(&source, "\trootHigh = nextRootHigh%d\n", search)
	}
	source.WriteString("\tprojectionDenominator := rootLow\n")
	fmt.Fprintf(&source,
		"\tif projectionDenominator == %s(0) { projectionDenominator = %s(1) }\n",
		uintType, uintType)
	maskStart := local
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tnewBeta%d := candidate%d\n", coefficient, coefficient)
		fmt.Fprintf(&source,
			"\tif outsideBall { newBeta%d = projectTowardZero(candidate%d, %s, projectionDenominator) }\n",
			coefficient, coefficient, constant(parsed.betaNorm))
		fmt.Fprintf(&source, "\tif !executionValid { newBeta%d = %s(0) }\n",
			coefficient, uintType)
		fmt.Fprintf(&source,
			"\toutBeta%d := (newBeta%d - g[%d]) & %s(0x%s)\n",
			coefficient, coefficient, maskStart+coefficient, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", p+1, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tout[%d] = outBeta%d\n", coefficient, coefficient)
	}
	fmt.Fprintf(&source, "\texecutionValue := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\tif executionValid { executionValue = %s(1) }\n",
		uintType)
	fmt.Fprintf(&source, "\tout[%d] = (executionValue + (g[%d] & %s(1))) & %s(1)\n",
		p, maskStart+p, uintType, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func formalCoxBlockwiseUpdateCircuitSource(plan formalCoxBlockwisePlan) (string, error) {
	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return "", err
	}
	p := plan.Policy.CovariateCount
	// beta[p], score[p], noise[p], execution validity, noise validity.
	local := 3*p + 2
	preamble, uintType, wideType, mask, constant :=
		formalCoxBlockwiseCircuitPreamble(parsed, plan.RingBits)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(plan.RingBits-1)).Text(16)
	var source strings.Builder
	source.WriteString(preamble)
	reciprocal := new(big.Int).Quo(
		new(big.Int).Lsh(big.NewInt(1), uint(plan.ContainerBits)),
		big.NewInt(int64(plan.TotalCapacity)))
	fmt.Fprintf(&source, `func divFloorCapacity(a %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	product := wideMul(magnitude, %[1]s(0x%[4]s))
	quotient := %[1]s(product >> %[5]d)
	remainder := %[6]s(magnitude) - wideMul(quotient, %[1]s(%[7]d))
	if remainder >= %[6]s(%[7]d) {
		quotient = quotient + 1
		remainder = remainder - %[6]s(%[7]d)
	}
	if negative && remainder != 0 { quotient = quotient + 1 }
	if negative { quotient = (%[1]s(0) - quotient) & %[1]s(0x%[3]s) }
	return quotient
}
`, uintType, sign, mask, reciprocal.Text(16), plan.ContainerBits,
		wideType, plan.TotalCapacity)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		local+p+1, uintType, local, uintType, p+1, uintType)
	fmt.Fprintf(&source,
		"\texecutionValid := (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		3*p, 3*p, uintType, uintType)
	fmt.Fprintf(&source,
		"\texecutionValid = executionValid && (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		3*p+1, 3*p+1, uintType, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tbeta%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			coefficient, coefficient, coefficient, uintType, mask)
		fmt.Fprintf(&source, "\tscore%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			coefficient, p+coefficient, p+coefficient, uintType, mask)
		formalCoxBlockwiseEmitRing128Input(&source,
			fmt.Sprintf("noise%d", coefficient), 2*p+coefficient,
			plan.RingBits, uintType, mask)
		negativeBound := new(big.Int).Neg(new(big.Int).Set(parsed.noiseBound))
		fmt.Fprintf(&source,
			"\tnoiseValid%d := !signedLess(noise%d, %s) && !signedLess(%s, noise%d)\n",
			coefficient, coefficient, constant(negativeBound),
			constant(parsed.noiseBound), coefficient)
		fmt.Fprintf(&source, "\texecutionValid = executionValid && noiseValid%d\n",
			coefficient)
		fmt.Fprintf(&source, "\tif !noiseValid%d { noise%d = %s(0) }\n",
			coefficient, coefficient, uintType)
	}
	fmt.Fprintf(&source, "\tinputBetaNormSquared := %s(0)\n", wideType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tinputBetaMagnitude%d := beta%d\n", coefficient, coefficient)
		fmt.Fprintf(&source,
			"\tif (beta%d & %s(0x%s)) != 0 { inputBetaMagnitude%d = (%s(0) - beta%d) & %s(0x%s) }\n",
			coefficient, uintType, sign, coefficient, uintType, coefficient, uintType, mask)
		fmt.Fprintf(&source,
			"\tinputBetaNormSquared = inputBetaNormSquared + wideMul(inputBetaMagnitude%d, inputBetaMagnitude%d)\n",
			coefficient, coefficient)
	}
	betaBoundSquared := new(big.Int).Mul(new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	fmt.Fprintf(&source, "\tinputBetaValid := inputBetaNormSquared <= %s(0x%s)\n",
		wideType, betaBoundSquared.Text(16))
	source.WriteString("\texecutionValid = executionValid && inputBetaValid\n")
	maskStart := local
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tif !inputBetaValid { beta%d = %s(0) }\n",
			coefficient, uintType)
		if plan.TotalCapacity == 1 {
			fmt.Fprintf(&source, "\taverage%d := score%d\n", coefficient, coefficient)
		} else {
			fmt.Fprintf(&source,
				"\taverage%d := divFloorCapacity(score%d)\n",
				coefficient, coefficient)
		}
		fmt.Fprintf(&source, "\tridge%d := mulFloor(%s, beta%d)\n",
			coefficient, constant(parsed.ridge), coefficient)
		fmt.Fprintf(&source,
			"\tgradient%d := (average%d - ridge%d + noise%d) & %s(0x%s)\n",
			coefficient, coefficient, coefficient, coefficient, uintType, mask)
		fmt.Fprintf(&source, "\tstep%d := mulFloor(%s, gradient%d)\n",
			coefficient, constant(parsed.alpha), coefficient)
		fmt.Fprintf(&source, "\tcandidate%d := (beta%d + step%d) & %s(0x%s)\n",
			coefficient, coefficient, coefficient, uintType, mask)
		fmt.Fprintf(&source, "\tif !executionValid { candidate%d = %s(0) }\n",
			coefficient, uintType)
		fmt.Fprintf(&source,
			"\toutCandidate%d := (candidate%d - g[%d]) & %s(0x%s)\n",
			coefficient, coefficient, maskStart+coefficient, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", p+1, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tout[%d] = outCandidate%d\n", coefficient, coefficient)
	}
	fmt.Fprintf(&source, "\texecutionValue := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\tif executionValid { executionValue = %s(1) }\n", uintType)
	fmt.Fprintf(&source, "\tout[%d] = (executionValue + (g[%d] & %s(1))) & %s(1)\n",
		p, maskStart+p, uintType, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func formalCoxBlockwiseProjectionCoefficientCircuitSource(
	plan formalCoxBlockwisePlan, selectedCoefficient int) (string, error) {
	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return "", err
	}
	p := plan.Policy.CovariateCount
	if selectedCoefficient < 0 || selectedCoefficient >= p {
		return "", fmt.Errorf("formal-cox: invalid projection coefficient")
	}
	local := p + 1
	preamble, uintType, wideType, mask, constant :=
		formalCoxBlockwiseCircuitPreamble(parsed, plan.RingBits)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(plan.RingBits-1)).Text(16)
	projectionRoot, ok := new(big.Int).SetString(plan.ProjectionRootUpper, 10)
	if !ok || projectionRoot.Sign() <= 0 {
		return "", fmt.Errorf("formal-cox: invalid blockwise projection root")
	}
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, `func projectTowardZero(a %[1]s, bound %[1]s, denominator %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	product := wideMul(magnitude, bound)
	quotient := product / %[4]s(denominator)
	result := %[1]s(quotient)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
`, uintType, sign, mask, wideType)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [2]%s {\n",
		local+2, uintType, local, uintType, uintType)
	fmt.Fprintf(&source,
		"\texecutionValid := (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		p, p, uintType, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tcandidate%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			coefficient, coefficient, coefficient, uintType, mask)
	}
	fmt.Fprintf(&source, "\tbetaNormSquared := %s(0)\n", wideType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tcandidateMagnitude%d := candidate%d\n", coefficient, coefficient)
		fmt.Fprintf(&source,
			"\tif (candidate%d & %s(0x%s)) != 0 { candidateMagnitude%d = (%s(0) - candidate%d) & %s(0x%s) }\n",
			coefficient, uintType, sign, coefficient, uintType, coefficient, uintType, mask)
		fmt.Fprintf(&source,
			"\tbetaNormSquared = betaNormSquared + wideMul(candidateMagnitude%d, candidateMagnitude%d)\n",
			coefficient, coefficient)
	}
	betaBoundSquared := new(big.Int).Mul(new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	fmt.Fprintf(&source, "\toutsideBall := betaNormSquared > %s(0x%s)\n",
		wideType, betaBoundSquared.Text(16))
	fmt.Fprintf(&source, "\trootLow := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\trootHigh := %s(0x%s)\n", uintType, projectionRoot.Text(16))
	firstRootMid := new(big.Int).Rsh(new(big.Int).Set(projectionRoot), 1)
	firstRootSquare := new(big.Int).Mul(new(big.Int).Set(firstRootMid), firstRootMid)
	fmt.Fprintf(&source, "\trootLess0 := %s(0x%s) < betaNormSquared\n",
		wideType, firstRootSquare.Text(16))
	fmt.Fprintf(&source, "\tif rootLess0 { rootLow = %s(0x%s) }\n",
		uintType, new(big.Int).Add(new(big.Int).Set(firstRootMid), big.NewInt(1)).Text(16))
	fmt.Fprintf(&source, "\tif !rootLess0 { rootHigh = %s(0x%s) }\n",
		uintType, firstRootMid.Text(16))
	for search := 1; search < plan.ProjectionSearchSteps; search++ {
		fmt.Fprintf(&source, "\trootMid%d := rootLow + ((rootHigh - rootLow) >> 1)\n", search)
		fmt.Fprintf(&source, "\trootSquare%d := wideMul(rootMid%d, rootMid%d)\n",
			search, search, search)
		fmt.Fprintf(&source, "\trootLess%d := rootSquare%d < betaNormSquared\n", search, search)
		fmt.Fprintf(&source, "\tnextRootLow%d := rootLow\n", search)
		fmt.Fprintf(&source, "\tnextRootHigh%d := rootHigh\n", search)
		fmt.Fprintf(&source, "\tif rootLess%d { nextRootLow%d = rootMid%d + %s(1) }\n",
			search, search, search, uintType)
		fmt.Fprintf(&source, "\tif !rootLess%d { nextRootHigh%d = rootMid%d }\n",
			search, search, search)
		fmt.Fprintf(&source, "\trootLow = nextRootLow%d\n", search)
		fmt.Fprintf(&source, "\trootHigh = nextRootHigh%d\n", search)
	}
	source.WriteString("\tprojectionDenominator := rootLow\n")
	fmt.Fprintf(&source, "\tif projectionDenominator == %s(0) { projectionDenominator = %s(1) }\n",
		uintType, uintType)
	maskStart := local
	fmt.Fprintf(&source, "\tbeta := candidate%d\n", selectedCoefficient)
	fmt.Fprintf(&source,
		"\tif outsideBall { beta = projectTowardZero(candidate%d, %s, projectionDenominator) }\n",
		selectedCoefficient, constant(parsed.betaNorm))
	fmt.Fprintf(&source, "\tif !executionValid { beta = %s(0) }\n", uintType)
	fmt.Fprintf(&source, "\toutBeta := (beta - g[%d]) & %s(0x%s)\n",
		maskStart, uintType, mask)
	fmt.Fprintf(&source, "\tvar out [2]%s\n", uintType)
	source.WriteString("\tout[0] = outBeta\n")
	fmt.Fprintf(&source, "\texecutionValue := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\tif executionValid { executionValue = %s(1) }\n", uintType)
	fmt.Fprintf(&source, "\tout[1] = (executionValue + (g[%d] & %s(1))) & %s(1)\n",
		maskStart+1, uintType, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

func formalCoxBlockwiseMonolithicFinalizeCircuitSource(plan formalCoxBlockwisePlan) (string, error) {
	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return "", err
	}
	policy := plan.Policy
	p, g := policy.CovariateCount, policy.GridTickCount
	offsets := formalCoxBlockwiseStateOffsets(policy)
	local := plan.StateCoordinates + p + 1
	preamble, uintType, wideType, mask, constant :=
		formalCoxBlockwiseCircuitPreamble(parsed, plan.RingBits)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(plan.RingBits-1)).Text(16)
	projectionRoot, ok := new(big.Int).SetString(plan.ProjectionRootUpper, 10)
	if !ok || projectionRoot.Sign() <= 0 {
		return "", fmt.Errorf("formal-cox: invalid blockwise projection root")
	}
	var source strings.Builder
	source.WriteString(preamble)
	fmt.Fprintf(&source, `func divFloorInteger(a %[1]s, denominator %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	quotient := magnitude / denominator
	remainder := magnitude %% denominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	if negative { quotient = (%[1]s(0) - quotient) & %[1]s(0x%[3]s) }
	return quotient
}
func divScaledFloor(a %[1]s, denominator %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	numerator := wideMul(magnitude, %[1]s(0x%[4]s))
	wideDenominator := %[5]s(denominator)
	quotient := numerator / wideDenominator
	remainder := numerator %% wideDenominator
	if negative && remainder != 0 { quotient = quotient + 1 }
	result := %[1]s(quotient)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
func mulInteger(a %[1]s, integer %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	product := wideMul(magnitude, integer)
	result := %[1]s(product)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
func projectTowardZero(a %[1]s, bound %[1]s, denominator %[1]s) %[1]s {
	negative := (a & %[1]s(0x%[2]s)) != 0
	magnitude := a
	if negative { magnitude = (%[1]s(0) - a) & %[1]s(0x%[3]s) }
	product := wideMul(magnitude, bound)
	quotient := product / %[5]s(denominator)
	result := %[1]s(quotient)
	if negative { result = (%[1]s(0) - result) & %[1]s(0x%[3]s) }
	return result
}
`, uintType, sign, mask, parsed.scale.Text(16), wideType)
	fmt.Fprintf(&source, "func main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		local+p+1, uintType, local, uintType, p+1, uintType)
	fmt.Fprintf(&source,
		"\texecutionValid := (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		plan.StateArithmetic, plan.StateArithmetic, uintType, uintType)
	for index := 0; index < plan.StateArithmetic; index++ {
		fmt.Fprintf(&source,
			"\tstate%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			index, index, index, uintType, mask)
	}
	noiseStart := plan.StateCoordinates
	for coefficient := 0; coefficient < p; coefficient++ {
		formalCoxBlockwiseEmitRing128Input(
			&source, fmt.Sprintf("noise%d", coefficient), noiseStart+coefficient,
			plan.RingBits, uintType, mask)
		negativeBound := new(big.Int).Neg(new(big.Int).Set(parsed.noiseBound))
		fmt.Fprintf(&source,
			"\tnoiseValid%d := !signedLess(noise%d, %s) && !signedLess(%s, noise%d)\n",
			coefficient, coefficient, constant(negativeBound),
			constant(parsed.noiseBound), coefficient)
		fmt.Fprintf(&source,
			"\texecutionValid = executionValid && noiseValid%d\n", coefficient)
		fmt.Fprintf(&source, "\tif !noiseValid%d { noise%d = %s(0) }\n",
			coefficient, coefficient, uintType)
	}
	noiseValidity := noiseStart + p
	fmt.Fprintf(&source,
		"\texecutionValid = executionValid && (((g[%d] + e[%d]) & %s(1)) == %s(1))\n",
		noiseValidity, noiseValidity, uintType, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tscore%d := %s(0)\n", coefficient, uintType)
	}
	for grid := 1; grid <= g; grid++ {
		risk := offsets.riskCount + grid - 1
		events := offsets.eventCount + grid - 1
		s0 := offsets.s0 + grid - 1
		fmt.Fprintf(&source,
			"\triskFloorValid%d := state%d == %s(0) || state%d >= %s(%d)\n",
			grid, events, uintType, risk, uintType, policy.MinimumAtRisk)
		fmt.Fprintf(&source,
			"\texecutionValid = executionValid && riskFloorValid%d\n", grid)
		fmt.Fprintf(&source, "\tdenominator%d := state%d\n", grid, s0)
		fmt.Fprintf(&source,
			"\tif denominator%d == %s(0) { denominator%d = %s(1) }\n",
			grid, uintType, grid, uintType)
		for coefficient := 0; coefficient < p; coefficient++ {
			s1 := offsets.s1 + (grid-1)*p + coefficient
			eventX := offsets.eventX + (grid-1)*p + coefficient
			fmt.Fprintf(&source,
				"\tmean%d_%d := divScaledFloor(state%d, denominator%d)\n",
				grid, coefficient, s1, grid)
			fmt.Fprintf(&source,
				"\triskTerm%d_%d := mulInteger(mean%d_%d, state%d)\n",
				grid, coefficient, grid, coefficient, events)
			fmt.Fprintf(&source,
				"\tscore%d = (score%d + state%d - riskTerm%d_%d) & %s(0x%s)\n",
				coefficient, coefficient, eventX, grid, coefficient,
				uintType, mask)
		}
	}
	for coefficient := 0; coefficient < p; coefficient++ {
		if plan.TotalCapacity == 1 {
			fmt.Fprintf(&source, "\taverage%d := score%d\n", coefficient, coefficient)
		} else {
			fmt.Fprintf(&source,
				"\taverage%d := divFloorInteger(score%d, %s(%d))\n",
				coefficient, coefficient, uintType, plan.TotalCapacity)
		}
		fmt.Fprintf(&source, "\tridge%d := mulFloor(%s, state%d)\n",
			coefficient, constant(parsed.ridge), offsets.beta+coefficient)
		fmt.Fprintf(&source,
			"\tgradient%d := (average%d - ridge%d + noise%d) & %s(0x%s)\n",
			coefficient, coefficient, coefficient, coefficient, uintType, mask)
		fmt.Fprintf(&source, "\tstep%d := mulFloor(%s, gradient%d)\n",
			coefficient, constant(parsed.alpha), coefficient)
		fmt.Fprintf(&source,
			"\tcandidate%d := (state%d + step%d) & %s(0x%s)\n",
			coefficient, offsets.beta+coefficient, coefficient, uintType, mask)
	}
	fmt.Fprintf(&source, "\tbetaNormSquared := %s(0)\n", wideType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tcandidateMagnitude%d := candidate%d\n",
			coefficient, coefficient)
		fmt.Fprintf(&source,
			"\tif (candidate%d & %s(0x%s)) != 0 { candidateMagnitude%d = (%s(0) - candidate%d) & %s(0x%s) }\n",
			coefficient, uintType, sign, coefficient, uintType, coefficient,
			uintType, mask)
		fmt.Fprintf(&source,
			"\tbetaNormSquared = betaNormSquared + wideMul(candidateMagnitude%d, candidateMagnitude%d)\n",
			coefficient, coefficient)
	}
	betaBoundSquared := new(big.Int).Mul(
		new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	fmt.Fprintf(&source, "\toutsideBall := betaNormSquared > %s(0x%s)\n",
		wideType, betaBoundSquared.Text(16))
	fmt.Fprintf(&source, "\trootLow := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\trootHigh := %s(0x%s)\n",
		uintType, projectionRoot.Text(16))
	firstRootMid := new(big.Int).Rsh(new(big.Int).Set(projectionRoot), 1)
	firstRootSquare := new(big.Int).Mul(
		new(big.Int).Set(firstRootMid), firstRootMid)
	fmt.Fprintf(&source, "\trootLess0 := %s(0x%s) < betaNormSquared\n",
		wideType, firstRootSquare.Text(16))
	fmt.Fprintf(&source, "\tif rootLess0 { rootLow = %s(0x%s) }\n",
		uintType, new(big.Int).Add(
			new(big.Int).Set(firstRootMid), big.NewInt(1)).Text(16))
	fmt.Fprintf(&source, "\tif !rootLess0 { rootHigh = %s(0x%s) }\n",
		uintType, firstRootMid.Text(16))
	for search := 1; search < plan.ProjectionSearchSteps; search++ {
		fmt.Fprintf(&source,
			"\trootMid%d := rootLow + ((rootHigh - rootLow) >> 1)\n", search)
		fmt.Fprintf(&source,
			"\trootSquare%d := wideMul(rootMid%d, rootMid%d)\n",
			search, search, search)
		fmt.Fprintf(&source,
			"\trootLess%d := rootSquare%d < betaNormSquared\n", search, search)
		fmt.Fprintf(&source, "\tnextRootLow%d := rootLow\n", search)
		fmt.Fprintf(&source, "\tnextRootHigh%d := rootHigh\n", search)
		fmt.Fprintf(&source,
			"\tif rootLess%d { nextRootLow%d = rootMid%d + %s(1) }\n",
			search, search, search, uintType)
		fmt.Fprintf(&source,
			"\tif !rootLess%d { nextRootHigh%d = rootMid%d }\n",
			search, search, search)
		fmt.Fprintf(&source, "\trootLow = nextRootLow%d\n", search)
		fmt.Fprintf(&source, "\trootHigh = nextRootHigh%d\n", search)
	}
	source.WriteString("\tprojectionDenominator := rootLow\n")
	fmt.Fprintf(&source,
		"\tif projectionDenominator == %s(0) { projectionDenominator = %s(1) }\n",
		uintType, uintType)
	maskStart := local
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tbeta%d := candidate%d\n", coefficient, coefficient)
		fmt.Fprintf(&source,
			"\tif outsideBall { beta%d = projectTowardZero(candidate%d, %s, projectionDenominator) }\n",
			coefficient, coefficient, constant(parsed.betaNorm))
		fmt.Fprintf(&source, "\tif !executionValid { beta%d = %s(0) }\n",
			coefficient, uintType)
		fmt.Fprintf(&source,
			"\tout%d := (beta%d - g[%d]) & %s(0x%s)\n",
			coefficient, coefficient, maskStart+coefficient, uintType, mask)
	}
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", p+1, uintType)
	for coefficient := 0; coefficient < p; coefficient++ {
		fmt.Fprintf(&source, "\tout[%d] = out%d\n", coefficient, coefficient)
	}
	fmt.Fprintf(&source, "\texecutionValue := %s(0)\n", uintType)
	fmt.Fprintf(&source, "\tif executionValid { executionValue = %s(1) }\n",
		uintType)
	fmt.Fprintf(&source, "\tout[%d] = (executionValue + (g[%d] & %s(1))) & %s(1)\n",
		p, maskStart+p, uintType, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String(), nil
}

type formalCoxBlockwiseCircuitFlight struct {
	done chan struct{}
	circ *circuit.Circuit
	err  error
}

const formalCoxBlockwiseCircuitCacheEntries = 8

var formalCoxBlockwiseCircuitCache = struct {
	sync.Mutex
	entries map[string]*circuit.Circuit
	flights map[string]*formalCoxBlockwiseCircuitFlight
	order   []string
}{
	entries: make(map[string]*circuit.Circuit),
	flights: make(map[string]*formalCoxBlockwiseCircuitFlight),
}

// formalCoxBlockwiseCircuitCacheTouchLocked records a use of one public,
// deterministic circuit.
func formalCoxBlockwiseCircuitCacheTouchLocked(key string) {
	for index, candidate := range formalCoxBlockwiseCircuitCache.order {
		if candidate == key {
			copy(formalCoxBlockwiseCircuitCache.order[index:],
				formalCoxBlockwiseCircuitCache.order[index+1:])
			formalCoxBlockwiseCircuitCache.order[len(formalCoxBlockwiseCircuitCache.order)-1] = key
			return
		}
	}
	formalCoxBlockwiseCircuitCache.order = append(formalCoxBlockwiseCircuitCache.order, key)
}

func formalCoxBlockwiseCircuitCacheStoreLocked(key string, circ *circuit.Circuit) {
	if formalCoxBlockwiseCircuitCache.entries[key] == nil {
		for len(formalCoxBlockwiseCircuitCache.entries) >= formalCoxBlockwiseCircuitCacheEntries {
			if len(formalCoxBlockwiseCircuitCache.order) == 0 {
				for stale := range formalCoxBlockwiseCircuitCache.entries {
					delete(formalCoxBlockwiseCircuitCache.entries, stale)
					break
				}
				continue
			}
			oldest := formalCoxBlockwiseCircuitCache.order[0]
			formalCoxBlockwiseCircuitCache.order = formalCoxBlockwiseCircuitCache.order[1:]
			delete(formalCoxBlockwiseCircuitCache.entries, oldest)
		}
	}
	formalCoxBlockwiseCircuitCache.entries[key] = circ
	formalCoxBlockwiseCircuitCacheTouchLocked(key)
}

func compileFormalCoxBlockwiseSource(source, label string) (*circuit.Circuit, error) {
	return compileFormalCoxBlockwiseSourceWith(source, label, formalCoxCompileSource)
}

// compileFormalCoxBlockwiseSourceWith coalesces only a deterministic circuit
// source.  It never keys or retains protected rows, session material, shares,
// or DP randomness.
func compileFormalCoxBlockwiseSourceWith(source, label string,
	compile func(string) (*circuit.Circuit, error)) (*circuit.Circuit, error) {

	digest := sha256.Sum256([]byte(source))
	key := hex.EncodeToString(digest[:])
	formalCoxBlockwiseCircuitCache.Lock()
	if cached := formalCoxBlockwiseCircuitCache.entries[key]; cached != nil {
		formalCoxBlockwiseCircuitCacheTouchLocked(key)
		formalCoxBlockwiseCircuitCache.Unlock()
		return cached, nil
	}
	if flight := formalCoxBlockwiseCircuitCache.flights[key]; flight != nil {
		formalCoxBlockwiseCircuitCache.Unlock()
		<-flight.done
		return flight.circ, flight.err
	}
	flight := &formalCoxBlockwiseCircuitFlight{done: make(chan struct{})}
	formalCoxBlockwiseCircuitCache.flights[key] = flight
	formalCoxBlockwiseCircuitCache.Unlock()
	circ, err := compile(source)
	if err != nil {
		err = exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("formal-cox: compile blockwise %s: %w", label, err))
	}
	formalCoxBlockwiseCircuitCache.Lock()
	if err == nil {
		formalCoxBlockwiseCircuitCacheStoreLocked(key, circ)
	}
	flight.circ, flight.err = circ, err
	delete(formalCoxBlockwiseCircuitCache.flights, key)
	close(flight.done)
	formalCoxBlockwiseCircuitCache.Unlock()
	return circ, err
}

func compileFormalCoxBlockwiseBlock(plan formalCoxBlockwisePlan) (*circuit.Circuit, error) {
	source, err := formalCoxBlockwiseBlockCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	return compileFormalCoxBlockwiseSource(source, "block update")
}

func compileFormalCoxBlockwiseGrid(plan formalCoxBlockwisePlan) (*circuit.Circuit, error) {
	source, err := formalCoxBlockwiseGridCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	return compileFormalCoxBlockwiseSource(source, "grid reduction")
}

func compileFormalCoxBlockwiseGridCoefficient(plan formalCoxBlockwisePlan) (*circuit.Circuit, error) {
	source, err := formalCoxBlockwiseGridCoefficientCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	return compileFormalCoxBlockwiseSource(source, "grid coefficient reduction")
}

func compileFormalCoxBlockwiseUpdate(plan formalCoxBlockwisePlan) (*circuit.Circuit, error) {
	source, err := formalCoxBlockwiseUpdateCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	return compileFormalCoxBlockwiseSource(source, "coefficient update")
}

func compileFormalCoxBlockwiseProjectionCoefficient(
	plan formalCoxBlockwisePlan, coefficient int) (*circuit.Circuit, error) {
	source, err := formalCoxBlockwiseProjectionCoefficientCircuitSource(
		plan, coefficient)
	if err != nil {
		return nil, err
	}
	return compileFormalCoxBlockwiseSource(source, "coefficient projection")
}

func compileFormalCoxBlockwiseFinalize(plan formalCoxBlockwisePlan) (*circuit.Circuit, error) {
	source, err := formalCoxBlockwiseFinalizeCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	return compileFormalCoxBlockwiseSource(source, "iteration finalizer")
}
