package main

// Independent big.Int oracle for the blockwise Cox schedule.  It mirrors the
// fixed lattice and reduction order without using compiled circuits, Boolean
// wires, modular intermediate arithmetic, or a transport/session object.

import (
	"fmt"
	"math/big"
)

type formalCoxBlockwiseReferenceState struct {
	values []*big.Int
	valid  bool
}

func formalCoxBlockwiseReferenceInitial(plan formalCoxBlockwisePlan,
	beta []*big.Int, valid bool) (formalCoxBlockwiseReferenceState, error) {

	if len(beta) != plan.Policy.CovariateCount {
		return formalCoxBlockwiseReferenceState{},
			fmt.Errorf("formal-cox: invalid blockwise reference beta shape")
	}
	values := make([]*big.Int, plan.StateArithmetic)
	for index := range values {
		values[index] = new(big.Int)
	}
	for index := range beta {
		if beta[index] == nil {
			return formalCoxBlockwiseReferenceState{},
				fmt.Errorf("formal-cox: nil blockwise reference beta")
		}
		values[index].Set(beta[index])
	}
	return formalCoxBlockwiseReferenceState{values: values, valid: valid}, nil
}

func formalCoxBlockwiseReferenceStateResidues(plan formalCoxBlockwisePlan,
	state formalCoxBlockwiseReferenceState) ([]*big.Int, error) {

	if len(state.values) != plan.StateArithmetic {
		return nil, fmt.Errorf("formal-cox: invalid blockwise reference state")
	}
	result := make([]*big.Int, plan.StateCoordinates)
	for index, value := range state.values {
		if value == nil {
			return nil, fmt.Errorf("formal-cox: nil blockwise reference state")
		}
		result[index] = formalCoxResidue(value, plan.RingBits)
	}
	result[plan.StateArithmetic] = new(big.Int)
	if state.valid {
		result[plan.StateArithmetic].SetInt64(1)
	}
	return result, nil
}

func formalCoxBlockwiseReferenceDecode(value *big.Int, ringBits int) (*big.Int, error) {
	if value == nil || value.Sign() < 0 || value.Cmp(exactGCModulus(ringBits)) >= 0 {
		return nil, fmt.Errorf("formal-cox: invalid blockwise reference residue")
	}
	return exactGCReferenceSigned(value, ringBits), nil
}

func referenceFormalCoxBlockwiseBlock(plan formalCoxBlockwisePlan,
	state formalCoxBlockwiseReferenceState, rows []*big.Int) (
	formalCoxBlockwiseReferenceState, error) {

	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return formalCoxBlockwiseReferenceState{}, err
	}
	if len(state.values) != plan.StateArithmetic ||
		len(rows) != plan.BlockCapacity*plan.RowWidth {
		return formalCoxBlockwiseReferenceState{},
			fmt.Errorf("formal-cox: invalid blockwise reference block shape")
	}
	result := formalCoxBlockwiseReferenceState{
		values: make([]*big.Int, len(state.values)), valid: state.valid}
	for index, value := range state.values {
		if value == nil {
			return formalCoxBlockwiseReferenceState{},
				fmt.Errorf("formal-cox: nil blockwise reference state")
		}
		result.values[index] = new(big.Int).Set(value)
	}
	policy := plan.Policy
	p, g, k := policy.CovariateCount, policy.GridTickCount,
		len(policy.CustodianPeers)
	offsets := formalCoxBlockwiseStateOffsets(policy)
	normSquared := new(big.Int)
	for coefficient := 0; coefficient < p; coefficient++ {
		normSquared.Add(normSquared, new(big.Int).Mul(
			new(big.Int).Set(result.values[offsets.beta+coefficient]),
			result.values[offsets.beta+coefficient]))
	}
	betaBoundSquared := new(big.Int).Mul(
		new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	if normSquared.Cmp(betaBoundSquared) > 0 {
		result.valid = false
		for coefficient := 0; coefficient < p; coefficient++ {
			result.values[offsets.beta+coefficient].SetInt64(0)
		}
	}
	type rowValue struct {
		valid               bool
		entry, stop, status int
		x, weightedX        []*big.Int
		weightedXX          [][]*big.Int
		weight              *big.Int
	}
	decodedRows := make([]rowValue, plan.BlockCapacity)
	xNormSquaredBound := new(big.Int).Mul(
		new(big.Int).Set(parsed.xNorm), parsed.xNorm)
	for row := 0; row < plan.BlockCapacity; row++ {
		base := row * plan.RowWidth
		decoded := make([]*big.Int, plan.RowWidth)
		for index := range decoded {
			decoded[index], err = formalCoxBlockwiseReferenceDecode(
				rows[base+index], plan.RingBits)
			if err != nil {
				return formalCoxBlockwiseReferenceState{}, err
			}
		}
		valid := true
		for peer := 0; peer < k; peer++ {
			valid = valid && decoded[peer].Cmp(big.NewInt(1)) == 0
		}
		entryValue, stopValue, statusValue := decoded[k], decoded[k+1], decoded[k+2]
		entryOK := entryValue.Sign() >= 0 && entryValue.IsInt64() &&
			entryValue.Int64() < int64(g)
		stopOK := stopValue.IsInt64() && stopValue.Int64() >= 1 &&
			stopValue.Int64() <= int64(g)
		statusOK := statusValue.Sign() == 0 || statusValue.Cmp(big.NewInt(1)) == 0
		if policy.EntryMode == "none" {
			entryOK = entryOK && entryValue.Sign() == 0
		}
		valid = valid && entryOK && stopOK && statusOK &&
			entryValue.Cmp(stopValue) < 0
		x := make([]*big.Int, p)
		xSquared := new(big.Int)
		for coefficient := 0; coefficient < p; coefficient++ {
			x[coefficient] = new(big.Int).Set(decoded[k+3+coefficient])
			valid = valid && x[coefficient].Cmp(parsed.xLower[coefficient]) >= 0 &&
				x[coefficient].Cmp(parsed.xUpper[coefficient]) <= 0
			xSquared.Add(xSquared, new(big.Int).Mul(
				new(big.Int).Set(x[coefficient]), x[coefficient]))
		}
		valid = valid && xSquared.Cmp(xNormSquaredBound) <= 0
		current := rowValue{valid: valid, x: x}
		if valid {
			current.entry, current.stop, current.status = int(entryValue.Int64()),
				int(stopValue.Int64()), int(statusValue.Int64())
		} else {
			current.entry, current.stop, current.status = 0, 1, 0
			for coefficient := range current.x {
				current.x[coefficient] = new(big.Int)
			}
		}
		eta := new(big.Int)
		for coefficient := 0; coefficient < p; coefficient++ {
			eta.Add(eta, formalCoxFloorMul(
				current.x[coefficient],
				result.values[offsets.beta+coefficient], parsed.scale))
		}
		if eta.Cmp(parsed.expKnots[0]) < 0 ||
			eta.Cmp(parsed.expKnots[len(parsed.expKnots)-1]) > 0 {
			result.valid = false
			if eta.Cmp(parsed.expKnots[0]) < 0 {
				eta.Set(parsed.expKnots[0])
			} else {
				eta.Set(parsed.expKnots[len(parsed.expKnots)-1])
			}
		}
		segment := 0
		for segment+1 < len(parsed.expValues) &&
			eta.Cmp(parsed.expKnots[segment+1]) >= 0 {
			segment++
		}
		current.weight = new(big.Int).Set(parsed.expValues[segment])
		current.weightedX = make([]*big.Int, p)
		for coefficient := 0; coefficient < p; coefficient++ {
			current.weightedX[coefficient] = formalCoxFloorMul(
				current.weight, current.x[coefficient], parsed.scale)
		}
		current.weightedXX = make([][]*big.Int, p)
		for left := 0; left < p; left++ {
			current.weightedXX[left] = make([]*big.Int, p)
			for right := left; right < p; right++ {
				current.weightedXX[left][right] = formalCoxFloorMul(
					current.weightedX[left], current.x[right], parsed.scale)
			}
		}
		decodedRows[row] = current
	}
	for grid := 1; grid <= g; grid++ {
		for _, row := range decodedRows {
			atRisk := row.valid && row.entry < grid && row.stop >= grid
			event := row.valid && row.status == 1 && row.stop == grid
			if atRisk {
				result.values[offsets.riskCount+grid-1].Add(
					result.values[offsets.riskCount+grid-1], big.NewInt(1))
				result.values[offsets.s0+grid-1].Add(
					result.values[offsets.s0+grid-1], row.weight)
				for coefficient := 0; coefficient < p; coefficient++ {
					index := offsets.s1 + (grid-1)*p + coefficient
					result.values[index].Add(result.values[index],
						row.weightedX[coefficient])
				}
				for left := 0; left < p; left++ {
					for right := left; right < p; right++ {
						index := offsets.s2 +
							(grid-1)*formalCoxBlockwiseSecondMomentCoordinates(policy) +
							formalCoxBlockwiseSecondMomentIndex(policy, left, right)
						result.values[index].Add(result.values[index],
							row.weightedXX[left][right])
					}
				}
			}
			if event {
				result.values[offsets.eventCount+grid-1].Add(
					result.values[offsets.eventCount+grid-1], big.NewInt(1))
				for coefficient := 0; coefficient < p; coefficient++ {
					index := offsets.eventX + (grid-1)*p + coefficient
					result.values[index].Add(result.values[index], row.x[coefficient])
				}
			}
		}
	}
	return result, nil
}

// referenceFormalCoxBlockwiseInformationStep is deliberately independent of
// the circuit generator. It evaluates one lower-triangular Breslow observed
// information coordinate from private block moments, without opening them.
func referenceFormalCoxBlockwiseInformationStep(plan formalCoxBlockwisePlan,
	state formalCoxBlockwiseReferenceState, grid, coefficient int,
	current *big.Int) (*big.Int, bool, error) {

	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return nil, false, err
	}
	if len(state.values) != plan.StateArithmetic || grid < 0 ||
		grid >= plan.Policy.GridTickCount || current == nil {
		return nil, false, fmt.Errorf("formal-cox: invalid observed-information reference state")
	}
	left, right, err := formalCoxBlockwiseSecondMomentPairAt(plan.Policy, coefficient)
	if err != nil {
		return nil, false, err
	}
	offsets := formalCoxBlockwiseStateOffsets(plan.Policy)
	risk := state.values[offsets.riskCount+grid]
	events := state.values[offsets.eventCount+grid]
	denominator := new(big.Int).Set(state.values[offsets.s0+grid])
	if denominator.Sign() == 0 {
		denominator.SetInt64(1)
	}
	leftMean := formalCoxFloorDiv(new(big.Int).Mul(
		new(big.Int).Set(state.values[offsets.s1+grid*plan.Policy.CovariateCount+left]),
		parsed.scale), denominator)
	rightMean := formalCoxFloorDiv(new(big.Int).Mul(
		new(big.Int).Set(state.values[offsets.s1+grid*plan.Policy.CovariateCount+right]),
		parsed.scale), denominator)
	secondMean := formalCoxFloorDiv(new(big.Int).Mul(
		new(big.Int).Set(state.values[offsets.s2+grid*formalCoxBlockwiseInformationCoordinates(plan.Policy)+coefficient]),
		parsed.scale), denominator)
	meanOuter := formalCoxFloorMul(leftMean, rightMean, parsed.scale)
	increment := new(big.Int).Mul(new(big.Int).Sub(secondMean, meanOuter), events)
	valid := state.valid && (events.Sign() == 0 ||
		risk.Cmp(big.NewInt(int64(plan.Policy.MinimumAtRisk))) >= 0)
	return new(big.Int).Add(current, increment), valid, nil
}

func referenceFormalCoxBlockwiseFinalize(plan formalCoxBlockwisePlan,
	state formalCoxBlockwiseReferenceState, noise []*big.Int,
	noiseValid bool) (formalCoxBlockwiseReferenceState, error) {

	parsed, err := formalCoxBlockwiseValidateShape(plan)
	if err != nil {
		return formalCoxBlockwiseReferenceState{}, err
	}
	policy := plan.Policy
	p, g := policy.CovariateCount, policy.GridTickCount
	if len(state.values) != plan.StateArithmetic || len(noise) != p {
		return formalCoxBlockwiseReferenceState{},
			fmt.Errorf("formal-cox: invalid blockwise finalizer shape")
	}
	valid := state.valid && noiseValid
	decodedNoise := make([]*big.Int, p)
	for coefficient := 0; coefficient < p; coefficient++ {
		decodedNoise[coefficient], err = formalCoxBlockwiseReferenceDecode(
			noise[coefficient], plan.RingBits)
		if err != nil {
			return formalCoxBlockwiseReferenceState{}, err
		}
		if formalCoxAbs(decodedNoise[coefficient]).Cmp(parsed.noiseBound) > 0 {
			valid = false
			decodedNoise[coefficient].SetInt64(0)
		}
	}
	offsets := formalCoxBlockwiseStateOffsets(policy)
	score := make([]*big.Int, p)
	for coefficient := range score {
		score[coefficient] = new(big.Int)
	}
	for grid := 1; grid <= g; grid++ {
		risk := state.values[offsets.riskCount+grid-1]
		events := state.values[offsets.eventCount+grid-1]
		if events.Sign() > 0 && risk.Cmp(big.NewInt(int64(policy.MinimumAtRisk))) < 0 {
			valid = false
		}
		denominator := new(big.Int).Set(state.values[offsets.s0+grid-1])
		if denominator.Sign() == 0 {
			denominator.SetInt64(1)
		}
		for coefficient := 0; coefficient < p; coefficient++ {
			s1 := state.values[offsets.s1+(grid-1)*p+coefficient]
			eventX := state.values[offsets.eventX+(grid-1)*p+coefficient]
			mean := formalCoxFloorDiv(new(big.Int).Mul(
				new(big.Int).Set(s1), parsed.scale), denominator)
			riskTerm := new(big.Int).Mul(mean, events)
			score[coefficient].Add(score[coefficient], eventX)
			score[coefficient].Sub(score[coefficient], riskTerm)
		}
	}
	candidate := make([]*big.Int, p)
	normSquared := new(big.Int)
	for coefficient := 0; coefficient < p; coefficient++ {
		average := formalCoxFloorDiv(
			score[coefficient], big.NewInt(int64(plan.TotalCapacity)))
		ridge := formalCoxFloorMul(parsed.ridge,
			state.values[offsets.beta+coefficient], parsed.scale)
		gradient := new(big.Int).Sub(average, ridge)
		gradient.Add(gradient, decodedNoise[coefficient])
		step := formalCoxFloorMul(parsed.alpha, gradient, parsed.scale)
		candidate[coefficient] = new(big.Int).Add(
			state.values[offsets.beta+coefficient], step)
		normSquared.Add(normSquared, new(big.Int).Mul(
			new(big.Int).Set(candidate[coefficient]), candidate[coefficient]))
	}
	beta := candidate
	boundSquared := new(big.Int).Mul(
		new(big.Int).Set(parsed.betaNorm), parsed.betaNorm)
	if normSquared.Cmp(boundSquared) > 0 {
		denominator := formalCoxCeilSqrt(normSquared)
		beta = make([]*big.Int, p)
		for coefficient := 0; coefficient < p; coefficient++ {
			beta[coefficient] = formalCoxProjectTowardZero(
				candidate[coefficient], parsed.betaNorm, denominator)
		}
	}
	if !valid {
		for coefficient := range beta {
			beta[coefficient] = new(big.Int)
		}
	}
	return formalCoxBlockwiseReferenceInitial(plan, beta, valid)
}

func referenceFormalCoxBlockwiseSchedule(plan formalCoxBlockwisePlan,
	rows, noise []*big.Int, noiseValidity []bool) ([]*big.Int, bool, error) {

	if err := validateFormalCoxBlockwisePlan(plan); err != nil {
		return nil, false, err
	}
	p := plan.Policy.CovariateCount
	if len(rows) != plan.TotalCapacity*plan.RowWidth ||
		len(noise) != plan.Iterations*p || len(noiseValidity) != plan.Iterations {
		return nil, false, fmt.Errorf("formal-cox: invalid blockwise schedule input")
	}
	beta := make([]*big.Int, p)
	for coefficient := range beta {
		beta[coefficient] = new(big.Int)
	}
	state, err := formalCoxBlockwiseReferenceInitial(plan, beta, true)
	if err != nil {
		return nil, false, err
	}
	zero := new(big.Int)
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		for block := 0; block < plan.TotalBlocks; block++ {
			blockRows := make([]*big.Int, plan.BlockCapacity*plan.RowWidth)
			for index := range blockRows {
				blockRows[index] = zero
			}
			firstRow := block * plan.BlockCapacity
			rowsInBlock := plan.BlockCapacity
			if remaining := plan.TotalCapacity - firstRow; remaining < rowsInBlock {
				rowsInBlock = remaining
			}
			copy(blockRows, rows[firstRow*plan.RowWidth:(firstRow+rowsInBlock)*plan.RowWidth])
			state, err = referenceFormalCoxBlockwiseBlock(plan, state, blockRows)
			if err != nil {
				return nil, false, err
			}
		}
		state, err = referenceFormalCoxBlockwiseFinalize(
			plan, state, noise[iteration*p:(iteration+1)*p],
			noiseValidity[iteration])
		if err != nil {
			return nil, false, err
		}
	}
	result := make([]*big.Int, p)
	for coefficient := 0; coefficient < p; coefficient++ {
		result[coefficient] = formalCoxResidue(state.values[coefficient], plan.RingBits)
	}
	return result, state.valid, nil
}
