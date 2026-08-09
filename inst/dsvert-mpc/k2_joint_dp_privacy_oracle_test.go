package main

import (
	"math/big"
	"strconv"
	"testing"
)

// jointDPExactCappedDifferencePMF is an independent arithmetic oracle for the
// distribution implemented by the fixed circuit.  It intentionally does not
// call the sampler: each capped geometric mass is constructed as an exact
// rational and the two variables are convolved directly.
func jointDPExactCappedDifferencePMF(
	stop, denominator *big.Int, steps int,
) map[int]*big.Rat {
	q := new(big.Rat).SetFrac(new(big.Int).Set(stop),
		new(big.Int).Set(denominator))
	p := new(big.Rat).Sub(big.NewRat(1, 1), q)
	geometric := make([]*big.Rat, steps+1)
	power := big.NewRat(1, 1)
	for k := 0; k < steps; k++ {
		geometric[k] = new(big.Rat).Mul(new(big.Rat).Set(power), q)
		power.Mul(power, p)
	}
	geometric[steps] = new(big.Rat).Set(power)

	result := make(map[int]*big.Rat, 2*steps+1)
	for left, leftMass := range geometric {
		for right, rightMass := range geometric {
			value := left - right
			mass := new(big.Rat).Mul(leftMass, rightMass)
			if result[value] == nil {
				result[value] = mass
			} else {
				result[value].Add(result[value], mass)
			}
		}
	}
	return result
}

func jointDPExactHockeyStick(
	pmf map[int]*big.Rat, shift int, expEpsilon *big.Rat,
) *big.Rat {
	result := new(big.Rat)
	steps := (len(pmf) - 1) / 2
	lower := -steps
	upper := steps
	if shift < 0 {
		lower += shift
	} else {
		upper += shift
	}
	for output := lower; output <= upper; output++ {
		left := pmf[output]
		if left == nil {
			left = new(big.Rat)
		}
		right := pmf[output-shift]
		if right == nil {
			right = new(big.Rat)
		}
		difference := new(big.Rat).Sub(
			left, new(big.Rat).Mul(expEpsilon, right))
		if difference.Sign() > 0 {
			result.Add(result, difference)
		}
	}
	return result
}

func TestJointDPCountPlanExactPrivacyOracle(t *testing.T) {
	plan, err := jointDPPlanLaplace(jointDPLaplacePlanInput{
		Epsilon: "1", Delta: "7.888609052210118e-31",
		SensitivitySteps: "1", CoordinateCount: 1, BernoulliBits: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	stop, ok := new(big.Int).SetString(plan.StopNumerator, 10)
	if !ok {
		t.Fatal("planner returned a non-integer stop numerator")
	}
	denominator := new(big.Int).Lsh(
		big.NewInt(1), uint(plan.BernoulliBits))
	pmf := jointDPExactCappedDifferencePMF(
		stop, denominator, plan.MaxGeometricSteps)
	totalMass := new(big.Rat)
	for _, mass := range pmf {
		totalMass.Add(totalMass, mass)
	}
	if totalMass.Cmp(big.NewRat(1, 1)) != 0 {
		t.Fatalf("exact capped-noise oracle has mass %s", totalMass.RatString())
	}

	// The ideal unbounded mechanism has exp(epsilon_eff)=1/(1-q).
	// Checking the capped mechanism at epsilon_eff is stronger than checking
	// it at the (slightly larger) declared epsilon.
	expEffective := new(big.Rat).SetFrac(
		new(big.Int).Set(denominator),
		new(big.Int).Sub(new(big.Int).Set(denominator), stop))
	deltaCertificate := jointDPTestRat(
		t, plan.ImplementationDeltaNumerator,
		plan.ImplementationDeltaDenom)
	forward := jointDPExactHockeyStick(pmf, 1, expEffective)
	reverse := jointDPExactHockeyStick(pmf, -1, expEffective)
	if forward.Sign() <= 0 || reverse.Sign() <= 0 {
		t.Fatal("finite support unexpectedly passed as pure differential privacy")
	}
	if forward.Cmp(deltaCertificate) > 0 ||
		reverse.Cmp(deltaCertificate) > 0 {
		t.Fatalf(
			"exact capped Count mechanism exceeds certificate: forward=%s reverse=%s certificate=%s",
			forward.RatString(), reverse.RatString(),
			deltaCertificate.RatString())
	}

	allocated, err := jointDPParseDecimalRat(
		"7.888609052210118e-31", "delta", false)
	if err != nil || deltaCertificate.Cmp(allocated) > 0 {
		t.Fatalf("implementation delta is outside allocation: %v %v", err,
			deltaCertificate)
	}
	if plan.StopNumerator != "161" ||
		strconv.Itoa(plan.MaxGeometricSteps) != "71" {
		t.Fatalf("unexpected Count plan audited by oracle: %#v", plan)
	}
}
