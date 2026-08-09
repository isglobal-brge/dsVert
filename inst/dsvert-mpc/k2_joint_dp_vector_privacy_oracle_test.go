package main

import (
	"math/big"
	"testing"
)

// The oracle below never calls the sampler or its TV-bound helper.  It builds
// the exact dyadic distribution implemented by the circuit directly from the
// public integer thresholds, convolves the two geometrics, applies the public
// clamp, forms a two-coordinate product distribution, and evaluates both
// directed hockey-stick divergences for a worst-case joint-L1 neighbour.

func jointDPVectorOracleGeometric(plan jointDPVectorPlanOutput) []*big.Rat {
	bits := plan.BinaryGeometricBits
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(plan.UniformBits))
	thresholds := make([]*big.Int, bits)
	for index, value := range plan.BernoulliThresholds {
		thresholds[index], _ = new(big.Int).SetString(value, 10)
	}
	result := make([]*big.Rat, 1<<bits)
	for value := range result {
		mass := big.NewRat(1, 1)
		for bit, threshold := range thresholds {
			numerator := new(big.Int).Sub(
				new(big.Int).Set(denominator), threshold)
			if value&(1<<bit) != 0 {
				numerator.Set(threshold)
			}
			mass.Mul(mass, new(big.Rat).SetFrac(
				numerator, new(big.Int).Set(denominator)))
		}
		result[value] = mass
	}
	return result
}

func jointDPVectorOracleNoise(geometric []*big.Rat) map[int]*big.Rat {
	result := make(map[int]*big.Rat, 2*len(geometric)-1)
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

func jointDPVectorOracleClamp(noise map[int]*big.Rat, statistic,
	upper int) map[int]*big.Rat {
	result := make(map[int]*big.Rat, upper+1)
	for value, mass := range noise {
		output := statistic + value
		if output < 0 {
			output = 0
		} else if output > upper {
			output = upper
		}
		if result[output] == nil {
			result[output] = new(big.Rat).Set(mass)
		} else {
			result[output].Add(result[output], mass)
		}
	}
	return result
}

type jointDPVectorOraclePair struct{ first, second int }

func jointDPVectorOracleProduct(first, second map[int]*big.Rat) map[jointDPVectorOraclePair]*big.Rat {
	result := make(map[jointDPVectorOraclePair]*big.Rat,
		len(first)*len(second))
	for firstValue, firstMass := range first {
		for secondValue, secondMass := range second {
			result[jointDPVectorOraclePair{firstValue, secondValue}] =
				new(big.Rat).Mul(firstMass, secondMass)
		}
	}
	return result
}

func jointDPVectorOracleHockey(
	left, right map[jointDPVectorOraclePair]*big.Rat,
	expEpsilonLower *big.Rat,
) *big.Rat {
	result := new(big.Rat)
	for output, leftMass := range left {
		rightMass := right[output]
		if rightMass == nil {
			rightMass = new(big.Rat)
		}
		difference := new(big.Rat).Sub(
			leftMass, new(big.Rat).Mul(expEpsilonLower, rightMass))
		if difference.Sign() > 0 {
			result.Add(result, difference)
		}
	}
	return result
}

func jointDPVectorOracleTotal[K comparable](pmf map[K]*big.Rat) *big.Rat {
	result := new(big.Rat)
	for _, mass := range pmf {
		result.Add(result, mass)
	}
	return result
}

func TestJointDPVectorExactRationalPrivacyOracleBothDirections(t *testing.T) {
	plan := jointDPVectorTestPlan(
		t, "1", "7.888609052210118e-31", "2", 2)
	geometric := jointDPVectorOracleGeometric(plan)
	noise := jointDPVectorOracleNoise(geometric)
	if total := jointDPVectorOracleTotal(noise); total.Cmp(big.NewRat(1, 1)) != 0 {
		t.Fatalf("oracle noise mass is %s", total.RatString())
	}
	// Q and Q' differ by one in each coordinate: their joint L1 distance is
	// exactly the globally certified sensitivity 2.  Bounds are intentionally
	// tight so this also audits the exact saturating postprocessing.
	left := jointDPVectorOracleProduct(
		jointDPVectorOracleClamp(noise, 1, 4),
		jointDPVectorOracleClamp(noise, 1, 4))
	right := jointDPVectorOracleProduct(
		jointDPVectorOracleClamp(noise, 2, 4),
		jointDPVectorOracleClamp(noise, 2, 4))
	if total := jointDPVectorOracleTotal(left); total.Cmp(big.NewRat(1, 1)) != 0 {
		t.Fatalf("left vector mass is %s", total.RatString())
	}
	if total := jointDPVectorOracleTotal(right); total.Cmp(big.NewRat(1, 1)) != 0 {
		t.Fatalf("right vector mass is %s", total.RatString())
	}
	epsilon, _ := jointDPParseDecimalRat("1", "epsilon", false)
	expLower, err := jointDPExpLowerCapped(epsilon, big.NewRat(10, 1))
	if err != nil {
		t.Fatal(err)
	}
	forward := jointDPVectorOracleHockey(left, right, expLower)
	reverse := jointDPVectorOracleHockey(right, left, expLower)
	certificate := jointDPTestRat(t, plan.ImplementationDeltaNumerator,
		plan.ImplementationDeltaDenominator)
	if forward.Cmp(certificate) > 0 || reverse.Cmp(certificate) > 0 {
		t.Fatalf("exact vector mechanism exceeds certificate: forward=%s reverse=%s certificate=%s",
			forward.RatString(), reverse.RatString(), certificate.RatString())
	}
}

func TestJointDPVectorDeltaFormulaIncludesEveryCoordinateAndBit(t *testing.T) {
	plan := jointDPVectorTestPlan(
		t, "1", "7.888609052210118e-31", "131073", 1000000)
	tail := jointDPTestRat(t, plan.TailUpperNumerator,
		plan.TailUpperDenominator)
	rounding := jointDPTestRat(t, plan.RoundingUpperNumerator,
		plan.RoundingUpperDenominator)
	oneGeom := jointDPTestRat(t, plan.OneGeometricTVNumerator,
		plan.OneGeometricTVDenominator)
	if new(big.Rat).Add(tail, rounding).Cmp(oneGeom) != 0 {
		t.Fatal("one-geometric certificate omitted tail or Bernoulli rounding")
	}
	epsilon, _ := jointDPParseDecimalRat("1", "epsilon", false)
	expUpper, err := jointDPExpUpper(epsilon)
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Rat).Mul(
		new(big.Rat).Add(big.NewRat(1, 1), expUpper),
		new(big.Rat).Mul(
			new(big.Rat).SetInt64(2*int64(plan.TotalCoordinateCount)),
			oneGeom))
	got := jointDPTestRat(t, plan.ImplementationDeltaNumerator,
		plan.ImplementationDeltaDenominator)
	if want.Cmp(got) != 0 {
		t.Fatalf("delta transfer formula changed: got=%s want=%s",
			got.RatString(), want.RatString())
	}
	// Rounding is accumulated once per Bernoulli of one geometric and then
	// multiplied by 2*d above.  It must not remain constant when J grows.
	short := jointDPVectorTestPlan(
		t, "1", "7.888609052210118e-31", "1", 1000000)
	shortRounding := jointDPTestRat(t, short.RoundingUpperNumerator,
		short.RoundingUpperDenominator)
	if plan.BinaryGeometricBits <= short.BinaryGeometricBits ||
		rounding.Cmp(shortRounding) <= 0 {
		t.Fatal("additional binary Bernoulli approximations were not accounted")
	}
}
