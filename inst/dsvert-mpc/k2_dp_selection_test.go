package main

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func validDPNoiseSelectionInput() dpNoiseSelectionInt64Input {
	return dpNoiseSelectionInt64Input{
		CoordinateCount:       1,
		LaplaceEpsilon:        1,
		LaplaceL1Sensitivity:  1,
		GaussianEpsilon:       1,
		GaussianDelta:         1e-5,
		GaussianL2Sensitivity: 1,
		Objective:             dpNoiseObjectiveMarginal95,
	}
}

func TestDecodeDPNoiseSelectionInputIsStrict(t *testing.T) {
	valid := `{"coordinate_count":1,"laplace_epsilon":1,` +
		`"laplace_l1_sensitivity":1,"gaussian_epsilon":1,` +
		`"gaussian_delta":0.00001,"gaussian_l2_sensitivity":1,` +
		`"objective":"marginal_95_abs"}`
	decoded, err := decodeDPNoiseSelectionInt64Input(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("decode valid selector input: %v", err)
	}
	if !reflect.DeepEqual(decoded, validDPNoiseSelectionInput()) {
		t.Fatalf("decoded selector input=%+v", decoded)
	}
	for name, encoded := range map[string]string{
		"unknown":  strings.TrimSuffix(valid, "}") + `,"other":1}`,
		"trailing": valid + ` {}`,
		"fractional count": strings.Replace(
			valid, `"coordinate_count":1`, `"coordinate_count":1.5`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDPNoiseSelectionInt64Input(
				strings.NewReader(encoded)); err == nil {
				t.Fatal("invalid selector JSON unexpectedly decoded")
			}
		})
	}
}

func TestDPNoiseSelectionFailsClosedOnMalformedPublicCalibration(t *testing.T) {
	cases := map[string]func(*dpNoiseSelectionInt64Input){
		"zero coordinates": func(input *dpNoiseSelectionInt64Input) {
			input.CoordinateCount = 0
		},
		"too many coordinates": func(input *dpNoiseSelectionInt64Input) {
			input.CoordinateCount = dpNoiseMaxCoordinates + 1
		},
		"bad objective": func(input *dpNoiseSelectionInt64Input) {
			input.Objective = "rmse"
		},
		"marginal vector": func(input *dpNoiseSelectionInt64Input) {
			input.CoordinateCount = 2
		},
		"zero Laplace epsilon": func(input *dpNoiseSelectionInt64Input) {
			input.LaplaceEpsilon = 0
		},
		"zero Laplace sensitivity": func(input *dpNoiseSelectionInt64Input) {
			input.LaplaceL1Sensitivity = 0
		},
		"negative Gaussian delta": func(input *dpNoiseSelectionInt64Input) {
			input.GaussianDelta = -1e-5
		},
		"Gaussian delta one": func(input *dpNoiseSelectionInt64Input) {
			input.GaussianDelta = 1
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := validDPNoiseSelectionInput()
			mutate(&input)
			if _, err := selectDPNoiseInt64(input); err == nil {
				t.Fatal("malformed selector calibration unexpectedly accepted")
			}
		})
	}
}

func TestDPNoiseSelectionUsesStrictConservativeTieBreak(t *testing.T) {
	laplace := dpNoiseSelectionCandidate{
		Available: true, Marginal95Abs: 5, Simultaneous95Abs: 8,
		AnalyticAccountingVerified: true,
	}
	gaussian := dpNoiseSelectionCandidate{
		Available: true, Marginal95Abs: 5, Simultaneous95Abs: 7,
		AnalyticAccountingVerified: true,
	}
	if got := chooseDPNoiseCandidate(
		laplace, gaussian, dpNoiseObjectiveMarginal95); got != "laplace" {
		t.Fatalf("tie selected %q, want conservative Laplace", got)
	}
	if got := chooseDPNoiseCandidate(
		laplace, gaussian, dpNoiseObjectiveSimultaneous); got != "gaussian" {
		t.Fatalf("strict improvement selected %q, want Gaussian", got)
	}
	gaussian.AnalyticAccountingVerified = false
	if got := chooseDPNoiseCandidate(
		laplace, gaussian, dpNoiseObjectiveSimultaneous); got != "laplace" {
		t.Fatalf("unverified Gaussian selected %q", got)
	}
	laplace.Available = false
	laplace.AnalyticAccountingVerified = false
	if got := chooseDPNoiseCandidate(
		laplace, gaussian, dpNoiseObjectiveSimultaneous); got != "none" {
		t.Fatalf("unavailable candidates selected %q", got)
	}
}

func TestDPNoiseSelectionFallsBackAcrossUnrepresentableCandidates(t *testing.T) {
	input := validDPNoiseSelectionInput()
	input.CoordinateCount = 64
	input.Objective = dpNoiseObjectiveSimultaneous
	input.LaplaceL1Sensitivity = math.MaxInt64
	result, err := selectDPNoiseInt64(input)
	if err != nil {
		t.Fatalf("Gaussian fallback: %v", err)
	}
	if result.Laplace.Available || result.Winner != "gaussian" ||
		!result.Gaussian.Available || result.WinnerDelta != input.GaussianDelta {
		t.Fatalf("unexpected Gaussian fallback certificate: %+v", result)
	}

	input.GaussianDelta = 0
	result, err = selectDPNoiseInt64(input)
	if err != nil {
		t.Fatalf("no representable candidate: %v", err)
	}
	if result.Winner != "none" || result.WinnerMechanism != "" ||
		result.WinningMetricAbs != 0 || result.WinnerDelta != 0 ||
		result.Laplace.Available || result.Gaussian.Available {
		t.Fatalf("unexpected unavailable certificate: %+v", result)
	}
}

func TestDPNoiseSelectionChoosesMinimumConservative95Radius(t *testing.T) {
	laplaceInput := validDPNoiseSelectionInput()
	laplaceResult, err := selectDPNoiseInt64(laplaceInput)
	if err != nil {
		t.Fatalf("scalar selector: %v", err)
	}
	if laplaceResult.Winner != "laplace" ||
		laplaceResult.WinnerDelta != 0 ||
		laplaceResult.Selector != dpNoiseSelectorVersion ||
		laplaceResult.TieBreak != dpNoiseTieBreak {
		t.Fatalf("unexpected scalar selector result: %+v", laplaceResult)
	}

	gaussianInput := validDPNoiseSelectionInput()
	gaussianInput.CoordinateCount = 64
	gaussianInput.Objective = dpNoiseObjectiveSimultaneous
	gaussianInput.LaplaceL1Sensitivity = 100
	gaussianResult, err := selectDPNoiseInt64(gaussianInput)
	if err != nil {
		t.Fatalf("vector selector: %v", err)
	}
	if gaussianResult.Winner != "gaussian" ||
		gaussianResult.WinnerDelta != gaussianInput.GaussianDelta ||
		!gaussianResult.Gaussian.AnalyticAccountingVerified ||
		gaussianResult.Gaussian.Simultaneous95Abs >=
			gaussianResult.Laplace.Simultaneous95Abs {
		t.Fatalf("unexpected Gaussian selector result: %+v", gaussianResult)
	}
	implementationBound, err := dpGaussianImplementationDeltaBound(
		gaussianInput.CoordinateCount, gaussianInput.GaussianEpsilon)
	if err != nil {
		t.Fatal(err)
	}
	if gaussianResult.SchemaVersion != 2 ||
		gaussianResult.Gaussian.ImplementationDeltaBound !=
			implementationBound ||
		gaussianResult.Gaussian.AnalyticDelta <= 0 ||
		gaussianResult.Gaussian.AnalyticDelta+implementationBound >
			gaussianInput.GaussianDelta ||
		gaussianResult.Gaussian.AccountingRule != dpGaussianAccountingRule ||
		gaussianResult.Gaussian.AccuracyAccounting != dpGaussianAccuracyRule {
		t.Fatalf("invalid Gaussian accounting certificate: %+v", gaussianResult)
	}

	boundary := gaussianInput
	boundary.GaussianDelta = implementationBound
	boundaryResult, err := selectDPNoiseInt64(boundary)
	if err != nil {
		t.Fatalf("implementation-bound selector: %v", err)
	}
	if boundaryResult.Winner != "laplace" ||
		boundaryResult.Gaussian.Available ||
		boundaryResult.Gaussian.UnavailableReason !=
			"gaussian_delta_does_not_cover_implementation_bound" {
		t.Fatalf("implementation-bound selector result: %+v", boundaryResult)
	}

	noDelta := gaussianInput
	noDelta.GaussianDelta = 0
	noDeltaResult, err := selectDPNoiseInt64(noDelta)
	if err != nil {
		t.Fatalf("zero-delta selector: %v", err)
	}
	if noDeltaResult.Winner != "laplace" ||
		noDeltaResult.Gaussian.Available ||
		noDeltaResult.Gaussian.UnavailableReason != "gaussian_delta_is_zero" {
		t.Fatalf("zero-delta selector result: %+v", noDeltaResult)
	}
}

func TestDPNoiseSelectionDimensionAndSensitivityAreMonotone(t *testing.T) {
	previous := int64(0)
	for _, dimension := range []int{1, 2, 16, 1024} {
		input := validDPNoiseSelectionInput()
		input.CoordinateCount = dimension
		input.Objective = dpNoiseObjectiveSimultaneous
		result, err := selectDPNoiseInt64(input)
		if err != nil {
			t.Fatalf("dimension %d: %v", dimension, err)
		}
		if result.Laplace.Simultaneous95Abs < previous ||
			result.Gaussian.Simultaneous95Abs < previous {
			t.Fatalf("dimension %d reduced simultaneous radius: %+v",
				dimension, result)
		}
		previous = result.Laplace.Simultaneous95Abs
	}

	input := validDPNoiseSelectionInput()
	first, err := selectDPNoiseInt64(input)
	if err != nil {
		t.Fatal(err)
	}
	input.GaussianL2Sensitivity *= 2
	second, err := selectDPNoiseInt64(input)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(second.Gaussian.Sigma/first.Gaussian.Sigma-2) > 1e-12 {
		t.Fatalf("selector Gaussian sigma not linear: %g vs %g",
			first.Gaussian.Sigma, second.Gaussian.Sigma)
	}
}
