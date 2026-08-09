package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/google/differential-privacy/go/v4/noise"
)

const (
	dpNoiseSelectorVersion       = "minimum_conservative_95_radius_v3"
	dpNoiseObjectiveMarginal95   = "marginal_95_abs"
	dpNoiseObjectiveSimultaneous = "simultaneous_95_abs"
	dpNoiseTieBreak              = "laplace_unless_gaussian_strictly_improves"
)

type dpNoiseSelectionInt64Input struct {
	CoordinateCount       int     `json:"coordinate_count"`
	LaplaceEpsilon        float64 `json:"laplace_epsilon"`
	LaplaceL1Sensitivity  int64   `json:"laplace_l1_sensitivity"`
	GaussianEpsilon       float64 `json:"gaussian_epsilon"`
	GaussianDelta         float64 `json:"gaussian_delta"`
	GaussianL2Sensitivity float64 `json:"gaussian_l2_sensitivity"`
	Objective             string  `json:"objective"`
}

type dpNoiseSelectionCandidate struct {
	Available                  bool    `json:"available"`
	Mechanism                  string  `json:"mechanism"`
	Epsilon                    float64 `json:"epsilon"`
	Delta                      float64 `json:"delta"`
	AnalyticDelta              float64 `json:"analytic_delta"`
	ImplementationDeltaBound   float64 `json:"implementation_delta_bound"`
	AccountingRule             string  `json:"accounting_rule"`
	AccuracyAccounting         string  `json:"accuracy_accounting"`
	SensitivityNorm            string  `json:"sensitivity_norm"`
	Sensitivity                float64 `json:"sensitivity"`
	Marginal95Abs              int64   `json:"marginal_95_abs"`
	Simultaneous95Abs          int64   `json:"simultaneous_95_abs"`
	NominalRMSE                float64 `json:"nominal_rmse"`
	Sigma                      float64 `json:"sigma"`
	Granularity                float64 `json:"granularity"`
	AnalyticAccountingVerified bool    `json:"analytic_accounting_verified"`
	UnavailableReason          string  `json:"unavailable_reason"`
}

type dpNoiseSelectionInt64Output struct {
	SchemaVersion    int                       `json:"schema_version"`
	Selector         string                    `json:"selector"`
	Objective        string                    `json:"objective"`
	CoordinateCount  int                       `json:"coordinate_count"`
	Laplace          dpNoiseSelectionCandidate `json:"laplace"`
	Gaussian         dpNoiseSelectionCandidate `json:"gaussian"`
	Winner           string                    `json:"winner"`
	WinnerMechanism  string                    `json:"winner_mechanism"`
	WinningMetricAbs int64                     `json:"winning_metric_abs"`
	WinnerDelta      float64                   `json:"winner_delta"`
	TieBreak         string                    `json:"tie_break"`
}

func decodeDPNoiseSelectionInt64Input(r io.Reader) (
	dpNoiseSelectionInt64Input, error,
) {
	limited := io.LimitReader(r, dpNoiseMaxInputBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return dpNoiseSelectionInt64Input{}, fmt.Errorf("read input: %w", err)
	}
	if len(data) > dpNoiseMaxInputBytes {
		return dpNoiseSelectionInt64Input{}, fmt.Errorf(
			"input exceeds %d bytes", dpNoiseMaxInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input dpNoiseSelectionInt64Input
	if err := decoder.Decode(&input); err != nil {
		return dpNoiseSelectionInt64Input{}, fmt.Errorf("parse input: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return dpNoiseSelectionInt64Input{}, err
	}
	return input, nil
}

func dpConfidenceRadius(interval noise.ConfidenceInterval) (int64, error) {
	radius := math.Ceil(math.Max(
		math.Abs(interval.LowerBound), math.Abs(interval.UpperBound)))
	if math.IsNaN(radius) || math.IsInf(radius, 0) || radius < 0 ||
		radius > float64(dpNoiseOutputMax) {
		return 0, fmt.Errorf("DP confidence radius is not exactly representable")
	}
	return int64(radius), nil
}

func dpGaussianAnalyticDelta(
	sigma, l2Sensitivity, epsilon float64,
) (float64, bool) {
	a := l2Sensitivity / (2 * sigma)
	b := epsilon * sigma / l2Sensitivity
	phi := func(value float64) float64 {
		return 0.5 * math.Erfc(-value/math.Sqrt2)
	}
	exponential := math.Exp(epsilon)
	achieved := 0.0
	if !math.IsInf(exponential, 1) {
		achieved = phi(a-b) - exponential*phi(-a-b)
	}
	if math.IsNaN(achieved) || math.IsInf(achieved, 0) {
		return 0, false
	}
	if achieved < 0 {
		// Tiny negative values can arise from cancellation in the two CDF
		// tails. Zero is the conservative representable privacy-loss floor.
		if achieved < -1e-15 {
			return 0, false
		}
		achieved = 0
	}
	return achieved, true
}

func dpNoiseSelectionMetric(
	candidate dpNoiseSelectionCandidate, objective string,
) int64 {
	if objective == dpNoiseObjectiveMarginal95 {
		return candidate.Marginal95Abs
	}
	return candidate.Simultaneous95Abs
}

func chooseDPNoiseCandidate(
	laplace, gaussian dpNoiseSelectionCandidate, objective string,
) string {
	if gaussian.Available && gaussian.AnalyticAccountingVerified &&
		(!laplace.Available || dpNoiseSelectionMetric(gaussian, objective) <
			dpNoiseSelectionMetric(laplace, objective)) {
		return "gaussian"
	}
	if laplace.Available && laplace.AnalyticAccountingVerified {
		return "laplace"
	}
	return "none"
}

func selectDPNoiseInt64(
	input dpNoiseSelectionInt64Input,
) (dpNoiseSelectionInt64Output, error) {
	if input.CoordinateCount < 1 ||
		input.CoordinateCount > dpNoiseMaxCoordinates {
		return dpNoiseSelectionInt64Output{}, fmt.Errorf(
			"coordinate_count must be between one and %d", dpNoiseMaxCoordinates)
	}
	if input.Objective != dpNoiseObjectiveMarginal95 &&
		input.Objective != dpNoiseObjectiveSimultaneous {
		return dpNoiseSelectionInt64Output{}, fmt.Errorf(
			"objective must be marginal_95_abs or simultaneous_95_abs")
	}
	if input.Objective == dpNoiseObjectiveMarginal95 &&
		input.CoordinateCount != 1 {
		return dpNoiseSelectionInt64Output{}, fmt.Errorf(
			"marginal_95_abs is valid only for a scalar release")
	}

	if math.IsNaN(input.LaplaceEpsilon) ||
		math.IsInf(input.LaplaceEpsilon, 0) ||
		input.LaplaceEpsilon <= 0 ||
		input.LaplaceEpsilon > dpNoiseMaximumEpsilon {
		return dpNoiseSelectionInt64Output{}, fmt.Errorf(
			"laplace_epsilon must be finite and lie in (0,2^40]")
	}
	if input.LaplaceL1Sensitivity <= 0 {
		return dpNoiseSelectionInt64Output{}, fmt.Errorf(
			"laplace_l1_sensitivity must be positive")
	}
	laplaceInput := dpNoiseInt64Input{
		Values:        []int64{0},
		Epsilons:      []float64{input.LaplaceEpsilon},
		Sensitivities: []int64{input.LaplaceL1Sensitivity},
		Seed:          strings.Repeat("0", 64),
	}
	// The all-zero string above is valid lowercase hex and deliberately public:
	// selection computes confidence bounds only and never samples.
	laplace := dpNoiseSelectionCandidate{
		Available:                  false,
		Mechanism:                  dpNoiseMechanism,
		Epsilon:                    input.LaplaceEpsilon,
		Delta:                      0,
		AnalyticDelta:              0,
		ImplementationDeltaBound:   0,
		AccountingRule:             "pure_dp_no_implementation_slack",
		AccuracyAccounting:         "exact_granular_laplace_confidence_interval",
		SensitivityNorm:            "l1",
		Sensitivity:                float64(input.LaplaceL1Sensitivity),
		AnalyticAccountingVerified: false,
		UnavailableReason:          "laplace_calibration_not_representable",
	}
	if validateDPNoiseInt64Input(laplaceInput) == nil {
		laplaceNoise := noise.Laplace()
		marginalInterval, marginalError :=
			laplaceNoise.ComputeConfidenceIntervalInt64(
				0, 1, input.LaplaceL1Sensitivity, input.LaplaceEpsilon,
				0, 0.05)
		simultaneousInterval, simultaneousError :=
			laplaceNoise.ComputeConfidenceIntervalInt64(
				0, 1, input.LaplaceL1Sensitivity, input.LaplaceEpsilon,
				0, 0.05/float64(input.CoordinateCount))
		marginal, marginalRadiusError := dpConfidenceRadius(marginalInterval)
		simultaneous, simultaneousRadiusError :=
			dpConfidenceRadius(simultaneousInterval)
		rmse := math.Sqrt2 * float64(input.LaplaceL1Sensitivity) /
			input.LaplaceEpsilon
		if marginalError == nil && simultaneousError == nil &&
			marginalRadiusError == nil && simultaneousRadiusError == nil &&
			!math.IsNaN(rmse) && !math.IsInf(rmse, 0) && rmse > 0 {
			laplace.Available = true
			laplace.Marginal95Abs = marginal
			laplace.Simultaneous95Abs = simultaneous
			laplace.NominalRMSE = rmse
			laplace.Granularity = dpCeilPowerOfTwo(
				(float64(input.LaplaceL1Sensitivity) /
					input.LaplaceEpsilon) / dpNoiseGranularityParam)
			laplace.AnalyticAccountingVerified = true
			laplace.UnavailableReason = ""
		}
	}

	gaussian := dpNoiseSelectionCandidate{
		Available:                  false,
		Mechanism:                  dpGaussianMechanism,
		Epsilon:                    input.GaussianEpsilon,
		Delta:                      input.GaussianDelta,
		AnalyticDelta:              0,
		ImplementationDeltaBound:   0,
		AccountingRule:             dpGaussianAccountingRule,
		AccuracyAccounting:         dpGaussianAccuracyRule,
		SensitivityNorm:            "l2",
		Sensitivity:                input.GaussianL2Sensitivity,
		AnalyticAccountingVerified: false,
		UnavailableReason:          "gaussian_delta_is_zero",
	}
	if input.GaussianDelta < 0 || input.GaussianDelta >= 1 ||
		math.IsNaN(input.GaussianDelta) || math.IsInf(input.GaussianDelta, 0) {
		return dpNoiseSelectionInt64Output{}, fmt.Errorf(
			"gaussian_delta must be finite and lie in [0,1)")
	}
	implementationDeltaBound, implementationDeltaError :=
		dpGaussianImplementationDeltaBound(
			input.CoordinateCount, input.GaussianEpsilon)
	if implementationDeltaError == nil {
		gaussian.ImplementationDeltaBound = implementationDeltaBound
	}
	if input.GaussianDelta > 0 && implementationDeltaError != nil {
		gaussian.UnavailableReason =
			"gaussian_implementation_bound_not_representable"
	} else if input.GaussianDelta > 0 &&
		input.GaussianDelta <= gaussian.ImplementationDeltaBound {
		gaussian.UnavailableReason =
			"gaussian_delta_does_not_cover_implementation_bound"
	} else if input.GaussianDelta > 0 {
		gaussianInput := dpGaussianInt64Input{
			Values:        []int64{0},
			Epsilon:       input.GaussianEpsilon,
			Delta:         input.GaussianDelta,
			L2Sensitivity: input.GaussianL2Sensitivity,
			Seed:          strings.Repeat("0", 64),
		}
		sigma, granularity, analyticDelta, implementationDeltaBound,
			parameterError := dpGaussianParametersForCoordinateCount(
			gaussianInput, input.CoordinateCount)
		if parameterError != nil {
			gaussian.UnavailableReason = "gaussian_calibration_not_representable"
		} else {
			marginal, marginalError := dpGaussianAccuracyRadius(sigma, 0.05)
			simultaneous, simultaneousError := dpGaussianAccuracyRadius(
				sigma, 0.05/float64(input.CoordinateCount))
			achievedDelta, accountingOK := dpGaussianAnalyticDelta(
				sigma, input.GaussianL2Sensitivity, input.GaussianEpsilon)
			accountingOK = accountingOK && achievedDelta <= analyticDelta &&
				analyticDelta+implementationDeltaBound <= input.GaussianDelta
			if marginalError != nil || simultaneousError != nil {
				gaussian.UnavailableReason =
					"gaussian_accuracy_not_representable"
			} else if !accountingOK {
				gaussian.UnavailableReason =
					"gaussian_analytic_accounting_not_verified"
			} else {
				gaussian.Available = true
				gaussian.Marginal95Abs = marginal
				gaussian.Simultaneous95Abs = simultaneous
				gaussian.NominalRMSE = sigma
				gaussian.Sigma = sigma
				gaussian.Granularity = granularity
				gaussian.AnalyticDelta = analyticDelta
				gaussian.ImplementationDeltaBound = implementationDeltaBound
				gaussian.AnalyticAccountingVerified = true
				gaussian.UnavailableReason = ""
			}
		}
	}

	winner := chooseDPNoiseCandidate(laplace, gaussian, input.Objective)
	winnerMechanism := ""
	winnerMetric := int64(0)
	winnerDelta := 0.0
	if winner != "none" {
		winnerCandidate := laplace
		if winner == "gaussian" {
			winnerCandidate = gaussian
		}
		winnerMechanism = winnerCandidate.Mechanism
		winnerMetric = dpNoiseSelectionMetric(winnerCandidate, input.Objective)
		winnerDelta = winnerCandidate.Delta
	}
	return dpNoiseSelectionInt64Output{
		SchemaVersion:    2,
		Selector:         dpNoiseSelectorVersion,
		Objective:        input.Objective,
		CoordinateCount:  input.CoordinateCount,
		Laplace:          laplace,
		Gaussian:         gaussian,
		Winner:           winner,
		WinnerMechanism:  winnerMechanism,
		WinningMetricAbs: winnerMetric,
		WinnerDelta:      winnerDelta,
		TieBreak:         dpNoiseTieBreak,
	}, nil
}

func handleDPNoiseSelectionInt64() {
	input, err := decodeDPNoiseSelectionInt64Input(os.Stdin)
	if err != nil {
		mpcFatalError(err.Error())
	}
	result, err := selectDPNoiseInt64(input)
	if err != nil {
		mpcFatalError(err.Error())
	}
	mpcWriteOutput(result)
}
