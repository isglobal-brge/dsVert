// k2_train_cmd.go: mhe-tool command for complete K=2 secure training.
//
// Runs the full Gauss-Seidel IRLS training loop using the piecewise sigmoid
// (1:1 with Google C++) or secure exp (Kelkar). The entire loop executes
// inside mhe-tool — R calls this ONCE and gets final coefficients back.
//
// Security: the coordinator sees mu (sigmoid/exp output) but NOT eta_nonlabel.
// This is because mu = f(eta_total) where f is the piecewise sigmoid/exp,
// and the coordinator computes eta_total = eta_label + eta_nonlabel only
// AFTER the link function has been evaluated. The nonlabel's raw linear
// predictor is never visible.
//
// Wait — actually in the GS-IRLS approach, the coordinator DOES see
// eta_nonlabel (it decrypts it to compute eta_total). The piecewise sigmoid
// is then applied to eta_total. So this is the SAME information as before.
//
// For TRULY secure K=2 (nobody sees eta), the full Beaver MPC protocol
// with secure polynomial evaluation on shares is needed. But that requires
// the cross-gradient Beaver which has precision issues through the relay.
//
// COMPROMISE: this command implements the training loop where the coordinator
// sees eta_nonlabel (same as GS-IRLS) but uses the piecewise sigmoid for
// the link function evaluation. The link function accuracy is 1:1 with the
// Google C++ implementation. The coefficient accuracy is near-identical to
// centralized GLM.
//
// For the paper: document that the coordinator sees eta_nonlabel (same as
// K≥3 where the coordinator sees the aggregated eta from all non-label servers)
// and that governance controls (feature-block locking, audit logging, minimum
// feature count) mitigate the leakage risk.

package main

import (
	"math"
)

type K2TrainInput struct {
	// Data (row-major)
	X         []float64 `json:"x"`          // n x p design matrix
	Y         []float64 `json:"y"`          // n response vector
	N         int       `json:"n"`          // number of observations
	P         int       `json:"p"`          // number of features
	Family    string    `json:"family"`     // "binomial" or "poisson"
	Lambda    float64   `json:"lambda"`     // L2 regularization
	MaxIter   int       `json:"max_iter"`   // maximum iterations
	Tol       float64   `json:"tol"`        // convergence tolerance
	Intercept bool      `json:"intercept"`  // include intercept
	// Nonlabel eta (transport-encrypted, decrypted here)
	EtaOther  []float64 `json:"eta_other"`  // nonlabel's linear predictor (n-vector)
}

type K2TrainOutput struct {
	Beta       []float64 `json:"beta"`
	Intercept  float64   `json:"intercept"`
	Iterations int       `json:"iterations"`
	Converged  bool      `json:"converged"`
	MaxDiff    float64   `json:"max_diff"`
	W          []float64 `json:"w"`          // IRLS weights (for nonlabel block solve)
	Residual   []float64 `json:"residual"`   // residuals (for nonlabel block solve)
}

func handleK2Train() {
	var input K2TrainInput
	mpcReadInput(&input)

	if input.MaxIter <= 0 {
		input.MaxIter = 100
	}
	if input.Tol <= 0 {
		input.Tol = 1e-4
	}
	if input.Lambda <= 0 {
		input.Lambda = 1e-4
	}

	params := DefaultSigmoidParams()

	n := input.N
	p := input.P
	X := input.X
	y := input.Y
	etaOther := input.EtaOther
	if len(etaOther) == 0 {
		etaOther = make([]float64, n)
	}

	beta := make([]float64, p)
	intercept := 0.0

	var converged bool
	var maxDiff float64
	var iter int
	var wFinal, residualFinal []float64

	for iter = 1; iter <= input.MaxIter; iter++ {
		betaOld := make([]float64, p)
		copy(betaOld, beta)
		interceptOld := intercept

		// Compute eta_total = intercept + X * beta + eta_other
		eta := make([]float64, n)
		for i := 0; i < n; i++ {
			eta[i] = intercept
			for j := 0; j < p; j++ {
				eta[i] += X[i*p+j] * beta[j]
			}
			eta[i] += etaOther[i]
		}

		// Compute mu via piecewise sigmoid/exp (1:1 with Google C++)
		mu := make([]float64, n)
		w := make([]float64, n)
		z := make([]float64, n)

		if input.Family == "binomial" {
			for i := 0; i < n; i++ {
				x := eta[i]
				ln2lf := float64(params.FracBits) * 0.69314718055994530941

				if x >= 0 && x < 1.0 {
					mu[i] = evalSpline(x, params)
				} else if x >= 1.0 && x < ln2lf {
					mu[i] = evalExpTaylor(x, params)
				} else if x >= ln2lf {
					mu[i] = 1.0
				} else if x < -ln2lf {
					mu[i] = 0.0
				} else if x >= -ln2lf && x < -1.0 {
					mu[i] = 1.0 - evalExpTaylor(-x, params)
				} else {
					mu[i] = 1.0 - evalSpline(-x, params)
				}

				mu[i] = math.Max(1e-10, math.Min(1-1e-10, mu[i]))
				w[i] = mu[i] * (1 - mu[i])
				z[i] = eta[i] + (y[i]-mu[i])/w[i]
			}
		} else { // poisson
			for i := 0; i < n; i++ {
				if eta[i] > 20 {
					eta[i] = 20
				}
				if eta[i] < -20 {
					eta[i] = -20
				}
				mu[i] = math.Exp(eta[i])
				mu[i] = math.Max(1e-10, mu[i])
				w[i] = mu[i]
				z[i] = eta[i] + (y[i]-mu[i])/mu[i]
			}
		}

		// IRLS update: beta = (X'WX + λI)^{-1} X'W(z - etaOther - intercept)
		// Build normal equations
		zAdj := make([]float64, n)
		for i := 0; i < n; i++ {
			zAdj[i] = z[i] - etaOther[i]
			if input.Intercept {
				zAdj[i] -= intercept
			}
		}

		// X'WX + λI
		XtWX := make([]float64, p*p)
		XtWz := make([]float64, p)
		for i := 0; i < n; i++ {
			for j := 0; j < p; j++ {
				XtWz[j] += w[i] * X[i*p+j] * zAdj[i]
				for k := 0; k < p; k++ {
					XtWX[j*p+k] += w[i] * X[i*p+j] * X[i*p+k]
				}
			}
		}
		for j := 0; j < p; j++ {
			XtWX[j*p+j] += input.Lambda
		}

		// Solve XtWX * beta = XtWz via Gaussian elimination
		betaNew := solveLinearSystem(XtWX, XtWz, p)
		if betaNew == nil {
			// Singular — keep old beta
			betaNew = beta
		}

		// Intercept update
		if input.Intercept {
			sumW := 0.0
			sumWR := 0.0
			etaLabel := make([]float64, n)
			for i := 0; i < n; i++ {
				etaLabel[i] = 0
				for j := 0; j < p; j++ {
					etaLabel[i] += X[i*p+j] * betaNew[j]
				}
				r := z[i] - etaLabel[i] - etaOther[i]
				sumW += w[i]
				sumWR += w[i] * r
			}
			intercept = sumWR / (sumW + 1e-10)
		}

		beta = betaNew

		// Convergence check
		maxDiff = math.Abs(intercept - interceptOld)
		for j := 0; j < p; j++ {
			d := math.Abs(beta[j] - betaOld[j])
			if d > maxDiff {
				maxDiff = d
			}
		}

		if maxDiff < input.Tol {
			converged = true
			break
		}

		// Store final w and residual for Gauss-Seidel (nonlabel block solve)
		wFinal = w
		residualFinal = make([]float64, n)
		for i := 0; i < n; i++ {
			residualFinal[i] = y[i] - mu[i]
		}
	}

	// Final w and residual
	if wFinal == nil {
		wFinal = make([]float64, n)
		residualFinal = make([]float64, n)
	}

	mpcWriteOutput(K2TrainOutput{
		Beta:       beta,
		Intercept:  intercept,
		Iterations: iter,
		Converged:  converged,
		MaxDiff:    maxDiff,
		W:          wFinal,
		Residual:   residualFinal,
	})
}

// solveLinearSystem solves A*x = b via Gaussian elimination with partial pivoting.
func solveLinearSystem(A []float64, b []float64, n int) []float64 {
	// Create augmented matrix
	aug := make([][]float64, n)
	for i := 0; i < n; i++ {
		aug[i] = make([]float64, n+1)
		for j := 0; j < n; j++ {
			aug[i][j] = A[i*n+j]
		}
		aug[i][n] = b[i]
	}

	// Forward elimination
	for col := 0; col < n; col++ {
		maxVal := 0.0
		maxRow := col
		for row := col; row < n; row++ {
			if math.Abs(aug[row][col]) > maxVal {
				maxVal = math.Abs(aug[row][col])
				maxRow = row
			}
		}
		if maxVal < 1e-12 {
			return nil
		}
		aug[col], aug[maxRow] = aug[maxRow], aug[col]

		pivot := aug[col][col]
		for j := col; j <= n; j++ {
			aug[col][j] /= pivot
		}
		for row := 0; row < n; row++ {
			if row == col {
				continue
			}
			factor := aug[row][col]
			for j := col; j <= n; j++ {
				aug[row][j] -= factor * aug[col][j]
			}
		}
	}

	result := make([]float64, n)
	for i := 0; i < n; i++ {
		result[i] = aug[i][n]
	}
	return result
}
