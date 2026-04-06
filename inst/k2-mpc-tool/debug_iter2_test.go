package main

import (
	"math"
	"testing"
)

// TestSigmoidDivergencePerIteration traces where distributed vs piecewise diverge.
func TestSigmoidDivergencePerIteration(t *testing.T) {
	rp := DefaultRingParams()

	n := 10
	p := 2
	X := []float64{
		0.5, -0.3, -1.2, 0.8, 0.7, 0.4, -0.4, -0.9, 1.1, 0.2,
		-0.8, 1.3, 0.3, -0.5, -0.1, 0.7, 0.9, -1.1, -0.6, 0.1,
	}
	y := []float64{1, 0, 1, 0, 1, 0, 1, 0, 1, 0}

	xFP := rp.VecFromDoubles(X)
	yFP := rp.VecFromDoubles(y)
	x0, x1 := rp.SplitVecShare(xFP)
	y0, y1 := rp.SplitVecShare(yFP)

	alpha := 1.0
	lambda := 1e-4

	// Run BOTH methods in lockstep
	betaD := make([]float64, p+1) // distributed
	betaP := make([]float64, p+1) // piecewise

	for iter := 1; iter <= 30; iter++ {
		// Compute eta from beta (same for both since we check divergence)
		betaFP_D := rp.VecFromDoubles(betaD)
		beta0_D, beta1_D := rp.SplitVecShare(betaFP_D)
		betaFP_P := rp.VecFromDoubles(betaP)
		beta0_P, beta1_P := rp.SplitVecShare(betaFP_P)

		// Eta via Beaver (same code for both)
		etaD0 := make([]uint64, n)
		etaD1 := make([]uint64, n)
		etaP0 := make([]uint64, n)
		etaP1 := make([]uint64, n)

		for i := 0; i < n; i++ {
			etaD0[i] = beta0_D[0]; etaD1[i] = beta1_D[0]
			etaP0[i] = beta0_P[0]; etaP1[i] = beta1_P[0]
			for j := 0; j < p; j++ {
				idx := i*p + j
				t0, t1 := GenerateBeaverTriples(rp, 1)
				pd0, pd1 := BeaverFixedPointMul(rp,
					[]uint64{x0[idx]}, []uint64{beta0_D[j+1]},
					[]uint64{x1[idx]}, []uint64{beta1_D[j+1]}, t0, t1)
				etaD0[i] = rp.ModAdd(etaD0[i], pd0[0])
				etaD1[i] = rp.ModAdd(etaD1[i], pd1[0])

				t0b, t1b := GenerateBeaverTriples(rp, 1)
				pp0, pp1 := BeaverFixedPointMul(rp,
					[]uint64{x0[idx]}, []uint64{beta0_P[j+1]},
					[]uint64{x1[idx]}, []uint64{beta1_P[j+1]}, t0b, t1b)
				etaP0[i] = rp.ModAdd(etaP0[i], pp0[0])
				etaP1[i] = rp.ModAdd(etaP1[i], pp1[0])
			}
		}

		// Check eta values
		maxEtaDiff := 0.0
		for i := 0; i < n; i++ {
			ed := rp.ToDouble(rp.ModAdd(etaD0[i], etaD1[i]))
			ep := rp.ToDouble(rp.ModAdd(etaP0[i], etaP1[i]))
			d := math.Abs(ed - ep)
			if d > maxEtaDiff { maxEtaDiff = d }
		}

		// Sigmoid
		dmu0, dmu1 := DistributedSigmoidLocal(rp, etaD0, etaD1)
		pmu0, pmu1 := SecurePiecewiseSigmoidLocal(rp, etaP0, etaP1)

		maxMuDiff := 0.0
		worstI := -1
		for i := 0; i < n; i++ {
			dv := rp.ToDouble(rp.ModAdd(dmu0[i], dmu1[i]))
			pv := rp.ToDouble(rp.ModAdd(pmu0[i], pmu1[i]))
			d := math.Abs(dv - pv)
			if d > maxMuDiff { maxMuDiff = d; worstI = i }
		}
		if maxMuDiff > 0.01 {
			ed := rp.ToDouble(rp.ModAdd(etaD0[worstI], etaD1[worstI]))
			dv := rp.ToDouble(rp.ModAdd(dmu0[worstI], dmu1[worstI]))
			pv := rp.ToDouble(rp.ModAdd(pmu0[worstI], pmu1[worstI]))
			t.Logf("  WORST[%d]: eta=%.6f dist_mu=%.6f piecewise_mu=%.6f", worstI, ed, dv, pv)
		}

		// Gradient (reconstructed for comparison)
		dr0 := rp.VecSub(dmu0, y0); dr1 := rp.VecSub(dmu1, y1)
		pr0 := rp.VecSub(pmu0, y0); pr1 := rp.VecSub(pmu1, y1)

		gradD := make([]float64, p+1)
		gradP := make([]float64, p+1)
		for i := 0; i < n; i++ {
			drv := rp.ToDouble(rp.ModAdd(dr0[i], dr1[i]))
			prv := rp.ToDouble(rp.ModAdd(pr0[i], pr1[i]))
			gradD[0] += drv; gradP[0] += prv
			for j := 0; j < p; j++ {
				gradD[j+1] += X[i*p+j] * drv
				gradP[j+1] += X[i*p+j] * prv
			}
		}

		maxGradDiff := 0.0
		for j := 0; j <= p; j++ {
			gradD[j] = gradD[j]/float64(n) + lambda*betaD[j]
			gradP[j] = gradP[j]/float64(n) + lambda*betaP[j]
			d := math.Abs(gradD[j] - gradP[j])
			if d > maxGradDiff { maxGradDiff = d }
		}

		t.Logf("Iter %d: maxEtaDiff=%.2e maxMuDiff=%.2e maxGradDiff=%.2e betaD=%v betaP=%v",
			iter, maxEtaDiff, maxMuDiff, maxGradDiff,
			[]float64{betaD[0], betaD[1], betaD[2]},
			[]float64{betaP[0], betaP[1], betaP[2]})

		// Update betas
		for j := 0; j <= p; j++ {
			betaD[j] -= alpha * gradD[j]
			betaP[j] -= alpha * gradP[j]
		}
	}
}
