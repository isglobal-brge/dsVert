package main

import (
    "math"
    "testing"
)

func TestSigmoidBias(t *testing.T) {
    ring := NewRing63(20)

    // Test sigmoid at many points, average the ERROR (not abs error)
    // If there's a systematic bias, the mean error will be nonzero
    testX := make([]float64, 50)
    for i := range testX {
        testX[i] = -2.5 + 5.0*float64(i)/float64(len(testX)-1) // [-2.5, 2.5]
    }

    // Run multiple times with different shares
    sumBias := make([]float64, len(testX))
    sumAbsErr := make([]float64, len(testX))
    N := 20

    for trial := 0; trial < N; trial++ {
        xFP := make([]uint64, len(testX))
        for i, v := range testX { xFP[i] = ring.FromDouble(v) }
        x0 := make([]uint64, len(testX)); x1 := make([]uint64, len(testX))
        for i := range xFP { x0[i], x1[i] = ring.SplitShare(xFP[i]) }

        dmu0, dmu1 := DistributedSigmoidLocalMhe(ring, x0, x1)

        for i, x := range testX {
            got := ring.ToDouble(ring.Add(dmu0[i], dmu1[i]))
            want := 1.0 / (1.0 + math.Exp(-x))
            err := got - want  // SIGNED error
            sumBias[i] += err
            sumAbsErr[i] += math.Abs(err)
        }
    }

    // Report
    t.Log("x        | mean_bias    | mean_abs_err | bias/abs_err")
    t.Log("---------+--------------+--------------+-------------")
    totalBias := 0.0
    totalAbs := 0.0
    for i, x := range testX {
        meanBias := sumBias[i] / float64(N)
        meanAbs := sumAbsErr[i] / float64(N)
        ratio := 0.0
        if meanAbs > 1e-10 { ratio = meanBias / meanAbs }
        totalBias += meanBias
        totalAbs += meanAbs
        if i%5 == 0 { // print every 5th
            t.Logf("%+6.2f    | %+12.2e | %12.2e | %+.2f", x, meanBias, meanAbs, ratio)
        }
    }
    t.Logf("TOTAL    | %+12.2e | %12.2e | %+.2f", totalBias/float64(len(testX)), totalAbs/float64(len(testX)), totalBias/totalAbs)
    t.Logf("If |ratio| ≈ 1.0: systematic bias. If ≈ 0: random noise.")
}
