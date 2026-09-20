package main

// Plaintext complete-cohort evaluator exists only in Go test builds. It is
// deliberately independent of the emitted chunk schedule and share handling.
import (
	"math"
	"math/big"
	"sort"
)

func coxLossReference(eta []int32, time []float64, event, live []bool, cap uint64, g int) (uint64, error) {
	n := len(eta)
	if n < 2 || n > 10000 || len(time) != n || len(event) != n || len(live) != n || g < 8 || g > 18 {
		return 0, coxLossError()
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
		if math.IsNaN(time[i]) || math.IsInf(time[i], 0) || (live[i] && (eta[i] < -524288 || eta[i] > 524288)) {
			return 0, coxLossError()
		}
	}
	sort.SliceStable(order, func(a, b int) bool { return time[order[a]] > time[order[b]] })
	risk := new(big.Int)
	loss := new(big.Int)
	for start := 0; start < n; {
		end := start + 1
		for end < n && time[order[end]] == time[order[start]] {
			end++
		}
		for _, i := range order[start:end] {
			if live[i] {
				w, err := CoxGridCrossExpProfileQ16(eta[i])
				if err != nil {
					return 0, err
				}
				risk.Add(risk, new(big.Int).SetUint64(uint64(w)))
			}
		}
		den := risk
		if den.Sign() == 0 {
			den = big.NewInt(1 << 20)
		}
		h, err := CoxGridCrossLogProfileQ20(den)
		if err != nil {
			return 0, err
		}
		for _, i := range order[start:end] {
			if live[i] && event[i] {
				loss.Add(loss, big.NewInt(h-int64(eta[i])*16))
			}
		}
		start = end
	}
	q := primitiveVRoundDivReference(loss, new(big.Int).Lsh(big.NewInt(1), uint(20-g)))
	if q.Sign() < 0 {
		return 0, nil
	}
	if q.Cmp(new(big.Int).SetUint64(cap)) > 0 {
		return cap, nil
	}
	return q.Uint64(), nil
}
