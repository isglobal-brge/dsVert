package main

import (
	"errors"
	"math/big"
	"math/bits"
)

// Plaintext oracle for synthetic tests. It evaluates precisely the integer
// schedule used by the circuits, including nearest-even arithmetic and caps.
// It must not be used to reconstruct production protected inputs.
func primitiveVFamilyReference(spec primitiveVFamilySpec, values []*big.Int, live, response, starts []bool, permutation []int) (*big.Int, bool, error) {
	shape, err := primitiveVFamilyInputShape(spec)
	reject := errors.New("primitive-v: family reference rejected")
	if err != nil || len(values) != spec.Rows || len(live) != spec.Rows || len(response) != spec.Rows || len(starts) != shape.PaddedRows || len(permutation) != spec.Rows {
		return nil, false, reject
	}
	if _, err := primitiveVPermutationControls(permutation); err != nil {
		return nil, false, reject
	}
	if !starts[0] {
		return new(big.Int), false, nil
	}
	x := make([]*big.Int, shape.PaddedRows)
	v := make([]bool, shape.PaddedRows)
	y := make([]bool, shape.PaddedRows)
	capQ := new(big.Int).Lsh(big.NewInt(spec.Cap), 64)
	for i := range x {
		x[i] = new(big.Int)
		if i < spec.Rows {
			j := permutation[i]
			if values[j] == nil {
				return nil, false, reject
			}
			if live[j] && new(big.Int).Abs(values[j]).Cmp(capQ) > 0 {
				return new(big.Int), false, nil
			}
			if live[j] {
				x[i].Set(values[j])
				v[i] = true
				y[i] = response[j]
			}
		}
	}
	counts := make([]int, shape.PaddedRows)
	count := 0
	for i := range x {
		if starts[i] {
			count = 0
		}
		if v[i] {
			count++
		}
		if count > spec.GroupCap {
			return new(big.Int), false, nil
		}
		counts[i] = count
	}
	loss := new(big.Int)
	switch spec.Family {
	case primitiveVCox:
		lse, err := primitiveVPrefixLogSumExpReference(x, v)
		if err != nil {
			return nil, false, reject
		}
		eventEta := new(big.Int)
		eventCount := int64(0)
		for i := range x {
			if starts[i] {
				eventEta.SetInt64(0)
				eventCount = 0
			}
			if v[i] && y[i] {
				eventEta.Add(eventEta, x[i])
				eventCount++
			}
			if i+1 == len(x) || starts[i+1] {
				loss.Add(loss, new(big.Int).Sub(eventEta, new(big.Int).Mul(big.NewInt(eventCount), lse[i])))
			}
		}
		bound := new(big.Int).Lsh(big.NewInt(int64(spec.Rows)*(2*spec.Cap+int64(bits.Len(uint(spec.Rows-1)))+1)), 64)
		primitiveVFamilyClamp(loss, new(big.Int).Neg(bound), new(big.Int))
	case primitiveVLMM:
		sums, err := primitiveVSegmentedReduceReference(x, starts)
		if err != nil {
			return nil, false, reject
		}
		for i := range x {
			if i+1 < len(x) && !starts[i+1] {
				continue
			}
			square := primitiveVMulQ64Reference(sums.SegmentPrefix[i], sums.SegmentPrefix[i])
			denominator := new(big.Int).Add(primitiveVScale, new(big.Int).Mul(big.NewInt(int64(counts[i])), spec.RhoQ64))
			correction := primitiveVRoundDivReference(new(big.Int).Mul(spec.RhoQ64, square), denominator)
			cluster := new(big.Int).Sub(sums.SegmentSquarePrefix[i], correction)
			maximum := new(big.Int).Lsh(big.NewInt(int64(counts[i])*spec.Cap*spec.Cap), 64)
			primitiveVFamilyClamp(cluster, new(big.Int), maximum)
			loss.Add(loss, cluster)
		}
	case primitiveVGLMM:
		nodes, weights := primitiveVGH5()
		scores := make([][]*big.Int, 5)
		for q := 0; q < 5; q++ {
			ll := make([]*big.Int, len(x))
			for i := range x {
				z := new(big.Int).Add(x[i], nodes[q])
				soft, err := primitiveVLogQ64Reference(new(big.Int).Add(primitiveVScale, primitiveVExpQ64Reference(z)))
				if err != nil {
					return nil, false, reject
				}
				ll[i] = new(big.Int).Neg(soft)
				if y[i] {
					ll[i].Add(ll[i], z)
				}
				if !v[i] {
					ll[i].SetInt64(0)
				}
			}
			sums, err := primitiveVSegmentedReduceReference(ll, starts)
			if err != nil {
				return nil, false, reject
			}
			logw, err := primitiveVLogQ64Reference(weights[q])
			if err != nil {
				return nil, false, reject
			}
			scores[q] = sums.SegmentPrefix
			for i := range x {
				scores[q][i].Add(scores[q][i], logw)
			}
		}
		for i := range x {
			if counts[i] == 0 || i+1 < len(x) && !starts[i+1] {
				continue
			}
			maximum := new(big.Int).Set(scores[0][i])
			for q := 1; q < 5; q++ {
				if scores[q][i].Cmp(maximum) > 0 {
					maximum.Set(scores[q][i])
				}
			}
			integral := new(big.Int)
			for q := 0; q < 5; q++ {
				integral.Add(integral, primitiveVExpNegativeQ64Reference(new(big.Int).Sub(scores[q][i], maximum)))
			}
			logIntegral, err := primitiveVLogQ64Reference(integral)
			if err != nil {
				return nil, false, reject
			}
			cluster := new(big.Int).Neg(new(big.Int).Add(maximum, logIntegral))
			upper := new(big.Int).Lsh(big.NewInt(int64(counts[i])*(spec.Cap+4)), 64)
			primitiveVFamilyClamp(cluster, new(big.Int), upper)
			loss.Add(loss, cluster)
		}
	}
	return loss, true, nil
}

func primitiveVFamilyClamp(value, lower, upper *big.Int) {
	if value.Cmp(lower) < 0 {
		value.Set(lower)
	}
	if value.Cmp(upper) > 0 {
		value.Set(upper)
	}
}
