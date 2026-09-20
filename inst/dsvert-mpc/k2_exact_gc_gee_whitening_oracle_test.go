package main

import "math/big"

// Independent integer assembly for the new profile. It does not call the
// producer's operand maps, reductions or boundary emitters. Eta inputs are
// complete q64 dots (the source boundary is separately checked at f100).
func groupedGEEWhiteningOracle(s groupedGEESpec, rows []groupedGEERow, clusterCap int64) ([]int64, bool) {
	n, d := s.Slots, s.Predictors+1
	tri := d * (d + 1) / 2
	out := make([]int64, 1+2*tri)
	if groupedGEEValidate(s) != nil || len(rows) != n {
		return out, false
	}
	live := []int{}
	base := make([][]*big.Int, n)
	loss := new(big.Int)
	for i, row := range rows {
		base[i] = make([]*big.Int, d+1)
		for k := range base[i] {
			base[i][k] = new(big.Int)
		}
		if row.Live != 0 && row.Live != 1 {
			return out, false
		}
		if row.Live == 0 {
			continue
		}
		if row.EtaQ64 == nil || new(big.Int).Abs(row.EtaQ64).Cmp(new(big.Int).Lsh(big.NewInt(4), 64)) > 0 || row.Outcome < 0 || row.Outcome > s.MaxOutcome || len(row.FeaturesF50) != s.Predictors {
			return out, false
		}
		eta := primitiveVRoundDivReference(row.EtaQ64, new(big.Int).Lsh(big.NewInt(1), 48)).Int64()
		x := []int64{65536}
		for _, f := range row.FeaturesF50 {
			if f == nil || f.Sign() < 0 || f.Cmp(new(big.Int).Lsh(big.NewInt(1), 50)) > 0 {
				return out, false
			}
			x = append(x, primitiveVRoundDivReference(f, new(big.Int).Lsh(big.NewInt(1), 34)).Int64())
		}
		var mu, a, b, l int64
		if s.Family == "binomial" {
			mu, _ = groupedProfileEval("sigmoid", eta)
			a, _ = groupedProfileEval("sqrt_variance", eta)
			b, _ = groupedProfileEval("inverse_sqrt_variance", eta)
			l, _ = groupedProfileEval("softplus", eta)
		} else {
			mu, _ = groupedProfileEval("exp", eta)
			a, _ = groupedProfileEval("exp", groupedRoundDiv(eta, 2))
			b, _ = groupedProfileEval("exp", -groupedRoundDiv(eta, 2))
			l = mu + groupedGEEWhiteningLogFactorial[row.Outcome]
		}
		loss.Add(loss, new(big.Int).Lsh(big.NewInt(l-row.Outcome*eta), 16))
		for k := 0; k < d; k++ {
			base[i][k].Mul(big.NewInt(x[k]), big.NewInt(a))
		}
		base[i][d].Mul(big.NewInt(row.Outcome*65536-mu), big.NewInt(b))
		live = append(live, i)
	}
	one := new(big.Int).Lsh(big.NewInt(1), 64)
	alpha, c, ar := groupedGEEWhiteningConstants(s)
	w := make([][]*big.Int, n)
	factors := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		w[i] = make([]*big.Int, n)
		factors[i] = make([]*big.Int, d+1)
		for j := 0; j < n; j++ {
			w[i][j] = new(big.Int)
		}
	}
	for at, i := range live {
		switch s.Correlation {
		case "independence":
			w[i][i].Set(one)
		case "exchangeable":
			for _, j := range live {
				w[i][j].Set(c[len(live)])
			}
			w[i][i].Add(w[i][i], alpha)
		case "ar1":
			if at == 0 {
				w[i][i].Set(one)
			} else {
				prev := live[at-1]
				w[i][i].Set(ar[i-prev][0])
				w[i][prev].Set(ar[i-prev][1])
			}
		}
	}
	for i := 0; i < n; i++ {
		for k := 0; k <= d; k++ {
			sum := new(big.Int)
			for j := 0; j < n; j++ {
				sum.Add(sum, new(big.Int).Mul(w[i][j], base[j][k]))
			}
			factors[i][k] = primitiveVRoundDivReference(sum, new(big.Int).Lsh(big.NewInt(1), 32))
		}
	}
	quant := func(x *big.Int, shift int) *big.Int {
		return primitiveVRoundDivReference(x, new(big.Int).Lsh(big.NewInt(1), uint(shift)))
	}
	clamp := func(x *big.Int, lo, hi int64) int64 {
		if x.Cmp(big.NewInt(lo)) < 0 {
			return lo
		}
		if x.Cmp(big.NewInt(hi)) > 0 {
			return hi
		}
		return x.Int64()
	}
	out[0] = clamp(quant(loss, 32-s.GridBits), 0, clusterCap)
	score := make([]int64, d)
	clip := new(big.Int).Lsh(big.NewInt(s.ScoreClipQ16), 112)
	for k := 0; k < d; k++ {
		v := new(big.Int)
		for i := 0; i < n; i++ {
			v.Add(v, new(big.Int).Mul(factors[i][k], factors[i][d]))
		}
		if v.Cmp(clip) > 0 {
			v.Set(clip)
		}
		minus := new(big.Int).Neg(clip)
		if v.Cmp(minus) < 0 {
			v.Set(minus)
		}
		score[k] = quant(v, 112).Int64()
	}
	idx := 0
	shift, upper := int64(0), s.BreadCap
	if s.Correlation != "independence" {
		shift = s.BreadCap
		upper *= 2
	}
	for l := 0; l < d; l++ {
		for k := 0; k <= l; k++ {
			v := new(big.Int)
			for i := 0; i < n; i++ {
				v.Add(v, new(big.Int).Mul(factors[i][k], factors[i][l]))
			}
			out[1+idx] = clamp(new(big.Int).Add(quant(v, 128-s.GridBits), big.NewInt(shift)), 0, upper)
			meat := big.NewInt(score[k]*score[l] + s.ScoreClipQ16*s.ScoreClipQ16)
			out[1+tri+idx] = quant(meat, 32-s.GridBits).Int64()
			idx++
		}
	}
	return out, true
}
