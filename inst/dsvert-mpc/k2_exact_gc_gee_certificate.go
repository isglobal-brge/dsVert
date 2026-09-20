package main

import "math/big"

// Natural-scale, per-cluster coordinate errors relative to the equally
// clamped real likelihood / bread / clipped-meat statistic. Exact rational
// propagation; no empirical or provisional error allowance is used.
type groupedGEECertificate struct {
	Profile                                   string
	Likelihood, Bread, Meat, FactorU, FactorZ *big.Rat
}

func groupedGEEWhiteningCertificate(s groupedGEESpec) (*groupedGEECertificate, error) {
	if groupedGEEValidate(s) != nil {
		return nil, primitiveVError()
	}
	r := func(a, b int64) *big.Rat { return big.NewRat(a, b) }
	add := func(a, b *big.Rat) *big.Rat { return new(big.Rat).Add(a, b) }
	mul := func(a, b *big.Rat) *big.Rat { return new(big.Rat).Mul(a, b) }
	halfULP := r(1, 131072)
	// Includes original f50 feature/coefficient encoding and f100->q64 slack
	// for the signed p<=3, |beta_j|<=8 contract, then q16 argument rounding.
	etaError := add(halfULP, r(1, 1000000000000))
	featureError := add(halfULP, r(1, 2251799813685248))
	var muError, aError, bError, lossError, A, Z *big.Rat
	if s.Family == "binomial" {
		muError = add(r(69, 327680), mul(r(1, 4), etaError))
		aError = add(r(17, 65536), mul(r(1, 4), etaError))
		bError = add(r(257, 65536), mul(r(4, 1), etaError))
		lossError = add(r(33, 65536), etaError)
		A, Z = r(1, 2), r(8, 1)
	} else {
		muError = add(r(55, 10000), mul(r(55, 1), etaError))
		aError = add(r(55, 10000), mul(r(8, 1), add(mul(r(1, 2), etaError), halfULP)))
		bError = new(big.Rat).Set(aError)
		lossError = add(add(r(55, 10000), mul(r(59, 1), etaError)), halfULP)
		A, Z = r(8, 1), r(40, 1)
	}
	eu := add(aError, mul(add(A, aError), featureError))
	residualBound := r(1, 1)
	if s.Family == "poisson" {
		residualBound = r(55, 1)
	}
	ez := add(mul(residualBound, bError), mul(add(r(8, 1), bError), muError))
	// All exact W row absolute sums <=4. Each q64 coefficient differs by
	// <10*2^-64, including exchangeable count correction / AR1 gap rounding.
	u64 := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 64))
	wc := mul(r(int64(10*s.Slots), 1), u64)
	Eu := add(add(mul(r(4, 1), eu), mul(wc, add(A, eu))), mul(r(1, 2), u64))
	Ez := add(add(mul(r(4, 1), ez), mul(wc, add(Z, ez))), mul(r(1, 2), u64))
	U, V := mul(r(4, 1), A), mul(r(4, 1), Z)
	rows := r(int64(s.Slots), 1)
	score := mul(rows, add(add(mul(U, Ez), mul(V, Eu)), mul(Eu, Ez)))
	bread := mul(rows, add(mul(mul(r(2, 1), U), Eu), mul(Eu, Eu)))
	C := r(s.ScoreClipQ16, 65536)
	meat := mul(mul(r(2, 1), C), add(score, halfULP))
	maxMeatError := mul(r(2, 1), mul(C, C))
	if meat.Cmp(maxMeatError) > 0 {
		meat = maxMeatError
	}
	q := r(1, int64(2)<<uint(s.GridBits))
	return &groupedGEECertificate{groupedGEEWhiteningProfile, add(mul(rows, lossError), q), add(bread, q), add(meat, q), Eu, Ez}, nil
}
