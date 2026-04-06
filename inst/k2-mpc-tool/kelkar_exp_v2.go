// kelkar_exp_v2.go: Kelkar secure exp — direct copy from validated mhe-tool.
//
// Uses Ring63 internally (same as mhe-tool) to avoid any subtle arithmetic
// differences with RingParams.

package main

import (
	"math"
	"math/big"
)

const kelkarLog2Ev2 = 1.4426950408889634073599
const kelkarFracBits = 20
const kelkarModulus = uint64(1) << 63
const kelkarFracMul = uint64(1) << kelkarFracBits
const kelkarIntRingMod = uint64(1) << (63 - kelkarFracBits)
const kelkarPrimeQ = uint64(2305843009213693951)
const kelkarExpBound = 10

func kelkarFromDouble(x float64) uint64 {
	if x >= 0 {
		return uint64(x*float64(kelkarFracMul)+0.5) % kelkarModulus
	}
	abs := uint64(-x*float64(kelkarFracMul) + 0.5)
	return (kelkarModulus - abs%kelkarModulus) % kelkarModulus
}

func kelkarAdd(a, b uint64) uint64 { return (a + b) % kelkarModulus }
func kelkarSub(a, b uint64) uint64 { return (kelkarModulus + a - b) % kelkarModulus }

func kelkarTruncMul(a, b uint64) uint64 {
	prod := new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	prod.Rsh(prod, kelkarFracBits)
	prod.Mod(prod, new(big.Int).SetUint64(kelkarModulus))
	return prod.Uint64()
}

type KelkarMTAv2 struct{ Alpha0, Beta0, Alpha1, Beta1 uint64 }

func kelkarGenMTAv2() KelkarMTAv2 {
	q := kelkarPrimeQ
	qBig := new(big.Int).SetUint64(q)
	a0, a1, b0 := randMod(q), randMod(q), randMod(q)
	aa := mulMod(a0, a1, q)
	target := (q + 1 - aa) % q
	b0Inv := new(big.Int).ModInverse(new(big.Int).SetUint64(b0), qBig)
	b1 := new(big.Int).Mul(new(big.Int).SetUint64(target), b0Inv)
	b1.Mod(b1, qBig)
	return KelkarMTAv2{a0, b0, a1, b1.Uint64()}
}

func KelkarExpLocalV2(rp RingParams, x0, x1 []uint64) (exp0, exp1 []uint64) {
	q := kelkarPrimeQ
	n := len(x0)
	b2Bound := int(math.Ceil(kelkarLog2Ev2*float64(kelkarExpBound))) + 1
	log2eFP := kelkarFromDouble(kelkarLog2Ev2)
	adderFP := uint64(b2Bound) * kelkarFracMul
	twoPowB2 := expMod(2, uint64(b2Bound), q)

	// P1 correction
	corrBig := new(big.Int).Mul(new(big.Int).SetUint64(log2eFP), new(big.Int).SetUint64(kelkarModulus))
	corrBig.Div(corrBig, new(big.Int).SetUint64(kelkarFracMul))
	corrBig.Mod(corrBig, new(big.Int).SetUint64(kelkarModulus))
	corr := corrBig.Uint64()

	mta := kelkarGenMTAv2()

	// P0 round 1
	mult0 := make([]uint64, n)
	msg0 := make([]uint64, n)
	for i := 0; i < n; i++ {
		base2 := kelkarTruncMul(x0[i], log2eFP)
		posBase2 := kelkarAdd(base2, adderFP)
		intPart := posBase2 / kelkarFracMul
		fracPart := float64(posBase2%kelkarFracMul) / float64(kelkarFracMul)
		intInQ := (intPart + (q - 1) - kelkarIntRingMod) % (q - 1)
		intExp := expMod(2, intInQ, q)
		fracExpFP := uint64(math.Pow(2.0, fracPart)*float64(kelkarFracMul) + 0.5)
		mult0[i] = mulMod(intExp, fracExpFP, q)
		msg0[i] = mulMod(mta.Beta0, mult0[i], q)
	}

	// P1 round 1
	mult1 := make([]uint64, n)
	msg1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		firstTerm := kelkarTruncMul(x1[i], log2eFP)
		base2 := kelkarSub(firstTerm, corr)
		intPart := base2 / kelkarFracMul
		fracPart := float64(base2%kelkarFracMul) / float64(kelkarFracMul)
		intInQ := intPart % (q - 1)
		intExp := expMod(2, intInQ, q)
		fracExpFP := uint64(math.Pow(2.0, fracPart)*float64(kelkarFracMul) + 0.5)
		mult1[i] = mulMod(intExp, fracExpFP, q)
		msg1[i] = mulMod(mta.Alpha1, mult1[i], q)
	}

	// P0 output
	exp0 = make([]uint64, n)
	for i := 0; i < n; i++ {
		r0 := mulMod(mulMod(mult0[i], mta.Alpha0, q), msg1[i], q)
		negR0 := (q - r0) % q
		divided := negR0 / (kelkarFracMul * twoPowB2)
		shareQ := (q - divided) % q
		exp0[i] = (shareQ + kelkarModulus - q) % kelkarModulus
	}

	// P1 output
	exp1 = make([]uint64, n)
	for i := 0; i < n; i++ {
		r1 := mulMod(mulMod(mult1[i], mta.Beta1, q), msg0[i], q)
		exp1[i] = r1 / (kelkarFracMul * twoPowB2)
	}

	return
}
