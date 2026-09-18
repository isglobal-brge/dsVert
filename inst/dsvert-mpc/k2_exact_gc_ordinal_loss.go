package main

import (
	"fmt"
	"math/big"
	"strings"
)

const exactGCOrdinalProfileV1 = "cross-grid-ordinal-piecewise-q16-v1"

func exactGCRegisterOrdinalLossV1() exactGCFamilyLossRegistration {
	return exactGCFamilyLossRegistration{"ordinal", "ordinal_grid_cross_v1", exactGCOrdinalProfileV1, "fc0d85381d6effb30776848ccf301f4b9b18fc5dc55bdc80a8503f7d8916fcef", "b480edd4ab1ad8f2403026f2d718bfd093068816160a893ee0f7935056251f67", exactGCOrdinalLossSource}
}

func exactGCOrdinalThresholds(s exactGCFamilyLossSpec) ([]*big.Int, error) {
	if exactGCFamilyLossValidate(s) != nil || len(s.Thresholds) != s.Classes-1 {
		return nil, exactGCFamilyLossReject()
	}
	out := make([]*big.Int, len(s.Thresholds))
	bound := new(big.Int).Lsh(big.NewInt(8), 50)
	gap := new(big.Int).Lsh(big.NewInt(1), 46)
	for i, raw := range s.Thresholds {
		if len(raw) > 18 {
			return nil, exactGCFamilyLossReject()
		}
		n, ok := new(big.Int).SetString(raw, 10)
		if !ok || n.String() != raw || new(big.Int).Abs(n).Cmp(bound) > 0 {
			return nil, exactGCFamilyLossReject()
		}
		if i > 0 && new(big.Int).Sub(n, out[i-1]).Cmp(gap) < 0 {
			return nil, exactGCFamilyLossReject()
		}
		out[i] = n
	}
	return out, nil
}

func exactGCOrdinalLossSource(s exactGCFamilyLossSpec) (string, error) {
	thresholds, err := exactGCOrdinalThresholds(s)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(exactGCFamilyMathSource())
	b.WriteString("func main(g [5]uint192,e [3]uint192) [2]uint192 {\ndot:=g[0]+e[0]\ny:=g[1]+e[1]\nvalid:=g[2]+e[2]\n")
	bound := new(big.Int).Lsh(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(8), 50), big.NewInt(9)), 50)
	fmt.Fprintf(&b, "guard:=y<uint192(%d) && valid<=uint192(1) && abs192(dot)<=uint192(%s)\nif !guard { dot=uint192(0) }\neta:=eta16(dot)\nloss:=uint32(0)\n", s.Classes, bound)
	encoded := make([]uint32, len(thresholds))
	for i, c := range thresholds {
		encoded[i] = uint32(exactGCOrdinalPublicRound(c, new(big.Int).Lsh(big.NewInt(1), 34)).Int64())
	}
	if s.Classes == 2 {
		fmt.Fprintf(&b, "x:=uint32(%d)-eta\nloss=soft16(x)\nif y==uint192(0) { loss=loss-x }\n", encoded[0])
	} else {
		fmt.Fprintf(&b, "hi:=uint32(%d)\nlo:=uint32(0)\ngaplog:=uint32(0)\n", encoded[0])
		for k := 1; k < s.Classes-1; k++ {
			gap := new(big.Int).Lsh(new(big.Int).Sub(thresholds[k], thresholds[k-1]), 14)
			// Old q64 approximation is used only for public signed threshold metadata.
			gaplog := uint32(exactGCOrdinalPublicRound(exactGCOrdinalPublicGapLog(gap), new(big.Int).Lsh(big.NewInt(1), 48)).Int64())
			fmt.Fprintf(&b, "if y==uint192(%d) { hi=uint32(%d); lo=uint32(%d); gaplog=uint32(%d) }\n", k, encoded[k], encoded[k-1], gaplog)
		}
		fmt.Fprintf(&b, "if y==uint192(%d) { hi=uint32(%d) }\n", s.Classes-1, encoded[len(encoded)-1])
		b.WriteString("xh:=hi-eta\nxl:=lo-eta\nsh:=soft16(xh)\nsl:=soft16(xl)\nloss=sh+sl-xh-gaplog\nif y==uint192(0) { loss=sh-xh }\n")
		fmt.Fprintf(&b, "if y==uint192(%d) { loss=sh }\n", s.Classes-1)
	}
	exactGCFamilyFinishSource(&b, s, 3)
	return strings.ReplaceAll(b.String(), ";", "\n"), nil
}

// These exact host routines generate constants from signed PUBLIC threshold
// gaps. Row-loss references live exclusively in _test.go / tagged test files.
func exactGCOrdinalPublicRound(x, d *big.Int) *big.Int {
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(new(big.Int).Abs(x), d, r)
	cmp := new(big.Int).Lsh(r, 1).Cmp(d)
	if cmp > 0 || (cmp == 0 && q.Bit(0) != 0) {
		q.Add(q, big.NewInt(1))
	}
	if x.Sign() < 0 {
		q.Neg(q)
	}
	return q
}
func exactGCOrdinalPublicExp(x *big.Int) *big.Int {
	q := new(big.Int).Lsh(big.NewInt(1), 64)
	t := exactGCOrdinalPublicRound(x, big.NewInt(17))
	b1, b2 := big.NewInt(0), big.NewInt(0)
	for i := len(exactGCFamilyExpQuarterQ64) - 1; i >= 1; i-- {
		v := new(big.Int).Mul(new(big.Int).Lsh(t, 1), b1)
		next := new(big.Int).Sub(new(big.Int).Add(exactGCFamilyInteger(exactGCFamilyExpQuarterQ64[i]), exactGCOrdinalPublicRound(v, q)), b2)
		b2, b1 = b1, next
	}
	v := new(big.Int).Sub(new(big.Int).Add(exactGCFamilyInteger(exactGCFamilyExpQuarterQ64[0]), exactGCOrdinalPublicRound(new(big.Int).Mul(t, b1), q)), b2)
	for i := 0; i < 2; i++ {
		v = exactGCOrdinalPublicRound(new(big.Int).Mul(v, v), q)
	}
	return v
}
func exactGCOrdinalPublicLog(x *big.Int) *big.Int {
	q := new(big.Int).Lsh(big.NewInt(1), 64)
	exponent := x.BitLen() - 65
	m := new(big.Int)
	if exponent < 0 {
		m.Lsh(x, uint(-exponent))
	} else {
		m = exactGCOrdinalPublicRound(x, new(big.Int).Lsh(big.NewInt(1), uint(exponent)))
	}
	z := exactGCOrdinalPublicRound(new(big.Int).Mul(new(big.Int).Sub(m, q), q), new(big.Int).Add(m, q))
	z2 := exactGCOrdinalPublicRound(new(big.Int).Mul(z, z), q)
	term, sum := new(big.Int).Set(z), new(big.Int).Set(z)
	for i := 1; i < 24; i++ {
		term = exactGCOrdinalPublicRound(new(big.Int).Mul(term, z2), q)
		sum.Add(sum, exactGCOrdinalPublicRound(term, big.NewInt(int64(2*i+1))))
	}
	return new(big.Int).Add(new(big.Int).Lsh(sum, 1), new(big.Int).Mul(big.NewInt(int64(exponent)), exactGCFamilyInteger(exactGCFamilyLog2Q64)))
}
func exactGCOrdinalPublicGapLog(gap *big.Int) *big.Int {
	q := new(big.Int).Lsh(big.NewInt(1), 64)
	return exactGCOrdinalPublicLog(new(big.Int).Sub(q, exactGCOrdinalPublicExp(new(big.Int).Neg(gap))))
}
