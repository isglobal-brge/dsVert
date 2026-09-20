package main

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Fixed-length vectors preserve private segment count and boundaries. Tail-only
// segment results are zero in every nonterminal position and must remain secret.
type primitiveVReductionNames struct {
	Prefix, SegmentPrefix, SegmentSquarePrefix, SegmentSums, SegmentSquares, SegmentCounts []string
	Valid                                                                                  string
}

// primitiveVEmitSegmentedReduce emits a fixed schedule over already permuted
// q64 words and boolean boundary expressions. values must have magnitude <=2^24
// in natural units and length<=16384; sum-of-squares products then fit int192.
// The caller validates encoded boundary bits and incorporates Valid in its final
// secret validity AND. Expression strings are public compiler-generated names.
func primitiveVEmitSegmentedReduce(dst *strings.Builder, prefix string, values, starts []string) primitiveVReductionNames {
	n := len(values)
	if n == 0 || n > 16384 || len(starts) != n {
		panic("primitive-v internal reduction shape rejected")
	}
	r := primitiveVReductionNames{
		Prefix: make([]string, n), SegmentPrefix: make([]string, n), SegmentSquarePrefix: make([]string, n),
		SegmentSums: make([]string, n), SegmentSquares: make([]string, n), SegmentCounts: make([]string, n), Valid: prefix + "Valid",
	}
	fmt.Fprintf(dst, "%s := (%s)\n", r.Valid, starts[0])
	for i := 0; i < n; i++ {
		r.Prefix[i] = fmt.Sprintf("%sPrefix%d", prefix, i)
		r.SegmentPrefix[i] = fmt.Sprintf("%sSegment%d", prefix, i)
		r.SegmentSquarePrefix[i] = fmt.Sprintf("%sSquare%d", prefix, i)
		r.SegmentCounts[i] = fmt.Sprintf("%sCount%d", prefix, i)
		r.SegmentSums[i] = fmt.Sprintf("%sTail%d", prefix, i)
		r.SegmentSquares[i] = fmt.Sprintf("%sSquareTail%d", prefix, i)
		fmt.Fprintf(dst, "%s := %s\n%s := %s\n%s := primitiveVMulQ64(%s,%s)\n%s := %s-%s+1\n", r.Prefix[i], values[i], r.SegmentPrefix[i], values[i], r.SegmentSquarePrefix[i], values[i], values[i], r.SegmentCounts[i], values[i], values[i])
		if i > 0 {
			fmt.Fprintf(dst, "%s = %s+%s\nif !(%s) {\n%s = %s+%s\n%s = %s+%s\n%s = %s+1\n}\n", r.Prefix[i], r.Prefix[i], r.Prefix[i-1], starts[i], r.SegmentPrefix[i], r.SegmentPrefix[i], r.SegmentPrefix[i-1], r.SegmentSquarePrefix[i], r.SegmentSquarePrefix[i], r.SegmentSquarePrefix[i-1], r.SegmentCounts[i], r.SegmentCounts[i-1])
		}
		fmt.Fprintf(dst, "%s := %s\n%s := %s\n", r.SegmentSums[i], r.SegmentPrefix[i], r.SegmentSquares[i], r.SegmentSquarePrefix[i])
		if i < n-1 {
			fmt.Fprintf(dst, "if !(%s) { %s=0\n %s=0 }\n", starts[i+1], r.SegmentSums[i], r.SegmentSquares[i])
		}
	}
	return r
}

type primitiveVReductionReference struct {
	Prefix, SegmentPrefix, SegmentSquarePrefix, SegmentSums, SegmentSquares []*big.Int
	SegmentCounts                                                           []int
}

func primitiveVSegmentedReduceReference(values []*big.Int, starts []bool) (primitiveVReductionReference, error) {
	n := len(values)
	r := primitiveVReductionReference{}
	if n == 0 || n > 16384 || len(starts) != n || !starts[0] {
		return r, errors.New("primitive-v reduction input rejected")
	}
	r = primitiveVReductionReference{make([]*big.Int, n), make([]*big.Int, n), make([]*big.Int, n), make([]*big.Int, n), make([]*big.Int, n), make([]int, n)}
	bound := new(big.Int).Lsh(big.NewInt(1), 88)
	for i, v := range values {
		if v == nil || new(big.Int).Abs(v).Cmp(bound) > 0 {
			return primitiveVReductionReference{}, errors.New("primitive-v reduction input rejected")
		}
		r.Prefix[i] = new(big.Int).Set(v)
		r.SegmentPrefix[i] = new(big.Int).Set(v)
		r.SegmentSquarePrefix[i] = primitiveVMulQ64Reference(v, v)
		r.SegmentCounts[i] = 1
		if i > 0 {
			r.Prefix[i].Add(r.Prefix[i], r.Prefix[i-1])
			if !starts[i] {
				r.SegmentPrefix[i].Add(r.SegmentPrefix[i], r.SegmentPrefix[i-1])
				r.SegmentSquarePrefix[i].Add(r.SegmentSquarePrefix[i], r.SegmentSquarePrefix[i-1])
				r.SegmentCounts[i] = r.SegmentCounts[i-1] + 1
			}
		}
		r.SegmentSums[i] = new(big.Int)
		r.SegmentSquares[i] = new(big.Int)
		if i == n-1 || starts[i+1] {
			r.SegmentSums[i].Set(r.SegmentPrefix[i])
			r.SegmentSquares[i].Set(r.SegmentSquarePrefix[i])
		}
	}
	return r, nil
}

type primitiveVPrefixLSENames struct {
	ExponentSums, PrefixLSE []string
	Valid                   string
}

// Every live eta must be in [-17,17]. Empty prefixes are represented by zero,
// and the companion ExponentSums zero identifies the empty sentinel secretly.
// The numerical domain validation is folded into Valid; no plaintext bit leaks.
func primitiveVEmitPrefixLogSumExp(dst *strings.Builder, prefix string, values, live []string) primitiveVPrefixLSENames {
	n := len(values)
	if n == 0 || n > 16384 || len(live) != n {
		panic("primitive-v internal prefix shape rejected")
	}
	r := primitiveVPrefixLSENames{make([]string, n), make([]string, n), prefix + "Valid"}
	fmt.Fprintf(dst, "%s := true\n", r.Valid)
	cap := new(big.Int).Mul(big.NewInt(17), primitiveVScale)
	for i := 0; i < n; i++ {
		r.ExponentSums[i] = fmt.Sprintf("%sExpSum%d", prefix, i)
		r.PrefixLSE[i] = fmt.Sprintf("%sLSE%d", prefix, i)
		safe := fmt.Sprintf("%sSafe%d", prefix, i)
		fmt.Fprintf(dst, "%s := %s\nif %s < -int192(%s) || %s > int192(%s) { %s=false\n %s=0 }\n", safe, values[i], safe, cap, safe, cap, r.Valid, safe)
		fmt.Fprintf(dst, "%s := primitiveVExpQ64(%s)\nif !(%s) { %s=0 }\n", r.ExponentSums[i], safe, live[i], r.ExponentSums[i])
		if i > 0 {
			fmt.Fprintf(dst, "%s = %s+%s\n", r.ExponentSums[i], r.ExponentSums[i], r.ExponentSums[i-1])
		}
		fmt.Fprintf(dst, "%s := primitiveVLogQ64(%s)\nif %s == 0 { %s=0 }\n", r.PrefixLSE[i], r.ExponentSums[i], r.ExponentSums[i], r.PrefixLSE[i])
	}
	return r
}

func primitiveVPrefixLogSumExpReference(values []*big.Int, live []bool) ([]*big.Int, error) {
	if len(values) == 0 || len(values) > 16384 || len(values) != len(live) {
		return nil, errors.New("primitive-v prefix input rejected")
	}
	cap := new(big.Int).Mul(big.NewInt(17), primitiveVScale)
	out := make([]*big.Int, len(values))
	sum := new(big.Int)
	for i, v := range values {
		if v == nil || new(big.Int).Abs(v).Cmp(cap) > 0 {
			return nil, errors.New("primitive-v prefix input rejected")
		}
		if live[i] {
			sum.Add(sum, primitiveVExpQ64Reference(v))
		}
		if sum.Sign() == 0 {
			out[i] = new(big.Int)
		} else {
			var err error
			out[i], err = primitiveVLogQ64Reference(sum)
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
