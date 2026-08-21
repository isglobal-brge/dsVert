package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const exactGCMulPlanVersion = "dsvert-exact-gc-mul-plan-v3"

type exactGCMulPlanInput struct {
	BoundX        string `json:"bound_x"`
	BoundY        string `json:"bound_y"`
	FracBits      int    `json:"frac_bits"`
	FixedRingBits int    `json:"fixed_ring_bits,omitempty"`
}

type exactGCMulPlanOutput struct {
	Version            string `json:"version"`
	PlanID             string `json:"plan_id"`
	RingBits           int    `json:"ring_bits"`
	ContainerBits      int    `json:"container_bits"`
	FracBits           int    `json:"frac_bits"`
	BoundX             string `json:"bound_x"`
	BoundY             string `json:"bound_y"`
	TruncatedBound     string `json:"truncated_bound"`
	RoundingMode       string `json:"rounding_mode"`
	Backend            string `json:"backend"`
	MaxChunk           int    `json:"max_chunk"`
	RawProductHeadroom bool   `json:"raw_product_headroom"`
	OutputHeadroom     bool   `json:"output_headroom"`
}

func exactGCParseCanonicalPositive(value, name string) (*big.Int, error) {
	if value == "" || len(value) > exactGCMaxDecimalBoundDigits ||
		strings.HasPrefix(value, "+") ||
		(len(value) > 1 && value[0] == '0') {
		return nil, fmt.Errorf("exact-gc: invalid %s", name)
	}
	result := new(big.Int)
	if _, ok := result.SetString(value, 10); !ok || result.Sign() <= 0 ||
		result.String() != value {
		return nil, fmt.Errorf("exact-gc: invalid %s", name)
	}
	return result, nil
}

func exactGCCeilDiv(value, denominator *big.Int) *big.Int {
	result := new(big.Int).Add(
		new(big.Int).Set(value), new(big.Int).Sub(denominator, big.NewInt(1)))
	return result.Quo(result, denominator)
}

func exactGCPlanMul(input exactGCMulPlanInput) (exactGCMulPlanOutput, error) {
	boundX, err := exactGCParseCanonicalPositive(input.BoundX, "x bound")
	if err != nil {
		return exactGCMulPlanOutput{}, err
	}
	boundY, err := exactGCParseCanonicalPositive(input.BoundY, "y bound")
	if err != nil {
		return exactGCMulPlanOutput{}, err
	}
	if input.FracBits < 0 || input.FracBits >= exactGCMaxRingBits {
		return exactGCMulPlanOutput{}, fmt.Errorf("exact-gc: invalid fractional-bit count")
	}
	if input.FixedRingBits != 0 &&
		(input.FixedRingBits < 63 || input.FixedRingBits > exactGCMaxRingBits) {
		return exactGCMulPlanOutput{}, fmt.Errorf("exact-gc: invalid fixed ring")
	}

	product := new(big.Int).Mul(boundX, boundY)
	denominator := new(big.Int).Lsh(big.NewInt(1), uint(input.FracBits))
	truncated := exactGCCeilDiv(product, denominator)
	ringBits := input.FixedRingBits
	if ringBits == 0 {
		ringBits = 63
		for _, value := range []*big.Int{boundX, boundY, truncated} {
			if required := value.BitLen() + 1; required > ringBits {
				ringBits = required
			}
		}
		if input.FracBits+1 > ringBits {
			ringBits = input.FracBits + 1
		}
	}
	if ringBits <= exactGCMaxRingBits && input.FracBits < ringBits {
		maxSigned := exactGCMaxSigned(ringBits)
		if boundX.Cmp(maxSigned) <= 0 && boundY.Cmp(maxSigned) <= 0 &&
			truncated.Cmp(maxSigned) <= 0 {
			rawHeadroom := product.Cmp(maxSigned) <= 0
			backend := exactGCMulBackendDirect
			maxChunk := exactGCMaxDirectMulChunk(ringBits)
			if ringBits == 127 && input.FracBits > 0 && rawHeadroom {
				backend = exactGCMulBackendHybrid
				maxChunk = exactGCMaxHybridVectorLen
			}
			if maxChunk > 0 {
				canonical := strings.Join([]string{
					exactGCMulPlanVersion,
					strconv.Itoa(ringBits),
					strconv.Itoa(input.FracBits),
					boundX.String(), boundY.String(), truncated.String(),
					"floor",
					string(backend), strconv.Itoa(maxChunk),
				}, "\x00")
				digest := sha256.Sum256([]byte(canonical))
				return exactGCMulPlanOutput{
					Version:  exactGCMulPlanVersion,
					PlanID:   hex.EncodeToString(digest[:]),
					RingBits: ringBits, ContainerBits: exactGCTypeBits(ringBits),
					FracBits: input.FracBits,
					BoundX:   boundX.String(), BoundY: boundY.String(),
					TruncatedBound: truncated.String(), RoundingMode: "floor",
					Backend:  string(backend),
					MaxChunk: maxChunk, RawProductHeadroom: rawHeadroom,
					OutputHeadroom: true,
				}, nil
			}
		}
	}
	return exactGCMulPlanOutput{}, fmt.Errorf(
		"exact-gc: no ring in [63,%d] proves operand and truncated-output headroom within the circuit resource policy",
		exactGCMaxRingBits)
}

func handleExactGCMulPlan() {
	var input exactGCMulPlanInput
	mpcReadInput(&input)
	result, err := exactGCPlanMul(input)
	if err != nil {
		outputError("exact-gc multiplication planning failed")
		return
	}
	mpcWriteOutput(result)
}
