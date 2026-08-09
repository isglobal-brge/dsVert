package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

const (
	k2Ring63Bits        = 63
	k2Ring127Bits       = 127
	k2Ring63DcfElemSize = 1671
)

// normalizeRingAndFracBits validates the public fixed-point configuration.
// A zero frac_bits value means that the caller omitted it and selects the
// ring-specific default. Negative and out-of-range values are rejected.
func normalizeRingAndFracBits(ring string, fracBits int) (string, int, error) {
	if ring == "" {
		ring = "ring63"
	}
	if ring != "ring63" && ring != "ring127" {
		return "", 0, fmt.Errorf("unknown ring %s", ring)
	}
	if fracBits == 0 {
		if ring == "ring127" {
			return ring, K2DefaultFracBits127, nil
		}
		return ring, K2DefaultFracBits, nil
	}
	if fracBits < 0 {
		return "", 0, fmt.Errorf("frac_bits must be positive")
	}
	maxFracBits := k2Ring63Bits - 1
	if ring == "ring127" {
		maxFracBits = k2Ring127Bits - 1
	}
	if fracBits > maxFracBits {
		return "", 0, fmt.Errorf("frac_bits exceeds %s capacity", ring)
	}
	return ring, fracBits, nil
}

func normalizeRing127FracBits(fracBits int) (int, error) {
	_, normalized, err := normalizeRingAndFracBits("ring127", fracBits)
	return normalized, err
}

func validateFinite(name string, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("%s must be finite", name)
	}
	return nil
}

// roundedScaledMagnitude returns round(abs(value)*2^fracBits), matching the
// fixed-point encoders' round-to-nearest, halves-away-from-zero convention.
func roundedScaledMagnitude(value float64, fracBits int) *big.Int {
	abs := math.Abs(value)
	bf := new(big.Float).SetPrec(256).SetFloat64(abs)
	scale := new(big.Float).SetPrec(256).SetInt(
		new(big.Int).Lsh(big.NewInt(1), uint(fracBits)),
	)
	bf.Mul(bf, scale)
	bf.Add(bf, new(big.Float).SetPrec(256).SetFloat64(0.5))
	result, _ := bf.Int(nil)
	return result
}

// FromDoubleChecked encodes a public float without allowing NaN, infinity, or
// modular wrap to turn an out-of-domain number into an unrelated Ring63 value.
func (r Ring63) FromDoubleChecked(value float64) (uint64, error) {
	if err := validateFinite("value", value); err != nil {
		return 0, err
	}
	mag := roundedScaledMagnitude(value, r.FracBits)
	signLimit := new(big.Int).Lsh(big.NewInt(1), k2Ring63Bits-1)
	cmp := mag.Cmp(signLimit)
	if cmp > 0 || (cmp == 0 && !math.Signbit(value)) {
		return 0, fmt.Errorf("value is outside signed Ring63 range")
	}
	encoded := mag.Uint64()
	if math.Signbit(value) && encoded != 0 {
		return r.Neg(encoded), nil
	}
	return encoded, nil
}

// FromDoubleChecked is the Ring127 counterpart of Ring63.FromDoubleChecked.
func (r Ring127) FromDoubleChecked(value float64) (Uint128, error) {
	if err := validateFinite("value", value); err != nil {
		return Uint128{}, err
	}
	mag := roundedScaledMagnitude(value, r.FracBits)
	signLimit := new(big.Int).Lsh(big.NewInt(1), k2Ring127Bits-1)
	cmp := mag.Cmp(signLimit)
	if cmp > 0 || (cmp == 0 && !math.Signbit(value)) {
		return Uint128{}, fmt.Errorf("value is outside signed Ring127 range")
	}
	encoded := U128FromBig(mag)
	if math.Signbit(value) && encoded.Cmp(U128Zero()) != 0 {
		return r.Neg(encoded), nil
	}
	return encoded, nil
}

func encodeK2FloatToFP(input K2FloatToFPInput) (K2FloatToFPOutput, error) {
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		return K2FloatToFPOutput{}, err
	}
	if ringName == "ring127" {
		ring := NewRing127(fracBits)
		encoded := make([]Uint128, len(input.Values))
		for i, value := range input.Values {
			encoded[i], err = ring.FromDoubleChecked(value)
			if err != nil {
				return K2FloatToFPOutput{}, fmt.Errorf("values element %d %s", i, err)
			}
		}
		return K2FloatToFPOutput{FPData: Uint128VecToB64(encoded)}, nil
	}

	ring := NewRing63(fracBits)
	encoded := make([]uint64, len(input.Values))
	for i, value := range input.Values {
		encoded[i], err = ring.FromDoubleChecked(value)
		if err != nil {
			return K2FloatToFPOutput{}, fmt.Errorf("values element %d %s", i, err)
		}
	}
	return K2FloatToFPOutput{
		FPData: bytesToBase64(fpVecToBytes(ring63ToFP(encoded))),
	}, nil
}

func decodeBase64Records(value string, recordBytes, expected int) ([]byte, error) {
	if recordBytes <= 0 {
		return nil, fmt.Errorf("record size must be positive")
	}
	if expected < -1 {
		return nil, fmt.Errorf("expected record count must be non-negative or -1")
	}
	var raw []byte
	var err error
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding.Strict(),
		base64.URLEncoding.Strict(),
	} {
		raw, err = encoding.DecodeString(value)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("invalid base64")
	}
	if len(raw)%recordBytes != 0 {
		return nil, fmt.Errorf("payload has a partial %d byte record", recordBytes)
	}
	count := len(raw) / recordBytes
	if expected >= 0 && count != expected {
		return nil, fmt.Errorf("length mismatch got %d want %d", count, expected)
	}
	return raw, nil
}

func decodeRing63FPVector(value string, expected int) ([]uint64, error) {
	raw, err := decodeBase64Records(value, 8, expected)
	if err != nil {
		return nil, err
	}
	result := make([]uint64, len(raw)/8)
	minSigned := -int64(uint64(1) << 62)
	maxSigned := int64((uint64(1) << 62) - 1)
	for i := range result {
		wireValue := int64(binary.LittleEndian.Uint64(raw[i*8:]))
		// Ring63 FP values use the canonical signed wire interval
		// [-2^62, 2^62). ring63ToFP emits exactly this representation.
		if wireValue < minSigned || wireValue > maxSigned {
			return nil, fmt.Errorf("element %d is not canonical signed Ring63", i)
		}
		result[i] = uint64(wireValue) % (uint64(1) << 63)
	}
	return result, nil
}

// decodeRing63ResidueVector decodes fields whose protocol wire format is an
// unsigned Ring63 residue rather than the signed FixedPoint representation.
// Historical DCF masked values use this format.
func decodeRing63ResidueVector(value string, expected int) ([]uint64, error) {
	raw, err := decodeBase64Records(value, 8, expected)
	if err != nil {
		return nil, err
	}
	result := make([]uint64, len(raw)/8)
	for i := range result {
		result[i] = binary.LittleEndian.Uint64(raw[i*8:])
		if result[i] >= uint64(1)<<63 {
			return nil, fmt.Errorf("element %d is outside Ring63", i)
		}
	}
	return result, nil
}

func decodeRing127Vector(value string, expected int) ([]Uint128, error) {
	raw, err := decodeBase64Records(value, 16, expected)
	if err != nil {
		return nil, err
	}
	result := bytesToUint128Vec(raw)
	for i, element := range result {
		if element.Hi>>63 != 0 {
			return nil, fmt.Errorf("element %d is outside Ring127", i)
		}
	}
	return result, nil
}

func applyPublicBitMask63(shares, mask []uint64, ring Ring63) ([]uint64, error) {
	if len(shares) != len(mask) {
		return nil, fmt.Errorf("bit mask length mismatch")
	}
	// At frac_bits=62, 2^frac_bits is the Ring63 sign threshold and
	// represents -1, not +1. Never let that boundary alias pass as a bit.
	if ring.FracBits >= k2Ring63Bits-1 {
		return nil, fmt.Errorf("frac_bits cannot encode public bit 1 in signed Ring63")
	}
	result := make([]uint64, len(shares))
	for i, bit := range mask {
		switch bit {
		case 0:
			result[i] = 0
		case ring.FracMul:
			result[i] = shares[i]
		default:
			return nil, fmt.Errorf("bit mask element %d is not encoded 0 or 1", i)
		}
	}
	return result, nil
}

func applyPublicBitMask127(shares, mask []Uint128, ring Ring127) ([]Uint128, error) {
	if len(shares) != len(mask) {
		return nil, fmt.Errorf("bit mask length mismatch")
	}
	// Ring127 has the same signed-boundary alias at frac_bits=126.
	if ring.FracBits >= k2Ring127Bits-1 {
		return nil, fmt.Errorf("frac_bits cannot encode public bit 1 in signed Ring127")
	}
	result := make([]Uint128, len(shares))
	zero := U128Zero()
	for i, bit := range mask {
		switch {
		case bit.Cmp(zero) == 0:
			result[i] = zero
		case bit.Cmp(ring.FracMul) == 0:
			result[i] = shares[i]
		default:
			return nil, fmt.Errorf("bit mask element %d is not encoded 0 or 1", i)
		}
	}
	return result, nil
}

func checkedProduct(name string, dimensions ...int) (int, error) {
	result := 1
	maxInt := int(^uint(0) >> 1)
	for _, dimension := range dimensions {
		if dimension < 0 {
			return 0, fmt.Errorf("%s has a negative dimension", name)
		}
		if dimension != 0 && result > maxInt/dimension {
			return 0, fmt.Errorf("%s dimensions overflow", name)
		}
		result *= dimension
	}
	return result, nil
}

func checkedSum(name string, values ...int) (int, error) {
	result := 0
	maxInt := int(^uint(0) >> 1)
	for _, value := range values {
		if value < 0 {
			return 0, fmt.Errorf("%s has a negative term", name)
		}
		if result > maxInt-value {
			return 0, fmt.Errorf("%s dimensions overflow", name)
		}
		result += value
	}
	return result, nil
}

func validateWideSplineInput(input K2WideSplineFullInput) (K2WideSplineFullInput, int, error) {
	ringName, fracBits, err := normalizeRingAndFracBits(input.Ring, input.FracBits)
	if err != nil {
		return input, 0, err
	}
	input.Ring, input.FracBits = ringName, fracBits
	if input.N <= 0 {
		return input, 0, fmt.Errorf("n must be positive")
	}
	if input.PartyID != 0 && input.PartyID != 1 {
		return input, 0, fmt.Errorf("party_id must be 0 or 1")
	}
	if input.Phase < 1 || input.Phase > 4 {
		return input, 0, fmt.Errorf("phase must be in 1 through 4")
	}
	if err := validateFinite("lower", input.Lower); err != nil {
		return input, 0, err
	}
	if err := validateFinite("upper", input.Upper); err != nil {
		return input, 0, err
	}

	numInt := input.NumIntervals
	switch input.Family {
	case "binomial", "sigmoid", "":
		if numInt == 0 {
			numInt = K2SigmoidIntervals
		}
	case "poisson":
		if numInt == 0 {
			numInt = K2ExpIntervals
		}
	case "softplus":
		if numInt == 0 {
			numInt = 80
		}
	case "reciprocal":
		if numInt == 0 {
			numInt = K2ReciprocalIntervals
		}
		if input.Lower == 0 {
			input.Lower = K2ReciprocalLower
		}
		if input.Upper == 0 {
			input.Upper = K2ReciprocalUpper
		}
	case "log":
		if numInt == 0 {
			numInt = K2LogIntervals
		}
		if input.Lower == 0 {
			input.Lower = K2LogLower
		}
		if input.Upper == 0 {
			input.Upper = K2LogUpper
		}
	default:
		return input, 0, fmt.Errorf("unsupported family %s", input.Family)
	}
	if numInt < 2 {
		return input, 0, fmt.Errorf("num_intervals must be at least 2")
	}
	numThresh, err := checkedSum("k2-wide-spline-full threshold count", numInt, 1)
	if err != nil {
		return input, 0, err
	}
	coefficientCapacity, err := checkedProduct(
		"k2-wide-spline-full coefficient count", numThresh, 2,
	)
	if err != nil {
		return input, 0, err
	}
	input.NumIntervals = numInt
	if (input.Family == "reciprocal" || input.Family == "log") &&
		(input.Lower <= 0 || input.Upper <= input.Lower) {
		return input, 0, fmt.Errorf("domain must satisfy 0 less than lower less than upper")
	}

	var slopes, intercepts []float64
	publicValues := make([]float64, 0, coefficientCapacity)
	switch input.Family {
	case "poisson":
		slopes, intercepts, _, _ = WideExpParams(numInt)
		publicValues = append(publicValues, math.Exp(8))
	case "softplus":
		slopes, intercepts, _ = WideSoftplusParams(numInt)
		publicValues = append(publicValues, math.Log1p(math.Exp(8)))
	case "reciprocal":
		slopes, intercepts, _ = WideReciprocalParamsWithRange(numInt, input.Lower, input.Upper)
		publicValues = append(publicValues, 1/input.Lower, 1/input.Upper)
	case "log":
		slopes, intercepts, _ = WideLogParamsWithRange(numInt, input.Lower, input.Upper)
		publicValues = append(publicValues, math.Log(input.Lower), math.Log(input.Upper))
	default:
		slopes, intercepts, _ = WideSigmoidParams(numInt)
		publicValues = append(publicValues, 1)
	}
	publicValues = append(publicValues, slopes...)
	publicValues = append(publicValues, intercepts...)
	if ringName == "ring127" {
		ring := NewRing127(fracBits)
		for i, value := range publicValues {
			if _, err := ring.FromDoubleChecked(value); err != nil {
				return input, 0, fmt.Errorf("spline coefficient %d %s", i, err)
			}
		}
	} else {
		ring := NewRing63(fracBits)
		for i, value := range publicValues {
			if _, err := ring.FromDoubleChecked(value); err != nil {
				return input, 0, fmt.Errorf("spline coefficient %d %s", i, err)
			}
		}
	}

	totalThresholdElements, err := checkedProduct(
		"k2-wide-spline-full threshold matrix", input.N, numThresh,
	)
	if err != nil {
		return input, 0, err
	}
	if ringName == "ring127" {
		if _, err := decodeRing127Vector(input.EtaShareFP, input.N); err != nil {
			return input, 0, fmt.Errorf("invalid eta_share_fp %s", err)
		}
		if _, err := decodeBase64Records(input.DcfKeys, ring127DcfElemSize, totalThresholdElements); err != nil {
			return input, 0, fmt.Errorf("invalid dcf_keys %s", err)
		}
	} else {
		if _, err := decodeRing63FPVector(input.EtaShareFP, input.N); err != nil {
			return input, 0, fmt.Errorf("invalid eta_share_fp %s", err)
		}
		if _, err := decodeBase64Records(input.DcfKeys, k2Ring63DcfElemSize, totalThresholdElements); err != nil {
			return input, 0, fmt.Errorf("invalid dcf_keys %s", err)
		}
	}

	validateVector := func(name, value string, required bool) error {
		if !required {
			return nil
		}
		if ringName == "ring127" {
			if _, err := decodeRing127Vector(value, input.N); err != nil {
				return fmt.Errorf("invalid %s %s", name, err)
			}
			return nil
		}
		if _, err := decodeRing63FPVector(value, input.N); err != nil {
			return fmt.Errorf("invalid %s %s", name, err)
		}
		return nil
	}
	if input.Phase >= 2 {
		if ringName == "ring127" {
			if _, err := decodeRing127Vector(input.PeerDcfMasked, totalThresholdElements); err != nil {
				return input, 0, fmt.Errorf("invalid peer_dcf_masked %s", err)
			}
		} else if _, err := decodeRing63ResidueVector(input.PeerDcfMasked, totalThresholdElements); err != nil {
			return input, 0, fmt.Errorf("invalid peer_dcf_masked %s", err)
		}
	}

	fields := []struct {
		name     string
		value    string
		required bool
	}{
		{name: "t_and_a", value: input.TripleAND_A, required: input.Phase >= 2},
		{name: "t_and_b", value: input.TripleAND_B, required: input.Phase >= 2},
		{name: "t_and_c", value: input.TripleAND_C, required: input.Phase >= 3},
		{name: "t_had1_a", value: input.TripleHad1_A, required: input.Phase >= 2},
		{name: "t_had1_b", value: input.TripleHad1_B, required: input.Phase >= 2},
		{name: "t_had1_c", value: input.TripleHad1_C, required: input.Phase >= 3},
		{name: "t_had2_a", value: input.TripleHad2_A, required: input.Phase >= 3},
		{name: "t_had2_b", value: input.TripleHad2_B, required: input.Phase >= 3},
		{name: "t_had2_c", value: input.TripleHad2_C, required: input.Phase >= 4},
		{name: "p_and_xma", value: input.PeerAND_XMA, required: input.Phase >= 3},
		{name: "p_and_ymb", value: input.PeerAND_YMB, required: input.Phase >= 3},
		{name: "p_had1_xma", value: input.PeerHad1_XMA, required: input.Phase >= 3},
		{name: "p_had1_ymb", value: input.PeerHad1_YMB, required: input.Phase >= 3},
		{name: "p_had2_xma", value: input.PeerHad2_XMA, required: input.Phase >= 4},
		{name: "p_had2_ymb", value: input.PeerHad2_YMB, required: input.Phase >= 4},
	}
	for _, field := range fields {
		if err := validateVector(field.name, field.value, field.required); err != nil {
			return input, 0, err
		}
	}
	return input, numThresh, nil
}
