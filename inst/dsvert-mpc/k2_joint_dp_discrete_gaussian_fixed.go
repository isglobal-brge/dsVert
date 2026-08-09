package main

// This file implements the productive finite-work discrete-Gaussian sampler.
// It targets the ideal CKS discrete Gaussian, truncates it to the public
// Ring128 support, and samples a rigorously outward-bounded dyadic
// approximation of that finite law.  Both deviations are charged to the
// public implementation-delta certificate.
//
// Per coordinate the private shape is one fixed-width dyadic word plus one
// sign byte, followed by a complete sequential scan of a fixed-width public
// CDF.  Comparison uses a byte-wise borrow and first-hit mask: there is no
// rejection, retry, early acceptance, secret-indexed table read, or
// data-dependent message size.  Go and the host runtime are not constant-time
// primitives, so this remains a logical fixed-work/fixed-I/O certificate, not
// an absolute physical timing claim.

import (
	"fmt"
	"io"
	"math/big"
)

const (
	jointDPGaussianMinRandomBits    = 128
	jointDPGaussianMaxRandomBits    = 16384
	jointDPGaussianMaxTableSupport  = 1 << 20
	jointDPGaussianMaxFixedCDFBytes = 256 << 20
	jointDPGaussianTableGuardBits   = 48
	jointDPGaussianRandomBitsStride = 64
)

type jointDPGaussianDyadicInterval struct {
	low  *big.Int
	high *big.Int
	bits int
}

func jointDPGaussianDyadicScale(bits int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(bits))
}

func jointDPGaussianDyadicFloor(value *big.Rat, bits int) *big.Int {
	scaled := new(big.Int).Lsh(new(big.Int).Set(value.Num()), uint(bits))
	return scaled.Quo(scaled, value.Denom())
}

func jointDPGaussianDyadicCeil(value *big.Rat, bits int) *big.Int {
	scaled := new(big.Int).Lsh(new(big.Int).Set(value.Num()), uint(bits))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(scaled, value.Denom(), remainder)
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}

func jointDPGaussianDyadicMul(
	left, right jointDPGaussianDyadicInterval,
) jointDPGaussianDyadicInterval {
	if left.bits != right.bits {
		panic("mismatched Gaussian dyadic precision")
	}
	bits := left.bits
	low := new(big.Int).Mul(left.low, right.low)
	low.Rsh(low, uint(bits))
	highProduct := new(big.Int).Mul(left.high, right.high)
	high := new(big.Int).Rsh(new(big.Int).Set(highProduct), uint(bits))
	mask := new(big.Int).Sub(jointDPGaussianDyadicScale(bits), big.NewInt(1))
	if new(big.Int).And(highProduct, mask).Sign() != 0 {
		high.Add(high, big.NewInt(1))
	}
	return jointDPGaussianDyadicInterval{low: low, high: high, bits: bits}
}

// jointDPGaussianExpNegUnitDyadic encloses exp(-x) for x in [0,1].
// Alternating Taylor partial sums enclose the exact value; outward dyadic
// rounding is performed only after the next omitted term is below one grid
// unit.
func jointDPGaussianExpNegUnitDyadic(
	x *big.Rat, bits int,
) (jointDPGaussianDyadicInterval, error) {
	var zero jointDPGaussianDyadicInterval
	if x == nil || x.Sign() < 0 || x.Cmp(big.NewRat(1, 1)) > 0 || bits < 1 {
		return zero, fmt.Errorf("invalid unit negative-exponential interval")
	}
	scale := jointDPGaussianDyadicScale(bits)
	if x.Sign() == 0 {
		return jointDPGaussianDyadicInterval{
			low: new(big.Int).Set(scale), high: new(big.Int).Set(scale), bits: bits,
		}, nil
	}
	sum := big.NewRat(1, 1)
	term := big.NewRat(1, 1)
	var lower, upper *big.Rat
	for index := int64(1); index <= int64(2*bits+64); index++ {
		previous := new(big.Rat).Set(sum)
		term.Mul(term, x)
		term.Quo(term, new(big.Rat).SetInt64(index))
		if index&1 == 1 {
			sum.Sub(sum, term)
			lower, upper = new(big.Rat).Set(sum), previous
		} else {
			sum.Add(sum, term)
			lower, upper = previous, new(big.Rat).Set(sum)
		}
		width := new(big.Rat).Sub(new(big.Rat).Set(upper), lower)
		if new(big.Rat).Mul(width, new(big.Rat).SetInt(scale)).Cmp(
			big.NewRat(1, 1)) <= 0 {
			low := jointDPGaussianDyadicFloor(lower, bits)
			high := jointDPGaussianDyadicCeil(upper, bits)
			if low.Sign() < 0 || high.Cmp(scale) > 0 || low.Cmp(high) > 0 {
				return zero, fmt.Errorf("invalid negative-exponential enclosure")
			}
			return jointDPGaussianDyadicInterval{
				low: low, high: high, bits: bits,
			}, nil
		}
	}
	return zero, fmt.Errorf("negative-exponential interval did not converge")
}

func jointDPGaussianExpNegDyadic(
	x *big.Rat, bits int,
) (jointDPGaussianDyadicInterval, error) {
	var zero jointDPGaussianDyadicInterval
	if x == nil || x.Sign() < 0 || bits < 1 {
		return zero, fmt.Errorf("invalid negative-exponential interval")
	}
	scale := jointDPGaussianDyadicScale(bits)
	integer := new(big.Int).Quo(x.Num(), x.Denom())
	remainder := new(big.Rat).Sub(
		new(big.Rat).Set(x), new(big.Rat).SetInt(integer))
	if integer.Cmp(big.NewInt(int64(bits+2))) > 0 {
		// e > 2, hence exp(-integer) < 2^-integer.  At this grid the
		// outward upper endpoint is at most one unit.
		return jointDPGaussianDyadicInterval{
			low: new(big.Int), high: big.NewInt(1), bits: bits,
		}, nil
	}
	unit, err := jointDPGaussianExpNegUnitDyadic(big.NewRat(1, 1), bits)
	if err != nil {
		return zero, err
	}
	result := jointDPGaussianDyadicInterval{
		low: new(big.Int).Set(scale), high: new(big.Int).Set(scale), bits: bits,
	}
	exponent := integer.Int64()
	for exponent > 0 {
		if exponent&1 == 1 {
			result = jointDPGaussianDyadicMul(result, unit)
		}
		exponent >>= 1
		if exponent != 0 {
			unit = jointDPGaussianDyadicMul(unit, unit)
		}
	}
	remainderInterval, err := jointDPGaussianExpNegUnitDyadic(remainder, bits)
	if err != nil {
		return zero, err
	}
	return jointDPGaussianDyadicMul(result, remainderInterval), nil
}

func jointDPGaussianCeilLog2Int(value *big.Int) (int, error) {
	if value == nil || value.Sign() <= 0 {
		return 0, fmt.Errorf("invalid Gaussian table size")
	}
	result := value.BitLen() - 1
	if new(big.Int).Lsh(big.NewInt(1), uint(result)).Cmp(value) != 0 {
		result++
	}
	return result, nil
}

type jointDPGaussianFixedShape struct {
	RandomBits     int
	RandomBytes    int
	PrecisionBits  int
	SearchSteps    int
	FullScanSteps  int
	MagnitudeCount int
}

func jointDPGaussianPlanFixedShape(
	maximum *big.Int, totalCoordinateCount int, vectorTV *big.Rat,
) (jointDPGaussianFixedShape, error) {
	var zero jointDPGaussianFixedShape
	if maximum == nil || maximum.Sign() < 0 || !maximum.IsInt64() ||
		maximum.Int64() > jointDPGaussianMaxTableSupport ||
		totalCoordinateCount < 1 || vectorTV == nil || vectorTV.Sign() <= 0 {
		return zero, fmt.Errorf("fixed-work Gaussian table is outside the certified support")
	}
	magnitudeCount := new(big.Int).Add(maximum, big.NewInt(1))
	perCoordinateTV := new(big.Rat).Quo(
		new(big.Rat).Set(vectorTV), big.NewRat(int64(totalCoordinateCount), 1))
	randomBits := jointDPGaussianMinRandomBits
	for ; randomBits <= jointDPGaussianMaxRandomBits; randomBits += jointDPGaussianRandomBitsStride {
		quantization := new(big.Rat).SetFrac(
			new(big.Int).Set(magnitudeCount),
			new(big.Int).Lsh(big.NewInt(1), uint(randomBits+1)))
		if quantization.Cmp(new(big.Rat).Quo(
			new(big.Rat).Set(perCoordinateTV), big.NewRat(4, 1))) <= 0 {
			break
		}
	}
	if randomBits > jointDPGaussianMaxRandomBits {
		return zero, fmt.Errorf("fixed-work Gaussian random word exceeds policy")
	}
	logSupport, err := jointDPGaussianCeilLog2Int(magnitudeCount)
	if err != nil {
		return zero, err
	}
	fixedBytes := magnitudeCount.Int64() * int64(randomBits/8+1)
	if fixedBytes < 1 || fixedBytes > jointDPGaussianMaxFixedCDFBytes {
		return zero, fmt.Errorf("fixed-work Gaussian CDF exceeds memory policy")
	}
	searchSteps := logSupport
	if searchSteps < 1 {
		searchSteps = 1
	}
	return jointDPGaussianFixedShape{
		RandomBits: randomBits, RandomBytes: randomBits/8 + 1,
		PrecisionBits:  randomBits + 2*logSupport + jointDPGaussianTableGuardBits,
		SearchSteps:    searchSteps,
		FullScanSteps:  int(magnitudeCount.Int64()),
		MagnitudeCount: int(magnitudeCount.Int64()),
	}, nil
}

type jointDPGaussianDyadicTable struct {
	Grid                *big.Int
	Cumulative          []*big.Int
	CumulativeFixed     []byte
	FixedThresholdBytes int
	Maximum             *big.Int
	TVUpper             *big.Rat
	RandomBits          int
	RandomBytes         int
	LookupDepth         int
	SearchSteps         int
}

func jointDPGaussianWeightTotals(
	sigmaSquared *big.Rat, maximum int64, precisionBits int,
) (*big.Int, *big.Int, jointDPGaussianDyadicInterval,
	jointDPGaussianDyadicInterval, error) {
	if sigmaSquared == nil || sigmaSquared.Sign() <= 0 || maximum < 0 {
		return nil, nil, jointDPGaussianDyadicInterval{},
			jointDPGaussianDyadicInterval{}, fmt.Errorf("invalid Gaussian table")
	}
	inverse := new(big.Rat).Inv(new(big.Rat).Set(sigmaSquared))
	q, err := jointDPGaussianExpNegDyadic(inverse, precisionBits)
	if err != nil {
		return nil, nil, q, q, err
	}
	halfInverse := new(big.Rat).Quo(inverse, big.NewRat(2, 1))
	ratio, err := jointDPGaussianExpNegDyadic(halfInverse, precisionBits)
	if err != nil {
		return nil, nil, q, ratio, err
	}
	scale := jointDPGaussianDyadicScale(precisionBits)
	lowerTotal := new(big.Int).Set(scale)
	upperTotal := new(big.Int).Set(scale)
	weight := jointDPGaussianDyadicInterval{
		low: new(big.Int).Set(scale), high: new(big.Int).Set(scale),
		bits: precisionBits,
	}
	currentRatio := ratio
	for magnitude := int64(1); magnitude <= maximum; magnitude++ {
		weight = jointDPGaussianDyadicMul(weight, currentRatio)
		lowerTotal.Add(lowerTotal, new(big.Int).Lsh(
			new(big.Int).Set(weight.low), 1))
		upperTotal.Add(upperTotal, new(big.Int).Lsh(
			new(big.Int).Set(weight.high), 1))
		currentRatio = jointDPGaussianDyadicMul(currentRatio, q)
	}
	return lowerTotal, upperTotal, q, ratio, nil
}

func jointDPGaussianRoundFraction(numerator, denominator *big.Int) *big.Int {
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, denominator, remainder)
	if new(big.Int).Lsh(remainder, 1).Cmp(denominator) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}

func jointDPGaussianBuildDyadicTable(
	sigmaSquared *big.Rat, maximum *big.Int, randomBits, precisionBits int,
	tvTarget *big.Rat,
) (jointDPGaussianDyadicTable, error) {
	var zero jointDPGaussianDyadicTable
	if maximum == nil || maximum.Sign() < 0 || !maximum.IsInt64() ||
		maximum.Int64() > jointDPGaussianMaxTableSupport ||
		randomBits < jointDPGaussianMinRandomBits || randomBits%8 != 0 ||
		randomBits > jointDPGaussianMaxRandomBits ||
		precisionBits < randomBits || tvTarget == nil || tvTarget.Sign() <= 0 {
		return zero, fmt.Errorf("invalid fixed-work Gaussian table contract")
	}
	maximumInt := maximum.Int64()
	lowerTotal, upperTotal, q, initialRatio, err :=
		jointDPGaussianWeightTotals(sigmaSquared, maximumInt, precisionBits)
	if err != nil || lowerTotal.Sign() <= 0 || lowerTotal.Cmp(upperTotal) > 0 {
		return zero, fmt.Errorf("construct Gaussian weight enclosure: %w", err)
	}
	grid := jointDPGaussianDyadicScale(randomBits)
	precisionScale := jointDPGaussianDyadicScale(precisionBits)
	counts := make([]*big.Int, maximumInt+1)
	// Summing the normalized interval widths does not require one rational
	// normalization per support point:
	//   sum_i(U_i/L - L_i/U) = U/L - L/U.
	widthSum := new(big.Rat).Sub(
		new(big.Rat).SetFrac(new(big.Int).Set(upperTotal),
			new(big.Int).Set(lowerTotal)),
		new(big.Rat).SetFrac(new(big.Int).Set(lowerTotal),
			new(big.Int).Set(upperTotal)))
	midpointDenominator := new(big.Int).Mul(
		new(big.Int).Set(upperTotal), lowerTotal)
	midpointDenominator.Lsh(midpointDenominator, 1)
	weight := jointDPGaussianDyadicInterval{
		low:  new(big.Int).Set(precisionScale),
		high: new(big.Int).Set(precisionScale), bits: precisionBits,
	}
	currentRatio := initialRatio
	for magnitude := int64(0); magnitude <= maximumInt; magnitude++ {
		if magnitude > 0 {
			weight = jointDPGaussianDyadicMul(weight, currentRatio)
			currentRatio = jointDPGaussianDyadicMul(currentRatio, q)
		}
		lowWeight := new(big.Int).Set(weight.low)
		highWeight := new(big.Int).Set(weight.high)
		if magnitude > 0 {
			lowWeight.Lsh(lowWeight, 1)
			highWeight.Lsh(highWeight, 1)
		}
		if new(big.Int).Mul(new(big.Int).Set(lowWeight), lowerTotal).Cmp(
			new(big.Int).Mul(new(big.Int).Set(highWeight), upperTotal)) > 0 {
			return zero, fmt.Errorf("invalid Gaussian probability enclosure")
		}
		midpointNumerator := new(big.Int).Add(
			new(big.Int).Mul(lowWeight, lowerTotal),
			new(big.Int).Mul(highWeight, upperTotal))
		midpointNumerator.Mul(midpointNumerator, grid)
		counts[magnitude] = jointDPGaussianRoundFraction(
			midpointNumerator, midpointDenominator)
	}
	tvUpper := new(big.Rat).Quo(widthSum, big.NewRat(2, 1))
	tvUpper.Add(tvUpper, new(big.Rat).SetFrac(
		big.NewInt(int64(len(counts))),
		new(big.Int).Lsh(new(big.Int).Set(grid), 1)))
	if tvUpper.Cmp(tvTarget) > 0 {
		exactGCZeroBigInts(counts)
		return zero, fmt.Errorf("fixed-work Gaussian table exceeds sampler TV allocation")
	}
	total := new(big.Int)
	for _, count := range counts {
		total.Add(total, count)
	}
	counts[0].Add(counts[0], new(big.Int).Sub(
		new(big.Int).Set(grid), total))
	if counts[0].Sign() < 0 {
		exactGCZeroBigInts(counts)
		return zero, fmt.Errorf("fixed-work Gaussian normalization is not representable")
	}
	cumulative := make([]*big.Int, len(counts))
	running := new(big.Int)
	for index, count := range counts {
		running.Add(running, count)
		cumulative[index] = new(big.Int).Set(running)
	}
	exactGCZeroBigInts(counts)
	if running.Cmp(grid) != 0 {
		exactGCZeroBigInts(cumulative)
		return zero, fmt.Errorf("fixed-work Gaussian CDF does not close")
	}
	thresholdBytes := randomBits/8 + 1
	fixedSize := int64(len(cumulative)) * int64(thresholdBytes)
	if fixedSize < 1 || fixedSize > jointDPGaussianMaxFixedCDFBytes {
		exactGCZeroBigInts(cumulative)
		return zero, fmt.Errorf("fixed-work Gaussian CDF exceeds memory policy")
	}
	fixed := make([]byte, int(fixedSize))
	for index, threshold := range cumulative {
		if threshold.Sign() < 0 || threshold.BitLen() > thresholdBytes*8 {
			exactGCZeroBigInts(cumulative)
			clear(fixed)
			return zero, fmt.Errorf("fixed-work Gaussian threshold exceeds its word")
		}
		threshold.FillBytes(
			fixed[index*thresholdBytes : (index+1)*thresholdBytes])
	}
	lookupDepth, err := jointDPGaussianCeilLog2Int(
		big.NewInt(int64(len(cumulative))))
	if err != nil {
		exactGCZeroBigInts(cumulative)
		clear(fixed)
		return zero, err
	}
	if lookupDepth < 1 {
		lookupDepth = 1
	}
	return jointDPGaussianDyadicTable{
		Grid: new(big.Int).Set(grid), Cumulative: cumulative,
		CumulativeFixed: fixed, FixedThresholdBytes: thresholdBytes,
		Maximum: new(big.Int).Set(maximum), TVUpper: tvUpper,
		RandomBits: randomBits, RandomBytes: randomBits/8 + 1,
		LookupDepth: lookupDepth,
		SearchSteps: len(cumulative),
	}, nil
}

type jointDPGaussianFixedAudit struct {
	RandomBytes           int
	SearchSteps           int
	ThresholdBytesRead    int
	SecretIndexedReads    int
	DataDependentBranches bool
}

// jointDPGaussianFixedLess returns one iff left < right. Both operands are
// unsigned big-endian words of a public fixed width. The subtraction borrow is
// propagated over every byte; control flow and memory addresses depend only on
// the public width.
func jointDPGaussianFixedLess(left, right []byte) byte {
	if len(left) == 0 || len(left) != len(right) {
		panic("mismatched fixed Gaussian words")
	}
	borrow := uint16(0)
	for index := len(left) - 1; index >= 0; index-- {
		difference := uint16(left[index]) - uint16(right[index]) - borrow
		borrow = (difference >> 15) & 1
	}
	return byte(borrow)
}

func jointDPGaussianSampleDyadic(
	random io.Reader, table jointDPGaussianDyadicTable,
) (*big.Int, jointDPGaussianFixedAudit, error) {
	var zero jointDPGaussianFixedAudit
	expectedGrid := jointDPGaussianDyadicScale(table.RandomBits)
	entries := table.SearchSteps
	if random == nil || table.Grid == nil || table.Grid.Sign() <= 0 ||
		entries < 1 || table.RandomBits < 1 ||
		table.RandomBytes != table.RandomBits/8+1 || table.SearchSteps < 1 ||
		table.FixedThresholdBytes != table.RandomBytes ||
		len(table.CumulativeFixed) != entries*table.FixedThresholdBytes ||
		table.Grid.Cmp(expectedGrid) != 0 ||
		table.CumulativeFixed[len(table.CumulativeFixed)-table.FixedThresholdBytes] != 1 ||
		!allZero(table.CumulativeFixed[len(table.CumulativeFixed)-table.FixedThresholdBytes+1:]) {
		return nil, zero, fmt.Errorf("invalid fixed-work Gaussian sampler")
	}
	tape := make([]byte, table.RandomBytes)
	defer clear(tape)
	if _, err := io.ReadFull(random, tape); err != nil {
		return nil, zero, fmt.Errorf("fixed-work Gaussian random stream: %w", err)
	}
	wordBytes := table.RandomBits / 8
	draw := make([]byte, table.FixedThresholdBytes)
	defer clear(draw)
	copy(draw[table.FixedThresholdBytes-wordBytes:], tape[:wordBytes])
	found := byte(0)
	selected := uint64(0)
	for index, offset := 0, 0; index < entries; index, offset =
		index+1, offset+table.FixedThresholdBytes {
		less := jointDPGaussianFixedLess(
			draw, table.CumulativeFixed[offset:offset+table.FixedThresholdBytes])
		take := less & (found ^ 1)
		mask := uint64(0) - uint64(take)
		selected = (selected &^ mask) | (uint64(index) & mask)
		found |= less
	}
	if found != 1 || selected >= uint64(entries) {
		return nil, zero, fmt.Errorf("fixed-work Gaussian CDF selection failed")
	}
	nonzero := ((selected | (uint64(0) - selected)) >> 63) & 1
	negate := uint64(tape[wordBytes]&1) & nonzero
	negativeMask := uint64(0) - negate
	signed := (selected ^ negativeMask) + negate
	value := big.NewInt(int64(signed))
	return value, jointDPGaussianFixedAudit{
		RandomBytes: table.RandomBytes, SearchSteps: table.SearchSteps,
		ThresholdBytesRead: table.SearchSteps * table.FixedThresholdBytes,
		SecretIndexedReads: 0, DataDependentBranches: false,
	}, nil
}

func allZero(value []byte) bool {
	var aggregate byte
	for _, item := range value {
		aggregate |= item
	}
	return aggregate == 0
}
