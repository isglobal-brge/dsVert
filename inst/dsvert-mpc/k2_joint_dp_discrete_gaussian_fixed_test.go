package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math"
	"math/big"
	"testing"
)

func TestJointDPGaussianFixedPlanAccountsForSamplerTV(t *testing.T) {
	plan, err := jointDPPlanVectorGaussian(jointDPGaussianPlanInput{
		Epsilon: "1", Delta: "0.000001", L2SensitivitySteps: "1",
		TotalCoordinateCount: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.FixedWorkSampler || plan.ExactRationalSampler ||
		plan.SamplerCandidateCount != 1 ||
		plan.SamplerRandomBitsPerCoordinate < 128 ||
		plan.SamplerRandomBitsPerCoordinate%8 != 0 ||
		plan.SamplerRandomBytesPerCoordinate !=
			plan.SamplerRandomBitsPerCoordinate/8+1 ||
		plan.SamplerTablePrecisionBits < plan.SamplerRandomBitsPerCoordinate ||
		plan.SamplerSearchSteps < 1 ||
		plan.SamplerFullScanSteps != plan.SamplerMagnitudeCount ||
		plan.SamplerCDFTableBytes != plan.SamplerMagnitudeCount*
			plan.SamplerRandomBytesPerCoordinate ||
		plan.HostConstantTimeClaim || !plan.TranscriptDPClaim ||
		!plan.LogicalTranscriptFixedShape || plan.PhysicalTimingDPClaim ||
		plan.SamplerBranchesOnPrivateRandomness {
		t.Fatalf("dishonest or non-fixed Gaussian plan: %#v", plan)
	}
	parse := func(numerator, denominator string) *big.Rat {
		t.Helper()
		value := new(big.Rat)
		if _, ok := value.SetString(numerator + "/" + denominator); !ok {
			t.Fatalf("invalid rational %s/%s", numerator, denominator)
		}
		return value
	}
	projection := parse(plan.VectorTailTVUpperNumerator,
		plan.VectorTailTVUpperDenominator)
	sampler := parse(plan.VectorSamplerTVUpperNumerator,
		plan.VectorSamplerTVUpperDenominator)
	total := parse(plan.VectorTotalTVUpperNumerator,
		plan.VectorTotalTVUpperDenominator)
	if new(big.Rat).Add(projection, sampler).Cmp(total) != 0 {
		t.Fatal("the total vector TV certificate does not compose")
	}
	transfer, err := jointDPGaussianExpUpper(big.NewRat(1, 1))
	if err != nil {
		t.Fatal(err)
	}
	transfer.Add(transfer, big.NewRat(1, 1))
	implementation := parse(plan.PerPeerImplementationDeltaNum,
		plan.PerPeerImplementationDeltaDenom)
	if new(big.Rat).Mul(transfer, total).Cmp(implementation) > 0 {
		t.Fatal("sampler TV is not absorbed by implementation_delta")
	}
}

func TestJointDPGaussianDyadicTableHasCertifiedTV(t *testing.T) {
	for _, variance := range []string{"1/2", "3/2", "17/3", "560"} {
		t.Run(variance, func(t *testing.T) {
			sigmaSquared := new(big.Rat)
			if _, ok := sigmaSquared.SetString(variance); !ok {
				t.Fatal("bad variance")
			}
			target := big.NewRat(1, 1<<30)
			table, err := jointDPGaussianBuildDyadicTable(
				sigmaSquared, big.NewInt(32), 128, 192, target)
			if err != nil {
				t.Fatal(err)
			}
			if table.TVUpper.Cmp(target) > 0 || table.Grid.BitLen() != 129 ||
				len(table.Cumulative) != 33 ||
				table.Cumulative[len(table.Cumulative)-1].Cmp(table.Grid) != 0 {
				t.Fatalf("invalid table certificate: %#v", table)
			}

			varianceFloat, _ := sigmaSquared.Float64()
			weights := make([]float64, len(table.Cumulative))
			weights[0] = 1
			idealTotal := 1.0
			for magnitude := 1; magnitude < len(weights); magnitude++ {
				weights[magnitude] = 2 * math.Exp(
					-float64(magnitude*magnitude)/(2*varianceFloat))
				idealTotal += weights[magnitude]
			}
			gridFloat, _ := new(big.Float).SetInt(table.Grid).Float64()
			previous := new(big.Int)
			tv := 0.0
			for magnitude, cumulative := range table.Cumulative {
				count := new(big.Int).Sub(cumulative, previous)
				countFloat, _ := new(big.Float).SetInt(count).Float64()
				tv += math.Abs(countFloat/gridFloat - weights[magnitude]/idealTotal)
				previous = cumulative
			}
			tv /= 2
			boundFloat, _ := table.TVUpper.Float64()
			if tv > boundFloat+1e-14 {
				t.Fatalf("observed TV %.17g exceeds exact certificate %.17g", tv, boundFloat)
			}
		})
	}
}

func TestJointDPGaussianPlannedTablesMeetTheirAllocation(t *testing.T) {
	cases := []jointDPGaussianPlanInput{
		{Epsilon: "0.1", Delta: "0.000001", L2SensitivitySteps: "1", TotalCoordinateCount: 1},
		{Epsilon: "1", Delta: "0.000001", L2SensitivitySteps: "1", TotalCoordinateCount: 1000},
		{Epsilon: "8", Delta: "0.000001", L2SensitivitySteps: "1", TotalCoordinateCount: 1000000},
		{Epsilon: "1", Delta: "7.888609052210118e-31", L2SensitivitySteps: "16", TotalCoordinateCount: 1000},
	}
	for _, input := range cases {
		plan, err := jointDPPlanVectorGaussian(input)
		if err != nil {
			t.Fatalf("plan %+v: %v", input, err)
		}
		sigmaSquared := new(big.Rat)
		if _, ok := sigmaSquared.SetString(
			plan.SigmaSquaredNumerator + "/" + plan.SigmaSquaredDenominator); !ok {
			t.Fatal("bad planned variance")
		}
		maximum, ok := new(big.Int).SetString(plan.MaximumNoiseMagnitudePerPeer, 10)
		if !ok {
			t.Fatal("bad planned support")
		}
		vectorTV := new(big.Rat)
		if _, ok := vectorTV.SetString(plan.VectorSamplerTVUpperNumerator + "/" +
			plan.VectorSamplerTVUpperDenominator); !ok {
			t.Fatal("bad planned sampler TV")
		}
		perCoordinateTV := new(big.Rat).Quo(
			vectorTV, big.NewRat(int64(input.TotalCoordinateCount), 1))
		table, err := jointDPGaussianBuildDyadicTable(
			sigmaSquared, maximum, plan.SamplerRandomBitsPerCoordinate,
			plan.SamplerTablePrecisionBits, perCoordinateTV)
		if err != nil {
			t.Fatalf("planned table %+v: %v", input, err)
		}
		if table.TVUpper.Cmp(perCoordinateTV) > 0 ||
			table.RandomBytes != plan.SamplerRandomBytesPerCoordinate ||
			table.SearchSteps != plan.SamplerFullScanSteps ||
			len(table.CumulativeFixed) != plan.SamplerCDFTableBytes {
			t.Fatalf("planned table violated its certificate: plan=%+v table=%+v", plan, table)
		}
		exactGCZeroBigInts(table.Cumulative)
	}
}

type gaussianFixedCountingReader struct {
	reader *bytes.Reader
	bytes  int
	calls  int
}

func (reader *gaussianFixedCountingReader) Read(output []byte) (int, error) {
	reader.calls++
	n, err := reader.reader.Read(output)
	reader.bytes += n
	return n, err
}

func TestJointDPGaussianFixedSamplerReadsOnePublicShapeAndReplays(t *testing.T) {
	table, err := jointDPGaussianBuildDyadicTable(
		big.NewRat(3, 2), big.NewInt(16), 128, 192, big.NewRat(1, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	draw := func(tape []byte) (*big.Int, jointDPGaussianFixedAudit) {
		reader := &gaussianFixedCountingReader{reader: bytes.NewReader(tape)}
		value, audit, sampleErr := jointDPGaussianSampleDyadic(reader, table)
		if sampleErr != nil {
			t.Fatal(sampleErr)
		}
		if reader.bytes != table.RandomBytes || reader.calls != 1 ||
			audit.RandomBytes != table.RandomBytes ||
			audit.SearchSteps != table.SearchSteps ||
			audit.ThresholdBytesRead !=
				table.SearchSteps*table.FixedThresholdBytes ||
			audit.SecretIndexedReads != 0 || audit.DataDependentBranches {
			t.Fatalf("private draw changed public work shape: reader=%+v audit=%+v", reader, audit)
		}
		return value, audit
	}
	digest := sha256.Sum256([]byte("fixed-gaussian-tape"))
	left, leftAudit := draw(digest[:])
	right, rightAudit := draw(digest[:])
	if left.Cmp(right) != 0 || leftAudit != rightAudit {
		t.Fatal("fixed sampler replay is not bit-exact")
	}
	for _, tape := range [][]byte{
		make([]byte, table.RandomBytes),
		bytes.Repeat([]byte{0xff}, table.RandomBytes),
		append(make([]byte, table.RandomBytes-1), 1),
	} {
		value, audit := draw(tape)
		if new(big.Int).Abs(new(big.Int).Set(value)).Cmp(table.Maximum) > 0 ||
			audit.RandomBytes != table.RandomBytes ||
			audit.SearchSteps != table.SearchSteps ||
			audit.ThresholdBytesRead !=
				table.SearchSteps*table.FixedThresholdBytes ||
			audit.SecretIndexedReads != 0 || audit.DataDependentBranches {
			t.Fatalf("boundary tape changed fixed sampler shape: value=%s audit=%+v",
				value, audit)
		}
	}
}

func TestJointDPGaussianObliviousScanMatchesExactCDFAtEveryBoundary(t *testing.T) {
	table, err := jointDPGaussianBuildDyadicTable(
		big.NewRat(17, 3), big.NewInt(32), 128, 192, big.NewRat(1, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	wordBytes := table.RandomBits / 8
	check := func(draw *big.Int, sign byte) {
		t.Helper()
		if draw.Sign() < 0 || draw.Cmp(table.Grid) >= 0 {
			t.Fatal("invalid boundary draw")
		}
		tape := make([]byte, table.RandomBytes)
		draw.FillBytes(tape[:wordBytes])
		tape[wordBytes] = sign & 1
		got, audit, err := jointDPGaussianSampleDyadic(
			bytes.NewReader(tape), table)
		if err != nil {
			t.Fatal(err)
		}
		index := -1
		for candidate, threshold := range table.Cumulative {
			if draw.Cmp(threshold) < 0 {
				index = candidate
				break
			}
		}
		if index < 0 {
			t.Fatal("reference CDF did not close")
		}
		want := big.NewInt(int64(index))
		if index != 0 && sign&1 == 1 {
			want.Neg(want)
		}
		if got.Cmp(want) != 0 ||
			audit.SearchSteps != len(table.Cumulative) ||
			audit.ThresholdBytesRead !=
				len(table.Cumulative)*table.FixedThresholdBytes ||
			audit.SecretIndexedReads != 0 || audit.DataDependentBranches {
			t.Fatalf("oblivious CDF mismatch: draw=%s sign=%d got=%s want=%s audit=%+v",
				draw, sign, got, want, audit)
		}
	}
	check(new(big.Int), 0)
	check(new(big.Int), 1)
	for _, threshold := range table.Cumulative {
		if threshold.Sign() > 0 {
			below := new(big.Int).Sub(new(big.Int).Set(threshold), big.NewInt(1))
			if below.Cmp(table.Grid) < 0 {
				check(below, 0)
				check(below, 1)
			}
		}
		if threshold.Cmp(table.Grid) < 0 {
			check(new(big.Int).Set(threshold), 0)
			check(new(big.Int).Set(threshold), 1)
		}
	}
}

func TestJointDPGaussianFixedBorrowComparisonMatchesBigInt(t *testing.T) {
	for left := 0; left < 512; left++ {
		for right := 0; right < 512; right++ {
			leftWord := []byte{byte(left >> 8), byte(left)}
			rightWord := []byte{byte(right >> 8), byte(right)}
			got := jointDPGaussianFixedLess(leftWord, rightWord)
			want := byte(0)
			if left < right {
				want = 1
			}
			if got != want {
				t.Fatalf("borrow comparison %d < %d: got=%d want=%d",
					left, right, got, want)
			}
		}
	}
}

func TestJointDPGaussianFixedShapeBoundariesFailClosed(t *testing.T) {
	target := big.NewRat(1, 1<<30)
	maximum := big.NewInt(jointDPGaussianMaxTableSupport)
	shape, err := jointDPGaussianPlanFixedShape(maximum, 1, target)
	if err != nil || shape.MagnitudeCount != jointDPGaussianMaxTableSupport+1 {
		t.Fatalf("maximum fixed table support rejected: shape=%+v err=%v", shape, err)
	}
	if _, err := jointDPGaussianPlanFixedShape(
		new(big.Int).Add(maximum, big.NewInt(1)), 1, target); err == nil {
		t.Fatal("oversize fixed table support was silently accepted")
	}
	if _, err := jointDPGaussianBuildDyadicTable(
		big.NewRat(3, 2), big.NewInt(32), 128, 128,
		new(big.Rat).SetFrac(big.NewInt(1),
			new(big.Int).Lsh(big.NewInt(1), 512))); err == nil {
		t.Fatal("an under-precision table was silently accepted")
	}
}

func TestJointDPGaussianNegativeExponentialIntervalsContainReference(t *testing.T) {
	for _, text := range []string{"0", "1/100", "1/2", "1", "3/2", "10", "100"} {
		x := new(big.Rat)
		if _, ok := x.SetString(text); !ok {
			t.Fatal("bad exponent fixture")
		}
		interval, err := jointDPGaussianExpNegDyadic(x, 192)
		if err != nil {
			t.Fatal(err)
		}
		scale := new(big.Float).SetInt(jointDPGaussianDyadicScale(192))
		low, _ := new(big.Float).Quo(
			new(big.Float).SetInt(interval.low), scale).Float64()
		high, _ := new(big.Float).Quo(
			new(big.Float).SetInt(interval.high), scale).Float64()
		xFloat, _ := x.Float64()
		want := math.Exp(-xFloat)
		tolerance := math.Max(1e-300, math.Abs(want)*2e-15)
		if low-want > tolerance || want-high > tolerance {
			t.Fatalf("exp(-%s)=%.17g outside [%.17g,%.17g]", text, want, low, high)
		}
	}
}

func TestJointDPGaussianWorkerPayloadShapeIsRandomnessIndependent(t *testing.T) {
	leftSeed := sha256.Sum256([]byte("fixed-worker-shape-left"))
	rightSeed := sha256.Sum256([]byte("fixed-worker-shape-right"))
	leftInput := jointDPGaussianTestInput(t, "peer-a", leftSeed,
		[]*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2)},
		[]int64{20, 20, 20}, []int{8, 8, 8}, 0, 3)
	rightInput := jointDPGaussianTestInput(t, "peer-a", rightSeed,
		[]*big.Int{big.NewInt(99), big.NewInt(42), big.NewInt(7)},
		[]int64{20, 20, 20}, []int{8, 8, 8}, 0, 3)
	left, err := jointDPGaussianSampleShare(leftInput)
	if err != nil {
		t.Fatal(err)
	}
	right, err := jointDPGaussianSampleShare(rightInput)
	if err != nil {
		t.Fatal(err)
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	if len(leftJSON) != len(rightJSON) || len(left.NoisedShare) != len(right.NoisedShare) ||
		!left.FixedWorkShapeVerified || !right.FixedWorkShapeVerified {
		t.Fatalf("private randomness changed worker envelope shape: left=%d right=%d",
			len(leftJSON), len(rightJSON))
	}
}

func FuzzJointDPGaussianDyadicSamplerBoundaries(f *testing.F) {
	f.Add([]byte{0})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add([]byte("sticky-fixed-gaussian"))
	table, err := jointDPGaussianBuildDyadicTable(
		big.NewRat(17, 3), big.NewInt(32), 128, 192, big.NewRat(1, 1<<30))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		digest := sha256.Sum256(input)
		value, audit, sampleErr := jointDPGaussianSampleDyadic(
			bytes.NewReader(digest[:]), table)
		if sampleErr != nil {
			t.Fatal(sampleErr)
		}
		if new(big.Int).Abs(new(big.Int).Set(value)).Cmp(table.Maximum) > 0 ||
			audit.RandomBytes != table.RandomBytes ||
			audit.SearchSteps != table.SearchSteps ||
			audit.ThresholdBytesRead !=
				table.SearchSteps*table.FixedThresholdBytes ||
			audit.SecretIndexedReads != 0 || audit.DataDependentBranches {
			t.Fatalf("out-of-contract fixed draw: value=%s audit=%+v", value, audit)
		}
	})
}

func BenchmarkJointDPGaussianFixedSampler8192(b *testing.B) {
	table, err := jointDPGaussianBuildDyadicTable(
		big.NewRat(17, 3), big.NewInt(32), 128, 192, big.NewRat(1, 1<<30))
	if err != nil {
		b.Fatal(err)
	}
	tape := sha256.Sum256([]byte("fixed-gaussian-benchmark"))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		for coordinate := 0; coordinate < 8192; coordinate++ {
			if _, _, err := jointDPGaussianSampleDyadic(
				bytes.NewReader(tape[:]), table); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func benchmarkJointDPGaussianObliviousPoissonFallback(
	b *testing.B, coordinates int,
) {
	plan, err := jointDPPlanVectorGaussian(jointDPGaussianPlanInput{
		Epsilon: "1", Delta: "0.000001", L2SensitivitySteps: "1024",
		TotalCoordinateCount: coordinates,
	})
	if err != nil {
		b.Fatal(err)
	}
	sigmaSquared := new(big.Rat)
	if _, ok := sigmaSquared.SetString(
		plan.SigmaSquaredNumerator + "/" + plan.SigmaSquaredDenominator); !ok {
		b.Fatal("invalid benchmark variance")
	}
	maximum, ok := new(big.Int).SetString(
		plan.MaximumNoiseMagnitudePerPeer, 10)
	if !ok {
		b.Fatal("invalid benchmark support")
	}
	vectorTV := new(big.Rat)
	if _, ok := vectorTV.SetString(plan.VectorSamplerTVUpperNumerator + "/" +
		plan.VectorSamplerTVUpperDenominator); !ok {
		b.Fatal("invalid benchmark TV")
	}
	perCoordinateTV := new(big.Rat).Quo(
		vectorTV, big.NewRat(int64(coordinates), 1))
	table, err := jointDPGaussianBuildDyadicTable(
		sigmaSquared, maximum, plan.SamplerRandomBitsPerCoordinate,
		plan.SamplerTablePrecisionBits, perCoordinateTV)
	if err != nil {
		b.Fatal(err)
	}
	tape := make([]byte, table.RandomBytes)
	digest := sha256.Sum256([]byte("formal-poisson-oblivious-full-fallback"))
	copy(tape, digest[:])
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		for coordinate := 0; coordinate < coordinates; coordinate++ {
			if _, _, err := jointDPGaussianSampleDyadic(
				bytes.NewReader(tape), table); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(table.SearchSteps), "cdf-entries/coordinate")
	b.ReportMetric(float64(len(table.CumulativeFixed)), "cdf-bytes/coordinate")
}

func BenchmarkJointDPGaussianObliviousPoissonFallbackP1(b *testing.B) {
	benchmarkJointDPGaussianObliviousPoissonFallback(b, 1)
}

func BenchmarkJointDPGaussianObliviousPoissonFallbackP8(b *testing.B) {
	benchmarkJointDPGaussianObliviousPoissonFallback(b, 8)
}

func BenchmarkJointDPGaussianFixedTableBuild(b *testing.B) {
	for iteration := 0; iteration < b.N; iteration++ {
		table, err := jointDPGaussianBuildDyadicTable(
			big.NewRat(560, 1), big.NewInt(256), 128, 208,
			big.NewRat(1, 1<<30))
		if err != nil {
			b.Fatal(err)
		}
		exactGCZeroBigInts(table.Cumulative)
	}
}

func BenchmarkJointDPGaussianFixedNoise8192(b *testing.B) {
	const coordinates = 8192
	seed := sha256.Sum256([]byte("fixed-gaussian-noise-benchmark"))
	source := make([]*big.Int, coordinates)
	upper := make([]int64, coordinates)
	shifts := make([]int, coordinates)
	for index := range source {
		source[index] = new(big.Int)
		upper[index] = 1
	}
	input := jointDPGaussianTestInput(
		b, "peer-a", seed, source, upper, shifts, 0, coordinates)
	spec, err := jointDPGaussianParseSpec(input)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		noise, err := jointDPGaussianNoise(seed, spec)
		if err != nil {
			b.Fatal(err)
		}
		exactGCZeroBigInts(noise)
	}
}

func BenchmarkJointDPGaussianLegacyExact8192(b *testing.B) {
	const coordinates = 8192
	sigmaSquared := big.NewRat(17, 3)
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		reader := &sha256CounterReader{seed: []byte("legacy-exact-benchmark")}
		sampler := exactDGaussianSampler{random: reader}
		for coordinate := 0; coordinate < coordinates; coordinate++ {
			value, err := sampler.discreteGaussian(sigmaSquared)
			if err != nil {
				b.Fatal(err)
			}
			value.SetInt64(0)
		}
	}
}
