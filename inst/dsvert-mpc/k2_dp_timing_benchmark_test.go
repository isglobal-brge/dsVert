package main

import (
	"math"
	"math/bits"
	"testing"
)

// These benchmarks are an audit aid, not a constant-time test. Wall-clock
// assertions would be scheduler- and machine-dependent. The buckets keep the
// deterministic seed and public mechanism parameters fixed while selecting
// coordinates by the magnitude of their sticky draw, so `go test -bench
// DPSamplerTiming` can reveal coarse draw-dependent runtime.

var dpTimingBenchmarkSink int64

type dpTimingAudit struct {
	entropyBytes         int
	halfGeometricBytes   int
	i63Attempts          int
	laplaceSearchRounds  int
	laplaceRetries       int
	gaussianProposalRuns int
}

type dpTimingAuditStream struct {
	stream *dpDeterministicStream
	audit  *dpTimingAudit
}

func (stream *dpTimingAuditStream) u64() uint64 {
	stream.audit.entropyBytes += 8
	return stream.stream.u64()
}

func (stream *dpTimingAuditStream) u8() uint8 {
	stream.audit.entropyBytes++
	return stream.stream.u8()
}

func (stream *dpTimingAuditStream) boolean() bool {
	return stream.u8()&1 == 1
}

func (stream *dpTimingAuditStream) sign() int64 {
	if stream.boolean() {
		return 1
	}
	return -1
}

func (stream *dpTimingAuditStream) halfGeometric() float64 {
	b := 1
	var value uint8
	for value == 0 {
		value = stream.u8()
		stream.audit.halfGeometricBytes++
		b += bits.LeadingZeros8(value)
	}
	return float64(b)
}

func (stream *dpTimingAuditStream) uniform() float64 {
	i := stream.u64() % (uint64(1) << 53)
	r := (1 + float64(i)/(1<<53)) /
		math.Pow(2, stream.halfGeometric())
	if r == 0 {
		return 1
	}
	return r
}

func (stream *dpTimingAuditStream) i63n(n int64) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	domainSize := uint64(1) << 63
	bound := uint64(n)
	cutoff := domainSize - domainSize%bound
	for {
		stream.audit.i63Attempts++
		candidate := stream.u64() >> 1
		if candidate < cutoff {
			return int64(candidate % bound), nil
		}
	}
}

func dpTimingAuditGeometric(
	stream *dpTimingAuditStream, lambda float64,
) int64 {
	if stream.uniform() > -math.Expm1(-lambda*math.MaxInt64) {
		return math.MaxInt64
	}
	left, right := int64(0), int64(math.MaxInt64)
	for left+1 < right {
		stream.audit.laplaceSearchRounds++
		mid := left - int64(math.Floor(
			(math.Log(0.5)+math.Log1p(math.Exp(lambda*float64(left-right))))/lambda,
		))
		if mid <= left {
			mid = left + 1
		} else if mid >= right {
			mid = right - 1
		}
		q := math.Expm1(lambda*float64(left-mid)) /
			math.Expm1(lambda*float64(left-right))
		if stream.uniform() <= q {
			right = mid
		} else {
			left = mid
		}
	}
	return right
}

func dpTimingAuditLaplaceDraw(seed []byte, coordinate int) (
	int64, dpTimingAudit, error,
) {
	inner, err := newDPDeterministicStream(seed, coordinate)
	if err != nil {
		return 0, dpTimingAudit{}, err
	}
	audit := dpTimingAudit{}
	stream := &dpTimingAuditStream{stream: inner, audit: &audit}
	var sample, sign int64
	sign = -1
	for sample == 0 && sign == -1 {
		audit.laplaceRetries++
		granularity := dpCeilPowerOfTwo(1.0 / dpNoiseGranularityParam)
		lambda := granularity / (1 + granularity)
		sample = dpTimingAuditGeometric(stream, lambda) - 1
		sign = stream.sign()
	}
	granularity := dpCeilPowerOfTwo(1.0 / dpNoiseGranularityParam)
	return int64(math.Round(float64(sample*sign) * granularity)), audit, nil
}

func dpTimingAuditGaussianDraw(seed []byte, coordinate int, sigma float64) (
	int64, dpTimingAudit, error,
) {
	inner, err := newDPDeterministicStreamForDomain(
		seed, coordinate, dpGaussianStreamDomain)
	if err != nil {
		return 0, dpTimingAudit{}, err
	}
	audit := dpTimingAudit{}
	stream := &dpTimingAuditStream{stream: inner, audit: &audit}
	granularity := dpCeilPowerOfTwo(sigma / math.Exp2(56))
	sqrtN := 2 * sigma / granularity
	stepSize := int64(math.Round(math.Sqrt2*sqrtN + 1))
	for iteration := 0; iteration < dpGaussianMaxIterations; iteration++ {
		audit.gaussianProposalRuns++
		geometric := int64(stream.halfGeometric()) - 1
		if geometric > dpGaussianGeometricBound {
			geometric = dpGaussianGeometricBound
		}
		twoSided := geometric
		if stream.boolean() {
			twoSided = -twoSided - 1
		}
		uniform, uniformErr := stream.i63n(stepSize)
		if uniformErr != nil {
			return 0, audit, uniformErr
		}
		result := stepSize*twoSided + uniform
		probability := dpGaussianBinomialProbability(sqrtN, result)
		rejectProbability := stream.uniform()
		if probability > 0 && rejectProbability <
			probability*float64(stepSize)*math.Pow(2, float64(geometric))/4 {
			if granularity == 1 {
				return result, audit, nil
			}
			return int64(math.Round(float64(result) * granularity)), audit, nil
		}
	}
	return 0, audit, nil
}

type dpTimingBucket struct {
	coordinates   []int
	meanMagnitude float64
	auditTotal    dpTimingAudit
}

func TestDPTimingAuditModelMatchesProduction(t *testing.T) {
	seed := make([]byte, 32)
	laplace := dpDeterministicAddNoise(seed)
	input := validDPGaussianInput()
	sigma, _, _, _, err := dpGaussianParameters(input)
	if err != nil {
		t.Fatal(err)
	}
	gaussian := dpDeterministicGaussianSample(seed)
	for coordinate := 0; coordinate < 4_096; coordinate++ {
		wantLaplace, err := laplace(coordinate, 0, 1, 1, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		gotLaplace, _, err := dpTimingAuditLaplaceDraw(seed, coordinate)
		if err != nil || gotLaplace != wantLaplace {
			t.Fatalf("Laplace coordinate %d audit=%d production=%d error=%v",
				coordinate, gotLaplace, wantLaplace, err)
		}
		wantGaussian, err := gaussian(coordinate, sigma)
		if err != nil {
			t.Fatal(err)
		}
		gotGaussian, _, err := dpTimingAuditGaussianDraw(seed, coordinate, sigma)
		if err != nil || gotGaussian != wantGaussian {
			t.Fatalf("Gaussian coordinate %d audit=%d production=%d error=%v",
				coordinate, gotGaussian, wantGaussian, err)
		}
	}
}

func dpTimingBenchmarkCoordinates(
	b *testing.B, draw func(int) (int64, error),
	auditDraw func(int) (int64, dpTimingAudit, error),
	accept func(int64) bool,
) dpTimingBucket {
	b.Helper()
	coordinates := make([]int, 0, 256)
	var magnitude float64
	total := dpTimingAudit{}
	for coordinate := 0; coordinate < 1_000_000 && len(coordinates) < cap(coordinates); coordinate++ {
		value, err := draw(coordinate)
		if err != nil {
			b.Fatal(err)
		}
		if accept(value) {
			auditedValue, audit, auditErr := auditDraw(coordinate)
			if auditErr != nil {
				b.Fatal(auditErr)
			}
			if auditedValue != value {
				b.Fatalf("timing audit draw=%d, production draw=%d",
					auditedValue, value)
			}
			coordinates = append(coordinates, coordinate)
			magnitude += math.Abs(float64(value))
			total.entropyBytes += audit.entropyBytes
			total.halfGeometricBytes += audit.halfGeometricBytes
			total.i63Attempts += audit.i63Attempts
			total.laplaceSearchRounds += audit.laplaceSearchRounds
			total.laplaceRetries += audit.laplaceRetries
			total.gaussianProposalRuns += audit.gaussianProposalRuns
		}
	}
	if len(coordinates) != cap(coordinates) {
		b.Fatalf("found %d timing-audit coordinates, want %d",
			len(coordinates), cap(coordinates))
	}
	return dpTimingBucket{
		coordinates:   coordinates,
		meanMagnitude: magnitude / float64(len(coordinates)),
		auditTotal:    total,
	}
}

func benchmarkDPTimingBucket(
	b *testing.B, bucket dpTimingBucket, draw func(int) (int64, error),
) {
	b.Helper()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		value, err := draw(bucket.coordinates[i%len(bucket.coordinates)])
		if err != nil {
			b.Fatal(err)
		}
		dpTimingBenchmarkSink = value
	}
	b.ReportMetric(bucket.meanMagnitude, "mean_abs_noise")
	count := float64(len(bucket.coordinates))
	b.ReportMetric(float64(bucket.auditTotal.entropyBytes)/count, "entropy_B/draw")
	b.ReportMetric(float64(bucket.auditTotal.halfGeometricBytes)/count, "halfgeom_B/draw")
	b.ReportMetric(float64(bucket.auditTotal.i63Attempts)/count, "i63_attempts/draw")
	b.ReportMetric(float64(bucket.auditTotal.laplaceSearchRounds)/count, "search_rounds/draw")
	b.ReportMetric(float64(bucket.auditTotal.laplaceRetries)/count, "laplace_retries/draw")
	b.ReportMetric(float64(bucket.auditTotal.gaussianProposalRuns)/count, "gaussian_proposals/draw")
}

func BenchmarkDPSamplerTimingLaplace(b *testing.B) {
	addNoise := dpDeterministicAddNoise(make([]byte, 32))
	seed := make([]byte, 32)
	draw := func(coordinate int) (int64, error) {
		return addNoise(coordinate, 0, 1, 1, 1, 0)
	}
	auditDraw := func(coordinate int) (int64, dpTimingAudit, error) {
		return dpTimingAuditLaplaceDraw(seed, coordinate)
	}
	for name, accept := range map[string]func(int64) bool{
		"abs_le_1": func(value int64) bool { return value >= -1 && value <= 1 },
		"abs_ge_5": func(value int64) bool { return value <= -5 || value >= 5 },
	} {
		b.Run(name, func(b *testing.B) {
			bucket := dpTimingBenchmarkCoordinates(b, draw, auditDraw, accept)
			benchmarkDPTimingBucket(b, bucket, draw)
		})
	}
}

func BenchmarkDPSamplerTimingGaussian(b *testing.B) {
	input := validDPGaussianInput()
	sigma, _, _, _, err := dpGaussianParameters(input)
	if err != nil {
		b.Fatal(err)
	}
	seed := make([]byte, 32)
	sample := dpDeterministicGaussianSample(seed)
	draw := func(coordinate int) (int64, error) {
		return sample(coordinate, sigma)
	}
	auditDraw := func(coordinate int) (int64, dpTimingAudit, error) {
		return dpTimingAuditGaussianDraw(seed, coordinate, sigma)
	}
	for name, accept := range map[string]func(int64) bool{
		"abs_le_1": func(value int64) bool { return value >= -1 && value <= 1 },
		"abs_ge_8": func(value int64) bool { return value <= -8 || value >= 8 },
	} {
		b.Run(name, func(b *testing.B) {
			bucket := dpTimingBenchmarkCoordinates(b, draw, auditDraw, accept)
			benchmarkDPTimingBucket(b, bucket, draw)
		})
	}
}
