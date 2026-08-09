package twopc

import (
	"math/big"
	"testing"

	linearaccel "github.com/isglobal-brge/dsvert/experiments/lattigo-linear-accel"
)

func BenchmarkAdditiveShare2PC63Online(b *testing.B) {
	b.StopTimer()
	spec, err := linearaccel.NewCRTSpec(linearaccel.Signed63, 12)
	if err != nil {
		b.Fatal(err)
	}
	input := smallFullInput()
	firstShares, secondShares := splitForTest(spec, input)
	first, err := NewPeer("compute-1", spec, firstShares)
	if err != nil {
		b.Fatal(err)
	}
	second, err := NewPeer("compute-2", spec, secondShares)
	if err != nil {
		b.Fatal(err)
	}
	session, err := NewSession(spec, 2, 2, 2, input.Bounds, []Identity{first.Identity(), second.Identity()})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		result, err := session.Run(first, second)
		if err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			b.ReportMetric(float64(result.Metrics.EncryptedInputWireBytes), "encrypted-input-B/op")
			b.ReportMetric(float64(result.Metrics.MaskedOutputWireBytes), "masked-output-B/op")
			b.ReportMetric(float64(result.Metrics.TotalWireBytes()), "total-wire-B/op")
		}
	}
}

func benchmarkAdditiveShare2PC63PackedXtR(b *testing.B, rows, columns int) {
	b.StopTimer()
	spec, err := linearaccel.NewCRTSpec(linearaccel.Signed63, 12)
	if err != nil {
		b.Fatal(err)
	}
	input := linearaccel.LinearInput{
		X:        make([][]*big.Int, rows),
		Beta:     make([]*big.Int, columns),
		Residual: make([]*big.Int, rows),
		Bounds:   testBounds("7", "5", "3"),
	}
	for row := range input.X {
		input.X[row] = make([]*big.Int, columns)
		for column := range input.X[row] {
			input.X[row][column] = big.NewInt(int64((row+column)%7 - 3))
		}
		input.Residual[row] = big.NewInt(int64(row%5 - 2))
	}
	for column := range input.Beta {
		input.Beta[column] = big.NewInt(int64(column - 1))
	}
	firstShares, secondShares := splitForTest(spec, input)
	first, err := NewPeer("compute-1", spec, firstShares)
	if err != nil {
		b.Fatal(err)
	}
	second, err := NewPeer("compute-2", spec, secondShares)
	if err != nil {
		b.Fatal(err)
	}
	session, err := NewSession(spec, rows, columns, 5, input.Bounds,
		[]Identity{first.Identity(), second.Identity()})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		result, err := session.Run(first, second)
		if err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			b.ReportMetric(float64(result.Metrics.EncryptedInputWireBytes),
				"encrypted-input-B/op")
			b.ReportMetric(float64(result.Metrics.MaskedOutputWireBytes),
				"masked-output-B/op")
			b.ReportMetric(float64(result.Metrics.TotalWireBytes()),
				"total-wire-B/op")
			b.ReportMetric(float64(result.Metrics.MessageCount), "messages/op")
		}
	}
}

func BenchmarkAdditiveShare2PC63PackedXtR64x3(b *testing.B) {
	benchmarkAdditiveShare2PC63PackedXtR(b, 64, 3)
}

func BenchmarkAdditiveShare2PC63PackedXtR4096x8(b *testing.B) {
	benchmarkAdditiveShare2PC63PackedXtR(b, 4096, 8)
}

func BenchmarkAdditiveShare2PC63Setup(b *testing.B) {
	spec, err := linearaccel.NewCRTSpec(linearaccel.Signed63, 12)
	if err != nil {
		b.Fatal(err)
	}
	input := smallFullInput()
	firstShares, secondShares := splitForTest(spec, input)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		first, err := NewPeer("compute-1", spec, firstShares)
		if err != nil {
			b.Fatal(err)
		}
		second, err := NewPeer("compute-2", spec, secondShares)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := NewSession(spec, 2, 2, 2, input.Bounds, []Identity{first.Identity(), second.Identity()}); err != nil {
			b.Fatal(err)
		}
	}
}
