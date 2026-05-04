package main

import "testing"

func TestK2CmpThresholdPrimitive(t *testing.T) {
	ring := NewRing63(K2DefaultFracBits)
	values := []float64{0, 0.5, 1, 4.999, 5, 9}
	n := len(values)
	x0 := make([]uint64, n)
	x1 := make([]uint64, n)
	for i, v := range values {
		fp := ring.FromDouble(v)
		share0 := uint64(1234567 + i*17)
		x0[i] = share0 % ring.Modulus
		x1[i] = ring.Sub(fp, x0[i])
	}

	p0, p1 := cmpGeneratePreprocess(ring, n, ring.FromDouble(5))
	m0 := cmpRound1(ring, 0, x0, p0)
	m1 := cmpRound1(ring, 1, x1, p1)
	b0 := cmpRound2(ring, 0, p0, m0, m1)
	b1 := cmpRound2(ring, 1, p1, m1, m0)

	for i, v := range values {
		got := ring.Add(b0.Shares[i], b1.Shares[i])
		want := uint64(0)
		if v < 5 {
			want = 1
		}
		if got != want {
			t.Fatalf("value %g: got comparison bit %d, want %d", v, got, want)
		}
	}
}
