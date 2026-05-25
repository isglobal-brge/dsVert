package main

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

func TestOTArithmeticCrossTermRing63(t *testing.T) {
	n := 8
	mod := uint64(1) << 63
	x := make([]uint64, n)
	y := make([]uint64, n)
	for i := 0; i < n; i++ {
		x[i] = cryptoRandUint64K2() % mod
		y[i] = cryptoRandUint64K2() % mod
	}

	sender, receiver := runOTCrossTermForTest(t, ring63VectorToFPB64(x), ring63VectorToFPB64(y), n, "ring63")
	s := sender.([]uint64)
	r := receiver.([]uint64)
	for i := 0; i < n; i++ {
		got := (s[i] + r[i]) % mod
		want := modMulBig63(x[i], y[i], mod)
		if got != want {
			t.Fatalf("ring63 cross[%d]=%d want %d", i, got, want)
		}
	}
}

func TestOTArithmeticCrossTermRing127(t *testing.T) {
	n := 8
	ring := NewRing127(K2DefaultFracBits127)
	x := make([]Uint128, n)
	y := make([]Uint128, n)
	for i := 0; i < n; i++ {
		x[i] = cryptoRandUint128().ModPow127()
		y[i] = cryptoRandUint128().ModPow127()
	}

	sender, receiver := runOTCrossTermForTest(t, Uint128VecToB64(x), Uint128VecToB64(y), n, "ring127")
	s := sender.([]Uint128)
	r := receiver.([]Uint128)
	for i := 0; i < n; i++ {
		got := ring.Add(s[i], r[i])
		want := x[i].Mul(y[i]).ModPow127()
		if got != want {
			t.Fatalf("ring127 cross[%d]=%v want %v", i, got, want)
		}
	}
}

func runOTCrossTermForTest(t *testing.T, xB64, yB64 string, n int, ring string) (any, any) {
	t.Helper()
	curve := elliptic.P256()
	setup, err := ot.GenerateCOSenderSetup(crand.Reader, curve)
	if err != nil {
		t.Fatal(err)
	}
	bits, err := otChoiceBits(yB64, n, ring)
	if err != nil {
		t.Fatal(err)
	}
	bundle, points, err := ot.BuildCOChoices(crand.Reader, curve, setup.Ax, setup.Ay, bits)
	if err != nil {
		t.Fatal(err)
	}
	wires, senderShare, err := otArithmeticWires(xB64, n, ring)
	if err != nil {
		t.Fatal(err)
	}
	ciphertexts, err := ot.EncryptCOCiphertexts(curve, setup, points, wires)
	if err != nil {
		t.Fatal(err)
	}
	labels, err := ot.DecryptCOCiphertexts(curve, bundle, ciphertexts)
	if err != nil {
		t.Fatal(err)
	}
	receiverShare, err := otLabelsToRingShare(labels, n, ring)
	if err != nil {
		t.Fatal(err)
	}
	return senderShare, receiverShare
}
