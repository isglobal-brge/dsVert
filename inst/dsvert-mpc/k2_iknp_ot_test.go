package main

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

func TestIKNPArithmeticCrossTermRing63(t *testing.T) {
	n := 16
	mod := uint64(1) << 63
	x := make([]uint64, n)
	y := make([]uint64, n)
	for i := 0; i < n; i++ {
		x[i] = cryptoRandUint64K2() % mod
		y[i] = cryptoRandUint64K2() % mod
	}

	sender, receiver := runIKNPCrossTermForTest(t,
		ring63VectorToFPB64(x), ring63VectorToFPB64(y), n, "ring63")
	s := sender.([]uint64)
	r := receiver.([]uint64)
	for i := 0; i < n; i++ {
		got := (s[i] + r[i]) % mod
		want := modMulBig63(x[i], y[i], mod)
		if got != want {
			t.Fatalf("iknp ring63 cross[%d]=%d want %d", i, got, want)
		}
	}
}

func TestIKNPArithmeticCrossTermRing127(t *testing.T) {
	n := 16
	ring := NewRing127(K2DefaultFracBits127)
	x := make([]Uint128, n)
	y := make([]Uint128, n)
	for i := 0; i < n; i++ {
		x[i] = cryptoRandUint128().ModPow127()
		y[i] = cryptoRandUint128().ModPow127()
	}

	sender, receiver := runIKNPCrossTermForTest(t,
		Uint128VecToB64(x), Uint128VecToB64(y), n, "ring127")
	s := sender.([]Uint128)
	r := receiver.([]Uint128)
	for i := 0; i < n; i++ {
		got := ring.Add(s[i], r[i])
		want := x[i].Mul(y[i]).ModPow127()
		if got != want {
			t.Fatalf("iknp ring127 cross[%d]=%v want %v", i, got, want)
		}
	}
}

func runIKNPCrossTermForTest(t *testing.T, xB64, yB64 string, n int, ring string) (any, any) {
	t.Helper()
	curve := elliptic.P256()
	setup, err := ot.GenerateCOSenderSetup(crand.Reader, curve)
	if err != nil {
		t.Fatal(err)
	}
	baseWires, err := iknpRandomBaseWires()
	if err != nil {
		t.Fatal(err)
	}
	delta, err := ot.NewLabel(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	flags := make([]bool, iknpK)
	for i := range flags {
		flags[i] = delta.Bit(i) == 1
	}
	bundle, points, err := ot.BuildCOChoices(crand.Reader, curve, setup.Ax, setup.Ay, flags)
	if err != nil {
		t.Fatal(err)
	}
	baseCiphertexts, err := ot.EncryptCOCiphertexts(curve, setup, points, baseWires)
	if err != nil {
		t.Fatal(err)
	}
	baseLabels, err := ot.DecryptCOCiphertexts(curve, bundle, baseCiphertexts)
	if err != nil {
		t.Fatal(err)
	}

	choices, err := otChoiceBits(yB64, n, ring)
	if err != nil {
		t.Fatal(err)
	}
	receiverLabels, uMatrix, err := iknpReceiverExtend(baseWires, choices)
	if err != nil {
		t.Fatal(err)
	}
	wires, senderShare, err := otArithmeticWires(xB64, n, ring)
	if err != nil {
		t.Fatal(err)
	}
	senderLabels, err := iknpSenderLabels(baseLabels, delta, uMatrix, len(wires))
	if err != nil {
		t.Fatal(err)
	}
	c0 := make([]ot.Label, len(wires))
	c1 := make([]ot.Label, len(wires))
	for i := range wires {
		q0 := senderLabels[i]
		q1 := q0
		q1.Xor(delta)
		c0[i] = wires[i].L0
		c0[i].Xor(iknpPad(q0, i, 0))
		c1[i] = wires[i].L1
		c1[i].Xor(iknpPad(q1, i, 1))
	}
	msg := make([]ot.Label, len(wires))
	for i := range msg {
		if choices[i] {
			msg[i] = c1[i]
			msg[i].Xor(iknpPad(receiverLabels[i], i, 1))
		} else {
			msg[i] = c0[i]
			msg[i].Xor(iknpPad(receiverLabels[i], i, 0))
		}
	}
	receiverShare, err := otLabelsToRingShare(msg, n, ring)
	if err != nil {
		t.Fatal(err)
	}
	return senderShare, receiverShare
}
