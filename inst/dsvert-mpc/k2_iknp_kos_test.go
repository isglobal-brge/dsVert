package main

import (
	crand "crypto/rand"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

func TestGF128MulIdentity(t *testing.T) {
	one := gfElem{lo: 1}
	a := gfElem{lo: 0xdeadbeef12345678, hi: 0xcafebabef00dbaad}
	if gfMul(a, one) != a {
		t.Fatal("a*1 != a")
	}
	if gfMul(one, a) != a {
		t.Fatal("1*a != a")
	}
	if gfMul(a, gfElem{}) != (gfElem{}) {
		t.Fatal("a*0 != 0")
	}
}

func TestGF128MulFieldLaws(t *testing.T) {
	a := gfElem{0x1122334455667788, 0x99aabbccddeeff00}
	b := gfElem{0x0f0e0d0c0b0a0908, 0x0706050403020100}
	c := gfElem{0xfedcba9876543210, 0x0123456789abcdef}
	if gfMul(a, b) != gfMul(b, a) {
		t.Fatal("gfMul not commutative")
	}
	// distributive: a*(b+c) == a*b + a*c
	if gfMul(a, gfAdd(b, c)) != gfAdd(gfMul(a, b), gfMul(a, c)) {
		t.Fatal("gfMul not distributive over gfAdd")
	}
	// associative: (a*b)*c == a*(b*c)
	if gfMul(gfMul(a, b), c) != gfMul(a, gfMul(b, c)) {
		t.Fatal("gfMul not associative")
	}
}

func TestIKNPKOSEncodeRoundTrip(t *testing.T) {
	x := gfElem{0x1111111122222222, 0x3333333344444444}
	tt := gfElem{0x5555555566666666, 0x7777777788888888}
	dx, dtt, ok := iknpKOSDecode(iknpKOSEncode(x, tt))
	if !ok || dx != x || dtt != tt {
		t.Fatalf("KOS opener round-trip failed: ok=%v", ok)
	}
}

// iknpKOSTranscript builds an honest IKNP extension transcript: base wires,
// the sender's Delta and its base labels L_{Delta_i}, a random choice vector,
// the receiver's extended seeds t_i + U matrix, and the sender's q_i.
func iknpKOSTranscript(t *testing.T, n int) (recv, send []ot.Label, choices []bool,
	uMatrix []byte, delta ot.Label, domain string, baseLabels []ot.Label) {
	t.Helper()
	domain = "kos-test"
	wires, err := iknpRandomBaseWires()
	if err != nil {
		t.Fatal(err)
	}
	delta, err = ot.NewLabel(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	baseLabels = make([]ot.Label, iknpK)
	for i := 0; i < iknpK; i++ {
		if delta.Bit(i) == 1 {
			baseLabels[i] = wires[i].L1
		} else {
			baseLabels[i] = wires[i].L0
		}
	}
	choices = make([]bool, n)
	rb := make([]byte, (n+7)/8)
	if _, err := crand.Read(rb); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		choices[i] = (rb[i/8]>>(uint(i)%8))&1 == 1
	}
	recv, uMatrix, err = iknpReceiverExtend(wires, choices, domain)
	if err != nil {
		t.Fatal(err)
	}
	send, err = iknpSenderLabels(baseLabels, delta, uMatrix, n, domain)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestIKNPInvariantAndKOSHonest(t *testing.T) {
	n := 200
	recv, send, choices, uMatrix, delta, domain, _ := iknpKOSTranscript(t, n)
	// Core IKNP correlation: q_i == t_i XOR (r_i ? Delta : 0).
	for i := 0; i < n; i++ {
		exp := recv[i]
		if choices[i] {
			exp.Xor(delta)
		}
		if exp != send[i] {
			t.Fatalf("IKNP correlation broken at row %d", i)
		}
	}
	// Honest KOS consistency check must pass.
	xHat, tHat := iknpReceiverKOSCheck(recv, choices, uMatrix, n, "63", domain)
	if !iknpSenderKOSVerify(send, delta, uMatrix, n, "63", domain, xHat, tHat) {
		t.Fatal("honest KOS consistency check was rejected")
	}
}

func TestIKNPKOSRejectsInconsistentChoice(t *testing.T) {
	n := 200
	recv, send, choices, uMatrix, delta, domain, _ := iknpKOSTranscript(t, n)
	// A malicious receiver opens with a choice vector that differs from what its
	// U matrix actually encodes -> x_hat is wrong -> the check must reject.
	bad := make([]bool, n)
	copy(bad, choices)
	bad[7] = !bad[7]
	xHat, tHat := iknpReceiverKOSCheck(recv, bad, uMatrix, n, "63", domain)
	if iknpSenderKOSVerify(send, delta, uMatrix, n, "63", domain, xHat, tHat) {
		t.Fatal("KOS check accepted an inconsistent choice vector")
	}
}

func TestIKNPKOSRejectsTamperedLabel(t *testing.T) {
	n := 128
	recv, send, choices, uMatrix, delta, domain, _ := iknpKOSTranscript(t, n)
	xHat, tHat := iknpReceiverKOSCheck(recv, choices, uMatrix, n, "63", domain)
	send[3].D0 ^= 1 // corrupt one sender seed -> q_hat changes -> must reject
	if iknpSenderKOSVerify(send, delta, uMatrix, n, "63", domain, xHat, tHat) {
		t.Fatal("KOS check accepted a tampered sender label")
	}
}

// TestIKNPKOSRejectsInconsistentUMatrix constructs the actual selective-failure
// malformation KOS defends against: a receiver whose U matrix encodes DIFFERENT
// choice bits across columns of the same row (no single r_j explains the row).
func TestIKNPKOSRejectsInconsistentUMatrix(t *testing.T) {
	n := 128 // single chunk (< iknpChunkRows), byteRows = 16
	recv, _, choices, uMatrix, delta, domain, baseLabels := iknpKOSTranscript(t, n)
	byteRows := (n + 7) / 8
	bad := make([]byte, len(uMatrix))
	copy(bad, uMatrix)
	// Flip row-0's choice contribution in only the first 64 of the 128 columns,
	// making row 0 inconsistent (a genuinely malformed U, not just a tampered
	// opener). The receiver's seeds t are independent of U, so it opens honestly.
	for i := 0; i < 64; i++ {
		bad[i*byteRows] ^= 1 // column i, row 0, bit 0
	}
	sendBad, err := iknpSenderLabels(baseLabels, delta, bad, n, domain)
	if err != nil {
		t.Fatal(err)
	}
	xHat, tHat := iknpReceiverKOSCheck(recv, choices, bad, n, "63", domain)
	if iknpSenderKOSVerify(sendBad, delta, bad, n, "63", domain, xHat, tHat) {
		t.Fatal("KOS check accepted an inconsistent (malformed) U matrix")
	}
}
