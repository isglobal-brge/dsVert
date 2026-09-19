package main

import (
	"math/big"
	"testing"
)

func TestCoxGridCrossJointDPBridge(t *testing.T) {
	const cap = uint64(1000)
	p, err := registerCoxGridCrossLoss().JointDPBridgeCompile(cap)
	if err != nil {
		t.Fatal(err)
	}
	ring64 := new(big.Int).Lsh(big.NewInt(1), 64)
	ring128 := new(big.Int).Lsh(big.NewInt(1), 128)
	mask := new(big.Int).Sub(ring128, big.NewInt(97))
	validityMask := new(big.Int).Lsh(big.NewInt(1), 110)
	for _, test := range []struct {
		name         string
		a, b, va, vb *big.Int
		want         int64
		ok           bool
	}{
		{"no_carry", big.NewInt(3), big.NewInt(4), big.NewInt(1), big.NewInt(0), 7, true},
		{"carry", new(big.Int).Sub(ring64, big.NewInt(3)), big.NewInt(10), new(big.Int).Sub(ring64, big.NewInt(2)), big.NewInt(3), 7, true},
		{"zero", new(big.Int).Sub(ring64, big.NewInt(1)), big.NewInt(1), big.NewInt(0), big.NewInt(1), 0, true},
		{"cap", big.NewInt(499), big.NewInt(501), big.NewInt(1), big.NewInt(0), 1000, true},
		{"above_cap", big.NewInt(500), big.NewInt(501), big.NewInt(1), big.NewInt(0), 0, false},
		{"invalid", big.NewInt(3), big.NewInt(4), big.NewInt(0), big.NewInt(0), 0, false},
		{"validity_two", big.NewInt(3), big.NewInt(4), big.NewInt(1), big.NewInt(1), 0, false},
		{"high_word", new(big.Int).Add(ring64, big.NewInt(3)), big.NewInt(4), big.NewInt(1), big.NewInt(0), 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := []*big.Int{test.a, test.va, mask, validityMask}
			e := []*big.Int{test.b, test.vb}
			packed, err := p.Circuit.Compute([]*big.Int{exactGCPackChunks(g, 128), exactGCPackChunks(e, 128)})
			if err != nil {
				t.Fatal(err)
			}
			got := []*big.Int{
				new(big.Int).And(new(big.Int).Set(packed[0]), exactGCMask(128)),
				new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(packed[0]), 128), exactGCMask(128)),
			}
			got[0].Add(got[0], mask).Mod(got[0], ring128)
			got[1].Add(got[1], validityMask).Mod(got[1], ring128)
			ok := int64(0)
			if test.ok {
				ok = 1
			}
			if got[0].Int64() != test.want || got[1].Int64() != ok {
				t.Fatalf("private bridge differs: %v", got)
			}
			encrypted, wire := primitiveVTestProtocol(t, p, g[:2], e)
			if encrypted[0].Int64() != test.want || encrypted[1].Int64() != ok {
				t.Fatalf("encrypted private bridge differs: %v", encrypted)
			}
			t.Logf("measured_garbler_direction_bytes=%d", wire)
		})
	}
	for _, bad := range []uint64{0, 1 << 53} {
		if _, err := coxLossJointDPBridgeCompile(bad); err == nil {
			t.Fatal("invalid cap admitted")
		}
	}
}
