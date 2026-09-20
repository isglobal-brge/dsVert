package main

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"
)

// This regression records the missing private carry in EXECUTOR_SPEC.md C.
// Opening z=(x+r) mod 2^128 and subtracting lift(r) in Ring192 is not an
// exact lift: the wrap must be restored before interpreting a signed input.
func TestCrossGridStageConversionMaskedOpeningNeedsPrivateCarry(t *testing.T) {
	m128 := new(big.Int).Lsh(big.NewInt(1), 128)
	m192 := new(big.Int).Lsh(big.NewInt(1), 192)
	x := big.NewInt(1)
	r := new(big.Int).Sub(m128, big.NewInt(1))
	z := new(big.Int).Mod(new(big.Int).Add(x, r), m128)
	literal := new(big.Int).Mod(new(big.Int).Sub(z, r), m192)
	if z.Sign() != 0 || literal.Cmp(x) == 0 {
		t.Fatal("missing-carry counterexample was lost")
	}
	wantWrong := new(big.Int).Add(new(big.Int).Sub(m192, m128), x)
	if literal.Cmp(wantWrong) != 0 {
		t.Fatal("counterexample does not differ by exactly -2^128")
	}
}

func TestCrossGridStageConversionPrivateCarryIdentity(t *testing.T) {
	m128 := new(big.Int).Lsh(big.NewInt(1), 128)
	m192 := new(big.Int).Lsh(big.NewInt(1), 192)
	half := new(big.Int).Rsh(new(big.Int).Set(m128), 1)
	values := []*big.Int{
		new(big.Int), big.NewInt(1), big.NewInt(-1),
		new(big.Int).Sub(half, big.NewInt(1)), new(big.Int).Neg(half),
		new(big.Int).Lsh(big.NewInt(7), 100),
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(7), 100)),
	}
	masks := []*big.Int{
		new(big.Int), big.NewInt(1), new(big.Int).Sub(m128, big.NewInt(1)),
		new(big.Int).Set(half), new(big.Int).Sub(half, big.NewInt(1)),
	}
	for _, value := range values {
		x := new(big.Int).Mod(new(big.Int).Set(value), m128)
		for _, r := range masks {
			z := new(big.Int).Mod(new(big.Int).Add(x, r), m128)
			lift := new(big.Int).Sub(z, r)
			// Both predicates must be evaluated privately; the opened z
			// alone is uniformly masked and does not reveal either bit.
			if z.Cmp(r) < 0 {
				lift.Add(lift, m128)
			}
			if x.Cmp(half) >= 0 {
				lift.Sub(lift, m128)
			}
			lift.Mod(lift, m192)
			want := new(big.Int).Mod(new(big.Int).Set(value), m192)
			if lift.Cmp(want) != 0 {
				t.Fatalf("carry/sign identity differs: x=%s mask=%s", value, r)
			}
		}
	}
}

// Two canonical Ring192 limbs form ONE Ring384 additive share. Remasking
// the low limb modulo 2^192 independently discards a carry and corrupts the
// wide value, including across fresh execution attempts of the same graph.
func TestCrossGridStageConversionWideRemaskPreservesValue(t *testing.T) {
	m192 := new(big.Int).Lsh(big.NewInt(1), 192)
	m384 := new(big.Int).Lsh(big.NewInt(1), 384)
	half := new(big.Int).Rsh(new(big.Int).Set(m384), 1)
	values := []*big.Int{
		new(big.Int), big.NewInt(1), big.NewInt(-1),
		new(big.Int).Sub(m192, big.NewInt(1)), new(big.Int).Set(m192),
		new(big.Int).Sub(half, big.NewInt(1)), new(big.Int).Neg(half),
	}
	splits := []*big.Int{
		new(big.Int), big.NewInt(1), new(big.Int).Sub(m192, big.NewInt(1)),
		new(big.Int).Sub(m384, big.NewInt(1)),
	}
	abi := crossGridStagePlan{ID: "wide", Ring: 192, FPScale: 264,
		CoordOrder: []string{"quadratic:0:limb:0", "quadratic:0:limb:1"}}
	encode := func(v *big.Int) []byte {
		v = new(big.Int).Mod(new(big.Int).Set(v), m384)
		be := v.FillBytes(make([]byte, 48))
		for i, j := 0, len(be)-1; i < j; i, j = i+1, j-1 {
			be[i], be[j] = be[j], be[i]
		}
		return be
	}
	decode := func(le []byte) *big.Int {
		be := bytes.Clone(le)
		for i, j := 0, len(be)-1; i < j; i, j = i+1, j-1 {
			be[i], be[j] = be[j], be[i]
		}
		return new(big.Int).SetBytes(be)
	}
	for _, value := range values {
		for _, split := range splits {
			inputs := [2]crossGridStageOutput{
				{Share: encode(split), Validity: []byte{1, 0}},
				{Share: encode(new(big.Int).Sub(value, split)), Validity: []byte{0, 1}},
			}
			for attemptIndex := byte(0); attemptIndex < 4; attemptIndex++ {
				attempt := crossGridStageAttempt{
					Nonce:               sha256.Sum256([]byte{attemptIndex, 0}),
					OutputMaskDomainTag: sha256.Sum256([]byte{attemptIndex, 1}),
					Session:             exactGCSession{MasterKey: sha256.Sum256([]byte{attemptIndex, 2})},
				}
				var outputs [2]crossGridStageOutput
				for role := range outputs {
					outputs[role] = crossGridStageRemask(inputs[role], abi, exactGCRole(role), attempt)
					if abi.validateOutput(outputs[role]) != nil {
						t.Fatal("remask produced invalid wide ABI")
					}
					if bytes.Equal(inputs[role].Share, outputs[role].Share) {
						t.Fatal("wide share was not remasked")
					}
				}
				got := new(big.Int).Add(decode(outputs[0].Share), decode(outputs[1].Share))
				got.Mod(got, m384)
				want := new(big.Int).Mod(new(big.Int).Set(value), m384)
				if got.Cmp(want) != 0 {
					t.Fatalf("wide remask lost limb carry: value=%s split=%s attempt=%d got=%s want=%s", value, split, attemptIndex, got, want)
				}
				for coordinate := 0; coordinate < 2; coordinate++ {
					if outputs[0].Validity[coordinate]^outputs[1].Validity[coordinate] != 1 {
						t.Fatal("wide remask changed private validity")
					}
				}
			}
		}
	}
}
