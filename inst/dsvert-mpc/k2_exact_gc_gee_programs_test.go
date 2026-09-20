package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestGroupedGEEPublicProgramCacheAndFreshness(t *testing.T) {
	programs := make(groupedGEEPublicPrograms)
	get := func(shifts []int) *primitiveVProgram {
		p, err := programs.compile("unpack", shifts, func() (*primitiveVProgram, error) { return groupedGEEStagedUnpackCompile(shifts) })
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := get([]int{0})
	if get([]int{0}) != p || get([]int{1}) == p || get([]int{0, 0}) == p || len(programs) != 3 {
		t.Fatal("public shape key alias or missed reuse")
	}
	numeric := groupedGEEStagedTestSpec("binomial").Numeric
	for _, cap := range []int64{100, 101} {
		for _, rho := range []int64{16384, 32768} {
			numeric.RhoQ16 = rho
			parameters := struct {
				Numeric groupedGEESpec
				Cap     int64
			}{numeric, cap}
			a, err := programs.compile("likelihood", parameters, func() (*primitiveVProgram, error) { return groupedGEELikelihoodCompile(numeric, cap) })
			if err != nil {
				t.Fatal(err)
			}
			b, err := programs.compile("likelihood", parameters, func() (*primitiveVProgram, error) { t.Fatal("recompiled same numeric/cap key"); return nil, nil })
			if err != nil || a != b {
				t.Fatal("numeric/cap cache mismatch")
			}
		}
	}
	if len(programs) != 7 {
		t.Fatal("numeric/cap key omitted a public field")
	}
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var previous *big.Int
	for attempt := 0; attempt < 2; attempt++ {
		left, right := net.Pipe()
		left.SetDeadline(time.Now().Add(time.Minute))
		right.SetDeadline(time.Now().Add(time.Minute))
		session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
		contract := sha256.Sum256([]byte("cached-public-program-fresh-run"))
		type result struct {
			values []*big.Int
			err    error
		}
		ch := make(chan result, 1)
		go func() {
			out, err := primitiveVRunGarbler(left, p, session, contract, []*big.Int{big.NewInt(7), big.NewInt(1)})
			left.Close()
			ch <- result{out, err}
		}()
		evaluator, err := primitiveVRunEvaluator(right, p, session, contract, []*big.Int{big.NewInt(0), big.NewInt(0)})
		right.Close()
		garbler := <-ch
		if err != nil || garbler.err != nil {
			t.Fatalf("fresh run: %v / %v", garbler.err, err)
		}
		for i, want := range []int64{7, 1} {
			if exactGCReferenceReconstruct(garbler.values[i], evaluator[i], 192).Int64() != want {
				t.Fatal("cached program changed reconstruction")
			}
		}
		if previous != nil && previous.Cmp(garbler.values[0]) == 0 {
			t.Fatal("cached program reused secret output mask")
		}
		previous = new(big.Int).Set(garbler.values[0])
		after, err := json.Marshal(p)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("execution mutated cached public program")
		}
	}
}

func TestGroupedGEEGlobalSourceValidity(t *testing.T) {
	const count = 193 // exercise a partial final packed word as well
	programs := [2]groupedGEEPublicPrograms{make(groupedGEEPublicPrograms), make(groupedGEEPublicPrograms)}
	for _, invalid := range []int{-1, 0, count - 1} {
		var input [2]crossGridStageOutput
		for role := range input {
			input[role] = crossGridStageOutput{Share: make([]byte, 24*count), Validity: make([]byte, count)}
			for i := 0; i < count; i++ {
				input[role].Validity[i] = byte(i % 2)
			}
		}
		for i := 0; i < count; i++ {
			if i != invalid {
				input[1].Validity[i] ^= 1
			}
		}
		left, right := net.Pipe()
		left.SetDeadline(time.Now().Add(time.Minute))
		right.SetDeadline(time.Now().Add(time.Minute))
		a := crossGridStageAttempt{Session: exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})}
		a.OutputMaskDomainTag = sha256.Sum256([]byte{byte(invalid + 1), 23})
		type result struct {
			out crossGridStageOutput
			err error
		}
		ch := make(chan result, 1)
		go func() {
			out, err := programs[0].sourceValidity(left, a, 0, input[0])
			left.Close()
			ch <- result{out, err}
		}()
		b, err := programs[1].sourceValidity(right, a, 1, input[1])
		right.Close()
		g := <-ch
		if err != nil || g.err != nil {
			t.Fatalf("global validity: %v / %v", g.err, err)
		}
		if !bytes.Equal(g.out.Share, input[0].Share) || !bytes.Equal(b.Share, input[1].Share) {
			t.Fatal("validity changed numeric shares")
		}
		abi := crossGridStagePlan{Ring: 192, CoordOrder: make([]string, count)}
		g.out = crossGridStageRemask(g.out, abi, 0, a)
		b = crossGridStageRemask(b, abi, 1, a)
		want := byte(0)
		if invalid < 0 {
			want = 1
		}
		for i := 0; i < count; i++ {
			if g.out.Validity[i]^b.Validity[i] != want {
				t.Fatalf("coordinate %d escaped global validity", i)
			}
		}
	}
	if len(programs[0]) != 1 || len(programs[1]) != 1 {
		t.Fatal("secret validity pattern changed public compilation")
	}
}
