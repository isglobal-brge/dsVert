package main

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/big"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"
)

func groupedWordBig(w groupedWord) *big.Int {
	z := new(big.Int)
	for i := 2; i >= 0; i-- {
		z.Lsh(z, 64)
		z.Add(z, new(big.Int).SetUint64(w[i]))
	}
	return z
}
func TestGroupedWideRingOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(712))
	mod := new(big.Int).Lsh(big.NewInt(1), 192)
	for i := 0; i < 1000; i++ {
		a, b := groupedWord{rng.Uint64(), rng.Uint64(), rng.Uint64()}, groupedWord{rng.Uint64(), rng.Uint64(), rng.Uint64()}
		for _, op := range []string{"add", "sub", "mul"} {
			want := new(big.Int)
			var got groupedWord
			switch op {
			case "add":
				want.Add(groupedWordBig(a), groupedWordBig(b))
				got = a.add(b)
			case "sub":
				want.Sub(groupedWordBig(a), groupedWordBig(b))
				got = a.sub(b)
			case "mul":
				want.Mul(groupedWordBig(a), groupedWordBig(b))
				got = a.mul(b)
			}
			want.Mod(want, mod)
			if groupedWordBig(got).Cmp(want) != 0 {
				t.Fatalf("%s mismatch", op)
			}
		}
		shift := i % 192
		want := new(big.Int).Lsh(groupedWordBig(a), uint(shift))
		want.Mod(want, mod)
		if groupedWordBig(a.shl(shift)).Cmp(want) != 0 {
			t.Fatal("shift mismatch")
		}
	}
}
func TestGroupedDealerFreeProduct(t *testing.T) {
	n := 8
	if os.Getenv("DSVERT_GROUPED_ARITHMETIC_PROBE") == "1" {
		n = 1024
	}
	x, y := make([]groupedWord, n), make([]groupedWord, n)
	a, b, c, d := make([]groupedWord, n), make([]groupedWord, n), make([]groupedWord, n), make([]groupedWord, n)
	for i := range x {
		// Includes negative integers, exact q64 values, and wraparound ring edges.
		x[i] = groupedWord{uint64(i), uint64(i + 1), 0}
		y[i] = groupedWord{}.sub(groupedWord{uint64(i + 7), 1, 0})
		if i == 0 {
			x[i] = groupedWord{^uint64(0), ^uint64(0), ^uint64(0)}
			y[i] = x[i]
		}
		var err error
		a[i], err = groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		c[i], err = groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		b[i] = x[i].sub(a[i])
		d[i] = y[i].sub(c[i])
	}
	run := func() (*groupedArithmeticResult, *groupedArithmeticResult) {
		left, right := net.Pipe()
		defer left.Close()
		defer right.Close()
		left.SetDeadline(time.Now().Add(5 * time.Minute))
		right.SetDeadline(time.Now().Add(5 * time.Minute))
		l, r := &primitiveVCountingRW{Conn: left}, &primitiveVCountingRW{Conn: right}
		s := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
		plan := groupedArithmeticPlan{Count: n, Contract: sha256.Sum256([]byte("public synthetic arithmetic test"))}
		type result struct {
			out *groupedArithmeticResult
			err error
		}
		ch := make(chan result, 1)
		start := time.Now()
		go func() {
			v, err := registerGroupedExactArithmetic()(l, s, exactGCRoleGarbler, plan, a, c)
			if err != nil {
				left.Close()
			}
			ch <- result{v, err}
		}()
		v, err := registerGroupedExactArithmetic()(r, s, exactGCRoleEvaluator, plan, b, d)
		if err != nil {
			right.Close()
		}
		peer := <-ch
		if err != nil || peer.err != nil {
			t.Fatalf("protocol %v / %v", peer.err, err)
		}
		t.Logf("products=%d garbler_bytes=%d evaluator_bytes=%d seconds=%.6f", n, l.Written, r.Written, time.Since(start).Seconds())
		for i := range x {
			got := peer.out.Shares[i].add(v.Shares[i])
			want := new(big.Int).Mul(groupedWordBig(x[i]), groupedWordBig(y[i]))
			want.Mod(want, new(big.Int).Lsh(big.NewInt(1), 192))
			if groupedWordBig(got).Cmp(want) != 0 {
				t.Fatalf("product %d mismatch", i)
			}
		}
		if peer.out.Receipt == v.Receipt || v.Receipt == ([32]byte{}) {
			t.Fatal("receipt missing role binding")
		}
		return peer.out, v
	}
	first, _ := run()
	if n == 8 {
		second, _ := run()
		if first.Shares[0] == second.Shares[0] || first.Receipt == second.Receipt {
			t.Fatal("freshness failure")
		}
	}
}
func TestGroupedArithmeticRejectsInvalidPlans(t *testing.T) {
	s := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
	good := groupedArithmeticPlan{Count: 1, Contract: sha256.Sum256([]byte("test"))}
	bad := []groupedArithmeticPlan{good, good, good, good, good}
	bad[0].Contract = [32]byte{}
	bad[1].Count = 0
	bad[2].Count = 1025
	bad[3].Chunk = 1
	bad[4].Previous = good.Contract
	for _, p := range bad {
		if _, err := groupedArithmeticSession(s, p); err == nil {
			t.Fatal("bad plan accepted")
		}
	}
	if _, err := groupedArithmeticProduct(nil, s, exactGCRoleGarbler, good, nil, nil); err == nil {
		t.Fatal("bad shape accepted")
	}
	next := good
	next.Chunk = 1
	next.Previous = good.Contract
	a, err := groupedArithmeticSession(s, good)
	if err != nil {
		t.Fatal(err)
	}
	b, err := groupedArithmeticSession(s, next)
	if err != nil {
		t.Fatal(err)
	}
	if exactGCContextDigest(a) == exactGCContextDigest(b) {
		t.Fatal("schedule not bound")
	}
}

func TestGroupedArithmeticRecordBinding(t *testing.T) {
	base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
	plan := groupedArithmeticPlan{Count: 1, Contract: sha256.Sum256([]byte("record binding"))}
	session, err := groupedArithmeticSession(base, plan)
	if err != nil {
		t.Fatal(err)
	}
	raw := exactGCTestRecord(session, []byte("synthetic arithmetic share"))
	for _, kind := range []string{"contract", "chunk", "count", "tamper", "role", "replay"} {
		t.Run(kind, func(t *testing.T) {
			changed := plan
			role := exactGCRoleEvaluator
			wire := append([]byte(nil), raw...)
			switch kind {
			case "contract":
				changed.Contract[0] ^= 1
			case "chunk":
				changed.Chunk = 1
				changed.Previous = plan.Contract
			case "count":
				changed.Count = 2
			case "tamper":
				wire[len(wire)-1] ^= 1
			case "role":
				role = exactGCRoleGarbler
			case "replay":
				wire = append(wire, raw...)
			}
			other, err := groupedArithmeticSession(base, changed)
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := newExactGCSecureRecordRW(&readWriter{Reader: bytes.NewReader(wire)}, other, role)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadAll(receiver); err == nil {
				t.Fatal("unauthenticated arithmetic record accepted")
			}
		})
	}
}
