package main

import (
	"crypto/sha256"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func groupedShareComponentProbe(t *testing.T, p *primitiveVProgram, g, e, want []*big.Int) {
	t.Helper()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(3 * time.Minute))
	right.SetDeadline(time.Now().Add(3 * time.Minute))
	a, b := &primitiveVCountingRW{Conn: left}, &primitiveVCountingRW{Conn: right}
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
	contract := sha256.Sum256([]byte("synthetic share component benchmark"))
	type result struct {
		out []*big.Int
		err error
	}
	ch := make(chan result, 1)
	start := time.Now()
	go func() {
		out, err := groupedCompactRunGarbler(a, p, session, contract, g)
		if err != nil {
			left.Close()
		}
		ch <- result{out, err}
	}()
	out, err := groupedCompactRunEvaluator(b, p, session, contract, e)
	if err != nil {
		right.Close()
	}
	peer := <-ch
	if err != nil || peer.err != nil {
		t.Fatalf("protocol %v / %v", err, peer.err)
	}
	for i, v := range want {
		got := exactGCReferenceReconstruct(peer.out[i], out[i], 192)
		got = exactGCReferenceSigned(got, 192)
		if got.Cmp(v) != 0 {
			t.Fatalf("component coordinate %d mismatch", i)
		}
	}
	t.Logf("outputs=%d garbler_bytes=%d evaluator_bytes=%d seconds=%.6f tables=%d source=%x", p.OutputWords, a.Written, b.Written, time.Since(start).Seconds(), primitiveVTableBytes(p.Circuit), p.SourceSHA256)
}
func TestGroupedWideScalarEncrypted(t *testing.T) {
	n := 4
	if os.Getenv("DSVERT_GROUPED_WIDE_PROBE") == "1" {
		n = 32
	}
	p, err := groupedWideScalarCompile("exp", n)
	if err != nil {
		t.Fatal(err)
	}
	g, e, want := make([]*big.Int, n), make([]*big.Int, n), make([]*big.Int, n+1)
	for i := range g {
		x := int64(-262144 + i*524288/(n-1))
		v, err := groupedProfileEval("exp", x)
		if err != nil {
			t.Fatal(err)
		}
		mask, err := groupedRandomWord()
		if err != nil {
			t.Fatal(err)
		}
		g[i] = groupedWordInteger(mask)
		e[i] = exactGCEncodeSigned(new(big.Int).Sub(big.NewInt(x), g[i]), 192)
		want[i] = big.NewInt(v)
	}
	want[n] = big.NewInt(1)
	groupedShareComponentProbe(t, p, g, e, want)
}
func TestGroupedLMMWideBoundaryEncrypted(t *testing.T) {
	lift, err := groupedLMMLiftCompile(1)
	if err != nil {
		t.Fatal(err)
	}
	groupedShareComponentProbe(t, lift, []*big.Int{exactGCEncodeSigned(big.NewInt(-3), 192)}, []*big.Int{big.NewInt(2)}, []*big.Int{big.NewInt(-1)})
	final, err := groupedLMMFinalCompile(16, 999)
	if err != nil {
		t.Fatal(err)
	}
	value := new(big.Int).Lsh(big.NewInt(13), 248)
	groupedShareComponentProbe(t, final, []*big.Int{big.NewInt(19), big.NewInt(0), big.NewInt(8)}, []*big.Int{exactGCEncodeSigned(big.NewInt(-19), 192), new(big.Int).Sub(new(big.Int).Rsh(value, 192), big.NewInt(1)), exactGCEncodeSigned(big.NewInt(-7), 192)}, []*big.Int{big.NewInt(13), big.NewInt(1)})
}
