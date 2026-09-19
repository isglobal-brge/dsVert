package main

import (
	"crypto/sha256"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
)

func groupedScalarFixture(t *testing.T, p *primitiveVProgram, name string, invalid bool, compact bool) (int64, int64) {
	t.Helper()
	n := p.InputWordsE
	g, e, want := make([]*big.Int, n), make([]*big.Int, n), make([]int64, n+1)
	lower, upper := int64(-262144), int64(262144)
	if profile, ok := groupedProfiles[name]; ok {
		lower, upper = profile.Lower, profile.Upper
	}
	if name == "exp_negative" {
		lower, upper = -1048576, 0
	}
	for i := range g {
		x := lower + int64(i)*(upper-lower)/int64(n-1)
		want[i], _ = groupedProfileEval(name, x)
		if invalid && i == 0 {
			x = lower - 1
		}
		g[i] = new(big.Int).Mod(big.NewInt(x-101), exactGCModulus(32))
		e[i] = big.NewInt(101)
	}
	want[n] = 1
	if invalid {
		for i := range want {
			want[i] = 0
		}
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Minute))
	b.SetDeadline(time.Now().Add(time.Minute))
	ca, cb := &primitiveVCountingRW{Conn: a}, &primitiveVCountingRW{Conn: b}
	s := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 32, VectorLen: 1})
	contract := sha256.Sum256([]byte("grouped scalar synthetic component only"))
	garbler, evaluator := primitiveVRunGarbler, primitiveVRunEvaluator
	if compact {
		garbler, evaluator = groupedCompactRunGarbler, groupedCompactRunEvaluator
	}
	type result struct {
		out []*big.Int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := garbler(ca, p, s, contract, g)
		if err != nil {
			a.Close()
		}
		ch <- result{out, err}
	}()
	out, err := evaluator(cb, p, s, contract, e)
	if err != nil {
		b.Close()
	}
	peer := <-ch
	if err != nil || peer.err != nil {
		t.Fatalf("protocol: %v %v", err, peer.err)
	}
	for i := range want {
		v := exactGCReferenceReconstruct(peer.out[i], out[i], 32)
		if v.Int64() != want[i] {
			t.Fatalf("%s coordinate %d got %s want %d", name, i, v, want[i])
		}
	}
	return ca.Written, cb.Written
}

func TestGroupedScalarChunks(t *testing.T) {
	count := 4
	if os.Getenv("DSVERT_GROUPED_SCALAR_PROBE") == "1" {
		count = 32
	}
	for _, name := range []string{"softplus", "exp", "exp_negative", "log", "sigmoid", "sqrt_variance", "inverse_sqrt_variance"} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			p, err := groupedScalarCompile(name, count)
			if err != nil {
				t.Fatal(err)
			}
			compile := time.Since(start).Seconds()
			if p.Circuit.Stats[circuit.AND] > uint64(5000*count) {
				t.Fatal("scalar gate exceeded including guards/masks")
			}
			start = time.Now()
			g, e := groupedScalarFixture(t, p, name, false, true)
			t.Logf("component=%s count=%d gates=%d and=%d tables=%d garbler_bytes=%d evaluator_bytes=%d compile_s=%.6f protocol_s=%.6f source=%x", name, count, p.Circuit.NumGates, p.Circuit.Stats[circuit.AND], primitiveVTableBytes(p.Circuit), g, e, compile, time.Since(start).Seconds(), p.SourceSHA256)
			groupedScalarFixture(t, p, name, true, true)
			if name == "softplus" {
				lg, le := groupedScalarFixture(t, p, name, false, false)
				if g+e >= lg+le {
					t.Fatal("compact framing did not reduce transport")
				}
			}
		})
	}
}

func TestGroupedScalarAdmissionAndTopology(t *testing.T) {
	for _, name := range []string{"", "unknown", "x);"} {
		if _, err := groupedScalarCompile(name, 4); err == nil {
			t.Fatal("unknown scalar accepted")
		}
	}
	for _, n := range []int{-1, 0, 33} {
		if _, err := groupedScalarCompile("softplus", n); err == nil {
			t.Fatal("bad chunk accepted")
		}
	}
	p, err := groupedScalarCompile("softplus", 2)
	if err != nil {
		t.Fatal(err)
	}
	s := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 32, VectorLen: 1})
	contract := sha256.Sum256([]byte("record-context regression"))
	legacy, err := p.session(s, contract)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := groupedCompactSession(p, s, contract)
	if err != nil {
		t.Fatal(err)
	}
	if exactGCContextDigest(legacy) == exactGCContextDigest(compact) {
		t.Fatal("framing mode shares record-key context")
	}
	d := exactGCProtocolDigest(s, p.Circuit, true)
	if d == exactGCProtocolDigest(s, p.Circuit, false) {
		t.Fatal("framing mode unbound")
	}
	other := *p.Circuit
	other.NumWires++
	if d == exactGCProtocolDigest(s, &other, true) {
		t.Fatal("topology unbound")
	}
	s.Purpose += "/foreign"
	if d == exactGCProtocolDigest(s, p.Circuit, true) {
		t.Fatal("purpose unbound")
	}
}
