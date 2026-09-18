package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/markkurossi/mpc/circuit"
	"math/big"
	"math/rand"
	"net"
	"testing"
	"time"
)

func crossGridKernelProtocolTest(t testing.TB, k *crossGridKernelPrepared, x []*big.Int, label string) ([]*big.Int, []*big.Int, uint64) {
	t.Helper()
	rng := rand.New(rand.NewSource(20260918))
	p := k.plan
	left, right := exactGCTestSplit(rng, x, 128)
	for i := p.Rows * 2 * (p.Predictors + 1); i < len(x); i++ {
		right[i].Xor(left[i], x[i])
	}
	a, b := net.Pipe()
	gconn, econn := &crossGridPWCountingConn{Conn: a}, &crossGridPWCountingConn{Conn: b}
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(5 * time.Minute))
	b.SetDeadline(time.Now().Add(5 * time.Minute))
	session := exactGCTestSession(exactGCCircuitSpec{Operation: crossGridKernelOperation, RingBits: 128, VectorLen: len(p.Beta)})
	session.Purpose = p.purpose()
	session.SessionID = sha256.Sum256([]byte(label))
	var g []*big.Int
	done := make(chan error, 1)
	go func() {
		var err error
		g, err = k.run(gconn, session, left, exactGCRoleGarbler)
		if err != nil {
			a.Close()
		}
		done <- err
	}()
	e, err := k.run(econn, session, right, exactGCRoleEvaluator)
	if err != nil {
		b.Close()
		<-done
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	want := crossGridKernelOracle(t, p, x)
	for i := range want {
		if exactGCReferenceReconstruct(g[i], e[i], 128).Cmp(want[i]) != 0 {
			t.Fatal("two-authority fused oracle mismatch")
		}
	}
	return g, e, gconn.written.Load() + econn.written.Load()
}

func TestCrossGridKernelTwoAuthority(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			p := crossGridKernelTestPlan(family)
			k, err := crossGridKernelPrepare(p)
			if err != nil {
				t.Fatal(err)
			}
			x := crossGridKernelTestSource(p, rand.New(rand.NewSource(92)))
			for _, bad := range []bool{false, true} {
				if bad {
					x[len(x)-1].SetInt64(92)
				}
				g, e, bytes := crossGridKernelProtocolTest(t, k, x, fmt.Sprintf("%s/invalid=%t", family, bad))
				valid := g[len(p.Beta)].Bit(0) != e[len(p.Beta)].Bit(0)
				if valid == bad {
					t.Fatal("private alignment validity mismatch")
				}
				t.Logf("family=%s invalid=%t wire-bytes=%d", family, bad, bytes)
			}
		})
	}
}

func TestCrossGridKernelJointNoise(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			p := crossGridKernelTestPlan(family)
			k, err := crossGridKernelPrepare(p)
			if err != nil {
				t.Fatal(err)
			}
			x := crossGridKernelTestSource(p, rand.New(rand.NewSource(92)))
			g, e, _ := crossGridKernelProtocolTest(t, k, x, "joint/"+family)
			gseed := sha256.Sum256([]byte("synthetic/garbler/" + family))
			eseed := sha256.Sum256([]byte("synthetic/evaluator/" + family))
			sensitivity := new(big.Int)
			upper := make([]int64, len(p.Beta))
			for j, cap := range p.Caps {
				sensitivity.Add(sensitivity, new(big.Int).SetUint64(cap))
				upper[j] = int64(cap) * int64(p.Rows)
			}
			plan := jointDPVectorTestPlan(t, "4", "7.888609052210118054117285652827862296732064351090230047702789306640625e-31", sensitivity.String(), len(p.Beta))
			spec := jointDPVectorTestSpec(t, plan, 0, upper, "synthetic/grid/"+p.purpose(), gseed, eseed)
			spec.OutputLatticeBits = p.GridBits
			session := jointDPVectorTestSession(spec, "synthetic/grid/"+family)
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(60 * time.Second))
			b.SetDeadline(time.Now().Add(60 * time.Second))
			var ng []*big.Int
			done := make(chan error, 1)
			go func() {
				var err error
				ng, err = jointDPVectorRunGarbler(a, session, spec, g[:len(p.Beta)], gseed)
				if err != nil {
					a.Close()
				}
				done <- err
			}()
			ne, err := jointDPVectorRunEvaluator(b, session, spec, e[:len(p.Beta)], eseed)
			if err != nil {
				b.Close()
				<-done
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			noise, err := jointDPVectorReferenceNoise(spec, gseed, eseed)
			if err != nil {
				t.Fatal(err)
			}
			raw := crossGridKernelOracle(t, p, x)
			for j := range raw {
				want := new(big.Int).Add(raw[j], noise[j])
				if want.Sign() < 0 {
					want.SetInt64(0)
				}
				if want.Cmp(spec.RawUpperBounds[j]) > 0 {
					want.Set(spec.RawUpperBounds[j])
				}
				if exactGCReferenceReconstruct(ng[j], ne[j], 128).Cmp(want) != 0 {
					t.Fatal("joint DP oracle mismatch")
				}
			}
			t.Log("real two-authority kernel plus joint-noise equality; no server lifecycle claim")
		})
	}
}

func BenchmarkCrossGridFusedBatch(b *testing.B) {
	for _, family := range []string{"binomial", "poisson"} {
		b.Run(family, func(b *testing.B) {
			p := crossGridKernelCostPlan(b, family)
			start := time.Now()
			k, err := crossGridKernelPrepare(p)
			if err != nil {
				b.Fatal(err)
			}
			compile := time.Since(start)
			x := crossGridKernelTestSource(p, rand.New(rand.NewSource(92)))
			b.ResetTimer()
			var bytes uint64
			for i := 0; i < b.N; i++ {
				_, _, n := crossGridKernelProtocolTest(b, k, x, fmt.Sprintf("benchmark/%s/%d", family, i))
				bytes += n
			}
			b.StopTimer()
			b.ReportMetric(float64(bytes)/float64(b.N*256), "wire-B/eval")
			b.ReportMetric(float64(k.circuit.Stats[circuit.AND])/256, "AND/eval")
			b.Logf("batch_AND=%d total_wire_bytes=%d iterations=%d cap=%d", k.circuit.Stats[circuit.AND], bytes, b.N, p.Caps[0])
			b.ReportMetric(compile.Seconds(), "compile-s")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*256), "ns/eval")
		})
	}
}

func TestCrossGridKernelPurposeAndAdmissionGate(t *testing.T) {
	p := crossGridKernelTestPlan("binomial")
	spec := exactGCCircuitSpec{Operation: crossGridKernelOperation, RingBits: 128, VectorLen: len(p.Beta)}
	if _, err := exactGCCompileCircuit(spec); err != errCrossGridKernel {
		t.Fatal("ordinary RPC compiler admitted specialised kernel")
	}
	k, err := crossGridKernelPrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	session := exactGCTestSession(spec)
	session.Purpose = p.purpose()
	channel := new(bytes.Buffer)
	if _, err := k.run(channel, session, nil, exactGCRoleGarbler); err != errCrossGridKernel || channel.Len() != 0 {
		t.Fatal("unsafe source-shape admission")
	}
	x := crossGridKernelTestSource(p, rand.New(rand.NewSource(3)))
	altered := session
	altered.Purpose += "/tampered"
	if _, err := k.run(channel, altered, x, exactGCRoleGarbler); err != errCrossGridKernel || channel.Len() != 0 {
		t.Fatal("unsafe context admission")
	}
	x[0] = new(big.Int).Lsh(big.NewInt(1), 128)
	if _, err := k.run(channel, session, x, exactGCRoleGarbler); err != errCrossGridKernel || channel.Len() != 0 {
		t.Fatal("unsafe residue admission")
	}
	p.Beta[0][0] = "0"
	p.Caps[0] = 1
	if k.plan.Beta[0][0] == "0" || k.plan.Caps[0] == 1 {
		t.Fatal("prepared plan aliases caller storage")
	}
}
