package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/p2p"
)

func crossGridExpReducedBatchCompile(t testing.TB, p crossGridExpReducedProfile, n int) *circuit.Circuit {
	t.Helper()
	return crossGridProfileBatchCompile(t, crossGridExpReducedSource(p), n)
}

func crossGridProfileBatchCompile(t testing.TB, source string, n int) *circuit.Circuit {
	t.Helper()
	source = strings.Replace(source, "func main(", "func one(", 1)
	source += fmt.Sprintf(`func main(g [%d]uint64,e [%d]uint32) ([%d]uint64,bool) {
 var out [%d]uint64
 valid:=true
 var v uint64
 var ok bool
 var row [2]uint64
 for i:=0;i<%d;i++ {
  row[0]=g[2*i]
  row[1]=g[2*i+1]
  v,ok=one(row,e[i])
  out[i]=v
  valid=valid && ok
 }
 return out,valid
}
`, 2*n, n, n, n, n)
	c, _, err := compiler.New(crossGridPWCompilerParams()).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	return crossGridPWOptimize(c)
}

// Real two-authority Yao/KOS, synthetic inputs, no source/admission bypass
// represented as production. Compact mode is topology-bound before any OT.
func crossGridExpReducedProtocol(t testing.TB, c *circuit.Circuit, p crossGridExpReducedProfile, values []int32, compact bool) uint64 {
	t.Helper()
	return crossGridProfileProtocol(t, c, p.Identity, values, compact, func(x int32) (uint64, bool) { return crossGridExpReducedOracle(p, x) })
}

func crossGridProfileProtocol(t testing.TB, c *circuit.Circuit, identity string, values []int32, compact bool, oracle func(int32) (uint64, bool)) uint64 {
	t.Helper()
	a, b := net.Pipe()
	left, right := &crossGridPWCountingConn{Conn: a}, &crossGridPWCountingConn{Conn: b}
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(60 * time.Second))
	_ = right.SetDeadline(time.Now().Add(60 * time.Second))
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 32, VectorLen: 1})
	session.Purpose = "test-only-cross-grid-profile-batch/" + identity
	session.SessionID = sha256.Sum256([]byte(session.Purpose))
	first, err := newExactGCSecureRecordRW(left, session, exactGCRoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newExactGCSecureRecordRW(right, session, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	g, e := new(big.Int), new(big.Int)
	const mask uint64 = 0xfedcba9876543210
	for i, x := range values {
		share := uint32(0x81234567 + uint32(i))
		g.Or(g, new(big.Int).Lsh(new(big.Int).SetUint64(uint64(share)), uint(128*i)))
		g.Or(g, new(big.Int).Lsh(new(big.Int).SetUint64(mask), uint(128*i+64)))
		e.Or(e, new(big.Int).Lsh(new(big.Int).SetUint64(uint64(uint32(x)-share)), uint(32*i)))
	}
	done := make(chan error, 1)
	go func() {
		err := exactGCGarblerProtocolMode(p2p.NewConn(first), c, g, session, compact)
		if err != nil {
			left.Close()
		}
		done <- err
	}()
	result, err := exactGCEvaluatorProtocolMode(p2p.NewConn(second), c, e, session, compact)
	if err != nil {
		right.Close()
		<-done
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	allValid := true
	for i, x := range values {
		want, valid := oracle(x)
		got := new(big.Int).Rsh(new(big.Int).Set(result), uint(64*i)).Uint64() + mask
		if got != want {
			t.Fatal("two-authority integer oracle mismatch")
		}
		allValid = allValid && valid
	}
	if (result.Bit(64*len(values)) != 0) != allValid || result.BitLen() > 64*len(values)+1 {
		t.Fatal("two-authority output shape/validity mismatch")
	}
	return left.written.Load() + right.written.Load()
}

func TestCrossGridExpReducedV2TwoAuthority(t *testing.T) {
	p := crossGridExpReducedProfiles(t)[2]
	for _, batch := range []int{1, 32} {
		c := crossGridExpReducedBatchCompile(t, p, batch)
		for _, compact := range []bool{false, true} {
			for _, invalid := range []bool{false, true} {
				values := make([]int32, batch)
				for i := range values {
					values[i] = int32(-16*(1<<26) + int64(i)*32*(1<<26)/int64(batch))
				}
				if invalid {
					values[0] = -(16 << 26) - 1
				}
				bytes := crossGridExpReducedProtocol(t, c, p, values, compact)
				t.Logf("batch=%d compact=%t invalid=%t AND/eval=%.3f wire-B/eval=%.3f", batch, compact, invalid, float64(c.Stats[circuit.AND])/float64(batch), float64(bytes)/float64(batch))
			}
		}
	}
}

func TestCrossGridExpReducedV2CompactContext(t *testing.T) {
	p := crossGridExpReducedProfiles(t)[2]
	c := crossGridExpReducedCompile(t, p)
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 32, VectorLen: 1})
	legacy := exactGCProtocolDigest(session, c, false)
	if legacy != exactGCContextDigest(session) {
		t.Fatal("legacy context changed")
	}
	compact := exactGCProtocolDigest(session, c, true)
	if compact == legacy {
		t.Fatal("framing mode not domain separated")
	}
	changed := *c
	changed.Gates = append([]circuit.Gate(nil), c.Gates...)
	changed.Gates[0].Input0++
	if exactGCProtocolDigest(session, &changed, true) == compact {
		t.Fatal("gate topology not committed")
	}
	session.Purpose += "/different"
	if exactGCProtocolDigest(session, c, true) == compact {
		t.Fatal("session not committed")
	}
	// Actual protocol mismatch, rejected at the context exchange before OT.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() { done <- exactGCGarblerProtocolMode(p2p.NewConn(a), c, big.NewInt(0), session, true) }()
	_, err := exactGCEvaluatorProtocolMode(p2p.NewConn(b), &changed, big.NewInt(0), session, true)
	if err == nil || err.Error() != "exact-gc: peer context mismatch" {
		t.Fatal("topology mismatch accepted or unsafe error")
	}
	b.Close()
	if <-done == nil {
		t.Fatal("garbler accepted mismatched topology")
	}
}

func BenchmarkCrossGridExpReducedV2Protocol(b *testing.B) {
	p := crossGridExpReducedProfiles(b)[2]
	for _, batch := range []int{1, 32} {
		for _, compact := range []bool{false, true} {
			b.Run(fmt.Sprintf("batch%d/compact%t", batch, compact), func(b *testing.B) {
				c := crossGridExpReducedBatchCompile(b, p, batch)
				values := make([]int32, batch)
				for i := range values {
					values[i] = int32(i * (1 << 20))
				}
				b.ResetTimer()
				var bytes uint64
				for i := 0; i < b.N; i++ {
					bytes += crossGridExpReducedProtocol(b, c, p, values, compact)
				}
				b.StopTimer()
				b.ReportMetric(float64(bytes)/float64(b.N*batch), "wire-B/eval")
				b.ReportMetric(float64(c.Stats[circuit.AND])/float64(batch), "AND/eval")
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*batch), "ns/eval")
			})
		}
	}
}
