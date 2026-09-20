package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/p2p"
)

type crossGridPWCountingConn struct {
	net.Conn
	written atomic.Uint64
}

func (c *crossGridPWCountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(uint64(n))
	return n, err
}

// Both authorities use the real Yao/KOS engine and encrypted record framing.
// This test has no production admission, source materializer or DP release.
func crossGridPWProtocol(t testing.TB, c *circuit.Circuit, p crossGridPWProfile, x uint32) (uint32, bool, uint64) {
	t.Helper()
	a, b := net.Pipe()
	left, right := &crossGridPWCountingConn{Conn: a}, &crossGridPWCountingConn{Conn: b}
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(20 * time.Second))
	_ = right.SetDeadline(time.Now().Add(20 * time.Second))
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 32, FracBits: 0, VectorLen: 1})
	session.Purpose = "test-only-cross-grid-profile/" + p.Identity
	session.SessionID = sha256.Sum256([]byte(session.Purpose))
	first, err := newExactGCSecureRecordRW(left, session, exactGCRoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newExactGCSecureRecordRW(right, session, exactGCRoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	const share, mask uint32 = 0x81234567, 0xfedcba98
	g := new(big.Int).SetUint64(uint64(mask)<<32 | uint64(share))
	e := new(big.Int).SetUint64(uint64(x - share))
	done := make(chan error, 1)
	go func() {
		err := exactGCGarblerProtocol(p2p.NewConn(first), c, g, session)
		if err != nil {
			left.Close()
		}
		done <- err
	}()
	result, err := exactGCEvaluatorProtocol(p2p.NewConn(second), c, e, session)
	if err != nil {
		right.Close()
		<-done
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.BitLen() > 33 {
		t.Fatal("public profile output arity")
	}
	return uint32(result.Uint64()) + mask, result.Bit(32) != 0, left.written.Load() + right.written.Load()
}

func TestCrossGridPWV2TwoAuthorityProtocol(t *testing.T) {
	for _, p := range crossGridPWProfiles(t) {
		if p.Pieces != 64 || (p.A != 4 && p.A != 16) {
			continue
		}
		t.Run(p.Identity, func(t *testing.T) {
			c := crossGridPWCompile(t, p)
			for _, x := range []uint32{0, uint32(p.A*65536 + 1), uint32(2 * p.A * 65536), uint32(2*p.A*65536 + 1)} {
				start := time.Now()
				got, valid, bytes := crossGridPWProtocol(t, c, p, x)
				want, wantValid := crossGridPWOracle(p, x)
				if got != want || valid != wantValid {
					t.Fatal("two-authority integer oracle mismatch")
				}
				t.Logf("protocol_bytes=%d wall_ms=%.3f", bytes, float64(time.Since(start).Microseconds())/1000)
			}
		})
	}
}

func BenchmarkCrossGridPWV2Protocol(b *testing.B) {
	for _, p := range crossGridPWProfiles(b) {
		if p.Pieces != 64 || (p.A != 4 && p.A != 16) {
			continue
		}
		b.Run(fmt.Sprintf("%s/A%d", p.Family, p.A), func(b *testing.B) {
			c := crossGridPWCompile(b, p)
			x := uint32(p.A*65536 + 1)
			want, wantValid := crossGridPWOracle(p, x)
			b.ResetTimer()
			var bytes uint64
			for i := 0; i < b.N; i++ {
				got, valid, n := crossGridPWProtocol(b, c, p, x)
				if got != want || valid != wantValid {
					b.Fatal("integer mismatch")
				}
				bytes += n
			}
			b.StopTimer()
			b.ReportMetric(float64(bytes)/float64(b.N), "wire-B/eval")
			b.ReportMetric(float64(c.Stats[circuit.AND]), "AND/eval")
		})
	}
}

func TestCrossGridPWV2OptimizerExhaustive(t *testing.T) {
	raw, _, err := compiler.New(crossGridPWCompilerParams()).Compile(`package main
func main(a uint8,b uint8)(uint8,uint8) {
 x := (a*b) ^ ((a+b)<<2)
 if a < b {x = x ^ 255}
 return x, (a & b) | ((a ^ 255) & (b ^ 255))
}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	optimized := crossGridPWOptimize(raw)
	for a := int64(0); a < 256; a++ {
		for b := int64(0); b < 256; b++ {
			input := []*big.Int{big.NewInt(a), big.NewInt(b)}
			want, err := raw.Compute(input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := optimized.Compute(input)
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				if got[i].Cmp(want[i]) != 0 {
					t.Fatal("Boolean optimization changed output")
				}
			}
		}
	}
}
