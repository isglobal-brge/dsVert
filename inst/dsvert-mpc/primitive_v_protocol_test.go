package main

import (
	"crypto/sha256"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

const primitiveVProtocolTestSource = `package main
func main(g [4]int192, e [2]int192) [2]int192 {
	var output [2]int192
	x := g[0] + e[0]
	valid := g[1] + e[1] == 1
	v := int192(0)
	if valid { v = 1 } else { x = 0 }
	output[0] = x - g[2]
	output[1] = v - g[3]
	return output
}`

func primitiveVTestProtocol(t *testing.T, p *primitiveVProgram, g, e []*big.Int) ([]*big.Int, int64) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(2 * time.Minute))
	b.SetDeadline(time.Now().Add(2 * time.Minute))
	session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: p.WordBits, VectorLen: 1})
	contract := sha256.Sum256([]byte("synthetic public signed-contract digest"))
	type result struct {
		out []*big.Int
		err error
	}
	ch := make(chan result, 1)
	counted := &primitiveVCountingRW{Conn: a}
	go func() {
		out, err := primitiveVRunGarbler(counted, p, session, contract, g)
		ch <- result{out, err}
	}()
	eout, err := primitiveVRunEvaluator(b, p, session, contract, e)
	if err != nil {
		b.Close()
	}
	got := <-ch
	if err != nil || got.err != nil {
		t.Fatalf("protocol rejected: evaluator=%v garbler=%v", err, got.err)
	}
	for i := range eout {
		eout[i] = exactGCReferenceReconstruct(got.out[i], eout[i], p.WordBits)
	}
	return eout, counted.Written
}

type primitiveVCountingRW struct {
	net.Conn
	Written int64
}

func (c *primitiveVCountingRW) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.Written += int64(n)
	return n, err
}

func TestPrimitiveVProtocolMaskedValidityAndNative192(t *testing.T) {
	p, err := primitiveVCompile(primitiveVProtocolTestSource, 192, 4, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, live := range []int64{0, 1, 2} {
		g := []*big.Int{exactGCEncodeSigned(big.NewInt(-27), 192), big.NewInt(63)}
		e := []*big.Int{big.NewInt(12), exactGCEncodeSigned(big.NewInt(live-63), 192)}
		out, _ := primitiveVTestProtocol(t, p, g, e)
		if live == 1 {
			if exactGCReferenceSigned(out[0], 192).Int64() != -15 || out[1].Int64() != 1 {
				t.Fatal("valid native Ring192 result differs")
			}
		} else if out[0].Sign() != 0 || out[1].Sign() != 0 {
			t.Fatal("invalid private input was not masked closed")
		}
	}
}

func TestPrimitiveVProtocolContextAndAdmission(t *testing.T) {
	p, err := primitiveVCompile(primitiveVProtocolTestSource, 192, 4, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
	contract := sha256.Sum256([]byte("contract one"))
	s1, err := p.session(base, contract)
	if err != nil {
		t.Fatal(err)
	}
	contract[0] ^= 1
	s2, _ := p.session(base, contract)
	if exactGCContextDigest(s1) == exactGCContextDigest(s2) {
		t.Fatal("contract not bound")
	}
	q := *p
	q.SourceSHA256[0] ^= 1
	s3, _ := q.session(base, contract)
	if exactGCContextDigest(s2) == exactGCContextDigest(s3) {
		t.Fatal("source not bound")
	}
	if _, err := exactGCCompileCircuit(base.Spec); err == nil {
		t.Fatal("generic route admitted primitive")
	}
	if _, err := p.session(base, [32]byte{}); err == nil {
		t.Fatal("missing contract admitted")
	}
	if _, err := primitiveVCompile(primitiveVProtocolTestSource, 192, 3, 2, 2); err == nil {
		t.Fatal("shape mismatch admitted")
	}
	if _, err := primitiveVCompile(strings.Repeat("x", (2<<20)+1), 192, 4, 2, 2); err == nil {
		t.Fatal("oversized source admitted")
	}
	if primitiveVValidateWords([]*big.Int{big.NewInt(-1)}, 1, 192) == nil {
		t.Fatal("negative share admitted")
	}
	if primitiveVValidateWords([]*big.Int{new(big.Int).Lsh(big.NewInt(1), 192)}, 1, 192) == nil {
		t.Fatal("oversized share admitted")
	}
}
