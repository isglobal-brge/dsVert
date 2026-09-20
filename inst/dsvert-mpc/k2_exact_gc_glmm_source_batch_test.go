package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// Compare the original and batched authenticated exchanges on identical private
// inputs, including two full batches, a tail and an invalid boundary value.
func TestGroupedGLMMOutcomeBatchEquality(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, invalid := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/invalid=%v", family, invalid), func(t *testing.T) {
				s, _, _, _ := groupedGLMMSourceFixture(t, family)
				const rows = 516
				s.Route.Clusters, s.Route.Slots = rows/4, 4
				numeric, outcome := make([]*big.Int, rows), make([]*big.Int, rows)
				maximum := int64(1)
				if family == "poisson" {
					maximum = 4
				}
				for i := range numeric {
					numeric[i] = new(big.Int).Lsh(big.NewInt(int64(i%2)), 49)
					outcome[i] = big.NewInt(int64(i) % (maximum + 1))
				}
				if invalid {
					outcome[256] = big.NewInt(maximum + 1)
				}
				x, y := crossGridStageConversionTestShares(numeric), crossGridStageConversionTestShares(outcome)
				for role := range x {
					for i := range x[role].Validity {
						x[role].Validity[i] = byte(role)
						y[role].Validity[i] = byte(role)
					}
				}
				var baseline []byte
				for _, batch := range []int{32, 256} {
					base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1})
					attempt := crossGridStageAttempt{Session: base, Nonce: sha256.Sum256([]byte(fmt.Sprint(batch))), OutputMaskDomainTag: sha256.Sum256([]byte("outcome-batch-test"))}
					left, right := net.Pipe()
					left.SetDeadline(time.Now().Add(3 * time.Minute))
					right.SetDeadline(time.Now().Add(3 * time.Minute))
					type result struct {
						out crossGridStageOutput
						err error
					}
					run := func(role int, rw io.ReadWriter) result {
						_, compute := groupedGLMMSourceNormalizationBatch(s, exactGCRole(role), batch)
						out, err := compute(rw, attempt, []crossGridStageOutput{x[role], y[role]})
						return result{out, err}
					}
					ch := make(chan result, 1)
					go func() { a := run(0, left); left.Close(); ch <- a }()
					b := run(1, right)
					right.Close()
					a := <-ch
					if a.err != nil || b.err != nil {
						t.Fatalf("batch %d: %v / %v", batch, a.err, b.err)
					}
					opened := make([]byte, len(a.out.Share)+len(a.out.Validity))
					for i := range a.out.Validity {
						v := getUint128LE(a.out.Share[16*i:]).Add(getUint128LE(b.out.Share[16*i:]))
						want := numeric[i/2]
						if i%2 == 1 {
							want = new(big.Int).Lsh(new(big.Int).Set(outcome[i/2]), 50)
							if invalid && i/2 == 256 {
								want = new(big.Int)
							}
						}
						if v != U128FromBig(want) {
							t.Fatalf("batch %d coordinate %d differs", batch, i)
						}
						putUint128LE(opened[16*i:], v)
						flag := a.out.Validity[i] ^ b.out.Validity[i]
						if flag != byte(map[bool]int{false: 1, true: 0}[invalid]) {
							t.Fatal("private validity changed")
						}
						opened[len(a.out.Share)+i] = flag
					}
					if batch == 32 {
						baseline = opened
					} else if !bytes.Equal(baseline, opened) {
						t.Fatal("batching changed opened values/validity")
					}
					t.Logf("batch=%d opened_sha256=%x", batch, sha256.Sum256(opened))
				}
			})
		}
	}
}
