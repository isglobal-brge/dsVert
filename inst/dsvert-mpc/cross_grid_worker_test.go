package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCrossGridDurableWorkers(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			p := crossGridKernelTestPlan(family)
			x := crossGridKernelTestSource(p, rand.New(rand.NewSource(927)))
			left, right := exactGCTestSplit(rand.New(rand.NewSource(918)), x, 128)
			for i := p.Rows * 2 * (p.Predictors + 1); i < len(x); i++ {
				right[i].Xor(left[i], x[i])
			}
			gd, ed := exactGCTestSpool(t, "grid-g"), exactGCTestSpool(t, "grid-e")
			sid := sha256.Sum256([]byte("synthetic/durable/" + family))
			master := sha256.Sum256([]byte("synthetic/master/" + family))
			base := exactGCWorkerConfig{Version: exactGCWorkerConfigVersion, SessionID: hex.EncodeToString(sid[:]), MasterKey: base64.StdEncoding.EncodeToString(master[:]), GarblerID: "peer-a", EvaluatorID: "peer-b", Purpose: p.purpose(), Operation: string(crossGridKernelOperation), RingBits: 128, VectorLen: len(p.Beta), CrossGrid: &p, MaxSpoolBytes: 1 << 30, TTLSeconds: 120}
			encoding := exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 128, FracBits: 1, VectorLen: p.sourceCount()}
			gc, ec := base, base
			gc.Role, gc.SpoolDir = "garbler", gd
			ec.Role, ec.SpoolDir = "evaluator", ed
			seed := sha256.Sum256([]byte("synthetic/sticky-mask/" + family))
			gc.PrivateSeed = base64.StdEncoding.EncodeToString(seed[:])
			gc.SourceShare = exactGCTestEncodeSource(t, left, encoding)
			ec.SourceShare = exactGCTestEncodeSource(t, right, encoding)
			gp, ep := exactGCTestWriteConfig(t, gd, gc), exactGCTestWriteConfig(t, ed, ec)
			done := make(chan error, 2)
			go func() { done <- handleExactGCWorker(gp) }()
			go func() { done <- handleExactGCWorker(ep) }()
			goff, eoff := int64(0), int64(0)
			deadline := time.Now().Add(120 * time.Second)
			received := 0
			for !exactGCTestBothDone(gd, ed) && time.Now().Before(deadline) {
				select {
				case err := <-done:
					received++
					if err != nil {
						t.Fatal(err)
					}
				default:
				}
				goff = exactGCTestRelaySpool(t, gd, ed, goff)
				eoff = exactGCTestRelaySpool(t, ed, gd, eoff)
				now := time.Now()
				for _, dir := range []string{gd, ed} {
					if err := os.Chtimes(filepath.Join(dir, "exchange.hb"), now, now); err != nil {
						t.Fatal(err)
					}
				}
				time.Sleep(time.Millisecond)
			}
			if !exactGCTestBothDone(gd, ed) {
				t.Fatal("grid worker completion rejected")
			}
			for i := received; i < 2; i++ {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			if fileExists(gp) || fileExists(ep) {
				t.Fatal("source-bearing config survived")
			}
			gr, er := exactGCTestReadResult(t, gd), exactGCTestReadResult(t, ed)
			if gr.Kind != "cross-grid-ring128-share-v2" || er.Kind != gr.Kind || gr.ContextHash != er.ContextHash {
				t.Fatal("grid result evidence mismatch")
			}
			encoding.VectorLen = len(p.Beta)
			g, err := exactGCDecodeWorkerShares(gr.Share, encoding)
			if err != nil {
				t.Fatal(err)
			}
			e, err := exactGCDecodeWorkerShares(er.Share, encoding)
			if err != nil {
				t.Fatal(err)
			}
			for j, want := range crossGridKernelOracle(t, p, x) {
				if exactGCReferenceReconstruct(g[j], e[j], 128).Cmp(want) != 0 {
					t.Fatal("durable worker oracle mismatch")
				}
			}
			gv, err := unpackBoolsB64(gr.ValidityShare, 1)
			if err != nil {
				t.Fatal(err)
			}
			ev, err := unpackBoolsB64(er.ValidityShare, 1)
			if err != nil {
				t.Fatal(err)
			}
			if gv[0] == ev[0] {
				t.Fatal("durable alignment failed")
			}
			// Completed spool state cannot be reused for a new evaluation.
			if exactGCPrepareWorkerSpool(gd) == nil || exactGCPrepareWorkerSpool(ed) == nil {
				t.Fatal("terminal spool replay accepted")
			}
		})
	}
}

func TestCrossGridStickyOutputMasks(t *testing.T) {
	p := crossGridKernelTestPlan("binomial")
	k, err := crossGridKernelPrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	x := crossGridKernelTestSource(p, rand.New(rand.NewSource(123)))
	seed := sha256.Sum256([]byte("synthetic/release-key-and-batch"))
	var priorG, priorE []*big.Int
	for attempt := 0; attempt < 2; attempt++ {
		left, right := exactGCTestSplit(rand.New(rand.NewSource(int64(attempt+1))), x, 128)
		for i := p.Rows * 2 * (p.Predictors + 1); i < len(x); i++ {
			right[i].Xor(left[i], x[i])
		}
		a, b := net.Pipe()
		session := exactGCTestSession(exactGCCircuitSpec{Operation: crossGridKernelOperation, RingBits: 128, VectorLen: len(p.Beta)})
		session.Purpose = p.purpose()
		session.SessionID = sha256.Sum256([]byte(fmt.Sprint("synthetic/fresh-attempt/", attempt)))
		var g []*big.Int
		done := make(chan error, 1)
		go func() {
			var err error
			g, err = k.runWithSeed(a, session, left, exactGCRoleGarbler, &seed)
			if err != nil {
				a.Close()
			}
			done <- err
		}()
		e, err := k.run(b, session, right, exactGCRoleEvaluator)
		if err != nil {
			b.Close()
			<-done
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
		a.Close()
		b.Close()
		if attempt > 0 {
			for j := range g {
				if g[j].Cmp(priorG[j]) != 0 || e[j].Cmp(priorE[j]) != 0 {
					t.Fatal("sticky output changed across fresh transport/source sharing")
				}
			}
		}
		priorG, priorE = g, e
	}
}
