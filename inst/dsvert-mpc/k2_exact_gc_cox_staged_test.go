package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCoxGridCrossStagedPrivateBridgeComposition(t *testing.T) {
	const n, jcount = 4, 2
	caps := make([]uint64, jcount)
	for j := range caps {
		caps[j], _ = coxLossCap(n, 12, []float64{4, 4})
	}
	p, err := registerCoxGridCrossLoss().SharedPlan(coxLossSpec{n, jcount, 12, caps, CoxGridCrossProfileID})
	if err != nil {
		t.Fatal(err)
	}
	programs, err := registerCoxGridCrossLoss().SharedCompile(p)
	if err != nil {
		t.Fatal(err)
	}
	times := []float64{1, 2, 2, 0}
	live := []bool{true, true, true, false}
	events := []bool{true, true, false, false}
	etas := [][]int32{{65536, -65536, 32768, 0}, {0, 16384, -32768, 0}}
	controls, err := primitiveVPermutationControls([]int{1, 2, 0, 3})
	if err != nil {
		t.Fatal(err)
	}
	ends := []bool{false, true, true, true}
	var shares [2][]Uint128
	var flags [2][]byte
	for i := 0; i < n; i++ {
		for c := 0; c < jcount+2; c++ {
			value := new(big.Int)
			if c < jcount {
				value.Lsh(big.NewInt(int64(etas[c][i])), 84)
			} else if (c == jcount && live[i]) || (c == jcount+1 && events[i]) {
				value.SetInt64(1)
			}
			mask := sha256.Sum256([]byte(fmt.Sprintf("synthetic Cox bridge/%d/%d", i, c)))
			a := U128FromBig(new(big.Int).SetBytes(mask[:16]))
			b := U128FromBig(exactGCEncodeSigned(value, 128)).Sub(a)
			shares[0] = append(shares[0], a)
			shares[1] = append(shares[1], b)
			flags[0] = append(flags[0], 1)
			flags[1] = append(flags[1], 0)
		}
	}
	wants := make([]uint64, jcount)
	for j := range wants {
		wants[j], err = coxLossReference(etas[j], times, events, live, caps[j], 12)
		if err != nil {
			t.Fatal(err)
		}
	}
	coxLossStagedDurableTest(t, p, shares, controls, ends, wants)
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid-source-%v", invalid), func(t *testing.T) {
			validity := [2][]byte{append([]byte(nil), flags[0]...), append([]byte(nil), flags[1]...)}
			if invalid {
				validity[1][0] = 1
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(time.Minute))
			right.SetDeadline(time.Now().Add(time.Minute))
			a := crossGridStageAttempt{Nonce: sha256.Sum256([]byte("attempt")), OutputMaskDomainTag: sha256.Sum256([]byte("mask")), Session: exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1})}
			contract := sha256.Sum256([]byte("synthetic Cox source and private sort"))
			type result struct {
				out crossGridStageOutput
				err error
			}
			ch := make(chan result, 1)
			go func() {
				out, err := coxLossRunBridgedShares(left, true, p, programs, a, contract, shares[0], controls, ends, validity[0])
				if err != nil {
					left.Close()
				}
				ch <- result{out, err}
			}()
			b, err := coxLossRunBridgedShares(right, false, p, programs, a, contract, shares[1], nil, nil, validity[1])
			if err != nil {
				right.Close()
			}
			peer := <-ch
			if err != nil || peer.err != nil {
				t.Fatalf("bridge composition %v / %v", peer.err, err)
			}
			for j := 0; j < jcount; j++ {
				want, err := coxLossReference(etas[j], times, events, live, caps[j], 12)
				if err != nil {
					t.Fatal(err)
				}
				v := byte(1)
				if invalid {
					want = 0
					v = 0
				}
				got := new(big.Int).Add(crossGridStageTestInteger(peer.out.Share[16*j:16*(j+1)]), crossGridStageTestInteger(b.Share[16*j:16*(j+1)]))
				got.Mod(got, exactGCModulus(128))
				if got.Uint64() != want || peer.out.Validity[j]^b.Validity[j] != v {
					t.Fatalf("candidate %d got %s want %d", j, got, want)
				}
			}
		})
	}
}

func coxLossStagedDurableTest(t *testing.T, p coxLossSharedPlan, shares [2][]Uint128, controls, ends []bool, want []uint64) {
	t.Helper()
	s := coxLossStagedSpec{Plan: p, Prefix: "cox.test", SourceDigest: sha256.Sum256([]byte("synthetic source")), Contract: sha256.Sum256([]byte("synthetic signed contract"))}
	n, j := p.PaddedRows, p.Spec.Candidates
	var sources [2][2]crossGridStageOutput
	for i, width := range []int{n * j, 2 * n} {
		s.Sources[i] = crossGridStagePlan{ID: fmt.Sprintf("source.%d", i), Kind: "test.source", Ring: 128, FPScale: []int{100, 0}[i], CoordOrder: make([]string, width), PublicBounds: map[string]int{"rows": n}, SourceDigest: s.SourceDigest, ProfileDigest: s.Contract}
		for c := range s.Sources[i].CoordOrder {
			s.Sources[i].CoordOrder[c] = fmt.Sprintf("field.%d/%d", i, c)
		}
		for role := range sources {
			sources[role][i] = crossGridStageOutput{Share: make([]byte, 16*width), Validity: make([]byte, width)}
		}
	}
	for role := range sources {
		for row := 0; row < n; row++ {
			for c := 0; c < j+2; c++ {
				field, index := 0, row*j+c
				if c >= j {
					field, index = 1, 2*row+c-j
				}
				word := shares[role][row*(j+2)+c]
				copy(sources[role][field].Share[16*index:16*(index+1)], coxLossStagedWordBytes(word.ToBig()))
				sources[role][field].Validity[index] = byte(1 - role)
			}
		}
	}
	key := sha256.Sum256([]byte("owner local private routing key"))
	side, err := coxLossSealStagedRouting(s, controls, ends, key)
	if err != nil {
		t.Fatal(err)
	}
	s.RoutingDigest = side.MAC
	ga, err := coxLossBuildStagedGraph(s, exactGCRoleGarbler, side, key)
	if err != nil {
		t.Fatal(err)
	}
	gb, err := coxLossBuildStagedGraph(s, exactGCRoleEvaluator, nil, [32]byte{})
	if err != nil || !reflect.DeepEqual(ga.Plans, gb.Plans) {
		t.Fatal("public plans differ", err)
	}
	tampered := *side
	tampered.Ends = append([]bool(nil), side.Ends...)
	tampered.Ends[0] = !tampered.Ends[0]
	if _, err := coxLossBuildStagedGraph(s, exactGCRoleGarbler, &tampered, key); err == nil {
		t.Fatal("private tie sidecar tamper admitted")
	}
	base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1})
	sourceSpec := coxLossSourceSpec{Session: "cox-durable-test", Authorities: [2]string{base.GarblerID, base.EvaluatorID}, SchemaDigest: s.Contract, SemanticKey: s.Contract, Cox: s}
	keys := [2][32]byte{key, crossGridStageTestKey(exactGCRoleEvaluator)}
	var authenticated [2]*coxLossSourceGraph
	for role := range authenticated {
		record, err := coxLossSealSource(sourceSpec, exactGCRole(role), sources[role][0], sources[role][1], keys[role])
		if err != nil {
			t.Fatal(err)
		}
		privateSide := side
		if role == 1 {
			privateSide = nil
		}
		authenticated[role], err = coxLossBuildSourceGraph(sourceSpec, exactGCRole(role), record, privateSide, keys[role])
		if err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(authenticated[0].Graph, authenticated[1].Graph) {
		t.Fatal("authenticated source plans disagree")
	}
	plan := authenticated[0].Graph
	kernels := [2][]crossGridStageCompute{authenticated[0].Compute, authenticated[1].Compute}
	dirs := [2]string{filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")}
	var previous []byte
	for _, scenario := range []string{"bilateral-abort", "unilateral-commit", "fresh", "cold"} {
		var stores [2]*crossGridStageStore
		for role := range stores {
			stores[role], err = crossGridStageOpenStore(dirs[role], crossGridStageTestKey(exactGCRole(role)), plan, exactGCRole(role))
			if err != nil {
				t.Fatal(err)
			}
		}
		left, right := net.Pipe()
		left.SetDeadline(time.Now().Add(time.Minute))
		right.SetDeadline(time.Now().Add(time.Minute))
		type result struct {
			out []crossGridStageOutput
			err error
		}
		ch := make(chan result, 1)
		run := func(role int, rw io.ReadWriter) result {
			k := kernels[role]
			if scenario == "cold" {
				k = make([]crossGridStageCompute, len(k))
				for i := range k {
					k[i] = func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
						return crossGridStageOutput{}, errors.New("cold recomputed")
					}
				}
			}
			e := crossGridStageExecutor{Store: stores[role], Base: base}
			if role == 0 {
				e.fault = func(event string, r crossGridStageRecord) error {
					if r.StageID == s.Prefix+".bridged" && ((scenario == "bilateral-abort" && event == "after-compute") || (scenario == "unilateral-commit" && event == "after-commit")) {
						return errors.New("synthetic death")
					}
					return nil
				}
			}
			out, err := e.Execute(rw, k)
			return result{out, err}
		}
		go func() {
			v := run(0, left)
			if v.err != nil {
				left.Close()
			}
			ch <- v
		}()
		b := run(1, right)
		if b.err != nil {
			right.Close()
		}
		a := <-ch
		left.Close()
		right.Close()
		for _, store := range stores {
			store.Close()
		}
		if scenario == "bilateral-abort" || scenario == "unilateral-commit" {
			if a.err == nil || b.err == nil {
				t.Fatal("fault did not stop both peers")
			}
			continue
		}
		if a.err != nil || b.err != nil {
			t.Fatalf("durable Cox %v / %v", a.err, b.err)
		}
		av, bv := a.out[len(a.out)-1], b.out[len(b.out)-1]
		var encoded []byte
		for c, w := range want {
			v := new(big.Int).Add(crossGridStageTestInteger(av.Share[16*c:16*(c+1)]), crossGridStageTestInteger(bv.Share[16*c:16*(c+1)]))
			v.Mod(v, exactGCModulus(128))
			if v.Uint64() != w || av.Validity[c]^bv.Validity[c] != 1 {
				t.Fatal("durable Cox oracle mismatch")
			}
			encoded = append(encoded, coxLossStagedWordBytes(v)...)
		}
		if scenario == "cold" && !bytes.Equal(previous, encoded) {
			t.Fatal("cold changed bytes")
		}
		previous = encoded
	}
}
