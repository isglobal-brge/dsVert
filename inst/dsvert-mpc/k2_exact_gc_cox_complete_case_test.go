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
	"testing"
	"time"
)

func TestCoxCompleteCasePrivateGuards(t *testing.T) {
	for _, scenario := range []string{"complete", "missing", "presence-alias", "negative-presence", "event-alias", "invalid-source"} {
		t.Run(scenario, func(t *testing.T) {
			values := make([]*big.Int, 16)
			for i := range values {
				values[i] = big.NewInt(1)
			}
			switch scenario {
			case "missing":
				values[1] = big.NewInt(0)
			case "presence-alias":
				values[1] = new(big.Int).Add(exactGCModulus(64), big.NewInt(1))
			case "negative-presence":
				values[1] = big.NewInt(-1)
			case "event-alias":
				values[3] = new(big.Int).Add(exactGCModulus(64), big.NewInt(1))
			}
			shares := crossGridStageConversionTestShares(values)
			for i := range shares[0].Validity {
				shares[1].Validity[i] = shares[0].Validity[i] ^ 1
			}
			if scenario == "invalid-source" {
				shares[1].Validity[1] ^= 1
			}
			source := crossGridStageTestGraph().Stages[0]
			source.FPScale = 0
			source.CoordOrder = make([]string, len(values))
			for i := range values {
				source.CoordOrder[i] = fmt.Sprint(i)
			}
			var compute [2]crossGridStageCompute
			for role := range compute {
				_, c, err := coxLossCompleteCaseStage(source, 3, 4, 3, exactGCRole(role))
				if err != nil {
					t.Fatal(err)
				}
				compute[role] = c
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(time.Minute))
			right.SetDeadline(time.Now().Add(time.Minute))
			a := crossGridStageAttempt{Session: exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1})}
			type result struct {
				value crossGridStageOutput
				err   error
			}
			ch := make(chan result, 1)
			go func() {
				v, err := compute[0](left, a, []crossGridStageOutput{shares[0]})
				left.Close()
				ch <- result{v, err}
			}()
			v, err := compute[1](right, a, []crossGridStageOutput{shares[1]})
			other := <-ch
			if err != nil || other.err != nil {
				t.Fatalf("%v / %v", err, other.err)
			}
			valid := byte(0)
			if scenario == "complete" || scenario == "missing" {
				valid = 1
			}
			for i := range v.Validity {
				if v.Validity[i]^other.value.Validity[i] != valid {
					t.Fatal("invalid source accepted or missingness treated as arithmetic failure")
				}
				if valid == 1 {
					want := int64(1)
					if i >= 6 || (scenario == "missing" && i < 2) {
						want = 0
					}
					got := getUint128LE(v.Share[16*i : 16*(i+1)]).Add(getUint128LE(other.value.Share[16*i : 16*(i+1)]))
					if got.ToBig().Cmp(big.NewInt(want)) != 0 {
						t.Fatalf("lane %d: %s != %d", i, got.ToBig(), want)
					}
				}
			}
		})
	}
}

func TestCoxCompleteCaseDurableBoundary(t *testing.T) {
	const rows, capacity, presence = 64, 35, 4
	values := make([]*big.Int, rows*(presence+1))
	want := make([]int64, 2*rows)
	for row := 0; row < rows; row++ {
		live := row < capacity && row%5 != 2
		for c := 0; c < presence; c++ {
			v := int64(1)
			if row%5 == 2 && c == row%presence {
				v = 0
			}
			values[row*(presence+1)+c] = big.NewInt(v)
		}
		values[row*(presence+1)+presence] = big.NewInt(int64(row % 2))
		if live {
			want[2*row], want[2*row+1] = 1, int64(row%2)
		}
	}
	inputs := crossGridStageConversionTestShares(values)
	for i := range inputs[0].Validity {
		inputs[1].Validity[i] = inputs[0].Validity[i] ^ 1
	}
	for _, scenario := range []string{"fresh", "bilateral-abort", "unilateral-commit"} {
		t.Run(scenario, func(t *testing.T) {
			graph := crossGridStageTestGraph()
			graph.Stages = graph.Stages[:1]
			source := &graph.Stages[0]
			source.FPScale = 0
			source.CoordOrder = make([]string, len(values))
			for i := range values {
				source.CoordOrder[i] = fmt.Sprintf("presence-event/%d", i)
			}
			var kernels [2][]crossGridStageCompute
			for role := range kernels {
				plan, convert, err := coxLossCompleteCaseStage(*source, capacity, rows, presence, exactGCRole(role))
				if err != nil {
					t.Fatal(err)
				}
				if role == 0 {
					graph.Stages = append(graph.Stages, plan)
				}
				role := role
				kernels[role] = []crossGridStageCompute{func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
					return inputs[role], nil
				}, convert}
			}
			composition := graph.Stages[1]
			if composition.FPScale != 0 || composition.Ring != 128 || composition.ProfileDigest == source.ProfileDigest {
				t.Fatal("composition ABI/profile not bound")
			}
			dirs := [2]string{filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "authority")}
			type result struct {
				out []crossGridStageOutput
				err error
			}
			run := func(interrupt, cold bool) [2]result {
				var stores [2]*crossGridStageStore
				for role := range stores {
					var err error
					stores[role], err = crossGridStageOpenStore(dirs[role], crossGridStageTestKey(exactGCRole(role)), graph, exactGCRole(role))
					if err != nil {
						t.Fatal(err)
					}
					defer stores[role].Close()
				}
				base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
				base.GarblerID, base.EvaluatorID = graph.Authorities[0], graph.Authorities[1]
				left, right := net.Pipe()
				left.SetDeadline(time.Now().Add(2 * time.Minute))
				right.SetDeadline(time.Now().Add(2 * time.Minute))
				execute := func(role int, conn net.Conn) result {
					defer conn.Close()
					executor := &crossGridStageExecutor{Store: stores[role], Base: base}
					if interrupt {
						executor.fault = func(event string, record crossGridStageRecord) error {
							if record.StageID == composition.ID && ((scenario == "bilateral-abort" && role == 0 && event == "after-compute") ||
								(scenario == "unilateral-commit" && role == 1 && event == "after-prepare-exchange")) {
								return errors.New("synthetic composition interruption")
							}
							return nil
						}
					}
					ks := kernels[role]
					if cold {
						fail := func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
							return crossGridStageOutput{}, errors.New("cold replay recomputed composition")
						}
						ks = []crossGridStageCompute{fail, fail}
					}
					out, err := executor.Execute(conn, ks)
					return result{out, err}
				}
				ch := make(chan result, 1)
				go func() { ch <- execute(0, left) }()
				b := execute(1, right)
				return [2]result{<-ch, b}
			}
			read := func() [2]crossGridStageRecord {
				var records [2]crossGridStageRecord
				for role := range records {
					store, err := crossGridStageOpenStore(dirs[role], crossGridStageTestKey(exactGCRole(role)), graph, exactGCRole(role))
					if err != nil {
						t.Fatal(err)
					}
					src, err := store.load(graph.Stages[0], nil)
					if err == nil {
						records[role], err = store.load(composition, [][32]byte{src.StageReceipt})
					}
					store.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				return records
			}
			var interrupted [2]crossGridStageRecord
			if scenario != "fresh" {
				r := run(true, false)
				if r[0].err == nil || r[1].err == nil {
					t.Fatal("composition interruption was ignored")
				}
				interrupted = read()
				if scenario == "unilateral-commit" && (interrupted[0].State != "COMMIT" || interrupted[1].State != "PREPARE") {
					t.Fatal("fault failed to create unilateral commit")
				}
			}
			first := run(false, false)
			var outputs [2]crossGridStageOutput
			for role := range first {
				if first[role].err != nil {
					t.Fatal(first[role].err)
				}
				outputs[role] = first[role].out[1]
			}
			for i, expected := range want {
				got := getUint128LE(outputs[0].Share[16*i : 16*(i+1)]).Add(getUint128LE(outputs[1].Share[16*i : 16*(i+1)]))
				if got.ToBig().Cmp(big.NewInt(expected)) != 0 || outputs[0].Validity[i]^outputs[1].Validity[i] != 1 {
					t.Fatalf("coordinate %d: got %s expected %d", i, got.ToBig(), expected)
				}
			}
			committed := read()
			if committed[0].StageReceipt == ([32]byte{}) || committed[0].StageReceipt != committed[1].StageReceipt {
				t.Fatal("composition missing its own bilateral receipt")
			}
			for role, record := range committed {
				if record.State != "COMMIT" || len(record.ShareMAC) != sha256.Size {
					t.Fatal("composition output not durably authenticated")
				}
				if scenario == "bilateral-abort" && record.AttemptNonce == interrupted[role].AttemptNonce {
					t.Fatal("composition reused an aborted mask/OT attempt")
				}
				if scenario == "unilateral-commit" && (record.AttemptNonce != interrupted[role].AttemptNonce || !bytes.Equal(record.Output.Share, interrupted[role].Output.Share)) {
					t.Fatal("composition regenerated a prepared share")
				}
				changed := record
				changed.Output = crossGridStageClone(record.Output)
				changed.Output.Share[0] ^= 1
				if bytes.Equal(record.ShareMAC, crossGridStageShareMAC(crossGridStageTestKey(exactGCRole(role)), changed)) {
					t.Fatal("composition share tamper did not change MAC")
				}
			}
			cold := run(false, true)
			for role := range cold {
				if cold[role].err != nil || !bytes.Equal(cold[role].out[1].Share, outputs[role].Share) || !bytes.Equal(cold[role].out[1].Validity, outputs[role].Validity) {
					t.Fatal("cold replay changed composition bytes or recomputed")
				}
			}
		})
	}
}
