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

func crossGridStageConversionTestShares(values []*big.Int) [2]crossGridStageOutput {
	var result [2]crossGridStageOutput
	for i, value := range values {
		split := new(big.Int).Sub(exactGCModulus(128), big.NewInt(int64(2+i)))
		result[0].Share = append(result[0].Share, crossGridStageTestBytes(split)...)
		result[1].Share = append(result[1].Share, crossGridStageTestBytes(new(big.Int).Sub(value, split))...)
		flag := byte(i & 1)
		result[0].Validity = append(result[0].Validity, flag)
		// Include a private invalid coordinate without changing its value.
		valid := byte(1)
		if i%7 == 6 {
			valid = 0
		}
		result[1].Validity = append(result[1].Validity, flag^valid)
	}
	return result
}

func crossGridStageConversionTestCheck(t *testing.T, values []*big.Int, signed bool, inputs, outputs [2]crossGridStageOutput) {
	t.Helper()
	for i, value := range values {
		got := groupedDecodeWord(outputs[0].Share[24*i:]).add(groupedDecodeWord(outputs[1].Share[24*i:]))
		want := new(big.Int).Mod(new(big.Int).Set(value), exactGCModulus(128))
		if signed && want.Bit(127) == 1 {
			want.Sub(want, exactGCModulus(128))
		}
		if got != groupedWordFromBig(want) {
			t.Fatalf("coordinate=%d signed=%v got=%s want=%s", i, signed, groupedWordInteger(got), want)
		}
		if outputs[0].Validity[i]^outputs[1].Validity[i] != inputs[0].Validity[i]^inputs[1].Validity[i] {
			t.Fatalf("coordinate=%d private source validity changed", i)
		}
	}
}

// This exercises the real checked-OT/GC boundary, including the exact reviewer
// counterexample x=1,r=M-1 and both signed endpoints. Test-only fixture setup
// knows both inputs; neither authority's production function receives them.
func TestCrossGridStageConversionTwoAuthorityPrivateCarry(t *testing.T) {
	m, half := exactGCModulus(128), exactGCModulus(127)
	values := []*big.Int{big.NewInt(1), big.NewInt(0), big.NewInt(-1),
		new(big.Int).Sub(half, big.NewInt(1)), new(big.Int).Neg(half),
		new(big.Int).Lsh(big.NewInt(7), 100), new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(7), 100))}
	masks := []*big.Int{new(big.Int).Sub(m, big.NewInt(1)), new(big.Int), big.NewInt(1), new(big.Int).Set(half), new(big.Int).Sub(half, big.NewInt(1))}
	var xs, rs []*big.Int
	for _, mask := range masks {
		for _, value := range values {
			xs, rs = append(xs, value), append(rs, mask)
		}
	}
	for _, signed := range []bool{true, false} {
		t.Run(fmt.Sprintf("signed=%v", signed), func(t *testing.T) {
			inputs := crossGridStageConversionTestShares(xs)
			var outputs [2]crossGridStageOutput
			for start := 0; start < len(xs); start += crossGridStageConversionBatch {
				count := min(crossGridStageConversionBatch, len(xs)-start)
				programs, err := crossGridStageConversionCompile(count, signed)
				if err != nil {
					t.Fatal(err)
				}
				var localMasks [2][]groupedWord
				for i := 0; i < count; i++ {
					a := new(big.Int).Sub(m, big.NewInt(int64(3+i)))
					b := new(big.Int).Mod(new(big.Int).Sub(rs[start+i], a), m)
					localMasks[0] = append(localMasks[0], groupedWordFromBig(a))
					localMasks[1] = append(localMasks[1], groupedWordFromBig(b))
				}
				left, right := net.Pipe()
				left.SetDeadline(time.Now().Add(2 * time.Minute))
				right.SetDeadline(time.Now().Add(2 * time.Minute))
				base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
				attempt := crossGridStageAttempt{Session: base, Nonce: sha256.Sum256([]byte(fmt.Sprintf("attempt/%d/%v", start, signed))), OutputMaskDomainTag: sha256.Sum256([]byte("conversion masks"))}
				contract := sha256.Sum256([]byte(fmt.Sprintf("conversion private-boundary test/%v", signed)))
				type result struct {
					out crossGridStageOutput
					err error
				}
				ch := make(chan result, 1)
				run := func(role exactGCRole, rw io.ReadWriter) result {
					input := crossGridStageOutput{Share: inputs[role].Share[16*start : 16*(start+count)], Validity: inputs[role].Validity[start : start+count]}
					out, err := crossGridStageConversionChunk(rw, attempt, role, contract, "test", programs, input, localMasks[role])
					return result{out, err}
				}
				go func() { r := run(0, left); left.Close(); ch <- r }()
				b := run(1, right)
				right.Close()
				a := <-ch
				if a.err != nil || b.err != nil {
					t.Fatalf("private conversion: %v / %v", a.err, b.err)
				}
				for role, r := range []result{a, b} {
					outputs[role].Share = append(outputs[role].Share, r.out.Share...)
					outputs[role].Validity = append(outputs[role].Validity, r.out.Validity...)
				}
			}
			crossGridStageConversionTestCheck(t, xs, signed, inputs, outputs)
		})
	}
}

func TestCrossGridStageConversionDurableBoundary(t *testing.T) {
	values := []*big.Int{big.NewInt(1), big.NewInt(-1), new(big.Int).Neg(exactGCModulus(127))}
	inputs := crossGridStageConversionTestShares(values)
	for _, scenario := range []string{"fresh", "bilateral-abort", "unilateral-commit"} {
		t.Run(scenario, func(t *testing.T) {
			graph := crossGridStageTestGraph()
			graph.Stages = graph.Stages[:1]
			source := &graph.Stages[0]
			source.FPScale = 50
			source.CoordOrder = []string{"value:0", "value:1", "value:2"}
			var kernels [2][]crossGridStageCompute
			for role := range kernels {
				plan, convert, err := crossGridStageBuildConversion(*source, "convert192", true, exactGCRole(role))
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
			conversion := graph.Stages[1]
			if conversion.FPScale != 50 || conversion.Ring != 192 || conversion.ProfileDigest == source.ProfileDigest {
				t.Fatal("conversion ABI/profile not bound")
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
							if record.StageID == conversion.ID && ((scenario == "bilateral-abort" && role == 0 && event == "after-compute") ||
								(scenario == "unilateral-commit" && role == 1 && event == "after-prepare-exchange")) {
								return errors.New("synthetic conversion interruption")
							}
							return nil
						}
					}
					ks := kernels[role]
					if cold {
						fail := func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
							return crossGridStageOutput{}, errors.New("cold replay recomputed conversion")
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
						records[role], err = store.load(conversion, [][32]byte{src.StageReceipt})
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
					t.Fatal("conversion interruption was ignored")
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
			crossGridStageConversionTestCheck(t, values, true, inputs, outputs)
			committed := read()
			if committed[0].StageReceipt == ([32]byte{}) || committed[0].StageReceipt != committed[1].StageReceipt {
				t.Fatal("conversion missing its own bilateral receipt")
			}
			for role, record := range committed {
				if record.State != "COMMIT" || len(record.ShareMAC) != sha256.Size {
					t.Fatal("conversion output not durably authenticated")
				}
				if scenario == "bilateral-abort" && record.AttemptNonce == interrupted[role].AttemptNonce {
					t.Fatal("conversion reused an aborted mask/OT attempt")
				}
				if scenario == "unilateral-commit" && (record.AttemptNonce != interrupted[role].AttemptNonce || !bytes.Equal(record.Output.Share, interrupted[role].Output.Share)) {
					t.Fatal("conversion regenerated a prepared share")
				}
				changed := record
				changed.Output = crossGridStageClone(record.Output)
				changed.Output.Share[0] ^= 1
				if bytes.Equal(record.ShareMAC, crossGridStageShareMAC(crossGridStageTestKey(exactGCRole(role)), changed)) {
					t.Fatal("conversion share tamper did not change MAC")
				}
			}
			cold := run(false, true)
			for role := range cold {
				if cold[role].err != nil || !bytes.Equal(cold[role].out[1].Share, outputs[role].Share) || !bytes.Equal(cold[role].out[1].Validity, outputs[role].Validity) {
					t.Fatal("cold replay changed conversion bytes or recomputed")
				}
			}
		})
	}
}
