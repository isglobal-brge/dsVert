package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestJointDPVectorStagedValidityBoundAndCanonical(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "2", 2)
	input := jointDPVectorTestContractInput(t, plan, []string{"100", "200"}, [32]byte{1}, [32]byte{2})
	legacy, err := jointDPCompileVectorWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	input.SourceStagePlanDigest = strings.Repeat("a", 64)
	staged, err := jointDPCompileVectorWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Purpose == legacy.Purpose {
		t.Fatal("source validity was not bound to circuit")
	}
	session := exactGCSession{Purpose: staged.Purpose, Spec: exactGCCircuitSpec{VectorLen: 2}}
	spec, err := jointDPVectorSpecFromPolicy(staged.WorkerPolicy, session)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{"", "AA==\n", "BA==", "AAAA"} {
		if _, err := spec.decodeSourceValidity(encoded); err == nil {
			t.Fatalf("accepted invalid bitmap %q", encoded)
		}
	}
	bits, err := spec.decodeSourceValidity("Ag==")
	if err != nil || !reflect.DeepEqual(bits, []bool{false, true}) {
		t.Fatal("wrong bit order", bits, err)
	}
	policy := staged.WorkerPolicy
	policy.SourceStagePlanDigest = strings.Repeat("b", 64)
	if _, err := jointDPVectorSpecFromPolicy(policy, session); err == nil {
		t.Fatal("swapped stage plan accepted")
	}
	for _, digest := range []string{strings.Repeat("0", 64), strings.Repeat("A", 64), "a"} {
		input.SourceStagePlanDigest = digest
		if _, err := jointDPCompileVectorWorkerContract(input); err == nil {
			t.Fatal("invalid stage digest accepted")
		}
	}
	spec.SourceStagePlanDigest = ""
	if _, err := spec.decodeSourceValidity("AA=="); err == nil {
		t.Fatal("legacy sampler accepted stray validity")
	}
}

func TestJointDPVectorStagedValidityPrivateGateAndStickyWorkers(t *testing.T) {
	plan := jointDPVectorTestPlan(t, "1", "7.888609052210118e-31", "2", 2)
	gseed, eseed := sha256.Sum256([]byte("staged-validity-g")), sha256.Sum256([]byte("staged-validity-e"))
	input := jointDPVectorTestContractInput(t, plan, []string{"100", "200"}, gseed, eseed)
	input.SourceStagePlanDigest = strings.Repeat("a", 64)
	compiled, err := jointDPCompileVectorWorkerContract(input)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := jointDPVectorSpecFromPolicy(compiled.WorkerPolicy,
		exactGCSession{Purpose: compiled.Purpose, Spec: exactGCCircuitSpec{VectorLen: 2}})
	if err != nil {
		t.Fatal(err)
	}
	noise, err := jointDPVectorReferenceNoise(spec, gseed, eseed)
	if err != nil {
		t.Fatal(err)
	}
	var first [2]string
	for attempt := 0; attempt < 3; attempt++ {
		left := []*big.Int{big.NewInt(int64(1000 + attempt)), big.NewInt(int64(2000 + attempt))}
		right := []*big.Int{new(big.Int).Mod(new(big.Int).Sub(big.NewInt(37), left[0]), exactGCModulus(128)),
			new(big.Int).Mod(new(big.Int).Sub(big.NewInt(121), left[1]), exactGCModulus(128))}
		validity := [2][]bool{{false, true}, {true, false}}
		if attempt == 1 {
			validity = [2][]bool{{true, false}, {false, true}}
		}
		if attempt == 2 {
			validity[1][1] = true
		}
		g, e, _, _ := jointDPVectorTestRunDurableWorkers(t, compiled, gseed, eseed, left, right,
			[]string{"first", "fresh-transport-reshared", "invalid"}[attempt], validity)
		gb, _ := base64.StdEncoding.DecodeString(g.ValidityShare)
		eb, _ := base64.StdEncoding.DecodeString(e.ValidityShare)
		wantValid := byte(1)
		if attempt == 2 {
			wantValid = 0
		}
		if len(gb) != 1 || len(eb) != 1 || gb[0]^eb[0] != wantValid {
			t.Fatal("candidate invalidity did not gate final validity")
		}
		gr, _ := base64.StdEncoding.DecodeString(g.Share)
		er, _ := base64.StdEncoding.DecodeString(e.Share)
		for i, raw := range []int64{37, 121} {
			decode := func(b []byte) *big.Int {
				b = append([]byte(nil), b...)
				for l, r := 0, len(b)-1; l < r; l, r = l+1, r-1 {
					b[l], b[r] = b[r], b[l]
				}
				return new(big.Int).SetBytes(b)
			}
			got := exactGCReferenceReconstruct(decode(gr[i*16:(i+1)*16]), decode(er[i*16:(i+1)*16]), 128)
			want := new(big.Int).Add(big.NewInt(raw), noise[i])
			if want.Sign() < 0 {
				want.SetInt64(0)
			}
			if want.Cmp(spec.RawUpperBounds[i]) > 0 {
				want.Set(spec.RawUpperBounds[i])
			}
			if attempt == 2 {
				want.SetInt64(0)
			}
			if got.Cmp(want) != 0 {
				t.Fatalf("attempt %d coordinate %d got %s want %s", attempt, i, got, want)
			}
		}
		if attempt == 0 {
			first = [2]string{g.Share, e.Share}
		}
		if attempt == 1 && first != [2]string{g.Share, e.Share} {
			t.Fatal("resharing/retry redrew sticky output")
		}
	}
	// Repeating a plan and seeds is independent of any transport/stage receipt.
	a, _ := jointDPVectorPrivateStream(gseed, spec, "garbler")
	b, _ := jointDPVectorPrivateStream(gseed, spec, "garbler")
	if !bytes.Equal(a, b) {
		t.Fatal("semantic stream changed")
	}
}
