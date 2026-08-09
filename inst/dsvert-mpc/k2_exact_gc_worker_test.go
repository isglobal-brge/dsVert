package main

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExactGCDeriveMasterIsSymmetricAndContextBound(t *testing.T) {
	curve := ecdh.X25519()
	a, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sid := sha256.Sum256([]byte("derive-master-session"))
	base := exactGCDeriveMasterInput{
		SessionID:   hex.EncodeToString(sid[:]),
		GarblerID:   "dsv1_" + strings.Repeat("1", 64),
		EvaluatorID: "dsv1_" + strings.Repeat("2", 64),
		Purpose:     "test/exact-truncate",
		Operation:   string(exactGCTruncateFloor), RingBits: 127, FracBits: 37,
		VectorLen: 3,
	}
	left := base
	left.LocalSecret = base64.StdEncoding.EncodeToString(a.Bytes())
	left.LocalPublic = base64.StdEncoding.EncodeToString(a.PublicKey().Bytes())
	left.PeerPublic = base64.StdEncoding.EncodeToString(b.PublicKey().Bytes())
	right := base
	right.LocalSecret = base64.StdEncoding.EncodeToString(b.Bytes())
	right.LocalPublic = base64.StdEncoding.EncodeToString(b.PublicKey().Bytes())
	right.PeerPublic = base64.StdEncoding.EncodeToString(a.PublicKey().Bytes())

	l, err := exactGCDeriveMaster(left)
	if err != nil {
		t.Fatal(err)
	}
	r, err := exactGCDeriveMaster(right)
	if err != nil {
		t.Fatal(err)
	}
	if l != r {
		t.Fatalf("peer key agreement differs: %#v != %#v", l, r)
	}
	changed := right
	changed.Purpose = "test/different-purpose"
	c, err := exactGCDeriveMaster(changed)
	if err != nil {
		t.Fatal(err)
	}
	if c.MasterKey == l.MasterKey || c.ContextHash == l.ContextHash {
		t.Fatal("purpose change did not domain-separate key and context")
	}

	mismatch := left
	mismatch.LocalPublic = left.PeerPublic
	if _, err := exactGCDeriveMaster(mismatch); err == nil {
		t.Fatal("local secret/public mismatch was accepted")
	}
}

func TestExactGCWorkerConfigIsOneLinkAndRemovedBeforeUse(t *testing.T) {
	dir := exactGCTestSpool(t, "config-policy")
	config := exactGCWorkerConfig{
		Version: exactGCWorkerConfigVersion, Role: "garbler",
		SessionID: strings.Repeat("a", 64), MasterKey: base64.StdEncoding.EncodeToString(
			bytes.Repeat([]byte{1}, 32)),
		GarblerID:   "dsv1_" + strings.Repeat("a", 64),
		EvaluatorID: "dsv1_" + strings.Repeat("b", 64),
		Purpose:     "worker-config-test", Operation: string(exactGCTruncateFloor),
		RingBits: 63, FracBits: 20, VectorLen: 1,
		SourceShare: base64.StdEncoding.EncodeToString(make([]byte, 8)),
		SpoolDir:    dir, MaxSpoolBytes: 64 << 20, TTLSeconds: 30,
	}
	path := exactGCTestWriteConfig(t, dir, config)
	if runtime.GOOS != "windows" {
		alias := filepath.Join(dir, "config-hardlink.json")
		if err := os.Link(path, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := exactGCReadWorkerConfig(path); err == nil {
			t.Fatal("worker accepted a hard-linked sensitive config")
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := exactGCReadWorkerConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := exactGCRemoveSensitiveConfig(path); err != nil {
		t.Fatal(err)
	}
	if fileExists(path) {
		t.Fatal("sensitive worker config survived removal")
	}
	if err := exactGCRemoveSensitiveConfig(path); err == nil {
		t.Fatal("missing sensitive config did not fail closed")
	}
}

func TestExactGCWorkerFailureIsTypedAndCannotLeaveSuccessArtifacts(t *testing.T) {
	dir := exactGCTestSpool(t, "typed-failure")
	sid := sha256.Sum256([]byte("typed-worker-failure-session"))
	master := sha256.Sum256([]byte("typed-worker-failure-master"))
	config := exactGCWorkerConfig{
		Version: exactGCWorkerConfigVersion, Role: "invalid-role",
		SessionID:   hex.EncodeToString(sid[:]),
		MasterKey:   base64.StdEncoding.EncodeToString(master[:]),
		GarblerID:   "dsv1_" + strings.Repeat("a", 64),
		EvaluatorID: "dsv1_" + strings.Repeat("b", 64),
		Purpose:     "worker-typed-failure",
		Operation:   string(exactGCTruncateFloor),
		RingBits:    127, FracBits: 50, VectorLen: 1,
		SourceShare:   base64.StdEncoding.EncodeToString(make([]byte, 16)),
		SpoolDir:      dir,
		MaxSpoolBytes: 64 << 20, TTLSeconds: 30,
	}
	path := exactGCTestWriteConfig(t, dir, config)
	if err := handleExactGCWorker(path); err == nil {
		t.Fatal("worker accepted an invalid role")
	}
	if fileExists(path) {
		t.Fatal("failed worker retained its sensitive config")
	}
	for _, name := range []string{"ready", "result.json", "done"} {
		if fileExists(filepath.Join(dir, name)) {
			t.Fatalf("failed worker retained success artifact %s", name)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "failure.json"))
	if err != nil {
		t.Fatal(err)
	}
	var failure exactGCWorkerFailure
	if err := json.Unmarshal(data, &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Version != exactGCWorkerFailureVersion ||
		failure.Code != exactGCFailureInfrastructureUnavailable ||
		!failure.Retryable || failure.RetryContract != exactGCRetryContractVersion ||
		failure.Operation != string(exactGCTruncateFloor) || failure.RingBits != 127 ||
		len(failure.ContextHash) != 64 {
		t.Fatalf("invalid typed failure: %#v", failure)
	}
	if bytes.Contains(data, []byte("invalid-role")) ||
		bytes.Contains(data, []byte("worker role")) {
		t.Fatal("public failure marker exposed a private diagnostic")
	}
	if !fileExists(filepath.Join(dir, "error")) {
		t.Fatal("failed worker did not publish its terminal error marker")
	}

	for _, tc := range []struct {
		code      exactGCFailureCode
		retryable bool
	}{
		{exactGCFailureInfrastructureUnavailable, true},
		{exactGCFailureNumericBackendUnavailable, true},
		{exactGCFailureBoundExceeded, false},
		{exactGCFailureNonIdentifiable, false},
	} {
		record := exactGCWorkerFailureRecord(config, nil,
			exactGCFailure(tc.code, fmt.Errorf("private detail")))
		if record.Code != tc.code || record.Retryable != tc.retryable ||
			record.ContextHash != "" {
			t.Fatalf("wrong failure classification: %#v", record)
		}
	}
}

func TestExactGCWorkerRejectsStaleTranscriptOrTerminalState(t *testing.T) {
	for _, name := range []string{"inbound.bin", "outbound.bin", "result.json", "done"} {
		t.Run(name, func(t *testing.T) {
			dir := exactGCTestSpool(t, "stale-state")
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := exactGCPrepareWorkerSpool(dir); err == nil {
				t.Fatalf("worker accepted stale %s", name)
			}
		})
	}
}

func TestExactGCWorkersOverSegmentedSpools(t *testing.T) {
	tests := []struct {
		name string
		spec exactGCCircuitSpec
		x    []*big.Int
	}{
		{
			name: "Ring127 truncate",
			spec: exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 127,
				FracBits: 23, VectorLen: 4},
			x: []*big.Int{exactGCEncodeSigned(big.NewInt(-8388609), 127),
				exactGCEncodeSigned(big.NewInt(-1), 127), big.NewInt(0),
				new(big.Int).Lsh(big.NewInt(1), 90)},
		},
		{
			name: "Ring63 count guard",
			spec: exactGCCircuitSpec{Operation: exactGCCountGuard, RingBits: 63,
				Threshold: big.NewInt(5), VectorLen: 4},
			x: []*big.Int{big.NewInt(0), big.NewInt(5), big.NewInt(8), big.NewInt(100)},
		},
		{
			name: "Ring256 truncate",
			spec: exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 256,
				FracBits: 37, VectorLen: 3},
			x: []*big.Int{exactGCEncodeSigned(big.NewInt(-1), 256),
				exactGCEncodeSigned(new(big.Int).Neg(new(big.Int).Lsh(
					big.NewInt(1), 173)), 256),
				new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 220),
					big.NewInt(17))},
		},
		{
			name: "Ring127 nearest-even truncate",
			spec: exactGCCircuitSpec{Operation: exactGCTruncateNearestEven,
				RingBits: 127, FracBits: 50, VectorLen: 4},
			x: []*big.Int{
				exactGCEncodeSigned(new(big.Int).Lsh(big.NewInt(1), 49), 127),
				exactGCEncodeSigned(new(big.Int).Neg(
					new(big.Int).Lsh(big.NewInt(3), 49)), 127),
				exactGCMaxSigned(127),
				exactGCEncodeSigned(new(big.Int).Neg(
					new(big.Int).Lsh(big.NewInt(1), 126)), 127),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rng := newDeterministicRand(117)
			a, b := exactGCTestSplit(rng, test.x, test.spec.RingBits)
			gResult, eResult := exactGCTestRunWorkers(t, test.spec, a, b)
			if gResult.VectorLen != test.spec.VectorLen ||
				eResult.VectorLen != test.spec.VectorLen {
				t.Fatalf("worker result lost bound input shape: garbler=%d evaluator=%d want=%d",
					gResult.VectorLen, eResult.VectorLen, test.spec.VectorLen)
			}
			if test.spec.Operation == exactGCTruncateFloor ||
				test.spec.Operation == exactGCTruncateNearestEven {
				for _, result := range []exactGCWorkerResult{gResult, eResult} {
					if result.Kind != "ring-share" || result.ValidityShare != "" {
						t.Fatalf("truncate worker exposed a non-share result: %#v", result)
					}
					encoded, err := json.Marshal(result)
					if err != nil {
						t.Fatal(err)
					}
					for _, forbidden := range []string{
						"correction", "low_carry", "ring_wrap", "sign_bit",
					} {
						if bytes.Contains(encoded, []byte(forbidden)) {
							t.Fatalf("truncate result exposed private %q state", forbidden)
						}
					}
				}
				gShares, err := exactGCDecodeWorkerShares(gResult.Share, test.spec)
				if err != nil {
					t.Fatal(err)
				}
				eShares, err := exactGCDecodeWorkerShares(eResult.Share, test.spec)
				if err != nil {
					t.Fatal(err)
				}
				for i := range gShares {
					got := exactGCReferenceReconstruct(gShares[i], eShares[i], test.spec.RingBits)
					want := exactGCReferenceTruncateFloor(a[i], b[i], test.spec.RingBits,
						test.spec.FracBits)
					if test.spec.Operation == exactGCTruncateNearestEven {
						want = exactGCReferenceTruncateNearestEven(
							a[i], b[i], test.spec.RingBits, test.spec.FracBits)
					}
					if got.Cmp(want) != 0 {
						t.Fatalf("worker truncation %d: got %s want %s", i, got, want)
					}
				}
			} else {
				gb, err := unpackBoolsB64(gResult.Share, 1)
				if err != nil {
					t.Fatal(err)
				}
				eb, err := unpackBoolsB64(eResult.Share, 1)
				if err != nil {
					t.Fatal(err)
				}
				got := gb[0] != eb[0]
				want := exactGCReferenceCountGuard(a, b, test.spec.Threshold,
					test.spec.RingBits)
				if got != want {
					t.Fatalf("worker guard: got %v want %v", got, want)
				}
			}
		})
	}
}

func TestExactGCWorkersRing127TruncateN180Benchmark(t *testing.T) {
	if os.Getenv("DSVERT_RUN_EXACT_GC_GO_BENCHMARK") != "true" {
		t.Skip("set DSVERT_RUN_EXACT_GC_GO_BENCHMARK=true for the real n=180 worker benchmark")
	}
	spec := exactGCCircuitSpec{
		Operation: exactGCTruncateFloor,
		RingBits:  127,
		FracBits:  50,
		VectorLen: 180,
	}
	x := make([]*big.Int, spec.VectorLen)
	for i := range x {
		value := new(big.Int).Lsh(big.NewInt(int64(i+1)), uint(20+i%70))
		if i%3 == 0 {
			value.Neg(value)
		}
		x[i] = exactGCEncodeSigned(value, spec.RingBits)
	}
	x[0] = exactGCEncodeSigned(new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 126)), 127)
	x[1] = exactGCMaxSigned(127)
	rng := newDeterministicRand(18050)
	a, b := exactGCTestSplit(rng, x, spec.RingBits)
	started := time.Now()
	gResult, eResult := exactGCTestRunWorkers(t, spec, a, b)
	t.Logf("Ring127 specialized truncate n=180 worker E2E: %s", time.Since(started))
	gShares, err := exactGCDecodeWorkerShares(gResult.Share, spec)
	if err != nil {
		t.Fatal(err)
	}
	eShares, err := exactGCDecodeWorkerShares(eResult.Share, spec)
	if err != nil {
		t.Fatal(err)
	}
	for i := range x {
		got := exactGCReferenceReconstruct(gShares[i], eShares[i], spec.RingBits)
		want := exactGCReferenceTruncateFloor(a[i], b[i], spec.RingBits, spec.FracBits)
		if got.Cmp(want) != 0 {
			t.Fatalf("worker truncation %d: got %s want %s", i, got, want)
		}
	}
}

func TestExactGCWorkersRing127HybridMulN180Benchmark(t *testing.T) {
	if os.Getenv("DSVERT_RUN_EXACT_GC_HYBRID_BENCHMARK") != "true" {
		t.Skip("set DSVERT_RUN_EXACT_GC_HYBRID_BENCHMARK=true for the real n=180 hybrid benchmark")
	}
	spec := exactGCTestMulSpec(127, 50, 180)
	scale := new(big.Int).Lsh(big.NewInt(1), 50)
	x := make([]*big.Int, spec.VectorLen)
	y := make([]*big.Int, spec.VectorLen)
	for i := range x {
		xSigned := new(big.Int).Mul(
			big.NewInt(int64(i%17-8)), scale)
		xSigned.Add(xSigned, big.NewInt(int64(i%11-5)))
		ySigned := new(big.Int).Mul(
			big.NewInt(int64(i%13-6)), scale)
		ySigned.Sub(ySigned, big.NewInt(int64(i%7-3)))
		x[i] = exactGCEncodeSigned(xSigned, spec.RingBits)
		y[i] = exactGCEncodeSigned(ySigned, spec.RingBits)
	}
	rng := newDeterministicRand(18051)
	xa, xb := exactGCTestSplit(rng, x, spec.RingBits)
	ya, yb := exactGCTestSplit(rng, y, spec.RingBits)
	garbler := append(append([]*big.Int{}, xa...), ya...)
	evaluator := append(append([]*big.Int{}, xb...), yb...)
	started := time.Now()
	gResult, eResult := exactGCTestRunWorkers(t, spec, garbler, evaluator)
	t.Logf("Ring127 hybrid checked mul n=180 worker E2E: %s", time.Since(started))
	resultSpec := exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: spec.RingBits,
		FracBits: spec.FracBits, VectorLen: spec.VectorLen,
	}
	gShares, err := exactGCDecodeWorkerShares(gResult.Share, resultSpec)
	if err != nil {
		t.Fatal(err)
	}
	eShares, err := exactGCDecodeWorkerShares(eResult.Share, resultSpec)
	if err != nil {
		t.Fatal(err)
	}
	validG, err := unpackBoolsB64(gResult.ValidityShare, 1)
	if err != nil {
		t.Fatal(err)
	}
	validE, err := unpackBoolsB64(eResult.ValidityShare, 1)
	if err != nil {
		t.Fatal(err)
	}
	if validG[0] == validE[0] {
		t.Fatal("in-bound hybrid benchmark was not marked valid")
	}
	for i := range x {
		got := exactGCReferenceReconstruct(gShares[i], eShares[i], spec.RingBits)
		want, valid := exactGCReferenceMulTruncateChecked(
			xa[i], xb[i], ya[i], yb[i], spec)
		if !valid || got.Cmp(want) != 0 {
			t.Fatalf("hybrid worker result %d: got %s want %s valid=%v",
				i, got, want, valid)
		}
	}
}

func TestExactGCWorkersCheckedMulKeepValidityPeerLocal(t *testing.T) {
	spec := exactGCTestMulSpec(127, 50, 2)
	rng := newDeterministicRand(991)
	x := []*big.Int{
		exactGCEncodeSigned(big.NewInt(-3), 127),
		exactGCEncodeSigned(new(big.Int).Add(spec.BoundX, big.NewInt(1)), 127),
	}
	y := []*big.Int{big.NewInt(1), big.NewInt(2)}
	xa, xb := exactGCTestSplit(rng, x, spec.RingBits)
	ya, yb := exactGCTestSplit(rng, y, spec.RingBits)
	garbler := append(append([]*big.Int{}, xa...), ya...)
	evaluator := append(append([]*big.Int{}, xb...), yb...)
	gResult, eResult := exactGCTestRunWorkers(t, spec, garbler, evaluator)
	for _, result := range []exactGCWorkerResult{gResult, eResult} {
		if result.Kind != "checked-ring-share" || result.ValidityShare == "" {
			t.Fatalf("checked worker result omitted its peer-only validity share: %#v",
				result)
		}
	}
	resultSpec := exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: spec.RingBits,
		FracBits: spec.FracBits, VectorLen: spec.VectorLen,
	}
	gShares, err := exactGCDecodeWorkerShares(gResult.Share, resultSpec)
	if err != nil {
		t.Fatal(err)
	}
	eShares, err := exactGCDecodeWorkerShares(eResult.Share, resultSpec)
	if err != nil {
		t.Fatal(err)
	}
	validG, err := unpackBoolsB64(gResult.ValidityShare, 1)
	if err != nil {
		t.Fatal(err)
	}
	validE, err := unpackBoolsB64(eResult.ValidityShare, 1)
	if err != nil {
		t.Fatal(err)
	}
	if validG[0] != validE[0] {
		// XOR FALSE is the fail-closed aggregate validity for this fixture.
		t.Fatal("out-of-bound checked multiplication was marked valid")
	}
	for i := range gShares {
		got := exactGCReferenceReconstruct(gShares[i], eShares[i], spec.RingBits)
		_, valid := exactGCReferenceMulTruncateChecked(
			xa[i], xb[i], ya[i], yb[i], spec)
		// An invalid aggregate is fail-closed: every arithmetic output is
		// replaced by zero before masking, so no partial valid result can be
		// committed or used after a failed bound proof.
		if got.Sign() != 0 {
			t.Fatalf("checked worker result %d survived an invalid aggregate: %s", i, got)
		}
		if i == 0 && !valid {
			t.Fatal("in-bound worker result was unexpectedly invalid")
		}
		if i == 1 && valid {
			t.Fatal("out-of-bound worker result was unexpectedly valid")
		}
	}
}

func TestExactGCWorkersDirectInvalidAggregateClearsEveryOutput(t *testing.T) {
	spec := exactGCTestMulSpec(63, 1, 2)
	spec.MulBackend = exactGCMulBackendDirect
	rng := newDeterministicRand(20260806)
	x := []*big.Int{
		exactGCEncodeSigned(big.NewInt(-3), spec.RingBits),
		exactGCEncodeSigned(
			new(big.Int).Add(new(big.Int).Set(spec.BoundX), big.NewInt(1)),
			spec.RingBits),
	}
	y := []*big.Int{big.NewInt(1), big.NewInt(1)}
	xa, xb := exactGCTestSplit(rng, x, spec.RingBits)
	ya, yb := exactGCTestSplit(rng, y, spec.RingBits)
	garbler := append(append([]*big.Int{}, xa...), ya...)
	evaluator := append(append([]*big.Int{}, xb...), yb...)
	gResult, eResult := exactGCTestRunWorkers(t, spec, garbler, evaluator)
	resultSpec := exactGCCircuitSpec{
		Operation: exactGCTruncateFloor, RingBits: spec.RingBits,
		FracBits: spec.FracBits, VectorLen: spec.VectorLen,
	}
	gShares, err := exactGCDecodeWorkerShares(gResult.Share, resultSpec)
	if err != nil {
		t.Fatal(err)
	}
	eShares, err := exactGCDecodeWorkerShares(eResult.Share, resultSpec)
	if err != nil {
		t.Fatal(err)
	}
	validG, err := unpackBoolsB64(gResult.ValidityShare, 1)
	if err != nil {
		t.Fatal(err)
	}
	validE, err := unpackBoolsB64(eResult.ValidityShare, 1)
	if err != nil {
		t.Fatal(err)
	}
	if validG[0] != validE[0] {
		t.Fatal("out-of-bound direct multiplication was marked valid")
	}
	for i := range gShares {
		got := exactGCReferenceReconstruct(gShares[i], eShares[i], spec.RingBits)
		if got.Sign() != 0 {
			t.Fatalf("invalid direct aggregate retained output %d: %s", i, got)
		}
	}
}

func TestExactGCWorkersDirectWideProductAcrossRings(t *testing.T) {
	tests := []struct {
		ring  int
		frac  int
		power uint
	}{
		{ring: 63, frac: 20, power: 40},
		{ring: 127, frac: 50, power: 80},
		{ring: 256, frac: 50, power: 140},
		{ring: 512, frac: 50, power: 270},
		{ring: 513, frac: 50, power: 280},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("Ring%d", test.ring), func(t *testing.T) {
			value := new(big.Int).Lsh(big.NewInt(1), test.power)
			spec := exactGCCircuitSpec{
				Operation: exactGCMulTruncateChecked,
				RingBits:  test.ring, FracBits: test.frac, VectorLen: 1,
				MulBackend: exactGCMulBackendDirect,
				BoundX:     new(big.Int).Set(value), BoundY: new(big.Int).Set(value),
			}
			x := []*big.Int{exactGCEncodeSigned(value, test.ring)}
			y := []*big.Int{exactGCEncodeSigned(new(big.Int).Neg(value), test.ring)}
			rng := newDeterministicRand(int64(1200 + test.ring))
			xa, xb := exactGCTestSplit(rng, x, test.ring)
			ya, yb := exactGCTestSplit(rng, y, test.ring)
			garbler := append(append([]*big.Int{}, xa...), ya...)
			evaluator := append(append([]*big.Int{}, xb...), yb...)
			gResult, eResult := exactGCTestRunWorkers(
				t, spec, garbler, evaluator)
			resultSpec := exactGCCircuitSpec{
				Operation: exactGCTruncateFloor, RingBits: test.ring,
				FracBits: test.frac, VectorLen: 1,
			}
			gShares, err := exactGCDecodeWorkerShares(gResult.Share, resultSpec)
			if err != nil {
				t.Fatal(err)
			}
			eShares, err := exactGCDecodeWorkerShares(eResult.Share, resultSpec)
			if err != nil {
				t.Fatal(err)
			}
			validG, err := unpackBoolsB64(gResult.ValidityShare, 1)
			if err != nil {
				t.Fatal(err)
			}
			validE, err := unpackBoolsB64(eResult.ValidityShare, 1)
			if err != nil {
				t.Fatal(err)
			}
			if validG[0] == validE[0] {
				t.Fatal("wide-product execution was not marked valid")
			}
			got := exactGCReferenceReconstruct(gShares[0], eShares[0], test.ring)
			want, valid := exactGCReferenceMulTruncateChecked(
				xa[0], xb[0], ya[0], yb[0], spec)
			if !valid || got.Cmp(want) != 0 {
				t.Fatalf("direct wide product got %s want %s valid=%v", got, want, valid)
			}
		})
	}
}

func TestExactGCWorkerRejectsUnsafeConfigAndExpiredHeartbeat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := exactGCReadWorkerConfig(path); err == nil {
		t.Fatal("group/world-readable config was accepted")
	}

	spool := exactGCTestSpool(t, "expired")
	old := time.Now().Add(-20 * time.Second)
	if err := os.Chtimes(filepath.Join(spool, "exchange.hb"), old, old); err != nil {
		t.Fatal(err)
	}
	rw, err := newExactGCSpoolRW(spool, 1<<20, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired heartbeat, got %v", err)
	}
}

func TestExactGCSpoolBuffersToPublicChunkAndFlushesAtReadDependency(t *testing.T) {
	spool := exactGCTestSpool(t, "buffered")
	if _, err := exactGCPublishSegment(
		filepath.Join(spool, "inbound.segments"), 0, []byte{0x7f}); err != nil {
		t.Fatal(err)
	}
	rw, err := newExactGCSpoolRW(spool, 8<<20, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	size := func() int64 {
		value, err := exactGCReadOffset(filepath.Join(spool, "outbound.head"))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}

	small := bytes.Repeat([]byte{0x31}, 4096)
	if n, err := rw.Write(small); err != nil || n != len(small) {
		t.Fatalf("buffer small write: n=%d err=%v", n, err)
	}
	if got := size(); got != 0 {
		t.Fatalf("sub-chunk write was published before a dependency: %d", got)
	}
	var incoming [1]byte
	if n, err := rw.Read(incoming[:]); err != nil || n != 1 || incoming[0] != 0x7f {
		t.Fatalf("read dependency: n=%d byte=%x err=%v", n, incoming[0], err)
	}
	if got := size(); got != int64(len(small)) {
		t.Fatalf("read dependency did not flush pending output: %d", got)
	}

	half := bytes.Repeat([]byte{0x42}, exactGCSpoolWriteBuffer/2)
	if _, err := rw.Write(half); err != nil {
		t.Fatal(err)
	}
	if got := size(); got != int64(len(small)) {
		t.Fatalf("half chunk was published early: %d", got)
	}
	if _, err := rw.Write(half); err != nil {
		t.Fatal(err)
	}
	if got := size(); got != int64(len(small)+exactGCSpoolWriteBuffer) {
		t.Fatalf("full public chunk was not published atomically: %d", got)
	}

	tail := bytes.Repeat([]byte{0x53}, 1024)
	if _, err := rw.Write(tail); err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	if got := size(); got != int64(len(small)+exactGCSpoolWriteBuffer+len(tail)) {
		t.Fatalf("close did not flush final protocol bytes: %d", got)
	}
}

func TestExactGCSegmentSpoolReclaimsAcknowledgedCapacity(t *testing.T) {
	spool := exactGCTestSpool(t, "reclaim-capacity")
	rw, err := newExactGCSpoolRW(spool, 1<<20, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first := bytes.Repeat([]byte{0x11}, 700<<10)
	if _, err := rw.Write(first); err != nil {
		t.Fatal(err)
	}
	if err := rw.Flush(); err != nil {
		t.Fatal(err)
	}
	second := bytes.Repeat([]byte{0x22}, 400<<10)
	writeDone := make(chan error, 1)
	go func() {
		_, err := rw.Write(second)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		t.Fatalf("full spool did not apply backpressure: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	segments, err := exactGCListSegments(filepath.Join(spool, "outbound.segments"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("unexpected retained segments: %v err=%v", segments, err)
	}
	if err := os.Remove(segments[0].path); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("acknowledged bytes did not release capacity: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("acknowledged bytes did not release backpressure")
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	if head, err := exactGCReadOffset(filepath.Join(spool, "outbound.head")); err != nil || head != int64(len(first)+len(second)) {
		t.Fatalf("absolute outbound head=%d err=%v", head, err)
	}
}

func TestExactGCSegmentSpoolConsumesAndReclaimsInboundBytes(t *testing.T) {
	spool := exactGCTestSpool(t, "consume-inbound")
	payload := bytes.Repeat([]byte{0x5a}, 128<<10)
	segment, err := exactGCPublishSegment(
		filepath.Join(spool, "inbound.segments"), 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	rw, err := newExactGCSpoolRW(spool, 1<<20, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(rw, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("segmented inbound stream changed bytes")
	}
	if fileExists(segment.path) {
		t.Fatal("fully consumed inbound segment was retained")
	}
	if ack, err := exactGCReadOffset(filepath.Join(spool, "inbound.ack")); err != nil || ack != int64(len(payload)) {
		t.Fatalf("durable inbound base=%d err=%v", ack, err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExactGCSegmentSpoolRejectsTamperOverlapAndGap(t *testing.T) {
	t.Run("tamper", func(t *testing.T) {
		spool := exactGCTestSpool(t, "tamper")
		segment, err := exactGCPublishSegment(
			filepath.Join(spool, "inbound.segments"), 0, []byte("abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(segment.path, []byte("abcdeg"), 0o600); err != nil {
			t.Fatal(err)
		}
		rw, err := newExactGCSpoolRW(spool, 1<<20, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rw.Read(make([]byte, 6)); err == nil ||
			!strings.Contains(err.Error(), "hash mismatch") {
			t.Fatalf("expected fail-closed segment hash, got %v", err)
		}
	})

	t.Run("overlap", func(t *testing.T) {
		spool := exactGCTestSpool(t, "overlap")
		dir := filepath.Join(spool, "inbound.segments")
		if _, err := exactGCPublishSegment(dir, 0, []byte("abcdef")); err != nil {
			t.Fatal(err)
		}
		if _, err := exactGCPublishSegment(dir, 0, []byte("ABCDEF")); err == nil ||
			!strings.Contains(err.Error(), "conflicting") {
			t.Fatalf("expected conflicting segment rejection, got %v", err)
		}
	})

	t.Run("gap", func(t *testing.T) {
		spool := exactGCTestSpool(t, "gap")
		if _, err := exactGCPublishSegment(
			filepath.Join(spool, "inbound.segments"), 1, []byte("x")); err != nil {
			t.Fatal(err)
		}
		rw, err := newExactGCSpoolRW(spool, 1<<20, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rw.Read(make([]byte, 1)); err == nil ||
			!strings.Contains(err.Error(), "segment gap") {
			t.Fatalf("expected fail-closed segment gap, got %v", err)
		}
	})
}

func TestExactGCSegmentSpoolRestoresDurableAbsoluteBases(t *testing.T) {
	spool := exactGCTestSpool(t, "durable-bases")
	inboundDir := filepath.Join(spool, "inbound.segments")
	stale, err := exactGCPublishSegment(inboundDir, 0, []byte("old!"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exactGCPublishSegment(inboundDir, 4, []byte("next")); err != nil {
		t.Fatal(err)
	}
	if err := exactGCWriteOffset(filepath.Join(spool, "inbound.ack"), 4); err != nil {
		t.Fatal(err)
	}

	outboundDir := filepath.Join(spool, "outbound.segments")
	if _, err := exactGCPublishSegment(outboundDir, 0, []byte("sent")); err != nil {
		t.Fatal(err)
	}
	if err := exactGCWriteOffset(filepath.Join(spool, "outbound.head"), 4); err != nil {
		t.Fatal(err)
	}

	rw, err := newExactGCSpoolRW(spool, 1<<20, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(rw, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "next" || fileExists(stale.path) {
		t.Fatalf("resume read=%q stale_exists=%v", got, fileExists(stale.path))
	}
	if _, err := rw.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	if head, err := exactGCReadOffset(filepath.Join(spool, "outbound.head")); err != nil || head != 8 {
		t.Fatalf("resumed outbound head=%d err=%v", head, err)
	}
	segments, err := exactGCListSegments(outboundDir)
	if err != nil || len(segments) != 2 || segments[1].start != 4 ||
		segments[1].end != 8 {
		t.Fatalf("resumed outbound segments=%#v err=%v", segments, err)
	}
}

func TestExactGCOffsetSnapshotSurvivesConcurrentAtomicReplace(t *testing.T) {
	spool := exactGCTestSpool(t, "offset-snapshot")
	path := filepath.Join(spool, "outbound.head")
	const writes = 1000
	start := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		<-start
		for i := 1; i <= writes; i++ {
			if err := exactGCWriteOffset(path, int64(i)); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	close(start)
	last := int64(0)
	for i := 0; i < writes; i++ {
		value, err := exactGCReadOffset(path)
		if err != nil {
			t.Fatalf("concurrent offset snapshot failed: %v", err)
		}
		if value < 0 || value > writes {
			t.Fatalf("non-atomic offset snapshot: %d", value)
		}
		if value < last {
			t.Fatalf("offset snapshot rolled back: %d after %d", value, last)
		}
		last = value
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if value, err := exactGCReadOffset(path); err != nil || value != writes {
		t.Fatalf("final offset=%d err=%v", value, err)
	}
}

func TestExactGCVerifiedSegmentDescriptorSurvivesReclaim(t *testing.T) {
	spool := exactGCTestSpool(t, "open-reclaim")
	payload := bytes.Repeat([]byte("immutable-segment/"), 1024)
	segment, err := exactGCPublishSegment(
		filepath.Join(spool, "inbound.segments"), 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	file, err := exactGCOpenVerifiedSegment(segment)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Remove(segment.path); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := file.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reclaimed open segment changed bytes")
	}
}

func BenchmarkExactGCSegmentPublishReclaim480KiB(b *testing.B) {
	dir := b.TempDir()
	payload := bytes.Repeat([]byte{0xa5}, 480<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		segment, err := exactGCPublishSegment(dir, 0, payload)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.Remove(segment.path); err != nil {
			b.Fatal(err)
		}
	}
}

func exactGCTestRunWorkers(t *testing.T, spec exactGCCircuitSpec,
	a, b []*big.Int) (exactGCWorkerResult, exactGCWorkerResult) {
	t.Helper()
	gDir := exactGCTestSpool(t, "garbler")
	eDir := exactGCTestSpool(t, "evaluator")
	sid := sha256.Sum256([]byte("worker-session/" + t.Name()))
	master := sha256.Sum256([]byte("worker-master/" + t.Name()))
	threshold := ""
	if spec.Threshold != nil {
		threshold = spec.Threshold.String()
	}
	base := exactGCWorkerConfig{
		Version:     exactGCWorkerConfigVersion,
		SessionID:   hex.EncodeToString(sid[:]),
		MasterKey:   base64.StdEncoding.EncodeToString(master[:]),
		GarblerID:   "dsv1_" + strings.Repeat("a", 64),
		EvaluatorID: "dsv1_" + strings.Repeat("b", 64),
		Purpose:     "worker-e2e-test", Operation: string(spec.Operation),
		RingBits: spec.RingBits, FracBits: spec.FracBits, Threshold: threshold,
		VectorLen: spec.VectorLen, MaxSpoolBytes: 64 << 20, TTLSeconds: 30,
	}
	if spec.Operation == exactGCMulTruncateChecked {
		base.MulBackend = string(spec.MulBackend)
		base.BoundX = spec.BoundX.String()
		base.BoundY = spec.BoundY.String()
	}
	gCfg := base
	gCfg.Role, gCfg.SpoolDir = "garbler", gDir
	gCfg.SourceShare = exactGCTestEncodeSource(t, a, spec)
	eCfg := base
	eCfg.Role, eCfg.SpoolDir = "evaluator", eDir
	eCfg.SourceShare = exactGCTestEncodeSource(t, b, spec)
	gPath := exactGCTestWriteConfig(t, gDir, gCfg)
	ePath := exactGCTestWriteConfig(t, eDir, eCfg)

	errs := make(chan error, 2)
	go func() { errs <- handleExactGCWorker(gPath) }()
	go func() { errs <- handleExactGCWorker(ePath) }()
	gOffset, eOffset := int64(0), int64(0)
	deadline := time.Now().Add(20 * time.Second)
	for !exactGCTestBothDone(gDir, eDir) && time.Now().Before(deadline) {
		gOffset = exactGCTestRelaySpool(t, gDir, eDir, gOffset)
		eOffset = exactGCTestRelaySpool(t, eDir, gDir, eOffset)
		now := time.Now()
		for _, dir := range []string{gDir, eDir} {
			hb := filepath.Join(dir, "exchange.hb")
			if err := os.Chtimes(hb, now, now); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Millisecond)
	}
	if !exactGCTestBothDone(gDir, eDir) {
		t.Fatal("exact-gc workers did not complete")
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("worker failed: %v", err)
		}
	}
	return exactGCTestReadResult(t, gDir), exactGCTestReadResult(t, eDir)
}

func exactGCTestSpool(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{
		"inbound.bin", "outbound.bin", "exchange.hb", "worker.hb",
	} {
		data := []byte{}
		if file == "exchange.hb" || file == "worker.hb" {
			data = []byte(".")
		}
		if err := os.WriteFile(filepath.Join(dir, file), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"inbound.segments", "outbound.segments"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(dir, "inbound.state"), []byte(exactGCInboundStateInitial),
		0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inbound.ack", "outbound.head", "outbound.ack"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("0"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func exactGCTestWriteConfig(t *testing.T, dir string, config exactGCWorkerConfig) string {
	t.Helper()
	if config.HeartbeatKey == "" {
		key := sha256.Sum256([]byte("exact-gc-test-heartbeat/" + dir))
		config.HeartbeatKey = base64.StdEncoding.EncodeToString(key[:])
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func exactGCTestRelaySpool(t *testing.T, from, to string, offset int64) int64 {
	t.Helper()
	head, err := exactGCReadOffset(filepath.Join(from, "outbound.head"))
	if err != nil {
		t.Fatal(err)
	}
	if head <= offset {
		return offset
	}
	segments, err := exactGCListSegments(filepath.Join(from, "outbound.segments"))
	if err != nil {
		t.Fatal(err)
	}
	pending := make([]byte, 0, head-offset)
	cursor := offset
	for cursor < head {
		var selected *exactGCSegment
		for i := range segments {
			if segments[i].start <= cursor && segments[i].end > cursor {
				selected = &segments[i]
				break
			}
		}
		if selected == nil {
			t.Fatal("exact-gc test relay found an outbound segment gap")
		}
		if err := exactGCVerifySegment(*selected); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(selected.path)
		if err != nil {
			t.Fatal(err)
		}
		first := cursor - selected.start
		last := selected.end - selected.start
		pending = append(pending, data[first:last]...)
		cursor = selected.end
	}
	if _, err := exactGCPublishSegment(
		filepath.Join(to, "inbound.segments"), offset, pending); err != nil {
		t.Fatal(err)
	}
	for _, segment := range segments {
		if segment.end <= head {
			if err := os.Remove(segment.path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
	}
	return head
}

func exactGCTestBothDone(a, b string) bool {
	return fileExists(filepath.Join(a, "done")) && fileExists(filepath.Join(b, "done"))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func exactGCTestReadResult(t *testing.T, dir string) exactGCWorkerResult {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result exactGCWorkerResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func exactGCTestEncodeSource(t *testing.T, shares []*big.Int,
	spec exactGCCircuitSpec) string {
	t.Helper()
	encodingSpec := spec
	if spec.Operation == exactGCMulTruncateChecked {
		encodingSpec = exactGCCircuitSpec{
			Operation: exactGCTruncateFloor, RingBits: spec.RingBits,
			FracBits: spec.FracBits, VectorLen: len(shares),
		}
	}
	encoded, err := exactGCEncodeWorkerCanonicalShares(shares, encodingSpec)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func newDeterministicRand(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}
