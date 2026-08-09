package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func jointDPTestRat(t *testing.T, numerator, denominator string) *big.Rat {
	t.Helper()
	n, ok := new(big.Int).SetString(numerator, 10)
	if !ok {
		t.Fatal("invalid numerator")
	}
	d, ok := new(big.Int).SetString(denominator, 10)
	if !ok {
		t.Fatal("invalid denominator")
	}
	return new(big.Rat).SetFrac(n, d)
}

func TestJointDPMPCLAssetsArePinnedPrivateAndTamperEvident(t *testing.T) {
	pkgRoot := filepath.Join(t.TempDir(), "pkg")
	for _, asset := range jointDPMPCLAssets {
		if err := jointDPExpandMPCLAsset(pkgRoot, asset); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(pkgRoot, filepath.FromSlash(asset.packagePath))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if int64(len(data)) != asset.size ||
			hex.EncodeToString(digest[:]) != asset.sha256Hex {
			t.Fatalf("expanded asset does not match manifest: %s", asset.packagePath)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("expanded asset is group/world accessible: %s", asset.packagePath)
		}
	}

	tampered := jointDPMPCLAssets[0]
	tampered.sha256Hex = "00" + tampered.sha256Hex[2:]
	if err := jointDPExpandMPCLAsset(
		filepath.Join(t.TempDir(), "pkg"), tampered); err == nil {
		t.Fatal("asset digest tamper was accepted")
	}
	wrongSize := jointDPMPCLAssets[0]
	wrongSize.size--
	if err := jointDPExpandMPCLAsset(
		filepath.Join(t.TempDir(), "pkg"), wrongSize); err == nil {
		t.Fatal("asset size tamper was accepted")
	}

	manifest := jointDPMPCLManifestDigest()
	changedAssets := append([]jointDPMPCLAsset(nil), jointDPMPCLAssets...)
	changedAssets[0].sha256Hex = tampered.sha256Hex
	changedManifest := jointDPMPCLManifestDigestFor(changedAssets)
	if manifest == changedManifest {
		t.Fatal("asset manifest digest ignored a changed circuit hash")
	}
	spec, _, _ := jointDPTestSpec(t, 127, 50, 1, 1)
	if spec.digestWithAssets(manifest) == spec.digestWithAssets(changedManifest) {
		t.Fatal("circuit digest did not bind the asset manifest")
	}
}

func TestJointDPMPCLRuntimeIsScopedRestoredAndRemoved(t *testing.T) {
	tempParent := t.TempDir()
	t.Setenv("TMPDIR", tempParent)
	t.Setenv("MPCLDIR", "pre-existing-mpcl-root")
	var leasedRoot string
	wantErr := "deliberate compile failure"
	err := jointDPWithMPCLRuntime(func() error {
		leasedRoot = os.Getenv("MPCLDIR")
		if filepath.Dir(leasedRoot) != tempParent ||
			!strings.HasPrefix(filepath.Base(leasedRoot), "dsvert-mpcl-") {
			t.Fatalf("runtime used an unexpected root: %q", leasedRoot)
		}
		if info, statErr := os.Stat(leasedRoot); statErr != nil ||
			info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("runtime root is absent or not private: %v %#v", statErr, info)
		}
		return fmt.Errorf("%s", wantErr)
	})
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("runtime lost callback error: %v", err)
	}
	if got := os.Getenv("MPCLDIR"); got != "pre-existing-mpcl-root" {
		t.Fatalf("MPCLDIR was not restored: %q", got)
	}
	if _, err := os.Stat(leasedRoot); !os.IsNotExist(err) {
		t.Fatalf("private runtime survived callback failure: %q", leasedRoot)
	}
	matches, err := filepath.Glob(filepath.Join(tempParent, "dsvert-mpcl-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("private runtime leaked after callback failure: %v %v", matches, err)
	}
}

func TestJointDPGCCompileLeavesNoMPCLRuntime(t *testing.T) {
	tempParent := t.TempDir()
	t.Setenv("TMPDIR", tempParent)
	t.Setenv("MPCLDIR", "compile-sentinel")
	spec, _, _ := jointDPTestSpec(t, 127, 50, 2, 3)
	keyDigest := spec.digest()
	key := hex.EncodeToString(keyDigest[:])
	jointDPGCCache.Lock()
	delete(jointDPGCCache.entries, key)
	jointDPGCCache.Unlock()
	if _, err := jointDPGCCompile(spec); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("MPCLDIR"); got != "compile-sentinel" {
		t.Fatalf("compile did not restore MPCLDIR: %q", got)
	}
	matches, err := filepath.Glob(filepath.Join(tempParent, "dsvert-mpcl-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("compile leaked private MPCL runtime: %v %v", matches, err)
	}
}

func TestJointDPProtocolFailureLeavesNoMPCLRuntime(t *testing.T) {
	tempParent := t.TempDir()
	t.Setenv("TMPDIR", tempParent)
	t.Setenv("MPCLDIR", "protocol-failure-sentinel")
	spec, garblerSeed, _ := jointDPTestSpec(t, 127, 50, 1, 3)
	keyDigest := spec.digest()
	key := hex.EncodeToString(keyDigest[:])
	jointDPGCCache.Lock()
	delete(jointDPGCCache.entries, key)
	jointDPGCCache.Unlock()
	session := jointDPTestSession(spec, "runtime-cleanup-error")
	if _, err := jointDPGCRunGarbler(
		nilReadWriter{}, session, spec, []*big.Int{big.NewInt(0)},
		garblerSeed); err == nil {
		t.Fatal("expected the deliberately unavailable peer channel to fail")
	}
	if got := os.Getenv("MPCLDIR"); got != "protocol-failure-sentinel" {
		t.Fatalf("failed protocol did not restore MPCLDIR: %q", got)
	}
	matches, err := filepath.Glob(filepath.Join(tempParent, "dsvert-mpcl-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("failed protocol leaked private MPCL runtime: %v %v", matches, err)
	}
}

func TestJointDPLaplacePlanCertificate(t *testing.T) {
	input := jointDPLaplacePlanInput{
		Epsilon: ".5", Delta: "5e-7", SensitivitySteps: "2",
		CoordinateCount: 4, BernoulliBits: 8,
	}
	plan, err := jointDPPlanLaplace(input)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Version != jointDPLaplacePlanVersion ||
		plan.Sampler != jointDPSamplerVersion || plan.MaxGeometricSteps < 1 {
		t.Fatalf("invalid plan: %#v", plan)
	}
	wantBytes := 2 * input.CoordinateCount * plan.MaxGeometricSteps *
		(input.BernoulliBits / 8)
	if plan.BernoulliTrials != 2*input.CoordinateCount*plan.MaxGeometricSteps ||
		plan.AESBlocks != (wantBytes+15)/16 || plan.CapabilityAvailable ||
		plan.UnavailableReason == "" {
		t.Fatalf("planner cost/promotion contract is invalid: %#v", plan)
	}
	epsilon, _ := jointDPParseDecimalRat(input.Epsilon, "epsilon", false)
	epsilonUpper := jointDPTestRat(t, plan.EpsilonEffectiveUpperNumerator,
		plan.EpsilonEffectiveUpperDenom)
	if epsilonUpper.Cmp(epsilon) > 0 {
		t.Fatal("effective epsilon certificate exceeds allocation")
	}
	delta, _ := jointDPParseDecimalRat(input.Delta, "delta", false)
	deltaUpper := jointDPTestRat(t, plan.ImplementationDeltaNumerator,
		plan.ImplementationDeltaDenom)
	if deltaUpper.Cmp(delta) > 0 {
		t.Fatal("implementation delta certificate exceeds allocation")
	}
	// The planner chooses the smallest fixed truncation depth satisfying the
	// exact rational certificate.
	q, _ := new(big.Int).SetString(plan.StopNumerator, 10)
	den := new(big.Int).Lsh(big.NewInt(1), uint(plan.BernoulliBits))
	p := new(big.Rat).SetFrac(new(big.Int).Sub(den, q), den)
	if plan.MaxGeometricSteps > 1 {
		previous := new(big.Rat).Quo(new(big.Rat).Set(deltaUpper), p)
		if previous.Cmp(delta) <= 0 {
			t.Fatal("planner did not choose the minimal truncation depth")
		}
	}
}

func TestJointDPLaplacePlanFailsClosed(t *testing.T) {
	tests := []jointDPLaplacePlanInput{
		{Epsilon: ".5", Delta: "0", SensitivitySteps: "1", CoordinateCount: 1, BernoulliBits: 8},
		{Epsilon: "1e-100", Delta: "1e-6", SensitivitySteps: "1", CoordinateCount: 1, BernoulliBits: 8},
		{Epsilon: ".5", Delta: "1e-6", SensitivitySteps: "1.5", CoordinateCount: 1, BernoulliBits: 8},
		{Epsilon: ".5", Delta: "1e-1000", SensitivitySteps: "1000000", CoordinateCount: 64, BernoulliBits: 16, MaxSteps: 2},
		{Epsilon: "1" + string(bytes.Repeat([]byte{'0'}, 256)), Delta: "1e-6", SensitivitySteps: "1", CoordinateCount: 1, BernoulliBits: 8},
	}
	for _, test := range tests {
		if _, err := jointDPPlanLaplace(test); err == nil {
			t.Fatalf("unsafe plan was accepted: %#v", test)
		}
	}
}

func TestJointDPExpUpperReallyIsUpper(t *testing.T) {
	for _, value := range []string{"1e-9", ".1", ".5", "1", "5", "20"} {
		x, err := jointDPParseDecimalRat(value, "epsilon", false)
		if err != nil {
			t.Fatal(err)
		}
		upper, err := jointDPExpUpper(x)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := upper.Float64()
		want, _ := new(big.Float).SetRat(x).Float64()
		if got < math.Exp(want) {
			t.Fatalf("exp upper bound is below exp(%s)", value)
		}
	}
}

func TestJointDPExpLowerCappedReallyIsLower(t *testing.T) {
	for _, value := range []string{"1e-9", ".1", ".5", "1", "5", "20"} {
		x, err := jointDPParseDecimalRat(value, "epsilon", false)
		if err != nil {
			t.Fatal(err)
		}
		lower, err := jointDPExpLowerCapped(x, big.NewRat(1<<20, 1))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := lower.Float64()
		want, _ := new(big.Float).SetRat(x).Float64()
		if got > math.Exp(want)*(1+2e-15) {
			t.Fatalf("exp lower bound exceeds exp(%s)", value)
		}
	}
}

func TestJointDPLaplacePlanUsesTightCertifiedDyadicRate(t *testing.T) {
	plan, err := jointDPPlanLaplace(jointDPLaplacePlanInput{
		Epsilon: "1", Delta: "7.888609052210118e-31",
		SensitivitySteps: "1", CoordinateCount: 1, BernoulliBits: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	// floor(256*(1-exp(-1))) is 161.  The former q/(1-q) certificate
	// selected only 128 and silently left about 30% of the declared epsilon
	// unused.  The rational exp-lower certificate reaches the tight dyadic.
	if plan.StopNumerator != "161" {
		t.Fatalf("tight certified stop numerator=%s, want 161", plan.StopNumerator)
	}
	if plan.MaxGeometricSteps >= 102 {
		t.Fatalf("tight calibration did not reduce the old 102-step plan: %#v", plan)
	}

	epsilon, _ := jointDPParseDecimalRat("1", "epsilon", false)
	sensitivity, _ := jointDPParseDecimalRat("1", "sensitivity", false)
	denominator := big.NewInt(256)
	q, err := jointDPMaxCertifiedStopNumerator(
		epsilon, sensitivity, denominator)
	if err != nil || q.String() != plan.StopNumerator {
		t.Fatalf("planner and exact certificate disagree: q=%v err=%v", q, err)
	}
	x := new(big.Rat).Quo(epsilon, sensitivity)
	lower, err := jointDPExpLowerCapped(x, new(big.Rat).SetInt(denominator))
	if err != nil {
		t.Fatal(err)
	}
	ratio := func(numerator *big.Int) *big.Rat {
		return new(big.Rat).SetFrac(new(big.Int).Set(denominator),
			new(big.Int).Sub(new(big.Int).Set(denominator), numerator))
	}
	if ratio(q).Cmp(lower) > 0 {
		t.Fatal("selected q lacks the exact exp-lower certificate")
	}
	if ratio(new(big.Int).Add(new(big.Int).Set(q), big.NewInt(1))).Cmp(lower) <= 0 {
		t.Fatal("planner did not choose the largest certified dyadic q")
	}
	actualEffective := -math.Log(float64(256-161) / 256)
	if actualEffective > 1 || actualEffective < .99 {
		t.Fatalf("unexpected effective epsilon: %.17g", actualEffective)
	}
}

func TestJointDPLaplaceDyadicCertificateGridNeverOverspendsEpsilon(t *testing.T) {
	for _, bits := range []int{8, 16} {
		denominator := float64(uint64(1) << uint(bits))
		for _, epsilon := range []string{".01", ".1", ".5", "1", "3", "8"} {
			for _, sensitivity := range []string{"1", "2", "10", "100"} {
				epsilonRat, _ := jointDPParseDecimalRat(epsilon, "epsilon", false)
				sensitivityRat, _ := jointDPParseDecimalRat(
					sensitivity, "sensitivity", false)
				q, err := jointDPMaxCertifiedStopNumerator(
					epsilonRat, sensitivityRat,
					new(big.Int).SetUint64(uint64(denominator)))
				if err != nil {
					// At a fixed dyadic precision a sufficiently small
					// epsilon/sensitivity ratio is correctly unavailable.
					continue
				}
				qFloat, _ := new(big.Float).SetInt(q).Float64()
				sensitivityFloat, _ := new(big.Float).SetRat(sensitivityRat).Float64()
				epsilonFloat, _ := new(big.Float).SetRat(epsilonRat).Float64()
				effective := sensitivityFloat * -math.Log1p(-qFloat/denominator)
				if effective > epsilonFloat*(1+2e-15) {
					t.Fatalf("bits=%d epsilon=%s sensitivity=%s effective=%.17g",
						bits, epsilon, sensitivity, effective)
				}
			}
		}
	}
}

func TestJointDPTruncatedGeometricExactSmallDistribution(t *testing.T) {
	// Exhaustively enumerate all sequences for D=4, q=1, L=3.  The sampler
	// must produce P(G=k)=p^k*q for k<L and P(G=L)=p^L.
	const denominator = 4
	const steps = 3
	counts := make([]int, steps+1)
	total := 1
	for i := 0; i < steps; i++ {
		total *= denominator
	}
	for encoded := 0; encoded < total; encoded++ {
		value := encoded
		active := true
		g := 0
		for i := 0; i < steps; i++ {
			u := value % denominator
			value /= denominator
			if active && u >= 1 {
				g++
			} else {
				active = false
			}
		}
		counts[g]++
	}
	want := []int{16, 12, 9, 27}
	for i := range want {
		if counts[i] != want[i] {
			t.Fatalf("G=%d: got %d, want %d", i, counts[i], want[i])
		}
	}
	// The capped mass at L is p^L=27/64, but only the original tail G>L is
	// moved by the coupling.  Therefore TV(Geom, min(Geom,L)) is
	// p^(L+1)=81/256, not p^L.  This distinction drives the planner's L+1.
	tv := big.NewRat(81, 256)
	if tv.Cmp(new(big.Rat).Mul(big.NewRat(27, 64), big.NewRat(3, 4))) != 0 {
		t.Fatal("invalid geometric truncation TV identity")
	}
}

func jointDPTestSpec(t *testing.T, ringBits, fracBits, coordinates, steps int) (jointDPGCLaplaceSpec, [32]byte, [32]byte) {
	t.Helper()
	transcript := sha256.Sum256([]byte("joint-DP test transcript"))
	garblerSeed := sha256.Sum256([]byte("joint-DP garbler seed"))
	evaluatorSeed := sha256.Sum256([]byte("joint-DP evaluator seed"))
	gctx := jointDPCommitmentContext(transcript, "garbler", "peer-a")
	ectx := jointDPCommitmentContext(transcript, "evaluator", "peer-b")
	scale := new(big.Int).Lsh(big.NewInt(1), uint(fracBits))
	spec := jointDPGCLaplaceSpec{
		RingBits: ringBits, FracBits: fracBits, CoordinateCount: coordinates,
		BernoulliBits: 8, StopNumerator: 161, MaxGeometricSteps: steps,
		SensitivitySteps: big.NewInt(1),
		EncodedLower:     new(big.Int).Mul(big.NewInt(-100), scale),
		EncodedUpper:     new(big.Int).Mul(big.NewInt(100), scale),
		TranscriptHash:   transcript, GarblerCommitmentContext: gctx,
		EvaluatorCommitmentContext: ectx,
		GarblerSeedCommitment:      jointDPSeedCommitment(gctx, garblerSeed),
		EvaluatorSeedCommitment:    jointDPSeedCommitment(ectx, evaluatorSeed),
	}
	if err := spec.validate(); err != nil {
		t.Fatal(err)
	}
	return spec, garblerSeed, evaluatorSeed
}

func TestJointDPGCCircuitMatchesReference(t *testing.T) {
	spec, garblerSeed, evaluatorSeed := jointDPTestSpec(t, 63, 20, 1, 1)
	circ, err := jointDPGCCompile(spec)
	if err != nil {
		t.Fatal(err)
	}
	scale := new(big.Int).Lsh(big.NewInt(1), 20)
	value := new(big.Int).Mul(big.NewInt(5), scale)
	garblerShare := big.NewInt(1234567)
	evaluatorShare := new(big.Int).Sub(value, garblerShare)
	evaluatorShare.Mod(evaluatorShare, exactGCModulus(63))
	digest := spec.digest()
	masks, validityMask := jointDPDeterministicMasks(garblerSeed, digest, spec)
	g := jointDPPackInput([]*big.Int{garblerShare}, garblerSeed, masks,
		validityMask, spec, true)
	e := jointDPPackInput([]*big.Int{evaluatorShare}, evaluatorSeed, nil,
		false, spec, false)
	chunk := func(packed *big.Int, offset, bits int) *big.Int {
		value := new(big.Int).Rsh(new(big.Int).Set(packed), uint(offset))
		return value.And(value, exactGCMask(bits))
	}
	computed, err := circ.Compute([]*big.Int{
		chunk(g, 0, 64), chunk(g, 64, 256), chunk(g, 320, 64),
		chunk(g, 384, 1), chunk(e, 0, 64), chunk(e, 64, 256),
	})
	if err != nil {
		t.Fatal(err)
	}
	outputs := jointDPUnpackOutputs(computed[0], spec)
	if outputs[1].Bit(0) == uint(validityMaskToBit(validityMask)) {
		// XOR of the two validity shares must be true.
		t.Fatal("validity shares did not reconstruct true")
	}
	result := exactGCReferenceReconstruct(masks[0], outputs[0], 63)
	noise, err := jointDPReferenceNoise(spec, garblerSeed, evaluatorSeed)
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Add(value,
		new(big.Int).Mul(big.NewInt(noise[0]), scale))
	want.Mod(want, exactGCModulus(63))
	if result.Cmp(want) != 0 {
		t.Fatalf("circuit result=%s, reference=%s (noise=%d)", result, want, noise[0])
	}
}

func jointDPDirectCompute(t *testing.T, spec jointDPGCLaplaceSpec,
	garblerSeed, evaluatorSeed [32]byte, a, b []*big.Int) ([]*big.Int, []*big.Int) {
	t.Helper()
	circ, err := jointDPGCCompile(spec)
	if err != nil {
		t.Fatal(err)
	}
	digest := spec.digest()
	masks, validityMask := jointDPDeterministicMasks(garblerSeed, digest, spec)
	g := jointDPPackInput(a, garblerSeed, masks, validityMask, spec, true)
	e := jointDPPackInput(b, evaluatorSeed, nil, false, spec, false)
	typeBits := exactGCTypeBits(spec.RingBits)
	chunk := func(packed *big.Int, offset, bits int) *big.Int {
		value := new(big.Int).Rsh(new(big.Int).Set(packed), uint(offset))
		return value.And(value, exactGCMask(bits))
	}
	gStatBits := spec.CoordinateCount * typeBits
	gMaskOffset := gStatBits + 256
	gValidityOffset := gMaskOffset + spec.CoordinateCount*typeBits
	computed, err := circ.Compute([]*big.Int{
		chunk(g, 0, gStatBits), chunk(g, gStatBits, 256),
		chunk(g, gMaskOffset, spec.CoordinateCount*typeBits),
		chunk(g, gValidityOffset, 1),
		chunk(e, 0, gStatBits), chunk(e, gStatBits, 256),
	})
	if err != nil {
		t.Fatal(err)
	}
	garblerOutputs := append(append([]*big.Int{}, masks...),
		new(big.Int).SetUint64(boolToUint64(validityMask)))
	return garblerOutputs, jointDPUnpackOutputs(computed[0], spec)
}

func TestJointDPGCRing127AndSixteenBitDrawsMatchReference(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ringBits int
		fracBits int
		bits     int
		stop     uint32
	}{{"Ring63/B16", 63, 20, 16, 32768}, {"Ring127/B8", 127, 50, 8, 128}} {
		t.Run(tc.name, func(t *testing.T) {
			spec, garblerSeed, evaluatorSeed := jointDPTestSpec(
				t, tc.ringBits, tc.fracBits, 1, 1)
			spec.BernoulliBits, spec.StopNumerator = tc.bits, tc.stop
			if err := spec.validate(); err != nil {
				t.Fatal(err)
			}
			scale := new(big.Int).Lsh(big.NewInt(1), uint(tc.fracBits))
			valueSigned := new(big.Int).Mul(big.NewInt(-7), scale)
			value := jointDPResidue(valueSigned, tc.ringBits)
			a := []*big.Int{big.NewInt(987654321)}
			b := []*big.Int{new(big.Int).Mod(
				new(big.Int).Sub(value, a[0]), exactGCModulus(tc.ringBits))}
			g, e := jointDPDirectCompute(t, spec, garblerSeed, evaluatorSeed, a, b)
			if g[1].Bit(0)^e[1].Bit(0) != 1 {
				t.Fatal("validity shares did not reconstruct true")
			}
			opened := exactGCReferenceReconstruct(g[0], e[0], tc.ringBits)
			noise, err := jointDPReferenceNoise(spec, garblerSeed, evaluatorSeed)
			if err != nil {
				t.Fatal(err)
			}
			wantSigned := new(big.Int).Add(valueSigned,
				new(big.Int).Mul(big.NewInt(noise[0]), scale))
			want := jointDPResidue(wantSigned, tc.ringBits)
			if opened.Cmp(want) != 0 {
				t.Fatalf("opened=%s, reference=%s", opened, want)
			}
		})
	}
}

func TestJointDPGCCircuitRejectsRemoteCommitmentAndOutOfBoundsInput(t *testing.T) {
	spec, garblerSeed, evaluatorSeed := jointDPTestSpec(t, 63, 20, 1, 1)
	wrongGarblerSeed := garblerSeed
	wrongGarblerSeed[0] ^= 1
	g, e := jointDPDirectCompute(t, spec, wrongGarblerSeed, evaluatorSeed,
		[]*big.Int{big.NewInt(0)}, []*big.Int{big.NewInt(0)})
	if g[1].Bit(0)^e[1].Bit(0) != 0 {
		t.Fatal("wrong remote seed commitment reconstructed valid")
	}
	if exactGCReferenceReconstruct(g[0], e[0], 63).Sign() != 0 {
		t.Fatal("invalid commitment did not zero the masked payload")
	}

	tooHigh := new(big.Int).Add(spec.EncodedUpper, big.NewInt(1))
	residue := jointDPResidue(tooHigh, 63)
	a := []*big.Int{big.NewInt(123)}
	b := []*big.Int{new(big.Int).Mod(new(big.Int).Sub(residue, a[0]), exactGCModulus(63))}
	g, e = jointDPDirectCompute(t, spec, garblerSeed, evaluatorSeed, a, b)
	if g[1].Bit(0)^e[1].Bit(0) != 0 ||
		exactGCReferenceReconstruct(g[0], e[0], 63).Sign() != 0 {
		t.Fatal("out-of-bounds aggregate was not rejected and zeroed")
	}
}

func TestJointDPReferenceSamplerDistribution(t *testing.T) {
	spec, _, _ := jointDPTestSpec(t, 63, 20, 1, 20)
	// Keep this distribution oracle at q=1/2; planner tightness is tested
	// separately above.
	spec.StopNumerator = 128
	const samples = 12000
	var sum, sumSquares float64
	for i := 0; i < samples; i++ {
		gSeed := sha256.Sum256([]byte("distribution-g/" + strconv.Itoa(i)))
		eSeed := sha256.Sum256([]byte("distribution-e/" + strconv.Itoa(i)))
		spec.GarblerSeedCommitment = jointDPSeedCommitment(
			spec.GarblerCommitmentContext, gSeed)
		spec.EvaluatorSeedCommitment = jointDPSeedCommitment(
			spec.EvaluatorCommitmentContext, eSeed)
		noise, err := jointDPReferenceNoise(spec, gSeed, eSeed)
		if err != nil {
			t.Fatal(err)
		}
		value := float64(noise[0])
		sum += value
		sumSquares += value * value
	}
	mean := sum / samples
	variance := sumSquares/samples - mean*mean
	// For q=1/2 the untruncated difference has mean 0 and variance 4.
	// L=20 changes this by less than the sampling tolerance below.
	if math.Abs(mean) > 0.08 || math.Abs(variance-4) > 0.25 {
		t.Fatalf("unexpected sampler moments: mean=%g variance=%g", mean, variance)
	}
}

func TestJointDPLaplaceRepresentativeCostBudgets(t *testing.T) {
	for _, workload := range []struct {
		name        string
		sensitivity string
		coordinates int
		available   bool
	}{
		{"Count", "1", 1, true},
		{"MeanVar", "2", 3, true},
		{"Describe", "2", 8, true},
		{"Survival", "2", 20, true},
		{"FineGridSensitivity", "65536", 3, false},
	} {
		t.Run(workload.name, func(t *testing.T) {
			plan, err := jointDPPlanLaplace(jointDPLaplacePlanInput{
				Epsilon: ".5", Delta: "1e-6",
				SensitivitySteps: workload.sensitivity,
				CoordinateCount:  workload.coordinates, BernoulliBits: 8,
			})
			if workload.available {
				if err != nil || plan.AESBlocks > jointDPMaxAESBlocks {
					t.Fatalf("representative budget unexpectedly unavailable: %#v %v", plan, err)
				}
				if plan.CapabilityAvailable {
					t.Fatal("cost feasibility incorrectly promoted the release capability")
				}
			} else if err == nil {
				t.Fatalf("unsafe high-sensitivity budget was accepted: %#v", plan)
			}
		})
	}
}

func validityMaskToBit(value bool) int {
	if value {
		return 1
	}
	return 0
}

func jointDPTestSession(spec jointDPGCLaplaceSpec, tag string) exactGCSession {
	sid := sha256.Sum256([]byte("joint-DP session/" + tag))
	master := sha256.Sum256([]byte("joint-DP test master/" + tag))
	return exactGCSession{
		SessionID: sid, MasterKey: master,
		GarblerID: "peer-a-pinned-key", EvaluatorID: "peer-b-pinned-key",
		Purpose: spec.purpose(), Spec: exactGCCircuitSpec{
			Operation: exactGCJointDPLaplace, RingBits: spec.RingBits,
			FracBits: spec.FracBits, VectorLen: spec.CoordinateCount,
		},
	}
}

func jointDPTestProtocol(t *testing.T, spec jointDPGCLaplaceSpec,
	garblerSeed, evaluatorSeed [32]byte, a, b []*big.Int,
	tag string) ([]*big.Int, []*big.Int) {
	t.Helper()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	session := jointDPTestSession(spec, tag)
	type outcome struct {
		shares []*big.Int
		err    error
	}
	gdone := make(chan outcome, 1)
	go func() {
		shares, err := jointDPGCRunGarbler(left, session, spec, a, garblerSeed)
		gdone <- outcome{shares, err}
	}()
	eShares, eErr := jointDPGCRunEvaluator(
		right, session, spec, b, evaluatorSeed)
	if eErr != nil {
		t.Fatalf("evaluator: %v", eErr)
	}
	select {
	case result := <-gdone:
		if result.err != nil {
			t.Fatalf("garbler: %v", result.err)
		}
		return result.shares, eShares
	case <-time.After(30 * time.Second):
		t.Fatal("joint-DP garbler did not complete")
	}
	return nil, nil
}

func TestJointDPGCRealProtocolReplayIsByteIdentical(t *testing.T) {
	if testing.Short() {
		t.Skip("real KOS/garbled-circuit protocol")
	}
	spec, garblerSeed, evaluatorSeed := jointDPTestSpec(t, 63, 20, 1, 1)
	scale := new(big.Int).Lsh(big.NewInt(1), 20)
	value := new(big.Int).Mul(big.NewInt(7), scale)
	a := []*big.Int{big.NewInt(912345)}
	b := []*big.Int{new(big.Int).Mod(new(big.Int).Sub(value, a[0]), exactGCModulus(63))}
	g1, e1 := jointDPTestProtocol(t, spec, garblerSeed, evaluatorSeed, a, b, "first")
	g2, e2 := jointDPTestProtocol(t, spec, garblerSeed, evaluatorSeed, a, b, "retry")
	for i := range g1 {
		if g1[i].Cmp(g2[i]) != 0 || e1[i].Cmp(e2[i]) != 0 {
			t.Fatal("a retry under a fresh transport session changed deterministic output shares")
		}
	}
	if g1[1].Bit(0)^e1[1].Bit(0) != 1 {
		t.Fatal("validity shares did not reconstruct true")
	}
	opened := exactGCReferenceReconstruct(g1[0], e1[0], 63)
	noise, err := jointDPReferenceNoise(spec, garblerSeed, evaluatorSeed)
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Add(value, new(big.Int).Mul(big.NewInt(noise[0]), scale))
	want.Mod(want, exactGCModulus(63))
	if opened.Cmp(want) != 0 {
		t.Fatalf("opened payload=%s, want=%s", opened, want)
	}
}

func TestJointDPGCRejectsWrongSeedContextAndBounds(t *testing.T) {
	spec, _, evaluatorSeed := jointDPTestSpec(t, 63, 20, 1, 2)
	wrongSeed := evaluatorSeed
	wrongSeed[0] ^= 1
	session := jointDPTestSession(spec, "wrong-seed")
	if _, err := jointDPGCRunEvaluator(bytes.NewBuffer(nil), session, spec,
		[]*big.Int{big.NewInt(0)}, wrongSeed); err == nil {
		t.Fatal("wrong private seed was accepted")
	}
	wrongPurpose := session
	wrongPurpose.Purpose = spec.purpose() + "/tampered"
	if err := jointDPValidateSession(wrongPurpose, spec); err == nil {
		t.Fatal("wrong purpose context was accepted")
	}
	badBounds := spec
	badBounds.EncodedUpper = exactGCMaxSigned(63)
	if err := badBounds.validate(); err == nil {
		t.Fatal("bounds without worst-case noise headroom were accepted")
	}
	policy := jointDPTestWorkerPolicy(t, spec)
	policy.CircuitDigest = string(bytes.Repeat([]byte{'0'}, 64))
	config := exactGCWorkerConfig{
		JointDP:     &policy,
		PrivateSeed: base64.StdEncoding.EncodeToString(evaluatorSeed[:]),
	}
	if _, _, err := jointDPGCWorkerInputs(config, session); err == nil {
		t.Fatal("tampered circuit digest was accepted by the worker")
	}
}

func jointDPTestWorkerPolicy(t *testing.T, spec jointDPGCLaplaceSpec) jointDPGCWorkerPolicy {
	t.Helper()
	plan, err := jointDPPlanLaplace(jointDPLaplacePlanInput{
		Epsilon: "1", Delta: ".5",
		SensitivitySteps: spec.SensitivitySteps.String(),
		CoordinateCount:  spec.CoordinateCount,
		BernoulliBits:    spec.BernoulliBits, MaxSteps: spec.MaxGeometricSteps,
	})
	if err != nil || plan.MaxGeometricSteps != spec.MaxGeometricSteps ||
		plan.StopNumerator != specStopString(spec) {
		t.Fatalf("test spec is not a certified minimal plan: %#v err=%v", plan, err)
	}
	digest := spec.digest()
	return jointDPGCWorkerPolicy{
		Version: jointDPGCTemplateVersion, Sampler: jointDPSamplerVersion,
		BernoulliBits:     spec.BernoulliBits,
		StopNumerator:     specStopString(spec),
		MaxGeometricSteps: spec.MaxGeometricSteps,
		SensitivitySteps:  spec.SensitivitySteps.String(),
		Epsilon:           "1",
		AllocatedDelta:    ".5",
		EncodedLower:      spec.EncodedLower.String(), EncodedUpper: spec.EncodedUpper.String(),
		TranscriptHash:                 hex.EncodeToString(spec.TranscriptHash[:]),
		GarblerCommitmentContext:       hex.EncodeToString(spec.GarblerCommitmentContext[:]),
		EvaluatorCommitmentContext:     hex.EncodeToString(spec.EvaluatorCommitmentContext[:]),
		GarblerSeedCommitment:          hex.EncodeToString(spec.GarblerSeedCommitment[:]),
		EvaluatorSeedCommitment:        hex.EncodeToString(spec.EvaluatorSeedCommitment[:]),
		CircuitDigest:                  hex.EncodeToString(digest[:]),
		ImplementationDeltaNumerator:   plan.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator: plan.ImplementationDeltaDenom,
	}
}

func specStopString(spec jointDPGCLaplaceSpec) string {
	return new(big.Int).SetUint64(uint64(spec.StopNumerator)).String()
}

func jointDPTestRunWorkers(t *testing.T, spec jointDPGCLaplaceSpec,
	garblerSeed, evaluatorSeed [32]byte, a, b []*big.Int,
	tag string) (exactGCWorkerResult, exactGCWorkerResult, string, string) {
	t.Helper()
	gDir := exactGCTestSpool(t, "joint-g-"+tag)
	eDir := exactGCTestSpool(t, "joint-e-"+tag)
	sid := sha256.Sum256([]byte("joint-worker-session/" + tag))
	master := sha256.Sum256([]byte("joint-worker-master/" + tag))
	workerSpec := exactGCCircuitSpec{
		Operation: exactGCJointDPLaplace, RingBits: spec.RingBits,
		FracBits: spec.FracBits, VectorLen: spec.CoordinateCount,
	}
	policy := jointDPTestWorkerPolicy(t, spec)
	base := exactGCWorkerConfig{
		Version:     exactGCWorkerConfigVersion,
		SessionID:   hex.EncodeToString(sid[:]),
		MasterKey:   base64.StdEncoding.EncodeToString(master[:]),
		GarblerID:   "dsv1_" + string(bytes.Repeat([]byte{'a'}, 64)),
		EvaluatorID: "dsv1_" + string(bytes.Repeat([]byte{'b'}, 64)),
		Purpose:     spec.purpose(), Operation: string(exactGCJointDPLaplace),
		RingBits: spec.RingBits, FracBits: spec.FracBits,
		VectorLen: spec.CoordinateCount, MaxSpoolBytes: 64 << 20,
		TTLSeconds: 30, JointDP: &policy,
	}
	gCfg := base
	gCfg.Role, gCfg.SpoolDir = "garbler", gDir
	gCfg.PrivateSeed = base64.StdEncoding.EncodeToString(garblerSeed[:])
	gCfg.SourceShare = exactGCTestEncodeSource(t, a, workerSpec)
	eCfg := base
	eCfg.Role, eCfg.SpoolDir = "evaluator", eDir
	eCfg.PrivateSeed = base64.StdEncoding.EncodeToString(evaluatorSeed[:])
	eCfg.SourceShare = exactGCTestEncodeSource(t, b, workerSpec)
	gPath := exactGCTestWriteConfig(t, gDir, gCfg)
	ePath := exactGCTestWriteConfig(t, eDir, eCfg)
	errs := make(chan error, 2)
	go func() { errs <- handleExactGCWorker(gPath) }()
	go func() { errs <- handleExactGCWorker(ePath) }()
	gOffset, eOffset := int64(0), int64(0)
	deadline := time.Now().Add(30 * time.Second)
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
		t.Fatal("joint-DP workers did not complete")
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("joint-DP worker failed: %v", err)
		}
	}
	return exactGCTestReadResult(t, gDir), exactGCTestReadResult(t, eDir),
		gPath, ePath
}

func TestJointDPGCDurableWorkersDeleteSeedsAndReplayExactly(t *testing.T) {
	if testing.Short() {
		t.Skip("real worker/spool KOS protocol")
	}
	spec, garblerSeed, evaluatorSeed := jointDPTestSpec(t, 63, 20, 1, 2)
	value := new(big.Int).Lsh(big.NewInt(9), 20)
	a := []*big.Int{big.NewInt(424242)}
	b := []*big.Int{new(big.Int).Mod(new(big.Int).Sub(value, a[0]), exactGCModulus(63))}
	g1, e1, gPath, ePath := jointDPTestRunWorkers(
		t, spec, garblerSeed, evaluatorSeed, a, b, "one")
	for _, path := range []string{gPath, ePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("sensitive worker config survived startup: %s", path)
		}
	}
	if g1.Kind != "joint-dp-ring-share-v2" || e1.Kind != g1.Kind ||
		g1.ContextHash != e1.ContextHash {
		t.Fatalf("invalid joint-DP worker results: %#v %#v", g1, e1)
	}
	g2, e2, _, _ := jointDPTestRunWorkers(
		t, spec, garblerSeed, evaluatorSeed, a, b, "two")
	if g1.Share != g2.Share || e1.Share != e2.Share ||
		g1.ValidityShare != g2.ValidityShare ||
		e1.ValidityShare != e2.ValidityShare {
		t.Fatal("durable worker replay changed deterministic DP shares")
	}
}

func TestJointDPGCTwoOSProcessWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("two packaged-runtime processes")
	}
	for _, tc := range []struct {
		name     string
		ringBits int
		fracBits int
	}{
		{name: "Ring63", ringBits: 63, fracBits: 20},
		{name: "Ring127", ringBits: 127, fracBits: 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jointDPTestTwoOSProcessWorkers(t, tc.ringBits, tc.fracBits)
		})
	}
}

func jointDPTestTwoOSProcessWorkers(t *testing.T, ringBits, fracBits int) {
	t.Helper()
	platform := runtime.GOOS + "-" + runtime.GOARCH
	binaryName := "dsvert-mpc"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binary, err := filepath.Abs(filepath.Join("..", "bin", platform, binaryName))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() {
		t.Skip("packaged runtime for this platform is unavailable")
	}
	spec, garblerSeed, evaluatorSeed := jointDPTestSpec(t, ringBits, fracBits, 1, 2)
	value := new(big.Int).Lsh(big.NewInt(11), uint(fracBits))
	a := []*big.Int{big.NewInt(7654321)}
	b := []*big.Int{new(big.Int).Mod(new(big.Int).Sub(value, a[0]),
		exactGCModulus(ringBits))}
	gDir := exactGCTestSpool(t, "joint-process-g")
	eDir := exactGCTestSpool(t, "joint-process-e")
	sid := sha256.Sum256([]byte("joint-process-session"))
	master := sha256.Sum256([]byte("joint-process-master"))
	workerSpec := exactGCCircuitSpec{
		Operation: exactGCJointDPLaplace, RingBits: ringBits,
		FracBits: fracBits, VectorLen: 1,
	}
	policy := jointDPTestWorkerPolicy(t, spec)
	base := exactGCWorkerConfig{
		Version:     exactGCWorkerConfigVersion,
		SessionID:   hex.EncodeToString(sid[:]),
		MasterKey:   base64.StdEncoding.EncodeToString(master[:]),
		GarblerID:   "dsv1_" + string(bytes.Repeat([]byte{'a'}, 64)),
		EvaluatorID: "dsv1_" + string(bytes.Repeat([]byte{'b'}, 64)),
		Purpose:     spec.purpose(), Operation: string(exactGCJointDPLaplace),
		RingBits: ringBits, FracBits: fracBits, VectorLen: 1,
		MaxSpoolBytes: 64 << 20, TTLSeconds: 30, JointDP: &policy,
	}
	gConfig := base
	gConfig.Role, gConfig.SpoolDir = "garbler", gDir
	gConfig.PrivateSeed = base64.StdEncoding.EncodeToString(garblerSeed[:])
	gConfig.SourceShare = exactGCTestEncodeSource(t, a, workerSpec)
	eConfig := base
	eConfig.Role, eConfig.SpoolDir = "evaluator", eDir
	eConfig.PrivateSeed = base64.StdEncoding.EncodeToString(evaluatorSeed[:])
	eConfig.SourceShare = exactGCTestEncodeSource(t, b, workerSpec)
	gPath := exactGCTestWriteConfig(t, gDir, gConfig)
	ePath := exactGCTestWriteConfig(t, eDir, eConfig)
	var gLog, eLog bytes.Buffer
	runtimeTemp := t.TempDir()
	t.Setenv("TMPDIR", runtimeTemp)
	gCmd := exec.Command(binary, "exact-gc-worker", gPath)
	eCmd := exec.Command(binary, "exact-gc-worker", ePath)
	gCmd.Stdout, gCmd.Stderr = &gLog, &gLog
	eCmd.Stdout, eCmd.Stderr = &eLog, &eLog
	if err := gCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gCmd.Process.Kill() }()
	if err := eCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = eCmd.Process.Kill() }()
	gOffset, eOffset := int64(0), int64(0)
	deadline := time.Now().Add(45 * time.Second)
	for !exactGCTestBothDone(gDir, eDir) && time.Now().Before(deadline) {
		gOffset = exactGCTestRelaySpool(t, gDir, eDir, gOffset)
		eOffset = exactGCTestRelaySpool(t, eDir, gDir, eOffset)
		now := time.Now()
		for _, dir := range []string{gDir, eDir} {
			if err := os.Chtimes(filepath.Join(dir, "exchange.hb"), now, now); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Millisecond)
	}
	if !exactGCTestBothDone(gDir, eDir) {
		t.Fatalf("two-process workers timed out; garbler=%s evaluator=%s",
			gLog.String(), eLog.String())
	}
	if err := gCmd.Wait(); err != nil {
		t.Fatalf("garbler process: %v: %s", err, gLog.String())
	}
	if err := eCmd.Wait(); err != nil {
		t.Fatalf("evaluator process: %v: %s", err, eLog.String())
	}
	gResult := exactGCTestReadResult(t, gDir)
	eResult := exactGCTestReadResult(t, eDir)
	if gResult.Kind != "joint-dp-ring-share-v2" ||
		eResult.Kind != gResult.Kind || gResult.ContextHash != eResult.ContextHash {
		t.Fatalf("invalid two-process result: %#v %#v", gResult, eResult)
	}
	if _, err := os.Stat(gPath); !os.IsNotExist(err) {
		t.Fatal("garbler process retained its seed-bearing config")
	}
	if _, err := os.Stat(ePath); !os.IsNotExist(err) {
		t.Fatal("evaluator process retained its seed-bearing config")
	}
	matches, err := filepath.Glob(filepath.Join(runtimeTemp, "dsvert-mpcl-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("two-process workers leaked private MPCL runtime: %v %v",
			matches, err)
	}
}
