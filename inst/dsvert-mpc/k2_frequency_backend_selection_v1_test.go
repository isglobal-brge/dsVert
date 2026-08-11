package main

import (
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func jointDPFrequencyTestInput() jointDPFrequencyBackendSelectionInput {
	return jointDPFrequencyBackendSelectionInput{
		Version:              jointDPFrequencyBackendSelectionRequestVersion,
		Adjacency:            "add_remove_patient",
		CoordinateUpperBound: "1000",
		ConvolutionRequest: jointDPVectorPlanInput{
			Epsilon: "1e+00", Delta: "1e-02", SensitivitySteps: "1",
			TotalCoordinateCount: 3,
		},
		GaussianRequest: jointDPGaussianPlanInput{
			Epsilon:              "9.9999999999997158e-01",
			Delta:                "9.9999999999997157e-03",
			L2SensitivitySteps:   "1.0000000000000284e+00",
			TotalCoordinateCount: 3,
		},
	}
}

func jointDPFrequencyTestHalfPlan(t testing.TB, alpha *big.Rat,
	dimensions, binaryBits int,
) jointDPVectorConvolutionPlanOutput {
	t.Helper()
	if alpha == nil || alpha.Sign() < 0 || alpha.Cmp(big.NewRat(1, 20)) > 0 {
		t.Fatal("invalid synthetic alpha")
	}
	tau := new(big.Rat).Sub(big.NewRat(1, 20), alpha)
	tau.Quo(tau, big.NewRat(int64(4*dimensions), 1))
	denominator := new(big.Int).Lsh(big.NewInt(1), jointDPVectorStopBits)
	stop := new(big.Int).Rsh(new(big.Int).Set(denominator), 1)
	return jointDPVectorConvolutionPlanOutput{
		jointDPVectorPlanOutput: jointDPVectorPlanOutput{
			StopBits: jointDPVectorStopBits, StopNumerator: stop.String(),
			BinaryGeometricBits:       binaryBits,
			OneGeometricTVNumerator:   tau.Num().String(),
			OneGeometricTVDenominator: tau.Denom().String(),
			TotalCoordinateCount:      dimensions, CapabilityAvailable: true,
		},
	}
}

func TestJointDPFrequencyBackendSelectionDecodeIsStrict(t *testing.T) {
	input := jointDPFrequencyTestInput()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeJointDPFrequencyBackendSelection(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("decode valid input: %v", err)
	}
	if !reflect.DeepEqual(decoded, input) {
		t.Fatalf("decoded input changed: %#v", decoded)
	}
	padded := append(append([]byte(nil), encoded...),
		[]byte(strings.Repeat(" ",
			jointDPFrequencyBackendSelectionMaxInputBytes-len(encoded)))...)
	if _, err := decodeJointDPFrequencyBackendSelection(
		strings.NewReader(string(padded))); err != nil {
		t.Fatalf("exactly 4096 bytes rejected: %v", err)
	}
	invalid := map[string]string{
		"unknown":  strings.TrimSuffix(string(encoded), "}") + `,"other":1}`,
		"source":   strings.TrimSuffix(string(encoded), "}") + `,"source":"x"}`,
		"seed":     strings.TrimSuffix(string(encoded), "}") + `,"seed":"x"}`,
		"trailing": string(encoded) + ` {}`,
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeJointDPFrequencyBackendSelection(
				strings.NewReader(value)); err == nil {
				t.Fatal("invalid selector JSON unexpectedly decoded")
			}
		})
	}
	tooLarge := strings.NewReader(strings.Repeat(" ",
		jointDPFrequencyBackendSelectionMaxInputBytes+1))
	if _, err := decodeJointDPFrequencyBackendSelection(tooLarge); err == nil ||
		!strings.Contains(err.Error(), "exceeds 4096 bytes") {
		t.Fatalf("oversize error=%v", err)
	}
}

func TestJointDPFrequencyConvolutionTailUsesStrictGreaterEvent(t *testing.T) {
	p := big.NewRat(1, 2)
	for radius, want := range map[int]*big.Rat{
		0: big.NewRat(22, 27),
		1: big.NewRat(14, 27),
		2: big.NewRat(17, 54),
		6: big.NewRat(29, 864),
	} {
		got, err := jointDPFrequencyConvolutionTail(p, radius)
		if err != nil {
			t.Fatal(err)
		}
		if got.Cmp(want) != 0 {
			t.Fatalf("P(|X1+X2|>%d)=%s, want %s", radius, got, want)
		}
	}
}

func TestJointDPFrequencyConvolutionRadiusChargesFourGeometricVariables(t *testing.T) {
	// At p=1/2, alpha=.05 gives r=6. Charging eta=4*tau with
	// tau=.005 leaves alpha=.03 and moves the minimum to r=7; a factor-two
	// bug would incorrectly leave r=6.
	plan := jointDPFrequencyTestHalfPlan(t, big.NewRat(3, 100), 1, 63)
	certificate, err := jointDPFrequencyConvolutionAccuracy(plan)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Simultaneous95Abs != "7" ||
		certificate.ReleaseTVUpperNumerator != "1" ||
		certificate.ReleaseTVUpperDenominator != "50" ||
		certificate.Method != jointDPFrequencyExactTailMethod {
		t.Fatalf("wrong four-geometric certificate: %#v", certificate)
	}
}

func TestJointDPFrequencyExactSearchCapBoundary(t *testing.T) {
	p := big.NewRat(1, 2)
	for _, target := range []int{
		jointDPFrequencyExactRadiusCap - 1,
		jointDPFrequencyExactRadiusCap,
		jointDPFrequencyExactRadiusCap + 1,
	} {
		t.Run(new(big.Int).SetInt64(int64(target)).String(), func(t *testing.T) {
			alpha, err := jointDPFrequencyConvolutionTail(p, target)
			if err != nil {
				t.Fatal(err)
			}
			plan := jointDPFrequencyTestHalfPlan(t, alpha, 1, 63)
			certificate, err := jointDPFrequencyConvolutionAccuracy(plan)
			if err != nil {
				t.Fatal(err)
			}
			if target <= jointDPFrequencyExactRadiusCap {
				if certificate.Simultaneous95Abs != new(big.Int).
					SetInt64(int64(target)).String() ||
					certificate.Method != jointDPFrequencyExactTailMethod {
					t.Fatalf("target %d did not use exact search: %#v",
						target, certificate)
				}
			} else if certificate.Method != jointDPFrequencyEnvelopeMethod ||
				certificate.Simultaneous95Abs == "" {
				t.Fatalf("target %d did not cross resource cap: %#v",
					target, certificate)
			}
		})
	}
}

func TestJointDPFrequencyEnvelopeIsExactAndSupportBounded(t *testing.T) {
	// q=s/D=1/2 and alpha=3/64 give k=7 and
	// n=ceil(21*k*D/(20*s))=15, hence r=14.
	for _, test := range []struct {
		support  string
		want     string
		fallback bool
	}{
		{support: "13", want: "13", fallback: true},
		{support: "14", want: "14", fallback: true},
		{support: "15", want: "14", fallback: false},
	} {
		radius, fallback, err := jointDPFrequencyEnvelopeRadius(
			big.NewInt(1), big.NewInt(2), big.NewRat(3, 64), 1,
			jointDPFrequencyMustInt(t, test.support))
		if err != nil {
			t.Fatal(err)
		}
		if radius.String() != test.want || fallback != test.fallback {
			t.Fatalf("support=%s: radius=%s fallback=%v, want %s/%v",
				test.support, radius, fallback, test.want, test.fallback)
		}
	}
}

func jointDPFrequencyMustInt(t testing.TB, value string) *big.Int {
	t.Helper()
	result, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatal("bad test integer")
	}
	return result
}

func TestJointDPFrequencyAlphaAndBinarySupportEdges(t *testing.T) {
	zeroAlpha := jointDPFrequencyTestHalfPlan(t, new(big.Rat), 1, 63)
	zeroCertificate, err := jointDPFrequencyConvolutionAccuracy(zeroAlpha)
	if err != nil {
		t.Fatal(err)
	}
	wantJ63 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64),
		big.NewInt(2)).String()
	if zeroCertificate.Method != jointDPFrequencySupportMethod ||
		zeroCertificate.Simultaneous95Abs != wantJ63 {
		t.Fatalf("alpha=0 did not use J=63 support: %#v", zeroCertificate)
	}

	j1 := jointDPFrequencyTestHalfPlan(t, big.NewRat(1, 20), 1, 1)
	j1Certificate, err := jointDPFrequencyConvolutionAccuracy(j1)
	if err != nil {
		t.Fatal(err)
	}
	if j1Certificate.AbsoluteSupport != "2" ||
		j1Certificate.Simultaneous95Abs != "2" ||
		j1Certificate.Method != jointDPFrequencySupportMethod {
		t.Fatalf("J=1 support is wrong: %#v", j1Certificate)
	}

	j63 := jointDPFrequencyTestHalfPlan(t, big.NewRat(1, 20), 1, 63)
	j63Certificate, err := jointDPFrequencyConvolutionAccuracy(j63)
	if err != nil {
		t.Fatal(err)
	}
	if j63Certificate.AbsoluteSupport != wantJ63 ||
		j63Certificate.Simultaneous95Abs != "6" ||
		j63Certificate.Method != jointDPFrequencyExactTailMethod {
		t.Fatalf("J=63 exact radius is wrong: %#v", j63Certificate)
	}
	quantum := new(big.Rat).SetFrac(big.NewInt(1),
		new(big.Int).Lsh(big.NewInt(1), 8192))
	quantumPlan := jointDPFrequencyTestHalfPlan(t, quantum, 1, 63)
	quantumCertificate, err := jointDPFrequencyConvolutionAccuracy(quantumPlan)
	if err != nil {
		t.Fatal(err)
	}
	if quantumCertificate.Method != jointDPFrequencyEnvelopeMethod ||
		quantumCertificate.Simultaneous95Abs == quantumCertificate.AbsoluteSupport {
		t.Fatalf("one positive alpha quantum was treated as exhausted: %#v",
			quantumCertificate)
	}
}

func TestJointDPFrequencyPublishedTVIsCappedAndCertificateIsCompact(t *testing.T) {
	plan := jointDPFrequencyTestHalfPlan(t, new(big.Rat), 1, 63)
	plan.OneGeometricTVNumerator = "1"
	plan.OneGeometricTVDenominator = "1"
	certificate, err := jointDPFrequencyConvolutionAccuracy(plan)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.ReleaseTVUpperNumerator != "1" ||
		certificate.ReleaseTVUpperDenominator != "1" ||
		certificate.Method != jointDPFrequencySupportMethod {
		t.Fatalf("uncapped release TV certificate: %#v", certificate)
	}
	encoded, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	for _, derived := range []string{"continuation_probability", "one_geometric_tv",
		"minimal_under", "support_fallback", "no_wrap_certified"} {
		if strings.Contains(string(encoded), derived) {
			t.Fatalf("derived field %q leaked into compact certificate: %s",
				derived, encoded)
		}
	}
}

func TestJointDPFrequencyNoWrapUsesSupportNotR95(t *testing.T) {
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127),
		big.NewInt(1))
	support := big.NewInt(14)
	if !jointDPFrequencyNoWrap(new(big.Int).Sub(new(big.Int).Set(maximum), support),
		support) {
		t.Fatal("exact support boundary rejected")
	}
	if jointDPFrequencyNoWrap(new(big.Int).Add(
		new(big.Int).Sub(new(big.Int).Set(maximum), support), big.NewInt(1)),
		support) {
		t.Fatal("support boundary plus one accepted")
	}
	if jointDPFrequencyNoWrap(big.NewInt(-1), support) ||
		jointDPFrequencyNoWrap(big.NewInt(0), big.NewInt(-1)) {
		t.Fatal("negative headroom input accepted")
	}
}

func TestJointDPFrequencyPureSelectionWinsAndTie(t *testing.T) {
	if got := jointDPFrequencyChoose(big.NewInt(8), big.NewInt(9)); got != jointDPVectorConvolutionBackend {
		t.Fatalf("convolution win selected %q", got)
	}
	if got := jointDPFrequencyChoose(big.NewInt(9), big.NewInt(8)); got != jointDPGaussianBackend {
		t.Fatalf("Gaussian win selected %q", got)
	}
	if got := jointDPFrequencyChoose(big.NewInt(8), big.NewInt(8)); got != jointDPVectorConvolutionBackend {
		t.Fatalf("tie selected %q", got)
	}
}

func TestJointDPFrequencyPlanHashIsCanonicalDomainSeparatedAndTamperEvident(t *testing.T) {
	left := map[string]any{
		"z": json.Number("1"),
		"a": map[string]any{"y": "2", "x": true},
	}
	right := struct {
		A struct {
			X bool   `json:"x"`
			Y string `json:"y"`
		} `json:"a"`
		Z int `json:"z"`
	}{Z: 1}
	right.A.X, right.A.Y = true, "2"
	leftHash, err := jointDPFrequencyPlanHash(left)
	if err != nil {
		t.Fatal(err)
	}
	rightHash, err := jointDPFrequencyPlanHash(right)
	if err != nil {
		t.Fatal(err)
	}
	const golden = "d42279109b343c8beb165f9a12a9e96920c87f096b51f2af3e1d74140fe3c8dd"
	if leftHash != golden || rightHash != golden {
		t.Fatalf("canonical Frequency hash mismatch: left=%s right=%s", leftHash,
			rightHash)
	}
	left["z"] = json.Number("2")
	tampered, err := jointDPFrequencyPlanHash(left)
	if err != nil {
		t.Fatal(err)
	}
	if tampered == golden {
		t.Fatal("full-plan tamper preserved Frequency hash")
	}
	crossR, err := jointDPFrequencyPlanHash(map[string]any{
		"text": "TV<=x&a>y",
	})
	if err != nil {
		t.Fatal(err)
	}
	const crossRGolden = "c0a12b527bd5d4a9ad5cf34e2369a05ec490022bba98e8850f8d3abc944fa794"
	if crossR != crossRGolden {
		t.Fatalf("HTML-safe canonical JSON diverged from R: %s", crossR)
	}
}

func TestJointDPFrequencyCanonicalFloatPairsPointThreeAndPointZeroZeroSeven(t *testing.T) {
	if got := jointDPFrequencyCanonicalFloat(0.3); got != "2.9999999999999999e-01" {
		t.Fatalf("canonical .3=%q", got)
	}
	if got := jointDPFrequencyCanonicalFloat(0.007); got != "7.0000000000000001e-03" {
		t.Fatalf("canonical .007=%q", got)
	}
	input := jointDPFrequencyTestInput()
	input.ConvolutionRequest.Epsilon = "2.9999999999999999e-01"
	input.ConvolutionRequest.Delta = "7.0000000000000001e-03"
	input.GaussianRequest.Epsilon = "2.9999999999999144e-01"
	input.GaussianRequest.Delta = "6.9999999999998015e-03"
	if _, err := selectJointDPFrequencyBackend(input); err != nil {
		t.Fatalf("canonical paired decimals rejected: %v", err)
	}
}

func TestJointDPFrequencyBackendSelectionBuildsBothPlansAndChoosesStrictly(t *testing.T) {
	for name, adjacency := range map[string]string{
		"add-remove":  "add_remove_patient",
		"replace-one": "replace_one_fixed_cohort",
	} {
		t.Run(name, func(t *testing.T) {
			input := jointDPFrequencyTestInput()
			input.Adjacency = adjacency
			if adjacency == "replace_one_fixed_cohort" {
				input.ConvolutionRequest.SensitivitySteps = "2"
				input.GaussianRequest.L2SensitivitySteps =
					"1.4142135623731353e+00"
			}
			output, err := selectJointDPFrequencyBackend(input)
			if err != nil {
				t.Fatal(err)
			}
			if !output.ConvolutionPlan.CapabilityAvailable ||
				!output.GaussianPlan.CapabilityAvailable ||
				output.ConvolutionCertificate.PlanSHA256 == "" ||
				output.GaussianCertificate.PlanSHA256 == "" ||
				!reflect.DeepEqual(output.Request, input) {
				t.Fatalf("incomplete oracle output: %#v", output)
			}
			convolutionRadius := jointDPFrequencyMustInt(t,
				output.ConvolutionCertificate.Simultaneous95Abs)
			gaussianRadius := jointDPFrequencyMustInt(t,
				output.GaussianCertificate.Simultaneous95Abs)
			want := jointDPFrequencyChoose(convolutionRadius, gaussianRadius)
			if output.SelectionCertificate.SelectedPrimitive != want {
				t.Fatalf("selected %q, want %q (conv=%s Gaussian=%s)",
					output.SelectionCertificate.SelectedPrimitive, want,
					output.ConvolutionCertificate.Simultaneous95Abs,
					output.GaussianCertificate.Simultaneous95Abs)
			}
			convolutionHash, err := jointDPFrequencyPlanHash(output.ConvolutionPlan)
			if err != nil || convolutionHash !=
				output.ConvolutionCertificate.PlanSHA256 {
				t.Fatalf("convolution plan hash is not bound: %s / %v",
					convolutionHash, err)
			}
			gaussianHash, err := jointDPFrequencyPlanHash(output.GaussianPlan)
			if err != nil || gaussianHash != output.GaussianCertificate.PlanSHA256 {
				t.Fatalf("Gaussian plan hash is not bound: %s / %v", gaussianHash, err)
			}
			selection := output.SelectionCertificate
			if selection.InputScope != jointDPFrequencyPublicInputScope ||
				selection.SourceMaterialConsulted ||
				selection.PrivateRandomnessConsulted ||
				selection.RuntimeFailureConsulted || selection.AutomaticFallback ||
				selection.UtilityOptimalityClaimed {
				t.Fatalf("invalid public-only selection certificate: %#v", selection)
			}
		})
	}
}

func TestJointDPFrequencyBackendSelectionFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*jointDPFrequencyBackendSelectionInput){
		"version": func(input *jointDPFrequencyBackendSelectionInput) {
			input.Version = "v2"
		},
		"dimension mismatch": func(input *jointDPFrequencyBackendSelectionInput) {
			input.GaussianRequest.TotalCoordinateCount++
		},
		"adjacency": func(input *jointDPFrequencyBackendSelectionInput) {
			input.Adjacency = "user_level"
		},
		"add-remove L1": func(input *jointDPFrequencyBackendSelectionInput) {
			input.ConvolutionRequest.SensitivitySteps = "2"
		},
		"add-remove L2": func(input *jointDPFrequencyBackendSelectionInput) {
			input.GaussianRequest.L2SensitivitySteps = "1"
		},
		"noncanonical convolution epsilon": func(input *jointDPFrequencyBackendSelectionInput) {
			input.ConvolutionRequest.Epsilon = "1.0"
		},
		"unpaired Gaussian epsilon": func(input *jointDPFrequencyBackendSelectionInput) {
			input.GaussianRequest.Epsilon = "1"
		},
		"unpaired Gaussian delta": func(input *jointDPFrequencyBackendSelectionInput) {
			input.GaussianRequest.Delta = "0.01"
		},
		"convolution planner": func(input *jointDPFrequencyBackendSelectionInput) {
			input.ConvolutionRequest.SensitivitySteps = "1.5"
		},
		"Gaussian planner": func(input *jointDPFrequencyBackendSelectionInput) {
			input.GaussianRequest.Delta = "0"
		},
		"noncanonical upper": func(input *jointDPFrequencyBackendSelectionInput) {
			input.CoordinateUpperBound = "01"
		},
		"zero upper": func(input *jointDPFrequencyBackendSelectionInput) {
			input.CoordinateUpperBound = "0"
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := jointDPFrequencyTestInput()
			mutate(&input)
			if _, err := selectJointDPFrequencyBackend(input); err == nil {
				t.Fatal("invalid oracle request unexpectedly selected a backend")
			}
		})
	}
}

func TestJointDPFrequencyBothSupportsMustNotWrap(t *testing.T) {
	input := jointDPFrequencyTestInput()
	baseline, err := selectJointDPFrequencyBackend(input)
	if err != nil {
		t.Fatal(err)
	}
	convSupport := jointDPFrequencyMustInt(t,
		baseline.ConvolutionCertificate.AbsoluteSupport)
	gaussianSupport := jointDPFrequencyMustInt(t,
		baseline.GaussianCertificate.AbsoluteSupport)
	maximumSupport := new(big.Int).Set(convSupport)
	if gaussianSupport.Cmp(maximumSupport) > 0 {
		maximumSupport.Set(gaussianSupport)
	}
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127),
		big.NewInt(1))
	input.CoordinateUpperBound = new(big.Int).Sub(
		new(big.Int).Set(maximum), maximumSupport).String()
	if _, err := selectJointDPFrequencyBackend(input); err != nil {
		t.Fatalf("both-support boundary rejected: %v", err)
	}
	upper, _ := new(big.Int).SetString(input.CoordinateUpperBound, 10)
	input.CoordinateUpperBound = upper.Add(upper, big.NewInt(1)).String()
	if _, err := selectJointDPFrequencyBackend(input); err == nil {
		t.Fatal("request wrapping either complete support unexpectedly selected")
	}
}

func TestJointDPFrequencyTinyEpsilonMillionCoordinatesIsBounded(t *testing.T) {
	input := jointDPFrequencyTestInput()
	input.CoordinateUpperBound = "1"
	input.ConvolutionRequest = jointDPVectorPlanInput{
		Epsilon: "1e-04", Delta: "1e-02", SensitivitySteps: "1",
		TotalCoordinateCount: jointDPVectorMaxTotal,
	}
	input.GaussianRequest = jointDPGaussianPlanInput{
		Epsilon:              "9.9999999999997159e-05",
		Delta:                "9.9999999999997157e-03",
		L2SensitivitySteps:   "1.0000000000000284e+00",
		TotalCoordinateCount: jointDPVectorMaxTotal,
	}
	output, err := selectJointDPFrequencyBackend(input)
	if err != nil {
		t.Fatal(err)
	}
	radius := jointDPFrequencyMustInt(t,
		output.ConvolutionCertificate.Simultaneous95Abs)
	if output.ConvolutionCertificate.Method != jointDPFrequencyEnvelopeMethod ||
		radius.Cmp(big.NewInt(jointDPFrequencyExactRadiusCap)) <= 0 {
		t.Fatalf("tiny-epsilon request did not take bounded envelope: %#v",
			output.ConvolutionCertificate)
	}
}

func TestJointDPFrequencyEnvelopeGuardsShiftBeforeAllocation(t *testing.T) {
	alpha := new(big.Rat).SetFrac(big.NewInt(1),
		new(big.Int).Lsh(big.NewInt(1), jointDPFrequencyEnvelopeMaxShift+1))
	radius, fallback, err := jointDPFrequencyEnvelopeRadius(
		big.NewInt(1), big.NewInt(2), alpha, 1, big.NewInt(100))
	if err != nil {
		t.Fatal(err)
	}
	if !fallback || radius.String() != "100" {
		t.Fatalf("oversize k did not fail safely to support: %s/%v",
			radius, fallback)
	}
}

func TestJointDPFrequencyRejectsInvalidProbabilityAndRadius(t *testing.T) {
	for name, test := range map[string]struct {
		p      *big.Rat
		radius int
	}{
		"nil p":           {p: nil, radius: 0},
		"zero p":          {p: new(big.Rat), radius: 0},
		"unit p":          {p: big.NewRat(1, 1), radius: 0},
		"negative radius": {p: big.NewRat(1, 2), radius: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := jointDPFrequencyConvolutionTail(
				test.p, test.radius); err == nil {
				t.Fatal("invalid tail request unexpectedly accepted")
			}
		})
	}
	plan := jointDPFrequencyTestHalfPlan(t, big.NewRat(1, 20), 1, 63)
	plan.StopNumerator = "0"
	if _, err := jointDPFrequencyConvolutionAccuracy(plan); err == nil {
		t.Fatal("invalid continuation probability unexpectedly certified")
	}
}
