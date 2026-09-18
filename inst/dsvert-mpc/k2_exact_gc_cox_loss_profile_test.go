package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"os"
	"reflect"
	"testing"
)

type coxProfileFixture struct {
	Profile           map[string]interface{} `json:"profile"`
	ProfileSHA256     string                 `json:"profile_sha256"`
	Certificate       map[string]interface{} `json:"certificate"`
	CertificateSHA256 string                 `json:"certificate_sha256"`
	ExpCases          []struct {
		Eta int32  `json:"eta_q16"`
		Exp uint32 `json:"exp_q20"`
	} `json:"exp_cases"`
	LogCases []struct {
		Risk int64 `json:"risk_q20"`
		Log  int64 `json:"log_q20"`
	} `json:"log_cases"`
}

func coxReadProfileFixture(t *testing.T) coxProfileFixture {
	t.Helper()
	data, err := os.ReadFile("../cross-cox-v1/numeric_cox_profile_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture coxProfileFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestCoxGridCrossProfileHashesAndKnots(t *testing.T) {
	f := coxReadProfileFixture(t)
	for _, pair := range []struct {
		value interface{}
		got   string
		want  string
	}{
		{f.Profile, f.ProfileSHA256, CoxGridCrossProfileSHA256},
		{f.Certificate, f.CertificateSHA256, CoxGridCrossCertificateSHA256},
	} {
		encoded, err := json.Marshal(pair.value)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		if pair.got != pair.want || pair.got != hex.EncodeToString(digest[:]) {
			t.Fatal("Cox profile or certificate hash differs")
		}
	}
	var knots struct {
		Exp [65]uint32 `json:"exp_knots_q20"`
		Log [65]int32  `json:"log_knots_q20"`
		Ln2 int64      `json:"ln2_q20"`
	}
	encoded, _ := json.Marshal(f.Profile)
	if err := json.Unmarshal(encoded, &knots); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(knots.Exp, CoxGridCrossExpKnotsQ20) || !reflect.DeepEqual(knots.Log, CoxGridCrossLogKnotsQ20) || knots.Ln2 != CoxGridCrossLn2Q20 {
		t.Fatal("Cox code constants differ from the interval-generated profile")
	}
}

func TestCoxGridCrossProfileIntegerBoundaryFixtures(t *testing.T) {
	f := coxReadProfileFixture(t)
	for _, c := range f.ExpCases {
		got, err := CoxGridCrossExpProfileQ16(c.Eta)
		if err != nil || got != c.Exp {
			t.Fatalf("exp profile boundary eta=%d: got=%d want=%d err=%v", c.Eta, got, c.Exp, err)
		}
	}
	for _, c := range f.LogCases {
		got, err := CoxGridCrossLogProfileQ20(big.NewInt(c.Risk))
		if err != nil || got != c.Log {
			t.Fatalf("log profile boundary risk=%d: got=%d want=%d err=%v", c.Risk, got, c.Log, err)
		}
	}
}

func TestCoxGridCrossExpProfileExhaustiveQ16(t *testing.T) {
	maximum, last := 0.0, uint32(0)
	for eta := int32(-524288); eta <= 524288; eta++ {
		got, err := CoxGridCrossExpProfileQ16(eta)
		if err != nil || got == 0 || got < last {
			t.Fatalf("exp positivity/monotonicity eta=%d", eta)
		}
		last = got
		real := math.Exp(float64(eta) / 65536)
		relative := math.Abs(float64(got)/1048576-real) / real
		maximum = math.Max(maximum, relative)
		if relative >= CoxGridCrossExpRelativeError {
			t.Fatalf("exp certified relative error eta=%d: %.12g", eta, relative)
		}
	}
	t.Logf("all 1,048,577 q16 inputs: maximum relative exp error %.12g < %.4g", maximum, CoxGridCrossExpRelativeError)
}

func TestCoxGridCrossLogProfileDenseNormalizationAndSlack(t *testing.T) {
	maximum := 0.0
	check := func(risk int64) {
		if risk < 352 || risk > CoxGridCrossRiskMaxQ20 {
			return
		}
		got, err := CoxGridCrossLogProfileQ20(big.NewInt(risk))
		if err != nil {
			t.Fatal(err)
		}
		difference := math.Abs(float64(got)/1048576 - math.Log(float64(risk)/1048576))
		maximum = math.Max(maximum, difference)
		if difference >= CoxGridCrossLogAbsoluteError {
			t.Fatalf("log certified absolute error risk=%d: %.12g", risk, difference)
		}
	}
	// Every small prefix integer, every mantissa piece at 1/128 density, and
	// both ends of every normalization floor cell across all certified powers.
	for risk := int64(352); risk < 1048576; risk++ {
		check(risk)
	}
	for exponent := uint(0); exponent <= 24; exponent++ {
		for mantissa := int64(1048576); mantissa < 2097152; mantissa += 128 {
			check(mantissa << exponent)
			check(((mantissa + 1) << exponent) - 1)
		}
	}
	check(CoxGridCrossRiskMaxQ20)
	t.Logf("dense log maximum absolute error %.12g < %.5g", maximum, CoxGridCrossLogAbsoluteError)
}

func TestCoxGridCrossProfileDomainsFailClosed(t *testing.T) {
	for _, eta := range []int32{-524289, 524289, math.MinInt32, math.MaxInt32} {
		if _, err := CoxGridCrossExpProfileQ16(eta); err == nil || err.Error() != "cox profile input rejected" {
			t.Fatal("uncertified exp input accepted or error not transcript-safe")
		}
	}
	for _, risk := range []*big.Int{nil, big.NewInt(-1), big.NewInt(0), big.NewInt(351), big.NewInt(CoxGridCrossRiskMaxQ20 + 1), new(big.Int).Lsh(big.NewInt(1), 80)} {
		if _, err := CoxGridCrossLogProfileQ20(risk); err == nil || err.Error() != "cox profile input rejected" {
			t.Fatal("uncertified log input accepted or error not transcript-safe")
		}
	}
}

func TestCoxGridCrossProfileAnalyticErrorAndWidths(t *testing.T) {
	rho := big.NewRat(144, 10000)
	eta := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 17))
	eta.Add(eta, new(big.Rat).SetFrac(big.NewInt(24), new(big.Int).Lsh(big.NewInt(1), 51)))
	eta.Add(eta, new(big.Rat).SetFrac(big.NewInt(16), new(big.Int).Lsh(big.NewInt(1), 102)))
	event := new(big.Rat).Mul(eta, big.NewRat(2, 1))
	event.Add(event, new(big.Rat).Quo(rho, new(big.Rat).Sub(big.NewRat(1, 1), rho)))
	event.Add(event, big.NewRat(6, 100000))
	if event.Cmp(big.NewRat(1, 64)) >= 0 || CoxGridCrossEventErrorQ24 != (1<<24)/64 {
		t.Fatal("analytic event error does not fit signed 1/64 budget")
	}
	for i := 0; i < 64; i++ {
		expProduct := uint64(CoxGridCrossExpKnotsQ20[i+1]-CoxGridCrossExpKnotsQ20[i]) * 16383
		logProduct := uint64(CoxGridCrossLogKnotsQ20[i+1]-CoxGridCrossLogKnotsQ20[i]) * 16383
		if expProduct >= 1<<44 || logProduct >= 1<<28 {
			t.Fatal("interpolation raw product exceeds certified width")
		}
	}
	if 10000*int64(CoxGridCrossExpKnotsQ20[64]) != CoxGridCrossRiskMaxQ20 || CoxGridCrossRiskMaxQ20 >= 1<<45 {
		t.Fatal("prefix accumulation width certificate differs")
	}
	// Default N=10k, A=8, J=50 with conservative whole-coordinate range
	// sensitivity. Even epsilon=8 leaves the certified error below 0.1% of
	// the Laplace noise scale; smaller epsilon only increases that margin.
	for _, epsilon := range []float64{1, 4, 8} {
		errorBudget := 10000.0 / 64
		laplaceScale := 50 * 10000 * (math.Log(10000) + 16) / epsilon
		if errorBudget >= laplaceScale/1000 {
			t.Fatal("default arithmetic error is not far below DP noise scale")
		}
	}
}
