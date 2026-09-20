package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"reflect"
	"testing"
)

func TestCrossGridV1SignedRContractStructRoundTrip(t *testing.T) {
	data, err := os.ReadFile("../cross-grid-v1/public_contract_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract CrossGridSignedContractV1
	decode := func(data []byte, value *CrossGridSignedContractV1) error {
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if err := d.Decode(value); err != nil {
			return err
		}
		var extra interface{}
		if err := d.Decode(&extra); err != io.EOF {
			return fmt.Errorf("invalid trailing contract data")
		}
		return nil
	}
	if err := decode(data, &contract); err != nil {
		t.Fatal(err)
	}
	if err := crossGridValidateNumericContractV1(contract.Spec.Family, contract.Spec.NumericContract); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	var original, roundtrip map[string]interface{}
	if json.Unmarshal(data, &original) != nil || json.Unmarshal(encoded, &roundtrip) != nil || !reflect.DeepEqual(original, roundtrip) {
		t.Fatal("R signed ABI did not round trip")
	}
	original["spec"].(map[string]interface{})["unknown_field"] = true
	mutated, _ := json.Marshal(original)
	if decode(mutated, &contract) == nil {
		t.Fatal("unknown nested ABI field accepted")
	}
	if decode(append(data, []byte(" {}")...), &contract) == nil {
		t.Fatal("trailing ABI object accepted")
	}
}

type crossGridProfileFixtureV1 struct {
	Profile           map[string]interface{}                `json:"profile"`
	ProfileSHA256     string                                `json:"profile_sha256"`
	Certificate       map[string]interface{}                `json:"certificate"`
	CertificateSHA256 string                                `json:"certificate_sha256"`
	NumericContract   map[string]CrossGridNumericContractV1 `json:"numeric_contract"`
	ReferenceCases    []crossGridReferenceCaseV1            `json:"reference_cases"`
}

type crossGridReferenceCaseV1 struct {
	Family          string     `json:"family"`
	G               uint       `json:"g"`
	FeaturesEncoded [][]int64  `json:"features_encoded"`
	Outcomes        []int64    `json:"outcomes"`
	Validity        [][]int    `json:"validity"`
	BetaEncoded     [][]string `json:"beta_encoded"`
	Caps            []int64    `json:"caps"`
	ExpectedSums    []int64    `json:"expected_sums"`
}

func crossGridFixtureV1(t *testing.T) crossGridProfileFixtureV1 {
	t.Helper()
	data, err := os.ReadFile("../cross-grid-v1/numeric_profile_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture crossGridProfileFixtureV1
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(fixture.Profile)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if fixture.ProfileSHA256 != hex.EncodeToString(digest[:]) || fixture.ProfileSHA256 != CrossGridProfileSHA256V1 {
		t.Fatal("profile hash differs")
	}
	encoded, err = json.Marshal(fixture.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	digest = sha256.Sum256(encoded)
	if fixture.CertificateSHA256 != hex.EncodeToString(digest[:]) || fixture.CertificateSHA256 != CrossGridCertificateSHA256V1 {
		t.Fatal("certificate hash differs")
	}
	return fixture
}

func crossGridIntegerV1(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid reference integer")
	}
	return v
}

func crossGridCoefficientsV1(f crossGridProfileFixtureV1, field string) []*big.Int {
	a := f.Profile[field].([]interface{})
	out := make([]*big.Int, len(a))
	for i, v := range a {
		out[i] = crossGridIntegerV1(v.(string))
	}
	return out
}

// Every integer circuit operation checks its signed 192-bit width. Values are
// test-only cleartext mathematical references, never production source data.
func crossGridWidthV1(v *big.Int, bits int) *big.Int {
	if v.BitLen() >= bits {
		panic("reference width exceeded")
	}
	return v
}

func crossGridAddV1(a, b *big.Int) *big.Int { return crossGridWidthV1(new(big.Int).Add(a, b), 192) }
func crossGridSubV1(a, b *big.Int) *big.Int { return crossGridWidthV1(new(big.Int).Sub(a, b), 192) }
func crossGridMulV1(a, b *big.Int) *big.Int { return crossGridWidthV1(new(big.Int).Mul(a, b), 192) }
func crossGridPow2V1(n uint) *big.Int       { return new(big.Int).Lsh(big.NewInt(1), n) }

func crossGridRoundDivV1(value, divisor *big.Int) *big.Int {
	if divisor.Sign() <= 0 {
		panic("invalid reference divisor")
	}
	abs := new(big.Int).Abs(value)
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(abs, divisor, r)
	cmp := new(big.Int).Lsh(r, 1).Cmp(divisor)
	if cmp > 0 || cmp == 0 && q.Bit(0) == 1 {
		q.Add(q, big.NewInt(1))
	}
	if value.Sign() < 0 {
		q.Neg(q)
	}
	return crossGridWidthV1(q, 192)
}

func crossGridClenshawV1(eta *big.Int, c []*big.Int) *big.Int {
	x := crossGridRoundDivV1(eta, big.NewInt(17))
	b1, b2 := big.NewInt(0), big.NewInt(0)
	for k := len(c) - 1; k >= 1; k-- {
		product := crossGridMulV1(crossGridMulV1(big.NewInt(2), x), b1)
		b := crossGridSubV1(crossGridAddV1(c[k], crossGridRoundDivV1(product, crossGridPow2V1(64))), b2)
		crossGridWidthV1(b, 90)
		b2, b1 = b1, b
	}
	return crossGridSubV1(crossGridAddV1(c[0], crossGridRoundDivV1(crossGridMulV1(x, b1), crossGridPow2V1(64))), b2)
}

func crossGridExpV1(eta *big.Int, coeff []*big.Int) *big.Int {
	value := crossGridClenshawV1(eta, coeff)
	for i := 0; i < 2; i++ {
		value = crossGridRoundDivV1(crossGridMulV1(value, value), crossGridPow2V1(64))
	}
	return value
}

func crossGridQuantizeV1(loss *big.Int, valid bool, cap int64, g uint) *big.Int {
	if !valid || loss.Sign() < 0 {
		return big.NewInt(0)
	}
	max := new(big.Int).Lsh(big.NewInt(cap), 64-g)
	if loss.Cmp(max) > 0 {
		loss = max
	}
	return crossGridRoundDivV1(loss, crossGridPow2V1(64-g))
}

func crossGridReferenceBatchV1(c crossGridReferenceCaseV1, f crossGridProfileFixtureV1) []int64 {
	soft := crossGridCoefficientsV1(f, "softplus_coefficients_q64")
	exp := crossGridCoefficientsV1(f, "exp_quarter_coefficients_q64")
	logfact := crossGridCoefficientsV1(f, "log_factorial_q64")
	sums := make([]int64, len(c.BetaEncoded))
	for j, beta := range c.BetaEncoded {
		sum := big.NewInt(0)
		for i, x := range c.FeaturesEncoded {
			dot := crossGridMulV1(crossGridIntegerV1(beta[0]), crossGridPow2V1(50))
			for k, v := range x {
				dot = crossGridAddV1(dot, crossGridMulV1(crossGridIntegerV1(beta[k+1]), big.NewInt(v)))
			}
			crossGridWidthV1(dot, 106)
			eta := crossGridRoundDivV1(dot, crossGridPow2V1(36))
			var loss *big.Int
			if c.Family == "binomial" {
				loss = crossGridClenshawV1(eta, soft)
				if c.Outcomes[i] == 1 {
					loss = crossGridSubV1(loss, eta)
				}
			} else {
				loss = crossGridAddV1(crossGridSubV1(crossGridExpV1(eta, exp), crossGridMulV1(big.NewInt(c.Outcomes[i]), eta)), logfact[c.Outcomes[i]])
			}
			valid := true
			for _, v := range c.Validity[i] {
				valid = valid && v == 1
			}
			sum = crossGridAddV1(sum, crossGridQuantizeV1(loss, valid, c.Caps[j], c.G))
		}
		if !sum.IsInt64() || sum.Cmp(crossGridIntegerV1("9007199254740991")) > 0 {
			panic("reference release width exceeded")
		}
		sums[j] = sum.Int64()
	}
	return sums
}

func TestCrossGridV1ProfileAndContract(t *testing.T) {
	f := crossGridFixtureV1(t)
	for _, family := range []string{"binomial", "poisson"} {
		n := f.NumericContract[family]
		if err := crossGridValidateNumericContractV1(family, n); err != nil {
			t.Fatal(err)
		}
		value := reflect.ValueOf(&n).Elem()
		for i := 0; i < value.NumField(); i++ {
			changed := f.NumericContract[family]
			field := reflect.ValueOf(&changed).Elem().Field(i)
			field.Set(reflect.Zero(field.Type()))
			if err := crossGridValidateNumericContractV1(family, changed); err == nil {
				t.Errorf("field %s accepted mutation", value.Type().Field(i).Name)
			}
		}
	}
	if _, err := crossGridNumericContractV1("gaussian"); err == nil {
		t.Fatal("accepted unknown family")
	}
}

func TestCrossGridV1BatchReferenceFixtures(t *testing.T) {
	f := crossGridFixtureV1(t)
	for _, c := range f.ReferenceCases {
		t.Run(c.Family, func(t *testing.T) {
			if actual := crossGridReferenceBatchV1(c, f); !reflect.DeepEqual(actual, c.ExpectedSums) {
				t.Fatalf("reference fixture differs: %v", actual)
			}
			for i := range c.Validity {
				for k := range c.Validity[i] {
					c.Validity[i][k] = 0
				}
			}
			for _, value := range crossGridReferenceBatchV1(c, f) {
				if value != 0 {
					t.Fatal("padding contributed")
				}
			}
		})
	}
}

func TestCrossGridV1RoundingAndSaturation(t *testing.T) {
	for _, c := range [][2]int64{{1, 0}, {3, 2}, {5, 2}, {7, 4}, {-1, 0}, {-3, -2}, {-5, -2}, {-7, -4}} {
		if got := crossGridRoundDivV1(big.NewInt(c[0]), big.NewInt(2)).Int64(); got != c[1] {
			t.Fatal("ties-to-even differs")
		}
	}
	for _, g := range []uint{8, 18} {
		for _, c := range []struct {
			loss  *big.Int
			valid bool
			want  int64
		}{
			{big.NewInt(-1), true, 0}, {new(big.Int).Lsh(big.NewInt(999), 64-g), true, 17},
			{new(big.Int).Lsh(big.NewInt(999), 64-g), false, 0},
			{new(big.Int).Lsh(big.NewInt(5), 63-g), true, 2},
			{new(big.Int).Lsh(big.NewInt(7), 63-g), true, 4},
		} {
			if got := crossGridQuantizeV1(c.loss, c.valid, 17, g).Int64(); got != c.want {
				t.Fatal("quantization differs")
			}
		}
	}
}

// Independent 256-bit transcendental oracle. The exp Taylor remainder at
// degree 220 on |x|<=17 is < 2^-479; log uses atanh with |u|<=1/3 and 180 terms.
func crossGridHighV1() *big.Float { return new(big.Float).SetPrec(256).SetMode(big.ToNearestEven) }
func crossGridHighExpV1(x *big.Float) *big.Float {
	one := crossGridHighV1().SetInt64(1)
	term, sum := crossGridHighV1().Set(one), crossGridHighV1().Set(one)
	for k := int64(1); k <= 220; k++ {
		term.Mul(term, x)
		term.Quo(term, crossGridHighV1().SetInt64(k))
		sum.Add(sum, term)
	}
	return sum
}

func crossGridHighSoftplusV1(x *big.Float) *big.Float {
	abs := crossGridHighV1().Abs(x)
	e := crossGridHighExpV1(crossGridHighV1().Neg(abs))
	u := crossGridHighV1().Quo(e, crossGridHighV1().Add(crossGridHighV1().SetInt64(2), e))
	u2 := crossGridHighV1().Mul(u, u)
	term, sum := crossGridHighV1().Set(u), crossGridHighV1().Set(u)
	for k := int64(1); k < 180; k++ {
		term.Mul(term, u2)
		sum.Add(sum, crossGridHighV1().Quo(term, crossGridHighV1().SetInt64(2*k+1)))
	}
	sum.Mul(sum, crossGridHighV1().SetInt64(2))
	if x.Sign() > 0 {
		sum.Add(sum, x)
	}
	return sum
}

func TestCrossGridV1NonlinearAgainstHighPrecision(t *testing.T) {
	f := crossGridFixtureV1(t)
	soft := crossGridCoefficientsV1(f, "softplus_coefficients_q64")
	exp := crossGridCoefficientsV1(f, "exp_quarter_coefficients_q64")
	for i := -256; i <= 256; i++ {
		eta := new(big.Int).Lsh(big.NewInt(int64(i)), 60)
		x := crossGridHighV1().Quo(crossGridHighV1().SetInt(eta), crossGridHighV1().SetInt(crossGridPow2V1(64)))
		for _, family := range []string{"binomial", "poisson"} {
			var got *big.Int
			var want *big.Float
			if family == "binomial" {
				got = crossGridClenshawV1(eta, soft)
				want = crossGridHighSoftplusV1(x)
			} else {
				got = crossGridExpV1(eta, exp)
				want = crossGridHighExpV1(x)
			}
			value := crossGridHighV1().Quo(crossGridHighV1().SetInt(got), crossGridHighV1().SetInt(crossGridPow2V1(64)))
			error := crossGridHighV1().Abs(crossGridHighV1().Sub(value, want))
			bound, _, err := big.ParseFloat(f.NumericContract[family].CertifiedUniformError, 10, 256, big.ToNearestEven)
			if err != nil || error.Cmp(bound) > 0 {
				t.Fatal(fmt.Sprintf("%s certified error exceeded", family))
			}
		}
	}
	// Encoded eta slack is inside the certified [-17,17] polynomial domain.
	for _, sign := range []int64{-1, 1} {
		eta := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(300000))
		eta.Mul(eta, big.NewInt(sign))
		for _, point := range []*big.Int{eta, new(big.Int).Lsh(big.NewInt(17*sign), 64)} {
			x := crossGridHighV1().Quo(crossGridHighV1().SetInt(point), crossGridHighV1().SetInt(crossGridPow2V1(64)))
			for _, family := range []string{"binomial", "poisson"} {
				got, want := crossGridClenshawV1(point, soft), crossGridHighSoftplusV1(x)
				if family == "poisson" {
					got, want = crossGridExpV1(point, exp), crossGridHighExpV1(x)
				}
				value := crossGridHighV1().Quo(crossGridHighV1().SetInt(got), crossGridHighV1().SetInt(crossGridPow2V1(64)))
				error := crossGridHighV1().Abs(crossGridHighV1().Sub(value, want))
				bound, _, _ := big.ParseFloat(f.NumericContract[family].CertifiedUniformError, 10, 256, big.ToNearestEven)
				if error.Cmp(bound) > 0 {
					t.Fatal("endpoint certificate exceeded")
				}
			}
		}
	}
}

func TestCrossGridV1SixteenPredictorsEveryGridPrecision(t *testing.T) {
	f := crossGridFixtureV1(t)
	x := make([]int64, 16)
	beta := make([]string, 17)
	valid := make([]int, 17)
	for k := range x {
		x[k] = 1 << 50
		beta[k+1] = "1125899906842624"
		valid[k] = 1
	}
	valid[16] = 1
	beta[0] = "0"
	for _, family := range []string{"binomial", "poisson"} {
		want := crossGridHighSoftplusV1(crossGridHighV1().SetInt64(16))
		if family == "poisson" {
			want = crossGridHighExpV1(crossGridHighV1().SetInt64(16))
		}
		for g := uint(8); g <= 18; g++ {
			c := crossGridReferenceCaseV1{Family: family, G: g, FeaturesEncoded: [][]int64{x}, Outcomes: []int64{0}, Validity: [][]int{valid}, BetaEncoded: [][]string{beta}, Caps: []int64{1 << 45}}
			got := crossGridReferenceBatchV1(c, f)[0]
			natural := crossGridHighV1().Quo(crossGridHighV1().SetInt64(got), crossGridHighV1().SetInt(crossGridPow2V1(g)))
			error := crossGridHighV1().Abs(crossGridHighV1().Sub(natural, want))
			bound := crossGridHighV1().Quo(crossGridHighV1().SetFloat64(.75), crossGridHighV1().SetInt(crossGridPow2V1(g)))
			if error.Cmp(bound) > 0 {
				t.Fatal("per-patient lattice error exceeded")
			}
		}
	}
}

func TestCrossGridV1CertificateBudgetsAndWidths(t *testing.T) {
	f := crossGridFixtureV1(t)
	u := new(big.Rat).SetFrac(big.NewInt(1), crossGridPow2V1(64))
	eta := new(big.Rat).Add(new(big.Rat).SetFrac(big.NewInt(33), crossGridPow2V1(51)), new(big.Rat).SetFrac(big.NewInt(16), crossGridPow2V1(102)))
	eta.Add(eta, new(big.Rat).Quo(u, big.NewRat(2, 1)))
	etaCap, _ := new(big.Rat).SetString(f.NumericContract["poisson"].CertifiedEtaError)
	if eta.Cmp(etaCap) > 0 {
		t.Fatal("eta certificate insufficient")
	}
	for _, family := range []string{"binomial", "poisson"} {
		bound, _ := new(big.Rat).SetString(f.NumericContract[family].CertifiedUniformError)
		if bound.Cmp(new(big.Rat).SetFrac(big.NewInt(1), crossGridPow2V1(20))) >= 0 {
			t.Fatal("loss precision budget exceeded")
		}
	}
	// Worst public Clenshaw bound: (2M+1)*(n+1)*(n+2)/2 in natural units.
	for _, v := range [][2]int64{{32, 256}, {10000, 32}} {
		state := big.NewInt((2*v[0] + 1) * (v[1] + 1) * (v[1] + 2) / 2)
		state.Lsh(state, 64)
		if state.Cmp(crossGridPow2V1(89)) >= 0 {
			t.Fatal("state width certificate insufficient")
		}
		product := new(big.Int).Lsh(state, 65)
		if product.Cmp(crossGridPow2V1(155)) >= 0 || product.BitLen() >= 192 {
			t.Fatal("product width certificate insufficient")
		}
	}
}

// Compute log(n/d) independently through atanh, with 1 <= n/d <= 2.
// The 180-term remainder is below 2^-570 because |u| <= 1/3.
func crossGridHighLogRatioV1(n, d int64) *big.Float {
	u := crossGridHighV1().SetRat(big.NewRat(n-d, n+d))
	u2 := crossGridHighV1().Mul(u, u)
	term, sum := crossGridHighV1().Set(u), crossGridHighV1().Set(u)
	for k := int64(1); k < 180; k++ {
		term.Mul(term, u2)
		sum.Add(sum, crossGridHighV1().Quo(term, crossGridHighV1().SetInt64(2*k+1)))
	}
	return sum.Mul(sum, crossGridHighV1().SetInt64(2))
}

func TestCrossGridV1EncodingThroughLossCertificate(t *testing.T) {
	f := crossGridFixtureV1(t)
	soft := crossGridCoefficientsV1(f, "softplus_coefficients_q64")
	exp := crossGridCoefficientsV1(f, "exp_quarter_coefficients_q64")
	logfact := crossGridCoefficientsV1(f, "log_factorial_q64")
	log2 := crossGridHighLogRatioV1(2, 1)
	trueLogFactorial := crossGridHighV1().SetInt64(0)
	for k := int64(2); k <= 1024; k++ {
		shift := big.NewInt(k).BitLen() - 1
		term := crossGridHighLogRatioV1(k, 1<<shift)
		term.Add(term, crossGridHighV1().Mul(log2, crossGridHighV1().SetInt64(int64(shift))))
		trueLogFactorial.Add(trueLogFactorial, term)
	}
	encode := func(value float64) (*big.Rat, *big.Int) {
		// Public binary64 values are exact rationals here: no float dot product
		// or rounding approximation enters the independent reference.
		exact := new(big.Rat).SetFloat64(value)
		scaled := new(big.Rat).Mul(exact, new(big.Rat).SetInt(crossGridPow2V1(50)))
		return exact, crossGridRoundDivV1(scaled.Num(), scaled.Denom())
	}
	for _, mode := range []string{"positive", "negative", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			intercept := 0.123456789
			if mode == "negative" {
				intercept = -intercept
			}
			trueEta, encodedIntercept := encode(intercept)
			dot := crossGridMulV1(encodedIntercept, crossGridPow2V1(50))
			slopeL1 := new(big.Rat)
			featureRounding, coefficientRounding := false, false
			for k := 0; k < 16; k++ {
				beta, feature := 0.99228394, 1-float64(k+1)*1e-10
				if mode == "negative" || mode == "mixed" && k%2 == 1 {
					beta = -beta
				}
				if mode == "mixed" && k%2 == 1 {
					feature = float64(k+1) * 1e-10
				}
				b, bi := encode(beta)
				x, xi := encode(feature)
				be := new(big.Rat).Sub(b, new(big.Rat).SetFrac(bi, crossGridPow2V1(50)))
				xe := new(big.Rat).Sub(x, new(big.Rat).SetFrac(xi, crossGridPow2V1(50)))
				coefficientRounding = coefficientRounding || be.Sign() != 0
				featureRounding = featureRounding || xe.Sign() != 0
				inputBound := new(big.Rat).SetFrac(big.NewInt(1), crossGridPow2V1(51))
				if new(big.Rat).Abs(be).Cmp(inputBound) > 0 || new(big.Rat).Abs(xe).Cmp(inputBound) > 0 {
					t.Fatal("input encoding error exceeded")
				}
				slopeL1.Add(slopeL1, new(big.Rat).Abs(b))
				trueEta.Add(trueEta, new(big.Rat).Mul(b, x))
				dot = crossGridAddV1(dot, crossGridMulV1(bi, xi))
			}
			if !featureRounding || !coefficientRounding || new(big.Int).Rem(dot, crossGridPow2V1(36)).Sign() == 0 {
				t.Fatal("encoding fixture did not exercise rounding")
			}
			encodedEta := crossGridRoundDivV1(dot, crossGridPow2V1(36))
			etaError := new(big.Rat).Abs(new(big.Rat).Sub(new(big.Rat).SetFrac(encodedEta, crossGridPow2V1(64)), trueEta))
			etaBound := new(big.Rat).Mul(slopeL1, new(big.Rat).SetFrac(big.NewInt(1), crossGridPow2V1(51)))
			etaBound.Add(etaBound, new(big.Rat).SetFrac(big.NewInt(17), crossGridPow2V1(51)))
			etaBound.Add(etaBound, new(big.Rat).SetFrac(big.NewInt(16), crossGridPow2V1(102)))
			etaBound.Add(etaBound, new(big.Rat).SetFrac(big.NewInt(1), crossGridPow2V1(65)))
			certificateEta, _ := new(big.Rat).SetString(f.NumericContract["poisson"].CertifiedEtaError)
			if etaError.Sign() == 0 || etaError.Cmp(etaBound) > 0 || etaBound.Cmp(certificateEta) > 0 {
				t.Fatal("complete dot encoding certificate exceeded")
			}
			trueEtaHigh := crossGridHighV1().SetRat(trueEta)
			for _, family := range []string{"binomial", "poisson"} {
				outcomes := []int64{0, 1}
				if family == "poisson" {
					outcomes = []int64{0, 1024}
				}
				for _, y := range outcomes {
					loss, want := crossGridClenshawV1(encodedEta, soft), crossGridHighSoftplusV1(trueEtaHigh)
					if family == "poisson" {
						loss, want = crossGridExpV1(encodedEta, exp), crossGridHighExpV1(trueEtaHigh)
						loss = crossGridAddV1(loss, logfact[y])
						if y == 1024 {
							want.Add(want, trueLogFactorial)
						}
					}
					loss = crossGridSubV1(loss, crossGridMulV1(big.NewInt(y), encodedEta))
					want.Sub(want, crossGridHighV1().Mul(crossGridHighV1().SetInt64(y), trueEtaHigh))
					got := crossGridHighV1().SetRat(new(big.Rat).SetFrac(loss, crossGridPow2V1(64)))
					error := crossGridHighV1().Abs(crossGridHighV1().Sub(got, want))
					bound, _, _ := big.ParseFloat(f.NumericContract[family].CertifiedUniformError, 10, 256, big.ToNearestEven)
					if error.Cmp(bound) > 0 {
						t.Fatal("encoding through loss certificate exceeded")
					}
				}
			}
		})
	}
}
