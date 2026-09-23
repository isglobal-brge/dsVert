package main

import (
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

func TestJointDPFrequencyBackendSelectionV2ExactAndPositiveDelta(t *testing.T) {
	input := jointDPFrequencyTestInput()
	input.Version = jointDPFrequencyBackendSelectionRequestVersionV2
	for _, delta := range []float64{0, .01} {
		input.ConvolutionRequest.Delta = jointDPFrequencyCanonicalFloat(delta)
		input.GaussianRequest.Delta = jointDPFrequencyCanonicalFloat(delta * (1 - 128*2.220446049250313e-16))
		output, err := selectJointDPFrequencyBackendV2(input)
		if err != nil {
			t.Fatal(err)
		}
		if output.Version != jointDPFrequencyBackendSelectionVersionV2 || output.ConvolutionPlan.Version != jointDPVectorConvolutionPlanVersionV4 || output.ConvolutionPlan.ImplementationDeltaBound != "0" ||
			output.ConvolutionCertificate.Method != jointDPFrequencyExactModularMethod || output.ConvolutionCertificate.AbsoluteSupport != input.CoordinateUpperBound {
			t.Fatalf("wrong v2 selection certificate: %+v", output)
		}
		if delta == 0 {
			if output.GaussianPlan != nil || output.GaussianCertificate != nil || output.GaussianUnavailableReason == "" || output.SelectionCertificate.SelectedPrimitive != jointDPVectorConvolutionBackendV4 {
				t.Fatal("zero delta did not select exact production")
			}
		} else {
			if output.GaussianPlan == nil || output.GaussianCertificate == nil || output.GaussianUnavailableReason != "" {
				t.Fatal("positive delta lost Gaussian candidate")
			}
			left, _ := new(big.Int).SetString(output.ConvolutionCertificate.Simultaneous95Abs, 10)
			right, _ := new(big.Int).SetString(output.GaussianCertificate.Simultaneous95Abs, 10)
			want := jointDPVectorConvolutionBackendV4
			if right.Cmp(left) < 0 {
				want = jointDPGaussianBackend
			}
			if output.SelectionCertificate.SelectedPrimitive != want {
				t.Fatal("v2 did not select minimum public certified radius")
			}
		}
		again, err := selectJointDPFrequencyBackendV2(input)
		if err != nil || !reflect.DeepEqual(output, again) {
			t.Fatal("v2 selection is not deterministic")
		}
		encoded, _ := json.Marshal(output)
		var decoded jointDPFrequencyBackendSelectionOutput
		if err := json.Unmarshal(encoded, &decoded); err != nil || !reflect.DeepEqual(output, decoded) {
			t.Fatal("v2 null-candidate roundtrip changed")
		}
	}
}

func TestJointDPFrequencyBackendSelectionV2ClampAndAdmission(t *testing.T) {
	input := jointDPFrequencyTestInput()
	input.Version = jointDPFrequencyBackendSelectionRequestVersionV2
	input.ConvolutionRequest.Delta, input.GaussianRequest.Delta = "0e+00", "0e+00"
	for _, upper := range []string{"1", exactGCMaxSigned(128).String()} {
		input.CoordinateUpperBound = upper
		out, err := selectJointDPFrequencyBackendV2(input)
		if err != nil || out.ConvolutionCertificate.Simultaneous95Abs != upper {
			t.Fatal("fixed clamp bound absent", err)
		}
	}
	input.CoordinateUpperBound = new(big.Int).Lsh(big.NewInt(1), 127).String()
	if _, err := selectJointDPFrequencyBackendV2(input); err == nil {
		t.Fatal("source outside signed range accepted")
	}
	input.CoordinateUpperBound = "1000"
	input.ConvolutionRequest.Epsilon = "1.0001e+04"
	input.GaussianRequest.Epsilon = jointDPFrequencyCanonicalFloat(10001 * (1 - 128*2.220446049250313e-16))
	if _, err := selectJointDPFrequencyBackendV2(input); err == nil {
		t.Fatal("out-of-range exact epsilon admitted")
	}
}

func TestJointDPFrequencyBackendSelectionV2UtilityRadiusProof(t *testing.T) {
	for _, dimensions := range []int{1, 3, 1000000} {
		for _, sensitivity := range []string{"1", "256", "1267650600228229401496703205376"} {
			plan, err := jointDPPlanVectorConvolutionLaplaceV4(jointDPVectorPlanInput{Epsilon: "1", Delta: "0", SensitivitySteps: sensitivity, TotalCoordinateCount: dimensions})
			if err != nil {
				t.Fatal(err)
			}
			upper := new(big.Int).Lsh(big.NewInt(1), 126)
			certificate, err := jointDPFrequencyExactConvolutionAccuracy(plan, upper)
			if err != nil {
				t.Fatal(err)
			}
			radius, _ := new(big.Int).SetString(certificate.Simultaneous95Abs, 10)
			if radius.Cmp(upper) == 0 {
				continue
			}
			threshold := new(big.Int).Rsh(new(big.Int).Set(radius), 1)
			exponent := new(big.Rat).Mul(jointDPVectorConvolutionExactRate(plan), new(big.Rat).SetInt(threshold))
			// Verify the rational proof 4*d*10^-floor(alpha*T/3)<=.05.
			power := jointDPVectorFloorRat(new(big.Rat).Quo(exponent, big.NewRat(3, 1)))
			bound := new(big.Rat).SetFrac(big.NewInt(int64(4*dimensions)), new(big.Int).Exp(big.NewInt(10), power, nil))
			if bound.Cmp(big.NewRat(1, 20)) > 0 {
				t.Fatal("uncertified radius", bound)
			}
		}
	}
}
