package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/markkurossi/mpc/circuit"
	"math"
	"math/big"
	"os"
	"testing"
)

func TestGroupedProfileCertificate(t *testing.T) {
	functions := map[string]func(float64) float64{
		"softplus": func(x float64) float64 { return math.Log1p(math.Exp(x)) }, "exp": math.Exp, "exp_negative": math.Exp, "log": math.Log,
		"sigmoid":               func(x float64) float64 { return 1 / (1 + math.Exp(-x)) },
		"sqrt_variance":         func(x float64) float64 { return 1 / (2 * math.Cosh(x/2)) },
		"inverse_sqrt_variance": func(x float64) float64 { return 2 * math.Cosh(x/2) },
	}
	for name, p := range groupedProfiles {
		worst := 0.0
		for x := p.Lower; x <= p.Upper; x++ {
			got, err := groupedProfileEval(name, x)
			if err != nil {
				t.Fatal(err)
			}
			e := math.Abs(float64(got)/65536 - functions[name](float64(x)/65536))
			if e > worst {
				worst = e
			}
			if e > p.Error {
				t.Fatalf("%s certificate violated: %.12g > %.12g", name, e, p.Error)
			}
		}
		t.Logf("%s dense lattice max_error=%g certificate=%g", name, worst, p.Error)
		for _, x := range []int64{p.Lower - 1, p.Upper + 1} {
			if _, err := groupedProfileEval(name, x); err == nil {
				t.Fatal("domain accepted")
			}
		}
	}
}

func TestGroupedProfileCircuitEquality(t *testing.T) {
	for name, p := range groupedProfiles {
		t.Run(name, func(t *testing.T) {
			source := fmt.Sprintf("package main\n%s\nfunc main(g [2]int32,e [1]int32) [1]int32 { var out [1]int32\n out[0]=%s(g[0]+e[0])-g[1]\nreturn out\n}\n", groupedProfileSource(), groupedProfileFunction(name))
			program, err := primitiveVCompile(source, 32, 2, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("gates=%d AND=%d table_bytes=%d", program.Circuit.NumGates, program.Circuit.Stats[circuit.AND], primitiveVTableBytes(program.Circuit))
			for _, x := range []int64{p.Lower, p.Lower + 1, p.Lower + p.Step/2, p.Upper - p.Step/2, p.Upper - 1, p.Upper} {
				want, _ := groupedProfileEval(name, x)
				input := new(big.Int).Mod(big.NewInt(x), exactGCModulus(32))
				got, err := program.Circuit.Compute([]*big.Int{input, new(big.Int)})
				if err != nil {
					t.Fatal(err)
				}
				if got[0].Cmp(big.NewInt(want)) != 0 {
					t.Fatalf("x=%d got=%s want=%d", x, got[0], want)
				}
			}
		})
	}
}

func TestGroupedProfileManifest(t *testing.T) {
	data, err := os.ReadFile("../certificates/grouped_pwlinear_q16_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if digest != groupedProfileSHA256 {
		t.Fatal("profile hash differs")
	}
	var manifest struct {
		Profile  string
		Profiles []struct {
			Name               string
			Lower, Upper, Step int64
			Knots              []int64
			Error              float64
			Derivative         float64 `json:"second_derivative_bound"`
		}
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Profile != groupedProfileID || len(manifest.Profiles) != len(groupedProfiles) {
		t.Fatal("profile metadata differs")
	}
	for _, entry := range manifest.Profiles {
		p, ok := groupedProfiles[entry.Name]
		if !ok || p.Lower != entry.Lower || p.Upper != entry.Upper || p.Step != entry.Step || p.Error != entry.Error || len(entry.Knots) != 65 {
			t.Fatal("profile layout differs")
		}
		for i, v := range entry.Knots {
			if v != p.Knots[i] {
				t.Fatal("profile coefficient differs")
			}
		}
		h := float64(p.Step) / 65536
		if p.Error < entry.Derivative*h*h/8+1.0/65536 {
			t.Fatal("interpolation and rounding certificate does not enclose")
		}
	}
}
