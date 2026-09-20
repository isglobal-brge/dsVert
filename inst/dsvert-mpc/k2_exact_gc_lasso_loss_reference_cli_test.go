//go:build dsvert_family_reference

package main

// This synthetic-data oracle exists only in a tagged Go TEST executable.
// It is absent from go build, including go build -tags dsvert_family_reference.
// No production command, handler, registry, or environment switch calls it.
import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type familyAReferenceRequest struct {
	Family        string     `json:"family"`
	G             uint       `json:"g"`
	Features      [][]string `json:"features"`
	Outcomes      []string   `json:"outcomes"`
	Validity      [][]int    `json:"validity"`
	Beta          [][]string `json:"beta"`
	Caps          []int64    `json:"caps"`
	ThetaExponent []int      `json:"theta_exponent"`
}

func TestFamilyAReferenceInputGuards(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"family":"nb","g":18,"features":[["0","1125899906842624"]],"outcomes":["1"],"validity":[[1,1,1,1]],"beta":[["0","0","0"]],"caps":[10000000],"theta_exponent":[1]}`
	cases := []struct {
		name, data string
		accepted   bool
	}{
		{"valid_f50_endpoint", valid, true},
		{"valid_beta_eight", strings.Replace(valid, `"beta":[["0","0","0"]]`, `"beta":[["9007199254740992","0","0"]]`, 1), true},
		{"noncanonical_beta", strings.Replace(valid, `"beta":[["0","0","0"]]`, `"beta":[["0.0","0","0"]]`, 1), false},
		{"beta_outside_domain", strings.Replace(valid, `"beta":[["0","0","0"]]`, `"beta":[["9007199254740993","0","0"]]`, 1), false},
		{"beta_l1_outside_domain", strings.Replace(valid, `"beta":[["0","0","0"]]`, `"beta":[["9007199254740992","9007199254740992","9007199254740992"]]`, 1), false},
		{"rounded_numeric_feature", strings.Replace(valid, `"1125899906842624"`, `1.12589990684262e+15`, 1), false},
		{"exponent_string_feature", strings.Replace(valid, `"1125899906842624"`, `"1e15"`, 1), false},
		{"feature_outside_domain", strings.Replace(valid, `"1125899906842624"`, `"1125899906842625"`, 1), false},
		{"unknown_field", strings.TrimSuffix(valid, "}") + `,"unknown":true}`, false},
		{"theta_outside_domain", strings.Replace(valid, `"theta_exponent":[1]`, `"theta_exponent":[8]`, 1), false},
		{"trailing_object", valid + `{}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			directory := t.TempDir()
			input, output := filepath.Join(directory, "input.json"), filepath.Join(directory, "output.json")
			if err := os.WriteFile(input, []byte(c.data), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestFamilyAReferenceCommand$")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "DSVERT_FAMA_SYNTHETIC_INPUT=") && !strings.HasPrefix(entry, "DSVERT_FAMA_SYNTHETIC_OUTPUT=") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, "DSVERT_FAMA_SYNTHETIC_INPUT="+input, "DSVERT_FAMA_SYNTHETIC_OUTPUT="+output)
			_, runError := command.CombinedOutput()
			_, fileError := os.Stat(output)
			if (runError == nil) != c.accepted || (fileError == nil) != c.accepted {
				t.Fatal("synthetic CLI acceptance or fail-closed output differs")
			}
		})
	}
}

func TestFamilyAReferenceCommand(t *testing.T) {
	input, output := os.Getenv("DSVERT_FAMA_SYNTHETIC_INPUT"), os.Getenv("DSVERT_FAMA_SYNTHETIC_OUTPUT")
	if input == "" || output == "" {
		t.Skip("synthetic reference harness only")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal("synthetic reference input rejected")
	}
	var req familyAReferenceRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || req.G < 8 || req.G > 18 || len(req.Features) == 0 || len(req.Features) > 10000 || len(req.Features) != len(req.Outcomes) || len(req.Validity) != len(req.Outcomes) {
		t.Fatal("synthetic reference input rejected")
	}
	var trailing interface{}
	if decoder.Decode(&trailing) != io.EOF {
		t.Fatal("synthetic reference input rejected")
	}
	if len(req.Beta) == 0 || len(req.Beta) != len(req.Caps) || len(req.Beta) > 256 {
		t.Fatal("synthetic reference input rejected")
	}
	for _, cap := range req.Caps {
		if cap <= 0 || cap > (1<<53-1)/int64(len(req.Features)) {
			t.Fatal("synthetic reference input rejected")
		}
	}
	for _, beta := range req.Beta {
		if len(beta) < 2 || len(beta) > 17 {
			t.Fatal("synthetic reference input rejected")
		}
		total := new(big.Int)
		for _, value := range beta {
			parsed, ok := new(big.Int).SetString(value, 10)
			if !ok || parsed.String() != value || new(big.Int).Abs(parsed).Cmp(crossGridPow2V1(53)) > 0 {
				t.Fatal("synthetic reference input rejected")
			}
			total.Add(total, new(big.Int).Abs(parsed))
		}
		limit := new(big.Int).Add(crossGridPow2V1(54), big.NewInt(int64((len(beta)+1)/2)))
		if total.Cmp(limit) > 0 {
			t.Fatal("synthetic reference input rejected")
		}
	}
	// Decimal strings retain the exact f50 integers through R/JSON; ordinary
	// jsonlite numeric output may round large inputs or use exponent notation.
	integer := func(value string, maximum int64) int64 {
		parsed, ok := new(big.Int).SetString(value, 10)
		if !ok || parsed.String() != value || !parsed.IsInt64() || parsed.Sign() < 0 || parsed.Cmp(big.NewInt(maximum)) > 0 {
			t.Fatal("synthetic reference input rejected")
		}
		return parsed.Int64()
	}
	features := make([][]int64, len(req.Features))
	outcomes := make([]int64, len(req.Outcomes))
	maximumOutcome := int64(1024)
	if req.Family == "gaussian" {
		maximumOutcome = 1 << 50
	} else if req.Family == "binomial" {
		maximumOutcome = 1
	}
	for i, row := range req.Features {
		features[i] = make([]int64, len(row))
		for k, value := range row {
			features[i][k] = integer(value, 1<<50)
		}
		outcomes[i] = integer(req.Outcomes[i], maximumOutcome)
		if len(row) == 0 || len(row) > 16 || len(req.Validity[i]) != len(row)+2 {
			t.Fatal("synthetic reference input rejected")
		}
		for _, bit := range req.Validity[i] {
			if bit != 0 && bit != 1 {
				t.Fatal("synthetic reference input rejected")
			}
		}
		for _, beta := range req.Beta {
			if len(beta) != len(row)+1 {
				t.Fatal("synthetic reference input rejected")
			}
		}
	}
	var sums []int64
	switch req.Family {
	case "binomial", "poisson":
		sums = crossGridReferenceBatchV1(crossGridReferenceCaseV1{
			Family: req.Family, G: req.G, FeaturesEncoded: features,
			Outcomes: outcomes, Validity: req.Validity, BetaEncoded: req.Beta, Caps: req.Caps,
		}, crossGridFixtureV1(t))
	case "nb":
		if len(req.ThetaExponent) != len(req.Beta) {
			t.Fatal("synthetic reference input rejected")
		}
		for _, exponent := range req.ThetaExponent {
			if exponent < -3 || exponent > 7 {
				t.Fatal("synthetic reference input rejected")
			}
		}
		profile, _, _ := crossGridNBFixtureV1(t)
		sums = make([]int64, len(req.Beta))
		for j, beta := range req.Beta {
			for i, row := range features {
				dot := crossGridMulV1(crossGridIntegerV1(beta[0]), crossGridPow2V1(50))
				for k, value := range row {
					dot = crossGridAddV1(dot, crossGridMulV1(crossGridIntegerV1(beta[k+1]), big.NewInt(value)))
				}
				eta := crossGridRoundDivV1(dot, crossGridPow2V1(36))
				valid := true
				for _, bit := range req.Validity[i] {
					valid = valid && bit == 1
				}
				loss := crossGridNBReferenceLossV1(profile, eta, outcomes[i], valid, req.ThetaExponent[j], int(req.G), req.Caps[j])
				sums[j] += loss.Int64()
			}
		}
	case "gaussian":
		// Existing cross-owner Gaussian primitive: upper-triangle X'X, X'y,
		// y'y. Inputs round to g; nonnegative products truncate by floor,
		// exactly as the existing cross-owner sufficient-statistic route.
		p := len(req.Beta[0])
		sums = make([]int64, p*(p+1)/2+p+2)
		for i, row := range features {
			valid := true
			for _, bit := range req.Validity[i] {
				valid = valid && bit == 1
			}
			if !valid {
				continue
			}
			x := append([]int64{1 << 50}, row...)
			for k, value := range x {
				x[k] = crossGridRoundDivV1(big.NewInt(value), crossGridPow2V1(50-req.G)).Int64()
			}
			y := crossGridRoundDivV1(big.NewInt(outcomes[i]), crossGridPow2V1(50-req.G)).Int64()
			sums[0] += 1 << req.G
			offset := 1
			add := func(a, b int64) {
				sums[offset] += new(big.Int).Quo(new(big.Int).Mul(big.NewInt(a), big.NewInt(b)), crossGridPow2V1(req.G)).Int64()
				offset++
			}
			for b := 0; b < p; b++ {
				for a := 0; a <= b; a++ {
					add(x[a], x[b])
				}
			}
			for _, value := range x {
				add(value, y)
			}
			add(y, y)
		}
	default:
		t.Fatal("synthetic reference input rejected")
	}
	encoded, err := json.Marshal(map[string]interface{}{"reference_only": true, "family": req.Family, "coordinates": sums})
	if err != nil || os.WriteFile(output, encoded, 0600) != nil {
		t.Fatal("synthetic reference output failed")
	}
}
