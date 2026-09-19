//go:build grouped_reference_test

package main

// This synthetic reference bridge exists only in an explicitly tagged Go test
// executable. It is neither a production command nor a server RPC.
import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

type groupedReferenceRequest struct {
	ClusterCap    int64
	Family        string
	Profile       string
	InputQ16      []int64
	Sigma, Tau    string
	Eta, Residual []string
	Beta          []string
	Features      [][]string
	Live, Outcome []int64
	LMM           groupedLMMSpec
	GLMM          groupedGLMMSpec
	GEE           groupedGEESpec
}

func TestGroupedReferenceBridge(t *testing.T) {
	input := os.Getenv("DSVERT_GROUPED_TEST_INPUT")
	output := os.Getenv("DSVERT_GROUPED_TEST_OUTPUT")
	if input == "" || output == "" {
		t.Skip("explicit synthetic fixture paths required")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var r groupedReferenceRequest
	if err = json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	parse := func(values []string) []*big.Int {
		out := make([]*big.Int, len(values))
		for i, v := range values {
			var ok bool
			out[i], ok = new(big.Int).SetString(v, 10)
			if !ok {
				t.Fatal("invalid test integer")
			}
		}
		return out
	}
	var values []int64
	var valid bool
	var errorBounds map[string]float64
	switch r.Family {
	case "profile":
		valid = true
		for _, x := range r.InputQ16 {
			value, e := groupedProfileEval(r.Profile, x)
			if e != nil {
				t.Fatal(e)
			}
			values = append(values, value)
		}
	case "lmm_stats":
		variance := parse([]string{r.Sigma, r.Tau})
		r.LMM.Sigma2Q64, r.LMM.Tau2Q64 = variance[0], variance[1]
		if groupedLMMValidate(r.LMM) != nil || len(r.Features) != r.LMM.Slots || len(r.Beta) < 2 || len(r.Beta) > 17 {
			t.Fatal("invalid test dimensions")
		}
		rows := make([][]*big.Int, len(r.Features))
		for i, row := range r.Features {
			if len(row) != len(r.Beta)+1 {
				t.Fatal("invalid test dimensions")
			}
			rows[i] = parse(row)
		}
		value := groupedLMMStatsOracle(r.LMM, rows, parse(r.Beta))
		values = []int64{value.Int64()}
		valid = true
	case "lmm":
		variance := parse([]string{r.Sigma, r.Tau})
		r.LMM.Sigma2Q64 = variance[0]
		r.LMM.Tau2Q64 = variance[1]
		flags := make([]*big.Int, len(r.Live))
		for i, v := range r.Live {
			flags[i] = big.NewInt(v)
		}
		value, ok, e := groupedLMMReference(r.LMM, parse(r.Residual), flags)
		err = e
		valid = ok
		if value != nil {
			values = []int64{value.Int64()}
		}
	case "glmm":
		value, ok, e := groupedGLMMReference(r.GLMM, parse(r.Eta), r.Live, r.Outcome)
		err = e
		valid = ok
		values = []int64{value}
	case "gee", "gee_whitening":
		eta := parse(r.Eta)
		rows := make([]groupedGEERow, len(eta))
		if len(r.Features) != len(eta) || len(r.Live) != len(eta) || len(r.Outcome) != len(eta) {
			t.Fatal("invalid test dimensions")
		}
		for i := range rows {
			rows[i] = groupedGEERow{eta[i], parse(r.Features[i]), r.Outcome[i], r.Live[i]}
		}
		if r.Family == "gee_whitening" {
			values, valid = groupedGEEWhiteningOracle(r.GEE, rows, r.ClusterCap)
			cert, e := groupedGEEWhiteningCertificate(r.GEE)
			if e != nil {
				t.Fatal(e)
			}
			errorBounds = map[string]float64{}
			for name, value := range map[string]*big.Rat{"likelihood": cert.Likelihood, "bread": cert.Bread, "meat": cert.Meat} {
				errorBounds[name], _ = value.Float64()
			}
		} else {
			values, valid, err = groupedGEEReference(r.GEE, rows)
		}
	default:
		t.Fatal("invalid test family")
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(struct {
		Values      []int64
		Valid       bool
		ErrorBounds map[string]float64 `json:",omitempty"`
	}{values, valid, errorBounds})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(output, data, 0600); err != nil {
		t.Fatal(err)
	}
}
