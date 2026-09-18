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
	Family        string
	Sigma, Tau    string
	Eta, Residual []string
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
	switch r.Family {
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
	case "gee":
		eta := parse(r.Eta)
		rows := make([]groupedGEERow, len(eta))
		if len(r.Features) != len(eta) || len(r.Live) != len(eta) || len(r.Outcome) != len(eta) {
			t.Fatal("invalid test dimensions")
		}
		for i := range rows {
			rows[i] = groupedGEERow{eta[i], parse(r.Features[i]), r.Outcome[i], r.Live[i]}
		}
		values, valid, err = groupedGEEReference(r.GEE, rows)
	default:
		t.Fatal("invalid test family")
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(struct {
		Values []int64
		Valid  bool
	}{values, valid})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(output, data, 0600); err != nil {
		t.Fatal(err)
	}
}
