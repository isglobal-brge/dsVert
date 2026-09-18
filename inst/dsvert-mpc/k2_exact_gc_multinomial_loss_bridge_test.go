//go:build dsvert_family_reference_test

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"testing"
)

// Explicit test-build-only bridge for PUBLIC synthetic DSLite validation.
// No production handler, init hook, environment flag, or fallback exists.
func TestFamilyReferenceBridge(t *testing.T) {
	path := os.Getenv("DSVERT_FAMILY_REFERENCE_INPUT")
	if path == "" {
		t.Skip("no public synthetic bridge input")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("reference input rejected")
	}
	var in struct {
		Family            string     `json:"family"`
		Classes           int        `json:"classes"`
		G                 int        `json:"g"`
		FeaturesEncoded   [][]int64  `json:"features_encoded"`
		BetaEncoded       [][]string `json:"beta_encoded"`
		ThresholdsEncoded [][]string `json:"thresholds_encoded"`
		Outcomes          []int      `json:"outcomes"`
		Valid             []bool     `json:"valid"`
		Caps              []int64    `json:"caps"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil {
		t.Fatal("reference input rejected")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		t.Fatal("reference input rejected")
	}
	if (in.Family != "multinomial" && in.Family != "ordinal") || len(in.FeaturesEncoded) != len(in.Outcomes) || len(in.Valid) != len(in.Outcomes) || len(in.Caps) != len(in.BetaEncoded) {
		t.Fatal("reference input rejected")
	}
	rows := make([][]int64, len(in.Outcomes))
	for i := range rows {
		rows[i] = make([]int64, len(in.Caps))
	}
	sums := make([]int64, len(in.Caps))
	for j, beta := range in.BetaEncoded {
		s := exactGCFamilyLossSpec{Classes: in.Classes, GridBits: in.G, Cap: in.Caps[j]}
		neta := in.Classes - 1
		if in.Family == "ordinal" {
			neta = 1
			if len(in.ThresholdsEncoded) != len(in.Caps) {
				t.Fatal("reference input rejected")
			}
			s.Thresholds = in.ThresholdsEncoded[j]
			if _, err := exactGCOrdinalThresholds(s); err != nil {
				t.Fatal("reference input rejected")
			}
		} else if exactGCFamilyLossValidate(s) != nil {
			t.Fatal("reference input rejected")
		}
		for i, x := range in.FeaturesEncoded {
			if len(x) < 1 || len(x) > 16 || len(beta) != neta*(len(x)+1) || in.Outcomes[i] < 0 || in.Outcomes[i] >= in.Classes {
				t.Fatal("reference input rejected")
			}
			dots := make([]*big.Int, neta)
			for c := 0; c < neta; c++ {
				offset := c * (len(x) + 1)
				dots[c] = new(big.Int).Lsh(exactGCFamilyInteger(beta[offset]), 50)
				for k, v := range x {
					if v < 0 || v > 1<<50 {
						t.Fatal("reference input rejected")
					}
					dots[c].Add(dots[c], new(big.Int).Mul(exactGCFamilyInteger(beta[offset+k+1]), big.NewInt(v)))
				}
			}
			value := familyLossReference(in.Family, s, dots, in.Outcomes[i], in.Valid[i])
			rows[i][j] = value.Int64()
			sums[j] += value.Int64()
		}
	}
	result, err := json.Marshal(struct {
		Rows [][]int64 `json:"rows"`
		Sums []int64   `json:"sums"`
	}{rows, sums})
	if err != nil || os.WriteFile(os.Getenv("DSVERT_FAMILY_REFERENCE_OUTPUT"), result, 0600) != nil {
		t.Fatal("reference output rejected")
	}
}
