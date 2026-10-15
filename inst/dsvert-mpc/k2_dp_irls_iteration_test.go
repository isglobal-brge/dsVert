package main

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

type dpIRLSB2IterationEvidence struct {
	Family       string                `json:"family"`
	Rows         []dpIRLSB2Row         `json:"rows"`
	Path         [][]int64             `json:"path_q16"`
	Terminal     []string              `json:"terminal_translated_q12"`
	Certificate  dpIRLSProducerProfile `json:"certificate"`
	Iterations   int                   `json:"iterations"`
	BoxMagnitude dpIRLSRat             `json:"box_magnitude"`
}

func dpIRLSB2InteriorFixture(family string) []dpIRLSB2Row {
	binomialCounts := []int{4, 5, 3, 4, 4, 5, 3, 4}
	poissonCounts := []int{8, 10, 6, 8, 10, 12, 8, 10}
	var rows []dpIRLSB2Row
	for cell := 0; cell < 8; cell++ {
		x, offset := []int64{65536, -32768, -32768}, int64(-8192)
		if cell&1 != 0 {
			x[1] = 32768
		}
		if cell&2 != 0 {
			x[2] = 32768
		}
		if cell&4 != 0 {
			offset = 8192
		}
		for i := 0; i < 8; i++ {
			y := int64(0)
			if family == "binomial" {
				if i < binomialCounts[cell] {
					y = 1
				}
			} else {
				y = int64(poissonCounts[cell] / 8)
				if i < poissonCounts[cell]%8 {
					y++
				}
			}
			rows = append(rows, dpIRLSB2Row{Present: 1, X: append([]int64(nil), x...), Y: y, Offset: offset})
		}
	}
	return rows
}

// Exercises the actual B1 rational update using only synthetic oracle sums.
// Optional JSON is consumed by the separate R glm driver, never by production.
func TestDPIRLSB2NoiselessIteration(t *testing.T) {
	var evidence []dpIRLSB2IterationEvidence
	for _, family := range []string{"binomial", "poisson"} {
		rows := dpIRLSB2InteriorFixture(family)
		certificate, err := dpIRLSProducerCertificate(family, 3, len(rows), 1)
		if err != nil {
			t.Fatal(err)
		}
		beta := []int64{0, 0, 0}
		item := dpIRLSB2IterationEvidence{Family: family, Rows: rows, Certificate: certificate, Iterations: 12, BoxMagnitude: irlsTestRat(1, 1)}
		item.Path = append(item.Path, append([]int64(nil), beta...))
		var fixedLimits dpIRLSLimits
		for stage := 0; stage < item.Iterations; stage++ {
			values := dpIRLSB2Oracle(t, family, beta, rows, len(rows))
			r := dpIRLSRequest{Version: dpIRLSUpdateVersion, Damping: irlsTestRat(1, 1), Floor: irlsTestRat(1, 1024), FloorQuantum: irlsTestRat(1, 1024), GUnit: irlsTestRat(1, 4096), HUnit: irlsTestRat(1, 4096), Lattice: irlsTestRat(1, 65536), Ridge: irlsTestRat(0, 1), Trust: irlsTestRat(1, 1)}
			for j := range beta {
				r.Beta = append(r.Beta, irlsTestRat(beta[j], 65536))
				r.BoxLower = append(r.BoxLower, irlsTestRat(-1, 1))
				r.BoxUpper = append(r.BoxUpper, irlsTestRat(1, 1))
				r.G = append(r.G, values[j].String())
				r.GTranslation = append(r.GTranslation, big.NewInt(certificate.GTranslation).String())
			}
			for _, value := range values[3:] {
				r.H = append(r.H, value.String())
				r.HTranslation = append(r.HTranslation, big.NewInt(certificate.HTranslation).String())
			}
			irlsTestCertify(&r)
			if stage == 0 {
				fixedLimits = r.Limits
			} else if fixedLimits != r.Limits {
				t.Fatal("public path numeric certificate changed between stages")
			}
			encoded, _ := json.Marshal(r)
			result, err := DPIRLSCanonicalUpdate(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var out dpIRLSResult
			if err := json.Unmarshal(result, &out); err != nil {
				t.Fatal(err)
			}
			if out.K != "0" || out.TrustScaled || out.Saturated {
				t.Fatalf("interior fixture required stabilization: %+v", out)
			}
			for j, b := range out.Beta {
				if out.Projected[j] {
					t.Fatal("interior fixture projected")
				}
				v := new(big.Rat).Mul(irlsRat(b), big.NewRat(65536, 1))
				if !v.IsInt() || !v.Num().IsInt64() {
					t.Fatal("B1 successor is off producer q16 lattice")
				}
				beta[j] = v.Num().Int64()
			}
			item.Path = append(item.Path, append([]int64(nil), beta...))
		}
		for _, v := range dpIRLSB2Oracle(t, family, beta, rows, len(rows)) {
			item.Terminal = append(item.Terminal, v.String())
		}
		evidence = append(evidence, item)
		t.Logf("%s T=%d beta_q16=%v, no floor/trust/projection/saturation", family, item.Iterations, beta)
	}
	if path := os.Getenv("DSVERT_B2_ITERATION_OUTPUT"); path != "" {
		encoded, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
