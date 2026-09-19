//go:build grouped_reference_test

package main

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// Test-binary fixture only: absent from ordinary builds and all production RPCs.
func TestGroupedLMMStatsFixture(t *testing.T) {
	path := os.Getenv("DSVERT_GROUPED_LMM_STATS_FIXTURE")
	if path == "" {
		t.Skip("test fixture path absent")
	}
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	s := groupedLMMTestSpec()
	type fixture struct {
		Rows       [][]string `json:"rows"`
		Beta       []string   `json:"beta"`
		Sigma, Tau string
		Cap        int64
		Bits       int
		Want       string
	}
	var fixtures []fixture
	for _, b := range [][]int64{{0, 0}, {1, 2}, {-4, 8}} {
		rows := [][]*big.Int{{new(big.Int).Set(f), new(big.Int).Rsh(new(big.Int).Set(f), 1), new(big.Int).Rsh(new(big.Int).Set(f), 2)}, {new(big.Int).Set(f), new(big.Int).Rsh(new(big.Int).Set(f), 2), new(big.Int).Rsh(new(big.Int).Set(f), 1)}}
		beta := []*big.Int{new(big.Int).Mul(big.NewInt(b[0]), new(big.Int).Rsh(new(big.Int).Set(f), 2)), new(big.Int).Mul(big.NewInt(b[1]), new(big.Int).Rsh(new(big.Int).Set(f), 2))}
		item := fixture{Sigma: s.Sigma2Q64.String(), Tau: s.Tau2Q64.String(), Cap: s.OutputCap, Bits: s.GridBits, Want: groupedLMMStatsOracle(s, rows, beta).String()}
		for _, row := range rows {
			var encoded []string
			for _, v := range row {
				encoded = append(encoded, v.String())
			}
			item.Rows = append(item.Rows, encoded)
		}
		for _, v := range beta {
			item.Beta = append(item.Beta, v.String())
		}
		fixtures = append(fixtures, item)
	}
	raw, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
