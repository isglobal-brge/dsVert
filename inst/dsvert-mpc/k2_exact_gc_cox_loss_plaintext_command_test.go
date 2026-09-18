//go:build dsvert_cox_plaintext_test

package main

// No production executable can contain this command: both _test.go and the
// explicit build constraint are required. It accepts PUBLIC SYNTHETIC fixtures
// only and never attaches to any server session, source transport or release.
import (
	"encoding/json"
	"io"
	"math"
	"os"
	"testing"
)

func TestCoxGridCrossPlaintextCommand(t *testing.T) {
	if os.Getenv("DSVERT_COX_PLAINTEXT_TEST") != "1" {
		t.Skip("explicit synthetic oracle command")
	}
	fail := func() { os.Stdout.Write([]byte("{\"error\":\"cox-grid-cross: rejected\"}\n")); os.Exit(2) }
	var request struct {
		Eta      [][]int32   `json:"eta_q16"`
		Time     []float64   `json:"time"`
		Event    []int       `json:"event"`
		Valid    []bool      `json:"valid"`
		GridBits int         `json:"numeric_grid_bits"`
		L1       []float64   `json:"coefficient_l1"`
		Beta     [][]float64 `json:"coefficient_grid"`
		Capacity int         `json:"capacity"`
	}
	d := json.NewDecoder(io.LimitReader(os.Stdin, 16<<20))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil {
		fail()
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail()
	}
	n := len(request.Eta)
	j := len(request.L1)
	if len(request.Beta) > 0 {
		j = len(request.Beta)
	}
	if n < 1 || n > request.Capacity || request.Capacity < 2 || request.Capacity > 10000 || j < 1 || j > 128 ||
		len(request.Time) != n || len(request.Event) != n || len(request.Valid) != n {
		fail()
	}
	for i := range request.Eta {
		if len(request.Eta[i]) != j || (request.Event[i] != 0 && request.Event[i] != 1) {
			fail()
		}
	}
	coordinates := make([]uint64, j)
	for c := 0; c < j; c++ {
		var beta []float64
		if len(request.Beta) > 0 {
			beta = request.Beta[c]
		} else {
			a := request.L1[c]
			if math.IsNaN(a) || math.IsInf(a, 0) || a < 0 || a > 8 {
				fail()
			}
			beta = []float64{math.Min(a, 4)}
			if a > 4 {
				beta = append(beta, a-4)
			}
		}
		cap, err := coxLossCap(request.Capacity, request.GridBits, beta)
		if err != nil {
			fail()
		}
		eta := make([]int32, request.Capacity)
		times := make([]float64, request.Capacity)
		events := make([]bool, request.Capacity)
		valid := make([]bool, request.Capacity)
		for i := 0; i < n; i++ {
			eta[i] = request.Eta[i][c]
			times[i] = request.Time[i]
			events[i] = request.Event[i] == 1
			valid[i] = request.Valid[i]
		}
		coordinates[c], err = coxLossReference(eta, times, events, valid, cap, request.GridBits)
		if err != nil {
			fail()
		}
	}
	if json.NewEncoder(os.Stdout).Encode(struct {
		Loss     []uint64 `json:"loss_coordinates"`
		Profile  string   `json:"profile"`
		TestOnly bool     `json:"test_only"`
	}{coordinates, CoxGridCrossProfileID, true}) != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
