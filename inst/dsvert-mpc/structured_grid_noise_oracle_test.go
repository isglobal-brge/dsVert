package main

// Public synthetic fixture only. Independent R integer family oracles supply
// Exact; this replays the real two-authority sampler seeds and support clamp.
import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

func TestStructuredGridNoiseOracle(t *testing.T) {
	path := os.Getenv("DSVERT_STRUCTURED_ORACLE_FIXTURE")
	if path == "" {
		t.Skip("synthetic structured release fixture opt-in")
	}
	var f struct {
		Exact       []string
		Draws       []crossGridOracleDraw
		NativeCalls []crossGridNativeCall
		Output      string
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &f) != nil || len(f.Exact) < 2 || len(f.Draws)+len(f.NativeCalls) == 0 || f.Output == "" {
		t.Fatal("invalid synthetic structured fixture")
	}
	raw := make([]*big.Int, len(f.Exact))
	for i, text := range f.Exact {
		v, ok := new(big.Int).SetString(text, 10)
		if !ok || v.Sign() < 0 || v.BitLen() > 53 {
			t.Fatal("invalid synthetic exact coordinate")
		}
		raw[i] = v
	}
	var released []string
	if len(f.NativeCalls) > 0 {
		if len(f.Draws) != 0 {
			t.Fatal("mixed synthetic sampler backends")
		}
		released, f.NativeCalls = crossGridNativeRelease(t, raw, f.NativeCalls)
	} else {
		released = crossGridOracleRelease(t, raw, f.Draws)
	}
	for _, value := range released {
		if value == "" {
			t.Fatal("synthetic noise does not cover the complete workload")
		}
	}
	out, err := json.Marshal(struct {
		Exact, Released []string
		NativeCalls     []crossGridNativeCall `json:",omitempty"`
	}{f.Exact[1:], released, f.NativeCalls})
	if err != nil || os.WriteFile(f.Output, out, 0600) != nil {
		t.Fatal("cannot write synthetic oracle")
	}
}
