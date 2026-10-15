package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

func irlsTestRat(n, d int64) dpIRLSRat { return irlsEncodeRat(big.NewRat(n, d)) }
func irlsTestRequest(g []int64, H [][]int64) dpIRLSRequest {
	p := len(g)
	r := dpIRLSRequest{Version: dpIRLSUpdateVersion, Damping: irlsTestRat(1, 1), Floor: irlsTestRat(1, 1), FloorQuantum: irlsTestRat(1, 1), GUnit: irlsTestRat(1, 1), HUnit: irlsTestRat(1, 1), Lattice: irlsTestRat(1, 2), Ridge: irlsTestRat(0, 1), Trust: irlsTestRat(100, 1)}
	for i := 0; i < p; i++ {
		r.Beta = append(r.Beta, irlsTestRat(0, 1))
		r.BoxLower = append(r.BoxLower, irlsTestRat(-100, 1))
		r.BoxUpper = append(r.BoxUpper, irlsTestRat(100, 1))
		r.G = append(r.G, big.NewInt(g[i]+100).String())
		r.GTranslation = append(r.GTranslation, "100")
		for j := i; j < p; j++ {
			r.H = append(r.H, big.NewInt(H[i][j]+100).String())
			r.HTranslation = append(r.HTranslation, "100")
		}
	}
	return r
}
func irlsTestCertify(r *dpIRLSRequest) {
	c := irlsValidate(r, false)
	r.Limits = dpIRLSLimits{CommonDenominator: c.D.String(), InputBits: big.NewInt(int64(c.w)).String(), KMax: c.kmax.String(), TemporaryBits: big.NewInt(int64(c.a.bits)).String()}
}
func irlsTestRun(t *testing.T, r dpIRLSRequest) dpIRLSResult {
	t.Helper()
	irlsTestCertify(&r)
	b, _ := json.Marshal(r)
	got, err := DPIRLSCanonicalUpdate(b)
	if err != nil {
		t.Fatal(err)
	}
	var out dpIRLSResult
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestDPIRLSKnownAnswers(t *testing.T) {
	tests := []struct {
		name string
		g    []int64
		h    [][]int64
		k    string
		beta []dpIRLSRat
	}{
		{"positive-definite", []int64{1}, [][]int64{{2}}, "0", []dpIRLSRat{irlsTestRat(1, 2)}},
		{"semidefinite-zero", []int64{2}, [][]int64{{0}}, "1", []dpIRLSRat{irlsTestRat(2, 1)}},
		{"negative-pivot", []int64{1}, [][]int64{{-3}}, "4", []dpIRLSRat{irlsTestRat(1, 1)}},
		{"zero-residual-row-between-positive-pivots", []int64{4, 1, 6, 5}, [][]int64{{3, 0, 1, 0}, {0, 1, 0, 0}, {1, 0, 4, 1}, {0, 0, 1, 4}}, "0", []dpIRLSRat{irlsTestRat(1, 1), irlsTestRat(1, 1), irlsTestRat(1, 1), irlsTestRat(1, 1)}},
		{"zero-pivot-nonzero-residual", []int64{2, 2}, [][]int64{{1, 1}, {1, 1}}, "1", []dpIRLSRat{irlsTestRat(1, 2), irlsTestRat(1, 2)}},
		{"negative-half-tie", []int64{-1}, [][]int64{{4}}, "0", []dpIRLSRat{irlsTestRat(0, 1)}},
		{"negative-odd-half-tie", []int64{-3}, [][]int64{{4}}, "0", []dpIRLSRat{irlsTestRat(-1, 1)}},
		{"positive-half-tie", []int64{1}, [][]int64{{4}}, "0", []dpIRLSRat{irlsTestRat(0, 1)}},
		{"positive-odd-half-tie", []int64{3}, [][]int64{{4}}, "0", []dpIRLSRat{irlsTestRat(1, 1)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := irlsTestRun(t, irlsTestRequest(tc.g, tc.h))
			want, _ := json.Marshal(tc.beta)
			got, _ := json.Marshal(out.Beta)
			if out.K != tc.k || !bytes.Equal(want, got) {
				t.Fatalf("k=%s beta=%s; want k=%s beta=%s", out.K, got, tc.k, want)
			}
		})
	}
}
func TestDPIRLSDampingTrustProjection(t *testing.T) {
	r := irlsTestRequest([]int64{8, -4}, [][]int64{{2, 0}, {0, 2}})
	r.Damping = irlsTestRat(1, 2)
	r.Trust = irlsTestRat(1, 1)
	r.BoxLower[1] = irlsTestRat(0, 1)
	out := irlsTestRun(t, r)
	if !out.TrustScaled || !out.Projected[1] || out.Projected[0] || out.Beta[0] != irlsTestRat(1, 1) || out.Beta[1] != irlsTestRat(0, 1) {
		t.Fatalf("unexpected flags/result: %+v", out)
	}
	r = irlsTestRequest([]int64{0}, [][]int64{{1}})
	r.Trust = irlsTestRat(0, 1)
	out = irlsTestRun(t, r)
	if out.TrustScaled {
		t.Fatal("zero vector must retain unit trust scale")
	}
	r = irlsTestRequest([]int64{100}, [][]int64{{1}})
	out = irlsTestRun(t, r)
	if !out.Saturated {
		t.Fatal("finalizer endpoint was not flagged")
	}
}
func TestDPIRLSShiftBracketingEdges(t *testing.T) {
	for _, k := range []int64{0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100} {
		r := irlsTestRequest([]int64{0}, [][]int64{{1 - k}})
		out := irlsTestRun(t, r)
		if out.K != big.NewInt(k).String() {
			t.Fatalf("k=%s want %d", out.K, k)
		}
	}
	r := irlsTestRequest([]int64{0}, [][]int64{{-100}})
	out := irlsTestRun(t, r)
	if out.K != "101" {
		t.Fatalf("k_max edge: %s", out.K)
	}
}
func TestDPIRLSCertificateRejection(t *testing.T) {
	base := irlsTestRequest([]int64{1}, [][]int64{{2}})
	irlsTestCertify(&base)
	cases := map[string]func(*dpIRLSRequest){
		"understated-kmax":        func(r *dpIRLSRequest) { r.Limits.KMax = "1" },
		"overstated-kmax":         func(r *dpIRLSRequest) { r.Limits.KMax = "1000" },
		"wrong-denominator":       func(r *dpIRLSRequest) { r.Limits.CommonDenominator = "2" },
		"understated-input-width": func(r *dpIRLSRequest) { r.Limits.InputBits = "1" },
		"understated-temp":        func(r *dpIRLSRequest) { r.Limits.TemporaryBits = "2" },
		"overstated-temp":         func(r *dpIRLSRequest) { r.Limits.TemporaryBits = "999999" },
		"payload-negative":        func(r *dpIRLSRequest) { r.G[0] = "-1" },
		"payload-above-finalizer": func(r *dpIRLSRequest) { r.H[0] = "201" },
		"beta-off-lattice":        func(r *dpIRLSRequest) { r.Beta[0] = irlsTestRat(1, 3) },
		"beta-outside-box":        func(r *dpIRLSRequest) { r.Beta[0] = irlsTestRat(101, 1) },
		"zero-floor":              func(r *dpIRLSRequest) { r.Floor = irlsTestRat(0, 1) },
		"negative-trust":          func(r *dpIRLSRequest) { r.Trust = irlsTestRat(-1, 1) },
		"unreduced":               func(r *dpIRLSRequest) { r.Damping = dpIRLSRat{D: "2", N: "2"} },
		"signed-zero":             func(r *dpIRLSRequest) { r.Beta[0] = dpIRLSRat{D: "1", N: "-0"} },
		"zero-translation":        func(r *dpIRLSRequest) { r.GTranslation[0] = "0" },
		"missing-coordinate":      func(r *dpIRLSRequest) { r.H = nil },
		"wrong-version":           func(r *dpIRLSRequest) { r.Version = "dp_irls_update_v2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(base)
			var r dpIRLSRequest
			json.Unmarshal(b, &r)
			mutate(&r)
			b, _ = json.Marshal(r)
			if _, err := DPIRLSCanonicalUpdate(b); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	b, _ := json.Marshal(base)
	for name, raw := range map[string][]byte{"newline": append(append([]byte{}, b...), '\n'), "duplicate": []byte(strings.Replace(string(b), `"version":"dp_irls_update_v1"`, `"version":"dp_irls_update_v1","version":"dp_irls_update_v1"`, 1)), "unknown": append([]byte(`{"unknown":"x",`), b[1:]...), "missing": []byte(strings.Replace(string(b), `"version":"dp_irls_update_v1"`, `"version":null`, 1)), "oversize": bytes.Repeat([]byte(" "), dpIRLSMaxBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := DPIRLSCanonicalUpdate(raw); err == nil {
				t.Fatal("accepted noncanonical JSON")
			}
		})
	}
}
func TestDPIRLSSharedFixtures(t *testing.T) {
	f, err := os.Open("testdata/dp_irls_update_v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 65536), dpIRLSMaxBytes)
	total, random := 0, 0
	for scanner.Scan() {
		var fixture struct {
			Expected json.RawMessage `json:"expected"`
			Name     string          `json:"name"`
			Request  json.RawMessage `json:"request"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &fixture); err != nil {
			t.Fatal(err)
		}
		total++
		if strings.HasPrefix(fixture.Name, "random-") {
			random++
		}
		t.Run(fixture.Name, func(t *testing.T) {
			got, err := DPIRLSCanonicalUpdate(fixture.Request)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, fixture.Expected) {
				t.Fatalf("byte mismatch\ngot  %s\nwant %s", got, fixture.Expected)
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if random < 200 {
		t.Fatalf("only %d random fixtures", random)
	}
	t.Logf("%d fixtures, %d random: byte-for-byte agreement", total, random)
}
