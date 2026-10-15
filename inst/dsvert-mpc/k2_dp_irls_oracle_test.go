package main

// All clear reconstruction and noiseless arithmetic in this file is restricted
// to synthetic tests. There is no production noise-off flag or clear evaluator.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/markkurossi/mpc/circuit"
)

type dpIRLSB2Row struct {
	Present int64   `json:"present"`
	X       []int64 `json:"x"`
	Y       int64   `json:"y"`
	Offset  int64   `json:"offset"`
}

func dpIRLSB2TestPlan(family string, n int, beta []int64) dpIRLSStagePlan {
	c, err := dpIRLSProducerCertificate(family, 3, n, 1)
	if err != nil {
		panic(err)
	}
	p := dpIRLSStagePlan{Family: family, P: 3, Rows: n, Owners: 2, StageIndex: 1, OffsetMode: "offset",
		Root: strings.Repeat("1", 64), StageID: strings.Repeat("2", 64), Predecessor: strings.Repeat("3", 64),
		Purpose: "optimizer", CertificateDigest: dpIRLSProducerCertificateDigest(c), Version: dpIRLSStageVersion}
	for _, b := range beta {
		p.Beta = append(p.Beta, big.NewInt(b).String())
	}
	p.PointDigest = p.pointDigest()
	return p
}

func dpIRLSB2Source(rows []dpIRLSB2Row, owners int) []*big.Int {
	var source []*big.Int
	modulus := new(big.Int).Lsh(big.NewInt(1), 128)
	add := func(v int64) { source = append(source, new(big.Int).Mod(big.NewInt(v), modulus)) }
	for _, row := range rows {
		add(row.Present)
		for _, x := range row.X {
			add(x)
		}
		add(row.Y)
		add(row.Offset)
	}
	for owner := 0; owner < owners; owner++ {
		add(37)
		add(91)
	}
	return source
}

func dpIRLSB2TestInputs(t testing.TB, p crossGridKernelPlan, source []*big.Int, rng *rand.Rand) ([]*big.Int, []*big.Int, []*big.Int) {
	t.Helper()
	left, right := exactGCTestSplit(rng, source, 128)
	for i := p.IRLS.Rows * (p.IRLS.P + 3); i < len(source); i++ {
		right[i].Xor(left[i], source[i])
	}
	g, err := crossGridKernelPrivateInput(p, left, true)
	if err != nil {
		t.Fatal(err)
	}
	e, err := crossGridKernelPrivateInput(p, right, false)
	if err != nil {
		t.Fatal(err)
	}
	masks := make([]*big.Int, 10)
	for i := range masks {
		masks[i] = exactGCTestRandomResidue(rng, 128)
	}
	masks[9].And(masks[9], big.NewInt(1))
	return append(g, masks...), e, masks
}

type dpIRLSB2OracleProfile struct {
	Name               string
	Lower, Upper, Step int64
	Knots              []int64
}

// This reads the signed constants independently of groupedProfiles and never
// invokes groupedProfileEval, groupedExpEval, circuit source or producer code.
func dpIRLSB2OracleProfiles(t testing.TB) map[string]dpIRLSB2OracleProfile {
	t.Helper()
	b, err := os.ReadFile("../certificates/grouped_pwlinear_q16_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != "f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84" {
		t.Fatal("oracle profile manifest hash differs")
	}
	var manifest struct{ Profiles []dpIRLSB2OracleProfile }
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	profiles := make(map[string]dpIRLSB2OracleProfile)
	for _, p := range manifest.Profiles {
		profiles[p.Name] = p
	}
	return profiles
}

// Independent nearest-even integer division: quotient is mathematical floor,
// and the remainder lies in [0,den). This also defines negative half ties.
func dpIRLSB2OracleRN(num, den *big.Int) *big.Int {
	q, rem := new(big.Int), new(big.Int)
	q.DivMod(num, den, rem)
	cmp := new(big.Int).Lsh(rem, 1).Cmp(den)
	if cmp > 0 || (cmp == 0 && q.Bit(0) == 1) {
		q.Add(q, big.NewInt(1))
	}
	return q
}

func dpIRLSB2OracleClip(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func dpIRLSB2OracleLinear(p dpIRLSB2OracleProfile, x int64) int64 {
	if x < p.Lower || x > p.Upper || len(p.Knots) != 65 {
		panic("oracle profile domain")
	}
	if x == p.Upper {
		return p.Knots[64]
	}
	k := (x - p.Lower) / p.Step
	// Interpolate as an exact rational slope, then round the change once.
	part := new(big.Int).Mul(big.NewInt(x-p.Lower-k*p.Step), big.NewInt(p.Knots[k+1]-p.Knots[k]))
	return p.Knots[k] + dpIRLSB2OracleRN(part, big.NewInt(p.Step)).Int64()
}

func dpIRLSB2OracleLink(profiles map[string]dpIRLSB2OracleProfile, family string, eta int64) int64 {
	if family == "binomial" {
		return dpIRLSB2OracleClip(dpIRLSB2OracleLinear(profiles["sigmoid"], eta), 0, 65536)
	}
	if family != "poisson" {
		panic("oracle family")
	}
	// Choose the nearest signed ln(2) multiple, with half ties away from zero.
	// This formulation differs from the circuit's fixed subtract/shift network.
	k := dpIRLSB2OracleRN(big.NewInt(eta), big.NewInt(45426)).Int64()
	if eta%45426 == 22713 && k*45426 < eta {
		k++
	}
	if eta%45426 == -22713 && k*45426 > eta {
		k--
	}
	v := big.NewInt(dpIRLSB2OracleLinear(profiles["exp_reduced"], eta-k*45426))
	if k < 0 {
		v = dpIRLSB2OracleRN(v, new(big.Int).Lsh(big.NewInt(1), uint(-k)))
	} else {
		v.Lsh(v, uint(k))
	}
	return dpIRLSB2OracleClip(v.Int64(), 1200, 3604480)
}

func dpIRLSB2Oracle(t testing.TB, family string, beta []int64, rows []dpIRLSB2Row, capacity int) []*big.Int {
	t.Helper()
	return dpIRLSB2OracleWithProfiles(dpIRLSB2OracleProfiles(t), family, beta, rows, capacity)
}

func dpIRLSB2OracleWithProfiles(profiles map[string]dpIRLSB2OracleProfile, family string, beta []int64, rows []dpIRLSB2Row, capacity int) []*big.Int {
	p := len(beta)
	gcap, hcap := int64(4096), int64(1024)
	if family == "poisson" {
		gcap, hcap = 225280, 225280
	}
	out := make([]*big.Int, p+p*(p+1)/2)
	for j := range out {
		cap := hcap
		if j < p {
			cap = gcap
		}
		out[j] = big.NewInt(int64(capacity) * cap)
	}
	for _, row := range rows {
		if row.Present != 1 || (family == "binomial" && row.Y != 0 && row.Y != 1) {
			continue
		}
		x := make([]int64, p)
		dot := new(big.Int).Lsh(big.NewInt(dpIRLSB2OracleClip(row.Offset, -65536, 65536)), 16)
		for j := range x {
			x[j] = dpIRLSB2OracleClip(row.X[j], -65536, 65536)
			dot.Add(dot, new(big.Int).Mul(big.NewInt(x[j]), big.NewInt(beta[j])))
		}
		eta := dpIRLSB2OracleClip(dpIRLSB2OracleRN(dot, big.NewInt(65536)).Int64(), -262144, 262144)
		mu := dpIRLSB2OracleLink(profiles, family, eta)
		y, w := row.Y, mu
		if family == "binomial" {
			prod := new(big.Int).Mul(big.NewInt(mu), big.NewInt(65536-mu))
			w = dpIRLSB2OracleClip(dpIRLSB2OracleRN(prod, big.NewInt(65536)).Int64(), 0, 16384)
		} else {
			y = dpIRLSB2OracleClip(y, 0, 8)
		}
		residual := y*65536 - mu
		for j := 0; j < p; j++ {
			prod := new(big.Int).Mul(big.NewInt(x[j]), big.NewInt(residual))
			out[j].Add(out[j], dpIRLSB2OracleRN(prod, big.NewInt(1<<20)))
		}
		k := p
		for j := 0; j < p; j++ {
			for l := j; l < p; l++ {
				prod := new(big.Int).Mul(big.NewInt(x[j]), big.NewInt(x[l]))
				prod.Mul(prod, big.NewInt(w))
				out[k].Add(out[k], dpIRLSB2OracleRN(prod, big.NewInt(1<<36)))
				k++
			}
		}
	}
	return out
}

// Deterministic synthetic fixtures include invalid/absent rows, zero design,
// negative coordinates, clamped source values and outcomes, offset extremes,
// profile endpoints and arbitrary q16 residues. The caller supplies public beta.
func dpIRLSB2Fixtures(family string, n int) []dpIRLSB2Row {
	rng := rand.New(rand.NewSource(0x423249524c53))
	rows := make([]dpIRLSB2Row, n)
	for i := range rows {
		rows[i] = dpIRLSB2Row{Present: 1, X: []int64{65536, rng.Int63n(196609) - 98304, rng.Int63n(196609) - 98304}, Y: rng.Int63n(2), Offset: rng.Int63n(196609) - 98304}
		if family == "poisson" {
			rows[i].Y = rng.Int63n(17) - 4
		}
	}
	corners := []dpIRLSB2Row{
		{1, []int64{-65536, -65536, -65536}, 0, -65536},
		{1, []int64{65536, 65536, 65536}, 1, 65536},
		{1, []int64{0, 0, 0}, 1, 0},
		{0, []int64{65536, -65536, 65536}, 1, 65536},
		{2, []int64{65536, -65536, 65536}, 1, 65536},
		{1, []int64{1 << 40, -(1 << 40), 65537}, 1, -(1 << 40)},
		{1, []int64{-65537, 65535, -1}, -1, 1 << 40},
		{1, []int64{65536, -32768, 32768}, 9, -65537},
	}
	copy(rows, corners)
	return rows
}

func TestDPIRLSB2OracleRounding(t *testing.T) {
	for _, tc := range []struct{ n, d, want int64 }{{1, 2, 0}, {3, 2, 2}, {-1, 2, 0}, {-3, 2, -2}, {-5, 2, -2}, {-7, 2, -4}, {7, 2, 4}} {
		if got := dpIRLSB2OracleRN(big.NewInt(tc.n), big.NewInt(tc.d)).Int64(); got != tc.want {
			t.Fatalf("RN(%d/%d)=%d want %d", tc.n, tc.d, got, tc.want)
		}
	}
}

func dpIRLSB2CheckCircuit(t testing.TB, c *circuit.Circuit, p crossGridKernelPlan, rows []dpIRLSB2Row, source []*big.Int, want []*big.Int, aligned bool, rng *rand.Rand) {
	t.Helper()
	g, e, masks := dpIRLSB2TestInputs(t, p, source, rng)
	got, err := c.Compute([]*big.Int{exactGCPackChunks(g, 128), exactGCPackChunks(e, 128)})
	if err != nil {
		t.Fatal(err)
	}
	for j := range want {
		actual := new(big.Int).Rsh(new(big.Int).Set(got[0]), uint(128*j))
		actual.Add(actual, masks[j]).Mod(actual, exactGCModulus(128))
		if actual.Cmp(want[j]) != 0 {
			t.Fatalf("%s coordinate %d got %s want %s rows=%+v", p.IRLS.Family, j, actual, want[j], rows)
		}
	}
	valid := aligned
	for _, row := range rows {
		valid = valid && (row.Present == 0 || row.Present == 1)
		if row.Present == 1 && p.IRLS.Family == "binomial" {
			valid = valid && (row.Y == 0 || row.Y == 1)
		}
	}
	gotValid := new(big.Int).Rsh(new(big.Int).Set(got[0]), 128*9)
	gotValid.Xor(gotValid, masks[9])
	if gotValid.Sign() != 0 && !valid || gotValid.Sign() == 0 && valid || gotValid.BitLen() > 1 {
		t.Fatalf("protected validity got %s want %t", gotValid, valid)
	}
}

func TestDPIRLSB2CircuitExactness(t *testing.T) {
	rng := rand.New(rand.NewSource(0x42324558414354))
	for _, family := range []string{"binomial", "poisson"} {
		for _, beta := range [][]int64{{65536, 65536, 65536}, {12345, -23456, 34567}} {
			plan := dpIRLSB2TestPlan(family, 4, beta)
			p, err := dpIRLSStageKernelPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			c := crossGridKernelTestCompile(t, p)
			fixtures := dpIRLSB2Fixtures(family, 128)
			for i := 0; i < len(fixtures); i += 4 {
				rows := fixtures[i : i+4]
				want := dpIRLSB2Oracle(t, family, beta, rows, 4)
				dpIRLSB2CheckCircuit(t, c, p, rows, dpIRLSB2Source(rows, 2), want, true, rng)
			}
			zero := make([]dpIRLSB2Row, 4)
			for i := range zero {
				zero[i].X = []int64{0, 0, 0}
			}
			dpIRLSB2CheckCircuit(t, c, p, zero, dpIRLSB2Source(zero, 2), dpIRLSB2Oracle(t, family, beta, zero, 4), true, rng)
			rows := fixtures[:4]
			for _, zeroAlignment := range []bool{false, true} {
				source := dpIRLSB2Source(rows, 2)
				if zeroAlignment {
					for i := len(source) - 4; i < len(source); i++ {
						source[i].SetInt64(0)
					}
				} else {
					source[len(source)-1].Add(source[len(source)-1], big.NewInt(1))
				}
				dpIRLSB2CheckCircuit(t, c, p, rows, source, dpIRLSB2Oracle(t, family, beta, nil, 4), false, rng)
			}
			for _, negative := range []bool{false, true} {
				boundaryRows := append([]dpIRLSB2Row(nil), zero...)
				v := int64(1 << 40)
				if negative {
					v = -v
				}
				boundaryRows[0] = dpIRLSB2Row{Present: 1, X: []int64{v, v, v}, Y: v, Offset: v}
				source := dpIRLSB2Source(boundaryRows, 2)
				extreme := new(big.Int).Lsh(big.NewInt(1), 127)
				if !negative {
					extreme.Sub(extreme, big.NewInt(1))
				}
				for j := 1; j <= 5; j++ {
					source[j] = new(big.Int).Set(extreme)
				}
				dpIRLSB2CheckCircuit(t, c, p, boundaryRows, source, dpIRLSB2Oracle(t, family, beta, boundaryRows, 4), true, rng)
			}
			t.Logf("%s beta=%v: 37 circuits, 148 rows, 333 aggregate coordinates, validity checked", family, beta)
		}
	}
}

func TestDPIRLSB2SignedInterceptAndOffset(t *testing.T) {
	rng := rand.New(rand.NewSource(211))
	beta := []int64{12345, -23456, 34567}
	for _, family := range []string{"binomial", "poisson"} {
		for _, intercept := range []bool{false, true} {
			for _, offsetMode := range []string{"none", "offset"} {
				t.Run(fmt.Sprintf("%s/intercept_%t/%s", family, intercept, offsetMode), func(t *testing.T) {
					plan := dpIRLSB2TestPlan(family, 1, beta)
					plan.Intercept, plan.OffsetMode = intercept, offsetMode
					p, err := dpIRLSStageKernelPlan(plan)
					if err != nil {
						t.Fatal(err)
					}
					c := crossGridKernelTestCompile(t, p)
					for _, rawOffset := range []int64{0, -65537, 65537} {
						t.Run(fmt.Sprintf("raw_offset_%d", rawOffset), func(t *testing.T) {
							rows := []dpIRLSB2Row{{Present: 1, X: []int64{-65536, 12345, -32768}, Y: 1, Offset: rawOffset}}
							source := dpIRLSB2Source(rows, 2)
							if intercept {
								rows[0].X[0] = 65536
							}
							if offsetMode == "none" {
								rows[0].Offset = 0
							}
							dpIRLSB2CheckCircuit(t, c, p, rows, source, dpIRLSB2Oracle(t, family, beta, rows, 1), true, rng)
						})
					}
				})
			}
		}
	}
}

func TestDPIRLSB2IntegerSensitivityWitness(t *testing.T) {
	profiles := dpIRLSB2OracleProfiles(t)
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			gcap, hcap := int64(4096), int64(1024)
			outcomes := []int64{0, 1}
			if family == "poisson" {
				gcap, hcap = 225280, 225280
				outcomes = []int64{-1, 0, 1, 8, 9}
			}
			certificate, err := dpIRLSProducerCertificate(family, 3, 1, 1)
			if err != nil || certificate.GCap != gcap || certificate.HCap != hcap || certificate.S1G != 3*gcap || certificate.S1H != 6*hcap {
				t.Fatal("declared integer sensitivity differs from independent coordinate-cap proof")
			}
			maxAddG, maxAddH, maxReplaceG, maxReplaceH, witnesses := int64(0), int64(0), int64(0), int64(0), 0
			for _, beta := range [][]int64{{0, 0, 0}, {65536, 65536, 65536}, {-65536, 65536, -65536}, {12345, -32767, 45678}} {
				p, err := dpIRLSStageKernelPlan(dpIRLSB2TestPlan(family, 1, beta))
				if err != nil {
					t.Fatal(err)
				}
				c := crossGridKernelTestCompile(t, p)
				rng := rand.New(rand.NewSource(19))
				evaluate := func(row dpIRLSB2Row) []*big.Int {
					rows := []dpIRLSB2Row{row}
					want := dpIRLSB2OracleWithProfiles(profiles, family, beta, rows, 1)
					dpIRLSB2CheckCircuit(t, c, p, rows, dpIRLSB2Source(rows, 2), want, true, rng)
					return want
				}
				var values [][]*big.Int
				values = append(values, evaluate(dpIRLSB2Row{X: []int64{0, 0, 0}}))
				for corner := 0; corner < 8; corner++ {
					x := make([]int64, 3)
					for j := range x {
						x[j] = -65536
						if corner&(1<<j) != 0 {
							x[j] = 65536
						}
					}
					for _, offset := range []int64{-65537, -65536, 0, 65536, 65537} {
						for _, y := range outcomes {
							values = append(values, evaluate(dpIRLSB2Row{1, x, y, offset}))
						}
					}
				}
				for i, a := range values {
					for j, b := range values {
						if j > i {
							continue
						}
						g, h := new(big.Int), new(big.Int)
						for k := range a {
							d := new(big.Int).Abs(new(big.Int).Sub(a[k], b[k]))
							if k < 3 {
								g.Add(g, d)
							} else {
								h.Add(h, d)
							}
						}
						aFactor := int64(2)
						if j == 0 {
							aFactor = 1
							maxAddG, maxAddH = max(maxAddG, g.Int64()), max(maxAddH, h.Int64())
						}
						maxReplaceG, maxReplaceH = max(maxReplaceG, g.Int64()), max(maxReplaceH, h.Int64())
						if g.Cmp(big.NewInt(aFactor*certificate.S1G)) > 0 || h.Cmp(big.NewInt(aFactor*certificate.S1H)) > 0 {
							t.Fatalf("lane sensitivity violated: g=%s h=%s factor=%d", g, h, aFactor)
						}
						witnesses++
					}
				}
			}
			t.Logf("%s neighbours=%d max_add=(%d,%d) S1_add=(%d,%d) max_replace=(%d,%d) S1_replace=(%d,%d)", family, witnesses, maxAddG, maxAddH, 3*gcap, 6*hcap, maxReplaceG, maxReplaceH, 6*gcap, 12*hcap)
		})
	}
}
