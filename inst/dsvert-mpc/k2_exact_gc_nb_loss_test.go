package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
)

type crossGridNBReferenceCaseV1 struct {
	EtaQ64        string `json:"eta_q64"`
	Outcome       int64  `json:"outcome"`
	Valid         bool   `json:"valid"`
	ThetaExponent int    `json:"theta_exponent"`
	G             int    `json:"g"`
	Cap           int64  `json:"cap"`
	Expected      int64  `json:"expected"`
}

func crossGridNBFixtureV1(t testing.TB) (exactGCNBProfileV1, []crossGridNBReferenceCaseV1, []byte) {
	t.Helper()
	data, err := os.ReadFile("../cross-grid-nb/numeric_profile_nb_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := exactGCNBReadProfileV1(data)
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		ReferenceCases []crossGridNBReferenceCaseV1 `json:"reference_cases"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	return p, cases.ReferenceCases, data
}

// This plaintext evaluator is compiled ONLY by go test. The production file
// provides a source generator, never an executable cleartext loss operation.
func crossGridNBSoftplusReferenceV1(p exactGCNBProfileV1, z *big.Int) *big.Int {
	x := crossGridRoundDivV1(z, crossGridPow2V1(48))
	absolute := new(big.Int).Abs(new(big.Int).Set(x))
	residual := big.NewInt(0)
	if absolute.Cmp(big.NewInt(1048576)) < 0 {
		index := absolute.Int64() >> 14
		r := big.NewInt(absolute.Int64() & 16383)
		row := p.SoftplusQuadraticQ16[index]
		inner := crossGridAddV1(crossGridIntegerV1(row[1]), crossGridRoundDivV1(crossGridMulV1(crossGridIntegerV1(row[2]), r), crossGridPow2V1(16)))
		residual = crossGridAddV1(crossGridIntegerV1(row[0]), crossGridRoundDivV1(crossGridMulV1(inner, r), crossGridPow2V1(16)))
	}
	if x.Sign() > 0 {
		residual.Add(residual, x)
	}
	return residual
}

func crossGridNBReferenceRawV1(p exactGCNBProfileV1, eta *big.Int, y int64, exponent int) *big.Int {
	th := p.Theta[exponent+3]
	soft := new(big.Int).Lsh(crossGridNBSoftplusReferenceV1(p, crossGridSubV1(eta, crossGridIntegerV1(th.LogThetaQ64))), 48)
	return crossGridSubV1(crossGridAddV1(crossGridIntegerV1(th.ConstantQ64[y]), crossGridRoundDivV1(crossGridMulV1(big.NewInt(8*y+int64(th.ThetaTimesEight)), soft), big.NewInt(8))), crossGridMulV1(big.NewInt(y), eta))
}

func crossGridNBReferenceLossV1(p exactGCNBProfileV1, eta *big.Int, y int64, valid bool, exponent, g int, cap int64) *big.Int {
	return crossGridQuantizeV1(crossGridNBReferenceRawV1(p, eta, y, exponent), valid, cap, uint(g))
}

func TestCrossGridNBV1FixtureAndRegistration(t *testing.T) {
	p, cases, data := crossGridNBFixtureV1(t)
	for _, c := range cases {
		got := crossGridNBReferenceLossV1(p, crossGridIntegerV1(c.EtaQ64), c.Outcome, c.Valid, c.ThetaExponent, c.G, c.Cap)
		if got.Cmp(big.NewInt(c.Expected)) != 0 {
			t.Fatal("NB integer fixture differs")
		}
	}
	for g := 8; g <= 18; g++ {
		kernel, err := exactGCBuildNBLossV1(data, exactGCNBLossParametersV1{1, 1, g, 1 << 24})
		if err != nil || strings.Count(kernel.Declarations, "func "+kernel.Function+"Round48(") != 1 {
			t.Fatal("profile/output rounding declarations collide")
		}
	}
	calls := 0
	err := exactGCRegisterNBLossV1(func(r exactGCNBLossRegistrationV1) error {
		calls++
		if r.SpecVersion != "nb_grid_cross_v1" || r.MaterializedState != "cross_owner_exact_gc_materialized" || r.ReleaseState != "exact_gc_to_joint_dp_vector_v1" {
			t.Fatal("registration contract differs")
		}
		kernel, err := r.Build(data, exactGCNBLossParametersV1{1, 1024, 18, 1 << 40})
		if err != nil {
			return err
		}
		if !strings.Contains(kernel.Declarations, "domainValid") || strings.Contains(kernel.Declarations, "func main") {
			t.Fatal("kernel must expose only a private producer function")
		}
		return nil
	})
	if err != nil || calls != 1 || exactGCRegisterNBLossV1(nil) == nil {
		t.Fatal("registration must be explicit and singular")
	}
}

func TestCrossGridNBV1RejectsPublicTampering(t *testing.T) {
	_, _, data := crossGridNBFixtureV1(t)
	good := exactGCNBLossParametersV1{1, 1024, 18, 1 << 40}
	for _, p := range []exactGCNBLossParametersV1{{-4, 1, 18, 1}, {8, 1, 18, 1}, {1, 0, 18, 1}, {1, 1025, 18, 1}, {1, 1, 7, 1}, {1, 1, 19, 1}, {1, 1, 18, 0}, {1, 1, 18, 9007199254740992}} {
		if _, err := exactGCBuildNBLossV1(data, p); err == nil || err.Error() != "cross-grid NB contract rejected" {
			t.Fatal("invalid public parameter accepted or unsafe failure")
		}
	}
	for _, bad := range [][]byte{[]byte("{}"), append(append([]byte{}, data...), []byte("{}")...), []byte(strings.Replace(string(data), `"softplus_degree": 2`, `"softplus_degree": 3`, 1)), []byte(strings.Replace(string(data), `"profile_multiplications": 2`, `"profile_multiplications": 3`, 1))} {
		if _, err := exactGCBuildNBLossV1(bad, good); err == nil {
			t.Fatal("tampered numeric proof accepted")
		}
	}
}

func crossGridNBHighLogRatioV1(n, d int64) *big.Float {
	shift := int64(0)
	for n < d {
		n *= 2
		shift--
	}
	for n >= 2*d {
		d *= 2
		shift++
	}
	return crossGridHighV1().Add(crossGridHighLogRatioV1(n, d), crossGridHighV1().Mul(crossGridHighLogRatioV1(2, 1), crossGridHighV1().SetInt64(shift)))
}

func TestCrossGridNBV1IndependentLikelihoodAndBoundaryError(t *testing.T) {
	p, _, _ := crossGridNBFixtureV1(t)
	q := crossGridHighV1().SetInt(crossGridPow2V1(64))
	bound, _, _ := big.ParseFloat("0.045343", 10, 256, big.ToNearestEven)
	for exponent := -3; exponent <= 7; exponent++ {
		th8 := int64(1) << uint(exponent+3)
		th := crossGridHighV1().SetRat(big.NewRat(th8, 8))
		logTh := crossGridNBHighLogRatioV1(th8, 8)
		constants := make([]*big.Float, 1025)
		constants[0] = crossGridHighV1().SetInt64(0)
		for y := int64(1); y <= 1024; y++ {
			constants[y] = crossGridHighV1().Add(constants[y-1], crossGridHighV1().Add(crossGridNBHighLogRatioV1(8*y, th8+8*(y-1)), logTh))
		}
		for _, y := range []int64{0, 1, 17, 1024} {
			for _, eta := range []*big.Int{new(big.Int).Neg(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(270337))), big.NewInt(-11), big.NewInt(0), big.NewInt(11), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(270337))} {
				x := crossGridHighV1().Quo(crossGridHighV1().SetInt(eta), q)
				soft := crossGridHighSoftplusV1(crossGridHighV1().Sub(x, logTh))
				want := crossGridHighV1().Sub(crossGridHighV1().Add(constants[y], crossGridHighV1().Mul(crossGridHighV1().Add(th, crossGridHighV1().SetInt64(y)), soft)), crossGridHighV1().Mul(crossGridHighV1().SetInt64(y), x))
				got := crossGridHighV1().Quo(crossGridHighV1().SetInt(crossGridNBReferenceRawV1(p, eta, y, exponent)), q)
				if crossGridHighV1().Abs(crossGridHighV1().Sub(got, want)).Cmp(bound) > 0 {
					t.Fatal("NB independent likelihood exceeds uniform bound")
				}
				for g := 8; g <= 18; g++ {
					out := crossGridNBReferenceLossV1(p, eta, y, true, exponent, g, 1<<40)
					v := crossGridHighV1().Quo(crossGridHighV1().SetInt(out), crossGridHighV1().SetInt(crossGridPow2V1(uint(g))))
					if crossGridHighV1().Abs(crossGridHighV1().Sub(v, want)).Cmp(crossGridHighV1().Add(bound, crossGridHighV1().SetRat(big.NewRat(1, 2*(1<<uint(g)))))) > 0 {
						t.Fatal("NB lattice error exceeds piecewise certificate plus rounding")
					}
				}
			}
		}
	}
}

func TestCrossGridNBV1CircuitMatchesIntegerReference(t *testing.T) {
	p, _, data := crossGridNBFixtureV1(t)
	// Full 192-bit compiled arithmetic at extreme theta profiles. Deterministic
	// share reconstruction and circuit Compute occur ONLY in this test file.
	for _, exponent := range []int{-3, 1, 7} {
		t.Run(fmt.Sprintf("theta_exponent_%d", exponent), func(t *testing.T) {
			kernel, err := exactGCBuildNBLossV1(data, exactGCNBLossParametersV1{exponent, 1024, 18, 1 << 24})
			if err != nil {
				t.Fatal(err)
			}
			source := "package main\n" + kernel.Declarations + fmt.Sprintf("func main(g [5]uint192, e [3]uint192) [2]uint128 {\n eta := int192(g[0]+e[0])\n outcome := uint128(g[1]+e[1])\n valid := uint128(g[2]+e[2])\n loss, domain := %s(eta,outcome,valid == uint128(1))\n guard := uint128(0)\n if domain && valid <= uint128(1) { guard = uint128(1) }\n var out [2]uint128\n out[0] = loss - uint128(g[3])\n out[1] = guard - uint128(g[4])\n return out\n}\n", kernel.Function)
			start := time.Now()
			circ, _, err := compiler.New(utils.NewParams()).Compile(source, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("NB circuit theta=%d gates=%d compile=%s", exponent, len(circ.Gates), time.Since(start))
			for i, c := range []struct {
				eta    *big.Int
				y      int64
				valid  bool
				domain bool
			}{{big.NewInt(0), 1, true, true}, {new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(270337)), 1024, true, true}, {new(big.Int).Neg(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(270337))), 1024, true, true}, {big.NewInt(11), 17, false, true}, {big.NewInt(-11), 0, true, true}, {new(big.Int).Lsh(big.NewInt(17), 64), 0, true, false}, {big.NewInt(0), 1025, true, false}, {new(big.Int).Neg(crossGridPow2V1(191)), 0, true, false}, {new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(270338)), 0, true, false}, {new(big.Int).Neg(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(270338))), 0, true, false}} {
				valid := int64(0)
				if c.valid {
					valid = 1
				}
				values := []*big.Int{c.eta, big.NewInt(c.y), big.NewInt(valid)}
				g, e := big.NewInt(0), big.NewInt(0)
				for k, v := range values {
					share := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(int64(i+k+1)), 183), big.NewInt(int64(i*101+k)))
					other := new(big.Int).Mod(new(big.Int).Sub(v, share), crossGridPow2V1(192))
					g.Or(g, new(big.Int).Lsh(share, uint(k*192)))
					e.Or(e, new(big.Int).Lsh(other, uint(k*192)))
				}
				g.Or(g, new(big.Int).Lsh(big.NewInt(731), 3*192))
				g.Or(g, new(big.Int).Lsh(big.NewInt(911), 4*192))
				outputs, err := circ.Compute([]*big.Int{g, e})
				if err != nil {
					t.Fatal(err)
				}
				got := new(big.Int).And(outputs[0], new(big.Int).Sub(crossGridPow2V1(128), big.NewInt(1)))
				got.Mod(got.Add(got, big.NewInt(731)), crossGridPow2V1(128))
				guard := new(big.Int).Rsh(new(big.Int).Set(outputs[0]), 128)
				guard.Mod(guard.Add(guard, big.NewInt(911)), crossGridPow2V1(128))
				want := big.NewInt(0)
				if c.domain {
					want = crossGridNBReferenceLossV1(p, c.eta, c.y, c.valid, exponent, 18, 1<<24)
				}
				if got.Cmp(want) != 0 || (guard.Cmp(big.NewInt(1)) == 0) != c.domain {
					t.Fatalf("compiled NB circuit differs: case=%d eta=%s y=%d got=%s want=%s guard=%s domain=%t", i, c.eta, c.y, got, want, guard, c.domain)
				}
			}
		})
	}
}

func TestCrossGridNBV1DensePiecewiseCertificate(t *testing.T) {
	p, _, _ := crossGridNBFixtureV1(t)
	maxError := 0.0
	check := func(z *big.Int) {
		x, _ := new(big.Rat).SetFrac(z, crossGridPow2V1(64)).Float64()
		got := float64(crossGridNBSoftplusReferenceV1(p, z).Int64()) / 65536
		want := math.Max(x, 0) + math.Log1p(math.Exp(-math.Abs(x)))
		error := math.Abs(got - want)
		if error > maxError {
			maxError = error
		}
		if error > 0.00003936 {
			t.Fatalf("profile uniform certificate exceeded: %g", error)
		}
	}
	for i := -220000; i <= 220000; i++ {
		check(crossGridRoundDivV1(crossGridMulV1(big.NewInt(int64(i)), crossGridPow2V1(64)), big.NewInt(10000)))
	}
	for i := int64(0); i <= 64; i++ {
		for _, offset := range []*big.Int{big.NewInt(-1), big.NewInt(0), big.NewInt(1), crossGridPow2V1(47), new(big.Int).Neg(crossGridPow2V1(47))} {
			z := crossGridAddV1(new(big.Int).Lsh(big.NewInt(i), 62), offset)
			check(z)
			check(new(big.Int).Neg(z))
		}
	}
	t.Logf("softplus dense maximum absolute error=%g; certified=0.00003936", maxError)
	// Public default envelope: n10000, grid50, A16, M1024, theta128.
	loss := crossGridNBReferenceRawV1(p, new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(16), 64)), 1024, 7)
	endpoint, _ := new(big.Rat).SetFrac(loss, crossGridPow2V1(64)).Float64()
	for _, epsilon := range []float64{1, 4, 8} {
		laplaceScaleLower := 50 * (endpoint - 0.045343) / epsilon
		if 10000*0.045343 >= laplaceScaleLower/100 {
			t.Fatal("default aggregate approximation error is not below1% of Laplace scale")
		}
	}
}

func TestCrossGridNBV1SoftplusCircuitCostAndEquality(t *testing.T) {
	p, _, _ := crossGridNBFixtureV1(t)
	declarations := exactGCNBSoftplusSourceV1(p, "softplusProfileV1")
	source := "package main\n" + declarations + "func main(g int32,e int32) int32 { return softplusProfileV1(g+e) }\n"
	compiled, _, err := compiler.New(utils.NewParams()).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	andGates := 0
	bytesPerRow := 0
	for _, gate := range compiled.Gates {
		if gate.Op == circuit.AND {
			andGates++
		}
		// exactGC engine table rows: AND2, OR3, INV1; labels16 bytes.
		switch gate.Op {
		case circuit.AND:
			bytesPerRow += 32
		case circuit.OR:
			bytesPerRow += 48
		case circuit.INV:
			bytesPerRow += 16
		}
	}
	t.Logf("profile word_bits=32 pieces=64 polynomial_multiplications=2 AND=%d gates=%d garbled_bytes=%d n10000_grid50_GB=%g target_AND=2000 target_met=%t", andGates, len(compiled.Gates), bytesPerRow, float64(bytesPerRow)*500000/1e9, andGates <= 2000)
	// Actual cost is reported; this is no waiver of the production cost target.
	for segment := int64(-88); segment <= 88; segment++ {
		for _, offset := range []int64{-1, 0, 1, 8192, 16383} {
			x := segment*16384 + offset
			if x < -22*65536 || x > 22*65536 {
				continue
			}
			split := int64(173813)
			g := new(big.Int).Mod(big.NewInt(split), crossGridPow2V1(32))
			e := new(big.Int).Mod(big.NewInt(x-split), crossGridPow2V1(32))
			outputs, err := compiled.Compute([]*big.Int{g, e})
			if err != nil {
				t.Fatal(err)
			}
			want := crossGridNBSoftplusReferenceV1(p, new(big.Int).Lsh(big.NewInt(x), 48))
			if outputs[0].Cmp(want) != 0 {
				t.Fatalf("profile circuit/reference mismatch x=%d got=%s want=%s", x, outputs[0], want)
			}
		}
	}
}
