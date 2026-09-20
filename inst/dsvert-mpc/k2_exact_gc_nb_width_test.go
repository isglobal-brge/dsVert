package main

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/markkurossi/mpc/compiler"
)

func TestCrossGridNB128CertifiedDomain(t *testing.T) {
	profile, _, data := crossGridNBFixtureV1(t)
	for exponent := -3; exponent <= 7; exponent++ {
		grids := []int{16}
		if exponent == -3 || exponent == 2 || exponent == 7 {
			grids = []int{8, 16, 18}
		}
		for _, grid := range grids {
			kernel, err := exactGCBuildNBLossWidthV1(data, exactGCNBLossParametersV1{exponent, 1024, grid, 1 << 40}, 128)
			if err != nil {
				t.Fatal(err)
			}
			source := "package main\n" + kernel.Declarations + fmt.Sprintf("func main(eta int128,y uint16) (uint128,bool) {return %s(eta,uint128(y),true)}\n", kernel.Function)
			compiled, _, err := compiler.New(crossGridPWCompilerParams()).Compile(source, nil)
			if err != nil {
				t.Fatal(err)
			}
			compiled = crossGridPWOptimize(compiled)
			bound := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(270337))
			for _, eta := range []*big.Int{new(big.Int).Neg(new(big.Int).Set(bound)), big.NewInt(-11), new(big.Int), big.NewInt(11), new(big.Int).Lsh(big.NewInt(5), 62), bound} {
				for _, y := range []int64{0, 1, 2, 17, 1024} {
					encoded := new(big.Int).Mod(new(big.Int).Set(eta), crossGridPow2V1(128))
					out, err := compiled.Compute([]*big.Int{encoded, big.NewInt(y)})
					if err != nil {
						t.Fatal(err)
					}
					want := crossGridNBReferenceLossV1(profile, eta, y, true, exponent, grid, 1<<40)
					if out[0].Cmp(want) != 0 || out[1].Cmp(big.NewInt(1)) != 0 {
						t.Fatalf("theta=%d g=%d eta=%s y=%d got=%v want=%s", exponent, grid, eta, y, out, want)
					}
				}
			}
			for _, invalid := range [][]*big.Int{{new(big.Int).Add(bound, big.NewInt(1)), big.NewInt(0)}, {new(big.Int), big.NewInt(1025)}, {new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(0)}} {
				out, err := compiled.Compute(invalid)
				if err != nil {
					t.Fatal(err)
				}
				if out[0].Sign() != 0 || out[1].Sign() != 0 {
					t.Fatal("invalid NB domain accepted")
				}
			}
			t.Logf("theta=%d grid_bits=%d full_domain_oracle_equal=true", exponent, grid)
		}
	}
}
