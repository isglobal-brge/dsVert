package main

import (
	"fmt"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"math/big"
	"strings"
	"testing"
)

func TestCrossGridNBComposition(t *testing.T) {
	p, _, data := crossGridNBFixtureV1(t)
	kernel, err := exactGCBuildNBLossV1(data, exactGCNBLossParametersV1{2, 4, 16, 1 << 24})
	if err != nil {
		t.Fatal(err)
	}
	round := strings.ReplaceAll(crossGridKernelRoundSource("roundNBeta", 36), "int64", "int128")
	src := "package main\n" + round + kernel.Declarations + fmt.Sprintf(`func main(x uint128,y uint128) [4]uint192 {
 eta:=roundNBeta(int128(x))
 wide:=int192(eta)
 if eta<0 {wide= -int192(-eta)}
 loss,domain:=%s(wide,y,true)
 var out [4]uint192
 out[0]=uint192(eta)
 out[1]=uint192(wide)
 out[2]=uint192(loss)
 if domain {out[3]=1}
 return out
 }
`, kernel.Function)
	c, _, err := compiler.New(utils.NewParams()).Compile(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ x, z, y int64 }{{0, 480112190661474, 3}, {544440899158631, 110484395074469, 4}} {
		dot := new(big.Int).Lsh(big.NewInt(1), 100)
		dot.Sub(dot, new(big.Int).Mul(big.NewInt(1<<50), big.NewInt(row.x)))
		dot.Add(dot, new(big.Int).Mul(big.NewInt(1<<49), big.NewInt(row.z)))
		eta := crossGridRoundDivV1(dot, crossGridPow2V1(36))
		out, err := c.Compute([]*big.Int{dot, big.NewInt(row.y)})
		if err != nil {
			t.Fatal(err)
		}
		fields := make([]*big.Int, 4)
		for i := range fields {
			fields[i] = new(big.Int).Rsh(new(big.Int).Set(out[0]), uint(192*i))
			fields[i].Mod(fields[i], crossGridPow2V1(192))
		}
		want := crossGridNBReferenceLossV1(p, eta, row.y, true, 2, 16, 1<<24)
		t.Logf("eta_want=%s fields=%v loss_want=%s", eta, fields, want)
		if fields[2].Cmp(want) != 0 {
			t.Error("NB composition changed certified loss")
		}
	}
}
