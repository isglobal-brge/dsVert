package main

// One public B-slot cluster, after private routing. Neither the cluster's live
// count nor its loss is opened. This is an internal producer registration only.
import (
	"fmt"
	"math/big"
	"strings"
)

type groupedLMMSpec struct {
	Slots, GridBits    int
	ResidualCap        int64
	Sigma2Q64, Tau2Q64 *big.Int
	OutputCap          int64
}

func groupedLMMValidate(s groupedLMMSpec) error {
	if s.Slots < 1 || s.Slots > 32 || s.GridBits < 8 || s.GridBits > 18 || s.ResidualCap < 1 || s.ResidualCap > 17 || s.OutputCap < 1 || s.OutputCap > 9007199254740991 || s.Sigma2Q64 == nil || s.Tau2Q64 == nil {
		return primitiveVError()
	}
	if s.Sigma2Q64.Cmp(new(big.Int).Rsh(new(big.Int).Set(primitiveVScale), 2)) < 0 || s.Sigma2Q64.Cmp(new(big.Int).Lsh(new(big.Int).Set(primitiveVScale), 4)) > 0 || s.Tau2Q64.Sign() < 0 || s.Tau2Q64.Cmp(new(big.Int).Lsh(new(big.Int).Set(primitiveVScale), 4)) > 0 {
		return primitiveVError()
	}
	return nil
}

// Public reciprocals are rounded by integer division, without a floating
// transcendental or a protected-data solve. k=0 has lambda zero.
func groupedLMMTable(s groupedLMMSpec) (*big.Int, []*big.Int) {
	scale2 := new(big.Int).Lsh(big.NewInt(1), 128)
	inv := primitiveVRoundDivReference(scale2, s.Sigma2Q64)
	table := make([]*big.Int, s.Slots+1)
	table[0] = new(big.Int)
	for k := 1; k <= s.Slots; k++ {
		d := new(big.Int).Add(s.Sigma2Q64, new(big.Int).Mul(big.NewInt(int64(k)), s.Tau2Q64))
		d.Mul(d, s.Sigma2Q64)
		table[k] = primitiveVRoundDivReference(new(big.Int).Mul(s.Tau2Q64, scale2), d)
	}
	return inv, table
}

func groupedLMMReference(s groupedLMMSpec, residual, live []*big.Int) (*big.Int, bool, error) {
	if groupedLMMValidate(s) != nil || len(residual) != s.Slots || len(live) != s.Slots {
		return nil, false, primitiveVError()
	}
	total, squares := new(big.Int), new(big.Int)
	bound := new(big.Int).Mul(big.NewInt(s.ResidualCap), primitiveVScale)
	n := 0
	for i, r := range residual {
		if r == nil || live[i] == nil || (live[i].Sign() != 0 && live[i].Cmp(big.NewInt(1)) != 0) {
			return new(big.Int), false, nil
		}
		if live[i].Sign() == 0 {
			continue
		}
		if new(big.Int).Abs(r).Cmp(bound) > 0 {
			return new(big.Int), false, nil
		}
		n++
		total.Add(total, r)
		squares.Add(squares, primitiveVMulQ64Reference(r, r))
	}
	inv, table := groupedLMMTable(s)
	q := primitiveVMulQ64Reference(squares, inv)
	q.Sub(q, primitiveVMulQ64Reference(primitiveVMulQ64Reference(total, total), table[n]))
	upper := new(big.Int).Lsh(big.NewInt(s.OutputCap), uint(64-s.GridBits))
	primitiveVFamilyClamp(q, new(big.Int), upper)
	return primitiveVRoundDivReference(q, new(big.Int).Lsh(big.NewInt(1), uint(64-s.GridBits))), true, nil
}

func groupedLMMSource(s groupedLMMSpec) (string, error) {
	if groupedLMMValidate(s) != nil {
		return "", primitiveVError()
	}
	inv, table := groupedLMMTable(s)
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(primitiveVMultiplySource("groupedLMMMul", 88))
	b.WriteString(strings.ReplaceAll(primitiveVDividePowerTwoSource("groupedLMMQuantize", 64-s.GridBits), "uint72", "uint88"))
	fmt.Fprintf(&b, "func main(g [%d]int192,e [%d]int192) [2]int192 {\nvalid:=true\nzero:=g[0]-g[0]\nsum:=zero\nsquares:=zero\ncount:=zero\n", 2*s.Slots+2, 2*s.Slots)
	bound := new(big.Int).Mul(big.NewInt(s.ResidualCap), primitiveVScale)
	for i := 0; i < s.Slots; i++ {
		fmt.Fprintf(&b, "r%d:=g[%d]+e[%d]\nlive%d:=g[%d]+e[%d]\nok%d:=live%d==0 || live%d==1\nif live%d==1 { ok%d=ok%d && r%d>=-int192(%s) && r%d<=int192(%s) }\nvalid=valid && ok%d\nif !ok%d || live%d!=1 { r%d=0 }\nsum=sum+r%d\nsquares=squares+groupedLMMMul(r%d,r%d)\nif live%d==1 && ok%d { count=count+1 }\n", i, 2*i, 2*i, i, 2*i+1, 2*i+1, i, i, i, i, i, i, i, bound, i, bound, i, i, i, i, i, i, i, i, i)
	}
	b.WriteString("lambda:=int192(0)\n")
	for k := 1; k <= s.Slots; k++ {
		fmt.Fprintf(&b, "if count==%d { lambda=int192(%s) }\n", k, table[k])
	}
	upper := new(big.Int).Lsh(big.NewInt(s.OutputCap), uint(64-s.GridBits))
	fmt.Fprintf(&b, "inverse:=zero+int192(%s)\nloss:=groupedLMMMul(squares,inverse)-groupedLMMMul(groupedLMMMul(sum,sum),lambda)\nif loss<0 { loss=0 }\nif loss>int192(%s) { loss=int192(%s) }\nloss=groupedLMMQuantize(loss)\nv:=int192(0)\nif valid { v=1 } else { loss=0 }\nvar out [2]int192\nout[0]=loss-g[%d]\nout[1]=v-g[%d]\nreturn out\n}\n", inv, upper, upper, 2*s.Slots, 2*s.Slots+1)
	return b.String(), nil
}

func groupedLMMCompile(s groupedLMMSpec) (*primitiveVProgram, error) {
	source, err := groupedLMMSource(s)
	if err != nil {
		return nil, err
	}
	return primitiveVCompile(source, 192, 2*s.Slots+2, 2*s.Slots, 2)
}

// The fused producer calls this one registration; no general nonlinear RPC.
func registerGroupedLMM() groupedLMMRegistration { return groupedLMMRegistry() }
