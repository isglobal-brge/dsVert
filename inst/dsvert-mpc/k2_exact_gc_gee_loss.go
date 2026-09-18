package main

import (
	"fmt"
	"math/big"
	"strings"
)

// Candidate-major likelihood, symmetric upper bread, shifted clipped-score
// meat. AR1 is on stable original slot distances, including missingness gaps.
type groupedGEESpec struct {
	Slots, Predictors, GridBits                int
	Family, Correlation                        string
	RhoQ16, ScoreClipQ16, RowLossCap, BreadCap int64
	MaxOutcome                                 int64
}
type groupedGEERow struct {
	EtaQ64        *big.Int
	FeaturesF50   []*big.Int
	Outcome, Live int64
}

func groupedGEEValidate(s groupedGEESpec) error {
	if s.Slots < 1 || s.Slots > 8 || s.Predictors < 1 || s.Predictors > 3 || s.GridBits < 8 || s.GridBits > 18 || (s.Family != "binomial" && s.Family != "poisson") || (s.Correlation != "independence" && s.Correlation != "exchangeable" && s.Correlation != "ar1") || (s.RhoQ16 != 0 && s.RhoQ16 != 16384 && s.RhoQ16 != 32768) || (s.Correlation == "independence" && s.RhoQ16 != 0) || s.ScoreClipQ16 < 16384 || s.ScoreClipQ16 > 262144 || s.ScoreClipQ16%16384 != 0 || s.RowLossCap < 1 || s.RowLossCap > 1<<30 || s.BreadCap < 1 || s.BreadCap > 1<<30 || s.MaxOutcome < 1 || s.MaxOutcome > 4 || (s.Family == "binomial" && s.MaxOutcome != 1) {
		return primitiveVError()
	}
	return nil
}

func groupedGEEPublicRN(x *big.Rat) int64 {
	return primitiveVRoundDivReference(new(big.Int).Mul(x.Num(), big.NewInt(groupedProfileScale)), x.Denom()).Int64()
}

func groupedGEECorrelationConstants(s groupedGEESpec) (alpha int64, beta []int64, transition [][3]int64) {
	rho := new(big.Rat).SetFrac64(s.RhoQ16, groupedProfileScale)
	one := big.NewRat(1, 1)
	minus := new(big.Rat).Sub(one, rho)
	alpha = groupedGEEPublicRN(new(big.Rat).Inv(minus))
	beta = make([]int64, s.Slots+1)
	transition = make([][3]int64, s.Slots)
	for k := 1; k <= s.Slots; k++ {
		denom := new(big.Rat).Mul(minus, new(big.Rat).Add(minus, new(big.Rat).Mul(big.NewRat(int64(k), 1), rho)))
		beta[k] = groupedGEEPublicRN(new(big.Rat).Quo(rho, denom))
	}
	a := big.NewRat(1, 1)
	for gap := 1; gap < s.Slots; gap++ {
		a.Mul(a, rho)
		square := new(big.Rat).Mul(a, a)
		denom := new(big.Rat).Sub(one, square)
		transition[gap] = [3]int64{groupedGEEPublicRN(new(big.Rat).Quo(square, denom)), groupedGEEPublicRN(new(big.Rat).Inv(denom)), groupedGEEPublicRN(new(big.Rat).Neg(new(big.Rat).Quo(a, denom)))}
	}
	return
}

func groupedGEEMul(a, b int64) int64 { return groupedRoundDiv(a*b, groupedProfileScale) }
func groupedGEEQuantize(x int64, g int) int64 {
	if g <= 16 {
		return groupedRoundDiv(x, 1<<uint(16-g))
	}
	return x << uint(g-16)
}
func groupedGEEClamp(x, lo, hi int64) int64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

var groupedGEELogFactorial = [5]int64{0, 0, 45426, 117423, 208277}

func groupedGEEReference(s groupedGEESpec, rows []groupedGEERow) ([]int64, bool, error) {
	if groupedGEEValidate(s) != nil || len(rows) != s.Slots {
		return nil, false, primitiveVError()
	}
	d := s.Predictors + 1
	tri := d * (d + 1) / 2
	out := make([]int64, 1+2*tri)
	live := make([]bool, s.Slots)
	u := make([][]int64, s.Slots)
	z := make([]int64, s.Slots)
	count := 0
	for i, r := range rows {
		if r.EtaQ64 == nil || len(r.FeaturesF50) != s.Predictors || (r.Live != 0 && r.Live != 1) {
			return make([]int64, len(out)), false, nil
		}
		u[i] = make([]int64, d)
		if r.Live == 0 {
			continue
		}
		if new(big.Int).Abs(r.EtaQ64).Cmp(new(big.Int).Lsh(big.NewInt(4), 64)) > 0 || r.Outcome < 0 || r.Outcome > s.MaxOutcome {
			return make([]int64, len(out)), false, nil
		}
		x := make([]int64, d)
		x[0] = groupedProfileScale
		for k, f := range r.FeaturesF50 {
			if f == nil || f.Sign() < 0 || f.Cmp(new(big.Int).Lsh(big.NewInt(1), 50)) > 0 {
				return make([]int64, len(out)), false, nil
			}
			x[k+1] = primitiveVRoundDivReference(f, new(big.Int).Lsh(big.NewInt(1), 34)).Int64()
		}
		eta := primitiveVRoundDivReference(r.EtaQ64, new(big.Int).Lsh(big.NewInt(1), 48)).Int64()
		var mu, a, b, loss int64
		if s.Family == "binomial" {
			mu, _ = groupedProfileEval("sigmoid", eta)
			a, _ = groupedProfileEval("sqrt_variance", eta)
			b, _ = groupedProfileEval("inverse_sqrt_variance", eta)
			loss, _ = groupedProfileEval("softplus", eta)
		} else {
			mu, _ = groupedProfileEval("exp", eta)
			half := groupedRoundDiv(eta, 2)
			a, _ = groupedProfileEval("exp", half)
			b, _ = groupedProfileEval("exp", -half)
			loss = mu + groupedGEELogFactorial[r.Outcome]
		}
		loss -= r.Outcome * eta
		out[0] += groupedGEEClamp(groupedGEEQuantize(loss, s.GridBits), 0, s.RowLossCap)
		for k := 0; k < d; k++ {
			u[i][k] = groupedGEEMul(x[k], a)
		}
		z[i] = groupedGEEMul(r.Outcome*groupedProfileScale-mu, b)
		live[i] = true
		count++
	}
	w := make([][]int64, s.Slots)
	for i := range w {
		w[i] = make([]int64, s.Slots)
	}
	alpha, beta, trans := groupedGEECorrelationConstants(s)
	if s.Correlation == "ar1" {
		prev := -1
		for i := range rows {
			if live[i] {
				if prev < 0 {
					w[i][i] += groupedProfileScale
				} else {
					c := trans[i-prev]
					w[prev][prev] += c[0]
					w[i][i] += c[1]
					w[prev][i] += c[2]
					w[i][prev] += c[2]
				}
				prev = i
			}
		}
	} else {
		for i := range rows {
			for j := range rows {
				if live[i] && live[j] {
					if s.Correlation == "exchangeable" {
						w[i][j] = -beta[count]
					}
					if i == j {
						if s.Correlation == "independence" {
							w[i][j] += groupedProfileScale
						} else {
							w[i][j] += alpha
						}
					}
				}
			}
		}
	}
	score := make([]int64, d)
	bread := make([][]int64, d)
	for k := range bread {
		bread[k] = make([]int64, d)
	}
	for i := range rows {
		wz := int64(0)
		wu := make([]int64, d)
		for j := range rows {
			wz += groupedGEEMul(w[i][j], z[j])
			for k := 0; k < d; k++ {
				wu[k] += groupedGEEMul(w[i][j], u[j][k])
			}
		}
		for k := 0; k < d; k++ {
			score[k] += groupedGEEMul(u[i][k], wz)
			for l := 0; l < d; l++ {
				bread[k][l] += groupedGEEMul(u[i][k], wu[l])
			}
		}
	}
	for k := range score {
		score[k] = groupedGEEClamp(score[k], -s.ScoreClipQ16, s.ScoreClipQ16)
	}
	shift := int64(0)
	maxBread := s.BreadCap
	if s.Correlation != "independence" {
		shift = s.BreadCap
		maxBread = 2 * s.BreadCap
	}
	meatShift := groupedGEEMul(s.ScoreClipQ16, s.ScoreClipQ16)
	index := 0
	for l := 0; l < d; l++ {
		for k := 0; k <= l; k++ {
			out[1+index] = groupedGEEClamp(groupedGEEQuantize(bread[k][l], s.GridBits)+shift, 0, maxBread)
			out[1+tri+index] = groupedGEEQuantize(groupedGEEClamp(meatShift+groupedGEEMul(score[k], score[l]), 0, 2*meatShift), s.GridBits)
			index++
		}
	}
	return out, true, nil
}

func groupedGEESource(s groupedGEESpec) (string, error) {
	if groupedGEEValidate(s) != nil {
		return "", primitiveVError()
	}
	d := s.Predictors + 1
	tri := d * (d + 1) / 2
	nout := 2 + 2*tri
	ninput := s.Slots * (s.Predictors + 3)
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(groupedProfileSource())
	b.WriteString(primitiveVDividePowerTwoSource("groupedGEEEta", 48))
	b.WriteString(primitiveVDividePowerTwoSource("groupedGEEFeature", 34))
	// All divisors are public powers of two. Emit shifts explicitly because the
	// pinned backend does not strength-reduce its generic signed divider.
	emitted := map[int]bool{}
	for _, shift := range []int{1, 16, 16 - s.GridBits} {
		if shift < 0 || emitted[shift] {
			continue
		}
		emitted[shift] = true
		fmt.Fprintf(&b, "func groupedGEERound%d(a int64) int64 {\nnegative:=a<0\nif negative { a=-a }\nq:=a>>%d\nr:=a & int64(%d)\n", shift, shift, (int64(1)<<uint(shift))-1)
		if shift > 0 {
			fmt.Fprintf(&b, "if r>int64(%d) || (r==int64(%d) && (q&1)!=0) { q=q+1 }\n", int64(1)<<uint(shift-1), int64(1)<<uint(shift-1))
		}
		b.WriteString("if negative { q=-q }\nreturn q\n}\n")
	}
	b.WriteString("func groupedGEEMul(a,b int64) int64 { return groupedGEERound16(a*b) }\n")
	if s.GridBits <= 16 {
		fmt.Fprintf(&b, "func groupedGEEQuantize(a int64) int64 { return groupedGEERound%d(a) }\n", 16-s.GridBits)
	} else {
		fmt.Fprintf(&b, "func groupedGEEQuantize(a int64) int64 { return a<<%d }\n", s.GridBits-16)
	}
	fmt.Fprintf(&b, "func main(g [%d]int192,e [%d]int192) [%d]int192 {\nvalid:=true\ncount:=int64(0)\nloss:=int64(0)\n", ninput+nout, ninput, nout)
	for i := 0; i < s.Slots; i++ {
		base := i * (s.Predictors + 3)
		fmt.Fprintf(&b, "rawEta%d:=g[%d]+e[%d]\ny%d:=g[%d]+e[%d]\nrawLive%d:=g[%d]+e[%d]\nok%d:=rawLive%d==0 || rawLive%d==1\n", i, base, base, i, base+1, base+1, i, base+2, base+2, i, i, i)
		fmt.Fprintf(&b, "if rawLive%d==1 { ok%d=ok%d && rawEta%d>=-int192(73786976294838206464) && rawEta%d<=int192(73786976294838206464) && y%d>=0 && y%d<=%d }\n", i, i, i, i, i, i, i, s.MaxOutcome)
		for k := 1; k < d; k++ {
			fmt.Fprintf(&b, "rawX%d_%d:=g[%d]+e[%d]\nif rawLive%d==1 { ok%d=ok%d && rawX%d_%d>=0 && rawX%d_%d<=int192(1125899906842624) }\n", i, k, base+2+k, base+2+k, i, i, i, i, k, i, k)
		}
		fmt.Fprintf(&b, "valid=valid && ok%d\nlive%d:=rawLive%d==1 && ok%d\nif !live%d { rawEta%d=0\ny%d=0 }\neta%d:=int32(groupedGEEEta(rawEta%d))\n", i, i, i, i, i, i, i, i, i)
		for k := 0; k < d; k++ {
			if k == 0 {
				fmt.Fprintf(&b, "x%d_%d:=int64(65536)\n", i, k)
			} else {
				fmt.Fprintf(&b, "if !live%d { rawX%d_%d=0 }\nx%d_%d:=int64(groupedGEEFeature(rawX%d_%d))\n", i, i, k, i, k, i, k)
			}
		}
		if s.Family == "binomial" {
			fmt.Fprintf(&b, "mu%d:=int64(groupedProfileSigmoid(eta%d))\na%d:=int64(groupedProfileSqrtVariance(eta%d))\nb%d:=int64(groupedProfileInverseSqrtVariance(eta%d))\nrowloss%d:=int64(groupedProfileSoftplus(eta%d))-int64(y%d)*int64(eta%d)\n", i, i, i, i, i, i, i, i, i, i)
		} else {
			fmt.Fprintf(&b, "mu%d:=int64(groupedProfileExp(eta%d))\nhalf%d:=int32(groupedGEERound1(int64(eta%d)))\na%d:=int64(groupedProfileExp(half%d))\nb%d:=int64(groupedProfileExp(-half%d))\nlogfactorial%d:=int64(0)\n", i, i, i, i, i, i, i, i, i)
			for y := 2; y <= int(s.MaxOutcome); y++ {
				fmt.Fprintf(&b, "if y%d==%d { logfactorial%d=%d }\n", i, y, i, groupedGEELogFactorial[y])
			}
			fmt.Fprintf(&b, "rowloss%d:=mu%d-int64(y%d)*int64(eta%d)+logfactorial%d\n", i, i, i, i, i)
		}
		fmt.Fprintf(&b, "rowloss%d=groupedGEEQuantize(rowloss%d)\nif rowloss%d<0 { rowloss%d=0 }\nif rowloss%d>%d { rowloss%d=%d }\nif live%d { loss=loss+rowloss%d\ncount=count+1 }\nz%d:=groupedGEEMul(int64(y%d)*65536-mu%d,b%d)\nif !live%d { z%d=0 }\n", i, i, i, i, i, s.RowLossCap, i, s.RowLossCap, i, i, i, i, i, i, i, i)
		for k := 0; k < d; k++ {
			fmt.Fprintf(&b, "u%d_%d:=groupedGEEMul(x%d_%d,a%d)\nif !live%d { u%d_%d=0 }\n", i, k, i, k, i, i, i, k)
		}
	}
	alpha, beta, trans := groupedGEECorrelationConstants(s)
	for i := 0; i < s.Slots; i++ {
		for j := 0; j < s.Slots; j++ {
			fmt.Fprintf(&b, "w%d_%d:=int64(0)\n", i, j)
		}
	}
	if s.Correlation == "ar1" {
		for i := 0; i < s.Slots; i++ {
			fmt.Fprintf(&b, "first%d:=live%d\n", i, i)
			for k := 0; k < i; k++ {
				fmt.Fprintf(&b, "first%d=first%d && !live%d\n", i, i, k)
			}
			fmt.Fprintf(&b, "if first%d { w%d_%d=w%d_%d+65536 }\n", i, i, i, i, i)
			for j := i + 1; j < s.Slots; j++ {
				fmt.Fprintf(&b, "adj%d_%d:=live%d && live%d\n", i, j, i, j)
				for k := i + 1; k < j; k++ {
					fmt.Fprintf(&b, "adj%d_%d=adj%d_%d && !live%d\n", i, j, i, j, k)
				}
				c := trans[j-i]
				fmt.Fprintf(&b, "if adj%d_%d { w%d_%d=w%d_%d+%d\nw%d_%d=w%d_%d+%d\nw%d_%d=w%d_%d-int64(%d)\nw%d_%d=w%d_%d-int64(%d) }\n", i, j, i, i, i, i, c[0], j, j, j, j, c[1], i, j, i, j, -c[2], j, i, j, i, -c[2])
			}
		}
	} else {
		b.WriteString("correction:=int64(0)\n")
		if s.Correlation == "exchangeable" {
			for k := 1; k <= s.Slots; k++ {
				fmt.Fprintf(&b, "if count==%d { correction=%d }\n", k, beta[k])
			}
		}
		diag := groupedProfileScale
		if s.Correlation == "exchangeable" {
			diag = alpha
		}
		for i := 0; i < s.Slots; i++ {
			for j := 0; j < s.Slots; j++ {
				fmt.Fprintf(&b, "if live%d && live%d { w%d_%d=-correction", i, j, i, j)
				if i == j {
					fmt.Fprintf(&b, "+int64(%d)", diag)
				}
				b.WriteString(" }\n")
			}
		}
	}
	for k := 0; k < d; k++ {
		fmt.Fprintf(&b, "score%d:=int64(0)\n", k)
		for l := k; l < d; l++ {
			fmt.Fprintf(&b, "bread%d_%d:=int64(0)\n", k, l)
		}
	}
	for i := 0; i < s.Slots; i++ {
		fmt.Fprintf(&b, "wz%d:=int64(0)\n", i)
		for k := 0; k < d; k++ {
			fmt.Fprintf(&b, "wu%d_%d:=int64(0)\n", i, k)
		}
		for j := 0; j < s.Slots; j++ {
			fmt.Fprintf(&b, "wz%d=wz%d+groupedGEEMul(w%d_%d,z%d)\n", i, i, i, j, j)
			for k := 0; k < d; k++ {
				fmt.Fprintf(&b, "wu%d_%d=wu%d_%d+groupedGEEMul(w%d_%d,u%d_%d)\n", i, k, i, k, i, j, j, k)
			}
		}
		for k := 0; k < d; k++ {
			fmt.Fprintf(&b, "score%d=score%d+groupedGEEMul(u%d_%d,wz%d)\n", k, k, i, k, i)
			for l := k; l < d; l++ {
				fmt.Fprintf(&b, "bread%d_%d=bread%d_%d+groupedGEEMul(u%d_%d,wu%d_%d)\n", k, l, k, l, i, k, i, l)
			}
		}
	}
	for k := 0; k < d; k++ {
		fmt.Fprintf(&b, "if score%d>int64(%d) { score%d=int64(%d) }\nif score%d< -int64(%d) { score%d= -int64(%d) }\n", k, s.ScoreClipQ16, k, s.ScoreClipQ16, k, s.ScoreClipQ16, k, s.ScoreClipQ16)
	}
	fmt.Fprintf(&b, "var out [%d]int192\nout[0]=int192(loss)\n", nout)
	shift := int64(0)
	maxBread := s.BreadCap
	if s.Correlation != "independence" {
		shift = s.BreadCap
		maxBread = 2 * s.BreadCap
	}
	meatShift := groupedGEEMul(s.ScoreClipQ16, s.ScoreClipQ16)
	index := 0
	for l := 0; l < d; l++ {
		for k := 0; k <= l; k++ {
			fmt.Fprintf(&b, "bread%d_%d=groupedGEEQuantize(bread%d_%d)+int64(%d)\nif bread%d_%d<0 { bread%d_%d=0 }\nif bread%d_%d>int64(%d) { bread%d_%d=int64(%d) }\nout[%d]=int192(bread%d_%d)\n", k, l, k, l, shift, k, l, k, l, k, l, maxBread, k, l, maxBread, 1+index, k, l)
			fmt.Fprintf(&b, "meat%d:=int64(%d)+groupedGEEMul(score%d,score%d)\nif meat%d<0 { meat%d=0 }\nif meat%d>int64(%d) { meat%d=int64(%d) }\nout[%d]=int192(groupedGEEQuantize(meat%d))\n", index, meatShift, k, l, index, index, index, 2*meatShift, index, 2*meatShift, 1+tri+index, index)
			index++
		}
	}
	fmt.Fprintf(&b, "if valid { out[%d]=1 }\n", nout-1)
	for k := 0; k < nout; k++ {
		fmt.Fprintf(&b, "if !valid { out[%d]=0 }\nout[%d]=out[%d]-g[%d]\n", k, k, k, ninput+k)
	}
	b.WriteString("return out\n}\n")
	return b.String(), nil
}

func groupedGEECompile(s groupedGEESpec) (*primitiveVProgram, error) {
	source, err := groupedGEESource(s)
	if err != nil {
		return nil, err
	}
	d := s.Predictors + 1
	nout := 2 + d*(d+1)
	ninput := s.Slots * (s.Predictors + 3)
	return primitiveVCompile(source, 192, ninput+nout, ninput, nout)
}
func registerGroupedGEE() func(groupedGEESpec) (*primitiveVProgram, error) { return groupedGEECompile }
