package main

// Bounded one-cluster composition kernel. Primitive-V routing supplies exactly
// B padded slots; no cluster sizes or flags are opened by this kernel.
import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

const groupedGLMMVersion = "glmm_grid_cross_v1"

type groupedGLMMSpec struct {
	Family           string
	Rows, OutputBits int
	VarianceQ16      int64
}
type groupedGLMMCaps struct {
	RowBound, ClusterError    float64
	UnitCap, PatientInfluence int64
}

func groupedGLMMValidate(s groupedGLMMSpec) error {
	if (s.Family != "binomial" && s.Family != "poisson") || s.Rows < 1 || s.Rows > 16 || s.OutputBits < 8 || s.OutputBits > 18 || (s.VarianceQ16 != 0 && s.VarianceQ16 != 16384) {
		return errors.New("grouped GLMM rejected")
	}
	return nil
}

func groupedGLMMBounds(s groupedGLMMSpec) (groupedGLMMCaps, error) {
	if err := groupedGLMMValidate(s); err != nil {
		return groupedGLMMCaps{}, err
	}
	rowBound := 3.0
	rowError := groupedProfiles["softplus"].Error + 1.0/65536 + 1e-12
	if s.Family == "poisson" {
		rowBound = 32
		rowError = groupedExpError + 17.0/65536 + 0.5/65536 + 1e-12
	}
	e := float64(s.Rows)*rowError + 0.5/65536 + 4*(groupedNegativeExpError+1.0/8000000) + groupedProfiles["log"].Error
	scale := float64(int64(1) << s.OutputBits)
	u := int64(math.Ceil(scale * (float64(s.Rows)*rowBound + e)))
	d := int64(math.Ceil(scale*(rowBound+2*e) + 1))
	if d > u {
		d = u
	}
	return groupedGLMMCaps{rowBound, e, u, d}, nil
}

var groupedGLMMNodes = [5]int64{-93617, -44421, 0, 44421, 93617}
var groupedGLMMLogWeights = [5]int64{-294042, -98614, -41196, -98614, -294042}
// Legacy full loss VALUE only; the share-composed selection omits factorials.
var groupedGLMMLogFactorials = [5]int64{0, 0, 45426, 117425, 208277}

// Registration is the only family integration entry. It creates no dispatch
// or release capability; the fused producer must bind authenticated source,
// routing, chunk sequence, caps and output evidence before invoking Compile.
type groupedGLMMRegistration struct {
	Shares                                groupedGLMMShareRegistration
	Version, Profile, State, ReleaseState string
	Validate                              func(groupedGLMMSpec) error
	Bounds                                func(groupedGLMMSpec) (groupedGLMMCaps, error)
	Compile                               func(groupedGLMMSpec) (*primitiveVProgram, error)
}

func registerGroupedGLMMLoss() groupedGLMMRegistration {
	return groupedGLMMRegistration{groupedGLMMShareRegistry(), groupedGLMMVersion, groupedProfileID, "cross_owner_exact_gc_materialized", "exact_gc_to_joint_dp_vector_v1", groupedGLMMValidate, groupedGLMMBounds, groupedGLMMCompile}
}

// eta contains already-combined frozen-ABI q64 predictors. The exact public
// coefficient dot product is rounded once upstream, never separately by owner.
func groupedGLMMReference(s groupedGLMMSpec, eta []*big.Int, live, outcome []int64) (int64, bool, error) {
	cap, err := groupedGLMMBounds(s)
	if err != nil || len(eta) != s.Rows || len(live) != s.Rows || len(outcome) != s.Rows {
		return 0, false, errors.New("grouped GLMM rejected")
	}
	score := groupedGLMMLogWeights
	count := 0
	bound := new(big.Int).Lsh(big.NewInt(1), 64)
	for i := 0; i < s.Rows; i++ {
		if eta[i] == nil || live[i] < 0 || live[i] > 1 {
			return 0, false, nil
		}
		if live[i] == 0 {
			continue
		}
		ycap := int64(1)
		if s.Family == "poisson" {
			ycap = 4
		}
		if outcome[i] < 0 || outcome[i] > ycap || new(big.Int).Abs(eta[i]).Cmp(bound) > 0 {
			return 0, false, nil
		}
		count++
		x := primitiveVRoundDivReference(eta[i], new(big.Int).Lsh(big.NewInt(1), 48)).Int64()
		for q := 0; q < 5; q++ {
			t := x
			if s.VarianceQ16 != 0 {
				t += groupedGLMMNodes[q]
			}
			profile := "softplus"
			if s.Family == "poisson" {
				profile = "exp"
			}
			loss, _ := groupedProfileEval(profile, t)
			loss -= outcome[i] * t
			if s.Family == "poisson" {
				loss += groupedGLMMLogFactorials[outcome[i]]
			}
			score[q] -= loss
		}
	}
	if count == 0 {
		return 0, true, nil
	}
	maximum := score[0]
	for _, x := range score[1:] {
		if x > maximum {
			maximum = x
		}
	}
	sum := int64(0)
	for _, x := range score {
		d := x - maximum
		v := int64(0)
		if d >= -16*65536 {
			v, _ = groupedProfileEval("exp_negative", d)
		}
		if d == 0 {
			v = 65536
		}
		if v < 0 {
			v = 0
		}
		if v > 65536 {
			v = 65536
		}
		sum += v
	}
	log, _ := groupedProfileEval("log", sum)
	loss := -maximum - log
	if loss < 0 {
		loss = 0
	}
	if s.OutputBits < 16 {
		loss = groupedRoundDiv(loss, 1<<uint(16-s.OutputBits))
	} else {
		loss <<= uint(s.OutputBits - 16)
	}
	if loss > cap.UnitCap {
		loss = cap.UnitCap
	}
	return loss, true, nil
}

func groupedGLMMCircuitSource(s groupedGLMMSpec) (string, error) {
	cap, err := groupedGLMMBounds(s)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(groupedProfileSource())
	b.WriteString(primitiveVDividePowerTwoSource("groupedGLMMQ64ToQ16", 48))
	fmt.Fprintf(&b, "func main(g [%d]int192,e [%d]int192) [2]int192 {\n valid := true\ncount := int32(0)\n", 3*s.Rows+2, 3*s.Rows)
	for q, v := range groupedGLMMLogWeights {
		fmt.Fprintf(&b, "score%d := int32(%d)\n", q, v)
	}
	for i := 0; i < s.Rows; i++ {
		ycap := 1
		if s.Family == "poisson" {
			ycap = 4
		}
		fmt.Fprintf(&b, "eta%d := g[%d]+e[%d]\nlive%d := g[%d]+e[%d]\ny%d := g[%d]+e[%d]\nrowOK%d := live%d == 0 || live%d == 1\n if live%d == 1 {rowOK%d = rowOK%d && eta%d >= -int192(18446744073709551616) && eta%d <= int192(18446744073709551616) && y%d >= 0 && y%d <= %d}\n valid = valid && rowOK%d\n if !rowOK%d || live%d != 1 {eta%d = 0\ny%d = 0\nlive%d = 0}\n x%d := int32(groupedGLMMQ64ToQ16(eta%d))\n yN%d := int32(y%d)\n if live%d == 1 { count=count+1 }\n", i, 3*i, 3*i, i, 3*i+1, 3*i+1, i, 3*i+2, 3*i+2, i, i, i, i, i, i, i, i, i, i, ycap, i, i, i, i, i, i, i, i, i, i, i)
		if s.Family == "poisson" {
			fmt.Fprintf(&b, "factorial%d := int32(0)\n", i)
			for y := 2; y <= 4; y++ {
				fmt.Fprintf(&b, "if yN%d == %d {factorial%d = %d}\n", i, y, i, groupedGLMMLogFactorials[y])
			}
		}
		for q := 0; q < 5; q++ {
			node := int64(0)
			if s.VarianceQ16 != 0 {
				node = groupedGLMMNodes[q]
			}
			fn := "groupedProfileSoftplus"
			if s.Family == "poisson" {
				fn = "groupedProfileExp"
			}
			fmt.Fprintf(&b, "t%d_%d := x%d + int32(%d)\nloss%d_%d := %s(t%d_%d) - yN%d*t%d_%d\n", i, q, i, node, i, q, fn, i, q, i, i, q)
			if s.Family == "poisson" {
				fmt.Fprintf(&b, "loss%d_%d = loss%d_%d + factorial%d\n", i, q, i, q, i)
			}
			fmt.Fprintf(&b, "if live%d == 1 {score%d = score%d-loss%d_%d}\n", i, q, q, i, q)
		}
	}
	b.WriteString("maximum := score0\n")
	for q := 1; q < 5; q++ {
		fmt.Fprintf(&b, "if score%d > maximum {maximum=score%d}\n", q, q)
	}
	b.WriteString("sum := int32(0)\n")
	for q := 0; q < 5; q++ {
		fmt.Fprintf(&b, "difference%d := score%d-maximum\nsafe%d:=difference%d\nif difference%d < -1048576 {safe%d=0}\nv%d:=groupedProfileExpNegative(safe%d)\nif difference%d < -1048576 {v%d=0}\nif difference%d == 0 {v%d=65536}\nif v%d<0 {v%d=0}\nif v%d>65536 {v%d=65536}\nsum=sum+v%d\n", q, q, q, q, q, q, q, q, q, q, q, q, q, q, q, q, q)
	}
	b.WriteString("loss := -maximum-groupedProfileLog(sum)\nif loss<0 {loss=0}\n")
	if s.OutputBits < 16 {
		shift := 16 - s.OutputBits
		fmt.Fprintf(&b, "rounded := loss >> %d\n remainder := loss & %d\n if remainder > %d || (remainder == %d && (rounded & 1) != 0) {rounded=rounded+1}\n", shift, (1<<shift)-1, 1<<(shift-1), 1<<(shift-1))
	} else {
		fmt.Fprintf(&b, "rounded := loss << %d\n", s.OutputBits-16)
	}
	fmt.Fprintf(&b, "if rounded > %d {rounded=%d}\nif count==0 || !valid {rounded=0}\nflag:=int192(0)\nif valid {flag=1}\nvar out [2]int192\nout[0]=int192(rounded)-g[%d]\nout[1]=flag-g[%d]\nreturn out\n}\n", cap.UnitCap, cap.UnitCap, 3*s.Rows, 3*s.Rows+1)
	return b.String(), nil
}

func groupedGLMMCompile(s groupedGLMMSpec) (*primitiveVProgram, error) {
	source, err := groupedGLMMCircuitSource(s)
	if err != nil {
		return nil, err
	}
	return primitiveVCompile(source, 192, 3*s.Rows+2, 3*s.Rows, 2)
}
