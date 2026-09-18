package main

import (
	"fmt"
	"math/big"
	"strings"
)

// Local GH5 composition for ONE fixed public cluster/candidate. maskedProfile
// contains live*profile(eta+node), produced by checked OT; yEta contains the
// exact y*eta q16 product ONCE per row, reused at all nodes. Outcome/factorial
// shares were privately validated and masked upstream. No row is opened.
// All products here are public-node-by-share or local additions, at f16.
func groupedGLMMScoreShares(s groupedGLMMSpec, role exactGCRole, maskedProfile, yEta, outcome, logFactorial []groupedWord) ([5]groupedWord, error) {
	var score [5]groupedWord
	if groupedGLMMValidate(s) != nil || (role != exactGCRoleGarbler && role != exactGCRoleEvaluator) || len(maskedProfile) != s.Rows*5 || len(yEta) != s.Rows || len(outcome) != s.Rows || len(logFactorial) != s.Rows {
		return score, primitiveVError()
	}
	for q := range score {
		if role == exactGCRoleGarbler {
			score[q] = groupedWordFromBig(big.NewInt(groupedGLMMLogWeights[q]))
		}
		node := int64(0)
		if s.VarianceQ16 != 0 {
			node = groupedGLMMNodes[q]
		}
		for i := 0; i < s.Rows; i++ {
			score[q] = score[q].add(yEta[i]).add(outcome[i].mul(groupedWordFromBig(big.NewInt(node)))).sub(maskedProfile[i*5+q])
			if s.Family == "poisson" {
				score[q] = score[q].sub(logFactorial[i])
			}
		}
	}
	return score, nil
}

// Stable quadrature boundary. Input five shared node scores and the private
// live count; output five clipped exp arguments, max score and private valid.
// d<-16 maps to -16 whose certified integer exp is exactly zero, matching
// the existing truncation rule. No high-precision transcendental is emitted.
func groupedGLMMCenterCompile(s groupedGLMMSpec) (*primitiveVProgram, error) {
	if groupedGLMMValidate(s) != nil {
		return nil, primitiveVError()
	}
	var b strings.Builder
	b.WriteString("package main\nfunc main(g [13]int192,e [6]int192) [7]int192 {\nvar out [7]int192\ncount:=g[5]+e[5]\n")
	fmt.Fprintf(&b, "valid:=count>=0 && count<=%d\n", s.Rows)
	for q := 0; q < 5; q++ {
		fmt.Fprintf(&b, "wide%d:=g[%d]+e[%d]\nok%d:=wide%d>=-int192(%d) && wide%d<=0\nvalid=valid && ok%d\nif !ok%d { wide%d=0 }\ns%d:=int32(wide%d)\n", q, q, q, q, q, (s.Rows*32+8)*65536, q, q, q, q, q, q)
	}
	b.WriteString("maximum:=s0\n")
	for q := 1; q < 5; q++ {
		fmt.Fprintf(&b, "if s%d>maximum { maximum=s%d }\n", q, q)
	}
	for q := 0; q < 5; q++ {
		fmt.Fprintf(&b, "d%d:=s%d-maximum\nif d%d < -1048576 { d%d=-1048576 }\nif !valid { d%d=0 }\nout[%d]=int192(d%d)-g[%d]\n", q, q, q, q, q, q, q, 6+q)
	}
	b.WriteString("v:=int192(0)\nif valid { v=1 } else { maximum=0 }\nout[5]=int192(maximum)-g[11]\nout[6]=v-g[12]\nreturn out\n}\n")
	return primitiveVCompile(b.String(), 192, 13, 6, 7)
}

// Final GH5 boundary after five certified exp profiles, local share sum and
// certified log profile. Signed per-candidate cap is explicit, not the older
// compiler's universal bound. All upstream private validity must be conjoined
// into the last input. Zero-size clusters contribute exactly zero.
func groupedGLMMFinalCompile(s groupedGLMMSpec, cap int64) (*primitiveVProgram, error) {
	if groupedGLMMValidate(s) != nil || cap < 1 || cap > 9007199254740991 {
		return nil, primitiveVError()
	}
	var b strings.Builder
	b.WriteString("package main\n")
	if s.OutputBits < 16 {
		b.WriteString(primitiveVDividePowerTwoSource("quantize", 16-s.OutputBits))
	}
	b.WriteString("func main(g [6]int192,e [4]int192) [2]int192 {\nvar out [2]int192\nmaximum:=g[0]+e[0]\nlogsum:=g[1]+e[1]\ncount:=g[2]+e[2]\nvalid:=g[3]+e[3]==1\n")
	fmt.Fprintf(&b, "valid=valid && count>=0 && count<=%d && maximum>=-int192(%d) && maximum<=0 && logsum>=0 && logsum<=int192(131072)\n", s.Rows, (s.Rows*32+8)*65536)
	b.WriteString("loss:=-maximum-logsum\nif loss<0 { loss=0 }\n")
	if s.OutputBits < 16 {
		b.WriteString("loss=quantize(loss)\n")
	} else if s.OutputBits > 16 {
		fmt.Fprintf(&b, "loss=loss<<%d\n", s.OutputBits-16)
	}
	fmt.Fprintf(&b, "if loss>int192(%d) { loss=int192(%d) }\n", cap, cap)
	b.WriteString("v:=int192(0)\nif valid { v=1 } else { loss=0 }\nif count==0 { loss=0 }\nout[0]=loss-g[4]\nout[1]=v-g[5]\nreturn out\n}\n")
	return primitiveVCompile(b.String(), 192, 6, 4, 2)
}
