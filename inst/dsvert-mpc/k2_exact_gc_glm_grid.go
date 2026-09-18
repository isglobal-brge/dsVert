package main

// Typed, bounded batch producer. There is deliberately no public RPC: admission
// must bind the plan, source claims, alignment and output persistence first.
import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"strings"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
)

//go:embed cross_grid_profiles_v2.json
var crossGridProfilesV2JSON []byte

var errCrossGridKernel = errors.New("cross-grid kernel rejected")

// Public plan for one frozen row/candidate batch. Beta includes the intercept
// (zero when absent). Source slots are row-major value,validity pairs followed
// by the outcome pair. Alignment contains two XOR limbs per participating owner.
type crossGridKernelPlan struct {
	Family                                            string
	Rows, Predictors, Owners, A, GridBits, MaxOutcome int
	Beta                                              [][]string
	Caps                                              []uint64
}

type crossGridKernelProfiles struct {
	Binomial     []crossGridPWProfile       `json:"binomial"`
	Poisson      crossGridExpReducedProfile `json:"poisson"`
	LogFactorial []uint64                   `json:"log_factorial"`
}

func crossGridKernelProfilesLoad() (crossGridKernelProfiles, error) {
	var p crossGridKernelProfiles
	h := sha256.Sum256(crossGridProfilesV2JSON)
	if hex.EncodeToString(h[:]) != "133103c132d0d034b59d6f22c269209dea68b383433aea114bddac8a6f85a05e" || json.Unmarshal(crossGridProfilesV2JSON, &p) != nil {
		return p, errCrossGridKernel
	}
	return p, nil
}

func (p crossGridKernelPlan) validate() error {
	if (p.Family != "binomial" && p.Family != "poisson") || p.Rows < 1 || p.Rows > 32 || p.Predictors < 1 || p.Predictors > 16 || p.Owners < 2 || p.Owners > 64 || p.GridBits < 8 || p.GridBits > 18 || p.MaxOutcome < 1 || p.MaxOutcome > 1024 || (p.Family == "binomial" && p.MaxOutcome != 1) || (p.A != 1 && p.A != 2 && p.A != 4 && p.A != 8 && p.A != 16) || len(p.Beta) < 1 || len(p.Beta) > 8 || len(p.Caps) != len(p.Beta) {
		return errCrossGridKernel
	}
	bound := new(big.Int).Lsh(big.NewInt(int64(p.A)), 50)
	// Half-ulp encoding slack is admitted, then projected before the profile.
	bound.Add(bound, big.NewInt(int64((p.Predictors+2)/2)))
	for j, row := range p.Beta {
		if len(row) != p.Predictors+1 || p.Caps[j] == 0 || p.Caps[j] > (1<<53-1)/uint64(p.Rows) {
			return errCrossGridKernel
		}
		sum := new(big.Int)
		for _, s := range row {
			if len(s) > 18 {
				return errCrossGridKernel
			}
			v, ok := new(big.Int).SetString(s, 10)
			if !ok || v.String() != s {
				return errCrossGridKernel
			}
			a := new(big.Int).Abs(v)
			if a.Cmp(new(big.Int).Lsh(big.NewInt(8), 50)) > 0 {
				return errCrossGridKernel
			}
			sum.Add(sum, a)
		}
		if sum.Cmp(bound) > 0 {
			return errCrossGridKernel
		}
	}
	return nil
}

func (p crossGridKernelPlan) sourceCount() int { return p.Rows*2*(p.Predictors+1) + 2*p.Owners }

// Derive f100 shares without reconstruction, truncation or floating point.
// Inputs are copied; the caller retains custody of its original source shares.
func crossGridKernelPrivateInput(p crossGridKernelPlan, source []*big.Int, garbler bool) ([]*big.Int, error) {
	if p.validate() != nil || len(source) != p.sourceCount() {
		return nil, errCrossGridKernel
	}
	out := make([]*big.Int, 0, len(source)+p.Rows*len(p.Beta))
	for _, v := range source {
		if v == nil || v.Sign() < 0 || v.BitLen() > 128 {
			return nil, errCrossGridKernel
		}
		out = append(out, new(big.Int).Set(v))
	}
	modulus := exactGCModulus(128)
	for r := 0; r < p.Rows; r++ {
		for _, beta := range p.Beta {
			dot := new(big.Int)
			if garbler {
				dot.SetString(beta[0], 10)
				dot.Lsh(dot, 50)
			}
			for k := 0; k < p.Predictors; k++ {
				b, _ := new(big.Int).SetString(beta[k+1], 10)
				dot.Add(dot, new(big.Int).Mul(source[r*2*(p.Predictors+1)+2*k], b))
			}
			out = append(out, dot.Mod(dot, modulus))
		}
	}
	return out, nil
}

// Round a signed 128-bit integer once, nearest with ties to even. Arithmetic
// right shift gives floor, including negative inputs; the unsigned low bits
// give its nonnegative remainder. Source checks prove |dot|<2^105.
func crossGridKernelRoundSource(name string, shift int) string {
	half := new(big.Int).Lsh(big.NewInt(1), uint(shift-1))
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(shift)), big.NewInt(1))
	return fmt.Sprintf(`func %s(v int128) int64 {
 q:=int64(v >> %d)
 r:=uint128(v) & %s
 if r>%s || (r==%s && (q & 1)!=0) {q=q+1}
 return q
}
`, name, shift, mask, half, half)
}

func crossGridKernelSource(p crossGridKernelPlan) (string, error) {
	if p.validate() != nil {
		return "", errCrossGridKernel
	}
	profiles, err := crossGridKernelProfilesLoad()
	if err != nil {
		return "", err
	}
	q := 26
	var profile string
	if p.Family == "binomial" {
		q = 16
		for _, v := range profiles.Binomial {
			if v.A == p.A {
				profile = crossGridPWSource(v)
			}
		}
		profile = strings.Replace(profile, "func main(g [2]uint32, e uint32)", "func nonlinear(g [2]uint32, e uint32)", 1)
	} else {
		profile = crossGridExpReducedSource(profiles.Poisson)
		profile = strings.Replace(profile, "func main(g [2]uint64,e uint32)", "func nonlinear(g [2]uint64,e uint32)", 1)
	}
	var s strings.Builder
	s.WriteString(profile)
	s.WriteString(crossGridKernelRoundSource("rounddot", 100-q))
	if q > p.GridBits {
		s.WriteString(crossGridKernelRoundSource("roundloss", q-p.GridBits))
	}
	if p.Family == "poisson" {
		// Log-factorial selected once per row. The public table is interval-rounded.
		s.WriteString("func logfactor(y uint16) int64 {\n v:=int64(0)\n")
		for y := 2; y <= p.MaxOutcome; y++ {
			fmt.Fprintf(&s, "if y==%d {v=%d}\n", y, profiles.LogFactorial[y]<<10)
		}
		s.WriteString("return v\n}\n")
	}
	n := p.sourceCount() + p.Rows*len(p.Beta)
	fmt.Fprintf(&s, "func main(g [%d]uint128,e [%d]uint128) [%d]uint128 {\n var out [%d]uint128\n", n+len(p.Beta)+1, n, len(p.Beta)+1, len(p.Beta)+1)
	fmt.Fprintf(&s, "var sums [%d]uint64\n", len(p.Beta))
	alignStart := p.Rows * 2 * (p.Predictors + 1)
	fmt.Fprintf(&s, "a0:=g[%d]^e[%d]\n a1:=g[%d]^e[%d]\n aligned:=(a0!=0 || a1!=0)\n", alignStart, alignStart, alignStart+1, alignStart+1)
	for k := 1; k < p.Owners; k++ {
		i := alignStart + 2*k
		fmt.Fprintf(&s, "aligned=aligned && (g[%d]^e[%d])==a0 && (g[%d]^e[%d])==a1\n", i, i, i+1, i+1)
	}
	for r := 0; r < p.Rows; r++ {
		fmt.Fprintf(&s, "ok%d:=aligned\n", r)
		for k := 0; k <= p.Predictors; k++ {
			i := r*2*(p.Predictors+1) + 2*k
			bound := uint64(1 << 50)
			if k == p.Predictors {
				bound = uint64(p.MaxOutcome)
			}
			fmt.Fprintf(&s, "x%d_%d:=g[%d]+e[%d]\n ok%d=ok%d && x%d_%d<=%d && (g[%d]+e[%d])==1\n", r, k, i, i, r, r, r, k, bound, i+1, i+1)
		}
		fmt.Fprintf(&s, "y%d:=uint16(x%d_%d & %d)\n if !ok%d {y%d=0}\n", r, r, p.Predictors, (1<<bits.Len(uint(p.MaxOutcome)))-1, r, r)
		if p.Family == "poisson" {
			fmt.Fprintf(&s, "lf%d:=logfactor(y%d)\n", r, r)
		}
		for j := range p.Beta {
			id := fmt.Sprintf("%d_%d", r, j)
			i := p.sourceCount() + r*len(p.Beta) + j
			fmt.Fprintf(&s, "dot%s:=int128(g[%d]+e[%d])\n if !ok%d {dot%s=0}\n eta%s:=int32(rounddot(dot%s))\n", id, i, i, r, id, id, id)
			lim := int64(p.A) << q
			fmt.Fprintf(&s, "if eta%s < -%d {eta%s= -%d}\n if eta%s > %d {eta%s=%d}\n", id, lim, id, lim, id, lim, id, lim)
			if p.Family == "binomial" {
				fmt.Fprintf(&s, "var in%s [2]uint32\n in%s[0]=uint32(eta%s+%d)\n v%s,_:=nonlinear(in%s,0)\n loss%s:=int32(v%s)\n if y%d==1 {loss%s=loss%s-eta%s}\n", id, id, id, lim, id, id, id, id, r, id, id, id)
			} else {
				fmt.Fprintf(&s, "var in%s [2]uint64\n in%s[0]=uint64(uint32(eta%s))\n v%s,_:=nonlinear(in%s,0)\n loss%s:=int64(v%s << 10)-int64(y%d)*int64(eta%s)+lf%d\n", id, id, id, id, id, id, id, r, id, r)
			}
			fmt.Fprintf(&s, "if loss%s<0 || !ok%d {loss%s=0}\n", id, r, id)
			if q > p.GridBits {
				fmt.Fprintf(&s, "quant%s:=uint64(roundloss(int128(loss%s)))\n", id, id)
			} else {
				fmt.Fprintf(&s, "quant%s:=uint64(loss%s)<<%d\n", id, id, p.GridBits-q)
			}
			fmt.Fprintf(&s, "if quant%s>%d {quant%s=%d}\n sums[%d]=sums[%d]+quant%s\n", id, p.Caps[j], id, p.Caps[j], j, j, id)
		}
	}
	for j := range p.Beta {
		fmt.Fprintf(&s, "out[%d]=uint128(sums[%d])-g[%d]\n", j, j, n+j)
	}
	fmt.Fprintf(&s, "out[%d]=g[%d]\n if aligned {out[%d]=out[%d]^1}\n", len(p.Beta), n+len(p.Beta), len(p.Beta), len(p.Beta))
	s.WriteString("return out\n}\n")
	return s.String(), nil
}

func crossGridKernelCompile(p crossGridKernelPlan) (*circuit.Circuit, error) {
	source, err := crossGridKernelSource(p)
	if err != nil {
		return nil, errCrossGridKernel
	}
	c, _, err := compiler.New(crossGridPWCompilerParams()).Compile(source, nil)
	if err != nil {
		return nil, errCrossGridKernel
	}
	return crossGridPWOptimize(c), nil
}
