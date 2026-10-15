package main

// One authenticated public evaluation point, one fused protected score/curvature
// evaluation. This internal producer returns aggregate shares only. The B3
// private worker consumes them through mandatory split noise before publication.
// B1 chain authentication precedes construction of this purpose-bound plan.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

const dpIRLSStageOperation exactGCOperation = "dp-irls-fused-stage-v1"
const dpIRLSStageVersion = "dsvert-dp-irls-stage-v1"

// Beta contains signed q16 integers. A row is one signed person slot, including
// an absent padded slot; the row cap is one in this certificate. The signed
// root commits source provenance and person layout. All digests are lowercase.
// Fields are in canonical lexical JSON order, shared with the R admission ABI.
type dpIRLSStagePlan struct {
	Beta              []string `json:"beta"`
	CertificateDigest string   `json:"certificate_digest"`
	Family            string   `json:"family"`
	Intercept         bool     `json:"intercept"`
	OffsetMode        string   `json:"offset_mode"`
	Owners            int      `json:"owners"`
	P                 int      `json:"p"`
	PointDigest       string   `json:"point_digest"`
	Predecessor       string   `json:"predecessor"`
	Purpose           string   `json:"purpose"`
	Root              string   `json:"root"`
	Rows              int      `json:"rows"`
	SourceABI         string   `json:"source_abi,omitempty"`
	StageID           string   `json:"stage_id"`
	StageIndex        int      `json:"stage_index"`
	Version           string   `json:"version"`
}

func (p dpIRLSStagePlan) pointDigest() string {
	point := struct {
		Beta        []string `json:"beta"`
		Predecessor string   `json:"predecessor"`
		Purpose     string   `json:"purpose"`
		Root        string   `json:"root"`
		StageID     string   `json:"stage_id"`
		StageIndex  int      `json:"stage_index"`
	}{p.Beta, p.Predecessor, p.Purpose, p.Root, p.StageID, p.StageIndex}
	encoded, _ := json.Marshal(point)
	digest := sha256.Sum256(append([]byte("dsvert-dp-irls-public-point-v1\x00"), encoded...))
	return hex.EncodeToString(digest[:])
}

func (p dpIRLSStagePlan) validate() error {
	if (p.SourceABI != "" && p.SourceABI != dpIRLSB3SourceABI) || p.Version != dpIRLSStageVersion || p.P != 3 || p.Rows < 1 || p.Rows > 64 || p.Owners != 2 || (p.OffsetMode != "none" && p.OffsetMode != "offset") || p.StageIndex < 0 || p.StageIndex > 10000 || (p.Purpose != "optimizer" && p.Purpose != "terminal-audit") || len(p.Beta) != p.P {
		return errCrossGridKernel
	}
	for _, d := range []string{p.Root, p.StageID, p.Predecessor, p.PointDigest, p.CertificateDigest} {
		if !formalGLMIsSHA256(d) {
			return errCrossGridKernel
		}
	}
	for _, v := range p.Beta {
		x, ok := new(big.Int).SetString(v, 10)
		if !ok || x.String() != v || !x.IsInt64() || x.Int64() < -65536 || x.Int64() > 65536 {
			return errCrossGridKernel
		}
	}
	certificate, err := dpIRLSProducerCertificate(p.Family, p.P, p.Rows, 1)
	if err != nil || p.CertificateDigest != dpIRLSProducerCertificateDigest(certificate) || p.PointDigest != p.pointDigest() {
		return errCrossGridKernel
	}
	return nil
}

func dpIRLSStageKernelPlan(p dpIRLSStagePlan) (crossGridKernelPlan, error) {
	if p.validate() != nil {
		return crossGridKernelPlan{}, errCrossGridKernel
	}
	p.Beta = append([]string(nil), p.Beta...)
	return crossGridKernelPlan{IRLS: &p}, nil
}

func (p crossGridKernelPlan) outputCount() int {
	if p.IRLS != nil {
		return p.IRLS.P + p.IRLS.P*(p.IRLS.P+1)/2
	}
	return len(p.Beta)
}
func (p crossGridKernelPlan) operation() exactGCOperation {
	if p.IRLS != nil {
		return dpIRLSStageOperation
	}
	return crossGridKernelOperation
}

// This version clamps reconstructed signed Ring128 values before narrowing.
// With q16 |X|,|beta|,|offset|<=65536 and mu<=55*65536, every
// deterministic intermediate fits signed int64 (the largest H product <2^54).
// No source share is interpreted or compared outside the circuit.
func dpIRLSStageSource(p dpIRLSStagePlan) (string, error) {
	if p.validate() != nil {
		return "", errCrossGridKernel
	}
	certificate, err := dpIRLSProducerCertificate(p.Family, p.P, p.Rows, 1)
	if err != nil {
		return "", err
	}
	d := p.P + p.P*(p.P+1)/2
	stride := p.P + 3
	if p.SourceABI == dpIRLSB3SourceABI {
		stride++
	}
	n := p.Rows*stride + 2*p.Owners
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(dpIRLSClampUnitSource())
	b.WriteString(groupedProfileSource())
	for _, round := range []struct {
		name  string
		shift int
	}{{"irlsRoundEta", 16}, {"irlsRoundWeight", 16}, {"irlsRoundScore", 20}, {"irlsRoundCurvature", 36}} {
		// int64 arithmetic shift and low-bit remainder implement nearest even for
		// both signs. This is the only person-coordinate lattice rounding.
		half := int64(1) << uint(round.shift-1)
		fmt.Fprintf(&b, "func %s(v int64) int64 { q:=v >> %d\n r:=uint64(v)&%d\n if r>%d || (r==%d && (q&1)!=0) {q=q+1}\n return q\n}\n", round.name, round.shift, 2*half-1, half, half)
	}
	fmt.Fprintf(&b, "func main(g [%d]uint128,e [%d]uint128) [%d]uint128 {\nvar out [%d]uint128\nvar sums [%d]int64\n", n+d+1, n, d+1, d+1, d)
	alignment := p.Rows * stride
	fmt.Fprintf(&b, "a0:=g[%d]^e[%d]\n a1:=g[%d]^e[%d]\n valid:=(a0!=0 || a1!=0)\n", alignment, alignment, alignment+1, alignment+1)
	for owner := 1; owner < p.Owners; owner++ {
		i := alignment + 2*owner
		fmt.Fprintf(&b, "valid=valid && (g[%d]^e[%d])==a0 && (g[%d]^e[%d])==a1\n", i, i, i+1, i+1)
	}
	b.WriteString("aligned:=valid\n")
	for row := 0; row < p.Rows; row++ {
		base := row * stride
		fmt.Fprintf(&b, "present%d:=g[%d]+e[%d]\n valid=valid && (present%d==0 || present%d==1)\n active%d:=present%d==1 && aligned\n", row, base, base, row, row, row, row)
		if p.SourceABI == dpIRLSB3SourceABI {
			fmt.Fprintf(&b, "other%d:=g[%d]+e[%d]\n active%d=active%d && other%d==1\n", row, base+1, base+1, row, row, row)
			base++
		}
		for j := 0; j < p.P; j++ {
			i := base + 1 + j
			if p.SourceABI == dpIRLSB3SourceABI {
				fmt.Fprintf(&b, "active%d=active%d && irlsInUnit(g[%d]+e[%d])\n", row, row, i, i)
			}
			fmt.Fprintf(&b, "x%d_%d:=irlsClampUnit(g[%d]+e[%d])\n", row, j, i, i)
		}
		if p.Intercept {
			fmt.Fprintf(&b, "x%d_0=65536\n", row)
		}
		y, o := base+p.P+1, base+p.P+2
		fmt.Fprintf(&b, "rawY%d:=g[%d]+e[%d]\n", row, y, y)
		if p.Family == "binomial" {
			fmt.Fprintf(&b, "binary%d:=rawY%d==0 || rawY%d==1\n valid=valid && (present%d!=1 || binary%d)\n active%d=active%d && binary%d\n if !binary%d {rawY%d=0}\n", row, row, row, row, row, row, row, row, row, row)
		} else {
			if p.SourceABI == dpIRLSB3SourceABI {
				fmt.Fprintf(&b, "active%d=active%d && rawY%d<=8\n", row, row, row)
			}
			fmt.Fprintf(&b, "if (rawY%d >> 127)!=0 {rawY%d=0}\n if rawY%d>8 {rawY%d=8}\n", row, row, row, row)
		}
		if p.SourceABI == dpIRLSB3SourceABI {
			fmt.Fprintf(&b, "active%d=active%d && irlsInUnit(g[%d]+e[%d])\n", row, row, o, o)
		}
		fmt.Fprintf(&b, "y%d:=int32(rawY%d)\n offset%d:=irlsClampUnit(g[%d]+e[%d])\n dot%d:=int64(offset%d)*65536\n", row, row, row, o, o, row, row)
		if p.OffsetMode == "none" {
			fmt.Fprintf(&b, "dot%d=0\n", row)
		}
		for j, beta := range p.Beta {
			// MPCL widens a negative int32 literal to int64 without sign
			// extension. Select public subtraction and multiply by |beta|.
			op := "+"
			if strings.HasPrefix(beta, "-") {
				op, beta = "-", strings.TrimPrefix(beta, "-")
			}
			fmt.Fprintf(&b, "dot%d=dot%d%sint64(x%d_%d)*int64(%s)\n", row, row, op, row, j, beta)
		}
		fmt.Fprintf(&b, "eta%d:=int32(irlsRoundEta(dot%d))\n if eta%d < -262144 {eta%d= -262144}\n if eta%d>262144 {eta%d=262144}\n", row, row, row, row, row, row)
		if p.Family == "binomial" {
			fmt.Fprintf(&b, "mu%d:=groupedProfileSigmoid(eta%d)\n if mu%d<0 {mu%d=0}\n if mu%d>65536 {mu%d=65536}\n w%d:=int32(irlsRoundWeight(int64(mu%d)*int64(65536-mu%d)))\n if w%d<0 {w%d=0}\n if w%d>16384 {w%d=16384}\n", row, row, row, row, row, row, row, row, row, row, row, row, row)
		} else {
			fmt.Fprintf(&b, "mu%d:=groupedRangeExp(eta%d)\n if mu%d<1200 {mu%d=1200}\n if mu%d>3604480 {mu%d=3604480}\n w%d:=mu%d\n", row, row, row, row, row, row, row, row)
		}
		fmt.Fprintf(&b, "r%d:=y%d*65536-mu%d\n if !active%d {r%d=0\n w%d=0}\n", row, row, row, row, row, row)
		for j := 0; j < p.P; j++ {
			fmt.Fprintf(&b, "sums[%d]=sums[%d]+irlsRoundScore(int64(x%d_%d)*int64(r%d))\n", j, j, row, j, row)
		}
		index := p.P
		for j := 0; j < p.P; j++ {
			for k := j; k < p.P; k++ {
				fmt.Fprintf(&b, "h%d_%d:=int64(w%d)*int64(x%d_%d)*int64(x%d_%d)\n sums[%d]=sums[%d]+irlsRoundCurvature(h%d_%d)\n", row, index, row, row, j, row, k, index, index, row, index)
				index++
			}
		}
	}
	for j := 0; j < d; j++ {
		translation := certificate.GTranslation
		if j >= p.P {
			translation = certificate.HTranslation
		}
		fmt.Fprintf(&b, "out[%d]=uint128(sums[%d]+%d)-g[%d]\n", j, j, translation, n+j)
	}
	fmt.Fprintf(&b, "out[%d]=g[%d]\n if valid {out[%d]=out[%d]^1}\n return out\n}\n", d, n+d, d, d)
	return b.String(), nil
}

// MPCL compares signed words wider than 64 bits against negative literals
// incorrectly (zero < -65536 at int128). Decode the sign and magnitude in
// unsigned Ring128 first, then narrow only the proven bounded magnitude.
func dpIRLSClampUnitSource() string {
	return `func irlsInUnit(v uint128) bool {
 negative := (v >> 127) != 0
 magnitude := v
 if negative { magnitude = uint128(0)-v }
 return magnitude<=65536
}
func irlsClampUnit(v uint128) int32 {
 negative := (v >> 127) != 0
 magnitude := v
 if negative { magnitude = uint128(0)-v }
 if magnitude > 65536 { magnitude = 65536 }
 value := int32(magnitude)
 if negative { value = -value }
 return value
}
`
}
