package main

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const exactGCMultinomialProfileV1 = "cross-grid-multinomial-piecewise-q16-v1"
const exactGCFamilyLog2Q64 = "12786308645202655660"

// Public source registration only: this does not authorize a release, consume
// protected input, install a worker handler, or enable a plaintext fallback.
type exactGCFamilyLossRegistration struct {
	Family, Version, Profile, ProfileSHA256, CertificateSHA256 string
	Source                                                     func(exactGCFamilyLossSpec) (string, error)
}

type exactGCFamilyLossSpec struct {
	Classes  int
	GridBits int
	Cap      int64
	// Ordinal candidate thresholds, canonical signed decimal f50 integers.
	Thresholds []string
}

func exactGCRegisterMultinomialLossV1() exactGCFamilyLossRegistration {
	return exactGCFamilyLossRegistration{"multinomial", "multinomial_grid_cross_v1", exactGCMultinomialProfileV1, "fc0d85381d6effb30776848ccf301f4b9b18fc5dc55bdc80a8503f7d8916fcef", "b480edd4ab1ad8f2403026f2d718bfd093068816160a893ee0f7935056251f67", exactGCMultinomialLossSource}
}

func exactGCFamilyLossReject() error { return errors.New("cross-grid family contract rejected") }

func exactGCFamilyLossValidate(s exactGCFamilyLossSpec) error {
	if s.Classes < 2 || s.Classes > 8 || s.GridBits < 8 || s.GridBits > 18 || s.Cap < 1 || s.Cap > 9007199254740991 {
		return exactGCFamilyLossReject()
	}
	return nil
}

// Frozen q64 coefficients used ONLY to derive candidate-public ordinal gap
// constants. These are never emitted into a protected-input circuit.
var exactGCFamilyExpQuarterQ64 = []string{
	"259015597631784680005",
	"451977499337582261846",
	"305335901457648295612",
	"164602533259795630681",
	"72955854502642699357",
	"27273865960703490715",
	"8782052242163897674",
	"2477483159299544341",
	"620931246824222199",
	"139859641843649005",
	"28584528427591119",
	"5344213949102563",
	"920362102824912",
	"146875015503060",
	"21832596217955",
	"3036734537708",
	"396823010603",
	"48890693171",
	"5697465236",
	"629811174",
	"66212386",
	"6635773",
	"635331",
	"58226",
	"5117",
	"432",
	"35",
	"3",
	"0",
	"0",
	"0",
	"0",
	"0"}

func exactGCFamilyInteger(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid public family constant")
	}
	return v
}

// The ABI remains Ring192/f100. Only the signed input addition, domain guard,
// f100→f16 rounding and final mask use the ABI width; the profile is uint32.
func exactGCFamilyMathSource() string {
	var b strings.Builder
	b.WriteString(`package main
func abs192(x uint192) uint192 { if (x >> 191) != 0 { return uint192(0)-x }; return x }
func eta16(x uint192) uint32 {
 a:=abs192(x)
 q:=a>>84
 r:=a&uint192(19342813113834066795298815)
 if r>uint192(9671406556917033397649408) || (r==uint192(9671406556917033397649408) && (q&1)!=0) { q=q+1 }
 v:=uint32(q)
 if (x>>191)!=0 { v=uint32(0)-v }
 return v
}
func abs32(x uint32) uint32 { if (x>>31)!=0 { return uint32(0)-x }; return x }
func less32(x uint32,y uint32) bool { return (x^uint32(2147483648))<(y^uint32(2147483648)) }
func rnd16(x uint32) uint32 {
 a:=abs32(x)
 q:=a>>16
 r:=a&uint32(65535)
 if r>uint32(32768) || (r==uint32(32768) && (q&1)!=0) { q=q+1 }
 if (x>>31)!=0 { q=uint32(0)-q }
 return q
}
`)
	exactGCFamilyEmitPolynomial(&b, "exppoly", exactGCFamilyExpProfile, 14)
	exactGCFamilyEmitPolynomial(&b, "logpoly", exactGCFamilyLogProfile, 10)
	exactGCFamilyEmitPolynomial(&b, "softpoly", exactGCFamilySoftProfile, 14)
	b.WriteString(`func exp16(x uint32) uint32 {
 if x==uint32(0) { return uint32(65536) }
 if less32(x,uint32(4293918720)) { return uint32(0) }
 return exppoly(x+uint32(1048576))
}
func log16(x uint32) uint32 {
 m:=x
 exponent:=uint32(0)
`)
	for k := 1; k <= 3; k++ {
		fmt.Fprintf(&b, "if x>=uint32(%d) { m=x>>%d\nr%d:=x&uint32(%d)\nif r%d>uint32(%d) || (r%d==uint32(%d) && (m&1)!=0) { m=m+1 }\nexponent=uint32(%d) }\n", 65536<<k, k, k, (1<<k)-1, k, 1<<(k-1), k, 1<<(k-1), k)
	}
	b.WriteString(`return logpoly(m-uint32(65536))+exponent*uint32(45426)
}
func soft16(x uint32) uint32 {
 v:=softpoly(abs32(x))
 if (x>>31)==0 { v=v+x }
 return v
}
`)
	return strings.ReplaceAll(b.String(), ";", "\n")
}

// Every coefficient and breakpoint is public. Exactly two signed 32-bit
// multiplications evaluate a selected quadratic. Local t<=2^14 ensures the
// signed products fit 32 bits; no wide protected transcendental remains.
func exactGCFamilyEmitPolynomial(b *strings.Builder, name string, table [64][3]int64, shift uint) {
	fmt.Fprintf(b, "func %s(x uint32) uint32 {\ni:=x>>%d\nt:=x&uint32(%d)\nif i>=uint32(64) { i=uint32(63); t=uint32(%d) }\n", name, shift, (1<<shift)-1, 1<<shift)
	b.WriteString("a:=uint32(0)\nb:=uint32(0)\nc:=uint32(0)\n")
	var selectRow func(int, int)
	selectRow = func(lo, hi int) {
		if hi-lo == 1 {
			v := table[lo]
			fmt.Fprintf(b, "a=uint32(%d)\nb=uint32(%d)\nc=uint32(%d)\n", uint32(v[2]), uint32(v[1]), uint32(v[0]))
			return
		}
		mid := (lo + hi) / 2
		fmt.Fprintf(b, "if i<uint32(%d) {\n", mid)
		selectRow(lo, mid)
		b.WriteString("} else {\n")
		selectRow(mid, hi)
		b.WriteString("}\n")
	}
	selectRow(0, len(table))
	b.WriteString("return rnd16((rnd16(a*t)+b)*t)+c\n}\n")
}

// Input order is frozen: f100 partial-predictor shares, outcome share,
// complete-case/alignment bit share, then garbler-only loss and guard masks.
// Both outputs MUST remain shared in the fused release producer.
func exactGCMultinomialLossSource(s exactGCFamilyLossSpec) (string, error) {
	if exactGCFamilyLossValidate(s) != nil || len(s.Thresholds) != 0 {
		return "", exactGCFamilyLossReject()
	}
	n := s.Classes - 1
	var b strings.Builder
	b.WriteString(exactGCFamilyMathSource())
	fmt.Fprintf(&b, "func main(g [%d]uint192,e [%d]uint192) [2]uint192 {\n", n+4, n+2)
	fmt.Fprintf(&b, "y:=g[%d]+e[%d]\nvalid:=g[%d]+e[%d]\nguard:=y<uint192(%d) && valid<=uint192(1)\n", n, n, n+1, n+1, s.Classes)
	b.WriteString("maximum:=uint32(0)\nobserved:=uint32(0)\n")
	bound := new(big.Int).Lsh(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 50), big.NewInt(9)), 50)
	for c := 0; c < n; c++ {
		fmt.Fprintf(&b, "dot%d:=g[%d]+e[%d]\nok%d:=abs192(dot%d)<=uint192(%s)\nguard=guard && ok%d\nif !ok%d { dot%d=uint192(0) }\nv%d:=eta16(dot%d)\nif less32(maximum,v%d) { maximum=v%d }\nif y==uint192(%d) { observed=v%d }\n", c, c, c, c, c, bound, c, c, c, c, c, c, c, c+1, c)
	}
	b.WriteString("sum:=exp16(uint32(0)-maximum)\n")
	for c := 0; c < n; c++ {
		fmt.Fprintf(&b, "sum=sum+exp16(v%d-maximum)\n", c)
	}
	b.WriteString("loss:=log16(sum)+maximum-observed\n")
	exactGCFamilyFinishSource(&b, s, n+2)
	return strings.ReplaceAll(b.String(), ";", "\n"), nil
}

func exactGCFamilyFinishSource(b *strings.Builder, s exactGCFamilyLossSpec, mask int) {
	b.WriteString("if (loss>>31)!=0 { loss=uint32(0) }\n")
	if s.GridBits < 16 {
		k := 16 - s.GridBits
		fmt.Fprintf(b, "q:=loss>>%d\nr:=loss&uint32(%d)\nif r>uint32(%d) || (r==uint32(%d) && (q&1)!=0) { q=q+1 }\n", k, (1<<k)-1, 1<<(k-1), 1<<(k-1))
	} else {
		fmt.Fprintf(b, "q:=loss<<%d\n", s.GridBits-16)
	}
	if s.Cap < 1<<32 {
		fmt.Fprintf(b, "if q>uint32(%d) { q=uint32(%d) }\n", s.Cap, s.Cap)
	}
	fmt.Fprintf(b, "if valid!=uint192(1) || !guard { q=uint32(0) }\nvar out [2]uint192\nout[0]=uint192(q)-g[%d]\nout[1]=g[%d]&1\nif guard { out[1]=out[1]^uint192(1) }\nreturn out\n}\n", mask, mask+1)
}
