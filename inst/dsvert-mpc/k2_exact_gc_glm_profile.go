package main

import (
	"fmt"
	"github.com/markkurossi/mpc/compiler/utils"
	"math/bits"
	"strings"
)

// A balanced public-table mux uses index bits, avoiding K full-width compares.
func crossGridPWLookup(p crossGridPWProfile, column int) string {
	var out strings.Builder
	fmt.Fprintf(&out, "func table%d(i uint8) uint32 {\n", column)
	for j, c := range p.Coefficients {
		fmt.Fprintf(&out, "v0_%d := uint32(%d)\n", j, c[column])
	}
	for level, n := 1, p.Pieces/2; n > 0; level, n = level+1, n/2 {
		for j := 0; j < n; j++ {
			fmt.Fprintf(&out, "v%d_%d := v%d_%d\nif (i & %d) != 0 { v%d_%d = v%d_%d }\n", level, j, level-1, 2*j, 1<<(level-1), level, j, level-1, 2*j+1)
		}
	}
	fmt.Fprintf(&out, "return v%d_0\n}\n", bits.Len(uint(p.Pieces))-1)
	return out.String()
}

func crossGridPWSource(p crossGridPWProfile) string {
	var out strings.Builder
	out.WriteString("package main\n")
	for c := 0; c < 3; c++ {
		out.WriteString(crossGridPWLookup(p, c))
	}
	shift := bits.TrailingZeros(uint(p.Width))
	fmt.Fprintf(&out, `func rounded(x uint64) uint32 {
 q := uint32(x >> %d)
 r := uint32(x & %d)
 if r > %d || (r == %d && (q & 1) != 0) { q = q + 1 }
 return q
}
func main(g [2]uint32, e uint32) (uint32, bool) {
 x := g[0] + e
 valid := x <= %d
 if !valid { x = 0 }
 i := uint8(x >> %d)
 if i == %d { i = %d }
 r := x - uint32(i)*%d
 v := table1(i) + rounded(uint64(table2(i))*uint64(r))
 v = table0(i) + rounded(uint64(v)*uint64(r))
 if !valid { v = 0 }
 return v - g[1], valid
}
`, shift, p.Width-1, p.Width/2, p.Width/2, 2*p.A*65536, shift, p.Pieces, p.Pieces-1, p.Width)
	return out.String()
}

type crossGridPWProfile struct {
	TestVectors  [][2]uint32 `json:"test_vectors"`
	Identity     string      `json:"identity"`
	Family       string      `json:"family"`
	A            int         `json:"a"`
	Pieces       int         `json:"pieces"`
	FractionBits int         `json:"fraction_bits"`
	Width        int         `json:"interval_integer_width"`
	Coefficients [][3]int64  `json:"coefficients"`
	LossError    string      `json:"loss_error"`
}

func crossGridExpReducedSource(p crossGridExpReducedProfile) string {
	var s strings.Builder
	s.WriteString("package main\n")
	s.WriteString("func scale(v uint32,n uint8) uint64 {\n out:=uint64(v)<<12\n guard:=false\n sticky:=false\n")
	for b := 0; b < 6; b++ {
		d := 1 << b
		fmt.Fprintf(&s, "if (n & %d)!=0 {\n sticky=sticky || guard || (out & %d)!=0\n guard=(out & %d)!=0\n out=out >> %d\n}\n", d, (uint64(1)<<(d-1))-1, uint64(1)<<(d-1), d)
	}
	s.WriteString("if guard && (sticky || (out & 1)!=0) {out=out+1}\n return out\n}\n")
	table := crossGridPWProfile{Pieces: p.Pieces, Coefficients: p.Coefficients}
	for col := 0; col < 3; col++ {
		s.WriteString(crossGridPWLookup(table, col))
	}
	shift := 0
	for 1<<shift < p.Width {
		shift++
	}
	fmt.Fprintf(&s, `func roundpoly(x uint64) uint32 {
 q:=uint32(x >> %d)
 r:=uint32(x & %d)
 if r > %d || (r == %d && (q & 1) != 0) {q=q+1}
 return q
}
func main(g [2]uint64,e uint32) (uint64,bool) {
 eta:=int32(uint32(g[0])+e)
 valid:=eta >= -1073741824 && eta <= 1073741824
 if !valid {eta=0}
 neg:=eta<0
 magnitude:=uint32(eta)
 if neg {magnitude=uint32(-eta)}
 raw:=uint64(magnitude)*%d
 k:=int32(raw >> 56)
 tail:=raw & 72057594037927935
 if tail > 36028797018963968 || (tail == 36028797018963968 && (k & 1)!=0) {k=k+1}
 residual:=int32(uint64(magnitude)*16-uint64(uint32(k))*%d)
 if neg {
 k=-k
 residual=-residual
 }
 rneg:=residual<0
 ar:=uint32(residual)
 if rneg {ar=uint32(-residual)}
 rq:=int32(ar >> 6)
 rt:=uint32(ar & 63)
 if rt > 32 || (rt == 32 && (rq & 1)!=0) {rq=rq+1}
 if rneg {rq=-rq}
 offset:=uint32(rq+8388608)
 i:=uint8(offset >> %d)
 r:=offset & %d
 v:=table1(i)+roundpoly(uint64(table2(i))*uint64(r))
 v=table0(i)+roundpoly(uint64(v)*uint64(r))
 out:=scale(v,uint8(23-k))
 if !valid {out=0}
 return out-g[1],valid
}
`, shift, p.Width-1, p.Width/2, p.Width/2, p.InvLn2, p.Ln2, shift, p.Width-1)
	return s.String()
}

type crossGridExpReducedProfile struct {
	Identity      string            `json:"identity"`
	Pieces        int               `json:"pieces"`
	Width         int               `json:"width"`
	Ln2           int64             `json:"ln2"`
	InvLn2        int64             `json:"inv_ln2"`
	Coefficients  [][3]int64        `json:"coefficients"`
	TestVectors   [][2]int64        `json:"test_vectors"`
	LossErrors    map[string]string `json:"loss_errors"`
	RelativeError string            `json:"relative_exp_error"`
}

func crossGridPWCompilerParams() *utils.Params {
	p := utils.NewParams()
	p.OptPruneGates = true
	p.CircMultArrayTreshold = 128
	return p
}
