package main

import (
	"fmt"
	"math/big"
	"strings"
)

// Exact frozen f100 -> q64 -> q16 boundary. Bound is a signed public integer
// predictor cap (GLMM=1, GEE=4); invalid batches zero outputs and validity.
// Caller includes this private validity in all subsequent profile receipts.
func groupedPredictorCompile(count, bound int) (*primitiveVProgram, error) {
	if count < 1 || count > 32 || (bound != 1 && bound != 4) {
		return nil, primitiveVError()
	}
	var b strings.Builder
	b.WriteString("package main\n")
	for _, shift := range []int{36, 48} {
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(shift)), big.NewInt(1))
		half := new(big.Int).Lsh(big.NewInt(1), uint(shift-1))
		fmt.Fprintf(&b, `func round%d(x int192) int192 {
 negative:=x<0
 a:=uint108(x)
 if negative { a=uint108(-x) }
 q:=a>>%d
 r:=a & uint108(%s)
 if r>uint108(%s) || (r==uint108(%s) && (q & 1)==1) { q=q+1 }
 value:=int192(q)
 if negative { value=-value }
 return value
}
`, shift, shift, mask, half, half)
	}
	fmt.Fprintf(&b, "func main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=true\n", 2*count+1, count, count+1, count+1)
	limit := new(big.Int).Lsh(big.NewInt(int64(bound)), 100)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "x%d:=g[%d]+e[%d]\nok%d:=x%d>=-int192(%s) && x%d<=int192(%s)\nvalid=valid && ok%d\nif !ok%d { x%d=0 }\nvalue%d:=round48(round36(x%d))\n", i, i, i, i, i, limit, i, limit, i, i, i, i, i)
	}
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "if !valid { value%d=0 }\nout[%d]=value%d-g[%d]\n", i, i, i, count+i)
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", count, 2*count)
	return primitiveVCompile(b.String(), 192, 2*count+1, count, count+1)
}
