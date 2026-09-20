package main

import (
	"fmt"
	"strings"
)

// Scalar profile bridge for exact arithmetic composition. Inputs are Ring192
// shares of CERTIFIED signed-int32 q16 arguments. Reduction modulo 2^32 is a
// local ring homomorphism; output widening happens only on GC wires, followed
// by fresh Ring192 masks. The fused adapter MUST carry the preceding wide
// input-range receipt/validity, since this bridge cannot detect a value that
// differs by 2^32. This internal emitter is not a standalone source validator.
func groupedWideScalarCompile(name string, count int) (*primitiveVProgram, error) {
	if count < 1 || count > 32 {
		return nil, primitiveVError()
	}
	p, ok := groupedProfiles[name]
	function := ""
	if name == "exp" || name == "exp_negative" {
		p.Lower, p.Upper, ok = -262144, 262144, true
		if name == "exp_negative" {
			p.Lower, p.Upper = -1048576, 0
		}
		function = "groupedRangeExp"
	}
	if !ok {
		return nil, primitiveVError()
	}
	if function == "" {
		function = groupedProfileFunction(name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "package main\n%s\nfunc main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=true\n", groupedProfileSource(), 2*count+1, count, count+1, count+1)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "x%d:=int32(g[%d])+int32(e[%d])\nok%d:=x%d>=%d && x%d<=%d\nvalid=valid && ok%d\nif !ok%d { x%d=%d }\nvalue%d:=%s(x%d)\n", i, i, i, i, i, p.Lower, i, p.Upper, i, i, i, p.Lower, i, function, i)
	}
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "if !valid { value%d=0 }\nout[%d]=int192(value%d)-g[%d]\n", i, i, i, count+i)
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", count, 2*count)
	return primitiveVCompile(b.String(), 192, 2*count+1, count, count+1)
}
