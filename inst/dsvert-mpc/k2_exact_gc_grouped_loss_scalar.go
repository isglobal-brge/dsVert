package main

import (
	"fmt"
	"strings"
)

// A chunk contains scalar profiles only: input conversion, validity masking,
// outcome products, and final clipping remain explicit fusion obligations.
// One aggregate private validity coordinate must accompany every output batch.
func groupedScalarCompile(name string, count int) (*primitiveVProgram, error) {
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
	fmt.Fprintf(&b, "package main\n%s\nfunc main(g [%d]int32,e [%d]int32) [%d]int32 {\nvar out [%d]int32\nvalid:=true\n", groupedProfileSource(), 2*count+1, count, count+1, count+1)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "x%d:=g[%d]+e[%d]\nok%d:=x%d>=%d && x%d<=%d\nvalid=valid && ok%d\nif !ok%d { x%d=%d }\nvalue%d:=%s(x%d)\n", i, i, i, i, i, p.Lower, i, p.Upper, i, i, i, p.Lower, i, function, i)
	}
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "if !valid { value%d=0 }\nout[%d]=value%d-g[%d]\n", i, i, i, count+i)
	}
	fmt.Fprintf(&b, "v:=int32(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", count, 2*count)
	return primitiveVCompile(b.String(), 32, 2*count+1, count, count+1)
}
