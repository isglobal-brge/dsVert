package main

import "fmt"

// Terminal private Ring64 -> Ring128 conversion for ONE Cox coordinate.
// Inputs are local q/validity shares embedded as unsigned 64-bit words, plus
// fresh full-width garbler output masks. Reconstruct modulo 2^64 BEFORE the
// cast; extending each input share separately would retain an unwanted carry.
// The caller must bind this source and cap to the authenticated schedule and
// conjoin the returned validity before injecting any coordinate into joint DP.
// This internal compiler does not authorize a release or open either value.
func coxLossJointDPBridgeCompile(cap uint64) (*primitiveVProgram, error) {
	if cap == 0 || cap > (1<<53)-1 {
		return nil, coxLossError()
	}
	source := fmt.Sprintf(`package main
func main(g [4]uint128,e [2]uint128) [2]uint128 {
 var out [2]uint128
 valid:=g[0]>>64==0 && g[1]>>64==0 && e[0]>>64==0 && e[1]>>64==0
 q:=uint64(g[0])+uint64(e[0])
 v:=uint64(g[1])+uint64(e[1])
 valid=valid && v==1 && q<=%d
 value:=uint128(0)
 ok:=uint128(0)
 if valid {
 value=uint128(q)
 ok=1
 }
 out[0]=value-g[2]
 out[1]=ok-g[3]
 return out
}
`, cap)
	p, err := primitiveVCompile(source, 128, 4, 2, 2)
	if err != nil {
		return nil, err
	}
	// Same finalizer ceiling as the admitted Cox kernel.
	if p.Circuit.Stats.NumNonXOR() > 4096 {
		return nil, coxLossError()
	}
	return p, nil
}
