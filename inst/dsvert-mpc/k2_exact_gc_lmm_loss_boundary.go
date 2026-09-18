package main

import (
	"fmt"
	"math/big"
	"strings"
)

// Carry-correct signed Ring192 -> two Ring192 limbs (Ring384). Original low
// shares stay local; GC returns only fresh shares of -carry-sign. Thus the sum
// of low0+low1+(high0+high1)*2^192 is the signed input modulo 2^384. No private
// value, carry or sign is opened. This is a representation boundary, not a
// rescale. Public f100 beta products can then be accumulated exactly at f264.
func groupedLMMLiftCompile(count int) (*primitiveVProgram, error) {
	if count < 1 || count > 32 {
		return nil, primitiveVError()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]uint192,e [%d]uint192) [%d]uint192 {\nvar out [%d]uint192\n", 2*count, count, count, count)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "s%d:=g[%d]+e[%d]\nh%d:=g[0]-g[0]\nif s%d<g[%d] { h%d=h%d-uint192(1) }\nif int192(s%d)<0 { h%d=h%d-uint192(1) }\nout[%d]=h%d-g[%d]\n", i, i, i, i, i, i, i, i, i, i, i, i, i, count+i)
	}
	b.WriteString("return out\n}\n")
	return primitiveVCompile(b.String(), 192, 2*count, count, count)
}

// The selected q64 precision coefficient remains private. Count arrives as
// the f50 intercept-column sum, so malformed nonintegral or overflow counts
// fail the private validity output. lambda[0]=0; no count is published.
func groupedLMMPrecisionCompile(s groupedLMMSpec) (*primitiveVProgram, error) {
	if groupedLMMValidate(s) != nil {
		return nil, primitiveVError()
	}
	_, table := groupedLMMTable(s)
	var b strings.Builder
	b.WriteString("package main\nfunc main(g [3]uint192,e [1]uint192) [2]uint192 {\nn:=g[0]+e[0]\nlambda:=uint192(0)\nv:=uint192(0)\n")
	for k, entry := range table {
		value := new(big.Int).Lsh(big.NewInt(int64(k)), 50)
		fmt.Fprintf(&b, "if n==uint192(%s) { lambda=uint192(%s)\nv=uint192(1) }\n", value, entry)
	}
	b.WriteString("var out [2]uint192\nout[0]=lambda-g[1]\nout[1]=v-g[2]\nreturn out\n}\n")
	return primitiveVCompile(b.String(), 192, 3, 1, 2)
}

// Precision Gram entries are f164 and fit signed Ring192 for B<=32 and
// sigma^2>=1/4: |entry| <= 256*2^164 (generous outward bound). The products
// passed here are authenticated Beaver outputs Between[f100]*lambda[f64].
func groupedLMMPrecisionShares(m *groupedLMMMoments, s groupedLMMSpec, products []groupedWord) ([]groupedWord, error) {
	if m == nil || m.Plan.validate() != nil || groupedLMMValidate(s) != nil || s.Slots != m.Plan.Slots || len(products) != len(m.Within) || len(products) != m.Plan.Clusters*m.Plan.triangle() {
		return nil, primitiveVError()
	}
	inv, _ := groupedLMMTable(s)
	w := groupedWordFromBig(inv)
	out := make([]groupedWord, len(products))
	for i := range out {
		out[i] = m.Within[i].mul(w).sub(products[i])
	}
	return out, nil
}
func groupedWordFromBig(x *big.Int) (w groupedWord) {
	v := new(big.Int).Mod(new(big.Int).Set(x), new(big.Int).Lsh(big.NewInt(1), 192))
	for i := range w {
		w[i] = v.Uint64()
		v.Rsh(v, 64)
	}
	return
}

// Wide local public-coefficient arithmetic. No secret product occurs here.
// Return low/high Ring192 limbs; they are still one authority's shares.
func groupedLMMGridShares(p groupedLMMMomentPlan, low, high []groupedWord, beta [][]*big.Int) ([][2]groupedWord, error) {
	if p.validate() != nil || len(low) != p.Clusters*p.triangle() || len(high) != len(low) || len(beta) < 1 || len(beta) > 256 {
		return nil, primitiveVError()
	}
	scale := new(big.Int).Lsh(big.NewInt(1), 50)
	bound := new(big.Int).Mul(big.NewInt(8), scale)
	l1cap := new(big.Int).Mul(big.NewInt(16), scale)
	l1cap.Add(l1cap, big.NewInt(int64((p.Columns+1)/2))) // frozen encoding slack
	coefficients := make([][]*big.Int, len(beta))
	for j, b := range beta {
		if len(b) != p.Columns-1 {
			return nil, primitiveVError()
		}
		t := make([]*big.Int, p.Columns)
		sum := new(big.Int)
		for k, v := range b {
			if v == nil || new(big.Int).Abs(v).Cmp(bound) > 0 {
				return nil, primitiveVError()
			}
			sum.Add(sum, new(big.Int).Abs(v))
			t[k] = new(big.Int).Neg(v)
		}
		if sum.Cmp(l1cap) > 0 {
			return nil, primitiveVError()
		}
		t[p.Columns-1] = scale
		coefficients[j] = make([]*big.Int, p.triangle())
		for k := range coefficients[j] {
			a, b := p.pair(k)
			v := new(big.Int).Mul(t[a], t[b])
			if a != b {
				v.Lsh(v, 1)
			}
			coefficients[j][k] = v
		}
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), 384)
	out := make([][2]groupedWord, p.Clusters*len(beta))
	for c := 0; c < p.Clusters; c++ {
		for j := range beta {
			sum := new(big.Int)
			for k, coefficient := range coefficients[j] {
				index := c*p.triangle() + k
				w := groupedWordInteger(high[index])
				w.Lsh(w, 192)
				w.Add(w, groupedWordInteger(low[index]))
				sum.Add(sum, new(big.Int).Mul(w, coefficient))
			}
			sum.Mod(sum, modulus)
			out[c*len(beta)+j][0] = groupedWordFromBig(sum)
			out[c*len(beta)+j][1] = groupedWordFromBig(new(big.Int).Rsh(sum, 192))
		}
	}
	return out, nil
}
func groupedWordInteger(w groupedWord) *big.Int {
	v := new(big.Int)
	for i := 2; i >= 0; i-- {
		v.Lsh(v, 64)
		v.Add(v, new(big.Int).SetUint64(w[i]))
	}
	return v
}

// One final clamp and nearest-even rescale per cluster/candidate. Input is
// f264 in two Ring192 limbs, plus an aggregate private valid bit. The exact
// wide addition belongs to this output boundary; candidate sums/products have
// already been done on shares. No change to the runner or source ABI caps.
func groupedLMMFinalCompile(gridBits int, cap int64) (*primitiveVProgram, error) {
	if gridBits < 8 || gridBits > 18 || cap < 1 || cap > 9007199254740991 {
		return nil, primitiveVError()
	}
	shift := 264 - gridBits
	half := new(big.Int).Lsh(big.NewInt(1), uint(shift-1))
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(shift)), big.NewInt(1))
	upper := new(big.Int).Lsh(big.NewInt(cap), uint(shift))
	source := fmt.Sprintf(`package main
func main(g [5]uint192,e [3]uint192) [2]uint192 {
 a:=uint384(g[0])+(uint384(g[1])<<192)
 b:=uint384(e[0])+(uint384(e[1])<<192)
 x:=int384(a+b)
 valid:=g[2]+e[2]==1
 if x<0 { x=0 }
 if x>int384(%s) { x=int384(%s) }
 u:=uint384(x)
 q:=u>>%d
 r:=u & uint384(%s)
 if r>uint384(%s) || (r==uint384(%s) && (q & 1)==1) { q=q+1 }
 v:=uint192(0)
 if valid { v=1 } else { q=0 }
 var out [2]uint192
 out[0]=uint192(q)-g[3]
 out[1]=v-g[4]
 return out
}
`, upper, upper, shift, mask, half, half)
	return primitiveVCompile(source, 192, 5, 3, 2)
}
