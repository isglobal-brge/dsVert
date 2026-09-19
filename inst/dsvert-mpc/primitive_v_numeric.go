package main

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Primitive V adds a numeric profile; it does not alter the frozen grid V1 ABI.
// All words are signed int192, with 64 fractional bits. The circuit caller
// checks the documented domains inside the circuit and masks invalid results.
const primitiveVNumericProfile = "primitive-v-taylor12-exp64-atanh20-q64-v1"

var primitiveVScale = new(big.Int).Lsh(big.NewInt(1), 64)
var primitiveVLn2, _ = new(big.Int).SetString("12786308645202655660", 10)

func primitiveVRoundDivReference(a, b *big.Int) *big.Int {
	if b.Sign() <= 0 {
		panic("primitive-v internal positive divisor required")
	}
	mag := new(big.Int).Abs(a)
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(mag, b, r)
	cmp := new(big.Int).Lsh(r, 1).Cmp(b)
	if cmp > 0 || (cmp == 0 && q.Bit(0) != 0) {
		q.Add(q, big.NewInt(1))
	}
	if a.Sign() < 0 {
		q.Neg(q)
	}
	return q
}

func primitiveVMulQ64Reference(a, b *big.Int) *big.Int {
	return primitiveVRoundDivReference(new(big.Int).Mul(a, b), primitiveVScale)
}

func primitiveVExpCoefficients() []*big.Int {
	out := make([]*big.Int, 13)
	factorial := big.NewInt(1)
	for k := range out {
		if k > 0 {
			factorial.Mul(factorial, big.NewInt(int64(k)))
		}
		out[k] = primitiveVRoundDivReference(primitiveVScale, factorial)
	}
	return out
}

// primitiveVExpQ64Reference requires -17 <= a/2^64 <= 17.
func primitiveVExpQ64Reference(a *big.Int) *big.Int {
	x := primitiveVRoundDivReference(a, big.NewInt(64))
	c := primitiveVExpCoefficients()
	y := new(big.Int).Set(c[12])
	for k := 11; k >= 0; k-- {
		y.Add(primitiveVMulQ64Reference(y, x), c[k])
	}
	for i := 0; i < 6; i++ {
		y = primitiveVMulQ64Reference(y, y)
	}
	return y
}

// primitiveVExpNegativeQ64Reference requires a<=0. A fixed cutoff gives absolute
// error <1.4e-14 on the whole negative half-line, including cutoff error.
func primitiveVExpNegativeQ64Reference(a *big.Int) *big.Int {
	cutoff := new(big.Int).Mul(big.NewInt(-32), primitiveVScale)
	if a.Cmp(cutoff) < 0 {
		return new(big.Int)
	}
	half := primitiveVRoundDivReference(a, big.NewInt(2))
	y := primitiveVExpQ64Reference(half)
	return primitiveVMulQ64Reference(y, y)
}

// primitiveVLogQ64Reference accepts positive encoded values below 2^127.
// Its error from the logarithm of the supplied q64 number is <3e-17.
func primitiveVLogQ64Reference(a *big.Int) (*big.Int, error) {
	if a == nil || a.Sign() <= 0 || a.BitLen() > 127 {
		return nil, errors.New("primitive-v numeric input rejected")
	}
	m := new(big.Int).Set(a)
	k := m.BitLen() - 65
	if k >= 0 {
		m.Rsh(m, uint(k))
	} else {
		m.Lsh(m, uint(-k))
	}
	z := primitiveVRoundDivReference(new(big.Int).Lsh(new(big.Int).Sub(m, primitiveVScale), 64), new(big.Int).Add(m, primitiveVScale))
	z2 := primitiveVMulQ64Reference(z, z)
	c := func(j int) *big.Int {
		return primitiveVRoundDivReference(new(big.Int).Lsh(new(big.Int).Set(primitiveVScale), 1), big.NewInt(int64(2*j+1)))
	}
	y := c(19)
	for j := 18; j >= 0; j-- {
		y.Add(primitiveVMulQ64Reference(y, z2), c(j))
	}
	y = primitiveVMulQ64Reference(y, z)
	y.Add(y, new(big.Int).Mul(big.NewInt(int64(k)), primitiveVLn2))
	return y, nil
}

// primitiveVNumericSource returns MPCL helpers without a package declaration.
// Generic division requires b>0 and |a|<2^190. Generic q64 multiplication
// requires each operand magnitude <2^95; reductions/families enforce tighter
// caps. Narrow unsigned wideMul temporaries preserve the full int192 product.
// Products in this profile are below 2^179. The caller enforces numeric
// preconditions using secret bits.
func primitiveVNumericSource() string {
	var s strings.Builder
	s.WriteString(primitiveVMultiplySource("primitiveVMulQ64", 96))
	s.WriteString(primitiveVMultiplySource("primitiveVCoreMulQ64", 66))
	s.WriteString(primitiveVMultiplySource("primitiveVExpSquareQ64", 80))
	s.WriteString(primitiveVDividePowerTwoSource("primitiveVDiv64", 6))
	s.WriteString(primitiveVDividePowerTwoSource("primitiveVDiv2", 1))
	fmt.Fprintf(&s, `func primitiveVRoundDiv(a, b int192) int192 {
 negative := a < 0
 magnitude := a
 if negative { magnitude = -a }
 q := magnitude / b
 r := magnitude %% b
 if r > b-r || (r == b-r && (q & 1) != 0) { q = q+1 }
 if negative { q = -q }
 return q
}
func primitiveVPositiveRatioQ64(a,b int192) int192 {
 numerator := uint128(a) << 64
 denominator := uint128(b)
 q := numerator/denominator
 r := numerator%%denominator
 if r > denominator-r || (r == denominator-r && (q & 1) != 0) { q=q+1 }
 return int192(q)
}
func primitiveVExpQ64(a int192) int192 {
 x := primitiveVDiv64(a)
 y := int192(%s)
`, primitiveVExpCoefficients()[12])
	c := primitiveVExpCoefficients()
	for k := 11; k >= 0; k-- {
		fmt.Fprintf(&s, "y = primitiveVCoreMulQ64(y,x)+int192(%s)\n", c[k])
	}
	for k := 0; k < 6; k++ {
		s.WriteString("y = primitiveVExpSquareQ64(y,y)\n")
	}
	s.WriteString("return y\n}\n")
	fmt.Fprintf(&s, `func primitiveVExpNegativeQ64(a int192) int192 {
 safe := a
 if a < -int192(590295810358705651712) { safe = 0 }
 y := primitiveVExpQ64(primitiveVDiv2(safe))
 y = primitiveVMulQ64(y,y)
 if a < -int192(590295810358705651712) { y = 0 }
 return y
}
func primitiveVLogQ64(a int192) int192 {
 m := a
 if a <= 0 || a >= int192(170141183460469231731687303715884105728) { m = int192(%s) }
 k := a-a
`, primitiveVScale)
	for _, shift := range []int{32, 16, 8, 4, 2, 1} {
		bound := new(big.Int).Lsh(new(big.Int).Set(primitiveVScale), uint(shift))
		fmt.Fprintf(&s, "if m >= int192(%s) { m = m >> %d\n k = k + %d }\n", bound, shift, shift)
	}
	for _, shift := range []int{64, 32, 16, 8, 4, 2, 1} {
		bound := new(big.Int).Rsh(new(big.Int).Set(primitiveVScale), uint(shift-1))
		fmt.Fprintf(&s, "if m < int192(%s) { m = m << %d\n k = k - %d }\n", bound, shift, shift)
	}
	fmt.Fprintf(&s, "z := primitiveVPositiveRatioQ64(m-int192(%s),m+int192(%s))\nz2 := primitiveVCoreMulQ64(z,z)\n", primitiveVScale, primitiveVScale)
	for j := 19; j >= 0; j-- {
		c := primitiveVRoundDivReference(new(big.Int).Lsh(new(big.Int).Set(primitiveVScale), 1), big.NewInt(int64(2*j+1)))
		if j == 19 {
			fmt.Fprintf(&s, "y := int192(%s)\n", c)
		} else {
			fmt.Fprintf(&s, "y = primitiveVCoreMulQ64(y,z2)+int192(%s)\n", c)
		}
	}
	fmt.Fprintf(&s, "return primitiveVCoreMulQ64(y,z)+k*int192(%s)\n}\n", primitiveVLn2)
	return s.String()
}

// Narrow unsigned operands preserve the certified int192 product exactly and
// let the existing compiler's wideMul backend avoid sign-extension work.
func primitiveVMultiplySource(name string, bits int) string {
	return fmt.Sprintf(`func %s(a,b int192) int192 {
 negative := (a < 0) != (b < 0)
 aMagnitude := a
 bMagnitude := b
 if a < 0 { aMagnitude = -a }
 if b < 0 { bMagnitude = -b }
 product := wideMul(uint%d(aMagnitude),uint%d(bMagnitude))
 q := product >> 64
 r := product & uint%d(18446744073709551615)
 if r > uint%d(9223372036854775808) || (r == uint%d(9223372036854775808) && (q & 1) != 0) { q=q+1 }
 result := int192(q)
 if negative { result = -result }
 return result
}
`, name, bits, bits, 2*bits, 2*bits, 2*bits)
}

func primitiveVDividePowerTwoSource(name string, shift int) string {
	return fmt.Sprintf(`func %s(a int192) int192 {
 negative := a < 0
 magnitude := uint72(a)
 if negative { magnitude = uint72(-a) }
 q := magnitude >> %d
 r := magnitude & uint72(%d)
 if r > uint72(%d) || (r == uint72(%d) && (q & 1) != 0) { q=q+1 }
 result := int192(q)
 if negative { result = -result }
 return result
}
`, name, shift, (1<<uint(shift))-1, 1<<uint(shift-1), 1<<uint(shift-1))
}
