package main

import "strings"

// ln(2) is enclosed by the exact-rational certificate generator. The rounded
// exponent need not equal real-arithmetic rounding: the residual identity is
// exact for this signed ln2 integer, with the ln2 discrepancy bounded separately.
const groupedExpError = 0.0055
const groupedNegativeExpError = 0.00013

func groupedExpEval(x int64) int64 {
	negative := x < 0
	magnitude := x
	if negative {
		magnitude = -magnitude
	}
	k := (magnitude + 22713) / 45426
	r := magnitude - k*45426
	if negative {
		k = -k
		r = -r
	}
	v, _ := groupedProfileEval("exp_reduced", r)
	if k >= 0 {
		return v << uint(k)
	}
	return groupedRoundDiv(v, int64(1)<<uint(-k))
}

func groupedExpSource() string {
	var b strings.Builder
	b.WriteString(`
func groupedRangeExp(x int32) int32 {
 negative := x < 0
 magnitude := x
 if negative { magnitude = -magnitude }
 remainder := magnitude + int32(22713)
 exponent := int32(0)
`)
	// Fixed five-stage unsigned quotient extraction, not secret division.
	for _, step := range []struct{ threshold, bit string }{
		{"726816", "16"}, {"363408", "8"}, {"181704", "4"},
		{"90852", "2"}, {"45426", "1"},
	} {
		b.WriteString("if remainder >= int32(" + step.threshold + ") { remainder = remainder-int32(" + step.threshold + ")\n exponent = exponent+int32(" + step.bit + ") }\n")
	}
	b.WriteString(`
 residual := remainder-int32(22713)
 if negative { residual = -residual
 exponent = -exponent }
 value := uint32(groupedProfileExpReduced(residual))
 left := value
 right := value
 divisor := uint32(1)
 shift := exponent
 if shift < 0 { shift = -shift }
`)
	for _, shift := range []string{"16", "8", "4", "2", "1"} {
		b.WriteString("if (shift & int32(" + shift + ")) != 0 {\nleft = left << " + shift + "\nright = right >> " + shift + "\ndivisor = divisor << " + shift + "\n}\n")
	}
	b.WriteString(`
 result := left
 if exponent < 0 {
  mask := divisor-uint32(1)
  rest := value & mask
  half := divisor >> 1
  if rest > half || (rest == half && (right & 1) != 0) { right = right+1 }
  result = right
 }
 return int32(result)
}
func groupedProfileExp(x int32) int32 { return groupedRangeExp(x) }
func groupedProfileExpNegative(x int32) int32 { return groupedRangeExp(x) }
`)
	return b.String()
}
