package main

import (
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

const groupedProfileSHA256 = "a32101f12fec76cbed9ae0f5a8eaa6dab621acecb98c4a269fcee6912a5d3cfc"

const groupedProfileID = "grouped-pwlinear-q16-k64-v1"
const groupedProfileScale int64 = 65536

type groupedProfile struct {
	Lower, Upper, Step int64
	Knots              [65]int64
	Error              float64
}

func groupedRoundDiv(a, b int64) int64 {
	negative := a < 0
	if negative {
		a = -a
	}
	q, r := a/b, a%b
	if r > b-r || (r == b-r && q&1 != 0) {
		q++
	}
	if negative {
		return -q
	}
	return q
}

// groupedProfileEval evaluates the signed public profile, not a transcendental.
// The caller must handle the negative-exp cutoff separately.
func groupedProfileEval(name string, x int64) (int64, error) {
	p, ok := groupedProfiles[name]
	if !ok || x < p.Lower || x > p.Upper {
		return 0, errors.New("grouped profile rejected")
	}
	if x == p.Upper {
		return p.Knots[64], nil
	}
	k := (x - p.Lower) / p.Step
	return p.Knots[k] + groupedRoundDiv((x-p.Lower-k*p.Step)*(p.Knots[k+1]-p.Knots[k]), p.Step), nil
}

func groupedProfileFunction(name string) string {
	var out strings.Builder
	out.WriteString("groupedProfile")
	for _, part := range strings.Split(name, "_") {
		out.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return out.String()
}

// Every profile has 32-bit input/output and a single narrow exact product.
// Runtime callers validate the public domain in-circuit before calling it.
func groupedProfileSource() string {
	var b strings.Builder
	names := make([]string, 0, len(groupedProfiles))
	for name := range groupedProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := groupedProfiles[name]
		shift := bits.TrailingZeros64(uint64(p.Step))
		maxDelta := int64(0)
		for i := 0; i < 64; i++ {
			v := p.Knots[i+1] - p.Knots[i]
			if v < 0 {
				v = -v
			}
			if v > maxDelta {
				maxDelta = v
			}
		}
		deltaBits := bits.Len64(uint64(maxDelta))
		if deltaBits < shift+1 {
			deltaBits = shift + 1
		}
		fmt.Fprintf(&b, "func %s(x int32) int32 {\n offset := x - int32(%d)\n index := uint6(offset >> %d)\n if x == int32(%d) { index = 63 }\n", groupedProfileFunction(name), p.Lower, shift, p.Upper)
		// A mux tree over index bits avoids 64 full-width comparisons.
		for _, column := range []string{"base", "delta"} {
			values := make([]string, 64)
			for i := 0; i < 64; i++ {
				v := p.Knots[i]
				if column == "delta" {
					v = p.Knots[i+1] - p.Knots[i]
				}
				if v < 0 {
					values[i] = fmt.Sprintf("-int32(%d)", -v)
				} else {
					values[i] = fmt.Sprintf("int32(%d)", v)
				}
			}
			for level := 0; len(values) > 1; level++ {
				next := make([]string, len(values)/2)
				for i := range next {
					n := fmt.Sprintf("%s%d_%d", column, level, i)
					fmt.Fprintf(&b, "%s := %s\n if (index & %d) != 0 { %s = %s }\n", n, values[2*i], 1<<level, n, values[2*i+1])
					next[i] = n
				}
				values = next
			}
			fmt.Fprintf(&b, "%s := %s\n", column, values[0])
		}
		fmt.Fprintf(&b, "fraction := uint%d(offset & %d)\n if x == int32(%d) { fraction = %d }\n negative := delta < 0\n magnitude := delta\n if negative { magnitude = -delta }\n product := wideMul(uint%d(fraction), uint%d(magnitude))\n quotient := product >> %d\n remainder := product & %d\n if remainder > %d || (remainder == %d && (quotient & 1) != 0) { quotient = quotient + 1 }\n change := int32(quotient)\n if negative { change = -change }\n return base + change\n}\n", shift+1, p.Step-1, p.Upper, p.Step, deltaBits, deltaBits, shift, p.Step-1, p.Step/2, p.Step/2)
	}
	return b.String()
}
