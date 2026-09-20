package main

import (
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

const groupedProfileSHA256 = "f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84"

const groupedProfileID = "grouped-pwlinear-q16-k64-range-exp-v2"
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
	if name == "exp" || name == "exp_negative" {
		lower, upper := int64(-262144), int64(262144)
		if name == "exp_negative" {
			lower, upper = -1048576, 0
		}
		if x < lower || x > upper {
			return 0, errors.New("grouped profile rejected")
		}
		return groupedExpEval(x), nil
	}
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
		for level := 0; level < 6; level++ {
			fmt.Fprintf(&b, "bit%d := (index & uint6(%d)) != uint6(0)\n", level, 1<<level)
		}
		// Bit-plane decision diagrams preserve full signed int32 table values.
		// Constant subtrees collapse before MPCL compilation; shared Boolean
		// nodes serve both columns without narrow signed-word casts.
		nodes := map[string]string{}
		var lookup func([]bool, int) string
		lookup = func(values []bool, level int) string {
			if len(values) == 1 {
				if values[0] {
					return "true"
				}
				return "false"
			}
			lo := lookup(values[:len(values)/2], level-1)
			hi := lookup(values[len(values)/2:], level-1)
			if lo == hi {
				return lo
			}
			key := fmt.Sprintf("%d:%s:%s", level, lo, hi)
			if n, ok := nodes[key]; ok {
				return n
			}
			expression := fmt.Sprintf("(%s != ((%s != %s) && bit%d))", lo, lo, hi, level)
			if lo == "false" && hi == "true" {
				return fmt.Sprintf("bit%d", level)
			}
			if lo == "true" && hi == "false" {
				return fmt.Sprintf("!bit%d", level)
			}
			n := fmt.Sprintf("lookup%d", len(nodes))
			nodes[key] = n
			fmt.Fprintf(&b, "%s := %s\n", n, expression)
			return n
		}
		for _, column := range []string{"base", "delta"} {
			fmt.Fprintf(&b, "%s := int32(0)\n", column)
			for bit := 0; bit < 32; bit++ {
				values := make([]bool, 64)
				for i := range values {
					v := p.Knots[i]
					if column == "delta" {
						v = p.Knots[i+1] - p.Knots[i]
					}
					values[i] = (uint32(v) & (uint32(1) << bit)) != 0
				}
				expression := lookup(values, 5)
				if expression == "false" {
					continue
				}
				fmt.Fprintf(&b, "%sBit%d := uint1(0)\nif %s { %sBit%d = 1 }\n%s = %s | int32(uint32(%sBit%d) << %d)\n", column, bit, expression, column, bit, column, column, column, bit, bit)
			}
		}
		fmt.Fprintf(&b, "fraction := uint%d(offset & %d)\n if x == int32(%d) { fraction = %d }\n negative := delta < 0\n magnitude := delta\n if negative { magnitude = -delta }\n product := wideMul(uint%d(fraction), uint%d(magnitude))\n quotient := product >> %d\n remainder := product & %d\n if remainder > %d || (remainder == %d && (quotient & 1) != 0) { quotient = quotient + 1 }\n change := int32(quotient)\n if negative { change = -change }\n return base + change\n}\n", shift+1, p.Step-1, p.Upper, p.Step, deltaBits, deltaBits, shift, p.Step-1, p.Step/2, p.Step/2)
	}
	return b.String() + groupedExpSource()
}
