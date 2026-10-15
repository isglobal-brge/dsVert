package main

// Exact, public postprocessing of retained DP payloads. No private input,
// sampler, source read, or floating point operation belongs in this module.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
)

const dpIRLSUpdateVersion = "dp_irls_update_v1"
const dpIRLSMaxBytes = 4 << 20

type dpIRLSRat struct {
	D string `json:"d"`
	N string `json:"n"`
}
type dpIRLSLimits struct {
	CommonDenominator string `json:"common_denominator"`
	InputBits         string `json:"input_bits"`
	KMax              string `json:"k_max"`
	TemporaryBits     string `json:"temporary_bits"`
}

// Field order is the canonical lexicographic JSON order, including nested objects.
type dpIRLSRequest struct {
	Beta         []dpIRLSRat  `json:"beta"`
	BoxLower     []dpIRLSRat  `json:"box_lower"`
	BoxUpper     []dpIRLSRat  `json:"box_upper"`
	Damping      dpIRLSRat    `json:"damping"`
	Floor        dpIRLSRat    `json:"floor"`
	FloorQuantum dpIRLSRat    `json:"floor_quantum"`
	G            []string     `json:"g"`
	GTranslation []string     `json:"g_translation"`
	GUnit        dpIRLSRat    `json:"g_unit"`
	H            []string     `json:"h"`
	HTranslation []string     `json:"h_translation"`
	HUnit        dpIRLSRat    `json:"h_unit"`
	Lattice      dpIRLSRat    `json:"lattice"`
	Limits       dpIRLSLimits `json:"limits"`
	Ridge        dpIRLSRat    `json:"ridge"`
	Trust        dpIRLSRat    `json:"trust"`
	Version      string       `json:"version"`
}
type dpIRLSResult struct {
	Beta        []dpIRLSRat `json:"beta"`
	K           string      `json:"k"`
	Projected   []bool      `json:"projected"`
	Saturated   bool        `json:"saturated"`
	TrustScaled bool        `json:"trust_scaled"`
	Version     string      `json:"version"`
}
type dpIRLSRejection struct{ reason string }

func irlsReject(s string) { panic(dpIRLSRejection{s}) }

var irlsIntegerPattern = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

func irlsInt(s string) *big.Int {
	if len(s) > 1500 || !irlsIntegerPattern.MatchString(s) {
		irlsReject("noncanonical or oversized integer")
	}
	x, ok := new(big.Int).SetString(s, 10)
	if !ok {
		irlsReject("invalid integer")
	}
	return x
}
func irlsRat(s dpIRLSRat) *big.Rat {
	n, d := irlsInt(s.N), irlsInt(s.D)
	if d.Sign() <= 0 || new(big.Int).GCD(nil, nil, n, d).Cmp(big.NewInt(1)) != 0 {
		irlsReject("rational must be reduced with positive denominator")
	}
	return new(big.Rat).SetFrac(n, d)
}
func irlsEncodeRat(x *big.Rat) dpIRLSRat {
	return dpIRLSRat{D: x.Denom().String(), N: x.Num().String()}
}

// Every multiplication and addition is checked before reduction or division.
// These checks therefore cover the temporary integers, not only reduced results.
type irlsArithmetic struct{ bits int }

func (a irlsArithmetic) check(x *big.Int) *big.Int {
	if x.BitLen() > a.bits {
		irlsReject("signed temporary bit ceiling exceeded")
	}
	return x
}
func (a irlsArithmetic) add(x, y *big.Int) *big.Int { return a.check(new(big.Int).Add(x, y)) }
func (a irlsArithmetic) sub(x, y *big.Int) *big.Int { return a.check(new(big.Int).Sub(x, y)) }
func (a irlsArithmetic) mul(x, y *big.Int) *big.Int { return a.check(new(big.Int).Mul(x, y)) }
func (a irlsArithmetic) exact(x, y *big.Int) *big.Int {
	if y.Sign() == 0 {
		irlsReject("zero exact divisor")
	}
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(x, y, r)
	if r.Sign() != 0 {
		irlsReject("non-exact fraction-free division")
	}
	return a.check(q)
}
func (a irlsArithmetic) rat(n, d *big.Int) *big.Rat {
	a.check(n)
	a.check(d)
	if d.Sign() == 0 {
		irlsReject("zero rational divisor")
	}
	return new(big.Rat).SetFrac(n, d)
}
func (a irlsArithmetic) radd(x, y *big.Rat) *big.Rat {
	return a.rat(a.add(a.mul(x.Num(), y.Denom()), a.mul(y.Num(), x.Denom())), a.mul(x.Denom(), y.Denom()))
}
func (a irlsArithmetic) rsub(x, y *big.Rat) *big.Rat { return a.radd(x, new(big.Rat).Neg(y)) }
func (a irlsArithmetic) rmul(x, y *big.Rat) *big.Rat {
	return a.rat(a.mul(x.Num(), y.Num()), a.mul(x.Denom(), y.Denom()))
}
func (a irlsArithmetic) rdiv(x, y *big.Rat) *big.Rat {
	return a.rat(a.mul(x.Num(), y.Denom()), a.mul(x.Denom(), y.Num()))
}
func (a irlsArithmetic) cmp(x, y *big.Rat) int {
	return a.mul(x.Num(), y.Denom()).Cmp(a.mul(y.Num(), x.Denom()))
}
func irlsAbs(x *big.Rat) *big.Rat { return new(big.Rat).Abs(x) }
func irlsCeil(x *big.Rat) *big.Int {
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(x.Num(), x.Denom(), r)
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}
func irlsSmall(x *big.Int, max int) int {
	if !x.IsInt64() || x.Sign() < 0 || x.Int64() > int64(max) {
		irlsReject("engine numeric envelope exceeded")
	}
	return int(x.Int64())
}
func irlsMinorBits(p, w int) int {
	pow := new(big.Int).Exp(big.NewInt(int64(p)), big.NewInt(int64(p)), nil)
	m := 0
	for new(big.Int).Lsh(big.NewInt(1), uint(2*m)).Cmp(pow) < 0 {
		m++
	}
	return p*w + m + 2
}

type irlsContext struct {
	p, w, L                                  int
	a                                        irlsArithmetic
	beta, lo, hi, g                          []*big.Rat
	h                                        [][]*big.Rat
	damping, floor, q, ridge, trust, lattice *big.Rat
	D, kmax                                  *big.Int
	saturated                                bool
}

func irlsValidate(r *dpIRLSRequest, verify bool) *irlsContext {
	p := len(r.Beta)
	if r.Version != dpIRLSUpdateVersion || p < 1 || p > 128 {
		irlsReject("unsupported version or dimension")
	}
	n := p * (p + 1) / 2
	if len(r.BoxLower) != p || len(r.BoxUpper) != p || len(r.G) != p || len(r.GTranslation) != p || len(r.H) != n || len(r.HTranslation) != n {
		irlsReject("coordinate shape mismatch")
	}
	// The fixed engine envelope bounds certificate admission itself. After deriving
	// the signed bound all arithmetic, including admission, is re-run under it.
	a := irlsArithmetic{5000000}
	if verify {
		a.bits = irlsSmall(irlsInt(r.Limits.TemporaryBits), 5000000)
		if a.bits == 0 {
			irlsReject("zero temporary ceiling")
		}
	}
	c := &irlsContext{p: p, a: a, beta: make([]*big.Rat, p), lo: make([]*big.Rat, p), hi: make([]*big.Rat, p), g: make([]*big.Rat, p), h: make([][]*big.Rat, p)}
	c.damping, c.floor, c.q, c.ridge, c.trust, c.lattice = irlsRat(r.Damping), irlsRat(r.Floor), irlsRat(r.FloorQuantum), irlsRat(r.Ridge), irlsRat(r.Trust), irlsRat(r.Lattice)
	gu, hu := irlsRat(r.GUnit), irlsRat(r.HUnit)
	one := big.NewRat(1, 1)
	if c.damping.Sign() <= 0 || a.cmp(c.damping, one) > 0 || c.floor.Sign() <= 0 || c.q.Sign() <= 0 || c.ridge.Sign() < 0 || c.trust.Sign() < 0 || c.lattice.Sign() <= 0 || gu.Sign() <= 0 || hu.Sign() <= 0 {
		irlsReject("invalid signed numeric constants")
	}
	static := []*big.Rat{c.damping, c.floor, c.q, c.ridge, c.trust, c.lattice, gu, hu}
	Bbeta := new(big.Rat)
	for i := 0; i < p; i++ {
		c.beta[i], c.lo[i], c.hi[i] = irlsRat(r.Beta[i]), irlsRat(r.BoxLower[i]), irlsRat(r.BoxUpper[i])
		static = append(static, c.lo[i], c.hi[i])
		c.h[i] = make([]*big.Rat, p)
		if a.cmp(c.lo[i], c.hi[i]) > 0 || a.cmp(c.beta[i], c.lo[i]) < 0 || a.cmp(c.beta[i], c.hi[i]) > 0 {
			irlsReject("beta or box outside signed domain")
		}
		for _, x := range []*big.Rat{c.beta[i], c.lo[i], c.hi[i]} {
			if !a.rdiv(x, c.lattice).IsInt() {
				irlsReject("beta and box endpoints must lie on lattice")
			}
		}
		for _, x := range []*big.Rat{c.lo[i], c.hi[i]} {
			if a.cmp(irlsAbs(x), Bbeta) > 0 {
				Bbeta = irlsAbs(x)
			}
		}
	}
	required := 1
	addWidth := func(x *big.Int) {
		a.check(x)
		if x.BitLen() > required {
			required = x.BitLen()
		}
	}
	for _, x := range static {
		addWidth(x.Num())
		addWidth(x.Denom())
	}
	Hmax, Gmax, RH := new(big.Rat), new(big.Rat), new(big.Rat)
	hbounds := make([][]*big.Rat, p)
	for i := range hbounds {
		hbounds[i] = make([]*big.Rat, p)
	}
	decode := func(payload, translation string, unit *big.Rat) (*big.Rat, *big.Rat) {
		v, A := irlsInt(payload), irlsInt(translation)
		a.check(v)
		a.check(A)
		if A.Sign() <= 0 {
			irlsReject("translation must be positive")
		}
		U := a.mul(big.NewInt(2), A)
		addWidth(U)
		if v.Sign() < 0 || v.Cmp(U) > 0 {
			irlsReject("payload outside translated finalizer bounds")
		}
		if v.Sign() == 0 || v.Cmp(U) == 0 {
			c.saturated = true
		}
		return a.rmul(new(big.Rat).SetInt(a.sub(v, A)), unit), a.rmul(new(big.Rat).SetInt(A), unit)
	}
	for i := range c.g {
		var bound *big.Rat
		c.g[i], bound = decode(r.G[i], r.GTranslation[i], gu)
		if a.cmp(bound, Gmax) > 0 {
			Gmax = bound
		}
	}
	index := 0
	for i := 0; i < p; i++ {
		for j := i; j < p; j++ {
			x, bound := decode(r.H[index], r.HTranslation[index], hu)
			c.h[i][j], c.h[j][i] = x, x
			hbounds[i][j], hbounds[j][i] = bound, bound
			if a.cmp(bound, Hmax) > 0 {
				Hmax = bound
			}
			index++
		}
	}
	for i := 0; i < p; i++ {
		row := new(big.Rat)
		for j := 0; j < p; j++ {
			row = a.radd(row, hbounds[i][j])
		}
		if a.cmp(row, RH) > 0 {
			RH = row
		}
	}
	c.kmax = irlsCeil(a.rdiv(a.radd(c.floor, RH), c.q))
	c.D = big.NewInt(1)
	for _, x := range []*big.Rat{hu, c.q, c.ridge, c.floor, gu, a.rmul(c.ridge, c.lattice)} {
		gcd := new(big.Int).GCD(nil, nil, c.D, x.Denom())
		c.D = a.mul(a.exact(c.D, gcd), x.Denom())
	}
	addWidth(c.D)
	B := a.radd(a.radd(a.radd(Hmax, a.rmul(new(big.Rat).SetInt(c.kmax), c.q)), c.ridge), c.floor)
	rhs := a.radd(Gmax, a.rmul(c.ridge, Bbeta))
	if a.cmp(rhs, B) > 0 {
		B = rhs
	}
	addWidth(irlsCeil(a.rmul(new(big.Rat).SetInt(c.D), B)))
	addWidth(irlsCeil(a.rmul(Bbeta, new(big.Rat).SetInt(c.lattice.Denom()))))
	c.w = required
	if verify {
		c.w = irlsSmall(irlsInt(r.Limits.InputBits), 4096)
		if c.w < required || irlsInt(r.Limits.CommonDenominator).Cmp(c.D) != 0 || irlsInt(r.Limits.KMax).Cmp(c.kmax) != 0 {
			irlsReject("incorrect signed numeric certificate")
		}
	}
	if c.w > 4096 {
		irlsReject("input bit envelope exceeded")
	}
	c.L = irlsMinorBits(p, c.w)
	temporary := 8*c.L + 16*c.w + 64
	if temporary > 5000000 || (verify && a.bits != temporary) {
		irlsReject("incorrect signed temporary ceiling")
	}
	c.a = irlsArithmetic{temporary}
	return c
}
func irlsMatrix(c *irlsContext, k *big.Int, solve bool) [][]*big.Int {
	a := c.a
	n := c.p
	cols := n
	if solve {
		cols++
	}
	m := make([][]*big.Int, n)
	shift := a.rmul(new(big.Rat).SetInt(k), c.q)
	if solve {
		shift = a.radd(shift, c.ridge)
	} else {
		shift = a.rsub(shift, c.floor)
	}
	toInt := func(x *big.Rat) *big.Int {
		v := a.rmul(x, new(big.Rat).SetInt(c.D))
		if !v.IsInt() {
			irlsReject("matrix common denominator is insufficient")
		}
		vnum := new(big.Int).Set(v.Num())
		if vnum.BitLen() > c.w {
			irlsReject("augmented matrix exceeds signed input width")
		}
		return vnum
	}
	for i := 0; i < n; i++ {
		m[i] = make([]*big.Int, cols)
		for j := 0; j < n; j++ {
			x := c.h[i][j]
			if i == j {
				x = a.radd(x, shift)
			}
			m[i][j] = toInt(x)
		}
		if solve {
			m[i][n] = toInt(a.rsub(c.g[i], a.rmul(c.ridge, c.beta[i])))
		}
	}
	return m
}
func irlsCheckMinor(c *irlsContext, x *big.Int) *big.Int {
	if x.BitLen() > c.L {
		irlsReject("Bareiss minor exceeds certificate")
	}
	return x
}

// The previous successful positive pivot remains unchanged when an all-zero
// residual row is skipped. Resetting it to 1 (or 0) changes the scale and is wrong.
func irlsPSD(c *irlsContext, k *big.Int) bool {
	m := irlsMatrix(c, k, false)
	prev := big.NewInt(1)
	a := c.a
	for i := 0; i < c.p; i++ {
		pivot := m[i][i]
		if pivot.Sign() < 0 {
			return false
		}
		if pivot.Sign() == 0 {
			for j := i + 1; j < c.p; j++ {
				if m[i][j].Sign() != 0 {
					return false
				}
			}
			continue
		}
		for j := i + 1; j < c.p; j++ {
			for l := j; l < c.p; l++ {
				v := a.exact(a.sub(a.mul(pivot, m[j][l]), a.mul(m[j][i], m[i][l])), prev)
				irlsCheckMinor(c, v)
				m[j][l] = v
				m[l][j] = v
			}
		}
		prev = new(big.Int).Set(pivot)
	}
	return true
}
func irlsShift(c *irlsContext) *big.Int {
	zero := big.NewInt(0)
	if irlsPSD(c, zero) {
		return zero
	}
	lo, hi := big.NewInt(0), big.NewInt(1)
	for {
		if hi.Cmp(c.kmax) > 0 {
			hi.Set(c.kmax)
		}
		if irlsPSD(c, hi) {
			break
		}
		if hi.Cmp(c.kmax) == 0 {
			irlsReject("PSD failed at signed k_max")
		}
		lo.Set(hi)
		hi = c.a.mul(hi, big.NewInt(2))
	}
	for new(big.Int).Sub(hi, lo).Cmp(big.NewInt(1)) > 0 {
		mid := new(big.Int).Rsh(c.a.add(lo, hi), 1)
		if irlsPSD(c, mid) {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}
func irlsSolve(c *irlsContext, k *big.Int) []*big.Rat {
	m := irlsMatrix(c, k, true)
	a := c.a
	n := c.p
	prev := big.NewInt(1)
	for i := 0; i < n-1; i++ {
		pivot := m[i][i]
		if pivot.Sign() <= 0 {
			irlsReject("solve requires positive fixed-order pivots")
		}
		for j := i + 1; j < n; j++ {
			for l := i + 1; l <= n; l++ {
				m[j][l] = irlsCheckMinor(c, a.exact(a.sub(a.mul(pivot, m[j][l]), a.mul(m[j][i], m[i][l])), prev))
			}
			m[j][i] = new(big.Int)
		}
		prev = new(big.Int).Set(pivot)
	}
	det := m[n-1][n-1]
	if det.Sign() <= 0 {
		irlsReject("nonpositive solve determinant")
	}
	N := make([]*big.Int, n)
	v := make([]*big.Rat, n)
	for i := n - 1; i >= 0; i-- {
		num := a.mul(m[i][n], det)
		for j := i + 1; j < n; j++ {
			num = a.sub(num, a.mul(m[i][j], N[j]))
		}
		N[i] = irlsCheckMinor(c, a.exact(num, m[i][i]))
		v[i] = a.rat(N[i], det)
	}
	return v
}
func irlsRound(a irlsArithmetic, x, lattice *big.Rat) *big.Rat {
	z := a.rdiv(x, lattice)
	n := new(big.Int).Abs(z.Num())
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(n, z.Denom(), r)
	cmp := a.mul(r, big.NewInt(2)).Cmp(z.Denom())
	if cmp > 0 || (cmp == 0 && q.Bit(0) == 1) {
		q = a.add(q, big.NewInt(1))
	}
	if z.Sign() < 0 {
		q.Neg(q)
	}
	return a.rmul(new(big.Rat).SetInt(q), lattice)
}
func irlsUpdate(c *irlsContext) dpIRLSResult {
	k := irlsShift(c)
	v := irlsSolve(c, k)
	a := c.a
	norm := new(big.Rat)
	for i := range v {
		v[i] = a.rmul(v[i], c.damping)
		if a.cmp(irlsAbs(v[i]), norm) > 0 {
			norm = irlsAbs(v[i])
		}
	}
	scale := big.NewRat(1, 1)
	scaled := norm.Sign() > 0 && a.cmp(norm, c.trust) > 0
	if scaled {
		scale = a.rdiv(c.trust, norm)
	}
	out := dpIRLSResult{Beta: make([]dpIRLSRat, c.p), K: k.String(), Projected: make([]bool, c.p), Saturated: c.saturated, TrustScaled: scaled, Version: dpIRLSUpdateVersion}
	for i := range v {
		x := a.radd(c.beta[i], a.rmul(v[i], scale))
		if a.cmp(x, c.lo[i]) < 0 {
			x = c.lo[i]
			out.Projected[i] = true
		}
		if a.cmp(x, c.hi[i]) > 0 {
			x = c.hi[i]
			out.Projected[i] = true
		}
		out.Beta[i] = irlsEncodeRat(irlsRound(a, x, c.lattice))
	}
	return out
}

// DPIRLSCanonicalUpdate validates and computes one deterministic public successor.
// It accepts only canonical bytes; callers must authenticate the signed contract,
// released lanes and predecessor before using this result in the path state machine.
func DPIRLSCanonicalUpdate(input []byte) (output []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			if r, ok := p.(dpIRLSRejection); ok {
				output = nil
				err = fmt.Errorf("dp IRLS rejected: %s", r.reason)
			} else {
				panic(p)
			}
		}
	}()
	if len(input) > dpIRLSMaxBytes {
		return nil, fmt.Errorf("dp IRLS input exceeds byte ceiling")
	}
	var r dpIRLSRequest
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("invalid dp IRLS JSON: %w", err)
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(input, canonical) {
		return nil, fmt.Errorf("dp IRLS JSON is not canonical or has missing/duplicate fields")
	}
	c := irlsValidate(&r, true)
	return json.Marshal(irlsUpdate(c))
}
func handleDPIRLSUpdate() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "dp-irls-update takes canonical JSON on stdin only")
		os.Exit(1)
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, dpIRLSMaxBytes+1))
	if err == nil {
		b, err = DPIRLSCanonicalUpdate(b)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err = os.Stdout.Write(b); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
