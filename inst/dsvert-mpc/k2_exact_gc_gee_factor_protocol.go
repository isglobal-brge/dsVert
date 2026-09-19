package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Private arithmetic predecessor, not a release RPC. Raw input shares must be
// receipt-bound to the signed complete predictor and once-only grouping. The
// release scheduler owns durable state/replay and must carry Valid through ALL
// likelihood/bread/meat terminal boundaries; no field here goes to the analyst.
type groupedGEEFactorResult struct {
	Factors        []groupedWord // row-major (d u,z), q64
	Likelihood     groupedWord   // cluster sum at q32, before signed per-cluster cap
	Valid          groupedWord
	Certificate    *groupedGEECertificate
	ScheduleSHA256 [32]byte
}

func groupedGEEValidityCompile(n int) (*primitiveVProgram, error) {
	if n < 1 || n > 8 {
		return nil, primitiveVError()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]int192,e [%d]int192) [1]int192 {\nvar out [1]int192\nvalid:=true\n", n+1, n)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "valid=valid && g[%d]+e[%d]==1\n", i, i)
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[0]=v-g[%d]\nreturn out\n}\n", n)
	return primitiveVCompile(b.String(), 192, n+1, n, 1)
}

func groupedGEEProduceFactors(rw io.ReadWriter, base exactGCSession, role exactGCRole, contract [32]byte, s groupedGEESpec, raw []groupedWord) (*groupedGEEFactorResult, error) {
	if rw == nil || base.validate() != nil || (role != exactGCRoleGarbler && role != exactGCRoleEvaluator) || contract == ([32]byte{}) || groupedGEEValidate(s) != nil || len(raw) != s.Slots*(s.Predictors+3) {
		return nil, primitiveVError()
	}
	cert, err := groupedGEEWhiteningCertificate(s)
	if err != nil {
		return nil, err
	}
	// The signed family contract is an input, not replaced by an unsigned spec.
	// Bind the arithmetic schedule to it and to the exact new profile/spec.
	encoded, err := json.Marshal(struct {
		Contract        [32]byte
		Spec            groupedGEESpec
		Profile, Scalar string
	}{contract, s, groupedGEEWhiteningProfile, groupedProfileSHA256})
	if err != nil {
		return nil, primitiveVError()
	}
	schedule := sha256.Sum256(encoded)
	stage := 0
	next := func(name string) exactGCSession {
		stage++
		v := base
		v.Purpose = fmt.Sprintf("%s/gee-factors-v3/%d/%s", base.Purpose, stage, name)
		return v
	}
	boundary := func(name string, p *primitiveVProgram, x []groupedWord) ([]groupedWord, error) {
		words := make([]*big.Int, len(x))
		for i, v := range x {
			words[i] = groupedWordInteger(v)
		}
		session := next(name)
		var result []*big.Int
		var err error
		if role == exactGCRoleGarbler {
			result, err = primitiveVRunGarbler(rw, p, session, schedule, words)
		} else {
			result, err = primitiveVRunEvaluator(rw, p, session, schedule, words)
		}
		if err != nil {
			return nil, primitiveVError()
		}
		out := make([]groupedWord, len(result))
		for i, v := range result {
			out[i] = groupedWordFromBig(v)
		}
		return out, nil
	}
	product := func(name string, x, y []groupedWord) ([]groupedWord, error) {
		result, err := registerGroupedExactArithmetic()(rw, next(name), role, groupedArithmeticPlan{Contract: schedule, Count: len(x)}, x, y)
		if err != nil {
			return nil, primitiveVError()
		}
		return result.Shares, nil
	}
	inputProgram, err := groupedGEEInputCompile(s)
	if err != nil {
		return nil, err
	}
	normalized, err := boundary("guarded-input", inputProgram, raw)
	if err != nil {
		return nil, err
	}
	ow, n, d := s.Predictors+7, s.Slots, s.Predictors+1
	flags := []groupedWord{normalized[len(normalized)-1]}
	normalized = normalized[:len(normalized)-1]
	live := make([]groupedWord, n)
	for i := range live {
		live[i] = normalized[i*ow+ow-2]
	}
	whiteProgram, err := groupedGEEWhiteningCompile(s)
	if err != nil {
		return nil, err
	}
	white, err := boundary("private-whitening", whiteProgram, append(append([]groupedWord(nil), live...), flags[0]))
	if err != nil {
		return nil, err
	}
	flags = append(flags, white[len(white)-1])
	white = white[:len(white)-1]
	profiles := make([]groupedWord, n*4)
	names := []string{"sigmoid", "sqrt_variance", "inverse_sqrt_variance", "softplus"}
	if s.Family == "poisson" {
		names = []string{"exp", "exp", "exp"}
	}
	for k, name := range names {
		args := make([]groupedWord, n)
		offset := 0
		if s.Family == "poisson" {
			offset = k
		}
		for i := range args {
			args[i] = normalized[i*ow+offset]
		}
		p, err := groupedWideScalarCompile(name, n)
		if err != nil {
			return nil, err
		}
		values, err := boundary(fmt.Sprintf("profile-%d-%s", k, name), p, args)
		if err != nil {
			return nil, err
		}
		flags = append(flags, values[n])
		for i := 0; i < n; i++ {
			profiles[i*4+k] = values[i]
			if s.Family == "poisson" && k == 0 {
				profiles[i*4+3] = values[i]
			}
		}
	}
	validityProgram, err := groupedGEEValidityCompile(len(flags))
	if err != nil {
		return nil, err
	}
	valid, err := boundary("predecessor-validity", validityProgram, flags)
	if err != nil {
		return nil, err
	}
	x, y, err := groupedGEEBaseOperands(s, normalized, profiles)
	if err != nil {
		return nil, err
	}
	products, err := product("base-products", x, y)
	if err != nil {
		return nil, err
	}
	unmasked, err := groupedGEEBaseShares(s, normalized, profiles, products)
	if err != nil {
		return nil, err
	}
	baseProgram, err := groupedGEEBaseBoundaryCompile(s)
	if err != nil {
		return nil, err
	}
	masked, err := boundary("live-factor-mask", baseProgram, append(append(unmasked, live...), valid[0]))
	if err != nil {
		return nil, err
	}
	factorBase := make([]groupedWord, 0, n*(d+1))
	loss := groupedWord{}
	for i := 0; i < n; i++ {
		factorBase = append(factorBase, masked[i*(d+2):i*(d+2)+d+1]...)
		loss = loss.add(masked[i*(d+2)+d+1])
	}
	x, y, err = groupedGEEWhiteningOperands(s, white, factorBase)
	if err != nil {
		return nil, err
	}
	products, err = product("whitening-products", x, y)
	if err != nil {
		return nil, err
	}
	sums, err := groupedGEEWhiteningSums(s, products)
	if err != nil {
		return nil, err
	}
	factorProgram, err := groupedGEEFactorBoundaryCompile(s)
	if err != nil {
		return nil, err
	}
	factors, err := boundary("factor-rounding", factorProgram, append(sums, masked[len(masked)-1]))
	if err != nil {
		return nil, err
	}
	return &groupedGEEFactorResult{factors[:len(factors)-1], loss, factors[len(factors)-1], cert, schedule}, nil
}
