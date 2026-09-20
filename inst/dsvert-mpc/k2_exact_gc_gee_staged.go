package main

// Internal fixed-rho v3 predecessor composition. This is not H.4's unresolved
// moment-estimated-alpha contract and does not authorize a public release.
// One instance consumes one candidate/cluster after once-only private routing.
import (
	"fmt"
	"io"
	"strings"
)

type groupedGEEStagedSpec struct {
	Numeric                groupedGEESpec
	ClusterCap             int64
	Prefix                 string
	SourceDigest, Contract [32]byte
	// Ring192 records: complete eta q100, features q50, then row-major y/live q0.
	Sources             [3]crossGridStagePlan
	CorrelationContract string
}

type groupedGEEStagedGraph struct {
	Plans   []crossGridStagePlan
	Compute []crossGridStageCompute
}

// Downscaling additive shares is PRIVATE: reconstruction precedes the shift.
// Exact common-lattice records never right-shift individual masked shares.
func groupedGEEStagedUnpackCompile(shifts []int) (*primitiveVProgram, error) {
	if len(shifts) == 0 {
		return nil, primitiveVError()
	}
	n := len(shifts)
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=g[%d]+e[%d]==1\n", 2*(n+1), n+1, n+1, n+1, n, n)
	for i, shift := range shifts {
		if shift < 0 || shift > 100 {
			return nil, primitiveVError()
		}
		fmt.Fprintf(&b, "x%d:=g[%d]+e[%d]\n", i, i, i)
		if shift > 0 {
			fmt.Fprintf(&b, "valid=valid && (x%d>>%d)<<%d==x%d\nx%d=x%d>>%d\n", i, shift, shift, i, i, i, shift)
		}
	}
	for i := range shifts {
		fmt.Fprintf(&b, "if !valid { x%d=0 }\nout[%d]=x%d-g[%d]\n", i, i, i, n+1+i)
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid { v=1 }\nout[%d]=v-g[%d]\nreturn out\n}\n", n, 2*n+1)
	return primitiveVCompile(b.String(), 192, 2*(n+1), n+1, n+1)
}

func groupedGEEStagedOutput(words []groupedWord, valid groupedWord) crossGridStageOutput {
	out := crossGridStageOutput{Share: groupedEncodeWords(words), Validity: make([]byte, len(words))}
	for i := range out.Validity {
		out.Validity[i] = byte(valid[0] & 1)
	}
	return out
}

func groupedGEEBuildStagedGraph(s groupedGEEStagedSpec, role exactGCRole) (*groupedGEEStagedGraph, error) {
	n, p := s.Numeric.Slots, s.Numeric.Predictors
	d := p + 1
	tri := d * (d + 1) / 2
	if groupedGEEValidate(s.Numeric) != nil || s.ClusterCap < 1 || s.ClusterCap > 1<<40 || s.SourceDigest == ([32]byte{}) || s.Contract == ([32]byte{}) || exactGCValidateLabel("stage", s.Prefix, 80) != nil || s.CorrelationContract != "signed-fixed-rho-v3-predecessor" || (role != exactGCRoleGarbler && role != exactGCRoleEvaluator) {
		return nil, primitiveVError()
	}
	widths := [3]int{n, n * p, 2 * n}
	scales := [3]int{100, 50, 0}
	ids := make([]string, 3)
	for i, src := range s.Sources {
		if src.Ring != 192 || src.FPScale != scales[i] || len(src.CoordOrder) != widths[i] || src.SourceDigest != s.SourceDigest || src.ID == "" {
			return nil, primitiveVError()
		}
		ids[i] = src.ID
		for j := 0; j < i; j++ {
			if ids[i] == ids[j] {
				return nil, primitiveVError()
			}
		}
	}
	profile := crossGridStageHash("gee-fixed-rho-v3-staged", s)
	graph := &groupedGEEStagedGraph{}
	add := func(id, kind string, scale, count int, previous []string, compute crossGridStageCompute) {
		coords := make([]string, count)
		for i := range coords {
			coords[i] = fmt.Sprintf("%s/coordinate/%d", id, i)
		}
		graph.Plans = append(graph.Plans, crossGridStagePlan{ID: id, Kind: kind, Ring: 192, FPScale: scale, CoordOrder: coords, PublicBounds: map[string]int{"slots": n, "predictors": p}, SourceDigest: s.SourceDigest, ProfileDigest: profile, Predecessors: previous})
		graph.Compute = append(graph.Compute, compute)
	}
	boundary := func(rw io.ReadWriter, a crossGridStageAttempt, label string, program *primitiveVProgram, x []groupedWord) ([]groupedWord, error) {
		return groupedLMMStagedPrimitive(rw, a, role, "gee/"+label, profile, program, x)
	}
	product := func(rw io.ReadWriter, a crossGridStageAttempt, label string, x, y []groupedWord) ([]groupedWord, error) {
		result, err := registerGroupedExactArithmetic()(rw, groupedLMMStagedSession(a, "gee/"+label), role, groupedArithmeticPlan{Contract: profile, Count: len(x)}, x, y)
		if err != nil {
			return nil, err
		}
		return result.Shares, nil
	}
	factorsID, momentsID, terminalID := s.Prefix+".factors", s.Prefix+".moments", s.Prefix+".terminal"
	add(factorsID, "gee.v3.fixed-rho-factors", 64, n*(d+1)+1, ids, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 3 {
			return crossGridStageOutput{}, primitiveVError()
		}
		var fields [3][]groupedWord
		var flags []byte
		for i := range in {
			var err error
			fields[i], err = groupedLMMStagedWords(in[i], widths[i])
			if err != nil {
				return crossGridStageOutput{}, err
			}
			flags = append(flags, in[i].Validity...)
		}
		raw := make([]groupedWord, 0, n*(p+3))
		for i := 0; i < n; i++ {
			raw = append(raw, fields[0][i])
			raw = append(raw, fields[1][i*p:(i+1)*p]...)
			raw = append(raw, fields[2][2*i:2*i+2]...)
		}
		inputValid, err := groupedLMMStagedValidity(rw, a, role, "gee/source-validity", flags)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		result, err := groupedGEERegistry().ProduceFactors(rw, groupedLMMStagedSession(a, "gee/producer"), role, profile, s.Numeric, raw)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		vp, err := groupedGEEValidityCompile(2)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		valid, err := boundary(rw, a, "factor-validity", vp, []groupedWord{inputValid, result.Valid})
		if err != nil {
			return crossGridStageOutput{}, err
		}
		// Common q64 lattice: factors unchanged, q32 likelihood shifted exactly.
		words := append(result.Factors, result.Likelihood.shl(32))
		return groupedGEEStagedOutput(words, valid[0]), nil
	})
	add(momentsID, "gee.v3.score-bread", 64, d+tri+1, []string{factorsID}, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 {
			return crossGridStageOutput{}, primitiveVError()
		}
		words, err := groupedLMMStagedWords(in[0], n*(d+1)+1)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		valid, err := groupedLMMStagedValidity(rw, a, role, "gee/factor-validity", in[0].Validity)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		x, y, err := groupedGEEMomentOperands(s.Numeric, words[:len(words)-1])
		if err != nil {
			return crossGridStageOutput{}, err
		}
		products, err := product(rw, a, "moment-products", x, y)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		sums, err := groupedGEEMomentSums(s.Numeric, products)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		program, err := groupedGEEMomentBoundaryCompile(s.Numeric)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		moments, err := boundary(rw, a, "moment-boundary", program, append(sums, valid))
		if err != nil {
			return crossGridStageOutput{}, err
		}
		out := make([]groupedWord, d+tri+1)
		for i := 0; i < d; i++ {
			out[i] = moments[i].shl(48)
		}
		for i := 0; i < tri; i++ {
			out[d+i] = moments[d+i].shl(64 - s.Numeric.GridBits)
		}
		out[d+tri] = words[len(words)-1]
		return groupedGEEStagedOutput(out, moments[len(moments)-1]), nil
	})
	add(terminalID, "gee.v3.likelihood-bread-meat", s.Numeric.GridBits, 1+2*tri, []string{momentsID}, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 {
			return crossGridStageOutput{}, primitiveVError()
		}
		words, err := groupedLMMStagedWords(in[0], d+tri+1)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		valid, err := groupedLMMStagedValidity(rw, a, role, "gee/moment-validity", in[0].Validity)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		shifts := make([]int, len(words))
		for i := 0; i < d; i++ {
			shifts[i] = 48
		}
		for i := 0; i < tri; i++ {
			shifts[d+i] = 64 - s.Numeric.GridBits
		}
		shifts[len(shifts)-1] = 32
		unpack, err := groupedGEEStagedUnpackCompile(shifts)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		decoded, err := boundary(rw, a, "common-lattice-unpack", unpack, append(words, valid))
		if err != nil {
			return crossGridStageOutput{}, err
		}
		valid = decoded[len(decoded)-1]
		x, y, err := groupedGEEMeatOperands(s.Numeric, decoded[:d])
		if err != nil {
			return crossGridStageOutput{}, err
		}
		products, err := product(rw, a, "meat-products", x, y)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		meatProgram, err := groupedGEEMeatFinalCompile(s.Numeric)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		meat, err := boundary(rw, a, "meat-boundary", meatProgram, append(products, valid))
		if err != nil {
			return crossGridStageOutput{}, err
		}
		lossProgram, err := groupedGEELikelihoodCompile(s.Numeric, s.ClusterCap)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		loss, err := boundary(rw, a, "likelihood-boundary", lossProgram, []groupedWord{decoded[d+tri], valid})
		if err != nil {
			return crossGridStageOutput{}, err
		}
		vp, err := groupedGEEValidityCompile(3)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		flags, err := boundary(rw, a, "terminal-validity", vp, []groupedWord{valid, meat[tri], loss[1]})
		if err != nil {
			return crossGridStageOutput{}, err
		}
		out := append([]groupedWord{loss[0]}, decoded[d:d+tri]...)
		out = append(out, meat[:tri]...)
		// Zero every branch if any branch rejected; never release partial validity.
		gate, err := groupedGEEStagedUnpackCompile(make([]int, len(out)))
		if err != nil {
			return crossGridStageOutput{}, err
		}
		gated, err := boundary(rw, a, "terminal-gate", gate, append(out, flags[0]))
		if err != nil {
			return crossGridStageOutput{}, err
		}
		return groupedGEEStagedOutput(gated[:len(out)], gated[len(out)]), nil
	})
	// Canonical coordinates document the exact common-lattice embedding.
	factorOrder := graph.Plans[0].CoordOrder
	for row := 0; row < n; row++ {
		for k := 0; k < d; k++ {
			factorOrder[row*(d+1)+k] = fmt.Sprintf("row/%d/whitened-u/%d", row, k)
		}
		factorOrder[row*(d+1)+d] = fmt.Sprintf("row/%d/whitened-z", row)
	}
	factorOrder[len(factorOrder)-1] = "likelihood-q32-lifted-to-q64"
	momentOrder := graph.Plans[1].CoordOrder
	for k := 0; k < d; k++ {
		momentOrder[k] = fmt.Sprintf("clipped-score/%d/q16-lifted-to-q64", k)
	}
	terminalOrder := graph.Plans[2].CoordOrder
	terminalOrder[0] = "likelihood"
	index := 0
	for col := 0; col < d; col++ {
		for row := 0; row <= col; row++ {
			momentOrder[d+index] = fmt.Sprintf("bread/%d/%d/grid-lifted-to-q64", row, col)
			terminalOrder[1+index] = fmt.Sprintf("bread/%d/%d", row, col)
			terminalOrder[1+tri+index] = fmt.Sprintf("shifted-meat/%d/%d", row, col)
			index++
		}
	}
	momentOrder[len(momentOrder)-1] = "likelihood-q32-lifted-to-q64"
	return graph, nil
}
