package main

// Internal LMM composition after authenticated private routing and Ring128 to
// Ring192 conversion. This graph grants no source read or release capability.
// Every edge is consumed through the shared durable executor; no mutable
// accumulator survives a stage, so replay cannot double-add a product chunk.
import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
)

type groupedLMMStagedSpec struct {
	Moments                     groupedLMMMomentPlan
	Numeric                     groupedLMMSpec
	Beta                        [][]*big.Int
	Caps                        []int64
	SourceDigest, ProfileDigest [32]byte
	RoutedStage                 string // authenticated Ring192 f50, cluster/slot/column order
}

type groupedLMMStagedGraph struct {
	Plans   []crossGridStagePlan
	Compute []crossGridStageCompute
}

func (s groupedLMMStagedSpec) validate() error {
	if s.Moments.validate() != nil || groupedLMMValidate(s.Numeric) != nil ||
		s.Numeric.Slots != s.Moments.Slots || len(s.Beta) < 1 || len(s.Beta) > 256 ||
		len(s.Caps) != len(s.Beta) || s.SourceDigest == ([32]byte{}) ||
		s.ProfileDigest == ([32]byte{}) || s.RoutedStage == "" {
		return primitiveVError()
	}
	// Reuse the public-coefficient validator without invoking private arithmetic.
	n := s.Moments.Clusters * s.Moments.triangle()
	if _, err := groupedLMMGridShares(s.Moments, make([]groupedWord, n), make([]groupedWord, n), s.Beta); err != nil {
		return err
	}
	for _, cap := range s.Caps {
		if cap < 1 || cap > 9007199254740991 {
			return primitiveVError()
		}
	}
	return nil
}

// groupedLMMBuildStagedGraph binds all public arithmetic parameters in its
// profile digest. Public capacities are not a measured admission decision.
func groupedLMMBuildStagedGraph(s groupedLMMStagedSpec, role exactGCRole) (*groupedLMMStagedGraph, error) {
	if s.validate() != nil || (role != exactGCRoleGarbler && role != exactGCRoleEvaluator) {
		return nil, primitiveVError()
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, primitiveVError()
	}
	// Freeze caller-owned slices and big integers before closures capture them.
	// Later mutation must not change arithmetic under an already pinned digest.
	var pinned groupedLMMStagedSpec
	if json.Unmarshal(raw, &pinned) != nil {
		return nil, primitiveVError()
	}
	s = pinned
	p := s.Moments
	profile := sha256.Sum256(raw)
	graph := &groupedLMMStagedGraph{}
	add := func(id, kind string, scale, count, ring int, predecessors []string, coordinate func(int) string,
		compute func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error)) {
		coordinates := make([]string, count)
		for i := range coordinates {
			coordinates[i] = coordinate(i)
		}
		graph.Plans = append(graph.Plans, crossGridStagePlan{ID: id, Kind: kind, Ring: ring, FPScale: scale,
			CoordOrder: coordinates, PublicBounds: map[string]int{"clusters": p.Clusters, "slots": p.Slots, "columns": p.Columns, "candidates": len(s.Beta)},
			SourceDigest: s.SourceDigest, ProfileDigest: profile, Predecessors: predecessors})
		graph.Compute = append(graph.Compute, compute)
	}
	coord := func(prefix string) func(int) string {
		return func(i int) string { return fmt.Sprintf("%s:%d", prefix, i) }
	}
	countRows := p.Clusters * p.Slots * p.Columns
	productIDs := []string{}
	for start := 0; start < p.products(); start += 1024 {
		start := start
		count := p.products() - start
		if count > 1024 {
			count = 1024
		}
		id := fmt.Sprintf("lmm.products.%06d", start/1024)
		productIDs = append(productIDs, id)
		add(id, "lmm.exact-moment-products", 100, count, 192, []string{s.RoutedStage}, func(i int) string {
			k := start + i
			within := p.Clusters * p.Slots * p.triangle()
			kind := "within"
			if k >= within {
				k -= within
				kind = "between"
			}
			a, b := p.pair(k % p.triangle())
			return fmt.Sprintf("%s:%d:%d:%d", kind, k/p.triangle(), a, b)
		}, func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 1 {
				return crossGridStageOutput{}, primitiveVError()
			}
			rows, e := groupedLMMStagedWords(in[0], countRows)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			moments, e := groupedLMMPrepareMoments(p, rows)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			x, y, e := moments.operands(rows, start, count)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			session := groupedLMMStagedSession(attempt, "products")
			value, e := groupedArithmeticProduct(rw, session, role, groupedArithmeticPlan{Contract: profile, Count: count}, x, y)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			return groupedLMMStagedOutput(rw, attempt, role, value.Shares, in)
		})
	}
	triangle := p.Clusters * p.triangle()
	add("lmm.moments", "lmm.sufficient-statistic-assembly", 100, 2*triangle, 192, productIDs, func(i int) string {
		kind := "within"
		if i >= triangle {
			i -= triangle
			kind = "between"
		}
		a, b := p.pair(i % p.triangle())
		return fmt.Sprintf("%s:%d:%d:%d", kind, i/p.triangle(), a, b)
	}, func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != len(productIDs) {
			return crossGridStageOutput{}, primitiveVError()
		}
		m := &groupedLMMMoments{Plan: p, Within: make([]groupedWord, triangle), Between: make([]groupedWord, triangle)}
		for k, value := range in {
			count := p.products() - 1024*k
			if count > 1024 {
				count = 1024
			}
			words, e := groupedLMMStagedWords(value, count)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			if e = m.accumulate(1024*k, words); e != nil {
				return crossGridStageOutput{}, e
			}
		}
		return groupedLMMStagedOutput(rw, attempt, role, append(m.Within, m.Between...), in)
	})
	add("lmm.precision", "lmm.private-count-precision", 64, p.Clusters, 192, []string{s.RoutedStage}, coord("cluster-lambda"), func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 {
			return crossGridStageOutput{}, primitiveVError()
		}
		rows, e := groupedLMMStagedWords(in[0], countRows)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		m, e := groupedLMMPrepareMoments(p, rows)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		program, e := groupedLMMPrecisionCompile(s.Numeric)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		words := make([]groupedWord, p.Clusters)
		profileValid := make([]byte, p.Clusters)
		for c := 0; c < p.Clusters; c++ {
			out, e := groupedLMMStagedPrimitive(rw, attempt, role, fmt.Sprintf("count/%d", c), profile, program, []groupedWord{m.Sums[c*p.Columns]})
			if e != nil {
				return crossGridStageOutput{}, e
			}
			words[c] = out[0]
			profileValid[c] = byte(out[1][0] & 1)
		}
		validity := append(append([]byte(nil), in[0].Validity...), profileValid...)
		return groupedLMMStagedOutput(rw, attempt, role, words, []crossGridStageOutput{{Validity: validity}})
	})
	correctionIDs := []string{}
	for start := 0; start < triangle; start += 1024 {
		start := start
		count := triangle - start
		if count > 1024 {
			count = 1024
		}
		id := fmt.Sprintf("lmm.correction.%06d", start/1024)
		correctionIDs = append(correctionIDs, id)
		add(id, "lmm.exact-precision-products", 164, count, 192, []string{"lmm.moments", "lmm.precision"}, func(i int) string { return fmt.Sprintf("precision-product:%d", start+i) }, func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 2 {
				return crossGridStageOutput{}, primitiveVError()
			}
			mom, e := groupedLMMStagedWords(in[0], 2*triangle)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			lambda, e := groupedLMMStagedWords(in[1], p.Clusters)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			y := make([]groupedWord, count)
			for i := range y {
				y[i] = lambda[(start+i)/p.triangle()]
			}
			result, e := groupedArithmeticProduct(rw, groupedLMMStagedSession(attempt, "products"), role, groupedArithmeticPlan{Contract: profile, Count: count}, mom[triangle+start:triangle+start+count], y)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			return groupedLMMStagedOutput(rw, attempt, role, result.Shares, in)
		})
	}
	gramPredecessors := append([]string{"lmm.moments"}, correctionIDs...)
	add("lmm.gram", "lmm.precision-gram", 164, triangle, 192, gramPredecessors, coord("precision-gram"), func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != len(gramPredecessors) {
			return crossGridStageOutput{}, primitiveVError()
		}
		mom, e := groupedLMMStagedWords(in[0], 2*triangle)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		products := make([]groupedWord, 0, triangle)
		for k, value := range in[1:] {
			count := triangle - 1024*k
			if count > 1024 {
				count = 1024
			}
			v, e := groupedLMMStagedWords(value, count)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			products = append(products, v...)
		}
		m := &groupedLMMMoments{Plan: p, Within: mom[:triangle], Between: mom[triangle:]}
		words, e := groupedLMMPrecisionShares(m, s.Numeric, products)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		return groupedLMMStagedOutput(rw, attempt, role, words, in)
	})
	add("lmm.lift", "lmm.signed-192-to-two-limbs", 164, 2*triangle, 192, []string{"lmm.gram"}, func(i int) string { return fmt.Sprintf("precision-gram:%d:limb:%d", i/2, i%2) }, func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 {
			return crossGridStageOutput{}, primitiveVError()
		}
		low, e := groupedLMMStagedWords(in[0], triangle)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		words := make([]groupedWord, 2*triangle)
		for start := 0; start < triangle; start += 32 {
			count := triangle - start
			if count > 32 {
				count = 32
			}
			program, e := groupedLMMLiftCompile(count)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			high, e := groupedLMMStagedPrimitive(rw, attempt, role, fmt.Sprintf("lift/%d", start), profile, program, low[start:start+count])
			if e != nil {
				return crossGridStageOutput{}, e
			}
			for i := 0; i < count; i++ {
				words[2*(start+i)] = low[start+i]
				words[2*(start+i)+1] = high[i]
			}
		}
		return groupedLMMStagedOutput(rw, attempt, role, words, in)
	})
	add("lmm.grid", "lmm.public-grid-quadratic", 264, 2*p.Clusters*len(s.Beta), 192, []string{"lmm.lift"}, func(i int) string {
		return fmt.Sprintf("cluster:%d:candidate:%d:limb:%d", i/(2*len(s.Beta)), (i/2)%len(s.Beta), i%2)
	}, func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 {
			return crossGridStageOutput{}, primitiveVError()
		}
		lift, e := groupedLMMStagedWords(in[0], 2*triangle)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		low, high := make([]groupedWord, triangle), make([]groupedWord, triangle)
		for i := range low {
			low[i], high[i] = lift[2*i], lift[2*i+1]
		}
		grid, e := groupedLMMGridShares(p, low, high, s.Beta)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		words := make([]groupedWord, 0, 2*len(grid))
		for _, v := range grid {
			words = append(words, v[:]...)
		}
		return groupedLMMStagedOutput(rw, attempt, role, words, in)
	})
	add("lmm.terminal", "lmm.certified-clamp-quantize-ring128", s.Numeric.GridBits, len(s.Beta), 128, []string{"lmm.grid"}, coord("candidate-loss"), func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 {
			return crossGridStageOutput{}, primitiveVError()
		}
		grid, e := groupedLMMStagedWords(in[0], 2*p.Clusters*len(s.Beta))
		if e != nil {
			return crossGridStageOutput{}, e
		}
		valid, e := groupedLMMStagedValidity(rw, attempt, role, "terminal-validity", in[0].Validity)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		sums := make([]groupedWord, len(s.Beta))
		flags := make([]byte, p.Clusters*len(s.Beta))
		for j, cap := range s.Caps {
			program, e := groupedLMMFinalCompile(s.Numeric.GridBits, cap)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			for c := 0; c < p.Clusters; c++ {
				i := c*len(s.Beta) + j
				out, e := groupedLMMStagedPrimitive(rw, attempt, role, fmt.Sprintf("final/%d", i), profile, program, []groupedWord{grid[2*i], grid[2*i+1], valid})
				if e != nil {
					return crossGridStageOutput{}, e
				}
				sums[j] = sums[j].add(out[0])
				flags[i] = byte(out[1][0] & 1)
			}
		}
		all, e := groupedLMMStagedValidity(rw, attempt, role, "final-validity", flags)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		out := crossGridStageOutput{Share: make([]byte, 16*len(sums)), Validity: make([]byte, len(sums))}
		for i, w := range sums {
			copy(out.Share[16*i:16*(i+1)], groupedEncodeWords([]groupedWord{w})[:16])
			out.Validity[i] = byte(all[0] & 1)
		}
		return out, nil
	})
	return graph, nil
}

func groupedLMMStagedWords(value crossGridStageOutput, count int) ([]groupedWord, error) {
	if len(value.Share) != 24*count || len(value.Validity) != count {
		return nil, primitiveVError()
	}
	words := make([]groupedWord, count)
	for i := range words {
		if value.Validity[i] > 1 {
			return nil, primitiveVError()
		}
		words[i] = groupedDecodeWord(value.Share[24*i : 24*(i+1)])
	}
	return words, nil
}

func groupedLMMStagedSession(attempt crossGridStageAttempt, label string) exactGCSession {
	s := attempt.Session
	// Each composed exchange has its own secure-record domain, even while using
	// the same transport. Attempt.Session is already fresh after an abort.
	s.Purpose = fmt.Sprintf("%s/lmm/%x/%s", s.Purpose, attempt.OutputMaskDomainTag, label)
	return s
}

func groupedLMMStagedPrimitive(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, label string, contract [32]byte, program *primitiveVProgram, words []groupedWord) ([]groupedWord, error) {
	input := make([]*big.Int, len(words))
	for i, w := range words {
		input[i] = groupedWordInteger(w)
	}
	run := primitiveVRunGarbler
	if role == exactGCRoleEvaluator {
		run = primitiveVRunEvaluator
	}
	output, err := run(rw, program, groupedLMMStagedSession(attempt, label), contract, input)
	if err != nil {
		return nil, err
	}
	result := make([]groupedWord, len(output))
	for i, w := range output {
		result[i] = groupedWordFromBig(w)
	}
	return result, nil
}

// XOR-validity is never ANDed locally. Packed XOR words keep the private
// conjunction within the existing circuit input bound; output stays shared.
func groupedLMMStagedValidity(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, label string, flags []byte) (groupedWord, error) {
	if len(flags) < 1 || len(flags) > 192*2048 {
		return groupedWord{}, primitiveVError()
	}
	count := (len(flags) + 191) / 192
	words := make([]groupedWord, count)
	for i, flag := range flags {
		if flag > 1 {
			return groupedWord{}, primitiveVError()
		}
		words[i/192][(i%192)/64] |= uint64(flag) << uint(i%64)
	}
	var source strings.Builder
	fmt.Fprintf(&source, "package main\nfunc main(g [%d]uint192,e [%d]uint192) [1]uint192 {\nv:=uint192(1)\n", count+1, count)
	for i := 0; i < count; i++ {
		bits := len(flags) - 192*i
		if bits > 192 {
			bits = 192
		}
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
		fmt.Fprintf(&source, "if (g[%d]^e[%d])!=uint192(%s) {v=0}\n", i, i, mask)
	}
	fmt.Fprintf(&source, "var out [1]uint192\nout[0]=v-g[%d]\nreturn out\n}\n", count)
	program, err := primitiveVCompile(source.String(), 192, count+1, count, 1)
	if err != nil {
		return groupedWord{}, err
	}
	contract := sha256.Sum256([]byte("lmm-staged-private-validity-v1"))
	out, err := groupedLMMStagedPrimitive(rw, attempt, role, label, contract, program, words)
	if err != nil {
		return groupedWord{}, err
	}
	return out[0], nil
}

func groupedLMMStagedOutput(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, words []groupedWord, inputs []crossGridStageOutput) (crossGridStageOutput, error) {
	var flags []byte
	for _, input := range inputs {
		flags = append(flags, input.Validity...)
	}
	valid, err := groupedLMMStagedValidity(rw, attempt, role, "output-validity", flags)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	output := crossGridStageOutput{Share: groupedEncodeWords(words), Validity: make([]byte, len(words))}
	for i := range output.Validity {
		output.Validity[i] = byte(valid[0] & 1)
	}
	return output, nil
}
