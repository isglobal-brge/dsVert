package main

// Binomial GH5 composition. All edges are homogeneous, authenticated durable
// stages; no accumulator crosses a stage boundary outside a committed output.
import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
)

type groupedGLMMStagedSpec struct {
	Clusters, Slots, Predictors, GridBits int
	Beta                                  [][]*big.Int
	Caps                                  []int64
	VarianceGrid                          []int64
	SourceDigest, ProfileDigest           [32]byte
	RoutedStage                           string
}
type groupedGLMMStagedGraph struct {
	Plans   []crossGridStagePlan
	Compute []crossGridStageCompute
}

func (s groupedGLMMStagedSpec) validate() error {
	if s.Clusters < 1 || s.Clusters > 500 || s.Slots < 1 || s.Slots > 16 || s.Clusters*s.Slots > 2000 || s.Predictors < 1 || s.Predictors > 3 || s.GridBits < 8 || s.GridBits > 18 || len(s.Beta) < 1 || len(s.Beta) > 4 || len(s.VarianceGrid) < 1 || len(s.VarianceGrid) > 2 || len(s.Caps) != len(s.Beta)*len(s.VarianceGrid) || len(s.Caps) > 4 || s.SourceDigest == ([32]byte{}) || s.ProfileDigest == ([32]byte{}) || s.RoutedStage == "" {
		return primitiveVError()
	}
	for j, v := range s.VarianceGrid {
		if (v != 0 && v != 16384) || (j > 0 && v <= s.VarianceGrid[j-1]) {
			return primitiveVError()
		}
	}
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	for _, beta := range s.Beta {
		if len(beta) != s.Predictors+1 {
			return primitiveVError()
		}
		lo, hi := new(big.Int), new(big.Int)
		for j, b := range beta {
			if b == nil || new(big.Int).Abs(b).Cmp(f) > 0 {
				return primitiveVError()
			}
			if j == 0 {
				lo.Set(b)
				hi.Set(b)
			} else if b.Sign() < 0 {
				lo.Add(lo, b)
			} else {
				hi.Add(hi, b)
			}
		}
		if lo.Cmp(new(big.Int).Neg(f)) < 0 || hi.Cmp(f) > 0 {
			return primitiveVError()
		}
	}
	for _, cap := range s.Caps {
		if cap < 1 || cap > 9007199254740991 {
			return primitiveVError()
		}
	}
	return nil
}

// Full-width checks precede every narrowing, including the logsum boundary.
func groupedGLMMGuardCompile(count int, liveOutcome bool) (*primitiveVProgram, error) {
	if count < 1 || count > 32 {
		return nil, primitiveVError()
	}
	inputs, outputs := count, count
	if liveOutcome {
		inputs, outputs = 2*count, 2*count
	}
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=true\n", inputs+outputs+1, inputs, outputs+1, outputs+1)
	for i := 0; i < count; i++ {
		if liveOutcome {
			fmt.Fprintf(&b, "l%d:=g[%d]+e[%d]\ny%d:=g[%d]+e[%d]\nok%d:=(l%d==0 || l%d==1125899906842624) && (y%d==0 || y%d==1125899906842624) && y%d<=l%d\nvalid=valid && ok%d\na%d:=int192(0)\nb%d:=int192(0)\nif ok%d && l%d!=0 {a%d=1}\nif ok%d && y%d!=0 {b%d=1}\n", i, 2*i, 2*i, i, 2*i+1, 2*i+1, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i)
		} else {
			fmt.Fprintf(&b, "a%d:=g[%d]+e[%d]\nok%d:=a%d>=65536 && a%d<=327680\nvalid=valid && ok%d\nif !ok%d {a%d=65536}\n", i, i, i, i, i, i, i, i, i)
		}
	}
	for i := 0; i < count; i++ {
		if liveOutcome {
			fmt.Fprintf(&b, "out[%d]=a%d-g[%d]\nout[%d]=b%d-g[%d]\n", 2*i, i, inputs+2*i, 2*i+1, i, inputs+2*i+1)
		} else {
			fmt.Fprintf(&b, "out[%d]=a%d-g[%d]\n", i, i, inputs+i)
		}
	}
	fmt.Fprintf(&b, "v:=int192(0)\nif valid {v=1}\nout[%d]=v-g[%d]\nreturn out\n}\n", outputs, inputs+outputs)
	return primitiveVCompile(b.String(), 192, inputs+outputs+1, inputs, outputs+1)
}

func groupedGLMMBuildStagedGraph(s groupedGLMMStagedSpec, role exactGCRole) (*groupedGLMMStagedGraph, error) {
	if s.validate() != nil || role > exactGCRoleEvaluator {
		return nil, primitiveVError()
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var pinned groupedGLMMStagedSpec
	if json.Unmarshal(raw, &pinned) != nil {
		return nil, primitiveVError()
	}
	s = pinned
	profile := sha256.Sum256(raw)
	rows, cols := s.Clusters*s.Slots, s.Predictors+2
	graph := &groupedGLMMStagedGraph{}
	add := func(id, kind string, scale, count, ring int, previous []string, coordinate func(int) string, compute crossGridStageCompute) {
		coords := make([]string, count)
		for i := range coords {
			coords[i] = coordinate(i)
		}
		graph.Plans = append(graph.Plans, crossGridStagePlan{ID: id, Kind: kind, Ring: ring, FPScale: scale, CoordOrder: coords, PublicBounds: map[string]int{"clusters": s.Clusters, "slots": s.Slots, "predictors": s.Predictors, "candidates": len(s.Caps)}, SourceDigest: s.SourceDigest, ProfileDigest: profile, Predecessors: previous})
		graph.Compute = append(graph.Compute, compute)
	}
	coord := func(prefix string) func(int) string {
		return func(i int) string { return fmt.Sprintf("%s:%d", prefix, i) }
	}
	// q0 layout: row-major live,y followed by one private count per cluster.
	add("glmm.live-outcome-count", "glmm.full-width-live-outcome-q0", 0, 2*rows+s.Clusters, 192, []string{s.RoutedStage}, func(i int) string {
		if i < 2*rows {
			return fmt.Sprintf("row:%d:%s", i/2, []string{"live", "y"}[i%2])
		}
		return fmt.Sprintf("cluster:%d:count", i-2*rows)
	}, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 {
			return crossGridStageOutput{}, primitiveVError()
		}
		r, e := groupedLMMStagedWords(in[0], rows*cols)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		out := make([]groupedWord, 2*rows+s.Clusters)
		var flags []byte
		var program *primitiveVProgram
		for start := 0; start < rows; start += 32 {
			n := min(32, rows-start)
			input := make([]groupedWord, 2*n)
			for i := 0; i < n; i++ {
				input[2*i] = r[(start+i)*cols]
				input[2*i+1] = r[(start+i)*cols+cols-1]
			}
			if program == nil || program.InputWordsE != 2*n {
				program, e = groupedGLMMGuardCompile(n, true)
				if e != nil {
					return crossGridStageOutput{}, e
				}
			}
			v, e := groupedGLMMStagedPrimitive(rw, a, role, fmt.Sprintf("live/%d", start), profile, program, input)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			copy(out[2*start:], v[:2*n])
			flags = append(flags, byte(v[2*n][0]&1))
		}
		for i := 0; i < rows; i++ {
			out[2*rows+i/s.Slots] = out[2*rows+i/s.Slots].add(out[2*i])
		}
		return groupedGLMMStagedOutput(rw, a, role, out, append(in, crossGridStageOutput{Validity: flags}))
	})
	for betaIndex, beta := range s.Beta {
		betaIndex, beta := betaIndex, beta
		etaID := fmt.Sprintf("glmm.beta.%03d.eta", betaIndex)
		add(etaID, "glmm.complete-dot-f100-rne-q64-q16", 16, rows, 192, []string{s.RoutedStage}, coord("row-eta"), func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 1 {
				return crossGridStageOutput{}, primitiveVError()
			}
			r, e := groupedLMMStagedWords(in[0], rows*cols)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			out := make([]groupedWord, rows)
			var flags []byte
			var program *primitiveVProgram
			for start := 0; start < rows; start += 32 {
				n := min(32, rows-start)
				dot := make([]groupedWord, n)
				for i := 0; i < n; i++ {
					for j, b := range beta {
						dot[i] = dot[i].add(r[(start+i)*cols+j].mul(groupedWordFromBig(b)))
					}
				}
				if program == nil || program.InputWordsE != n {
					program, e = groupedPredictorCompile(n, 1)
					if e != nil {
						return crossGridStageOutput{}, e
					}
				}
				v, e := groupedGLMMStagedPrimitive(rw, a, role, fmt.Sprintf("predictor/%d", start), profile, program, dot)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				copy(out[start:], v[:n])
				flags = append(flags, byte(v[n][0]&1))
			}
			return groupedGLMMStagedOutput(rw, a, role, out, append(in, crossGridStageOutput{Validity: flags}))
		})
		add(fmt.Sprintf("glmm.beta.%03d.yeta", betaIndex), "glmm.exact-y-times-eta", 16, rows, 192, []string{etaID, "glmm.live-outcome-count"}, coord("row-yeta"), func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 2 {
				return crossGridStageOutput{}, primitiveVError()
			}
			eta, e := groupedLMMStagedWords(in[0], rows)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			q0, e := groupedLMMStagedWords(in[1], 2*rows+s.Clusters)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			out := make([]groupedWord, rows)
			for start := 0; start < rows; start += 1024 {
				n := min(1024, rows-start)
				y := make([]groupedWord, n)
				for i := range y {
					y[i] = q0[2*(start+i)+1]
				}
				v, e := groupedArithmeticProduct(rw, groupedGLMMStagedSession(a, fmt.Sprintf("product/%d", start)), role, groupedArithmeticPlan{Contract: profile, Count: n}, y, eta[start:start+n])
				if e != nil {
					return crossGridStageOutput{}, e
				}
				copy(out[start:], v.Shares)
			}
			return groupedGLMMStagedOutput(rw, a, role, out, in)
		})
	}
	lossIDs := []string{}
	for varianceIndex, variance := range s.VarianceGrid {
		for betaIndex := range s.Beta {
			candidate := varianceIndex*len(s.Beta) + betaIndex
			numeric := groupedGLMMSpec{Family: "binomial", Rows: s.Slots, OutputBits: s.GridBits, VarianceQ16: variance}
			prefix := fmt.Sprintf("glmm.candidate.%03d", candidate)
			etaID, yetaID := fmt.Sprintf("glmm.beta.%03d.eta", betaIndex), fmt.Sprintf("glmm.beta.%03d.yeta", betaIndex)
			add(prefix+".profile", "glmm.gh5-softplus", 16, rows*5, 192, []string{etaID}, func(i int) string { return fmt.Sprintf("row:%d:node:%d", i/5, i%5) }, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
				if len(in) != 1 {
					return crossGridStageOutput{}, primitiveVError()
				}
				eta, e := groupedLMMStagedWords(in[0], rows)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				out := make([]groupedWord, 5*rows)
				var flags []byte
				// Retain only the current public chunk shape within this stage
				// attempt. Protocol calls still draw fresh masks and OT state.
				var program *primitiveVProgram
				for start := 0; start < len(out); start += 32 {
					n := min(32, len(out)-start)
					args := make([]groupedWord, n)
					for i := range args {
						k := start + i
						args[i] = eta[k/5]
						if role == exactGCRoleGarbler && variance != 0 {
							args[i] = args[i].add(groupedWordFromBig(big.NewInt(groupedGLMMNodes[k%5])))
						}
					}
					// Predictor range is full-width certified and the public node is <2^17;
					// hence every reconstructed q16 argument is a signed int32 here.
					if program == nil || program.InputWordsE != n {
						program, e = groupedWideScalarCompile("softplus", n)
						if e != nil {
							return crossGridStageOutput{}, e
						}
					}
					v, e := groupedGLMMStagedPrimitive(rw, a, role, fmt.Sprintf("softplus/%d", start), profile, program, args)
					if e != nil {
						return crossGridStageOutput{}, e
					}
					copy(out[start:], v[:n])
					flags = append(flags, byte(v[n][0]&1))
				}
				return groupedGLMMStagedOutput(rw, a, role, out, append(in, crossGridStageOutput{Validity: flags}))
			})
			add(prefix+".live-profile", "glmm.exact-live-times-profile", 16, rows*5, 192, []string{prefix + ".profile", "glmm.live-outcome-count"}, coord("row-node-product"), func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
				if len(in) != 2 {
					return crossGridStageOutput{}, primitiveVError()
				}
				values, e := groupedLMMStagedWords(in[0], 5*rows)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				q0, e := groupedLMMStagedWords(in[1], 2*rows+s.Clusters)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				out := make([]groupedWord, 5*rows)
				for start := 0; start < len(out); start += 1024 {
					n := min(1024, len(out)-start)
					live := make([]groupedWord, n)
					for i := range live {
						live[i] = q0[2*((start+i)/5)]
					}
					v, e := groupedArithmeticProduct(rw, groupedGLMMStagedSession(a, fmt.Sprintf("product/%d", start)), role, groupedArithmeticPlan{Contract: profile, Count: n}, live, values[start:start+n])
					if e != nil {
						return crossGridStageOutput{}, e
					}
					copy(out[start:], v.Shares)
				}
				return groupedGLMMStagedOutput(rw, a, role, out, in)
			})
			add(prefix+".center", "glmm.gh5-node-scores-private-center", 16, 6*s.Clusters, 192, []string{prefix + ".live-profile", yetaID, "glmm.live-outcome-count"}, func(i int) string { return fmt.Sprintf("cluster:%d:center:%d", i/6, i%6) }, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
				if len(in) != 3 {
					return crossGridStageOutput{}, primitiveVError()
				}
				values, e := groupedLMMStagedWords(in[0], 5*rows)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				yeta, e := groupedLMMStagedWords(in[1], rows)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				q0, e := groupedLMMStagedWords(in[2], 2*rows+s.Clusters)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				out := make([]groupedWord, 6*s.Clusters)
				flags := make([]byte, s.Clusters)
				program, e := groupedGLMMCenterCompile(numeric)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				for c := 0; c < s.Clusters; c++ {
					start := c * s.Slots
					y, live := make([]groupedWord, s.Slots), make([]groupedWord, s.Slots)
					for i := range y {
						y[i], live[i] = q0[2*(start+i)+1], q0[2*(start+i)]
					}
					scores, e := groupedGLMMScoreShares(numeric, role, values[5*start:5*(start+s.Slots)], yeta[start:start+s.Slots], y, live)
					if e != nil {
						return crossGridStageOutput{}, e
					}
					input := append(append([]groupedWord{}, scores[:]...), q0[2*rows+c])
					v, e := groupedGLMMStagedPrimitive(rw, a, role, fmt.Sprintf("center/%d", c), profile, program, input)
					if e != nil {
						return crossGridStageOutput{}, e
					}
					copy(out[6*c:], v[:6])
					flags[c] = byte(v[6][0] & 1)
				}
				return groupedGLMMStagedOutput(rw, a, role, out, append(in, crossGridStageOutput{Validity: flags}))
			})
			add(prefix+".exp-sum", "glmm.certified-negative-exp-sum", 16, s.Clusters, 192, []string{prefix + ".center"}, coord("cluster-expsum"), func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
				if len(in) != 1 {
					return crossGridStageOutput{}, primitiveVError()
				}
				center, e := groupedLMMStagedWords(in[0], 6*s.Clusters)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				out := make([]groupedWord, s.Clusters)
				var flags []byte
				var program *primitiveVProgram
				for start := 0; start < 5*s.Clusters; start += 32 {
					n := min(32, 5*s.Clusters-start)
					args := make([]groupedWord, n)
					for i := range args {
						k := start + i
						args[i] = center[6*(k/5)+k%5]
					}
					if program == nil || program.InputWordsE != n {
						program, e = groupedWideScalarCompile("exp_negative", n)
						if e != nil {
							return crossGridStageOutput{}, e
						}
					}
					v, e := groupedGLMMStagedPrimitive(rw, a, role, fmt.Sprintf("exp-negative/%d", start), profile, program, args)
					if e != nil {
						return crossGridStageOutput{}, e
					}
					for i := 0; i < n; i++ {
						c := (start + i) / 5
						out[c] = out[c].add(v[i])
					}
					flags = append(flags, byte(v[n][0]&1))
				}
				return groupedGLMMStagedOutput(rw, a, role, out, append(in, crossGridStageOutput{Validity: flags}))
			})
			add(prefix+".log", "glmm.full-width-logsum-guard-profile", 16, s.Clusters, 192, []string{prefix + ".exp-sum"}, coord("cluster-logsum"), func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
				if len(in) != 1 {
					return crossGridStageOutput{}, primitiveVError()
				}
				sum, e := groupedLMMStagedWords(in[0], s.Clusters)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				out := make([]groupedWord, s.Clusters)
				var flags []byte
				var guard, program *primitiveVProgram
				for start := 0; start < s.Clusters; start += 32 {
					n := min(32, s.Clusters-start)
					if guard == nil || guard.InputWordsE != n {
						guard, e = groupedGLMMGuardCompile(n, false)
						if e != nil {
							return crossGridStageOutput{}, e
						}
					}
					v, e := groupedGLMMStagedPrimitive(rw, a, role, fmt.Sprintf("log-guard/%d", start), profile, guard, sum[start:start+n])
					if e != nil {
						return crossGridStageOutput{}, e
					}
					flags = append(flags, byte(v[n][0]&1))
					if program == nil || program.InputWordsE != n {
						program, e = groupedWideScalarCompile("log", n)
						if e != nil {
							return crossGridStageOutput{}, e
						}
					}
					v, e = groupedGLMMStagedPrimitive(rw, a, role, fmt.Sprintf("log/%d", start), profile, program, v[:n])
					if e != nil {
						return crossGridStageOutput{}, e
					}
					copy(out[start:], v[:n])
					flags = append(flags, byte(v[n][0]&1))
				}
				return groupedGLMMStagedOutput(rw, a, role, out, append(in, crossGridStageOutput{Validity: flags}))
			})
			lossID := prefix + ".loss"
			lossIDs = append(lossIDs, lossID)
			cap := s.Caps[candidate]
			add(lossID, "glmm.signed-clamp-quantize", s.GridBits, s.Clusters, 192, []string{prefix + ".center", prefix + ".log", "glmm.live-outcome-count"}, coord("cluster-capped-loss"), func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
				if len(in) != 3 {
					return crossGridStageOutput{}, primitiveVError()
				}
				center, e := groupedLMMStagedWords(in[0], 6*s.Clusters)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				log, e := groupedLMMStagedWords(in[1], s.Clusters)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				q0, e := groupedLMMStagedWords(in[2], 2*rows+s.Clusters)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				var upstream []byte
				for _, v := range in {
					upstream = append(upstream, v.Validity...)
				}
				valid, e := groupedGLMMStagedValidity(rw, a, role, "loss-validity", upstream)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				program, e := groupedGLMMFinalCompile(numeric, cap)
				if e != nil {
					return crossGridStageOutput{}, e
				}
				out := make([]groupedWord, s.Clusters)
				flags := make([]byte, s.Clusters)
				for c := range out {
					v, e := groupedGLMMStagedPrimitive(rw, a, role, fmt.Sprintf("final/%d", c), profile, program, []groupedWord{center[6*c+5], log[c], q0[2*rows+c], valid})
					if e != nil {
						return crossGridStageOutput{}, e
					}
					out[c] = v[0]
					flags[c] = byte(v[1][0] & 1)
				}
				return groupedGLMMStagedOutput(rw, a, role, out, []crossGridStageOutput{{Validity: flags}})
			})
		}
	}
	add("glmm.terminal", "glmm.candidate-sum-ring128", s.GridBits, len(s.Caps), 128, lossIDs, coord("variance-major-beta-minor-loss"), func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != len(s.Caps) {
			return crossGridStageOutput{}, primitiveVError()
		}
		sums := make([]groupedWord, len(s.Caps))
		var flags []byte
		for j, v := range in {
			values, e := groupedLMMStagedWords(v, s.Clusters)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			for _, w := range values {
				sums[j] = sums[j].add(w)
			}
			flags = append(flags, v.Validity...)
		}
		valid, e := groupedGLMMStagedValidity(rw, a, role, "terminal-validity", flags)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		var boundary strings.Builder
		n := len(sums)
		fmt.Fprintf(&boundary, "package main\nfunc main(g [%d]int192,e [%d]int192) [%d]int192 {\nvar out [%d]int192\nvalid:=g[%d]+e[%d]==1\n", 2*n+2, n+1, n+1, n+1, n, n)
		for j := range sums {
			fmt.Fprintf(&boundary, "v%d:=g[%d]+e[%d]\nif !valid {v%d=0}\nout[%d]=v%d-g[%d]\n", j, j, j, j, j, j, n+1+j)
		}
		fmt.Fprintf(&boundary, "flag:=int192(0)\nif valid {flag=1}\nout[%d]=flag-g[%d]\nreturn out\n}\n", n, 2*n+1)
		program, e := primitiveVCompile(boundary.String(), 192, 2*n+2, n+1, n+1)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		masked, e := groupedGLMMStagedPrimitive(rw, a, role, "terminal-zero-invalid", profile, program, append(sums, valid))
		if e != nil {
			return crossGridStageOutput{}, e
		}
		sums, valid = masked[:n], masked[n]
		out := crossGridStageOutput{Share: make([]byte, 16*len(sums)), Validity: make([]byte, len(sums))}
		for j, w := range sums {
			copy(out.Share[16*j:16*(j+1)], groupedEncodeWords([]groupedWord{w})[:16])
			out.Validity[j] = byte(valid[0] & 1)
		}
		return out, nil
	})
	return graph, nil
}
