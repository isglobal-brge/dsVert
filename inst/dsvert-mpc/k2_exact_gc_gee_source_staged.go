package main

// Authenticated fixed-rho v3 predecessor. Source/routing runs once, before
// candidate expansion. This internal graph does not admit an estimated alpha.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

type groupedGEESourceSpec struct {
	Session                             string
	Authorities                         [2]string
	SchemaDigest, SemanticKey, Contract [32]byte
	Route                               groupedRouteStagedSpec
	Numeric                             groupedGEESpec
	Beta                                [][]*big.Int
	Caps                                []int64
	CorrelationContract                 string
}

type groupedGEESourceRecord struct {
	Version                    string
	Role                       exactGCRole
	Binding                    [32]byte
	Numeric, Outcome, Metadata crossGridStageOutput
	MAC                        []byte
}

type groupedGEESourceGraph struct {
	Graph   crossGridStageGraph
	Compute []crossGridStageCompute
}

func groupedGEESourcePlans(s groupedGEESourceSpec) ([]crossGridStagePlan, error) {
	r := s.Route
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	if groupedGEEValidate(s.Numeric) != nil || r.validate() != nil || s.Session == "" || s.Authorities[0] == s.Authorities[1] || s.SchemaDigest == ([32]byte{}) || s.SemanticKey == ([32]byte{}) || s.Contract == ([32]byte{}) || s.CorrelationContract != "signed-fixed-rho-v3-predecessor" || r.Clusters > 500 || r.Clusters*r.Slots > 2000 || r.Slots != s.Numeric.Slots || r.Predictors != s.Numeric.Predictors || r.NumericStage != "gee.source.normalized" || r.MetadataStage != "gee.source.metadata" || r.ProfileDigest != s.Contract || !r.Nonnegative || r.NumericBound.Cmp(f) != 0 || r.OutcomeBound == nil || r.OutcomeBound.Cmp(new(big.Int).Mul(f, big.NewInt(s.Numeric.MaxOutcome))) != 0 || len(s.Beta) < 1 || len(s.Beta) > 4 || len(s.Caps) != len(s.Beta) {
		return nil, errCrossGridStage
	}
	limit := new(big.Int).Lsh(big.NewInt(4), 50)
	for j, beta := range s.Beta {
		if len(beta) != r.Predictors+1 || s.Caps[j] < 1 || s.Caps[j] > 1<<40 {
			return nil, errCrossGridStage
		}
		lo, hi := new(big.Int), new(big.Int)
		for k, b := range beta {
			if b == nil || new(big.Int).Abs(b).Cmp(limit) > 0 {
				return nil, errCrossGridStage
			}
			if k == 0 {
				lo.Set(b)
				hi.Set(b)
			} else if b.Sign() < 0 {
				lo.Add(lo, b)
			} else {
				hi.Add(hi, b)
			}
		}
		if lo.Cmp(new(big.Int).Neg(limit)) < 0 || hi.Cmp(limit) > 0 {
			return nil, errCrossGridStage
		}
	}
	profile := crossGridStageHash("gee-fixed-rho-source-spec", s)
	plans := make([]crossGridStagePlan, 3)
	for i, width := range []int{r.Predictors, 1, r.Predictors + 3} {
		id := []string{"gee.source.numeric", "gee.source.outcome", r.MetadataStage}[i]
		coords := make([]string, r.Clusters*r.Slots*width)
		for k := range coords {
			coords[k] = fmt.Sprintf("source-row:%d:column:%d", k/width, k%width)
		}
		plans[i] = crossGridStagePlan{ID: id, Kind: []string{"gee.authenticated-f50-features", "gee.authenticated-" + s.Numeric.Family + "-q0-outcome", "gee.authenticated-private-metadata"}[i], Ring: 128, FPScale: []int{50, 0, 0}[i], CoordOrder: coords, PublicBounds: map[string]int{"clusters": r.Clusters, "slots": r.Slots, "predictors": r.Predictors, "max_outcome": int(s.Numeric.MaxOutcome)}, SourceDigest: r.SourceDigest, ProfileDigest: profile}
	}
	return plans, nil
}

func groupedGEESourceMAC(key [32]byte, record groupedGEESourceRecord) []byte {
	record.MAC = nil
	raw, _ := json.Marshal(record)
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("dsvert/gee-fixed-rho-v3-source/v1\x00"))
	mac.Write(raw)
	return mac.Sum(nil)
}

func groupedGEESealSource(s groupedGEESourceSpec, role exactGCRole, numeric, outcome, metadata crossGridStageOutput, key [32]byte) (*groupedGEESourceRecord, error) {
	plans, err := groupedGEESourcePlans(s)
	if err != nil || role > exactGCRoleEvaluator || key == ([32]byte{}) || plans[0].validateOutput(numeric) != nil || plans[1].validateOutput(outcome) != nil || plans[2].validateOutput(metadata) != nil {
		return nil, errCrossGridStage
	}
	record := &groupedGEESourceRecord{Version: "gee-fixed-rho-v3-source-v1", Role: role, Binding: crossGridStageHash("gee-fixed-rho-source-binding", s), Numeric: crossGridStageClone(numeric), Outcome: crossGridStageClone(outcome), Metadata: crossGridStageClone(metadata)}
	record.MAC = groupedGEESourceMAC(key, *record)
	return record, nil
}

func groupedGEEBuildSourceGraph(s groupedGEESourceSpec, role exactGCRole, source *groupedGEESourceRecord, side *groupedRouteSidecar, key [32]byte) (*groupedGEESourceGraph, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, errCrossGridStage
	}
	var pinned groupedGEESourceSpec
	if json.Unmarshal(raw, &pinned) != nil {
		return nil, errCrossGridStage
	}
	s = pinned
	plans, err := groupedGEESourcePlans(s)
	if err != nil || source == nil || role > exactGCRoleEvaluator || key == ([32]byte{}) || source.Version != "gee-fixed-rho-v3-source-v1" || source.Role != role || source.Binding != crossGridStageHash("gee-fixed-rho-source-binding", s) || !hmac.Equal(source.MAC, groupedGEESourceMAC(key, *source)) || plans[0].validateOutput(source.Numeric) != nil || plans[1].validateOutput(source.Outcome) != nil || plans[2].validateOutput(source.Metadata) != nil {
		return nil, errCrossGridStage
	}
	graph := &groupedGEESourceGraph{Graph: crossGridStageGraph{Version: "cross-grid-stage-graph-v1", Family: "gee-fixed-rho-v3-predecessor", Session: s.Session, Authorities: s.Authorities, SchemaDigest: s.SchemaDigest, SemanticKey: s.SemanticKey, Stages: plans}}
	for _, value := range []crossGridStageOutput{source.Numeric, source.Outcome, source.Metadata} {
		value := crossGridStageClone(value)
		graph.Compute = append(graph.Compute, func(_ io.ReadWriter, _ crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 0 {
				return crossGridStageOutput{}, errCrossGridStage
			}
			return crossGridStageClone(value), nil
		})
	}
	// Reuse only the exact q0->f50 primitive; all public identifiers and digests
	// are GEE-specific, and no GLMM source record or graph is accepted.
	normalSpec := groupedGLMMSourceSpec{Route: s.Route, GLMM: groupedGLMMStagedSpec{}}
	if s.Numeric.Family == "poisson" {
		normalSpec.GLMM.Family = "poisson"
		normalSpec.GLMM.MaxOutcome = int(s.Numeric.MaxOutcome)
	}
	normal, normalize := groupedGLMMSourceNormalization(normalSpec, role)
	normal.Kind = "gee.full-width-q0-to-homogeneous-f50"
	normal.Predecessors = []string{"gee.source.numeric", "gee.source.outcome"}
	normal.ProfileDigest = crossGridStageHash("gee-fixed-rho-source-spec", s)
	graph.Graph.Stages = append(graph.Graph.Stages, normal)
	graph.Compute = append(graph.Compute, normalize)
	route, err := groupedRouteBuildStagedGraph(s.Route, role, side, key)
	if err != nil {
		return nil, err
	}
	graph.Graph.Stages = append(graph.Graph.Stages, route.Plans...)
	graph.Compute = append(graph.Compute, route.Compute...)
	lift, convert, err := crossGridStageBuildConversion(route.Plans[len(route.Plans)-1], "gee.source.ring192", true, role)
	if err != nil {
		return nil, err
	}
	graph.Graph.Stages = append(graph.Graph.Stages, lift)
	graph.Compute = append(graph.Compute, convert)
	profile := crossGridStageHash("gee-fixed-rho-source-spec", s)
	n, p := s.Numeric.Slots, s.Numeric.Predictors
	add := func(id, kind string, scale, width int, previous []string, compute crossGridStageCompute) crossGridStagePlan {
		coords := make([]string, width)
		for i := range coords {
			coords[i] = fmt.Sprintf("%s/coordinate/%d", id, i)
		}
		plan := crossGridStagePlan{ID: id, Kind: kind, Ring: 192, FPScale: scale, CoordOrder: coords, PublicBounds: map[string]int{"clusters": s.Route.Clusters, "slots": n, "predictors": p}, SourceDigest: s.Route.SourceDigest, ProfileDigest: profile, Predecessors: previous}
		graph.Graph.Stages = append(graph.Graph.Stages, plan)
		graph.Compute = append(graph.Compute, compute)
		return plan
	}
	terminalIDs := make([]string, 0, s.Route.Clusters*len(s.Beta))
	for cluster := 0; cluster < s.Route.Clusters; cluster++ {
		cluster := cluster
		prefix := fmt.Sprintf("gee.cluster.%03d", cluster)
		features := add(prefix+".features", "gee.routed-f50-features", 50, n*p, []string{lift.ID}, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 1 {
				return crossGridStageOutput{}, errCrossGridStage
			}
			r, e := groupedLMMStagedWords(in[0], s.Route.Clusters*n*(p+2))
			if e != nil {
				return crossGridStageOutput{}, e
			}
			out := make([]groupedWord, n*p)
			for row := 0; row < n; row++ {
				copy(out[row*p:(row+1)*p], r[(cluster*n+row)*(p+2)+1:(cluster*n+row)*(p+2)+1+p])
			}
			return groupedGLMMStagedOutput(rw, a, role, out, in)
		})
		outcome := add(prefix+".outcome-live", "gee.full-width-y-live-q0", 0, 2*n, []string{lift.ID}, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 1 {
				return crossGridStageOutput{}, errCrossGridStage
			}
			r, e := groupedLMMStagedWords(in[0], s.Route.Clusters*n*(p+2))
			if e != nil {
				return crossGridStageOutput{}, e
			}
			args := make([]groupedWord, 2*n)
			for row := 0; row < n; row++ {
				args[2*row] = r[(cluster*n+row)*(p+2)]
				args[2*row+1] = r[(cluster*n+row)*(p+2)+p+1]
			}
			guard, e := groupedGLMMOutcomeGuardCompile(n, true, int(s.Numeric.MaxOutcome))
			if e != nil {
				return crossGridStageOutput{}, e
			}
			checked, e := groupedGLMMStagedPrimitive(rw, a, role, "gee/y-live", profile, guard, args)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			out := make([]groupedWord, 2*n)
			for row := 0; row < n; row++ {
				out[2*row], out[2*row+1] = checked[2*row+1], checked[2*row]
			}
			return groupedGLMMStagedOutput(rw, a, role, out, append(in, crossGridStageOutput{Validity: []byte{byte(checked[2*n][0] & 1)}}))
		})
		for candidate, beta := range s.Beta {
			candidate, beta := candidate, beta
			candidatePrefix := fmt.Sprintf("%s.candidate.%03d", prefix, candidate)
			eta := add(candidatePrefix+".eta", "gee.complete-dot-f100", 100, n, []string{lift.ID}, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
				if len(in) != 1 {
					return crossGridStageOutput{}, errCrossGridStage
				}
				r, e := groupedLMMStagedWords(in[0], s.Route.Clusters*n*(p+2))
				if e != nil {
					return crossGridStageOutput{}, e
				}
				out := make([]groupedWord, n)
				for row := 0; row < n; row++ {
					for j, b := range beta {
						out[row] = out[row].add(r[(cluster*n+row)*(p+2)+j].mul(groupedWordFromBig(b)))
					}
				}
				return groupedGLMMStagedOutput(rw, a, role, out, in)
			})
			numeric, err := groupedGEEBuildStagedGraph(groupedGEEStagedSpec{Numeric: s.Numeric, ClusterCap: s.Caps[candidate], Prefix: candidatePrefix, SourceDigest: s.Route.SourceDigest, Contract: s.Contract, Sources: [3]crossGridStagePlan{eta, features, outcome}, CorrelationContract: s.CorrelationContract}, role)
			if err != nil {
				return nil, err
			}
			graph.Graph.Stages = append(graph.Graph.Stages, numeric.Plans...)
			graph.Compute = append(graph.Compute, numeric.Compute...)
			terminalIDs = append(terminalIDs, numeric.Plans[len(numeric.Plans)-1].ID)
		}
	}
	width := 1 + (p+1)*(p+2)
	add("gee.terminal", "gee.fixed-rho-v3-candidate-sums", s.Numeric.GridBits, width*len(s.Beta), terminalIDs, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != len(terminalIDs) {
			return crossGridStageOutput{}, errCrossGridStage
		}
		out := make([]groupedWord, width*len(s.Beta))
		var flags []byte
		for i, input := range in {
			words, e := groupedLMMStagedWords(input, width)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			for j, w := range words {
				out[(i%len(s.Beta))*width+j] = out[(i%len(s.Beta))*width+j].add(w)
			}
			flags = append(flags, input.Validity...)
		}
		valid, e := groupedGLMMStagedValidity(rw, a, role, "gee/terminal-validity", flags)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		gate, e := groupedGEEStagedUnpackCompile(make([]int, len(out)))
		if e != nil {
			return crossGridStageOutput{}, e
		}
		result, e := groupedGLMMStagedPrimitive(rw, a, role, "gee/terminal-gate", profile, gate, append(out, valid))
		if e != nil {
			return crossGridStageOutput{}, e
		}
		// Downward modulo is a ring homomorphism on additive shares. The
		// signed public caps put every nonnegative sum strictly below 2^128.
		terminal := crossGridStageOutput{Share: make([]byte, 16*len(out)), Validity: make([]byte, len(out))}
		for i, w := range result[:len(out)] {
			putUint128LE(terminal.Share[16*i:16*(i+1)], Uint128{Lo: w[0], Hi: w[1]})
			terminal.Validity[i] = byte(result[len(out)][0] & 1)
		}
		return terminal, nil
	})
	graph.Graph.Stages[len(graph.Graph.Stages)-1].Ring = 128
	if graph.Graph.validate() != nil {
		return nil, errCrossGridStage
	}
	return graph, nil
}
