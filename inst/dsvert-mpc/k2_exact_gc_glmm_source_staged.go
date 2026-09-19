package main

// The server-local adapter joins authenticated source shares to private routing,
// exact extension and the retained GLMM arithmetic. It grants no source access:
// the R source loader must verify the signed compilation, owner receipts and
// private PSI agreement before sealing these two homogeneous source records.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
)

type groupedGLMMSourceSpec struct {
	Session                   string
	Authorities               [2]string
	SchemaDigest, SemanticKey [32]byte
	Route                     groupedRouteStagedSpec
	GLMM                      groupedGLMMStagedSpec
}

type groupedGLMMSourceRecord struct {
	Version  string
	Role     exactGCRole
	Binding  [32]byte
	Numeric  crossGridStageOutput
	Outcome  crossGridStageOutput
	Metadata crossGridStageOutput
	MAC      []byte
}

type groupedGLMMSourceGraph struct {
	Graph   crossGridStageGraph
	Compute []crossGridStageCompute
}

func groupedGLMMSourcePlans(s groupedGLMMSourceSpec) ([]crossGridStagePlan, error) {
	r := s.Route
	if r.validate() != nil || s.GLMM.validate() != nil || s.Session == "" ||
		s.Authorities[0] == s.Authorities[1] || s.SchemaDigest == ([32]byte{}) || s.SemanticKey == ([32]byte{}) ||
		r.NumericStage != "glmm.source.normalized" || r.MetadataStage != "glmm.source.metadata" || s.GLMM.RoutedStage != "glmm.source.ring192" ||
		!r.Nonnegative || r.NumericBound.Cmp(new(big.Int).Lsh(big.NewInt(1), 50)) != 0 ||
		s.GLMM.Clusters != r.Clusters || s.GLMM.Slots != r.Slots || s.GLMM.Predictors != r.Predictors ||
		s.GLMM.SourceDigest != r.SourceDigest || s.GLMM.ProfileDigest != r.ProfileDigest {
		return nil, errCrossGridStage
	}
	rows := r.Clusters * r.Slots
	plans := make([]crossGridStagePlan, 3)
	for i := range plans {
		columns, id, scale := r.Predictors, "glmm.source.numeric", 50
		kind := "glmm.authenticated-numeric-source"
		if i == 2 {
			columns, id, scale = r.Predictors+3, r.MetadataStage, 0
			kind = "glmm.authenticated-private-metadata"
		}
		if i == 1 {
			columns, id, scale, kind = 1, "glmm.source.outcome", 0, "glmm.authenticated-binary-outcome"
		}
		coordinates := make([]string, rows*columns)
		for row := 0; row < rows; row++ {
			for col := 0; col < columns; col++ {
				coordinates[row*columns+col] = fmt.Sprintf("source-row:%d:column:%d", row, col)
			}
		}
		plans[i] = crossGridStagePlan{ID: id, Kind: kind, Ring: 128, FPScale: scale,
			CoordOrder: coordinates, PublicBounds: map[string]int{"clusters": r.Clusters,
				"slots": r.Slots, "predictors": r.Predictors}, SourceDigest: r.SourceDigest,
			ProfileDigest: r.ProfileDigest}
	}
	return plans, nil
}

func groupedGLMMSourceMAC(key [32]byte, record groupedGLMMSourceRecord) []byte {
	record.MAC = nil
	data, _ := json.Marshal(record)
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("dsvert/grouped-glmm-authenticated-source/v1\x00"))
	m.Write(data)
	return m.Sum(nil)
}

func groupedGLMMSealSource(s groupedGLMMSourceSpec, role exactGCRole,
	numeric, outcome, metadata crossGridStageOutput, key [32]byte) (*groupedGLMMSourceRecord, error) {
	plans, err := groupedGLMMSourcePlans(s)
	if err != nil || role > exactGCRoleEvaluator || key == ([32]byte{}) ||
		plans[0].validateOutput(numeric) != nil || plans[1].validateOutput(outcome) != nil || plans[2].validateOutput(metadata) != nil {
		return nil, errCrossGridStage
	}
	record := &groupedGLMMSourceRecord{Version: "grouped-glmm-source-v1", Role: role,
		Binding: crossGridStageHash("glmm-source-binding", s), Numeric: crossGridStageClone(numeric),
		Outcome: crossGridStageClone(outcome), Metadata: crossGridStageClone(metadata)}
	record.MAC = groupedGLMMSourceMAC(key, *record)
	return record, nil
}

func groupedGLMMBuildSourceGraph(s groupedGLMMSourceSpec, role exactGCRole,
	source *groupedGLMMSourceRecord, sidecar *groupedRouteSidecar, key [32]byte) (*groupedGLMMSourceGraph, error) {
	// All captured public inputs and local private shares are frozen together.
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, errCrossGridStage
	}
	var pinned groupedGLMMSourceSpec
	if json.Unmarshal(raw, &pinned) != nil {
		return nil, errCrossGridStage
	}
	s = pinned
	plans, err := groupedGLMMSourcePlans(s)
	if err != nil || source == nil || key == ([32]byte{}) || role > exactGCRoleEvaluator ||
		source.Version != "grouped-glmm-source-v1" || source.Role != role ||
		source.Binding != crossGridStageHash("glmm-source-binding", s) ||
		!hmac.Equal(source.MAC, groupedGLMMSourceMAC(key, *source)) ||
		plans[0].validateOutput(source.Numeric) != nil || plans[1].validateOutput(source.Outcome) != nil || plans[2].validateOutput(source.Metadata) != nil {
		return nil, errCrossGridStage
	}
	graph := &groupedGLMMSourceGraph{Graph: crossGridStageGraph{Version: "cross-grid-stage-graph-v1",
		Family: "glmm", Session: s.Session, Authorities: s.Authorities,
		SchemaDigest: s.SchemaDigest, SemanticKey: s.SemanticKey, Stages: plans}}
	for _, input := range []crossGridStageOutput{source.Numeric, source.Outcome, source.Metadata} {
		input := crossGridStageClone(input)
		graph.Compute = append(graph.Compute, func(_ io.ReadWriter, _ crossGridStageAttempt,
			in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 0 {
				return crossGridStageOutput{}, errCrossGridStage
			}
			return crossGridStageClone(input), nil
		})
	}
	normal, normalize := groupedGLMMSourceNormalization(s, role)
	graph.Graph.Stages = append(graph.Graph.Stages, normal)
	graph.Compute = append(graph.Compute, normalize)
	route, err := groupedRouteBuildStagedGraph(s.Route, role, sidecar, key)
	if err != nil || len(route.Plans) == 0 {
		return nil, errCrossGridStage
	}
	graph.Graph.Stages = append(graph.Graph.Stages, route.Plans...)
	graph.Compute = append(graph.Compute, route.Compute...)
	lift, convert, err := crossGridStageBuildConversion(route.Plans[len(route.Plans)-1], s.GLMM.RoutedStage, true, role)
	if err != nil {
		return nil, err
	}
	graph.Graph.Stages = append(graph.Graph.Stages, lift)
	graph.Compute = append(graph.Compute, convert)
	arithmetic, err := groupedGLMMBuildStagedGraph(s.GLMM, role)
	if err != nil {
		return nil, err
	}
	graph.Graph.Stages = append(graph.Graph.Stages, arithmetic.Plans...)
	graph.Compute = append(graph.Compute, arithmetic.Compute...)
	if graph.Graph.validate() != nil {
		return nil, errCrossGridStage
	}
	return graph, nil
}

// Typed q0 y is reconstructed and checked at full width before multiplication
// by 2^50. Feature shares remain f50 throughout; no local division is performed.
func groupedGLMMSourceNormalization(s groupedGLMMSourceSpec, role exactGCRole) (crossGridStagePlan, crossGridStageCompute) {
	rows, p := s.Route.Clusters*s.Route.Slots, s.Route.Predictors
	coordinates := make([]string, rows*(p+1))
	for i := range coordinates {
		coordinates[i] = fmt.Sprintf("source-row:%d:column:%d", i/(p+1), i%(p+1))
	}
	plan := crossGridStagePlan{ID: s.Route.NumericStage, Kind: "glmm.binary-q0-to-homogeneous-f50", Ring: 128, FPScale: 50, CoordOrder: coordinates, PublicBounds: map[string]int{"clusters": s.Route.Clusters, "slots": s.Route.Slots, "predictors": p}, SourceDigest: s.Route.SourceDigest, ProfileDigest: s.Route.ProfileDigest, Predecessors: []string{"glmm.source.numeric", "glmm.source.outcome"}}
	compute := func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 2 || groupedRouteCheckOutput(in[0], rows*p) != nil || groupedRouteCheckOutput(in[1], rows) != nil {
			return crossGridStageOutput{}, errCrossGridStage
		}
		out := crossGridStageOutput{Share: make([]byte, 16*rows*(p+1)), Validity: make([]byte, rows*(p+1))}
		var flags []byte
		for start := 0; start < rows; start += 32 {
			n := min(32, rows-start)
			var b strings.Builder
			fmt.Fprintf(&b, "package main\nfunc main(g [%d]uint128,e [%d]uint128) [%d]uint128 {\nvar out [%d]uint128\nvalid:=true\n", 2*n+1, n, n+1, n+1)
			words := make([]*big.Int, n)
			for i := 0; i < n; i++ {
				k := start + i
				words[i] = getUint128LE(in[1].Share[16*k : 16*(k+1)]).ToBig()
				fmt.Fprintf(&b, "y%d:=g[%d]+e[%d]\nok%d:=y%d==0 || y%d==1\nvalid=valid && ok%d\nif !ok%d {y%d=0}\nout[%d]=(y%d<<50)-g[%d]\n", i, i, i, i, i, i, i, i, i, i, i, n+i)
			}
			fmt.Fprintf(&b, "v:=uint128(0)\nif valid {v=1}\nout[%d]=v-g[%d]\nreturn out\n}\n", n, 2*n)
			program, e := primitiveVCompile(b.String(), 128, 2*n+1, n, n+1)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			run := primitiveVRunGarbler
			if role == exactGCRoleEvaluator {
				run = primitiveVRunEvaluator
			}
			result, e := run(rw, program, groupedGLMMStagedSession(a, fmt.Sprintf("binary-source/%d", start)), s.Route.ProfileDigest, words)
			if e != nil {
				return crossGridStageOutput{}, e
			}
			flags = append(flags, byte(result[n].Bit(0)))
			for i := 0; i < n; i++ {
				k := start + i
				copy(out.Share[16*k*(p+1):16*(k*(p+1)+p)], in[0].Share[16*k*p:16*(k+1)*p])
				putUint128LE(out.Share[16*(k*(p+1)+p):16*(k+1)*(p+1)], U128FromBig(result[i]))
			}
		}
		flags = append(flags, in[0].Validity...)
		flags = append(flags, in[1].Validity...)
		valid, e := groupedGLMMStagedValidity(rw, a, role, "normalized-source-validity", flags)
		if e != nil {
			return crossGridStageOutput{}, e
		}
		for i := range out.Validity {
			out.Validity[i] = byte(valid[0] & 1)
		}
		return out, nil
	}
	return plan, compute
}
