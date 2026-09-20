package main

// The server-local adapter joins authenticated source shares to private routing,
// exact extension and the retained LMM arithmetic. It grants no source access:
// the R source loader must verify the signed compilation, owner receipts and
// private PSI agreement before sealing these two homogeneous source records.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

type groupedLMMSourceSpec struct {
	Session                   string
	Authorities               [2]string
	SchemaDigest, SemanticKey [32]byte
	Route                     groupedRouteStagedSpec
	LMM                       groupedLMMStagedSpec
}

type groupedLMMSourceRecord struct {
	Version  string
	Role     exactGCRole
	Binding  [32]byte
	Numeric  crossGridStageOutput
	Metadata crossGridStageOutput
	MAC      []byte
}

type groupedLMMSourceGraph struct {
	Graph   crossGridStageGraph
	Compute []crossGridStageCompute
}

func groupedLMMSourcePlans(s groupedLMMSourceSpec) ([]crossGridStagePlan, error) {
	r := s.Route
	if r.validate() != nil || s.LMM.validate() != nil || s.Session == "" ||
		s.Authorities[0] == s.Authorities[1] || s.SchemaDigest == ([32]byte{}) || s.SemanticKey == ([32]byte{}) ||
		r.NumericStage == r.MetadataStage || s.LMM.RoutedStage != "lmm.source.ring192" ||
		!r.Nonnegative || r.NumericBound.Cmp(new(big.Int).Lsh(big.NewInt(1), 50)) != 0 ||
		s.LMM.Moments.Clusters != r.Clusters || s.LMM.Moments.Slots != r.Slots ||
		s.LMM.Moments.Columns != r.Predictors+2 ||
		s.LMM.SourceDigest != r.SourceDigest || s.LMM.ProfileDigest != r.ProfileDigest {
		return nil, errCrossGridStage
	}
	// The retained certificate uses normalized x,y in [0,1]. Check the
	// encoded public beta endpoints as integers, including rounding slack.
	f := new(big.Int).Lsh(big.NewInt(1), 50)
	limit := new(big.Int).Mul(big.NewInt(s.LMM.Numeric.ResidualCap), f)
	// ResidualCap is formed before coefficient encoding. Match the frozen
	// f50 encoding slack in groupedLMMGridShares at either predictor endpoint.
	limit.Add(limit, big.NewInt(int64((s.LMM.Moments.Columns+1)/2)))
	for _, beta := range s.LMM.Beta {
		lower, upper := new(big.Int).Set(beta[0]), new(big.Int).Set(beta[0])
		for _, coefficient := range beta[1:] {
			if coefficient.Sign() < 0 {
				lower.Add(lower, coefficient)
			} else {
				upper.Add(upper, coefficient)
			}
		}
		if new(big.Int).Abs(upper).Cmp(limit) > 0 || new(big.Int).Abs(new(big.Int).Sub(f, lower)).Cmp(limit) > 0 {
			return nil, errCrossGridStage
		}
	}
	rows := r.Clusters * r.Slots
	plans := make([]crossGridStagePlan, 2)
	for i := range plans {
		columns, id, scale := r.Predictors+1, r.NumericStage, 50
		kind := "lmm.authenticated-numeric-source"
		if i == 1 {
			columns, id, scale = r.Predictors+3, r.MetadataStage, 0
			kind = "lmm.authenticated-private-metadata"
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

func groupedLMMSourceMAC(key [32]byte, record groupedLMMSourceRecord) []byte {
	record.MAC = nil
	data, _ := json.Marshal(record)
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("dsvert/grouped-lmm-authenticated-source/v1\x00"))
	m.Write(data)
	return m.Sum(nil)
}

func groupedLMMSealSource(s groupedLMMSourceSpec, role exactGCRole,
	numeric, metadata crossGridStageOutput, key [32]byte) (*groupedLMMSourceRecord, error) {
	plans, err := groupedLMMSourcePlans(s)
	if err != nil || role > exactGCRoleEvaluator || key == ([32]byte{}) ||
		plans[0].validateOutput(numeric) != nil || plans[1].validateOutput(metadata) != nil {
		return nil, errCrossGridStage
	}
	record := &groupedLMMSourceRecord{Version: "grouped-lmm-source-v1", Role: role,
		Binding: crossGridStageHash("lmm-source-binding", s), Numeric: crossGridStageClone(numeric),
		Metadata: crossGridStageClone(metadata)}
	record.MAC = groupedLMMSourceMAC(key, *record)
	return record, nil
}

func groupedLMMBuildSourceGraph(s groupedLMMSourceSpec, role exactGCRole,
	source *groupedLMMSourceRecord, sidecar *groupedRouteSidecar, key [32]byte) (*groupedLMMSourceGraph, error) {
	// All captured public inputs and local private shares are frozen together.
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, errCrossGridStage
	}
	var pinned groupedLMMSourceSpec
	if json.Unmarshal(raw, &pinned) != nil {
		return nil, errCrossGridStage
	}
	s = pinned
	plans, err := groupedLMMSourcePlans(s)
	if err != nil || source == nil || key == ([32]byte{}) || role > exactGCRoleEvaluator ||
		source.Version != "grouped-lmm-source-v1" || source.Role != role ||
		source.Binding != crossGridStageHash("lmm-source-binding", s) ||
		!hmac.Equal(source.MAC, groupedLMMSourceMAC(key, *source)) ||
		plans[0].validateOutput(source.Numeric) != nil || plans[1].validateOutput(source.Metadata) != nil {
		return nil, errCrossGridStage
	}
	graph := &groupedLMMSourceGraph{Graph: crossGridStageGraph{Version: "cross-grid-stage-graph-v1",
		Family: "lmm", Session: s.Session, Authorities: s.Authorities,
		SchemaDigest: s.SchemaDigest, SemanticKey: s.SemanticKey, Stages: plans}}
	for _, input := range []crossGridStageOutput{source.Numeric, source.Metadata} {
		input := crossGridStageClone(input)
		graph.Compute = append(graph.Compute, func(_ io.ReadWriter, _ crossGridStageAttempt,
			in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 0 {
				return crossGridStageOutput{}, errCrossGridStage
			}
			return crossGridStageClone(input), nil
		})
	}
	route, err := groupedRouteBuildStagedGraphBatched(s.Route, role, sidecar, key)
	if err != nil || len(route.Plans) == 0 {
		return nil, errCrossGridStage
	}
	graph.Graph.Stages = append(graph.Graph.Stages, route.Plans...)
	graph.Compute = append(graph.Compute, route.Compute...)
	lift, convert, err := crossGridStageBuildConversionBatch(route.Plans[len(route.Plans)-1], s.LMM.RoutedStage, true, role, crossGridStageConversionRelayBatch)
	if err != nil {
		return nil, err
	}
	graph.Graph.Stages = append(graph.Graph.Stages, lift)
	graph.Compute = append(graph.Compute, convert)
	arithmetic, err := groupedLMMBuildStagedGraph(s.LMM, role)
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
