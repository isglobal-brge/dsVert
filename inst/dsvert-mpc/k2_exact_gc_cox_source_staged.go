package main

// Authority-local authenticated source adapter. The upstream source loader must
// first verify owner receipts, signed compilation and private PSI agreement.
// It seals complete f100 candidate dots and q0 live/event in original PSI order;
// private sorting remains exclusively in the retained packed Cox runner.
import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
)

type coxLossSourceSpec struct {
	Session                   string
	Authorities               [2]string
	SchemaDigest, SemanticKey [32]byte
	Cox                       coxLossStagedSpec
}

type coxLossSourceRecord struct {
	Version               string
	Role                  exactGCRole
	Binding               [32]byte
	Predictors, LiveEvent crossGridStageOutput
	MAC                   []byte
}

type coxLossSourceGraph struct {
	Graph   crossGridStageGraph
	Compute []crossGridStageCompute
}

func coxLossSourcePlans(s coxLossSourceSpec) ([]crossGridStagePlan, error) {
	c := s.Cox
	if c.SourceDigest == ([32]byte{}) || c.Contract == ([32]byte{}) || c.RoutingDigest == ([32]byte{}) {
		return nil, errCrossGridStage
	}
	if _, err := registerCoxGridCrossLoss().SharedPlan(c.Plan.Spec); err != nil {
		return nil, errCrossGridStage
	}
	if _, err := c.Plan.digest(); err != nil {
		return nil, errCrossGridStage
	}
	plans := append([]crossGridStagePlan(nil), c.Sources[:]...)
	counts := [2]int{c.Plan.PaddedRows * c.Plan.Spec.Candidates, 2 * c.Plan.PaddedRows}
	for i, p := range plans {
		if p.Ring != 128 || p.FPScale != []int{100, 0}[i] || len(p.CoordOrder) != counts[i] || len(p.Predecessors) != 0 || p.SourceDigest != c.SourceDigest || p.ProfileDigest != c.Contract {
			return nil, errCrossGridStage
		}
	}
	graph := crossGridStageGraph{Version: "cross-grid-stage-graph-v1", Family: "cox", Session: s.Session, Authorities: s.Authorities, SchemaDigest: s.SchemaDigest, SemanticKey: s.SemanticKey, Stages: plans}
	if graph.validate() != nil {
		return nil, errCrossGridStage
	}
	return plans, nil
}

func coxLossSourceMAC(key [32]byte, record coxLossSourceRecord) []byte {
	record.MAC = nil
	raw, _ := json.Marshal(record)
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte("dsvert/cox-authenticated-source/v1\x00"))
	h.Write(raw)
	return h.Sum(nil)
}

func coxLossSealSource(s coxLossSourceSpec, role exactGCRole, predictors, liveEvent crossGridStageOutput, key [32]byte) (*coxLossSourceRecord, error) {
	plans, err := coxLossSourcePlans(s)
	if err != nil || role > exactGCRoleEvaluator || key == ([32]byte{}) || plans[0].validateOutput(predictors) != nil || plans[1].validateOutput(liveEvent) != nil {
		return nil, errCrossGridStage
	}
	record := &coxLossSourceRecord{Version: "cox-source-v1", Role: role, Binding: crossGridStageHash("cox-source-binding", s), Predictors: crossGridStageClone(predictors), LiveEvent: crossGridStageClone(liveEvent)}
	record.MAC = coxLossSourceMAC(key, *record)
	return record, nil
}

func coxLossBuildSourceGraph(s coxLossSourceSpec, role exactGCRole, source *coxLossSourceRecord, side *coxLossStagedRouting, key [32]byte) (*coxLossSourceGraph, error) {
	// Freeze signed descriptors and private shares before capturing any closures.
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, errCrossGridStage
	}
	var pinned coxLossSourceSpec
	if json.Unmarshal(raw, &pinned) != nil {
		return nil, errCrossGridStage
	}
	s = pinned
	plans, err := coxLossSourcePlans(s)
	if err != nil || source == nil || role > exactGCRoleEvaluator || key == ([32]byte{}) || source.Version != "cox-source-v1" || source.Role != role || source.Binding != crossGridStageHash("cox-source-binding", s) || !hmac.Equal(source.MAC, coxLossSourceMAC(key, *source)) || plans[0].validateOutput(source.Predictors) != nil || plans[1].validateOutput(source.LiveEvent) != nil {
		return nil, errCrossGridStage
	}
	graph := &coxLossSourceGraph{Graph: crossGridStageGraph{Version: "cross-grid-stage-graph-v1", Family: "cox", Session: s.Session, Authorities: s.Authorities, SchemaDigest: s.SchemaDigest, SemanticKey: s.SemanticKey, Stages: plans}}
	for _, value := range []crossGridStageOutput{source.Predictors, source.LiveEvent} {
		value := crossGridStageClone(value)
		graph.Compute = append(graph.Compute, func(_ io.ReadWriter, _ crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 0 {
				return crossGridStageOutput{}, errCrossGridStage
			}
			return crossGridStageClone(value), nil
		})
	}
	arithmetic, err := coxLossBuildStagedGraph(s.Cox, role, side, key)
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
