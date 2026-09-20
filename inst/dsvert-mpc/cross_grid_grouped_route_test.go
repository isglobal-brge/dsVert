package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func groupedRouteTestSpec() groupedRouteStagedSpec {
	return groupedRouteStagedSpec{Clusters: 2, Slots: 2, Predictors: 1,
		NumericStage: "source.numeric", MetadataStage: "source.metadata",
		SourceDigest: sha256.Sum256([]byte("signed routing source")), ProfileDigest: sha256.Sum256([]byte("signed routing profile")),
		NumericBound: new(big.Int).Lsh(big.NewInt(4), 50)}
}

func TestGroupedRouteSidecarAndPublicTopology(t *testing.T) {
	s, key := groupedRouteTestSpec(), crossGridStageTestKey(0)
	labels, present := []int{1, 0, 1, 0}, []bool{true, true, true, true}
	side, err := groupedRouteSeal(s, labels, present, key)
	if err != nil {
		t.Fatal(err)
	}
	permutation := []int{0, 1, 2, 3}
	control := 0
	primitiveVWalkBenes(4, 0, 1, func(a, b int) {
		if side.Controls[control] {
			permutation[a], permutation[b] = permutation[b], permutation[a]
		}
		control++
	})
	if fmt.Sprint(permutation) != "[1 3 0 2]" {
		t.Fatalf("owner ordering lost stable slots: %v", permutation)
	}
	a, err := groupedRouteBuildStagedGraph(s, exactGCRoleGarbler, side, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := groupedRouteBuildStagedGraph(s, exactGCRoleEvaluator, nil, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	ar, _ := json.Marshal(a.Plans)
	br, _ := json.Marshal(b.Plans)
	if !bytes.Equal(ar, br) {
		t.Fatal("private owner metadata changed public topology")
	}
	other, err := groupedRouteSeal(s, []int{0, 1, 0, 1}, present, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := groupedRouteBuildStagedGraph(s, exactGCRoleGarbler, other, key)
	if err != nil {
		t.Fatal(err)
	}
	cr, _ := json.Marshal(c.Plans)
	if !bytes.Equal(ar, cr) {
		t.Fatal("labels or controls entered public plans")
	}
	for _, mutate := range []func(*groupedRouteSidecar){
		func(v *groupedRouteSidecar) { v.Controls[0] = !v.Controls[0] },
		func(v *groupedRouteSidecar) { v.Labels[0] ^= 1 },
		func(v *groupedRouteSidecar) { v.Present[0] = !v.Present[0] },
		func(v *groupedRouteSidecar) { v.SpecDigest[0] ^= 1 },
		func(v *groupedRouteSidecar) { v.CapacityOK = !v.CapacityOK },
	} {
		v, _ := groupedRouteSeal(s, labels, present, key)
		mutate(v)
		if _, err := groupedRouteBuildStagedGraph(s, exactGCRoleGarbler, v, key); err == nil {
			t.Fatal("tampered private route sidecar admitted")
		}
	}
	// Even a correctly MACed arbitrary control vector is not a canonical
	// owner-derived routing input.
	side.Controls[0] = !side.Controls[0]
	side.MAC = groupedRouteSidecarMAC(*side, key)
	if _, err := groupedRouteBuildStagedGraph(s, exactGCRoleGarbler, side, key); err == nil {
		t.Fatal("arbitrary permutation admitted")
	}

	s.Clusters, s.Slots = 500, 4
	labels, present = make([]int, 2000), make([]bool, 2000)
	for i := range labels {
		labels[i], present[i] = i%500, true
	}
	side, err = groupedRouteSeal(s, labels, present, key)
	if err != nil {
		t.Fatal(err)
	}
	a, err = groupedRouteBuildStagedGraph(s, exactGCRoleGarbler, side, key)
	if err != nil {
		t.Fatal(err)
	}
	last := a.Plans[len(a.Plans)-1]
	if last.ID != "grouped.route.output" || last.Ring != 128 || last.FPScale != 50 || len(last.CoordOrder) != 6000 {
		t.Fatal("C500 descriptor lost exact source ABI")
	}
	for _, p := range a.Plans {
		if p.Kind == "grouped.private-packed-ot-switches" && len(p.CoordOrder) > 2*coxLossOTBatch {
			t.Fatal("packed OT tile bypassed fixed cap")
		}
	}
}

func TestGroupedRouteTwoAuthorityDurable(t *testing.T) {
	for _, scenario := range []string{"fresh-cold", "private-padding", "bilateral-recovery", "unilateral-recovery", "source-invalid", "nonbinary-presence", "source-label-mismatch", "private-capacity-overflow", "numeric-bound", "nonnegative-domain", "outcome-bound", "outcome-overflow", "feature-bound-under-poisson"} {
		t.Run(scenario, func(t *testing.T) { groupedRouteRunTest(t, scenario) })
	}
}

func groupedRouteRunTest(t *testing.T, scenario string) {
	t.Helper()
	s := groupedRouteTestSpec()
	if scenario == "nonnegative-domain" {
		s.Nonnegative = true
	}
	numeric := []*big.Int{}
	for _, eighths := range []int64{4, 2, 2, 6, -4, 4, 1, -2} {
		numeric = append(numeric, new(big.Int).Lsh(big.NewInt(eighths), 47))
	}
	if scenario == "outcome-bound" || scenario == "outcome-overflow" || scenario == "feature-bound-under-poisson" {
		s.NumericBound = new(big.Int).Lsh(big.NewInt(1), 50)
		s.OutcomeBound = new(big.Int).Lsh(big.NewInt(4), 50)
		numeric[1] = new(big.Int).Set(s.OutcomeBound)
		if scenario == "outcome-overflow" {
			numeric[1].Add(numeric[1], big.NewInt(1))
		}
		if scenario == "feature-bound-under-poisson" {
			numeric[0] = new(big.Int).Add(s.NumericBound, big.NewInt(1))
		}
	}
	labels, present := []int{1, 0, 1, 0}, []bool{true, true, true, true}
	if scenario == "private-padding" {
		labels[0], present[0] = -1, false
	}
	if scenario == "private-capacity-overflow" {
		labels = []int{0, 0, 0, 1}
	}
	metadata := []*big.Int{}
	for i, label := range labels {
		py := int64(1)
		if i == 1 {
			py = 0 // Missing y preserves cluster 0 slot 0 as a gap.
		}
		lp := int64(0)
		if present[i] {
			lp = 1
		}
		metadata = append(metadata, big.NewInt(1), big.NewInt(py), big.NewInt(int64(label)), big.NewInt(lp))
	}
	if scenario == "nonbinary-presence" {
		metadata[0] = big.NewInt(2)
	}
	if scenario == "numeric-bound" {
		numeric[0] = new(big.Int).Add(s.NumericBound, big.NewInt(1))
	}
	if scenario == "source-label-mismatch" {
		metadata[2] = big.NewInt(0)
	}
	keys := [2][32]byte{crossGridStageTestKey(0), crossGridStageTestKey(1)}
	side, err := groupedRouteSeal(s, labels, present, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	sources := [2][2]crossGridStageOutput{}
	for field, values := range [][]*big.Int{numeric, metadata} {
		for role := range sources {
			sources[role][field] = crossGridStageOutput{Share: make([]byte, 16*len(values)), Validity: make([]byte, len(values))}
		}
		for i, value := range values {
			mask, e := groupedRandomWord()
			if e != nil {
				t.Fatal(e)
			}
			a := Uint128{Lo: mask[0], Hi: mask[1]}
			b := U128FromBig(new(big.Int).Mod(value, exactGCModulus(128))).Sub(a)
			putUint128LE(sources[0][field].Share[16*i:16*(i+1)], a)
			putUint128LE(sources[1][field].Share[16*i:16*(i+1)], b)
			flag := byte(mask[2] & 1)
			sources[0][field].Validity[i], sources[1][field].Validity[i] = flag, flag^1
		}
	}
	if scenario == "source-invalid" {
		sources[1][0].Validity[0] ^= 1
	}
	base := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1})
	plan := crossGridStageGraph{Version: "cross-grid-stage-graph-v1", Family: "lmm", Session: "private-grouped-route-test",
		Authorities: [2]string{base.GarblerID, base.EvaluatorID}, SchemaDigest: sha256.Sum256([]byte("signed grouped route schema")), SemanticKey: sha256.Sum256([]byte("sticky grouped route release"))}
	for field, id := range []string{s.NumericStage, s.MetadataStage} {
		p := crossGridStagePlan{ID: id, Kind: "test.authenticated-source", Ring: 128, FPScale: 50,
			CoordOrder: make([]string, len(sources[0][field].Validity)), PublicBounds: map[string]int{"rows": 4}, SourceDigest: s.SourceDigest, ProfileDigest: s.ProfileDigest}
		if field == 1 {
			p.FPScale = 0
		}
		for i := range p.CoordOrder {
			p.CoordOrder[i] = fmt.Sprintf("source:%d", i)
		}
		plan.Stages = append(plan.Stages, p)
	}
	kernels := [2][]crossGridStageCompute{}
	for role := range kernels {
		for _, output := range sources[role] {
			output := output
			kernels[role] = append(kernels[role], func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
				return output, nil
			})
		}
		var owner *groupedRouteSidecar
		if role == 0 {
			owner = side
		}
		graph, err := groupedRouteBuildStagedGraph(s, exactGCRole(role), owner, keys[role])
		if err != nil {
			t.Fatal(err)
		}
		kernels[role] = append(kernels[role], graph.Compute...)
		if role == 0 {
			plan.Stages = append(plan.Stages, graph.Plans...)
		}
	}
	dirs := [2]string{filepath.Join(t.TempDir(), "private"), filepath.Join(t.TempDir(), "private")}
	type result struct {
		out []crossGridStageOutput
		err error
	}
	run := func(fault string, cold bool) [2]result {
		stores := [2]*crossGridStageStore{}
		for role := range stores {
			stores[role], err = crossGridStageOpenStore(dirs[role], keys[role], plan, exactGCRole(role))
			if err != nil {
				t.Fatal(err)
			}
			defer stores[role].Close()
		}
		left, right := net.Pipe()
		left.SetDeadline(time.Now().Add(3 * time.Minute))
		right.SetDeadline(time.Now().Add(3 * time.Minute))
		defer left.Close()
		defer right.Close()
		executors := [2]*crossGridStageExecutor{{Store: stores[0], Base: base}, {Store: stores[1], Base: base}}
		if fault != "" {
			events := [2]string{"after-prepare", "after-prepare"}
			if fault == "unilateral-recovery" {
				events = [2]string{"after-commit", "after-prepare-exchange"}
			}
			for role, event := range events {
				executors[role].fault = func(at string, r crossGridStageRecord) error {
					if r.StageID == "grouped.route.layer.000.tile.0000" && at == event {
						return errors.New("synthetic routing interruption")
					}
					return nil
				}
			}
		}
		active := kernels
		if cold {
			for role := range active {
				active[role] = make([]crossGridStageCompute, len(kernels[role]))
				for i := range active[role] {
					active[role][i] = func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error) {
						return crossGridStageOutput{}, errors.New("cold replay recomputed private routing")
					}
				}
			}
		}
		ch := make(chan result, 1)
		go func() {
			out, e := executors[0].Execute(left, active[0])
			left.Close()
			ch <- result{out, e}
		}()
		out, e := executors[1].Execute(right, active[1])
		right.Close()
		return [2]result{<-ch, {out, e}}
	}
	readTile := func() [2]crossGridStageRecord {
		var records [2]crossGridStageRecord
		for role := range records {
			store, e := crossGridStageOpenStore(dirs[role], keys[role], plan, exactGCRole(role))
			if e != nil {
				t.Fatal(e)
			}
			receipts := map[string][32]byte{}
			for _, abi := range plan.Stages {
				var previous [][32]byte
				for _, id := range abi.Predecessors {
					previous = append(previous, receipts[id])
				}
				r, e := store.load(abi, previous)
				if e != nil {
					store.Close()
					t.Fatal(e)
				}
				receipts[abi.ID] = r.StageReceipt
				if abi.ID == "grouped.route.layer.000.tile.0000" {
					records[role] = r
					break
				}
			}
			store.Close()
		}
		return records
	}
	var interrupted [2]crossGridStageRecord
	if scenario == "bilateral-recovery" || scenario == "unilateral-recovery" {
		failed := run(scenario, false)
		if failed[0].err == nil || failed[1].err == nil {
			t.Fatal("routing interruption did not interrupt both peers")
		}
		interrupted = readTile()
		want := [2]string{"PREPARE", "PREPARE"}
		if scenario == "unilateral-recovery" {
			want[0] = "COMMIT"
		}
		for role, r := range interrupted {
			if r.State != want[role] {
				t.Fatalf("fault did not produce intended durable state: %s", r.State)
			}
		}
	}
	got := run("", false)
	for _, result := range got {
		if result.err != nil {
			t.Fatal(result.err)
		}
	}
	a, b := got[0].out[len(plan.Stages)-1], got[1].out[len(plan.Stages)-1]
	valid := scenario == "outcome-bound" || scenario == "fresh-cold" || scenario == "private-padding" || scenario == "bilateral-recovery" || scenario == "unilateral-recovery"
	for i := range a.Validity {
		want := byte(0)
		if valid {
			want = 1
		}
		if a.Validity[i]^b.Validity[i] != want {
			t.Fatalf("coordinate %d lost sticky private validity", i)
		}
	}
	if valid {
		permutation := []int{1, 3, 0, 2}
		if scenario == "private-padding" {
			permutation = []int{1, 3, 2, 0}
		}
		for destination, source := range permutation {
			for c := 0; c < 3; c++ {
				want := new(big.Int)
				if source != 1 && present[source] {
					if c == 0 {
						want.Lsh(big.NewInt(1), 50)
					} else {
						want.Set(numeric[source*2+c-1])
					}
				}
				index := destination*3 + c
				opened := getUint128LE(a.Share[16*index : 16*(index+1)]).Add(getUint128LE(b.Share[16*index : 16*(index+1)]))
				if opened != U128FromBig(new(big.Int).Mod(want, exactGCModulus(128))) {
					t.Fatalf("coordinate %d changed values or compressed a missing slot", index)
				}
			}
		}
	}
	if scenario == "bilateral-recovery" || scenario == "unilateral-recovery" {
		after := readTile()
		for role, r := range after {
			old := interrupted[role]
			if scenario == "bilateral-recovery" {
				if r.AttemptNonce == old.AttemptNonce || r.OutputMaskDomainTag == old.OutputMaskDomainTag || r.StageReceipt == old.StageReceipt {
					t.Fatal("aborted routing tile reused attempt randomness")
				}
			} else if r.AttemptNonce != old.AttemptNonce || !bytes.Equal(r.Output.Share, old.Output.Share) {
				t.Fatal("unilateral recovery recomputed persisted routing tile")
			}
		}
	}
	if scenario == "fresh-cold" {
		replayed := run("", true)
		for role, result := range replayed {
			if result.err != nil || !bytes.Equal(result.out[len(plan.Stages)-1].Share, got[role].out[len(plan.Stages)-1].Share) {
				t.Fatal("cold replay changed committed routing shares", result.err)
			}
		}
	}
}
