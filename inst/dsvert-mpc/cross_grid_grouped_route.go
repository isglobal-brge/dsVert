package main

// The grouping owner is the garbler in this admitted adapter. Its private
// sidecar is authenticated locally; labels, controls, counts and their raw
// hashes never enter a public plan or receipt. This is an internal source
// handoff, not an analyst-supplied permutation endpoint.
import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

type groupedRouteStagedSpec struct {
	Clusters, Slots, Predictors int
	NumericStage, MetadataStage string
	SourceDigest, ProfileDigest [32]byte
	NumericBound                *big.Int // absolute f50 integer bound
	Nonnegative                 bool     // signed profile may require [0, NumericBound]
}

func (s groupedRouteStagedSpec) validate() error {
	if s.Clusters < 1 || s.Clusters > 16384 || s.Slots < 1 || s.Slots > 4096 ||
		s.Clusters > 16384/s.Slots || s.Predictors < 1 || s.Predictors > 16 ||
		s.NumericStage == "" || s.MetadataStage == "" || s.NumericStage == s.MetadataStage ||
		s.SourceDigest == ([32]byte{}) || s.ProfileDigest == ([32]byte{}) ||
		s.NumericBound == nil || s.NumericBound.Sign() < 1 || s.NumericBound.BitLen() > 126 {
		return errCrossGridStage
	}
	return nil
}

type groupedRouteSidecar struct {
	Version    string   `json:"version"`
	SpecDigest [32]byte `json:"spec_digest"`
	Labels     []int    `json:"labels"`
	Present    []bool   `json:"present"`
	Controls   []bool   `json:"controls"`
	CapacityOK bool     `json:"capacity_ok"`
	MAC        []byte   `json:"mac"`
}

func groupedRouteSidecarMAC(side groupedRouteSidecar, key [32]byte) []byte {
	side.MAC = nil
	raw, _ := json.Marshal(side)
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("grouped-private-route-v1\x00"))
	m.Write(raw)
	return m.Sum(nil)
}

// Seal runs at the authenticated grouping owner over the original PSI slots,
// before complete-case masking. An absent numeric value never compresses the
// owner's within-cluster slots. Capacity failures remain private validity.
func groupedRouteSeal(s groupedRouteStagedSpec, labels []int, present []bool, key [32]byte) (*groupedRouteSidecar, error) {
	if s.validate() != nil || key == ([32]byte{}) || len(labels) != s.Clusters*s.Slots || len(present) != len(labels) {
		return nil, errCrossGridStage
	}
	n := intNextPowerOfTwo(len(labels))
	permutation := make([]int, n)
	for i := range permutation {
		permutation[i] = -1
	}
	used, counts := make([]bool, n), make([]int, s.Clusters)
	side := &groupedRouteSidecar{Version: "grouped-private-route-v1", SpecDigest: crossGridStageHash("grouped-route-spec", s),
		Labels: append([]int(nil), labels...), Present: append([]bool(nil), present...), CapacityOK: true}
	for i, label := range labels {
		if !present[i] {
			continue
		}
		if label < 0 || label >= s.Clusters || counts[label] >= s.Slots {
			side.CapacityOK = false
			continue
		}
		permutation[label*s.Slots+counts[label]], used[i] = i, true
		counts[label]++
	}
	next := 0
	for i, source := range permutation {
		if source >= 0 {
			continue
		}
		for used[next] {
			next++
		}
		permutation[i], used[next] = next, true
	}
	var err error
	side.Controls, err = primitiveVPermutationControls(permutation)
	if err != nil {
		return nil, err
	}
	side.MAC = groupedRouteSidecarMAC(*side, key)
	return side, nil
}

type groupedRouteStagedGraph struct {
	Plans   []crossGridStagePlan
	Compute []crossGridStageCompute
}

// NumericStage is homogeneous f50 [PSI row, x1,...,xp,y]. MetadataStage is
// homogeneous q0 [PSI row, presentX1,...,presentXp,presentY,label,labelPresent].
// Their Validity bytes certify arithmetic/provenance; presence is private data.
func groupedRouteBuildStagedGraph(s groupedRouteStagedSpec, role exactGCRole, side *groupedRouteSidecar, key [32]byte) (*groupedRouteStagedGraph, error) {
	if s.validate() != nil || role > exactGCRoleEvaluator || (role == exactGCRoleEvaluator && side != nil) {
		return nil, errCrossGridStage
	}
	s.NumericBound = new(big.Int).Set(s.NumericBound)
	profile := crossGridStageHash("grouped-route-spec", s)
	if role == exactGCRoleGarbler {
		if side == nil || key == ([32]byte{}) || side.Version != "grouped-private-route-v1" || side.SpecDigest != profile ||
			!hmac.Equal(side.MAC, groupedRouteSidecarMAC(*side, key)) {
			return nil, errCrossGridStage
		}
		// Re-derive controls from authenticated labels: a valid MAC alone must
		// never admit an arbitrary caller-selected permutation.
		canonical, err := groupedRouteSeal(s, side.Labels, side.Present, key)
		if err != nil || !hmac.Equal(canonical.MAC, side.MAC) {
			return nil, errCrossGridStage
		}
		side = canonical
	}
	rows, cols := s.Clusters*s.Slots, s.Predictors+2
	n := intNextPowerOfTwo(rows)
	graph := &groupedRouteStagedGraph{}
	add := func(id, kind string, count int, previous []string, compute crossGridStageCompute) {
		coords := make([]string, count)
		for i := range coords {
			coords[i] = fmt.Sprintf("packed:%d", i)
		}
		graph.Plans = append(graph.Plans, crossGridStagePlan{ID: id, Kind: kind, Ring: 128, FPScale: 50,
			CoordOrder: coords, PublicBounds: map[string]int{"clusters": s.Clusters, "slots": s.Slots, "predictors": s.Predictors, "padded_rows": n},
			SourceDigest: s.SourceDigest, ProfileDigest: profile, Predecessors: previous})
		graph.Compute = append(graph.Compute, compute)
	}
	chunks := []string{}
	for start := 0; start < rows; start += 16 {
		start, count := start, min(16, rows-start)
		id := fmt.Sprintf("grouped.route.normalize.%06d", start/16)
		chunks = append(chunks, id)
		add(id, "grouped.private-complete-case-normalize", count*cols, []string{s.NumericStage, s.MetadataStage}, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 2 || groupedRouteCheckOutput(in[0], rows*(cols-1)) != nil || groupedRouteCheckOutput(in[1], rows*(cols+1)) != nil {
				return crossGridStageOutput{}, errCrossGridStage
			}
			return groupedRouteNormalize(rw, a, role, s, side, start, count, in)
		})
	}
	add("grouped.route.normalized", "grouped.normalized-assembly", n*cols, chunks, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != len(chunks) {
			return crossGridStageOutput{}, errCrossGridStage
		}
		out := crossGridStageOutput{Share: make([]byte, 16*n*cols), Validity: make([]byte, n*cols)}
		position := 0
		var flags []byte
		for k, value := range in {
			if groupedRouteCheckOutput(value, min(16, rows-16*k)*cols) != nil {
				return crossGridStageOutput{}, errCrossGridStage
			}
			copy(out.Share[position:], value.Share)
			position += len(value.Share)
			flags = append(flags, value.Validity...)
		}
		valid, err := groupedLMMStagedValidity(rw, a, role, "route-assembly-validity", flags)
		for i := range out.Validity {
			out.Validity[i] = byte(valid[0] & 1)
		}
		return out, err
	})
	previous := "grouped.route.normalized"
	var layers [][]coxLossSwitch
	if n > 1 {
		layers = coxLossLayers(n)
	}
	for layerIndex, layer := range layers {
		inputID := previous
		tileIDs := []string{}
		tileSize := max(1, coxLossOTBatch/cols)
		for start := 0; start < len(layer); start += tileSize {
			switches := append([]coxLossSwitch(nil), layer[start:min(start+tileSize, len(layer))]...)
			id := fmt.Sprintf("grouped.route.layer.%03d.tile.%04d", layerIndex, start/tileSize)
			tileIDs = append(tileIDs, id)
			add(id, "grouped.private-packed-ot-switches", 2*len(switches)*cols, []string{inputID}, func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
				if len(in) != 1 || groupedRouteCheckOutput(in[0], n*cols) != nil {
					return crossGridStageOutput{}, errCrossGridStage
				}
				return groupedRouteSwitchTile(rw, a, role, cols, switches, side, in[0])
			})
		}
		layer := append([]coxLossSwitch(nil), layer...)
		previous = fmt.Sprintf("grouped.route.layer.%03d", layerIndex)
		add(previous, "grouped.private-layer-assembly", n*cols, tileIDs, func(_ io.ReadWriter, _ crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != len(tileIDs) {
				return crossGridStageOutput{}, errCrossGridStage
			}
			out := crossGridStageOutput{Share: make([]byte, 16*n*cols), Validity: make([]byte, n*cols)}
			for k, value := range in {
				switches := layer[k*tileSize : min((k+1)*tileSize, len(layer))]
				if groupedRouteCheckOutput(value, 2*len(switches)*cols) != nil {
					return crossGridStageOutput{}, errCrossGridStage
				}
				for j, sw := range switches {
					for side, row := range []int{sw.Left, sw.Right} {
						from, to := (2*j+side)*cols, row*cols
						copy(out.Share[16*to:16*(to+cols)], value.Share[16*from:16*(from+cols)])
						copy(out.Validity[to:to+cols], value.Validity[from:from+cols])
					}
				}
			}
			return out, nil
		})
	}
	add("grouped.route.output", "grouped.private-routed-f50", rows*cols, []string{previous}, func(_ io.ReadWriter, _ crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 || groupedRouteCheckOutput(in[0], n*cols) != nil {
			return crossGridStageOutput{}, errCrossGridStage
		}
		return crossGridStageOutput{Share: append([]byte(nil), in[0].Share[:16*rows*cols]...), Validity: append([]byte(nil), in[0].Validity[:rows*cols]...)}, nil
	})
	last := &graph.Plans[len(graph.Plans)-1]
	for i := range last.CoordOrder {
		last.CoordOrder[i] = fmt.Sprintf("cluster:%d:slot:%d:column:%d", i/(s.Slots*cols), (i/cols)%s.Slots, i%cols)
	}
	return graph, nil
}

func groupedRouteCheckOutput(in crossGridStageOutput, count int) error {
	if len(in.Share) != 16*count || len(in.Validity) != count {
		return errCrossGridStage
	}
	for _, v := range in.Validity {
		if v > 1 {
			return errCrossGridStage
		}
	}
	return nil
}

func groupedRouteNormalize(rw io.ReadWriter, a crossGridStageAttempt, role exactGCRole, s groupedRouteStagedSpec, side *groupedRouteSidecar, start, count int, in []crossGridStageOutput) (crossGridStageOutput, error) {
	// Per row: numeric, presence+label+labelPresence, owner's label+presence,
	// packed XOR arithmetic validity. The final input is private capacityOK.
	numeric, metadata, cols := s.Predictors+1, s.Predictors+3, s.Predictors+2
	stride, outputs := numeric+metadata+3, count*cols+1
	inputs := count*stride + 1
	words := make([]*big.Int, inputs)
	for i := range words {
		words[i] = new(big.Int)
	}
	var source strings.Builder
	fmt.Fprintf(&source, "package main\nfunc main(g [%d]uint128,e [%d]uint128) [%d]uint128 {\nok:=g[%d]+e[%d]==1\n", inputs+outputs, inputs, outputs, inputs-1, inputs-1)
	values := []string{}
	for r := 0; r < count; r++ {
		base, row := r*stride, start+r
		flags := uint64(0)
		for c := 0; c < numeric; c++ {
			index := row*numeric + c
			words[base+c] = getUint128LE(in[0].Share[16*index : 16*(index+1)]).ToBig()
			flags |= uint64(in[0].Validity[index]) << uint(c)
		}
		for c := 0; c < metadata; c++ {
			index := row*metadata + c
			words[base+numeric+c] = getUint128LE(in[1].Share[16*index : 16*(index+1)]).ToBig()
			flags |= uint64(in[1].Validity[index]) << uint(numeric+c)
		}
		ownerLabel, ownerPresent := base+numeric+metadata, base+numeric+metadata+1
		if role == exactGCRoleGarbler {
			words[ownerLabel] = new(big.Int).Mod(big.NewInt(int64(side.Labels[row])), exactGCModulus(128))
			if side.Present[row] {
				words[ownerPresent].SetInt64(1)
			}
		}
		words[base+stride-1].SetUint64(flags)
		fmt.Fprintf(&source, "ok=ok && (g[%d]^e[%d])==%d\nlive%d:=true\n", base+stride-1, base+stride-1, (uint64(1)<<uint(numeric+metadata))-1, r)
		for c := 0; c < numeric; c++ {
			v, p := base+c, base+numeric+c
			fmt.Fprintf(&source, "v%d_%d:=int128(g[%d]+e[%d])\np%d_%d:=g[%d]+e[%d]\nok=ok && (p%d_%d==0 || p%d_%d==1)\nif p%d_%d==1 {ok=ok && v%d_%d>=-int128(%s) && v%d_%d<=int128(%s)}\nlive%d=live%d && p%d_%d==1\n", r, c, v, v, r, c, p, p, r, c, r, c, r, c, r, c, s.NumericBound, r, c, s.NumericBound, r, r, r, c)
			if s.Nonnegative {
				fmt.Fprintf(&source, "if p%d_%d==1 {ok=ok && v%d_%d>=0}\n", r, c, r, c)
			}
		}
		label, presence := base+numeric+numeric, base+numeric+numeric+1
		fmt.Fprintf(&source, "label%d:=g[%d]+e[%d]\nlp%d:=g[%d]+e[%d]\nok=ok && label%d==g[%d]+e[%d] && lp%d==g[%d]+e[%d] && (lp%d==0 || lp%d==1)\nif lp%d==1 {ok=ok && label%d<%d}\nlive%d=live%d && lp%d==1\nl%d:=uint128(0)\nif live%d {l%d=1125899906842624}\n", r, label, label, r, presence, presence, r, ownerLabel, ownerLabel, r, ownerPresent, ownerPresent, r, r, r, r, s.Clusters, r, r, r, r, r, r)
		values = append(values, fmt.Sprintf("l%d", r))
		for c := 0; c < numeric; c++ {
			fmt.Fprintf(&source, "if !live%d {v%d_%d=0}\n", r, r, c)
			values = append(values, fmt.Sprintf("uint128(v%d_%d)", r, c))
		}
	}
	if role == exactGCRoleGarbler && side.CapacityOK {
		words[inputs-1].SetInt64(1)
	}
	source.WriteString("valid:=uint128(0)\nif ok {valid=1}\n")
	values = append(values, "valid")
	fmt.Fprintf(&source, "var out [%d]uint128\n", outputs)
	for i, value := range values {
		fmt.Fprintf(&source, "out[%d]=%s-g[%d]\n", i, value, inputs+i)
	}
	source.WriteString("return out\n}\n")
	program, err := primitiveVCompile(source.String(), 128, inputs+outputs, inputs, outputs)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	run := primitiveVRunGarbler
	if role == exactGCRoleEvaluator {
		run = primitiveVRunEvaluator
	}
	result, err := run(rw, program, groupedLMMStagedSession(a, "route-normalize"), crossGridStageHash("grouped-route-spec", s), words)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	out := crossGridStageOutput{Share: make([]byte, 16*count*cols), Validity: make([]byte, count*cols)}
	for i := range out.Validity {
		putUint128LE(out.Share[16*i:16*(i+1)], U128FromBig(result[i]))
		out.Validity[i] = byte(result[len(result)-1].Bit(0))
	}
	return out, nil
}

func groupedRouteSwitchTile(rw io.ReadWriter, a crossGridStageAttempt, role exactGCRole, cols int, switches []coxLossSwitch, side *groupedRouteSidecar, in crossGridStageOutput) (out crossGridStageOutput, failure error) {
	owner := role == exactGCRoleGarbler
	x := make([]Uint128, len(switches)*cols)
	var choices []bool
	if owner {
		choices = make([]bool, len(x))
	}
	for i, sw := range switches {
		for c := 0; c < cols; c++ {
			left, right := (sw.Left*cols+c)*16, (sw.Right*cols+c)*16
			x[i*cols+c] = getUint128LE(in.Share[right : right+16]).Sub(getUint128LE(in.Share[left : left+16]))
			if owner {
				choices[i*cols+c] = side.Controls[sw.Control]
			}
		}
	}
	// This tile owns a new checked extension and encrypted record context on
	// every durable attempt; no volatile stream survives an abort or replay.
	session := groupedLMMStagedSession(a, "route-switch-ot")
	session.Spec = exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 128, VectorLen: 1}
	secure, err := newExactGCSecureRecordRW(rw, session, role)
	if err != nil {
		return out, err
	}
	conn := p2p.NewConn(secure)
	transfer := ot.NewCOT(ot.NewCO(rand.Reader), rand.Reader, true, false)
	masks, err := coxLossOTSelect(conn, owner, x, choices, transfer)
	if finish := exactGCFinishConn(conn, rw, err); finish != nil || err != nil {
		return out, errCrossGridStage
	}
	valid, err := groupedLMMStagedValidity(rw, a, role, "route-switch-validity", in.Validity)
	if err != nil {
		return out, err
	}
	out = crossGridStageOutput{Share: make([]byte, 32*len(x)), Validity: make([]byte, 2*len(x))}
	for i, sw := range switches {
		for c := 0; c < cols; c++ {
			left, right := (sw.Left*cols+c)*16, (sw.Right*cols+c)*16
			v, w := getUint128LE(in.Share[left:left+16]), getUint128LE(in.Share[right:right+16])
			if owner && choices[i*cols+c] {
				v, w = w, v
			}
			v, w = v.Add(masks[i*cols+c]), w.Sub(masks[i*cols+c])
			for side, value := range []Uint128{v, w} {
				index := (2*i+side)*cols + c
				putUint128LE(out.Share[16*index:16*(index+1)], value)
				out.Validity[index] = byte(valid[0] & 1)
			}
		}
	}
	return out, nil
}
