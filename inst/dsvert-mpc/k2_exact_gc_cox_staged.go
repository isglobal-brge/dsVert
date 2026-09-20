package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// One attempt-local packed runner followed by the RETAINED private bridge.
// No Ring64 word is ever written into the durable Ring128 ABI by relabelling.
// The authenticated adapter must bind packed sources and private sort sidecars
// before invoking this internal compute helper. Kernel receipts are not COMMIT.
func coxLossRunBridgedShares(rw io.ReadWriter, owner bool, p coxLossSharedPlan, programs *coxLossSharedPrograms, a crossGridStageAttempt, contract [32]byte, packed []Uint128, controls, ends []bool, sourceValidity []byte) (crossGridStageOutput, error) {
	if len(sourceValidity) != len(packed) {
		return crossGridStageOutput{}, coxLossError()
	}
	for _, v := range sourceValidity {
		if v > 1 {
			return crossGridStageOutput{}, coxLossError()
		}
	}
	result, err := registerCoxGridCrossLoss().RunShares(rw, owner, p, programs, a.Session, contract, packed, controls, ends)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	role := exactGCRoleEvaluator
	run := primitiveVRunEvaluator
	if owner {
		role = exactGCRoleGarbler
		run = primitiveVRunGarbler
	}
	sourceValid, err := groupedLMMStagedValidity(rw, a, role, "cox/source-validity", sourceValidity)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	words := make([]*big.Int, 2*p.Spec.Candidates)
	for j, cap := range p.Spec.Caps {
		bridge, err := registerCoxGridCrossLoss().JointDPBridgeCompile(cap)
		if err != nil {
			return crossGridStageOutput{}, err
		}
		session := groupedLMMStagedSession(a, fmt.Sprintf("cox/private-ring64-bridge/%d", j))
		// Original local words are embedded only as circuit INPUTS. The bridge
		// reconstructs modulo 2^64 on private wires before conversion and masking.
		out, err := run(rw, bridge, session, contract, []*big.Int{new(big.Int).SetUint64(result.Coordinates[j]), new(big.Int).SetUint64(result.Validity[j])})
		if err != nil {
			return crossGridStageOutput{}, err
		}
		words[2*j], words[2*j+1] = out[0], out[1]
	}
	// Source validity remains private and gates every bridged coordinate. Its
	// least significant additive-share bits form the equivalent XOR sharing.
	program, err := coxLossStagedGateCompile(p.Spec.Candidates)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	words = append(words, new(big.Int).SetUint64(sourceValid[0]&1))
	out, err := run(rw, program, groupedLMMStagedSession(a, "cox/source-terminal-gate"), contract, words)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	value := crossGridStageOutput{Share: make([]byte, 16*p.Spec.Candidates), Validity: make([]byte, p.Spec.Candidates)}
	for j := range value.Validity {
		copy(value.Share[16*j:16*(j+1)], coxLossStagedWordBytes(out[2*j]))
		value.Validity[j] = byte(out[2*j+1].Bit(0))
	}
	return value, nil
}

func coxLossStagedWordBytes(x *big.Int) []byte {
	out := make([]byte, 16)
	raw := new(big.Int).And(new(big.Int).Set(x), exactGCMask(128)).Bytes()
	for i, v := range raw {
		out[len(raw)-1-i] = v
	}
	return out
}

func coxLossStagedGateCompile(n int) (*primitiveVProgram, error) {
	if n < 1 || n > 50 {
		return nil, coxLossError()
	}
	in, out := 2*n+1, 2*n
	var b strings.Builder
	fmt.Fprintf(&b, "package main\nfunc main(g [%d]uint128,e [%d]uint128) [%d]uint128 {\nvar out [%d]uint128\nsource:=(g[%d]^e[%d])==1\n", in+out, in, out, out, in-1, in-1)
	for j := 0; j < n; j++ {
		fmt.Fprintf(&b, "q%d:=g[%d]+e[%d]\nv%d:=uint128(0)\nif source && g[%d]+e[%d]==1 { v%d=1 } else { q%d=0 }\nout[%d]=q%d-g[%d]\nout[%d]=v%d-g[%d]\n", j, 2*j, 2*j, j, 2*j+1, 2*j+1, j, j, 2*j, j, in+2*j, 2*j+1, j, in+2*j+1)
	}
	b.WriteString("return out\n}\n")
	return primitiveVCompile(b.String(), 128, in+out, in, out)
}

// Sources are complete candidate f100 dots and row-major q0 live/event. Both
// records are in original PSI order. The runner applies one packed permutation.
// All Ring64 prefixes/tie scans stay in one attempt-local phase ending at the
// private bridge; abort restarts that phase with fresh streams, never a cursor.
type coxLossStagedSpec struct {
	Plan                                  coxLossSharedPlan
	Prefix                                string
	SourceDigest, Contract, RoutingDigest [32]byte
	Sources                               [2]crossGridStagePlan
}

type coxLossStagedRouting struct {
	Controls, Ends []bool
	MAC            [32]byte
}
type coxLossStagedGraph struct {
	Plans   []crossGridStagePlan
	Compute []crossGridStageCompute
}

func coxLossStagedRoutingMAC(s coxLossStagedSpec, controls, ends []bool, key [32]byte) [32]byte {
	s.RoutingDigest = [32]byte{}
	digest := crossGridStageHash("cox-private-routing-sidecar", struct {
		Spec           coxLossStagedSpec
		Controls, Ends []bool
	}{s, controls, ends})
	h := hmac.New(sha256.New, key[:])
	h.Write(digest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Called by the authenticated time/event owner's source adapter. Only the
// opaque keyed digest is placed in the signed shared plan; order/ties stay local.
func coxLossSealStagedRouting(s coxLossStagedSpec, controls, ends []bool, key [32]byte) (*coxLossStagedRouting, error) {
	shape, err := primitiveVPermutationShape(s.Plan.PaddedRows, 1, 1)
	if err != nil || key == ([32]byte{}) || len(controls) != shape.Switches || len(ends) != s.Plan.PaddedRows || len(ends) == 0 || !ends[len(ends)-1] {
		return nil, coxLossError()
	}
	side := &coxLossStagedRouting{Controls: append([]bool(nil), controls...), Ends: append([]bool(nil), ends...)}
	side.MAC = coxLossStagedRoutingMAC(s, side.Controls, side.Ends, key)
	return side, nil
}

func coxLossBuildStagedGraph(s coxLossStagedSpec, role exactGCRole, side *coxLossStagedRouting, key [32]byte) (*coxLossStagedGraph, error) {
	if s.SourceDigest == ([32]byte{}) || s.Contract == ([32]byte{}) || s.RoutingDigest == ([32]byte{}) || exactGCValidateLabel("stage", s.Prefix, 80) != nil || (role != exactGCRoleGarbler && role != exactGCRoleEvaluator) {
		return nil, coxLossError()
	}
	// Registered admission remains authoritative; no unregistered larger profile.
	programs, err := registerCoxGridCrossLoss().SharedCompile(s.Plan)
	if err != nil {
		return nil, err
	}
	n, j := s.Plan.PaddedRows, s.Plan.Spec.Candidates
	widths := [2]int{n * j, 2 * n}
	ids := make([]string, 2)
	for i, src := range s.Sources {
		if src.Ring != 128 || src.FPScale != []int{100, 0}[i] || len(src.CoordOrder) != widths[i] || src.SourceDigest != s.SourceDigest || src.ID == "" {
			return nil, coxLossError()
		}
		ids[i] = src.ID
	}
	if ids[0] == ids[1] {
		return nil, coxLossError()
	}
	var controls, ends []bool
	if role == exactGCRoleGarbler {
		if side == nil || key == ([32]byte{}) || side.MAC != s.RoutingDigest || coxLossStagedRoutingMAC(s, side.Controls, side.Ends, key) != side.MAC {
			return nil, coxLossError()
		}
		sealed, err := coxLossSealStagedRouting(s, side.Controls, side.Ends, key)
		if err != nil {
			return nil, err
		}
		controls, ends = sealed.Controls, sealed.Ends
	} else if side != nil {
		return nil, coxLossError()
	}
	profile := crossGridStageHash("cox-staged-packed-bridged", s)
	coords := make([]string, j)
	for i := range coords {
		coords[i] = fmt.Sprintf("candidate/%d/breslow-loss", i)
	}
	plan := crossGridStagePlan{ID: s.Prefix + ".bridged", Kind: "cox.packed-breslow-private-bridge", Ring: 128, FPScale: s.Plan.Spec.GridBits, CoordOrder: coords, PublicBounds: map[string]int{"capacity": s.Plan.Spec.Capacity, "padded_rows": n, "candidates": j}, SourceDigest: s.SourceDigest, ProfileDigest: profile, Predecessors: ids}
	compute := func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 2 {
			return crossGridStageOutput{}, coxLossError()
		}
		for i := range in {
			if s.Sources[i].validateOutput(in[i]) != nil {
				return crossGridStageOutput{}, coxLossError()
			}
		}
		packed := make([]Uint128, n*(j+2))
		validity := make([]byte, len(packed))
		for row := 0; row < n; row++ {
			for c := 0; c < j+2; c++ {
				field, index := 0, row*j+c
				if c >= j {
					field, index = 1, 2*row+c-j
				}
				raw := in[field].Share[16*index : 16*(index+1)]
				packed[row*(j+2)+c] = Uint128{Lo: binary.LittleEndian.Uint64(raw[:8]), Hi: binary.LittleEndian.Uint64(raw[8:])}
				validity[row*(j+2)+c] = in[field].Validity[index]
			}
		}
		return coxLossRunBridgedShares(rw, role == exactGCRoleGarbler, s.Plan, programs, a, profile, packed, controls, ends, validity)
	}
	return &coxLossStagedGraph{Plans: []crossGridStagePlan{plan}, Compute: []crossGridStageCompute{compute}}, nil
}
