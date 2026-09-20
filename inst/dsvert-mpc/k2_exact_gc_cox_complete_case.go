package main

// Private composition of authenticated additive presence words. Missingness is
// data (live=0), not an arithmetic failure. Neither presence nor live is opened.
import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"strings"
)

func coxLossPresencePlans(c coxLossStagedSpec, presence int) (crossGridStagePlan, crossGridStagePlan, error) {
	if presence < 3 || presence > 18 || c.Plan.PaddedRows < 2 || c.Plan.PaddedRows > 512 {
		return crossGridStagePlan{}, crossGridStagePlan{}, errCrossGridStage
	}
	coords := make([]string, c.Plan.PaddedRows*(presence+1))
	for i := range coords {
		coords[i] = fmt.Sprintf("presence-event/%d", i)
	}
	raw := crossGridStagePlan{ID: "cox.source.presence-event", Kind: "cox.authenticated-presence-event",
		Ring: 128, FPScale: 0, CoordOrder: coords, SourceDigest: c.SourceDigest, ProfileDigest: c.Contract,
		PublicBounds: map[string]int{"capacity": c.Plan.Spec.Capacity, "padded_rows": c.Plan.PaddedRows, "presence_columns": presence}}
	composed, _, err := coxLossCompleteCaseStage(raw, c.Plan.Spec.Capacity, c.Plan.PaddedRows, presence, exactGCRoleGarbler)
	return raw, composed, err
}

// Input rows contain predictor/time/event presence, then the q0 event value.
// All words stay in Ring128 until the circuit reconstructs them privately.
// The output is row-major q0 live/event, ready for the retained Cox runner.
func coxLossCompleteCaseStage(source crossGridStagePlan, capacity, rows, presence int, role exactGCRole) (crossGridStagePlan, crossGridStageCompute, error) {
	if capacity < 2 || capacity > 400 || rows != 1<<uint(bits.Len(uint(capacity-1))) ||
		presence < 3 || presence > 18 || role > exactGCRoleEvaluator ||
		source.Ring != 128 || source.FPScale != 0 || len(source.CoordOrder) != rows*(presence+1) {
		return crossGridStagePlan{}, nil, errCrossGridStage
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		return crossGridStagePlan{}, nil, errCrossGridStage
	}
	var pinned crossGridStagePlan
	if json.Unmarshal(encoded, &pinned) != nil {
		return crossGridStagePlan{}, nil, errCrossGridStage
	}
	source = pinned
	coords := make([]string, 2*rows)
	for row := 0; row < rows; row++ {
		coords[2*row], coords[2*row+1] = fmt.Sprintf("row/%d/live", row), fmt.Sprintf("row/%d/event", row)
	}
	plan := crossGridStagePlan{ID: source.ID + ".complete-case", Kind: "cox.private-complete-case",
		Ring: 128, FPScale: 0, CoordOrder: coords, Predecessors: []string{source.ID},
		PublicBounds: map[string]int{"capacity": capacity, "padded_rows": rows, "presence_columns": presence},
		SourceDigest: source.SourceDigest, ProfileDigest: crossGridStageHash("cox-complete-case-v1", source)}
	// Immutable public programs only. Execution always draws fresh masks/OT under
	// the durable attempt and chunk domains, including after bilateral abort.
	programs := map[string]*primitiveVProgram{}
	compute := func(rw io.ReadWriter, a crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 || source.validateOutput(in[0]) != nil {
			return crossGridStageOutput{}, errCrossGridStage
		}
		out := crossGridStageOutput{}
		for start := 0; start < rows; start += 16 {
			count := min(16, rows-start)
			stride, outputs := presence+2, 2*count+1
			inputs := count * stride
			words := make([]*big.Int, inputs)
			var b strings.Builder
			fmt.Fprintf(&b, "package main\nfunc main(g [%d]uint128,e [%d]uint128) [%d]uint128 {\nok:=true\n", inputs+outputs, inputs, outputs)
			for r := 0; r < count; r++ {
				base := r * stride
				flags := uint64(0)
				for c := 0; c <= presence; c++ {
					index := (start+r)*(presence+1) + c
					words[base+c] = getUint128LE(in[0].Share[16*index : 16*(index+1)]).ToBig()
					flags |= uint64(in[0].Validity[index]) << uint(c)
				}
				words[base+presence+1] = new(big.Int).SetUint64(flags)
				fmt.Fprintf(&b, "ok=ok && (g[%d]^e[%d])==%d\nlive%d:=%t\n", base+presence+1, base+presence+1, (uint64(1)<<uint(presence+1))-1, r, start+r < capacity)
				for c := 0; c < presence; c++ {
					fmt.Fprintf(&b, "p%d_%d:=g[%d]+e[%d]\nok=ok && p%d_%d<=1\nlive%d=live%d && p%d_%d==1\n", r, c, base+c, base+c, r, c, r, r, r, c)
				}
				fmt.Fprintf(&b, "event%d:=g[%d]+e[%d]\nok=ok && event%d<=1\nl%d:=uint128(0)\nif live%d {l%d=1} else {event%d=0}\n", r, base+presence, base+presence, r, r, r, r, r)
			}
			fmt.Fprintf(&b, "valid:=uint128(0)\nif ok {valid=1}\nvar out [%d]uint128\n", outputs)
			for r := 0; r < count; r++ {
				fmt.Fprintf(&b, "out[%d]=l%d-g[%d]\nout[%d]=event%d-g[%d]\n", 2*r, r, inputs+2*r, 2*r+1, r, inputs+2*r+1)
			}
			fmt.Fprintf(&b, "out[%d]=valid-g[%d]\nreturn out\n}\n", outputs-1, inputs+outputs-1)
			text := b.String()
			program := programs[text]
			if program == nil {
				var err error
				program, err = primitiveVCompile(text, 128, inputs+outputs, inputs, outputs)
				if err != nil {
					return crossGridStageOutput{}, err
				}
				programs[text] = program
			}
			run := primitiveVRunGarbler
			if role == exactGCRoleEvaluator {
				run = primitiveVRunEvaluator
			}
			result, err := run(rw, program, groupedLMMStagedSession(a, fmt.Sprintf("cox/complete-case/%d", start)), plan.ProfileDigest, words)
			if err != nil {
				return crossGridStageOutput{}, err
			}
			for i := 0; i < outputs-1; i++ {
				out.Share = append(out.Share, coxLossStagedWordBytes(result[i])...)
				out.Validity = append(out.Validity, byte(result[outputs-1].Bit(0)))
			}
		}
		return out, nil
	}
	return plan, compute, nil
}
