package main

// Canonical Ring128 -> Ring192 boundary (EXECUTOR_SPEC C). Only z=x+r mod
// 2^128 is opened. Neither r, the carry, the sign nor validity is opened.
// The stage executor authenticates and durably commits the returned shares.
import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const crossGridStageConversionBatch = 32
const crossGridStageConversionRelayBatch = 256

type crossGridStageConversionPrograms struct {
	mask, correction *primitiveVProgram
}

func crossGridStageConversionCompile(count int, signed bool) (*crossGridStageConversionPrograms, error) {
	if count < 1 || count > crossGridStageConversionRelayBatch {
		return nil, errCrossGridStage
	}
	mask128 := exactGCMask(128)
	var source strings.Builder
	fmt.Fprintf(&source, "package main\nfunc main(g [%d]uint192,e [%d]uint192) [%d]uint192 {\nvar out [%d]uint192\n", 2*count, count, count, count)
	for i := 0; i < count; i++ {
		// Each authority contributes an independent uniform Ring128 share.
		// Reduction happens INSIDE GC, before sharing the exact integer r
		// in Ring192. Locally widening the two contributions would be wrong.
		fmt.Fprintf(&source, "r%d:=(g[%d]+e[%d])&uint192(%s)\nout[%d]=r%d-g[%d]\n", i, i, i, mask128, i, i, count+i)
	}
	source.WriteString("return out\n}\n")
	preprocess, err := primitiveVCompile(source.String(), 192, 2*count, count, count)
	if err != nil {
		return nil, err
	}
	source.Reset()
	fmt.Fprintf(&source, "package main\nfunc main(g [%d]uint192,e [%d]uint192) [%d]uint192 {\nvar out [%d]uint192\n", 5*count, 3*count, 2*count, 2*count)
	for i := 0; i < count; i++ {
		base := 3 * i
		fmt.Fprintf(&source, "r%d:=g[%d]+e[%d]\nz%d:=g[%d]\nc%d:=uint192(0)\nv%d:=(g[%d]^e[%d])&uint192(1)\n", i, base, base, i, base+1, i, i, base+2, base+2)
		fmt.Fprintf(&source, "if z%d<r%d { c%d=uint192(1) }\n", i, i, i)
		if signed {
			fmt.Fprintf(&source, "x%d:=(z%d-r%d)&uint192(%s)\nif x%d>=uint192(%s) { c%d=c%d-uint192(1) }\n", i, i, i, mask128, i, exactGCModulus(127), i, i)
		}
		// Both parties independently computed the same public opening. These
		// guards stay private and feed the existing per-coordinate validity.
		fmt.Fprintf(&source, "if r%d>uint192(%s)||z%d>uint192(%s)||z%d!=e[%d] { v%d=uint192(0) }\n", i, mask128, i, mask128, i, base+1, i)
		fmt.Fprintf(&source, "out[%d]=c%d-g[%d]\nout[%d]=v%d-g[%d]\n", 2*i, i, 3*count+2*i, 2*i+1, i, 3*count+2*i+1)
	}
	source.WriteString("return out\n}\n")
	correction, err := primitiveVCompile(source.String(), 192, 5*count, 3*count, 2*count)
	if err != nil {
		return nil, err
	}
	return &crossGridStageConversionPrograms{preprocess, correction}, nil
}

func crossGridStageConversionSession(attempt crossGridStageAttempt, label string) exactGCSession {
	s := attempt.Session
	s.Purpose = fmt.Sprintf("%s/ring128-to-ring192/%x/%s", s.Purpose, attempt.OutputMaskDomainTag, label)
	return s
}

func crossGridStageConversionRun(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, label string, contract [32]byte, program *primitiveVProgram, words []groupedWord) ([]groupedWord, error) {
	inputs := make([]*big.Int, len(words))
	for i, w := range words {
		inputs[i] = groupedWordInteger(w)
	}
	run := primitiveVRunGarbler
	if role == exactGCRoleEvaluator {
		run = primitiveVRunEvaluator
	}
	outputs, err := run(rw, program, crossGridStageConversionSession(attempt, label), contract, inputs)
	if err != nil {
		return nil, err
	}
	result := make([]groupedWord, len(outputs))
	for i, w := range outputs {
		result[i] = groupedWordFromBig(w)
	}
	return result, nil
}

// These words are wire containers for 128-bit shares, never locally lifted
// Ring192 values. Only the correlated mask preprocessing produces [r]_192.
func crossGridStageConversionWord(raw []byte) groupedWord {
	return groupedWord{binary.LittleEndian.Uint64(raw[:8]), binary.LittleEndian.Uint64(raw[8:16]), 0}
}

func crossGridStageConversionChunk(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, contract [32]byte, label string, programs *crossGridStageConversionPrograms, input crossGridStageOutput, mask128 []groupedWord) (crossGridStageOutput, error) {
	count := len(mask128)
	if count < 1 || count > crossGridStageConversionRelayBatch || len(input.Share) != 16*count || len(input.Validity) != count || programs == nil {
		return crossGridStageOutput{}, errCrossGridStage
	}
	for i, mask := range mask128 {
		if mask[2] != 0 || input.Validity[i] > 1 {
			return crossGridStageOutput{}, errCrossGridStage
		}
	}
	mask192, err := crossGridStageConversionRun(rw, attempt, role, label+"/dual-ring-mask", contract, programs.mask, mask128)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	// Online opening of one-time-pad shares, with a distinct encrypted-record
	// domain. Masks are local fresh coins, never derived from a shared key.
	local, peer := make([]byte, 16*count), make([]byte, 16*count)
	for i, mask := range mask128 {
		z := crossGridStageConversionWord(input.Share[16*i:]).add(mask)
		binary.LittleEndian.PutUint64(local[16*i:], z[0])
		binary.LittleEndian.PutUint64(local[16*i+8:], z[1])
	}
	secure, err := newExactGCSecureRecordRW(rw, crossGridStageConversionSession(attempt, label+"/masked-opening"), role)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	exchange := func(send bool) error {
		if send {
			return exactGCWriteFull(secure, local)
		}
		_, err := io.ReadFull(secure, peer)
		return err
	}
	if err = exchange(role == exactGCRoleGarbler); err != nil {
		return crossGridStageOutput{}, err
	}
	if err = exchange(role != exactGCRoleGarbler); err != nil {
		return crossGridStageOutput{}, err
	}
	opened := make([]groupedWord, count)
	words := make([]groupedWord, 3*count)
	for i := range opened {
		opened[i] = crossGridStageConversionWord(local[16*i:]).add(crossGridStageConversionWord(peer[16*i:]))
		opened[i][2] = 0 // z is the PUBLIC opening modulo 2^128.
		words[3*i], words[3*i+1], words[3*i+2] = mask192[i], opened[i], groupedWord{uint64(input.Validity[i])}
	}
	correction, err := crossGridStageConversionRun(rw, attempt, role, label+"/private-carry-sign", contract, programs.correction, words)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	result := make([]groupedWord, count)
	out := crossGridStageOutput{Validity: make([]byte, count)}
	for i := range result {
		// [x]_192 = lift_public(z) - [r]_192 + ([z<r]-[sign])*M.
		// Multiplication by M uses the PRIVATE Ring192 correction share.
		result[i] = correction[2*i].shl(128).sub(mask192[i])
		if role == exactGCRoleGarbler {
			result[i] = result[i].add(opened[i])
		}
		out.Validity[i] = byte(correction[2*i+1][0] & 1)
	}
	out.Share = groupedEncodeWords(result)
	return out, nil
}

func crossGridStageBuildConversion(input crossGridStagePlan, id string, signed bool, role exactGCRole) (crossGridStagePlan, crossGridStageCompute, error) {
	return crossGridStageBuildConversionBatch(input, id, signed, role, crossGridStageConversionBatch)
}

func crossGridStageBuildConversionBatch(input crossGridStagePlan, id string, signed bool, role exactGCRole, batch int) (crossGridStagePlan, crossGridStageCompute, error) {
	if batch < 1 || batch > crossGridStageConversionRelayBatch || input.Ring != 128 || len(input.CoordOrder) == 0 || input.FPScale < 0 || input.FPScale > 128 ||
		input.SourceDigest == ([32]byte{}) || input.ProfileDigest == ([32]byte{}) || input.ID == "" ||
		exactGCValidateLabel("stage", id, 128) != nil || id == input.ID || role > exactGCRoleEvaluator {
		return crossGridStagePlan{}, nil, errCrossGridStage
	}
	// Freeze the full input ABI so later caller mutation cannot alter execution
	// under the conversion's already-pinned profile digest.
	raw, err := json.Marshal(input)
	var pinned crossGridStagePlan
	if err != nil || json.Unmarshal(raw, &pinned) != nil {
		return crossGridStagePlan{}, nil, errCrossGridStage
	}
	input = pinned
	profile := crossGridStageHash("ring128-to-ring192-private-carry-v1", struct {
		Input  crossGridStagePlan
		Signed bool
	}{input, signed})
	plan := crossGridStagePlan{ID: id, Kind: "ring128-to-ring192", Ring: 192, FPScale: input.FPScale,
		CoordOrder: append([]string(nil), input.CoordOrder...), PublicBounds: make(map[string]int),
		SourceDigest: input.SourceDigest, ProfileDigest: profile, Predecessors: []string{input.ID}}
	for k, v := range input.PublicBounds {
		plan.PublicBounds[k] = v
	}
	if batch != crossGridStageConversionBatch {
		plan.PublicBounds["conversion_batch_coordinates"] = batch
	}
	compute := func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != 1 || input.validateOutput(in[0]) != nil {
			return crossGridStageOutput{}, errCrossGridStage
		}
		// Cache only public circuits during this attempt. Mask correlations and
		// openings are never cached or reused across attempts or coordinates.
		compiled := make(map[int]*crossGridStageConversionPrograms)
		out := crossGridStageOutput{Share: make([]byte, 0, 24*len(input.CoordOrder)), Validity: make([]byte, 0, len(input.CoordOrder))}
		for start := 0; start < len(input.CoordOrder); start += batch {
			count := min(batch, len(input.CoordOrder)-start)
			programs := compiled[count]
			if programs == nil {
				var err error
				programs, err = crossGridStageConversionCompile(count, signed)
				if err != nil {
					return crossGridStageOutput{}, err
				}
				compiled[count] = programs
			}
			random := make([]byte, 16*count)
			if _, err := io.ReadFull(rand.Reader, random); err != nil {
				return crossGridStageOutput{}, err
			}
			masks := make([]groupedWord, count)
			for i := range masks {
				masks[i] = crossGridStageConversionWord(random[16*i:])
			}
			clear(random)
			value := crossGridStageOutput{Share: in[0].Share[16*start : 16*(start+count)], Validity: in[0].Validity[start : start+count]}
			chunk, err := crossGridStageConversionChunk(rw, attempt, role, profile, fmt.Sprintf("chunk/%d", start), programs, value, masks)
			clear(masks)
			if err != nil {
				return crossGridStageOutput{}, err
			}
			out.Share = append(out.Share, chunk.Share...)
			out.Validity = append(out.Validity, chunk.Validity...)
		}
		return out, nil
	}
	return plan, compute, nil
}
