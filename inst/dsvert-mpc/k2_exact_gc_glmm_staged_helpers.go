package main

// Retained durable primitive mechanics with a distinct GLMM purpose domain.
import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"strings"
)

func groupedGLMMStagedSession(attempt crossGridStageAttempt, label string) exactGCSession {
	s := attempt.Session
	// Each composed exchange has its own secure-record domain, even while using
	// the same transport. Attempt.Session is already fresh after an abort.
	s.Purpose = fmt.Sprintf("%s/glmm/%x/%s", s.Purpose, attempt.OutputMaskDomainTag, label)
	return s
}

func groupedGLMMStagedPrimitive(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, label string, contract [32]byte, program *primitiveVProgram, words []groupedWord) ([]groupedWord, error) {
	input := make([]*big.Int, len(words))
	for i, w := range words {
		input[i] = groupedWordInteger(w)
	}
	run := primitiveVRunGarbler
	if role == exactGCRoleEvaluator {
		run = primitiveVRunEvaluator
	}
	output, err := run(rw, program, groupedGLMMStagedSession(attempt, label), contract, input)
	if err != nil {
		return nil, err
	}
	result := make([]groupedWord, len(output))
	for i, w := range output {
		result[i] = groupedWordFromBig(w)
	}
	return result, nil
}

// XOR-validity is never ANDed locally. Packed XOR words keep the private
// conjunction within the existing circuit input bound; output stays shared.
func groupedGLMMStagedValidity(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, label string, flags []byte) (groupedWord, error) {
	if len(flags) < 1 || len(flags) > 192*2048 {
		return groupedWord{}, primitiveVError()
	}
	count := (len(flags) + 191) / 192
	words := make([]groupedWord, count)
	for i, flag := range flags {
		if flag > 1 {
			return groupedWord{}, primitiveVError()
		}
		words[i/192][(i%192)/64] |= uint64(flag) << uint(i%64)
	}
	var source strings.Builder
	fmt.Fprintf(&source, "package main\nfunc main(g [%d]uint192,e [%d]uint192) [1]uint192 {\nv:=uint192(1)\n", count+1, count)
	for i := 0; i < count; i++ {
		bits := len(flags) - 192*i
		if bits > 192 {
			bits = 192
		}
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
		fmt.Fprintf(&source, "if (g[%d]^e[%d])!=uint192(%s) {v=0}\n", i, i, mask)
	}
	fmt.Fprintf(&source, "var out [1]uint192\nout[0]=v-g[%d]\nreturn out\n}\n", count)
	program, err := primitiveVCompile(source.String(), 192, count+1, count, 1)
	if err != nil {
		return groupedWord{}, err
	}
	contract := sha256.Sum256([]byte("glmm-staged-private-validity-v1"))
	out, err := groupedGLMMStagedPrimitive(rw, attempt, role, label, contract, program, words)
	if err != nil {
		return groupedWord{}, err
	}
	return out[0], nil
}

func groupedGLMMStagedOutput(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, words []groupedWord, inputs []crossGridStageOutput) (crossGridStageOutput, error) {
	var flags []byte
	for _, input := range inputs {
		flags = append(flags, input.Validity...)
	}
	valid, err := groupedGLMMStagedValidity(rw, attempt, role, "output-validity", flags)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	output := crossGridStageOutput{Share: groupedEncodeWords(words), Validity: make([]byte, len(words))}
	for i := range output.Validity {
		output.Validity[i] = byte(valid[0] & 1)
	}
	return output, nil
}
