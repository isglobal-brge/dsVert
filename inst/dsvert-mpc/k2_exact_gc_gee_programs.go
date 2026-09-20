package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// One sequential source graph owns this cache. Only immutable PUBLIC circuit
// topology is retained; masks, labels, OT and records are recreated by Run*.
// Keys include the emitter and every public parameter used by that emitter.
type groupedGEEPublicPrograms map[[32]byte]*primitiveVProgram

func (p groupedGEEPublicPrograms) compile(kind string, parameters any, build func() (*primitiveVProgram, error)) (*primitiveVProgram, error) {
	key := crossGridStageHash("gee-public-program-v1", struct {
		Kind       string
		Parameters any
	}{kind, parameters})
	if program := p[key]; program != nil {
		return program, nil
	}
	program, err := build()
	if err == nil {
		p[key] = program
	}
	return program, err
}

// Same packed private conjunction as the retained staged helpers. Compilation
// depends only on flag count; secret flag words never enter the cache.
func (p groupedGEEPublicPrograms) validity(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, label string, flags []byte) (groupedWord, error) {
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
	program, err := p.compile("xor-validity", len(flags), func() (*primitiveVProgram, error) {
		var source strings.Builder
		fmt.Fprintf(&source, "package main\nfunc main(g [%d]uint192,e [%d]uint192) [1]uint192 {\nv:=uint192(1)\n", count+1, count)
		for i := 0; i < count; i++ {
			bits := min(192, len(flags)-192*i)
			mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
			fmt.Fprintf(&source, "if (g[%d]^e[%d])!=uint192(%s) {v=0}\n", i, i, mask)
		}
		fmt.Fprintf(&source, "var out [1]uint192\nout[0]=v-g[%d]\nreturn out\n}\n", count)
		return primitiveVCompile(source.String(), 192, count+1, count, 1)
	})
	if err != nil {
		return groupedWord{}, err
	}
	contract := sha256.Sum256([]byte("gee-staged-private-validity-v1"))
	out, err := groupedLMMStagedPrimitive(rw, attempt, role, "gee/"+label, contract, program, words)
	if err != nil {
		return groupedWord{}, err
	}
	return out[0], nil
}

func (p groupedGEEPublicPrograms) sourceValidity(rw io.ReadWriter, attempt crossGridStageAttempt, role exactGCRole, out crossGridStageOutput) (crossGridStageOutput, error) {
	valid, err := p.validity(rw, attempt, role, "global-source-validity", out.Validity)
	if err != nil {
		return crossGridStageOutput{}, err
	}
	for i := range out.Validity {
		out.Validity[i] = byte(valid[0] & 1)
	}
	return out, nil
}
