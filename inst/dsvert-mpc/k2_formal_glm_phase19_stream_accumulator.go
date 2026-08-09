package main

// External-memory execution-validity reduction for the durable schedule.
// Each exact-GC circuit still has the public fan-in bound of 64. Intermediate
// XOR shares are written as fixed-size backend-MACed records, so both circuit
// size and process RAM are independent of TotalBlocks.

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/markkurossi/mpc/circuit"
)

const (
	formalGLMPhase19AccumulatorStateRecordBytes = 4 + 2 + 32
	formalGLMPhase19AccumulatorStateDomain      = "dsVert/formal-glm/phase19/stream-accumulator-state/v1"
)

type formalGLMPhase19AccumulatorCircuitKey struct {
	kind  string
	count int
}

func formalGLMPhase19StreamAccumulatorStateMAC(backendKey [32]byte,
	accumulator formalGLMPhase19AccumulatorPlan, level, index int,
	body []byte) [32]byte {
	message := formalGLMPhase15AppendString(nil,
		formalGLMPhase19AccumulatorStateDomain)
	message = formalGLMPhase15AppendString(message, accumulator.AccumulatorRoot)
	message = formalGLMPhase15AppendUint64(message, uint64(level))
	message = formalGLMPhase15AppendUint64(message, uint64(index))
	message = formalGLMPhase15AppendBytes(message, body)
	return formalGLMPhase19MAC(backendKey,
		formalGLMPhase19AccumulatorStateDomain+"/record", message)
}

func formalGLMPhase19StreamAccumulatorWriteState(file *os.File,
	backendKey [32]byte, accumulator formalGLMPhase19AccumulatorPlan,
	level, index int, state formalGLMPhase19AccumulatorStateShare) error {
	if file == nil || index < 0 || state.valid > 1 || state.active > 1 {
		return fmt.Errorf("formal-glm: invalid streamed accumulator state")
	}
	record := make([]byte, formalGLMPhase19AccumulatorStateRecordBytes)
	binary.BigEndian.PutUint32(record[:4], uint32(index))
	record[4], record[5] = state.valid, state.active
	mac := formalGLMPhase19StreamAccumulatorStateMAC(
		backendKey, accumulator, level, index, record[:6])
	copy(record[6:], mac[:])
	err := exactGCWriteFull(file, record)
	clear(record)
	return err
}

func formalGLMPhase19StreamAccumulatorReadState(file *os.File,
	backendKey [32]byte, accumulator formalGLMPhase19AccumulatorPlan,
	level, index int) (formalGLMPhase19AccumulatorStateShare, error) {
	var zero formalGLMPhase19AccumulatorStateShare
	if file == nil || index < 0 {
		return zero, fmt.Errorf("formal-glm: invalid streamed accumulator read")
	}
	record := make([]byte, formalGLMPhase19AccumulatorStateRecordBytes)
	defer clear(record)
	n, err := file.ReadAt(record,
		int64(index*formalGLMPhase19AccumulatorStateRecordBytes))
	if err != nil && err != io.EOF {
		return zero, err
	}
	if n != len(record) || int(binary.BigEndian.Uint32(record[:4])) != index ||
		record[4] > 1 || record[5] > 1 {
		return zero, fmt.Errorf("formal-glm: invalid streamed accumulator record")
	}
	want := formalGLMPhase19StreamAccumulatorStateMAC(
		backendKey, accumulator, level, index, record[:6])
	if !hmac.Equal(want[:], record[6:]) {
		return zero, fmt.Errorf("formal-glm: streamed accumulator authentication failed")
	}
	return formalGLMPhase19AccumulatorStateShare{
		valid: record[4], active: record[5],
	}, nil
}

func formalGLMPhase19RunBoundedAccumulatorStream(
	rw io.ReadWriter, plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	store *formalGLMPhase19StreamStore, attempt [32]byte,
	role string, backendKey [32]byte) (formalGLMPhase19ExecutionSeal, error) {

	var zero formalGLMPhase19ExecutionSeal
	if rw == nil || store == nil || !store.complete ||
		store.plan.TotalBlocks != plan.TotalBlocks ||
		store.ctx.ContextSHA256ForPhase19() != ctx.ContextSHA256ForPhase19() ||
		(role != "garbler" && role != "evaluator") ||
		!formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: invalid streamed accumulator schedule")
	}
	if err := formalGLMPhase19VerifyAccumulatorPlan(
		ctx, accumulator, backendKey); err != nil {
		return zero, err
	}
	return formalGLMPhase19RunBoundedAccumulatorExternal(
		rw, plan, ctx, accumulator, filepath.Dir(store.path),
		func(index int) (byte, error) {
			block, err := store.ReadMetadata(index)
			return block.ExecutionShare, err
		}, attempt, role, backendKey)
}

func formalGLMPhase19RunBoundedAccumulatorExternal(
	rw io.ReadWriter, plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan, workDir string,
	readShare func(int) (byte, error), attempt [32]byte,
	role string, backendKey [32]byte) (formalGLMPhase19ExecutionSeal, error) {

	var zero formalGLMPhase19ExecutionSeal
	if rw == nil || !filepath.IsAbs(workDir) || filepath.Clean(workDir) != workDir ||
		readShare == nil ||
		(role != "garbler" && role != "evaluator") ||
		!formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: invalid external-memory accumulator")
	}
	info, err := os.Lstat(workDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return zero, fmt.Errorf("formal-glm: unsafe external-memory accumulator directory")
	}
	if err := formalGLMPhase19VerifyAccumulatorPlan(
		ctx, accumulator, backendKey); err != nil {
		return zero, err
	}
	compiled := make(map[formalGLMPhase19AccumulatorCircuitKey]*circuit.Circuit)
	getCircuit := func(kind string, count int) (*circuit.Circuit, error) {
		key := formalGLMPhase19AccumulatorCircuitKey{kind: kind, count: count}
		if value := compiled[key]; value != nil {
			return value, nil
		}
		value, err := compileFormalGLMPhase19BoundedAccumulator(kind, count)
		if err == nil {
			compiled[key] = value
		}
		return value, err
	}
	runState := func(kind string, level, group int, input []byte) (
		formalGLMPhase19AccumulatorStateShare, error) {
		count := len(input)
		if kind == "state" {
			if count < 2 || count%2 != 0 {
				return formalGLMPhase19AccumulatorStateShare{},
					fmt.Errorf("formal-glm: invalid streamed accumulator state input")
			}
			count /= 2
		}
		circ, err := getCircuit(kind, count)
		if err != nil {
			return formalGLMPhase19AccumulatorStateShare{}, err
		}
		session, err := formalGLMPhase19BoundedAccumulatorSession(
			plan, ctx, accumulator, attempt, kind, level, group, count,
			backendKey)
		if err != nil {
			return formalGLMPhase19AccumulatorStateShare{}, err
		}
		values := make([]*big.Int, 0, len(input)+2)
		for _, value := range input {
			values = append(values, new(big.Int).SetUint64(uint64(value)))
		}
		if role == "garbler" {
			validMask, maskErr := formalGLMPhase19RandomExecutionMask()
			if maskErr != nil {
				exactGCZeroBigInts(values)
				return formalGLMPhase19AccumulatorStateShare{}, maskErr
			}
			activeMask, maskErr := formalGLMPhase19RandomExecutionMask()
			if maskErr != nil {
				exactGCZeroBigInts(values)
				return formalGLMPhase19AccumulatorStateShare{}, maskErr
			}
			values = append(values,
				new(big.Int).SetUint64(uint64(validMask)),
				new(big.Int).SetUint64(uint64(activeMask)))
			if _, err := formalGLMPhase19BoundedAccumulatorRunCircuit(
				rw, role, circ, session, values); err != nil {
				return formalGLMPhase19AccumulatorStateShare{}, err
			}
			return formalGLMPhase19AccumulatorStateShare{
				valid: validMask, active: activeMask,
			}, nil
		}
		packed, err := formalGLMPhase19BoundedAccumulatorRunCircuit(
			rw, role, circ, session, values)
		if err != nil {
			return formalGLMPhase19AccumulatorStateShare{}, err
		}
		return formalGLMPhase19BoundedAccumulatorDecodeState(packed)
	}

	paths := make([]string, 0, 4)
	defer func() {
		for _, path := range paths {
			_ = os.Remove(path)
		}
	}()
	newLevel := func(level int) (*os.File, string, error) {
		path := filepath.Join(workDir,
			fmt.Sprintf("formal-phase19-acc-level-%03d.bin", level))
		file, err := os.OpenFile(path,
			os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			paths = append(paths, path)
		}
		return file, path, err
	}

	current, currentPath, err := newLevel(0)
	if err != nil {
		return zero, err
	}
	stateCount := 0
	for start, group := 0, 0; start < plan.TotalBlocks; group++ {
		end := start + formalGLMPhase19AccumulatorMaxFanIn
		if end > plan.TotalBlocks {
			end = plan.TotalBlocks
		}
		shares := make([]byte, end-start)
		for index := start; index < end; index++ {
			share, readErr := readShare(index)
			if readErr != nil {
				_ = current.Close()
				return zero, readErr
			}
			if share > 1 {
				_ = current.Close()
				return zero, fmt.Errorf(
					"formal-glm: external accumulator source is not a bit share")
			}
			shares[index-start] = share
		}
		state, runErr := runState("leaf", 0, group, shares)
		clear(shares)
		if runErr != nil {
			_ = current.Close()
			return zero, runErr
		}
		if err := formalGLMPhase19StreamAccumulatorWriteState(
			current, backendKey, accumulator, 0, stateCount, state); err != nil {
			_ = current.Close()
			return zero, err
		}
		stateCount++
		start = end
	}
	if err := current.Sync(); err != nil {
		_ = current.Close()
		return zero, err
	}
	if err := current.Close(); err != nil {
		return zero, err
	}

	level := 1
	for stateCount > 1 {
		input, err := os.Open(currentPath)
		if err != nil {
			return zero, err
		}
		next, nextPath, err := newLevel(level)
		if err != nil {
			_ = input.Close()
			return zero, err
		}
		nextCount := 0
		for start, group := 0, 0; start < stateCount; group++ {
			end := start + formalGLMPhase19AccumulatorMaxFanIn
			if end > stateCount {
				end = stateCount
			}
			encoded := make([]byte, 0, 2*(end-start))
			for index := start; index < end; index++ {
				state, readErr := formalGLMPhase19StreamAccumulatorReadState(
					input, backendKey, accumulator, level-1, index)
				if readErr != nil {
					clear(encoded)
					_ = input.Close()
					_ = next.Close()
					return zero, readErr
				}
				encoded = append(encoded, state.valid, state.active)
			}
			state, runErr := runState("state", level, group, encoded)
			clear(encoded)
			if runErr != nil {
				_ = input.Close()
				_ = next.Close()
				return zero, runErr
			}
			if err := formalGLMPhase19StreamAccumulatorWriteState(
				next, backendKey, accumulator, level, nextCount, state); err != nil {
				_ = input.Close()
				_ = next.Close()
				return zero, err
			}
			nextCount++
			start = end
		}
		if err := input.Close(); err != nil {
			_ = next.Close()
			return zero, err
		}
		if err := next.Sync(); err != nil {
			_ = next.Close()
			return zero, err
		}
		if err := next.Close(); err != nil {
			return zero, err
		}
		if err := os.Remove(currentPath); err != nil {
			return zero, err
		}
		currentPath, stateCount = nextPath, nextCount
		level++
	}
	finalFile, err := os.Open(currentPath)
	if err != nil {
		return zero, err
	}
	state, err := formalGLMPhase19StreamAccumulatorReadState(
		finalFile, backendKey, accumulator, level-1, 0)
	closeErr := finalFile.Close()
	if err != nil {
		return zero, err
	}
	if closeErr != nil {
		return zero, closeErr
	}

	finalCircuit, err := getCircuit("final", 1)
	if err != nil {
		return zero, err
	}
	finalSession, err := formalGLMPhase19BoundedAccumulatorSession(
		plan, ctx, accumulator, attempt, "final", 0, 0, 1, backendKey)
	if err != nil {
		return zero, err
	}
	values := []*big.Int{
		new(big.Int).SetUint64(uint64(state.valid)),
		new(big.Int).SetUint64(uint64(state.active)),
	}
	var share byte
	if role == "garbler" {
		share, err = formalGLMPhase19RandomExecutionMask()
		if err != nil {
			exactGCZeroBigInts(values)
			return zero, err
		}
		values = append(values, new(big.Int).SetUint64(uint64(share)))
		_, err = formalGLMPhase19BoundedAccumulatorRunCircuit(
			rw, role, finalCircuit, finalSession, values)
	} else {
		var packed *big.Int
		packed, err = formalGLMPhase19BoundedAccumulatorRunCircuit(
			rw, role, finalCircuit, finalSession, values)
		if err == nil && (packed == nil || packed.Sign() < 0 ||
			packed.Cmp(big.NewInt(1)) > 0) {
			err = fmt.Errorf(
				"formal-glm: streamed accumulator emitted invalid execution share")
		}
		if err == nil {
			share = byte(packed.Uint64())
		}
	}
	if err != nil {
		return zero, err
	}
	peer := ctx.ComputePeers[0]
	if role == "evaluator" {
		peer = ctx.ComputePeers[1]
	}
	return formalGLMPhase19BuildExecutionSeal(
		ctx, accumulator, finalSession, peer, share, backendKey)
}
