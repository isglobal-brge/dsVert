package main

// Durable, private checkpointing for the bounded formal-Cox schedule.
//
// The checkpoint stores only one compute peer's sealed shares. A completed
// exact-GC step is committed only after both pinned compute peers sign the
// same purpose-bound barrier. Interrupted GC is never resumed mid-transcript:
// an unrecorded pending attempt may only be replaced by a fresh attempt for
// the exact same schedule step. This file registers no command, capability or
// remote method and deliberately leaves ProductionReady false.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/p2p"
)

const (
	formalCoxBlockwiseCheckpointVersion = "dsvert-formal-cox-blockwise-checkpoint-v1"
	formalCoxBlockwiseReceiptVersion    = "dsvert-formal-cox-blockwise-step-receipt-v1"
	formalCoxBlockwiseCompletionVersion = "dsvert-formal-cox-blockwise-completion-v1"
	formalCoxBlockwiseCheckpointMax     = 1 << 20
	formalCoxBlockwiseCompletionMax     = 8 << 10
	formalCoxBlockwiseCompletionNext    = ".next"

	formalCoxBlockwiseStepBlock             = "block"
	formalCoxBlockwiseStepGrid              = "grid_coefficient"
	formalCoxBlockwiseStepUpdate            = "coefficient_update"
	formalCoxBlockwiseStepProjection        = "coefficient_projection"
	formalCoxBlockwiseStepInformationBlock  = "information_block"
	formalCoxBlockwiseStepInformationMoment = "observed_information_moment"
	formalCoxBlockwiseStepInformation       = "observed_information"
)

type formalCoxBlockwiseWorkerStep struct {
	ScheduleIndex   int    `json:"schedule_index"`
	Iteration       int    `json:"iteration"`
	Kind            string `json:"kind"`
	BlockIndex      int    `json:"block_index"`
	GridIndex       int    `json:"grid_index"`
	Coefficient     int    `json:"coefficient"`
	InformationPart int    `json:"information_part"`
	InputRoot       string `json:"input_root,omitempty"`
}

type formalCoxBlockwiseStepOutput struct {
	ArithmeticShares []*big.Int
	ValidityShare    bool
}

type formalCoxBlockwisePendingState struct {
	Step             formalCoxBlockwiseWorkerStep `json:"step"`
	AttemptID        string                       `json:"attempt_id"`
	StepPurpose      string                       `json:"step_purpose"`
	TranscriptSHA256 string                       `json:"transcript_sha256"`
	OutputRecorded   bool                         `json:"output_recorded"`
	Output           []string                     `json:"output"`
	ValidityShare    bool                         `json:"validity_share"`
	NextStateSHA256  string                       `json:"next_state_sha256"`
}

type formalCoxBlockwiseCheckpoint struct {
	Version            string                          `json:"version"`
	PlanSHA256         string                          `json:"plan_sha256"`
	Peer               string                          `json:"peer"`
	Generation         uint64                          `json:"generation"`
	NextStep           int                             `json:"next_step"`
	State              []string                        `json:"state"`
	Scores             []string                        `json:"scores"`
	Candidate          []string                        `json:"candidate"`
	Projected          []string                        `json:"projected"`
	Information        []string                        `json:"information"`
	InformationScratch []string                        `json:"information_scratch"`
	TranscriptSHA256   string                          `json:"transcript_sha256"`
	Pending            *formalCoxBlockwisePendingState `json:"pending,omitempty"`
	LastReceipt        *formalCoxBlockwiseStepReceipt  `json:"last_receipt,omitempty"`
	FinalCommitSHA256  string                          `json:"final_commit_sha256,omitempty"`
	PreviousMAC        string                          `json:"previous_mac"`
	MAC                string                          `json:"mac"`
}

type formalCoxBlockwiseStepReceipt struct {
	Version          string                       `json:"version"`
	PlanSHA256       string                       `json:"plan_sha256"`
	Peer             string                       `json:"peer"`
	Step             formalCoxBlockwiseWorkerStep `json:"step"`
	AttemptID        string                       `json:"attempt_id"`
	StateSHA256      string                       `json:"state_sha256"`
	TranscriptSHA256 string                       `json:"transcript_sha256"`
	Signature        []byte                       `json:"signature"`
}

type formalCoxBlockwiseCompletion struct {
	Version               string `json:"version"`
	PlanSHA256            string `json:"plan_sha256"`
	TranscriptSHA256      string `json:"transcript_sha256"`
	FinalCommitSHA256     string `json:"final_commit_sha256"`
	ScheduleSteps         int    `json:"schedule_steps"`
	FixedScheduleComplete bool   `json:"fixed_schedule_complete"`
	OutputKind            string `json:"output_kind"`
	ProductionReady       bool   `json:"production_ready"`
	CompletionSHA256      string `json:"completion_sha256"`
}

type formalCoxBlockwiseCheckpointStore struct {
	mu             sync.Mutex
	runMu          sync.Mutex
	path           string
	completionPath string
	key            [32]byte
	plan           formalCoxBlockwisePlan
	peer           string
}

// Serializes compare-and-swap inside one worker process, including distinct
// store handles reopened after a retry. The expected-MAC check still detects
// stale writers; atomic replace prevents torn checkpoints.
var formalCoxBlockwiseCheckpointCAS sync.Mutex

func formalCoxBlockwiseAppendString(dst []byte, value string) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func formalCoxBlockwiseAppendUint64(dst []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(dst, encoded[:]...)
}

func formalCoxBlockwisePlanSHA256(plan formalCoxBlockwisePlan) (string, error) {
	digest, err := formalCoxBlockwisePlanDigest(plan)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseWorkerStepsPerIteration(plan formalCoxBlockwisePlan) int {
	return plan.TotalBlocks + plan.Policy.GridTickCount*plan.Policy.CovariateCount +
		1 + plan.Policy.CovariateCount
}

func formalCoxBlockwiseWorkerStepAt(plan formalCoxBlockwisePlan,
	index int) (formalCoxBlockwiseWorkerStep, error) {
	var zero formalCoxBlockwiseWorkerStep
	if _, err := formalCoxBlockwiseValidateShape(plan); err != nil {
		return zero, err
	}
	if index < 0 || index >= plan.ScheduleSteps {
		return zero, fmt.Errorf("formal-cox: invalid blockwise worker step index")
	}
	perIteration := formalCoxBlockwiseWorkerStepsPerIteration(plan)
	normalSteps := plan.Iterations * perIteration
	if index >= normalSteps {
		within := index - normalSteps
		step := formalCoxBlockwiseWorkerStep{
			ScheduleIndex: index, Iteration: plan.Iterations,
			BlockIndex: -1, GridIndex: -1, Coefficient: -1, InformationPart: -1,
		}
		if within < plan.TotalBlocks {
			step.Kind, step.BlockIndex = formalCoxBlockwiseStepInformationBlock, within
			return step, nil
		}
		within -= plan.TotalBlocks
		information := formalCoxBlockwiseInformationCoordinates(plan.Policy)
		if within < 4*plan.Policy.GridTickCount*information {
			step.GridIndex = within / (4 * information)
			part := (within / information) % 4
			step.Coefficient = within % information
			if part < 3 {
				step.Kind, step.InformationPart = formalCoxBlockwiseStepInformationMoment, part
			} else {
				step.Kind = formalCoxBlockwiseStepInformation
			}
			return step, nil
		}
		return zero, fmt.Errorf("formal-cox: invalid observed-information step")
	}
	step := formalCoxBlockwiseWorkerStep{
		ScheduleIndex: index, Iteration: index / perIteration,
		BlockIndex: -1, GridIndex: -1, Coefficient: -1, InformationPart: -1,
	}
	within := index % perIteration
	if within < plan.TotalBlocks {
		step.Kind, step.BlockIndex = formalCoxBlockwiseStepBlock, within
		return step, nil
	}
	within -= plan.TotalBlocks
	gridSteps := plan.Policy.GridTickCount * plan.Policy.CovariateCount
	if within < gridSteps {
		step.Kind = formalCoxBlockwiseStepGrid
		step.GridIndex = within / plan.Policy.CovariateCount
		step.Coefficient = within % plan.Policy.CovariateCount
		return step, nil
	}
	within -= gridSteps
	if within == 0 {
		step.Kind = formalCoxBlockwiseStepUpdate
		return step, nil
	}
	step.Kind = formalCoxBlockwiseStepProjection
	step.Coefficient = within - 1
	if step.Coefficient < 0 || step.Coefficient >= plan.Policy.CovariateCount {
		return zero, fmt.Errorf("formal-cox: invalid blockwise worker projection step")
	}
	return step, nil
}

func formalCoxBlockwiseWorkerStepNeedsInput(step formalCoxBlockwiseWorkerStep) bool {
	return step.Kind == formalCoxBlockwiseStepBlock ||
		step.Kind == formalCoxBlockwiseStepUpdate ||
		step.Kind == formalCoxBlockwiseStepInformationBlock
}

func formalCoxBlockwiseValidateWorkerStep(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep) error {
	want, err := formalCoxBlockwiseWorkerStepAt(plan, step.ScheduleIndex)
	if err != nil {
		return err
	}
	inputRoot := step.InputRoot
	step.InputRoot = ""
	if step != want {
		return fmt.Errorf("formal-cox: reordered or skipped blockwise worker step")
	}
	if formalCoxBlockwiseWorkerStepNeedsInput(want) {
		if !formalCoxIsSHA256(inputRoot) {
			return fmt.Errorf("formal-cox: blockwise worker input is missing its authenticated root")
		}
	} else if inputRoot != "" {
		return fmt.Errorf("formal-cox: internal blockwise step cannot bind an external input")
	}
	return nil
}

func formalCoxBlockwiseWorkerOutputCoordinates(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep) int {
	switch step.Kind {
	case formalCoxBlockwiseStepBlock, formalCoxBlockwiseStepInformationBlock:
		return plan.StateArithmetic
	case formalCoxBlockwiseStepGrid, formalCoxBlockwiseStepProjection,
		formalCoxBlockwiseStepInformationMoment, formalCoxBlockwiseStepInformation:
		return 1
	case formalCoxBlockwiseStepUpdate:
		return plan.Policy.CovariateCount
	default:
		return 0
	}
}

func formalCoxBlockwiseWorkerInputCoordinates(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep) int {
	p := plan.Policy.CovariateCount
	switch step.Kind {
	case formalCoxBlockwiseStepBlock, formalCoxBlockwiseStepInformationBlock:
		return plan.BlockCapacity*plan.RowWidth + plan.StateCoordinates
	case formalCoxBlockwiseStepGrid:
		return 7
	case formalCoxBlockwiseStepUpdate:
		return 3*p + 2
	case formalCoxBlockwiseStepProjection:
		return p + 1
	case formalCoxBlockwiseStepInformationMoment:
		return 5
	case formalCoxBlockwiseStepInformation:
		return 6
	default:
		return 0
	}
}

func formalCoxBlockwiseWorkerResidentCoordinates(plan formalCoxBlockwisePlan) int {
	checkpoint := plan.StateCoordinates + 3*plan.Policy.CovariateCount +
		4*formalCoxBlockwiseInformationCoordinates(plan.Policy)
	peakStep := 0
	for _, index := range []int{
		0,
		plan.TotalBlocks,
		plan.TotalBlocks + plan.Policy.GridTickCount*plan.Policy.CovariateCount,
		plan.TotalBlocks + plan.Policy.GridTickCount*plan.Policy.CovariateCount + 1,
		plan.Iterations*formalCoxBlockwiseWorkerStepsPerIteration(plan) + plan.TotalBlocks,
		plan.ScheduleSteps - 1,
	} {
		step, err := formalCoxBlockwiseWorkerStepAt(plan, index)
		if err != nil {
			continue
		}
		resident := formalCoxBlockwiseWorkerInputCoordinates(plan, step) +
			formalCoxBlockwiseWorkerOutputCoordinates(plan, step) + 1
		if resident > peakStep {
			peakStep = resident
		}
	}
	return checkpoint + peakStep
}

func formalCoxBlockwiseWorkerStepPurpose(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep, attempt [32]byte) (string, error) {
	if bytes.Equal(attempt[:], make([]byte, len(attempt))) ||
		formalCoxBlockwiseValidateWorkerStep(plan, step) != nil {
		return "", fmt.Errorf("formal-cox: invalid blockwise worker attempt")
	}
	planSHA, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"formal-cox/blockwise-worker/v1/%s/step/%d/iteration/%d/%s/block/%d/grid/%d/coefficient/%d/input/%s/attempt/%s",
		planSHA, step.ScheduleIndex, step.Iteration, step.Kind, step.BlockIndex,
		step.GridIndex, step.Coefficient, step.InputRoot,
		hex.EncodeToString(attempt[:])), nil
}

func formalCoxBlockwiseWorkerSession(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep, attempt, master [32]byte) (
	exactGCSession, error) {
	if err := validateFormalCoxBlockwisePlan(plan); err != nil {
		return exactGCSession{}, err
	}
	purpose, err := formalCoxBlockwiseWorkerStepPurpose(plan, step, attempt)
	if err != nil {
		return exactGCSession{}, err
	}
	session := exactGCSession{
		SessionID: attempt, MasterKey: master,
		GarblerID:   plan.Policy.ComputePeers[0],
		EvaluatorID: plan.Policy.ComputePeers[1], Purpose: purpose,
		Spec: exactGCCircuitSpec{
			Operation: exactGCFormalCoxIterations, RingBits: plan.RingBits,
			FracBits:  plan.Policy.FracBits,
			VectorLen: formalCoxBlockwiseWorkerInputCoordinates(plan, step),
		},
	}
	if err := session.validate(); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func formalCoxBlockwiseValidateWorkerSession(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep, session exactGCSession) error {
	want, err := formalCoxBlockwiseWorkerSession(
		plan, step, session.SessionID, session.MasterKey)
	if err != nil {
		return err
	}
	if session.GarblerID != want.GarblerID ||
		session.EvaluatorID != want.EvaluatorID || session.Purpose != want.Purpose ||
		session.Spec.Operation != want.Spec.Operation ||
		session.Spec.RingBits != want.Spec.RingBits ||
		session.Spec.FracBits != want.Spec.FracBits ||
		session.Spec.VectorLen != want.Spec.VectorLen {
		return fmt.Errorf("formal-cox: blockwise step/session binding mismatch")
	}
	return nil
}

func formalCoxBlockwiseCompileWorkerStep(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep) (*circuit.Circuit, error) {
	switch step.Kind {
	case formalCoxBlockwiseStepBlock, formalCoxBlockwiseStepInformationBlock:
		return compileFormalCoxBlockwiseBlock(plan)
	case formalCoxBlockwiseStepGrid:
		return compileFormalCoxBlockwiseGridCoefficient(plan)
	case formalCoxBlockwiseStepUpdate:
		return compileFormalCoxBlockwiseUpdate(plan)
	case formalCoxBlockwiseStepProjection:
		return compileFormalCoxBlockwiseProjectionCoefficient(
			plan, step.Coefficient)
	case formalCoxBlockwiseStepInformation:
		return compileFormalCoxBlockwiseInformation(plan)
	case formalCoxBlockwiseStepInformationMoment:
		return compileFormalCoxBlockwiseInformationMoment(plan)
	default:
		return nil, fmt.Errorf("formal-cox: unsupported blockwise worker circuit")
	}
}

func formalCoxBlockwiseWorkerLocalInput(plan formalCoxBlockwisePlan,
	state formalCoxBlockwiseCheckpoint, step formalCoxBlockwiseWorkerStep,
	external []*big.Int, externalValidity *bool) ([]*big.Int, error) {
	if formalCoxBlockwiseValidateWorkerStep(plan, step) != nil ||
		step.ScheduleIndex != state.NextStep {
		return nil, fmt.Errorf("formal-cox: local input does not match the pending step")
	}
	stateValues, err := formalCoxBlockwiseDecodeValues(
		state.State, plan.StateCoordinates, plan.RingBits)
	if err != nil {
		return nil, err
	}
	scores, err := formalCoxBlockwiseDecodeValues(
		state.Scores, plan.Policy.CovariateCount, plan.RingBits)
	if err != nil {
		return nil, err
	}
	candidate, err := formalCoxBlockwiseDecodeValues(
		state.Candidate, plan.Policy.CovariateCount, plan.RingBits)
	if err != nil {
		return nil, err
	}
	information, err := formalCoxBlockwiseDecodeValues(
		state.Information, formalCoxBlockwiseInformationCoordinates(plan.Policy),
		plan.RingBits)
	if err != nil {
		return nil, err
	}
	scratch, err := formalCoxBlockwiseDecodeValues(state.InformationScratch,
		3*formalCoxBlockwiseInformationCoordinates(plan.Policy), plan.RingBits)
	if err != nil {
		return nil, err
	}
	p := plan.Policy.CovariateCount
	validity := stateValues[plan.StateArithmetic]
	var input []*big.Int
	switch step.Kind {
	case formalCoxBlockwiseStepBlock, formalCoxBlockwiseStepInformationBlock:
		if len(external) != plan.BlockCapacity*plan.RowWidth ||
			externalValidity != nil {
			return nil, fmt.Errorf("formal-cox: pending block is missing its fixed padded input")
		}
		input = append(input, external...)
		input = append(input, stateValues...)
	case formalCoxBlockwiseStepGrid:
		if len(external) != 0 || externalValidity != nil {
			return nil, fmt.Errorf("formal-cox: grid reduction received external input")
		}
		offsets := formalCoxBlockwiseStateOffsets(plan.Policy)
		grid, coefficient := step.GridIndex, step.Coefficient
		input = []*big.Int{
			stateValues[offsets.riskCount+grid],
			stateValues[offsets.eventCount+grid],
			stateValues[offsets.s0+grid],
			stateValues[offsets.s1+grid*p+coefficient],
			stateValues[offsets.eventX+grid*p+coefficient],
			scores[coefficient], validity,
		}
	case formalCoxBlockwiseStepUpdate:
		if len(external) != p || externalValidity == nil {
			return nil, fmt.Errorf("formal-cox: coefficient update is missing its sealed noise slice")
		}
		input = append(input, stateValues[:p]...)
		input = append(input, scores...)
		input = append(input, external...)
		input = append(input, validity)
		if *externalValidity {
			input = append(input, big.NewInt(1))
		} else {
			input = append(input, new(big.Int))
		}
	case formalCoxBlockwiseStepProjection:
		if len(external) != 0 || externalValidity != nil {
			return nil, fmt.Errorf("formal-cox: coefficient projection received external input")
		}
		input = append(input, candidate...)
		input = append(input, validity)
	case formalCoxBlockwiseStepInformationMoment:
		if len(external) != 0 || externalValidity != nil {
			return nil, fmt.Errorf("formal-cox: observed information moment received external input")
		}
		left, right, err := formalCoxBlockwiseSecondMomentPairAt(
			plan.Policy, step.Coefficient)
		if err != nil {
			return nil, err
		}
		offsets := formalCoxBlockwiseStateOffsets(plan.Policy)
		grid := step.GridIndex
		moment := stateValues[offsets.s1+grid*p+left]
		switch step.InformationPart {
		case 0:
		case 1:
			moment = stateValues[offsets.s1+grid*p+right]
		case 2:
			moment = stateValues[offsets.s2+grid*formalCoxBlockwiseInformationCoordinates(plan.Policy)+step.Coefficient]
		default:
			return nil, fmt.Errorf("formal-cox: invalid observed-information moment part")
		}
		input = []*big.Int{
			stateValues[offsets.riskCount+grid],
			stateValues[offsets.eventCount+grid],
			stateValues[offsets.s0+grid],
			moment, validity,
		}
	case formalCoxBlockwiseStepInformation:
		if len(external) != 0 || externalValidity != nil {
			return nil, fmt.Errorf("formal-cox: observed information received external input")
		}
		width := formalCoxBlockwiseInformationCoordinates(plan.Policy)
		input = []*big.Int{
			stateValues[formalCoxBlockwiseStateOffsets(plan.Policy).eventCount+step.GridIndex],
			scratch[step.Coefficient], scratch[width+step.Coefficient],
			scratch[2*width+step.Coefficient],
			information[step.Coefficient], validity,
		}
	default:
		return nil, fmt.Errorf("formal-cox: unsupported blockwise worker input")
	}
	if len(input) != formalCoxBlockwiseWorkerInputCoordinates(plan, step) {
		return nil, fmt.Errorf("formal-cox: blockwise worker input shape mismatch")
	}
	return input, nil
}

func formalCoxBlockwiseRunGarbler(rw io.ReadWriter,
	plan formalCoxBlockwisePlan, step formalCoxBlockwiseWorkerStep,
	session exactGCSession, local []*big.Int) (formalCoxBlockwiseStepOutput, error) {
	var zero formalCoxBlockwiseStepOutput
	if rw == nil || formalCoxBlockwiseValidateWorkerSession(
		plan, step, session) != nil || exactGCValidateShares(local, session.Spec) != nil {
		return zero, fmt.Errorf("formal-cox: invalid garbler blockwise worker input")
	}
	count := formalCoxBlockwiseWorkerOutputCoordinates(plan, step)
	masks, validity, err := formalCoxRandomOutputMasks(count, plan.RingBits)
	if err != nil {
		return zero, err
	}
	circ, err := formalCoxBlockwiseCompileWorkerStep(plan, step)
	if err != nil {
		exactGCZeroBigInts(masks)
		return zero, err
	}
	packed := append(append([]*big.Int{}, local...), masks...)
	if validity {
		packed = append(packed, big.NewInt(1))
	} else {
		packed = append(packed, new(big.Int))
	}
	input := exactGCPackChunks(packed, plan.ContainerBits)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		exactGCZeroBigInts(masks)
		return zero, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		exactGCZeroBigInts(masks)
		return zero, err
	}
	return formalCoxBlockwiseStepOutput{
		ArithmeticShares: masks, ValidityShare: validity,
	}, nil
}

func formalCoxBlockwiseRunEvaluator(rw io.ReadWriter,
	plan formalCoxBlockwisePlan, step formalCoxBlockwiseWorkerStep,
	session exactGCSession, local []*big.Int) (formalCoxBlockwiseStepOutput, error) {
	var zero formalCoxBlockwiseStepOutput
	if rw == nil || formalCoxBlockwiseValidateWorkerSession(
		plan, step, session) != nil || exactGCValidateShares(local, session.Spec) != nil {
		return zero, fmt.Errorf("formal-cox: invalid evaluator blockwise worker input")
	}
	circ, err := formalCoxBlockwiseCompileWorkerStep(plan, step)
	if err != nil {
		return zero, err
	}
	input := exactGCPackChunks(local, plan.ContainerBits)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return zero, err
	}
	conn := p2p.NewConn(secure)
	packed, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return zero, err
	}
	count := formalCoxBlockwiseWorkerOutputCoordinates(plan, step)
	outputs := make([]*big.Int, count+1)
	for index := range outputs {
		outputs[index] = new(big.Int).Rsh(
			new(big.Int).Set(packed), uint(index*plan.ContainerBits))
		outputs[index].And(outputs[index], exactGCMask(plan.RingBits))
	}
	return formalCoxBlockwiseStepOutput{
		ArithmeticShares: outputs[:count],
		ValidityShare:    outputs[count].Bit(0) == 1,
	}, nil
}

func formalCoxBlockwiseInitialTranscript(planSHA string) string {
	message := formalCoxBlockwiseAppendString(nil,
		"dsVert/formal-cox/blockwise-worker/transcript/v1")
	message = formalCoxBlockwiseAppendString(message, planSHA)
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:])
}

func formalCoxBlockwiseAdvanceTranscript(current string, stepIndex int,
	purpose string) (string, error) {
	if !formalCoxIsSHA256(current) || stepIndex < 0 ||
		exactGCValidateLabel("formal Cox blockwise purpose", purpose, 512) != nil {
		return "", fmt.Errorf("formal-cox: invalid blockwise execution transcript")
	}
	message := formalCoxBlockwiseAppendString(nil,
		"dsVert/formal-cox/blockwise-worker/transcript/v1")
	message = formalCoxBlockwiseAppendString(message, current)
	message = formalCoxBlockwiseAppendUint64(message, uint64(stepIndex))
	message = formalCoxBlockwiseAppendString(message, purpose)
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseEncodeValues(values []*big.Int, ringBits int) (
	[]string, error) {
	modulus := exactGCModulus(ringBits)
	result := make([]string, len(values))
	for index, value := range values {
		if value == nil || value.Sign() < 0 || value.Cmp(modulus) >= 0 {
			return nil, fmt.Errorf("formal-cox: invalid blockwise checkpoint residue")
		}
		result[index] = value.Text(16)
	}
	return result, nil
}

func formalCoxBlockwiseDecodeValues(values []string, count, ringBits int) (
	[]*big.Int, error) {
	if len(values) != count {
		return nil, fmt.Errorf("formal-cox: invalid blockwise checkpoint shape")
	}
	result := make([]*big.Int, count)
	for index, value := range values {
		if value == "" || len(value) > 1 && value[0] == '0' {
			return nil, fmt.Errorf("formal-cox: non-canonical checkpoint residue")
		}
		result[index] = new(big.Int)
		if _, ok := result[index].SetString(value, 16); !ok ||
			result[index].Text(16) != value || result[index].Sign() < 0 ||
			result[index].BitLen() > ringBits {
			return nil, fmt.Errorf("formal-cox: invalid checkpoint residue encoding")
		}
	}
	return result, nil
}

func formalCoxBlockwiseZeroStrings(count int) []string {
	result := make([]string, count)
	for index := range result {
		result[index] = "0"
	}
	return result
}

func formalCoxBlockwiseCloneCheckpoint(state formalCoxBlockwiseCheckpoint) formalCoxBlockwiseCheckpoint {
	state.State = append([]string(nil), state.State...)
	state.Scores = append([]string(nil), state.Scores...)
	state.Candidate = append([]string(nil), state.Candidate...)
	state.Projected = append([]string(nil), state.Projected...)
	state.Information = append([]string(nil), state.Information...)
	state.InformationScratch = append([]string(nil), state.InformationScratch...)
	return state
}

func formalCoxBlockwisePrivateStateSHA256(state formalCoxBlockwiseCheckpoint) string {
	message := formalCoxBlockwiseAppendString(nil,
		"dsVert/formal-cox/blockwise-worker/private-state/v1")
	for _, values := range [][]string{
		state.State, state.Scores, state.Candidate, state.Projected,
		state.Information, state.InformationScratch,
	} {
		message = formalCoxBlockwiseAppendUint64(message, uint64(len(values)))
		for _, value := range values {
			message = formalCoxBlockwiseAppendString(message, value)
		}
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:])
}

func formalCoxBlockwiseApplyOutput(plan formalCoxBlockwisePlan,
	state *formalCoxBlockwiseCheckpoint, step formalCoxBlockwiseWorkerStep,
	output []string, validity bool) error {
	if state == nil || formalCoxBlockwiseValidateWorkerStep(plan, step) != nil ||
		len(output) != formalCoxBlockwiseWorkerOutputCoordinates(plan, step) {
		return fmt.Errorf("formal-cox: invalid blockwise pending output")
	}
	if _, err := formalCoxBlockwiseDecodeValues(
		output, len(output), plan.RingBits); err != nil {
		return err
	}
	validityValue := "0"
	if validity {
		validityValue = "1"
	}
	p := plan.Policy.CovariateCount
	validityIndex := plan.StateArithmetic
	switch step.Kind {
	case formalCoxBlockwiseStepBlock, formalCoxBlockwiseStepInformationBlock:
		state.State = append(append([]string(nil), output...), validityValue)
	case formalCoxBlockwiseStepGrid:
		state.Scores[step.Coefficient] = output[0]
		state.State[validityIndex] = validityValue
	case formalCoxBlockwiseStepUpdate:
		state.Candidate = append([]string(nil), output...)
		state.Projected = formalCoxBlockwiseZeroStrings(p)
		state.State[validityIndex] = validityValue
	case formalCoxBlockwiseStepProjection:
		state.Projected[step.Coefficient] = output[0]
		state.State[validityIndex] = validityValue
		if step.Coefficient == p-1 {
			next := formalCoxBlockwiseZeroStrings(plan.StateCoordinates)
			copy(next[:p], state.Projected)
			next[validityIndex] = validityValue
			state.State = next
			state.Scores = formalCoxBlockwiseZeroStrings(p)
			state.Candidate = formalCoxBlockwiseZeroStrings(p)
			state.Projected = formalCoxBlockwiseZeroStrings(p)
		}
	case formalCoxBlockwiseStepInformationMoment:
		width := formalCoxBlockwiseInformationCoordinates(plan.Policy)
		state.InformationScratch[step.InformationPart*width+step.Coefficient] = output[0]
		state.State[validityIndex] = validityValue
	case formalCoxBlockwiseStepInformation:
		state.Information[step.Coefficient] = output[0]
		state.State[validityIndex] = validityValue
	default:
		return fmt.Errorf("formal-cox: unsupported blockwise checkpoint step")
	}
	return nil
}

func formalCoxBlockwiseCheckpointUnsigned(state formalCoxBlockwiseCheckpoint) (
	[]byte, error) {
	state.MAC = ""
	return json.Marshal(state)
}

func formalCoxBlockwiseCheckpointMAC(key [32]byte,
	state formalCoxBlockwiseCheckpoint) (string, error) {
	encoded, err := formalCoxBlockwiseCheckpointUnsigned(state)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("dsVert/formal-cox/blockwise-worker/checkpoint-mac/v1|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalCoxBlockwisePinsetSHA256(pins map[string]ed25519.PublicKey) (
	string, error) {
	if len(pins) < 2 {
		return "", fmt.Errorf("formal-cox: incomplete pinned consortium")
	}
	canonical := make(map[string]string, len(pins))
	seen := make(map[string]bool, len(pins))
	for name, pin := range pins {
		if exactGCValidateLabel("formal Cox pinned peer", name, 128) != nil ||
			len(pin) != ed25519.PublicKeySize {
			return "", fmt.Errorf("formal-cox: invalid pinned consortium")
		}
		encoded := base64.RawURLEncoding.EncodeToString(pin)
		if seen[encoded] {
			return "", fmt.Errorf("formal-cox: duplicate pinned identity")
		}
		seen[encoded] = true
		canonical[name] = encoded
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseReceiptUnsigned(receipt formalCoxBlockwiseStepReceipt) (
	[]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte("dsVert/formal-cox/blockwise-worker/step-receipt/v1|"),
		encoded...), nil
}

func formalCoxBlockwiseReceiptEqual(left, right formalCoxBlockwiseStepReceipt) bool {
	leftSignature := left.Signature
	rightSignature := right.Signature
	left.Signature, right.Signature = nil, nil
	leftEncoded, leftErr := json.Marshal(left)
	rightEncoded, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil &&
		bytes.Equal(leftEncoded, rightEncoded) &&
		bytes.Equal(leftSignature, rightSignature)
}

func formalCoxBlockwiseFinalCommitSHA256(
	receipts []formalCoxBlockwiseStepReceipt) (string, error) {
	if len(receipts) != 2 {
		return "", fmt.Errorf("formal-cox: incomplete final commit barrier")
	}
	ordered := append([]formalCoxBlockwiseStepReceipt(nil), receipts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Peer < ordered[j].Peer })
	encoded, err := json.Marshal(ordered)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte("dsVert/formal-cox/blockwise-worker/final-commit/v1|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseValidateReceiptPair(plan formalCoxBlockwisePlan,
	receipts []formalCoxBlockwiseStepReceipt,
	pins map[string]ed25519.PublicKey) error {
	if err := validateFormalCoxBlockwisePlan(plan); err != nil {
		return err
	}
	if len(receipts) != 2 || len(pins) != len(plan.Policy.CustodianPeers) {
		return fmt.Errorf("formal-cox: incomplete blockwise step commit barrier")
	}
	for _, peer := range plan.Policy.CustodianPeers {
		if len(pins[peer]) != ed25519.PublicKeySize {
			return fmt.Errorf("formal-cox: pinset does not cover every custodian")
		}
	}
	pinset, err := formalCoxBlockwisePinsetSHA256(pins)
	if err != nil || pinset != plan.Policy.PinsetSHA256 {
		return fmt.Errorf("formal-cox: blockwise receipt pinset mismatch")
	}
	planSHA, _ := formalCoxBlockwisePlanSHA256(plan)
	seen := make(map[string]bool, 2)
	for _, receipt := range receipts {
		pin, ok := pins[receipt.Peer]
		message, messageErr := formalCoxBlockwiseReceiptUnsigned(receipt)
		if !ok || seen[receipt.Peer] ||
			(receipt.Peer != plan.Policy.ComputePeers[0] &&
				receipt.Peer != plan.Policy.ComputePeers[1]) ||
			receipt.Version != formalCoxBlockwiseReceiptVersion ||
			receipt.PlanSHA256 != planSHA ||
			formalCoxBlockwiseValidateWorkerStep(plan, receipt.Step) != nil ||
			!formalCoxIsSHA256(receipt.AttemptID) ||
			!formalCoxIsSHA256(receipt.StateSHA256) ||
			!formalCoxIsSHA256(receipt.TranscriptSHA256) || messageErr != nil ||
			len(receipt.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pin, message, receipt.Signature) {
			return fmt.Errorf("formal-cox: invalid blockwise step receipt")
		}
		seen[receipt.Peer] = true
	}
	if receipts[0].Step != receipts[1].Step ||
		receipts[0].AttemptID != receipts[1].AttemptID ||
		receipts[0].TranscriptSHA256 != receipts[1].TranscriptSHA256 {
		return fmt.Errorf("formal-cox: blockwise receipts bind different attempts")
	}
	return nil
}

func formalCoxBlockwiseEnsurePrivateDir(path string) error {
	if path == "" || path == "." || path == string(filepath.Separator) {
		return fmt.Errorf("formal-cox: invalid blockwise checkpoint directory")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("formal-cox: unsafe blockwise checkpoint directory")
	}
	return nil
}

func newFormalCoxBlockwiseCheckpointStore(dir string, key [32]byte,
	plan formalCoxBlockwisePlan, peer string) (
	*formalCoxBlockwiseCheckpointStore, error) {
	if bytes.Equal(key[:], make([]byte, len(key))) {
		return nil, fmt.Errorf("formal-cox: blockwise checkpoint key is missing")
	}
	if err := validateFormalCoxBlockwisePlan(plan); err != nil {
		return nil, err
	}
	if peer != plan.Policy.ComputePeers[0] && peer != plan.Policy.ComputePeers[1] {
		return nil, fmt.Errorf("formal-cox: checkpoint peer is not a compute peer")
	}
	dir = filepath.Clean(dir)
	if err := formalCoxBlockwiseEnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	return &formalCoxBlockwiseCheckpointStore{
		path:           filepath.Join(dir, "formal-cox-blockwise-state.json"),
		completionPath: filepath.Join(dir, "formal-cox-blockwise-completion.json"),
		key:            key, plan: plan, peer: peer,
	}, nil
}

func formalCoxBlockwiseReadPrivateFile(path string, minimum, maximum int64) (
	[]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() < minimum || info.Size() > maximum {
		return nil, fmt.Errorf("formal-cox: unsafe private blockwise artifact")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("formal-cox: blockwise artifact changed while opening")
	}
	encoded := make([]byte, opened.Size())
	_, readErr := io.ReadFull(file, encoded)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return encoded, nil
}

func (store *formalCoxBlockwiseCheckpointStore) validateState(
	state formalCoxBlockwiseCheckpoint) error {
	planSHA, _ := formalCoxBlockwisePlanSHA256(store.plan)
	if state.Version != formalCoxBlockwiseCheckpointVersion ||
		state.PlanSHA256 != planSHA || state.Peer != store.peer ||
		state.Generation < 1 || state.NextStep < 0 ||
		state.NextStep > store.plan.ScheduleSteps ||
		!formalCoxIsSHA256(state.TranscriptSHA256) ||
		!formalCoxIsSHA256(state.MAC) ||
		(state.PreviousMAC != "" && !formalCoxIsSHA256(state.PreviousMAC)) {
		return fmt.Errorf("formal-cox: invalid blockwise checkpoint context")
	}
	wantMAC, err := formalCoxBlockwiseCheckpointMAC(store.key, state)
	if err != nil || !hmac.Equal([]byte(wantMAC), []byte(state.MAC)) {
		return fmt.Errorf("formal-cox: blockwise checkpoint authentication failed")
	}
	p := store.plan.Policy.CovariateCount
	if _, err := formalCoxBlockwiseDecodeValues(
		state.State, store.plan.StateCoordinates, store.plan.RingBits); err != nil {
		return err
	}
	if state.State[store.plan.StateArithmetic] != "0" &&
		state.State[store.plan.StateArithmetic] != "1" {
		return fmt.Errorf("formal-cox: invalid checkpoint validity share")
	}
	for _, values := range [][]string{state.Scores, state.Candidate, state.Projected} {
		if _, err := formalCoxBlockwiseDecodeValues(values, p,
			store.plan.RingBits); err != nil {
			return err
		}
	}
	if _, err := formalCoxBlockwiseDecodeValues(state.Information,
		formalCoxBlockwiseInformationCoordinates(store.plan.Policy),
		store.plan.RingBits); err != nil {
		return err
	}
	if _, err := formalCoxBlockwiseDecodeValues(state.InformationScratch,
		3*formalCoxBlockwiseInformationCoordinates(store.plan.Policy),
		store.plan.RingBits); err != nil {
		return err
	}
	stateSHA := formalCoxBlockwisePrivateStateSHA256(state)
	if state.NextStep == 0 {
		if state.LastReceipt != nil {
			return fmt.Errorf("formal-cox: initial checkpoint has a receipt")
		}
	} else {
		if state.LastReceipt == nil ||
			state.LastReceipt.Peer != state.Peer ||
			state.LastReceipt.PlanSHA256 != state.PlanSHA256 ||
			state.LastReceipt.Step.ScheduleIndex != state.NextStep-1 ||
			state.LastReceipt.StateSHA256 != stateSHA ||
			state.LastReceipt.TranscriptSHA256 != state.TranscriptSHA256 ||
			len(state.LastReceipt.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("formal-cox: invalid committed blockwise receipt")
		}
	}
	if state.NextStep == store.plan.ScheduleSteps {
		if !formalCoxIsSHA256(state.FinalCommitSHA256) || state.Pending != nil {
			return fmt.Errorf("formal-cox: completed checkpoint lacks its final barrier")
		}
	} else if state.FinalCommitSHA256 != "" {
		return fmt.Errorf("formal-cox: incomplete checkpoint has a final barrier")
	}
	if state.Pending != nil {
		pending := state.Pending
		if pending.Step.ScheduleIndex != state.NextStep ||
			formalCoxBlockwiseValidateWorkerStep(store.plan, pending.Step) != nil ||
			!formalCoxIsSHA256(pending.AttemptID) {
			return fmt.Errorf("formal-cox: invalid pending blockwise step")
		}
		attemptBytes, decodeErr := hex.DecodeString(pending.AttemptID)
		var attempt [32]byte
		if decodeErr != nil || len(attemptBytes) != len(attempt) {
			return fmt.Errorf("formal-cox: invalid pending attempt encoding")
		}
		copy(attempt[:], attemptBytes)
		purpose, purposeErr := formalCoxBlockwiseWorkerStepPurpose(
			store.plan, pending.Step, attempt)
		wantTranscript, transcriptErr := formalCoxBlockwiseAdvanceTranscript(
			state.TranscriptSHA256, state.NextStep, purpose)
		if purposeErr != nil || transcriptErr != nil ||
			pending.StepPurpose != purpose ||
			pending.TranscriptSHA256 != wantTranscript {
			return fmt.Errorf("formal-cox: pending blockwise transcript mismatch")
		}
		if pending.OutputRecorded {
			if _, err := formalCoxBlockwiseDecodeValues(pending.Output,
				formalCoxBlockwiseWorkerOutputCoordinates(store.plan, pending.Step),
				store.plan.RingBits); err != nil {
				return err
			}
			next := formalCoxBlockwiseCloneCheckpoint(state)
			next.Pending = nil
			if err := formalCoxBlockwiseApplyOutput(store.plan, &next,
				pending.Step, pending.Output, pending.ValidityShare); err != nil {
				return err
			}
			if pending.NextStateSHA256 != formalCoxBlockwisePrivateStateSHA256(next) {
				return fmt.Errorf("formal-cox: pending blockwise state commitment mismatch")
			}
		} else if len(pending.Output) != 0 || pending.ValidityShare ||
			pending.NextStateSHA256 != "" {
			return fmt.Errorf("formal-cox: malformed unexecuted blockwise attempt")
		}
	}
	return nil
}

func (store *formalCoxBlockwiseCheckpointStore) readUnlocked() (
	formalCoxBlockwiseCheckpoint, error) {
	var state formalCoxBlockwiseCheckpoint
	encoded, err := formalCoxBlockwiseReadPrivateFile(
		store.path, 2, formalCoxBlockwiseCheckpointMax)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(encoded, &state); err != nil {
		return state, fmt.Errorf("formal-cox: decode blockwise checkpoint: %w", err)
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return state, fmt.Errorf("formal-cox: non-canonical blockwise checkpoint")
	}
	if err := store.validateState(state); err != nil {
		return state, err
	}
	return state, nil
}

func (store *formalCoxBlockwiseCheckpointStore) writeCAS(expected string,
	state formalCoxBlockwiseCheckpoint) error {
	formalCoxBlockwiseCheckpointCAS.Lock()
	defer formalCoxBlockwiseCheckpointCAS.Unlock()
	old, err := store.readUnlocked()
	if expected == "" {
		if err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("formal-cox: blockwise checkpoint CAS conflict")
		}
		if state.Generation != 1 {
			return fmt.Errorf("formal-cox: invalid initial checkpoint generation")
		}
	} else {
		if err != nil || old.MAC != expected ||
			state.Generation != old.Generation+1 {
			return fmt.Errorf("formal-cox: blockwise checkpoint CAS conflict")
		}
	}
	state.PreviousMAC = expected
	state.MAC = ""
	state.MAC, err = formalCoxBlockwiseCheckpointMAC(store.key, state)
	if err != nil {
		return err
	}
	if err := store.validateState(state); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) > formalCoxBlockwiseCheckpointMax {
		return fmt.Errorf("formal-cox: blockwise checkpoint exceeds its fixed bound")
	}
	return exactGCAtomicReplace(store.path, encoded)
}

func (store *formalCoxBlockwiseCheckpointStore) Bootstrap() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, err := store.readUnlocked(); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	planSHA, _ := formalCoxBlockwisePlanSHA256(store.plan)
	state := formalCoxBlockwiseCheckpoint{
		Version:    formalCoxBlockwiseCheckpointVersion,
		PlanSHA256: planSHA, Peer: store.peer, Generation: 1,
		State:              formalCoxBlockwiseZeroStrings(store.plan.StateCoordinates),
		Scores:             formalCoxBlockwiseZeroStrings(store.plan.Policy.CovariateCount),
		Candidate:          formalCoxBlockwiseZeroStrings(store.plan.Policy.CovariateCount),
		Projected:          formalCoxBlockwiseZeroStrings(store.plan.Policy.CovariateCount),
		Information:        formalCoxBlockwiseZeroStrings(formalCoxBlockwiseInformationCoordinates(store.plan.Policy)),
		InformationScratch: formalCoxBlockwiseZeroStrings(3 * formalCoxBlockwiseInformationCoordinates(store.plan.Policy)),
		TranscriptSHA256:   formalCoxBlockwiseInitialTranscript(planSHA),
	}
	// XOR shares 0 and 1 reconstruct the public initial execution-valid bit.
	if store.peer == store.plan.Policy.ComputePeers[1] {
		state.State[store.plan.StateArithmetic] = "1"
	}
	if err := store.writeCAS("", state); err != nil {
		// A concurrently reopened handle may have won the initial CAS.
		if _, loadErr := store.readUnlocked(); loadErr == nil {
			return nil
		}
		return err
	}
	return nil
}

func (store *formalCoxBlockwiseCheckpointStore) Load() (
	formalCoxBlockwiseCheckpoint, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.readUnlocked()
}

func (store *formalCoxBlockwiseCheckpointStore) BeginFreshAttempt(
	step formalCoxBlockwiseWorkerStep) ([32]byte, error) {
	var attempt [32]byte
	if _, err := crand.Read(attempt[:]); err != nil {
		return attempt, err
	}
	_, err := store.BeginAttempt(step, attempt)
	return attempt, err
}

func (store *formalCoxBlockwiseCheckpointStore) BeginAttempt(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte) (
	formalCoxBlockwiseWorkerStep, error) {
	if bytes.Equal(attempt[:], make([]byte, len(attempt))) {
		return formalCoxBlockwiseWorkerStep{},
			fmt.Errorf("formal-cox: blockwise attempt id must be non-zero")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return formalCoxBlockwiseWorkerStep{}, err
	}
	if state.NextStep >= store.plan.ScheduleSteps {
		return formalCoxBlockwiseWorkerStep{},
			fmt.Errorf("formal-cox: fixed blockwise schedule is complete")
	}
	if err := formalCoxBlockwiseValidateWorkerStep(store.plan, step); err != nil ||
		step.ScheduleIndex != state.NextStep {
		return formalCoxBlockwiseWorkerStep{},
			fmt.Errorf("formal-cox: reordered or skipped blockwise worker step")
	}
	if state.Pending != nil && state.Pending.OutputRecorded {
		return formalCoxBlockwiseWorkerStep{},
			fmt.Errorf("formal-cox: pending sealed output must cross its commit barrier")
	}
	purpose, err := formalCoxBlockwiseWorkerStepPurpose(store.plan, step, attempt)
	if err != nil {
		return formalCoxBlockwiseWorkerStep{}, err
	}
	transcript, err := formalCoxBlockwiseAdvanceTranscript(
		state.TranscriptSHA256, state.NextStep, purpose)
	if err != nil {
		return formalCoxBlockwiseWorkerStep{}, err
	}
	expected := state.MAC
	state.Generation++
	state.Pending = &formalCoxBlockwisePendingState{
		Step: step, AttemptID: hex.EncodeToString(attempt[:]),
		StepPurpose: purpose, TranscriptSHA256: transcript,
	}
	if err := store.writeCAS(expected, state); err != nil {
		return formalCoxBlockwiseWorkerStep{}, err
	}
	return step, nil
}

func (store *formalCoxBlockwiseCheckpointStore) RecordPendingOutput(
	step formalCoxBlockwiseWorkerStep, session exactGCSession,
	output formalCoxBlockwiseStepOutput) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return err
	}
	if state.Pending == nil || state.Pending.OutputRecorded ||
		state.Pending.Step != step ||
		state.Pending.AttemptID != hex.EncodeToString(session.SessionID[:]) ||
		formalCoxBlockwiseValidateWorkerSession(store.plan, step, session) != nil {
		return fmt.Errorf("formal-cox: output is not bound to the pending blockwise step")
	}
	encoded, err := formalCoxBlockwiseEncodeValues(
		output.ArithmeticShares, store.plan.RingBits)
	if err != nil || len(encoded) != formalCoxBlockwiseWorkerOutputCoordinates(
		store.plan, step) {
		return fmt.Errorf("formal-cox: invalid sealed blockwise output shape")
	}
	next := formalCoxBlockwiseCloneCheckpoint(state)
	next.Pending = nil
	if err := formalCoxBlockwiseApplyOutput(
		store.plan, &next, step, encoded, output.ValidityShare); err != nil {
		return err
	}
	expected := state.MAC
	state.Generation++
	state.Pending.OutputRecorded = true
	state.Pending.Output = encoded
	state.Pending.ValidityShare = output.ValidityShare
	state.Pending.NextStateSHA256 = formalCoxBlockwisePrivateStateSHA256(next)
	return store.writeCAS(expected, state)
}

func (store *formalCoxBlockwiseCheckpointStore) PendingReceipt(
	privateKey ed25519.PrivateKey) (formalCoxBlockwiseStepReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return formalCoxBlockwiseStepReceipt{}, err
	}
	if state.Pending == nil || !state.Pending.OutputRecorded ||
		len(privateKey) != ed25519.PrivateKeySize {
		return formalCoxBlockwiseStepReceipt{},
			fmt.Errorf("formal-cox: pending blockwise result is not receiptable")
	}
	receipt := formalCoxBlockwiseStepReceipt{
		Version:    formalCoxBlockwiseReceiptVersion,
		PlanSHA256: state.PlanSHA256, Peer: store.peer,
		Step: state.Pending.Step, AttemptID: state.Pending.AttemptID,
		StateSHA256:      state.Pending.NextStateSHA256,
		TranscriptSHA256: state.Pending.TranscriptSHA256,
	}
	message, err := formalCoxBlockwiseReceiptUnsigned(receipt)
	if err != nil {
		return formalCoxBlockwiseStepReceipt{}, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	return receipt, nil
}

// RunPendingWorkerStep executes exactly one purpose-bound circuit. External
// rows are required only for a block and one sealed noise slice is required
// only for the update. Their authenticated roots were fixed by BeginAttempt;
// the future source bridge must verify those roots before calling this method.
func (store *formalCoxBlockwiseCheckpointStore) RunPendingWorkerStep(
	rw io.ReadWriter, session exactGCSession, external []*big.Int,
	externalValidity *bool, signingKey ed25519.PrivateKey) (
	formalCoxBlockwiseStepReceipt, error) {
	store.runMu.Lock()
	defer store.runMu.Unlock()
	state, err := store.Load()
	if err != nil {
		return formalCoxBlockwiseStepReceipt{}, err
	}
	if state.Pending == nil || state.Pending.OutputRecorded ||
		state.Pending.AttemptID != hex.EncodeToString(session.SessionID[:]) {
		return formalCoxBlockwiseStepReceipt{},
			fmt.Errorf("formal-cox: worker has no matching unexecuted step")
	}
	step := state.Pending.Step
	local, err := formalCoxBlockwiseWorkerLocalInput(
		store.plan, state, step, external, externalValidity)
	if err != nil {
		return formalCoxBlockwiseStepReceipt{}, err
	}
	var output formalCoxBlockwiseStepOutput
	if store.peer == store.plan.Policy.ComputePeers[0] {
		output, err = formalCoxBlockwiseRunGarbler(
			rw, store.plan, step, session, local)
	} else {
		output, err = formalCoxBlockwiseRunEvaluator(
			rw, store.plan, step, session, local)
	}
	if err != nil {
		return formalCoxBlockwiseStepReceipt{}, err
	}
	if err := store.RecordPendingOutput(step, session, output); err != nil {
		return formalCoxBlockwiseStepReceipt{}, err
	}
	return store.PendingReceipt(signingKey)
}

func (store *formalCoxBlockwiseCheckpointStore) CommitPending(
	receipts []formalCoxBlockwiseStepReceipt,
	pins map[string]ed25519.PublicKey) error {
	if err := formalCoxBlockwiseValidateReceiptPair(
		store.plan, receipts, pins); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return err
	}
	var local *formalCoxBlockwiseStepReceipt
	for index := range receipts {
		if receipts[index].Peer == store.peer {
			local = &receipts[index]
		}
	}
	if local == nil {
		return fmt.Errorf("formal-cox: commit barrier omits the local compute peer")
	}
	if state.Pending == nil {
		if state.LastReceipt != nil &&
			formalCoxBlockwiseReceiptEqual(*state.LastReceipt, *local) &&
			state.NextStep == local.Step.ScheduleIndex+1 {
			if state.NextStep == store.plan.ScheduleSteps {
				_, _, err = store.completionUnlocked(state)
			}
			return err
		}
		return fmt.Errorf("formal-cox: no pending blockwise result for commit")
	}
	pending := state.Pending
	if !pending.OutputRecorded || local.Step != pending.Step ||
		local.AttemptID != pending.AttemptID ||
		local.StateSHA256 != pending.NextStateSHA256 ||
		local.TranscriptSHA256 != pending.TranscriptSHA256 {
		return fmt.Errorf("formal-cox: commit barrier does not match pending state")
	}
	expected := state.MAC
	next := formalCoxBlockwiseCloneCheckpoint(state)
	if err := formalCoxBlockwiseApplyOutput(store.plan, &next, pending.Step,
		pending.Output, pending.ValidityShare); err != nil {
		return err
	}
	if formalCoxBlockwisePrivateStateSHA256(next) != pending.NextStateSHA256 {
		return fmt.Errorf("formal-cox: pending state changed before commit")
	}
	state.State, state.Scores = next.State, next.Scores
	state.Candidate, state.Projected = next.Candidate, next.Projected
	state.Information = next.Information
	state.InformationScratch = next.InformationScratch
	state.Pending = nil
	state.TranscriptSHA256 = local.TranscriptSHA256
	committed := *local
	committed.Signature = append([]byte(nil), local.Signature...)
	state.LastReceipt = &committed
	state.NextStep++
	state.Generation++
	if state.NextStep == store.plan.ScheduleSteps {
		state.FinalCommitSHA256, err = formalCoxBlockwiseFinalCommitSHA256(receipts)
		if err != nil {
			return err
		}
	}
	if err := store.writeCAS(expected, state); err != nil {
		return err
	}
	if state.NextStep == store.plan.ScheduleSteps {
		_, _, err = store.completionUnlocked(state)
	}
	return err
}

func formalCoxBlockwiseCompletionDigest(
	completion formalCoxBlockwiseCompletion) (string, error) {
	completion.CompletionSHA256 = ""
	encoded, err := json.Marshal(completion)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte("dsVert/formal-cox/blockwise-worker/completion/v1|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseReadCompletion(path string) ([]byte, error) {
	return formalCoxBlockwiseReadPrivateFile(
		path, 2, formalCoxBlockwiseCompletionMax)
}

func formalCoxBlockwiseCompletionNextPath(path string) string {
	return path + formalCoxBlockwiseCompletionNext
}

func formalCoxBlockwiseCompletionMatches(path string, encoded []byte) (bool, error) {
	existing, err := formalCoxBlockwiseReadCompletion(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(existing, encoded) {
		return false, fmt.Errorf("formal-cox: conflicting sticky blockwise completion")
	}
	return true, nil
}

func formalCoxBlockwiseValidateCompletionNext(path string, encoded []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() != int64(len(encoded)) {
		return fmt.Errorf("formal-cox: unsafe pending sticky completion")
	}
	pending, err := formalCoxBlockwiseReadCompletion(path)
	if err != nil || !bytes.Equal(pending, encoded) {
		return fmt.Errorf("formal-cox: invalid pending sticky completion")
	}
	return nil
}

// formalCoxBlockwiseRecoverCompletionNext repairs only the deterministic
// predecessor left by a crash. It never scans a directory or accepts a
// linked pending artifact other than the exact link window created below.
func formalCoxBlockwiseRecoverCompletionNext(path string, encoded []byte) error {
	nextPath := formalCoxBlockwiseCompletionNextPath(path)
	nextInfo, err := os.Lstat(nextPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	finalInfo, finalErr := os.Lstat(path)
	if os.IsNotExist(finalErr) {
		pending, err := formalCoxBlockwiseReadPrivateFile(
			nextPath, 0, formalCoxBlockwiseCompletionMax)
		if err != nil {
			return err
		}
		if len(pending) < len(encoded) {
			if err := os.Remove(nextPath); err != nil {
				return err
			}
			return exactGCSyncDir(filepath.Dir(path))
		}
		if !bytes.Equal(pending, encoded) {
			return fmt.Errorf("formal-cox: conflicting pending sticky completion")
		}
		if err := formalCoxBlockwiseValidateCompletionNext(nextPath, encoded); err != nil {
			return err
		}
		if err := os.Link(nextPath, path); err != nil {
			return err
		}
	} else if finalErr != nil {
		return finalErr
	} else if os.SameFile(nextInfo, finalInfo) {
		if !nextInfo.Mode().IsRegular() || nextInfo.Mode()&os.ModeSymlink != 0 ||
			nextInfo.Mode().Perm() != 0o600 || nextInfo.Size() != int64(len(encoded)) {
			return fmt.Errorf("formal-cox: unsafe linked sticky completion")
		}
	} else {
		matched, err := formalCoxBlockwiseCompletionMatches(path, encoded)
		if err != nil {
			return err
		}
		if !matched {
			return fmt.Errorf("formal-cox: sticky completion disappeared during recovery")
		}
		if err := formalCoxBlockwiseValidateCompletionNext(nextPath, encoded); err != nil {
			return err
		}
	}
	if err := os.Remove(nextPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := exactGCSyncDir(filepath.Dir(path)); err != nil {
		return err
	}
	matched, err := formalCoxBlockwiseCompletionMatches(path, encoded)
	if err != nil || !matched {
		return fmt.Errorf("formal-cox: sticky completion recovery did not stabilize")
	}
	return nil
}

func formalCoxBlockwisePersistCompletion(path string, encoded []byte) error {
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseCompletionMax {
		return fmt.Errorf("formal-cox: invalid sticky blockwise completion")
	}
	formalCoxBlockwiseCheckpointCAS.Lock()
	defer formalCoxBlockwiseCheckpointCAS.Unlock()
	if err := formalCoxBlockwiseRecoverCompletionNext(path, encoded); err != nil {
		return err
	}
	if matched, err := formalCoxBlockwiseCompletionMatches(path, encoded); err != nil {
		return err
	} else if matched {
		return nil
	}
	nextPath := formalCoxBlockwiseCompletionNextPath(path)
	tmp, err := os.OpenFile(nextPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		if recoverErr := formalCoxBlockwiseRecoverCompletionNext(path, encoded); recoverErr != nil {
			return recoverErr
		}
		if matched, matchErr := formalCoxBlockwiseCompletionMatches(path, encoded); matchErr != nil || !matched {
			return fmt.Errorf("formal-cox: sticky completion CAS conflict")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err := exactGCWriteFull(tmp, encoded); err != nil {
		_ = tmp.Close()
		_ = os.Remove(nextPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(nextPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(nextPath)
		return err
	}
	if err := formalCoxBlockwiseValidateCompletionNext(nextPath, encoded); err != nil {
		return err
	}
	if err := os.Link(nextPath, path); err != nil {
		if recoverErr := formalCoxBlockwiseRecoverCompletionNext(path, encoded); recoverErr != nil {
			return recoverErr
		}
		if matched, matchErr := formalCoxBlockwiseCompletionMatches(path, encoded); matchErr != nil || !matched {
			return fmt.Errorf("formal-cox: sticky completion CAS conflict")
		}
		return nil
	}
	if err := os.Remove(nextPath); err != nil {
		return err
	}
	return exactGCSyncDir(filepath.Dir(path))
}

func (store *formalCoxBlockwiseCheckpointStore) completionUnlocked(
	state formalCoxBlockwiseCheckpoint) (formalCoxBlockwiseCompletion,
	[]byte, error) {
	var zero formalCoxBlockwiseCompletion
	if state.NextStep != store.plan.ScheduleSteps || state.Pending != nil ||
		!formalCoxIsSHA256(state.FinalCommitSHA256) {
		return zero, nil, fmt.Errorf("formal-cox: blockwise completion is unavailable")
	}
	completion := formalCoxBlockwiseCompletion{
		Version:               formalCoxBlockwiseCompletionVersion,
		PlanSHA256:            state.PlanSHA256,
		TranscriptSHA256:      state.TranscriptSHA256,
		FinalCommitSHA256:     state.FinalCommitSHA256,
		ScheduleSteps:         store.plan.ScheduleSteps,
		FixedScheduleComplete: true,
		OutputKind:            "sealed_private_result_v1",
		ProductionReady:       false,
	}
	var err error
	completion.CompletionSHA256, err = formalCoxBlockwiseCompletionDigest(completion)
	if err != nil {
		return zero, nil, err
	}
	encoded, err := json.Marshal(completion)
	if err != nil || len(encoded) > formalCoxBlockwiseCompletionMax {
		return zero, nil, fmt.Errorf("formal-cox: invalid blockwise completion")
	}
	if err := formalCoxBlockwisePersistCompletion(
		store.completionPath, encoded); err != nil {
		return zero, nil, err
	}
	persisted, err := formalCoxBlockwiseReadCompletion(store.completionPath)
	if err != nil || !bytes.Equal(persisted, encoded) {
		return zero, nil, fmt.Errorf("formal-cox: sticky completion did not stabilize")
	}
	return completion, persisted, nil
}

func (store *formalCoxBlockwiseCheckpointStore) Completion() (
	formalCoxBlockwiseCompletion, []byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.readUnlocked()
	if err != nil {
		return formalCoxBlockwiseCompletion{}, nil, err
	}
	return store.completionUnlocked(state)
}

// FinalSealedOutput is private worker state. It is intentionally not part of
// the opaque completion and no caller outside the future protected release
// bridge should receive it.
func (store *formalCoxBlockwiseCheckpointStore) FinalSealedOutput() (
	formalCoxSealedOutput, error) {
	state, err := store.Load()
	if err != nil {
		return formalCoxSealedOutput{}, err
	}
	if state.NextStep != store.plan.ScheduleSteps || state.Pending != nil {
		return formalCoxSealedOutput{},
			fmt.Errorf("formal-cox: final sealed output is unavailable")
	}
	values, err := formalCoxBlockwiseDecodeValues(
		state.State[:store.plan.Policy.CovariateCount],
		store.plan.Policy.CovariateCount, store.plan.RingBits)
	if err != nil {
		return formalCoxSealedOutput{}, err
	}
	return formalCoxSealedOutput{
		CoefficientShares: values,
		ValidityShare:     state.State[store.plan.StateArithmetic] == "1",
	}, nil
}
