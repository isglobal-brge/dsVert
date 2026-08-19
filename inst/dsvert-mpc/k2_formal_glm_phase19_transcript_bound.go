package main

// Data-independent bound for the unique exact-GC byte stream emitted by one
// complete Phase-1.9 schedule.  The bound is derived from the validated plan,
// the canonical pre-source DP projection, and the circuits compiled from that
// public shape.  It deliberately contains no attempt, path, TTL, relay chunk,
// or caller-provided maximum.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
)

const (
	formalGLMPhase19TranscriptBoundVersion  = "dsvert-formal-glm-phase19-transcript-bound-v1"
	formalGLMPhase19ExactGCWireBoundVersion = "dsvert-exact-gc-unique-stream-bound-v1"
	formalGLMPhase19TranscriptBoundPurpose  = "formal_glm_phase19_complete_unique_exact_gc_stream_v1"

	formalGLMPhase19TranscriptBoundDomain     = "dsVert/formal-glm/phase19/transcript-bound/v1"
	formalGLMPhase19TranscriptInventoryDomain = "dsVert/formal-glm/phase19/transcript-circuit-inventory/v1"
	formalGLMPhase19TranscriptWireABIDomain   = "dsVert/exact-gc/unique-stream-wire-abi/v1"

	formalGLMPhase19TranscriptP2PBufferBytes   uint64 = 64 << 10
	formalGLMPhase19TranscriptUint32Bytes      uint64 = 4
	formalGLMPhase19TranscriptLabelBytes       uint64 = 16
	formalGLMPhase19TranscriptRecordOverhead   uint64 = 36
	formalGLMPhase19TranscriptCOBaseOTs        uint64 = 128
	formalGLMPhase19TranscriptIKNPChunkBits    uint64 = 512
	formalGLMPhase19TranscriptIKNPMaliciousBit uint64 = 256
)

type formalGLMPhase19TranscriptCircuitV1 struct {
	Kind                 string `json:"kind"`
	CircuitSourceSHA256  string `json:"circuit_source_sha256"`
	Multiplicity         uint64 `json:"multiplicity"`
	Gates                uint64 `json:"gates"`
	CompilerRelativeCost uint64 `json:"compiler_relative_cost"`
	GarblerInputBits     uint64 `json:"garbler_input_bits"`
	EvaluatorInputBits   uint64 `json:"evaluator_input_bits"`
	OutputBits           uint64 `json:"output_bits"`
	G2EPlainBytes        uint64 `json:"g2e_plain_bytes"`
	E2GPlainBytes        uint64 `json:"e2g_plain_bytes"`
	G2EPhysicalBytes     uint64 `json:"g2e_physical_bytes"`
	E2GPhysicalBytes     uint64 `json:"e2g_physical_bytes"`
	G2ERecordCount       uint64 `json:"g2e_record_count"`
	E2GRecordCount       uint64 `json:"e2g_record_count"`
}

type formalGLMPhase19TranscriptBoundV1 struct {
	Version                    string                                `json:"version"`
	Purpose                    string                                `json:"purpose"`
	WireBoundVersion           string                                `json:"wire_bound_version"`
	WireABISHA256              string                                `json:"wire_abi_sha256"`
	CanonicalPlanSHA256        string                                `json:"canonical_plan_sha256"`
	CanonicalPreSourceDPSHA256 string                                `json:"canonical_pre_source_dp_sha256"`
	ShapeSHA256                string                                `json:"shape_sha256"`
	CircuitInventorySHA256     string                                `json:"circuit_inventory_sha256"`
	CircuitInventory           []formalGLMPhase19TranscriptCircuitV1 `json:"circuit_inventory"`
	G2EPlainBytes              uint64                                `json:"g2e_plain_bytes"`
	E2GPlainBytes              uint64                                `json:"e2g_plain_bytes"`
	G2EPhysicalBytes           uint64                                `json:"g2e_physical_bytes"`
	E2GPhysicalBytes           uint64                                `json:"e2g_physical_bytes"`
	TotalPhysicalBytes         uint64                                `json:"total_physical_bytes"`
	UniqueRecordCount          uint64                                `json:"unique_record_count"`
	MaxUniqueChunks            uint64                                `json:"max_unique_chunks"`
}

type formalGLMPhase19TranscriptWireABIV1 struct {
	Version                 string `json:"version"`
	P2PWriteBufferBytes     uint64 `json:"p2p_write_buffer_bytes"`
	SendUint32Bytes         uint64 `json:"send_uint32_bytes"`
	SendDataPrefixBytes     uint64 `json:"send_data_prefix_bytes"`
	LabelBytes              uint64 `json:"label_bytes"`
	COCurve                 string `json:"co_curve"`
	COBaseOTs               uint64 `json:"co_base_ots"`
	IKNPSecurityBits        uint64 `json:"iknp_security_bits"`
	IKNPChunkBits           uint64 `json:"iknp_chunk_bits"`
	IKNPMaliciousCheckBits  uint64 `json:"iknp_malicious_check_bits"`
	IKNPMalicious           bool   `json:"iknp_malicious"`
	SecureRecordVersion     uint64 `json:"secure_record_version"`
	SecureRecordHeaderBytes uint64 `json:"secure_record_header_bytes"`
	SecureRecordTagBytes    uint64 `json:"secure_record_tag_bytes"`
	SecureRecordOverhead    uint64 `json:"secure_record_overhead_bytes"`
	SecureRecordMaxPlain    uint64 `json:"secure_record_max_plain_bytes"`
	SpoolCoalesceBytes      uint64 `json:"spool_coalesce_bytes"`
	G2EPlainFormula         string `json:"g2e_plain_formula"`
	E2GPlainFormula         string `json:"e2g_plain_formula"`
	CompilerCostFormula     string `json:"compiler_cost_formula"`
	GarbledRowUpperFormula  string `json:"garbled_row_upper_formula"`
}

type formalGLMPhase19TranscriptPackingV1 struct {
	position uint64
	plain    uint64
	records  uint64
}

func formalGLMPhase19TranscriptCheckedAddV1(left, right uint64) (
	uint64, error) {
	if left > math.MaxUint64-right {
		return 0, fmt.Errorf("formal-glm: transcript byte bound addition overflow")
	}
	return left + right, nil
}

func formalGLMPhase19TranscriptCheckedMulV1(left, right uint64) (
	uint64, error) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, fmt.Errorf("formal-glm: transcript byte bound multiplication overflow")
	}
	return left * right, nil
}

func formalGLMPhase19TranscriptCeilDivV1(value, divisor uint64) (
	uint64, error) {
	if divisor == 0 {
		return 0, fmt.Errorf("formal-glm: invalid transcript bound divisor")
	}
	quotient := value / divisor
	if value%divisor != 0 {
		return formalGLMPhase19TranscriptCheckedAddV1(quotient, 1)
	}
	return quotient, nil
}

func (packing *formalGLMPhase19TranscriptPackingV1) flush() error {
	if packing.position == 0 {
		return nil
	}
	count, err := formalGLMPhase19TranscriptCheckedAddV1(packing.records, 1)
	if err != nil {
		return err
	}
	packing.records = count
	packing.position = 0
	return nil
}

func (packing *formalGLMPhase19TranscriptPackingV1) sendAtomic(
	size uint64) error {
	if size > formalGLMPhase19TranscriptP2PBufferBytes {
		return fmt.Errorf("formal-glm: transcript atom exceeds p2p buffer")
	}
	if packing.position > formalGLMPhase19TranscriptP2PBufferBytes-size {
		if err := packing.flush(); err != nil {
			return err
		}
	}
	plain, err := formalGLMPhase19TranscriptCheckedAddV1(packing.plain, size)
	if err != nil {
		return err
	}
	position, err := formalGLMPhase19TranscriptCheckedAddV1(
		packing.position, size)
	if err != nil {
		return err
	}
	packing.plain, packing.position = plain, position
	return nil
}

func (packing *formalGLMPhase19TranscriptPackingV1) sendUint32() error {
	return packing.sendAtomic(formalGLMPhase19TranscriptUint32Bytes)
}

func (packing *formalGLMPhase19TranscriptPackingV1) sendLabel() error {
	return packing.sendAtomic(formalGLMPhase19TranscriptLabelBytes)
}

func (packing *formalGLMPhase19TranscriptPackingV1) sendData(
	size uint64) error {
	if err := packing.sendUint32(); err != nil {
		return err
	}
	for size > 0 {
		if packing.position == formalGLMPhase19TranscriptP2PBufferBytes {
			if err := packing.flush(); err != nil {
				return err
			}
		}
		available := formalGLMPhase19TranscriptP2PBufferBytes - packing.position
		count := size
		if count > available {
			count = available
		}
		plain, err := formalGLMPhase19TranscriptCheckedAddV1(
			packing.plain, count)
		if err != nil {
			return err
		}
		position, err := formalGLMPhase19TranscriptCheckedAddV1(
			packing.position, count)
		if err != nil {
			return err
		}
		packing.plain, packing.position = plain, position
		size -= count
	}
	return nil
}

func (packing *formalGLMPhase19TranscriptPackingV1) physical() (
	uint64, error) {
	overhead, err := formalGLMPhase19TranscriptCheckedMulV1(
		packing.records, formalGLMPhase19TranscriptRecordOverhead)
	if err != nil {
		return 0, err
	}
	return formalGLMPhase19TranscriptCheckedAddV1(packing.plain, overhead)
}

func formalGLMPhase19TranscriptWireABISHA256V1() (string, error) {
	var labelData ot.LabelData
	if len(labelData) != int(formalGLMPhase19TranscriptLabelBytes) ||
		ot.K != int(formalGLMPhase19TranscriptCOBaseOTs) ||
		exactGCRecordVersion != 1 || exactGCRecordHeader != 20 ||
		exactGCRecordMaxPlain != 1<<20 || exactGCSpoolWriteBuffer != 1<<20 ||
		formalGLMPhase19TranscriptRecordOverhead !=
			uint64(exactGCRecordHeader+16) {
		return "", fmt.Errorf("formal-glm: exact-GC wire ABI drift")
	}
	abi := formalGLMPhase19TranscriptWireABIV1{
		Version:             formalGLMPhase19ExactGCWireBoundVersion,
		P2PWriteBufferBytes: formalGLMPhase19TranscriptP2PBufferBytes,
		SendUint32Bytes:     formalGLMPhase19TranscriptUint32Bytes,
		SendDataPrefixBytes: formalGLMPhase19TranscriptUint32Bytes,
		LabelBytes:          formalGLMPhase19TranscriptLabelBytes,
		COCurve:             "P-256", COBaseOTs: formalGLMPhase19TranscriptCOBaseOTs,
		IKNPSecurityBits:       uint64(ot.K),
		IKNPChunkBits:          formalGLMPhase19TranscriptIKNPChunkBits,
		IKNPMaliciousCheckBits: formalGLMPhase19TranscriptIKNPMaliciousBit,
		IKNPMalicious:          true,
		SecureRecordVersion:    1, SecureRecordHeaderBytes: exactGCRecordHeader,
		SecureRecordTagBytes:   16,
		SecureRecordOverhead:   formalGLMPhase19TranscriptRecordOverhead,
		SecureRecordMaxPlain:   exactGCRecordMaxPlain,
		SpoolCoalesceBytes:     exactGCSpoolWriteBuffer,
		G2EPlainFormula:        "9321+4G+16(g+C)+32e+ceil(o/8)",
		E2GPlainFormula:        "9436+128ceil(e/8)+4ceil(e/512)",
		CompilerCostFormula:    "2*AND+3*OR+2*INV",
		GarbledRowUpperFormula: "2*AND+3*OR+2*INV",
	}
	encoded, err := json.Marshal(abi)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase19TranscriptWireABIDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase19TranscriptGateLabelsV1(op circuit.Operation) (
	uint64, error) {
	switch op {
	case circuit.XOR, circuit.XNOR:
		return 0, nil
	case circuit.AND, circuit.INV:
		return 2, nil
	case circuit.OR:
		return 3, nil
	default:
		return 0, fmt.Errorf("formal-glm: unsupported exact-GC gate operation")
	}
}

func formalGLMPhase19TranscriptPackG2EV1(circ *circuit.Circuit,
	garblerBits, evaluatorBits, outputBits uint64) (
	formalGLMPhase19TranscriptPackingV1, error) {
	var packing formalGLMPhase19TranscriptPackingV1
	if err := packing.sendData(32); err != nil {
		return packing, err
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	if err := packing.sendData(32); err != nil {
		return packing, err
	}
	if err := packing.sendUint32(); err != nil {
		return packing, err
	}
	for _, gate := range circ.Gates {
		if err := packing.sendUint32(); err != nil {
			return packing, err
		}
		labels, err := formalGLMPhase19TranscriptGateLabelsV1(gate.Op)
		if err != nil {
			return packing, err
		}
		for index := uint64(0); index < labels; index++ {
			if err := packing.sendLabel(); err != nil {
				return packing, err
			}
		}
	}
	for index := uint64(0); index < garblerBits; index++ {
		if err := packing.sendLabel(); err != nil {
			return packing, err
		}
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	if err := packing.sendData(5); err != nil {
		return packing, err
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	for index := uint64(0); index < 2*formalGLMPhase19TranscriptCOBaseOTs; index++ {
		if err := packing.sendData(32); err != nil {
			return packing, err
		}
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	if err := packing.sendLabel(); err != nil {
		return packing, err
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	padLabels, err := formalGLMPhase19TranscriptCheckedMulV1(evaluatorBits, 2)
	if err != nil {
		return packing, err
	}
	for index := uint64(0); index < padLabels; index++ {
		if err := packing.sendLabel(); err != nil {
			return packing, err
		}
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	decodeBytes, err := formalGLMPhase19TranscriptCeilDivV1(outputBits, 8)
	if err != nil {
		return packing, err
	}
	if err := packing.sendData(decodeBytes); err != nil {
		return packing, err
	}
	return packing, packing.flush()
}

func formalGLMPhase19TranscriptPackE2GV1(evaluatorBits uint64) (
	formalGLMPhase19TranscriptPackingV1, error) {
	var packing formalGLMPhase19TranscriptPackingV1
	if err := packing.sendData(32); err != nil {
		return packing, err
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	for index := 0; index < 2; index++ {
		if err := packing.sendData(32); err != nil {
			return packing, err
		}
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	for index := uint64(0); index < 2*formalGLMPhase19TranscriptCOBaseOTs; index++ {
		if err := packing.sendData(16); err != nil {
			return packing, err
		}
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	if err := packing.sendUint32(); err != nil {
		return packing, err
	}
	if err := packing.sendUint32(); err != nil {
		return packing, err
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	remaining := evaluatorBits
	for remaining > 0 {
		rows := remaining
		if rows > formalGLMPhase19TranscriptIKNPChunkBits {
			rows = formalGLMPhase19TranscriptIKNPChunkBits
		}
		byteRows, err := formalGLMPhase19TranscriptCeilDivV1(rows, 8)
		if err != nil {
			return packing, err
		}
		payload, err := formalGLMPhase19TranscriptCheckedMulV1(
			byteRows, uint64(ot.K))
		if err != nil {
			return packing, err
		}
		if err := packing.sendData(payload); err != nil {
			return packing, err
		}
		remaining -= rows
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	maliciousRows, err := formalGLMPhase19TranscriptCeilDivV1(
		formalGLMPhase19TranscriptIKNPMaliciousBit, 8)
	if err != nil {
		return packing, err
	}
	maliciousPayload, err := formalGLMPhase19TranscriptCheckedMulV1(
		maliciousRows, uint64(ot.K))
	if err != nil {
		return packing, err
	}
	if err := packing.sendData(maliciousPayload); err != nil {
		return packing, err
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	if err := packing.sendLabel(); err != nil {
		return packing, err
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	for index := 0; index < 3; index++ {
		if err := packing.sendLabel(); err != nil {
			return packing, err
		}
	}
	if err := packing.flush(); err != nil {
		return packing, err
	}
	if err := packing.sendData(32); err != nil {
		return packing, err
	}
	return packing, packing.flush()
}

func formalGLMPhase19TranscriptPlainFormulaV1(gates, cost, garblerBits,
	evaluatorBits, outputBits uint64) (uint64, uint64, error) {
	g2e := uint64(9321)
	term, err := formalGLMPhase19TranscriptCheckedMulV1(4, gates)
	if err != nil {
		return 0, 0, err
	}
	g2e, err = formalGLMPhase19TranscriptCheckedAddV1(g2e, term)
	if err != nil {
		return 0, 0, err
	}
	inputAndCost, err := formalGLMPhase19TranscriptCheckedAddV1(
		garblerBits, cost)
	if err != nil {
		return 0, 0, err
	}
	term, err = formalGLMPhase19TranscriptCheckedMulV1(16, inputAndCost)
	if err != nil {
		return 0, 0, err
	}
	g2e, err = formalGLMPhase19TranscriptCheckedAddV1(g2e, term)
	if err != nil {
		return 0, 0, err
	}
	term, err = formalGLMPhase19TranscriptCheckedMulV1(32, evaluatorBits)
	if err != nil {
		return 0, 0, err
	}
	g2e, err = formalGLMPhase19TranscriptCheckedAddV1(g2e, term)
	if err != nil {
		return 0, 0, err
	}
	decodeBytes, err := formalGLMPhase19TranscriptCeilDivV1(outputBits, 8)
	if err != nil {
		return 0, 0, err
	}
	g2e, err = formalGLMPhase19TranscriptCheckedAddV1(g2e, decodeBytes)
	if err != nil {
		return 0, 0, err
	}
	evaluatorBytes, err := formalGLMPhase19TranscriptCeilDivV1(
		evaluatorBits, 8)
	if err != nil {
		return 0, 0, err
	}
	evaluatorChunks, err := formalGLMPhase19TranscriptCeilDivV1(
		evaluatorBits, formalGLMPhase19TranscriptIKNPChunkBits)
	if err != nil {
		return 0, 0, err
	}
	e2g := uint64(9436)
	term, err = formalGLMPhase19TranscriptCheckedMulV1(
		uint64(ot.K), evaluatorBytes)
	if err != nil {
		return 0, 0, err
	}
	e2g, err = formalGLMPhase19TranscriptCheckedAddV1(e2g, term)
	if err != nil {
		return 0, 0, err
	}
	term, err = formalGLMPhase19TranscriptCheckedMulV1(4, evaluatorChunks)
	if err != nil {
		return 0, 0, err
	}
	e2g, err = formalGLMPhase19TranscriptCheckedAddV1(e2g, term)
	return g2e, e2g, err
}

func formalGLMPhase19BuildTranscriptCircuitV1(kind, source string,
	multiplicity uint64, circ *circuit.Circuit) (
	formalGLMPhase19TranscriptCircuitV1, error) {
	var zero formalGLMPhase19TranscriptCircuitV1
	if kind == "" || source == "" || multiplicity == 0 || circ == nil ||
		circ.NumGates < 0 || circ.NumGates != len(circ.Gates) ||
		len(circ.Inputs) != 2 || len(circ.Outputs) != 1 ||
		circ.Outputs.Size() < 1 {
		return zero, fmt.Errorf("formal-glm: invalid transcript circuit inventory")
	}
	garblerBits := uint64(circ.Inputs[0].Type.Bits)
	evaluatorBits := uint64(circ.Inputs[1].Type.Bits)
	outputBits := uint64(circ.Outputs.Size())
	gates, cost := uint64(circ.NumGates), circ.Cost()
	g2e, err := formalGLMPhase19TranscriptPackG2EV1(
		circ, garblerBits, evaluatorBits, outputBits)
	if err != nil {
		return zero, err
	}
	e2g, err := formalGLMPhase19TranscriptPackE2GV1(evaluatorBits)
	if err != nil {
		return zero, err
	}
	wantG2E, wantE2G, err := formalGLMPhase19TranscriptPlainFormulaV1(
		gates, cost, garblerBits, evaluatorBits, outputBits)
	if err != nil {
		return zero, err
	}
	if g2e.plain != wantG2E || e2g.plain != wantE2G {
		return zero, fmt.Errorf("formal-glm: exact-GC transcript ABI formula drift")
	}
	g2ePhysical, err := g2e.physical()
	if err != nil {
		return zero, err
	}
	e2gPhysical, err := e2g.physical()
	if err != nil {
		return zero, err
	}
	digest := sha256.Sum256([]byte(source))
	return formalGLMPhase19TranscriptCircuitV1{
		Kind: kind, CircuitSourceSHA256: hex.EncodeToString(digest[:]),
		Multiplicity: multiplicity, Gates: gates,
		CompilerRelativeCost: cost,
		GarblerInputBits:     garblerBits, EvaluatorInputBits: evaluatorBits,
		OutputBits:    outputBits,
		G2EPlainBytes: g2e.plain, E2GPlainBytes: e2g.plain,
		G2EPhysicalBytes: g2ePhysical, E2GPhysicalBytes: e2gPhysical,
		G2ERecordCount: g2e.records, E2GRecordCount: e2g.records,
	}, nil
}

func formalGLMPhase19CanonicalPreSourceDPForLatticeV1(
	plan formalGLMPhase15Plan, lattice int) (
	formalGLMCanonicalPreSourceDPV1, error) {
	var zero formalGLMCanonicalPreSourceDPV1
	evidence, err := buildFormalGLMPreSourceDPProjectionForLatticeV1(
		plan, lattice)
	if err != nil {
		return zero, err
	}
	canonicalPlanSHA256, err := formalGLMPhase21CanonicalPlanSHA256(plan)
	if err != nil {
		return zero, err
	}
	result := formalGLMCanonicalPreSourceDPV1{
		Version:             formalGLMCanonicalPreSourceDPVersion,
		Purpose:             formalGLMCanonicalPreSourceDPPurpose,
		CanonicalPlanSHA256: canonicalPlanSHA256,
		SnapshotSHA256:      evidence.SnapshotSHA256,
		PinsetSHA256:        evidence.PinsetSHA256,
		Family:              evidence.Family, Adjacency: evidence.Adjacency,
		SourceFractionBits: evidence.SourceFracBits,
		OutputLatticeBits:  evidence.OutputLatticeBits,
		QuantizationShift:  evidence.QuantizationShift,
		CoordinateCount:    evidence.CoordinateCount,
		ShiftedUpperBounds: append([]string(nil),
			evidence.ShiftedUpperBounds...),
		SelectedSensitivitySteps:       evidence.SelectedSensitivitySteps,
		SelectedSensitivityProof:       evidence.SelectedSensitivityProof,
		Quantization:                   evidence.Quantization,
		BoundsSHA256:                   evidence.BoundsSHA256,
		QuantizationSHA256:             evidence.QuantizationSHA256,
		TransportCoordinateOrderSHA256: evidence.CoordinateOrderSHA256,
	}
	if err := formalGLMValidateCanonicalPreSourceDPV1(result); err != nil {
		return zero, err
	}
	return result, nil
}

func formalGLMPhase19ValidateTranscriptDPV1(plan formalGLMPhase15Plan,
	dp formalGLMCanonicalPreSourceDPV1) error {
	if err := formalGLMValidateCanonicalPreSourceDPV1(dp); err != nil {
		return err
	}
	want, err := formalGLMPhase19CanonicalPreSourceDPForLatticeV1(
		plan, dp.OutputLatticeBits)
	if err != nil {
		return err
	}
	wantBytes, err := json.Marshal(want)
	if err != nil {
		return err
	}
	gotBytes, err := json.Marshal(dp)
	if err != nil {
		return err
	}
	if !bytes.Equal(wantBytes, gotBytes) {
		return fmt.Errorf("formal-glm: canonical pre-source DP does not bind transcript shape")
	}
	return nil
}

func formalGLMPhase19TranscriptShapeContextV1(plan formalGLMPhase15Plan) (
	formalGLMPhase19Context, error) {
	pre := sha256.Sum256([]byte(
		formalGLMPhase19TranscriptBoundDomain + "/shape-only-pre-execution"))
	root := sha256.Sum256([]byte(
		formalGLMPhase19TranscriptBoundDomain + "/shape-only-materialization"))
	return formalGLMPhase19BuildContext(
		plan, hex.EncodeToString(pre[:]), hex.EncodeToString(root[:]))
}

func formalGLMPhase19TranscriptDPBridgeShapeV1(plan formalGLMPhase15Plan,
	dp formalGLMCanonicalPreSourceDPV1) formalGLMPhase15DPBridgePlan {
	return formalGLMPhase15DPBridgePlan{
		Version:        formalGLMPhase15DPBridgeVersion,
		SourceRingBits: plan.RingBits, SourceFracBits: dp.SourceFractionBits,
		OutputRingBits: 128, OutputLatticeBits: dp.OutputLatticeBits,
		QuantizationShift:  dp.QuantizationShift,
		CoordinateCount:    dp.CoordinateCount,
		ShiftedUpperBounds: append([]string(nil), dp.ShiftedUpperBounds...),
	}
}

func formalGLMPhase19TranscriptAddCircuitV1(
	inventory *[]formalGLMPhase19TranscriptCircuitV1, kind, source string,
	multiplicity uint64, circ *circuit.Circuit) error {
	for index := range *inventory {
		if (*inventory)[index].Kind != kind {
			continue
		}
		candidate, err := formalGLMPhase19BuildTranscriptCircuitV1(
			kind, source, 1, circ)
		if err != nil {
			return err
		}
		existing := (*inventory)[index]
		candidate.Multiplicity = existing.Multiplicity
		if !reflect.DeepEqual(existing, candidate) {
			return fmt.Errorf("formal-glm: conflicting transcript circuit kind")
		}
		total, err := formalGLMPhase19TranscriptCheckedAddV1(
			existing.Multiplicity, multiplicity)
		if err != nil {
			return err
		}
		(*inventory)[index].Multiplicity = total
		return nil
	}
	item, err := formalGLMPhase19BuildTranscriptCircuitV1(
		kind, source, multiplicity, circ)
	if err != nil {
		return err
	}
	*inventory = append(*inventory, item)
	return nil
}

func formalGLMPhase19TranscriptAddAccumulatorLevelV1(
	inventory *[]formalGLMPhase19TranscriptCircuitV1, kind string,
	states uint64) (uint64, error) {
	groups, err := formalGLMPhase19TranscriptCeilDivV1(
		states, formalGLMPhase19AccumulatorMaxFanIn)
	if err != nil {
		return 0, err
	}
	full := states / formalGLMPhase19AccumulatorMaxFanIn
	remainder := states % formalGLMPhase19AccumulatorMaxFanIn
	add := func(count int, multiplicity uint64) error {
		var source string
		var sourceErr error
		if kind == "leaf" {
			source, sourceErr = formalGLMPhase19AccumulatorLeafCircuitSource(count)
		} else {
			source, sourceErr = formalGLMPhase19AccumulatorStateCircuitSource(count)
		}
		if sourceErr != nil {
			return sourceErr
		}
		circ, compileErr := compileFormalGLMPhase19BoundedAccumulator(kind, count)
		if compileErr != nil {
			return compileErr
		}
		return formalGLMPhase19TranscriptAddCircuitV1(inventory,
			fmt.Sprintf("phase19-execution-accumulator/%s/%d", kind, count),
			source, multiplicity, circ)
	}
	if full > 0 {
		if err := add(formalGLMPhase19AccumulatorMaxFanIn, full); err != nil {
			return 0, err
		}
	}
	if remainder > 0 {
		if err := add(int(remainder), 1); err != nil {
			return 0, err
		}
	}
	return groups, nil
}

func formalGLMPhase19TranscriptInventoryV1(plan formalGLMPhase15Plan,
	dp formalGLMCanonicalPreSourceDPV1) (
	[]formalGLMPhase19TranscriptCircuitV1, error) {
	ctx, err := formalGLMPhase19TranscriptShapeContextV1(plan)
	if err != nil {
		return nil, err
	}
	inventory := make([]formalGLMPhase19TranscriptCircuitV1, 0, 10)
	lastRows, err := formalGLMPhase19RowsInBlock(plan, plan.TotalBlocks-1)
	if err != nil {
		return nil, err
	}
	fullBlocks := uint64(plan.TotalBlocks)
	if lastRows < plan.BlockCapacity {
		fullBlocks--
	}
	if fullBlocks > 0 {
		source, err := formalGLMPhase19BlockCircuitSource(plan, ctx, 0)
		if err != nil {
			return nil, err
		}
		circ, err := compileFormalGLMPhase19Block(plan, ctx, 0)
		if err != nil {
			return nil, err
		}
		if err := formalGLMPhase19TranscriptAddCircuitV1(&inventory,
			"phase19-protected-fanin/full", source, fullBlocks, circ); err != nil {
			return nil, err
		}
	}
	if lastRows < plan.BlockCapacity {
		index := plan.TotalBlocks - 1
		source, err := formalGLMPhase19BlockCircuitSource(plan, ctx, index)
		if err != nil {
			return nil, err
		}
		circ, err := compileFormalGLMPhase19Block(plan, ctx, index)
		if err != nil {
			return nil, err
		}
		if err := formalGLMPhase19TranscriptAddCircuitV1(&inventory,
			fmt.Sprintf("phase19-protected-fanin/final-partial/%d", lastRows),
			source, 1, circ); err != nil {
			return nil, err
		}
	}
	states := uint64(plan.TotalBlocks)
	states, err = formalGLMPhase19TranscriptAddAccumulatorLevelV1(
		&inventory, "leaf", states)
	if err != nil {
		return nil, err
	}
	for states > 1 {
		states, err = formalGLMPhase19TranscriptAddAccumulatorLevelV1(
			&inventory, "state", states)
		if err != nil {
			return nil, err
		}
	}
	finalSource := formalGLMPhase19AccumulatorFinalCircuitSource()
	finalCircuit, err := compileFormalGLMPhase19BoundedAccumulator("final", 1)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase19TranscriptAddCircuitV1(&inventory,
		"phase19-execution-accumulator/final/1", finalSource, 1,
		finalCircuit); err != nil {
		return nil, err
	}
	blockSource, err := formalGLMPhase15BlockCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	blockCircuit, err := compileFormalGLMPhase15Block(plan)
	if err != nil {
		return nil, err
	}
	blockMultiplicity, err := formalGLMPhase19TranscriptCheckedMulV1(
		uint64(plan.TotalBlocks), uint64(plan.Iterations))
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase19TranscriptAddCircuitV1(&inventory,
		"phase15-optimizer/block", blockSource, blockMultiplicity,
		blockCircuit); err != nil {
		return nil, err
	}
	finalizeSource, err := formalGLMPhase15FinalizeCircuitSource(plan)
	if err != nil {
		return nil, err
	}
	finalizeCircuit, err := compileFormalGLMPhase15Finalize(plan)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase19TranscriptAddCircuitV1(&inventory,
		"phase15-optimizer/finalize", finalizeSource, uint64(plan.Iterations),
		finalizeCircuit); err != nil {
		return nil, err
	}
	bridge := formalGLMPhase19TranscriptDPBridgeShapeV1(plan, dp)
	bridgeSource, err := formalGLMPhase15DPBridgeCircuitSource(plan, bridge)
	if err != nil {
		return nil, err
	}
	bridgeCircuit, err := compileFormalGLMPhase15DPBridge(plan, bridge)
	if err != nil {
		return nil, err
	}
	if err := formalGLMPhase19TranscriptAddCircuitV1(&inventory,
		"phase15-dp-bridge", bridgeSource, 1, bridgeCircuit); err != nil {
		return nil, err
	}
	sort.Slice(inventory, func(left, right int) bool {
		return inventory[left].Kind < inventory[right].Kind
	})
	for index := 1; index < len(inventory); index++ {
		if inventory[index-1].Kind >= inventory[index].Kind {
			return nil, fmt.Errorf("formal-glm: non-canonical transcript inventory")
		}
	}
	return inventory, nil
}

func formalGLMPhase19TranscriptInventorySHA256V1(
	inventory []formalGLMPhase19TranscriptCircuitV1) (string, error) {
	if len(inventory) == 0 {
		return "", fmt.Errorf("formal-glm: empty transcript circuit inventory")
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase19TranscriptInventoryDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase19TranscriptShapeSHA256V1(
	bound formalGLMPhase19TranscriptBoundV1) (string, error) {
	bound.ShapeSHA256 = ""
	encoded, err := json.Marshal(bound)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase19TranscriptBoundDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase19TranscriptAccumulateV1(total *uint64, value,
	multiplicity uint64) error {
	product, err := formalGLMPhase19TranscriptCheckedMulV1(value, multiplicity)
	if err != nil {
		return err
	}
	*total, err = formalGLMPhase19TranscriptCheckedAddV1(*total, product)
	return err
}

func formalGLMPhase19BuildTranscriptBoundV1(plan formalGLMPhase15Plan,
	dp formalGLMCanonicalPreSourceDPV1) (
	formalGLMPhase19TranscriptBoundV1, error) {
	var zero formalGLMPhase19TranscriptBoundV1
	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		return zero, err
	}
	if err := formalGLMPhase19ValidateTranscriptDPV1(plan, dp); err != nil {
		return zero, err
	}
	wireABI, err := formalGLMPhase19TranscriptWireABISHA256V1()
	if err != nil {
		return zero, err
	}
	dpSHA256, err := formalGLMCanonicalPreSourceDPSHA256V1(dp)
	if err != nil {
		return zero, err
	}
	inventory, err := formalGLMPhase19TranscriptInventoryV1(plan, dp)
	if err != nil {
		return zero, err
	}
	inventorySHA256, err := formalGLMPhase19TranscriptInventorySHA256V1(inventory)
	if err != nil {
		return zero, err
	}
	bound := formalGLMPhase19TranscriptBoundV1{
		Version:                    formalGLMPhase19TranscriptBoundVersion,
		Purpose:                    formalGLMPhase19TranscriptBoundPurpose,
		WireBoundVersion:           formalGLMPhase19ExactGCWireBoundVersion,
		WireABISHA256:              wireABI,
		CanonicalPlanSHA256:        dp.CanonicalPlanSHA256,
		CanonicalPreSourceDPSHA256: dpSHA256,
		CircuitInventorySHA256:     inventorySHA256,
		CircuitInventory:           inventory,
	}
	for _, item := range inventory {
		for _, field := range []struct {
			total *uint64
			value uint64
		}{
			{&bound.G2EPlainBytes, item.G2EPlainBytes},
			{&bound.E2GPlainBytes, item.E2GPlainBytes},
			{&bound.G2EPhysicalBytes, item.G2EPhysicalBytes},
			{&bound.E2GPhysicalBytes, item.E2GPhysicalBytes},
		} {
			if err := formalGLMPhase19TranscriptAccumulateV1(
				field.total, field.value, item.Multiplicity); err != nil {
				return zero, err
			}
		}
		if err := formalGLMPhase19TranscriptAccumulateV1(
			&bound.UniqueRecordCount, item.G2ERecordCount,
			item.Multiplicity); err != nil {
			return zero, err
		}
		if err := formalGLMPhase19TranscriptAccumulateV1(
			&bound.UniqueRecordCount, item.E2GRecordCount,
			item.Multiplicity); err != nil {
			return zero, err
		}
	}
	bound.TotalPhysicalBytes, err = formalGLMPhase19TranscriptCheckedAddV1(
		bound.G2EPhysicalBytes, bound.E2GPhysicalBytes)
	if err != nil {
		return zero, err
	}
	// The spool normally coalesces several records into one 1 MiB segment.
	// At an interactive read boundary it may publish sooner, so one published
	// chunk per authenticated record is the closed, configuration-free maximum.
	bound.MaxUniqueChunks = bound.UniqueRecordCount
	bound.ShapeSHA256, err = formalGLMPhase19TranscriptShapeSHA256V1(bound)
	if err != nil {
		return zero, err
	}
	return bound, nil
}

func formalGLMPhase19ValidateTranscriptBoundV1(
	bound formalGLMPhase19TranscriptBoundV1, plan formalGLMPhase15Plan,
	dp formalGLMCanonicalPreSourceDPV1) error {
	want, err := formalGLMPhase19BuildTranscriptBoundV1(plan, dp)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bound, want) {
		return fmt.Errorf("formal-glm: invalid exact-GC Phase-1.9 transcript bound")
	}
	return nil
}
