package main

// Sealed runtime chain:
//
//   common sticky one-draw sampler -> exact Cox GC -> purpose-bound provenance
//   receipt -> common durable one-opening finalizer.
//
// No intermediate is reconstructed.  The provenance receipt is required
// because the generic one-draw chunk receipt alone cannot prove that its
// payload was post-processed by the Cox circuit.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"reflect"
)

const (
	formalCoxRuntimeExecutionReceiptVersion = "dsvert-formal-cox-runtime-execution-receipt-v1"
	formalCoxRuntimeExecutionReceiptDomain  = "dsVert/formal-cox/runtime-execution-receipt/v1"
	formalCoxRuntimeNoiseTransform          = "sampler_garbler_subtracts_public_support_center_mod_2_128_then_circuit_sign_lifts_v1"
	formalCoxRuntimeFinalCarrierRule        = "reduce_ring2k_shares_mod_2_128_shift_garbler_by_beta_bound_first_p_then_public_zero_padding_v1"
)

var formalCoxRuntimeExecutionBlockers = []string{
	"semi_honest_pinned_two_compute_peer_gc_only_v1",
	"malicious_secure_proof_of_gc_execution_unavailable_v1",
	"end_to_end_nonlinear_numeric_error_certificate_incomplete_v1",
	"dp_safe_identification_certificate_unavailable_v1",
	"r_dsi_server_to_peer_end_to_end_not_executed_v1",
}

type formalCoxRuntimeSamplerRoleChunk struct {
	EnvelopeIndex   int                                          `json:"envelope_index"`
	Role            string                                       `json:"role"`
	RawOutputShares []*big.Int                                   `json:"-"`
	NoiseShares     []*big.Int                                   `json:"-"`
	ValidityShare   bool                                         `json:"-"`
	OutputReceipt   jointDPBiomedicalGaussianOneDrawChunkReceipt `json:"output_receipt"`
}

type formalCoxRuntimeExecutionReceipt struct {
	Version                       string   `json:"version"`
	Domain                        string   `json:"domain"`
	PolicySHA256                  string   `json:"policy_sha256"`
	CoxCircuitSHA256              string   `json:"cox_circuit_sha256"`
	CoxPurpose                    string   `json:"cox_purpose"`
	CoxSessionID                  string   `json:"cox_session_id"`
	ReleaseInstanceID             string   `json:"release_instance_id"`
	ReleaseContractSHA256         string   `json:"release_contract_sha256"`
	ProductiveStreamSHA256        string   `json:"productive_stream_sha256"`
	SamplerEnvelopeSetSHA256      string   `json:"sampler_envelope_set_sha256"`
	SamplerOutputReceiptSetSHA256 string   `json:"sampler_output_receipt_set_sha256"`
	SourceFanInReceiptSHA256      string   `json:"source_fan_in_receipt_sha256"`
	NoiseTransform                string   `json:"noise_transform"`
	NoiseCenter                   string   `json:"noise_center"`
	SamplerChunkCount             int      `json:"sampler_chunk_count"`
	SamplerValidityShareCount     int      `json:"sampler_validity_share_count"`
	CoxInputShareSHA256           string   `json:"cox_input_share_sha256"`
	CoxOutputShareSHA256          string   `json:"cox_output_share_sha256"`
	OutputRingBits                int      `json:"output_ring_bits"`
	CoefficientCount              int      `json:"coefficient_count"`
	ValidityXORShare              int      `json:"validity_xor_share"`
	FinalCarrierRule              string   `json:"final_carrier_rule"`
	FinalCoefficientShift         string   `json:"final_coefficient_shift"`
	FinalCarrierCoordinateCount   int      `json:"final_carrier_coordinate_count"`
	PeerName                      string   `json:"peer_name"`
	PeerID                        string   `json:"peer_id"`
	Role                          string   `json:"role"`
	ExactIntermediateOpenings     int      `json:"exact_intermediate_openings"`
	ProductionReady               bool     `json:"production_ready"`
	Blockers                      []string `json:"blockers"`
	Signature                     []byte   `json:"signature"`
}

type formalCoxRuntimeCoxRoleResult struct {
	Role             string                             `json:"role"`
	Session          exactGCSession                     `json:"-"`
	InputShares      []*big.Int                         `json:"-"`
	Sampler          []formalCoxRuntimeSamplerRoleChunk `json:"-"`
	SourceFanIn      formalCoxRuntimeSourceFanIn        `json:"-"`
	Output           formalCoxSealedOutput              `json:"-"`
	ExecutionReceipt formalCoxRuntimeExecutionReceipt   `json:"execution_receipt"`
}

type formalCoxRuntimeFinalRoleChunk struct {
	EnvelopeIndex int                                          `json:"envelope_index"`
	Shares        []*big.Int                                   `json:"-"`
	Receipt       jointDPBiomedicalGaussianOneDrawChunkReceipt `json:"receipt"`
}

type formalCoxRuntimeFinalRoleSchedule struct {
	Role      string                           `json:"role"`
	CoxResult formalCoxRuntimeCoxRoleResult    `json:"-"`
	Chunks    []formalCoxRuntimeFinalRoleChunk `json:"chunks"`
}

type formalCoxRuntimeRelease struct {
	Version                  string                                        `json:"version"`
	ReleaseInstanceID        string                                        `json:"release_instance_id"`
	PolicySHA256             string                                        `json:"policy_sha256"`
	NumericCertificate       formalCoxRuntimeNumericCertificate            `json:"numeric_certificate"`
	NumericCertificateSHA256 string                                        `json:"numeric_certificate_sha256"`
	ScaledCoefficients       []string                                      `json:"scaled_coefficients"`
	FracBits                 int                                           `json:"frac_bits"`
	CommonRelease            jointDPBiomedicalGaussianOneDrawCommonRelease `json:"common_release"`
	RuntimeNoiseConnected    bool                                          `json:"runtime_noise_connected"`
	ProvenanceConnected      bool                                          `json:"provenance_connected"`
	DurableOpeningConnected  bool                                          `json:"durable_opening_connected"`
	CommonLedgerVerified     bool                                          `json:"common_ledger_verified"`
	OpeningCount             int                                           `json:"opening_count"`
	ProductionReady          bool                                          `json:"production_ready"`
	Blockers                 []string                                      `json:"blockers"`
}

func formalCoxRuntimeSamplerSession(
	envelope jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot, master [32]byte,
) (exactGCSession, error) {
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(envelope, trust)
	if err != nil {
		return exactGCSession{}, err
	}
	sessionID, err := jointDPGaussianOneDrawDecodeHex(
		envelope.Preimage.RunNonceSHA256, "formal Cox sampler run nonce")
	if err != nil {
		return exactGCSession{}, err
	}
	session := exactGCSession{
		SessionID: sessionID, MasterKey: master,
		GarblerID: spec.GarblerPeerID, EvaluatorID: spec.EvaluatorPeerID,
		Purpose: spec.purpose(),
		Spec: exactGCCircuitSpec{
			Operation: jointDPGaussianOneDrawOperation,
			RingBits:  128, FracBits: 0, VectorLen: spec.CoordinateCount,
		},
	}
	if err := jointDPGaussianOneDrawValidateSession(session, spec); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func formalCoxRuntimeRunSamplerRoleChunk(rw io.ReadWriter,
	admission formalCoxRuntimeAdmission, envelopeIndex int, role string,
	master [32]byte, privateSeed string, signer ed25519.PrivateKey,
) (formalCoxRuntimeSamplerRoleChunk, error) {
	var zero formalCoxRuntimeSamplerRoleChunk
	if envelopeIndex < 0 || envelopeIndex >= len(admission.Envelopes) ||
		(role != "garbler" && role != "evaluator") {
		return zero, fmt.Errorf("formal-cox: invalid sampler chunk role")
	}
	envelope := admission.Envelopes[envelopeIndex]
	session, err := formalCoxRuntimeSamplerSession(
		envelope, admission.Trust, master)
	if err != nil {
		return zero, err
	}
	center, ok := new(big.Int).SetString(admission.NoiseCenter, 10)
	if !ok || center.Sign() < 0 {
		return zero, fmt.Errorf("formal-cox: invalid sampler support center")
	}
	values := make([]*big.Int, envelope.Preimage.CoordinateCount)
	for index := range values {
		values[index] = new(big.Int)
		if role == "garbler" {
			values[index].Set(center)
		}
	}
	sourceShare, err := exactGCEncodeWorkerCanonicalShares(values, session.Spec)
	exactGCZeroBigInts(values)
	if err != nil {
		return zero, err
	}
	peerName := envelope.Preimage.GarblerPeerName
	if role == "evaluator" {
		peerName = envelope.Preimage.EvaluatorPeerName
	}
	local, err := jointDPBiomedicalGaussianBuildLocalSourceBinding(
		envelope.Preimage, admission.Binding.SnapshotSHA256,
		admission.Binding.SourceFanInTranscriptSHA256,
		peerName, role, sourceShare)
	if err != nil {
		return zero, err
	}
	var raw []*big.Int
	if role == "garbler" {
		raw, err = jointDPBiomedicalGaussianRunProductiveGarbler(
			rw, envelope, admission.Trust, local, session, sourceShare, privateSeed)
	} else {
		raw, err = jointDPBiomedicalGaussianRunProductiveEvaluator(
			rw, envelope, admission.Trust, local, session, sourceShare, privateSeed)
	}
	if err != nil {
		return zero, err
	}
	if len(raw) != envelope.Preimage.CoordinateCount+1 ||
		raw[len(raw)-1] == nil || raw[len(raw)-1].BitLen() > 1 {
		exactGCZeroBigInts(raw)
		return zero, fmt.Errorf("formal-cox: malformed sampler sealed output")
	}
	receipt, err := jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
		envelope, admission.Trust, role, raw, signer)
	if err != nil {
		exactGCZeroBigInts(raw)
		return zero, err
	}
	mask := exactGCMask(128)
	noise := make([]*big.Int, envelope.Preimage.CoordinateCount)
	for index := range noise {
		noise[index] = new(big.Int).Set(raw[index])
		if role == "garbler" {
			noise[index].Sub(noise[index], center)
			noise[index].And(noise[index], mask)
		}
	}
	return formalCoxRuntimeSamplerRoleChunk{
		EnvelopeIndex: envelopeIndex, Role: role,
		RawOutputShares: raw, NoiseShares: noise,
		ValidityShare: raw[len(raw)-1].Bit(0) == 1,
		OutputReceipt: receipt,
	}, nil
}

func formalCoxRuntimeAssembleCoxRoleInput(admission formalCoxRuntimeAdmission,
	role string, sourcePrefix []*big.Int,
	samplers []formalCoxRuntimeSamplerRoleChunk,
) ([]*big.Int, error) {
	if role != "garbler" && role != "evaluator" {
		return nil, fmt.Errorf("formal-cox: invalid Cox input role")
	}
	prefixCount := admission.Phase1Plan.RowCoordinates +
		admission.Phase1Plan.ZeroBlindCoordinates
	if len(sourcePrefix) != prefixCount || len(samplers) != len(admission.Envelopes) {
		return nil, fmt.Errorf("formal-cox: incomplete Cox source/noise schedule")
	}
	result := make([]*big.Int, 0, admission.Phase1Plan.InputCoordinates)
	for index, value := range sourcePrefix {
		bits := admission.Phase1Plan.RingBits
		if index < admission.Phase1Plan.RowCoordinates {
			bits = 128
		}
		if value == nil || value.Sign() < 0 || value.BitLen() > bits {
			exactGCZeroBigInts(result)
			return nil, fmt.Errorf("formal-cox: source share outside its materializer ring")
		}
		result = append(result, new(big.Int).Set(value))
	}
	center, _ := new(big.Int).SetString(admission.NoiseCenter, 10)
	mask128 := exactGCMask(128)
	validity := make([]*big.Int, 0, len(samplers))
	next := 0
	for index, sampler := range samplers {
		if sampler.EnvelopeIndex != index || sampler.Role != role ||
			index >= len(admission.Envelopes) {
			exactGCZeroBigInts(result)
			exactGCZeroBigInts(validity)
			return nil, fmt.Errorf("formal-cox: reordered sampler handoff")
		}
		envelope := admission.Envelopes[index]
		if envelope.Preimage.ChunkStart != next ||
			len(sampler.RawOutputShares) != envelope.Preimage.CoordinateCount+1 ||
			len(sampler.NoiseShares) != envelope.Preimage.CoordinateCount {
			exactGCZeroBigInts(result)
			exactGCZeroBigInts(validity)
			return nil, fmt.Errorf("formal-cox: malformed sampler handoff")
		}
		payload, validityByte, err :=
			jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
				envelope, admission.Trust, sampler.OutputReceipt, role,
				sampler.RawOutputShares)
		if err != nil {
			exactGCZeroBigInts(result)
			exactGCZeroBigInts(validity)
			return nil, err
		}
		clear(payload)
		if (validityByte == 1) != sampler.ValidityShare {
			exactGCZeroBigInts(result)
			exactGCZeroBigInts(validity)
			return nil, fmt.Errorf("formal-cox: sampler validity substitution")
		}
		for local := range sampler.NoiseShares {
			expected := new(big.Int).Set(sampler.RawOutputShares[local])
			if role == "garbler" {
				expected.Sub(expected, center)
				expected.And(expected, mask128)
			}
			if expected.Cmp(sampler.NoiseShares[local]) != 0 ||
				sampler.NoiseShares[local].Sign() < 0 ||
				sampler.NoiseShares[local].BitLen() > 128 {
				exactGCZeroBigInts(result)
				exactGCZeroBigInts(validity)
				return nil, fmt.Errorf("formal-cox: sampler-to-noise transform mismatch")
			}
			result = append(result, new(big.Int).Set(sampler.NoiseShares[local]))
		}
		validity = append(validity, new(big.Int).SetUint64(
			boolToUint64(sampler.ValidityShare)))
		next += envelope.Preimage.CoordinateCount
	}
	result = append(result, validity...)
	if next != admission.DPPlan.NoiseCoordinates ||
		len(result) != admission.Phase1Plan.InputCoordinates {
		exactGCZeroBigInts(result)
		return nil, fmt.Errorf("formal-cox: incomplete assembled Cox input")
	}
	if err := exactGCValidateShares(result, exactGCCircuitSpec{
		Operation: exactGCFormalCoxIterations,
		RingBits:  admission.Phase1Plan.RingBits,
		FracBits:  admission.Policy.FracBits,
		VectorLen: admission.Phase1Plan.InputCoordinates,
	}); err != nil {
		exactGCZeroBigInts(result)
		return nil, err
	}
	return result, nil
}

func formalCoxRuntimeAssembleCoxRoleInputFromFanIn(
	admission formalCoxRuntimeAdmission, role string,
	source formalCoxRuntimeSourceFanIn,
	samplers []formalCoxRuntimeSamplerRoleChunk,
) ([]*big.Int, error) {
	if err := formalCoxRuntimeValidateSourceFanIn(
		admission, role, source); err != nil {
		return nil, err
	}
	prefix := make([]*big.Int, 0, admission.Phase1Plan.RowCoordinates+
		admission.Phase1Plan.ZeroBlindCoordinates)
	for _, value := range source.AggregateShares {
		prefix = append(prefix, new(big.Int).Set(value))
	}
	for index := 0; index < admission.Phase1Plan.ZeroBlindCoordinates; index++ {
		prefix = append(prefix, new(big.Int))
	}
	result, err := formalCoxRuntimeAssembleCoxRoleInput(
		admission, role, prefix, samplers)
	exactGCZeroBigInts(prefix)
	return result, err
}

func formalCoxRuntimeEnvelopeSetSHA256(
	admission formalCoxRuntimeAdmission) (string, error) {
	type entry struct {
		PreimageSHA256  string `json:"preimage_sha256"`
		CircuitSHA256   string `json:"circuit_sha256"`
		ChunkStart      int    `json:"chunk_start"`
		CoordinateCount int    `json:"coordinate_count"`
	}
	entries := make([]entry, len(admission.Envelopes))
	for index, envelope := range admission.Envelopes {
		if _, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
			envelope, admission.Trust); err != nil {
			return "", err
		}
		preimageSHA256, err := jointDPBiomedicalGaussianEnvelopePreimageSHA256(
			envelope.Preimage)
		if err != nil {
			return "", err
		}
		entries[index] = entry{
			PreimageSHA256:  preimageSHA256,
			CircuitSHA256:   envelope.WorkerPolicy.CircuitDigest,
			ChunkStart:      envelope.Preimage.ChunkStart,
			CoordinateCount: envelope.Preimage.CoordinateCount,
		}
	}
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		formalCoxRuntimeExecutionReceiptDomain+"/sampler-envelopes", entries)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxRuntimeSamplerReceiptSetSHA256(role string,
	samplers []formalCoxRuntimeSamplerRoleChunk) (string, error) {
	receipts := make([]jointDPBiomedicalGaussianOneDrawChunkReceipt,
		len(samplers))
	for index, sampler := range samplers {
		if sampler.Role != role || sampler.EnvelopeIndex != index {
			return "", fmt.Errorf("formal-cox: invalid sampler receipt order")
		}
		receipts[index] = sampler.OutputReceipt
	}
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		formalCoxRuntimeExecutionReceiptDomain+"/sampler-output-receipts/"+role,
		receipts)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxRuntimeShareSHA256(domain, role string, values []*big.Int,
	spec exactGCCircuitSpec, validity *bool) (string, error) {
	encoded, err := exactGCEncodeWorkerCanonicalShares(values, spec)
	if err != nil {
		return "", err
	}
	validityValue := -1
	if validity != nil {
		validityValue = int(boolToUint64(*validity))
	}
	digest, err := jointDPBiomedicalGaussianDomainDigest(domain, struct {
		Role          string `json:"role"`
		EncodedShares string `json:"encoded_shares"`
		ValidityShare int    `json:"validity_share"`
	}{role, encoded, validityValue})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxRuntimeCircuitSHA256(policy formalCoxPhase1Policy,
	ringBits int) (string, error) {
	source, err := formalCoxCircuitSource(policy, ringBits)
	if err != nil {
		return "", err
	}
	digest := formalCoxSHA256Domain("dsVert/formal-cox/runtime-circuit-source/v1|",
		[]byte(source))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxRuntimeExecutionReceiptBase(admission formalCoxRuntimeAdmission,
	role string, session exactGCSession, inputShares []*big.Int,
	source formalCoxRuntimeSourceFanIn,
	samplers []formalCoxRuntimeSamplerRoleChunk, output formalCoxSealedOutput,
) (formalCoxRuntimeExecutionReceipt, error) {
	var zero formalCoxRuntimeExecutionReceipt
	if role != "garbler" && role != "evaluator" ||
		len(inputShares) != admission.Phase1Plan.InputCoordinates ||
		len(output.CoefficientShares) != admission.Policy.CovariateCount {
		return zero, fmt.Errorf("formal-cox: malformed execution provenance")
	}
	if _, _, err := validateFormalCoxSession(session, admission.Policy); err != nil {
		return zero, err
	}
	// Revalidate the complete authenticated source fan-in, sampler chain and
	// exact transformation. The zero-beta blinding lanes are created locally;
	// no caller or relay supplies them.
	reassembled, err := formalCoxRuntimeAssembleCoxRoleInputFromFanIn(
		admission, role, source, samplers)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(reassembled, inputShares) {
		exactGCZeroBigInts(reassembled)
		return zero, fmt.Errorf("formal-cox: provenance input differs from sampler chain")
	}
	exactGCZeroBigInts(reassembled)
	policyDigest, err := formalCoxPolicyDigest(admission.Policy)
	if err != nil {
		return zero, err
	}
	circuitSHA256, err := formalCoxRuntimeCircuitSHA256(
		admission.Policy, admission.Phase1Plan.RingBits)
	if err != nil {
		return zero, err
	}
	envelopeSetSHA256, err := formalCoxRuntimeEnvelopeSetSHA256(admission)
	if err != nil {
		return zero, err
	}
	receiptSetSHA256, err := formalCoxRuntimeSamplerReceiptSetSHA256(
		role, samplers)
	if err != nil {
		return zero, err
	}
	sourceFanInSHA256, err := formalCoxRuntimeSourceFanInSHA256(source)
	if err != nil {
		return zero, err
	}
	inputSHA256, err := formalCoxRuntimeShareSHA256(
		formalCoxRuntimeExecutionReceiptDomain+"/cox-input", role,
		inputShares, session.Spec, nil)
	if err != nil {
		return zero, err
	}
	outputSpec := exactGCCircuitSpec{
		Operation: exactGCFormalCoxIterations,
		RingBits:  session.Spec.RingBits, FracBits: session.Spec.FracBits,
		VectorLen: admission.Policy.CovariateCount,
	}
	outputSHA256, err := formalCoxRuntimeShareSHA256(
		formalCoxRuntimeExecutionReceiptDomain+"/cox-output", role,
		output.CoefficientShares, outputSpec, &output.ValidityShare)
	if err != nil {
		return zero, err
	}
	peerName, peerID := admission.Roles.GarblerPeerName,
		admission.Roles.GarblerPeerID
	if role == "evaluator" {
		peerName, peerID = admission.Roles.EvaluatorPeerName,
			admission.Roles.EvaluatorPeerID
	}
	return formalCoxRuntimeExecutionReceipt{
		Version:          formalCoxRuntimeExecutionReceiptVersion,
		Domain:           formalCoxRuntimeExecutionReceiptDomain,
		PolicySHA256:     hex.EncodeToString(policyDigest[:]),
		CoxCircuitSHA256: circuitSHA256, CoxPurpose: session.Purpose,
		CoxSessionID:                  hex.EncodeToString(session.SessionID[:]),
		ReleaseInstanceID:             admission.Binding.ReleaseInstanceID,
		ReleaseContractSHA256:         admission.Binding.ReleaseContractSHA256,
		ProductiveStreamSHA256:        admission.Envelopes[0].Preimage.ProductiveStreamSHA256,
		SamplerEnvelopeSetSHA256:      envelopeSetSHA256,
		SamplerOutputReceiptSetSHA256: receiptSetSHA256,
		SourceFanInReceiptSHA256:      sourceFanInSHA256,
		NoiseTransform:                formalCoxRuntimeNoiseTransform,
		NoiseCenter:                   admission.NoiseCenter,
		SamplerChunkCount:             len(samplers),
		SamplerValidityShareCount:     len(samplers),
		CoxInputShareSHA256:           inputSHA256,
		CoxOutputShareSHA256:          outputSHA256,
		OutputRingBits:                session.Spec.RingBits,
		CoefficientCount:              admission.Policy.CovariateCount,
		ValidityXORShare:              int(boolToUint64(output.ValidityShare)),
		FinalCarrierRule:              formalCoxRuntimeFinalCarrierRule,
		FinalCoefficientShift:         admission.FinalCoefficientShift,
		FinalCarrierCoordinateCount:   admission.DPPlan.NoiseCoordinates,
		PeerName:                      peerName, PeerID: peerID, Role: role,
		ExactIntermediateOpenings: 0, ProductionReady: false,
		Blockers: append([]string(nil), formalCoxRuntimeExecutionBlockers...),
	}, nil
}

func formalCoxRuntimeExecutionReceiptMessage(
	receipt formalCoxRuntimeExecutionReceipt) ([]byte, error) {
	unsigned := receipt
	unsigned.Signature = nil
	noiseCenter, noiseCenterOK := new(big.Int).SetString(receipt.NoiseCenter, 10)
	coefficientShift, coefficientShiftOK := new(big.Int).SetString(
		receipt.FinalCoefficientShift, 10)
	if receipt.Version != formalCoxRuntimeExecutionReceiptVersion ||
		receipt.Domain != formalCoxRuntimeExecutionReceiptDomain ||
		!formalCoxIsSHA256(receipt.PolicySHA256) ||
		!formalCoxIsSHA256(receipt.CoxCircuitSHA256) ||
		!formalCoxIsSHA256(receipt.CoxSessionID) ||
		!formalCoxIsSHA256(receipt.ReleaseInstanceID) ||
		!formalCoxIsSHA256(receipt.ReleaseContractSHA256) ||
		!formalCoxIsSHA256(receipt.ProductiveStreamSHA256) ||
		!formalCoxIsSHA256(receipt.SamplerEnvelopeSetSHA256) ||
		!formalCoxIsSHA256(receipt.SamplerOutputReceiptSetSHA256) ||
		!formalCoxIsSHA256(receipt.SourceFanInReceiptSHA256) ||
		!formalCoxIsSHA256(receipt.CoxInputShareSHA256) ||
		!formalCoxIsSHA256(receipt.CoxOutputShareSHA256) ||
		receipt.NoiseTransform != formalCoxRuntimeNoiseTransform ||
		receipt.FinalCarrierRule != formalCoxRuntimeFinalCarrierRule ||
		!noiseCenterOK || noiseCenter.Sign() < 0 ||
		noiseCenter.String() != receipt.NoiseCenter ||
		!coefficientShiftOK || coefficientShift.Sign() <= 0 ||
		coefficientShift.String() != receipt.FinalCoefficientShift ||
		receipt.SamplerChunkCount < 1 ||
		receipt.SamplerValidityShareCount != receipt.SamplerChunkCount ||
		receipt.OutputRingBits < 128 || receipt.CoefficientCount < 1 ||
		receipt.FinalCarrierCoordinateCount < receipt.CoefficientCount ||
		(receipt.ValidityXORShare != 0 && receipt.ValidityXORShare != 1) ||
		(receipt.Role != "garbler" && receipt.Role != "evaluator") ||
		!jointDPBiomedicalGaussianValidPeerName(receipt.PeerName) ||
		!jointDPGaussianOneDrawPinnedPeer.MatchString(receipt.PeerID) ||
		exactGCValidateLabel("formal Cox purpose", receipt.CoxPurpose, 512) != nil ||
		receipt.ExactIntermediateOpenings != 0 || receipt.ProductionReady ||
		!reflect.DeepEqual(receipt.Blockers, formalCoxRuntimeExecutionBlockers) {
		return nil, fmt.Errorf("formal-cox: invalid execution provenance receipt")
	}
	return jointDPBiomedicalGaussianDomainMessage(
		formalCoxRuntimeExecutionReceiptDomain, unsigned)
}

func formalCoxRuntimeBuildExecutionReceipt(admission formalCoxRuntimeAdmission,
	role string, session exactGCSession, inputShares []*big.Int,
	source formalCoxRuntimeSourceFanIn,
	samplers []formalCoxRuntimeSamplerRoleChunk, output formalCoxSealedOutput,
	signer ed25519.PrivateKey,
) (formalCoxRuntimeExecutionReceipt, error) {
	receipt, err := formalCoxRuntimeExecutionReceiptBase(
		admission, role, session, inputShares, source, samplers, output)
	if err != nil {
		return formalCoxRuntimeExecutionReceipt{}, err
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(admission.Trust)
	if err != nil {
		return formalCoxRuntimeExecutionReceipt{}, err
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(public, pins[receipt.PeerName]) {
		return formalCoxRuntimeExecutionReceipt{},
			fmt.Errorf("formal-cox: execution receipt signer is not pinned")
	}
	message, err := formalCoxRuntimeExecutionReceiptMessage(receipt)
	if err != nil {
		return formalCoxRuntimeExecutionReceipt{}, err
	}
	receipt.Signature = ed25519.Sign(signer, message)
	return receipt, nil
}

func formalCoxRuntimeValidateExecutionReceipt(admission formalCoxRuntimeAdmission,
	result formalCoxRuntimeCoxRoleResult) error {
	want, err := formalCoxRuntimeExecutionReceiptBase(
		admission, result.Role, result.Session, result.InputShares,
		result.SourceFanIn, result.Sampler, result.Output)
	if err != nil {
		return err
	}
	got := result.ExecutionReceipt
	signature := append([]byte(nil), got.Signature...)
	got.Signature = nil
	if !reflect.DeepEqual(got, want) || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("formal-cox: execution provenance mismatch")
	}
	message, err := formalCoxRuntimeExecutionReceiptMessage(want)
	if err != nil {
		return err
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(admission.Trust)
	if err != nil || !ed25519.Verify(pins[want.PeerName], message, signature) {
		return fmt.Errorf("formal-cox: execution provenance signature failed")
	}
	return nil
}

func formalCoxRuntimeRunCoxRole(rw io.ReadWriter,
	admission formalCoxRuntimeAdmission, role string, session exactGCSession,
	source formalCoxRuntimeSourceFanIn,
	samplers []formalCoxRuntimeSamplerRoleChunk,
	signer ed25519.PrivateKey,
) (formalCoxRuntimeCoxRoleResult, error) {
	var zero formalCoxRuntimeCoxRoleResult
	inputShares, err := formalCoxRuntimeAssembleCoxRoleInputFromFanIn(
		admission, role, source, samplers)
	if err != nil {
		return zero, err
	}
	var output formalCoxSealedOutput
	if role == "garbler" {
		output, err = runFormalCoxGarbler(
			rw, session, admission.Policy, inputShares)
	} else if role == "evaluator" {
		output, err = runFormalCoxEvaluator(
			rw, session, admission.Policy, inputShares)
	} else {
		return zero, fmt.Errorf("formal-cox: invalid execution role")
	}
	if err != nil {
		exactGCZeroBigInts(inputShares)
		return zero, err
	}
	receipt, err := formalCoxRuntimeBuildExecutionReceipt(
		admission, role, session, inputShares, source, samplers, output, signer)
	if err != nil {
		exactGCZeroBigInts(inputShares)
		exactGCZeroBigInts(output.CoefficientShares)
		return zero, err
	}
	return formalCoxRuntimeCoxRoleResult{
		Role: role, Session: session,
		InputShares: append([]*big.Int(nil), inputShares...),
		Sampler:     append([]formalCoxRuntimeSamplerRoleChunk(nil), samplers...),
		SourceFanIn: source,
		Output:      output, ExecutionReceipt: receipt,
	}, nil
}

func formalCoxRuntimeFinalCarrierShares(role string,
	output formalCoxSealedOutput, coefficientCount, total int, shift *big.Int,
) ([]*big.Int, error) {
	if (role != "garbler" && role != "evaluator") ||
		shift == nil || shift.Sign() <= 0 || coefficientCount < 1 ||
		coefficientCount > total || len(output.CoefficientShares) != coefficientCount {
		return nil, fmt.Errorf("formal-cox: invalid final carrier input")
	}
	carrier := make([]*big.Int, total)
	mask128 := exactGCMask(128)
	for index := range carrier {
		carrier[index] = new(big.Int)
		if index < coefficientCount {
			if output.CoefficientShares[index] == nil ||
				output.CoefficientShares[index].Sign() < 0 {
				exactGCZeroBigInts(carrier)
				return nil, fmt.Errorf("formal-cox: invalid coefficient output share")
			}
			carrier[index].Set(output.CoefficientShares[index])
			carrier[index].And(carrier[index], mask128)
			if role == "garbler" {
				carrier[index].Add(carrier[index], shift)
				carrier[index].And(carrier[index], mask128)
			}
		}
	}
	return carrier, nil
}

func formalCoxRuntimeBuildFinalRoleSchedule(admission formalCoxRuntimeAdmission,
	result formalCoxRuntimeCoxRoleResult, signer ed25519.PrivateKey,
) (formalCoxRuntimeFinalRoleSchedule, error) {
	var zero formalCoxRuntimeFinalRoleSchedule
	if err := formalCoxRuntimeValidateExecutionReceipt(admission, result); err != nil {
		return zero, err
	}
	shift, ok := new(big.Int).SetString(admission.FinalCoefficientShift, 10)
	if !ok || shift.Sign() <= 0 {
		return zero, fmt.Errorf("formal-cox: invalid final carrier shift")
	}
	total := admission.DPPlan.NoiseCoordinates
	carrier, err := formalCoxRuntimeFinalCarrierShares(
		result.Role, result.Output, admission.Policy.CovariateCount, total, shift)
	if err != nil {
		return zero, err
	}
	chunks := make([]formalCoxRuntimeFinalRoleChunk, len(admission.Envelopes))
	for index, envelope := range admission.Envelopes {
		start, count := envelope.Preimage.ChunkStart,
			envelope.Preimage.CoordinateCount
		shares := make([]*big.Int, 0, count+1)
		for local := 0; local < count; local++ {
			shares = append(shares, new(big.Int).Set(carrier[start+local]))
		}
		shares = append(shares, new(big.Int).SetUint64(
			boolToUint64(result.Output.ValidityShare)))
		receipt, err := jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
			envelope, admission.Trust, result.Role, shares, signer)
		if err != nil {
			exactGCZeroBigInts(carrier)
			for prior := 0; prior < index; prior++ {
				exactGCZeroBigInts(chunks[prior].Shares)
			}
			return zero, err
		}
		chunks[index] = formalCoxRuntimeFinalRoleChunk{
			EnvelopeIndex: index, Shares: shares, Receipt: receipt}
	}
	exactGCZeroBigInts(carrier)
	return formalCoxRuntimeFinalRoleSchedule{
		Role: result.Role, CoxResult: result, Chunks: chunks,
	}, nil
}

func formalCoxRuntimePairFinalHandoffs(admission formalCoxRuntimeAdmission,
	garbler, evaluator formalCoxRuntimeFinalRoleSchedule,
) ([]jointDPBiomedicalGaussianOneDrawChunkHandoff, error) {
	if garbler.Role != "garbler" || evaluator.Role != "evaluator" ||
		len(garbler.Chunks) != len(admission.Envelopes) ||
		len(evaluator.Chunks) != len(admission.Envelopes) ||
		formalCoxRuntimeValidateExecutionReceipt(admission, garbler.CoxResult) != nil ||
		formalCoxRuntimeValidateExecutionReceipt(admission, evaluator.CoxResult) != nil {
		return nil, fmt.Errorf("formal-cox: invalid final provenance schedules")
	}
	leftReceipt, rightReceipt := garbler.CoxResult.ExecutionReceipt,
		evaluator.CoxResult.ExecutionReceipt
	if leftReceipt.PolicySHA256 != rightReceipt.PolicySHA256 ||
		leftReceipt.CoxCircuitSHA256 != rightReceipt.CoxCircuitSHA256 ||
		leftReceipt.CoxPurpose != rightReceipt.CoxPurpose ||
		leftReceipt.CoxSessionID != rightReceipt.CoxSessionID ||
		leftReceipt.ReleaseInstanceID != rightReceipt.ReleaseInstanceID ||
		leftReceipt.SamplerEnvelopeSetSHA256 !=
			rightReceipt.SamplerEnvelopeSetSHA256 {
		return nil, fmt.Errorf("formal-cox: peer provenance receipts disagree")
	}
	result := make([]jointDPBiomedicalGaussianOneDrawChunkHandoff,
		len(admission.Envelopes))
	for index, envelope := range admission.Envelopes {
		left, right := garbler.Chunks[index], evaluator.Chunks[index]
		if left.EnvelopeIndex != index || right.EnvelopeIndex != index {
			return nil, fmt.Errorf("formal-cox: final carrier chunks reordered")
		}
		if _, _, err := jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
			envelope, admission.Trust, left.Receipt, "garbler", left.Shares); err != nil {
			return nil, err
		}
		if _, _, err := jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
			envelope, admission.Trust, right.Receipt, "evaluator", right.Shares); err != nil {
			return nil, err
		}
		result[index] = jointDPBiomedicalGaussianOneDrawChunkHandoff{
			Envelope: envelope, Garbler: left.Receipt, Evaluator: right.Receipt,
			GarblerShares: left.Shares, EvaluatorShares: right.Shares,
		}
	}
	return result, nil
}

func formalCoxRuntimeDecodeCommonRelease(admission formalCoxRuntimeAdmission,
	common jointDPBiomedicalGaussianOneDrawCommonRelease,
) (formalCoxRuntimeRelease, error) {
	var zero formalCoxRuntimeRelease
	if err := jointDPBiomedicalGaussianValidateOneDrawCommonRelease(
		admission.Envelopes, admission.Trust, common); err != nil {
		return zero, err
	}
	if len(common.ClampedScaledValues) != admission.DPPlan.NoiseCoordinates ||
		common.OpeningsPerformed != 1 || common.ProductionReady {
		return zero, fmt.Errorf("formal-cox: invalid common carrier release")
	}
	shift, ok := new(big.Int).SetString(admission.FinalCoefficientShift, 10)
	if !ok || shift.Sign() <= 0 {
		return zero, fmt.Errorf("formal-cox: invalid final coefficient shift")
	}
	doubleShift := new(big.Int).Mul(big.NewInt(2), shift)
	coefficients := make([]string, admission.Policy.CovariateCount)
	normSquared := new(big.Int)
	for index, text := range common.ClampedScaledValues {
		value, err := jointDPBiomedicalGaussianParseCanonicalInt(
			text, "formal Cox final carrier", false)
		if err != nil {
			return zero, err
		}
		if index >= admission.Policy.CovariateCount {
			if value.Sign() != 0 {
				return zero, fmt.Errorf("formal-cox: non-zero final carrier padding")
			}
			continue
		}
		if value.Cmp(doubleShift) > 0 {
			return zero, fmt.Errorf("formal-cox: final coefficient outside projection bound")
		}
		coefficient := new(big.Int).Sub(value, shift)
		coefficients[index] = coefficient.String()
		normSquared.Add(normSquared,
			new(big.Int).Mul(new(big.Int).Set(coefficient), coefficient))
	}
	if normSquared.Cmp(new(big.Int).Mul(
		new(big.Int).Set(shift), shift)) > 0 {
		return zero, fmt.Errorf("formal-cox: final coefficient vector exceeds L2 projection")
	}
	policyDigest, _ := formalCoxPolicyDigest(admission.Policy)
	return formalCoxRuntimeRelease{
		Version:                  "dsvert-formal-cox-runtime-release-v1",
		ReleaseInstanceID:        admission.Binding.ReleaseInstanceID,
		PolicySHA256:             hex.EncodeToString(policyDigest[:]),
		NumericCertificate:       admission.NumericCertificate,
		NumericCertificateSHA256: admission.NumericCertificateSHA256,
		ScaledCoefficients:       coefficients, FracBits: admission.Policy.FracBits,
		CommonRelease:         common,
		RuntimeNoiseConnected: true, ProvenanceConnected: true,
		DurableOpeningConnected: true,
		CommonLedgerVerified:    admission.CommonLedgerVerified,
		OpeningCount:            1,
		ProductionReady:         false,
		Blockers:                append([]string(nil), formalCoxRuntimeExecutionBlockers...),
	}, nil
}
