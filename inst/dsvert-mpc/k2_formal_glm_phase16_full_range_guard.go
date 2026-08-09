package main

// Exact pre-noise range gate for the formal independent-full fallback.
//
// The scalable sampler deliberately works on additive shares and therefore
// cannot itself tell whether Phase-1.9 supplied the invalid upper+1 sentinel.
// Before either complete noise draw is admitted, this fixed-shape GC checks
// 0 <= x_i <= U_i for every coordinate.  It emits only one XOR-shared bit;
// neither source values nor a per-coordinate predicate are opened.  The
// durable finalizer consumes that bit before it reconstructs any DP value.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

const (
	formalGLMPhase16FullRangeGuardVersion        = "dsvert-formal-glm-phase16-independent-full-range-guard-v1"
	formalGLMPhase16FullRangeGuardDomain         = "dsVert/formal-glm/phase16/independent-full-range-guard/v1"
	formalGLMPhase16FullRangeGuardPurpose        = "formal-glm-independent-full-pre-noise-range-gate-v1"
	formalGLMPhase16FullRangeGuardMaxCoordinates = exactGCMaxVectorLen / 2
)

type formalGLMPhase16FullRangeGuardReceipt struct {
	Version                 string `json:"version"`
	BackendSelectionSHA256  string `json:"backend_selection_sha256"`
	FullContractSHA256      string `json:"full_contract_sha256"`
	ReleaseInstanceID       string `json:"release_instance_id"`
	ReleaseContractSHA256   string `json:"release_contract_sha256"`
	SourceBindingSHA256     string `json:"source_binding_sha256"`
	SessionContextSHA256    string `json:"session_context_sha256"`
	PeerName                string `json:"peer_name"`
	Role                    string `json:"role"`
	ChunkStart              int    `json:"chunk_start"`
	CoordinateCount         int    `json:"coordinate_count"`
	ValidityShareSHA256     string `json:"validity_share_sha256"`
	ProtectedSourceExposed  bool   `json:"protected_source_exposed"`
	ValidityPredicateOpened bool   `json:"validity_predicate_opened"`
	Signature               []byte `json:"signature"`
	validityShare           byte
}

func formalGLMPhase16FullRangeGuardSession(
	base exactGCSession, selectionSHA256, fullContractSHA256 string,
	chunkStart, coordinateCount int,
) (exactGCSession, error) {
	if !formalGLMIsSHA256(selectionSHA256) ||
		!formalGLMIsSHA256(fullContractSHA256) ||
		coordinateCount < 1 ||
		coordinateCount > formalGLMPhase16FullRangeGuardMaxCoordinates ||
		chunkStart < 0 {
		return exactGCSession{}, fmt.Errorf("formal-glm: invalid range-guard geometry")
	}
	// Release-stable session identity makes a crash/retry reproduce the same
	// private validity shares.  The full release/selection digests and absolute
	// chunk geometry make it unique across semantic releases; transport retries
	// cannot request a new mask or cause a durable-input conflict.
	base.SessionID = sha256.Sum256([]byte(fmt.Sprintf(
		"%s/session|selection=%s|contract=%s|start=%d|count=%d",
		formalGLMPhase16FullRangeGuardDomain, selectionSHA256,
		fullContractSHA256, chunkStart, coordinateCount)))
	base.Purpose = fmt.Sprintf("%s|selection=%s|contract=%s|start=%d|count=%d",
		formalGLMPhase16FullRangeGuardPurpose, selectionSHA256,
		fullContractSHA256, chunkStart, coordinateCount)
	base.Spec = exactGCCircuitSpec{
		Operation: exactGCCountGuard, RingBits: 128, FracBits: 0,
		Threshold: big.NewInt(1), VectorLen: 2 * coordinateCount,
	}
	if err := base.validate(); err != nil {
		return exactGCSession{}, err
	}
	return base, nil
}

func formalGLMPhase16FullRangeGuardInputs(shares []*big.Int,
	upperBounds []string, garbler bool,
) ([]*big.Int, error) {
	if len(shares) < 1 || len(shares) != len(upperBounds) ||
		len(shares) > formalGLMPhase16FullRangeGuardMaxCoordinates {
		return nil, fmt.Errorf("formal-glm: invalid range-guard source shape")
	}
	mask := exactGCMask(128)
	result := make([]*big.Int, 0, 2*len(shares))
	for _, share := range shares {
		if share == nil || share.Sign() < 0 || share.BitLen() > 128 {
			return nil, fmt.Errorf("formal-glm: invalid Ring128 range-guard share")
		}
		result = append(result, new(big.Int).Set(share))
	}
	for index, share := range shares {
		upper, ok := new(big.Int).SetString(upperBounds[index], 10)
		if !ok || upper.Sign() < 0 || upper.Cmp(exactGCMaxSigned(128)) > 0 {
			return nil, fmt.Errorf("formal-glm: invalid range-guard upper bound")
		}
		value := new(big.Int).Neg(share)
		if garbler {
			value.Add(value, upper)
		}
		value.And(value, mask)
		result = append(result, value)
	}
	return result, nil
}

func formalGLMPhase16FullRangeGuardMask(maskRoot [32]byte,
	session exactGCSession,
) (*big.Int, error) {
	if maskRoot == ([32]byte{}) {
		return nil, fmt.Errorf("formal-glm: missing persistent range-guard mask root")
	}
	context := exactGCContextDigest(session)
	mac := hmac.New(sha256.New, maskRoot[:])
	mac.Write([]byte(formalGLMPhase16FullRangeGuardDomain + "/validity-mask"))
	mac.Write(context[:])
	return new(big.Int).SetUint64(uint64(mac.Sum(nil)[0] & 1)), nil
}

func formalGLMPhase16FullRangeGuardReceiptMessage(
	receipt formalGLMPhase16FullRangeGuardReceipt,
) ([]byte, error) {
	if receipt.Version != formalGLMPhase16FullRangeGuardVersion ||
		!formalGLMIsSHA256(receipt.BackendSelectionSHA256) ||
		!formalGLMIsSHA256(receipt.FullContractSHA256) ||
		!formalGLMIsSHA256(receipt.ReleaseInstanceID) ||
		!formalGLMIsSHA256(receipt.ReleaseContractSHA256) ||
		!formalGLMIsSHA256(receipt.SourceBindingSHA256) ||
		!formalGLMIsSHA256(receipt.SessionContextSHA256) ||
		!formalGLMIsSHA256(receipt.ValidityShareSHA256) ||
		!jointDPBiomedicalGaussianValidPeerName(receipt.PeerName) ||
		(receipt.Role != "garbler" && receipt.Role != "evaluator") ||
		receipt.ChunkStart < 0 || receipt.CoordinateCount < 1 ||
		receipt.CoordinateCount > formalGLMPhase16FullRangeGuardMaxCoordinates ||
		receipt.ProtectedSourceExposed || receipt.ValidityPredicateOpened {
		return nil, fmt.Errorf("formal-glm: invalid range-guard receipt")
	}
	unsigned := receipt
	unsigned.Signature = nil
	unsigned.validityShare = 0
	return jointDPBiomedicalGaussianDomainMessage(
		formalGLMPhase16FullRangeGuardDomain, unsigned)
}

func formalGLMPhase16BuildFullRangeGuardReceipt(
	admission jointDPBiomedicalGaussianFullAdmission,
	session exactGCSession, sourceBindingSHA256, peerName, role string,
	chunkStart, coordinateCount int, validityShare *big.Int,
	signer ed25519.PrivateKey,
) (formalGLMPhase16FullRangeGuardReceipt, error) {
	var zero formalGLMPhase16FullRangeGuardReceipt
	if admission.formalSelection == nil || validityShare == nil ||
		validityShare.Sign() < 0 || validityShare.BitLen() > 1 ||
		len(signer) != ed25519.PrivateKeySize {
		return zero, fmt.Errorf("formal-glm: invalid range-guard receipt input")
	}
	selectionSHA256, err := formalGLMPhase16BackendSelectionSHA256(
		*admission.formalSelection)
	if err != nil {
		return zero, err
	}
	contract := admission.selection.Contract
	contractDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullSelectionDomain, contract)
	if err != nil {
		return zero, err
	}
	context := exactGCContextDigest(session)
	shareDigest := sha256.Sum256([]byte{
		byte(validityShare.Uint64()),
	})
	receipt := formalGLMPhase16FullRangeGuardReceipt{
		Version:                formalGLMPhase16FullRangeGuardVersion,
		BackendSelectionSHA256: selectionSHA256,
		FullContractSHA256:     hex.EncodeToString(contractDigest[:]),
		ReleaseInstanceID:      contract.ReleaseInstanceID,
		ReleaseContractSHA256:  contract.ReleaseContractSHA256,
		SourceBindingSHA256:    sourceBindingSHA256,
		SessionContextSHA256:   hex.EncodeToString(context[:]),
		PeerName:               peerName, Role: role,
		ChunkStart: chunkStart, CoordinateCount: coordinateCount,
		ValidityShareSHA256:    hex.EncodeToString(shareDigest[:]),
		ProtectedSourceExposed: false, ValidityPredicateOpened: false,
		validityShare: byte(validityShare.Uint64()),
	}
	message, err := formalGLMPhase16FullRangeGuardReceiptMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(signer, message)
	return receipt, nil
}

func formalGLMPhase16ValidateFullRangeGuardReceipt(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	receipt formalGLMPhase16FullRangeGuardReceipt,
	sourceBindingSHA256, role string,
) error {
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return err
	}
	if admission.formalBinding == nil ||
		receipt.SourceBindingSHA256 != sourceBindingSHA256 ||
		receipt.Role != role || receipt.validityShare > 1 {
		return fmt.Errorf("formal-glm: substituted range-guard receipt")
	}
	selectionSHA256, selectionErr :=
		formalGLMPhase16BackendSelectionSHA256(*admission.formalSelection)
	contractDigest, contractErr := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullSelectionDomain,
		admission.selection.Contract)
	binding := admission.formalBinding
	wantPeer := binding.GarblerPeerName
	if role == "evaluator" {
		wantPeer = binding.EvaluatorPeerName
	}
	shareDigest := sha256.Sum256([]byte{receipt.validityShare})
	message, err := formalGLMPhase16FullRangeGuardReceiptMessage(receipt)
	pin := pins[receipt.PeerName]
	if err != nil || selectionErr != nil || contractErr != nil ||
		receipt.BackendSelectionSHA256 != selectionSHA256 ||
		receipt.FullContractSHA256 != hex.EncodeToString(contractDigest[:]) ||
		receipt.ReleaseInstanceID !=
			admission.selection.Contract.ReleaseInstanceID ||
		receipt.ReleaseContractSHA256 !=
			admission.selection.Contract.ReleaseContractSHA256 ||
		receipt.PeerName != wantPeer ||
		receipt.ValidityShareSHA256 != hex.EncodeToString(shareDigest[:]) ||
		len(pin) != ed25519.PublicKeySize ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, message, receipt.Signature) {
		return fmt.Errorf("formal-glm: range-guard receipt authentication failed")
	}
	return nil
}

func formalGLMPhase16RunFullRangeGuardGarbler(rw io.ReadWriter,
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey, session exactGCSession,
	shares []*big.Int, upperBounds []string, sourceBindingSHA256 string,
	chunkStart int, maskRoot [32]byte, signer ed25519.PrivateKey,
) (formalGLMPhase16FullRangeGuardReceipt, error) {
	var zero formalGLMPhase16FullRangeGuardReceipt
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	input, err := formalGLMPhase16FullRangeGuardInputs(
		shares, upperBounds, true)
	if err != nil {
		return zero, err
	}
	mask, err := formalGLMPhase16FullRangeGuardMask(maskRoot, session)
	if err != nil {
		return zero, err
	}
	output, err := exactGCRunGarblerWithOutputShares(
		rw, session, input, []*big.Int{mask})
	if err != nil {
		return zero, err
	}
	return formalGLMPhase16BuildFullRangeGuardReceipt(
		admission, session, sourceBindingSHA256,
		admission.formalBinding.GarblerPeerName, "garbler", chunkStart,
		len(shares), output[0], signer)
}

func formalGLMPhase16RunFullRangeGuardEvaluator(rw io.ReadWriter,
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey, session exactGCSession,
	shares []*big.Int, upperBounds []string, sourceBindingSHA256 string,
	chunkStart int, signer ed25519.PrivateKey,
) (formalGLMPhase16FullRangeGuardReceipt, error) {
	var zero formalGLMPhase16FullRangeGuardReceipt
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return zero, err
	}
	input, err := formalGLMPhase16FullRangeGuardInputs(
		shares, upperBounds, false)
	if err != nil {
		return zero, err
	}
	output, err := exactGCRunEvaluator(rw, session, input)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase16BuildFullRangeGuardReceipt(
		admission, session, sourceBindingSHA256,
		admission.formalBinding.EvaluatorPeerName, "evaluator", chunkStart,
		len(shares), output[0], signer)
}
