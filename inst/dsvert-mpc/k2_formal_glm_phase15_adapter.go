package main

// Phase 1.5 producer and K-to-two fan-in adapter for the sealed formal GLM.
//
// This file deliberately exposes no command handler.  A relay only transports
// signed ciphertext envelopes.  It cannot substitute a source share, change a
// recipient, mix blocks/runs, or omit a custodian without detection.  As in the
// underlying exact-GC backend, a deliberately dishonest data custodian can
// still lie about its own source data; preventing that requires an attested
// source or a malicious-secure input proof and is outside the pinned,
// semi-honest threat model.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"sync"
)

const (
	formalGLMPhase15ApprovalDomain = "dsVert/formal-glm/phase15/plan-approval/v1"
	formalGLMPhase15EnvelopeDomain = "dsVert/formal-glm/phase15/source-envelope/v1"
	formalGLMPhase15PairDomain     = "dsVert/formal-glm/phase15/source-pair/v1"
	formalGLMPhase15FanInDomain    = "dsVert/formal-glm/phase15/fan-in-root/v1"
	formalGLMPhase15PacketVersion  = "dsvert-formal-glm-phase15-source-packet-v1"
)

type formalGLMPhase15Approval struct {
	Signer    string `json:"signer"`
	Signature []byte `json:"signature"`
}

// formalGLMPhase15SourceEnvelope contains only public routing metadata and an
// IND-CCA authenticated ciphertext.  PairCommitment binds the two recipient
// ciphertexts without hashing a low-entropy patient value.
type formalGLMPhase15SourceEnvelope struct {
	Version        string `json:"version"`
	PlanSHA256     string `json:"plan_sha256"`
	RunID          string `json:"run_id"`
	Custodian      string `json:"custodian"`
	Recipient      string `json:"recipient"`
	BlockIndex     int    `json:"block_index"`
	TotalBlocks    int    `json:"total_blocks"`
	RowsInBlock    int    `json:"rows_in_block"`
	RingBits       int    `json:"ring_bits"`
	PayloadSHA256  string `json:"payload_sha256"`
	PairCommitment string `json:"pair_commitment"`
	Ciphertext     []byte `json:"ciphertext"`
	Signature      []byte `json:"signature"`
}

type formalGLMPhase15FanInResult struct {
	PlanSHA256     string
	Recipient      string
	BlockIndex     int
	Shares         []*big.Int
	PairCommitment map[string]string
	EnvelopeSHA256 map[string]string
	CipherSHA256   map[string]string
	FanInRoot      string
	verified       bool
}

// The ledger is deliberately not a request counter.  It memoizes the unique
// signed packet occupying a semantic source slot.  An identical retry is
// idempotent forever; a conflicting retry fails closed.
type formalGLMPhase15ReplayLedger struct {
	mu      sync.Mutex
	entries map[string][32]byte
	path    string
	key     [32]byte
}

func newFormalGLMPhase15ReplayLedger() *formalGLMPhase15ReplayLedger {
	return &formalGLMPhase15ReplayLedger{entries: make(map[string][32]byte)}
}

func formalGLMPhase15AppendBytes(dst []byte, value []byte) []byte {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...)
}

func formalGLMPhase15AppendString(dst []byte, value string) []byte {
	return formalGLMPhase15AppendBytes(dst, []byte(value))
}

func formalGLMPhase15AppendUint64(dst []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(dst, encoded[:]...)
}

func formalGLMPhase15ApprovalMessage(plan formalGLMPhase15Plan) ([]byte, error) {
	digest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	message := formalGLMPhase15AppendString(nil, formalGLMPhase15ApprovalDomain)
	return append(message, digest[:]...), nil
}

func formalGLMPhase15SignPlan(plan formalGLMPhase15Plan, signer string,
	privateKey ed25519.PrivateKey) (formalGLMPhase15Approval, error) {

	if err := exactGCValidateLabel("formal GLM plan signer", signer, 256); err != nil {
		return formalGLMPhase15Approval{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return formalGLMPhase15Approval{}, fmt.Errorf("formal-glm: invalid plan signing key")
	}
	message, err := formalGLMPhase15ApprovalMessage(plan)
	if err != nil {
		return formalGLMPhase15Approval{}, err
	}
	return formalGLMPhase15Approval{
		Signer: signer, Signature: ed25519.Sign(privateKey, message)}, nil
}

func formalGLMPhase15VerifyPlanApprovals(plan formalGLMPhase15Plan,
	approvals []formalGLMPhase15Approval,
	pins map[string]ed25519.PublicKey) error {

	if err := validateFormalGLMPhase15Plan(plan); err != nil {
		return err
	}
	if len(approvals) != len(plan.Kernel.CustodianPeers) {
		return fmt.Errorf("formal-glm: plan is not unanimously approved")
	}
	message, err := formalGLMPhase15ApprovalMessage(plan)
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(plan.Kernel.CustodianPeers))
	for _, peer := range plan.Kernel.CustodianPeers {
		want[peer] = true
	}
	seen := make(map[string]bool, len(approvals))
	for _, approval := range approvals {
		publicKey, ok := pins[approval.Signer]
		if !ok || !want[approval.Signer] || seen[approval.Signer] ||
			len(publicKey) != ed25519.PublicKeySize ||
			len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(publicKey, message, approval.Signature) {
			return fmt.Errorf("formal-glm: invalid or duplicate plan approval")
		}
		seen[approval.Signer] = true
	}
	return nil
}

func formalGLMPhase15EnvelopeUnsignedBytes(
	envelope formalGLMPhase15SourceEnvelope) []byte {

	result := formalGLMPhase15AppendString(nil, formalGLMPhase15EnvelopeDomain)
	for _, value := range []string{
		envelope.Version, envelope.PlanSHA256, envelope.RunID,
		envelope.Custodian, envelope.Recipient, envelope.PayloadSHA256,
		envelope.PairCommitment,
	} {
		result = formalGLMPhase15AppendString(result, value)
	}
	for _, value := range []int{
		envelope.BlockIndex, envelope.TotalBlocks, envelope.RowsInBlock,
		envelope.RingBits,
	} {
		result = formalGLMPhase15AppendUint64(result, uint64(value))
	}
	return formalGLMPhase15AppendBytes(result, envelope.Ciphertext)
}

func formalGLMPhase15EnvelopeDigest(
	envelope formalGLMPhase15SourceEnvelope) [32]byte {
	return sha256.Sum256(formalGLMPhase15EnvelopeUnsignedBytes(envelope))
}

func formalGLMPhase15PairCommitment(planHash, runID, custodian string,
	blockIndex int, recipients []string, ciphertexts map[string][]byte) (string, error) {
	hashes := make(map[string]string, len(ciphertexts))
	for recipient, ciphertext := range ciphertexts {
		digest := sha256.Sum256(ciphertext)
		hashes[recipient] = hex.EncodeToString(digest[:])
	}
	return formalGLMPhase15PairCommitmentFromHashes(planHash, runID,
		custodian, blockIndex, recipients, hashes)
}

func formalGLMPhase15PairCommitmentFromHashes(planHash, runID, custodian string,
	blockIndex int, recipients []string, hashes map[string]string) (string, error) {

	if len(recipients) != 2 || recipients[0] == recipients[1] ||
		!sort.StringsAreSorted(recipients) {
		return "", fmt.Errorf("formal-glm: invalid source-pair recipients")
	}
	message := formalGLMPhase15AppendString(nil, formalGLMPhase15PairDomain)
	for _, value := range []string{planHash, runID, custodian} {
		message = formalGLMPhase15AppendString(message, value)
	}
	message = formalGLMPhase15AppendUint64(message, uint64(blockIndex))
	for _, recipient := range recipients {
		hash, ok := hashes[recipient]
		if !ok || !formalGLMIsSHA256(hash) {
			return "", fmt.Errorf("formal-glm: incomplete source-pair ciphertexts")
		}
		digest, _ := hex.DecodeString(hash)
		message = formalGLMPhase15AppendString(message, recipient)
		message = append(message, digest...)
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase15FanInRoot(plan formalGLMPhase15Plan, planHash string,
	blockIndex int, commitments map[string]string) (string, error) {
	if len(commitments) != len(plan.Kernel.CustodianPeers) {
		return "", fmt.Errorf("formal-glm: incomplete fan-in commitment set")
	}
	message := formalGLMPhase15AppendString(nil, formalGLMPhase15FanInDomain)
	message = formalGLMPhase15AppendString(message, planHash)
	message = formalGLMPhase15AppendString(message, plan.RunID)
	message = formalGLMPhase15AppendUint64(message, uint64(blockIndex))
	for _, custodian := range plan.Kernel.CustodianPeers {
		commitment := commitments[custodian]
		if !formalGLMIsSHA256(commitment) {
			return "", fmt.Errorf("formal-glm: invalid fan-in pair commitment")
		}
		message = formalGLMPhase15AppendString(message, custodian)
		message = formalGLMPhase15AppendString(message, commitment)
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase15EncodeRecords(values []*big.Int, ringBits int) ([]byte, error) {
	if ringBits < 128 || ringBits > exactGCMaxRingBits {
		return nil, fmt.Errorf("formal-glm: invalid source ring")
	}
	width := exactGCRecordBytes(ringBits)
	result := make([]byte, width*len(values))
	modulus := exactGCModulus(ringBits)
	for i, value := range values {
		if value == nil || value.Sign() < 0 || value.Cmp(modulus) >= 0 {
			return nil, fmt.Errorf("formal-glm: non-canonical source residue")
		}
		record, err := exactGCBigLittleEndian(value, width)
		if err != nil {
			return nil, err
		}
		copy(result[i*width:], record)
	}
	return result, nil
}

func formalGLMPhase15DecodeRecords(encoded []byte, count, ringBits int) ([]*big.Int, error) {
	width := exactGCRecordBytes(ringBits)
	if count < 1 || len(encoded) != count*width {
		return nil, fmt.Errorf("formal-glm: source payload shape mismatch")
	}
	result := make([]*big.Int, count)
	for i := range result {
		result[i] = exactGCLittleEndianBig(encoded[i*width : (i+1)*width])
		if result[i].BitLen() > ringBits {
			return nil, fmt.Errorf("formal-glm: source payload is outside Ring%d", ringBits)
		}
	}
	return result, nil
}

// formalGLMPhase15ProduceBlock is the server-authoritative adapter boundary.
// localValues is a full fixed-shape block; every coordinate not assigned to
// custodian by the signed plan must be exactly zero.
func formalGLMPhase15ProduceBlock(plan formalGLMPhase15Plan,
	approvals []formalGLMPhase15Approval, identityPins map[string]ed25519.PublicKey,
	custodian string, signingKey ed25519.PrivateKey,
	recipientPublicKeys map[string][]byte, blockIndex int,
	localValues []*big.Int) ([]formalGLMPhase15SourceEnvelope, error) {

	if err := formalGLMPhase15VerifyPlanApprovals(plan, approvals, identityPins); err != nil {
		return nil, err
	}
	pinned, ok := identityPins[custodian]
	if !ok || len(signingKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(pinned, signingKey.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("formal-glm: producer identity does not match its pin")
	}
	if blockIndex < 0 || blockIndex >= plan.TotalBlocks {
		return nil, fmt.Errorf("formal-glm: invalid source block index")
	}
	coordinates := plan.Kernel.CoefficientCount + 3
	want := plan.BlockCapacity * coordinates
	if len(localValues) != want {
		return nil, fmt.Errorf("formal-glm: invalid local source block shape")
	}
	for i, value := range localValues {
		if value == nil || value.Sign() < 0 || value.Cmp(exactGCModulus(plan.RingBits)) >= 0 {
			return nil, fmt.Errorf("formal-glm: local source residue is outside the planned ring")
		}
		row, coordinate := i/coordinates, i%coordinates
		globalRow := blockIndex*plan.BlockCapacity + row
		if (plan.CoordinateOwners[coordinate] != custodian ||
			globalRow >= plan.TotalCapacity) && value.Sign() != 0 {
			return nil, fmt.Errorf("formal-glm: producer attempted an unowned or padded coordinate")
		}
	}

	left := make([]*big.Int, len(localValues))
	right := make([]*big.Int, len(localValues))
	modulus := exactGCModulus(plan.RingBits)
	for i, value := range localValues {
		mask, err := crand.Int(crand.Reader, modulus)
		if err != nil {
			return nil, fmt.Errorf("formal-glm: split source share: %w", err)
		}
		left[i] = mask
		right[i] = new(big.Int).Mod(new(big.Int).Sub(value, mask), modulus)
	}
	shares := map[string][]*big.Int{
		plan.Kernel.ComputePeers[0]: left,
		plan.Kernel.ComputePeers[1]: right,
	}
	planDigest, _ := formalGLMPhase15PlanDigest(plan)
	planHash := hex.EncodeToString(planDigest[:])
	ciphertexts := make(map[string][]byte, 2)
	payloadHashes := make(map[string]string, 2)
	for _, recipient := range plan.Kernel.ComputePeers {
		publicBytes, ok := recipientPublicKeys[recipient]
		if !ok || len(publicBytes) != 32 {
			return nil, fmt.Errorf("formal-glm: missing recipient encryption pin")
		}
		if _, err := ecdh.X25519().NewPublicKey(publicBytes); err != nil {
			return nil, fmt.Errorf("formal-glm: invalid recipient encryption pin")
		}
		payload, err := formalGLMPhase15EncodeRecords(shares[recipient], plan.RingBits)
		if err != nil {
			return nil, err
		}
		payloadDigest := sha256.Sum256(payload)
		payloadHashes[recipient] = hex.EncodeToString(payloadDigest[:])
		ciphertext, err := transportEncryptBytes(payload, publicBytes)
		if err != nil {
			return nil, err
		}
		ciphertexts[recipient] = ciphertext
	}
	pair, err := formalGLMPhase15PairCommitment(planHash, plan.RunID,
		custodian, blockIndex, plan.Kernel.ComputePeers, ciphertexts)
	if err != nil {
		return nil, err
	}
	rows := plan.BlockCapacity
	if remaining := plan.TotalCapacity - blockIndex*plan.BlockCapacity; remaining < rows {
		rows = remaining
	}
	result := make([]formalGLMPhase15SourceEnvelope, 2)
	for i, recipient := range plan.Kernel.ComputePeers {
		result[i] = formalGLMPhase15SourceEnvelope{
			Version: formalGLMPhase15PacketVersion, PlanSHA256: planHash,
			RunID: plan.RunID, Custodian: custodian, Recipient: recipient,
			BlockIndex: blockIndex, TotalBlocks: plan.TotalBlocks,
			RowsInBlock: rows, RingBits: plan.RingBits,
			PayloadSHA256: payloadHashes[recipient], PairCommitment: pair,
			Ciphertext: ciphertexts[recipient],
		}
		result[i].Signature = ed25519.Sign(signingKey,
			formalGLMPhase15EnvelopeUnsignedBytes(result[i]))
	}
	return result, nil
}

func (ledger *formalGLMPhase15ReplayLedger) accept(key string, digest [32]byte) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.path != "" {
		return ledger.durableAcceptLocked(key, digest)
	}
	if ledger.entries == nil {
		ledger.entries = make(map[string][32]byte)
	}
	if previous, ok := ledger.entries[key]; ok {
		if previous != digest {
			return fmt.Errorf("formal-glm: conflicting source replay")
		}
		return nil
	}
	ledger.entries[key] = digest
	return nil
}

func formalGLMPhase15FanIn(plan formalGLMPhase15Plan,
	approvals []formalGLMPhase15Approval, identityPins map[string]ed25519.PublicKey,
	recipient string, recipientSecretKey []byte, blockIndex int,
	envelopes []formalGLMPhase15SourceEnvelope,
	ledger *formalGLMPhase15ReplayLedger) (formalGLMPhase15FanInResult, error) {

	var result formalGLMPhase15FanInResult
	if err := formalGLMPhase15VerifyPlanApprovals(plan, approvals, identityPins); err != nil {
		return result, err
	}
	if recipient != plan.Kernel.ComputePeers[0] && recipient != plan.Kernel.ComputePeers[1] {
		return result, fmt.Errorf("formal-glm: fan-in recipient is not a compute peer")
	}
	secret, err := ecdh.X25519().NewPrivateKey(recipientSecretKey)
	if err != nil {
		return result, fmt.Errorf("formal-glm: invalid recipient decryption key")
	}
	if len(envelopes) != len(plan.Kernel.CustodianPeers) {
		return result, fmt.Errorf("formal-glm: incomplete custodian fan-in")
	}
	planDigest, _ := formalGLMPhase15PlanDigest(plan)
	planHash := hex.EncodeToString(planDigest[:])
	wantSenders := make(map[string]bool, len(plan.Kernel.CustodianPeers))
	for _, sender := range plan.Kernel.CustodianPeers {
		wantSenders[sender] = true
	}
	seen := make(map[string]bool, len(envelopes))
	count := plan.BlockCapacity * (plan.Kernel.CoefficientCount + 3)
	sum := make([]*big.Int, count)
	for i := range sum {
		sum[i] = new(big.Int)
	}
	result = formalGLMPhase15FanInResult{
		PlanSHA256: planHash, Recipient: recipient, BlockIndex: blockIndex,
		Shares: sum, PairCommitment: make(map[string]string),
		EnvelopeSHA256: make(map[string]string),
		CipherSHA256:   make(map[string]string),
	}
	modulus := exactGCModulus(plan.RingBits)
	for _, envelope := range envelopes {
		publicKey, ok := identityPins[envelope.Custodian]
		if !ok || !wantSenders[envelope.Custodian] || seen[envelope.Custodian] ||
			envelope.Version != formalGLMPhase15PacketVersion ||
			envelope.PlanSHA256 != planHash || envelope.RunID != plan.RunID ||
			envelope.Recipient != recipient || envelope.BlockIndex != blockIndex ||
			envelope.TotalBlocks != plan.TotalBlocks ||
			envelope.RingBits != plan.RingBits ||
			!formalGLMIsSHA256(envelope.PayloadSHA256) ||
			!formalGLMIsSHA256(envelope.PairCommitment) ||
			len(envelope.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(publicKey,
				formalGLMPhase15EnvelopeUnsignedBytes(envelope), envelope.Signature) {
			return formalGLMPhase15FanInResult{},
				fmt.Errorf("formal-glm: invalid, duplicate, or misrouted source envelope")
		}
		rows := plan.BlockCapacity
		if remaining := plan.TotalCapacity - blockIndex*plan.BlockCapacity; remaining < rows {
			rows = remaining
		}
		if envelope.RowsInBlock != rows {
			return formalGLMPhase15FanInResult{}, fmt.Errorf("formal-glm: source row-count mismatch")
		}
		digest := formalGLMPhase15EnvelopeDigest(envelope)
		ledgerKey := fmt.Sprintf("%s|%s|%d|%s", planHash, recipient,
			blockIndex, envelope.Custodian)
		if ledger == nil {
			return formalGLMPhase15FanInResult{}, fmt.Errorf("formal-glm: replay ledger is required")
		}
		payload, err := transportDecryptBytes(envelope.Ciphertext, secret.Bytes())
		if err != nil {
			return formalGLMPhase15FanInResult{}, fmt.Errorf("formal-glm: source envelope authentication failed")
		}
		payloadDigest := sha256.Sum256(payload)
		if hex.EncodeToString(payloadDigest[:]) != envelope.PayloadSHA256 {
			return formalGLMPhase15FanInResult{}, fmt.Errorf("formal-glm: source payload commitment mismatch")
		}
		shares, err := formalGLMPhase15DecodeRecords(payload, count, plan.RingBits)
		if err != nil {
			return formalGLMPhase15FanInResult{}, err
		}
		// Commit a slot only after signature, AEAD, payload hash, and canonical
		// record validation have all succeeded.  Malformed input cannot poison
		// the durable idempotency ledger.
		if err := ledger.accept(ledgerKey, digest); err != nil {
			return formalGLMPhase15FanInResult{}, err
		}
		for i := range sum {
			sum[i].Add(sum[i], shares[i])
			sum[i].Mod(sum[i], modulus)
		}
		seen[envelope.Custodian] = true
		result.PairCommitment[envelope.Custodian] = envelope.PairCommitment
		result.EnvelopeSHA256[envelope.Custodian] = hex.EncodeToString(digest[:])
		cipherDigest := sha256.Sum256(envelope.Ciphertext)
		result.CipherSHA256[envelope.Custodian] = hex.EncodeToString(cipherDigest[:])
	}
	result.FanInRoot, err = formalGLMPhase15FanInRoot(plan, planHash,
		blockIndex, result.PairCommitment)
	if err != nil {
		return formalGLMPhase15FanInResult{}, err
	}
	result.verified = true
	return result, nil
}

func formalGLMPhase15ValidatePairedFanIn(plan formalGLMPhase15Plan,
	left, right formalGLMPhase15FanInResult) error {

	if left.PlanSHA256 != right.PlanSHA256 || left.BlockIndex != right.BlockIndex ||
		left.Recipient != plan.Kernel.ComputePeers[0] ||
		right.Recipient != plan.Kernel.ComputePeers[1] ||
		len(left.PairCommitment) != len(plan.Kernel.CustodianPeers) ||
		len(right.PairCommitment) != len(plan.Kernel.CustodianPeers) ||
		!left.verified || !right.verified || left.FanInRoot != right.FanInRoot {
		return fmt.Errorf("formal-glm: mismatched paired fan-in receipts")
	}
	for _, custodian := range plan.Kernel.CustodianPeers {
		if left.PairCommitment[custodian] == "" ||
			left.PairCommitment[custodian] != right.PairCommitment[custodian] {
			return fmt.Errorf("formal-glm: custodian equivocation or mixed source pair")
		}
		hashes := map[string]string{
			plan.Kernel.ComputePeers[0]: left.CipherSHA256[custodian],
			plan.Kernel.ComputePeers[1]: right.CipherSHA256[custodian],
		}
		want, err := formalGLMPhase15PairCommitmentFromHashes(
			left.PlanSHA256, plan.RunID, custodian, left.BlockIndex,
			plan.Kernel.ComputePeers, hashes)
		if err != nil || want != left.PairCommitment[custodian] {
			return fmt.Errorf("formal-glm: invalid source-pair commitment")
		}
	}
	wantRoot, err := formalGLMPhase15FanInRoot(plan, left.PlanSHA256,
		left.BlockIndex, left.PairCommitment)
	if err != nil || wantRoot != left.FanInRoot {
		return fmt.Errorf("formal-glm: invalid paired fan-in root")
	}
	return nil
}
