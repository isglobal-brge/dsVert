package main

// Durable, server-local Phase-1.8 -> Phase-1.9 finalisation boundary.
//
// The DSI-facing R adapter authenticates the pinned source envelope and writes
// only this bounded ciphertext frame.  This Go boundary authenticates that
// local hand-off before parsing it, checks the fixed source/recipient slot,
// decrypts only in the recipient process, rejects the legacy full-alignment
// header, and seals the resulting private shares into the Phase-1.9 trust type.
// Plaintext is never written to disk and no command handler is registered.

import (
	"bytes"
	"crypto/hmac"
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
	"strings"
	"sync"
	"time"
)

const (
	formalGLMPhase18IngressMagic       = "DSVFG182"
	formalGLMPhase18IngressMACDomain   = "dsVert/formal-glm/phase18/local-ingress-frame/v2"
	formalGLMPhase18IngressSlotDomain  = "dsVert/formal-glm/phase18/local-ingress-slot/v2"
	formalGLMPhase18PrivateBlockV2     = "dsvert-formal-glm-phase18-private-block-v2"
	formalGLMPhase18Purpose            = "formal_glm_fixed_rows_and_local_validity_shares_phase19_only_v1"
	formalGLMPhase18ValiditySharing    = "one_xor_shared_local_validity_bit_per_peer_and_capacity_slot_v1"
	formalGLMPhase18AlignmentSharing   = "recipient_specific_xor_shared_gate_and_consensus_digest_v2"
	formalGLMPhase18RequiredOperation  = "xor_reconstruct_validity_alignment_and_consensus_then_all_k_mask_full_tuple_before_glm_kernel_v2"
	formalGLMPhase18CoordinateEncoding = "little_endian_unsigned_fixed_container_masked_to_ring_bits_v1"
	formalGLMPhase18NoRelease          = "none_pre_execution"

	// These are fixed per-frame parser/resource bounds, never request or query
	// quotas.  Arbitrarily many valid blocks can be stored over time.
	formalGLMPhase18MaxPrivateHeader  = 65535
	formalGLMPhase18MaxIngressFrame   = 2 << 20
	formalGLMPhase18TransportOverhead = 32 + 12 + 16
	formalGLMPhase18TempGrace         = 24 * time.Hour
)

// formalGLMPhase18IngressFrame contains public routing/shape commitments plus
// one authenticated ciphertext.  Alignment/validity values and patient-level
// hashes have no representation in this format.
type formalGLMPhase18IngressFrame struct {
	CapsuleSHA256             string
	PlanSHA256                string
	PreExecutionSHA256        string
	GlobalMaterializationRoot string
	RunID                     string
	Source                    string
	Recipient                 string
	RecipientTicketSHA256     string
	PairCommitment            string
	BlockCommitment           string
	CiphertextSHA256          string
	EnvelopeSHA256            string
	SourceSlot                int
	RecipientSlot             int
	BlockIndex                int
	TotalBlocks               int
	GlobalSlotOffset          int
	SlotsInBlock              int
	CoordinateCount           int
	CoordinateRecords         int
	RingBits                  int
	RecordBytes               int
	ValidityRecords           int
	Ciphertext                []byte
}

func formalGLMPhase18FrameAppendString(dst []byte, value string) ([]byte, error) {
	if len(value) > 4096 {
		return nil, fmt.Errorf("formal-glm: Phase-1.8 ingress string is too large")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...), nil
}

func formalGLMPhase18FrameAppendInt(dst []byte, value int) ([]byte, error) {
	if value < 0 {
		return nil, fmt.Errorf("formal-glm: negative Phase-1.8 ingress integer")
	}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	return append(dst, encoded[:]...), nil
}

func formalGLMPhase18ValidateIngressFrame(frame formalGLMPhase18IngressFrame) error {
	hashes := []string{
		frame.CapsuleSHA256, frame.PlanSHA256, frame.PreExecutionSHA256,
		frame.GlobalMaterializationRoot,
		frame.RecipientTicketSHA256, frame.PairCommitment,
		frame.BlockCommitment, frame.CiphertextSHA256, frame.EnvelopeSHA256,
	}
	for _, value := range hashes {
		if !formalGLMIsSHA256(value) {
			return fmt.Errorf("formal-glm: invalid Phase-1.8 ingress commitment")
		}
	}
	if exactGCValidateLabel("Phase-1.8 ingress run", frame.RunID, 256) != nil ||
		exactGCValidateLabel("Phase-1.8 ingress source", frame.Source, 128) != nil ||
		exactGCValidateLabel("Phase-1.8 ingress recipient", frame.Recipient, 128) != nil {
		return fmt.Errorf("formal-glm: invalid Phase-1.8 ingress route")
	}
	if frame.SourceSlot < 0 || frame.SourceSlot >= formalGLMPhase15MaxTotal ||
		frame.RecipientSlot < 0 || frame.RecipientSlot > 1 ||
		frame.BlockIndex < 0 || frame.TotalBlocks < 1 ||
		frame.BlockIndex >= frame.TotalBlocks || frame.GlobalSlotOffset < 0 ||
		frame.SlotsInBlock < 1 || frame.SlotsInBlock > formalGLMPhase1MaxCapacity ||
		frame.CoordinateCount < 4 ||
		frame.CoordinateCount > formalGLMPhase1MaxCoefficients+3 ||
		frame.CoordinateRecords != frame.SlotsInBlock*frame.CoordinateCount ||
		frame.RingBits < 128 || frame.RingBits > exactGCMaxRingBits ||
		frame.RecordBytes != exactGCRecordBytes(frame.RingBits) ||
		frame.ValidityRecords != frame.SlotsInBlock {
		return fmt.Errorf("formal-glm: invalid Phase-1.8 ingress shape")
	}
	shareBytes := frame.CoordinateRecords*frame.RecordBytes + frame.ValidityRecords
	maxCiphertext := formalGLMPhase18TransportOverhead + 4 +
		formalGLMPhase18MaxPrivateHeader + shareBytes
	if shareBytes < 1 || len(frame.Ciphertext) <
		formalGLMPhase18TransportOverhead+4+2+shareBytes ||
		len(frame.Ciphertext) > maxCiphertext ||
		len(frame.Ciphertext)+512 > formalGLMPhase18MaxIngressFrame {
		return fmt.Errorf("formal-glm: Phase-1.8 ingress ciphertext is outside its fixed bound")
	}
	digest := sha256.Sum256(frame.Ciphertext)
	if frame.CiphertextSHA256 != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("formal-glm: Phase-1.8 ingress ciphertext hash mismatch")
	}
	return nil
}

func formalGLMPhase18IngressMessage(frame formalGLMPhase18IngressFrame) ([]byte, error) {
	if err := formalGLMPhase18ValidateIngressFrame(frame); err != nil {
		return nil, err
	}
	message := append([]byte(nil), []byte(formalGLMPhase18IngressMagic)...)
	var err error
	for _, value := range []string{
		frame.CapsuleSHA256, frame.PlanSHA256, frame.PreExecutionSHA256,
		frame.GlobalMaterializationRoot, frame.RunID, frame.Source,
		frame.Recipient, frame.RecipientTicketSHA256,
		frame.PairCommitment, frame.BlockCommitment, frame.CiphertextSHA256,
		frame.EnvelopeSHA256,
	} {
		message, err = formalGLMPhase18FrameAppendString(message, value)
		if err != nil {
			return nil, err
		}
	}
	for _, value := range []int{
		frame.SourceSlot, frame.RecipientSlot, frame.BlockIndex,
		frame.TotalBlocks, frame.GlobalSlotOffset, frame.SlotsInBlock,
		frame.CoordinateCount, frame.CoordinateRecords, frame.RingBits,
		frame.RecordBytes, frame.ValidityRecords,
	} {
		message, err = formalGLMPhase18FrameAppendInt(message, value)
		if err != nil {
			return nil, err
		}
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(frame.Ciphertext)))
	message = append(message, size[:]...)
	message = append(message, frame.Ciphertext...)
	return message, nil
}

func formalGLMPhase18EncodeIngressFrame(frame formalGLMPhase18IngressFrame,
	localKey [32]byte) ([]byte, error) {
	if !formalGLMPhase19KeyValid(localKey) {
		return nil, fmt.Errorf("formal-glm: missing Phase-1.8 local ingress key")
	}
	message, err := formalGLMPhase18IngressMessage(frame)
	if err != nil {
		return nil, err
	}
	mac := formalGLMPhase19MAC(localKey, formalGLMPhase18IngressMACDomain, message)
	result := append(append([]byte(nil), message...), mac[:]...)
	if len(result) > formalGLMPhase18MaxIngressFrame {
		return nil, fmt.Errorf("formal-glm: Phase-1.8 ingress frame exceeds its fixed bound")
	}
	return result, nil
}

type formalGLMPhase18FrameReader struct {
	value  []byte
	offset int
}

func (reader *formalGLMPhase18FrameReader) take(n int) ([]byte, error) {
	if n < 0 || reader.offset > len(reader.value)-n {
		return nil, fmt.Errorf("formal-glm: truncated Phase-1.8 ingress frame")
	}
	result := reader.value[reader.offset : reader.offset+n]
	reader.offset += n
	return result, nil
}

func (reader *formalGLMPhase18FrameReader) readString() (string, error) {
	sizeBytes, err := reader.take(4)
	if err != nil {
		return "", err
	}
	size := int(binary.BigEndian.Uint32(sizeBytes))
	if size < 1 || size > 4096 {
		return "", fmt.Errorf("formal-glm: invalid Phase-1.8 ingress string length")
	}
	value, err := reader.take(size)
	if err != nil {
		return "", err
	}
	if !json.Valid(append(append([]byte{'"'}, value...), '"')) ||
		!bytes.Equal(value, []byte(string(value))) {
		return "", fmt.Errorf("formal-glm: invalid Phase-1.8 ingress string")
	}
	return string(value), nil
}

func (reader *formalGLMPhase18FrameReader) readInt() (int, error) {
	value, err := reader.take(8)
	if err != nil {
		return 0, err
	}
	parsed := binary.BigEndian.Uint64(value)
	maxInt := uint64(^uint(0) >> 1)
	if parsed > maxInt {
		return 0, fmt.Errorf("formal-glm: Phase-1.8 ingress integer overflows")
	}
	return int(parsed), nil
}

func formalGLMPhase18DecodeIngressFrame(encoded []byte,
	localKey [32]byte) (formalGLMPhase18IngressFrame, error) {
	var zero formalGLMPhase18IngressFrame
	if !formalGLMPhase19KeyValid(localKey) || len(encoded) <
		len(formalGLMPhase18IngressMagic)+32 || len(encoded) > formalGLMPhase18MaxIngressFrame {
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.8 ingress frame")
	}
	message := encoded[:len(encoded)-32]
	gotMAC := encoded[len(encoded)-32:]
	wantMAC := formalGLMPhase19MAC(localKey, formalGLMPhase18IngressMACDomain, message)
	if !hmac.Equal(wantMAC[:], gotMAC) {
		return zero, fmt.Errorf("formal-glm: Phase-1.8 ingress authentication failed")
	}
	reader := formalGLMPhase18FrameReader{value: message}
	magic, err := reader.take(len(formalGLMPhase18IngressMagic))
	if err != nil || string(magic) != formalGLMPhase18IngressMagic {
		return zero, fmt.Errorf("formal-glm: legacy or invalid Phase-1.8 ingress frame")
	}
	stringsRead := make([]string, 12)
	for i := range stringsRead {
		stringsRead[i], err = reader.readString()
		if err != nil {
			return zero, err
		}
	}
	intsRead := make([]int, 11)
	for i := range intsRead {
		intsRead[i], err = reader.readInt()
		if err != nil {
			return zero, err
		}
	}
	sizeBytes, err := reader.take(4)
	if err != nil {
		return zero, err
	}
	ciphertextBytes := int(binary.BigEndian.Uint32(sizeBytes))
	ciphertext, err := reader.take(ciphertextBytes)
	if err != nil || reader.offset != len(reader.value) {
		return zero, fmt.Errorf("formal-glm: truncated or trailing Phase-1.8 ingress data")
	}
	frame := formalGLMPhase18IngressFrame{
		CapsuleSHA256: stringsRead[0], PlanSHA256: stringsRead[1],
		PreExecutionSHA256:        stringsRead[2],
		GlobalMaterializationRoot: stringsRead[3], RunID: stringsRead[4],
		Source: stringsRead[5], Recipient: stringsRead[6],
		RecipientTicketSHA256: stringsRead[7], PairCommitment: stringsRead[8],
		BlockCommitment: stringsRead[9], CiphertextSHA256: stringsRead[10],
		EnvelopeSHA256: stringsRead[11], SourceSlot: intsRead[0],
		RecipientSlot: intsRead[1], BlockIndex: intsRead[2],
		TotalBlocks: intsRead[3], GlobalSlotOffset: intsRead[4],
		SlotsInBlock: intsRead[5], CoordinateCount: intsRead[6],
		CoordinateRecords: intsRead[7], RingBits: intsRead[8],
		RecordBytes: intsRead[9], ValidityRecords: intsRead[10],
		Ciphertext: append([]byte(nil), ciphertext...),
	}
	if err := formalGLMPhase18ValidateIngressFrame(frame); err != nil {
		return zero, err
	}
	reencoded, err := formalGLMPhase18EncodeIngressFrame(frame, localKey)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return zero, fmt.Errorf("formal-glm: non-canonical Phase-1.8 ingress frame")
	}
	return frame, nil
}

// Field order is alphabetical so json.Marshal exactly matches the canonical
// R object emitted by .dsvert_dp_canonical_query_value().
type formalGLMPhase18PrivateBlockHeader struct {
	AlignmentSharing               string `json:"alignment_sharing"`
	BlockIndex                     int    `json:"block_index"`
	CapsuleID                      string `json:"capsule_id"`
	CoordinateCount                int    `json:"coordinate_count"`
	CoordinateShareBytes           int    `json:"coordinate_share_bytes"`
	GlobalSlotOffset               int    `json:"global_slot_offset"`
	OpeningsPerformed              int    `json:"openings_performed"`
	Phase19RequiredOperation       string `json:"phase19_required_operation"`
	PlanSHA256                     string `json:"plan_sha256"`
	PreExecutionSHA256             string `json:"pre_execution_sha256"`
	PrivateAlignmentConsensusShare string `json:"private_alignment_consensus_share"`
	PrivateAlignmentGateShare      int    `json:"private_alignment_gate_share"`
	Purpose                        string `json:"purpose"`
	RecipientName                  string `json:"recipient_name"`
	RecipientRole                  string `json:"recipient_role"`
	RecipientTicketSHA256          string `json:"recipient_ticket_sha256"`
	RecordBytes                    int    `json:"record_bytes"`
	ReleaseToken                   string `json:"release_token"`
	RingBits                       int    `json:"ring_bits"`
	RunID                          string `json:"run_id"`
	SlotsInBlock                   int    `json:"slots_in_block"`
	SourceName                     string `json:"source_name"`
	SourceSlot                     int    `json:"source_slot"`
	TotalBlocks                    int    `json:"total_blocks"`
	ValidityShareBytes             int    `json:"validity_share_bytes"`
	ValiditySharing                string `json:"validity_sharing"`
	Version                        string `json:"version"`
}

func formalGLMPhase18ValidateRoute(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, frame formalGLMPhase18IngressFrame) error {
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return err
	}
	sourceSlot, recipientSlot := -1, -1
	for i, source := range ctx.CustodianPeers {
		if source == frame.Source {
			sourceSlot = i
		}
	}
	for i, recipient := range ctx.ComputePeers {
		if recipient == frame.Recipient {
			recipientSlot = i
		}
	}
	if frame.CapsuleSHA256 != ctx.CapsuleSHA256 ||
		frame.PlanSHA256 != hex.EncodeToString(planDigest[:]) ||
		frame.PlanSHA256 != ctx.Phase15PlanSHA256 ||
		frame.PreExecutionSHA256 != ctx.PreExecutionTokenSHA256 ||
		frame.GlobalMaterializationRoot != ctx.GlobalMaterializationRoot ||
		frame.RunID != ctx.RunID || sourceSlot != frame.SourceSlot ||
		recipientSlot != frame.RecipientSlot || frame.TotalBlocks != ctx.TotalBlocks ||
		frame.BlockIndex < 0 || frame.BlockIndex >= ctx.TotalBlocks ||
		frame.GlobalSlotOffset != frame.BlockIndex*ctx.BlockCapacity ||
		frame.SlotsInBlock != ctx.BlockCapacity ||
		frame.CoordinateCount != ctx.CoordinatesPerRow ||
		frame.CoordinateRecords != ctx.BlockCapacity*ctx.CoordinatesPerRow ||
		frame.RingBits != ctx.RingBits || frame.RecordBytes != plan.ContainerBits/8 ||
		frame.ValidityRecords != ctx.BlockCapacity {
		return fmt.Errorf("formal-glm: misrouted or shape-confused Phase-1.8 ingress frame")
	}
	return nil
}

func formalGLMPhase18DecodePrivateHeader(plaintext []byte,
	frame formalGLMPhase18IngressFrame) (formalGLMPhase18PrivateBlockHeader,
	[]byte, error) {
	var zero formalGLMPhase18PrivateBlockHeader
	if len(plaintext) < 4 {
		return zero, nil, fmt.Errorf("formal-glm: truncated Phase-1.8 private block")
	}
	headerBytes := int(binary.BigEndian.Uint32(plaintext[:4]))
	shareBytes := frame.CoordinateRecords*frame.RecordBytes + frame.ValidityRecords
	if headerBytes < 2 || headerBytes > formalGLMPhase18MaxPrivateHeader ||
		len(plaintext) != 4+headerBytes+shareBytes {
		return zero, nil, fmt.Errorf("formal-glm: invalid Phase-1.8 private block shape")
	}
	encodedHeader := plaintext[4 : 4+headerBytes]
	decoder := json.NewDecoder(bytes.NewReader(encodedHeader))
	decoder.DisallowUnknownFields()
	var header formalGLMPhase18PrivateBlockHeader
	if err := decoder.Decode(&header); err != nil {
		return zero, nil, fmt.Errorf("formal-glm: invalid Phase-1.8 private header: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return zero, nil, fmt.Errorf("formal-glm: trailing Phase-1.8 private header")
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(canonical, encodedHeader) {
		return zero, nil, fmt.Errorf("formal-glm: non-canonical or duplicate Phase-1.8 private header")
	}
	return header, plaintext[4+headerBytes:], nil
}

func formalGLMPhase18DecodeCoordinateShares(encoded []byte, count,
	ringBits, recordBytes int) ([]*big.Int, error) {
	if count < 1 || ringBits < 128 || ringBits > exactGCMaxRingBits ||
		recordBytes != exactGCRecordBytes(ringBits) ||
		len(encoded) != count*recordBytes {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.8 coordinate-share shape")
	}
	coordinates := make([]*big.Int, count)
	for i := range coordinates {
		record := encoded[i*recordBytes : (i+1)*recordBytes]
		coordinates[i] = exactGCLittleEndianBig(record)
		if coordinates[i].BitLen() > ringBits {
			return nil, fmt.Errorf("formal-glm: non-zero Phase-1.8 high container padding")
		}
	}
	return coordinates, nil
}

func formalGLMPhase18FinalizeFrame(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context, frame formalGLMPhase18IngressFrame,
	recipientSecretKey []byte, backendKey [32]byte) (
	formalGLMPhase19VerifiedSourceBlock, error) {
	var zero formalGLMPhase19VerifiedSourceBlock
	if err := formalGLMPhase18ValidateRoute(plan, ctx, frame); err != nil {
		return zero, err
	}
	if len(recipientSecretKey) != 32 || !formalGLMPhase19KeyValid(backendKey) {
		return zero, fmt.Errorf("formal-glm: missing Phase-1.8 recipient key material")
	}
	plaintext, err := transportDecryptBytes(frame.Ciphertext, recipientSecretKey)
	if err != nil {
		return zero, fmt.Errorf("formal-glm: decrypt local Phase-1.8 ingress: %w", err)
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()
	header, shares, err := formalGLMPhase18DecodePrivateHeader(plaintext, frame)
	if err != nil {
		return zero, err
	}
	expectedRole := "garbler"
	if frame.RecipientSlot == 1 {
		expectedRole = "evaluator"
	}
	coordinateBytes := frame.CoordinateRecords * frame.RecordBytes
	if header.Version != formalGLMPhase18PrivateBlockV2 ||
		header.Purpose != formalGLMPhase18Purpose ||
		header.CapsuleID != frame.CapsuleSHA256 ||
		header.PlanSHA256 != frame.PlanSHA256 ||
		header.PreExecutionSHA256 != frame.PreExecutionSHA256 ||
		header.RunID != frame.RunID || header.SourceName != frame.Source ||
		header.SourceSlot != frame.SourceSlot ||
		header.RecipientName != frame.Recipient || header.RecipientRole != expectedRole ||
		header.RecipientTicketSHA256 != frame.RecipientTicketSHA256 ||
		header.BlockIndex != frame.BlockIndex || header.TotalBlocks != frame.TotalBlocks ||
		header.GlobalSlotOffset != frame.GlobalSlotOffset ||
		header.SlotsInBlock != frame.SlotsInBlock ||
		header.CoordinateCount != frame.CoordinateCount ||
		header.CoordinateShareBytes != coordinateBytes ||
		header.ValidityShareBytes != frame.ValidityRecords ||
		header.RingBits != frame.RingBits || header.RecordBytes != frame.RecordBytes ||
		header.ValiditySharing != formalGLMPhase18ValiditySharing ||
		header.AlignmentSharing != formalGLMPhase18AlignmentSharing ||
		header.PrivateAlignmentGateShare < 0 || header.PrivateAlignmentGateShare > 1 ||
		header.Phase19RequiredOperation != formalGLMPhase18RequiredOperation ||
		header.ReleaseToken != formalGLMPhase18NoRelease || header.OpeningsPerformed != 0 {
		return zero, fmt.Errorf("formal-glm: legacy, misrouted, or malformed Phase-1.8 private header")
	}
	consensusShare, err := base64.RawURLEncoding.Strict().DecodeString(
		header.PrivateAlignmentConsensusShare)
	if err != nil || len(consensusShare) != 32 ||
		base64.RawURLEncoding.EncodeToString(consensusShare) !=
			header.PrivateAlignmentConsensusShare {
		return zero, fmt.Errorf("formal-glm: invalid Phase-1.8 consensus share")
	}
	coordinates, err := formalGLMPhase18DecodeCoordinateShares(
		shares[:coordinateBytes], frame.CoordinateRecords,
		frame.RingBits, frame.RecordBytes)
	if err != nil {
		return zero, err
	}
	validity := append([]byte(nil), shares[coordinateBytes:]...)
	for _, value := range validity {
		if value > 1 {
			return zero, fmt.Errorf("formal-glm: invalid Phase-1.8 validity share")
		}
	}
	var consensus [32]byte
	copy(consensus[:], consensusShare)
	return formalGLMPhase19SealSourceBlock(
		plan, ctx, frame.Source, frame.Recipient, frame.BlockIndex,
		coordinates, validity, byte(header.PrivateAlignmentGateShare),
		consensus, frame.PairCommitment, frame.BlockCommitment, backendKey)
}

type formalGLMPhase18DurableFinalizer struct {
	mu        sync.Mutex
	dir       string
	recordDir string
	recipient string
	key       [32]byte
}

type formalGLMPhase18FinalizedSource struct {
	Handle   string
	Replayed bool
	Block    formalGLMPhase19VerifiedSourceBlock
}

func formalGLMPhase18EnsurePrivateDir(path string) error {
	if path == "" || path == "." || path == string(filepath.Separator) {
		return fmt.Errorf("formal-glm: invalid Phase-1.8 finalizer directory")
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
		return fmt.Errorf("formal-glm: unsafe Phase-1.8 finalizer directory")
	}
	return nil
}

func formalGLMPhase18CleanupTemps(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".phase18-finalizer-") {
			return nil
		}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 ||
			info.Size() > formalGLMPhase18MaxIngressFrame {
			return fmt.Errorf("formal-glm: unsafe stale Phase-1.8 finalizer file")
		}
		committed, err := formalGLMPhase18ReapCommittedTemp(path, info)
		if err != nil || committed {
			return err
		}
		if !exactGCPrivateOwnedRegular(info) {
			return fmt.Errorf("formal-glm: unsafe linked Phase-1.8 finalizer file")
		}
		// A second process may be writing a same-prefix temporary file.  Only
		// reap files old enough that a bounded 2 MiB write cannot plausibly be
		// active; current files are left to their writer's deferred cleanup.
		if age := time.Since(info.ModTime()); age < formalGLMPhase18TempGrace {
			return nil
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}

// A hard-link commit briefly has link count two until its temporary name is
// removed.  If the writer crashes in that exact window, the durable slot is
// already complete but strict record reads would reject it forever.  Remove
// only a same-inode, same-directory, internal temporary name paired with a
// canonical slot name; unrelated hard links remain fatal.
func formalGLMPhase18ReapCommittedTemp(path string, tempInfo os.FileInfo) (bool, error) {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "slot-") || !strings.HasSuffix(name, ".bin") {
			continue
		}
		slotID := strings.TrimSuffix(strings.TrimPrefix(name, "slot-"), ".bin")
		if !formalGLMIsSHA256(slotID) {
			continue
		}
		target := filepath.Join(filepath.Dir(path), name)
		targetInfo, err := os.Lstat(target)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, err
		}
		if !os.SameFile(tempInfo, targetInfo) {
			continue
		}
		if !targetInfo.Mode().IsRegular() || targetInfo.Mode()&os.ModeSymlink != 0 ||
			targetInfo.Mode().Perm()&0o077 != 0 ||
			targetInfo.Size() < 64 || targetInfo.Size() > formalGLMPhase18MaxIngressFrame {
			return false, fmt.Errorf("formal-glm: unsafe linked Phase-1.8 durable slot")
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		if err := exactGCSyncDir(filepath.Dir(path)); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func newFormalGLMPhase18DurableFinalizer(dir, recipient string,
	key [32]byte) (*formalGLMPhase18DurableFinalizer, error) {
	if !formalGLMPhase19KeyValid(key) ||
		exactGCValidateLabel("Phase-1.8 finalizer recipient", recipient, 128) != nil {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.8 finalizer identity")
	}
	dir = filepath.Clean(dir)
	if err := formalGLMPhase18EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	recordDir := filepath.Join(dir, "records-v2")
	if err := formalGLMPhase18EnsurePrivateDir(recordDir); err != nil {
		return nil, err
	}
	if err := formalGLMPhase18CleanupTemps(recordDir); err != nil {
		return nil, err
	}
	return &formalGLMPhase18DurableFinalizer{
		dir: dir, recordDir: recordDir, recipient: recipient, key: key,
	}, nil
}

func formalGLMPhase18SlotID(ctx formalGLMPhase19Context, source, recipient string,
	blockIndex int) (string, error) {
	ctxDigest, err := formalGLMPhase19ContextDigest(ctx)
	if err != nil || blockIndex < 0 || blockIndex >= ctx.TotalBlocks ||
		!formalGLMPhase19Contains(ctx.CustodianPeers, source) ||
		!formalGLMPhase19Contains(ctx.ComputePeers, recipient) {
		return "", fmt.Errorf("formal-glm: invalid Phase-1.8 durable source slot")
	}
	message := formalGLMPhase15AppendString(nil, formalGLMPhase18IngressSlotDomain)
	message = append(message, ctxDigest[:]...)
	message = formalGLMPhase15AppendString(message, source)
	message = formalGLMPhase15AppendString(message, recipient)
	message = formalGLMPhase15AppendUint64(message, uint64(blockIndex))
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func (store *formalGLMPhase18DurableFinalizer) recordPath(slotID string,
	create bool) (string, error) {
	if !formalGLMIsSHA256(slotID) {
		return "", fmt.Errorf("formal-glm: invalid Phase-1.8 durable slot id")
	}
	shard := filepath.Join(store.recordDir, slotID[:2], slotID[2:4])
	if create {
		if err := formalGLMPhase18EnsurePrivateDir(shard); err != nil {
			return "", err
		}
	}
	return filepath.Join(shard, "slot-"+slotID+".bin"), nil
}

func formalGLMPhase18ReadRecord(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() < 64 || info.Size() > formalGLMPhase18MaxIngressFrame {
		return nil, fmt.Errorf("formal-glm: unsafe Phase-1.8 durable record")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("formal-glm: Phase-1.8 durable record changed while opening")
	}
	value := make([]byte, opened.Size())
	_, readErr := io.ReadFull(file, value)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return value, nil
}

func (store *formalGLMPhase18DurableFinalizer) persist(slotID string,
	encoded []byte) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	path, err := store.recordPath(slotID, true)
	if err != nil {
		return false, err
	}
	if existing, err := formalGLMPhase18ReadRecord(path); err == nil {
		if !bytes.Equal(existing, encoded) {
			return false, fmt.Errorf("formal-glm: conflicting Phase-1.8 durable replay")
		}
		if _, err := formalGLMPhase18DecodeIngressFrame(existing, store.key); err != nil {
			return false, err
		}
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".phase18-finalizer-")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := exactGCWriteFull(tmp, encoded); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Link(tmpPath, path); err != nil {
		// The winning process may still be between link and temporary-name
		// removal.  Repair that committed state before enforcing link-count 1.
		if cleanupErr := formalGLMPhase18CleanupTemps(filepath.Dir(path)); cleanupErr != nil {
			return false, cleanupErr
		}
		existing, readErr := formalGLMPhase18ReadRecord(path)
		if readErr != nil {
			return false, readErr
		}
		if !bytes.Equal(existing, encoded) {
			return false, fmt.Errorf("formal-glm: conflicting Phase-1.8 durable replay")
		}
		return true, nil
	}
	if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := exactGCSyncDir(filepath.Dir(path)); err != nil {
		return false, err
	}
	return false, nil
}

func (store *formalGLMPhase18DurableFinalizer) IngestAndFinalize(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context, encoded []byte,
	recipientSecretKey []byte) (formalGLMPhase18FinalizedSource, error) {
	return store.IngestAndFinalizeWithBackend(
		plan, ctx, encoded, recipientSecretKey, store.key)
}

// IngestAndFinalizeWithBackend keeps the local durable-frame authentication
// key distinct from the two-compute-peer Phase-1.9 backend key. The latter is
// ECDH-derived and unknown to the relay; using it for the in-memory source
// seal lets both compute peers authenticate public fan-in receipts without
// sharing either server's durable-at-rest key.
func (store *formalGLMPhase18DurableFinalizer) IngestAndFinalizeWithBackend(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context, encoded []byte,
	recipientSecretKey []byte, backendKey [32]byte) (
	formalGLMPhase18FinalizedSource, error) {
	var zero formalGLMPhase18FinalizedSource
	frame, err := formalGLMPhase18DecodeIngressFrame(encoded, store.key)
	if err != nil {
		return zero, err
	}
	if frame.Recipient != store.recipient {
		return zero, fmt.Errorf("formal-glm: Phase-1.8 finalizer recipient mismatch")
	}
	block, err := formalGLMPhase18FinalizeFrame(
		plan, ctx, frame, recipientSecretKey, backendKey)
	if err != nil {
		return zero, err
	}
	slotID, err := formalGLMPhase18SlotID(
		ctx, frame.Source, frame.Recipient, frame.BlockIndex)
	if err != nil {
		return zero, err
	}
	replayed, err := store.persist(slotID, encoded)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase18FinalizedSource{
		Handle: slotID, Replayed: replayed, Block: block,
	}, nil
}

// LoadCompleteBlock is the restart boundary: it requires exactly one durable
// ciphertext slot for every K custodian and recreates only in-memory sealed
// Phase-1.9 blocks.  Missing data never produces a partial fan-in.
func (store *formalGLMPhase18DurableFinalizer) LoadCompleteBlock(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context, blockIndex int,
	recipientSecretKey []byte) ([]formalGLMPhase19VerifiedSourceBlock, error) {
	return store.LoadCompleteBlockWithBackend(
		plan, ctx, blockIndex, recipientSecretKey, store.key)
}

// LoadCompleteBlockWithBackend is the restart form of the split-key boundary
// above. Durable records remain MACed by store.key while recreated in-memory
// trust types are sealed by the current purpose-bound ECDH backend key.
func (store *formalGLMPhase18DurableFinalizer) LoadCompleteBlockWithBackend(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context, blockIndex int,
	recipientSecretKey []byte, backendKey [32]byte) (
	[]formalGLMPhase19VerifiedSourceBlock, error) {
	if store.recipient == "" || blockIndex < 0 || blockIndex >= ctx.TotalBlocks {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.8 durable block request")
	}
	encoded := make([][]byte, len(ctx.CustodianPeers))
	for i, source := range ctx.CustodianPeers {
		slotID, err := formalGLMPhase18SlotID(ctx, source, store.recipient, blockIndex)
		if err != nil {
			return nil, err
		}
		path, err := store.recordPath(slotID, false)
		if err != nil {
			return nil, err
		}
		encoded[i], err = formalGLMPhase18ReadRecord(path)
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("formal-glm: incomplete durable Phase-1.8 block")
		}
		if err != nil {
			return nil, err
		}
	}
	result := make([]formalGLMPhase19VerifiedSourceBlock, len(encoded))
	for i, value := range encoded {
		frame, err := formalGLMPhase18DecodeIngressFrame(value, store.key)
		if err != nil {
			return nil, err
		}
		result[i], err = formalGLMPhase18FinalizeFrame(
			plan, ctx, frame, recipientSecretKey, backendKey)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
