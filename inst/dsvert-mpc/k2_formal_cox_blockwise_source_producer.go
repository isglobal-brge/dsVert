package main

// Rock-local block producer for formal Cox source rows. It consumes one
// canonical decimal block at a time, splits the rows inside this process, and
// persists only recipient-encrypted C1 envelopes plus signed public metadata.
// It deliberately registers no command, capability, handler, or DSI method.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
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
)

const (
	formalCoxBlockwiseSourceProducerVersion        = "dsvert-formal-cox-blockwise-source-producer-v1"
	formalCoxBlockwiseSourceProducerPurpose        = "formal-cox-rock-local-incremental-source-production-v1"
	formalCoxBlockwiseSourceProducerEncoding       = "canonical-signed-ring128-decimal-lines-row-major-v1"
	formalCoxBlockwiseSourceProducerIntentVersion  = "dsvert-formal-cox-blockwise-source-production-intent-v1"
	formalCoxBlockwiseSourceProducerOutboxVersion  = "dsvert-formal-cox-blockwise-source-production-outbox-binding-v1"
	formalCoxBlockwiseSourceProducerReceiptVersion = "dsvert-formal-cox-blockwise-source-production-receipt-v1"
	formalCoxBlockwiseSourceProducerStateVersion   = "dsvert-formal-cox-blockwise-source-producer-state-v1"
	formalCoxBlockwiseSourceProducerInputDomain    = "dsVert/formal-cox/blockwise-source-producer/input/v1"
	formalCoxBlockwiseSourceProducerMaskDomain     = "dsVert/formal-cox/blockwise-source-producer/mask/v1"
	formalCoxBlockwiseSourceProducerIntentDomain   = "dsVert/formal-cox/blockwise-source-producer/intent/v1"
	formalCoxBlockwiseSourceProducerOutboxDomain   = "dsVert/formal-cox/blockwise-source-producer/outbox-binding/v1"
	formalCoxBlockwiseSourceProducerReceiptDomain  = "dsVert/formal-cox/blockwise-source-producer/receipt/v1"
	formalCoxBlockwiseSourceProducerStateDomain    = "dsVert/formal-cox/blockwise-source-producer/state/v1"
	formalCoxBlockwiseSourceProducerMetadataMax    = 256 << 10
	formalCoxBlockwiseSourceProducerStateMax       = 16 << 10
	formalCoxBlockwiseSourceProducerReadBuffer     = 32 << 10
	formalCoxBlockwiseSourceProducerTokenMax       = 40
)

type formalCoxBlockwiseSourceProductionBinding struct {
	Version                 string `json:"version"`
	Purpose                 string `json:"purpose"`
	ArtifactID              string `json:"artifact_id"`
	PlanSHA256              string `json:"plan_sha256"`
	RunID                   string `json:"run_id"`
	SnapshotSHA256          string `json:"snapshot_sha256"`
	PinsetSHA256            string `json:"pinset_sha256"`
	RecipientManifestSHA256 string `json:"recipient_manifest_sha256"`
	SourcePeerName          string `json:"source_peer_name"`
	SourcePeerID            string `json:"source_peer_id"`
	BlockIndex              int    `json:"block_index"`
	RowsInBlock             int    `json:"rows_in_block"`
	PaddingRows             int    `json:"padding_rows"`
	RowWidth                int    `json:"row_width"`
	InputCoordinateCount    int    `json:"input_coordinate_count"`
	SealedCoordinateCount   int    `json:"sealed_coordinate_count"`
	RingBits                int    `json:"ring_bits"`
	InputEncoding           string `json:"input_encoding"`
}

type formalCoxBlockwiseSourceProductionIntent struct {
	Version               string                                    `json:"version"`
	Purpose               string                                    `json:"purpose"`
	Binding               formalCoxBlockwiseSourceProductionBinding `json:"binding"`
	SourceInputCommitment string                                    `json:"source_input_commitment"`
	Signature             []byte                                    `json:"signature"`
}

type formalCoxBlockwiseSourceProductionOutboxBinding struct {
	Version               string                                    `json:"version"`
	Purpose               string                                    `json:"purpose"`
	Binding               formalCoxBlockwiseSourceProductionBinding `json:"binding"`
	SourceInputCommitment string                                    `json:"source_input_commitment"`
	RecipientPeerName     string                                    `json:"recipient_peer_name"`
	EnvelopeSHA256        string                                    `json:"envelope_sha256"`
	Signature             []byte                                    `json:"signature"`
}

type formalCoxBlockwiseSourceProductionReceipt struct {
	Version               string                                    `json:"version"`
	Purpose               string                                    `json:"purpose"`
	Binding               formalCoxBlockwiseSourceProductionBinding `json:"binding"`
	SourceInputCommitment string                                    `json:"source_input_commitment"`
	PairManifest          formalCoxBlockwiseSourcePairManifest      `json:"pair_manifest"`
	PairManifestSHA256    string                                    `json:"pair_manifest_sha256"`
	PreviousReceiptSHA256 string                                    `json:"previous_receipt_sha256,omitempty"`
	Signature             []byte                                    `json:"signature"`
}

type formalCoxBlockwiseSourceProductionResult struct {
	Receipt       formalCoxBlockwiseSourceProductionReceipt `json:"receipt"`
	ReceiptSHA256 string                                    `json:"receipt_sha256"`
	Replayed      bool                                      `json:"replayed"`
}

type formalCoxBlockwiseSourceProducerState struct {
	Version                 string `json:"version"`
	PlanSHA256              string `json:"plan_sha256"`
	RunID                   string `json:"run_id"`
	SnapshotSHA256          string `json:"snapshot_sha256"`
	PinsetSHA256            string `json:"pinset_sha256"`
	RecipientManifestSHA256 string `json:"recipient_manifest_sha256"`
	SourcePeerName          string `json:"source_peer_name"`
	SourcePeerID            string `json:"source_peer_id"`
	Generation              uint64 `json:"generation"`
	NextBlock               int    `json:"next_block"`
	PreviousMAC             string `json:"previous_mac,omitempty"`
	PreviousReceiptSHA256   string `json:"previous_receipt_sha256,omitempty"`
	MAC                     string `json:"mac"`
}

type formalCoxBlockwiseSourceProducer struct {
	mu                     sync.Mutex
	root                   string
	metadataDir            string
	outboxDirs             [2]string
	statePath              string
	owner                  *os.File
	key                    [32]byte
	session                *formalCoxBlockwiseSourceSession
	source                 string
	signingKey             []byte
	peakPrivateCoordinates int
	hook                   func(string) error
	closed                 bool
}

func formalCoxBlockwiseSourceProductionBindingFor(
	session *formalCoxBlockwiseSourceSession, source string, block int,
) (formalCoxBlockwiseSourceProductionBinding, error) {
	var zero formalCoxBlockwiseSourceProductionBinding
	if session == nil || session.context == nil ||
		session.context.peerIDs[source] == "" || block < 0 ||
		block >= session.context.plan.TotalBlocks {
		return zero, fmt.Errorf("formal-cox: invalid source production block")
	}
	plan := session.context.plan
	rows := formalCoxBlockwiseSourceRowsInBlock(plan, block)
	return formalCoxBlockwiseSourceProductionBinding{
		Version:    formalCoxBlockwiseSourceProducerVersion,
		Purpose:    formalCoxBlockwiseSourceProducerPurpose,
		ArtifactID: session.context.artifactID,
		PlanSHA256: session.context.planSHA256, RunID: plan.RunID,
		SnapshotSHA256:          plan.Policy.SnapshotSHA256,
		PinsetSHA256:            session.context.pinsetSHA256,
		RecipientManifestSHA256: session.manifestSHA256,
		SourcePeerName:          source, SourcePeerID: session.context.peerIDs[source],
		BlockIndex: block, RowsInBlock: rows,
		PaddingRows: plan.BlockCapacity - rows, RowWidth: plan.RowWidth,
		InputCoordinateCount:  rows * plan.RowWidth,
		SealedCoordinateCount: plan.BlockCapacity * plan.RowWidth,
		RingBits:              plan.RingBits, InputEncoding: formalCoxBlockwiseSourceProducerEncoding,
	}, nil
}

func formalCoxBlockwiseValidateSourceProductionSession(
	session *formalCoxBlockwiseSourceSession,
) error {
	if session == nil || session.context == nil {
		return fmt.Errorf("formal-cox: invalid source production session")
	}
	freshContext, err := newFormalCoxBlockwiseSourceContext(
		session.context.plan, session.context.pins)
	if err != nil || freshContext.planSHA256 != session.context.planSHA256 ||
		freshContext.pinsetSHA256 != session.context.pinsetSHA256 ||
		freshContext.artifactID != session.context.artifactID ||
		len(session.manifest.Tickets) != 2 {
		return fmt.Errorf("formal-cox: invalid source production session")
	}
	fresh, err := freshContext.bindRecipientManifest(session.manifest.Tickets)
	if err != nil || fresh.manifestSHA256 != session.manifestSHA256 ||
		len(session.tickets) != 2 || len(session.ticketSHA256) != 2 {
		return fmt.Errorf("formal-cox: invalid source production session")
	}
	wantManifest, wantErr := json.Marshal(fresh.manifest)
	gotManifest, gotErr := json.Marshal(session.manifest)
	if wantErr != nil || gotErr != nil || !bytes.Equal(wantManifest, gotManifest) {
		return fmt.Errorf("formal-cox: invalid source production session")
	}
	for _, peer := range freshContext.plan.Policy.CustodianPeers {
		if freshContext.peerIDs[peer] != session.context.peerIDs[peer] ||
			!hmac.Equal(freshContext.pins[peer], session.context.pins[peer]) {
			return fmt.Errorf("formal-cox: invalid source production session")
		}
	}
	for _, recipient := range freshContext.plan.Policy.ComputePeers {
		wantTicket, wantErr := json.Marshal(fresh.tickets[recipient])
		gotTicket, gotErr := json.Marshal(session.tickets[recipient])
		if wantErr != nil || gotErr != nil || !bytes.Equal(wantTicket, gotTicket) ||
			fresh.ticketSHA256[recipient] != session.ticketSHA256[recipient] ||
			freshContext.peerIDs[recipient] != session.context.peerIDs[recipient] ||
			freshContext.roles[recipient] != session.context.roles[recipient] {
			return fmt.Errorf("formal-cox: invalid source production session")
		}
	}
	return nil
}

func formalCoxBlockwiseSourceProductionIntentMessage(
	intent formalCoxBlockwiseSourceProductionIntent,
) ([]byte, error) {
	intent.Signature = nil
	encoded, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSourceProducerIntentDomain+"|"),
		encoded...), nil
}

func formalCoxBlockwiseSourceProductionOutboxMessage(
	binding formalCoxBlockwiseSourceProductionOutboxBinding,
) ([]byte, error) {
	binding.Signature = nil
	encoded, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSourceProducerOutboxDomain+"|"),
		encoded...), nil
}

func formalCoxBlockwiseValidateSourceProductionOutboxBinding(
	session *formalCoxBlockwiseSourceSession,
	binding formalCoxBlockwiseSourceProductionOutboxBinding,
	recipientIndex int, inputCommitment, envelopeSHA256 string,
) error {
	if session == nil || session.context == nil || recipientIndex < 0 ||
		recipientIndex >= len(session.context.plan.Policy.ComputePeers) {
		return fmt.Errorf("formal-cox: invalid source outbox binding context")
	}
	want, err := formalCoxBlockwiseSourceProductionBindingFor(
		session, binding.Binding.SourcePeerName, binding.Binding.BlockIndex)
	message, messageErr := formalCoxBlockwiseSourceProductionOutboxMessage(binding)
	recipient := session.context.plan.Policy.ComputePeers[recipientIndex]
	if err != nil || messageErr != nil ||
		binding.Version != formalCoxBlockwiseSourceProducerOutboxVersion ||
		binding.Purpose != formalCoxBlockwiseSourceProducerPurpose ||
		binding.Binding != want || binding.RecipientPeerName != recipient ||
		binding.SourceInputCommitment != inputCommitment ||
		binding.EnvelopeSHA256 != envelopeSHA256 ||
		!formalCoxIsSHA256(binding.SourceInputCommitment) ||
		!formalCoxIsSHA256(binding.EnvelopeSHA256) ||
		len(binding.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(session.context.pins[binding.Binding.SourcePeerName],
			message, binding.Signature) {
		return fmt.Errorf("formal-cox: invalid source outbox input binding")
	}
	return nil
}

func formalCoxBlockwiseSourceProductionReceiptMessage(
	receipt formalCoxBlockwiseSourceProductionReceipt,
) ([]byte, error) {
	receipt.Signature = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSourceProducerReceiptDomain+"|"),
		encoded...), nil
}

func formalCoxBlockwiseSourceProductionReceiptSHA256(
	receipt formalCoxBlockwiseSourceProductionReceipt,
) (string, error) {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourceProducerReceiptDomain+"/signed|"),
		encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseSourcePairManifestSHA256(
	manifest formalCoxBlockwiseSourcePairManifest,
) (string, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourcePairDomain+"/signed-manifest|"),
		encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseValidateSourceProductionReceipt(
	session *formalCoxBlockwiseSourceSession,
	receipt formalCoxBlockwiseSourceProductionReceipt,
	sourcePin ed25519.PublicKey,
) error {
	if session == nil || session.context == nil ||
		len(sourcePin) != ed25519.PublicKeySize ||
		!hmac.Equal(sourcePin, session.context.pins[receipt.Binding.SourcePeerName]) {
		return fmt.Errorf("formal-cox: invalid source production receipt context")
	}
	wantBinding, err := formalCoxBlockwiseSourceProductionBindingFor(
		session, receipt.Binding.SourcePeerName, receipt.Binding.BlockIndex)
	manifest := receipt.PairManifest
	wantRoot, rootErr := formalCoxBlockwiseSourcePairManifestRoot(manifest)
	manifestMessage, messageErr := formalCoxBlockwiseSourcePairManifestMessage(manifest)
	wantManifestSHA, digestErr := formalCoxBlockwiseSourcePairManifestSHA256(manifest)
	receiptMessage, receiptErr := formalCoxBlockwiseSourceProductionReceiptMessage(receipt)
	if err != nil || rootErr != nil || messageErr != nil || digestErr != nil ||
		receiptErr != nil || receipt.Version != formalCoxBlockwiseSourceProducerReceiptVersion ||
		receipt.Purpose != formalCoxBlockwiseSourceProducerPurpose ||
		receipt.Binding != wantBinding ||
		!formalCoxIsSHA256(receipt.SourceInputCommitment) ||
		receipt.PairManifestSHA256 != wantManifestSHA ||
		(receipt.PreviousReceiptSHA256 != "" &&
			!formalCoxIsSHA256(receipt.PreviousReceiptSHA256)) ||
		manifest.PairedInputRootSHA256 != wantRoot ||
		manifest.PlanSHA256 != wantBinding.PlanSHA256 ||
		manifest.RunID != wantBinding.RunID ||
		manifest.PinsetSHA256 != wantBinding.PinsetSHA256 ||
		manifest.RecipientManifestSHA256 != wantBinding.RecipientManifestSHA256 ||
		manifest.SourcePeerName != wantBinding.SourcePeerName ||
		manifest.SourcePeerID != wantBinding.SourcePeerID ||
		manifest.StepKind != formalCoxBlockwiseStepBlock ||
		manifest.BlockIndex != wantBinding.BlockIndex ||
		len(manifest.Recipients) != 2 ||
		len(manifest.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(sourcePin, manifestMessage, manifest.Signature) ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(sourcePin, receiptMessage, receipt.Signature) {
		return fmt.Errorf("formal-cox: invalid source production receipt")
	}
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		entry := manifest.Recipients[index]
		step, stepErr := formalCoxBlockwiseSourceCanonicalStep(
			session.context.plan, formalCoxBlockwiseStepBlock,
			receipt.Binding.BlockIndex)
		wantSlot, slotErr := formalCoxBlockwiseSourceSlotFor(
			session.context.plan, recipient, receipt.Binding.SourcePeerName,
			step, true)
		if entry.RecipientPeerName != recipient ||
			entry.RecipientPeerID != session.context.peerIDs[recipient] ||
			entry.RecipientRole != session.context.roles[recipient] ||
			entry.RecipientTicketSHA256 != session.ticketSHA256[recipient] ||
			entry.RecipientTransportKeySHA256 !=
				session.tickets[recipient].TransportKeySHA256 ||
			stepErr != nil || slotErr != nil || entry.AssetSlot != wantSlot ||
			manifest.CanonicalScheduleIndex != step.ScheduleIndex ||
			manifest.Iteration != step.Iteration ||
			!formalCoxIsSHA256(entry.EnvelopeSHA256) {
			return fmt.Errorf("formal-cox: invalid source production recipient")
		}
	}
	return nil
}

type formalCoxBlockwiseSourceDecimalReader struct {
	reader  io.Reader
	buffer  []byte
	start   int
	end     int
	pending error
}

func newFormalCoxBlockwiseSourceDecimalReader(
	reader io.Reader,
) *formalCoxBlockwiseSourceDecimalReader {
	return &formalCoxBlockwiseSourceDecimalReader{
		reader: reader, buffer: make([]byte, formalCoxBlockwiseSourceProducerReadBuffer),
	}
}

func (reader *formalCoxBlockwiseSourceDecimalReader) close() {
	clear(reader.buffer)
	reader.start, reader.end = 0, 0
	reader.reader = nil
	reader.pending = nil
}

func (reader *formalCoxBlockwiseSourceDecimalReader) next() (byte, error) {
	emptyReads := 0
	for reader.start == reader.end {
		if reader.pending != nil {
			err := reader.pending
			reader.pending = nil
			return 0, err
		}
		n, err := reader.reader.Read(reader.buffer)
		if n > 0 {
			reader.start, reader.end = 0, n
			if err != nil {
				reader.pending = err
			}
			break
		}
		if err != nil {
			return 0, err
		}
		emptyReads++
		if emptyReads >= 100 {
			return 0, io.ErrNoProgress
		}
	}
	value := reader.buffer[reader.start]
	reader.buffer[reader.start] = 0
	reader.start++
	return value, nil
}

func (reader *formalCoxBlockwiseSourceDecimalReader) signed(
	commitment io.Writer,
) (*big.Int, error) {
	value := new(big.Int)
	negative, first, digits := false, true, 0
	for {
		character, err := reader.next()
		if err != nil {
			value.SetInt64(0)
			return nil, fmt.Errorf("formal-cox: truncated decimal source block")
		}
		if _, err := commitment.Write([]byte{character}); err != nil {
			value.SetInt64(0)
			return nil, err
		}
		if character == '\n' {
			if first || digits == 0 {
				value.SetInt64(0)
				return nil, fmt.Errorf("formal-cox: empty decimal source coordinate")
			}
			break
		}
		if first && character == '-' {
			negative, first = true, false
			continue
		}
		if character < '0' || character > '9' ||
			digits >= formalCoxBlockwiseSourceProducerTokenMax ||
			(digits == 0 && character == '0' && negative) {
			value.SetInt64(0)
			return nil, fmt.Errorf("formal-cox: non-canonical decimal source coordinate")
		}
		if digits == 1 && value.Sign() == 0 {
			value.SetInt64(0)
			return nil, fmt.Errorf("formal-cox: non-canonical decimal source coordinate")
		}
		value.Mul(value, big.NewInt(10))
		value.Add(value, big.NewInt(int64(character-'0')))
		digits++
		first = false
	}
	if negative {
		value.Neg(value)
	}
	minimum := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	maximum := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	if value.Cmp(minimum) < 0 || value.Cmp(maximum) > 0 {
		value.SetInt64(0)
		return nil, fmt.Errorf("formal-cox: decimal source coordinate exceeds Ring128")
	}
	return value, nil
}

func formalCoxBlockwiseReadSourceDecimalBlock(
	input io.Reader, binding formalCoxBlockwiseSourceProductionBinding,
	key [32]byte,
) ([]*big.Int, string, error) {
	if input == nil || binding.InputCoordinateCount < 1 {
		return nil, "", fmt.Errorf("formal-cox: invalid decimal source stream")
	}
	encodedBinding, err := json.Marshal(binding)
	if err != nil {
		return nil, "", err
	}
	commitment := hmac.New(sha256.New, key[:])
	_, _ = commitment.Write([]byte(formalCoxBlockwiseSourceProducerInputDomain + "|"))
	_, _ = commitment.Write(encodedBinding)
	_, _ = commitment.Write([]byte{'|'})
	decoder := newFormalCoxBlockwiseSourceDecimalReader(input)
	defer decoder.close()
	values := make([]*big.Int, binding.InputCoordinateCount)
	for index := range values {
		values[index], err = decoder.signed(commitment)
		if err != nil {
			exactGCZeroBigInts(values)
			return nil, "", err
		}
	}
	if _, err := decoder.next(); err != io.EOF {
		exactGCZeroBigInts(values)
		return nil, "", fmt.Errorf("formal-cox: trailing decimal source coordinates")
	}
	return values, hex.EncodeToString(commitment.Sum(nil)), nil
}

func formalCoxBlockwiseSourceProductionMask(
	key [32]byte, binding formalCoxBlockwiseSourceProductionBinding,
	inputCommitment string, coordinate int,
) (*big.Int, error) {
	if !formalCoxIsSHA256(inputCommitment) || coordinate < 0 ||
		binding.RingBits < 128 || binding.RingBits > exactGCMaxRingBits {
		return nil, fmt.Errorf("formal-cox: invalid source production mask binding")
	}
	encodedBinding, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	width := exactGCRecordBytes(binding.RingBits)
	material := make([]byte, width)
	defer clear(material)
	var counterBytes [8]byte
	for offset, counter := 0, uint64(0); offset < width; counter++ {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte(formalCoxBlockwiseSourceProducerMaskDomain + "|"))
		_, _ = mac.Write(encodedBinding)
		_, _ = mac.Write([]byte{'|'})
		_, _ = mac.Write([]byte(inputCommitment))
		binary.BigEndian.PutUint64(counterBytes[:], uint64(coordinate))
		_, _ = mac.Write(counterBytes[:])
		binary.BigEndian.PutUint64(counterBytes[:], counter)
		_, _ = mac.Write(counterBytes[:])
		chunk := mac.Sum(nil)
		offset += copy(material[offset:], chunk)
		clear(chunk)
	}
	excess := width*8 - binding.RingBits
	if excess > 0 {
		material[0] &= byte(0xff >> excess)
	}
	return new(big.Int).SetBytes(material), nil
}

func formalCoxBlockwiseSourceProducerStateMAC(
	key [32]byte, state formalCoxBlockwiseSourceProducerState,
) (string, error) {
	state.MAC = ""
	encoded, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(formalCoxBlockwiseSourceProducerStateDomain + "|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func newFormalCoxBlockwiseSourceProducer(
	root string, key [32]byte, session *formalCoxBlockwiseSourceSession,
	source string, signingKey ed25519.PrivateKey,
) (*formalCoxBlockwiseSourceProducer, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		root == string(filepath.Separator) ||
		bytes.Equal(key[:], make([]byte, len(key))) || session == nil ||
		session.context == nil || session.context.peerIDs[source] == "" ||
		len(signingKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(signingKey.Public().(ed25519.PublicKey),
			session.context.pins[source]) {
		return nil, fmt.Errorf("formal-cox: invalid private source producer policy")
	}
	if err := formalCoxBlockwiseValidateSourceProductionSession(session); err != nil {
		return nil, err
	}
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(root); err != nil {
		return nil, err
	}
	producer := &formalCoxBlockwiseSourceProducer{
		root: root, metadataDir: filepath.Join(root, "metadata-v1"),
		statePath: filepath.Join(root, "cursor-v1.json"), key: key,
		session: session, source: source,
		signingKey: append([]byte(nil), signingKey...),
	}
	producer.outboxDirs = [2]string{
		filepath.Join(root, "outbox-0-v1"), filepath.Join(root, "outbox-1-v1"),
	}
	for _, directory := range append([]string{producer.metadataDir},
		producer.outboxDirs[:]...) {
		if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
			clear(producer.signingKey)
			clear(producer.key[:])
			return nil, err
		}
	}
	owner, err := formalCoxBlockwiseSourceAcquireOwner(
		filepath.Join(root, "owner.lock"))
	if err != nil {
		clear(producer.signingKey)
		clear(producer.key[:])
		return nil, err
	}
	producer.owner = owner
	for _, directory := range append([]string{producer.metadataDir},
		producer.outboxDirs[:]...) {
		if err := formalCoxBlockwiseSourceProducerCleanupTemps(directory); err != nil {
			_ = producer.Close()
			return nil, err
		}
	}
	if err := producer.bootstrapAndRecover(); err != nil {
		_ = producer.Close()
		return nil, err
	}
	return producer, nil
}

func (producer *formalCoxBlockwiseSourceProducer) BlockBinding(
	block int,
) (formalCoxBlockwiseSourceProductionBinding, error) {
	producer.mu.Lock()
	defer producer.mu.Unlock()
	if producer.closed || producer.owner == nil {
		return formalCoxBlockwiseSourceProductionBinding{},
			fmt.Errorf("formal-cox: source producer is closed")
	}
	return formalCoxBlockwiseSourceProductionBindingFor(
		producer.session, producer.source, block)
}

func (producer *formalCoxBlockwiseSourceProducer) intentPath(block int) string {
	return filepath.Join(producer.metadataDir,
		fmt.Sprintf("intent-%012d.json", block))
}

func (producer *formalCoxBlockwiseSourceProducer) receiptPath(block int) string {
	return filepath.Join(producer.metadataDir,
		fmt.Sprintf("receipt-%012d.json", block))
}

func (producer *formalCoxBlockwiseSourceProducer) outboxPath(
	block, recipientIndex int,
) string {
	return filepath.Join(producer.outboxDirs[recipientIndex],
		fmt.Sprintf("block-%012d.json", block))
}

func (producer *formalCoxBlockwiseSourceProducer) outboxBindingPath(
	block, recipientIndex int,
) string {
	return filepath.Join(producer.metadataDir,
		fmt.Sprintf("outbox-binding-%012d-%d.json", block, recipientIndex))
}

func formalCoxBlockwiseSourceProducerRemoveOrphan(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) {
		return fmt.Errorf("formal-cox: unsafe orphaned source outbox")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return exactGCSyncDir(filepath.Dir(path))
}

func formalCoxBlockwiseSourceProducerCleanupTemps(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".formal-cox-source-producer-") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("formal-cox: unsafe source producer temporary")
		}
		if exactGCPrivateOwnedRegular(info) {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		matches := 0
		matchedPath := ""
		for _, candidate := range entries {
			if strings.HasPrefix(candidate.Name(), ".formal-cox-source-producer-") {
				continue
			}
			candidateInfo, candidateErr := os.Lstat(filepath.Join(dir, candidate.Name()))
			if candidateErr == nil && candidateInfo.Mode().IsRegular() &&
				os.SameFile(info, candidateInfo) {
				matches++
				matchedPath = filepath.Join(dir, candidate.Name())
			}
		}
		if matches != 1 {
			return fmt.Errorf("formal-cox: unsafe linked source producer temporary")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := exactGCSyncDir(dir); err != nil {
			return err
		}
		finalInfo, err := os.Lstat(matchedPath)
		if err != nil || !finalInfo.Mode().IsRegular() ||
			finalInfo.Mode().Perm()&0o077 != 0 ||
			!exactGCPrivateOwnedRegular(finalInfo) {
			return fmt.Errorf("formal-cox: unsafe recovered source producer record")
		}
	}
	return nil
}

func formalCoxBlockwiseSourceProducerPersistCAS(
	path string, encoded []byte, maximum int64,
) (bool, error) {
	if int64(len(encoded)) < 2 || int64(len(encoded)) > maximum {
		return false, fmt.Errorf("formal-cox: source producer record exceeds its bound")
	}
	if existing, err := formalCoxBlockwiseReadPrivateFile(path, 2, maximum); err == nil {
		if !bytes.Equal(existing, encoded) {
			return false, fmt.Errorf("formal-cox: conflicting source producer replay")
		}
		return true, exactGCSyncDir(filepath.Dir(path))
	} else if !os.IsNotExist(err) {
		return false, err
	}
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".formal-cox-source-producer-")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := exactGCWriteFull(temporary, encoded); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		existing, readErr := formalCoxBlockwiseReadPrivateFile(path, 2, maximum)
		if readErr != nil || !bytes.Equal(existing, encoded) {
			return false, fmt.Errorf("formal-cox: conflicting source producer replay")
		}
		return true, exactGCSyncDir(dir)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return false, err
	}
	if err := exactGCSyncDir(dir); err != nil {
		return false, err
	}
	if _, err := formalCoxBlockwiseReadPrivateFile(path, 2, maximum); err != nil {
		return false, err
	}
	return false, nil
}

func (producer *formalCoxBlockwiseSourceProducer) initialState() (
	formalCoxBlockwiseSourceProducerState, error,
) {
	context := producer.session.context
	state := formalCoxBlockwiseSourceProducerState{
		Version:    formalCoxBlockwiseSourceProducerStateVersion,
		PlanSHA256: context.planSHA256, RunID: context.plan.RunID,
		SnapshotSHA256:          context.plan.Policy.SnapshotSHA256,
		PinsetSHA256:            context.pinsetSHA256,
		RecipientManifestSHA256: producer.session.manifestSHA256,
		SourcePeerName:          producer.source,
		SourcePeerID:            context.peerIDs[producer.source], Generation: 1,
	}
	var err error
	state.MAC, err = formalCoxBlockwiseSourceProducerStateMAC(producer.key, state)
	return state, err
}

func (producer *formalCoxBlockwiseSourceProducer) validateState(
	state formalCoxBlockwiseSourceProducerState,
) error {
	want, err := producer.initialState()
	if err != nil || state.Version != want.Version ||
		state.PlanSHA256 != want.PlanSHA256 || state.RunID != want.RunID ||
		state.SnapshotSHA256 != want.SnapshotSHA256 ||
		state.PinsetSHA256 != want.PinsetSHA256 ||
		state.RecipientManifestSHA256 != want.RecipientManifestSHA256 ||
		state.SourcePeerName != want.SourcePeerName ||
		state.SourcePeerID != want.SourcePeerID || state.Generation < 1 ||
		state.NextBlock < 0 || state.NextBlock > producer.session.context.plan.TotalBlocks ||
		(state.PreviousMAC != "" && !formalCoxIsSHA256(state.PreviousMAC)) ||
		(state.PreviousReceiptSHA256 != "" &&
			!formalCoxIsSHA256(state.PreviousReceiptSHA256)) ||
		((state.NextBlock == 0) != (state.PreviousReceiptSHA256 == "")) ||
		!formalCoxIsSHA256(state.MAC) {
		return fmt.Errorf("formal-cox: invalid source producer cursor")
	}
	wantMAC, err := formalCoxBlockwiseSourceProducerStateMAC(producer.key, state)
	if err != nil || !hmac.Equal([]byte(wantMAC), []byte(state.MAC)) {
		return fmt.Errorf("formal-cox: source producer cursor authentication failed")
	}
	return nil
}

func (producer *formalCoxBlockwiseSourceProducer) readState() (
	formalCoxBlockwiseSourceProducerState, error,
) {
	var state formalCoxBlockwiseSourceProducerState
	encoded, err := formalCoxBlockwiseReadPrivateFile(
		producer.statePath, 2, formalCoxBlockwiseSourceProducerStateMax)
	if err != nil {
		return state, err
	}
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseSourceProducerStateMax, "source producer cursor",
		&state); err != nil {
		return state, err
	}
	return state, producer.validateState(state)
}

func (producer *formalCoxBlockwiseSourceProducer) writeState(
	state formalCoxBlockwiseSourceProducerState,
) error {
	if err := producer.validateState(state); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) > formalCoxBlockwiseSourceProducerStateMax {
		return fmt.Errorf("formal-cox: source producer cursor exceeds its bound")
	}
	if _, err := os.Lstat(producer.statePath); err == nil {
		if _, err := formalCoxBlockwiseReadPrivateFile(
			producer.statePath, 2, formalCoxBlockwiseSourceProducerStateMax); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := exactGCAtomicReplace(producer.statePath, encoded); err != nil {
		return err
	}
	_, err = producer.readState()
	return err
}

func (producer *formalCoxBlockwiseSourceProducer) advanceState(
	state formalCoxBlockwiseSourceProducerState, receiptSHA string,
) (formalCoxBlockwiseSourceProducerState, error) {
	if state.NextBlock >= producer.session.context.plan.TotalBlocks ||
		!formalCoxIsSHA256(receiptSHA) {
		return state, fmt.Errorf("formal-cox: invalid source producer cursor advance")
	}
	previous := state.MAC
	state.Generation++
	state.NextBlock++
	state.PreviousMAC = previous
	state.PreviousReceiptSHA256 = receiptSHA
	state.MAC = ""
	var err error
	state.MAC, err = formalCoxBlockwiseSourceProducerStateMAC(producer.key, state)
	if err != nil {
		return state, err
	}
	if err := producer.writeState(state); err != nil {
		return state, err
	}
	return state, nil
}

func (producer *formalCoxBlockwiseSourceProducer) readReceipt(
	block int,
) (formalCoxBlockwiseSourceProductionReceipt, []byte, error) {
	var receipt formalCoxBlockwiseSourceProductionReceipt
	encoded, err := formalCoxBlockwiseReadPrivateFile(
		producer.receiptPath(block), 2,
		formalCoxBlockwiseSourceProducerMetadataMax)
	if err != nil {
		return receipt, nil, err
	}
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseSourceProducerMetadataMax, "source production receipt",
		&receipt); err != nil {
		return receipt, nil, err
	}
	return receipt, encoded, nil
}

func (producer *formalCoxBlockwiseSourceProducer) readIntent(
	block int,
) (formalCoxBlockwiseSourceProductionIntent, error) {
	var intent formalCoxBlockwiseSourceProductionIntent
	encoded, err := formalCoxBlockwiseReadPrivateFile(
		producer.intentPath(block), 2,
		formalCoxBlockwiseSourceProducerMetadataMax)
	if err != nil {
		return intent, err
	}
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseSourceProducerMetadataMax, "source production intent",
		&intent); err != nil {
		return intent, err
	}
	want, err := formalCoxBlockwiseSourceProductionBindingFor(
		producer.session, producer.source, block)
	message, messageErr := formalCoxBlockwiseSourceProductionIntentMessage(intent)
	if err != nil || messageErr != nil ||
		intent.Version != formalCoxBlockwiseSourceProducerIntentVersion ||
		intent.Purpose != formalCoxBlockwiseSourceProducerPurpose ||
		intent.Binding != want || !formalCoxIsSHA256(intent.SourceInputCommitment) ||
		len(intent.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(producer.session.context.pins[producer.source],
			message, intent.Signature) {
		return intent, fmt.Errorf("formal-cox: invalid source production intent")
	}
	return intent, nil
}

func (producer *formalCoxBlockwiseSourceProducer) readOutboxBinding(
	block, recipientIndex int,
) (formalCoxBlockwiseSourceProductionOutboxBinding, error) {
	var binding formalCoxBlockwiseSourceProductionOutboxBinding
	encoded, err := formalCoxBlockwiseReadPrivateFile(
		producer.outboxBindingPath(block, recipientIndex), 2,
		formalCoxBlockwiseSourceProducerMetadataMax)
	if err != nil {
		return binding, err
	}
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseSourceProducerMetadataMax,
		"source production outbox binding", &binding); err != nil {
		return binding, err
	}
	return binding, nil
}

func (producer *formalCoxBlockwiseSourceProducer) validateCommittedBlock(
	block int, previous string,
) (formalCoxBlockwiseSourceProductionReceipt, string, error) {
	var zero formalCoxBlockwiseSourceProductionReceipt
	intent, intentErr := producer.readIntent(block)
	receipt, _, err := producer.readReceipt(block)
	if intentErr != nil || err != nil ||
		receipt.SourceInputCommitment != intent.SourceInputCommitment ||
		receipt.Binding != intent.Binding ||
		receipt.PreviousReceiptSHA256 != previous {
		return zero, "", fmt.Errorf("formal-cox: invalid source production receipt chain")
	}
	if err := formalCoxBlockwiseValidateSourceProductionReceipt(
		producer.session, receipt,
		producer.session.context.pins[producer.source]); err != nil {
		return zero, "", err
	}
	for index, recipient := range producer.session.context.plan.Policy.ComputePeers {
		encoded, err := formalCoxBlockwiseReadPrivateFile(
			producer.outboxPath(block, index), 2,
			producer.session.context.maximum)
		if err != nil {
			return zero, "", err
		}
		envelope, digest, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
			producer.session, recipient, encoded)
		outboxBinding, bindingErr := producer.readOutboxBinding(block, index)
		if err != nil || envelope.Header.SourcePeerName != producer.source ||
			envelope.Header.BlockIndex != block ||
			receipt.PairManifest.Recipients[index].EnvelopeSHA256 != digest ||
			bindingErr != nil ||
			formalCoxBlockwiseValidateSourceProductionOutboxBinding(
				producer.session, outboxBinding, index,
				receipt.SourceInputCommitment, digest) != nil {
			return zero, "", fmt.Errorf("formal-cox: invalid source producer outbox")
		}
		if _, err := formalCoxBlockwiseSourceValidatePairManifest(
			producer.session, receipt.PairManifest, envelope.Header, digest); err != nil {
			return zero, "", err
		}
	}
	digest, err := formalCoxBlockwiseSourceProductionReceiptSHA256(receipt)
	if err != nil {
		return zero, "", err
	}
	return receipt, digest, nil
}

func (producer *formalCoxBlockwiseSourceProducer) bootstrapAndRecover() error {
	state, err := producer.readState()
	if os.IsNotExist(err) {
		state, err = producer.initialState()
		if err == nil {
			err = producer.writeState(state)
		}
	}
	if err != nil {
		return err
	}
	previous := ""
	for block := 0; block < state.NextBlock; block++ {
		_, previous, err = producer.validateCommittedBlock(block, previous)
		if err != nil {
			return err
		}
	}
	if previous != state.PreviousReceiptSHA256 {
		return fmt.Errorf("formal-cox: source producer cursor lost its receipt chain")
	}
	for state.NextBlock < producer.session.context.plan.TotalBlocks {
		if _, err := os.Lstat(producer.receiptPath(state.NextBlock)); os.IsNotExist(err) {
			break
		} else if err != nil {
			return err
		}
		_, receiptSHA, err := producer.validateCommittedBlock(
			state.NextBlock, state.PreviousReceiptSHA256)
		if err != nil {
			return err
		}
		state, err = producer.advanceState(state, receiptSHA)
		if err != nil {
			return err
		}
	}
	return nil
}

func (producer *formalCoxBlockwiseSourceProducer) callHook(phase string) error {
	if producer.hook == nil {
		return nil
	}
	return producer.hook(phase)
}

func (producer *formalCoxBlockwiseSourceProducer) intent(
	binding formalCoxBlockwiseSourceProductionBinding, commitment string,
) (formalCoxBlockwiseSourceProductionIntent, []byte, error) {
	intent := formalCoxBlockwiseSourceProductionIntent{
		Version: formalCoxBlockwiseSourceProducerIntentVersion,
		Purpose: formalCoxBlockwiseSourceProducerPurpose,
		Binding: binding, SourceInputCommitment: commitment,
	}
	message, err := formalCoxBlockwiseSourceProductionIntentMessage(intent)
	if err != nil {
		return intent, nil, err
	}
	intent.Signature = ed25519.Sign(producer.signingKey, message)
	encoded, err := json.Marshal(intent)
	return intent, encoded, err
}

func (producer *formalCoxBlockwiseSourceProducer) loadOrSealOutbox(
	binding formalCoxBlockwiseSourceProductionBinding,
	step formalCoxBlockwiseWorkerStep, recipientIndex int,
	inputCommitment string, shares []*big.Int,
) ([]byte, bool, error) {
	recipient := producer.session.context.plan.Policy.ComputePeers[recipientIndex]
	path := producer.outboxPath(binding.BlockIndex, recipientIndex)
	bindingPath := producer.outboxBindingPath(binding.BlockIndex, recipientIndex)
	if existing, err := formalCoxBlockwiseReadPrivateFile(
		path, 2, producer.session.context.maximum); err == nil {
		envelope, digest, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
			producer.session, recipient, existing)
		if err != nil || envelope.Header.SourcePeerName != producer.source ||
			envelope.Header.BlockIndex != binding.BlockIndex {
			return nil, false, fmt.Errorf("formal-cox: invalid existing source outbox")
		}
		outboxBinding, bindingErr := producer.readOutboxBinding(
			binding.BlockIndex, recipientIndex)
		if bindingErr == nil {
			if err := formalCoxBlockwiseValidateSourceProductionOutboxBinding(
				producer.session, outboxBinding, recipientIndex,
				inputCommitment, digest); err != nil {
				return nil, false, err
			}
			return existing, true, nil
		}
		if !os.IsNotExist(bindingErr) {
			return nil, false, bindingErr
		}
		// A process can stop after the ciphertext CAS and before its signed
		// input-binding CAS.  Such an orphan is never reusable: discard it
		// and seal the deterministic shares again under fresh C1 randomness.
		if err := formalCoxBlockwiseSourceProducerRemoveOrphan(path); err != nil {
			return nil, false, err
		}
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	if _, err := os.Lstat(bindingPath); err == nil {
		return nil, false, fmt.Errorf("formal-cox: source outbox binding lacks ciphertext")
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	encoded, err := formalCoxBlockwiseSealSourceInput(
		producer.session, producer.source, recipient, step, shares, nil,
		producer.signingKey)
	if err != nil {
		return nil, false, err
	}
	replayed, err := formalCoxBlockwiseSourceProducerPersistCAS(
		path, encoded, producer.session.context.maximum)
	if err != nil {
		clear(encoded)
		return nil, false, err
	}
	_, envelopeSHA256, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
		producer.session, recipient, encoded)
	if err != nil {
		clear(encoded)
		return nil, false, err
	}
	outboxBinding := formalCoxBlockwiseSourceProductionOutboxBinding{
		Version: formalCoxBlockwiseSourceProducerOutboxVersion,
		Purpose: formalCoxBlockwiseSourceProducerPurpose,
		Binding: binding, SourceInputCommitment: inputCommitment,
		RecipientPeerName: recipient, EnvelopeSHA256: envelopeSHA256,
	}
	message, err := formalCoxBlockwiseSourceProductionOutboxMessage(outboxBinding)
	if err != nil {
		clear(encoded)
		return nil, false, err
	}
	outboxBinding.Signature = ed25519.Sign(producer.signingKey, message)
	encodedBinding, err := json.Marshal(outboxBinding)
	if err != nil {
		clear(encoded)
		return nil, false, err
	}
	if _, err := formalCoxBlockwiseSourceProducerPersistCAS(
		bindingPath, encodedBinding,
		formalCoxBlockwiseSourceProducerMetadataMax); err != nil {
		clear(encoded)
		return nil, false, err
	}
	return encoded, replayed, nil
}

func (producer *formalCoxBlockwiseSourceProducer) ProduceBlock(
	binding formalCoxBlockwiseSourceProductionBinding, input io.Reader,
) (formalCoxBlockwiseSourceProductionResult, error) {
	producer.mu.Lock()
	defer producer.mu.Unlock()
	var zero formalCoxBlockwiseSourceProductionResult
	if producer.closed || producer.owner == nil {
		return zero, fmt.Errorf("formal-cox: source producer is closed")
	}
	want, err := formalCoxBlockwiseSourceProductionBindingFor(
		producer.session, producer.source, binding.BlockIndex)
	if err != nil || binding != want {
		return zero, fmt.Errorf("formal-cox: source production binding mismatch")
	}
	state, err := producer.readState()
	if err != nil {
		return zero, err
	}
	if binding.BlockIndex > state.NextBlock {
		return zero, fmt.Errorf("formal-cox: source blocks must be produced in canonical order")
	}
	values, commitment, err := formalCoxBlockwiseReadSourceDecimalBlock(
		input, binding, producer.key)
	if err != nil {
		return zero, err
	}
	defer exactGCZeroBigInts(values)
	if len(values) > producer.peakPrivateCoordinates {
		producer.peakPrivateCoordinates = len(values)
	}
	intent, encodedIntent, err := producer.intent(binding, commitment)
	if err != nil {
		return zero, err
	}
	if _, err := formalCoxBlockwiseSourceProducerPersistCAS(
		producer.intentPath(binding.BlockIndex), encodedIntent,
		formalCoxBlockwiseSourceProducerMetadataMax); err != nil {
		return zero, err
	}
	if err := producer.callHook("after-intent"); err != nil {
		return zero, err
	}
	if binding.BlockIndex < state.NextBlock {
		receipt, receiptSHA, err := producer.validateCommittedBlock(
			binding.BlockIndex, receiptPreviousForBlock(producer, binding.BlockIndex))
		if err != nil || receipt.SourceInputCommitment != intent.SourceInputCommitment {
			return zero, fmt.Errorf("formal-cox: conflicting source producer replay")
		}
		return formalCoxBlockwiseSourceProductionResult{
			Receipt: receipt, ReceiptSHA256: receiptSHA, Replayed: true,
		}, nil
	}

	plan := producer.session.context.plan
	step, err := formalCoxBlockwiseSourceCanonicalStep(
		plan, formalCoxBlockwiseStepBlock, binding.BlockIndex)
	if err != nil {
		return zero, err
	}
	modulus := exactGCModulus(plan.RingBits)
	shares := make([]*big.Int, binding.SealedCoordinateCount)
	defer exactGCZeroBigInts(shares)
	if resident := len(values) + len(shares); resident > producer.peakPrivateCoordinates {
		producer.peakPrivateCoordinates = resident
	}
	for index := range shares {
		shares[index] = new(big.Int)
		if index >= len(values) {
			continue
		}
		values[index].Mod(values[index], modulus)
		shares[index], err = formalCoxBlockwiseSourceProductionMask(
			producer.key, binding, commitment, index)
		if err != nil {
			return zero, err
		}
	}
	var outboxes [2][]byte
	outboxes[0], _, err = producer.loadOrSealOutbox(
		binding, step, 0, commitment, shares)
	if err != nil {
		return zero, err
	}
	defer clear(outboxes[0])
	if err := producer.callHook("after-outbox-0"); err != nil {
		return zero, err
	}
	for index := range shares {
		if index >= len(values) {
			shares[index].SetInt64(0)
			continue
		}
		shares[index].Sub(values[index], shares[index])
		shares[index].Mod(shares[index], modulus)
		values[index].SetInt64(0)
	}
	outboxes[1], _, err = producer.loadOrSealOutbox(
		binding, step, 1, commitment, shares)
	if err != nil {
		return zero, err
	}
	defer clear(outboxes[1])
	if err := producer.callHook("after-outbox-1"); err != nil {
		return zero, err
	}
	manifestBytes, err := formalCoxBlockwisePairSourceEnvelopes(
		producer.session, producer.source, step, outboxes[:], producer.signingKey)
	if err != nil {
		return zero, err
	}
	defer clear(manifestBytes)
	var manifest formalCoxBlockwiseSourcePairManifest
	if err := formalCoxBlockwiseSourceDecodeCanonical(manifestBytes,
		formalCoxBlockwiseSourceProducerMetadataMax, "source pair manifest",
		&manifest); err != nil {
		return zero, err
	}
	manifestSHA, err := formalCoxBlockwiseSourcePairManifestSHA256(manifest)
	if err != nil {
		return zero, err
	}
	receipt := formalCoxBlockwiseSourceProductionReceipt{
		Version: formalCoxBlockwiseSourceProducerReceiptVersion,
		Purpose: formalCoxBlockwiseSourceProducerPurpose,
		Binding: binding, SourceInputCommitment: commitment,
		PairManifest: manifest, PairManifestSHA256: manifestSHA,
		PreviousReceiptSHA256: state.PreviousReceiptSHA256,
	}
	message, err := formalCoxBlockwiseSourceProductionReceiptMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(producer.signingKey, message)
	if err := formalCoxBlockwiseValidateSourceProductionReceipt(
		producer.session, receipt,
		producer.session.context.pins[producer.source]); err != nil {
		return zero, err
	}
	encodedReceipt, err := json.Marshal(receipt)
	if err != nil {
		return zero, err
	}
	if _, err := formalCoxBlockwiseSourceProducerPersistCAS(
		producer.receiptPath(binding.BlockIndex), encodedReceipt,
		formalCoxBlockwiseSourceProducerMetadataMax); err != nil {
		return zero, err
	}
	receiptSHA, err := formalCoxBlockwiseSourceProductionReceiptSHA256(receipt)
	if err != nil {
		return zero, err
	}
	if err := producer.callHook("after-receipt"); err != nil {
		return zero, err
	}
	if _, err := producer.advanceState(state, receiptSHA); err != nil {
		return zero, err
	}
	if err := producer.callHook("after-state"); err != nil {
		return zero, err
	}
	return formalCoxBlockwiseSourceProductionResult{
		Receipt: receipt, ReceiptSHA256: receiptSHA,
	}, nil
}

func receiptPreviousForBlock(
	producer *formalCoxBlockwiseSourceProducer, block int,
) string {
	if block == 0 {
		return ""
	}
	receipt, _, err := producer.readReceipt(block - 1)
	if err != nil {
		return ""
	}
	digest, err := formalCoxBlockwiseSourceProductionReceiptSHA256(receipt)
	if err != nil {
		return ""
	}
	return digest
}

func (producer *formalCoxBlockwiseSourceProducer) Close() error {
	producer.mu.Lock()
	defer producer.mu.Unlock()
	if producer.closed {
		return nil
	}
	producer.closed = true
	clear(producer.signingKey)
	clear(producer.key[:])
	if producer.owner == nil {
		return nil
	}
	unlockErr := formalFinalizerHandoffUnlockAuthority(producer.owner)
	closeErr := producer.owner.Close()
	producer.owner = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
