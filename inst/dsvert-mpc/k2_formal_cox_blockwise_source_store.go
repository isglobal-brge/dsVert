package main

// Recipient-local encrypted source/noise spool for the bounded formal-Cox
// worker. The codec is purpose-bound to one signed blockwise plan. Durable
// slots contain only signed transport ciphertexts; plaintext additive shares
// exist only while one recipient validates or loads one slot. This file
// registers no command, capability, DSI method, publication, or lifecycle.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	formalCoxBlockwiseSourcePurpose         = "formal-cox-blockwise-source-v1"
	formalCoxBlockwiseSourceEnvelopeVersion = "dsvert-formal-cox-blockwise-source-envelope-v1"
	formalCoxBlockwiseSourceStateVersion    = "dsvert-formal-cox-blockwise-source-state-v1"
	formalCoxBlockwiseSourceTicketVersion   = "dsvert-formal-cox-blockwise-source-recipient-ticket-v1"
	formalCoxBlockwiseSourceManifestVersion = "dsvert-formal-cox-blockwise-source-recipient-manifest-v1"
	formalCoxBlockwiseSourceRootDomain      = "dsVert/formal-cox/blockwise-source/root/v1"
	formalCoxBlockwiseSourceEnvelopeDomain  = "dsVert/formal-cox/blockwise-source/envelope/v1"
	formalCoxBlockwiseSourceHeaderDomain    = "dsVert/formal-cox/blockwise-source/private-header/v1"
	formalCoxBlockwiseSourceStateDomain     = "dsVert/formal-cox/blockwise-source/state/v1"
	formalCoxBlockwiseSourceKeyDomain       = "dsVert/formal-cox/blockwise-source/transport-key/v1"
	formalCoxBlockwiseSourceTicketDomain    = "dsVert/formal-cox/blockwise-source/recipient-ticket/v1"
	formalCoxBlockwiseSourceManifestDomain  = "dsVert/formal-cox/blockwise-source/recipient-manifest/v1"
	formalCoxBlockwiseSourcePairVersion     = "dsvert-formal-cox-blockwise-source-pair-v1"
	formalCoxBlockwiseSourcePairDomain      = "dsVert/formal-cox/blockwise-source/pair/v1"
	formalCoxBlockwiseNoiseBarrierVersion   = "dsvert-formal-cox-blockwise-noise-barrier-v1"
	formalCoxBlockwiseNoiseBarrierDomain    = "dsVert/formal-cox/blockwise-source/noise-barrier/v1"
	formalCoxBlockwiseBoundSlotVersion      = "dsvert-formal-cox-blockwise-bound-source-slot-v1"
	formalCoxBlockwisePairedStepRootDomain  = "dsVert/formal-cox/blockwise-source/paired-step-root/v1"
	formalCoxBlockwiseSourceStateMax        = 8 << 10
	formalCoxBlockwiseSourceJSONSlack       = 8 << 10
	formalCoxBlockwiseSourceBindingMax      = 256 << 10
	formalCoxBlockwiseSourceCipherOverhead  = 32 + 12 + 16
)

var formalCoxBlockwiseSourcePrivateMagic = [8]byte{'F', 'C', 'X', 'S', 'R', 'C', 'V', '1'}

type formalCoxBlockwiseSourceHeader struct {
	Version                     string `json:"version"`
	Purpose                     string `json:"purpose"`
	PlanSHA256                  string `json:"plan_sha256"`
	RunID                       string `json:"run_id"`
	PinsetSHA256                string `json:"pinset_sha256"`
	SourcePeerName              string `json:"source_peer_name"`
	SourcePeerID                string `json:"source_peer_id"`
	SourceIndex                 int    `json:"source_index"`
	RecipientPeerName           string `json:"recipient_peer_name"`
	RecipientPeerID             string `json:"recipient_peer_id"`
	RecipientRole               string `json:"recipient_role"`
	RecipientTransportKeySHA256 string `json:"recipient_transport_key_sha256"`
	RecipientTicketSHA256       string `json:"recipient_ticket_sha256"`
	RecipientManifestSHA256     string `json:"recipient_manifest_sha256"`
	AssetSlot                   int    `json:"asset_slot"`
	StepKind                    string `json:"step_kind"`
	CanonicalScheduleIndex      int    `json:"canonical_schedule_index"`
	Iteration                   int    `json:"iteration"`
	BlockIndex                  int    `json:"block_index"`
	CoordinateOffset            int    `json:"coordinate_offset"`
	CoordinateCount             int    `json:"coordinate_count"`
	RowsInBlock                 int    `json:"rows_in_block"`
	PaddingRows                 int    `json:"padding_rows"`
	RingBits                    int    `json:"ring_bits"`
	RecordBytes                 int    `json:"record_bytes"`
	HasValidityShare            bool   `json:"has_validity_share"`
	ReusableAcrossIterations    bool   `json:"reusable_across_iterations"`
}

type formalCoxBlockwiseSourceEnvelope struct {
	Header           formalCoxBlockwiseSourceHeader `json:"header"`
	CiphertextSHA256 string                         `json:"ciphertext_sha256"`
	Ciphertext       []byte                         `json:"ciphertext"`
	Signature        []byte                         `json:"signature"`
}

type formalCoxBlockwiseSourceInput struct {
	Step                  formalCoxBlockwiseWorkerStep
	RecipientPeer         string
	RecipientRootSHA256   string
	PairedInputRootSHA256 string
	EnvelopeSHA256        []string
	Shares                []*big.Int `json:"-"`
	ValidityShare         *bool      `json:"-"`
}

type formalCoxBlockwiseSourcePairRecipient struct {
	RecipientPeerName           string `json:"recipient_peer_name"`
	RecipientPeerID             string `json:"recipient_peer_id"`
	RecipientRole               string `json:"recipient_role"`
	RecipientTicketSHA256       string `json:"recipient_ticket_sha256"`
	RecipientTransportKeySHA256 string `json:"recipient_transport_key_sha256"`
	AssetSlot                   int    `json:"asset_slot"`
	EnvelopeSHA256              string `json:"envelope_sha256"`
}

type formalCoxBlockwiseSourcePairManifest struct {
	Version                 string                                  `json:"version"`
	Purpose                 string                                  `json:"purpose"`
	PlanSHA256              string                                  `json:"plan_sha256"`
	RunID                   string                                  `json:"run_id"`
	PinsetSHA256            string                                  `json:"pinset_sha256"`
	RecipientManifestSHA256 string                                  `json:"recipient_manifest_sha256"`
	SourcePeerName          string                                  `json:"source_peer_name"`
	SourcePeerID            string                                  `json:"source_peer_id"`
	StepKind                string                                  `json:"step_kind"`
	CanonicalScheduleIndex  int                                     `json:"canonical_schedule_index"`
	Iteration               int                                     `json:"iteration"`
	BlockIndex              int                                     `json:"block_index"`
	Recipients              []formalCoxBlockwiseSourcePairRecipient `json:"recipients"`
	PairedInputRootSHA256   string                                  `json:"paired_input_root_sha256"`
	Signature               []byte                                  `json:"signature"`
}

type formalCoxBlockwiseNoiseRootCommitment struct {
	RecipientPeerName           string `json:"recipient_peer_name"`
	RecipientPeerID             string `json:"recipient_peer_id"`
	RecipientRole               string `json:"recipient_role"`
	RecipientTicketSHA256       string `json:"recipient_ticket_sha256"`
	RecipientTransportKeySHA256 string `json:"recipient_transport_key_sha256"`
	AssetSlot                   int    `json:"asset_slot"`
	EnvelopeSHA256              string `json:"envelope_sha256"`
}

type formalCoxBlockwiseNoiseApproval struct {
	SignerPeerName string `json:"signer_peer_name"`
	SignerPeerID   string `json:"signer_peer_id"`
	SignerRole     string `json:"signer_role"`
	Signature      []byte `json:"signature"`
}

type formalCoxBlockwiseNoiseBarrier struct {
	Version                 string                                  `json:"version"`
	Purpose                 string                                  `json:"purpose"`
	CanonicalArtifactID     string                                  `json:"canonical_artifact_id,omitempty"`
	SamplerContractSHA256   string                                  `json:"sampler_contract_sha256,omitempty"`
	SamplerGuardRootSHA256  string                                  `json:"sampler_guard_root_sha256,omitempty"`
	PlanSHA256              string                                  `json:"plan_sha256"`
	RunID                   string                                  `json:"run_id"`
	PinsetSHA256            string                                  `json:"pinset_sha256"`
	RecipientManifestSHA256 string                                  `json:"recipient_manifest_sha256"`
	StepKind                string                                  `json:"step_kind"`
	CanonicalScheduleIndex  int                                     `json:"canonical_schedule_index"`
	Iteration               int                                     `json:"iteration"`
	NoiseRoots              []formalCoxBlockwiseNoiseRootCommitment `json:"noise_root_commitments"`
	PairedNoiseRootSHA256   string                                  `json:"paired_noise_root_sha256"`
	Approvals               []formalCoxBlockwiseNoiseApproval       `json:"approvals"`
}

type formalCoxBlockwiseBoundSourceSlot struct {
	Version  string          `json:"version"`
	Envelope json.RawMessage `json:"envelope"`
	Binding  json.RawMessage `json:"binding"`
}

type formalCoxBlockwiseSourceRecipientTicket struct {
	Version            string `json:"version"`
	Purpose            string `json:"purpose"`
	PlanSHA256         string `json:"plan_sha256"`
	RunID              string `json:"run_id"`
	PinsetSHA256       string `json:"pinset_sha256"`
	RecipientPeerName  string `json:"recipient_peer_name"`
	RecipientPeerID    string `json:"recipient_peer_id"`
	RecipientRole      string `json:"recipient_role"`
	TransportKeySHA256 string `json:"transport_key_sha256"`
	TransportPublicKey []byte `json:"transport_public_key"`
	Signature          []byte `json:"signature"`
}

type formalCoxBlockwiseSourceRecipientManifest struct {
	Version      string                                    `json:"version"`
	Purpose      string                                    `json:"purpose"`
	PlanSHA256   string                                    `json:"plan_sha256"`
	RunID        string                                    `json:"run_id"`
	PinsetSHA256 string                                    `json:"pinset_sha256"`
	Tickets      []formalCoxBlockwiseSourceRecipientTicket `json:"tickets"`
}

type formalCoxBlockwiseSourceContext struct {
	plan         formalCoxBlockwisePlan
	pins         map[string]ed25519.PublicKey
	artifact     formalCoxBlockwiseStickyArtifact
	artifactID   string
	planSHA256   string
	pinsetSHA256 string
	peerIDs      map[string]string
	roles        map[string]string
	maximum      int64
	slotMaximum  int64
}

type formalCoxBlockwiseSourceSession struct {
	context        *formalCoxBlockwiseSourceContext
	manifest       formalCoxBlockwiseSourceRecipientManifest
	manifestSHA256 string
	tickets        map[string]formalCoxBlockwiseSourceRecipientTicket
	ticketSHA256   map[string]string
}

type formalCoxBlockwiseSourceState struct {
	Version        string `json:"version"`
	PlanSHA256     string `json:"plan_sha256"`
	PinsetSHA256   string `json:"pinset_sha256"`
	RecipientPeer  string `json:"recipient_peer"`
	RecipientRole  string `json:"recipient_role"`
	TransportKeyID string `json:"transport_key_sha256"`
	TicketSHA256   string `json:"recipient_ticket_sha256"`
	ManifestSHA256 string `json:"recipient_manifest_sha256"`
	Generation     uint64 `json:"generation"`
	NextSlot       int    `json:"next_slot"`
	PreviousMAC    string `json:"previous_mac"`
	MAC            string `json:"mac"`
}

type formalCoxBlockwiseSourceStore struct {
	mu             sync.Mutex
	slotDir        string
	statePath      string
	owner          *os.File
	key            [32]byte
	session        *formalCoxBlockwiseSourceSession
	plan           formalCoxBlockwisePlan
	recipient      string
	recipientRole  string
	recipientSK    []byte
	transportKeyID string
	ticketSHA256   string
	manifestSHA256 string
	syncSlotDir    func(string) error
	closed         bool
}

func formalCoxBlockwiseSourcePeerID(pin ed25519.PublicKey) (string, error) {
	if len(pin) != ed25519.PublicKeySize {
		return "", fmt.Errorf("formal-cox: invalid source identity pin")
	}
	message := append([]byte("dsVert/peer-capability/v1|"), pin...)
	digest := sha256.Sum256(message)
	return "dsv1_" + hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseSourceTransportKeyID(public []byte) (string, error) {
	if len(public) != 32 {
		return "", fmt.Errorf("formal-cox: invalid source transport key")
	}
	curve := ecdh.X25519()
	peer, err := curve.NewPublicKey(public)
	probeSeed := sha256.Sum256([]byte(
		formalCoxBlockwiseSourceKeyDomain + "/validation-probe"))
	probe, probeErr := curve.NewPrivateKey(probeSeed[:])
	if err != nil || probeErr != nil {
		return "", fmt.Errorf("formal-cox: invalid source transport key")
	}
	if _, err := probe.ECDH(peer); err != nil {
		return "", fmt.Errorf("formal-cox: invalid source transport key")
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourceKeyDomain+"|"), public...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseSourceClonePlan(plan formalCoxBlockwisePlan) (
	formalCoxBlockwisePlan, error) {
	var clone formalCoxBlockwisePlan
	encoded, err := json.Marshal(plan)
	if err != nil {
		return clone, err
	}
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return clone, err
	}
	return clone, nil
}

func newFormalCoxBlockwiseSourceContext(plan formalCoxBlockwisePlan,
	pins map[string]ed25519.PublicKey) (*formalCoxBlockwiseSourceContext, error) {
	frozen, err := formalCoxBlockwiseSourceClonePlan(plan)
	if err != nil {
		return nil, err
	}
	if err := validateFormalCoxBlockwisePlan(frozen); err != nil {
		return nil, err
	}
	copyPins := make(map[string]ed25519.PublicKey, len(pins))
	for peer, pin := range pins {
		copyPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	pinset, err := formalCoxBlockwisePinsetSHA256(copyPins)
	if err != nil || len(copyPins) != len(frozen.Policy.CustodianPeers) ||
		pinset != frozen.Policy.PinsetSHA256 {
		return nil, fmt.Errorf("formal-cox: source context pinset mismatch")
	}
	peerIDs := make(map[string]string, len(copyPins))
	for _, peer := range frozen.Policy.CustodianPeers {
		peerID, peerErr := formalCoxBlockwiseSourcePeerID(copyPins[peer])
		if peerErr != nil {
			return nil, fmt.Errorf("formal-cox: source context pinset is incomplete")
		}
		peerIDs[peer] = peerID
	}
	roles := make(map[string]string, 2)
	for _, recipient := range frozen.Policy.ComputePeers {
		role, roleErr := formalCoxBlockwiseSourceRole(frozen, recipient)
		if roleErr != nil {
			return nil, roleErr
		}
		roles[recipient] = role
	}
	planSHA, err := formalCoxBlockwisePlanSHA256(frozen)
	if err != nil {
		return nil, err
	}
	maximum, err := formalCoxBlockwiseSourceMaxEnvelope(frozen)
	if err != nil {
		return nil, err
	}
	artifact, artifactID, err := formalCoxBlockwiseBuildStickyArtifact(
		frozen, copyPins)
	if err != nil {
		return nil, fmt.Errorf("formal-cox: source context sticky artifact: %w", err)
	}
	if maximum > exactGCMaxAbsoluteOffset-formalCoxBlockwiseSourceBindingMax {
		return nil, fmt.Errorf("formal-cox: bound source slot maximum overflow")
	}
	return &formalCoxBlockwiseSourceContext{
		plan: frozen, pins: copyPins, artifact: artifact,
		artifactID: artifactID, planSHA256: planSHA,
		pinsetSHA256: pinset, peerIDs: peerIDs, roles: roles,
		maximum: maximum, slotMaximum: maximum + formalCoxBlockwiseSourceBindingMax,
	}, nil
}

func formalCoxBlockwiseSourceTicketUnsigned(
	ticket formalCoxBlockwiseSourceRecipientTicket) ([]byte, error) {
	ticket.Signature = nil
	encoded, err := json.Marshal(ticket)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSourceTicketDomain+"|"),
		encoded...), nil
}

func formalCoxBlockwiseSourceTicketDigest(
	ticket formalCoxBlockwiseSourceRecipientTicket) (string, error) {
	encoded, err := json.Marshal(ticket)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourceTicketDomain+"/signed|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func (context *formalCoxBlockwiseSourceContext) recipientTicketBase(
	recipient string, public []byte) (
	formalCoxBlockwiseSourceRecipientTicket, error) {
	var zero formalCoxBlockwiseSourceRecipientTicket
	if context == nil || context.roles[recipient] == "" ||
		context.peerIDs[recipient] == "" {
		return zero, fmt.Errorf("formal-cox: invalid source ticket recipient")
	}
	transportID, err := formalCoxBlockwiseSourceTransportKeyID(public)
	if err != nil {
		return zero, err
	}
	return formalCoxBlockwiseSourceRecipientTicket{
		Version:    formalCoxBlockwiseSourceTicketVersion,
		Purpose:    formalCoxBlockwiseSourcePurpose,
		PlanSHA256: context.planSHA256, RunID: context.plan.RunID,
		PinsetSHA256:       context.pinsetSHA256,
		RecipientPeerName:  recipient,
		RecipientPeerID:    context.peerIDs[recipient],
		RecipientRole:      context.roles[recipient],
		TransportKeySHA256: transportID,
		TransportPublicKey: append([]byte(nil), public...),
	}, nil
}

func (context *formalCoxBlockwiseSourceContext) signRecipientTicket(
	recipient string, public []byte, signingKey ed25519.PrivateKey) (
	formalCoxBlockwiseSourceRecipientTicket, error) {
	var zero formalCoxBlockwiseSourceRecipientTicket
	if context == nil || len(signingKey) != ed25519.PrivateKeySize {
		return zero, fmt.Errorf("formal-cox: invalid source ticket signer")
	}
	pinned := context.pins[recipient]
	signer := signingKey.Public().(ed25519.PublicKey)
	if len(pinned) != ed25519.PublicKeySize || !hmac.Equal(signer, pinned) {
		return zero, fmt.Errorf("formal-cox: source ticket signer is not pinned")
	}
	ticket, err := context.recipientTicketBase(recipient, public)
	if err != nil {
		return zero, err
	}
	message, err := formalCoxBlockwiseSourceTicketUnsigned(ticket)
	if err != nil {
		return zero, err
	}
	ticket.Signature = ed25519.Sign(signingKey, message)
	return ticket, nil
}

func formalCoxBlockwiseSourceManifestDigest(
	manifest formalCoxBlockwiseSourceRecipientManifest) (string, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourceManifestDomain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseSourceCloneTicket(
	ticket formalCoxBlockwiseSourceRecipientTicket) formalCoxBlockwiseSourceRecipientTicket {
	ticket.TransportPublicKey = append([]byte(nil), ticket.TransportPublicKey...)
	ticket.Signature = append([]byte(nil), ticket.Signature...)
	return ticket
}

func (context *formalCoxBlockwiseSourceContext) bindRecipientManifest(
	tickets []formalCoxBlockwiseSourceRecipientTicket) (
	*formalCoxBlockwiseSourceSession, error) {
	if context == nil || len(tickets) != 2 {
		return nil, fmt.Errorf("formal-cox: incomplete source recipient manifest")
	}
	manifest := formalCoxBlockwiseSourceRecipientManifest{
		Version:    formalCoxBlockwiseSourceManifestVersion,
		Purpose:    formalCoxBlockwiseSourcePurpose,
		PlanSHA256: context.planSHA256, RunID: context.plan.RunID,
		PinsetSHA256: context.pinsetSHA256,
		Tickets:      make([]formalCoxBlockwiseSourceRecipientTicket, 2),
	}
	byRecipient := make(map[string]formalCoxBlockwiseSourceRecipientTicket, 2)
	digests := make(map[string]string, 2)
	seenKeys := make(map[string]bool, 2)
	for index, recipient := range context.plan.Policy.ComputePeers {
		ticket := formalCoxBlockwiseSourceCloneTicket(tickets[index])
		expected, err := context.recipientTicketBase(
			recipient, ticket.TransportPublicKey)
		message, messageErr := formalCoxBlockwiseSourceTicketUnsigned(ticket)
		expectedMessage, expectedErr := formalCoxBlockwiseSourceTicketUnsigned(expected)
		if err != nil || messageErr != nil || expectedErr != nil ||
			ticket.RecipientPeerName != recipient ||
			!bytes.Equal(message, expectedMessage) ||
			len(ticket.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(context.pins[recipient], message, ticket.Signature) ||
			seenKeys[ticket.TransportKeySHA256] {
			return nil, fmt.Errorf("formal-cox: invalid source recipient manifest")
		}
		seenKeys[ticket.TransportKeySHA256] = true
		digest, err := formalCoxBlockwiseSourceTicketDigest(ticket)
		if err != nil {
			return nil, err
		}
		manifest.Tickets[index] = ticket
		byRecipient[recipient] = ticket
		digests[recipient] = digest
	}
	manifestSHA, err := formalCoxBlockwiseSourceManifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	return &formalCoxBlockwiseSourceSession{
		context: context, manifest: manifest, manifestSHA256: manifestSHA,
		tickets: byRecipient, ticketSHA256: digests,
	}, nil
}

func formalCoxBlockwiseSourceRole(plan formalCoxBlockwisePlan,
	recipient string) (string, error) {
	if recipient == plan.Policy.ComputePeers[0] {
		return "garbler", nil
	}
	if recipient == plan.Policy.ComputePeers[1] {
		return "evaluator", nil
	}
	return "", fmt.Errorf("formal-cox: source recipient is not a compute peer")
}

func formalCoxBlockwiseSourceRowsInBlock(plan formalCoxBlockwisePlan,
	block int) int {
	if block < 0 || block >= plan.TotalBlocks {
		return 0
	}
	rows := plan.BlockCapacity
	if remaining := plan.TotalCapacity - block*plan.BlockCapacity; remaining < rows {
		rows = remaining
	}
	return rows
}

func formalCoxBlockwiseSourceSlotCount(plan formalCoxBlockwisePlan) (int, error) {
	k := len(plan.Policy.CustodianPeers)
	maxInt := int(^uint(0) >> 1)
	if k < 2 || plan.TotalBlocks > (maxInt-plan.Iterations)/k {
		return 0, fmt.Errorf("formal-cox: source slot count overflow")
	}
	return plan.TotalBlocks*k + plan.Iterations, nil
}

func formalCoxBlockwiseSourceCanonicalStep(plan formalCoxBlockwisePlan,
	kind string, asset int) (formalCoxBlockwiseWorkerStep, error) {
	index := asset
	if kind == formalCoxBlockwiseStepUpdate {
		if asset < 0 || asset >= plan.Iterations {
			return formalCoxBlockwiseWorkerStep{},
				fmt.Errorf("formal-cox: invalid source noise iteration")
		}
		index = asset*formalCoxBlockwiseWorkerStepsPerIteration(plan) +
			plan.TotalBlocks +
			plan.Policy.GridTickCount*plan.Policy.CovariateCount
	}
	step, err := formalCoxBlockwiseWorkerStepAt(plan, index)
	if err != nil || step.Kind != kind {
		return formalCoxBlockwiseWorkerStep{},
			fmt.Errorf("formal-cox: invalid source asset step")
	}
	return step, nil
}

func formalCoxBlockwiseSourceStepAsset(plan formalCoxBlockwisePlan,
	step formalCoxBlockwiseWorkerStep, sealing bool) (string, int, error) {
	inputRoot := step.InputRoot
	step.InputRoot = ""
	want, err := formalCoxBlockwiseWorkerStepAt(plan, step.ScheduleIndex)
	if err != nil || step != want || inputRoot != "" {
		return "", 0, fmt.Errorf("formal-cox: invalid source worker step")
	}
	switch step.Kind {
	case formalCoxBlockwiseStepBlock:
		if sealing && step.Iteration != 0 {
			return "", 0, fmt.Errorf(
				"formal-cox: source blocks are sealed once for canonical reuse")
		}
		return step.Kind, step.BlockIndex, nil
	case formalCoxBlockwiseStepInformationBlock:
		if sealing {
			return "", 0, fmt.Errorf(
				"formal-cox: observed information reuses an already sealed source block")
		}
		// The post-fit pass is a second authenticated use of the canonical
		// iteration-zero encrypted block; it never generates a second input
		// asset or a new sticky draw.
		return formalCoxBlockwiseStepBlock, step.BlockIndex, nil
	case formalCoxBlockwiseStepUpdate:
		return step.Kind, step.Iteration, nil
	default:
		return "", 0, fmt.Errorf("formal-cox: worker step has no external source asset")
	}
}

func formalCoxBlockwiseSourceExpectedSlot(plan formalCoxBlockwisePlan,
	recipient string, slot int) (string, int, string, int, error) {
	total, err := formalCoxBlockwiseSourceSlotCount(plan)
	if err != nil || slot < 0 || slot >= total {
		return "", 0, "", 0, fmt.Errorf("formal-cox: invalid source asset slot")
	}
	k := len(plan.Policy.CustodianPeers)
	blockSlots := plan.TotalBlocks * k
	if slot < blockSlots {
		block, sourceIndex := slot/k, slot%k
		return formalCoxBlockwiseStepBlock, block,
			plan.Policy.CustodianPeers[sourceIndex], sourceIndex, nil
	}
	iteration := slot - blockSlots
	sourceIndex := -1
	for index, peer := range plan.Policy.CustodianPeers {
		if peer == recipient {
			sourceIndex = index
			break
		}
	}
	if sourceIndex < 0 {
		return "", 0, "", 0, fmt.Errorf("formal-cox: source recipient is not pinned")
	}
	return formalCoxBlockwiseStepUpdate, iteration, recipient, sourceIndex, nil
}

func formalCoxBlockwiseSourceHeaderForSlot(
	session *formalCoxBlockwiseSourceSession, recipient string,
	slot int) (formalCoxBlockwiseSourceHeader, error) {
	var zero formalCoxBlockwiseSourceHeader
	if session == nil || session.context == nil ||
		session.tickets[recipient].RecipientPeerName != recipient ||
		!formalCoxIsSHA256(session.ticketSHA256[recipient]) ||
		!formalCoxIsSHA256(session.manifestSHA256) {
		return zero, fmt.Errorf("formal-cox: invalid source recipient session")
	}
	context := session.context
	plan := context.plan
	kind, asset, source, sourceIndex, err :=
		formalCoxBlockwiseSourceExpectedSlot(plan, recipient, slot)
	if err != nil {
		return zero, err
	}
	ticket := session.tickets[recipient]
	step, err := formalCoxBlockwiseSourceCanonicalStep(plan, kind, asset)
	if err != nil {
		return zero, err
	}
	header := formalCoxBlockwiseSourceHeader{
		Version:    formalCoxBlockwiseSourceEnvelopeVersion,
		Purpose:    formalCoxBlockwiseSourcePurpose,
		PlanSHA256: context.planSHA256, RunID: plan.RunID,
		PinsetSHA256:   context.pinsetSHA256,
		SourcePeerName: source, SourcePeerID: context.peerIDs[source],
		SourceIndex:       sourceIndex,
		RecipientPeerName: recipient, RecipientPeerID: context.peerIDs[recipient],
		RecipientRole:               context.roles[recipient],
		RecipientTransportKeySHA256: ticket.TransportKeySHA256,
		RecipientTicketSHA256:       session.ticketSHA256[recipient],
		RecipientManifestSHA256:     session.manifestSHA256,
		AssetSlot:                   slot, StepKind: kind,
		CanonicalScheduleIndex: step.ScheduleIndex,
		Iteration:              step.Iteration, BlockIndex: step.BlockIndex,
		RingBits: plan.RingBits, RecordBytes: exactGCRecordBytes(plan.RingBits),
	}
	if kind == formalCoxBlockwiseStepBlock {
		header.CoordinateOffset = asset * plan.BlockCapacity * plan.RowWidth
		header.CoordinateCount = plan.BlockCapacity * plan.RowWidth
		header.RowsInBlock = formalCoxBlockwiseSourceRowsInBlock(plan, asset)
		header.PaddingRows = plan.BlockCapacity - header.RowsInBlock
		header.ReusableAcrossIterations = true
	} else {
		header.CoordinateOffset = asset * plan.Policy.CovariateCount
		header.CoordinateCount = plan.Policy.CovariateCount
		header.HasValidityShare = true
	}
	return header, nil
}

func formalCoxBlockwiseSourceSlotFor(plan formalCoxBlockwisePlan,
	recipient, source string, step formalCoxBlockwiseWorkerStep,
	sealing bool) (int, error) {
	kind, asset, err := formalCoxBlockwiseSourceStepAsset(plan, step, sealing)
	if err != nil {
		return 0, err
	}
	if kind == formalCoxBlockwiseStepBlock {
		for index, peer := range plan.Policy.CustodianPeers {
			if peer == source {
				return asset*len(plan.Policy.CustodianPeers) + index, nil
			}
		}
		return 0, fmt.Errorf("formal-cox: source is not a pinned custodian")
	}
	if source != recipient {
		return 0, fmt.Errorf("formal-cox: sealed noise must remain recipient-local")
	}
	return plan.TotalBlocks*len(plan.Policy.CustodianPeers) + asset, nil
}

func formalCoxBlockwiseSourceHeaderSHA256(
	header formalCoxBlockwiseSourceHeader) ([32]byte, error) {
	encoded, err := json.Marshal(header)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourceHeaderDomain+"|"), encoded...)), nil
}

func formalCoxBlockwiseSourceEncodeRecords(values []*big.Int,
	ringBits int) ([]byte, error) {
	if ringBits < 128 || ringBits > exactGCMaxRingBits || len(values) < 1 {
		return nil, fmt.Errorf("formal-cox: invalid source record shape")
	}
	width := exactGCRecordBytes(ringBits)
	if len(values) > int(^uint(0)>>1)/width {
		return nil, fmt.Errorf("formal-cox: source record shape overflow")
	}
	encoded := make([]byte, len(values)*width)
	modulus := exactGCModulus(ringBits)
	for index, value := range values {
		if value == nil || value.Sign() < 0 || value.Cmp(modulus) >= 0 {
			return nil, fmt.Errorf("formal-cox: source residue is outside the planned ring")
		}
		record, err := exactGCBigLittleEndian(value, width)
		if err != nil {
			return nil, err
		}
		copy(encoded[index*width:], record)
	}
	return encoded, nil
}

func formalCoxBlockwiseSourceDecodeRecords(encoded []byte, count,
	ringBits int) ([]*big.Int, error) {
	width := exactGCRecordBytes(ringBits)
	if count < 1 || width < 1 || count > int(^uint(0)>>1)/width ||
		len(encoded) != count*width {
		return nil, fmt.Errorf("formal-cox: source payload shape mismatch")
	}
	result := make([]*big.Int, count)
	for index := range result {
		result[index] = exactGCLittleEndianBig(
			encoded[index*width : (index+1)*width])
		if result[index].BitLen() > ringBits {
			exactGCZeroBigInts(result)
			return nil, fmt.Errorf(
				"formal-cox: source payload has non-zero high limb padding")
		}
	}
	return result, nil
}

func formalCoxBlockwiseSourceValidatePadding(
	header formalCoxBlockwiseSourceHeader, values []*big.Int) error {
	if header.StepKind != formalCoxBlockwiseStepBlock {
		return nil
	}
	first := header.RowsInBlock * (header.CoordinateCount /
		(header.RowsInBlock + header.PaddingRows))
	if first < 0 || first > len(values) {
		return fmt.Errorf("formal-cox: invalid padded source shape")
	}
	for _, value := range values[first:] {
		if value == nil || value.Sign() != 0 {
			return fmt.Errorf("formal-cox: padded source coordinates must be zero")
		}
	}
	return nil
}

func formalCoxBlockwiseSourcePrivatePayload(
	header formalCoxBlockwiseSourceHeader, values []*big.Int,
	validity *bool) ([]byte, error) {
	if len(values) != header.CoordinateCount ||
		(header.HasValidityShare != (validity != nil)) {
		return nil, fmt.Errorf("formal-cox: source payload does not match its header")
	}
	if err := formalCoxBlockwiseSourceValidatePadding(header, values); err != nil {
		return nil, err
	}
	records, err := formalCoxBlockwiseSourceEncodeRecords(values, header.RingBits)
	if err != nil {
		return nil, err
	}
	defer clear(records)
	headerSHA, err := formalCoxBlockwiseSourceHeaderSHA256(header)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(formalCoxBlockwiseSourcePrivateMagic)+32+1+len(records))
	result = append(result, formalCoxBlockwiseSourcePrivateMagic[:]...)
	result = append(result, headerSHA[:]...)
	if validity != nil && *validity {
		result = append(result, 1)
	} else {
		result = append(result, 0)
	}
	result = append(result, records...)
	return result, nil
}

func formalCoxBlockwiseSourceEnvelopeUnsigned(
	envelope formalCoxBlockwiseSourceEnvelope) ([]byte, error) {
	envelope.Signature = nil
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSourceEnvelopeDomain+"|"),
		encoded...), nil
}

func formalCoxBlockwiseSourceEnvelopeDigest(encoded []byte) string {
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourceEnvelopeDomain+"/encoded|"), encoded...))
	return hex.EncodeToString(digest[:])
}

func formalCoxBlockwiseSourceDecodeCanonical(encoded []byte, maximum int64,
	label string, value any) error {
	if len(encoded) < 2 || int64(len(encoded)) > maximum {
		return fmt.Errorf("formal-cox: invalid %s size", label)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("formal-cox: decode %s: %w", label, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("formal-cox: trailing %s data", label)
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("formal-cox: non-canonical %s", label)
	}
	return nil
}

func formalCoxBlockwiseSourceValidatePublicEnvelope(
	session *formalCoxBlockwiseSourceSession, recipient string, encoded []byte) (
	formalCoxBlockwiseSourceEnvelope, string, error) {
	var zero formalCoxBlockwiseSourceEnvelope
	if session == nil || session.context == nil {
		return zero, "", fmt.Errorf("formal-cox: invalid source recipient session")
	}
	envelope, err := formalCoxBlockwiseSourceDecodeEnvelope(
		encoded, session.context.maximum)
	if err != nil {
		return zero, "", err
	}
	want, err := formalCoxBlockwiseSourceHeaderForSlot(
		session, recipient, envelope.Header.AssetSlot)
	if err != nil || envelope.Header != want {
		return zero, "", fmt.Errorf(
			"formal-cox: source envelope header binding mismatch")
	}
	plaintextBytes := len(formalCoxBlockwiseSourcePrivateMagic) + 32 + 1 +
		want.CoordinateCount*want.RecordBytes
	if len(envelope.Ciphertext) !=
		plaintextBytes+formalCoxBlockwiseSourceCipherOverhead ||
		!formalCoxIsSHA256(envelope.CiphertextSHA256) ||
		len(envelope.Signature) != ed25519.SignatureSize {
		return zero, "", fmt.Errorf("formal-cox: invalid source ciphertext shape")
	}
	cipherSHA := sha256.Sum256(envelope.Ciphertext)
	if hex.EncodeToString(cipherSHA[:]) != envelope.CiphertextSHA256 {
		return zero, "", fmt.Errorf(
			"formal-cox: source ciphertext commitment mismatch")
	}
	message, err := formalCoxBlockwiseSourceEnvelopeUnsigned(envelope)
	if err != nil || !ed25519.Verify(session.context.pins[want.SourcePeerName],
		message, envelope.Signature) {
		return zero, "", fmt.Errorf("formal-cox: source envelope signature failed")
	}
	return envelope, formalCoxBlockwiseSourceEnvelopeDigest(encoded), nil
}

func formalCoxBlockwiseSourcePairManifestRoot(
	manifest formalCoxBlockwiseSourcePairManifest) (string, error) {
	manifest.PairedInputRootSHA256 = ""
	manifest.Signature = nil
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSourcePairDomain+"/root|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseSourcePairManifestMessage(
	manifest formalCoxBlockwiseSourcePairManifest) ([]byte, error) {
	manifest.Signature = nil
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSourcePairDomain+"|"), encoded...), nil
}

func formalCoxBlockwisePairSourceEnvelopes(
	session *formalCoxBlockwiseSourceSession, source string,
	step formalCoxBlockwiseWorkerStep, encodedEnvelopes [][]byte,
	signingKey ed25519.PrivateKey) ([]byte, error) {
	if session == nil || session.context == nil || len(encodedEnvelopes) != 2 ||
		len(signingKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(signingKey.Public().(ed25519.PublicKey),
			session.context.pins[source]) {
		return nil, fmt.Errorf("formal-cox: invalid source pair signer")
	}
	kind, _, err := formalCoxBlockwiseSourceStepAsset(
		session.context.plan, step, true)
	if err != nil || kind != formalCoxBlockwiseStepBlock {
		return nil, fmt.Errorf("formal-cox: source pair is not a canonical block")
	}
	manifest := formalCoxBlockwiseSourcePairManifest{
		Version:                 formalCoxBlockwiseSourcePairVersion,
		Purpose:                 formalCoxBlockwiseSourcePurpose,
		PlanSHA256:              session.context.planSHA256,
		RunID:                   session.context.plan.RunID,
		PinsetSHA256:            session.context.pinsetSHA256,
		RecipientManifestSHA256: session.manifestSHA256,
		SourcePeerName:          source, SourcePeerID: session.context.peerIDs[source],
		StepKind: step.Kind, CanonicalScheduleIndex: step.ScheduleIndex,
		Iteration: step.Iteration, BlockIndex: step.BlockIndex,
		Recipients: make([]formalCoxBlockwiseSourcePairRecipient, 2),
	}
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		envelope, digest, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
			session, recipient, encodedEnvelopes[index])
		if err != nil || envelope.Header.SourcePeerName != source ||
			envelope.Header.StepKind != step.Kind ||
			envelope.Header.CanonicalScheduleIndex != step.ScheduleIndex ||
			envelope.Header.BlockIndex != step.BlockIndex {
			return nil, fmt.Errorf("formal-cox: invalid source envelope pair")
		}
		manifest.Recipients[index] = formalCoxBlockwiseSourcePairRecipient{
			RecipientPeerName:           recipient,
			RecipientPeerID:             session.context.peerIDs[recipient],
			RecipientRole:               session.context.roles[recipient],
			RecipientTicketSHA256:       session.ticketSHA256[recipient],
			RecipientTransportKeySHA256: session.tickets[recipient].TransportKeySHA256,
			AssetSlot:                   envelope.Header.AssetSlot, EnvelopeSHA256: digest,
		}
	}
	manifest.PairedInputRootSHA256, err =
		formalCoxBlockwiseSourcePairManifestRoot(manifest)
	if err != nil {
		return nil, err
	}
	message, err := formalCoxBlockwiseSourcePairManifestMessage(manifest)
	if err != nil {
		return nil, err
	}
	manifest.Signature = ed25519.Sign(signingKey, message)
	return json.Marshal(manifest)
}

func formalCoxBlockwiseSourceValidatePairManifest(
	session *formalCoxBlockwiseSourceSession,
	manifest formalCoxBlockwiseSourcePairManifest,
	local formalCoxBlockwiseSourceHeader, localDigest string) (string, error) {
	if session == nil || session.context == nil ||
		manifest.Version != formalCoxBlockwiseSourcePairVersion ||
		manifest.Purpose != formalCoxBlockwiseSourcePurpose ||
		manifest.PlanSHA256 != session.context.planSHA256 ||
		manifest.RunID != session.context.plan.RunID ||
		manifest.PinsetSHA256 != session.context.pinsetSHA256 ||
		manifest.RecipientManifestSHA256 != session.manifestSHA256 ||
		manifest.SourcePeerName != local.SourcePeerName ||
		manifest.SourcePeerID != session.context.peerIDs[local.SourcePeerName] ||
		manifest.StepKind != formalCoxBlockwiseStepBlock ||
		manifest.StepKind != local.StepKind ||
		manifest.CanonicalScheduleIndex != local.CanonicalScheduleIndex ||
		manifest.Iteration != local.Iteration ||
		manifest.BlockIndex != local.BlockIndex || len(manifest.Recipients) != 2 ||
		len(manifest.Signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("formal-cox: invalid source pair manifest")
	}
	localMatches, digestMatches := 0, 0
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		entry := manifest.Recipients[index]
		if entry.EnvelopeSHA256 == localDigest {
			digestMatches++
		}
		slot, err := formalCoxBlockwiseSourceSlotFor(
			session.context.plan, recipient, manifest.SourcePeerName,
			formalCoxBlockwiseWorkerStep{
				ScheduleIndex: manifest.CanonicalScheduleIndex,
				Iteration:     manifest.Iteration, Kind: manifest.StepKind,
				BlockIndex: manifest.BlockIndex, GridIndex: -1, Coefficient: -1,
				InformationPart: -1,
			}, true)
		if err != nil || entry.RecipientPeerName != recipient ||
			entry.RecipientPeerID != session.context.peerIDs[recipient] ||
			entry.RecipientRole != session.context.roles[recipient] ||
			entry.RecipientTicketSHA256 != session.ticketSHA256[recipient] ||
			entry.RecipientTransportKeySHA256 !=
				session.tickets[recipient].TransportKeySHA256 ||
			entry.AssetSlot != slot || !formalCoxIsSHA256(entry.EnvelopeSHA256) {
			return "", fmt.Errorf("formal-cox: invalid source pair recipient")
		}
		if recipient == local.RecipientPeerName {
			if entry.AssetSlot != local.AssetSlot ||
				entry.EnvelopeSHA256 != localDigest {
				return "", fmt.Errorf(
					"formal-cox: local ciphertext is not in its source pair")
			}
			localMatches++
		}
	}
	wantRoot, err := formalCoxBlockwiseSourcePairManifestRoot(manifest)
	message, messageErr := formalCoxBlockwiseSourcePairManifestMessage(manifest)
	if err != nil || messageErr != nil || localMatches != 1 || digestMatches != 1 ||
		manifest.PairedInputRootSHA256 != wantRoot ||
		!ed25519.Verify(session.context.pins[manifest.SourcePeerName],
			message, manifest.Signature) {
		return "", fmt.Errorf("formal-cox: source pair authentication failed")
	}
	return wantRoot, nil
}

func formalCoxBlockwiseNoiseBarrierRoot(
	barrier formalCoxBlockwiseNoiseBarrier) (string, error) {
	barrier.PairedNoiseRootSHA256 = ""
	barrier.Approvals = nil
	encoded, err := json.Marshal(barrier)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseNoiseBarrierDomain+"/root|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseNoiseBarrierMessage(
	barrier formalCoxBlockwiseNoiseBarrier) ([]byte, error) {
	barrier.Approvals = nil
	encoded, err := json.Marshal(barrier)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseNoiseBarrierDomain+"|"), encoded...), nil
}

func formalCoxBlockwiseValidateNoiseBarrierCore(
	session *formalCoxBlockwiseSourceSession,
	barrier formalCoxBlockwiseNoiseBarrier) error {
	if session == nil || session.context == nil ||
		barrier.Version != formalCoxBlockwiseNoiseBarrierVersion ||
		barrier.Purpose != formalCoxBlockwiseSourcePurpose ||
		barrier.PlanSHA256 != session.context.planSHA256 ||
		barrier.RunID != session.context.plan.RunID ||
		barrier.PinsetSHA256 != session.context.pinsetSHA256 ||
		barrier.RecipientManifestSHA256 != session.manifestSHA256 ||
		barrier.StepKind != formalCoxBlockwiseStepUpdate ||
		len(barrier.NoiseRoots) != 2 {
		return fmt.Errorf("formal-cox: invalid paired noise barrier")
	}
	guarded := formalCoxIsSHA256(barrier.CanonicalArtifactID) &&
		formalCoxIsSHA256(barrier.SamplerContractSHA256) &&
		formalCoxIsSHA256(barrier.SamplerGuardRootSHA256)
	unguarded := barrier.CanonicalArtifactID == "" &&
		barrier.SamplerContractSHA256 == "" &&
		barrier.SamplerGuardRootSHA256 == ""
	if !guarded && !unguarded {
		return fmt.Errorf("formal-cox: incomplete sampler guard binding")
	}
	step, err := formalCoxBlockwiseWorkerStepAt(
		session.context.plan, barrier.CanonicalScheduleIndex)
	if err != nil || step.Kind != formalCoxBlockwiseStepUpdate ||
		step.Iteration != barrier.Iteration {
		return fmt.Errorf("formal-cox: invalid paired noise schedule")
	}
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		entry := barrier.NoiseRoots[index]
		slot, slotErr := formalCoxBlockwiseSourceSlotFor(
			session.context.plan, recipient, recipient, step, true)
		if slotErr != nil || entry.RecipientPeerName != recipient ||
			entry.RecipientPeerID != session.context.peerIDs[recipient] ||
			entry.RecipientRole != session.context.roles[recipient] ||
			entry.RecipientTicketSHA256 != session.ticketSHA256[recipient] ||
			entry.RecipientTransportKeySHA256 !=
				session.tickets[recipient].TransportKeySHA256 ||
			entry.AssetSlot != slot || !formalCoxIsSHA256(entry.EnvelopeSHA256) {
			return fmt.Errorf("formal-cox: invalid paired noise commitment")
		}
	}
	want, err := formalCoxBlockwiseNoiseBarrierRoot(barrier)
	if err != nil || barrier.PairedNoiseRootSHA256 != want {
		return fmt.Errorf("formal-cox: paired noise root authentication failed")
	}
	return nil
}

func formalCoxBlockwiseNewNoiseBarrier(
	session *formalCoxBlockwiseSourceSession,
	step formalCoxBlockwiseWorkerStep, encodedEnvelopes [][]byte) (
	formalCoxBlockwiseNoiseBarrier, error) {
	var zero formalCoxBlockwiseNoiseBarrier
	if session == nil || session.context == nil || len(encodedEnvelopes) != 2 ||
		step.InputRoot != "" || step.Kind != formalCoxBlockwiseStepUpdate {
		return zero, fmt.Errorf("formal-cox: invalid paired noise inputs")
	}
	barrier := formalCoxBlockwiseNoiseBarrier{
		Version:                 formalCoxBlockwiseNoiseBarrierVersion,
		Purpose:                 formalCoxBlockwiseSourcePurpose,
		PlanSHA256:              session.context.planSHA256,
		RunID:                   session.context.plan.RunID,
		PinsetSHA256:            session.context.pinsetSHA256,
		RecipientManifestSHA256: session.manifestSHA256,
		StepKind:                step.Kind, CanonicalScheduleIndex: step.ScheduleIndex,
		Iteration:  step.Iteration,
		NoiseRoots: make([]formalCoxBlockwiseNoiseRootCommitment, 2),
	}
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		envelope, digest, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
			session, recipient, encodedEnvelopes[index])
		if err != nil || envelope.Header.SourcePeerName != recipient ||
			envelope.Header.StepKind != step.Kind ||
			envelope.Header.CanonicalScheduleIndex != step.ScheduleIndex ||
			envelope.Header.Iteration != step.Iteration {
			return zero, fmt.Errorf("formal-cox: invalid paired noise envelope")
		}
		barrier.NoiseRoots[index] = formalCoxBlockwiseNoiseRootCommitment{
			RecipientPeerName:           recipient,
			RecipientPeerID:             session.context.peerIDs[recipient],
			RecipientRole:               session.context.roles[recipient],
			RecipientTicketSHA256:       session.ticketSHA256[recipient],
			RecipientTransportKeySHA256: session.tickets[recipient].TransportKeySHA256,
			AssetSlot:                   envelope.Header.AssetSlot, EnvelopeSHA256: digest,
		}
	}
	var err error
	barrier.PairedNoiseRootSHA256, err =
		formalCoxBlockwiseNoiseBarrierRoot(barrier)
	if err != nil {
		return zero, err
	}
	if err := formalCoxBlockwiseValidateNoiseBarrierCore(session, barrier); err != nil {
		return zero, err
	}
	return barrier, nil
}

func formalCoxBlockwiseSignNoiseBarrier(
	session *formalCoxBlockwiseSourceSession,
	barrier formalCoxBlockwiseNoiseBarrier, encodedEnvelopes [][]byte,
	signer string,
	signingKey ed25519.PrivateKey) (formalCoxBlockwiseNoiseApproval, error) {
	var zero formalCoxBlockwiseNoiseApproval
	if session == nil || session.context == nil {
		return zero, fmt.Errorf("formal-cox: invalid paired noise signer")
	}
	step, err := formalCoxBlockwiseWorkerStepAt(
		session.context.plan, barrier.CanonicalScheduleIndex)
	want, wantErr := formalCoxBlockwiseNewNoiseBarrier(
		session, step, encodedEnvelopes)
	if wantErr == nil && barrier.CanonicalArtifactID != "" {
		want.CanonicalArtifactID = barrier.CanonicalArtifactID
		want.SamplerContractSHA256 = barrier.SamplerContractSHA256
		want.SamplerGuardRootSHA256 = barrier.SamplerGuardRootSHA256
		want.PairedNoiseRootSHA256, wantErr =
			formalCoxBlockwiseNoiseBarrierRoot(want)
	}
	wantEncoded, wantEncodeErr := json.Marshal(want)
	barrierEncoded, barrierEncodeErr := json.Marshal(barrier)
	if err != nil || wantErr != nil || wantEncodeErr != nil ||
		barrierEncodeErr != nil || !bytes.Equal(wantEncoded, barrierEncoded) ||
		len(barrier.Approvals) != 0 || len(signingKey) != ed25519.PrivateKeySize ||
		session.context.roles[signer] == "" ||
		!hmac.Equal(signingKey.Public().(ed25519.PublicKey),
			session.context.pins[signer]) {
		return zero, fmt.Errorf("formal-cox: invalid paired noise signer")
	}
	message, err := formalCoxBlockwiseNoiseBarrierMessage(barrier)
	if err != nil {
		return zero, err
	}
	return formalCoxBlockwiseNoiseApproval{
		SignerPeerName: signer, SignerPeerID: session.context.peerIDs[signer],
		SignerRole: session.context.roles[signer],
		Signature:  ed25519.Sign(signingKey, message),
	}, nil
}

func formalCoxBlockwiseValidateNoiseBarrier(
	session *formalCoxBlockwiseSourceSession,
	barrier formalCoxBlockwiseNoiseBarrier) error {
	if err := formalCoxBlockwiseValidateNoiseBarrierCore(session, barrier); err != nil ||
		len(barrier.Approvals) != 2 {
		return fmt.Errorf("formal-cox: incomplete paired noise barrier")
	}
	message, err := formalCoxBlockwiseNoiseBarrierMessage(barrier)
	if err != nil {
		return err
	}
	for index, signer := range session.context.plan.Policy.ComputePeers {
		approval := barrier.Approvals[index]
		if approval.SignerPeerName != signer ||
			approval.SignerPeerID != session.context.peerIDs[signer] ||
			approval.SignerRole != session.context.roles[signer] ||
			len(approval.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(session.context.pins[signer],
				message, approval.Signature) {
			return fmt.Errorf("formal-cox: paired noise approval failed")
		}
	}
	return nil
}

func formalCoxBlockwiseFinalizeNoiseBarrier(
	session *formalCoxBlockwiseSourceSession,
	barrier formalCoxBlockwiseNoiseBarrier,
	approvals []formalCoxBlockwiseNoiseApproval) ([]byte, error) {
	barrier.Approvals = append([]formalCoxBlockwiseNoiseApproval(nil), approvals...)
	for index := range barrier.Approvals {
		barrier.Approvals[index].Signature = append(
			[]byte(nil), barrier.Approvals[index].Signature...)
	}
	if err := formalCoxBlockwiseValidateNoiseBarrier(session, barrier); err != nil {
		return nil, err
	}
	return json.Marshal(barrier)
}

func formalCoxBlockwiseSourceValidateNoiseBinding(
	session *formalCoxBlockwiseSourceSession,
	barrier formalCoxBlockwiseNoiseBarrier,
	local formalCoxBlockwiseSourceHeader, localDigest string) (string, error) {
	if err := formalCoxBlockwiseValidateNoiseBarrier(session, barrier); err != nil {
		return "", err
	}
	localMatches, digestMatches := 0, 0
	for _, entry := range barrier.NoiseRoots {
		if entry.EnvelopeSHA256 == localDigest {
			digestMatches++
		}
		if entry.RecipientPeerName == local.RecipientPeerName {
			if entry.AssetSlot != local.AssetSlot ||
				entry.EnvelopeSHA256 != localDigest ||
				local.SourcePeerName != local.RecipientPeerName ||
				local.StepKind != formalCoxBlockwiseStepUpdate ||
				barrier.CanonicalScheduleIndex != local.CanonicalScheduleIndex ||
				barrier.Iteration != local.Iteration {
				return "", fmt.Errorf(
					"formal-cox: local noise ciphertext is not in its barrier")
			}
			localMatches++
		}
	}
	if localMatches != 1 || digestMatches != 1 {
		return "", fmt.Errorf("formal-cox: paired noise barrier omits local input")
	}
	return barrier.PairedNoiseRootSHA256, nil
}

func formalCoxBlockwiseSealSourceInput(
	session *formalCoxBlockwiseSourceSession, source, recipient string,
	step formalCoxBlockwiseWorkerStep, values []*big.Int, validity *bool,
	signingKey ed25519.PrivateKey) ([]byte, error) {
	if session == nil || session.context == nil {
		return nil, fmt.Errorf("formal-cox: invalid source recipient session")
	}
	plan := session.context.plan
	slot, err := formalCoxBlockwiseSourceSlotFor(
		plan, recipient, source, step, true)
	if err != nil {
		return nil, err
	}
	header, err := formalCoxBlockwiseSourceHeaderForSlot(
		session, recipient, slot)
	if err != nil || header.SourcePeerName != source {
		return nil, fmt.Errorf("formal-cox: source header does not match its signer")
	}
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("formal-cox: source signer is not pinned")
	}
	public := signingKey.Public().(ed25519.PublicKey)
	if !hmac.Equal(public, session.context.pins[source]) {
		return nil, fmt.Errorf("formal-cox: source signer is not pinned")
	}
	plaintext, err := formalCoxBlockwiseSourcePrivatePayload(
		header, values, validity)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	ciphertext, err := transportEncryptBytes(
		plaintext, session.tickets[recipient].TransportPublicKey)
	if err != nil {
		return nil, err
	}
	cipherSHA := sha256.Sum256(ciphertext)
	envelope := formalCoxBlockwiseSourceEnvelope{
		Header: header, CiphertextSHA256: hex.EncodeToString(cipherSHA[:]),
		Ciphertext: ciphertext,
	}
	message, err := formalCoxBlockwiseSourceEnvelopeUnsigned(envelope)
	if err != nil {
		return nil, err
	}
	envelope.Signature = ed25519.Sign(signingKey, message)
	return json.Marshal(envelope)
}

func formalCoxBlockwiseSourceMaxEnvelope(plan formalCoxBlockwisePlan) (int64, error) {
	count := plan.BlockCapacity * plan.RowWidth
	width := exactGCRecordBytes(plan.RingBits)
	if count < 1 || width < 1 ||
		int64(count) > (exactGCMaxAbsoluteOffset-4096)/int64(width) {
		return 0, fmt.Errorf("formal-cox: source envelope bound overflow")
	}
	plaintext := int64(len(formalCoxBlockwiseSourcePrivateMagic) + 32 + 1)
	plaintext += int64(count * width)
	ciphertext := plaintext + formalCoxBlockwiseSourceCipherOverhead
	if ciphertext > (exactGCMaxAbsoluteOffset-formalCoxBlockwiseSourceJSONSlack)/2 {
		return 0, fmt.Errorf("formal-cox: source envelope bound overflow")
	}
	return 2*ciphertext + formalCoxBlockwiseSourceJSONSlack, nil
}

func formalCoxBlockwiseSourceDecodeEnvelope(encoded []byte, maximum int64) (
	formalCoxBlockwiseSourceEnvelope, error) {
	var envelope formalCoxBlockwiseSourceEnvelope
	if len(encoded) < 2 || int64(len(encoded)) > maximum {
		return envelope, fmt.Errorf("formal-cox: invalid source envelope size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("formal-cox: decode source envelope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return envelope, fmt.Errorf("formal-cox: trailing source envelope data")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return envelope, fmt.Errorf("formal-cox: non-canonical source envelope")
	}
	return envelope, nil
}

func formalCoxBlockwiseSourceDecodePrivate(header formalCoxBlockwiseSourceHeader,
	plaintext []byte) ([]*big.Int, *bool, error) {
	prefix := len(formalCoxBlockwiseSourcePrivateMagic) + 32 + 1
	expected := prefix + header.CoordinateCount*header.RecordBytes
	if len(plaintext) != expected ||
		!bytes.Equal(plaintext[:len(formalCoxBlockwiseSourcePrivateMagic)],
			formalCoxBlockwiseSourcePrivateMagic[:]) {
		return nil, nil, fmt.Errorf("formal-cox: invalid private source payload shape")
	}
	headerSHA, err := formalCoxBlockwiseSourceHeaderSHA256(header)
	if err != nil || !hmac.Equal(
		plaintext[len(formalCoxBlockwiseSourcePrivateMagic):len(formalCoxBlockwiseSourcePrivateMagic)+32], headerSHA[:]) {
		return nil, nil, fmt.Errorf("formal-cox: private source header mismatch")
	}
	validityByte := plaintext[prefix-1]
	if validityByte > 1 || !header.HasValidityShare && validityByte != 0 {
		return nil, nil, fmt.Errorf("formal-cox: invalid private source validity share")
	}
	shares, err := formalCoxBlockwiseSourceDecodeRecords(
		plaintext[prefix:], header.CoordinateCount, header.RingBits)
	if err != nil {
		return nil, nil, err
	}
	if err := formalCoxBlockwiseSourceValidatePadding(header, shares); err != nil {
		exactGCZeroBigInts(shares)
		return nil, nil, err
	}
	var validity *bool
	if header.HasValidityShare {
		value := validityByte == 1
		validity = &value
	}
	return shares, validity, nil
}

func formalCoxBlockwiseSourceStateMAC(key [32]byte,
	state formalCoxBlockwiseSourceState) (string, error) {
	state.MAC = ""
	encoded, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(formalCoxBlockwiseSourceStateDomain + "|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalCoxBlockwiseSourceEnsurePrivateDir(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		path == string(filepath.Separator) {
		return fmt.Errorf("formal-cox: invalid private source directory")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		!formalFinalizerHandoffPrivateOwnedDirectory(info) {
		return fmt.Errorf("formal-cox: unsafe private source directory")
	}
	return nil
}

func formalCoxBlockwiseSourceAcquireOwner(path string) (*os.File, error) {
	for attempt := 0; attempt < 4; attempt++ {
		info, err := os.Lstat(path)
		flags := formalCoxBlockwiseSourceOwnerOpenFlags()
		if os.IsNotExist(err) {
			flags |= os.O_CREATE | os.O_EXCL
		} else if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
			!exactGCPrivateOwnedRegular(info) {
			return nil, fmt.Errorf("formal-cox: unsafe source owner lock")
		}
		file, openErr := os.OpenFile(path, flags, 0o600)
		if openErr != nil {
			if os.IsExist(openErr) || os.IsNotExist(openErr) {
				continue
			}
			return nil, fmt.Errorf("formal-cox: unsafe source owner lock")
		}
		fail := func(err error) (*os.File, error) {
			_ = file.Close()
			return nil, err
		}
		current, statErr := os.Lstat(path)
		opened, openStatErr := file.Stat()
		if statErr != nil || openStatErr != nil ||
			!current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
			current.Mode().Perm()&0o077 != 0 ||
			!exactGCPrivateOwnedRegular(current) ||
			!os.SameFile(current, opened) {
			return fail(fmt.Errorf("formal-cox: unsafe source owner lock"))
		}
		if err := formalFinalizerHandoffTryAuthorityLock(file); err != nil {
			return fail(fmt.Errorf("formal-cox: source spool already has an owner"))
		}
		return file, nil
	}
	return nil, fmt.Errorf("formal-cox: source owner lock changed continuously")
}

func formalCoxBlockwiseSourceReapCommittedTemp(dir, path string,
	tempInfo os.FileInfo, maximum int64) (bool, error) {
	directory, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			name := entry.Name()
			if len(name) != len("slot-000000000000.bin") ||
				!strings.HasPrefix(name, "slot-") ||
				!strings.HasSuffix(name, ".bin") {
				continue
			}
			digits := strings.TrimSuffix(strings.TrimPrefix(name, "slot-"), ".bin")
			slot, parseErr := strconv.ParseInt(digits, 10, 64)
			if parseErr != nil || slot < 0 ||
				fmt.Sprintf("slot-%012d.bin", slot) != name {
				continue
			}
			target := filepath.Join(dir, name)
			targetInfo, statErr := os.Lstat(target)
			if statErr != nil {
				if os.IsNotExist(statErr) {
					continue
				}
				return false, statErr
			}
			if !os.SameFile(tempInfo, targetInfo) {
				continue
			}
			if !targetInfo.Mode().IsRegular() ||
				targetInfo.Mode()&os.ModeSymlink != 0 ||
				targetInfo.Mode().Perm()&0o077 != 0 ||
				targetInfo.Size() < 2 || targetInfo.Size() > maximum {
				return false, fmt.Errorf("formal-cox: unsafe linked source slot")
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return false, err
			}
			if err := exactGCSyncDir(dir); err != nil {
				return false, err
			}
			finalInfo, err := os.Lstat(target)
			if err != nil || !exactGCPrivateOwnedRegular(finalInfo) {
				return false, fmt.Errorf("formal-cox: source slot retained an unsafe link")
			}
			return true, nil
		}
		if readErr == io.EOF {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

func formalCoxBlockwiseSourceCleanupTemps(dir string, maximum int64) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(
				entry.Name(), ".formal-cox-source-") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() ||
				info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
				info.Size() < 2 || info.Size() > maximum {
				return fmt.Errorf("formal-cox: unsafe temporary source artifact")
			}
			if !exactGCPrivateOwnedRegular(info) {
				committed, reapErr := formalCoxBlockwiseSourceReapCommittedTemp(
					dir, path, info, maximum)
				if reapErr != nil || !committed {
					if reapErr != nil {
						return reapErr
					}
					return fmt.Errorf("formal-cox: unsafe linked source temporary")
				}
				continue
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func newFormalCoxBlockwiseSourceStore(dir string, key [32]byte,
	session *formalCoxBlockwiseSourceSession, recipient string,
	recipientSecretKey []byte) (
	*formalCoxBlockwiseSourceStore, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		bytes.Equal(key[:], make([]byte, len(key))) ||
		len(recipientSecretKey) != 32 || session == nil ||
		session.context == nil {
		return nil, fmt.Errorf("formal-cox: invalid private source-store policy")
	}
	ticket, ok := session.tickets[recipient]
	if !ok || ticket.RecipientRole != session.context.roles[recipient] ||
		!formalCoxIsSHA256(session.ticketSHA256[recipient]) ||
		!formalCoxIsSHA256(session.manifestSHA256) {
		return nil, fmt.Errorf("formal-cox: invalid source-store recipient binding")
	}
	private, err := ecdh.X25519().NewPrivateKey(recipientSecretKey)
	if err != nil {
		return nil, fmt.Errorf("formal-cox: invalid recipient source key")
	}
	public := private.PublicKey().Bytes()
	transportID, err := formalCoxBlockwiseSourceTransportKeyID(public)
	if err != nil || transportID != ticket.TransportKeySHA256 ||
		!hmac.Equal(public, ticket.TransportPublicKey) {
		return nil, fmt.Errorf("formal-cox: source-store recipient key binding mismatch")
	}
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	slotDir := filepath.Join(dir, "slots-v1")
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(slotDir); err != nil {
		return nil, err
	}
	ownerPath := filepath.Join(dir, "owner.lock")
	owner, err := formalCoxBlockwiseSourceAcquireOwner(ownerPath)
	if err != nil {
		return nil, err
	}
	store := &formalCoxBlockwiseSourceStore{
		slotDir: slotDir, statePath: filepath.Join(dir, "cursor-v1.json"),
		owner: owner, key: key, session: session,
		plan:      session.context.plan,
		recipient: recipient, recipientRole: ticket.RecipientRole,
		recipientSK:    append([]byte(nil), recipientSecretKey...),
		transportKeyID: transportID,
		ticketSHA256:   session.ticketSHA256[recipient],
		manifestSHA256: session.manifestSHA256,
		syncSlotDir:    exactGCSyncDir,
	}
	maximum := session.context.slotMaximum
	if err := formalCoxBlockwiseSourceCleanupTemps(slotDir, maximum); err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := store.bootstrapAndRecover(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (store *formalCoxBlockwiseSourceStore) slotPath(slot int) string {
	return filepath.Join(store.slotDir, fmt.Sprintf("slot-%012d.bin", slot))
}

func (store *formalCoxBlockwiseSourceStore) initialState() (
	formalCoxBlockwiseSourceState, error) {
	state := formalCoxBlockwiseSourceState{
		Version:       formalCoxBlockwiseSourceStateVersion,
		PlanSHA256:    store.session.context.planSHA256,
		PinsetSHA256:  store.session.context.pinsetSHA256,
		RecipientPeer: store.recipient, RecipientRole: store.recipientRole,
		TransportKeyID: store.transportKeyID,
		TicketSHA256:   store.ticketSHA256,
		ManifestSHA256: store.manifestSHA256, Generation: 1,
	}
	var err error
	state.MAC, err = formalCoxBlockwiseSourceStateMAC(store.key, state)
	return state, err
}

func (store *formalCoxBlockwiseSourceStore) validateState(
	state formalCoxBlockwiseSourceState) error {
	want, err := store.initialState()
	total, totalErr := formalCoxBlockwiseSourceSlotCount(store.plan)
	if err != nil || totalErr != nil ||
		state.Version != want.Version || state.PlanSHA256 != want.PlanSHA256 ||
		state.PinsetSHA256 != want.PinsetSHA256 ||
		state.RecipientPeer != want.RecipientPeer ||
		state.RecipientRole != want.RecipientRole ||
		state.TransportKeyID != want.TransportKeyID ||
		state.TicketSHA256 != want.TicketSHA256 ||
		state.ManifestSHA256 != want.ManifestSHA256 ||
		state.Generation < 1 || state.NextSlot < 0 || state.NextSlot > total ||
		!formalCoxIsSHA256(state.MAC) ||
		(state.PreviousMAC != "" && !formalCoxIsSHA256(state.PreviousMAC)) {
		return fmt.Errorf("formal-cox: invalid source-store cursor")
	}
	wantMAC, err := formalCoxBlockwiseSourceStateMAC(store.key, state)
	if err != nil || !hmac.Equal([]byte(wantMAC), []byte(state.MAC)) {
		return fmt.Errorf("formal-cox: source-store cursor authentication failed")
	}
	return nil
}

func (store *formalCoxBlockwiseSourceStore) readState() (
	formalCoxBlockwiseSourceState, error) {
	var state formalCoxBlockwiseSourceState
	encoded, err := formalCoxBlockwiseReadPrivateFile(
		store.statePath, 2, formalCoxBlockwiseSourceStateMax)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(encoded, &state); err != nil {
		return state, fmt.Errorf("formal-cox: decode source-store cursor: %w", err)
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return state, fmt.Errorf("formal-cox: non-canonical source-store cursor")
	}
	if err := store.validateState(state); err != nil {
		return state, err
	}
	return state, nil
}

func (store *formalCoxBlockwiseSourceStore) writeState(
	state formalCoxBlockwiseSourceState) error {
	if err := store.validateState(state); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) > formalCoxBlockwiseSourceStateMax {
		return fmt.Errorf("formal-cox: source-store cursor exceeds its bound")
	}
	return exactGCAtomicReplace(store.statePath, encoded)
}

func (store *formalCoxBlockwiseSourceStore) advanceState(
	state formalCoxBlockwiseSourceState) (formalCoxBlockwiseSourceState, error) {
	total, err := formalCoxBlockwiseSourceSlotCount(store.plan)
	if err != nil || state.NextSlot >= total {
		return state, fmt.Errorf("formal-cox: source-store cursor is complete")
	}
	previous := state.MAC
	state.Generation++
	state.NextSlot++
	state.PreviousMAC = previous
	state.MAC = ""
	state.MAC, err = formalCoxBlockwiseSourceStateMAC(store.key, state)
	if err != nil {
		return state, err
	}
	if err := store.writeState(state); err != nil {
		return state, err
	}
	return state, nil
}

func (store *formalCoxBlockwiseSourceStore) bootstrapAndRecover() error {
	state, err := store.readState()
	if os.IsNotExist(err) {
		directory, openErr := os.Open(store.slotDir)
		if openErr != nil {
			return openErr
		}
		entries, readErr := directory.ReadDir(1)
		closeErr := directory.Close()
		if readErr != nil {
			if readErr != io.EOF {
				return readErr
			}
		}
		if closeErr != nil {
			return closeErr
		}
		if len(entries) != 0 {
			return fmt.Errorf("formal-cox: source slots exist without a cursor")
		}
		state, err = store.initialState()
		if err != nil {
			return err
		}
		if err := store.writeState(state); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	total, _ := formalCoxBlockwiseSourceSlotCount(store.plan)
	for state.NextSlot < total {
		encoded, readErr := store.readSlot(state.NextSlot)
		if os.IsNotExist(readErr) {
			break
		}
		if readErr != nil {
			return readErr
		}
		header, _, _, shares, _, validateErr := store.validateBoundSlot(encoded)
		exactGCZeroBigInts(shares)
		if validateErr != nil || header.AssetSlot != state.NextSlot {
			return fmt.Errorf("formal-cox: invalid recoverable source slot")
		}
		state, err = store.advanceState(state)
		if err != nil {
			return err
		}
	}
	return nil
}

func formalCoxBlockwiseSourceEncodeBoundSlot(envelope, binding []byte) (
	[]byte, error) {
	if len(envelope) < 2 || len(binding) < 2 {
		return nil, fmt.Errorf("formal-cox: incomplete bound source slot")
	}
	record := formalCoxBlockwiseBoundSourceSlot{
		Version:  formalCoxBlockwiseBoundSlotVersion,
		Envelope: append(json.RawMessage(nil), envelope...),
		Binding:  append(json.RawMessage(nil), binding...),
	}
	return json.Marshal(record)
}

func formalCoxBlockwiseSourceDecodeBoundSlot(encoded []byte, maximum int64) (
	formalCoxBlockwiseBoundSourceSlot, error) {
	var record formalCoxBlockwiseBoundSourceSlot
	if err := formalCoxBlockwiseSourceDecodeCanonical(
		encoded, maximum, "bound source slot", &record); err != nil {
		return record, err
	}
	if record.Version != formalCoxBlockwiseBoundSlotVersion ||
		len(record.Envelope) < 2 || len(record.Binding) < 2 {
		return record, fmt.Errorf("formal-cox: invalid bound source slot")
	}
	return record, nil
}

func (store *formalCoxBlockwiseSourceStore) validateBoundSlot(encoded []byte) (
	formalCoxBlockwiseSourceHeader, string, string, []*big.Int, *bool, error) {
	var zero formalCoxBlockwiseSourceHeader
	record, err := formalCoxBlockwiseSourceDecodeBoundSlot(
		encoded, store.session.context.slotMaximum)
	if err != nil {
		return zero, "", "", nil, nil, err
	}
	envelope, digest, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
		store.session, store.recipient, record.Envelope)
	if err != nil {
		return zero, "", "", nil, nil, err
	}
	header := envelope.Header
	var pairedRoot string
	switch header.StepKind {
	case formalCoxBlockwiseStepBlock:
		var manifest formalCoxBlockwiseSourcePairManifest
		if err := formalCoxBlockwiseSourceDecodeCanonical(record.Binding,
			formalCoxBlockwiseSourceBindingMax, "source pair manifest",
			&manifest); err != nil {
			return zero, "", "", nil, nil, err
		}
		pairedRoot, err = formalCoxBlockwiseSourceValidatePairManifest(
			store.session, manifest, header, digest)
	case formalCoxBlockwiseStepUpdate:
		var barrier formalCoxBlockwiseGuardedNoiseBarrier
		if err := formalCoxBlockwiseSourceDecodeCanonical(record.Binding,
			formalCoxBlockwiseSourceBindingMax, "guarded paired noise barrier",
			&barrier); err != nil {
			return zero, "", "", nil, nil, err
		}
		pairedRoot, err = formalCoxBlockwiseSourceValidateGuardedNoiseBinding(
			store.session, barrier, header, digest)
	default:
		err = fmt.Errorf("formal-cox: source slot has no paired binding")
	}
	if err != nil || !formalCoxIsSHA256(pairedRoot) {
		return zero, "", "", nil, nil,
			fmt.Errorf("formal-cox: source slot pair binding failed")
	}
	plaintext, err := transportDecryptBytes(envelope.Ciphertext, store.recipientSK)
	if err != nil {
		return zero, "", "", nil, nil,
			fmt.Errorf("formal-cox: source ciphertext authentication failed")
	}
	defer clear(plaintext)
	shares, validity, err := formalCoxBlockwiseSourceDecodePrivate(header, plaintext)
	if err != nil {
		return zero, "", "", nil, nil, err
	}
	return header, digest, pairedRoot, shares, validity, nil
}

func formalCoxBlockwiseSourcePairedStepRoot(
	session *formalCoxBlockwiseSourceSession,
	step formalCoxBlockwiseWorkerStep, pairRoots []string) (string, error) {
	if session == nil || session.context == nil || step.InputRoot != "" {
		return "", fmt.Errorf("formal-cox: invalid paired source step")
	}
	kind, _, err := formalCoxBlockwiseSourceStepAsset(
		session.context.plan, step, false)
	want := 1
	if kind == formalCoxBlockwiseStepBlock {
		want = len(session.context.plan.Policy.CustodianPeers)
	}
	if err != nil || len(pairRoots) != want {
		return "", fmt.Errorf("formal-cox: incomplete paired source step")
	}
	message := formalCoxBlockwiseAppendString(nil,
		formalCoxBlockwisePairedStepRootDomain)
	for _, value := range []string{
		session.context.planSHA256, session.context.plan.RunID,
		session.context.pinsetSHA256, session.manifestSHA256, step.Kind,
	} {
		message = formalCoxBlockwiseAppendString(message, value)
	}
	message = formalCoxBlockwiseAppendUint64(message, uint64(step.ScheduleIndex))
	message = formalCoxBlockwiseAppendUint64(message, uint64(step.Iteration))
	message = formalCoxBlockwiseAppendUint64(message, uint64(step.BlockIndex+1))
	for index, root := range pairRoots {
		if !formalCoxIsSHA256(root) {
			return "", fmt.Errorf("formal-cox: invalid paired source root member")
		}
		label := "noise-authority-pair"
		if kind == formalCoxBlockwiseStepBlock {
			label = session.context.plan.Policy.CustodianPeers[index]
		}
		message = formalCoxBlockwiseAppendString(message, label)
		message = formalCoxBlockwiseAppendString(message, root)
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func (store *formalCoxBlockwiseSourceStore) readSlot(slot int) ([]byte, error) {
	return formalCoxBlockwiseReadPrivateFile(
		store.slotPath(slot), 2, store.session.context.slotMaximum)
}

func (store *formalCoxBlockwiseSourceStore) persistSlot(slot int,
	encoded []byte) (bool, error) {
	path := store.slotPath(slot)
	if existing, err := store.readSlot(slot); err == nil {
		if !bytes.Equal(existing, encoded) {
			return false, fmt.Errorf("formal-cox: conflicting source replay")
		}
		if store.syncSlotDir == nil {
			return false, fmt.Errorf("formal-cox: source slot durability is unavailable")
		}
		if err := store.syncSlotDir(store.slotDir); err != nil {
			return false, err
		}
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	tmp, err := os.CreateTemp(store.slotDir, ".formal-cox-source-")
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
		existing, readErr := store.readSlot(slot)
		if readErr != nil {
			return false, readErr
		}
		if !bytes.Equal(existing, encoded) {
			return false, fmt.Errorf("formal-cox: conflicting source replay")
		}
		if store.syncSlotDir == nil {
			return false, fmt.Errorf("formal-cox: source slot durability is unavailable")
		}
		if err := store.syncSlotDir(store.slotDir); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if store.syncSlotDir == nil {
		return false, fmt.Errorf("formal-cox: source slot durability is unavailable")
	}
	if err := store.syncSlotDir(store.slotDir); err != nil {
		return false, err
	}
	return false, nil
}

func (store *formalCoxBlockwiseSourceStore) Accept(encoded, binding []byte) (
	bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.owner == nil {
		return false, fmt.Errorf("formal-cox: source store is closed")
	}
	persisted, err := formalCoxBlockwiseSourceEncodeBoundSlot(encoded, binding)
	var header formalCoxBlockwiseSourceHeader
	var shares []*big.Int
	if err == nil {
		header, _, _, shares, _, err = store.validateBoundSlot(persisted)
	}
	exactGCZeroBigInts(shares)
	if err != nil {
		return false, err
	}
	state, err := store.readState()
	if err != nil {
		return false, err
	}
	if header.AssetSlot > state.NextSlot {
		return false, fmt.Errorf("formal-cox: source slots must arrive in canonical order")
	}
	if header.AssetSlot < state.NextSlot {
		existing, err := store.readSlot(header.AssetSlot)
		if err != nil || !bytes.Equal(existing, persisted) {
			return false, fmt.Errorf("formal-cox: conflicting source replay")
		}
		return true, nil
	}
	replayed, err := store.persistSlot(header.AssetSlot, persisted)
	if err != nil {
		return false, err
	}
	if replayed {
		existing, readErr := store.readSlot(header.AssetSlot)
		if readErr != nil || !bytes.Equal(existing, persisted) {
			return false, fmt.Errorf("formal-cox: conflicting source replay")
		}
	}
	if _, err := store.advanceState(state); err != nil {
		return false, err
	}
	return replayed, nil
}

func formalCoxBlockwiseSourceRoot(plan formalCoxBlockwisePlan,
	header formalCoxBlockwiseSourceHeader, recipient string,
	digests []string) (string, error) {
	planSHA, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil || len(digests) < 1 {
		return "", fmt.Errorf("formal-cox: invalid recipient source root")
	}
	message := formalCoxBlockwiseAppendString(nil,
		formalCoxBlockwiseSourceRootDomain)
	message = formalCoxBlockwiseAppendString(message, planSHA)
	message = formalCoxBlockwiseAppendString(message, recipient)
	message = formalCoxBlockwiseAppendString(message, header.RecipientRole)
	message = formalCoxBlockwiseAppendString(message, header.StepKind)
	message = formalCoxBlockwiseAppendUint64(message, uint64(header.BlockIndex+1))
	message = formalCoxBlockwiseAppendUint64(message, uint64(header.Iteration))
	message = formalCoxBlockwiseAppendUint64(message, uint64(header.CoordinateOffset))
	message = formalCoxBlockwiseAppendUint64(message, uint64(header.CoordinateCount))
	for _, digest := range digests {
		if !formalCoxIsSHA256(digest) {
			return "", fmt.Errorf("formal-cox: invalid source envelope root member")
		}
		message = formalCoxBlockwiseAppendString(message, digest)
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func (store *formalCoxBlockwiseSourceStore) Load(
	step formalCoxBlockwiseWorkerStep) (formalCoxBlockwiseSourceInput, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var zero formalCoxBlockwiseSourceInput
	if store.closed || store.owner == nil {
		return zero, fmt.Errorf("formal-cox: source store is closed")
	}
	kind, asset, err := formalCoxBlockwiseSourceStepAsset(store.plan, step, false)
	if err != nil {
		return zero, err
	}
	first, count := 0, 1
	if kind == formalCoxBlockwiseStepBlock {
		first = asset * len(store.plan.Policy.CustodianPeers)
		count = len(store.plan.Policy.CustodianPeers)
	} else {
		first = store.plan.TotalBlocks*len(store.plan.Policy.CustodianPeers) + asset
	}
	state, err := store.readState()
	if err != nil {
		return zero, err
	}
	if state.NextSlot < first+count {
		return zero, fmt.Errorf("formal-cox: source asset is incomplete")
	}
	var aggregate []*big.Int
	var validity *bool
	digests := make([]string, count)
	pairRoots := make([]string, count)
	var firstHeader formalCoxBlockwiseSourceHeader
	modulus := exactGCModulus(store.plan.RingBits)
	for local := 0; local < count; local++ {
		encoded, err := store.readSlot(first + local)
		if err != nil {
			exactGCZeroBigInts(aggregate)
			return zero, err
		}
		header, digest, pairRoot, shares, localValidity, err :=
			store.validateBoundSlot(encoded)
		if err != nil || header.AssetSlot != first+local {
			exactGCZeroBigInts(aggregate)
			exactGCZeroBigInts(shares)
			return zero, fmt.Errorf("formal-cox: invalid, missing, or reordered source slot")
		}
		if local == 0 {
			firstHeader = header
			aggregate = make([]*big.Int, len(shares))
			for index := range aggregate {
				aggregate[index] = new(big.Int)
			}
		}
		for index := range aggregate {
			aggregate[index].Add(aggregate[index], shares[index])
			aggregate[index].Mod(aggregate[index], modulus)
		}
		exactGCZeroBigInts(shares)
		if localValidity != nil {
			if count != 1 || validity != nil {
				exactGCZeroBigInts(aggregate)
				return zero, fmt.Errorf("formal-cox: invalid source validity schedule")
			}
			value := *localValidity
			validity = &value
		}
		digests[local] = digest
		pairRoots[local] = pairRoot
	}
	root, err := formalCoxBlockwiseSourceRoot(
		store.plan, firstHeader, store.recipient, digests)
	if err != nil {
		exactGCZeroBigInts(aggregate)
		return zero, err
	}
	pairedRoot, err := formalCoxBlockwiseSourcePairedStepRoot(
		store.session, step, pairRoots)
	if err != nil {
		exactGCZeroBigInts(aggregate)
		return zero, err
	}
	return formalCoxBlockwiseSourceInput{
		Step: step, RecipientPeer: store.recipient,
		RecipientRootSHA256: root, PairedInputRootSHA256: pairedRoot,
		EnvelopeSHA256: digests,
		Shares:         aggregate, ValidityShare: validity,
	}, nil
}

func (store *formalCoxBlockwiseSourceStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	clear(store.recipientSK)
	if store.owner == nil {
		return nil
	}
	unlockErr := formalFinalizerHandoffUnlockAuthority(store.owner)
	closeErr := store.owner.Close()
	store.owner = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
