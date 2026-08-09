package main

// Recipient-local authenticated handoff from the existing typed-source
// transport to the Cox circuit.  The relay-visible receipt contains only
// commitments. AggregateShares is private local state and is deliberately
// excluded from JSON; a production R bridge must stage it directly into the
// exact-GC worker, never return it through DSI.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
)

const (
	formalCoxRuntimeSourceFanInVersion = "dsvert-formal-cox-typed-source-fanin-v1"
	formalCoxRuntimeSourceFanInDomain  = "dsVert/formal-cox/typed-source-fanin/v1"
)

var formalCoxRuntimeSourceFanInBlockers = []string{
	"r_dsi_recipient_encrypted_typed_source_bridge_not_executed_v1",
	"real_multiprocess_source_to_worker_handoff_not_executed_v1",
}

type formalCoxRuntimeSourceFanIn struct {
	Version                     string     `json:"version"`
	Domain                      string     `json:"domain"`
	PolicySHA256                string     `json:"policy_sha256"`
	SnapshotSHA256              string     `json:"snapshot_sha256"`
	MaterializationRootSHA256   string     `json:"materialization_root_sha256"`
	SourceFanInTranscriptSHA256 string     `json:"source_fan_in_transcript_sha256"`
	RecipientPeerName           string     `json:"recipient_peer_name"`
	RecipientPeerID             string     `json:"recipient_peer_id"`
	Role                        string     `json:"role"`
	RingBits                    int        `json:"ring_bits"`
	CoordinateCount             int        `json:"coordinate_count"`
	SourcePeers                 []string   `json:"source_peers"`
	SourceReceiptSHA256         []string   `json:"source_receipt_sha256"`
	AggregateShareSHA256        string     `json:"aggregate_share_sha256"`
	FixedShape                  bool       `json:"fixed_shape"`
	RelayVisiblePlaintextShares bool       `json:"relay_visible_plaintext_shares"`
	ProductionReady             bool       `json:"production_ready"`
	Blockers                    []string   `json:"blockers"`
	Signature                   []byte     `json:"signature"`
	AggregateShares             []*big.Int `json:"-"`
}

func formalCoxRuntimeSourceFanInBase(admission formalCoxRuntimeAdmission,
	role string, sourceReceiptSHA256 []string, shares []*big.Int,
) (formalCoxRuntimeSourceFanIn, error) {
	var zero formalCoxRuntimeSourceFanIn
	peerName, peerID := admission.Roles.GarblerPeerName,
		admission.Roles.GarblerPeerID
	if role == "evaluator" {
		peerName, peerID = admission.Roles.EvaluatorPeerName,
			admission.Roles.EvaluatorPeerID
	} else if role != "garbler" {
		return zero, fmt.Errorf("formal-cox: invalid source fan-in role")
	}
	if len(shares) != admission.Phase1Plan.RowCoordinates ||
		len(sourceReceiptSHA256) != len(admission.Policy.CustodianPeers) {
		return zero, fmt.Errorf("formal-cox: incomplete fixed-shape source fan-in")
	}
	spec := exactGCCircuitSpec{
		Operation: exactGCFormalCoxIterations, RingBits: 128,
		FracBits:  admission.Policy.FracBits,
		VectorLen: admission.Phase1Plan.RowCoordinates,
	}
	digest, err := formalCoxRuntimeShareSHA256(
		formalCoxRuntimeSourceFanInDomain+"/aggregate-share", role,
		shares, spec, nil)
	if err != nil {
		return zero, err
	}
	policySHA256, err := formalCoxPolicyDigest(admission.Policy)
	if err != nil {
		return zero, err
	}
	return formalCoxRuntimeSourceFanIn{
		Version:                     formalCoxRuntimeSourceFanInVersion,
		Domain:                      formalCoxRuntimeSourceFanInDomain,
		PolicySHA256:                hex.EncodeToString(policySHA256[:]),
		SnapshotSHA256:              admission.Binding.SnapshotSHA256,
		MaterializationRootSHA256:   admission.Envelopes[0].Preimage.MaterializationRootSHA256,
		SourceFanInTranscriptSHA256: admission.Binding.SourceFanInTranscriptSHA256,
		RecipientPeerName:           peerName, RecipientPeerID: peerID, Role: role,
		RingBits: 128, CoordinateCount: len(shares),
		SourcePeers:          append([]string(nil), admission.Policy.CustodianPeers...),
		SourceReceiptSHA256:  append([]string(nil), sourceReceiptSHA256...),
		AggregateShareSHA256: digest, FixedShape: true,
		RelayVisiblePlaintextShares: false, ProductionReady: false,
		Blockers:        append([]string(nil), formalCoxRuntimeSourceFanInBlockers...),
		AggregateShares: shares,
	}, nil
}

func formalCoxRuntimeSourceFanInMessage(
	receipt formalCoxRuntimeSourceFanIn,
) ([]byte, error) {
	unsigned := receipt
	unsigned.Signature = nil
	unsigned.AggregateShares = nil
	return jointDPBiomedicalGaussianDomainMessage(
		formalCoxRuntimeSourceFanInDomain, unsigned)
}

func formalCoxRuntimeBuildSourceFanIn(admission formalCoxRuntimeAdmission,
	role string, sourceReceiptSHA256 []string, shares []*big.Int,
	signer ed25519.PrivateKey,
) (formalCoxRuntimeSourceFanIn, error) {
	receipt, err := formalCoxRuntimeSourceFanInBase(
		admission, role, sourceReceiptSHA256, shares)
	if err != nil {
		return formalCoxRuntimeSourceFanIn{}, err
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(admission.Trust)
	if err != nil {
		return formalCoxRuntimeSourceFanIn{}, err
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(public, pins[receipt.RecipientPeerName]) {
		return formalCoxRuntimeSourceFanIn{},
			fmt.Errorf("formal-cox: source fan-in signer is not the pinned recipient")
	}
	message, err := formalCoxRuntimeSourceFanInMessage(receipt)
	if err != nil {
		return formalCoxRuntimeSourceFanIn{}, err
	}
	receipt.Signature = ed25519.Sign(signer, message)
	return receipt, nil
}

func formalCoxRuntimeValidateSourceFanIn(admission formalCoxRuntimeAdmission,
	role string, receipt formalCoxRuntimeSourceFanIn,
) error {
	want, err := formalCoxRuntimeSourceFanInBase(
		admission, role, receipt.SourceReceiptSHA256, receipt.AggregateShares)
	if err != nil {
		return err
	}
	signature := append([]byte(nil), receipt.Signature...)
	receipt.Signature = nil
	want.Signature = nil
	if len(signature) != ed25519.SignatureSize ||
		!reflect.DeepEqual(receipt, want) {
		return fmt.Errorf("formal-cox: source fan-in binding mismatch")
	}
	seen := make(map[string]bool, len(receipt.SourceReceiptSHA256))
	for _, digest := range receipt.SourceReceiptSHA256 {
		if !formalCoxIsSHA256(digest) || seen[digest] {
			return fmt.Errorf("formal-cox: invalid typed-source receipt set")
		}
		seen[digest] = true
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(admission.Trust)
	if err != nil {
		return err
	}
	message, err := formalCoxRuntimeSourceFanInMessage(want)
	if err != nil || !ed25519.Verify(
		pins[want.RecipientPeerName], message, signature) {
		return fmt.Errorf("formal-cox: source fan-in signature failed")
	}
	return nil
}

func formalCoxRuntimeSourceFanInSHA256(
	receipt formalCoxRuntimeSourceFanIn,
) (string, error) {
	if len(receipt.Signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("formal-cox: unsigned source fan-in receipt")
	}
	receipt.AggregateShares = nil
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	digest := formalCoxSHA256Domain(
		formalCoxRuntimeSourceFanInDomain+"/signed-receipt|", encoded)
	return hex.EncodeToString(digest[:]), nil
}
