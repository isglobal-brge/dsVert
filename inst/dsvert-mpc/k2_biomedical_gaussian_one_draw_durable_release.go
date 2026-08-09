package main

// Durable, fixed-shape finalization for the biomedical Gaussian one-draw
// route.  The GC output stays split between the two pinned computation peers.
// Each peer signs a digest of its private chunk output; a server-local
// finalizer verifies both receipts, commits the release reservation, checks
// every private validity share, and only then reconstructs the one clamped DP
// vector.  No command, R endpoint, or relay-visible share is added here.

import (
	"bytes"
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
	"reflect"
	"sort"
	"sync"
)

const (
	jointDPBiomedicalGaussianOneDrawChunkReceiptVersion  = "dsvert-biomedical-gaussian-one-draw-private-chunk-receipt-v1"
	jointDPBiomedicalGaussianOneDrawChunkReceiptDomain   = "dsVert/biomedical-gaussian-one-draw/private-chunk-receipt/v1"
	jointDPBiomedicalGaussianOneDrawDurableRecordVersion = "dsvert-biomedical-gaussian-one-draw-durable-record-v1"
	jointDPBiomedicalGaussianOneDrawDurableRecordDomain  = "dsVert/biomedical-gaussian-one-draw/durable-record/v1"
	jointDPBiomedicalGaussianOneDrawLocalReleaseVersion  = "dsvert-biomedical-gaussian-one-draw-local-release-v1"
	jointDPBiomedicalGaussianOneDrawLocalReleaseDomain   = "dsVert/biomedical-gaussian-one-draw/local-release/v1"
	jointDPBiomedicalGaussianOneDrawCommonReleaseVersion = "dsvert-biomedical-gaussian-one-draw-common-release-v1"
	jointDPBiomedicalGaussianOneDrawCommonReleaseDomain  = "dsVert/biomedical-gaussian-one-draw/common-release/v1"
	jointDPBiomedicalGaussianOneDrawCostVersion          = "dsvert-biomedical-gaussian-one-draw-cost-certificate-v1"
	jointDPBiomedicalGaussianOneDrawBackend              = "exact_gc_yao_joint_discrete_gaussian_one_draw_v1"
	jointDPBiomedicalGaussianOneDrawRouteRole            = "certified_one_draw_internal_candidate_not_public_v1"
	jointDPBiomedicalGaussianOneDrawPrivacyScope         = "formal_epsilon_delta_per_canonical_release_unlimited_distinct_releases_have_no_finite_global_composition_bound_v1"
	jointDPBiomedicalGaussianOneDrawMaximumRecordBytes   = 64 * 1024 * 1024
)

var jointDPBiomedicalGaussianOneDrawReleaseBlockers = []string{
	"server_authoritative_materializer_and_durable_worker_handoff_not_wired_e2e_v1",
	"r_dsi_verified_common_release_projection_not_wired_v1",
	"exact_gc_cdf_cost_requires_deployment_benchmark_v1",
	"semi_honest_two_compute_peer_gc_only_v1",
	"unlimited_distinct_release_composition_has_no_finite_global_dp_bound_v1",
}

type jointDPBiomedicalGaussianOneDrawChunkReceipt struct {
	Version                  string `json:"version"`
	Route                    string `json:"route"`
	EnvelopePreimageSHA256   string `json:"envelope_preimage_sha256"`
	ProductiveStreamSHA256   string `json:"productive_stream_sha256"`
	ReleaseInstanceID        string `json:"release_instance_id"`
	ReleaseContractSHA256    string `json:"release_contract_sha256"`
	PlanSHA256               string `json:"plan_sha256"`
	CoordinateOrderSHA256    string `json:"coordinate_order_sha256"`
	TotalCoordinateCount     int    `json:"total_coordinate_count"`
	ChunkStart               int    `json:"chunk_start"`
	CoordinateCount          int    `json:"coordinate_count"`
	PeerName                 string `json:"peer_name"`
	PeerID                   string `json:"peer_id"`
	Role                     string `json:"role"`
	OutputShareSHA256        string `json:"output_share_sha256"`
	PayloadShareCount        int    `json:"payload_share_count"`
	ValidityXORShareIncluded bool   `json:"validity_xor_share_included"`
	ProtectedPayloadExposed  bool   `json:"protected_payload_exposed"`
	ValidityPredicateOpened  bool   `json:"validity_predicate_opened"`
	Signature                []byte `json:"signature"`
}

// Shares are server-local GC output and are never JSON-serializable.  The
// signed receipt commits to their canonical fixed-width encoding.
type jointDPBiomedicalGaussianOneDrawChunkHandoff struct {
	Envelope        jointDPBiomedicalGaussianSignedWorkerEnvelope `json:"envelope"`
	Garbler         jointDPBiomedicalGaussianOneDrawChunkReceipt  `json:"garbler"`
	Evaluator       jointDPBiomedicalGaussianOneDrawChunkReceipt  `json:"evaluator"`
	GarblerShares   []*big.Int                                    `json:"-"`
	EvaluatorShares []*big.Int                                    `json:"-"`
}

type jointDPBiomedicalGaussianOneDrawCostCertificate struct {
	Version                                     string `json:"version"`
	PlanSHA256                                  string `json:"plan_sha256"`
	TotalCoordinateCount                        int    `json:"total_coordinate_count"`
	CanonicalChunkCount                         int    `json:"canonical_chunk_count"`
	MaximumChunkCoordinates                     int    `json:"maximum_chunk_coordinates"`
	SamplerMagnitudeCount                       int    `json:"sampler_magnitude_count"`
	CDFComparisonsPerCoordinate                 int    `json:"cdf_comparisons_per_coordinate"`
	CanonicalTotalCDFComparisons                int64  `json:"canonical_total_cdf_comparisons"`
	CDFLookupCircuitModel                       string `json:"cdf_lookup_circuit_model"`
	SecretIndexedPublicRAMAvailable             bool   `json:"secret_indexed_public_ram_available"`
	LogarithmicCircuitSizeClaim                 bool   `json:"logarithmic_circuit_size_claim"`
	PeakProjectedGateCountUpper                 int64  `json:"peak_projected_gate_count_upper"`
	PeakProjectedNonXORGateCountUpper           int64  `json:"peak_projected_non_xor_gate_count_upper"`
	PeakProjectedGarbledTableBytesUpper         int64  `json:"peak_projected_garbled_table_bytes_upper"`
	PeakProjectedWireLabelBytesUpper            int64  `json:"peak_projected_wire_label_bytes_upper"`
	PeakProjectedCompilerAllocationBytesUpper   int64  `json:"peak_projected_compiler_allocation_bytes_upper"`
	AggregateProjectedGateCountUpper            int64  `json:"aggregate_projected_gate_count_upper"`
	AggregateProjectedNonXORGateCountUpper      int64  `json:"aggregate_projected_non_xor_gate_count_upper"`
	AggregateProjectedGarbledTableBytesUpper    int64  `json:"aggregate_projected_garbled_table_bytes_upper"`
	AggregateProjectedWireLabelBytesUpper       int64  `json:"aggregate_projected_wire_label_bytes_upper"`
	MaximumProjectedGateCount                   int64  `json:"maximum_projected_gate_count"`
	MaximumProjectedNonXORGateCount             int64  `json:"maximum_projected_non_xor_gate_count"`
	MaximumProjectedGarbledTableBytes           int64  `json:"maximum_projected_garbled_table_bytes"`
	MaximumProjectedWireLabelBytes              int64  `json:"maximum_projected_wire_label_bytes"`
	MaximumProjectedCompilerAllocationBytes     int64  `json:"maximum_projected_compiler_allocation_bytes"`
	IndependentFullProtectedSharePayloadBytes   int64  `json:"independent_full_protected_share_payload_bytes"`
	OneDrawPostGCProtectedSharePayloadBytes     int64  `json:"one_draw_post_gc_protected_share_payload_bytes"`
	GarbledToIndependentPayloadRatioNumerator   string `json:"garbled_to_independent_payload_ratio_numerator"`
	GarbledToIndependentPayloadRatioDenominator string `json:"garbled_to_independent_payload_ratio_denominator"`
	CostProjectionIsConservative                bool   `json:"cost_projection_is_conservative"`
	ResourcePolicySatisfied                     bool   `json:"resource_policy_satisfied"`
	CapabilityAvailable                         bool   `json:"capability_available"`
	FallbackAutomatic                           bool   `json:"fallback_automatic"`
	FallbackNominalVarianceMultiplier           int    `json:"fallback_nominal_variance_multiplier"`
}

type jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt struct {
	Version                             string                                          `json:"version"`
	Backend                             string                                          `json:"backend"`
	Mechanism                           string                                          `json:"mechanism"`
	Sampler                             string                                          `json:"sampler"`
	PeerName                            string                                          `json:"peer_name"`
	PeerIdentitySHA256                  string                                          `json:"peer_identity_sha256"`
	ReleaseInstanceID                   string                                          `json:"release_instance_id"`
	ReleaseContractSHA256               string                                          `json:"release_contract_sha256"`
	ProductiveStreamSHA256              string                                          `json:"productive_stream_sha256"`
	PlanSHA256                          string                                          `json:"plan_sha256"`
	CoordinateOrderSHA256               string                                          `json:"coordinate_order_sha256"`
	LedgerReservationSHA256             string                                          `json:"ledger_reservation_sha256"`
	FinalizerReservationSHA256          string                                          `json:"finalizer_reservation_sha256"`
	VectorSHA256                        string                                          `json:"vector_sha256"`
	ClampedScaledValues                 []string                                        `json:"clamped_scaled_values"`
	OutputLatticeBits                   int                                             `json:"output_lattice_bits"`
	Epsilon                             string                                          `json:"epsilon"`
	Delta                               string                                          `json:"delta"`
	CoreDeltaNumerator                  string                                          `json:"core_delta_numerator"`
	CoreDeltaDenominator                string                                          `json:"core_delta_denominator"`
	VectorTailTVUpperNumerator          string                                          `json:"vector_tail_tv_upper_numerator"`
	VectorTailTVUpperDenominator        string                                          `json:"vector_tail_tv_upper_denominator"`
	VectorCDFTVUpperNumerator           string                                          `json:"vector_cdf_tv_upper_numerator"`
	VectorCDFTVUpperDenominator         string                                          `json:"vector_cdf_tv_upper_denominator"`
	VectorTotalTVUpperNumerator         string                                          `json:"vector_total_tv_upper_numerator"`
	VectorTotalTVUpperDenominator       string                                          `json:"vector_total_tv_upper_denominator"`
	ImplementationDeltaNumerator        string                                          `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator      string                                          `json:"implementation_delta_denominator"`
	RouteRole                           string                                          `json:"route_role"`
	PrivacyClaimScope                   string                                          `json:"privacy_claim_scope"`
	TargetVarianceOptimal               bool                                            `json:"target_variance_optimal"`
	NominalVarianceMultiplier           int                                             `json:"nominal_variance_multiplier"`
	NominalStandardDeviationFactor      string                                          `json:"nominal_standard_deviation_factor"`
	Cost                                jointDPBiomedicalGaussianOneDrawCostCertificate `json:"cost"`
	LedgerAppendBeforeValidityOrRelease bool                                            `json:"ledger_append_before_validity_or_release"`
	ExactlyOnceRelease                  bool                                            `json:"exactly_once_release"`
	SingleCommonDPVector                bool                                            `json:"single_common_dp_vector"`
	UnlimitedDeterministicReplay        bool                                            `json:"unlimited_deterministic_replay"`
	UnlimitedPostprocessing             bool                                            `json:"unlimited_postprocessing"`
	HistoryCanDenyOperation             bool                                            `json:"history_can_deny_operation"`
	OperationLimit                      bool                                            `json:"operation_limit"`
	RequestLimit                        bool                                            `json:"request_limit"`
	OpeningsPerformed                   int                                             `json:"openings_performed"`
	ProductionReady                     bool                                            `json:"production_ready"`
	Blockers                            []string                                        `json:"blockers"`
	CommonReleaseSignature              []byte                                          `json:"common_release_signature"`
	Signature                           []byte                                          `json:"signature"`
}

type jointDPBiomedicalGaussianOneDrawLocalRelease struct {
	Receipt  jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt
	Replayed bool
}

type jointDPBiomedicalGaussianOneDrawCommonRelease struct {
	Version                             string                                          `json:"version"`
	Backend                             string                                          `json:"backend"`
	Mechanism                           string                                          `json:"mechanism"`
	Sampler                             string                                          `json:"sampler"`
	ReleaseInstanceID                   string                                          `json:"release_instance_id"`
	ReleaseContractSHA256               string                                          `json:"release_contract_sha256"`
	ProductiveStreamSHA256              string                                          `json:"productive_stream_sha256"`
	PlanSHA256                          string                                          `json:"plan_sha256"`
	CoordinateOrderSHA256               string                                          `json:"coordinate_order_sha256"`
	LedgerReservationSHA256             string                                          `json:"ledger_reservation_sha256"`
	FinalizerReservationSHA256          string                                          `json:"finalizer_reservation_sha256"`
	DesignatedComputePeers              []string                                        `json:"designated_compute_peers"`
	VectorSHA256                        string                                          `json:"vector_sha256"`
	ClampedScaledValues                 []string                                        `json:"clamped_scaled_values"`
	OutputLatticeBits                   int                                             `json:"output_lattice_bits"`
	Epsilon                             string                                          `json:"epsilon"`
	Delta                               string                                          `json:"delta"`
	CoreDeltaNumerator                  string                                          `json:"core_delta_numerator"`
	CoreDeltaDenominator                string                                          `json:"core_delta_denominator"`
	VectorTailTVUpperNumerator          string                                          `json:"vector_tail_tv_upper_numerator"`
	VectorTailTVUpperDenominator        string                                          `json:"vector_tail_tv_upper_denominator"`
	VectorCDFTVUpperNumerator           string                                          `json:"vector_cdf_tv_upper_numerator"`
	VectorCDFTVUpperDenominator         string                                          `json:"vector_cdf_tv_upper_denominator"`
	VectorTotalTVUpperNumerator         string                                          `json:"vector_total_tv_upper_numerator"`
	VectorTotalTVUpperDenominator       string                                          `json:"vector_total_tv_upper_denominator"`
	ImplementationDeltaNumerator        string                                          `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator      string                                          `json:"implementation_delta_denominator"`
	RouteRole                           string                                          `json:"route_role"`
	PrivacyClaimScope                   string                                          `json:"privacy_claim_scope"`
	TargetVarianceOptimal               bool                                            `json:"target_variance_optimal"`
	NominalVarianceMultiplier           int                                             `json:"nominal_variance_multiplier"`
	NominalStandardDeviationFactor      string                                          `json:"nominal_standard_deviation_factor"`
	Cost                                jointDPBiomedicalGaussianOneDrawCostCertificate `json:"cost"`
	LedgerAppendBeforeValidityOrRelease bool                                            `json:"ledger_append_before_validity_or_release"`
	ExactlyOnceRelease                  bool                                            `json:"exactly_once_release"`
	SingleCommonDPVector                bool                                            `json:"single_common_dp_vector"`
	UnlimitedDeterministicReplay        bool                                            `json:"unlimited_deterministic_replay"`
	UnlimitedPostprocessing             bool                                            `json:"unlimited_postprocessing"`
	HistoryCanDenyOperation             bool                                            `json:"history_can_deny_operation"`
	OperationLimit                      bool                                            `json:"operation_limit"`
	RequestLimit                        bool                                            `json:"request_limit"`
	OpeningsPerformed                   int                                             `json:"openings_performed"`
	ProductionReady                     bool                                            `json:"production_ready"`
	Blockers                            []string                                        `json:"blockers"`
	Signatures                          []jointDPBiomedicalGaussianSignature            `json:"signatures"`
}

type jointDPBiomedicalGaussianOneDrawDurableRecord struct {
	Version                             string `json:"version"`
	State                               string `json:"state"`
	PeerName                            string `json:"peer_name"`
	ReleaseInstanceID                   string `json:"release_instance_id"`
	ReleaseContractSHA256               string `json:"release_contract_sha256"`
	ProductiveStreamSHA256              string `json:"productive_stream_sha256"`
	InputCommitmentSHA256               string `json:"input_commitment_sha256"`
	ValidityScheduleCommitmentSHA256    string `json:"validity_schedule_commitment_sha256"`
	LedgerReservationSHA256             string `json:"ledger_reservation_sha256"`
	FinalizerReservationSHA256          string `json:"finalizer_reservation_sha256"`
	LedgerAppendBeforeValidityOrRelease bool   `json:"ledger_append_before_validity_or_release"`
	ValidityChecked                     bool   `json:"validity_checked"`
	AllChunksValid                      bool   `json:"all_chunks_valid"`
	HistoryCanDenyOperation             bool   `json:"history_can_deny_operation"`
	OperationLimit                      bool   `json:"operation_limit"`
	RequestLimit                        bool   `json:"request_limit"`
	ReleaseReceiptJSON                  string `json:"release_receipt_json"`
	RecordMAC                           string `json:"record_mac"`
}

type jointDPBiomedicalGaussianOneDrawDurableReleaseStore struct {
	mu      sync.Mutex
	records string
	peer    string
	key     [32]byte
	signer  ed25519.PrivateKey
}

type jointDPBiomedicalGaussianOneDrawAuthority struct {
	preimage     jointDPBiomedicalGaussianWorkerEnvelopePreimage
	plan         jointDPGaussianOneDrawPlanOutput
	planSHA256   string
	ledger       jointDPBiomedicalGaussianReceiptReference
	finalizer    jointDPBiomedicalGaussianReceiptReference
	computePeers []string
	pins         map[string]ed25519.PublicKey
	cost         jointDPBiomedicalGaussianOneDrawCostCertificate
}

type jointDPBiomedicalGaussianOneDrawNormalizedChunk struct {
	start, count                       int
	garbler, evaluator                 []byte
	garblerValidity, evaluatorValidity byte
}

type jointDPBiomedicalGaussianOneDrawNormalizedInput struct {
	authority        jointDPBiomedicalGaussianOneDrawAuthority
	chunks           []jointDPBiomedicalGaussianOneDrawNormalizedChunk
	digest           string
	validitySchedule string
}

type jointDPBiomedicalGaussianOneDrawInvalidSource struct {
	ReleaseInstanceID string
}

func (condition *jointDPBiomedicalGaussianOneDrawInvalidSource) Error() string {
	return "joint-dp-biomedical-gaussian-one-draw: protected source violated its signed bounds; no DP vector was released"
}

func jointDPBiomedicalGaussianOneDrawFixedShare(value *big.Int, bits int) ([]byte, error) {
	if value == nil || value.Sign() < 0 || value.BitLen() > bits {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid private GC output share")
	}
	width := (bits + 7) / 8
	encoded := make([]byte, width)
	value.FillBytes(encoded)
	return encoded, nil
}

func jointDPBiomedicalGaussianOneDrawEncodeOutputShares(shares []*big.Int,
	coordinateCount int,
) ([]byte, byte, error) {
	if coordinateCount < 1 || len(shares) != coordinateCount+1 {
		return nil, 0, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid private GC output shape")
	}
	payload := make([]byte, coordinateCount*16)
	for index := 0; index < coordinateCount; index++ {
		encoded, err := jointDPBiomedicalGaussianOneDrawFixedShare(shares[index], 128)
		if err != nil {
			clear(payload)
			return nil, 0, err
		}
		copy(payload[index*16:], encoded)
		clear(encoded)
	}
	validity, err := jointDPBiomedicalGaussianOneDrawFixedShare(
		shares[coordinateCount], 1)
	if err != nil {
		clear(payload)
		return nil, 0, err
	}
	return payload, validity[0], nil
}

func jointDPBiomedicalGaussianOneDrawOutputShareSHA256(
	preimageSHA256, role string, payload []byte, validity byte,
) (string, error) {
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianOneDrawChunkReceiptDomain+"/private-output", struct {
			EnvelopePreimageSHA256 string `json:"envelope_preimage_sha256"`
			Role                   string `json:"role"`
			PayloadSHA256          string `json:"payload_sha256"`
			PayloadBytes           int    `json:"payload_bytes"`
			ValidityXORShare       int    `json:"validity_xor_share"`
		}{preimageSHA256, role,
			hex.EncodeToString(func() []byte { sum := sha256.Sum256(payload); return sum[:] }()),
			len(payload), int(validity)})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianOneDrawChunkReceiptMessage(
	receipt jointDPBiomedicalGaussianOneDrawChunkReceipt,
) ([]byte, error) {
	if receipt.Version != jointDPBiomedicalGaussianOneDrawChunkReceiptVersion ||
		receipt.Route != jointDPBiomedicalGaussianWorkerRoute ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.EnvelopePreimageSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.ProductiveStreamSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.PlanSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.CoordinateOrderSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.OutputShareSHA256) ||
		!jointDPBiomedicalGaussianValidPeerName(receipt.PeerName) ||
		!jointDPGaussianOneDrawPinnedPeer.MatchString(receipt.PeerID) ||
		(receipt.Role != "garbler" && receipt.Role != "evaluator") ||
		receipt.TotalCoordinateCount < 1 || receipt.ChunkStart < 0 ||
		receipt.CoordinateCount < 1 ||
		receipt.ChunkStart > receipt.TotalCoordinateCount-receipt.CoordinateCount ||
		receipt.PayloadShareCount != receipt.CoordinateCount ||
		!receipt.ValidityXORShareIncluded || receipt.ProtectedPayloadExposed ||
		receipt.ValidityPredicateOpened {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid private chunk receipt")
	}
	unsigned := receipt
	unsigned.Signature = nil
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianOneDrawChunkReceiptDomain, unsigned)
}

// BuildOneDrawChunkReceipt is the isolated integration point immediately
// after RunProductive{Garbler,Evaluator}.  It commits to, but never serializes,
// the returned private shares.
func jointDPBiomedicalGaussianBuildOneDrawChunkReceipt(
	envelope jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	role string, shares []*big.Int, privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianOneDrawChunkReceipt, error) {
	var zero jointDPBiomedicalGaussianOneDrawChunkReceipt
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(envelope, trust)
	if err != nil {
		return zero, err
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(trust)
	if err != nil {
		return zero, err
	}
	peerName, peerID := envelope.Preimage.GarblerPeerName, spec.GarblerPeerID
	if role == "evaluator" {
		peerName, peerID = envelope.Preimage.EvaluatorPeerName, spec.EvaluatorPeerID
	} else if role != "garbler" {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid private chunk role")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(publicKey, pins[peerName]) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: private chunk signer is not pinned")
	}
	payload, validity, err := jointDPBiomedicalGaussianOneDrawEncodeOutputShares(
		shares, spec.CoordinateCount)
	if err != nil {
		return zero, err
	}
	defer clear(payload)
	preimageSHA256, err := jointDPBiomedicalGaussianEnvelopePreimageSHA256(
		envelope.Preimage)
	if err != nil {
		return zero, err
	}
	outputSHA256, err := jointDPBiomedicalGaussianOneDrawOutputShareSHA256(
		preimageSHA256, role, payload, validity)
	if err != nil {
		return zero, err
	}
	receipt := jointDPBiomedicalGaussianOneDrawChunkReceipt{
		Version:                jointDPBiomedicalGaussianOneDrawChunkReceiptVersion,
		Route:                  jointDPBiomedicalGaussianWorkerRoute,
		EnvelopePreimageSHA256: preimageSHA256,
		ProductiveStreamSHA256: envelope.Preimage.ProductiveStreamSHA256,
		ReleaseInstanceID:      envelope.Preimage.ReleaseInstanceID,
		ReleaseContractSHA256:  envelope.Preimage.ReleaseContractSHA256,
		PlanSHA256:             envelope.Preimage.PlanSHA256,
		CoordinateOrderSHA256:  envelope.Preimage.CoordinateOrderSHA256,
		TotalCoordinateCount:   envelope.Preimage.TotalCoordinateCount,
		ChunkStart:             envelope.Preimage.ChunkStart,
		CoordinateCount:        envelope.Preimage.CoordinateCount,
		PeerName:               peerName, PeerID: peerID, Role: role,
		OutputShareSHA256:        outputSHA256,
		PayloadShareCount:        spec.CoordinateCount,
		ValidityXORShareIncluded: true,
		ProtectedPayloadExposed:  false,
		ValidityPredicateOpened:  false,
	}
	message, err := jointDPBiomedicalGaussianOneDrawChunkReceiptMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	return receipt, nil
}

func jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
	envelope jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	receipt jointDPBiomedicalGaussianOneDrawChunkReceipt,
	role string, shares []*big.Int,
) ([]byte, byte, error) {
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(envelope, trust)
	if err != nil {
		return nil, 0, err
	}
	pins, _, err := jointDPBiomedicalGaussianTrustPins(trust)
	if err != nil {
		return nil, 0, err
	}
	peerName, peerID := envelope.Preimage.GarblerPeerName, spec.GarblerPeerID
	if role == "evaluator" {
		peerName, peerID = envelope.Preimage.EvaluatorPeerName, spec.EvaluatorPeerID
	} else if role != "garbler" {
		return nil, 0, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid private chunk role")
	}
	preimageSHA256, err := jointDPBiomedicalGaussianEnvelopePreimageSHA256(
		envelope.Preimage)
	if err != nil {
		return nil, 0, err
	}
	payload, validity, err := jointDPBiomedicalGaussianOneDrawEncodeOutputShares(
		shares, spec.CoordinateCount)
	if err != nil {
		return nil, 0, err
	}
	wantOutput, err := jointDPBiomedicalGaussianOneDrawOutputShareSHA256(
		preimageSHA256, role, payload, validity)
	if err != nil {
		clear(payload)
		return nil, 0, err
	}
	message, err := jointDPBiomedicalGaussianOneDrawChunkReceiptMessage(receipt)
	valid := err == nil && receipt.EnvelopePreimageSHA256 == preimageSHA256 &&
		receipt.ProductiveStreamSHA256 == envelope.Preimage.ProductiveStreamSHA256 &&
		receipt.ReleaseInstanceID == envelope.Preimage.ReleaseInstanceID &&
		receipt.ReleaseContractSHA256 == envelope.Preimage.ReleaseContractSHA256 &&
		receipt.PlanSHA256 == envelope.Preimage.PlanSHA256 &&
		receipt.CoordinateOrderSHA256 == envelope.Preimage.CoordinateOrderSHA256 &&
		receipt.TotalCoordinateCount == spec.TotalCoordinateCount &&
		receipt.ChunkStart == spec.ChunkStart &&
		receipt.CoordinateCount == spec.CoordinateCount &&
		receipt.PeerName == peerName && receipt.PeerID == peerID &&
		receipt.Role == role && receipt.OutputShareSHA256 == wantOutput &&
		len(receipt.Signature) == ed25519.SignatureSize &&
		ed25519.Verify(pins[peerName], message, receipt.Signature)
	if !valid {
		clear(payload)
		return nil, 0, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: private chunk receipt verification failed")
	}
	return payload, validity, nil
}

func jointDPBiomedicalGaussianOneDrawCost(
	plan jointDPGaussianOneDrawPlanOutput, planSHA256 string,
) (jointDPBiomedicalGaussianOneDrawCostCertificate, error) {
	var zero jointDPBiomedicalGaussianOneDrawCostCertificate
	if !plan.CapabilityAvailable || plan.MaximumChunkCoordinates < 1 ||
		plan.TotalCoordinateCount < 1 || plan.SamplerMagnitudeCount < 1 ||
		!jointDPBiomedicalGaussianIsSHA256(planSHA256) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: unavailable cost certificate")
	}
	chunks := (plan.TotalCoordinateCount + plan.MaximumChunkCoordinates - 1) /
		plan.MaximumChunkCoordinates
	var aggregateGates, aggregateNonXOR, aggregateGarbled, aggregateWires int64
	var peakGates, peakNonXOR, peakGarbled, peakWires, peakCompiler int64
	for start := 0; start < plan.TotalCoordinateCount; start += plan.MaximumChunkCoordinates {
		count := plan.MaximumChunkCoordinates
		if count > plan.TotalCoordinateCount-start {
			count = plan.TotalCoordinateCount - start
		}
		_, _, _, _, gates, nonXOR, _, garbled, wires :=
			jointDPGaussianOneDrawCostProjection(plan.SamplerMagnitudeCount, count)
		aggregateGates += gates
		aggregateNonXOR += nonXOR
		aggregateGarbled += garbled
		aggregateWires += wires
		if gates > peakGates {
			peakGates = gates
		}
		if nonXOR > peakNonXOR {
			peakNonXOR = nonXOR
		}
		if garbled > peakGarbled {
			peakGarbled = garbled
		}
		if wires > peakWires {
			peakWires = wires
		}
		if wires*10 > peakCompiler {
			peakCompiler = wires * 10
		}
	}
	independentBytes := int64(plan.TotalCoordinateCount) * 16 * 2
	oneDrawPostGC := independentBytes + int64(chunks*2)
	resourceOK := peakGates <= plan.MaximumProjectedGateCount &&
		peakNonXOR <= plan.MaximumProjectedNonXORGateCount &&
		peakGarbled <= plan.MaximumProjectedGarbledTableBytes &&
		peakWires <= plan.MaximumProjectedWireLabelBytes &&
		peakCompiler <= plan.MaximumProjectedCompilerAllocationBytes
	if !resourceOK {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: cost exceeds signed resource policy")
	}
	return jointDPBiomedicalGaussianOneDrawCostCertificate{
		Version:                                     jointDPBiomedicalGaussianOneDrawCostVersion,
		PlanSHA256:                                  planSHA256,
		TotalCoordinateCount:                        plan.TotalCoordinateCount,
		CanonicalChunkCount:                         chunks,
		MaximumChunkCoordinates:                     plan.MaximumChunkCoordinates,
		SamplerMagnitudeCount:                       plan.SamplerMagnitudeCount,
		CDFComparisonsPerCoordinate:                 plan.CDFComparisonsPerCoordinate,
		CanonicalTotalCDFComparisons:                int64(plan.CDFComparisonsPerCoordinate) * int64(plan.TotalCoordinateCount),
		CDFLookupCircuitModel:                       plan.CDFLookupCircuitModel,
		SecretIndexedPublicRAMAvailable:             plan.SecretIndexedPublicRAMAvailable,
		LogarithmicCircuitSizeClaim:                 plan.LogarithmicCircuitSizeClaim,
		PeakProjectedGateCountUpper:                 peakGates,
		PeakProjectedNonXORGateCountUpper:           peakNonXOR,
		PeakProjectedGarbledTableBytesUpper:         peakGarbled,
		PeakProjectedWireLabelBytesUpper:            peakWires,
		PeakProjectedCompilerAllocationBytesUpper:   peakCompiler,
		AggregateProjectedGateCountUpper:            aggregateGates,
		AggregateProjectedNonXORGateCountUpper:      aggregateNonXOR,
		AggregateProjectedGarbledTableBytesUpper:    aggregateGarbled,
		AggregateProjectedWireLabelBytesUpper:       aggregateWires,
		MaximumProjectedGateCount:                   plan.MaximumProjectedGateCount,
		MaximumProjectedNonXORGateCount:             plan.MaximumProjectedNonXORGateCount,
		MaximumProjectedGarbledTableBytes:           plan.MaximumProjectedGarbledTableBytes,
		MaximumProjectedWireLabelBytes:              plan.MaximumProjectedWireLabelBytes,
		MaximumProjectedCompilerAllocationBytes:     plan.MaximumProjectedCompilerAllocationBytes,
		IndependentFullProtectedSharePayloadBytes:   independentBytes,
		OneDrawPostGCProtectedSharePayloadBytes:     oneDrawPostGC,
		GarbledToIndependentPayloadRatioNumerator:   fmt.Sprint(aggregateGarbled),
		GarbledToIndependentPayloadRatioDenominator: fmt.Sprint(independentBytes),
		CostProjectionIsConservative:                plan.CostProjectionIsConservative,
		ResourcePolicySatisfied:                     true,
		CapabilityAvailable:                         true,
		FallbackAutomatic:                           plan.FallbackAutomatic,
		FallbackNominalVarianceMultiplier:           plan.FallbackNominalVarianceMultiplier,
	}, nil
}

func jointDPBiomedicalGaussianOneDrawGlobalEnvelopeEqual(
	left, right jointDPBiomedicalGaussianWorkerEnvelopePreimage,
) bool {
	return left.Route == right.Route &&
		left.CapsuleID == right.CapsuleID &&
		left.ManifestSHA256 == right.ManifestSHA256 &&
		left.SchemaManifestSHA256 == right.SchemaManifestSHA256 &&
		left.WorkloadSHA256 == right.WorkloadSHA256 &&
		left.LogicalSnapshotHandleSHA256 == right.LogicalSnapshotHandleSHA256 &&
		left.PrivacyEpochSHA256 == right.PrivacyEpochSHA256 &&
		left.ReleaseInstanceID == right.ReleaseInstanceID &&
		left.ReleaseContractSHA256 == right.ReleaseContractSHA256 &&
		left.WorkerTranscriptSHA256 == right.WorkerTranscriptSHA256 &&
		left.Mechanism == right.Mechanism && left.Allocation == right.Allocation &&
		left.Adjacency == right.Adjacency && left.Epsilon == right.Epsilon &&
		left.EpsilonNumerator == right.EpsilonNumerator &&
		left.EpsilonDenominator == right.EpsilonDenominator &&
		left.Delta == right.Delta && left.DeltaNumerator == right.DeltaNumerator &&
		left.DeltaDenominator == right.DeltaDenominator &&
		left.PinsetSHA256 == right.PinsetSHA256 &&
		reflect.DeepEqual(left.CustodianPeers, right.CustodianPeers) &&
		left.CustodianCount == right.CustodianCount &&
		left.GarblerPeerName == right.GarblerPeerName &&
		left.GarblerPeerID == right.GarblerPeerID &&
		left.EvaluatorPeerName == right.EvaluatorPeerName &&
		left.EvaluatorPeerID == right.EvaluatorPeerID &&
		left.CoordinateOrderSHA256 == right.CoordinateOrderSHA256 &&
		left.LatticeTransformSHA256 == right.LatticeTransformSHA256 &&
		left.CommonLattice == right.CommonLattice &&
		left.OutputLatticeBits == right.OutputLatticeBits &&
		left.TotalCoordinateCount == right.TotalCoordinateCount &&
		reflect.DeepEqual(left.CommonLatticeUpperBounds,
			right.CommonLatticeUpperBounds) &&
		left.L2SensitivitySteps == right.L2SensitivitySteps &&
		left.SensitivityCertificateSHA == right.SensitivityCertificateSHA &&
		left.WorkerSensitivitySHA256 == right.WorkerSensitivitySHA256 &&
		left.PlanSHA256 == right.PlanSHA256 &&
		left.WorkerImplementationSHA256 == right.WorkerImplementationSHA256 &&
		left.ProductiveStreamSHA256 == right.ProductiveStreamSHA256 &&
		left.MaterializationRootSHA256 == right.MaterializationRootSHA256 &&
		left.SourceContractHandleSHA256 == right.SourceContractHandleSHA256 &&
		reflect.DeepEqual(left.ReceiptReferences, right.ReceiptReferences)
}

func jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
	envelopes []jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
) (jointDPBiomedicalGaussianOneDrawAuthority, error) {
	var zero jointDPBiomedicalGaussianOneDrawAuthority
	if len(envelopes) < 1 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: empty worker schedule")
	}
	ordered := append([]jointDPBiomedicalGaussianSignedWorkerEnvelope(nil),
		envelopes...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Preimage.ChunkStart < ordered[j].Preimage.ChunkStart
	})
	pins, _, err := jointDPBiomedicalGaussianTrustPins(trust)
	if err != nil {
		return zero, err
	}
	first := ordered[0].Preimage
	var plan jointDPGaussianOneDrawPlanOutput
	next := 0
	for index, envelope := range ordered {
		spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(envelope, trust)
		if err != nil {
			return zero, err
		}
		if spec.ChunkStart != next || spec.CoordinateCount < 1 ||
			spec.CoordinateCount > spec.Plan.MaximumChunkCoordinates {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: overlapping, missing, or oversized worker chunk")
		}
		if index == 0 {
			plan = spec.Plan
		} else if !jointDPBiomedicalGaussianOneDrawGlobalEnvelopeEqual(
			first, envelope.Preimage) || !reflect.DeepEqual(plan, spec.Plan) {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: worker chunks use different release authority")
		}
		next += spec.CoordinateCount
	}
	if next != first.TotalCoordinateCount {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: incomplete worker coordinate coverage")
	}
	planSHA256, err := jointDPBiomedicalGaussianHash(plan)
	if err != nil || planSHA256 != first.PlanSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: worker plan digest mismatch")
	}
	ledger, ok := jointDPBiomedicalGaussianReceiptByKind(
		first.ReceiptReferences, jointDPBiomedicalGaussianReceiptPrivacyLedger)
	if !ok {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: missing ledger reservation")
	}
	finalizer, ok := jointDPBiomedicalGaussianReceiptByKind(
		first.ReceiptReferences, jointDPBiomedicalGaussianReceiptFinalizer)
	if !ok {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: missing finalizer reservation")
	}
	cost, err := jointDPBiomedicalGaussianOneDrawCost(plan, planSHA256)
	if err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianOneDrawAuthority{
		preimage: first, plan: plan, planSHA256: planSHA256,
		ledger: ledger, finalizer: finalizer,
		computePeers: []string{first.GarblerPeerName, first.EvaluatorPeerName},
		pins:         pins, cost: cost,
	}, nil
}

func jointDPBiomedicalGaussianOneDrawNormalizeHandoffs(
	handoffs []jointDPBiomedicalGaussianOneDrawChunkHandoff,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
) (jointDPBiomedicalGaussianOneDrawNormalizedInput, error) {
	var zero jointDPBiomedicalGaussianOneDrawNormalizedInput
	if len(handoffs) < 1 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: empty private handoff schedule")
	}
	ordered := append([]jointDPBiomedicalGaussianOneDrawChunkHandoff(nil),
		handoffs...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Envelope.Preimage.ChunkStart <
			ordered[j].Envelope.Preimage.ChunkStart
	})
	envelopes := make([]jointDPBiomedicalGaussianSignedWorkerEnvelope,
		len(ordered))
	for index := range ordered {
		envelopes[index] = ordered[index].Envelope
	}
	authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
		envelopes, trust)
	if err != nil {
		return zero, err
	}
	chunks := make([]jointDPBiomedicalGaussianOneDrawNormalizedChunk, 0,
		len(ordered))
	garblerHash, evaluatorHash := sha256.New(), sha256.New()
	garblerOutputCommitments := make([]string, 0, len(ordered))
	evaluatorOutputCommitments := make([]string, 0, len(ordered))
	for _, handoff := range ordered {
		count := handoff.Envelope.Preimage.CoordinateCount
		garbler, garblerValidity, err :=
			jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
				handoff.Envelope, trust, handoff.Garbler, "garbler",
				handoff.GarblerShares)
		if err != nil {
			return zero, err
		}
		evaluator, evaluatorValidity, err :=
			jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
				handoff.Envelope, trust, handoff.Evaluator, "evaluator",
				handoff.EvaluatorShares)
		if err != nil {
			clear(garbler)
			return zero, err
		}
		_, _ = garblerHash.Write(garbler)
		_, _ = evaluatorHash.Write(evaluator)
		garblerOutputCommitments = append(
			garblerOutputCommitments, handoff.Garbler.OutputShareSHA256)
		evaluatorOutputCommitments = append(
			evaluatorOutputCommitments, handoff.Evaluator.OutputShareSHA256)
		chunks = append(chunks, jointDPBiomedicalGaussianOneDrawNormalizedChunk{
			start: handoff.Envelope.Preimage.ChunkStart, count: count,
			garbler: garbler, evaluator: evaluator,
			garblerValidity:   garblerValidity,
			evaluatorValidity: evaluatorValidity,
		})
	}
	garblerDigest, evaluatorDigest := garblerHash.Sum(nil), evaluatorHash.Sum(nil)
	inputDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianOneDrawDurableRecordDomain+"/input", struct {
			ReleaseInstanceID      string `json:"release_instance_id"`
			ReleaseContractSHA256  string `json:"release_contract_sha256"`
			ProductiveStreamSHA256 string `json:"productive_stream_sha256"`
			PlanSHA256             string `json:"plan_sha256"`
			GarblerPayloadSHA256   string `json:"garbler_payload_sha256"`
			EvaluatorPayloadSHA256 string `json:"evaluator_payload_sha256"`
		}{authority.preimage.ReleaseInstanceID,
			authority.preimage.ReleaseContractSHA256,
			authority.preimage.ProductiveStreamSHA256, authority.planSHA256,
			hex.EncodeToString(garblerDigest), hex.EncodeToString(evaluatorDigest)})
	clear(garblerDigest)
	clear(evaluatorDigest)
	if err != nil {
		for index := range chunks {
			clear(chunks[index].garbler)
			clear(chunks[index].evaluator)
		}
		return zero, err
	}
	validityScheduleDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianOneDrawDurableRecordDomain+"/validity-schedule", struct {
			ReleaseInstanceID          string   `json:"release_instance_id"`
			GarblerOutputCommitments   []string `json:"garbler_output_commitments"`
			EvaluatorOutputCommitments []string `json:"evaluator_output_commitments"`
		}{authority.preimage.ReleaseInstanceID,
			garblerOutputCommitments, evaluatorOutputCommitments})
	if err != nil {
		for index := range chunks {
			clear(chunks[index].garbler)
			clear(chunks[index].evaluator)
		}
		return zero, err
	}
	return jointDPBiomedicalGaussianOneDrawNormalizedInput{
		authority: authority, chunks: chunks,
		digest:           hex.EncodeToString(inputDigest[:]),
		validitySchedule: hex.EncodeToString(validityScheduleDigest[:]),
	}, nil
}

func (normalized *jointDPBiomedicalGaussianOneDrawNormalizedInput) clear() {
	for index := range normalized.chunks {
		clear(normalized.chunks[index].garbler)
		clear(normalized.chunks[index].evaluator)
	}
	normalized.chunks = nil
}

func jointDPBiomedicalGaussianOneDrawReconstruct(
	normalized jointDPBiomedicalGaussianOneDrawNormalizedInput,
) ([]string, bool, error) {
	// Check the entire private control plane first. No prefix of the vector is
	// reconstructed if any chunk failed its in-circuit bound predicate.
	for _, chunk := range normalized.chunks {
		if chunk.garblerValidity^chunk.evaluatorValidity != 1 {
			return nil, false, nil
		}
	}
	values := make([]string, 0, normalized.authority.preimage.TotalCoordinateCount)
	ringMask := exactGCMask(128)
	for _, chunk := range normalized.chunks {
		for local := 0; local < chunk.count; local++ {
			first := new(big.Int).SetBytes(chunk.garbler[local*16 : (local+1)*16])
			second := new(big.Int).SetBytes(chunk.evaluator[local*16 : (local+1)*16])
			value := new(big.Int).Add(first, second)
			value.And(value, ringMask)
			absolute := chunk.start + local
			upper, err := jointDPBiomedicalGaussianParseCanonicalInt(
				normalized.authority.preimage.CommonLatticeUpperBounds[absolute],
				"one-draw released coordinate upper bound", false)
			if err != nil || value.Cmp(upper) > 0 {
				return nil, true, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: released coordinate exceeds its certified bound")
			}
			values = append(values, value.String())
		}
	}
	if len(values) != normalized.authority.preimage.TotalCoordinateCount {
		return nil, true, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: reconstructed vector shape mismatch")
	}
	return values, true, nil
}

func jointDPBiomedicalGaussianOneDrawVectorSHA256(values []string) (string, error) {
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianOneDrawLocalReleaseDomain+"/vector", values)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianOneDrawLocalReleaseMessage(
	receipt jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt,
) ([]byte, error) {
	if receipt.Version != jointDPBiomedicalGaussianOneDrawLocalReleaseVersion ||
		receipt.Backend != jointDPBiomedicalGaussianOneDrawBackend ||
		receipt.Mechanism != jointDPGaussianOneDrawMechanism ||
		receipt.Sampler != jointDPGaussianOneDrawSampler ||
		!jointDPBiomedicalGaussianValidPeerName(receipt.PeerName) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.PeerIdentitySHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.ProductiveStreamSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.PlanSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.CoordinateOrderSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.LedgerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.FinalizerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(receipt.VectorSHA256) ||
		len(receipt.ClampedScaledValues) < 1 || receipt.OutputLatticeBits < 1 ||
		receipt.OutputLatticeBits > 62 ||
		receipt.RouteRole != jointDPBiomedicalGaussianOneDrawRouteRole ||
		receipt.PrivacyClaimScope != jointDPBiomedicalGaussianOneDrawPrivacyScope ||
		!receipt.TargetVarianceOptimal || receipt.NominalVarianceMultiplier != 1 ||
		receipt.NominalStandardDeviationFactor != "1_relative_to_one_full_draw" ||
		!receipt.LedgerAppendBeforeValidityOrRelease ||
		!receipt.ExactlyOnceRelease || receipt.SingleCommonDPVector ||
		!receipt.UnlimitedDeterministicReplay ||
		!receipt.UnlimitedPostprocessing || receipt.HistoryCanDenyOperation ||
		receipt.OperationLimit || receipt.RequestLimit ||
		receipt.OpeningsPerformed != 1 || receipt.ProductionReady ||
		!reflectStringSlicesEqual(receipt.Blockers,
			jointDPBiomedicalGaussianOneDrawReleaseBlockers) ||
		len(receipt.CommonReleaseSignature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid local durable release")
	}
	for _, value := range receipt.ClampedScaledValues {
		if _, err := jointDPBiomedicalGaussianParseCanonicalInt(
			value, "one-draw released coordinate", false); err != nil {
			return nil, err
		}
	}
	unsigned := receipt
	unsigned.Signature = nil
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianOneDrawLocalReleaseDomain, unsigned)
}

func jointDPBiomedicalGaussianOneDrawCommonFromLocal(
	authority jointDPBiomedicalGaussianOneDrawAuthority,
	receipt jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt,
) jointDPBiomedicalGaussianOneDrawCommonRelease {
	return jointDPBiomedicalGaussianOneDrawCommonRelease{
		Version: jointDPBiomedicalGaussianOneDrawCommonReleaseVersion,
		Backend: receipt.Backend, Mechanism: receipt.Mechanism,
		Sampler:                    receipt.Sampler,
		ReleaseInstanceID:          receipt.ReleaseInstanceID,
		ReleaseContractSHA256:      receipt.ReleaseContractSHA256,
		ProductiveStreamSHA256:     receipt.ProductiveStreamSHA256,
		PlanSHA256:                 receipt.PlanSHA256,
		CoordinateOrderSHA256:      receipt.CoordinateOrderSHA256,
		LedgerReservationSHA256:    receipt.LedgerReservationSHA256,
		FinalizerReservationSHA256: receipt.FinalizerReservationSHA256,
		DesignatedComputePeers:     append([]string(nil), authority.computePeers...),
		VectorSHA256:               receipt.VectorSHA256,
		ClampedScaledValues:        append([]string(nil), receipt.ClampedScaledValues...),
		OutputLatticeBits:          receipt.OutputLatticeBits,
		Epsilon:                    receipt.Epsilon, Delta: receipt.Delta,
		CoreDeltaNumerator:             receipt.CoreDeltaNumerator,
		CoreDeltaDenominator:           receipt.CoreDeltaDenominator,
		VectorTailTVUpperNumerator:     receipt.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:   receipt.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:      receipt.VectorCDFTVUpperNumerator,
		VectorCDFTVUpperDenominator:    receipt.VectorCDFTVUpperDenominator,
		VectorTotalTVUpperNumerator:    receipt.VectorTotalTVUpperNumerator,
		VectorTotalTVUpperDenominator:  receipt.VectorTotalTVUpperDenominator,
		ImplementationDeltaNumerator:   receipt.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator: receipt.ImplementationDeltaDenominator,
		RouteRole:                      receipt.RouteRole, PrivacyClaimScope: receipt.PrivacyClaimScope,
		TargetVarianceOptimal: true, NominalVarianceMultiplier: 1,
		NominalStandardDeviationFactor:      "1_relative_to_one_full_draw",
		Cost:                                receipt.Cost,
		LedgerAppendBeforeValidityOrRelease: true,
		ExactlyOnceRelease:                  true, SingleCommonDPVector: true,
		UnlimitedDeterministicReplay: true, UnlimitedPostprocessing: true,
		HistoryCanDenyOperation: false, OperationLimit: false,
		RequestLimit: false, OpeningsPerformed: 1, ProductionReady: false,
		Blockers: append([]string(nil),
			jointDPBiomedicalGaussianOneDrawReleaseBlockers...),
	}
}

func jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(
	release jointDPBiomedicalGaussianOneDrawCommonRelease,
) ([]byte, error) {
	if release.Version != jointDPBiomedicalGaussianOneDrawCommonReleaseVersion ||
		release.Backend != jointDPBiomedicalGaussianOneDrawBackend ||
		release.Mechanism != jointDPGaussianOneDrawMechanism ||
		release.Sampler != jointDPGaussianOneDrawSampler ||
		!jointDPBiomedicalGaussianIsSHA256(release.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(release.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.ProductiveStreamSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.PlanSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.CoordinateOrderSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.LedgerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.FinalizerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.VectorSHA256) ||
		len(release.DesignatedComputePeers) != 2 ||
		release.DesignatedComputePeers[0] == release.DesignatedComputePeers[1] ||
		len(release.ClampedScaledValues) < 1 || release.OutputLatticeBits < 1 ||
		release.OutputLatticeBits > 62 ||
		release.RouteRole != jointDPBiomedicalGaussianOneDrawRouteRole ||
		release.PrivacyClaimScope != jointDPBiomedicalGaussianOneDrawPrivacyScope ||
		!release.TargetVarianceOptimal || release.NominalVarianceMultiplier != 1 ||
		release.NominalStandardDeviationFactor != "1_relative_to_one_full_draw" ||
		!release.LedgerAppendBeforeValidityOrRelease ||
		!release.ExactlyOnceRelease || !release.SingleCommonDPVector ||
		!release.UnlimitedDeterministicReplay ||
		!release.UnlimitedPostprocessing || release.HistoryCanDenyOperation ||
		release.OperationLimit || release.RequestLimit ||
		release.OpeningsPerformed != 1 || release.ProductionReady ||
		!reflectStringSlicesEqual(release.Blockers,
			jointDPBiomedicalGaussianOneDrawReleaseBlockers) {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid common durable release")
	}
	unsigned := release
	unsigned.Signatures = nil
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianOneDrawCommonReleaseDomain, unsigned)
}

func jointDPBiomedicalGaussianValidateOneDrawReleasedVector(
	authority jointDPBiomedicalGaussianOneDrawAuthority,
	vectorSHA256 string, values []string,
) error {
	if len(values) != authority.preimage.TotalCoordinateCount ||
		len(authority.preimage.CommonLatticeUpperBounds) != len(values) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: released vector shape mismatch")
	}
	for index, text := range values {
		value, err := jointDPBiomedicalGaussianParseCanonicalInt(
			text, "one-draw released coordinate", false)
		upper, upperErr := jointDPBiomedicalGaussianParseCanonicalInt(
			authority.preimage.CommonLatticeUpperBounds[index],
			"one-draw coordinate upper bound", false)
		if err != nil || upperErr != nil || value.Cmp(upper) > 0 {
			return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: released coordinate exceeds its certified bound")
		}
	}
	want, err := jointDPBiomedicalGaussianOneDrawVectorSHA256(values)
	if err != nil || want != vectorSHA256 {
		return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: released vector digest mismatch")
	}
	return nil
}

func jointDPBiomedicalGaussianOneDrawReleaseMatchesAuthority(
	authority jointDPBiomedicalGaussianOneDrawAuthority,
	receipt jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt,
) bool {
	p := authority.preimage
	plan := authority.plan
	return receipt.ReleaseInstanceID == p.ReleaseInstanceID &&
		receipt.ReleaseContractSHA256 == p.ReleaseContractSHA256 &&
		receipt.ProductiveStreamSHA256 == p.ProductiveStreamSHA256 &&
		receipt.PlanSHA256 == authority.planSHA256 &&
		receipt.CoordinateOrderSHA256 == p.CoordinateOrderSHA256 &&
		receipt.LedgerReservationSHA256 == authority.ledger.SHA256 &&
		receipt.FinalizerReservationSHA256 == authority.finalizer.SHA256 &&
		receipt.OutputLatticeBits == p.OutputLatticeBits &&
		receipt.Epsilon == p.Epsilon && receipt.Delta == p.Delta &&
		receipt.CoreDeltaNumerator == plan.CoreDeltaNumerator &&
		receipt.CoreDeltaDenominator == plan.CoreDeltaDenominator &&
		receipt.VectorTailTVUpperNumerator == plan.VectorTailTVUpperNumerator &&
		receipt.VectorTailTVUpperDenominator == plan.VectorTailTVUpperDenominator &&
		receipt.VectorCDFTVUpperNumerator == plan.VectorCDFTVUpperNumerator &&
		receipt.VectorCDFTVUpperDenominator == plan.VectorCDFTVUpperDenominator &&
		receipt.VectorTotalTVUpperNumerator == plan.VectorTotalTVUpperNumerator &&
		receipt.VectorTotalTVUpperDenominator == plan.VectorTotalTVUpperDenominator &&
		receipt.ImplementationDeltaNumerator == plan.ImplementationDeltaNumerator &&
		receipt.ImplementationDeltaDenominator == plan.ImplementationDeltaDenominator &&
		reflect.DeepEqual(receipt.Cost, authority.cost)
}

func jointDPBiomedicalGaussianValidateOneDrawLocalRelease(
	authority jointDPBiomedicalGaussianOneDrawAuthority,
	receipt jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt,
) error {
	if !jointDPBiomedicalGaussianOneDrawReleaseMatchesAuthority(authority, receipt) ||
		!formalGLMPhase19Contains(authority.computePeers, receipt.PeerName) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: local release binding mismatch")
	}
	if err := jointDPBiomedicalGaussianValidateOneDrawReleasedVector(
		authority, receipt.VectorSHA256, receipt.ClampedScaledValues); err != nil {
		return err
	}
	pin := authority.pins[receipt.PeerName]
	pinDigest := sha256.Sum256(pin)
	message, err := jointDPBiomedicalGaussianOneDrawLocalReleaseMessage(receipt)
	if err != nil || receipt.PeerIdentitySHA256 != hex.EncodeToString(pinDigest[:]) ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, message, receipt.Signature) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: local release signature verification failed")
	}
	common := jointDPBiomedicalGaussianOneDrawCommonFromLocal(authority, receipt)
	commonMessage, err := jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(common)
	if err != nil || len(receipt.CommonReleaseSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, commonMessage, receipt.CommonReleaseSignature) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: common release signature verification failed")
	}
	return nil
}

func jointDPBiomedicalGaussianValidateOneDrawCommonRelease(
	envelopes []jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	release jointDPBiomedicalGaussianOneDrawCommonRelease,
) error {
	authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
		envelopes, trust)
	if err != nil {
		return err
	}
	probe := jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt{
		ReleaseInstanceID:          release.ReleaseInstanceID,
		ReleaseContractSHA256:      release.ReleaseContractSHA256,
		ProductiveStreamSHA256:     release.ProductiveStreamSHA256,
		PlanSHA256:                 release.PlanSHA256,
		CoordinateOrderSHA256:      release.CoordinateOrderSHA256,
		LedgerReservationSHA256:    release.LedgerReservationSHA256,
		FinalizerReservationSHA256: release.FinalizerReservationSHA256,
		OutputLatticeBits:          release.OutputLatticeBits,
		Epsilon:                    release.Epsilon, Delta: release.Delta,
		CoreDeltaNumerator:             release.CoreDeltaNumerator,
		CoreDeltaDenominator:           release.CoreDeltaDenominator,
		VectorTailTVUpperNumerator:     release.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:   release.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:      release.VectorCDFTVUpperNumerator,
		VectorCDFTVUpperDenominator:    release.VectorCDFTVUpperDenominator,
		VectorTotalTVUpperNumerator:    release.VectorTotalTVUpperNumerator,
		VectorTotalTVUpperDenominator:  release.VectorTotalTVUpperDenominator,
		ImplementationDeltaNumerator:   release.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator: release.ImplementationDeltaDenominator,
		Cost:                           release.Cost,
	}
	if !jointDPBiomedicalGaussianOneDrawReleaseMatchesAuthority(authority, probe) ||
		!reflect.DeepEqual(release.DesignatedComputePeers, authority.computePeers) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: common release binding mismatch")
	}
	if err := jointDPBiomedicalGaussianValidateOneDrawReleasedVector(
		authority, release.VectorSHA256, release.ClampedScaledValues); err != nil {
		return err
	}
	message, err := jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(release)
	if err != nil {
		return err
	}
	if len(release.Signatures) != len(authority.computePeers) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: common release lacks both designated signatures")
	}
	for index, peer := range authority.computePeers {
		signature := release.Signatures[index]
		if signature.Signer != peer ||
			len(signature.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(authority.pins[peer], message, signature.Signature) {
			return fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: common release signature verification failed")
		}
	}
	return nil
}

func jointDPBiomedicalGaussianPairOneDrawLocalReleases(
	envelopes []jointDPBiomedicalGaussianSignedWorkerEnvelope,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	first, second jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt,
) (jointDPBiomedicalGaussianOneDrawCommonRelease, error) {
	var zero jointDPBiomedicalGaussianOneDrawCommonRelease
	authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
		envelopes, trust)
	if err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateOneDrawLocalRelease(
		authority, first); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateOneDrawLocalRelease(
		authority, second); err != nil {
		return zero, err
	}
	byPeer := map[string]jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt{
		first.PeerName: first, second.PeerName: second,
	}
	left, leftOK := byPeer[authority.computePeers[0]]
	right, rightOK := byPeer[authority.computePeers[1]]
	if !leftOK || !rightOK || len(byPeer) != 2 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: common release lacks both designated peers")
	}
	leftCore, rightCore := left, right
	leftCore.PeerName, rightCore.PeerName = "", ""
	leftCore.PeerIdentitySHA256, rightCore.PeerIdentitySHA256 = "", ""
	leftCore.CommonReleaseSignature, rightCore.CommonReleaseSignature = nil, nil
	leftCore.Signature, rightCore.Signature = nil, nil
	if !reflect.DeepEqual(leftCore, rightCore) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: designated peers released different DP vectors")
	}
	common := jointDPBiomedicalGaussianOneDrawCommonFromLocal(authority, left)
	common.Signatures = []jointDPBiomedicalGaussianSignature{
		{Signer: authority.computePeers[0], Signature: append([]byte(nil),
			left.CommonReleaseSignature...)},
		{Signer: authority.computePeers[1], Signature: append([]byte(nil),
			right.CommonReleaseSignature...)},
	}
	if err := jointDPBiomedicalGaussianValidateOneDrawCommonRelease(
		envelopes, trust, common); err != nil {
		return zero, err
	}
	return common, nil
}

func newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
	dir, peer string, backendKey [32]byte, signer ed25519.PrivateKey,
) (*jointDPBiomedicalGaussianOneDrawDurableReleaseStore, error) {
	if !jointDPBiomedicalGaussianValidPeerName(peer) ||
		backendKey == ([32]byte{}) || len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid durable release identity")
	}
	if err := formalGLMPhase18EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	records := filepath.Join(dir, "one-draw-records")
	if err := formalGLMPhase18EnsurePrivateDir(records); err != nil {
		return nil, err
	}
	return &jointDPBiomedicalGaussianOneDrawDurableReleaseStore{
		records: records, peer: peer, key: backendKey,
		signer: append(ed25519.PrivateKey(nil), signer...),
	}, nil
}

func (store *jointDPBiomedicalGaussianOneDrawDurableReleaseStore) recordPath(
	releaseID string, create bool,
) (string, error) {
	if !jointDPBiomedicalGaussianIsSHA256(releaseID) {
		return "", fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid durable release id")
	}
	shard := filepath.Join(store.records, releaseID[:2], releaseID[2:4])
	if create {
		if err := formalGLMPhase18EnsurePrivateDir(shard); err != nil {
			return "", err
		}
	}
	return filepath.Join(shard, "release-"+releaseID+".json"), nil
}

func jointDPBiomedicalGaussianOneDrawRecordMAC(key [32]byte,
	record jointDPBiomedicalGaussianOneDrawDurableRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(jointDPBiomedicalGaussianOneDrawDurableRecordDomain))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func jointDPBiomedicalGaussianOneDrawEncodeRecord(key [32]byte,
	record jointDPBiomedicalGaussianOneDrawDurableRecord,
) ([]byte, error) {
	mac, err := jointDPBiomedicalGaussianOneDrawRecordMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func jointDPBiomedicalGaussianOneDrawDecodeRecord(key [32]byte,
	encoded []byte,
) (jointDPBiomedicalGaussianOneDrawDurableRecord, error) {
	var zero jointDPBiomedicalGaussianOneDrawDurableRecord
	if len(encoded) < 64 || len(encoded) >
		jointDPBiomedicalGaussianOneDrawMaximumRecordBytes {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid durable record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record jointDPBiomedicalGaussianOneDrawDurableRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: trailing durable record data")
	}
	want, err := jointDPBiomedicalGaussianOneDrawRecordMAC(key, record)
	if err != nil || !hmac.Equal([]byte(want), []byte(record.RecordMAC)) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: durable record authentication failed")
	}
	validState := record.State == "ledger_committed" ||
		record.State == "invalid_source" || record.State == "released"
	validPayload := (record.State == "ledger_committed" &&
		!record.ValidityChecked && record.ReleaseReceiptJSON == "") ||
		(record.State == "invalid_source" && record.ValidityChecked &&
			!record.AllChunksValid && record.ReleaseReceiptJSON == "") ||
		(record.State == "released" && record.ValidityChecked &&
			record.AllChunksValid && record.ReleaseReceiptJSON != "")
	if record.Version != jointDPBiomedicalGaussianOneDrawDurableRecordVersion ||
		!validState || !validPayload ||
		!jointDPBiomedicalGaussianValidPeerName(record.PeerName) ||
		!jointDPBiomedicalGaussianIsSHA256(record.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(record.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.ProductiveStreamSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.InputCommitmentSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			record.ValidityScheduleCommitmentSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.LedgerReservationSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(record.FinalizerReservationSHA256) ||
		!record.LedgerAppendBeforeValidityOrRelease ||
		record.HistoryCanDenyOperation || record.OperationLimit ||
		record.RequestLimit {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: invalid durable record contract")
	}
	canonical, err := jointDPBiomedicalGaussianOneDrawEncodeRecord(key, record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: non-canonical durable record")
	}
	return record, nil
}

func jointDPBiomedicalGaussianOneDrawRecordMatches(
	left, right jointDPBiomedicalGaussianOneDrawDurableRecord,
) bool {
	return left.PeerName == right.PeerName &&
		left.ReleaseInstanceID == right.ReleaseInstanceID &&
		left.ReleaseContractSHA256 == right.ReleaseContractSHA256 &&
		left.ProductiveStreamSHA256 == right.ProductiveStreamSHA256 &&
		left.InputCommitmentSHA256 == right.InputCommitmentSHA256 &&
		left.LedgerReservationSHA256 == right.LedgerReservationSHA256 &&
		left.FinalizerReservationSHA256 == right.FinalizerReservationSHA256
}

func (store *jointDPBiomedicalGaussianOneDrawDurableReleaseStore) FinalizeVector(
	handoffs []jointDPBiomedicalGaussianOneDrawChunkHandoff,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	phaseHook func(string),
) (jointDPBiomedicalGaussianOneDrawLocalRelease, error) {
	var zero jointDPBiomedicalGaussianOneDrawLocalRelease
	normalized, err := jointDPBiomedicalGaussianOneDrawNormalizeHandoffs(
		handoffs, trust)
	if err != nil {
		return zero, err
	}
	defer normalized.clear()
	authority := normalized.authority
	if !formalGLMPhase19Contains(authority.computePeers, store.peer) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: durable finalizer peer is not designated")
	}
	publicKey, ok := store.signer.Public().(ed25519.PublicKey)
	if !ok || !hmac.Equal(publicKey, authority.pins[store.peer]) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: durable finalizer signer is not pinned")
	}
	record := jointDPBiomedicalGaussianOneDrawDurableRecord{
		Version: jointDPBiomedicalGaussianOneDrawDurableRecordVersion,
		State:   "ledger_committed", PeerName: store.peer,
		ReleaseInstanceID:                   authority.preimage.ReleaseInstanceID,
		ReleaseContractSHA256:               authority.preimage.ReleaseContractSHA256,
		ProductiveStreamSHA256:              authority.preimage.ProductiveStreamSHA256,
		InputCommitmentSHA256:               normalized.digest,
		ValidityScheduleCommitmentSHA256:    normalized.validitySchedule,
		LedgerReservationSHA256:             authority.ledger.SHA256,
		FinalizerReservationSHA256:          authority.finalizer.SHA256,
		LedgerAppendBeforeValidityOrRelease: true,
		ValidityChecked:                     false, AllChunksValid: false,
		HistoryCanDenyOperation: false, OperationLimit: false,
		RequestLimit: false, ReleaseReceiptJSON: "",
	}
	path, err := store.recordPath(authority.preimage.ReleaseInstanceID, true)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	read := func() (jointDPBiomedicalGaussianOneDrawDurableRecord, error) {
		encoded, readErr := jointDPBiomedicalGaussianFullReadDurableRecord(path)
		if readErr != nil {
			return jointDPBiomedicalGaussianOneDrawDurableRecord{}, readErr
		}
		return jointDPBiomedicalGaussianOneDrawDecodeRecord(store.key, encoded)
	}
	existing, readErr := read()
	created := false
	if os.IsNotExist(readErr) {
		encoded, encodeErr := jointDPBiomedicalGaussianOneDrawEncodeRecord(
			store.key, record)
		if encodeErr != nil {
			return zero, encodeErr
		}
		created, err = jointDPBiomedicalGaussianFullCreateRecord(path, encoded)
		if err != nil {
			return zero, err
		}
		existing, err = read()
		if err != nil {
			return zero, err
		}
	} else if readErr != nil {
		return zero, readErr
	}
	if !jointDPBiomedicalGaussianOneDrawRecordMatches(existing, record) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: conflicting durable release replay")
	}
	if created && phaseHook != nil {
		phaseHook("after_ledger_append_before_validity_or_release")
	}
	if existing.State == "ledger_committed" &&
		existing.ValidityScheduleCommitmentSHA256 !=
			record.ValidityScheduleCommitmentSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: conflicting durable release replay")
	}
	values, allValid, err := jointDPBiomedicalGaussianOneDrawReconstruct(normalized)
	if err != nil {
		return zero, err
	}
	if existing.State == "invalid_source" {
		if allValid {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: conflicting durable validity replay")
		}
		return zero, &jointDPBiomedicalGaussianOneDrawInvalidSource{
			ReleaseInstanceID: authority.preimage.ReleaseInstanceID}
	}
	if existing.State == "released" {
		if !allValid {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: conflicting durable validity replay")
		}
		var receipt jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt
		if err := json.Unmarshal([]byte(existing.ReleaseReceiptJSON), &receipt); err != nil {
			return zero, err
		}
		if err := jointDPBiomedicalGaussianValidateOneDrawLocalRelease(
			authority, receipt); err != nil {
			return zero, err
		}
		if !reflect.DeepEqual(values, receipt.ClampedScaledValues) {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: durable vector replay mismatch")
		}
		return jointDPBiomedicalGaussianOneDrawLocalRelease{
			Receipt: receipt, Replayed: true,
		}, nil
	}
	if !allValid {
		existing.State = "invalid_source"
		existing.ValidityChecked = true
		existing.AllChunksValid = false
		encoded, encodeErr := jointDPBiomedicalGaussianOneDrawEncodeRecord(
			store.key, existing)
		if encodeErr != nil {
			return zero, encodeErr
		}
		if err := exactGCAtomicReplace(path, encoded); err != nil {
			return zero, err
		}
		if phaseHook != nil {
			phaseHook("after_invalid_source_durable_no_release")
		}
		return zero, &jointDPBiomedicalGaussianOneDrawInvalidSource{
			ReleaseInstanceID: authority.preimage.ReleaseInstanceID}
	}
	vectorSHA256, err := jointDPBiomedicalGaussianOneDrawVectorSHA256(values)
	if err != nil {
		return zero, err
	}
	pinDigest := sha256.Sum256(publicKey)
	plan := authority.plan
	receipt := jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt{
		Version:                    jointDPBiomedicalGaussianOneDrawLocalReleaseVersion,
		Backend:                    jointDPBiomedicalGaussianOneDrawBackend,
		Mechanism:                  jointDPGaussianOneDrawMechanism,
		Sampler:                    jointDPGaussianOneDrawSampler,
		PeerName:                   store.peer,
		PeerIdentitySHA256:         hex.EncodeToString(pinDigest[:]),
		ReleaseInstanceID:          authority.preimage.ReleaseInstanceID,
		ReleaseContractSHA256:      authority.preimage.ReleaseContractSHA256,
		ProductiveStreamSHA256:     authority.preimage.ProductiveStreamSHA256,
		PlanSHA256:                 authority.planSHA256,
		CoordinateOrderSHA256:      authority.preimage.CoordinateOrderSHA256,
		LedgerReservationSHA256:    authority.ledger.SHA256,
		FinalizerReservationSHA256: authority.finalizer.SHA256,
		VectorSHA256:               vectorSHA256,
		ClampedScaledValues:        append([]string(nil), values...),
		OutputLatticeBits:          authority.preimage.OutputLatticeBits,
		Epsilon:                    authority.preimage.Epsilon, Delta: authority.preimage.Delta,
		CoreDeltaNumerator:             plan.CoreDeltaNumerator,
		CoreDeltaDenominator:           plan.CoreDeltaDenominator,
		VectorTailTVUpperNumerator:     plan.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:   plan.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:      plan.VectorCDFTVUpperNumerator,
		VectorCDFTVUpperDenominator:    plan.VectorCDFTVUpperDenominator,
		VectorTotalTVUpperNumerator:    plan.VectorTotalTVUpperNumerator,
		VectorTotalTVUpperDenominator:  plan.VectorTotalTVUpperDenominator,
		ImplementationDeltaNumerator:   plan.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator: plan.ImplementationDeltaDenominator,
		RouteRole:                      jointDPBiomedicalGaussianOneDrawRouteRole,
		PrivacyClaimScope:              jointDPBiomedicalGaussianOneDrawPrivacyScope,
		TargetVarianceOptimal:          true, NominalVarianceMultiplier: 1,
		NominalStandardDeviationFactor:      "1_relative_to_one_full_draw",
		Cost:                                authority.cost,
		LedgerAppendBeforeValidityOrRelease: true,
		ExactlyOnceRelease:                  true, SingleCommonDPVector: false,
		UnlimitedDeterministicReplay: true, UnlimitedPostprocessing: true,
		HistoryCanDenyOperation: false, OperationLimit: false,
		RequestLimit: false, OpeningsPerformed: 1, ProductionReady: false,
		Blockers: append([]string(nil),
			jointDPBiomedicalGaussianOneDrawReleaseBlockers...),
	}
	common := jointDPBiomedicalGaussianOneDrawCommonFromLocal(authority, receipt)
	commonMessage, err := jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(common)
	if err != nil {
		return zero, err
	}
	receipt.CommonReleaseSignature = ed25519.Sign(store.signer, commonMessage)
	message, err := jointDPBiomedicalGaussianOneDrawLocalReleaseMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(store.signer, message)
	if err := jointDPBiomedicalGaussianValidateOneDrawLocalRelease(
		authority, receipt); err != nil {
		return zero, err
	}
	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		return zero, err
	}
	existing.State = "released"
	existing.ValidityChecked = true
	existing.AllChunksValid = true
	existing.ReleaseReceiptJSON = string(receiptBytes)
	encoded, err := jointDPBiomedicalGaussianOneDrawEncodeRecord(store.key, existing)
	if err != nil {
		return zero, err
	}
	if err := exactGCAtomicReplace(path, encoded); err != nil {
		return zero, err
	}
	committed, err := read()
	if err != nil || committed.State != "released" ||
		committed.ReleaseReceiptJSON != string(receiptBytes) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-one-draw: durable DP release commit failed")
	}
	if phaseHook != nil {
		phaseHook("after_dp_vector_durable")
	}
	return jointDPBiomedicalGaussianOneDrawLocalRelease{
		Receipt: receipt, Replayed: false,
	}, nil
}
