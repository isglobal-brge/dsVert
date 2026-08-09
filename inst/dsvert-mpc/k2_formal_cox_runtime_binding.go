package main

// Purpose-bound Cox binding for the common one-draw Gaussian control plane.
// The common sampler/finalizer previously decoded only formal-GLM bindings.
// This dispatcher preserves that contract byte-for-byte and admits Cox only
// under a distinct domain and schema, preventing cross-protocol type confusion.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

const (
	formalCoxRuntimeReleaseVersion     = "dsvert-formal-cox-runtime-release-binding-v1"
	formalCoxRuntimeReleaseDomain      = "dsVert/formal-cox/runtime-release-binding/v1"
	formalCoxRuntimeSensitivityVersion = "dsvert-formal-cox-runtime-sensitivity-certificate-v1"
	formalCoxRuntimeSensitivityStatus  = "machine_proven_implemented_integer_lattice_bound_v1"
	formalCoxRuntimeSensitivityProof   = "positive_weight_bounded_score_plus_exact_floor_error_adaptive_l2_v1"
)

type jointDPGaussianOneDrawReleaseBindingView struct {
	CapsuleID                   string
	ManifestSHA256              string
	SchemaManifestSHA256        string
	WorkloadSHA256              string
	ReleaseInstanceID           string
	FinalReceiptPairSHA256      string
	Adjacency                   string
	CoordinateOrderSHA256       string
	QuantizationSHA256          string
	GarblerPeerName             string
	GarblerPeerID               string
	EvaluatorPeerName           string
	EvaluatorPeerID             string
	ShiftedUpperBounds          []string
	SnapshotSHA256              string
	SourceFanInTranscriptSHA256 string
	SensitivityStatusAllowed    bool
}

func jointDPGaussianOneDrawReleaseBindingDomainAllowed(domain string) bool {
	return domain == formalGLMPhase16ReleaseDomain ||
		domain == formalCoxRuntimeReleaseDomain
}

func jointDPGaussianOneDrawReleaseBindingViewFromPolicy(
	policy jointDPGaussianOneDrawWorkerPolicy,
) (jointDPGaussianOneDrawReleaseBindingView, error) {
	var zero jointDPGaussianOneDrawReleaseBindingView
	if err := jointDPGaussianOneDrawValidateReleaseBinding(policy); err != nil {
		return zero, err
	}
	switch policy.ReleaseBindingDomain {
	case formalGLMPhase16ReleaseDomain:
		var binding formalGLMPhase16ReleaseBinding
		if err := json.Unmarshal(
			[]byte(policy.ReleaseBindingCanonicalJSON), &binding); err != nil {
			return zero, err
		}
		return jointDPGaussianOneDrawReleaseBindingView{
			CapsuleID:              binding.CapsuleID,
			ManifestSHA256:         binding.ManifestSHA256,
			SchemaManifestSHA256:   binding.SchemaManifestSHA256,
			WorkloadSHA256:         binding.WorkloadSHA256,
			ReleaseInstanceID:      binding.ReleaseInstanceID,
			FinalReceiptPairSHA256: binding.FinalReceiptPairSHA256,
			Adjacency:              binding.Adjacency,
			CoordinateOrderSHA256:  binding.CoordinateOrderSHA256,
			QuantizationSHA256:     binding.QuantizationSHA256,
			GarblerPeerName:        binding.GarblerPeerName,
			GarblerPeerID:          binding.GarblerPeerID,
			EvaluatorPeerName:      binding.EvaluatorPeerName,
			EvaluatorPeerID:        binding.EvaluatorPeerID,
			ShiftedUpperBounds: append([]string(nil),
				binding.ShiftedUpperBounds...),
			SnapshotSHA256:              binding.SnapshotSHA256,
			SourceFanInTranscriptSHA256: binding.SourceFanInTranscriptSHA256,
			SensitivityStatusAllowed:    jointDPBiomedicalGaussianWorkerSensitivityStatusAllowed(binding),
		}, nil
	case formalCoxRuntimeReleaseDomain:
		var binding formalCoxRuntimeReleaseBinding
		if err := json.Unmarshal(
			[]byte(policy.ReleaseBindingCanonicalJSON), &binding); err != nil {
			return zero, err
		}
		return jointDPGaussianOneDrawReleaseBindingView{
			CapsuleID:              binding.CapsuleID,
			ManifestSHA256:         binding.ManifestSHA256,
			SchemaManifestSHA256:   binding.SchemaManifestSHA256,
			WorkloadSHA256:         binding.WorkloadSHA256,
			ReleaseInstanceID:      binding.ReleaseInstanceID,
			FinalReceiptPairSHA256: binding.FinalReceiptPairSHA256,
			Adjacency:              binding.Adjacency,
			CoordinateOrderSHA256:  binding.CoordinateOrderSHA256,
			QuantizationSHA256:     binding.QuantizationSHA256,
			GarblerPeerName:        binding.GarblerPeerName,
			GarblerPeerID:          binding.GarblerPeerID,
			EvaluatorPeerName:      binding.EvaluatorPeerName,
			EvaluatorPeerID:        binding.EvaluatorPeerID,
			ShiftedUpperBounds: append([]string(nil),
				binding.ShiftedUpperBounds...),
			SnapshotSHA256:              binding.SnapshotSHA256,
			SourceFanInTranscriptSHA256: binding.SourceFanInTranscriptSHA256,
			SensitivityStatusAllowed: binding.SensitivityCertificate.Status ==
				formalCoxRuntimeSensitivityStatus,
		}, nil
	default:
		return zero, fmt.Errorf("unsupported one-draw release-binding domain")
	}
}

type formalCoxRuntimeSensitivityCertificate struct {
	Version                        string `json:"version"`
	Status                         string `json:"status"`
	Norm                           string `json:"norm"`
	SelectedProof                  string `json:"selected_proof"`
	SelectedBoundSteps             string `json:"selected_bound_steps"`
	ScoreSensitivitySteps          string `json:"score_sensitivity_steps"`
	Iterations                     int    `json:"iterations"`
	CovariateCount                 int    `json:"covariate_count"`
	NoiseCoordinates               int    `json:"noise_coordinates"`
	RiskMeanRoundingPerCoordinate  string `json:"risk_mean_rounding_per_coordinate"`
	NormalizedRoundingL2Steps      string `json:"normalized_rounding_l2_steps"`
	FiniteSupportTransferToDelta   bool   `json:"finite_support_transfer_to_delta"`
	ClientSensitivityOverrideUsed  bool   `json:"client_sensitivity_override_used"`
	ImplementedArithmeticCertified bool   `json:"implemented_arithmetic_certified"`
}

type formalCoxRuntimeReleaseBinding struct {
	Version                      string                                 `json:"version"`
	PolicySHA256                 string                                 `json:"policy_sha256"`
	CapsuleID                    string                                 `json:"capsule_id"`
	ManifestSHA256               string                                 `json:"manifest_sha256"`
	SchemaManifestSHA256         string                                 `json:"schema_manifest_sha256"`
	WorkloadSHA256               string                                 `json:"workload_sha256"`
	SnapshotSHA256               string                                 `json:"snapshot_sha256"`
	SourceFanInTranscriptSHA256  string                                 `json:"source_fan_in_transcript_sha256"`
	LedgerOpeningTokenSetSHA256  string                                 `json:"ledger_opening_token_set_sha256"`
	ReleaseInstanceID            string                                 `json:"release_instance_id"`
	ReleaseContractSHA256        string                                 `json:"release_contract_sha256"`
	FinalReceiptPairSHA256       string                                 `json:"final_receipt_pair_sha256"`
	Adjacency                    string                                 `json:"adjacency"`
	Mechanism                    string                                 `json:"mechanism"`
	Allocation                   string                                 `json:"allocation"`
	Epsilon                      string                                 `json:"epsilon"`
	AllocatedDelta               string                                 `json:"allocated_delta"`
	CommonRingBits               int                                    `json:"common_ring_bits"`
	OutputLatticeBits            int                                    `json:"output_lattice_bits"`
	CoordinateCount              int                                    `json:"coordinate_count"`
	CoordinateOrderSHA256        string                                 `json:"coordinate_order_sha256"`
	QuantizationSHA256           string                                 `json:"quantization_sha256"`
	ShiftedUpperBounds           []string                               `json:"shifted_upper_bounds"`
	SensitivitySteps             string                                 `json:"sensitivity_steps"`
	SensitivityNorm              string                                 `json:"sensitivity_norm"`
	SensitivityProof             string                                 `json:"sensitivity_proof"`
	SensitivityCertificateKind   string                                 `json:"sensitivity_certificate_kind"`
	SensitivityCertificateSHA256 string                                 `json:"sensitivity_certificate_sha256"`
	SensitivityCertificate       formalCoxRuntimeSensitivityCertificate `json:"sensitivity_certificate"`
	NumericCertificateSHA256     string                                 `json:"numeric_certificate_sha256"`
	NumericCertificate           formalCoxRuntimeNumericCertificate     `json:"numeric_certificate"`
	PinsetSHA256                 string                                 `json:"pinset_sha256"`
	CustodianCount               int                                    `json:"custodian_count"`
	GarblerPeerName              string                                 `json:"garbler_peer_name"`
	GarblerPeerID                string                                 `json:"garbler_peer_id"`
	EvaluatorPeerName            string                                 `json:"evaluator_peer_name"`
	EvaluatorPeerID              string                                 `json:"evaluator_peer_id"`
	GarblerCommitmentContext     string                                 `json:"garbler_commitment_context"`
	GarblerSeedCommitment        string                                 `json:"garbler_seed_commitment"`
	EvaluatorCommitmentContext   string                                 `json:"evaluator_commitment_context"`
	EvaluatorSeedCommitment      string                                 `json:"evaluator_seed_commitment"`
	OpeningCount                 int                                    `json:"opening_count"`
	ExactIntermediateOpenings    int                                    `json:"exact_intermediate_openings"`
	ProductionReady              bool                                   `json:"production_ready"`
	BindingSHA256                string                                 `json:"binding_sha256"`
}

func formalCoxRuntimeSensitivityDigest(
	certificate formalCoxRuntimeSensitivityCertificate,
) (string, error) {
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return "", err
	}
	digest := formalCoxSHA256Domain("dsVert/formal-cox/runtime-sensitivity/v1|", encoded)
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxRuntimeReleaseBindingPreimage(
	binding formalCoxRuntimeReleaseBinding,
) ([]byte, error) {
	binding.BindingSHA256 = ""
	return json.Marshal(binding)
}

func formalCoxRuntimeReleaseBindingDigest(
	binding formalCoxRuntimeReleaseBinding,
) (string, error) {
	encoded, err := formalCoxRuntimeReleaseBindingPreimage(binding)
	if err != nil {
		return "", err
	}
	digest := formalCoxSHA256Domain(formalCoxRuntimeReleaseDomain+"|", encoded)
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxValidateRuntimeReleaseBinding(
	policy jointDPGaussianOneDrawWorkerPolicy,
) error {
	if policy.ReleaseBindingDomain != formalCoxRuntimeReleaseDomain ||
		len(policy.ReleaseBindingCanonicalJSON) == 0 ||
		len(policy.ReleaseBindingCanonicalJSON) >
			jointDPGaussianOneDrawMaxBindingBytes {
		return fmt.Errorf("formal-cox: invalid runtime release-binding preimage")
	}
	decoder := json.NewDecoder(bytes.NewReader(
		[]byte(policy.ReleaseBindingCanonicalJSON)))
	decoder.DisallowUnknownFields()
	var binding formalCoxRuntimeReleaseBinding
	if err := decoder.Decode(&binding); err != nil {
		return fmt.Errorf("formal-cox: decode runtime release binding: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-cox: trailing runtime release binding")
	}
	canonical, err := formalCoxRuntimeReleaseBindingPreimage(binding)
	if err != nil || binding.BindingSHA256 != "" ||
		!bytes.Equal(canonical, []byte(policy.ReleaseBindingCanonicalJSON)) {
		return fmt.Errorf("formal-cox: non-canonical runtime release binding")
	}
	digest, err := formalCoxRuntimeReleaseBindingDigest(binding)
	if err != nil || digest != policy.ReleaseBindingSHA256 ||
		digest != policy.CrossSignedPolicySHA256 {
		return fmt.Errorf("formal-cox: runtime release-binding digest mismatch")
	}
	certificateDigest, err := formalCoxRuntimeSensitivityDigest(
		binding.SensitivityCertificate)
	if err != nil {
		return err
	}
	numericCertificateDigest, err := formalCoxRuntimeNumericCertificateSHA256(
		binding.NumericCertificate)
	if err != nil {
		return err
	}
	hashes := []string{
		binding.PolicySHA256, binding.CapsuleID, binding.ManifestSHA256,
		binding.SchemaManifestSHA256, binding.WorkloadSHA256,
		binding.SnapshotSHA256, binding.SourceFanInTranscriptSHA256,
		binding.LedgerOpeningTokenSetSHA256,
		binding.ReleaseInstanceID, binding.ReleaseContractSHA256,
		binding.FinalReceiptPairSHA256, binding.CoordinateOrderSHA256,
		binding.QuantizationSHA256, binding.SensitivityCertificateSHA256,
		binding.NumericCertificateSHA256,
		binding.PinsetSHA256, binding.GarblerCommitmentContext,
		binding.GarblerSeedCommitment, binding.EvaluatorCommitmentContext,
		binding.EvaluatorSeedCommitment,
	}
	for _, value := range hashes {
		if !formalCoxIsSHA256(value) {
			return fmt.Errorf("formal-cox: invalid runtime release commitment")
		}
	}
	certificate := binding.SensitivityCertificate
	if binding.Version != formalCoxRuntimeReleaseVersion ||
		binding.Mechanism != jointDPGaussianOneDrawMechanism ||
		binding.Allocation != jointDPGaussianOneDrawAllocation ||
		binding.Epsilon != policy.Epsilon ||
		binding.AllocatedDelta != policy.AllocatedDelta ||
		binding.CommonRingBits != 128 ||
		binding.OutputLatticeBits != policy.OutputLatticeBits ||
		binding.CoordinateCount != policy.TotalCoordinateCount ||
		binding.SensitivitySteps != policy.L2SensitivitySteps ||
		binding.SensitivityNorm != "l2" ||
		binding.SensitivityProof != formalCoxRuntimeSensitivityProof ||
		binding.SensitivityCertificateKind !=
			jointDPGaussianOneDrawSensitivityCertificateKind ||
		binding.SensitivityCertificateKind !=
			policy.L2SensitivityCertificateKind ||
		binding.SensitivityCertificateSHA256 != certificateDigest ||
		certificateDigest != policy.L2SensitivityCertificateSHA256 ||
		binding.NumericCertificateSHA256 != numericCertificateDigest ||
		binding.NumericCertificate.PolicySHA256 != binding.PolicySHA256 ||
		binding.NumericCertificate.FracBits != binding.OutputLatticeBits ||
		binding.NumericCertificate.ProductionReady ||
		binding.NumericCertificate.EndToEndNumericCertified ||
		binding.NumericCertificate.ContinuousCoxTrajectoryCertified ||
		binding.NumericCertificate.OptimizerDistanceCertified ||
		binding.NumericCertificate.DataDependentIdentificationOpened ||
		binding.NumericCertificate.ConvergenceInferred ||
		certificate.Version != formalCoxRuntimeSensitivityVersion ||
		certificate.Status != formalCoxRuntimeSensitivityStatus ||
		certificate.Norm != "l2" ||
		certificate.SelectedProof != binding.SensitivityProof ||
		certificate.SelectedBoundSteps != binding.SensitivitySteps ||
		certificate.NoiseCoordinates != binding.CoordinateCount ||
		!certificate.FiniteSupportTransferToDelta ||
		certificate.ClientSensitivityOverrideUsed ||
		!certificate.ImplementedArithmeticCertified ||
		binding.ReleaseContractSHA256 != policy.TranscriptHash ||
		binding.FinalReceiptPairSHA256 != binding.ReleaseContractSHA256 ||
		binding.PinsetSHA256 != policy.PinsetSHA256 ||
		binding.CustodianCount != policy.CustodianCount ||
		binding.GarblerPeerID != policy.GarblerPeerID ||
		binding.EvaluatorPeerID != policy.EvaluatorPeerID ||
		binding.GarblerCommitmentContext != policy.GarblerCommitmentContext ||
		binding.EvaluatorCommitmentContext !=
			policy.EvaluatorCommitmentContext ||
		binding.GarblerSeedCommitment != policy.GarblerSeedCommitment ||
		binding.EvaluatorSeedCommitment != policy.EvaluatorSeedCommitment ||
		binding.OpeningCount != 1 || binding.ExactIntermediateOpenings != 0 ||
		binding.ProductionReady ||
		len(binding.ShiftedUpperBounds) != policy.TotalCoordinateCount {
		return fmt.Errorf("formal-cox: runtime release authority mismatch")
	}
	for local := 0; local < policy.CoordinateCount; local++ {
		absolute := policy.ChunkStart + local
		if policy.ScaleShifts[local] != 0 ||
			policy.RawUpperBounds[local] != binding.ShiftedUpperBounds[absolute] {
			return fmt.Errorf("formal-cox: runtime chunk geometry mismatch")
		}
	}
	if _, err := jointDPParseDecimalRat(binding.Epsilon,
		"formal Cox runtime epsilon", false); err != nil {
		return err
	}
	delta, err := jointDPParseDecimalRat(binding.AllocatedDelta,
		"formal Cox runtime delta", false)
	if err != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return fmt.Errorf("formal-cox: invalid runtime delta")
	}
	for _, upper := range binding.ShiftedUpperBounds {
		if _, err := jointDPVectorParseInt(
			upper, "formal Cox runtime upper bound", false); err != nil {
			return err
		}
	}
	return nil
}

// formalCoxSHA256Domain avoids reusing JSON helper domains that have different
// canonicalization contracts.
func formalCoxSHA256Domain(domain string, value []byte) [32]byte {
	return sha256.Sum256(append([]byte(domain), value...))
}
