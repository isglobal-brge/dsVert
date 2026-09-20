package main

import (
	"encoding/json"
	"errors"
	"reflect"
)

// CrossGridSignedContractV1 mirrors the R canonical signed envelope. The R
// boundary owns schema/pin verification in Step 1. No Go handler accepts this
// envelope until the typed producer and its authorization gate are implemented.
type CrossGridSignedContractV1 struct {
	Version        string                    `json:"version"`
	Spec           CrossGridSpecV1           `json:"spec"`
	Artifact       CrossGridArtifactV1       `json:"artifact"`
	SourceContract CrossGridSourceContractV1 `json:"source_contract"`
	Signatures     map[string]string         `json:"signatures"`
}

type CrossGridColumnV1 struct {
	Reference string  `json:"reference"`
	Dataset   string  `json:"dataset"`
	OwnerPeer string  `json:"owner_peer"`
	Column    string  `json:"column"`
	Lower     float64 `json:"lower"`
	Upper     float64 `json:"upper"`
}

type CrossGridAlignmentV1 struct {
	Version                       string `json:"version"`
	Method                        string `json:"method"`
	AlignmentGroup                string `json:"alignment_group"`
	PublicAlignmentContractSHA256 string `json:"public_alignment_contract_sha256"`
	PublicPatientDependentHash    bool   `json:"public_patient_dependent_hash"`
}

type CrossGridSpecV1 struct {
	Version                string                       `json:"version"`
	Family                 string                       `json:"family"`
	AnalysisID             string                       `json:"analysis_id"`
	Dataset                string                       `json:"dataset"`
	SchemaSHA256           string                       `json:"schema_sha256"`
	LogicalSnapshot        json.RawMessage              `json:"logical_snapshot"`
	PeerPinsetSHA256       string                       `json:"peer_pinset_sha256"`
	Outcome                CrossGridColumnV1            `json:"outcome"`
	Predictors             map[string]CrossGridColumnV1 `json:"predictors"`
	OwnerPeer              string                       `json:"owner_peer"`
	ParticipatingPeers     []string                     `json:"participating_peers"`
	ComputationPeers       []string                     `json:"computation_peers"`
	PredictorOrder         []string                     `json:"predictor_order"`
	InputVariableOrder     []string                     `json:"input_variable_order"`
	DesignTerms            []string                     `json:"design_terms"`
	Intercept              bool                         `json:"intercept"`
	BetaGrid               [][]float64                  `json:"beta_grid"`
	BetaEncoded            [][]string                   `json:"beta_encoded"`
	CandidateOrder         []string                     `json:"candidate_order"`
	MaxOutcome             int64                        `json:"max_outcome"`
	ObservationCapacity    int64                        `json:"observation_capacity"`
	NumericGridBits        int                          `json:"numeric_grid_bits"`
	Adjacency              string                       `json:"adjacency"`
	Alignment              CrossGridAlignmentV1         `json:"alignment"`
	NumericContract        CrossGridNumericContractV1   `json:"numeric_contract"`
	Preprocessing          string                       `json:"preprocessing"`
	PredictorNormalization string                       `json:"predictor_normalization"`
	CompleteCase           string                       `json:"complete_case"`
	Sensitivity            CrossGridSensitivityV1       `json:"sensitivity"`
}

type CrossGridCandidateBoundV1 struct {
	EtaLower         float64 `json:"eta_lower"`
	EtaUpper         float64 `json:"eta_upper"`
	AbsoluteEtaBound float64 `json:"absolute_eta_bound"`
	LossBound        float64 `json:"loss_bound"`
	PerPatientCap    int64   `json:"per_patient_cap"`
}

type CrossGridSensitivityV1 struct {
	CandidateBounds      []CrossGridCandidateBoundV1 `json:"candidate_bounds"`
	MaximumCoordinates   []int64                     `json:"maximum_coordinates"`
	AdjacencyMultiplier  int                         `json:"adjacency_multiplier"`
	RawL1Sensitivity     float64                     `json:"raw_l1_sensitivity"`
	RawL2Sensitivity     float64                     `json:"raw_l2_sensitivity"`
	NaturalL1Sensitivity float64                     `json:"natural_l1_sensitivity"`
	NaturalL2Sensitivity float64                     `json:"natural_l2_sensitivity"`
}

type CrossGridTranscriptV1 struct {
	Version            string `json:"version"`
	Operation          string `json:"operation"`
	PaddedUnits        int64  `json:"padded_units"`
	CandidateCount     int    `json:"candidate_count"`
	RowBatchSize       int    `json:"row_batch_size"`
	CandidateBatchSize int    `json:"candidate_batch_size"`
	Traversal          string `json:"traversal"`
	Output             string `json:"output"`
}

type CrossGridArtifactV1 struct {
	Version                 string                 `json:"version"`
	SpecVersion             string                 `json:"spec_version"`
	SpecSHA256              string                 `json:"spec_sha256"`
	AnalysisID              string                 `json:"analysis_id"`
	OwnerPeer               string                 `json:"owner_peer"`
	ParticipatingPeers      []string               `json:"participating_peers"`
	ComputationPeers        []string               `json:"computation_peers"`
	CandidateOrder          []string               `json:"candidate_order"`
	CoordinateCount         int                    `json:"coordinate_count"`
	NumericGridBits         int                    `json:"numeric_grid_bits"`
	SourceCoordinateScaling string                 `json:"source_coordinate_scaling"`
	Sensitivity             CrossGridSensitivityV1 `json:"sensitivity"`
	NumericContractSHA256   string                 `json:"numeric_contract_sha256"`
	PrivateLayoutSHA256     string                 `json:"private_layout_sha256"`
	Transcript              CrossGridTranscriptV1  `json:"transcript"`
	ResultEvidenceRequired  bool                   `json:"result_evidence_required"`
	ImplementationState     string                 `json:"implementation_state"`
	CrossOwnerState         string                 `json:"cross_owner_state"`
}

type CrossGridSourceBlockV1 struct {
	Reference            string `json:"reference"`
	OwnerPeer            string `json:"owner_peer"`
	ValueStart           int64  `json:"value_start"`
	ValidityStart        int64  `json:"validity_start"`
	Length               int64  `json:"length"`
	ValueFractionBits    int    `json:"value_fraction_bits"`
	ValueEncoding        string `json:"value_encoding"`
	ValueMaximum         int64  `json:"value_maximum"`
	ValidityFractionBits int    `json:"validity_fraction_bits"`
	ValidityMaximum      int    `json:"validity_maximum"`
}

type CrossGridPrivateLayoutV1 struct {
	Version                  string                   `json:"version"`
	RingBits                 int                      `json:"ring_bits"`
	RecordBytes              int                      `json:"record_bytes"`
	ReleaseCoordinateCount   int                      `json:"release_coordinate_count"`
	ReleasePrefixSourceRule  string                   `json:"release_prefix_source_rule"`
	PrivateStart             int64                    `json:"private_start"`
	PaddingCoordinates       int64                    `json:"padding_coordinates"`
	PaddingRule              string                   `json:"padding_rule"`
	PaddedUnits              int64                    `json:"padded_units"`
	PaddingValue             int                      `json:"padding_value"`
	PaddingValidity          int                      `json:"padding_validity"`
	BlockOrder               string                   `json:"block_order"`
	Blocks                   []CrossGridSourceBlockV1 `json:"blocks"`
	TransportCoordinateCount int64                    `json:"transport_coordinate_count"`
}

type CrossGridSourceContractV1 struct {
	Version               string                   `json:"version"`
	Purpose               string                   `json:"purpose"`
	SpecSHA256            string                   `json:"spec_sha256"`
	ArtifactSHA256        string                   `json:"artifact_sha256"`
	SchemaSHA256          string                   `json:"schema_sha256"`
	LogicalSnapshot       json.RawMessage          `json:"logical_snapshot"`
	PeerPinsetSHA256      string                   `json:"peer_pinset_sha256"`
	SourcePeers           []string                 `json:"source_peers"`
	Recipients            []string                 `json:"recipients"`
	Alignment             CrossGridAlignmentV1     `json:"alignment"`
	AlignmentSharing      string                   `json:"alignment_sharing"`
	NumericContractSHA256 string                   `json:"numeric_contract_sha256"`
	PrivateLayout         CrossGridPrivateLayoutV1 `json:"private_layout"`
}

const (
	CrossGridBinomialSpecV1      = "binomial_grid_cross_v1"
	CrossGridPoissonSpecV1       = "poisson_grid_cross_v1"
	CrossGridBinomialArtifactV1  = "bounded-binomial-cross-likelihood-grid-v1"
	CrossGridPoissonArtifactV1   = "bounded-poisson-cross-likelihood-grid-v1"
	CrossGridSourceVersionV1     = "dsvert-biomedical-capsule-source-contract-v6-cross-grid-xor-alignment"
	CrossGridSourcePurposeV1     = "biomedical_capsule_ring128_cross_grid_inputs_and_release_shares_only"
	CrossGridCertificateSHA256V1 = "887fdf3eb38528bde7497580ba90b13d187bee94da54d67fd2c55e813565e1d8"
	CrossGridProfileIdentityV1   = "cross-grid-chebyshev-q64-softplus256-exp32-v1"
	CrossGridProfileSHA256V1     = "748900bb7f0d4d1026ba5e9b162bfb16e45e306033851dfc203c2461a6a78e4f"
	CrossGridEvaluationOrderV1   = "dot_exact_f100_to_q64;eta_div17_q64;binomial_softplus_clenshaw256_then_binary_outcome_mux;poisson_exp_quarter_clenshaw32_then_square_then_square_then_integer_outcome_product_then_private_log_factorial_lookup;validity_mux;clamp_q64;quantize_g;sums"
)

// CrossGridNumericContractV1 freezes the public integer circuit ABI. It is not
// an execution command or release authorization. No existing route uses it.
type CrossGridNumericContractV1 struct {
	Version                 string                     `json:"version"`
	ProfileIdentity         string                     `json:"profile_identity"`
	ProfileSHA256           string                     `json:"profile_sha256"`
	CertificateSHA256       string                     `json:"certificate_sha256"`
	InputFractionBits       int                        `json:"input_fraction_bits"`
	CoefficientFractionBits int                        `json:"coefficient_fraction_bits"`
	CoefficientEncoding     string                     `json:"coefficient_encoding"`
	NonlinearFractionBits   int                        `json:"nonlinear_fraction_bits"`
	ArithmeticWidthBits     int                        `json:"arithmetic_width_bits"`
	OutputGridBitsRange     [2]int                     `json:"output_grid_bits_range"`
	PredictorCountRange     [2]int                     `json:"predictor_count_range"`
	MaxCoefficientAbsolute  int                        `json:"max_coefficient_absolute"`
	MaxCoefficientL1        int                        `json:"max_coefficient_l1"`
	MaxOutcome              int                        `json:"max_outcome"`
	EtaDomain               [2]int                     `json:"eta_domain"`
	RoundingRule            string                     `json:"rounding_rule"`
	EvaluationOrder         string                     `json:"evaluation_order"`
	PerOperationBounds      CrossGridOperationBoundsV1 `json:"per_operation_bounds"`
	CertifiedUniformError   string                     `json:"certified_uniform_error"`
	CertifiedEtaError       string                     `json:"certified_eta_error"`
}

type CrossGridOperationBoundsV1 struct {
	SourceFeatureAbsLtPow2      int    `json:"source_feature_abs_lt_pow2"`
	PublicBetaAbsLtPow2         int    `json:"public_beta_abs_lt_pow2"`
	DotRawAbsLtPow2             int    `json:"dot_raw_abs_lt_pow2"`
	EtaQ64AbsLtPow2             int    `json:"eta_q64_abs_lt_pow2"`
	ClenshawStateAbsLtPow2      int    `json:"clenshaw_state_abs_lt_pow2"`
	ClenshawRawProductAbsLtPow2 int    `json:"clenshaw_raw_product_abs_lt_pow2"`
	ExpSquareRawAbsLtPow2       int    `json:"exp_square_raw_abs_lt_pow2"`
	LossQ64AbsLtPow2            int    `json:"loss_q64_abs_lt_pow2"`
	ReleasedIntegerMax          string `json:"released_integer_max"`
}

func crossGridNumericContractV1(family string) (CrossGridNumericContractV1, error) {
	if family != "binomial" && family != "poisson" {
		return CrossGridNumericContractV1{}, errors.New("cross-grid contract rejected")
	}
	n := CrossGridNumericContractV1{
		Version: "cross-grid-public-numeric-contract-v1", ProfileIdentity: CrossGridProfileIdentityV1,
		ProfileSHA256: CrossGridProfileSHA256V1, CertificateSHA256: CrossGridCertificateSHA256V1, InputFractionBits: 50,
		CoefficientFractionBits: 50, CoefficientEncoding: "signed_decimal_integer_v1",
		NonlinearFractionBits: 64, ArithmeticWidthBits: 192,
		OutputGridBitsRange: [2]int{8, 18}, PredictorCountRange: [2]int{1, 16},
		MaxCoefficientAbsolute: 8, MaxCoefficientL1: 16, MaxOutcome: 1,
		EtaDomain: [2]int{-17, 17}, RoundingRule: "nearest_ties_to_even",
		EvaluationOrder:       CrossGridEvaluationOrderV1,
		PerOperationBounds:    CrossGridOperationBoundsV1{51, 54, 105, 69, 89, 155, 155, 90, "9007199254740991"},
		CertifiedUniformError: "0.00000003242", CertifiedEtaError: "0.000000000000014655",
	}
	if family == "poisson" {
		n.MaxOutcome = 1024
		n.CertifiedUniformError = "0.0000001342"
	}
	return n, nil
}

func crossGridValidateNumericContractV1(family string, n CrossGridNumericContractV1) error {
	expected, err := crossGridNumericContractV1(family)
	if err != nil || !reflect.DeepEqual(n, expected) {
		return errors.New("cross-grid contract rejected")
	}
	return nil
}
