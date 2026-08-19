package main

// Canonical pre-sampler guard for the internal blockwise Cox kernel. The
// canonical artifact is scientific/DP identity only. It deliberately excludes
// execution runs, physical block geometry, transport tickets and receipts.
// This file registers no command, capability, opening or publication route.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	formalCoxBlockwiseStickyArtifactVersion = "dsvert-formal-cox-blockwise-canonical-artifact-v1"
	formalCoxBlockwiseStickyArtifactPurpose = "formal_cox_canonical_scientific_dp_artifact_v1"
	formalCoxBlockwiseStickyArtifactDomain  = "dsVert/formal-cox/blockwise-sticky/artifact/v1"

	formalCoxBlockwiseSamplerContractVersion = "dsvert-formal-cox-blockwise-sampler-contract-v1"
	formalCoxBlockwiseSamplerContractPurpose = "formal_cox_canonical_artifact_sampler_v1"
	formalCoxBlockwiseSamplerContractDomain  = "dsVert/formal-cox/blockwise-sticky/sampler/v1"
	// SamplerMode versions the semantic seed-stream/sign/CDF mapping. A
	// backend-only rewrite keeps it; any mapping change must advance it.
	formalCoxBlockwiseSamplerMode = "one_draw_finite_discrete_gaussian_v1"

	formalCoxBlockwiseSamplerGuardVersion  = "dsvert-formal-cox-blockwise-sampler-guard-v1"
	formalCoxBlockwiseSamplerGuardMaxBytes = 256 << 10

	formalCoxBlockwiseGuardedNoiseVersion = "dsvert-formal-cox-blockwise-guarded-noise-v1"
	formalCoxBlockwiseGuardedNoisePurpose = "formal_cox_guarded_iteration_noise_v1"
)

type formalCoxBlockwiseStickyAuthority struct {
	Role     string `json:"role"`
	PeerName string `json:"peer_name"`
	PeerID   string `json:"peer_id"`
}

// formalCoxBlockwiseStickyArtifact is computable before a sampler is invoked.
// ScientificPlanSHA256 commits only to the explicit scientific projection
// below, so execution and transport upgrades cannot create fresh randomness.
type formalCoxBlockwiseStickyArtifact struct {
	Version                     string                              `json:"version"`
	Purpose                     string                              `json:"purpose"`
	ScientificArtifactSHA256    string                              `json:"scientific_artifact_sha256"`
	FormulaColumnBindingsSHA256 string                              `json:"formula_column_bindings_sha256"`
	CohortSnapshotSHA256        string                              `json:"cohort_snapshot_sha256"`
	ScientificPlanSHA256        string                              `json:"scientific_plan_sha256"`
	DPPlanSHA256                string                              `json:"dp_plan_sha256"`
	BoundsSHA256                string                              `json:"bounds_sha256"`
	GridSHA256                  string                              `json:"grid_sha256"`
	PinsetSHA256                string                              `json:"pinset_sha256"`
	CustodianPeers              []string                            `json:"custodian_peers"`
	CustodianCount              int                                 `json:"custodian_count"`
	NoiseAuthorities            []formalCoxBlockwiseStickyAuthority `json:"noise_authorities"`
	Adjacency                   string                              `json:"adjacency"`
	PrivacyUnit                 string                              `json:"privacy_unit"`
	EntryMode                   string                              `json:"entry_mode"`
	Ties                        string                              `json:"ties"`
	Mechanism                   string                              `json:"mechanism"`
	Allocation                  string                              `json:"allocation"`
	EpsilonRational             string                              `json:"epsilon_rational"`
	DeltaRational               string                              `json:"delta_rational"`
	SensitivitySteps            string                              `json:"l2_sensitivity_steps"`
	Alpha                       string                              `json:"alpha"`
	Ridge                       string                              `json:"ridge"`
	Iterations                  int                                 `json:"iterations"`
	CovariateCount              int                                 `json:"covariate_count"`
	NoiseCoordinateCount        int                                 `json:"noise_coordinate_count"`
	FractionBits                int                                 `json:"fraction_bits"`
	ReductionOrder              string                              `json:"reduction_order"`
	Truncation                  string                              `json:"truncation"`
	Projection                  string                              `json:"projection"`
	ProductionReady             bool                                `json:"-"`
}

// formalCoxBlockwiseCanonicalScientificPlan is deliberately not embedded in,
// nor copied from, formalCoxPhase1Policy. Every field here is part of the
// scientific query or output contract. Policy/compiler versions, circuit input
// layout, sharing/transport encodings and sampler chunking are operational.
type formalCoxBlockwiseCanonicalScientificPlan struct {
	ScientificArtifactSHA256    string   `json:"scientific_artifact_sha256"`
	FormulaColumnBindingsSHA256 string   `json:"formula_column_bindings_sha256"`
	CohortSnapshotSHA256        string   `json:"cohort_snapshot_sha256"`
	PinsetSHA256                string   `json:"pinset_sha256"`
	ExpTableSHA256              string   `json:"exp_table_sha256"`
	CustodianPeers              []string `json:"custodian_peers"`
	ComputePeers                []string `json:"compute_peers"`
	Adjacency                   string   `json:"adjacency"`
	EntryMode                   string   `json:"entry_mode"`
	// Capacity is the declared denominator of every optimizer update, not
	// physical block padding; changing it changes the fitted beta trajectory.
	Capacity           int      `json:"capacity"`
	CovariateCount     int      `json:"covariate_count"`
	GridTickCount      int      `json:"grid_tick_count"`
	Iterations         int      `json:"iterations"`
	FractionBits       int      `json:"fraction_bits"`
	XLower             []string `json:"x_lower"`
	XUpper             []string `json:"x_upper"`
	CovariateL2Bound   string   `json:"covariate_l2_bound"`
	BetaL2Bound        string   `json:"beta_l2_bound"`
	MinimumAtRisk      int      `json:"minimum_at_risk"`
	Alpha              string   `json:"alpha"`
	Ridge              string   `json:"ridge"`
	EpsilonRational    string   `json:"epsilon_rational"`
	DeltaRational      string   `json:"delta_rational"`
	NoiseBound         string   `json:"noise_bound"`
	ExpKnots           []string `json:"exp_knots"`
	ExpValues          []string `json:"exp_values"`
	ExpErrorUpper      string   `json:"exp_error_upper"`
	ExpCertificateBits int      `json:"exp_certificate_bits"`
	Ties               string   `json:"ties"`
	PrivacyUnit        string   `json:"privacy_unit"`
	ReductionOrder     string   `json:"reduction_order"`
	Truncation         string   `json:"truncation"`
	Projection         string   `json:"projection"`
	Output             string   `json:"output"`
}

// formalCoxBlockwiseCanonicalDPPlan contains the numerical DP contract, not
// its implementation evidence. Backend/sampler implementation labels, proof
// prose, status flags and resource/chunk projections remain external gates;
// the semantic sampler mapping version is committed by NoiseLawSHA256.
type formalCoxBlockwiseCanonicalDPPlan struct {
	EpsilonRational                string `json:"epsilon_rational"`
	DeltaRational                  string `json:"delta_rational"`
	Adjacency                      string `json:"adjacency"`
	Iterations                     int    `json:"iterations"`
	CovariateCount                 int    `json:"covariate_count"`
	NoiseCoordinates               int    `json:"noise_coordinates"`
	ScoreSensitivitySteps          string `json:"score_l2_sensitivity_steps"`
	AdaptiveStackSensitivitySteps  string `json:"adaptive_stack_l2_sensitivity_steps"`
	RiskMeanRoundingPerCoordinate  string `json:"risk_mean_rounding_steps_per_coordinate"`
	NormalizedRoundingL2Steps      string `json:"normalized_rounding_l2_steps"`
	Mechanism                      string `json:"mechanism"`
	Allocation                     string `json:"allocation"`
	MaximumNoiseMagnitude          string `json:"maximum_noise_magnitude"`
	VectorTailTVUpperNumerator     string `json:"vector_tail_tv_upper_numerator"`
	VectorTailTVUpperDenominator   string `json:"vector_tail_tv_upper_denominator"`
	VectorCDFTVUpperNumerator      string `json:"vector_cdf_tv_upper_numerator"`
	VectorCDFTVUpperDenominator    string `json:"vector_cdf_tv_upper_denominator"`
	VectorTotalTVUpperNumerator    string `json:"vector_total_tv_upper_numerator"`
	VectorTotalTVUpperDenominator  string `json:"vector_total_tv_upper_denominator"`
	ImplementationDeltaNumerator   string `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator string `json:"implementation_delta_denominator"`
	NoiseLawSHA256                 string `json:"noise_law_sha256"`
}

// formalCoxBlockwiseCanonicalNoiseLaw fixes the exact finite distribution and
// seed-to-noise interpretation. It excludes physical chunking, circuit costs,
// backend/proof labels and readiness while retaining every numerical field
// that can change the sampled vector.
type formalCoxBlockwiseCanonicalNoiseLaw struct {
	Version                        string `json:"version"`
	SamplerMode                    string `json:"sampler_mode"`
	Mechanism                      string `json:"mechanism"`
	Allocation                     string `json:"allocation"`
	EpsilonNumerator               string `json:"epsilon_numerator"`
	EpsilonDenominator             string `json:"epsilon_denominator"`
	AllocatedDeltaNumerator        string `json:"allocated_delta_numerator"`
	AllocatedDeltaDenominator      string `json:"allocated_delta_denominator"`
	CoreDeltaNumerator             string `json:"core_delta_numerator"`
	CoreDeltaDenominator           string `json:"core_delta_denominator"`
	L2SensitivitySteps             string `json:"l2_sensitivity_steps"`
	RhoNumerator                   string `json:"rho_numerator"`
	RhoDenominator                 string `json:"rho_denominator"`
	SigmaSquaredNumerator          string `json:"sigma_squared_numerator"`
	SigmaSquaredDenominator        string `json:"sigma_squared_denominator"`
	MaximumNoiseMagnitude          string `json:"maximum_noise_magnitude"`
	VectorTailTVUpperNumerator     string `json:"vector_tail_tv_upper_numerator"`
	VectorTailTVUpperDenominator   string `json:"vector_tail_tv_upper_denominator"`
	VectorCDFTVUpperNumerator      string `json:"vector_cdf_tv_upper_numerator"`
	VectorCDFTVUpperDenominator    string `json:"vector_cdf_tv_upper_denominator"`
	VectorTotalTVUpperNumerator    string `json:"vector_total_tv_upper_numerator"`
	VectorTotalTVUpperDenominator  string `json:"vector_total_tv_upper_denominator"`
	ImplementationDeltaNumerator   string `json:"implementation_delta_numerator"`
	ImplementationDeltaDenominator string `json:"implementation_delta_denominator"`
	// RingBits is semantic here: it fixes modular interpretation/wrap in the
	// seed-to-noise map. Physical container/chunk geometry remains excluded.
	RingBits                        int    `json:"ring_bits"`
	FractionBits                    int    `json:"fraction_bits"`
	NoiseDrawCount                  int    `json:"noise_draw_count"`
	TotalCoordinateCount            int    `json:"total_coordinate_count"`
	SamplerRandomBitsPerCoordinate  int    `json:"sampler_random_bits_per_coordinate"`
	SamplerPrivateBitsPerCoordinate int    `json:"sampler_private_bits_per_coordinate"`
	SamplerTablePrecisionBits       int    `json:"sampler_table_precision_bits"`
	SamplerMagnitudeCount           int    `json:"sampler_magnitude_count"`
	CDFCumulativeSHA256             string `json:"cdf_cumulative_sha256"`
}

type formalCoxBlockwiseSamplerCommitment struct {
	Role                    string `json:"role"`
	PeerName                string `json:"peer_name"`
	PeerID                  string `json:"peer_id"`
	SamplerPurpose          string `json:"sampler_purpose"`
	CommitmentContextSHA256 string `json:"commitment_context_sha256"`
	SeedCommitmentSHA256    string `json:"seed_commitment_sha256"`
}

type formalCoxBlockwiseSamplerContract struct {
	Version             string                                `json:"version"`
	Purpose             string                                `json:"purpose"`
	ArtifactID          string                                `json:"artifact_id"`
	Artifact            formalCoxBlockwiseStickyArtifact      `json:"artifact"`
	SamplerMode         string                                `json:"sampler_mode"`
	PinsetSHA256        string                                `json:"pinset_sha256"`
	CustodianPeers      []string                              `json:"custodian_peers"`
	CustodianCount      int                                   `json:"custodian_count"`
	NoiseCommitments    []formalCoxBlockwiseSamplerCommitment `json:"noise_commitments"`
	ProductionReady     bool                                  `json:"-"`
	CustodianSignatures []jointDPBiomedicalGaussianSignature  `json:"custodian_signatures"`
}

type formalCoxBlockwiseSamplerAuthorization struct {
	Version                        string `json:"version"`
	Purpose                        string `json:"purpose"`
	ArtifactID                     string `json:"artifact_id"`
	ContractSHA256                 string `json:"contract_sha256"`
	PeerName                       string `json:"peer_name"`
	PeerID                         string `json:"peer_id"`
	Role                           string `json:"role"`
	PredecessorAuthorizationSHA256 string `json:"predecessor_authorization_sha256,omitempty"`
	Signature                      []byte `json:"signature"`
}

// formalCoxBlockwiseGuardedNoiseBarrier carries only public commitments. The
// two existing noise-barrier approvals sign the embedded contract/guard hashes
// after ciphertext creation, linking the pre-sampler CAS to the exact pair of
// recipient-local encrypted noise shares.
type formalCoxBlockwiseGuardedNoiseBarrier struct {
	Version                string                                   `json:"version"`
	Purpose                string                                   `json:"purpose"`
	ArtifactID             string                                   `json:"artifact_id"`
	ContractSHA256         string                                   `json:"contract_sha256"`
	SamplerGuardRootSHA256 string                                   `json:"sampler_guard_root_sha256"`
	Contract               formalCoxBlockwiseSamplerContract        `json:"sampler_contract"`
	Authorizations         []formalCoxBlockwiseSamplerAuthorization `json:"sampler_authorizations"`
	Barrier                formalCoxBlockwiseNoiseBarrier           `json:"noise_barrier"`
}

type formalCoxBlockwiseSamplerGuardRecord struct {
	Version                  string                                 `json:"version"`
	Purpose                  string                                 `json:"purpose"`
	Peer                     string                                 `json:"peer"`
	Role                     string                                 `json:"role"`
	ArtifactID               string                                 `json:"artifact_id"`
	ContractSHA256           string                                 `json:"contract_sha256"`
	ContractJSON             string                                 `json:"contract_json"`
	PredecessorSignatureHash string                                 `json:"predecessor_signature_sha256,omitempty"`
	Authorization            formalCoxBlockwiseSamplerAuthorization `json:"authorization"`
	RecordMAC                string                                 `json:"record_mac"`
}

type formalCoxBlockwiseSamplerGuardStore struct {
	mu   sync.Mutex
	dir  string
	peer string
	key  [32]byte
	pins map[string]ed25519.PublicKey
	root *os.Root
}

func formalCoxBlockwiseStickyHash(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(domain+"|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseStickyArtifactID(
	artifact formalCoxBlockwiseStickyArtifact,
) (string, error) {
	return formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseStickyArtifactDomain+"/id", artifact)
}

func formalCoxBlockwiseCanonicalScientificPlanSHA256(
	policy formalCoxPhase1Policy, parsed formalCoxParsedPolicy,
) (string, error) {
	projection := formalCoxBlockwiseCanonicalScientificPlan{
		ScientificArtifactSHA256:    policy.ArtifactSHA256,
		FormulaColumnBindingsSHA256: policy.CapsuleSHA256,
		CohortSnapshotSHA256:        policy.SnapshotSHA256,
		PinsetSHA256:                policy.PinsetSHA256,
		ExpTableSHA256:              policy.ExpTableSHA256,
		CustodianPeers:              append([]string(nil), policy.CustodianPeers...),
		ComputePeers:                append([]string(nil), policy.ComputePeers...),
		Adjacency:                   policy.Adjacency,
		EntryMode:                   policy.EntryMode,
		Capacity:                    policy.Capacity,
		CovariateCount:              policy.CovariateCount,
		GridTickCount:               policy.GridTickCount,
		Iterations:                  policy.Iterations,
		FractionBits:                policy.FracBits,
		XLower:                      append([]string(nil), policy.XLower...),
		XUpper:                      append([]string(nil), policy.XUpper...),
		CovariateL2Bound:            policy.CovariateL2Bound,
		BetaL2Bound:                 policy.BetaL2Bound,
		MinimumAtRisk:               policy.MinimumAtRisk,
		Alpha:                       policy.Alpha,
		Ridge:                       policy.Ridge,
		EpsilonRational:             parsed.epsilon.RatString(),
		DeltaRational:               parsed.delta.RatString(),
		NoiseBound:                  policy.NoiseBound,
		ExpKnots:                    append([]string(nil), policy.ExpKnots...),
		ExpValues:                   append([]string(nil), policy.ExpValues...),
		ExpErrorUpper:               policy.ExpErrorUpper,
		ExpCertificateBits:          policy.ExpCertificateBits,
		Ties:                        policy.Ties,
		PrivacyUnit:                 policy.PrivacyUnit,
		ReductionOrder:              policy.ReductionOrder,
		Truncation:                  policy.Truncation,
		Projection:                  policy.Projection,
		Output:                      policy.Output,
	}
	return formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseStickyArtifactDomain+"/scientific-plan", projection)
}

func formalCoxBlockwiseCanonicalDPPlanSHA256(dpPlan formalCoxDPPlan,
	parsed formalCoxParsedPolicy,
) (string, error) {
	common := dpPlan.CommonPlan
	cdfSHA256, err := formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseStickyArtifactDomain+"/noise-law/cdf",
		append([]string(nil), common.CDFCumulative...))
	if err != nil {
		return "", err
	}
	noiseLawSHA256, err := formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseStickyArtifactDomain+"/noise-law",
		formalCoxBlockwiseCanonicalNoiseLaw{
			Version:                         "formal-cox-canonical-noise-law-v1",
			SamplerMode:                     formalCoxBlockwiseSamplerMode,
			Mechanism:                       common.Mechanism,
			Allocation:                      common.Allocation,
			EpsilonNumerator:                common.EpsilonNumerator,
			EpsilonDenominator:              common.EpsilonDenominator,
			AllocatedDeltaNumerator:         common.AllocatedDeltaNumerator,
			AllocatedDeltaDenominator:       common.AllocatedDeltaDenominator,
			CoreDeltaNumerator:              common.CoreDeltaNumerator,
			CoreDeltaDenominator:            common.CoreDeltaDenominator,
			L2SensitivitySteps:              common.L2SensitivitySteps,
			RhoNumerator:                    common.RhoNumerator,
			RhoDenominator:                  common.RhoDenominator,
			SigmaSquaredNumerator:           common.SigmaSquaredNumerator,
			SigmaSquaredDenominator:         common.SigmaSquaredDenominator,
			MaximumNoiseMagnitude:           common.MaximumNoiseMagnitude,
			VectorTailTVUpperNumerator:      common.VectorTailTVUpperNumerator,
			VectorTailTVUpperDenominator:    common.VectorTailTVUpperDenominator,
			VectorCDFTVUpperNumerator:       common.VectorCDFTVUpperNumerator,
			VectorCDFTVUpperDenominator:     common.VectorCDFTVUpperDenominator,
			VectorTotalTVUpperNumerator:     common.VectorTotalTVUpperNumerator,
			VectorTotalTVUpperDenominator:   common.VectorTotalTVUpperDenominator,
			ImplementationDeltaNumerator:    common.ImplementationDeltaNumerator,
			ImplementationDeltaDenominator:  common.ImplementationDeltaDenominator,
			RingBits:                        common.RingBits,
			FractionBits:                    common.FracBits,
			NoiseDrawCount:                  common.NoiseDrawCount,
			TotalCoordinateCount:            common.TotalCoordinateCount,
			SamplerRandomBitsPerCoordinate:  common.SamplerRandomBitsPerCoordinate,
			SamplerPrivateBitsPerCoordinate: common.SamplerPrivateBitsPerCoordinate,
			SamplerTablePrecisionBits:       common.SamplerTablePrecisionBits,
			SamplerMagnitudeCount:           common.SamplerMagnitudeCount,
			CDFCumulativeSHA256:             cdfSHA256,
		})
	if err != nil {
		return "", err
	}
	projection := formalCoxBlockwiseCanonicalDPPlan{
		EpsilonRational:                parsed.epsilon.RatString(),
		DeltaRational:                  parsed.delta.RatString(),
		Adjacency:                      dpPlan.Adjacency,
		Iterations:                     dpPlan.Iterations,
		CovariateCount:                 dpPlan.CovariateCount,
		NoiseCoordinates:               dpPlan.NoiseCoordinates,
		ScoreSensitivitySteps:          dpPlan.ScoreSensitivitySteps,
		AdaptiveStackSensitivitySteps:  dpPlan.AdaptiveStackSensitivitySteps,
		RiskMeanRoundingPerCoordinate:  dpPlan.RiskMeanRoundingPerCoordinate,
		NormalizedRoundingL2Steps:      dpPlan.NormalizedRoundingL2Steps,
		Mechanism:                      dpPlan.Mechanism,
		Allocation:                     dpPlan.Allocation,
		MaximumNoiseMagnitude:          dpPlan.MaximumNoiseMagnitude,
		VectorTailTVUpperNumerator:     dpPlan.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:   dpPlan.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:      dpPlan.VectorCDFTVUpperNumerator,
		VectorCDFTVUpperDenominator:    dpPlan.VectorCDFTVUpperDenominator,
		VectorTotalTVUpperNumerator:    dpPlan.VectorTotalTVUpperNumerator,
		VectorTotalTVUpperDenominator:  dpPlan.VectorTotalTVUpperDenominator,
		ImplementationDeltaNumerator:   dpPlan.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator: dpPlan.ImplementationDeltaDenominator,
		NoiseLawSHA256:                 noiseLawSHA256,
	}
	return formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseStickyArtifactDomain+"/dp-plan", projection)
}

func formalCoxBlockwiseBuildStickyArtifact(plan formalCoxBlockwisePlan,
	pins map[string]ed25519.PublicKey,
) (formalCoxBlockwiseStickyArtifact, string, error) {
	var zero formalCoxBlockwiseStickyArtifact
	if err := validateFormalCoxBlockwisePlan(plan); err != nil {
		return zero, "", err
	}
	pinset, err := formalCoxBlockwisePinsetSHA256(pins)
	if err != nil || pinset != plan.Policy.PinsetSHA256 ||
		len(pins) != len(plan.Policy.CustodianPeers) {
		return zero, "", fmt.Errorf("formal-cox: sticky artifact pinset mismatch")
	}
	for _, peer := range plan.Policy.CustodianPeers {
		if len(pins[peer]) != ed25519.PublicKeySize {
			return zero, "", fmt.Errorf("formal-cox: sticky artifact pinset is incomplete")
		}
	}
	parsed, err := parseFormalCoxBlockwisePolicy(plan.Policy)
	if err != nil {
		return zero, "", err
	}
	dpPlan, err := planFormalCoxBlockwiseDP(plan.Policy)
	if err != nil {
		return zero, "", err
	}
	if !dpPlan.PolicyNoiseChunkCountMatches ||
		!dpPlan.PolicyNoiseBoundMatches || !dpPlan.NoiseCoordinatesFixedShape ||
		!dpPlan.FiniteSupportTransferCharged || !dpPlan.FixedWorkSampler ||
		!dpPlan.NoWrapCertified || !dpPlan.PrivacyPlanCertified {
		return zero, "", fmt.Errorf(
			"formal-cox: sticky artifact DP certificate does not close")
	}
	scientificPlanSHA256, err :=
		formalCoxBlockwiseCanonicalScientificPlanSHA256(plan.Policy, parsed)
	if err != nil {
		return zero, "", err
	}
	dpPlanSHA256, err :=
		formalCoxBlockwiseCanonicalDPPlanSHA256(dpPlan, parsed)
	if err != nil {
		return zero, "", err
	}
	boundsSHA256, err := formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseStickyArtifactDomain+"/bounds", struct {
			XLower           []string `json:"x_lower"`
			XUpper           []string `json:"x_upper"`
			CovariateL2Bound string   `json:"covariate_l2_bound"`
			BetaL2Bound      string   `json:"beta_l2_bound"`
			MinimumAtRisk    int      `json:"minimum_at_risk"`
		}{append([]string(nil), plan.Policy.XLower...),
			append([]string(nil), plan.Policy.XUpper...),
			plan.Policy.CovariateL2Bound, plan.Policy.BetaL2Bound,
			plan.Policy.MinimumAtRisk})
	if err != nil {
		return zero, "", err
	}
	gridSHA256, err := formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseStickyArtifactDomain+"/grid", struct {
			GridTickCount      int      `json:"grid_tick_count"`
			ExpTableSHA256     string   `json:"exp_table_sha256"`
			ExpKnots           []string `json:"exp_knots"`
			ExpValues          []string `json:"exp_values"`
			ExpErrorUpper      string   `json:"exp_error_upper"`
			ExpCertificateBits int      `json:"exp_certificate_bits"`
		}{plan.Policy.GridTickCount, plan.Policy.ExpTableSHA256,
			append([]string(nil), plan.Policy.ExpKnots...),
			append([]string(nil), plan.Policy.ExpValues...),
			plan.Policy.ExpErrorUpper, plan.Policy.ExpCertificateBits})
	if err != nil {
		return zero, "", err
	}
	authorities := make([]formalCoxBlockwiseStickyAuthority, 2)
	for index, peer := range plan.Policy.ComputePeers {
		peerID, peerErr := formalCoxBlockwiseSourcePeerID(pins[peer])
		role, roleErr := formalCoxBlockwiseSourceRole(plan, peer)
		if peerErr != nil || roleErr != nil {
			return zero, "", fmt.Errorf("formal-cox: invalid sticky noise authority")
		}
		authorities[index] = formalCoxBlockwiseStickyAuthority{
			Role: role, PeerName: peer, PeerID: peerID,
		}
	}
	artifact := formalCoxBlockwiseStickyArtifact{
		Version:                     formalCoxBlockwiseStickyArtifactVersion,
		Purpose:                     formalCoxBlockwiseStickyArtifactPurpose,
		ScientificArtifactSHA256:    plan.Policy.ArtifactSHA256,
		FormulaColumnBindingsSHA256: plan.Policy.CapsuleSHA256,
		CohortSnapshotSHA256:        plan.Policy.SnapshotSHA256,
		ScientificPlanSHA256:        scientificPlanSHA256,
		DPPlanSHA256:                dpPlanSHA256, BoundsSHA256: boundsSHA256,
		GridSHA256: gridSHA256, PinsetSHA256: pinset,
		CustodianPeers:   append([]string(nil), plan.Policy.CustodianPeers...),
		CustodianCount:   len(plan.Policy.CustodianPeers),
		NoiseAuthorities: authorities,
		Adjacency:        plan.Policy.Adjacency, PrivacyUnit: plan.Policy.PrivacyUnit,
		EntryMode: plan.Policy.EntryMode, Ties: plan.Policy.Ties,
		Mechanism: dpPlan.Mechanism, Allocation: dpPlan.Allocation,
		EpsilonRational:  parsed.epsilon.RatString(),
		DeltaRational:    parsed.delta.RatString(),
		SensitivitySteps: dpPlan.AdaptiveStackSensitivitySteps,
		Alpha:            plan.Policy.Alpha, Ridge: plan.Policy.Ridge,
		Iterations:           plan.Policy.Iterations,
		CovariateCount:       plan.Policy.CovariateCount,
		NoiseCoordinateCount: dpPlan.NoiseCoordinates,
		FractionBits:         plan.Policy.FracBits,
		ReductionOrder:       plan.Policy.ReductionOrder,
		Truncation:           plan.Policy.Truncation, Projection: plan.Policy.Projection,
		ProductionReady: false,
	}
	if err := formalCoxBlockwiseValidateStickyArtifact(artifact, pins); err != nil {
		return zero, "", err
	}
	id, err := formalCoxBlockwiseStickyArtifactID(artifact)
	return artifact, id, err
}

func formalCoxBlockwiseValidateStickyArtifact(
	artifact formalCoxBlockwiseStickyArtifact,
	pins map[string]ed25519.PublicKey,
) error {
	if artifact.Version != formalCoxBlockwiseStickyArtifactVersion ||
		artifact.Purpose != formalCoxBlockwiseStickyArtifactPurpose ||
		artifact.ProductionReady || artifact.CustodianCount < 2 ||
		artifact.CustodianCount != len(artifact.CustodianPeers) ||
		artifact.CustodianCount != len(pins) ||
		!sort.StringsAreSorted(artifact.CustodianPeers) ||
		len(artifact.NoiseAuthorities) != 2 || artifact.Iterations < 1 ||
		artifact.CovariateCount < 1 ||
		artifact.NoiseCoordinateCount != artifact.Iterations*artifact.CovariateCount ||
		artifact.FractionBits < 1 || artifact.SensitivitySteps == "" ||
		artifact.Mechanism == "" || artifact.Allocation == "" {
		return fmt.Errorf("formal-cox: invalid canonical sticky artifact")
	}
	for _, value := range []string{
		artifact.ScientificArtifactSHA256,
		artifact.FormulaColumnBindingsSHA256,
		artifact.CohortSnapshotSHA256, artifact.ScientificPlanSHA256,
		artifact.DPPlanSHA256, artifact.BoundsSHA256, artifact.GridSHA256,
		artifact.PinsetSHA256,
	} {
		if !formalCoxIsSHA256(value) {
			return fmt.Errorf("formal-cox: invalid sticky artifact commitment")
		}
	}
	pinset, err := formalCoxBlockwisePinsetSHA256(pins)
	if err != nil || pinset != artifact.PinsetSHA256 {
		return fmt.Errorf("formal-cox: sticky artifact pinset authentication failed")
	}
	seen := make(map[string]bool, artifact.CustodianCount)
	for _, peer := range artifact.CustodianPeers {
		if seen[peer] || len(pins[peer]) != ed25519.PublicKeySize {
			return fmt.Errorf("formal-cox: invalid sticky artifact custodian set")
		}
		seen[peer] = true
	}
	for index, authority := range artifact.NoiseAuthorities {
		peerID, peerErr := formalCoxBlockwiseSourcePeerID(pins[authority.PeerName])
		if !seen[authority.PeerName] || authority.PeerID != peerID ||
			authority.Role != []string{"garbler", "evaluator"}[index] ||
			peerErr != nil || index == 1 && authority.PeerName ==
			artifact.NoiseAuthorities[0].PeerName {
			return fmt.Errorf("formal-cox: invalid sticky artifact authority set")
		}
	}
	for value, label := range map[string]string{
		artifact.EpsilonRational: "epsilon", artifact.DeltaRational: "delta",
	} {
		rat, ok := new(big.Rat).SetString(value)
		if !ok || rat.Sign() <= 0 || rat.RatString() != value ||
			label == "delta" && rat.Cmp(big.NewRat(1, 1)) >= 0 {
			return fmt.Errorf("formal-cox: non-canonical sticky %s", label)
		}
	}
	return nil
}

func formalCoxBlockwiseSamplerContext(artifactID, role, peerID string) (
	[32]byte, error,
) {
	var artifact [32]byte
	decoded, err := hex.DecodeString(artifactID)
	if err != nil || len(decoded) != sha256.Size ||
		(role != "garbler" && role != "evaluator") || peerID == "" {
		clear(decoded)
		return artifact, fmt.Errorf("formal-cox: invalid sampler commitment context")
	}
	copy(artifact[:], decoded)
	clear(decoded)
	return jointDPCommitmentContext(artifact,
		formalCoxBlockwiseSamplerContractPurpose+"/"+role, peerID), nil
}

func formalCoxBlockwiseDeriveSamplerSeed(authorityRoot [32]byte,
	artifact formalCoxBlockwiseStickyArtifact, artifactID, role string,
) ([32]byte, formalCoxBlockwiseSamplerCommitment, error) {
	var zero [32]byte
	var zeroCommitment formalCoxBlockwiseSamplerCommitment
	if hmac.Equal(authorityRoot[:], zero[:]) {
		return zero, zeroCommitment,
			fmt.Errorf("formal-cox: invalid sampler authority root")
	}
	id, err := formalCoxBlockwiseStickyArtifactID(artifact)
	if err != nil || id != artifactID {
		return zero, zeroCommitment,
			fmt.Errorf("formal-cox: invalid sampler artifact identity")
	}
	position := -1
	for index, authority := range artifact.NoiseAuthorities {
		if authority.Role == role {
			position = index
		}
	}
	if position < 0 {
		return zero, zeroCommitment, fmt.Errorf("formal-cox: unknown sampler role")
	}
	authority := artifact.NoiseAuthorities[position]
	context, err := formalCoxBlockwiseSamplerContext(
		artifactID, role, authority.PeerID)
	if err != nil {
		return zero, zeroCommitment, err
	}
	info, err := json.Marshal(struct {
		Domain     string `json:"domain"`
		ArtifactID string `json:"artifact_id"`
		Mode       string `json:"mode"`
		Role       string `json:"role"`
		PeerName   string `json:"peer_name"`
		PeerID     string `json:"peer_id"`
	}{formalCoxBlockwiseSamplerContractDomain + "/authority-root-hkdf",
		artifactID, formalCoxBlockwiseSamplerMode, role,
		authority.PeerName, authority.PeerID})
	if err != nil {
		return zero, zeroCommitment, err
	}
	reader := hkdf.New(sha256.New, authorityRoot[:], context[:], info)
	clear(info)
	var seed [32]byte
	if _, err := io.ReadFull(reader, seed[:]); err != nil ||
		hmac.Equal(seed[:], zero[:]) {
		clear(seed[:])
		return zero, zeroCommitment,
			fmt.Errorf("formal-cox: sampler seed derivation failed")
	}
	commitment := jointDPSeedCommitment(context, seed)
	return seed, formalCoxBlockwiseSamplerCommitment{
		Role: role, PeerName: authority.PeerName, PeerID: authority.PeerID,
		SamplerPurpose:          formalCoxBlockwiseSamplerContractPurpose + "/" + role,
		CommitmentContextSHA256: hex.EncodeToString(context[:]),
		SeedCommitmentSHA256:    hex.EncodeToString(commitment[:]),
	}, nil
}

func formalCoxBlockwiseValidateSamplerContractCore(
	contract formalCoxBlockwiseSamplerContract,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalCoxBlockwiseValidateStickyArtifact(
		contract.Artifact, pins); err != nil {
		return err
	}
	artifactID, err := formalCoxBlockwiseStickyArtifactID(contract.Artifact)
	if err != nil || artifactID != contract.ArtifactID ||
		contract.Version != formalCoxBlockwiseSamplerContractVersion ||
		contract.Purpose != formalCoxBlockwiseSamplerContractPurpose ||
		contract.SamplerMode != formalCoxBlockwiseSamplerMode ||
		contract.PinsetSHA256 != contract.Artifact.PinsetSHA256 ||
		contract.CustodianCount != contract.Artifact.CustodianCount ||
		!equalStrings(contract.CustodianPeers, contract.Artifact.CustodianPeers) ||
		len(contract.NoiseCommitments) != 2 || contract.ProductionReady {
		return fmt.Errorf("formal-cox: invalid sampler contract identity")
	}
	for index, commitment := range contract.NoiseCommitments {
		authority := contract.Artifact.NoiseAuthorities[index]
		context, contextErr := formalCoxBlockwiseSamplerContext(
			contract.ArtifactID, authority.Role, authority.PeerID)
		if contextErr != nil || commitment.Role != authority.Role ||
			commitment.PeerName != authority.PeerName ||
			commitment.PeerID != authority.PeerID ||
			commitment.SamplerPurpose !=
				formalCoxBlockwiseSamplerContractPurpose+"/"+authority.Role ||
			commitment.CommitmentContextSHA256 != hex.EncodeToString(context[:]) ||
			!formalCoxIsSHA256(commitment.SeedCommitmentSHA256) {
			return fmt.Errorf("formal-cox: invalid sampler commitment")
		}
	}
	if contract.NoiseCommitments[0].CommitmentContextSHA256 ==
		contract.NoiseCommitments[1].CommitmentContextSHA256 ||
		contract.NoiseCommitments[0].SeedCommitmentSHA256 ==
			contract.NoiseCommitments[1].SeedCommitmentSHA256 {
		return fmt.Errorf("formal-cox: sampler authorities are not separated")
	}
	return nil
}

func formalCoxBlockwiseSamplerContractMessage(
	contract formalCoxBlockwiseSamplerContract,
) ([]byte, error) {
	contract.CustodianSignatures = nil
	encoded, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSamplerContractDomain+"/custodian|"),
		encoded...), nil
}

func formalCoxBlockwiseBuildSamplerContract(
	artifact formalCoxBlockwiseStickyArtifact, artifactID string,
	commitments []formalCoxBlockwiseSamplerCommitment,
	pins map[string]ed25519.PublicKey,
) (formalCoxBlockwiseSamplerContract, error) {
	contract := formalCoxBlockwiseSamplerContract{
		Version:    formalCoxBlockwiseSamplerContractVersion,
		Purpose:    formalCoxBlockwiseSamplerContractPurpose,
		ArtifactID: artifactID, Artifact: artifact,
		SamplerMode:    formalCoxBlockwiseSamplerMode,
		PinsetSHA256:   artifact.PinsetSHA256,
		CustodianPeers: append([]string(nil), artifact.CustodianPeers...),
		CustodianCount: artifact.CustodianCount,
		NoiseCommitments: append(
			[]formalCoxBlockwiseSamplerCommitment(nil), commitments...),
		ProductionReady: false,
	}
	if err := formalCoxBlockwiseValidateSamplerContractCore(
		contract, pins); err != nil {
		return formalCoxBlockwiseSamplerContract{}, err
	}
	return contract, nil
}

func formalCoxBlockwiseSignSamplerContract(
	contract formalCoxBlockwiseSamplerContract, signer string,
	privateKey ed25519.PrivateKey, pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSignature, error) {
	var zero jointDPBiomedicalGaussianSignature
	if len(contract.CustodianSignatures) != 0 ||
		formalCoxBlockwiseValidateSamplerContractCore(contract, pins) != nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey), pins[signer]) {
		return zero, fmt.Errorf("formal-cox: invalid sampler contract signer")
	}
	position := sort.SearchStrings(contract.CustodianPeers, signer)
	if position >= len(contract.CustodianPeers) ||
		contract.CustodianPeers[position] != signer {
		return zero, fmt.Errorf("formal-cox: sampler signer is not a custodian")
	}
	message, err := formalCoxBlockwiseSamplerContractMessage(contract)
	if err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianSignature{
		Signer: signer, Signature: ed25519.Sign(privateKey, message),
	}, nil
}

func formalCoxBlockwiseSealSamplerContract(
	contract formalCoxBlockwiseSamplerContract,
	signatures []jointDPBiomedicalGaussianSignature,
	pins map[string]ed25519.PublicKey,
) (formalCoxBlockwiseSamplerContract, error) {
	if len(contract.CustodianSignatures) != 0 ||
		formalCoxBlockwiseValidateSamplerContractCore(contract, pins) != nil ||
		len(signatures) != contract.CustodianCount {
		return formalCoxBlockwiseSamplerContract{},
			fmt.Errorf("formal-cox: sampler contract requires K-of-K signatures")
	}
	message, err := formalCoxBlockwiseSamplerContractMessage(contract)
	if err != nil {
		return formalCoxBlockwiseSamplerContract{}, err
	}
	sealed := contract
	sealed.CustodianSignatures = make(
		[]jointDPBiomedicalGaussianSignature, len(signatures))
	for index, peer := range contract.CustodianPeers {
		signature := signatures[index]
		if signature.Signer != peer ||
			len(signature.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, signature.Signature) {
			return formalCoxBlockwiseSamplerContract{},
				fmt.Errorf("formal-cox: invalid sampler custodian signature")
		}
		sealed.CustodianSignatures[index] = jointDPBiomedicalGaussianSignature{
			Signer: peer, Signature: append([]byte(nil), signature.Signature...),
		}
	}
	if err := formalCoxBlockwiseValidateSamplerContract(sealed, pins); err != nil {
		return formalCoxBlockwiseSamplerContract{}, err
	}
	return sealed, nil
}

func formalCoxBlockwiseValidateSamplerContract(
	contract formalCoxBlockwiseSamplerContract,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalCoxBlockwiseValidateSamplerContractCore(
		contract, pins); err != nil {
		return err
	}
	if len(contract.CustodianSignatures) != contract.CustodianCount {
		return fmt.Errorf("formal-cox: sampler contract is not K-of-K signed")
	}
	message, err := formalCoxBlockwiseSamplerContractMessage(contract)
	if err != nil {
		return err
	}
	for index, peer := range contract.CustodianPeers {
		signature := contract.CustodianSignatures[index]
		if signature.Signer != peer ||
			len(signature.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[peer], message, signature.Signature) {
			return fmt.Errorf("formal-cox: sampler contract signature failed")
		}
	}
	return nil
}

func formalCoxBlockwiseSamplerContractSHA256(
	contract formalCoxBlockwiseSamplerContract,
) (string, error) {
	return formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseSamplerContractDomain+"/sealed-contract", contract)
}

func formalCoxBlockwiseSamplerAuthorizationMessage(
	authorization formalCoxBlockwiseSamplerAuthorization,
) ([]byte, error) {
	authorization.Signature = nil
	encoded, err := json.Marshal(authorization)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSamplerContractDomain+"/authorization|"),
		encoded...), nil
}

func formalCoxBlockwiseSamplerAuthorizationSHA256(
	authorization formalCoxBlockwiseSamplerAuthorization,
) (string, error) {
	return formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseSamplerContractDomain+"/authorization-receipt",
		authorization)
}

func formalCoxBlockwiseValidateSamplerAuthorizationAt(
	contract formalCoxBlockwiseSamplerContract,
	authorization formalCoxBlockwiseSamplerAuthorization,
	position int, expectedPredecessor string,
	pins map[string]ed25519.PublicKey,
) error {
	if position < 0 || position >= len(contract.Artifact.NoiseAuthorities) {
		return fmt.Errorf("formal-cox: invalid sampler authorization position")
	}
	contractSHA256, err := formalCoxBlockwiseSamplerContractSHA256(contract)
	if err != nil {
		return err
	}
	authority := contract.Artifact.NoiseAuthorities[position]
	if authorization.Version != formalCoxBlockwiseSamplerGuardVersion ||
		authorization.Purpose != formalCoxBlockwiseSamplerContractPurpose ||
		authorization.ArtifactID != contract.ArtifactID ||
		authorization.ContractSHA256 != contractSHA256 ||
		authorization.PeerName != authority.PeerName ||
		authorization.PeerID != authority.PeerID ||
		authorization.Role != authority.Role ||
		authorization.PredecessorAuthorizationSHA256 != expectedPredecessor ||
		len(authorization.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("formal-cox: sampler authorization binding mismatch")
	}
	message, err := formalCoxBlockwiseSamplerAuthorizationMessage(authorization)
	if err != nil || !ed25519.Verify(
		pins[authority.PeerName], message, authorization.Signature) {
		return fmt.Errorf("formal-cox: sampler authorization signature failed")
	}
	return nil
}

func formalCoxBlockwiseValidateSamplerAuthorizations(
	contract formalCoxBlockwiseSamplerContract,
	authorizations []formalCoxBlockwiseSamplerAuthorization,
	pins map[string]ed25519.PublicKey,
) (string, error) {
	if err := formalCoxBlockwiseValidateSamplerContract(contract, pins); err != nil {
		return "", err
	}
	if len(authorizations) != 2 {
		return "", fmt.Errorf("formal-cox: sampler requires both authorities")
	}
	predecessor := ""
	for index := range contract.Artifact.NoiseAuthorities {
		if err := formalCoxBlockwiseValidateSamplerAuthorizationAt(
			contract, authorizations[index], index, predecessor, pins); err != nil {
			return "", err
		}
		var err error
		predecessor, err = formalCoxBlockwiseSamplerAuthorizationSHA256(
			authorizations[index])
		if err != nil {
			return "", err
		}
	}
	return formalCoxBlockwiseStickyHash(
		formalCoxBlockwiseSamplerContractDomain+"/authorization-root",
		authorizations)
}

func formalCoxBlockwiseValidateSamplerContractForSession(
	session *formalCoxBlockwiseSourceSession,
	contract formalCoxBlockwiseSamplerContract,
) error {
	if session == nil || session.context == nil ||
		formalCoxBlockwiseValidateSamplerContract(
			contract, session.context.pins) != nil ||
		contract.ArtifactID != session.context.artifactID {
		return fmt.Errorf("formal-cox: sampler contract targets another source context")
	}
	want, wantErr := json.Marshal(session.context.artifact)
	got, gotErr := json.Marshal(contract.Artifact)
	if wantErr != nil || gotErr != nil || !bytes.Equal(want, got) {
		return fmt.Errorf("formal-cox: sampler contract scientific identity mismatch")
	}
	return nil
}

func formalCoxBlockwiseNewGuardedNoiseBarrier(
	session *formalCoxBlockwiseSourceSession,
	step formalCoxBlockwiseWorkerStep, encodedEnvelopes [][]byte,
	contract formalCoxBlockwiseSamplerContract,
	authorizations []formalCoxBlockwiseSamplerAuthorization,
) (formalCoxBlockwiseNoiseBarrier, error) {
	var zero formalCoxBlockwiseNoiseBarrier
	if err := formalCoxBlockwiseValidateSamplerContractForSession(
		session, contract); err != nil {
		return zero, err
	}
	guardRoot, err := formalCoxBlockwiseValidateSamplerAuthorizations(
		contract, authorizations, session.context.pins)
	if err != nil {
		return zero, err
	}
	contractSHA256, err := formalCoxBlockwiseSamplerContractSHA256(contract)
	if err != nil {
		return zero, err
	}
	barrier, err := formalCoxBlockwiseNewNoiseBarrier(
		session, step, encodedEnvelopes)
	if err != nil {
		return zero, err
	}
	barrier.CanonicalArtifactID = contract.ArtifactID
	barrier.SamplerContractSHA256 = contractSHA256
	barrier.SamplerGuardRootSHA256 = guardRoot
	barrier.PairedNoiseRootSHA256, err =
		formalCoxBlockwiseNoiseBarrierRoot(barrier)
	if err != nil {
		return zero, err
	}
	if err := formalCoxBlockwiseValidateNoiseBarrierCore(
		session, barrier); err != nil {
		return zero, err
	}
	return barrier, nil
}

func formalCoxBlockwiseValidateGuardedNoiseBarrier(
	session *formalCoxBlockwiseSourceSession,
	binding formalCoxBlockwiseGuardedNoiseBarrier,
) error {
	if binding.Version != formalCoxBlockwiseGuardedNoiseVersion ||
		binding.Purpose != formalCoxBlockwiseGuardedNoisePurpose ||
		binding.ArtifactID != binding.Contract.ArtifactID ||
		!formalCoxIsSHA256(binding.ArtifactID) ||
		!formalCoxIsSHA256(binding.ContractSHA256) ||
		!formalCoxIsSHA256(binding.SamplerGuardRootSHA256) {
		return fmt.Errorf("formal-cox: invalid guarded noise identity")
	}
	if err := formalCoxBlockwiseValidateSamplerContractForSession(
		session, binding.Contract); err != nil {
		return err
	}
	contractSHA256, err := formalCoxBlockwiseSamplerContractSHA256(
		binding.Contract)
	if err != nil || contractSHA256 != binding.ContractSHA256 {
		return fmt.Errorf("formal-cox: guarded noise contract digest mismatch")
	}
	guardRoot, err := formalCoxBlockwiseValidateSamplerAuthorizations(
		binding.Contract, binding.Authorizations, session.context.pins)
	if err != nil || guardRoot != binding.SamplerGuardRootSHA256 {
		return fmt.Errorf("formal-cox: guarded noise authorization root mismatch")
	}
	if binding.Barrier.CanonicalArtifactID != binding.ArtifactID ||
		binding.Barrier.SamplerContractSHA256 != binding.ContractSHA256 ||
		binding.Barrier.SamplerGuardRootSHA256 !=
			binding.SamplerGuardRootSHA256 {
		return fmt.Errorf("formal-cox: noise barrier is detached from sampler guard")
	}
	return formalCoxBlockwiseValidateNoiseBarrier(session, binding.Barrier)
}

func formalCoxBlockwiseFinalizeGuardedNoiseBarrier(
	session *formalCoxBlockwiseSourceSession,
	contract formalCoxBlockwiseSamplerContract,
	authorizations []formalCoxBlockwiseSamplerAuthorization,
	barrier formalCoxBlockwiseNoiseBarrier,
	approvals []formalCoxBlockwiseNoiseApproval,
) ([]byte, error) {
	barrier.Approvals = make(
		[]formalCoxBlockwiseNoiseApproval, len(approvals))
	for index := range approvals {
		barrier.Approvals[index] = approvals[index]
		barrier.Approvals[index].Signature = append(
			[]byte(nil), approvals[index].Signature...)
	}
	contractSHA256, err := formalCoxBlockwiseSamplerContractSHA256(contract)
	if err != nil {
		return nil, err
	}
	guardRoot, err := formalCoxBlockwiseValidateSamplerAuthorizations(
		contract, authorizations, session.context.pins)
	if err != nil {
		return nil, err
	}
	binding := formalCoxBlockwiseGuardedNoiseBarrier{
		Version:    formalCoxBlockwiseGuardedNoiseVersion,
		Purpose:    formalCoxBlockwiseGuardedNoisePurpose,
		ArtifactID: contract.ArtifactID, ContractSHA256: contractSHA256,
		SamplerGuardRootSHA256: guardRoot, Contract: contract,
		Authorizations: append(
			[]formalCoxBlockwiseSamplerAuthorization(nil), authorizations...),
		Barrier: barrier,
	}
	if err := formalCoxBlockwiseValidateGuardedNoiseBarrier(
		session, binding); err != nil {
		return nil, err
	}
	return json.Marshal(binding)
}

func formalCoxBlockwiseSourceValidateGuardedNoiseBinding(
	session *formalCoxBlockwiseSourceSession,
	binding formalCoxBlockwiseGuardedNoiseBarrier,
	local formalCoxBlockwiseSourceHeader, localDigest string,
) (string, error) {
	if err := formalCoxBlockwiseValidateGuardedNoiseBarrier(
		session, binding); err != nil {
		return "", err
	}
	return formalCoxBlockwiseSourceValidateNoiseBinding(
		session, binding.Barrier, local, localDigest)
}

func formalCoxBlockwiseSamplerGuardMAC(key [32]byte,
	record formalCoxBlockwiseSamplerGuardRecord,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(
		formalCoxBlockwiseSamplerContractDomain + "/guard-record|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalCoxBlockwiseSamplerGuardEncode(key [32]byte,
	record formalCoxBlockwiseSamplerGuardRecord,
) ([]byte, error) {
	mac, err := formalCoxBlockwiseSamplerGuardMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func formalCoxBlockwiseGuardEnsureRootDir(root *os.Root, relative string) error {
	if root == nil || relative == "" || filepath.IsAbs(relative) ||
		filepath.Clean(relative) != relative {
		return fmt.Errorf("formal-cox: invalid rooted sampler guard directory")
	}
	if err := root.MkdirAll(relative, 0o700); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.ToSlash(relative), "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("formal-cox: invalid rooted sampler guard directory")
		}
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("formal-cox: unsafe rooted sampler guard directory")
		}
	}
	return nil
}

func formalCoxBlockwiseGuardRootSyncDir(root *os.Root, relative string) error {
	directory, err := root.Open(filepath.Dir(relative))
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func formalCoxBlockwiseGuardRootCreateRecord(root *os.Root, relative string,
	encoded []byte,
) (bool, error) {
	if root == nil || filepath.IsAbs(relative) ||
		filepath.Clean(relative) != relative {
		return false, fmt.Errorf("formal-cox: invalid rooted sampler guard record")
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return false, err
	}
	temporary := filepath.Join(filepath.Dir(relative),
		".formal-cox-sampler-guard-"+hex.EncodeToString(random[:]))
	file, err := root.OpenFile(temporary,
		os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = root.Remove(temporary)
		}
	}()
	if err := exactGCWriteFull(file, encoded); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	if err := root.Link(temporary, relative); err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}
	if err := root.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	removeTemporary = false
	if err := formalCoxBlockwiseGuardRootSyncDir(root, relative); err != nil {
		return false, err
	}
	return true, nil
}

func formalCoxBlockwiseGuardReapTemp(root *os.Root, relative string,
	target os.FileInfo,
) (bool, error) {
	directoryName := filepath.Dir(relative)
	directory, err := root.Open(directoryName)
	if err != nil {
		return false, err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return false, readErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	for _, entry := range entries {
		if entry.IsDir() || !bytes.HasPrefix([]byte(entry.Name()),
			[]byte(".formal-cox-sampler-guard-")) {
			continue
		}
		candidate := filepath.Join(directoryName, entry.Name())
		info, err := root.Lstat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !os.SameFile(target, info) {
			continue
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 || info.Size() != target.Size() {
			return false, fmt.Errorf("formal-cox: unsafe linked sampler guard temporary")
		}
		if err := root.Remove(candidate); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		if err := formalCoxBlockwiseGuardRootSyncDir(root, relative); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func formalCoxBlockwiseGuardRootReadRecord(root *os.Root, relative string,
	maximum int64,
) ([]byte, error) {
	for attempt := 0; attempt < 32; attempt++ {
		info, err := root.Lstat(relative)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 || info.Size() < 64 ||
			info.Size() > maximum {
			return nil, fmt.Errorf("formal-cox: unsafe rooted sampler guard record")
		}
		if !exactGCPrivateOwnedRegular(info) {
			reaped, reapErr := formalCoxBlockwiseGuardReapTemp(root, relative, info)
			if reapErr != nil {
				return nil, reapErr
			}
			if reaped {
				continue
			}
			runtime.Gosched()
			continue
		}
		file, err := root.Open(relative)
		if err != nil {
			return nil, err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) ||
			!exactGCPrivateOwnedRegular(opened) || opened.Size() != info.Size() ||
			opened.Size() < 64 || opened.Size() > maximum {
			_ = file.Close()
			if statErr != nil {
				return nil, statErr
			}
			runtime.Gosched()
			continue
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
	return nil, fmt.Errorf("formal-cox: rooted sampler guard did not stabilize")
}

func newFormalCoxBlockwiseSamplerGuardStore(dir, peer string,
	storageRoot [32]byte, pins map[string]ed25519.PublicKey,
) (*formalCoxBlockwiseSamplerGuardStore, error) {
	var zero [32]byte
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		dir == string(filepath.Separator) ||
		hmac.Equal(storageRoot[:], zero[:]) ||
		len(pins[peer]) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("formal-cox: invalid sampler guard store")
	}
	if err := formalCoxBlockwiseSourceEnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*formalCoxBlockwiseSamplerGuardStore, error) {
		_ = root.Close()
		return nil, err
	}
	if err := formalCoxBlockwiseGuardEnsureRootDir(root, "guards-v1"); err != nil {
		return fail(err)
	}
	pinset, err := formalCoxBlockwisePinsetSHA256(pins)
	if err != nil {
		return fail(err)
	}
	peerID, err := formalCoxBlockwiseSourcePeerID(pins[peer])
	if err != nil {
		return fail(err)
	}
	salt := sha256.Sum256([]byte(
		formalCoxBlockwiseSamplerContractDomain + "/store-key/" + pinset))
	info, err := json.Marshal(struct {
		Peer   string `json:"peer"`
		PeerID string `json:"peer_id"`
	}{peer, peerID})
	if err != nil {
		return fail(err)
	}
	reader := hkdf.New(sha256.New, storageRoot[:], salt[:], info)
	clear(info)
	var key [32]byte
	if _, err := io.ReadFull(reader, key[:]); err != nil ||
		hmac.Equal(key[:], zero[:]) {
		clear(key[:])
		return fail(fmt.Errorf("formal-cox: sampler guard key derivation failed"))
	}
	copyPins := make(map[string]ed25519.PublicKey, len(pins))
	for name, pin := range pins {
		if len(pin) != ed25519.PublicKeySize {
			clear(key[:])
			return fail(fmt.Errorf("formal-cox: invalid sampler guard pinset"))
		}
		copyPins[name] = append(ed25519.PublicKey(nil), pin...)
	}
	return &formalCoxBlockwiseSamplerGuardStore{
		dir: dir, peer: peer, key: key, pins: copyPins, root: root,
	}, nil
}

func (store *formalCoxBlockwiseSamplerGuardStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	clear(store.key[:])
	if store.root == nil {
		return nil
	}
	err := store.root.Close()
	store.root = nil
	return err
}

func (store *formalCoxBlockwiseSamplerGuardStore) recordRelativePath(
	artifactID string, create bool,
) (string, error) {
	if store == nil || store.root == nil || !formalCoxIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-cox: invalid sampler guard artifact id")
	}
	shard := filepath.Join("guards-v1", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalCoxBlockwiseGuardEnsureRootDir(store.root, shard); err != nil {
			return "", err
		}
	}
	return filepath.Join(shard,
		"guard-"+store.peer+"-"+artifactID+".json"), nil
}

func (store *formalCoxBlockwiseSamplerGuardStore) decodeRecord(
	encoded []byte,
) (formalCoxBlockwiseSamplerGuardRecord, error) {
	var zero formalCoxBlockwiseSamplerGuardRecord
	var record formalCoxBlockwiseSamplerGuardRecord
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseSamplerGuardMaxBytes, "sampler guard record",
		&record); err != nil {
		return zero, err
	}
	wantMAC, err := formalCoxBlockwiseSamplerGuardMAC(store.key, record)
	if err != nil || !hmac.Equal([]byte(wantMAC), []byte(record.RecordMAC)) ||
		record.Version != formalCoxBlockwiseSamplerGuardVersion ||
		record.Purpose != formalCoxBlockwiseSamplerContractPurpose ||
		record.Peer != store.peer || !formalCoxIsSHA256(record.ArtifactID) ||
		!formalCoxIsSHA256(record.ContractSHA256) ||
		len(record.Authorization.Signature) != ed25519.SignatureSize {
		return zero, fmt.Errorf("formal-cox: sampler guard authentication failed")
	}
	var contract formalCoxBlockwiseSamplerContract
	if err := formalCoxBlockwiseSourceDecodeCanonical([]byte(record.ContractJSON),
		formalCoxBlockwiseSamplerGuardMaxBytes, "sampler guard contract",
		&contract); err != nil ||
		formalCoxBlockwiseValidateSamplerContract(contract, store.pins) != nil ||
		contract.ArtifactID != record.ArtifactID {
		return zero, fmt.Errorf("formal-cox: invalid sampler guard contract")
	}
	contractSHA256, err := formalCoxBlockwiseSamplerContractSHA256(contract)
	if err != nil || contractSHA256 != record.ContractSHA256 {
		return zero, fmt.Errorf("formal-cox: sampler guard contract digest mismatch")
	}
	position := -1
	for index, authority := range contract.Artifact.NoiseAuthorities {
		if authority.PeerName == store.peer {
			position = index
		}
	}
	if position < 0 || record.Role !=
		contract.Artifact.NoiseAuthorities[position].Role ||
		record.PredecessorSignatureHash !=
			record.Authorization.PredecessorAuthorizationSHA256 ||
		formalCoxBlockwiseValidateSamplerAuthorizationAt(contract,
			record.Authorization, position,
			record.PredecessorSignatureHash, store.pins) != nil {
		return zero, fmt.Errorf("formal-cox: sampler guard authorization failed")
	}
	return record, nil
}

func (store *formalCoxBlockwiseSamplerGuardStore) AuthorizeOnce(
	contract formalCoxBlockwiseSamplerContract, authorityRoot [32]byte,
	privateKey ed25519.PrivateKey,
	predecessors []formalCoxBlockwiseSamplerAuthorization,
) (formalCoxBlockwiseSamplerAuthorization, bool, error) {
	var zero formalCoxBlockwiseSamplerAuthorization
	if store == nil || store.root == nil ||
		formalCoxBlockwiseValidateSamplerContract(contract, store.pins) != nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey),
			store.pins[store.peer]) {
		return zero, false, fmt.Errorf("formal-cox: invalid sampler guard signer")
	}
	position := -1
	for index, authority := range contract.Artifact.NoiseAuthorities {
		if authority.PeerName == store.peer {
			position = index
		}
	}
	if position < 0 {
		return zero, false, fmt.Errorf("formal-cox: sampler guard peer is not an authority")
	}
	authority := contract.Artifact.NoiseAuthorities[position]
	seed, commitment, err := formalCoxBlockwiseDeriveSamplerSeed(
		authorityRoot, contract.Artifact, contract.ArtifactID, authority.Role)
	clear(seed[:])
	wantCommitment, wantErr := json.Marshal(contract.NoiseCommitments[position])
	gotCommitment, gotErr := json.Marshal(commitment)
	if err != nil || wantErr != nil || gotErr != nil ||
		!bytes.Equal(wantCommitment, gotCommitment) {
		return zero, false,
			fmt.Errorf("formal-cox: authority root differs from sampler contract")
	}
	predecessorHash := ""
	if position == 0 {
		if len(predecessors) != 0 {
			return zero, false,
				fmt.Errorf("formal-cox: sampler garbler has a predecessor")
		}
	} else {
		if len(predecessors) != 1 ||
			formalCoxBlockwiseValidateSamplerAuthorizationAt(
				contract, predecessors[0], 0, "", store.pins) != nil {
			return zero, false,
				fmt.Errorf("formal-cox: sampler evaluator lacks exact garbler authorization")
		}
		predecessorHash, err = formalCoxBlockwiseSamplerAuthorizationSHA256(
			predecessors[0])
		if err != nil {
			return zero, false, err
		}
	}
	contractSHA256, err := formalCoxBlockwiseSamplerContractSHA256(contract)
	if err != nil {
		return zero, false, err
	}
	authorization := formalCoxBlockwiseSamplerAuthorization{
		Version:    formalCoxBlockwiseSamplerGuardVersion,
		Purpose:    formalCoxBlockwiseSamplerContractPurpose,
		ArtifactID: contract.ArtifactID, ContractSHA256: contractSHA256,
		PeerName: authority.PeerName, PeerID: authority.PeerID,
		Role:                           authority.Role,
		PredecessorAuthorizationSHA256: predecessorHash,
	}
	message, err := formalCoxBlockwiseSamplerAuthorizationMessage(authorization)
	if err != nil {
		return zero, false, err
	}
	authorization.Signature = ed25519.Sign(privateKey, message)
	contractJSON, err := json.Marshal(contract)
	if err != nil {
		return zero, false, err
	}
	record := formalCoxBlockwiseSamplerGuardRecord{
		Version: formalCoxBlockwiseSamplerGuardVersion,
		Purpose: formalCoxBlockwiseSamplerContractPurpose,
		Peer:    store.peer, Role: authority.Role,
		ArtifactID: contract.ArtifactID, ContractSHA256: contractSHA256,
		ContractJSON:             string(contractJSON),
		PredecessorSignatureHash: predecessorHash,
		Authorization:            authorization,
	}
	encoded, err := formalCoxBlockwiseSamplerGuardEncode(store.key, record)
	if err != nil {
		return zero, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path, err := store.recordRelativePath(contract.ArtifactID, true)
	if err != nil {
		return zero, false, err
	}
	created, err := formalCoxBlockwiseGuardRootCreateRecord(
		store.root, path, encoded)
	if err != nil {
		return zero, false, err
	}
	existingBytes, err := formalCoxBlockwiseGuardRootReadRecord(
		store.root, path, formalCoxBlockwiseSamplerGuardMaxBytes)
	if err != nil {
		return zero, false, err
	}
	existing, err := store.decodeRecord(existingBytes)
	if err != nil {
		return zero, false, err
	}
	existingJSON, existingErr := json.Marshal(existing.Authorization)
	wantJSON, wantErr := json.Marshal(authorization)
	if existingErr != nil || wantErr != nil ||
		existing.ArtifactID != record.ArtifactID ||
		existing.ContractSHA256 != record.ContractSHA256 ||
		existing.PredecessorSignatureHash != record.PredecessorSignatureHash ||
		existing.Role != record.Role || !bytes.Equal(existingJSON, wantJSON) {
		return zero, false,
			fmt.Errorf("formal-cox: conflicting sampler guard authorization")
	}
	return existing.Authorization, !created, nil
}
