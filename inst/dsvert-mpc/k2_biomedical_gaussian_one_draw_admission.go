package main

// Internal, sealed admission for the biomedical one-draw Gaussian route.
//
// This file intentionally adds no command, runtime capability, JSON decoder,
// R entry point, or opening.  The future R materializer must project its
// locally memoized all-custodian manifest into the contract below and obtain
// one Ed25519 signature from every pinned custodian.  The gate derives the
// exact typed-domain L2 bound, shifted coordinate bounds, no-wrap preconditions,
// privacy plan, release binding, and generic worker input.  A caller-supplied
// sensitivity certificate is never accepted.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
)

const (
	jointDPBiomedicalGaussianManifestVersion    = "dsvert-biomedical-gaussian-one-draw-manifest-authority-v2"
	jointDPBiomedicalGaussianReleaseVersion     = "dsvert-biomedical-gaussian-one-draw-release-v1"
	jointDPBiomedicalGaussianSensitivityVersion = "dsvert-biomedical-gaussian-one-draw-l2-certificate-v2"
	jointDPBiomedicalGaussianAdmissionVersion   = "dsvert-biomedical-gaussian-one-draw-authenticated-admission-v1"
	jointDPBiomedicalGaussianChunkVersion       = "dsvert-biomedical-gaussian-one-draw-admitted-chunk-v1"

	jointDPBiomedicalGaussianManifestDomain     = "dsVert/biomedical-gaussian-one-draw/manifest-authority/v2"
	jointDPBiomedicalGaussianSensitivityDomain  = "dsVert/biomedical-gaussian-one-draw/l2-certificate/v2"
	jointDPBiomedicalGaussianAdmissionDomain    = "dsVert/biomedical-gaussian-one-draw/authenticated-admission/v1"
	jointDPBiomedicalGaussianSignatureSetDomain = "dsVert/biomedical-gaussian-one-draw/signature-set/v1"
	jointDPBiomedicalGaussianSealDomain         = "dsVert/biomedical-gaussian-one-draw/private-seal/v1"
	jointDPBiomedicalGaussianChunkSealDomain    = "dsVert/biomedical-gaussian-one-draw/private-chunk-seal/v1"

	jointDPBiomedicalGaussianL2Proof                 = "all_k_signed_typed_layout_exact_bigint_adjacency_derivation_and_ceil_sqrt_v2"
	jointDPBiomedicalGaussianContributionLayout      = "dsvert-biomedical-bounded-contribution-layout-v1"
	jointDPBiomedicalGaussianContributionLattice     = "post_transform_output_integer_lattice_steps_v1"
	jointDPBiomedicalGaussianDenseBlock              = "dense_box_zero_to_upper_per_coordinate_v1"
	jointDPBiomedicalGaussianOneHotBlock             = "zero_or_one_active_coordinate_per_block_v1"
	jointDPBiomedicalGaussianConstantBlock           = "constant_vector_per_patient_v1"
	jointDPBiomedicalGaussianFiniteProfilesBlock     = "finite_allowed_contribution_profiles_v1"
	jointDPBiomedicalGaussianMonomialGridBlock       = "nonnegative_integer_monomial_grid_v1"
	jointDPBiomedicalGaussianExactTypedDomain        = "exact_declared_typed_contribution_domain_v1"
	jointDPBiomedicalGaussianRoleSelection           = "lexicographic_pinned_cryptographic_peer_id_v1"
	jointDPBiomedicalGaussianContribution            = "at_most_one_bounded_collapsed_record_per_admitted_patient_v1"
	jointDPBiomedicalGaussianMaterializer            = "server_authoritative_manifest_and_bounded_materializer_v1"
	jointDPBiomedicalGaussianChunkPolicy             = "full_capsule_signed_once_then_absolute_coordinate_chunk_derivation_v1"
	jointDPBiomedicalGaussianNoWrap                  = "exact_bigint_shifted_bounds_inside_signed_ring128_and_saturating_noise_v1"
	jointDPBiomedicalGaussianThreatModel             = "semi_honest_pinned_custodians_two_designated_compute_peers_at_least_one_honest_noncolluding_v1"
	jointDPBiomedicalGaussianWorkerSensitivityStatus = "biomedical_machine_derived_typed_layout_pending_materializer_e2e_v1"

	jointDPBiomedicalGaussianBlockerCode = "biomedical_gaussian_one_draw_r_dsi_admission_and_opening_unavailable"
)

type jointDPBiomedicalGaussianSignature struct {
	Signer    string `json:"signer"`
	Signature []byte `json:"signature"`
}

type jointDPBiomedicalGaussianL2Component struct {
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	CoordinateStart    int    `json:"coordinate_start"`
	CoordinateCount    int    `json:"coordinate_count"`
	Tightness          string `json:"tightness"`
	SquaredNumerator   string `json:"squared_numerator"`
	SquaredDenominator string `json:"squared_denominator"`
}

// Contribution blocks are a typed structural description of every value one
// collapsed patient may add to the released integer vector. Bounds are in the
// post-transform output lattice, never observed maxima. Blocks form an exact,
// ordered partition of all coordinates. Dense blocks permit every coordinate
// independently in [0, upper]; one-hot blocks permit at most one non-zero
// coordinate. The authoritative materializer must enforce the same layout.
type jointDPBiomedicalGaussianContributionBlock struct {
	Name                       string     `json:"name"`
	Kind                       string     `json:"kind"`
	CoordinateStart            int        `json:"coordinate_start"`
	CoordinateCount            int        `json:"coordinate_count"`
	PerPatientUpperBoundsSteps []string   `json:"per_patient_upper_bounds_steps,omitempty"`
	ConstantValuesSteps        []string   `json:"constant_values_steps,omitempty"`
	ProfilesSteps              [][]string `json:"profiles_steps,omitempty"`
	AxisUpperBoundsSteps       []string   `json:"axis_upper_bounds_steps,omitempty"`
	MonomialPowers             [][]int    `json:"monomial_powers,omitempty"`
}

type jointDPBiomedicalGaussianContributionLayoutDescriptor struct {
	Version string                                       `json:"version"`
	Lattice string                                       `json:"lattice"`
	Blocks  []jointDPBiomedicalGaussianContributionBlock `json:"blocks"`
}

// The fields in this contract are public policy and manifest projections.
// K-of-K signatures authenticate that every custodian derived the same bytes
// from its own server-authoritative manifest cache.  The protected data and
// source shares are deliberately absent.
type jointDPBiomedicalGaussianManifestContract struct {
	Version                     string                                                `json:"version"`
	CapsuleID                   string                                                `json:"capsule_id"`
	ManifestSHA256              string                                                `json:"manifest_sha256"`
	SchemaManifestSHA256        string                                                `json:"schema_manifest_sha256"`
	WorkloadSHA256              string                                                `json:"workload_sha256"`
	SourceContextSHA256         string                                                `json:"source_context_sha256"`
	SourceContractSHA256        string                                                `json:"source_contract_sha256"`
	LogicalSnapshotSHA256       string                                                `json:"logical_snapshot_sha256"`
	CoordinateOrderSHA256       string                                                `json:"coordinate_order_sha256"`
	LatticeTransformSHA256      string                                                `json:"lattice_transform_sha256"`
	PinsetSHA256                string                                                `json:"pinset_sha256"`
	CustodianPeers              []string                                              `json:"custodian_peers"`
	CustodianCount              int                                                   `json:"custodian_count"`
	DesignatedComputePeers      []string                                              `json:"designated_compute_peers"`
	UnitCapacity                int                                                   `json:"unit_capacity"`
	Adjacency                   string                                                `json:"adjacency"`
	MaximumActiveRowsPerPatient int                                                   `json:"maximum_active_rows_per_patient"`
	PatientContribution         string                                                `json:"patient_contribution"`
	MaterializerContract        string                                                `json:"materializer_contract"`
	RingBits                    int                                                   `json:"ring_bits"`
	OutputLatticeBits           int                                                   `json:"output_lattice_bits"`
	TotalCoordinateCount        int                                                   `json:"total_coordinate_count"`
	ScaleShifts                 []int                                                 `json:"scale_shifts"`
	RawUpperBounds              []string                                              `json:"raw_upper_bounds"`
	ContributionLayout          jointDPBiomedicalGaussianContributionLayoutDescriptor `json:"contribution_layout"`
	OperationLimit              bool                                                  `json:"operation_limit"`
	RequestLimit                bool                                                  `json:"request_limit"`
	HistoryCanDenyOperation     bool                                                  `json:"history_can_deny_operation"`
}

type jointDPBiomedicalGaussianManifestAttestation struct {
	Contract   jointDPBiomedicalGaussianManifestContract `json:"contract"`
	Signatures []jointDPBiomedicalGaussianSignature      `json:"signatures"`
}

type jointDPBiomedicalGaussianNoiseCommitment struct {
	ContextSHA256 string `json:"context_sha256"`
	SeedSHA256    string `json:"seed_sha256"`
}

type jointDPBiomedicalGaussianReleaseContract struct {
	Version                             string                                              `json:"version"`
	ReleaseInstanceID                   string                                              `json:"release_instance_id"`
	ReleaseContractSHA256               string                                              `json:"release_contract_sha256"`
	WorkerTranscriptSHA256              string                                              `json:"worker_transcript_sha256"`
	Epsilon                             string                                              `json:"epsilon"`
	AllocatedDelta                      string                                              `json:"allocated_delta"`
	MaximumChunkCoordinates             int                                                 `json:"maximum_chunk_coordinates"`
	NoiseCommitments                    map[string]jointDPBiomedicalGaussianNoiseCommitment `json:"noise_commitments"`
	ReleaseInstanceCompositionAccounted bool                                                `json:"release_instance_composition_accounted"`
	OperationLimit                      bool                                                `json:"operation_limit"`
	RequestLimit                        bool                                                `json:"request_limit"`
	HistoryCanDenyOperation             bool                                                `json:"history_can_deny_operation"`
}

type jointDPBiomedicalGaussianSensitivityCertificate struct {
	Version                       string                                                `json:"version"`
	Kind                          string                                                `json:"kind"`
	Status                        string                                                `json:"status"`
	Norm                          string                                                `json:"norm"`
	Proof                         string                                                `json:"proof"`
	ManifestSHA256                string                                                `json:"manifest_sha256"`
	WorkloadSHA256                string                                                `json:"workload_sha256"`
	LatticeTransformSHA256        string                                                `json:"lattice_transform_sha256"`
	Adjacency                     string                                                `json:"adjacency"`
	UnitCapacity                  int                                                   `json:"unit_capacity"`
	CoordinateCount               int                                                   `json:"coordinate_count"`
	OutputLatticeBits             int                                                   `json:"output_lattice_bits"`
	ContributionLayout            jointDPBiomedicalGaussianContributionLayoutDescriptor `json:"contribution_layout"`
	Components                    []jointDPBiomedicalGaussianL2Component                `json:"components"`
	SquaredSensitivityNumerator   string                                                `json:"squared_sensitivity_numerator"`
	SquaredSensitivityDenominator string                                                `json:"squared_sensitivity_denominator"`
	SelectedBoundSteps            string                                                `json:"selected_bound_steps"`
	ShiftedUpperBounds            []string                                              `json:"shifted_upper_bounds"`
	NoWrapCertificate             string                                                `json:"no_wrap_certificate"`
}

type jointDPBiomedicalGaussianAdmissionPreimage struct {
	Version                             string   `json:"version"`
	ManifestAttestationSHA256           string   `json:"manifest_attestation_sha256"`
	CapsuleID                           string   `json:"capsule_id"`
	ManifestSHA256                      string   `json:"manifest_sha256"`
	SchemaManifestSHA256                string   `json:"schema_manifest_sha256"`
	WorkloadSHA256                      string   `json:"workload_sha256"`
	SourceContextSHA256                 string   `json:"source_context_sha256"`
	SourceContractSHA256                string   `json:"source_contract_sha256"`
	LogicalSnapshotSHA256               string   `json:"logical_snapshot_sha256"`
	CoordinateOrderSHA256               string   `json:"coordinate_order_sha256"`
	LatticeTransformSHA256              string   `json:"lattice_transform_sha256"`
	SensitivityCertificateSHA256        string   `json:"sensitivity_certificate_sha256"`
	WorkerSensitivitySHA256             string   `json:"worker_sensitivity_sha256"`
	PrivacyPlanSHA256                   string   `json:"privacy_plan_sha256"`
	ReleaseBindingSHA256                string   `json:"release_binding_sha256"`
	ReleaseInstanceID                   string   `json:"release_instance_id"`
	ReleaseContractSHA256               string   `json:"release_contract_sha256"`
	WorkerTranscriptSHA256              string   `json:"worker_transcript_sha256"`
	PinsetSHA256                        string   `json:"pinset_sha256"`
	CustodianPeers                      []string `json:"custodian_peers"`
	CustodianCount                      int      `json:"custodian_count"`
	DesignatedComputePeers              []string `json:"designated_compute_peers"`
	DesignatedComputePeerCount          int      `json:"designated_compute_peer_count"`
	GarblerPeerName                     string   `json:"garbler_peer_name"`
	GarblerPeerID                       string   `json:"garbler_peer_id"`
	EvaluatorPeerName                   string   `json:"evaluator_peer_name"`
	EvaluatorPeerID                     string   `json:"evaluator_peer_id"`
	RoleSelection                       string   `json:"role_selection"`
	Mechanism                           string   `json:"mechanism"`
	Allocation                          string   `json:"allocation"`
	Epsilon                             string   `json:"epsilon"`
	AllocatedDelta                      string   `json:"allocated_delta"`
	RingBits                            int      `json:"ring_bits"`
	OutputLatticeBits                   int      `json:"output_lattice_bits"`
	TotalCoordinateCount                int      `json:"total_coordinate_count"`
	MaximumChunkCoordinates             int      `json:"maximum_chunk_coordinates"`
	L2SensitivitySteps                  string   `json:"l2_sensitivity_steps"`
	MaximumNoiseMagnitude               string   `json:"maximum_noise_magnitude"`
	ShiftedUpperBounds                  []string `json:"shifted_upper_bounds"`
	ChunkPolicy                         string   `json:"chunk_policy"`
	NoWrapCertificate                   string   `json:"no_wrap_certificate"`
	ThreatModel                         string   `json:"threat_model"`
	AtLeastOneHonestDesignatedPeer      bool     `json:"at_least_one_honest_designated_peer"`
	StickyAbsoluteCoordinates           bool     `json:"sticky_absolute_coordinates"`
	ReleaseInstanceCompositionAccounted bool     `json:"release_instance_composition_accounted"`
	OperationLimit                      bool     `json:"operation_limit"`
	RequestLimit                        bool     `json:"request_limit"`
	HistoryCanDenyOperation             bool     `json:"history_can_deny_operation"`
	ProtectedDataE2EVerified            bool     `json:"protected_data_e2e_verified"`
	ProductionReady                     bool     `json:"production_ready"`
}

type jointDPBiomedicalGaussianSignedAdmission struct {
	Preimage   jointDPBiomedicalGaussianAdmissionPreimage `json:"preimage"`
	Signatures []jointDPBiomedicalGaussianSignature       `json:"signatures"`
}

type jointDPBiomedicalGaussianCandidate struct {
	preimage          jointDPBiomedicalGaussianAdmissionPreimage
	manifest          jointDPBiomedicalGaussianManifestContract
	release           jointDPBiomedicalGaussianReleaseContract
	certificate       jointDPBiomedicalGaussianSensitivityCertificate
	workerCertificate formalGLMPhase15DPSensitivityCertificate
	releaseBinding    formalGLMPhase16ReleaseBinding
	plan              jointDPGaussianOneDrawPlanOutput
}

// Private fields are intentionally omitted from JSON.  This deterministic
// seal is an in-process integrity invariant, not a MAC and not a transport
// token.  A future cross-process route must carry and reverify the K signatures.
type jointDPBiomedicalGaussianAuthenticatedAdmission struct {
	Version                      string `json:"version"`
	PreimageSHA256               string `json:"preimage_sha256"`
	ManifestSignatureSetSHA256   string `json:"manifest_signature_set_sha256"`
	AdmissionSignatureSetSHA256  string `json:"admission_signature_set_sha256"`
	SensitivityCertificateSHA256 string `json:"sensitivity_certificate_sha256"`
	AuthenticatedGatePassed      bool   `json:"authenticated_gate_passed"`
	ProtectedDataE2EVerified     bool   `json:"protected_data_e2e_verified"`
	OpeningsPerformed            int    `json:"openings_performed"`
	ProductionReady              bool   `json:"production_ready"`
	candidate                    *jointDPBiomedicalGaussianCandidate
	seal                         [32]byte
}

type jointDPBiomedicalGaussianAdmittedChunk struct {
	Version                   string `json:"version"`
	AdmissionSHA256           string `json:"admission_sha256"`
	ChunkStart                int    `json:"chunk_start"`
	CoordinateCount           int    `json:"coordinate_count"`
	CircuitDigest             string `json:"circuit_digest"`
	Purpose                   string `json:"purpose"`
	StickyAbsoluteCoordinates bool   `json:"sticky_absolute_coordinates"`
	ProductionReady           bool   `json:"production_ready"`
	worker                    *jointDPGaussianOneDrawWorkerContractOutput
	seal                      [32]byte
}

type jointDPBiomedicalGaussianReleaseBlocker struct {
	Code              string
	Missing           []string
	OpeningsPerformed int
}

func (e *jointDPBiomedicalGaussianReleaseBlocker) Error() string {
	return "joint-dp-biomedical-gaussian: " + e.Code
}

func jointDPBiomedicalGaussianCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian: encode canonical object: %w", err)
	}
	return encoded, nil
}

func jointDPBiomedicalGaussianDomainMessage(domain string, value any) ([]byte, error) {
	encoded, err := jointDPBiomedicalGaussianCanonical(value)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, len(domain)+1+len(encoded))
	message = append(message, []byte(domain)...)
	message = append(message, '|')
	return append(message, encoded...), nil
}

func jointDPBiomedicalGaussianDomainDigest(domain string, value any) ([32]byte, error) {
	message, err := jointDPBiomedicalGaussianDomainMessage(domain, value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(message), nil
}

func jointDPBiomedicalGaussianHash(value any) (string, error) {
	encoded, err := jointDPBiomedicalGaussianCanonical(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func jointDPBiomedicalGaussianCanonicalSignatures(
	signatures []jointDPBiomedicalGaussianSignature,
) []jointDPBiomedicalGaussianSignature {
	result := append([]jointDPBiomedicalGaussianSignature(nil), signatures...)
	sort.Slice(result, func(i, j int) bool { return result[i].Signer < result[j].Signer })
	return result
}

func jointDPBiomedicalGaussianSignatureSetDigest(
	signatures []jointDPBiomedicalGaussianSignature,
) ([32]byte, error) {
	return jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianSignatureSetDomain,
		jointDPBiomedicalGaussianCanonicalSignatures(signatures))
}

func jointDPBiomedicalGaussianVerifySignatures(message []byte,
	signatures []jointDPBiomedicalGaussianSignature, peers []string,
	pins map[string]ed25519.PublicKey, what string,
) error {
	if len(signatures) != len(peers) || len(pins) != len(peers) {
		return fmt.Errorf("joint-dp-biomedical-gaussian: %s is not signed by exactly K custodians", what)
	}
	wanted := make(map[string]bool, len(peers))
	for _, peer := range peers {
		wanted[peer] = true
	}
	seen := make(map[string]bool, len(peers))
	for _, signature := range signatures {
		pin, ok := pins[signature.Signer]
		if !ok || !wanted[signature.Signer] || seen[signature.Signer] ||
			len(pin) != ed25519.PublicKeySize ||
			len(signature.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pin, message, signature.Signature) {
			return fmt.Errorf("joint-dp-biomedical-gaussian: invalid or duplicate %s signature", what)
		}
		seen[signature.Signer] = true
	}
	return nil
}

func jointDPBiomedicalGaussianSign(domain string, value any, signer string,
	privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianSignature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("joint-dp-biomedical-gaussian: invalid signing key")
	}
	message, err := jointDPBiomedicalGaussianDomainMessage(domain, value)
	if err != nil {
		return jointDPBiomedicalGaussianSignature{}, err
	}
	return jointDPBiomedicalGaussianSignature{
		Signer: signer, Signature: ed25519.Sign(privateKey, message)}, nil
}

func jointDPBiomedicalGaussianManifestMessage(
	contract jointDPBiomedicalGaussianManifestContract,
) ([]byte, error) {
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianManifestDomain, contract)
}

func jointDPBiomedicalGaussianAdmissionMessage(
	preimage jointDPBiomedicalGaussianAdmissionPreimage,
) ([]byte, error) {
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianAdmissionDomain, preimage)
}

func jointDPBiomedicalGaussianIsSHA256(value string) bool {
	return formalGLMIsSHA256(value)
}

func jointDPBiomedicalGaussianValidPeerName(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := range value {
		character := value[index]
		alphaNumeric := character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if !alphaNumeric && (index == 0 ||
			(character != '.' && character != '_' && character != '-')) {
			return false
		}
	}
	return true
}

func jointDPBiomedicalGaussianParseCanonicalInt(value, what string,
	positive bool,
) (*big.Int, error) {
	parsed, err := jointDPVectorParseInt(value, what, positive)
	if err != nil || parsed.String() != value {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid %s", what)
	}
	return parsed, nil
}

func jointDPBiomedicalGaussianCeilSqrtRat(value *big.Rat) *big.Int {
	if value == nil || value.Sign() <= 0 {
		return new(big.Int)
	}
	result := new(big.Int).Sqrt(new(big.Int).Quo(
		new(big.Int).Set(value.Num()), value.Denom()))
	left := new(big.Int).Mul(new(big.Int).Set(result), result)
	left.Mul(left, value.Denom())
	if left.Cmp(value.Num()) < 0 {
		result.Add(result, big.NewInt(1))
	}
	return result
}

func jointDPBiomedicalGaussianValidatePins(
	contract jointDPBiomedicalGaussianManifestContract,
	pins map[string]ed25519.PublicKey,
) error {
	if contract.CustodianCount < 2 ||
		contract.CustodianCount != len(contract.CustodianPeers) ||
		len(pins) != contract.CustodianCount ||
		!sort.StringsAreSorted(contract.CustodianPeers) {
		return fmt.Errorf("joint-dp-biomedical-gaussian: invalid K-custodian set")
	}
	seen := make(map[string]bool, len(contract.CustodianPeers))
	for _, peer := range contract.CustodianPeers {
		if !jointDPBiomedicalGaussianValidPeerName(peer) || seen[peer] ||
			len(pins[peer]) != ed25519.PublicKeySize {
			return fmt.Errorf("joint-dp-biomedical-gaussian: invalid K-custodian pinset")
		}
		seen[peer] = true
	}
	pinset, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil || pinset != contract.PinsetSHA256 {
		return fmt.Errorf("joint-dp-biomedical-gaussian: pinset digest mismatch")
	}
	return nil
}

func jointDPBiomedicalGaussianRoles(
	contract jointDPBiomedicalGaussianManifestContract,
	pins map[string]ed25519.PublicKey,
) (garblerName, garblerID, evaluatorName, evaluatorID string, err error) {
	if len(contract.DesignatedComputePeers) != 2 ||
		!sort.StringsAreSorted(contract.DesignatedComputePeers) ||
		contract.DesignatedComputePeers[0] == contract.DesignatedComputePeers[1] {
		err = fmt.Errorf("joint-dp-biomedical-gaussian: exactly two ordered designated peers are required")
		return
	}
	type role struct{ name, id string }
	roles := make([]role, 2)
	for index, name := range contract.DesignatedComputePeers {
		pin, ok := pins[name]
		if !ok {
			err = fmt.Errorf("joint-dp-biomedical-gaussian: designated peer is not pinned")
			return
		}
		id, idErr := formalGLMPhase16PeerID(pin)
		if idErr != nil {
			err = idErr
			return
		}
		roles[index] = role{name: name, id: id}
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].id < roles[j].id })
	if roles[0].id == roles[1].id {
		err = fmt.Errorf("joint-dp-biomedical-gaussian: duplicate designated pin")
		return
	}
	return roles[0].name, roles[0].id, roles[1].name, roles[1].id, nil
}

func jointDPBiomedicalGaussianCloneContributionLayout(
	layout jointDPBiomedicalGaussianContributionLayoutDescriptor,
) jointDPBiomedicalGaussianContributionLayoutDescriptor {
	result := layout
	result.Blocks = append([]jointDPBiomedicalGaussianContributionBlock(nil),
		layout.Blocks...)
	for index := range result.Blocks {
		result.Blocks[index].PerPatientUpperBoundsSteps = append([]string(nil),
			layout.Blocks[index].PerPatientUpperBoundsSteps...)
		result.Blocks[index].ConstantValuesSteps = append([]string(nil),
			layout.Blocks[index].ConstantValuesSteps...)
		result.Blocks[index].AxisUpperBoundsSteps = append([]string(nil),
			layout.Blocks[index].AxisUpperBoundsSteps...)
		result.Blocks[index].ProfilesSteps = make([][]string,
			len(layout.Blocks[index].ProfilesSteps))
		for profile := range result.Blocks[index].ProfilesSteps {
			result.Blocks[index].ProfilesSteps[profile] = append([]string(nil),
				layout.Blocks[index].ProfilesSteps[profile]...)
		}
		result.Blocks[index].MonomialPowers = make([][]int,
			len(layout.Blocks[index].MonomialPowers))
		for monomial := range result.Blocks[index].MonomialPowers {
			result.Blocks[index].MonomialPowers[monomial] = append([]int(nil),
				layout.Blocks[index].MonomialPowers[monomial]...)
		}
	}
	return result
}

func jointDPBiomedicalGaussianSquaredNorm(values []*big.Int) *big.Int {
	result := new(big.Int)
	for _, value := range values {
		result.Add(result, new(big.Int).Mul(new(big.Int).Set(value), value))
	}
	return result
}

func jointDPBiomedicalGaussianSquaredDistance(left, right []*big.Int) *big.Int {
	result := new(big.Int)
	for index := range left {
		difference := new(big.Int).Sub(left[index], right[index])
		result.Add(result, new(big.Int).Mul(difference, difference))
	}
	return result
}

func jointDPBiomedicalGaussianCompareIntVectors(left, right []*big.Int) int {
	for index := range left {
		if comparison := left[index].Cmp(right[index]); comparison != 0 {
			return comparison
		}
	}
	return 0
}

func jointDPBiomedicalGaussianParseContributionVector(values []string,
	block jointDPBiomedicalGaussianContributionBlock,
	shiftedUpperBounds []string, what string,
) ([]*big.Int, error) {
	if len(values) != block.CoordinateCount {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid %s shape", what)
	}
	result := make([]*big.Int, len(values))
	for local, text := range values {
		value, err := jointDPBiomedicalGaussianParseCanonicalInt(text, what, false)
		aggregate, aggregateErr := jointDPBiomedicalGaussianParseCanonicalInt(
			shiftedUpperBounds[block.CoordinateStart+local],
			"shifted aggregate upper bound", false)
		if err != nil || aggregateErr != nil || value.Cmp(aggregate) > 0 {
			return nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid %s", what)
		}
		result[local] = value
	}
	return result, nil
}

// jointDPBiomedicalGaussianDeriveSensitivity computes the exact squared L2
// diameter of the declared typed contribution domain and accepts no supplied
// sensitivity number. Dense/one-hot blocks define explicit envelope domains;
// constant, finite-profile and monomial-grid blocks preserve their real
// coupling. UnitCapacity is deliberately absent: it fixes padded aggregate
// shape/no-wrap bounds, while patient-level adjacency changes one contribution.
func jointDPBiomedicalGaussianDeriveSensitivity(
	contract jointDPBiomedicalGaussianManifestContract,
	shiftedUpperBounds []string,
) ([]jointDPBiomedicalGaussianL2Component, *big.Int, error) {
	layout := contract.ContributionLayout
	if layout.Version != jointDPBiomedicalGaussianContributionLayout ||
		layout.Lattice != jointDPBiomedicalGaussianContributionLattice ||
		len(layout.Blocks) == 0 || len(layout.Blocks) > contract.TotalCoordinateCount ||
		len(shiftedUpperBounds) != contract.TotalCoordinateCount {
		return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid typed contribution layout")
	}
	components := make([]jointDPBiomedicalGaussianL2Component, 0,
		len(layout.Blocks))
	total := new(big.Int)
	nextCoordinate := 0
	priorName := ""
	for _, block := range layout.Blocks {
		if !jointDPBiomedicalGaussianValidPeerName(block.Name) ||
			block.Name <= priorName ||
			(block.Kind != jointDPBiomedicalGaussianDenseBlock &&
				block.Kind != jointDPBiomedicalGaussianOneHotBlock &&
				block.Kind != jointDPBiomedicalGaussianConstantBlock &&
				block.Kind != jointDPBiomedicalGaussianFiniteProfilesBlock &&
				block.Kind != jointDPBiomedicalGaussianMonomialGridBlock) ||
			block.CoordinateStart != nextCoordinate || block.CoordinateCount < 1 ||
			block.CoordinateCount > contract.TotalCoordinateCount-nextCoordinate {
			return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical contribution block")
		}
		blockSquared := new(big.Int)
		switch block.Kind {
		case jointDPBiomedicalGaussianDenseBlock,
			jointDPBiomedicalGaussianOneHotBlock:
			if len(block.PerPatientUpperBoundsSteps) != block.CoordinateCount ||
				len(block.ConstantValuesSteps) != 0 || len(block.ProfilesSteps) != 0 ||
				len(block.AxisUpperBoundsSteps) != 0 || len(block.MonomialPowers) != 0 {
				return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid bounded contribution block")
			}
			upper, err := jointDPBiomedicalGaussianParseContributionVector(
				block.PerPatientUpperBoundsSteps, block, shiftedUpperBounds,
				"per-patient contribution upper bound")
			if err != nil {
				return nil, nil, err
			}
			if block.Kind == jointDPBiomedicalGaussianDenseBlock {
				blockSquared.Set(jointDPBiomedicalGaussianSquaredNorm(upper))
				break
			}
			largestSquared := new(big.Int)
			secondSquared := new(big.Int)
			for _, value := range upper {
				squared := new(big.Int).Mul(new(big.Int).Set(value), value)
				if squared.Cmp(largestSquared) > 0 {
					secondSquared.Set(largestSquared)
					largestSquared.Set(squared)
				} else if squared.Cmp(secondSquared) > 0 {
					secondSquared.Set(squared)
				}
			}
			blockSquared.Set(largestSquared)
			if contract.Adjacency == "replace_one_fixed_cohort" {
				blockSquared.Add(blockSquared, secondSquared)
			}
		case jointDPBiomedicalGaussianConstantBlock:
			if len(block.PerPatientUpperBoundsSteps) != 0 ||
				len(block.ProfilesSteps) != 0 || len(block.AxisUpperBoundsSteps) != 0 ||
				len(block.MonomialPowers) != 0 {
				return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid constant contribution block")
			}
			values, err := jointDPBiomedicalGaussianParseContributionVector(
				block.ConstantValuesSteps, block, shiftedUpperBounds,
				"constant per-patient contribution")
			if err != nil {
				return nil, nil, err
			}
			if contract.Adjacency == "add_remove_patient" {
				blockSquared.Set(jointDPBiomedicalGaussianSquaredNorm(values))
			}
		case jointDPBiomedicalGaussianFiniteProfilesBlock:
			if len(block.PerPatientUpperBoundsSteps) != 0 ||
				len(block.ConstantValuesSteps) != 0 ||
				len(block.AxisUpperBoundsSteps) != 0 || len(block.MonomialPowers) != 0 ||
				len(block.ProfilesSteps) == 0 || len(block.ProfilesSteps) > 4096 {
				return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid finite-profile contribution block")
			}
			profiles := make([][]*big.Int, len(block.ProfilesSteps))
			for index, profile := range block.ProfilesSteps {
				parsed, err := jointDPBiomedicalGaussianParseContributionVector(
					profile, block, shiftedUpperBounds, "finite contribution profile")
				if err != nil || (index > 0 &&
					jointDPBiomedicalGaussianCompareIntVectors(profiles[index-1], parsed) >= 0) {
					return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical finite contribution profiles")
				}
				profiles[index] = parsed
			}
			if contract.Adjacency == "add_remove_patient" {
				for _, profile := range profiles {
					if squared := jointDPBiomedicalGaussianSquaredNorm(profile); squared.Cmp(blockSquared) > 0 {
						blockSquared.Set(squared)
					}
				}
			} else {
				for left := range profiles {
					for right := 0; right < left; right++ {
						if squared := jointDPBiomedicalGaussianSquaredDistance(
							profiles[left], profiles[right]); squared.Cmp(blockSquared) > 0 {
							blockSquared.Set(squared)
						}
					}
				}
			}
		case jointDPBiomedicalGaussianMonomialGridBlock:
			if len(block.PerPatientUpperBoundsSteps) != 0 ||
				len(block.ConstantValuesSteps) != 0 || len(block.ProfilesSteps) != 0 ||
				len(block.AxisUpperBoundsSteps) < 1 ||
				len(block.AxisUpperBoundsSteps) > 8 ||
				len(block.MonomialPowers) != block.CoordinateCount {
				return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid monomial contribution block")
			}
			axes := make([]*big.Int, len(block.AxisUpperBoundsSteps))
			for index, text := range block.AxisUpperBoundsSteps {
				axis, err := jointDPBiomedicalGaussianParseCanonicalInt(
					text, "monomial axis upper bound", false)
				if err != nil {
					return nil, nil, err
				}
				axes[index] = axis
			}
			priorPowers := []int(nil)
			for local, powers := range block.MonomialPowers {
				if len(powers) != len(axes) {
					return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid monomial powers")
				}
				if local > 0 {
					comparison := 0
					for axis := range powers {
						if powers[axis] != priorPowers[axis] {
							if powers[axis] < priorPowers[axis] {
								comparison = -1
							} else {
								comparison = 1
							}
							break
						}
					}
					if comparison <= 0 {
						return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: non-canonical monomial powers")
					}
				}
				maximum := big.NewInt(1)
				constant := true
				for axis, power := range powers {
					if power < 0 || power > 16 {
						return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: invalid monomial power")
					}
					if power != 0 {
						constant = false
						maximum.Mul(maximum, new(big.Int).Exp(
							axes[axis], big.NewInt(int64(power)), nil))
					}
				}
				aggregate, err := jointDPBiomedicalGaussianParseCanonicalInt(
					shiftedUpperBounds[block.CoordinateStart+local],
					"shifted aggregate upper bound", false)
				if err != nil || maximum.Cmp(aggregate) > 0 {
					return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: monomial exceeds aggregate bound")
				}
				if contract.Adjacency == "add_remove_patient" || !constant {
					blockSquared.Add(blockSquared,
						new(big.Int).Mul(new(big.Int).Set(maximum), maximum))
				}
				priorPowers = powers
			}
		}
		components = append(components, jointDPBiomedicalGaussianL2Component{
			Name: block.Name, Kind: block.Kind,
			CoordinateStart:  block.CoordinateStart,
			CoordinateCount:  block.CoordinateCount,
			Tightness:        jointDPBiomedicalGaussianExactTypedDomain,
			SquaredNumerator: blockSquared.String(), SquaredDenominator: "1",
		})
		total.Add(total, blockSquared)
		nextCoordinate += block.CoordinateCount
		priorName = block.Name
	}
	if nextCoordinate != contract.TotalCoordinateCount {
		return nil, nil, fmt.Errorf("joint-dp-biomedical-gaussian: contribution layout does not cover every coordinate")
	}
	return components, total, nil
}

func jointDPBiomedicalGaussianValidateManifest(
	contract jointDPBiomedicalGaussianManifestContract,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSensitivityCertificate, error) {
	var zero jointDPBiomedicalGaussianSensitivityCertificate
	hashes := []string{
		contract.CapsuleID, contract.ManifestSHA256,
		contract.SchemaManifestSHA256, contract.WorkloadSHA256,
		contract.SourceContextSHA256, contract.SourceContractSHA256,
		contract.LogicalSnapshotSHA256, contract.CoordinateOrderSHA256,
		contract.LatticeTransformSHA256, contract.PinsetSHA256,
	}
	validHashes := true
	for _, value := range hashes {
		validHashes = validHashes && jointDPBiomedicalGaussianIsSHA256(value)
	}
	if contract.Version != jointDPBiomedicalGaussianManifestVersion ||
		!validHashes || contract.UnitCapacity < 1 ||
		(contract.Adjacency != "add_remove_patient" &&
			contract.Adjacency != "replace_one_fixed_cohort") ||
		contract.MaximumActiveRowsPerPatient != 1 ||
		contract.PatientContribution != jointDPBiomedicalGaussianContribution ||
		contract.MaterializerContract != jointDPBiomedicalGaussianMaterializer ||
		contract.RingBits != 128 || contract.OutputLatticeBits < 1 ||
		contract.OutputLatticeBits > 62 || contract.TotalCoordinateCount < 1 ||
		contract.TotalCoordinateCount > jointDPVectorMaxTotal ||
		len(contract.ScaleShifts) != contract.TotalCoordinateCount ||
		len(contract.RawUpperBounds) != contract.TotalCoordinateCount ||
		contract.OperationLimit ||
		contract.RequestLimit || contract.HistoryCanDenyOperation {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid server-authoritative manifest projection")
	}
	if err := jointDPBiomedicalGaussianValidatePins(contract, pins); err != nil {
		return zero, err
	}
	if _, _, _, _, err := jointDPBiomedicalGaussianRoles(contract, pins); err != nil {
		return zero, err
	}

	shifted := make([]string, contract.TotalCoordinateCount)
	maxSigned := exactGCMaxSigned(128)
	for index, rawText := range contract.RawUpperBounds {
		raw, err := jointDPBiomedicalGaussianParseCanonicalInt(
			rawText, "raw coordinate upper bound", false)
		shift := contract.ScaleShifts[index]
		if err != nil || shift < 0 || shift > contract.OutputLatticeBits ||
			raw.Cmp(maxSigned) > 0 {
			return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid coordinate bound")
		}
		value := new(big.Int).Lsh(new(big.Int).Set(raw), uint(shift))
		if value.Cmp(maxSigned) > 0 {
			return zero, exactGCFailure(exactGCFailureBoundExceeded,
				fmt.Errorf("joint-dp-biomedical-gaussian: shifted coordinate outside signed Ring128"))
		}
		shifted[index] = value.String()
	}

	components, totalSquared, err :=
		jointDPBiomedicalGaussianDeriveSensitivity(contract, shifted)
	if err != nil {
		return zero, err
	}
	selected := jointDPBiomedicalGaussianCeilSqrtRat(
		new(big.Rat).SetInt(totalSquared))
	if selected.Sign() <= 0 || selected.Cmp(maxSigned) > 0 {
		return zero, exactGCFailure(exactGCFailureBoundExceeded,
			fmt.Errorf("joint-dp-biomedical-gaussian: L2 sensitivity outside signed Ring128"))
	}
	return jointDPBiomedicalGaussianSensitivityCertificate{
		Version: jointDPBiomedicalGaussianSensitivityVersion,
		Kind:    jointDPGaussianOneDrawSensitivityCertificateKind,
		Status:  "machine_derived_exact_for_declared_typed_contribution_domain_v1", Norm: "l2",
		Proof:                  jointDPBiomedicalGaussianL2Proof,
		ManifestSHA256:         contract.ManifestSHA256,
		WorkloadSHA256:         contract.WorkloadSHA256,
		LatticeTransformSHA256: contract.LatticeTransformSHA256,
		Adjacency:              contract.Adjacency, UnitCapacity: contract.UnitCapacity,
		CoordinateCount:               contract.TotalCoordinateCount,
		OutputLatticeBits:             contract.OutputLatticeBits,
		ContributionLayout:            jointDPBiomedicalGaussianCloneContributionLayout(contract.ContributionLayout),
		Components:                    components,
		SquaredSensitivityNumerator:   totalSquared.String(),
		SquaredSensitivityDenominator: "1",
		SelectedBoundSteps:            selected.String(),
		ShiftedUpperBounds:            shifted,
		NoWrapCertificate:             jointDPBiomedicalGaussianNoWrap,
	}, nil
}

func jointDPBiomedicalGaussianValidateManifestAttestation(
	attestation jointDPBiomedicalGaussianManifestAttestation,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSensitivityCertificate, error) {
	certificate, err := jointDPBiomedicalGaussianValidateManifest(
		attestation.Contract, pins)
	if err != nil {
		return jointDPBiomedicalGaussianSensitivityCertificate{}, err
	}
	message, err := jointDPBiomedicalGaussianManifestMessage(attestation.Contract)
	if err != nil {
		return jointDPBiomedicalGaussianSensitivityCertificate{}, err
	}
	if err := jointDPBiomedicalGaussianVerifySignatures(
		message, attestation.Signatures, attestation.Contract.CustodianPeers,
		pins, "manifest authority"); err != nil {
		return jointDPBiomedicalGaussianSensitivityCertificate{}, err
	}
	return certificate, nil
}

func jointDPBiomedicalGaussianWorkerCertificate(
	manifest jointDPBiomedicalGaussianManifestContract,
	certificate jointDPBiomedicalGaussianSensitivityCertificate,
	manifestAttestationSHA256, certificateSHA256 string,
) formalGLMPhase15DPSensitivityCertificate {
	changed := 1
	if manifest.Adjacency == "replace_one_fixed_cohort" {
		changed = 2
	}
	selected, _ := new(big.Int).SetString(certificate.SelectedBoundSteps, 10)
	squared := new(big.Int).Mul(new(big.Int).Set(selected), selected)
	return formalGLMPhase15DPSensitivityCertificate{
		Version: formalGLMPhase15DPSensitivityCertificateVersion,
		Kind:    jointDPGaussianOneDrawSensitivityCertificateKind,
		Status:  jointDPBiomedicalGaussianWorkerSensitivityStatus, Norm: "l2",
		SelectedProof:      jointDPBiomedicalGaussianL2Proof,
		SelectedBoundSteps: certificate.SelectedBoundSteps,
		PolicySHA256:       manifestAttestationSHA256,
		Phase15PlanSHA256:  manifest.ManifestSHA256,
		TheoremSHA256:      certificateSHA256,
		Adjacency:          manifest.Adjacency, ChangedRowFactor: changed,
		TotalCapacity: manifest.UnitCapacity, CoordinateCount: manifest.TotalCoordinateCount,
		SourceFracBits: 0, OutputLatticeBits: manifest.OutputLatticeBits,
		QuantizationShift: 0, SourceScale: "1", QuantizationDenominator: "1",
		Quantization:              "manifest_coordinate_specific_exact_left_shift_v1",
		QuantizationInequality:    "raw_upper_times_two_to_shift_equals_shifted_upper_exact_bigint_v1",
		CoefficientBox:            append([]string(nil), certificate.ShiftedUpperBounds...),
		ShiftedUpperBounds:        append([]string(nil), certificate.ShiftedUpperBounds...),
		UniversalCoordinateBounds: append([]string(nil), certificate.ShiftedUpperBounds...),
		UniversalL2Squared:        squared.String(),
		UniversalBoundSteps:       certificate.SelectedBoundSteps,
		RecurrenceL2Squared:       squared.String(),
		RecurrenceBoundSteps:      certificate.SelectedBoundSteps,
		Selection:                 jointDPBiomedicalGaussianL2Proof,
	}
}

func jointDPBiomedicalGaussianValidateRelease(
	release jointDPBiomedicalGaussianReleaseContract,
	manifest jointDPBiomedicalGaussianManifestContract,
	pins map[string]ed25519.PublicKey,
) (garblerName, garblerID, evaluatorName, evaluatorID string, err error) {
	if release.Version != jointDPBiomedicalGaussianReleaseVersion ||
		!jointDPBiomedicalGaussianIsSHA256(release.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(release.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(release.WorkerTranscriptSHA256) ||
		release.MaximumChunkCoordinates < 1 ||
		release.MaximumChunkCoordinates > jointDPGaussianOneDrawMaxCoordinates ||
		!release.ReleaseInstanceCompositionAccounted || release.OperationLimit ||
		release.RequestLimit || release.HistoryCanDenyOperation {
		err = fmt.Errorf("joint-dp-biomedical-gaussian: invalid release contract")
		return
	}
	epsilon, epsilonErr := jointDPParseDecimalRat(release.Epsilon, "epsilon", false)
	delta, deltaErr := jointDPParseDecimalRat(release.AllocatedDelta, "delta", false)
	if epsilonErr != nil || epsilon.Sign() <= 0 || deltaErr != nil ||
		delta.Sign() <= 0 || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		err = fmt.Errorf("joint-dp-biomedical-gaussian: invalid privacy parameters")
		return
	}
	garblerName, garblerID, evaluatorName, evaluatorID, err =
		jointDPBiomedicalGaussianRoles(manifest, pins)
	if err != nil {
		return
	}
	if len(release.NoiseCommitments) != 2 {
		err = fmt.Errorf("joint-dp-biomedical-gaussian: incomplete designated commitments")
		return
	}
	transcript, decodeErr := jointDPGaussianOneDrawDecodeHex(
		release.WorkerTranscriptSHA256, "worker transcript")
	if decodeErr != nil {
		err = decodeErr
		return
	}
	roles := []struct{ name, id, role string }{
		{garblerName, garblerID, "garbler"},
		{evaluatorName, evaluatorID, "evaluator"},
	}
	for _, role := range roles {
		commitment, ok := release.NoiseCommitments[role.name]
		expectedContext := jointDPCommitmentContext(transcript,
			jointDPGaussianOneDrawCommitmentPurpose+"/"+role.role, role.id)
		if !ok || commitment.ContextSHA256 != hex.EncodeToString(expectedContext[:]) ||
			!jointDPBiomedicalGaussianIsSHA256(commitment.SeedSHA256) {
			err = fmt.Errorf("joint-dp-biomedical-gaussian: invalid pinned noise commitment")
			return
		}
	}
	return
}

func jointDPBiomedicalGaussianBuildReleaseBinding(
	manifest jointDPBiomedicalGaussianManifestContract,
	release jointDPBiomedicalGaussianReleaseContract,
	certificate jointDPBiomedicalGaussianSensitivityCertificate,
	workerCertificate formalGLMPhase15DPSensitivityCertificate,
	workerCertificateSHA256, garblerName, garblerID,
	evaluatorName, evaluatorID string,
) (formalGLMPhase16ReleaseBinding, error) {
	garblerCommitment := release.NoiseCommitments[garblerName]
	evaluatorCommitment := release.NoiseCommitments[evaluatorName]
	zero := make([]string, manifest.TotalCoordinateCount)
	for index := range zero {
		zero[index] = "0"
	}
	return formalGLMPhase16ReleaseBinding{
		Version:               formalGLMPhase16ReleaseVersion,
		CapsuleID:             manifest.CapsuleID,
		ManifestSHA256:        manifest.ManifestSHA256,
		SchemaManifestSHA256:  manifest.SchemaManifestSHA256,
		WorkloadSHA256:        manifest.WorkloadSHA256,
		SourceContextSHA256:   manifest.SourceContextSHA256,
		CoordinateOrderSHA256: manifest.CoordinateOrderSHA256,
		ReleaseInstanceID:     release.ReleaseInstanceID,
		// The generic worker historically names this its release contract.
		// The biomedical admission separately binds the actual release hash and
		// requires this field to equal the worker transcript.
		ReleaseContractSHA256:           release.WorkerTranscriptSHA256,
		Phase15PlanSHA256:               manifest.ManifestSHA256,
		Phase15BridgeSHA256:             workerCertificateSHA256,
		FinalReceiptPairSHA256:          release.ReleaseContractSHA256,
		SourceFanInTranscriptSHA256:     manifest.SourceContractSHA256,
		FinalCheckpointTranscriptSHA256: release.ReleaseContractSHA256,
		SnapshotSHA256:                  manifest.LogicalSnapshotSHA256,
		PinsetSHA256:                    manifest.PinsetSHA256,
		KernelSpecSHA256:                manifest.WorkloadSHA256,
		BoundsSHA256:                    manifest.LatticeTransformSHA256,
		QuantizationSHA256:              manifest.LatticeTransformSHA256,
		Family:                          "biomedical_capsule_vector",
		Adjacency:                       manifest.Adjacency,
		Mechanism:                       jointDPGaussianOneDrawMechanism,
		Allocation:                      jointDPGaussianOneDrawAllocation,
		Epsilon:                         release.Epsilon, AllocatedDelta: release.AllocatedDelta,
		SourceRingBits: 128, CommonRingBits: 128,
		SourceFracBits: 0, OutputLatticeBits: manifest.OutputLatticeBits,
		QuantizationShift: 0, CoordinateCount: manifest.TotalCoordinateCount,
		ShiftedUpperBounds: append([]string(nil), certificate.ShiftedUpperBounds...),
		SignedLowerBounds:  zero,
		SignedUpperBounds:  append([]string(nil), certificate.ShiftedUpperBounds...),
		SensitivitySteps:   certificate.SelectedBoundSteps,
		SensitivityNorm:    "l2", SensitivityProof: jointDPBiomedicalGaussianL2Proof,
		SensitivityCertificateKind:   jointDPGaussianOneDrawSensitivityCertificateKind,
		SensitivityCertificateSHA256: workerCertificateSHA256,
		SensitivityCertificate:       workerCertificate,
		TightSensitivityStatus:       "exact_machine_derived_typed_contribution_domain_v1",
		GarblerPeerName:              garblerName, GarblerPeerID: garblerID,
		EvaluatorPeerName: evaluatorName, EvaluatorPeerID: evaluatorID,
		GarblerCommitmentContext:   garblerCommitment.ContextSHA256,
		GarblerSeedCommitment:      garblerCommitment.SeedSHA256,
		EvaluatorCommitmentContext: evaluatorCommitment.ContextSHA256,
		EvaluatorSeedCommitment:    evaluatorCommitment.SeedSHA256,
		CustodianCount:             manifest.CustodianCount,
		RoleSelection:              jointDPBiomedicalGaussianRoleSelection,
		Quantization:               "coordinate_specific_exact_left_shift_inside_gc_v1",
		SignedDecode:               "ring128_signed_decode_after_selective_share_reconstruction_v1",
		QuantizationError:          "zero_for_integer_source_coordinates",
		RangeCertificate:           jointDPBiomedicalGaussianNoWrap,
		NoWrapCertificate:          jointDPBiomedicalGaussianNoWrap,
		Noise:                      jointDPGaussianOneDrawSampler,
		OpeningCount:               1,
		Opening:                    "single_common_dp_capsule_vector_only",
		ProductionReady:            false,
	}, nil
}

func jointDPBiomedicalGaussianPrepareCandidate(
	manifestAttestation jointDPBiomedicalGaussianManifestAttestation,
	release jointDPBiomedicalGaussianReleaseContract,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianCandidate, error) {
	var zero jointDPBiomedicalGaussianCandidate
	certificate, err := jointDPBiomedicalGaussianValidateManifestAttestation(
		manifestAttestation, pins)
	if err != nil {
		return zero, err
	}
	manifest := manifestAttestation.Contract
	garblerName, garblerID, evaluatorName, evaluatorID, err :=
		jointDPBiomedicalGaussianValidateRelease(release, manifest, pins)
	if err != nil {
		return zero, err
	}
	manifestDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianManifestDomain, manifest)
	if err != nil {
		return zero, err
	}
	manifestSignatures, err := jointDPBiomedicalGaussianSignatureSetDigest(
		manifestAttestation.Signatures)
	if err != nil {
		return zero, err
	}
	manifestAttestationDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianManifestDomain+"/attestation", struct {
			ManifestSHA256     string `json:"manifest_sha256"`
			SignatureSetSHA256 string `json:"signature_set_sha256"`
		}{hex.EncodeToString(manifestDigest[:]), hex.EncodeToString(manifestSignatures[:])})
	if err != nil {
		return zero, err
	}
	certificateDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianSensitivityDomain, certificate)
	if err != nil {
		return zero, err
	}
	workerCertificate := jointDPBiomedicalGaussianWorkerCertificate(
		manifest, certificate, hex.EncodeToString(manifestAttestationDigest[:]),
		hex.EncodeToString(certificateDigest[:]))
	workerCertificateDigest, err := formalGLMPhase15DPSensitivityCertificateDigest(
		workerCertificate)
	if err != nil {
		return zero, err
	}
	plan, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: release.Epsilon, Delta: release.AllocatedDelta,
		L2SensitivitySteps:   certificate.SelectedBoundSteps,
		TotalCoordinateCount: manifest.TotalCoordinateCount,
	})
	if err != nil {
		return zero, err
	}
	if !plan.CapabilityAvailable || !plan.NoWrapCertified ||
		plan.MaximumChunkCoordinates < 1 ||
		release.MaximumChunkCoordinates != plan.MaximumChunkCoordinates {
		return zero, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("joint-dp-biomedical-gaussian: one-draw plan is unavailable or release-substituted"))
	}
	maximumNoise, err := jointDPBiomedicalGaussianParseCanonicalInt(
		plan.MaximumNoiseMagnitude, "maximum noise magnitude", false)
	if err != nil || maximumNoise.Cmp(exactGCMaxSigned(128)) > 0 {
		return zero, exactGCFailure(exactGCFailureBoundExceeded,
			fmt.Errorf("joint-dp-biomedical-gaussian: noise support outside signed Ring128"))
	}
	releaseBinding, err := jointDPBiomedicalGaussianBuildReleaseBinding(
		manifest, release, certificate, workerCertificate,
		hex.EncodeToString(workerCertificateDigest[:]),
		garblerName, garblerID, evaluatorName, evaluatorID)
	if err != nil {
		return zero, err
	}
	releaseBindingDigest, err := formalGLMPhase16ReleaseBindingDigest(releaseBinding)
	if err != nil {
		return zero, err
	}
	planSHA, err := jointDPBiomedicalGaussianHash(plan)
	if err != nil {
		return zero, err
	}
	preimage := jointDPBiomedicalGaussianAdmissionPreimage{
		Version:                   jointDPBiomedicalGaussianAdmissionVersion,
		ManifestAttestationSHA256: hex.EncodeToString(manifestAttestationDigest[:]),
		CapsuleID:                 manifest.CapsuleID, ManifestSHA256: manifest.ManifestSHA256,
		SchemaManifestSHA256:         manifest.SchemaManifestSHA256,
		WorkloadSHA256:               manifest.WorkloadSHA256,
		SourceContextSHA256:          manifest.SourceContextSHA256,
		SourceContractSHA256:         manifest.SourceContractSHA256,
		LogicalSnapshotSHA256:        manifest.LogicalSnapshotSHA256,
		CoordinateOrderSHA256:        manifest.CoordinateOrderSHA256,
		LatticeTransformSHA256:       manifest.LatticeTransformSHA256,
		SensitivityCertificateSHA256: hex.EncodeToString(certificateDigest[:]),
		WorkerSensitivitySHA256:      hex.EncodeToString(workerCertificateDigest[:]),
		PrivacyPlanSHA256:            planSHA, ReleaseBindingSHA256: releaseBindingDigest,
		ReleaseInstanceID:          release.ReleaseInstanceID,
		ReleaseContractSHA256:      release.ReleaseContractSHA256,
		WorkerTranscriptSHA256:     release.WorkerTranscriptSHA256,
		PinsetSHA256:               manifest.PinsetSHA256,
		CustodianPeers:             append([]string(nil), manifest.CustodianPeers...),
		CustodianCount:             manifest.CustodianCount,
		DesignatedComputePeers:     append([]string(nil), manifest.DesignatedComputePeers...),
		DesignatedComputePeerCount: 2,
		GarblerPeerName:            garblerName, GarblerPeerID: garblerID,
		EvaluatorPeerName: evaluatorName, EvaluatorPeerID: evaluatorID,
		RoleSelection: jointDPBiomedicalGaussianRoleSelection,
		Mechanism:     jointDPGaussianOneDrawMechanism,
		Allocation:    jointDPGaussianOneDrawAllocation,
		Epsilon:       release.Epsilon, AllocatedDelta: release.AllocatedDelta,
		RingBits: 128, OutputLatticeBits: manifest.OutputLatticeBits,
		TotalCoordinateCount:                manifest.TotalCoordinateCount,
		MaximumChunkCoordinates:             plan.MaximumChunkCoordinates,
		L2SensitivitySteps:                  certificate.SelectedBoundSteps,
		MaximumNoiseMagnitude:               plan.MaximumNoiseMagnitude,
		ShiftedUpperBounds:                  append([]string(nil), certificate.ShiftedUpperBounds...),
		ChunkPolicy:                         jointDPBiomedicalGaussianChunkPolicy,
		NoWrapCertificate:                   jointDPBiomedicalGaussianNoWrap,
		ThreatModel:                         jointDPBiomedicalGaussianThreatModel,
		AtLeastOneHonestDesignatedPeer:      true,
		StickyAbsoluteCoordinates:           true,
		ReleaseInstanceCompositionAccounted: true,
		OperationLimit:                      false, RequestLimit: false,
		HistoryCanDenyOperation:  false,
		ProtectedDataE2EVerified: false, ProductionReady: false,
	}
	return jointDPBiomedicalGaussianCandidate{
		preimage: preimage, manifest: manifest, release: release,
		certificate: certificate, workerCertificate: workerCertificate,
		releaseBinding: releaseBinding, plan: plan,
	}, nil
}

func jointDPBiomedicalGaussianAdmissionSeal(candidate *jointDPBiomedicalGaussianCandidate,
	manifestSignatureSet, admissionSignatureSet [32]byte,
) ([32]byte, error) {
	if candidate == nil {
		return [32]byte{}, errors.New("joint-dp-biomedical-gaussian: missing private candidate")
	}
	preimage, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianAdmissionDomain, candidate.preimage)
	if err != nil {
		return [32]byte{}, err
	}
	candidateDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianSealDomain+"/candidate", struct {
			Preimage          jointDPBiomedicalGaussianAdmissionPreimage      `json:"preimage"`
			Manifest          jointDPBiomedicalGaussianManifestContract       `json:"manifest"`
			Release           jointDPBiomedicalGaussianReleaseContract        `json:"release"`
			Certificate       jointDPBiomedicalGaussianSensitivityCertificate `json:"certificate"`
			WorkerCertificate formalGLMPhase15DPSensitivityCertificate        `json:"worker_certificate"`
			ReleaseBinding    formalGLMPhase16ReleaseBinding                  `json:"release_binding"`
			Plan              jointDPGaussianOneDrawPlanOutput                `json:"plan"`
		}{candidate.preimage, candidate.manifest, candidate.release,
			candidate.certificate, candidate.workerCertificate,
			candidate.releaseBinding, candidate.plan})
	if err != nil {
		return [32]byte{}, err
	}
	return jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianSealDomain, struct {
			Preimage            string `json:"preimage"`
			Candidate           string `json:"candidate"`
			ManifestSignatures  string `json:"manifest_signatures"`
			AdmissionSignatures string `json:"admission_signatures"`
			ReleaseBinding      string `json:"release_binding"`
		}{hex.EncodeToString(preimage[:]), hex.EncodeToString(candidateDigest[:]),
			hex.EncodeToString(manifestSignatureSet[:]),
			hex.EncodeToString(admissionSignatureSet[:]),
			candidate.preimage.ReleaseBindingSHA256})
}

func admitJointDPBiomedicalGaussianOneDraw(
	manifestAttestation jointDPBiomedicalGaussianManifestAttestation,
	release jointDPBiomedicalGaussianReleaseContract,
	pins map[string]ed25519.PublicKey,
	signed jointDPBiomedicalGaussianSignedAdmission,
) (jointDPBiomedicalGaussianAuthenticatedAdmission, error) {
	var zero jointDPBiomedicalGaussianAuthenticatedAdmission
	candidate, err := jointDPBiomedicalGaussianPrepareCandidate(
		manifestAttestation, release, pins)
	if err != nil {
		return zero, err
	}
	want, _ := jointDPBiomedicalGaussianCanonical(candidate.preimage)
	got, err := jointDPBiomedicalGaussianCanonical(signed.Preimage)
	if err != nil || !bytes.Equal(got, want) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: modified admission preimage")
	}
	message, err := jointDPBiomedicalGaussianAdmissionMessage(candidate.preimage)
	if err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianVerifySignatures(
		message, signed.Signatures, candidate.manifest.CustodianPeers,
		pins, "release admission"); err != nil {
		return zero, err
	}
	manifestSignatures, err := jointDPBiomedicalGaussianSignatureSetDigest(
		manifestAttestation.Signatures)
	if err != nil {
		return zero, err
	}
	admissionSignatures, err := jointDPBiomedicalGaussianSignatureSetDigest(
		signed.Signatures)
	if err != nil {
		return zero, err
	}
	seal, err := jointDPBiomedicalGaussianAdmissionSeal(
		&candidate, manifestSignatures, admissionSignatures)
	if err != nil {
		return zero, err
	}
	preimageDigest, _ := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianAdmissionDomain, candidate.preimage)
	admission := jointDPBiomedicalGaussianAuthenticatedAdmission{
		Version:                      jointDPBiomedicalGaussianAdmissionVersion,
		PreimageSHA256:               hex.EncodeToString(preimageDigest[:]),
		ManifestSignatureSetSHA256:   hex.EncodeToString(manifestSignatures[:]),
		AdmissionSignatureSetSHA256:  hex.EncodeToString(admissionSignatures[:]),
		SensitivityCertificateSHA256: candidate.preimage.SensitivityCertificateSHA256,
		AuthenticatedGatePassed:      true,
		ProtectedDataE2EVerified:     false, OpeningsPerformed: 0,
		ProductionReady: false, candidate: &candidate, seal: seal,
	}
	return admission, &jointDPBiomedicalGaussianReleaseBlocker{
		Code: jointDPBiomedicalGaussianBlockerCode,
		Missing: []string{
			"R projection from the locally memoized biomedical manifest",
			"K-of-K DSI admission receipt collection",
			"authenticated cross-process exact-GC admission token",
			"single common DP-vector opening and durable finalizer",
		},
		OpeningsPerformed: 0,
	}
}

func validateJointDPBiomedicalGaussianAdmission(
	admission jointDPBiomedicalGaussianAuthenticatedAdmission,
) error {
	if admission.Version != jointDPBiomedicalGaussianAdmissionVersion ||
		!admission.AuthenticatedGatePassed || admission.ProtectedDataE2EVerified ||
		admission.OpeningsPerformed != 0 || admission.ProductionReady ||
		admission.candidate == nil || !jointDPBiomedicalGaussianIsSHA256(
		admission.PreimageSHA256) || !jointDPBiomedicalGaussianIsSHA256(
		admission.ManifestSignatureSetSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(admission.AdmissionSignatureSetSHA256) ||
		admission.SensitivityCertificateSHA256 !=
			admission.candidate.preimage.SensitivityCertificateSHA256 {
		return fmt.Errorf("joint-dp-biomedical-gaussian: invalid sealed admission")
	}
	preimage, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianAdmissionDomain, admission.candidate.preimage)
	if err != nil || hex.EncodeToString(preimage[:]) != admission.PreimageSHA256 {
		return fmt.Errorf("joint-dp-biomedical-gaussian: admission preimage changed")
	}
	manifestSignatures, err := jointDPGaussianOneDrawDecodeHex(
		admission.ManifestSignatureSetSHA256, "manifest signature set")
	if err != nil {
		return err
	}
	admissionSignatures, err := jointDPGaussianOneDrawDecodeHex(
		admission.AdmissionSignatureSetSHA256, "admission signature set")
	if err != nil {
		return err
	}
	want, err := jointDPBiomedicalGaussianAdmissionSeal(
		admission.candidate, manifestSignatures, admissionSignatures)
	if err != nil || want != admission.seal {
		return fmt.Errorf("joint-dp-biomedical-gaussian: private admission seal mismatch")
	}
	return nil
}

func jointDPBiomedicalGaussianChunkSeal(
	admission jointDPBiomedicalGaussianAuthenticatedAdmission,
	worker jointDPGaussianOneDrawWorkerContractOutput, start, count int,
) ([32]byte, error) {
	workerHash, err := jointDPBiomedicalGaussianHash(worker)
	if err != nil {
		return [32]byte{}, err
	}
	return jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianChunkSealDomain, struct {
			AdmissionSeal string `json:"admission_seal"`
			Start         int    `json:"start"`
			Count         int    `json:"count"`
			WorkerSHA256  string `json:"worker_sha256"`
		}{hex.EncodeToString(admission.seal[:]), start, count, workerHash})
}

func compileJointDPBiomedicalGaussianChunk(
	admission jointDPBiomedicalGaussianAuthenticatedAdmission,
	chunkStart, coordinateCount int,
) (jointDPBiomedicalGaussianAdmittedChunk, error) {
	var zero jointDPBiomedicalGaussianAdmittedChunk
	if err := validateJointDPBiomedicalGaussianAdmission(admission); err != nil {
		return zero, err
	}
	candidate := admission.candidate
	manifest := candidate.manifest
	if chunkStart < 0 || coordinateCount < 1 ||
		coordinateCount > candidate.plan.MaximumChunkCoordinates ||
		chunkStart > manifest.TotalCoordinateCount-coordinateCount {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: invalid absolute chunk geometry")
	}
	end := chunkStart + coordinateCount
	releaseBindingJSON, err := formalGLMPhase16ReleaseBindingPreimage(
		candidate.releaseBinding)
	if err != nil {
		return zero, err
	}
	workerCertificateDigest, err := formalGLMPhase15DPSensitivityCertificateDigest(
		candidate.workerCertificate)
	if err != nil {
		return zero, err
	}
	worker, err := jointDPCompileGaussianOneDrawWorkerContract(
		jointDPGaussianOneDrawWorkerContractInput{
			Version:  jointDPGaussianOneDrawWorkerContractInputVersion,
			RingBits: 128, FracBits: 0,
			TotalCoordinateCount: manifest.TotalCoordinateCount,
			ChunkStart:           chunkStart, CoordinateCount: coordinateCount,
			OutputLatticeBits:              manifest.OutputLatticeBits,
			Epsilon:                        candidate.release.Epsilon,
			AllocatedDelta:                 candidate.release.AllocatedDelta,
			L2SensitivitySteps:             candidate.certificate.SelectedBoundSteps,
			L2SensitivityCertificateKind:   jointDPGaussianOneDrawSensitivityCertificateKind,
			L2SensitivityCertificateSHA256: hex.EncodeToString(workerCertificateDigest[:]),
			ReleaseBindingDomain:           formalGLMPhase16ReleaseDomain,
			ReleaseBindingCanonicalJSON:    string(releaseBindingJSON),
			ScaleShifts:                    append([]int(nil), manifest.ScaleShifts[chunkStart:end]...),
			RawUpperBounds:                 append([]string(nil), manifest.RawUpperBounds[chunkStart:end]...),
			ReleaseBindingSHA256:           candidate.preimage.ReleaseBindingSHA256,
			CrossSignedPolicySHA256:        candidate.preimage.ReleaseBindingSHA256,
			TranscriptHash:                 candidate.release.WorkerTranscriptSHA256,
			PinsetSHA256:                   manifest.PinsetSHA256,
			CustodianCount:                 manifest.CustodianCount,
			DesignatedComputePeerCount:     2,
			GarblerPeerID:                  candidate.preimage.GarblerPeerID,
			EvaluatorPeerID:                candidate.preimage.EvaluatorPeerID,
			GarblerCommitmentContext:       candidate.release.NoiseCommitments[candidate.preimage.GarblerPeerName].ContextSHA256,
			EvaluatorCommitmentContext:     candidate.release.NoiseCommitments[candidate.preimage.EvaluatorPeerName].ContextSHA256,
			GarblerSeedCommitment:          candidate.release.NoiseCommitments[candidate.preimage.GarblerPeerName].SeedSHA256,
			EvaluatorSeedCommitment:        candidate.release.NoiseCommitments[candidate.preimage.EvaluatorPeerName].SeedSHA256,
		})
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(worker.Plan, candidate.plan) ||
		worker.WorkerPolicy.ReleaseBindingSHA256 != candidate.preimage.ReleaseBindingSHA256 ||
		worker.WorkerPolicy.TranscriptHash != candidate.preimage.WorkerTranscriptSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian: deterministic worker derivation changed")
	}
	seal, err := jointDPBiomedicalGaussianChunkSeal(
		admission, worker, chunkStart, coordinateCount)
	if err != nil {
		return zero, err
	}
	return jointDPBiomedicalGaussianAdmittedChunk{
		Version:         jointDPBiomedicalGaussianChunkVersion,
		AdmissionSHA256: admission.PreimageSHA256,
		ChunkStart:      chunkStart, CoordinateCount: coordinateCount,
		CircuitDigest: worker.CircuitDigest, Purpose: worker.Purpose,
		StickyAbsoluteCoordinates: true, ProductionReady: false,
		worker: &worker, seal: seal,
	}, nil
}

func validateJointDPBiomedicalGaussianChunk(
	admission jointDPBiomedicalGaussianAuthenticatedAdmission,
	chunk jointDPBiomedicalGaussianAdmittedChunk,
) error {
	if err := validateJointDPBiomedicalGaussianAdmission(admission); err != nil {
		return err
	}
	if chunk.Version != jointDPBiomedicalGaussianChunkVersion ||
		chunk.AdmissionSHA256 != admission.PreimageSHA256 ||
		chunk.ChunkStart < 0 || chunk.CoordinateCount < 1 ||
		!chunk.StickyAbsoluteCoordinates || chunk.ProductionReady ||
		chunk.worker == nil || chunk.CircuitDigest != chunk.worker.CircuitDigest ||
		chunk.Purpose != chunk.worker.Purpose ||
		chunk.worker.WorkerPolicy.ChunkStart != chunk.ChunkStart ||
		chunk.worker.WorkerPolicy.CoordinateCount != chunk.CoordinateCount {
		return fmt.Errorf("joint-dp-biomedical-gaussian: invalid admitted chunk")
	}
	want, err := jointDPBiomedicalGaussianChunkSeal(
		admission, *chunk.worker, chunk.ChunkStart, chunk.CoordinateCount)
	if err != nil || want != chunk.seal {
		return fmt.Errorf("joint-dp-biomedical-gaussian: private chunk seal mismatch")
	}
	return nil
}

func authorizeJointDPBiomedicalGaussianOpening(
	admission jointDPBiomedicalGaussianAuthenticatedAdmission,
	chunk jointDPBiomedicalGaussianAdmittedChunk,
) error {
	if err := validateJointDPBiomedicalGaussianChunk(admission, chunk); err != nil {
		return err
	}
	return &jointDPBiomedicalGaussianReleaseBlocker{
		Code: jointDPBiomedicalGaussianBlockerCode,
		Missing: []string{
			"authenticated cross-process exact-GC admission token",
			"R/DSI server-authoritative source handoff",
			"single common DP-vector opening and durable finalizer",
		},
		OpeningsPerformed: 0,
	}
}
