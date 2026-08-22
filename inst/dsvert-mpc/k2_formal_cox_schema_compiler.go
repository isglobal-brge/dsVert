package main

// Server-local compiler from the unanimously signed R Cox schema to the exact
// Go lattice policy.  The command consumes only public, custodian-signed
// metadata.  It is intentionally absent from runtime-capabilities and never
// accepts source shares, randomness, an analyst-selected sensitivity, or an
// opening request.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
)

const (
	formalCoxSchemaCompilerInputVersion  = "dsvert-formal-cox-r-to-go-compiler-input-v1"
	formalCoxSchemaCompilerOutputVersion = "dsvert-formal-cox-r-to-go-compiler-output-v2"
	formalCoxRSchemaVersion              = "dsvert-formal-cox-schema-v1"
	formalCoxRSealVersion                = "dsvert-formal-cox-seal-v1"
	formalCoxRSignatureDomain            = "dsVert/formal-cox/schema-signature/v1|"
	formalCoxRSchemaDomain               = "dsVert/formal-cox/schema/v1|"
	formalCoxRPinsetDomain               = "dsVert/formal-cox/pinset/v1|"
	formalCoxRSensitivityTheorem         = "hung-yu-lemma9-with-left-truncation-extension-v2"
	formalCoxRAlgorithm                  = "interactive-projected-noisy-gradient-central-dp-candidate-v1"
	formalCoxREstimand                   = "bounded-ridge-grid-breslow-cox-ph-partial-likelihood-v1"
	formalCoxCompilerContract            = "signed-r-schema-to-exact-lattice-policy-no-client-sensitivity-override-v1"
)

type formalCoxRationalSchema struct {
	Numerator   string `json:"numerator"`
	Denominator string `json:"denominator"`
}

type formalCoxRUnsignedSchema struct {
	Version                 string                  `json:"version"`
	ArtifactSHA256          string                  `json:"artifact_sha256"`
	LogicalSnapshotID       string                  `json:"logical_snapshot_id"`
	PeerPinset              map[string]string       `json:"peer_pinset"`
	PeerPinsetSHA256        string                  `json:"peer_pinset_sha256"`
	ComputePeers            []string                `json:"compute_peers"`
	OutcomeOwner            string                  `json:"outcome_owner"`
	CovariateOwners         map[string]string       `json:"covariate_owners"`
	Estimand                string                  `json:"estimand"`
	Response                string                  `json:"response"`
	EntryMode               string                  `json:"entry_mode"`
	Ties                    string                  `json:"ties"`
	GridSemantics           string                  `json:"grid_semantics"`
	Strata                  string                  `json:"strata"`
	CaseWeights             string                  `json:"case_weights"`
	TimeDependentCovariates string                  `json:"time_dependent_covariates"`
	RecurrentEvents         string                  `json:"recurrent_events"`
	PrivacyUnit             string                  `json:"privacy_unit"`
	Adjacency               string                  `json:"adjacency"`
	AdjacencyInterpretation string                  `json:"adjacency_interpretation"`
	Capacity                string                  `json:"capacity"`
	MinimumAtRiskPerEvent   string                  `json:"minimum_at_risk_per_event"`
	TimeGridTicks           []string                `json:"time_grid_ticks"`
	FracBits                string                  `json:"frac_bits"`
	XLowerLattice           map[string]string       `json:"x_lower_lattice"`
	XUpperLattice           map[string]string       `json:"x_upper_lattice"`
	CovariateL2BoundLattice string                  `json:"covariate_l2_bound_lattice"`
	BetaL2BoundLattice      string                  `json:"beta_l2_bound_lattice"`
	Iterations              string                  `json:"iterations"`
	StepSize                formalCoxRationalSchema `json:"step_size"`
	Ridge                   formalCoxRationalSchema `json:"ridge"`
	Epsilon                 formalCoxRationalSchema `json:"epsilon"`
	Delta                   formalCoxRationalSchema `json:"delta"`
	Algorithm               string                  `json:"algorithm"`
	SensitivityTheorem      string                  `json:"sensitivity_theorem"`
	ReductionOrder          string                  `json:"reduction_order"`
	SourceLayout            string                  `json:"source_layout"`
	Alignment               string                  `json:"alignment"`
	Opening                 string                  `json:"opening"`
	ExactOutputsForbidden   []string                `json:"exact_outputs_forbidden"`
}

type formalCoxRSealedSchema struct {
	Version      string                   `json:"version"`
	Unsigned     formalCoxRUnsignedSchema `json:"unsigned"`
	Signatures   map[string]string        `json:"signatures"`
	SchemaSHA256 string                   `json:"schema_sha256"`
}

type formalCoxSchemaCompilerInput struct {
	Version string          `json:"version"`
	Schema  json.RawMessage `json:"schema"`
}

type formalCoxTheoremReconciliation struct {
	Version                         string `json:"version"`
	SignedRTheorem                  string `json:"signed_r_theorem"`
	ImplementedLatticeProof         string `json:"implemented_lattice_proof"`
	ReleaseCalibrationAuthority     string `json:"release_calibration_authority"`
	RReferenceFormulaUsedForRelease bool   `json:"r_reference_formula_used_for_release"`
	ClientSensitivityOverrideUsed   bool   `json:"client_sensitivity_override_used"`
	ExactLatticeSensitivitySteps    string `json:"exact_lattice_sensitivity_steps"`
	AdaptiveStackSensitivitySteps   string `json:"adaptive_stack_sensitivity_steps"`
	FiniteSupportTVChargedToDelta   bool   `json:"finite_support_tv_charged_to_delta"`
}

type formalCoxSchemaCompilerOutput struct {
	Version                    string                               `json:"version"`
	SchemaSHA256               string                               `json:"schema_sha256"`
	RSchemaSignaturesVerified  bool                                 `json:"r_schema_signatures_verified"`
	Policy                     formalCoxPhase1Policy                `json:"policy"`
	PolicySHA256               string                               `json:"policy_sha256"`
	DPPlan                     formalCoxDPPlan                      `json:"dp_plan"`
	NumericCertificate         formalCoxBlockwiseNumericCertificate `json:"blockwise_numeric_certificate"`
	NumericCertificateSHA256   string                               `json:"blockwise_numeric_certificate_sha256"`
	TheoremReconciliation      formalCoxTheoremReconciliation       `json:"theorem_reconciliation"`
	AnalystControlledOverrides bool                                 `json:"analyst_controlled_overrides"`
	SourceSharesAccepted       bool                                 `json:"source_shares_accepted"`
	NoiseSeedAccepted          bool                                 `json:"noise_seed_accepted"`
	OpeningsPerformed          int                                  `json:"openings_performed"`
	ProductionReady            bool                                 `json:"production_ready"`
	Blockers                   []string                             `json:"blockers"`
}

func formalCoxRejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("formal-cox: duplicate or invalid JSON field")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return fmt.Errorf("formal-cox: malformed JSON object")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return fmt.Errorf("formal-cox: malformed JSON array")
			}
		default:
			return fmt.Errorf("formal-cox: invalid JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("formal-cox: trailing JSON input")
	}
	return nil
}

func formalCoxCanonicalJSONValue(value interface{}) ([]byte, error) {
	return json.Marshal(value)
}

func formalCoxSchemaDecode(raw json.RawMessage) (
	formalCoxRSealedSchema, map[string]interface{}, error) {
	var schema formalCoxRSealedSchema
	if len(raw) < 2 || len(raw) > 4<<20 {
		return schema, nil, fmt.Errorf("formal-cox: invalid signed schema size")
	}
	if err := formalCoxRejectDuplicateJSON(raw); err != nil {
		return schema, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&schema); err != nil {
		return schema, nil, fmt.Errorf("formal-cox: decode signed schema: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return schema, nil, fmt.Errorf("formal-cox: trailing signed schema")
	}
	genericDecoder := json.NewDecoder(bytes.NewReader(raw))
	genericDecoder.UseNumber()
	var generic map[string]interface{}
	if err := genericDecoder.Decode(&generic); err != nil {
		return schema, nil, err
	}
	return schema, generic, nil
}

func formalCoxCompilerCanonicalSmallUnsigned(value, name string,
	allowZero bool) (*big.Int, error) {
	parsed, err := formalCoxCanonicalSigned(value, name)
	limit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 53), big.NewInt(1))
	if err != nil || parsed.Sign() < 0 || !allowZero && parsed.Sign() == 0 ||
		parsed.Cmp(limit) > 0 {
		return nil, fmt.Errorf("formal-cox: invalid signed-schema %s", name)
	}
	return parsed, nil
}

func formalCoxCompilerCanonicalRSigned(value, name string) (*big.Int, error) {
	parsed, err := formalCoxCanonicalSigned(value, name)
	limit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 53), big.NewInt(1))
	if err != nil || new(big.Int).Abs(new(big.Int).Set(parsed)).Cmp(limit) > 0 {
		return nil, fmt.Errorf("formal-cox: invalid signed-schema %s", name)
	}
	return parsed, nil
}

func formalCoxCompilerRLabel(value string) bool {
	if len(value) < 1 || len(value) > 128 ||
		!((value[0] >= 'A' && value[0] <= 'Z') ||
			(value[0] >= 'a' && value[0] <= 'z')) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !((character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:-", rune(character))) {
			return false
		}
	}
	return true
}

func formalCoxCompilerRational(value formalCoxRationalSchema, name string,
	allowZero bool) (*big.Rat, error) {
	numerator, err := formalCoxCompilerCanonicalSmallUnsigned(
		value.Numerator, name+" numerator", allowZero)
	if err != nil {
		return nil, err
	}
	denominator, err := formalCoxCompilerCanonicalSmallUnsigned(
		value.Denominator, name+" denominator", false)
	if err != nil {
		return nil, err
	}
	return new(big.Rat).SetFrac(numerator, denominator), nil
}

func formalCoxCompilerRoundRatToLattice(value *big.Rat, scale *big.Int) *big.Int {
	numerator := new(big.Int).Mul(value.Num(), scale)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, value.Denom(), remainder)
	if new(big.Int).Lsh(remainder, 1).Cmp(value.Denom()) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}

func formalCoxCompilerDecimalDown(value *big.Rat) (string, error) {
	if value == nil || value.Sign() <= 0 {
		return "", fmt.Errorf("formal-cox: invalid privacy rational")
	}
	decimalScale := new(big.Int).Exp(big.NewInt(10), big.NewInt(40), nil)
	scaled := new(big.Int).Quo(
		new(big.Int).Mul(value.Num(), decimalScale), value.Denom())
	if scaled.Sign() <= 0 {
		return "", fmt.Errorf("formal-cox: privacy rational underflows compiler precision")
	}
	digits := scaled.String()
	if len(digits) <= 40 {
		digits = strings.Repeat("0", 41-len(digits)) + digits
	}
	point := len(digits) - 40
	result := digits[:point] + "." + digits[point:]
	result = strings.TrimRight(result, "0")
	result = strings.TrimSuffix(result, ".")
	return result, nil
}

func formalCoxCompilerHash(domain string, value interface{}) (string, error) {
	encoded, err := formalCoxCanonicalJSONValue(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(domain), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxCompilerValidateSignedSchema(raw json.RawMessage) (
	formalCoxRSealedSchema, map[string]ed25519.PublicKey, error) {
	var zero formalCoxRSealedSchema
	schema, generic, err := formalCoxSchemaDecode(raw)
	if err != nil {
		return zero, nil, err
	}
	unsignedGeneric, ok := generic["unsigned"]
	if !ok {
		return zero, nil, fmt.Errorf("formal-cox: missing signed schema payload")
	}
	signedGeneric := map[string]interface{}{
		"version": generic["version"], "unsigned": unsignedGeneric,
		"signatures": generic["signatures"],
	}
	wantSchema, err := formalCoxCompilerHash(formalCoxRSchemaDomain, signedGeneric)
	if err != nil || schema.Version != formalCoxRSealVersion ||
		schema.SchemaSHA256 != wantSchema || !formalCoxIsSHA256(schema.SchemaSHA256) {
		return zero, nil, fmt.Errorf("formal-cox: signed R schema commitment mismatch")
	}
	u := schema.Unsigned
	if u.Version != formalCoxRSchemaVersion ||
		u.Estimand != formalCoxREstimand || u.Algorithm != formalCoxRAlgorithm ||
		u.SensitivityTheorem != formalCoxRSensitivityTheorem ||
		u.Ties != "breslow" ||
		u.GridSemantics != "ex_ante_public_exact_ticks_no_runtime_snapping_ties_induced_by_grid_v1" ||
		u.Strata != "single_public_baseline_stratum_only_v1" ||
		u.CaseWeights != "unsupported_unit_weight_only_v1" ||
		u.TimeDependentCovariates != "unsupported_v1" ||
		u.RecurrentEvents != "unsupported_one_record_one_event_per_patient_v1" ||
		u.PrivacyUnit != "one_patient_one_fixed_capacity_slot_v1" ||
		u.AdjacencyInterpretation != "fixed_capacity_replace_one_triple_zero_slot_models_add_remove_v1" ||
		u.ReductionOrder != "grid_then_capacity_slot_then_covariate_v1" ||
		u.SourceLayout != "all_sources_same_fixed_ring128_layout_v1" ||
		u.Alignment != "recipient_shared_exact_gc_consensus_and_mask_required_v3" ||
		u.Opening != "one_final_sticky_dp_beta_vector_only_v1" {
		return zero, nil, fmt.Errorf("formal-cox: unsupported signed R scientific contract")
	}
	if u.EntryMode != "none" && u.EntryMode != "single_interval" ||
		u.Response != map[bool]string{true: "Surv(stop,status)", false: "Surv(entry,stop,status)"}[u.EntryMode == "none"] ||
		u.Adjacency != "add_remove_patient" && u.Adjacency != "replace_one_patient" {
		return zero, nil, fmt.Errorf("formal-cox: invalid signed R survival contract")
	}
	wantForbidden := []string{"score", "hessian", "risk_sets", "event_counts",
		"loglik", "baseline_hazard", "row_validity", "alignment_digest"}
	if len(u.ExactOutputsForbidden) != len(wantForbidden) {
		return zero, nil, fmt.Errorf("formal-cox: incomplete forbidden-output contract")
	}
	for index := range wantForbidden {
		if u.ExactOutputsForbidden[index] != wantForbidden[index] {
			return zero, nil, fmt.Errorf("formal-cox: changed forbidden-output contract")
		}
	}
	if !formalCoxIsSHA256(u.ArtifactSHA256) ||
		!formalCoxCompilerRLabel(u.LogicalSnapshotID) ||
		len(u.PeerPinset) < 2 || len(u.PeerPinset) > formalCoxPhase1MaxCustodians ||
		len(schema.Signatures) != len(u.PeerPinset) {
		return zero, nil, fmt.Errorf("formal-cox: invalid signed R consortium")
	}
	pins := make(map[string]ed25519.PublicKey, len(u.PeerPinset))
	seenPins := make(map[string]bool, len(u.PeerPinset))
	for name, encoded := range u.PeerPinset {
		if !formalCoxCompilerRLabel(name) {
			return zero, nil, fmt.Errorf("formal-cox: invalid signed R custodian")
		}
		decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if decodeErr != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.RawURLEncoding.EncodeToString(decoded) != encoded || seenPins[encoded] {
			clear(decoded)
			return zero, nil, fmt.Errorf("formal-cox: invalid or duplicate Ed25519 pin")
		}
		seenPins[encoded] = true
		pins[name] = ed25519.PublicKey(decoded)
	}
	pinsetHash, err := formalCoxCompilerHash(formalCoxRPinsetDomain, genericUnsignedPinset(unsignedGeneric))
	if err != nil || pinsetHash != u.PeerPinsetSHA256 {
		return zero, nil, fmt.Errorf("formal-cox: signed R pinset digest mismatch")
	}
	unsignedJSON, err := formalCoxCanonicalJSONValue(unsignedGeneric)
	if err != nil {
		return zero, nil, err
	}
	message := append([]byte(formalCoxRSignatureDomain), unsignedJSON...)
	for name, pin := range pins {
		encoded, ok := schema.Signatures[name]
		if !ok {
			return zero, nil, fmt.Errorf("formal-cox: incomplete unanimous schema approval")
		}
		signature, decodeErr := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if decodeErr != nil || len(signature) != ed25519.SignatureSize ||
			base64.RawURLEncoding.EncodeToString(signature) != encoded ||
			!ed25519.Verify(pin, message, signature) {
			clear(signature)
			return zero, nil, fmt.Errorf("formal-cox: invalid unanimous schema approval")
		}
		clear(signature)
	}
	return schema, pins, nil
}

func genericUnsignedPinset(unsigned interface{}) interface{} {
	object, ok := unsigned.(map[string]interface{})
	if !ok {
		return nil
	}
	return object["peer_pinset"]
}

func formalCoxCompilerExpTable(xNorm, betaNorm, scale *big.Int,
	fracBits, covariates int) ([]string, []string, string, int, error) {
	if covariates < 1 {
		return nil, nil, "", 0, fmt.Errorf("formal-cox: invalid exp table dimension")
	}
	eta := formalCoxCeilMulMagnitude(xNorm, betaNorm, scale)
	if eta.Sign() <= 0 || !eta.IsInt64() {
		return nil, nil, "", 0, fmt.Errorf("formal-cox: exp domain is unrepresentable")
	}
	// One floor per covariate can make the quantized eta smaller than the
	// continuous L2 bound.  The parser enforces the same lower margin.
	lower := new(big.Int).Add(new(big.Int).Set(eta),
		big.NewInt(int64(covariates)))
	lower.Neg(lower)
	upper := new(big.Int).Set(eta)
	width := new(big.Int).Sub(upper, lower)
	segments := formalCoxPhase1MaxExpSegments
	if width.Cmp(big.NewInt(int64(segments))) < 0 {
		segments = int(width.Int64())
	}
	if segments < 1 {
		return nil, nil, "", 0, fmt.Errorf("formal-cox: empty exp domain")
	}
	knots := make([]*big.Int, segments+1)
	for index := 0; index <= segments; index++ {
		offset := new(big.Int).Quo(new(big.Int).Mul(
			width, big.NewInt(int64(index))), big.NewInt(int64(segments)))
		knots[index] = new(big.Int).Add(new(big.Int).Set(lower), offset)
		if index > 0 && knots[index].Cmp(knots[index-1]) <= 0 {
			return nil, nil, "", 0, fmt.Errorf("formal-cox: exp knot quantization collapsed")
		}
	}
	certificateBits := 192
	dyadicScale := jointDPGaussianDyadicScale(certificateBits)
	values := make([]*big.Int, segments)
	maximumError := new(big.Int)
	for index := 0; index < segments; index++ {
		left, err := formalCoxExpDyadic(knots[index], scale, certificateBits)
		if err != nil {
			return nil, nil, "", 0, err
		}
		right, err := formalCoxExpDyadic(knots[index+1], scale, certificateBits)
		if err != nil {
			return nil, nil, "", 0, err
		}
		numerator := new(big.Int).Mul(
			new(big.Int).Add(left.low, right.high), scale)
		denominator := new(big.Int).Lsh(new(big.Int).Set(dyadicScale), 1)
		values[index] = exactGCCeilDiv(numerator, denominator)
		if values[index].Sign() <= 0 {
			return nil, nil, "", 0, fmt.Errorf("formal-cox: exp table underflows the lattice")
		}
		valueDyadic := new(big.Int).Mul(values[index], dyadicScale)
		leftDyadic := new(big.Int).Mul(left.low, scale)
		rightDyadic := new(big.Int).Mul(right.high, scale)
		leftError := formalCoxAbs(new(big.Int).Sub(valueDyadic, leftDyadic))
		rightError := formalCoxAbs(new(big.Int).Sub(rightDyadic, valueDyadic))
		segmentError := exactGCCeilDiv(formalCoxMax(leftError, rightError), dyadicScale)
		maximumError = formalCoxMax(maximumError, segmentError)
	}
	knotText := make([]string, len(knots))
	valueText := make([]string, len(values))
	for index := range knots {
		knotText[index] = knots[index].String()
	}
	for index := range values {
		valueText[index] = values[index].String()
	}
	return knotText, valueText, maximumError.String(), certificateBits, nil
}

func formalCoxCompileSignedRSchema(raw json.RawMessage) (
	formalCoxSchemaCompilerOutput, error) {
	var zero formalCoxSchemaCompilerOutput
	schema, pins, err := formalCoxCompilerValidateSignedSchema(raw)
	if err != nil {
		return zero, err
	}
	u := schema.Unsigned
	capacityBig, err := formalCoxCompilerCanonicalSmallUnsigned(u.Capacity, "capacity", false)
	if err != nil || !capacityBig.IsInt64() {
		return zero, fmt.Errorf("formal-cox: invalid signed capacity")
	}
	capacity := int(capacityBig.Int64())
	minimumRiskBig, err := formalCoxCompilerCanonicalSmallUnsigned(
		u.MinimumAtRiskPerEvent, "minimum at risk", false)
	if err != nil || !minimumRiskBig.IsInt64() {
		return zero, fmt.Errorf("formal-cox: invalid signed at-risk floor")
	}
	minimumRisk := int(minimumRiskBig.Int64())
	fracBig, err := formalCoxCompilerCanonicalSmallUnsigned(u.FracBits, "frac bits", false)
	if err != nil || !fracBig.IsInt64() {
		return zero, fmt.Errorf("formal-cox: invalid signed fixed-point precision")
	}
	fracBits := int(fracBig.Int64())
	iterationsBig, err := formalCoxCompilerCanonicalSmallUnsigned(u.Iterations, "iterations", false)
	if err != nil || !iterationsBig.IsInt64() {
		return zero, fmt.Errorf("formal-cox: invalid signed iteration count")
	}
	iterations := int(iterationsBig.Int64())
	if capacity < 2 || capacity > formalCoxBlockwiseMaxCapacity ||
		minimumRisk < 1 || minimumRisk > capacity || fracBits < 8 || fracBits > 40 ||
		iterations < 1 || iterations > formalCoxBlockwiseMaxIterations ||
		len(u.TimeGridTicks) < 2 || len(u.TimeGridTicks) > formalCoxBlockwiseMaxGridTicks ||
		len(u.CovariateOwners) < 1 || len(u.CovariateOwners) > formalCoxPhase1MaxCovariates {
		return zero, fmt.Errorf("formal-cox: signed schema exceeds the reviewed compiler resource envelope")
	}
	previousGrid := new(big.Int)
	for index, value := range u.TimeGridTicks {
		grid, parseErr := formalCoxCompilerCanonicalRSigned(
			value, "time grid tick")
		if parseErr != nil || index > 0 && grid.Cmp(previousGrid) <= 0 {
			return zero, fmt.Errorf("formal-cox: invalid signed time grid")
		}
		previousGrid.Set(grid)
	}
	if _, ok := pins[u.OutcomeOwner]; !ok {
		return zero, fmt.Errorf("formal-cox: outcome owner is not pinned")
	}
	covariates := make([]string, 0, len(u.CovariateOwners))
	for name, owner := range u.CovariateOwners {
		if !formalCoxCompilerRLabel(name) || name == "(Intercept)" {
			return zero, fmt.Errorf("formal-cox: invalid signed covariate layout")
		}
		if _, ok := pins[owner]; !ok {
			return zero, fmt.Errorf("formal-cox: covariate owner is not pinned")
		}
		covariates = append(covariates, name)
	}
	sort.Strings(covariates)
	if len(u.XLowerLattice) != len(covariates) || len(u.XUpperLattice) != len(covariates) {
		return zero, fmt.Errorf("formal-cox: incomplete signed covariate bounds")
	}
	xLower := make([]string, len(covariates))
	xUpper := make([]string, len(covariates))
	for index, name := range covariates {
		lower, lowerOK := u.XLowerLattice[name]
		upper, upperOK := u.XUpperLattice[name]
		if !lowerOK || !upperOK {
			return zero, fmt.Errorf("formal-cox: signed covariate bound names diverge")
		}
		lowerInteger, lowerErr := formalCoxCompilerCanonicalRSigned(
			lower, "covariate lower lattice")
		upperInteger, upperErr := formalCoxCompilerCanonicalRSigned(
			upper, "covariate upper lattice")
		if lowerErr != nil || upperErr != nil || lowerInteger.Cmp(upperInteger) >= 0 {
			return zero, fmt.Errorf("formal-cox: invalid signed covariate bounds")
		}
		xLower[index], xUpper[index] = lower, upper
	}
	peers := make([]string, 0, len(pins))
	for name := range pins {
		peers = append(peers, name)
	}
	sort.Strings(peers)
	type peerRole struct{ name, id string }
	roles := make([]peerRole, len(peers))
	for index, name := range peers {
		id, idErr := formalGLMPhase16PeerID(pins[name])
		if idErr != nil {
			return zero, idErr
		}
		roles[index] = peerRole{name, id}
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].id < roles[j].id })
	if len(u.ComputePeers) != 2 || u.ComputePeers[0] != roles[0].name ||
		u.ComputePeers[1] != roles[1].name {
		return zero, fmt.Errorf("formal-cox: signed compute-peer role order is not cryptographic")
	}
	pinsetSHA256, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		return zero, err
	}
	scale := new(big.Int).Lsh(big.NewInt(1), uint(fracBits))
	xNorm, err := formalCoxCompilerCanonicalRSigned(
		u.CovariateL2BoundLattice, "covariate L2 bound")
	if err != nil || xNorm.Sign() <= 0 {
		return zero, fmt.Errorf("formal-cox: invalid signed covariate L2 bound")
	}
	betaNorm, err := formalCoxCompilerCanonicalRSigned(
		u.BetaL2BoundLattice, "beta L2 bound")
	if err != nil || betaNorm.Sign() <= 0 {
		return zero, fmt.Errorf("formal-cox: invalid signed coefficient L2 bound")
	}
	step, err := formalCoxCompilerRational(u.StepSize, "step size", false)
	if err != nil {
		return zero, err
	}
	ridge, err := formalCoxCompilerRational(u.Ridge, "ridge", true)
	if err != nil {
		return zero, err
	}
	epsilon, err := formalCoxCompilerRational(u.Epsilon, "epsilon", false)
	if err != nil {
		return zero, err
	}
	delta, err := formalCoxCompilerRational(u.Delta, "delta", false)
	if err != nil || delta.Cmp(big.NewRat(1, 1)) >= 0 {
		return zero, fmt.Errorf("formal-cox: invalid signed privacy allocation")
	}
	alphaLattice := formalCoxCompilerRoundRatToLattice(step, scale)
	ridgeLattice := formalCoxCompilerRoundRatToLattice(ridge, scale)
	if alphaLattice.Sign() <= 0 || alphaLattice.Cmp(scale) > 0 ||
		ridge.Sign() > 0 && ridgeLattice.Sign() == 0 {
		return zero, fmt.Errorf("formal-cox: step/ridge cannot be faithfully represented on the signed lattice")
	}
	epsilonText, err := formalCoxCompilerDecimalDown(epsilon)
	if err != nil {
		return zero, err
	}
	deltaText, err := formalCoxCompilerDecimalDown(delta)
	if err != nil {
		return zero, err
	}
	knots, values, expError, certificateBits, err := formalCoxCompilerExpTable(
		xNorm, betaNorm, scale, fracBits, len(covariates))
	if err != nil {
		return zero, err
	}
	compilerHash := sha256.Sum256([]byte(formalCoxCompilerContract))
	theoremHash := sha256.Sum256([]byte(formalCoxRSensitivityTheorem + "|" +
		"implemented_positive_weight_bounded_score_plus_exact_floor_error_adaptive_l2_composition_v1"))
	snapshotPayload := struct {
		Artifact string `json:"artifact_sha256"`
		Logical  string `json:"logical_snapshot_id"`
		Schema   string `json:"schema_sha256"`
	}{u.ArtifactSHA256, u.LogicalSnapshotID, schema.SchemaSHA256}
	snapshotSHA256, err := formalCoxCompilerHash(
		"dsVert/formal-cox/logical-snapshot/v1|", snapshotPayload)
	if err != nil {
		return zero, err
	}
	policy := formalCoxPhase1Policy{
		Version: formalCoxPhase1PolicyVersion, ArtifactSHA256: u.ArtifactSHA256,
		CapsuleSHA256: schema.SchemaSHA256, SnapshotSHA256: snapshotSHA256,
		PinsetSHA256:   pinsetSHA256,
		CompilerSHA256: hex.EncodeToString(compilerHash[:]),
		TheoremSHA256:  hex.EncodeToString(theoremHash[:]),
		CustodianPeers: peers, ComputePeers: append([]string(nil), u.ComputePeers...),
		Adjacency: u.Adjacency, EntryMode: u.EntryMode, Capacity: capacity,
		CovariateCount: len(covariates), GridTickCount: len(u.TimeGridTicks),
		Iterations: iterations, NoiseChunkCount: 1, FracBits: fracBits,
		XLower: xLower, XUpper: xUpper, CovariateL2Bound: xNorm.String(),
		BetaL2Bound: betaNorm.String(), MinimumAtRisk: minimumRisk,
		Alpha: alphaLattice.String(), Ridge: ridgeLattice.String(),
		Epsilon: epsilonText, Delta: deltaText, NoiseBound: "1",
		ExpKnots: knots, ExpValues: values, ExpErrorUpper: expError,
		ExpCertificateBits: certificateBits, Ties: "breslow",
		PrivacyUnit:    "one_patient_one_fixed_capacity_slot_v1",
		ReductionOrder: "grid_then_capacity_slot_then_covariate_v1",
		Truncation:     "exact_signed_floor_after_each_fixed_point_product_v1",
		Projection:     "exact_integer_l2_radial_toward_zero_v1",
		InputLayout:    "capacity_major_all_k_validity_entry_stop_status_design_then_zero_beta_blinding_then_iteration_noise_then_sampler_chunk_validity_v2",
		InputSharing:   "additive_mod_2k_two_recipient_v1",
		NoiseInput:     "one_joint_finite_support_discrete_gaussian_vector_tv_charged_to_delta_v1",
		Output:         "sealed_final_beta_additive_shares_and_xor_execution_validity_v1",
	}
	policy.ExpTableSHA256, err = formalCoxExpTableDigest(policy)
	if err != nil {
		return zero, err
	}
	preDP, err := planFormalCoxBlockwiseDP(policy)
	if err != nil {
		return zero, err
	}
	policy.NoiseBound = preDP.MaximumNoiseMagnitude
	policy.NoiseChunkCount = preDP.SamplerChunkCount
	policy.ExpTableSHA256, err = formalCoxExpTableDigest(policy)
	if err != nil {
		return zero, err
	}
	dpPlan, err := planFormalCoxBlockwiseDP(policy)
	if err != nil || !dpPlan.PrivacyPlanCertified || !dpPlan.PolicyNoiseBoundMatches ||
		!dpPlan.PolicyNoiseChunkCountMatches {
		if err == nil {
			err = fmt.Errorf("formal-cox: compiler failed to close the DP plan")
		}
		return zero, err
	}
	numericCertificate, err := formalCoxBlockwiseNumericCertificateForPolicy(policy)
	if err != nil {
		return zero, err
	}
	numericCertificateSHA256, err := formalCoxBlockwiseNumericCertificateSHA256(
		numericCertificate)
	if err != nil {
		return zero, err
	}
	policyDigest, err := formalCoxPolicyDigest(policy)
	if err != nil {
		return zero, err
	}
	blockers := []string{
		"r_dsi_recipient_encrypted_typed_source_bridge_not_executed_v1",
		"end_to_end_nonlinear_numeric_error_certificate_incomplete_v1",
		"dp_safe_identification_certificate_unavailable_v1",
		"r_dsi_server_to_peer_end_to_end_not_executed_v1",
	}
	return formalCoxSchemaCompilerOutput{
		Version:      formalCoxSchemaCompilerOutputVersion,
		SchemaSHA256: schema.SchemaSHA256, RSchemaSignaturesVerified: true,
		Policy: policy, PolicySHA256: hex.EncodeToString(policyDigest[:]),
		DPPlan:                   dpPlan,
		NumericCertificate:       numericCertificate,
		NumericCertificateSHA256: numericCertificateSHA256,
		TheoremReconciliation: formalCoxTheoremReconciliation{
			Version:                         "dsvert-formal-cox-theorem-reconciliation-v1",
			SignedRTheorem:                  formalCoxRSensitivityTheorem,
			ImplementedLatticeProof:         dpPlan.SensitivityRoute,
			ReleaseCalibrationAuthority:     "go_exact_implemented_lattice_dp_plan_v1",
			RReferenceFormulaUsedForRelease: false,
			ClientSensitivityOverrideUsed:   false,
			ExactLatticeSensitivitySteps:    dpPlan.ScoreSensitivitySteps,
			AdaptiveStackSensitivitySteps:   dpPlan.AdaptiveStackSensitivitySteps,
			FiniteSupportTVChargedToDelta:   dpPlan.FiniteSupportTransferCharged,
		},
		AnalystControlledOverrides: false, SourceSharesAccepted: false,
		NoiseSeedAccepted: false, OpeningsPerformed: 0,
		ProductionReady: false, Blockers: blockers,
	}, nil
}

func handleFormalCoxCompileSignedRSchema() {
	var input formalCoxSchemaCompilerInput
	mpcReadInput(&input)
	if input.Version != formalCoxSchemaCompilerInputVersion || len(input.Schema) == 0 {
		outputError("formal Cox compiler input is invalid")
		return
	}
	result, err := formalCoxCompileSignedRSchema(input.Schema)
	if err != nil {
		outputError("formal Cox compiler rejected the signed schema: " + err.Error())
		return
	}
	mpcWriteOutput(result)
}
