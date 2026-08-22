package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const formalCoxRSchemaFixtureScript = `
source("../../R/mpcUtils.R")
source("../../R/dsiRelay.R")
source("../../R/dpPolicyDS.R")
source("../../R/formalCoxCapsuleInternal.R")
k <- as.integer(commandArgs(trailingOnly = TRUE)[[1L]])
keys <- stats::setNames(
  replicate(k, openssl::ed25519_keygen(), simplify = FALSE),
  paste0("site", seq_len(k)))
pins <- lapply(keys, function(key) {
  public <- as.list(as.list(key)$pubkey)$data
  base64_to_base64url(jsonlite::base64_enc(public))
})
unsigned <- .dsvert_formal_cox_schema_compile(
  artifact_sha256 = paste(rep("1", 64L), collapse = ""),
  logical_snapshot_id = paste0("go_compiler_k", k),
  peer_pinset = pins, outcome_owner = "site1",
  covariate_owners = c(x = "site2"), capacity = 4L,
  time_grid_ticks = 0:3, x_lower = c(x = -0.125),
  x_upper = c(x = 0.125), covariate_l2_bound = 0.125,
  beta_l2_bound = 0.125, minimum_at_risk_per_event = 1L,
  iterations = 1L, step_numerator = 1L, step_denominator = 16L,
  ridge_numerator = 1L, ridge_denominator = 100L,
  epsilon_numerator = 8L, epsilon_denominator = 1L,
  delta_numerator = 1L, delta_denominator = 1000L,
  frac_bits = 8L)
message <- .dsvert_formal_cox_schema_message(unsigned)
signatures <- lapply(keys, function(key) {
  base64_to_base64url(gsub(
    "[\\r\\n[:space:]]", "",
    jsonlite::base64_enc(openssl::ed25519_sign(message, key))))
})
schema <- .dsvert_formal_cox_schema_seal(unsigned, signatures)
cat(.dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(schema)))
`

func formalCoxRSchemaFixture(t testing.TB, custodians int) []byte {
	t.Helper()
	if custodians < 2 || custodians > 5 {
		t.Fatalf("invalid R fixture consortium size %d", custodians)
	}
	if _, err := exec.LookPath("Rscript"); err != nil {
		t.Skip("Rscript is required for the real R-to-Go schema integration test")
	}
	command := exec.Command(
		"Rscript", "--vanilla", "-e", formalCoxRSchemaFixtureScript,
		strconv.Itoa(custodians))
	command.Env = append(os.Environ(), "R_TESTS=")
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("generate canonical R Cox schema for K=%d: %v\n%s",
			custodians, err, raw)
	}
	if !json.Valid(raw) {
		t.Fatalf("R emitted non-JSON Cox schema for K=%d: %q", custodians, raw)
	}
	return bytes.TrimSpace(raw)
}

func formalCoxCompilerRecommitGeneric(t testing.TB,
	generic map[string]interface{},
) []byte {
	t.Helper()
	signed := map[string]interface{}{
		"version":    generic["version"],
		"unsigned":   generic["unsigned"],
		"signatures": generic["signatures"],
	}
	digest, err := formalCoxCompilerHash(formalCoxRSchemaDomain, signed)
	if err != nil {
		t.Fatal(err)
	}
	generic["schema_sha256"] = digest
	raw, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func formalCoxCompilerGeneric(t testing.TB, raw []byte) map[string]interface{} {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic map[string]interface{}
	if err := decoder.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	return generic
}

func formalCoxCompilerResignMutation(t testing.TB, raw []byte,
	mutate func(map[string]interface{}),
) []byte {
	t.Helper()
	generic := formalCoxCompilerGeneric(t, raw)
	unsigned, ok := generic["unsigned"].(map[string]interface{})
	if !ok {
		t.Fatal("fixture unsigned schema is not an object")
	}
	mutate(unsigned)

	oldPins, ok := unsigned["peer_pinset"].(map[string]interface{})
	if !ok || len(oldPins) < 2 {
		t.Fatal("fixture pinset is invalid")
	}
	peerNames := make([]string, 0, len(oldPins))
	for name := range oldPins {
		peerNames = append(peerNames, name)
	}
	sort.Strings(peerNames)
	type signer struct {
		name       string
		id         string
		privateKey ed25519.PrivateKey
	}
	signers := make([]signer, len(peerNames))
	newPins := make(map[string]interface{}, len(peerNames))
	for index, name := range peerNames {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, err := formalGLMPhase16PeerID(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		encoded := base64.RawURLEncoding.EncodeToString(publicKey)
		newPins[name] = encoded
		signers[index] = signer{name: name, id: id, privateKey: privateKey}
	}
	sort.Slice(signers, func(i, j int) bool { return signers[i].id < signers[j].id })
	unsigned["peer_pinset"] = newPins
	pinsetSHA256, err := formalCoxCompilerHash(formalCoxRPinsetDomain, newPins)
	if err != nil {
		t.Fatal(err)
	}
	unsigned["peer_pinset_sha256"] = pinsetSHA256
	unsigned["compute_peers"] = []interface{}{signers[0].name, signers[1].name}
	unsignedJSON, err := formalCoxCanonicalJSONValue(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(formalCoxRSignatureDomain), unsignedJSON...)
	signatures := make(map[string]interface{}, len(signers))
	for _, signer := range signers {
		signatures[signer.name] = base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(signer.privateKey, message))
	}
	generic["signatures"] = signatures
	return formalCoxCompilerRecommitGeneric(t, generic)
}

func TestFormalCoxSchemaCompilerAcceptsCanonicalRSealsK2ThroughK5(t *testing.T) {
	for custodians := 2; custodians <= 5; custodians++ {
		t.Run("K"+strconv.Itoa(custodians), func(t *testing.T) {
			raw := formalCoxRSchemaFixture(t, custodians)
			compiled, err := formalCoxCompileSignedRSchema(raw)
			if err != nil {
				t.Fatalf("compile real canonical R schema: %v", err)
			}
			if !compiled.RSchemaSignaturesVerified ||
				len(compiled.Policy.CustodianPeers) != custodians ||
				len(compiled.Policy.ComputePeers) != 2 ||
				compiled.PolicySHA256 != compiled.DPPlan.PolicySHA256 ||
				compiled.PolicySHA256 != compiled.NumericCertificate.PolicySHA256 {
				t.Fatalf("K=%d compiler bindings diverged: %+v", custodians, compiled)
			}
			if !compiled.NumericCertificate.DynamicRingSelectedFromBounds ||
				!compiled.NumericCertificate.DeterministicNoWrapCertified ||
				!compiled.NumericCertificate.FiniteNoiseNoWrapCertified ||
				!compiled.NumericCertificate.IdealGradientContractionCertified ||
				compiled.NumericCertificate.IdealSmoothnessUpperNumerator == "" ||
				compiled.NumericCertificate.IdealSmoothnessUpperDenominator == "" ||
				compiled.NumericCertificate.IdealContractionFactorNumerator == "" ||
				compiled.NumericCertificate.IdealContractionFactorDenominator == "" ||
				!compiled.NumericCertificate.FixedGridTrajectoryPerturbationCertified ||
				!compiled.NumericCertificate.FixedGridOptimizerDistanceBoundCertified ||
				compiled.NumericCertificate.ImplementedIterationPerturbationL2Steps == "" ||
				compiled.NumericCertificate.FixedGridTrajectoryErrorUpperNumerator == "" ||
				compiled.NumericCertificate.FixedGridTrajectoryErrorUpperDenominator == "" ||
				compiled.NumericCertificate.FixedGridOptimizerDistanceUpperNumerator == "" ||
				compiled.NumericCertificate.FixedGridOptimizerDistanceUpperDenominator == "" ||
				!compiled.NumericCertificate.PerRunCircuitPlanValidationNeeded ||
				compiled.NumericCertificate.RingBits < 128 ||
				compiled.NumericCertificate.RingBits > exactGCMaxRingBits {
				t.Fatalf("K=%d compiler did not close its dynamic no-wrap plan: %+v",
					custodians, compiled.NumericCertificate)
			}
			if compiled.AnalystControlledOverrides || compiled.SourceSharesAccepted ||
				compiled.NoiseSeedAccepted || compiled.OpeningsPerformed != 0 ||
				compiled.ProductionReady ||
				compiled.DPPlan.ProductionReady ||
				compiled.NumericCertificate.ProductionReady ||
				len(compiled.Blockers) == 0 {
				t.Fatalf("K=%d compiler overstated readiness or accepted private input: %+v",
					custodians, compiled)
			}
			if err := formalCoxBlockwiseValidateNumericCertificate(
				compiled.Policy, compiled.NumericCertificate); err != nil {
				t.Fatalf("K=%d compiler emitted invalid blockwise certificate: %v",
					custodians, err)
			}
			parsed, err := parseFormalCoxBlockwisePolicy(compiled.Policy)
			if err != nil {
				t.Fatalf("K=%d compiler emitted invalid blockwise policy: %v",
					custodians, err)
			}
			etaBound := formalCoxCeilMulMagnitude(
				parsed.xNorm, parsed.betaNorm, parsed.scale)
			wantLower := new(big.Int).Add(etaBound,
				big.NewInt(int64(compiled.Policy.CovariateCount)))
			wantLower.Neg(wantLower)
			if parsed.expKnots[0].Cmp(wantLower) > 0 {
				t.Fatalf("K=%d compiler omitted quantized eta margin: %s > %s",
					custodians, parsed.expKnots[0], wantLower)
			}
			digest, err := formalCoxBlockwiseNumericCertificateSHA256(
				compiled.NumericCertificate)
			if err != nil || digest != compiled.NumericCertificateSHA256 {
				t.Fatalf("K=%d compiler certificate digest diverged: %q %v",
					custodians, digest, err)
			}
		})
	}
}

func TestFormalCoxSchemaCompilerAdmitsBlockwiseCapacityBeyondLegacyCircuit(t *testing.T) {
	resigned := formalCoxCompilerResignMutation(t,
		formalCoxRSchemaFixture(t, 2), func(unsigned map[string]interface{}) {
			unsigned["capacity"] = "5"
		})
	compiled, err := formalCoxCompileSignedRSchema(resigned)
	if err != nil {
		t.Fatalf("compile signed blockwise capacity: %v", err)
	}
	if compiled.Policy.Capacity != 5 {
		t.Fatalf("compiler changed the signed blockwise capacity: %+v", compiled.Policy)
	}
	if _, err := parseFormalCoxPhase1Policy(compiled.Policy); err == nil {
		t.Fatalf("compiler used the legacy whole-capacity circuit: %+v", compiled.Policy)
	}
	if _, err := parseFormalCoxBlockwisePolicy(compiled.Policy); err != nil {
		t.Fatalf("compiler did not emit a valid blockwise policy: %v", err)
	}
	if err := formalCoxBlockwiseValidateNumericCertificate(
		compiled.Policy, compiled.NumericCertificate); err != nil {
		t.Fatalf("compiler did not bind its blockwise no-wrap certificate: %v", err)
	}
}

func TestFormalCoxSchemaCompilerAdmitsSignedBlockwiseIterationRange(t *testing.T) {
	resigned := formalCoxCompilerResignMutation(t,
		formalCoxRSchemaFixture(t, 2), func(unsigned map[string]interface{}) {
			unsigned["iterations"] = "12"
		})
	compiled, err := formalCoxCompileSignedRSchema(resigned)
	if err != nil {
		t.Fatalf("compile signed twelve-iteration schedule: %v", err)
	}
	if compiled.Policy.Iterations != 12 {
		t.Fatalf("compiler changed signed iteration count: %+v", compiled.Policy)
	}
	if _, err := parseFormalCoxPhase1Policy(compiled.Policy); err == nil {
		t.Fatalf("compiler used the legacy monolithic iteration limit: %+v", compiled.Policy)
	}
	if _, err := parseFormalCoxBlockwisePolicy(compiled.Policy); err != nil {
		t.Fatalf("compiler did not emit a valid blockwise iteration schedule: %v", err)
	}
}

func TestFormalCoxSchemaCompilerRejectsUnknownDuplicateTamperAndNonUnanimity(t *testing.T) {
	raw := formalCoxRSchemaFixture(t, 3)

	unknown := bytes.Replace(raw, []byte(`"unsigned":{`),
		[]byte(`"unsigned":{"client_score_sensitivity_steps":"1",`), 1)
	if _, err := formalCoxCompileSignedRSchema(unknown); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown client sensitivity was not rejected: %v", err)
	}

	duplicate := append([]byte(`{"version":"duplicate",`), raw[1:]...)
	if _, err := formalCoxCompileSignedRSchema(duplicate); err == nil ||
		!strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate JSON field was not rejected: %v", err)
	}

	tampered := bytes.Replace(raw, []byte(`"capacity":"4"`),
		[]byte(`"capacity":"3"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("test failed to modify the signed capacity")
	}
	if _, err := formalCoxCompileSignedRSchema(tampered); err == nil {
		t.Fatal("tampered signed schema was accepted")
	}

	incomplete := formalCoxCompilerGeneric(t, raw)
	delete(incomplete["signatures"].(map[string]interface{}), "site1")
	incompleteRaw := formalCoxCompilerRecommitGeneric(t, incomplete)
	if _, err := formalCoxCompileSignedRSchema(incompleteRaw); err == nil ||
		!strings.Contains(err.Error(), "consortium") {
		t.Fatalf("non-unanimous schema was not rejected: %v", err)
	}

	forged := formalCoxCompilerGeneric(t, raw)
	signatures := forged["signatures"].(map[string]interface{})
	signatures["site1"] = signatures["site2"]
	forgedRaw := formalCoxCompilerRecommitGeneric(t, forged)
	if _, err := formalCoxCompileSignedRSchema(forgedRaw); err == nil ||
		!strings.Contains(err.Error(), "unanimous") {
		t.Fatalf("forged unanimous approval was not rejected: %v", err)
	}
}

func TestFormalCoxSchemaCompilerRejectsUnanimouslyResignedValuesOutsideRContract(t *testing.T) {
	raw := formalCoxRSchemaFixture(t, 3)
	tests := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{
			name: "non-R logical snapshot label",
			mutate: func(unsigned map[string]interface{}) {
				unsigned["logical_snapshot_id"] = "contains a space"
			},
		},
		{
			name: "grid tick outside exact R integer range",
			mutate: func(unsigned map[string]interface{}) {
				unsigned["time_grid_ticks"] = []interface{}{
					"0", "1", "2", "9007199254740992",
				}
			},
		},
		{
			name: "covariate lattice outside exact R integer range",
			mutate: func(unsigned map[string]interface{}) {
				lower := unsigned["x_lower_lattice"].(map[string]interface{})
				lower["x"] = "-9007199254740992"
			},
		},
		{
			name: "unsupported scientific constant",
			mutate: func(unsigned map[string]interface{}) {
				unsigned["ties"] = "efron"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resigned := formalCoxCompilerResignMutation(t, raw, test.mutate)
			if _, err := formalCoxCompileSignedRSchema(resigned); err == nil {
				t.Fatal("unanimously re-signed schema outside the R contract was accepted")
			}
		})
	}
}

func TestFormalCoxSchemaCompilerDerivesSensitivityOnlyInGo(t *testing.T) {
	compiled, err := formalCoxCompileSignedRSchema(formalCoxRSchemaFixture(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseFormalCoxBlockwisePolicy(compiled.Policy)
	if err != nil {
		t.Fatal(err)
	}
	score, adaptive, _, _ := formalCoxImplementedScoreSensitivity(parsed)
	if compiled.DPPlan.ScoreSensitivitySteps != score.String() ||
		compiled.DPPlan.AdaptiveStackSensitivitySteps != adaptive.String() ||
		compiled.TheoremReconciliation.ExactLatticeSensitivitySteps != score.String() ||
		compiled.TheoremReconciliation.AdaptiveStackSensitivitySteps != adaptive.String() ||
		compiled.TheoremReconciliation.ReleaseCalibrationAuthority !=
			"go_exact_implemented_lattice_dp_plan_v1" ||
		compiled.TheoremReconciliation.RReferenceFormulaUsedForRelease ||
		compiled.TheoremReconciliation.ClientSensitivityOverrideUsed {
		t.Fatalf("compiler did not derive release sensitivity solely in Go: %+v",
			compiled.TheoremReconciliation)
	}
}

func TestFormalCoxSchemaCompilerBoundaryIsDataFreeAndUnadvertised(t *testing.T) {
	inputType := reflect.TypeOf(formalCoxSchemaCompilerInput{})
	wantFields := []string{"Version", "Schema"}
	if inputType.NumField() != len(wantFields) {
		t.Fatalf("compiler input grew a non-schema field: %v", inputType)
	}
	for index, want := range wantFields {
		if inputType.Field(index).Name != want {
			t.Fatalf("compiler input field %d is %q, want %q",
				index, inputType.Field(index).Name, want)
		}
	}
	manifest, err := json.Marshal(runtimeCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range [][]byte{manifest, mainSource} {
		if bytes.Contains(surface, []byte("formal-cox-r-to-go")) ||
			bytes.Contains(surface, []byte("formal-cox-compile")) {
			t.Fatal("unready formal Cox compiler escaped onto the command/capability surface")
		}
	}
}
