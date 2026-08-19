package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type formalCoxBlockwiseStickyGuardFixture struct {
	plan        formalCoxBlockwisePlan
	pins        map[string]ed25519.PublicKey
	private     map[string]ed25519.PrivateKey
	artifact    formalCoxBlockwiseStickyArtifact
	artifactID  string
	roots       map[string][32]byte
	contract    formalCoxBlockwiseSamplerContract
	storageRoot map[string][32]byte
}

func formalCoxBlockwiseStickyGuardTestContract(t testing.TB, custodians int,
	rootTag string,
) formalCoxBlockwiseStickyGuardFixture {
	t.Helper()
	plan, pins, private := formalCoxBlockwiseSourceTestPlan(t, custodians)
	artifact, artifactID, err := formalCoxBlockwiseBuildStickyArtifact(plan, pins)
	if err != nil {
		t.Fatal(err)
	}
	roots := make(map[string][32]byte, 2)
	storageRoots := make(map[string][32]byte, 2)
	commitments := make([]formalCoxBlockwiseSamplerCommitment, 2)
	for index, authority := range artifact.NoiseAuthorities {
		roots[authority.PeerName] = sha256.Sum256([]byte(
			"formal-cox/sticky/authority-root/" + rootTag + "/" +
				authority.PeerName))
		storageRoots[authority.PeerName] = sha256.Sum256([]byte(
			"formal-cox/sticky/storage-root/" + authority.PeerName))
		seed, commitment, deriveErr := formalCoxBlockwiseDeriveSamplerSeed(
			roots[authority.PeerName], artifact, artifactID, authority.Role)
		clear(seed[:])
		if deriveErr != nil {
			t.Fatal(deriveErr)
		}
		commitments[index] = commitment
	}
	contract, err := formalCoxBlockwiseBuildSamplerContract(
		artifact, artifactID, commitments, pins)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]jointDPBiomedicalGaussianSignature, custodians)
	for index, peer := range artifact.CustodianPeers {
		signatures[index], err = formalCoxBlockwiseSignSamplerContract(
			contract, peer, private[peer], pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	contract, err = formalCoxBlockwiseSealSamplerContract(
		contract, signatures, pins)
	if err != nil {
		t.Fatal(err)
	}
	return formalCoxBlockwiseStickyGuardFixture{
		plan: plan, pins: pins, private: private,
		artifact: artifact, artifactID: artifactID,
		roots: roots, contract: contract, storageRoot: storageRoots,
	}
}

func formalCoxBlockwiseStickyGuardTestStore(t testing.TB,
	fixture formalCoxBlockwiseStickyGuardFixture, peer, dir string,
) *formalCoxBlockwiseSamplerGuardStore {
	t.Helper()
	store, err := newFormalCoxBlockwiseSamplerGuardStore(
		dir, peer, fixture.storageRoot[peer], fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func formalCoxBlockwiseStickyGuardTestPreflight(t testing.TB,
	session *formalCoxBlockwiseSourceSession,
	signing map[string]ed25519.PrivateKey,
) (formalCoxBlockwiseSamplerContract,
	[]formalCoxBlockwiseSamplerAuthorization) {
	t.Helper()
	fixture := formalCoxBlockwiseStickyGuardTestContract(
		t, len(session.context.plan.Policy.CustodianPeers), "source-preflight")
	return fixture.contract,
		formalCoxBlockwiseStickyGuardTestAuthorizeFixture(t, fixture, signing)
}

func formalCoxBlockwiseStickyGuardTestAuthorizeFixture(t testing.TB,
	fixture formalCoxBlockwiseStickyGuardFixture,
	signing map[string]ed25519.PrivateKey,
) []formalCoxBlockwiseSamplerAuthorization {
	t.Helper()
	authorizations := make([]formalCoxBlockwiseSamplerAuthorization, 2)
	for index, authority := range fixture.artifact.NoiseAuthorities {
		store := formalCoxBlockwiseStickyGuardTestStore(t, fixture,
			authority.PeerName, filepath.Join(t.TempDir(), authority.Role))
		predecessors := []formalCoxBlockwiseSamplerAuthorization(nil)
		if index == 1 {
			predecessors = authorizations[:1]
		}
		var err error
		authorizations[index], _, err = store.AuthorizeOnce(
			fixture.contract, fixture.roots[authority.PeerName],
			signing[authority.PeerName], predecessors)
		closeErr := store.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("formal Cox test sampler preflight: %v / close=%v", err, closeErr)
		}
	}
	return authorizations
}

func TestFormalCoxBlockwiseCanonicalArtifactK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalCoxBlockwiseStickyGuardTestContract(
				t, custodians, "canonical")
			if err := formalCoxBlockwiseValidateStickyArtifact(
				fixture.artifact, fixture.pins); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(fixture.artifact)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"run_id", "session", "epoch", "reservation", "receipt",
				"release_instance", "lifetime", "request", "rate", "catalog",
				"quota", "ledger", "block_capacity", "transport_ticket",
				"production_ready", "compiler", "theorem", "input_layout",
				"input_sharing", "noise_input", "noise_chunk", "backend",
				"sensitivity_proof", "status",
			} {
				if bytes.Contains(bytes.ToLower(encoded), []byte(forbidden)) {
					t.Fatalf("canonical artifact contains operational field %q", forbidden)
				}
			}
			parsed, err := parseFormalCoxBlockwisePolicy(fixture.plan.Policy)
			if err != nil {
				t.Fatal(err)
			}
			dpPlan, err := planFormalCoxBlockwiseDP(fixture.plan.Policy)
			if err != nil {
				t.Fatal(err)
			}
			baseScientific, err :=
				formalCoxBlockwiseCanonicalScientificPlanSHA256(
					fixture.plan.Policy, parsed)
			if err != nil || baseScientific != fixture.artifact.ScientificPlanSHA256 {
				t.Fatalf("scientific projection mismatch: %v", err)
			}
			baseDP, err := formalCoxBlockwiseCanonicalDPPlanSHA256(dpPlan, parsed)
			if err != nil || baseDP != fixture.artifact.DPPlanSHA256 {
				t.Fatalf("DP projection mismatch: %v", err)
			}

			clonePolicy := func(policy formalCoxPhase1Policy) formalCoxPhase1Policy {
				policy.CustodianPeers = append([]string(nil), policy.CustodianPeers...)
				policy.ComputePeers = append([]string(nil), policy.ComputePeers...)
				policy.XLower = append([]string(nil), policy.XLower...)
				policy.XUpper = append([]string(nil), policy.XUpper...)
				policy.ExpKnots = append([]string(nil), policy.ExpKnots...)
				policy.ExpValues = append([]string(nil), policy.ExpValues...)
				return policy
			}
			assertScientificInvariant := func(name string,
				mutate func(*formalCoxPhase1Policy),
			) {
				t.Helper()
				candidatePolicy := clonePolicy(fixture.plan.Policy)
				mutate(&candidatePolicy)
				candidateHash, hashErr :=
					formalCoxBlockwiseCanonicalScientificPlanSHA256(
						candidatePolicy, parsed)
				candidate := fixture.artifact
				candidate.ScientificPlanSHA256 = candidateHash
				candidateID, idErr := formalCoxBlockwiseStickyArtifactID(candidate)
				if hashErr != nil || idErr != nil || candidateHash != baseScientific ||
					candidateID != fixture.artifactID {
					t.Errorf("operational policy field %s changed artifact ID: %v / %v",
						name, hashErr, idErr)
				}
			}
			for _, test := range []struct {
				name   string
				mutate func(*formalCoxPhase1Policy)
			}{
				{"version", func(policy *formalCoxPhase1Policy) {
					policy.Version += "/transport-upgrade"
				}},
				{"compiler", func(policy *formalCoxPhase1Policy) {
					policy.CompilerSHA256 = strings.Repeat("1", 64)
				}},
				{"theorem", func(policy *formalCoxPhase1Policy) {
					policy.TheoremSHA256 = strings.Repeat("2", 64)
				}},
				{"sampler_chunking", func(policy *formalCoxPhase1Policy) {
					policy.NoiseChunkCount++
				}},
				{"input_layout", func(policy *formalCoxPhase1Policy) {
					policy.InputLayout += "/v3"
				}},
				{"input_sharing", func(policy *formalCoxPhase1Policy) {
					policy.InputSharing += "/v2"
				}},
				{"noise_transport", func(policy *formalCoxPhase1Policy) {
					policy.NoiseInput += "/v2"
				}},
			} {
				t.Run("operational-policy/"+test.name, func(t *testing.T) {
					assertScientificInvariant(test.name, test.mutate)
				})
			}
			backendOnly := fixture.plan
			backendOnly.BackendSelection += "/upgrade"
			backendHash, err :=
				formalCoxBlockwiseCanonicalScientificPlanSHA256(
					backendOnly.Policy, parsed)
			if err != nil || backendHash != baseScientific {
				t.Errorf("backend upgrade changed scientific projection: %v", err)
			}

			assertDPInvariant := func(name string, mutate func(*formalCoxDPPlan)) {
				t.Helper()
				candidatePlan := dpPlan
				candidatePlan.Blockers = append([]string(nil), dpPlan.Blockers...)
				mutate(&candidatePlan)
				candidateHash, hashErr :=
					formalCoxBlockwiseCanonicalDPPlanSHA256(candidatePlan, parsed)
				candidate := fixture.artifact
				candidate.DPPlanSHA256 = candidateHash
				candidateID, idErr := formalCoxBlockwiseStickyArtifactID(candidate)
				if hashErr != nil || idErr != nil || candidateHash != baseDP ||
					candidateID != fixture.artifactID {
					t.Errorf("operational DP field %s changed artifact ID: %v / %v",
						name, hashErr, idErr)
				}
			}
			for _, test := range []struct {
				name   string
				mutate func(*formalCoxDPPlan)
			}{
				{"version", func(plan *formalCoxDPPlan) { plan.Version += "/v2" }},
				{"policy_digest", func(plan *formalCoxDPPlan) {
					plan.PolicySHA256 = strings.Repeat("3", 64)
				}},
				{"chunking", func(plan *formalCoxDPPlan) {
					plan.SamplerChunkCount++
					plan.PolicyNoiseChunkCountMatches = !plan.PolicyNoiseChunkCountMatches
				}},
				{"proof_evidence", func(plan *formalCoxDPPlan) {
					plan.SensitivityRoute += "/v2"
					plan.SensitivityProof += "/reworded"
				}},
				{"sampler_backend", func(plan *formalCoxDPPlan) {
					plan.Sampler += "/v2"
					plan.CommonPlan.Version += "/v2"
					plan.CommonPlan.Reference += "/v2"
				}},
				{"certificate_status", func(plan *formalCoxDPPlan) {
					plan.NoiseCoordinatesFixedShape = !plan.NoiseCoordinatesFixedShape
					plan.PolicyNoiseBoundMatches = !plan.PolicyNoiseBoundMatches
					plan.FiniteSupportTransferCharged = !plan.FiniteSupportTransferCharged
					plan.FixedWorkSampler = !plan.FixedWorkSampler
					plan.NoWrapCertified = !plan.NoWrapCertified
					plan.PrivacyPlanCertified = !plan.PrivacyPlanCertified
				}},
				{"connection_status", func(plan *formalCoxDPPlan) {
					plan.RuntimeNoiseAdapterConnected = !plan.RuntimeNoiseAdapterConnected
					plan.StickyDurableFinalizerConnected =
						!plan.StickyDurableFinalizerConnected
				}},
				{"readiness", func(plan *formalCoxDPPlan) {
					plan.ProductionReady = !plan.ProductionReady
					plan.Blockers = append(plan.Blockers, "new_status_only_blocker")
				}},
			} {
				t.Run("operational-dp/"+test.name, func(t *testing.T) {
					assertDPInvariant(test.name, test.mutate)
				})
			}

			assertScientificChange := func(name string,
				mutate func(*formalCoxPhase1Policy),
			) {
				t.Helper()
				candidatePolicy := clonePolicy(fixture.plan.Policy)
				mutate(&candidatePolicy)
				candidateHash, hashErr :=
					formalCoxBlockwiseCanonicalScientificPlanSHA256(
						candidatePolicy, parsed)
				candidate := fixture.artifact
				candidate.ScientificPlanSHA256 = candidateHash
				candidateID, idErr := formalCoxBlockwiseStickyArtifactID(candidate)
				if hashErr != nil || idErr != nil || candidateHash == baseScientific ||
					candidateID == fixture.artifactID {
					t.Errorf("scientific field %s did not change artifact ID: %v / %v",
						name, hashErr, idErr)
				}
			}
			for _, test := range []struct {
				name   string
				mutate func(*formalCoxPhase1Policy)
			}{
				{"formula", func(policy *formalCoxPhase1Policy) {
					policy.ArtifactSHA256 = strings.Repeat("4", 64)
				}},
				{"column_bindings", func(policy *formalCoxPhase1Policy) {
					policy.CapsuleSHA256 = strings.Repeat("5", 64)
				}},
				{"snapshot_cohort", func(policy *formalCoxPhase1Policy) {
					policy.SnapshotSHA256 = strings.Repeat("6", 64)
				}},
				{"owners", func(policy *formalCoxPhase1Policy) {
					policy.CustodianPeers[0] += "-changed"
				}},
				{"capacity", func(policy *formalCoxPhase1Policy) { policy.Capacity++ }},
				{"mask", func(policy *formalCoxPhase1Policy) {
					if policy.EntryMode == "none" {
						policy.EntryMode = "single_interval"
					} else {
						policy.EntryMode = "none"
					}
				}},
				{"bounds", func(policy *formalCoxPhase1Policy) {
					policy.XLower[0] += "1"
				}},
				{"grid", func(policy *formalCoxPhase1Policy) {
					policy.ExpTableSHA256 = strings.Repeat("7", 64)
				}},
				{"ties", func(policy *formalCoxPhase1Policy) { policy.Ties += "/v2" }},
				{"ridge", func(policy *formalCoxPhase1Policy) { policy.Ridge += "1" }},
				{"iterations", func(policy *formalCoxPhase1Policy) { policy.Iterations++ }},
				{"pinset", func(policy *formalCoxPhase1Policy) {
					policy.PinsetSHA256 = strings.Repeat("8", 64)
				}},
				{"roles", func(policy *formalCoxPhase1Policy) {
					policy.ComputePeers[0], policy.ComputePeers[1] =
						policy.ComputePeers[1], policy.ComputePeers[0]
				}},
				{"noise_support", func(policy *formalCoxPhase1Policy) {
					policy.NoiseBound += "1"
				}},
				{"privacy_unit", func(policy *formalCoxPhase1Policy) {
					policy.PrivacyUnit += "/v2"
				}},
				{"output", func(policy *formalCoxPhase1Policy) { policy.Output += "/v2" }},
			} {
				t.Run("scientific/"+test.name, func(t *testing.T) {
					assertScientificChange(test.name, test.mutate)
				})
			}

			assertDPChange := func(name string, mutate func(*formalCoxDPPlan)) {
				t.Helper()
				candidatePlan := dpPlan
				candidatePlan.CommonPlan.CDFCumulative = append(
					[]string(nil), dpPlan.CommonPlan.CDFCumulative...)
				mutate(&candidatePlan)
				candidateHash, hashErr :=
					formalCoxBlockwiseCanonicalDPPlanSHA256(candidatePlan, parsed)
				candidate := fixture.artifact
				candidate.DPPlanSHA256 = candidateHash
				candidateID, idErr := formalCoxBlockwiseStickyArtifactID(candidate)
				if hashErr != nil || idErr != nil || candidateHash == baseDP ||
					candidateID == fixture.artifactID {
					t.Errorf("DP field %s did not change artifact ID: %v / %v",
						name, hashErr, idErr)
				}
			}
			for _, test := range []struct {
				name   string
				mutate func(*formalCoxDPPlan)
			}{
				{"sensitivity", func(plan *formalCoxDPPlan) {
					plan.AdaptiveStackSensitivitySteps += "1"
				}},
				{"rounding", func(plan *formalCoxDPPlan) {
					plan.NormalizedRoundingL2Steps += "1"
				}},
				{"support", func(plan *formalCoxDPPlan) {
					plan.MaximumNoiseMagnitude += "1"
				}},
				{"finite_support_error", func(plan *formalCoxDPPlan) {
					plan.VectorTotalTVUpperNumerator += "1"
				}},
				{"implementation_delta", func(plan *formalCoxDPPlan) {
					plan.ImplementationDeltaNumerator += "1"
				}},
				{"mechanism", func(plan *formalCoxDPPlan) { plan.Mechanism += "/v2" }},
				{"noise_law_mechanism", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.Mechanism += "/v2"
				}},
				{"noise_law_allocation", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.Allocation += "/v2"
				}},
				{"noise_law_epsilon_numerator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.EpsilonNumerator += "1"
				}},
				{"noise_law_epsilon_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.EpsilonDenominator += "1"
				}},
				{"allocated_delta", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.AllocatedDeltaNumerator += "1"
				}},
				{"allocated_delta_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.AllocatedDeltaDenominator += "1"
				}},
				{"core_delta", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.CoreDeltaNumerator += "1"
				}},
				{"core_delta_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.CoreDeltaDenominator += "1"
				}},
				{"noise_law_sensitivity", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.L2SensitivitySteps += "1"
				}},
				{"rho", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.RhoNumerator += "1"
				}},
				{"rho_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.RhoDenominator += "1"
				}},
				{"sigma_squared", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.SigmaSquaredNumerator += "1"
				}},
				{"sigma_squared_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.SigmaSquaredDenominator += "1"
				}},
				{"noise_law_support", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.MaximumNoiseMagnitude += "1"
				}},
				{"noise_law_tail_tv_numerator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.VectorTailTVUpperNumerator += "1"
				}},
				{"noise_law_tail_tv_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.VectorTailTVUpperDenominator += "1"
				}},
				{"noise_law_cdf_tv_numerator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.VectorCDFTVUpperNumerator += "1"
				}},
				{"noise_law_cdf_tv_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.VectorCDFTVUpperDenominator += "1"
				}},
				{"noise_law_total_tv_numerator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.VectorTotalTVUpperNumerator += "1"
				}},
				{"noise_law_total_tv_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.VectorTotalTVUpperDenominator += "1"
				}},
				{"noise_law_implementation_delta_numerator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.ImplementationDeltaNumerator += "1"
				}},
				{"noise_law_implementation_delta_denominator", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.ImplementationDeltaDenominator += "1"
				}},
				{"noise_draw_count", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.NoiseDrawCount++
				}},
				{"noise_ring", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.RingBits++
				}},
				{"noise_fraction_bits", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.FracBits++
				}},
				{"noise_coordinate_count", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.TotalCoordinateCount++
				}},
				{"sampler_random_bits", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.SamplerRandomBitsPerCoordinate++
				}},
				{"sampler_private_bits", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.SamplerPrivateBitsPerCoordinate++
				}},
				{"sampler_table_precision", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.SamplerTablePrecisionBits++
				}},
				{"sampler_magnitude_count", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.SamplerMagnitudeCount++
				}},
				{"sampler_cdf", func(plan *formalCoxDPPlan) {
					plan.CommonPlan.CDFCumulative[0] += "1"
				}},
			} {
				t.Run("dp/"+test.name, func(t *testing.T) {
					assertDPChange(test.name, test.mutate)
				})
			}

			for _, rational := range []struct {
				name   string
				mutate func(*formalCoxParsedPolicy)
			}{
				{"epsilon", func(candidate *formalCoxParsedPolicy) {
					candidate.epsilon = new(big.Rat).Add(
						parsed.epsilon, big.NewRat(1, 10))
				}},
				{"delta", func(candidate *formalCoxParsedPolicy) {
					candidate.delta = new(big.Rat).Quo(parsed.delta, big.NewRat(2, 1))
				}},
			} {
				t.Run("dp/"+rational.name, func(t *testing.T) {
					candidateParsed := parsed
					rational.mutate(&candidateParsed)
					scientificHash, scientificErr :=
						formalCoxBlockwiseCanonicalScientificPlanSHA256(
							fixture.plan.Policy, candidateParsed)
					dpHash, dpErr := formalCoxBlockwiseCanonicalDPPlanSHA256(
						dpPlan, candidateParsed)
					candidate := fixture.artifact
					candidate.ScientificPlanSHA256 = scientificHash
					candidate.DPPlanSHA256 = dpHash
					candidateID, idErr := formalCoxBlockwiseStickyArtifactID(candidate)
					if scientificErr != nil || dpErr != nil || idErr != nil ||
						scientificHash == baseScientific || dpHash == baseDP ||
						candidateID == fixture.artifactID {
						t.Fatalf("%s did not change artifact ID: %v / %v / %v",
							rational.name, scientificErr, dpErr, idErr)
					}
				})
			}
			readinessOnly := fixture.artifact
			readinessOnly.ProductionReady = true
			readinessID, err := formalCoxBlockwiseStickyArtifactID(readinessOnly)
			if err != nil || readinessID != fixture.artifactID {
				t.Fatalf("readiness changed canonical artifact identity: %v", err)
			}

			physicalRun := sha256.Sum256([]byte(t.Name() + "/physical-run"))
			physical, err := buildFormalCoxBlockwisePlan(
				fixture.plan.Policy, 1, fmt.Sprintf("%x", physicalRun[:]))
			if err != nil {
				t.Fatal(err)
			}
			_, physicalID, err := formalCoxBlockwiseBuildStickyArtifact(
				physical, fixture.pins)
			if err != nil || physicalID != fixture.artifactID {
				t.Fatalf("physical run/geometry changed canonical identity: %v", err)
			}
			upgradedPolicy := fixture.plan.Policy
			upgradedPolicy.CompilerSHA256 = fmt.Sprintf("%x",
				sha256.Sum256([]byte(t.Name()+"/compiler-upgrade")))
			upgradedPolicy.TheoremSHA256 = fmt.Sprintf("%x",
				sha256.Sum256([]byte(t.Name()+"/theorem-upgrade")))
			upgraded, err := buildFormalCoxBlockwisePlan(
				upgradedPolicy, 2, physical.RunID)
			if err != nil {
				t.Fatal(err)
			}
			_, upgradedID, err := formalCoxBlockwiseBuildStickyArtifact(
				upgraded, fixture.pins)
			if err != nil || upgradedID != fixture.artifactID {
				t.Fatalf("compiler/theorem upgrade changed canonical identity: %v", err)
			}
			aliasPolicy := fixture.plan.Policy
			aliasPolicy.Epsilon = "2.0"
			aliasPolicy.Delta = "1e-6"
			alias, err := buildFormalCoxBlockwisePlan(
				aliasPolicy, 2, fixture.plan.RunID)
			if err != nil {
				t.Fatal(err)
			}
			_, aliasID, err := formalCoxBlockwiseBuildStickyArtifact(
				alias, fixture.pins)
			if err != nil || aliasID != fixture.artifactID {
				t.Fatalf("equivalent DP decimal spelling changed identity: %v", err)
			}

			scientificPolicy := fixture.plan.Policy
			scientificPolicy.SnapshotSHA256 =
				fmt.Sprintf("%x", sha256.Sum256([]byte(t.Name()+"/snapshot")))
			scientific, err := buildFormalCoxBlockwisePlan(
				scientificPolicy, 2, fixture.plan.RunID)
			if err != nil {
				t.Fatal(err)
			}
			_, scientificID, err := formalCoxBlockwiseBuildStickyArtifact(
				scientific, fixture.pins)
			if err != nil || scientificID == fixture.artifactID {
				t.Fatalf("scientific snapshot did not change canonical identity: %v", err)
			}
			mismatchedPolicy := fixture.plan.Policy
			mismatchedPolicy.NoiseBound = "1"
			mismatched, err := buildFormalCoxBlockwisePlan(
				mismatchedPolicy, 2, fixture.plan.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := formalCoxBlockwiseBuildStickyArtifact(
				mismatched, fixture.pins); err == nil {
				t.Fatal("noise support differing from the DP certificate reached the guard")
			}
		})
	}
}

func TestFormalCoxBlockwiseSamplerContractKOfKRejectsTamperK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalCoxBlockwiseStickyGuardTestContract(
				t, custodians, "contract")
			if err := formalCoxBlockwiseValidateSamplerContract(
				fixture.contract, fixture.pins); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(fixture.contract)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(bytes.ToLower(encoded), []byte("production_ready")) {
				t.Fatal("sampler contract serialized readiness")
			}
			readinessOnly := fixture.contract
			readinessOnly.ProductionReady = true
			readinessSHA256, err :=
				formalCoxBlockwiseSamplerContractSHA256(readinessOnly)
			originalSHA256, originalErr :=
				formalCoxBlockwiseSamplerContractSHA256(fixture.contract)
			if err != nil || originalErr != nil || readinessSHA256 != originalSHA256 {
				t.Fatalf("readiness changed sampler contract bytes: %v / %v",
					err, originalErr)
			}
			missing := fixture.contract
			missing.CustodianSignatures = append(
				[]jointDPBiomedicalGaussianSignature(nil),
				fixture.contract.CustodianSignatures[:custodians-1]...)
			if err := formalCoxBlockwiseValidateSamplerContract(
				missing, fixture.pins); err == nil {
				t.Fatal("a non-K-of-K sampler contract was accepted")
			}
			reordered := fixture.contract
			reordered.CustodianSignatures = append(
				[]jointDPBiomedicalGaussianSignature(nil),
				fixture.contract.CustodianSignatures...)
			reordered.CustodianSignatures[0], reordered.CustodianSignatures[1] =
				reordered.CustodianSignatures[1], reordered.CustodianSignatures[0]
			if err := formalCoxBlockwiseValidateSamplerContract(
				reordered, fixture.pins); err == nil {
				t.Fatal("reordered K-of-K signatures were accepted")
			}
			tampered := fixture.contract
			tampered.NoiseCommitments = append(
				[]formalCoxBlockwiseSamplerCommitment(nil),
				fixture.contract.NoiseCommitments...)
			tampered.NoiseCommitments[0].SeedCommitmentSHA256 =
				strings.Repeat("0", 64)
			if err := formalCoxBlockwiseValidateSamplerContract(
				tampered, fixture.pins); err == nil {
				t.Fatal("a tampered seed commitment was accepted")
			}
		})
	}
}

func TestFormalCoxBlockwiseSamplerGuardRestartConcurrentRerollK2K3K5(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalCoxBlockwiseStickyGuardTestContract(
				t, custodians, "guard-a")
			garbler := fixture.artifact.NoiseAuthorities[0].PeerName
			evaluator := fixture.artifact.NoiseAuthorities[1].PeerName
			base := t.TempDir()
			garblerDir := filepath.Join(base, "garbler")
			garblerStore := formalCoxBlockwiseStickyGuardTestStore(
				t, fixture, garbler, garblerDir)

			type result struct {
				authorization formalCoxBlockwiseSamplerAuthorization
				replayed      bool
				err           error
			}
			results := make(chan result, 2)
			var start sync.WaitGroup
			start.Add(1)
			for index := 0; index < 2; index++ {
				go func() {
					start.Wait()
					authorization, replayed, err := garblerStore.AuthorizeOnce(
						fixture.contract, fixture.roots[garbler],
						fixture.private[garbler], nil)
					results <- result{authorization, replayed, err}
				}()
			}
			start.Done()
			first, second := <-results, <-results
			if first.err != nil || second.err != nil ||
				first.replayed == second.replayed {
				t.Fatalf("concurrent guard CAS diverged: first=%v/%v second=%v/%v",
					first.err, first.replayed, second.err, second.replayed)
			}
			firstBytes, _ := json.Marshal(first.authorization)
			secondBytes, _ := json.Marshal(second.authorization)
			if !bytes.Equal(firstBytes, secondBytes) {
				t.Fatal("concurrent guard replay changed authorization bytes")
			}
			garblerAuthorization := first.authorization

			evaluatorStore := formalCoxBlockwiseStickyGuardTestStore(
				t, fixture, evaluator, filepath.Join(base, "evaluator"))
			if _, _, err := evaluatorStore.AuthorizeOnce(
				fixture.contract, fixture.roots[evaluator],
				fixture.private[evaluator], nil); err == nil {
				t.Fatal("evaluator authorized without the garbler predecessor")
			}
			evaluatorAuthorization, replayed, err := evaluatorStore.AuthorizeOnce(
				fixture.contract, fixture.roots[evaluator],
				fixture.private[evaluator],
				[]formalCoxBlockwiseSamplerAuthorization{garblerAuthorization})
			if err != nil || replayed {
				t.Fatalf("ordered evaluator guard failed: %v / replay=%v", err, replayed)
			}
			root, err := formalCoxBlockwiseValidateSamplerAuthorizations(
				fixture.contract,
				[]formalCoxBlockwiseSamplerAuthorization{
					garblerAuthorization, evaluatorAuthorization,
				}, fixture.pins)
			if err != nil || !formalCoxIsSHA256(root) {
				t.Fatalf("guard authorization root failed: %v", err)
			}

			if err := garblerStore.Close(); err != nil {
				t.Fatal(err)
			}
			garblerStore = formalCoxBlockwiseStickyGuardTestStore(
				t, fixture, garbler, garblerDir)
			recovered, replayed, err := garblerStore.AuthorizeOnce(
				fixture.contract, fixture.roots[garbler],
				fixture.private[garbler], nil)
			recoveredBytes, _ := json.Marshal(recovered)
			if err != nil || !replayed ||
				!bytes.Equal(recoveredBytes, firstBytes) {
				t.Fatalf("restart changed guard replay: %v / replay=%v", err, replayed)
			}

			competing := formalCoxBlockwiseStickyGuardTestContract(
				t, custodians, "guard-b")
			if competing.artifactID != fixture.artifactID {
				t.Fatal("test reroll changed the canonical artifact")
			}
			if _, _, err := garblerStore.AuthorizeOnce(
				competing.contract, competing.roots[garbler],
				competing.private[garbler], nil); err == nil {
				t.Fatal("durable guard authorized a sampler reroll")
			}

			if err := garblerStore.Close(); err != nil {
				t.Fatal(err)
			}
			if err := evaluatorStore.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFormalCoxBlockwiseSamplerGuardRejectsTamperAndUnsafeRoots(t *testing.T) {
	fixture := formalCoxBlockwiseStickyGuardTestContract(t, 2, "tamper")
	peer := fixture.artifact.NoiseAuthorities[0].PeerName
	dir := filepath.Join(t.TempDir(), "guard")
	store := formalCoxBlockwiseStickyGuardTestStore(t, fixture, peer, dir)
	if _, _, err := store.AuthorizeOnce(fixture.contract,
		fixture.roots[peer], fixture.private[peer], nil); err != nil {
		t.Fatal(err)
	}
	relative, err := store.recordRelativePath(fixture.artifactID, false)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, relative)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)/2] ^= 1
	if err := exactGCAtomicReplace(path, encoded); err != nil {
		t.Fatal(err)
	}
	store = formalCoxBlockwiseStickyGuardTestStore(t, fixture, peer, dir)
	if _, _, err := store.AuthorizeOnce(fixture.contract,
		fixture.roots[peer], fixture.private[peer], nil); err == nil {
		t.Fatal("a tampered durable guard record was accepted")
	}
	_ = store.Close()

	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := newFormalCoxBlockwiseSamplerGuardStore(
		alias, peer, fixture.storageRoot[peer], fixture.pins); err == nil {
		t.Fatal("a symlinked sampler guard root was accepted")
	}
	tooOpen := filepath.Join(t.TempDir(), "too-open")
	if err := os.Mkdir(tooOpen, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newFormalCoxBlockwiseSamplerGuardStore(
		tooOpen, peer, fixture.storageRoot[peer], fixture.pins); err == nil {
		t.Fatal("an owner-readable-by-group sampler guard root was accepted")
	}

	hardlinkDir := filepath.Join(t.TempDir(), "hardlink-guard")
	hardlinkStore := formalCoxBlockwiseStickyGuardTestStore(
		t, fixture, peer, hardlinkDir)
	if _, _, err := hardlinkStore.AuthorizeOnce(fixture.contract,
		fixture.roots[peer], fixture.private[peer], nil); err != nil {
		t.Fatal(err)
	}
	hardlinkRelative, err := hardlinkStore.recordRelativePath(
		fixture.artifactID, false)
	if err != nil {
		t.Fatal(err)
	}
	hardlinkPath := filepath.Join(hardlinkDir, hardlinkRelative)
	if err := hardlinkStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(hardlinkPath, hardlinkPath+".alias"); err != nil {
		t.Fatal(err)
	}
	hardlinkStore = formalCoxBlockwiseStickyGuardTestStore(
		t, fixture, peer, hardlinkDir)
	if _, _, err := hardlinkStore.AuthorizeOnce(fixture.contract,
		fixture.roots[peer], fixture.private[peer], nil); err == nil {
		t.Fatal("a hardlinked sampler guard record was accepted")
	}
	_ = hardlinkStore.Close()
}

func TestFormalCoxBlockwiseGuardedNoiseLinkRejectsMixesK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
			session, _, transportSK := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			step := formalCoxBlockwiseSourceTestStep(
				t, plan, formalCoxBlockwiseStepUpdate, 0)
			values := make(map[string][]*big.Int, 2)
			validity := make(map[string]bool, 2)
			for index, peer := range plan.Policy.ComputePeers {
				local, valid := formalCoxBlockwiseSourceTestShares(
					plan, step, index, index)
				values[peer], validity[peer] = local, *valid
			}
			envelopes, encoded := formalCoxBlockwiseSourceTestSealNoisePair(
				t, session, signing, step, values, validity)
			var valid formalCoxBlockwiseGuardedNoiseBarrier
			if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
				formalCoxBlockwiseSourceBindingMax, "test guarded noise",
				&valid); err != nil {
				t.Fatal(err)
			}
			if err := formalCoxBlockwiseValidateGuardedNoiseBarrier(
				session, valid); err != nil {
				t.Fatal(err)
			}
			lower := bytes.ToLower(encoded)
			for _, forbidden := range [][]byte{
				[]byte(`"shares"`), []byte(`"plaintext"`),
				[]byte(`"validity_share"`),
			} {
				if bytes.Contains(lower, forbidden) {
					t.Fatalf("guarded noise serialized private field %s", forbidden)
				}
			}

			left, right := plan.Policy.ComputePeers[0], plan.Policy.ComputePeers[1]
			leftStore := formalCoxBlockwiseSourceTestStore(t,
				filepath.Join(t.TempDir(), "guarded-left"), session,
				left, transportSK[left])
			defer leftStore.Close()
			rightStore := formalCoxBlockwiseSourceTestStore(t,
				filepath.Join(t.TempDir(), "guarded-right"), session,
				right, transportSK[right])
			defer rightStore.Close()
			leftSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[left], encoded)
			rightSlot, _ := formalCoxBlockwiseSourceEncodeBoundSlot(
				envelopes[right], encoded)
			_, _, leftRoot, leftShares, _, leftErr :=
				leftStore.validateBoundSlot(leftSlot)
			_, _, rightRoot, rightShares, _, rightErr :=
				rightStore.validateBoundSlot(rightSlot)
			exactGCZeroBigInts(leftShares)
			exactGCZeroBigInts(rightShares)
			if leftErr != nil || rightErr != nil || leftRoot != rightRoot ||
				leftRoot != valid.Barrier.PairedNoiseRootSHA256 {
				t.Fatalf("guarded roles derived different roots: %v / %v", leftErr, rightErr)
			}

			competing := formalCoxBlockwiseStickyGuardTestContract(
				t, custodians, "guarded-mix")
			competingAuthorizations :=
				formalCoxBlockwiseStickyGuardTestAuthorizeFixture(
					t, competing, signing)
			clone := func() formalCoxBlockwiseGuardedNoiseBarrier {
				encoded, err := json.Marshal(valid)
				if err != nil {
					t.Fatal(err)
				}
				var result formalCoxBlockwiseGuardedNoiseBarrier
				if err := json.Unmarshal(encoded, &result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			mutations := []struct {
				name  string
				apply func(*formalCoxBlockwiseGuardedNoiseBarrier)
			}{
				{"outer-artifact", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.ArtifactID = strings.Repeat("0", 64)
				}},
				{"outer-contract-root", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.ContractSHA256 = strings.Repeat("0", 64)
				}},
				{"outer-guard-root", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.SamplerGuardRootSHA256 = strings.Repeat("0", 64)
				}},
				{"missing-authorization", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.Authorizations = value.Authorizations[:1]
				}},
				{"reordered-authorization", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.Authorizations[0], value.Authorizations[1] =
						value.Authorizations[1], value.Authorizations[0]
				}},
				{"authorization-signature", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.Authorizations[0].Signature[0] ^= 1
				}},
				{"mixed-contract", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.Contract = competing.contract
					value.Authorizations = competingAuthorizations
					value.ContractSHA256, _ =
						formalCoxBlockwiseSamplerContractSHA256(competing.contract)
					value.SamplerGuardRootSHA256, _ =
						formalCoxBlockwiseValidateSamplerAuthorizations(
							competing.contract, competingAuthorizations, pins)
				}},
				{"barrier-contract-link", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.Barrier.SamplerContractSHA256 = strings.Repeat("0", 64)
				}},
				{"barrier-guard-link", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.Barrier.SamplerGuardRootSHA256 = strings.Repeat("0", 64)
				}},
				{"barrier-ciphertext-root", func(value *formalCoxBlockwiseGuardedNoiseBarrier) {
					value.Barrier.NoiseRoots[0].EnvelopeSHA256 = strings.Repeat("0", 64)
				}},
			}
			for _, mutation := range mutations {
				mutated := clone()
				mutation.apply(&mutated)
				if err := formalCoxBlockwiseValidateGuardedNoiseBarrier(
					session, mutated); err == nil {
					t.Fatalf("guarded noise accepted %s mix", mutation.name)
				}
			}
		})
	}
}
