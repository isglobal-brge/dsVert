package main

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
)

type jointDPBiomedicalGaussianTestFixture struct {
	pins          map[string]ed25519.PublicKey
	private       map[string]ed25519.PrivateKey
	manifest      jointDPBiomedicalGaussianManifestAttestation
	release       jointDPBiomedicalGaussianReleaseContract
	candidate     jointDPBiomedicalGaussianCandidate
	signed        jointDPBiomedicalGaussianSignedAdmission
	admission     jointDPBiomedicalGaussianAuthenticatedAdmission
	garblerSeed   [32]byte
	evaluatorSeed [32]byte
}

func jointDPBiomedicalGaussianTestHash(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func jointDPBiomedicalGaussianTestClone[T any](t testing.TB, value T) T {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result T
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func jointDPBiomedicalGaussianTestSignManifest(t testing.TB,
	contract jointDPBiomedicalGaussianManifestContract,
	private map[string]ed25519.PrivateKey,
) []jointDPBiomedicalGaussianSignature {
	t.Helper()
	result := make([]jointDPBiomedicalGaussianSignature, 0, len(contract.CustodianPeers))
	for _, peer := range contract.CustodianPeers {
		signature, err := jointDPBiomedicalGaussianSign(
			jointDPBiomedicalGaussianManifestDomain, contract, peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, signature)
	}
	return result
}

func jointDPBiomedicalGaussianTestSignAdmission(t testing.TB,
	preimage jointDPBiomedicalGaussianAdmissionPreimage,
	peers []string, private map[string]ed25519.PrivateKey,
) []jointDPBiomedicalGaussianSignature {
	t.Helper()
	result := make([]jointDPBiomedicalGaussianSignature, 0, len(peers))
	for _, peer := range peers {
		signature, err := jointDPBiomedicalGaussianSign(
			jointDPBiomedicalGaussianAdmissionDomain, preimage, peer, private[peer])
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, signature)
	}
	return result
}

func jointDPBiomedicalGaussianTestSetup(t testing.TB, custodians, coordinates int,
	label string,
) jointDPBiomedicalGaussianTestFixture {
	t.Helper()
	peers := make([]string, custodians)
	pins := make(map[string]ed25519.PublicKey, custodians)
	private := make(map[string]ed25519.PrivateKey, custodians)
	for index := range peers {
		peers[index] = "site" + string(rune('a'+index))
		publicKey, privateKey, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pins[peers[index]] = publicKey
		private[peers[index]] = privateKey
	}
	pinset, err := formalGLMPhase16PinsetSHA256(pins)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]string, coordinates)
	shifts := make([]int, coordinates)
	for index := range raw {
		raw[index] = new(big.Int).SetInt64(int64(10 + index)).String()
		shifts[index] = index % 3
	}
	perPatientUpper := make([]string, coordinates)
	if coordinates == 1 {
		perPatientUpper[0] = "2"
	} else {
		for index := range perPatientUpper {
			if index < 3 {
				perPatientUpper[index] = "1"
			} else {
				perPatientUpper[index] = "0"
			}
		}
	}
	manifestContract := jointDPBiomedicalGaussianManifestContract{
		Version:                jointDPBiomedicalGaussianManifestVersion,
		CapsuleID:              jointDPBiomedicalGaussianTestHash(label + "/capsule"),
		ManifestSHA256:         jointDPBiomedicalGaussianTestHash(label + "/manifest"),
		SchemaManifestSHA256:   jointDPBiomedicalGaussianTestHash(label + "/schema"),
		WorkloadSHA256:         jointDPBiomedicalGaussianTestHash(label + "/workload"),
		SourceContextSHA256:    jointDPBiomedicalGaussianTestHash(label + "/source-context"),
		SourceContractSHA256:   jointDPBiomedicalGaussianTestHash(label + "/source-contract"),
		LogicalSnapshotSHA256:  jointDPBiomedicalGaussianTestHash(label + "/snapshot"),
		CoordinateOrderSHA256:  jointDPBiomedicalGaussianTestHash(label + "/order"),
		LatticeTransformSHA256: jointDPBiomedicalGaussianTestHash(label + "/lattice"),
		PinsetSHA256:           pinset, CustodianPeers: peers, CustodianCount: custodians,
		DesignatedComputePeers: append([]string(nil), peers[:2]...),
		UnitCapacity:           100, Adjacency: "add_remove_patient",
		MaximumActiveRowsPerPatient: 1,
		PatientContribution:         jointDPBiomedicalGaussianContribution,
		MaterializerContract:        jointDPBiomedicalGaussianMaterializer,
		RingBits:                    128, OutputLatticeBits: 8,
		TotalCoordinateCount: coordinates,
		ScaleShifts:          shifts, RawUpperBounds: raw,
		ContributionLayout: jointDPBiomedicalGaussianContributionLayoutDescriptor{
			Version: jointDPBiomedicalGaussianContributionLayout,
			Lattice: jointDPBiomedicalGaussianContributionLattice,
			Blocks: []jointDPBiomedicalGaussianContributionBlock{{
				Name: "family_a", Kind: jointDPBiomedicalGaussianDenseBlock,
				CoordinateStart: 0, CoordinateCount: coordinates,
				PerPatientUpperBoundsSteps: perPatientUpper,
			}},
		},
		OperationLimit: false, RequestLimit: false,
		HistoryCanDenyOperation: false,
	}
	manifest := jointDPBiomedicalGaussianManifestAttestation{
		Contract: manifestContract,
		Signatures: jointDPBiomedicalGaussianTestSignManifest(
			t, manifestContract, private),
	}
	garblerName, garblerID, evaluatorName, evaluatorID, err :=
		jointDPBiomedicalGaussianRoles(manifestContract, pins)
	if err != nil {
		t.Fatal(err)
	}
	transcriptText := jointDPBiomedicalGaussianTestHash(label + "/worker-transcript")
	transcript, err := jointDPGaussianOneDrawDecodeHex(transcriptText, "test transcript")
	if err != nil {
		t.Fatal(err)
	}
	garblerSeed := sha256.Sum256([]byte(label + "/garbler-seed"))
	evaluatorSeed := sha256.Sum256([]byte(label + "/evaluator-seed"))
	gctx := jointDPCommitmentContext(transcript,
		jointDPGaussianOneDrawCommitmentPurpose+"/garbler", garblerID)
	ectx := jointDPCommitmentContext(transcript,
		jointDPGaussianOneDrawCommitmentPurpose+"/evaluator", evaluatorID)
	gcommit := jointDPSeedCommitment(gctx, garblerSeed)
	ecommit := jointDPSeedCommitment(ectx, evaluatorSeed)
	plan, err := jointDPPlanGaussianOneDraw(jointDPGaussianOneDrawPlanInput{
		Epsilon: "1", Delta: "0.000001", L2SensitivitySteps: "2",
		TotalCoordinateCount: coordinates,
	})
	if err != nil || !plan.CapabilityAvailable {
		t.Fatalf("test plan unavailable: %#v %v", plan, err)
	}
	release := jointDPBiomedicalGaussianReleaseContract{
		Version:                jointDPBiomedicalGaussianReleaseVersion,
		ReleaseInstanceID:      jointDPBiomedicalGaussianTestHash(label + "/instance"),
		ReleaseContractSHA256:  jointDPBiomedicalGaussianTestHash(label + "/release"),
		WorkerTranscriptSHA256: transcriptText,
		Epsilon:                "1", AllocatedDelta: "0.000001",
		MaximumChunkCoordinates: plan.MaximumChunkCoordinates,
		NoiseCommitments: map[string]jointDPBiomedicalGaussianNoiseCommitment{
			garblerName: {
				ContextSHA256: hex.EncodeToString(gctx[:]),
				SeedSHA256:    hex.EncodeToString(gcommit[:]),
			},
			evaluatorName: {
				ContextSHA256: hex.EncodeToString(ectx[:]),
				SeedSHA256:    hex.EncodeToString(ecommit[:]),
			},
		},
		ReleaseInstanceCompositionAccounted: true,
		OperationLimit:                      false, RequestLimit: false,
		HistoryCanDenyOperation: false,
	}
	candidate, err := jointDPBiomedicalGaussianPrepareCandidate(
		manifest, release, pins)
	if err != nil {
		t.Fatal(err)
	}
	signed := jointDPBiomedicalGaussianSignedAdmission{
		Preimage: candidate.preimage,
		Signatures: jointDPBiomedicalGaussianTestSignAdmission(
			t, candidate.preimage, peers, private),
	}
	admission, err := admitJointDPBiomedicalGaussianOneDraw(
		manifest, release, pins, signed)
	var blocker *jointDPBiomedicalGaussianReleaseBlocker
	if !errors.As(err, &blocker) || blocker.OpeningsPerformed != 0 {
		t.Fatalf("expected sealed admission blocker, got %T %v", err, err)
	}
	return jointDPBiomedicalGaussianTestFixture{
		pins: pins, private: private, manifest: manifest, release: release,
		candidate: candidate, signed: signed, admission: admission,
		garblerSeed: garblerSeed, evaluatorSeed: evaluatorSeed,
	}
}

func TestJointDPBiomedicalGaussianAdmissionK2K3K5IsSealed(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(string(rune('0'+custodians)), func(t *testing.T) {
			fixture := jointDPBiomedicalGaussianTestSetup(
				t, custodians, 3, t.Name())
			if err := validateJointDPBiomedicalGaussianAdmission(
				fixture.admission); err != nil {
				t.Fatal(err)
			}
			if fixture.candidate.certificate.SelectedBoundSteps != "2" ||
				fixture.candidate.certificate.SquaredSensitivityNumerator != "3" ||
				fixture.candidate.certificate.SquaredSensitivityDenominator != "1" ||
				!reflect.DeepEqual(
					fixture.candidate.certificate.ShiftedUpperBounds,
					[]string{"10", "22", "48"}) ||
				fixture.admission.ProductionReady ||
				fixture.admission.ProtectedDataE2EVerified ||
				fixture.admission.OpeningsPerformed != 0 {
				t.Fatalf("invalid sealed K=%d admission: %#v", custodians,
					fixture.admission)
			}
			chunk, err := compileJointDPBiomedicalGaussianChunk(
				fixture.admission, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateJointDPBiomedicalGaussianChunk(
				fixture.admission, chunk); err != nil {
				t.Fatal(err)
			}
			var blocker *jointDPBiomedicalGaussianReleaseBlocker
			if err := authorizeJointDPBiomedicalGaussianOpening(
				fixture.admission, chunk); !errors.As(err, &blocker) ||
				blocker.OpeningsPerformed != 0 {
				t.Fatalf("sealed opening boundary failed: %T %v", err, err)
			}
		})
	}
}

func TestJointDPBiomedicalGaussianRequiresExactKSignatures(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestSetup(t, 3, 1, t.Name())
	for name, mutate := range map[string]func(*jointDPBiomedicalGaussianSignedAdmission){
		"omitted": func(value *jointDPBiomedicalGaussianSignedAdmission) {
			value.Signatures = value.Signatures[:2]
		},
		"duplicate": func(value *jointDPBiomedicalGaussianSignedAdmission) {
			value.Signatures[2] = value.Signatures[0]
		},
		"extra": func(value *jointDPBiomedicalGaussianSignedAdmission) {
			value.Signatures = append(value.Signatures, value.Signatures[0])
		},
		"wrong-key": func(value *jointDPBiomedicalGaussianSignedAdmission) {
			_, wrong, err := ed25519.GenerateKey(crand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			message, err := jointDPBiomedicalGaussianAdmissionMessage(value.Preimage)
			if err != nil {
				t.Fatal(err)
			}
			value.Signatures[0].Signature = ed25519.Sign(wrong, message)
		},
	} {
		t.Run("admission-"+name, func(t *testing.T) {
			changed := jointDPBiomedicalGaussianTestClone(t, fixture.signed)
			mutate(&changed)
			if _, err := admitJointDPBiomedicalGaussianOneDraw(
				fixture.manifest, fixture.release, fixture.pins, changed); err == nil {
				t.Fatalf("%s admission signatures were accepted", name)
			}
		})
	}
	for name, mutate := range map[string]func(*jointDPBiomedicalGaussianManifestAttestation){
		"omitted": func(value *jointDPBiomedicalGaussianManifestAttestation) {
			value.Signatures = value.Signatures[:2]
		},
		"duplicate": func(value *jointDPBiomedicalGaussianManifestAttestation) {
			value.Signatures[2] = value.Signatures[0]
		},
		"extra": func(value *jointDPBiomedicalGaussianManifestAttestation) {
			value.Signatures = append(value.Signatures, value.Signatures[0])
		},
	} {
		t.Run("manifest-"+name, func(t *testing.T) {
			changed := jointDPBiomedicalGaussianTestClone(t, fixture.manifest)
			mutate(&changed)
			if _, err := jointDPBiomedicalGaussianPrepareCandidate(
				changed, fixture.release, fixture.pins); err == nil {
				t.Fatalf("%s manifest signatures were accepted", name)
			}
		})
	}
}

func TestJointDPBiomedicalGaussianRecomputesSensitivityAndBindings(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestSetup(t, 3, 3, t.Name())
	for name, mutate := range map[string]func(*jointDPBiomedicalGaussianAdmissionPreimage){
		"sensitivity": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.L2SensitivitySteps = "1"
		},
		"certificate": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.SensitivityCertificateSHA256 = jointDPBiomedicalGaussianTestHash("forged cert")
		},
		"manifest": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.ManifestSHA256 = jointDPBiomedicalGaussianTestHash("other manifest")
		},
		"source": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.SourceContractSHA256 = jointDPBiomedicalGaussianTestHash("other source")
		},
		"snapshot": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.LogicalSnapshotSHA256 = jointDPBiomedicalGaussianTestHash("other snapshot")
		},
		"workload": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.WorkloadSHA256 = jointDPBiomedicalGaussianTestHash("other workload")
		},
		"release": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.ReleaseContractSHA256 = jointDPBiomedicalGaussianTestHash("other release")
		},
		"transcript": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.WorkerTranscriptSHA256 = jointDPBiomedicalGaussianTestHash("other transcript")
		},
		"pinset": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.PinsetSHA256 = jointDPBiomedicalGaussianTestHash("other pins")
		},
		"bounds": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.ShiftedUpperBounds[0] = "9"
		},
		"quota": func(value *jointDPBiomedicalGaussianAdmissionPreimage) {
			value.RequestLimit = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := jointDPBiomedicalGaussianTestClone(t, fixture.signed)
			mutate(&changed.Preimage)
			// Even unanimous signatures over a caller-modified preimage cannot
			// replace the object recomputed by the admission constructor.
			changed.Signatures = jointDPBiomedicalGaussianTestSignAdmission(
				t, changed.Preimage, fixture.manifest.Contract.CustodianPeers,
				fixture.private)
			if _, err := admitJointDPBiomedicalGaussianOneDraw(
				fixture.manifest, fixture.release, fixture.pins, changed); err == nil {
				t.Fatalf("re-signed caller %s substitution was accepted", name)
			}
		})
	}

	changedRelease := fixture.release
	changedRelease.ReleaseInstanceID = jointDPBiomedicalGaussianTestHash("new instance")
	if _, err := admitJointDPBiomedicalGaussianOneDraw(
		fixture.manifest, changedRelease, fixture.pins, fixture.signed); err == nil {
		t.Fatal("admission signatures replayed across release instances")
	}
}

func TestJointDPBiomedicalGaussianNumericalAndPinsetFailures(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestSetup(t, 3, 1, t.Name())

	overflow := jointDPBiomedicalGaussianTestClone(t, fixture.manifest)
	raw := new(big.Int).Lsh(big.NewInt(1), 126)
	overflow.Contract.RawUpperBounds[0] = raw.String()
	overflow.Contract.ScaleShifts[0] = 2
	overflow.Signatures = jointDPBiomedicalGaussianTestSignManifest(
		t, overflow.Contract, fixture.private)
	if _, err := jointDPBiomedicalGaussianPrepareCandidate(
		overflow, fixture.release, fixture.pins); err == nil {
		t.Fatal("K-signed shifted bound outside signed Ring128 was accepted")
	}

	badLayout := jointDPBiomedicalGaussianTestClone(t, fixture.manifest)
	badLayout.Contract.ContributionLayout.Blocks[0].
		PerPatientUpperBoundsSteps[0] = "999"
	badLayout.Signatures = jointDPBiomedicalGaussianTestSignManifest(
		t, badLayout.Contract, fixture.private)
	if _, err := jointDPBiomedicalGaussianPrepareCandidate(
		badLayout, fixture.release, fixture.pins); err == nil {
		t.Fatal("K-signed invalid typed contribution layout was accepted")
	}

	omittedPins := make(map[string]ed25519.PublicKey, len(fixture.pins)-1)
	for peer, pin := range fixture.pins {
		if peer != fixture.manifest.Contract.CustodianPeers[2] {
			omittedPins[peer] = pin
		}
	}
	if _, err := jointDPBiomedicalGaussianPrepareCandidate(
		fixture.manifest, fixture.release, omittedPins); err == nil {
		t.Fatal("omitted custodian pin was accepted")
	}
	wrongPins := make(map[string]ed25519.PublicKey, len(fixture.pins))
	for peer, pin := range fixture.pins {
		wrongPins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	wrongPins[fixture.manifest.Contract.CustodianPeers[2]][0] ^= 1
	if _, err := jointDPBiomedicalGaussianPrepareCandidate(
		fixture.manifest, fixture.release, wrongPins); err == nil {
		t.Fatal("substituted custodian pin was accepted")
	}
}

func jointDPBiomedicalGaussianTestEnumerateBlock(
	block jointDPBiomedicalGaussianContributionBlock,
) [][]int {
	upper := make([]int, block.CoordinateCount)
	for index, text := range block.PerPatientUpperBoundsSteps {
		value, _ := new(big.Int).SetString(text, 10)
		upper[index] = int(value.Int64())
	}
	result := [][]int{make([]int, block.CoordinateCount)}
	if block.Kind == jointDPBiomedicalGaussianOneHotBlock {
		for coordinate, maximum := range upper {
			for value := 1; value <= maximum; value++ {
				row := make([]int, block.CoordinateCount)
				row[coordinate] = value
				result = append(result, row)
			}
		}
		return result
	}
	result = result[:0]
	var visit func(int, []int)
	visit = func(coordinate int, row []int) {
		if coordinate == len(upper) {
			result = append(result, append([]int(nil), row...))
			return
		}
		for value := 0; value <= upper[coordinate]; value++ {
			row[coordinate] = value
			visit(coordinate+1, row)
		}
	}
	visit(0, make([]int, len(upper)))
	return result
}

func jointDPBiomedicalGaussianTestEnumerateLayout(
	layout jointDPBiomedicalGaussianContributionLayoutDescriptor,
) [][]int {
	result := [][]int{{}}
	for _, block := range layout.Blocks {
		blockRows := jointDPBiomedicalGaussianTestEnumerateBlock(block)
		next := make([][]int, 0, len(result)*len(blockRows))
		for _, prefix := range result {
			for _, suffix := range blockRows {
				row := append(append([]int(nil), prefix...), suffix...)
				next = append(next, row)
			}
		}
		result = next
	}
	return result
}

func jointDPBiomedicalGaussianTestBruteSquaredSensitivity(
	layout jointDPBiomedicalGaussianContributionLayoutDescriptor,
	adjacency string,
) *big.Int {
	rows := jointDPBiomedicalGaussianTestEnumerateLayout(layout)
	return jointDPBiomedicalGaussianTestBruteRows(rows, adjacency)
}

func jointDPBiomedicalGaussianTestBruteRows(rows [][]int, adjacency string) *big.Int {
	maximum := new(big.Int)
	compare := func(left, right []int) {
		squared := new(big.Int)
		for coordinate := range left {
			difference := int64(left[coordinate] - right[coordinate])
			term := big.NewInt(difference)
			squared.Add(squared, new(big.Int).Mul(term, term))
		}
		if squared.Cmp(maximum) > 0 {
			maximum.Set(squared)
		}
	}
	zero := make([]int, len(rows[0]))
	if adjacency == "add_remove_patient" {
		for _, row := range rows {
			compare(row, zero)
		}
		return maximum
	}
	for _, left := range rows {
		for _, right := range rows {
			compare(left, right)
		}
	}
	return maximum
}

func TestJointDPBiomedicalGaussianTypedLayoutMatchesSmallExhaustiveOracle(t *testing.T) {
	for coordinates := 1; coordinates <= 4; coordinates++ {
		assignmentCount := 1
		for index := 0; index < coordinates; index++ {
			assignmentCount *= 3
		}
		for encoded := 0; encoded < assignmentCount; encoded++ {
			bounds := make([]string, coordinates)
			value := encoded
			for index := range bounds {
				bounds[index] = new(big.Int).SetInt64(int64(value % 3)).String()
				value /= 3
			}
			partitions := [][]int{{coordinates}}
			for first := 1; first < coordinates; first++ {
				partitions = append(partitions, []int{first, coordinates - first})
			}
			for _, partition := range partitions {
				kindAssignments := 1 << len(partition)
				for kindMask := 0; kindMask < kindAssignments; kindMask++ {
					blocks := make([]jointDPBiomedicalGaussianContributionBlock,
						len(partition))
					start := 0
					for blockIndex, count := range partition {
						kind := jointDPBiomedicalGaussianDenseBlock
						if kindMask&(1<<blockIndex) != 0 {
							kind = jointDPBiomedicalGaussianOneHotBlock
						}
						blocks[blockIndex] = jointDPBiomedicalGaussianContributionBlock{
							Name: string(rune('a' + blockIndex)), Kind: kind,
							CoordinateStart: start, CoordinateCount: count,
							PerPatientUpperBoundsSteps: append([]string(nil),
								bounds[start:start+count]...),
						}
						start += count
					}
					layout := jointDPBiomedicalGaussianContributionLayoutDescriptor{
						Version: jointDPBiomedicalGaussianContributionLayout,
						Lattice: jointDPBiomedicalGaussianContributionLattice,
						Blocks:  blocks,
					}
					for _, adjacency := range []string{
						"add_remove_patient", "replace_one_fixed_cohort",
					} {
						contract := jointDPBiomedicalGaussianManifestContract{
							TotalCoordinateCount: coordinates,
							Adjacency:            adjacency,
							ContributionLayout:   layout,
						}
						aggregateUpper := make([]string, coordinates)
						for index := range aggregateUpper {
							aggregateUpper[index] = "2"
						}
						_, derived, err := jointDPBiomedicalGaussianDeriveSensitivity(
							contract, aggregateUpper)
						if err != nil {
							t.Fatal(err)
						}
						brute := jointDPBiomedicalGaussianTestBruteSquaredSensitivity(
							layout, adjacency)
						if derived.Cmp(brute) != 0 {
							t.Fatalf("coordinates=%d bounds=%v partition=%v kind-mask=%d adjacency=%s: derived=%s brute=%s",
								coordinates, bounds, partition, kindMask, adjacency,
								derived, brute)
						}
					}
				}
			}
		}
	}
}

func TestJointDPBiomedicalGaussianCoupledFamiliesMatchRealDomainOracle(t *testing.T) {
	monomialRows := make([][]int, 0, 12)
	for first := 0; first <= 2; first++ {
		for second := 0; second <= 3; second++ {
			monomialRows = append(monomialRows,
				[]int{1, second, first, first * second})
		}
	}
	cases := []struct {
		name      string
		block     jointDPBiomedicalGaussianContributionBlock
		aggregate []string
		realRows  [][]int
	}{
		{
			name: "fixed-count-and-constant",
			block: jointDPBiomedicalGaussianContributionBlock{
				Name: "constant", Kind: jointDPBiomedicalGaussianConstantBlock,
				CoordinateStart: 0, CoordinateCount: 2,
				ConstantValuesSteps: []string{"1", "2"},
			},
			aggregate: []string{"10", "10"},
			realRows:  [][]int{{1, 2}},
		},
		{
			name: "survival-finite-profiles",
			block: jointDPBiomedicalGaussianContributionBlock{
				Name: "survival", Kind: jointDPBiomedicalGaussianFiniteProfilesBlock,
				CoordinateStart: 0, CoordinateCount: 4,
				ProfilesSteps: [][]string{
					{"0", "0", "0", "0"},
					{"1", "0", "0", "1"},
					{"1", "1", "0", "0"},
					{"1", "1", "1", "0"},
				},
			},
			aggregate: []string{"1", "1", "1", "1"},
			realRows: [][]int{
				{0, 0, 0, 0}, {1, 0, 0, 1},
				{1, 1, 0, 0}, {1, 1, 1, 0},
			},
		},
		{
			name: "numeric-pair-monomials",
			block: jointDPBiomedicalGaussianContributionBlock{
				Name: "moments", Kind: jointDPBiomedicalGaussianMonomialGridBlock,
				CoordinateStart: 0, CoordinateCount: 4,
				AxisUpperBoundsSteps: []string{"2", "3"},
				MonomialPowers:       [][]int{{0, 0}, {0, 1}, {1, 0}, {1, 1}},
			},
			aggregate: []string{"1", "3", "2", "6"},
			realRows:  monomialRows,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			layout := jointDPBiomedicalGaussianContributionLayoutDescriptor{
				Version: jointDPBiomedicalGaussianContributionLayout,
				Lattice: jointDPBiomedicalGaussianContributionLattice,
				Blocks:  []jointDPBiomedicalGaussianContributionBlock{test.block},
			}
			for _, adjacency := range []string{
				"add_remove_patient", "replace_one_fixed_cohort",
			} {
				contract := jointDPBiomedicalGaussianManifestContract{
					TotalCoordinateCount: test.block.CoordinateCount,
					Adjacency:            adjacency,
					UnitCapacity:         1,
					ContributionLayout:   layout,
				}
				components, derived, err :=
					jointDPBiomedicalGaussianDeriveSensitivity(
						contract, test.aggregate)
				if err != nil {
					t.Fatal(err)
				}
				brute := jointDPBiomedicalGaussianTestBruteRows(
					test.realRows, adjacency)
				if derived.Cmp(brute) != 0 || len(components) != 1 ||
					components[0].Tightness != jointDPBiomedicalGaussianExactTypedDomain {
					t.Fatalf("adjacency=%s derived=%s brute=%s components=%#v",
						adjacency, derived, brute, components)
				}
				contract.UnitCapacity = 1_000_000
				_, otherCapacity, err :=
					jointDPBiomedicalGaussianDeriveSensitivity(
						contract, test.aggregate)
				if err != nil || otherCapacity.Cmp(derived) != 0 {
					t.Fatal("fixed padded capacity changed per-patient sensitivity")
				}
			}
		})
	}
}

func TestJointDPBiomedicalGaussianManifestHasNoFreeSensitivityComponents(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestSetup(t, 3, 3, t.Name())
	encoded, err := json.Marshal(fixture.manifest.Contract)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"l2_components"`, `"squared_numerator"`,
		`"squared_denominator"`} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("manifest retained caller-selectable sensitivity field %s", forbidden)
		}
	}
}

func TestJointDPBiomedicalGaussianStickyAbsoluteCoordinateChunking(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestSetup(t, 3, 3, t.Name())
	full, err := compileJointDPBiomedicalGaussianChunk(fixture.admission, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	first, err := compileJointDPBiomedicalGaussianChunk(fixture.admission, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileJointDPBiomedicalGaussianChunk(fixture.admission, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	fullSpec, err := jointDPGaussianOneDrawPolicySpec(full.worker.WorkerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	firstSpec, err := jointDPGaussianOneDrawPolicySpec(first.worker.WorkerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	secondSpec, err := jointDPGaussianOneDrawPolicySpec(second.worker.WorkerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	fullWords, fullSigns, err := jointDPGaussianOneDrawPrivateInputs(
		fixture.garblerSeed, fullSpec, "garbler")
	if err != nil {
		t.Fatal(err)
	}
	firstWords, firstSigns, err := jointDPGaussianOneDrawPrivateInputs(
		fixture.garblerSeed, firstSpec, "garbler")
	if err != nil {
		t.Fatal(err)
	}
	secondWords, secondSigns, err := jointDPGaussianOneDrawPrivateInputs(
		fixture.garblerSeed, secondSpec, "garbler")
	if err != nil {
		t.Fatal(err)
	}
	joinedWords := append(firstWords, secondWords...)
	joinedSigns := append(firstSigns, secondSigns...)
	for index := range fullWords {
		if fullWords[index].Cmp(joinedWords[index]) != 0 ||
			fullSigns[index] != joinedSigns[index] {
			t.Fatalf("absolute coordinate %d rerolled after rechunking", index)
		}
	}
	if fullSpec.globalStreamDigest() != firstSpec.globalStreamDigest() ||
		fullSpec.globalStreamDigest() != secondSpec.globalStreamDigest() {
		t.Fatal("public chunk geometry entered the sticky global stream domain")
	}

	tampered := first
	tampered.ChunkStart = 1
	if err := validateJointDPBiomedicalGaussianChunk(
		fixture.admission, tampered); err == nil {
		t.Fatal("chunk geometry changed without invalidating its seal")
	}
}

func TestJointDPBiomedicalGaussianGenericWorkerNeverBecomesAdmitted(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestSetup(t, 2, 1, t.Name())
	plan := jointDPGaussianOneDrawTestPlan(t, "1", "0.000001", "1", 1)
	genericInput := jointDPGaussianOneDrawTestContract(
		t, plan, 0, []string{"10"}, fixture.garblerSeed,
		fixture.evaluatorSeed, 2)
	generic, err := jointDPCompileGaussianOneDrawWorkerContract(genericInput)
	if err != nil {
		t.Fatal(err)
	}
	forgedAdmission := jointDPBiomedicalGaussianAuthenticatedAdmission{
		Version:                 jointDPBiomedicalGaussianAdmissionVersion,
		AuthenticatedGatePassed: true,
	}
	if err := validateJointDPBiomedicalGaussianAdmission(forgedAdmission); err == nil {
		t.Fatal("generic machine_proven certificate became an authenticated admission")
	}
	validChunk, err := compileJointDPBiomedicalGaussianChunk(
		fixture.admission, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	forgedChunk := validChunk
	forgedChunk.worker = &generic
	forgedChunk.CircuitDigest = generic.CircuitDigest
	forgedChunk.Purpose = generic.Purpose
	if err := validateJointDPBiomedicalGaussianChunk(
		fixture.admission, forgedChunk); err == nil {
		t.Fatal("generic worker replaced a K-admitted deterministic worker")
	}
	if err := authorizeJointDPBiomedicalGaussianOpening(
		fixture.admission, forgedChunk); err == nil {
		t.Fatal("generic worker reached the opening boundary")
	}
}

func TestJointDPBiomedicalGaussianPrivateStateAndRemoteSurfaceStaySealed(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestSetup(t, 3, 1, t.Name())
	chunk, err := compileJointDPBiomedicalGaussianChunk(fixture.admission, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	encodedAdmission, err := json.Marshal(fixture.admission)
	if err != nil {
		t.Fatal(err)
	}
	encodedChunk, err := json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"worker_policy", "release_binding", "raw_upper_bounds",
		"private_seed", "source_share", "seal",
	} {
		if strings.Contains(string(encodedAdmission), forbidden) ||
			strings.Contains(string(encodedChunk), forbidden) {
			t.Fatalf("sealed JSON exposed %q", forbidden)
		}
	}
	for _, path := range []string{"main.go", "runtime_capabilities.go"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content),
			jointDPBiomedicalGaussianAdmissionVersion) ||
			strings.Contains(string(content),
				"biomedical-gaussian-one-draw-admit") {
			t.Fatalf("sealed admission leaked into %s", path)
		}
	}
}

func TestJointDPBiomedicalGaussianPrivateAdmissionSealRejectsMutation(t *testing.T) {
	fixture := jointDPBiomedicalGaussianTestSetup(t, 3, 1, t.Name())
	changed := fixture.admission
	changed.PreimageSHA256 = jointDPBiomedicalGaussianTestHash("changed admission")
	if err := validateJointDPBiomedicalGaussianAdmission(changed); err == nil {
		t.Fatal("changed admission digest retained its seal")
	}
	changed = fixture.admission
	changed.candidate = &jointDPBiomedicalGaussianCandidate{}
	if err := validateJointDPBiomedicalGaussianAdmission(changed); err == nil {
		t.Fatal("changed private candidate retained its seal")
	}
	changed = fixture.admission
	privateCandidate := *fixture.admission.candidate
	privateCandidate.release.MaximumChunkCoordinates++
	changed.candidate = &privateCandidate
	if err := validateJointDPBiomedicalGaussianAdmission(changed); err == nil {
		t.Fatal("changed private release state retained its seal")
	}
}

func BenchmarkJointDPBiomedicalGaussianK5Admission(b *testing.B) {
	fixture := jointDPBiomedicalGaussianTestSetup(b, 5, 3, b.Name())
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := admitJointDPBiomedicalGaussianOneDraw(
			fixture.manifest, fixture.release, fixture.pins,
			fixture.signed); err == nil {
			b.Fatal("sealed admission unexpectedly returned without blocker")
		}
	}
}
