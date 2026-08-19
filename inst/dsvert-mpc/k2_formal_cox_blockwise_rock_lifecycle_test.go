package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const formalCoxBlockwiseRockHelperEnvironment = "DSVERT_COX_ROCK_HELPER"

type formalCoxBlockwiseRockTestFixture struct {
	contractFixture formalCoxBlockwiseStickyGuardFixture
	stateRoot       string
	roots           [2]string
	openingRoots    [2][32]byte
	transportRoots  [2][32]byte
	planPaths       [2]string
	pinsetPaths     [2]string
	contractPaths   [2]string
	openingDirs     [2]string
	checkpointDirs  [2]string
	headerPaths     [2][2]string
	ticketPaths     [2]string
	publication     formalCoxBlockwiseRockPublication
	sequence        int
}

func formalCoxBlockwiseRockTestMkdir(t testing.TB, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil || os.Chmod(path, 0o700) != nil {
		t.Fatalf("private test directory: %v", err)
	}
}

func formalCoxBlockwiseRockTestCopyTree(t testing.TB, source, destination string) {
	t.Helper()
	formalCoxBlockwiseRockTestMkdir(t, destination)
	err := filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(encoded)
		return os.WriteFile(target, encoded, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func formalCoxBlockwiseRockTestWrite(t testing.TB, root, path string, value any) {
	t.Helper()
	if _, _, err := formalCoxBlockwiseRockWriteJSON(root, path, value); err != nil {
		t.Fatal(err)
	}
}

func formalCoxBlockwiseRockTestRelay(t testing.TB, sourceRoot, sourcePath,
	destinationRoot, destinationPath string, value any,
) {
	t.Helper()
	if err := formalCoxBlockwiseRockReadJSON(sourceRoot, sourcePath,
		formalCoxBlockwiseRockMaxRecord, value); err != nil {
		t.Fatal(err)
	}
	formalCoxBlockwiseRockTestWrite(t, destinationRoot, destinationPath, value)
}

func formalCoxBlockwiseRockTestBase64(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func formalCoxBlockwiseRockTestPinset(
	pins map[string]ed25519.PublicKey,
) formalCoxBlockwiseRockPinset {
	encoded := make(map[string]string, len(pins))
	for peer, pin := range pins {
		encoded[peer] = formalCoxBlockwiseRockTestBase64(pin)
	}
	return formalCoxBlockwiseRockPinset{
		Version: formalCoxBlockwiseRockPinsetVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Purpose: formalCoxBlockwiseRockPurpose, PinnedPublicKey: encoded,
	}
}

func newFormalCoxBlockwiseRockTestFixture(t testing.TB,
	custodians int,
) *formalCoxBlockwiseRockTestFixture {
	t.Helper()
	contractFixture := formalCoxBlockwiseStickyGuardTestContract(
		t, custodians, fmt.Sprintf("rock-lifecycle-k%d", custodians))
	stateRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixture := &formalCoxBlockwiseRockTestFixture{
		contractFixture: contractFixture, stateRoot: stateRoot,
	}
	if err := os.Chmod(fixture.stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	_, checkpointRoot := formalCoxBlockwiseOpeningTestCompletedStores(
		t, contractFixture.plan, contractFixture.private,
		[]*big.Int{big.NewInt(64), big.NewInt(-32)}, true)
	for position, peer := range contractFixture.plan.Policy.ComputePeers {
		root := filepath.Join(fixture.stateRoot, peer)
		fixture.roots[position] = root
		for _, slot := range []string{"config", "inputs", "records", "relay", "secrets"} {
			formalCoxBlockwiseRockTestMkdir(t, filepath.Join(root, slot))
		}
		fixture.openingDirs[position] = filepath.Join(root, "opening")
		formalCoxBlockwiseRockTestMkdir(t, fixture.openingDirs[position])
		fixture.checkpointDirs[position] = filepath.Join(root, "checkpoint")
		formalCoxBlockwiseRockTestCopyTree(t,
			filepath.Join(checkpointRoot, peer), fixture.checkpointDirs[position])
		fixture.openingRoots[position] = sha256.Sum256(
			[]byte(fmt.Sprintf("%s/opening/%s", t.Name(), peer)))
		fixture.transportRoots[position] = sha256.Sum256(
			[]byte(fmt.Sprintf("%s/transport/%s", t.Name(), peer)))
		fixture.planPaths[position] = filepath.Join(root, "inputs", "plan.json")
		fixture.pinsetPaths[position] = filepath.Join(root, "inputs", "pins.json")
		fixture.contractPaths[position] = filepath.Join(root, "inputs", "contract.json")
		formalCoxBlockwiseRockTestWrite(
			t, root, fixture.planPaths[position], contractFixture.plan)
		formalCoxBlockwiseRockTestWrite(t, root, fixture.pinsetPaths[position],
			formalCoxBlockwiseRockTestPinset(contractFixture.pins))
		formalCoxBlockwiseRockTestWrite(
			t, root, fixture.contractPaths[position], contractFixture.contract)
		for headerPosition, role := range []string{"garbler", "evaluator"} {
			fixture.headerPaths[position][headerPosition] = filepath.Join(
				root, "relay", "header-"+role+".json")
		}
		fixture.ticketPaths[position] = filepath.Join(root, "relay", "ticket.json")
	}
	return fixture
}

func (fixture *formalCoxBlockwiseRockTestFixture) writeSecret(t testing.TB,
	position int, action, label string,
) string {
	t.Helper()
	peer := fixture.contractFixture.plan.Policy.ComputePeers[position]
	path := filepath.Join(fixture.roots[position], "secrets", label+".json")
	secret := formalCoxBlockwiseRockTransportSecret{
		Version: formalCoxBlockwiseRockSecretVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Purpose: formalCoxBlockwiseRockPurpose, Action: action,
		OpeningStorageRoot: formalCoxBlockwiseRockTestBase64(
			fixture.openingRoots[position][:]),
		TransportStorageRoot: formalCoxBlockwiseRockTestBase64(
			fixture.transportRoots[position][:]),
		SigningPrivateKey: formalCoxBlockwiseRockTestBase64(
			fixture.contractFixture.private[peer]),
	}
	formalCoxBlockwiseRockTestWrite(t, fixture.roots[position], path, secret)
	return path
}

func (fixture *formalCoxBlockwiseRockTestFixture) writeOpeningSecret(t testing.TB,
	position int, action, label string,
) string {
	t.Helper()
	peer := fixture.contractFixture.plan.Policy.ComputePeers[position]
	path := filepath.Join(fixture.roots[position], "secrets", label+".json")
	secret := formalCoxBlockwiseRockPreflightSecret{
		Version: formalCoxBlockwiseRockSecretVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Purpose: formalCoxBlockwiseRockPurpose, Action: action,
		OpeningStorageRoot: formalCoxBlockwiseRockTestBase64(
			fixture.openingRoots[position][:]),
		SigningPrivateKey: formalCoxBlockwiseRockTestBase64(
			fixture.contractFixture.private[peer]),
	}
	formalCoxBlockwiseRockTestWrite(t, fixture.roots[position], path, secret)
	return path
}

func (fixture *formalCoxBlockwiseRockTestFixture) writeStageSecret(t testing.TB,
	position int, label string,
) string {
	t.Helper()
	peer := fixture.contractFixture.plan.Policy.ComputePeers[position]
	checkpointKey := formalCoxBlockwiseWorkerTestKey(peer)
	path := filepath.Join(fixture.roots[position], "secrets", label+".json")
	secret := formalCoxBlockwiseRockStageSecret{
		Version: formalCoxBlockwiseRockSecretVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Purpose: formalCoxBlockwiseRockPurpose,
		Action:  formalCoxBlockwiseRockActionStage,
		PreflightOpeningStorageRoot: formalCoxBlockwiseRockTestBase64(
			fixture.openingRoots[position][:]),
		CheckpointKey: formalCoxBlockwiseRockTestBase64(checkpointKey[:]),
		OpeningStorageRoot: formalCoxBlockwiseRockTestBase64(
			fixture.openingRoots[position][:]),
		SigningPrivateKey: formalCoxBlockwiseRockTestBase64(
			fixture.contractFixture.private[peer]),
	}
	formalCoxBlockwiseRockTestWrite(t, fixture.roots[position], path, secret)
	return path
}

func TestFormalCoxBlockwiseRockLifecycleHelperProcess(t *testing.T) {
	if os.Getenv(formalCoxBlockwiseRockHelperEnvironment) != "1" {
		return
	}
	configPath := os.Getenv("DSVERT_COX_ROCK_CONFIG")
	stateRoot := os.Getenv("DSVERT_COX_ROCK_STATE_ROOT")
	request, root, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
		configPath, stateRoot)
	if err == nil && request.Family != formalFinalizerHandoffFamilyCox {
		err = fmt.Errorf("wrong lifecycle family")
	}
	crashPhase := os.Getenv("DSVERT_COX_ROCK_CRASH_PHASE")
	hook := func(phase string) error {
		if phase == crashPhase {
			return fmt.Errorf("injected crash")
		}
		return nil
	}
	var response formalCoxBlockwiseRockLifecycleResponse
	if err == nil {
		response, err = formalCoxBlockwiseRockRun(
			root, false, request.Action, request.Operation, hook)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "formal-cox lifecycle action failed")
		os.Exit(23)
	}
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		os.Exit(24)
	}
	os.Exit(0)
}

func (fixture *formalCoxBlockwiseRockTestFixture) run(t testing.TB,
	position int, action string, operation any, crashPhase string,
) (formalCoxBlockwiseRockLifecycleResponse, error) {
	t.Helper()
	fixture.sequence++
	root := fixture.roots[position]
	operationJSON, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	request := formalTypedFinalizerLifecycleRequest{
		Version: formalTypedFinalizerLifecycleVersion,
		Family:  formalFinalizerHandoffFamilyCox, Action: action,
		Operation: operationJSON,
	}
	configPath := filepath.Join(root, "config",
		fmt.Sprintf("%03d-%s.json", fixture.sequence, action))
	formalCoxBlockwiseRockTestWrite(t, root, configPath, request)
	command := exec.Command(os.Args[0],
		"-test.run=^TestFormalCoxBlockwiseRockLifecycleHelperProcess$")
	command.Env = append(os.Environ(),
		formalCoxBlockwiseRockHelperEnvironment+"=1",
		"DSVERT_COX_ROCK_CONFIG="+configPath,
		"DSVERT_COX_ROCK_STATE_ROOT="+fixture.stateRoot,
		"DSVERT_COX_ROCK_CRASH_PHASE="+crashPhase)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout, command.Stderr = stdout, stderr
	err = command.Run()
	combined := append(append([]byte(nil), stdout.Bytes()...), stderr.Bytes()...)
	for _, forbidden := range []string{
		fixture.stateRoot, `"ciphertext"`, `"coefficient_shares"`,
		`"signing_private_key"`, `"transport_storage_root"`,
	} {
		if strings.Contains(string(combined), forbidden) {
			t.Fatalf("lifecycle output leaked %q", forbidden)
		}
	}
	for _, privateKey := range fixture.contractFixture.private {
		if strings.Contains(string(combined),
			formalCoxBlockwiseRockTestBase64(privateKey)) {
			t.Fatal("lifecycle output leaked an authority private key")
		}
	}
	if err != nil {
		if stdout.Len() != 0 || strings.TrimSpace(stderr.String()) !=
			"formal-cox lifecycle action failed" {
			t.Fatalf("non-coarse lifecycle failure: stdout=%q stderr=%q",
				stdout.String(), stderr.String())
		}
		return formalCoxBlockwiseRockLifecycleResponse{}, err
	}
	var response formalCoxBlockwiseRockLifecycleResponse
	if decodeErr := formalCoxBlockwiseRockStrictDecode(
		bytes.TrimSpace(stdout.Bytes()), &response); decodeErr != nil ||
		response.Version != formalTypedFinalizerLifecycleVersion ||
		response.Family != formalFinalizerHandoffFamilyCox ||
		response.Action != action || response.ProductionReady {
		t.Fatalf("invalid lifecycle response: %#v / %v", response, decodeErr)
	}
	return response, nil
}

func (fixture *formalCoxBlockwiseRockTestFixture) crashThenRun(t testing.TB,
	position int, action string, operation any, crashPhase, secretPath string,
) formalCoxBlockwiseRockLifecycleResponse {
	t.Helper()
	if _, err := fixture.run(t, position, action, operation, crashPhase); err == nil {
		t.Fatalf("%s ignored injected crash at %s", action, crashPhase)
	}
	if exists, err := formalCoxBlockwiseRockExists(
		fixture.roots[position], secretPath); err != nil || !exists {
		t.Fatalf("%s deleted retry secret before output commit: %v/%v",
			action, exists, err)
	}
	response, err := fixture.run(t, position, action, operation, "")
	if err != nil {
		t.Fatalf("%s retry failed: %v", action, err)
	}
	if exists, err := formalCoxBlockwiseRockExists(
		fixture.roots[position], secretPath); err != nil || exists {
		t.Fatalf("%s retained secret after output commit: %v/%v",
			action, exists, err)
	}
	return response
}

func formalCoxBlockwiseRockTestRelayPreflights(t testing.TB,
	fixture *formalCoxBlockwiseRockTestFixture, source [2]string,
	destination [2][2]string,
) {
	t.Helper()
	for local := range fixture.roots {
		for remote := range source {
			var record formalCoxBlockwiseRockPreflightRecord
			formalCoxBlockwiseRockTestRelay(t,
				fixture.roots[remote], source[remote],
				fixture.roots[local], destination[local][remote], &record)
		}
	}
}

func formalCoxBlockwiseRockTestRelayHeaders(t testing.TB,
	fixture *formalCoxBlockwiseRockTestFixture, source [2]string,
) {
	t.Helper()
	for local := range fixture.roots {
		for remote := range source {
			var record formalCoxBlockwiseRockHeaderRecord
			formalCoxBlockwiseRockTestRelay(t,
				fixture.roots[remote], source[remote],
				fixture.roots[local], fixture.headerPaths[local][remote], &record)
		}
	}
}

func formalCoxBlockwiseRockTestPreflightOperation(
	fixture *formalCoxBlockwiseRockTestFixture, position int,
	secretPath, recordPath, publicationPath string,
) formalCoxBlockwiseRockPreflightOperation {
	peer := fixture.contractFixture.plan.Policy.ComputePeers[position]
	return formalCoxBlockwiseRockPreflightOperation{
		ArtifactContractPath: fixture.contractPaths[position],
		PinsetPath:           fixture.pinsetPaths[position],
		OpeningDir:           fixture.openingDirs[position], PeerName: peer,
		SecretBundlePath: secretPath, RecordPath: recordPath,
		PublicationRecordPath: publicationPath,
	}
}

func TestFormalCoxBlockwiseRockLifecycleK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseRockTestFixture(t, custodians)
			plan := fixture.contractFixture.plan
			roles := [2]string{"garbler", "evaluator"}

			var preflightSource [2]string
			var preflightLocal [2][2]string
			for local := range fixture.roots {
				for remote, role := range roles {
					preflightLocal[local][remote] = filepath.Join(
						fixture.roots[local], "relay", "preflight-"+role+".json")
				}
				secret := fixture.writeOpeningSecret(t, local,
					formalCoxBlockwiseRockActionPreflight, "preflight-initial")
				preflightSource[local] = filepath.Join(
					fixture.roots[local], "records", "preflight-initial.json")
				operation := formalCoxBlockwiseRockTestPreflightOperation(
					fixture, local, secret, preflightSource[local], filepath.Join(
						fixture.roots[local], "records", "preflight-publication-initial.json"))
				response := fixture.crashThenRun(t, local,
					formalCoxBlockwiseRockActionPreflight, operation,
					"after_preflight_before_record", secret)
				if response.State != formalCoxBlockwiseRockStateAbsent ||
					response.Publication != nil {
					t.Fatalf("initial preflight was not absent: %#v", response)
				}
			}
			formalCoxBlockwiseRockTestRelayPreflights(
				t, fixture, preflightSource, preflightLocal)

			var headerSource [2]string
			for position, peer := range plan.Policy.ComputePeers {
				secret := fixture.writeStageSecret(t, position, "stage-initial")
				headerSource[position] = filepath.Join(
					fixture.roots[position], "records", "header-local.json")
				operation := formalCoxBlockwiseRockStageOperation{
					ArtifactContractPath: fixture.contractPaths[position],
					PinsetPath:           fixture.pinsetPaths[position],
					PreflightRecordPaths: preflightLocal[position],
					PlanPath:             fixture.planPaths[position],
					PreflightOpeningDir:  fixture.openingDirs[position],
					CheckpointDir:        fixture.checkpointDirs[position],
					OpeningDir:           fixture.openingDirs[position], PeerName: peer,
					SecretBundlePath: secret, HeaderRecordPath: headerSource[position],
				}
				response := fixture.crashThenRun(t, position,
					formalCoxBlockwiseRockActionStage, operation,
					"after_stage_durable", secret)
				if response.State != formalCoxBlockwiseRockStateStaged {
					t.Fatalf("stage did not persist local handoff: %#v", response)
				}
			}
			formalCoxBlockwiseRockTestRelayHeaders(t, fixture, headerSource)

			finalizerSecret := fixture.writeSecret(t, 0,
				formalCoxBlockwiseRockActionTicket, "ticket")
			ticketOperation := formalCoxBlockwiseRockTicketOperation{
				ArtifactContractPath: fixture.contractPaths[0],
				PinsetPath:           fixture.pinsetPaths[0],
				PreflightRecordPaths: preflightLocal[0],
				PlanPath:             fixture.planPaths[0], OpeningDir: fixture.openingDirs[0],
				TransportDir: fixture.roots[0], HeaderRecordPaths: fixture.headerPaths[0],
				SecretBundlePath: finalizerSecret, TicketRecordPath: fixture.ticketPaths[0],
			}
			fixture.crashThenRun(t, 0, formalCoxBlockwiseRockActionTicket,
				ticketOperation, "after_ticket_durable", finalizerSecret)
			var ticketRecord formalCoxBlockwiseRockTicketRecord
			formalCoxBlockwiseRockTestRelay(t,
				fixture.roots[0], fixture.ticketPaths[0], fixture.roots[1],
				fixture.ticketPaths[1], &ticketRecord)

			var envelopeSource [2]string
			var sealOperations [2]formalCoxBlockwiseRockSealOperation
			for position, peer := range plan.Policy.ComputePeers {
				secret := fixture.writeSecret(t, position,
					formalCoxBlockwiseRockActionSeal, "seal")
				envelopeSource[position] = filepath.Join(
					fixture.roots[position], "records", "envelope-local.json")
				sealOperations[position] = formalCoxBlockwiseRockSealOperation{
					PinsetPath:   fixture.pinsetPaths[position],
					PlanPath:     fixture.planPaths[position],
					OpeningDir:   fixture.openingDirs[position],
					TransportDir: fixture.roots[position], PeerName: peer,
					HeaderRecordPaths: fixture.headerPaths[position],
					TicketRecordPath:  fixture.ticketPaths[position],
					SecretBundlePath:  secret, EnvelopeRecordPath: envelopeSource[position],
				}
				fixture.crashThenRun(t, position, formalCoxBlockwiseRockActionSeal,
					sealOperations[position], "after_seal_durable", secret)
			}
			// This is the only simulated network boundary in the Go gate. The
			// production gate will carry the same signed envelope through the
			// closed formal-finalizer-handoff typed-blob capability.
			var envelopeIngress [2]string
			for position, role := range roles {
				envelopeIngress[position] = filepath.Join(
					fixture.roots[0], "relay", "envelope-"+role+".json")
				var record formalCoxBlockwiseRockEnvelopeRecord
				formalCoxBlockwiseRockTestRelay(t,
					fixture.roots[position], envelopeSource[position], fixture.roots[0],
					envelopeIngress[position], &record)
			}

			prepareSecret := fixture.writeSecret(t, 0,
				formalCoxBlockwiseRockActionPrepare, "prepare")
			candidatePath := filepath.Join(
				fixture.roots[0], "records", "candidate.json")
			prepareOperation := formalCoxBlockwiseRockPrepareOperation{
				PinsetPath: fixture.pinsetPaths[0], PlanPath: fixture.planPaths[0],
				OpeningDir: fixture.openingDirs[0], TransportDir: fixture.roots[0],
				HeaderRecordPaths:   fixture.headerPaths[0],
				TicketRecordPath:    fixture.ticketPaths[0],
				EnvelopeRecordPaths: envelopeIngress,
				SecretBundlePath:    prepareSecret, CandidateRecordPath: candidatePath,
			}
			fixture.crashThenRun(t, 0, formalCoxBlockwiseRockActionPrepare,
				prepareOperation, "after_prepare_durable", prepareSecret)

			var candidateRecord formalCoxBlockwiseRockCandidateRecord
			if err := formalCoxBlockwiseRockReadJSON(fixture.roots[0], candidatePath,
				formalCoxBlockwiseRockMaxRecord, &candidateRecord); err != nil {
				t.Fatal(err)
			}
			badCandidate := formalCoxBlockwiseDistributedTestCandidateBeta(
				t, candidateRecord.Candidate, 0, big.NewInt(63))
			badIntent, err := formalCoxBlockwiseOpeningIntentFor(badCandidate)
			if err != nil || formalCoxBlockwiseValidateOpeningCandidateCore(
				badCandidate, fixture.contractFixture.pins) != nil ||
				badIntent.CandidateSHA256 == candidateRecord.Intent.CandidateSHA256 {
				t.Fatalf("substitute candidate control is not valid/distinct: %v", err)
			}
			badCandidatePath := filepath.Join(
				fixture.roots[0], "records", "candidate-substitute.json")
			badRecord := candidateRecord
			badRecord.Candidate, badRecord.Intent = badCandidate, badIntent
			formalCoxBlockwiseRockTestWrite(t,
				fixture.roots[0], badCandidatePath, badRecord)
			garblerSignSecret := fixture.writeSecret(t, 0,
				formalCoxBlockwiseRockActionSign, "sign-garbler")
			garblerAuthorizationPath := filepath.Join(
				fixture.roots[0], "records", "authorization-garbler.json")
			garblerSign := formalCoxBlockwiseRockSignOperation{
				PinsetPath: fixture.pinsetPaths[0], PlanPath: fixture.planPaths[0],
				OpeningDir: fixture.openingDirs[0], TransportDir: fixture.roots[0],
				PeerName: plan.Policy.ComputePeers[0], Role: "garbler",
				HeaderRecordPaths:   fixture.headerPaths[0],
				TicketRecordPath:    fixture.ticketPaths[0],
				CandidateRecordPath: badCandidatePath,
				SecretBundlePath:    garblerSignSecret,
				AuthorizationRecordPath: filepath.Join(
					fixture.roots[0], "records", "authorization-substitute.json"),
			}
			if _, err := fixture.run(t, 0, formalCoxBlockwiseRockActionSign,
				garblerSign, ""); err == nil {
				t.Fatal("valid substitute candidate obtained the first local signature")
			}
			if exists, err := formalCoxBlockwiseRockExists(
				fixture.roots[0], garblerSignSecret); err != nil || !exists {
				t.Fatal("rejected substitute consumed the signer retry secret")
			}
			garblerSign.CandidateRecordPath = candidatePath
			garblerSign.AuthorizationRecordPath = garblerAuthorizationPath
			fixture.crashThenRun(t, 0, formalCoxBlockwiseRockActionSign,
				garblerSign, "after_sign_durable", garblerSignSecret)

			candidateEvaluatorPath := filepath.Join(
				fixture.roots[1], "relay", "candidate.json")
			var relayedCandidate formalCoxBlockwiseRockCandidateRecord
			formalCoxBlockwiseRockTestRelay(t,
				fixture.roots[0], candidatePath, fixture.roots[1],
				candidateEvaluatorPath, &relayedCandidate)
			garblerAuthorizationEvaluatorPath := filepath.Join(
				fixture.roots[1], "relay", "authorization-garbler.json")
			var garblerAuthorization formalCoxBlockwiseRockAuthorizationRecord
			formalCoxBlockwiseRockTestRelay(t,
				fixture.roots[0], garblerAuthorizationPath, fixture.roots[1],
				garblerAuthorizationEvaluatorPath, &garblerAuthorization)
			evaluatorSignSecret := fixture.writeSecret(t, 1,
				formalCoxBlockwiseRockActionSign, "sign-evaluator")
			evaluatorAuthorizationPath := filepath.Join(
				fixture.roots[1], "records", "authorization-evaluator.json")
			evaluatorSign := formalCoxBlockwiseRockSignOperation{
				PinsetPath: fixture.pinsetPaths[1], PlanPath: fixture.planPaths[1],
				OpeningDir: fixture.openingDirs[1], TransportDir: fixture.roots[1],
				PeerName: plan.Policy.ComputePeers[1], Role: "evaluator",
				HeaderRecordPaths:             fixture.headerPaths[1],
				TicketRecordPath:              fixture.ticketPaths[1],
				CandidateRecordPath:           candidateEvaluatorPath,
				PredecessorAuthorizationPaths: []string{garblerAuthorizationEvaluatorPath},
				SecretBundlePath:              evaluatorSignSecret,
				AuthorizationRecordPath:       evaluatorAuthorizationPath,
			}
			fixture.crashThenRun(t, 1, formalCoxBlockwiseRockActionSign,
				evaluatorSign, "after_sign_durable", evaluatorSignSecret)

			authorizationIngress := [2]string{
				filepath.Join(fixture.roots[0], "relay", "authorization-garbler.json"),
				filepath.Join(fixture.roots[0], "relay", "authorization-evaluator.json"),
			}
			formalCoxBlockwiseRockTestRelay(t,
				fixture.roots[0], garblerAuthorizationPath, fixture.roots[0],
				authorizationIngress[0], &formalCoxBlockwiseRockAuthorizationRecord{})
			formalCoxBlockwiseRockTestRelay(t,
				fixture.roots[1], evaluatorAuthorizationPath, fixture.roots[0],
				authorizationIngress[1], &formalCoxBlockwiseRockAuthorizationRecord{})

			publicationSecret := fixture.writeSecret(t, 0,
				formalCoxBlockwiseRockActionPreparePublication, "prepare-publication")
			publicationPath := filepath.Join(
				fixture.roots[0], "records", "publication-finalizer.json")
			preparePublication := formalCoxBlockwiseRockPreparePublicationOperation{
				PinsetPath: fixture.pinsetPaths[0], PlanPath: fixture.planPaths[0],
				OpeningDir: fixture.openingDirs[0], TransportDir: fixture.roots[0],
				HeaderRecordPaths: fixture.headerPaths[0],
				TicketRecordPath:  fixture.ticketPaths[0], CandidateRecordPath: candidatePath,
				AuthorizationRecordPaths: authorizationIngress,
				SecretBundlePath:         publicationSecret, PublicationRecordPath: publicationPath,
			}
			publicationResponse := fixture.crashThenRun(t, 0,
				formalCoxBlockwiseRockActionPreparePublication, preparePublication,
				"after_publication_durable", publicationSecret)
			if publicationResponse.Publication == nil ||
				publicationResponse.Publication.CertificateSHA256 == "" {
				t.Fatalf("publication response lacked public certificate: %#v",
					publicationResponse)
			}
			fixture.publication = *publicationResponse.Publication

			commitSecrets := [2]string{}
			commitPaths := [2]string{}
			commitPublicationPaths := [2]string{}
			commitOperations := [2]formalCoxBlockwiseRockCommitPublicationOperation{}
			for position, peer := range plan.Policy.ComputePeers {
				commitSecrets[position] = fixture.writeOpeningSecret(t, position,
					formalCoxBlockwiseRockActionCommitPublication,
					"commit-publication")
				commitPaths[position] = filepath.Join(
					fixture.roots[position], "records", "commit-publication.json")
				commitPublicationPaths[position] = filepath.Join(
					fixture.roots[position], "records", "publication-local.json")
				commitOperations[position] = formalCoxBlockwiseRockCommitPublicationOperation{
					PinsetPath: fixture.pinsetPaths[position],
					PlanPath:   fixture.planPaths[position],
					OpeningDir: fixture.openingDirs[position], PeerName: peer,
					Role: roles[position], Publication: fixture.publication,
					PublicationRecordPath: commitPublicationPaths[position],
					SecretBundlePath:      commitSecrets[position],
					CommitRecordPath:      commitPaths[position],
				}
			}
			fixture.crashThenRun(t, 0,
				formalCoxBlockwiseRockActionCommitPublication, commitOperations[0],
				"after_publication_commit_durable", commitSecrets[0])

			// Exercise the recoverable 1/2 state before evaluator commit. Each
			// preflight runs on one root; repair consumes only the signed public
			// publication returned by the published peer's command.
			var repairSource [2]string
			var repairLocal [2][2]string
			var repairResponse [2]formalCoxBlockwiseRockLifecycleResponse
			for local := range fixture.roots {
				for remote, role := range roles {
					repairLocal[local][remote] = filepath.Join(
						fixture.roots[local], "relay", "repair-preflight-"+role+".json")
				}
				secret := fixture.writeOpeningSecret(t, local,
					formalCoxBlockwiseRockActionPreflight, "preflight-repair")
				repairSource[local] = filepath.Join(
					fixture.roots[local], "records", "preflight-repair.json")
				operation := formalCoxBlockwiseRockTestPreflightOperation(
					fixture, local, secret, repairSource[local], filepath.Join(
						fixture.roots[local], "records", "preflight-repair-publication.json"))
				repairResponse[local] = fixture.crashThenRun(t, local,
					formalCoxBlockwiseRockActionPreflight, operation,
					"after_preflight_before_record", secret)
			}
			if repairResponse[0].State != formalCoxBlockwiseRockStatePublished ||
				repairResponse[0].Publication == nil ||
				repairResponse[1].State != formalCoxBlockwiseRockStateAbsent ||
				repairResponse[1].Publication != nil {
				t.Fatalf("unexpected 1/2 repair preflight: %#v / %#v",
					repairResponse[0], repairResponse[1])
			}
			formalCoxBlockwiseRockTestRelayPreflights(
				t, fixture, repairSource, repairLocal)
			repairSecret := fixture.writeStageSecret(t, 1, "stage-repair")
			repairStage := formalCoxBlockwiseRockStageOperation{
				ArtifactContractPath: fixture.contractPaths[1],
				PinsetPath:           fixture.pinsetPaths[1],
				PreflightRecordPaths: repairLocal[1],
				PlanPath:             filepath.Join(fixture.roots[1], "inputs", "must-not-open-plan.json"),
				PreflightOpeningDir:  fixture.openingDirs[1],
				CheckpointDir:        filepath.Join(fixture.roots[1], "must-not-open-checkpoint"),
				OpeningDir:           fixture.openingDirs[1], PeerName: plan.Policy.ComputePeers[1],
				SecretBundlePath: repairSecret,
				HeaderRecordPath: filepath.Join(
					fixture.roots[1], "records", "must-not-stage-header.json"),
			}
			repaired, err := fixture.run(t, 1,
				formalCoxBlockwiseRockActionStage, repairStage, "before_run_plan")
			if err != nil || repaired.State != formalCoxBlockwiseRockStateRepairPending ||
				repaired.Publication == nil || !reflect.DeepEqual(
				*repaired.Publication, *repairResponse[0].Publication) {
				t.Fatalf("repair did not relay exact public output without source: %#v/%v",
					repaired, err)
			}
			commitOperations[1].Publication = *repaired.Publication
			fixture.crashThenRun(t, 1,
				formalCoxBlockwiseRockActionCommitPublication, commitOperations[1],
				"after_publication_commit_durable", commitSecrets[1])

			commitIngress := [2]string{}
			for position, role := range roles {
				commitIngress[position] = filepath.Join(
					fixture.roots[0], "relay", "commit-"+role+".json")
				formalCoxBlockwiseRockTestRelay(t,
					fixture.roots[position], commitPaths[position], fixture.roots[0],
					commitIngress[position], &formalCoxBlockwiseRockCommitRecord{})
			}
			finalizeSecret := fixture.writeSecret(t, 0,
				formalCoxBlockwiseRockActionFinalizeAck, "finalize-ack")
			ackPath := filepath.Join(fixture.roots[0], "records", "ack.json")
			finalize := formalCoxBlockwiseRockFinalizeAckOperation{
				PinsetPath: fixture.pinsetPaths[0], PlanPath: fixture.planPaths[0],
				OpeningDir: fixture.openingDirs[0], TransportDir: fixture.roots[0],
				HeaderRecordPaths:     fixture.headerPaths[0],
				TicketRecordPath:      fixture.ticketPaths[0],
				PublicationRecordPath: commitPublicationPaths[0],
				CommitRecordPaths:     commitIngress,
				SecretBundlePath:      finalizeSecret, AckRecordPath: ackPath,
			}
			fixture.crashThenRun(t, 0, formalCoxBlockwiseRockActionFinalizeAck,
				finalize, "after_ack_durable", finalizeSecret)

			ackLocalPaths := [2]string{ackPath, filepath.Join(
				fixture.roots[1], "relay", "ack.json")}
			formalCoxBlockwiseRockTestRelay(t,
				fixture.roots[0], ackPath, fixture.roots[1],
				ackLocalPaths[1], &formalCoxBlockwiseRockAckRecord{})
			var ackOperations [2]formalCoxBlockwiseRockAckOperation
			var cleanupPaths [2]string
			for position, peer := range plan.Policy.ComputePeers {
				secret := fixture.writeSecret(t, position,
					formalCoxBlockwiseRockActionAck, "ack-local")
				cleanupPaths[position] = filepath.Join(
					fixture.roots[position], "records", "cleanup.json")
				ackOperations[position] = formalCoxBlockwiseRockAckOperation{
					PinsetPath:   fixture.pinsetPaths[position],
					PlanPath:     fixture.planPaths[position],
					OpeningDir:   fixture.openingDirs[position],
					TransportDir: fixture.roots[position], PeerName: peer,
					Role: roles[position], HeaderRecordPaths: fixture.headerPaths[position],
					TicketRecordPath:      fixture.ticketPaths[position],
					PublicationRecordPath: commitPublicationPaths[position],
					AckRecordPath:         ackLocalPaths[position], SecretBundlePath: secret,
					CleanupRecordPath: cleanupPaths[position],
				}
				if position == 1 {
					var tampered formalCoxBlockwiseRockAckRecord
					if err := formalCoxBlockwiseRockReadJSON(
						fixture.roots[position], ackLocalPaths[position],
						formalCoxBlockwiseRockMaxRecord, &tampered); err != nil {
						t.Fatal(err)
					}
					tampered.Proof.Signature = append(
						[]byte(nil), tampered.Proof.Signature...)
					tampered.Proof.Signature[0] ^= 1
					tamperedPath := filepath.Join(
						fixture.roots[position], "records", "ack-tampered.json")
					formalCoxBlockwiseRockTestWrite(
						t, fixture.roots[position], tamperedPath, tampered)
					badSecret := fixture.writeSecret(t, position,
						formalCoxBlockwiseRockActionAck, "ack-tampered")
					badOperation := ackOperations[position]
					badOperation.AckRecordPath = tamperedPath
					badOperation.SecretBundlePath = badSecret
					badOperation.CleanupRecordPath = filepath.Join(
						fixture.roots[position], "records", "cleanup-tampered.json")
					if _, err := fixture.run(t, position,
						formalCoxBlockwiseRockActionAck, badOperation, ""); err == nil {
						t.Fatal("tampered ACK reached local publication/cleanup")
					}
					if exists, err := formalCoxBlockwiseRockExists(
						fixture.roots[position], badSecret); err != nil || !exists {
						t.Fatal("tampered ACK consumed retry secret")
					}
				}
				fixture.crashThenRun(t, position, formalCoxBlockwiseRockActionAck,
					ackOperations[position], "after_transport_cleanup", secret)
				var cleanup formalCoxBlockwiseRockCleanupRecord
				if err := formalCoxBlockwiseRockReadJSON(fixture.roots[position],
					cleanupPaths[position], formalCoxBlockwiseRockMaxRecord,
					&cleanup); err != nil || cleanup.Receipt.RemovedRecords != []int{4, 1}[position] {
					t.Fatalf("unexpected exact cleanup count: %#v/%v", cleanup, err)
				}
			}

			for position := range fixture.roots {
				replaySecret := fixture.writeSecret(t, position,
					formalCoxBlockwiseRockActionAck, "ack-replay")
				replayOperation := ackOperations[position]
				replayOperation.SecretBundlePath = replaySecret
				replayed, err := fixture.run(t, position,
					formalCoxBlockwiseRockActionAck, replayOperation, "")
				if err != nil || !replayed.Replayed ||
					replayed.State != formalCoxBlockwiseRockStateCleaned {
					t.Fatalf("terminal cleanup replay failed: %#v/%v", replayed, err)
				}
				lateSealSecret := fixture.writeSecret(t, position,
					formalCoxBlockwiseRockActionSeal, "seal-after-ack")
				lateSeal := sealOperations[position]
				lateSeal.SecretBundlePath = lateSealSecret
				lateSeal.EnvelopeRecordPath = filepath.Join(
					fixture.roots[position], "records", "late-envelope.json")
				if _, err := fixture.run(t, position,
					formalCoxBlockwiseRockActionSeal, lateSeal, ""); err == nil {
					t.Fatal("late seal recreated terminal transport")
				}
			}

			latePrepareSecret := fixture.writeSecret(t, 0,
				formalCoxBlockwiseRockActionPrepare, "prepare-after-ack")
			latePrepare := prepareOperation
			latePrepare.SecretBundlePath = latePrepareSecret
			latePrepare.EnvelopeRecordPaths = [2]string{
				filepath.Join(fixture.roots[0], "relay", "must-not-import-garbler.json"),
				filepath.Join(fixture.roots[0], "relay", "must-not-import-evaluator.json"),
			}
			latePrepare.CandidateRecordPath = filepath.Join(
				fixture.roots[0], "records", "must-not-rebuild-candidate.json")
			latePrepared, err := fixture.run(t, 0,
				formalCoxBlockwiseRockActionPrepare, latePrepare, "prepare_after_import_garbler")
			if err != nil || latePrepared.State != formalCoxBlockwiseRockStatePublished ||
				!latePrepared.Replayed {
				t.Fatalf("late prepare did not replay before import: %#v/%v",
					latePrepared, err)
			}
			lateTicketSecret := fixture.writeSecret(t, 0,
				formalCoxBlockwiseRockActionTicket, "ticket-after-ack")
			lateTicket := ticketOperation
			lateTicket.SecretBundlePath = lateTicketSecret
			lateTicket.TicketRecordPath = filepath.Join(
				fixture.roots[0], "records", "late-ticket.json")
			if _, err := fixture.run(t, 0,
				formalCoxBlockwiseRockActionTicket, lateTicket, "before_ticket_issue"); err == nil {
				t.Fatal("late ticket proceeded past ArtifactID publication preflight")
			}
			for _, root := range fixture.roots {
				if err := filepath.Walk(root, func(path string, info os.FileInfo,
					walkErr error,
				) error {
					if walkErr != nil || info.IsDir() {
						return walkErr
					}
					name := filepath.Base(path)
					if strings.HasPrefix(name, "outbox-") ||
						strings.HasPrefix(name, "ingress-") ||
						strings.HasPrefix(name, "transport-key-") {
						return fmt.Errorf("terminal transport record reappeared")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}

			var terminalSource [2]string
			var terminalLocal [2][2]string
			for local := range fixture.roots {
				for remote, role := range roles {
					terminalLocal[local][remote] = filepath.Join(
						fixture.roots[local], "relay", "terminal-preflight-"+role+".json")
				}
				secret := fixture.writeOpeningSecret(t, local,
					formalCoxBlockwiseRockActionPreflight, "preflight-terminal")
				terminalSource[local] = filepath.Join(
					fixture.roots[local], "records", "preflight-terminal.json")
				operation := formalCoxBlockwiseRockTestPreflightOperation(
					fixture, local, secret, terminalSource[local], filepath.Join(
						fixture.roots[local], "records", "preflight-terminal-publication.json"))
				response, err := fixture.run(t, local,
					formalCoxBlockwiseRockActionPreflight, operation, "")
				if err != nil || response.State != formalCoxBlockwiseRockStatePublished ||
					response.Publication == nil || !reflect.DeepEqual(
					*response.Publication, fixture.publication) {
					t.Fatalf("terminal preflight changed public replay: %#v/%v",
						response, err)
				}
			}
			formalCoxBlockwiseRockTestRelayPreflights(
				t, fixture, terminalSource, terminalLocal)
			terminalStageSecret := fixture.writeStageSecret(t, 1, "stage-terminal")
			terminalStage := repairStage
			terminalStage.PreflightRecordPaths = terminalLocal[1]
			terminalStage.SecretBundlePath = terminalStageSecret
			terminalStage.PlanPath = filepath.Join(
				fixture.roots[1], "inputs", "new-run-must-not-open.json")
			terminalStage.HeaderRecordPath = filepath.Join(
				fixture.roots[1], "records", "terminal-must-not-stage.json")
			terminalResponse, err := fixture.run(t, 1,
				formalCoxBlockwiseRockActionStage, terminalStage, "before_run_plan")
			if err != nil || terminalResponse.State != formalCoxBlockwiseRockStatePublished ||
				!terminalResponse.Replayed {
				t.Fatalf("terminal stage touched new run/source: %#v/%v",
					terminalResponse, err)
			}
		})
	}
}
