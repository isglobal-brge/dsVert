package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type formalCoxBlockwiseOpeningTestFixture struct {
	plan        formalCoxBlockwisePlan
	pins        map[string]ed25519.PublicKey
	private     map[string]ed25519.PrivateKey
	checkpoints map[string]*formalCoxBlockwiseCheckpointStore
	store       *formalCoxBlockwiseOpeningStore
	dir         string
	storageKey  [32]byte
}

func formalCoxBlockwiseOpeningTestCompletedStores(t testing.TB,
	plan formalCoxBlockwisePlan, private map[string]ed25519.PrivateKey,
	beta []*big.Int, valid bool,
) (map[string]*formalCoxBlockwiseCheckpointStore, string) {
	t.Helper()
	if len(beta) != plan.Policy.CovariateCount {
		t.Fatal("invalid opening test beta")
	}
	residues := make([]*big.Int, len(beta))
	for index := range beta {
		residues[index] = formalCoxResidue(beta[index], plan.RingBits)
	}
	left, right := formalCoxBlockwiseTestSplit(residues, plan.RingBits, 91)
	parts := [][]*big.Int{left, right}
	transcriptDigest := sha256.Sum256([]byte(t.Name() + "/final-transcript"))
	transcript := hex.EncodeToString(transcriptDigest[:])
	attemptDigest := sha256.Sum256([]byte(t.Name() + "/final-attempt"))
	attempt := hex.EncodeToString(attemptDigest[:])
	planSHA, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	lastStep, err := formalCoxBlockwiseWorkerStepAt(plan, plan.ScheduleSteps-1)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stores := make(map[string]*formalCoxBlockwiseCheckpointStore, 2)
	receipts := make([]formalCoxBlockwiseStepReceipt, 2)
	states := make([]formalCoxBlockwiseCheckpoint, 2)
	for index, peer := range plan.Policy.ComputePeers {
		store, err := newFormalCoxBlockwiseCheckpointStore(
			filepath.Join(root, peer), formalCoxBlockwiseWorkerTestKey(peer),
			plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Bootstrap(); err != nil {
			t.Fatal(err)
		}
		initial, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		state := initial
		state.Generation++
		state.NextStep = plan.ScheduleSteps
		state.Pending = nil
		state.State = formalCoxBlockwiseZeroStrings(plan.StateCoordinates)
		for coefficient := range parts[index] {
			state.State[coefficient] = parts[index][coefficient].Text(16)
		}
		validityShare := index == 1 && valid
		if validityShare {
			state.State[plan.StateArithmetic] = "1"
		}
		state.Scores = formalCoxBlockwiseZeroStrings(plan.Policy.CovariateCount)
		state.Candidate = formalCoxBlockwiseZeroStrings(plan.Policy.CovariateCount)
		state.Projected = formalCoxBlockwiseZeroStrings(plan.Policy.CovariateCount)
		state.TranscriptSHA256 = transcript
		state.FinalCommitSHA256 = ""
		state.LastReceipt = nil
		state.MAC = ""
		stateSHA := formalCoxBlockwisePrivateStateSHA256(state)
		receipt := formalCoxBlockwiseStepReceipt{
			Version: formalCoxBlockwiseReceiptVersion, PlanSHA256: planSHA,
			Peer: peer, Step: lastStep, AttemptID: attempt,
			StateSHA256: stateSHA, TranscriptSHA256: transcript,
		}
		message, err := formalCoxBlockwiseReceiptUnsigned(receipt)
		if err != nil {
			t.Fatal(err)
		}
		receipt.Signature = ed25519.Sign(private[peer], message)
		state.LastReceipt = &receipt
		states[index], receipts[index], stores[peer] = state, receipt, store
	}
	finalCommit, err := formalCoxBlockwiseFinalCommitSHA256(receipts)
	if err != nil {
		t.Fatal(err)
	}
	for index, peer := range plan.Policy.ComputePeers {
		state := states[index]
		state.FinalCommitSHA256 = finalCommit
		initial, err := stores[peer].Load()
		if err != nil {
			t.Fatal(err)
		}
		if err := stores[peer].writeCAS(initial.MAC, state); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stores[peer].Completion(); err != nil {
			t.Fatal(err)
		}
	}
	return stores, root
}

func newFormalCoxBlockwiseOpeningTestFixture(t testing.TB, custodians int,
	tag string,
) formalCoxBlockwiseOpeningTestFixture {
	t.Helper()
	plan, pins, private := formalCoxBlockwiseSourceTestPlan(t, custodians)
	checkpoints, _ := formalCoxBlockwiseOpeningTestCompletedStores(
		t, plan, private, []*big.Int{big.NewInt(64), big.NewInt(-32)}, true)
	dir := filepath.Join(t.TempDir(), "opening")
	storageKey := sha256.Sum256([]byte("formal-cox/opening/" + tag))
	store, err := newFormalCoxBlockwiseOpeningStore(
		dir, storageKey, plan, pins)
	if err != nil {
		t.Fatal(err)
	}
	return formalCoxBlockwiseOpeningTestFixture{
		plan: plan, pins: pins, private: private, checkpoints: checkpoints,
		store: store, dir: dir, storageKey: storageKey,
	}
}

func (fixture formalCoxBlockwiseOpeningTestFixture) submitAll(t testing.TB) {
	t.Helper()
	for _, peer := range fixture.plan.Policy.ComputePeers {
		header, replayed, err := fixture.store.SubmitLocal(
			fixture.checkpoints[peer], fixture.private[peer])
		if err != nil || replayed || header.PeerName != peer ||
			header.ArtifactID != fixture.store.artifactID {
			t.Fatalf("submit %s: %+v replay=%v err=%v", peer, header, replayed, err)
		}
	}
}

func TestFormalCoxBlockwiseStickyOpeningK2K3K5ColdReplay(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseOpeningTestFixture(
				t, custodians, "cold-replay")
			defer fixture.store.Close()
			fixture.submitAll(t)
			intent, publication, replayed, err := fixture.store.Prepare(nil)
			if err != nil || replayed || len(publication.Certificate) != 0 ||
				!formalCoxIsSHA256(intent.CandidateSHA256) {
				t.Fatalf("prepare: %+v %+v %v %v", intent, publication, replayed, err)
			}
			if err := fixture.store.Close(); err != nil {
				t.Fatal(err)
			}
			beforeSignRestart, err := newFormalCoxBlockwiseOpeningStore(
				fixture.dir, fixture.storageKey, fixture.plan, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			fixture.store = beforeSignRestart
			defer beforeSignRestart.Close()
			privateOpened := 0
			restartedIntent, _, found, err := fixture.store.Prepare(
				func(phase string) error {
					if phase == "before_private_open" {
						privateOpened++
					}
					return nil
				})
			if err != nil || found || privateOpened != 0 ||
				!formalCoxBlockwiseOpeningEqual(restartedIntent, intent) {
				t.Fatalf("candidate restart reopened shares: %v/%d/%v", err, privateOpened, found)
			}
			peers := fixture.plan.Policy.ComputePeers
			first, firstReplay, err := fixture.store.SignOnce(
				intent, peers[0], fixture.private[peers[0]], nil)
			if err != nil || firstReplay {
				t.Fatalf("first SignOnce: %v replay=%v", err, firstReplay)
			}
			second, secondReplay, err := fixture.store.SignOnce(
				intent, peers[1], fixture.private[peers[1]],
				[]jointDPBiomedicalGaussianSignature{first})
			if err != nil || secondReplay {
				t.Fatalf("second SignOnce: %v replay=%v", err, secondReplay)
			}
			crashed, crashErr := fixture.store.Publish(intent,
				[]jointDPBiomedicalGaussianSignature{first, second},
				func(string) error { return fmt.Errorf("injected pre-CAS crash") })
			if crashErr == nil || len(crashed.Certificate) != 0 {
				t.Fatal("pre-CAS crash returned an unstored public opening")
			}
			if _, err := fixture.store.Replay(fixture.store.artifactID); !os.IsNotExist(err) {
				t.Fatalf("pre-CAS crash left a public opening: %v", err)
			}
			publication, err = fixture.store.Publish(intent,
				[]jointDPBiomedicalGaussianSignature{first, second}, nil)
			if err != nil || publication.Replayed {
				t.Fatalf("publish: %v replay=%v", err, publication.Replayed)
			}
			certificate, err := formalCoxBlockwiseDecodeOpeningPublication(
				publication, fixture.pins)
			if err != nil || !certificate.Candidate.Valid ||
				len(certificate.Candidate.Coefficients) != 2 ||
				certificate.Candidate.Coefficients[0].BetaSteps != "64" ||
				certificate.Candidate.Coefficients[1].BetaSteps != "-32" ||
				certificate.Candidate.ProductionReady {
				t.Fatalf("invalid public Cox opening: %+v / %v", certificate, err)
			}
			lower := bytes.ToLower(publication.Certificate)
			for _, forbidden := range [][]byte{
				[]byte(`coefficient_shares`), []byte(`validity_share`),
				[]byte(`private_key`), []byte(`storage_key`),
				[]byte(`run_id`), []byte(`production_ready`),
				[]byte(`lifetime`), []byte(`reservation`), []byte(`ledger`),
				[]byte(`quota`), []byte(`catalog`), []byte(`request_count`),
			} {
				if bytes.Contains(lower, forbidden) {
					t.Fatalf("public opening contains %s", forbidden)
				}
			}
			replay, err := fixture.store.Replay(fixture.store.artifactID)
			if err != nil || !replay.Replayed ||
				!bytes.Equal(replay.Certificate, publication.Certificate) {
				t.Fatalf("warm replay: %v", err)
			}
			if err := fixture.store.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := newFormalCoxBlockwiseOpeningStore(
				fixture.dir, fixture.storageKey, fixture.plan, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			cold, err := restarted.Replay(restarted.artifactID)
			if err != nil || !cold.Replayed ||
				!bytes.Equal(cold.Certificate, publication.Certificate) {
				t.Fatalf("cold replay: %v", err)
			}
			opened := 0
			_, preflight, found, err := restarted.Prepare(func(phase string) error {
				if phase == "before_private_open" {
					opened++
				}
				return nil
			})
			if err != nil || !found || opened != 0 ||
				!bytes.Equal(preflight.Certificate, publication.Certificate) {
				t.Fatalf("preflight replay reopened private state: %v/%d/%v", err, opened, found)
			}
		})
	}
}

func TestFormalCoxBlockwiseStickyOpeningConcurrentSignAndPublish(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			formalCoxBlockwiseStickyOpeningTestConcurrentSignAndPublish(
				t, custodians)
		})
	}
}

func formalCoxBlockwiseStickyOpeningTestConcurrentSignAndPublish(
	t *testing.T, custodians int,
) {
	fixture := newFormalCoxBlockwiseOpeningTestFixture(t, custodians, "concurrent")
	defer fixture.store.Close()
	fixture.submitAll(t)
	intent, _, _, err := fixture.store.Prepare(nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newFormalCoxBlockwiseOpeningStore(
		fixture.dir, fixture.storageKey, fixture.plan, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	peer := fixture.plan.Policy.ComputePeers[0]
	type signed struct {
		receipt  jointDPBiomedicalGaussianSignature
		replayed bool
		err      error
	}
	results := make(chan signed, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, store := range []*formalCoxBlockwiseOpeningStore{
		fixture.store, restarted,
	} {
		go func(store *formalCoxBlockwiseOpeningStore) {
			start.Wait()
			receipt, replayed, err := store.SignOnce(
				intent, peer, fixture.private[peer], nil)
			results <- signed{receipt, replayed, err}
		}(store)
	}
	start.Done()
	left, right := <-results, <-results
	if left.err != nil || right.err != nil || left.replayed == right.replayed ||
		!bytes.Equal(left.receipt.Signature, right.receipt.Signature) {
		t.Fatalf("concurrent SignOnce: %+v / %+v", left, right)
	}
	first := left.receipt
	secondPeer := fixture.plan.Policy.ComputePeers[1]
	second, _, err := fixture.store.SignOnce(intent, secondPeer,
		fixture.private[secondPeer], []jointDPBiomedicalGaussianSignature{first})
	if err != nil {
		t.Fatal(err)
	}
	type published struct {
		value formalCoxBlockwiseOpeningPublication
		err   error
	}
	publications := make(chan published, 2)
	start = sync.WaitGroup{}
	start.Add(1)
	for _, store := range []*formalCoxBlockwiseOpeningStore{
		fixture.store, restarted,
	} {
		go func(store *formalCoxBlockwiseOpeningStore) {
			start.Wait()
			value, err := store.Publish(intent,
				[]jointDPBiomedicalGaussianSignature{first, second}, nil)
			publications <- published{value, err}
		}(store)
	}
	start.Done()
	one, two := <-publications, <-publications
	if one.err != nil || two.err != nil || one.value.Replayed == two.value.Replayed ||
		!bytes.Equal(one.value.Certificate, two.value.Certificate) {
		t.Fatalf("concurrent publication: %+v / %+v", one, two)
	}
}

func TestFormalCoxBlockwiseStickyOpeningK2K3K5BlocksRerollAndRelink(
	t *testing.T,
) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseOpeningTestFixture(
				t, custodians, "reroll-link")
			defer fixture.store.Close()
			fixture.submitAll(t)
			firstPeer := fixture.plan.Policy.ComputePeers[0]
			original, err := fixture.store.loadPrivateHandoff(firstPeer)
			if err != nil {
				t.Fatal(err)
			}
			reroll, _ := formalCoxBlockwiseOpeningTestCompletedStores(
				t, fixture.plan, fixture.private,
				[]*big.Int{big.NewInt(12), big.NewInt(9)}, true)
			replayedHeader, replayed, err := fixture.store.SubmitLocal(
				reroll[firstPeer], fixture.private[firstPeer])
			if err != nil || !replayed || !formalCoxBlockwiseOpeningEqual(
				replayedHeader, original) {
				t.Fatalf("reroll did not replay first handoff: %v replay=%v", err, replayed)
			}

			alternate := fixture.plan
			run := sha256.Sum256([]byte(t.Name() + "/operational-relink"))
			alternate.RunID = hex.EncodeToString(run[:])
			_, alternateID, err := formalCoxBlockwiseBuildStickyArtifact(
				alternate, fixture.pins)
			if err != nil || alternateID != fixture.store.artifactID {
				t.Fatalf("operational relink changed canonical ID: %v", err)
			}
			alternateCheckpoints, _ := formalCoxBlockwiseOpeningTestCompletedStores(
				t, alternate, fixture.private,
				[]*big.Int{big.NewInt(20), big.NewInt(-7)}, true)
			alternateStore, err := newFormalCoxBlockwiseOpeningStore(
				fixture.dir, fixture.storageKey, alternate, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			defer alternateStore.Close()
			if _, _, err := alternateStore.SubmitLocal(
				alternateCheckpoints[firstPeer], fixture.private[firstPeer]); err == nil {
				t.Fatal("different physical run relinked an existing canonical handoff")
			}

			intent, _, _, err := fixture.store.Prepare(nil)
			if err != nil {
				t.Fatal(err)
			}
			peers := fixture.plan.Policy.ComputePeers
			first, _, err := fixture.store.SignOnce(
				intent, peers[0], fixture.private[peers[0]], nil)
			if err != nil {
				t.Fatal(err)
			}
			second, _, err := fixture.store.SignOnce(intent, peers[1],
				fixture.private[peers[1]],
				[]jointDPBiomedicalGaussianSignature{first})
			if err != nil {
				t.Fatal(err)
			}
			publication, err := fixture.store.Publish(intent,
				[]jointDPBiomedicalGaussianSignature{first, second}, nil)
			if err != nil {
				t.Fatal(err)
			}
			opened := 0
			_, replay, found, err := alternateStore.Prepare(func(phase string) error {
				if phase == "before_private_open" {
					opened++
				}
				return nil
			})
			if err != nil || !found || opened != 0 ||
				!bytes.Equal(replay.Certificate, publication.Certificate) {
				t.Fatalf("canonical replay opened relinked run: %v/%d/%v", err, opened, found)
			}
		})
	}
}

func TestFormalCoxBlockwiseStickyOpeningInvalidityIsPublicAndFailClosed(
	t *testing.T,
) {
	plan, pins, private := formalCoxBlockwiseSourceTestPlan(t, 2)
	zeroCheckpoints, _ := formalCoxBlockwiseOpeningTestCompletedStores(
		t, plan, private, []*big.Int{big.NewInt(0), big.NewInt(0)}, false)
	dir := filepath.Join(t.TempDir(), "invalid-opening")
	key := sha256.Sum256([]byte(t.Name() + "/invalid-opening-key"))
	store, err := newFormalCoxBlockwiseOpeningStore(dir, key, plan, pins)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, peer := range plan.Policy.ComputePeers {
		if _, _, err := store.SubmitLocal(zeroCheckpoints[peer], private[peer]); err != nil {
			t.Fatal(err)
		}
	}
	intent, _, _, err := store.Prepare(nil)
	if err != nil {
		t.Fatal(err)
	}
	peers := plan.Policy.ComputePeers
	first, _, err := store.SignOnce(intent, peers[0], private[peers[0]], nil)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.SignOnce(intent, peers[1], private[peers[1]],
		[]jointDPBiomedicalGaussianSignature{first})
	if err != nil {
		t.Fatal(err)
	}
	publication, err := store.Publish(intent,
		[]jointDPBiomedicalGaussianSignature{first, second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := formalCoxBlockwiseDecodeOpeningPublication(publication, pins)
	if err != nil || certificate.Candidate.Valid {
		t.Fatalf("invalid execution was not published as invalid: %v", err)
	}
	for _, coefficient := range certificate.Candidate.Coefficients {
		if coefficient.BetaSteps != "0" ||
			coefficient.HazardRatioMidpointRational != "1" {
			t.Fatalf("invalid execution leaked beta: %+v", coefficient)
		}
	}

	nonzeroCheckpoints, _ := formalCoxBlockwiseOpeningTestCompletedStores(
		t, plan, private, []*big.Int{big.NewInt(1), big.NewInt(0)}, false)
	nonzeroDir := filepath.Join(t.TempDir(), "invalid-nonzero")
	nonzeroStore, err := newFormalCoxBlockwiseOpeningStore(
		nonzeroDir, sha256.Sum256([]byte(t.Name()+"/invalid-nonzero-key")),
		plan, pins)
	if err != nil {
		t.Fatal(err)
	}
	defer nonzeroStore.Close()
	for _, peer := range peers {
		if _, _, err := nonzeroStore.SubmitLocal(
			nonzeroCheckpoints[peer], private[peer]); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := nonzeroStore.Prepare(nil); err == nil {
		t.Fatal("invalid execution with non-zero beta reached an opening intent")
	}
}

func TestFormalCoxBlockwiseStickyOpeningOwnerOnlyLinkAndPublicTamper(
	t *testing.T,
) {
	fixture := newFormalCoxBlockwiseOpeningTestFixture(t, 3, "owner-link-tamper")
	defer fixture.store.Close()
	fixture.submitAll(t)
	intent, _, _, err := fixture.store.Prepare(nil)
	if err != nil {
		t.Fatal(err)
	}
	badReady := intent
	badReady.ProductionReady = true
	firstPeer := fixture.plan.Policy.ComputePeers[0]
	if _, _, err := fixture.store.SignOnce(
		badReady, firstPeer, fixture.private[firstPeer], nil); err == nil {
		t.Fatal("in-memory readiness promoted an opening intent")
	}
	header, err := fixture.store.loadPrivateHandoff(firstPeer)
	if err != nil {
		t.Fatal(err)
	}
	header.ProductionReady = true
	if err := fixture.store.validateHandoffHeader(header); err == nil {
		t.Fatal("in-memory readiness promoted a local handoff")
	}
	peers := fixture.plan.Policy.ComputePeers
	first, _, err := fixture.store.SignOnce(
		intent, peers[0], fixture.private[peers[0]], nil)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := fixture.store.SignOnce(intent, peers[1],
		fixture.private[peers[1]], []jointDPBiomedicalGaussianSignature{first})
	if err != nil {
		t.Fatal(err)
	}
	publication, err := fixture.store.Publish(intent,
		[]jointDPBiomedicalGaussianSignature{first, second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := formalCoxBlockwiseDecodeOpeningPublication(
		publication, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	certificate.ProductionReady = true
	if err := formalCoxBlockwiseValidateOpeningCertificate(
		certificate, fixture.pins); err == nil {
		t.Fatal("in-memory readiness promoted a public certificate")
	}

	if err := filepath.WalkDir(fixture.dir,
		func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("opening path is not owner-only: %s", path)
			}
			if entry.Type().IsRegular() {
				encoded, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				lower := bytes.ToLower(encoded)
				for _, forbidden := range [][]byte{
					[]byte("coefficient_shares"), []byte("validity_share"),
					[]byte("private_key"), []byte("storage_key"),
					[]byte("beta_shares"),
				} {
					if bytes.Contains(lower, forbidden) {
						return fmt.Errorf("private record contains plaintext %s", forbidden)
					}
				}
				if bytes.Contains([]byte(filepath.ToSlash(path)),
					[]byte("/private-v1/")) && bytes.Contains(lower, []byte("beta_steps")) {
					return fmt.Errorf("pre-publication candidate contains plaintext beta")
				}
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}

	publicRelative, err := fixture.store.publicRelativePath(
		fixture.store.artifactID, false)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(fixture.dir, publicRelative)
	alias := publicPath + ".alias"
	if err := os.Link(publicPath, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Replay(fixture.store.artifactID); err == nil {
		t.Fatal("hard-linked public record was accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Replay(fixture.store.artifactID); err == nil {
		t.Fatal("non-owner-only public record was accepted")
	}
	if err := os.Chmod(publicPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Replay(fixture.store.artifactID); err != nil {
		t.Fatal(err)
	}

	badCertificate := certificate
	badCertificate.ProductionReady = false
	badCertificate.Candidate.Coefficients = append(
		[]formalCoxBlockwiseOpeningCoefficient(nil),
		certificate.Candidate.Coefficients...)
	badCertificate.Candidate.Coefficients[0].BetaSteps = "65"
	badBytes, err := json.Marshal(badCertificate)
	if err != nil {
		t.Fatal(err)
	}
	badPublication := formalCoxBlockwiseOpeningPublication{
		ArtifactID:        publication.ArtifactID,
		CertificateSHA256: formalCoxBlockwiseOpeningCertificateSHA256(badBytes),
		Certificate:       badBytes,
	}
	if _, err := formalCoxBlockwiseDecodeOpeningPublication(
		badPublication, fixture.pins); err == nil {
		t.Fatal("tampered public beta was accepted")
	}
}

func TestFormalCoxBlockwiseStickyOpeningRejectsMissingOrderModeAndTamper(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			formalCoxBlockwiseStickyOpeningTestRejectsMissingOrderModeAndTamper(
				t, custodians)
		})
	}
}

func formalCoxBlockwiseStickyOpeningTestRejectsMissingOrderModeAndTamper(
	t *testing.T, custodians int,
) {
	fixture := newFormalCoxBlockwiseOpeningTestFixture(t, custodians, "adversarial")
	defer fixture.store.Close()
	firstPeer, secondPeer := fixture.plan.Policy.ComputePeers[0],
		fixture.plan.Policy.ComputePeers[1]
	if _, _, _, err := fixture.store.Prepare(nil); err == nil {
		t.Fatal("opening prepared without either local handoff")
	}
	if _, _, err := fixture.store.SubmitLocal(
		fixture.checkpoints[firstPeer], fixture.private[firstPeer]); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := fixture.store.Prepare(nil); err == nil {
		t.Fatal("opening prepared with one local handoff")
	}
	if _, _, err := fixture.store.SubmitLocal(
		fixture.checkpoints[secondPeer], fixture.private[secondPeer]); err != nil {
		t.Fatal(err)
	}
	intent, _, _, err := fixture.store.Prepare(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.SignOnce(intent, secondPeer,
		fixture.private[secondPeer], nil); err == nil {
		t.Fatal("evaluator signed without ordered garbler predecessor")
	}
	witness := fixture.plan.Policy.CustodianPeers[len(fixture.plan.Policy.CustodianPeers)-1]
	if witness != firstPeer && witness != secondPeer {
		if _, _, err := fixture.store.SignOnce(
			intent, witness, fixture.private[witness], nil); err == nil {
			t.Fatal("witness acted as an opening authority")
		}
	}
	badMode := intent
	badMode.OpeningMode += "/other"
	if _, _, err := fixture.store.SignOnce(
		badMode, firstPeer, fixture.private[firstPeer], nil); err == nil {
		t.Fatal("changed opening mode reached SignOnce")
	}
	first, _, err := fixture.store.SignOnce(
		intent, firstPeer, fixture.private[firstPeer], nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong := first
	wrong.Signature = append([]byte(nil), first.Signature...)
	wrong.Signature[0] ^= 1
	if _, _, err := fixture.store.SignOnce(intent, secondPeer,
		fixture.private[secondPeer], []jointDPBiomedicalGaussianSignature{wrong}); err == nil {
		t.Fatal("tampered predecessor reached evaluator SignOnce")
	}
	second, _, err := fixture.store.SignOnce(intent, secondPeer,
		fixture.private[secondPeer], []jointDPBiomedicalGaussianSignature{first})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Publish(intent,
		[]jointDPBiomedicalGaussianSignature{second, first}, nil); err == nil {
		t.Fatal("reordered opening receipts were published")
	}
	if _, err := fixture.store.Publish(intent,
		[]jointDPBiomedicalGaussianSignature{first}, nil); err == nil {
		t.Fatal("missing opening receipt was published")
	}
	spool, err := fixture.store.privateRelativePath(
		fixture.store.artifactID, "handoff", firstPeer, false)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.dir, spool)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(encoded), []byte("coefficient_shares")) ||
		bytes.Contains(bytes.ToLower(encoded), []byte("validity_share")) {
		t.Fatal("durable handoff stored plaintext shares")
	}
	encoded[len(encoded)/2] ^= 1
	if err := exactGCAtomicReplace(path, encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.loadPrivateHandoff(firstPeer); err == nil {
		t.Fatal("tampered encrypted handoff was accepted")
	}
}
