package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type formalCoxBlockwiseDistributedLifecycleFixture struct {
	plan              formalCoxBlockwisePlan
	pins              map[string]ed25519.PublicKey
	private           map[string]ed25519.PrivateKey
	checkpoints       map[string]*formalCoxBlockwiseCheckpointStore
	locals            [2]*formalCoxBlockwiseOpeningStore
	outboxes          [2]*formalFinalizerHandoffStore
	headers           [2]formalCoxBlockwiseOpeningHandoffHeader
	envelopes         [2]formalFinalizerHandoffEnvelope
	binding           formalFinalizerHandoffBinding
	ticket            formalFinalizerHandoffTicket
	finalizer         *formalCoxBlockwiseOpeningStore
	finalizerDir      string
	finalizerKey      [32]byte
	ingress           *formalFinalizerHandoffStore
	ingressDir        string
	ingressStorage    [32]byte
	transportSecret64 string
}

func newFormalCoxBlockwiseDistributedLifecycleFixture(
	t *testing.T, custodians int,
) *formalCoxBlockwiseDistributedLifecycleFixture {
	t.Helper()
	base := newFormalCoxBlockwiseOpeningTestFixture(
		t, custodians, "distributed-lifecycle")
	if err := base.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture := &formalCoxBlockwiseDistributedLifecycleFixture{
		plan: base.plan, pins: base.pins, private: base.private,
		checkpoints: base.checkpoints,
	}
	for index, peer := range fixture.plan.Policy.ComputePeers {
		role := []string{"garbler", "evaluator"}[index]
		key := sha256.Sum256([]byte(t.Name() + "/local-opening/" + role))
		store, err := newFormalCoxBlockwiseOpeningStore(
			filepath.Join(t.TempDir(), "local-opening-"+role), key,
			fixture.plan, fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
		fixture.locals[index] = store
		header, replayed, err := store.SubmitLocal(
			fixture.checkpoints[peer], fixture.private[peer])
		if err != nil || replayed {
			t.Fatalf("local %s handoff: replay=%v err=%v", role, replayed, err)
		}
		fixture.headers[index] = header
	}
	binding, err := formalCoxBlockwiseOpeningFinalizerBinding(
		fixture.locals[0], fixture.headers)
	if err != nil {
		t.Fatal(err)
	}
	fixture.binding = binding
	fixture.finalizerDir = filepath.Join(t.TempDir(), "private-finalizer")
	fixture.finalizerKey = sha256.Sum256([]byte(t.Name() + "/private-finalizer"))
	fixture.finalizer, err = newFormalCoxBlockwiseOpeningStore(
		fixture.finalizerDir, fixture.finalizerKey, fixture.plan, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	fixture.ingressDir = filepath.Join(t.TempDir(), "typed-ingress")
	fixture.ingressStorage = sha256.Sum256([]byte(t.Name() + "/typed-ingress"))
	fixture.ingress, err = newFormalFinalizerHandoffStoreForTest(
		fixture.ingressDir, binding, fixture.ingressStorage, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	finalizerPeer := fixture.plan.Policy.ComputePeers[0]
	ticket, secret, replayed, err := fixture.ingress.IssueTicketOnce(
		fixture.private[finalizerPeer])
	if err != nil || replayed || len(secret) != 32 {
		t.Fatalf("durable ticket: replay=%v secret=%d err=%v",
			replayed, len(secret), err)
	}
	fixture.transportSecret64 = base64.StdEncoding.EncodeToString(secret)
	clear(secret)
	fixture.ticket = ticket
	for index, peer := range fixture.plan.Policy.ComputePeers {
		role := []string{"garbler", "evaluator"}[index]
		storage := sha256.Sum256([]byte(t.Name() + "/outbox/" + role))
		outbox, err := newFormalFinalizerHandoffStoreForTest(
			filepath.Join(t.TempDir(), "outbox-"+role), binding, storage, fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
		fixture.outboxes[index] = outbox
		envelope, replayed, err := formalCoxBlockwiseSealLocalOpening(
			fixture.locals[index], outbox, ticket, fixture.headers,
			peer, fixture.private[peer])
		if err != nil || replayed {
			t.Fatalf("seal %s: replay=%v err=%v", role, replayed, err)
		}
		fixture.envelopes[index] = envelope
	}
	t.Cleanup(func() {
		for _, store := range fixture.locals {
			if store != nil {
				_ = store.Close()
			}
		}
		for _, store := range fixture.outboxes {
			if store != nil {
				store.Close()
			}
		}
		if fixture.finalizer != nil {
			_ = fixture.finalizer.Close()
		}
		if fixture.ingress != nil {
			fixture.ingress.Close()
		}
	})
	return fixture
}

func formalCoxBlockwiseDistributedTestCandidateBeta(
	t *testing.T, candidate formalCoxBlockwiseOpeningCandidate,
	index int, beta *big.Int,
) formalCoxBlockwiseOpeningCandidate {
	t.Helper()
	changed := candidate
	changed.Coefficients = append(
		[]formalCoxBlockwiseOpeningCoefficient(nil), candidate.Coefficients...)
	scale := new(big.Int).Lsh(big.NewInt(1), uint(candidate.FractionBits))
	digestScale := new(big.Int).Lsh(
		big.NewInt(1), uint(candidate.ExpCertificateBits))
	interval, err := formalCoxExpDyadic(
		beta, scale, candidate.ExpCertificateBits)
	if err != nil {
		t.Fatal(err)
	}
	midpointNumerator := new(big.Int).Add(interval.low, interval.high)
	midpointDenominator := new(big.Int).Lsh(new(big.Int).Set(digestScale), 1)
	changed.Coefficients[index] = formalCoxBlockwiseOpeningCoefficient{
		Index: index, BetaSteps: beta.String(),
		BetaRational: formalCoxBlockwiseOpeningRational(beta, scale),
		HazardRatioLowerRational: formalCoxBlockwiseOpeningRational(
			interval.low, digestScale),
		HazardRatioUpperRational: formalCoxBlockwiseOpeningRational(
			interval.high, digestScale),
		HazardRatioMidpointRational: formalCoxBlockwiseOpeningRational(
			midpointNumerator, midpointDenominator),
	}
	return changed
}

func formalCoxBlockwiseDistributedAssertEncryptedRecords(
	t *testing.T, root, secretBase64 string,
) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := bytes.ToLower(encoded)
		for _, forbidden := range [][]byte{
			[]byte(`"secret_key"`), []byte(`coefficient_shares`),
			[]byte(`validity_share`), []byte(secretBase64),
		} {
			if len(forbidden) != 0 && bytes.Contains(lower, bytes.ToLower(forbidden)) {
				return fmt.Errorf("plaintext private field in %s", path)
			}
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("non-owner durable record %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFormalCoxBlockwiseDistributedLifecycleK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseDistributedLifecycleFixture(
				t, custodians)
			for index, local := range fixture.locals {
				otherPeer := fixture.plan.Policy.ComputePeers[1-index]
				if _, err := local.loadPrivateHandoff(otherPeer); !os.IsNotExist(err) {
					t.Fatalf("peer-local store contained both handoffs: %v", err)
				}
			}
			if _, err := formalCoxBlockwiseDistributedCleanupAfterAck(
				fixture.ingress, formalFinalizerHandoffCommitProof{}); err == nil {
				t.Fatal("transport cleanup ran before durable ACK")
			}
			for index, peer := range fixture.plan.Policy.ComputePeers {
				reencrypted, replayed, err := formalCoxBlockwiseSealLocalOpening(
					fixture.locals[index], fixture.outboxes[index], fixture.ticket,
					fixture.headers, peer, fixture.private[peer])
				if err != nil || !replayed || !reflect.DeepEqual(
					reencrypted, fixture.envelopes[index]) {
					t.Fatalf("outbox replay changed ciphertext bytes: %v/%v", replayed, err)
				}
			}
			missing := fixture.envelopes
			missing[1] = formalFinalizerHandoffEnvelope{}
			if _, _, err := formalCoxBlockwiseOpeningDistributedPreflight(
				fixture.finalizer, fixture.ingress, fixture.ticket,
				fixture.headers, missing); err == nil {
				t.Fatal("preflight accepted a missing evaluator envelope")
			}
			reordered := [2]formalFinalizerHandoffEnvelope{
				fixture.envelopes[1], fixture.envelopes[0]}
			if _, _, err := formalCoxBlockwiseOpeningDistributedPreflight(
				fixture.finalizer, fixture.ingress, fixture.ticket,
				fixture.headers, reordered); err == nil {
				t.Fatal("preflight accepted reordered envelopes")
			}
			tampered := fixture.envelopes
			tampered[0].Ciphertext = append(
				[]byte(nil), fixture.envelopes[0].Ciphertext...)
			tampered[0].Ciphertext[0] ^= 1
			if _, _, err := formalCoxBlockwiseOpeningDistributedPreflight(
				fixture.finalizer, fixture.ingress, fixture.ticket,
				fixture.headers, tampered); err == nil {
				t.Fatal("preflight accepted tampered ciphertext")
			}
			if _, found, err := formalCoxBlockwiseOpeningDistributedPreflight(
				fixture.finalizer, fixture.ingress, fixture.ticket,
				fixture.headers, fixture.envelopes); err != nil || found {
				t.Fatalf("valid preflight: found=%v err=%v", found, err)
			}

			rotatedTransport, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			finalizerPeer := fixture.plan.Policy.ComputePeers[0]
			rotatedTicket, err := formalFinalizerHandoffIssueTicket(
				fixture.binding, rotatedTransport.PublicKey().Bytes(),
				fixture.private[finalizerPeer], fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := fixture.ingress.CommitTicket(rotatedTicket); err == nil {
				t.Fatal("split-brain finalizer key replaced the first ticket")
			}
			alternateBinding := fixture.binding
			alternateBinding.FinalPairRootSHA256 = formalFinalizerHandoffTestSHA(
				t.Name() + "/alternate-pair")
			alternateTicket, err := formalFinalizerHandoffIssueTicket(
				alternateBinding, rotatedTransport.PublicKey().Bytes(),
				fixture.private[finalizerPeer], fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := fixture.ingress.CommitTicket(alternateTicket); err == nil {
				t.Fatal("alternate pair root replaced the ArtifactID ticket")
			}
			splitBrain, err := newFormalFinalizerHandoffStoreForTest(
				fixture.ingressDir, alternateBinding,
				fixture.ingressStorage, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := splitBrain.CommitTicket(alternateTicket); err == nil {
				splitBrain.Close()
				t.Fatal("split-brain store replaced the first ArtifactID pair root")
			}
			splitBrain.Close()

			_, _, _, crashErr := formalCoxBlockwiseOpeningDistributedOpenAndPrepare(
				fixture.finalizer, fixture.ingress, fixture.ticket, fixture.headers,
				func(phase string) error {
					if phase == "after_import_garbler" {
						return fmt.Errorf("injected post-garbler crash")
					}
					return nil
				})
			if crashErr == nil {
				t.Fatal("injected import crash did not stop the finalizer")
			}
			if _, err := fixture.finalizer.loadPrivateHandoff(finalizerPeer); err != nil {
				t.Fatal("garbler import was not durable across crash")
			}
			if err := fixture.finalizer.Close(); err != nil {
				t.Fatal(err)
			}
			fixture.ingress.Close()
			fixture.finalizer, err = newFormalCoxBlockwiseOpeningStore(
				fixture.finalizerDir, fixture.finalizerKey,
				fixture.plan, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			fixture.ingress, err = newFormalFinalizerHandoffStoreForTest(
				fixture.ingressDir, fixture.binding,
				fixture.ingressStorage, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			type prepared struct {
				intent      formalCoxBlockwiseOpeningIntent
				publication formalCoxBlockwiseOpeningPublication
				found       bool
				err         error
			}
			preparedResults := make(chan prepared, 2)
			for count := 0; count < 2; count++ {
				go func() {
					value, publication, found, err :=
						formalCoxBlockwiseOpeningDistributedOpenAndPrepare(
							fixture.finalizer, fixture.ingress, fixture.ticket,
							fixture.headers, nil)
					preparedResults <- prepared{value, publication, found, err}
				}()
			}
			left, right := <-preparedResults, <-preparedResults
			if left.err != nil || right.err != nil || left.found || right.found ||
				len(left.publication.Certificate) != 0 ||
				len(right.publication.Certificate) != 0 ||
				!reflect.DeepEqual(left.intent, right.intent) {
				t.Fatalf("concurrent restart prepare: %#v / %#v", left, right)
			}
			intent := left.intent
			candidate, err := fixture.finalizer.loadCandidate()
			if err != nil {
				t.Fatal(err)
			}
			badCandidate := formalCoxBlockwiseDistributedTestCandidateBeta(
				t, candidate, 0, big.NewInt(63))
			badIntent, err := formalCoxBlockwiseOpeningIntentFor(badCandidate)
			if err != nil || fixture.finalizer.validateCandidate(badCandidate) != nil ||
				badIntent.CandidateSHA256 == intent.CandidateSHA256 {
				t.Fatalf("substitute candidate was not a valid distinct control: %v", err)
			}
			if _, _, err := formalCoxBlockwiseRemoteOpeningSignOnce(
				fixture.locals[0], fixture.outboxes[0], fixture.ticket,
				fixture.headers, badCandidate, "garbler",
				fixture.private[finalizerPeer], nil, nil); err == nil {
				t.Fatal("valid-ticket substitute CandidateSHA reached first SignOnce")
			}
			first, replayed, err := formalCoxBlockwiseRemoteOpeningSignOnce(
				fixture.locals[0], fixture.outboxes[0], fixture.ticket,
				fixture.headers, candidate, "garbler",
				fixture.private[finalizerPeer], nil, nil)
			if err != nil || replayed {
				t.Fatalf("garbler remote SignOnce: replay=%v err=%v", replayed, err)
			}
			firstReplay, replayed, err := formalCoxBlockwiseRemoteOpeningSignOnce(
				fixture.locals[0], fixture.outboxes[0], fixture.ticket,
				fixture.headers, candidate, "garbler",
				fixture.private[finalizerPeer], nil, nil)
			if err != nil || !replayed || !reflect.DeepEqual(firstReplay, first) {
				t.Fatalf("garbler SignOnce replay: replay=%v err=%v", replayed, err)
			}
			tamperedAuthorization := first
			tamperedAuthorization.TransportAuthorization.Signature = append(
				[]byte(nil), first.TransportAuthorization.Signature...)
			tamperedAuthorization.TransportAuthorization.Signature[0] ^= 1
			if _, _, err := formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
				fixture.finalizer, fixture.ingress, fixture.ticket, intent, "garbler",
				tamperedAuthorization, nil, nil); err == nil {
				t.Fatal("tampered remote authorization reached finalizer SignOnce")
			}
			firstReceipt, replayed, err :=
				formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
					fixture.finalizer, fixture.ingress, fixture.ticket, intent,
					"garbler", first, nil, nil)
			if err != nil || replayed {
				t.Fatalf("accept garbler: replay=%v err=%v", replayed, err)
			}
			evaluatorPeer := fixture.plan.Policy.ComputePeers[1]
			if _, _, err := formalCoxBlockwiseRemoteOpeningSignOnce(
				fixture.locals[1], fixture.outboxes[1], fixture.ticket,
				fixture.headers, candidate, "evaluator",
				fixture.private[evaluatorPeer], nil, nil); err == nil {
				t.Fatal("evaluator signed without ordered predecessor")
			}
			second, replayed, err := formalCoxBlockwiseRemoteOpeningSignOnce(
				fixture.locals[1], fixture.outboxes[1], fixture.ticket,
				fixture.headers, candidate, "evaluator",
				fixture.private[evaluatorPeer],
				[]formalFinalizerHandoffIntentAuthorization{
					first.TransportAuthorization},
				[]jointDPBiomedicalGaussianSignature{firstReceipt})
			if err != nil || replayed {
				t.Fatalf("evaluator remote SignOnce: replay=%v err=%v", replayed, err)
			}
			if _, _, err := formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
				fixture.finalizer, fixture.ingress, fixture.ticket, intent,
				"evaluator", second, nil, nil); err == nil {
				t.Fatal("finalizer accepted evaluator without predecessors")
			}
			secondReceipt, replayed, err :=
				formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
					fixture.finalizer, fixture.ingress, fixture.ticket, intent,
					"evaluator", second,
					[]formalFinalizerHandoffIntentAuthorization{
						first.TransportAuthorization},
					[]jointDPBiomedicalGaussianSignature{firstReceipt})
			if err != nil || replayed ||
				!reflect.DeepEqual(secondReceipt, second.OpeningReceipt) {
				t.Fatalf("accept evaluator: replay=%v err=%v", replayed, err)
			}
			authorizations := [2]formalCoxBlockwiseRemoteOpeningAuthorization{
				first, second}
			if _, _, _, err := formalCoxBlockwiseDistributedPublishAndAck(
				fixture.finalizer, fixture.ingress, fixture.ticket, intent,
				authorizations, fixture.private[finalizerPeer],
				func(phase string) error {
					if phase == "before_publication_cas" {
						return fmt.Errorf("injected publication crash")
					}
					return nil
				}); err == nil {
				t.Fatal("injected publication crash was ignored")
			}
			if _, found, err := fixture.ingress.PreflightAck(); err != nil || found {
				t.Fatalf("ACK preceded public commit: found=%v err=%v", found, err)
			}
			if _, err := formalCoxBlockwiseDistributedCleanupAfterAck(
				fixture.ingress, formalFinalizerHandoffCommitProof{}); err == nil {
				t.Fatal("cleanup ran after failed publication but before ACK")
			}
			publication, proof, ackReplay, err :=
				formalCoxBlockwiseDistributedPublishAndAck(
					fixture.finalizer, fixture.ingress, fixture.ticket, intent,
					authorizations, fixture.private[finalizerPeer], nil)
			if err != nil || ackReplay || publication.Replayed {
				t.Fatalf("publish+ACK: replay=%v/%v err=%v",
					publication.Replayed, ackReplay, err)
			}
			certificate, err := formalCoxBlockwiseDecodeOpeningPublication(
				publication, fixture.pins)
			if err != nil || certificate.Candidate.ProductionReady ||
				certificate.Candidate.Coefficients[0].BetaSteps != "64" ||
				certificate.Candidate.Coefficients[1].BetaSteps != "-32" {
				t.Fatalf("invalid distributed public Cox beta: %#v / %v",
					certificate.Candidate.Coefficients, err)
			}
			formalCoxBlockwiseDistributedAssertEncryptedRecords(
				t, fixture.ingressDir, fixture.transportSecret64)
			for _, outbox := range fixture.outboxes {
				formalCoxBlockwiseDistributedAssertEncryptedRecords(
					t, outbox.dir, "")
			}
			ticketSHA, err := formalFinalizerHandoffTicketSHA256(fixture.ticket)
			if err != nil {
				t.Fatal(err)
			}
			wrongCertificateProof, err := formalFinalizerHandoffBuildCommitProof(
				fixture.binding, ticketSHA,
				formalFinalizerHandoffTestSHA(t.Name()+"/wrong-certificate"),
				fixture.private[finalizerPeer], fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			tamperedProof := proof
			tamperedProof.Signature = append([]byte(nil), proof.Signature...)
			tamperedProof.Signature[0] ^= 1
			var terminal *formalFinalizerHandoffTerminalAckError
			for index, outbox := range fixture.outboxes {
				if _, _, err := outbox.AckAfterCommit(
					wrongCertificateProof, fixture.finalizer); err == nil {
					t.Fatal("outbox ACK accepted an absent public certificate")
				}
				if _, _, err := outbox.AckAfterCommit(
					tamperedProof, fixture.finalizer); err == nil {
					t.Fatal("outbox ACK accepted a tampered proof")
				}
				storedProof, ackReplayed, err := outbox.AckAfterCommit(
					proof, fixture.finalizer)
				if err != nil || ackReplayed || !reflect.DeepEqual(storedProof, proof) {
					t.Fatalf("authority outbox ACK: replay=%v err=%v", ackReplayed, err)
				}
				removed, err := formalCoxBlockwiseDistributedCleanupAfterAck(
					outbox, proof)
				if err != nil || removed != 1 {
					t.Fatalf("authority outbox cleanup: removed=%d err=%v", removed, err)
				}
				if _, replayed, err := outbox.CommitOutbox(
					fixture.envelopes[index]); !replayed || !errors.As(err, &terminal) {
					t.Fatal("late CommitOutbox recreated terminal ciphertext")
				}
				peer := fixture.plan.Policy.ComputePeers[index]
				if _, replayed, err := formalCoxBlockwiseSealLocalOpening(
					fixture.locals[index], outbox, fixture.ticket, fixture.headers,
					peer, fixture.private[peer]); !replayed ||
					!errors.As(err, &terminal) {
					t.Fatal("late SealLocal recreated terminal ciphertext")
				}
				lateOutboxTicket, secret, replayed, err := outbox.IssueTicketOnce(
					fixture.private[finalizerPeer])
				clear(secret)
				if !replayed || !errors.As(err, &terminal) ||
					!reflect.DeepEqual(lateOutboxTicket, fixture.ticket) {
					t.Fatal("late outbox IssueTicket recreated a transport key")
				}
				role := []string{"garbler", "evaluator"}[index]
				if _, err := outbox.loadEnvelope("outbox-v1", role); !os.IsNotExist(err) {
					t.Fatalf("cleaned outbox ciphertext reappeared: %v", err)
				}
			}
			removed, err := formalCoxBlockwiseDistributedCleanupAfterAck(
				fixture.ingress, proof)
			if err != nil || removed != 3 {
				t.Fatalf("post-ACK cleanup: removed=%d err=%v", removed, err)
			}
			lateTicket, lateSecret, replayed, err := fixture.ingress.IssueTicketOnce(
				fixture.private[finalizerPeer])
			clear(lateSecret)
			if !replayed || !errors.As(err, &terminal) ||
				!reflect.DeepEqual(lateTicket, fixture.ticket) {
				t.Fatalf("post-cleanup ticket was not terminal replay: %v/%v", replayed, err)
			}
			if _, _, err := fixture.ingress.CommitIngress(
				fixture.envelopes[0]); !errors.As(err, &terminal) {
				t.Fatal("late envelope recreated terminal transport state")
			}
			terminalPublication, terminalProof, replayed, err :=
				formalCoxBlockwiseDistributedPublishAndAck(
					fixture.finalizer, fixture.ingress,
					formalFinalizerHandoffTicket{}, formalCoxBlockwiseOpeningIntent{},
					[2]formalCoxBlockwiseRemoteOpeningAuthorization{}, nil, nil)
			if err != nil || !replayed ||
				!bytes.Equal(terminalPublication.Certificate, publication.Certificate) ||
				!reflect.DeepEqual(terminalProof, proof) {
				t.Fatalf("terminal publication replay changed bytes: %v/%v", replayed, err)
			}

			alternatePlan := fixture.plan
			alternatePlan.RunID = formalFinalizerHandoffTestSHA(
				t.Name() + "/new-run")
			alternateCheckpoints, _ := formalCoxBlockwiseOpeningTestCompletedStores(
				t, alternatePlan, fixture.private,
				[]*big.Int{big.NewInt(12), big.NewInt(9)}, true)
			var alternateHeaders [2]formalCoxBlockwiseOpeningHandoffHeader
			for index, peer := range alternatePlan.Policy.ComputePeers {
				key := sha256.Sum256([]byte(
					t.Name() + "/alternate-local/" + peer))
				store, err := newFormalCoxBlockwiseOpeningStore(
					filepath.Join(t.TempDir(), "alternate-local"), key,
					alternatePlan, fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				header, _, err := store.SubmitLocal(
					alternateCheckpoints[peer], fixture.private[peer])
				if err != nil {
					t.Fatal(err)
				}
				alternateHeaders[index] = header
			}
			alternateFinalizer, err := newFormalCoxBlockwiseOpeningStore(
				fixture.finalizerDir, fixture.finalizerKey,
				alternatePlan, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			defer alternateFinalizer.Close()
			alternatePair, err := alternateFinalizer.pairRoot(
				alternateHeaders[0], alternateHeaders[1])
			if err != nil || alternatePair == fixture.binding.FinalPairRootSHA256 ||
				alternateFinalizer.artifactID != fixture.binding.ArtifactID {
				t.Fatalf("alternate run did not exercise same artifact/new pair: %v", err)
			}
			replayedPublication, found, err :=
				formalCoxBlockwiseOpeningDistributedPreflight(
					alternateFinalizer, fixture.ingress,
					formalFinalizerHandoffTicket{}, alternateHeaders,
					[2]formalFinalizerHandoffEnvelope{})
			if err != nil || !found || !bytes.Equal(
				replayedPublication.Certificate, publication.Certificate) {
				t.Fatalf("new RunID/pair did not preflight ArtifactID replay: %v/%v",
					found, err)
			}
			opened := 0
			_, replayedPublication, found, err =
				formalCoxBlockwiseOpeningDistributedOpenAndPrepare(
					alternateFinalizer, fixture.ingress,
					formalFinalizerHandoffTicket{}, alternateHeaders,
					func(string) error { opened++; return nil })
			if err != nil || !found || opened != 0 || !bytes.Equal(
				replayedPublication.Certificate, publication.Certificate) {
				t.Fatalf("ArtifactID replay touched new run transport: %v/%d/%v",
					found, opened, err)
			}
		})
	}
}
