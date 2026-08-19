package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestFormalCoxBlockwiseControlContractK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalCoxBlockwiseStickyGuardTestContract(
				t, custodians, "control-contract")
			context, err := formalCoxControlContextFor(
				fixture.plan, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if context.ArtifactID != fixture.contract.ArtifactID ||
				context.RunID != fixture.plan.RunID ||
				!formalCoxIsSHA256(context.PlanSHA256) ||
				!formalCoxIsSHA256(context.ExecutionSHA256) {
				t.Fatalf("invalid control execution context: %#v", context)
			}

			want := map[string]map[string]string{
				formalCoxControlRecordPreflight: {
					"garbler": "evaluator", "evaluator": "garbler"},
				formalCoxControlRecordHeader: {
					"garbler": "evaluator", "evaluator": "garbler"},
				formalCoxControlRecordTicket:    {"garbler": "evaluator"},
				formalCoxControlRecordEnvelope:  {"evaluator": "garbler"},
				formalCoxControlRecordCandidate: {"garbler": "evaluator"},
				formalCoxControlRecordAuthorization: {
					"garbler": "evaluator", "evaluator": "garbler"},
				formalCoxControlRecordPublication: {"garbler": "evaluator"},
				formalCoxControlRecordCommit:      {"evaluator": "garbler"},
				formalCoxControlRecordAck:         {"garbler": "evaluator"},
			}
			for recordType, directions := range want {
				for sender, recipient := range directions {
					got, err := formalCoxControlDirection(recordType, sender)
					if err != nil || got != recipient {
						t.Fatalf("direction %s/%s: %q/%v",
							recordType, sender, got, err)
					}
				}
			}
			for _, invalid := range [][2]string{
				{formalCoxControlRecordTicket, "evaluator"},
				{formalCoxControlRecordEnvelope, "garbler"},
				{formalCoxControlRecordCommit, "garbler"},
				{"cleanup", "garbler"},
			} {
				if _, err := formalCoxControlDirection(
					invalid[0], invalid[1]); err == nil {
					t.Fatalf("accepted invalid direction %#v", invalid)
				}
			}
		})
	}
}

type formalCoxControlTestRecords struct {
	fixture     *formalCoxBlockwiseDistributedLifecycleFixture
	context     formalCoxBlockwiseControlContext
	records     map[string][]byte
	related     formalCoxBlockwiseControlRelated
	candidate   formalCoxBlockwiseRockCandidateRecord
	garblerAuth formalCoxBlockwiseRockAuthorizationRecord
	publication formalCoxBlockwiseRockPublicationRecord
}

func formalCoxControlTestRecordKey(recordType, role string) string {
	return recordType + "/" + role
}

func formalCoxControlTestMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func newFormalCoxControlTestRecords(t *testing.T,
	custodians int,
) *formalCoxControlTestRecords {
	t.Helper()
	fixture := newFormalCoxBlockwiseDistributedLifecycleFixture(t, custodians)
	context, err := formalCoxControlContextFor(fixture.plan, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	records := make(map[string][]byte)
	for _, role := range []string{"garbler", "evaluator"} {
		authority, _ := formalCoxControlAuthority(context, role)
		records[formalCoxControlTestRecordKey(
			formalCoxControlRecordPreflight, role)] =
			formalCoxControlTestPreflight(
				t, context, role, fixture.private[authority.PeerName])
		position := 0
		if role == "evaluator" {
			position = 1
		}
		records[formalCoxControlTestRecordKey(
			formalCoxControlRecordHeader, role)] = formalCoxControlTestMarshal(
			t, formalCoxBlockwiseRockHeaderRecord{
				Version:    formalCoxBlockwiseRockRecordVersion,
				Family:     formalFinalizerHandoffFamilyCox,
				Purpose:    formalCoxBlockwiseRockPurpose,
				ArtifactID: context.ArtifactID,
				Header:     fixture.headers[position], ProductionReady: false,
			})
	}
	records[formalCoxControlTestRecordKey(
		formalCoxControlRecordTicket, "garbler")] = formalCoxControlTestMarshal(
		t, formalCoxBlockwiseRockTicketRecord{
			Version:    formalCoxBlockwiseRockRecordVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Purpose:    formalCoxBlockwiseRockPurpose,
			ArtifactID: context.ArtifactID, Ticket: fixture.ticket,
			ProductionReady: false,
		})
	records[formalCoxControlTestRecordKey(
		formalCoxControlRecordEnvelope, "evaluator")] = formalCoxControlTestMarshal(
		t, formalCoxBlockwiseRockEnvelopeRecord{
			Version:    formalCoxBlockwiseRockRecordVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Purpose:    formalCoxBlockwiseRockPurpose,
			ArtifactID: context.ArtifactID, Role: "evaluator",
			Envelope: fixture.envelopes[1], ProductionReady: false,
		})
	if _, found, err := formalCoxBlockwiseOpeningDistributedPreflight(
		fixture.finalizer, fixture.ingress, fixture.ticket,
		fixture.headers, fixture.envelopes); err != nil || found {
		t.Fatalf("control fixture preflight: found=%v err=%v", found, err)
	}
	intent, _, found, err := formalCoxBlockwiseOpeningDistributedOpenAndPrepare(
		fixture.finalizer, fixture.ingress, fixture.ticket,
		fixture.headers, nil)
	if err != nil || found {
		t.Fatalf("control fixture prepare: found=%v err=%v", found, err)
	}
	candidate, err := fixture.finalizer.loadCandidate()
	if err != nil {
		t.Fatal(err)
	}
	candidateRecord := formalCoxBlockwiseRockCandidateRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.ArtifactID, Candidate: candidate,
		Intent: intent, ProductionReady: false,
	}
	records[formalCoxControlTestRecordKey(
		formalCoxControlRecordCandidate, "garbler")] =
		formalCoxControlTestMarshal(t, candidateRecord)
	badCandidate := formalCoxBlockwiseDistributedTestCandidateBeta(
		t, candidate, 0, big.NewInt(63))
	garblerPeer := context.Authorities[0].PeerName
	if _, _, err := formalCoxBlockwiseRemoteOpeningSignOnce(
		fixture.locals[0], fixture.outboxes[0], fixture.ticket,
		fixture.headers, badCandidate, "garbler", fixture.private[garblerPeer],
		nil, nil); err == nil {
		t.Fatal("control fixture let a substitute candidate reach SignOnce")
	}
	first, _, err := formalCoxBlockwiseRemoteOpeningSignOnce(
		fixture.locals[0], fixture.outboxes[0], fixture.ticket,
		fixture.headers, candidate, "garbler", fixture.private[garblerPeer],
		nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstReceipt, _, err := formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
		fixture.finalizer, fixture.ingress, fixture.ticket, intent, "garbler",
		first, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorPeer := context.Authorities[1].PeerName
	second, _, err := formalCoxBlockwiseRemoteOpeningSignOnce(
		fixture.locals[1], fixture.outboxes[1], fixture.ticket,
		fixture.headers, candidate, "evaluator", fixture.private[evaluatorPeer],
		[]formalFinalizerHandoffIntentAuthorization{
			first.TransportAuthorization},
		[]jointDPBiomedicalGaussianSignature{firstReceipt})
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, _, err := formalCoxBlockwiseAcceptRemoteOpeningSignOnce(
		fixture.finalizer, fixture.ingress, fixture.ticket, intent, "evaluator",
		second, []formalFinalizerHandoffIntentAuthorization{
			first.TransportAuthorization},
		[]jointDPBiomedicalGaussianSignature{firstReceipt})
	if err != nil {
		t.Fatal(err)
	}
	garblerAuth := formalCoxBlockwiseRockAuthorizationRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.ArtifactID, Role: "garbler",
		Authorization: first, ProductionReady: false,
	}
	evaluatorAuth := formalCoxBlockwiseRockAuthorizationRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.ArtifactID, Role: "evaluator",
		Authorization: second, ProductionReady: false,
	}
	records[formalCoxControlTestRecordKey(
		formalCoxControlRecordAuthorization, "garbler")] =
		formalCoxControlTestMarshal(t, garblerAuth)
	records[formalCoxControlTestRecordKey(
		formalCoxControlRecordAuthorization, "evaluator")] =
		formalCoxControlTestMarshal(t, evaluatorAuth)
	publication, err := fixture.finalizer.Publish(
		intent, []jointDPBiomedicalGaussianSignature{firstReceipt, secondReceipt}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rockPublication := formalCoxBlockwiseRockPublicationFromOpening(publication)
	publicationRecord := formalCoxBlockwiseRockPublicationRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.ArtifactID, Publication: rockPublication,
		ProductionReady: false,
	}
	records[formalCoxControlTestRecordKey(
		formalCoxControlRecordPublication, "garbler")] =
		formalCoxControlTestMarshal(t, publicationRecord)
	commitReceipt := formalCoxBlockwiseRockCommitReceipt{
		Version:           formalCoxBlockwiseRockRecordVersion,
		Purpose:           formalCoxBlockwiseRockCommitPurpose,
		ArtifactID:        context.ArtifactID,
		CertificateSHA256: rockPublication.CertificateSHA256,
		PeerName:          context.Authorities[1].PeerName,
		PeerID:            context.Authorities[1].PeerID, Role: "evaluator",
		ProductionReady: false,
	}
	commitMessage, err := formalCoxBlockwiseRockCommitMessage(commitReceipt)
	if err != nil {
		t.Fatal(err)
	}
	commitReceipt.Signature = ed25519.Sign(
		fixture.private[evaluatorPeer], commitMessage)
	records[formalCoxControlTestRecordKey(
		formalCoxControlRecordCommit, "evaluator")] = formalCoxControlTestMarshal(
		t, formalCoxBlockwiseRockCommitRecord{
			Version: formalCoxBlockwiseRockRecordVersion,
			Family:  formalFinalizerHandoffFamilyCox,
			Purpose: formalCoxBlockwiseRockCommitPurpose,
			Receipt: commitReceipt, ProductionReady: false,
		})
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(fixture.ticket)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := formalFinalizerHandoffBuildCommitProof(
		fixture.binding, ticketSHA, rockPublication.CertificateSHA256,
		fixture.private[garblerPeer], fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	records[formalCoxControlTestRecordKey(
		formalCoxControlRecordAck, "garbler")] = formalCoxControlTestMarshal(
		t, formalCoxBlockwiseRockAckRecord{
			Version:    formalCoxBlockwiseRockRecordVersion,
			Family:     formalFinalizerHandoffFamilyCox,
			Purpose:    formalCoxBlockwiseRockPurpose,
			ArtifactID: context.ArtifactID, Proof: proof,
			ProductionReady: false,
		})
	related := formalCoxBlockwiseControlRelated{
		Candidate: &candidateRecord, GarblerAuthorization: &garblerAuth,
		Publication: &publicationRecord,
	}
	return &formalCoxControlTestRecords{
		fixture: fixture, context: context, records: records, related: related,
		candidate: candidateRecord, garblerAuth: garblerAuth,
		publication: publicationRecord,
	}
}

func TestFormalCoxBlockwiseControlAllSchemasK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			values := newFormalCoxControlTestRecords(t, custodians)
			keys := make(map[string]*ecdh.PrivateKey, 2)
			signatures := make(map[string][]byte, 2)
			for _, authority := range values.context.Authorities {
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				keys[authority.Role] = key
				signatures[authority.Role] = ed25519.Sign(
					values.fixture.private[authority.PeerName],
					key.PublicKey().Bytes())
			}
			for key, record := range values.records {
				recordType, senderRole, found := strings.Cut(key, "/")
				if !found {
					t.Fatalf("invalid test record key %q", key)
				}
				recipientRole, err := formalCoxControlDirection(
					recordType, senderRole)
				if err != nil {
					t.Fatal(err)
				}
				binding := values.fixture.binding
				ticket := values.fixture.ticket
				if recordType == formalCoxControlRecordPreflight ||
					recordType == formalCoxControlRecordHeader {
					binding, ticket = formalFinalizerHandoffBinding{},
						formalFinalizerHandoffTicket{}
				}
				envelope, err := formalCoxBlockwiseControlSeal(
					values.context, binding, recordType, senderRole, record,
					ticket, keys[recipientRole].PublicKey().Bytes(),
					signatures[recipientRole], values.related)
				if err != nil {
					t.Fatalf("seal %s: %v", key, err)
				}
				openTicket := ticket
				if recordType == formalCoxControlRecordTicket {
					openTicket = formalFinalizerHandoffTicket{}
				}
				opened, err := formalCoxBlockwiseControlOpen(
					values.context, binding, envelope, openTicket,
					keys[recipientRole].Bytes(), values.related)
				if err != nil || !bytes.Equal(opened, record) {
					t.Fatalf("open %s: %v", key, err)
				}
				encodedEnvelope := formalCoxControlTestMarshal(t, envelope)
				if bytes.Contains(encodedEnvelope, record) ||
					bytes.Contains(encodedEnvelope, []byte(`"coefficients"`)) ||
					bytes.Contains(encodedEnvelope, []byte(`"certificate"`)) {
					t.Fatalf("outer envelope leaked typed record %s", key)
				}
			}
		})
	}
}

func formalCoxControlTestPreflight(t *testing.T,
	context formalCoxBlockwiseControlContext, senderRole string,
	private ed25519.PrivateKey,
) []byte {
	t.Helper()
	sender, err := formalCoxControlAuthority(context, senderRole)
	if err != nil {
		t.Fatal(err)
	}
	receipt := formalCoxBlockwiseRockPreflightReceipt{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Purpose:    formalCoxBlockwiseRockPreflightPurpose,
		ArtifactID: context.ArtifactID, PinsetSHA256: context.PinsetSHA256,
		PeerName: sender.PeerName, PeerID: sender.PeerID, Role: sender.Role,
		State: formalCoxBlockwiseRockStateAbsent, ProductionReady: false,
	}
	message, err := formalCoxBlockwiseRockPreflightMessage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = ed25519.Sign(private, message)
	encoded, err := json.Marshal(formalCoxBlockwiseRockPreflightRecord{
		Version: formalCoxBlockwiseRockRecordVersion,
		Family:  formalFinalizerHandoffFamilyCox,
		Purpose: formalCoxBlockwiseRockPreflightPurpose,
		Receipt: receipt, ProductionReady: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalCoxBlockwiseControlSealOpenPreAndPostTicket(t *testing.T) {
	fixture := newFormalCoxBlockwiseDistributedLifecycleFixture(t, 2)
	context, err := formalCoxControlContextFor(fixture.plan, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := context.Authorities[1]
	transportSignature := ed25519.Sign(
		fixture.private[evaluator.PeerName], transport.PublicKey().Bytes())
	preflight := formalCoxControlTestPreflight(
		t, context, "garbler", fixture.private[context.Authorities[0].PeerName])
	envelope, err := formalCoxBlockwiseControlSeal(
		context, formalFinalizerHandoffBinding{},
		formalCoxControlRecordPreflight, "garbler", preflight,
		formalFinalizerHandoffTicket{}, transport.PublicKey().Bytes(),
		transportSignature, formalCoxBlockwiseControlRelated{})
	if err != nil {
		t.Fatalf("seal preflight: %v", err)
	}
	opened, err := formalCoxBlockwiseControlOpen(
		context, formalFinalizerHandoffBinding{}, envelope,
		formalFinalizerHandoffTicket{}, transport.Bytes(),
		formalCoxBlockwiseControlRelated{})
	if err != nil || !reflect.DeepEqual(opened, preflight) {
		t.Fatalf("open preflight: %v", err)
	}

	for name, mutate := range map[string]func(*formalCoxBlockwiseControlEnvelope){
		"run": func(value *formalCoxBlockwiseControlEnvelope) {
			value.AAD.RunID = formalFinalizerHandoffTestSHA("other-run")
		},
		"record digest": func(value *formalCoxBlockwiseControlEnvelope) {
			value.AAD.RecordSHA256 = formalFinalizerHandoffTestSHA("other-record")
		},
		"ciphertext": func(value *formalCoxBlockwiseControlEnvelope) {
			value.Ciphertext = append([]byte(nil), value.Ciphertext...)
			value.Ciphertext[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := envelope
			mutate(&changed)
			if _, err := formalCoxBlockwiseControlOpen(
				context, formalFinalizerHandoffBinding{}, changed,
				formalFinalizerHandoffTicket{}, transport.Bytes(),
				formalCoxBlockwiseControlRelated{}); err == nil {
				t.Fatal("tampered pre-ticket envelope was accepted")
			}
		})
	}

	ticketRecord, err := json.Marshal(formalCoxBlockwiseRockTicketRecord{
		Version:    formalCoxBlockwiseRockRecordVersion,
		Family:     formalFinalizerHandoffFamilyCox,
		Purpose:    formalCoxBlockwiseRockPurpose,
		ArtifactID: context.ArtifactID, Ticket: fixture.ticket,
		ProductionReady: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ticketEnvelope, err := formalCoxBlockwiseControlSeal(
		context, fixture.binding, formalCoxControlRecordTicket, "garbler",
		ticketRecord, fixture.ticket, transport.PublicKey().Bytes(),
		transportSignature, formalCoxBlockwiseControlRelated{})
	if err != nil {
		t.Fatalf("seal ticket: %v", err)
	}
	opened, err = formalCoxBlockwiseControlOpen(
		context, fixture.binding, ticketEnvelope,
		formalFinalizerHandoffTicket{}, transport.Bytes(),
		formalCoxBlockwiseControlRelated{})
	if err != nil || !reflect.DeepEqual(opened, ticketRecord) {
		t.Fatalf("open ticket: %v", err)
	}
	wrongBinding := fixture.binding
	wrongBinding.FinalPairRootSHA256 = formalFinalizerHandoffTestSHA("wrong-pair")
	if _, err := formalCoxBlockwiseControlOpen(
		context, wrongBinding, ticketEnvelope,
		formalFinalizerHandoffTicket{}, transport.Bytes(),
		formalCoxBlockwiseControlRelated{}); err == nil {
		t.Fatal("ticket crossed its exact pair root")
	}
}

func TestFormalCoxBlockwiseControlPreTicketAADRunBinding(t *testing.T) {
	fixture := formalCoxBlockwiseStickyGuardTestContract(
		t, 2, "control-pre-ticket")
	context, err := formalCoxControlContextFor(fixture.plan, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	sender, recipient := context.Authorities[0], context.Authorities[1]
	aad := formalCoxBlockwiseControlAAD{
		Family:     formalFinalizerHandoffFamilyCox,
		ArtifactID: context.ArtifactID, PlanSHA256: context.PlanSHA256,
		RunID: context.RunID, ExecutionSHA256: context.ExecutionSHA256,
		PinsetSHA256:   context.PinsetSHA256,
		SenderPeerName: sender.PeerName, SenderPeerID: sender.PeerID,
		SenderRole: sender.Role, RecipientPeerName: recipient.PeerName,
		RecipientPeerID: recipient.PeerID, RecipientRole: recipient.Role,
		RecordType: formalCoxControlRecordHeader,
		RecordSHA256: formalCoxControlSHA(
			formalCoxControlRecordDomain, []byte("signed-header")),
	}
	if err := formalCoxControlValidateAAD(context, aad); err != nil {
		t.Fatalf("valid pre-ticket AAD: %v", err)
	}
	for name, mutate := range map[string]func(*formalCoxBlockwiseControlAAD){
		"pair root": func(value *formalCoxBlockwiseControlAAD) {
			value.FinalPairRootSHA256 = context.ArtifactID
		},
		"ticket": func(value *formalCoxBlockwiseControlAAD) {
			value.TicketSHA256 = context.ArtifactID
		},
		"run": func(value *formalCoxBlockwiseControlAAD) {
			value.RunID = context.ArtifactID
		},
		"execution": func(value *formalCoxBlockwiseControlAAD) {
			value.ExecutionSHA256 = context.ArtifactID
		},
		"record digest": func(value *formalCoxBlockwiseControlAAD) {
			value.RecordSHA256 = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := aad
			mutate(&changed)
			if err := formalCoxControlValidateAAD(context, changed); err == nil {
				t.Fatal("mutated pre-ticket AAD was accepted")
			}
		})
	}

	alternate := fixture.plan
	alternate.RunID = formalFinalizerHandoffTestSHA("control-new-run")
	alternateContext, err := formalCoxControlContextFor(alternate, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	if alternateContext.ArtifactID != context.ArtifactID ||
		alternateContext.RunID == context.RunID ||
		alternateContext.ExecutionSHA256 == context.ExecutionSHA256 ||
		formalCoxControlValidateAAD(alternateContext, aad) == nil {
		t.Fatal("same ArtifactID/new RunID was not isolated from the prior execution")
	}
}
