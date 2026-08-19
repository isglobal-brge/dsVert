package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
)

func formalGLMControlTestTransport(t *testing.T,
	identity ed25519.PrivateKey,
) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(identity, key.PublicKey().Bytes())
	return key, signature
}

func formalGLMControlTestRecord(t *testing.T,
	recordType, senderRole string,
	fixture formalFinalizerHandoffTestFixture,
	ticket formalFinalizerHandoffTicket,
) []byte {
	t.Helper()
	binding := fixture.binding
	sender, err := formalFinalizerHandoffPeer(binding, senderRole)
	if err != nil {
		t.Fatal(err)
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		t.Fatal(err)
	}
	sha := formalFinalizerHandoffTestSHA(t.Name() + "/" + recordType)
	var value any
	switch recordType {
	case formalGLMControlRecordStage:
		receipt := formalGLMPhase21RockStageReceipt{
			Version:    formalGLMPhase21RockRecordVersion,
			Purpose:    formalGLMPhase21RockStagePurpose,
			ArtifactID: binding.ArtifactID,
			PeerName:   sender.PeerName, PeerID: sender.PeerID,
			Role:                sender.Role,
			FinalPairRootSHA256: binding.FinalPairRootSHA256,
			PlanSHA256:          binding.PlanSHA256,
			ContractSHA256:      sha, SourceReceiptSHA256: sha,
		}
		message, messageErr := formalGLMPhase21RockStageMessage(receipt)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		receipt.Signature = ed25519.Sign(
			fixture.private[sender.PeerName], message)
		value = formalGLMPhase21RockStageRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockStagePurpose,
			ArtifactID: binding.ArtifactID, Binding: binding, Receipt: receipt,
		}
	case formalGLMControlRecordTicket:
		value = formalGLMPhase21RockTicketRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockTicketPurpose,
			ArtifactID: binding.ArtifactID, Binding: binding, Ticket: ticket,
		}
	case formalGLMControlRecordSealReceipt:
		receipt := formalGLMPhase21RockSealReceipt{
			Version:             formalGLMPhase21RockRecordVersion,
			Purpose:             formalGLMPhase21RockSealPurpose,
			ArtifactID:          binding.ArtifactID,
			FinalPairRootSHA256: binding.FinalPairRootSHA256,
			PlanSHA256:          binding.PlanSHA256,
			PinsetSHA256:        binding.PinsetSHA256, TicketSHA256: ticketSHA,
			PeerName: sender.PeerName, PeerID: sender.PeerID, Role: sender.Role,
			PayloadKind:   formalFinalizerHandoffGLMOneDrawKind,
			PayloadSHA256: sha, CiphertextSHA256: sha, EnvelopeSHA256: sha,
		}
		message, messageErr := formalGLMPhase21RockSealMessage(receipt)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		receipt.Signature = ed25519.Sign(
			fixture.private[sender.PeerName], message)
		value = formalGLMPhase21RockSealRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockSealPurpose,
			ArtifactID: binding.ArtifactID, Receipt: receipt,
		}
	case formalGLMControlRecordCandidate:
		receipt := formalGLMPhase21RockCandidateReceipt{
			Version:             formalGLMPhase21RockRecordVersion,
			Purpose:             formalGLMPhase21RockCandidatePurpose,
			ArtifactID:          binding.ArtifactID,
			FinalPairRootSHA256: binding.FinalPairRootSHA256,
			PlanSHA256:          binding.PlanSHA256,
			PinsetSHA256:        binding.PinsetSHA256, TicketSHA256: ticketSHA,
			CandidateSHA256:   sha,
			FinalizerPeerName: sender.PeerName,
			FinalizerPeerID:   sender.PeerID, FinalizerRole: sender.Role,
		}
		message, messageErr := formalGLMPhase21RockCandidateMessage(receipt)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		receipt.Signature = ed25519.Sign(
			fixture.private[sender.PeerName], message)
		value = formalGLMPhase21RockCandidateRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockCandidatePurpose,
			ArtifactID: binding.ArtifactID, Receipt: receipt,
		}
	case formalGLMControlRecordLocalRelease:
		local := formalGLMPhase21RockLocalReleaseBinding{
			Version:             formalGLMPhase21RockRecordVersion,
			Purpose:             formalGLMPhase21RockLocalReleasePurpose,
			ArtifactID:          binding.ArtifactID,
			FinalPairRootSHA256: binding.FinalPairRootSHA256,
			PlanSHA256:          binding.PlanSHA256,
			PinsetSHA256:        binding.PinsetSHA256, TicketSHA256: ticketSHA,
			CandidateSHA256: sha, LocalReleaseSHA256: sha,
			PeerName: sender.PeerName, PeerID: sender.PeerID, Role: sender.Role,
		}
		message, messageErr := formalGLMPhase21RockLocalReleaseMessage(local)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		local.Signature = ed25519.Sign(
			fixture.private[sender.PeerName], message)
		value = formalGLMPhase21RockLocalReleaseRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockLocalReleasePurpose,
			ArtifactID: binding.ArtifactID, Binding: local,
		}
	case formalGLMControlRecordBaseCertificate:
		receipt := formalGLMPhase21RockBaseCertificateReceipt{
			Version:             formalGLMPhase21RockRecordVersion,
			Purpose:             formalGLMPhase21RockBaseCertificatePurpose,
			ArtifactID:          binding.ArtifactID,
			FinalPairRootSHA256: binding.FinalPairRootSHA256,
			PlanSHA256:          binding.PlanSHA256,
			PinsetSHA256:        binding.PinsetSHA256, TicketSHA256: ticketSHA,
			CandidateSHA256: sha, CertifiedReleaseSHA256: sha,
			BaseCertificateSHA256: sha,
			FinalizerPeerName:     sender.PeerName,
			FinalizerPeerID:       sender.PeerID, FinalizerRole: sender.Role,
		}
		message, messageErr := formalGLMPhase21RockBaseCertificateMessage(receipt)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		receipt.Signature = ed25519.Sign(
			fixture.private[sender.PeerName], message)
		value = formalGLMPhase21RockBaseCertificateRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockBaseCertificatePurpose,
			ArtifactID: binding.ArtifactID, Receipt: receipt,
		}
	case formalGLMControlRecordAuthorization:
		authorization := formalFinalizerHandoffIntentAuthorization{
			Version: formalFinalizerHandoffIntentVersion,
			Family:  binding.Family, Purpose: binding.Purpose,
			ArtifactID:          binding.ArtifactID,
			FinalPairRootSHA256: binding.FinalPairRootSHA256,
			PlanSHA256:          binding.PlanSHA256,
			PinsetSHA256:        binding.PinsetSHA256, TicketSHA256: ticketSHA,
			SignerPeerName: sender.PeerName, SignerPeerID: sender.PeerID,
			SignerRole: sender.Role, IntentSHA256: sha, LocalGuardSHA256: sha,
		}
		if sender.Role == "evaluator" {
			authorization.PredecessorReceiptSHA256 = sha
		}
		message, messageErr := formalFinalizerHandoffIntentMessage(authorization)
		if messageErr != nil {
			t.Fatal(messageErr)
		}
		authorization.Signature = ed25519.Sign(
			fixture.private[sender.PeerName], message)
		value = formalGLMPhase21RockAuthorizationRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockAuthorizationPurpose,
			ArtifactID: binding.ArtifactID, Role: sender.Role,
			IntentSHA256: sha, TransportAuthorization: authorization,
		}
	case formalGLMControlRecordAck:
		proof, proofErr := formalFinalizerHandoffBuildCommitProof(
			binding, ticketSHA, sha,
			fixture.private[binding.Finalizer.PeerName], fixture.public)
		if proofErr != nil {
			t.Fatal(proofErr)
		}
		value = formalGLMPhase21RockAckRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockAckPurpose,
			ArtifactID: binding.ArtifactID, Proof: proof,
		}
	default:
		t.Fatalf("unknown test record %q", recordType)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalGLMOneDrawControlClosedDirectionsK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		fixture := formalFinalizerHandoffTestFixtureForK(
			t, custodians, formalFinalizerHandoffFamilyGLM)
		finalizerTransport, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalFinalizerHandoffIssueTicket(
			fixture.binding, finalizerTransport.PublicKey().Bytes(),
			fixture.private[fixture.binding.Finalizer.PeerName], fixture.public)
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct{ recordType, senderRole string }{
			{formalGLMControlRecordStage, "garbler"},
			{formalGLMControlRecordStage, "evaluator"},
			{formalGLMControlRecordTicket, "garbler"},
			{formalGLMControlRecordSealReceipt, "evaluator"},
			{formalGLMControlRecordCandidate, "garbler"},
			{formalGLMControlRecordLocalRelease, "evaluator"},
			{formalGLMControlRecordBaseCertificate, "garbler"},
			{formalGLMControlRecordAuthorization, "garbler"},
			{formalGLMControlRecordAuthorization, "evaluator"},
			{formalGLMControlRecordAck, "garbler"},
		}
		for _, test := range cases {
			t.Run(test.recordType+"/"+test.senderRole, func(t *testing.T) {
				sender, _ := formalFinalizerHandoffPeer(
					fixture.binding, test.senderRole)
				recipientRole := "garbler"
				if sender.Role == "garbler" {
					recipientRole = "evaluator"
				}
				recipient, _ := formalFinalizerHandoffPeer(
					fixture.binding, recipientRole)
				recipientKey, recipientSignature := formalGLMControlTestTransport(
					t, fixture.private[recipient.PeerName])
				record := formalGLMControlTestRecord(
					t, test.recordType, test.senderRole, fixture, ticket)
				envelope, err := formalGLMOneDrawControlSeal(
					fixture.binding, test.recordType, sender.Role, record, ticket,
					recipientKey.PublicKey().Bytes(), recipientSignature,
					fixture.public)
				if err != nil {
					t.Fatal(err)
				}
				openTicket := ticket
				if test.recordType == formalGLMControlRecordTicket {
					// The evaluator learns the ticket from this encrypted record;
					// requiring it as an out-of-band argument would be circular.
					openTicket = formalFinalizerHandoffTicket{}
				}
				opened, err := formalGLMOneDrawControlOpen(
					fixture.binding, envelope, openTicket,
					recipientKey.Bytes(), fixture.public)
				if err != nil || !reflect.DeepEqual(opened, record) {
					t.Fatalf("control roundtrip failed: %v", err)
				}
			})
		}
	}
}

func TestFormalGLMOneDrawControlRejectsMixReorderAndTamper(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyGLM)
	finalizerTransport, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ticket, err := formalFinalizerHandoffIssueTicket(
		fixture.binding, finalizerTransport.PublicKey().Bytes(),
		fixture.private[fixture.binding.Finalizer.PeerName], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	recipient := fixture.binding.Authorities[1]
	recipientKey, recipientSignature := formalGLMControlTestTransport(
		t, fixture.private[recipient.PeerName])
	record := formalGLMControlTestRecord(
		t, formalGLMControlRecordCandidate, "garbler", fixture, ticket)
	envelope, err := formalGLMOneDrawControlSeal(
		fixture.binding, formalGLMControlRecordCandidate, "garbler", record,
		ticket, recipientKey.PublicKey().Bytes(), recipientSignature,
		fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*formalGLMOneDrawControlEnvelope){
		func(value *formalGLMOneDrawControlEnvelope) {
			value.Version = "wrong-version"
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.Protocol = "formal_cox_control_v1"
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.RecordType = formalGLMControlRecordBaseCertificate
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.SenderRole = "evaluator"
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.TicketSHA256 = formalFinalizerHandoffTestSHA("wrong-ticket")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.Family = formalFinalizerHandoffFamilyCox
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.ArtifactID = formalFinalizerHandoffTestSHA("other-artifact")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.PlanSHA256 = formalFinalizerHandoffTestSHA("other-plan")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.FinalPairRootSHA256 = formalFinalizerHandoffTestSHA("other-pair")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.PinsetSHA256 = formalFinalizerHandoffTestSHA("other-pinset")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.SenderPeerName = "other-sender"
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.SenderPeerID = "dsv1_" + formalFinalizerHandoffTestSHA("other-sender")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.RecipientPeerName = "other-recipient"
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.RecipientPeerID = "dsv1_" + formalFinalizerHandoffTestSHA("other-recipient")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.AAD.RecipientRole = "garbler"
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.RecordSHA256 = formalFinalizerHandoffTestSHA("other-record")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.RecipientTransportKeySHA256 = formalFinalizerHandoffTestSHA("other-key")
		},
		func(value *formalGLMOneDrawControlEnvelope) {
			value.Ciphertext[len(value.Ciphertext)/2] ^= 1
		},
	}
	for index, mutate := range mutations {
		changed := envelope
		changed.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
		mutate(&changed)
		if _, err := formalGLMOneDrawControlOpen(
			fixture.binding, changed, ticket,
			recipientKey.Bytes(), fixture.public); err == nil {
			t.Fatalf("tamper mutation %d was accepted", index)
		}
	}
	badSignature := append([]byte(nil), recipientSignature...)
	badSignature[0] ^= 1
	if _, err := formalGLMOneDrawControlSeal(
		fixture.binding, formalGLMControlRecordCandidate, "garbler", record,
		ticket, recipientKey.PublicKey().Bytes(), badSignature,
		fixture.public); err == nil {
		t.Fatal("unbound pre-ticket recipient key was accepted")
	}
	stage := formalGLMControlTestRecord(
		t, formalGLMControlRecordStage, "garbler", fixture, ticket)
	if _, err := formalGLMOneDrawControlSeal(
		fixture.binding, formalGLMControlRecordStage, "garbler", stage,
		formalFinalizerHandoffTicket{}, recipientKey.PublicKey().Bytes(),
		badSignature, fixture.public); err == nil {
		t.Fatal("unbound pre-ticket recipient key was accepted")
	}
	if _, err := formalGLMOneDrawControlSeal(
		fixture.binding, formalGLMControlRecordStage, "garbler", stage,
		formalFinalizerHandoffTicket{}, recipientKey.PublicKey().Bytes(),
		recipientSignature, fixture.public); err != nil {
		t.Fatalf("identity-bound pre-ticket stage failed: %v", err)
	}
}
