package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
)

const (
	formalGLMPhase21DistributedAuthorizationVersion = "dsvert-formal-glm-phase21-distributed-authorization-v1"
	formalGLMPhase21DistributedAuthorizationPurpose = "formal_glm_one_draw_sticky_publication_v1"
)

// This authorization is process-local until a recipient-encrypted reverse
// transport is connected. Its fields deliberately have no JSON surface: a
// caller cannot relay the DP candidate or either signature as plaintext.
type formalGLMPhase21DistributedAuthorization struct {
	Version                string                                    `json:"-"`
	Purpose                string                                    `json:"-"`
	ArtifactID             string                                    `json:"-"`
	IntentSHA256           string                                    `json:"-"`
	TransportAuthorization formalFinalizerHandoffIntentAuthorization `json:"-"`
	StickyAuthorization    jointDPBiomedicalGaussianSignature        `json:"-"`
	ProductionReady        bool                                      `json:"-"`
}

type formalGLMPhase21DistributedCleanupResult struct {
	SourceBytesRemoved      int64
	LocalSpoolsRemoved      int
	TransportRecordsRemoved int
}

type formalGLMPhase21DualPublicationGuard struct {
	stores [2]*formalGLMPhase21StickyReleaseStore
}

func formalGLMPhase21ValidatePublicationStoreOrder(
	stores [2]*formalGLMPhase21StickyReleaseStore,
	artifact formalGLMPhase21StickyArtifact,
) error {
	if stores[0] == nil || stores[1] == nil || stores[0] == stores[1] ||
		stores[0].peer == stores[1].peer || len(artifact.NoiseAuthorities) != 2 {
		return fmt.Errorf("formal-glm: invalid dual sticky authority stores")
	}
	for index, role := range []string{"garbler", "evaluator"} {
		authority := artifact.NoiseAuthorities[index]
		if authority.Role != role || stores[index].peer != authority.PeerName {
			return fmt.Errorf("formal-glm: dual sticky authority order changed")
		}
	}
	return nil
}

// formalGLMPhase21RequireProductiveOneDraw seals the currently promoted
// distributed lifecycle to the one backend whose remote authority can verify
// the final candidate from its local share and the opposite signed receipt.
// The independent-full implementation remains internal and unpromoted until
// it has an equivalent non-blind opening proof.
func formalGLMPhase21RequireProductiveOneDraw(mode string) error {
	if mode != formalGLMPhase21SamplerV2OneDraw {
		return fmt.Errorf(
			"formal-glm: productive distributed lifecycle requires %s; %s is not promoted",
			formalGLMPhase21SamplerV2OneDraw, mode)
	}
	return nil
}

// formalGLMPhase21RunProductiveOneDrawOnly is the no-effects promotion
// boundary. Callers place every run/source/sampler/decrypt operation inside
// run; unsupported modes return before the continuation is entered.
func formalGLMPhase21RunProductiveOneDrawOnly(mode string,
	run func() error,
) error {
	if err := formalGLMPhase21RequireProductiveOneDraw(mode); err != nil {
		return err
	}
	if run == nil {
		return fmt.Errorf("formal-glm: missing one-draw lifecycle continuation")
	}
	return run()
}

// formalGLMPhase21RunOrReplayProductiveOneDraw is the productive coordinator
// boundary. The K-signed SamplerV2 contract is a server-owned catalog asset:
// it already contains the canonical ArtifactID and needs no attempt RunID,
// pair root, ticket or source slot. Only an ArtifactID miss may enter run.
func formalGLMPhase21RunOrReplayProductiveOneDraw(
	stores [2]*formalGLMPhase21StickyReleaseStore,
	contract formalGLMPhase21SamplerV2Contract,
	run func() ([2]formalGLMPhase21StickyPublication, error),
) ([2]formalGLMPhase21StickyPublication, bool, error) {
	var zero [2]formalGLMPhase21StickyPublication
	if err := formalGLMPhase21RequireProductiveOneDraw(
		contract.SamplerMode); err != nil {
		return zero, false, err
	}
	if stores[0] == nil || stores[1] == nil ||
		formalGLMPhase21ValidateSamplerV2Contract(
			contract, stores[0].pins) != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(
			contract, stores[1].pins) != nil ||
		formalGLMPhase21ValidatePublicationStoreOrder(
			stores, contract.Artifact) != nil {
		return zero, false,
			fmt.Errorf("formal-glm: invalid signed productive preflight asset")
	}
	publications, found, err := formalGLMPhase21DistributedReplayPreflight(
		stores, contract.ArtifactID)
	if err != nil || found {
		return publications, found, err
	}
	if run == nil {
		return zero, false,
			fmt.Errorf("formal-glm: missing productive one-draw execution")
	}
	publications, err = run()
	if err != nil {
		return publications, false, err
	}
	verified, found, err := formalGLMPhase21DistributedReplayPreflight(
		stores, contract.ArtifactID)
	if err != nil || !found ||
		publications[0].CertificateSHA256 != verified[0].CertificateSHA256 ||
		publications[1].CertificateSHA256 != verified[1].CertificateSHA256 ||
		!bytes.Equal(publications[0].Certificate, verified[0].Certificate) ||
		!bytes.Equal(publications[1].Certificate, verified[1].Certificate) {
		return zero, false,
			fmt.Errorf("formal-glm: productive execution did not commit exact dual publication")
	}
	return verified, false, nil
}

// formalGLMPhase21DistributedReplayPreflight is the first operation of a
// promoted request. It uses only the canonical ArtifactID, so a fresh attempt
// never needs a RunID, pair root, source handoff, sampler, ticket or decrypt in
// order to replay an existing result.
func formalGLMPhase21DistributedReplayPreflight(
	stores [2]*formalGLMPhase21StickyReleaseStore,
	artifactID string,
) ([2]formalGLMPhase21StickyPublication, bool, error) {
	var publications [2]formalGLMPhase21StickyPublication
	if !formalGLMIsSHA256(artifactID) || stores[0] == nil || stores[1] == nil ||
		stores[0] == stores[1] || stores[0].peer == stores[1].peer {
		return publications, false,
			fmt.Errorf("formal-glm: invalid dual sticky preflight")
	}
	found := [2]bool{}
	for index, store := range stores {
		publication, err := store.Replay(artifactID)
		if err == nil {
			publications[index], found[index] = publication, true
			continue
		}
		if !os.IsNotExist(err) {
			return publications, false, err
		}
	}
	if found[0] != found[1] {
		return publications, false,
			fmt.Errorf("formal-glm: split dual sticky publication")
	}
	if !found[0] {
		return publications, false, nil
	}
	if publications[0].ArtifactID != artifactID ||
		publications[1].ArtifactID != artifactID ||
		publications[0].CertificateSHA256 != publications[1].CertificateSHA256 ||
		!bytes.Equal(publications[0].Certificate, publications[1].Certificate) {
		return publications, false,
			fmt.Errorf("formal-glm: divergent dual sticky publication")
	}
	certificate, err := formalGLMPhase21DecodeStickyPublication(publications[0])
	if err != nil || formalGLMPhase21ValidatePublicationStoreOrder(
		stores, certificate.Artifact) != nil {
		return publications, false,
			fmt.Errorf("formal-glm: invalid dual sticky publication authority order")
	}
	return publications, true, nil
}

func (guard formalGLMPhase21DualPublicationGuard) formalFinalizerHandoffVerifyPublication(
	artifactID, certificateSHA256 string,
) error {
	publications, found, err := formalGLMPhase21DistributedReplayPreflight(
		guard.stores, artifactID)
	if err != nil || !found ||
		publications[0].CertificateSHA256 != certificateSHA256 {
		return fmt.Errorf("formal-glm: exact dual sticky publication is absent")
	}
	return nil
}

func formalGLMPhase21SealLocalOneDraw(
	source *formalGLMPhase20HandoffStore,
	outbox *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	ticket formalFinalizerHandoffTicket,
	output formalGLMPhase21OneDrawLocalOutput,
	privateKey ed25519.PrivateKey,
	phaseHook func(string) error,
) (formalFinalizerHandoffEnvelope, bool, error) {
	return formalGLMPhase21SealLocalOneDrawWithResolution(
		source, outbox, contract, ticket, output, privateKey, phaseHook, nil)
}

func formalGLMPhase21SealLocalOneDrawWithResolution(
	source *formalGLMPhase20HandoffStore,
	outbox *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	ticket formalFinalizerHandoffTicket,
	output formalGLMPhase21OneDrawLocalOutput,
	privateKey ed25519.PrivateKey,
	phaseHook func(string) error,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (formalFinalizerHandoffEnvelope, bool, error) {
	var zero formalFinalizerHandoffEnvelope
	if err := formalGLMPhase21RequireProductiveOneDraw(
		contract.SamplerMode); err != nil {
		return zero, false, err
	}
	if source == nil || outbox == nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, source.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm: invalid local one-draw transport")
	}
	if ack, found, err := outbox.PreflightAck(); err != nil {
		return zero, false, err
	} else if found {
		return zero, true, &formalFinalizerHandoffTerminalAckError{Proof: ack}
	}
	var binding formalFinalizerHandoffBinding
	var err error
	if contract.Artifact.DescriptorCoreSHA256 != "" && resolution != nil {
		binding, err = formalGLMPhase21RegisteredOneDrawFinalizerBinding(
			source, output, contract, *resolution)
	} else if contract.Artifact.DescriptorCoreSHA256 == "" && resolution == nil {
		binding, err = formalGLMPhase21OneDrawFinalizerBinding(source, output)
	} else {
		err = fmt.Errorf("formal-glm: invalid local transport registry resolution")
	}
	if err != nil || !reflect.DeepEqual(binding, outbox.binding) ||
		binding.ArtifactID != contract.ArtifactID {
		return zero, false, fmt.Errorf("formal-glm: local one-draw transport binding mismatch")
	}
	if _, err := formalGLMPhase21PersistLocalOneDrawSpoolWithResolution(
		source, outbox, contract, output, resolution); err != nil {
		return zero, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_local_spool_before_seal"); err != nil {
			return zero, false, err
		}
	}
	if _, _, err := outbox.CommitTicket(ticket); err != nil {
		return zero, false, err
	}
	payload, err := formalGLMPhase21BuildOneDrawTransitWithResolution(
		source, binding, ticket, output, &contract, resolution)
	if err != nil {
		return zero, false, err
	}
	defer formalGLMPhase21ClearOneDrawTransit(&payload)
	envelope, err := formalFinalizerHandoffSealGLMOneDraw(
		binding, ticket, payload, privateKey, source.pins)
	if err != nil {
		return zero, false, err
	}
	committed, replayed, err := outbox.CommitOutbox(envelope)
	if err != nil {
		return zero, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_outbox_seal"); err != nil {
			return committed, replayed, err
		}
	}
	return committed, replayed, nil
}

// formalGLMPhase21DistributedIngressPreflight validates and durably CASes
// exactly two ordered ciphertext envelopes. The ArtifactID replay lookup is
// deliberately first.
func formalGLMPhase21DistributedIngressPreflight(
	stores [2]*formalGLMPhase21StickyReleaseStore,
	ingress *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	ticket formalFinalizerHandoffTicket,
	envelopes [2]formalFinalizerHandoffEnvelope,
) ([2]formalGLMPhase21StickyPublication, bool, error) {
	var zero [2]formalGLMPhase21StickyPublication
	if err := formalGLMPhase21RequireProductiveOneDraw(
		contract.SamplerMode); err != nil {
		return zero, false, err
	}
	publications, found, err := formalGLMPhase21DistributedReplayPreflight(
		stores, contract.ArtifactID)
	if err != nil || found {
		return publications, found, err
	}
	if ingress == nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, ingress.pins) != nil ||
		formalGLMPhase21ValidatePublicationStoreOrder(
			stores, contract.Artifact) != nil ||
		ingress.binding.ArtifactID != contract.ArtifactID ||
		ingress.binding.PinsetSHA256 != contract.Artifact.PinsetSHA256 ||
		formalFinalizerHandoffValidateTicket(
			ticket, ingress.binding, ingress.pins) != nil {
		return zero, false, fmt.Errorf("formal-glm: invalid distributed ingress")
	}
	if ack, ackFound, ackErr := ingress.PreflightAck(); ackErr != nil {
		return zero, false, ackErr
	} else if ackFound {
		if guardErr := (formalGLMPhase21DualPublicationGuard{stores}).
			formalFinalizerHandoffVerifyPublication(
				ack.ArtifactID, ack.CertificateSHA256); guardErr != nil {
			return zero, false, guardErr
		}
		publications, _, replayErr := formalGLMPhase21DistributedReplayPreflight(
			stores, contract.ArtifactID)
		return publications, true, replayErr
	}
	for index, role := range []string{"garbler", "evaluator"} {
		authority := ingress.binding.Authorities[index]
		envelope := envelopes[index]
		if envelope.SenderRole != role ||
			envelope.SenderPeerName != authority.PeerName ||
			envelope.SenderPeerID != authority.PeerID ||
			envelope.PayloadKind != formalFinalizerHandoffGLMOneDrawKind ||
			formalFinalizerHandoffValidateEnvelope(
				ingress.binding, ticket, envelope, ingress.pins) != nil {
			return zero, false,
				fmt.Errorf("formal-glm: invalid ordered one-draw ingress")
		}
	}
	if _, _, err := ingress.CommitTicket(ticket); err != nil {
		return zero, false, err
	}
	for _, envelope := range envelopes {
		if _, _, err := ingress.CommitIngress(envelope); err != nil {
			return zero, false, err
		}
	}
	return zero, false, nil
}

func formalGLMPhase21OpenDurableOneDrawTransit(
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	role string,
) (formalGLMPhase21OneDrawTransitPayload, error) {
	var zero formalGLMPhase21OneDrawTransitPayload
	encoded, err := ingress.OpenIngressDurableCanonical(role, ticket)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var payload formalGLMPhase21OneDrawTransitPayload
	if err := formalGLMPhase21DecodeOneDrawTransitCanonical(
		encoded, &payload); err != nil {
		return zero, err
	}
	if payload.SenderRole != role || formalGLMPhase21ValidateOneDrawTransit(
		ingress.binding, ticket, payload, ingress.pins) != nil {
		formalGLMPhase21ClearOneDrawTransit(&payload)
		return zero, fmt.Errorf("formal-glm: invalid durable typed ingress")
	}
	return payload, nil
}

// formalGLMPhase21DistributedOpenAndPrepare decrypts only after the
// ArtifactID publication and terminal-ACK checks. Only the fixed garbler
// finalizer imports both private shares, one at a time.
func formalGLMPhase21DistributedOpenAndPrepare(
	stores [2]*formalGLMPhase21StickyReleaseStore,
	finalizerSource *formalGLMPhase20HandoffStore,
	finalizerRelease *jointDPBiomedicalGaussianOneDrawDurableReleaseStore,
	ingress *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	ticket formalFinalizerHandoffTicket,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	phaseHook func(string) error,
) (jointDPBiomedicalGaussianOneDrawCommonRelease,
	[2]formalGLMPhase21StickyPublication, bool, error,
) {
	var zeroCandidate jointDPBiomedicalGaussianOneDrawCommonRelease
	var zeroPublications [2]formalGLMPhase21StickyPublication
	if err := formalGLMPhase21RequireProductiveOneDraw(
		contract.SamplerMode); err != nil {
		return zeroCandidate, zeroPublications, false, err
	}
	publications, found, err := formalGLMPhase21DistributedReplayPreflight(
		stores, contract.ArtifactID)
	if err != nil || found {
		return zeroCandidate, publications, found, err
	}
	if finalizerSource == nil || finalizerRelease == nil || ingress == nil ||
		finalizerSource.peer != ingress.binding.Finalizer.PeerName ||
		finalizerRelease.peer != ingress.binding.Finalizer.PeerName ||
		ingress.binding.ArtifactID != contract.ArtifactID ||
		formalGLMPhase21ValidateSamplerV2Contract(
			contract, finalizerSource.pins) != nil ||
		formalGLMPhase21ValidatePublicationStoreOrder(
			stores, contract.Artifact) != nil ||
		formalFinalizerHandoffValidateTicket(
			ticket, ingress.binding, ingress.pins) != nil {
		return zeroCandidate, zeroPublications, false,
			fmt.Errorf("formal-glm: invalid distributed one-draw finalizer")
	}
	if ack, ackFound, ackErr := ingress.PreflightAck(); ackErr != nil {
		return zeroCandidate, zeroPublications, false, ackErr
	} else if ackFound {
		if guardErr := (formalGLMPhase21DualPublicationGuard{stores}).
			formalFinalizerHandoffVerifyPublication(
				ack.ArtifactID, ack.CertificateSHA256); guardErr != nil {
			return zeroCandidate, zeroPublications, false, guardErr
		}
		publications, _, replayErr := formalGLMPhase21DistributedReplayPreflight(
			stores, contract.ArtifactID)
		return zeroCandidate, publications, true, replayErr
	}
	storedTicket, err := ingress.loadTicket()
	storedTicketJSON, _ := json.Marshal(storedTicket)
	ticketJSON, _ := json.Marshal(ticket)
	if err != nil || !bytes.Equal(storedTicketJSON, ticketJSON) {
		return zeroCandidate, zeroPublications, false,
			fmt.Errorf("formal-glm: durable one-draw ticket changed")
	}
	for index, role := range []string{"garbler", "evaluator"} {
		envelope, envelopeErr := ingress.loadEnvelope("ingress-v1", role)
		authority := ingress.binding.Authorities[index]
		if envelopeErr != nil || envelope.SenderRole != role ||
			envelope.SenderPeerName != authority.PeerName ||
			envelope.SenderPeerID != authority.PeerID ||
			envelope.PayloadKind != formalFinalizerHandoffGLMOneDrawKind {
			return zeroCandidate, zeroPublications, false,
				fmt.Errorf("formal-glm: incomplete durable one-draw ingress")
		}
	}
	if phaseHook != nil {
		if err := phaseHook("after_public_preflight"); err != nil {
			return zeroCandidate, zeroPublications, false, err
		}
	}
	var imported [2]formalGLMPhase21OneDrawLocalOutput
	defer imported[0].clear()
	defer imported[1].clear()
	for index, role := range []string{"garbler", "evaluator"} {
		payload, err := formalGLMPhase21OpenDurableOneDrawTransit(
			ingress, ticket, role)
		if err != nil {
			return zeroCandidate, zeroPublications, false, err
		}
		imported[index], err = formalGLMPhase21ImportOneDrawTransit(
			finalizerSource, capsule, request, backendSignatures,
			workerSignatures, ingress.binding, ticket, payload)
		formalGLMPhase21ClearOneDrawTransit(&payload)
		if err != nil {
			return zeroCandidate, zeroPublications, false, err
		}
		if phaseHook != nil {
			if err := phaseHook("after_import_" + role); err != nil {
				return zeroCandidate, zeroPublications, false, err
			}
		}
	}
	localRelease, err := formalGLMPhase21FinalizeOneDrawLocal(
		finalizerSource, finalizerRelease, imported[0], imported[1], nil)
	if err != nil {
		return zeroCandidate, zeroPublications, false, err
	}
	authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{
			imported[0].Admission.Envelope,
		}, imported[0].Admission.Trust)
	if err != nil {
		return zeroCandidate, zeroPublications, false, err
	}
	candidate := jointDPBiomedicalGaussianOneDrawCommonFromLocal(
		authority, localRelease.Receipt)
	if len(candidate.Signatures) != 0 {
		return zeroCandidate, zeroPublications, false,
			fmt.Errorf("formal-glm: finalizer candidate was prematurely signed")
	}
	if _, err := formalGLMPhase21OneDrawUnsignedCandidateValid(
		imported[0], candidate); err != nil {
		return zeroCandidate, zeroPublications, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_candidate_durable"); err != nil {
			return zeroCandidate, zeroPublications, false, err
		}
	}
	return candidate, zeroPublications, false, nil
}

// formalGLMPhase21BuildVerifiedOneDrawLocalRelease signs the legacy internal
// common-release evidence only after the signer has independently checked the
// complete candidate against its local share and the opposite signed digest.
func formalGLMPhase21BuildVerifiedOneDrawLocalRelease(
	store *formalGLMPhase20HandoffStore,
	local formalGLMPhase21OneDrawLocalOutput,
	opposite jointDPBiomedicalGaussianOneDrawChunkReceipt,
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
	privateKey ed25519.PrivateKey,
) (jointDPBiomedicalGaussianOneDrawLocalRelease, error) {
	var zero jointDPBiomedicalGaussianOneDrawLocalRelease
	if len(candidate.Signatures) != 0 || len(privateKey) != ed25519.PrivateKeySize ||
		formalGLMPhase21VerifyOneDrawCandidateAgainstLocal(
			store, local, opposite, candidate) != nil {
		return zero, fmt.Errorf("formal-glm: non-blind local release check failed")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(publicKey, store.pins[local.Peer]) {
		return zero, fmt.Errorf("formal-glm: local release signer is not pinned")
	}
	pinDigest := sha256.Sum256(publicKey)
	receipt := jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt{
		Version:                    jointDPBiomedicalGaussianOneDrawLocalReleaseVersion,
		Backend:                    candidate.Backend,
		Mechanism:                  candidate.Mechanism,
		Sampler:                    candidate.Sampler,
		PeerName:                   local.Peer,
		PeerIdentitySHA256:         hex.EncodeToString(pinDigest[:]),
		ReleaseInstanceID:          candidate.ReleaseInstanceID,
		ReleaseContractSHA256:      candidate.ReleaseContractSHA256,
		ProductiveStreamSHA256:     candidate.ProductiveStreamSHA256,
		PlanSHA256:                 candidate.PlanSHA256,
		CoordinateOrderSHA256:      candidate.CoordinateOrderSHA256,
		LedgerReservationSHA256:    candidate.LedgerReservationSHA256,
		FinalizerReservationSHA256: candidate.FinalizerReservationSHA256,
		VectorSHA256:               candidate.VectorSHA256,
		ClampedScaledValues: append(
			[]string(nil), candidate.ClampedScaledValues...),
		OutputLatticeBits:                   candidate.OutputLatticeBits,
		Epsilon:                             candidate.Epsilon,
		Delta:                               candidate.Delta,
		CoreDeltaNumerator:                  candidate.CoreDeltaNumerator,
		CoreDeltaDenominator:                candidate.CoreDeltaDenominator,
		VectorTailTVUpperNumerator:          candidate.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:        candidate.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:           candidate.VectorCDFTVUpperNumerator,
		VectorCDFTVUpperDenominator:         candidate.VectorCDFTVUpperDenominator,
		VectorTotalTVUpperNumerator:         candidate.VectorTotalTVUpperNumerator,
		VectorTotalTVUpperDenominator:       candidate.VectorTotalTVUpperDenominator,
		ImplementationDeltaNumerator:        candidate.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator:      candidate.ImplementationDeltaDenominator,
		RouteRole:                           candidate.RouteRole,
		PrivacyClaimScope:                   candidate.PrivacyClaimScope,
		TargetVarianceOptimal:               candidate.TargetVarianceOptimal,
		NominalVarianceMultiplier:           candidate.NominalVarianceMultiplier,
		NominalStandardDeviationFactor:      candidate.NominalStandardDeviationFactor,
		Cost:                                candidate.Cost,
		LedgerAppendBeforeValidityOrRelease: candidate.LedgerAppendBeforeValidityOrRelease,
		ExactlyOnceRelease:                  candidate.ExactlyOnceRelease,
		SingleCommonDPVector:                false,
		UnlimitedDeterministicReplay:        candidate.UnlimitedDeterministicReplay,
		UnlimitedPostprocessing:             candidate.UnlimitedPostprocessing,
		HistoryCanDenyOperation:             false,
		OperationLimit:                      false,
		RequestLimit:                        false,
		OpeningsPerformed:                   candidate.OpeningsPerformed,
		ProductionReady:                     false,
		Blockers: append([]string(nil),
			candidate.Blockers...),
	}
	commonMessage, err := jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(
		candidate)
	if err != nil {
		return zero, err
	}
	receipt.CommonReleaseSignature = ed25519.Sign(privateKey, commonMessage)
	message, err := jointDPBiomedicalGaussianOneDrawLocalReleaseMessage(receipt)
	if err != nil {
		return zero, err
	}
	receipt.Signature = ed25519.Sign(privateKey, message)
	authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{local.Admission.Envelope},
		local.Admission.Trust)
	if err != nil || jointDPBiomedicalGaussianValidateOneDrawLocalRelease(
		authority, receipt) != nil {
		return zero, fmt.Errorf("formal-glm: invalid verified local release")
	}
	return jointDPBiomedicalGaussianOneDrawLocalRelease{Receipt: receipt}, nil
}

func formalGLMPhase21BuildDistributedOneDrawCertificate(
	source *formalGLMPhase20HandoffStore,
	local formalGLMPhase21OneDrawLocalOutput,
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
	localReleases [2]jointDPBiomedicalGaussianOneDrawLocalRelease,
	contract formalGLMPhase21SamplerV2Contract,
) (formalGLMPhase16CertifiedRelease,
	formalGLMPhase21StickyCertificate, error,
) {
	return formalGLMPhase21BuildDistributedOneDrawCertificateWithResolution(
		source, local, candidate, localReleases, contract, nil)
}

func formalGLMPhase21BuildDistributedOneDrawCertificateWithResolution(
	source *formalGLMPhase20HandoffStore,
	local formalGLMPhase21OneDrawLocalOutput,
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
	localReleases [2]jointDPBiomedicalGaussianOneDrawLocalRelease,
	contract formalGLMPhase21SamplerV2Contract,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (formalGLMPhase16CertifiedRelease,
	formalGLMPhase21StickyCertificate, error,
) {
	var zeroRelease formalGLMPhase16CertifiedRelease
	var zeroCertificate formalGLMPhase21StickyCertificate
	if err := formalGLMPhase21RequireProductiveOneDraw(
		contract.SamplerMode); err != nil {
		return zeroRelease, zeroCertificate, err
	}
	if source == nil || len(candidate.Signatures) != 0 ||
		formalGLMPhase21ValidateLocalOutputSource(source, local) != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, source.pins) != nil {
		return zeroRelease, zeroCertificate,
			fmt.Errorf("formal-glm: invalid distributed certificate source")
	}
	release, err := formalGLMPhase21CertifyOneDrawRelease(
		localReleases[0], localReleases[1], local.Admission)
	if err != nil {
		return zeroRelease, zeroCertificate, err
	}
	if release.OneDraw == nil {
		return zeroRelease, zeroCertificate,
			fmt.Errorf("formal-glm: distributed certificate lacks one-draw release")
	}
	releasedCandidate := *release.OneDraw
	releasedCandidate.Signatures = nil
	if !reflect.DeepEqual(releasedCandidate, candidate) {
		return zeroRelease, zeroCertificate,
			fmt.Errorf("formal-glm: local releases signed another candidate")
	}
	handoff, _, err := source.Load()
	if err != nil {
		return zeroRelease, zeroCertificate, err
	}
	plan := handoff.Plan
	handoff.clear()
	certificate, err := formalGLMPhase21BuildStickyCertificateV2WithResolution(
		release, local.Admission.Compiled.Binding, local.Admission.Token,
		plan, source.pins, contract, resolution)
	if err != nil {
		return zeroRelease, zeroCertificate, err
	}
	return release, certificate, nil
}

func formalGLMPhase21DistributedIntentSHA256(
	certificate formalGLMPhase21StickyCertificate,
) (string, error) {
	if len(certificate.AuthorityReceipts) != 0 {
		return "", fmt.Errorf("formal-glm: distributed intent is not unsigned")
	}
	return formalGLMPhase21StickyHash(
		formalGLMPhase21StickyDomain+"/distributed-one-draw-intent", certificate)
}

func formalGLMPhase21DistributedSignOnce(
	source *formalGLMPhase20HandoffStore,
	outbox *formalFinalizerHandoffStore,
	sticky *formalGLMPhase21StickyReleaseStore,
	ticket formalFinalizerHandoffTicket,
	contract formalGLMPhase21SamplerV2Contract,
	local formalGLMPhase21OneDrawLocalOutput,
	opposite jointDPBiomedicalGaussianOneDrawChunkReceipt,
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
	release formalGLMPhase16CertifiedRelease,
	baseCertificate formalGLMPhase21StickyCertificate,
	privateKey ed25519.PrivateKey,
	transportPredecessors []formalFinalizerHandoffIntentAuthorization,
	stickyPredecessors []jointDPBiomedicalGaussianSignature,
) (formalGLMPhase21DistributedAuthorization, bool, error) {
	return formalGLMPhase21DistributedSignOnceWithResolution(
		source, outbox, sticky, ticket, contract, local, opposite,
		candidate, release, baseCertificate, privateKey,
		transportPredecessors, stickyPredecessors, nil)
}

func formalGLMPhase21DistributedSignOnceWithResolution(
	source *formalGLMPhase20HandoffStore,
	outbox *formalFinalizerHandoffStore,
	sticky *formalGLMPhase21StickyReleaseStore,
	ticket formalFinalizerHandoffTicket,
	contract formalGLMPhase21SamplerV2Contract,
	local formalGLMPhase21OneDrawLocalOutput,
	opposite jointDPBiomedicalGaussianOneDrawChunkReceipt,
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
	release formalGLMPhase16CertifiedRelease,
	baseCertificate formalGLMPhase21StickyCertificate,
	privateKey ed25519.PrivateKey,
	transportPredecessors []formalFinalizerHandoffIntentAuthorization,
	stickyPredecessors []jointDPBiomedicalGaussianSignature,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (formalGLMPhase21DistributedAuthorization, bool, error) {
	var zero formalGLMPhase21DistributedAuthorization
	if err := formalGLMPhase21RequireProductiveOneDraw(
		contract.SamplerMode); err != nil {
		return zero, false, err
	}
	if source == nil || outbox == nil || sticky == nil ||
		local.Peer != source.peer || local.Peer != sticky.peer ||
		formalGLMPhase21VerifyOneDrawCandidateAgainstLocal(
			source, local, opposite, candidate) != nil ||
		formalGLMPhase16ValidateCertifiedRelease(
			release, local.Admission.Compiled.Binding,
			local.Admission.Token, source.pins) != nil ||
		release.OneDraw == nil {
		return zero, false, fmt.Errorf("formal-glm: remote signer rejected candidate")
	}
	releaseCandidate := *release.OneDraw
	releaseCandidate.Signatures = nil
	if !reflect.DeepEqual(releaseCandidate, candidate) {
		return zero, false, fmt.Errorf("formal-glm: certified release changed candidate")
	}
	handoff, _, err := source.Load()
	if err != nil {
		return zero, false, err
	}
	plan := handoff.Plan
	handoff.clear()
	expected, err := formalGLMPhase21BuildStickyCertificateV2WithResolution(
		release, local.Admission.Compiled.Binding, local.Admission.Token,
		plan, source.pins, contract, resolution)
	if err != nil || !reflect.DeepEqual(expected, baseCertificate) {
		return zero, false,
			fmt.Errorf("formal-glm: remote signer received another certificate")
	}
	staged, _, err := sticky.FinalizeSamplerV2Once(
		contract, func() (formalGLMPhase21StickyCertificate, error) {
			return baseCertificate, nil
		}, nil)
	if err != nil {
		return zero, false, err
	}
	intentSHA, err := formalGLMPhase21DistributedIntentSHA256(staged)
	if err != nil {
		return zero, false, err
	}
	envelope, err := outbox.loadEnvelope("outbox-v1", local.Role)
	if err != nil || envelope.SenderPeerName != local.Peer {
		return zero, false, fmt.Errorf("formal-glm: remote signer lacks durable outbox")
	}
	transportAuthorization, transportReplayed, err := outbox.SignIntentOnce(
		ticket, local.Role, intentSHA, envelope.PayloadSHA256,
		transportPredecessors, privateKey)
	if err != nil {
		return zero, false, err
	}
	stickyAuthorization, stickyReplayed, err := sticky.SignOnce(
		staged, privateKey, stickyPredecessors)
	if err != nil {
		return zero, false, err
	}
	authorization := formalGLMPhase21DistributedAuthorization{
		Version:    formalGLMPhase21DistributedAuthorizationVersion,
		Purpose:    formalGLMPhase21DistributedAuthorizationPurpose,
		ArtifactID: contract.ArtifactID, IntentSHA256: intentSHA,
		TransportAuthorization: transportAuthorization,
		StickyAuthorization:    stickyAuthorization,
		ProductionReady:        false,
	}
	return authorization, transportReplayed && stickyReplayed, nil
}

func formalGLMPhase21ValidateDistributedAuthorization(
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	certificate formalGLMPhase21StickyCertificate,
	role string,
	authorization formalGLMPhase21DistributedAuthorization,
	transportPredecessors []formalFinalizerHandoffIntentAuthorization,
	stickyPredecessors []jointDPBiomedicalGaussianSignature,
) error {
	if ingress == nil || len(certificate.AuthorityReceipts) != 0 ||
		formalGLMPhase21ValidateStickyCertificateCore(
			certificate, ingress.pins) != nil {
		return fmt.Errorf("formal-glm: invalid distributed authorization verifier")
	}
	intentSHA, err := formalGLMPhase21DistributedIntentSHA256(certificate)
	ticketSHA, ticketErr := formalFinalizerHandoffTicketSHA256(ticket)
	authority, authorityErr := formalFinalizerHandoffPeer(ingress.binding, role)
	if err != nil || ticketErr != nil || authorityErr != nil ||
		authorization.Version != formalGLMPhase21DistributedAuthorizationVersion ||
		authorization.Purpose != formalGLMPhase21DistributedAuthorizationPurpose ||
		authorization.ArtifactID != ingress.binding.ArtifactID ||
		authorization.IntentSHA256 != intentSHA || authorization.ProductionReady ||
		formalFinalizerHandoffValidateIntentAuthorization(
			authorization.TransportAuthorization, ingress.binding,
			ticketSHA, ingress.pins) != nil ||
		authorization.TransportAuthorization.SignerRole != role ||
		authorization.TransportAuthorization.SignerPeerName != authority.PeerName ||
		authorization.TransportAuthorization.IntentSHA256 != intentSHA ||
		authorization.StickyAuthorization.Signer != authority.PeerName {
		return fmt.Errorf("formal-glm: distributed authorization mismatch")
	}
	ingressEnvelope, err := ingress.loadEnvelope("ingress-v1", role)
	if err != nil || authorization.TransportAuthorization.LocalGuardSHA256 !=
		ingressEnvelope.PayloadSHA256 {
		return fmt.Errorf("formal-glm: distributed authorization lost local guard")
	}
	message, err := formalGLMPhase21StickyCertificateMessage(certificate)
	if err != nil || len(authorization.StickyAuthorization.Signature) !=
		ed25519.SignatureSize || !ed25519.Verify(
		ingress.pins[authority.PeerName], message,
		authorization.StickyAuthorization.Signature) {
		return fmt.Errorf("formal-glm: invalid sticky authorization signature")
	}
	if role == "garbler" {
		if len(transportPredecessors) != 0 || len(stickyPredecessors) != 0 ||
			authorization.TransportAuthorization.PredecessorReceiptSHA256 != "" {
			return fmt.Errorf("formal-glm: garbler authorization has predecessor")
		}
		return nil
	}
	if role != "evaluator" || len(transportPredecessors) != 1 ||
		len(stickyPredecessors) != 1 ||
		formalFinalizerHandoffValidateIntentAuthorization(
			transportPredecessors[0], ingress.binding,
			ticketSHA, ingress.pins) != nil ||
		transportPredecessors[0].SignerRole != "garbler" ||
		transportPredecessors[0].IntentSHA256 != intentSHA ||
		stickyPredecessors[0].Signer !=
			ingress.binding.Authorities[0].PeerName ||
		!ed25519.Verify(ingress.pins[stickyPredecessors[0].Signer], message,
			stickyPredecessors[0].Signature) {
		return fmt.Errorf("formal-glm: evaluator authorization lacks predecessor")
	}
	predecessorSHA, err := formalFinalizerHandoffIntentSHA256(
		transportPredecessors[0])
	if err != nil ||
		authorization.TransportAuthorization.PredecessorReceiptSHA256 !=
			predecessorSHA {
		return fmt.Errorf("formal-glm: evaluator transport predecessor mismatch")
	}
	return nil
}

// formalGLMPhase21DistributedPublishAndAck commits one sealed byte sequence to
// both authority stores before it creates the shared transport ACK. Repeating
// the function repairs a crash after either identical CAS; any different byte
// sequence collides by canonical ArtifactID.
func formalGLMPhase21DistributedPublishAndAck(
	stores [2]*formalGLMPhase21StickyReleaseStore,
	ingress *formalFinalizerHandoffStore,
	ticket formalFinalizerHandoffTicket,
	baseCertificate formalGLMPhase21StickyCertificate,
	authorizations [2]formalGLMPhase21DistributedAuthorization,
	finalizerPrivateKey ed25519.PrivateKey,
	phaseHook func(string) error,
) ([2]formalGLMPhase21StickyPublication,
	formalFinalizerHandoffCommitProof, bool, error,
) {
	var zeroPublications [2]formalGLMPhase21StickyPublication
	var zeroProof formalFinalizerHandoffCommitProof
	if ingress == nil || stores[0] == nil || stores[1] == nil ||
		baseCertificate.SamplerV2Contract == nil ||
		formalGLMPhase21RequireProductiveOneDraw(
			baseCertificate.SamplerV2Contract.SamplerMode) != nil ||
		formalGLMPhase21ValidateStickyCertificateCore(
			baseCertificate, ingress.pins) != nil ||
		formalGLMPhase21ValidatePublicationStoreOrder(
			stores, baseCertificate.Artifact) != nil ||
		baseCertificate.ArtifactID != ingress.binding.ArtifactID {
		return zeroPublications, zeroProof, false,
			fmt.Errorf("formal-glm: invalid distributed publication")
	}
	guard := formalGLMPhase21DualPublicationGuard{stores}
	if ack, found, err := ingress.PreflightAck(); err != nil {
		return zeroPublications, zeroProof, false, err
	} else if found {
		if err := guard.formalFinalizerHandoffVerifyPublication(
			ack.ArtifactID, ack.CertificateSHA256); err != nil {
			return zeroPublications, zeroProof, false, err
		}
		publications, _, err := formalGLMPhase21DistributedReplayPreflight(
			stores, ack.ArtifactID)
		return publications, ack, true, err
	}
	promoted, err := formalGLMPhase21PromoteDurableV2(
		baseCertificate, ingress.pins)
	if err != nil {
		return zeroPublications, zeroProof, false, err
	}
	if err := formalGLMPhase21ValidateDistributedAuthorization(
		ingress, ticket, promoted, "garbler", authorizations[0], nil, nil); err != nil {
		return zeroPublications, zeroProof, false, err
	}
	if err := formalGLMPhase21ValidateDistributedAuthorization(
		ingress, ticket, promoted, "evaluator", authorizations[1],
		[]formalFinalizerHandoffIntentAuthorization{
			authorizations[0].TransportAuthorization,
		}, []jointDPBiomedicalGaussianSignature{
			authorizations[0].StickyAuthorization,
		}); err != nil {
		return zeroPublications, zeroProof, false, err
	}
	sealed, err := formalGLMPhase21SealStickyCertificate(
		promoted, []jointDPBiomedicalGaussianSignature{
			authorizations[0].StickyAuthorization,
			authorizations[1].StickyAuthorization,
		}, ingress.pins)
	if err != nil {
		return zeroPublications, zeroProof, false, err
	}
	publications := zeroPublications
	for index, role := range []string{"garbler", "evaluator"} {
		publications[index], err = stores[index].Commit(sealed)
		if err != nil {
			return publications, zeroProof, false, err
		}
		if phaseHook != nil {
			if err := phaseHook("after_sticky_commit_" + role); err != nil {
				return publications, zeroProof, false, err
			}
		}
	}
	if publications[0].CertificateSHA256 != publications[1].CertificateSHA256 ||
		!bytes.Equal(publications[0].Certificate, publications[1].Certificate) {
		return publications, zeroProof, false,
			fmt.Errorf("formal-glm: dual publication bytes diverged")
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return publications, zeroProof, false, err
	}
	proof, err := formalFinalizerHandoffBuildCommitProof(
		ingress.binding, ticketSHA, publications[0].CertificateSHA256,
		finalizerPrivateKey, ingress.pins)
	if err != nil {
		return publications, zeroProof, false, err
	}
	proof, ackReplayed, err := ingress.AckAfterCommit(proof, guard)
	if err != nil {
		return publications, zeroProof, false, err
	}
	if phaseHook != nil {
		if err := phaseHook("after_transport_ack"); err != nil {
			return publications, proof, false, err
		}
	}
	return publications, proof,
		publications[0].Replayed && publications[1].Replayed && ackReplayed, nil
}

// formalGLMPhase21DistributedCleanupAfterAck first propagates the exact ACK
// to both authority outboxes, then acknowledges/consumes both local source
// slots, and finally removes only encrypted transport records. Tickets,
// SignOnce records, ACKs and public publications remain durable.
func formalGLMPhase21DistributedCleanupAfterAck(
	stores [2]*formalGLMPhase21StickyReleaseStore,
	sources [2]*formalGLMPhase20HandoffStore,
	outboxes [2]*formalFinalizerHandoffStore,
	ingress *formalFinalizerHandoffStore,
	outputs [2]formalGLMPhase21OneDrawLocalOutput,
	proof formalFinalizerHandoffCommitProof,
) (formalGLMPhase21DistributedCleanupResult, error) {
	var result formalGLMPhase21DistributedCleanupResult
	if ingress == nil || stores[0] == nil || stores[1] == nil ||
		sources[0] == nil || sources[1] == nil ||
		outboxes[0] == nil || outboxes[1] == nil {
		return result, fmt.Errorf("formal-glm: invalid distributed cleanup")
	}
	guard := formalGLMPhase21DualPublicationGuard{stores}
	if err := guard.formalFinalizerHandoffVerifyPublication(
		proof.ArtifactID, proof.CertificateSHA256); err != nil {
		return result, err
	}
	ack, found, err := ingress.PreflightAck()
	ackJSON, _ := json.Marshal(ack)
	proofJSON, _ := json.Marshal(proof)
	if err != nil || !found || !bytes.Equal(ackJSON, proofJSON) {
		return result, fmt.Errorf("formal-glm: cleanup lacks exact durable ACK")
	}
	for _, outbox := range outboxes {
		if _, _, err := outbox.AckAfterCommit(proof, guard); err != nil {
			return result, err
		}
	}
	publications, found, err := formalGLMPhase21DistributedReplayPreflight(
		stores, proof.ArtifactID)
	if err != nil || !found {
		return result, fmt.Errorf("formal-glm: cleanup publication disappeared")
	}
	certificate, err := formalGLMPhase21DecodeStickyPublication(publications[0])
	if err != nil || certificate.SamplerV2Contract == nil {
		return result, fmt.Errorf("formal-glm: cleanup contract disappeared")
	}
	contract := *certificate.SamplerV2Contract
	for index := range stores {
		if _, err := stores[index].AckDurableV2(publications[index]); err != nil {
			return result, err
		}
		output := outputs[index]
		if output.Peer != stores[index].peer || output.Peer != sources[index].peer {
			return result, fmt.Errorf("formal-glm: cleanup authority order changed")
		}
		removed, err := formalGLMPhase21CleanupCommittedOneDraw(
			stores[index], sources[index], proof.ArtifactID,
			output.capsule, output.request,
			output.Admission.BackendSelection.Signatures,
			output.Admission.Envelope.Signatures)
		if err != nil {
			return result, err
		}
		result.SourceBytesRemoved += removed
	}
	for _, outbox := range outboxes {
		removed, err := formalGLMPhase21CleanupLocalOneDrawSpoolAfterAck(
			outbox, contract, proof)
		if err != nil {
			return result, err
		}
		result.LocalSpoolsRemoved += removed
	}
	for _, transport := range []*formalFinalizerHandoffStore{
		ingress, outboxes[0], outboxes[1],
	} {
		removed, err := transport.CleanupTransportAfterAck(proof)
		if err != nil {
			return result, err
		}
		result.TransportRecordsRemoved += removed
	}
	return result, nil
}
