package main

// A sampler source offer is the public, share-free handoff between the
// certified one-draw Gaussian worker and the recipient-local blockwise Cox
// source spool.  The offer is not a release and never contains a raw output
// share, a seed, or a transport private key.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
)

const (
	formalCoxBlockwiseSamplerSourceOfferVersion = "dsvert-formal-cox-blockwise-sampler-source-offer-v1"
	formalCoxBlockwiseSamplerSourceOfferPurpose = "formal_cox_sampler_to_recipient_source_v1"
	formalCoxBlockwiseSamplerSourceOfferDomain  = "dsVert/formal-cox/blockwise/sampler-source-offer/v1"
)

// formalCoxBlockwiseSamplerPublicEnvelope is the relay-safe projection of a
// one-draw worker envelope. WorkerPolicy deliberately remains local to the
// producer: its K-signed public digest and the K custodian signatures are the
// only provenance a recipient needs to verify.
type formalCoxBlockwiseSamplerPublicEnvelope struct {
	Preimage   jointDPBiomedicalGaussianWorkerEnvelopePreimage `json:"preimage"`
	Signatures []jointDPBiomedicalGaussianSignature            `json:"signatures"`
}

// formalCoxBlockwiseSamplerSourceOffer has only opaque ciphertext and signed
// public provenance.  SourceEnvelope is encrypted to RecipientPeerName.
type formalCoxBlockwiseSamplerSourceOffer struct {
	Version              string                                       `json:"version"`
	Purpose              string                                       `json:"purpose"`
	CanonicalArtifactID  string                                       `json:"canonical_artifact_id"`
	DPPlanSHA256         string                                       `json:"dp_plan_sha256"`
	Iteration            int                                          `json:"iteration"`
	RecipientPeerName    string                                       `json:"recipient_peer_name"`
	RecipientPeerID      string                                       `json:"recipient_peer_id"`
	RecipientRole        string                                       `json:"recipient_role"`
	SourceEnvelope       []byte                                       `json:"source_envelope"`
	SourceEnvelopeSHA256 string                                       `json:"source_envelope_sha256"`
	SamplerEnvelope      formalCoxBlockwiseSamplerPublicEnvelope      `json:"sampler_envelope"`
	SamplerReceipt       jointDPBiomedicalGaussianOneDrawChunkReceipt `json:"sampler_receipt"`
	ProductionReady      bool                                         `json:"-"`
	Signature            []byte                                       `json:"signature"`
}

func formalCoxBlockwiseSamplerSourceOfferMessage(
	offer formalCoxBlockwiseSamplerSourceOffer,
) ([]byte, error) {
	offer.Signature = nil
	encoded, err := json.Marshal(offer)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxBlockwiseSamplerSourceOfferDomain+"|"),
		encoded...), nil
}

func formalCoxBlockwiseSamplerSourceOfferLayout(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
) (formalCoxBlockwisePlan, formalCoxBlockwiseSamplerChunkLayout, error) {
	var zero formalCoxBlockwisePlan
	var zeroLayout formalCoxBlockwiseSamplerChunkLayout
	if session == nil || session.context == nil ||
		dpPlan.PolicySHA256 != session.context.plan.PolicySHA256 ||
		dpPlan.Iterations != session.context.plan.Policy.Iterations ||
		dpPlan.CovariateCount != session.context.plan.Policy.CovariateCount ||
		dpPlan.NoiseCoordinates != session.context.plan.Policy.Iterations*
			session.context.plan.Policy.CovariateCount ||
		!dpPlan.PolicyNoiseChunkCountMatches ||
		!dpPlan.PrivacyPlanCertified || !dpPlan.FixedWorkSampler ||
		!dpPlan.NoWrapCertified {
		return zero, zeroLayout,
			fmt.Errorf("formal-cox: sampler source offer DP plan mismatch")
	}
	layout, err := formalCoxBlockwiseSamplerLayout(
		dpPlan.NoiseCoordinates, dpPlan.CovariateCount,
		dpPlan.CommonPlan.MaximumChunkCoordinates)
	if err != nil || layout.chunkCount != dpPlan.SamplerChunkCount ||
		layout.chunkCount != session.context.plan.Policy.NoiseChunkCount {
		return zero, zeroLayout,
			fmt.Errorf("formal-cox: sampler source offer chunk layout mismatch")
	}
	return session.context.plan, layout, nil
}

func formalCoxBlockwiseSamplerSourceOfferTrust(
	session *formalCoxBlockwiseSourceSession,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
) (map[string]ed25519.PublicKey, error) {
	pins, peers, err := jointDPBiomedicalGaussianTrustPins(trust)
	if err != nil || session == nil || session.context == nil ||
		len(peers) != len(session.context.plan.Policy.CustodianPeers) ||
		trust.PinsetSHA256 != session.context.pinsetSHA256 {
		return nil, fmt.Errorf("formal-cox: sampler source offer trust mismatch")
	}
	for index, peer := range session.context.plan.Policy.CustodianPeers {
		if peers[index] != peer || !hmac.Equal(pins[peer], session.context.pins[peer]) {
			return nil, fmt.Errorf("formal-cox: sampler source offer trust mismatch")
		}
	}
	return pins, nil
}

func formalCoxBlockwiseSamplerSourceOfferChunk(
	plan formalCoxBlockwisePlan, layout formalCoxBlockwiseSamplerChunkLayout,
	iteration int,
) (formalCoxBlockwiseWorkerStep, int, int, error) {
	if iteration < 0 || iteration >= plan.Policy.Iterations {
		return formalCoxBlockwiseWorkerStep{}, 0, 0,
			fmt.Errorf("formal-cox: invalid sampler source offer iteration")
	}
	coordinateStart := iteration * plan.Policy.CovariateCount
	chunkIndex := coordinateStart / layout.chunkCoordinates
	chunkStart := chunkIndex * layout.chunkCoordinates
	chunkCount := layout.chunkCoordinates
	if remaining := plan.Policy.Iterations*plan.Policy.CovariateCount -
		chunkStart; chunkCount > remaining {
		chunkCount = remaining
	}
	if coordinateStart < chunkStart ||
		coordinateStart+plan.Policy.CovariateCount > chunkStart+chunkCount {
		return formalCoxBlockwiseWorkerStep{}, 0, 0,
			fmt.Errorf("formal-cox: sampler chunk splits a Cox iteration")
	}
	step, err := formalCoxBlockwiseSourceCanonicalStep(
		plan, formalCoxBlockwiseStepUpdate, iteration)
	if err != nil {
		return formalCoxBlockwiseWorkerStep{}, 0, 0, err
	}
	return step, chunkIndex, coordinateStart - chunkStart, nil
}

func formalCoxBlockwiseSamplerPublicEnvelopeFromLocal(
	envelope jointDPBiomedicalGaussianSignedWorkerEnvelope,
) formalCoxBlockwiseSamplerPublicEnvelope {
	preimage := envelope.Preimage
	preimage.CustodianPeers = append([]string(nil), preimage.CustodianPeers...)
	preimage.CommonLatticeUpperBounds = append(
		[]string(nil), preimage.CommonLatticeUpperBounds...)
	preimage.ReceiptReferences = append(
		[]jointDPBiomedicalGaussianReceiptReference(nil), preimage.ReceiptReferences...)
	public := formalCoxBlockwiseSamplerPublicEnvelope{
		Preimage: preimage,
		Signatures: make([]jointDPBiomedicalGaussianSignature,
			len(envelope.Signatures)),
	}
	for index, signature := range envelope.Signatures {
		public.Signatures[index] = jointDPBiomedicalGaussianSignature{
			Signer: signature.Signer, Signature: append([]byte(nil), signature.Signature...),
		}
	}
	return public
}

// formalCoxBlockwiseValidateSamplerPublicEnvelope validates the part of a
// generic sampler certificate that is deliberately relay-visible. It cannot
// and must not reconstruct WorkerPolicy; Build validates that local policy
// before constructing an offer. Recipients instead require the exact K-signed
// public preimage, then bind its chunk and compute identities to this Cox run.
func formalCoxBlockwiseValidateSamplerPublicEnvelope(
	plan formalCoxBlockwisePlan, dpPlan formalCoxDPPlan,
	session *formalCoxBlockwiseSourceSession,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	chunkIndex int, public formalCoxBlockwiseSamplerPublicEnvelope,
) (jointDPBiomedicalGaussianWorkerEnvelopePreimage, error) {
	var zero jointDPBiomedicalGaussianWorkerEnvelopePreimage
	pins, trustedPeers, err := jointDPBiomedicalGaussianTrustPins(trust)
	if err != nil {
		return zero, err
	}
	preimage := public.Preimage
	// The final chunk can be shorter. The layout is authoritative rather than
	// recomputing with division, which would be wrong for non-dividing caps.
	layout, err := formalCoxBlockwiseSamplerLayout(dpPlan.NoiseCoordinates,
		dpPlan.CovariateCount, dpPlan.CommonPlan.MaximumChunkCoordinates)
	if err != nil {
		return zero, err
	}
	chunkStart := chunkIndex * layout.chunkCoordinates
	chunkCount := layout.chunkCoordinates
	if remaining := dpPlan.NoiseCoordinates - chunkStart; chunkCount > remaining {
		chunkCount = remaining
	}
	if preimage.Version != jointDPBiomedicalGaussianWorkerEnvelopeVersion ||
		preimage.Route != jointDPBiomedicalGaussianWorkerRoute ||
		preimage.PublicIdentifierContract != jointDPBiomedicalGaussianPublicIdentifierRule ||
		preimage.Mechanism != jointDPGaussianOneDrawMechanism ||
		preimage.Allocation != jointDPGaussianOneDrawAllocation ||
		(preimage.Adjacency != "add_remove_patient" &&
			preimage.Adjacency != "replace_one_fixed_cohort") ||
		preimage.PinsetSHA256 != trust.PinsetSHA256 ||
		preimage.WorkerImplementationSHA256 != trust.WorkerImplementationSHA256 ||
		preimage.CustodianCount != len(trustedPeers) ||
		!reflect.DeepEqual(preimage.CustodianPeers, trustedPeers) ||
		preimage.DesignatedComputeCount != 2 ||
		preimage.GarblerPeerName != plan.Policy.ComputePeers[0] ||
		preimage.GarblerPeerID != session.context.peerIDs[plan.Policy.ComputePeers[0]] ||
		preimage.EvaluatorPeerName != plan.Policy.ComputePeers[1] ||
		preimage.EvaluatorPeerID != session.context.peerIDs[plan.Policy.ComputePeers[1]] ||
		preimage.OutputLatticeBits < 1 || preimage.OutputLatticeBits > 62 ||
		preimage.TotalCoordinateCount != dpPlan.NoiseCoordinates ||
		preimage.ChunkStart != chunkStart || preimage.CoordinateCount != chunkCount ||
		preimage.GenericMachineProvenAuthorizes || preimage.SourceShareMayBeUnbound ||
		preimage.OperationLimit || preimage.RequestLimit ||
		preimage.HistoryCanDenyOperation || preimage.OpeningsAuthorized != 0 ||
		preimage.ProductionReady ||
		!reflect.DeepEqual(preimage.Blockers, jointDPBiomedicalGaussianWorkerBlockers) {
		return zero, fmt.Errorf("formal-cox: invalid public sampler envelope")
	}
	message, err := jointDPBiomedicalGaussianWorkerEnvelopeMessage(preimage)
	if err != nil || jointDPBiomedicalGaussianVerifySignatures(
		message, public.Signatures, trustedPeers, pins, "public sampler envelope") != nil {
		return zero, fmt.Errorf("formal-cox: invalid public sampler signatures")
	}
	return preimage, nil
}

// formalCoxBlockwiseBuildSamplerSourceOffer validates one local private
// sampler output, derives exactly one full Cox update from it, and encrypts
// that update to the same compute peer.  It must run before the ciphertext is
// offered to the other role.
func formalCoxBlockwiseBuildSamplerSourceOffer(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot, noiseCenter string,
	recipient string, iteration int,
	samplerEnvelope jointDPBiomedicalGaussianSignedWorkerEnvelope,
	sampler formalCoxRuntimeSamplerRoleChunk, signingKey ed25519.PrivateKey,
) (formalCoxBlockwiseSamplerSourceOffer, error) {
	var zero formalCoxBlockwiseSamplerSourceOffer
	plan, layout, err := formalCoxBlockwiseSamplerSourceOfferLayout(session, dpPlan)
	if err != nil {
		return zero, err
	}
	pins, err := formalCoxBlockwiseSamplerSourceOfferTrust(session, trust)
	if err != nil {
		return zero, err
	}
	role, roleErr := formalCoxBlockwiseSourceRole(plan, recipient)
	if roleErr != nil || len(signingKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(signingKey.Public().(ed25519.PublicKey), pins[recipient]) {
		return zero, fmt.Errorf("formal-cox: invalid sampler source offer signer")
	}
	step, chunkIndex, localStart, err :=
		formalCoxBlockwiseSamplerSourceOfferChunk(plan, layout, iteration)
	if err != nil {
		return zero, err
	}
	spec, err := jointDPBiomedicalGaussianValidateWorkerEnvelope(
		samplerEnvelope, trust)
	if err != nil {
		return zero, fmt.Errorf("formal-cox: sampler source offer worker envelope: %w", err)
	}
	if sampler.EnvelopeIndex != chunkIndex || sampler.Role != role ||
		spec.TotalCoordinateCount != dpPlan.NoiseCoordinates ||
		spec.ChunkStart != chunkIndex*layout.chunkCoordinates ||
		spec.CoordinateCount < plan.Policy.CovariateCount ||
		localStart+plan.Policy.CovariateCount > spec.CoordinateCount {
		return zero, fmt.Errorf("formal-cox: sampler source offer envelope mismatch")
	}
	payload, validity, err := jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
		samplerEnvelope, trust, sampler.OutputReceipt, role,
		sampler.RawOutputShares)
	if err != nil {
		return zero, err
	}
	defer clear(payload)
	if sampler.ValidityShare != (validity == 1) {
		return zero, fmt.Errorf("formal-cox: sampler source offer validity mismatch")
	}
	center, ok := new(big.Int).SetString(noiseCenter, 10)
	if !ok || center.Sign() < 0 {
		return zero, fmt.Errorf("formal-cox: invalid sampler source offer center")
	}
	values := make([]*big.Int, plan.Policy.CovariateCount)
	mask := exactGCMask(128)
	for local := range values {
		value := new(big.Int).Set(sampler.RawOutputShares[localStart+local])
		if role == "garbler" {
			value.Sub(value, center)
			value.And(value, mask)
		}
		values[local] = value
	}
	defer exactGCZeroBigInts(values)
	validityShare := validity == 1
	sourceEnvelope, err := formalCoxBlockwiseSealSourceInput(
		session, recipient, recipient, step, values, &validityShare, signingKey)
	if err != nil {
		return zero, err
	}
	_, envelopeSHA256, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
		session, recipient, sourceEnvelope)
	if err != nil {
		clear(sourceEnvelope)
		return zero, err
	}
	offer := formalCoxBlockwiseSamplerSourceOffer{
		Version:              formalCoxBlockwiseSamplerSourceOfferVersion,
		Purpose:              formalCoxBlockwiseSamplerSourceOfferPurpose,
		CanonicalArtifactID:  session.context.artifactID,
		DPPlanSHA256:         session.context.artifact.DPPlanSHA256,
		Iteration:            iteration,
		RecipientPeerName:    recipient,
		RecipientPeerID:      session.context.peerIDs[recipient],
		RecipientRole:        role,
		SourceEnvelope:       append([]byte(nil), sourceEnvelope...),
		SourceEnvelopeSHA256: envelopeSHA256,
		SamplerEnvelope:      formalCoxBlockwiseSamplerPublicEnvelopeFromLocal(samplerEnvelope),
		SamplerReceipt:       sampler.OutputReceipt,
		ProductionReady:      false,
	}
	offer.SamplerReceipt.Signature = append(
		[]byte(nil), offer.SamplerReceipt.Signature...)
	message, err := formalCoxBlockwiseSamplerSourceOfferMessage(offer)
	if err != nil {
		clear(sourceEnvelope)
		return zero, err
	}
	offer.Signature = ed25519.Sign(signingKey, message)
	clear(sourceEnvelope)
	if err := formalCoxBlockwiseValidateSamplerSourceOffer(
		session, dpPlan, trust, offer); err != nil {
		clear(offer.SourceEnvelope)
		clear(offer.Signature)
		clear(offer.SamplerReceipt.Signature)
		return zero, err
	}
	return offer, nil
}

// formalCoxBlockwiseValidateSamplerSourceOffer verifies public provenance only.
// It never decrypts SourceEnvelope or receives a raw sampler output share.
func formalCoxBlockwiseValidateSamplerSourceOffer(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	offer formalCoxBlockwiseSamplerSourceOffer,
) error {
	plan, layout, err := formalCoxBlockwiseSamplerSourceOfferLayout(session, dpPlan)
	if err != nil {
		return err
	}
	pins, err := formalCoxBlockwiseSamplerSourceOfferTrust(session, trust)
	if err != nil {
		return err
	}
	role, roleErr := formalCoxBlockwiseSourceRole(plan, offer.RecipientPeerName)
	message, messageErr := formalCoxBlockwiseSamplerSourceOfferMessage(offer)
	if roleErr != nil || messageErr != nil ||
		offer.Version != formalCoxBlockwiseSamplerSourceOfferVersion ||
		offer.Purpose != formalCoxBlockwiseSamplerSourceOfferPurpose ||
		offer.CanonicalArtifactID != session.context.artifactID ||
		offer.DPPlanSHA256 != session.context.artifact.DPPlanSHA256 ||
		offer.ProductionReady || role != offer.RecipientRole ||
		offer.RecipientPeerID != session.context.peerIDs[offer.RecipientPeerName] ||
		len(offer.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[offer.RecipientPeerName], message, offer.Signature) {
		return fmt.Errorf("formal-cox: invalid sampler source offer")
	}
	step, chunkIndex, _, err := formalCoxBlockwiseSamplerSourceOfferChunk(
		plan, layout, offer.Iteration)
	if err != nil {
		return err
	}
	preimage, err := formalCoxBlockwiseValidateSamplerPublicEnvelope(
		plan, dpPlan, session, trust, chunkIndex, offer.SamplerEnvelope)
	if err != nil {
		return fmt.Errorf("formal-cox: sampler source offer public envelope: %w", err)
	}
	preimageSHA256, err := jointDPBiomedicalGaussianEnvelopePreimageSHA256(
		preimage)
	receiptMessage, receiptErr :=
		jointDPBiomedicalGaussianOneDrawChunkReceiptMessage(offer.SamplerReceipt)
	if err != nil || receiptErr != nil ||
		offer.SamplerReceipt.EnvelopePreimageSHA256 != preimageSHA256 ||
		offer.SamplerReceipt.PeerName != offer.RecipientPeerName ||
		offer.SamplerReceipt.PeerID != offer.RecipientPeerID ||
		offer.SamplerReceipt.Role != offer.RecipientRole ||
		offer.SamplerReceipt.TotalCoordinateCount != preimage.TotalCoordinateCount ||
		offer.SamplerReceipt.ChunkStart != preimage.ChunkStart ||
		offer.SamplerReceipt.CoordinateCount != preimage.CoordinateCount ||
		len(offer.SamplerReceipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[offer.RecipientPeerName], receiptMessage,
			offer.SamplerReceipt.Signature) {
		return fmt.Errorf("formal-cox: invalid sampler source offer receipt")
	}
	sourceEnvelope, envelopeSHA256, err := formalCoxBlockwiseSourceValidatePublicEnvelope(
		session, offer.RecipientPeerName, offer.SourceEnvelope)
	if err != nil || envelopeSHA256 != offer.SourceEnvelopeSHA256 ||
		sourceEnvelope.Header.SourcePeerName != offer.RecipientPeerName ||
		sourceEnvelope.Header.StepKind != formalCoxBlockwiseStepUpdate ||
		sourceEnvelope.Header.CanonicalScheduleIndex != step.ScheduleIndex ||
		sourceEnvelope.Header.Iteration != offer.Iteration ||
		!sourceEnvelope.Header.HasValidityShare ||
		sourceEnvelope.Header.CoordinateCount != plan.Policy.CovariateCount {
		return fmt.Errorf("formal-cox: sampler source offer ciphertext mismatch")
	}
	return nil
}

func formalCoxBlockwiseSamplerSourceOfferSHA256(
	offer formalCoxBlockwiseSamplerSourceOffer,
) (string, error) {
	encoded, err := json.Marshal(offer)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSamplerSourceOfferDomain+"/commitment|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseSamplerSourceOfferCommitmentRoot(
	commitments []formalCoxBlockwiseSamplerSourceOfferCommitment,
) (string, error) {
	if len(commitments) != 2 {
		return "", fmt.Errorf("formal-cox: invalid sampler offer commitment count")
	}
	encoded, err := json.Marshal(commitments)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalCoxBlockwiseSamplerSourceOfferDomain+"/barrier-root|"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxBlockwiseSamplerSourceOfferCommitments(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	offers []formalCoxBlockwiseSamplerSourceOffer,
) ([]formalCoxBlockwiseSamplerSourceOfferCommitment, error) {
	if session == nil || session.context == nil || len(offers) != 2 {
		return nil, fmt.Errorf("formal-cox: invalid sampler offers")
	}
	commitments := make([]formalCoxBlockwiseSamplerSourceOfferCommitment, 2)
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		offer := offers[index]
		if offer.RecipientPeerName != recipient ||
			formalCoxBlockwiseValidateSamplerSourceOffer(
				session, dpPlan, trust, offer) != nil {
			return nil, fmt.Errorf("formal-cox: invalid sampler offer commitment")
		}
		offerSHA256, err := formalCoxBlockwiseSamplerSourceOfferSHA256(offer)
		if err != nil {
			return nil, err
		}
		preimageSHA256, err := jointDPBiomedicalGaussianEnvelopePreimageSHA256(
			offer.SamplerEnvelope.Preimage)
		if err != nil {
			return nil, err
		}
		commitments[index] = formalCoxBlockwiseSamplerSourceOfferCommitment{
			RecipientPeerName:      offer.RecipientPeerName,
			RecipientPeerID:        offer.RecipientPeerID,
			RecipientRole:          offer.RecipientRole,
			SourceEnvelopeSHA256:   offer.SourceEnvelopeSHA256,
			SamplerOfferSHA256:     offerSHA256,
			EnvelopePreimageSHA256: preimageSHA256,
		}
	}
	return commitments, nil
}

// formalCoxBlockwiseNewGuardedSamplerSourceOfferBarrier couples the existing
// sticky sampler contract to the exact two authenticated sampler offers. The
// commitments become part of the existing barrier root and approvals.
func formalCoxBlockwiseNewGuardedSamplerSourceOfferBarrier(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	step formalCoxBlockwiseWorkerStep, offers []formalCoxBlockwiseSamplerSourceOffer,
	contract formalCoxBlockwiseSamplerContract,
	authorizations []formalCoxBlockwiseSamplerAuthorization,
) (formalCoxBlockwiseNoiseBarrier, error) {
	var zero formalCoxBlockwiseNoiseBarrier
	commitments, err := formalCoxBlockwiseSamplerSourceOfferCommitments(
		session, dpPlan, trust, offers)
	if err != nil {
		return zero, err
	}
	encoded := make([][]byte, len(offers))
	for index := range offers {
		encoded[index] = offers[index].SourceEnvelope
	}
	barrier, err := formalCoxBlockwiseNewGuardedNoiseBarrier(
		session, step, encoded, contract, authorizations)
	if err != nil {
		return zero, err
	}
	barrier.SamplerOfferCommitments = commitments
	barrier.SamplerOfferRootSHA256, err =
		formalCoxBlockwiseSamplerSourceOfferCommitmentRoot(commitments)
	if err != nil {
		return zero, err
	}
	barrier.PairedNoiseRootSHA256, err = formalCoxBlockwiseNoiseBarrierRoot(barrier)
	if err != nil || formalCoxBlockwiseValidateNoiseBarrierCore(session, barrier) != nil {
		return zero, fmt.Errorf("formal-cox: invalid guarded sampler offer barrier")
	}
	return barrier, nil
}

func formalCoxBlockwiseValidateSamplerSourceOfferBarrier(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	barrier formalCoxBlockwiseNoiseBarrier,
	offers []formalCoxBlockwiseSamplerSourceOffer,
) error {
	if err := formalCoxBlockwiseValidateNoiseBarrierCore(session, barrier); err != nil {
		return err
	}
	commitments, err := formalCoxBlockwiseSamplerSourceOfferCommitments(
		session, dpPlan, trust, offers)
	if err != nil || !reflect.DeepEqual(commitments, barrier.SamplerOfferCommitments) {
		return fmt.Errorf("formal-cox: sampler offers do not match their barrier")
	}
	root, err := formalCoxBlockwiseSamplerSourceOfferCommitmentRoot(commitments)
	if err != nil || root != barrier.SamplerOfferRootSHA256 {
		return fmt.Errorf("formal-cox: sampler offer barrier root mismatch")
	}
	return nil
}

func formalCoxBlockwiseSignGuardedSamplerSourceOfferBarrier(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	barrier formalCoxBlockwiseNoiseBarrier,
	offers []formalCoxBlockwiseSamplerSourceOffer,
	contract formalCoxBlockwiseSamplerContract,
	authorizations []formalCoxBlockwiseSamplerAuthorization,
	signer string, signingKey ed25519.PrivateKey,
) (formalCoxBlockwiseNoiseApproval, error) {
	var zero formalCoxBlockwiseNoiseApproval
	if session == nil || session.context == nil {
		return zero, fmt.Errorf("formal-cox: invalid guarded sampler offer signer")
	}
	step, err := formalCoxBlockwiseWorkerStepAt(
		session.context.plan, barrier.CanonicalScheduleIndex)
	if err != nil {
		return zero, err
	}
	want, err := formalCoxBlockwiseNewGuardedSamplerSourceOfferBarrier(
		session, dpPlan, trust, step, offers, contract, authorizations)
	if err != nil {
		return zero, err
	}
	wantEncoded, wantErr := json.Marshal(want)
	barrierEncoded, barrierErr := json.Marshal(barrier)
	if wantErr != nil || barrierErr != nil || len(barrier.Approvals) != 0 ||
		!bytes.Equal(wantEncoded, barrierEncoded) ||
		len(signingKey) != ed25519.PrivateKeySize ||
		session.context.roles[signer] == "" ||
		!hmac.Equal(signingKey.Public().(ed25519.PublicKey),
			session.context.pins[signer]) {
		return zero, fmt.Errorf("formal-cox: invalid guarded sampler offer signer")
	}
	message, err := formalCoxBlockwiseNoiseBarrierMessage(barrier)
	if err != nil {
		return zero, err
	}
	return formalCoxBlockwiseNoiseApproval{
		SignerPeerName: signer, SignerPeerID: session.context.peerIDs[signer],
		SignerRole: session.context.roles[signer],
		Signature:  ed25519.Sign(signingKey, message),
	}, nil
}

func formalCoxBlockwiseValidateGuardedSamplerSourceOfferBinding(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	offers []formalCoxBlockwiseSamplerSourceOffer, encoded []byte,
) error {
	var binding formalCoxBlockwiseGuardedNoiseBarrier
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseSourceBindingMax, "guarded sampler offer binding", &binding); err != nil {
		return err
	}
	if err := formalCoxBlockwiseValidateGuardedNoiseBarrier(session, binding); err != nil {
		return err
	}
	return formalCoxBlockwiseValidateSamplerSourceOfferBarrier(
		session, dpPlan, trust, binding.Barrier, offers)
}

func formalCoxBlockwiseFinalizeGuardedSamplerSourceOfferBarrier(
	session *formalCoxBlockwiseSourceSession, dpPlan formalCoxDPPlan,
	trust jointDPBiomedicalGaussianWorkerTrustRoot,
	offers []formalCoxBlockwiseSamplerSourceOffer,
	contract formalCoxBlockwiseSamplerContract,
	authorizations []formalCoxBlockwiseSamplerAuthorization,
	barrier formalCoxBlockwiseNoiseBarrier,
	approvals []formalCoxBlockwiseNoiseApproval,
) ([]byte, error) {
	if session == nil || session.context == nil {
		return nil, fmt.Errorf("formal-cox: invalid guarded sampler offer finalizer")
	}
	step, err := formalCoxBlockwiseWorkerStepAt(
		session.context.plan, barrier.CanonicalScheduleIndex)
	if err != nil {
		return nil, err
	}
	want, err := formalCoxBlockwiseNewGuardedSamplerSourceOfferBarrier(
		session, dpPlan, trust, step, offers, contract, authorizations)
	if err != nil {
		return nil, err
	}
	wantEncoded, wantErr := json.Marshal(want)
	barrierEncoded, barrierErr := json.Marshal(barrier)
	if wantErr != nil || barrierErr != nil || len(barrier.Approvals) != 0 ||
		!bytes.Equal(wantEncoded, barrierEncoded) {
		return nil, fmt.Errorf("formal-cox: invalid guarded sampler offer barrier")
	}
	encoded, err := formalCoxBlockwiseFinalizeGuardedNoiseBarrier(
		session, contract, authorizations, barrier, approvals)
	if err != nil {
		return nil, err
	}
	if err := formalCoxBlockwiseValidateGuardedSamplerSourceOfferBinding(
		session, dpPlan, trust, offers, encoded); err != nil {
		clear(encoded)
		return nil, err
	}
	return encoded, nil
}
