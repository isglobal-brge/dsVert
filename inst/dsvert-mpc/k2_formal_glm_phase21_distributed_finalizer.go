package main

// Typed, encrypted transport for one formal-GLM one-draw output. The private
// Ring128 shares are serializable only inside the recipient-bound handoff
// envelope; the public transport header contains only canonical digests.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
)

type formalGLMPhase21OneDrawTransitBody struct {
	Version string                                       `json:"version"`
	Receipt jointDPBiomedicalGaussianOneDrawChunkReceipt `json:"receipt"`
	Shares  []string                                     `json:"shares"`
}

type formalGLMPhase21OneDrawTransitPayload struct {
	Version             string                             `json:"version"`
	Purpose             string                             `json:"purpose"`
	ArtifactID          string                             `json:"artifact_id"`
	PlanSHA256          string                             `json:"plan_sha256"`
	FinalPairRootSHA256 string                             `json:"final_pair_root_sha256"`
	TicketSHA256        string                             `json:"ticket_sha256"`
	SenderPeerName      string                             `json:"sender_peer_name"`
	SenderPeerID        string                             `json:"sender_peer_id"`
	SenderRole          string                             `json:"sender_role"`
	OneDraw             formalGLMPhase21OneDrawTransitBody `json:"one_draw"`
	ProductionReady     bool                               `json:"-"`
}

func formalGLMPhase21ClearOneDrawTransit(
	payload *formalGLMPhase21OneDrawTransitPayload,
) {
	if payload == nil {
		return
	}
	for index := range payload.OneDraw.Shares {
		payload.OneDraw.Shares[index] = ""
	}
	payload.OneDraw.Shares = nil
}

func formalGLMPhase21MarshalOneDrawTransitCanonical(
	payload formalGLMPhase21OneDrawTransitPayload,
) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func formalGLMPhase21DecodeOneDrawTransitCanonical(encoded []byte,
	payload *formalGLMPhase21OneDrawTransitPayload,
) error {
	if payload == nil || formalFinalizerHandoffCanonicalObject(
		encoded, formalFinalizerHandoffMaxPayload) != nil {
		return fmt.Errorf("formal-glm: invalid canonical one-draw transit")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(payload); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-glm: trailing one-draw transit")
	}
	return nil
}

func formalGLMPhase21DecodeOneDrawTransitShares(values []string,
	coordinateCount int,
) ([]*big.Int, error) {
	if coordinateCount < 1 || len(values) != coordinateCount+1 {
		return nil, fmt.Errorf("formal-glm: invalid one-draw transit shape")
	}
	shares := make([]*big.Int, len(values))
	for index, value := range values {
		parsed, err := jointDPBiomedicalGaussianParseCanonicalInt(
			value, "one-draw transit Ring128 share", false)
		maximumBits := 128
		if index == coordinateCount {
			maximumBits = 1
		}
		if err != nil || parsed.Sign() < 0 || parsed.BitLen() > maximumBits {
			exactGCZeroBigInts(shares)
			return nil, fmt.Errorf("formal-glm: invalid exact one-draw transit share")
		}
		shares[index] = parsed
	}
	return shares, nil
}

func formalGLMPhase21OneDrawFinalizerBinding(
	store *formalGLMPhase20HandoffStore,
	output formalGLMPhase21OneDrawLocalOutput,
) (formalFinalizerHandoffBinding, error) {
	var zero formalFinalizerHandoffBinding
	if err := formalGLMPhase21ValidateLocalOutputSource(store, output); err != nil {
		return zero, err
	}
	source, _, err := store.Load()
	if err != nil {
		return zero, err
	}
	defer source.clear()
	binding := output.Admission.Compiled.Binding
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		binding, source.Plan, store.pins)
	if err != nil {
		return zero, err
	}
	if len(artifact.NoiseAuthorities) != 2 {
		return zero, fmt.Errorf("formal-glm: invalid distributed one-draw authorities")
	}
	if !formalGLMIsSHA256(output.Admission.Token.ExecutionReceiptPairSHA256) {
		return zero, fmt.Errorf("formal-glm: missing distributed execution pair root")
	}
	if !formalGLMIsSHA256(output.Receipt.PlanSHA256) {
		return zero, fmt.Errorf("formal-glm: missing distributed one-draw release plan")
	}
	authorities := make([]formalFinalizerHandoffAuthority, 2)
	for index, authority := range artifact.NoiseAuthorities {
		authorities[index] = formalFinalizerHandoffAuthority{
			PeerName: authority.PeerName,
			PeerID:   authority.PeerID,
			Role:     authority.Role,
		}
	}
	result := formalFinalizerHandoffBinding{
		Family:              formalFinalizerHandoffFamilyGLM,
		Purpose:             formalFinalizerHandoffGLMPurpose,
		ArtifactID:          artifactID,
		FinalPairRootSHA256: output.Admission.Token.ExecutionReceiptPairSHA256,
		PlanSHA256:          output.Receipt.PlanSHA256,
		PinsetSHA256:        artifact.PinsetSHA256,
		Authorities:         authorities,
		Finalizer:           authorities[0],
	}
	if err := formalFinalizerHandoffValidateBinding(result, store.pins); err != nil {
		return zero, err
	}
	return result, nil
}

func formalGLMPhase21RegisteredOneDrawFinalizerBinding(
	store *formalGLMPhase20HandoffStore,
	output formalGLMPhase21OneDrawLocalOutput,
	contract formalGLMPhase21SamplerV2Contract,
	resolution formalGLMArtifactRegistryResolutionV1,
) (formalFinalizerHandoffBinding, error) {
	var zero formalFinalizerHandoffBinding
	binding, err := formalGLMPhase21OneDrawFinalizerBinding(store, output)
	if err != nil {
		return zero, err
	}
	source, _, err := store.Load()
	if err != nil {
		return zero, err
	}
	defer source.clear()
	legacy, _, err := formalGLMPhase21BuildCanonicalArtifact(
		output.Admission.Compiled.Binding, source.Plan, store.pins)
	if err != nil {
		return zero, err
	}
	registered, artifactID, err := formalGLMPhase21ProjectRegisteredArtifactV1(
		legacy, contract.Artifact, resolution, store.pins)
	if err != nil || artifactID != contract.ArtifactID ||
		!reflect.DeepEqual(registered, contract.Artifact) {
		return zero, fmt.Errorf(
			"formal-glm: invalid registered finalizer binding")
	}
	binding.ArtifactID = artifactID
	if err := formalFinalizerHandoffValidateBinding(binding, store.pins); err != nil {
		return zero, err
	}
	return binding, nil
}

func formalGLMPhase21ValidateOneDrawTransit(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	payload formalGLMPhase21OneDrawTransitPayload,
	pins map[string]ed25519.PublicKey,
) error {
	if formalFinalizerHandoffValidateTicket(ticket, binding, pins) != nil ||
		binding.Family != formalFinalizerHandoffFamilyGLM ||
		binding.Purpose != formalFinalizerHandoffGLMPurpose ||
		payload.ProductionReady {
		return fmt.Errorf("formal-glm: invalid typed one-draw transit binding")
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return err
	}
	authority, err := formalFinalizerHandoffPeer(binding, payload.SenderRole)
	receipt := payload.OneDraw.Receipt
	message, messageErr := jointDPBiomedicalGaussianOneDrawChunkReceiptMessage(
		receipt)
	if err != nil || messageErr != nil ||
		payload.Version != formalFinalizerHandoffGLMOneDrawPayloadVersion ||
		payload.Purpose != binding.Purpose ||
		payload.ArtifactID != binding.ArtifactID ||
		payload.PlanSHA256 != binding.PlanSHA256 ||
		payload.FinalPairRootSHA256 != binding.FinalPairRootSHA256 ||
		payload.TicketSHA256 != ticketSHA ||
		payload.SenderPeerName != authority.PeerName ||
		payload.SenderPeerID != authority.PeerID ||
		payload.OneDraw.Version != formalGLMPhase21BoundReleaseVersion ||
		receipt.PeerName != authority.PeerName ||
		receipt.PeerID != authority.PeerID || receipt.Role != authority.Role ||
		receipt.PlanSHA256 != binding.PlanSHA256 || receipt.ChunkStart != 0 ||
		receipt.CoordinateCount != receipt.TotalCoordinateCount ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pins[authority.PeerName], message, receipt.Signature) {
		return fmt.Errorf("formal-glm: typed one-draw receipt mismatch")
	}
	shares, err := formalGLMPhase21DecodeOneDrawTransitShares(
		payload.OneDraw.Shares, receipt.CoordinateCount)
	if err != nil {
		return err
	}
	defer exactGCZeroBigInts(shares)
	encoded, validity, err := jointDPBiomedicalGaussianOneDrawEncodeOutputShares(
		shares, receipt.CoordinateCount)
	if err != nil {
		return err
	}
	defer clear(encoded)
	want, err := jointDPBiomedicalGaussianOneDrawOutputShareSHA256(
		receipt.EnvelopePreimageSHA256, receipt.Role, encoded, validity)
	if err != nil || want != receipt.OutputShareSHA256 {
		return fmt.Errorf("formal-glm: typed one-draw share digest mismatch")
	}
	return nil
}

func formalGLMPhase21BuildOneDrawTransit(
	store *formalGLMPhase20HandoffStore,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	output formalGLMPhase21OneDrawLocalOutput,
) (formalGLMPhase21OneDrawTransitPayload, error) {
	return formalGLMPhase21BuildOneDrawTransitWithResolution(
		store, binding, ticket, output, nil, nil)
}

func formalGLMPhase21BuildOneDrawTransitWithResolution(
	store *formalGLMPhase20HandoffStore,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	output formalGLMPhase21OneDrawLocalOutput,
	contract *formalGLMPhase21SamplerV2Contract,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (formalGLMPhase21OneDrawTransitPayload, error) {
	var zero formalGLMPhase21OneDrawTransitPayload
	var wantBinding formalFinalizerHandoffBinding
	var err error
	if contract != nil && contract.Artifact.DescriptorCoreSHA256 != "" &&
		resolution != nil {
		wantBinding, err = formalGLMPhase21RegisteredOneDrawFinalizerBinding(
			store, output, *contract, *resolution)
	} else if contract == nil && resolution == nil {
		wantBinding, err = formalGLMPhase21OneDrawFinalizerBinding(store, output)
	} else if contract != nil &&
		contract.Artifact.DescriptorCoreSHA256 == "" && resolution == nil {
		wantBinding, err = formalGLMPhase21OneDrawFinalizerBinding(store, output)
		if err == nil && (formalGLMPhase21ValidateSamplerV2Contract(
			*contract, store.pins) != nil ||
			wantBinding.ArtifactID != contract.ArtifactID) {
			err = fmt.Errorf("formal-glm: broad transit contract mismatch")
		}
	} else {
		err = fmt.Errorf("formal-glm: invalid transit registry resolution")
	}
	if err != nil || !reflect.DeepEqual(wantBinding, binding) ||
		formalFinalizerHandoffValidateTicket(ticket, binding, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm: distributed one-draw binding mismatch")
	}
	shares := make([]string, len(output.Shares))
	for index, share := range output.Shares {
		if share == nil {
			return zero, fmt.Errorf("formal-glm: nil one-draw transit share")
		}
		shares[index] = share.String()
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	payload := formalGLMPhase21OneDrawTransitPayload{
		Version:             formalFinalizerHandoffGLMOneDrawPayloadVersion,
		Purpose:             binding.Purpose,
		ArtifactID:          binding.ArtifactID,
		PlanSHA256:          binding.PlanSHA256,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		TicketSHA256:        ticketSHA,
		SenderPeerName:      output.Peer,
		SenderPeerID:        output.Receipt.PeerID,
		SenderRole:          output.Role,
		OneDraw: formalGLMPhase21OneDrawTransitBody{
			Version: formalGLMPhase21BoundReleaseVersion,
			Receipt: output.Receipt,
			Shares:  shares,
		},
		ProductionReady: false,
	}
	if err := formalGLMPhase21ValidateOneDrawTransit(
		binding, ticket, payload, store.pins); err != nil {
		formalGLMPhase21ClearOneDrawTransit(&payload)
		return zero, err
	}
	return payload, nil
}

func formalFinalizerHandoffSealGLMOneDraw(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	payload formalGLMPhase21OneDrawTransitPayload,
	signingKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (formalFinalizerHandoffEnvelope, error) {
	var zero formalFinalizerHandoffEnvelope
	if err := formalGLMPhase21ValidateOneDrawTransit(
		binding, ticket, payload, pins); err != nil {
		return zero, err
	}
	encoded, err := formalGLMPhase21MarshalOneDrawTransitCanonical(payload)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	return formalFinalizerHandoffSealCanonical(
		binding, ticket, payload.SenderPeerName,
		formalFinalizerHandoffGLMOneDrawKind, encoded, signingKey, pins)
}

func formalFinalizerHandoffOpenGLMOneDraw(
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	envelope formalFinalizerHandoffEnvelope,
	recipientSecret []byte,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21OneDrawTransitPayload, error) {
	var zero formalGLMPhase21OneDrawTransitPayload
	encoded, err := formalFinalizerHandoffOpenCanonical(
		binding, ticket, envelope, recipientSecret, pins)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var payload formalGLMPhase21OneDrawTransitPayload
	if err := formalGLMPhase21DecodeOneDrawTransitCanonical(
		encoded, &payload); err != nil {
		return zero, err
	}
	if err := formalGLMPhase21ValidateOneDrawTransit(
		binding, ticket, payload, pins); err != nil {
		formalGLMPhase21ClearOneDrawTransit(&payload)
		return zero, err
	}
	return payload, nil
}

func formalGLMPhase21ImportOneDrawTransit(
	store *formalGLMPhase20HandoffStore,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	payload formalGLMPhase21OneDrawTransitPayload,
) (formalGLMPhase21OneDrawLocalOutput, error) {
	return formalGLMPhase21ImportOneDrawTransitWithResolution(
		store, capsule, request, backendSignatures, workerSignatures,
		binding, ticket, payload, nil, nil)
}

func formalGLMPhase21ImportOneDrawTransitWithResolution(
	store *formalGLMPhase20HandoffStore,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	binding formalFinalizerHandoffBinding,
	ticket formalFinalizerHandoffTicket,
	payload formalGLMPhase21OneDrawTransitPayload,
	contract *formalGLMPhase21SamplerV2Contract,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (formalGLMPhase21OneDrawLocalOutput, error) {
	var zero formalGLMPhase21OneDrawLocalOutput
	if store == nil || formalGLMPhase21ValidateOneDrawTransit(
		binding, ticket, payload, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm: invalid one-draw transit import")
	}
	runtime, commit, err := formalGLMPhase21LoadAndAdmit(
		store, capsule, request, backendSignatures, workerSignatures)
	if err != nil {
		return zero, err
	}
	defer runtime.clear()
	artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
		runtime.Admission.Productive.Compiled.Binding,
		runtime.Source.Plan, store.pins)
	if err == nil && contract != nil {
		if formalGLMPhase21ValidateSamplerV2Contract(
			*contract, store.pins) != nil ||
			contract.ArtifactID != binding.ArtifactID {
			return zero, fmt.Errorf(
				"formal-glm: transit import contract mismatch")
		}
		if contract.Artifact.DescriptorCoreSHA256 != "" {
			if resolution == nil {
				return zero, fmt.Errorf(
					"formal-glm: registered transit lacks registry resolution")
			}
			artifact, artifactID, err = formalGLMPhase21ProjectRegisteredArtifactV1(
				artifact, contract.Artifact, *resolution, store.pins)
		} else if resolution != nil {
			return zero, fmt.Errorf(
				"formal-glm: broad transit cannot use registry resolution")
		} else if !reflect.DeepEqual(artifact, contract.Artifact) ||
			artifactID != contract.ArtifactID {
			return zero, fmt.Errorf(
				"formal-glm: transit import contract artifact changed")
		}
	} else if err == nil && resolution != nil {
		return zero, fmt.Errorf(
			"formal-glm: transit resolution lacks exact contract")
	}
	if err != nil || artifactID != binding.ArtifactID ||
		artifact.PinsetSHA256 != binding.PinsetSHA256 ||
		runtime.Admission.Productive.Token.ExecutionReceiptPairSHA256 !=
			binding.FinalPairRootSHA256 {
		return zero, fmt.Errorf("formal-glm: transit import targets another artifact")
	}
	shares, err := formalGLMPhase21DecodeOneDrawTransitShares(
		payload.OneDraw.Shares, payload.OneDraw.Receipt.CoordinateCount)
	if err != nil {
		return zero, err
	}
	if encoded, _, receiptErr :=
		jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
			runtime.Admission.Productive.Envelope,
			runtime.Admission.Productive.Trust, payload.OneDraw.Receipt,
			payload.SenderRole, shares); receiptErr != nil {
		clear(encoded)
		exactGCZeroBigInts(shares)
		return zero, receiptErr
	} else {
		clear(encoded)
	}
	output := formalGLMPhase21OneDrawLocalOutput{
		Version:       formalGLMPhase21BoundReleaseVersion,
		Peer:          payload.SenderPeerName,
		Role:          payload.SenderRole,
		Admission:     runtime.Admission.Productive,
		Receipt:       payload.OneDraw.Receipt,
		Shares:        shares,
		HandoffSHA256: commit.SHA256,
		HandoffBytes:  commit.Bytes,
	}
	if output.Peer == store.peer {
		_, _, role, _, sourceBinding, sourceErr :=
			formalGLMPhase21SourceMaterial(runtime)
		if sourceErr != nil || role != output.Role {
			output.clear()
			return zero, fmt.Errorf("formal-glm: local transit source changed")
		}
		output.capsule = capsule
		output.request = request
		output.sourceBindingSHA = sourceBinding.BindingSHA256
	}
	return output, nil
}

func formalGLMPhase21OneDrawUnsignedCandidateValid(
	local formalGLMPhase21OneDrawLocalOutput,
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
) (jointDPBiomedicalGaussianOneDrawAuthority, error) {
	var zero jointDPBiomedicalGaussianOneDrawAuthority
	authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
		[]jointDPBiomedicalGaussianSignedWorkerEnvelope{local.Admission.Envelope},
		local.Admission.Trust)
	if err != nil {
		return zero, err
	}
	if _, err := jointDPBiomedicalGaussianOneDrawCommonReleaseMessage(
		candidate); err != nil ||
		!reflect.DeepEqual(candidate.DesignatedComputePeers,
			authority.computePeers) {
		return zero, fmt.Errorf("formal-glm: invalid unsigned one-draw candidate")
	}
	probe := jointDPBiomedicalGaussianOneDrawLocalReleaseReceipt{
		ReleaseInstanceID:              candidate.ReleaseInstanceID,
		ReleaseContractSHA256:          candidate.ReleaseContractSHA256,
		ProductiveStreamSHA256:         candidate.ProductiveStreamSHA256,
		PlanSHA256:                     candidate.PlanSHA256,
		CoordinateOrderSHA256:          candidate.CoordinateOrderSHA256,
		LedgerReservationSHA256:        candidate.LedgerReservationSHA256,
		FinalizerReservationSHA256:     candidate.FinalizerReservationSHA256,
		OutputLatticeBits:              candidate.OutputLatticeBits,
		Epsilon:                        candidate.Epsilon,
		Delta:                          candidate.Delta,
		CoreDeltaNumerator:             candidate.CoreDeltaNumerator,
		CoreDeltaDenominator:           candidate.CoreDeltaDenominator,
		VectorTailTVUpperNumerator:     candidate.VectorTailTVUpperNumerator,
		VectorTailTVUpperDenominator:   candidate.VectorTailTVUpperDenominator,
		VectorCDFTVUpperNumerator:      candidate.VectorCDFTVUpperNumerator,
		VectorCDFTVUpperDenominator:    candidate.VectorCDFTVUpperDenominator,
		VectorTotalTVUpperNumerator:    candidate.VectorTotalTVUpperNumerator,
		VectorTotalTVUpperDenominator:  candidate.VectorTotalTVUpperDenominator,
		ImplementationDeltaNumerator:   candidate.ImplementationDeltaNumerator,
		ImplementationDeltaDenominator: candidate.ImplementationDeltaDenominator,
		Cost:                           candidate.Cost,
	}
	if !jointDPBiomedicalGaussianOneDrawReleaseMatchesAuthority(
		authority, probe) ||
		jointDPBiomedicalGaussianValidateOneDrawReleasedVector(
			authority, candidate.VectorSHA256,
			candidate.ClampedScaledValues) != nil {
		return zero, fmt.Errorf("formal-glm: one-draw candidate changed authority")
	}
	return authority, nil
}

// VerifyOneDrawCandidateAgainstLocal proves that the complete candidate and
// this authority's exact Ring128 share imply the opposite signed output
// digest. The authority therefore never signs solely on finalizer trust.
func formalGLMPhase21VerifyOneDrawCandidateAgainstLocal(
	store *formalGLMPhase20HandoffStore,
	local formalGLMPhase21OneDrawLocalOutput,
	opposite jointDPBiomedicalGaussianOneDrawChunkReceipt,
	candidate jointDPBiomedicalGaussianOneDrawCommonRelease,
) error {
	if err := formalGLMPhase21ValidateLocalOutputSource(store, local); err != nil {
		return err
	}
	_, err := formalGLMPhase21OneDrawUnsignedCandidateValid(local, candidate)
	if err != nil || local.Receipt.ChunkStart != 0 ||
		local.Receipt.CoordinateCount != local.Receipt.TotalCoordinateCount ||
		len(candidate.ClampedScaledValues) != local.Receipt.CoordinateCount {
		return fmt.Errorf("formal-glm: unverifiable one-draw candidate shape")
	}
	localPayload, localValidity, err :=
		jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
			local.Admission.Envelope, local.Admission.Trust,
			local.Receipt, local.Role, local.Shares)
	if err != nil {
		clear(localPayload)
		return err
	}
	clear(localPayload)
	oppositeRole := "garbler"
	if local.Role == "garbler" {
		oppositeRole = "evaluator"
	} else if local.Role != "evaluator" {
		return fmt.Errorf("formal-glm: invalid local one-draw authority role")
	}
	mask := exactGCMask(128)
	implied := make([]*big.Int, local.Receipt.CoordinateCount+1)
	for index, value := range candidate.ClampedScaledValues {
		parsed, parseErr := jointDPBiomedicalGaussianParseCanonicalInt(
			value, "one-draw candidate Ring128 coordinate", false)
		if parseErr != nil || parsed.BitLen() > 128 ||
			local.Shares[index] == nil || local.Shares[index].BitLen() > 128 {
			exactGCZeroBigInts(implied)
			return fmt.Errorf("formal-glm: invalid candidate Ring128 coordinate")
		}
		implied[index] = new(big.Int).Sub(parsed, local.Shares[index])
		implied[index].And(implied[index], mask)
	}
	implied[len(implied)-1] = new(big.Int).SetUint64(
		uint64(localValidity ^ 1))
	defer exactGCZeroBigInts(implied)
	encoded, _, err := jointDPBiomedicalGaussianValidateOneDrawChunkReceipt(
		local.Admission.Envelope, local.Admission.Trust,
		opposite, oppositeRole, implied)
	clear(encoded)
	if err != nil {
		return fmt.Errorf("formal-glm: candidate does not imply opposite signed share")
	}
	return nil
}
