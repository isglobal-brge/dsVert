package main

// Server-local bridge from the recipient-specific Phase-1.8/1.9 fan-in to the
// scalable biomedical Gaussian worker.  It deliberately registers no command:
// the analyst can relay encrypted frames and public receipts, but cannot mint
// this bridge, replace its local source share, or authorize an opening.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
)

const (
	jointDPBiomedicalGaussianFullPhase19SourceVersion  = "dsvert-biomedical-gaussian-independent-full-phase19-source-v1"
	jointDPBiomedicalGaussianFullPhase19SourceDomain   = "dsVert/biomedical-gaussian/independent-full/phase19-source/v1"
	jointDPBiomedicalGaussianFullPhase19PeerVersion    = "dsvert-biomedical-gaussian-independent-full-phase19-peer-share-v1"
	jointDPBiomedicalGaussianFullPhase19PeerDomain     = "dsVert/biomedical-gaussian/independent-full/phase19-peer-share/v1"
	jointDPBiomedicalGaussianFullPhase19HandoffVersion = "dsvert-biomedical-gaussian-independent-full-phase19-finalizer-handoff-v1"
	jointDPBiomedicalGaussianFullPhase19HandoffDomain  = "dsVert/biomedical-gaussian/independent-full/phase19-finalizer-handoff/v1"
)

var jointDPBiomedicalGaussianFullPhase19HandoffBlockers = []string{
	"durable_append_before_release_record_not_yet_committed",
	"paired_common_dp_vector_not_yet_durable",
}

var jointDPBiomedicalGaussianFullPhase19ExpectedTokenBlockers = []string{
	"registered_r_dsi_lifecycle_and_real_multiprocess_e2e_unavailable_v1",
	"joint_dp_release_consuming_hidden_execution_validity_v1",
}

// All members are process-local.  In particular, the Phase-1.9 token carries
// HMAC state and must never be reconstructed from relay JSON.
type jointDPBiomedicalGaussianFullPhase19SourceBinding struct {
	Version                           string `json:"-"`
	PeerName                          string `json:"-"`
	ChunkStart                        int    `json:"-"`
	CoordinateCount                   int    `json:"-"`
	Phase19PostExecutionRootSHA256    string `json:"-"`
	Phase19ExecutionReceiptPairSHA256 string `json:"-"`
	Phase19GlobalMaterializationRoot  string `json:"-"`
	Phase19PostExecutionTokenSHA256   string `json:"-"`
	SourceBindingSHA256               string `json:"-"`
	token                             formalGLMPhase19PostExecutionToken
	source                            jointDPBiomedicalGaussianFullLocalSourceBinding
	seal                              [32]byte
	verified                          bool
}

// The protected Gaussian share remains in `share`; public JSON contains only
// non-patient-derived release routing.  The Ed25519 signature binds the hidden
// output/source digests, and the backend HMAC binds the Phase-1.9 evidence.
type jointDPBiomedicalGaussianFullPhase19PeerShare struct {
	Version                           string `json:"version"`
	Backend                           string `json:"backend"`
	ReleaseInstanceID                 string `json:"release_instance_id"`
	ReleaseContractSHA256             string `json:"release_contract_sha256"`
	PeerName                          string `json:"peer_name"`
	ChunkStart                        int    `json:"chunk_start"`
	CoordinateCount                   int    `json:"coordinate_count"`
	Phase19PostExecutionRootSHA256    string `json:"phase19_post_execution_root_sha256"`
	Phase19ExecutionReceiptPairSHA256 string `json:"phase19_execution_receipt_pair_sha256"`
	OpeningsPerformed                 int    `json:"openings_performed"`
	ProductionReady                   bool   `json:"production_ready"`
	Signature                         []byte `json:"signature"`
	share                             jointDPBiomedicalGaussianFullPeerShare
	source                            jointDPBiomedicalGaussianFullPhase19SourceBinding
	seal                              [32]byte
	verified                          bool
}

type jointDPBiomedicalGaussianFullPhase19FinalizerHandoff struct {
	Version                           string   `json:"version"`
	Backend                           string   `json:"backend"`
	ReleaseInstanceID                 string   `json:"release_instance_id"`
	ReleaseContractSHA256             string   `json:"release_contract_sha256"`
	ChunkStart                        int      `json:"chunk_start"`
	CoordinateCount                   int      `json:"coordinate_count"`
	Phase19PostExecutionRootSHA256    string   `json:"phase19_post_execution_root_sha256"`
	Phase19ExecutionReceiptPairSHA256 string   `json:"phase19_execution_receipt_pair_sha256"`
	OpeningAuthorized                 bool     `json:"opening_authorized"`
	OpeningsPerformed                 int      `json:"openings_performed"`
	ProductionReady                   bool     `json:"production_ready"`
	Blockers                          []string `json:"blockers"`
	handoff                           jointDPBiomedicalGaussianFullFinalizerHandoff
	left                              jointDPBiomedicalGaussianFullPhase19PeerShare
	right                             jointDPBiomedicalGaussianFullPhase19PeerShare
	phase19Seal                       [32]byte
	verified                          bool
}

func jointDPBiomedicalGaussianFullValidatePhase19Token(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	token formalGLMPhase19PostExecutionToken, backendKey [32]byte,
) error {
	if err := jointDPBiomedicalGaussianValidateFullAdmissionCached(
		admission, pins); err != nil {
		return err
	}
	if err := formalGLMPhase19VerifyPostExecutionToken(
		token, backendKey); err != nil {
		return err
	}
	contract := admission.selection.Contract
	hashes := []string{
		token.ContextSHA256, token.CapsuleSHA256,
		token.Phase15PlanSHA256, token.PreExecutionTokenSHA256,
		token.RunID, token.PinsetSHA256,
		token.GlobalMaterializationRoot, token.FanInTranscriptSHA256,
		token.BlockCommitmentRootSHA256, token.BlockReceiptRootSHA256,
		token.AccumulatorRoot, token.ExecutionReceiptPairSHA256,
		token.FinalReceiptSetSeal, token.CheckpointEvidenceSeal,
		token.Phase15ExecutionTranscriptSHA256,
		token.FinalCheckpointTranscriptSHA256,
		token.WorkerTranscriptSHA256, token.PostExecutionRootSHA256,
		token.TokenSHA256,
	}
	for _, value := range hashes {
		if !jointDPBiomedicalGaussianIsSHA256(value) {
			return fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid Phase-1.9 evidence digest")
		}
	}
	// Despite its historical field name, Phase-1.9 CapsuleSHA256 carries the
	// canonical capsule_id. The Phase-1.8 materializer enforces this same
	// binding when it compares plan$kernel$capsule_sha256 with capsule_id.
	if token.CapsuleSHA256 != contract.CapsuleID ||
		token.PinsetSHA256 != contract.PinsetSHA256 ||
		token.GlobalMaterializationRoot != contract.MaterializationRootSHA256 ||
		token.CustodianCount != contract.CustodianCount ||
		!reflect.DeepEqual(token.ComputePeers,
			contract.DesignatedComputePeers) ||
		!token.FanInExecuted || !token.ExactAllKValidityInsideGC ||
		!token.ConsensusComparedInsideGC || !token.FullTupleMaskInsideGC ||
		!token.ExecutionValidSealed || token.ExecutionValidityOpened ||
		token.PatientDependentDigestsExposed ||
		token.ProtectedDataE2EVerified || token.OpeningAuthorized ||
		token.OpeningsPerformed != 0 || token.ProductionReady ||
		token.DPReleaseStatus !=
			"blocked_until_joint_dp_release_consumes_hidden_execution_validity_v1" ||
		!reflect.DeepEqual(token.RemainingBlockers,
			jointDPBiomedicalGaussianFullPhase19ExpectedTokenBlockers) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: Phase-1.9 evidence is not bound to this release")
	}
	return nil
}

func jointDPBiomedicalGaussianFullPhase19SourceMessage(
	binding jointDPBiomedicalGaussianFullPhase19SourceBinding,
) ([]byte, error) {
	if binding.Version != jointDPBiomedicalGaussianFullPhase19SourceVersion ||
		!jointDPBiomedicalGaussianValidPeerName(binding.PeerName) ||
		binding.ChunkStart < 0 || binding.CoordinateCount < 1 ||
		!jointDPBiomedicalGaussianIsSHA256(
			binding.Phase19PostExecutionRootSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			binding.Phase19ExecutionReceiptPairSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			binding.Phase19GlobalMaterializationRoot) ||
		!jointDPBiomedicalGaussianIsSHA256(
			binding.Phase19PostExecutionTokenSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(binding.SourceBindingSHA256) {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid Phase-1.9 local source binding")
	}
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianFullPhase19SourceDomain, struct {
			Version                           string `json:"version"`
			PeerName                          string `json:"peer_name"`
			ChunkStart                        int    `json:"chunk_start"`
			CoordinateCount                   int    `json:"coordinate_count"`
			Phase19PostExecutionRootSHA256    string `json:"phase19_post_execution_root_sha256"`
			Phase19ExecutionReceiptPairSHA256 string `json:"phase19_execution_receipt_pair_sha256"`
			Phase19GlobalMaterializationRoot  string `json:"phase19_global_materialization_root"`
			Phase19PostExecutionTokenSHA256   string `json:"phase19_post_execution_token_sha256"`
			SourceBindingSHA256               string `json:"source_binding_sha256"`
		}{
			binding.Version, binding.PeerName, binding.ChunkStart,
			binding.CoordinateCount,
			binding.Phase19PostExecutionRootSHA256,
			binding.Phase19ExecutionReceiptPairSHA256,
			binding.Phase19GlobalMaterializationRoot,
			binding.Phase19PostExecutionTokenSHA256,
			binding.SourceBindingSHA256,
		})
}

func jointDPBiomedicalGaussianBindFullPhase19Source(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	token formalGLMPhase19PostExecutionToken, backendKey [32]byte,
	peerName string, chunkStart, coordinateCount int, sourceShare string,
) (jointDPBiomedicalGaussianFullPhase19SourceBinding, error) {
	var zero jointDPBiomedicalGaussianFullPhase19SourceBinding
	if err := jointDPBiomedicalGaussianFullValidatePhase19Token(
		admission, pins, token, backendKey); err != nil {
		return zero, err
	}
	contract := admission.selection.Contract
	if !formalGLMPhase19Contains(
		contract.DesignatedComputePeers, peerName) {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: Phase-1.9 source recipient is not designated")
	}
	sourceContractDigest, err := jointDPBiomedicalGaussianDomainDigest(
		jointDPBiomedicalGaussianFullPhase19SourceDomain+"/source-contract",
		struct {
			TokenSHA256                     string `json:"token_sha256"`
			PostExecutionRootSHA256         string `json:"post_execution_root_sha256"`
			ExecutionReceiptPairSHA256      string `json:"execution_receipt_pair_sha256"`
			GlobalMaterializationRootSHA256 string `json:"global_materialization_root_sha256"`
			PeerName                        string `json:"peer_name"`
		}{
			token.TokenSHA256, token.PostExecutionRootSHA256,
			token.ExecutionReceiptPairSHA256,
			token.GlobalMaterializationRoot, peerName,
		})
	if err != nil {
		return zero, err
	}
	source, err := jointDPBiomedicalGaussianBuildFullLocalSourceBinding(
		admission, pins, peerName, token.PostExecutionRootSHA256,
		hex.EncodeToString(sourceContractDigest[:]), chunkStart,
		coordinateCount, sourceShare)
	if err != nil {
		return zero, err
	}
	binding := jointDPBiomedicalGaussianFullPhase19SourceBinding{
		Version:                           jointDPBiomedicalGaussianFullPhase19SourceVersion,
		PeerName:                          peerName,
		ChunkStart:                        chunkStart,
		CoordinateCount:                   coordinateCount,
		Phase19PostExecutionRootSHA256:    token.PostExecutionRootSHA256,
		Phase19ExecutionReceiptPairSHA256: token.ExecutionReceiptPairSHA256,
		Phase19GlobalMaterializationRoot:  token.GlobalMaterializationRoot,
		Phase19PostExecutionTokenSHA256:   token.TokenSHA256,
		SourceBindingSHA256:               source.BindingSHA256,
		token:                             token,
		source:                            source,
		verified:                          true,
	}
	message, err := jointDPBiomedicalGaussianFullPhase19SourceMessage(binding)
	if err != nil {
		return zero, err
	}
	binding.seal = formalGLMPhase19MAC(backendKey,
		jointDPBiomedicalGaussianFullPhase19SourceDomain+"/seal", message)
	return binding, nil
}

func jointDPBiomedicalGaussianValidateFullPhase19Source(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	binding jointDPBiomedicalGaussianFullPhase19SourceBinding,
	backendKey [32]byte, sourceShare string,
) error {
	if !binding.verified {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: unverified Phase-1.9 source handoff")
	}
	if err := jointDPBiomedicalGaussianFullValidatePhase19Token(
		admission, pins, binding.token, backendKey); err != nil {
		return err
	}
	if binding.PeerName != binding.source.LocalPeerName ||
		binding.ChunkStart != binding.source.ChunkStart ||
		binding.CoordinateCount != binding.source.CoordinateCount ||
		binding.Phase19PostExecutionRootSHA256 !=
			binding.token.PostExecutionRootSHA256 ||
		binding.Phase19ExecutionReceiptPairSHA256 !=
			binding.token.ExecutionReceiptPairSHA256 ||
		binding.Phase19GlobalMaterializationRoot !=
			binding.token.GlobalMaterializationRoot ||
		binding.Phase19PostExecutionTokenSHA256 != binding.token.TokenSHA256 ||
		binding.SourceBindingSHA256 != binding.source.BindingSHA256 {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: Phase-1.9 source binding changed")
	}
	if err := jointDPBiomedicalGaussianValidateFullLocalSourceBinding(
		admission, binding.source, binding.PeerName, sourceShare); err != nil {
		return err
	}
	message, err := jointDPBiomedicalGaussianFullPhase19SourceMessage(binding)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(backendKey,
		jointDPBiomedicalGaussianFullPhase19SourceDomain+"/seal", message)
	if !hmac.Equal(want[:], binding.seal[:]) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: Phase-1.9 source seal failed authentication")
	}
	return nil
}

func jointDPBiomedicalGaussianFullPhase19PeerMessage(
	value jointDPBiomedicalGaussianFullPhase19PeerShare,
) ([]byte, error) {
	if value.Version != jointDPBiomedicalGaussianFullPhase19PeerVersion ||
		value.Backend != jointDPGaussianBackend ||
		!jointDPBiomedicalGaussianIsSHA256(value.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(value.ReleaseContractSHA256) ||
		!jointDPBiomedicalGaussianValidPeerName(value.PeerName) ||
		value.ChunkStart < 0 || value.CoordinateCount < 1 ||
		!jointDPBiomedicalGaussianIsSHA256(
			value.Phase19PostExecutionRootSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			value.Phase19ExecutionReceiptPairSHA256) ||
		value.OpeningsPerformed != 0 || value.ProductionReady ||
		!jointDPBiomedicalGaussianIsSHA256(value.share.OutputSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(value.share.SourceBindingSHA256) {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid Phase-1.9 peer share")
	}
	return jointDPBiomedicalGaussianDomainMessage(
		jointDPBiomedicalGaussianFullPhase19PeerDomain, struct {
			Version                           string `json:"version"`
			Backend                           string `json:"backend"`
			ReleaseInstanceID                 string `json:"release_instance_id"`
			ReleaseContractSHA256             string `json:"release_contract_sha256"`
			PeerName                          string `json:"peer_name"`
			ChunkStart                        int    `json:"chunk_start"`
			CoordinateCount                   int    `json:"coordinate_count"`
			Phase19PostExecutionRootSHA256    string `json:"phase19_post_execution_root_sha256"`
			Phase19ExecutionReceiptPairSHA256 string `json:"phase19_execution_receipt_pair_sha256"`
			OutputSHA256                      string `json:"output_sha256"`
			SourceBindingSHA256               string `json:"source_binding_sha256"`
		}{
			value.Version, value.Backend, value.ReleaseInstanceID,
			value.ReleaseContractSHA256, value.PeerName, value.ChunkStart,
			value.CoordinateCount, value.Phase19PostExecutionRootSHA256,
			value.Phase19ExecutionReceiptPairSHA256,
			value.share.OutputSHA256, value.share.SourceBindingSHA256,
		})
}

func jointDPBiomedicalGaussianRunFullPhase19Peer(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	binding jointDPBiomedicalGaussianFullPhase19SourceBinding,
	backendKey, root [32]byte, signer ed25519.PrivateKey,
	sourceShare string,
) (jointDPBiomedicalGaussianFullPhase19PeerShare, error) {
	var zero jointDPBiomedicalGaussianFullPhase19PeerShare
	if err := jointDPBiomedicalGaussianValidateFullPhase19Source(
		admission, pins, binding, backendKey, sourceShare); err != nil {
		return zero, err
	}
	share, err := jointDPBiomedicalGaussianRunFullPeer(
		admission, pins, binding.source, binding.PeerName, root,
		signer, sourceShare)
	if err != nil {
		return zero, err
	}
	value := jointDPBiomedicalGaussianFullPhase19PeerShare{
		Version:                           jointDPBiomedicalGaussianFullPhase19PeerVersion,
		Backend:                           jointDPGaussianBackend,
		ReleaseInstanceID:                 share.ReleaseInstanceID,
		ReleaseContractSHA256:             share.ReleaseContractSHA256,
		PeerName:                          share.PeerName,
		ChunkStart:                        share.ChunkStart,
		CoordinateCount:                   share.CoordinateCount,
		Phase19PostExecutionRootSHA256:    binding.Phase19PostExecutionRootSHA256,
		Phase19ExecutionReceiptPairSHA256: binding.Phase19ExecutionReceiptPairSHA256,
		OpeningsPerformed:                 0,
		ProductionReady:                   false,
		share:                             share,
		source:                            binding,
		verified:                          true,
	}
	message, err := jointDPBiomedicalGaussianFullPhase19PeerMessage(value)
	if err != nil {
		return zero, err
	}
	value.Signature = ed25519.Sign(signer, message)
	value.seal = formalGLMPhase19MAC(backendKey,
		jointDPBiomedicalGaussianFullPhase19PeerDomain+"/seal", message)
	if err := jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
		admission, pins, value, backendKey); err != nil {
		return zero, err
	}
	return value, nil
}

func jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	value jointDPBiomedicalGaussianFullPhase19PeerShare,
	backendKey [32]byte,
) error {
	if !value.verified || value.PeerName != value.share.PeerName ||
		value.PeerName != value.source.PeerName ||
		value.ChunkStart != value.share.ChunkStart ||
		value.ChunkStart != value.source.ChunkStart ||
		value.CoordinateCount != value.share.CoordinateCount ||
		value.CoordinateCount != value.source.CoordinateCount ||
		value.Phase19PostExecutionRootSHA256 !=
			value.source.Phase19PostExecutionRootSHA256 ||
		value.Phase19ExecutionReceiptPairSHA256 !=
			value.source.Phase19ExecutionReceiptPairSHA256 {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: unverified Phase-1.9 peer output")
	}
	if err := jointDPBiomedicalGaussianValidateFullPeerShare(
		admission, pins, value.share); err != nil {
		return err
	}
	message, err := jointDPBiomedicalGaussianFullPhase19PeerMessage(value)
	if err != nil {
		return err
	}
	pin := pins[value.PeerName]
	if len(pin) != ed25519.PublicKeySize ||
		len(value.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pin, message, value.Signature) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: Phase-1.9 peer signature verification failed")
	}
	want := formalGLMPhase19MAC(backendKey,
		jointDPBiomedicalGaussianFullPhase19PeerDomain+"/seal", message)
	if !hmac.Equal(want[:], value.seal[:]) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: Phase-1.9 peer seal failed authentication")
	}
	return nil
}

func jointDPBiomedicalGaussianFullPhase19HandoffMessage(
	value jointDPBiomedicalGaussianFullPhase19FinalizerHandoff,
) ([]byte, error) {
	if value.Version != jointDPBiomedicalGaussianFullPhase19HandoffVersion ||
		value.Backend != jointDPGaussianBackend ||
		!jointDPBiomedicalGaussianIsSHA256(value.ReleaseInstanceID) ||
		!jointDPBiomedicalGaussianIsSHA256(value.ReleaseContractSHA256) ||
		value.ChunkStart < 0 || value.CoordinateCount < 1 ||
		!jointDPBiomedicalGaussianIsSHA256(
			value.Phase19PostExecutionRootSHA256) ||
		!jointDPBiomedicalGaussianIsSHA256(
			value.Phase19ExecutionReceiptPairSHA256) ||
		value.OpeningAuthorized || value.OpeningsPerformed != 0 ||
		value.ProductionReady || !reflect.DeepEqual(value.Blockers,
		jointDPBiomedicalGaussianFullPhase19HandoffBlockers) {
		return nil, fmt.Errorf("joint-dp-biomedical-gaussian-full: invalid Phase-1.9 finalizer handoff")
	}
	return json.Marshal(struct {
		Version                           string   `json:"version"`
		Backend                           string   `json:"backend"`
		ReleaseInstanceID                 string   `json:"release_instance_id"`
		ReleaseContractSHA256             string   `json:"release_contract_sha256"`
		ChunkStart                        int      `json:"chunk_start"`
		CoordinateCount                   int      `json:"coordinate_count"`
		Phase19PostExecutionRootSHA256    string   `json:"phase19_post_execution_root_sha256"`
		Phase19ExecutionReceiptPairSHA256 string   `json:"phase19_execution_receipt_pair_sha256"`
		LeftOutputSHA256                  string   `json:"left_output_sha256"`
		RightOutputSHA256                 string   `json:"right_output_sha256"`
		LeftSourceBindingSHA256           string   `json:"left_source_binding_sha256"`
		RightSourceBindingSHA256          string   `json:"right_source_binding_sha256"`
		Blockers                          []string `json:"blockers"`
	}{
		value.Version, value.Backend, value.ReleaseInstanceID,
		value.ReleaseContractSHA256, value.ChunkStart, value.CoordinateCount,
		value.Phase19PostExecutionRootSHA256,
		value.Phase19ExecutionReceiptPairSHA256,
		value.left.share.OutputSHA256, value.right.share.OutputSHA256,
		value.left.share.SourceBindingSHA256,
		value.right.share.SourceBindingSHA256,
		value.Blockers,
	})
}

func jointDPBiomedicalGaussianBuildFullPhase19FinalizerHandoff(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	token formalGLMPhase19PostExecutionToken, backendKey [32]byte,
	first, second jointDPBiomedicalGaussianFullPhase19PeerShare,
) (jointDPBiomedicalGaussianFullPhase19FinalizerHandoff, error) {
	var zero jointDPBiomedicalGaussianFullPhase19FinalizerHandoff
	if err := jointDPBiomedicalGaussianFullValidatePhase19Token(
		admission, pins, token, backendKey); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
		admission, pins, first, backendKey); err != nil {
		return zero, err
	}
	if err := jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
		admission, pins, second, backendKey); err != nil {
		return zero, err
	}
	peers := admission.selection.Contract.DesignatedComputePeers
	byPeer := map[string]jointDPBiomedicalGaussianFullPhase19PeerShare{
		first.PeerName: first, second.PeerName: second,
	}
	left, leftOK := byPeer[peers[0]]
	right, rightOK := byPeer[peers[1]]
	if !leftOK || !rightOK || len(byPeer) != 2 ||
		left.Phase19PostExecutionRootSHA256 != token.PostExecutionRootSHA256 ||
		right.Phase19PostExecutionRootSHA256 != token.PostExecutionRootSHA256 ||
		left.Phase19ExecutionReceiptPairSHA256 != token.ExecutionReceiptPairSHA256 ||
		right.Phase19ExecutionReceiptPairSHA256 != token.ExecutionReceiptPairSHA256 {
		return zero, fmt.Errorf("joint-dp-biomedical-gaussian-full: Phase-1.9 peer evidence differs")
	}
	handoff, err := jointDPBiomedicalGaussianBuildFullFinalizerHandoff(
		admission, pins, left.share, right.share)
	if err != nil {
		return zero, err
	}
	value := jointDPBiomedicalGaussianFullPhase19FinalizerHandoff{
		Version:                           jointDPBiomedicalGaussianFullPhase19HandoffVersion,
		Backend:                           jointDPGaussianBackend,
		ReleaseInstanceID:                 handoff.ReleaseInstanceID,
		ReleaseContractSHA256:             handoff.ReleaseContractSHA256,
		ChunkStart:                        left.ChunkStart,
		CoordinateCount:                   left.CoordinateCount,
		Phase19PostExecutionRootSHA256:    token.PostExecutionRootSHA256,
		Phase19ExecutionReceiptPairSHA256: token.ExecutionReceiptPairSHA256,
		OpeningAuthorized:                 false,
		OpeningsPerformed:                 0,
		ProductionReady:                   false,
		Blockers: append([]string(nil),
			jointDPBiomedicalGaussianFullPhase19HandoffBlockers...),
		handoff:  handoff,
		left:     left,
		right:    right,
		verified: true,
	}
	message, err := jointDPBiomedicalGaussianFullPhase19HandoffMessage(value)
	if err != nil {
		return zero, err
	}
	value.phase19Seal = formalGLMPhase19MAC(backendKey,
		jointDPBiomedicalGaussianFullPhase19HandoffDomain+"/seal", message)
	return value, nil
}

func jointDPBiomedicalGaussianValidateFullPhase19FinalizerHandoff(
	admission jointDPBiomedicalGaussianFullAdmission,
	pins map[string]ed25519.PublicKey,
	value jointDPBiomedicalGaussianFullPhase19FinalizerHandoff,
	backendKey [32]byte,
) error {
	if !value.verified || value.ReleaseInstanceID !=
		value.handoff.ReleaseInstanceID ||
		value.ReleaseContractSHA256 != value.handoff.ReleaseContractSHA256 ||
		value.ChunkStart != value.handoff.finalizerInput.ChunkStart ||
		value.CoordinateCount != value.handoff.finalizerInput.CoordinateCount {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: unverified Phase-1.9 finalizer handoff")
	}
	if err := jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
		admission, pins, value.left, backendKey); err != nil {
		return err
	}
	if err := jointDPBiomedicalGaussianValidateFullPhase19PeerShare(
		admission, pins, value.right, backendKey); err != nil {
		return err
	}
	message, err := jointDPBiomedicalGaussianFullPhase19HandoffMessage(value)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(backendKey,
		jointDPBiomedicalGaussianFullPhase19HandoffDomain+"/seal", message)
	if !hmac.Equal(want[:], value.phase19Seal[:]) {
		return fmt.Errorf("joint-dp-biomedical-gaussian-full: Phase-1.9 finalizer seal failed authentication")
	}
	return nil
}
