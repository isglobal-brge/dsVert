package main

// Clean analyst-visible projection of the formal GLM one-draw release. The
// larger sticky certificate remains owner-local validation evidence. Neither
// operational run identifiers nor legacy reservation/lifetime fields enter
// this object, its signature, or its ArtifactID-keyed publication slot.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
)

const (
	formalGLMPhase21PublicV2Version       = "dsvert-formal-glm-public-release-v2"
	formalGLMPhase21PublicV2Purpose       = "formal_glm_one_draw_sticky_publication_v2"
	formalGLMPhase21PublicV2RecordVersion = "dsvert-formal-glm-public-release-record-v2"
	formalGLMPhase21PublicV2Domain        = "dsVert/formal-glm/phase21/public-release/v2"
)

type formalGLMPhase21PublicCertificateV2 struct {
	Version                      string                               `json:"version"`
	Purpose                      string                               `json:"purpose"`
	ArtifactID                   string                               `json:"artifact_id"`
	Artifact                     formalGLMPhase21StickyArtifact       `json:"artifact"`
	PublicDescriptor             *formalGLMSignedPublicDescriptorV1   `json:"public_descriptor,omitempty"`
	SamplerMode                  string                               `json:"sampler_mode"`
	VectorSHA256                 string                               `json:"vector_sha256"`
	ClampedScaledValues          []string                             `json:"clamped_scaled_values"`
	PrivacyScope                 string                               `json:"privacy_scope"`
	GlobalCompositionClaim       bool                                 `json:"global_composition_claim"`
	SingleCommonDPVector         bool                                 `json:"single_common_dp_vector"`
	ExactlyOnceDPOpening         bool                                 `json:"exactly_once_dp_opening"`
	UnlimitedDeterministicReplay bool                                 `json:"unlimited_deterministic_replay"`
	UnlimitedPostprocessing      bool                                 `json:"unlimited_postprocessing"`
	HistoryCanDenyOperation      bool                                 `json:"history_can_deny_operation"`
	AuthorityReceipts            []jointDPBiomedicalGaussianSignature `json:"authority_receipts"`
	ProductionReady              bool                                 `json:"production_ready"`
}

type formalGLMPhase21PublicV2Record struct {
	Version           string `json:"version"`
	Purpose           string `json:"purpose"`
	Peer              string `json:"peer"`
	ArtifactID        string `json:"artifact_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	CertificateJSON   string `json:"certificate_json"`
	RecordMAC         string `json:"record_mac"`
}

func formalGLMPhase21BuildPublicCertificateV2(
	internal formalGLMPhase21StickyCertificate,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21PublicCertificateV2, error) {
	var zero formalGLMPhase21PublicCertificateV2
	if len(internal.AuthorityReceipts) != 0 ||
		internal.SamplerV2Contract == nil ||
		internal.SamplerV2Contract.SamplerMode != formalGLMPhase21SamplerV2OneDraw ||
		internal.DurablePublicationProtocol != formalGLMPhase21DurableV2Version ||
		!internal.ExactlyOnceDPOpening ||
		formalGLMPhase21ValidateStickyCertificateCore(internal, pins) != nil {
		return zero, fmt.Errorf("formal-glm: invalid public-v2 source certificate")
	}
	artifactBytes, err := json.Marshal(internal.Artifact)
	if err != nil {
		return zero, err
	}
	var artifact formalGLMPhase21StickyArtifact
	if err := json.Unmarshal(artifactBytes, &artifact); err != nil {
		return zero, err
	}
	certificate := formalGLMPhase21PublicCertificateV2{
		Version:    formalGLMPhase21PublicV2Version,
		Purpose:    formalGLMPhase21PublicV2Purpose,
		ArtifactID: internal.ArtifactID, Artifact: artifact,
		SamplerMode:  formalGLMPhase21SamplerV2OneDraw,
		VectorSHA256: internal.VectorSHA256,
		ClampedScaledValues: append(
			[]string(nil), internal.ClampedScaledValues...),
		PrivacyScope:                 internal.PrivacyScope,
		GlobalCompositionClaim:       false,
		SingleCommonDPVector:         true,
		ExactlyOnceDPOpening:         true,
		UnlimitedDeterministicReplay: true,
		UnlimitedPostprocessing:      true,
		HistoryCanDenyOperation:      false,
		AuthorityReceipts:            nil,
		ProductionReady:              false,
	}
	if err := formalGLMPhase21ValidatePublicCertificateV2Core(
		certificate, pins); err != nil {
		return zero, err
	}
	return certificate, nil
}

func formalGLMPhase21ValidatePublicCertificateV2Core(
	certificate formalGLMPhase21PublicCertificateV2,
	pins map[string]ed25519.PublicKey,
) error {
	if certificate.Version != formalGLMPhase21PublicV2Version ||
		certificate.Purpose != formalGLMPhase21PublicV2Purpose ||
		certificate.SamplerMode != formalGLMPhase21SamplerV2OneDraw ||
		certificate.PrivacyScope != "per_canonical_artifact_v1" ||
		certificate.GlobalCompositionClaim ||
		!certificate.SingleCommonDPVector ||
		!certificate.ExactlyOnceDPOpening ||
		!certificate.UnlimitedDeterministicReplay ||
		!certificate.UnlimitedPostprocessing ||
		certificate.HistoryCanDenyOperation || certificate.ProductionReady ||
		formalGLMPhase21ValidateStickyArtifact(certificate.Artifact, pins) != nil {
		return fmt.Errorf("formal-glm: invalid public-v2 lifecycle contract")
	}
	artifactID, err := formalGLMPhase21StickyArtifactID(certificate.Artifact)
	if err != nil || artifactID != certificate.ArtifactID ||
		len(certificate.ClampedScaledValues) !=
			certificate.Artifact.CoordinateCount {
		return fmt.Errorf("formal-glm: public-v2 artifact mismatch")
	}
	if certificate.PublicDescriptor != nil {
		if err := formalGLMValidateSignedPublicDescriptorV1(
			*certificate.PublicDescriptor, pins); err != nil ||
			formalGLMValidatePublicDescriptorAgainstArtifactV1(
				*certificate.PublicDescriptor, certificate.Artifact) != nil {
			return fmt.Errorf("formal-glm: invalid public-v2 descriptor")
		}
	}
	vectorSHA256, err := jointDPBiomedicalGaussianOneDrawVectorSHA256(
		certificate.ClampedScaledValues)
	if err != nil || vectorSHA256 != certificate.VectorSHA256 {
		return fmt.Errorf("formal-glm: public-v2 vector mismatch")
	}
	for _, value := range certificate.ClampedScaledValues {
		parsed, err := jointDPBiomedicalGaussianParseCanonicalInt(
			value, "public-v2 Ring128 coordinate", false)
		if err != nil || parsed.Sign() < 0 || parsed.BitLen() > 128 {
			return fmt.Errorf("formal-glm: invalid exact public-v2 coordinate")
		}
	}
	if len(certificate.AuthorityReceipts) != 0 &&
		len(certificate.AuthorityReceipts) != 2 {
		return fmt.Errorf("formal-glm: incomplete public-v2 authority set")
	}
	return nil
}

func formalGLMPhase21PublicCertificateV2Message(
	certificate formalGLMPhase21PublicCertificateV2,
) ([]byte, error) {
	certificate.AuthorityReceipts = nil
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMPhase21PublicV2Domain+"/certificate|"),
		encoded...), nil
}

func formalGLMPhase21PublicCertificateV2SHA256(
	certificate formalGLMPhase21PublicCertificateV2,
) (string, error) {
	certificate.AuthorityReceipts = nil
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21PublicV2Domain+"/unsigned-certificate|"),
		encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func formalGLMPhase21SignPublicCertificateV2(
	certificate formalGLMPhase21PublicCertificateV2,
	peer string, privateKey ed25519.PrivateKey,
	pins map[string]ed25519.PublicKey,
) (jointDPBiomedicalGaussianSignature, error) {
	if len(certificate.AuthorityReceipts) != 0 ||
		formalGLMPhase21ValidatePublicCertificateV2Core(certificate, pins) != nil ||
		len(privateKey) != ed25519.PrivateKeySize ||
		!hmac.Equal(privateKey.Public().(ed25519.PublicKey), pins[peer]) {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("formal-glm: invalid public-v2 signer")
	}
	found := false
	for _, authority := range certificate.Artifact.NoiseAuthorities {
		found = found || authority.PeerName == peer
	}
	if !found {
		return jointDPBiomedicalGaussianSignature{},
			fmt.Errorf("formal-glm: public-v2 signer is not an authority")
	}
	message, err := formalGLMPhase21PublicCertificateV2Message(certificate)
	if err != nil {
		return jointDPBiomedicalGaussianSignature{}, err
	}
	return jointDPBiomedicalGaussianSignature{
		Signer: peer, Signature: ed25519.Sign(privateKey, message),
	}, nil
}

func formalGLMPhase21SealPublicCertificateV2(
	certificate formalGLMPhase21PublicCertificateV2,
	receipts []jointDPBiomedicalGaussianSignature,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21PublicCertificateV2, error) {
	certificate.AuthorityReceipts = make(
		[]jointDPBiomedicalGaussianSignature, len(receipts))
	for index, receipt := range receipts {
		certificate.AuthorityReceipts[index] = jointDPBiomedicalGaussianSignature{
			Signer:    receipt.Signer,
			Signature: append([]byte(nil), receipt.Signature...),
		}
	}
	if err := formalGLMPhase21ValidatePublicCertificateV2(
		certificate, pins); err != nil {
		return formalGLMPhase21PublicCertificateV2{}, err
	}
	return certificate, nil
}

func formalGLMPhase21ValidatePublicCertificateV2(
	certificate formalGLMPhase21PublicCertificateV2,
	pins map[string]ed25519.PublicKey,
) error {
	if err := formalGLMPhase21ValidatePublicCertificateV2Core(
		certificate, pins); err != nil {
		return err
	}
	if len(certificate.AuthorityReceipts) != 2 {
		return fmt.Errorf("formal-glm: public-v2 lacks both authorities")
	}
	message, err := formalGLMPhase21PublicCertificateV2Message(certificate)
	if err != nil {
		return err
	}
	for index, authority := range certificate.Artifact.NoiseAuthorities {
		receipt := certificate.AuthorityReceipts[index]
		if receipt.Signer != authority.PeerName ||
			len(receipt.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(pins[receipt.Signer], message, receipt.Signature) {
			return fmt.Errorf("formal-glm: invalid public-v2 authority receipt")
		}
	}
	return nil
}

func formalGLMPhase21PublicV2RecordMAC(key [32]byte,
	record formalGLMPhase21PublicV2Record,
) (string, error) {
	record.RecordMAC = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(formalGLMPhase21PublicV2Domain + "/record|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalGLMPhase21EncodePublicV2Record(key [32]byte,
	record formalGLMPhase21PublicV2Record,
) ([]byte, error) {
	mac, err := formalGLMPhase21PublicV2RecordMAC(key, record)
	if err != nil {
		return nil, err
	}
	record.RecordMAC = mac
	return json.Marshal(record)
}

func (store *formalGLMPhase21StickyReleaseStore) publicV2RelativePath(
	artifactID string, create bool,
) (string, error) {
	if !formalGLMIsSHA256(artifactID) {
		return "", fmt.Errorf("formal-glm: invalid public-v2 artifact id")
	}
	shard := filepath.Join("public-v2", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(
			store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	return filepath.Join(shard, "release-"+artifactID+".json"), nil
}

func (store *formalGLMPhase21StickyReleaseStore) decodePublicV2Record(
	encoded []byte,
) (formalGLMPhase21PublicV2Record,
	formalGLMPhase21PublicCertificateV2, []byte, error,
) {
	var zeroRecord formalGLMPhase21PublicV2Record
	var zeroCertificate formalGLMPhase21PublicCertificateV2
	if len(encoded) < 64 || len(encoded) > formalGLMPhase21StickyMaxBytes {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: invalid public-v2 record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase21PublicV2Record
	if err := decoder.Decode(&record); err != nil {
		return zeroRecord, zeroCertificate, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: trailing public-v2 record")
	}
	wantMAC, err := formalGLMPhase21PublicV2RecordMAC(store.key, record)
	if err != nil || !hmac.Equal([]byte(wantMAC), []byte(record.RecordMAC)) ||
		record.Version != formalGLMPhase21PublicV2RecordVersion ||
		record.Purpose != formalGLMPhase21PublicV2Purpose ||
		record.Peer != store.peer || !formalGLMIsSHA256(record.ArtifactID) ||
		!formalGLMIsSHA256(record.CertificateSHA256) ||
		len(record.CertificateJSON) == 0 {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: public-v2 record authentication failed")
	}
	canonicalRecord, err := formalGLMPhase21EncodePublicV2Record(store.key, record)
	if err != nil || !bytes.Equal(canonicalRecord, encoded) {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: non-canonical public-v2 record")
	}
	certificateBytes := []byte(record.CertificateJSON)
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21PublicV2Domain+"/sealed-certificate|"),
		certificateBytes...))
	if hex.EncodeToString(digest[:]) != record.CertificateSHA256 {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: public-v2 certificate digest mismatch")
	}
	certificateDecoder := json.NewDecoder(bytes.NewReader(certificateBytes))
	certificateDecoder.DisallowUnknownFields()
	var certificate formalGLMPhase21PublicCertificateV2
	if err := certificateDecoder.Decode(&certificate); err != nil {
		return zeroRecord, zeroCertificate, nil, err
	}
	if err := certificateDecoder.Decode(&trailing); err != io.EOF {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: trailing public-v2 certificate")
	}
	canonicalCertificate, err := json.Marshal(certificate)
	if err != nil || !bytes.Equal(canonicalCertificate, certificateBytes) ||
		certificate.ArtifactID != record.ArtifactID ||
		formalGLMPhase21ValidatePublicCertificateV2(certificate, store.pins) != nil {
		return zeroRecord, zeroCertificate, nil,
			fmt.Errorf("formal-glm: invalid canonical public-v2 certificate")
	}
	return record, certificate, certificateBytes, nil
}

func (store *formalGLMPhase21StickyReleaseStore) CommitPublicV2(
	certificate formalGLMPhase21PublicCertificateV2,
) (formalGLMPhase21StickyPublication, error) {
	var zero formalGLMPhase21StickyPublication
	if store == nil || store.root == nil ||
		!formalGLMPhase19KeyValid(store.key) ||
		formalGLMPhase21ValidatePublicCertificateV2(certificate, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm: invalid public-v2 commit")
	}
	certificateBytes, err := json.Marshal(certificate)
	if err != nil || len(certificateBytes) > formalGLMPhase21StickyMaxBytes/2 {
		return zero, fmt.Errorf("formal-glm: public-v2 certificate too large")
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21PublicV2Domain+"/sealed-certificate|"),
		certificateBytes...))
	record := formalGLMPhase21PublicV2Record{
		Version: formalGLMPhase21PublicV2RecordVersion,
		Purpose: formalGLMPhase21PublicV2Purpose, Peer: store.peer,
		ArtifactID:        certificate.ArtifactID,
		CertificateSHA256: hex.EncodeToString(digest[:]),
		CertificateJSON:   string(certificateBytes),
	}
	encoded, err := formalGLMPhase21EncodePublicV2Record(store.key, record)
	if err != nil {
		return zero, err
	}
	path, err := store.publicV2RelativePath(certificate.ArtifactID, true)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	created, err := formalGLMPhase21RootCreateRecord(store.root, path, encoded)
	if err != nil {
		return zero, err
	}
	existingBytes, err := formalGLMPhase21RootReadRecord(
		store.root, path, formalGLMPhase21StickyMaxBytes)
	if err != nil {
		return zero, err
	}
	existing, _, publicBytes, err := store.decodePublicV2Record(existingBytes)
	if err != nil || existing.ArtifactID != record.ArtifactID ||
		existing.CertificateSHA256 != record.CertificateSHA256 ||
		!bytes.Equal(publicBytes, certificateBytes) {
		return zero, fmt.Errorf("formal-glm: conflicting public-v2 release")
	}
	return formalGLMPhase21StickyPublication{
		ArtifactID:        existing.ArtifactID,
		CertificateSHA256: existing.CertificateSHA256,
		Certificate:       append([]byte(nil), publicBytes...), Replayed: !created,
	}, nil
}

func (store *formalGLMPhase21StickyReleaseStore) ReplayPublicV2(
	artifactID string,
) (formalGLMPhase21StickyPublication, error) {
	var zero formalGLMPhase21StickyPublication
	if store == nil || store.root == nil ||
		!formalGLMPhase19KeyValid(store.key) {
		return zero, fmt.Errorf("formal-glm: closed public-v2 store")
	}
	path, err := store.publicV2RelativePath(artifactID, false)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	encoded, err := formalGLMPhase21RootReadRecord(
		store.root, path, formalGLMPhase21StickyMaxBytes)
	if err != nil {
		return zero, err
	}
	record, _, certificate, err := store.decodePublicV2Record(encoded)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase21StickyPublication{
		ArtifactID:        record.ArtifactID,
		CertificateSHA256: record.CertificateSHA256,
		Certificate:       append([]byte(nil), certificate...), Replayed: true,
	}, nil
}

func formalGLMPhase21DecodePublicV2Publication(
	publication formalGLMPhase21StickyPublication,
	pins map[string]ed25519.PublicKey,
) (formalGLMPhase21PublicCertificateV2, error) {
	var zero formalGLMPhase21PublicCertificateV2
	decoder := json.NewDecoder(bytes.NewReader(publication.Certificate))
	decoder.DisallowUnknownFields()
	var certificate formalGLMPhase21PublicCertificateV2
	if err := decoder.Decode(&certificate); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF ||
		certificate.ArtifactID != publication.ArtifactID ||
		formalGLMPhase21ValidatePublicCertificateV2(certificate, pins) != nil {
		return zero, fmt.Errorf("formal-glm: invalid public-v2 publication")
	}
	return certificate, nil
}

func formalGLMPhase21PublicV2RecordPath(
	store *formalGLMPhase21StickyReleaseStore, artifactID string,
) (string, error) {
	if store == nil {
		return "", fmt.Errorf("formal-glm: missing public-v2 store")
	}
	relative, err := store.publicV2RelativePath(artifactID, false)
	if err != nil {
		return "", err
	}
	return filepath.Join(store.dir, relative), nil
}
