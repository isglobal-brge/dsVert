package main

// Verification adapter for the existing R joint-DP control plane.  It does
// not create a Cox-specific accountant or ledger.  Instead it consumes the
// two Ed25519-signed `open_authorized` tokens already minted after both local
// durable ledgers have committed the same allocation.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
)

const (
	formalCoxRuntimeLedgerTokenVersion  = "dsvert-joint-dp-opening-token-v1"
	formalCoxRuntimeLedgerTokenPhase    = "open_authorized"
	formalCoxRuntimeLedgerScope         = "joint_mpc_single_opening"
	formalCoxRuntimeLedgerMessageDomain = "dsVert/joint-dp/signed-receipt/v1|"
	formalCoxRuntimeLedgerSetDomain     = "dsVert/formal-cox/common-ledger-opening-token-set/v1"
)

var formalCoxRuntimeConsortiumID = regexp.MustCompile(`^jdpc1_[0-9a-f]{64}$`)

// Field names and types mirror .DSVERT_JOINT_DP_OPEN_VERSION in
// R/jointDPControlPlane.R. Signature uses the R base64url representation.
type formalCoxRuntimeLedgerOpeningToken struct {
	Version              string `json:"version"`
	Phase                string `json:"phase"`
	ConsortiumID         string `json:"consortium_id"`
	PeerName             string `json:"peer_name"`
	PeerIdentityPK       string `json:"peer_identity_pk"`
	CapsuleID            string `json:"capsule_id"`
	QueryID              string `json:"query_id"`
	AllocationIndex      string `json:"allocation_index"`
	NewChain             string `json:"new_chain"`
	JointRecordHash      string `json:"joint_record_hash"`
	AuthorizationSetHash string `json:"authorization_set_hash"`
	SeedCommitment       string `json:"seed_commitment"`
	ReleaseScope         string `json:"release_scope"`
	CapabilityAvailable  bool   `json:"capability_available"`
	Signature            string `json:"signature"`
}

// R canonicalizes object names in radix order before signing.  Keep this
// projection in that exact alphabetical order so encoding/json emits the same
// bytes as .dsvert_joint_dp_receipt_message().
type formalCoxRuntimeLedgerUnsignedCanonical struct {
	AllocationIndex      string `json:"allocation_index"`
	AuthorizationSetHash string `json:"authorization_set_hash"`
	CapabilityAvailable  bool   `json:"capability_available"`
	CapsuleID            string `json:"capsule_id"`
	ConsortiumID         string `json:"consortium_id"`
	JointRecordHash      string `json:"joint_record_hash"`
	NewChain             string `json:"new_chain"`
	PeerIdentityPK       string `json:"peer_identity_pk"`
	PeerName             string `json:"peer_name"`
	Phase                string `json:"phase"`
	QueryID              string `json:"query_id"`
	ReleaseScope         string `json:"release_scope"`
	SeedCommitment       string `json:"seed_commitment"`
	Version              string `json:"version"`
}

func formalCoxRuntimeLedgerUnsigned(
	token formalCoxRuntimeLedgerOpeningToken,
) formalCoxRuntimeLedgerUnsignedCanonical {
	return formalCoxRuntimeLedgerUnsignedCanonical{
		AllocationIndex:      token.AllocationIndex,
		AuthorizationSetHash: token.AuthorizationSetHash,
		CapabilityAvailable:  token.CapabilityAvailable,
		CapsuleID:            token.CapsuleID, ConsortiumID: token.ConsortiumID,
		JointRecordHash: token.JointRecordHash, NewChain: token.NewChain,
		PeerIdentityPK: token.PeerIdentityPK, PeerName: token.PeerName,
		Phase: token.Phase, QueryID: token.QueryID,
		ReleaseScope: token.ReleaseScope, SeedCommitment: token.SeedCommitment,
		Version: token.Version,
	}
}

func formalCoxRuntimeLedgerTokenMessage(
	token formalCoxRuntimeLedgerOpeningToken,
) ([]byte, error) {
	canonical, err := json.Marshal(formalCoxRuntimeLedgerUnsigned(token))
	if err != nil {
		return nil, err
	}
	return append([]byte(formalCoxRuntimeLedgerMessageDomain), canonical...), nil
}

func formalCoxRuntimeLedgerAllocationIndex(value string) bool {
	if value == "0" {
		return true
	}
	if len(value) < 1 || len(value) > 16 || value[0] == '0' {
		return false
	}
	var n uint64
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
		n = n*10 + uint64(character-'0')
		if n > 1<<53-1 {
			return false
		}
	}
	return true
}

func formalCoxRuntimeLedgerTokenSetSHA256(
	tokens []formalCoxRuntimeLedgerOpeningToken,
) (string, error) {
	ordered := append([]formalCoxRuntimeLedgerOpeningToken(nil), tokens...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].PeerName < ordered[j].PeerName
	})
	digest, err := jointDPBiomedicalGaussianDomainDigest(
		formalCoxRuntimeLedgerSetDomain, ordered)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func formalCoxRuntimeValidateCommonLedgerAuthority(
	policy formalCoxPhase1Policy, roles formalCoxRuntimeRoles,
	pins map[string]ed25519.PublicKey,
	commitments map[string]string,
	tokens []formalCoxRuntimeLedgerOpeningToken,
	references []jointDPBiomedicalGaussianReceiptReference,
) error {
	if len(tokens) != 2 {
		return fmt.Errorf("formal-cox: two common-ledger opening tokens are required")
	}
	ordered := append([]formalCoxRuntimeLedgerOpeningToken(nil), tokens...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].PeerName < ordered[j].PeerName
	})
	wantPeers := []string{roles.GarblerPeerName, roles.EvaluatorPeerName}
	sort.Strings(wantPeers)
	if ordered[0].PeerName != wantPeers[0] ||
		ordered[1].PeerName != wantPeers[1] ||
		ordered[0].PeerName == ordered[1].PeerName {
		return fmt.Errorf("formal-cox: common-ledger tokens do not cover both compute peers")
	}
	for _, token := range ordered {
		pin := pins[token.PeerName]
		identity := base64.RawURLEncoding.EncodeToString(pin)
		signature, signatureErr := base64.RawURLEncoding.DecodeString(token.Signature)
		message, messageErr := formalCoxRuntimeLedgerTokenMessage(token)
		if token.Version != formalCoxRuntimeLedgerTokenVersion ||
			token.Phase != formalCoxRuntimeLedgerTokenPhase ||
			token.ReleaseScope != formalCoxRuntimeLedgerScope ||
			token.CapabilityAvailable ||
			!formalCoxRuntimeConsortiumID.MatchString(token.ConsortiumID) ||
			token.PeerIdentityPK != identity ||
			token.CapsuleID != policy.CapsuleSHA256 ||
			token.QueryID != policy.CapsuleSHA256 ||
			!formalCoxRuntimeLedgerAllocationIndex(token.AllocationIndex) ||
			!formalCoxIsSHA256(token.NewChain) ||
			!formalCoxIsSHA256(token.JointRecordHash) ||
			!formalCoxIsSHA256(token.AuthorizationSetHash) ||
			token.SeedCommitment != commitments[token.PeerName] ||
			signatureErr != nil || len(signature) != ed25519.SignatureSize ||
			messageErr != nil || !ed25519.Verify(pin, message, signature) {
			return fmt.Errorf("formal-cox: invalid signed common-ledger opening token")
		}
	}
	type common struct {
		ConsortiumID         string
		CapsuleID            string
		QueryID              string
		AllocationIndex      string
		NewChain             string
		JointRecordHash      string
		AuthorizationSetHash string
		ReleaseScope         string
	}
	project := func(token formalCoxRuntimeLedgerOpeningToken) common {
		return common{token.ConsortiumID, token.CapsuleID, token.QueryID,
			token.AllocationIndex, token.NewChain, token.JointRecordHash,
			token.AuthorizationSetHash, token.ReleaseScope}
	}
	if !reflect.DeepEqual(project(ordered[0]), project(ordered[1])) {
		return fmt.Errorf("formal-cox: common-ledger tokens describe different allocations")
	}
	digest, err := formalCoxRuntimeLedgerTokenSetSHA256(ordered)
	if err != nil {
		return err
	}
	reference, ok := jointDPBiomedicalGaussianReceiptByKind(
		references, jointDPBiomedicalGaussianReceiptPrivacyLedger)
	if !ok || !hmac.Equal([]byte(reference.SHA256), []byte(digest)) {
		return fmt.Errorf("formal-cox: common-ledger receipt reference mismatch")
	}
	return nil
}
