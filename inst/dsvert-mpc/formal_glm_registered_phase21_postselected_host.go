package main

// Private host operations for the post-Selected Phase16 signing relay.  They
// retain the Selected source, authority root, and Ed25519 key in the existing
// owner-only host; all return values are public admission records only.

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"reflect"
)

type formalGLMRegisteredPhase21PostSelectedHostInputsV1 struct {
	terminal      *formalGLMRegisteredPhase20TerminalOwnerV1
	policy        formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1
	authorityRoot [32]byte
	signing       ed25519.PrivateKey
	contract      formalGLMSourceContractV1
	pins          map[string]ed25519.PublicKey
	peer          string
}

func (inputs *formalGLMRegisteredPhase21PostSelectedHostInputsV1) clearV1() {
	if inputs == nil {
		return
	}
	clear(inputs.signing)
	inputs.signing = nil
	formalGLMRegisteredPhase21PostSelectedPhase16PolicyClearV1(&inputs.policy)
	formalGLMRegisteredPhase20TerminalClearPinsV1(inputs.pins)
	inputs.pins = nil
	clear(inputs.authorityRoot[:])
	inputs.terminal = nil
	inputs.contract = formalGLMSourceContractV1{}
	inputs.peer = ""
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) postSelectedInputsV1(
	owner *formalGLMRegisteredPhase20JobOwnerV1,
) (formalGLMRegisteredPhase21PostSelectedHostInputsV1, error) {
	var zero formalGLMRegisteredPhase21PostSelectedHostInputsV1
	if host == nil || owner == nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected host: unavailable")
	}
	host.mu.Lock()
	policy := host.phase16Policy
	authorityRoot := host.samplerAuthorityRoot
	closed := host.closed
	if policy == nil || closed {
		host.mu.Unlock()
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected host: policy unavailable")
	}
	policyCopy := *policy
	policyCopy.ReceiptReferences = append(
		[]jointDPBiomedicalGaussianReceiptReference(nil), policy.ReceiptReferences...)
	policyCopy.CustodianSignatures = make(
		[]jointDPBiomedicalGaussianSignature, len(policy.CustodianSignatures))
	for index, signature := range policy.CustodianSignatures {
		policyCopy.CustodianSignatures[index] = jointDPBiomedicalGaussianSignature{
			Signer: signature.Signer, Signature: append([]byte(nil), signature.Signature...),
		}
	}
	host.mu.Unlock()

	owner.mu.Lock()
	terminal := owner.terminal
	owner.mu.Unlock()
	if terminal == nil {
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyClearV1(&policyCopy)
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected host: terminal unavailable")
	}
	terminal.mu.Lock()
	if terminal.closed || terminal.attempts == nil {
		terminal.mu.Unlock()
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyClearV1(&policyCopy)
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected host: terminal unavailable")
	}
	attempts := terminal.attempts
	contract, peer := terminal.contract, terminal.peer
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(terminal.pins)
	terminal.mu.Unlock()
	attempts.mu.Lock()
	signing := append(ed25519.PrivateKey(nil), attempts.signingKey...)
	attempts.mu.Unlock()
	if len(signing) != ed25519.PrivateKeySize ||
		formalGLMRegisteredPhase21ValidatePostSelectedPhase16PolicyV1(
			policyCopy, contract, pins) != nil {
		clear(signing)
		formalGLMRegisteredPhase21PostSelectedPhase16PolicyClearV1(&policyCopy)
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		return zero, fmt.Errorf("formal-glm registered Phase21 post-Selected host: invalid local inputs")
	}
	return formalGLMRegisteredPhase21PostSelectedHostInputsV1{
		terminal: terminal, policy: policyCopy, authorityRoot: authorityRoot,
		signing: signing, contract: contract, pins: pins, peer: peer,
	}, nil
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) BuildPostSelectedAuthorityCommitmentV1() (
	formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1, error,
) {
	var zero formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1
	owner, done, err := host.beginOpV1()
	if err != nil {
		return zero, err
	}
	defer done()
	inputs, err := host.postSelectedInputsV1(owner)
	if err != nil {
		return zero, err
	}
	defer inputs.clearV1()
	selected, trusted, err := inputs.terminal.LoadSelectedSourceV1()
	if err != nil {
		return zero, err
	}
	defer trusted.clear()
	receiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(
		trusted.source.Result.FinalReceipts)
	if err != nil {
		return zero, err
	}
	policySHA256, err := formalGLMRegisteredPhase21PostSelectedPhase16PolicySHA256V1(inputs.policy)
	if err != nil {
		return zero, err
	}
	authority, err := formalGLMRegisteredPhase21PostSelectedComputeAuthorityV1(
		inputs.contract.Core.RegisteredExecutionPlan, inputs.peer)
	if err != nil {
		return zero, err
	}
	return formalGLMRegisteredPhase21DerivePostSelectedAuthorityCommitmentV1(
		inputs.authorityRoot, selected.SelectedSHA256, policySHA256,
		hex.EncodeToString(receiptDigest[:]), authority, inputs.signing)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) BuildPostSelectedPhase16V1(
	commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
) (formalGLMRegisteredPhase21PostSelectedPhase16V1, error) {
	var zero formalGLMRegisteredPhase21PostSelectedPhase16V1
	owner, done, err := host.beginOpV1()
	if err != nil {
		return zero, err
	}
	defer done()
	inputs, err := host.postSelectedInputsV1(owner)
	if err != nil {
		return zero, err
	}
	defer inputs.clearV1()
	selected, trusted, err := inputs.terminal.LoadSelectedSourceV1()
	if err != nil {
		return zero, err
	}
	defer trusted.clear()
	return formalGLMRegisteredPhase21BuildPostSelectedPhase16V1(
		selected, trusted.source, inputs.policy, inputs.contract, commitments, inputs.pins)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) AttestPostSelectedPhase16V1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
) (formalGLMRegisteredPhase21PostSelectedComputeAttestationV1, error) {
	var zero formalGLMRegisteredPhase21PostSelectedComputeAttestationV1
	owner, done, err := host.beginOpV1()
	if err != nil {
		return zero, err
	}
	defer done()
	inputs, err := host.postSelectedInputsV1(owner)
	if err != nil {
		return zero, err
	}
	defer inputs.clearV1()
	selected, trusted, err := inputs.terminal.LoadSelectedSourceV1()
	if err != nil {
		return zero, err
	}
	defer trusted.clear()
	return formalGLMRegisteredPhase21SignPostSelectedComputeAttestationV1(
		proposal, selected, trusted.source, inputs.policy, inputs.contract,
		commitments, inputs.peer, inputs.signing, inputs.pins)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) SignPostSelectedPhase16V1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
	attestations []formalGLMRegisteredPhase21PostSelectedComputeAttestationV1,
) (jointDPBiomedicalGaussianSignature, jointDPBiomedicalGaussianSignature, error) {
	var zero jointDPBiomedicalGaussianSignature
	owner, done, err := host.beginOpV1()
	if err != nil {
		return zero, zero, err
	}
	defer done()
	inputs, err := host.postSelectedInputsV1(owner)
	if err != nil {
		return zero, zero, err
	}
	defer inputs.clearV1()
	selected, trusted, err := inputs.terminal.LoadSelectedSourceV1()
	if err != nil {
		return zero, zero, err
	}
	defer trusted.clear()
	want, err := formalGLMRegisteredPhase21BuildPostSelectedPhase16V1(
		selected, trusted.source, inputs.policy, inputs.contract, commitments, inputs.pins)
	if err != nil || !reflect.DeepEqual(want, proposal) {
		return zero, zero, fmt.Errorf("formal-glm registered Phase21 post-Selected host: candidate mismatch")
	}
	return formalGLMRegisteredPhase21SignPostSelectedPhase16V1(
		proposal, inputs.policy, inputs.contract, attestations,
		inputs.peer, inputs.signing, inputs.pins)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) AdmitPostSelectedPhase16V1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
	attestations []formalGLMRegisteredPhase21PostSelectedComputeAttestationV1,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
) (formalGLMPhase16ProductiveAdmission, error) {
	var zero formalGLMPhase16ProductiveAdmission
	owner, done, err := host.beginOpV1()
	if err != nil {
		return zero, err
	}
	defer done()
	inputs, err := host.postSelectedInputsV1(owner)
	if err != nil {
		return zero, err
	}
	defer inputs.clearV1()
	selected, trusted, err := inputs.terminal.LoadSelectedSourceV1()
	if err != nil {
		return zero, err
	}
	defer trusted.clear()
	return formalGLMRegisteredPhase21AdmitPostSelectedPhase16V1(
		proposal, selected, trusted.source, inputs.policy, inputs.contract,
		commitments, attestations, backendSignatures, workerSignatures, inputs.pins)
}

// FinalizePostSelectedPhase16V1 is the single transition from the public
// post-Selected signatures into the private Phase21 asset set. It persists
// only after rebuilding and admitting the same candidate from this host's
// sealed Selected source. No caller-provided source, share, path, or key is
// accepted.
func (host *formalGLMRegisteredPhase20JobControlHostV1) FinalizePostSelectedPhase16V1(
	proposal formalGLMRegisteredPhase21PostSelectedPhase16V1,
	commitments []formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1,
	attestations []formalGLMRegisteredPhase21PostSelectedComputeAttestationV1,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
) error {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return err
	}
	defer done()
	inputs, err := host.postSelectedInputsV1(owner)
	if err != nil {
		return err
	}
	defer inputs.clearV1()
	selected, trusted, err := inputs.terminal.LoadSelectedSourceV1()
	if err != nil {
		return err
	}
	defer trusted.clear()
	admission, err := formalGLMRegisteredPhase21AdmitPostSelectedPhase16V1(
		proposal, selected, trusted.source, inputs.policy, inputs.contract,
		commitments, attestations, backendSignatures, workerSignatures, inputs.pins)
	if err != nil || !reflect.DeepEqual(admission.BackendSelection.Contract, proposal.BackendSelection) ||
		!reflect.DeepEqual(admission.Envelope.Preimage, proposal.WorkerPreimage) {
		return fmt.Errorf("formal-glm registered Phase21 post-Selected host: admission mismatch")
	}

	host.mu.Lock()
	current := host.publication
	if host.closed || current == nil {
		host.mu.Unlock()
		return fmt.Errorf("formal-glm registered Phase21 post-Selected host: publication unavailable")
	}
	next, err := formalGLMRegisteredPhase21PublicationContextCloneV1(
		*current, inputs.contract, inputs.pins)
	host.mu.Unlock()
	if err != nil {
		return err
	}
	next.Capsule = proposal.Capsule
	next.Request = proposal.Request
	next.BackendSignatures = jointDPBiomedicalGaussianFullCloneSignatures(
		jointDPBiomedicalGaussianCanonicalSignatures(backendSignatures))
	next.WorkerSignatures = jointDPBiomedicalGaussianFullCloneSignatures(
		jointDPBiomedicalGaussianCanonicalSignatures(workerSignatures))
	inputs.terminal.mu.Lock()
	authorityRoot := ""
	if !inputs.terminal.closed && inputs.terminal.attempts != nil && inputs.terminal.attempts.root != nil {
		authorityRoot = filepath.Join(inputs.terminal.attempts.root.Name(), inputs.terminal.peer)
	}
	inputs.terminal.mu.Unlock()
	if err := formalGLMRegisteredPhase21PersistSelectedPublicationContextV1(
		inputs.terminal, authorityRoot, next, inputs.contract, inputs.pins); err != nil {
		formalGLMRegisteredPhase21PublicationContextClearV1(&next)
		return err
	}
	host.mu.Lock()
	if host.closed || host.publication != current {
		host.mu.Unlock()
		formalGLMRegisteredPhase21PublicationContextClearV1(&next)
		return fmt.Errorf("formal-glm registered Phase21 post-Selected host: publication changed")
	}
	host.publication = &next
	host.mu.Unlock()
	formalGLMRegisteredPhase21PublicationContextClearV1(current)
	return nil
}
