package main

import "fmt"

// formalGLMRegisteredPhase21TerminalEvidenceV1 is the sole bridge from the
// private Phase21 lifecycle into the public endpoint.  Every field is loaded
// and validated from Rock records; no share, key, path, or transient state
// crosses this boundary.
func formalGLMRegisteredPhase21TerminalEvidenceV1(state formalGLMRegisteredPhase21StageHostStateV1) (formalGLMPublicTerminalEvidenceV1, error) {
	var zero formalGLMPublicTerminalEvidenceV1
	context, _, _, binding, local, ticket, _, _, _, err := formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil || !formalFinalizerHandoffAuthorityEqual(local, binding.Finalizer) {
		return zero, fmt.Errorf("formal-glm registered Phase21 terminal: finalizer unavailable")
	}
	var ready formalGLMPhase21RockPublicationReadyRecord
	readyPath, err := formalGLMPhase21RockPublicationReadyRecordPath(state.rockRoot, context.artifactID)
	if err != nil || formalGLMPhase21RockReadJSON(state.rockRoot, readyPath, formalGLMPhase21RockMaxRecord, &ready) != nil || formalGLMPhase21RockValidatePublicationReadyRecord(ready, context, binding, ticket.Ticket) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 terminal: publication unavailable")
	}
	sha, err := formalGLMPhase21RockPublicCertificateDigest(ready.PublicCertificate)
	if err != nil {
		return zero, err
	}
	var commits [2]formalGLMPhase21RockCommitRecord
	var cleanups [2]formalGLMPhase21RockCleanupRecord
	for index, authority := range binding.Authorities {
		commitPath, cleanupPath := "", ""
		if authority.PeerName == local.PeerName {
			commitPath, err = formalGLMPhase21RockCommitRecordPath(state.rockRoot, context.artifactID, authority.Role)
			if err == nil {
				cleanupPath, err = formalGLMPhase21RockCleanupRecordPath(state.rockRoot, context.artifactID, authority.Role)
			}
		} else {
			commitPath, err = formalGLMRegisteredPhase21CommitInboxPathV1(state.rockRoot, context.artifactID, authority.Role)
			if err == nil {
				cleanupPath, err = formalGLMRegisteredPhase21CleanupInboxPathV1(state.rockRoot, context.artifactID, authority.Role)
			}
		}
		if err != nil || formalGLMPhase21RockReadJSON(state.rockRoot, commitPath, formalGLMPhase21RockMaxRecord, &commits[index]) != nil || formalGLMPhase21RockReadJSON(state.rockRoot, cleanupPath, formalGLMPhase21RockMaxRecord, &cleanups[index]) != nil {
			return zero, fmt.Errorf("formal-glm registered Phase21 terminal: incomplete peer records")
		}
		peer := formalFinalizerHandoffAuthority{PeerName: authority.PeerName, PeerID: authority.PeerID, Role: authority.Role}
		if formalGLMPhase21RockValidateCommitRecord(commits[index], context, peer) != nil || commits[index].Receipt.CertificateSHA256 != sha || formalGLMPhase21RockValidateCleanupRecord(cleanups[index], context, peer) != nil || cleanups[index].Receipt.CertificateSHA256 != sha {
			return zero, fmt.Errorf("formal-glm registered Phase21 terminal: invalid peer records")
		}
	}
	ackPath, err := formalGLMPhase21RockAckRecordPath(state.rockRoot, context.artifactID)
	if err != nil {
		return zero, err
	}
	var ack formalGLMPhase21RockAckRecord
	if formalGLMPhase21RockReadJSON(state.rockRoot, ackPath, formalGLMPhase21RockMaxRecord, &ack) != nil || formalGLMPhase21RockValidateAckRecord(ack, context, binding, ticket.Ticket, sha) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 terminal: ACK unavailable")
	}
	return formalGLMPublicTerminalEvidenceV1{Contract: context.contract, Binding: binding, Ticket: ticket.Ticket, Publication: ready.PublicCertificate, Commits: commits, Ack: ack, Cleanups: cleanups}, nil
}
