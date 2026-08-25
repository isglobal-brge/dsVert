package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func formalGLMRegisteredPhase20JobControlHostComputeConfigV1(
	t testing.TB,
	fixture *formalGLMRegisteredPhase20JobComputeTestFixtureV1,
	index int,
) formalGLMRegisteredPhase20JobControlHostConfigV1 {
	t.Helper()
	peer := fixture.provenance.source.plan.DesignatedComputePeers[index]
	pins := formalGLMRegisteredPhase19ScheduleTailClonePinsV1(
		fixture.provenance.source.inputs.identities.public)
	publication := formalGLMRegisteredPhase21PublicationContextTestBuildV1(
		t, fixture.provenance.source)
	policy := formalGLMRegisteredPhase21PostSelectedPolicyTestV1(
		t, fixture.provenance.source.contract, pins,
		fixture.provenance.source.inputs.identities.private)
	return formalGLMRegisteredPhase20JobControlHostConfigV1{
		Version:              formalGLMRegisteredPhase20JobControlHostVersionV1,
		Contract:             fixture.provenance.source.contract,
		Record:               fixture.record,
		Pins:                 pins,
		Peer:                 peer,
		Signing:              append([]byte(nil), fixture.provenance.source.inputs.identities.private[peer]...),
		SamplerAuthorityRoot: formalGLMRegisteredPhase21PublicationContextTestAuthorityRootV1(peer),
		Start: formalGLMRegisteredPhase20JobStartV1{
			ArtifactID:       fixture.record.Binding.ArtifactID,
			ReceiptSetSHA256: fixture.record.Binding.ReceiptSetSHA256,
		},
		Publication:   &publication,
		Phase16Policy: &policy,
	}
}

func formalGLMRegisteredPhase20JobControlHostPostSelectedFrameV1(
	t testing.TB, host *formalGLMRegisteredPhase20JobControlHostV1,
	action string, frames [][]byte,
) []byte {
	t.Helper()
	payload := json.RawMessage(`{}`)
	if frames != nil {
		encoded, err := json.Marshal(
			formalGLMRegisteredPhase20JobControlHostDaemonPostSelectedFramesV1{Frames: frames})
		if err != nil {
			t.Fatal(err)
		}
		payload = encoded
	}
	response, err := (&formalGLMRegisteredPhase20JobControlHostDaemonV1{host: host}).dispatchV1(
		action, payload)
	clear(payload)
	if err != nil {
		t.Fatalf("post-Selected %s: %v", action, err)
	}
	var envelope formalGLMRegisteredPhase20JobControlHostDaemonPostSelectedFrameV1
	if err := formalGLMPhase21RockStrictDecode(response, &envelope); err != nil {
		clear(response)
		t.Fatalf("post-Selected %s returned invalid frame: %v", action, err)
	}
	clear(response)
	return append([]byte(nil), envelope.Frame...)
}

func formalGLMRegisteredPhase20JobControlHostPostSelectedFinalizeV1(
	t testing.TB, host *formalGLMRegisteredPhase20JobControlHostV1, frames [][]byte,
) {
	t.Helper()
	encoded, err := json.Marshal(
		formalGLMRegisteredPhase20JobControlHostDaemonPostSelectedFramesV1{Frames: frames})
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&formalGLMRegisteredPhase20JobControlHostDaemonV1{host: host}).dispatchV1(
		"phase16_postselected_finalize", encoded)
	clear(encoded)
	if err != nil || formalGLMPhase21RockStrictDecode(response, &struct{}{}) != nil {
		clear(response)
		t.Fatalf("post-Selected finalization failed: %v", err)
	}
	clear(response)
}

// formalGLMRegisteredPhase20JobControlHostPostSelectedWitnessFrameV1 crosses
// the same closed Phase18 source-command boundary used by a non-compute
// custodian.  The witness sees only the already public policy, proposal and
// compute attestations; it never receives a Selected record or a handoff.
func formalGLMRegisteredPhase20JobControlHostPostSelectedWitnessFrameV1(
	t testing.TB, fixture *formalGLMRegisteredPhase20JobComputeTestFixtureV1,
	policy formalGLMRegisteredPhase21PostSelectedPhase16PolicyV1, peer string,
	proposalFrame []byte, attestationFrames [][]byte,
) []byte {
	t.Helper()
	if len(attestationFrames) != 2 {
		t.Fatal("post-Selected witness requires exactly two attestations")
	}
	contractJSON, err := json.Marshal(fixture.provenance.source.contract)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(contractJSON)
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(policyJSON)
	command := formalGLMRegisteredPhase18SourceCommandV1{
		Version:                    formalGLMRegisteredPhase18SourceCommandVersionV1,
		Action:                     formalGLMRegisteredPhase18SourceCommandActionPostSelectedSignV1,
		SourceContractJSON:         string(contractJSON),
		Pins:                       formalGLMRegisteredPhase18SourceCommandTestPinsV1(t, fixture.provenance.source.inputs.identities.public),
		LocalPeerName:              peer,
		LocalSigningKey:            base64.StdEncoding.EncodeToString(fixture.provenance.source.inputs.identities.private[peer]),
		Phase16PolicyJSON:          string(policyJSON),
		PostSelectedProposalBase64: base64.StdEncoding.EncodeToString(proposalFrame),
		PostSelectedAttestationsBase64: []string{
			base64.StdEncoding.EncodeToString(attestationFrames[0]),
			base64.StdEncoding.EncodeToString(attestationFrames[1]),
		},
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	response, err := formalGLMRegisteredPhase18SourceCommandRunAtRootV1(encoded, t.TempDir())
	if err != nil || response.Version != formalGLMRegisteredPhase18SourceCommandVersionV1 ||
		response.Replayed || response.PostSelectedSignaturePairBase64 == "" {
		t.Fatalf("post-Selected witness command: %#v / %v", response, err)
	}
	frame, err := base64.StdEncoding.Strict().DecodeString(response.PostSelectedSignaturePairBase64)
	if err != nil || base64.StdEncoding.EncodeToString(frame) != response.PostSelectedSignaturePairBase64 {
		clear(frame)
		t.Fatalf("post-Selected witness response was not canonical: %v", err)
	}
	var pair formalGLMRegisteredPhase20JobControlHostDaemonPostSelectedSignaturePairV1
	if err := formalGLMPhase21RockStrictDecode(frame, &pair); err != nil ||
		pair.Backend.Signer != peer || pair.Worker.Signer != peer {
		clear(frame)
		t.Fatalf("post-Selected witness signature pair: %#v / %v", pair, err)
	}
	return frame
}

func formalGLMRegisteredPhase20JobControlHostComputeRelayV1(
	stop <-chan struct{}, from, to *formalGLMRegisteredPhase20JobControlHostV1,
	fromRef, toRef formalGLMRegisteredPhase20JobRefV1,
	errs chan<- error, done chan<- struct{},
) {
	defer func() { done <- struct{}{} }()
	ack := int64(0)
	for {
		select {
		case <-stop:
			return
		default:
		}
		result, err := from.PollV1(fromRef, ack)
		if err != nil {
			errs <- err
			return
		}
		if result.RelayChunk == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		ack, err = to.RelayV1(toRef, *result.RelayChunk)
		if err != nil {
			errs <- err
			return
		}
	}
}

func formalGLMRegisteredPhase20JobControlHostRunsFromPendingIngressV1(
	t *testing.T, family string, custodians int,
) {
	t.Helper()
	if family != "binomial" && family != "poisson" {
		t.Fatalf("unsupported registered GLM family %q", family)
	}
	fixture := formalGLMRegisteredPhase20JobComputeTestBuildWithValuesV1(
		t, family, custodians, 9,
		func(authorization formalGLMRegisteredPhase18AuthorizationV1,
			blockIndex int,
		) ([]string, []bool) {
			return formalGLMRegisteredPhase20JobControlHostPlausibleBlockValuesV1(
				family, authorization, blockIndex)
		}, true)
	for index := range fixture.roots {
		formalGLMRegisteredPhase20JobIngressBridgeTestPersistPendingV1(t, fixture, index)
		if err := fixture.owners[index].Close(); err != nil {
			t.Fatal(err)
		}
		fixture.owners[index] = nil
	}
	hosts := [2]*formalGLMRegisteredPhase20JobControlHostV1{}
	for index := range hosts {
		config := formalGLMRegisteredPhase20JobControlHostComputeConfigV1(t, fixture, index)
		host, err := newFormalGLMRegisteredPhase20JobControlHostV1(
			fixture.roots[index], config)
		if err != nil {
			t.Fatal(err)
		}
		hosts[index] = host
		t.Cleanup(func() { _ = host.Close() })
		encoded, marshalErr := json.Marshal(host)
		if marshalErr != nil || string(encoded) != "{}" {
			t.Fatalf("host %d exposed private compute state: %q / %v", index, encoded, marshalErr)
		}
	}
	waiting, err := hosts[1].NegotiateV1(nil)
	if err != nil || waiting.state != formalGLMRegisteredPhase20JobControlWaitingProposalStateV1 {
		t.Fatalf("evaluator waiting: %+v / %v", waiting, err)
	}
	proposal, err := hosts[0].NegotiateV1(nil)
	if err != nil || len(proposal.outbound) == 0 {
		t.Fatalf("garbler proposal: %+v / %v", proposal, err)
	}
	accept, err := hosts[1].NegotiateV1(proposal.outbound)
	if err != nil || len(accept.outbound) == 0 {
		t.Fatalf("evaluator accept: %+v / %v", accept, err)
	}
	if _, err := hosts[0].NegotiateV1(accept.outbound); err != nil {
		t.Fatal(err)
	}
	refs := [2]formalGLMRegisteredPhase20JobRefV1{}
	claims := [2][]byte{}
	for index := range hosts {
		started, startErr := hosts[index].StartOrInspectV1()
		if startErr != nil || started.state != formalGLMRegisteredPhase20JobOwnerRunningStateV1 ||
			started.inspectOnly || started.productionReady {
			t.Fatalf("host %d start: %+v / %v", index, started, startErr)
		}
		refs[index], claims[index], err = hosts[index].JobRefV1()
		if err != nil || refs[index].ProductionReady || len(claims[index]) == 0 {
			t.Fatalf("host %d ref: %+v / %v", index, refs[index], err)
		}
	}
	if refs[0] != refs[1] {
		t.Fatal("hosts derived different job refs")
	}
	for index := range hosts {
		if err := hosts[index].BindPeerJobRefV1(claims[1-index]); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	relayErrs := make(chan error, 2)
	relayDone := make(chan struct{}, 2)
	for index := range hosts {
		go formalGLMRegisteredPhase20JobControlHostComputeRelayV1(
			stop, hosts[index], hosts[1-index], refs[index], refs[1-index],
			relayErrs, relayDone)
	}
	completed := make(chan error, 2)
	for index := range hosts {
		go func(index int) { completed <- hosts[index].RunComputeV1() }(index)
	}
	for range hosts {
		select {
		case runErr := <-completed:
			if runErr != nil {
				close(stop)
				<-relayDone
				<-relayDone
				t.Fatal(runErr)
			}
		case relayErr := <-relayErrs:
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal(relayErr)
		case <-time.After(90 * time.Second):
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal("host compute did not complete")
		}
	}
	var commits [2]formalGLMPhase20HandoffCommit
	terminalErrs := make(chan error, 2)
	for index := range hosts {
		go func(index int) {
			commit, terminalErr := hosts[index].RunTerminalV1()
			commits[index] = commit
			terminalErrs <- terminalErr
		}(index)
	}
	for range hosts {
		select {
		case terminalErr := <-terminalErrs:
			if terminalErr != nil {
				close(stop)
				<-relayDone
				<-relayDone
				t.Fatal(terminalErr)
			}
		case relayErr := <-relayErrs:
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal(relayErr)
		case <-time.After(90 * time.Second):
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal("host terminal did not complete")
		}
	}
	var replays [2]formalGLMPhase20HandoffCommit
	replayErrs := make(chan error, 2)
	for index := range hosts {
		go func(index int) {
			commit, terminalErr := hosts[index].RunTerminalV1()
			replays[index] = commit
			replayErrs <- terminalErr
		}(index)
	}
	for range hosts {
		select {
		case terminalErr := <-replayErrs:
			if terminalErr != nil {
				close(stop)
				<-relayDone
				<-relayDone
				t.Fatal(terminalErr)
			}
		case relayErr := <-relayErrs:
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal(relayErr)
		case <-time.After(90 * time.Second):
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal("host terminal replay did not complete")
		}
	}
	close(stop)
	<-relayDone
	<-relayDone
	select {
	case relayErr := <-relayErrs:
		t.Fatal(relayErr)
	default:
	}
	for index, host := range hosts {
		host.mu.Lock()
		owner := host.owner
		host.mu.Unlock()
		owner.mu.Lock()
		sealed := owner.terminal != nil && owner.attempts == nil && owner.jobKeys == nil
		owner.mu.Unlock()
		if !sealed {
			t.Fatalf("host %d did not retain only the sealed terminal owner", index)
		}
		if !formalGLMIsSHA256(commits[index].SHA256) || commits[index].Bytes < 64 ||
			commits[index].Replayed {
			t.Fatalf("host %d did not commit an encrypted terminal handoff: %#v", index, commits[index])
		}
		if !replays[index].Replayed || replays[index].SHA256 != commits[index].SHA256 ||
			replays[index].Bytes != commits[index].Bytes {
			t.Fatalf("host %d terminal replay changed the handoff: %#v", index, replays[index])
		}
		owner.mu.Lock()
		terminal := owner.terminal
		owner.mu.Unlock()
		status, statusErr := terminal.LoadStatusV1()
		if statusErr != nil || status.selected == nil ||
			status.selected.OpeningsPerformed != 0 || status.selected.ProductionReady {
			t.Fatalf("host %d terminal status: %#v / %v", index, status, statusErr)
		}
		assets, assetsErr := formalGLMRegisteredPhase21PublicationAssetsPathsV1(
			filepath.Join(fixture.roots[index], owner.terminal.peer),
			fixture.provenance.source.contract.Core.SamplerV2ContractCore.ArtifactID)
		if assetsErr != nil {
			t.Fatal(assetsErr)
		}
		for _, path := range []string{assets.contractPath, assets.pinsetPath, assets.resolutionPath} {
			info, statErr := os.Lstat(path)
			if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("host %d did not persist Phase21 asset %q: %v / %#v", index, path, statErr, info)
			}
		}
	}
	policy := formalGLMRegisteredPhase21PostSelectedPolicyTestV1(
		t, fixture.provenance.source.contract, fixture.provenance.source.inputs.identities.public,
		fixture.provenance.source.inputs.identities.private)
	commitmentFrames := make([][]byte, 2)
	commitments := make([]formalGLMRegisteredPhase21PostSelectedAuthorityCommitmentV1, 2)
	for index, host := range hosts {
		commitmentFrames[index] = formalGLMRegisteredPhase20JobControlHostPostSelectedFrameV1(
			t, host, "phase16_postselected_commitment", nil)
		if err := formalGLMPhase21RockStrictDecode(commitmentFrames[index], &commitments[index]); err != nil {
			t.Fatalf("host %d authority commitment frame: %v", index, err)
		}
	}
	tamperedCommitment := append([]byte(nil), commitmentFrames[0]...)
	tamperedCommitment[len(tamperedCommitment)-1] ^= 1
	tamperedRequest, err := json.Marshal(
		formalGLMRegisteredPhase20JobControlHostDaemonPostSelectedFramesV1{
			Frames: [][]byte{tamperedCommitment, commitmentFrames[1]},
		})
	if err != nil {
		clear(tamperedCommitment)
		t.Fatal(err)
	}
	response, err := (&formalGLMRegisteredPhase20JobControlHostDaemonV1{host: hosts[0]}).dispatchV1(
		"phase16_postselected_proposal", tamperedRequest)
	clear(tamperedRequest)
	if err == nil {
		clear(response)
		clear(tamperedCommitment)
		t.Fatal("host accepted a tampered post-Selected commitment")
	}
	clear(tamperedCommitment)
	proposals := [2]formalGLMRegisteredPhase21PostSelectedPhase16V1{}
	proposalFrames := make([][]byte, 2)
	for index, host := range hosts {
		proposalFrames[index] = formalGLMRegisteredPhase20JobControlHostPostSelectedFrameV1(
			t, host, "phase16_postselected_proposal", commitmentFrames)
		if err := formalGLMPhase21RockStrictDecode(proposalFrames[index], &proposals[index]); err != nil {
			t.Fatalf("host %d post-Selected proposal frame: %v", index, err)
		}
	}
	if !reflect.DeepEqual(proposals[0], proposals[1]) {
		t.Fatal("compute hosts derived different post-Selected Phase16 proposals")
	}
	attestations := make([]formalGLMRegisteredPhase21PostSelectedComputeAttestationV1, 0, 2)
	attestationFrames := make([][]byte, 2)
	for index, host := range hosts {
		attestationFrames[index] = formalGLMRegisteredPhase20JobControlHostPostSelectedFrameV1(
			t, host, "phase16_postselected_attestation",
			[][]byte{proposalFrames[index], commitmentFrames[0], commitmentFrames[1]})
		var attestation formalGLMRegisteredPhase21PostSelectedComputeAttestationV1
		if err := formalGLMPhase21RockStrictDecode(attestationFrames[index], &attestation); err != nil {
			t.Fatalf("host %d post-Selected attestation frame: %v", index, err)
		}
		attestations = append(attestations, attestation)
	}
	signatureFrames := make([][]byte, 0, custodians)
	for _, peer := range fixture.provenance.source.plan.CustodianPeers {
		var signatureErr error
		if peer == fixture.provenance.source.plan.DesignatedComputePeers[0] {
			frame := formalGLMRegisteredPhase20JobControlHostPostSelectedFrameV1(
				t, hosts[0], "phase16_postselected_sign",
				[][]byte{proposalFrames[0], commitmentFrames[0], commitmentFrames[1],
					attestationFrames[0], attestationFrames[1]})
			var pair formalGLMRegisteredPhase20JobControlHostDaemonPostSelectedSignaturePairV1
			signatureErr = formalGLMPhase21RockStrictDecode(frame, &pair)
			signatureFrames = append(signatureFrames, frame)
		} else if peer == fixture.provenance.source.plan.DesignatedComputePeers[1] {
			frame := formalGLMRegisteredPhase20JobControlHostPostSelectedFrameV1(
				t, hosts[1], "phase16_postselected_sign",
				[][]byte{proposalFrames[0], commitmentFrames[0], commitmentFrames[1],
					attestationFrames[0], attestationFrames[1]})
			var pair formalGLMRegisteredPhase20JobControlHostDaemonPostSelectedSignaturePairV1
			signatureErr = formalGLMPhase21RockStrictDecode(frame, &pair)
			signatureFrames = append(signatureFrames, frame)
		} else {
			frame := formalGLMRegisteredPhase20JobControlHostPostSelectedWitnessFrameV1(
				t, fixture, policy, peer, proposalFrames[0], attestationFrames)
			var pair formalGLMRegisteredPhase20JobControlHostDaemonPostSelectedSignaturePairV1
			signatureErr = formalGLMPhase21RockStrictDecode(frame, &pair)
			signatureFrames = append(signatureFrames, frame)
		}
		if signatureErr != nil {
			t.Fatalf("post-Selected signature %s: %v", peer, signatureErr)
		}
	}
	for index, host := range hosts {
		finalFrames := make([][]byte, 0, 5+len(signatureFrames))
		finalFrames = append(finalFrames, proposalFrames[index], commitmentFrames[0], commitmentFrames[1],
			attestationFrames[0], attestationFrames[1])
		finalFrames = append(finalFrames, signatureFrames...)
		formalGLMRegisteredPhase20JobControlHostPostSelectedFinalizeV1(t, host, finalFrames)
		formalGLMRegisteredPhase20JobControlHostPostSelectedFinalizeV1(t, host, finalFrames)
		host.mu.Lock()
		owner := host.owner
		host.mu.Unlock()
		owner.mu.Lock()
		terminal := owner.terminal
		owner.mu.Unlock()
		terminal.mu.Lock()
		authorityRoot := filepath.Join(fixture.roots[index], terminal.peer)
		terminal.mu.Unlock()
		assets, assetsErr := formalGLMRegisteredPhase21PublicationAssetsPathsV1(
			authorityRoot, fixture.provenance.source.contract.Core.ArtifactID)
		host.mu.Lock()
		stageReady, stageErr := formalGLMRegisteredPhase21PublicationStageInputsV1(*host.publication)
		host.mu.Unlock()
		if assetsErr != nil || stageErr != nil || !stageReady {
			t.Fatalf("host %d did not create Stage-ready assets: %#v / %v", index, assets, assetsErr)
		}
		for _, path := range []string{
			assets.capsulePath, assets.requestPath, assets.backendSignaturesPath,
			assets.workerSignaturesPath, assets.samplerAuthorizationsPath,
		} {
			info, statErr := os.Lstat(path)
			if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("host %d did not persist post-Selected asset %q: %v / %#v",
					index, path, statErr, info)
			}
		}
	}
	var preflight [2]formalGLMPhase21RockPreflightRecord
	var preflightFrames [2][]byte
	for index, host := range hosts {
		response, preflightErr := (&formalGLMRegisteredPhase20JobControlHostDaemonV1{host: host}).dispatchV1(
			"phase21_preflight", json.RawMessage(`{}`))
		if preflightErr != nil {
			t.Fatalf("host %d Phase21 preflight: %v", index, preflightErr)
		}
		var frame formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1
		if err := formalGLMPhase21RockStrictDecode(response, &frame); err != nil ||
			formalGLMPhase21RockStrictDecode(frame.Frame, &preflight[index]) != nil ||
			preflight[index].Receipt.State != formalGLMPhase21RockStateAbsent ||
			preflight[index].ProductionReady {
			t.Fatalf("host %d Phase21 preflight frame: %#v / %v", index, frame, err)
		}
		preflightFrames[index] = append([]byte(nil), frame.Frame...)
	}
	tamperedPreflight := preflight[0]
	tamperedPreflight.Receipt.Signature = append([]byte(nil), preflight[0].Receipt.Signature...)
	tamperedPreflight.Receipt.Signature[0] ^= 1
	tamperedFrame, err := json.Marshal(tamperedPreflight)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPreflightRequest, err := json.Marshal(
		formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1{Frame: tamperedFrame})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&formalGLMRegisteredPhase20JobControlHostDaemonV1{host: hosts[1]}).dispatchV1(
		"phase21_preflight_bind", tamperedPreflightRequest); err == nil {
		t.Fatal("accepted tampered Phase21 peer preflight")
	}
	localRequest, err := json.Marshal(
		formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1{Frame: preflightFrames[0]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&formalGLMRegisteredPhase20JobControlHostDaemonV1{host: hosts[0]}).dispatchV1(
		"phase21_preflight_bind", localRequest); err == nil {
		t.Fatal("accepted local Phase21 preflight as peer input")
	}
	for index, host := range hosts {
		request, requestErr := json.Marshal(
			formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1{Frame: preflightFrames[1-index]})
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if _, err := (&formalGLMRegisteredPhase20JobControlHostDaemonV1{host: host}).dispatchV1(
			"phase21_preflight_bind", request); err != nil {
			t.Fatalf("host %d did not import the signed peer preflight: %v", index, err)
		}
		replayResponse, replayErr := (&formalGLMRegisteredPhase20JobControlHostDaemonV1{host: host}).dispatchV1(
			"phase21_preflight", json.RawMessage(`{}`))
		var replayFrame formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1
		if replayErr != nil || formalGLMPhase21RockStrictDecode(replayResponse, &replayFrame) != nil ||
			!bytes.Equal(replayFrame.Frame, preflightFrames[index]) {
			t.Fatalf("host %d preflight replay changed: %q / %v", index, replayResponse, replayErr)
		}
	}
	formalGLMRegisteredPhase20JobControlHostRunPhase21V1(
		t, hosts, fixture.provenance.source.inputs.identities.public)
}

// The full public-release fixture keeps every source coordinate within the
// signed input range. The separate materialization tests retain their
// above-2^53 and negative Ring128 stress rows; those must fail closed at the
// protected boundary rather than masquerade as a plausible clinical release.
func formalGLMRegisteredPhase20JobControlHostPlausibleBlockValuesV1(
	family string,
	authorization formalGLMRegisteredPhase18AuthorizationV1,
	blockIndex int,
) ([]string, []bool) {
	geometry := authorization.Geometry
	values := make([]string, geometry.BlockCapacity*geometry.CoordinateCount)
	for index := range values {
		values[index] = "0"
	}
	validity := make([]bool, geometry.BlockCapacity)
	offset := blockIndex * geometry.BlockCapacity
	for row := 0; row < geometry.BlockCapacity; row++ {
		if offset+row >= geometry.TotalCapacity {
			continue
		}
		validity[row] = true
		for coordinate, owner := range geometry.CoordinateOwners {
			if owner == authorization.LocalSource.SignerPeerName {
				value := int64(256)
				switch coordinate {
				case geometry.CoordinateCount - 2:
					if family == "poisson" {
						value = int64(offset+row) % 3 * 256
					} else {
						value = int64(offset+row) % 2 * 256
					}
				case geometry.CoordinateCount - 1:
					value = int64((offset+row)%3-1) * 64
				}
				values[row*geometry.CoordinateCount+coordinate] = fmt.Sprintf("%d", value)
			}
		}
	}
	return values, validity
}

// formalGLMRegisteredPhase20JobControlHostRunPhase21V1 continues the exact
// host that produced the selected Phase20 terminal. It uses only private host
// methods and checks the public result only after dual commit, ACK and cleanup.
func formalGLMRegisteredPhase20JobControlHostRunPhase21V1(
	t testing.TB,
	hosts [2]*formalGLMRegisteredPhase20JobControlHostV1,
	pins map[string]ed25519.PublicKey,
) {
	t.Helper()
	for index, host := range hosts {
		if status, err := host.StartPhase21StageV1(); err != nil ||
			status.State == formalGLMRegisteredPhase21StageFailedV1 || status.ProductionReady {
			t.Fatalf("host %d Phase21 Stage start: %#v / %v", index, status, err)
		}
	}
	var acknowledgements [2]*formalGLMRegisteredPhase21StageRelayAckV1
	deadline := time.Now().Add(90 * time.Second)
	for {
		complete := 0
		for index, host := range hosts {
			status, err := host.Phase21StageStatusV1()
			if err != nil || status.State == formalGLMRegisteredPhase21StageFailedV1 ||
				status.ProductionReady {
				host.mu.Lock()
				task := host.stage
				host.mu.Unlock()
				var failure error
				if task != nil {
					task.mu.Lock()
					failure = task.failure
					task.mu.Unlock()
				}
				t.Fatalf("host %d Phase21 Stage status: %#v / %v / %v", index, status, err, failure)
			}
			if status.State == formalGLMRegisteredPhase21StageCompleteV1 {
				complete++
			}
		}
		if complete == len(hosts) {
			break
		}
		for index, host := range hosts {
			chunk, err := host.PollPhase21StageV1(acknowledgements[index])
			acknowledgements[index] = nil
			if err != nil {
				t.Fatalf("host %d Phase21 Stage poll: %v", index, err)
			}
			if chunk == nil {
				continue
			}
			acknowledgement, err := hosts[1-index].RelayPhase21StageV1(*chunk)
			if err != nil {
				t.Fatalf("host %d Phase21 Stage relay: %v", index, err)
			}
			acknowledgements[index] = &acknowledgement
		}
		if time.Now().After(deadline) {
			t.Fatal("registered Phase21 Stage did not complete")
		}
		time.Sleep(time.Millisecond)
	}

	var stages [2]formalGLMPhase21RockStageRecord
	for index, host := range hosts {
		status, err := host.Phase21StageStatusV1()
		if err != nil || status.State != formalGLMRegisteredPhase21StageCompleteV1 ||
			status.Stage == nil || status.Stage.ProductionReady {
			t.Fatalf("host %d Phase21 Stage record: %#v / %v", index, status, err)
		}
		stages[index] = *status.Stage
	}
	for index, host := range hosts {
		if err := host.ImportPhase21PeerStageV1(stages[1-index]); err != nil {
			t.Fatalf("host %d Phase21 peer Stage: %v", index, err)
		}
	}

	ticket, err := hosts[0].RunPhase21TicketV1()
	if err != nil || ticket.ProductionReady {
		t.Fatalf("Phase21 ticket: %#v / %v", ticket, err)
	}
	if err := hosts[1].ImportPhase21PeerTicketV1(ticket); err != nil {
		t.Fatalf("Phase21 peer ticket: %v", err)
	}
	var seals [2]formalGLMPhase21RockSealRecord
	for index, host := range hosts {
		seals[index], err = host.RunPhase21SealV1()
		if err != nil || seals[index].ProductionReady {
			t.Fatalf("host %d Phase21 seal: %#v / %v", index, seals[index], err)
		}
	}
	for index, host := range hosts {
		if err := host.ImportPhase21PeerSealV1(seals[1-index]); err != nil {
			t.Fatalf("host %d Phase21 peer seal: %v", index, err)
		}
	}
	var envelopes [2]formalFinalizerHandoffEnvelope
	for index, host := range hosts {
		envelopes[index], err = host.ExportPhase21LocalOneDrawEnvelopeV1()
		if err != nil {
			t.Fatalf("host %d Phase21 local ciphertext envelope: %v", index, err)
		}
	}
	for index := range envelopes {
		if err := hosts[0].ImportPhase21FinalizerOneDrawEnvelopeV1(envelopes[index]); err != nil {
			t.Fatalf("Phase21 finalizer ciphertext envelope %d: %v", index, err)
		}
		clear(envelopes[index].Ciphertext)
		clear(envelopes[index].Signature)
	}
	candidate, err := hosts[0].RunPhase21CandidateV1()
	if err != nil || candidate.ProductionReady {
		t.Fatalf("Phase21 candidate: %#v / %v", candidate, err)
	}
	if err := hosts[1].ImportPhase21PeerCandidateV1(candidate); err != nil {
		t.Fatalf("Phase21 peer candidate: %v", err)
	}
	var releases [2]formalGLMPhase21RockLocalReleaseRecord
	for index, host := range hosts {
		releases[index], err = host.VerifyPhase21CandidateV1()
		if err != nil || releases[index].ProductionReady {
			t.Fatalf("host %d Phase21 candidate verification: %#v / %v", index, releases[index], err)
		}
	}
	for index, host := range hosts {
		if err := host.ImportPhase21PeerLocalReleaseV1(releases[1-index]); err != nil {
			t.Fatalf("host %d Phase21 peer local release: %v", index, err)
		}
	}
	certificate, err := hosts[0].RunPhase21BaseCertificateV1()
	if err != nil || certificate.ProductionReady {
		t.Fatalf("Phase21 base certificate: %#v / %v", certificate, err)
	}
	if err := hosts[1].ImportPhase21PeerBaseCertificateV1(certificate); err != nil {
		t.Fatalf("Phase21 peer base certificate: %v", err)
	}
	firstAuthorization, err := hosts[0].RunPhase21AuthorizationV1()
	if err != nil || firstAuthorization.ProductionReady {
		t.Fatalf("Phase21 first authorization: %#v / %v", firstAuthorization, err)
	}
	if err := hosts[1].ImportPhase21PeerAuthorizationV1(firstAuthorization); err != nil {
		t.Fatalf("Phase21 peer first authorization: %v", err)
	}
	secondAuthorization, err := hosts[1].RunPhase21AuthorizationV1()
	if err != nil || secondAuthorization.ProductionReady {
		t.Fatalf("Phase21 second authorization: %#v / %v", secondAuthorization, err)
	}
	if err := hosts[0].ImportPhase21PeerAuthorizationV1(secondAuthorization); err != nil {
		t.Fatalf("Phase21 peer second authorization: %v", err)
	}
	publication, err := hosts[0].RunPhase21PublicationV1()
	if err != nil || publication.ProductionReady ||
		formalGLMPhase21ValidatePublicCertificateV2(publication, pins) != nil {
		t.Fatalf("Phase21 publication: %#v / %v", publication, err)
	}
	replay, replayErr := hosts[0].RunPhase21PublicationV1()
	if replayErr != nil || !reflect.DeepEqual(replay, publication) {
		t.Fatalf("Phase21 publication replay changed: %#v / %#v / %v", replay, publication, replayErr)
	}
	var commits [2]formalGLMPhase21RockCommitRecord
	for index, host := range hosts {
		commits[index], err = host.RunPhase21CommitV1(publication)
		if err != nil || commits[index].ProductionReady {
			t.Fatalf("host %d Phase21 commit: %#v / %v", index, commits[index], err)
		}
	}
	if err := hosts[0].ImportPhase21PeerCommitV1(commits[1]); err != nil {
		t.Fatalf("Phase21 peer commit: %v", err)
	}
	ack, err := hosts[0].RunPhase21AckV1()
	if err != nil || ack.ProductionReady {
		t.Fatalf("Phase21 ACK: %#v / %v", ack, err)
	}
	if err := hosts[1].ImportPhase21PeerAckV1(ack, publication); err != nil {
		t.Fatalf("Phase21 peer ACK: %v", err)
	}
	var cleanups [2]formalGLMPhase21RockCleanupRecord
	for index, host := range hosts {
		cleanups[index], err = host.RunPhase21CleanupV1(publication)
		if err != nil || cleanups[index].ProductionReady {
			t.Fatalf("host %d Phase21 cleanup: %#v / %v", index, cleanups[index], err)
		}
	}
	if err := hosts[0].ImportPhase21PeerCleanupV1(cleanups[1]); err != nil {
		t.Fatalf("Phase21 peer cleanup: %v", err)
	}
	public, err := formalGLMPublicResultFromCertificateV1(publication, pins)
	if err != nil || public.ProductionReady || len(public.Coefficients) == 0 {
		t.Fatalf("Phase21 public result: %#v / %v", public, err)
	}
	for _, coefficient := range public.Coefficients {
		if math.IsNaN(coefficient.Value) || math.IsInf(coefficient.Value, 0) {
			t.Fatalf("Phase21 public coefficient is not finite: %#v", coefficient)
		}
	}
}

func TestFormalGLMRegisteredPhase20JobControlHostRunsK2K3K5FromPendingIngress(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			for _, custodians := range []int{2, 3, 5} {
				t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
					formalGLMRegisteredPhase20JobControlHostRunsFromPendingIngressV1(
						t, family, custodians)
				})
			}
		})
	}
}
