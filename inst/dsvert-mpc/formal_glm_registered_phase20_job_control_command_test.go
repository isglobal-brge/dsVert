package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestFormalGLMRegisteredPhase20JobControlUsesProvisionedHost(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	config := formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 1)
	encodedProvision, err := json.Marshal(formalGLMRegisteredPhase20JobControlHostProvisionV1{
		Version: formalGLMRegisteredPhase20JobControlHostProvisionVersionV1,
		Config:  config,
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
		encodedProvision, fixture.roots[1])
	if err != nil {
		t.Fatal(err)
	}
	host, err := formalGLMRegisteredPhase20JobControlHostOpenProvisionedV1(
		fixture.roots[1], receipt)
	if err != nil {
		t.Fatal(err)
	}
	key, socketDir, err := formalGLMRegisteredPhase20JobControlCredentialsV1(config)
	if err != nil {
		_ = host.Close()
		t.Fatal(err)
	}
	defer clear(key)
	daemon, err := newFormalGLMRegisteredPhase20JobControlHostDaemonAtDirV1(
		host, key, socketDir)
	if err != nil {
		_ = host.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = daemon.Close() })

	payload, err := json.Marshal(struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	commandValue := formalGLMRegisteredPhase20JobControlCommandV1{
		Version:          formalGLMRegisteredPhase20JobControlCommandVersionV1,
		Peer:             receipt.Peer,
		ArtifactID:       receipt.ArtifactID,
		ReceiptSetSHA256: receipt.ReceiptSetSHA256,
		Action:           "health",
		Payload:          payload,
	}
	command, err := json.Marshal(commandValue)
	if err != nil {
		t.Fatal(err)
	}
	response, err := formalGLMRegisteredPhase20JobControlRunAtRootV1(
		command, fixture.roots[1])
	if err != nil {
		t.Fatal(err)
	}
	var health struct{}
	if err := formalGLMPhase21RockStrictDecode(response.Payload, &health); err != nil {
		t.Fatalf("control health=%#v / %v", response, err)
	}
	commandValue.Action = "negotiate"
	commandValue.Payload, err = json.Marshal(formalGLMRegisteredPhase20JobControlHostDaemonInboundV1{})
	if err != nil {
		t.Fatal(err)
	}
	command, err = json.Marshal(commandValue)
	if err != nil {
		t.Fatal(err)
	}
	response, err = formalGLMRegisteredPhase20JobControlRunAtRootV1(
		command, fixture.roots[1])
	if err != nil {
		t.Fatal(err)
	}
	var result formalGLMRegisteredPhase20JobControlHostDaemonResultV1
	if err := formalGLMPhase21RockStrictDecode(response.Payload, &result); err != nil ||
		result.State != formalGLMRegisteredPhase20JobControlWaitingProposalStateV1 ||
		len(result.Outbound) != 0 || result.ProductionReady {
		t.Fatalf("control result=%#v / %v", result, err)
	}
	if bytes.Contains(command, config.Signing) || bytes.Contains(response.Payload, config.Signing) {
		t.Fatal("local control exposed the provisioned signing key")
	}

	var crossed formalGLMRegisteredPhase20JobControlCommandV1
	if err := formalGLMPhase21RockStrictDecode(command, &crossed); err != nil {
		t.Fatal(err)
	}
	crossed.ArtifactID = strings.Repeat("0", 64)
	crossedCommand, err := json.Marshal(crossed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMRegisteredPhase20JobControlRunAtRootV1(
		crossedCommand, fixture.roots[1]); err == nil {
		t.Fatal("local control accepted a crossed provision selector")
	}
}
