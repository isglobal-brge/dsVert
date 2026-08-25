package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFormalGLMRegisteredPhase20JobControlFramesPhase21Lifecycle(t *testing.T) {
	cases := []struct {
		action string
		inner  any
	}{
		{"phase21_preflight", struct{}{}},
		{"phase21_preflight_bind", formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1{}},
		{"phase21_stage_poll", formalGLMRegisteredPhase20JobControlHostDaemonStagePollV1{}},
		{"phase21_stage_record", struct{}{}},
		{"phase21_stage_relay", formalGLMRegisteredPhase20JobControlHostDaemonStageRelayV1{}},
		{"phase21_stage_import", formalGLMRegisteredPhase20JobControlHostDaemonStageRecordV1{}},
		{"phase21_ticket_import", formalGLMRegisteredPhase20JobControlHostDaemonTicketRecordV1{}},
		{"phase21_seal_import", formalGLMRegisteredPhase20JobControlHostDaemonSealRecordV1{}},
		{"phase21_candidate_import", formalGLMRegisteredPhase20JobControlHostDaemonCandidateRecordV1{}},
		{"phase21_local_release_import", formalGLMRegisteredPhase20JobControlHostDaemonLocalReleaseRecordV1{}},
		{"phase21_base_certificate_import", formalGLMRegisteredPhase20JobControlHostDaemonBaseCertificateRecordV1{}},
		{"phase21_authorization_import", formalGLMRegisteredPhase20JobControlHostDaemonAuthorizationRecordV1{}},
		{"phase21_commit", formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1{}},
		{"phase21_commit_import", formalGLMRegisteredPhase20JobControlHostDaemonCommitRecordV1{}},
		{"phase21_ack", struct{}{}},
		{"phase21_ack_import", formalGLMRegisteredPhase20JobControlHostDaemonAckRecordV1{}},
		{"phase21_cleanup", formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1{}},
		{"phase21_cleanup_import", formalGLMRegisteredPhase20JobControlHostDaemonCleanupRecordV1{}},
	}
	for _, test := range cases {
		t.Run(test.action, func(t *testing.T) {
			inner, err := json.Marshal(test.inner)
			if err != nil {
				t.Fatal(err)
			}
			outer, err := json.Marshal(formalGLMRegisteredPhase20JobControlOpaqueFrameV1{
				Frame: inner,
			})
			if err != nil {
				t.Fatal(err)
			}
			command, err := json.Marshal(formalGLMRegisteredPhase20JobControlCommandV1{
				Version:          formalGLMRegisteredPhase20JobControlCommandVersionV1,
				Peer:             "site_a",
				ArtifactID:       strings.Repeat("a", 64),
				ReceiptSetSHA256: strings.Repeat("b", 64),
				Action:           test.action,
				Payload:          outer,
			})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := formalGLMRegisteredPhase20JobControlDecodeV1(command)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := formalGLMRegisteredPhase20JobControlDaemonPayloadV1(decoded)
			if err != nil || !bytes.Equal(payload, inner) {
				t.Fatalf("unwrapped=%s / %v", payload, err)
			}
			responsePayload := json.RawMessage(`{"plan_sha256":"not-exposed"}`)
			if test.action == "phase21_stage_relay" {
				responsePayload, err = formalGLMRegisteredPhase20JobControlHostDaemonCanonicalV1(
					formalGLMRegisteredPhase21StageRelayAckV1{})
				if err != nil {
					t.Fatal(err)
				}
			}
			response, err := formalGLMRegisteredPhase20JobControlResponsePayloadV1(
				test.action, responsePayload)
			if err != nil {
				t.Fatal(err)
			}
			var framed formalGLMRegisteredPhase20JobControlOpaqueFrameV1
			if err := formalGLMPhase21RockStrictDecode(response, &framed); err != nil ||
				len(framed.Frame) < 2 || (test.action != "phase21_stage_relay" &&
				!bytes.Equal(framed.Frame, []byte(`{"plan_sha256":"not-exposed"}`))) {
				t.Fatalf("framed=%#v / %v", framed, err)
			}
			if test.action == "phase21_stage_relay" {
				var poll formalGLMRegisteredPhase20JobControlHostDaemonStagePollV1
				if err := formalGLMPhase21RockStrictDecode(framed.Frame, &poll); err != nil ||
					poll.Acknowledgement == nil {
					t.Fatalf("Stage acknowledgement=%#v / %v", poll, err)
				}
			}

			bare, err := json.Marshal(formalGLMRegisteredPhase20JobControlCommandV1{
				Version:          formalGLMRegisteredPhase20JobControlCommandVersionV1,
				Peer:             "site_a",
				ArtifactID:       strings.Repeat("a", 64),
				ReceiptSetSHA256: strings.Repeat("b", 64),
				Action:           test.action,
				Payload:          inner,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMRegisteredPhase20JobControlDecodeV1(bare); err == nil {
				t.Fatal("accepted a bare Phase21 lifecycle record")
			}
		})
	}
}

func TestFormalGLMRegisteredPhase20JobControlHostCommandServesProvisionedHealth(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	config := formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 1)
	formalGLMRegisteredPhase20JobControlHostTestReleaseFixtureV1(t, fixture)
	encodedProvision, err := json.Marshal(formalGLMRegisteredPhase20JobControlHostProvisionV1{
		Version: formalGLMRegisteredPhase20JobControlHostProvisionVersionV1,
		Config:  config,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encodedProvision)
	receipt, err := formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
		encodedProvision, fixture.roots[1])
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	ready := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- runFormalGLMRegisteredPhase20JobControlHostAtRootV1(
			receipt.Peer, receipt.ArtifactID, receipt.ReceiptSetSHA256,
			fixture.roots[1], stop, ready)
	}()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			close(stop)
			select {
			case err := <-finished:
				if err != nil {
					t.Errorf("host command shutdown: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("host command did not stop")
			}
		}
	})
	select {
	case <-ready:
	case err := <-finished:
		t.Fatalf("host command stopped before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("host command did not become ready")
	}
	payload, err := json.Marshal(struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	command, err := json.Marshal(formalGLMRegisteredPhase20JobControlCommandV1{
		Version:          formalGLMRegisteredPhase20JobControlCommandVersionV1,
		Peer:             receipt.Peer,
		ArtifactID:       receipt.ArtifactID,
		ReceiptSetSHA256: receipt.ReceiptSetSHA256,
		Action:           "health",
		Payload:          payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(command)
	response, err := formalGLMRegisteredPhase20JobControlRunAtRootV1(
		command, fixture.roots[1])
	if err != nil {
		t.Fatal(err)
	}
	var health struct{}
	if err := formalGLMPhase21RockStrictDecode(response.Payload, &health); err != nil {
		t.Fatalf("host command health=%#v / %v", response, err)
	}
	close(stop)
	stopped = true
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("host command did not stop")
	}
}

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
