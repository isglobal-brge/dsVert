package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func formalCoxBlockwiseWorkerHostTestControlEncode(t testing.TB,
	bootstrap formalCoxBlockwiseWorkerBootstrapCommand, action string,
	payload any,
) []byte {
	t.Helper()
	config := formalCoxBlockwiseWorkerHostConfig{
		Version: formalCoxBlockwiseWorkerHostConfigVersion, Bootstrap: bootstrap,
	}
	_, peer, attempt, planSHA, err := formalCoxBlockwiseWorkerHostIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encodedPayload)
	encoded, err := json.Marshal(formalCoxBlockwiseWorkerControlCommand{
		Version:             formalCoxBlockwiseWorkerHostControlVersion,
		PeerName:            peer,
		PlanSHA256:          planSHA,
		AttemptID:           fmt.Sprintf("%x", attempt),
		RecipientSigningKey: bootstrap.Source.RecipientSigningKey,
		Action:              action,
		Payload:             encodedPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func formalCoxBlockwiseWorkerHostTestControl(t testing.TB, root string,
	bootstrap formalCoxBlockwiseWorkerBootstrapCommand, action string,
	payload any, response any,
) {
	t.Helper()
	encoded := formalCoxBlockwiseWorkerHostTestControlEncode(t, bootstrap, action, payload)
	defer clear(encoded)
	result, err := formalCoxBlockwiseWorkerControlRunAtRoot(encoded, root, false)
	if err != nil {
		t.Fatalf("worker control %s: %v", action, err)
	}
	if err := json.Unmarshal(result.Payload, response); err != nil {
		t.Fatalf("worker control %s response: %v", action, err)
	}
}

// The host-control command is deliberately short lived.  The full fixed
// schedule below instead holds one authenticated attachment per live worker:
// it proves the exact-GC relay without recompiling the signed schema for every
// individual poll frame.  The finalizer-stage transition itself still crosses
// the short-lived host-control boundary below.
func formalCoxBlockwiseWorkerHostTestAttachmentControl(t testing.TB,
	attachment *formalCoxBlockwiseWorkerBootstrapAttachment, action string,
	payload any, response any,
) {
	t.Helper()
	if attachment == nil || attachment.client == nil {
		t.Fatal("worker attachment is unavailable")
	}
	if err := attachment.client.callV1(action, payload, response); err != nil {
		t.Fatalf("worker attachment %s: %v", action, err)
	}
}

// formalCoxBlockwiseWorkerHostTestStageAllBlocks supplies the complete fixed
// source prefix before attaching either long-lived worker. A live host cannot
// safely infer missing source blocks after the schedule has begun.
func formalCoxBlockwiseWorkerHostTestStageAllBlocks(t testing.TB, custodians int,
	root string,
) (formalCoxBlockwisePlan, map[string]ed25519.PublicKey,
	map[string]formalCoxBlockwiseSourceImportCommand) {
	t.Helper()
	source, session, signers := formalCoxBlockwiseSourceImportCommandTestSource(
		t, custodians, root)
	plan := session.context.plan
	fixture := formalCoxRSourceBridgeFixtureFor(t, custodians)
	imports := make(map[string]formalCoxBlockwiseSourceImportCommand,
		len(plan.Policy.ComputePeers))
	for block := 0; block < plan.TotalBlocks; block++ {
		for _, sourcePeer := range plan.Policy.CustodianPeers {
			lines, ok := fixture.Blocks[sourcePeer]
			if !ok || len(lines) != plan.TotalBlocks {
				t.Fatalf("source %s has incomplete blocks", sourcePeer)
			}
			producer := source
			producer.SourcePeerName = sourcePeer
			producer.SourceSigningKey = base64.StdEncoding.EncodeToString(signers[sourcePeer])
			producer.BlockIndex = block
			producer.CanonicalInputBase64 = base64.StdEncoding.EncodeToString(
				[]byte(strings.Join(lines[block], "\n") + "\n"))
			formalCoxBlockwiseSourceProducerCommandTestRun(t, producer, root)
			for _, recipient := range plan.Policy.ComputePeers {
				deliveryCommand := formalCoxBlockwiseSourceDeliveryCommandTestRequest(
					t, producer, recipient)
				deliveryJSON, err := json.Marshal(deliveryCommand)
				if err != nil {
					t.Fatal(err)
				}
				delivery, err := formalCoxBlockwiseSourceDeliveryRunAtRoot(
					deliveryJSON, root, false)
				if err != nil {
					t.Fatal(err)
				}
				command := formalCoxBlockwiseSourceImportCommandTestRequest(
					t, producer, delivery, recipient, signers[recipient])
				encoded, err := json.Marshal(command)
				if err != nil {
					t.Fatal(err)
				}
				result, err := formalCoxBlockwiseSourceImportRunAtRoot(encoded, root, false)
				if err != nil || result.Replayed || result.ReceiptSHA256 != delivery.ReceiptSHA256 {
					t.Fatalf("source import %s/%d to %s: %+v / %v",
						sourcePeer, block, recipient, result, err)
				}
				imports[recipient] = command
			}
		}
	}
	stores := make(map[string]*formalCoxBlockwiseSourceStore, len(plan.Policy.ComputePeers))
	closers := make([]func(), 0, len(plan.Policy.ComputePeers))
	for _, recipient := range plan.Policy.ComputePeers {
		store, closeStore, err := formalCoxBlockwiseSourceImportOpen(
			imports[recipient], root, false)
		if err != nil {
			for _, closeStore := range closers {
				closeStore()
			}
			t.Fatal(err)
		}
		stores[recipient] = store
		closers = append(closers, closeStore)
	}
	noise := formalCoxRSourceBridgeStageZeroNoise(
		t, plan, session, session.context.pins, signers, stores)
	exactGCZeroBigInts(noise)
	for _, closeStore := range closers {
		closeStore()
	}
	return plan, session.context.pins, imports
}

// This is deliberately an internal, server-local proof.  A worker host owns
// one burned exact-GC attempt; callers can only attach through the signed
// recipient bootstrap and never supply a socket, a storage path or a key.
func TestFormalCoxBlockwiseWorkerHostAttachesLiveK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "dsvert-cox-worker-host-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			plan, pins, imports := formalCoxBlockwiseWorkerHostTestStageAllBlocks(t, custodians, root)
			attempt := sha256.Sum256([]byte(t.Name() + "/attempt"))
			configs := make([]formalCoxBlockwiseWorkerHostConfig, len(plan.Policy.ComputePeers))
			paths := make([]string, len(configs))
			stops := make([]chan struct{}, len(configs))
			ready := make([]chan struct{}, len(configs))
			done := make([]chan error, len(configs))
			for index, peer := range plan.Policy.ComputePeers {
				configs[index] = formalCoxBlockwiseWorkerHostConfig{
					Version: formalCoxBlockwiseWorkerHostConfigVersion,
					Bootstrap: formalCoxBlockwiseWorkerBootstrapCommand{
						Version: formalCoxBlockwiseWorkerBootstrapVersion,
						Source:  imports[peer], AttemptID: fmt.Sprintf("%x", attempt),
					},
				}
				var err error
				paths[index], err = formalCoxBlockwiseWorkerHostConfigPath(root, configs[index])
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(formalCoxBlockwiseWorkerProvisionCommand{
					Version: formalCoxBlockwiseWorkerProvisionVersion,
					Config:  configs[index],
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalCoxBlockwiseWorkerProvisionRunAtRoot(encoded, root, false); err != nil {
					t.Fatal(err)
				}
				stops[index], ready[index], done[index] = make(chan struct{}), make(chan struct{}), make(chan error, 1)
				go func(index int) {
					_, peer, attempt, planSHA, err := formalCoxBlockwiseWorkerHostIdentity(configs[index])
					if err != nil {
						done[index] <- err
						return
					}
					done[index] <- runFormalCoxBlockwiseWorkerHostSelectorAtRoot(
						peer, planSHA, fmt.Sprintf("%x", attempt), root, false, stops[index], ready[index])
				}(index)
			}
			for index := range configs {
				select {
				case <-ready[index]:
				case err := <-done[index]:
					t.Fatalf("host %d exited before attachment: %v", index, err)
				case <-time.After(10 * time.Second):
					t.Fatalf("host %d did not become ready", index)
				}
				_, peer, selectedAttempt, planSHA, err :=
					formalCoxBlockwiseWorkerHostIdentity(configs[index])
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(formalCoxBlockwiseWorkerControlCommand{
					Version:             formalCoxBlockwiseWorkerHostControlVersion,
					PeerName:            peer,
					PlanSHA256:          planSHA,
					AttemptID:           fmt.Sprintf("%x", selectedAttempt),
					RecipientSigningKey: configs[index].Bootstrap.Source.RecipientSigningKey,
					Action:              "bind",
					Payload:             json.RawMessage(fmt.Sprintf(`{"peer":%q}`, plan.Policy.ComputePeers[1-index])),
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalCoxBlockwiseWorkerControlRunAtRoot(encoded, root, false); err != nil {
					t.Fatalf("attach %d: %v", index, err)
				}
				if _, err := os.Lstat(paths[index]); !os.IsNotExist(err) {
					t.Fatalf("host %d retained sensitive config: %v", index, err)
				}
				opened, err := os.OpenRoot(filepath.Join(root, peer))
				if err != nil {
					t.Fatal(err)
				}
				burned, burnErr := formalCoxBlockwiseWorkerHostBurnedAtRoot(
					opened, filepath.Join(root, peer), paths[index], configs[index])
				closeErr := opened.Close()
				if burnErr != nil || closeErr != nil || !burned {
					t.Fatalf("host %d burn = %v / %v / %t", index, burnErr, closeErr, burned)
				}
				provision, err := json.Marshal(formalCoxBlockwiseWorkerProvisionCommand{
					Version: formalCoxBlockwiseWorkerProvisionVersion, Config: configs[index],
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalCoxBlockwiseWorkerProvisionRunAtRoot(provision, root, false); err == nil {
					clear(provision)
					t.Fatalf("host %d allowed reprovision after burn", index)
				}
				clear(provision)
			}
			firstAttachment := formalCoxBlockwiseWorkerAttachmentPath(paths[0])
			secondAttachment := formalCoxBlockwiseWorkerAttachmentPath(paths[1])
			firstBytes, err := os.ReadFile(firstAttachment)
			if err != nil {
				t.Fatal(err)
			}
			secondBytes, err := os.ReadFile(secondAttachment)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(firstAttachment); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(firstAttachment, secondBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			crossed := formalCoxBlockwiseWorkerHostTestControlEncode(
				t, configs[0].Bootstrap, "result", struct{}{})
			if _, err := formalCoxBlockwiseWorkerControlRunAtRoot(crossed, root, false); err == nil {
				clear(crossed)
				t.Fatal("worker control accepted a cross-peer attachment descriptor")
			}
			clear(crossed)
			if err := os.WriteFile(firstAttachment, firstBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			attachments := make([]*formalCoxBlockwiseWorkerBootstrapAttachment, len(configs))
			for index := range configs {
				encoded, err := json.Marshal(configs[index].Bootstrap)
				if err != nil {
					t.Fatal(err)
				}
				attachment, openErr := openFormalCoxBlockwiseWorkerBootstrapAttachmentAtRoot(
					encoded, root, false)
				clear(encoded)
				if openErr != nil {
					t.Fatal(openErr)
				}
				attachments[index] = attachment
			}
			t.Cleanup(func() {
				for _, attachment := range attachments {
					_ = attachment.Close()
				}
			})
			var acknowledgements [2]int64
			for scheduleIndex := 0; scheduleIndex < plan.ScheduleSteps; scheduleIndex++ {
				step, err := formalCoxBlockwiseWorkerStepAt(plan, scheduleIndex)
				if err != nil {
					t.Fatal(err)
				}
				claims := make([]formalCoxBlockwiseExchangeRootClaim, len(configs))
				for index := range configs {
					formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[index],
						"root_claim", formalCoxBlockwiseExchangeDaemonRootV1{
							Step: step, Attempt: fmt.Sprintf("%x", attempt),
						}, &claims[index])
				}
				for index := range configs {
					formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[index],
						"start", formalCoxBlockwiseExchangeDaemonStartV1{
							Step: step, Attempt: fmt.Sprintf("%x", attempt), PeerClaim: claims[1-index],
						}, &struct{}{})
				}
				var receipts [2]formalCoxBlockwiseStepReceipt
				var completed [2]bool
				deadline := time.Now().Add(3 * time.Minute)
				for !completed[0] || !completed[1] {
					if time.Now().After(deadline) {
						t.Fatal("worker host relay did not complete")
					}
					for _, direction := range []struct{ from, to int }{{0, 1}, {1, 0}} {
						var poll formalCoxBlockwiseExchangeDaemonPollResultV1
						formalCoxBlockwiseWorkerHostTestAttachmentControl(t,
							attachments[direction.from], "poll",
							formalCoxBlockwiseExchangeDaemonPollV1{
								Acknowledged: strconv.FormatInt(acknowledgements[direction.from], 10),
							}, &poll)
						if poll.Chunk != nil {
							var relayed formalCoxBlockwiseExchangeDaemonRelayResultV1
							formalCoxBlockwiseWorkerHostTestAttachmentControl(t,
								attachments[direction.to], "relay",
								formalCoxBlockwiseExchangeDaemonRelayV1{Chunk: *poll.Chunk}, &relayed)
							accepted, err := formalCoxBlockwiseExchangeDaemonOffsetV1(relayed.Accepted)
							if err != nil {
								t.Fatal(err)
							}
							acknowledgements[direction.from] = accepted
						}
					}
					for index := range configs {
						var result formalCoxBlockwiseExchangeDaemonResultV1
						formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[index],
							"result", struct{}{}, &result)
						if result.Done {
							receipts[index], completed[index] = result.Receipt, true
						}
					}
				}
				if err := formalCoxBlockwiseValidateReceiptPair(plan, receipts[:], pins); err != nil {
					t.Fatal(err)
				}
				for index := range configs {
					formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[index],
						"commit", formalCoxBlockwiseExchangeDaemonCommitV1{Receipts: receipts[:]}, &struct{}{})
				}
			}
			var headers [2]formalCoxBlockwiseOpeningHandoffHeader
			for index := range configs {
				var opening formalCoxBlockwiseExchangeDaemonOpeningV1
				formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[index],
					"opening", struct{}{}, &opening)
				if opening.Header == nil {
					t.Fatalf("host %d returned no sticky opening header", index)
				}
				headers[index] = *opening.Header
			}
			var issued formalCoxBlockwiseExchangeDaemonFinalizerTicketResultV1
			formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[0],
				"finalizer_ticket",
				formalCoxBlockwiseExchangeDaemonFinalizerTicketV1{Headers: headers}, &issued)
			if issued.Replayed || len(issued.Ticket.RecipientTransportPublicKey) == 0 {
				t.Fatalf("finalizer ticket = %+v", issued)
			}
			nonFinalizer := formalCoxBlockwiseWorkerHostTestControlEncode(
				t, configs[1].Bootstrap, "finalizer_ticket",
				formalCoxBlockwiseExchangeDaemonFinalizerTicketV1{Headers: headers})
			if _, err := formalCoxBlockwiseWorkerControlRunAtRoot(nonFinalizer, root, false); err == nil {
				clear(nonFinalizer)
				t.Fatal("non-finalizer worker issued a finalizer ticket")
			}
			clear(nonFinalizer)
			var envelopes [2]formalFinalizerHandoffEnvelope
			for index := range configs {
				var sealed formalCoxBlockwiseExchangeDaemonFinalizerSealResultV1
				formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[index],
					"finalizer_seal", formalCoxBlockwiseExchangeDaemonFinalizerSealV1{
						Ticket: issued.Ticket, Headers: headers,
					}, &sealed)
				if sealed.Replayed || len(sealed.Envelope.Ciphertext) == 0 {
					t.Fatalf("host %d finalizer envelope = %+v", index, sealed)
				}
				envelopes[index] = sealed.Envelope
				var replay formalCoxBlockwiseExchangeDaemonFinalizerSealResultV1
				formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[index],
					"finalizer_seal", formalCoxBlockwiseExchangeDaemonFinalizerSealV1{
						Ticket: issued.Ticket, Headers: headers,
					}, &replay)
				if !replay.Replayed || !formalFinalizerHandoffEnvelopeSemanticEqual(
					sealed.Envelope, replay.Envelope) {
					t.Fatalf("host %d finalizer envelope replay changed", index)
				}
			}
			var prepared formalCoxBlockwiseExchangeDaemonFinalizerPrepareResultV1
			formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[0],
				"finalizer_prepare", formalCoxBlockwiseExchangeDaemonFinalizerPrepareV1{
					Ticket: issued.Ticket, Headers: headers, Envelopes: envelopes,
				}, &prepared)
			if prepared.Replayed || prepared.Finalized || prepared.Intent == nil ||
				prepared.Intent.ArtifactID != headers[0].ArtifactID ||
				prepared.CertificateSHA256 != "" {
				t.Fatalf("fresh finalizer prepare = %+v", prepared)
			}
			for index := range configs {
				var staged formalCoxBlockwiseLiveControlStageV1
				formalCoxBlockwiseWorkerHostTestControl(t, root, configs[index].Bootstrap,
					"finalizer_stage", formalCoxBlockwiseExchangeDaemonFinalizerPrepareV1{
						Ticket: issued.Ticket, Headers: headers, Envelopes: envelopes,
					}, &staged)
				if staged.ArtifactID != headers[index].ArtifactID ||
					staged.LocalRole != headers[index].Role || staged.ProductionReady ||
					(headers[index].Role == "garbler" &&
						!formalCoxIsSHA256(staged.CandidateSHA256)) ||
					(headers[index].Role == "evaluator" && staged.CandidateSHA256 != "") {
					t.Fatalf("host %d finalizer stage = %+v", index, staged)
				}
			}
			var preparedReplay formalCoxBlockwiseExchangeDaemonFinalizerPrepareResultV1
			formalCoxBlockwiseWorkerHostTestAttachmentControl(t, attachments[0],
				"finalizer_prepare", formalCoxBlockwiseExchangeDaemonFinalizerPrepareV1{
					Ticket: issued.Ticket, Headers: headers, Envelopes: envelopes,
				}, &preparedReplay)
			if preparedReplay.Replayed || preparedReplay.Finalized ||
				preparedReplay.Intent == nil ||
				!formalCoxBlockwiseOpeningEqual(*prepared.Intent, *preparedReplay.Intent) {
				t.Fatalf("finalizer prepare replay changed: %+v", preparedReplay)
			}
			nonFinalizerPrepare := formalCoxBlockwiseWorkerHostTestControlEncode(
				t, configs[1].Bootstrap, "finalizer_prepare",
				formalCoxBlockwiseExchangeDaemonFinalizerPrepareV1{
					Ticket: issued.Ticket, Headers: headers, Envelopes: envelopes,
				})
			if _, err := formalCoxBlockwiseWorkerControlRunAtRoot(
				nonFinalizerPrepare, root, false); err == nil {
				clear(nonFinalizerPrepare)
				t.Fatal("non-finalizer worker prepared a finalizer opening")
			}
			clear(nonFinalizerPrepare)
			for index := range stops {
				close(stops[index])
				if err := <-done[index]; err != nil {
					t.Fatalf("host %d close: %v", index, err)
				}
				_, peer, selectedAttempt, planSHA, err :=
					formalCoxBlockwiseWorkerHostIdentity(configs[index])
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(formalCoxBlockwiseWorkerControlCommand{
					Version:             formalCoxBlockwiseWorkerHostControlVersion,
					PeerName:            peer,
					PlanSHA256:          planSHA,
					AttemptID:           fmt.Sprintf("%x", selectedAttempt),
					RecipientSigningKey: configs[index].Bootstrap.Source.RecipientSigningKey,
					Action:              "result", Payload: json.RawMessage(`{}`),
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalCoxBlockwiseWorkerControlRunAtRoot(encoded, root, false); err == nil {
					t.Fatalf("host %d accepted an attachment after close", index)
				}
			}
		})
	}
}
