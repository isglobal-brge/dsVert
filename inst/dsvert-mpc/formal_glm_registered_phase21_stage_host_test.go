package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func formalGLMRegisteredPhase21StageTaskTestStateV1(
	t testing.TB,
	fixture formalGLMPhase21TestFixture,
	contract formalGLMPhase21SamplerV2Contract,
	authority formalGLMPhase21RockStageTestAuthority,
	index int,
) formalGLMRegisteredPhase21StageHostStateV1 {
	t.Helper()
	peer := contract.Artifact.NoiseAuthorities[index].PeerName
	remote := contract.Artifact.NoiseAuthorities[1-index].PeerName
	source, _, err := fixture.stores[peer].Load()
	if err != nil {
		t.Fatal(err)
	}
	backend := source.backend
	source.clear()
	phase20 := sha256.Sum256([]byte(t.Name() + "/phase20/" + peer))
	sticky := sha256.Sum256([]byte(t.Name() + "/sticky/" + peer))
	pins := make(map[string]ed25519.PublicKey, 2)
	for _, name := range []string{peer, remote} {
		pins[name] = append(ed25519.PublicKey(nil), fixture.formal.identities.public[name]...)
	}
	return formalGLMRegisteredPhase21StageHostStateV1{
		stickyRoot: sticky, phase20StorageRoot: phase20, backendKey: backend,
		authorityRoot: fixture.seeds[peer], transportRoot: authority.transportRoot,
		semanticRoot: authority.operation.Phase20SemanticRootSHA256,
		rockRoot:     authority.root, spoolDir: authority.spool, secretPath: authority.secret,
		operation: authority.operation, peer: peer, remotePeer: remote,
		artifactID: contract.ArtifactID, pins: pins,
		signing: append(ed25519.PrivateKey(nil), fixture.formal.identities.private[peer]...),
	}
}

func TestFormalGLMRegisteredPhase21StageTaskK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPhase21TestSetup(t, custodians, "binomial")
			defer fixture.close()
			reference := fixture.formal.ctx.ComputePeers[0]
			runtime, _, err := formalGLMPhase21LoadAndAdmit(
				fixture.stores[reference], fixture.capsule, fixture.request,
				fixture.backendSignatures, fixture.workerSignatures)
			if err != nil {
				t.Fatal(err)
			}
			source, _, err := formalGLMPhase21BuildCanonicalArtifact(
				runtime.Admission.Productive.Compiled.Binding,
				runtime.Source.Plan, fixture.formal.identities.public)
			binding := runtime.Admission.Productive.Compiled.Binding
			runtime.clear()
			if err != nil {
				t.Fatal(err)
			}
			artifact, artifactID, resolution := formalGLMRegisteredLifecycleTestResolution(
				t, fixture, source, binding)
			contract := formalGLMRegisteredLifecycleTestContract(
				t, fixture, artifact, artifactID)
			authorizations := formalGLMPhase21SamplerV2TestAuthorize(
				t, contract, fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			authorities := formalGLMPhase21RockTestStageAuthorities(
				t, fixture, contract, authorizations)
			for index := range authorities {
				path := filepath.Join(authorities[index].root,
					"assets-v1", "registry-resolution.json")
				formalGLMPhase21RockTestWriteJSON(t, path, resolution)
				authorities[index].operation.RegistryResolutionPath = path
			}
			tasks := [2]*formalGLMRegisteredPhase21StageTaskV1{}
			clients := [2]*formalGLMRegisteredPhase20JobControlHostDaemonClientV1{}
			for index := range tasks {
				state := formalGLMRegisteredPhase21StageTaskTestStateV1(
					t, fixture, contract, authorities[index], index)
				task, err := newFormalGLMRegisteredPhase21StageTaskV1(state, func() {})
				state.clearV1()
				if err != nil {
					t.Fatal(err)
				}
				tasks[index] = task
				t.Cleanup(task.closeV1)
				peer := contract.Artifact.NoiseAuthorities[index].PeerName
				key := sha256.Sum256([]byte(t.Name() + "/daemon/" + peer))
				daemon, daemonErr := newFormalGLMRegisteredPhase20JobControlHostDaemonV1(
					&formalGLMRegisteredPhase20JobControlHostV1{stage: task}, key[:])
				if daemonErr != nil {
					t.Fatal(daemonErr)
				}
				t.Cleanup(func() { _ = daemon.Close() })
				client, clientErr := newFormalGLMRegisteredPhase20JobControlHostDaemonClientV1(
					daemon.SocketPathV1(), key[:])
				if clientErr != nil {
					t.Fatal(clientErr)
				}
				t.Cleanup(client.Close)
				clients[index] = client
			}

			var acknowledgements [2]*formalGLMRegisteredPhase21StageRelayAckV1
			deadline := time.Now().Add(90 * time.Second)
			for {
				complete := 0
				for index := range tasks {
					status, err := clients[index].Phase21StageStatusV1()
					if err != nil || status.ProductionReady || status.State == formalGLMRegisteredPhase21StageFailedV1 {
						for _, value := range tasks {
							_ = value.abortV1()
						}
						t.Fatalf("Stage task %d failed: %#v / %v", index, status, err)
					}
					if status.State == formalGLMRegisteredPhase21StageCompleteV1 {
						if status.Stage == nil || status.Stage.ArtifactID != contract.ArtifactID ||
							status.Stage.ProductionReady {
							t.Fatalf("Stage task %d exposed an invalid result: %#v", index, status)
						}
						complete++
					}
				}
				if complete == len(tasks) {
					break
				}
				for index := range tasks {
					chunk, err := clients[index].PollPhase21StageV1(acknowledgements[index])
					acknowledgements[index] = nil
					if err != nil {
						for _, value := range tasks {
							_ = value.abortV1()
						}
						t.Fatalf("Stage task %d poll: %v", index, err)
					}
					if chunk == nil {
						continue
					}
					ack, err := clients[1-index].RelayPhase21StageV1(*chunk)
					if err != nil {
						for _, value := range tasks {
							_ = value.abortV1()
						}
						t.Fatalf("Stage task %d relay: %v", index, err)
					}
					acknowledgements[index] = &ack
				}
				if time.Now().After(deadline) {
					for _, value := range tasks {
						_ = value.abortV1()
					}
					t.Fatal("registered Phase21 Stage tasks timed out")
				}
				time.Sleep(time.Millisecond)
			}
			var stages [2]formalGLMPhase21RockStageRecord
			for index := range clients {
				status, err := clients[index].Phase21StageStatusV1()
				if err != nil || status.Stage == nil ||
					status.State != formalGLMRegisteredPhase21StageCompleteV1 {
					t.Fatalf("Stage task %d did not retain its signed record: %#v / %v",
						index, status, err)
				}
				stages[index] = *status.Stage
			}
			states := [2]formalGLMRegisteredPhase21StageHostStateV1{}
			for index := range states {
				states[index] = formalGLMRegisteredPhase21StageTaskTestStateV1(
					t, fixture, contract, authorities[index], index)
				defer states[index].clearV1()
				if index == 0 {
					tampered := stages[1]
					tampered.Receipt.Signature = append([]byte(nil),
						stages[1].Receipt.Signature...)
					tampered.Receipt.Signature[0] ^= 1
					if err := formalGLMRegisteredPhase21ImportPeerStageV1(
						states[index], tampered); err == nil {
						t.Fatal("Stage authority accepted a tampered peer record")
					}
				}
				if err := formalGLMRegisteredPhase21ImportPeerStageV1(
					states[index], stages[1-index]); err != nil {
					t.Fatalf("Stage authority %d did not import its peer: %v", index, err)
				}
			}
			ticket, err := formalGLMRegisteredPhase21RunTicketV1(states[0])
			if err != nil || ticket.ArtifactID != contract.ArtifactID ||
				ticket.ProductionReady {
				t.Fatalf("finalizer did not issue the signed ticket: %#v / %v", ticket, err)
			}
			tamperedTicket := ticket
			tamperedTicket.Ticket.Signature = append([]byte(nil), ticket.Ticket.Signature...)
			tamperedTicket.Ticket.Signature[0] ^= 1
			if err := formalGLMRegisteredPhase21ImportPeerTicketV1(
				states[1], tamperedTicket); err == nil {
				t.Fatal("peer accepted a tampered ticket")
			}
			if err := formalGLMRegisteredPhase21ImportPeerTicketV1(states[1], ticket); err != nil {
				t.Fatalf("peer did not import the signed ticket: %v", err)
			}
			replay, replayErr := formalGLMRegisteredPhase21RunTicketV1(states[0])
			if replayErr != nil || !reflect.DeepEqual(replay, ticket) {
				t.Fatalf("ticket replay changed: %#v / %#v / %v", replay, ticket, replayErr)
			}
			var seals [2]formalGLMPhase21RockSealRecord
			for index := range states {
				seal, sealErr := formalGLMRegisteredPhase21RunSealV1(states[index])
				if sealErr != nil || seal.ArtifactID != contract.ArtifactID ||
					seal.ProductionReady {
					t.Fatalf("authority %d did not seal its local result: %#v / %v",
						index, seal, sealErr)
				}
				seals[index] = seal
			}
			tamperedSeal := seals[1]
			tamperedSeal.Receipt.Signature = append([]byte(nil), seals[1].Receipt.Signature...)
			tamperedSeal.Receipt.Signature[0] ^= 1
			if err := formalGLMRegisteredPhase21ImportPeerSealV1(states[0], tamperedSeal); err == nil {
				t.Fatal("authority accepted a tampered peer seal")
			}
			for index := range states {
				if err := formalGLMRegisteredPhase21ImportPeerSealV1(
					states[index], seals[1-index]); err != nil {
					t.Fatalf("authority %d did not import its peer seal: %v", index, err)
				}
				replay, replayErr := formalGLMRegisteredPhase21RunSealV1(states[index])
				if replayErr != nil || !reflect.DeepEqual(replay, seals[index]) {
					t.Fatalf("seal replay %d changed: %#v / %#v / %v",
						index, replay, seals[index], replayErr)
				}
			}
		})
	}
}
