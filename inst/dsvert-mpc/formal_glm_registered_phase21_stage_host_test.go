package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"path/filepath"
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
			}

			var acknowledgements [2]*formalGLMRegisteredPhase21StageRelayAckV1
			deadline := time.Now().Add(90 * time.Second)
			for {
				complete := 0
				for index, task := range tasks {
					status, err := task.statusV1()
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
				for index, task := range tasks {
					chunk, err := task.pollV1(acknowledgements[index])
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
					ack, err := tasks[1-index].relayChunkV1(*chunk)
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
		})
	}
}
