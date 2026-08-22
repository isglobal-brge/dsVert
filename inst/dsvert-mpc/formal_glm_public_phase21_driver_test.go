package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFormalGLMPublicPhase21TerminalDriverK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicEndpointTestSetup(t, custodians)
			terminal := formalGLMPublicEndpointTestTerminal(t, fixture)
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "rock")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			formalGLMPhase21PublicTerminalTestPersistV1(t, root, fixture, terminal)

			driver, err := newFormalGLMPublicPhase21TerminalDriverV1(
				root, terminal.Contract, fixture.phase21.pins)
			if err != nil {
				t.Fatal(err)
			}
			defer driver.Close()
			if encoded, marshalErr := json.Marshal(driver); marshalErr != nil ||
				string(encoded) != "{}" {
				t.Fatalf("driver exposed private state: %q / %v", encoded, marshalErr)
			}

			observation, err := driver.AdvanceV1(formalGLMPublicAdvanceContextV1{
				Resolution: fixture.resolution,
			})
			if err != nil || observation.Terminal == nil || observation.Failed ||
				!reflect.DeepEqual(*observation.Terminal, terminal) {
				t.Fatalf("durable terminal observation = %#v / %v", observation, err)
			}
			advanceStore := formalGLMPublicAdvanceStoreTestNew(
				t, filepath.Join(base, "advance"), fixture)
			bootstrap := formalGLMPublicEndpointTestNew(t, fixture,
				func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					return formalGLMPublicAdvanceObservationV1{},
						fmt.Errorf("bootstrap driver reached")
				})
			resolved, _ := formalGLMPublicEndpointTestResolve(
				t, bootstrap, fixture.selector)
			endpoint := formalGLMPublicAdvanceStoreTestEndpoint(
				t, fixture, advanceStore, driver.AdvanceV1)
			complete, err := endpoint.Advance([]byte(resolved.ReceiptFrameJSON), nil)
			if err != nil || complete.State != formalGLMPublicStateComplete ||
				complete.Replayed || complete.PublicV2JSON == "" ||
				!formalGLMIsSHA256(complete.CertificateSHA256) {
				t.Fatalf("public durable completion = %#v / %v", complete, err)
			}
			advanceStore.Close()

			cleanupPath, err := formalGLMPhase21RockCleanupRecordPath(
				root, terminal.Contract.ArtifactID,
				terminal.Contract.Artifact.NoiseAuthorities[1].Role)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(cleanupPath); err != nil {
				t.Fatal(err)
			}
			if _, err := driver.AdvanceV1(formalGLMPublicAdvanceContextV1{
				Resolution: fixture.resolution,
			}); err == nil {
				t.Fatal("driver accepted missing dual cleanup")
			}
			reopenedStore := formalGLMPublicAdvanceStoreTestNew(
				t, filepath.Join(base, "advance"), fixture)
			defer reopenedStore.Close()
			reopened := formalGLMPublicAdvanceStoreTestEndpoint(
				t, fixture, reopenedStore, driver.AdvanceV1)
			replay, err := reopened.Advance([]byte(resolved.ReceiptFrameJSON), nil)
			if err != nil || !replay.Replayed ||
				replay.PublicV2JSON != complete.PublicV2JSON ||
				replay.CertificateSHA256 != complete.CertificateSHA256 {
				t.Fatalf("public durable replay = %#v / %v", replay, err)
			}
			driver.Close()
			if _, err := driver.AdvanceV1(formalGLMPublicAdvanceContextV1{
				Resolution: fixture.resolution,
			}); err == nil {
				t.Fatal("closed driver remained usable")
			}
		})
	}
}
