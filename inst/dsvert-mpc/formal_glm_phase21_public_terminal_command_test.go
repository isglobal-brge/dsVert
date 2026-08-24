package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func formalGLMPhase21PublicTerminalCommandRequestV1(
	t testing.TB,
	fixture formalGLMPublicEndpointTestFixture,
	terminal formalGLMPublicTerminalEvidenceV1,
) []byte {
	t.Helper()
	contractJSON, err := json.Marshal(terminal.Contract)
	if err != nil {
		t.Fatal(err)
	}
	resolutionJSON, err := json.Marshal(fixture.resolution)
	if err != nil {
		t.Fatal(err)
	}
	pins := make(map[string]string, len(fixture.phase21.pins))
	for peer, pin := range fixture.phase21.pins {
		pins[peer] = base64.RawURLEncoding.EncodeToString(pin)
	}
	encoded, err := json.Marshal(formalGLMPhase21PublicTerminalRequestV1{
		AuthorityPeer: terminal.Contract.Artifact.NoiseAuthorities[0].PeerName,
		ContractJSON:  string(contractJSON), ResolutionJSON: string(resolutionJSON),
		Pins: pins,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalGLMPhase21PublicTerminalCommandK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicEndpointTestSetup(t, custodians)
			terminal := formalGLMPublicEndpointTestTerminal(t, fixture)
			stateRoot, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			authorityPeer := terminal.Contract.Artifact.NoiseAuthorities[0].PeerName
			root := filepath.Join(stateRoot, authorityPeer)
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			formalGLMPhase21PublicTerminalTestPersistV1(t, root, fixture, terminal)
			request := formalGLMPhase21PublicTerminalCommandRequestV1(t, fixture, terminal)
			expected, err := formalGLMPublicResultFromCertificateV1(
				terminal.Publication, fixture.phase21.pins)
			if err != nil {
				t.Fatal(err)
			}
			response, err := formalGLMRunPhase21PublicTerminalAtRootV1(request, stateRoot)
			if err != nil || !reflect.DeepEqual(response, expected) ||
				response.ProductionReady {
				t.Fatalf("public terminal result = %#v / %v", response, err)
			}
			replayed, err := formalGLMRunPhase21PublicTerminalAtRootV1(request, stateRoot)
			if err != nil || !reflect.DeepEqual(replayed, response) {
				t.Fatalf("public terminal replay = %#v / %v", replayed, err)
			}

			cleanupPath, err := formalGLMPhase21RockCleanupRecordPath(
				root, terminal.Contract.ArtifactID,
				terminal.Contract.Artifact.NoiseAuthorities[1].Role)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(cleanupPath); err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMRunPhase21PublicTerminalAtRootV1(request, stateRoot); err == nil {
				t.Fatal("public terminal command accepted missing dual cleanup")
			}
		})
	}
}
