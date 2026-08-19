package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func formalGLMPhase18SourceProjectTestRequest(
	t testing.TB,
	fixture formalGLMSourceContractTestFixtureV1,
	localPeer string,
) formalGLMPhase18SourceProjectRequestV1 {
	t.Helper()
	contractJSON, err := json.Marshal(fixture.contract)
	if err != nil {
		t.Fatal(err)
	}
	pins := make(map[string]string, len(fixture.inputs.identities.public))
	for peer, pin := range fixture.inputs.identities.public {
		pins[peer] = formalGLMIdentityPKV1(pin)
	}
	return formalGLMPhase18SourceProjectRequestV1{
		SourceContractJSON: string(contractJSON),
		Pins:               pins,
		LocalPeerName:      localPeer,
	}
}

func formalGLMPhase18SourceProjectTestRun(
	t testing.TB,
	request formalGLMPhase18SourceProjectRequestV1,
) (formalGLMPhase18SourceProjectResponseV1, []byte) {
	t.Helper()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := formalGLMRunPhase18SourceProjectV1(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return response, encoded
}

func TestFormalGLMPhase18SourceProjectCommandK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMSourceContractTestFixture(t, custodians)
			localPeer := fixture.plan.CustodianPeers[custodians-1]
			request := formalGLMPhase18SourceProjectTestRequest(
				t, fixture, localPeer)
			response, _ := formalGLMPhase18SourceProjectTestRun(t, request)
			expected, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
				fixture.contract, localPeer, fixture.inputs.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			expectedJSON, err := json.Marshal(expected)
			if err != nil {
				t.Fatal(err)
			}
			if response.Version != formalGLMPhase18SourceProjectResponseVersion ||
				response.AuthorizationSHA256 != expected.AuthorizationSHA256 ||
				response.AuthorizationJSON != string(expectedJSON) {
				t.Fatalf("source project diverged from authorization: %+v", response)
			}
			decoded, err := formalGLMDecodeRegisteredPhase18AuthorizationV1(
				[]byte(response.AuthorizationJSON), fixture.contract,
				fixture.inputs.identities.public)
			if err != nil || !reflect.DeepEqual(decoded, expected) {
				t.Fatalf("projected authorization is not exact: equal=%v err=%v",
					reflect.DeepEqual(decoded, expected), err)
			}
		})
	}
}

func TestFormalGLMPhase18SourceProjectCommandClosedCanonicalRequest(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	request := formalGLMPhase18SourceProjectTestRequest(
		t, fixture, fixture.plan.CustodianPeers[0])
	_, canonical := formalGLMPhase18SourceProjectTestRun(t, request)

	var object map[string]any
	if err := json.Unmarshal(canonical, &object); err != nil {
		t.Fatal(err)
	}
	object["action"] = "advance"
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	delete(object, "action")
	object["path"] = "/tmp/caller-selected"
	openPath, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	delete(object, "path")
	object["artifact_id"] = sha256Hex([]byte("caller-selected artifact"))
	freeArtifact, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, canonical, "", "  "); err != nil {
		t.Fatal(err)
	}
	noncanonicalContract := request
	noncanonicalContract.SourceContractJSON += "\n"
	noncanonicalContractJSON, err := json.Marshal(noncanonicalContract)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"unknown":                     unknown,
		"path":                        openPath,
		"free artifact":               freeArtifact,
		"extra":                       append(append([]byte(nil), canonical...), []byte(`{}`)...),
		"noncanonical outer":          indented.Bytes(),
		"noncanonical inner contract": noncanonicalContractJSON,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := formalGLMRunPhase18SourceProjectV1(encoded); err == nil {
				t.Fatal("source project accepted an open or noncanonical request")
			}
		})
	}
}

func TestFormalGLMPhase18SourceProjectCommandRejectsContractAndPeer(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 3)
	base := formalGLMPhase18SourceProjectTestRequest(
		t, fixture, fixture.plan.CustodianPeers[0])

	missing := fixture.contract
	missing.CustodianApprovals = append(
		[]jointDPBiomedicalGaussianSignature(nil),
		fixture.contract.CustodianApprovals[:2]...)
	missingJSON, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	missingRequest := base
	missingRequest.SourceContractJSON = string(missingJSON)

	tampered := fixture.contract
	tampered.CustodianApprovals = append(
		[]jointDPBiomedicalGaussianSignature(nil),
		fixture.contract.CustodianApprovals...)
	tampered.CustodianApprovals[0].Signature = append(
		[]byte(nil), fixture.contract.CustodianApprovals[0].Signature...)
	tampered.CustodianApprovals[0].Signature[0] ^= 1
	tamperedJSON, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedRequest := base
	tamperedRequest.SourceContractJSON = string(tamperedJSON)

	badPins := base
	badPins.Pins = make(map[string]string, len(base.Pins))
	for peer, pin := range base.Pins {
		badPins.Pins[peer] = pin
	}
	badPins.Pins[fixture.plan.CustodianPeers[0]] =
		base.Pins[fixture.plan.CustodianPeers[1]]
	outsider := base
	outsider.LocalPeerName = "outsider"

	for name, request := range map[string]formalGLMPhase18SourceProjectRequestV1{
		"K-1":          missingRequest,
		"tampered":     tamperedRequest,
		"wrong pinset": badPins,
		"outsider":     outsider,
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMRunPhase18SourceProjectV1(encoded); err == nil {
				t.Fatal("source project accepted invalid authority input")
			}
		})
	}
}

func TestFormalGLMPhase18SourceProjectCommandResponseIsMinimalAndSafe(t *testing.T) {
	fixture := formalGLMSourceContractTestFixture(t, 5)
	request := formalGLMPhase18SourceProjectTestRequest(
		t, fixture, fixture.plan.CustodianPeers[0])
	response, _ := formalGLMPhase18SourceProjectTestRun(t, request)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope) != 3 || envelope["version"] == nil ||
		envelope["authorization_json"] == nil ||
		envelope["authorization_sha256"] == nil {
		t.Fatalf("source-project response is not minimal: %s", encoded)
	}

	var structured formalGLMRegisteredPhase18AuthorizationV1
	if err := json.Unmarshal([]byte(response.AuthorizationJSON),
		&structured); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(structured)
	if err != nil || string(canonical) != response.AuthorizationJSON {
		t.Fatal("authorization JSON is not byte-canonical")
	}
	var authorization any
	if err := json.Unmarshal([]byte(response.AuthorizationJSON),
		&authorization); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"capsule", "run_id", "analysis", "request", "lifetime", "ttl",
		"path", "private_key", "secret_key", "table_handle", "psi_token",
		"alignment_secret", "signature", "formal_analysis_ids",
		"attestation_id", "nonce",
	}
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				for _, fragment := range forbidden {
					if strings.Contains(strings.ToLower(key), fragment) {
						t.Errorf("forbidden source-project authorization field %q", key)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(authorization)
}
