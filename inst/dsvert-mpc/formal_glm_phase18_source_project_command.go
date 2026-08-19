package main

// Closed server-internal projection from one exact K-of-K source contract to
// one custodian's public Phase18 authorization. This command has no data,
// store, path, action or caller-selected artifact input.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	formalGLMPhase18SourceProjectResponseVersion = "dsvert-formal-glm-phase18-source-project-response-v1"
	formalGLMPhase18SourceProjectCommandMaxJSON  = (formalGLMSourceContractMaxJSON * 2) + (1 << 20)
)

type formalGLMPhase18SourceProjectRequestV1 struct {
	SourceContractJSON string            `json:"source_contract_json"`
	Pins               map[string]string `json:"pins"`
	LocalPeerName      string            `json:"local_peer_name"`
}

type formalGLMPhase18SourceProjectResponseV1 struct {
	Version             string `json:"version"`
	AuthorizationJSON   string `json:"authorization_json"`
	AuthorizationSHA256 string `json:"authorization_sha256"`
}

func formalGLMPhase18SourceProjectDecodeRequestV1(
	encoded []byte,
) (formalGLMPhase18SourceProjectRequestV1, error) {
	var request formalGLMPhase18SourceProjectRequestV1
	if len(encoded) < 2 ||
		len(encoded) > formalGLMPhase18SourceProjectCommandMaxJSON ||
		encoded[0] != '{' {
		return request, fmt.Errorf("formal-glm Phase18 source project: invalid request")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return formalGLMPhase18SourceProjectRequestV1{},
			fmt.Errorf("formal-glm Phase18 source project: invalid request")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return formalGLMPhase18SourceProjectRequestV1{},
			fmt.Errorf("formal-glm Phase18 source project: trailing request")
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, encoded) ||
		request.SourceContractJSON == "" ||
		!formalGLMRegistryLabelV1(request.LocalPeerName, 128) {
		return formalGLMPhase18SourceProjectRequestV1{},
			fmt.Errorf("formal-glm Phase18 source project: non-canonical request")
	}
	return request, nil
}

func formalGLMRunPhase18SourceProjectV1(
	encoded []byte,
) (formalGLMPhase18SourceProjectResponseV1, error) {
	var zero formalGLMPhase18SourceProjectResponseV1
	request, err := formalGLMPhase18SourceProjectDecodeRequestV1(encoded)
	if err != nil {
		return zero, err
	}
	pins, err := formalGLMPublicModelDecodePinsV1(request.Pins)
	if err != nil {
		return zero, err
	}
	contract, err := formalGLMDecodeSourceContractV1(
		[]byte(request.SourceContractJSON), pins)
	if err != nil {
		return zero, err
	}
	authorization, err := formalGLMBuildRegisteredPhase18AuthorizationV1(
		contract, request.LocalPeerName, pins)
	if err != nil {
		return zero, err
	}
	authorizationJSON, err := json.Marshal(authorization)
	if err != nil {
		return zero, err
	}
	return formalGLMPhase18SourceProjectResponseV1{
		Version:             formalGLMPhase18SourceProjectResponseVersion,
		AuthorizationJSON:   string(authorizationJSON),
		AuthorizationSHA256: authorization.AuthorizationSHA256,
	}, nil
}

func formalGLMPhase18SourceProjectReadCommandV1() ([]byte, error) {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalGLMPhase18SourceProjectCommandMaxJSON)+1))
	if err != nil || len(encoded) > formalGLMPhase18SourceProjectCommandMaxJSON {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm Phase18 source project: invalid command input")
	}
	return encoded, nil
}

func handleFormalGLMPhase18SourceProjectV1() {
	encoded, err := formalGLMPhase18SourceProjectReadCommandV1()
	if err != nil {
		mpcFatalError("formal-glm Phase18 source project failed")
	}
	defer clear(encoded)
	response, err := formalGLMRunPhase18SourceProjectV1(encoded)
	if err != nil {
		mpcFatalError("formal-glm Phase18 source project failed")
	}
	output(response)
}
