package main

// Closed outer command envelope shared by the GLM and Cox Rock-local
// lifecycles. Family handlers still decode their operation into exact typed
// schemas; this layer never accepts an arbitrary payload or store path.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	formalTypedFinalizerLifecycleVersion   = "dsvert-typed-finalizer-lifecycle-v1"
	formalTypedFinalizerLifecycleMaxConfig = 256 << 10

	formalGLMPhase21RockActionPreflight          = "preflight-local"
	formalGLMPhase21RockActionStage              = "stage-local"
	formalGLMPhase21RockActionTicket             = "issue-ticket"
	formalGLMPhase21RockActionSeal               = "seal-local"
	formalGLMPhase21RockActionPrepareCandidate   = "prepare-candidate-finalizer"
	formalGLMPhase21RockActionVerifyCandidate    = "verify-candidate-local"
	formalGLMPhase21RockActionPrepareCertificate = "prepare-certificate-finalizer"
	formalGLMPhase21RockActionSignCertificate    = "sign-certificate-local"
	formalGLMPhase21RockActionPreparePublication = "prepare-publication-finalizer"
	formalGLMPhase21RockActionCommitPublication  = "commit-publication-local"
	formalGLMPhase21RockActionFinalizeAck        = "finalize-ack"
	formalGLMPhase21RockActionAck                = "ack-local"
)

type formalTypedFinalizerLifecycleRequest struct {
	Version   string          `json:"version"`
	Family    string          `json:"family"`
	Action    string          `json:"action"`
	Operation json.RawMessage `json:"operation"`
}

func formalTypedFinalizerLifecycleRootAt(configPath, stateRoot string) (
	string, error,
) {
	if !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath ||
		!filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return "", fmt.Errorf("typed-finalizer-lifecycle: invalid config path")
	}
	relative, err := filepath.Rel(stateRoot, configPath)
	if err != nil || relative == "." || relative == "" || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("typed-finalizer-lifecycle: config left Rock state")
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) < 2 || !formalFinalizerHandoffPathSafePeerName(parts[0]) {
		return "", fmt.Errorf("typed-finalizer-lifecycle: invalid local authority")
	}
	root := filepath.Join(stateRoot, parts[0])
	if !strings.HasPrefix(configPath, root+string(filepath.Separator)) {
		return "", fmt.Errorf("typed-finalizer-lifecycle: config escaped authority root")
	}
	return root, nil
}

func formalTypedFinalizerLifecycleProductionRoot(configPath string) (
	string, error,
) {
	return formalTypedFinalizerLifecycleRootAt(
		configPath, formalFinalizerHandoffStateRoot)
}

func formalTypedFinalizerLifecycleRequireLocalAuthority(
	rootPath, stateRoot, peerName string,
) error {
	if !formalFinalizerHandoffPathSafePeerName(peerName) ||
		rootPath != filepath.Join(stateRoot, peerName) {
		return fmt.Errorf(
			"typed-finalizer-lifecycle: local authority root mismatch")
	}
	return nil
}

func formalTypedFinalizerLifecycleActionAllowed(family, action string) bool {
	switch family {
	case formalFinalizerHandoffFamilyGLM:
		switch action {
		case formalGLMPhase21RockActionPreflight,
			formalGLMPhase21RockActionStage,
			formalGLMPhase21RockActionTicket,
			formalGLMPhase21RockActionSeal,
			formalGLMPhase21RockActionPrepareCandidate,
			formalGLMPhase21RockActionVerifyCandidate,
			formalGLMPhase21RockActionPrepareCertificate,
			formalGLMPhase21RockActionSignCertificate,
			formalGLMPhase21RockActionPreparePublication,
			formalGLMPhase21RockActionCommitPublication,
			formalGLMPhase21RockActionFinalizeAck,
			formalGLMPhase21RockActionAck:
			return true
		}
	case formalFinalizerHandoffFamilyCox:
		switch action {
		case formalCoxBlockwiseRockActionPreflight,
			formalCoxBlockwiseRockActionStage,
			formalCoxBlockwiseRockActionTicket,
			formalCoxBlockwiseRockActionSeal,
			formalCoxBlockwiseRockActionPrepare,
			formalCoxBlockwiseRockActionSign,
			formalCoxBlockwiseRockActionPreparePublication,
			formalCoxBlockwiseRockActionCommitPublication,
			formalCoxBlockwiseRockActionFinalizeAck,
			formalCoxBlockwiseRockActionAck:
			return true
		}
	}
	return false
}

func formalTypedFinalizerLifecycleReadRequestAtRoot(
	configPath, stateRoot string,
) (
	formalTypedFinalizerLifecycleRequest, string, error,
) {
	var request formalTypedFinalizerLifecycleRequest
	rootPath, err := formalTypedFinalizerLifecycleRootAt(configPath, stateRoot)
	if err != nil {
		return request, "", err
	}
	if err := formalFinalizerHandoffEnsurePrivateDir(stateRoot); err != nil {
		return request, "", err
	}
	if err := formalFinalizerHandoffEnsurePrivateDir(rootPath); err != nil {
		return request, "", err
	}
	resolvedState, stateErr := filepath.EvalSymlinks(stateRoot)
	resolved, err := filepath.EvalSymlinks(rootPath)
	if stateErr != nil || err != nil ||
		filepath.Clean(resolvedState) != stateRoot ||
		filepath.Clean(resolved) != filepath.Join(
			filepath.Clean(resolvedState), filepath.Base(rootPath)) {
		return request, "", fmt.Errorf(
			"typed-finalizer-lifecycle: redirected authority root")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return request, "", err
	}
	defer root.Close()
	relative, err := filepath.Rel(rootPath, configPath)
	if err != nil || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return request, "", fmt.Errorf("typed-finalizer-lifecycle: invalid config slot")
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		root, relative, formalTypedFinalizerLifecycleMaxConfig)
	if err != nil {
		return request, "", fmt.Errorf("typed-finalizer-lifecycle: unreadable config")
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, "", fmt.Errorf("typed-finalizer-lifecycle: invalid config")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF ||
		request.Version != formalTypedFinalizerLifecycleVersion ||
		(request.Family != formalFinalizerHandoffFamilyGLM &&
			request.Family != formalFinalizerHandoffFamilyCox) ||
		!formalTypedFinalizerLifecycleActionAllowed(
			request.Family, request.Action) ||
		len(request.Operation) < 2 || request.Operation[0] != '{' ||
		!json.Valid(request.Operation) {
		clear(request.Operation)
		return formalTypedFinalizerLifecycleRequest{}, "",
			fmt.Errorf("typed-finalizer-lifecycle: rejected command envelope")
	}
	return request, rootPath, nil
}

func formalTypedFinalizerLifecycleReadRequest(configPath string) (
	formalTypedFinalizerLifecycleRequest, string, error,
) {
	return formalTypedFinalizerLifecycleReadRequestAtRoot(
		configPath, formalFinalizerHandoffStateRoot)
}

type formalTypedFinalizerLifecycleHandler func(
	root, action string, operation json.RawMessage,
) error

func formalTypedFinalizerLifecycleRemoveConfig(
	configPath, rootPath string,
) error {
	relative, err := filepath.Rel(rootPath, configPath)
	if err != nil || filepath.IsAbs(relative) || relative == "." ||
		filepath.Clean(relative) != relative {
		return fmt.Errorf("typed-finalizer-lifecycle: invalid config cleanup")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("typed-finalizer-lifecycle: config cleanup failed")
	}
	defer root.Close()
	info, err := root.Lstat(relative)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() < 64 || info.Size() > formalTypedFinalizerLifecycleMaxConfig ||
		!exactGCPrivateOwnedRegular(info) {
		return fmt.Errorf("typed-finalizer-lifecycle: config cleanup refused")
	}
	if err := root.Remove(relative); err != nil {
		return fmt.Errorf("typed-finalizer-lifecycle: config cleanup failed")
	}
	if err := formalGLMPhase21RootSyncDir(root, relative); err != nil {
		return fmt.Errorf("typed-finalizer-lifecycle: config cleanup sync failed")
	}
	return nil
}

func formalTypedFinalizerLifecycleDispatchRequest(
	configPath, rootPath string,
	request formalTypedFinalizerLifecycleRequest,
	glm, cox formalTypedFinalizerLifecycleHandler,
) error {
	defer clear(request.Operation)
	if glm == nil || cox == nil {
		return fmt.Errorf("typed-finalizer-lifecycle: invalid handler")
	}
	var err error
	switch request.Family {
	case formalFinalizerHandoffFamilyGLM:
		err = glm(rootPath, request.Action, request.Operation)
	case formalFinalizerHandoffFamilyCox:
		err = cox(rootPath, request.Action, request.Operation)
	default:
		return fmt.Errorf("typed-finalizer-lifecycle: rejected family")
	}
	if err != nil {
		return fmt.Errorf("typed-finalizer-lifecycle: action failed")
	}
	if err := formalTypedFinalizerLifecycleRemoveConfig(
		configPath, rootPath); err != nil {
		return err
	}
	return nil
}

func formalTypedFinalizerLifecycleDispatchAtRoot(
	configPath, stateRoot string,
	glm, cox formalTypedFinalizerLifecycleHandler,
) error {
	request, rootPath, err := formalTypedFinalizerLifecycleReadRequestAtRoot(
		configPath, stateRoot)
	if err != nil {
		return err
	}
	return formalTypedFinalizerLifecycleDispatchRequest(
		configPath, rootPath, request, glm, cox)
}

func handleFormalTypedFinalizerLifecycle(configPath string) error {
	request, rootPath, err := formalTypedFinalizerLifecycleReadRequest(configPath)
	if err != nil {
		return err
	}
	return formalTypedFinalizerLifecycleDispatchRequest(
		configPath, rootPath, request,
		handleFormalGLMPhase21RockLifecycle,
		handleFormalCoxBlockwiseRockLifecycle)
}
