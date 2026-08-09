package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	exactGCWorkerFailureVersion = "dsvert-exact-gc-failure-v1"
	exactGCRetryContractVersion = "same-operation-query-transcript-no-reroll-v1"
)

type exactGCFailureCode string

const (
	exactGCFailureInfrastructureUnavailable exactGCFailureCode = "infrastructure_unavailable"
	exactGCFailureNonIdentifiable           exactGCFailureCode = "non_identifiable"
	exactGCFailureBoundExceeded             exactGCFailureCode = "bound_exceeded"
	exactGCFailureNumericBackendUnavailable exactGCFailureCode = "numeric_backend_unavailable"
)

type exactGCClassifiedError struct {
	Code exactGCFailureCode
	Err  error
}

func (e *exactGCClassifiedError) Error() string { return e.Err.Error() }
func (e *exactGCClassifiedError) Unwrap() error { return e.Err }

func exactGCFailure(code exactGCFailureCode, err error) error {
	if err == nil {
		return nil
	}
	var classified *exactGCClassifiedError
	if errors.As(err, &classified) {
		return err
	}
	return &exactGCClassifiedError{Code: code, Err: err}
}

func exactGCFailureCodeOf(err error) exactGCFailureCode {
	var classified *exactGCClassifiedError
	if errors.As(err, &classified) && exactGCValidFailureCode(classified.Code) {
		return classified.Code
	}
	// Unknown runtime errors are deliberately coarsened. Detailed diagnostics
	// stay in the mode-0600 worker log and never become an analyst oracle.
	return exactGCFailureInfrastructureUnavailable
}

func exactGCValidFailureCode(code exactGCFailureCode) bool {
	switch code {
	case exactGCFailureInfrastructureUnavailable,
		exactGCFailureNonIdentifiable,
		exactGCFailureBoundExceeded,
		exactGCFailureNumericBackendUnavailable:
		return true
	default:
		return false
	}
}

type exactGCWorkerFailure struct {
	Version       string             `json:"version"`
	Code          exactGCFailureCode `json:"code"`
	Retryable     bool               `json:"retryable"`
	RetryContract string             `json:"retry_contract"`
	Operation     string             `json:"operation"`
	RingBits      int                `json:"ring_bits"`
	ContextHash   string             `json:"context_hash,omitempty"`
}

func exactGCWorkerFailureRecord(config exactGCWorkerConfig,
	session *exactGCSession, protocolErr error) exactGCWorkerFailure {
	code := exactGCFailureCodeOf(protocolErr)
	record := exactGCWorkerFailure{
		Version: exactGCWorkerFailureVersion, Code: code,
		Retryable: code == exactGCFailureInfrastructureUnavailable ||
			code == exactGCFailureNumericBackendUnavailable,
		RetryContract: exactGCRetryContractVersion,
		Operation:     config.Operation, RingBits: config.RingBits,
	}
	if session != nil {
		context := exactGCContextDigest(*session)
		record.ContextHash = hex.EncodeToString(context[:])
	}
	return record
}

// exactGCCommitWorkerFailure removes every success artifact before publishing
// a bounded, non-sensitive failure code. A failed worker can therefore never
// leave a partial result or a stale done marker that the server might consume.
func exactGCCommitWorkerFailure(dir string, config exactGCWorkerConfig,
	session *exactGCSession, protocolErr error) error {
	for _, name := range []string{"result.json", "done", "ready"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove partial exact-gc artifact: %w", err)
		}
	}
	record := exactGCWorkerFailureRecord(config, session, protocolErr)
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode exact-gc failure marker: %w", err)
	}
	if err := exactGCPrivateMarker(dir, "failure.json", encoded); err != nil {
		return fmt.Errorf("persist exact-gc failure marker: %w", err)
	}
	if err := exactGCPrivateMarker(dir, "error", []byte("1")); err != nil {
		return fmt.Errorf("persist exact-gc error marker: %w", err)
	}
	return nil
}
