package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func formalGLMPublicAdvanceStoreTestNew(
	t testing.TB, dir string, fixture formalGLMPublicEndpointTestFixture,
) *formalGLMPublicAdvanceStoreV1 {
	t.Helper()
	peer := fixture.phase21.artifact.CustodianPeers[0]
	store, err := newFormalGLMPublicAdvanceStoreV1(
		dir, fixture.phase21.pins, peer, fixture.phase21.keys[peer])
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func formalGLMPublicAdvanceStoreTestEndpoint(
	t testing.TB, fixture formalGLMPublicEndpointTestFixture,
	store *formalGLMPublicAdvanceStoreV1,
	driver formalGLMPublicAdvanceFuncV1,
) *formalGLMPublicEndpointV1 {
	t.Helper()
	peer := fixture.phase21.artifact.CustodianPeers[0]
	endpoint, err := newFormalGLMPublicEndpointWithAdvanceStoreV1(
		fixture.store, fixture.receipts, fixture.phase21.pins,
		peer, fixture.phase21.keys[peer], driver, store)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

func TestFormalGLMPublicAdvanceStoreK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicEndpointTestSetup(t, custodians)
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "advance")
			store := formalGLMPublicAdvanceStoreTestNew(t, dir, fixture)
			driverCalls := 0
			terminal := formalGLMPublicEndpointTestTerminal(t, fixture)
			bootstrap := formalGLMPublicEndpointTestNew(
				t, fixture, func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					return formalGLMPublicAdvanceObservationV1{},
						fmt.Errorf("bootstrap driver reached")
				})
			resolved, receipt := formalGLMPublicEndpointTestResolve(
				t, bootstrap, fixture.selector)
			peerFrame := []byte(`{"opaque":"inbound-frame-must-not-persist"}`)
			receiptSHA256 := formalGLMPublicReceiptSHA256V1(
				[]byte(resolved.ReceiptFrameJSON))
			peerSHA256, err := formalGLMPublicValidateOpaquePeerFrameV1(peerFrame)
			if err != nil {
				t.Fatal(err)
			}
			if pending, exists, beginErr := store.BeginV1(
				receipt, receiptSHA256, peerSHA256); beginErr != nil || exists ||
				pending != (formalGLMPublicAdvanceResponseV1{}) {
				t.Fatalf("durable pending request = %+v exists=%v err=%v",
					pending, exists, beginErr)
			}
			store.Close()
			store = formalGLMPublicAdvanceStoreTestNew(t, dir, fixture)
			endpoint := formalGLMPublicAdvanceStoreTestEndpoint(
				t, fixture, store, func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					driverCalls++
					return formalGLMPublicAdvanceObservationV1{Terminal: &terminal}, nil
				})
			first, err := endpoint.Advance(
				[]byte(resolved.ReceiptFrameJSON), peerFrame)
			if err != nil || first.State != formalGLMPublicStateComplete ||
				first.Replayed || first.PublicV2JSON == "" || driverCalls != 1 {
				t.Fatalf("initial durable Advance = %+v calls=%d err=%v",
					first, driverCalls, err)
			}
			if encoded, marshalErr := json.Marshal(store); marshalErr != nil ||
				string(encoded) != "{}" {
				t.Fatalf("advance store exposed private state: %q %v", encoded, marshalErr)
			}
			responsePath, pathErr := store.responseRelativePathV1(
				receiptSHA256, false)
			if pathErr != nil {
				t.Fatal(pathErr)
			}
			encodedResponse, readErr := os.ReadFile(filepath.Join(dir, responsePath))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.Contains(string(encodedResponse), string(peerFrame)) ||
				strings.Contains(string(encodedResponse), "canonical_dp_share") {
				t.Fatal("durable advance response exposed protected frame material")
			}
			store.Close()

			reopenedStore := formalGLMPublicAdvanceStoreTestNew(t, dir, fixture)
			defer reopenedStore.Close()
			reopenedCalls := 0
			reopened := formalGLMPublicAdvanceStoreTestEndpoint(
				t, fixture, reopenedStore, func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					reopenedCalls++
					return formalGLMPublicAdvanceObservationV1{}, fmt.Errorf("durable replay reran driver")
				})
			replayed, replayErr := reopened.Advance(
				[]byte(resolved.ReceiptFrameJSON), peerFrame)
			if replayErr != nil || !replayed.Replayed || reopenedCalls != 0 ||
				!reflect.DeepEqual(first.PublicV2JSON, replayed.PublicV2JSON) ||
				first.ReceiptFrameJSON != replayed.ReceiptFrameJSON {
				t.Fatalf("reopened durable replay = %+v calls=%d err=%v",
					replayed, reopenedCalls, replayErr)
			}
			if _, err := reopened.Advance(
				[]byte(resolved.ReceiptFrameJSON), []byte(`{}`)); err == nil ||
				reopenedCalls != 0 {
				t.Fatalf("different peer frame reused durable receipt: calls=%d err=%v",
					reopenedCalls, err)
			}

			if err := os.WriteFile(filepath.Join(dir, responsePath),
				append([]byte("x"), encodedResponse[1:]...), 0o600); err != nil {
				t.Fatal(err)
			}
			reopenedStore.Close()
			tamperedStore := formalGLMPublicAdvanceStoreTestNew(t, dir, fixture)
			defer tamperedStore.Close()
			tampered := formalGLMPublicAdvanceStoreTestEndpoint(
				t, fixture, tamperedStore, func(formalGLMPublicAdvanceContextV1) (
					formalGLMPublicAdvanceObservationV1, error,
				) {
					return formalGLMPublicAdvanceObservationV1{}, fmt.Errorf("tamper reached driver")
				})
			if _, err := tampered.Advance(
				[]byte(resolved.ReceiptFrameJSON), peerFrame); err == nil {
				t.Fatal("tampered durable response was accepted")
			}
		})
	}
}
