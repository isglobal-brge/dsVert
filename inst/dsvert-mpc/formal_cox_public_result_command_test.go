package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"testing"
)

func formalCoxPublicResultTestPublication(t testing.TB, custodians int) (
	formalCoxBlockwiseOpeningPublication, map[string]string,
) {
	t.Helper()
	fixture := newFormalCoxBlockwiseOpeningTestFixture(
		t, custodians, fmt.Sprintf("public-result-k%d", custodians))
	t.Cleanup(func() { _ = fixture.store.Close() })
	fixture.submitAll(t)
	intent, publication, replayed, err := fixture.store.Prepare(nil)
	if err != nil || replayed || len(publication.Certificate) != 0 {
		t.Fatalf("prepare: replay=%v certificate=%d err=%v", replayed,
			len(publication.Certificate), err)
	}
	peers := fixture.plan.Policy.ComputePeers
	first, replayed, err := fixture.store.SignOnce(
		intent, peers[0], fixture.private[peers[0]], nil)
	if err != nil || replayed {
		t.Fatalf("first signature: replay=%v err=%v", replayed, err)
	}
	second, replayed, err := fixture.store.SignOnce(
		intent, peers[1], fixture.private[peers[1]],
		[]jointDPBiomedicalGaussianSignature{first})
	if err != nil || replayed {
		t.Fatalf("second signature: replay=%v err=%v", replayed, err)
	}
	publication, err = fixture.store.Publish(
		intent, []jointDPBiomedicalGaussianSignature{first, second}, nil)
	if err != nil || publication.Replayed {
		t.Fatalf("publish: replay=%v err=%v", publication.Replayed, err)
	}
	pins := make(map[string]string, len(fixture.pins))
	for peer, pin := range fixture.pins {
		pins[peer] = base64.RawURLEncoding.EncodeToString(pin)
	}
	return publication, pins
}

func TestFormalCoxPublicResultCommandK2K3K5AndTamper(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			publication, pins := formalCoxPublicResultTestPublication(t, custodians)
			request, err := json.Marshal(formalCoxPublicResultRequestV1{
				CertificateJSON: string(publication.Certificate), Pins: pins,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := formalCoxRunPublicResultV1(request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Version != formalCoxPublicResultVersion ||
				result.ArtifactID != publication.ArtifactID ||
				result.CertificateSHA256 != publication.CertificateSHA256 ||
				!result.Valid || result.ProductionReady ||
				len(result.Coefficients) != 2 ||
				result.Coefficients[0].BetaSteps != "64" ||
				result.Coefficients[1].BetaSteps != "-32" {
				t.Fatalf("unexpected public result: %#v", result)
			}
			for _, coefficient := range result.Coefficients {
				if math.IsNaN(coefficient.Beta) || math.IsInf(coefficient.Beta, 0) ||
					math.IsNaN(coefficient.HazardRatioLower) ||
					math.IsInf(coefficient.HazardRatioLower, 0) ||
					math.IsNaN(coefficient.HazardRatioUpper) ||
					math.IsInf(coefficient.HazardRatioUpper, 0) ||
					coefficient.HazardRatioLower <= 0 ||
					coefficient.HazardRatioUpper < coefficient.HazardRatioLower {
					t.Fatalf("non-plausible public coefficient: %#v", coefficient)
				}
			}
			replay, err := formalCoxRunPublicResultV1(request)
			if err != nil || !formalCoxPublicResultEqualV1(result, replay) {
				t.Fatalf("result replay: %#v / %v", replay, err)
			}

			tampered := append([]byte(nil), request...)
			for index := range tampered {
				if tampered[index] == '6' {
					tampered[index] = '7'
					break
				}
			}
			if _, err := formalCoxRunPublicResultV1(tampered); err == nil {
				t.Fatal("tampered public certificate was accepted")
			}
		})
	}
}
