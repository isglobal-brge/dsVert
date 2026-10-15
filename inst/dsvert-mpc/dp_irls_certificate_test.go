package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestDPIRLSProducerCertificateRBytes(t *testing.T) {
	f, err := os.Open("testdata/dp_irls_certificate_v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	count := 0
	for s.Scan() {
		var fixture struct {
			Certificate json.RawMessage `json:"certificate"`
			Digest      string          `json:"digest"`
		}
		if err := json.Unmarshal(s.Bytes(), &fixture); err != nil {
			t.Fatal(err)
		}
		var expected dpIRLSProducerProfile
		if err := json.Unmarshal(fixture.Certificate, &expected); err != nil {
			t.Fatal(err)
		}
		actual, err := dpIRLSProducerCertificate(expected.Family, expected.P, expected.Rows, expected.RowCap)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(actual)
		if !bytes.Equal(encoded, fixture.Certificate) || dpIRLSProducerCertificateDigest(actual) != fixture.Digest {
			t.Fatalf("R/Go producer certificate differs for %s", expected.Family)
		}
		count++
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected two R certificate fixtures, got %d", count)
	}
}

func TestDPIRLSProducerCertificateAdmission(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for rows := 1; rows <= 64; rows++ {
			c, err := dpIRLSProducerCertificate(family, 3, rows, 1)
			if err != nil {
				t.Fatal(err)
			}
			if c.S1G != 3*c.GCap || c.S1H != 6*c.HCap || c.GTranslation != int64(rows)*c.GCap || c.HTranslation != int64(rows)*c.HCap {
				t.Fatal("inconsistent lane calibration or translation")
			}
			if 2*c.GTranslation >= 1<<25 || 2*c.HTranslation >= 1<<25 {
				t.Fatal("headroom certificate")
			}
		}
	}
	for _, shape := range [][3]int{{2, 64, 1}, {5, 64, 1}, {10, 64, 1}, {3, 0, 1}, {3, 65, 1}, {3, 200, 1}, {3, 1000, 1}, {3, 64, 2}} {
		if _, err := dpIRLSProducerCertificate("binomial", shape[0], shape[1], shape[2]); err == nil {
			t.Fatalf("uncertified shape admitted: %v", shape)
		}
	}
	if _, err := dpIRLSProducerCertificate("gaussian", 3, 64, 1); err == nil {
		t.Fatal("uncertified family admitted")
	}
}

// These plans are emitted by .dsvert_dp_irls_stage_plan after authenticating a
// signed B1 contract and provisioning its durable store, not handwritten JSON.
func TestDPIRLSProducerSignedPointRBytes(t *testing.T) {
	f, err := os.Open("testdata/dp_irls_signed_point_v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	count := 0
	for s.Scan() {
		var p dpIRLSStagePlan
		if err := json.Unmarshal(s.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		if err := p.validate(); err != nil {
			t.Fatalf("authenticated R point rejected: %v", err)
		}
		encoded, err := json.Marshal(p)
		if err != nil || !bytes.Equal(encoded, s.Bytes()) {
			t.Fatal("R/Go signed point wire bytes differ")
		}
		if !p.Intercept || p.OffsetMode != "none" {
			t.Fatal("fixture should exercise enforced intercept and absent offset")
		}
		p.Beta[0] = "1"
		if p.validate() == nil {
			t.Fatal("alternate beta admitted with stale point digest")
		}
		count++
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected two authenticated R point fixtures, got %d", count)
	}
}
