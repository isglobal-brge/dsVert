package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func formalGLMPhase21PublicV2TestCertificate(t testing.TB,
	fixture formalGLMPhase21SamplerV2TestFixture,
) formalGLMPhase21PublicCertificateV2 {
	t.Helper()
	base := formalGLMPhase21SamplerV2TestUnsignedCertificate(t, fixture)
	promoted, err := formalGLMPhase21PromoteDurableV2(base, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	public, err := formalGLMPhase21BuildPublicCertificateV2(
		promoted, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]jointDPBiomedicalGaussianSignature, 2)
	for index, authority := range fixture.artifact.NoiseAuthorities {
		receipts[index], err = formalGLMPhase21SignPublicCertificateV2(
			public, authority.PeerName, fixture.keys[authority.PeerName],
			fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := formalGLMPhase21SealPublicCertificateV2(
		public, receipts, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestFormalGLMPhase21PublicV2CleanProjectionAndCAS_K2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPhase21SamplerV2TestSetup(
				t, custodians, formalGLMPhase21SamplerV2OneDraw)
			base := formalGLMPhase21SamplerV2TestUnsignedCertificate(t, fixture)
			promoted, err := formalGLMPhase21PromoteDurableV2(base, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			public, err := formalGLMPhase21BuildPublicCertificateV2(
				promoted, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			legacyChanged := promoted
			legacyChanged.CapsuleID = sha256Hex([]byte(t.Name() + "/capsule-rerun"))
			legacyChanged.SourceWorkloadSHA256 = sha256Hex(
				[]byte(t.Name() + "/workload-evidence-rerun"))
			legacyChanged.SourceReleaseInstanceID = sha256Hex(
				[]byte(t.Name() + "/source-instance-rerun"))
			legacyChanged.DPReleaseInstanceID = sha256Hex(
				[]byte(t.Name() + "/dp-instance-rerun"))
			legacyChanged.ReleaseContractSHA256 = sha256Hex(
				[]byte(t.Name() + "/release-contract-rerun"))
			legacyChanged.SelectionReason = "implementation_evidence_rerun"
			stable, err := formalGLMPhase21BuildPublicCertificateV2(
				legacyChanged, fixture.pins)
			if err != nil || !reflect.DeepEqual(public, stable) {
				t.Fatalf("legacy evidence changed public projection: %v", err)
			}

			unsignedBytes, err := json.Marshal(public)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range [][]byte{
				[]byte(`"capsule_id"`), []byte(`"release_instance`),
				[]byte(`"epoch`), []byte(`"reservation`), []byte(`"ledger`),
				[]byte(`"lifetime`), []byte(`"quota`), []byte(`"request`),
				[]byte(`"catalog`), []byte(`"source_workload`),
				[]byte(promoted.CapsuleID),
				[]byte(promoted.SourceReleaseInstanceID),
				[]byte(promoted.DPReleaseInstanceID),
			} {
				if bytes.Contains(unsignedBytes, forbidden) {
					t.Fatalf("public projection leaked %q", forbidden)
				}
			}

			receipts := make([]jointDPBiomedicalGaussianSignature, 2)
			for index, authority := range fixture.artifact.NoiseAuthorities {
				receipts[index], err = formalGLMPhase21SignPublicCertificateV2(
					public, authority.PeerName,
					fixture.keys[authority.PeerName], fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := formalGLMPhase21SealPublicCertificateV2(
				public, []jointDPBiomedicalGaussianSignature{
					receipts[1], receipts[0],
				}, fixture.pins); err == nil {
				t.Fatal("public projection accepted reordered authorities")
			}
			sealed, err := formalGLMPhase21SealPublicCertificateV2(
				public, receipts, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}

			var stores [2]*formalGLMPhase21StickyReleaseStore
			var roots [2]string
			for index, authority := range fixture.artifact.NoiseAuthorities {
				roots[index] = filepath.Join(t.TempDir(), authority.Role)
				stores[index], err = newFormalGLMPhase21StickyReleaseStore(
					roots[index], authority.PeerName,
					sha256.Sum256([]byte(t.Name()+"/store/"+authority.Role)),
					fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer func() {
				for _, store := range stores {
					store.close()
				}
			}()
			var publications [2]formalGLMPhase21StickyPublication
			for index := range stores {
				publications[index], err = stores[index].CommitPublicV2(sealed)
				if err != nil || publications[index].Replayed {
					t.Fatalf("initial public-v2 commit %d: %v", index, err)
				}
			}
			if publications[0].CertificateSHA256 !=
				publications[1].CertificateSHA256 ||
				!bytes.Equal(publications[0].Certificate,
					publications[1].Certificate) {
				t.Fatal("authority public-v2 bytes diverged")
			}
			for index := range stores {
				replay, err := stores[index].CommitPublicV2(sealed)
				if err != nil || !replay.Replayed || !bytes.Equal(
					replay.Certificate, publications[index].Certificate) {
					t.Fatalf("public-v2 replay %d: %v", index, err)
				}
				stores[index].close()
				stores[index], err = newFormalGLMPhase21StickyReleaseStore(
					roots[index], fixture.artifact.NoiseAuthorities[index].PeerName,
					sha256.Sum256([]byte(t.Name()+"/store/"+
						fixture.artifact.NoiseAuthorities[index].Role)), fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
				restarted, err := stores[index].ReplayPublicV2(fixture.artifactID)
				if err != nil || !bytes.Equal(
					restarted.Certificate, publications[index].Certificate) {
					t.Fatalf("public-v2 restart %d: %v", index, err)
				}
			}

			divergent := public
			divergent.ClampedScaledValues = append(
				[]string(nil), public.ClampedScaledValues...)
			divergent.ClampedScaledValues[0] = "12"
			divergent.VectorSHA256, err =
				jointDPBiomedicalGaussianOneDrawVectorSHA256(
					divergent.ClampedScaledValues)
			if err != nil {
				t.Fatal(err)
			}
			for index, authority := range fixture.artifact.NoiseAuthorities {
				receipts[index], err = formalGLMPhase21SignPublicCertificateV2(
					divergent, authority.PeerName,
					fixture.keys[authority.PeerName], fixture.pins)
				if err != nil {
					t.Fatal(err)
				}
			}
			divergentSealed, err := formalGLMPhase21SealPublicCertificateV2(
				divergent, receipts, fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stores[0].CommitPublicV2(divergentSealed); err == nil {
				t.Fatal("same ArtifactID accepted another public draw")
			}
		})
	}
}

func TestFormalGLMPhase21PublicV2RejectsUnsafeDurableRecord(t *testing.T) {
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, 2, formalGLMPhase21SamplerV2OneDraw)
	sealed := formalGLMPhase21PublicV2TestCertificate(t, fixture)
	authority := fixture.artifact.NoiseAuthorities[0]
	root := filepath.Join(t.TempDir(), "sticky")
	storageRoot := sha256.Sum256([]byte(t.Name() + "/store"))
	open := func() *formalGLMPhase21StickyReleaseStore {
		store, err := newFormalGLMPhase21StickyReleaseStore(
			root, authority.PeerName, storageRoot, fixture.pins)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	store := open()
	if _, err := store.CommitPublicV2(sealed); err != nil {
		t.Fatal(err)
	}
	path, err := formalGLMPhase21PublicV2RecordPath(store, fixture.artifactID)
	if err != nil {
		t.Fatal(err)
	}
	store.close()

	t.Run("mode", func(t *testing.T) {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		candidate := open()
		defer candidate.close()
		if _, err := candidate.ReplayPublicV2(fixture.artifactID); err == nil {
			t.Fatal("0644 public-v2 record was accepted")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		link := filepath.Join(filepath.Dir(path), "linked.json")
		if err := os.Link(path, link); err != nil {
			t.Fatal(err)
		}
		candidate := open()
		defer candidate.close()
		if _, err := candidate.ReplayPublicV2(fixture.artifactID); err == nil {
			t.Fatal("hard-linked public-v2 record was accepted")
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("tamper", func(t *testing.T) {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		encoded[len(encoded)-8] ^= 1
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		candidate := open()
		defer candidate.close()
		if _, err := candidate.ReplayPublicV2(fixture.artifactID); err == nil {
			t.Fatal("tampered public-v2 record was accepted")
		}
	})
}
