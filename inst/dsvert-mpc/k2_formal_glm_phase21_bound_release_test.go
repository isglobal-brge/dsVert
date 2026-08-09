package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

type formalGLMPhase21TestFixture struct {
	formal            formalGLMPhase18FinalizerFixture
	runtime           map[string]formalGLMPhase19RuntimeScheduleResult
	stores            map[string]*formalGLMPhase20HandoffStore
	capsule           formalGLMPhase16CapsuleBinding
	request           formalGLMPhase16ProductiveRequest
	seeds             map[string][32]byte
	backendSignatures []jointDPBiomedicalGaussianSignature
	workerSignatures  []jointDPBiomedicalGaussianSignature
}

func formalGLMPhase21TestSetup(t testing.TB, custodians int,
	family string) formalGLMPhase21TestFixture {
	t.Helper()
	formal, runtime := formalGLMPhase16TestDurableRuntime(
		t, custodians, family)
	stores := formalGLMPhase20TestPersistStores(t, formal, runtime)
	capsule, request, seeds, _ := formalGLMPhase20TestOneDrawInputs(
		t, formal, runtime)
	referencePeer := formal.ctx.ComputePeers[0]
	draft, err := formalGLMPhase20BuildLocalRuntime(
		stores[referencePeer], formal.identities.public, capsule, request)
	if err != nil {
		t.Fatal(err)
	}
	defer draft.clear()
	backendSignatures := formalGLMPhase16TestSignBackendSelection(
		t, draft.Admission.Productive.BackendSelection.Contract,
		formal.identities.private)
	names := append([]string(nil), formal.plan.Kernel.CustodianPeers...)
	sort.Strings(names)
	workerSignatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(names))
	for _, name := range names {
		signature, err := formalGLMPhase16SignProductiveEnvelope(
			draft.Admission.Productive.Envelope.Preimage, name,
			formal.identities.private[name])
		if err != nil {
			t.Fatal(err)
		}
		workerSignatures = append(workerSignatures, signature)
	}
	return formalGLMPhase21TestFixture{
		formal: formal, runtime: runtime, stores: stores,
		capsule: capsule, request: request, seeds: seeds,
		backendSignatures: backendSignatures,
		workerSignatures:  workerSignatures,
	}
}

func (fixture *formalGLMPhase21TestFixture) close() {
	for _, store := range fixture.stores {
		store.close()
	}
}

func formalGLMPhase21TestRun(t testing.TB,
	fixture formalGLMPhase21TestFixture,
) map[string]formalGLMPhase21OneDrawLocalOutput {
	t.Helper()
	peers := fixture.formal.ctx.ComputePeers
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(90 * time.Second))
	_ = right.SetDeadline(time.Now().Add(90 * time.Second))
	outputs := make(map[string]formalGLMPhase21OneDrawLocalOutput, 2)
	errorsByPeer := make(map[string]error, 2)
	var lock sync.Mutex
	var wait sync.WaitGroup
	wait.Add(2)
	for index, peer := range peers {
		index, peer := index, peer
		connection := net.Conn(left)
		if index == 1 {
			connection = right
		}
		go func() {
			defer wait.Done()
			value, err := formalGLMPhase21RunOneDrawLocal(
				connection, fixture.stores[peer], fixture.capsule,
				fixture.request, fixture.backendSignatures,
				fixture.workerSignatures, fixture.seeds[peer],
				fixture.formal.identities.private[peer])
			lock.Lock()
			outputs[peer], errorsByPeer[peer] = value, err
			lock.Unlock()
		}()
	}
	wait.Wait()
	for _, peer := range peers {
		if errorsByPeer[peer] != nil {
			t.Fatalf("Phase-2.1 peer %s: %v", peer, errorsByPeer[peer])
		}
	}
	return outputs
}

func formalGLMPhase21TestCopyOutput(
	value formalGLMPhase21OneDrawLocalOutput,
) formalGLMPhase21OneDrawLocalOutput {
	result := value
	result.Shares = make([]*big.Int, len(value.Shares))
	for index := range value.Shares {
		result.Shares[index] = new(big.Int).Set(value.Shares[index])
	}
	return result
}

func TestFormalGLMPhase21SourceBoundReleaseBinomialPoissonK2K3K5(
	t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, custodians := range []int{2, 3, 5} {
			t.Run(family+"-K"+string(rune('0'+custodians)), func(t *testing.T) {
				fixture := formalGLMPhase21TestSetup(t, custodians, family)
				defer fixture.close()
				first := formalGLMPhase21TestRun(t, fixture)
				defer func() {
					for peer := range first {
						value := first[peer]
						value.clear()
					}
				}()
				encodedOutput, err := json.Marshal(
					first[fixture.formal.ctx.ComputePeers[0]])
				if err != nil || string(encodedOutput) != "{}" {
					t.Fatalf("Phase-2.1 private output acquired a JSON surface: %s / %v",
						encodedOutput, err)
				}

				// Restart every source store, then rerun from no caller-provided
				// share. Sticky private streams and absolute output masks must
				// reproduce the exact signed private outputs.
				for _, peer := range fixture.formal.ctx.ComputePeers {
					old := fixture.stores[peer]
					dir := old.dir
					old.close()
					storageRoot := sha256.Sum256(
						[]byte(t.Name() + "/handoff-key/" + peer))
					restarted, err := newFormalGLMPhase20HandoffStore(
						dir, old.semanticRoot, peer, storageRoot,
						fixture.runtime[peer].backend,
						fixture.formal.identities.public)
					if err != nil {
						t.Fatal(err)
					}
					fixture.stores[peer] = restarted
				}
				restarted := formalGLMPhase21TestRun(t, fixture)
				defer func() {
					for peer := range restarted {
						value := restarted[peer]
						value.clear()
					}
				}()
				for _, peer := range fixture.formal.ctx.ComputePeers {
					if !reflect.DeepEqual(first[peer].Receipt,
						restarted[peer].Receipt) ||
						!reflect.DeepEqual(first[peer].Shares,
							restarted[peer].Shares) ||
						first[peer].HandoffSHA256 !=
							restarted[peer].HandoffSHA256 {
						t.Fatal("Phase-2.1 restart changed a source-bound output")
					}
				}

				peers := fixture.formal.ctx.ComputePeers
				tampered := formalGLMPhase21TestCopyOutput(restarted[peers[0]])
				tampered.Shares[0].Add(tampered.Shares[0], big.NewInt(1))
				tampered.Shares[0].And(tampered.Shares[0], exactGCMask(128))
				if _, err := formalGLMPhase21PairOneDrawOutputs(
					tampered, restarted[peers[1]]); err == nil {
					tampered.clear()
					t.Fatal("Phase-2.1 accepted a caller-substituted output share")
				}
				tampered.clear()

				localReleases := make(map[string]jointDPBiomedicalGaussianOneDrawLocalRelease, 2)
				for _, peer := range peers {
					key := sha256.Sum256([]byte(t.Name() + "/release-store/" + peer))
					releaseStore, err :=
						newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
							filepath.Join(t.TempDir(), peer), peer, key,
							fixture.formal.identities.private[peer])
					if err != nil {
						t.Fatal(err)
					}
					other := peers[0]
					if other == peer {
						other = peers[1]
					}
					localReleases[peer], err =
						formalGLMPhase21FinalizeOneDrawLocal(
							fixture.stores[peer], releaseStore,
							restarted[peer], restarted[other], nil)
					if err != nil {
						t.Fatal(err)
					}
					replay, err := formalGLMPhase21FinalizeOneDrawLocal(
						fixture.stores[peer], releaseStore,
						restarted[peer], restarted[other], nil)
					if err != nil || !replay.Replayed ||
						!reflect.DeepEqual(replay.Receipt,
							localReleases[peer].Receipt) {
						t.Fatalf("Phase-2.1 durable replay changed: %#v %v",
							replay, err)
					}
				}
				certified, err := formalGLMPhase21CertifyOneDrawRelease(
					localReleases[peers[0]], localReleases[peers[1]],
					restarted[peers[0]].Admission)
				if err != nil {
					t.Fatal(err)
				}
				if certified.ProductionReady || certified.OpeningsPerformed != 1 ||
					len(certified.Blockers) == 0 ||
					certified.SelectedBackend != formalGLMPhase16BackendOneDraw {
					t.Fatal("Phase-2.1 overstated public formal-GLM readiness")
				}

				for _, peer := range peers {
					wrong := certified
					wrong.VectorSHA256 = sha256Hex([]byte("tampered public vector"))
					if _, err := formalGLMPhase21CleanupReleasedSource(
						fixture.stores[peer], restarted[peer], wrong); err == nil {
						t.Fatal("tampered release authorized source cleanup")
					}
					if !fileExists(fixture.stores[peer].recordPath) {
						t.Fatal("failed cleanup removed the durable source")
					}
					removed, err := formalGLMPhase21CleanupReleasedSource(
						fixture.stores[peer], restarted[peer], certified)
					if err != nil || removed != restarted[peer].HandoffBytes ||
						fileExists(fixture.stores[peer].recordPath) {
						t.Fatalf("release-bound cleanup failed: %d / %v", removed, err)
					}
				}
			})
		}
	}
}

func formalGLMPhase21TestInvalidateValidity(t testing.TB,
	fixture *formalGLMPhase18FinalizerFixture) {
	t.Helper()
	recipient := fixture.ctx.ComputePeers[0]
	frame, err := formalGLMPhase18DecodeIngressFrame(
		fixture.frames[recipient][0], fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := transportDecryptBytes(
		frame.Ciphertext, fixture.recipientSK[recipient])
	if err != nil {
		t.Fatal(err)
	}
	header, shares, err := formalGLMPhase18DecodePrivateHeader(plaintext, frame)
	clear(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	shares = append([]byte(nil), shares...)
	shares[len(shares)-1] ^= 1
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(headerJSON)))
	updated := append([]byte(nil), size[:]...)
	updated = append(updated, headerJSON...)
	updated = append(updated, shares...)
	clear(shares)
	frame.Ciphertext, err = transportEncryptBytes(
		updated, fixture.recipientPK[recipient])
	clear(updated)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(frame.Ciphertext)
	frame.CiphertextSHA256 = hex.EncodeToString(digest[:])
	frame.EnvelopeSHA256 = sha256Hex(append(
		[]byte("phase21/invalid-hidden-validity/"), digest[:]...))
	fixture.frames[recipient][0], err = formalGLMPhase18EncodeIngressFrame(
		frame, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
}

func formalGLMPhase21TestRuntimeFromFixture(t testing.TB,
	fixture formalGLMPhase18FinalizerFixture,
) map[string]formalGLMPhase19RuntimeScheduleResult {
	t.Helper()
	inputs := formalGLMPhase19RuntimeTestInputs(t, fixture)
	peers := fixture.ctx.ComputePeers
	prepared := make(map[string]formalGLMPhase19RuntimePrepareOutput, 2)
	for _, peer := range peers {
		value, err := formalGLMPhase19RuntimePrepare(inputs[peer])
		if err != nil {
			t.Fatal(err)
		}
		prepared[peer] = value
	}
	configs := make(map[string]formalGLMPhase19RuntimeDurableConfig, 2)
	checkpointRoot := t.TempDir()
	for _, peer := range peers {
		configs[peer] = formalGLMPhase19RuntimeDurableConfig{
			CheckpointDir: filepath.Join(checkpointRoot, peer),
			CheckpointKey: sha256.Sum256(
				[]byte(t.Name() + "/checkpoint/" + peer)),
			SigningKey:        fixture.identities.private[peer],
			Pins:              fixture.identities.public,
			OutputLatticeBits: fixture.plan.Kernel.FracBits,
		}
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(90 * time.Second))
	_ = right.SetDeadline(time.Now().Add(90 * time.Second))
	root := sha256.Sum256([]byte(t.Name() + "/runtime-root"))
	results := make(map[string]formalGLMPhase19RuntimeScheduleResult, 2)
	errorsByPeer := make(map[string]error, 2)
	var lock sync.Mutex
	var wait sync.WaitGroup
	wait.Add(2)
	for index, peer := range peers {
		index, peer := index, peer
		connection := net.Conn(left)
		other := peers[1]
		if index == 1 {
			connection, other = right, peers[0]
		}
		go func() {
			defer wait.Done()
			value, err := formalGLMPhase19RuntimeRunDurableSchedule(
				connection, []formalGLMPhase19RuntimeLocalInput{inputs[peer]},
				[]formalGLMPhase19FanInReceipt{prepared[other].Receipt},
				root, configs[peer])
			lock.Lock()
			results[peer], errorsByPeer[peer] = value, err
			lock.Unlock()
		}()
	}
	wait.Wait()
	for _, peer := range peers {
		if errorsByPeer[peer] != nil {
			t.Fatalf("invalid-validity runtime %s: %v", peer, errorsByPeer[peer])
		}
	}
	return results
}

func TestFormalGLMPhase21HiddenInvalidityIsDurableNoRelease(t *testing.T) {
	formal := formalGLMPhase18TestBuildFinalizerFixtureFamily(
		t, 3, "poisson")
	formalGLMPhase21TestInvalidateValidity(t, &formal)
	runtime := formalGLMPhase21TestRuntimeFromFixture(t, formal)
	stores := formalGLMPhase20TestPersistStores(t, formal, runtime)
	fixture := formalGLMPhase21TestFixture{
		formal: formal, runtime: runtime, stores: stores,
	}
	defer fixture.close()
	fixture.capsule, fixture.request, fixture.seeds, _ =
		formalGLMPhase20TestOneDrawInputs(t, formal, runtime)
	draft, err := formalGLMPhase20BuildLocalRuntime(
		stores[formal.ctx.ComputePeers[0]], formal.identities.public,
		fixture.capsule, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.backendSignatures = formalGLMPhase16TestSignBackendSelection(
		t, draft.Admission.Productive.BackendSelection.Contract,
		formal.identities.private)
	names := append([]string(nil), formal.plan.Kernel.CustodianPeers...)
	sort.Strings(names)
	for _, name := range names {
		signature, err := formalGLMPhase16SignProductiveEnvelope(
			draft.Admission.Productive.Envelope.Preimage, name,
			formal.identities.private[name])
		if err != nil {
			t.Fatal(err)
		}
		fixture.workerSignatures = append(fixture.workerSignatures, signature)
	}
	draft.clear()
	outputs := formalGLMPhase21TestRun(t, fixture)
	defer func() {
		for peer := range outputs {
			value := outputs[peer]
			value.clear()
		}
	}()
	peers := formal.ctx.ComputePeers
	for _, peer := range peers {
		key := sha256.Sum256([]byte(t.Name() + "/release-store/" + peer))
		releaseDir := filepath.Join(t.TempDir(), peer)
		releaseStore, err :=
			newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				releaseDir, peer, key, formal.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		other := peers[0]
		if other == peer {
			other = peers[1]
		}
		_, err = formalGLMPhase21FinalizeOneDrawLocal(
			stores[peer], releaseStore, outputs[peer], outputs[other], nil)
		var invalid *jointDPBiomedicalGaussianOneDrawInvalidSource
		if !errors.As(err, &invalid) {
			t.Fatalf("hidden invalidity was not a typed no-release: %T %v", err, err)
		}
		// The durable invalid-source state survives restart, contains no
		// public release receipt, and does not authorize source cleanup.
		restarted, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
			releaseDir, peer, key, formal.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		_, err = formalGLMPhase21FinalizeOneDrawLocal(
			stores[peer], restarted, outputs[peer], outputs[other], nil)
		if !errors.As(err, &invalid) {
			t.Fatalf("invalid no-release did not survive restart: %T %v", err, err)
		}
		recordPath, err := restarted.recordPath(
			outputs[peer].Admission.Envelope.Preimage.ReleaseInstanceID, false)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		record, err := jointDPBiomedicalGaussianOneDrawDecodeRecord(key, encoded)
		if err != nil || record.State != "invalid_source" ||
			record.ReleaseReceiptJSON != "" ||
			bytes.Contains(encoded, []byte(`"clamped_scaled_values"`)) {
			t.Fatalf("invalid execution persisted a public result: %#v %v", record, err)
		}
		if !fileExists(stores[peer].recordPath) {
			t.Fatal("no-release path removed the authenticated source handoff")
		}
	}
}

func TestFormalGLMPhase21RemainsOffCommandAndPublicReadinessSurfaces(
	t *testing.T) {
	encoded, err := json.Marshal(runtimeCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{
		[]byte("formal-glm-phase21"),
		[]byte(formalGLMPhase21BoundReleaseVersion),
		[]byte(formalGLMPhase21FullBoundReleaseVersion),
	} {
		if bytes.Contains(encoded, value) {
			t.Fatal("internal Phase-2.1 was advertised as a runtime capability")
		}
	}
	if !reflect.DeepEqual(formalGLMPhase16CertifiedReleaseBlockers,
		[]string{
			"r_dsi_verified_formal_glm_projection_not_wired_v1",
			"mixed_arithmetic_boolean_scalability_backend_not_benchmarked_v1",
			"physical_wall_clock_and_retransmission_cadence_dp_not_certified_v1",
			"semi_honest_two_compute_peer_protocol_only_v1",
			"unlimited_distinct_release_composition_has_no_finite_global_dp_bound_v1",
		}) {
		t.Fatal("Phase-2.1 changed the public promotion blockers")
	}
}
