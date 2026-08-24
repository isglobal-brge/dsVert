package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFormalGLMRegisteredPhase20JobControlHostProvisionRockReplayAndFailClosed(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	config := formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 0)
	publication := formalGLMRegisteredPhase21PublicationContextTestBuildV1(
		t, fixture.core.source)
	config.Publication = &publication
	t.Cleanup(func() { formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config) })
	formalGLMRegisteredPhase20JobControlHostTestReleaseFixtureV1(t, fixture)

	command, err := json.Marshal(formalGLMRegisteredPhase20JobControlHostProvisionV1{
		Version: formalGLMRegisteredPhase20JobControlHostProvisionVersionV1,
		Config:  config,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(command)
	receipt, err := formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
		command, fixture.roots[0])
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Version != formalGLMRegisteredPhase20JobControlHostProvisionVersionV1 ||
		receipt.Peer != config.Peer ||
		receipt.ArtifactID != config.Start.ArtifactID ||
		receipt.ReceiptSetSHA256 != config.Start.ReceiptSetSHA256 ||
		receipt.ConfigSHA256 == "" || receipt.Replayed || receipt.ProductionReady {
		t.Fatalf("invalid host provision receipt: %+v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte(base64.StdEncoding.EncodeToString(config.Signing))) ||
		bytes.Contains(public, []byte(`"path"`)) ||
		bytes.Contains(public, []byte(`"key"`)) {
		t.Fatalf("host provision receipt exposed sensitive state: %s", public)
	}

	path, err := formalGLMRegisteredPhase20JobControlHostProvisionPathV1(
		fixture.roots[0], config.Peer, config.Start.ArtifactID,
		config.Start.ReceiptSetSHA256)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		!exactGCPrivateOwnedRegular(info) {
		t.Fatalf("host bootstrap is not an exact private regular record: %v / %v", info, err)
	}
	relative, err := formalGLMRegisteredPhase20JobControlHostProvisionRelativePathV1(
		config.Peer, config.Start.ArtifactID, config.Start.ReceiptSetSHA256)
	if err != nil {
		t.Fatal(err)
	}
	root, err := formalGLMRegisteredPhase19OpenRockRootV1(fixture.roots[0])
	if err != nil {
		t.Fatal(err)
	}
	persisted, _, err := formalGLMRegisteredPhase20JobControlHostProvisionReadConfigV1(
		root, relative)
	closeErr := root.Close()
	if err != nil || closeErr != nil || persisted.Publication == nil ||
		persisted.Publication.SourceContractCoreSHA256 != config.Contract.CoreSHA256 {
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&persisted)
		t.Fatalf("host bootstrap did not retain its private publication context: %v / %v", err, closeErr)
	}
	formalGLMRegisteredPhase20JobControlHostClearConfigV1(&persisted)

	host, err := formalGLMRegisteredPhase20JobControlHostOpenProvisionedV1(
		fixture.roots[0], receipt)
	if err != nil {
		t.Fatal(err)
	}
	encodedHost, err := json.Marshal(host)
	if err != nil || !bytes.Equal(encodedHost, []byte(`{}`)) {
		t.Fatalf("provisioned host exposed private state: %s / %v", encodedHost, err)
	}
	proposal, err := host.NegotiateV1(nil)
	if err != nil || proposal.state != formalGLMRegisteredPhase20JobControlProposalStateV1 ||
		len(proposal.outbound) == 0 || proposal.productionReady {
		t.Fatalf("provisioned host could not own the signed proposal: %+v / %v", proposal, err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(filepath.Dir(path),
		formalGLMRegisteredPhase20JobControlHostProvisionTempV1)
	if err := os.Link(path, temporary); err != nil {
		t.Fatal(err)
	}
	recovered, err := formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
		command, fixture.roots[0])
	_, temporaryErr := os.Lstat(temporary)
	if err != nil || !recovered.Replayed || !os.IsNotExist(temporaryErr) {
		t.Fatalf("linked bootstrap temporary did not recover: %+v / %v", recovered, err)
	}
	bootstrap, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporary, bootstrap, 0o600); err != nil {
		t.Fatal(err)
	}
	if replay, err := formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
		command, fixture.roots[0]); err != nil || !replay.Replayed {
		t.Fatalf("unlinked bootstrap temporary did not recover: %+v / %v", replay, err)
	}
	if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
		t.Fatalf("unlinked bootstrap temporary survived recovery: %v", err)
	}

	replay, err := formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
		command, fixture.roots[0])
	if err != nil || !replay.Replayed ||
		replay.ConfigSHA256 != receipt.ConfigSHA256 ||
		replay.Peer != receipt.Peer {
		t.Fatalf("host bootstrap replay changed: %+v / %v", replay, err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if host, err := formalGLMRegisteredPhase20JobControlHostOpenProvisionedV1(
		fixture.roots[0], receipt); err == nil || host != nil {
		t.Fatalf("non-0600 bootstrap was accepted: %#v / %v", host, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	hardlink := path + ".link"
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if host, err := formalGLMRegisteredPhase20JobControlHostOpenProvisionedV1(
		fixture.roots[0], receipt); err == nil || host != nil {
		t.Fatalf("hard-linked bootstrap was accepted: %#v / %v", host, err)
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMRegisteredPhase20JobControlHostProvisionRunAtRootV1(
		append(append([]byte(nil), command...), '\n'), fixture.roots[0]); err == nil {
		t.Fatal("non-canonical provision command was accepted")
	}
}
