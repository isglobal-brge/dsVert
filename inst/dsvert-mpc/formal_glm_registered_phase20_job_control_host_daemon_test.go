package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The production constructor receives a socket directory derived from the
// provisioned Rock root. This test-only convenience keeps isolated daemon
// tests independent of a host provision.
func formalGLMRegisteredPhase20JobControlHostDaemonPrivateDirV1() (
	string, *os.Root, os.FileInfo, error,
) {
	directory, err := os.MkdirTemp("", "dsvert-glm-job-")
	if err != nil || os.Chmod(directory, 0o700) != nil {
		if directory != "" {
			_ = os.RemoveAll(directory)
		}
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || !formalFinalizerHandoffPrivateOwnedDirectory(info) {
		_ = os.RemoveAll(directory)
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket directory")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !opened.IsDir() ||
		opened.Mode().Perm() != 0o700 || !formalFinalizerHandoffPrivateOwnedDirectory(opened) {
		_ = root.Close()
		_ = os.RemoveAll(directory)
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: socket directory changed")
	}
	return directory, root, opened, nil
}

func newFormalGLMRegisteredPhase20JobControlHostDaemonV1(
	host *formalGLMRegisteredPhase20JobControlHostV1, controlKey []byte,
) (*formalGLMRegisteredPhase20JobControlHostDaemonV1, error) {
	if host == nil || len(controlKey) != sha256.Size {
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: invalid configuration")
	}
	socketDir, root, info, err := formalGLMRegisteredPhase20JobControlHostDaemonPrivateDirV1()
	if err != nil {
		return nil, err
	}
	return newFormalGLMRegisteredPhase20JobControlHostDaemonAtOpenDirV1(
		host, controlKey, socketDir, root, info)
}

func TestFormalGLMRegisteredPhase20JobControlHostDaemonK2(t *testing.T) {
	fixture := newFormalGLMRegisteredPhase20JobControlTestFixtureV1(t)
	config := formalGLMRegisteredPhase20JobControlHostTestConfigV1(t, fixture, 1)
	formalGLMRegisteredPhase20JobControlHostTestReleaseFixtureV1(t, fixture)
	host, err := newFormalGLMRegisteredPhase20JobControlHostV1(fixture.roots[1], config)
	if err != nil {
		t.Fatal(err)
	}

	key := sha256.Sum256([]byte(t.Name() + "/control-key"))
	daemon, err := newFormalGLMRegisteredPhase20JobControlHostDaemonV1(
		host, key[:])
	if err != nil {
		_ = host.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	t.Cleanup(func() { _ = daemon.Close() })
	socketPath := daemon.SocketPathV1()
	socketDir := filepath.Dir(socketPath)
	if info, statErr := os.Lstat(socketDir); statErr != nil || !info.IsDir() ||
		info.Mode().Perm() != 0o700 || !formalFinalizerHandoffPrivateOwnedDirectory(info) {
		t.Fatalf("daemon created an unsafe transient socket directory: %q / %v", socketDir, statErr)
	}

	if encoded, marshalErr := json.Marshal(daemon); marshalErr != nil ||
		!bytes.Equal(encoded, []byte(`{}`)) {
		t.Fatalf("daemon exposed private host state: %q / %v", encoded, marshalErr)
	}
	client, err := newFormalGLMRegisteredPhase20JobControlHostDaemonClientV1(
		socketPath, key[:])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err := client.HealthV1(); err != nil {
		t.Fatalf("authenticated health check failed: %v", err)
	}
	wrongKey := sha256.Sum256([]byte(t.Name() + "/wrong-control-key"))
	wrong, err := newFormalGLMRegisteredPhase20JobControlHostDaemonClientV1(
		socketPath, wrongKey[:])
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err := wrong.NegotiateV1(nil); err == nil {
		t.Fatal("daemon accepted a control frame with the wrong MAC key")
	}

	waiting, err := client.NegotiateV1(nil)
	if err != nil || waiting.State !=
		formalGLMRegisteredPhase20JobControlWaitingProposalStateV1 ||
		len(waiting.Outbound) != 0 || waiting.ProductionReady {
		t.Fatalf("daemon evaluator wait: state=%q outbound=%d inspect=%t ready=%t / %v",
			waiting.State, len(waiting.Outbound), waiting.InspectOnly,
			waiting.ProductionReady, err)
	}
	if err := daemon.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("daemon socket survived close: %v", err)
	}
	if _, err := os.Lstat(socketDir); !os.IsNotExist(err) {
		t.Fatalf("daemon socket directory survived close: %v", err)
	}
	if err := client.HealthV1(); err == nil {
		t.Fatal("closed daemon passed a health check")
	}
	if _, err := client.NegotiateV1(nil); err == nil {
		t.Fatal("closed daemon accepted another control frame")
	}
}

func formalGLMRegisteredPhase20JobControlHostDaemonRelayLoopV1(
	stop <-chan struct{}, from, to *formalGLMRegisteredPhase20JobControlHostDaemonClientV1,
	fromRef, toRef formalGLMRegisteredPhase20JobRefV1,
	errs chan<- error, done chan<- struct{},
) {
	defer func() { done <- struct{}{} }()
	acknowledged := int64(0)
	for {
		select {
		case <-stop:
			return
		default:
		}
		result, err := from.PollV1(fromRef, acknowledged)
		if err != nil {
			errs <- err
			return
		}
		if result.RelayChunk == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		acknowledged, err = to.RelayV1(toRef, *result.RelayChunk)
		if err != nil {
			errs <- err
			return
		}
	}
}

func formalGLMRegisteredPhase20JobControlHostDaemonRunsFromPendingIngressV1(
	t *testing.T, custodians int,
) {
	t.Helper()
	fixture := formalGLMRegisteredPhase20JobComputeTestBuild(t, custodians, 9)
	for index := range fixture.roots {
		formalGLMRegisteredPhase20JobIngressBridgeTestPersistPendingV1(t, fixture, index)
		if err := fixture.owners[index].Close(); err != nil {
			t.Fatal(err)
		}
		fixture.owners[index] = nil
	}

	daemons := [2]*formalGLMRegisteredPhase20JobControlHostDaemonV1{}
	clients := [2]*formalGLMRegisteredPhase20JobControlHostDaemonClientV1{}
	for index := range daemons {
		config := formalGLMRegisteredPhase20JobControlHostComputeConfigV1(t, fixture, index)
		host, err := newFormalGLMRegisteredPhase20JobControlHostV1(fixture.roots[index], config)
		if err != nil {
			t.Fatal(err)
		}
		key := sha256.Sum256([]byte(t.Name() + "/control/" + string(rune('0'+index))))
		daemon, err := newFormalGLMRegisteredPhase20JobControlHostDaemonV1(host, key[:])
		if err != nil {
			_ = host.Close()
			t.Fatal(err)
		}
		daemons[index] = daemon
		t.Cleanup(func() { _ = host.Close() })
		t.Cleanup(func() { _ = daemon.Close() })
		client, err := newFormalGLMRegisteredPhase20JobControlHostDaemonClientV1(
			daemon.SocketPathV1(), key[:])
		if err != nil {
			t.Fatal(err)
		}
		clients[index] = client
		t.Cleanup(client.Close)
	}

	proposal, err := clients[0].NegotiateV1(nil)
	if err != nil || len(proposal.Outbound) == 0 {
		t.Fatalf("daemon proposal: outbound=%d / %v", len(proposal.Outbound), err)
	}
	accept, err := clients[1].NegotiateV1(proposal.Outbound)
	if err != nil || len(accept.Outbound) == 0 {
		t.Fatalf("daemon acceptance: outbound=%d / %v", len(accept.Outbound), err)
	}
	if _, err := clients[0].NegotiateV1(accept.Outbound); err != nil {
		t.Fatal(err)
	}

	refs := [2]formalGLMRegisteredPhase20JobRefV1{}
	claims := [2][]byte{}
	for index := range clients {
		started, err := clients[index].StartOrInspectV1()
		if err != nil || started.State != formalGLMRegisteredPhase20JobOwnerRunningStateV1 ||
			started.InspectOnly || started.ProductionReady {
			t.Fatalf("daemon %d start: %#v / %v", index, started, err)
		}
		frame, err := clients[index].JobRefV1()
		if err != nil || frame.Ref.ProductionReady || len(frame.Claim) == 0 {
			t.Fatalf("daemon %d job ref: %#v / %v", index, frame, err)
		}
		refs[index], claims[index] = frame.Ref, frame.Claim
	}
	if refs[0] != refs[1] {
		t.Fatal("daemon peers derived different JobRefs")
	}
	for index := range clients {
		if err := clients[index].BindPeerJobRefV1(claims[1-index]); err != nil {
			t.Fatal(err)
		}
		if err := clients[index].HeartbeatV1(); err != nil {
			t.Fatal(err)
		}
	}

	stop := make(chan struct{})
	relayErrs := make(chan error, 2)
	relayDone := make(chan struct{}, 2)
	for index := range clients {
		go formalGLMRegisteredPhase20JobControlHostDaemonRelayLoopV1(
			stop, clients[index], clients[1-index], refs[index], refs[1-index], relayErrs, relayDone)
	}
	for index := range clients {
		status, startErr := clients[index].StartComputeV1()
		if startErr != nil || (status.State != "running" && status.State != "complete") ||
			status.ProductionReady || status.Commit != nil {
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatalf("daemon %d compute start: %#v / %v", index, status, startErr)
		}
	}
	computeDeadline := time.After(90 * time.Second)
	for {
		complete := 0
		for index := range clients {
			status, statusErr := clients[index].ComputeStatusV1()
			if statusErr != nil || status.State == "failed" || status.ProductionReady ||
				status.Commit != nil {
				close(stop)
				<-relayDone
				<-relayDone
				t.Fatalf("daemon %d compute status: %#v / %v", index, status, statusErr)
			}
			if status.State == "complete" {
				complete++
			} else if status.State != "running" {
				close(stop)
				<-relayDone
				<-relayDone
				t.Fatalf("daemon %d invalid compute state: %#v", index, status)
			}
		}
		if complete == len(clients) {
			break
		}
		select {
		case err := <-relayErrs:
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal(err)
		case <-computeDeadline:
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal("daemon compute did not complete")
		case <-time.After(time.Millisecond):
		}
	}

	for index := range clients {
		status, startErr := clients[index].StartTerminalV1()
		if startErr != nil || (status.State != "running" && status.State != "complete") ||
			status.ProductionReady || status.Commit != nil {
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatalf("daemon %d terminal start: %#v / %v", index, status, startErr)
		}
	}
	var commits [2]formalGLMPhase20HandoffCommit
	terminalDeadline := time.After(90 * time.Second)
	for {
		complete := 0
		for index := range clients {
			status, statusErr := clients[index].TerminalStatusV1()
			if statusErr != nil || status.State == "failed" || status.ProductionReady {
				close(stop)
				<-relayDone
				<-relayDone
				t.Fatalf("daemon %d terminal status: %#v / %v", index, status, statusErr)
			}
			if status.State == "complete" {
				if status.Commit == nil {
					close(stop)
					<-relayDone
					<-relayDone
					t.Fatalf("daemon %d terminal completion omitted the handoff commitment", index)
				}
				commits[index] = *status.Commit
				complete++
			} else if status.State != "running" || status.Commit != nil {
				close(stop)
				<-relayDone
				<-relayDone
				t.Fatalf("daemon %d invalid terminal state: %#v", index, status)
			}
		}
		if complete == len(clients) {
			break
		}
		select {
		case err := <-relayErrs:
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal(err)
		case <-terminalDeadline:
			close(stop)
			<-relayDone
			<-relayDone
			t.Fatal("daemon terminal did not complete")
		case <-time.After(time.Millisecond):
		}
	}
	close(stop)
	<-relayDone
	<-relayDone
	select {
	case err := <-relayErrs:
		t.Fatal(err)
	default:
	}
	for index := range commits {
		if !formalGLMIsSHA256(commits[index].SHA256) || commits[index].Bytes < 64 ||
			commits[index].Replayed {
			t.Fatalf("daemon %d did not return an encrypted handoff commitment: %#v", index, commits[index])
		}
	}
}

func TestFormalGLMRegisteredPhase20JobControlHostDaemonRunsK2K3K5FromPendingIngress(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			formalGLMRegisteredPhase20JobControlHostDaemonRunsFromPendingIngressV1(t, custodians)
		})
	}
}
