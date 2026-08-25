package main

// A live registered job owns one exact-GC spool and cannot be reconstructed
// for every local R command.  This private Unix-socket adapter lets a later
// Rock-only provisioner attach authenticated local commands to that one host.
// It deliberately exposes only authenticated job frames, encrypted handoff
// commitments, and signed Phase21 lifecycle records. It never exposes the
// host configuration, stores, paths, keys, shares, or a raw result.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	formalGLMRegisteredPhase20JobControlHostDaemonVersionV1 = "dsvert-formal-glm-registered-phase20-job-control-host-daemon-v1"
	formalGLMRegisteredPhase20JobControlHostDaemonDomainV1  = "dsVert/formal-glm/registered-phase20/job-control-host-daemon/v1"
	formalGLMRegisteredPhase20JobControlHostDaemonMaxV1     = 2 << 20
	formalGLMRegisteredPhase20JobControlHostDaemonSocketV1  = ".j"
)

type formalGLMRegisteredPhase20JobControlHostDaemonRequestV1 struct {
	Version string          `json:"version"`
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonResponseV1 struct {
	Version string          `json:"version"`
	OK      bool            `json:"ok"`
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonResultV1 struct {
	State           string `json:"state"`
	Outbound        []byte `json:"outbound"`
	InspectOnly     bool   `json:"inspect_only"`
	ProductionReady bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonInboundV1 struct {
	Inbound []byte `json:"inbound"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonBindV1 struct {
	Frame []byte `json:"frame"`
}

// Preflight frames are signed public lifecycle records.  They are transported
// as opaque bytes so the local control surface never has to expose or accept
// a Phase21 filesystem record.
type formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1 struct {
	Frame []byte `json:"frame"`
}

// Stage traffic is the existing signed relay envelope around encrypted
// exact-GC ranges. Neither request form includes a storage path, a secret,
// or a local output share.
type formalGLMRegisteredPhase20JobControlHostDaemonStagePollV1 struct {
	Acknowledgement *formalGLMRegisteredPhase21StageRelayAckV1 `json:"acknowledgement,omitempty"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonStagePollResultV1 struct {
	Chunk *formalGLMRegisteredPhase21StageRelayChunkV1 `json:"chunk,omitempty"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonStageRelayV1 struct {
	Chunk formalGLMRegisteredPhase21StageRelayChunkV1 `json:"chunk"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonStageRecordV1 struct {
	Record formalGLMPhase21RockStageRecord `json:"record"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonTicketRecordV1 struct {
	Record formalGLMPhase21RockTicketRecord `json:"record"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonSealRecordV1 struct {
	Record formalGLMPhase21RockSealRecord `json:"record"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonCandidateRecordV1 struct {
	Record formalGLMPhase21RockCandidateRecord `json:"record"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonLocalReleaseRecordV1 struct {
	Record formalGLMPhase21RockLocalReleaseRecord `json:"record"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonBaseCertificateRecordV1 struct {
	Record formalGLMPhase21RockBaseCertificateRecord `json:"record"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonAuthorizationRecordV1 struct {
	Record formalGLMPhase21RockAuthorizationRecord `json:"record"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1 struct {
	Publication formalGLMPhase21PublicCertificateV2 `json:"publication"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonCommitRecordV1 struct {
	Record formalGLMPhase21RockCommitRecord `json:"record"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonAckRecordV1 struct {
	Record      formalGLMPhase21RockAckRecord       `json:"record"`
	Publication formalGLMPhase21PublicCertificateV2 `json:"publication"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonCleanupRecordV1 struct {
	Record      formalGLMPhase21RockCleanupRecord   `json:"record"`
	Publication formalGLMPhase21PublicCertificateV2 `json:"publication,omitempty"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonPollV1 struct {
	Ref          formalGLMRegisteredPhase20JobRefV1 `json:"ref"`
	Acknowledged int64                              `json:"acknowledged"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonRelayV1 struct {
	Ref   formalGLMRegisteredPhase20JobRefV1     `json:"ref"`
	Chunk formalGLMRegisteredPhase20RelayChunkV1 `json:"chunk"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonJobRefV1 struct {
	Ref   formalGLMRegisteredPhase20JobRefV1 `json:"ref"`
	Claim []byte                             `json:"claim"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonRelayResultV1 struct {
	Accepted int64 `json:"accepted"`
}

const (
	formalGLMRegisteredPhase20JobControlTaskRunningV1  = "running"
	formalGLMRegisteredPhase20JobControlTaskCompleteV1 = "complete"
	formalGLMRegisteredPhase20JobControlTaskFailedV1   = "failed"
)

// The status is deliberately opaque about failures.  Transport and durable
// stores hold the diagnostic state; the control channel exposes only whether
// a single locally owned operation is still running, completed or failed.
type formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1 struct {
	State           string                         `json:"state"`
	Commit          *formalGLMPhase20HandoffCommit `json:"commit,omitempty"`
	ProductionReady bool                           `json:"production_ready"`
}

type formalGLMRegisteredPhase20JobControlHostDaemonTaskV1 struct {
	running  bool
	complete bool
	failed   bool
	commit   formalGLMPhase20HandoffCommit
	done     chan struct{}
}

type formalGLMRegisteredPhase20JobControlHostDaemonV1 struct {
	mu          sync.Mutex
	host        *formalGLMRegisteredPhase20JobControlHostV1
	key         []byte
	socketRoot  *os.Root
	socketInfo  os.FileInfo
	socketDir   string
	socketPath  string
	listener    *net.UnixListener
	closed      bool
	connections sync.WaitGroup
	tasks       sync.WaitGroup
	compute     formalGLMRegisteredPhase20JobControlHostDaemonTaskV1
	terminal    formalGLMRegisteredPhase20JobControlHostDaemonTaskV1
	done        chan struct{}
}

type formalGLMRegisteredPhase20JobControlHostDaemonClientV1 struct {
	socketPath string
	key        []byte
}

func formalGLMRegisteredPhase20JobControlHostDaemonCanonicalV1(value any) ([]byte, error) {
	return json.Marshal(value)
}

func formalGLMRegisteredPhase20JobControlHostDaemonMACV1(
	key []byte, value any,
) (string, error) {
	if len(key) != sha256.Size {
		return "", fmt.Errorf("formal-glm registered Phase20 job daemon: invalid control key")
	}
	encoded, err := formalGLMRegisteredPhase20JobControlHostDaemonCanonicalV1(value)
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(formalGLMRegisteredPhase20JobControlHostDaemonDomainV1 + "|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalGLMRegisteredPhase20JobControlHostDaemonSignRequestV1(
	key []byte, request formalGLMRegisteredPhase20JobControlHostDaemonRequestV1,
) (formalGLMRegisteredPhase20JobControlHostDaemonRequestV1, error) {
	request.MAC = ""
	mac, err := formalGLMRegisteredPhase20JobControlHostDaemonMACV1(key, request)
	if err != nil {
		return formalGLMRegisteredPhase20JobControlHostDaemonRequestV1{}, err
	}
	request.MAC = mac
	return request, nil
}

func formalGLMRegisteredPhase20JobControlHostDaemonSignResponseV1(
	key []byte, response formalGLMRegisteredPhase20JobControlHostDaemonResponseV1,
) (formalGLMRegisteredPhase20JobControlHostDaemonResponseV1, error) {
	response.MAC = ""
	mac, err := formalGLMRegisteredPhase20JobControlHostDaemonMACV1(key, response)
	if err != nil {
		return formalGLMRegisteredPhase20JobControlHostDaemonResponseV1{}, err
	}
	response.MAC = mac
	return response, nil
}

func formalGLMRegisteredPhase20JobControlHostDaemonDecodeV1[T any](
	encoded []byte,
) (T, error) {
	var zero T
	if len(encoded) < 2 || len(encoded) > formalGLMRegisteredPhase20JobControlHostDaemonMaxV1 {
		return zero, fmt.Errorf("formal-glm registered Phase20 job daemon: invalid message")
	}
	if err := formalGLMPhase21RockStrictDecode(encoded, &zero); err != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job daemon: invalid message")
	}
	return zero, nil
}

// Unix-domain sockets are transient transport endpoints, not protocol state.
// They must stay short enough for sockaddr_un, so the daemon owns a private
// temporary directory and removes it with the listener. All durable state and
// every secret remain in the host's Rock stores.
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

func formalGLMRegisteredPhase20JobControlHostDaemonPrivateDirAtV1(
	directory string,
) (string, *os.Root, os.FileInfo, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		len(directory) >= 96 || os.Mkdir(directory, 0o700) != nil {
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.Remove(directory)
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || !formalFinalizerHandoffPrivateOwnedDirectory(info) {
		_ = os.Remove(directory)
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		_ = os.Remove(directory)
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket directory")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || !opened.IsDir() ||
		opened.Mode().Perm() != 0o700 || !formalFinalizerHandoffPrivateOwnedDirectory(opened) {
		_ = root.Close()
		_ = os.Remove(directory)
		return "", nil, nil, fmt.Errorf("formal-glm registered Phase20 job daemon: socket directory changed")
	}
	return directory, root, opened, nil
}

func formalGLMRegisteredPhase20JobControlHostDaemonSocketValidV1(
	daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1,
) error {
	if daemon == nil || daemon.socketRoot == nil || daemon.socketPath == "" {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: unavailable")
	}
	current, err := daemon.socketRoot.Stat(".")
	if err != nil || !os.SameFile(daemon.socketInfo, current) || !current.IsDir() ||
		current.Mode().Perm() != 0o700 || !formalFinalizerHandoffPrivateOwnedDirectory(current) {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: socket directory changed")
	}
	info, err := os.Lstat(daemon.socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket")
	}
	return nil
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

func newFormalGLMRegisteredPhase20JobControlHostDaemonAtDirV1(
	host *formalGLMRegisteredPhase20JobControlHostV1, controlKey []byte,
	socketDir string,
) (*formalGLMRegisteredPhase20JobControlHostDaemonV1, error) {
	if host == nil || len(controlKey) != sha256.Size {
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: invalid configuration")
	}
	directory, root, info, err := formalGLMRegisteredPhase20JobControlHostDaemonPrivateDirAtV1(socketDir)
	if err != nil {
		return nil, err
	}
	return newFormalGLMRegisteredPhase20JobControlHostDaemonAtOpenDirV1(
		host, controlKey, directory, root, info)
}

func newFormalGLMRegisteredPhase20JobControlHostDaemonAtOpenDirV1(
	host *formalGLMRegisteredPhase20JobControlHostV1, controlKey []byte,
	socketDir string, root *os.Root, info os.FileInfo,
) (*formalGLMRegisteredPhase20JobControlHostDaemonV1, error) {
	path := filepath.Join(socketDir, formalGLMRegisteredPhase20JobControlHostDaemonSocketV1)
	if len(path) >= 100 {
		_ = root.Close()
		_ = os.Remove(socketDir)
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: socket path too long")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		_ = root.Close()
		_ = os.Remove(socketDir)
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: socket already exists")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		_ = root.Close()
		_ = os.Remove(socketDir)
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: socket unavailable")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		_ = root.Close()
		_ = os.Remove(socketDir)
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket")
	}
	daemon := &formalGLMRegisteredPhase20JobControlHostDaemonV1{
		host: host, key: append([]byte(nil), controlKey...), socketRoot: root,
		socketInfo: info, socketDir: socketDir, socketPath: path,
		listener: listener, done: make(chan struct{}),
	}
	if err := formalGLMRegisteredPhase20JobControlHostDaemonSocketValidV1(daemon); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		_ = root.Close()
		_ = os.Remove(socketDir)
		clear(daemon.key)
		return nil, err
	}
	go daemon.serveV1()
	return daemon, nil
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) SocketPathV1() string {
	if daemon == nil {
		return ""
	}
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	if daemon.closed {
		return ""
	}
	return daemon.socketPath
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) serveV1() {
	defer close(daemon.done)
	for {
		daemon.mu.Lock()
		listener, closed := daemon.listener, daemon.closed
		daemon.mu.Unlock()
		if closed || listener == nil {
			return
		}
		connection, err := listener.AcceptUnix()
		if err != nil {
			daemon.mu.Lock()
			closed = daemon.closed
			daemon.mu.Unlock()
			if closed {
				return
			}
			continue
		}
		daemon.mu.Lock()
		if daemon.closed {
			daemon.mu.Unlock()
			_ = connection.Close()
			return
		}
		daemon.connections.Add(1)
		daemon.mu.Unlock()
		go func() {
			defer daemon.connections.Done()
			defer connection.Close()
			daemon.handleV1(connection)
		}()
	}
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) handleV1(
	connection *net.UnixConn,
) {
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	encoded, err := io.ReadAll(io.LimitReader(connection,
		formalGLMRegisteredPhase20JobControlHostDaemonMaxV1+1))
	if err != nil || len(encoded) > formalGLMRegisteredPhase20JobControlHostDaemonMaxV1 {
		clear(encoded)
		return
	}
	defer clear(encoded)
	request, err := formalGLMRegisteredPhase20JobControlHostDaemonDecodeV1[formalGLMRegisteredPhase20JobControlHostDaemonRequestV1](encoded)
	if err != nil || request.Version != formalGLMRegisteredPhase20JobControlHostDaemonVersionV1 ||
		request.MAC == "" {
		return
	}
	claimedMAC := request.MAC
	request.MAC = ""
	daemon.mu.Lock()
	key := append([]byte(nil), daemon.key...)
	closed := daemon.closed
	daemon.mu.Unlock()
	defer clear(key)
	wantMAC, err := formalGLMRegisteredPhase20JobControlHostDaemonMACV1(key, request)
	if closed || err != nil || !hmac.Equal([]byte(claimedMAC), []byte(wantMAC)) {
		return
	}
	payload, operationErr := daemon.dispatchV1(request.Action, request.Payload)
	if operationErr != nil {
		payload = json.RawMessage(`{}`)
	}
	response, err := formalGLMRegisteredPhase20JobControlHostDaemonSignResponseV1(key,
		formalGLMRegisteredPhase20JobControlHostDaemonResponseV1{
			Version: formalGLMRegisteredPhase20JobControlHostDaemonVersionV1,
			OK:      operationErr == nil, Payload: payload,
		})
	if err != nil {
		return
	}
	responseEncoded, err := formalGLMRegisteredPhase20JobControlHostDaemonCanonicalV1(response)
	if err != nil || len(responseEncoded) > formalGLMRegisteredPhase20JobControlHostDaemonMaxV1 {
		clear(responseEncoded)
		return
	}
	defer clear(responseEncoded)
	_, _ = connection.Write(responseEncoded)
}

func formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[T any](
	encoded json.RawMessage,
) (T, error) {
	return formalGLMRegisteredPhase20JobControlHostDaemonDecodeV1[T](encoded)
}

func formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
	value any,
) (json.RawMessage, error) {
	encoded, err := formalGLMRegisteredPhase20JobControlHostDaemonCanonicalV1(value)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

func formalGLMRegisteredPhase20JobControlHostDaemonResultFromOwnerV1(
	result formalGLMRegisteredPhase20JobOwnerResultV1,
) formalGLMRegisteredPhase20JobControlHostDaemonResultV1 {
	return formalGLMRegisteredPhase20JobControlHostDaemonResultV1{
		State: result.state, Outbound: append([]byte(nil), result.outbound...),
		InspectOnly: result.inspectOnly, ProductionReady: result.productionReady,
	}
}

func formalGLMRegisteredPhase20JobControlHostDaemonTaskSnapshotV1(
	task formalGLMRegisteredPhase20JobControlHostDaemonTaskV1,
) (formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error) {
	if task.running {
		return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{
			State: formalGLMRegisteredPhase20JobControlTaskRunningV1,
		}, nil
	}
	if task.complete {
		status := formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{
			State: formalGLMRegisteredPhase20JobControlTaskCompleteV1,
		}
		if task.commit.SHA256 != "" {
			commit := task.commit
			status.Commit = &commit
		}
		return status, nil
	}
	if task.failed {
		return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{
			State: formalGLMRegisteredPhase20JobControlTaskFailedV1,
		}, nil
	}
	return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{},
		fmt.Errorf("formal-glm registered Phase20 job daemon: task not started")
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) startComputeV1() (
	formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error,
) {
	daemon.mu.Lock()
	if daemon.closed || daemon.host == nil || daemon.terminal.running ||
		daemon.terminal.complete || daemon.terminal.failed {
		daemon.mu.Unlock()
		return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{},
			fmt.Errorf("formal-glm registered Phase20 job daemon: compute unavailable")
	}
	if daemon.compute.running || daemon.compute.complete || daemon.compute.failed {
		status, err := formalGLMRegisteredPhase20JobControlHostDaemonTaskSnapshotV1(daemon.compute)
		daemon.mu.Unlock()
		return status, err
	}
	host := daemon.host
	daemon.compute.running = true
	daemon.compute.done = make(chan struct{})
	daemon.tasks.Add(1)
	daemon.mu.Unlock()
	go func() {
		err := host.RunComputeV1()
		daemon.mu.Lock()
		daemon.compute.running = false
		daemon.compute.complete = err == nil
		daemon.compute.failed = err != nil
		close(daemon.compute.done)
		daemon.mu.Unlock()
		daemon.tasks.Done()
	}()
	return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{
		State: formalGLMRegisteredPhase20JobControlTaskRunningV1,
	}, nil
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) computeStatusV1() (
	formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error,
) {
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	if daemon.closed {
		return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{},
			fmt.Errorf("formal-glm registered Phase20 job daemon: closed")
	}
	return formalGLMRegisteredPhase20JobControlHostDaemonTaskSnapshotV1(daemon.compute)
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) startTerminalV1() (
	formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error,
) {
	daemon.mu.Lock()
	if daemon.closed || daemon.host == nil || !daemon.compute.complete || daemon.compute.failed {
		daemon.mu.Unlock()
		return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{},
			fmt.Errorf("formal-glm registered Phase20 job daemon: terminal unavailable")
	}
	if daemon.terminal.running || daemon.terminal.complete || daemon.terminal.failed {
		status, err := formalGLMRegisteredPhase20JobControlHostDaemonTaskSnapshotV1(daemon.terminal)
		daemon.mu.Unlock()
		return status, err
	}
	host := daemon.host
	daemon.terminal.running = true
	daemon.terminal.done = make(chan struct{})
	daemon.tasks.Add(1)
	daemon.mu.Unlock()
	go func() {
		commit, err := host.RunTerminalV1()
		daemon.mu.Lock()
		daemon.terminal.running = false
		daemon.terminal.complete = err == nil
		daemon.terminal.failed = err != nil
		if err == nil {
			daemon.terminal.commit = commit
		}
		close(daemon.terminal.done)
		daemon.mu.Unlock()
		daemon.tasks.Done()
	}()
	return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{
		State: formalGLMRegisteredPhase20JobControlTaskRunningV1,
	}, nil
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) terminalStatusV1() (
	formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error,
) {
	daemon.mu.Lock()
	defer daemon.mu.Unlock()
	if daemon.closed {
		return formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1{},
			fmt.Errorf("formal-glm registered Phase20 job daemon: closed")
	}
	return formalGLMRegisteredPhase20JobControlHostDaemonTaskSnapshotV1(daemon.terminal)
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) waitComputeV1() error {
	if _, err := daemon.startComputeV1(); err != nil {
		return err
	}
	daemon.mu.Lock()
	done := daemon.compute.done
	daemon.mu.Unlock()
	<-done
	status, err := daemon.computeStatusV1()
	if err != nil || status.State != formalGLMRegisteredPhase20JobControlTaskCompleteV1 {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: compute failed")
	}
	return nil
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) waitTerminalV1() (
	formalGLMPhase20HandoffCommit, error,
) {
	var zero formalGLMPhase20HandoffCommit
	if _, err := daemon.startTerminalV1(); err != nil {
		return zero, err
	}
	daemon.mu.Lock()
	done := daemon.terminal.done
	daemon.mu.Unlock()
	<-done
	status, err := daemon.terminalStatusV1()
	if err != nil || status.State != formalGLMRegisteredPhase20JobControlTaskCompleteV1 || status.Commit == nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job daemon: terminal failed")
	}
	return *status.Commit, nil
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) dispatchV1(
	action string, encoded json.RawMessage,
) (json.RawMessage, error) {
	daemon.mu.Lock()
	host, closed := daemon.host, daemon.closed
	daemon.mu.Unlock()
	if closed || host == nil {
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: closed")
	}
	switch action {
	case "negotiate":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonInboundV1](encoded)
		if err != nil {
			return nil, err
		}
		result, err := host.NegotiateV1(request.Inbound)
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonResultFromOwnerV1(result))
	case "start":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		result, err := host.StartOrInspectV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonResultFromOwnerV1(result))
	case "health":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		if err := host.HealthV1(); err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "job_ref":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		ref, claim, err := host.JobRefV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonJobRefV1{Ref: ref, Claim: claim})
	case "bind":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonBindV1](encoded)
		if err != nil || host.BindPeerJobRefV1(request.Frame) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: bind failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_preflight":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		record, err := host.RunPhase21PreflightV1()
		if err != nil {
			return nil, err
		}
		frame, err := formalGLMRegisteredPhase20JobControlHostDaemonCanonicalV1(record)
		if err != nil {
			return nil, err
		}
		defer clear(frame)
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1{Frame: frame})
	case "phase21_preflight_bind":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonPreflightV1](encoded)
		if err != nil {
			return nil, err
		}
		var record formalGLMPhase21RockPreflightRecord
		if err := formalGLMPhase21RockStrictDecode(request.Frame, &record); err != nil ||
			host.ImportPhase21PeerPreflightV1(record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 preflight bind failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_stage_start":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		status, err := host.StartPhase21StageV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(status)
	case "phase21_stage_status":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		status, err := host.Phase21StageStatusV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(status)
	case "phase21_stage_record":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		status, err := host.Phase21StageStatusV1()
		if err != nil || status.State != formalGLMRegisteredPhase21StageCompleteV1 || status.Stage == nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 Stage unavailable")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonStageRecordV1{Record: *status.Stage})
	case "phase21_stage_poll":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonStagePollV1](encoded)
		if err != nil {
			return nil, err
		}
		chunk, err := host.PollPhase21StageV1(request.Acknowledgement)
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonStagePollResultV1{Chunk: chunk})
	case "phase21_stage_relay":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonStageRelayV1](encoded)
		if err != nil {
			return nil, err
		}
		acknowledgement, err := host.RelayPhase21StageV1(request.Chunk)
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(acknowledgement)
	case "phase21_stage_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonStageRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerStageV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 Stage import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_ticket":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		record, err := host.RunPhase21TicketV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonTicketRecordV1{Record: record})
	case "phase21_ticket_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonTicketRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerTicketV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 Ticket import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_seal":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		record, err := host.RunPhase21SealV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonSealRecordV1{Record: record})
	case "phase21_seal_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonSealRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerSealV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 Seal import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_candidate":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		record, err := host.RunPhase21CandidateV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonCandidateRecordV1{Record: record})
	case "phase21_candidate_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonCandidateRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerCandidateV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 candidate import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_candidate_verify":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		record, err := host.VerifyPhase21CandidateV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonLocalReleaseRecordV1{Record: record})
	case "phase21_local_release_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonLocalReleaseRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerLocalReleaseV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 local release import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_base_certificate":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		record, err := host.RunPhase21BaseCertificateV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonBaseCertificateRecordV1{Record: record})
	case "phase21_base_certificate_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonBaseCertificateRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerBaseCertificateV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 base certificate import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_authorization":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		record, err := host.RunPhase21AuthorizationV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonAuthorizationRecordV1{Record: record})
	case "phase21_authorization_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonAuthorizationRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerAuthorizationV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 authorization import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_publication":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		publication, err := host.RunPhase21PublicationV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1{Publication: publication})
	case "phase21_commit":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1](encoded)
		if err != nil {
			return nil, err
		}
		record, err := host.RunPhase21CommitV1(request.Publication)
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonCommitRecordV1{Record: record})
	case "phase21_commit_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonCommitRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerCommitV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 commit import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_ack":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		record, err := host.RunPhase21AckV1()
		if err != nil {
			return nil, err
		}
		publication, err := host.RunPhase21PublicationV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonAckRecordV1{
				Record: record, Publication: publication,
			})
	case "phase21_ack_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonAckRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerAckV1(request.Record, request.Publication) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 ACK import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "phase21_cleanup":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1](encoded)
		if err != nil {
			return nil, err
		}
		record, err := host.RunPhase21CleanupV1(request.Publication)
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonCleanupRecordV1{Record: record})
	case "phase21_cleanup_import":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonCleanupRecordV1](encoded)
		if err != nil || host.ImportPhase21PeerCleanupV1(request.Record) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: Phase21 cleanup import failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "heartbeat":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil || host.HeartbeatV1() != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: heartbeat failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "poll":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonPollV1](encoded)
		if err != nil {
			return nil, err
		}
		result, err := host.PollV1(request.Ref, request.Acknowledged)
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(result)
	case "relay":
		request, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonRelayV1](encoded)
		if err != nil {
			return nil, err
		}
		accepted, err := host.RelayV1(request.Ref, request.Chunk)
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(
			formalGLMRegisteredPhase20JobControlHostDaemonRelayResultV1{Accepted: accepted})
	case "compute":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil || daemon.waitComputeV1() != nil {
			return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: compute failed")
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(struct{}{})
	case "terminal":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		commit, err := daemon.waitTerminalV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(commit)
	case "compute_start":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		status, err := daemon.startComputeV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(status)
	case "compute_status":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		status, err := daemon.computeStatusV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(status)
	case "terminal_start":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		status, err := daemon.startTerminalV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(status)
	case "terminal_status":
		if _, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](encoded); err != nil {
			return nil, err
		}
		status, err := daemon.terminalStatusV1()
		if err != nil {
			return nil, err
		}
		return formalGLMRegisteredPhase20JobControlHostDaemonResponsePayloadV1(status)
	default:
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: unsupported action")
	}
}

func newFormalGLMRegisteredPhase20JobControlHostDaemonClientV1(
	socketPath string, controlKey []byte,
) (*formalGLMRegisteredPhase20JobControlHostDaemonClientV1, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		len(controlKey) != sha256.Size {
		return nil, fmt.Errorf("formal-glm registered Phase20 job daemon: invalid client")
	}
	return &formalGLMRegisteredPhase20JobControlHostDaemonClientV1{
		socketPath: socketPath, key: append([]byte(nil), controlKey...),
	}, nil
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) Close() {
	if client == nil {
		return
	}
	clear(client.key)
	client.key = nil
	client.socketPath = ""
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) callV1(
	action string, payload any, response any,
) error {
	if client == nil || len(client.key) != sha256.Size || client.socketPath == "" {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: client closed")
	}
	payloadEncoded, err := formalGLMRegisteredPhase20JobControlHostDaemonCanonicalV1(payload)
	if err != nil {
		return err
	}
	defer clear(payloadEncoded)
	request, err := formalGLMRegisteredPhase20JobControlHostDaemonSignRequestV1(client.key,
		formalGLMRegisteredPhase20JobControlHostDaemonRequestV1{
			Version: formalGLMRegisteredPhase20JobControlHostDaemonVersionV1,
			Action:  action, Payload: json.RawMessage(payloadEncoded),
		})
	if err != nil {
		return err
	}
	encoded, err := formalGLMRegisteredPhase20JobControlHostDaemonCanonicalV1(request)
	if err != nil {
		return err
	}
	defer clear(encoded)
	connection, err := net.DialTimeout("unix", client.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: unavailable")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := connection.Write(encoded); err != nil {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: unavailable")
	}
	if unix, ok := connection.(*net.UnixConn); ok {
		_ = unix.CloseWrite()
	}
	responseEncoded, err := io.ReadAll(io.LimitReader(connection,
		formalGLMRegisteredPhase20JobControlHostDaemonMaxV1+1))
	if err != nil || len(responseEncoded) > formalGLMRegisteredPhase20JobControlHostDaemonMaxV1 {
		clear(responseEncoded)
		return fmt.Errorf("formal-glm registered Phase20 job daemon: unavailable")
	}
	defer clear(responseEncoded)
	decoded, err := formalGLMRegisteredPhase20JobControlHostDaemonDecodeV1[formalGLMRegisteredPhase20JobControlHostDaemonResponseV1](responseEncoded)
	if err != nil || decoded.Version != formalGLMRegisteredPhase20JobControlHostDaemonVersionV1 || decoded.MAC == "" {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: invalid response")
	}
	claimedMAC := decoded.MAC
	decoded.MAC = ""
	wantMAC, err := formalGLMRegisteredPhase20JobControlHostDaemonMACV1(client.key, decoded)
	if err != nil || !hmac.Equal([]byte(claimedMAC), []byte(wantMAC)) || !decoded.OK {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: rejected")
	}
	if response == nil {
		return nil
	}
	if err := formalGLMPhase21RockStrictDecode(decoded.Payload, response); err != nil {
		return fmt.Errorf("formal-glm registered Phase20 job daemon: invalid response")
	}
	return nil
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) NegotiateV1(
	inbound []byte,
) (formalGLMRegisteredPhase20JobControlHostDaemonResultV1, error) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonResultV1
	err := client.callV1("negotiate",
		formalGLMRegisteredPhase20JobControlHostDaemonInboundV1{Inbound: inbound}, &result)
	return result, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) StartOrInspectV1() (formalGLMRegisteredPhase20JobControlHostDaemonResultV1, error) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonResultV1
	err := client.callV1("start", struct{}{}, &result)
	return result, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) HealthV1() error {
	return client.callV1("health", struct{}{}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) JobRefV1() (formalGLMRegisteredPhase20JobControlHostDaemonJobRefV1, error) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonJobRefV1
	err := client.callV1("job_ref", struct{}{}, &result)
	return result, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) BindPeerJobRefV1(
	frame []byte,
) error {
	return client.callV1("bind",
		formalGLMRegisteredPhase20JobControlHostDaemonBindV1{Frame: frame}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) HeartbeatV1() error {
	return client.callV1("heartbeat", struct{}{}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) StartPhase21StageV1() (
	formalGLMRegisteredPhase21StageStatusV1, error,
) {
	var status formalGLMRegisteredPhase21StageStatusV1
	err := client.callV1("phase21_stage_start", struct{}{}, &status)
	return status, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) Phase21StageStatusV1() (
	formalGLMRegisteredPhase21StageStatusV1, error,
) {
	var status formalGLMRegisteredPhase21StageStatusV1
	err := client.callV1("phase21_stage_status", struct{}{}, &status)
	return status, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) Phase21StageRecordV1() (
	formalGLMPhase21RockStageRecord, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonStageRecordV1
	err := client.callV1("phase21_stage_record", struct{}{}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) PollPhase21StageV1(
	acknowledgement *formalGLMRegisteredPhase21StageRelayAckV1,
) (*formalGLMRegisteredPhase21StageRelayChunkV1, error) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonStagePollResultV1
	err := client.callV1("phase21_stage_poll",
		formalGLMRegisteredPhase20JobControlHostDaemonStagePollV1{Acknowledgement: acknowledgement}, &result)
	return result.Chunk, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RelayPhase21StageV1(
	chunk formalGLMRegisteredPhase21StageRelayChunkV1,
) (formalGLMRegisteredPhase21StageRelayAckV1, error) {
	var acknowledgement formalGLMRegisteredPhase21StageRelayAckV1
	err := client.callV1("phase21_stage_relay",
		formalGLMRegisteredPhase20JobControlHostDaemonStageRelayV1{Chunk: chunk}, &acknowledgement)
	return acknowledgement, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerStageV1(
	record formalGLMPhase21RockStageRecord,
) error {
	return client.callV1("phase21_stage_import",
		formalGLMRegisteredPhase20JobControlHostDaemonStageRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21TicketV1() (
	formalGLMPhase21RockTicketRecord, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonTicketRecordV1
	err := client.callV1("phase21_ticket", struct{}{}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerTicketV1(
	record formalGLMPhase21RockTicketRecord,
) error {
	return client.callV1("phase21_ticket_import",
		formalGLMRegisteredPhase20JobControlHostDaemonTicketRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21SealV1() (
	formalGLMPhase21RockSealRecord, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonSealRecordV1
	err := client.callV1("phase21_seal", struct{}{}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerSealV1(
	record formalGLMPhase21RockSealRecord,
) error {
	return client.callV1("phase21_seal_import",
		formalGLMRegisteredPhase20JobControlHostDaemonSealRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21CandidateV1() (
	formalGLMPhase21RockCandidateRecord, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonCandidateRecordV1
	err := client.callV1("phase21_candidate", struct{}{}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerCandidateV1(
	record formalGLMPhase21RockCandidateRecord,
) error {
	return client.callV1("phase21_candidate_import",
		formalGLMRegisteredPhase20JobControlHostDaemonCandidateRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) VerifyPhase21CandidateV1() (
	formalGLMPhase21RockLocalReleaseRecord, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonLocalReleaseRecordV1
	err := client.callV1("phase21_candidate_verify", struct{}{}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerLocalReleaseV1(
	record formalGLMPhase21RockLocalReleaseRecord,
) error {
	return client.callV1("phase21_local_release_import",
		formalGLMRegisteredPhase20JobControlHostDaemonLocalReleaseRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21BaseCertificateV1() (
	formalGLMPhase21RockBaseCertificateRecord, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonBaseCertificateRecordV1
	err := client.callV1("phase21_base_certificate", struct{}{}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerBaseCertificateV1(
	record formalGLMPhase21RockBaseCertificateRecord,
) error {
	return client.callV1("phase21_base_certificate_import",
		formalGLMRegisteredPhase20JobControlHostDaemonBaseCertificateRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21AuthorizationV1() (
	formalGLMPhase21RockAuthorizationRecord, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonAuthorizationRecordV1
	err := client.callV1("phase21_authorization", struct{}{}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerAuthorizationV1(
	record formalGLMPhase21RockAuthorizationRecord,
) error {
	return client.callV1("phase21_authorization_import",
		formalGLMRegisteredPhase20JobControlHostDaemonAuthorizationRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21PublicationV1() (
	formalGLMPhase21PublicCertificateV2, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1
	err := client.callV1("phase21_publication", struct{}{}, &result)
	return result.Publication, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21CommitV1(
	publication formalGLMPhase21PublicCertificateV2,
) (formalGLMPhase21RockCommitRecord, error) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonCommitRecordV1
	err := client.callV1("phase21_commit",
		formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1{Publication: publication}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerCommitV1(
	record formalGLMPhase21RockCommitRecord,
) error {
	return client.callV1("phase21_commit_import",
		formalGLMRegisteredPhase20JobControlHostDaemonCommitRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21AckV1() (
	formalGLMPhase21RockAckRecord, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonAckRecordV1
	err := client.callV1("phase21_ack", struct{}{}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerAckV1(
	record formalGLMPhase21RockAckRecord,
	publication formalGLMPhase21PublicCertificateV2,
) error {
	return client.callV1("phase21_ack_import",
		formalGLMRegisteredPhase20JobControlHostDaemonAckRecordV1{
			Record: record, Publication: publication,
		}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunPhase21CleanupV1(
	publication formalGLMPhase21PublicCertificateV2,
) (formalGLMPhase21RockCleanupRecord, error) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonCleanupRecordV1
	err := client.callV1("phase21_cleanup",
		formalGLMRegisteredPhase20JobControlHostDaemonPublicationV1{Publication: publication}, &result)
	return result.Record, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ImportPhase21PeerCleanupV1(
	record formalGLMPhase21RockCleanupRecord,
) error {
	return client.callV1("phase21_cleanup_import",
		formalGLMRegisteredPhase20JobControlHostDaemonCleanupRecordV1{Record: record}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) PollV1(
	ref formalGLMRegisteredPhase20JobRefV1, acknowledged int64,
) (formalGLMRegisteredPhase20JobPollResultV1, error) {
	var result formalGLMRegisteredPhase20JobPollResultV1
	err := client.callV1("poll",
		formalGLMRegisteredPhase20JobControlHostDaemonPollV1{
			Ref: ref, Acknowledged: acknowledged,
		}, &result)
	return result, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RelayV1(
	ref formalGLMRegisteredPhase20JobRefV1,
	chunk formalGLMRegisteredPhase20RelayChunkV1,
) (int64, error) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonRelayResultV1
	err := client.callV1("relay",
		formalGLMRegisteredPhase20JobControlHostDaemonRelayV1{Ref: ref, Chunk: chunk},
		&result)
	return result.Accepted, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunComputeV1() error {
	return client.callV1("compute", struct{}{}, nil)
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) StartComputeV1() (
	formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1
	err := client.callV1("compute_start", struct{}{}, &result)
	return result, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) ComputeStatusV1() (
	formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1
	err := client.callV1("compute_status", struct{}{}, &result)
	return result, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) RunTerminalV1() (formalGLMPhase20HandoffCommit, error) {
	var result formalGLMPhase20HandoffCommit
	err := client.callV1("terminal", struct{}{}, &result)
	return result, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) StartTerminalV1() (
	formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1
	err := client.callV1("terminal_start", struct{}{}, &result)
	return result, err
}

func (client *formalGLMRegisteredPhase20JobControlHostDaemonClientV1) TerminalStatusV1() (
	formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1, error,
) {
	var result formalGLMRegisteredPhase20JobControlHostDaemonTaskStatusV1
	err := client.callV1("terminal_status", struct{}{}, &result)
	return result, err
}

func (daemon *formalGLMRegisteredPhase20JobControlHostDaemonV1) Close() error {
	if daemon == nil {
		return nil
	}
	daemon.mu.Lock()
	if daemon.closed {
		done := daemon.done
		daemon.mu.Unlock()
		if done != nil {
			<-done
		}
		return nil
	}
	daemon.closed = true
	listener, host := daemon.listener, daemon.host
	daemon.listener, daemon.host = nil, nil
	socketPath, socketDir, root := daemon.socketPath, daemon.socketDir, daemon.socketRoot
	daemon.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	<-daemon.done
	daemon.connections.Wait()
	daemon.tasks.Wait()
	var result error
	if socketPath != "" {
		if info, err := os.Lstat(socketPath); err == nil {
			if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
				result = fmt.Errorf("formal-glm registered Phase20 job daemon: unsafe socket on close")
			} else if err := os.Remove(socketPath); err != nil {
				result = err
			}
		} else if !os.IsNotExist(err) {
			result = err
		}
	}
	if root != nil {
		if err := root.Close(); result == nil && err != nil {
			result = err
		}
	}
	if socketDir != "" {
		if err := os.Remove(socketDir); result == nil && err != nil && !os.IsNotExist(err) {
			result = err
		}
	}
	if host != nil {
		if err := host.Close(); result == nil && err != nil {
			result = err
		}
	}
	daemon.mu.Lock()
	clear(daemon.key)
	daemon.key = nil
	daemon.socketPath, daemon.socketDir = "", ""
	daemon.socketRoot = nil
	daemon.mu.Unlock()
	return result
}
