package main

// A short-lived local command cannot own an exact-GC Cox worker: the worker
// needs a live duplex spool while two servers relay opaque frames.  This
// private Unix-socket boundary lets later server-local command handlers speak
// to the one live controller without reopening its lease, source store, or
// spool. The socket is a sibling of the long durable attempt slot: Unix path
// limits must not make a valid Rock root unusable. It has no CLI registration
// or public DTO.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	formalCoxBlockwiseExchangeDaemonVersion = "dsvert-formal-cox-blockwise-exchange-daemon-v1"
	formalCoxBlockwiseExchangeDaemonDomain  = "dsVert/formal-cox/blockwise-exchange-daemon/v1"
	formalCoxBlockwiseExchangeDaemonMax     = 2 << 20
)

type formalCoxBlockwiseExchangeDaemonRequestV1 struct {
	Version string          `json:"version"`
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

type formalCoxBlockwiseExchangeDaemonResponseV1 struct {
	Version string          `json:"version"`
	OK      bool            `json:"ok"`
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

type formalCoxBlockwiseExchangeDaemonBindV1 struct {
	Peer string `json:"peer"`
}

type formalCoxBlockwiseExchangeDaemonRootV1 struct {
	Step    formalCoxBlockwiseWorkerStep `json:"step"`
	Attempt string                       `json:"attempt"`
}

type formalCoxBlockwiseExchangeDaemonStartV1 struct {
	Step      formalCoxBlockwiseWorkerStep        `json:"step"`
	Attempt   string                              `json:"attempt"`
	PeerClaim formalCoxBlockwiseExchangeRootClaim `json:"peer_claim"`
}

// formalCoxBlockwiseExchangeDaemonFrameV1 deliberately makes a signed root
// claim opaque to short-lived command callers.  The live owner, rather than
// R or a DataSHIELD caller, derives the step and attempt it contains.
type formalCoxBlockwiseExchangeDaemonFrameV1 struct {
	Frame string `json:"frame"`
}

type formalCoxBlockwiseExchangeDaemonPollV1 struct {
	Acknowledged int64 `json:"acknowledged"`
}

type formalCoxBlockwiseExchangeDaemonRelayV1 struct {
	Chunk formalCoxBlockwiseExchangeChunk `json:"chunk"`
}

type formalCoxBlockwiseExchangeDaemonCommitV1 struct {
	Receipts []formalCoxBlockwiseStepReceipt `json:"receipts"`
	Pins     map[string][]byte               `json:"pins"`
}

type formalCoxBlockwiseExchangeDaemonPollResultV1 struct {
	Chunk    *formalCoxBlockwiseExchangeChunk `json:"chunk"`
	Accepted int64                            `json:"accepted"`
}

type formalCoxBlockwiseExchangeDaemonRelayResultV1 struct {
	Accepted int64 `json:"accepted"`
}

type formalCoxBlockwiseExchangeDaemonResultV1 struct {
	Receipt formalCoxBlockwiseStepReceipt `json:"receipt"`
	Done    bool                          `json:"done"`
}

type formalCoxBlockwiseExchangeDaemonV1 struct {
	mu          sync.Mutex
	controller  *formalCoxBlockwiseExchangeController
	key         []byte
	socketRoot  *os.Root
	socketDir   string
	socketPath  string
	listener    *net.UnixListener
	closed      bool
	connections sync.WaitGroup
	done        chan struct{}
}

type formalCoxBlockwiseExchangeDaemonClientV1 struct {
	socketPath string
	key        []byte
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) Close() {
	if client == nil {
		return
	}
	clear(client.key)
	client.key = nil
	client.socketPath = ""
}

func formalCoxBlockwiseExchangeDaemonCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func formalCoxBlockwiseExchangeDaemonMAC(key []byte, value any) (string, error) {
	if len(key) != sha256.Size {
		return "", fmt.Errorf("formal-cox: invalid exchange daemon control key")
	}
	encoded, err := formalCoxBlockwiseExchangeDaemonCanonical(value)
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(formalCoxBlockwiseExchangeDaemonDomain + "|"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func formalCoxBlockwiseExchangeDaemonSignRequest(key []byte,
	request formalCoxBlockwiseExchangeDaemonRequestV1,
) (formalCoxBlockwiseExchangeDaemonRequestV1, error) {
	request.MAC = ""
	mac, err := formalCoxBlockwiseExchangeDaemonMAC(key, request)
	if err != nil {
		return formalCoxBlockwiseExchangeDaemonRequestV1{}, err
	}
	request.MAC = mac
	return request, nil
}

func formalCoxBlockwiseExchangeDaemonSignResponse(key []byte,
	response formalCoxBlockwiseExchangeDaemonResponseV1,
) (formalCoxBlockwiseExchangeDaemonResponseV1, error) {
	response.MAC = ""
	mac, err := formalCoxBlockwiseExchangeDaemonMAC(key, response)
	if err != nil {
		return formalCoxBlockwiseExchangeDaemonResponseV1{}, err
	}
	response.MAC = mac
	return response, nil
}

func formalCoxBlockwiseExchangeDaemonDecodeCanonical(encoded []byte, maximum int,
	value any,
) error {
	if len(encoded) < 2 || len(encoded) > maximum || encoded[0] != '{' {
		return fmt.Errorf("formal-cox: invalid exchange daemon message")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("formal-cox: invalid exchange daemon message")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return fmt.Errorf("formal-cox: invalid exchange daemon message")
	}
	canonical, err := formalCoxBlockwiseExchangeDaemonCanonical(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return fmt.Errorf("formal-cox: non-canonical exchange daemon message")
	}
	clear(canonical)
	return nil
}

func formalCoxBlockwiseExchangeDaemonDecodeHash(value string) ([32]byte, error) {
	var result [32]byte
	if len(value) != sha256.Size*2 || !formalCoxIsSHA256(value) {
		return result, fmt.Errorf("formal-cox: invalid exchange daemon hash")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		clear(decoded)
		return result, fmt.Errorf("formal-cox: invalid exchange daemon hash")
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, nil
}

func formalCoxBlockwiseExchangeDaemonSocketValid(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("formal-cox: invalid exchange daemon socket path")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 {
		return fmt.Errorf("formal-cox: exchange daemon socket is unsafe")
	}
	return nil
}

// formalCoxBlockwiseExchangeDaemonSocketLocation selects the nearest private
// ancestor that fits a Unix-domain socket name. Attempt identifiers remain in
// the durable spool tree; only the local control socket moves upward when a
// long Rock root would exceed the platform address bound.
func formalCoxBlockwiseExchangeDaemonSocketLocation(
	transportRoot string,
) (*os.Root, string, string, error) {
	if !filepath.IsAbs(transportRoot) || filepath.Clean(transportRoot) != transportRoot {
		return nil, "", "", fmt.Errorf("formal-cox: exchange daemon socket root is unsafe")
	}
	socketHash := sha256.Sum256([]byte(
		formalCoxBlockwiseExchangeDaemonDomain + "|" + transportRoot))
	name := "worker-" + hex.EncodeToString(socketHash[:8]) + ".sock"
	for directory := filepath.Dir(transportRoot); ; directory = filepath.Dir(directory) {
		root, err := os.OpenRoot(directory)
		if err != nil || formalCoxBlockwiseExchangeLeaseValidateDir(root, directory) != nil {
			if root != nil {
				_ = root.Close()
			}
			return nil, "", "", fmt.Errorf("formal-cox: exchange daemon socket root is unsafe")
		}
		path := filepath.Join(directory, name)
		if len(path) < 100 {
			return root, directory, path, nil
		}
		_ = root.Close()
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil, "", "", fmt.Errorf("formal-cox: exchange daemon socket path is too long")
		}
	}
}

func newFormalCoxBlockwiseExchangeDaemonV1(
	controller *formalCoxBlockwiseExchangeController, controlKey []byte,
) (*formalCoxBlockwiseExchangeDaemonV1, error) {
	if controller == nil || len(controlKey) != sha256.Size {
		return nil, fmt.Errorf("formal-cox: invalid exchange daemon configuration")
	}
	controller.mu.Lock()
	transport := controller.transport
	valid := !controller.closed && !controller.started && transport != nil &&
		transport.root != nil && !transport.closed &&
		formalCoxBlockwiseExchangeLeaseValidateDir(transport.root, transport.rootPath) == nil
	controller.mu.Unlock()
	if !valid {
		return nil, fmt.Errorf("formal-cox: exchange daemon controller is unavailable")
	}
	socketRoot, socketDir, path, err := formalCoxBlockwiseExchangeDaemonSocketLocation(
		transport.rootPath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		_ = socketRoot.Close()
		return nil, fmt.Errorf("formal-cox: exchange daemon socket already exists")
	}
	address := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		_ = socketRoot.Close()
		return nil, fmt.Errorf("formal-cox: exchange daemon socket unavailable")
	}
	if err := os.Chmod(path, 0o600); err != nil ||
		formalCoxBlockwiseExchangeLeaseValidateDir(socketRoot, socketDir) != nil ||
		formalCoxBlockwiseExchangeDaemonSocketValid(path) != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		_ = socketRoot.Close()
		return nil, fmt.Errorf("formal-cox: exchange daemon socket is unsafe")
	}
	daemon := &formalCoxBlockwiseExchangeDaemonV1{
		controller: controller, key: append([]byte(nil), controlKey...),
		socketRoot: socketRoot, socketDir: socketDir,
		socketPath: path, listener: listener, done: make(chan struct{}),
	}
	go daemon.serveV1()
	return daemon, nil
}

func (daemon *formalCoxBlockwiseExchangeDaemonV1) SocketPathV1() string {
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

func (daemon *formalCoxBlockwiseExchangeDaemonV1) serveV1() {
	defer close(daemon.done)
	for {
		daemon.mu.Lock()
		listener := daemon.listener
		closed := daemon.closed
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
		daemon.connections.Add(1)
		go func() {
			defer daemon.connections.Done()
			defer connection.Close()
			daemon.handleV1(connection)
		}()
	}
}

func (daemon *formalCoxBlockwiseExchangeDaemonV1) handleV1(connection *net.UnixConn) {
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	encoded, err := io.ReadAll(io.LimitReader(connection, formalCoxBlockwiseExchangeDaemonMax+1))
	if err != nil || len(encoded) > formalCoxBlockwiseExchangeDaemonMax {
		clear(encoded)
		return
	}
	defer clear(encoded)
	var request formalCoxBlockwiseExchangeDaemonRequestV1
	if err := formalCoxBlockwiseExchangeDaemonDecodeCanonical(encoded,
		formalCoxBlockwiseExchangeDaemonMax, &request); err != nil ||
		request.Version != formalCoxBlockwiseExchangeDaemonVersion || request.MAC == "" {
		return
	}
	claimedMAC := request.MAC
	request.MAC = ""
	daemon.mu.Lock()
	key := append([]byte(nil), daemon.key...)
	closed := daemon.closed
	daemon.mu.Unlock()
	defer clear(key)
	if closed {
		return
	}
	wantMAC, err := formalCoxBlockwiseExchangeDaemonMAC(key, request)
	if err != nil || !hmac.Equal([]byte(claimedMAC), []byte(wantMAC)) {
		return
	}
	payload, operationErr := daemon.dispatchV1(request.Action, request.Payload)
	if operationErr != nil {
		payload = json.RawMessage(`{}`)
	}
	response, err := formalCoxBlockwiseExchangeDaemonSignResponse(key,
		formalCoxBlockwiseExchangeDaemonResponseV1{
			Version: formalCoxBlockwiseExchangeDaemonVersion,
			OK:      operationErr == nil, Payload: payload,
		})
	if err != nil {
		return
	}
	responseEncoded, err := formalCoxBlockwiseExchangeDaemonCanonical(response)
	if err != nil || len(responseEncoded) > formalCoxBlockwiseExchangeDaemonMax {
		clear(responseEncoded)
		return
	}
	defer clear(responseEncoded)
	_, _ = connection.Write(responseEncoded)
}

func formalCoxBlockwiseExchangeDaemonPayload(encoded json.RawMessage, value any) error {
	return formalCoxBlockwiseExchangeDaemonDecodeCanonical(encoded,
		formalCoxBlockwiseExchangeDaemonMax, value)
}

func formalCoxBlockwiseExchangeDaemonResponsePayload(value any) (json.RawMessage, error) {
	encoded, err := formalCoxBlockwiseExchangeDaemonCanonical(value)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

func formalCoxBlockwiseExchangeDaemonRootFrameV1(
	claim formalCoxBlockwiseExchangeRootClaim,
) (formalCoxBlockwiseExchangeDaemonFrameV1, error) {
	encoded, err := formalCoxBlockwiseExchangeMarshalRootClaim(claim)
	if err != nil {
		return formalCoxBlockwiseExchangeDaemonFrameV1{}, err
	}
	defer clear(encoded)
	return formalCoxBlockwiseExchangeDaemonFrameV1{
		Frame: base64.StdEncoding.EncodeToString(encoded),
	}, nil
}

func formalCoxBlockwiseExchangeDaemonDecodeRootFrameV1(
	frame formalCoxBlockwiseExchangeDaemonFrameV1,
) (formalCoxBlockwiseExchangeRootClaim, error) {
	if frame.Frame == "" || len(frame.Frame) > formalCoxBlockwiseExchangeDaemonMax*2 {
		return formalCoxBlockwiseExchangeRootClaim{}, fmt.Errorf("formal-cox: invalid opaque root frame")
	}
	encoded, err := base64.StdEncoding.Strict().DecodeString(frame.Frame)
	if err != nil || len(encoded) < 2 || len(encoded) > formalCoxBlockwiseExchangeRootClaimMax ||
		base64.StdEncoding.EncodeToString(encoded) != frame.Frame {
		clear(encoded)
		return formalCoxBlockwiseExchangeRootClaim{}, fmt.Errorf("formal-cox: invalid opaque root frame")
	}
	defer clear(encoded)
	return formalCoxBlockwiseExchangeDecodeRootClaim(encoded)
}

func (daemon *formalCoxBlockwiseExchangeDaemonV1) dispatchV1(action string,
	encoded json.RawMessage,
) (json.RawMessage, error) {
	daemon.mu.Lock()
	controller := daemon.controller
	closed := daemon.closed
	daemon.mu.Unlock()
	if closed || controller == nil {
		return nil, fmt.Errorf("formal-cox: exchange daemon is closed")
	}
	switch action {
	case "bind":
		var request formalCoxBlockwiseExchangeDaemonBindV1
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &request); err != nil {
			return nil, err
		}
		if err := controller.BindPeer(request.Peer); err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(struct{}{})
	case "offer":
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &struct{}{}); err != nil {
			return nil, err
		}
		claim, err := controller.OfferV1()
		if err != nil {
			return nil, err
		}
		frame, err := formalCoxBlockwiseExchangeDaemonRootFrameV1(claim)
		if err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(frame)
	case "accept":
		var request formalCoxBlockwiseExchangeDaemonFrameV1
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &request); err != nil {
			return nil, err
		}
		claim, err := formalCoxBlockwiseExchangeDaemonDecodeRootFrameV1(request)
		if err != nil {
			return nil, err
		}
		local, err := controller.AcceptOfferV1(claim)
		if err != nil {
			return nil, err
		}
		frame, err := formalCoxBlockwiseExchangeDaemonRootFrameV1(local)
		if err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(frame)
	case "confirm":
		var request formalCoxBlockwiseExchangeDaemonFrameV1
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &request); err != nil {
			return nil, err
		}
		claim, err := formalCoxBlockwiseExchangeDaemonDecodeRootFrameV1(request)
		if err != nil {
			return nil, err
		}
		if err := controller.ConfirmOfferV1(claim); err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(struct{}{})
	case "root_claim":
		var request formalCoxBlockwiseExchangeDaemonRootV1
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &request); err != nil {
			return nil, err
		}
		attempt, err := formalCoxBlockwiseExchangeDaemonDecodeHash(request.Attempt)
		if err != nil {
			return nil, err
		}
		claim, err := controller.RootClaim(request.Step, attempt)
		if err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(claim)
	case "start":
		var request formalCoxBlockwiseExchangeDaemonStartV1
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &request); err != nil {
			return nil, err
		}
		attempt, err := formalCoxBlockwiseExchangeDaemonDecodeHash(request.Attempt)
		if err != nil {
			return nil, err
		}
		if err := controller.Start(request.Step, attempt, request.PeerClaim); err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(struct{}{})
	case "poll":
		var request formalCoxBlockwiseExchangeDaemonPollV1
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &request); err != nil {
			return nil, err
		}
		chunk, accepted, err := controller.Poll(request.Acknowledged)
		if err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(
			formalCoxBlockwiseExchangeDaemonPollResultV1{Chunk: chunk, Accepted: accepted})
	case "relay":
		var request formalCoxBlockwiseExchangeDaemonRelayV1
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &request); err != nil {
			return nil, err
		}
		accepted, err := controller.Relay(request.Chunk)
		if err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(
			formalCoxBlockwiseExchangeDaemonRelayResultV1{Accepted: accepted})
	case "result":
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &struct{}{}); err != nil {
			return nil, err
		}
		receipt, done, err := controller.Result()
		if err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(
			formalCoxBlockwiseExchangeDaemonResultV1{Receipt: receipt, Done: done})
	case "commit":
		var request formalCoxBlockwiseExchangeDaemonCommitV1
		if err := formalCoxBlockwiseExchangeDaemonPayload(encoded, &request); err != nil {
			return nil, err
		}
		pins := make(map[string]ed25519.PublicKey, len(request.Pins))
		for peer, pin := range request.Pins {
			pins[peer] = append(ed25519.PublicKey(nil), pin...)
		}
		defer func() {
			for peer := range pins {
				clear(pins[peer])
			}
		}()
		if err := controller.Commit(request.Receipts, pins); err != nil {
			return nil, err
		}
		return formalCoxBlockwiseExchangeDaemonResponsePayload(struct{}{})
	default:
		return nil, fmt.Errorf("formal-cox: unsupported exchange daemon action")
	}
}

func newFormalCoxBlockwiseExchangeDaemonClientV1(socketPath string,
	controlKey []byte,
) (*formalCoxBlockwiseExchangeDaemonClientV1, error) {
	if len(controlKey) != sha256.Size || formalCoxBlockwiseExchangeDaemonSocketValid(socketPath) != nil {
		return nil, fmt.Errorf("formal-cox: invalid exchange daemon client")
	}
	return &formalCoxBlockwiseExchangeDaemonClientV1{
		socketPath: socketPath, key: append([]byte(nil), controlKey...),
	}, nil
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) callV1(action string,
	payload any, response any,
) error {
	if client == nil || len(client.key) != sha256.Size ||
		formalCoxBlockwiseExchangeDaemonSocketValid(client.socketPath) != nil {
		return fmt.Errorf("formal-cox: exchange daemon client is unavailable")
	}
	encodedPayload, err := formalCoxBlockwiseExchangeDaemonCanonical(payload)
	if err != nil {
		return err
	}
	defer clear(encodedPayload)
	request, err := formalCoxBlockwiseExchangeDaemonSignRequest(client.key,
		formalCoxBlockwiseExchangeDaemonRequestV1{
			Version: formalCoxBlockwiseExchangeDaemonVersion,
			Action:  action, Payload: json.RawMessage(encodedPayload),
		})
	if err != nil {
		return err
	}
	encodedRequest, err := formalCoxBlockwiseExchangeDaemonCanonical(request)
	if err != nil {
		return err
	}
	defer clear(encodedRequest)
	connection, err := net.DialTimeout("unix", client.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("formal-cox: exchange daemon is unavailable")
	}
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return fmt.Errorf("formal-cox: invalid exchange daemon connection")
	}
	defer unix.Close()
	_ = unix.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := unix.Write(encodedRequest); err != nil {
		return err
	}
	if err := unix.CloseWrite(); err != nil {
		return err
	}
	encodedResponse, err := io.ReadAll(io.LimitReader(unix, formalCoxBlockwiseExchangeDaemonMax+1))
	if err != nil || len(encodedResponse) > formalCoxBlockwiseExchangeDaemonMax {
		clear(encodedResponse)
		return fmt.Errorf("formal-cox: invalid exchange daemon response")
	}
	defer clear(encodedResponse)
	var decoded formalCoxBlockwiseExchangeDaemonResponseV1
	if err := formalCoxBlockwiseExchangeDaemonDecodeCanonical(encodedResponse,
		formalCoxBlockwiseExchangeDaemonMax, &decoded); err != nil ||
		decoded.Version != formalCoxBlockwiseExchangeDaemonVersion || decoded.MAC == "" {
		return fmt.Errorf("formal-cox: invalid exchange daemon response")
	}
	providedMAC := decoded.MAC
	decoded.MAC = ""
	wantMAC, err := formalCoxBlockwiseExchangeDaemonMAC(client.key, decoded)
	if err != nil || !hmac.Equal([]byte(providedMAC), []byte(wantMAC)) || !decoded.OK {
		return fmt.Errorf("formal-cox: exchange daemon request failed")
	}
	return formalCoxBlockwiseExchangeDaemonDecodeCanonical(decoded.Payload,
		formalCoxBlockwiseExchangeDaemonMax, response)
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) BindPeerV1(peer string) error {
	return client.callV1("bind", formalCoxBlockwiseExchangeDaemonBindV1{Peer: peer}, &struct{}{})
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) OfferV1() (string, error) {
	var response formalCoxBlockwiseExchangeDaemonFrameV1
	err := client.callV1("offer", struct{}{}, &response)
	return response.Frame, err
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) AcceptV1(
	frame string,
) (formalCoxBlockwiseExchangeDaemonFrameV1, error) {
	var response formalCoxBlockwiseExchangeDaemonFrameV1
	err := client.callV1("accept", formalCoxBlockwiseExchangeDaemonFrameV1{Frame: frame}, &response)
	return response, err
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) ConfirmV1(frame string) error {
	return client.callV1("confirm", formalCoxBlockwiseExchangeDaemonFrameV1{Frame: frame}, &struct{}{})
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) RootClaimV1(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
) (formalCoxBlockwiseExchangeRootClaim, error) {
	var claim formalCoxBlockwiseExchangeRootClaim
	err := client.callV1("root_claim", formalCoxBlockwiseExchangeDaemonRootV1{
		Step: step, Attempt: hex.EncodeToString(attempt[:]),
	}, &claim)
	return claim, err
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) StartV1(
	step formalCoxBlockwiseWorkerStep, attempt [32]byte,
	peerClaim formalCoxBlockwiseExchangeRootClaim,
) error {
	return client.callV1("start", formalCoxBlockwiseExchangeDaemonStartV1{
		Step: step, Attempt: hex.EncodeToString(attempt[:]),
		PeerClaim: peerClaim,
	}, &struct{}{})
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) PollV1(ack int64) (
	*formalCoxBlockwiseExchangeChunk, int64, error,
) {
	var result formalCoxBlockwiseExchangeDaemonPollResultV1
	err := client.callV1("poll", formalCoxBlockwiseExchangeDaemonPollV1{
		Acknowledged: ack,
	}, &result)
	return result.Chunk, result.Accepted, err
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) RelayV1(
	chunk formalCoxBlockwiseExchangeChunk,
) (int64, error) {
	var result formalCoxBlockwiseExchangeDaemonRelayResultV1
	err := client.callV1("relay", formalCoxBlockwiseExchangeDaemonRelayV1{Chunk: chunk}, &result)
	return result.Accepted, err
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) ResultV1() (
	formalCoxBlockwiseStepReceipt, bool, error,
) {
	var result formalCoxBlockwiseExchangeDaemonResultV1
	err := client.callV1("result", struct{}{}, &result)
	return result.Receipt, result.Done, err
}

func (client *formalCoxBlockwiseExchangeDaemonClientV1) CommitV1(
	receipts []formalCoxBlockwiseStepReceipt, pins map[string]ed25519.PublicKey,
) error {
	encodedPins := make(map[string][]byte, len(pins))
	for peer, pin := range pins {
		encodedPins[peer] = append([]byte(nil), pin...)
	}
	defer func() {
		for peer := range encodedPins {
			clear(encodedPins[peer])
		}
	}()
	return client.callV1("commit", formalCoxBlockwiseExchangeDaemonCommitV1{
		Receipts: receipts, Pins: encodedPins,
	}, &struct{}{})
}

func (daemon *formalCoxBlockwiseExchangeDaemonV1) Close() error {
	if daemon == nil {
		return nil
	}
	daemon.mu.Lock()
	if daemon.closed {
		daemon.mu.Unlock()
		return nil
	}
	daemon.closed = true
	listener, controller, socketRoot, socketDir, path := daemon.listener, daemon.controller,
		daemon.socketRoot, daemon.socketDir, daemon.socketPath
	daemon.listener, daemon.controller, daemon.socketRoot = nil, nil, nil
	clear(daemon.key)
	daemon.key = nil
	daemon.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	<-daemon.done
	daemon.connections.Wait()
	var result error
	if controller != nil {
		result = controller.Close()
	}
	if info, err := os.Lstat(path); err == nil {
		if socketRoot == nil || formalCoxBlockwiseExchangeLeaseValidateDir(socketRoot, socketDir) != nil ||
			info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			if result == nil {
				result = fmt.Errorf("formal-cox: exchange daemon socket changed before close")
			}
		} else if err := os.Remove(path); err != nil && result == nil {
			result = err
		}
	}
	if socketRoot != nil {
		if err := socketRoot.Close(); err != nil && result == nil {
			result = err
		}
	}
	return result
}
