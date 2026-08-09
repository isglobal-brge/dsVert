// k2_exact_gc_worker.go -- background spool worker for exact peer-to-peer GC.

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	exactGCWorkerConfigVersion = "dsvert-exact-gc-worker-v4"
	exactGCWorkerResultVersion = "dsvert-exact-gc-result-v1"
	// Match the public DSI chunk policy. Protocol writes are buffered until a
	// full public chunk is available or the local protocol reaches a read
	// dependency. This collapses p2p's 64 KiB internal writes without delaying
	// an interactive phase or making the flush policy depend on secret data.
	exactGCSpoolWriteBuffer = 1 << 20
)

type exactGCWorkerConfig struct {
	Version     string `json:"version"`
	Role        string `json:"role"`
	SessionID   string `json:"session_id"`
	MasterKey   string `json:"master_key"`
	GarblerID   string `json:"garbler_id"`
	EvaluatorID string `json:"evaluator_id"`
	Purpose     string `json:"purpose"`
	Operation   string `json:"operation"`
	RingBits    int    `json:"ring_bits"`
	FracBits    int    `json:"frac_bits"`
	Threshold   string `json:"threshold,omitempty"`
	MulBackend  string `json:"mul_backend,omitempty"`
	BoundX      string `json:"bound_x,omitempty"`
	BoundY      string `json:"bound_y,omitempty"`
	VectorLen   int    `json:"vector_len"`
	SourceShare string `json:"source_share"`
	// JointDP and PrivateSeed remain in the same mode-0600,
	// unlink-before-ready file as the ephemeral master key and input share.
	// PrivateSeed is also accepted for a garbler-side Count clamp, where it
	// deterministically re-creates only the post-clamp additive output mask.
	JointDP                *jointDPGCWorkerPolicy              `json:"joint_dp,omitempty"`
	JointDPVector          *jointDPVectorWorkerPolicy          `json:"joint_dp_vector,omitempty"`
	JointDPGaussianOneDraw *jointDPGaussianOneDrawWorkerPolicy `json:"joint_dp_gaussian_one_draw,omitempty"`
	PrivateSeed            string                              `json:"private_seed,omitempty"`
	SpoolDir               string                              `json:"spool_dir"`
	MaxSpoolBytes          int64                               `json:"max_spool_bytes"`
	TTLSeconds             int                                 `json:"ttl_seconds"`
	HeartbeatKey           string                              `json:"heartbeat_key"`
}

type exactGCWorkerResult struct {
	Version       string `json:"version"`
	Kind          string `json:"kind"`
	RingBits      int    `json:"ring_bits"`
	VectorLen     int    `json:"vector_len"`
	Share         string `json:"share"`
	ValidityShare string `json:"validity_share,omitempty"`
	ContextHash   string `json:"context_hash"`
}

type exactGCDeriveMasterInput struct {
	LocalSecret string `json:"local_secret"`
	LocalPublic string `json:"local_public"`
	PeerPublic  string `json:"peer_public"`
	SessionID   string `json:"session_id"`
	GarblerID   string `json:"garbler_id"`
	EvaluatorID string `json:"evaluator_id"`
	Purpose     string `json:"purpose"`
	Operation   string `json:"operation"`
	RingBits    int    `json:"ring_bits"`
	FracBits    int    `json:"frac_bits"`
	Threshold   string `json:"threshold,omitempty"`
	MulBackend  string `json:"mul_backend,omitempty"`
	BoundX      string `json:"bound_x,omitempty"`
	BoundY      string `json:"bound_y,omitempty"`
	VectorLen   int    `json:"vector_len"`
}

type exactGCDeriveMasterOutput struct {
	MasterKey   string `json:"master_key"`
	ContextHash string `json:"context_hash"`
}

func handleExactGCDeriveMaster() {
	var input exactGCDeriveMasterInput
	mpcReadInput(&input)
	result, err := exactGCDeriveMaster(input)
	if err != nil {
		outputError("exact-gc key agreement failed")
		return
	}
	mpcWriteOutput(result)
}

func exactGCDeriveMaster(input exactGCDeriveMasterInput) (exactGCDeriveMasterOutput, error) {
	session, err := exactGCSessionFromWire(input.SessionID, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		input.GarblerID, input.EvaluatorID, input.Purpose, input.Operation,
		input.RingBits, input.FracBits, input.Threshold, input.MulBackend,
		input.BoundX, input.BoundY, input.VectorLen)
	if err != nil {
		return exactGCDeriveMasterOutput{}, err
	}
	secretBytes, err := exactGCStrictBase64(input.LocalSecret, 32)
	if err != nil {
		return exactGCDeriveMasterOutput{}, err
	}
	localPublicBytes, err := exactGCStrictBase64(input.LocalPublic, 32)
	if err != nil {
		return exactGCDeriveMasterOutput{}, err
	}
	peerPublicBytes, err := exactGCStrictBase64(input.PeerPublic, 32)
	if err != nil {
		return exactGCDeriveMasterOutput{}, err
	}
	curve := ecdh.X25519()
	secret, err := curve.NewPrivateKey(secretBytes)
	if err != nil {
		return exactGCDeriveMasterOutput{}, fmt.Errorf("invalid local X25519 key")
	}
	if !bytes.Equal(secret.PublicKey().Bytes(), localPublicBytes) {
		return exactGCDeriveMasterOutput{}, fmt.Errorf("local X25519 keypair mismatch")
	}
	peer, err := curve.NewPublicKey(peerPublicBytes)
	if err != nil {
		return exactGCDeriveMasterOutput{}, fmt.Errorf("invalid peer X25519 key")
	}
	shared, err := secret.ECDH(peer)
	if err != nil {
		return exactGCDeriveMasterOutput{}, fmt.Errorf("X25519 key agreement failed")
	}
	defer clear(shared)
	contextHash := exactGCContextDigest(session)
	reader := hkdf.New(sha256.New, shared, contextHash[:],
		[]byte("dsvert-exact-gc-master-v1"))
	master := make([]byte, 32)
	defer clear(master)
	if _, err := io.ReadFull(reader, master); err != nil {
		return exactGCDeriveMasterOutput{}, fmt.Errorf("derive exact-gc master key")
	}
	return exactGCDeriveMasterOutput{
		MasterKey:   base64.StdEncoding.EncodeToString(master),
		ContextHash: hex.EncodeToString(contextHash[:]),
	}, nil
}

func handleExactGCWorker(configPath string) (returnErr error) {
	config, err := exactGCReadWorkerConfig(configPath)
	if err != nil {
		return err
	}
	canReportFailure := false
	var failureSession *exactGCSession
	defer func() {
		config.MasterKey = ""
		config.SourceShare = ""
		config.PrivateSeed = ""
		config.HeartbeatKey = ""
		if returnErr != nil && canReportFailure {
			if markerErr := exactGCCommitWorkerFailure(
				config.SpoolDir, config, failureSession, returnErr); markerErr != nil {
				returnErr = fmt.Errorf("%w; failure marker: %v", returnErr, markerErr)
			}
		}
	}()
	// The config contains an ephemeral X25519-derived key and both local input
	// shares. It must disappear before the worker advertises readiness.
	if err := exactGCRemoveSensitiveConfig(configPath); err != nil {
		return err
	}
	if err := exactGCPrepareWorkerSpool(config.SpoolDir); err != nil {
		return err
	}
	stopHeartbeat, err := exactGCStartWorkerHeartbeat(
		config.SpoolDir, config.SessionID, config.HeartbeatKey,
		time.Duration(config.TTLSeconds)*time.Second)
	if err != nil {
		return err
	}
	config.HeartbeatKey = ""
	heartbeatStopped := false
	defer func() {
		if !heartbeatStopped {
			if heartbeatErr := stopHeartbeat(); returnErr == nil && heartbeatErr != nil {
				returnErr = fmt.Errorf("exact-gc worker heartbeat: %w", heartbeatErr)
			}
		}
	}()
	canReportFailure = true
	session, err := exactGCSessionFromWire(config.SessionID, config.MasterKey,
		config.GarblerID, config.EvaluatorID, config.Purpose, config.Operation,
		config.RingBits, config.FracBits, config.Threshold, config.MulBackend,
		config.BoundX, config.BoundY, config.VectorLen)
	if err != nil {
		return err
	}
	failureSession = &session
	defer clear(session.MasterKey[:])
	shares, err := exactGCDecodeWorkerShares(config.SourceShare, session.Spec)
	config.MasterKey = ""
	config.SourceShare = ""
	if err != nil {
		return err
	}
	defer exactGCZeroBigInts(shares)
	var jointSpec *jointDPGCLaplaceSpec
	var jointVectorSpec *jointDPVectorSpec
	var jointGaussianOneDrawSpec *jointDPGaussianOneDrawSpec
	var privateSeed [32]byte
	deterministicClampMask := false
	if session.Spec.Operation == exactGCJointDPLaplace {
		parsed, seed, parseErr := jointDPGCWorkerInputs(config, session)
		config.PrivateSeed = ""
		if parseErr != nil {
			return parseErr
		}
		jointSpec = &parsed
		privateSeed = seed
		defer clear(privateSeed[:])
	} else if session.Spec.Operation == jointDPVectorOperation {
		parsed, seed, parseErr := jointDPVectorWorkerInputs(config, session)
		config.PrivateSeed = ""
		if parseErr != nil {
			return parseErr
		}
		jointVectorSpec = &parsed
		privateSeed = seed
		defer clear(privateSeed[:])
	} else if session.Spec.Operation == jointDPGaussianOneDrawOperation {
		parsed, seed, parseErr := jointDPGaussianOneDrawWorkerInputs(config, session)
		config.PrivateSeed = ""
		if parseErr != nil {
			return parseErr
		}
		jointGaussianOneDrawSpec = &parsed
		privateSeed = seed
		defer clear(privateSeed[:])
	} else if session.Spec.Operation == exactGCClampCount &&
		config.PrivateSeed != "" {
		if config.Role != "garbler" || config.JointDP != nil ||
			config.JointDPVector != nil || config.JointDPGaussianOneDraw != nil {
			return fmt.Errorf("invalid deterministic Count output-mask policy")
		}
		seed, parseErr := exactGCStrictBase64(config.PrivateSeed, 32)
		config.PrivateSeed = ""
		if parseErr != nil {
			return parseErr
		}
		copy(privateSeed[:], seed)
		clear(seed)
		deterministicClampMask = true
		defer clear(privateSeed[:])
	} else if config.JointDP != nil || config.JointDPVector != nil ||
		config.JointDPGaussianOneDraw != nil ||
		config.PrivateSeed != "" {
		return fmt.Errorf("unexpected joint-DP worker policy")
	}
	spool, err := newExactGCSpoolRW(config.SpoolDir, config.MaxSpoolBytes,
		time.Duration(config.TTLSeconds)*time.Second)
	if err != nil {
		return err
	}
	spoolClosed := false
	defer func() {
		if !spoolClosed {
			if closeErr := spool.Close(); returnErr == nil && closeErr != nil {
				returnErr = exactGCFailure(
					exactGCFailureInfrastructureUnavailable, closeErr)
			}
		}
	}()

	var outputShares []*big.Int
	defer func() { exactGCZeroBigInts(outputShares) }()
	if err := exactGCPrivateMarker(config.SpoolDir, "ready", []byte("1")); err != nil {
		return err
	}
	if config.Role == "garbler" {
		if jointGaussianOneDrawSpec != nil {
			outputShares, err = jointDPGaussianOneDrawRunGarbler(
				spool, session, *jointGaussianOneDrawSpec, shares, privateSeed)
		} else if jointVectorSpec != nil {
			outputShares, err = jointDPVectorRunGarbler(
				spool, session, *jointVectorSpec, shares, privateSeed)
		} else if jointSpec != nil {
			outputShares, err = jointDPGCRunGarbler(
				spool, session, *jointSpec, shares, privateSeed)
		} else if deterministicClampMask {
			outputShares, err = exactGCRunGarblerWithDeterministicOutputSeed(
				spool, session, shares, privateSeed)
		} else {
			outputShares, err = exactGCRunGarbler(spool, session, shares)
		}
	} else if config.Role == "evaluator" {
		if jointGaussianOneDrawSpec != nil {
			outputShares, err = jointDPGaussianOneDrawRunEvaluator(
				spool, session, *jointGaussianOneDrawSpec, shares, privateSeed)
		} else if jointVectorSpec != nil {
			outputShares, err = jointDPVectorRunEvaluator(
				spool, session, *jointVectorSpec, shares, privateSeed)
		} else if jointSpec != nil {
			outputShares, err = jointDPGCRunEvaluator(
				spool, session, *jointSpec, shares, privateSeed)
		} else {
			outputShares, err = exactGCRunEvaluator(spool, session, shares)
		}
	} else {
		err = fmt.Errorf("invalid exact-gc worker role")
	}
	if err != nil {
		return err
	}
	if err := spool.Close(); err != nil {
		return exactGCFailure(exactGCFailureInfrastructureUnavailable, err)
	}
	spoolClosed = true
	result, err := exactGCEncodeWorkerResult(outputShares, session)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if err := stopHeartbeat(); err != nil {
		return fmt.Errorf("exact-gc worker heartbeat: %w", err)
	}
	heartbeatStopped = true
	if err := exactGCPrivateMarker(config.SpoolDir, "result.json", encoded); err != nil {
		return err
	}
	if err := exactGCPrivateMarker(config.SpoolDir, "done", []byte("1")); err != nil {
		return err
	}
	canReportFailure = false
	return nil
}

func exactGCReadWorkerConfig(path string) (exactGCWorkerConfig, error) {
	var config exactGCWorkerConfig
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return config, fmt.Errorf("invalid exact-gc config path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) {
		return config, fmt.Errorf("unsafe exact-gc config file")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 64<<20 {
		return config, fmt.Errorf("invalid exact-gc config file")
	}
	defer clear(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return config, fmt.Errorf("invalid exact-gc config")
	}
	if config.Version != exactGCWorkerConfigVersion || config.MaxSpoolBytes < 1<<20 ||
		config.MaxSpoolBytes > 64<<30 || config.TTLSeconds < 10 || config.TTLSeconds > 86400 {
		return config, fmt.Errorf("invalid exact-gc worker policy")
	}
	heartbeatKey, err := exactGCStrictBase64(config.HeartbeatKey, 32)
	if err != nil {
		return config, fmt.Errorf("invalid exact-gc worker heartbeat policy")
	}
	clear(heartbeatKey)
	if !filepath.IsAbs(config.SpoolDir) || filepath.Clean(config.SpoolDir) != config.SpoolDir ||
		filepath.Dir(path) != config.SpoolDir {
		return config, fmt.Errorf("invalid exact-gc config location")
	}
	return config, nil
}

func exactGCRemoveSensitiveConfig(path string) error {
	if err := os.Remove(path); err == nil {
		return nil
	}
	// Best-effort overwrite limits persistence on filesystems where unlink was
	// denied after the already-open read. The operation still fails closed.
	if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		if info, statErr := file.Stat(); statErr == nil && info.Size() > 0 {
			zero := make([]byte, 4096)
			remaining := info.Size()
			for remaining > 0 {
				chunk := int64(len(zero))
				if remaining < chunk {
					chunk = remaining
				}
				if _, writeErr := file.Write(zero[:chunk]); writeErr != nil {
					break
				}
				remaining -= chunk
			}
			_ = file.Sync()
		}
		_ = file.Close()
	}
	_ = os.Remove(path)
	return fmt.Errorf("exact-gc: sensitive worker config could not be removed")
}

func exactGCZeroBigInts(values []*big.Int) {
	for _, value := range values {
		if value == nil {
			continue
		}
		clear(value.Bits())
		value.SetInt64(0)
	}
}

func exactGCSessionFromWire(sessionHex, masterB64, garblerID, evaluatorID,
	purpose, operation string, ringBits, fracBits int, thresholdString string,
	mulBackend, boundXString, boundYString string,
	vectorLen int) (exactGCSession, error) {

	var sessionID [32]byte
	sessionRaw, err := hex.DecodeString(sessionHex)
	if err != nil || len(sessionRaw) != len(sessionID) {
		return exactGCSession{}, fmt.Errorf("invalid exact-gc session id")
	}
	copy(sessionID[:], sessionRaw)
	master, err := exactGCStrictBase64(masterB64, 32)
	if err != nil {
		return exactGCSession{}, err
	}
	var masterKey [32]byte
	copy(masterKey[:], master)
	var threshold *big.Int
	if thresholdString != "" {
		threshold = new(big.Int)
		if _, ok := threshold.SetString(thresholdString, 10); !ok {
			return exactGCSession{}, fmt.Errorf("invalid exact-gc threshold")
		}
	}
	operationValue := exactGCOperation(operation)
	if operationValue == exactGCFormalCoxIterations {
		return exactGCSession{}, fmt.Errorf(
			"formal Cox is an internal purpose-bound protocol and is unavailable through exact-gc-worker")
	}
	spec := exactGCCircuitSpec{
		Operation: operationValue, RingBits: ringBits,
		FracBits: fracBits, Threshold: threshold, VectorLen: vectorLen,
	}
	if operationValue == exactGCMulTruncateChecked {
		spec.MulBackend = exactGCMulBackend(mulBackend)
		spec.BoundX = new(big.Int)
		spec.BoundY = new(big.Int)
		if _, ok := spec.BoundX.SetString(boundXString, 10); !ok ||
			spec.BoundX.Sign() <= 0 {
			return exactGCSession{}, fmt.Errorf("invalid exact-gc x bound")
		}
		if _, ok := spec.BoundY.SetString(boundYString, 10); !ok ||
			spec.BoundY.Sign() <= 0 {
			return exactGCSession{}, fmt.Errorf("invalid exact-gc y bound")
		}
	} else if mulBackend != "" || boundXString != "" || boundYString != "" {
		return exactGCSession{}, fmt.Errorf("unexpected exact-gc multiplication policy")
	}
	session := exactGCSession{
		SessionID: sessionID, MasterKey: masterKey,
		GarblerID: garblerID, EvaluatorID: evaluatorID, Purpose: purpose,
		Spec: spec,
	}
	if err := session.validate(); err != nil {
		return exactGCSession{}, err
	}
	return session, nil
}

func exactGCStrictBase64(value string, expected int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != expected ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("invalid exact-gc base64 field")
	}
	return decoded, nil
}

func exactGCDecodeWorkerShares(value string, spec exactGCCircuitSpec) ([]*big.Int, error) {
	return exactGCDecodeWorkerCanonicalShares(value, spec)
}

func exactGCEncodeWorkerResult(shares []*big.Int,
	session exactGCSession) (exactGCWorkerResult, error) {
	context := exactGCContextDigest(session)
	result := exactGCWorkerResult{
		Version: exactGCWorkerResultVersion, RingBits: session.Spec.RingBits,
		// VectorLen describes the bound input shape. count-guard intentionally
		// emits one aggregate bit, but its context must still attest to the full
		// vector that was checked.
		VectorLen: session.Spec.VectorLen, ContextHash: hex.EncodeToString(context[:]),
	}
	if session.Spec.Operation == exactGCCompareSigned ||
		session.Spec.Operation == exactGCTruncateFloor ||
		session.Spec.Operation == exactGCTruncateNearestEven ||
		session.Spec.Operation == exactGCClampCount {
		result.Kind = "ring-share"
		encoded, err := exactGCEncodeWorkerCanonicalShares(shares, session.Spec)
		if err != nil {
			return exactGCWorkerResult{}, err
		}
		result.Share = encoded
		return result, nil
	}
	if session.Spec.Operation == exactGCMulTruncateChecked {
		if len(shares) != session.Spec.VectorLen+1 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid checked multiplication result shape")
		}
		result.Kind = "checked-ring-share"
		encoded, err := exactGCEncodeWorkerCanonicalShares(
			shares[:session.Spec.VectorLen], session.Spec)
		if err != nil {
			return exactGCWorkerResult{}, err
		}
		validity := shares[session.Spec.VectorLen]
		if validity.Cmp(big.NewInt(0)) != 0 && validity.Cmp(big.NewInt(1)) != 0 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid exact-gc validity share")
		}
		result.Share = encoded
		result.ValidityShare = packBoolsB64([]bool{validity.Bit(0) == 1})
		return result, nil
	}
	if session.Spec.Operation == exactGCAlignmentMaskRing128 {
		if len(shares) != session.Spec.VectorLen+1 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid alignment-mask result shape")
		}
		result.Kind = "alignment-masked-ring128-share-v1"
		encoded, err := exactGCEncodeWorkerCanonicalShares(
			shares[:session.Spec.VectorLen], session.Spec)
		if err != nil {
			return exactGCWorkerResult{}, err
		}
		validity := shares[session.Spec.VectorLen]
		if validity.Cmp(big.NewInt(0)) != 0 && validity.Cmp(big.NewInt(1)) != 0 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid alignment-mask validity share")
		}
		result.Share = encoded
		result.ValidityShare = packBoolsB64([]bool{validity.Bit(0) == 1})
		return result, nil
	}
	if session.Spec.Operation == exactGCJointDPLaplace {
		if len(shares) != session.Spec.VectorLen+1 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid joint-DP result shape")
		}
		result.Kind = "joint-dp-ring-share-v2"
		encoded, err := exactGCEncodeWorkerCanonicalShares(
			shares[:session.Spec.VectorLen], session.Spec)
		if err != nil {
			return exactGCWorkerResult{}, err
		}
		validity := shares[session.Spec.VectorLen]
		if validity.Cmp(big.NewInt(0)) != 0 && validity.Cmp(big.NewInt(1)) != 0 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid joint-DP validity share")
		}
		result.Share = encoded
		result.ValidityShare = packBoolsB64([]bool{validity.Bit(0) == 1})
		return result, nil
	}
	if session.Spec.Operation == jointDPVectorOperation {
		if len(shares) != session.Spec.VectorLen+1 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid joint-DP vector result shape")
		}
		result.Kind = "joint-dp-vector-ring128-share-v1"
		encoded, err := exactGCEncodeWorkerCanonicalShares(
			shares[:session.Spec.VectorLen], session.Spec)
		if err != nil {
			return exactGCWorkerResult{}, err
		}
		validity := shares[session.Spec.VectorLen]
		if validity.Cmp(big.NewInt(0)) != 0 && validity.Cmp(big.NewInt(1)) != 0 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid joint-DP vector validity share")
		}
		result.Share = encoded
		result.ValidityShare = packBoolsB64([]bool{validity.Bit(0) == 1})
		return result, nil
	}
	if session.Spec.Operation == jointDPGaussianOneDrawOperation {
		if len(shares) != session.Spec.VectorLen+1 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid one-draw Gaussian result shape")
		}
		result.Kind = "joint-dp-vector-gaussian-one-draw-ring128-share-v1"
		encoded, err := exactGCEncodeWorkerCanonicalShares(
			shares[:session.Spec.VectorLen], session.Spec)
		if err != nil {
			return exactGCWorkerResult{}, err
		}
		validity := shares[session.Spec.VectorLen]
		if validity.Cmp(big.NewInt(0)) != 0 && validity.Cmp(big.NewInt(1)) != 0 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid one-draw Gaussian validity share")
		}
		result.Share = encoded
		result.ValidityShare = packBoolsB64([]bool{validity.Bit(0) == 1})
		return result, nil
	}
	result.Kind = "xor-bit-share"
	bits := make([]bool, len(shares))
	for i := range shares {
		if shares[i].Cmp(big.NewInt(0)) != 0 && shares[i].Cmp(big.NewInt(1)) != 0 {
			return exactGCWorkerResult{}, fmt.Errorf("invalid exact-gc bit share")
		}
		bits[i] = shares[i].Bit(0) == 1
	}
	result.Share = packBoolsB64(bits)
	return result, nil
}

func exactGCPrepareWorkerSpool(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("invalid exact-gc spool path")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("unsafe exact-gc spool directory")
	}
	for _, name := range []string{
		"inbound.bin", "outbound.bin", "exchange.hb", "worker.hb",
	} {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("unsafe exact-gc spool file")
		}
		if name != "exchange.hb" && name != "worker.hb" && info.Size() != 0 {
			return fmt.Errorf("exact-gc spool contains a stale protocol transcript")
		}
		if (name == "exchange.hb" || name == "worker.hb") && info.Size() != 1 {
			return fmt.Errorf("invalid exact-gc heartbeat sentinel")
		}
	}
	for _, name := range []string{"inbound.segments", "outbound.segments"} {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("unsafe exact-gc segment spool")
		}
		segments, err := exactGCListSegments(path)
		if err != nil || len(segments) != 0 {
			return fmt.Errorf("exact-gc spool contains a stale segmented transcript")
		}
	}
	for _, name := range []string{"inbound.ack", "outbound.head", "outbound.ack"} {
		value, err := exactGCReadOffset(filepath.Join(dir, name))
		if err != nil || value != 0 {
			return fmt.Errorf("invalid initial exact-gc spool offset")
		}
	}
	inboundStatePath := filepath.Join(dir, "inbound.state")
	inboundStateInfo, err := os.Lstat(inboundStatePath)
	if err != nil || !inboundStateInfo.Mode().IsRegular() ||
		inboundStateInfo.Mode()&os.ModeSymlink != 0 ||
		inboundStateInfo.Mode().Perm()&0o077 != 0 ||
		!exactGCPrivateOwnedRegular(inboundStateInfo) {
		return fmt.Errorf("unsafe exact-gc inbound state")
	}
	inboundState, err := os.ReadFile(inboundStatePath)
	if err != nil || string(inboundState) != exactGCInboundStateInitial {
		return fmt.Errorf("invalid initial exact-gc inbound state")
	}
	for _, name := range []string{
		"ready", "error", "failure.json", "result.json", "done", "abort",
		"outbound.offer",
	} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("exact-gc spool contains a stale terminal artifact")
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect exact-gc terminal artifact: %w", err)
		}
	}
	return nil
}

const exactGCWorkerHeartbeatVersion = "dsvert-exact-gc-worker-heartbeat-v1"

type exactGCWorkerHeartbeatRecord struct {
	Version   string `json:"version"`
	SessionID string `json:"session_id"`
	PID       int64  `json:"pid"`
	Counter   int64  `json:"counter"`
	MAC       string `json:"mac"`
}

func exactGCWorkerHeartbeatMaterial(sessionID string, pid, counter int64) string {
	return fmt.Sprintf("%s|%s|%d|%d",
		exactGCWorkerHeartbeatVersion, sessionID, pid, counter)
}

// The fixed-cadence marker is HMAC-bound to this worker's one-time config,
// protocol session and PID. A stale marker, PID reuse or another worker cannot
// extend the operation lease, and the cadence never follows secret GC flow.
func exactGCStartWorkerHeartbeat(
	dir, sessionID, encodedKey string, ttl time.Duration,
) (func() error, error) {
	key, err := exactGCStrictBase64(encodedKey, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid exact-gc worker heartbeat key")
	}
	pid := int64(os.Getpid())
	counter := int64(0)
	touch := func() error {
		counter++
		material := exactGCWorkerHeartbeatMaterial(sessionID, pid, counter)
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(material))
		record := exactGCWorkerHeartbeatRecord{
			Version: exactGCWorkerHeartbeatVersion, SessionID: sessionID,
			PID: pid, Counter: counter, MAC: hex.EncodeToString(mac.Sum(nil)),
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return exactGCPrivateMarker(dir, "worker.hb", encoded)
	}
	if err := touch(); err != nil {
		clear(key)
		return nil, fmt.Errorf("initialize exact-gc worker heartbeat: %w", err)
	}
	interval := 5 * time.Second
	if candidate := ttl / 3; candidate < interval {
		interval = candidate
	}
	if interval < time.Second {
		interval = time.Second
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		defer clear(key)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-ticker.C:
				if err := touch(); err != nil {
					done <- err
					return
				}
			}
		}
	}()
	stopped := false
	return func() error {
		if stopped {
			return fmt.Errorf("exact-gc worker heartbeat already stopped")
		}
		stopped = true
		close(stop)
		return <-done
	}, nil
}

func exactGCPrivateMarker(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, ".exact-gc-marker-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
