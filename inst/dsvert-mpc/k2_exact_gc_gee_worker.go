package main

// Signed analyst-specified fixed working correlation. The typed source adapter
// constructs every stage; no analyst-supplied graph or circuit is accepted.
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const groupedGEEWorkerOperation exactGCOperation = "grouped-gee-fixed-rho-staged-v1"

type groupedGEEWorkerInput struct {
	Spec           groupedGEESourceSpec    `json:"spec"`
	Source         *groupedGEESourceRecord `json:"source"`
	Routing        *groupedRouteSidecar    `json:"routing,omitempty"`
	StoreDirectory string                  `json:"store_directory"`
	StoreKey       string                  `json:"store_key"`
}

// R carries one opaque string, preserving every native f50/f64 integer bit.
func (in *groupedGEEWorkerInput) MarshalJSON() ([]byte, error) {
	type native groupedGEEWorkerInput
	raw, err := json.Marshal((*native)(in))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return json.Marshal(base64.StdEncoding.EncodeToString(raw))
}

func (in *groupedGEEWorkerInput) UnmarshalJSON(raw []byte) error {
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil {
		return errCrossGridStage
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > 48<<20 || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return errCrossGridStage
	}
	defer clear(decoded)
	type native groupedGEEWorkerInput
	var value native
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errCrossGridStage
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return errCrossGridStage
	}
	defer clear(canonical)
	if !bytes.Equal(decoded, canonical) {
		return errCrossGridStage
	}
	*in = groupedGEEWorkerInput(value)
	return nil
}

func groupedGEEWorkerPurpose(spec groupedGEESourceSpec) string {
	digest := crossGridStageHash("gee-worker-public-source-spec-v1", spec)
	return fmt.Sprintf("%s/%x", groupedGEEWorkerOperation, digest)
}

type groupedGEEWorkerPrepared struct {
	graph        *groupedGEESourceGraph
	directory    string
	key, binding [32]byte
	role         exactGCRole
}

func groupedGEEWorkerPrepare(config exactGCWorkerConfig, session exactGCSession) (*groupedGEEWorkerPrepared, error) {
	in := config.GroupedGEE
	if in == nil || session.Spec.Operation != groupedGEEWorkerOperation || session.validate() != nil ||
		config.SourceShare != "" || config.SourceValidity != "" || config.CoxLoss != nil || config.GroupedLMM != nil || config.GroupedGLMM != nil || config.CrossGrid != nil || config.CrossGridCache != nil ||
		config.JointDP != nil || config.JointDPVector != nil || config.JointDPGaussianOneDraw != nil || config.PrivateSeed != "" ||
		session.Purpose != groupedGEEWorkerPurpose(in.Spec) || session.Spec.VectorLen != len(in.Spec.Caps)*(1+(in.Spec.Numeric.Predictors+1)*(in.Spec.Numeric.Predictors+2)) ||
		session.GarblerID != in.Spec.Authorities[0] || session.EvaluatorID != in.Spec.Authorities[1] ||
		!filepath.IsAbs(in.StoreDirectory) || filepath.Clean(in.StoreDirectory) != in.StoreDirectory {
		return nil, errCrossGridStage
	}
	role := exactGCRoleGarbler
	if config.Role == "evaluator" {
		role = exactGCRoleEvaluator
	} else if config.Role != "garbler" {
		return nil, errCrossGridStage
	}
	// Durable state must survive disposal of a failed transport spool.
	relative, err := filepath.Rel(config.SpoolDir, in.StoreDirectory)
	if err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return nil, errCrossGridStage
	}
	rawKey, err := exactGCStrictBase64(in.StoreKey, 32)
	if err != nil {
		return nil, errCrossGridStage
	}
	var key [32]byte
	copy(key[:], rawKey)
	clear(rawKey)
	defer clear(key[:])
	graph, err := groupedGEEBuildSourceGraph(in.Spec, role, in.Source, in.Routing, key)
	if err != nil {
		return nil, err
	}
	// Never public: authenticates exact local source bytes across cold replay.
	raw, err := json.Marshal(struct {
		Plan    [32]byte
		Source  *groupedGEESourceRecord
		Routing *groupedRouteSidecar
	}{crossGridStageHash("public-plan", graph.Graph), in.Source, in.Routing})
	if err != nil {
		return nil, errCrossGridStage
	}
	defer clear(raw)
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("dsvert/grouped-gee-worker-private-source-binding/v1\x00"))
	m.Write(raw)
	prepared := &groupedGEEWorkerPrepared{graph: graph, directory: in.StoreDirectory, key: key, role: role}
	copy(prepared.binding[:], m.Sum(nil))
	return prepared, nil
}

func (p *groupedGEEWorkerPrepared) bindSource(store *crossGridStageStore) error {
	const name = "gee-source.binding"
	info, err := store.root.Lstat(name)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !exactGCPrivateOwnedRegular(info) || info.Size() != 32 {
			return errCrossGridStage
		}
		file, err := store.root.Open(name)
		if err != nil {
			return err
		}
		defer file.Close()
		actual, err := file.Stat()
		var binding [32]byte
		if err != nil || !os.SameFile(info, actual) {
			return errCrossGridStage
		}
		if _, err := io.ReadFull(file, binding[:]); err != nil || !hmac.Equal(binding[:], p.binding[:]) {
			return errCrossGridStage
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	// Missing binding is allowed only before any stage has ever been written.
	for _, stage := range store.graph.Stages {
		if _, err := store.root.Lstat(store.name(stage.ID)); !os.IsNotExist(err) {
			return errCrossGridStage
		}
	}
	token, err := newExactGCSessionID()
	if err != nil {
		return err
	}
	temporary := ".gee-source-" + hex.EncodeToString(token[:])
	file, err := store.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer store.root.Remove(temporary)
	err = exactGCWriteFull(file, p.binding[:])
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := store.root.Rename(temporary, name); err != nil {
		return err
	}
	directory, err := store.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (p *groupedGEEWorkerPrepared) run(rw io.ReadWriter, session exactGCSession) (exactGCWorkerResult, error) {
	store, err := crossGridStageOpenStore(p.directory, p.key, p.graph.Graph, p.role)
	if err != nil {
		return exactGCWorkerResult{}, err
	}
	defer store.Close()
	if err := p.bindSource(store); err != nil {
		return exactGCWorkerResult{}, err
	}
	executor := crossGridStageExecutor{Store: store, Base: session}
	outputs, err := executor.Execute(rw, p.graph.Compute)
	if err != nil {
		return exactGCWorkerResult{}, err
	}
	// Reload authenticated commitments to produce the terminal receipt. The
	// shares and validity remain local for the subsequent private DP handoff.
	receipts := make(map[string][32]byte)
	var terminal crossGridStageRecord
	for _, stage := range store.graph.Stages {
		var previous [][32]byte
		for _, id := range stage.Predecessors {
			previous = append(previous, receipts[id])
		}
		terminal, err = store.load(stage, previous)
		if err != nil || terminal.State != "COMMIT" {
			return exactGCWorkerResult{}, errCrossGridStage
		}
		receipts[stage.ID] = terminal.StageReceipt
	}
	output := outputs[len(outputs)-1]
	if terminal.ABI.Ring != 128 || terminal.ABI.validateOutput(output) != nil || len(output.Validity) != session.Spec.VectorLen ||
		!bytes.Equal(terminal.Output.Share, output.Share) || !bytes.Equal(terminal.Output.Validity, output.Validity) {
		return exactGCWorkerResult{}, errCrossGridStage
	}
	flags := make([]bool, len(output.Validity))
	for i, bit := range output.Validity {
		flags[i] = bit == 1
	}
	context := exactGCContextDigest(session)
	return exactGCWorkerResult{Version: exactGCWorkerResultVersion, Kind: "grouped-gee-fixed-rho-staged-ring128-share-v1",
		RingBits: 128, VectorLen: session.Spec.VectorLen, Share: base64.StdEncoding.EncodeToString(output.Share),
		ValidityShare: packBoolsB64(flags), ContextHash: hex.EncodeToString(context[:]),
		StageReceipt: hex.EncodeToString(terminal.StageReceipt[:]), StagePlanDigest: hex.EncodeToString(store.plan[:])}, nil
}
