package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type dpIRLSWorkerInput struct {
	dpIRLSNoisePolicy
	StoreDirectory string `json:"store_dir"`
	StoreKey       string `json:"store_key"`
	NoiseSeed      string `json:"noise_seed"`
}
type dpIRLSWorkerTimings struct {
	Compile   float64 `json:"compile_seconds"`
	Protected float64 `json:"protected_seconds"`
	Noise     float64 `json:"noise_seconds"`
}
type dpIRLSWorkerOutput struct {
	Lanes        []dpIRLSNoisedLane  `json:"lanes"`
	LaneReceipts [2][2]string        `json:"lane_receipts"`
	Timings      dpIRLSWorkerTimings `json:"timings"`
}
type dpIRLSWorkerPrepared struct {
	input              dpIRLSWorkerInput
	kernel             *crossGridKernelPrepared
	source             []*big.Int
	role               exactGCRole
	key, seed, binding [32]byte
	timings            dpIRLSWorkerTimings
	fault              func(string) error
}
type dpIRLSPrivateJournal struct {
	Binding   [32]byte
	Protected bool
	Lanes     []dpIRLSNoisedLane
	Receipts  [2][2]string
}

func dpIRLSWorkerPrepare(config exactGCWorkerConfig, session exactGCSession) (*dpIRLSWorkerPrepared, error) {
	in := config.DPIRLS
	if in == nil || session.Spec.Operation != dpIRLSStageOperation || session.validate() != nil || config.SourceValidity != "" || config.GroupedLMM != nil || config.GroupedGLMM != nil || config.GroupedGEE != nil || config.CoxLoss != nil || config.CrossGrid != nil || config.JointDP != nil || config.JointDPVector != nil || config.JointDPGaussianOneDraw != nil || config.PrivateSeed != "" {
		return nil, errCrossGridStage
	}
	if _, e := dpIRLSNoiseLanes(in.dpIRLSNoisePolicy); e != nil {
		return nil, e
	}
	plan, e := dpIRLSStageKernelPlan(in.Plan)
	if e != nil || session.Purpose != plan.purpose() {
		return nil, errCrossGridStage
	}
	if !filepath.IsAbs(in.StoreDirectory) || filepath.Clean(in.StoreDirectory) != in.StoreDirectory {
		return nil, errCrossGridStage
	}
	relative, e := filepath.Rel(config.SpoolDir, in.StoreDirectory)
	if e != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return nil, errCrossGridStage
	}
	p := &dpIRLSWorkerPrepared{input: *in}
	if config.Role == "evaluator" {
		p.role = exactGCRoleEvaluator
	} else if config.Role != "garbler" {
		return nil, errCrossGridStage
	}
	key, e := exactGCStrictBase64(in.StoreKey, 32)
	if e != nil {
		return nil, e
	}
	copy(p.key[:], key)
	clear(key)
	seed, e := hex.DecodeString(in.NoiseSeed)
	if e != nil || len(seed) != 32 || hex.EncodeToString(seed) != in.NoiseSeed {
		return nil, errCrossGridStage
	}
	copy(p.seed[:], seed)
	clear(seed)
	source, e := exactGCDecodeWorkerShares(config.SourceShare, exactGCCircuitSpec{Operation: exactGCTruncateFloor, RingBits: 128, FracBits: 1, VectorLen: plan.sourceCount()})
	if e != nil {
		return nil, e
	}
	p.source = source
	mac := hmac.New(sha256.New, p.key[:])
	raw, _ := json.Marshal(struct {
		Policy dpIRLSNoisePolicy
		Source string
		Seed   [32]byte
	}{in.dpIRLSNoisePolicy, config.SourceShare, p.seed})
	mac.Write(raw)
	clear(raw)
	copy(p.binding[:], mac.Sum(nil))
	begin := time.Now()
	p.kernel, e = crossGridKernelPrepareCached(plan, config.CrossGridCache)
	p.timings.Compile = time.Since(begin).Seconds()
	if e != nil {
		return nil, e
	}
	return p, nil
}
func dpIRLSJournalRead(store *crossGridStageStore) (dpIRLSPrivateJournal, bool, error) {
	var j dpIRLSPrivateJournal
	info, e := store.root.Lstat("irls-noise.journal")
	if os.IsNotExist(e) {
		return j, false, nil
	}
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !exactGCPrivateOwnedRegular(info) || info.Size() > 1<<20 {
		return j, false, errCrossGridStage
	}
	f, e := store.root.Open("irls-noise.journal")
	if e != nil {
		return j, false, e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return j, false, errCrossGridStage
	}
	data, e := io.ReadAll(io.LimitReader(f, 1<<20))
	if e != nil || len(data) < 32 || !hmac.Equal(data[:32], store.recordMAC(data[32:])) {
		return j, false, errCrossGridStage
	}
	d := json.NewDecoder(bytes.NewReader(data[32:]))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF {
		return j, false, errCrossGridStage
	}
	return j, true, nil
}
func dpIRLSJournalWrite(store *crossGridStageStore, j dpIRLSPrivateJournal) error {
	data, e := json.Marshal(j)
	if e != nil {
		return e
	}
	data = append(store.recordMAC(data), data...)
	token, e := newExactGCSessionID()
	if e != nil {
		return e
	}
	name := ".irls-" + hex.EncodeToString(token[:])
	f, e := store.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer store.root.Remove(name)
	e = exactGCWriteFull(f, data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = store.root.Rename(name, "irls-noise.journal"); e != nil {
		return e
	}
	dir, e := store.root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (p *dpIRLSWorkerPrepared) checkpoint(event string) error {
	if p.fault != nil {
		return p.fault(event)
	}
	return nil
}
func (p *dpIRLSWorkerPrepared) run(rw io.ReadWriter, session exactGCSession) (exactGCWorkerResult, error) {
	var result exactGCWorkerResult
	graph, e := dpIRLSBuildStageGraph(p.input.Plan, [2]string{session.GarblerID, session.EvaluatorID})
	if e != nil {
		return result, e
	}
	store, e := crossGridStageOpenStore(p.input.StoreDirectory, p.key, graph, p.role)
	if e != nil {
		return result, e
	}
	defer store.Close()
	journal, exists, e := dpIRLSJournalRead(store)
	if e != nil {
		return result, e
	}
	stage, e := store.load(graph.Stages[0], nil)
	if e != nil {
		return result, e
	}
	if !exists {
		if stage.State != "EMPTY" {
			return result, errCrossGridStage
		}
		journal.Binding = p.binding
		if e = dpIRLSJournalWrite(store, journal); e != nil {
			return result, e
		}
	} else if journal.Binding != p.binding || len(journal.Lanes) > 2 || (journal.Protected && stage.State != "COMMIT") {
		return result, errCrossGridStage
	}
	begin := time.Now()
	output, e := dpIRLSExecuteStage(rw, &crossGridStageExecutor{Store: store, Base: session}, p.kernel, p.source, nil)
	p.timings.Protected = time.Since(begin).Seconds()
	if e != nil {
		return result, e
	}
	defer clear(output.Share)
	defer clear(output.Validity)
	journal.Protected = true
	if e = dpIRLSJournalWrite(store, journal); e != nil {
		return result, e
	}
	if e = p.checkpoint("protected"); e != nil {
		return result, e
	}
	begin = time.Now()
	lanes, _ := dpIRLSNoiseLanes(p.input.dpIRLSNoisePolicy)
	// A fresh encrypted channel binds both public lane laws before any barrier.
	law := crossGridStageHash("dp-irls-noise-laws", lanes)
	channel, e := crossGridStageRecoveryChannel(rw, session, p.role, law)
	if e != nil {
		return result, e
	}
	for i, lane := range lanes {
		if i >= len(journal.Lanes) {
			start, end := 0, 48
			if i == 1 {
				start, end = 48, 144
			}
			peer := session.GarblerID
			if p.role == exactGCRoleEvaluator {
				peer = session.EvaluatorID
			}
			block, e := dpIRLSSampleLane(lane, peer, p.seed, output.Share[start:end])
			if e != nil {
				return result, e
			}
			journal.Lanes = append(journal.Lanes, block)
			if e = dpIRLSJournalWrite(store, journal); e != nil {
				return result, e
			}
		} else if !reflect.DeepEqual(journal.Lanes[i].Metadata, lane) {
			return result, errCrossGridStage
		}
		if e = p.checkpoint("lane-" + lane.Lane); e != nil {
			return result, e
		}
		own := crossGridStageHash("dp-irls-noised-lane-receipt", journal.Lanes[i])
		peer, e := crossGridStageExchange(channel, p.role, crossGridStageMessage{StageID: lane.ChildID, Phase: "durable-noise", State: "COMMIT", Receipt: own})
		if e != nil || peer.State != "COMMIT" || peer.Receipt == ([32]byte{}) {
			return result, errCrossGridStage
		}
		receipts := [2]string{}
		receipts[p.role] = hex.EncodeToString(own[:])
		receipts[1-p.role] = hex.EncodeToString(peer.Receipt[:])
		if journal.Receipts[i] != ([2]string{}) && journal.Receipts[i] != receipts {
			return result, errCrossGridStage
		}
		journal.Receipts[i] = receipts
		if e = dpIRLSJournalWrite(store, journal); e != nil {
			return result, e
		}
		if e = p.checkpoint("barrier-" + lane.Lane); e != nil {
			return result, e
		}
	}
	p.timings.Noise = time.Since(begin).Seconds()
	context := exactGCContextDigest(session)
	result = exactGCWorkerResult{Version: exactGCWorkerResultVersion, Kind: "dp-irls-noised-lanes-v1", RingBits: 128, VectorLen: 9, ContextHash: hex.EncodeToString(context[:]), DPIRLS: &dpIRLSWorkerOutput{Lanes: journal.Lanes, LaneReceipts: journal.Receipts, Timings: p.timings}}
	return result, nil
}
