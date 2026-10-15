package main

// Split-block B3 policy is reconstructed from the numeric certificate. Each
// authority supplies one full v4 draw; source shares never cross this adapter.
import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
)

const dpIRLSB3SourceABI = "signed-person-q16-two-owner-valid-v1"

type dpIRLSNoisePolicy struct {
	Adjacency string          `json:"adjacency"`
	EpsilonG  dpIRLSRat       `json:"epsilon_g"`
	EpsilonH  dpIRLSRat       `json:"epsilon_h"`
	Plan      dpIRLSStagePlan `json:"plan"`
}
type dpIRLSNoiseLane struct {
	Alpha       dpIRLSRat `json:"alpha"`
	Backend     string    `json:"backend"`
	ChildID     string    `json:"child_id"`
	Coordinates int       `json:"coordinates"`
	Epsilon     dpIRLSRat `json:"epsilon"`
	Lane        string    `json:"lane"`
	Lattice     dpIRLSRat `json:"lattice"`
	Sensitivity string    `json:"sensitivity"`
	Translation []string  `json:"translation"`
	Upper       []string  `json:"upper"`
}
type dpIRLSNoisedLane struct {
	Metadata    dpIRLSNoiseLane                     `json:"metadata"`
	NoisedShare string                              `json:"noised_share"`
	Sampler     jointDPVectorConvolutionShareOutput `json:"sampler"`
}
type dpIRLSReleasedLane struct {
	EndpointHits     []bool          `json:"endpoint_hits"`
	Metadata         dpIRLSNoiseLane `json:"metadata"`
	SignedValues     []string        `json:"signed_values"`
	TranslatedValues []string        `json:"translated_values"`
	SumWrapBound     string          `json:"sum_wrap_bound"`
}
type dpIRLSFinalizeInput struct {
	Policy dpIRLSNoisePolicy  `json:"policy"`
	Left   []dpIRLSNoisedLane `json:"left"`
	Right  []dpIRLSNoisedLane `json:"right"`
}

func dpIRLSNoiseRational(v dpIRLSRat) (*big.Rat, error) {
	n, ok := new(big.Int).SetString(v.N, 10)
	if !ok || n.String() != v.N || n.Sign() <= 0 || n.BitLen() > 128 {
		return nil, errCrossGridStage
	}
	d, ok := new(big.Int).SetString(v.D, 10)
	if !ok || d.String() != v.D || d.Sign() <= 0 || d.BitLen() > 128 {
		return nil, errCrossGridStage
	}
	r := new(big.Rat).SetFrac(n, d)
	if r.Num().String() != v.N || r.Denom().String() != v.D {
		return nil, errCrossGridStage
	}
	return r, nil
}
func dpIRLSNoiseDecimal(v dpIRLSRat) (string, error) {
	r, e := dpIRLSNoiseRational(v)
	if e != nil {
		return "", e
	}
	// The signed smoke profile has integral budgets. Finite decimals are also
	// exact; nonterminating decimal conversions are never rounded for admission.
	for digits := 0; digits <= 100; digits++ {
		s := r.FloatString(digits)
		q, ok := new(big.Rat).SetString(s)
		if ok && q.Cmp(r) == 0 {
			return s, nil
		}
	}
	return "", errCrossGridStage
}
func dpIRLSNoiseLanes(p dpIRLSNoisePolicy) ([]dpIRLSNoiseLane, error) {
	if p.Plan.validate() != nil || p.Plan.SourceABI != dpIRLSB3SourceABI || (p.Adjacency != "add_remove" && p.Adjacency != "replace_one") {
		return nil, errCrossGridStage
	}
	c, e := dpIRLSProducerCertificate(p.Plan.Family, p.Plan.P, p.Plan.Rows, 1)
	if e != nil {
		return nil, e
	}
	lanes := make([]dpIRLSNoiseLane, 2)
	for i, name := range []string{"g", "H"} {
		epsilon, sensitivity, a, count := p.EpsilonG, c.S1G, c.GTranslation, 3
		if i == 1 {
			epsilon, sensitivity, a, count = p.EpsilonH, c.S1H, c.HTranslation, 6
		}
		if p.Adjacency == "replace_one" {
			sensitivity *= 2
		}
		r, e := dpIRLSNoiseRational(epsilon)
		if e != nil {
			return nil, e
		}
		decimal, e := dpIRLSNoiseDecimal(epsilon)
		if e != nil {
			return nil, e
		}
		if _, e = jointDPPlanVectorConvolutionLaplaceV4(jointDPVectorPlanInput{Epsilon: decimal, Delta: "0", SensitivitySteps: strconv.FormatInt(sensitivity, 10), TotalCoordinateCount: count}); e != nil {
			return nil, e
		}
		alpha := new(big.Rat).Quo(r, new(big.Rat).SetInt64(sensitivity))
		id := sha256.Sum256([]byte("dsvert-dp-irls-child-v1\x00" + p.Plan.StageID + "\x00" + name))
		lane := dpIRLSNoiseLane{Alpha: dpIRLSRat{D: alpha.Denom().String(), N: alpha.Num().String()}, Backend: jointDPVectorConvolutionBackendV4, ChildID: hex.EncodeToString(id[:]), Coordinates: count, Epsilon: epsilon, Lane: name, Lattice: dpIRLSRat{D: "4096", N: "1"}, Sensitivity: strconv.FormatInt(sensitivity, 10), Translation: make([]string, count), Upper: make([]string, count)}
		for j := 0; j < count; j++ {
			lane.Translation[j] = strconv.FormatInt(a, 10)
			lane.Upper[j] = strconv.FormatInt(2*a, 10)
		}
		lanes[i] = lane
	}
	return lanes, nil
}
func dpIRLSNoiseTranscript(lane dpIRLSNoiseLane) [32]byte {
	b, _ := json.Marshal(lane)
	return sha256.Sum256(append([]byte("dsvert-dp-irls-lane-law-v1\x00"), b...))
}
func dpIRLSSampleLane(lane dpIRLSNoiseLane, peer string, seed [32]byte, share []byte) (dpIRLSNoisedLane, error) {
	transcript := dpIRLSNoiseTranscript(lane)
	context := jointDPCommitmentContext(transcript, "convolution", peer)
	commitment := jointDPSeedCommitment(context, seed)
	epsilon, e := dpIRLSNoiseDecimal(lane.Epsilon)
	if e != nil {
		return dpIRLSNoisedLane{}, e
	}
	in := jointDPVectorConvolutionShareInput{Version: jointDPVectorConvolutionInputVersionV4, RingBits: 128, TotalCoordinateCount: lane.Coordinates, CoordinateCount: lane.Coordinates, OutputLatticeBits: 12, Epsilon: epsilon, AllocatedDelta: "0", SensitivitySteps: lane.Sensitivity, ScaleShifts: make([]int, lane.Coordinates), RawUpperBounds: lane.Upper, ReleaseContractHash: lane.ChildID, TranscriptHash: hex.EncodeToString(transcript[:]), PeerName: peer, CommitmentContext: hex.EncodeToString(context[:]), SeedCommitment: hex.EncodeToString(commitment[:]), PrivateSeed: hex.EncodeToString(seed[:]), SourceShare: base64.StdEncoding.EncodeToString(share)}
	out, e := jointDPVectorConvolutionSampleShare(in)
	if e != nil {
		return dpIRLSNoisedLane{}, e
	}
	return dpIRLSNoisedLane{Metadata: lane, NoisedShare: out.NoisedShare, Sampler: out}, nil
}
func dpIRLSFinalize(in dpIRLSFinalizeInput) ([]dpIRLSReleasedLane, error) {
	lanes, e := dpIRLSNoiseLanes(in.Policy)
	if e != nil || len(in.Left) != 2 || len(in.Right) != 2 {
		return nil, errCrossGridStage
	}
	out := make([]dpIRLSReleasedLane, 2)
	for i, lane := range lanes {
		transcript := dpIRLSNoiseTranscript(lane)
		th := hex.EncodeToString(transcript[:])
		epsilon, _ := dpIRLSNoiseDecimal(lane.Epsilon)
		for _, block := range []dpIRLSNoisedLane{in.Left[i], in.Right[i]} {
			s := block.Sampler
			// Recompute the entire public noise law, including exact epsilon/S1.
			expected, e := jointDPPlanVectorConvolutionLaplaceV4(jointDPVectorPlanInput{Epsilon: epsilon, Delta: "0", SensitivitySteps: lane.Sensitivity, TotalCoordinateCount: lane.Coordinates})
			if e != nil || !reflect.DeepEqual(block.Metadata, lane) || s.Version != jointDPVectorConvolutionOutputVersionV4 || s.Backend != lane.Backend || s.Sampler != jointDPVectorConvolutionSamplerVersionV4 || s.ReleaseContractHash != lane.ChildID || s.TranscriptHash != th || s.NoisedShare != block.NoisedShare || !reflect.DeepEqual(s.Plan, expected) || !s.FullCapsuleParametersPerPeer || s.EpsilonDividedByPeerCount {
				return nil, errCrossGridStage
			}
		}
		if in.Left[i].Sampler.PeerName == in.Right[i].Sampler.PeerName {
			return nil, errCrossGridStage
		}
		final, e := jointDPVectorConvolutionFinalize(jointDPVectorConvolutionFinalizerInput{Version: jointDPVectorConvolutionFinalizerInputVersionV4, RingBits: 128, TotalCoordinateCount: lane.Coordinates, CoordinateCount: lane.Coordinates, OutputLatticeBits: 12, Epsilon: epsilon, AllocatedDelta: "0", SensitivitySteps: lane.Sensitivity, ScaleShifts: make([]int, lane.Coordinates), RawUpperBounds: lane.Upper, ReleaseContractHash: lane.ChildID, TranscriptHash: th, LeftNoisedShare: in.Left[i].NoisedShare, RightNoisedShare: in.Right[i].NoisedShare})
		if e != nil {
			return nil, e
		}
		released := dpIRLSReleasedLane{Metadata: lane, EndpointHits: make([]bool, lane.Coordinates), SignedValues: make([]string, lane.Coordinates), TranslatedValues: final.ClampedScaledValues, SumWrapBound: final.SumWrapBound}
		for j, s := range final.ClampedScaledValues {
			v, _ := new(big.Int).SetString(s, 10)
			a, _ := new(big.Int).SetString(lane.Translation[j], 10)
			released.EndpointHits[j] = s == "0" || s == lane.Upper[j]
			released.SignedValues[j] = v.Sub(v, a).String()
		}
		out[i] = released
	}
	return out, nil
}
func handleDPIRLSNoisePlan() {
	var in dpIRLSNoisePolicy
	mpcReadInput(&in)
	lanes, e := dpIRLSNoiseLanes(in)
	if e != nil {
		outputError("dp IRLS noise policy rejected")
		return
	}
	p, _ := dpIRLSStageKernelPlan(in.Plan)
	mpcWriteOutput(struct {
		Lanes   []dpIRLSNoiseLane `json:"lanes"`
		Purpose string            `json:"purpose"`
	}{lanes, p.purpose()})
}
func handleDPIRLSFinalize() {
	var in dpIRLSFinalizeInput
	mpcReadInput(&in)
	out, e := dpIRLSFinalize(in)
	if e != nil {
		outputError(fmt.Sprint("dp IRLS finalization rejected"))
		return
	}
	mpcWriteOutput(out)
}
