package main

// Internal staged release ABI. Only an authenticated family adapter may build
// this plan; this file does not add a generic analyst-supplied circuit endpoint.
// Values are little-endian additive shares. Validity is one XOR-shared bit per
// coordinate. Kernels, never local share arithmetic, conjoin input validity.
import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var errCrossGridStage = errors.New("cross-grid staged execution rejected")

type crossGridStagePlan struct {
	ID, Kind                    string
	Ring, FPScale               int
	CoordOrder                  []string
	PublicBounds                map[string]int
	SourceDigest, ProfileDigest [32]byte
	Predecessors                []string
}

type crossGridStageGraph struct {
	Version                   string
	Family, Session           string // Session is durable, not a transport retry ID.
	Authorities               [2]string
	SchemaDigest, SemanticKey [32]byte
	Stages                    []crossGridStagePlan
}

type crossGridStageOutput struct {
	Share, Validity []byte
}

type crossGridStageAttempt struct {
	Nonce, OutputMaskDomainTag [32]byte
	Session                    exactGCSession // fresh OT/record context on every attempt
}

type crossGridStageCompute func(io.ReadWriter, crossGridStageAttempt, []crossGridStageOutput) (crossGridStageOutput, error)

func crossGridStageHash(domain string, value any) [32]byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic("non-JSON internal stage value")
	}
	return sha256.Sum256(append([]byte("dsvert/staged-grid/v1/"+domain+"\x00"), data...))
}

func (p crossGridStageGraph) validate() error {
	if p.Version != "cross-grid-stage-graph-v1" || p.SchemaDigest == ([32]byte{}) ||
		p.SemanticKey == ([32]byte{}) || len(p.Stages) == 0 ||
		exactGCValidateLabel("session", p.Session, 256) != nil ||
		exactGCValidateLabel("family", p.Family, 64) != nil ||
		exactGCValidateLabel("authority", p.Authorities[0], 256) != nil ||
		exactGCValidateLabel("authority", p.Authorities[1], 256) != nil || p.Authorities[0] == p.Authorities[1] {
		return errCrossGridStage
	}
	seen := make(map[string]bool)
	for _, s := range p.Stages {
		if seen[s.ID] || exactGCValidateLabel("stage", s.ID, 128) != nil ||
			exactGCValidateLabel("kind", s.Kind, 128) != nil ||
			(s.Ring != 128 && s.Ring != 192) || s.FPScale < 0 || s.FPScale > 384 ||
			len(s.CoordOrder) == 0 || len(s.CoordOrder) > 1<<20 || len(s.PublicBounds) == 0 ||
			s.SourceDigest == ([32]byte{}) || s.ProfileDigest == ([32]byte{}) {
			return errCrossGridStage
		}
		coords, deps := make(map[string]bool), make(map[string]bool)
		for _, c := range s.CoordOrder {
			if coords[c] || exactGCValidateLabel("coordinate", c, 256) != nil {
				return errCrossGridStage
			}
			coords[c] = true
		}
		// Reserved suffixes describe the two little-endian limbs of ONE
		// Ring384 share carried in Ring192 words. Low-word carry is retained.
		for i := 0; i < len(s.CoordOrder); i++ {
			c := s.CoordOrder[i]
			if strings.Contains(c, ":limb:") {
				if s.Ring != 192 || !strings.HasSuffix(c, ":limb:0") || i+1 == len(s.CoordOrder) ||
					s.CoordOrder[i+1] != strings.TrimSuffix(c, "0")+"1" {
					return errCrossGridStage
				}
				i++
			}
		}
		for k, v := range s.PublicBounds {
			if exactGCValidateLabel("bound", k, 128) != nil || v < 0 {
				return errCrossGridStage
			}
		}
		for _, id := range s.Predecessors {
			if !seen[id] || deps[id] {
				return errCrossGridStage
			}
			deps[id] = true
		}
		seen[s.ID] = true
	}
	return nil
}

func (s crossGridStagePlan) validateOutput(out crossGridStageOutput) error {
	if len(out.Share) != len(s.CoordOrder)*(s.Ring/8) || len(out.Validity) != len(s.CoordOrder) {
		return errCrossGridStage
	}
	for _, v := range out.Validity {
		if v > 1 {
			return errCrossGridStage
		}
	}
	return nil
}

func crossGridStageClone(out crossGridStageOutput) crossGridStageOutput {
	return crossGridStageOutput{bytes.Clone(out.Share), bytes.Clone(out.Validity)}
}

// Refresh an ALREADY secret-shared kernel output with a zero sharing. The two
// authorities know this refresh stream, so it cannot hide a plaintext kernel
// output and is never used as a substitute for private computation. It makes
// even linear assembly stages use their declared attempt/mask domain.
func crossGridStageRemask(out crossGridStageOutput, abi crossGridStagePlan, role exactGCRole, attempt crossGridStageAttempt) crossGridStageOutput {
	out = crossGridStageClone(out)
	width := abi.Ring / 8
	for i := 0; i < len(out.Validity); {
		limbs := 1
		if strings.HasSuffix(abi.CoordOrder[i], ":limb:0") {
			limbs = 2
		}
		carry, sign := 0, 1
		if role == exactGCRoleEvaluator {
			sign = -1
		}
		for limb := 0; limb < limbs; limb++ {
			m := hmac.New(sha256.New, attempt.Session.MasterKey[:])
			m.Write([]byte("staged-output-zero-share-v1\x00"))
			m.Write(attempt.OutputMaskDomainTag[:])
			var index [8]byte
			binary.LittleEndian.PutUint64(index[:], uint64(i+limb))
			m.Write(index[:])
			mask := m.Sum(nil)
			for j := 0; j < width; j++ {
				pos := (i+limb)*width + j
				v := int(out.Share[pos]) + sign*int(mask[j]) + carry
				out.Share[pos], carry = byte(v), v>>8
			}
			out.Validity[i+limb] ^= mask[width] & 1
		}
		i += limbs
	}
	return out
}

// These are local private-store records. Public receipts expose neither shares
// nor validity nor a share MAC. The pair of commitments is in authority order.
type crossGridStageRecord struct {
	Version                 string
	Session, StageID, State string
	Role                    exactGCRole
	PlanDigest              [32]byte
	ABI                     crossGridStagePlan
	Generation              uint64
	AttemptNonce            [32]byte
	PredecessorReceipts     [][32]byte
	Commitments             [2][32]byte
	StageReceipt            [32]byte
	OutputMaskDomainTag     [32]byte
	Output                  crossGridStageOutput
	ShareMAC                []byte
}

func crossGridStageReceipt(r crossGridStageRecord) [32]byte {
	return crossGridStageHash("receipt", struct {
		Plan            [32]byte
		Stage           string
		Predecessors    [][32]byte
		Source, Profile [32]byte
		Commitments     [2][32]byte
	}{r.PlanDigest, r.StageID, r.PredecessorReceipts, r.ABI.SourceDigest, r.ABI.ProfileDigest, r.Commitments})
}

func crossGridStageCommitment(r crossGridStageRecord) [32]byte {
	return crossGridStageHash("masked-share-commitment", struct {
		Plan              [32]byte
		Stage             string
		Role              exactGCRole
		Nonce, MaskDomain [32]byte
		Output            crossGridStageOutput
	}{r.PlanDigest, r.StageID, r.Role, r.AttemptNonce, r.OutputMaskDomainTag, r.Output})
}

func crossGridStageShareMAC(key [32]byte, r crossGridStageRecord) []byte {
	context := crossGridStageHash("share-mac-key", struct {
		Session, Stage string
		Role           exactGCRole
		Nonce          [32]byte
	}{r.Session, r.StageID, r.Role, r.AttemptNonce})
	k := hmac.New(sha256.New, key[:])
	k.Write(context[:])
	m := hmac.New(sha256.New, k.Sum(nil))
	commitment := crossGridStageCommitment(r)
	m.Write(commitment[:])
	return m.Sum(nil)
}

func crossGridStageMaskDomain(session, stage string, nonce [32]byte) [32]byte {
	return crossGridStageHash("output-remask", struct {
		Session, Stage string
		Nonce          [32]byte
	}{session, stage, nonce})
}

func crossGridStageAttemptSession(base exactGCSession, plan [32]byte, stage string, nonce [32]byte) exactGCSession {
	context := crossGridStageHash("attempt-ot-and-record-context", struct {
		Plan  [32]byte
		Stage string
		Nonce [32]byte
	}{plan, stage, nonce})
	base.SessionID = context
	base.Purpose = fmt.Sprintf("cross-grid-stage-v1/%x", context)
	key := hmac.New(sha256.New, base.MasterKey[:])
	key.Write(context[:])
	copy(base.MasterKey[:], key.Sum(nil))
	return base
}

// Recovery metadata uses its own fresh encrypted-record context, even when an
// old authenticated peer session is reused. Hello nonces contain no secrets;
// altering or replaying one fails the subsequent context-bound AEAD exchange.
func crossGridStageRecoveryChannel(rw io.ReadWriter, base exactGCSession, role exactGCRole, plan [32]byte) (*exactGCSecureRecordRW, error) {
	if base.validate() != nil || role > exactGCRoleEvaluator {
		return nil, errCrossGridStage
	}
	var nonces [2][32]byte
	if _, err := io.ReadFull(rand.Reader, nonces[role][:]); err != nil {
		return nil, err
	}
	exchange := func(write bool) error {
		if write {
			return exactGCWriteFull(rw, nonces[role][:])
		}
		_, err := io.ReadFull(rw, nonces[1-role][:])
		return err
	}
	if err := exchange(role == exactGCRoleGarbler); err != nil {
		return nil, err
	}
	if err := exchange(role != exactGCRoleGarbler); err != nil {
		return nil, err
	}
	nonce := crossGridStageHash("recovery-channel-nonces", nonces)
	return newExactGCSecureRecordRW(rw, crossGridStageAttemptSession(base, plan, "recovery", nonce), role)
}

type crossGridStageMessage struct {
	StageID, Phase, State string
	Role                  exactGCRole
	Generation            uint64
	Nonce, Receipt        [32]byte
	Commitments           [2][32]byte
}

func crossGridStageExchange(rw io.ReadWriter, role exactGCRole, local crossGridStageMessage) (crossGridStageMessage, error) {
	local.Role = role
	var peer crossGridStageMessage
	send := func() error {
		data, err := json.Marshal(local)
		if err != nil {
			return err
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(data)))
		return exactGCWriteFull(rw, append(header[:], data...))
	}
	receive := func() error {
		var header [4]byte
		if _, err := io.ReadFull(rw, header[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(header[:])
		if n == 0 || n > 16384 {
			return errCrossGridStage
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(rw, data); err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&peer) != nil || decoder.Decode(new(any)) != io.EOF {
			return errCrossGridStage
		}
		if peer.Role != 1-role || peer.StageID != local.StageID || peer.Phase != local.Phase {
			return errCrossGridStage
		}
		return nil
	}
	first, second := send, receive
	if role == exactGCRoleEvaluator {
		first, second = receive, send
	}
	if err := first(); err != nil {
		return peer, err
	}
	return peer, second()
}
