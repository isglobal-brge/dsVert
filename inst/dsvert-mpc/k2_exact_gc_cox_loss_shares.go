package main

// Clause-5 composition. All values passed here are one party's additive shares.
// No function reconstructs a row, prefix or unnoised coordinate. Source and
// publication authentication belong to the fused caller, not this library.
import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

const coxLossSharesVersion = "cox-packed-ot-prefix-shares-v2"
const coxLossOTBatch = 4096

// Same Beneš switches and control numbering as primitiveVWalkBenes, grouped
// into disjoint public layers. A row participates at most once in each layer.
func coxLossLayers(n int) [][]coxLossSwitch {
	layers := make([][]coxLossSwitch, 2*big.NewInt(int64(n)).BitLen()-3)
	control := 0
	var walk func(int, int, int, int)
	walk = func(size, base, stride, depth int) {
		for i := 0; i < size/2; i++ {
			layers[depth] = append(layers[depth], coxLossSwitch{base + 2*i*stride, base + (2*i+1)*stride, control})
			control++
		}
		if size == 2 {
			return
		}
		walk(size/2, base, stride*2, depth+1)
		walk(size/2, base+stride, stride*2, depth+1)
		for i := 0; i < size/2; i++ {
			k := len(layers) - 1 - depth
			layers[k] = append(layers[k], coxLossSwitch{base + 2*i*stride, base + (2*i+1)*stride, control})
			control++
		}
	}
	walk(n, 0, 1, 0)
	return layers
}

// The sender holds x, the outcome owner holds c. Outputs sum to c*x in
// Ring128. One checked OT transfers r or r+x; sender retains -r. This is NOT
// dealer-generated Beaver material and does not reveal either input.
func coxLossOTSelect(conn *p2p.Conn, owner bool, x []Uint128, choices []bool) ([]Uint128, error) {
	if len(x) < 1 || len(x) > coxLossOTBatch || (owner && len(choices) != len(x)) || (!owner && len(choices) != 0) {
		return nil, coxLossError()
	}
	transfer := ot.NewCOT(ot.NewCO(rand.Reader), rand.Reader, true, false)
	out := make([]Uint128, len(x))
	if owner {
		labels := make([]ot.Label, len(x))
		if err := transfer.InitReceiver(conn); err != nil {
			return nil, coxLossError()
		}
		if err := transfer.Receive(choices, labels); err != nil {
			return nil, coxLossError()
		}
		for i, v := range labels {
			// The legacy uint128FromLabel helper truncates to Ring127.
			// Cox source dots and masks use the full frozen Ring128 ABI.
			var data ot.LabelData
			v.GetData(&data)
			out[i] = getUint128LE(data[:])
		}
	} else {
		wires := make([]ot.Wire, len(x))
		for i, v := range x {
			var data [16]byte
			if _, err := rand.Read(data[:]); err != nil {
				return nil, coxLossError()
			}
			r := Uint128{Lo: binary.LittleEndian.Uint64(data[:8]), Hi: binary.LittleEndian.Uint64(data[8:])}
			wires[i] = ot.Wire{L0: labelFromUint128(r), L1: labelFromUint128(r.Add(v))}
			out[i] = Uint128{}.Sub(r)
		}
		if err := transfer.InitSender(conn); err != nil {
			return nil, coxLossError()
		}
		if err := transfer.Send(wires); err != nil {
			return nil, coxLossError()
		}
	}
	return out, nil
}

// receipt commits local random shares with a secret session key. Only keyed
// commitments cross the channel; never publish a raw private-state digest.
// Both receipts, ordinal and prior receipt chain enter the next chunk context.
func coxLossReceipt(conn *p2p.Conn, owner bool, session exactGCSession, previous [32]byte, ordinal int, state []Uint128) ([32]byte, error) {
	h := hmac.New(sha256.New, session.MasterKey[:])
	h.Write([]byte(coxLossSharesVersion))
	h.Write(session.SessionID[:])
	h.Write(previous[:])
	var word [8]byte
	binary.LittleEndian.PutUint64(word[:], uint64(ordinal))
	h.Write(word[:])
	if owner {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	for _, v := range state {
		binary.LittleEndian.PutUint64(word[:], v.Lo)
		h.Write(word[:])
		binary.LittleEndian.PutUint64(word[:], v.Hi)
		h.Write(word[:])
	}
	local := h.Sum(nil)
	var remote []byte
	var err error
	if owner {
		if err = conn.SendData(local); err == nil {
			err = conn.Flush()
		}
		if err == nil {
			remote, err = conn.ReceiveData()
		}
	} else {
		remote, err = conn.ReceiveData()
		if err == nil {
			err = conn.SendData(local)
		}
		if err == nil {
			err = conn.Flush()
		}
	}
	if err != nil || len(remote) != 32 {
		return [32]byte{}, coxLossError()
	}
	digest := sha256.New()
	digest.Write(previous[:])
	binary.LittleEndian.PutUint64(word[:], uint64(ordinal))
	digest.Write(word[:])
	if owner {
		digest.Write(local)
		digest.Write(remote)
	} else {
		digest.Write(remote)
		digest.Write(local)
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

// Exp inputs: (joined exact f100 dot, live, event) per row, source validity.
// Outputs: (q20 weight, q20 event*eta, live*event) per row, batch validity.
// The existing frozen rounding/range checks are reused unchanged. No prefix,
// reduction or candidate loss addition takes place inside this circuit.
func coxLossSharedExpSource(rows int) (string, int, int, int, int) {
	src, w, g, e, out := coxLossPrepareSource(rows)
	src = strings.Replace(src, "package main\n", "package main\n"+coxLossProfileSource(), 1)
	cut := strings.Index(src, fmt.Sprintf("var out [%d]int128", out))
	src = src[:cut]
	var b strings.Builder
	b.WriteString(src)
	values := make([]string, 0, out)
	for r := 0; r < rows; r++ {
		fmt.Fprintf(&b, "weight%d:=int128(coxexp(int32(eta%d)))\nactive%d:=int128(0)\nif v%d==1 && event%d==1 {active%d=1}\nterm%d:=eta%d << 4\nif v%d!=1 {weight%d=0}\nif active%d!=1 {term%d=0}\n", r, r, r, r, r, r, r, r, r, r, r, r)
		values = append(values, fmt.Sprintf("weight%d", r), fmt.Sprintf("term%d", r), fmt.Sprintf("active%d", r))
	}
	values = append(values, "valid")
	// The exp bridge consumes Ring128 but emits Ring64 shares. Upper output
	// bits are public zero; low masks remain uniform and independent. This
	// removes unnecessary 128-bit remasking without changing the source ABI.
	fmt.Fprintf(&b, "var out [%d]int128\n", len(values))
	for i, v := range values {
		fmt.Fprintf(&b, "out[%d]=int128(uint64(int64(%s)-int64(g[%d])))\n", i, v, e+i)
	}
	b.WriteString("return out\n}\n")
	return b.String(), w, g, e, out
}

// Log inputs: (tie-complete q20 prefix, live*event) per padded row, validity.
// The fixed padded shape hides the event count; unused log results are masked.
func coxLossSharedLogSource(capacity, rows int) (string, int, int, int, int) {
	in, out := 2*rows+1, rows+1
	var b strings.Builder
	b.WriteString("package main\n")
	b.WriteString(coxLossProfileSource())
	fmt.Fprintf(&b, "func main(g [%d]int64,e [%d]int64) [%d]int64 {\nok:=g[%d]+e[%d]==1\n", in+out, in, out, in-1, in-1)
	values := make([]string, 0, out)
	maxRisk := uint64(capacity) * uint64(CoxGridCrossExpKnotsQ20[64])
	for r := 0; r < rows; r++ {
		fmt.Fprintf(&b, "risk%[1]d:=g[%[2]d]+e[%[2]d]\nactive%[1]d:=g[%[3]d]+e[%[3]d]\ngood%[1]d:=risk%[1]d>=0 && risk%[1]d<=%[4]d && (active%[1]d==0 || active%[1]d==1)\nif active%[1]d==1 {good%[1]d=good%[1]d && risk%[1]d>0}\nok=ok && good%[1]d\nif !good%[1]d || risk%[1]d==0 {risk%[1]d=1048576}\nh%[1]d:=int64(coxlogrisk(uint64(risk%[1]d)))\nif active%[1]d!=1 {h%[1]d=0}\n", r, 2*r, 2*r+1, maxRisk)
		values = append(values, fmt.Sprintf("h%d", r))
	}
	b.WriteString("valid:=int64(0)\nif ok {valid=1}\n")
	values = append(values, "valid")
	coxLossEmitOutput(&b, values, in, 64)
	return b.String(), 64, in + out, in, out
}
