package main

// The NB2 extension emits circuit source only. It has no protected plaintext
// evaluator, command handler, release handler, or automatic registration.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const (
	CrossGridNBSpecV1              = "nb_grid_cross_v1"
	CrossGridNBProfileIdentityV1   = "cross-grid-nb2-softplus-pwq64-q16-domain22-v1"
	CrossGridNBProfileSHA256V1     = "36771f85ecc4edf240dc49a8fc2d49345f314ec5c8e758f4a918532902b3da17"
	CrossGridNBCertificateSHA256V1 = "1b21c0b8fe91b0f2f280c273469aaf0bad6a4deae176e3db2559ee83beea7dfd"
)

type exactGCNBThetaV1 struct {
	Exponent        int      `json:"exponent"`
	ThetaTimesEight int      `json:"theta_times_eight"`
	LogThetaQ64     string   `json:"log_theta_q64"`
	ConstantQ64     []string `json:"constant_q64"`
}

type exactGCNBProfileV1 struct {
	SoftplusQuadraticQ16 [][3]string        `json:"softplus_quadratic_q16"`
	Theta                []exactGCNBThetaV1 `json:"theta"`
}

type exactGCNBLossParametersV1 struct {
	ThetaExponent  int
	MaxOutcome     int
	OutputGridBits int
	PerPatientCap  int64
}

// Declarations is appended once to a fused circuit's package. Invocation of
// Function accepts the complete once-rounded q64 eta, secret f0 outcome and
// the private AND of every input validity and PSI alignment. Its second return
// is a PRIVATE domain-valid bit that must join the producer's terminal guard.
// It is never an analyst-visible row diagnostic. Sum its uint128 loss results
// in shares and inject joint DP noise only after successful completion.
type exactGCNBLossKernelV1 struct {
	Declarations      string
	Function          string
	ProfileSHA256     string
	CertificateSHA256 string
	// A producer may reuse this profile component and perform linear assembly
	// on arithmetic shares. The complete Function remains an equality adapter.
	SoftplusDeclarations string
	SoftplusFunction     string
}

type exactGCNBLossRegistrationV1 struct {
	SpecVersion       string
	MaterializedState string
	ReleaseState      string
	Build             func([]byte, exactGCNBLossParametersV1) (exactGCNBLossKernelV1, error)
}

// exactGCRegisterNBLossV1 is the sole family integration hook. The fused
// producer provides registration only after its signed-contract/source/evidence
// checks; merely calling this hook never enables a command or authorizes DP.
func exactGCRegisterNBLossV1(add func(exactGCNBLossRegistrationV1) error) error {
	if add == nil {
		return errors.New("cross-grid NB contract rejected")
	}
	return add(exactGCNBLossRegistrationV1{
		SpecVersion:       CrossGridNBSpecV1,
		MaterializedState: "cross_owner_exact_gc_materialized",
		ReleaseState:      "exact_gc_to_joint_dp_vector_v1",
		Build:             exactGCBuildNBLossV1,
	})
}

func exactGCNBReadProfileV1(data []byte) (exactGCNBProfileV1, error) {
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&envelope) != nil {
		return exactGCNBProfileV1{}, errors.New("cross-grid NB contract rejected")
	}
	var trailing interface{}
	if decoder.Decode(&trailing) != io.EOF {
		return exactGCNBProfileV1{}, errors.New("cross-grid NB contract rejected")
	}
	for _, item := range []struct{ field, digest string }{{"profile", CrossGridNBProfileSHA256V1}, {"certificate", CrossGridNBCertificateSHA256V1}} {
		var object map[string]interface{}
		if json.Unmarshal(envelope[item.field], &object) != nil {
			return exactGCNBProfileV1{}, errors.New("cross-grid NB contract rejected")
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return exactGCNBProfileV1{}, errors.New("cross-grid NB contract rejected")
		}
		digest := sha256.Sum256(canonical)
		if hex.EncodeToString(digest[:]) != item.digest {
			return exactGCNBProfileV1{}, errors.New("cross-grid NB contract rejected")
		}
	}
	var profile exactGCNBProfileV1
	if json.Unmarshal(envelope["profile"], &profile) != nil || len(profile.SoftplusQuadraticQ16) != 64 || len(profile.Theta) != 11 {
		return exactGCNBProfileV1{}, errors.New("cross-grid NB contract rejected")
	}
	return profile, nil
}

// exactGCNBSoftplusSourceV1 compiles the same public softplus table used by the
// integer oracles. The two polynomial products use at most 32-bit words; both
// raw products are strictly below 2^30. This helper registers no separate route.
func exactGCNBSoftplusSourceV1(profile exactGCNBProfileV1, name string) string {
	var s strings.Builder
	fmt.Fprintf(&s, "func %sRound16(v uint29) uint15 {\n q := uint15(v >> 16)\n r := uint16(v)\n if r > uint16(32768) || (r == uint16(32768) && (q & uint15(1)) != uint15(0)) { q = q + uint15(1) }\n return q\n}\n", name)
	fmt.Fprintf(&s, "func %s(z int32) int32 {\n x := z\n if x < int32(0) { x = -x }\n r := uint14(x)\n index := uint6(x >> 14)\n a := uint16(0)\n b := uint15(0)\n c := uint13(0)\n", name)
	var table func(int, int)
	table = func(lo, hi int) {
		if hi-lo == 1 {
			row := profile.SoftplusQuadraticQ16[lo]
			fmt.Fprintf(&s, " a = uint16(%s)\n b = uint15(%s)\n c = uint13(%s)\n", row[0], strings.TrimPrefix(row[1], "-"), row[2])
			return
		}
		mid := (lo + hi) / 2
		fmt.Fprintf(&s, " if index < uint6(%d) {\n", mid)
		table(lo, mid)
		s.WriteString(" } else {\n")
		table(mid, hi)
		s.WriteString(" }\n")
	}
	table(0, 64)
	fmt.Fprintf(&s, " residual := int32(a) - int32(%sRound16(uint29(b - %sRound16(uint29(c) * uint29(r))) * uint29(r)))\n if x >= int32(1048576) { residual = int32(0) }\n if z > int32(0) { residual = residual + z }\n return residual\n}\n", name, name)
	return s.String()
}

// Emit all wide constants by their exact 192-bit two's-complement pattern.
// The pinned MPCL compiler does not sign-extend a negative decimal literal
// reliably and can panic when it constant-folds zero minus a wide literal.
func exactGCNBWideLiteralV1(value string) string {
	return exactGCNBWideLiteralWidthV1(value, 192)
}

func exactGCNBWideLiteralWidthV1(value string, width uint) string {
	n, _ := new(big.Int).SetString(value, 10)
	if n.Sign() < 0 {
		n.Add(n, new(big.Int).Lsh(big.NewInt(1), width))
	}
	return fmt.Sprintf("int%d(%s)", width, n.String())
}

func exactGCBuildNBLossV1(data []byte, p exactGCNBLossParametersV1) (exactGCNBLossKernelV1, error) {
	return exactGCBuildNBLossWidthV1(data, p, 192)
}

// The pinned certificate bounds eta below 2^69 and the q64 loss below
// 2^80. Its largest pre-division product is below 2^83. Thus signed128
// preserves every intermediate and ties-even rounding in the shared batch.
func exactGCBuildNBLossWidthV1(data []byte, p exactGCNBLossParametersV1, width uint) (exactGCNBLossKernelV1, error) {
	if width != 128 && width != 192 {
		return exactGCNBLossKernelV1{}, errors.New("cross-grid NB contract rejected")
	}
	if p.ThetaExponent < -3 || p.ThetaExponent > 7 || p.MaxOutcome < 1 || p.MaxOutcome > 1024 || p.OutputGridBits < 8 || p.OutputGridBits > 18 || p.PerPatientCap < 1 || p.PerPatientCap > 9007199254740991 {
		return exactGCNBLossKernelV1{}, errors.New("cross-grid NB contract rejected")
	}
	profile, err := exactGCNBReadProfileV1(data)
	if err != nil {
		return exactGCNBLossKernelV1{}, err
	}
	theta := profile.Theta[p.ThetaExponent+3]
	// Public geometry/parameters determine every operation. The name binds all
	// per-candidate specializations so distinct candidates coexist in one circuit.
	name := fmt.Sprintf("nbLossV1E%dM%dG%dU%d", p.ThetaExponent+3, p.MaxOutcome, p.OutputGridBits, p.PerPatientCap)
	var s strings.Builder
	shifts := []int{3, 48}
	if 64-p.OutputGridBits != 48 {
		shifts = append(shifts, 64-p.OutputGridBits)
	}
	for _, shift := range shifts {
		fmt.Fprintf(&s, "func %sRound%d(v int192) int192 {\n negative := v < int192(0)\n if negative { v = -v }\n q := v >> %d\n r := v & int192(%s)\n if r > int192(%s) || (r == int192(%s) && (q & int192(1)) != int192(0)) { q = q + int192(1) }\n if negative { q = -q }\n return q\n}\n", name, shift, shift,
			new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(shift)), big.NewInt(1)),
			new(big.Int).Lsh(big.NewInt(1), uint(shift-1)), new(big.Int).Lsh(big.NewInt(1), uint(shift-1)))
	}
	softplusName := name + "SoftplusQ16"
	softplusDeclarations := exactGCNBSoftplusSourceV1(profile, softplusName)
	s.WriteString(softplusDeclarations)
	etaBound := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(16), 64), big.NewInt(270337))
	fmt.Fprintf(&s, "func %s(eta int192, outcome uint128, rowValid bool) (uint128, bool) {\n etaMagnitude := eta\n if etaMagnitude < int192(0) { etaMagnitude = -etaMagnitude }\n domainValid := etaMagnitude >= int192(0) && etaMagnitude <= int192(%s) && outcome <= uint128(%d)\n if !domainValid { eta = int192(0)\n outcome = uint128(0) }\n z := int32(%sRound48(eta - %s))\n soft := int192(%s(z)) << 48\n constant := int192(0)\n", name, etaBound, p.MaxOutcome, name, exactGCNBWideLiteralWidthV1(theta.LogThetaQ64, width), softplusName)
	for y := 1; y <= p.MaxOutcome; y++ {
		fmt.Fprintf(&s, " if outcome == uint128(%d) { constant = %s }\n", y, exactGCNBWideLiteralWidthV1(theta.ConstantQ64[y], width))
	}
	fmt.Fprintf(&s, " loss := constant + %sRound3(int192(outcome * uint128(8) + uint128(%d)) * soft) - int192(outcome) * eta\n if !rowValid || !domainValid { loss = int192(0) }\n if loss < int192(0) { loss = int192(0) }\n if loss > int192(%s) { loss = int192(%s) }\n return uint128(%sRound%d(loss)), domainValid\n}\n", name, theta.ThetaTimesEight,
		new(big.Int).Lsh(big.NewInt(p.PerPatientCap), uint(64-p.OutputGridBits)), new(big.Int).Lsh(big.NewInt(p.PerPatientCap), uint(64-p.OutputGridBits)), name, 64-p.OutputGridBits)
	declarations := strings.ReplaceAll(s.String(), "int192", fmt.Sprintf("int%d", width))
	return exactGCNBLossKernelV1{Declarations: declarations, Function: name, ProfileSHA256: CrossGridNBProfileSHA256V1, CertificateSHA256: CrossGridNBCertificateSHA256V1, SoftplusDeclarations: softplusDeclarations, SoftplusFunction: softplusName}, nil
}
