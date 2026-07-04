// dsvert-mpc: Ring63 MPC + PSI CLI for dsVert
//
// Pure Ring63 fixed-point arithmetic, Beaver triples, DCF wide spline,
// and EC-DH PSI.
//
// Usage:
//   dsvert-mpc <command> < input.json > output.json

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const VERSION = "1.0.0"

type ErrorOutput struct {
	Error string `json:"error"`
}

func outputError(msg string) {
	j, _ := json.Marshal(ErrorOutput{Error: msg})
	fmt.Println(string(j))
}

func output(v interface{}) {
	j, err := json.Marshal(v)
	if err != nil {
		outputError("JSON marshal error: " + err.Error())
		os.Exit(1)
	}
	fmt.Println(string(j))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: dsvert-mpc <command>")
		os.Exit(1)
	}
	cmd := os.Args[1]

	switch cmd {
	// Transport encryption (X25519 + AES-256-GCM)
	case "transport-keygen":
		handleTransportKeygen()
	case "transport-encrypt":
		handleTransportEncrypt()
	case "transport-decrypt":
		handleTransportDecrypt()

	// PSI (EC-DH on P-256)
	case "psi-mask":
		handlePSIMask()
	case "psi-double-mask":
		handlePSIDoubleMask()
	case "psi-match":
		handlePSIMatch()
	case "psi-pack-points":
		handlePSIPackPoints()
	case "psi-unpack-points":
		handlePSIUnpackPoints()

	// Ring63 fixed-point operations
	case "k2-float-to-fp":
		handleK2FloatToFP()
	case "k2-split-fp-share":
		handleK2SplitFPShare()
	case "k2-fp-add":
		handleK2FPAdd()
	case "k2-fp-sub":
		handleK2FPSub()
	case "k2-fp-vec-mul":
		handleK2FPVecMul()
	case "k2-fp-cumsum":
		handleK2FPCumsum()
	case "k2-fp-permute-share":
		handleK2FPPermuteShare()
	case "k2-fp-sum":
		handleK2FPSum()
	case "k2-fp-strided-sum":
		handleK2FPStridedSum()
	case "k2-fp-permute":
		handleK2FPPermute()
	case "k2-fp-column-concat":
		handleK2FPColumnConcat()
	case "k2-fp-extract-column":
		handleK2FPExtractColumn()

	// Element-wise Beaver vector multiplication (mu*G in Cox, generic 2-share product)
	case "k2-beaver-vecmul-gen-triples":
		handleK2BeaverVecmulGenTriples()
	case "k2-beaver-vecmul-round1":
		handleK2BeaverVecmulR1()
	case "k2-beaver-vecmul-round2":
		handleK2BeaverVecmulR2()

	// OT-Beaver preprocessing (dealer-free triple generation).
	case "k2-ot-beaver-sample":
		handleK2OTBeaverSample()
	case "k2-ot-mul-sender-setup":
		handleK2OTMulSenderSetup()
	case "k2-ot-mul-receiver-choices":
		handleK2OTMulReceiverChoices()
	case "k2-ot-mul-sender-encrypt":
		handleK2OTMulSenderEncrypt()
	case "k2-ot-mul-receiver-decrypt":
		handleK2OTMulReceiverDecrypt()
	case "k2-ot-beaver-finalize":
		handleK2OTBeaverFinalize()
	case "k2-iknp-base-receiver-setup":
		handleK2IKNPBaseReceiverSetup()
	case "k2-iknp-base-sender-choices":
		handleK2IKNPBaseSenderChoices()
	case "k2-iknp-base-receiver-encrypt":
		handleK2IKNPBaseReceiverEncrypt()
	case "k2-iknp-base-sender-finalize":
		handleK2IKNPBaseSenderFinalize()
	case "k2-iknp-receiver-extend":
		handleK2IKNPReceiverExtend()
	case "k2-iknp-sender-encrypt":
		handleK2IKNPSenderEncrypt()
	case "k2-iknp-receiver-decrypt":
		handleK2IKNPReceiverDecrypt()

	// Beaver triple generation
	case "k2-gen-beaver-triples":
		handleK2GenBeaverTriples()
	case "k2-gen-matvec-triples":
		handleK2GenMatvecTriples()

	// DCF (Distributed Comparison Function)
	case "k2-dcf-gen-batch":
		handleK2DcfGenBatch()
	case "k2-cmp-gen":
		handleK2CmpGen()
	case "k2-cmp-round1":
		handleK2CmpRound1()
	case "k2-cmp-round2":
		handleK2CmpRound2()

	// Wide spline sigmoid/exp (4-phase DCF protocol)
	case "k2-wide-spline-full":
		handleK2WideSplineFullEval()

	// Eta computation + Beaver gradient (Ring63)
	case "k2-compute-eta-fp":
		handleK2ComputeEtaFP()
	case "k2-full-iter-r3":
		handleK2FullIterR3()

	// Ring127 Chebyshev-exp coefficients (public)
	case "k2-exp127-get-coeffs":
		handleK2Exp127GetCoeffs()

	// Ring127 direct-sigmoid Chebyshev coefficients (public). GLM-specific
	// reveal-free logistic link; 29 rounds vs exp127+recip127's ~85.
	case "k2-sigmoid127-get-coeffs":
		handleK2Sigmoid127GetCoeffs()

	// Ring127 direct-softplus Chebyshev coefficients (public). Binomial-deviance
	// reveal-free link: softplus(eta)=log(1+exp(eta)) in one Clenshaw pass.
	case "k2-softplus127-get-coeffs":
		handleK2Softplus127GetCoeffs()

	// Ring127 Chebyshev-recip coefficients + NR constants (public)
	case "k2-recip127-get-coeffs":
		handleK2Recip127GetCoeffs()

	// Ring127 Chebyshev-log-shift coefficients on [1, 10] core (public).
	// Used by NB full-regression θ MLE for share-space log(μ + θ).
	case "k2-log-shift-coeffs":
		handleK2LogShiftGetCoeffs()

	// Ring127 wide-Chebyshev log coefficients on [0.1, 1000] (public).
	// NR-LOG seed: 30% rel initial → 5 NR iters drive to ULP precision.
	case "k2-log-shift-coeffs-wide":
		handleK2LogShiftWideGetCoeffs()

	// Ring127 local affine combine — used by Horner / NR R-orchestration
	case "k2-ring127-affine-combine":
		handleK2Ring127AffineCombine()
	case "k2-ring127-local-scale-share":
		handleK2Ring127LocalScaleShare()

	// Ring63 aggregation (client-side)
	case "k2-ring63-aggregate":
		handleK2Ring63Aggregate()

	// Ed25519 identity (pinned peers)
	case "derive-identity":
		handleDeriveIdentity()
	case "sign-transport":
		handleSignTransport()
	case "verify-transport":
		handleVerifyTransport()

	// Version
	case "version":
		output(map[string]string{"version": VERSION})

	default:
		outputError("Unknown command: " + cmd)
		os.Exit(1)
	}
}
