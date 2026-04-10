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

const VERSION = "2.0.0"

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
	case "k2-fp-permute":
		handleK2FPPermute()
	case "k2-fp-column-concat":
		handleK2FPColumnConcat()

	// Beaver triple generation
	case "k2-gen-beaver-triples":
		handleK2GenBeaverTriples()
	case "k2-gen-matvec-triples":
		handleK2GenMatvecTriples()

	// DCF (Distributed Comparison Function)
	case "k2-dcf-gen-batch":
		handleK2DcfGenBatch()

	// Wide spline sigmoid/exp (4-phase DCF protocol)
	case "k2-wide-spline-full":
		handleK2WideSplineFullEval()

	// Eta computation + Beaver gradient (Ring63)
	case "k2-compute-eta-fp":
		handleK2ComputeEtaFP()
	case "k2-full-iter-r3":
		handleK2FullIterR3()

	// Ring63 aggregation (client-side)
	case "k2-ring63-aggregate":
		handleK2Ring63Aggregate()

	// Version
	case "version":
		output(map[string]string{"version": VERSION})

	default:
		outputError("Unknown command: " + cmd)
		os.Exit(1)
	}
}
