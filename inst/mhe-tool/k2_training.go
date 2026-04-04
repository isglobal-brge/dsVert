//go:build ignore

package main

// k2_training.go: DEPRECATED — Sidecar training loop abandoned in favour of
// client-relayed GS-IRLS (pragmatic mode) and HE-Link (strict mode).
//
// SECURITY MODEL: Both servers run the sidecar binary. They communicate
// directly over TCP/TLS. Intermediate values (eta, mu, residual, gradients)
// are exchanged between the sidecars but NEVER leave the sidecar process.
// Only final coefficients are written to the output file.
//
// This is the architecture recommended by the researcher: the sidecar is
// a trusted computing boundary. The R/DataSHIELD process never sees
// observation-level data from the peer.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
)

// FitConfig holds parameters for the secure training.
type FitConfig struct {
	JobID        string  `json:"job_id"`
	Family       string  `json:"family"`
	Role         string  `json:"role"`
	PartyID      int     `json:"party_id"`
	PeerHost     string  `json:"peer_host"`
	PeerPort     int     `json:"peer_port"`
	ListenPort   int     `json:"listen_port"`
	MaxIter      int     `json:"max_iter"`
	Tol          float64 `json:"tol"`
	Lambda       float64 `json:"lambda"`
	Alpha        float64 `json:"alpha"`
	FracBits     int     `json:"frac_bits"`
	ManifestHash string  `json:"manifest_hash"`
	TLSCert      string  `json:"tls_cert"`
	TLSKey       string  `json:"tls_key"`
	TLSCA        string  `json:"tls_ca"`
}

// FitResult is the output.
type FitResult struct {
	Beta         []float64 `json:"beta"`
	Intercept    float64   `json:"intercept,omitempty"`
	Iterations   int       `json:"iterations"`
	Converged    bool      `json:"converged"`
	Deviance     float64   `json:"deviance,omitempty"`
	NullDeviance float64   `json:"null_deviance,omitempty"`
}

// LocalData holds this party's local data.
type LocalData struct {
	X    [][]float64
	Y    []float64
	N, P int
	HasY bool
}

// ReadLocalData reads the binary input file.
func ReadLocalData(path string) (*LocalData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]int32, 4)
	for i := range header {
		binary.Read(f, binary.LittleEndian, &header[i])
	}
	n, p, hasY := int(header[0]), int(header[1]), header[3] != 0

	X := make([][]float64, n)
	for i := 0; i < n; i++ {
		X[i] = make([]float64, p)
		for j := 0; j < p; j++ {
			binary.Read(f, binary.LittleEndian, &X[i][j])
		}
	}
	var Y []float64
	if hasY {
		Y = make([]float64, n)
		for i := 0; i < n; i++ {
			binary.Read(f, binary.LittleEndian, &Y[i])
		}
	}
	return &LocalData{X: X, Y: Y, N: n, P: p, HasY: hasY}, nil
}

// sendFloat64Vec sends a float64 vector over the sidecar connection.
func sendFloat64Vec(conn *SidecarConn, v []float64) error {
	buf := make([]byte, len(v)*8)
	for i, val := range v {
		binary.LittleEndian.PutUint64(buf[i*8:], math.Float64bits(val))
	}
	return conn.Send(buf)
}

// recvFloat64Vec receives a float64 vector.
func recvFloat64Vec(conn *SidecarConn, n int) ([]float64, error) {
	buf, err := conn.Recv()
	if err != nil {
		return nil, err
	}
	v := make([]float64, n)
	for i := 0; i < n; i++ {
		v[i] = math.Float64frombits(binary.LittleEndian.Uint64(buf[i*8:]))
	}
	return v, nil
}

// RunSecureTraining runs the full training loop inside the sidecar.
func RunSecureTraining(config FitConfig, data *LocalData, conn *SidecarConn) (*FitResult, error) {
	n := data.N
	alpha := config.Alpha
	if alpha <= 0 {
		alpha = 0.5
	}
	lambda := config.Lambda

	// Handshake
	type HS struct {
		N, P     int
		Family   string
		Manifest string
	}
	myHS, _ := json.Marshal(HS{n, data.P, config.Family, config.ManifestHash})
	conn.Send(myHS)
	peerHSBytes, err := conn.Recv()
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	var peerHS HS
	json.Unmarshal(peerHSBytes, &peerHS)
	if peerHS.N != n || peerHS.Family != config.Family {
		return nil, fmt.Errorf("handshake mismatch: n=%d/%d family=%s/%s",
			n, peerHS.N, config.Family, peerHS.Family)
	}

	// Initialize coefficients (float64, all zero)
	theta := make([]float64, data.P)
	intercept := 0.0

	converged := false
	var finalIter int

	for iter := 0; iter < config.MaxIter; iter++ {
		lr := alpha
		if iter > 20 {
			lr = alpha / (1 + float64(iter-20)/30)
		}

		// --- Step 1: Compute local eta contribution ---
		etaLocal := make([]float64, n)
		for i := 0; i < n; i++ {
			etaLocal[i] = intercept // both parties add intercept
			for j := 0; j < data.P; j++ {
				etaLocal[i] += data.X[i][j] * theta[j]
			}
		}

		// Exchange eta contributions
		sendFloat64Vec(conn, etaLocal)
		peerEta, _ := recvFloat64Vec(conn, n)

		// eta_total = local + peer - intercept (remove double-counted intercept)
		etaTotal := make([]float64, n)
		for i := 0; i < n; i++ {
			etaTotal[i] = etaLocal[i] + peerEta[i] - intercept
		}

		// --- Step 2: Evaluate exact link function ---
		mu := make([]float64, n)
		for i := 0; i < n; i++ {
			eta := math.Max(-20, math.Min(20, etaTotal[i]))
			switch config.Family {
			case "binomial":
				mu[i] = 1.0 / (1.0 + math.Exp(-eta))
				mu[i] = math.Max(1e-10, math.Min(1-1e-10, mu[i]))
			case "poisson":
				mu[i] = math.Max(1e-10, math.Exp(eta))
			}
		}

		// --- Step 3: Compute residual ---
		// Label party computes mu-y, sends to peer
		residual := make([]float64, n)
		if data.HasY {
			for i := 0; i < n; i++ {
				residual[i] = mu[i] - data.Y[i]
			}
			sendFloat64Vec(conn, residual)
			recvFloat64Vec(conn, n) // receive peer's (unused)
		} else {
			sendFloat64Vec(conn, residual) // send zeros
			residual, _ = recvFloat64Vec(conn, n) // receive label's residual
		}

		// --- Step 4: Gradient for own features ---
		grad := make([]float64, data.P)
		for j := 0; j < data.P; j++ {
			for i := 0; i < n; i++ {
				grad[j] += data.X[i][j] * residual[i]
			}
			grad[j] = grad[j]/float64(n) + lambda*theta[j]
		}

		// --- Step 5: Update theta ---
		maxDiff := 0.0
		for j := 0; j < data.P; j++ {
			update := lr * grad[j]
			theta[j] -= update
			if math.Abs(update) > maxDiff {
				maxDiff = math.Abs(update)
			}
		}

		// Intercept update (party 0 only, shared via eta exchange)
		if config.PartyID == 0 {
			intGrad := 0.0
			for i := 0; i < n; i++ {
				intGrad += residual[i]
			}
			update := lr * intGrad / float64(n)
			intercept -= update
			if math.Abs(update) > maxDiff {
				maxDiff = math.Abs(update)
			}
		}

		finalIter = iter + 1

		// Exchange convergence
		sendFloat64Vec(conn, []float64{maxDiff})
		peerDiff, _ := recvFloat64Vec(conn, 1)
		if math.Max(maxDiff, peerDiff[0]) < config.Tol {
			converged = true
			break
		}
	}

	result := &FitResult{
		Beta:       theta,
		Iterations: finalIter,
		Converged:  converged,
	}
	if config.PartyID == 0 {
		result.Intercept = intercept
	}
	return result, nil
}

// handleFit is the CLI handler for the `fit` subcommand.
func handleFit() {
	config := FitConfig{MaxIter: 200, Tol: 1e-6, Lambda: 1e-4, Alpha: 0.5, FracBits: 20}
	args := os.Args[2:]
	inputFile, outputFile, listenPort := "", "", 0

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--job-id":         i++; config.JobID = args[i]
		case "--family":         i++; config.Family = args[i]
		case "--role":           i++; config.Role = args[i]
		case "--party-id":       i++; fmt.Sscanf(args[i], "%d", &config.PartyID)
		case "--peer-host":      i++; config.PeerHost = args[i]
		case "--peer-port":      i++; fmt.Sscanf(args[i], "%d", &config.PeerPort)
		case "--listen-port":    i++; fmt.Sscanf(args[i], "%d", &listenPort)
		case "--input-file":     i++; inputFile = args[i]
		case "--output-file":    i++; outputFile = args[i]
		case "--max-iter":       i++; fmt.Sscanf(args[i], "%d", &config.MaxIter)
		case "--tol":            i++; fmt.Sscanf(args[i], "%e", &config.Tol)
		case "--lambda":         i++; fmt.Sscanf(args[i], "%e", &config.Lambda)
		case "--step-size":      i++; fmt.Sscanf(args[i], "%e", &config.Alpha)
		case "--fixed-point-frac-bits": i++; fmt.Sscanf(args[i], "%d", &config.FracBits)
		case "--manifest-hash":  i++; config.ManifestHash = args[i]
		case "--tls-cert":       i++; config.TLSCert = args[i]
		case "--tls-key":        i++; config.TLSKey = args[i]
		case "--tls-ca":         i++; config.TLSCA = args[i]
		}
	}

	if inputFile == "" || outputFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --input-file and --output-file required")
		os.Exit(1)
	}

	data, err := ReadLocalData(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR reading input: %v\n", err)
		os.Exit(1)
	}

	var conn *SidecarConn
	if config.Role == "label" {
		port := listenPort
		if port == 0 { port = config.PeerPort }
		fmt.Fprintf(os.Stderr, "Listening on port %d...\n", port)
		conn, err = StartServer(port, config.TLSCert, config.TLSKey, config.TLSCA)
	} else {
		fmt.Fprintf(os.Stderr, "Connecting to %s:%d...\n", config.PeerHost, config.PeerPort)
		conn, err = ConnectToPeer(config.PeerHost, config.PeerPort, config.TLSCert, config.TLSKey, config.TLSCA)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Fprintf(os.Stderr, "Training: %s %s, n=%d, p=%d\n", config.Family, config.Role, data.N, data.P)
	result, err := RunSecureTraining(config, data, conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Done: %d iters, converged=%v\n", result.Iterations, result.Converged)

	out, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(outputFile, out, 0600)
}
