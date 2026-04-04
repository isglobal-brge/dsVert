package main

// k2_training.go: Secure 2-party training sidecar for K=2 binomial/Poisson.
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

	// Initialize coefficients
	theta := make([]float64, data.P)
	intercept := 0.0
	p := data.P

	converged := false
	var finalIter int

	for iter := 0; iter < config.MaxIter; iter++ {
		// --- Step 1: Compute eta_local, exchange to get eta_total ---
		etaLocal := make([]float64, n)
		for i := 0; i < n; i++ {
			etaLocal[i] = intercept
			for j := 0; j < p; j++ {
				etaLocal[i] += data.X[i][j] * theta[j]
			}
		}
		sendFloat64Vec(conn, etaLocal)
		peerEta, _ := recvFloat64Vec(conn, n)

		etaOther := make([]float64, n)  // peer's contribution (without intercept)
		for i := 0; i < n; i++ {
			etaOther[i] = peerEta[i] - intercept  // remove double-counted intercept
		}
		etaTotal := make([]float64, n)
		for i := 0; i < n; i++ {
			etaTotal[i] = etaLocal[i] + etaOther[i]
		}

		// --- Step 2: IRLS quantities (mu, w, z) ---
		mu := make([]float64, n)
		w := make([]float64, n)
		z := make([]float64, n)  // working response

		// Get y from exchange (label sends y, nonlabel receives)
		var y []float64
		if data.HasY {
			y = data.Y
			sendFloat64Vec(conn, y)
			recvFloat64Vec(conn, n)  // discard peer's
		} else {
			sendFloat64Vec(conn, make([]float64, n))
			y, _ = recvFloat64Vec(conn, n)  // receive label's y
		}

		for i := 0; i < n; i++ {
			eta := math.Max(-20, math.Min(20, etaTotal[i]))
			switch config.Family {
			case "binomial":
				mu[i] = 1.0 / (1.0 + math.Exp(-eta))
				mu[i] = math.Max(1e-10, math.Min(1-1e-10, mu[i]))
				w[i] = mu[i] * (1 - mu[i])
				if w[i] < 1e-10 { w[i] = 1e-10 }
				z[i] = eta + (y[i]-mu[i])/w[i]
			case "poisson":
				mu[i] = math.Max(1e-10, math.Exp(eta))
				w[i] = mu[i]
				if w[i] < 1e-10 { w[i] = 1e-10 }
				z[i] = eta + (y[i]-mu[i])/mu[i]
			}
		}

		// --- Step 3: Gauss-Seidel IRLS ---
		// Party 0 (label) updates first. Then exchanges fresh eta.
		// Party 1 (nonlabel) updates with fresh mu/w from party 0's update.

		// Compute eta_other (everything except my contribution)
		etaOtherForMe := make([]float64, n)
		for i := 0; i < n; i++ {
			etaOtherForMe[i] = etaTotal[i]
			for j := 0; j < p; j++ {
				etaOtherForMe[i] -= data.X[i][j] * theta[j]
			}
		}

		// IRLS block solve: beta_new = (X'WX + λI)^{-1} X'W(z - eta_other)
		// Include intercept column for label party
		pWithInt := p
		if config.PartyID == 0 {
			pWithInt = p + 1  // intercept column
		}

		XtWX := make([][]float64, pWithInt)
		for j := 0; j < pWithInt; j++ {
			XtWX[j] = make([]float64, pWithInt)
		}
		rhs := make([]float64, pWithInt)

		for i := 0; i < n; i++ {
			// Build row of augmented X (with intercept for party 0)
			xRow := make([]float64, pWithInt)
			if config.PartyID == 0 {
				xRow[0] = 1.0  // intercept
				for j := 0; j < p; j++ {
					xRow[1+j] = data.X[i][j]
				}
			} else {
				for j := 0; j < p; j++ {
					xRow[j] = data.X[i][j]
				}
			}
			for j := 0; j < pWithInt; j++ {
				rhs[j] += xRow[j] * w[i] * (z[i] - etaOtherForMe[i])
				for k := 0; k < pWithInt; k++ {
					XtWX[j][k] += xRow[j] * w[i] * xRow[k]
				}
			}
		}
		// Add regularization (not on intercept)
		for j := 0; j < pWithInt; j++ {
			if config.PartyID == 0 && j == 0 {
				continue  // no regularization on intercept
			}
			XtWX[j][j] += lambda
		}

		betaSolve := solveLinearSystem(XtWX, rhs, pWithInt)

		betaNew := make([]float64, p)
		if config.PartyID == 0 {
			intercept = betaSolve[0]
			copy(betaNew, betaSolve[1:])
		} else {
			copy(betaNew, betaSolve)
		}

		// Check convergence
		maxDiff := 0.0
		for j := 0; j < p; j++ {
			diff := math.Abs(betaNew[j] - theta[j])
			if diff > maxDiff {
				maxDiff = diff
			}
		}
		theta = betaNew

		finalIter = iter + 1

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

// solveLinearSystem solves A*x = b via Gaussian elimination with partial pivoting.
func solveLinearSystem(A [][]float64, b []float64, n int) []float64 {
	// Create augmented matrix
	aug := make([][]float64, n)
	for i := 0; i < n; i++ {
		aug[i] = make([]float64, n+1)
		copy(aug[i][:n], A[i])
		aug[i][n] = b[i]
	}
	// Forward elimination
	for col := 0; col < n; col++ {
		maxVal := math.Abs(aug[col][col])
		maxRow := col
		for row := col + 1; row < n; row++ {
			if math.Abs(aug[row][col]) > maxVal {
				maxVal = math.Abs(aug[row][col])
				maxRow = row
			}
		}
		aug[col], aug[maxRow] = aug[maxRow], aug[col]
		if math.Abs(aug[col][col]) < 1e-15 {
			aug[col][col] = 1e-15
		}
		for row := col + 1; row < n; row++ {
			factor := aug[row][col] / aug[col][col]
			for j := col; j <= n; j++ {
				aug[row][j] -= factor * aug[col][j]
			}
		}
	}
	// Back substitution
	x := make([]float64, n)
	for i := n - 1; i >= 0; i-- {
		x[i] = aug[i][n]
		for j := i + 1; j < n; j++ {
			x[i] -= aug[i][j] * x[j]
		}
		x[i] /= aug[i][i]
	}
	return x
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
