// psi_handlers.go: PSI command handlers (mask, double-mask, match)

package main

import (
	"encoding/json"
	"fmt"
	"os"
)


func handlePSIMask() {
	inputBytes, err := readInputBytes()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input PSIMaskInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	output, err := psiMask(&input)
	if err != nil {
		outputError(fmt.Sprintf("PSI mask failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handlePSIDoubleMask() {
	inputBytes, err := readInputBytes()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input PSIDoubleMaskInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	output, err := psiDoubleMask(&input)
	if err != nil {
		outputError(fmt.Sprintf("PSI double-mask failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

func handlePSIMatch() {
	inputBytes, err := readInputBytes()
	if err != nil {
		outputError(fmt.Sprintf("Failed to read input: %v", err))
		os.Exit(1)
	}

	var input PSIMatchInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		outputError(fmt.Sprintf("Failed to parse input: %v", err))
		os.Exit(1)
	}

	output, err := psiMatch(&input)
	if err != nil {
		outputError(fmt.Sprintf("PSI match failed: %v", err))
		os.Exit(1)
	}

	outputJSON(output)
}

// ============================================================================
// PSI Fuse Server command handler
// ============================================================================

