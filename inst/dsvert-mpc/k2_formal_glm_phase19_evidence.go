package main

// Typed post-execution evidence for the Phase-1.9 protected fan-in.  Receipt
// and checkpoint objects which may transitively depend on protected shares are
// bound with HMAC seals and are not copied into the public token.  The token
// does not contain the execution-valid value and cannot authorize an opening.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	formalGLMPhase19PostTokenVersion = "dsvert-formal-glm-phase19-post-execution-token-v1"
	formalGLMPhase19PostTokenDomain  = "dsVert/formal-glm/phase19/post-execution-token/v1"
)

type formalGLMPhase19ExecutionEvidence struct {
	Phase15ExecutionTranscriptSHA256 string `json:"phase15_execution_transcript_sha256"`
	FinalCheckpointTranscriptSHA256  string `json:"final_checkpoint_transcript_sha256"`
	WorkerTranscriptSHA256           string `json:"worker_transcript_sha256"`
	CheckpointEvidenceSHA256         string `json:"checkpoint_evidence_sha256"`
}

type formalGLMPhase19PostExecutionToken struct {
	Version                          string   `json:"version"`
	ContextSHA256                    string   `json:"context_sha256"`
	CapsuleSHA256                    string   `json:"capsule_sha256"`
	Phase15PlanSHA256                string   `json:"phase15_plan_sha256"`
	PreExecutionTokenSHA256          string   `json:"pre_execution_token_sha256"`
	RunID                            string   `json:"run_id"`
	PinsetSHA256                     string   `json:"pinset_sha256"`
	GlobalMaterializationRoot        string   `json:"global_materialization_root"`
	FanInTranscriptSHA256            string   `json:"fan_in_transcript_sha256"`
	BlockCommitmentRootSHA256        string   `json:"block_commitment_root_sha256"`
	BlockReceiptRootSHA256           string   `json:"block_receipt_root_sha256"`
	AccumulatorRoot                  string   `json:"accumulator_root"`
	ExecutionReceiptPairSHA256       string   `json:"execution_receipt_pair_sha256"`
	FinalReceiptSetSeal              string   `json:"final_receipt_set_seal"`
	CheckpointEvidenceSeal           string   `json:"checkpoint_evidence_seal"`
	Phase15ExecutionTranscriptSHA256 string   `json:"phase15_execution_transcript_sha256"`
	FinalCheckpointTranscriptSHA256  string   `json:"final_checkpoint_transcript_sha256"`
	WorkerTranscriptSHA256           string   `json:"worker_transcript_sha256"`
	PostExecutionRootSHA256          string   `json:"post_execution_root_sha256"`
	TokenSHA256                      string   `json:"token_sha256"`
	CustodianCount                   int      `json:"custodian_count"`
	ComputePeers                     []string `json:"compute_peers"`
	FanInExecuted                    bool     `json:"fan_in_executed"`
	ExactAllKValidityInsideGC        bool     `json:"exact_all_k_validity_inside_gc"`
	ConsensusComparedInsideGC        bool     `json:"consensus_compared_inside_gc"`
	FullTupleMaskInsideGC            bool     `json:"full_tuple_mask_inside_gc"`
	ExecutionValidSealed             bool     `json:"execution_valid_sealed"`
	ExecutionValidityOpened          bool     `json:"execution_validity_opened"`
	PatientDependentDigestsExposed   bool     `json:"patient_dependent_digests_exposed"`
	ProtectedDataE2EVerified         bool     `json:"protected_data_e2e_verified"`
	OpeningAuthorized                bool     `json:"opening_authorized"`
	OpeningsPerformed                int      `json:"openings_performed"`
	DPReleaseStatus                  string   `json:"dp_release_status"`
	RemainingBlockers                []string `json:"remaining_blockers"`
	ProductionReady                  bool     `json:"production_ready"`
	seal                             [32]byte
	verified                         bool
}

func formalGLMPhase19ExecutionPairMessage(
	pair formalGLMPhase19ExecutionReceiptPair) ([]byte, error) {
	if pair.Version != formalGLMPhase19ExecVersion+"-receipt-pair" ||
		!formalGLMIsSHA256(pair.ContextSHA256) ||
		!formalGLMIsSHA256(pair.AccumulatorRoot) ||
		!formalGLMIsSHA256(pair.GarblerReceiptSHA256) ||
		!formalGLMIsSHA256(pair.EvaluatorReceiptSHA256) ||
		!formalGLMIsSHA256(pair.ExecutionReceiptPairSHA256) ||
		!pair.ExecutionValidSealed || pair.ExecutionValidityOpened ||
		pair.OpeningsPerformed != 0 || pair.ProductionReady {
		return nil, fmt.Errorf("formal-glm: invalid Phase-1.9 execution receipt pair")
	}
	public := pair
	public.seal = [32]byte{}
	public.verified = false
	return json.Marshal(public)
}

func formalGLMPhase19VerifyExecutionReceiptPair(ctx formalGLMPhase19Context,
	accumulator formalGLMPhase19AccumulatorPlan,
	pair formalGLMPhase19ExecutionReceiptPair, backendKey [32]byte) error {
	if !pair.verified || pair.ContextSHA256 != ctx.ContextSHA256ForPhase19() ||
		pair.AccumulatorRoot != accumulator.AccumulatorRoot ||
		!formalGLMPhase19KeyValid(backendKey) {
		return fmt.Errorf("formal-glm: unverified Phase-1.9 execution receipt pair")
	}
	message, err := formalGLMPhase19ExecutionPairMessage(pair)
	if err != nil {
		return err
	}
	want := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19ExecDomain+"/receipt-pair-seal", message)
	if !hmac.Equal(want[:], pair.seal[:]) {
		return fmt.Errorf("formal-glm: execution receipt-pair authentication failed")
	}
	return nil
}

func formalGLMPhase19PublicExecutionRoots(ctx formalGLMPhase19Context,
	blocks []formalGLMPhase19MaskedBlockReceiptPair,
	backendKey [32]byte) (fanIn, commitments, receipts string, err error) {
	if len(blocks) != ctx.TotalBlocks {
		return "", "", "", fmt.Errorf("formal-glm: incomplete post-execution block schedule")
	}
	ordered := make([]formalGLMPhase19MaskedBlockReceiptPair, ctx.TotalBlocks)
	seen := make([]bool, ctx.TotalBlocks)
	for _, block := range blocks {
		if err := formalGLMPhase19VerifyMaskedBlockReceiptPair(
			ctx, block, backendKey); err != nil {
			return "", "", "", err
		}
		if seen[block.BlockIndex] {
			return "", "", "", fmt.Errorf("formal-glm: duplicate post-execution block")
		}
		seen[block.BlockIndex] = true
		ordered[block.BlockIndex] = block
	}
	ctxHash := ctx.ContextSHA256ForPhase19()
	fanMessage := formalGLMPhase15AppendString(nil,
		formalGLMPhase19PostTokenDomain+"/fanin")
	commitmentMessage := formalGLMPhase15AppendString(nil,
		formalGLMPhase19PostTokenDomain+"/commitments")
	receiptMessage := formalGLMPhase15AppendString(nil,
		formalGLMPhase19PostTokenDomain+"/receipts")
	for _, message := range []*[]byte{&fanMessage, &commitmentMessage, &receiptMessage} {
		*message = formalGLMPhase15AppendString(*message, ctxHash)
		*message = formalGLMPhase15AppendString(*message, ctx.GlobalMaterializationRoot)
	}
	for _, block := range ordered {
		fanMessage = formalGLMPhase15AppendString(fanMessage, block.PairRoot)
		commitmentMessage = formalGLMPhase15AppendString(
			commitmentMessage, block.PairRoot)
		receiptMessage = formalGLMPhase15AppendString(
			receiptMessage, block.ReceiptPairSHA256)
	}
	fanDigest := sha256.Sum256(fanMessage)
	commitmentDigest := sha256.Sum256(commitmentMessage)
	receiptDigest := sha256.Sum256(receiptMessage)
	return hex.EncodeToString(fanDigest[:]),
		hex.EncodeToString(commitmentDigest[:]),
		hex.EncodeToString(receiptDigest[:]), nil
}

func formalGLMPhase19PostTokenPreimage(
	token formalGLMPhase19PostExecutionToken) ([]byte, error) {
	public := token
	public.TokenSHA256 = ""
	public.seal = [32]byte{}
	public.verified = false
	return json.Marshal(public)
}

func formalGLMPhase19BuildPostExecutionToken(plan formalGLMPhase15Plan,
	ctx formalGLMPhase19Context,
	blockPairs []formalGLMPhase19MaskedBlockReceiptPair,
	accumulator formalGLMPhase19AccumulatorPlan,
	executionPair formalGLMPhase19ExecutionReceiptPair,
	finalReceipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey,
	evidence formalGLMPhase19ExecutionEvidence,
	backendKey [32]byte) (formalGLMPhase19PostExecutionToken, error) {

	var zero formalGLMPhase19PostExecutionToken
	fanInRoot, commitmentRoot, blockReceiptRoot, err :=
		formalGLMPhase19PublicExecutionRoots(ctx, blockPairs, backendKey)
	if err != nil {
		return zero, err
	}
	rebuiltAccumulator, err := formalGLMPhase19BuildAccumulatorPlan(
		ctx, blockPairs, backendKey)
	if err != nil || rebuiltAccumulator.AccumulatorRoot != accumulator.AccumulatorRoot {
		return zero, fmt.Errorf("formal-glm: accumulator does not bind all protected blocks")
	}
	return formalGLMPhase19BuildPostExecutionTokenRoots(
		plan, ctx, fanInRoot, commitmentRoot, blockReceiptRoot,
		accumulator, executionPair, finalReceipts, pins, evidence, backendKey)
}

func formalGLMPhase19BuildPostExecutionTokenFromSummary(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	summary formalGLMPhase19BlockScheduleSummary,
	accumulator formalGLMPhase19AccumulatorPlan,
	executionPair formalGLMPhase19ExecutionReceiptPair,
	finalReceipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey,
	evidence formalGLMPhase19ExecutionEvidence,
	backendKey [32]byte) (formalGLMPhase19PostExecutionToken, error) {

	if summary.TotalBlocks != ctx.TotalBlocks ||
		summary.AccumulatorRoot != accumulator.AccumulatorRoot ||
		!formalGLMIsSHA256(summary.FanInTranscriptSHA256) ||
		!formalGLMIsSHA256(summary.BlockCommitmentSHA256) ||
		!formalGLMIsSHA256(summary.BlockReceiptRootSHA256) {
		return formalGLMPhase19PostExecutionToken{},
			fmt.Errorf("formal-glm: invalid streamed post-execution roots")
	}
	return formalGLMPhase19BuildPostExecutionTokenRoots(
		plan, ctx, summary.FanInTranscriptSHA256,
		summary.BlockCommitmentSHA256, summary.BlockReceiptRootSHA256,
		accumulator, executionPair, finalReceipts, pins, evidence, backendKey)
}

func formalGLMPhase19BuildPostExecutionTokenRoots(
	plan formalGLMPhase15Plan, ctx formalGLMPhase19Context,
	fanInRoot, commitmentRoot, blockReceiptRoot string,
	accumulator formalGLMPhase19AccumulatorPlan,
	executionPair formalGLMPhase19ExecutionReceiptPair,
	finalReceipts []formalGLMPhase15StepReceipt,
	pins map[string]ed25519.PublicKey,
	evidence formalGLMPhase19ExecutionEvidence,
	backendKey [32]byte) (formalGLMPhase19PostExecutionToken, error) {

	var zero formalGLMPhase19PostExecutionToken
	if err := formalGLMPhase19ValidateContext(plan, ctx); err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyAccumulatorPlan(
		ctx, accumulator, backendKey); err != nil {
		return zero, err
	}
	if err := formalGLMPhase19VerifyExecutionReceiptPair(
		ctx, accumulator, executionPair, backendKey); err != nil {
		return zero, err
	}
	if err := formalGLMPhase15VerifyReceiptPair(
		plan, finalReceipts, pins); err != nil {
		return zero, err
	}
	if len(finalReceipts) != 2 ||
		finalReceipts[0].StepIndex != plan.ScheduleSteps-1 ||
		finalReceipts[1].StepIndex != plan.ScheduleSteps-1 {
		return zero,
			fmt.Errorf("formal-glm: receipts are not the final worker checkpoint")
	}
	for _, value := range []string{
		fanInRoot, commitmentRoot, blockReceiptRoot,
		evidence.Phase15ExecutionTranscriptSHA256,
		evidence.FinalCheckpointTranscriptSHA256,
		evidence.WorkerTranscriptSHA256,
		evidence.CheckpointEvidenceSHA256,
	} {
		if !formalGLMIsSHA256(value) {
			return zero, fmt.Errorf("formal-glm: invalid Phase-1.9 execution evidence")
		}
	}
	if finalReceipts[0].TranscriptSHA256 != evidence.FinalCheckpointTranscriptSHA256 ||
		finalReceipts[1].TranscriptSHA256 != evidence.FinalCheckpointTranscriptSHA256 {
		return zero,
			fmt.Errorf("formal-glm: final receipts and checkpoint transcript differ")
	}
	finalReceiptDigest, err := formalGLMPhase15FinalReceiptPairDigest(finalReceipts)
	if err != nil {
		return zero, err
	}
	finalReceiptSeal := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19PostTokenDomain+"/final-receipts", finalReceiptDigest[:])
	checkpointMessage := formalGLMPhase15AppendString(nil,
		evidence.CheckpointEvidenceSHA256)
	checkpointMessage = formalGLMPhase15AppendString(checkpointMessage,
		evidence.FinalCheckpointTranscriptSHA256)
	checkpointSeal := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19PostTokenDomain+"/checkpoint", checkpointMessage)

	rootMessage := formalGLMPhase15AppendString(nil,
		formalGLMPhase19PostTokenDomain+"/root")
	for _, value := range []string{
		ctx.ContextSHA256ForPhase19(), ctx.GlobalMaterializationRoot,
		fanInRoot, commitmentRoot, blockReceiptRoot, accumulator.AccumulatorRoot,
		executionPair.ExecutionReceiptPairSHA256,
		hex.EncodeToString(finalReceiptSeal[:]), hex.EncodeToString(checkpointSeal[:]),
		evidence.Phase15ExecutionTranscriptSHA256,
		evidence.FinalCheckpointTranscriptSHA256, evidence.WorkerTranscriptSHA256,
	} {
		rootMessage = formalGLMPhase15AppendString(rootMessage, value)
	}
	postRoot := sha256.Sum256(rootMessage)
	result := formalGLMPhase19PostExecutionToken{
		Version:                          formalGLMPhase19PostTokenVersion,
		ContextSHA256:                    ctx.ContextSHA256ForPhase19(),
		CapsuleSHA256:                    ctx.CapsuleSHA256,
		Phase15PlanSHA256:                ctx.Phase15PlanSHA256,
		PreExecutionTokenSHA256:          ctx.PreExecutionTokenSHA256,
		RunID:                            ctx.RunID,
		PinsetSHA256:                     ctx.PinsetSHA256,
		GlobalMaterializationRoot:        ctx.GlobalMaterializationRoot,
		FanInTranscriptSHA256:            fanInRoot,
		BlockCommitmentRootSHA256:        commitmentRoot,
		BlockReceiptRootSHA256:           blockReceiptRoot,
		AccumulatorRoot:                  accumulator.AccumulatorRoot,
		ExecutionReceiptPairSHA256:       executionPair.ExecutionReceiptPairSHA256,
		FinalReceiptSetSeal:              hex.EncodeToString(finalReceiptSeal[:]),
		CheckpointEvidenceSeal:           hex.EncodeToString(checkpointSeal[:]),
		Phase15ExecutionTranscriptSHA256: evidence.Phase15ExecutionTranscriptSHA256,
		FinalCheckpointTranscriptSHA256:  evidence.FinalCheckpointTranscriptSHA256,
		WorkerTranscriptSHA256:           evidence.WorkerTranscriptSHA256,
		PostExecutionRootSHA256:          hex.EncodeToString(postRoot[:]),
		CustodianCount:                   len(ctx.CustodianPeers),
		ComputePeers:                     append([]string(nil), ctx.ComputePeers...),
		FanInExecuted:                    true,
		ExactAllKValidityInsideGC:        true,
		ConsensusComparedInsideGC:        true,
		FullTupleMaskInsideGC:            true,
		ExecutionValidSealed:             true,
		ExecutionValidityOpened:          false,
		PatientDependentDigestsExposed:   false,
		ProtectedDataE2EVerified:         false,
		OpeningAuthorized:                false,
		OpeningsPerformed:                0,
		DPReleaseStatus:                  "blocked_until_joint_dp_release_consumes_hidden_execution_validity_v1",
		RemainingBlockers: []string{
			"registered_r_dsi_lifecycle_and_real_multiprocess_e2e_unavailable_v1",
			"joint_dp_release_consuming_hidden_execution_validity_v1",
		},
		ProductionReady: false,
		verified:        true,
	}
	preimage, err := formalGLMPhase19PostTokenPreimage(result)
	if err != nil {
		return zero, err
	}
	tokenDigest := sha256.Sum256(append(
		[]byte(formalGLMPhase19PostTokenDomain+"|"), preimage...))
	result.TokenSHA256 = hex.EncodeToString(tokenDigest[:])
	result.seal = formalGLMPhase19MAC(backendKey,
		formalGLMPhase19PostTokenDomain+"/seal", tokenDigest[:])
	return result, nil
}

func formalGLMPhase19VerifyPostExecutionToken(
	token formalGLMPhase19PostExecutionToken, backendKey [32]byte) error {
	if !token.verified || token.Version != formalGLMPhase19PostTokenVersion ||
		!formalGLMIsSHA256(token.TokenSHA256) ||
		!formalGLMIsSHA256(token.PostExecutionRootSHA256) ||
		!token.FanInExecuted || !token.ExactAllKValidityInsideGC ||
		!token.ConsensusComparedInsideGC || !token.FullTupleMaskInsideGC ||
		!token.ExecutionValidSealed || token.ExecutionValidityOpened ||
		token.PatientDependentDigestsExposed || token.ProtectedDataE2EVerified ||
		token.OpeningAuthorized || token.OpeningsPerformed != 0 ||
		token.ProductionReady || len(token.RemainingBlockers) != 2 ||
		!formalGLMPhase19KeyValid(backendKey) {
		return fmt.Errorf("formal-glm: invalid Phase-1.9 post-execution token")
	}
	preimage, err := formalGLMPhase19PostTokenPreimage(token)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase19PostTokenDomain+"|"), preimage...))
	wantSeal := formalGLMPhase19MAC(backendKey,
		formalGLMPhase19PostTokenDomain+"/seal", digest[:])
	if token.TokenSHA256 != hex.EncodeToString(digest[:]) ||
		!hmac.Equal(wantSeal[:], token.seal[:]) {
		return fmt.Errorf("formal-glm: post-execution token authentication failed")
	}
	return nil
}
