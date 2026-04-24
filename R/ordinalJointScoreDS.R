#' @title Ordinal PO per-patient score-element routing (stub skeleton)
#' @description Outcome server reads patient-level indicator columns
#'   (\code{indicator_template \%\% class_name}), routes per-class
#'   share contributions based on which ordinal class each patient
#'   belongs to, and writes a share of the aggregate per-patient
#'   score term T_i to \code{output_key} for downstream Beaver matvec
#'   \eqn{X^\top T}.
#'
#' @details
#'   Proportional-odds joint score per McCullagh 1980 *JRSS B* 42:109-142
#'   §2.5 equation (2.5):
#'     \deqn{S(\beta) = \sum_i \left[ \sum_k I(y_i = k) \cdot T_{ik} \right] x_i}
#'   with
#'     \deqn{T_{ik} = \frac{f_{k-1}(\eta_i)}{F_k - F_{k-1}} -
#'           \frac{f_k(\eta_i)}{F_{k+1} - F_k}}
#'   where \eqn{f_k = F_k (1 - F_k)} and \eqn{F_k = \sigma(\theta_k -
#'   \eta_i)}, by convention \eqn{F_0 \equiv 0} and \eqn{F_K \equiv 1}.
#'
#' @section Implementation status (2026-04-24, AUDITORIA piece-by-piece):
#'   STUB — interface shipped, no-op body. Current code stores a zero
#'   share in \code{output_key} so the downstream orchestration (Beaver
#'   matvec) returns a trivial zero gradient. The client-side Newton in
#'   \code{ds.vertOrdinalJointNewton} continues to use its warm-Fisher
#'   fallback until the full body is wired.
#'
#'   Remaining piece-by-piece scope (each commit = one piece):
#'   \enumerate{
#'     \item Read indicator columns for each class from local data frame.
#'     \item For each patient, determine which class k they belong to.
#'     \item Compute \eqn{T_{ik}} share using session slots
#'       \code{f_keys}, \code{recipP_keys}. (\eqn{T_{i0}} and \eqn{T_{iK}}
#'       get boundary conventions.)
#'     \item Affine-combine class-specific shares into per-patient
#'       T_i share via indicator-masking (outcome server holds
#'       indicators in plaintext locally).
#'     \item Store T_i share in \code{output_key} session slot.
#'     \item Client-side: invoke existing
#'       \code{glmRing63GenGradTriplesDS} + \code{k2GradientR[12]DS}
#'       pipeline on \code{output_key} for the final X^T T matvec.
#'   }
#'
#'   All the MPC primitives needed (k2Ring127AffineCombineDS,
#'   k2Ring127LocalScaleDS, k2BeaverVecmul*) already exist. Scope is
#'   routing + indicator logic, not new cryptographic machinery.
#'
#' @param data_name Character. Local data frame name on outcome server.
#' @param indicator_template sprintf template for indicator column
#'   names (e.g., "\%s_leq" for cumulative indicators).
#' @param f_keys Character vector. Session slot keys holding share
#'   of \eqn{f_k = F_k (1 - F_k)} per patient, one per non-reference
#'   threshold.
#' @param recipP_keys Character vector. Session slot keys holding share
#'   of \eqn{1/(F_k - F_{k-1})} per patient (one per interior class).
#' @param output_key Character. Session slot to write per-patient
#'   T_i share.
#' @param n Integer. Number of patients.
#' @param is_outcome_server Logical. If FALSE, server contributes zero
#'   (only the outcome server holds indicators).
#' @param session_id MPC session id.
#' @return \code{list(stored = TRUE, stub = TRUE, n = <integer>)}.
#' @export
dsvertOrdinalPatientDiffsDS <- function(data_name = NULL,
                                         indicator_template = "%s_leq",
                                         f_keys = NULL,
                                         recipP_keys = NULL,
                                         output_key = NULL,
                                         n = NULL,
                                         is_outcome_server = FALSE,
                                         session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (is.null(output_key) || !nzchar(output_key))
    stop("output_key required", call. = FALSE)
  n_int <- as.integer(n)
  if (!is.finite(n_int) || n_int <= 0L)
    stop("n must be a positive integer", call. = FALSE)

  ss <- .S(session_id)

  # ===== STUB BODY =====
  # Piece (1)-(5) TODO: read indicator columns, route per-patient
  # shares, compute T_i via affine combines of f_k and recipP_k shares.
  # Placeholder: write a zero-valued share (all servers contribute
  # zero → downstream Beaver matvec X^T T yields zero gradient,
  # making the joint Newton step a no-op — exactly the current
  # warm-Fisher fallback behaviour). Safe, green, auditable baseline.
  #
  # Share format: Ring127 Uint128 (16 bytes per FP value) to match
  # the existing f_keys / recipP_keys pipeline (fracBits=50).
  zero_flat <- rep(0, n_int)
  fp <- .callMpcTool("k2-float-to-fp",
                      list(values = zero_flat, frac_bits = 50L,
                           ring = "ring127"))$fp_data
  # Both parties get the same "zero share" — sum is zero on reveal;
  # for a true random-split share we'd use k2-split-fp-share, but for
  # a no-op stub a deterministic zero-share is fine and keeps the slot
  # type compatible with vecmul/matvec consumers.
  ss[[output_key]] <- fp
  # ===== END STUB =====

  list(stored = TRUE, stub = TRUE, n = n_int)
}
