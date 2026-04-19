#' @title Cox Path B: iterative Newton with Fisher(beta_k) via Beaver
#' @description
#'   Server-side helpers for the iterative Newton refinement path that
#'   computes the observed Fisher information I(beta_k) at the current
#'   iterate using ONLY primitives that already exist in the Ring63 +
#'   Beaver + DCF toolkit. No new Go primitives.
#'
#'   Strategy at each iteration k:
#'     1. .cox_score_round(beta_k) has populated session state with shares
#'        of mu = exp(X beta_k), G, S, 1/S, mu*G (via existing DCF + Beaver
#'        infrastructure).
#'     2. For each column j: Beaver(X_j_share * mu_share) -> share of
#'        X_j*mu per row. Then local reverse cumsum (strata-aware) gives
#'        share of T_j(i) = sum_{k>=i} X_kj mu_k.
#'     3. One Beaver((1/S) * (1/S)) gives share of 1/S^2 per row.
#'     4. Per Fisher pair (j, k):
#'        Term1 = sum_m X_mj X_mk (mu G)_m
#'          = Beaver(X_j * X_k)  ->  Beaver(result * mu*G)  ->  sum
#'        Term2 = sum_i delta_i T_j(i) T_k(i) / S(t_i)^2
#'          = Beaver(T_j * T_k)  ->  Beaver(result * 1/S^2)  ->
#'            multiply by delta (plaintext at both)  ->  sum
#'        Fisher_jk = Term1 - Term2 (scalar aggregate revealed to client).
#'
#'   Bias cancellation: both grad(beta_k) and Fisher(beta_k) are
#'   computed by the same DCF-spline + Beaver pipeline, so the ~1-3%
#'   multiplicative bias per spline evaluation appears in BOTH numerator
#'   and denominator of the Newton step, cancelling to leading order
#'   (Greenland 1987, Therneau & Grambsch 2000 Sect 3.2).
#'
#'   Disclosure per iter (same tier as Newton one-step): client sees
#'   the p-vector grad(beta_k) and the p*p Fisher(beta_k). Max 5 iters
#'   capped at client.
#' @name cox-path-b
NULL

#' @title Generic strata-aware cumulative sum on an FP share vector
#' @description
#'   Applies k2-fp-cumsum to the share at `input_key` (optionally with
#'   strata from ss$k2_cox_strata), storing the result at `output_key`.
#'   Local on shares: cumsum(share_A) + cumsum(share_B) = cumsum(share_A + share_B)
#'   by linearity of cumulative sum.
#' @param input_key Session slot holding the input FP share vector.
#' @param output_key Session slot to receive the cumsum FP share.
#' @param reverse Logical. TRUE = right-to-left cumulative sum (used for
#'   risk-set weighted averages in Cox); FALSE = left-to-right.
#' @param session_id MPC session id.
#' @return list(stored = TRUE, output_key).
#' @export
dsvertCoxPathBCumsumDS <- function(input_key, output_key,
                                    reverse = TRUE, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  input_share <- ss[[input_key]]
  if (is.null(input_share)) {
    stop("input_key '", input_key, "' not in session", call. = FALSE)
  }
  n <- as.integer(ss$k2_x_n)
  args <- list(a = input_share, reverse = isTRUE(reverse),
               n = n, frac_bits = 20L)
  if (!is.null(ss$k2_cox_strata) && length(ss$k2_cox_strata) > 0L) {
    args$strata <- as.integer(ss$k2_cox_strata)
  }
  res <- .callMpcTool("k2-fp-cumsum", args)
  ss[[output_key]] <- res$result
  list(stored = TRUE, output_key = output_key)
}

#' @title Compute scalar share of Σ_i w_i * share(i) where w is plaintext at both parties
#' @description
#'   Multiplies share at `input_key` element-wise by plaintext vector at
#'   `weight_key` (plaintext means both parties hold identical bytes —
#'   e.g. k2_cox_delta_fp or cox_n_W1_fp). Uses k2-fp-vec-mul (local on
#'   share × plaintext) then k2-fp-sum to produce a scalar share.
#'   Used for the "× δ" step in Fisher term 2 aggregation.
#' @param input_key Session slot with FP share vector (e.g. the result of
#'   a Beaver product left over at cox_pb_<...>_fp).
#' @param weight_key Session slot with plaintext FP weight vector
#'   (e.g. "k2_cox_delta_fp"). Pass NULL to skip the weight step.
#' @param session_id MPC session id.
#' @return list(scalar_share_fp = 8-byte base64).
#' @export
dsvertCoxPathBScalarDS <- function(input_key, weight_key = NULL,
                                    session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  x <- ss[[input_key]]
  if (is.null(x)) {
    stop("input_key '", input_key, "' not in session", call. = FALSE)
  }
  z <- x
  if (!is.null(weight_key) && nzchar(weight_key)) {
    w <- ss[[weight_key]]
    if (is.null(w)) {
      stop("weight_key '", weight_key, "' not in session", call. = FALSE)
    }
    z <- .callMpcTool("k2-fp-vec-mul", list(
      a = x, b = w, frac_bits = 20L))$result
  }
  s <- .callMpcTool("k2-fp-sum", list(fp_data = z))
  list(scalar_share_fp = s$sum_fp)
}

#' @title Copy a session slot to another slot (alias helper for the Beaver plumbing)
#' @param source_key,target_key session slot names.
#' @param session_id MPC session id.
#' @return list(copied = TRUE).
#' @export
dsvertCoxPathBCopyDS <- function(source_key, target_key, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  v <- ss[[source_key]]
  if (is.null(v)) {
    stop("source_key '", source_key, "' missing", call. = FALSE)
  }
  ss[[target_key]] <- v
  list(copied = TRUE, target_key = target_key)
}
