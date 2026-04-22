#' @title Prepare softmax-gradient inputs by copying shares into the
#'   canonical \code{secure_mu_share} / \code{k2_y_share_fp} slots
#' @description Used by \code{ds.vertMultinomJointNewton} to reuse the
#'   existing \code{glmRing63GenGradTriplesDS} + \code{k2GradientR1DS}
#'   + \code{k2GradientR2DS} matvec pipeline on a per-class residual
#'   share already computed via \code{dsvertComputeResidualShareDS}.
#'
#'   The gradient pipeline computes \eqn{X^\top (\mu - y)} internally,
#'   so this helper:
#'   \itemize{
#'     \item Sets \code{secure_mu_share = 0} (zero share).
#'     \item Sets \code{k2_y_share_fp = -residual_share} so the
#'           pipeline's \eqn{\mu - y = 0 - (-r) = r} gives the right
#'           direction without further sign flipping.
#'   }
#'
#' @param residual_key Session slot holding a Ring127 residual share.
#' @param is_outcome_server Whether this server holds the outcome.
#' @param n Length of residual vector.
#' @param session_id MPC session id.
#' @return \code{list(stored = TRUE)}.
#' @export
dsvertPrepareMultinomGradDS <- function(residual_key, is_outcome_server,
                                          n, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (is.null(residual_key) || !nzchar(residual_key))
    stop("residual_key required", call. = FALSE)
  ss <- .S(session_id)
  r_share <- ss[[residual_key]]
  if (is.null(r_share) || !nzchar(r_share))
    stop("residual slot '", residual_key, "' is empty", call. = FALSE)

  n_int <- as.integer(n)
  # Zero mu share: same length as residual, Ring127 FP zeros
  zero_fp <- .callMpcTool("k2-float-to-fp", list(
    values = rep(0, n_int), frac_bits = 50L, ring = "ring127"))$fp_data
  ss$secure_mu_share <- zero_fp

  # y_share = -r_share (negation via affine combine)
  neg_r <- .callMpcTool("k2-ring127-affine-combine", list(
    a = r_share, b = "", sign_a = -1L, sign_b = 0L,
    public_const = "", is_party0 = isTRUE(is_outcome_server),
    frac_bits = 50L, n = n_int))$result
  ss$k2_y_share_fp <- neg_r
  list(stored = TRUE, residual_key = residual_key, n = n_int)
}

#' @title Sum K-1 exp(eta_k) shares + party-0 constant 1 → denominator share
#' @description Computes the softmax denominator share \code{D = 1 + Σ_k exp(η_k)}
#'   via K-1 sequential \code{k2-ring127-affine-combine} calls. Party 0 also
#'   adds the constant 1 at the first step; party 1 does not (additive
#'   share convention).
#'
#' @param exp_eta_keys Character vector of session slots holding the
#'   per-class \code{exp(η_k)} shares.
#' @param output_key Session slot to store the summed D share.
#' @param is_party0 Whether this server is party 0 (adds the +1 constant).
#' @param n Length of each share.
#' @param session_id MPC session id.
#' @export
dsvertSoftmaxDenominatorDS <- function(exp_eta_keys, output_key,
                                        is_party0 = FALSE, n,
                                        session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (!is.character(exp_eta_keys) || length(exp_eta_keys) < 1L)
    stop("exp_eta_keys must be a non-empty character vector", call. = FALSE)
  ss <- .S(session_id)
  n_int <- as.integer(n)

  # FP(1.0) constant
  one_fp <- .callMpcTool("k2-float-to-fp", list(
    values = 1.0, frac_bits = 50L, ring = "ring127"))$fp_data

  # Start: tmp_sum = first exp(eta) share + (constant 1 on party 0)
  first_share <- ss[[exp_eta_keys[1L]]]
  if (is.null(first_share) || !nzchar(first_share))
    stop("slot '", exp_eta_keys[1L], "' is empty", call. = FALSE)
  running <- .callMpcTool("k2-ring127-affine-combine", list(
    a = first_share, b = "",
    sign_a = 1L, sign_b = 0L,
    public_const = one_fp,   # +1 on party 0 only
    is_party0 = isTRUE(is_party0),
    frac_bits = 50L, n = n_int))$result

  # Accumulate the rest
  if (length(exp_eta_keys) >= 2L) {
    for (k in exp_eta_keys[-1L]) {
      slot_k <- ss[[k]]
      if (is.null(slot_k) || !nzchar(slot_k))
        stop("slot '", k, "' is empty", call. = FALSE)
      running <- .callMpcTool("k2-ring127-affine-combine", list(
        a = running, b = slot_k,
        sign_a = 1L, sign_b = 1L,
        public_const = "",
        is_party0 = isTRUE(is_party0),
        frac_bits = 50L, n = n_int))$result
    }
  }

  ss[[output_key]] <- running
  list(stored = TRUE, output_key = output_key, n = n_int)
}
