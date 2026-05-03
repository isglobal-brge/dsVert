#' @title Store a public intercept column as additive FP shares
#' @description Writes an n-vector of additive shares for the public
#'   intercept column. Party 0 receives the all-ones fixed-point vector and
#'   party 1 receives zeros, so the reconstructed vector is exactly one while
#'   no patient-level private value is introduced.
#' @param output_key Session slot to receive the column share.
#' @param n Vector length. Defaults to the active GLM session row count.
#' @param is_party0 Logical; TRUE for the first DCF party.
#' @param session_id Active MPC session identifier.
#' @param frac_bits Fixed-point fractional bits.
#' @param ring Integer 63 or 127.
#' @return list(stored, output_key, n).
#' @export
dsvertGEEInterceptShareDS <- function(output_key = "gee_x_col_0",
                                      n = NULL,
                                      is_party0 = FALSE,
                                      session_id = NULL,
                                      frac_bits = 20L,
                                      ring = 63L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (!is.character(output_key) || length(output_key) != 1L ||
      !nzchar(output_key)) {
    stop("output_key must be a non-empty string", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(n)) n <- ss$k2_x_n
  n <- as.integer(n)
  if (!is.finite(n) || n < 1L) {
    stop("n must be a positive integer", call. = FALSE)
  }
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  if (ring == 127L) frac_bits <- 50L
  values <- if (isTRUE(is_party0)) rep(1, n) else rep(0, n)
  fp <- .callMpcTool("k2-float-to-fp", list(
    values = values, frac_bits = as.integer(frac_bits), ring = ring_tag))
  ss[[output_key]] <- fp$fp_data
  list(stored = TRUE, output_key = output_key, n = n)
}

#' @title Restore GLM feature-share dimensions for GEE follow-on rounds
#' @description The GLM deviance pass temporarily changes the active
#'   \code{k2_x_*} shape to an n-by-1 residual vector. Follow-on sandwich
#'   rounds need the original feature-share dimensions so
#'   \code{k2ComputeEtaShareDS()} can rebuild the full design share without
#'   rerunning PSI or input sharing.
#' @param p_own Number of feature columns owned by this DCF party.
#' @param p_peer Number of feature columns held in the peer-share matrix.
#' @param session_id Active MPC session identifier.
#' @return list(stored, p_own, p_peer).
#' @export
dsvertGEERestoreFeatureShapeDS <- function(p_own, p_peer,
                                           session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  p_own <- as.integer(p_own)
  p_peer <- as.integer(p_peer)
  if (!is.finite(p_own) || p_own < 0L ||
      !is.finite(p_peer) || p_peer < 0L) {
    stop("p_own and p_peer must be non-negative integers", call. = FALSE)
  }
  ss$k2_x_p <- p_own
  ss$k2_peer_p <- p_peer
  list(stored = TRUE, p_own = p_own, p_peer = p_peer)
}
