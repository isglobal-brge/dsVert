#' @title LMM cross-server exact residual pipeline -- peer side
#' @description On the non-outcome server (which holds some of the
#'   predictors), compute the per-patient linear-predictor contribution
#'   \eqn{f^{peer}_{ij} = x^{peer}_{ij}{}^T \hat\beta^{peer}} in
#'   plaintext (both \eqn{x^{peer}} and \eqn{\hat\beta^{peer}} live on
#'   this server), split it into two additive Ring63 shares
#'   \eqn{f^{peer} = f^0 + f^1}, keep \eqn{f^1} in the session under
#'   \code{k2_lmm_exact_peer_share} for the Beaver r^2 step, and return
#'   the complementary share \eqn{f^0} transport-encrypted to the
#'   outcome server's pk so the caller can relay it via
#'   \code{mpcStoreBlobDS}.
#'
#'   Inter-party leakage: none beyond existing (the outcome server
#'   already learns an additive share of \eqn{f^{peer}_{ij}}, which is
#'   random and reveals nothing on its own; reconstruction requires
#'   combining with \eqn{f^1} on the peer).
#'
#' @param data_name Aligned data-frame name.
#' @param x_names Predictor names on THIS (peer) server.
#' @param betahat Plaintext coefficient vector matching \code{x_names}.
#' @param peer_pk Transport pk of the outcome server (base64url).
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits (default 20).
#' @return list(peer_blob, n) -- peer_blob is the transport-sealed
#'   share destined for the outcome server.
dsvertLMMPeerFittedShareDS <- function(data_name, x_names, betahat,
                                        peer_pk, session_id = NULL,
                                        frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  .k2_enforce_K(.S(session_id), 2L, "dsvertLMMPeerFittedShareDS")
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  missing_x <- setdiff(x_names, names(data))
  if (length(missing_x) > 0L) {
    stop("x_names not local to this server: ",
         paste(missing_x, collapse = ","), call. = FALSE)
  }
  if (length(x_names) != length(betahat)) {
    stop("length(x_names) must equal length(betahat)", call. = FALSE)
  }
  X <- as.matrix(data[, x_names, drop = FALSE])
  fitted <- drop(X %*% as.numeric(betahat))
  fp <- .callMpcTool("k2-float-to-fp",
    list(values = as.numeric(fitted), frac_bits = as.integer(frac_bits)))$fp_data
  split_res <- .callMpcTool("k2-split-fp-share", list(data_fp = fp))
  ss <- .S(session_id)
  .dsvert_validate_recipient_pk(peer_pk, ss, "peer")
  # Keep OWN share (random) for the negating side of the residual.
  ss$k2_lmm_exact_peer_share <- split_res$own_share
  sealed <- .callMpcTool("transport-encrypt",
    list(data = split_res$peer_share,
         recipient_pk = .base64url_to_base64(peer_pk)))
  list(peer_blob = base64_to_base64url(sealed$sealed),
       n = length(fitted))
}

#' @title LMM cross-server exact residual pipeline -- coordinator side
#' @description On the outcome server, consume the peer's relayed share
#'   blob, decrypt it, compute this party's share of the residual
#'   \eqn{r_{ij} = y_{ij} - \alpha - X^{local}_{ij}{}^T\hat\beta^{local}
#'   - f^{peer,0}_{ij}}, and store it in \code{k2_lmm_exact_r_share}.
#'   The peer side has \eqn{r^{peer} = -f^{peer,1}_{ij}} in its
#'   \code{k2_lmm_exact_peer_share} slot. Sum:
#'   \eqn{r^0 + r^1 = y - \alpha - X\hat\beta} which is the true
#'   residual. Subsequent Beaver vecmul on
#'   \code{k2_lmm_exact_r_share} with itself yields \eqn{r^2} shares
#'   which the caller sums per cluster from the two share holders via
#'   \code{\link{dsvertLMMPerClusterSumDS}}.
#'
#' @param data_name Aligned data-frame name.
#' @param y_var Outcome column.
#' @param x_names Predictor names on this (outcome) server.
#' @param betahat_local Coefficients for the local predictors.
#' @param intercept Scalar intercept (default 0).
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits (default 20).
#' @return list(stored = TRUE, n).
dsvertLMMCoordResidualShareDS <- function(data_name, y_var, x_names,
                                           betahat_local, intercept = 0,
                                           session_id = NULL,
                                           frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertLMMCoordResidualShareDS")
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!y_var %in% names(data)) stop("y_var not found", call. = FALSE)
  missing_x <- setdiff(x_names, names(data))
  if (length(missing_x) > 0L) {
    stop("x_names not local to this server: ",
         paste(missing_x, collapse = ","), call. = FALSE)
  }
  y <- as.numeric(data[[y_var]])
  X <- as.matrix(data[, x_names, drop = FALSE])
  fitted_local <- as.numeric(intercept) +
                    drop(X %*% as.numeric(betahat_local))
  r0 <- y - fitted_local  # partial residual (plaintext on outcome)
  # Receive peer's share of fitted_peer.
  blob <- .blob_consume("k2_lmm_exact_peer_blob", ss)
  if (is.null(blob)) {
    stop("peer fitted-share blob missing; relay via mpcStoreBlobDS",
         call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("transport_sk missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
    list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  peer_share_fp <- dec$data
  # Convert r0 to FP and subtract peer_share (local on shares).
  r0_fp <- .callMpcTool("k2-float-to-fp",
    list(values = r0, frac_bits = as.integer(frac_bits)))$fp_data
  r_share <- .callMpcTool("k2-fp-sub", list(
    a = r0_fp, b = peer_share_fp,
    frac_bits = as.integer(frac_bits)))
  ss$k2_lmm_exact_r_share <- r_share$result
  list(stored = TRUE, n = length(y))
}

#' @title LMM cross-server exact: peer-side residual slot finaliser
#' @description On the peer (non-outcome) server, the residual share is
#'   the NEGATIVE of the share we kept from
#'   \code{dsvertLMMPeerFittedShareDS} (because the total residual
#'   equals y - alpha - X_local * beta_local - f_peer, so peer
#'   contributes -f^peer_share_kept to the sum). This helper moves the
#'   negated value into the canonical \code{k2_lmm_exact_r_share} slot
#'   so the subsequent Beaver vecmul picks it up automatically.
#' @param n Optional integer -- the vector length. If omitted, we try
#'   \code{ss\$k2_x_n} (populated by k2ShareInputDS in the full GLM
#'   pipeline) and then fall back to decoding the peer-share byte
#'   length. Pass explicitly from the client orchestration whenever
#'   the session wasn't initialised by k2ShareInputDS.
#' @param session_id Character. Active MPC session identifier.
#' @param frac_bits Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50 for Ring127).
dsvertLMMPeerResidualFinaliseDS <- function(n = NULL, session_id = NULL,
                                             frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertLMMPeerResidualFinaliseDS")
  if (is.null(ss$k2_lmm_exact_peer_share)) {
    stop("peer share not registered; run dsvertLMMPeerFittedShareDS first",
         call. = FALSE)
  }
  # Determine length n: explicit arg wins, then session k2_x_n, then
  # infer from the base64-decoded byte length of the peer share.
  if (is.null(n) || !is.finite(n) || n <= 0) {
    n <- if (!is.null(ss$k2_x_n)) ss$k2_x_n else NULL
  }
  if (is.null(n) || !is.finite(n) || n <= 0) {
    raw_len <- length(jsonlite::base64_dec(ss$k2_lmm_exact_peer_share))
    n <- as.integer(raw_len / 8L)
  }
  if (is.null(n) || !is.finite(n) || n <= 0) {
    stop("peer-share length undetectable; pass n= explicitly",
         call. = FALSE)
  }
  n <- as.integer(n)
  zeros_fp <- .callMpcTool("k2-float-to-fp",
    list(values = rep(0, n), frac_bits = as.integer(frac_bits)))$fp_data
  neg <- .callMpcTool("k2-fp-sub", list(
    a = zeros_fp, b = ss$k2_lmm_exact_peer_share,
    frac_bits = as.integer(frac_bits)))
  ss$k2_lmm_exact_r_share <- neg$result
  # Cache n for subsequent helpers.
  ss$k2_x_n <- n
  list(stored = TRUE, n = n)
}
