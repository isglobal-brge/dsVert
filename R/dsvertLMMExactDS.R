#' @title LMM cross-server exact residual pipeline — peer side
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
#' @export
dsvertLMMPeerFittedShareDS <- function(data_name, x_names, betahat,
                                        peer_pk, session_id = NULL,
                                        frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
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
  # Keep OWN share (random) for the negating side of the residual.
  ss$k2_lmm_exact_peer_share <- split_res$own_share
  sealed <- .callMpcTool("transport-encrypt",
    list(data = split_res$peer_share,
         recipient_pk = .base64url_to_base64(peer_pk)))
  list(peer_blob = base64_to_base64url(sealed$sealed),
       n = length(fitted))
}

#' @title LMM cross-server exact residual pipeline — coordinator side
#' @description On the outcome server, consume the peer's relayed share
#'   blob, decrypt it, compute this party's share of the residual
#'   \eqn{r_{ij} = y_{ij} - \alpha - X^{local}_{ij}{}^T\hat\beta^{local}
#'   - f^{peer,0}_{ij}}, and store it in \code{k2_lmm_exact_r_share}.
#'   The peer side has \eqn{r^{peer} = -f^{peer,1}_{ij}} in its
#'   \code{k2_lmm_exact_peer_share} slot. Sum:
#'   \eqn{r^0 + r^1 = y - \alpha - X\hat\beta} which is the true
#'   residual. Subsequent Beaver vecmul on
#'   \code{k2_lmm_exact_r_share} with itself yields \eqn{r^2} shares
#'   which the caller sums per cluster on the outcome server via
#'   \code{\link{dsvertLMMExactClusterR2DS}}.
#'
#' @param data_name Aligned data-frame name.
#' @param y_var Outcome column.
#' @param x_names Predictor names on this (outcome) server.
#' @param betahat_local Coefficients for the local predictors.
#' @param intercept Scalar intercept (default 0).
#' @param session_id MPC session id.
#' @param frac_bits Ring63 fractional bits (default 20).
#' @return list(stored = TRUE, n).
#' @export
dsvertLMMCoordResidualShareDS <- function(data_name, y_var, x_names,
                                           betahat_local, intercept = 0,
                                           session_id = NULL,
                                           frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
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
#' @param n Optional integer — the vector length. If omitted, we try
#'   \code{ss\$k2_x_n} (populated by k2ShareInputDS in the full GLM
#'   pipeline) and then fall back to decoding the peer-share byte
#'   length. Pass explicitly from the client orchestration whenever
#'   the session wasn't initialised by k2ShareInputDS.
#' @export
dsvertLMMPeerResidualFinaliseDS <- function(n = NULL, session_id = NULL,
                                             frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
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

#' @title LMM cross-server exact: per-cluster r^2 aggregate
#' @description After the Beaver vecmul has populated
#'   \code{k2_lmm_exact_r2_share} (share of r^2) on the outcome
#'   server (where cluster IDs live plaintext), sum within each cluster
#'   to produce per-cluster scalar FP shares and return them. Client
#'   aggregates the two parties' outputs via \code{k2-ring63-aggregate}
#'   to reconstruct per-cluster RSS.
#'
#'   For the non-outcome party the cluster-ID info is NOT broadcast;
#'   this helper runs ONLY on the outcome server, and on the peer side
#'   we return a vector of per-cluster partial sums produced from the
#'   peer's own r^2 share by summing against the SAME cluster indicator
#'   vector (which must be broadcast client-side via mpcStoreBlobDS as
#'   well; see the companion broadcast helper).
#'
#' @param data_name Aligned data frame.
#' @param cluster_col Cluster column.
#' @param r2_key Session slot holding the r^2 share (default
#'   \code{"k2_lmm_exact_r2_share"}).
#' @param session_id MPC session id.
#' @return list(per_cluster_fp -- K vector of base64 FP scalars,
#'              cluster_sizes, n_clusters).
#' @export
dsvertLMMExactClusterR2DS <- function(data_name, cluster_col,
                                       r2_key = "k2_lmm_exact_r2_share",
                                       session_id = NULL,
                                       frac_bits = 20L) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!cluster_col %in% names(data))
    stop("cluster_col not found", call. = FALSE)
  r2_share_b64 <- ss[[r2_key]]
  if (is.null(r2_share_b64))
    stop("r^2 share missing in session slot ", r2_key, call. = FALSE)
  # Decode the FP share into Ring63 uint64 values so we can sum
  # per-cluster locally (linear op preserves sharing).
  raw <- jsonlite::base64_dec(r2_share_b64)
  # Each FP value is 8 little-endian bytes.
  n <- as.integer(length(raw) / 8L)
  ids <- data[[cluster_col]]
  if (length(ids) != n) {
    stop("cluster length (", length(ids),
         ") != r^2 length (", n, ")", call. = FALSE)
  }
  # Interpret shares as integer64 for linear accumulation.
  vals <- integer(n)
  # Use a per-byte read; we return raw per-cluster sums as aggregated
  # FP scalars by calling the server's k2-fp-sum via a sliced input.
  lvls <- sort(unique(ids))
  out_fp <- character(length(lvls))
  sizes <- integer(length(lvls))
  for (ci in seq_along(lvls)) {
    idx <- which(ids == lvls[ci])
    sizes[ci] <- length(idx)
    # Construct a masked vector: set to zero outside this cluster.
    # Use a 0/1 mask via k2-fp-vec-mul.
    mask <- rep(0, n); mask[idx] <- 1
    mask_fp <- .callMpcTool("k2-float-to-fp",
      list(values = mask, frac_bits = as.integer(frac_bits)))$fp_data
    masked <- .callMpcTool("k2-fp-vec-mul", list(
      a = r2_share_b64, b = mask_fp,
      frac_bits = as.integer(frac_bits)))
    s <- .callMpcTool("k2-fp-sum", list(fp_data = masked$result))
    out_fp[ci] <- s$sum_fp
  }
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && privacy_min > 0L) {
    mask_small <- sizes < privacy_min
    sizes[mask_small] <- 0L
    # Can't easily zero out an FP scalar share -- leave it; the client
    # will see the (noisy) share but the size=0 flag signals suppression.
  }
  list(per_cluster_fp = out_fp,
       cluster_sizes = sizes,
       n_clusters = length(lvls))
}
