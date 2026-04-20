#' @title Register Cox survival times and sort the cohort (outcome server, stratified)
#' @description Read the time and event columns from the outcome server,
#'   determine the ascending-time sort permutation locally, store the
#'   event indicator delta as a plaintext FP vector for subsequent
#'   Cox-gradient primitives, and return an encrypted blob (containing
#'   the permutation and the delta vector) destined for the DCF peer so
#'   both parties can align their shares with the sorted cohort.
#'
#'   Cox reformulated gradient:
#'     grad = sum_{j: delta_j = 1} x_j  -  sum_j x_j exp(eta_j) G_j,
#'   where G_j = sum_{i: delta_i = 1, t_i <= t_j} 1 / S(t_i) and
#'   S(t_i) = sum_{k: t_k >= t_i} exp(eta_k). After sorting by ascending
#'   t, S(t_i) is the REVERSE cumsum of exp(eta) and G_j is a forward
#'   cumsum of delta / S. Both are local cumsums on secret shares
#'   (k2-fp-cumsum primitive), so no new Beaver rounds are introduced
#'   beyond the existing DCF exp + DCF reciprocal + triple-product steps.
#'
#'   Inter-server disclosure: the DCF peer learns the sort permutation
#'   (i.e., the RANK order of event times) and the event indicator.
#'   Absolute event times are not disclosed. This is a deliberate,
#'   documented leakage tier, same class as cluster-ID in LMM; see
#'   V2_PROGRESS.md disclosure table.
#'
#' @param data_name    Aligned data frame on this server.
#' @param time_column  Numeric time-to-event column (>= 0).
#' @param event_column Binary event indicator (1 = event, 0 = censored).
#' @param peer_pk      Transport X25519 public key of the DCF peer.
#' @param session_id   GLM session id.
#' @return list(peer_blob = <encrypted permutation + delta>, n = length)
#' @export
k2SetCoxTimesDS <- function(data_name, time_column, event_column,
                            peer_pk, session_id = NULL,
                            strata_column = NULL, ring = NULL) {
  if (!is.character(data_name) || length(data_name) != 1L ||
      !is.character(time_column) || length(time_column) != 1L ||
      !is.character(event_column) || length(event_column) != 1L) {
    stop("data_name, time_column, event_column must each be a single
          character string", call. = FALSE)
  }
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  for (v in c(time_column, event_column)) {
    if (!v %in% names(data)) {
      stop("Column '", v, "' not found in '", data_name, "'",
           call. = FALSE)
    }
  }
  t_vec <- data[[time_column]]
  d_vec <- data[[event_column]]
  if (!is.numeric(t_vec) || !is.numeric(d_vec)) {
    stop("time and event columns must be numeric", call. = FALSE)
  }
  if (anyNA(t_vec) || anyNA(d_vec)) {
    stop("time / event columns contain NA on the aligned cohort",
         call. = FALSE)
  }
  if (any(t_vec < 0)) {
    stop("time column must be non-negative", call. = FALSE)
  }
  if (!all(d_vec %in% c(0, 1))) {
    stop("event column must be 0 or 1", call. = FALSE)
  }

  ss <- .S(session_id)
  n <- ss$k2_x_n
  if (!is.null(n) && length(t_vec) != n) {
    stop("time/event length (", length(t_vec),
         ") does not match aligned cohort size (", n, ")", call. = FALSE)
  }

  # Stratum handling: sort first by stratum id, then by ascending
  # event time within stratum, then events before censored on ties.
  strata_vec <- NULL
  if (!is.null(strata_column) && nzchar(strata_column)) {
    if (!strata_column %in% names(data)) {
      stop("strata_column '", strata_column, "' not found", call. = FALSE)
    }
    strata_vec <- as.integer(as.factor(data[[strata_column]]))
    if (anyNA(strata_vec)) {
      stop("strata column contains NA", call. = FALSE)
    }
  }
  if (is.null(strata_vec)) {
    ord <- order(t_vec, -d_vec)
  } else {
    ord <- order(strata_vec, t_vec, -d_vec)
  }
  d_sorted <- d_vec[ord]
  strata_sorted <- if (!is.null(strata_vec)) strata_vec[ord] else NULL

  # Ring selection (falls back to session-stored ring set by
  # k2ShareInputDS; defaults to 63 if neither caller nor session supplies).
  if (is.null(ring)) ring <- ss$k2_ring %||% 63L
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L
  # Encode delta_sorted as FP share-compatible vector (plaintext here,
  # peer will also hold it plaintext after decrypt).
  delta_fp <- .callMpcTool("k2-float-to-fp", list(
    values = as.numeric(d_sorted), frac_bits = frac_bits,
    ring = ring_tag))$fp_data
  ss$k2_cox_perm <- as.integer(ord)
  ss$k2_ring <- ring  # pin for downstream Cox ops
  ss$k2_cox_delta_fp <- delta_fp
  ss$k2_cox_n_events <- sum(d_vec)
  ss$k2_cox_strata <- if (!is.null(strata_sorted)) as.integer(strata_sorted) else NULL

  # Build peer blob: a small JSON payload with perm (ints) + delta_fp
  # (base64 FP vector) + optional strata, then encrypt via transport.
  payload <- list(perm = as.integer(ord), delta_fp = delta_fp,
                   strata = ss$k2_cox_strata,
                   n = length(t_vec))
  payload_json <- jsonlite::toJSON(payload, auto_unbox = TRUE)
  payload_b64 <- jsonlite::base64_enc(charToRaw(payload_json))

  # peer_pk arrives base64url (how glmRing63TransportInitDS emits it);
  # transport-encrypt expects standard base64 for recipient_pk.
  seal <- .callMpcTool("transport-encrypt", list(
    data = payload_b64,
    recipient_pk = .base64url_to_base64(peer_pk)))

  list(peer_blob = base64_to_base64url(seal$sealed),
       n = length(t_vec),
       n_events = sum(d_vec))
}

#' @title Receive Cox permutation and event indicator on the peer server
#' @description Consume the peer blob previously relayed via
#'   \code{mpcStoreBlobDS}, decrypt, and store the sort permutation +
#'   event indicator FP vector so the local Cox primitives can apply
#'   the same ordering to this server's X share.
#' @param session_id GLM session id.
#' @return list(stored = TRUE, n)
#' @export
k2ReceiveCoxMetaDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume("k2_peer_cox_meta", ss)
  if (is.null(blob)) {
    stop("No Cox metadata blob in session", call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) {
    stop("Transport secret key missing", call. = FALSE)
  }
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob),
    recipient_sk = tsk))
  payload_raw <- jsonlite::base64_dec(dec$data)
  payload <- jsonlite::fromJSON(rawToChar(payload_raw))

  ss$k2_cox_perm <- as.integer(payload$perm)
  ss$k2_cox_delta_fp <- payload$delta_fp
  ss$k2_cox_strata <- if (!is.null(payload$strata)) as.integer(payload$strata) else NULL
  list(stored = TRUE, n = length(ss$k2_cox_perm),
       stratified = !is.null(ss$k2_cox_strata))
}

#' @title Apply the Cox sort permutation to this server's X share
#' @description Reorder the cached X share (ss$k2_x_share_fp) and peer
#'   X share (ss$k2_peer_x_share_fp) in place so subsequent eta
#'   computations operate on the ascending-time ordering.
#' @param session_id GLM session id.
#' @return list(applied = TRUE)
#' @export
k2ApplyCoxPermutationDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  perm <- ss$k2_cox_perm
  if (is.null(perm)) {
    stop("No Cox permutation registered; call k2SetCoxTimesDS /
          k2ReceiveCoxMetaDS first", call. = FALSE)
  }
  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p

  # X is stored row-major (see k2InputSharingDS.R:23), so permuting
  # rows uses the cols= extension of k2-fp-permute-share: each output
  # row i is row perm[i] of the input. Shares are permuted
  # independently on each party; correctness follows because a public
  # permutation commutes with additive sharing.
  ring <- as.integer(ss$k2_ring %||% 63L)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L
  permute_rows <- function(flat_b64, p) {
    if (is.null(flat_b64) || !nzchar(flat_b64) || p <= 0L) return(flat_b64)
    .callMpcTool("k2-fp-permute-share", list(
      a = flat_b64, perm = as.integer(perm),
      n = as.integer(n), cols = as.integer(p),
      frac_bits = frac_bits, ring = ring_tag
    ))$result
  }
  if (!is.null(ss$k2_x_share_fp) && p_own > 0L) {
    ss$k2_x_share_fp <- permute_rows(ss$k2_x_share_fp, p_own)
  }
  if (!is.null(ss$k2_peer_x_share_fp) && !is.null(p_peer) && p_peer > 0L) {
    ss$k2_peer_x_share_fp <- permute_rows(ss$k2_peer_x_share_fp, p_peer)
  }
  # Also permute any pre-existing eta / mu / residual shares in case
  # the caller regenerates them without re-running the full pipeline.
  for (nm in c("k2_eta_share_fp", "secure_mu_share",
               "k2_y_share_fp", "k2_peer_y_share_fp",
               "k2_weights_share_fp")) {
    v <- ss[[nm]]
    if (!is.null(v) && is.character(v) && nzchar(v)) {
      ss[[nm]] <- permute_rows(v, 1L)
    }
  }
  ss$k2_cox_permuted <- TRUE
  list(applied = TRUE,
       perm_length = length(perm),
       n = n, p_own = p_own, p_peer = p_peer)
}

#' @title Cox-gradient second-term computation using reverse/forward cumsums
#' @description Given a secret-shared exp(eta) vector (ss$secure_mu_share
#'   after the wide-spline exp pass) already permuted to ascending-time
#'   order, compute shares of:
#'     S[i] = sum_{k >= i} exp(eta_k)       (reverse cumsum)
#'     G[j] = sum_{i: delta_i=1, i <= j} 1 / S[i]   (forward cumsum of
#'       delta*recip)
#'   and store S and G in the session as k2_cox_S_share_fp and
#'   k2_cox_G_share_fp. These are reused by the gradient reduction step
#'   that forms x_j * exp(eta_j) * G_j and sums over j.
#'
#'   NOTE: the reciprocal-on-shares step is delegated to the 4-phase
#'   k2-wide-spline-full protocol with family="reciprocal" (wired in
#'   commit 75f6883); callers orchestrate that phase first and pass the
#'   resulting 1/S share back in via k2StoreCoxRecipDS.
#'
#' @param session_id GLM session id.
#' @return list(S_length, G_length)
#' @export
k2CoxReverseCumsumSDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$secure_mu_share)) {
    stop("secure_mu_share not populated; run DCF exp pass first",
         call. = FALSE)
  }
  ring <- as.integer(ss$k2_ring %||% 63L)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L
  args <- list(
    a = ss$secure_mu_share, reverse = TRUE,
    n = as.integer(ss$k2_x_n), frac_bits = frac_bits,
    ring = ring_tag)
  if (!is.null(ss$k2_cox_strata)) {
    args$strata <- as.integer(ss$k2_cox_strata)
  }
  res <- .callMpcTool("k2-fp-cumsum", args)
  ss$k2_cox_S_share_fp <- res$result
  list(S_length = ss$k2_x_n,
       stratified = !is.null(ss$k2_cox_strata))
}

#' @title Compute the forward cumsum G_j = sum_{i<=j, delta=1} recip[i]
#' @param session_id GLM session id.
#' @return list(G_length)
#' @export
k2CoxForwardCumsumGDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$k2_cox_recip_S_share_fp)) {
    stop("1/S share not stored; run the wide-spline reciprocal phase
          first and store the result via k2StoreCoxRecipDS",
         call. = FALSE)
  }
  if (is.null(ss$k2_cox_delta_fp)) {
    stop("delta indicator not registered", call. = FALSE)
  }
  ring <- as.integer(ss$k2_ring %||% 63L)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L
  # Multiply delta element-wise into 1/S share (mask), then forward
  # cumsum. Both kernels in one call via the mask argument; strata
  # reset the accumulator at each boundary when stratified.
  args <- list(
    a = ss$k2_cox_recip_S_share_fp,
    mask = ss$k2_cox_delta_fp,
    reverse = FALSE,
    n = as.integer(ss$k2_x_n), frac_bits = frac_bits,
    ring = ring_tag)
  if (!is.null(ss$k2_cox_strata)) {
    args$strata <- as.integer(ss$k2_cox_strata)
  }
  res <- .callMpcTool("k2-fp-cumsum", args)
  ss$k2_cox_G_share_fp <- res$result
  list(G_length = ss$k2_x_n,
       stratified = !is.null(ss$k2_cox_strata))
}

#' @title Cache the reciprocal-of-S share returned by the DCF-reciprocal pass
#' @description If \code{recip_S_share_fp} is NULL, copy the current
#'   \code{ss$secure_mu_share} (which holds the 1/S share left over by
#'   the most recent wide-spline reciprocal pass) into
#'   \code{ss$k2_cox_recip_S_share_fp}. This is the usual in-session
#'   callers' path; passing an explicit vector is supported for tests.
#' @param recip_S_share_fp base64 FP vector (1/S share) or NULL.
#' @param session_id GLM session id.
#' @return list(stored = TRUE)
#' @export
k2StoreCoxRecipDS <- function(recip_S_share_fp = NULL, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(recip_S_share_fp) || !nzchar(recip_S_share_fp)) {
    if (is.null(ss$secure_mu_share)) {
      stop("no recip S share available (secure_mu_share empty)",
           call. = FALSE)
    }
    recip_S_share_fp <- ss$secure_mu_share
  }
  ss$k2_cox_recip_S_share_fp <- recip_S_share_fp
  list(stored = TRUE)
}

#' @title Prepare the DCF reciprocal phase for the Cox 1/S step
#' @description Copy \code{ss$k2_cox_S_share_fp} (the reverse cumsum of
#'   exp(eta) produced by \code{k2CoxReverseCumsumSDS}) into
#'   \code{ss$k2_eta_share_fp} so the standard 4-phase wide-spline
#'   pipeline (family = "reciprocal") operates on \eqn{S(t_i)} and
#'   produces shares of \eqn{1/S(t_i)} in \code{ss$secure_mu_share}.
#' @param session_id GLM session id.
#' @return list(prepared = TRUE, length = n)
#' @export
k2CoxPrepareRecipPhaseDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$k2_cox_S_share_fp)) {
    stop("k2_cox_S_share_fp not set; run k2CoxReverseCumsumSDS first",
         call. = FALSE)
  }
  ss$k2_eta_share_fp <- ss$k2_cox_S_share_fp
  list(prepared = TRUE, length = ss$k2_x_n)
}

#' @title Prepare the DCF log phase for the Cox S -> logS step
#' @description Copies \code{ss$k2_cox_S_share_fp} into
#'   \code{ss$k2_eta_share_fp} so a subsequent 4-phase wide-spline
#'   pass with \code{family = "log"} produces the share of \eqn{\log S(t_j)}
#'   in \code{ss$secure_mu_share}. Used by \code{ds.vertCox}'s
#'   post-convergence partial-log-likelihood aggregate.
#' @param session_id GLM session id.
#' @return list(prepared = TRUE, length).
#' @export
k2CoxPrepareLogSPhaseDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$k2_cox_S_share_fp)) {
    stop("k2_cox_S_share_fp not set; run k2CoxReverseCumsumSDS first",
         call. = FALSE)
  }
  ss$k2_eta_share_fp <- ss$k2_cox_S_share_fp
  list(prepared = TRUE, length = ss$k2_x_n)
}

#' @title Cox partial-log-likelihood aggregate
#' @description Return per-party scalar shares of the two summands of
#'   the Cox partial log-likelihood evaluated at the current
#'   \eqn{\hat\beta}:
#'     \eqn{T_1 = \sum_{j:\delta_j=1} \eta_j}
#'     \eqn{T_2 = \sum_{j:\delta_j=1} \log S(t_j)}
#'   where \code{eta} = \code{ss$k2_eta_share_fp} (cached from the last
#'   \code{k2ComputeEtaShareDS} call at \eqn{\hat\beta}) and
#'   \code{logS} = \code{ss$secure_mu_share} after the DCF log pass. The
#'   client reconstructs
#'     \eqn{\ell(\hat\beta) = (T_1^{(0)} + T_1^{(1)}) - (T_2^{(0)} + T_2^{(1)})}.
#' @param session_id GLM session id.
#' @return list(sum_delta_eta, sum_delta_logS).
#' @export
k2CoxPartialLogLikAggregateDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$k2_cox_delta_fp)) {
    stop("delta indicator missing", call. = FALSE)
  }
  if (is.null(ss$k2_eta_share_fp)) {
    stop("eta share missing", call. = FALSE)
  }
  if (is.null(ss$secure_mu_share)) {
    stop("log S share missing (run DCF log pass first)", call. = FALSE)
  }
  ring <- as.integer(ss$k2_ring %||% 63L)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L
  # Mask eta by delta and sum -> share of T_1.
  t1 <- .callMpcTool("k2-fp-vec-mul", list(
    a = ss$k2_eta_share_fp, b = ss$k2_cox_delta_fp,
    frac_bits = frac_bits, ring = ring_tag))
  t1_sum <- .callMpcTool("k2-fp-sum", list(
    fp_data = t1$result, ring = ring_tag))
  # Mask logS by delta and sum -> share of T_2.
  t2 <- .callMpcTool("k2-fp-vec-mul", list(
    a = ss$secure_mu_share, b = ss$k2_cox_delta_fp,
    frac_bits = frac_bits, ring = ring_tag))
  t2_sum <- .callMpcTool("k2-fp-sum", list(
    fp_data = t2$result, ring = ring_tag))
  # Return the raw scalar FP shares (one 8-byte base64 per party); the
  # client aggregates the two parties' shares via k2-ring63-aggregate.
  list(sum_delta_eta_fp = t1_sum$sum_fp,
       sum_delta_logS_fp = t2_sum$sum_fp)
}

#' @title Cox residual share (DEPRECATED - use the 4-step Beaver orchestration)
#' @description Kept for backward compatibility. The single-call helper
#'   has been superseded by the proper 2-round Beaver protocol
#'   orchestrated from the client:
#'   \enumerate{
#'     \item dealer calls \code{\link{k2BeaverVecmulGenTriplesDS}};
#'     \item each party calls \code{\link{k2BeaverVecmulConsumeTripleDS}};
#'     \item each party calls \code{\link{k2BeaverVecmulR1DS}} with
#'           \code{x_key="k2_cox_mu_share_fp"}, \code{y_key="k2_cox_G_share_fp"};
#'     \item each party calls \code{\link{k2BeaverVecmulR2DS}} with
#'           \code{output_key="k2_cox_mu_g_share_fp"};
#'     \item each party calls \code{\link{k2CoxFinaliseResidualDS}}.
#'   }
#' @keywords internal
#' @export
k2CoxResidualDS <- function(peer_pk = NULL, session_id = NULL) {
  stop("k2CoxResidualDS is deprecated; ds.vertCox now orchestrates the ",
       "mu*G Beaver product via k2BeaverVecmulGen/R1/R2DS + ",
       "k2CoxFinaliseResidualDS. Update dsVertClient to the matching ",
       "version (>= 1.2.0).", call. = FALSE)
}

#' @title Beaver K x L contingency counts across DCF parties
#' @description Computes the joint contingency counts
#'   \eqn{n_{kl} = \sum_i X_{ik} Y_{il}} where \eqn{X} is the one-hot
#'   encoding of \code{var1} on this server (held by the caller) and
#'   \eqn{Y} is the one-hot encoding of \code{var2} on the peer server
#'   (retrieved from the peer's session via a transport-encrypted blob
#'   relay). Both matrices are FP-encoded in the session store under
#'   \code{k2_onehot_<var>_fp} (see \code{dsvertOneHotDS}). Returns the
#'   K*L cells as a single aggregate vector; the analyst client never
#'   sees any \eqn{n}-length indicator vector.
#'
#'   Delegates the bilinear form to the Go binary via
#'   \code{k2-beaver-matrix-bilinear} which generates a single
#'   \eqn{K \times L} Beaver triple batch and returns the reconstructed
#'   counts as non-negative integers rounded from the Ring63 result.
#'
#' @param var1 character — the variable held on this server.
#' @param var2 character — the variable on the peer.
#' @param peer_name character — server name of the peer (used for
#'   session blob key disambiguation).
#' @param peer_pk base64 X25519 pk of the peer.
#' @param session_id MPC session.
#' @return list(counts = integer K*L vector row-major,
#'              K, L, row_levels, col_levels).
#' @export
k2CrossOneHotCountsDS <- function(var1, var2,
                                   peer_name = NULL,
                                   peer_pk = NULL,
                                   session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  X_key <- paste0("k2_onehot_", var1, "_fp")
  if (is.null(ss[[X_key]])) {
    stop("one-hot matrix for var1='", var1,
         "' not in session (call dsvertOneHotDS first)", call. = FALSE)
  }
  K <- ss[[paste0("k2_onehot_", var1, "_K")]]
  n <- ss[[paste0("k2_onehot_", var1, "_n")]]
  row_levels <- ss[[paste0("k2_onehot_", var1, "_levels")]]
  peer_blob_key <- paste0("k2_peer_onehot_", var2)
  blob <- .blob_consume(peer_blob_key, ss)
  if (is.null(blob)) {
    stop("peer one-hot blob not relayed for var2='", var2,
         "'; client must relay dsvertOneHotDS output from peer server",
         call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) stop("transport secret key missing", call. = FALSE)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob),
    recipient_sk = tsk))
  payload <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  Y_fp <- payload$Y_fp
  L <- payload$L
  col_levels <- payload$levels
  # Bilinear form: Ring63 Beaver product.
  res <- .callMpcTool("k2-beaver-matrix-bilinear", list(
    x_fp = ss[[X_key]], y_fp = Y_fp,
    n = as.integer(n), k = as.integer(K), l = as.integer(L),
    frac_bits = 20L))
  counts <- as.integer(round(res$counts))
  list(counts = counts, K = K, L = L,
       row_levels = row_levels, col_levels = col_levels)
}
