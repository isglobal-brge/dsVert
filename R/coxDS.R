#' @title Register Cox survival times and sort the cohort (outcome server)
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
                            peer_pk, session_id = NULL) {
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

  # Sort ascending by event time; break ties by placing events before
  # censored (standard convention for Breslow).
  ord <- order(t_vec, -d_vec)  # 1-indexed permutation
  d_sorted <- d_vec[ord]

  # Encode delta_sorted as FP share-compatible vector (plaintext here,
  # peer will also hold it plaintext after decrypt).
  delta_fp <- .callMpcTool("k2-float-to-fp", list(
    values = as.numeric(d_sorted), frac_bits = 20L))$fp_data
  ss$k2_cox_perm <- as.integer(ord)
  ss$k2_cox_delta_fp <- delta_fp
  ss$k2_cox_n_events <- sum(d_vec)

  # Build peer blob: a small JSON payload with perm (ints) + delta_fp
  # (base64 FP vector), then encrypt via transport.
  payload <- list(perm = as.integer(ord), delta_fp = delta_fp,
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
  list(stored = TRUE, n = length(ss$k2_cox_perm))
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
  permute_rows <- function(flat_b64, p) {
    if (is.null(flat_b64) || !nzchar(flat_b64) || p <= 0L) return(flat_b64)
    .callMpcTool("k2-fp-permute-share", list(
      a = flat_b64, perm = as.integer(perm),
      n = as.integer(n), cols = as.integer(p),
      frac_bits = 20L
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
  res <- .callMpcTool("k2-fp-cumsum", list(
    a = ss$secure_mu_share, reverse = TRUE,
    n = as.integer(ss$k2_x_n), frac_bits = 20L))
  ss$k2_cox_S_share_fp <- res$result
  list(S_length = ss$k2_x_n)
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
  # Multiply delta element-wise into 1/S share (mask), then forward
  # cumsum. Both kernels in one call via the mask argument.
  res <- .callMpcTool("k2-fp-cumsum", list(
    a = ss$k2_cox_recip_S_share_fp,
    mask = ss$k2_cox_delta_fp,
    reverse = FALSE,
    n = as.integer(ss$k2_x_n), frac_bits = 20L))
  ss$k2_cox_G_share_fp <- res$result
  list(G_length = ss$k2_x_n)
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

#' @title Cox residual share r_j = delta_j - exp(eta_j) * G_j
#' @description After the forward-cumsum G step, compute the Cox
#'   residual-like quantity on additive shares via a Beaver triple for
#'   the element-wise product \eqn{\mu_j G_j}, then subtract from the
#'   plaintext delta vector (delta is known on BOTH DCF parties: the
#'   outcome server set it via \code{k2SetCoxTimesDS}; the peer received
#'   it via \code{k2ReceiveCoxMetaDS}). Stores the result in
#'   \code{ss$secure_mu_share} so that the standard
#'   \code{glmRing63GenGradTriplesDS} -> \code{k2GradientR1DS} ->
#'   \code{k2GradientR2DS} chain computes \eqn{X^T r} and returns the
#'   Cox gradient aggregate to the client.
#'
#'   Uses the existing \code{k2-fp-vec-mul-beaver} Beaver-triple Go op
#'   (element-wise Ring63 multiplication of two secret shares) which is
#'   already deployed.  Because delta is plaintext on both parties, the
#'   subtraction is a LOCAL op: party 0 stores \code{delta_fp - mu_G};
#'   party 1 stores \code{-mu_G} (same share-sign convention as
#'   \code{k2StoreWeightsDS}).
#'
#'   Note: the Beaver triple for the element-wise product is generated
#'   on the dealer (non-label party) in the same way as the existing
#'   gradient triples.  The caller (client) is responsible for dealer
#'   coordination; the server simply consumes the triple from the
#'   session key \code{k2_cox_mug_triple}.
#'
#' @param peer_pk  Transport public key of the peer.
#' @param session_id GLM session id.
#' @return list(done = TRUE)
#' @export
k2CoxResidualDS <- function(peer_pk = NULL, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$secure_mu_share)) {
    stop("secure_mu_share empty (exp(eta) share); run exp DCF first",
         call. = FALSE)
  }
  if (is.null(ss$k2_cox_G_share_fp)) {
    stop("k2_cox_G_share_fp empty; run k2CoxForwardCumsumGDS first",
         call. = FALSE)
  }
  if (is.null(ss$k2_cox_delta_fp)) {
    stop("delta not registered; run k2SetCoxTimesDS / k2ReceiveCoxMetaDS",
         call. = FALSE)
  }

  # Element-wise Beaver product of two shares. Reuse the existing
  # triple infrastructure: the dealer generates a "grad triple" of
  # shape n x 1 via glmRing63GenGradTriplesDS with p = 1.
  # For a single-round implementation that avoids new dealer logic,
  # we delegate to the existing Beaver product helper:
  mug_res <- .callMpcTool("k2-fp-vec-mul-beaver", list(
    a_share = ss$secure_mu_share,
    b_share = ss$k2_cox_G_share_fp,
    triple  = ss$k2_cox_mug_triple,       # may be NULL → server error
    frac_bits = 20L))
  # Subtract from delta locally. On party 0 the convention is:
  #   r_share_0 = delta_fp - mu_G_share_0
  # On party 1:
  #   r_share_1 = -mu_G_share_1
  # The delta vector is reconstructed on both parties so only party 0
  # performs the subtraction; party 1 negates.
  r_share <- .callMpcTool("k2-fp-cox-residual-finalise", list(
    mu_g_share = mug_res$result,
    delta_fp   = ss$k2_cox_delta_fp,
    is_party0  = isTRUE(ss$k2_is_coordinator),
    frac_bits  = 20L))
  ss$secure_mu_share <- r_share$result
  list(done = TRUE)
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
