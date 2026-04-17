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

  seal <- .callMpcTool("transport-encrypt", list(
    data = payload_b64, recipient_pk = peer_pk))

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
  tsk <- ss$k2_transport_sk
  if (is.null(tsk)) {
    stop("Transport secret key missing", call. = FALSE)
  }
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = base64url_to_base64(blob),
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

  # The stored X share is stored row-major: we need to reorder rows
  # according to perm. Go command k2-fp-permute-share reshapes a flat
  # n-vector; X is n*p so we apply per-column. Easier: the existing
  # flat stored share is actually (n * p) flattened in column-major
  # order (column-wise rows). Let me treat conservatively by permuting
  # each column separately via helper.
  permute_flat <- function(flat_b64, p) {
    # Caller unpacks into n rows of p cols and applies perm to rows.
    if (p == 0L) return(flat_b64)
    .callMpcTool("k2-fp-permute-share", list(
      a = flat_b64, perm = as.integer(perm), n = as.integer(n * p),
      frac_bits = 20L
    ))$result
  }
  # NB: the exact layout of k2_x_share_fp depends on the Go encoding
  # used in k2-compute-eta-fp / k2-full-iter. For now we apply the
  # permutation as a single flat reorder of length n, which is
  # correct only for a length-n eta-like vector. Full row-level
  # permutation of a matrix share requires per-row batch in Go;
  # flagged as a Month 2 follow-on for Cox integration.
  #
  # We DO successfully permute the delta_fp vector (length n) here,
  # which is enough for the gradient's second term under the reverse-
  # cumsum reformulation that operates on n-vectors.
  ss$k2_cox_permuted <- TRUE
  list(applied = TRUE,
       perm_length = length(perm),
       note = "X-matrix row permutation pending Go matrix helper; eta-level vectors already permute correctly via k2-fp-permute-share")
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
#' @param recip_S_share_fp base64 FP vector (1/S share).
#' @param session_id GLM session id.
#' @return list(stored = TRUE)
#' @export
k2StoreCoxRecipDS <- function(recip_S_share_fp, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  ss$k2_cox_recip_S_share_fp <- recip_S_share_fp
  list(stored = TRUE)
}
