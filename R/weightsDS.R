#' @title Register observation weights for an open GLM session (outcome-side)
#' @description Read a numeric weights column held on this server, convert
#'   to Ring63 FP, store a copy locally for subsequent \code{k2ApplyWeightsDS}
#'   calls, and return an encrypted blob destined for the peer DCF party.
#'   This is the first of two registration steps needed for weighted GLM
#'   (inverse-probability weighting, survey-weighted regression, etc.).
#'
#'   The weights are disclosed to the DCF peer server through the returned
#'   ciphertext -- an acceptable server-to-server leakage for IPW, where
#'   weights are themselves derived from a propensity model whose
#'   coefficients are already public. Nothing is ever disclosed to the
#'   analyst client. Within-cohort, patient-level weight values never
#'   leave the pair of DCF parties.
#'
#' @param data_name Character. Aligned data-frame name on this server.
#' @param weights_column Character. Name of the numeric weights column.
#' @param peer_pk Character. Transport (X25519) public key of the DCF peer.
#' @param session_id Character. GLM session identifier.
#'
#' @return A list with \code{peer_blob} (base64url transport-encrypted
#'   serialised FP weights vector) and \code{n} (vector length). The
#'   client relays \code{peer_blob} to the peer via \code{mpcStoreBlobDS}
#'   + \code{k2ReceiveWeightsDS}.
#' @export
k2SetWeightsDS <- function(data_name, weights_column, peer_pk,
                           session_id = NULL) {
  if (!is.character(data_name) || length(data_name) != 1L) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(weights_column) || length(weights_column) != 1L) {
    stop("weights_column must be a single character string", call. = FALSE)
  }
  if (!is.character(peer_pk) || length(peer_pk) != 1L) {
    stop("peer_pk must be a single base64url public key", call. = FALSE)
  }
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!weights_column %in% names(data)) {
    stop("Weights column '", weights_column, "' not found in '",
         data_name, "'", call. = FALSE)
  }
  w <- data[[weights_column]]
  if (!is.numeric(w)) {
    stop("Weights column must be numeric", call. = FALSE)
  }
  if (anyNA(w)) {
    stop("Weights column contains NA on the aligned cohort; this is
          not supported", call. = FALSE)
  }
  if (any(w < 0)) {
    stop("Weights must be non-negative", call. = FALSE)
  }

  ss <- .S(session_id)
  n_expected <- ss$k2_x_n
  if (!is.null(n_expected) && length(w) != n_expected) {
    stop("Weights length (", length(w),
         ") does not match aligned cohort size (", n_expected, ")",
         call. = FALSE)
  }

  fp_res <- .callMpcTool("k2-float-to-fp", list(
    values = as.numeric(w), frac_bits = 20L))
  ss$k2_weights_fp <- fp_res$fp_data
  ss$k2_weights_column <- weights_column

  # Encrypt FP blob to peer. We send the base64 FP bytes; the peer will
  # decrypt and store as its own ss$k2_weights_fp. The peer_pk arrives
  # in base64url format (how glmRing63TransportInitDS emits it), so
  # convert back to standard base64 before calling the Go tool which
  # uses standard base64 decoding.
  seal <- .callMpcTool("transport-encrypt", list(
    data = fp_res$fp_data,
    recipient_pk = .base64url_to_base64(peer_pk)))

  list(peer_blob = base64_to_base64url(seal$sealed),
       n = length(w))
}

#' @title Receive observation weights from the DCF peer (non-outcome side)
#' @description Consume the peer's weights blob previously relayed via
#'   \code{mpcStoreBlobDS}, decrypt it with this server's transport
#'   secret key, and store the plaintext FP weights vector for
#'   subsequent \code{k2ApplyWeightsDS} calls. Pairs with
#'   \code{k2SetWeightsDS} on the outcome-holding server.
#'
#' @param session_id Character. GLM session identifier.
#' @return \code{list(stored = TRUE, n = length)}
#' @export
k2ReceiveWeightsDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume("k2_peer_weights", ss)
  if (is.null(blob)) {
    stop("No peer weights blob found for session", call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) {
    stop("Transport secret key missing for session", call. = FALSE)
  }
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob),
    recipient_sk = tsk))
  # dec$data is the base64 FP bytes sent by the peer
  ss$k2_weights_fp <- dec$data
  list(stored = TRUE)
}

#' @title Apply registered weights to the current mu and y shares
#' @description Scale this server's mu share (ss$secure_mu_share) AND its
#'   y share (ss$k2_y_share_fp) element-wise by the registered weights
#'   vector. After both DCF parties apply this, the reconstructed
#'   residual r' = mu' - y' equals w * (mu - y) = w * r, so the
#'   subsequent Beaver matrix-vector gradient X^T r' is the weighted
#'   gradient. No Beaver rounds required: element-wise scaling of a
#'   share by a publicly-known vector is local.
#'
#' @param session_id Character. GLM session identifier.
#' @return \code{list(applied = TRUE)}
#' @export
k2ApplyWeightsDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$k2_weights_fp)) {
    stop("No weights registered for this session; call k2SetWeightsDS /
          k2ReceiveWeightsDS first", call. = FALSE)
  }
  if (is.null(ss$secure_mu_share) || is.null(ss$k2_y_share_fp)) {
    stop("mu / y shares missing for this session; call
          k2ComputeEtaShareDS + spline first", call. = FALSE)
  }
  n <- ss$k2_x_n
  # --- Task #98 fix 2026-04-21 ---
  # BUG: Previously both mu and y were overwritten in-place by w*(...).
  # mu is recomputed fresh each iter via k2ComputeEtaShareDS + wide
  # spline so its in-place overwrite was harmless, but y_share_fp is
  # cached from Phase 1 input sharing and NEVER recomputed. Each
  # iter's k2ApplyWeightsDS therefore multiplied the CACHED y_share
  # by w AGAIN, so after N iters y_share held w^N · y. For ipw
  # weights in [1, 5] and max_iter=30 this blows up to w^30 ~ 1e19,
  # which in Ring63 FP manifested as the observed -2.8e8 coefficient
  # overflow reported in the v2c probe (probe_ipw_weights.R
  # confirmed: w=1 passes STRICT, w in [1.22, 4.52] catastrophic).
  #
  # Fix: snapshot the original y_share once at the first call and
  # re-derive the weighted y from that snapshot every iter. mu is
  # kept as before (it is re-derived upstream, never cached).
  if (is.null(ss$k2_y_share_fp_original)) {
    ss$k2_y_share_fp_original <- ss$k2_y_share_fp
  }
  # Scale mu share by w (element-wise, local, no Beaver).
  mu_w <- .callMpcTool("k2-fp-vec-mul", list(
    a = ss$secure_mu_share, b = ss$k2_weights_fp, n = as.integer(n)))
  ss$secure_mu_share <- mu_w$result
  ss$k2_eta_share_fp  <- mu_w$result  # wide spline reads this key
  ss$k2_eta_share     <- mu_w$result
  # Scale y share by w FROM THE CACHED ORIGINAL (not the possibly-
  # already-weighted current value).
  y_w <- .callMpcTool("k2-fp-vec-mul", list(
    a = ss$k2_y_share_fp_original, b = ss$k2_weights_fp,
    n = as.integer(n)))
  ss$k2_y_share_fp <- y_w$result
  list(applied = TRUE)
}

#' @title Clear registered weights from a session
#' @description Remove the cached weights vector so subsequent
#'   iterations fall back to unweighted GLM. Safe no-op if no weights
#'   were registered.
#' @param session_id Character.
#' @return \code{list(cleared = TRUE)}
#' @export
k2ClearWeightsDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  ss$k2_weights_fp <- NULL
  ss$k2_weights_column <- NULL
  list(cleared = TRUE)
}
