#' @keywords internal
.k2_plaintext_weights_allowed <- function() {
  opt <- isTRUE(getOption("dsvert.allow_plaintext_dcf_weights", FALSE))
  env <- Sys.getenv("DSVERT_ALLOW_PLAINTEXT_DCF_WEIGHTS", unset = "")
  opt || tolower(env) %in% c("1", "true", "yes")
}

#' @keywords internal
.k2_stop_plaintext_weights <- function() {
  stop("Plaintext DCF weights are disabled by default because patient-level ",
       "weights can reveal hidden row-level values in vertical IPW splits. ",
       "Use k2ShareWeightsDS with share-domain weighted residual helpers, ",
       "or set option ",
       "dsvert.allow_plaintext_dcf_weights=TRUE only for diagnostic legacy ",
       "reproduction.", call. = FALSE)
}

#' @keywords internal
.k2_weight_ring_info <- function(ring = NULL, ss = NULL) {
  if (is.null(ring) && !is.null(ss)) ring <- ss$k2_ring %||% 63L
  if (is.null(ring)) ring <- 63L
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  list(
    ring = ring,
    ring_tag = if (ring == 127L) "ring127" else "ring63",
    frac_bits = if (ring == 127L) 50L else 20L
  )
}

#' @keywords internal
.k2_read_weight_column <- function(data_name, weights_column, session_id) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame(2L))
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
    stop("Weights column contains NA on the aligned cohort; this is ",
         "not supported", call. = FALSE)
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
  as.numeric(w)
}

#' @keywords internal
.k2_seal_weight_share <- function(share, pk) {
  sealed <- .callMpcTool("transport-encrypt", list(
    data = share,
    recipient_pk = .base64url_to_base64(pk)))
  base64_to_base64url(sealed$sealed)
}

#' @title Secret-share observation weights for a GLM session
#' @description Reads a weights column, converts it to the session fixed-point
#'   ring, splits \eqn{w} and \eqn{\sqrt{w}} into two additive shares, and
#'   stores or seals those shares for the two DCF parties. Unlike
#'   \code{k2SetWeightsDS}, this helper never gives either DCF party the
#'   full patient-level weights vector.
#'
#' @param data_name Character. Aligned data-frame name on this server.
#' @param weights_column Character. Name of the numeric weights column.
#' @param dcf0_pk,dcf1_pk Transport public keys for the two DCF parties.
#' @param dcf_role Character. One of \code{"dcf0"}, \code{"dcf1"}, or
#'   \code{"dealer"}. DCF callers store their own share and return the peer
#'   blob; a non-DCF dealer returns both sealed DCF blobs.
#' @param ring Integer (63 or 127). MPC ring selector.
#' @param session_id Character. GLM session identifier.
#' @return Metadata and sealed share blobs for the client relay.
#' @export
k2ShareWeightsDS <- function(data_name, weights_column, dcf0_pk, dcf1_pk,
                             dcf_role = c("dealer", "dcf0", "dcf1"),
                             ring = NULL, session_id = NULL) {
  if (!is.character(data_name) || length(data_name) != 1L) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(weights_column) || length(weights_column) != 1L) {
    stop("weights_column must be a single character string", call. = FALSE)
  }
  if (!is.character(dcf0_pk) || length(dcf0_pk) != 1L ||
      !is.character(dcf1_pk) || length(dcf1_pk) != 1L) {
    stop("dcf0_pk and dcf1_pk must be single base64url public keys",
         call. = FALSE)
  }
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }

  dcf_role <- match.arg(dcf_role)
  ss <- .S(session_id)
  info <- .k2_weight_ring_info(ring, ss)
  w <- .k2_read_weight_column(data_name, weights_column, session_id)

  fp_res <- .callMpcTool("k2-float-to-fp", list(
    values = w, frac_bits = info$frac_bits, ring = info$ring_tag))
  sqrt_fp_res <- .callMpcTool("k2-float-to-fp", list(
    values = sqrt(w), frac_bits = info$frac_bits, ring = info$ring_tag))
  split_w <- .callMpcTool("k2-split-fp-share", list(
    data_fp = fp_res$fp_data, n = length(w),
    frac_bits = info$frac_bits, ring = info$ring_tag))
  split_sw <- .callMpcTool("k2-split-fp-share", list(
    data_fp = sqrt_fp_res$fp_data, n = length(w),
    frac_bits = info$frac_bits, ring = info$ring_tag))

  ss$k2_weights_column <- weights_column
  ss$k2_weights_ring <- info$ring

  if (dcf_role == "dcf0") {
    ss$k2_weights_share_fp <- split_w$own_share
    ss$k2_sqrt_weights_share_fp <- split_sw$own_share
    return(list(
      peer_blob = .k2_seal_weight_share(split_w$peer_share, dcf1_pk),
      peer_sqrt_blob = .k2_seal_weight_share(split_sw$peer_share, dcf1_pk),
      n = length(w), disclosure = "shared_weights"))
  }
  if (dcf_role == "dcf1") {
    ss$k2_weights_share_fp <- split_w$own_share
    ss$k2_sqrt_weights_share_fp <- split_sw$own_share
    return(list(
      peer_blob = .k2_seal_weight_share(split_w$peer_share, dcf0_pk),
      peer_sqrt_blob = .k2_seal_weight_share(split_sw$peer_share, dcf0_pk),
      n = length(w), disclosure = "shared_weights"))
  }

  list(
    dcf0_blob = .k2_seal_weight_share(split_w$own_share, dcf0_pk),
    dcf1_blob = .k2_seal_weight_share(split_w$peer_share, dcf1_pk),
    dcf0_sqrt_blob = .k2_seal_weight_share(split_sw$own_share, dcf0_pk),
    dcf1_sqrt_blob = .k2_seal_weight_share(split_sw$peer_share, dcf1_pk),
    n = length(w), disclosure = "shared_weights")
}

#' @title Receive secret-shared observation weights
#' @description Decrypts a relayed additive share generated by
#'   \code{k2ShareWeightsDS} and stores it for share-domain weighted GLM.
#' @param session_id Character. GLM session identifier.
#' @return \code{list(stored = TRUE)}
#' @export
k2ReceiveWeightSharesDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  blob <- .blob_consume("k2_peer_weight_share", ss)
  if (is.null(blob)) {
    stop("No peer weight-share blob found for session", call. = FALSE)
  }
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk)) {
    stop("Transport secret key missing for session", call. = FALSE)
  }
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob),
    recipient_sk = tsk))
  ss$k2_weights_share_fp <- dec$data

  sqrt_blob <- .blob_consume("k2_peer_sqrt_weight_share", ss)
  if (!is.null(sqrt_blob)) {
    sqrt_dec <- .callMpcTool("transport-decrypt", list(
      sealed = .base64url_to_base64(sqrt_blob),
      recipient_sk = tsk))
    ss$k2_sqrt_weights_share_fp <- sqrt_dec$data
  }
  list(stored = TRUE)
}

#' @title Prepare residual shares for share-domain weighting
#' @description Computes and stores this party's residual share
#'   \eqn{r = \mu - y}. The original \eqn{y} share is snapshotted once so
#'   repeated weighted iterations are independent.
#' @param session_id Character. GLM session identifier.
#' @return \code{list(stored = TRUE)}
#' @export
k2PrepareWeightedResidualShareDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$secure_mu_share) || is.null(ss$k2_y_share_fp)) {
    stop("mu / y shares missing for this session; call link evaluation first",
         call. = FALSE)
  }
  if (is.null(ss$k2_y_share_fp_original)) {
    ss$k2_y_share_fp_original <- ss$k2_y_share_fp
  }
  info <- .k2_weight_ring_info(NULL, ss)
  r <- .callMpcTool("k2-fp-sub", list(
    a = ss$secure_mu_share, b = ss$k2_y_share_fp_original,
    frac_bits = info$frac_bits, ring = info$ring_tag))
  ss$k2_weight_residual_share_fp <- r$result
  list(stored = TRUE)
}

#' @title Finalise a share-domain weighted residual
#' @description After Beaver vecmul has produced a share of
#'   \eqn{w \cdot r} or \eqn{\sqrt{w} \cdot r}, installs that share as the
#'   active residual by setting \code{secure_mu_share = product_share} and
#'   \code{k2_y_share_fp = 0}. Existing gradient/deviance routines then
#'   consume the weighted residual without learning patient-level weights.
#' @param input_key Character. Session key containing the product share.
#' @param session_id Character. GLM session identifier.
#' @return \code{list(applied = TRUE)}
#' @export
k2FinalizeWeightedResidualShareDS <- function(
    input_key = "k2_weighted_residual_share_fp", session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (!is.character(input_key) || length(input_key) != 1L || !nzchar(input_key)) {
    stop("input_key must be a single non-empty character string",
         call. = FALSE)
  }
  ss <- .S(session_id)
  product <- ss[[input_key]]
  if (is.null(product)) {
    stop("Weighted residual share '", input_key, "' not found", call. = FALSE)
  }
  info <- .k2_weight_ring_info(NULL, ss)
  zero <- .callMpcTool("k2-float-to-fp", list(
    values = rep(0, ss$k2_x_n), frac_bits = info$frac_bits,
    ring = info$ring_tag))
  ss$secure_mu_share <- product
  ss$k2_eta_share_fp <- product
  ss$k2_eta_share <- product
  ss$k2_y_share_fp <- zero$fp_data
  list(applied = TRUE)
}

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
#' @param ring Integer (63 or 127). MPC ring selector; controls fixed-point precision.
#' @return A list with \code{peer_blob} (base64url transport-encrypted
#'   serialised FP weights vector) and \code{n} (vector length). The
#'   client relays \code{peer_blob} to the peer via \code{mpcStoreBlobDS}
#'   + \code{k2ReceiveWeightsDS}.
#' @export
k2SetWeightsDS <- function(data_name, weights_column, peer_pk,
                           ring = NULL, session_id = NULL) {
  if (!.k2_plaintext_weights_allowed()) .k2_stop_plaintext_weights()
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

  # Ring-aware: if caller supplies `ring` (63 or 127), use the
  # corresponding frac_bits (20 or 50). Otherwise fall back to the
  # session-pinned ring from k2ShareInputDS (ss$k2_ring), defaulting
  # to Ring63 frac_bits=20 for back-compat.
  if (is.null(ring)) ring <- ss$k2_ring %||% 63L
  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits_w <- if (ring == 127L) 50L else 20L

  fp_res <- .callMpcTool("k2-float-to-fp", list(
    values = as.numeric(w), frac_bits = frac_bits_w,
    ring = ring_tag))
  sqrt_fp_res <- .callMpcTool("k2-float-to-fp", list(
    values = sqrt(as.numeric(w)), frac_bits = frac_bits_w,
    ring = ring_tag))
  ss$k2_weights_fp <- fp_res$fp_data
  ss$k2_sqrt_weights_fp <- sqrt_fp_res$fp_data
  ss$k2_weights_column <- weights_column
  ss$k2_weights_ring <- ring

  # Encrypt FP blob to peer. We send the base64 FP bytes; the peer will
  # decrypt and store as its own ss$k2_weights_fp. The peer_pk arrives
  # in base64url format (how glmRing63TransportInitDS emits it), so
  # convert back to standard base64 before calling the Go tool which
  # uses standard base64 decoding.
  seal <- .callMpcTool("transport-encrypt", list(
    data = fp_res$fp_data,
    recipient_pk = .base64url_to_base64(peer_pk)))
  sqrt_seal <- .callMpcTool("transport-encrypt", list(
    data = sqrt_fp_res$fp_data,
    recipient_pk = .base64url_to_base64(peer_pk)))

  list(peer_blob = base64_to_base64url(seal$sealed),
       peer_sqrt_blob = base64_to_base64url(sqrt_seal$sealed),
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
  if (!.k2_plaintext_weights_allowed()) .k2_stop_plaintext_weights()
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
  sqrt_blob <- .blob_consume("k2_peer_sqrt_weights", ss)
  if (!is.null(sqrt_blob)) {
    sqrt_dec <- .callMpcTool("transport-decrypt", list(
      sealed = .base64url_to_base64(sqrt_blob),
      recipient_sk = tsk))
    ss$k2_sqrt_weights_fp <- sqrt_dec$data
  }
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
  if (!.k2_plaintext_weights_allowed()) .k2_stop_plaintext_weights()
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
  # by w AGAIN, so after N iters y_share held w^N * y. For ipw
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
  # Ring-aware mul: use the ring pinned by k2SetWeightsDS (which
  # matches k2ShareInputDS). Ring127 uses 16-byte Uint128 records
  # with frac_bits=50; Ring63 uses 8-byte records with frac_bits=20.
  ring_w <- as.integer(ss$k2_weights_ring %||% ss$k2_ring %||% 63L)
  ring_tag <- if (ring_w == 127L) "ring127" else "ring63"
  frac_bits_w <- if (ring_w == 127L) 50L else 20L
  # Scale mu share by w (element-wise, local, no Beaver).
  mu_w <- .callMpcTool("k2-fp-vec-mul", list(
    a = ss$secure_mu_share, b = ss$k2_weights_fp,
    n = as.integer(n), frac_bits = frac_bits_w, ring = ring_tag))
  ss$secure_mu_share <- mu_w$result
  ss$k2_eta_share_fp  <- mu_w$result
  ss$k2_eta_share     <- mu_w$result
  y_w <- .callMpcTool("k2-fp-vec-mul", list(
    a = ss$k2_y_share_fp_original, b = ss$k2_weights_fp,
    n = as.integer(n), frac_bits = frac_bits_w, ring = ring_tag))
  ss$k2_y_share_fp <- y_w$result
  list(applied = TRUE)
}

#' @title Apply square-root registered weights to the current mu and y shares
#' @description Scale this server's mu and original y shares by
#'   \eqn{\sqrt{w}}. After both DCF parties apply this helper, Beaver
#'   RSS computes \eqn{\sum_i w_i(\mu_i-y_i)^2}. This is the correct
#'   Gaussian weighted deviance path; gradient scoring continues to use
#'   \code{k2ApplyWeightsDS}, which scales by \eqn{w}.
#'
#' @param session_id Character. GLM session identifier.
#' @return \code{list(applied = TRUE)}
#' @export
k2ApplySqrtWeightsDS <- function(session_id = NULL) {
  if (!.k2_plaintext_weights_allowed()) .k2_stop_plaintext_weights()
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  if (is.null(ss$k2_sqrt_weights_fp)) {
    stop("No sqrt weights registered for this session; call k2SetWeightsDS /
          k2ReceiveWeightsDS first", call. = FALSE)
  }
  if (is.null(ss$secure_mu_share) || is.null(ss$k2_y_share_fp)) {
    stop("mu / y shares missing for this session; call
          k2ComputeEtaShareDS + spline first", call. = FALSE)
  }
  n <- ss$k2_x_n
  if (is.null(ss$k2_y_share_fp_original)) {
    ss$k2_y_share_fp_original <- ss$k2_y_share_fp
  }
  ring_w <- as.integer(ss$k2_weights_ring %||% ss$k2_ring %||% 63L)
  ring_tag <- if (ring_w == 127L) "ring127" else "ring63"
  frac_bits_w <- if (ring_w == 127L) 50L else 20L
  mu_sw <- .callMpcTool("k2-fp-vec-mul", list(
    a = ss$secure_mu_share, b = ss$k2_sqrt_weights_fp,
    n = as.integer(n), frac_bits = frac_bits_w, ring = ring_tag))
  ss$secure_mu_share <- mu_sw$result
  ss$k2_eta_share_fp  <- mu_sw$result
  ss$k2_eta_share     <- mu_sw$result
  y_sw <- .callMpcTool("k2-fp-vec-mul", list(
    a = ss$k2_y_share_fp_original, b = ss$k2_sqrt_weights_fp,
    n = as.integer(n), frac_bits = frac_bits_w, ring = ring_tag))
  ss$k2_y_share_fp <- y_sw$result
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
  ss$k2_sqrt_weights_fp <- NULL
  ss$k2_weights_share_fp <- NULL
  ss$k2_sqrt_weights_share_fp <- NULL
  ss$k2_weights_column <- NULL
  list(cleared = TRUE)
}
