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
#'   stores or seals those shares for the two DCF parties. Neither DCF party
#'   ever holds the full patient-level weights vector, only an additive share.
#'
#'   The weights column is a purely local quantity: it is read as plaintext
#'   only on the server that owns it, immediately split into additive shares,
#'   and consumed only in the share domain, so a peer never receives the
#'   patient-level weights. This non-disclosure holds because the plaintext
#'   weight never leaves its holder; a weight is therefore derived from data
#'   local to that holder, never from a revealed cross-party quantity.
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
  # Both recipients are sealed to; pin them so a caller cannot supply its own
  # keys and, in dealer role, receive BOTH complementary shares of the weights.
  .dsvert_validate_recipient_pk(dcf0_pk, ss, "dcf0")
  .dsvert_validate_recipient_pk(dcf1_pk, ss, "dcf1")
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
