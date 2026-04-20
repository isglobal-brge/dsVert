#' @title K=2 Input-Sharing + Gradient (ALL in FixedPoint Ring63)
#' @description All operations stay in the FixedPoint ring until the final
#'   gradient scalars are converted to float64. This prevents the int64
#'   wrapping non-additivity issue that caused gradient divergence.
#' @name k2-input-sharing
NULL

#' Share local data with peer (FixedPoint shares)
#'
#' @param ring Integer 63 (default) or 127. Selects secret-share ring
#'   (task #116 Cox/LMM STRICT migration). Ring127 routes through 16-byte
#'   Uint128 records via k2-float-to-fp + k2-split-fp-share with
#'   ring="ring127"; Ring63 keeps the 8-byte pipeline.
#' @export
k2ShareInputDS <- function(data_name, x_vars, y_var = NULL,
                             peer_pk, ring = 63L, session_id = NULL) {
  ss <- .S(session_id)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p <- ncol(X)

  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) stop("Insufficient observations", call. = FALSE)
  .check_glm_disclosure(X)

  ring <- as.integer(ring)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  # Ring127 uses fracBits=50 (Beaver sign-boundary safe zone). Ring63 keeps
  # the existing 20.
  frac_bits <- if (ring == 127L) 50L else 20L

  # Convert X to FP and split into shares
  x_flat <- as.numeric(t(X)) # row-major
  fp_x <- .callMpcTool("k2-float-to-fp", list(
    values = x_flat, frac_bits = frac_bits, ring = ring_tag))$fp_data
  x_split <- .callMpcTool("k2-split-fp-share", list(
    data_fp = fp_x, n = length(x_flat), frac_bits = frac_bits,
    ring = ring_tag))

  ss$k2_x_share_fp <- x_split$own_share
  ss$k2_x_n <- n
  ss$k2_x_p <- p
  ss$k2_ring <- ring  # Remember choice for downstream ops.

  # y (label only)
  encrypted_y <- NULL
  if (!is.null(y_var)) {
    y <- as.numeric(data[[y_var]])
    ss$k2_y_raw <- y  # Store raw y for canonical deviance constants
    fp_y <- .callMpcTool("k2-float-to-fp", list(
      values = y, frac_bits = frac_bits, ring = ring_tag))$fp_data
    y_split <- .callMpcTool("k2-split-fp-share", list(
      data_fp = fp_y, n = length(y), frac_bits = frac_bits,
      ring = ring_tag))
    ss$k2_y_share_fp <- y_split$own_share

    # Transport-encrypt peer's y share
    pk <- .base64url_to_base64(peer_pk)
    sealed_y <- .callMpcTool("transport-encrypt", list(
      data = jsonlite::base64_enc(charToRaw(y_split$peer_share)),
      recipient_pk = pk))
    encrypted_y <- base64_to_base64url(sealed_y$sealed)
  }

  # Transport-encrypt peer's X share
  pk <- .base64url_to_base64(peer_pk)
  sealed_x <- .callMpcTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(x_split$peer_share)),
    recipient_pk = pk))

  list(
    encrypted_x_share = base64_to_base64url(sealed_x$sealed),
    encrypted_y_share = encrypted_y,
    n = n, p = p
  )
}

#' Receive peer's shared data (FixedPoint)
#' @export
k2ReceiveShareDS <- function(peer_p = NULL, session_id = NULL) {
  ss <- .S(session_id)
  tsk <- .key_get("transport_sk", ss)

  x_blob <- .blob_consume("k2_peer_x_share", ss)
  if (!is.null(x_blob)) {
    dec <- .callMpcTool("transport-decrypt", list(
      sealed = .base64url_to_base64(x_blob), recipient_sk = tsk))
    ss$k2_peer_x_share_fp <- rawToChar(jsonlite::base64_dec(dec$data))
    ss$k2_peer_p <- as.integer(peer_p)
  }

  y_blob <- .blob_consume("k2_peer_y_share", ss)
  if (!is.null(y_blob)) {
    dec <- .callMpcTool("transport-decrypt", list(
      sealed = .base64url_to_base64(y_blob), recipient_sk = tsk))
    ss$k2_y_share_fp <- rawToChar(jsonlite::base64_dec(dec$data))
  }

  list(stored = TRUE)
}

#' Compute eta share in FixedPoint from full data shares and public beta
#'
#' If an offset has been registered for this session via k2SetOffsetDS(),
#' the stored log-offset FP vector is added to THIS server's eta share
#' after the X * beta computation. Mathematically this gives
#'   eta = X beta + offset
#' because the offset is plaintext on exactly one server, so adding it to
#' that server's share is equivalent to adding it to the reconstructed
#' eta. The other server's share is unchanged. No cross-server round trip
#' is required; the offset values never leave their home server.
#' @export
k2ComputeEtaShareDS <- function(beta_coord, beta_nl, intercept = 0.0,
                                  is_coordinator = TRUE, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p
  p_total <- p_own + p_peer

  # Ring selection — read from session (pinned by upstream Cox/LMM setup
  # via k2SetCoxTimesDS or similar). Default Ring63.
  ring <- as.integer(ss$k2_ring %||% 63L)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L

  # Beta is ALWAYS in canonical order: [coord features | nonlabel features]
  # Both parties use the SAME order — this is the canonical feature ordering
  # from the specification.
  beta_full <- c(as.numeric(beta_coord), as.numeric(beta_nl))

  # Convert beta to FP (in the selected ring — 8 B/elem for ring63, 16 B
  # Uint128/elem for ring127). Ring127 handler parses 16 B records.
  fp_beta <- .callMpcTool("k2-float-to-fp", list(
    values = beta_full, frac_bits = frac_bits,
    ring = ring_tag))$fp_data

  # Compute eta_share = X_full_share * beta in FP ring
  # Uses k2-compute-eta-fp command
  result <- .callMpcTool("k2-compute-eta-fp", list(
    x_own_fp = ss$k2_x_share_fp,
    x_peer_fp = ss$k2_peer_x_share_fp,
    beta_fp = fp_beta,
    intercept = intercept,
    is_party_zero = is_coordinator,
    n = as.integer(n),
    p_own = as.integer(p_own),
    p_peer = as.integer(p_peer),
    frac_bits = frac_bits,
    ring = ring_tag
  ))

  eta_fp <- result$eta_fp

  # If this server holds an offset, add it into its share in-place.
  # Ring additive shares are linear, so adding a plaintext value to
  # one party's share is equivalent to adding it to the reconstructed
  # value. The peer's share is unchanged (they have no offset).
  if (!is.null(ss$k2_offset_fp)) {
    eta_fp <- .callMpcTool("k2-fp-add", list(
      a_fp = eta_fp, b_fp = ss$k2_offset_fp,
      n = as.integer(n),
      frac_bits = frac_bits,
      ring = ring_tag
    ))$sum_fp
  }

  # Store for Beaver polynomial eval AND gradient computation
  ss$k2_eta_share <- eta_fp
  ss$k2_eta_share_fp <- eta_fp  # wide spline DCF reads this key
  ss$secure_eta_share <- eta_fp
  ss$k2_x_full_fp <- result$x_full_fp  # full X share for gradient

  # Ensure y_share_fp exists (nonlabel gets it from input sharing, label creates it)
  if (is.null(ss$k2_y_share_fp)) {
    # Nonlabel: y_share is all zeros (since we subtract label's y_share from both)
    zero_y <- .callMpcTool("k2-float-to-fp", list(
      values = rep(0, n), frac_bits = frac_bits,
      ring = ring_tag))$fp_data
    ss$k2_y_share_fp <- zero_y
  }

  list(stored = TRUE, n = n)
}

#' Gradient round 1: compute (X-A, r-B) in selected ring (Ring63 / Ring127)
#' @export
k2GradientR1DS <- function(peer_pk, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p
  p_total <- p_own + p_peer

  # Ring selection — session-pinned by upstream setup. Default Ring63.
  ring <- as.integer(ss$k2_ring %||% 63L)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L

  # Assemble full X share FP: concatenate own + peer columns per row
  # This is done by the Go command
  result <- .callMpcTool("k2-full-iter-r3", list(
    x_share_fp = ss$k2_x_full_fp,
    mu_share_fp = ss$secure_mu_share,
    y_share_fp = ss$k2_y_share_fp,
    a_share_fp = ss$k2_grad_a_fp,
    b_share_fp = ss$k2_grad_b_fp,
    c_share_fp = "",
    peer_xma_fp = "",
    peer_rmb_fp = "",
    n = as.integer(n),
    p = as.integer(p_total),
    party_id = 0L,
    phase = 1L,
    frac_bits = frac_bits,
    ring = ring_tag
  ))

  # Transport-encrypt for peer
  pk <- .base64url_to_base64(peer_pk)
  msg_json <- jsonlite::toJSON(list(
    xma = result$xma_fp, rmb = result$rmb_fp), auto_unbox = TRUE)
  sealed <- .callMpcTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(msg_json)),
    recipient_pk = pk))

  list(
    encrypted_r1 = base64_to_base64url(sealed$sealed),
    sum_residual = result$sum_residual,
    sum_residual_fp = result$sum_residual_fp
  )
}

#' Gradient round 2: compute gradient share from Beaver formula
#' @export
k2GradientR2DS <- function(party_id = 0L, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_total <- ss$k2_x_p + ss$k2_peer_p

  # Ring selection — session-pinned by upstream setup. Default Ring63.
  ring <- as.integer(ss$k2_ring %||% 63L)
  if (!ring %in% c(63L, 127L)) stop("ring must be 63 or 127", call. = FALSE)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L

  # Decrypt peer's round-1 message
  blob <- .blob_consume("k2_grad_peer_r1", ss)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  peer_msg <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  result <- .callMpcTool("k2-full-iter-r3", list(
    x_share_fp = ss$k2_x_full_fp,
    mu_share_fp = ss$secure_mu_share,
    y_share_fp = ss$k2_y_share_fp,
    a_share_fp = ss$k2_grad_a_fp,
    b_share_fp = ss$k2_grad_b_fp,
    c_share_fp = ss$k2_grad_c_fp,
    peer_xma_fp = peer_msg$xma,
    peer_rmb_fp = peer_msg$rmb,
    n = as.integer(n),
    p = as.integer(p_total),
    party_id = as.integer(party_id),
    phase = 2L,
    frac_bits = frac_bits,
    ring = ring_tag
  ))

  list(gradient_share = result$gradient, sum_residual = result$sum_residual,
       gradient_fp = result$gradient_fp, sum_residual_fp = result$sum_residual_fp)
}

#' Store gradient Beaver triple (Ring63 FP format)
#' @export
k2StoreGradTripleDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  blob <- .blob_consume("k2_grad_triple_fp", ss)
  if (is.null(blob)) stop("No gradient triple blob", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  msg <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  ss$k2_grad_a_fp <- msg$a
  ss$k2_grad_b_fp <- msg$b
  ss$k2_grad_c_fp <- msg$c
  list(stored = TRUE)
}
