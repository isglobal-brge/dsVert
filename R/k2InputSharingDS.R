#' @title K=2 Input-Sharing + Gradient (ALL in FixedPoint Ring63)
#' @description All operations stay in the FixedPoint ring until the final
#'   gradient scalars are converted to float64. This prevents the int64
#'   wrapping non-additivity issue that caused gradient divergence.
#' @name k2-input-sharing
NULL

#' Share local data with peer (FixedPoint shares)
#' @export
k2ShareInputDS <- function(data_name, x_vars, y_var = NULL,
                             peer_pk, session_id = NULL) {
  ss <- .S(session_id)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p <- ncol(X)

  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) stop("Insufficient observations", call. = FALSE)
  .check_glm_disclosure(X)

  # Convert X to FP and split into shares
  x_flat <- as.numeric(t(X)) # row-major
  fp_x <- .callMheTool("k2-float-to-fp", list(values = x_flat, frac_bits = 20L))$fp_data
  x_split <- .callMheTool("k2-split-fp-share", list(data_fp = fp_x, n = length(x_flat)))

  ss$k2_x_share_fp <- x_split$own_share
  ss$k2_x_n <- n
  ss$k2_x_p <- p

  # y (label only)
  encrypted_y <- NULL
  if (!is.null(y_var)) {
    y <- as.numeric(data[[y_var]])
    fp_y <- .callMheTool("k2-float-to-fp", list(values = y, frac_bits = 20L))$fp_data
    y_split <- .callMheTool("k2-split-fp-share", list(data_fp = fp_y, n = length(y)))
    ss$k2_y_share_fp <- y_split$own_share

    # Transport-encrypt peer's y share
    pk <- .base64url_to_base64(peer_pk)
    sealed_y <- .callMheTool("transport-encrypt", list(
      data = jsonlite::base64_enc(charToRaw(y_split$peer_share)),
      recipient_pk = pk))
    encrypted_y <- base64_to_base64url(sealed_y$sealed)
  }

  # Transport-encrypt peer's X share
  pk <- .base64url_to_base64(peer_pk)
  sealed_x <- .callMheTool("transport-encrypt", list(
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
    dec <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(x_blob), recipient_sk = tsk))
    ss$k2_peer_x_share_fp <- rawToChar(jsonlite::base64_dec(dec$data))
    ss$k2_peer_p <- as.integer(peer_p)
  }

  y_blob <- .blob_consume("k2_peer_y_share", ss)
  if (!is.null(y_blob)) {
    dec <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(y_blob), recipient_sk = tsk))
    ss$k2_y_share_fp <- rawToChar(jsonlite::base64_dec(dec$data))
  }

  list(stored = TRUE)
}

#' Compute eta share in FixedPoint from full data shares and public beta
#' @export
k2ComputeEtaShareDS <- function(beta_coord, beta_nl, intercept = 0.0,
                                  is_coordinator = TRUE, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p
  p_total <- p_own + p_peer

  # Build full beta vector in the correct order
  if (is_coordinator) {
    beta_full <- c(as.numeric(beta_coord), as.numeric(beta_nl))
  } else {
    beta_full <- c(as.numeric(beta_nl), as.numeric(beta_coord))
  }

  # Convert beta to FP
  fp_beta <- .callMheTool("k2-float-to-fp", list(
    values = beta_full, frac_bits = 20L))$fp_data

  # Compute eta_share = X_full_share * beta in FP ring
  # Uses k2-compute-eta-fp command
  result <- .callMheTool("k2-compute-eta-fp", list(
    x_own_fp = ss$k2_x_share_fp,
    x_peer_fp = ss$k2_peer_x_share_fp,
    beta_fp = fp_beta,
    intercept = intercept,
    is_party_zero = is_coordinator,
    n = as.integer(n),
    p_own = as.integer(p_own),
    p_peer = as.integer(p_peer),
    frac_bits = 20L
  ))

  # Store for Beaver polynomial eval AND gradient computation
  ss$k2_eta_share <- result$eta_fp
  ss$secure_eta_share <- result$eta_fp
  ss$k2_x_full_fp <- result$x_full_fp  # full X share for gradient

  # Ensure y_share_fp exists (nonlabel gets it from input sharing, label creates it)
  if (is.null(ss$k2_y_share_fp)) {
    # Nonlabel: y_share is all zeros (since we subtract label's y_share from both)
    zero_y <- .callMheTool("k2-float-to-fp", list(
      values = rep(0, n), frac_bits = 20L))$fp_data
    ss$k2_y_share_fp <- zero_y
  }

  list(stored = TRUE, n = n)
}

#' Gradient round 1: compute (X-A, r-B) in Ring63
#' @export
k2GradientR1DS <- function(peer_pk, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p
  p_total <- p_own + p_peer

  # Assemble full X share FP: concatenate own + peer columns per row
  # This is done by the Go command
  result <- .callMheTool("k2-full-iter-r3", list(
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
    phase = 1L
  ))

  # Transport-encrypt for peer
  pk <- .base64url_to_base64(peer_pk)
  msg_json <- jsonlite::toJSON(list(
    xma = result$xma_fp, rmb = result$rmb_fp), auto_unbox = TRUE)
  sealed <- .callMheTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(msg_json)),
    recipient_pk = pk))

  list(
    encrypted_r1 = base64_to_base64url(sealed$sealed),
    sum_residual = result$sum_residual
  )
}

#' Gradient round 2: compute gradient share from Beaver formula
#' @export
k2GradientR2DS <- function(party_id = 0L, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_total <- ss$k2_x_p + ss$k2_peer_p

  # Decrypt peer's round-1 message
  blob <- .blob_consume("k2_grad_peer_r1", ss)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  peer_msg <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  result <- .callMheTool("k2-full-iter-r3", list(
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
    phase = 2L
  ))

  list(gradient_share = result$gradient, sum_residual = result$sum_residual)
}

#' Store gradient Beaver triple (Ring63 FP format)
#' @export
k2StoreGradTripleDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  blob <- .blob_consume("k2_grad_triple_fp", ss)
  if (is.null(blob)) stop("No gradient triple blob", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  msg <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  ss$k2_grad_a_fp <- msg$a
  ss$k2_grad_b_fp <- msg$b
  ss$k2_grad_c_fp <- msg$c
  list(stored = TRUE)
}
