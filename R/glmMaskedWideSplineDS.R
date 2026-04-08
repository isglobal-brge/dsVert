#' @title Masked Wide Spline Server Functions
#' @description Server-side functions for the K>=3 Masked Wide Spline protocol.
#'   Enables non-disclosive binomial/Poisson by combining CKKS aggregation
#'   with K=2 wide spline DCF evaluation.
#'
#' @details
#' The coordinator masks the aggregated eta with random noise before threshold
#' decryption. The fusion server and coordinator then hold additive shares of
#' eta_total, which are fed into the K=2 wide spline DCF protocol.
#' Nobody sees eta_total or mu in plaintext.
#'
#' @name glm-masked-wide-spline
NULL

#' Mask aggregated eta with random noise (coordinator only)
#'
#' After glmHELinkStepDS(skip_poly=TRUE) produces Enc(eta_total), this function:
#' 1. Generates random mask r (n-dimensional)
#' 2. Encrypts r under CPK: Enc(r)
#' 3. Computes Enc(eta_total + r) = Enc(eta_total) + Enc(r)
#' 4. Stores -r locally as the coordinator's Ring63 FP share
#'
#' @param n_obs Integer. Number of observations.
#' @param frac_bits Integer. Fixed-point fractional bits (default 20).
#' @param session_id Character or NULL.
#' @return List with \code{ct_masked} (base64url encrypted masked eta).
#' @export
glmMWSMaskEtaDS <- function(n_obs, intercept = 0, frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)

  # ct_eta_total was stored by glmHELinkStepDS(skip_poly=TRUE) as ss$ct_mu
  ct_eta <- ss$ct_mu
  if (is.null(ct_eta))
    stop("No aggregated eta. Call glmHELinkStepDS(skip_poly=TRUE) first.", call. = FALSE)

  n <- as.integer(n_obs)
  intercept <- as.numeric(intercept)

  # Generate random mask r (uniform in [-5, 5] to cover eta range)
  # Include intercept in the mask: r_effective = r - intercept
  # So share_A = eta_total + intercept + r, share_B = -(r + intercept) ...
  # Actually: share_B = -r, and we add intercept to the encrypted sum:
  # Enc(eta_total + intercept + r) = Enc(eta_total) + Enc(intercept_vec) + Enc(r)
  r <- runif(n, -5, 5)

  # Encrypt (r + intercept) — so share_A gets eta_total + intercept + r
  # and share_B = -(r + intercept)
  r_plus_intercept <- r + intercept

  # Encrypt under CPK
  enc_r <- .callMheTool("mhe-encrypt-vector", list(
    vector = r_plus_intercept,
    collective_public_key = .key_get("cpk", ss),
    log_n = as.integer(ss$log_n %||% 12),
    log_scale = as.integer(ss$log_scale %||% 40)
  ))

  # Enc(eta_total + r) = Enc(eta_total) + Enc(r)
  ct_masked <- .callMheTool("mhe-ct-add", list(
    ciphertext_a = ct_eta,
    ciphertext_b = enc_r$ciphertext,
    log_n = as.integer(ss$log_n %||% 12),
    log_scale = as.integer(ss$log_scale %||% 40)
  ))

  # Store -(r + intercept) as coordinator's share
  neg_r_fp <- .callMheTool("k2-float-to-fp", list(
    values = -r_plus_intercept, frac_bits = as.integer(frac_bits)
  ))
  ss$k2_eta_share_fp <- neg_r_fp$fp_data
  ss$k2_eta_share <- neg_r_fp$fp_data
  ss$mws_n_obs <- n

  # Register ct_masked in Protocol Firewall for threshold decryption
  ct_hash <- .register_ciphertext(ct_masked$ciphertext, "mws-masked-eta",
                                   session_id = session_id)

  list(ct_masked = base64_to_base64url(ct_masked$ciphertext),
       ct_hash = ct_hash)
}

#' Set eta share from plaintext float (for MWS threshold-decrypted share)
#'
#' After threshold decryption reveals eta_total + r on the fusion server,
#' this function converts the plaintext float vector to Ring63 fixed-point
#' and stores it as the server's eta share for the wide spline phases.
#'
#' @param eta_float Numeric vector. Plaintext eta share (eta_total + r).
#' @param frac_bits Integer. Fixed-point fractional bits (default 20).
#' @param session_id Character or NULL.
#' @return TRUE.
#' @export
glmMWSSetEtaShareDS <- function(eta_float = NULL, from_storage = FALSE,
                                 frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)

  if (from_storage) {
    # Read from chunked transfer (col_index=4, already standard base64 after assembly)
    blob_b64 <- NULL
    if (!is.null(ss$remote_enc_cols) && length(ss$remote_enc_cols) >= 4)
      blob_b64 <- ss$remote_enc_cols[[4]]
    if (is.null(blob_b64)) stop("No mws_eta_share data (col_index=4)", call. = FALSE)
    raw <- jsonlite::base64_dec(blob_b64)
    eta_float <- as.numeric(jsonlite::fromJSON(rawToChar(raw)))
  } else {
    eta_float <- as.numeric(eta_float)
  }

  # Disclosure check
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (length(eta_float) < privacy_level)
    stop("Insufficient observations", call. = FALSE)

  fp_result <- .callMheTool("k2-float-to-fp", list(
    values = eta_float, frac_bits = as.integer(frac_bits)
  ))
  ss$k2_eta_share_fp <- fp_result$fp_data
  ss$k2_eta_share <- fp_result$fp_data
  ss$mws_n_obs <- length(eta_float)
  TRUE
}

#' Get mu share as encrypted ciphertext (after wide spline phases)
#'
#' After the wide spline phases compute mu shares in Ring63, this function:
#' 1. Reads the mu share from session (stored by k2WideSplinePhase4DS)
#' 2. Converts from Ring63 FP to float
#' 3. Encrypts under CPK
#' Returns the encrypted mu share for homomorphic summation.
#'
#' @param session_id Character or NULL.
#' @return List with \code{encrypted_mu_share} (base64url ciphertext).
#' @export
glmMWSGetMuShareDS <- function(session_id = NULL) {
  ss <- .S(session_id)

  # Read mu share (stored by k2WideSplinePhase4DS as ss$k2_mu_share_fp)
  mu_fp <- ss$k2_mu_share_fp
  if (is.null(mu_fp))
    stop("No mu share. Run wide spline phases 1-4 first.", call. = FALSE)

  # Convert Ring63 FP to float
  mu_float <- .callMheTool("mpc-fp-to-float", list(
    fp_data = mu_fp,
    n = as.integer(ss$mws_n_obs %||% 0),
    frac_bits = 20L
  ))

  # Encrypt under CPK
  enc_mu <- .callMheTool("mhe-encrypt-vector", list(
    vector = mu_float$values,
    collective_public_key = .key_get("cpk", ss),
    log_n = as.integer(ss$log_n %||% 12),
    log_scale = as.integer(ss$log_scale %||% 40)
  ))

  list(encrypted_mu_share = base64_to_base64url(enc_mu$ciphertext))
}
