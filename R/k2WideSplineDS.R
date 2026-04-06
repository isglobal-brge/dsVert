# k2WideSplineDS.R: Server-side functions for K=2 wide spline protocol.
#
# These functions are called by the client (dsVertClient) to evaluate the
# sigmoid (binomial) or exp (Poisson) link function on secret-shared eta
# using DCF-based piecewise-linear spline approximation.
#
# Protocol flow (client orchestrates):
#   1. Client: k2-dcf-gen-batch → DCF keys
#   2. Server: k2StoreDcfKeysDS ← receive + store keys from blob
#   3. Server: k2DcfEvalDS(phase=1) → masked values for relay
#   4. Client: relay masked values between servers
#   5. Server: k2DcfEvalDS(phase=2) → comparison shares
#   6. Server: k2SplineIndicatorsDS → slope/intercept/indicator shares (LOCAL)
#   7. Server: k2BeaverRoundFPDS (reuse) → I_mid = NOT(c_low) * c_high
#   8. Server: k2BeaverRoundFPDS (reuse) → Hadamard slope*x, I_mid*spline
#   9. Server: k2SplineAssembleDS → mu = I_high + I_mid*spline

# ============================================================================
# k2StoreDcfKeysDS: receive DCF keys from blob, store in session
# ============================================================================
k2StoreDcfKeysDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  dcf_blob <- .blob_consume("k2_dcf_keys", ss)
  if (is.null(dcf_blob)) stop("No DCF keys blob found in session")
  ss$k2_dcf_keys <- dcf_blob
  return(list(status = "ok", dcf_keys_stored = TRUE))
}

# ============================================================================
# k2DcfEvalDS: evaluate DCF on this party's eta share
# phase=1: compute masked values → return for relay
# phase=2: combine with peer masked → comparison shares
# ============================================================================
k2DcfEvalDS <- function(phase = 1L, party_id = 0L, family = "binomial",
                         num_intervals = NULL, frac_bits = 20L,
                         session_id = NULL) {
  ss <- .S(session_id)

  if (is.null(num_intervals)) {
    num_intervals <- if (family == "poisson") 100L else 50L
  }

  # Number of thresholds: 2 broad + (num_intervals - 1) sub
  num_thresh <- 2L + num_intervals - 1L

  # Get eta share from session (stored by k2ComputeEtaShareDS)
  eta_fp <- ss$k2_eta_share_fp
  if (is.null(eta_fp)) stop("No eta share in session. Call k2ComputeEtaShareDS first.")
  # eta_fp is a base64 string. Each FP element = 8 bytes. base64: 4 chars = 3 bytes.
  n <- as.integer(nchar(eta_fp) * 3 / 4 / 8)

  # Get DCF keys from session
  dcf_keys_b64 <- ss$k2_dcf_keys
  if (is.null(dcf_keys_b64)) stop("No DCF keys in session. Call k2StoreDcfKeysDS first.")

  if (phase == 1L) {
    result <- .callMheTool("k2-dcf-eval", list(
      phase = 1L,
      party_id = party_id,
      eta_share_fp = .base64url_to_base64(eta_fp),
      dcf_keys = .base64url_to_base64(dcf_keys_b64),
      n = n,
      frac_bits = frac_bits,
      num_thresh = num_thresh
    ))
    # Store own masked values for phase 2 recomputation
    ss$k2_dcf_own_masked <- result$masked_values
    # Return masked values for relay (convert to base64url for DataSHIELD transport)
    return(list(
      masked_values = base64_to_base64url(result$masked_values),
      n = n, num_thresh = num_thresh
    ))

  } else {
    # Phase 2: consume peer's masked values from blob
    peer_masked_b64url <- .blob_consume("k2_dcf_peer_masked", ss)
    if (is.null(peer_masked_b64url)) stop("No peer masked values blob")

    result <- .callMheTool("k2-dcf-eval", list(
      phase = 2L,
      party_id = party_id,
      eta_share_fp = .base64url_to_base64(eta_fp),
      dcf_keys = .base64url_to_base64(dcf_keys_b64),
      peer_masked = .base64url_to_base64(peer_masked_b64url),
      n = n,
      frac_bits = frac_bits,
      num_thresh = num_thresh
    ))

    # Store comparison shares in session
    ss$k2_comparison_shares_fp <- base64_to_base64url(result$comparison_shares)
    # Clean up DCF keys (large, no longer needed)
    ss$k2_dcf_keys <- NULL
    gc()
    return(list(status = "ok", comparisons_computed = TRUE))
  }
}

# ============================================================================
# k2SplineIndicatorsDS: compute slope/intercept/indicator shares locally
# No communication needed — all ScalarVP with public coefficients.
# ============================================================================
k2SplineIndicatorsDS <- function(party_id = 0L, family = "binomial",
                                  num_intervals = NULL, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)

  if (is.null(num_intervals)) {
    num_intervals <- if (family == "poisson") 100L else 50L
  }

  cmp_fp <- ss$k2_comparison_shares_fp
  eta_fp <- ss$k2_eta_share_fp
  if (is.null(cmp_fp)) stop("No comparison shares. Call k2DcfEvalDS phase=2 first.")

  n <- .fp_n_from_b64(eta_fp)

  result <- .callMheTool("k2-spline-indicators", list(
    comparison_shares_fp = .base64url_to_base64(cmp_fp),
    eta_share_fp = .base64url_to_base64(eta_fp),
    family = family,
    party_id = party_id,
    n = n,
    frac_bits = frac_bits,
    num_intervals = num_intervals
  ))

  # Store results in session for subsequent Beaver operations
  ss$k2_slope_share_fp <- base64_to_base64url(result$slope_share_fp)
  ss$k2_intercept_share_fp <- base64_to_base64url(result$intercept_share_fp)
  ss$k2_c_low_share_fp <- base64_to_base64url(result$c_low_share_fp)  # NOT(c_low)
  ss$k2_c_high_share_fp <- base64_to_base64url(result$c_high_share_fp) # c_high
  ss$k2_i_high_fp <- base64_to_base64url(result$i_high_fp)

  # Clean up comparison shares (no longer needed)
  ss$k2_comparison_shares_fp <- NULL

  return(list(status = "ok", indicators_computed = TRUE))
}

# ============================================================================
# k2SplineAssembleDS: final assembly mu = I_high + I_mid * spline
# Called after Beaver AND (I_mid) and Hadamard (slope*x, I_mid*spline).
# ============================================================================
k2SplineAssembleDS <- function(party_id = 0L, family = "binomial",
                                frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)

  i_high_fp <- ss$k2_i_high_fp
  mid_spline_fp <- ss$k2_mid_spline_share_fp  # from Hadamard I_mid*spline

  if (is.null(mid_spline_fp)) stop("No I_mid*spline share. Run Hadamard first.")

  n <- .fp_n_from_b64(i_high_fp)

  result <- .callMheTool("k2-spline-assemble", list(
    family = family,
    party_id = party_id,
    i_high_fp = .base64url_to_base64(i_high_fp),
    mid_spline_fp = .base64url_to_base64(mid_spline_fp),
    n = n,
    frac_bits = frac_bits
  ))

  # Store mu share in session (used by gradient computation)
  ss$k2_mu_share_fp <- base64_to_base64url(result$mu_share_fp)
  ss$secure_mu_share <- result$mu_share_fp  # gradient functions read this key

  # Clean up intermediates
  ss$k2_slope_share_fp <- NULL
  ss$k2_intercept_share_fp <- NULL
  ss$k2_c_low_share_fp <- NULL
  ss$k2_c_high_share_fp <- NULL
  ss$k2_i_high_fp <- NULL
  ss$k2_mid_spline_share_fp <- NULL

  return(list(status = "ok", mu_computed = TRUE))
}

# ============================================================================
# k2FPAddDS: element-wise Ring63 addition of two session FP vectors.
# Used for: spline_value = slope*x + intercept
# ============================================================================
k2FPAddDS <- function(a_key, b_key, result_key, frac_bits = 20L,
                       session_id = NULL) {
  ss <- .S(session_id)
  a_fp <- ss[[a_key]]
  b_fp <- ss[[b_key]]
  if (is.null(a_fp)) stop("Session key '", a_key, "' not found")
  if (is.null(b_fp)) stop("Session key '", b_key, "' not found")

  result <- .callMheTool("k2-fp-add", list(
    a = .base64url_to_base64(a_fp),
    b = .base64url_to_base64(b_fp),
    frac_bits = frac_bits
  ))

  ss[[result_key]] <- base64_to_base64url(result$result)
  return(list(status = "ok", stored = result_key))
}

# ============================================================================
# k2ScaleIndicatorFPDS: scale I_mid (integer share from Beaver AND) to FP.
# I_mid from Beaver AND is in Ring63 integer domain. For Hadamard with
# spline_value (which is FP), we need I_mid scaled: I_mid_fp = I_mid * FracMul.
# This is done via modMulBig63 in Go.
# ============================================================================
k2ScaleIndicatorFPDS <- function(src_key, result_key, frac_bits = 20L,
                                  session_id = NULL) {
  ss <- .S(session_id)
  src_fp <- ss[[src_key]]
  if (is.null(src_fp)) stop("Session key '", src_key, "' not found")

  # Scale integer indicator shares to FP by multiplying each element by FracMul.
  # Uses k2-fp-scale-indicator Go command (modMulBig63 per element).
  result <- .callMheTool("k2-fp-scale-indicator", list(
    data_fp = .ensure_b64(src_fp),
    frac_bits = frac_bits
  ))

  ss[[result_key]] <- result$result
  return(list(status = "ok", stored = result_key))
}

# Helper to normalize base64url to standard base64
.ensure_b64 <- function(x) {
  if (is.null(x) || x == "") return(x)
  x <- gsub("-", "+", gsub("_", "/", x, fixed = TRUE), fixed = TRUE)
  pad <- nchar(x) %% 4
  if (pad == 2) x <- paste0(x, "==")
  if (pad == 3) x <- paste0(x, "=")
  x
}

# Helper: compute n elements from base64(url) FP string (8 bytes per element)
.fp_n_from_b64 <- function(b64str) {
  as.integer(nchar(b64str) * 3 / 4 / 8)
}
