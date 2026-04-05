#' @title K=2 Strict Mode: Chebyshev Beaver MPC Server Functions
#' @description Server-side functions for the improved K=2 strict mode using
#'   Chebyshev polynomial evaluation via Beaver triples with asymmetric
#'   truncation. These replace the old HE-Link polynomial path for K=2
#'   binomial/Poisson with much better accuracy (~7e-3 vs ~5e-2).
#'
#' @details
#' The protocol evaluates sigmoid (binomial) or exp (Poisson) on secret-shared
#' eta values using a degree-7 Chebyshev polynomial. The Beaver power chain
#' computes [x^2], [x^3], ..., [x^7] in 6 rounds, then the polynomial
#' combination is computed locally by each party.
#'
#' Security: all computation is on additive secret shares. The client relay
#' sees only transport-encrypted blobs. Neither party reconstructs eta, mu,
#' residuals, or weights during training — only p_k gradient scalars and
#' 2 intercept scalars are revealed per iteration.
#'
#' @name k2-strict
NULL

# ============================================================================
# Step 0: Get Chebyshev polynomial coefficients
# ============================================================================

#' Get Chebyshev polynomial coefficients for K=2 strict mode
#'
#' @param family Character. "binomial" or "poisson".
#' @param degree Integer. Polynomial degree (default 7).
#' @return List with coefficients, max_error, degree, lower, upper.
#' @export
k2ChebyshevCoeffsDS <- function(family = "binomial", degree = 7L) {
  input <- list(family = family, degree = as.integer(degree))
  .callMheTool("k2-chebyshev-coeffs", input)
}

# ============================================================================
# Step 1: Split eta into additive shares and transport-encrypt for peer
# ============================================================================

#' Compute eta and create additive share for K=2 strict Beaver protocol
#'
#' Each party computes eta_k = X_k * beta_k, converts to fixed-point,
#' splits into additive shares, and transport-encrypts the peer's share.
#'
#' @param data_name Character. Standardized data frame name.
#' @param x_vars Character vector. Feature column names.
#' @param beta Numeric vector. Current coefficients.
#' @param peer_pk Character. Peer's transport public key (base64url).
#' @param frac_bits Integer. Fixed-point fractional bits.
#' @param session_id Character or NULL.
#' @return List with peer_share_enc (base64url) and n_obs.
#' @export
k2StrictSplitEtaDS <- function(data_name, x_vars, beta, peer_pk,
                                 frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level)
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  .check_glm_disclosure(X)

  beta <- as.numeric(beta)
  if (length(beta) != ncol(X))
    stop("beta length mismatch", call. = FALSE)

  # Compute eta_k = X_k * beta_k
  eta_k <- as.numeric(X %*% beta)

  # Split via Go mpc-split-eta (reuse existing command)
  input <- list(
    eta = eta_k,
    peer_pk = .base64url_to_base64(peer_pk),
    frac_bits = as.integer(frac_bits)
  )
  result <- .callMheTool("mpc-split-eta", input)

  # Store own share for later use
  ss$k2_own_eta_share <- result$own_share

  list(
    peer_share_enc = base64_to_base64url(result$peer_share_enc),
    n_obs = n
  )
}

# ============================================================================
# Step 2: Combine eta shares
# ============================================================================

#' Combine own and peer eta shares for K=2 strict mode
#'
#' @param session_id Character or NULL.
#' @return List with stored = TRUE.
#' @export
k2StrictCombineEtaDS <- function(session_id = NULL) {
  ss <- .S(session_id)

  own_share <- ss$k2_own_eta_share
  if (is.null(own_share)) stop("Own eta share not found", call. = FALSE)

  peer_enc <- .blob_consume("k2_peer_eta_share", ss)
  if (is.null(peer_enc)) stop("Peer eta share not found", call. = FALSE)

  tsk <- .key_get("transport_sk", ss)
  peer_dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_enc),
    recipient_sk = tsk
  ))

  # Add shares: combined = own + peer (still shares of eta_total)
  combined <- .callMheTool("mpc-vec-add", list(
    a = own_share,
    b = peer_dec$data
  ))
  ss$k2_eta_share <- combined$result
  list(stored = TRUE)
}

# ============================================================================
# Step 2b: Initialize x^0 = 1 constant share
# ============================================================================

#' Initialize the constant x^0 = 1 share for polynomial evaluation
#'
#' Party 0 holds vector of 1.0 (in FixedPoint), Party 1 holds vector of 0.
#' Stored as session key "k2_one_share".
#'
#' @param party_id Integer. 0 or 1.
#' @param n_obs Integer. Number of observations.
#' @param frac_bits Integer. Fixed-point fractional bits.
#' @param session_id Character or NULL.
#' @return List with stored = TRUE.
#' @export
k2StrictInitOneShareDS <- function(party_id = 0L, n_obs, frac_bits = 20L,
                                     session_id = NULL) {
  ss <- .S(session_id)

  n <- as.integer(n_obs)

  # Party 0 holds 1.0 in FixedPoint for each observation.
  # Party 1 holds 0 for each observation.
  # Together: share0 + share1 = 1.0 (in fixed-point ring).
  if (as.integer(party_id) == 0L) {
    vals <- rep(1.0, n)
  } else {
    vals <- rep(0.0, n)
  }

  # Convert float64 values to base64 FixedPoint (no secret sharing — direct encoding)
  result <- .callMheTool("k2-float-to-fp", list(
    values = vals,
    frac_bits = as.integer(frac_bits)
  ))
  ss$k2_one_share <- result$fp_data

  list(stored = TRUE)
}

# ============================================================================
# Step 3: Beaver power chain + polynomial evaluation
# ============================================================================

#' Run one round of Beaver multiplication for K=2 strict power chain
#'
#' @param a_share_key Character. Session key for input a shares.
#' @param b_share_key Character. Session key for input b shares.
#' @param result_key Character. Session key to store result.
#' @param peer_pk Character. Peer's transport PK (base64url).
#' @param party_id Integer. 0 or 1.
#' @param frac_bits Integer.
#' @param session_id Character or NULL.
#' @return List with peer_msg_enc (base64url) in round 1, or stored key in round 2.
#' @export
k2StrictBeaverRoundDS <- function(step = "round1",
                                    a_share_key = NULL, b_share_key = NULL,
                                    result_key = NULL,
                                    peer_pk = NULL, party_id = 0L,
                                    frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)

  if (step == "round1") {
    a_share <- ss[[a_share_key]]
    b_share <- ss[[b_share_key]]

    # Beaver triples are stored in session by the triple-distribution step
    # that runs before each round. If not present, use the pre-existing
    # Beaver triples from the old MPC path.
    beaver_a <- ss$k2_beaver_a
    beaver_b <- ss$k2_beaver_b
    beaver_c <- ss$k2_beaver_c

    if (is.null(beaver_a)) {
      # Fallback: consume from blob (sent by client triple distribution)
      triple_blob <- .blob_consume("k2_beaver_triple", ss)
      if (!is.null(triple_blob)) {
        tsk <- .key_get("transport_sk", ss)
        dec <- .callMheTool("transport-decrypt-vectors", list(
          sealed = .base64url_to_base64(triple_blob),
          recipient_sk = tsk
        ))
        beaver_a <- dec$vectors$u
        beaver_b <- dec$vectors$v
        beaver_c <- dec$vectors$w
      } else {
        stop("No Beaver triples available", call. = FALSE)
      }
    }

    result <- .callMheTool("k2-beaver-mul", list(
      x_share = a_share,
      y_share = b_share,
      a_share_f64 = as.numeric(beaver_a),
      b_share_f64 = as.numeric(beaver_b),
      c_share_f64 = as.numeric(beaver_c),
      party_id = as.integer(party_id),
      frac_bits = as.integer(frac_bits)
    ))

    # Store own round-1 message
    ss$k2_own_xma <- result$own_x_minus_a
    ss$k2_own_ymb <- result$own_y_minus_b
    # Store triples for round2
    ss$k2_last_beaver_a <- beaver_a
    ss$k2_last_beaver_b <- beaver_b
    ss$k2_last_beaver_c <- beaver_c

    # Transport-encrypt the round-1 message (base64 FixedPoint blobs) for peer.
    # Encode as JSON, then base64-encode the JSON for transport-encrypt (which
    # expects base64-encoded binary data).
    msg_json <- jsonlite::toJSON(list(
      xma = result$own_x_minus_a,
      ymb = result$own_y_minus_b
    ), auto_unbox = TRUE)
    msg_b64 <- jsonlite::base64_enc(charToRaw(msg_json))
    pk <- .base64url_to_base64(peer_pk)
    sealed <- .callMheTool("transport-encrypt", list(
      data = msg_b64,
      recipient_pk = pk
    ))

    return(list(peer_msg_enc = base64_to_base64url(sealed$sealed)))

  } else if (step == "round2") {
    # Receive peer's round-1 message (transport-encrypted base64-encoded JSON)
    peer_enc <- .blob_consume("k2_beaver_peer_msg", ss)
    tsk <- .key_get("transport_sk", ss)
    peer_dec <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(peer_enc),
      recipient_sk = tsk
    ))
    # Decode: base64 → JSON → R list
    peer_json <- rawToChar(jsonlite::base64_dec(peer_dec$data))
    peer_msg <- jsonlite::fromJSON(peer_json)

    # Retrieve Beaver triples (same ones used in round1)
    beaver_a <- ss$k2_last_beaver_a
    beaver_b <- ss$k2_last_beaver_b
    beaver_c <- ss$k2_last_beaver_c

    result <- .callMheTool("k2-beaver-mul", list(
      x_share = ss[[a_share_key]],
      y_share = ss[[b_share_key]],
      a_share_f64 = as.numeric(beaver_a),
      b_share_f64 = as.numeric(beaver_b),
      c_share_f64 = as.numeric(beaver_c),
      peer_x_minus_a = peer_msg$xma,
      peer_y_minus_b = peer_msg$ymb,
      party_id = as.integer(party_id),
      frac_bits = as.integer(frac_bits)
    ))

    ss[[result_key]] <- result$result_share
    return(list(stored = result_key))
  }

  stop("Unknown step: ", step, call. = FALSE)
}

# ============================================================================
# Step 4: Local polynomial evaluation
# ============================================================================

#' Evaluate Chebyshev polynomial locally on power shares
#'
#' @param power_keys Character vector. Session keys for [x^0], [x^1], ..., [x^d].
#' @param coefficients Numeric vector. Chebyshev monomial coefficients.
#' @param party_id Integer. 0 or 1.
#' @param frac_bits Integer.
#' @param session_id Character or NULL.
#' @return List with stored = "k2_mu_share".
#' @export
k2StrictPolyEvalDS <- function(power_keys, coefficients,
                                 party_id = 0L, frac_bits = 20L,
                                 session_id = NULL) {
  ss <- .S(session_id)

  power_shares <- lapply(power_keys, function(k) ss[[k]])

  result <- .callMheTool("k2-poly-eval-local", list(
    power_shares = power_shares,
    coefficients = as.numeric(coefficients),
    party_id = as.integer(party_id),
    frac_bits = as.integer(frac_bits)
  ))

  ss$k2_mu_share <- result$result_share
  list(stored = "k2_mu_share")
}

# ============================================================================
# Step 5: Compute residual and gradient shares
# ============================================================================

#' Compute gradient for K=2 strict mode (label step)
#'
#' Label party: receives non-label's mu_share (from blob), reconstructs
#' mu = mu_share_label + mu_share_nonlabel, computes residual = mu - y,
#' computes own gradient X_label^T * residual, and transport-encrypts
#' the residual for the non-label party.
#'
#' Non-label party: decrypts the residual from the label and computes
#' X_nonlabel^T * residual.
#'
#' Security: the label sees mu (the sigmoid/exp output), NOT eta or
#' individual features. mu = sigmoid(eta_total) is a lossy function —
#' individual feature contributions cannot be recovered.
#'
#' @param data_name Character. Standardized data frame name.
#' @param x_vars Character vector. Feature column names.
#' @param y_var Character or NULL. Response variable (label party only).
#' @param role Character. "label" or "nonlabel".
#' @param peer_pk Character or NULL. Peer's transport PK (label sends residual to nonlabel).
#' @param frac_bits Integer.
#' @param session_id Character or NULL.
#' @return List with gradient (p_k scalars), sum_residual (1 scalar),
#'   and encrypted_residual (label only, for relay to nonlabel).
#' @export
k2StrictGradientDS <- function(data_name, x_vars, y_var = NULL,
                                 role = "label", peer_pk = NULL,
                                 frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)

  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)

  if (role == "label") {
    # Label: reconstruct mu from both FixedPoint shares (ring add first, then float)

    # Own mu share (base64 FixedPoint)
    own_mu_b64 <- ss$k2_mu_share
    if (is.null(own_mu_b64))
      stop("No mu share found", call. = FALSE)

    # Peer's mu share (transport-encrypted, contains base64-encoded FP string)
    peer_mu_blob <- .blob_consume("k2_peer_mu_share", ss)
    if (!is.null(peer_mu_blob)) {
      tsk <- .key_get("transport_sk", ss)
      peer_mu_dec <- .callMheTool("transport-decrypt", list(
        sealed = .base64url_to_base64(peer_mu_blob),
        recipient_sk = tsk
      ))
      # Decode: the decrypted data is a base64-encoded string of the FP base64
      peer_mu_b64 <- rawToChar(jsonlite::base64_dec(peer_mu_dec$data))
    } else {
      peer_mu_b64 <- NULL
    }

    # Reconstruct mu by RING ADD of FixedPoint shares, THEN convert to float
    if (!is.null(peer_mu_b64)) {
      mu_total_b64 <- .callMheTool("mpc-vec-add", list(
        a = own_mu_b64, b = peer_mu_b64))$result
    } else {
      mu_total_b64 <- own_mu_b64
    }
    mu <- .callMheTool("mpc-fp-to-float", list(
      fp_data = mu_total_b64, frac_bits = as.integer(frac_bits)))$values

    # Compute residual
    y <- as.numeric(data[[y_var]])
    residual <- mu - y

    # Gradient: X_label^T * residual
    gradient <- as.numeric(crossprod(X, residual))
    sum_residual <- sum(residual)

    # Transport-encrypt residual for non-label (so it can compute its gradient)
    encrypted_residual <- NULL
    if (!is.null(peer_pk)) {
      pk <- .base64url_to_base64(peer_pk)
      sealed <- .callMheTool("transport-encrypt-vectors", list(
        vectors = list(residual = as.numeric(residual)),
        recipient_pk = pk
      ))
      encrypted_residual <- base64_to_base64url(sealed$sealed)
    }

    return(list(
      gradient = gradient,
      sum_residual = sum_residual,
      encrypted_residual = encrypted_residual
    ))

  } else {
    # Non-label: send mu_share to label, then decrypt residual and compute gradient

    # Send raw base64 FixedPoint mu_share to label (transport-encrypted)
    own_mu_b64 <- ss$k2_mu_share
    if (is.null(own_mu_b64))
      stop("No mu share found", call. = FALSE)

    encrypted_mu <- NULL
    if (!is.null(peer_pk)) {
      pk <- .base64url_to_base64(peer_pk)
      # Encrypt the base64 FixedPoint string directly
      sealed <- .callMheTool("transport-encrypt", list(
        data = jsonlite::base64_enc(charToRaw(own_mu_b64)),
        recipient_pk = pk
      ))
      encrypted_mu <- base64_to_base64url(sealed$sealed)
    }

    # Decrypt residual from label (from blob, may not be available yet)
    residual_blob <- .blob_consume("k2_residual", ss)
    if (!is.null(residual_blob)) {
      tsk <- .key_get("transport_sk", ss)
      dec <- .callMheTool("transport-decrypt-vectors", list(
        sealed = .base64url_to_base64(residual_blob),
        recipient_sk = tsk
      ))
      residual <- as.numeric(dec$vectors$residual)
      gradient <- as.numeric(crossprod(X, residual))
      sum_residual <- sum(residual)
    } else {
      gradient <- rep(0, ncol(X))
      sum_residual <- 0
    }

    return(list(
      gradient = gradient,
      sum_residual = sum_residual,
      encrypted_mu = encrypted_mu
    ))
  }
}
