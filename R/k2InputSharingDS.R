#' @title K=2 Input-Sharing Preamble
#' @description Shares each party's local data (X, y) with the other party
#'   via additive secret sharing. After this step, both parties hold shares
#'   of the FULL design matrix and response vector.
#'
#' @details
#' Port of the input-sharing preamble from the Google fss_machine_learning
#' protocol specification. The owner samples a random additive share of the
#' same shape and sends the complementary share (transport-encrypted) to
#' the peer. At no point does a party send its raw data.
#'
#' After the preamble, each party can compute:
#'   X_full_share^T * residual_share
#' locally — no cross-gradient Beaver needed.
#'
#' @name k2-input-sharing
NULL

#' Share local data with peer for K=2 secure training
#'
#' The owner computes: own_share = random, peer_share = data - random.
#' Sends peer_share transport-encrypted. Both parties end up with additive
#' shares of the data that sum to the original.
#'
#' @param data_name Character. Standardized data frame name.
#' @param x_vars Character vector. Feature columns.
#' @param y_var Character or NULL. Response variable (label only).
#' @param peer_pk Character. Peer's transport public key.
#' @param session_id Character or NULL.
#' @return List with encrypted_peer_share (base64url) for relay.
#' @export
k2ShareInputDS <- function(data_name, x_vars, y_var = NULL,
                             peer_pk, session_id = NULL) {
  ss <- .S(session_id)

  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p <- ncol(X)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level)
    stop("Insufficient observations", call. = FALSE)
  .check_glm_disclosure(X)

  # Flatten X to vector (row-major)
  x_flat <- as.numeric(t(X))

  # Generate random share (own) and complement (peer)
  # Use mhe-tool to generate in FixedPoint-exact, then convert to float
  # Actually: for the gradient computation, we work in float64 (not FP shares)
  # because the gradient dot-product is done in float64 arithmetic.
  # The shares just need to be random and sum to the original.
  own_share_x <- runif(length(x_flat), -100, 100)
  peer_share_x <- x_flat - own_share_x

  # Store own share
  ss$k2_x_share <- own_share_x
  ss$k2_x_n <- n
  ss$k2_x_p <- p

  # Handle y (label only)
  encrypted_y <- NULL
  if (!is.null(y_var)) {
    y <- as.numeric(data[[y_var]])
    own_share_y <- runif(n, -100, 100)
    peer_share_y <- y - own_share_y
    ss$k2_y_share <- own_share_y
    # Transport-encrypt y peer share
    pk <- .base64url_to_base64(peer_pk)
    sealed_y <- .callMheTool("transport-encrypt-vectors", list(
      vectors = list(y = peer_share_y),
      recipient_pk = pk
    ))
    encrypted_y <- base64_to_base64url(sealed_y$sealed)
  }

  # Transport-encrypt X peer share
  pk <- .base64url_to_base64(peer_pk)
  sealed_x <- .callMheTool("transport-encrypt-vectors", list(
    vectors = list(x = peer_share_x),
    recipient_pk = pk
  ))

  list(
    encrypted_x_share = base64_to_base64url(sealed_x$sealed),
    encrypted_y_share = encrypted_y,
    n = n,
    p = p
  )
}

#' Receive peer's shared data for K=2 secure training
#'
#' @param peer_n Integer. Peer's number of observations (for validation).
#' @param peer_p Integer. Peer's number of features.
#' @param session_id Character or NULL.
#' @return List with stored = TRUE.
#' @export
k2ReceiveShareDS <- function(peer_n = NULL, peer_p = NULL, session_id = NULL) {
  ss <- .S(session_id)
  tsk <- .key_get("transport_sk", ss)

  # Decrypt peer's X share
  x_blob <- .blob_consume("k2_peer_x_share", ss)
  if (!is.null(x_blob)) {
    dec <- .callMheTool("transport-decrypt-vectors", list(
      sealed = .base64url_to_base64(x_blob),
      recipient_sk = tsk
    ))
    ss$k2_peer_x_share <- as.numeric(dec$vectors$x)
    ss$k2_peer_p <- as.integer(peer_p)
  }

  # Decrypt peer's y share (if available — only nonlabel receives this)
  y_blob <- .blob_consume("k2_peer_y_share", ss)
  if (!is.null(y_blob)) {
    dec <- .callMheTool("transport-decrypt-vectors", list(
      sealed = .base64url_to_base64(y_blob),
      recipient_sk = tsk
    ))
    ss$k2_y_share <- as.numeric(dec$vectors$y)
  }

  list(stored = TRUE)
}

#' Compute gradient share from the full shared data
#'
#' After the input-sharing preamble, each party has shares of the FULL
#' X and y. The gradient is: X_full_share^T * (mu_share - y_share).
#'
#' @param mu_share Numeric vector. This party's share of mu (from poly eval).
#' @param session_id Character or NULL.
#' @return List with gradient (p_total scalars), sum_residual (1 scalar).
#' @export
k2ComputeGradientShareDS <- function(mu_share = NULL, session_id = NULL) {
  ss <- .S(session_id)

  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p
  p_total <- p_own + p_peer

  # Assemble full X share (own block + peer's shared block)
  x_own <- ss$k2_x_share
  x_peer <- ss$k2_peer_x_share

  # Get mu_share from session if not passed
  if (is.null(mu_share)) {
    mu_fp <- ss$secure_mu_share
    if (is.null(mu_fp)) stop("No mu share found", call. = FALSE)
    mu_share <- .callMheTool("mpc-fp-to-float", list(
      fp_data = mu_fp, frac_bits = 20L))$values
  }

  # Residual share = mu_share - y_share
  y_share <- ss$k2_y_share
  if (is.null(y_share)) y_share <- rep(0, n)

  residual_share <- as.numeric(mu_share) - y_share

  # Gradient: [X_own | X_peer]^T * residual_share
  # = [X_own^T * residual_share, X_peer^T * residual_share]
  gradient <- numeric(p_total)

  # Own block gradient
  for (j in seq_len(p_own)) {
    for (i in seq_len(n)) {
      gradient[j] <- gradient[j] + x_own[(i - 1) * p_own + j] * residual_share[i]
    }
  }

  # Peer block gradient
  for (j in seq_len(p_peer)) {
    for (i in seq_len(n)) {
      gradient[p_own + j] <- gradient[p_own + j] +
        x_peer[(i - 1) * p_peer + j] * residual_share[i]
    }
  }

  list(
    gradient = gradient,
    sum_residual = sum(residual_share)
  )
}

#' Compute eta share from full data shares and public beta
#'
#' Each party computes: eta_share = X_full_share * beta + intercept_share
#' where X_full_share = [X_own_share | X_peer_share] and beta is public.
#'
#' @param beta_coord Numeric vector. Coordinator block coefficients (public).
#' @param beta_nl Numeric vector. Non-label block coefficients (public).
#' @param intercept Numeric. Intercept (added by party 0 only).
#' @param is_coordinator Logical. TRUE for party 0 (coordinator).
#' @param session_id Character or NULL.
#' @return List with eta_share stored in session.
#' @export
k2ComputeEtaShareDS <- function(beta_coord, beta_nl, intercept = 0.0,
                                  is_coordinator = TRUE, session_id = NULL) {
  ss <- .S(session_id)

  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p

  x_own <- ss$k2_x_share      # own block share (n * p_own)
  x_peer <- ss$k2_peer_x_share # peer block share (n * p_peer)

  # Determine beta ordering: coordinator block first, then nonlabel
  if (is_coordinator) {
    beta_own <- as.numeric(beta_coord)
    beta_peer <- as.numeric(beta_nl)
  } else {
    beta_own <- as.numeric(beta_nl)
    beta_peer <- as.numeric(beta_coord)
  }

  # eta_share[i] = sum_j X_own_share[i,j] * beta_own[j] + sum_j X_peer_share[i,j] * beta_peer[j]
  eta_share <- numeric(n)
  for (i in seq_len(n)) {
    for (j in seq_len(p_own)) {
      eta_share[i] <- eta_share[i] + x_own[(i - 1) * p_own + j] * beta_own[j]
    }
    for (j in seq_len(p_peer)) {
      eta_share[i] <- eta_share[i] + x_peer[(i - 1) * p_peer + j] * beta_peer[j]
    }
  }

  # Party 0 (coordinator) adds intercept
  if (is_coordinator) {
    eta_share <- eta_share + intercept
  }

  # Store in session for Beaver polynomial eval
  # Convert to FixedPoint for the Beaver pipeline
  fp_result <- .callMheTool("k2-float-to-fp", list(
    values = eta_share, frac_bits = 20L))
  ss$k2_eta_share <- fp_result$fp_data
  # Also store as "secure_eta_share" for compatibility with poly_eval step
  ss$secure_eta_share <- fp_result$fp_data

  list(stored = TRUE, n = n)
}

#' Beaver matrix-vector gradient: Round 1
#'
#' Computes (X_share - A) and (r_share - B) for the Beaver protocol.
#' The residual share is computed from mu_share (from poly_eval) minus y_share.
#'
#' @param peer_pk Character. Peer's transport PK.
#' @param session_id Character or NULL.
#' @return List with encrypted_round1_msg (for relay to peer).
#' @export
k2BeaverGradientR1DS <- function(peer_pk, session_id = NULL) {
  ss <- .S(session_id)

  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p
  p_total <- p_own + p_peer

  # Assemble full X share (own block + peer's shared block)
  x_own <- ss$k2_x_share
  x_peer <- ss$k2_peer_x_share

  # Get mu_share from polynomial eval (FP -> float)
  mu_fp <- ss$secure_mu_share
  if (is.null(mu_fp)) stop("No mu share found", call. = FALSE)
  mu_share <- .callMheTool("mpc-fp-to-float", list(
    fp_data = mu_fp, frac_bits = 20L))$values

  # Residual share = mu_share - y_share
  y_share <- ss$k2_y_share
  if (is.null(y_share)) y_share <- rep(0, n)
  residual_share <- mu_share - y_share

  # Full X share (row-major, p_total columns)
  x_full <- numeric(n * p_total)
  for (i in seq_len(n)) {
    for (j in seq_len(p_own)) {
      x_full[(i - 1) * p_total + j] <- x_own[(i - 1) * p_own + j]
    }
    for (j in seq_len(p_peer)) {
      x_full[(i - 1) * p_total + p_own + j] <- x_peer[(i - 1) * p_peer + j]
    }
  }

  # Get Beaver triple from blob (float64 format)
  triple_blob <- .blob_consume("k2_grad_triple", ss)
  if (is.null(triple_blob)) stop("No gradient Beaver triple", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt-vectors", list(
    sealed = .base64url_to_base64(triple_blob),
    recipient_sk = tsk
  ))
  a_share <- as.numeric(dec$vectors$a)
  b_share <- as.numeric(dec$vectors$b)

  # Store for round 2
  ss$k2_grad_a <- a_share
  ss$k2_grad_b <- b_share
  ss$k2_grad_x_full <- x_full
  ss$k2_grad_residual <- residual_share

  # Compute round 1: (X - A) and (r - B)
  result <- .callMheTool("k2-beaver-matvec-r1", list(
    x_share = x_full,
    r_share = residual_share,
    a_share = a_share,
    b_share = b_share,
    n = as.integer(n),
    p = as.integer(p_total),
    frac_bits = 20L
  ))

  # Transport-encrypt for peer
  pk <- .base64url_to_base64(peer_pk)
  sealed <- .callMheTool("transport-encrypt-vectors", list(
    vectors = list(xma = result$x_minus_a, rmb = result$r_minus_b),
    recipient_pk = pk
  ))

  list(
    encrypted_round1 = base64_to_base64url(sealed$sealed),
    sum_residual = sum(residual_share)
  )
}

#' Beaver matrix-vector gradient: Round 2
#'
#' Receives peer's round-1 message, computes gradient share.
#'
#' @param party_id Integer. 0 or 1.
#' @param session_id Character or NULL.
#' @return List with gradient_share (p_total scalars).
#' @export
k2BeaverGradientR2DS <- function(party_id = 0L, session_id = NULL) {
  ss <- .S(session_id)

  n <- ss$k2_x_n
  p_total <- ss$k2_x_p + ss$k2_peer_p

  # Decrypt peer's round-1 message
  blob <- .blob_consume("k2_grad_peer_r1", ss)
  if (is.null(blob)) stop("No peer round-1 message", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt-vectors", list(
    sealed = .base64url_to_base64(blob),
    recipient_sk = tsk
  ))

  # Get C share from blob
  c_blob <- .blob_consume("k2_grad_c", ss)
  if (is.null(c_blob)) stop("No C triple share", call. = FALSE)
  c_dec <- .callMheTool("transport-decrypt-vectors", list(
    sealed = .base64url_to_base64(c_blob),
    recipient_sk = tsk
  ))
  c_share <- as.numeric(c_dec$vectors$c)

  # Own round-1 values
  x_full <- ss$k2_grad_x_full
  residual <- ss$k2_grad_residual
  a_share <- ss$k2_grad_a
  b_share <- ss$k2_grad_b

  own_xma <- x_full - a_share
  own_rmb <- residual - b_share

  # Compute round 2
  result <- .callMheTool("k2-beaver-matvec-r2", list(
    own_x_minus_a = own_xma,
    own_r_minus_b = own_rmb,
    peer_x_minus_a = as.numeric(dec$vectors$xma),
    peer_r_minus_b = as.numeric(dec$vectors$rmb),
    a_share = a_share,
    b_share = b_share,
    c_share = c_share,
    n = as.integer(n),
    p = as.integer(p_total),
    party_id = as.integer(party_id)
  ))

  list(gradient_share = result$gradient_share)
}
