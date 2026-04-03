#' @title K=2 MPC GLM Protocol - Server-Side Functions
#' @description Server-side functions for the 2-party MPC GLM protocol (K=2).
#'   These evaluate the inverse link function (sigmoid for binomial, exp for
#'   Poisson) using piecewise polynomial approximation on secret-shared values,
#'   achieving near-exact coefficient recovery (~1e-3 error vs centralized).
#'
#' @details
#' The protocol replaces the CKKS polynomial HE-Link pathway for K=2
#' binomial/Poisson with additive secret sharing. Each MPC command is
#' stateless (same pattern as all other mhe-tool commands) and the client
#' orchestrates the protocol by relaying transport-encrypted shares.
#'
#' Per-iteration protocol:
#' \enumerate{
#'   \item Each server splits eta_k into shares, transport-encrypts peer's share
#'   \item Coordinator reconstructs eta_total, evaluates piecewise sigmoid/exp,
#'         splits result into new shares
#'   \item Both servers compute residual shares (label subtracts y)
#'   \item Both servers compute gradient shares (X_k^T * residual_share)
#'   \item Gradient shares are exchanged so each server reconstructs only its
#'         own gradient
#'   \item Coefficients updated locally via gradient descent
#' }
#'
#' @name k2-mpc-protocol
NULL

# ============================================================================
# Step 1: Split eta_k into additive shares
# ============================================================================

#' Split linear predictor into additive secret shares
#'
#' Computes eta_k = X_k * beta_k in plaintext, then splits it into two
#' additive shares. The peer's share is transport-encrypted under the peer's
#' public key. The own share is stored in the session.
#'
#' @param data_name Character. Name of the (standardized) data frame.
#' @param x_vars Character vector. Feature column names on this server.
#' @param beta Numeric vector. Current coefficients for this server's block.
#' @param peer_pk Character. Peer's transport public key (base64url).
#' @param frac_bits Integer. Fixed-point fractional bits. Default 20.
#' @param session_id Character or NULL.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{peer_share_enc}: base64url transport-encrypted peer share
#'     \item \code{num_obs}: number of observations
#'   }
#'
#' @export
k2MpcSplitEtaDS <- function(data_name, x_vars, beta, peer_pk,
                              frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)

  beta <- as.numeric(beta)
  if (length(beta) != ncol(X)) {
    stop("beta length (", length(beta), ") != number of variables (",
         ncol(X), ")", call. = FALSE)
  }

  # Compute eta_k = X_k * beta_k in plaintext
  eta_k <- as.numeric(X %*% beta)

  # Split into shares via Go mpc-split-eta
  input <- list(
    eta = eta_k,
    peer_pk = .base64url_to_base64(peer_pk),
    frac_bits = as.integer(frac_bits)
  )

  result <- .callMheTool("mpc-split-eta", input)

  # Store own share in session for later use
  ss$mpc_own_eta_share <- result$own_share

  list(
    peer_share_enc = base64_to_base64url(result$peer_share_enc),
    num_obs = n
  )
}

# ============================================================================
# Step 2: Evaluate link function on reconstructed eta (coordinator only)
# ============================================================================

#' Evaluate piecewise link function on eta_total (coordinator)
#'
#' Called on the coordinator (label server) after receiving the non-label
#' server's transport-encrypted eta share. Reconstructs eta_total from both
#' shares, evaluates the piecewise sigmoid/exp, and splits the result into
#' new shares.
#'
#' @param family Character. "binomial" or "poisson".
#' @param peer_share_key Character. Blob key where the peer's eta share
#'   (transport-encrypted) is stored.
#' @param peer_pk Character. Peer's transport public key (base64url) for
#'   encrypting the output mu share.
#' @param frac_bits Integer. Fixed-point fractional bits.
#' @param session_id Character or NULL.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{peer_mu_share_enc}: base64url transport-encrypted peer's mu share
#'   }
#'
#' @export
k2MpcLinkEvalDS <- function(family, peer_share_key = "mpc_peer_eta_share",
                              peer_pk, frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)

  # Get own eta share from session
  own_eta_share <- ss$mpc_own_eta_share
  if (is.null(own_eta_share)) {
    stop("Own eta share not stored. Call k2MpcSplitEtaDS first.", call. = FALSE)
  }

  # Get peer's transport-encrypted eta share from blob storage
  peer_eta_enc <- .blob_consume(peer_share_key, ss)
  if (is.null(peer_eta_enc)) {
    stop("Peer eta share not found in blob storage.", call. = FALSE)
  }

  # Transport-decrypt the peer's share
  my_sk <- .key_get("transport_sk", ss)
  if (is.null(my_sk)) {
    stop("Transport secret key not available.", call. = FALSE)
  }

  decrypt_result <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(peer_eta_enc),
    recipient_sk = my_sk
  ))
  peer_eta_share <- decrypt_result$data

  # Evaluate link function via Go mpc-link-eval
  input <- list(
    own_eta_share = own_eta_share,
    peer_eta_share = peer_eta_share,
    family = family,
    frac_bits = as.integer(frac_bits),
    peer_pk = .base64url_to_base64(peer_pk)
  )

  result <- .callMheTool("mpc-link-eval", input)

  # Store own mu share for gradient computation
  ss$mpc_own_mu_share <- result$own_mu_share

  list(
    peer_mu_share_enc = base64_to_base64url(result$peer_mu_share_enc)
  )
}

# ============================================================================
# Step 3: Compute residual share (mu_share - y for label)
# ============================================================================

#' Compute residual share
#'
#' Label party: residual_share = mu_share - y.
#' Non-label party: residual_share = mu_share (y contribution is zero).
#'
#' @param data_name Character. Name of the data frame (for y access).
#' @param y_var Character or NULL. Response variable name (label only).
#' @param role Character. "label" or "nonlabel".
#' @param from_storage Logical. If TRUE, read mu_share from blob storage
#'   (non-label server). If FALSE, use session-stored mu_share (coordinator).
#' @param frac_bits Integer. Fixed-point fractional bits.
#' @param session_id Character or NULL.
#'
#' @return List with \code{residual_share_stored = TRUE}.
#'
#' @export
k2MpcResidualDS <- function(data_name = NULL, y_var = NULL, role = "nonlabel",
                              from_storage = FALSE, frac_bits = 20L,
                              session_id = NULL) {
  ss <- .S(session_id)

  # Get mu share
  mu_share <- NULL
  if (from_storage) {
    mu_share_enc <- .blob_consume("mpc_peer_mu_share", ss)
    if (!is.null(mu_share_enc)) {
      my_sk <- .key_get("transport_sk", ss)
      decrypt_result <- .callMheTool("transport-decrypt", list(
        sealed = .base64url_to_base64(mu_share_enc),
        recipient_sk = my_sk
      ))
      mu_share <- decrypt_result$data
    }
  }
  if (is.null(mu_share)) {
    mu_share <- ss$mpc_own_mu_share
  }
  if (is.null(mu_share)) {
    stop("Mu share not available.", call. = FALSE)
  }

  # Get y if label party
  y_vals <- numeric(0)
  if (role == "label" && !is.null(y_var) && !is.null(data_name)) {
    data <- .resolveData(data_name, parent.frame(), session_id)
    y_vals <- as.numeric(data[[y_var]])
  }

  input <- list(
    mu_share = mu_share,
    y = if (length(y_vals) > 0) y_vals else NULL,
    role = role,
    frac_bits = as.integer(frac_bits)
  )

  result <- .callMheTool("mpc-residual", input)

  # Store residual share in session
  ss$mpc_residual_share <- result$residual_share

  list(residual_share_stored = TRUE)
}

# ============================================================================
# Step 4: Compute gradient share (X_k^T * residual_share)
# ============================================================================

#' Compute gradient share from local features and shared residual
#'
#' Computes g_k_share = X_k^T * residual_share. This is a plaintext times
#' share operation (no communication needed). The result is this party's
#' share of the gradient for its feature block.
#'
#' @param data_name Character. Name of the data frame.
#' @param x_vars Character vector. Feature column names.
#' @param num_obs Integer. Number of observations.
#' @param peer_pk Character. Peer's transport PK for encrypting gradient share.
#' @param frac_bits Integer. Fixed-point fractional bits.
#' @param session_id Character or NULL.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{gradient_share_for_peer}: base64url transport-encrypted
#'       gradient share (this party's contribution to the peer's gradient
#'       reconstruction)
#'   }
#'
#' @export
k2MpcGradientDS <- function(data_name, x_vars, num_obs, peer_pk,
                              frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)

  residual_share <- ss$mpc_residual_share
  if (is.null(residual_share)) {
    stop("Residual share not stored. Call k2MpcResidualDS first.", call. = FALSE)
  }

  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  x_list <- lapply(seq_len(nrow(X)), function(i) as.numeric(X[i, ]))

  input <- list(
    x = x_list,
    residual_share = residual_share,
    frac_bits = as.integer(frac_bits),
    n_obs = as.integer(num_obs)
  )

  result <- .callMheTool("mpc-gradient", input)

  # Store own gradient share
  ss$mpc_own_gradient_share <- result$gradient_share

  # Transport-encrypt this gradient share for the peer
  # (the peer needs this to reconstruct ITS gradient, not ours)
  enc_result <- .callMheTool("transport-encrypt", list(
    data = result$gradient_share,
    recipient_pk = .base64url_to_base64(peer_pk)
  ))

  list(
    gradient_share_for_peer = base64_to_base64url(enc_result$sealed)
  )
}

# ============================================================================
# Step 5: Reveal own gradient from shares
# ============================================================================

#' Reconstruct own gradient from own share + peer's share
#'
#' Each server reconstructs only its OWN gradient. The peer's gradient share
#' is transport-decrypted, combined with the local share, and converted to
#' float64.
#'
#' @param from_storage Logical. If TRUE, read peer's gradient share from blob.
#' @param num_obs Integer. Number of observations (for gradient scaling).
#' @param frac_bits Integer. Fixed-point fractional bits.
#' @param session_id Character or NULL.
#'
#' @return List with \code{gradient}: numeric vector (length p_k).
#'
#' @export
k2MpcRevealGradientDS <- function(from_storage = TRUE, num_obs = 1L,
                                    frac_bits = 20L, session_id = NULL) {
  ss <- .S(session_id)

  own_share <- ss$mpc_own_gradient_share
  if (is.null(own_share)) {
    stop("Own gradient share not stored.", call. = FALSE)
  }

  # Get peer's gradient share (transport-encrypted)
  peer_share <- NULL
  if (from_storage) {
    peer_enc <- .blob_consume("mpc_peer_gradient_share", ss)
    if (!is.null(peer_enc)) {
      my_sk <- .key_get("transport_sk", ss)
      decrypt_result <- .callMheTool("transport-decrypt", list(
        sealed = .base64url_to_base64(peer_enc),
        recipient_sk = my_sk
      ))
      peer_share <- decrypt_result$data
    }
  }
  if (is.null(peer_share)) {
    stop("Peer gradient share not available.", call. = FALSE)
  }

  input <- list(
    own_gradient_share = own_share,
    peer_gradient_share = peer_share,
    n_obs = as.integer(num_obs),
    frac_bits = as.integer(frac_bits)
  )

  result <- .callMheTool("mpc-reveal-gradient", input)

  list(gradient = result$gradient)
}
