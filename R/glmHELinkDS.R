#' @title HE-Link GLM Protocol - Server-Side Functions
#' @description Server-side functions for the HE-Link GLM protocol (K=2).
#'   These compute the link function inverse (mu = link^-1(eta)) homomorphically
#'   using polynomial approximation, preventing the K=2 privacy leak where the
#'   label server could reconstruct eta_nonlabel from eta_total - eta_label.
#'
#' @details
#' With K=2 servers (label + 1 non-label), standard secure routing leaks
#' eta_nonlabel to the label server because eta_total = eta_label + eta_nonlabel
#' and the label server knows eta_label. When the non-label server has p=1
#' predictor, this reveals individual-level data x = eta/beta.
#'
#' The HE-Link protocol fixes this by computing mu = sigma(eta_total)
#' entirely in the encrypted domain using CKKS polynomial approximation:
#' \enumerate{
#'   \item Each server encrypts eta_k = X_k * beta_k under the CPK
#'   \item Coordinator adds ciphertexts: ct_eta_total = ct_eta_label + ct_eta_nonlabel
#'   \item Coordinator evaluates degree-7 sigmoid polynomial on ct_eta_total -> ct_mu
#'   \item Both servers compute gradient using ct_y - ct_mu (both encrypted)
#'   \item Gradient scalars are threshold-decrypted; beta updated via GD
#' }
#'
#' The label server never sees eta_nonlabel in plaintext.
#'
#' @name glm-he-link-protocol
NULL

# ============================================================================
# Step 1: Encrypt eta_k = X_k * beta_k
# ============================================================================

#' Encrypt linear predictor contribution under CPK
#'
#' Each server computes eta_k = X_k * beta_k in plaintext, then encrypts it
#' as a single CKKS ciphertext under the collective public key. The encrypted
#' eta is sent to the coordinator for homomorphic aggregation.
#'
#' @param data_name Character. Name of the (standardized) data frame.
#' @param x_vars Character vector. Feature column names on this server.
#' @param beta Numeric vector. Current coefficients for this server's block
#'   (length p_k).
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{encrypted_eta}: base64url-encoded CKKS ciphertext of eta_k
#'     \item \code{num_obs}: number of observations
#'   }
#'
#' @export
glmHEEncryptEtaDS <- function(data_name, x_vars, beta, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$cpk)) {
    stop("CPK not stored. Call mheCombineDS or mheStoreCPKDS first.", call. = FALSE)
  }

  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)

  beta <- as.numeric(beta)
  if (length(beta) != ncol(X)) {
    stop("beta length (", length(beta), ") does not match number of variables (",
         ncol(X), ")", call. = FALSE)
  }

  # Compute eta_k = X_k * beta_k in plaintext
  eta_k <- as.numeric(X %*% beta)

  # Encrypt under CPK via Go mhe-encrypt-vector
  input <- list(
    vector = eta_k,
    collective_public_key = ss$cpk,
    log_n = as.integer(ss$log_n %||% 14),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-encrypt-vector", input)

  list(
    encrypted_eta = base64_to_base64url(result$ciphertext),
    num_obs = n
  )
}

# ============================================================================
# Step 2: Coordinator link step (ct_add + poly eval)
# ============================================================================

#' Compute mu = sigmoid(eta_total) homomorphically (coordinator only)
#'
#' Called on the coordinator (label server) after receiving encrypted etas
#' from all servers. Performs:
#' \enumerate{
#'   \item Homomorphic addition: ct_eta_total = ct_eta_label + ct_eta_nonlabel
#'   \item Polynomial evaluation: ct_mu = sigmoid_poly(ct_eta_total)
#' }
#'
#' The coordinator never sees eta_nonlabel in plaintext.
#'
#' @param from_storage Logical. If TRUE, read encrypted etas from blob storage
#'   (keys: "ct_eta_0", "ct_eta_1", ...). Default TRUE.
#' @param n_parties Integer. Number of parties (for reading from blob storage).
#' @param poly_coefficients Numeric vector or NULL. Polynomial coefficients in
#'   monomial basis. If NULL, uses built-in sigmoid approximation.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{ct_mu}: base64url-encoded encrypted mu ciphertext
#'     \item \code{level_out}: remaining ciphertext level after polynomial eval
#'   }
#'
#' @export
glmHELinkStepDS <- function(from_storage = TRUE, n_parties = 2,
                             poly_coefficients = NULL, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$relin_key) || !nzchar(ss$relin_key)) {
    stop("Relinearization key not stored. Generate RLK during key setup.", call. = FALSE)
  }

  # Read encrypted etas from blob storage
  if (from_storage) {
    blobs <- ss$blobs
    if (is.null(blobs)) stop("No blobs stored for HE link step", call. = FALSE)

    ct_etas <- character(n_parties)
    for (i in seq_len(n_parties)) {
      key <- paste0("ct_eta_", i - 1)
      if (is.null(blobs[[key]])) {
        stop("Missing encrypted eta for party ", i - 1, call. = FALSE)
      }
      ct_etas[i] <- .base64url_to_base64(blobs[[key]])
    }
    ss$blobs <- NULL
  } else {
    stop("Direct argument mode not supported for HE link step", call. = FALSE)
  }

  log_n <- as.integer(ss$log_n %||% 14)
  log_scale <- as.integer(ss$log_scale %||% 40)

  # Step 1: Aggregate all encrypted etas via homomorphic addition
  ct_total <- ct_etas[1]
  for (i in 2:length(ct_etas)) {
    add_result <- .callMheTool("mhe-ct-add", list(
      ciphertext_a = ct_total,
      ciphertext_b = ct_etas[i],
      log_n = log_n,
      log_scale = log_scale
    ))
    ct_total <- add_result$ciphertext
  }

  # Step 2: Evaluate sigmoid polynomial on ct_eta_total
  if (is.null(poly_coefficients)) {
    # Default: degree-7 sigmoid approximation on [-8, 8]
    poly_coefficients <- c(
      0.5,
      2.205572459845886e-01,
      0.0,
      -8.555529945829476e-03,
      0.0,
      1.743706748783766e-04,
      0.0,
      -1.247898376981334e-06
    )
  }

  poly_result <- .callMheTool("mhe-eval-poly", list(
    ciphertext = ct_total,
    coefficients = poly_coefficients,
    relinearization_key = ss$relin_key,
    log_n = log_n,
    log_scale = log_scale
  ))

  ct_mu <- poly_result$ciphertext
  level_out <- poly_result$level_out

  # Store ct_mu locally for own gradient computation
  ss$ct_mu <- ct_mu

  list(
    ct_mu = base64_to_base64url(ct_mu),
    level_out = level_out
  )
}

# ============================================================================
# Step 3: Encrypted gradient with encrypted mu
# ============================================================================

#' Compute encrypted gradient using encrypted mu (HE-Link mode)
#'
#' Computes the gradient contribution for this server's feature block using
#' homomorphic operations. Unlike \code{\link{mheGLMGradientDS}} which takes
#' plaintext mu, this function uses encrypted mu (ct_mu) from the polynomial
#' evaluation step, ensuring eta_nonlabel is never revealed.
#'
#' \deqn{g_k = X_k^T (ct_y - ct_mu)}
#'
#' @param data_name Character. Name of the data frame with local features.
#' @param x_vars Character vector. Feature column names on this server.
#' @param num_obs Integer. Number of observations.
#' @param from_storage Logical. If TRUE, read ct_mu from blob storage
#'   (key: "ct_mu"). Default FALSE (uses locally stored ct_mu).
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{encrypted_gradients}: base64url array of p_k encrypted
#'       gradient components, each requiring threshold decryption.
#'     \item \code{ct_hashes}: SHA-256 hashes for Protocol Firewall.
#'   }
#'
#' @export
glmHEGradientEncDS <- function(data_name, x_vars, num_obs,
                                from_storage = FALSE, session_id = NULL) {
  ss <- .S(session_id)
  # Resolve ct_mu: from blob storage, or locally stored
  ct_mu <- NULL
  if (from_storage) {
    blobs <- ss$blobs
    if (!is.null(blobs) && !is.null(blobs[["ct_mu"]])) {
      ct_mu <- .base64url_to_base64(blobs[["ct_mu"]])
      ss$blobs[["ct_mu"]] <- NULL
    }
  }
  if (is.null(ct_mu)) {
    ct_mu <- ss$ct_mu
  }
  if (is.null(ct_mu)) {
    stop("Encrypted mu not available. Call glmHELinkStepDS or store ct_mu via blob.",
         call. = FALSE)
  }

  # Resolve ct_y: same sources as mheGLMGradientDS
  enc_y <- NULL
  if (!is.null(ss$enc_y)) {
    enc_y <- ss$enc_y
  } else if (!is.null(ss$remote_enc_cols) &&
             length(ss$remote_enc_cols) >= 1) {
    enc_y <- ss$remote_enc_cols[[1]]
  }
  if (is.null(enc_y)) {
    stop("Encrypted y not stored. Transfer ct_y first.", call. = FALSE)
  }

  if (is.null(ss$galois_keys) ||
      length(ss$galois_keys) == 0) {
    stop("Galois keys not available.", call. = FALSE)
  }

  # Get local feature matrix
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])

  x_cols <- lapply(seq_len(ncol(X)), function(j) as.numeric(X[, j]))

  input <- list(
    encrypted_y = enc_y,
    encrypted_mu = ct_mu,
    x_cols = x_cols,
    galois_keys = as.list(ss$galois_keys),
    num_obs = as.integer(num_obs),
    log_n = as.integer(ss$log_n %||% 14),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-he-gradient", input)

  # Protocol Firewall: register each gradient ciphertext
  ct_hashes <- character(length(result$encrypted_gradients))
  for (j in seq_along(result$encrypted_gradients)) {
    ct_hashes[j] <- .register_ciphertext(
      result$encrypted_gradients[[j]], "he-link-gradient",
      session_id = session_id
    )
  }

  enc_grads <- sapply(result$encrypted_gradients, base64_to_base64url,
                      USE.NAMES = FALSE)

  list(encrypted_gradients = enc_grads, ct_hashes = ct_hashes)
}

# ============================================================================
# Step 4: Block update using decrypted gradient (Gradient Descent)
# ============================================================================

#' GD block update with decrypted gradient (HE-Link mode)
#'
#' After threshold decryption reveals the p_k-length gradient, this function
#' performs a simple gradient descent update:
#'
#' \deqn{\beta_{new} = \beta_{old} + \alpha \cdot (g_k / n - \lambda \cdot \beta_{old})}
#'
#' Unlike \code{\link{glmBlockSolveDS}} which uses Newton/IRLS updates
#' (requiring X^T W X and plaintext weights w), GD only needs the gradient
#' scalar per feature. This avoids transmitting the IRLS weight vector w,
#' which would require either plaintext mu (privacy leak) or an additional
#' encrypted computation.
#'
#' @param beta_current Numeric vector. Current coefficients (length p_k).
#' @param gradient Numeric vector. Decrypted gradient g_k (length p_k).
#' @param alpha Numeric. Learning rate (step size). Default 0.1.
#' @param lambda Numeric. L2 regularization parameter. Default 1e-4.
#' @param n_obs Integer. Number of observations (for gradient normalization).
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{beta}: Updated coefficient vector (length p_k)
#'   }
#'
#' @export
glmHEBlockUpdateDS <- function(beta_current, gradient, alpha = 0.1,
                                lambda = 1e-4, n_obs, session_id = NULL) {
  beta_current <- as.numeric(beta_current)
  gradient <- as.numeric(gradient)
  n_obs <- as.integer(n_obs)

  if (length(beta_current) != length(gradient)) {
    stop("beta_current length (", length(beta_current),
         ") != gradient length (", length(gradient), ")", call. = FALSE)
  }

  # GD update: beta_new = beta_old + alpha * (g/n - lambda * beta_old)
  beta_new <- beta_current + alpha * (gradient / n_obs - lambda * beta_current)

  # Guard against numerical blow-up
  if (any(abs(beta_new) > 1e6)) {
    beta_new <- beta_new / max(abs(beta_new)) * 1e2
    warning("Large coefficient update detected, scaling applied")
  }

  list(beta = beta_new)
}

# ============================================================================
# Step 5: Deviance preparation (one-time secure routing for final deviance)
# ============================================================================

#' Prepare transport-encrypted eta for deviance computation (HE-Link mode)
#'
#' After HE-Link convergence, this function computes eta_k = X_k * beta_k
#' and either stores it locally (on the coordinator) or transport-encrypts it
#' under the coordinator's public key (non-label servers). This enables a
#' single secure-routing deviance computation using the existing
#' \code{\link{glmSecureDevianceDS}}.
#'
#' @param data_name Character. Name of the (standardized) data frame.
#' @param x_vars Character vector. Feature column names on this server.
#' @param beta Numeric vector. Final converged coefficients for this block.
#' @param coordinator_pk Character or NULL. Coordinator's transport PK
#'   (base64url). If NULL, this IS the coordinator; eta is stored locally.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{encrypted_eta}: Transport-encrypted eta (base64url),
#'       NULL if this is the coordinator.
#'   }
#'
#' @export
glmHEPrepDevianceDS <- function(data_name, x_vars, beta,
                                 coordinator_pk = NULL, session_id = NULL) {
  ss <- .S(session_id)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  beta <- as.numeric(beta)
  eta <- as.vector(X %*% beta)

  if (is.null(coordinator_pk) || coordinator_pk == "") {
    # This is the coordinator: store eta_label locally for glmSecureDevianceDS
    ss$glm_eta_label <- eta
    ss$glm_eta_other <- rep(0, length(eta))
    return(list(encrypted_eta = NULL))
  }

  # Non-label server: transport-encrypt eta under coordinator PK
  sealed <- .callMheTool("transport-encrypt-vectors", list(
    vectors = list(eta = as.numeric(eta)),
    recipient_pk = .base64url_to_base64(coordinator_pk)
  ))

  list(encrypted_eta = base64_to_base64url(sealed$sealed))
}
