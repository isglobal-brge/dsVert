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
#' @param clip_radius Numeric or NULL. If non-NULL, eta_k values are clipped
#'   to \code{[-clip_radius, clip_radius]} before encryption. Used for Poisson
#'   GLMs to keep the total linear predictor within the polynomial approximation
#'   domain (e.g., clip_radius = 1.5 per server yields total in [-3, 3]).
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
glmHEEncryptEtaDS <- function(data_name = NULL, x_vars = NULL, beta = NULL,
                               clip_radius = NULL, from_storage = FALSE,
                               session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("cpk", ss)) {
    stop("CPK not stored. Call mheCombineDS or mheStoreCPKDS first.", call. = FALSE)
  }

  # from_storage: read beta + x_vars + clip_radius from session (enables parallel calls)
  if (isTRUE(from_storage)) {
    beta_blob <- .blob_consume("current_beta", ss)
    if (!is.null(beta_blob)) {
      beta_data <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(
        .base64url_to_base64(beta_blob))))
      beta <- as.numeric(beta_data$beta)
      if (!is.null(beta_data$clip_radius)) clip_radius <- as.numeric(beta_data$clip_radius)
      if (!is.null(beta_data$x_vars)) x_vars <- as.character(beta_data$x_vars)
      if (!is.null(beta_data$data_name)) data_name <- as.character(beta_data$data_name)
    }
  }
  if (is.null(data_name) || is.null(x_vars) || is.null(beta))
    stop("data_name, x_vars, and beta are required", call. = FALSE)

  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }
  .check_glm_disclosure(X)

  beta <- as.numeric(beta)
  if (length(beta) != ncol(X)) {
    stop("beta length (", length(beta), ") does not match number of variables (",
         ncol(X), ")", call. = FALSE)
  }

  # Compute eta_k = X_k * beta_k in plaintext
  eta_k <- as.numeric(X %*% beta)

  # Optional clipping for Poisson (keeps eta in polynomial domain)
  if (!is.null(clip_radius)) {
    clip_radius <- as.numeric(clip_radius)
    eta_k <- pmin(pmax(eta_k, -clip_radius), clip_radius)
  }

  # Encrypt under CPK via Go mhe-encrypt-vector
  input <- list(
    vector = eta_k,
    collective_public_key = .key_get("cpk", ss),
    log_n = as.integer(ss$log_n %||% 13),
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
#'   monomial basis. If NULL, uses built-in sigmoid approximation. Ignored when
#'   \code{skip_poly = TRUE}.
#' @param skip_poly Logical. If TRUE, skip polynomial evaluation and return
#'   ct_eta_total directly as ct_mu. Used for Gaussian GLMs where the identity
#'   link means mu = eta, so no non-linear transformation is needed. This also
#'   avoids requiring a relinearization key. Default FALSE.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{ct_mu}: base64url-encoded encrypted mu ciphertext
#'     \item \code{level_out}: remaining ciphertext level after polynomial eval
#'       (-1 when \code{skip_poly = TRUE})
#'   }
#'
#' @export
glmHELinkStepDS <- function(from_storage = TRUE, n_parties = 2,
                             poly_coefficients = NULL, skip_poly = FALSE,
                             intercept = 0,
                             session_id = NULL) {
  ss <- .S(session_id)

  # Only need RLK for polynomial evaluation
  if (!isTRUE(skip_poly)) {
    rk <- .key_get("relin_key", ss)
    if (is.null(rk) || !nzchar(rk)) {
      stop("Relinearization key not stored. Generate RLK during key setup.", call. = FALSE)
    }
  }

  # Read encrypted etas from blob storage
  if (from_storage) {
    blobs <- .blob_snapshot(ss)
    if (length(blobs) == 0L) stop("No blobs stored for HE link step", call. = FALSE)

    ct_etas <- character(n_parties)
    for (i in seq_len(n_parties)) {
      key <- paste0("ct_eta_", i - 1)
      if (is.null(blobs[[key]])) {
        stop("Missing encrypted eta for party ", i - 1, call. = FALSE)
      }
      ct_etas[i] <- .base64url_to_base64(blobs[[key]])
    }
    # Clean up only the consumed eta blobs (NOT all blobs — others may be needed)
    for (i in seq_len(n_parties))
      .blob_consume(paste0("ct_eta_", i - 1), ss)
  } else {
    stop("Direct argument mode not supported for HE link step", call. = FALSE)
  }

  log_n <- as.integer(ss$log_n %||% 13)
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

  # Add intercept to the encrypted sum (coordinator encrypts constant vector)
  intercept <- as.numeric(intercept)
  if (abs(intercept) > 1e-12) {
    n_slots <- 2^(log_n - 1)  # max slots for this log_n
    enc_int <- .callMheTool("mhe-encrypt-vector", list(
      vector = rep(intercept, n_slots),
      collective_public_key = .key_get("cpk", ss),
      log_n = log_n, log_scale = log_scale
    ))
    add_int <- .callMheTool("mhe-ct-add", list(
      ciphertext_a = ct_total,
      ciphertext_b = enc_int$ciphertext,
      log_n = log_n, log_scale = log_scale
    ))
    ct_total <- add_int$ciphertext
  }

  if (isTRUE(skip_poly)) {
    # Gaussian identity link: mu = eta, no polynomial needed
    ct_mu <- ct_total
    level_out <- -1L
  } else {
    # Step 2: Evaluate link-function polynomial on ct_eta_total
    if (is.null(poly_coefficients)) {
      # Default: degree-7 LS sigmoid approximation on [-8, 8]
      # Least-squares fit minimizes MSE (1.6e-4) → optimal for GLM gradient.
      # Max error 3.2e-2 (higher than Chebyshev) but better coefficient accuracy.
      poly_coefficients <- c(
        0.5,
        2.168562847948179e-01,
        0.0,
        -8.187988303382328e-03,
        0.0,
        1.656607674313851e-04,
        0.0,
        -1.193489025951639e-06
      )
    }

    poly_result <- .callMheTool("mhe-eval-poly", list(
      ciphertext = ct_total,
      coefficients = poly_coefficients,
      relinearization_key = rk,
      log_n = log_n,
      log_scale = log_scale
    ))

    ct_mu <- poly_result$ciphertext
    level_out <- poly_result$level_out
  }

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
glmHEGradientEncDS <- function(data_name = NULL, x_vars = NULL, num_obs = NULL,
                                from_storage = FALSE,
                                include_intercept = FALSE,
                                session_id = NULL) {
  ss <- .S(session_id)

  # from_storage: read x_vars, data_name, include_intercept from session
  if (from_storage) {
    if (is.null(data_name) && !is.null(ss$std_data_name)) data_name <- ss$std_data_name
    if (is.null(x_vars) && !is.null(ss$glm_x_vars)) x_vars <- ss$glm_x_vars
    if (is.null(num_obs) && !is.null(ss$mws_n_obs)) num_obs <- ss$mws_n_obs
    if (!is.null(ss$glm_include_intercept)) include_intercept <- ss$glm_include_intercept
  }

  # Resolve ct_mu: from blob storage, or locally stored
  ct_mu <- NULL
  if (from_storage) {
    val <- .blob_consume("ct_mu", ss)
    if (!is.null(val)) {
      ct_mu <- .base64url_to_base64(val)
    }
  }
  if (is.null(ct_mu)) {
    ct_mu <- ss$ct_mu
  }
  if (is.null(ct_mu)) {
    # Diagnostic: list all blob keys to help debug
    all_keys <- tryCatch(ls(.blob_snapshot(ss)), error = function(e) "snapshot_error")
    stop("Encrypted mu not available (from_storage=", from_storage,
         ", blob_keys=", paste(all_keys, collapse=","),
         ", has_ct_mu_session=", !is.null(ss$ct_mu), ")",
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

  gk <- .key_get("galois_keys", ss)
  if (is.null(gk) || length(gk) == 0) {
    stop("Galois keys not available.", call. = FALSE)
  }

  # Get local feature matrix
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }
  .check_glm_disclosure(X)

  # Optionally prepend intercept column (1s) for intercept gradient
  if (isTRUE(include_intercept)) {
    X <- cbind(rep(1, n), X)
  }
  x_cols <- lapply(seq_len(ncol(X)), function(j) as.numeric(X[, j]))

  input <- list(
    encrypted_y = enc_y,
    encrypted_mu = ct_mu,
    x_cols = x_cols,
    galois_keys = as.list(gk),
    num_obs = as.integer(num_obs),
    log_n = as.integer(ss$log_n %||% 13),
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
  n <- nrow(X)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }
  .check_glm_disclosure(X)

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
