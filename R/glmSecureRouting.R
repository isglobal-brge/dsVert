#' @title GLM Secure Routing - Server-Side Functions
#' @description Server-side functions for the GLM Secure Routing protocol.
#'   These ensure that individual-level vectors (eta, mu, w, v) are never
#'   visible to the client. The client acts as a blind relay, passing
#'   transport-encrypted blobs between the coordinator (label server) and
#'   non-label servers.
#'
#' @details
#' In the standard GLM protocol, the client computes and broadcasts
#' n-length vectors (eta_total, mu, w, v) at each BCD iteration. This is
#' disclosive because eta = X*beta can reveal individual-level features
#' (DataSHIELD blocks linear predictor disclosure in dsBase's ds.glm).
#'
#' The Secure Routing protocol replaces this with end-to-end encrypted
#' transport between servers:
#' \enumerate{
#'   \item The label server acts as \strong{coordinator}: it receives
#'     encrypted etas from non-label servers, decrypts them, runs IRLS,
#'     and encrypts (mu, w, v) under each non-label server's transport PK.
#'   \item Non-label servers decrypt their (mu, w, v) blob locally, compute
#'     encrypted gradients, and after threshold decryption + BCD solve,
#'     encrypt their new eta under the coordinator's transport PK.
#'   \item The client only sees: betas (p_k-length coefficient vectors,
#'     safe aggregate statistics) and opaque encrypted blobs.
#' }
#'
#' @name glm-secure-routing
NULL

# ============================================================================
# Coordinator Step (label server)
# ============================================================================

#' GLM Coordinator Step (label server, secure routing)
#'
#' Called once per BCD iteration on the label server (coordinator). Combines
#' eta aggregation from non-label servers, an IRLS update using local y, and
#' encrypted distribution of (mu, w, v) to each non-label server.
#'
#' @param data_name Character. Name of the standardized data frame on this server.
#' @param y_var Character. Name of the response variable (must exist on this server).
#' @param x_vars Character vector. Feature column names on the label server.
#' @param encrypted_eta_blobs Named list or NULL. Server name -> encrypted eta
#'   blob (base64url). NULL or empty on the first iteration (all etas are zero).
#'   Mutually exclusive with \code{eta_blob_keys}.
#' @param eta_blob_keys Character vector or NULL. Keys in
#'   \code{\link{mheStoreBlobDS}} storage from which to read encrypted eta blobs.
#'   Used when blobs are too large for direct parameter passing.
#' @param non_label_pks Named list or NULL. Server name -> transport PK (base64url)
#'   for non-label servers that need (mu, w, v) blobs.
#' @param family Character. GLM family: \code{"gaussian"}, \code{"binomial"},
#'   \code{"poisson"}, or \code{"Gamma"}. Default \code{"gaussian"}.
#' @param beta_current Numeric vector or NULL. Current coefficients for the
#'   label server block. NULL on first iteration.
#' @param lambda Numeric. L2 regularization parameter. Default 1e-4.
#' @param intercept Logical. Whether to include an intercept column.
#'   Default \code{FALSE}.
#' @param n_obs Integer or NULL. Number of observations. If NULL, inferred
#'   from the data.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{beta}: Updated label-server coefficients (p_k-length, safe)
#'     \item \code{encrypted_blobs}: Named list of encrypted (mu, w, v) blobs
#'       per non-label server (base64url, opaque to client)
#'     \item \code{converged}: Logical from IRLS convergence check
#'   }
#'
#' @seealso \code{\link{glmSecureGradientDS}}, \code{\link{glmSecureBlockSolveDS}},
#'   \code{\link{glmSecureDevianceDS}}
#' @export
glmCoordinatorStepDS <- function(data_name, y_var, x_vars,
                                  encrypted_eta_blobs = NULL,
                                  eta_blob_keys = NULL,
                                  non_label_pks = NULL,
                                  family = "gaussian",
                                  beta_current = NULL,
                                  lambda = 1e-4,
                                  intercept = FALSE,
                                  n_obs = NULL) {

  # Decrypt eta blobs from non-label servers
  eta_other <- rep(0, n_obs)

  # Read eta blobs from blob storage if keys provided (chunked transfer)
  if (is.null(encrypted_eta_blobs) && !is.null(eta_blob_keys)) {
    encrypted_eta_blobs <- list()
    for (key in eta_blob_keys) {
      blob <- .mhe_storage$blobs[[key]]
      if (!is.null(blob)) {
        encrypted_eta_blobs[[key]] <- blob
        .mhe_storage$blobs[[key]] <- NULL  # consume
      }
    }
  }

  if (!is.null(encrypted_eta_blobs) && length(encrypted_eta_blobs) > 0) {
    if (is.null(.mhe_storage$transport_sk)) {
      stop("Transport SK not stored. Call mheInitDS first.", call. = FALSE)
    }

    for (server_name in names(encrypted_eta_blobs)) {
      blob <- encrypted_eta_blobs[[server_name]]
      if (is.null(blob) || blob == "" || blob == "NULL") next

      # Decrypt the eta vector
      decrypted <- .callMheTool("transport-decrypt-vectors", list(
        sealed = .base64url_to_base64(blob),
        recipient_sk = .mhe_storage$transport_sk
      ))

      eta_k <- as.numeric(decrypted$vectors$eta)
      eta_other <- eta_other + eta_k
    }
  }

  # Run IRLS step (same logic as glmPartialFitDS)
  data <- .resolveData(data_name, parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  y <- as.numeric(data[[y_var]])
  X <- as.matrix(data[, x_vars, drop = FALSE])

  if (isTRUE(intercept)) {
    X <- cbind("(Intercept)" = rep(1, nrow(X)), X)
  }

  n <- length(y)
  p <- ncol(X)

  if (is.null(beta_current) || length(beta_current) == 0) {
    beta_current <- rep(0, p)
  }

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }
  .check_glm_disclosure(X, y)

  # Compute total linear predictor and IRLS quantities
  eta <- as.vector(eta_other + X %*% beta_current)

  if (family == "gaussian") {
    mu <- eta
    w <- rep(1, n)
    z <- y
  } else if (family == "binomial") {
    eta <- pmax(pmin(eta, 20), -20)
    mu <- 1 / (1 + exp(-eta))
    mu <- pmax(pmin(mu, 1 - 1e-10), 1e-10)
    w <- mu * (1 - mu)
    z <- eta + (y - mu) / w
  } else if (family == "poisson") {
    eta <- pmin(eta, 20)
    mu <- exp(eta)
    mu <- pmax(mu, 1e-10)
    w <- mu
    z <- eta + (y - mu) / mu
  } else if (family == "Gamma") {
    eta <- pmax(pmin(eta, 20), -20)
    mu <- exp(eta)
    mu <- pmax(mu, 1e-10)
    w <- rep(1, n)
    z <- eta + (y - mu) / mu
  } else if (family == "inverse.gaussian") {
    eta <- pmax(pmin(eta, 20), -20)
    mu <- exp(eta)
    mu <- pmax(mu, 1e-10)
    w <- 1 / mu
    z <- eta + (y - mu) / mu
  }

  # IRLS update with L2 regularization
  W <- diag(w)
  XtWX <- crossprod(X, W %*% X) + diag(lambda, p)
  XtWz <- crossprod(X, w * (z - eta_other))

  beta_new <- tryCatch(
    as.vector(solve(XtWX, XtWz)),
    error = function(e) {
      warning("Matrix near-singular, using additional regularization")
      as.vector(solve(XtWX + diag(0.01, p), XtWz))
    }
  )

  converged <- TRUE
  if (any(abs(beta_new) > 1e6)) {
    beta_new <- beta_new / max(abs(beta_new)) * 1e2
    converged <- FALSE
    warning("Large coefficient update detected, scaling applied")
  }

  eta_label <- as.vector(X %*% beta_new)

  # Compute eta_total, mu, w, v for non-label servers
  eta_total <- eta_label + eta_other

  # Store eta_total for deviance computation after convergence
  .mhe_storage$glm_eta_label <- eta_label
  .mhe_storage$glm_eta_other <- eta_other

  # Recompute mu, w from eta_total (for non-label servers)
  if (family == "gaussian") {
    mu_total <- eta_total
    w_total <- rep(1, n)
    v_total <- NULL
  } else if (family == "binomial") {
    eta_total <- pmax(pmin(eta_total, 20), -20)
    mu_total <- 1 / (1 + exp(-eta_total))
    mu_total <- pmax(pmin(mu_total, 1 - 1e-10), 1e-10)
    w_total <- mu_total * (1 - mu_total)
    v_total <- NULL
  } else if (family == "poisson") {
    eta_total <- pmin(eta_total, 20)
    mu_total <- exp(eta_total)
    mu_total <- pmax(mu_total, 1e-10)
    w_total <- mu_total
    v_total <- NULL
  } else if (family == "Gamma") {
    eta_total <- pmax(pmin(eta_total, 20), -20)
    mu_total <- exp(eta_total)
    mu_total <- pmax(mu_total, 1e-10)
    w_total <- rep(1, n)
    v_total <- 1 / mu_total
  } else if (family == "inverse.gaussian") {
    eta_total <- pmax(pmin(eta_total, 20), -20)
    mu_total <- exp(eta_total)
    mu_total <- pmax(mu_total, 1e-10)
    w_total <- 1 / mu_total
    v_total <- 1 / (mu_total^2)
  }

  # Encrypt (mu, w, v) under each non-label server's transport PK
  encrypted_blobs <- list()
  if (!is.null(non_label_pks) && length(non_label_pks) > 0) {
    vectors_to_encrypt <- list(mu = as.numeric(mu_total), w = as.numeric(w_total))
    if (!is.null(v_total)) {
      vectors_to_encrypt$v <- as.numeric(v_total)
    }

    for (server_name in names(non_label_pks)) {
      pk <- .base64url_to_base64(non_label_pks[[server_name]])
      sealed <- .callMheTool("transport-encrypt-vectors", list(
        vectors = vectors_to_encrypt,
        recipient_pk = pk
      ))
      encrypted_blobs[[server_name]] <- base64_to_base64url(sealed$sealed)
    }
  }

  list(
    beta = beta_new,
    encrypted_blobs = encrypted_blobs,
    converged = converged
  )
}

# ============================================================================
# Non-label server: Secure Gradient
# ============================================================================

#' Compute encrypted GLM gradient with transport-encrypted mu/w/v
#'
#' Non-label server function for the secure routing protocol. Decrypts the
#' (mu, w, v) blob from the coordinator using this server's X25519 transport
#' SK, then computes the CKKS-encrypted gradient \eqn{g_k = X_k^T (v \cdot
#' (ct_y - mu))} using stored \code{ct_y} and local features.
#'
#' @param data_name Character. Name of the data frame with local features.
#' @param x_vars Character vector. Feature column names on this server.
#' @param encrypted_mwv Character or NULL. Transport-encrypted (mu, w, v)
#'   blob (base64url). If NULL, reads from blob storage under key \code{"mwv"}
#'   (set via \code{\link{mheStoreBlobDS}}).
#' @param num_obs Integer. Number of observations.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{encrypted_gradients}: Character vector of CKKS-encrypted
#'       gradient components (base64url), one per feature.
#'     \item \code{ct_hashes}: SHA-256 hashes registered in the Protocol
#'       Firewall for subsequent threshold decryption.
#'   }
#'
#' @seealso \code{\link{glmCoordinatorStepDS}} which produces the (mu, w, v) blob,
#'   \code{\link{glmSecureBlockSolveDS}} which uses the decrypted gradient
#' @export
glmSecureGradientDS <- function(data_name, x_vars, encrypted_mwv = NULL, num_obs) {
  if (is.null(.mhe_storage$transport_sk)) {
    stop("Transport SK not stored. Call mheInitDS first.", call. = FALSE)
  }

  # Read from blob storage if not provided directly (chunked transfer)
  if (is.null(encrypted_mwv) || encrypted_mwv == "") {
    encrypted_mwv <- .mhe_storage$blobs[["mwv"]]
    .mhe_storage$blobs[["mwv"]] <- NULL  # consume
  }
  if (is.null(encrypted_mwv)) {
    stop("No encrypted (mu, w, v) blob provided or stored.", call. = FALSE)
  }

  # Decrypt (mu, w, v) from coordinator
  decrypted <- .callMheTool("transport-decrypt-vectors", list(
    sealed = .base64url_to_base64(encrypted_mwv),
    recipient_sk = .mhe_storage$transport_sk
  ))

  mu <- as.numeric(decrypted$vectors$mu)
  v <- if (!is.null(decrypted$vectors$v)) as.numeric(decrypted$vectors$v) else NULL

  # Delegate to existing gradient computation logic
  # (same as mheGLMGradientDS but sources mu/v from decrypted blob)
  enc_y <- NULL
  if (!is.null(.mhe_storage$enc_y)) {
    enc_y <- .mhe_storage$enc_y
  } else if (!is.null(.mhe_storage$remote_enc_cols) && length(.mhe_storage$remote_enc_cols) >= 1) {
    enc_y <- .mhe_storage$remote_enc_cols[[1]]
  }
  if (is.null(enc_y)) {
    stop("Encrypted y not stored. Transfer ct_y first.", call. = FALSE)
  }
  if (is.null(.mhe_storage$galois_keys) || length(.mhe_storage$galois_keys) == 0) {
    stop("Galois keys not available.", call. = FALSE)
  }

  data <- .resolveData(data_name, parent.frame())
  X <- as.matrix(data[, x_vars, drop = FALSE])

  x_cols <- lapply(seq_len(ncol(X)), function(j) as.numeric(X[, j]))

  input <- list(
    encrypted_y = enc_y,
    mu = as.numeric(mu),
    v = v,
    x_cols = x_cols,
    galois_keys = as.list(.mhe_storage$galois_keys),
    num_obs = as.integer(num_obs),
    log_n = as.integer(.mhe_storage$log_n %||% 12),
    log_scale = as.integer(.mhe_storage$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-glm-gradient", input)

  # Protocol Firewall: register each gradient ciphertext
  ct_hashes <- character(length(result$encrypted_gradients))
  for (j in seq_along(result$encrypted_gradients)) {
    ct_hashes[j] <- .register_ciphertext(result$encrypted_gradients[[j]], "glm-gradient")
  }

  enc_grads <- sapply(result$encrypted_gradients, base64_to_base64url, USE.NAMES = FALSE)

  list(encrypted_gradients = enc_grads, ct_hashes = ct_hashes)
}

# ============================================================================
# Non-label server: Secure Block Solve
# ============================================================================

#' BCD block update with transport-encrypted eta output
#'
#' Non-label server function for the secure routing protocol. After threshold
#' decryption reveals the p_k-length gradient, this function:
#' \enumerate{
#'   \item Decrypts (mu, w, v) from the coordinator's blob to get IRLS weights
#'   \item Solves the BCD block update: \eqn{beta = (X_k^T W X_k + \lambda I)^{-1}
#'     (X_k^T W X_k \cdot beta_{old} + gradient)} (same math as
#'     \code{\link{glmBlockSolveDS}})
#'   \item Computes \eqn{eta_k = X_k \cdot beta_k} and encrypts it under the
#'     coordinator's transport PK
#' }
#'
#' The client receives only beta (p_k-length, safe) and an opaque encrypted
#' eta blob that it relays to the coordinator on the next iteration.
#'
#' @param data_name Character. Name of the data frame with local features.
#' @param x_vars Character vector. Feature column names on this server.
#' @param encrypted_mwv Character or NULL. Transport-encrypted (mu, w, v) blob
#'   (base64url). If NULL, reads from blob storage under key \code{"mwv"}
#'   (set via \code{\link{mheStoreBlobDS}}).
#' @param beta_current Numeric vector. Current coefficients for this block.
#' @param gradient Numeric vector. Decrypted gradient from threshold decryption
#'   (p_k scalars).
#' @param lambda Numeric. L2 regularization parameter. Default 1e-4.
#' @param coordinator_pk Character or NULL. Coordinator's transport PK
#'   (base64url). If NULL, reads from stored peer transport PKs.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{beta}: Updated coefficient vector (p_k-length, safe aggregate)
#'     \item \code{encrypted_eta}: Transport-encrypted \eqn{eta_k = X_k \cdot beta_k}
#'       (base64url, opaque to client)
#'   }
#'
#' @seealso \code{\link{glmSecureGradientDS}}, \code{\link{glmCoordinatorStepDS}}
#' @export
glmSecureBlockSolveDS <- function(data_name, x_vars, encrypted_mwv = NULL,
                                   beta_current, gradient,
                                   lambda = 1e-4, coordinator_pk = NULL) {
  if (is.null(.mhe_storage$transport_sk)) {
    stop("Transport SK not stored. Call mheInitDS first.", call. = FALSE)
  }

  # Read from blob storage if not provided directly (chunked transfer)
  if (is.null(encrypted_mwv) || encrypted_mwv == "") {
    encrypted_mwv <- .mhe_storage$blobs[["mwv"]]
    .mhe_storage$blobs[["mwv"]] <- NULL  # consume
  }
  if (is.null(encrypted_mwv)) {
    stop("No encrypted (mu, w, v) blob provided or stored.", call. = FALSE)
  }

  # Decrypt (mu, w, v) to get IRLS weights
  decrypted <- .callMheTool("transport-decrypt-vectors", list(
    sealed = .base64url_to_base64(encrypted_mwv),
    recipient_sk = .mhe_storage$transport_sk
  ))

  w <- as.numeric(decrypted$vectors$w)

  # BCD block update (same math as glmBlockSolveDS)
  data <- .resolveData(data_name, parent.frame())
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p <- ncol(X)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }
  .check_glm_disclosure(X)

  XtWX <- crossprod(X, w * X) + diag(lambda, p)
  rhs <- as.vector(XtWX %*% beta_current) + gradient

  beta_new <- tryCatch(
    as.vector(solve(XtWX, rhs)),
    error = function(e) {
      warning("Matrix near-singular, using additional regularization")
      as.vector(solve(XtWX + diag(0.01, p), rhs))
    }
  )

  if (any(abs(beta_new) > 1e6)) {
    beta_new <- beta_new / max(abs(beta_new)) * 1e2
    warning("Large coefficient update detected, scaling applied")
  }

  eta_new <- as.vector(X %*% beta_new)

  # Encrypt eta under coordinator's transport PK
  encrypted_eta <- NULL
  if (!is.null(coordinator_pk) && coordinator_pk != "") {
    sealed <- .callMheTool("transport-encrypt-vectors", list(
      vectors = list(eta = as.numeric(eta_new)),
      recipient_pk = .base64url_to_base64(coordinator_pk)
    ))
    encrypted_eta <- base64_to_base64url(sealed$sealed)
  }

  list(
    beta = beta_new,
    encrypted_eta = encrypted_eta
  )
}

# ============================================================================
# Coordinator: Secure Deviance
# ============================================================================

#' Compute deviance server-side (coordinator only)
#'
#' After BCD convergence, computes deviance on the coordinator (label server)
#' using decrypted etas from non-label servers and local y. The client never
#' sees the n-length \code{eta_total} vector.
#'
#' For Gaussian family, the standardized etas are unstandardized using
#' \code{y_sd} and \code{y_mean} before computing deviance.
#'
#' @param data_name Character. Name of the ORIGINAL (not standardized) data
#'   frame containing the response variable.
#' @param y_var Character. Name of the response variable.
#' @param encrypted_eta_blobs Named list or NULL. Server name -> encrypted eta
#'   blob (base64url) from the final BCD iteration. NULL if there are no
#'   non-label servers. Mutually exclusive with \code{eta_blob_keys}.
#' @param eta_blob_keys Character vector or NULL. Keys in
#'   \code{\link{mheStoreBlobDS}} storage from which to read encrypted eta blobs.
#'   Used when blobs are too large for direct parameter passing.
#' @param family Character. GLM family: \code{"gaussian"}, \code{"binomial"},
#'   \code{"poisson"}, or \code{"Gamma"}. Default \code{"gaussian"}.
#' @param y_sd Numeric or NULL. Standard deviation of y, used for Gaussian
#'   unstandardization: \code{eta_orig = eta_std * y_sd + y_mean}.
#' @param y_mean Numeric or NULL. Mean of y, used for Gaussian
#'   unstandardization.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{deviance}: Residual deviance
#'     \item \code{null_deviance}: Null model deviance (intercept-only)
#'   }
#'
#' @seealso \code{\link{glmCoordinatorStepDS}}, \code{\link{glmDevianceDS}}
#' @export
glmSecureDevianceDS <- function(data_name, y_var, encrypted_eta_blobs = NULL,
                                 eta_blob_keys = NULL,
                                 family = "gaussian", y_sd = NULL, y_mean = NULL) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  y <- as.numeric(data[[y_var]])
  n <- length(y)

  # Reconstruct eta_total from stored label eta + decrypted non-label etas
  eta_total <- rep(0, n)

  # Add stored label server eta (from last coordinator step, on standardized scale)
  if (!is.null(.mhe_storage$glm_eta_label)) {
    eta_total <- eta_total + .mhe_storage$glm_eta_label
  }
  if (!is.null(.mhe_storage$glm_eta_other)) {
    eta_total <- eta_total + .mhe_storage$glm_eta_other
  }

  # Read eta blobs from blob storage if keys provided (chunked transfer)
  if (is.null(encrypted_eta_blobs) && !is.null(eta_blob_keys)) {
    encrypted_eta_blobs <- list()
    for (key in eta_blob_keys) {
      blob <- .mhe_storage$blobs[[key]]
      if (!is.null(blob)) {
        encrypted_eta_blobs[[key]] <- blob
        .mhe_storage$blobs[[key]] <- NULL  # consume
      }
    }
  }

  # If encrypted etas provided (final iteration), decrypt and add
  if (!is.null(encrypted_eta_blobs) && length(encrypted_eta_blobs) > 0) {
    eta_nonlabel <- rep(0, n)
    for (server_name in names(encrypted_eta_blobs)) {
      blob <- encrypted_eta_blobs[[server_name]]
      if (is.null(blob) || blob == "" || blob == "NULL") next
      decrypted <- .callMheTool("transport-decrypt-vectors", list(
        sealed = .base64url_to_base64(blob),
        recipient_sk = .mhe_storage$transport_sk
      ))
      eta_nonlabel <- eta_nonlabel + as.numeric(decrypted$vectors$eta)
    }
    # Use freshly decrypted etas instead of stored ones
    eta_total <- .mhe_storage$glm_eta_label + eta_nonlabel
  }

  # Transform back to original scale if Gaussian (standardized)
  if (!is.null(y_sd) && !is.null(y_mean)) {
    eta_total <- eta_total * y_sd + y_mean
  }

  # Delegate to existing deviance computation (reuse glmDevianceDS logic)
  # but without passing eta through the client
  if (family == "gaussian") {
    mu <- eta_total
    mu_null <- mean(y)
    deviance <- sum((y - mu)^2)
    null_deviance <- sum((y - mu_null)^2)
  } else if (family == "binomial") {
    eta_total <- pmax(pmin(eta_total, 20), -20)
    mu <- 1 / (1 + exp(-eta_total))
    mu <- pmax(pmin(mu, 1 - 1e-10), 1e-10)
    mu_null <- mean(y)
    mu_null <- pmax(pmin(mu_null, 1 - 1e-10), 1e-10)
    deviance <- 0
    for (i in seq_len(n)) {
      if (y[i] > 0) deviance <- deviance + y[i] * log(y[i] / mu[i])
      if (y[i] < 1) deviance <- deviance + (1 - y[i]) * log((1 - y[i]) / (1 - mu[i]))
    }
    deviance <- 2 * deviance
    null_deviance <- 0
    for (i in seq_len(n)) {
      if (y[i] > 0) null_deviance <- null_deviance + y[i] * log(y[i] / mu_null)
      if (y[i] < 1) null_deviance <- null_deviance + (1 - y[i]) * log((1 - y[i]) / (1 - mu_null))
    }
    null_deviance <- 2 * null_deviance
  } else if (family == "poisson") {
    eta_total <- pmin(eta_total, 20)
    mu <- pmax(exp(eta_total), 1e-10)
    mu_null <- pmax(mean(y), 1e-10)
    deviance <- 2 * sum(ifelse(y > 0, y * log(y / mu), 0) - (y - mu))
    null_deviance <- 2 * sum(ifelse(y > 0, y * log(y / mu_null), 0) - (y - mu_null))
  } else if (family == "Gamma") {
    eta_total <- pmax(pmin(eta_total, 20), -20)
    mu <- pmax(exp(eta_total), 1e-10)
    mu_null <- pmax(mean(y), 1e-10)
    deviance <- 2 * sum(-log(y / mu) + (y - mu) / mu)
    null_deviance <- 2 * sum(-log(y / mu_null) + (y - mu_null) / mu_null)
  } else if (family == "inverse.gaussian") {
    eta_total <- pmax(pmin(eta_total, 20), -20)
    mu <- pmax(exp(eta_total), 1e-10)
    mu_null <- pmax(mean(y), 1e-10)
    deviance <- sum((y - mu)^2 / (mu^2 * y))
    null_deviance <- sum((y - mu_null)^2 / (mu_null^2 * y))
  }

  list(deviance = deviance, null_deviance = null_deviance)
}
