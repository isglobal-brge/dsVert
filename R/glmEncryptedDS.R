#' @title Encrypted GLM Protocol - Server-Side Functions
#' @description Server-side functions for the encrypted-label GLM protocol.
#'   These enable fitting GLMs where the response variable y is only on one
#'   server (the "label server"), and other servers compute their gradient
#'   contributions using y encrypted under the collective public key.
#'
#' @name glm-encrypted-protocol
NULL

#' Encrypt raw response variable under CPK (label server only)
#'
#' @param data_name Character. Name of data frame
#' @param y_var Character. Name of response variable
#'
#' @return List with encrypted_y (base64url) and num_obs
#' @export
mheEncryptRawDS <- function(data_name, y_var) {
  if (is.null(.mhe_storage$cpk)) {
    stop("CPK not stored. Call mheCombineDS or mheStoreCPKDS first.", call. = FALSE)
  }

  data <- .resolveData(data_name, parent.frame())
  y <- as.numeric(data[[y_var]])
  n <- length(y)

  # Encrypt y as a single column (NO standardization, raw values)
  # I() prevents auto_unbox from flattening length-1 rows to scalars
  data_rows <- lapply(seq_len(n), function(i) I(y[i]))

  input <- list(
    data = data_rows,
    collective_public_key = .mhe_storage$cpk,
    log_n = as.integer(.mhe_storage$log_n %||% 12),
    log_scale = as.integer(.mhe_storage$log_scale %||% 40)
  )

  result <- .callMheTool("encrypt-columns", input)

  list(
    encrypted_y = base64_to_base64url(result$encrypted_columns[[1]]),
    num_obs = n
  )
}

#' Store encrypted response variable (non-label servers)
#'
#' @param enc_y Character. Encrypted y ciphertext (base64url, may be chunked)
#'
#' @return TRUE on success
#' @export
mheStoreEncYDS <- function(enc_y) {
  .mhe_storage$enc_y <- .base64url_to_base64(enc_y)
  TRUE
}

#' Compute encrypted GLM gradient using stored ct_y and local X_k
#'
#' @param data_name Character. Name of data frame with local features
#' @param x_vars Character vector. Feature column names on this server
#' @param mu Numeric vector. Plaintext mean vector (length n)
#' @param v Numeric vector. Plaintext v vector (length n, NULL for canonical links)
#' @param num_obs Integer. Number of observations
#'
#' @return List with encrypted_gradients (base64url array, one per feature)
#' @export
mheGLMGradientDS <- function(data_name, x_vars, mu, v = NULL, num_obs) {
  # ct_y stored via chunk mechanism (mheStoreEncChunkDS + mheAssembleEncColumnDS)
  # or directly via mheStoreEncYDS
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
    stop("Galois keys not available. Ensure mheCombineDS/mheStoreCPKDS was called with galois_keys.",
         call. = FALSE)
  }

  # Get local feature matrix (checks .mhe_storage for standardized data)
  data <- .resolveData(data_name, parent.frame())
  X <- as.matrix(data[, x_vars, drop = FALSE])

  # Convert X columns to list format (column-major)
  x_cols <- lapply(seq_len(ncol(X)), function(j) as.numeric(X[, j]))

  input <- list(
    encrypted_y = enc_y,
    mu = as.numeric(mu),
    v = if (!is.null(v)) as.numeric(v) else NULL,
    x_cols = x_cols,
    galois_keys = as.list(.mhe_storage$galois_keys),
    num_obs = as.integer(num_obs),
    log_n = as.integer(.mhe_storage$log_n %||% 12),
    log_scale = as.integer(.mhe_storage$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-glm-gradient", input)

  # Convert to base64url
  enc_grads <- sapply(result$encrypted_gradients, base64_to_base64url, USE.NAMES = FALSE)

  list(encrypted_gradients = enc_grads)
}

#' Solve BCD block update given decrypted gradient (non-label server)
#'
#' @param data_name Character. Name of data frame with local features
#' @param x_vars Character vector. Feature column names
#' @param w Numeric vector. IRLS weights (length n)
#' @param beta_current Numeric vector. Current coefficients (length p_k)
#' @param gradient Numeric vector. Decrypted gradient g_k (length p_k)
#' @param lambda Numeric. L2 regularization parameter
#'
#' @return List with beta (updated coefficients) and eta (X_k * beta_new)
#' @export
glmBlockSolveDS <- function(data_name, x_vars, w, beta_current, gradient, lambda = 1e-4) {
  data <- .resolveData(data_name, parent.frame())
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p <- ncol(X)

  # Privacy check
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }

  # BCD update: beta_new = (X^T W X + lambda*I)^{-1} (X^T W X beta + g_k)
  XtWX <- crossprod(X, w * X) + diag(lambda, p)
  rhs <- as.vector(XtWX %*% beta_current) + gradient

  beta_new <- tryCatch(
    as.vector(solve(XtWX, rhs)),
    error = function(e) {
      warning("Matrix near-singular, using additional regularization")
      as.vector(solve(XtWX + diag(0.01, p), rhs))
    }
  )

  # Check for extreme updates
  if (any(abs(beta_new) > 1e6)) {
    beta_new <- beta_new / max(abs(beta_new)) * 1e2
    warning("Large coefficient update detected, scaling applied")
  }

  eta_new <- as.vector(X %*% beta_new)

  list(
    beta = beta_new,
    eta = eta_new,
    converged = TRUE
  )
}
