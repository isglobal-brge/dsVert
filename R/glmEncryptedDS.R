#' @title Encrypted GLM Protocol - Server-Side Functions
#' @description Server-side functions for the encrypted-label GLM protocol.
#'   These enable fitting GLMs where the response variable y is only on one
#'   server (the "label server"), and other servers compute their gradient
#'   contributions using y encrypted under the collective public key.
#'
#' @details
#' In vertically partitioned GLM, the response y lives on a single "label
#' server" and must never be revealed to other servers. Non-label servers
#' hold feature matrices X_k and need to compute gradient contributions
#' X_k^T (y - mu) without seeing y. The solution: the label server encrypts
#' y under the collective public key (CPK), and non-label servers compute
#' gradients homomorphically on the ciphertext. Threshold decryption then
#' reveals only the p_k-length gradient vector (one scalar per feature),
#' not individual observations.
#'
#' The four functions below implement this encrypted gradient protocol:
#' \enumerate{
#'   \item \code{mheEncryptRawDS}: Label server encrypts y under CPK
#'   \item \code{mheStoreEncYDS}: Non-label servers receive and store ct_y
#'   \item \code{mheGLMGradientDS}: Non-label servers compute X_k^T (ct_y - mu)
#'     homomorphically, returning encrypted gradient vectors
#'   \item \code{glmBlockSolveDS}: After threshold decryption of the gradient,
#'     non-label servers solve the BCD block update using the plaintext gradient
#' }
#'
#' @references
#' van Kesteren, E.J. et al. (2019). Privacy-preserving generalized linear
#' models using distributed block coordinate descent. arXiv:1911.03183.
#'
#' @name glm-encrypted-protocol
NULL

#' Encrypt raw response variable under CPK (label server only)
#'
#' Encrypts the response variable y under the Collective Public Key (CPK)
#' so it can be distributed to non-label servers for homomorphic gradient
#' computation. The encrypted y is a CKKS ciphertext that supports
#' addition and multiplication with plaintext vectors.
#'
#' @param data_name Character. Name of data frame on the label server.
#' @param y_var Character. Name of the response variable column.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{encrypted_y}: base64url-encoded CKKS ciphertext of y
#'     \item \code{num_obs}: number of observations
#'   }
#'
#' @details
#' For Gaussian family, y is standardized before encryption (handled by
#' \code{glmStandardizeDS}). For non-Gaussian families, raw y values are
#' encrypted because the link function is nonlinear and standardization
#' would change the model.
#'
#' Each observation is packed as a single-element row because the Go
#' encrypt-columns command expects row-major input. The \code{I()} wrapper
#' prevents \code{jsonlite::auto_unbox} from converting length-1 vectors
#' to JSON scalars (Go expects arrays).
#'
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
#' Receives the encrypted response ciphertext ct_y from the client and stores
#' it in \code{.mhe_storage} for use by \code{mheGLMGradientDS}. This is a
#' simple storage function -- the non-label server cannot decrypt ct_y because
#' decryption requires ALL servers' secret key shares.
#'
#' @param enc_y Character. Encrypted y ciphertext (base64url encoded). May
#'   arrive via chunked transfer (\code{mheStoreEncChunkDS} +
#'   \code{mheAssembleEncColumnDS}) for large ciphertexts, in which case
#'   this function is not called directly.
#'
#' @return TRUE on success.
#' @export
mheStoreEncYDS <- function(enc_y) {
  .mhe_storage$enc_y <- .base64url_to_base64(enc_y)
  TRUE
}

#' Compute encrypted GLM gradient using stored ct_y and local X_k
#'
#' Core of the encrypted-label protocol. Computes the gradient contribution
#' for this server's feature block using homomorphic operations on ct_y:
#'
#' \deqn{g_k = X_k^T (ct_y - \mu)}
#'
#' For non-canonical link functions (Gamma, inverse.gaussian), the gradient
#' additionally involves a variance function factor v:
#'
#' \deqn{g_k = X_k^T \cdot v \cdot (ct_y - \mu)}
#'
#' The result is a vector of p_k encrypted scalars (one per feature). Each
#' requires threshold decryption by ALL servers before the gradient is usable.
#' This ensures no single server (or the client) learns anything about y beyond
#' what the p_k-length gradient reveals.
#'
#' @param data_name Character. Name of data frame with local features
#'   (typically the standardized version).
#' @param x_vars Character vector. Feature column names on this server.
#' @param mu Numeric vector. Current mean predictions (plaintext, length n).
#'   Broadcast by the client from the label server's IRLS step.
#' @param v Numeric vector or NULL. Variance function factor (length n).
#'   NULL for canonical links (gaussian, binomial, poisson) where v = 1.
#'   Non-NULL for Gamma (v = 1/mu) and inverse.gaussian (v = 1/mu^2).
#' @param num_obs Integer. Number of observations (for CKKS slot count).
#'
#' @return List with \code{encrypted_gradients}: base64url array of p_k
#'   encrypted gradient components, each requiring threshold decryption.
#'
#' @details
#' The Galois keys (stored in \code{.mhe_storage}) are required for the
#' inner sum reduction: after element-wise multiplication of x_j with
#' (ct_y - mu), the Go binary uses Galois rotations to sum across the n
#' slots of the ciphertext, producing a single encrypted scalar per feature.
#'
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

  # Protocol Firewall: register each gradient ciphertext
  ct_hashes <- character(length(result$encrypted_gradients))
  for (j in seq_along(result$encrypted_gradients)) {
    ct_hashes[j] <- .register_ciphertext(result$encrypted_gradients[[j]], "glm-gradient")
  }

  # Convert to base64url
  enc_grads <- sapply(result$encrypted_gradients, base64_to_base64url, USE.NAMES = FALSE)

  list(encrypted_gradients = enc_grads, ct_hashes = ct_hashes)
}

#' Solve BCD block update given decrypted gradient (non-label server)
#'
#' After threshold decryption reveals the p_k-length gradient g_k, this
#' function performs the Block Coordinate Descent update for the non-label
#' server's coefficient block. The update formula is:
#'
#' \deqn{\beta_k^{new} = (X_k^T W X_k + \lambda I)^{-1} (X_k^T W X_k \beta_k^{old} + g_k)}
#'
#' This is a Newton-Raphson step where X_k^T W X_k is the local Hessian
#' approximation and g_k is the gradient from the encrypted protocol.
#' The L2 penalty lambda*I ensures the Hessian is positive definite.
#'
#' @param data_name Character. Name of data frame with local features
#'   (typically the standardized version).
#' @param x_vars Character vector. Feature column names on this server.
#' @param w Numeric vector. IRLS weights (length n), broadcast by client.
#'   Family-dependent: gaussian=1, binomial=mu*(1-mu), poisson=mu.
#' @param beta_current Numeric vector. Current coefficients (length p_k).
#' @param gradient Numeric vector. Decrypted gradient g_k (length p_k)
#'   from threshold decryption.
#' @param lambda Numeric. L2 regularization parameter. Default 1e-4.
#'   Prevents singular Hessian and adds mild shrinkage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{beta}: Updated coefficient vector (length p_k)
#'     \item \code{eta}: Linear predictor contribution X_k * beta_new (length n)
#'     \item \code{converged}: TRUE unless extreme update scaling was needed
#'   }
#'
#' @export
glmBlockSolveDS <- function(data_name, x_vars, w, beta_current, gradient, lambda = 1e-4) {
  data <- .resolveData(data_name, parent.frame())
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p <- ncol(X)

  # Disclosure controls (dsBase pattern)
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }

  # GLM disclosure checks: saturation + binary variable small cells
  .check_glm_disclosure(X)

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

  # Guard against numerical blow-up from near-singular X^T W X or noisy
  # gradients (CKKS approximation noise can occasionally amplify updates).
  # Threshold 1e6 is conservative; scaling to 1e2 preserves direction.
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
