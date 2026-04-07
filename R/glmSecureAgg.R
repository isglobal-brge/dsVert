#' @title GLM Secure Aggregation Functions
#' @description Server-side functions for the GLM secure aggregation protocol
#'   (K>=3 non-label servers). Uses pairwise PRG masks with fixed-point
#'   arithmetic so the coordinator only sees the aggregate linear predictor
#'   (sum of all eta_k), never individual per-server contributions.
#'
#' @details
#' The secure aggregation protocol works as follows:
#' \enumerate{
#'   \item Each pair of non-label servers derives a shared PRG seed via
#'     X25519 + HKDF (bound to the session ID).
#'   \item When masking eta_k, server i adds +mask for peers j > i and
#'     -mask for peers j < i (canonical ordering ensures cancellation).
#'   \item The coordinator sums all masked etas. Pairwise masks cancel,
#'     leaving only the true aggregate eta_other = sum(eta_k).
#'   \item Individual eta_k values are never decrypted or stored.
#' }
#'
#' @name glm-secure-agg
NULL

# ============================================================================
# Secure Aggregation Initialization (non-label servers)
# ============================================================================

#' Initialize secure aggregation on a non-label server
#'
#' Derives pairwise PRG seeds with all other non-label servers using
#' X25519 ECDH + HKDF. The seeds are stored in \code{.mhe_storage} for
#' use in subsequent \code{glmSecureAggBlockSolveDS} calls.
#'
#' @param self_name Character. This server's canonical name.
#' @param session_id Character. UUID for this GLM session.
#' @param nonlabel_names Character vector. ALL non-label server names (sorted).
#' @param scale_bits Integer. Fixed-point scale exponent. Default 20.
#' @param topology Character. Seed derivation topology: \code{"pairwise"}
#'   (default, O(K-1) seeds per server) or \code{"ring"} (O(2) seeds per
#'   server for K>=4). For K=3, ring and pairwise are identical.
#'
#' @return TRUE (invisible)
#' @export
glmSecureAggInitDS <- function(self_name, session_id,
                                nonlabel_names, scale_bits = 20L,
                                topology = "pairwise") {
  ss <- .S(session_id)
  if (!.key_exists("transport_sk", ss))
    stop("Transport SK not stored. Call mheInitDS first.", call. = FALSE)
  if (is.null(ss$peer_transport_pks))
    stop("Peer transport PKs not stored. Call mheStoreTransportKeysDS first.",
         call. = FALSE)

  # Manifest consensus gate: when enabled, require all peers to be validated
  manifest_consensus <- .read_dsvert_option("dsvert.manifest_consensus", FALSE)
  if (isTRUE(manifest_consensus) || identical(tolower(as.character(manifest_consensus)), "true")) {
    if (is.null(ss$validated_peers) || length(ss$validated_peers) == 0) {
      stop("Manifest consensus required but no peers validated. ",
           "Run peerManifestStoreDS + peerManifestValidateDS first.",
           call. = FALSE)
    }
    expected_peers <- setdiff(sort(nonlabel_names), self_name)
    missing <- setdiff(expected_peers, ss$validated_peers)
    if (length(missing) > 0) {
      stop("Manifest consensus incomplete: peers not validated: ",
           paste(missing, collapse = ", "), call. = FALSE)
    }
  } else if (!is.null(ss$manifest_hash) &&
             (is.null(ss$validated_peers) || length(ss$validated_peers) == 0)) {
    warning("Manifest exists but peers not validated. ",
            "Set dsvert.manifest_consensus=TRUE to enforce.", call. = FALSE)
  }

  nonlabel_names <- sort(nonlabel_names)

  # Determine peers based on topology
  if (topology == "ring") {
    sorted <- nonlabel_names
    self_idx <- which(sorted == self_name)
    K <- length(sorted)
    if (K < 3) {
      # For K<3, ring and pairwise are identical
      topology <- "pairwise"
    }
  }

  if (topology == "ring") {
    prev_idx <- if (self_idx == 1) K else self_idx - 1
    next_idx <- if (self_idx == K) 1 else self_idx + 1
    peers <- unique(c(sorted[prev_idx], sorted[next_idx]))
  } else {
    peers <- setdiff(nonlabel_names, self_name)
  }

  if (length(peers) < 1)
    stop("Secure aggregation requires >= 2 non-label servers", call. = FALSE)

  seeds <- list()
  for (peer in peers) {
    peer_pk <- ss$peer_transport_pks[[peer]]
    if (is.null(peer_pk))
      stop("No transport PK stored for peer '", peer, "'", call. = FALSE)

    # Derive shared seed via Go binary
    result <- .callMheTool("derive-shared-seed", list(
      self_sk = .key_get("transport_sk", ss),
      peer_pk = peer_pk,
      session_id = session_id,
      self_name = self_name,
      peer_name = peer
    ))

    # Determine sign: canonical pair (A,B) where A < B: A gets +1, B gets -1
    pair_sorted <- sort(c(self_name, peer))
    sign <- if (self_name == pair_sorted[1]) 1L else -1L

    seeds[[peer]] <- list(seed = result$seed, sign = sign)
  }

  ss$secure_agg_seeds <- seeds
  ss$secure_agg_scale_bits <- as.integer(scale_bits)
  ss$secure_agg_session_id <- session_id

  invisible(TRUE)
}

# ============================================================================
# Secure Aggregation Block Solve (non-label servers)
# ============================================================================

#' BCD block solve with masked eta output (secure aggregation)
#'
#' Non-label server function for the secure aggregation protocol. After
#' threshold decryption reveals the gradient, this function:
#' \enumerate{
#'   \item Solves the BCD block update (same math as \code{glmSecureBlockSolveDS})
#'   \item Computes eta_new = X * beta_new (plaintext)
#'   \item Masks eta_new using pairwise PRG masks (fixed-point integer arithmetic)
#'   \item Transport-encrypts the masked vector under the coordinator's PK
#' }
#'
#' The coordinator can only recover the aggregate (sum of all masked etas),
#' never individual per-server eta_k values.
#'
#' @param data_name Character. Name of the data frame with local features.
#' @param x_vars Character vector. Feature column names on this server.
#' @param beta_current Numeric vector. Current coefficients for this block.
#' @param gradient Numeric vector. Decrypted gradient from threshold decryption.
#' @param lambda Numeric. L2 regularization parameter. Default 1e-4.
#' @param coordinator_pk Character. Coordinator's transport PK (base64url).
#' @param iteration Integer. Current BCD iteration.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{beta}: Updated coefficient vector (p_k-length, safe aggregate)
#'     \item \code{encrypted_masked_eta}: Transport-encrypted masked eta (opaque)
#'   }
#'
#' @seealso \code{\link{glmSecureAggInitDS}}, \code{\link{glmSecureAggCoordinatorStepDS}}
#' @export
#' Gaussian one-shot: compute local X_k^T X_k (and X_k^T y for label server)
#' @export
glmGaussianLocalXtXDS <- function(data_name, x_vars, y_var = NULL,
                                    session_id = NULL) {
  ss <- .S(session_id)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X); p <- ncol(X)

  XtX_local <- as.numeric(crossprod(X))

  Xty_local <- NULL
  if (!is.null(y_var) && y_var %in% names(data)) {
    y <- as.numeric(data[[y_var]])
    Xty_local <- as.numeric(crossprod(X, y))
  }

  list(xtx_local = XtX_local, xty_local = Xty_local, n = n, p = p)
}

#' Pairwise Beaver cross-product: compute X_j^T X_k between two servers
#' Each server provides its own columns. The Beaver product computes
#' the element-wise product, summed over rows.
#' @export
glmPairwiseCrossProductDS <- function(data_name, x_vars, peer_p,
                                        party_id = 0L, phase = 1L,
                                        y_var = NULL, frac_bits = 20L,
                                        session_id = NULL) {
  ss <- .S(session_id)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X); p_my <- ncol(X)

  if (phase == 1L) {
    # Phase 1: Beaver R1 for pairwise cross-product
    blob <- .blob_consume("pairwise_cross_triples", ss)
    if (is.null(blob)) stop("No pairwise cross triple blob")
    tsk <- .key_get("transport_sk", ss)
    dec <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(blob), recipient_sk = tsk))
    triple <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

    # Create operands: my_cols as one operand, zeros as the other
    # party_id=0 → my columns go first, party_id=1 → my columns go second
    # y_var: if provided, include y as the y_share operand (for X^T y computation)
    y_vals <- rep(0, n)
    if (!is.null(y_var) && y_var %in% names(data))
      y_vals <- as.numeric(data[[y_var]])

    result <- .callMheTool("k2-gaussian-oneshot", list(
      phase = 1L, party_id = as.integer(party_id), frac_bits = frac_bits,
      n = as.integer(n), p = as.integer(p_my + peer_p),
      x_full_fp = .callMheTool("k2-float-to-fp", list(
        values = if (party_id == 0L) c(as.numeric(t(cbind(X, matrix(0, n, peer_p)))))
                 else c(as.numeric(t(cbind(matrix(0, n, peer_p), X)))),
        frac_bits = frac_bits))$fp_data,
      y_share_fp = .callMheTool("k2-float-to-fp", list(
        values = y_vals, frac_bits = frac_bits))$fp_data,
      triple_a = triple$a, triple_b = triple$b))

    ss$pairwise_cross_triple <- triple
    list(xma = result$xma, ymb = result$ymb)
  } else {
    # Phase 2: Beaver close → cross-product shares
    triple <- ss$pairwise_cross_triple
    blob <- .blob_consume("pairwise_cross_peer_r1", ss)
    if (is.null(blob)) stop("No peer cross R1 blob")
    tsk <- .key_get("transport_sk", ss)
    dec <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(blob), recipient_sk = tsk))
    peer_r1 <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

    y_vals <- rep(0, n)
    if (!is.null(y_var) && y_var %in% names(data))
      y_vals <- as.numeric(data[[y_var]])

    result <- .callMheTool("k2-gaussian-oneshot", list(
      phase = 2L, party_id = as.integer(party_id), frac_bits = frac_bits,
      n = as.integer(n), p = as.integer(p_my + peer_p),
      x_full_fp = .callMheTool("k2-float-to-fp", list(
        values = if (party_id == 0L) c(as.numeric(t(cbind(X, matrix(0, n, peer_p)))))
                 else c(as.numeric(t(cbind(matrix(0, n, peer_p), X)))),
        frac_bits = frac_bits))$fp_data,
      y_share_fp = .callMheTool("k2-float-to-fp", list(
        values = y_vals, frac_bits = frac_bits))$fp_data,
      triple_a = triple$a, triple_b = triple$b, triple_c = triple$c,
      peer_xma = peer_r1$xma, peer_ymb = peer_r1$ymb))

    ss$pairwise_cross_triple <- NULL
    list(cross_xtx_fp = result$cross_xtx_fp, cross_xty_fp = result$cross_xty_fp)
  }
}

glmSecureAggBlockSolveDS <- function(data_name, x_vars,
                                      beta_current, gradient,
                                      lambda = 1e-4,
                                      coordinator_pk,
                                      iteration = 1L,
                                      skip_solve = FALSE,
                                      session_id = NULL) {
  ss <- .S(session_id)
  if (!.key_exists("transport_sk", ss))
    stop("Transport SK not stored. Call mheInitDS first.", call. = FALSE)
  if (is.null(ss$secure_agg_seeds))
    stop("Secure aggregation not initialized. Call glmSecureAggInitDS first.",
         call. = FALSE)

  # BCD block update (same math as glmSecureBlockSolveDS)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p <- ncol(X)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level)
    stop("Insufficient observations for privacy-preserving analysis",
         call. = FALSE)
  .check_glm_disclosure(X)

  if (isTRUE(skip_solve)) {
    # L-BFGS mode: client provides beta directly, skip block solve + mwv
    # Consume mwv blob if present (to clean up) but don't use it
    tryCatch(.blob_consume("mwv", ss), error = function(e) NULL)
    beta_new <- as.numeric(beta_current)
  } else {
    # Read (mu, w, v) from blob storage (sent by client)
    encrypted_mwv <- .blob_consume("mwv", ss)
    if (is.null(encrypted_mwv))
      stop("No encrypted (mu, w, v) blob stored.", call. = FALSE)
    decrypted <- .callMheTool("transport-decrypt-vectors", list(
      sealed = .base64url_to_base64(encrypted_mwv),
      recipient_sk = .key_get("transport_sk", ss)
    ))
    w <- as.numeric(decrypted$vectors$w)

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
  }

  # Compute eta_new = X * beta_new (plaintext, n-length)
  eta_new <- as.vector(X %*% beta_new)

  # Mask eta_new using pairwise PRG masks (fixed-point integer arithmetic)
  seeds_list <- ss$secure_agg_seeds
  seed_values <- vapply(seeds_list, function(s) s$seed, character(1))
  sign_values <- vapply(seeds_list, function(s) s$sign, integer(1))
  scale_bits <- ss$secure_agg_scale_bits

  mask_result <- .callMheTool("fixed-point-mask-eta", list(
    eta = as.numeric(eta_new),
    seeds = as.list(unname(seed_values)),
    signs = as.list(unname(sign_values)),
    iteration = as.integer(iteration),
    scale_bits = as.integer(scale_bits)
  ))

  # Transport-encrypt the masked vector under coordinator PK
  sealed <- .callMheTool("transport-encrypt-vectors", list(
    vectors = list(masked_eta = mask_result$masked_scaled),
    recipient_pk = .base64url_to_base64(coordinator_pk)
  ))
  encrypted_masked_eta <- base64_to_base64url(sealed$sealed)

  list(
    beta = beta_new,
    encrypted_masked_eta = encrypted_masked_eta
  )
}

# ============================================================================
# Secure Aggregation Coordinator Step (label server)
# ============================================================================

#' GLM Coordinator Step with secure aggregation (label server)
#'
#' Called once per BCD iteration on the label server (coordinator). Differs
#' from \code{glmCoordinatorStepDS} ONLY in eta aggregation:
#' \itemize{
#'   \item Decrypts masked eta blobs from non-label servers
#'   \item Sums ALL masked vectors element-wise (pairwise masks cancel)
#'   \item Immediately discards individual masked vectors (never stored)
#'   \item Recovers true aggregate eta_other by dividing by 2^scale_bits
#' }
#'
#' The rest (IRLS step, coefficient update, encrypting mu/w for non-label
#' servers) is identical to \code{glmCoordinatorStepDS}.
#'
#' @param data_name Character. Name of the standardized data frame.
#' @param y_var Character. Name of the response variable.
#' @param x_vars Character vector. Feature column names on the label server.
#' @param eta_blob_keys Character vector or NULL. Keys in blob storage
#'   containing encrypted masked eta blobs from non-label servers.
#' @param non_label_pks Named list. Server name -> transport PK (base64url).
#' @param family Character. GLM family. Default \code{"gaussian"}.
#' @param beta_current Numeric vector or NULL. Current label-server coefficients.
#' @param lambda Numeric. L2 regularization. Default 1e-4.
#' @param intercept Logical. Include intercept column. Default FALSE.
#' @param n_obs Integer. Number of observations.
#' @param scale_bits Integer. Fixed-point scale exponent. Default 20.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{beta}: Updated label-server coefficients
#'     \item \code{encrypted_blobs}: Named list of encrypted (mu, w) blobs
#'     \item \code{converged}: Logical from IRLS convergence check
#'   }
#'
#' @seealso \code{\link{glmSecureAggBlockSolveDS}}, \code{\link{glmSecureAggInitDS}}
#' @export
glmSecureAggCoordinatorStepDS <- function(data_name, y_var, x_vars,
                                           eta_blob_keys = NULL,
                                           non_label_pks = NULL,
                                           family = "gaussian",
                                           beta_current = NULL,
                                           lambda = 1e-4,
                                           intercept = FALSE,
                                           n_obs = NULL,
                                           scale_bits = 20L,
                                           session_id = NULL) {
  ss <- .S(session_id)
  # Aggregate masked etas from non-label servers
  eta_other <- rep(0, n_obs)

  if (!is.null(eta_blob_keys) && length(eta_blob_keys) > 0) {
    if (!.key_exists("transport_sk", ss))
      stop("Transport SK not stored. Call mheInitDS first.", call. = FALSE)

    tsk <- .key_get("transport_sk", ss)
    # Collect all masked vectors, decrypt, sum immediately
    masked_vectors <- list()
    for (key in eta_blob_keys) {
      blob <- .blob_consume(key, ss)
      if (is.null(blob)) next

      # Decrypt the masked eta vector
      decrypted <- .callMheTool("transport-decrypt-vectors", list(
        sealed = .base64url_to_base64(blob),
        recipient_sk = tsk
      ))

      masked_vectors[[length(masked_vectors) + 1]] <- as.numeric(decrypted$vectors$masked_eta)
    }

    # KEY DIFFERENCE: Sum all masked vectors (masks cancel)
    if (length(masked_vectors) > 0) {
      sum_masked <- Reduce("+", masked_vectors)
      # Immediately discard individual masked vectors (privacy guarantee)
      masked_vectors <- NULL

      # Recover true aggregate eta: divide by 2^scale_bits
      scale <- 2^as.integer(scale_bits)
      eta_other <- sum_masked / scale
    }
  }

  # ---- Remainder is identical to glmCoordinatorStepDS ----

  # Run IRLS step
  data <- .resolveData(data_name, parent.frame(), session_id)

  if (!is.data.frame(data))
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)

  y <- as.numeric(data[[y_var]])
  X <- as.matrix(data[, x_vars, drop = FALSE])

  if (isTRUE(intercept))
    X <- cbind("(Intercept)" = rep(1, nrow(X)), X)

  n <- length(y)
  p <- ncol(X)

  if (is.null(beta_current) || length(beta_current) == 0)
    beta_current <- rep(0, p)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level)
    stop("Insufficient observations for privacy-preserving analysis",
         call. = FALSE)
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

  # Compute eta_total, mu, w for non-label servers
  eta_total <- eta_label + eta_other

  # Store for deviance computation
  ss$glm_eta_label <- eta_label
  ss$glm_eta_other <- eta_other

  # Recompute mu, w from eta_total
  if (family == "gaussian") {
    mu_total <- eta_total
    w_total <- rep(1, n)
  } else if (family == "binomial") {
    eta_total <- pmax(pmin(eta_total, 20), -20)
    mu_total <- 1 / (1 + exp(-eta_total))
    mu_total <- pmax(pmin(mu_total, 1 - 1e-10), 1e-10)
    w_total <- mu_total * (1 - mu_total)
  } else if (family == "poisson") {
    eta_total <- pmin(eta_total, 20)
    mu_total <- exp(eta_total)
    mu_total <- pmax(mu_total, 1e-10)
    w_total <- mu_total
  }

  # Encrypt (mu, w) under each non-label server's transport PK
  # (kept for BCD mode compatibility)
  encrypted_blobs <- list()
  if (!is.null(non_label_pks) && length(non_label_pks) > 0) {
    vectors_to_encrypt <- list(mu = as.numeric(mu_total), w = as.numeric(w_total))

    for (server_name in names(non_label_pks)) {
      pk <- .base64url_to_base64(non_label_pks[[server_name]])
      sealed <- .callMheTool("transport-encrypt-vectors", list(
        vectors = vectors_to_encrypt,
        recipient_pk = pk
      ))
      encrypted_blobs[[server_name]] <- base64_to_base64url(sealed$sealed)
    }
  }

  # Encrypt residual r = y - mu under CPK for L-BFGS gradient
  # Non-label servers compute X_k^T * Enc(r) — they never see mu or w
  residual <- as.numeric(y - mu_total)
  encrypted_residual <- NULL
  if (.key_exists("cpk", ss)) {
    tryCatch({
      enc_r_result <- .callMheTool("mhe-encrypt-vector", list(
        vector = residual,
        collective_public_key = .key_get("cpk", ss),
        log_n = as.integer(ss$log_n %||% 12),
        log_scale = as.integer(ss$log_scale %||% 40)
      ))
      if (!is.null(enc_r_result$ciphertext))
        encrypted_residual <- base64_to_base64url(enc_r_result$ciphertext)
    }, error = function(e) NULL)
  }

  # Gradient for L-BFGS (client-side optimizer)
  # NOT divided by n — consistent with CKKS gradient (unnormalized)
  gradient_label <- as.numeric(crossprod(X, residual))

  list(
    beta = beta_new,
    encrypted_blobs = encrypted_blobs,
    converged = converged,
    gradient_label = gradient_label,
    encrypted_residual = encrypted_residual
  )
}

# ============================================================================
# Secure Aggregation Deviance Preparation (non-label servers)
# ============================================================================

#' Prepare eta for deviance computation (secure aggregation)
#'
#' After BCD convergence, computes eta = X * beta on the non-label server
#' and sends it (unmasked, one-time) to the coordinator. This is acceptable
#' because:
#' \itemize{
#'   \item Happens once after convergence (not per-iteration)
#'   \item eta_total = X*beta where beta is already public
#'   \item Coordinator already knows y
#' }
#'
#' @param data_name Character. Name of the data frame with local features.
#' @param x_vars Character vector. Feature column names on this server.
#' @param beta Numeric vector. Final converged coefficients.
#' @param coordinator_pk Character or NULL. Coordinator's transport PK.
#'   NULL if this IS the coordinator.
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses legacy shared storage.
#'
#' @return List with encrypted_eta (NULL if coordinator).
#'
#' @seealso \code{\link{glmSecureAggCoordinatorStepDS}}
#' @export
glmSecureAggPrepDevianceDS <- function(data_name, x_vars, beta,
                                        coordinator_pk = NULL,
                                        session_id = NULL) {
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
  # If beta includes an intercept (p+1 elements for p columns), add intercept column
  if (length(beta) == ncol(X) + 1) {
    X <- cbind(1, X)
  }
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
