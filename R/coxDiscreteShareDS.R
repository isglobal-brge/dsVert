#' @title Cox discrete-time non-disclosive share-mask primitives (#D')
#' @description Hide J_i (per-patient ending bin index) from every covariate
#'   server. Implements the
#'   share-mask gating pattern documented in
#'   \code{project_k2_strict_unified_plan_2026-04-27.md} Sec."Option B
#'   FEASIBILITY ANALYSIS":
#'
#'   - At the outcome (label) server, J_i and status_i are local plaintext.
#'     Compute the per-patient at-risk mask m_ij in \{0,1\} (j=1..J,
#'     i=1..n) where m_ij = I(j <= J_i) and the event indicator
#'     y_ij = I(j == J_i AND status_i = 1).
#'   - Both m and y get split into Ring127 additive shares between OS and
#'     one DCF/fusion covariate server. That server thereby never sees J_i
#'     directly; the only signal it receives is two random-looking
#'     length-(J*n) shares that, summed pointwise mod 2^127 with the OS
#'     shares, reconstruct m and y.
#'   - Every covariate server expands its X to a UNIFORM Jxn person-period
#'     frame (every patient contributes J rows, regardless of true J_i),
#'     so no row-count signal leaks. In K>=3, non-DCF servers send only
#'     encrypted additive shares of this uniform frame to the two DCF parties.
#'     The mask shares gate which rows enter the score / Hessian aggregations
#'     downstream via Beaver vecmul against (y - p) and W = p*(1-p).
#'
#'   Cite: Aliasgari-Blanton 2013 NDSS eprint 2012/405 (share-mask
#'   gating); Cock et al. 2016 eprint 2016/736 (oblivious selection);
#'   Mohassel-Zhang 2017 IEEE S&P eprint 2017/396 SecureML; Andreux et
#'   al. 2020 arXiv:2006.08997 (discrete-time Cox MLE pooled-logistic);
#'   Allison 1982 *Sociological Methodology* 13:61-98 (canonical pooled-
#'   logistic equivalence to discrete Cox); Catrina-Saxena 2010 FC2010
#'   (Ring127 frac=50 truncation noise floor).
#'
#' @param data_name Character. Local data frame name on outcome server.
#' @param time_var Character. Survival time column name.
#' @param status_var Character. Event indicator (0/1) column name.
#' @param J Integer. Number of time bins for the discrete-time grid.
#' @param bin_breaks Numeric vector of length J+1 (sorted, increasing,
#'   first = 0). Must be passed by client to keep bin definitions
#'   reproducible across servers.
#' @param mask_output_key,y_output_key Character. Session slots to write
#'   own (OS) Ring127 shares of the flattened m_ij and y_ij vectors
#'   (length J*n, row-major:
#'   \code{m[1,1], m[1,2], ..., m[1,J], m[2,1], ...}).
#' @param target_pk Character. NL's transport public key (base64url).
#' @param session_id Character.
#' @return List(sealed_m_blob = b64url, sealed_y_blob = b64url,
#'   n_obs = <int>, J = <int>, n_pp = <int>=J*n).
#' @export
dsvertCoxDiscreteShareMaskDS <- function(data_name, time_var, status_var,
                                          J, bin_breaks,
                                          mask_output_key, y_output_key,
                                          target_pk, session_id,
                                          debug = FALSE) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!time_var %in% names(data))
    stop("time_var '", time_var, "' not in data", call. = FALSE)
  if (!status_var %in% names(data))
    stop("status_var '", status_var, "' not in data", call. = FALSE)
  J <- as.integer(J)
  if (!is.finite(J) || J < 2L) stop("J must be >= 2", call. = FALSE)
  bin_breaks <- as.numeric(bin_breaks)
  if (length(bin_breaks) != J + 1L)
    stop(sprintf("bin_breaks length %d != J+1 = %d",
                  length(bin_breaks), J + 1L), call. = FALSE)
  if (any(diff(bin_breaks) <= 0))
    stop("bin_breaks must be strictly increasing", call. = FALSE)
  if (length(bin_breaks) > 1L) {
    eps <- max(1e-12, 128 * .Machine$double.eps *
                 max(1, max(abs(bin_breaks), na.rm = TRUE)))
    bin_breaks[-1L] <- bin_breaks[-1L] + eps
    if (any(diff(bin_breaks) <= 0))
      stop("bin_breaks too close after numeric stabilisation",
           call. = FALSE)
  }
  ss <- .S(session_id)

  t_vec <- as.numeric(data[[time_var]])
  d_vec <- as.integer(data[[status_var]])
  n <- length(t_vec)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n < privacy_min)
    stop("Insufficient observations (n=", n, ")", call. = FALSE)

  # Per-patient ending bin (1-indexed), capped to J.
  J_i <- as.integer(cut(t_vec, breaks = bin_breaks,
                         include.lowest = TRUE, right = TRUE))
  J_i <- pmin(pmax(J_i, 1L), J)

  # Build flattened (n, J) row-major matrices m, y (length n*J).
  # Convention: idx = (i-1)*J + j  for patient i, bin j.
  m <- numeric(as.integer(n) * J)
  y <- numeric(as.integer(n) * J)
  for (i in seq_len(n)) {
    Ji  <- J_i[i]
    di  <- d_vec[i]
    base <- (i - 1L) * J
    if (Ji >= 1L) m[base + seq_len(Ji)] <- 1
    if (di == 1L) y[base + Ji] <- 1
  }

  # Encode + split into Ring127 shares (frac_bits=50, sign-aware).
  fp_m <- .callMpcTool("k2-float-to-fp",
                        list(values = m, frac_bits = 50L,
                             ring = "ring127"))$fp_data
  split_m <- .callMpcTool("k2-split-fp-share",
                           list(data_fp = fp_m, n = length(m),
                                frac_bits = 50L, ring = "ring127"))
  ss[[mask_output_key]] <- split_m$own_share
  pk_std <- .base64url_to_base64(target_pk)
  sealed_m <- .callMpcTool("transport-encrypt",
                            list(data = jsonlite::base64_enc(
                                   charToRaw(split_m$peer_share)),
                                 recipient_pk = pk_std))

  fp_y <- .callMpcTool("k2-float-to-fp",
                        list(values = y, frac_bits = 50L,
                             ring = "ring127"))$fp_data
  split_y <- .callMpcTool("k2-split-fp-share",
                           list(data_fp = fp_y, n = length(y),
                                frac_bits = 50L, ring = "ring127"))
  ss[[y_output_key]] <- split_y$own_share
  sealed_y <- .callMpcTool("transport-encrypt",
                            list(data = jsonlite::base64_enc(
                                   charToRaw(split_y$peer_share)),
                                 recipient_pk = pk_std))

  list(
    sealed_m_blob = base64_to_base64url(sealed_m$sealed),
    sealed_y_blob = base64_to_base64url(sealed_y$sealed),
    n_obs         = as.integer(n),
    J             = J,
    n_pp          = as.integer(n) * J,
    debug         = if (isTRUE(debug)) {
      list(bin_breaks = bin_breaks,
           J_i_counts = as.integer(tabulate(J_i, nbins = J)),
           y_counts = as.integer(vapply(seq_len(J), function(j) {
             sum(J_i == j & d_vec == 1L)
           }, integer(1L))),
           time_range = range(t_vec, na.rm = TRUE))
    } else NULL
  )
}


#' @title Cox discrete-time receive shared mask + y at DCF peer
#' @description Counterpart to \code{dsvertCoxDiscreteShareMaskDS} --
#'   non-label server transport-decrypts the sealed mask + y blobs and
#'   stores them as Ring127 shares (length J*n, row-major). Forms the
#'   additive share pair (own at OS, peer at NL) needed for the
#'   downstream Beaver-gated person-period Cox Newton.
#' @param mask_blob_key,y_blob_key Character. Session blob slots
#'   holding sealed shares.
#' @param mask_output_key,y_output_key Character. Session slots to
#'   write decrypted Ring127 shares.
#' @param n_pp Integer. Total person-period rows = J * n_obs.
#' @param session_id Character.
#' @export
dsvertCoxDiscreteReceiveSharesDS <- function(mask_blob_key, y_blob_key,
                                              mask_output_key, y_output_key,
                                              n_pp, session_id) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  ss <- .S(session_id)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk))
    stop("transport_sk missing -- call glmRing63TransportInitDS first",
         call. = FALSE)
  m_blob <- .blob_consume(mask_blob_key, ss)
  if (is.null(m_blob))
    stop("mask blob missing at '", mask_blob_key, "'", call. = FALSE)
  dec_m <- .callMpcTool("transport-decrypt",
                         list(sealed = .base64url_to_base64(m_blob),
                              recipient_sk = tsk))
  ss[[mask_output_key]] <- rawToChar(jsonlite::base64_dec(dec_m$data))

  y_blob <- .blob_consume(y_blob_key, ss)
  if (is.null(y_blob))
    stop("y blob missing at '", y_blob_key, "'", call. = FALSE)
  dec_y <- .callMpcTool("transport-decrypt",
                         list(sealed = .base64url_to_base64(y_blob),
                              recipient_sk = tsk))
  ss[[y_output_key]] <- rawToChar(jsonlite::base64_dec(dec_y$data))

  list(stored = TRUE, n_pp = as.integer(n_pp),
       mask_output_key = mask_output_key,
       y_output_key = y_output_key)
}


#' @title Expand local covariates to uniform Jxn person-period frame
#' @description At each feature server, replicate each X_i row J times
#'   to form a uniform J*n x p person-period frame. No row-count signal
#'   leaks -- every patient contributes exactly J rows regardless of
#'   their true (hidden) ending bin J_i. Bin index per row is implicit
#'   in the row position: row idx (i-1)*J + j corresponds to (patient i,
#'   bin j). Bin-dummy alpha_j coefficients indexed by j are public; only
#'   J_i (per-patient hidden) is share-protected via the mask.
#' @param data_name Character. Local data frame name (NL side).
#' @param new_data_name Character. Name to assign expanded frame to.
#' @param x_vars Character vector of covariate column names.
#' @param J Integer. Number of bins.
#' @param session_id Character.
#' @return List(stored=TRUE, n_pp=<int>=J*n, p=<int>=length(x_vars))
#' @export
dsvertCoxDiscreteExpandXDS <- function(data_name, new_data_name,
                                        x_vars, J, session_id) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  J <- as.integer(J)
  if (!is.finite(J) || J < 2L) stop("J must be >= 2", call. = FALSE)
  missing_cols <- setdiff(x_vars, names(data))
  if (length(missing_cols) > 0L)
    stop("x_vars not found: ", paste(missing_cols, collapse=","),
         call. = FALSE)
  n <- nrow(data)

  # Uniform expansion: each row repeats J times, in row-major order
  # (patient 1 bins 1..J, patient 2 bins 1..J, ...).
  rep_idx <- rep(seq_len(n), each = J)
  expanded <- data[rep_idx, x_vars, drop = FALSE]
  expanded$bin <- rep(seq_len(J), times = n)
  expanded$patient_id <- sprintf("PP%05d_%03d",
                                  rep_idx,
                                  expanded$bin)
  # Add bin one-hot dummies (alpha_j coefficients indexed by j).
  for (j in seq_len(J)) {
    expanded[[paste0("bin", j)]] <- as.integer(expanded$bin == j)
  }
  assign(new_data_name, expanded, envir = parent.frame())
  list(stored = TRUE, n_pp = nrow(expanded), p = length(x_vars))
}
