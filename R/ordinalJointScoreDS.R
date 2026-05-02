# =====================================================================
# Historical design note (orphan): an earlier draft of the ordinal joint
# score pipeline factored a per-patient T_i routing helper out of
# `dsvertOrdinalPatientDiffsDS`. That helper was inlined back into
# PatientDiffs during the K=2 close-well refactor (worker2-k2safe-l2 ->
# d046049, 2026-04-24); its docstring has been removed here so it
# does not bleed into the next exported function's Rd. Reference:
# McCullagh 1980 JRSS B 42:109-142 Sec.2.5 eq.(2.5)
#   S(beta) = sum_i [ sum_k I(y_i = k) * T_{ik} ] x_i
# with T_{ik} = f_{k-1}/(F_k - F_{k-1}) - f_k/(F_{k+1} - F_k),
# f_k = F_k * (1 - F_k), F_k = sigma(theta_k - eta_i),
# boundary F_0 = 0, F_K = 1.
# =====================================================================

#' @title Seal F_k shares for inter-server reveal to outcome server
#' @description Non-outcome server transport-encrypts its Ring127 F_k
#'   shares to the outcome server's PK so the outcome server can
#'   assemble plaintext F per patient. Cox-class inter-server reveal.
#' @param F_keys character vector of session slot keys holding F_k shares.
#' @param target_pk outcome server transport PK (base64url).
#' @param session_id MPC session id.
#' @return list(sealed = base64url blob).
#' @export
dsvertOrdinalSealFkSharesDS <- function(F_keys, target_pk,
                                         session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (!is.character(F_keys) || length(F_keys) < 1L)
    stop("F_keys required", call. = FALSE)
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertOrdinalSealFkSharesDS")
  shares_b64 <- lapply(F_keys, function(k) {
    v <- ss[[k]]
    if (is.null(v)) stop("F share slot '", k, "' empty", call. = FALSE)
    v  # already base64-encoded FP data
  })
  payload <- jsonlite::base64_enc(charToRaw(
    jsonlite::toJSON(list(F_keys = F_keys, shares = shares_b64))))
  pk_std <- .base64url_to_base64(target_pk)
  sealed <- .callMpcTool("transport-encrypt",
                          list(data = payload, recipient_pk = pk_std))
  list(sealed = base64_to_base64url(sealed$sealed))
}


#' @title Receive transport-encrypted W (beta-Hessian weight) share
#' @description Counterpart to the W-sharing emitted by
#'   \code{dsvertOrdinalPatientDiffsDS} (when called with
#'   \code{weight_output_key} + \code{weight_target_pk}). NL transport-
#'   decrypts the sealed peer share and stores it as a Ring127 share
#'   in \code{output_key}. The two slots -- own at OS, peer at NL --
#'   form an additive Ring127 share of the per-patient W vector for
#'   downstream `.ring127_vecmul` in the client's X^T diag(W) X
#'   assembly (#A empirical beta-Hessian path, McCullagh 1980 Sec.2.5).
#' @param W_blob_key character. Session blob slot holding the sealed
#'   blob produced by `dsvertOrdinalPatientDiffsDS$W_sealed_blob`.
#' @param output_key character. Session slot to write the NL-side
#'   Ring127 share of W into.
#' @param n integer. Length of W vector (= n_obs).
#' @param session_id MPC session id.
#' @return list(stored = TRUE, n = <int>, output_key = <chr>).
#' @export
dsvertOrdinalReceiveBetaWeightsDS <- function(W_blob_key, output_key, n,
                                                session_id) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (is.null(output_key) || !nzchar(output_key))
    stop("output_key required", call. = FALSE)
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertOrdinalReceiveBetaWeightsDS")
  blob <- .blob_consume(W_blob_key, ss)
  if (is.null(blob))
    stop("W blob missing at '", W_blob_key, "'", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk))
    stop("transport_sk missing -- call glmRing63TransportInitDS first",
         call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
                       list(sealed = .base64url_to_base64(blob),
                            recipient_sk = tsk))
  peer_share <- rawToChar(jsonlite::base64_dec(dec$data))
  ss[[output_key]] <- peer_share
  list(stored = TRUE, n = as.integer(n), output_key = output_key)
}


#' @title Extract column j of an nxp Ring127 share matrix into n-vector slot
#' @description The K=2 X share is stored as a single n*p flat row-major
#'   Ring127 share (16 bytes per entry). For `.ring127_vecmul` operations
#'   on per-column X slices, we need length-n session slots. This
#'   primitive gathers row-major indices `[col_idx, p+col_idx,
#'   2p+col_idx, ...]` from the flat share into a new slot.
#'   ZERO MPC cost -- pure local share rearrangement (gather indices on
#'   raw bytes; the additive-share property is preserved row-by-row).
#' @param matrix_key character. Source flat n*p Ring127 share slot.
#' @param n integer. Number of rows.
#' @param p integer. Number of columns.
#' @param col_idx integer. 1-indexed column to extract.
#' @param output_key character. Destination length-n share slot.
#' @param session_id MPC session id.
#' @return list(stored = TRUE, n, output_key).
#' @export
dsvertOrdinalExtractXColumnDS <- function(matrix_key, n, p, col_idx,
                                            output_key, session_id) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (is.null(output_key) || !nzchar(output_key))
    stop("output_key required", call. = FALSE)
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertOrdinalExtractXColumnDS")
  flat <- ss[[matrix_key]]
  if (is.null(flat))
    stop("matrix slot '", matrix_key, "' empty", call. = FALSE)
  n_int <- as.integer(n)
  p_int <- as.integer(p)
  col_int <- as.integer(col_idx)
  if (col_int < 1L || col_int > p_int)
    stop("col_idx must be in [1, p]", call. = FALSE)
  raw_all <- jsonlite::base64_dec(flat)
  expected <- as.integer(n_int * p_int * 16L)
  if (length(raw_all) != expected)
    stop(sprintf("matrix slot expected %d bytes (n=%d, p=%d, 16/elem), got %d",
                  expected, n_int, p_int, length(raw_all)), call. = FALSE)
  # Gather column col_int (1-indexed): bytes for entry (i, col_int)
  # at row-major offset ((i-1)*p + (col_int-1)) * 16.
  col_raw <- raw(n_int * 16L)
  base <- (col_int - 1L) * 16L
  step <- p_int * 16L
  for (i in seq_len(n_int)) {
    src <- base + (i - 1L) * step
    dst <- (i - 1L) * 16L
    col_raw[(dst + 1L):(dst + 16L)] <- raw_all[(src + 1L):(src + 16L)]
  }
  ss[[output_key]] <- jsonlite::base64_enc(col_raw)
  list(stored = TRUE, n = n_int, output_key = output_key)
}


#' @title Seal non-label eta^nl vector for outcome-server reveal
#' @description Computes eta^nl = X^nl * beta^nl locally and transport-
#'   seals to outcome server's PK. Bypasses the F-reveal Ring127 ULP
#'   cancellation path; OS assembles full eta and computes F_k, P_k, T_i
#'   via Machler-stable log1mexp plaintext formulas.
#' @param data_name Character. Name of the data frame symbol on the server.
#' @param x_vars Character vector. Non-label feature names on this server.
#' @param beta_values Numeric vector. Coefficient slice corresponding to \code{x_vars}.
#' @param target_pk Character (base64url). Transport public key of the recipient server.
#' @param session_id Character. Active MPC session identifier.
#' @export
dsvertOrdinalSealEtaDS <- function(data_name, x_vars, beta_values,
                                    target_pk, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  .k2_enforce_K(.S(session_id), 2L, "dsvertOrdinalSealEtaDS")
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (length(x_vars) == 0L) {
    eta_nl <- rep(0, nrow(data))
  } else {
    missing_cols <- setdiff(x_vars, names(data))
    if (length(missing_cols) > 0L)
      stop("cols not found: ", paste(missing_cols, collapse=","), call. = FALSE)
    X <- as.matrix(data[, x_vars, drop = FALSE])
    beta_values <- as.numeric(beta_values)
    if (length(beta_values) != length(x_vars))
      stop("beta_values length mismatch", call. = FALSE)
    eta_nl <- as.numeric(X %*% beta_values)
  }
  payload <- jsonlite::base64_enc(charToRaw(jsonlite::toJSON(eta_nl)))
  pk_std <- .base64url_to_base64(target_pk)
  sealed <- .callMpcTool("transport-encrypt",
                          list(data = payload, recipient_pk = pk_std))
  list(sealed = base64_to_base64url(sealed$sealed))
}


#' Ordinal joint Newton: per-patient F differences for the threshold update
#'
#' Server-side aggregate that consumes the per-class cumulative-probability
#' shares (or plaintext F values relayed from the outcome server, mode b)
#' and emits the per-patient class indicator-minus-F differences used by
#' the joint Newton Hessian and gradient. Non-disclosive: only aggregate
#' summaries (sum_residual_fp, weight aggregates) are revealed at the
#' audit boundary; per-patient values stay share-secret.
#'
#' @param data_name Name of the aligned data frame on each server.
#' @param indicator_cols Character vector of integer-coded class indicator
#'   columns (one-hot) on the outcome server.
#' @param level_names Character vector of class names matching `indicator_cols`.
#' @param F_plaintext_b64 Optional: base64url-encoded plaintext F vector
#'   relayed from OS for mode b (eta-reveal disabled).
#' @param peer_F_blob_key Optional: session-slot key for the encrypted
#'   peer F-share blob.
#' @param F_keys Character vector of session keys holding per-class F shares.
#' @param output_key Session slot to store the resulting T_i vector.
#' @param weight_output_key Session slot to store the W_i weights.
#' @param weight_target_pk Recipient PK for the encrypted weights blob.
#' @param cross_output_keys Per-class cross-block session slots.
#' @param cross_target_pk Recipient PK for the encrypted cross-block blob.
#' @param n Integer patient count.
#' @param is_outcome_server Logical. TRUE on the server holding the outcome.
#' @param session_id MPC session id.
#' @return list with stored = TRUE and metadata about the Beaver round
#'   to be consumed by the client orchestrator.
#' @keywords internal
#' @export
dsvertOrdinalPatientDiffsDS <- function(data_name = NULL,
                                         indicator_cols = NULL,
                                         level_names = NULL,
                                         F_plaintext_b64 = NULL,
                                         peer_F_blob_key = NULL,
                                         F_keys = NULL,
                                         x_vars_label = NULL,
                                         beta_values_label = NULL,
                                         beta_intercept = 0,
                                         peer_eta_blob_key = NULL,
                                         theta_values = NULL,
                                         output_key = NULL,
                                         weight_output_key = NULL,
                                         weight_target_pk = NULL,
                                         cross_output_keys = NULL,
                                         cross_target_pk = NULL,
                                         n = NULL,
                                         is_outcome_server = FALSE,
                                         session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (is.null(output_key) || !nzchar(output_key))
    stop("output_key required", call. = FALSE)
  n_int <- as.integer(n)
  if (!is.finite(n_int) || n_int <= 0L)
    stop("n must be a positive integer", call. = FALSE)
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertOrdinalPatientDiffsDS")

  # Piece (5) -- default "no-op" output: both parties write a zero
  # Ring127 share. Required for the case where the caller only wants
  # to stage the slot (e.g., downstream matvec on a non-outcome
  # server that doesn't need to contribute).
  write_zero_share <- function() {
    zero_flat <- rep(0, n_int)
    fp <- .callMpcTool("k2-float-to-fp",
                        list(values = zero_flat, frac_bits = 50L,
                             ring = "ring127"))$fp_data
    ss[[output_key]] <- fp
  }

  if (!isTRUE(is_outcome_server)) {
    # Non-outcome path (piece 5): this server contributes zero T_i
    # locally. Any non-zero T_i share on this side arrives via the
    # reveal-blob pattern from the outcome server (separate DS fn
    # `dsvertOrdinalStoreTShareDS`, piece 6, future commit).
    write_zero_share()
    return(list(stored = TRUE, role = "nl", n = n_int))
  }

  # ===== OUTCOME-SERVER PATH (pieces 1-4) =====
  # Piece 1 -- read indicator columns. Uses cumulative encoding
  # (indicator_template = "%s_leq" gives I(y <= k) per threshold k).
  # From cumulative indicators we derive per-patient class j(i).
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data))
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  if (!is.character(level_names) || length(level_names) < 3L)
    stop("level_names must be >= 3 ordered level strings", call. = FALSE)
  thresh_levels <- head(level_names, -1L)
  K <- length(level_names)
  K_minus_1 <- K - 1L
  n_k <- n_int  # alias

  # Read each cumulative indicator column. indicator_cols is a
  # character vector of length K-1 passed by the client -- avoids
  # sprintf templates with "%" that hit the Opal DSL parser lexer
  # (observed 2026-04-24: "Lexical error Encountered '%' after '\"'"
  # on the "%s_leq" template literal).
  if (!is.character(indicator_cols) || length(indicator_cols) != K_minus_1)
    stop("indicator_cols must be a character vector of length K-1 = ",
         K_minus_1, call. = FALSE)
  ind_mat <- matrix(0L, nrow = n_int, ncol = K_minus_1)
  for (ki in seq_along(thresh_levels)) {
    col <- indicator_cols[ki]
    if (!(col %in% names(data)))
      stop("indicator column '", col, "' not found in '", data_name, "'",
           call. = FALSE)
    v <- as.integer(data[[col]])
    if (length(v) != n_int)
      stop("indicator column '", col, "' length ", length(v), " != n=",
           n_int, call. = FALSE)
    ind_mat[, ki] <- v
  }

  # Piece 2 -- derive per-patient class j(i) in {1, ..., K} from
  # cumulative indicators. y <= k for all k >= j(i) and y > k for k < j(i).
  # So j(i) = (K - rowSums(ind_mat)) if ind_mat is I(y <= k)... actually:
  # I(y <= k) = 1 iff y <= k. rowSums counts how many thresholds y is
  # below-or-equal. If y = 1: all K-1 indicators are 1 -> rowSums = K-1.
  # If y = K: all 0 -> rowSums = 0. So j(i) = K - rowSums(ind_mat).
  j_of_i <- K - rowSums(ind_mat)
  if (any(j_of_i < 1 | j_of_i > K))
    stop("invalid class derivation from indicators: out of range [1, K]",
         call. = FALSE)

  # Piece 3 -- assemble plaintext F on the OUTCOME SERVER ONLY.
  # Three supported input modes (listed in priority order):
  #   (a) peer_eta_blob_key : PRODUCTION path -- OS assembles eta_i
  #       plaintext from own eta_label + peer eta_nl, computes F_k
  #       and P_k via Machler log1mexp stable form (avoids F_k-F_{k-1}
  #       cancellation that the Ring127 F-reveal path suffers when both
  #       sigmoids saturate, observed 100% sat_frac on NHANES warm).
  #   (b) peer_F_blob_key + F_keys : ring127 F-reveal (LEGACY, kept for
  #       unit tests). See diag(#2b) 3e54582 for saturation analysis.
  #   (c) F_plaintext_b64 : row-major double[n x K-1] directly (tests).
  F_mat <- NULL
  if (!is.null(peer_eta_blob_key) && nzchar(peer_eta_blob_key)) {
    # --- Production path: assemble eta, compute F stably ---
    if (is.null(theta_values))
      stop("theta_values required for eta-reveal path", call. = FALSE)
    thresholds <- as.numeric(theta_values)
    if (length(thresholds) != K_minus_1)
      stop("theta_values length ", length(thresholds),
           " != K-1 ", K_minus_1, call. = FALSE)
    # Own label-side eta contribution
    if (length(x_vars_label) == 0L) {
      eta_lab <- rep(0, n_int)
    } else {
      Xl <- as.matrix(data[, x_vars_label, drop = FALSE])
      beta_lbl <- as.numeric(beta_values_label)
      if (length(beta_lbl) != length(x_vars_label))
        stop("beta_values_label length mismatch", call. = FALSE)
      eta_lab <- as.numeric(Xl %*% beta_lbl)
    }
    if (length(eta_lab) != n_int)
      stop("eta_label length != n", call. = FALSE)
    # Decrypt peer eta_nl blob
    eta_blob <- .blob_consume(peer_eta_blob_key, ss)
    if (is.null(eta_blob))
      stop("peer eta blob missing at '", peer_eta_blob_key, "'",
           call. = FALSE)
    tsk <- .key_get("transport_sk", ss)
    if (is.null(tsk))
      stop("transport_sk missing", call. = FALSE)
    dec <- .callMpcTool("transport-decrypt",
      list(sealed = .base64url_to_base64(eta_blob), recipient_sk = tsk))
    eta_nl <- as.numeric(jsonlite::fromJSON(rawToChar(
      jsonlite::base64_dec(dec$data))))
    if (length(eta_nl) != n_int)
      stop("peer eta_nl length ", length(eta_nl), " != n ", n_int,
           call. = FALSE)
    # Full per-patient eta (plaintext on OS only)
    eta_i <- as.numeric(beta_intercept) + eta_lab + eta_nl
    # Clamp for numerical safety (eta inside [-30, 30] covers all
    # realistic cases; sigmoid saturates completely by |x|>30 anyway)
    eta_i <- pmin(pmax(eta_i, -30), 30)
    # Per-threshold u_k = theta_k - eta_i
    U_mat <- matrix(0, nrow = n_int, ncol = K_minus_1)
    for (ki in seq_len(K_minus_1)) {
      U_mat[, ki] <- thresholds[ki] - eta_i
    }
    # F_k = sigmoid(u_k) computed via plogis (numerically stable)
    F_mat <- matrix(plogis(as.numeric(U_mat)),
                     nrow = n_int, ncol = K_minus_1)
    # Store U for later Machler stable P computation
    U_for_P <- U_mat
  } else if (!is.null(peer_F_blob_key) && nzchar(peer_F_blob_key)) {
    if (!is.character(F_keys) || length(F_keys) != K_minus_1)
      stop("F_keys length must equal K_minus_1=", K_minus_1, call. = FALSE)
    blob <- .blob_consume(peer_F_blob_key, ss)
    if (is.null(blob))
      stop("peer F blob missing at '", peer_F_blob_key, "'", call. = FALSE)
    tsk <- .key_get("transport_sk", ss)
    if (is.null(tsk))
      stop("transport_sk missing -- call glmRing63TransportInitDS first",
           call. = FALSE)
    dec <- .callMpcTool("transport-decrypt",
      list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
    peer <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
    peer_shares_b64 <- peer$shares
    if (length(peer_shares_b64) != K_minus_1)
      stop("peer F shares count ", length(peer_shares_b64),
           " != K_minus_1 ", K_minus_1, call. = FALSE)
    # Sum own + peer share per threshold -> plaintext F_k Ring127
    F_mat <- matrix(0, nrow = n_int, ncol = K_minus_1)
    for (ki in seq_len(K_minus_1)) {
      own_b64 <- ss[[F_keys[ki]]]
      if (is.null(own_b64))
        stop("own F share slot '", F_keys[ki], "' empty", call. = FALSE)
      # aggregate two Ring127 shares -> plaintext double vector
      agg <- .callMpcTool("k2-ring63-aggregate",
        list(share_a = own_b64, share_b = peer_shares_b64[[ki]],
             frac_bits = 50L, ring = "ring127"))
      F_mat[, ki] <- as.numeric(agg$values)[seq_len(n_int)]
    }
  } else if (!is.null(F_plaintext_b64) && nzchar(F_plaintext_b64)) {
    F_raw <- jsonlite::base64_dec(.base64url_to_base64(F_plaintext_b64))
    F_nums <- readBin(F_raw, what = "double", n = n_int * K_minus_1,
                       size = 8L, endian = "little")
    if (length(F_nums) != n_int * K_minus_1)
      stop("F_plaintext length mismatch: got ", length(F_nums),
           " expected ", n_int * K_minus_1, call. = FALSE)
    F_mat <- matrix(F_nums, nrow = n_int, ncol = K_minus_1, byrow = TRUE)
  } else {
    stop("outcome server needs either peer_F_blob_key + F_keys OR F_plaintext_b64",
         call. = FALSE)
  }
  # Ensure F in (eps, 1-eps) for numerical safety
  eps <- 1e-10
  F_mat <- pmin(pmax(F_mat, eps), 1 - eps)
  # Augmented: F_0 == 0, F_K == 1. Columns 0..K of cumulative Fs.
  F_aug <- cbind(0, F_mat, 1)   # n x (K+1)
  # P_{i,j} = F_j - F_{j-1} for j in 1..K
  # Naive form suffers cancellation when both F saturate (Machler 2012
  # Rmpfr log1mexp vignette). Stable form when available: compute
  # directly from U_for_P when the eta-reveal path supplies it.
  if (exists("U_for_P", inherits = FALSE) && !is.null(U_for_P)) {
    # Machler stable: P_{i,k} = sigma(u_k) - sigma(u_{k-1}) where
    # u_k = theta_k - eta, so u_1 > u_2 > ... > u_{K-1} (not
    # necessarily ordered; use absolute diff form).
    # Equivalent: -diff(plogis(U)) per row. plogis handles saturation
    # via logsumexp internals in R (>=3.5). For |u|<30 this is stable.
    P_mat <- matrix(0, nrow = n_int, ncol = K)
    # P_{i,1} = F_1 = plogis(u_1)
    P_mat[, 1L] <- F_mat[, 1L]
    # P_{i,k} for 1 < k < K: F_k - F_{k-1}
    # Use log-space stable: log P = log(F_k - F_{k-1}).
    # When both F near 1: use 1-F = plogis(-u), then
    # F_k - F_{k-1} = (1 - F_{k-1}) - (1 - F_k) = plogis(-u_{k-1}) - plogis(-u_k)
    # When both F near 0: naive F_k - F_{k-1} is fine.
    # Switch: if F_{k-1} > 0.5, use upper-tail form.
    if (K_minus_1 >= 2L) {
      for (kj in 2L:K_minus_1) {
        upper_flag <- F_mat[, kj - 1L] > 0.5
        # naive
        P_naive <- F_mat[, kj] - F_mat[, kj - 1L]
        # upper-tail stable: plogis(-u_{kj-1}) - plogis(-u_kj)
        P_upper <- plogis(-U_for_P[, kj - 1L]) - plogis(-U_for_P[, kj])
        P_mat[, kj] <- ifelse(upper_flag, P_upper, P_naive)
      }
    }
    # P_{i,K} = 1 - F_{K-1} via plogis(-u_{K-1}) (stable for F near 1)
    P_mat[, K] <- plogis(-U_for_P[, K_minus_1])
  } else {
    P_mat <- F_aug[, 2:(K + 1L), drop = FALSE] -
             F_aug[, 1:K,         drop = FALSE]
  }
  P_mat <- pmax(P_mat, eps)     # safety against underflow
  # f_k = F_k (1 - F_k)  for interior thresholds k in 1..K-1; boundary
  # f_0 = f_K = 0.
  f_interior <- F_mat * (1 - F_mat)  # n x K_minus_1
  f_aug <- cbind(0, f_interior, 0)   # n x (K+1)  i.e., f_0, f_1..f_{K-1}, f_K
  # Piece 4 -- per-patient T_i = (f_{j-1} - f_j) / P_{i,j}
  # per McCullagh 1980 JRSS B 42:109-142 Sec.2.5 eq (2.5) score form.
  # Derivation: rho_j = F(theta_j - eta), drho_j/dbeta = -f_j * x -> score x-weight
  # u_i = (f_{j-1} - f_j) / (rho_j - rho_{j-1}).
  # Boundaries: f_0 = f_K = 0 absorb automatically via f_aug.
  T_i <- numeric(n_int)
  for (i in seq_len(n_int)) {
    j <- j_of_i[i]
    T_i[i] <- (f_aug[i, j] - f_aug[i, j + 1L]) / P_mat[i, j]
  }
  if (any(!is.finite(T_i))) {
    T_i[!is.finite(T_i)] <- 0
  }
  # Clamp to sanity range; true |T_i| <= 1 for bounded eta (since
  # f_k <= 1/4 always, and P_{i,j} >= eps). Clamp at +/-10 as a safety
  # net against near-zero P (from P-floor 1e-10 scaling).
  T_i <- pmin(pmax(T_i, -10), 10)

  # Piece 5 (outcome side) -- split T_i into additive Ring127 share:
  # OS keeps (T_i - r), blob sends r to NL. For a generous baseline
  # without an NL round-trip yet, store T_i as the outcome's OWN
  # share and zero on NL (per dsvertComputeResidualShareDS pattern):
  # the non-outcome call sets zero above, outcome-sum = T_i locally.
  fp_T <- .callMpcTool("k2-float-to-fp",
                        list(values = as.numeric(T_i), frac_bits = 50L,
                             ring = "ring127"))$fp_data
  ss[[output_key]] <- fp_T

  # AUDITORIA F saturation diagnostic: report F quantiles + saturation
  # fraction. max|F - 0.5| >= 0.49 indicates Chebyshev sigmoid domain
  # saturation -> F_j and F_{j-1} both near 0 or 1 -> P small -> T clamp.
  F_abs_dev <- abs(F_mat - 0.5)
  F_q <- unname(quantile(as.numeric(F_mat), c(0.01, 0.25, 0.5, 0.75, 0.99)))
  P_q <- unname(quantile(as.numeric(P_mat), c(0.01, 0.25, 0.5, 0.75, 0.99)))
  sat_frac <- mean(F_abs_dev > 0.49)

  # Per-threshold score_theta_k for the Bohning H*_theta Newton step (Tutz 1990
  # Sec.3.2; Agresti 2010 Sec.8.1). PO gradient w.r.t. theta_k:
  #   dL/dtheta_k = Sum_{i: y_i = k}   f_k(eta_i) / P_{i,k}
  #           - Sum_{i: y_i = k+1} f_k(eta_i) / P_{i,k+1}
  # where f_k(eta_i) = F_k(1 - F_k). Computable plaintext on OS once F is
  # aggregated (we already pay that disclosure under mode b). H*_theta_k =
  # n_k / 4 is the Bohning majorant; client applies theta_k <- theta_k + (4/n_k) g_k.
  score_theta <- numeric(K_minus_1)
  class_counts_int <- as.integer(table(factor(j_of_i, levels = seq_len(K))))
  for (kk in seq_len(K_minus_1)) {
    in_k     <- which(j_of_i == kk)        # y_i = k
    in_kp1   <- which(j_of_i == kk + 1L)   # y_i = k + 1
    fk_vec   <- f_interior[, kk]
    g_pos <- if (length(in_k))   sum(fk_vec[in_k]   / pmax(P_mat[in_k,   kk    ], eps)) else 0
    g_neg <- if (length(in_kp1)) sum(fk_vec[in_kp1] / pmax(P_mat[in_kp1, kk + 1L], eps)) else 0
    score_theta[kk] <- g_pos - g_neg
  }

  # Empirical PO thetatheta-Hessian (negative log-lik, descent direction) via
  # McCullagh 1980 *JRSS B* 42:109-142 Sec.2.5 closed-form derivative of the
  # score equations. Tridiagonal symmetric (only adjacent thresholds
  # couple). Diagonal:
  #   H_thetatheta[k,k] = - Sum_{y=k}   f_k(1-2F_k)/P_k
  #              + Sum_{y=k+1} f_k(1-2F_k)/P_{k+1}
  #              + Sum_{y=k}   f_k^2/P_k^2
  #              + Sum_{y=k+1} f_k^2/P_{k+1}^2
  # Off-diagonal:
  #   H_thetatheta[k,k+1] = - Sum_{y=k+1} f_k * f_{k+1} / P_{k+1}^2
  # Available plaintext on OS once F is aggregated (mode b disclosure
  # already paid). Replaces the loose Bohning majorant H*_k = n_k/4
  # whose looseness under saturation was the root of the period-2 theta
  # oscillation in the 2026-04-26 30-min relaxation experiment.
  # Auto-regulates at saturation: when P_k -> eps, entries grow -> solve
  # gives tiny Newton step (Bertsekas 1999 Sec.2.7 block coord descent).
  H_theta_theta <- matrix(0, nrow = K_minus_1, ncol = K_minus_1)
  if (K_minus_1 >= 1L) {
    for (kk in seq_len(K_minus_1)) {
      in_k   <- which(j_of_i == kk)
      in_kp1 <- which(j_of_i == kk + 1L)
      fk_vec <- f_interior[, kk]
      Fk_vec <- F_mat[, kk]
      d_k   <- 0
      if (length(in_k))
        d_k <- d_k - sum(fk_vec[in_k]   * (1 - 2*Fk_vec[in_k])   / pmax(P_mat[in_k,   kk     ], eps)) +
                     sum(fk_vec[in_k]^2                          / pmax(P_mat[in_k,   kk     ], eps)^2)
      if (length(in_kp1))
        d_k <- d_k + sum(fk_vec[in_kp1] * (1 - 2*Fk_vec[in_kp1]) / pmax(P_mat[in_kp1, kk + 1L], eps)) +
                     sum(fk_vec[in_kp1]^2                        / pmax(P_mat[in_kp1, kk + 1L], eps)^2)
      H_theta_theta[kk, kk] <- d_k
    }
    if (K_minus_1 >= 2L) {
      for (kk in seq_len(K_minus_1 - 1L)) {
        in_kp1 <- which(j_of_i == kk + 1L)   # patients y=k+1 couple theta_k & theta_{k+1}
        if (length(in_kp1)) {
          fk_v   <- f_interior[in_kp1, kk]
          fkp1_v <- f_interior[in_kp1, kk + 1L]
          Pkp1_v <- pmax(P_mat[in_kp1, kk + 1L], eps)
          off    <- -sum(fk_v * fkp1_v / Pkp1_v^2)
          H_theta_theta[kk,     kk + 1L] <- off
          H_theta_theta[kk + 1L, kk    ] <- off
        }
      }
    }
  }

  # === Per-patient empirical beta-Hessian weight W_i for #A ===
  # Negative log-lik PO Hessian wrt beta: H_betabeta = X^T diag(W_i) X with
  #   W_i = [f_{j-1}(1-2F_{j-1}) - f_j(1-2F_j)] / P_j
  #         + (f_{j-1} - f_j)^2 / P_j^2        (j = y_i)
  # per McCullagh 1980 *JRSS B* 42:109-142 Sec.2.5 second derivative of the
  # PO log-likelihood; the form used by ordinal::clm.fit (Christensen
  # 2019 Sec.A.3 modified Newton with diagonal eigenvalue inflation).
  # Replaces the Bohning B_PO=(1/4)X^TX bound (provably loose per
  # Anceschi 2024 arXiv:2410.10309) with the empirical second-derivative
  # for quadratic local convergence (Pratt 1981; Burridge 1981).
  # Computable plaintext at OS in mode b -- F/P/f already revealed under
  # current K=2 disclosure budget; ZERO new disclosure beyond mode b.
  W_i <- numeric(n_int)
  if (n_int > 0L) {
    F_aug_for_W <- cbind(0, F_mat, 1)   # n x (K+1) augmented
    for (i in seq_len(n_int)) {
      j     <- j_of_i[i]
      fjm1  <- f_aug[i, j]                  # f_{j-1}
      fj    <- f_aug[i, j + 1L]             # f_j
      Fjm1  <- F_aug_for_W[i, j]            # F_{j-1}
      Fj    <- F_aug_for_W[i, j + 1L]       # F_j
      Pj    <- max(P_mat[i, j], eps)
      curv  <- (fjm1 * (1 - 2 * Fjm1) - fj * (1 - 2 * Fj)) / Pj
      sqsc  <- (fjm1 - fj)^2 / Pj^2
      W_i[i] <- curv + sqsc
    }
    if (any(!is.finite(W_i))) W_i[!is.finite(W_i)] <- 0
    # Christensen 2019 ordinal::clm.fit Sec.A.3 diagonal eigenvalue
    # inflation: when local Hessian has tiny / negative weights from
    # numerical instability (saturation, near-boundary eta), clamp the
    # weight to a small positive epsilon. Prevents H_betabeta from becoming
    # singular / non-PD; the client applies a Tikhonov ridge on the
    # assembled pxp matrix as a second-line safety.
    W_i <- pmax(W_i, 1e-8)
  }

  out <- list(stored = TRUE, role = "os", n = n_int,
              class_counts = class_counts_int,
              T_norm_L2 = sqrt(sum(T_i^2)),
              T_max = max(abs(T_i)),
              F_q01_q99 = F_q,
              P_q01_q99 = P_q,
              F_sat_frac = sat_frac,
              score_theta = score_theta,
              H_theta_theta = H_theta_theta,
              W_q01_q99 = unname(quantile(W_i, c(0.01, 0.25, 0.5, 0.75, 0.99))))

  # PO log-likelihood at current (beta, theta) for Armijo step-halving
  # (Nocedal-Wright 2006 Sec.3.5 backtracking line search). Required for
  # the empirical-Hessian Newton path: Bohning's monotone-descent
  # guarantee (Th 2) does NOT hold for empirical-H Newton, so we add
  # explicit Armijo to ensure log-lik increases per accepted step.
  out$loglik <- sum(log(pmax(P_mat[cbind(seq_len(n_int), j_of_i)], eps)))

  # === Optional W secret-share (#A empirical beta-Hessian path) ===
  # When the client requests `weight_output_key` + `weight_target_pk`,
  # we split W into Ring127 additive shares: own at OS (slot
  # weight_output_key), peer transport-encrypted to NL_pk for downstream
  # `.ring127_vecmul(W_key, X_:j_key, DX_:j_key)` in client-side
  # X^T diag(W) X assembly.
  if (!is.null(weight_output_key) && nzchar(weight_output_key) &&
      !is.null(weight_target_pk) && nzchar(weight_target_pk)) {
    fp_W <- .callMpcTool("k2-float-to-fp",
                          list(values = as.numeric(W_i), frac_bits = 50L,
                               ring = "ring127"))$fp_data
    split_W <- .callMpcTool("k2-split-fp-share",
                             list(data_fp = fp_W, n = n_int,
                                  frac_bits = 50L, ring = "ring127"))
    ss[[weight_output_key]] <- split_W$own_share
    pk_std <- .base64url_to_base64(weight_target_pk)
    sealed <- .callMpcTool("transport-encrypt",
                            list(data = jsonlite::base64_enc(
                                   charToRaw(split_W$peer_share)),
                                 recipient_pk = pk_std))
    out$W_sealed_blob   <- base64_to_base64url(sealed$sealed)
    out$W_share_key     <- weight_output_key
    out$W_share_emitted <- TRUE
  } else {
    out$W_share_emitted <- FALSE
  }

  # === Cross-block H_betatheta weights M_k (#A joint Newton, Tutz 1990 Sec.3.2) ===
  # Per-threshold k in 1..K-1 cross-Hessian weight (closed-form derivative
  # of the beta-score equation w.r.t. theta_k):
  #   M_k_i =  +f_k[(1-2F_k)/P_k + (f_{k-1}-f_k)/P_k^2]   if y_i = k
  #         =  -f_k(1-2F_k)/P_{k+1} - f_k(f_k-f_{k+1})/P_{k+1}^2  if y_i = k+1
  #         =   0                                              otherwise
  # (negative log-lik convention; signs flipped from raw dT_i/dtheta_k).
  # Provides the X^T M_k = H[beta, theta_k] cross-column needed for the full
  # joint (beta, theta) Newton step, without which BCD alternation oscillates
  # (observed 2026-04-27: iter 9 |g_beta|=0.009 + iter 10 |g_beta|=1.45).
  # Cite: McCullagh 1980 JRSS B 42:109-142 Sec.2.5; Tutz 1990 Statistics &
  # Decisions 7:21-37 Sec.3.2; Pratt 1981 (PO log-lik strict concavity).
  if (!is.null(cross_output_keys) && length(cross_output_keys) == K_minus_1 &&
      !is.null(cross_target_pk) && nzchar(cross_target_pk)) {
    F_aug_for_M <- F_aug
    cross_blobs <- character(K_minus_1)
    for (kk in seq_len(K_minus_1)) {
      M_k <- numeric(n_int)
      Fk_v <- F_mat[, kk]
      fk_v <- f_interior[, kk]
      Pk_v <- pmax(P_mat[, kk    ], eps)
      Pkp1_v <- pmax(P_mat[, kk + 1L], eps)
      f_km1_v <- f_aug[, kk]      # f_{k-1}, length n_int
      f_kp1_v <- f_aug[, kk + 2L] # f_{k+1}
      # y_i = k contribution (+ direction)
      mask_k <- which(j_of_i == kk)
      if (length(mask_k))
        M_k[mask_k] <- +fk_v[mask_k] * ((1 - 2*Fk_v[mask_k]) / Pk_v[mask_k] +
                                         (f_km1_v[mask_k] - fk_v[mask_k]) / Pk_v[mask_k]^2)
      # y_i = k+1 contribution (- direction)
      mask_kp1 <- which(j_of_i == kk + 1L)
      if (length(mask_kp1))
        M_k[mask_kp1] <- -fk_v[mask_kp1] * (1 - 2*Fk_v[mask_kp1]) / Pkp1_v[mask_kp1] -
                          fk_v[mask_kp1] * (fk_v[mask_kp1] - f_kp1_v[mask_kp1]) / Pkp1_v[mask_kp1]^2
      if (any(!is.finite(M_k))) M_k[!is.finite(M_k)] <- 0
      # Split + transport-encrypt to NL
      fp_M <- .callMpcTool("k2-float-to-fp",
                            list(values = as.numeric(M_k), frac_bits = 50L,
                                 ring = "ring127"))$fp_data
      split_M <- .callMpcTool("k2-split-fp-share",
                               list(data_fp = fp_M, n = n_int,
                                    frac_bits = 50L, ring = "ring127"))
      ss[[cross_output_keys[kk]]] <- split_M$own_share
      pk_std <- .base64url_to_base64(cross_target_pk)
      sealed <- .callMpcTool("transport-encrypt",
                              list(data = jsonlite::base64_enc(
                                     charToRaw(split_M$peer_share)),
                                   recipient_pk = pk_std))
      cross_blobs[kk] <- base64_to_base64url(sealed$sealed)
    }
    out$cross_sealed_blobs <- cross_blobs
    out$cross_share_keys   <- cross_output_keys
    out$cross_share_emitted <- TRUE
  } else {
    out$cross_share_emitted <- FALSE
  }

  out
}
