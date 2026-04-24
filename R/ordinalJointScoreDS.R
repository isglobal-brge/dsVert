#' @title Ordinal PO per-patient score-element routing (stub skeleton)
#' @description Outcome server reads patient-level indicator columns
#'   (\code{indicator_template \%\% class_name}), routes per-class
#'   share contributions based on which ordinal class each patient
#'   belongs to, and writes a share of the aggregate per-patient
#'   score term T_i to \code{output_key} for downstream Beaver matvec
#'   \eqn{X^\top T}.
#'
#' @details
#'   Proportional-odds joint score per McCullagh 1980 *JRSS B* 42:109-142
#'   §2.5 equation (2.5):
#'     \deqn{S(\beta) = \sum_i \left[ \sum_k I(y_i = k) \cdot T_{ik} \right] x_i}
#'   with
#'     \deqn{T_{ik} = \frac{f_{k-1}(\eta_i)}{F_k - F_{k-1}} -
#'           \frac{f_k(\eta_i)}{F_{k+1} - F_k}}
#'   where \eqn{f_k = F_k (1 - F_k)} and \eqn{F_k = \sigma(\theta_k -
#'   \eta_i)}, by convention \eqn{F_0 \equiv 0} and \eqn{F_K \equiv 1}.
#'
#' @section Implementation status (2026-04-24, AUDITORIA piece-by-piece):
#'   STUB — interface shipped, no-op body. Current code stores a zero
#'   share in \code{output_key} so the downstream orchestration (Beaver
#'   matvec) returns a trivial zero gradient. The client-side Newton in
#'   \code{ds.vertOrdinalJointNewton} continues to use its warm-Fisher
#'   fallback until the full body is wired.
#'
#'   Remaining piece-by-piece scope (each commit = one piece):
#'   \enumerate{
#'     \item Read indicator columns for each class from local data frame.
#'     \item For each patient, determine which class k they belong to.
#'     \item Compute \eqn{T_{ik}} share using session slots
#'       \code{f_keys}, \code{recipP_keys}. (\eqn{T_{i0}} and \eqn{T_{iK}}
#'       get boundary conventions.)
#'     \item Affine-combine class-specific shares into per-patient
#'       T_i share via indicator-masking (outcome server holds
#'       indicators in plaintext locally).
#'     \item Store T_i share in \code{output_key} session slot.
#'     \item Client-side: invoke existing
#'       \code{glmRing63GenGradTriplesDS} + \code{k2GradientR[12]DS}
#'       pipeline on \code{output_key} for the final X^T T matvec.
#'   }
#'
#'   All the MPC primitives needed (k2Ring127AffineCombineDS,
#'   k2Ring127LocalScaleDS, k2BeaverVecmul*) already exist. Scope is
#'   routing + indicator logic, not new cryptographic machinery.
#'
#' @param data_name Character. Local data frame name on outcome server.
#' @param indicator_template sprintf template for indicator column
#'   names (e.g., "\%s_leq" for cumulative indicators).
#' @param f_keys Character vector. Session slot keys holding share
#'   of \eqn{f_k = F_k (1 - F_k)} per patient, one per non-reference
#'   threshold.
#' @param recipP_keys Character vector. Session slot keys holding share
#'   of \eqn{1/(F_k - F_{k-1})} per patient (one per interior class).
#' @param output_key Character. Session slot to write per-patient
#'   T_i share.
#' @param n Integer. Number of patients.
#' @param is_outcome_server Logical. If FALSE, server contributes zero
#'   (only the outcome server holds indicators).
#' @param session_id MPC session id.
#' @return \code{list(stored = TRUE, stub = TRUE, n = <integer>)}.
#' @export
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


dsvertOrdinalPatientDiffsDS <- function(data_name = NULL,
                                         indicator_cols = NULL,
                                         level_names = NULL,
                                         F_plaintext_b64 = NULL,
                                         peer_F_blob_key = NULL,
                                         F_keys = NULL,
                                         theta_values = NULL,
                                         output_key = NULL,
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

  # Piece (5) — default "no-op" output: both parties write a zero
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
  # Piece 1 — read indicator columns. Uses cumulative encoding
  # (indicator_template = "%s_leq" gives I(y ≤ k) per threshold k).
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
  # character vector of length K-1 passed by the client — avoids
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

  # Piece 2 — derive per-patient class j(i) in {1, ..., K} from
  # cumulative indicators. y ≤ k for all k ≥ j(i) and y > k for k < j(i).
  # So j(i) = (K - rowSums(ind_mat)) if ind_mat is I(y ≤ k)... actually:
  # I(y ≤ k) = 1 iff y ≤ k. rowSums counts how many thresholds y is
  # below-or-equal. If y = 1: all K-1 indicators are 1 → rowSums = K-1.
  # If y = K: all 0 → rowSums = 0. So j(i) = K - rowSums(ind_mat).
  j_of_i <- K - rowSums(ind_mat)
  if (any(j_of_i < 1 | j_of_i > K))
    stop("invalid class derivation from indicators: out of range [1, K]",
         call. = FALSE)

  # Piece 3 — assemble plaintext F on the OUTCOME SERVER ONLY.
  # Two supported input modes:
  #   (a) F_plaintext_b64 : row-major double[n × K-1] directly (used
  #       for unit tests / simple paths)
  #   (b) peer_F_blob_key + F_keys : production MPC path. Outcome
  #       decrypts peer shares (sealed via dsvertOrdinalSealFkSharesDS),
  #       adds its own session-slot shares, decodes Ring127 → double.
  #       Plaintext F never leaves OS; client sees only scalar T stats.
  F_mat <- NULL
  if (!is.null(peer_F_blob_key) && nzchar(peer_F_blob_key)) {
    if (!is.character(F_keys) || length(F_keys) != K_minus_1)
      stop("F_keys length must equal K_minus_1=", K_minus_1, call. = FALSE)
    blob <- .blob_consume(peer_F_blob_key, ss)
    if (is.null(blob))
      stop("peer F blob missing at '", peer_F_blob_key, "'", call. = FALSE)
    tsk <- .key_get("transport_sk", ss)
    if (is.null(tsk))
      stop("transport_sk missing — call glmRing63TransportInitDS first",
           call. = FALSE)
    dec <- .callMpcTool("transport-decrypt",
      list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
    peer <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
    peer_shares_b64 <- peer$shares
    if (length(peer_shares_b64) != K_minus_1)
      stop("peer F shares count ", length(peer_shares_b64),
           " != K_minus_1 ", K_minus_1, call. = FALSE)
    # Sum own + peer share per threshold → plaintext F_k Ring127
    F_mat <- matrix(0, nrow = n_int, ncol = K_minus_1)
    for (ki in seq_len(K_minus_1)) {
      own_b64 <- ss[[F_keys[ki]]]
      if (is.null(own_b64))
        stop("own F share slot '", F_keys[ki], "' empty", call. = FALSE)
      # aggregate two Ring127 shares → plaintext double vector
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
  # Augmented: F_0 ≡ 0, F_K ≡ 1. Columns 0..K of cumulative Fs.
  F_aug <- cbind(0, F_mat, 1)   # n × (K+1)
  # P_{i,j} = F_j - F_{j-1} for j ∈ 1..K
  P_mat <- F_aug[, 2:(K + 1L), drop = FALSE] -
           F_aug[, 1:K,         drop = FALSE]
  P_mat <- pmax(P_mat, eps)     # safety against underflow
  # f_k = F_k (1 - F_k)  for interior thresholds k ∈ 1..K-1; boundary
  # f_0 = f_K = 0.
  f_interior <- F_mat * (1 - F_mat)  # n × K_minus_1
  f_aug <- cbind(0, f_interior, 0)   # n × (K+1)  i.e., f_0, f_1..f_{K-1}, f_K
  # Piece 4 — per-patient T_i = f_{j-1}/P_j − f_j/P_{j+1}
  # (with f_0 = f_K = 0 absorbing the boundaries)
  T_i <- numeric(n_int)
  for (i in seq_len(n_int)) {
    j <- j_of_i[i]
    num_lower <- f_aug[i, j] / P_mat[i, j]           # f_{j-1} / P_{i,j}
    num_upper <- if (j < K) f_aug[i, j + 1L] / P_mat[i, j + 1L] else 0
    T_i[i] <- num_lower - num_upper
  }
  if (any(!is.finite(T_i))) {
    T_i[!is.finite(T_i)] <- 0
  }

  # Piece 5 (outcome side) — split T_i into additive Ring127 share:
  # OS keeps (T_i − r), blob sends r to NL. For a generous baseline
  # without an NL round-trip yet, store T_i as the outcome's OWN
  # share and zero on NL (per dsvertComputeResidualShareDS pattern):
  # the non-outcome call sets zero above, outcome-sum = T_i locally.
  fp_T <- .callMpcTool("k2-float-to-fp",
                        list(values = as.numeric(T_i), frac_bits = 50L,
                             ring = "ring127"))$fp_data
  ss[[output_key]] <- fp_T

  # Plaintext θ passed back to client for diagnostic parity.
  list(stored = TRUE, role = "os", n = n_int,
       class_counts = as.integer(table(factor(j_of_i, levels = seq_len(K)))),
       T_norm_L2 = sqrt(sum(T_i^2)),
       T_max = max(abs(T_i)))
}
