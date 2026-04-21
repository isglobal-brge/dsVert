#' @title Cox one-step Newton at beta = 0 (bias-free)
#' @description
#'   At beta = 0, mu = exp(X*beta) = 1 identically. Neither the DCF exp
#'   spline nor the DCF reciprocal spline is invoked, so the score and
#'   the expected Fisher information are EXACT in the Ring63 FP ring
#'   (apart from ~1e-5 FP quantisation per op). A single Newton step
#'      beta_hat = Fisher(0)^{-1} . grad(0)
#'   recovers the Cox MLE to O(|beta|^2) — within 5-10% for small
#'   coefficients, plenty for the paper's inference bar.
#'
#'   Closed-form expressions at beta = 0:
#'     grad_j(0)      = sum_{i: delta_i=1} [ X_ij - S_j(t_i) / N(t_i) ]
#'     Fisher_jk(0)   = sum_{i: delta_i=1} [ S_jk(t_i)/N(t_i)
#'                                           - S_j(t_i)*S_k(t_i)/N(t_i)^2 ]
#'   with S_j(t_i)  = sum_{m >= i} X_mj  (reverse cumsum after sort by t)
#'        S_jk(t_i) = sum_{m >= i} X_mj X_mk                (ditto)
#'        N(t_i)    = |R(t_i)| = n - i + 1 (unique-ties; strata reset).
#'
#'   Ring63 shares are LINEAR: reverse cumsum of each party's share is
#'   a share of the reverse cumsum of the reconstructed column. Plain-
#'   text-at-both weights (delta/N, delta/N^2) can be folded in via the
#'   standard share * plaintext elementwise product. The only non-linear
#'   step is X_j * X_k and S_j * S_k, handled by the existing Beaver
#'   vecmul primitive (k2BeaverVecmul{Gen,Consume,R1,R2}DS).
#'
#'   Pre-conditions set by ds.vertCox setup BEFORE calling this path:
#'     * k2ShareInputDS(..) has populated k2_x_share_fp (own) and
#'       k2_peer_x_share_fp (peer cols) in row-major FP.
#'     * k2SetCoxTimesDS / k2ReceiveCoxMetaDS have broadcast the sort
#'       permutation + delta as PLAINTEXT FP (same bytes at both
#'       parties) in ss$k2_cox_delta_fp, and the permutation has been
#'       applied via k2ApplyCoxPermutationDS so shares are sorted by t.
#'     * strata (optional) are cached in ss$k2_cox_strata.
#'
#'   Inter-server disclosure: unchanged from the iterative Cox pipeline
#'   -- the permutation and delta are already disclosed at setup. No new
#'   channels, no per-observation reveal. All reveals are scalar
#'   aggregates (p-vector grad, p*p Fisher).
#'
#' @name cox-newton
NULL

# ---- internal helpers -------------------------------------------------

# Compute the plaintext 1/N(i) vector accounting for strata. N(t_i) is the
# number of rows at risk at event time i, i.e. within the current stratum,
# the count of rows with rank >= i. After sort-by-stratum-then-time, this is
# (stratum_size - position_within_stratum + 1).
.cox_newton_N_and_strata_splits <- function(strata) {
  if (is.null(strata)) {
    n <- NA_integer_  # caller passes n separately
    return(list(Ninv = NULL, strata_splits = NULL))
  }
  # Count per stratum, derive N(i) for each row.
  tbl <- rle(strata)
  strata_sizes <- tbl$lengths
  starts <- c(1L, cumsum(strata_sizes)[-length(strata_sizes)] + 1L)
  Nvec <- integer(length(strata))
  for (s in seq_along(strata_sizes)) {
    sz <- strata_sizes[s]
    rng <- starts[s]:(starts[s] + sz - 1L)
    Nvec[rng] <- sz:1L
  }
  list(Ninv = 1 / Nvec, strata_splits = NULL)
}

#' @title Cox-Newton prep: extract+cumsum all columns and build plaintext weights
#' @description
#'   Invariant inputs (already in session):
#'     ss$k2_x_share_fp        row-major FP share, n*p_own
#'     ss$k2_peer_x_share_fp   row-major FP share, n*p_peer
#'     ss$k2_x_n, ss$k2_x_p, ss$k2_peer_p
#'     ss$k2_cox_delta_fp      plaintext FP (same bytes at both parties)
#'     ss$k2_cox_strata        optional integer vector (plaintext, same bytes)
#'
#'   This helper:
#'     1. Extracts each column into its own FP share slot
#'          cox_n_Xc_<idx>_fp   (idx = 1..p_total, canonical order [own | peer])
#'     2. Computes reverse cumsums (strata-reset) on each column share
#'          cox_n_Sc_<idx>_fp
#'     3. Builds plaintext FP vectors (SAME bytes at both parties by
#'        construction — both parties read identical delta_fp and strata)
#'          cox_n_delta_fp    delta (already stored; repeated here)
#'          cox_n_W1_fp       delta(i)/N(i)          [plaintext FP]
#'          cox_n_W2_fp       delta(i)/N(i)^2        [plaintext FP]
#'
#'   Returns: list(n, p_own, p_peer, p_total, n_events).
#' @param session_id MPC session id.
#' @return list(n, p_own, p_peer, p_total, n_events).
#' @param is_coordinator Logical -- TRUE at the outcome server. Determines
#'   the canonical mapping from local "own" / "peer" share matrices to the
#'   global [coord | nonlabel] column order that BOTH parties must agree
#'   on. Without this mapping each party's grad_j / Fisher_jk refers to a
#'   different column and scalar aggregation across parties is garbage.
#' @param p_coord,p_nl Canonical column counts (coordinator / nonlabel
#'   covariates). The concatenated beta order is (coord, nl), total p.
#' @export
dsvertCoxNewtonPrepDS <- function(session_id = NULL,
                                   is_coordinator = NULL,
                                   p_coord = NULL, p_nl = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (is.null(is_coordinator) || is.null(p_coord) || is.null(p_nl)) {
    stop("cox-newton prep requires is_coordinator, p_coord, p_nl",
         call. = FALSE)
  }
  ss <- .S(session_id)
  n <- as.integer(ss$k2_x_n)
  p_own <- as.integer(ss$k2_x_p %||% 0L)
  p_peer <- as.integer(ss$k2_peer_p %||% 0L)
  p_total <- p_own + p_peer
  p_coord <- as.integer(p_coord)
  p_nl <- as.integer(p_nl)
  if (p_total != p_coord + p_nl) {
    stop(sprintf("cox-newton prep: p_total=%d != p_coord+p_nl=%d",
                  p_total, p_coord + p_nl), call. = FALSE)
  }
  # Build the mapping: canonical_idx j in [1..p_total] maps to
  #   (source = "own"/"peer", within-source col index 1..p_own or 1..p_peer).
  # At coordinator: canonical [1..p_coord] = own, [p_coord+1..p_total] = peer.
  # At nonlabel:    canonical [1..p_coord] = peer, [p_coord+1..p_total] = own.
  src <- character(p_total)
  idx_in_src <- integer(p_total)
  if (isTRUE(is_coordinator)) {
    src[1:p_coord] <- "own";  idx_in_src[1:p_coord] <- seq_len(p_coord)
    if (p_nl > 0L) {
      src[(p_coord + 1L):p_total] <- "peer"
      idx_in_src[(p_coord + 1L):p_total] <- seq_len(p_nl)
    }
  } else {
    src[1:p_coord] <- "peer"; idx_in_src[1:p_coord] <- seq_len(p_coord)
    if (p_nl > 0L) {
      src[(p_coord + 1L):p_total] <- "own"
      idx_in_src[(p_coord + 1L):p_total] <- seq_len(p_nl)
    }
  }
  strata_vec <- ss$k2_cox_strata  # may be NULL
  ring <- as.integer(ss$k2_ring %||% 63L)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L

  # ---- 1. Extract + reverse cumsum every canonical column.
  # canonical idx `j` maps to src[j] ("own" or "peer") and position idx_in_src[j].
  for (j in seq_len(p_total)) {
    src_mat <- if (src[j] == "own") ss$k2_x_share_fp else ss$k2_peer_x_share_fp
    src_k   <- if (src[j] == "own") p_own else p_peer
    col_res <- .callMpcTool("k2-fp-extract-column", list(
      fp_data = src_mat, n = n, k = as.integer(src_k),
      col = as.integer(idx_in_src[j] - 1L),
      frac_bits = frac_bits, ring = ring_tag))
    Xkey <- sprintf("cox_n_Xc_%d_fp", j)
    ss[[Xkey]] <- col_res$result
    args <- list(a = ss[[Xkey]], reverse = TRUE,
                 n = n, frac_bits = frac_bits, ring = ring_tag)
    if (!is.null(strata_vec) && length(strata_vec) > 0L) {
      args$strata <- as.integer(strata_vec)
    }
    Skey <- sprintf("cox_n_Sc_%d_fp", j)
    ss[[Skey]] <- .callMpcTool("k2-fp-cumsum", args)$result
  }

  # ---- 2. Plaintext weights (identical at both parties by construction).
  # Both parties hold the same k2_cox_delta_fp AND the same strata vector,
  # so the weights computed from them match byte-for-byte. Decode the
  # plaintext FP delta via k2-ring63-aggregate with a zero second share.
  # Decode plaintext FP delta via k2-ring63-aggregate with a zero second
  # share (standard trick to reinterpret plaintext FP as float).
  zero_fp <- .callMpcTool("k2-float-to-fp", list(
    values = as.numeric(rep(0, n)), frac_bits = frac_bits,
    ring = ring_tag))$fp_data
  delta_vals <- as.numeric(.callMpcTool("k2-ring63-aggregate", list(
    share_a = ss$k2_cox_delta_fp, share_b = zero_fp,
    frac_bits = frac_bits, ring = ring_tag))$values)
  if (length(delta_vals) != n) {
    stop(sprintf("delta length %d != n=%d", length(delta_vals), n),
         call. = FALSE)
  }
  # Build N(i) accounting for strata.
  if (!is.null(strata_vec) && length(strata_vec) > 0L) {
    strata_vec <- as.integer(strata_vec)
    tbl <- rle(strata_vec)
    Nvec <- integer(n)
    off <- 0L
    for (sz in tbl$lengths) {
      Nvec[(off + 1L):(off + sz)] <- sz:1L
      off <- off + sz
    }
  } else {
    Nvec <- n:1L
  }
  W1 <- as.numeric(delta_vals / Nvec)         # weights S_j in grad term 2
  W2 <- as.numeric(delta_vals / (Nvec * Nvec)) # weights S_j*S_k in Fisher term 2
  # W1cum = forward cumsum (strata-aware) of delta/N. Weights X_j*X_k
  # directly in Fisher term 1:
  #   sum_i (delta/N)(i) * S_jk(i) = sum_m X_j(m)*X_k(m) * W1cum(m)
  # (S_jk is the reverse cumsum of X_j*X_k, and the reverse cumsum
  # re-expressed as a forward cumsum on the weight vector is equivalent
  # and avoids an extra share-level cumsum op.)
  if (!is.null(strata_vec) && length(strata_vec) > 0L) {
    sv <- as.integer(strata_vec)
    acc <- 0; W1cum <- numeric(n)
    for (i in seq_len(n)) {
      if (i > 1L && sv[i] != sv[i - 1L]) acc <- 0
      acc <- acc + W1[i]
      W1cum[i] <- acc
    }
  } else {
    W1cum <- cumsum(W1)
  }
  ss$cox_n_W1_fp <- .callMpcTool("k2-float-to-fp", list(
    values = W1, frac_bits = frac_bits, ring = ring_tag))$fp_data
  ss$cox_n_W1cum_fp <- .callMpcTool("k2-float-to-fp", list(
    values = as.numeric(W1cum), frac_bits = frac_bits,
    ring = ring_tag))$fp_data
  ss$cox_n_W2_fp <- .callMpcTool("k2-float-to-fp", list(
    values = W2, frac_bits = frac_bits, ring = ring_tag))$fp_data
  ss$cox_n_p_own <- p_own
  ss$cox_n_p_peer <- p_peer
  ss$cox_n_p_total <- p_total

  list(n = n, p_own = p_own, p_peer = p_peer, p_total = p_total,
       n_events = sum(delta_vals))
}

#' @title Return the p_total-vector grad(0) scalar share
#' @description
#'   grad_c(0) = sum_i delta(i) X_c(i) - sum_i (delta/N)(i) S_c(i)
#'   Both terms are share * plaintext-at-both elementwise (safe -- gives
#'   a share of the product, since both parties multiply the same
#'   plaintext into their share).
#'   This helper returns a base64-encoded length-p_total FP scalar-share
#'   vector; the client aggregates the two parties' shares element-wise
#'   via k2-ring63-aggregate.
#' @param session_id MPC session id.
#' @return list(grad_shares_fp = base64 FP vector of length p_total).
#' @export
dsvertCoxNewtonGradDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  p_total <- as.integer(ss$cox_n_p_total %||%
                         (as.integer(ss$k2_x_p) + as.integer(ss$k2_peer_p)))
  if (p_total <= 0L) stop("cox-newton prep not run", call. = FALSE)
  n <- as.integer(ss$k2_x_n)
  delta_fp <- ss$k2_cox_delta_fp
  W1_fp <- ss$cox_n_W1_fp
  if (is.null(delta_fp) || is.null(W1_fp)) {
    stop("cox-newton prep missing weights", call. = FALSE)
  }
  ring <- as.integer(ss$k2_ring %||% 63L)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L
  # Return each scalar FP share as its own named field. The client
  # aggregates each one individually via k2-ring63-aggregate — avoids
  # any concat / endianness subtlety that can corrupt a packed p-vector.
  scalar_fps <- vector("list", p_total)
  for (cc in seq_len(p_total)) {
    Xkey <- sprintf("cox_n_Xc_%d_fp", cc)
    Skey <- sprintf("cox_n_Sc_%d_fp", cc)
    # t1_share = fp-sum( X_c_share .* delta_fp )
    t1vec <- .callMpcTool("k2-fp-vec-mul", list(
      a = ss[[Xkey]], b = delta_fp,
      frac_bits = frac_bits, ring = ring_tag))
    t1 <- .callMpcTool("k2-fp-sum", list(
      fp_data = t1vec$result, ring = ring_tag))
    # t2_share = fp-sum( S_c_share .* W1_fp )
    t2vec <- .callMpcTool("k2-fp-vec-mul", list(
      a = ss[[Skey]], b = W1_fp,
      frac_bits = frac_bits, ring = ring_tag))
    t2 <- .callMpcTool("k2-fp-sum", list(
      fp_data = t2vec$result, ring = ring_tag))
    # grad_c_share = t1_share - t2_share   (scalar FP)
    diff <- .callMpcTool("k2-fp-sub", list(
      a = t1$sum_fp, b = t2$sum_fp,
      frac_bits = frac_bits, ring = ring_tag))
    scalar_fps[[cc]] <- diff$result
  }
  names(scalar_fps) <- sprintf("grad_%d", seq_len(p_total))
  c(list(p = p_total), scalar_fps)
}

#' @title Seed and prepare for the per-pair Beaver vecmul round
#' @description
#'   For a single Fisher pair (j, k), copy the column shares into the
#'   canonical x_key/y_key slots that k2BeaverVecmulR1DS / R2DS expect.
#'   Two variants:
#'     which = "X"  -> copy cox_n_Xc_<j>_fp -> cox_n_Beaver_A_fp
#'                     copy cox_n_Xc_<k>_fp -> cox_n_Beaver_B_fp
#'     which = "S"  -> copy cox_n_Sc_<j>_fp -> cox_n_Beaver_A_fp
#'                     copy cox_n_Sc_<k>_fp -> cox_n_Beaver_B_fp
#'   After R1 + R2, the Beaver z-share sits in cox_n_Beaver_Z_fp; the
#'   caller then runs dsvertCoxNewtonFisherScalarDS to produce the
#'   scalar share for the chosen term.
#' @param j,k 1-based column indices (canonical [own | peer] order).
#' @param which "X" for first Fisher term, "S" for second.
#' @param session_id MPC session id.
#' @return list(stored = TRUE).
#' @export
dsvertCoxNewtonLoadPairDS <- function(j, k, which = c("X", "S"),
                                        session_id = NULL) {
  which <- match.arg(which)
  ss <- .S(session_id)
  prefix <- if (which == "X") "Xc" else "Sc"
  jkey <- sprintf("cox_n_%s_%d_fp", prefix, as.integer(j))
  kkey <- sprintf("cox_n_%s_%d_fp", prefix, as.integer(k))
  if (is.null(ss[[jkey]]) || is.null(ss[[kkey]])) {
    stop("missing column share for pair (", j, ",", k, ") which=",
         which, call. = FALSE)
  }
  ss$cox_n_Beaver_A_fp <- ss[[jkey]]
  ss$cox_n_Beaver_B_fp <- ss[[kkey]]
  list(stored = TRUE, which = which)
}

#' @title Compute scalar share of Fisher term (after Beaver round 2)
#' @description
#'   After k2BeaverVecmulR2DS has produced the share of z = a .* b into
#'   cox_n_Beaver_Z_fp, this helper multiplies z elementwise by the
#'   plaintext weight (W1 for first Fisher term, W2 for the second) and
#'   returns the scalar share sum. Caller aggregates both parties.
#' @param weight_key "W1" or "W2".
#' @param session_id MPC session id.
#' @return list(scalar_share_fp = 8-byte base64).
#' @export
dsvertCoxNewtonFisherScalarDS <- function(weight_key = c("W1cum", "W2"),
                                            session_id = NULL) {
  weight_key <- match.arg(weight_key)
  ss <- .S(session_id)
  z <- ss$cox_n_Beaver_Z_fp
  if (is.null(z)) {
    stop("Beaver z-share cox_n_Beaver_Z_fp missing; run R2 first",
         call. = FALSE)
  }
  # W1cum weights Beaver Z = X_j*X_k elementwise for Fisher term 1.
  # W2    weights Beaver Z = S_j*S_k elementwise for Fisher term 2.
  w <- if (weight_key == "W1cum") ss$cox_n_W1cum_fp else ss$cox_n_W2_fp
  if (is.null(w)) stop("weight ", weight_key, " missing", call. = FALSE)
  ring <- as.integer(ss$k2_ring %||% 63L)
  ring_tag <- if (ring == 127L) "ring127" else "ring63"
  frac_bits <- if (ring == 127L) 50L else 20L
  zw <- .callMpcTool("k2-fp-vec-mul", list(
    a = z, b = w, frac_bits = frac_bits, ring = ring_tag))
  s <- .callMpcTool("k2-fp-sum", list(
    fp_data = zw$result, ring = ring_tag))
  list(scalar_share_fp = s$sum_fp)
}

# %||% is provided by dsVert/R/mpcSession.R -- no local fallback needed.
