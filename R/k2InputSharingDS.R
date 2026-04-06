#' @title K=2 Input-Sharing + Gradient (ALL in FixedPoint Ring63)
#' @description All operations stay in the FixedPoint ring until the final
#'   gradient scalars are converted to float64. This prevents the int64
#'   wrapping non-additivity issue that caused gradient divergence.
#' @name k2-input-sharing
NULL

#' Share local data with peer (FixedPoint shares)
#' @export
k2ShareInputDS <- function(data_name, x_vars, y_var = NULL,
                             peer_pk, session_id = NULL) {
  ss <- .S(session_id)
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p <- ncol(X)

  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) stop("Insufficient observations", call. = FALSE)
  .check_glm_disclosure(X)

  # Convert X to FP and split into shares
  x_flat <- as.numeric(t(X)) # row-major
  fp_x <- .callMheTool("k2-float-to-fp", list(values = x_flat, frac_bits = 20L))$fp_data
  x_split <- .callMheTool("k2-split-fp-share", list(data_fp = fp_x, n = length(x_flat)))

  ss$k2_x_share_fp <- x_split$own_share
  ss$k2_x_n <- n
  ss$k2_x_p <- p

  # y (label only)
  encrypted_y <- NULL
  if (!is.null(y_var)) {
    y <- as.numeric(data[[y_var]])
    fp_y <- .callMheTool("k2-float-to-fp", list(values = y, frac_bits = 20L))$fp_data
    y_split <- .callMheTool("k2-split-fp-share", list(data_fp = fp_y, n = length(y)))
    ss$k2_y_share_fp <- y_split$own_share

    # Transport-encrypt peer's y share
    pk <- .base64url_to_base64(peer_pk)
    sealed_y <- .callMheTool("transport-encrypt", list(
      data = jsonlite::base64_enc(charToRaw(y_split$peer_share)),
      recipient_pk = pk))
    encrypted_y <- base64_to_base64url(sealed_y$sealed)
  }

  # Transport-encrypt peer's X share
  pk <- .base64url_to_base64(peer_pk)
  sealed_x <- .callMheTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(x_split$peer_share)),
    recipient_pk = pk))

  list(
    encrypted_x_share = base64_to_base64url(sealed_x$sealed),
    encrypted_y_share = encrypted_y,
    n = n, p = p
  )
}

#' Receive peer's shared data (FixedPoint)
#' @export
k2ReceiveShareDS <- function(peer_p = NULL, session_id = NULL) {
  ss <- .S(session_id)
  tsk <- .key_get("transport_sk", ss)

  x_blob <- .blob_consume("k2_peer_x_share", ss)
  if (!is.null(x_blob)) {
    dec <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(x_blob), recipient_sk = tsk))
    ss$k2_peer_x_share_fp <- rawToChar(jsonlite::base64_dec(dec$data))
    ss$k2_peer_p <- as.integer(peer_p)
  }

  y_blob <- .blob_consume("k2_peer_y_share", ss)
  if (!is.null(y_blob)) {
    dec <- .callMheTool("transport-decrypt", list(
      sealed = .base64url_to_base64(y_blob), recipient_sk = tsk))
    ss$k2_y_share_fp <- rawToChar(jsonlite::base64_dec(dec$data))
  }

  list(stored = TRUE)
}

#' Compute eta share in FixedPoint from full data shares and public beta
#' @export
k2ComputeEtaShareDS <- function(beta_coord, beta_nl, intercept = 0.0,
                                  is_coordinator = TRUE, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p
  p_total <- p_own + p_peer

  # Beta is ALWAYS in canonical order: [coord features | nonlabel features]
  # Both parties use the SAME order — this is the canonical feature ordering
  # from the specification.
  beta_full <- c(as.numeric(beta_coord), as.numeric(beta_nl))

  # Convert beta to FP
  fp_beta <- .callMheTool("k2-float-to-fp", list(
    values = beta_full, frac_bits = 20L))$fp_data

  # Compute eta_share = X_full_share * beta in FP ring
  # Uses k2-compute-eta-fp command
  result <- .callMheTool("k2-compute-eta-fp", list(
    x_own_fp = ss$k2_x_share_fp,
    x_peer_fp = ss$k2_peer_x_share_fp,
    beta_fp = fp_beta,
    intercept = intercept,
    is_party_zero = is_coordinator,
    n = as.integer(n),
    p_own = as.integer(p_own),
    p_peer = as.integer(p_peer),
    frac_bits = 20L
  ))

  # Store for Beaver polynomial eval AND gradient computation
  ss$k2_eta_share <- result$eta_fp
  ss$k2_eta_share_fp <- result$eta_fp  # wide spline DCF reads this key
  ss$secure_eta_share <- result$eta_fp
  ss$k2_x_full_fp <- result$x_full_fp  # full X share for gradient

  # Ensure y_share_fp exists (nonlabel gets it from input sharing, label creates it)
  if (is.null(ss$k2_y_share_fp)) {
    # Nonlabel: y_share is all zeros (since we subtract label's y_share from both)
    zero_y <- .callMheTool("k2-float-to-fp", list(
      values = rep(0, n), frac_bits = 20L))$fp_data
    ss$k2_y_share_fp <- zero_y
  }

  list(stored = TRUE, n = n)
}

#' Gradient round 1: compute (X-A, r-B) in Ring63
#' @export
k2GradientR1DS <- function(peer_pk, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_own <- ss$k2_x_p
  p_peer <- ss$k2_peer_p
  p_total <- p_own + p_peer

  # Assemble full X share FP: concatenate own + peer columns per row
  # This is done by the Go command
  result <- .callMheTool("k2-full-iter-r3", list(
    x_share_fp = ss$k2_x_full_fp,
    mu_share_fp = ss$secure_mu_share,
    y_share_fp = ss$k2_y_share_fp,
    a_share_fp = ss$k2_grad_a_fp,
    b_share_fp = ss$k2_grad_b_fp,
    c_share_fp = "",
    peer_xma_fp = "",
    peer_rmb_fp = "",
    n = as.integer(n),
    p = as.integer(p_total),
    party_id = 0L,
    phase = 1L
  ))

  # Transport-encrypt for peer
  pk <- .base64url_to_base64(peer_pk)
  msg_json <- jsonlite::toJSON(list(
    xma = result$xma_fp, rmb = result$rmb_fp), auto_unbox = TRUE)
  sealed <- .callMheTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(msg_json)),
    recipient_pk = pk))

  list(
    encrypted_r1 = base64_to_base64url(sealed$sealed),
    sum_residual = result$sum_residual,
    sum_residual_fp = result$sum_residual_fp
  )
}

#' Gradient round 2: compute gradient share from Beaver formula
#' @export
k2GradientR2DS <- function(party_id = 0L, session_id = NULL) {
  ss <- .S(session_id)
  n <- ss$k2_x_n
  p_total <- ss$k2_x_p + ss$k2_peer_p

  # Decrypt peer's round-1 message
  blob <- .blob_consume("k2_grad_peer_r1", ss)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  peer_msg <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))

  result <- .callMheTool("k2-full-iter-r3", list(
    x_share_fp = ss$k2_x_full_fp,
    mu_share_fp = ss$secure_mu_share,
    y_share_fp = ss$k2_y_share_fp,
    a_share_fp = ss$k2_grad_a_fp,
    b_share_fp = ss$k2_grad_b_fp,
    c_share_fp = ss$k2_grad_c_fp,
    peer_xma_fp = peer_msg$xma,
    peer_rmb_fp = peer_msg$rmb,
    n = as.integer(n),
    p = as.integer(p_total),
    party_id = as.integer(party_id),
    phase = 2L
  ))

  list(gradient_share = result$gradient, sum_residual = result$sum_residual,
       gradient_fp = result$gradient_fp, sum_residual_fp = result$sum_residual_fp)
}

#' Store power chain Beaver triple from blob (Ring63 FP format)
#' @export
k2StorePowerTripleDS <- function(triple_key, session_id = NULL) {
  ss <- .S(session_id)
  blob <- .blob_consume(triple_key, ss)
  if (is.null(blob)) stop("No power triple blob for key: ", triple_key, call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  msg <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  ss$k2_pow_a_fp <- msg$a
  ss$k2_pow_b_fp <- msg$b
  ss$k2_pow_c_fp <- msg$c
  list(stored = TRUE)
}

#' Store gradient Beaver triple (Ring63 FP format)
#' @export
k2StoreGradTripleDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  blob <- .blob_consume("k2_grad_triple_fp", ss)
  if (is.null(blob)) stop("No gradient triple blob", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMheTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  msg <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
  ss$k2_grad_a_fp <- msg$a
  ss$k2_grad_b_fp <- msg$b
  ss$k2_grad_c_fp <- msg$c
  list(stored = TRUE)
}

#' Read a session key value (for round-by-round debugging)
#' @param key Character. Session key name.
#' @param session_id Character or NULL.
#' @return List with value and nchar.
#' @export
k2ReadSessionKeyDS <- function(key, session_id = NULL) {
  ss <- .S(session_id)
  val <- ss[[key]]
  list(value = val, nchar = if (!is.null(val)) nchar(val) else 0L)
}

#' Diagnostic: check session state for K=2 gradient
#' @export
k2DiagnosticDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  # Convert FP shares to float for first 5 elements (diagnostic only)
  mu_first5 <- NULL
  eta_first5 <- NULL
  y_first5 <- NULL
  if (!is.null(ss$secure_mu_share)) {
    mu_first5 <- tryCatch({
      r <- .callMheTool("mpc-fp-to-float", list(
        fp_data = ss$secure_mu_share, frac_bits = 20L))
      head(r$values, 5)
    }, error = function(e) NULL)
  }
  if (!is.null(ss$secure_eta_share)) {
    eta_first5 <- tryCatch({
      r <- .callMheTool("mpc-fp-to-float", list(
        fp_data = ss$secure_eta_share, frac_bits = 20L))
      head(r$values, 5)
    }, error = function(e) NULL)
  }
  if (!is.null(ss$k2_y_share_fp)) {
    y_first5 <- tryCatch({
      r <- .callMheTool("mpc-fp-to-float", list(
        fp_data = ss$k2_y_share_fp, frac_bits = 20L))
      head(r$values, 5)
    }, error = function(e) NULL)
  }
  list(
    has_x_full = !is.null(ss$k2_x_full_fp),
    has_mu = !is.null(ss$secure_mu_share),
    has_y = !is.null(ss$k2_y_share_fp),
    has_grad_a = !is.null(ss$k2_grad_a_fp),
    has_grad_b = !is.null(ss$k2_grad_b_fp),
    has_grad_c = !is.null(ss$k2_grad_c_fp),
    x_full_len = if(!is.null(ss$k2_x_full_fp)) nchar(ss$k2_x_full_fp) else 0,
    mu_len = if(!is.null(ss$secure_mu_share)) nchar(ss$secure_mu_share) else 0,
    y_len = if(!is.null(ss$k2_y_share_fp)) nchar(ss$k2_y_share_fp) else 0,
    n = ss$k2_x_n,
    p_own = ss$k2_x_p,
    p_peer = ss$k2_peer_p,
    mu_first5 = mu_first5,
    eta_first5 = eta_first5,
    y_first5 = y_first5,
    mu_sum_fp = if (!is.null(ss$secure_mu_share)) {
      tryCatch({
        r <- .callMheTool("k2-ring63-sum", list(
          data_fp = ss$secure_mu_share, frac_bits = 20L))
        r$sum_fp  # Ring63 sum as base64 FP (single element)
      }, error = function(e) NULL)
    } else NULL,
    eta_sum_fp = if (!is.null(ss$secure_eta_share)) {
      tryCatch({
        r <- .callMheTool("k2-ring63-sum", list(
          data_fp = ss$secure_eta_share, frac_bits = 20L))
        r$sum_fp
      }, error = function(e) NULL)
    } else NULL
  )
}

#' One Beaver multiplication round in FP (int64 ring)
#'
#' Replaces the old beaver_open + beaver_close with a single command
#' that stays entirely in FixedPoint without float64 conversion.
#'
#' @param x_key Character. Session key for first multiplicand share (FP base64).
#' @param y_key Character. Session key for second multiplicand share (FP base64).
#' @param a_fp Character. Beaver A share (FP base64).
#' @param b_fp Character. Beaver B share (FP base64).
#' @param c_fp Character. Beaver C share (FP base64). Only needed for phase 2.
#' @param peer_xma_fp Character. Peer's X-A message (FP). Empty for phase 1.
#' @param peer_ymb_fp Character. Peer's Y-B message (FP). Empty for phase 1.
#' @param result_key Character. Session key to store result.
#' @param party_id Integer. 0 or 1.
#' @param phase Integer. 1 = generate message, 2 = compute result.
#' @param session_id Character or NULL.
#' @return Phase 1: list with xma_fp, ymb_fp. Phase 2: list with stored key.
#' @export
k2BeaverRoundFPDS <- function(x_key, y_key,
                                a_fp = "", b_fp = "", c_fp = "",
                                peer_xma_fp = "", peer_ymb_fp = "",
                                result_key = NULL,
                                party_id = 0L, phase = 1L,
                                use_session_triple = 0L,
                                peer_blob_key = "",
                                session_id = NULL) {
  ss <- .S(session_id)

  x_share_fp <- ss[[x_key]]
  y_share_fp <- ss[[y_key]]

  if (is.null(x_share_fp) || !nzchar(x_share_fp))
    stop("k2BeaverRoundFPDS: session key '", x_key, "' is NULL or empty. ",
         "Session keys: ", paste(ls(ss), collapse=", "), call. = FALSE)
  if (is.null(y_share_fp) || !nzchar(y_share_fp))
    stop("k2BeaverRoundFPDS: session key '", y_key, "' is NULL or empty.", call. = FALSE)

  # Get triple from session (via blob) or from function arguments
  if (use_session_triple == 1L) {
    a_b64 <- ss$k2_pow_a_fp
    b_b64 <- ss$k2_pow_b_fp
    c_b64 <- if (phase == 2L) ss$k2_pow_c_fp else ""
  } else {
    .from_b64url <- function(x) {
      if (is.null(x) || x == "") return(x)
      x <- gsub("-", "+", gsub("_", "/", x, fixed = TRUE), fixed = TRUE)
      pad <- nchar(x) %% 4
      if (pad == 2) x <- paste0(x, "==")
      if (pad == 3) x <- paste0(x, "=")
      x
    }
    a_b64 <- .from_b64url(a_fp)
    b_b64 <- .from_b64url(b_fp)
    c_b64 <- .from_b64url(c_fp)
  }

  # Get peer's Phase 1 message: from blob or from function arguments
  peer_xma_b64 <- ""
  peer_ymb_b64 <- ""
  if (phase == 2L && nzchar(peer_blob_key) && startsWith(peer_blob_key, "k2_")) {
    blob <- .blob_consume(peer_blob_key, ss)
    if (!is.null(blob)) {
      tsk <- .key_get("transport_sk", ss)
      dec <- .callMheTool("transport-decrypt", list(
        sealed = .base64url_to_base64(blob), recipient_sk = tsk))
      peer_msg <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(dec$data)))
      peer_xma_b64 <- peer_msg$xma
      peer_ymb_b64 <- peer_msg$ymb
    }
  } else if (phase == 2L) {
    .from_b64url <- function(x) {
      if (is.null(x) || x == "") return(x)
      x <- gsub("-", "+", gsub("_", "/", x, fixed = TRUE), fixed = TRUE)
      pad <- nchar(x) %% 4; if (pad == 2) x <- paste0(x, "=="); if (pad == 3) x <- paste0(x, "="); x
    }
    peer_xma_b64 <- .from_b64url(peer_xma_fp)
    peer_ymb_b64 <- .from_b64url(peer_ymb_fp)
  }

  # Diagnostic: verify JSON round-trip preserves base64 strings
  test_rt <- jsonlite::fromJSON(jsonlite::toJSON(list(test = x_share_fp), auto_unbox = TRUE))
  if (!identical(x_share_fp, test_rt$test))
    stop("JSON round-trip corrupted x_share_fp! orig_nchar=", nchar(x_share_fp),
         " rt_nchar=", nchar(test_rt$test))

  result <- tryCatch(
    .callMheTool("k2-beaver-round", list(
      x_share_fp = x_share_fp,
      y_share_fp = y_share_fp,
      a_share_fp = a_b64,
      b_share_fp = b_b64,
      c_share_fp = c_b64,
      peer_xma_fp = peer_xma_b64,
      peer_ymb_fp = peer_ymb_b64,
      party_id = as.integer(party_id),
      phase = as.integer(phase)
    )),
    error = function(e) {
      stop("k2-beaver-round failed. ",
           "x_len=", nchar(x_share_fp), " y_len=", nchar(y_share_fp),
           " a_len=", nchar(a_b64), " b_len=", nchar(b_b64),
           " x_first20=", substr(x_share_fp, 1, 20),
           " a_first20=", substr(a_b64, 1, 20),
           " phase=", phase, " party=", party_id,
           " orig_err: ", conditionMessage(e), call. = FALSE)
    }
  )

  if (phase == 1L) {
    return(list(xma_fp = result$xma_fp, ymb_fp = result$ymb_fp))
  } else {
    if (!is.null(result_key)) {
      ss[[result_key]] <- result$result_fp
    }
    return(list(stored = result_key))
  }
}

#' Local polynomial evaluation on FP power shares
#'
#' After the power chain produces [x], [x^2], ..., [x^d] shares in FP,
#' this evaluates p(x) = a0 + a1*x + ... + ad*x^d locally on each party.
#'
#' @param power_keys Character vector. Session keys for [x^1], [x^2], ..., [x^d].
#' @param coefficients Numeric vector. Polynomial coefficients [a0, a1, ..., ad].
#' @param party_id Integer. 0 or 1.
#' @param session_id Character or NULL.
#' @return List with stored = "k2_mu_share_fp".
#' @export
k2PolyEvalLocalFPDS <- function(power_keys, coefficients,
                                  party_id = 0L, session_id = NULL) {
  ss <- .S(session_id)

  # Call the existing mpc-secure-poly-eval but with FP shares
  # Actually: the old command works fine because it reads FP base64 shares
  # and uses FromFloat64 for coefficients + FPMulLocal for the combination.
  # The issue was in the TRIPLES (store_triples), not in poly_eval itself!

  power_shares <- lapply(power_keys, function(k) ss[[k]])

  result <- .callMheTool("mpc-secure-poly-eval", list(
    power_shares = power_shares,
    coefficients = as.numeric(coefficients),
    party_id = as.integer(party_id),
    frac_bits = 20L
  ))

  ss$secure_mu_share <- result$result_share
  list(stored = "secure_mu_share")
}
