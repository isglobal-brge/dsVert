#' @title Compute residual share r = y_ind − p on outcome server
#' @description Local share operation: on the outcome server, subtract a
#'   plaintext 0/1 class-indicator column from a softmax/sigmoid probability
#'   share stored under \code{p_key}. On the peer, just negate the p share.
#'   Output is a new Ring127 residual share under \code{output_key}.
#'
#'   Used by \code{ds.vertMultinomJointNewton} and
#'   \code{ds.vertOrdinalJointNewton} to build residuals for the joint
#'   Beaver matvec gradient per class without any cross-server MPC.
#'
#' @param p_key Character. Session slot holding Ring127 share of p per
#'   patient (from Beaver vecmul \code{exp(η_k) · (1/D)}).
#' @param indicator_col Character. Plaintext 0/1 column name on the
#'   outcome server (e.g. \code{"low_ind"}). Ignored on peer.
#' @param data_name Character. Data frame name (for indicator column
#'   resolution).
#' @param output_key Character. Session slot to store the residual share.
#' @param is_outcome_server Logical. When TRUE, subtract y_ind − p_share.
#'   When FALSE, just negate the p share.
#' @param n Integer. Length of p / indicator vector.
#' @param session_id MPC session id.
#' @return \code{list(stored = TRUE, output_key, n)}.
#' @export
dsvertComputeResidualShareDS <- function(p_key, indicator_col = NULL,
                                          data_name = NULL, output_key,
                                          is_outcome_server = FALSE,
                                          n, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (is.null(p_key) || !nzchar(p_key)) stop("p_key required", call. = FALSE)
  if (is.null(output_key) || !nzchar(output_key))
    stop("output_key required", call. = FALSE)

  ss <- .S(session_id)
  ring <- as.integer(ss$k2_ring %||% 63L)
  if (ring != 127L) {
    stop("dsvertComputeResidualShareDS invoked with ring=", ring,
         "; only ring=127 is supported.", call. = FALSE)
  }
  p_b64 <- ss[[p_key]]
  if (is.null(p_b64) || !nzchar(p_b64))
    stop("session slot '", p_key, "' is empty", call. = FALSE)

  if (isTRUE(is_outcome_server)) {
    if (is.null(indicator_col) || !nzchar(indicator_col))
      stop("indicator_col required on outcome server", call. = FALSE)
    if (is.null(data_name) || !nzchar(data_name))
      stop("data_name required on outcome server", call. = FALSE)
    .validate_data_name(data_name)
    data <- get(data_name, envir = parent.frame())
    if (!indicator_col %in% names(data))
      stop("indicator column '", indicator_col, "' not found in '",
           data_name, "'", call. = FALSE)
    y_ind <- as.numeric(data[[indicator_col]])
    if (length(y_ind) != n)
      stop("indicator length ", length(y_ind), " != n ", n, call. = FALSE)
    y_ind_fp <- .callMpcTool("k2-float-to-fp", list(
      values = y_ind, frac_bits = 50L, ring = "ring127"))$fp_data
    # r_share = y_ind_const − p_share per-element.
    # Use k2-ring127-per-element-combine (vector variant). If it doesn't exist,
    # fall back to: split y_ind into a "share" (y_ind, 0) and affine-combine.
    # For now: store y_ind as a temp share (outcome server holds the full
    # vector, peer has zeros — additive share of y_ind with peer).
    tmp_key <- paste0(output_key, "__y_ind_tmp")
    ss[[tmp_key]] <- y_ind_fp
    # r_share = (y_ind − p) on outcome server: use affine-combine vector form.
    .callMpcTool("k2-ring127-affine-combine", list(
      a = ss[[tmp_key]], b = ss[[p_key]],
      sign_a = 1L, sign_b = -1L,
      public_const = "", is_party0 = TRUE,
      frac_bits = 50L, n = as.integer(n)))$result -> res
    ss[[output_key]] <- res
    ss[[tmp_key]] <- NULL
  } else {
    # Peer: r_share = −p_share (just negate).
    res <- .callMpcTool("k2-ring127-affine-combine", list(
      a = ss[[p_key]], b = "",
      sign_a = -1L, sign_b = 0L,
      public_const = "", is_party0 = FALSE,
      frac_bits = 50L, n = as.integer(n)))$result
    ss[[output_key]] <- res
  }

  list(stored = TRUE, output_key = output_key, n = as.integer(n))
}
