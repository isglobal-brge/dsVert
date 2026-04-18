#' @title One-hot encode a categorical variable (server-side aggregate)
#' @description Return a server-side one-hot-encoded matrix for a single
#'   categorical column, along with metadata (levels, row margins). This
#'   is the prerequisite for cross-server chi-square: both servers share
#'   the level set and the indicator counts via the already-deployed
#'   Beaver cross-product infrastructure, allowing the client to assemble
#'   the K x L contingency table without ever materialising an n-vector
#'   on the analyst client.
#'
#' @details
#'   The raw one-hot matrix itself is NOT returned to the client: only the
#'   level set (character) and the row margin sums (per-level counts) come
#'   back. The n*K indicator matrix is materialised transiently inside the
#'   session for use by the downstream Beaver dot-product Aggregate, and
#'   is stored in the MPC session under `k2_onehot_<var>_fp` (row-major
#'   n*K FP vector) for the client orchestrator to reference via a
#'   session_id.
#'
#'   Privacy: the per-level row-margin counts are themselves an aggregate
#'   (one integer per category) and are subject to the same
#'   `datashield.privacyLevel` suppression rule as the existing
#'   `dsvertContingencyDS` helper.
#'
#' @param data_name Character. Name of the server-side data frame.
#' @param var Character. Name of the categorical column to encode.
#' @param levels Optional character vector. If supplied, use these as the
#'   canonical level set (useful when the client wants a fixed common
#'   level ordering across the two servers); otherwise
#'   `sort(unique(data[[var]]))` is used.
#' @param session_id MPC session id (required; the one-hot matrix is
#'   stored under this session for subsequent Beaver cross-product
#'   reduction).
#' @param suppress_small_cells Logical. If TRUE (default) suppress
#'   per-level row-margin counts below the DataSHIELD privacy threshold.
#' @return A list with elements:
#'   \itemize{
#'     \item \code{levels}: character vector of category names (canonical)
#'     \item \code{row_margins}: integer vector (count per level)
#'     \item \code{n}: total complete-case count
#'     \item \code{n_na}: count of dropped NA rows
#'     \item \code{session_key}: key under which the n x K one-hot matrix
#'       is stored in the MPC session for the downstream Beaver stage.
#'   }
#' @export
dsvertOneHotDS <- function(data_name, var, levels = NULL,
                           session_id = NULL,
                           suppress_small_cells = TRUE) {
  if (!is.character(data_name) || length(data_name) != 1L) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(var) || length(var) != 1L) {
    stop("var must be a single character string", call. = FALSE)
  }
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required (call dsvertOneHotDS inside a live MPC session)",
         call. = FALSE)
  }

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!var %in% names(data)) {
    stop("Variable '", var, "' not found in '", data_name, "'",
         call. = FALSE)
  }

  x <- data[[var]]
  keep <- !is.na(x)
  n_na <- sum(!keep)
  x <- x[keep]
  n <- length(x)

  lvls <- if (is.null(levels)) sort(unique(as.character(x))) else as.character(levels)
  K <- length(lvls)
  if (K < 2L) {
    stop("At least 2 levels required for one-hot encoding; got ", K,
         call. = FALSE)
  }

  # Row-major n x K indicator matrix (FP-encoded so it's share-compatible
  # with the existing Beaver machinery).
  mat <- matrix(0, nrow = n, ncol = K)
  lvl_idx <- match(as.character(x), lvls)
  for (i in seq_len(n)) {
    mat[i, lvl_idx[i]] <- 1
  }
  row_margins <- as.integer(colSums(mat))

  if (isTRUE(suppress_small_cells)) {
    privacy_min <- getOption("datashield.privacyLevel", 5L)
    if (is.numeric(privacy_min) && privacy_min > 0) {
      row_margins[row_margins > 0L & row_margins < privacy_min] <- 0L
      if (n < privacy_min) n <- 0L
    }
  }

  # Store the flat row-major FP matrix into the session so that a
  # subsequent Beaver dot-product reduction can consume it without the
  # client ever seeing the n*K indicator matrix.
  flat <- as.numeric(t(mat))
  fp <- .callMpcTool("k2-float-to-fp",
                     list(values = flat, frac_bits = 20L))$fp_data
  ss <- .S(session_id)
  session_key <- paste0("k2_onehot_", var, "_fp")
  ss[[session_key]] <- fp
  ss[[paste0("k2_onehot_", var, "_n")]] <- as.integer(n)
  ss[[paste0("k2_onehot_", var, "_K")]] <- as.integer(K)
  ss[[paste0("k2_onehot_", var, "_levels")]] <- lvls

  list(
    levels = lvls,
    row_margins = row_margins,
    n = n,
    n_na = n_na,
    session_key = session_key
  )
}
