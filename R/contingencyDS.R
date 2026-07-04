#' @title Server-side 2-way contingency table (aggregate)
#' @description Compute the joint frequency table of two categorical or
#'   numeric variables held at the same server. Returns the observed counts
#'   and margins as aggregates for client-side chi-square testing. Intended
#'   for the case where both variables are held on the same server (the
#'   cross-server case with vertically partitioned variables will reuse the
#'   k2 Beaver dot-product infrastructure and will be added as a separate
#'   aggregate once the MPC setup flow supports categorical one-hot sharing).
#'
#' @param data_name Character. Name of the server-side data frame.
#' @param var1 Character. First variable (rows of the contingency table).
#' @param var2 Character. Second variable (columns).
#' @param suppress_small_cells Logical. If TRUE (default) cells with
#'   positive counts below the DataSHIELD privacy threshold
#'   (\code{datashield.privacyLevel}) fail closed by default. Set
#'   \code{fail_on_small_cells = FALSE} only for legacy diagnostics to return
#'   suppressed zeros instead.
#' @param fail_on_small_cells Logical. Stop instead of returning a table if
#'   any positive cell or margin count is below the privacy threshold.
#'
#' @return A list with elements:
#'   \itemize{
#'     \item \code{counts}: integer matrix with rows indexed by
#'       \code{row_levels} and columns by \code{col_levels}
#'     \item \code{row_levels}: character vector (factor levels of var1)
#'     \item \code{col_levels}: character vector (factor levels of var2)
#'     \item \code{row_margins}: integer vector of row sums
#'     \item \code{col_margins}: integer vector of column sums
#'     \item \code{n}: total number of complete-case observations
#'     \item \code{n_na}: number of rows with missingness in either variable
#'   }
#' @seealso \code{dsvertHistogramDS}
#' @export
dsvertContingencyDS <- function(
    data_name, var1, var2,
    suppress_small_cells = TRUE,
    fail_on_small_cells = getOption("dsvert.fail_on_small_cells", TRUE)) {
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(var1) || length(var1) != 1 ||
      !is.character(var2) || length(var2) != 1) {
    stop("var1 and var2 must be single character strings", call. = FALSE)
  }
  if (var1 == var2) {
    stop("var1 and var2 must differ", call. = FALSE)
  }

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  for (v in c(var1, var2)) {
    if (!v %in% names(data)) {
      stop("Variable '", v, "' not found in data frame '",
           data_name, "'", call. = FALSE)
    }
  }

  x <- data[[var1]]
  y <- data[[var2]]

  keep <- !is.na(x) & !is.na(y)
  n_na <- sum(!keep)
  x <- x[keep]
  y <- y[keep]
  n <- length(x)

  fx <- as.factor(x)
  fy <- as.factor(y)
  tbl <- table(fx, fy)
  counts <- unname(as.matrix(tbl))
  mode(counts) <- "integer"
  row_levels <- levels(fx)
  col_levels <- levels(fy)
  row_margins <- as.integer(rowSums(counts))
  col_margins <- as.integer(colSums(counts))

  # SERVER-AUTHORITATIVE disclosure control (F3): a client argument may only
  # make suppression STRICTER. Applied unless the CUSTODIAN explicitly permits.
  suppress_effective <- isTRUE(suppress_small_cells) ||
    !isTRUE(getOption("dsvert.allow_small_cell_release", FALSE))
  fail_effective <- isTRUE(fail_on_small_cells) ||
    !isTRUE(getOption("dsvert.allow_silent_small_cells", FALSE))
  if (suppress_effective) {
    # F7: independent floor (max of privacyLevel and dsvert.min_release_n).
    privacy_min <- max(as.integer(getOption("datashield.privacyLevel", 5L)),
                       as.integer(getOption("dsvert.min_release_n", 1L)))
    if (is.numeric(privacy_min) && privacy_min > 0) {
      mask <- counts > 0L & counts < privacy_min
      small_margin <- any(row_margins > 0L & row_margins < privacy_min) ||
        any(col_margins > 0L & col_margins < privacy_min) ||
        (n > 0L && n < privacy_min)
      if ((any(mask) || small_margin) && fail_effective) {
        stop("Contingency table has a positive cell or margin below ",
             "datashield.privacyLevel; refusing to release counts",
             call. = FALSE)
      }
      counts[mask] <- 0L
      # F6: mask the level LABELS of any suppressed margin, so the exact
      # value domain of a (possibly continuous) column is not echoed.
      row_levels[row_margins > 0L & row_margins < privacy_min] <- "<suppressed>"
      col_levels[col_margins > 0L & col_margins < privacy_min] <- "<suppressed>"
      row_margins[row_margins > 0L & row_margins < privacy_min] <- 0L
      col_margins[col_margins > 0L & col_margins < privacy_min] <- 0L
      if (n < privacy_min) n <- 0L
    }
  }

  list(
    counts = counts,
    row_levels = row_levels,
    col_levels = col_levels,
    row_margins = row_margins,
    col_margins = col_margins,
    n = n,
    n_na = n_na,
    small_cell_policy = if (isTRUE(suppress_small_cells)) {
      if (isTRUE(fail_on_small_cells)) "fail" else "zero"
    } else {
      "none"
    }
  )
}
