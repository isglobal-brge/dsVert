#' @title Server-side histogram bucket counts (aggregate)
#' @description Compute per-bucket counts of a numeric variable server-side and
#'   return the aggregate count vector. This is the foundation primitive for
#'   approximate quantile / median estimation, chi-square across continuous
#'   variables after binning, and LASSO cross-validation diagnostics.
#'
#' @param data_name Character. Name of the server-side data frame.
#' @param variable Character. Name of the numeric column to bucketise.
#' @param edges Numeric vector (length K+1, strictly increasing). Defines the
#'   K buckets \code{[edges[1], edges[2]), ..., [edges[K], edges[K+1]]}
#'   (the last bucket is right-closed).
#' @param suppress_small_cells Logical. If TRUE (default) cells with positive
#'   count below the DataSHIELD privacy threshold
#'   (\code{datashield.privacyLevel}) fail closed by default. Set
#'   \code{fail_on_small_cells = FALSE} only for legacy diagnostics to return
#'   suppressed zeros instead.
#' @param fail_on_small_cells Logical. Stop instead of returning a histogram
#'   if any positive bucket/underflow/overflow count is below the privacy
#'   threshold.
#'
#' @return A list with elements
#'   \itemize{
#'     \item \code{counts}: length-K integer vector of per-bucket counts
#'     \item \code{below}: number of observations strictly below the
#'       lowest edge \code{edges[1]}
#'     \item \code{above}: number of observations strictly above the
#'       highest edge \code{edges[K+1]}
#'     \item \code{n_total}: number of non-missing observations
#'     \item \code{n_na}: number of missing observations
#'     \item \code{edges}: the edges vector (echoed for client-side reproducibility)
#'   }
#'
#' @details Bucket counts are aggregates: they carry no information about any
#'   individual observation beyond membership in a bucket of size \eqn{\ge}
#'   \code{datashield.privacyLevel}. Downstream helpers on the client side
#'   (\code{ds.vertDesc}) combine per-server counts into cohort-wide quantile
#'   and histogram summaries without ever reconstructing a per-patient value.
#'
#' @seealso \code{getObsCountDS}
#' @export
dsvertHistogramDS <- function(
    data_name, variable, edges,
    suppress_small_cells = TRUE,
    fail_on_small_cells = getOption("dsvert.fail_on_small_cells", TRUE)) {
  # --- Validate inputs --------------------------------------------------
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(variable) || length(variable) != 1) {
    stop("variable must be a single character string", call. = FALSE)
  }
  if (!is.numeric(edges) || length(edges) < 2) {
    stop("edges must be a numeric vector of length >= 2", call. = FALSE)
  }
  if (is.unsorted(edges, strictly = TRUE)) {
    stop("edges must be strictly increasing", call. = FALSE)
  }
  # F9: bound the number of analyst-chosen bins. Very fine, analyst-controlled
  # edges let an attacker read an exact empirical CDF and difference sliding
  # two-bucket queries to recover interior order statistics down to 1 record.
  # Cap the bin count (custodian-tunable). The full defence against un-budgeted
  # exact-count reconstruction is the output-DP / query-budget layer.
  max_bins <- as.integer(getOption("dsvert.histogram_max_bins", 1000L))
  if (is.finite(max_bins) && (length(edges) - 1L) > max_bins) {
    stop("histogram requested ", length(edges) - 1L, " bins > ",
         "dsvert.histogram_max_bins (", max_bins, "); refusing (F9: limits ",
         "CDF/order-statistic reconstruction from fine analyst-chosen edges)",
         call. = FALSE)
  }

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!variable %in% names(data)) {
    stop("Variable '", variable, "' not found in data frame '",
         data_name, "'", call. = FALSE)
  }

  raw <- data[[variable]]
  if (!is.numeric(raw)) {
    stop("Variable '", variable,
         "' must be numeric for histogram bucketing", call. = FALSE)
  }

  n_na <- sum(is.na(raw))
  x <- raw[!is.na(raw)]

  # --- Bucket assignment ------------------------------------------------
  K <- length(edges) - 1L
  # findInterval returns 0 for x < edges[1], K+1 for x > edges[K+1].
  # rightmost.closed = TRUE ensures x == edges[K+1] falls into bucket K.
  idx <- findInterval(x, edges, rightmost.closed = TRUE)
  counts <- as.integer(tabulate(idx, nbins = K))
  below <- sum(idx == 0L)
  above <- sum(idx > K)

  # --- Disclosure control (SERVER-AUTHORITATIVE, F3) --------------------
  # A client argument may only make suppression STRICTER, never looser: it is
  # applied unless the CUSTODIAN option explicitly permits an unsuppressed /
  # silent release. So an analyst passing suppress_small_cells=FALSE or
  # fail_on_small_cells=FALSE cannot loosen the control.
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
      small_tail <- (below > 0L && below < privacy_min) ||
        (above > 0L && above < privacy_min)
      if ((any(mask) || small_tail) && fail_effective) {
        stop("Histogram has a positive bucket/tail count below ",
             "datashield.privacyLevel; refusing to release counts",
             call. = FALSE)
      }
      counts[mask] <- 0L
      if (below > 0L && below < privacy_min) below <- 0L
      if (above > 0L && above < privacy_min) above <- 0L
    }
  }

  list(
    counts = counts,
    below = below,
    above = above,
    n_total = length(x),
    n_na = n_na,
    edges = edges,
    small_cell_policy = if (isTRUE(suppress_small_cells)) {
      if (isTRUE(fail_on_small_cells)) "fail" else "zero"
    } else {
      "none"
    }
  )
}
