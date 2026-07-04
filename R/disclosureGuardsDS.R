.dsvert_guard_matrix_release <- function(n_obs, p,
                                          what = "aggregate matrix") {
  n_obs <- as.integer(n_obs)
  p <- as.integer(p)
  if (!is.finite(n_obs) || n_obs < 1L || !is.finite(p) || p < 1L) {
    stop("invalid dimensions for ", what, " disclosure guard",
         call. = FALSE)
  }
  min_n <- as.integer(getOption(
    "dsvert.min_aggregate_n",
    getOption("datashield.privacyLevel", 5L)))
  min_n_per_variable <- as.numeric(getOption(
    "dsvert.min_n_per_released_variable", 5))
  max_p_over_n <- as.numeric(getOption("dsvert.max_p_over_n", 0.2))
  allow_high_dim <- isTRUE(getOption("dsvert.allow_high_dim_aggregates",
                                     FALSE))

  required_n <- max(min_n, ceiling(min_n_per_variable * p))
  p_over_n <- p / n_obs
  if (!allow_high_dim &&
      (n_obs < required_n || p_over_n > max_p_over_n)) {
    stop(sprintf(
      paste0(
        "%s release blocked by disclosure guard: n=%d, p=%d, p/n=%.3f. ",
        "Require n >= max(%d, %.1f*p) and p/n <= %.3f. ",
        "Set options(dsvert.allow_high_dim_aggregates=TRUE) only for ",
        "controlled diagnostics."
      ),
      what, n_obs, p, p_over_n, min_n, min_n_per_variable, max_p_over_n),
      call. = FALSE)
  }
  list(
    n_obs = n_obs,
    p = p,
    p_over_n = p_over_n,
    min_n = min_n,
    min_n_per_variable = min_n_per_variable,
    max_p_over_n = max_p_over_n,
    allow_high_dim = allow_high_dim)
}

.dsvert_cluster_min_size <- function() {
  as_single_int <- function(value, default) {
    out <- suppressWarnings(as.integer(value[[1L]]))
    if (length(out) != 1L || is.na(out)) default else out
  }
  privacy_min <- as_single_int(
    getOption("datashield.privacyLevel", 5L), 5L)
  cluster_min <- as_single_int(
    getOption("dsvert.min_cluster_size", privacy_min), privacy_min)
  # Hard floor of 3: per-cluster aggregates (sum, sum-of-squares, ...) on a
  # size-2 cluster form a determined system that inverts to both members'
  # values. Requiring >= 3 keeps the released aggregates underdetermined
  # regardless of a lowered datashield.privacyLevel.
  max(3L, privacy_min, cluster_min)
}

.dsvert_guard_cluster_sizes <- function(sizes,
                                        what = "per-cluster aggregate") {
  sizes <- as.integer(sizes)
  if (length(sizes) == 0L || anyNA(sizes) || any(sizes < 0L)) {
    stop("invalid cluster sizes for ", what, call. = FALSE)
  }
  min_size <- .dsvert_cluster_min_size()
  if (min_size > 1L && any(sizes > 0L & sizes < min_size)) {
    stop(
      "cluster size below datashield.privacyLevel/dsvert.min_cluster_size ",
      "for ", what, " (min ", min_size, ")",
      call. = FALSE)
  }
  invisible(min_size)
}

# Minimum number of per-observation contributions a released share-sum is
# permitted to fold together. Additive share-sums are revealed by combining
# both parties' outputs; a sum over a single observation IS that observation's
# plaintext value, so any slice/reshape that drives the aggregation size to
# one lets a caller isolate an individual record. The slicing primitives
# (single-column extraction, strided per-index sum) determine this granularity:
# extraction retains `n` rows and a strided sum folds `n_obs` rows per output
# index. Requiring both to meet the per-cluster underdetermination floor keeps
# every released aggregate spanning enough records that no single contribution
# is recoverable. Legitimate gradient/moment/bin sums always slice the full
# aligned sample, so they clear the floor; a degenerate one-observation slice
# does not.
.dsvert_guard_min_agg_count <- function(count, what = "share-sum aggregate") {
  count <- suppressWarnings(as.integer(count))
  if (length(count) != 1L || is.na(count) || count < 0L) {
    stop("invalid aggregation size for ", what, call. = FALSE)
  }
  min_n <- .dsvert_cluster_min_size()
  if (count < min_n) {
    stop("aggregation size ", count, " below the minimum releasable ",
         "aggregation floor for ", what, " (min ", min_n,
         "; single-observation isolation guard)", call. = FALSE)
  }
  invisible(min_n)
}
