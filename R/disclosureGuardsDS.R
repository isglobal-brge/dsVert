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
