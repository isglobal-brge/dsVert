# Signed ML covariance grids reuse the fixed-covariance exact statistic. These
# public descriptors alone grant no source read or release capability.
.dsvert_dp_grouped_cross_ml_parameters <- function(value) {
  .dsvert_dp_glm_grid_cross_fields(value, c("objective", "variance_grid"))
  if (!identical(value$objective, "ml") || !is.list(value$variance_grid) ||
      !is.null(names(value$variance_grid)) || !length(value$variance_grid) ||
      length(value$variance_grid) > 256L) .dsvert_dp_grouped_cross_fail()
  grid <- lapply(value$variance_grid, function(pair) {
    .dsvert_dp_glm_grid_cross_fields(pair, c("residual_variance", "random_intercept_variance"))
    .dsvert_dp_grouped_cross_parameters(pair, "lmm")
  })
  sigma <- vapply(grid, `[[`, numeric(1L), "residual_variance")
  tau <- vapply(grid, `[[`, numeric(1L), "random_intercept_variance")
  if (!identical(order(sigma, tau, method = "radix"), seq_along(grid)) ||
      anyDuplicated(paste(sigma * 2^16, tau * 2^16, sep = ":"))) {
    .dsvert_dp_grouped_cross_fail()
  }
  list(objective = "ml", variance_grid = grid)
}

.dsvert_dp_grouped_cross_ml_numeric <- function(grouping, parameters) {
  out <- .dsvert_dp_grouped_cross_numeric("lmm", grouping,
    parameters$variance_grid[[1L]])
  path <- system.file("certificates", "grouped_lmm_ml_v1.json", package = "dsVert")
  certificate <- "6c6f0c3f5413396494de455f8d240753d9f72256f3f09dbf931752c57855033e"
  if (!nzchar(path) || !identical(digest::digest(file = path, algo = "sha256"), certificate)) {
    .dsvert_dp_grouped_cross_fail()
  }
  out$profile_sha256 <- certificate
  out$certificate_sha256 <- certificate
  out$version <- "grouped-ml-grid-numeric-v1"
  out$profile <- "grouped-lmm-ml-variance-f264-q64-log-up-v1"
  out$objective <- "twice_gaussian_ml_without_n_log_2pi_plus_n_log_4_v1"
  out$candidate_traversal <- "variance_then_beta_v1"
  out$logdet_profile <- "exact_rational_atanh_enclosure_upper_ceiling_q64_v1"
  out$logdet_count <- "private_live_count_lookup_v1"
  out$logdet_fraction_bits <- 64
  out$logdet_addition <- "exact_f264_before_cluster_clamp_and_quantization_v1"
  out$logdet_shift_upper_bound <- 12 * grouping$max_patients_per_cluster
  out$full_likelihood_value <- FALSE
  out
}

.dsvert_dp_grouped_cross_ml_sensitivity <- function(beta_grid, grid_bits,
    grouping, parameters, adjacency, numeric_contract) {
  scale <- 2^grid_bits
  # For n>0 the shifted determinant is
  # (n-1)log(4*sigma2)+log(4*(sigma2+n*tau2)); for n=0 it is zero.
  # sigma2>=1/4 makes it nonnegative. B<=16 and sigma2,tau2<=16 give
  # 4*(sigma2+B*tau2)<=1088<2^12, and log(2)<1, hence it is <12*B.
  log_cap <- 12 * grouping$max_patients_per_cluster * scale
  bounds <- unlist(lapply(parameters$variance_grid, function(pair) {
    fixed <- .dsvert_dp_grouped_cross_sensitivity(beta_grid, "lmm", 1,
      grid_bits, grouping, pair, adjacency, numeric_contract)
    lapply(fixed$candidate_bounds, function(bound) {
      bound$per_cluster_caps <- lapply(bound$per_cluster_caps, function(cap) cap + log_cap)
      bound$shifted_logdet_upper_bound <- 12 * grouping$max_patients_per_cluster
      bound
    })
  }), recursive = FALSE)
  caps <- unlist(lapply(bounds, `[[`, "per_cluster_caps"), use.names = FALSE)
  multiplier <- if (identical(adjacency, "add_remove_patient")) 1 else 2
  maxima <- grouping$cluster_capacity * caps
  l1 <- multiplier * sum(caps)
  l2 <- multiplier * sqrt(sum(caps^2)) * (1 + 32 * .Machine$double.eps)
  if (any(!is.finite(c(caps, maxima, l1, l2))) ||
      any(c(caps, maxima, l1, l2) > 2^53-1)) .dsvert_dp_grouped_cross_fail()
  list(dp_unit = "patient", influence_proof = "one_affected_cluster_range_v1",
    candidate_bounds = bounds, per_cluster_caps = as.list(caps),
    maximum_coordinates = as.list(maxima), adjacency_multiplier = multiplier,
    raw_l1_sensitivity = l1, raw_l2_sensitivity = l2,
    natural_l1_sensitivity = l1/scale, natural_l2_sensitivity = l2/scale)
}
