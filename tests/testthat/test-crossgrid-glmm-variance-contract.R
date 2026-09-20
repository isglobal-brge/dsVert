test_that("binomial GH5 grids bind variance-major candidates and full patient sensitivity", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .grouped_contract_fixture("binomial_glmm", owners = owners)
    raw <- f$raw
    raw$beta_grid <- raw$beta_grid[1:2]
    raw$parameters <- list(variance_grid = list(0, .25), quadrature = "gh5_fixed_v1")
    spec <- .dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated)
    count <- length(spec$beta_grid)
    expect_length(spec$candidate_grid, 2 * count)
    expect_equal(vapply(spec$candidate_grid, `[[`, numeric(1L), "variance_index"),
      rep(1:2, each = count))
    expect_equal(vapply(spec$candidate_grid, `[[`, numeric(1L), "beta_index"),
      rep(seq_len(count), 2))
    expected_caps <- unlist(lapply(c(0, .25), function(tau) {
      fixed <- raw
      fixed$parameters <- list(random_intercept_variance = tau, quadrature = "gh5_fixed_v1")
      .dsvert_dp_grouped_cross_spec(fixed, f$policy, f$authenticated)$sensitivity$per_cluster_caps
    }), use.names = FALSE)
    caps <- unlist(spec$sensitivity$per_cluster_caps, use.names = FALSE)
    expect_equal(caps, expected_caps)
    expect_equal(spec$sensitivity$raw_l1_sensitivity, sum(caps))
    expect_equal(spec$sensitivity$raw_l2_sensitivity, sqrt(sum(caps^2)))
    expect_equal(unlist(spec$sensitivity$maximum_coordinates), spec$grouping$cluster_capacity*caps)
    replacement <- .dsvert_dp_grouped_cross_sensitivity(spec$beta_grid, spec$family,
      spec$max_outcome, spec$numeric_grid_bits, spec$grouping, spec$parameters,
      "replace_one_fixed_cohort", spec$numeric_contract)
    expect_equal(replacement$raw_l1_sensitivity, 2*sum(caps))
    expect_equal(replacement$raw_l2_sensitivity, 2*sqrt(sum(caps^2)))
    expect_identical(spec$numeric_contract$profile_sha256,
      "f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84")
    expect_identical(spec$numeric_contract$certificate_sha256,
      "76490f13d69f7968b5fa435f1ac7b5da844b8f7476ad582669b4e41a95960377")
    expect_lt(spec$numeric_contract$composition_error_bound, 1)
    expect_false(spec$numeric_contract$quadrature_error_included)
    artifact <- .dsvert_dp_grouped_cross_artifact(spec)
    expect_equal(artifact$coordinate_count, length(caps))
    source <- .dsvert_dp_grouped_cross_source_contract(spec, artifact)
    outcome <- source$private_layout$blocks[[length(spec$predictor_order)+1L]]
    expect_equal(outcome$value_fraction_bits, 0)
    expect_false(identical(spec$outcome$owner_peer, spec$grouping$owner_peer))
    unsigned <- list(version = f$unsigned$version, spec = spec, artifact = artifact,
      source_contract = source)
    validate <- function(x) .dsvert_dp_grouped_cross_contract_validate(f$sign(x), f$policy, f$schema)
    expect_equal(vapply(validate(unsigned)$spec$candidate_grid, `[[`, numeric(1L),
      "variance_index"), rep(1:2, each = count))
    for (mutate in list(
      function(x) { x$spec$candidate_order <- rev(x$spec$candidate_order); x },
      function(x) { x$spec$candidate_grid[[1]]$variance_index <- 2; x },
      function(x) { x$spec$candidate_grid <- x$spec$candidate_grid[-1]; x },
      function(x) { x$artifact$coordinate_count <- count; x },
      function(x) { x$spec$numeric_contract$certificate_sha256 <- strrep("0", 64); x },
      function(x) { x$spec$numeric_contract$composition_error_bound <- 0; x },
      function(x) { x$spec$sensitivity$per_cluster_caps[[1]] <- 1; x },
      function(x) { x$spec$sensitivity$maximum_coordinates[[1]] <- 1; x },
      function(x) { x$spec$sensitivity$raw_l1_sensitivity <- 1; x },
      function(x) { x$spec$sensitivity$raw_l2_sensitivity <- 1; x })) {
      expect_error(validate(mutate(unsigned)), class = "dsvert_dp_public_failure")
    }
  }
})

test_that("binomial GH5 variance grids reject ambiguous or uncertified values", {
  f <- .grouped_contract_fixture("binomial_glmm")
  for (grid in list(list(), list(.25, 0), list(0, 0), list(.125), c(0, .25),
      list(a = 0), list(NA_real_), list(Inf), list("0"), list(list(0)))) {
    raw <- f$raw
    raw$parameters <- list(variance_grid = grid, quadrature = "gh5_fixed_v1")
    expect_error(.dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated),
      class = "dsvert_dp_public_failure")
  }
  for (tau in c(0, .25)) {
    raw <- f$raw
    raw$parameters <- list(variance_grid = list(tau), quadrature = "gh5_fixed_v1")
    spec <- .dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated)
    expect_length(spec$candidate_grid, length(spec$beta_grid))
  }
  for (parameters in list(
      list(variance_grid = list(0), random_intercept_variance = 0, quadrature = "gh5_fixed_v1"),
      list(variance_grid = list(0), quadrature = "adaptive"))) {
    raw <- f$raw; raw$parameters <- parameters
    expect_error(.dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated),
      class = "dsvert_dp_public_failure")
  }
  numeric <- .dsvert_dp_grouped_cross_numeric("binomial_glmm",
    list(max_patients_per_cluster = 16), list(variance_grid = list(0, .25)))
  expect_lt(numeric$composition_error_bound, .012)
})

test_that("binomial GH5 C500 admission stays inside the named measurement domain", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .grouped_contract_fixture("binomial_glmm", owners = owners)
    raw <- f$raw
    raw$parameters <- list(variance_grid = list(0, .25), quadrature = "gh5_fixed_v1")
    raw$beta_grid <- raw$beta_grid[1:2]
    raw$grouping$cluster_capacity <- 500
    policy <- f$policy; policy$unit_capacity <- 2000
    spec <- .dsvert_dp_grouped_cross_spec(raw, policy, f$authenticated)
    expect_identical(spec$grouping$capacity_profile, "binomial-glmm-gh5-n2000-c500-b4-p3-j4-v1")
    expect_length(spec$candidate_grid, 4)
    expect_length(spec$participating_peers, owners)
    for (mutate in list(
      function(x) { x$grouping$cluster_capacity <- 499; x },
      function(x) { x$grouping$cluster_capacity <- 501; x },
      function(x) { x$grouping$max_patients_per_cluster <- 5; x },
      function(x) { x$parameters <- f$raw$parameters; x })) {
      expect_error(.dsvert_dp_grouped_cross_spec(mutate(raw), policy, f$authenticated),
        class = "dsvert_dp_public_failure")
    }
    policy$unit_capacity <- 1999
    expect_error(.dsvert_dp_grouped_cross_spec(raw, policy, f$authenticated),
      class = "dsvert_dp_public_failure")
  }
})


test_that("new binomial variance-grid contracts reject p4 and J5 before execution", {
  f <- .grouped_contract_fixture("binomial_glmm", owners = 5L)
  raw <- f$raw
  raw$parameters <- list(variance_grid = list(0), quadrature = "gh5_fixed_v1")
  raw$beta_grid <- lapply(c(-.5, -.25, 0, .25, .5), function(intercept) c(intercept, rep(0, 3)))
  raw$beta_grid <- raw$beta_grid[order(vapply(raw$beta_grid,
    .dsvert_dp_canonical_json, character(1L)), method = "radix")]
  admitted <- raw; admitted$beta_grid <- raw$beta_grid[1:4]
  expect_length(.dsvert_dp_grouped_cross_spec(admitted, f$policy, f$authenticated)$candidate_grid, 4)
  expect_error(.dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated),
    class = "dsvert_dp_public_failure")
  admitted$parameters$variance_grid <- list(0, .25)
  admitted$beta_grid <- raw$beta_grid[1:2]
  expect_length(.dsvert_dp_grouped_cross_spec(admitted, f$policy, f$authenticated)$candidate_grid, 4)
  admitted$beta_grid <- raw$beta_grid[1:3]
  expect_error(.dsvert_dp_grouped_cross_spec(admitted, f$policy, f$authenticated),
    class = "dsvert_dp_public_failure")
  rounded <- raw; rounded$beta_grid <- list(c(.01, .03, .15, .81))
  expect_error(.dsvert_dp_grouped_cross_spec(rounded, f$policy, f$authenticated),
    class = "dsvert_dp_public_failure")
  rounded$beta_grid[[1]][4] <- .81 - 2^-50
  expect_length(.dsvert_dp_grouped_cross_spec(rounded, f$policy, f$authenticated)$candidate_grid, 1)
  schema <- f$authenticated
  columns <- schema$unsigned$datasets[[raw$dataset]]$columns
  descriptor <- columns[[sub("^[^$]+\\$", "", raw$predictor_order[[1L]])]]
  schema$unsigned$datasets[[raw$dataset]]$columns$extra <- descriptor
  raw$predictor_order <- sort(c(raw$predictor_order, paste0(descriptor$owner_peer, "$extra")),
    method = "radix")
  raw$beta_grid <- list(rep(0, 5))
  fixed <- raw; fixed$parameters <- f$raw$parameters
  expect_length(.dsvert_dp_grouped_cross_spec(fixed, f$policy, schema)$predictors, 4)
  expect_error(.dsvert_dp_grouped_cross_spec(raw, f$policy, schema),
    class = "dsvert_dp_public_failure")
})
