test_that("fixed-rho staged GEE binds native cap scales and keeps legacy contracts", {
  for (family in c("binomial_gee", "poisson_gee")) {
    f <- .grouped_contract_fixture(family, "ar1")
    legacy <- .dsvert_dp_grouped_cross_spec(f$raw, f$policy, f$authenticated)
    expect_identical(legacy$numeric_contract$version, "grouped-fixed-profile-numeric-v1")
    expect_null(legacy$staged_numeric)
    raw <- f$raw
    raw$parameters$composition <- "staged_fixed_rho_v1"
    spec <- .dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated)
    expect_identical(spec$numeric_contract$version, "grouped-gee-fixed-rho-staged-numeric-v1")
    expect_identical(spec$numeric_contract$correlation_contract, "signed-analyst-fixed-rho-v1")
    expect_identical(spec$numeric_contract$working_correlation, list(
      rho_source = "analyst_specified_signed_parameter_v1",
      data_independent = TRUE, candidate_independent = TRUE, estimation = "none"))
    expect_equal(spec$numeric_contract$coordinate_error_bounds,
      legacy$numeric_contract$coordinate_error_bounds)
    native <- spec$staged_numeric
    expect_identical(native$RowLossCap, "1")
    expect_identical(native$RhoQ16, "16384")
    expect_identical(native$ScoreClipQ16, sprintf("%.0f", raw$parameters$score_clip*2^16))
    expect_equal(as.numeric(unlist(native$Caps)), vapply(spec$sensitivity$candidate_bounds,
      function(x) x$per_cluster_caps[[1L]], numeric(1L)))
    for (b in spec$sensitivity$candidate_bounds) {
      indices <- startsWith(unlist(b$coordinate_labels), "bread:")
      expect_true(all(unlist(b$per_cluster_caps)[indices] == 2*as.numeric(native$BreadCap)))
      expect_true(all(unlist(b$coordinate_shifts)[indices] == as.numeric(native$BreadCap)))
    }
    expect_equal(spec$sensitivity$raw_l1_sensitivity, sum(unlist(spec$sensitivity$per_cluster_caps)))
    expect_equal(spec$candidate_order, legacy$candidate_order)
    unsigned <- list(version = f$unsigned$version, spec = spec,
      artifact = .dsvert_dp_grouped_cross_artifact(spec))
    unsigned$source_contract <- .dsvert_dp_grouped_cross_source_contract(spec, unsigned$artifact)
    validate <- function(x) .dsvert_dp_grouped_cross_contract_validate(f$sign(x), f$policy, f$schema)
    expect_equal(validate(unsigned)$spec$staged_numeric[names(native)], native)
    for (field in c("BreadCap", "RowLossCap", "RhoQ16", "ScoreClipQ16", "MaxOutcome")) {
      changed <- unsigned; changed$spec$staged_numeric[[field]] <- "0"
      expect_error(validate(changed), class = "dsvert_dp_public_failure")
    }
    changed <- unsigned
    changed$spec$numeric_contract$certificate_sha256 <- strrep("0",64)
    expect_error(validate(changed), class = "dsvert_dp_public_failure")
    changed <- unsigned
    changed$spec$numeric_contract$working_correlation$data_independent <- FALSE
    expect_error(validate(changed), class = "dsvert_dp_public_failure")
    raw$parameters$composition <- "estimated_alpha"
    expect_error(.dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated),
      class = "dsvert_dp_public_failure")
  }
})

test_that("GEE n2000 descriptor is an explicit bounded measurement domain", {
  f <- .grouped_contract_fixture("poisson_gee")
  raw <- f$raw; raw$parameters$composition <- "staged_fixed_rho_v1"
  raw$grouping$cluster_capacity <- 500
  raw$grouping$max_patients_per_cluster <- 4
  policy <- f$policy; policy$unit_capacity <- 2000
  spec <- .dsvert_dp_grouped_cross_spec(raw, policy, f$authenticated)
  expect_identical(spec$grouping$capacity_profile, "poisson-gee-fixed-rho-n2000-c500-b4-p3-j4-v1")
  expect_equal(unlist(spec$sensitivity$maximum_coordinates),
    500*unlist(spec$sensitivity$per_cluster_caps))
  for (mutation in list(
      function(x) { x$parameters$composition <- NULL; x },
      function(x) { x$grouping$cluster_capacity <- 499; x },
      function(x) { x$grouping$max_patients_per_cluster <- 5; x },
      function(x) { x$beta_grid <- rep(x$beta_grid[1L], 5L); x })) {
    expect_error(.dsvert_dp_grouped_cross_spec(mutation(raw), policy, f$authenticated),
      class = "dsvert_dp_public_failure")
  }
})

test_that("fixed-rho sensitivity counts affected clusters, not cluster capacity", {
  for (family in c("binomial_gee", "poisson_gee")) {
    f <- .grouped_contract_fixture(family, "exchangeable")
    raw <- f$raw; raw$parameters$composition <- "staged_fixed_rho_v1"
    small <- .dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated)
    raw$grouping$cluster_capacity <- 500
    policy <- f$policy; policy$unit_capacity <- 2000
    large <- .dsvert_dp_grouped_cross_spec(raw, policy, f$authenticated)
    expect_equal(large$sensitivity$per_cluster_caps, small$sensitivity$per_cluster_caps)
    expect_equal(large$sensitivity$raw_l1_sensitivity, small$sensitivity$raw_l1_sensitivity)
    expect_equal(large$sensitivity$raw_l2_sensitivity, small$sensitivity$raw_l2_sensitivity)
    expect_equal(large$numeric_contract, small$numeric_contract)
    policy$adjacency <- "replace_one_fixed_cohort"
    replacement <- .dsvert_dp_grouped_cross_spec(raw, policy, f$authenticated)
    expect_equal(replacement$sensitivity$raw_l1_sensitivity, 2*large$sensitivity$raw_l1_sensitivity)
    expect_equal(replacement$sensitivity$raw_l2_sensitivity, 2*large$sensitivity$raw_l2_sensitivity)
    expect_equal(replacement$sensitivity$per_cluster_caps, large$sensitivity$per_cluster_caps)
  }
})

test_that("analyst fixed-rho parameters admit exactly the retained working correlations", {
  for (family in c("binomial_gee", "poisson_gee")) {
    for (correlation in c("independence", "exchangeable", "ar1")) {
      values <- if (correlation == "independence") 0 else c(0, .25, .5)
      for (rho in values) {
        parameters <- list(correlation = correlation, rho = rho, score_clip = 1,
          composition = "staged_fixed_rho_v1")
        expect_equal(.dsvert_dp_grouped_cross_parameters(parameters, family), parameters)
        for (mutation in list(
            function(x) { x$rho <- c(0, .25); x },
            function(x) { x$rho <- .125; x },
            function(x) { x$rho <- "estimated"; x },
            function(x) { x$estimator <- "private_moment"; x })) {
          expect_error(.dsvert_dp_grouped_cross_parameters(mutation(parameters), family),
            class = "dsvert_dp_public_failure")
        }
      }
    }
    expect_error(.dsvert_dp_grouped_cross_parameters(list(correlation = "independence",
      rho = .25, score_clip = 1, composition = "staged_fixed_rho_v1"), family),
      class = "dsvert_dp_public_failure")
  }
})
