test_that("grouped five-family contracts require both authentic signatures", {
  for (family in .DSVERT_DP_GROUPED_CROSS_FAMILIES) {
    fixture <- .grouped_contract_fixture(family)
    validate <- function(x) .dsvert_dp_grouped_cross_contract_validate(
      x, fixture$policy, fixture$schema)
    result <- validate(fixture$contract)
    expect_identical(result$spec$family, family)
    expect_identical(result$artifact$implementation_state, "cross_owner_exact_gc_materialized")
    expect_identical(result$artifact$cross_owner_state, "exact_gc_to_joint_dp_vector_v1")
    expect_identical(result$spec$sensitivity$dp_unit, "patient")
    roundtrip <- jsonlite::fromJSON(.dsvert_dp_canonical_json(result), simplifyVector = FALSE)
    expect_identical(validate(roundtrip), result)
    missing <- fixture$contract
    missing$signatures$peer_b <- NULL
    expect_error(validate(missing), class = "dsvert_dp_public_failure")
    forged <- fixture$contract
    forged$signatures$peer_b <- forged$signatures$peer_a
    expect_error(validate(forged), class = "dsvert_dp_public_failure")
  }
})

test_that("signed altered derived grouped fields fail with one public error", {
  fixture <- .grouped_contract_fixture("binomial_gee", "ar1")
  mutations <- list(
    function(x) { x$spec$numeric_contract$per_cluster_error_bound <- 0; x },
    function(x) { x$spec$grouping$ordering <- "repack_on_deletion"; x },
    function(x) { x$spec$grouping$patient_rule <- "each_row"; x },
    function(x) { x$spec$sensitivity$dp_unit <- "cluster"; x },
    function(x) { x$spec$sensitivity$raw_l1_sensitivity <- 1; x },
    function(x) { x$artifact$transcript$cluster_batch_size <- 2; x },
    function(x) { x$artifact$result_evidence_required <- FALSE; x },
    function(x) { x$source_contract$private_layout$grouping_controls$private_control_bits <- FALSE; x },
    function(x) { x$spec$extra <- TRUE; x },
    function(x) { x$spec$beta_grid <- rev(x$spec$beta_grid); x })
  for (mutation in mutations) {
    error <- tryCatch(.dsvert_dp_grouped_cross_contract_validate(
      fixture$sign(mutation(fixture$unsigned)), fixture$policy, fixture$schema), error = identity)
    expect_s3_class(error, "dsvert_dp_public_failure")
    expect_identical(conditionMessage(error), .DSVERT_DP_PUBLIC_FAILURE_MESSAGE)
  }
})

test_that("grouped public numeric and capacity domains fail closed", {
  for (family in .DSVERT_DP_GROUPED_CROSS_FAMILIES) {
    fixture <- .grouped_contract_fixture(family)
    raw <- fixture$raw
    raw$grouping$max_patients_per_cluster <- 0
    expect_error(.dsvert_dp_grouped_cross_spec(raw, fixture$policy, fixture$authenticated),
                 class = "dsvert_dp_public_failure")
    raw <- fixture$raw
    raw$grouping$cluster_capacity <- 1
    expect_error(.dsvert_dp_grouped_cross_spec(raw, fixture$policy, fixture$authenticated),
                 class = "dsvert_dp_public_failure")
    raw <- fixture$raw
    raw$parameters$unknown <- TRUE
    expect_error(.dsvert_dp_grouped_cross_spec(raw, fixture$policy, fixture$authenticated),
                 class = "dsvert_dp_public_failure")
    if (grepl("_glmm$", family)) {
      raw <- fixture$raw
      raw$beta_grid <- list(c(0, 1.01))
      expect_error(.dsvert_dp_grouped_cross_spec(raw, fixture$policy, fixture$authenticated),
                   class = "dsvert_dp_public_failure")
    }
  }
})

test_that("patient add/remove and movement sensitivities use whole cluster caps", {
  for (family in .DSVERT_DP_GROUPED_CROSS_FAMILIES) {
    fixture <- .grouped_contract_fixture(family)
    spec <- fixture$contract$spec
    caps <- unlist(spec$sensitivity$per_cluster_caps)
    expect_equal(spec$sensitivity$raw_l1_sensitivity, sum(caps))
    expect_equal(spec$sensitivity$raw_l2_sensitivity, sqrt(sum(caps^2)))
    expect_equal(unlist(spec$sensitivity$maximum_coordinates), 2*caps)
    policy <- fixture$policy
    policy$adjacency <- "replace_one_fixed_cohort"
    replacement <- .dsvert_dp_grouped_cross_spec(fixture$raw, policy, fixture$authenticated)
    expect_equal(replacement$sensitivity$raw_l1_sensitivity, 2*sum(caps))
    expect_equal(replacement$sensitivity$raw_l2_sensitivity, 2*sqrt(sum(caps^2)))
    expect_equal(replacement$sensitivity$dp_unit, "patient")
  }
})

test_that("GEE contract retains likelihood bread meat and signed correlation shifts", {
  for (correlation in c("independence", "exchangeable", "ar1")) {
    fixture <- .grouped_contract_fixture("poisson_gee", correlation)
    artifact <- fixture$contract$artifact
    expect_equal(artifact$coordinate_count, 3*(1+3+3))
    bounds <- fixture$contract$spec$sensitivity$candidate_bounds[[1]]
    expect_identical(unlist(bounds$coordinate_labels),
      c("likelihood", "bread:1:1", "bread:1:2", "bread:2:2", "meat:1:1", "meat:1:2", "meat:2:2"))
    shifts <- unlist(bounds$coordinate_shifts)
    expect_true(all(shifts[2:4] == 0) == (correlation == "independence"))
    expect_equal(shifts[5:7], rep(65536, 3))
  }
})

test_that("grouped registration cannot authorize a protected producer", {
  registration <- .dsvert_register_grouped_cross()
  expect_length(registration$versions, 5)
  expect_false(registration$production_enabled)
  expect_error(registration$materialize(list(production_enabled = TRUE)),
               class = "dsvert_dp_public_failure")
  fixture <- .grouped_contract_fixture("lmm")
  layout <- fixture$contract$source_contract$private_layout
  expect_equal(layout$blocks[[2]]$value_fraction_bits, 50)
  expect_true(layout$grouping_controls$authenticated_private_sidecar_required)
  expect_equal(layout$release_coordinate_count, 3)
})
