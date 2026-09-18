test_that("LASSO signed extensions authenticate two-owner base grids", {
  for (family in c("binomial", "poisson")) {
    fixture <- .lasso_cross_fixture(family)
    validated <- .dsvert_dp_lasso_cross_contract_validate(fixture$contract,
      fixture$policy, fixture$schema, fixture$base_contract)
    expect_identical(validated$spec$version, "lasso_grid_cross_v1")
    expect_identical(validated$spec$family, family)
    expect_equal(unlist(validated$spec$base_coordinate_index), c(1, 2, 1, 2))
    expect_equal(unlist(validated$spec$public_penalty_raw), c(0, 1024, 0, 0))
    expect_no_error(.dsvert_dp_glm_grid_cross_equal(
      validated$spec$base$sensitivity, fixture$base$sensitivity))
    expect_false(validated$spec$penalty_requires_mpc)
    expect_equal(validated$spec$additional_raw_l1_sensitivity, 0)
    expect_equal(validated$spec$additional_raw_l2_sensitivity, 0)
  }
})

test_that("LASSO signatures bind all penalties and preserve base sensitivity", {
  fixture <- .lasso_cross_fixture()
  mutate <- list(
    function(x) { x$spec$public_penalty_raw[[2]] <- 0; x },
    function(x) { x$spec$base$sensitivity$raw_l1_sensitivity <- 0; x },
    function(x) { x$spec$base$base_contract_sha256 <- strrep("0", 64); x },
    function(x) { x$spec$base_coordinate_index[[2]] <- 1; x },
    function(x) { x$spec$penalty_requires_mpc <- TRUE; x },
    function(x) { x$spec$result_evidence_required <- FALSE; x },
    function(x) { x$spec$base$observation_capacity <- 1; x })
  for (change in mutate) {
    bad <- fixture$sign(change(fixture$contract))
    expect_error(.dsvert_dp_lasso_cross_contract_validate(bad,
      fixture$policy, fixture$schema, fixture$base_contract),
      class = "dsvert_dp_public_failure")
  }
  missing <- fixture$contract
  missing$signatures$peer_b <- NULL
  expect_error(.dsvert_dp_lasso_cross_contract_validate(missing,
    fixture$policy, fixture$schema, fixture$base_contract),
    class = "dsvert_dp_public_failure")
  missing_base <- fixture$base_contract
  missing_base$signatures$peer_b <- NULL
  expect_error(.dsvert_dp_lasso_cross_contract_validate(fixture$contract,
    fixture$policy, fixture$schema, missing_base), class = "dsvert_dp_public_failure")
})

test_that("public L1 rational ceiling is exact at integer and subnormal boundaries", {
  for (g in c(8, 16, 18)) {
    expect_equal(.dsvert_dp_lasso_cross_penalty(c(8, 1, 0), 0.5, 7, g), 7 * 2^(g - 1))
    expect_equal(.dsvert_dp_lasso_cross_penalty(c(-8, 1, 0), 0.5, 7, g), 7 * 2^(g - 1))
    expect_equal(.dsvert_dp_lasso_cross_penalty(c(0, 1, 2^-100), 1, 1, g), 2^g + 1)
    expect_equal(.dsvert_dp_lasso_cross_penalty(c(0, 1 - 2^-52), 1, 1, g), 2^g)
    expect_equal(.dsvert_dp_lasso_cross_penalty(c(8, 2^-1074), 2^-1074, 1, g), 1)
    expect_equal(.dsvert_dp_lasso_cross_penalty(c(8, 0), 8, 2^31 - 1, g), 0)
    expect_equal(.dsvert_dp_lasso_cross_penalty(c(8, -2, 1), 0, 7, g), 0)
  }
  expect_error(.dsvert_dp_lasso_cross_penalty(c(0, 8, 8), 8, 2^31 - 1, 18),
    class = "dsvert_dp_public_failure")
})

test_that("malformed signed LASSO candidate plans fail closed", {
  fixture <- .lasso_cross_fixture()
  changes <- list(
    function(x) { x$candidate_grid[[1]]$lambda <- -1; x },
    function(x) { x$candidate_grid[[1]]$lambda <- 8.01; x },
    function(x) { x$candidate_grid[[1]]$lambda <- list(1); x },
    function(x) { x$candidate_grid[[1]]$beta <- c(8, 8, 2^-100); x },
    function(x) { x$candidate_grid[[1]]$beta <- c(1, 2); x },
    function(x) { x$candidate_grid[[1]]$beta <- c(0, 2, 0); x },
    function(x) { x$candidate_grid <- rev(x$candidate_grid); x },
    function(x) { x$candidate_grid[[2]] <- x$candidate_grid[[1]]; x },
    function(x) { x$candidate_grid[[1]]$unknown <- TRUE; x },
    function(x) { x$unknown <- TRUE; x })
  for (change in changes) expect_error(.dsvert_dp_lasso_cross_spec(
    change(fixture$raw), fixture$base), class = "dsvert_dp_public_failure")
})

test_that("public L1 postprocessing selects signed paths without changing loss releases", {
  fixture <- .lasso_cross_fixture()
  coordinates <- c(1024, 256)
  original <- coordinates
  result <- .dsvert_dp_lasso_cross_postprocess(coordinates, fixture$spec)
  expect_identical(coordinates, original)
  expect_identical(result$selected_candidates, c(1L, 4L))
  expect_equal(result$selected_objectives, c(0.5, 0.125))
  expect_equal(result$additional_privacy_cost, c(epsilon = 0, delta = 0))
  expect_null(result$standard_errors)
  expect_identical(.dsvert_dp_lasso_cross_postprocess(coordinates, fixture$spec), result)
  for (bad in list(c(NA, 0), c(1, Inf), c(1), c(0, 2^53), c(0, 0.25))) {
    expect_error(.dsvert_dp_lasso_cross_postprocess(bad, fixture$spec),
      class = "dsvert_dp_public_failure")
  }
})

test_that("Gaussian LASSO uses half RSS from the existing sufficient-statistic route", {
  fixture <- .lasso_cross_fixture("gaussian", capacity = 8, bits = 8)
  x <- cbind(1, c(0, 1, 0, 1), c(0, 0, 1, 1))
  y <- x[, 2]
  gram <- crossprod(x)
  moments <- 256 * c(nrow(x), gram[upper.tri(gram, diag = TRUE)], crossprod(x, y), sum(y^2))
  result <- .dsvert_dp_lasso_cross_postprocess(moments, fixture$spec)
  expected <- vapply(fixture$spec$candidate_grid, function(candidate) {
    beta <- unlist(candidate$beta)
    0.5 * sum((y - as.vector(x %*% beta))^2) / 8 + candidate$lambda * sum(abs(beta[-1L]))
  }, numeric(1L))
  expect_equal(result$selected_objectives, expected[c(1, 4)])
  expect_identical(result$selected_candidates, c(1L, 4L))
  moments[1L] <- 0
  expect_identical(.dsvert_dp_lasso_cross_postprocess(moments, fixture$spec), result)
  expect_equal(fixture$spec$base$sensitivity$raw_l1_sensitivity, 11 * 256)
  expect_null(fixture$spec$base_coordinate_index)
  expect_identical(fixture$spec$base$release_kind, "gaussian_cross_sufficient_statistics_v1")
  expect_error(.dsvert_dp_lasso_cross_contract_validate(fixture$contract,
    fixture$policy, fixture$schema, fixture$base_contract), class = "dsvert_dp_public_failure")
})

test_that("LASSO registration leaves all production release gates closed", {
  registration <- .dsvert_dp_lasso_cross_register()
  expect_identical(registration$version, "lasso_grid_cross_v1")
  expect_identical(registration$families, c("binomial", "poisson", "gaussian"))
  expect_false(registration$production_release_enabled)
  expect_true(registration$result_evidence_required)
  expect_identical(registration$implementation_state, "cross_owner_exact_gc_materialized")
  expect_identical(registration$cross_owner_state, "exact_gc_to_joint_dp_vector_v1")
})

test_that("LASSO public offsets preserve adjacent loss differences and reused caps", {
  for (family in c("binomial", "poisson")) {
    fixture <- .lasso_cross_fixture(family, capacity = 17, bits = 16)
    caps <- vapply(fixture$base$sensitivity$candidate_bounds,
      `[[`, numeric(1L), "per_patient_cap")
    mapping <- unlist(fixture$spec$base_coordinate_index)
    penalty <- unlist(fixture$spec$public_penalty_raw)
    left <- caps[mapping] + penalty
    right <- penalty
    expect_equal(left - right, caps[mapping])
    expect_equal(fixture$spec$base$coordinate_count, length(caps))
    expect_equal(fixture$spec$base$sensitivity, fixture$base$sensitivity)
    expect_equal(fixture$spec$additional_raw_l1_sensitivity, 0)
    expect_equal(fixture$spec$additional_raw_l2_sensitivity, 0)
    expect_length(fixture$spec$candidate_grid, 2 * length(caps))
  }
})

test_that("LASSO descriptors bind policy lattice and Gaussian moment conventions", {
  fixture <- .lasso_cross_fixture()
  expect_error(.dsvert_dp_lasso_cross_base(fixture$base_contract,
    fixture$policy, "poisson"), class = "dsvert_dp_public_failure")
  policy <- fixture$policy
  policy$numeric_grid_bits <- policy$numeric_grid_bits + 1
  expect_error(.dsvert_dp_lasso_cross_base(fixture$base_contract, policy),
    class = "dsvert_dp_public_failure")
  policy <- fixture$policy
  names(policy$peer_pinset) <- c("peer_a", "peer_c")
  expect_error(.dsvert_dp_lasso_cross_base(fixture$base_contract, policy),
    class = "dsvert_dp_public_failure")
  gaussian <- .lasso_cross_fixture("gaussian")
  mutations <- list(
    function(x) { x$coordinate_order <- "row_major"; x },
    function(x) { x$source_coordinate_scaling <- "different_lattices"; x },
    function(x) { x$coordinate_count <- x$coordinate_count - 1; x },
    function(x) { x$statistic_maximum[1] <- 0; x })
  for (change in mutations) expect_error(.dsvert_dp_lasso_cross_base(
    change(gaussian$base_contract), gaussian$policy, "gaussian"),
    class = "dsvert_dp_public_failure")
  expect_identical(.dsvert_dp_lasso_cross_register()$nonlinear_arithmetic_required,
    "certified_piecewise_polynomial_profile_v1")
})

test_that("Gaussian LASSO evaluates cross moments with canonical first-candidate ties", {
  fixture <- .lasso_cross_fixture("gaussian", capacity = 8, bits = 8,
    beta_grid = list(c(0, 0, 0), c(0.25, -0.5, 0.75)))
  x <- cbind(1, c(0, 0.25, 0.5, 1), c(1, 0.5, 0.25, 0))
  y <- c(0.75, 0.25, 0.5, 1)
  gram <- crossprod(x)
  coordinates <- 256 * c(nrow(x), gram[upper.tri(gram, diag = TRUE)],
    crossprod(x, y), sum(y^2))
  result <- .dsvert_dp_lasso_cross_postprocess(coordinates, fixture$spec)
  objective <- vapply(fixture$spec$candidate_grid, function(candidate) {
    beta <- unlist(candidate$beta)
    sum((y - as.vector(x %*% beta))^2) / 16 +
      candidate$lambda * sum(abs(beta[-1L]))
  }, numeric(1L))
  selected <- c(which.min(objective[1:2]), 2L + which.min(objective[3:4]))
  expect_equal(result$selected_candidates, selected)
  expect_equal(result$selected_objectives, objective[selected])
  zero <- .lasso_cross_fixture()
  tied <- .dsvert_dp_lasso_cross_postprocess(c(0, 0), zero$spec)
  expect_identical(tied$selected_candidates, c(1L, 3L))
})
